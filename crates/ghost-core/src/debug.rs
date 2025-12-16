//! Debug operations implementation helpers
//!
//! Provides VEH-based breakpoint management for in-process debugging.

use ghost_common::{Breakpoint, BreakpointId, BreakpointType, Error, Result};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use std::sync::RwLock;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

/// Exception codes
const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

/// Continue codes
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Trap flag bit in EFLAGS
const EFLAGS_TF: u32 = 0x100;

/// Counter for generating unique breakpoint IDs
static BREAKPOINT_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Global breakpoint manager (singleton)
static BREAKPOINT_MANAGER: RwLock<Option<BreakpointManager>> = RwLock::new(None);

/// VEH handler handle (using AtomicPtr for thread safety)
static VEH_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Flag indicating if we're in single-step mode
static SINGLE_STEPPING: AtomicBool = AtomicBool::new(false);

/// Address to restore breakpoint after single-step
static STEP_RESTORE_ADDRESS: AtomicUsize = AtomicUsize::new(0);

/// Breakpoint manager for in-process debugging
pub struct BreakpointManager {
    /// Software breakpoints (INT3)
    pub software_bps: HashMap<usize, SoftwareBreakpoint>,
    /// Hardware breakpoints (DR0-DR3)  
    pub hardware_bps: [Option<HardwareBreakpoint>; MAX_HW_BREAKPOINTS],
    /// Map from breakpoint ID to address
    pub id_to_address: HashMap<BreakpointId, usize>,
}

impl Default for BreakpointManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakpointManager {
    /// Create a new breakpoint manager
    pub fn new() -> Self {
        Self {
            software_bps: HashMap::new(),
            hardware_bps: [None, None, None, None],
            id_to_address: HashMap::new(),
        }
    }
}

/// Generate a new unique breakpoint ID
pub fn next_breakpoint_id() -> BreakpointId {
    BreakpointId(BREAKPOINT_COUNTER.fetch_add(1, Ordering::SeqCst))
}

/// Software breakpoint info (stores original byte)
pub struct SoftwareBreakpoint {
    pub id: BreakpointId,
    pub address: usize,
    pub original_byte: u8,
    pub enabled: bool,
    pub hit_count: u64,
    pub one_shot: bool,
}

/// Hardware breakpoint info
pub struct HardwareBreakpoint {
    pub id: BreakpointId,
    pub address: usize,
    pub dr_index: u8, // DR0-DR3
    pub enabled: bool,
    pub hit_count: u64,
}

/// INT3 opcode for software breakpoints
pub const INT3: u8 = 0xCC;

/// Maximum hardware breakpoints available (DR0-DR3)
pub const MAX_HW_BREAKPOINTS: usize = 4;

/// Convert internal breakpoint to common Breakpoint type
impl From<&SoftwareBreakpoint> for Breakpoint {
    fn from(bp: &SoftwareBreakpoint) -> Self {
        Breakpoint {
            id: bp.id,
            address: bp.address,
            bp_type: BreakpointType::Software,
            enabled: bp.enabled,
            hit_count: bp.hit_count,
        }
    }
}

impl From<&HardwareBreakpoint> for Breakpoint {
    fn from(bp: &HardwareBreakpoint) -> Self {
        Breakpoint {
            id: bp.id,
            address: bp.address,
            bp_type: BreakpointType::Hardware,
            enabled: bp.enabled,
            hit_count: bp.hit_count,
        }
    }
}

// ============================================================================
// VEH Handler and Breakpoint Management API
// ============================================================================

/// Initialize the VEH-based debugging system
pub fn initialize_debugger() -> Result<()> {
    // Check if already initialized
    if !VEH_HANDLE.load(Ordering::SeqCst).is_null() {
        return Ok(());
    }

    // Initialize breakpoint manager
    {
        let mut manager = BREAKPOINT_MANAGER
            .write()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;
        if manager.is_none() {
            *manager = Some(BreakpointManager::new());
        }
    }

    // Register VEH handler
    unsafe {
        let handle = AddVectoredExceptionHandler(1, Some(veh_handler));
        if handle.is_null() {
            return Err(Error::Internal("Failed to register VEH handler".into()));
        }
        VEH_HANDLE.store(handle, Ordering::SeqCst);
    }

    tracing::info!(target: "ghost_core::debug", "VEH debugger initialized");
    Ok(())
}

/// Cleanup the VEH-based debugging system
pub fn cleanup_debugger() -> Result<()> {
    let handle = VEH_HANDLE.swap(std::ptr::null_mut(), Ordering::SeqCst);
    if !handle.is_null() {
        unsafe {
            RemoveVectoredExceptionHandler(handle);
        }
    }

    // Clear breakpoint manager
    if let Ok(mut manager) = BREAKPOINT_MANAGER.write() {
        *manager = None;
    }

    tracing::info!(target: "ghost_core::debug", "VEH debugger cleaned up");
    Ok(())
}

/// Set a software breakpoint (INT3)
pub fn set_software_breakpoint(addr: usize) -> Result<BreakpointId> {
    let mut manager = BREAKPOINT_MANAGER
        .write()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    let manager = manager
        .as_mut()
        .ok_or_else(|| Error::Internal("Debugger not initialized".into()))?;

    // Check if breakpoint already exists
    if manager.software_bps.contains_key(&addr) {
        return Err(Error::Internal(format!(
            "Breakpoint already exists at 0x{:x}",
            addr
        )));
    }

    // Read original byte
    let original_byte = unsafe { *(addr as *const u8) };

    // Write INT3
    unsafe {
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        if VirtualProtect(
            addr as *mut c_void,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .is_err()
        {
            return Err(Error::Internal("VirtualProtect failed".into()));
        }

        *(addr as *mut u8) = INT3;

        let mut tmp = PAGE_PROTECTION_FLAGS::default();
        let _ = VirtualProtect(addr as *mut c_void, 1, old_protect, &mut tmp);
    }

    let id = next_breakpoint_id();
    let bp = SoftwareBreakpoint {
        id,
        address: addr,
        original_byte,
        enabled: true,
        hit_count: 0,
        one_shot: false,
    };

    manager.software_bps.insert(addr, bp);
    manager.id_to_address.insert(id, addr);

    tracing::debug!(target: "ghost_core::debug", id = id.0, addr = format!("0x{:x}", addr), "Software breakpoint set");
    Ok(id)
}

/// Set a one-shot software breakpoint (INT3)
/// The breakpoint will be automatically removed after it is hit.
pub fn set_one_shot_breakpoint(addr: usize) -> Result<BreakpointId> {
    let mut manager = BREAKPOINT_MANAGER
        .write()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    let manager = manager
        .as_mut()
        .ok_or_else(|| Error::Internal("Debugger not initialized".into()))?;

    // Check if breakpoint already exists
    if manager.software_bps.contains_key(&addr) {
        return Err(Error::Internal(format!(
            "Breakpoint already exists at 0x{:x}",
            addr
        )));
    }

    // Read original byte
    let original_byte = unsafe { *(addr as *const u8) };

    // Write INT3
    unsafe {
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        if VirtualProtect(
            addr as *mut c_void,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .is_err()
        {
            return Err(Error::Internal("VirtualProtect failed".into()));
        }

        *(addr as *mut u8) = INT3;

        let mut tmp = PAGE_PROTECTION_FLAGS::default();
        let _ = VirtualProtect(addr as *mut c_void, 1, old_protect, &mut tmp);
    }

    let id = next_breakpoint_id();
    let bp = SoftwareBreakpoint {
        id,
        address: addr,
        original_byte,
        enabled: true,
        hit_count: 0,
        one_shot: true,
    };

    manager.software_bps.insert(addr, bp);
    manager.id_to_address.insert(id, addr);

    tracing::debug!(target: "ghost_core::debug", id = id.0, addr = format!("0x{:x}", addr), "One-shot breakpoint set");
    Ok(id)
}

/// Set a hardware breakpoint (DR0-DR3)
#[cfg(target_arch = "x86_64")]
pub fn set_hardware_breakpoint(addr: usize) -> Result<BreakpointId> {
    let mut manager = BREAKPOINT_MANAGER
        .write()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    let manager = manager
        .as_mut()
        .ok_or_else(|| Error::Internal("Debugger not initialized".into()))?;

    // Find a free DR slot
    let slot = manager
        .hardware_bps
        .iter()
        .position(|bp| bp.is_none())
        .ok_or_else(|| Error::Internal("No free hardware breakpoint slots".into()))?;

    let id = next_breakpoint_id();
    let bp = HardwareBreakpoint {
        id,
        address: addr,
        dr_index: slot as u8,
        enabled: true,
        hit_count: 0,
    };

    manager.hardware_bps[slot] = Some(bp);
    manager.id_to_address.insert(id, addr);

    // Hardware breakpoints are set per-thread via debug registers
    // For now, we note that the breakpoint is registered but actual DR setup
    // happens in the VEH handler or requires iterating all threads
    tracing::debug!(target: "ghost_core::debug", id = id.0, addr = format!("0x{:x}", addr), slot = slot, "Hardware breakpoint registered");
    Ok(id)
}

/// Remove a breakpoint by ID
pub fn remove_breakpoint(id: BreakpointId) -> Result<()> {
    let mut manager = BREAKPOINT_MANAGER
        .write()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    let manager = manager
        .as_mut()
        .ok_or_else(|| Error::Internal("Debugger not initialized".into()))?;

    let addr = manager
        .id_to_address
        .remove(&id)
        .ok_or_else(|| Error::Internal(format!("Breakpoint {} not found", id.0)))?;

    // Check if it's a software breakpoint
    if let Some(bp) = manager.software_bps.remove(&addr) {
        // Restore original byte
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            if VirtualProtect(
                addr as *mut c_void,
                1,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .is_ok()
            {
                *(addr as *mut u8) = bp.original_byte;
                let mut tmp = PAGE_PROTECTION_FLAGS::default();
                let _ = VirtualProtect(addr as *mut c_void, 1, old_protect, &mut tmp);
            }
        }
        tracing::debug!(target: "ghost_core::debug", id = id.0, addr = format!("0x{:x}", addr), "Software breakpoint removed");
        return Ok(());
    }

    // Check if it's a hardware breakpoint
    for slot in &mut manager.hardware_bps {
        if let Some(bp) = slot {
            if bp.id == id {
                tracing::debug!(target: "ghost_core::debug", id = id.0, addr = format!("0x{:x}", addr), "Hardware breakpoint removed");
                *slot = None;
                return Ok(());
            }
        }
    }

    Err(Error::Internal(format!("Breakpoint {} not found", id.0)))
}

/// List all breakpoints
pub fn list_breakpoints() -> Result<Vec<Breakpoint>> {
    let manager = BREAKPOINT_MANAGER
        .read()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    let manager = manager
        .as_ref()
        .ok_or_else(|| Error::Internal("Debugger not initialized".into()))?;

    let mut breakpoints = Vec::new();

    for bp in manager.software_bps.values() {
        breakpoints.push(bp.into());
    }

    for bp in manager.hardware_bps.iter().flatten() {
        breakpoints.push(bp.into());
    }

    Ok(breakpoints)
}

/// Enable or disable a breakpoint
pub fn set_breakpoint_enabled(id: BreakpointId, enabled: bool) -> Result<()> {
    let mut manager = BREAKPOINT_MANAGER
        .write()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    let manager = manager
        .as_mut()
        .ok_or_else(|| Error::Internal("Debugger not initialized".into()))?;

    let addr = manager
        .id_to_address
        .get(&id)
        .copied()
        .ok_or_else(|| Error::Internal(format!("Breakpoint {} not found", id.0)))?;

    if let Some(bp) = manager.software_bps.get_mut(&addr) {
        if enabled && !bp.enabled {
            // Re-enable: write INT3
            unsafe {
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                if VirtualProtect(
                    addr as *mut c_void,
                    1,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
                .is_ok()
                {
                    *(addr as *mut u8) = INT3;
                    let mut tmp = PAGE_PROTECTION_FLAGS::default();
                    let _ = VirtualProtect(addr as *mut c_void, 1, old_protect, &mut tmp);
                }
            }
        } else if !enabled && bp.enabled {
            // Disable: restore original byte
            unsafe {
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                if VirtualProtect(
                    addr as *mut c_void,
                    1,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
                .is_ok()
                {
                    *(addr as *mut u8) = bp.original_byte;
                    let mut tmp = PAGE_PROTECTION_FLAGS::default();
                    let _ = VirtualProtect(addr as *mut c_void, 1, old_protect, &mut tmp);
                }
            }
        }
        bp.enabled = enabled;
        return Ok(());
    }

    for bp in manager.hardware_bps.iter_mut().flatten() {
        if bp.id == id {
            bp.enabled = enabled;
            return Ok(());
        }
    }

    Err(Error::Internal(format!("Breakpoint {} not found", id.0)))
}

/// VEH handler for breakpoint exceptions
#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;

    if exception_record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let code = (*exception_record).ExceptionCode.0 as u32;
    let addr = (*exception_record).ExceptionAddress as usize;

    match code {
        EXCEPTION_BREAKPOINT => {
            let mut handled = false;
            let mut is_one_shot = false;

            // Check if this is one of our breakpoints
            if let Ok(manager) = BREAKPOINT_MANAGER.read() {
                if let Some(manager) = manager.as_ref() {
                    if let Some(bp) = manager.software_bps.get(&addr) {
                        if bp.enabled {
                            is_one_shot = bp.one_shot;
                            handled = true;

                            // Restore original byte
                            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                            if VirtualProtect(
                                addr as *mut c_void,
                                1,
                                PAGE_EXECUTE_READWRITE,
                                &mut old_protect,
                            )
                            .is_ok()
                            {
                                *(addr as *mut u8) = bp.original_byte;
                                let mut tmp = PAGE_PROTECTION_FLAGS::default();
                                let _ =
                                    VirtualProtect(addr as *mut c_void, 1, old_protect, &mut tmp);
                            }
                        }
                    }
                }
            }

            if handled {
                if is_one_shot {
                    // Remove from manager
                    if let Ok(mut manager) = BREAKPOINT_MANAGER.write() {
                        if let Some(manager) = manager.as_mut() {
                            if let Some(bp) = manager.software_bps.remove(&addr) {
                                manager.id_to_address.remove(&bp.id);
                                tracing::debug!(target: "ghost_core::debug", id = bp.id.0, addr = format!("0x{:x}", addr), "One-shot breakpoint removed");
                            }
                        }
                    }
                } else {
                    // Set trap flag to single-step and restore BP after
                    (*context).EFlags |= EFLAGS_TF;
                    SINGLE_STEPPING.store(true, Ordering::SeqCst);
                    STEP_RESTORE_ADDRESS.store(addr, Ordering::SeqCst);
                }

                // Adjust RIP to point to the beginning of the instruction
                (*context).Rip = addr as u64;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        EXCEPTION_SINGLE_STEP => {
            // Check if we need to restore a breakpoint
            if SINGLE_STEPPING.load(Ordering::SeqCst) {
                let restore_addr = STEP_RESTORE_ADDRESS.swap(0, Ordering::SeqCst);
                if restore_addr != 0 {
                    // Re-write INT3
                    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                    if VirtualProtect(
                        restore_addr as *mut c_void,
                        1,
                        PAGE_EXECUTE_READWRITE,
                        &mut old_protect,
                    )
                    .is_ok()
                    {
                        *(restore_addr as *mut u8) = INT3;
                        let mut tmp = PAGE_PROTECTION_FLAGS::default();
                        let _ =
                            VirtualProtect(restore_addr as *mut c_void, 1, old_protect, &mut tmp);
                    }

                    // Update hit count
                    if let Ok(mut manager) = BREAKPOINT_MANAGER.write() {
                        if let Some(manager) = manager.as_mut() {
                            if let Some(bp) = manager.software_bps.get_mut(&restore_addr) {
                                bp.hit_count += 1;
                            }
                        }
                    }
                }
                SINGLE_STEPPING.store(false, Ordering::SeqCst);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        _ => {}
    }

    EXCEPTION_CONTINUE_SEARCH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_breakpoint_id() {
        let id1 = next_breakpoint_id();
        let id2 = next_breakpoint_id();
        assert!(id2.0 > id1.0);
    }

    #[test]
    fn test_int3_constant() {
        assert_eq!(INT3, 0xCC);
    }

    #[test]
    fn test_max_hw_breakpoints() {
        assert_eq!(MAX_HW_BREAKPOINTS, 4);
    }

    #[test]
    fn test_software_breakpoint_conversion() {
        let sw_bp = SoftwareBreakpoint {
            id: BreakpointId(1),
            address: 0x140001000,
            original_byte: 0x48,
            enabled: true,
            hit_count: 5,
            one_shot: false,
        };

        let bp: Breakpoint = (&sw_bp).into();
        assert_eq!(bp.id.0, 1);
        assert_eq!(bp.address, 0x140001000);
        assert_eq!(bp.bp_type, BreakpointType::Software);
        assert!(bp.enabled);
        assert_eq!(bp.hit_count, 5);
    }

    #[test]
    fn test_hardware_breakpoint_conversion() {
        let hw_bp = HardwareBreakpoint {
            id: BreakpointId(2),
            address: 0x140002000,
            dr_index: 0,
            enabled: false,
            hit_count: 10,
        };

        let bp: Breakpoint = (&hw_bp).into();
        assert_eq!(bp.id.0, 2);
        assert_eq!(bp.address, 0x140002000);
        assert_eq!(bp.bp_type, BreakpointType::Hardware);
        assert!(!bp.enabled);
        assert_eq!(bp.hit_count, 10);
    }

    #[test]
    fn test_breakpoint_manager_new() {
        let manager = BreakpointManager::new();
        assert!(manager.software_bps.is_empty());
        assert!(manager.hardware_bps.iter().all(|bp| bp.is_none()));
        assert!(manager.id_to_address.is_empty());
    }

    #[test]
    fn test_breakpoint_manager_default() {
        let manager = BreakpointManager::default();
        assert!(manager.software_bps.is_empty());
        assert_eq!(manager.hardware_bps.len(), MAX_HW_BREAKPOINTS);
    }

    #[test]
    fn test_exception_constants() {
        assert_eq!(EXCEPTION_BREAKPOINT, 0x80000003);
        assert_eq!(EXCEPTION_SINGLE_STEP, 0x80000004);
        assert_eq!(EXCEPTION_CONTINUE_EXECUTION, -1);
        assert_eq!(EXCEPTION_CONTINUE_SEARCH, 0);
        assert_eq!(EFLAGS_TF, 0x100);
    }

    #[test]
    fn test_initialize_debugger_idempotent() {
        // First init should succeed
        let result1 = initialize_debugger();
        assert!(result1.is_ok());

        // Second init should also succeed (no-op)
        let result2 = initialize_debugger();
        assert!(result2.is_ok());

        // Cleanup
        let _ = cleanup_debugger();
    }

    #[test]
    fn test_list_breakpoints_requires_init() {
        // Make sure debugger is cleaned up first
        let _ = cleanup_debugger();

        // Listing without init should fail
        let result = list_breakpoints();
        assert!(result.is_err());
    }
}
