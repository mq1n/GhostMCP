//! Debug operations implementation helpers
//!
//! Provides VEH-based breakpoint management for in-process debugging.

use ghost_common::{Breakpoint, BreakpointId, BreakpointType, Error, Result};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use std::sync::RwLock;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, GetThreadContext, RemoveVectoredExceptionHandler,
    SetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64, EXCEPTION_POINTERS,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
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

/// Hardware breakpoint slot being restored after single-step
static HW_BP_RESTORE_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);

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

/// Hardware breakpoint condition types for DR7
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum HwBpCondition {
    /// Break on execution
    Execute = 0b00,
    /// Break on write only
    Write = 0b01,
    /// Break on I/O read/write (not commonly used)
    IoReadWrite = 0b10,
    /// Break on read or write (but not execution)
    ReadWrite = 0b11,
}

/// Hardware breakpoint length for DR7
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum HwBpLength {
    /// 1 byte
    Byte1 = 0b00,
    /// 2 bytes
    Byte2 = 0b01,
    /// 8 bytes (only on x64)
    Byte8 = 0b10,
    /// 4 bytes
    Byte4 = 0b11,
}

/// Validate hardware breakpoint address alignment
/// Hardware breakpoints require proper alignment based on length
#[cfg(target_arch = "x86_64")]
fn validate_hw_bp_alignment(addr: usize, length: HwBpLength) -> Result<()> {
    let alignment = match length {
        HwBpLength::Byte1 => 1,
        HwBpLength::Byte2 => 2,
        HwBpLength::Byte4 => 4,
        HwBpLength::Byte8 => 8,
    };

    if !addr.is_multiple_of(alignment) {
        return Err(Error::Internal(format!(
            "Hardware breakpoint address 0x{:x} is not aligned to {} bytes",
            addr, alignment
        )));
    }
    Ok(())
}

/// Set hardware breakpoint on all threads in the process
#[cfg(target_arch = "x86_64")]
fn set_hw_bp_on_all_threads(
    slot: usize,
    addr: usize,
    condition: HwBpCondition,
    length: HwBpLength,
) -> Result<u32> {
    // Validate slot
    if slot >= MAX_HW_BREAKPOINTS {
        return Err(Error::Internal(format!(
            "Invalid breakpoint slot: {} (max {})",
            slot,
            MAX_HW_BREAKPOINTS - 1
        )));
    }

    // Validate address is not null
    if addr == 0 {
        return Err(Error::Internal(
            "Cannot set hardware breakpoint at null address".into(),
        ));
    }

    // Validate alignment for data breakpoints
    if !matches!(condition, HwBpCondition::Execute) {
        validate_hw_bp_alignment(addr, length)?;
    }

    tracing::trace!(
        target: "ghost_core::debug",
        slot = slot,
        addr = format!("0x{:x}", addr),
        condition = ?condition,
        length = ?length,
        "Setting hardware breakpoint on all threads"
    );

    unsafe {
        let current_pid = GetCurrentProcessId();
        let current_tid = GetCurrentThreadId();

        // Create a snapshot of all threads
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        // RAII guard for snapshot handle
        struct SnapshotGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }
        let _snapshot_guard = SnapshotGuard(snapshot);

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut threads_set = 0u32;
        let mut threads_failed = 0u32;

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                // Only process threads belonging to our process
                if thread_entry.th32OwnerProcessID == current_pid {
                    let tid = thread_entry.th32ThreadID;

                    // Open thread with required access
                    if let Ok(thread_handle) = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        false,
                        tid,
                    ) {
                        // RAII guard for thread handle
                        struct ThreadGuard(windows::Win32::Foundation::HANDLE);
                        impl Drop for ThreadGuard {
                            fn drop(&mut self) {
                                unsafe {
                                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                                }
                            }
                        }
                        let _thread_guard = ThreadGuard(thread_handle);

                        // For non-current threads, we need to suspend first
                        let is_current = tid == current_tid;
                        if !is_current {
                            SuspendThread(thread_handle);
                        }

                        // Get thread context
                        let mut context: CONTEXT = std::mem::zeroed();
                        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

                        let result = if GetThreadContext(thread_handle, &mut context).is_ok() {
                            // Set address in appropriate DR register
                            match slot {
                                0 => context.Dr0 = addr as u64,
                                1 => context.Dr1 = addr as u64,
                                2 => context.Dr2 = addr as u64,
                                3 => context.Dr3 = addr as u64,
                                _ => {}
                            }

                            // Enable the breakpoint in DR7
                            // Bits 0,2,4,6 are local enable bits for DR0-DR3
                            let local_enable_bit = 1u64 << (slot * 2);
                            context.Dr7 |= local_enable_bit;

                            // Set condition and length in DR7
                            // Bits 16-17 (condition) and 18-19 (length) for DR0, +4 for each DR
                            let condition_offset = 16 + (slot * 4);
                            // Clear existing condition/length bits
                            context.Dr7 &= !(0xFu64 << condition_offset);
                            // Set new condition and length
                            let cond_len = ((length as u64) << 2) | (condition as u64);
                            context.Dr7 |= cond_len << condition_offset;

                            SetThreadContext(thread_handle, &context).is_ok()
                        } else {
                            false
                        };

                        // Always resume if we suspended
                        if !is_current {
                            ResumeThread(thread_handle);
                        }

                        if result {
                            threads_set += 1;
                        } else {
                            threads_failed += 1;
                        }
                    }
                }

                // Move to next thread
                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        if threads_set == 0 {
            return Err(Error::Internal(
                "Failed to set hardware breakpoint on any thread".into(),
            ));
        }

        if threads_failed > 0 {
            tracing::warn!(
                target: "ghost_core::debug",
                slot = slot,
                threads_set = threads_set,
                threads_failed = threads_failed,
                "Some threads failed to set hardware breakpoint"
            );
        }

        tracing::debug!(
            target: "ghost_core::debug",
            slot = slot,
            addr = format!("0x{:x}", addr),
            threads = threads_set,
            "Hardware breakpoint set on threads"
        );

        Ok(threads_set)
    }
}

/// Clear hardware breakpoint on all threads in the process
#[cfg(target_arch = "x86_64")]
fn clear_hw_bp_on_all_threads(slot: usize) -> Result<u32> {
    if slot >= MAX_HW_BREAKPOINTS {
        return Err(Error::Internal(format!(
            "Invalid breakpoint slot: {} (max {})",
            slot,
            MAX_HW_BREAKPOINTS - 1
        )));
    }

    tracing::trace!(
        target: "ghost_core::debug",
        slot = slot,
        "Clearing hardware breakpoint on all threads"
    );

    unsafe {
        let current_pid = GetCurrentProcessId();
        let current_tid = GetCurrentThreadId();

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        // Ensure snapshot is closed on all exit paths
        struct SnapshotGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }
        let _snapshot_guard = SnapshotGuard(snapshot);

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut threads_cleared = 0u32;
        let mut threads_failed = 0u32;

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == current_pid {
                    let tid = thread_entry.th32ThreadID;

                    if let Ok(thread_handle) = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        false,
                        tid,
                    ) {
                        // Ensure thread handle is closed on all exit paths
                        struct ThreadGuard(windows::Win32::Foundation::HANDLE);
                        impl Drop for ThreadGuard {
                            fn drop(&mut self) {
                                unsafe {
                                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                                }
                            }
                        }
                        let _thread_guard = ThreadGuard(thread_handle);

                        let is_current = tid == current_tid;
                        if !is_current {
                            SuspendThread(thread_handle);
                        }

                        let mut context: CONTEXT = std::mem::zeroed();
                        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

                        let result = if GetThreadContext(thread_handle, &mut context).is_ok() {
                            // Clear DR register
                            match slot {
                                0 => context.Dr0 = 0,
                                1 => context.Dr1 = 0,
                                2 => context.Dr2 = 0,
                                3 => context.Dr3 = 0,
                                _ => {}
                            }

                            // Disable in DR7
                            let local_enable_bit = 1u64 << (slot * 2);
                            context.Dr7 &= !local_enable_bit;

                            // Clear condition/length bits
                            let condition_offset = 16 + (slot * 4);
                            context.Dr7 &= !(0xFu64 << condition_offset);

                            SetThreadContext(thread_handle, &context).is_ok()
                        } else {
                            false
                        };

                        // Always resume if we suspended
                        if !is_current {
                            ResumeThread(thread_handle);
                        }

                        if result {
                            threads_cleared += 1;
                        } else {
                            threads_failed += 1;
                        }
                    }
                }

                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        if threads_failed > 0 {
            tracing::warn!(
                target: "ghost_core::debug",
                slot = slot,
                threads_cleared = threads_cleared,
                threads_failed = threads_failed,
                "Some threads failed to clear hardware breakpoint"
            );
        }

        tracing::debug!(
            target: "ghost_core::debug",
            slot = slot,
            threads = threads_cleared,
            "Hardware breakpoint cleared on threads"
        );

        Ok(threads_cleared)
    }
}

/// Enable hardware breakpoint on all threads (set DR7 local enable bit)
#[cfg(target_arch = "x86_64")]
fn enable_hw_bp_on_all_threads(slot: usize) -> Result<u32> {
    if slot >= MAX_HW_BREAKPOINTS {
        return Err(Error::Internal(format!(
            "Invalid breakpoint slot: {} (max {})",
            slot,
            MAX_HW_BREAKPOINTS - 1
        )));
    }

    unsafe {
        let current_pid = GetCurrentProcessId();
        let current_tid = GetCurrentThreadId();

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        struct SnapshotGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }
        let _snapshot_guard = SnapshotGuard(snapshot);

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut threads_enabled = 0u32;

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == current_pid {
                    let tid = thread_entry.th32ThreadID;

                    if let Ok(thread_handle) = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        false,
                        tid,
                    ) {
                        struct ThreadGuard(windows::Win32::Foundation::HANDLE);
                        impl Drop for ThreadGuard {
                            fn drop(&mut self) {
                                unsafe {
                                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                                }
                            }
                        }
                        let _thread_guard = ThreadGuard(thread_handle);

                        let is_current = tid == current_tid;
                        if !is_current {
                            SuspendThread(thread_handle);
                        }

                        let mut context: CONTEXT = std::mem::zeroed();
                        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

                        if GetThreadContext(thread_handle, &mut context).is_ok() {
                            // Enable in DR7
                            let local_enable_bit = 1u64 << (slot * 2);
                            context.Dr7 |= local_enable_bit;

                            if SetThreadContext(thread_handle, &context).is_ok() {
                                threads_enabled += 1;
                            }
                        }

                        if !is_current {
                            ResumeThread(thread_handle);
                        }
                    }
                }

                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        tracing::trace!(
            target: "ghost_core::debug",
            slot = slot,
            threads = threads_enabled,
            "Hardware breakpoint enabled on threads"
        );

        Ok(threads_enabled)
    }
}

/// Disable hardware breakpoint on all threads (clear DR7 local enable bit, keep address)
#[cfg(target_arch = "x86_64")]
fn disable_hw_bp_on_all_threads(slot: usize) -> Result<u32> {
    if slot >= MAX_HW_BREAKPOINTS {
        return Err(Error::Internal(format!(
            "Invalid breakpoint slot: {} (max {})",
            slot,
            MAX_HW_BREAKPOINTS - 1
        )));
    }

    unsafe {
        let current_pid = GetCurrentProcessId();
        let current_tid = GetCurrentThreadId();

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        struct SnapshotGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }
        let _snapshot_guard = SnapshotGuard(snapshot);

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut threads_disabled = 0u32;

        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop {
                if thread_entry.th32OwnerProcessID == current_pid {
                    let tid = thread_entry.th32ThreadID;

                    if let Ok(thread_handle) = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        false,
                        tid,
                    ) {
                        struct ThreadGuard(windows::Win32::Foundation::HANDLE);
                        impl Drop for ThreadGuard {
                            fn drop(&mut self) {
                                unsafe {
                                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                                }
                            }
                        }
                        let _thread_guard = ThreadGuard(thread_handle);

                        let is_current = tid == current_tid;
                        if !is_current {
                            SuspendThread(thread_handle);
                        }

                        let mut context: CONTEXT = std::mem::zeroed();
                        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

                        if GetThreadContext(thread_handle, &mut context).is_ok() {
                            // Disable in DR7 (clear local enable bit only)
                            let local_enable_bit = 1u64 << (slot * 2);
                            context.Dr7 &= !local_enable_bit;

                            if SetThreadContext(thread_handle, &context).is_ok() {
                                threads_disabled += 1;
                            }
                        }

                        if !is_current {
                            ResumeThread(thread_handle);
                        }
                    }
                }

                thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }
        }

        tracing::trace!(
            target: "ghost_core::debug",
            slot = slot,
            threads = threads_disabled,
            "Hardware breakpoint disabled on threads"
        );

        Ok(threads_disabled)
    }
}

/// Set a hardware breakpoint (DR0-DR3) for write access
#[cfg(target_arch = "x86_64")]
pub fn set_hardware_breakpoint(addr: usize) -> Result<BreakpointId> {
    set_hardware_breakpoint_ex(addr, HwBpCondition::Write, HwBpLength::Byte4)
}

/// Set a hardware breakpoint with custom condition and length
#[cfg(target_arch = "x86_64")]
pub fn set_hardware_breakpoint_ex(
    addr: usize,
    condition: HwBpCondition,
    length: HwBpLength,
) -> Result<BreakpointId> {
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

    // Actually set the hardware breakpoint on all threads
    set_hw_bp_on_all_threads(slot, addr, condition, length)?;

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

    tracing::info!(target: "ghost_core::debug", id = id.0, addr = format!("0x{:x}", addr), slot = slot, "Hardware breakpoint set");
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
    for (slot_idx, slot) in manager.hardware_bps.iter_mut().enumerate() {
        if let Some(bp) = slot {
            if bp.id == id {
                // Clear hardware breakpoint on all threads
                #[cfg(target_arch = "x86_64")]
                {
                    let _ = clear_hw_bp_on_all_threads(slot_idx);
                }
                tracing::debug!(target: "ghost_core::debug", id = id.0, addr = format!("0x{:x}", addr), slot = slot_idx, "Hardware breakpoint removed");
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

    for (slot_idx, slot) in manager.hardware_bps.iter_mut().enumerate() {
        if let Some(bp) = slot {
            if bp.id == id {
                if enabled != bp.enabled {
                    // Actually enable/disable the hardware breakpoint on all threads
                    #[cfg(target_arch = "x86_64")]
                    {
                        if enabled {
                            // Re-enable: set DR7 bits
                            if let Err(e) = enable_hw_bp_on_all_threads(slot_idx) {
                                tracing::warn!(
                                    target: "ghost_core::debug",
                                    slot = slot_idx,
                                    error = %e,
                                    "Failed to enable hardware breakpoint on some threads"
                                );
                            }
                        } else {
                            // Disable: clear DR7 bits (but keep DR address)
                            if let Err(e) = disable_hw_bp_on_all_threads(slot_idx) {
                                tracing::warn!(
                                    target: "ghost_core::debug",
                                    slot = slot_idx,
                                    error = %e,
                                    "Failed to disable hardware breakpoint on some threads"
                                );
                            }
                        }
                    }
                    tracing::debug!(
                        target: "ghost_core::debug",
                        id = id.0,
                        slot = slot_idx,
                        enabled = enabled,
                        "Hardware breakpoint enabled state changed"
                    );
                }
                bp.enabled = enabled;
                return Ok(());
            }
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
            // First check DR6 for hardware breakpoint hits
            let dr6 = (*context).Dr6;
            let hw_bp_hit = dr6 & 0xF; // Bits 0-3 indicate DR0-DR3 triggered

            if hw_bp_hit != 0 {
                // Hardware breakpoint was hit
                let mut handled = false;

                if let Ok(mut manager) = BREAKPOINT_MANAGER.write() {
                    if let Some(manager) = manager.as_mut() {
                        for i in 0..MAX_HW_BREAKPOINTS {
                            if (hw_bp_hit & (1 << i)) != 0 {
                                if let Some(bp) = &mut manager.hardware_bps[i] {
                                    if bp.enabled {
                                        bp.hit_count += 1;
                                        handled = true;
                                        tracing::debug!(
                                            target: "ghost_core::debug",
                                            id = bp.id.0,
                                            addr = format!("0x{:x}", bp.address),
                                            slot = i,
                                            hit_count = bp.hit_count,
                                            "Hardware breakpoint hit"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                if handled {
                    // Clear DR6 status bits
                    (*context).Dr6 &= !0xF;

                    // For data breakpoints (read/write), we need to single-step past
                    // the instruction and re-enable the breakpoint
                    // Set Resume Flag (RF) to skip the breakpoint on the next instruction
                    (*context).EFlags |= 0x10000; // RF flag

                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            // Check if we need to restore a software breakpoint
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

            // Check if we need to restore a hardware breakpoint after single-step
            let restore_slot = HW_BP_RESTORE_SLOT.swap(usize::MAX, Ordering::SeqCst);
            if restore_slot < MAX_HW_BREAKPOINTS {
                // Re-enable the hardware breakpoint that was temporarily disabled
                if let Ok(manager) = BREAKPOINT_MANAGER.read() {
                    if let Some(manager) = manager.as_ref() {
                        if let Some(_bp) = &manager.hardware_bps[restore_slot] {
                            // Re-enable in DR7
                            let local_enable_bit = 1u64 << (restore_slot * 2);
                            (*context).Dr7 |= local_enable_bit;
                        }
                    }
                }
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

    #[test]
    fn test_hw_bp_condition_values() {
        assert_eq!(HwBpCondition::Execute as u8, 0b00);
        assert_eq!(HwBpCondition::Write as u8, 0b01);
        assert_eq!(HwBpCondition::IoReadWrite as u8, 0b10);
        assert_eq!(HwBpCondition::ReadWrite as u8, 0b11);
    }

    #[test]
    fn test_hw_bp_length_values() {
        assert_eq!(HwBpLength::Byte1 as u8, 0b00);
        assert_eq!(HwBpLength::Byte2 as u8, 0b01);
        assert_eq!(HwBpLength::Byte8 as u8, 0b10);
        assert_eq!(HwBpLength::Byte4 as u8, 0b11);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_hw_bp_alignment_validation() {
        // Byte1 - any alignment is fine
        assert!(validate_hw_bp_alignment(0x1001, HwBpLength::Byte1).is_ok());
        assert!(validate_hw_bp_alignment(0x1000, HwBpLength::Byte1).is_ok());

        // Byte2 - must be 2-byte aligned
        assert!(validate_hw_bp_alignment(0x1000, HwBpLength::Byte2).is_ok());
        assert!(validate_hw_bp_alignment(0x1002, HwBpLength::Byte2).is_ok());
        assert!(validate_hw_bp_alignment(0x1001, HwBpLength::Byte2).is_err());

        // Byte4 - must be 4-byte aligned
        assert!(validate_hw_bp_alignment(0x1000, HwBpLength::Byte4).is_ok());
        assert!(validate_hw_bp_alignment(0x1004, HwBpLength::Byte4).is_ok());
        assert!(validate_hw_bp_alignment(0x1001, HwBpLength::Byte4).is_err());
        assert!(validate_hw_bp_alignment(0x1002, HwBpLength::Byte4).is_err());

        // Byte8 - must be 8-byte aligned
        assert!(validate_hw_bp_alignment(0x1000, HwBpLength::Byte8).is_ok());
        assert!(validate_hw_bp_alignment(0x1008, HwBpLength::Byte8).is_ok());
        assert!(validate_hw_bp_alignment(0x1004, HwBpLength::Byte8).is_err());
    }

    #[test]
    fn test_dr7_bit_calculations() {
        // Test local enable bit positions (slot * 2)
        // DR0: slot=0, bit position = 0
        // DR1: slot=1, bit position = 2
        // DR2: slot=2, bit position = 4
        // DR3: slot=3, bit position = 6
        let dr0_enable = 1u64 << 0;
        let dr1_enable = 1u64 << 2;
        let dr2_enable = 1u64 << 4;
        let dr3_enable = 1u64 << 6;
        assert_eq!(dr0_enable, 0b0001);
        assert_eq!(dr1_enable, 0b0100);
        assert_eq!(dr2_enable, 0b010000);
        assert_eq!(dr3_enable, 0b01000000);

        // Test condition/length offset positions (16 + slot * 4)
        // DR0: offset = 16
        // DR1: offset = 20
        // DR2: offset = 24
        // DR3: offset = 28
        let dr0_cond_offset = 16usize;
        let dr1_cond_offset = 20usize;
        let dr2_cond_offset = 24usize;
        let dr3_cond_offset = 28usize;
        assert_eq!(dr0_cond_offset, 16);
        assert_eq!(dr1_cond_offset, 20);
        assert_eq!(dr2_cond_offset, 24);
        assert_eq!(dr3_cond_offset, 28);
    }

    #[test]
    fn test_cond_len_encoding() {
        // Test condition/length encoding: (length << 2) | condition
        // Write (01) + Byte4 (11) = 0b1101 = 13
        let cond_len = ((HwBpLength::Byte4 as u64) << 2) | (HwBpCondition::Write as u64);
        assert_eq!(cond_len, 0b1101);

        // Execute (00) + Byte1 (00) = 0b0000 = 0
        let cond_len = ((HwBpLength::Byte1 as u64) << 2) | (HwBpCondition::Execute as u64);
        assert_eq!(cond_len, 0b0000);

        // ReadWrite (11) + Byte8 (10) = 0b1011 = 11
        let cond_len = ((HwBpLength::Byte8 as u64) << 2) | (HwBpCondition::ReadWrite as u64);
        assert_eq!(cond_len, 0b1011);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_set_hardware_breakpoint_null_address() {
        let _ = initialize_debugger();

        // Setting breakpoint at null address should fail
        let result = set_hardware_breakpoint(0);
        assert!(result.is_err());

        let _ = cleanup_debugger();
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_set_hardware_breakpoint_unaligned() {
        let _ = initialize_debugger();

        // Unaligned address for 4-byte write breakpoint should fail
        let result = set_hardware_breakpoint(0x1001);
        assert!(result.is_err());

        let _ = cleanup_debugger();
    }

    #[test]
    fn test_rf_flag_constant() {
        // Resume Flag is bit 16 of EFLAGS
        assert_eq!(0x10000u32, 1 << 16);
    }
}
