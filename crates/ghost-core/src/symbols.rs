//! Symbol loading and resolution via DbgHelp
//!
//! Provides PDB symbol loading functionality for enhanced debugging and analysis.

use ghost_common::{Error, Result, StackFrame};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::Debug::{
    StackWalk64, SymCleanup, SymFromAddr, SymFromName, SymFunctionTableAccess64,
    SymGetModuleBase64, SymInitialize, SymLoadModuleEx, SymSetOptions, ADDRESS_MODE, STACKFRAME64,
    SYMBOL_INFO, SYMOPT_DEFERRED_LOADS, SYMOPT_LOAD_LINES, SYMOPT_UNDNAME, SYM_LOAD_FLAGS,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Global flag to track if DbgHelp has been initialized
static DBGHELP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Mutex to protect DbgHelp operations (it's not thread-safe)
static DBGHELP_LOCK: Mutex<()> = Mutex::new(());

/// Symbol information result
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub address: usize,
    pub displacement: u64,
    pub module_base: usize,
}

/// Initialize DbgHelp for the current process
pub fn initialize() -> Result<()> {
    let _lock = DBGHELP_LOCK
        .lock()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    if DBGHELP_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    unsafe {
        let process = GetCurrentProcess();

        // Set symbol options
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

        // Initialize symbol handler
        if SymInitialize(process, PCSTR::null(), true).is_err() {
            return Err(Error::Internal("Failed to initialize DbgHelp".into()));
        }

        DBGHELP_INITIALIZED.store(true, Ordering::SeqCst);
        tracing::info!(target: "ghost_core::symbols", "DbgHelp initialized");
    }

    Ok(())
}

/// Cleanup DbgHelp resources
pub fn cleanup() -> Result<()> {
    let _lock = DBGHELP_LOCK
        .lock()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    if !DBGHELP_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    unsafe {
        let process = GetCurrentProcess();
        let _ = SymCleanup(process);
        DBGHELP_INITIALIZED.store(false, Ordering::SeqCst);
        tracing::info!(target: "ghost_core::symbols", "DbgHelp cleaned up");
    }

    Ok(())
}

/// Load symbols for a module
///
/// Note: Symbol path is set via _NT_SYMBOL_PATH environment variable or
/// passed to SymInitialize. DbgHelp uses system defaults if not set.
pub fn load_module(module_base: usize, module_size: usize, _module_name: &str) -> Result<u64> {
    let _lock = DBGHELP_LOCK
        .lock()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    ensure_initialized()?;

    unsafe {
        let process = GetCurrentProcess();
        let base = SymLoadModuleEx(
            process,
            HANDLE::default(),
            PCSTR::null(),
            PCSTR::null(),
            module_base as u64,
            module_size as u32,
            None,
            SYM_LOAD_FLAGS(0),
        );

        if base == 0 {
            tracing::warn!(target: "ghost_core::symbols", 
                base = format!("0x{:x}", module_base),
                "Module symbols may already be loaded or not available");
        } else {
            tracing::info!(target: "ghost_core::symbols", 
                base = format!("0x{:x}", module_base),
                "Loaded symbols");
        }

        Ok(base)
    }
}

/// Resolve an address to a symbol name
pub fn resolve_address(addr: usize) -> Result<Option<SymbolInfo>> {
    let _lock = DBGHELP_LOCK
        .lock()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    ensure_initialized()?;

    unsafe {
        let process = GetCurrentProcess();

        // Allocate buffer for SYMBOL_INFO
        // SYMBOL_INFO has a Name[1] array at the end, so we need extra space for the name
        let buffer_size = std::mem::size_of::<SYMBOL_INFO>() + MAX_PATH as usize;
        let mut buffer = vec![0u8; buffer_size];
        let symbol = buffer.as_mut_ptr() as *mut SYMBOL_INFO;
        (*symbol).SizeOfStruct = std::mem::size_of::<SYMBOL_INFO>() as u32;
        (*symbol).MaxNameLen = MAX_PATH;

        let mut displacement: u64 = 0;

        if SymFromAddr(process, addr as u64, Some(&mut displacement), symbol).is_ok() {
            // Read the symbol name
            let name_ptr = (*symbol).Name.as_ptr();
            let name_len = (*symbol).NameLen as usize;
            let name_bytes: Vec<u8> = (0..name_len.min(MAX_PATH as usize))
                .map(|i| *name_ptr.add(i) as u8)
                .collect();
            let name = String::from_utf8_lossy(&name_bytes).to_string();

            Ok(Some(SymbolInfo {
                name,
                address: (*symbol).Address as usize,
                displacement,
                module_base: (*symbol).ModBase as usize,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Resolve a symbol name to an address
pub fn resolve_symbol_name(name: &str) -> Result<Option<SymbolInfo>> {
    let _lock = DBGHELP_LOCK
        .lock()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    ensure_initialized()?;

    unsafe {
        let process = GetCurrentProcess();

        // Allocate buffer for SYMBOL_INFO
        let buffer_size = std::mem::size_of::<SYMBOL_INFO>() + MAX_PATH as usize;
        let mut buffer = vec![0u8; buffer_size];
        let symbol = buffer.as_mut_ptr() as *mut SYMBOL_INFO;
        (*symbol).SizeOfStruct = std::mem::size_of::<SYMBOL_INFO>() as u32;
        (*symbol).MaxNameLen = MAX_PATH;

        let name_c = std::ffi::CString::new(name)
            .map_err(|e| Error::Internal(format!("Invalid symbol name: {}", e)))?;
        let name_pcstr = PCSTR::from_raw(name_c.as_ptr() as *const u8);

        if SymFromName(process, name_pcstr, symbol).is_ok() {
            // Read the symbol name
            let name_ptr = (*symbol).Name.as_ptr();
            let name_len = (*symbol).NameLen as usize;
            let name_bytes: Vec<u8> = (0..name_len.min(MAX_PATH as usize))
                .map(|i| *name_ptr.add(i) as u8)
                .collect();
            let resolved_name = String::from_utf8_lossy(&name_bytes).to_string();

            Ok(Some(SymbolInfo {
                name: resolved_name,
                address: (*symbol).Address as usize,
                displacement: 0,
                module_base: (*symbol).ModBase as usize,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Get symbol name for an address (simple version)
pub fn get_symbol_name(addr: usize) -> Option<String> {
    resolve_address(addr).ok().flatten().map(|s| {
        if s.displacement > 0 {
            format!("{}+0x{:x}", s.name, s.displacement)
        } else {
            s.name
        }
    })
}

/// Walk the stack using DbgHelp StackWalk64
#[cfg(target_arch = "x86_64")]
pub fn stack_walk_dbghelp(
    thread_handle: HANDLE,
    context: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
) -> Result<Vec<StackFrame>> {
    let _lock = DBGHELP_LOCK
        .lock()
        .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?;

    ensure_initialized()?;

    let mut frames = Vec::new();
    let max_frames = 64;

    unsafe {
        let process = GetCurrentProcess();

        // Initialize stack frame
        let mut stack_frame = STACKFRAME64::default();
        stack_frame.AddrPC.Offset = context.Rip;
        stack_frame.AddrPC.Mode = ADDRESS_MODE(3); // AddrModeFlat
        stack_frame.AddrFrame.Offset = context.Rbp;
        stack_frame.AddrFrame.Mode = ADDRESS_MODE(3);
        stack_frame.AddrStack.Offset = context.Rsp;
        stack_frame.AddrStack.Mode = ADDRESS_MODE(3);

        // Create mutable context copy
        let mut ctx = *context;

        for index in 0..max_frames {
            // IMAGE_FILE_MACHINE_AMD64 = 0x8664
            let result = StackWalk64(
                0x8664,
                process,
                thread_handle,
                &mut stack_frame,
                &mut ctx as *mut _ as *mut c_void,
                None,
                Some(sym_function_table_access_wrapper),
                Some(sym_get_module_base_wrapper),
                None,
            );

            if !result.as_bool() || stack_frame.AddrPC.Offset == 0 {
                break;
            }

            let symbol_name = get_symbol_name(stack_frame.AddrPC.Offset as usize);
            let module_base = SymGetModuleBase64(process, stack_frame.AddrPC.Offset);

            frames.push(StackFrame {
                index: index as u32,
                address: stack_frame.AddrPC.Offset as usize,
                return_address: stack_frame.AddrReturn.Offset as usize,
                symbol: symbol_name,
                module: if module_base != 0 {
                    Some(format!("0x{:x}", module_base))
                } else {
                    None
                },
            });
        }
    }

    Ok(frames)
}

/// Wrapper for SymFunctionTableAccess64 with correct calling convention
#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn sym_function_table_access_wrapper(
    h_process: HANDLE,
    addr_base: u64,
) -> *mut c_void {
    SymFunctionTableAccess64(h_process, addr_base)
}

/// Wrapper for SymGetModuleBase64 with correct calling convention
#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn sym_get_module_base_wrapper(h_process: HANDLE, addr: u64) -> u64 {
    SymGetModuleBase64(h_process, addr)
}

/// Ensure DbgHelp is initialized
fn ensure_initialized() -> Result<()> {
    if !DBGHELP_INITIALIZED.load(Ordering::SeqCst) {
        return Err(Error::Internal(
            "DbgHelp not initialized. Call symbols::initialize() first.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_cleanup() {
        // Initialize should succeed
        assert!(initialize().is_ok());

        // Second initialize should be no-op
        assert!(initialize().is_ok());

        // Cleanup should succeed
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_symbol_info_structure() {
        let info = SymbolInfo {
            name: "TestSymbol".to_string(),
            address: 0x140001000,
            displacement: 0x10,
            module_base: 0x140000000,
        };
        assert_eq!(info.name, "TestSymbol");
        assert_eq!(info.address, 0x140001000);
        assert_eq!(info.displacement, 0x10);
        assert_eq!(info.module_base, 0x140000000);
    }

    #[test]
    fn test_get_symbol_name_formats_displacement() {
        // This tests the formatting logic - actual symbol resolution requires DbgHelp init
        let info = SymbolInfo {
            name: "TestFunc".to_string(),
            address: 0x1000,
            displacement: 0x20,
            module_base: 0,
        };

        // Test the formatting that get_symbol_name would produce
        let formatted = if info.displacement > 0 {
            format!("{}+0x{:x}", info.name, info.displacement)
        } else {
            info.name.clone()
        };
        assert_eq!(formatted, "TestFunc+0x20");
    }

    #[test]
    fn test_ensure_initialized_fails_without_init() {
        // Clean up first to ensure we're in uninitialized state
        let _ = cleanup();

        // Should fail because not initialized
        let result = ensure_initialized();
        assert!(result.is_err());
    }

    #[test]
    fn test_load_module_requires_init() {
        // Clean up first
        let _ = cleanup();

        // Should fail because not initialized
        let result = load_module(0x140000000, 0x10000, "test.dll");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_address_requires_init() {
        // Clean up first
        let _ = cleanup();

        // Should fail because not initialized
        let result = resolve_address(0x140001000);
        assert!(result.is_err());
    }
}
