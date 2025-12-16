//! DLL injection implementation using CreateRemoteThread + LoadLibrary
//!
//! Supports multiple attachment modes:
//! - Attach to running process by PID or name
//! - Wait for process to start
//! - Launch process (normal, suspended, debug mode)
//! - Delayed injection

use crate::process::{self, ProcessHandle};
use ghost_common::{AttachMode, ProcessStartMode};
use std::ffi::CString;
use std::path::Path;
use thiserror::Error;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS,
};

#[derive(Debug, Error)]
pub enum InjectorError {
    #[error("Failed to open process: {0}")]
    OpenProcess(String),
    #[error("Failed to allocate memory in target: {0}")]
    AllocMemory(String),
    #[error("Failed to write memory: {0}")]
    WriteMemory(String),
    #[error("Failed to create remote thread: {0}")]
    CreateThread(String),
    #[error("Failed to get LoadLibraryA address")]
    GetLoadLibrary,
    #[error("Process not found: {0}")]
    ProcessNotFound(String),
    #[error("Timeout waiting for process")]
    Timeout,
    #[error("Remote thread failed")]
    ThreadFailed,
    #[error("Process launch failed: {0}")]
    LaunchFailed(String),
    #[error("Process preparation failed: {0}")]
    PreparationFailed(String),
}

/// Find a process by name, return its PID
pub fn find_process_by_name(name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let exe_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr()).to_string_lossy();

                if exe_name.eq_ignore_ascii_case(name) {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        None
    }
}

/// Wait for a process to start
pub fn wait_for_process(name: &str, timeout_secs: u64) -> Result<u32, InjectorError> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    loop {
        if let Some(pid) = find_process_by_name(name) {
            return Ok(pid);
        }

        if start.elapsed() > timeout {
            return Err(InjectorError::Timeout);
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Inject a DLL into a process by PID
pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), InjectorError> {
    let dll_path_str = dll_path
        .canonicalize()
        .map_err(|e| InjectorError::OpenProcess(e.to_string()))?
        .to_string_lossy()
        .to_string();

    let dll_path_cstr = CString::new(dll_path_str.clone())
        .map_err(|e| InjectorError::OpenProcess(e.to_string()))?;
    let dll_path_bytes = dll_path_cstr.as_bytes_with_nul();

    unsafe {
        // Open target process
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| InjectorError::OpenProcess(e.to_string()))?;

        inject_dll_to_handle(process, dll_path_bytes, true)
    }
}

/// Inject a DLL into a process using an existing process handle
/// If close_handle is true, the handle will be closed after injection
unsafe fn inject_dll_to_handle(
    process: HANDLE,
    dll_path_bytes: &[u8],
    close_handle: bool,
) -> Result<(), InjectorError> {
    // Allocate memory in target for DLL path
    let remote_mem = VirtualAllocEx(
        process,
        None,
        dll_path_bytes.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if remote_mem.is_null() {
        if close_handle {
            let _ = CloseHandle(process);
        }
        return Err(InjectorError::AllocMemory("VirtualAllocEx failed".into()));
    }

    // Write DLL path to target
    let mut bytes_written = 0;
    let write_result = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
        process,
        remote_mem,
        dll_path_bytes.as_ptr() as *const _,
        dll_path_bytes.len(),
        Some(&mut bytes_written),
    );

    if write_result.is_err() || bytes_written != dll_path_bytes.len() {
        let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        if close_handle {
            let _ = CloseHandle(process);
        }
        return Err(InjectorError::WriteMemory(
            "WriteProcessMemory failed".into(),
        ));
    }

    // Get LoadLibraryA address
    let kernel32 = GetModuleHandleA(windows::core::s!("kernel32.dll"))
        .map_err(|_| InjectorError::GetLoadLibrary)?;

    let load_library = GetProcAddress(kernel32, windows::core::s!("LoadLibraryA"))
        .ok_or(InjectorError::GetLoadLibrary)?;

    // Create remote thread to call LoadLibraryA
    let thread = CreateRemoteThread(
        process,
        None,
        0,
        Some(std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
        >(load_library)),
        Some(remote_mem),
        0,
        None,
    )
    .map_err(|e| InjectorError::CreateThread(e.to_string()))?;

    // Wait for thread to complete
    let wait_result = WaitForSingleObject(thread, INFINITE);

    // Cleanup
    let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    let _ = CloseHandle(thread);
    if close_handle {
        let _ = CloseHandle(process);
    }

    if wait_result != WAIT_OBJECT_0 {
        return Err(InjectorError::ThreadFailed);
    }

    Ok(())
}

/// Result of an attach operation
pub struct AttachResult {
    /// Process ID
    pub pid: u32,
    /// Optional process handle (for launched processes that may need cleanup)
    #[allow(dead_code)]
    pub process_handle: Option<ProcessHandle>,
    /// Whether the process was launched by us
    pub launched: bool,
}

/// Attach to a process and inject DLL using the specified attach mode
pub fn attach_and_inject(
    mode: &AttachMode,
    dll_path: &Path,
) -> Result<AttachResult, InjectorError> {
    let dll_path_str = dll_path
        .canonicalize()
        .map_err(|e| InjectorError::OpenProcess(e.to_string()))?
        .to_string_lossy()
        .to_string();

    let dll_path_cstr =
        CString::new(dll_path_str).map_err(|e| InjectorError::OpenProcess(e.to_string()))?;
    let dll_path_bytes = dll_path_cstr.as_bytes_with_nul();

    match mode {
        AttachMode::Pid(pid) => {
            inject_dll(*pid, dll_path)?;
            Ok(AttachResult {
                pid: *pid,
                process_handle: None,
                launched: false,
            })
        }

        AttachMode::ProcessName(name) => {
            let pid = find_process_by_name(name)
                .ok_or_else(|| InjectorError::ProcessNotFound(name.clone()))?;
            inject_dll(pid, dll_path)?;
            Ok(AttachResult {
                pid,
                process_handle: None,
                launched: false,
            })
        }

        AttachMode::WaitForProcess {
            name,
            timeout_secs,
            attach_delay_ms,
        } => {
            println!("Waiting for process '{}'...", name);
            let timeout = timeout_secs.unwrap_or(u64::MAX);
            let pid = wait_for_process(name, timeout)?;

            // Apply attach delay if specified
            if let Some(delay) = attach_delay_ms {
                println!("Waiting {}ms before injection...", delay);
                std::thread::sleep(std::time::Duration::from_millis(*delay));
            }

            inject_dll(pid, dll_path)?;
            Ok(AttachResult {
                pid,
                process_handle: None,
                launched: false,
            })
        }

        AttachMode::Launch(config) => {
            println!("Launching process: {}", config.executable);

            // Launch the process
            let mut handle = process::launch_process(config)
                .map_err(|e| InjectorError::LaunchFailed(e.to_string()))?;

            println!("Process launched with PID: {}", handle.pid);

            // Prepare for injection based on start mode
            let needs_resume_after = matches!(config.start_mode, ProcessStartMode::Suspended);

            process::prepare_for_injection(&mut handle, config)
                .map_err(|e| InjectorError::PreparationFailed(e.to_string()))?;

            // Apply additional injection delay if specified
            if let Some(delay) = config.inject_delay_ms {
                println!("Waiting {}ms before injection...", delay);
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }

            // Inject the DLL
            println!("Injecting DLL...");
            unsafe {
                inject_dll_to_handle(handle.process, dll_path_bytes, false)?;
            }

            // Resume if we started suspended
            if needs_resume_after {
                println!("Resuming suspended process...");
                handle
                    .resume()
                    .map_err(|e| InjectorError::PreparationFailed(e.to_string()))?;
            }

            // Detach debugger if attached
            if let Err(e) = handle.detach_debugger() {
                eprintln!("Warning: Failed to detach debugger: {}", e);
            }

            let pid = handle.pid;
            Ok(AttachResult {
                pid,
                process_handle: Some(handle),
                launched: true,
            })
        }
    }
}

/// Convenience function for delayed attach with retries
pub fn attach_with_retry(
    mode: &AttachMode,
    dll_path: &Path,
    max_retries: u32,
    retry_delay_ms: u64,
) -> Result<AttachResult, InjectorError> {
    let mut last_error = None;

    for attempt in 0..=max_retries {
        if attempt > 0 {
            println!("Retry attempt {} of {}...", attempt, max_retries);
            std::thread::sleep(std::time::Duration::from_millis(retry_delay_ms));
        }

        match attach_and_inject(mode, dll_path) {
            Ok(result) => return Ok(result),
            Err(e) => {
                eprintln!("Attempt {} failed: {}", attempt + 1, e);
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or(InjectorError::Timeout))
}
