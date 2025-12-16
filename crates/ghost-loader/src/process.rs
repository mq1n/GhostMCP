//! Process launching and management for Ghost-MCP
//!
//! Provides functionality to launch processes with various start modes,
//! wait for processes, and manage process state for injection.

use ghost_common::{LaunchResult, ProcessLaunchConfig, ProcessStartMode};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use thiserror::Error;
use windows::Win32::Foundation::DBG_CONTINUE;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, WaitForDebugEvent, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED, DEBUG_PROCESS,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("Failed to create process: {0}")]
    CreateProcess(String),
    #[error("Failed to resume thread: {0}")]
    ResumeThread(String),
    #[error("Timeout waiting for module: {0}")]
    ModuleTimeout(String),
    #[error("Process exited unexpectedly")]
    ProcessExited,
    #[error("Debug event error: {0}")]
    DebugError(String),
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Handle to a launched process that may need cleanup
pub struct ProcessHandle {
    pub process: HANDLE,
    pub thread: HANDLE,
    pub pid: u32,
    pub tid: u32,
    pub suspended: bool,
    debug_attached: bool,
}

impl ProcessHandle {
    /// Resume the main thread if suspended
    pub fn resume(&mut self) -> Result<(), ProcessError> {
        if self.suspended {
            unsafe {
                let result = ResumeThread(self.thread);
                if result == u32::MAX {
                    return Err(ProcessError::ResumeThread(
                        "ResumeThread returned -1".into(),
                    ));
                }
                self.suspended = false;
            }
        }
        Ok(())
    }

    /// Detach debugger if attached
    pub fn detach_debugger(&mut self) -> Result<(), ProcessError> {
        if self.debug_attached {
            unsafe {
                // Detach by calling DebugActiveProcessStop
                let result =
                    windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop(self.pid);
                if result.is_err() {
                    // Not critical, just log
                    eprintln!("Warning: Failed to detach debugger");
                }
                self.debug_attached = false;
            }
        }
        Ok(())
    }

    /// Get the LaunchResult for this process
    pub fn to_launch_result(&self) -> LaunchResult {
        LaunchResult {
            pid: self.pid,
            tid: self.tid,
            suspended: self.suspended,
            main_module_base: None,
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.thread.is_invalid() {
                let _ = CloseHandle(self.thread);
            }
            if !self.process.is_invalid() {
                let _ = CloseHandle(self.process);
            }
        }
    }
}

/// Launch a process with the given configuration
pub fn launch_process(config: &ProcessLaunchConfig) -> Result<ProcessHandle, ProcessError> {
    let exe_path = Path::new(&config.executable);
    if !exe_path.exists() {
        return Err(ProcessError::InvalidPath(format!(
            "Executable not found: {}",
            config.executable
        )));
    }

    // Build command line
    let mut cmd_line = format!("\"{}\"", config.executable);
    for arg in &config.args {
        cmd_line.push(' ');
        if arg.contains(' ') {
            cmd_line.push('"');
            cmd_line.push_str(arg);
            cmd_line.push('"');
        } else {
            cmd_line.push_str(arg);
        }
    }

    // Convert to wide string
    let cmd_line_wide: Vec<u16> = OsStr::new(&cmd_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Working directory
    let working_dir_wide: Option<Vec<u16>> = config.working_dir.as_ref().map(|dir| {
        OsStr::new(dir)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    });

    // Determine creation flags based on start mode
    let (creation_flags, suspended, debug_attached) = match &config.start_mode {
        ProcessStartMode::Normal => (PROCESS_CREATION_FLAGS(0), false, false),
        ProcessStartMode::Suspended => (CREATE_SUSPENDED, true, false),
        ProcessStartMode::WaitForMainModule => (CREATE_SUSPENDED, true, false),
        ProcessStartMode::Delayed { .. } => (PROCESS_CREATION_FLAGS(0), false, false),
        ProcessStartMode::Debug => (DEBUG_PROCESS, false, true),
        ProcessStartMode::WaitForModule { .. } => (CREATE_SUSPENDED, true, false),
    };

    unsafe {
        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };

        let mut process_info = PROCESS_INFORMATION::default();

        let result = CreateProcessW(
            None,
            windows::core::PWSTR(cmd_line_wide.as_ptr() as *mut u16),
            None,
            None,
            false,
            creation_flags,
            None,
            working_dir_wide
                .as_ref()
                .map(|v| windows::core::PCWSTR(v.as_ptr()))
                .unwrap_or(windows::core::PCWSTR::null()),
            &startup_info,
            &mut process_info,
        );

        if result.is_err() {
            return Err(ProcessError::CreateProcess(format!(
                "CreateProcessW failed: {:?}",
                result
            )));
        }

        let handle = ProcessHandle {
            process: process_info.hProcess,
            thread: process_info.hThread,
            pid: process_info.dwProcessId,
            tid: process_info.dwThreadId,
            suspended,
            debug_attached,
        };

        Ok(handle)
    }
}

/// Wait for a specific module to be loaded in the process
pub fn wait_for_module(
    pid: u32,
    module_name: &str,
    timeout_ms: u64,
) -> Result<usize, ProcessError> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let module_name_lower = module_name.to_lowercase();

    loop {
        if start.elapsed() > timeout {
            return Err(ProcessError::ModuleTimeout(module_name.to_string()));
        }

        if let Some(base) = find_module_in_process(pid, &module_name_lower) {
            return Ok(base);
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Find a module in a process by name, return its base address
fn find_module_in_process(pid: u32, module_name: &str) -> Option<usize> {
    unsafe {
        let snapshot =
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid).ok()?;

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name_len = entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szModule.len());
                let name = String::from_utf16_lossy(&entry.szModule[..name_len]);

                if name.to_lowercase() == module_name {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.modBaseAddr as usize);
                }

                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        None
    }
}

/// Wait for the main module to be fully loaded (process initialization complete)
pub fn wait_for_main_module(
    handle: &ProcessHandle,
    timeout_ms: u64,
) -> Result<usize, ProcessError> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    loop {
        if start.elapsed() > timeout {
            return Err(ProcessError::ModuleTimeout("main module".to_string()));
        }

        // Check if process is still alive
        unsafe {
            let wait_result = WaitForSingleObject(handle.process, 0);
            if wait_result == WAIT_OBJECT_0 {
                return Err(ProcessError::ProcessExited);
            }
        }

        // Try to get any module - if we can enumerate modules, process is initialized
        unsafe {
            let snapshot =
                CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, handle.pid);

            if let Ok(snapshot) = snapshot {
                let mut entry = MODULEENTRY32W {
                    dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                    ..Default::default()
                };

                if Module32FirstW(snapshot, &mut entry).is_ok() {
                    let base = entry.modBaseAddr as usize;
                    let _ = CloseHandle(snapshot);
                    return Ok(base);
                }

                let _ = CloseHandle(snapshot);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Handle debug events for a process started with DEBUG_PROCESS
/// Returns when process hits initial breakpoint or specified event
pub fn handle_debug_until_ready(
    handle: &mut ProcessHandle,
    timeout_ms: u64,
) -> Result<(), ProcessError> {
    if !handle.debug_attached {
        return Ok(());
    }

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    unsafe {
        loop {
            if start.elapsed() > timeout {
                return Err(ProcessError::DebugError(
                    "Timeout waiting for debug event".into(),
                ));
            }

            let mut debug_event = DEBUG_EVENT::default();
            let remaining = timeout.saturating_sub(start.elapsed());
            let wait_ms = remaining.as_millis().min(100) as u32;

            let result = WaitForDebugEvent(&mut debug_event, wait_ms);

            if result.is_ok() {
                let event_code = debug_event.dwDebugEventCode;

                // Continue the debug event
                let _ = ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    DBG_CONTINUE,
                );

                // Check for process exit
                if event_code == EXIT_PROCESS_DEBUG_EVENT {
                    return Err(ProcessError::ProcessExited);
                }

                // For EXCEPTION_DEBUG_EVENT with initial breakpoint, we're ready
                if event_code == EXCEPTION_DEBUG_EVENT {
                    // Initial breakpoint hit - process is ready
                    return Ok(());
                }
            }
        }
    }
}

/// Prepare a launched process for injection based on its start mode
/// This handles all the waiting/synchronization needed before injection
pub fn prepare_for_injection(
    handle: &mut ProcessHandle,
    config: &ProcessLaunchConfig,
) -> Result<(), ProcessError> {
    match &config.start_mode {
        ProcessStartMode::Normal => {
            // Nothing to do, inject immediately
            Ok(())
        }
        ProcessStartMode::Suspended => {
            // Process is suspended, inject will happen before resume
            Ok(())
        }
        ProcessStartMode::WaitForMainModule => {
            // Resume, wait for main module, then inject
            handle.resume()?;
            wait_for_main_module(handle, 30000)?;
            Ok(())
        }
        ProcessStartMode::Delayed { delay_ms } => {
            // Wait the specified delay
            std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
            Ok(())
        }
        ProcessStartMode::Debug => {
            // Handle debug events until ready
            handle_debug_until_ready(handle, 30000)?;
            Ok(())
        }
        ProcessStartMode::WaitForModule {
            module_name,
            timeout_ms,
        } => {
            // Resume, wait for specific module
            handle.resume()?;
            wait_for_module(handle.pid, module_name, *timeout_ms)?;
            Ok(())
        }
    }
}

/// Check if a process is still running
pub fn is_process_running(pid: u32) -> bool {
    unsafe {
        let process = windows::Win32::System::Threading::OpenProcess(
            windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        );

        if let Ok(process) = process {
            let result = WaitForSingleObject(process, 0);
            let _ = CloseHandle(process);
            // WAIT_TIMEOUT means the process is still running (didn't exit within timeout)
            // WAIT_OBJECT_0 means the process has exited
            result != WAIT_OBJECT_0
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_process_running_self() {
        let pid = std::process::id();
        assert!(is_process_running(pid));
    }

    #[test]
    fn test_is_process_running_invalid() {
        assert!(!is_process_running(0));
        assert!(!is_process_running(u32::MAX));
    }

    #[test]
    fn test_process_launch_config_builder() {
        let config = ProcessLaunchConfig::new("test.exe")
            .with_args(vec!["--arg1".to_string(), "--arg2".to_string()])
            .with_working_dir("C:\\test")
            .with_start_mode(ProcessStartMode::Suspended)
            .with_inject_delay(1000);

        assert_eq!(config.executable, "test.exe");
        assert_eq!(config.args.len(), 2);
        assert_eq!(config.working_dir, Some("C:\\test".to_string()));
        assert_eq!(config.start_mode, ProcessStartMode::Suspended);
        assert_eq!(config.inject_delay_ms, Some(1000));
    }

    #[test]
    fn test_process_start_mode_default() {
        let mode = ProcessStartMode::default();
        assert_eq!(mode, ProcessStartMode::Normal);
    }

    #[test]
    fn test_launch_result_fields() {
        let result = LaunchResult {
            pid: 1234,
            tid: 5678,
            suspended: true,
            main_module_base: Some(0x140000000),
        };

        assert_eq!(result.pid, 1234);
        assert_eq!(result.tid, 5678);
        assert!(result.suspended);
        assert_eq!(result.main_module_base, Some(0x140000000));
    }

    #[test]
    fn test_process_error_display() {
        let err = ProcessError::CreateProcess("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let err = ProcessError::ModuleTimeout("kernel32.dll".to_string());
        assert!(err.to_string().contains("kernel32.dll"));

        let err = ProcessError::ProcessExited;
        assert!(err.to_string().contains("exited"));
    }

    #[test]
    fn test_launch_process_invalid_path() {
        let config = ProcessLaunchConfig::new("nonexistent_file_that_does_not_exist.exe");
        let result = launch_process(&config);
        assert!(result.is_err());
    }
}
