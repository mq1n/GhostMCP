//! Process & System Introspection
//!
//! Comprehensive system introspection including:
//! - Process management and PEB access
//! - Thread management and TEB access
//! - Module load/unload monitoring
//! - Handle enumeration and management
//! - Window enumeration and manipulation
//! - Section and token management

use ghost_common::{
    Error, HandleFilter, HandleInfo, IntegrityLevel, ModuleDetails, PebInfo, PrivilegeRequest,
    ProcessDetails, ProcessMemoryMapEntry, RegionState, RegionType, Result, SectionInfo, TebInfo,
    ThreadDetails, ThreadExecutionState, TlsSlot, TokenInfo, TokenPrivilege, TokenType,
    WindowFilter, WindowInfo, WindowRect, WorkingDirectoryResult,
};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, HANDLE, HMODULE, HWND, LPARAM, LUID, MAX_PATH, RECT,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupAccountSidW, LookupPrivilegeNameW,
    LookupPrivilegeValueW, TokenElevation, TokenPrivileges, TokenUser, SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED,
    MEM_PRIVATE, MEM_RESERVE,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, IsWow64Process, OpenProcess,
    OpenProcessToken, OpenThread, OpenThreadToken, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    THREAD_QUERY_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetClassNameW, GetClientRect, GetParent, GetWindowLongW,
    GetWindowRect, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic,
    IsWindow, IsWindowVisible, IsZoomed, GWL_EXSTYLE, GWL_STYLE,
};

// ============================================================================
// Process Management
// ============================================================================

/// Get detailed process information for the current process
pub fn get_current_process_details() -> Result<ProcessDetails> {
    get_process_details(unsafe { GetCurrentProcessId() })
}

/// Get detailed process information for a specific process
pub fn get_process_details(pid: u32) -> Result<ProcessDetails> {
    trace!("Getting process details for PID {}", pid);

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| Error::Internal(format!("OpenProcess failed: {}", e)))?;

        let mut process_info = ProcessDetails {
            pid,
            name: String::new(),
            parent_pid: None,
            path: None,
            command_line: None,
            working_directory: None,
            environment: Vec::new(),
            arch: String::from("x64"),
            is_64bit: true,
            creation_time: None,
            session_id: 0,
            thread_count: 0,
            handle_count: 0,
            peb_address: None,
            image_base: None,
            priority_class: None,
            being_debugged: false,
        };

        // Check if WoW64 (32-bit on 64-bit)
        let mut is_wow64: BOOL = BOOL(0);
        if IsWow64Process(handle, &mut is_wow64).is_ok() {
            process_info.is_64bit = is_wow64.0 == 0;
            process_info.arch = if is_wow64.0 != 0 {
                "x86".to_string()
            } else {
                "x64".to_string()
            };
        }

        // Get module path
        let mut path_buf = [0u16; MAX_PATH as usize];
        let len = GetModuleFileNameExW(handle, HMODULE::default(), &mut path_buf);
        if len > 0 {
            let path = String::from_utf16_lossy(&path_buf[..len as usize]);
            process_info.path = Some(path.clone());
            process_info.name = std::path::Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
        }

        // Get thread and handle counts from snapshot
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if let Ok(snap) = snapshot {
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        process_info.thread_count += 1;
                    }
                    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }

        let _ = CloseHandle(handle);
        debug!(
            "Got process details for PID {}: {:?}",
            pid, process_info.name
        );
        Ok(process_info)
    }
}

/// Enumerate all running processes
pub fn enumerate_processes() -> Result<Vec<ProcessDetails>> {
    trace!("Enumerating all processes");

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        let mut processes = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                processes.push(ProcessDetails {
                    pid: entry.th32ProcessID,
                    name,
                    parent_pid: Some(entry.th32ParentProcessID),
                    path: None,
                    command_line: None,
                    working_directory: None,
                    environment: Vec::new(),
                    arch: "unknown".to_string(),
                    is_64bit: true,
                    creation_time: None,
                    session_id: 0,
                    thread_count: entry.cntThreads,
                    handle_count: 0,
                    peb_address: None,
                    image_base: None,
                    priority_class: Some(entry.pcPriClassBase as u32),
                    being_debugged: false,
                });

                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        info!("Enumerated {} processes", processes.len());
        Ok(processes)
    }
}

/// Get PEB information for the current process
/// Note: Uses direct memory access for current process only
pub fn get_peb_info() -> Result<PebInfo> {
    trace!("Getting PEB info for current process");

    unsafe {
        // Get PEB address via TEB for current process
        let teb_ptr: *const u8;
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb_ptr);
        }
        #[cfg(target_arch = "x86")]
        {
            std::arch::asm!("mov {}, fs:[0x18]", out(reg) teb_ptr);
        }

        let peb_addr = *(teb_ptr.add(0x60) as *const usize);
        let peb_ptr = peb_addr as *const u8;

        let peb_info = PebInfo {
            address: peb_addr,
            being_debugged: *peb_ptr.add(2) != 0,
            image_base: *(peb_ptr.add(0x10) as *const usize),
            ldr_address: *(peb_ptr.add(0x18) as *const usize),
            process_parameters: *(peb_ptr.add(0x20) as *const usize),
            nt_global_flag: *(peb_ptr.add(0xBC) as *const u32),
            process_heap: *(peb_ptr.add(0x30) as *const usize),
            fast_peb_lock: *(peb_ptr.add(0x38) as *const usize),
            number_of_processors: *(peb_ptr.add(0xB8) as *const u32),
            session_id: *(peb_ptr.add(0x2C0) as *const u32),
            os_major_version: *(peb_ptr.add(0x118) as *const u32),
            os_minor_version: *(peb_ptr.add(0x11C) as *const u32),
            os_build_number: *(peb_ptr.add(0x120) as *const u16),
        };

        debug!("Got PEB info: address=0x{:X}", peb_addr);
        Ok(peb_info)
    }
}

/// Get PEB information for a specific process (current process only supported)
pub fn get_peb_info_for_process(pid: u32) -> Result<PebInfo> {
    let current_pid = unsafe { GetCurrentProcessId() };
    if pid != current_pid {
        return Err(Error::Internal(
            "PEB access for remote processes requires NtQueryInformationProcess (not available)"
                .into(),
        ));
    }
    get_peb_info()
}

/// Get process memory map
pub fn get_process_memory_map(pid: u32) -> Result<Vec<ProcessMemoryMapEntry>> {
    trace!("Getting memory map for PID {}", pid);

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| Error::Internal(format!("OpenProcess failed: {}", e)))?;

        let mut entries = Vec::new();
        let mut address: usize = 0;

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            let state = match mbi.State {
                MEM_COMMIT => RegionState::Commit,
                MEM_RESERVE => RegionState::Reserve,
                MEM_FREE => RegionState::Free,
                _ => RegionState::Free,
            };

            let memory_type = match mbi.Type {
                MEM_IMAGE => RegionType::Image,
                MEM_MAPPED => RegionType::Mapped,
                MEM_PRIVATE => RegionType::Private,
                _ => RegionType::Unknown,
            };

            let protection = format_protection(mbi.Protect.0);

            entries.push(ProcessMemoryMapEntry {
                base_address: mbi.BaseAddress as usize,
                size: mbi.RegionSize,
                protection,
                state,
                memory_type,
                module_name: None, // Would need module enumeration to fill
            });

            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break;
            }
        }

        let _ = CloseHandle(handle);
        info!("Got {} memory regions for PID {}", entries.len(), pid);
        Ok(entries)
    }
}

/// Format protection flags as string
fn format_protection(protect: u32) -> String {
    let mut result = String::new();

    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_WRITECOPY: u32 = 0x08;
    const PAGE_GUARD: u32 = 0x100;

    match protect & 0xFF {
        PAGE_NOACCESS => result.push_str("---"),
        PAGE_READONLY => result.push_str("R--"),
        PAGE_READWRITE => result.push_str("RW-"),
        PAGE_WRITECOPY => result.push_str("RC-"),
        PAGE_EXECUTE => result.push_str("--X"),
        PAGE_EXECUTE_READ => result.push_str("R-X"),
        PAGE_EXECUTE_READWRITE => result.push_str("RWX"),
        PAGE_EXECUTE_WRITECOPY => result.push_str("RCX"),
        _ => result.push_str("???"),
    }

    if protect & PAGE_GUARD != 0 {
        result.push_str("+G");
    }

    result
}

/// Get environment variables for current process
pub fn get_environment_variables() -> Result<Vec<(String, String)>> {
    Ok(std::env::vars().collect())
}

/// Get current working directory
pub fn get_working_directory() -> Result<String> {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| Error::Internal(format!("Failed to get current directory: {}", e)))
}

/// Set current working directory
pub fn set_working_directory(path: &str) -> Result<WorkingDirectoryResult> {
    let previous = get_working_directory()?;
    std::env::set_current_dir(path)
        .map_err(|e| Error::Internal(format!("Failed to set directory: {}", e)))?;
    let current = get_working_directory()?;
    Ok(WorkingDirectoryResult { previous, current })
}

// ============================================================================
// Thread Management
// ============================================================================

/// Get detailed thread information
pub fn get_thread_details(tid: u32) -> Result<ThreadDetails> {
    trace!("Getting thread details for TID {}", tid);

    unsafe {
        let handle = OpenThread(THREAD_QUERY_INFORMATION, false, tid)
            .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

        // Get basic info from toolhelp
        let _current_pid = GetCurrentProcessId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        let mut thread_info = ThreadDetails {
            tid,
            pid: 0,
            state: ThreadExecutionState::Unknown,
            wait_reason: None,
            priority: 0,
            base_priority: 0,
            start_address: None,
            teb_address: None,
            creation_time: None,
            kernel_time: 0,
            user_time: 0,
            suspend_count: 0,
            is_main_thread: false,
        };

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ThreadID == tid {
                    thread_info.pid = entry.th32OwnerProcessID;
                    thread_info.base_priority = entry.tpBasePri;
                    thread_info.priority = entry.tpDeltaPri + entry.tpBasePri;
                    break;
                }
                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        let _ = CloseHandle(handle);

        debug!("Got thread details for TID {}", tid);
        Ok(thread_info)
    }
}

/// Enumerate all threads for a process
pub fn enumerate_threads_detailed(pid: u32) -> Result<Vec<ThreadDetails>> {
    trace!("Enumerating threads for PID {}", pid);

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        let mut threads = Vec::new();
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut first_thread = true;
        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    threads.push(ThreadDetails {
                        tid: entry.th32ThreadID,
                        pid,
                        state: ThreadExecutionState::Unknown,
                        wait_reason: None,
                        priority: entry.tpDeltaPri + entry.tpBasePri,
                        base_priority: entry.tpBasePri,
                        start_address: None,
                        teb_address: None,
                        creation_time: None,
                        kernel_time: 0,
                        user_time: 0,
                        suspend_count: 0,
                        is_main_thread: first_thread,
                    });
                    first_thread = false;
                }

                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        info!("Enumerated {} threads for PID {}", threads.len(), pid);
        Ok(threads)
    }
}

use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

// Define NtQueryInformationThread signature
type NtQueryInformationThreadFn = unsafe extern "system" fn(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *mut std::ffi::c_void,
    thread_information_length: u32,
    return_length: *mut u32,
) -> i32;

#[repr(C)]
#[allow(non_snake_case)]
struct THREAD_BASIC_INFORMATION {
    ExitStatus: i32,
    TebBaseAddress: usize,
    ClientId: CLIENT_ID,
    AffinityMask: usize,
    Priority: i32,
    BasePriority: i32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct CLIENT_ID {
    UniqueProcess: usize,
    UniqueThread: usize,
}

/// Get TEB information for a thread
pub fn get_teb_info(tid: u32) -> Result<TebInfo> {
    trace!("Getting TEB info for TID {}", tid);

    // Try to use NtQueryInformationThread to get TEB address
    let teb_addr = unsafe {
        let ntdll = GetModuleHandleA(PCSTR::from_raw(c"ntdll.dll".as_ptr() as *const u8))
            .map_err(|e| Error::Internal(format!("GetModuleHandleA failed: {}", e)))?;

        let func_ptr = GetProcAddress(
            ntdll,
            PCSTR::from_raw(c"NtQueryInformationThread".as_ptr() as *const u8),
        );

        if let Some(func) = func_ptr {
            let nt_query_information_thread: NtQueryInformationThreadFn = std::mem::transmute(func);

            let handle = OpenThread(THREAD_QUERY_INFORMATION, false, tid)
                .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

            let mut tbi = std::mem::zeroed::<THREAD_BASIC_INFORMATION>();
            let mut return_len = 0u32;

            // ThreadBasicInformation = 0
            let status = nt_query_information_thread(
                handle,
                0,
                &mut tbi as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
                &mut return_len,
            );

            let _ = CloseHandle(handle);

            if status >= 0 {
                Some(tbi.TebBaseAddress)
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(addr) = teb_addr {
        // We have the TEB address, now we need to read it.
        // If it's the current process, we can just read it directly.
        // But if we are an external tool attached to another process, we would need ReadProcessMemory.
        // However, this crate is 'ghost-core', which seems to be designed for in-process or injected agent mostly?
        // Let's assume in-process for now as get_peb_info uses direct memory access.

        // Check if the thread belongs to the current process
        let thread_pid = get_thread_details(tid)?.pid;
        let current_pid = unsafe { GetCurrentProcessId() };

        if thread_pid == current_pid {
            unsafe {
                let teb_ptr = addr as *const u8;
                Ok(TebInfo {
                    address: addr,
                    tid,
                    pid: thread_pid,
                    stack_base: *(teb_ptr.add(0x08) as *const usize),
                    stack_limit: *(teb_ptr.add(0x10) as *const usize),
                    tls_slots: *(teb_ptr.add(0x58) as *const usize),
                    peb_address: *(teb_ptr.add(0x60) as *const usize),
                    last_error: *(teb_ptr.add(0x68) as *const u32),
                    exception_list: *(teb_ptr as *const usize),
                    fiber_data: None,
                    current_locale: *(teb_ptr.add(0x108) as *const u32),
                })
            }
        } else {
            Err(Error::Internal(
                "TEB access for remote process threads requires ReadProcessMemory (not fully implemented in introspection)".into(),
            ))
        }
    } else {
        // Fallback to current thread check if NtQueryInformationThread failed or wasn't found
        let current_tid = unsafe { GetCurrentThreadId() };

        if tid == current_tid {
            unsafe {
                // Use intrinsic to get TEB
                let teb_ptr: *const u8;
                #[cfg(target_arch = "x86_64")]
                {
                    std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb_ptr);
                }
                #[cfg(target_arch = "x86")]
                {
                    std::arch::asm!("mov {}, fs:[0x18]", out(reg) teb_ptr);
                }

                let teb_addr = teb_ptr as usize;

                Ok(TebInfo {
                    address: teb_addr,
                    tid,
                    pid: GetCurrentProcessId(),
                    stack_base: *(teb_ptr.add(0x08) as *const usize),
                    stack_limit: *(teb_ptr.add(0x10) as *const usize),
                    tls_slots: *(teb_ptr.add(0x58) as *const usize),
                    peb_address: *(teb_ptr.add(0x60) as *const usize),
                    last_error: *(teb_ptr.add(0x68) as *const u32),
                    exception_list: *(teb_ptr as *const usize),
                    fiber_data: None,
                    current_locale: *(teb_ptr.add(0x108) as *const u32),
                })
            }
        } else {
            Err(Error::Internal(
                "TEB access for other threads requires NtQueryInformationThread which failed"
                    .into(),
            ))
        }
    }
}

/// Get TLS slots for the current thread
pub fn get_tls_slots() -> Result<Vec<TlsSlot>> {
    trace!("Getting TLS slots for current thread");

    unsafe {
        let teb_ptr: *const u8;
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb_ptr);
        }

        let tls_array_ptr = *(teb_ptr.add(0x58) as *const *const usize);
        let mut slots = Vec::new();

        // Standard TLS slots (0-63)
        for i in 0..64u32 {
            let value = *tls_array_ptr.add(i as usize);
            if value != 0 {
                slots.push(TlsSlot {
                    index: i,
                    value,
                    module: None,
                });
            }
        }

        debug!("Found {} TLS slots", slots.len());
        Ok(slots)
    }
}

// ============================================================================
// Module Management
// ============================================================================

/// Get detailed module information
pub fn get_module_details(module_name: &str) -> Result<ModuleDetails> {
    let pid = unsafe { GetCurrentProcessId() };
    let modules = enumerate_modules_detailed(pid)?;

    modules
        .into_iter()
        .find(|m| m.name.eq_ignore_ascii_case(module_name))
        .ok_or_else(|| Error::Internal(format!("Module '{}' not found", module_name)))
}

/// Enumerate all modules with detailed info
pub fn enumerate_modules_detailed(pid: u32) -> Result<Vec<ModuleDetails>> {
    trace!("Enumerating modules for PID {}", pid);

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
            .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

        let mut modules = Vec::new();
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        let mut is_first = true;
        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szModule[..entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len())],
                );

                let path = String::from_utf16_lossy(
                    &entry.szExePath[..entry
                        .szExePath
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExePath.len())],
                );

                modules.push(ModuleDetails {
                    name,
                    path,
                    base: entry.modBaseAddr as usize,
                    size: entry.modBaseSize as usize,
                    entry_point: None,
                    load_count: None,
                    tls_index: None,
                    is_main_module: is_first,
                    load_time: None,
                    file_version: None,
                    product_version: None,
                    company_name: None,
                    file_description: None,
                    checksum: None,
                    timestamp: None,
                });
                is_first = false;

                entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        info!("Enumerated {} modules for PID {}", modules.len(), pid);
        Ok(modules)
    }
}

// ============================================================================
// Handle Management
// ============================================================================

/// Enumerate handles (requires NtQuerySystemInformation - simplified version)
pub fn enumerate_handles(_filter: Option<HandleFilter>) -> Result<Vec<HandleInfo>> {
    // Full handle enumeration requires undocumented NtQuerySystemInformation
    // This is a placeholder that returns an empty list
    warn!("Full handle enumeration requires NtQuerySystemInformation - not fully implemented");
    Ok(Vec::new())
}

/// Duplicate a handle
pub fn duplicate_handle(_handle: usize, _access: u32) -> Result<usize> {
    Err(Error::Internal(
        "Handle duplication not yet implemented".into(),
    ))
}

/// Close a handle
pub fn close_handle(handle: usize) -> Result<()> {
    unsafe {
        CloseHandle(HANDLE(handle as *mut _))
            .map_err(|e| Error::Internal(format!("CloseHandle failed: {}", e)))
    }
}

// ============================================================================
// Window Management
// ============================================================================

/// Enumerate windows with optional filter
pub fn enumerate_windows(filter: Option<WindowFilter>) -> Result<Vec<WindowInfo>> {
    trace!("Enumerating windows");

    let windows = Arc::new(Mutex::new(Vec::new()));
    let windows_clone = Arc::clone(&windows);
    let filter_clone = filter.clone();

    unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let data = lparam.0 as *mut (Arc<Mutex<Vec<WindowInfo>>>, Option<WindowFilter>);
        let (windows, filter) = &*data;

        if let Ok(info) = get_window_info_internal(hwnd) {
            let mut include = true;

            if let Some(f) = filter {
                if f.visible_only && !info.visible {
                    include = false;
                }
                if f.top_level_only && !info.is_top_level {
                    include = false;
                }
                if let Some(pid) = f.pid {
                    if info.pid != pid {
                        include = false;
                    }
                }
                if let Some(tid) = f.tid {
                    if info.tid != tid {
                        include = false;
                    }
                }
                if let Some(ref class_contains) = f.class_name_contains {
                    if !info
                        .class_name
                        .to_lowercase()
                        .contains(&class_contains.to_lowercase())
                    {
                        include = false;
                    }
                }
                if let Some(ref title_contains) = f.title_contains {
                    if !info
                        .title
                        .to_lowercase()
                        .contains(&title_contains.to_lowercase())
                    {
                        include = false;
                    }
                }
            }

            if include {
                if let Ok(mut windows) = windows.lock() {
                    windows.push(info);
                }
            }
        }

        BOOL(1) // Continue enumeration
    }

    let mut callback_data = (windows_clone, filter_clone);
    unsafe {
        let _ = EnumWindows(
            Some(enum_callback),
            LPARAM(&mut callback_data as *mut _ as isize),
        );
    }

    let result = windows
        .lock()
        .map_err(|_| Error::Internal("Lock poisoned".into()))?
        .clone();

    info!("Enumerated {} windows", result.len());
    Ok(result)
}

/// Get window information
pub fn get_window_info(hwnd: usize) -> Result<WindowInfo> {
    get_window_info_internal(HWND(hwnd as *mut _))
}

fn get_window_info_internal(hwnd: HWND) -> Result<WindowInfo> {
    unsafe {
        if !IsWindow(hwnd).as_bool() {
            return Err(Error::Internal("Invalid window handle".into()));
        }

        // Get window text
        let text_len = GetWindowTextLengthW(hwnd);
        let title = if text_len > 0 {
            let mut buf = vec![0u16; (text_len + 1) as usize];
            GetWindowTextW(hwnd, &mut buf);
            String::from_utf16_lossy(&buf[..text_len as usize])
        } else {
            String::new()
        };

        // Get class name
        let mut class_buf = [0u16; 256];
        let class_len = GetClassNameW(hwnd, &mut class_buf);
        let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);

        // Get process and thread IDs
        let mut pid = 0u32;
        let tid = GetWindowThreadProcessId(hwnd, Some(&mut pid));

        // Get window rectangles
        let mut rect = RECT::default();
        let mut client_rect = RECT::default();
        let _ = GetWindowRect(hwnd, &mut rect);
        let _ = GetClientRect(hwnd, &mut client_rect);

        // Get parent
        let parent = match GetParent(hwnd) {
            Ok(p) if !p.is_invalid() => Some(p.0 as usize),
            _ => None,
        };

        // Get styles
        let style = GetWindowLongW(hwnd, GWL_STYLE) as u32;
        let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;

        // Count children
        let child_count = Arc::new(Mutex::new(0u32));
        let child_count_clone = Arc::clone(&child_count);

        unsafe extern "system" fn count_children(_hwnd: HWND, lparam: LPARAM) -> BOOL {
            let count = lparam.0 as *mut Arc<Mutex<u32>>;
            if let Ok(mut c) = (*count).lock() {
                *c += 1;
            }
            BOOL(1)
        }

        let _ = EnumChildWindows(
            hwnd,
            Some(count_children),
            LPARAM(&child_count_clone as *const _ as isize),
        );

        let children = *child_count.lock().unwrap();

        Ok(WindowInfo {
            hwnd: hwnd.0 as usize,
            title,
            class_name,
            pid,
            tid,
            parent,
            rect: WindowRect {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
            },
            client_rect: WindowRect {
                left: client_rect.left,
                top: client_rect.top,
                right: client_rect.right,
                bottom: client_rect.bottom,
            },
            style,
            ex_style,
            visible: IsWindowVisible(hwnd).as_bool(),
            enabled: true, // IsWindowEnabled not available in this windows-rs version
            minimized: IsIconic(hwnd).as_bool(),
            maximized: IsZoomed(hwnd).as_bool(),
            is_top_level: parent.is_none(),
            child_count: children,
        })
    }
}

/// Enumerate child windows
pub fn enumerate_child_windows(parent_hwnd: usize) -> Result<Vec<WindowInfo>> {
    trace!("Enumerating child windows for HWND 0x{:X}", parent_hwnd);

    let windows = Arc::new(Mutex::new(Vec::new()));
    let windows_clone = Arc::clone(&windows);

    unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let windows = lparam.0 as *mut Arc<Mutex<Vec<WindowInfo>>>;
        if let Ok(info) = get_window_info_internal(hwnd) {
            if let Ok(mut w) = (*windows).lock() {
                w.push(info);
            }
        }
        BOOL(1)
    }

    unsafe {
        let _ = EnumChildWindows(
            HWND(parent_hwnd as *mut _),
            Some(enum_callback),
            LPARAM(&windows_clone as *const _ as isize),
        );
    }

    let result = windows
        .lock()
        .map_err(|_| Error::Internal("Lock poisoned".into()))?
        .clone();

    debug!("Found {} child windows", result.len());
    Ok(result)
}

// ============================================================================
// Section Management
// ============================================================================

/// Get PE section information for a module
pub fn get_module_sections(module_base: usize) -> Result<Vec<SectionInfo>> {
    trace!("Getting sections for module at 0x{:X}", module_base);

    unsafe {
        let dos_header = module_base as *const u8;

        // Check DOS signature
        let dos_sig = *(dos_header as *const u16);
        if dos_sig != 0x5A4D {
            // "MZ"
            return Err(Error::Internal("Invalid DOS header".into()));
        }

        // Get PE header offset
        let pe_offset = *(dos_header.add(0x3C) as *const u32) as usize;
        let pe_header = dos_header.add(pe_offset);

        // Check PE signature
        let pe_sig = *(pe_header as *const u32);
        if pe_sig != 0x00004550 {
            // "PE\0\0"
            return Err(Error::Internal("Invalid PE header".into()));
        }

        // Get number of sections
        let num_sections = *(pe_header.add(6) as *const u16) as usize;
        let optional_header_size = *(pe_header.add(20) as *const u16) as usize;

        // Section headers start after optional header
        let section_headers = pe_header.add(24 + optional_header_size);

        let mut sections = Vec::new();
        for i in 0..num_sections {
            let section = section_headers.add(i * 40);

            // Read section name (8 bytes, null-padded)
            let mut name_bytes = [0u8; 8];
            std::ptr::copy_nonoverlapping(section, name_bytes.as_mut_ptr(), 8);
            let name = String::from_utf8_lossy(
                &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(8)],
            )
            .to_string();

            let virtual_size = *(section.add(8) as *const u32) as usize;
            let virtual_address = *(section.add(12) as *const u32) as usize;
            let raw_size = *(section.add(16) as *const u32) as usize;
            let raw_offset = *(section.add(20) as *const u32) as usize;
            let characteristics = *(section.add(36) as *const u32);

            const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
            const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
            const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
            const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
            const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

            sections.push(SectionInfo {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics,
                executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                writable: characteristics & IMAGE_SCN_MEM_WRITE != 0,
                readable: characteristics & IMAGE_SCN_MEM_READ != 0,
                contains_code: characteristics & IMAGE_SCN_CNT_CODE != 0,
                contains_initialized_data: characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0,
                contains_uninitialized_data: characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA
                    != 0,
            });
        }

        debug!("Found {} sections for module", sections.len());
        Ok(sections)
    }
}

// ============================================================================
// Token Management
// ============================================================================

/// Get token information for current process
pub fn get_current_token_info() -> Result<TokenInfo> {
    trace!("Getting current process token info");

    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle)
            .map_err(|e| Error::Internal(format!("OpenProcessToken failed: {}", e)))?;

        let result = get_token_info_internal(token_handle);
        let _ = CloseHandle(token_handle);
        result
    }
}

/// Get token information for a thread
pub fn get_thread_token_info(tid: u32) -> Result<TokenInfo> {
    trace!("Getting thread token info for TID {}", tid);

    unsafe {
        let thread_handle = OpenThread(THREAD_QUERY_INFORMATION, false, tid)
            .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

        let mut token_handle = HANDLE::default();
        let result = OpenThreadToken(thread_handle, TOKEN_QUERY, true, &mut token_handle);

        let _ = CloseHandle(thread_handle);

        if result.is_err() {
            return Err(Error::Internal("Thread has no impersonation token".into()));
        }

        let token_result = get_token_info_internal(token_handle);
        let _ = CloseHandle(token_handle);
        token_result
    }
}

fn get_token_info_internal(token: HANDLE) -> Result<TokenInfo> {
    unsafe {
        // Get token user
        let mut user_size = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut user_size);

        let mut user_buffer = vec![0u8; user_size as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(user_buffer.as_mut_ptr() as *mut _),
            user_size,
            &mut user_size,
        )
        .map_err(|e| Error::Internal(format!("GetTokenInformation(User) failed: {}", e)))?;

        let token_user = &*(user_buffer.as_ptr() as *const TOKEN_USER);

        // Convert SID to string (simplified)
        let user_sid = format!("{:?}", token_user.User.Sid);

        // Get user name
        let mut name_buf = [0u16; 256];
        let mut domain_buf = [0u16; 256];
        let mut name_size = 256u32;
        let mut domain_size = 256u32;
        let mut sid_use = SID_NAME_USE::default();

        let (user_name, user_domain) = if LookupAccountSidW(
            PCWSTR::null(),
            token_user.User.Sid,
            windows::core::PWSTR(name_buf.as_mut_ptr()),
            &mut name_size,
            windows::core::PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_size,
            &mut sid_use,
        )
        .is_ok()
        {
            (
                Some(String::from_utf16_lossy(&name_buf[..name_size as usize])),
                Some(String::from_utf16_lossy(
                    &domain_buf[..domain_size as usize],
                )),
            )
        } else {
            (None, None)
        };

        // Get elevation status
        let mut elevation = TOKEN_ELEVATION::default();
        let mut elev_size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let is_elevated = if GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            elev_size,
            &mut elev_size,
        )
        .is_ok()
        {
            elevation.TokenIsElevated != 0
        } else {
            false
        };

        // Get privileges
        let mut priv_size = 0u32;
        let _ = GetTokenInformation(token, TokenPrivileges, None, 0, &mut priv_size);

        let privileges = if priv_size > 0 {
            let mut priv_buffer = vec![0u8; priv_size as usize];
            if GetTokenInformation(
                token,
                TokenPrivileges,
                Some(priv_buffer.as_mut_ptr() as *mut _),
                priv_size,
                &mut priv_size,
            )
            .is_ok()
            {
                let token_privs = &*(priv_buffer.as_ptr() as *const TOKEN_PRIVILEGES);
                let count = token_privs.PrivilegeCount as usize;
                let privs_ptr = token_privs.Privileges.as_ptr();

                let mut privs = Vec::new();
                for i in 0..count {
                    let priv_entry = &*privs_ptr.add(i);

                    // Get privilege name
                    let mut name_buf = [0u16; 256];
                    let mut name_size = 256u32;
                    let name = if LookupPrivilegeNameW(
                        PCWSTR::null(),
                        &priv_entry.Luid,
                        windows::core::PWSTR(name_buf.as_mut_ptr()),
                        &mut name_size,
                    )
                    .is_ok()
                    {
                        String::from_utf16_lossy(&name_buf[..name_size as usize])
                    } else {
                        format!(
                            "LUID({},{})",
                            priv_entry.Luid.LowPart, priv_entry.Luid.HighPart
                        )
                    };

                    let luid = ((priv_entry.Luid.HighPart as u64) << 32)
                        | (priv_entry.Luid.LowPart as u64);

                    privs.push(TokenPrivilege {
                        name,
                        luid,
                        enabled: priv_entry.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0,
                        enabled_by_default: priv_entry.Attributes.0
                            & SE_PRIVILEGE_ENABLED_BY_DEFAULT.0
                            != 0,
                        removed: priv_entry.Attributes.0 & SE_PRIVILEGE_REMOVED.0 != 0,
                    });
                }
                privs
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(TokenInfo {
            handle: token.0 as usize,
            token_type: TokenType::Primary,
            impersonation_level: None,
            user_sid,
            user_name,
            user_domain,
            session_id: 0,
            integrity_level: IntegrityLevel::Unknown,
            is_elevated,
            is_restricted: false,
            privileges,
            groups: Vec::new(),
        })
    }
}

/// Enable or disable a privilege
pub fn adjust_privilege(priv_request: &PrivilegeRequest) -> Result<bool> {
    trace!(
        "Adjusting privilege '{}' to {}",
        priv_request.name,
        priv_request.enable
    );

    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .map_err(|e| Error::Internal(format!("OpenProcessToken failed: {}", e)))?;

        // Look up privilege LUID
        let priv_name: Vec<u16> = priv_request
            .name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut luid = LUID::default();
        if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(priv_name.as_ptr()), &mut luid).is_err() {
            let _ = CloseHandle(token_handle);
            return Err(Error::Internal(format!(
                "Privilege '{}' not found",
                priv_request.name
            )));
        }

        // Prepare TOKEN_PRIVILEGES structure
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: if priv_request.enable {
                    SE_PRIVILEGE_ENABLED
                } else {
                    windows::Win32::Security::TOKEN_PRIVILEGES_ATTRIBUTES(0)
                },
            }],
        };

        let result = AdjustTokenPrivileges(token_handle, false, Some(&tp), 0, None, None);

        let _ = CloseHandle(token_handle);

        if result.is_err() {
            return Err(Error::Internal("AdjustTokenPrivileges failed".into()));
        }

        // Check if adjustment was actually applied
        let error = GetLastError();
        if error.0 != 0 {
            warn!("Privilege adjustment warning: error code {}", error.0);
        }

        info!(
            "Privilege '{}' {} successfully",
            priv_request.name,
            if priv_request.enable {
                "enabled"
            } else {
                "disabled"
            }
        );
        Ok(true)
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current timestamp in Unix epoch seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_process_details() {
        let details = get_current_process_details();
        assert!(details.is_ok());
        let details = details.unwrap();
        assert!(details.pid > 0);
        assert!(!details.name.is_empty());
    }

    #[test]
    fn test_enumerate_processes() {
        let processes = enumerate_processes();
        assert!(processes.is_ok());
        let processes = processes.unwrap();
        assert!(!processes.is_empty());
    }

    #[test]
    fn test_get_peb_info() {
        let peb = get_peb_info();
        assert!(peb.is_ok());
        let peb = peb.unwrap();
        assert!(peb.address > 0);
    }

    #[test]
    fn test_enumerate_threads() {
        let pid = unsafe { GetCurrentProcessId() };
        let threads = enumerate_threads_detailed(pid);
        assert!(threads.is_ok());
        let threads = threads.unwrap();
        assert!(!threads.is_empty());
    }

    #[test]
    fn test_get_teb_info() {
        let tid = unsafe { GetCurrentThreadId() };
        let teb = get_teb_info(tid);
        assert!(teb.is_ok());
        let teb = teb.unwrap();
        assert!(teb.address > 0);
    }

    #[test]
    fn test_enumerate_modules() {
        let pid = unsafe { GetCurrentProcessId() };
        let modules = enumerate_modules_detailed(pid);
        assert!(modules.is_ok());
        let modules = modules.unwrap();
        assert!(!modules.is_empty());
    }

    #[test]
    fn test_enumerate_windows() {
        let windows = enumerate_windows(None);
        assert!(windows.is_ok());
    }

    #[test]
    fn test_get_current_token_info() {
        let token = get_current_token_info();
        assert!(token.is_ok());
        let token = token.unwrap();
        assert!(!token.user_sid.is_empty());
    }

    #[test]
    fn test_get_environment_variables() {
        let env = get_environment_variables();
        assert!(env.is_ok());
        assert!(!env.unwrap().is_empty());
    }

    #[test]
    fn test_get_working_directory() {
        let cwd = get_working_directory();
        assert!(cwd.is_ok());
        assert!(!cwd.unwrap().is_empty());
    }

    #[test]
    fn test_get_process_memory_map() {
        let pid = unsafe { GetCurrentProcessId() };
        let map = get_process_memory_map(pid);
        assert!(map.is_ok());
        let map = map.unwrap();
        assert!(!map.is_empty(), "Memory map should not be empty");
    }

    #[test]
    fn test_get_tls_slots() {
        let slots = get_tls_slots();
        assert!(slots.is_ok());
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts > 0, "Timestamp should be positive");
    }

    #[test]
    fn test_format_protection() {
        assert_eq!(format_protection(0x04), "RW-"); // PAGE_READWRITE
        assert_eq!(format_protection(0x02), "R--"); // PAGE_READONLY
        assert_eq!(format_protection(0x40), "RWX"); // PAGE_EXECUTE_READWRITE
        assert_eq!(format_protection(0x01), "---"); // PAGE_NOACCESS
        assert_eq!(format_protection(0x104), "RW-+G"); // PAGE_READWRITE | PAGE_GUARD
    }

    #[test]
    fn test_enumerate_handles() {
        let handles = enumerate_handles(None);
        assert!(handles.is_ok());
    }

    #[test]
    fn test_close_invalid_handle() {
        let result = close_handle(0);
        assert!(result.is_err(), "Closing invalid handle should fail");
    }

    #[test]
    fn test_get_peb_info_remote_process_fails() {
        // Trying to get PEB for a different PID should fail with current implementation
        let result = get_peb_info_for_process(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_enumerate_windows_with_filter() {
        let filter = WindowFilter {
            visible_only: true,
            top_level_only: true,
            ..Default::default()
        };
        let windows = enumerate_windows(Some(filter));
        assert!(windows.is_ok());
    }
}
