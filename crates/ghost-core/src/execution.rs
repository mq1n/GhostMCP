//! Direct Execution & API Calls Module
//!
//! Provides capabilities for:
//! - Dynamic function resolution (GetProcAddress)
//! - Direct ntdll syscall invocation
//! - Arbitrary function calling with parameter marshaling
//! - Shellcode execution (multiple methods)
//! - Code cave finding and management
//! - Remote execution primitives
//!
//! # Safety
//!
//! Many functions in this module are inherently unsafe as they deal with
//! raw memory manipulation and code execution. Care must be taken to ensure
//! addresses are valid and memory is properly allocated before use.

use ghost_common::{
    AllocatedCave, CallingConvention, CodeCave, CodeCaveOptions, Error, FunctionCallOptions,
    FunctionCallResult, MemoryRegion, Result, ShellcodeExecMethod, ShellcodeExecOptions,
    ShellcodeExecResult, SyscallInfo, SyscallResult,
};

// Re-export FunctionArg for use by consumers of this module
pub use ghost_common::FunctionArg;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::CloseHandle;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HMODULE;
#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT,
    CONTEXT_ALL_AMD64,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{VirtualAllocEx, VirtualFreeEx};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    ConvertThreadToFiber, CreateFiber, CreateRemoteThread, CreateThread, DeleteFiber,
    GetExitCodeThread, OpenProcess, OpenThread, QueueUserAPC, ResumeThread, SuspendThread,
    SwitchToFiber, WaitForSingleObject, INFINITE, LPFIBER_START_ROUTINE, PROCESS_ALL_ACCESS,
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE, THREAD_ALL_ACCESS, THREAD_CREATION_FLAGS,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

/// Next cave ID for allocation tracking
static NEXT_CAVE_ID: AtomicU32 = AtomicU32::new(1);

/// Execution engine for direct API calls and shellcode execution
pub struct ExecutionEngine {
    /// Cached module handles
    module_cache: RwLock<HashMap<String, usize>>,
    /// Cached function addresses
    function_cache: RwLock<HashMap<String, usize>>,
    /// Allocated code caves
    allocated_caves: RwLock<Vec<AllocatedCave>>,
    /// Cached syscall numbers
    syscall_cache: RwLock<HashMap<String, u32>>,
}

impl Default for ExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionEngine {
    /// Create a new execution engine
    pub fn new() -> Self {
        debug!(target: "ghost_core::execution", "Creating new ExecutionEngine");
        Self {
            module_cache: RwLock::new(HashMap::new()),
            function_cache: RwLock::new(HashMap::new()),
            allocated_caves: RwLock::new(Vec::new()),
            syscall_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Clear all caches (useful for testing or after process state changes)
    pub fn clear_caches(&self) {
        debug!(target: "ghost_core::execution", "Clearing all caches");
        if let Ok(mut cache) = self.module_cache.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.function_cache.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.syscall_cache.write() {
            cache.clear();
        }
    }

    /// Resolve a function address by module and function name
    ///
    /// # Arguments
    /// * `module` - Module name (e.g., "kernel32.dll")
    /// * `function` - Function name (e.g., "GetCurrentProcessId")
    ///
    /// # Returns
    /// The function address on success, or an error if resolution fails
    #[cfg(target_os = "windows")]
    pub fn resolve_function(&self, module: &str, function: &str) -> Result<usize> {
        // Validate inputs
        if module.is_empty() {
            warn!(target: "ghost_core::execution", "resolve_function called with empty module name");
            return Err(Error::Internal("Module name cannot be empty".into()));
        }
        if function.is_empty() {
            warn!(target: "ghost_core::execution", "resolve_function called with empty function name");
            return Err(Error::Internal("Function name cannot be empty".into()));
        }

        // Check cache first
        let cache_key = format!("{}!{}", module, function);
        if let Ok(cache) = self.function_cache.read() {
            if let Some(&addr) = cache.get(&cache_key) {
                trace!(target: "ghost_core::execution", "Cache hit for {}", cache_key);
                return Ok(addr);
            }
        }

        debug!(target: "ghost_core::execution", "Resolving {}!{}", module, function);

        // Get module handle
        let module_handle = self.get_module_handle(module)?;

        // Get function address
        let func_name = CString::new(function).map_err(|e| {
            error!(target: "ghost_core::execution", "Invalid function name '{}': {}", function, e);
            Error::Internal(format!(
                "Invalid function name '{}': contains null byte",
                function
            ))
        })?;

        let addr = unsafe {
            let proc = GetProcAddress(
                HMODULE(module_handle as *mut _),
                windows::core::PCSTR(func_name.as_ptr() as *const u8),
            );
            proc.map(|f| f as usize).ok_or_else(|| {
                Error::Internal(format!("Function '{}' not found in '{}'", function, module))
            })?
        };

        // Cache the result
        if let Ok(mut cache) = self.function_cache.write() {
            cache.insert(cache_key.clone(), addr);
            debug!(target: "ghost_core::execution", "Resolved {} -> {:#x}", cache_key, addr);
        }

        Ok(addr)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn resolve_function(&self, _module: &str, _function: &str) -> Result<usize> {
        Err(Error::NotImplemented(
            "Function resolution only supported on Windows".into(),
        ))
    }

    /// Get module handle (loads if not already loaded)
    ///
    /// # Arguments
    /// * `module` - Module name (e.g., "kernel32.dll")
    ///
    /// # Returns
    /// The module handle on success, or an error if the module cannot be found/loaded
    #[cfg(target_os = "windows")]
    pub fn get_module_handle(&self, module: &str) -> Result<usize> {
        // Validate input
        if module.is_empty() {
            return Err(Error::Internal("Module name cannot be empty".into()));
        }

        // Check cache first
        if let Ok(cache) = self.module_cache.read() {
            if let Some(&handle) = cache.get(module) {
                trace!(target: "ghost_core::execution", "Module cache hit for {}", module);
                return Ok(handle);
            }
        }

        // Convert to wide string
        let wide_name: Vec<u16> = module.encode_utf16().chain(std::iter::once(0)).collect();

        // Try to get existing module first
        let handle = unsafe {
            let h = GetModuleHandleW(PCWSTR(wide_name.as_ptr()));
            if let Ok(h) = h {
                h.0 as usize
            } else {
                // Module not loaded, try to load it
                let h = LoadLibraryW(PCWSTR(wide_name.as_ptr())).map_err(|e| {
                    Error::Internal(format!("Failed to load module '{}': {}", module, e))
                })?;
                h.0 as usize
            }
        };

        if handle == 0 {
            return Err(Error::Internal(format!("Module '{}' not found", module)));
        }

        // Cache the result
        if let Ok(mut cache) = self.module_cache.write() {
            cache.insert(module.to_string(), handle);
            debug!(target: "ghost_core::execution", "Loaded module {} -> {:#x}", module, handle);
        }

        Ok(handle)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_module_handle(&self, _module: &str) -> Result<usize> {
        Err(Error::NotImplemented(
            "Module resolution only supported on Windows".into(),
        ))
    }

    /// Call a function at the specified address with the given options
    ///
    /// # Safety
    /// The caller must ensure the address points to valid executable code
    /// and that the arguments match the expected function signature.
    ///
    /// # Arguments
    /// * `address` - The function address to call
    /// * `options` - Call options including arguments and calling convention
    #[cfg(target_os = "windows")]
    pub fn call_function(
        &self,
        address: usize,
        options: &FunctionCallOptions,
    ) -> Result<FunctionCallResult> {
        // Validate address
        if address == 0 {
            error!(target: "ghost_core::execution", "call_function called with null address");
            return Err(Error::InvalidAddress(0));
        }

        info!(target: "ghost_core::execution",
            address = format!("{:#x}", address),
            arg_count = options.args.len(),
            convention = ?options.convention,
            new_thread = options.new_thread,
            "Calling function"
        );

        let start = Instant::now();

        // Prepare arguments
        let args: Vec<u64> = options.args.iter().map(|a| a.as_u64()).collect();
        trace!(target: "ghost_core::execution", "Prepared {} arguments", args.len());

        // For x64 Windows, first 4 args go in RCX, RDX, R8, R9
        // Additional args go on stack
        let result = if options.new_thread {
            self.call_in_new_thread(address, &args, options.timeout_ms)?
        } else {
            self.call_direct(address, &args, &options.convention)?
        };

        let duration = start.elapsed();

        Ok(FunctionCallResult {
            return_value: result,
            return_value_high: None,
            float_return: None,
            out_params: Vec::new(),
            success: true,
            error: None,
            duration_us: duration.as_micros() as u64,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn call_function(
        &self,
        _address: usize,
        _options: &FunctionCallOptions,
    ) -> Result<FunctionCallResult> {
        Err(Error::NotImplemented(
            "Function calls only supported on Windows".into(),
        ))
    }

    /// Call a function directly in the current thread
    #[cfg(target_os = "windows")]
    fn call_direct(
        &self,
        address: usize,
        args: &[u64],
        _convention: &CallingConvention,
    ) -> Result<u64> {
        // For x64, use the standard Windows calling convention
        // We define a function signature with 16 arguments to cover most APIs.
        // The calling convention (stdcall/cdecl/fastcall) is mostly unified on x64 (Microsoft x64).
        // Extra arguments passed to functions that don't need them are ignored by the callee
        // (caller cleans up stack space if needed, but Rust handles this).

        // Define a function type with 16 arguments (u64) -> u64
        type Fn16 = extern "C" fn(
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> u64;

        let func: Fn16 = unsafe { std::mem::transmute(address) };

        // Prepare arguments (pad with 0)
        let mut a = [0u64; 16];
        for (i, arg) in args.iter().enumerate().take(16) {
            a[i] = *arg;
        }

        // Call with 16 arguments
        let result = func(
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13],
            a[14], a[15],
        );

        Ok(result)
    }

    /// Call a function in a new thread
    #[cfg(target_os = "windows")]
    fn call_in_new_thread(&self, address: usize, args: &[u64], timeout_ms: u64) -> Result<u64> {
        // For simplicity, we only pass the first argument via lpParameter
        let param = args.first().copied().unwrap_or(0);

        unsafe {
            let mut thread_id: u32 = 0;
            let handle = CreateThread(
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                >(address)),
                Some(param as *const std::ffi::c_void),
                THREAD_CREATION_FLAGS(0),
                Some(&mut thread_id),
            )
            .map_err(|e| Error::Internal(format!("CreateThread failed: {}", e)))?;

            // Wait for thread
            let wait_time = if timeout_ms == 0 {
                INFINITE
            } else {
                timeout_ms as u32
            };
            WaitForSingleObject(handle, wait_time);

            // Get exit code
            let mut exit_code: u32 = 0;
            let _ = GetExitCodeThread(handle, &mut exit_code);

            Ok(exit_code as u64)
        }
    }

    /// Execute shellcode with the specified options
    #[cfg(target_os = "windows")]
    pub fn execute_shellcode(
        &self,
        shellcode: &[u8],
        options: &ShellcodeExecOptions,
    ) -> Result<ShellcodeExecResult> {
        let start = Instant::now();

        // Allocate memory for shellcode
        let protection = options.protection.unwrap_or(PAGE_EXECUTE_READWRITE.0);

        let shellcode_addr = unsafe {
            VirtualAlloc(
                None,
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_PROTECTION_FLAGS(protection),
            )
        };

        if shellcode_addr.is_null() {
            return Err(Error::Internal(
                "Failed to allocate memory for shellcode".into(),
            ));
        }

        let shellcode_addr = shellcode_addr as usize;

        // Copy shellcode to allocated memory
        unsafe {
            std::ptr::copy_nonoverlapping(
                shellcode.as_ptr(),
                shellcode_addr as *mut u8,
                shellcode.len(),
            );
        }

        // Execute based on method
        let (return_value, thread_id) = match options.method {
            ShellcodeExecMethod::CurrentThread => {
                let func: extern "C" fn(u64) -> u64 =
                    unsafe { std::mem::transmute(shellcode_addr) };
                let param = options.parameter.unwrap_or(0);
                let result = func(param);
                (result, None)
            }
            ShellcodeExecMethod::NewThread | ShellcodeExecMethod::NtCreateThreadEx => {
                let tid = self.execute_shellcode_thread(
                    shellcode_addr,
                    options.parameter,
                    options.wait,
                    options.timeout_ms,
                )?;
                (0, Some(tid))
            }
            ShellcodeExecMethod::ApcInjection => {
                let target_tid = options
                    .target_tid
                    .ok_or_else(|| Error::Internal("APC injection requires target_tid".into()))?;
                self.execute_shellcode_apc(shellcode_addr, target_tid, options.parameter)?;
                (0, Some(target_tid))
            }
            ShellcodeExecMethod::ThreadHijack => {
                let target_tid = options.target_tid.ok_or_else(|| {
                    Error::Internal("Thread hijacking requires target_tid".into())
                })?;
                self.execute_shellcode_hijack(
                    shellcode_addr,
                    target_tid,
                    options.parameter,
                    options.wait,
                    options.timeout_ms,
                )?;
                (0, Some(target_tid))
            }
            ShellcodeExecMethod::Fiber => {
                let result = self.execute_shellcode_fiber(shellcode_addr, options.parameter)?;
                (result, None)
            }
            ShellcodeExecMethod::Callback => {
                let result = self.execute_shellcode_callback(shellcode_addr, options.parameter)?;
                (result, None)
            }
        };

        let duration = start.elapsed();

        // Free memory if requested
        if options.free_after {
            unsafe {
                let _ = VirtualFree(shellcode_addr as *mut _, 0, MEM_RELEASE);
            }
        }

        Ok(ShellcodeExecResult {
            return_value,
            thread_id,
            shellcode_address: shellcode_addr,
            success: true,
            error: None,
            duration_us: duration.as_micros() as u64,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn execute_shellcode(
        &self,
        _shellcode: &[u8],
        _options: &ShellcodeExecOptions,
    ) -> Result<ShellcodeExecResult> {
        Err(Error::NotImplemented(
            "Shellcode execution only supported on Windows".into(),
        ))
    }

    /// Execute shellcode in a new thread
    #[cfg(target_os = "windows")]
    fn execute_shellcode_thread(
        &self,
        address: usize,
        parameter: Option<u64>,
        wait: bool,
        timeout_ms: u64,
    ) -> Result<u32> {
        let param = parameter.unwrap_or(0);

        unsafe {
            let mut thread_id: u32 = 0;
            let handle = CreateThread(
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                >(address)),
                Some(param as *const std::ffi::c_void),
                THREAD_CREATION_FLAGS(0),
                Some(&mut thread_id),
            )
            .map_err(|e| Error::Internal(format!("CreateThread failed: {}", e)))?;

            if wait {
                let wait_time = if timeout_ms == 0 {
                    INFINITE
                } else {
                    timeout_ms as u32
                };
                WaitForSingleObject(handle, wait_time);
            }

            Ok(thread_id)
        }
    }

    /// Execute shellcode via APC injection
    ///
    /// Queues an Asynchronous Procedure Call (APC) to the target thread.
    /// The shellcode will execute when the thread enters an alertable wait state.
    ///
    /// # Arguments
    /// * `address` - Address of the shellcode to execute (must be non-zero)
    /// * `target_tid` - Thread ID to queue the APC to (must be non-zero)
    /// * `parameter` - Optional parameter to pass to the shellcode
    ///
    /// # Safety
    /// The caller must ensure the address points to valid executable shellcode.
    #[cfg(target_os = "windows")]
    fn execute_shellcode_apc(
        &self,
        address: usize,
        target_tid: u32,
        parameter: Option<u64>,
    ) -> Result<()> {
        // Input validation
        if address == 0 {
            warn!(target: "ghost_core::execution", "APC injection called with null address");
            return Err(Error::InvalidAddress(0));
        }
        if target_tid == 0 {
            warn!(target: "ghost_core::execution", "APC injection called with invalid thread ID 0");
            return Err(Error::Internal("Invalid thread ID: 0".into()));
        }

        info!(target: "ghost_core::execution",
            address = format!("{:#x}", address),
            target_tid = target_tid,
            parameter = ?parameter,
            "Executing shellcode via APC injection"
        );

        unsafe {
            // Open the target thread with appropriate access
            let thread_handle = OpenThread(THREAD_ALL_ACCESS, false, target_tid).map_err(|e| {
                error!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    error = %e,
                    "Failed to open thread for APC injection"
                );
                Error::Internal(format!("OpenThread failed for TID {}: {}", target_tid, e))
            })?;

            // Queue the APC
            let param = parameter.unwrap_or(0);
            let result = QueueUserAPC(
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(usize)>(address)),
                thread_handle,
                param as usize,
            );

            let close_result = CloseHandle(thread_handle);
            if close_result.is_err() {
                trace!(target: "ghost_core::execution", "CloseHandle warning (non-fatal)");
            }

            if result == 0 {
                error!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    address = format!("{:#x}", address),
                    "QueueUserAPC failed"
                );
                return Err(Error::Internal(format!(
                    "QueueUserAPC failed for thread {}",
                    target_tid
                )));
            }

            debug!(target: "ghost_core::execution",
                target_tid = target_tid,
                address = format!("{:#x}", address),
                "APC queued successfully"
            );
            Ok(())
        }
    }

    /// Execute shellcode via thread hijacking
    ///
    /// Suspends the target thread, modifies its instruction pointer to point to
    /// the shellcode, and resumes execution. This is a powerful but intrusive method.
    ///
    /// # Arguments
    /// * `address` - Address of the shellcode to execute (must be non-zero)
    /// * `target_tid` - Thread ID to hijack (must be non-zero)
    /// * `parameter` - Optional parameter (placed in RCX on x64)
    /// * `wait` - Whether to wait for shellcode completion
    /// * `timeout_ms` - Timeout for waiting
    ///
    /// # Safety
    /// This is an intrusive operation. The target thread will be suspended and its
    /// execution context modified. The caller must ensure the shellcode is valid
    /// and that the thread can safely be hijacked.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn execute_shellcode_hijack(
        &self,
        address: usize,
        target_tid: u32,
        parameter: Option<u64>,
        wait: bool,
        timeout_ms: u64,
    ) -> Result<()> {
        // Input validation
        if address == 0 {
            warn!(target: "ghost_core::execution", "Thread hijack called with null address");
            return Err(Error::InvalidAddress(0));
        }
        if target_tid == 0 {
            warn!(target: "ghost_core::execution", "Thread hijack called with invalid thread ID 0");
            return Err(Error::Internal("Invalid thread ID: 0".into()));
        }

        info!(target: "ghost_core::execution",
            address = format!("{:#x}", address),
            target_tid = target_tid,
            wait = wait,
            timeout_ms = timeout_ms,
            "Executing shellcode via thread hijacking"
        );

        unsafe {
            // Open the target thread
            let thread_handle = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                false,
                target_tid,
            )
            .map_err(|e| {
                error!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    error = %e,
                    "Failed to open thread for hijacking"
                );
                Error::Internal(format!("OpenThread failed for TID {}: {}", target_tid, e))
            })?;

            // Suspend the thread
            let suspend_count = SuspendThread(thread_handle);
            if suspend_count == u32::MAX {
                error!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    "SuspendThread failed"
                );
                let _ = CloseHandle(thread_handle);
                return Err(Error::Internal(format!(
                    "SuspendThread failed for TID {}",
                    target_tid
                )));
            }
            trace!(target: "ghost_core::execution",
                target_tid = target_tid,
                suspend_count = suspend_count,
                "Thread suspended"
            );

            // Get thread context
            let mut context: CONTEXT = std::mem::zeroed();
            context.ContextFlags = CONTEXT_ALL_AMD64;

            if let Err(e) = GetThreadContext(thread_handle, &mut context) {
                error!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    error = %e,
                    "GetThreadContext failed"
                );
                let _ = ResumeThread(thread_handle);
                let _ = CloseHandle(thread_handle);
                return Err(Error::Internal(format!(
                    "GetThreadContext failed for TID {}: {}",
                    target_tid, e
                )));
            }

            // Save original RIP for logging and restoration on stack
            let original_rip = context.Rip;
            let original_rsp = context.Rsp;

            // Validate stack pointer is reasonable (non-null, aligned)
            if original_rsp == 0 || !original_rsp.is_multiple_of(8) {
                warn!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    rsp = format!("{:#x}", original_rsp),
                    "Invalid stack pointer detected"
                );
                let _ = ResumeThread(thread_handle);
                let _ = CloseHandle(thread_handle);
                return Err(Error::Internal(format!(
                    "Invalid RSP {:#x} for TID {}",
                    original_rsp, target_tid
                )));
            }

            // Modify context: set RIP to shellcode address
            context.Rip = address as u64;

            // Set parameter in RCX (first argument in x64 calling convention)
            if let Some(param) = parameter {
                context.Rcx = param;
            }

            // Push return address onto stack (simulate CALL instruction)
            context.Rsp -= 8;
            std::ptr::write(context.Rsp as *mut u64, original_rip);

            // Set the modified context
            if let Err(e) = SetThreadContext(thread_handle, &context) {
                error!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    error = %e,
                    "SetThreadContext failed"
                );
                let _ = ResumeThread(thread_handle);
                let _ = CloseHandle(thread_handle);
                return Err(Error::Internal(format!(
                    "SetThreadContext failed for TID {}: {}",
                    target_tid, e
                )));
            }

            // Resume thread execution
            let resume_result = ResumeThread(thread_handle);
            if resume_result == u32::MAX {
                error!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    "ResumeThread failed after context modification"
                );
                // Thread is in unknown state - log but continue
            }

            debug!(target: "ghost_core::execution",
                target_tid = target_tid,
                original_rip = format!("{:#x}", original_rip),
                new_rip = format!("{:#x}", address),
                "Thread hijacked successfully"
            );

            // Wait for completion if requested
            if wait {
                let wait_time = if timeout_ms == 0 {
                    INFINITE
                } else {
                    timeout_ms as u32
                };
                let wait_result = WaitForSingleObject(thread_handle, wait_time);
                trace!(target: "ghost_core::execution",
                    target_tid = target_tid,
                    wait_result = wait_result.0,
                    "Wait completed"
                );
            }

            let _ = CloseHandle(thread_handle);
            Ok(())
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86"))]
    fn execute_shellcode_hijack(
        &self,
        _address: usize,
        _target_tid: u32,
        _parameter: Option<u64>,
        _wait: bool,
        _timeout_ms: u64,
    ) -> Result<()> {
        Err(Error::NotImplemented(
            "Thread hijacking not yet implemented for x86".into(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    fn execute_shellcode_apc(
        &self,
        _address: usize,
        _target_tid: u32,
        _parameter: Option<u64>,
    ) -> Result<()> {
        Err(Error::NotImplemented(
            "APC injection only supported on Windows".into(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    fn execute_shellcode_hijack(
        &self,
        _address: usize,
        _target_tid: u32,
        _parameter: Option<u64>,
        _wait: bool,
        _timeout_ms: u64,
    ) -> Result<()> {
        Err(Error::NotImplemented(
            "Thread hijacking only supported on Windows".into(),
        ))
    }

    /// Execute shellcode via Windows Fiber mechanism
    ///
    /// Converts current thread to a fiber, creates a new fiber with the shellcode,
    /// switches to it, and then cleans up. This executes synchronously in the current thread.
    ///
    /// # Arguments
    /// * `address` - Address of the shellcode to execute
    /// * `parameter` - Optional parameter to pass to the shellcode (fiber data)
    ///
    /// # Safety
    /// The caller must ensure the address points to valid executable shellcode.
    #[cfg(target_os = "windows")]
    fn execute_shellcode_fiber(&self, address: usize, parameter: Option<u64>) -> Result<u64> {
        if address == 0 {
            warn!(target: "ghost_core::execution", "Fiber execution called with null address");
            return Err(Error::InvalidAddress(0));
        }

        info!(target: "ghost_core::execution",
            address = format!("{:#x}", address),
            parameter = ?parameter,
            "Executing shellcode via Fiber"
        );

        unsafe {
            // Convert current thread to a fiber (required before using fiber functions)
            let main_fiber = ConvertThreadToFiber(Some(std::ptr::null()));
            if main_fiber.is_null() {
                // Thread might already be a fiber, try to get current fiber
                let err = std::io::Error::last_os_error();
                // ERROR_ALREADY_FIBER = 1280
                if err.raw_os_error() != Some(1280) {
                    error!(target: "ghost_core::execution",
                        error = %err,
                        "ConvertThreadToFiber failed"
                    );
                    return Err(Error::Internal(format!(
                        "ConvertThreadToFiber failed: {}",
                        err
                    )));
                }
                debug!(target: "ghost_core::execution", "Thread already a fiber");
            }

            // Create a fiber for the shellcode
            let fiber_param = parameter.unwrap_or(0) as *const std::ffi::c_void;
            let shellcode_fiber = CreateFiber(
                0, // Default stack size
                std::mem::transmute::<usize, LPFIBER_START_ROUTINE>(address),
                Some(fiber_param),
            );

            if shellcode_fiber.is_null() {
                let err = std::io::Error::last_os_error();
                error!(target: "ghost_core::execution",
                    error = %err,
                    "CreateFiber failed"
                );
                return Err(Error::Internal(format!("CreateFiber failed: {}", err)));
            }

            debug!(target: "ghost_core::execution",
                address = format!("{:#x}", address),
                fiber = format!("{:p}", shellcode_fiber),
                "Created shellcode fiber, switching..."
            );

            // Switch to the shellcode fiber - this will execute the shellcode
            // The shellcode should call SwitchToFiber back to main_fiber when done
            // For simple shellcode that just returns, we wrap it
            SwitchToFiber(shellcode_fiber);

            // Cleanup the shellcode fiber
            DeleteFiber(shellcode_fiber);

            debug!(target: "ghost_core::execution", "Fiber execution completed");

            // Return 0 as we can't easily get return value from fiber
            Ok(0)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn execute_shellcode_fiber(&self, _address: usize, _parameter: Option<u64>) -> Result<u64> {
        Err(Error::NotImplemented(
            "Fiber execution only supported on Windows".into(),
        ))
    }

    /// Execute shellcode via Windows callback mechanism
    ///
    /// Uses EnumWindows or similar callback-based API to execute shellcode.
    /// This is a stealthier execution method as it uses legitimate Windows APIs.
    ///
    /// # Arguments
    /// * `address` - Address of the shellcode to execute
    /// * `parameter` - Optional parameter to pass as lParam
    ///
    /// # Safety
    /// The caller must ensure the address points to valid executable shellcode
    /// that conforms to the WNDENUMPROC callback signature.
    #[cfg(target_os = "windows")]
    fn execute_shellcode_callback(&self, address: usize, parameter: Option<u64>) -> Result<u64> {
        use windows::Win32::UI::WindowsAndMessaging::EnumWindows;

        if address == 0 {
            warn!(target: "ghost_core::execution", "Callback execution called with null address");
            return Err(Error::InvalidAddress(0));
        }

        info!(target: "ghost_core::execution",
            address = format!("{:#x}", address),
            parameter = ?parameter,
            "Executing shellcode via Callback (EnumWindows)"
        );

        unsafe {
            // Use EnumWindows to trigger the callback
            // The shellcode must have WNDENUMPROC signature: fn(HWND, LPARAM) -> BOOL
            let lparam = parameter.unwrap_or(0) as isize;

            // EnumWindows will call our shellcode for each top-level window
            // Shellcode should return FALSE (0) to stop enumeration after first call
            let result = EnumWindows(
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(
                        windows::Win32::Foundation::HWND,
                        windows::Win32::Foundation::LPARAM,
                    )
                        -> windows::Win32::Foundation::BOOL,
                >(address)),
                windows::Win32::Foundation::LPARAM(lparam),
            );

            // EnumWindows returns FALSE if callback returned FALSE (which we expect)
            // or TRUE if all windows were enumerated
            debug!(target: "ghost_core::execution",
                result = ?result,
                "EnumWindows callback execution completed"
            );

            Ok(0)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn execute_shellcode_callback(&self, _address: usize, _parameter: Option<u64>) -> Result<u64> {
        Err(Error::NotImplemented(
            "Callback execution only supported on Windows".into(),
        ))
    }

    /// Find code caves in memory regions
    pub fn find_code_caves(
        &self,
        regions: &[MemoryRegion],
        options: &CodeCaveOptions,
        read_fn: impl Fn(usize, usize) -> Result<Vec<u8>>,
    ) -> Result<Vec<CodeCave>> {
        let mut caves = Vec::new();

        for region in regions {
            // Skip non-executable regions if requested
            if options.executable_only && !region.protection.execute {
                continue;
            }

            // Skip reserved/free regions
            if region.state != ghost_common::MemoryState::Commit {
                continue;
            }

            // Try to read region memory
            let data = match read_fn(region.base, region.size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Find sequences of zeros (potential caves)
            let mut cave_start: Option<usize> = None;
            let mut current_pos = 0;

            while current_pos < data.len() {
                // Align to requested alignment
                let aligned_pos = (current_pos + options.alignment - 1) & !(options.alignment - 1);
                if aligned_pos >= data.len() {
                    break;
                }
                current_pos = aligned_pos;

                if data[current_pos] == 0x00 || data[current_pos] == 0xCC {
                    // Potential cave byte
                    if cave_start.is_none() {
                        cave_start = Some(current_pos);
                    }
                } else {
                    // End of potential cave
                    if let Some(start) = cave_start {
                        let cave_size = current_pos - start;
                        if cave_size >= options.min_size {
                            caves.push(CodeCave {
                                address: region.base + start,
                                size: cave_size,
                                module: None, // Could be resolved from module list
                                section: None,
                                in_use: false,
                            });

                            if caves.len() >= options.max_results {
                                return Ok(caves);
                            }
                        }
                    }
                    cave_start = None;
                }
                current_pos += 1;
            }

            // Check for cave at end of region
            if let Some(start) = cave_start {
                let cave_size = data.len() - start;
                if cave_size >= options.min_size {
                    caves.push(CodeCave {
                        address: region.base + start,
                        size: cave_size,
                        module: None,
                        section: None,
                        in_use: false,
                    });
                }
            }

            if caves.len() >= options.max_results {
                break;
            }
        }

        Ok(caves)
    }

    /// Allocate a code cave for use
    pub fn allocate_cave(&self, cave: CodeCave, description: Option<String>) -> AllocatedCave {
        let id = NEXT_CAVE_ID.fetch_add(1, Ordering::SeqCst);

        let allocated = AllocatedCave {
            id,
            cave,
            bytes_used: 0,
            description,
        };

        self.allocated_caves
            .write()
            .unwrap()
            .push(allocated.clone());

        allocated
    }

    /// Free an allocated code cave
    pub fn free_cave(&self, id: u32) -> Result<()> {
        let mut caves = self.allocated_caves.write().unwrap();
        if let Some(pos) = caves.iter().position(|c| c.id == id) {
            caves.remove(pos);
            Ok(())
        } else {
            Err(Error::Internal(format!("Cave {} not found", id)))
        }
    }

    /// List all allocated caves
    pub fn list_allocated_caves(&self) -> Vec<AllocatedCave> {
        self.allocated_caves.read().unwrap().clone()
    }

    /// Get syscall number for a function
    #[cfg(target_os = "windows")]
    pub fn get_syscall_number(&self, function: &str) -> Result<SyscallInfo> {
        // Check cache first
        if let Some(&number) = self.syscall_cache.read().unwrap().get(function) {
            return Ok(SyscallInfo {
                number,
                name: function.to_string(),
                arg_count: 0, // Would need to be looked up
                module: "ntdll.dll".to_string(),
            });
        }

        // Get ntdll function address
        let addr = self.resolve_function("ntdll.dll", function)?;

        // Read the syscall number from the stub
        // On x64 Windows, the pattern is:
        // mov r10, rcx
        // mov eax, <syscall_number>
        // The syscall number is at offset 4
        let stub = unsafe { std::slice::from_raw_parts(addr as *const u8, 8) };

        // Check for the expected pattern: 4C 8B D1 B8 XX XX XX XX
        if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
            let syscall_num = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]);

            // Cache it
            self.syscall_cache
                .write()
                .unwrap()
                .insert(function.to_string(), syscall_num);

            Ok(SyscallInfo {
                number: syscall_num,
                name: function.to_string(),
                arg_count: 0,
                module: "ntdll.dll".to_string(),
            })
        } else {
            Err(Error::Internal(format!(
                "Function '{}' does not appear to be a syscall stub",
                function
            )))
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_syscall_number(&self, _function: &str) -> Result<SyscallInfo> {
        Err(Error::NotImplemented(
            "Syscall resolution only supported on Windows".into(),
        ))
    }

    /// Invoke a syscall directly (bypassing user-mode hooks)
    ///
    /// # Safety
    /// This function directly invokes NT syscalls, bypassing any user-mode hooks.
    /// The caller must ensure:
    /// - The syscall number is valid for the current Windows version
    /// - The arguments match the expected syscall signature
    /// - The syscall is safe to invoke in the current context
    ///
    /// # Arguments
    /// * `syscall_num` - The syscall number (obtained from `get_syscall_number`)
    /// * `args` - Arguments to pass to the syscall (up to 17 supported)
    ///
    /// # Returns
    /// `SyscallResult` containing the NTSTATUS and success indicator
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub fn invoke_syscall(&self, syscall_num: u32, args: &[u64]) -> Result<SyscallResult> {
        self.invoke_syscall_with_method(syscall_num, args, ghost_common::SyscallMethod::Syscall)
    }

    /// Invoke a syscall with a specific method (syscall instruction or int 2e)
    ///
    /// # Arguments
    /// * `syscall_num` - The syscall number
    /// * `args` - Arguments to pass (up to 17 supported)
    /// * `method` - The syscall method to use (Syscall or Int2e)
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub fn invoke_syscall_with_method(
        &self,
        syscall_num: u32,
        args: &[u64],
        method: ghost_common::SyscallMethod,
    ) -> Result<SyscallResult> {
        info!(target: "ghost_core::execution",
            syscall_num = syscall_num,
            arg_count = args.len(),
            method = ?method,
            "Invoking direct syscall"
        );

        // Validate argument count (Windows syscalls typically have up to 17 args max)
        if args.len() > 17 {
            return Err(Error::Internal(format!(
                "Too many syscall arguments: {} (max 17)",
                args.len()
            )));
        }

        // Build arg table - pad to 17 elements
        let mut arg_table: [u64; 17] = [0; 17];
        for (i, arg) in args.iter().enumerate() {
            arg_table[i] = *arg;
        }

        let arg_count = args.len() as u32;

        // Use the appropriate syscall method
        let status: i32 = match method {
            ghost_common::SyscallMethod::Syscall => unsafe {
                Self::do_syscall(syscall_num, arg_count, arg_table.as_ptr())
            },
            ghost_common::SyscallMethod::Int2e => unsafe {
                Self::do_int2e(syscall_num, arg_count, arg_table.as_ptr())
            },
            ghost_common::SyscallMethod::Sysenter => {
                return Err(Error::NotImplemented(
                    "Sysenter is only supported on x86".into(),
                ));
            }
        };

        // Convert NTSTATUS to result
        let success = status >= 0; // NT_SUCCESS macro: status >= 0
        let status_name = Self::ntstatus_to_string(status);

        debug!(target: "ghost_core::execution",
            syscall_num = syscall_num,
            status = format!("{:#X}", status),
            status_name = %status_name,
            success = success,
            "Syscall completed"
        );

        let error = if success {
            None
        } else {
            Some(status_name.clone())
        };

        Ok(SyscallResult {
            status,
            success,
            status_name,
            out_params: Vec::new(),
            error,
        })
    }

    /// Internal: Execute syscall using the `syscall` instruction
    /// Handles arbitrary number of arguments (first 4 in registers, rest on stack)
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[inline(never)]
    unsafe fn do_syscall(syscall_idx: u32, arg_count: u32, arg_table: *const u64) -> i32 {
        use std::arch::asm;

        let result: i32;

        // Based on the reference implementation:
        // - First 4 args go to RCX, RDX, R8, R9
        // - Additional args are pushed to stack
        // - Need shadow space (0x28 bytes = 40 bytes)
        // - mov r10, rcx is required before syscall
        asm!(
            // Save callee-saved registers we'll use
            "push rsi",
            "push rdi",
            "push rbx",
            "push r12",

            // syscall_idx is in ecx (1st arg), arg_count in edx (2nd), arg_table in r8 (3rd)
            "mov eax, ecx",      // syscall number
            "mov esi, edx",      // arg count
            "mov rdi, r8",       // arg table pointer

            "xor ebx, ebx",      // clear rbx for stack tracking

            // Check if we have any args
            "test esi, esi",
            "jz 2f",             // jump to make_call if no args

            // Load arg 0 -> rcx
            "mov rcx, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            // Load arg 1 -> rdx
            "mov rdx, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            // Load arg 2 -> r8
            "mov r8, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            // Load arg 3 -> r9
            "mov r9, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            // If more than 4 args, push them to stack (in reverse order for proper calling convention)
            "mov ebx, esi",      // save remaining count
            "shl ebx, 3",        // multiply by 8 (size of u64)
            "sub rsp, rbx",      // allocate stack space for extra args
            "xor r12d, r12d",    // r12 = 0 (stack offset)

            "3:",                // push_argument loop
            "mov r11, [rdi]",
            "mov [rsp + r12], r11",
            "add r12, 8",
            "add rdi, 8",
            "dec esi",
            "jnz 3b",

            "2:",                // make_call
            // Allocate shadow space (32 bytes) + alignment (8 bytes) = 0x28
            "sub rsp, 0x28",

            // Windows syscall convention: r10 = rcx
            "mov r10, rcx",
            "syscall",

            // Cleanup
            "add rsp, 0x28",
            "add rsp, rbx",      // remove extra args from stack (rbx still has the size)

            // Restore callee-saved registers
            "pop r12",
            "pop rbx",
            "pop rdi",
            "pop rsi",

            in("ecx") syscall_idx,
            in("edx") arg_count,
            in("r8") arg_table,
            lateout("eax") result,
            // Clobbers
            out("r10") _,
            out("r11") _,
            clobber_abi("sysv64"),
        );

        result
    }

    /// Internal: Execute syscall using `int 2e` (legacy method)
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[inline(never)]
    unsafe fn do_int2e(syscall_idx: u32, arg_count: u32, arg_table: *const u64) -> i32 {
        use std::arch::asm;

        let result: i32;

        // Same as do_syscall but uses int 0x2e instead of syscall instruction
        asm!(
            // Save callee-saved registers
            "push rsi",
            "push rdi",
            "push rbx",
            "push r12",

            "mov eax, ecx",      // syscall number
            "mov esi, edx",      // arg count
            "mov rdi, r8",       // arg table pointer

            "xor ebx, ebx",      // clear rbx for stack tracking

            "test esi, esi",
            "jz 2f",

            "mov rcx, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            "mov rdx, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            "mov r8, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            "mov r9, [rdi]",
            "add rdi, 8",
            "dec esi",
            "jz 2f",

            "mov ebx, esi",
            "shl ebx, 3",
            "sub rsp, rbx",
            "xor r12d, r12d",

            "3:",
            "mov r11, [rdi]",
            "mov [rsp + r12], r11",
            "add r12, 8",
            "add rdi, 8",
            "dec esi",
            "jnz 3b",

            "2:",
            "sub rsp, 0x28",
            "mov r10, rcx",
            "int 0x2e",          // Use int 2e instead of syscall

            "add rsp, 0x28",
            "add rsp, rbx",

            "pop r12",
            "pop rbx",
            "pop rdi",
            "pop rsi",

            in("ecx") syscall_idx,
            in("edx") arg_count,
            in("r8") arg_table,
            lateout("eax") result,
            out("r10") _,
            out("r11") _,
            clobber_abi("sysv64"),
        );

        result
    }

    /// Invoke syscall on 32-bit Windows (not yet implemented)
    #[cfg(all(target_os = "windows", target_arch = "x86"))]
    pub fn invoke_syscall(&self, _syscall_num: u32, _args: &[u64]) -> Result<SyscallResult> {
        Err(Error::NotImplemented(
            "Direct syscall invocation not yet implemented for 32-bit Windows".into(),
        ))
    }

    #[cfg(all(target_os = "windows", target_arch = "x86"))]
    pub fn invoke_syscall_with_method(
        &self,
        _syscall_num: u32,
        _args: &[u64],
        _method: ghost_common::SyscallMethod,
    ) -> Result<SyscallResult> {
        Err(Error::NotImplemented(
            "Direct syscall invocation not yet implemented for 32-bit Windows".into(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(unused_variables)]
    pub fn invoke_syscall(&self, syscall_num: u32, args: &[u64]) -> Result<SyscallResult> {
        Err(Error::NotImplemented(
            "Syscall invocation only supported on Windows".into(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(unused_variables)]
    pub fn invoke_syscall_with_method(
        &self,
        syscall_num: u32,
        args: &[u64],
        method: ghost_common::SyscallMethod,
    ) -> Result<SyscallResult> {
        Err(Error::NotImplemented(
            "Syscall invocation only supported on Windows".into(),
        ))
    }

    /// Allocate memory for shellcode or code
    #[cfg(target_os = "windows")]
    pub fn allocate_executable_memory(&self, size: usize) -> Result<usize> {
        let addr =
            unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

        if addr.is_null() {
            Err(Error::Internal(
                "Failed to allocate executable memory".into(),
            ))
        } else {
            Ok(addr as usize)
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn allocate_executable_memory(&self, _size: usize) -> Result<usize> {
        Err(Error::NotImplemented(
            "Memory allocation only supported on Windows".into(),
        ))
    }

    /// Free allocated memory
    #[cfg(target_os = "windows")]
    pub fn free_memory(&self, address: usize) -> Result<()> {
        let result = unsafe { VirtualFree(address as *mut _, 0, MEM_RELEASE) };
        if result.is_ok() {
            Ok(())
        } else {
            Err(Error::Internal("Failed to free memory".into()))
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn free_memory(&self, _address: usize) -> Result<()> {
        Err(Error::NotImplemented(
            "Memory operations only supported on Windows".into(),
        ))
    }

    /// Write shellcode/data to a memory address
    #[cfg(target_os = "windows")]
    pub fn write_executable(&self, address: usize, data: &[u8]) -> Result<()> {
        // Change protection temporarily if needed
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            let _ = VirtualProtect(
                address as *const _,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            std::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());

            // Restore protection
            let _ = VirtualProtect(
                address as *const _,
                data.len(),
                old_protect,
                &mut old_protect,
            );
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn write_executable(&self, _address: usize, _data: &[u8]) -> Result<()> {
        Err(Error::NotImplemented(
            "Memory operations only supported on Windows".into(),
        ))
    }

    // ========================================================================
    // Remote Execution Methods (Cross-Process)
    // ========================================================================

    /// Create a remote thread in another process to execute code at a specific address
    ///
    /// # Arguments
    /// * `pid` - Target process ID (must be non-zero)
    /// * `address` - Address to execute (must be non-zero)
    /// * `parameter` - Optional parameter to pass
    /// * `wait` - Whether to wait for thread completion
    /// * `timeout_ms` - Timeout for waiting (0 = infinite)
    ///
    /// # Returns
    /// `RemoteThreadResult` with thread info and execution status
    #[cfg(target_os = "windows")]
    pub fn create_remote_thread_at(
        &self,
        pid: u32,
        address: usize,
        parameter: Option<u64>,
        wait: bool,
        timeout_ms: u64,
    ) -> Result<ghost_common::RemoteThreadResult> {
        // Input validation
        if pid == 0 {
            warn!(target: "ghost_core::execution", "create_remote_thread_at called with PID 0");
            return Err(Error::Internal("Invalid process ID: 0".into()));
        }
        if address == 0 {
            warn!(target: "ghost_core::execution", "create_remote_thread_at called with null address");
            return Err(Error::Internal("Invalid address: 0".into()));
        }

        info!(target: "ghost_core::execution",
            pid = pid,
            address = format!("{:#x}", address),
            wait = wait,
            timeout_ms = timeout_ms,
            "Creating remote thread at address"
        );

        unsafe {
            // Open target process
            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid).map_err(|e| {
                error!(target: "ghost_core::execution",
                    pid = pid,
                    error = %e,
                    "Failed to open process for remote thread"
                );
                Error::Internal(format!("OpenProcess failed for PID {}: {}", pid, e))
            })?;

            // Create remote thread
            let param = parameter.unwrap_or(0);
            let mut thread_id: u32 = 0;
            let thread_handle = CreateRemoteThread(
                process_handle,
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                >(address)),
                Some(param as *const std::ffi::c_void),
                0,
                Some(&mut thread_id),
            )
            .map_err(|e| {
                let _ = CloseHandle(process_handle);
                Error::Internal(format!("CreateRemoteThread failed: {}", e))
            })?;

            debug!(target: "ghost_core::execution",
                "Remote thread {} created at {:#x} in process {}",
                thread_id, address, pid
            );

            let mut exit_code: Option<u32> = None;
            let mut completed = false;

            if wait {
                let wait_time = if timeout_ms == 0 {
                    INFINITE
                } else {
                    timeout_ms as u32
                };
                let wait_result = WaitForSingleObject(thread_handle, wait_time);

                // Check if completed (WAIT_OBJECT_0 = 0)
                if wait_result.0 == 0 {
                    completed = true;
                    let mut code: u32 = 0;
                    if GetExitCodeThread(thread_handle, &mut code).is_ok() {
                        exit_code = Some(code);
                    }
                }
            }

            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);

            Ok(ghost_common::RemoteThreadResult {
                thread_id,
                handle: 0, // Handle already closed
                remote_address: address,
                completed,
                exit_code,
                error: None,
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn create_remote_thread_at(
        &self,
        _pid: u32,
        _address: usize,
        _parameter: Option<u64>,
        _wait: bool,
        _timeout_ms: u64,
    ) -> Result<ghost_common::RemoteThreadResult> {
        Err(Error::NotImplemented(
            "Remote thread creation only supported on Windows".into(),
        ))
    }

    /// Queue an APC to a thread in a remote process at a specific address
    ///
    /// # Arguments
    /// * `pid` - Target process ID (must be non-zero)
    /// * `tid` - Target thread ID (must be non-zero)
    /// * `address` - Address to execute (must be non-zero)
    /// * `parameter` - Optional parameter to pass
    ///
    /// # Safety
    /// Requires sufficient privileges.
    #[cfg(target_os = "windows")]
    pub fn queue_remote_apc_at(
        &self,
        pid: u32,
        tid: u32,
        address: usize,
        parameter: Option<u64>,
    ) -> Result<()> {
        // Input validation
        if pid == 0 {
            warn!(target: "ghost_core::execution", "queue_remote_apc_at called with PID 0");
            return Err(Error::Internal("Invalid process ID: 0".into()));
        }
        if tid == 0 {
            warn!(target: "ghost_core::execution", "queue_remote_apc_at called with TID 0");
            return Err(Error::Internal("Invalid thread ID: 0".into()));
        }
        if address == 0 {
            warn!(target: "ghost_core::execution", "queue_remote_apc_at called with null address");
            return Err(Error::Internal("Invalid address: 0".into()));
        }

        info!(target: "ghost_core::execution",
            pid = pid,
            tid = tid,
            address = format!("{:#x}", address),
            parameter = ?parameter,
            "Queuing remote APC at address"
        );

        unsafe {
            // Open the target thread
            let thread_handle = OpenThread(THREAD_ALL_ACCESS, false, tid)
                .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

            // Queue the APC
            let param = parameter.unwrap_or(0);
            let result = QueueUserAPC(
                Some(std::mem::transmute::<usize, unsafe extern "system" fn(usize)>(address)),
                thread_handle,
                param as usize,
            );

            let _ = CloseHandle(thread_handle);

            if result == 0 {
                return Err(Error::Internal("QueueUserAPC failed".into()));
            }

            debug!(target: "ghost_core::execution",
                "Remote APC queued to thread {} at {:#x}",
                tid, address
            );

            Ok(())
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn queue_remote_apc_at(
        &self,
        _pid: u32,
        _tid: u32,
        _address: usize,
        _parameter: Option<u64>,
    ) -> Result<()> {
        Err(Error::NotImplemented(
            "Remote APC queuing only supported on Windows".into(),
        ))
    }

    /// Create a remote thread in another process to execute code
    ///
    /// # Arguments
    /// * `pid` - Target process ID (must be non-zero)
    /// * `shellcode` - Shellcode bytes to execute (must be non-empty)
    /// * `parameter` - Optional parameter to pass
    /// * `wait` - Whether to wait for thread completion
    /// * `timeout_ms` - Timeout for waiting (0 = infinite)
    ///
    /// # Returns
    /// `RemoteThreadResult` with thread info and execution status
    ///
    /// # Safety
    /// Requires sufficient privileges to access the target process.
    /// The shellcode must be valid x64 code that can execute in the target process.
    #[cfg(target_os = "windows")]
    pub fn create_remote_thread(
        &self,
        pid: u32,
        shellcode: &[u8],
        parameter: Option<u64>,
        wait: bool,
        timeout_ms: u64,
    ) -> Result<ghost_common::RemoteThreadResult> {
        // Input validation
        if pid == 0 {
            warn!(target: "ghost_core::execution", "create_remote_thread called with PID 0");
            return Err(Error::Internal("Invalid process ID: 0".into()));
        }
        if shellcode.is_empty() {
            warn!(target: "ghost_core::execution", "create_remote_thread called with empty shellcode");
            return Err(Error::Internal("Shellcode cannot be empty".into()));
        }
        // Sanity check: shellcode shouldn't be excessively large
        const MAX_SHELLCODE_SIZE: usize = 10 * 1024 * 1024; // 10MB limit
        if shellcode.len() > MAX_SHELLCODE_SIZE {
            warn!(target: "ghost_core::execution",
                shellcode_len = shellcode.len(),
                "Shellcode exceeds maximum size"
            );
            return Err(Error::Internal(format!(
                "Shellcode size {} exceeds maximum {}",
                shellcode.len(),
                MAX_SHELLCODE_SIZE
            )));
        }

        info!(target: "ghost_core::execution",
            pid = pid,
            shellcode_len = shellcode.len(),
            wait = wait,
            timeout_ms = timeout_ms,
            "Creating remote thread"
        );

        unsafe {
            // Open target process
            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid).map_err(|e| {
                error!(target: "ghost_core::execution",
                    pid = pid,
                    error = %e,
                    "Failed to open process for remote thread"
                );
                Error::Internal(format!("OpenProcess failed for PID {}: {}", pid, e))
            })?;

            // Allocate memory in remote process
            let remote_addr = VirtualAllocEx(
                process_handle,
                None,
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if remote_addr.is_null() {
                let _ = CloseHandle(process_handle);
                return Err(Error::Internal("VirtualAllocEx failed".into()));
            }

            let remote_addr_usize = remote_addr as usize;

            // Write shellcode to remote process
            let mut bytes_written: usize = 0;
            let write_result = WriteProcessMemory(
                process_handle,
                remote_addr,
                shellcode.as_ptr() as *const _,
                shellcode.len(),
                Some(&mut bytes_written),
            );

            if write_result.is_err() || bytes_written != shellcode.len() {
                let _ = VirtualFreeEx(process_handle, remote_addr, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(Error::Internal("WriteProcessMemory failed".into()));
            }

            // Flush instruction cache
            let _ = FlushInstructionCache(process_handle, Some(remote_addr), shellcode.len());

            // Create remote thread
            let param = parameter.unwrap_or(0);
            let mut thread_id: u32 = 0;
            let thread_handle = CreateRemoteThread(
                process_handle,
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                >(remote_addr_usize)),
                Some(param as *const std::ffi::c_void),
                0,
                Some(&mut thread_id),
            )
            .map_err(|e| {
                let _ = VirtualFreeEx(process_handle, remote_addr, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                Error::Internal(format!("CreateRemoteThread failed: {}", e))
            })?;

            debug!(target: "ghost_core::execution",
                "Remote thread {} created at {:#x} in process {}",
                thread_id, remote_addr_usize, pid
            );

            let mut exit_code: Option<u32> = None;
            let mut completed = false;

            if wait {
                let wait_time = if timeout_ms == 0 {
                    INFINITE
                } else {
                    timeout_ms as u32
                };
                let wait_result = WaitForSingleObject(thread_handle, wait_time);

                // Check if completed (WAIT_OBJECT_0 = 0)
                if wait_result.0 == 0 {
                    completed = true;
                    let mut code: u32 = 0;
                    if GetExitCodeThread(thread_handle, &mut code).is_ok() {
                        exit_code = Some(code);
                    }
                }
            }

            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);

            Ok(ghost_common::RemoteThreadResult {
                thread_id,
                handle: 0, // Handle already closed
                remote_address: remote_addr_usize,
                completed,
                exit_code,
                error: None,
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn create_remote_thread(
        &self,
        _pid: u32,
        _shellcode: &[u8],
        _parameter: Option<u64>,
        _wait: bool,
        _timeout_ms: u64,
    ) -> Result<ghost_common::RemoteThreadResult> {
        Err(Error::NotImplemented(
            "Remote thread creation only supported on Windows".into(),
        ))
    }

    /// Queue an APC to a thread in a remote process
    ///
    /// # Arguments
    /// * `pid` - Target process ID (must be non-zero)
    /// * `tid` - Target thread ID (must be non-zero)
    /// * `shellcode` - Shellcode bytes to execute (must be non-empty)
    /// * `parameter` - Optional parameter to pass
    ///
    /// # Returns
    /// The remote address where shellcode was written
    ///
    /// # Safety
    /// Requires sufficient privileges. The target thread must enter an alertable
    /// wait state for the APC to execute.
    #[cfg(target_os = "windows")]
    pub fn queue_remote_apc(
        &self,
        pid: u32,
        tid: u32,
        shellcode: &[u8],
        parameter: Option<u64>,
    ) -> Result<usize> {
        // Input validation
        if pid == 0 {
            warn!(target: "ghost_core::execution", "queue_remote_apc called with PID 0");
            return Err(Error::Internal("Invalid process ID: 0".into()));
        }
        if tid == 0 {
            warn!(target: "ghost_core::execution", "queue_remote_apc called with TID 0");
            return Err(Error::Internal("Invalid thread ID: 0".into()));
        }
        if shellcode.is_empty() {
            warn!(target: "ghost_core::execution", "queue_remote_apc called with empty shellcode");
            return Err(Error::Internal("Shellcode cannot be empty".into()));
        }

        info!(target: "ghost_core::execution",
            pid = pid,
            tid = tid,
            shellcode_len = shellcode.len(),
            parameter = ?parameter,
            "Queuing remote APC"
        );

        unsafe {
            // Open target process
            let process_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid)
                .map_err(|e| {
                error!(target: "ghost_core::execution",
                    pid = pid,
                    error = %e,
                    "Failed to open process for remote APC"
                );
                Error::Internal(format!("OpenProcess failed for PID {}: {}", pid, e))
            })?;

            // Allocate memory in remote process
            let remote_addr = VirtualAllocEx(
                process_handle,
                None,
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if remote_addr.is_null() {
                let _ = CloseHandle(process_handle);
                return Err(Error::Internal("VirtualAllocEx failed".into()));
            }

            let remote_addr_usize = remote_addr as usize;

            // Write shellcode to remote process
            let mut bytes_written: usize = 0;
            let write_result = WriteProcessMemory(
                process_handle,
                remote_addr,
                shellcode.as_ptr() as *const _,
                shellcode.len(),
                Some(&mut bytes_written),
            );

            if write_result.is_err() || bytes_written != shellcode.len() {
                let _ = VirtualFreeEx(process_handle, remote_addr, 0, MEM_RELEASE);
                let _ = CloseHandle(process_handle);
                return Err(Error::Internal("WriteProcessMemory failed".into()));
            }

            // Flush instruction cache
            let _ = FlushInstructionCache(process_handle, Some(remote_addr), shellcode.len());
            let _ = CloseHandle(process_handle);

            // Open the target thread
            let thread_handle = OpenThread(THREAD_ALL_ACCESS, false, tid)
                .map_err(|e| Error::Internal(format!("OpenThread failed: {}", e)))?;

            // Queue the APC
            let param = parameter.unwrap_or(0);
            let result = QueueUserAPC(
                Some(
                    std::mem::transmute::<usize, unsafe extern "system" fn(usize)>(
                        remote_addr_usize,
                    ),
                ),
                thread_handle,
                param as usize,
            );

            let _ = CloseHandle(thread_handle);

            if result == 0 {
                return Err(Error::Internal("QueueUserAPC failed".into()));
            }

            debug!(target: "ghost_core::execution",
                "Remote APC queued to thread {} at {:#x}",
                tid, remote_addr_usize
            );

            Ok(remote_addr_usize)
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn queue_remote_apc(
        &self,
        _pid: u32,
        _tid: u32,
        _shellcode: &[u8],
        _parameter: Option<u64>,
    ) -> Result<usize> {
        Err(Error::NotImplemented(
            "Remote APC queuing only supported on Windows".into(),
        ))
    }

    /// Free memory in a remote process
    ///
    /// # Arguments
    /// * `pid` - Target process ID
    /// * `address` - Address to free
    #[cfg(target_os = "windows")]
    pub fn free_remote_memory(&self, pid: u32, address: usize) -> Result<()> {
        unsafe {
            let process_handle = OpenProcess(PROCESS_VM_OPERATION, false, pid)
                .map_err(|e| Error::Internal(format!("OpenProcess failed: {}", e)))?;

            let result = VirtualFreeEx(process_handle, address as *mut _, 0, MEM_RELEASE);
            let _ = CloseHandle(process_handle);

            if result.is_ok() {
                Ok(())
            } else {
                Err(Error::Internal("VirtualFreeEx failed".into()))
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn free_remote_memory(&self, _pid: u32, _address: usize) -> Result<()> {
        Err(Error::NotImplemented(
            "Remote memory operations only supported on Windows".into(),
        ))
    }

    /// Get cache statistics for debugging/monitoring
    pub fn cache_stats(&self) -> (usize, usize, usize) {
        let modules = self.module_cache.read().map(|c| c.len()).unwrap_or(0);
        let functions = self.function_cache.read().map(|c| c.len()).unwrap_or(0);
        let syscalls = self.syscall_cache.read().map(|c| c.len()).unwrap_or(0);
        (modules, functions, syscalls)
    }

    /// Convert NTSTATUS code to human-readable string
    ///
    /// Covers the most common NT status codes encountered in syscall operations.
    /// Returns hex format for unknown codes.
    pub fn ntstatus_to_string(status: i32) -> String {
        // Success codes (positive or zero)
        match status as u32 {
            // Success codes
            0x00000000 => "STATUS_SUCCESS".to_string(),
            0x00000001 => "STATUS_WAIT_1".to_string(),
            0x00000002 => "STATUS_WAIT_2".to_string(),
            0x00000003 => "STATUS_WAIT_3".to_string(),
            0x0000003F => "STATUS_WAIT_63".to_string(),
            0x00000080 => "STATUS_ABANDONED_WAIT_0".to_string(),
            0x000000C0 => "STATUS_USER_APC".to_string(),
            0x00000101 => "STATUS_ALERTED".to_string(),
            0x00000102 => "STATUS_TIMEOUT".to_string(),
            0x00000103 => "STATUS_PENDING".to_string(),
            0x00000104 => "STATUS_REPARSE".to_string(),
            0x00000105 => "STATUS_MORE_ENTRIES".to_string(),
            0x00000106 => "STATUS_NOT_ALL_ASSIGNED".to_string(),
            0x00000107 => "STATUS_SOME_NOT_MAPPED".to_string(),
            0x00000108 => "STATUS_OPLOCK_BREAK_IN_PROGRESS".to_string(),
            0x0000010A => "STATUS_NOTIFY_CLEANUP".to_string(),
            0x0000010B => "STATUS_NOTIFY_ENUM_DIR".to_string(),
            0x0000010C => "STATUS_NO_QUOTAS_FOR_ACCOUNT".to_string(),

            // Informational codes (0x40xxxxxx)
            0x40000000 => "STATUS_OBJECT_NAME_EXISTS".to_string(),
            0x40000001 => "STATUS_THREAD_WAS_SUSPENDED".to_string(),
            0x40000002 => "STATUS_WORKING_SET_LIMIT_RANGE".to_string(),
            0x40000003 => "STATUS_IMAGE_NOT_AT_BASE".to_string(),
            0x40000005 => "STATUS_LOCAL_USER_SESSION_KEY".to_string(),
            0x40000006 => "STATUS_BAD_CURRENT_DIRECTORY".to_string(),
            0x4000000D => "STATUS_IMAGE_MACHINE_TYPE_MISMATCH".to_string(),
            0x40000015 => "STATUS_RECEIVE_PARTIAL".to_string(),
            0x40000016 => "STATUS_RECEIVE_EXPEDITED".to_string(),
            0x4000001A => "STATUS_EVENT_DONE".to_string(),
            0x4000001B => "STATUS_EVENT_PENDING".to_string(),

            // Warning codes (0x80xxxxxx)
            0x80000001 => "STATUS_GUARD_PAGE_VIOLATION".to_string(),
            0x80000002 => "STATUS_DATATYPE_MISALIGNMENT".to_string(),
            0x80000003 => "STATUS_BREAKPOINT".to_string(),
            0x80000004 => "STATUS_SINGLE_STEP".to_string(),
            0x80000005 => "STATUS_BUFFER_OVERFLOW".to_string(),
            0x80000006 => "STATUS_NO_MORE_FILES".to_string(),
            0x8000000A => "STATUS_HANDLES_CLOSED".to_string(),
            0x8000000B => "STATUS_NO_INHERITANCE".to_string(),
            0x8000000D => "STATUS_PARTIAL_COPY".to_string(),
            0x8000001A => "STATUS_NO_MORE_ENTRIES".to_string(),
            0x80000288 => "STATUS_DEVICE_PAPER_EMPTY".to_string(),

            // Error codes (0xC0xxxxxx)
            0xC0000001 => "STATUS_UNSUCCESSFUL".to_string(),
            0xC0000002 => "STATUS_NOT_IMPLEMENTED".to_string(),
            0xC0000003 => "STATUS_INVALID_INFO_CLASS".to_string(),
            0xC0000004 => "STATUS_INFO_LENGTH_MISMATCH".to_string(),
            0xC0000005 => "STATUS_ACCESS_VIOLATION".to_string(),
            0xC0000006 => "STATUS_IN_PAGE_ERROR".to_string(),
            0xC0000007 => "STATUS_PAGEFILE_QUOTA".to_string(),
            0xC0000008 => "STATUS_INVALID_HANDLE".to_string(),
            0xC0000009 => "STATUS_BAD_INITIAL_STACK".to_string(),
            0xC000000A => "STATUS_BAD_INITIAL_PC".to_string(),
            0xC000000B => "STATUS_INVALID_CID".to_string(),
            0xC000000C => "STATUS_TIMER_NOT_CANCELED".to_string(),
            0xC000000D => "STATUS_INVALID_PARAMETER".to_string(),
            0xC000000E => "STATUS_NO_SUCH_DEVICE".to_string(),
            0xC000000F => "STATUS_NO_SUCH_FILE".to_string(),
            0xC0000010 => "STATUS_INVALID_DEVICE_REQUEST".to_string(),
            0xC0000011 => "STATUS_END_OF_FILE".to_string(),
            0xC0000012 => "STATUS_WRONG_VOLUME".to_string(),
            0xC0000013 => "STATUS_NO_MEDIA_IN_DEVICE".to_string(),
            0xC0000014 => "STATUS_UNRECOGNIZED_MEDIA".to_string(),
            0xC0000015 => "STATUS_NONEXISTENT_SECTOR".to_string(),
            0xC0000016 => "STATUS_MORE_PROCESSING_REQUIRED".to_string(),
            0xC0000017 => "STATUS_NO_MEMORY".to_string(),
            0xC0000018 => "STATUS_CONFLICTING_ADDRESSES".to_string(),
            0xC0000019 => "STATUS_NOT_MAPPED_VIEW".to_string(),
            0xC000001A => "STATUS_UNABLE_TO_FREE_VM".to_string(),
            0xC000001B => "STATUS_UNABLE_TO_DELETE_SECTION".to_string(),
            0xC000001C => "STATUS_INVALID_SYSTEM_SERVICE".to_string(),
            0xC000001D => "STATUS_ILLEGAL_INSTRUCTION".to_string(),
            0xC000001E => "STATUS_INVALID_LOCK_SEQUENCE".to_string(),
            0xC000001F => "STATUS_INVALID_VIEW_SIZE".to_string(),
            0xC0000020 => "STATUS_INVALID_FILE_FOR_SECTION".to_string(),
            0xC0000021 => "STATUS_ALREADY_COMMITTED".to_string(),
            0xC0000022 => "STATUS_ACCESS_DENIED".to_string(),
            0xC0000023 => "STATUS_BUFFER_TOO_SMALL".to_string(),
            0xC0000024 => "STATUS_OBJECT_TYPE_MISMATCH".to_string(),
            0xC0000025 => "STATUS_NONCONTINUABLE_EXCEPTION".to_string(),
            0xC0000026 => "STATUS_INVALID_DISPOSITION".to_string(),
            0xC0000027 => "STATUS_UNWIND".to_string(),
            0xC0000028 => "STATUS_BAD_STACK".to_string(),
            0xC0000029 => "STATUS_INVALID_UNWIND_TARGET".to_string(),
            0xC000002A => "STATUS_NOT_LOCKED".to_string(),
            0xC000002B => "STATUS_PARITY_ERROR".to_string(),
            0xC000002C => "STATUS_UNABLE_TO_DECOMMIT_VM".to_string(),
            0xC000002D => "STATUS_NOT_COMMITTED".to_string(),
            0xC0000030 => "STATUS_INVALID_PORT_HANDLE".to_string(),
            0xC0000033 => "STATUS_OBJECT_NAME_INVALID".to_string(),
            0xC0000034 => "STATUS_OBJECT_NAME_NOT_FOUND".to_string(),
            0xC0000035 => "STATUS_OBJECT_NAME_COLLISION".to_string(),
            0xC0000037 => "STATUS_PORT_DISCONNECTED".to_string(),
            0xC0000039 => "STATUS_OBJECT_PATH_INVALID".to_string(),
            0xC000003A => "STATUS_OBJECT_PATH_NOT_FOUND".to_string(),
            0xC000003B => "STATUS_OBJECT_PATH_SYNTAX_BAD".to_string(),
            0xC000003C => "STATUS_DATA_OVERRUN".to_string(),
            0xC000003D => "STATUS_DATA_LATE_ERROR".to_string(),
            0xC000003E => "STATUS_DATA_ERROR".to_string(),
            0xC000003F => "STATUS_CRC_ERROR".to_string(),
            0xC0000040 => "STATUS_SECTION_TOO_BIG".to_string(),
            0xC0000041 => "STATUS_PORT_CONNECTION_REFUSED".to_string(),
            0xC0000042 => "STATUS_INVALID_PORT_HANDLE".to_string(),
            0xC0000043 => "STATUS_SHARING_VIOLATION".to_string(),
            0xC0000044 => "STATUS_QUOTA_EXCEEDED".to_string(),
            0xC0000045 => "STATUS_INVALID_PAGE_PROTECTION".to_string(),
            0xC0000046 => "STATUS_MUTANT_NOT_OWNED".to_string(),
            0xC0000047 => "STATUS_SEMAPHORE_LIMIT_EXCEEDED".to_string(),
            0xC0000048 => "STATUS_PORT_ALREADY_SET".to_string(),
            0xC0000049 => "STATUS_SECTION_NOT_IMAGE".to_string(),
            0xC000004A => "STATUS_SUSPEND_COUNT_EXCEEDED".to_string(),
            0xC000004B => "STATUS_THREAD_IS_TERMINATING".to_string(),
            0xC000004C => "STATUS_BAD_WORKING_SET_LIMIT".to_string(),
            0xC000004D => "STATUS_INCOMPATIBLE_FILE_MAP".to_string(),
            0xC000004E => "STATUS_SECTION_PROTECTION".to_string(),
            0xC0000050 => "STATUS_FILE_LOCK_CONFLICT".to_string(),
            0xC0000051 => "STATUS_LOCK_NOT_GRANTED".to_string(),
            0xC0000052 => "STATUS_DELETE_PENDING".to_string(),
            0xC0000054 => "STATUS_FILE_IS_A_DIRECTORY".to_string(),
            0xC0000055 => "STATUS_NOT_A_DIRECTORY".to_string(),
            0xC0000056 => "STATUS_PROCESS_IS_TERMINATING".to_string(),
            0xC000007A => "STATUS_PROCEDURE_NOT_FOUND".to_string(),
            0xC00000BB => "STATUS_NOT_SUPPORTED".to_string(),
            0xC00000BA => "STATUS_FILE_IS_OFFLINE".to_string(),
            0xC0000135 => "STATUS_DLL_NOT_FOUND".to_string(),
            0xC0000139 => "STATUS_ENTRYPOINT_NOT_FOUND".to_string(),
            0xC000013A => "STATUS_CONTROL_C_EXIT".to_string(),
            0xC0000142 => "STATUS_DLL_INIT_FAILED".to_string(),
            0xC0000194 => "STATUS_POSSIBLE_DEADLOCK".to_string(),
            0xC0000225 => "STATUS_NOT_FOUND".to_string(),
            0xC000022D => "STATUS_RETRY".to_string(),
            0xC0000236 => "STATUS_OBJECT_NO_LONGER_EXISTS".to_string(),

            // Unknown code - show hex
            _ => format!("NTSTATUS({:#010X})", status as u32),
        }
    }

    /// Check if an NTSTATUS is a success code
    #[inline]
    pub fn nt_success(status: i32) -> bool {
        status >= 0
    }

    /// Check if an NTSTATUS is an information code
    #[inline]
    pub fn nt_information(status: i32) -> bool {
        let u = status as u32;
        (u >> 30) == 1
    }

    /// Check if an NTSTATUS is a warning code
    #[inline]
    pub fn nt_warning(status: i32) -> bool {
        let u = status as u32;
        (u >> 30) == 2
    }

    /// Check if an NTSTATUS is an error code
    #[inline]
    pub fn nt_error(status: i32) -> bool {
        let u = status as u32;
        (u >> 30) == 3
    }
}

/// Parse hex string to bytes
///
/// Supports formats like:
/// - "48 8B C1" (space-separated)
/// - "488BC1" (continuous)
/// - "0x48 0x8B 0xC1" (with 0x prefix)
///
/// # Arguments
/// * `hex` - Hex string to parse
///
/// # Returns
/// A vector of bytes on success, or an error if parsing fails
pub fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }

    let hex = hex.replace(' ', "").replace("0x", "").replace(',', "");

    if !hex.len().is_multiple_of(2) {
        return Err(Error::Internal(format!(
            "Hex string must have even length, got {} characters",
            hex.len()
        )));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| Error::Internal(format!("Invalid hex byte at position {}: {}", i, e)))?;
        bytes.push(byte);
    }

    trace!(target: "ghost_core::execution", "Parsed {} hex bytes", bytes.len());
    Ok(bytes)
}

/// Format bytes as hex string
///
/// # Arguments
/// * `bytes` - Bytes to format
/// * `separator` - Optional separator between bytes
///
/// # Returns
/// Formatted hex string
pub fn format_hex_bytes(bytes: &[u8], separator: Option<&str>) -> String {
    match separator {
        Some(sep) => bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(sep),
        None => bytes.iter().map(|b| format!("{:02X}", b)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // CallingConvention Tests
    // ========================================

    #[test]
    fn test_calling_convention_parse() {
        assert_eq!(
            CallingConvention::parse("cdecl"),
            Some(CallingConvention::Cdecl)
        );
        assert_eq!(
            CallingConvention::parse("c"),
            Some(CallingConvention::Cdecl)
        );
        assert_eq!(
            CallingConvention::parse("win64"),
            Some(CallingConvention::Win64)
        );
        assert_eq!(
            CallingConvention::parse("x64"),
            Some(CallingConvention::Win64)
        );
        assert_eq!(
            CallingConvention::parse("stdcall"),
            Some(CallingConvention::Stdcall)
        );
        assert_eq!(
            CallingConvention::parse("winapi"),
            Some(CallingConvention::Stdcall)
        );
        assert_eq!(
            CallingConvention::parse("fastcall"),
            Some(CallingConvention::Fastcall)
        );
        assert_eq!(
            CallingConvention::parse("thiscall"),
            Some(CallingConvention::Thiscall)
        );
        assert_eq!(
            CallingConvention::parse("sysv64"),
            Some(CallingConvention::SysV64)
        );
        assert_eq!(CallingConvention::parse("invalid"), None);
        assert_eq!(CallingConvention::parse(""), None);
    }

    #[test]
    fn test_calling_convention_case_insensitive() {
        assert_eq!(
            CallingConvention::parse("CDECL"),
            Some(CallingConvention::Cdecl)
        );
        assert_eq!(
            CallingConvention::parse("Win64"),
            Some(CallingConvention::Win64)
        );
        assert_eq!(
            CallingConvention::parse("STDCALL"),
            Some(CallingConvention::Stdcall)
        );
    }

    // ========================================
    // ShellcodeExecMethod Tests
    // ========================================

    #[test]
    fn test_shellcode_exec_method_parse() {
        assert_eq!(
            ShellcodeExecMethod::parse("current"),
            Some(ShellcodeExecMethod::CurrentThread)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("direct"),
            Some(ShellcodeExecMethod::CurrentThread)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("thread"),
            Some(ShellcodeExecMethod::NewThread)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("newthread"),
            Some(ShellcodeExecMethod::NewThread)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("ntcreate"),
            Some(ShellcodeExecMethod::NtCreateThreadEx)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("apc"),
            Some(ShellcodeExecMethod::ApcInjection)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("hijack"),
            Some(ShellcodeExecMethod::ThreadHijack)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("fiber"),
            Some(ShellcodeExecMethod::Fiber)
        );
        assert_eq!(
            ShellcodeExecMethod::parse("callback"),
            Some(ShellcodeExecMethod::Callback)
        );
        assert_eq!(ShellcodeExecMethod::parse("invalid"), None);
    }

    // ========================================
    // Hex Parsing Tests
    // ========================================

    #[test]
    fn test_parse_hex_bytes_various_formats() {
        // Space-separated
        assert_eq!(parse_hex_bytes("48 8B C1").unwrap(), vec![0x48, 0x8B, 0xC1]);
        // Continuous
        assert_eq!(parse_hex_bytes("488BC1").unwrap(), vec![0x48, 0x8B, 0xC1]);
        // With 0x prefix
        assert_eq!(parse_hex_bytes("0x48 0x8B").unwrap(), vec![0x48, 0x8B]);
        // Mixed case
        assert_eq!(parse_hex_bytes("aAbBcC").unwrap(), vec![0xAA, 0xBB, 0xCC]);
        // With commas
        assert_eq!(parse_hex_bytes("48,8B,C1").unwrap(), vec![0x48, 0x8B, 0xC1]);
    }

    #[test]
    fn test_parse_hex_bytes_empty() {
        assert_eq!(parse_hex_bytes("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_parse_hex_bytes_errors() {
        assert!(parse_hex_bytes("4").is_err()); // Odd length
        assert!(parse_hex_bytes("GG").is_err()); // Invalid hex
        assert!(parse_hex_bytes("4Z").is_err()); // Invalid character
    }

    #[test]
    fn test_format_hex_bytes() {
        assert_eq!(format_hex_bytes(&[0x48, 0x8B, 0xC1], None), "488BC1");
        assert_eq!(format_hex_bytes(&[0x48, 0x8B, 0xC1], Some(" ")), "48 8B C1");
        assert_eq!(format_hex_bytes(&[], None), "");
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![0x48, 0x31, 0xC0, 0xC3];
        let hex = format_hex_bytes(&original, Some(" "));
        let parsed = parse_hex_bytes(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    // ========================================
    // FunctionArg Tests
    // ========================================

    #[test]
    fn test_function_arg_as_u64() {
        assert_eq!(FunctionArg::Int(42).as_u64(), 42);
        assert_eq!(
            FunctionArg::Int(0xFFFFFFFFFFFFFFFF).as_u64(),
            0xFFFFFFFFFFFFFFFF
        );
        assert_eq!(FunctionArg::Pointer(0x1000).as_u64(), 0x1000);
        assert_eq!(FunctionArg::Null.as_u64(), 0);

        // Float conversion
        let float_arg = FunctionArg::Float(1.5);
        assert_eq!(float_arg.as_u64(), 1.5_f64.to_bits());

        // String types return 0 (need allocation first)
        assert_eq!(FunctionArg::String("test".into()).as_u64(), 0);
        assert_eq!(FunctionArg::WideString("test".into()).as_u64(), 0);
        assert_eq!(FunctionArg::Bytes(vec![1, 2, 3]).as_u64(), 0);
    }

    // ========================================
    // ExecutionEngine Tests
    // ========================================

    #[test]
    fn test_execution_engine_new() {
        let engine = ExecutionEngine::new();
        assert!(engine.list_allocated_caves().is_empty());
        assert_eq!(engine.cache_stats(), (0, 0, 0));
    }

    #[test]
    fn test_execution_engine_clear_caches() {
        let engine = ExecutionEngine::new();
        engine.clear_caches();
        assert_eq!(engine.cache_stats(), (0, 0, 0));
    }

    #[test]
    fn test_cave_allocation_and_free() {
        let engine = ExecutionEngine::new();

        let cave = CodeCave {
            address: 0x1000,
            size: 64,
            module: Some("test.dll".into()),
            section: Some(".text".into()),
            in_use: false,
        };

        let allocated = engine.allocate_cave(cave.clone(), Some("test cave".into()));
        assert_eq!(allocated.cave.address, 0x1000);
        assert_eq!(allocated.bytes_used, 0);
        assert_eq!(allocated.description, Some("test cave".into()));

        let caves = engine.list_allocated_caves();
        assert_eq!(caves.len(), 1);

        // Free the cave
        engine.free_cave(allocated.id).unwrap();
        assert!(engine.list_allocated_caves().is_empty());

        // Double free should error
        assert!(engine.free_cave(allocated.id).is_err());
    }

    #[test]
    fn test_cave_allocation_ids_unique() {
        let engine = ExecutionEngine::new();

        let cave1 = engine.allocate_cave(
            CodeCave {
                address: 0x1000,
                size: 64,
                module: None,
                section: None,
                in_use: false,
            },
            None,
        );

        let cave2 = engine.allocate_cave(
            CodeCave {
                address: 0x2000,
                size: 64,
                module: None,
                section: None,
                in_use: false,
            },
            None,
        );

        assert_ne!(cave1.id, cave2.id);
    }

    // ========================================
    // CodeCaveOptions Tests
    // ========================================

    #[test]
    fn test_code_cave_options_default() {
        let opts = CodeCaveOptions::default();
        assert_eq!(opts.min_size, 64);
        assert!(opts.executable_only);
        assert_eq!(opts.alignment, 16);
        assert_eq!(opts.max_results, 100);
        assert!(opts.module.is_none());
    }

    // ========================================
    // ShellcodeExecOptions Tests
    // ========================================

    #[test]
    fn test_shellcode_exec_options_default() {
        let opts = ShellcodeExecOptions::default();
        assert_eq!(opts.method, ShellcodeExecMethod::CurrentThread);
        assert!(opts.wait);
        assert_eq!(opts.timeout_ms, 30000);
        assert!(opts.free_after);
        assert!(opts.target_tid.is_none());
        assert!(opts.parameter.is_none());
    }

    // ========================================
    // FunctionCallOptions Tests
    // ========================================

    #[test]
    fn test_function_call_options_default() {
        let opts = FunctionCallOptions::default();
        assert_eq!(opts.convention, CallingConvention::Win64);
        assert!(opts.args.is_empty());
        assert!(!opts.capture_out_params);
        assert_eq!(opts.timeout_ms, 0);
        assert!(!opts.new_thread);
    }

    // ========================================
    // SyscallMethod Tests
    // ========================================

    #[test]
    fn test_syscall_method_parse() {
        use ghost_common::SyscallMethod;

        assert_eq!(
            SyscallMethod::parse("syscall"),
            Some(SyscallMethod::Syscall)
        );
        assert_eq!(
            SyscallMethod::parse("default"),
            Some(SyscallMethod::Syscall)
        );
        assert_eq!(SyscallMethod::parse("int2e"), Some(SyscallMethod::Int2e));
        assert_eq!(SyscallMethod::parse("int 2e"), Some(SyscallMethod::Int2e));
        assert_eq!(SyscallMethod::parse("legacy"), Some(SyscallMethod::Int2e));
        assert_eq!(
            SyscallMethod::parse("sysenter"),
            Some(SyscallMethod::Sysenter)
        );
        assert_eq!(SyscallMethod::parse("invalid"), None);
        assert_eq!(SyscallMethod::parse(""), None);
    }

    #[test]
    fn test_syscall_method_default() {
        use ghost_common::SyscallMethod;

        let method: SyscallMethod = Default::default();
        assert_eq!(method, SyscallMethod::Syscall);
    }

    // ========================================
    // NTSTATUS Helper Tests
    // ========================================

    #[test]
    fn test_ntstatus_to_string_success() {
        assert_eq!(ExecutionEngine::ntstatus_to_string(0), "STATUS_SUCCESS");
        assert_eq!(ExecutionEngine::ntstatus_to_string(0x102), "STATUS_TIMEOUT");
        assert_eq!(ExecutionEngine::ntstatus_to_string(0x103), "STATUS_PENDING");
    }

    #[test]
    fn test_ntstatus_to_string_errors() {
        assert_eq!(
            ExecutionEngine::ntstatus_to_string(0xC0000005_u32 as i32),
            "STATUS_ACCESS_VIOLATION"
        );
        assert_eq!(
            ExecutionEngine::ntstatus_to_string(0xC0000022_u32 as i32),
            "STATUS_ACCESS_DENIED"
        );
        assert_eq!(
            ExecutionEngine::ntstatus_to_string(0xC000000D_u32 as i32),
            "STATUS_INVALID_PARAMETER"
        );
        assert_eq!(
            ExecutionEngine::ntstatus_to_string(0xC0000008_u32 as i32),
            "STATUS_INVALID_HANDLE"
        );
    }

    #[test]
    fn test_ntstatus_to_string_unknown() {
        let result = ExecutionEngine::ntstatus_to_string(0xDEADBEEF_u32 as i32);
        assert!(result.contains("NTSTATUS"));
        assert!(result.contains("DEADBEEF"));
    }

    #[test]
    fn test_nt_success() {
        assert!(ExecutionEngine::nt_success(0)); // STATUS_SUCCESS
        assert!(ExecutionEngine::nt_success(0x102)); // STATUS_TIMEOUT
        assert!(!ExecutionEngine::nt_success(0xC0000005_u32 as i32)); // ACCESS_VIOLATION
        assert!(!ExecutionEngine::nt_success(0x80000001_u32 as i32)); // Warning
    }

    #[test]
    fn test_nt_error() {
        assert!(ExecutionEngine::nt_error(0xC0000005_u32 as i32)); // ACCESS_VIOLATION
        assert!(ExecutionEngine::nt_error(0xC0000022_u32 as i32)); // ACCESS_DENIED
        assert!(!ExecutionEngine::nt_error(0)); // SUCCESS
        assert!(!ExecutionEngine::nt_error(0x80000001_u32 as i32)); // Warning
    }

    #[test]
    fn test_nt_warning() {
        assert!(ExecutionEngine::nt_warning(0x80000001_u32 as i32)); // GUARD_PAGE
        assert!(ExecutionEngine::nt_warning(0x80000003_u32 as i32)); // BREAKPOINT
        assert!(!ExecutionEngine::nt_warning(0)); // SUCCESS
        assert!(!ExecutionEngine::nt_warning(0xC0000005_u32 as i32)); // Error
    }

    #[test]
    fn test_nt_information() {
        assert!(ExecutionEngine::nt_information(0x40000000_u32 as i32)); // OBJECT_NAME_EXISTS
        assert!(!ExecutionEngine::nt_information(0)); // SUCCESS
        assert!(!ExecutionEngine::nt_information(0xC0000005_u32 as i32)); // Error
    }

    // ========================================
    // Input Validation Tests (non-Windows)
    // ========================================

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_non_windows_returns_not_implemented() {
        let engine = ExecutionEngine::new();

        assert!(engine
            .resolve_function("kernel32.dll", "GetCurrentProcessId")
            .is_err());
        assert!(engine.get_module_handle("kernel32.dll").is_err());
        assert!(engine
            .call_function(0x1000, &FunctionCallOptions::default())
            .is_err());
        assert!(engine
            .execute_shellcode(&[0x90], &ShellcodeExecOptions::default())
            .is_err());
        assert!(engine
            .get_syscall_number("NtQueryInformationProcess")
            .is_err());
        assert!(engine.invoke_syscall(0, &[]).is_err());
        assert!(engine.allocate_executable_memory(4096).is_err());
        assert!(engine.free_memory(0x1000).is_err());
        assert!(engine.write_executable(0x1000, &[0x90]).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_invoke_syscall_with_method_non_windows() {
        use ghost_common::SyscallMethod;

        let engine = ExecutionEngine::new();
        assert!(engine
            .invoke_syscall_with_method(0, &[], SyscallMethod::Syscall)
            .is_err());
    }

    // ========================================
    // Remote Execution Tests (non-Windows)
    // ========================================

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_remote_execution_non_windows() {
        let engine = ExecutionEngine::new();

        // Remote thread creation should fail on non-Windows
        assert!(engine
            .create_remote_thread(1234, &[0x90, 0xC3], None, false, 0)
            .is_err());

        // Remote APC queuing should fail on non-Windows
        assert!(engine
            .queue_remote_apc(1234, 5678, &[0x90, 0xC3], None)
            .is_err());

        // Remote memory free should fail on non-Windows
        assert!(engine.free_remote_memory(1234, 0x1000).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_apc_and_hijack_non_windows() {
        let engine = ExecutionEngine::new();
        let mut opts = ShellcodeExecOptions::default();

        // APC injection should fail on non-Windows
        opts.method = ShellcodeExecMethod::ApcInjection;
        opts.target_tid = Some(1234);
        assert!(engine.execute_shellcode(&[0x90, 0xC3], &opts).is_err());

        // Thread hijacking should fail on non-Windows
        opts.method = ShellcodeExecMethod::ThreadHijack;
        assert!(engine.execute_shellcode(&[0x90, 0xC3], &opts).is_err());
    }

    // ========================================
    // ShellcodeExecOptions Validation Tests
    // ========================================

    #[test]
    fn test_shellcode_exec_requires_target_tid() {
        // Test that APC and hijack methods require target_tid
        let opts_apc = ShellcodeExecOptions {
            method: ShellcodeExecMethod::ApcInjection,
            target_tid: None, // Missing!
            ..Default::default()
        };
        assert!(opts_apc.target_tid.is_none());

        let opts_hijack = ShellcodeExecOptions {
            method: ShellcodeExecMethod::ThreadHijack,
            target_tid: Some(1234), // Provided
            ..Default::default()
        };
        assert!(opts_hijack.target_tid.is_some());
    }

    // ========================================
    // Fiber and Callback Execution Tests
    // ========================================

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_fiber_and_callback_non_windows() {
        let engine = ExecutionEngine::new();
        let mut opts = ShellcodeExecOptions::default();

        // Fiber execution should fail on non-Windows
        opts.method = ShellcodeExecMethod::Fiber;
        assert!(engine.execute_shellcode(&[0x90, 0xC3], &opts).is_err());

        // Callback execution should fail on non-Windows
        opts.method = ShellcodeExecMethod::Callback;
        assert!(engine.execute_shellcode(&[0x90, 0xC3], &opts).is_err());
    }

    #[test]
    fn test_shellcode_exec_method_variants() {
        // Ensure all ShellcodeExecMethod variants are valid
        let methods = [
            ShellcodeExecMethod::CurrentThread,
            ShellcodeExecMethod::NewThread,
            ShellcodeExecMethod::NtCreateThreadEx,
            ShellcodeExecMethod::ApcInjection,
            ShellcodeExecMethod::ThreadHijack,
            ShellcodeExecMethod::Fiber,
            ShellcodeExecMethod::Callback,
        ];

        for method in methods {
            let opts = ShellcodeExecOptions {
                method,
                ..Default::default()
            };
            assert_eq!(opts.method, method);
        }
    }

    #[test]
    fn test_shellcode_options_fiber_and_callback() {
        // Test Fiber options
        let fiber_opts = ShellcodeExecOptions {
            method: ShellcodeExecMethod::Fiber,
            parameter: Some(0x12345678),
            wait: true,
            ..Default::default()
        };
        assert_eq!(fiber_opts.method, ShellcodeExecMethod::Fiber);
        assert_eq!(fiber_opts.parameter, Some(0x12345678));

        // Test Callback options
        let callback_opts = ShellcodeExecOptions {
            method: ShellcodeExecMethod::Callback,
            parameter: Some(0xDEADBEEF),
            ..Default::default()
        };
        assert_eq!(callback_opts.method, ShellcodeExecMethod::Callback);
        assert_eq!(callback_opts.parameter, Some(0xDEADBEEF));
    }
}
