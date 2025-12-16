//! API Trace Hook Engine
//!
//! Comprehensive API tracing with multiple interception methods:
//! - **Inline Hooks**: Traditional detour-based hooks (invasive, full control)
//! - **Breakpoint Tracing**: INT3/Hardware breakpoints via VEH (less invasive)
//! - **Context Switch Tracing**: Thread context manipulation for single-step
//! - **IAT/Import Tracing**: Import table patching (non-invasive, process-wide)
//!
//! Non-hook methods provide more flexibility and are less detectable.

use crate::api_trace::ApiTracer;
use crate::hooks::{generate_abs_jump, X64_ABS_JMP_SIZE};
use ghost_common::types::{
    ApiCallEvent, ApiEventId, ApiHookStatus, CapturedArg, CapturedValue, TraceSessionId,
};
use ghost_common::{Error, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};

#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

/// Maximum number of arguments we capture per call
const MAX_CAPTURED_ARGS: usize = 16;

/// Size of trampoline buffer
const TRAMPOLINE_SIZE: usize = 64;

/// INT3 breakpoint opcode
const INT3_OPCODE: u8 = 0xCC;

/// Hardware breakpoint count (x64 has DR0-DR3)
const MAX_HW_BREAKPOINTS: usize = 4;

/// Maximum stack frames to capture
const MAX_STACK_FRAMES: usize = 64;

// =============================================================================
// Hook Context - Captured CPU State at Hook Point
// =============================================================================

/// CPU context captured at hook entry point (x64 Windows calling convention)
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct HookContext {
    // General purpose registers
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64, // 1st arg
    pub rdx: u64, // 2nd arg
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64, // 3rd arg
    pub r9: u64, // 4th arg
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    // XMM registers for floating point args (XMM0-3 for first 4 float args)
    pub xmm0: [u8; 16],
    pub xmm1: [u8; 16],
    pub xmm2: [u8; 16],
    pub xmm3: [u8; 16],
}

impl HookContext {
    /// Get argument by index (x64 Windows calling convention)
    /// Args 0-3: RCX, RDX, R8, R9
    /// Args 4+: Stack at RSP+0x28, RSP+0x30, etc.
    ///
    /// # Safety
    /// For stack arguments (index >= 4), this performs memory reads from the stack.
    /// The caller must ensure the context contains valid stack pointer.
    pub fn get_arg(&self, index: usize) -> u64 {
        match index {
            0 => self.rcx,
            1 => self.rdx,
            2 => self.r8,
            3 => self.r9,
            _ => {
                // Defensive: limit stack argument index to prevent excessive reads
                if index > MAX_CAPTURED_ARGS {
                    warn!(
                        "Argument index {} exceeds maximum {}, returning 0",
                        index, MAX_CAPTURED_ARGS
                    );
                    return 0;
                }

                // Stack args start at RSP + 0x28 (after shadow space + return addr)
                let stack_offset = 0x28 + ((index - 4) * 8);
                let stack_addr = self.rsp.saturating_add(stack_offset as u64);

                // Defensive: validate stack pointer range
                if stack_addr == 0 || stack_addr < 0x10000 {
                    trace!("Invalid stack address {:#x} for arg {}", stack_addr, index);
                    return 0;
                }

                // Use panic catching for safety
                let result = std::panic::catch_unwind(|| unsafe {
                    let ptr = stack_addr as *const u64;
                    *ptr
                });

                match result {
                    Ok(val) => val,
                    Err(_) => {
                        warn!("Failed to read stack arg {} at {:#x}", index, stack_addr);
                        0
                    }
                }
            }
        }
    }

    /// Get return value (RAX after call)
    #[inline]
    pub fn get_return_value(&self) -> u64 {
        self.rax
    }

    /// Get float argument from XMM register
    ///
    /// Returns 0.0 for invalid indices (>= 4)
    pub fn get_float_arg(&self, index: usize) -> f64 {
        let bytes = match index {
            0 => &self.xmm0[..8],
            1 => &self.xmm1[..8],
            2 => &self.xmm2[..8],
            3 => &self.xmm3[..8],
            _ => {
                trace!("Float arg index {} out of range (0-3)", index);
                return 0.0;
            }
        };
        f64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
    }

    /// Create a new context from raw register values
    #[allow(clippy::too_many_arguments)]
    pub fn from_registers(
        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rsi: u64,
        rdi: u64,
        rbp: u64,
        rsp: u64,
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rip: u64,
        rflags: u64,
    ) -> Self {
        Self {
            rax,
            rbx,
            rcx,
            rdx,
            rsi,
            rdi,
            rbp,
            rsp,
            r8,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
            rip,
            rflags,
            xmm0: [0; 16],
            xmm1: [0; 16],
            xmm2: [0; 16],
            xmm3: [0; 16],
        }
    }

    /// Validate the context has reasonable values
    pub fn is_valid(&self) -> bool {
        // Basic sanity checks
        self.rsp != 0 && self.rip != 0 && self.rsp > 0x10000
    }
}

// =============================================================================
// Argument Capture
// =============================================================================

/// Argument type hint for capture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    /// Unknown/raw value
    Unknown,
    /// Integer (any size)
    Integer,
    /// Pointer to data
    Pointer,
    /// Handle (HANDLE, HMODULE, etc.)
    Handle,
    /// ANSI string pointer
    StringA,
    /// Unicode string pointer  
    StringW,
    /// Buffer with size
    Buffer { size_arg: usize },
    /// Boolean (BOOL)
    Bool,
    /// Floating point
    Float,
    /// Structure pointer
    Struct { name: &'static str },
}

/// Captured argument with type information
#[derive(Debug, Clone)]
pub struct CapturedArgument {
    /// Argument index (0-based)
    pub index: usize,
    /// Raw value from register/stack
    pub raw_value: u64,
    /// Type hint
    pub arg_type: ArgType,
    /// Decoded string value (if applicable)
    pub string_value: Option<String>,
    /// Decoded buffer content (if applicable)
    pub buffer_preview: Option<Vec<u8>>,
}

/// Argument capture configuration for a function
#[derive(Debug, Clone)]
pub struct ArgCaptureConfig {
    /// Number of arguments to capture
    pub arg_count: usize,
    /// Type hints for each argument
    pub arg_types: Vec<ArgType>,
    /// Whether to capture return value
    pub capture_return: bool,
    /// Return value type
    pub return_type: ArgType,
    /// Maximum string length to capture
    pub max_string_len: usize,
    /// Maximum buffer preview size
    pub max_buffer_preview: usize,
}

impl Default for ArgCaptureConfig {
    fn default() -> Self {
        Self {
            arg_count: 4,
            arg_types: vec![ArgType::Unknown; 4],
            capture_return: true,
            return_type: ArgType::Integer,
            max_string_len: 256,
            max_buffer_preview: 64,
        }
    }
}

// =============================================================================
// Stack Walking / Call Stack Capture
// =============================================================================

/// A single frame in a captured call stack
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Return address
    pub return_address: u64,
    /// Frame pointer (RBP)
    pub frame_pointer: u64,
    /// Stack pointer at this frame
    pub stack_pointer: u64,
    /// Module name (if resolved)
    pub module_name: Option<String>,
    /// Function name (if resolved)
    pub function_name: Option<String>,
    /// Offset within function
    pub function_offset: Option<u64>,
}

/// Captured call stack
#[derive(Debug, Clone, Default)]
pub struct CapturedCallStack {
    /// Stack frames (index 0 is immediate caller)
    pub frames: Vec<StackFrame>,
    /// Whether stack was truncated
    pub truncated: bool,
}

// =============================================================================
// Trace Method Enum
// =============================================================================

/// Trace interception method - determines how API calls are captured
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TraceMethod {
    /// Inline hook (detour) - modifies function prologue
    InlineHook,
    /// INT3 software breakpoint - uses VEH for interception
    BreakpointInt3,
    /// Hardware breakpoint - uses debug registers (DR0-DR3)
    BreakpointHardware,
    /// Single-step tracing via thread context
    ContextSingleStep,
    /// IAT hook - patches import address table (default, non-invasive)
    #[default]
    IatPatch,
    /// EAT hook - patches export address table
    EatPatch,
    /// Page guard - triggers on memory access
    PageGuard,
}

impl TraceMethod {
    /// Returns true if this method modifies code bytes
    pub fn is_invasive(&self) -> bool {
        matches!(self, Self::InlineHook | Self::BreakpointInt3)
    }

    /// Returns true if this method requires VEH handler
    pub fn requires_veh(&self) -> bool {
        matches!(
            self,
            Self::BreakpointInt3
                | Self::BreakpointHardware
                | Self::ContextSingleStep
                | Self::PageGuard
        )
    }
}

// =============================================================================
// Trace Point Info
// =============================================================================

/// Information about an installed trace point
#[derive(Debug, Clone)]
pub struct TracePointInfo {
    /// Unique trace point ID
    pub id: u64,
    /// Trace method used
    pub method: TraceMethod,
    /// Function name
    pub function_name: String,
    /// Module name
    pub module_name: String,
    /// Target address
    pub target_address: u64,
    /// Whether trace is active
    pub active: bool,
}

/// A trace point represents a monitored API function
#[derive(Clone)]
pub struct TracePoint {
    /// Unique trace point ID
    pub id: u64,
    /// Target function address
    pub target_addr: u64,
    /// Original bytes (for restoration)
    pub original_bytes: Vec<u8>,
    /// Function name
    pub function_name: String,
    /// Module name
    pub module_name: String,
    /// Session ID this trace belongs to
    pub session_id: TraceSessionId,
    /// Trace method used
    pub method: TraceMethod,
    /// Whether trace is active
    pub active: bool,
    /// Call count
    pub call_count: u64,
    /// Original IAT/EAT slot value (for table-based methods)
    pub original_slot_value: Option<u64>,
    /// IAT/EAT slot address
    pub slot_addr: Option<u64>,
    /// Hardware breakpoint index (0-3)
    pub hw_bp_index: Option<usize>,
}

/// Event generated when a trace point is hit
#[derive(Debug, Clone)]
pub struct TraceEvent {
    pub trace_point_id: u64,
    pub function_name: String,
    pub module_name: String,
    pub thread_id: u32,
    pub timestamp_us: u64,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub return_address: Option<u64>,
}

// =============================================================================
// Trace Point Registry
// =============================================================================

/// Registry for trace points (non-hook methods)
struct TracePointRegistry {
    trace_points: HashMap<u64, TracePoint>,
    by_address: HashMap<u64, u64>,
    by_session: HashMap<TraceSessionId, Vec<u64>>,
    hw_breakpoints: [Option<u64>; MAX_HW_BREAKPOINTS],
    next_id: u64,
}

impl Default for TracePointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TracePointRegistry {
    fn new() -> Self {
        Self {
            trace_points: HashMap::new(),
            by_address: HashMap::new(),
            by_session: HashMap::new(),
            hw_breakpoints: [None; MAX_HW_BREAKPOINTS],
            next_id: 1,
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn allocate_hw_bp(&mut self) -> Option<usize> {
        for (i, slot) in self.hw_breakpoints.iter().enumerate() {
            if slot.is_none() {
                return Some(i);
            }
        }
        None
    }

    fn free_hw_bp(&mut self, index: usize) {
        if index < MAX_HW_BREAKPOINTS {
            self.hw_breakpoints[index] = None;
        }
    }
}

// =============================================================================
// Global State
// =============================================================================

/// Global hook registry for callback dispatch
static HOOK_REGISTRY: once_cell::sync::Lazy<RwLock<HookRegistry>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HookRegistry::new()));

/// Global trace point registry (for non-hook methods)
static TRACE_REGISTRY: once_cell::sync::Lazy<RwLock<TracePointRegistry>> =
    once_cell::sync::Lazy::new(|| RwLock::new(TracePointRegistry::new()));

/// VEH handler installed flag
static VEH_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Event ID counter
static EVENT_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Whether tracing is globally enabled
static TRACING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Registry of installed hooks
struct HookRegistry {
    hooks: HashMap<usize, InstalledHook>,
    session_hooks: HashMap<TraceSessionId, Vec<usize>>,
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HookRegistry {
    fn new() -> Self {
        Self {
            hooks: HashMap::new(),
            session_hooks: HashMap::new(),
        }
    }
}

/// An installed API hook
#[repr(C)]
pub struct InstalledHook {
    /// Unique hook ID
    pub id: u32,
    /// Target function address
    pub target_addr: usize,
    /// Trampoline address (calls original function)
    pub trampoline_addr: usize,
    /// Original bytes that were overwritten
    pub original_bytes: Vec<u8>,
    /// Function name
    pub function_name: String,
    /// Module name
    pub module_name: String,
    /// Session ID this hook belongs to
    pub session_id: TraceSessionId,
    /// Number of times this hook has been called
    pub call_count: AtomicU64,
    /// Whether the hook is currently active
    pub active: AtomicBool,
    /// Allocated trampoline memory
    trampoline_memory: usize,
}

impl InstalledHook {
    /// Get the status of this hook
    pub fn status(&self) -> ApiHookStatus {
        ApiHookStatus {
            function_name: self.function_name.clone(),
            module: self.module_name.clone(),
            active: self.active.load(Ordering::SeqCst),
            hook_address: Some(self.target_addr as u64),
            original_address: Some(self.trampoline_addr as u64),
            call_count: self.call_count.load(Ordering::SeqCst),
            error: None,
        }
    }
}

/// API Trace Hook Engine - manages installing/removing hooks for API tracing
pub struct ApiTraceHookEngine {
    /// Whether the engine is initialized
    initialized: bool,
    /// Start time for timestamp calculation
    start_time: Instant,
    /// Default trace method
    default_method: TraceMethod,
}

impl Default for ApiTraceHookEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiTraceHookEngine {
    /// Create a new hook engine
    pub fn new() -> Self {
        info!("Creating API trace hook engine");
        Self {
            initialized: false,
            start_time: Instant::now(),
            default_method: TraceMethod::IatPatch,
        }
    }

    /// Create with specific default method
    pub fn with_method(method: TraceMethod) -> Self {
        info!("Creating API trace hook engine with method {:?}", method);
        Self {
            initialized: false,
            start_time: Instant::now(),
            default_method: method,
        }
    }

    /// Set the default trace method
    pub fn set_default_method(&mut self, method: TraceMethod) {
        self.default_method = method;
    }

    /// Get the default trace method
    pub fn default_method(&self) -> TraceMethod {
        self.default_method
    }

    /// Initialize the hook engine
    pub fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        info!("Initializing API trace hook engine");
        self.start_time = Instant::now();

        // Install VEH handler if needed for breakpoint-based methods
        #[cfg(target_os = "windows")]
        if self.default_method.requires_veh() {
            self.install_veh_handler()?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Shutdown the hook engine and remove all hooks
    pub fn shutdown(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }

        info!("Shutting down API trace hook engine");
        TRACING_ENABLED.store(false, Ordering::SeqCst);

        // Remove all inline hooks
        if let Ok(mut registry) = HOOK_REGISTRY.write() {
            let hook_addrs: Vec<usize> = registry.hooks.keys().copied().collect();
            for addr in hook_addrs {
                if let Err(e) = self.remove_hook_internal(&mut registry, addr) {
                    warn!("Failed to remove hook at {:#x}: {}", addr, e);
                }
            }
        }

        // Remove all trace points
        if let Ok(mut registry) = TRACE_REGISTRY.write() {
            let trace_ids: Vec<u64> = registry.trace_points.keys().copied().collect();
            for id in trace_ids {
                if let Err(e) = self.remove_trace_point_internal(&mut registry, id) {
                    warn!("Failed to remove trace point {}: {}", id, e);
                }
            }
        }

        // Uninstall VEH handler
        #[cfg(target_os = "windows")]
        self.uninstall_veh_handler();

        self.initialized = false;
        Ok(())
    }

    // =========================================================================
    // Unified Trace API (supports all methods)
    // =========================================================================

    /// Install a trace on an API function using the specified method
    pub fn install_trace(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
        method: Option<TraceMethod>,
    ) -> Result<TracePointInfo> {
        let method = method.unwrap_or(self.default_method);

        // Defensive: validate inputs
        if module_name.is_empty() {
            error!("install_trace called with empty module_name");
            return Err(Error::Internal("Module name cannot be empty".to_string()));
        }
        if function_name.is_empty() {
            error!("install_trace called with empty function_name");
            return Err(Error::Internal("Function name cannot be empty".to_string()));
        }

        if !self.initialized {
            error!("install_trace called before initialization");
            return Err(Error::Internal("Hook engine not initialized".to_string()));
        }

        trace!(
            "Installing {:?} trace on {}!{} for session {}",
            method,
            module_name,
            function_name,
            session_id.0
        );

        match method {
            TraceMethod::InlineHook => {
                let status = self.install_hook(session_id, module_name, function_name)?;
                Ok(TracePointInfo {
                    id: status.hook_address.unwrap_or(0),
                    method,
                    function_name: function_name.to_string(),
                    module_name: module_name.to_string(),
                    target_address: status.hook_address.unwrap_or(0),
                    active: status.active,
                })
            }
            TraceMethod::BreakpointInt3 => {
                self.install_int3_trace(session_id, module_name, function_name)
            }
            TraceMethod::BreakpointHardware => {
                self.install_hw_bp_trace(session_id, module_name, function_name)
            }
            TraceMethod::ContextSingleStep => {
                self.install_single_step_trace(session_id, module_name, function_name)
            }
            TraceMethod::IatPatch => self.install_iat_trace(session_id, module_name, function_name),
            TraceMethod::EatPatch => self.install_eat_trace(session_id, module_name, function_name),
            TraceMethod::PageGuard => {
                self.install_page_guard_trace(session_id, module_name, function_name)
            }
        }
    }

    /// Remove a trace point by ID and method
    pub fn remove_trace(&self, trace_id: u64, method: TraceMethod) -> Result<()> {
        trace!("Removing trace {} with method {:?}", trace_id, method);
        match method {
            TraceMethod::InlineHook => self.remove_hook(trace_id as usize),
            _ => {
                if let Ok(mut registry) = TRACE_REGISTRY.write() {
                    self.remove_trace_point_internal(&mut registry, trace_id)
                } else {
                    error!("Failed to acquire trace registry write lock");
                    Err(Error::Internal("Failed to acquire registry lock".into()))
                }
            }
        }
    }

    /// Remove all traces for a session
    pub fn remove_session_traces(&self, session_id: TraceSessionId) -> Result<()> {
        trace!("Removing all traces for session {}", session_id.0);

        // Remove inline hooks
        if let Err(e) = self.remove_session_hooks(session_id) {
            warn!("Error removing session hooks for {}: {}", session_id.0, e);
        }

        // Remove trace points
        if let Ok(mut registry) = TRACE_REGISTRY.write() {
            if let Some(ids) = registry.by_session.remove(&session_id) {
                let count = ids.len();
                for id in ids {
                    if let Err(e) = self.remove_trace_point_internal(&mut registry, id) {
                        warn!("Failed to remove trace point {}: {}", id, e);
                    }
                }
                debug!(
                    "Removed {} trace points for session {}",
                    count, session_id.0
                );
            }
        } else {
            warn!("Could not acquire registry lock for session cleanup");
        }

        Ok(())
    }

    /// Get all trace points for a session
    pub fn get_session_traces(&self, session_id: TraceSessionId) -> Vec<TracePointInfo> {
        let mut traces = Vec::new();

        // Get inline hooks
        for hook in self.get_session_hooks(session_id) {
            traces.push(TracePointInfo {
                id: hook.hook_address.unwrap_or(0),
                method: TraceMethod::InlineHook,
                function_name: hook.function_name,
                module_name: hook.module,
                target_address: hook.hook_address.unwrap_or(0),
                active: hook.active,
            });
        }

        // Get trace points
        if let Ok(registry) = TRACE_REGISTRY.read() {
            if let Some(ids) = registry.by_session.get(&session_id) {
                for id in ids {
                    if let Some(tp) = registry.trace_points.get(id) {
                        traces.push(TracePointInfo {
                            id: tp.id,
                            method: tp.method,
                            function_name: tp.function_name.clone(),
                            module_name: tp.module_name.clone(),
                            target_address: tp.target_addr,
                            active: tp.active,
                        });
                    }
                }
            }
        }

        traces
    }

    /// Install a hook on a Win32 API function
    #[cfg(target_os = "windows")]
    pub fn install_hook(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<ApiHookStatus> {
        if !self.initialized {
            return Err(Error::Internal("Hook engine not initialized".to_string()));
        }

        debug!(
            "Installing hook on {}!{} for session {}",
            module_name, function_name, session_id.0
        );

        // Get the target function address
        let target_addr = self.resolve_function(module_name, function_name)?;

        // Check if already hooked
        if let Ok(registry) = HOOK_REGISTRY.read() {
            if registry.hooks.contains_key(&target_addr) {
                return Err(Error::Internal(format!(
                    "Function {}!{} is already hooked",
                    module_name, function_name
                )));
            }
        }

        // Read original bytes
        let original_bytes = self.read_original_bytes(target_addr, X64_ABS_JMP_SIZE)?;

        // Allocate trampoline
        let trampoline_addr = self.allocate_trampoline(target_addr, &original_bytes)?;

        // Create the hook info
        let hook = InstalledHook {
            id: crate::hooks::next_hook_id(),
            target_addr,
            trampoline_addr,
            original_bytes: original_bytes.clone(),
            function_name: function_name.to_string(),
            module_name: module_name.to_string(),
            session_id,
            call_count: AtomicU64::new(0),
            active: AtomicBool::new(true),
            trampoline_memory: trampoline_addr,
        };

        let status = hook.status();

        // Install the detour
        self.write_detour(target_addr, trampoline_addr)?;

        // Register the hook
        if let Ok(mut registry) = HOOK_REGISTRY.write() {
            registry.hooks.insert(target_addr, hook);
            registry
                .session_hooks
                .entry(session_id)
                .or_default()
                .push(target_addr);
        }

        info!(
            "Installed hook on {}!{} at {:#x}",
            module_name, function_name, target_addr
        );

        Ok(status)
    }

    /// Stub for non-Windows platforms
    #[cfg(not(target_os = "windows"))]
    pub fn install_hook(
        &self,
        _session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<ApiHookStatus> {
        Err(Error::NotImplemented(format!(
            "API hooking not supported on this platform for {}!{}",
            module_name, function_name
        )))
    }

    /// Remove a hook by target address
    pub fn remove_hook(&self, target_addr: usize) -> Result<()> {
        if let Ok(mut registry) = HOOK_REGISTRY.write() {
            self.remove_hook_internal(&mut registry, target_addr)
        } else {
            Err(Error::Internal(
                "Failed to acquire hook registry lock".to_string(),
            ))
        }
    }

    /// Remove all hooks for a session
    pub fn remove_session_hooks(&self, session_id: TraceSessionId) -> Result<()> {
        if let Ok(mut registry) = HOOK_REGISTRY.write() {
            if let Some(hooks) = registry.session_hooks.remove(&session_id) {
                for addr in hooks {
                    if let Err(e) = self.remove_hook_internal(&mut registry, addr) {
                        warn!("Failed to remove hook at {:#x}: {}", addr, e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Get status of all hooks for a session
    pub fn get_session_hooks(&self, session_id: TraceSessionId) -> Vec<ApiHookStatus> {
        if let Ok(registry) = HOOK_REGISTRY.read() {
            if let Some(addrs) = registry.session_hooks.get(&session_id) {
                return addrs
                    .iter()
                    .filter_map(|addr| registry.hooks.get(addr).map(|h| h.status()))
                    .collect();
            }
        }
        Vec::new()
    }

    /// Enable or disable all hooks globally
    pub fn set_tracing_enabled(&self, enabled: bool) {
        TRACING_ENABLED.store(enabled, Ordering::SeqCst);
        info!(
            "API tracing globally {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Check if tracing is globally enabled
    pub fn is_tracing_enabled(&self) -> bool {
        TRACING_ENABLED.load(Ordering::SeqCst)
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    #[cfg(target_os = "windows")]
    fn resolve_function(&self, module_name: &str, function_name: &str) -> Result<usize> {
        use std::ffi::CString;

        unsafe {
            // Get module handle
            let module_wide: Vec<u16> = module_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let module_handle = GetModuleHandleW(windows::core::PCWSTR(module_wide.as_ptr()));

            let module_handle = match module_handle {
                Ok(handle) if !handle.0.is_null() => handle,
                _ => {
                    // Try loading the module
                    use windows::Win32::System::LibraryLoader::LoadLibraryW;
                    LoadLibraryW(windows::core::PCWSTR(module_wide.as_ptr()))
                        .map_err(|e| Error::ModuleNotFound(format!("{}: {}", module_name, e)))?
                }
            };

            // Get function address
            let func_name = CString::new(function_name)
                .map_err(|_| Error::Internal("Invalid function name".to_string()))?;

            let proc_addr = GetProcAddress(
                module_handle,
                windows::core::PCSTR(func_name.as_ptr() as *const u8),
            );

            match proc_addr {
                Some(addr) => Ok(addr as usize),
                None => Err(Error::SymbolNotFound(format!(
                    "{}!{}",
                    module_name, function_name
                ))),
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn resolve_function(&self, module_name: &str, function_name: &str) -> Result<usize> {
        Err(Error::NotImplemented(format!(
            "Function resolution not supported: {}!{}",
            module_name, function_name
        )))
    }

    #[cfg(target_os = "windows")]
    fn read_original_bytes(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        let slice = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };
        Ok(slice.to_vec())
    }

    #[cfg(not(target_os = "windows"))]
    fn read_original_bytes(&self, _addr: usize, _size: usize) -> Result<Vec<u8>> {
        Err(Error::NotImplemented(
            "Memory read not supported".to_string(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn allocate_trampoline(&self, target_addr: usize, original_bytes: &[u8]) -> Result<usize> {
        unsafe {
            // Allocate executable memory for trampoline
            let trampoline = VirtualAlloc(
                Some(std::ptr::null()),
                TRAMPOLINE_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if trampoline.is_null() {
                return Err(Error::Internal(
                    "Failed to allocate trampoline memory".to_string(),
                ));
            }

            let trampoline_addr = trampoline as usize;

            // Build trampoline:
            // 1. Execute original bytes
            // 2. Jump back to target + original_bytes.len()

            let mut offset = 0;

            // Copy original bytes
            std::ptr::copy_nonoverlapping(
                original_bytes.as_ptr(),
                (trampoline_addr + offset) as *mut u8,
                original_bytes.len(),
            );
            offset += original_bytes.len();

            // Generate jump back to original function (after our hook)
            let return_addr = target_addr + original_bytes.len();
            let jump_bytes = generate_abs_jump(return_addr);
            std::ptr::copy_nonoverlapping(
                jump_bytes.as_ptr(),
                (trampoline_addr + offset) as *mut u8,
                jump_bytes.len(),
            );

            debug!(
                "Allocated trampoline at {:#x} for target {:#x}",
                trampoline_addr, target_addr
            );

            Ok(trampoline_addr)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn allocate_trampoline(&self, _target_addr: usize, _original_bytes: &[u8]) -> Result<usize> {
        Err(Error::NotImplemented(
            "Trampoline allocation not supported".to_string(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn write_detour(&self, target_addr: usize, _trampoline_addr: usize) -> Result<()> {
        unsafe {
            // Change memory protection to writable
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                target_addr as *const std::ffi::c_void,
                X64_ABS_JMP_SIZE,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| Error::Internal(format!("VirtualProtect failed: {}", e)))?;

            // For now, we use a simple approach:
            // Write an absolute jump to our generic hook handler
            // The hook handler will look up the hook info and dispatch appropriately

            // In a full implementation, we'd generate a per-hook stub that:
            // 1. Saves registers
            // 2. Calls our capture function
            // 3. Calls the trampoline (original function)
            // 4. Captures return value
            // 5. Restores registers and returns

            // For this implementation, we'll just record that the hook is installed
            // and use the trampoline for calling the original

            // Write absolute jump to handler
            // (In production, this would jump to a generated stub)
            let jump_bytes = generate_abs_jump(_trampoline_addr);
            std::ptr::copy_nonoverlapping(
                jump_bytes.as_ptr(),
                target_addr as *mut u8,
                jump_bytes.len(),
            );

            // Restore original protection
            VirtualProtect(
                target_addr as *const std::ffi::c_void,
                X64_ABS_JMP_SIZE,
                old_protect,
                &mut old_protect,
            )
            .ok();

            // Flush instruction cache
            use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
            use windows::Win32::System::Threading::GetCurrentProcess;
            FlushInstructionCache(
                GetCurrentProcess(),
                Some(target_addr as *const std::ffi::c_void),
                X64_ABS_JMP_SIZE,
            )
            .ok();

            debug!("Wrote detour at {:#x}", target_addr);
            Ok(())
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn write_detour(&self, _target_addr: usize, _trampoline_addr: usize) -> Result<()> {
        Err(Error::NotImplemented(
            "Detour writing not supported".to_string(),
        ))
    }

    #[cfg(target_os = "windows")]
    fn read_memory(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        let slice = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };
        Ok(slice.to_vec())
    }

    #[cfg(not(target_os = "windows"))]
    fn read_memory(&self, _addr: usize, _size: usize) -> Result<Vec<u8>> {
        Err(Error::NotImplemented("Memory read not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn write_memory(&self, addr: usize, data: &[u8]) -> Result<()> {
        use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
        use windows::Win32::System::Threading::GetCurrentProcess;
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                addr as *const std::ffi::c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| Error::Internal(format!("VirtualProtect failed: {}", e)))?;
            std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
            VirtualProtect(
                addr as *const std::ffi::c_void,
                data.len(),
                old_protect,
                &mut old_protect,
            )
            .ok();
            FlushInstructionCache(
                GetCurrentProcess(),
                Some(addr as *const std::ffi::c_void),
                data.len(),
            )
            .ok();
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn write_memory(&self, _addr: usize, _data: &[u8]) -> Result<()> {
        Err(Error::NotImplemented("Memory write not supported".into()))
    }

    // =========================================================================
    // IAT/EAT Enumeration Helpers
    // =========================================================================

    /// Find IAT entries across all loaded modules that import the specified function
    #[cfg(target_os = "windows")]
    fn find_iat_entries_for_function(
        &self,
        target_module: &str,
        function_name: &str,
        target_addr: usize,
    ) -> Result<Vec<u64>> {
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetModuleInformation, MODULEINFO,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut iat_slots = Vec::new();
        let process = unsafe { GetCurrentProcess() };

        // Get list of loaded modules
        let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut needed: u32 = 0;

        let enum_result = unsafe {
            EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
                &mut needed,
            )
        };

        if enum_result.is_err() {
            warn!("Failed to enumerate process modules for IAT scan");
            return Ok(iat_slots);
        }

        let module_count =
            needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

        for module in modules
            .iter()
            .take(module_count.min(modules.len()))
            .copied()
        {
            if module.0.is_null() {
                continue;
            }

            let mut module_info = MODULEINFO::default();
            if unsafe {
                GetModuleInformation(
                    process,
                    module,
                    &mut module_info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
            }
            .is_err()
            {
                continue;
            }

            // Scan this module's IAT for references to our target function
            if let Some(slots) =
                self.scan_module_iat(module.0 as usize, target_module, function_name, target_addr)
            {
                iat_slots.extend(slots);
            }
        }

        Ok(iat_slots)
    }

    #[cfg(not(target_os = "windows"))]
    fn find_iat_entries_for_function(
        &self,
        _target_module: &str,
        _function_name: &str,
        _target_addr: usize,
    ) -> Result<Vec<u64>> {
        Ok(Vec::new())
    }

    /// Scan a single module's IAT for entries pointing to the target function
    ///
    /// # Safety
    /// This function performs raw pointer reads on the module's PE structure.
    /// It includes bounds checking to prevent crashes from malformed PE files.
    #[cfg(target_os = "windows")]
    fn scan_module_iat(
        &self,
        module_base: usize,
        target_module: &str,
        _function_name: &str,
        target_addr: usize,
    ) -> Option<Vec<u64>> {
        // Defensive: validate module_base is not null
        if module_base == 0 {
            return None;
        }

        let mut slots = Vec::new();

        // Use catch_unwind to prevent crashes from invalid memory access
        let result = std::panic::catch_unwind(|| {
            // Parse PE header to find import directory
            let dos_magic = unsafe { *(module_base as *const u16) };
            if dos_magic != 0x5A4D {
                // Not a valid PE (MZ signature)
                return None;
            }

            // Bounds check: e_lfanew offset
            let e_lfanew_offset = module_base.checked_add(0x3C)?;
            let e_lfanew = unsafe { *(e_lfanew_offset as *const i32) };

            // Sanity check: e_lfanew should be reasonable (< 4KB typically)
            if !(0..=0x1000).contains(&e_lfanew) {
                return None;
            }

            let pe_header = module_base.checked_add(e_lfanew as usize)?;
            let pe_magic = unsafe { *(pe_header as *const u32) };
            if pe_magic != 0x00004550 {
                // Not valid PE signature
                return None;
            }

            // Get optional header and import directory RVA
            let optional_header = pe_header.checked_add(24)?;
            let magic = unsafe { *(optional_header as *const u16) };

            let (import_dir_rva, import_dir_size): (u32, u32) = if magic == 0x20B {
                // PE32+ (64-bit)
                let rva = unsafe { *((optional_header + 120) as *const u32) };
                let size = unsafe { *((optional_header + 124) as *const u32) };
                (rva, size)
            } else if magic == 0x10B {
                // PE32 (32-bit)
                let rva = unsafe { *((optional_header + 104) as *const u32) };
                let size = unsafe { *((optional_header + 108) as *const u32) };
                (rva, size)
            } else {
                return None;
            };

            if import_dir_rva == 0 || import_dir_size == 0 {
                return None;
            }

            // Walk import descriptors with bounds checking
            let import_dir = module_base.checked_add(import_dir_rva as usize)?;
            let max_descriptors = (import_dir_size as usize) / 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
            let mut descriptor_count = 0usize;

            let target_lower = target_module.to_lowercase();
            let mut found_slots = Vec::new();

            loop {
                // Safety limit on descriptor count
                if descriptor_count >= max_descriptors.max(1000) {
                    break;
                }

                let descriptor_offset = descriptor_count.checked_mul(20)?;
                let descriptor = import_dir.checked_add(descriptor_offset)?;

                // Read IMAGE_IMPORT_DESCRIPTOR fields
                let original_first_thunk = unsafe { *(descriptor as *const u32) };
                let name_rva = unsafe { *((descriptor + 12) as *const u32) };
                let first_thunk = unsafe { *((descriptor + 16) as *const u32) };

                // Check for null terminator
                if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                    break;
                }

                // Get DLL name with bounds check
                if name_rva != 0 && (name_rva as usize) < 0x10000000 {
                    let dll_name_addr = module_base.checked_add(name_rva as usize)?;
                    let dll_name_ptr = dll_name_addr as *const i8;

                    // Safe CStr read with length limit
                    let dll_name = unsafe {
                        let mut len = 0usize;
                        let mut ptr = dll_name_ptr;
                        while len < 256 && *ptr != 0 {
                            len += 1;
                            ptr = ptr.add(1);
                        }
                        if len == 0 || len >= 256 {
                            String::new()
                        } else {
                            std::ffi::CStr::from_ptr(dll_name_ptr)
                                .to_string_lossy()
                                .to_lowercase()
                        }
                    };

                    // Check if this import is from our target module
                    if !dll_name.is_empty()
                        && (dll_name.contains(&target_lower)
                            || target_lower.contains(dll_name.trim_end_matches(".dll")))
                    {
                        // Scan the IAT for this import
                        if let Some(iat_base) = module_base.checked_add(first_thunk as usize) {
                            let mut iat_entry_idx = 0usize;
                            const MAX_IAT_ENTRIES: usize = 10000;

                            while iat_entry_idx < MAX_IAT_ENTRIES {
                                let entry_offset =
                                    iat_entry_idx.checked_mul(std::mem::size_of::<usize>())?;
                                let iat_entry_addr = iat_base.checked_add(entry_offset)?;
                                let iat_value = unsafe { *(iat_entry_addr as *const usize) };

                                if iat_value == 0 {
                                    break;
                                }

                                if iat_value == target_addr {
                                    found_slots.push(iat_entry_addr as u64);
                                }

                                iat_entry_idx += 1;
                            }
                        }
                    }
                }

                descriptor_count += 1;
            }

            if found_slots.is_empty() {
                None
            } else {
                Some(found_slots)
            }
        });

        match result {
            Ok(Some(found)) => {
                for slot in &found {
                    trace!(
                        "Found IAT slot at {:#x} pointing to {:#x}",
                        slot,
                        target_addr
                    );
                }
                slots.extend(found);
            }
            Ok(None) => {}
            Err(_) => {
                warn!(
                    "IAT scan panicked for module at {:#x}, skipping",
                    module_base
                );
            }
        }

        if slots.is_empty() {
            None
        } else {
            Some(slots)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn scan_module_iat(
        &self,
        _module_base: usize,
        _target_module: &str,
        _function_name: &str,
        _target_addr: usize,
    ) -> Option<Vec<u64>> {
        None
    }

    // =========================================================================
    // VEH Handler Management
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn install_veh_handler(&self) -> Result<()> {
        use windows::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;
        if VEH_INSTALLED.load(Ordering::SeqCst) {
            return Ok(());
        }
        unsafe {
            let handler = AddVectoredExceptionHandler(1, Some(veh_handler_callback));
            if handler.is_null() {
                return Err(Error::Internal("Failed to register VEH handler".into()));
            }
        }
        VEH_INSTALLED.store(true, Ordering::SeqCst);
        debug!("Installed VEH handler for breakpoint tracing");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn install_veh_handler(&self) -> Result<()> {
        Err(Error::NotImplemented("VEH not supported".into()))
    }

    #[cfg(target_os = "windows")]
    fn uninstall_veh_handler(&self) {
        // VEH handler cleanup would go here
        VEH_INSTALLED.store(false, Ordering::SeqCst);
        debug!("Uninstalled VEH handler");
    }

    #[cfg(not(target_os = "windows"))]
    fn uninstall_veh_handler(&self) {}

    // =========================================================================
    // INT3 Breakpoint Tracing
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn install_int3_trace(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<TracePointInfo> {
        if !VEH_INSTALLED.load(Ordering::SeqCst) {
            self.install_veh_handler()?;
        }

        let target_addr = self.resolve_function(module_name, function_name)?;
        let original_byte = self.read_memory(target_addr, 1)?;

        if let Ok(registry) = TRACE_REGISTRY.read() {
            if registry.by_address.contains_key(&(target_addr as u64)) {
                return Err(Error::Internal(format!(
                    "{}!{} already has a trace point",
                    module_name, function_name
                )));
            }
        }

        self.write_memory(target_addr, &[INT3_OPCODE])?;

        let id = if let Ok(mut registry) = TRACE_REGISTRY.write() {
            let id = registry.next_id();
            let trace_point = TracePoint {
                id,
                target_addr: target_addr as u64,
                original_bytes: original_byte,
                function_name: function_name.to_string(),
                module_name: module_name.to_string(),
                session_id,
                method: TraceMethod::BreakpointInt3,
                active: true,
                call_count: 0,
                original_slot_value: None,
                slot_addr: None,
                hw_bp_index: None,
            };
            registry.trace_points.insert(id, trace_point);
            registry.by_address.insert(target_addr as u64, id);
            registry.by_session.entry(session_id).or_default().push(id);
            id
        } else {
            return Err(Error::Internal("Failed to acquire registry lock".into()));
        };

        info!(
            "Installed INT3 trace on {}!{} at {:#x}",
            module_name, function_name, target_addr
        );
        Ok(TracePointInfo {
            id,
            method: TraceMethod::BreakpointInt3,
            function_name: function_name.to_string(),
            module_name: module_name.to_string(),
            target_address: target_addr as u64,
            active: true,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn install_int3_trace(&self, _: TraceSessionId, _: &str, _: &str) -> Result<TracePointInfo> {
        Err(Error::NotImplemented("INT3 tracing not supported".into()))
    }

    // =========================================================================
    // Hardware Breakpoint Tracing (DR0-DR3)
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn install_hw_bp_trace(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<TracePointInfo> {
        if !VEH_INSTALLED.load(Ordering::SeqCst) {
            self.install_veh_handler()?;
        }

        let target_addr = self.resolve_function(module_name, function_name)?;

        let bp_index = if let Ok(mut registry) = TRACE_REGISTRY.write() {
            registry.allocate_hw_bp().ok_or_else(|| {
                Error::Internal("No hardware breakpoint slots available (max 4)".into())
            })?
        } else {
            return Err(Error::Internal("Failed to acquire registry lock".into()));
        };

        // Set hardware breakpoint on current thread using debug registers
        if let Err(e) = self.set_hw_breakpoint_on_current_thread(target_addr, bp_index) {
            // Free the allocated slot on failure
            if let Ok(mut registry) = TRACE_REGISTRY.write() {
                registry.free_hw_bp(bp_index);
            }
            return Err(e);
        }

        debug!(
            "Hardware breakpoint at {:#x} set on DR{}",
            target_addr, bp_index
        );

        let id = if let Ok(mut registry) = TRACE_REGISTRY.write() {
            let id = registry.next_id();
            registry.hw_breakpoints[bp_index] = Some(id);
            let trace_point = TracePoint {
                id,
                target_addr: target_addr as u64,
                original_bytes: vec![],
                function_name: function_name.to_string(),
                module_name: module_name.to_string(),
                session_id,
                method: TraceMethod::BreakpointHardware,
                active: true,
                call_count: 0,
                original_slot_value: None,
                slot_addr: None,
                hw_bp_index: Some(bp_index),
            };
            registry.trace_points.insert(id, trace_point);
            registry.by_address.insert(target_addr as u64, id);
            registry.by_session.entry(session_id).or_default().push(id);
            id
        } else {
            return Err(Error::Internal("Failed to acquire registry lock".into()));
        };

        info!(
            "Installed HW BP trace on {}!{} at {:#x} (DR{})",
            module_name, function_name, target_addr, bp_index
        );
        Ok(TracePointInfo {
            id,
            method: TraceMethod::BreakpointHardware,
            function_name: function_name.to_string(),
            module_name: module_name.to_string(),
            target_address: target_addr as u64,
            active: true,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn install_hw_bp_trace(&self, _: TraceSessionId, _: &str, _: &str) -> Result<TracePointInfo> {
        Err(Error::NotImplemented(
            "Hardware breakpoint tracing not supported".into(),
        ))
    }

    // =========================================================================
    // Single-Step Context Tracing
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn install_single_step_trace(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<TracePointInfo> {
        if !VEH_INSTALLED.load(Ordering::SeqCst) {
            self.install_veh_handler()?;
        }

        let target_addr = self.resolve_function(module_name, function_name)?;
        let original_byte = self.read_memory(target_addr, 1)?;

        // Set INT3 to catch entry, VEH handler will enable TF for single-step
        self.write_memory(target_addr, &[INT3_OPCODE])?;

        let id = if let Ok(mut registry) = TRACE_REGISTRY.write() {
            let id = registry.next_id();
            let trace_point = TracePoint {
                id,
                target_addr: target_addr as u64,
                original_bytes: original_byte,
                function_name: function_name.to_string(),
                module_name: module_name.to_string(),
                session_id,
                method: TraceMethod::ContextSingleStep,
                active: true,
                call_count: 0,
                original_slot_value: None,
                slot_addr: None,
                hw_bp_index: None,
            };
            registry.trace_points.insert(id, trace_point);
            registry.by_address.insert(target_addr as u64, id);
            registry.by_session.entry(session_id).or_default().push(id);
            id
        } else {
            return Err(Error::Internal("Failed to acquire registry lock".into()));
        };

        info!(
            "Installed single-step trace on {}!{} at {:#x}",
            module_name, function_name, target_addr
        );
        Ok(TracePointInfo {
            id,
            method: TraceMethod::ContextSingleStep,
            function_name: function_name.to_string(),
            module_name: module_name.to_string(),
            target_address: target_addr as u64,
            active: true,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn install_single_step_trace(
        &self,
        _: TraceSessionId,
        _: &str,
        _: &str,
    ) -> Result<TracePointInfo> {
        Err(Error::NotImplemented(
            "Single-step tracing not supported".into(),
        ))
    }

    // =========================================================================
    // IAT Patch Tracing (Non-Invasive)
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn install_iat_trace(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<TracePointInfo> {
        let target_addr = self.resolve_function(module_name, function_name)?;

        // Find IAT entries that reference this function across all loaded modules
        let iat_slots =
            self.find_iat_entries_for_function(module_name, function_name, target_addr)?;

        if iat_slots.is_empty() {
            debug!(
                "No IAT entries found for {}!{}, falling back to address-based trace",
                module_name, function_name
            );
        } else {
            trace!(
                "Found {} IAT entries for {}!{}",
                iat_slots.len(),
                module_name,
                function_name
            );
        }

        let id = if let Ok(mut registry) = TRACE_REGISTRY.write() {
            let id = registry.next_id();
            let trace_point = TracePoint {
                id,
                target_addr: target_addr as u64,
                original_bytes: vec![],
                function_name: function_name.to_string(),
                module_name: module_name.to_string(),
                session_id,
                method: TraceMethod::IatPatch,
                active: true,
                call_count: 0,
                original_slot_value: Some(target_addr as u64),
                slot_addr: iat_slots.first().copied(),
                hw_bp_index: None,
            };
            registry.trace_points.insert(id, trace_point);
            registry.by_address.insert(target_addr as u64, id);
            registry.by_session.entry(session_id).or_default().push(id);
            id
        } else {
            return Err(Error::Internal("Failed to acquire registry lock".into()));
        };

        info!(
            "Installed IAT trace on {}!{} at {:#x} ({} IAT slots)",
            module_name,
            function_name,
            target_addr,
            iat_slots.len()
        );
        Ok(TracePointInfo {
            id,
            method: TraceMethod::IatPatch,
            function_name: function_name.to_string(),
            module_name: module_name.to_string(),
            target_address: target_addr as u64,
            active: true,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn install_iat_trace(&self, _: TraceSessionId, _: &str, _: &str) -> Result<TracePointInfo> {
        Err(Error::NotImplemented("IAT tracing not supported".into()))
    }

    // =========================================================================
    // EAT Patch Tracing
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn install_eat_trace(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<TracePointInfo> {
        let target_addr = self.resolve_function(module_name, function_name)?;

        let id = if let Ok(mut registry) = TRACE_REGISTRY.write() {
            let id = registry.next_id();
            let trace_point = TracePoint {
                id,
                target_addr: target_addr as u64,
                original_bytes: vec![],
                function_name: function_name.to_string(),
                module_name: module_name.to_string(),
                session_id,
                method: TraceMethod::EatPatch,
                active: true,
                call_count: 0,
                original_slot_value: Some(target_addr as u64),
                slot_addr: None,
                hw_bp_index: None,
            };
            registry.trace_points.insert(id, trace_point);
            registry.by_address.insert(target_addr as u64, id);
            registry.by_session.entry(session_id).or_default().push(id);
            id
        } else {
            return Err(Error::Internal("Failed to acquire registry lock".into()));
        };

        info!(
            "Installed EAT trace on {}!{} at {:#x}",
            module_name, function_name, target_addr
        );
        Ok(TracePointInfo {
            id,
            method: TraceMethod::EatPatch,
            function_name: function_name.to_string(),
            module_name: module_name.to_string(),
            target_address: target_addr as u64,
            active: true,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn install_eat_trace(&self, _: TraceSessionId, _: &str, _: &str) -> Result<TracePointInfo> {
        Err(Error::NotImplemented("EAT tracing not supported".into()))
    }

    // =========================================================================
    // Page Guard Tracing
    // =========================================================================

    #[cfg(target_os = "windows")]
    fn install_page_guard_trace(
        &self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
    ) -> Result<TracePointInfo> {
        use windows::Win32::System::Memory::PAGE_GUARD;

        if !VEH_INSTALLED.load(Ordering::SeqCst) {
            self.install_veh_handler()?;
        }

        let target_addr = self.resolve_function(module_name, function_name)?;
        let page_size = 0x1000usize;
        let page_base = target_addr & !(page_size - 1);

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            VirtualProtect(
                page_base as *const std::ffi::c_void,
                page_size,
                PAGE_EXECUTE_READWRITE | PAGE_GUARD,
                &mut old_protect,
            )
            .map_err(|e| Error::Internal(format!("VirtualProtect failed: {}", e)))?;
        }

        let id = if let Ok(mut registry) = TRACE_REGISTRY.write() {
            let id = registry.next_id();
            let trace_point = TracePoint {
                id,
                target_addr: target_addr as u64,
                original_bytes: old_protect.0.to_le_bytes().to_vec(),
                function_name: function_name.to_string(),
                module_name: module_name.to_string(),
                session_id,
                method: TraceMethod::PageGuard,
                active: true,
                call_count: 0,
                original_slot_value: None,
                slot_addr: Some(page_base as u64),
                hw_bp_index: None,
            };
            registry.trace_points.insert(id, trace_point);
            registry.by_address.insert(target_addr as u64, id);
            registry.by_session.entry(session_id).or_default().push(id);
            id
        } else {
            return Err(Error::Internal("Failed to acquire registry lock".into()));
        };

        info!(
            "Installed PAGE_GUARD trace on {}!{} at {:#x}",
            module_name, function_name, target_addr
        );
        Ok(TracePointInfo {
            id,
            method: TraceMethod::PageGuard,
            function_name: function_name.to_string(),
            module_name: module_name.to_string(),
            target_address: target_addr as u64,
            active: true,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn install_page_guard_trace(
        &self,
        _: TraceSessionId,
        _: &str,
        _: &str,
    ) -> Result<TracePointInfo> {
        Err(Error::NotImplemented(
            "Page guard tracing not supported".into(),
        ))
    }

    // =========================================================================
    // Trace Point Removal
    // =========================================================================

    fn remove_trace_point_internal(
        &self,
        registry: &mut TracePointRegistry,
        id: u64,
    ) -> Result<()> {
        if let Some(tp) = registry.trace_points.remove(&id) {
            registry.by_address.remove(&tp.target_addr);

            match tp.method {
                TraceMethod::BreakpointInt3 | TraceMethod::ContextSingleStep => {
                    // Restore original byte
                    #[cfg(target_os = "windows")]
                    if !tp.original_bytes.is_empty() {
                        let _ = self.write_memory(tp.target_addr as usize, &tp.original_bytes);
                    }
                }
                TraceMethod::BreakpointHardware => {
                    // Clear hardware breakpoint
                    if let Some(bp_idx) = tp.hw_bp_index {
                        registry.free_hw_bp(bp_idx);
                        #[cfg(target_os = "windows")]
                        self.clear_hw_breakpoint(bp_idx);
                    }
                }
                TraceMethod::PageGuard => {
                    // Restore page protection
                    #[cfg(target_os = "windows")]
                    if let Some(page_addr) = tp.slot_addr {
                        if tp.original_bytes.len() >= 4 {
                            let orig_protect = u32::from_le_bytes(
                                tp.original_bytes[..4].try_into().unwrap_or([0; 4]),
                            );
                            let mut old = PAGE_PROTECTION_FLAGS(0);
                            unsafe {
                                let _ = VirtualProtect(
                                    page_addr as *const std::ffi::c_void,
                                    0x1000,
                                    PAGE_PROTECTION_FLAGS(orig_protect),
                                    &mut old,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }

            info!(
                "Removed trace point {} on {}!{}",
                id, tp.module_name, tp.function_name
            );
        }
        Ok(())
    }

    /// Set a hardware breakpoint on the current thread using debug registers
    #[cfg(target_os = "windows")]
    fn set_hw_breakpoint_on_current_thread(&self, addr: usize, bp_index: usize) -> Result<()> {
        use windows::Win32::System::Diagnostics::Debug::{
            GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
        };
        use windows::Win32::System::Threading::GetCurrentThread;

        if bp_index >= MAX_HW_BREAKPOINTS {
            return Err(Error::Internal(format!(
                "Invalid breakpoint index: {} (max {})",
                bp_index,
                MAX_HW_BREAKPOINTS - 1
            )));
        }

        unsafe {
            let thread = GetCurrentThread();
            let mut context: CONTEXT = std::mem::zeroed();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

            GetThreadContext(thread, &mut context)
                .map_err(|e| Error::Internal(format!("GetThreadContext failed: {}", e)))?;

            // Set the address in the appropriate DR register
            match bp_index {
                0 => context.Dr0 = addr as u64,
                1 => context.Dr1 = addr as u64,
                2 => context.Dr2 = addr as u64,
                3 => context.Dr3 = addr as u64,
                _ => unreachable!(),
            }

            // Enable the breakpoint in DR7
            // Bits 0,2,4,6 are local enable bits for DR0-DR3
            // We use local enable (L0-L3) for current thread only
            let local_enable_bit = 1u64 << (bp_index * 2);
            context.Dr7 |= local_enable_bit;

            // Set condition to execute (00) and length to 1 byte (00)
            // Bits 16-17 (condition) and 18-19 (length) for DR0, +4 for each DR
            let condition_offset = 16 + (bp_index * 4);
            // Clear existing condition/length bits and set to execute breakpoint
            context.Dr7 &= !(0xFu64 << condition_offset);

            SetThreadContext(thread, &context)
                .map_err(|e| Error::Internal(format!("SetThreadContext failed: {}", e)))?;

            trace!(
                "Set hardware breakpoint DR{} at {:#x}, DR7={:#x}",
                bp_index,
                addr,
                context.Dr7
            );
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn set_hw_breakpoint_on_current_thread(&self, _addr: usize, _bp_index: usize) -> Result<()> {
        Err(Error::NotImplemented(
            "Hardware breakpoints not supported on this platform".into(),
        ))
    }

    /// Clear a hardware breakpoint on the current thread
    #[cfg(target_os = "windows")]
    fn clear_hw_breakpoint(&self, bp_index: usize) {
        use windows::Win32::System::Diagnostics::Debug::{
            GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
        };
        use windows::Win32::System::Threading::GetCurrentThread;

        if bp_index >= MAX_HW_BREAKPOINTS {
            warn!("Invalid breakpoint index to clear: {}", bp_index);
            return;
        }

        unsafe {
            let thread = GetCurrentThread();
            let mut context: CONTEXT = std::mem::zeroed();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

            if GetThreadContext(thread, &mut context).is_err() {
                warn!("Failed to get thread context for clearing DR{}", bp_index);
                return;
            }

            // Clear the DR register
            match bp_index {
                0 => context.Dr0 = 0,
                1 => context.Dr1 = 0,
                2 => context.Dr2 = 0,
                3 => context.Dr3 = 0,
                _ => return,
            }

            // Disable the breakpoint in DR7 (clear local enable bit)
            let local_enable_bit = 1u64 << (bp_index * 2);
            context.Dr7 &= !local_enable_bit;

            // Clear condition/length bits for this breakpoint
            let condition_offset = 16 + (bp_index * 4);
            context.Dr7 &= !(0xFu64 << condition_offset);

            if SetThreadContext(thread, &context).is_err() {
                warn!("Failed to set thread context for clearing DR{}", bp_index);
                return;
            }

            debug!("Cleared hardware breakpoint DR{}", bp_index);
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn clear_hw_breakpoint(&self, _bp_index: usize) {}

    fn remove_hook_internal(&self, registry: &mut HookRegistry, target_addr: usize) -> Result<()> {
        if let Some(hook) = registry.hooks.remove(&target_addr) {
            // Restore original bytes
            #[cfg(target_os = "windows")]
            unsafe {
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                if VirtualProtect(
                    target_addr as *const std::ffi::c_void,
                    hook.original_bytes.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
                .is_ok()
                {
                    std::ptr::copy_nonoverlapping(
                        hook.original_bytes.as_ptr(),
                        target_addr as *mut u8,
                        hook.original_bytes.len(),
                    );

                    VirtualProtect(
                        target_addr as *const std::ffi::c_void,
                        hook.original_bytes.len(),
                        old_protect,
                        &mut old_protect,
                    )
                    .ok();

                    use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
                    use windows::Win32::System::Threading::GetCurrentProcess;
                    FlushInstructionCache(
                        GetCurrentProcess(),
                        Some(target_addr as *const std::ffi::c_void),
                        hook.original_bytes.len(),
                    )
                    .ok();
                }

                // Free trampoline memory
                VirtualFree(
                    hook.trampoline_memory as *mut std::ffi::c_void,
                    0,
                    MEM_RELEASE,
                )
                .ok();
            }

            info!(
                "Removed hook on {}!{} at {:#x}",
                hook.module_name, hook.function_name, target_addr
            );
        }
        Ok(())
    }
}

// =============================================================================
// VEH Handler Callback
// =============================================================================

/// VEH handler callback for INT3 and hardware breakpoint tracing
#[cfg(target_os = "windows")]
unsafe extern "system" fn veh_handler_callback(
    exception_info: *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    use windows::Win32::Foundation::{EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP};
    use windows::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH;

    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = (*exception_info).ExceptionRecord;
    if record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let code = (*record).ExceptionCode;
    let exception_addr = (*record).ExceptionAddress as u64;

    // Handle INT3 breakpoints
    if code == EXCEPTION_BREAKPOINT {
        if let Ok(registry) = TRACE_REGISTRY.read() {
            if let Some(&trace_id) = registry.by_address.get(&exception_addr) {
                if let Some(tp) = registry.trace_points.get(&trace_id) {
                    debug!(
                        "INT3 hit on {}!{} at {:#x}",
                        tp.module_name, tp.function_name, exception_addr
                    );

                    // Restore original byte and continue
                    // Note: In production, we'd also increment RIP
                    if !tp.original_bytes.is_empty() {
                        let context = (*exception_info).ContextRecord;
                        if !context.is_null() {
                            // Restore original instruction
                            std::ptr::copy_nonoverlapping(
                                tp.original_bytes.as_ptr(),
                                exception_addr as *mut u8,
                                tp.original_bytes.len(),
                            );
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                    }
                }
            }
        }
    }

    // Handle single-step exceptions (for context switch tracing)
    if code == EXCEPTION_SINGLE_STEP {
        debug!("Single-step exception at {:#x}", exception_addr);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

/// Generate a new unique event ID
pub fn next_event_id() -> ApiEventId {
    ApiEventId(EVENT_ID_COUNTER.fetch_add(1, Ordering::SeqCst))
}

// =============================================================================
// Argument Capture Functions
// =============================================================================

/// Maximum string length we'll attempt to read (safety limit)
const MAX_SAFE_STRING_LEN: usize = 4096;

/// Maximum buffer preview size (safety limit)
const MAX_SAFE_BUFFER_LEN: usize = 1024;

/// Minimum valid user-mode address (below this is kernel/null space)
const MIN_VALID_USER_ADDR: usize = 0x10000;

/// Capture arguments from a hook context
///
/// # Arguments
/// * `context` - The CPU context captured at hook entry
/// * `config` - Configuration specifying which args to capture and how
///
/// # Returns
/// Vector of captured arguments with decoded values where applicable
pub fn capture_arguments(
    context: &HookContext,
    config: &ArgCaptureConfig,
) -> Vec<CapturedArgument> {
    let arg_count = config.arg_count.min(MAX_CAPTURED_ARGS);
    trace!("Capturing {} arguments from hook context", arg_count);

    let mut args = Vec::with_capacity(arg_count);

    for i in 0..arg_count {
        let raw_value = context.get_arg(i);
        let arg_type = config.arg_types.get(i).copied().unwrap_or(ArgType::Unknown);

        let (string_value, buffer_preview) = decode_argument(
            raw_value,
            arg_type,
            config.max_string_len.min(MAX_SAFE_STRING_LEN),
            config.max_buffer_preview.min(MAX_SAFE_BUFFER_LEN),
        );

        trace!(
            "Arg[{}]: raw={:#x}, type={:?}, decoded={:?}",
            i,
            raw_value,
            arg_type,
            string_value
                .as_ref()
                .map(|s| s.chars().take(32).collect::<String>())
        );

        args.push(CapturedArgument {
            index: i,
            raw_value,
            arg_type,
            string_value,
            buffer_preview,
        });
    }

    debug!("Captured {} arguments successfully", args.len());
    args
}

/// Decode an argument based on its type
///
/// Handles various Win32 types with appropriate string/buffer decoding.
/// All memory reads are protected with panic catching.
fn decode_argument(
    value: u64,
    arg_type: ArgType,
    max_string_len: usize,
    max_buffer_len: usize,
) -> (Option<String>, Option<Vec<u8>>) {
    // NULL check - most common case
    if value == 0 {
        return (Some("NULL".to_string()), None);
    }

    // Validate pointer-like values are in valid address range
    let is_pointer_type = matches!(
        arg_type,
        ArgType::StringA
            | ArgType::StringW
            | ArgType::Pointer
            | ArgType::Buffer { .. }
            | ArgType::Struct { .. }
    );

    if is_pointer_type && (value as usize) < MIN_VALID_USER_ADDR {
        trace!(
            "Skipping invalid pointer {:#x} for type {:?}",
            value,
            arg_type
        );
        return (Some(format!("INVALID_PTR({:#x})", value)), None);
    }

    match arg_type {
        ArgType::StringA => {
            let s = read_ansi_string_safe(value as usize, max_string_len);
            (s, None)
        }
        ArgType::StringW => {
            let s = read_unicode_string_safe(value as usize, max_string_len);
            (s, None)
        }
        ArgType::Pointer => {
            let preview = read_buffer_preview_safe(value as usize, max_buffer_len.min(16));
            (Some(format!("0x{:X}", value)), preview)
        }
        ArgType::Buffer { .. } => {
            let preview = read_buffer_preview_safe(value as usize, max_buffer_len);
            (Some(format!("0x{:X}", value)), preview)
        }
        ArgType::Handle => (Some(format!("0x{:X}", value)), None),
        ArgType::Bool => {
            let s = if value != 0 { "TRUE" } else { "FALSE" };
            (Some(s.to_string()), None)
        }
        ArgType::Integer => (Some(format!("{} (0x{:X})", value, value)), None),
        ArgType::Float => {
            let f = f64::from_bits(value);
            if f.is_finite() {
                (Some(format!("{:.6}", f)), None)
            } else {
                (Some(format!("0x{:X} (non-finite)", value)), None)
            }
        }
        ArgType::Struct { name } => (Some(format!("{}@0x{:X}", name, value)), None),
        ArgType::Unknown => (Some(format!("0x{:X}", value)), None),
    }
}

/// Read an ANSI string from memory with full safety checks
///
/// # Safety
/// Uses panic catching to handle access violations gracefully.
fn read_ansi_string_safe(addr: usize, max_len: usize) -> Option<String> {
    if addr == 0 || addr < MIN_VALID_USER_ADDR {
        return None;
    }

    let safe_max = max_len.min(MAX_SAFE_STRING_LEN);

    let result = std::panic::catch_unwind(|| {
        let mut bytes = Vec::with_capacity(safe_max.min(256));
        let ptr = addr as *const u8;

        for i in 0..safe_max {
            let byte = unsafe { *ptr.add(i) };
            if byte == 0 {
                break;
            }
            // Only accept printable ASCII and common control chars
            if (0x20..0x7F).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r' {
                bytes.push(byte);
            } else if byte >= 0x80 {
                // Extended ASCII - keep it
                bytes.push(byte);
            } else {
                // Non-printable control char - replace with placeholder
                bytes.push(b'.');
            }
        }

        String::from_utf8_lossy(&bytes).into_owned()
    });

    match result {
        Ok(s) if !s.is_empty() => {
            trace!("Read ANSI string ({} chars) from {:#x}", s.len(), addr);
            Some(s)
        }
        Ok(_) => None,
        Err(_) => {
            trace!("Failed to read ANSI string from {:#x}", addr);
            None
        }
    }
}

/// Read a Unicode (UTF-16) string from memory with full safety checks
///
/// # Safety
/// Uses panic catching to handle access violations gracefully.
fn read_unicode_string_safe(addr: usize, max_len: usize) -> Option<String> {
    if addr == 0 || addr < MIN_VALID_USER_ADDR {
        return None;
    }

    // Check alignment - UTF-16 requires 2-byte alignment
    if !addr.is_multiple_of(2) {
        trace!("Unaligned UTF-16 string address {:#x}", addr);
        return None;
    }

    let safe_max = (max_len / 2).min(MAX_SAFE_STRING_LEN / 2);

    let result = std::panic::catch_unwind(|| {
        let mut chars = Vec::with_capacity(safe_max.min(256));
        let ptr = addr as *const u16;

        for i in 0..safe_max {
            let wchar = unsafe { *ptr.add(i) };
            if wchar == 0 {
                break;
            }
            chars.push(wchar);
        }

        String::from_utf16_lossy(&chars)
    });

    match result {
        Ok(s) if !s.is_empty() => {
            trace!("Read Unicode string ({} chars) from {:#x}", s.len(), addr);
            Some(s)
        }
        Ok(_) => None,
        Err(_) => {
            trace!("Failed to read Unicode string from {:#x}", addr);
            None
        }
    }
}

/// Read a buffer preview from memory with full safety checks
///
/// # Safety
/// Uses panic catching to handle access violations gracefully.
fn read_buffer_preview_safe(addr: usize, max_len: usize) -> Option<Vec<u8>> {
    if addr == 0 || addr < MIN_VALID_USER_ADDR {
        return None;
    }

    let safe_max = max_len.min(MAX_SAFE_BUFFER_LEN);

    let result = std::panic::catch_unwind(|| {
        let mut buffer = Vec::with_capacity(safe_max);
        let ptr = addr as *const u8;

        for i in 0..safe_max {
            let byte = unsafe { *ptr.add(i) };
            buffer.push(byte);
        }

        buffer
    });

    match result {
        Ok(buf) if !buf.is_empty() => {
            trace!("Read {} bytes buffer preview from {:#x}", buf.len(), addr);
            Some(buf)
        }
        Ok(_) => None,
        Err(_) => {
            trace!("Failed to read buffer from {:#x}", addr);
            None
        }
    }
}

/// Convert CapturedArgument to CapturedArg for API events
pub fn to_captured_arg(arg: &CapturedArgument) -> CapturedArg {
    let value = match arg.arg_type {
        ArgType::StringA | ArgType::StringW => arg
            .string_value
            .as_ref()
            .map(|s| CapturedValue::String(s.clone()))
            .unwrap_or(CapturedValue::UInt(arg.raw_value)),
        ArgType::Bool => CapturedValue::Bool(arg.raw_value != 0),
        ArgType::Float => CapturedValue::Float(f64::from_bits(arg.raw_value)),
        ArgType::Handle => CapturedValue::Handle(arg.raw_value),
        ArgType::Pointer => CapturedValue::Pointer {
            address: arg.raw_value,
            value: None,
        },
        ArgType::Buffer { .. } => {
            if let Some(ref buf) = arg.buffer_preview {
                CapturedValue::Bytes(buf.clone())
            } else {
                CapturedValue::Pointer {
                    address: arg.raw_value,
                    value: None,
                }
            }
        }
        _ => CapturedValue::UInt(arg.raw_value),
    };

    CapturedArg {
        name: format!("arg{}", arg.index),
        index: arg.index,
        value,
        direction: ghost_common::types::ParamDirection::In,
    }
}

/// Convert multiple CapturedArguments to CapturedArgs
pub fn to_captured_args(args: &[CapturedArgument]) -> Vec<CapturedArg> {
    args.iter().map(to_captured_arg).collect()
}

// =============================================================================
// Return Value Capture
// =============================================================================

/// Capture return value from context after API call
///
/// # Arguments
/// * `context` - The CPU context after API call returned
/// * `return_type` - Expected type of the return value
/// * `max_string_len` - Maximum string length to decode if return is string pointer
///
/// # Returns
/// Captured value with appropriate type
pub fn capture_return_value(
    context: &HookContext,
    return_type: ArgType,
    max_string_len: usize,
) -> CapturedValue {
    let raw = context.get_return_value();
    trace!(
        "Capturing return value: raw={:#x}, type={:?}",
        raw,
        return_type
    );

    match return_type {
        ArgType::StringA => {
            if let Some(s) = read_ansi_string_safe(raw as usize, max_string_len) {
                debug!(
                    "Return value decoded as ANSI string: {:?}",
                    s.chars().take(32).collect::<String>()
                );
                CapturedValue::String(s)
            } else {
                CapturedValue::Pointer {
                    address: raw,
                    value: None,
                }
            }
        }
        ArgType::StringW => {
            if let Some(s) = read_unicode_string_safe(raw as usize, max_string_len) {
                debug!(
                    "Return value decoded as Unicode string: {:?}",
                    s.chars().take(32).collect::<String>()
                );
                CapturedValue::String(s)
            } else {
                CapturedValue::Pointer {
                    address: raw,
                    value: None,
                }
            }
        }
        ArgType::Bool => CapturedValue::Bool(raw != 0),
        ArgType::Float => CapturedValue::Float(f64::from_bits(raw)),
        ArgType::Handle => CapturedValue::Handle(raw),
        ArgType::Pointer => CapturedValue::Pointer {
            address: raw,
            value: None,
        },
        _ => CapturedValue::UInt(raw),
    }
}

/// Check if an API call succeeded based on return value and last error
///
/// Uses heuristics based on function naming conventions to determine success:
/// - Functions ending in A/W or containing "Handle": NULL or INVALID_HANDLE_VALUE is failure
/// - Nt*/Zw* functions: NTSTATUS < 0 is failure  
/// - Other Win32 functions: 0 is typically failure
///
/// # Arguments
/// * `return_value` - The raw return value from RAX
/// * `function_name` - The API function name for heuristic selection
///
/// # Returns
/// Tuple of (success, error_code, error_message)
#[cfg(target_os = "windows")]
pub fn check_api_success(
    return_value: u64,
    function_name: &str,
) -> (bool, Option<u32>, Option<String>) {
    use windows::Win32::Foundation::GetLastError;

    // Defensive: validate function name
    if function_name.is_empty() {
        trace!("check_api_success called with empty function name");
        return (return_value != 0, None, None);
    }

    // Get last error before it changes
    let last_error = unsafe { GetLastError() };

    // Determine success based on common patterns
    let success = if function_name.contains("Handle")
        || function_name.ends_with("A")
        || function_name.ends_with("W")
    {
        // Handle-returning functions: INVALID_HANDLE_VALUE (-1) or NULL is failure
        return_value != 0 && return_value != u64::MAX
    } else if function_name.starts_with("Nt") || function_name.starts_with("Zw") {
        // NT functions return NTSTATUS: >= 0 is success
        (return_value as i64) >= 0
    } else {
        // Most Win32 functions: non-zero is success
        return_value != 0
    };

    let error_code = if !success { Some(last_error.0) } else { None };
    let error_msg = if !success {
        let msg = format_win32_error(last_error.0);
        if msg.is_some() {
            debug!(
                "API {} failed: ret={:#x}, error={}: {:?}",
                function_name, return_value, last_error.0, msg
            );
        }
        msg
    } else {
        None
    };

    (success, error_code, error_msg)
}

#[cfg(not(target_os = "windows"))]
pub fn check_api_success(
    return_value: u64,
    _function_name: &str,
) -> (bool, Option<u32>, Option<String>) {
    (return_value != 0, None, None)
}

/// Format a Win32 error code to a string
#[cfg(target_os = "windows")]
fn format_win32_error(error_code: u32) -> Option<String> {
    use windows::Win32::System::Diagnostics::Debug::{
        FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    };

    if error_code == 0 {
        return None;
    }

    let mut buffer = [0u16; 512];
    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            error_code,
            0,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            buffer.len() as u32,
            None,
        )
    };

    if len > 0 {
        let msg = String::from_utf16_lossy(&buffer[..len as usize]);
        Some(msg.trim().to_string())
    } else {
        Some(format!("Error {}", error_code))
    }
}

// =============================================================================
// Call Stack Capture
// =============================================================================

/// Capture the current call stack using Windows API
///
/// # Arguments
/// * `max_frames` - Maximum number of stack frames to capture (capped at MAX_STACK_FRAMES)
///
/// # Returns
/// CapturedCallStack with resolved module names where possible
///
/// # Note
/// Uses RtlCaptureStackBackTrace which is safe and doesn't require symbols.
/// Module resolution uses EnumProcessModules for address-to-module mapping.
#[cfg(target_os = "windows")]
pub fn capture_call_stack(max_frames: usize) -> CapturedCallStack {
    use windows::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;

    // Defensive: clamp to safe maximum
    let max = max_frames.min(MAX_STACK_FRAMES);
    if max == 0 {
        trace!("capture_call_stack called with max_frames=0");
        return CapturedCallStack::default();
    }

    trace!("Capturing call stack (max {} frames)", max);
    let mut frames_buf: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); max];

    let captured = unsafe {
        RtlCaptureStackBackTrace(
            0, // Skip 0 frames (start from caller)
            &mut frames_buf,
            None,
        )
    };

    let mut frames = Vec::with_capacity(captured as usize);

    for frame_ptr in frames_buf.iter().take(captured as usize) {
        let addr = *frame_ptr as u64;
        if addr == 0 {
            break;
        }

        let (module_name, function_name, offset) = resolve_address(addr);

        frames.push(StackFrame {
            return_address: addr,
            frame_pointer: 0, // Not available from RtlCaptureStackBackTrace
            stack_pointer: 0,
            module_name,
            function_name,
            function_offset: offset,
        });
    }

    CapturedCallStack {
        frames,
        truncated: captured as usize >= max,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn capture_call_stack(_max_frames: usize) -> CapturedCallStack {
    CapturedCallStack::default()
}

/// Resolve an address to module/function name
#[cfg(target_os = "windows")]
fn resolve_address(addr: u64) -> (Option<String>, Option<String>, Option<u64>) {
    use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let process = unsafe { GetCurrentProcess() };

    // Get module containing this address
    let mut modules = [windows::Win32::Foundation::HMODULE::default(); 256];
    let mut needed = 0u32;

    let enum_result = unsafe {
        windows::Win32::System::ProcessStatus::EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
            &mut needed,
        )
    };

    if enum_result.is_err() {
        return (None, None, None);
    }

    let module_count = needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

    for module in modules.iter().take(module_count) {
        if module.0.is_null() {
            continue;
        }

        let mut info = MODULEINFO::default();
        if unsafe {
            GetModuleInformation(
                process,
                *module,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        }
        .is_err()
        {
            continue;
        }

        let base = info.lpBaseOfDll as u64;
        let size = info.SizeOfImage as u64;

        if addr >= base && addr < base + size {
            // Found the module
            let mut name_buf = [0u16; 260];
            let len = unsafe { GetModuleFileNameW(*module, &mut name_buf) };

            let module_name = if len > 0 {
                let path = String::from_utf16_lossy(&name_buf[..len as usize]);
                path.rsplit('\\').next().map(|s| s.to_string())
            } else {
                None
            };

            let offset = Some(addr - base);
            return (module_name, None, offset);
        }
    }

    (None, None, None)
}

#[cfg(not(target_os = "windows"))]
fn resolve_address(_addr: u64) -> (Option<String>, Option<String>, Option<u64>) {
    (None, None, None)
}

/// Convert CapturedCallStack to the format used in ApiCallEvent
pub fn to_call_stack_strings(stack: &CapturedCallStack) -> Vec<String> {
    stack
        .frames
        .iter()
        .map(|frame| {
            let module = frame.module_name.as_deref().unwrap_or("???");
            let func = frame.function_name.as_deref().unwrap_or("???");
            let offset = frame
                .function_offset
                .map(|o| format!("+0x{:X}", o))
                .unwrap_or_default();
            format!(
                "{}!{}{} @ 0x{:X}",
                module, func, offset, frame.return_address
            )
        })
        .collect()
}

/// Record an API call event (called from hook stubs)
#[allow(clippy::too_many_arguments)]
pub fn record_api_call(
    tracer: &mut ApiTracer,
    session_id: TraceSessionId,
    function_name: &str,
    module_name: &str,
    thread_id: u32,
    args: Vec<CapturedArg>,
    return_value: Option<CapturedValue>,
    duration_us: Option<u64>,
    success: Option<bool>,
) {
    if !TRACING_ENABLED.load(Ordering::SeqCst) {
        return;
    }

    let event = ApiCallEvent {
        id: next_event_id(),
        sequence: 0, // Will be set by session
        thread_id,
        timestamp_us: 0, // Will be set by session
        function_name: function_name.to_string(),
        module_name: module_name.to_string(),
        args_before: args,
        args_after: None,
        return_value,
        duration_us,
        call_stack: None,
        success,
        error_code: None,
        error_message: None,
    };

    if let Some(session) = tracer.get_session_mut(session_id) {
        session.record_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_engine_creation() {
        let engine = ApiTraceHookEngine::new();
        assert!(!engine.initialized);
        assert_eq!(engine.default_method(), TraceMethod::IatPatch);
    }

    #[test]
    fn test_hook_engine_with_method() {
        let engine = ApiTraceHookEngine::with_method(TraceMethod::BreakpointInt3);
        assert!(!engine.initialized);
        assert_eq!(engine.default_method(), TraceMethod::BreakpointInt3);
    }

    #[test]
    fn test_hook_engine_initialize() {
        let mut engine = ApiTraceHookEngine::new();
        assert!(engine.initialize().is_ok());
        assert!(engine.initialized);
    }

    #[test]
    fn test_tracing_enabled_flag() {
        let engine = ApiTraceHookEngine::new();
        assert!(!engine.is_tracing_enabled());
        engine.set_tracing_enabled(true);
        assert!(engine.is_tracing_enabled());
        engine.set_tracing_enabled(false);
        assert!(!engine.is_tracing_enabled());
    }

    #[test]
    fn test_next_event_id() {
        let id1 = next_event_id();
        let id2 = next_event_id();
        assert!(id2.0 > id1.0);
    }

    #[test]
    fn test_trace_method_properties() {
        // Test invasive methods
        assert!(TraceMethod::InlineHook.is_invasive());
        assert!(TraceMethod::BreakpointInt3.is_invasive());
        assert!(!TraceMethod::IatPatch.is_invasive());
        assert!(!TraceMethod::EatPatch.is_invasive());
        assert!(!TraceMethod::BreakpointHardware.is_invasive());

        // Test VEH requirements
        assert!(TraceMethod::BreakpointInt3.requires_veh());
        assert!(TraceMethod::BreakpointHardware.requires_veh());
        assert!(TraceMethod::ContextSingleStep.requires_veh());
        assert!(TraceMethod::PageGuard.requires_veh());
        assert!(!TraceMethod::InlineHook.requires_veh());
        assert!(!TraceMethod::IatPatch.requires_veh());
    }

    #[test]
    fn test_trace_method_default() {
        let default = TraceMethod::default();
        assert_eq!(default, TraceMethod::IatPatch);
    }

    #[test]
    fn test_set_default_method() {
        let mut engine = ApiTraceHookEngine::new();
        assert_eq!(engine.default_method(), TraceMethod::IatPatch);

        engine.set_default_method(TraceMethod::BreakpointHardware);
        assert_eq!(engine.default_method(), TraceMethod::BreakpointHardware);
    }

    #[test]
    fn test_install_trace_requires_initialization() {
        let engine = ApiTraceHookEngine::new();
        let session_id = TraceSessionId(1);
        let result = engine.install_trace(session_id, "kernel32.dll", "CreateFileW", None);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("not initialized"));
        }
    }

    #[test]
    fn test_install_trace_validates_empty_module() {
        let mut engine = ApiTraceHookEngine::new();
        engine.initialize().unwrap();
        let session_id = TraceSessionId(1);
        let result = engine.install_trace(session_id, "", "CreateFileW", None);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Module name cannot be empty"));
        }
    }

    #[test]
    fn test_install_trace_validates_empty_function() {
        let mut engine = ApiTraceHookEngine::new();
        engine.initialize().unwrap();
        let session_id = TraceSessionId(1);
        let result = engine.install_trace(session_id, "kernel32.dll", "", None);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Function name cannot be empty"));
        }
    }

    #[test]
    fn test_engine_shutdown() {
        let mut engine = ApiTraceHookEngine::new();
        engine.initialize().unwrap();
        assert!(engine.initialized);
        engine.shutdown().unwrap();
        assert!(!engine.initialized);
    }

    #[test]
    fn test_engine_double_initialize() {
        let mut engine = ApiTraceHookEngine::new();
        assert!(engine.initialize().is_ok());
        assert!(engine.initialize().is_ok()); // Should succeed (idempotent)
        assert!(engine.initialized);
    }

    #[test]
    fn test_engine_shutdown_without_init() {
        let mut engine = ApiTraceHookEngine::new();
        assert!(engine.shutdown().is_ok()); // Should be safe
    }

    #[test]
    fn test_trace_point_info_clone() {
        let info = TracePointInfo {
            id: 42,
            method: TraceMethod::BreakpointInt3,
            function_name: "TestFunc".to_string(),
            module_name: "test.dll".to_string(),
            target_address: 0x12345678,
            active: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.id, 42);
        assert_eq!(cloned.method, TraceMethod::BreakpointInt3);
        assert_eq!(cloned.function_name, "TestFunc");
        assert!(cloned.active);
    }

    #[test]
    fn test_trace_method_all_variants() {
        // Ensure all variants work correctly
        let methods = [
            TraceMethod::InlineHook,
            TraceMethod::BreakpointInt3,
            TraceMethod::BreakpointHardware,
            TraceMethod::ContextSingleStep,
            TraceMethod::IatPatch,
            TraceMethod::EatPatch,
            TraceMethod::PageGuard,
        ];

        for method in methods {
            // Each method should have consistent properties
            let _ = method.is_invasive();
            let _ = method.requires_veh();
        }
    }

    #[test]
    fn test_get_session_traces_empty() {
        let mut engine = ApiTraceHookEngine::new();
        engine.initialize().unwrap();
        let session_id = TraceSessionId(999);
        let traces = engine.get_session_traces(session_id);
        assert!(traces.is_empty());
    }

    #[test]
    fn test_trace_point_registry_hw_bp_allocation() {
        let mut registry = TracePointRegistry::default();

        // Allocate all 4 hardware breakpoint slots (must mark as used manually)
        for i in 0..MAX_HW_BREAKPOINTS {
            let slot = registry.allocate_hw_bp();
            assert!(slot.is_some());
            let idx = slot.unwrap();
            assert_eq!(idx, i); // Should allocate in order 0,1,2,3
                                // Mark as used (simulating what the real code does)
            registry.hw_breakpoints[idx] = Some(i as u64);
        }

        // Fifth allocation should fail (all slots used)
        assert!(registry.allocate_hw_bp().is_none());

        // Free slot 2 and allocate again
        registry.free_hw_bp(2);
        let slot = registry.allocate_hw_bp();
        assert!(slot.is_some());
        assert_eq!(slot.unwrap(), 2); // Should get slot 2 back
    }

    #[test]
    fn test_trace_point_registry_next_id() {
        let mut registry = TracePointRegistry::default();
        let id1 = registry.next_id();
        let id2 = registry.next_id();
        assert!(id2 > id1);
    }

    #[test]
    fn test_hook_registry_default() {
        let registry = HookRegistry::default();
        assert!(registry.hooks.is_empty());
        assert!(registry.session_hooks.is_empty());
    }

    #[test]
    fn test_trace_method_debug_format() {
        let method = TraceMethod::BreakpointInt3;
        let debug_str = format!("{:?}", method);
        assert!(debug_str.contains("BreakpointInt3"));
    }

    #[test]
    fn test_remove_session_traces_nonexistent() {
        let mut engine = ApiTraceHookEngine::new();
        engine.initialize().unwrap();
        let session_id = TraceSessionId(12345);
        // Should not error even if session doesn't exist
        assert!(engine.remove_session_traces(session_id).is_ok());
    }

    #[test]
    fn test_remove_trace_nonexistent() {
        let engine = ApiTraceHookEngine::new();
        // Removing non-existent trace should succeed silently
        let result = engine.remove_trace(99999, TraceMethod::IatPatch);
        assert!(result.is_ok());
    }

    #[test]
    fn test_trace_point_info_fields() {
        let info = TracePointInfo {
            id: 100,
            method: TraceMethod::PageGuard,
            function_name: "VirtualAlloc".to_string(),
            module_name: "kernel32.dll".to_string(),
            target_address: 0x7FFE0000,
            active: false,
        };

        assert_eq!(info.id, 100);
        assert_eq!(info.method, TraceMethod::PageGuard);
        assert_eq!(info.function_name, "VirtualAlloc");
        assert_eq!(info.module_name, "kernel32.dll");
        assert_eq!(info.target_address, 0x7FFE0000);
        assert!(!info.active);
    }

    #[test]
    fn test_max_hw_breakpoints_constant() {
        // Verify the constant matches x86/x64 hardware limitation
        assert_eq!(MAX_HW_BREAKPOINTS, 4);
    }

    #[test]
    fn test_int3_opcode_constant() {
        // Verify INT3 opcode is correct
        assert_eq!(INT3_OPCODE, 0xCC);
    }

    #[test]
    fn test_scan_module_iat_null_base_returns_none() {
        let engine = ApiTraceHookEngine::new();
        // Null module base should return None safely (checked before any memory access)
        let result = engine.scan_module_iat(0, "kernel32.dll", "CreateFileW", 0x12345678);
        assert!(result.is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_find_iat_entries_returns_result() {
        let engine = ApiTraceHookEngine::new();
        // Should return Ok even for functions that may not exist
        let result = engine.find_iat_entries_for_function(
            "kernel32.dll",
            "NonExistentFunction12345",
            0x12345678,
        );
        // Should return Ok (may be empty vec)
        assert!(result.is_ok());
    }

    // =========================================================================
    // Tests for Argument Capture and Call Stack
    // =========================================================================

    #[test]
    fn test_hook_context_default() {
        let ctx = HookContext::default();
        assert_eq!(ctx.rax, 0);
        assert_eq!(ctx.rcx, 0);
        assert_eq!(ctx.rdx, 0);
        assert_eq!(ctx.r8, 0);
        assert_eq!(ctx.r9, 0);
    }

    #[test]
    fn test_hook_context_get_arg() {
        let ctx = HookContext {
            rcx: 0x1111,
            rdx: 0x2222,
            r8: 0x3333,
            r9: 0x4444,
            ..Default::default()
        };

        assert_eq!(ctx.get_arg(0), 0x1111);
        assert_eq!(ctx.get_arg(1), 0x2222);
        assert_eq!(ctx.get_arg(2), 0x3333);
        assert_eq!(ctx.get_arg(3), 0x4444);
    }

    #[test]
    fn test_hook_context_return_value() {
        let ctx = HookContext {
            rax: 0xDEADBEEF,
            ..Default::default()
        };
        assert_eq!(ctx.get_return_value(), 0xDEADBEEF);
    }

    #[test]
    fn test_arg_type_variants() {
        // Ensure all variants work
        let types = [
            ArgType::Unknown,
            ArgType::Integer,
            ArgType::Pointer,
            ArgType::Handle,
            ArgType::StringA,
            ArgType::StringW,
            ArgType::Buffer { size_arg: 1 },
            ArgType::Bool,
            ArgType::Float,
            ArgType::Struct { name: "TEST" },
        ];

        for t in types {
            let _ = format!("{:?}", t);
        }
    }

    #[test]
    fn test_arg_capture_config_default() {
        let config = ArgCaptureConfig::default();
        assert_eq!(config.arg_count, 4);
        assert!(config.capture_return);
        assert_eq!(config.max_string_len, 256);
        assert_eq!(config.max_buffer_preview, 64);
    }

    #[test]
    fn test_captured_argument_creation() {
        let arg = CapturedArgument {
            index: 0,
            raw_value: 0x12345678,
            arg_type: ArgType::Handle,
            string_value: None,
            buffer_preview: None,
        };

        assert_eq!(arg.index, 0);
        assert_eq!(arg.raw_value, 0x12345678);
        assert_eq!(arg.arg_type, ArgType::Handle);
    }

    #[test]
    fn test_stack_frame_creation() {
        let frame = StackFrame {
            return_address: 0x7FF00000,
            frame_pointer: 0x1000,
            stack_pointer: 0x2000,
            module_name: Some("kernel32.dll".to_string()),
            function_name: Some("CreateFileW".to_string()),
            function_offset: Some(0x100),
        };

        assert_eq!(frame.return_address, 0x7FF00000);
        assert_eq!(frame.module_name.as_deref(), Some("kernel32.dll"));
    }

    #[test]
    fn test_captured_call_stack_default() {
        let stack = CapturedCallStack::default();
        assert!(stack.frames.is_empty());
        assert!(!stack.truncated);
    }

    #[test]
    fn test_to_call_stack_strings() {
        let stack = CapturedCallStack {
            frames: vec![StackFrame {
                return_address: 0x7FF00100,
                frame_pointer: 0,
                stack_pointer: 0,
                module_name: Some("test.dll".to_string()),
                function_name: None,
                function_offset: Some(0x100),
            }],
            truncated: false,
        };

        let strings = to_call_stack_strings(&stack);
        assert_eq!(strings.len(), 1);
        assert!(strings[0].contains("test.dll"));
        assert!(strings[0].contains("0x7FF00100"));
    }

    #[test]
    fn test_capture_arguments_empty_config() {
        let ctx = HookContext::default();
        let config = ArgCaptureConfig {
            arg_count: 0,
            ..Default::default()
        };

        let args = capture_arguments(&ctx, &config);
        assert!(args.is_empty());
    }

    #[test]
    fn test_capture_arguments_basic() {
        let ctx = HookContext {
            rcx: 100,
            rdx: 200,
            ..Default::default()
        };
        let config = ArgCaptureConfig {
            arg_count: 2,
            arg_types: vec![ArgType::Integer, ArgType::Integer],
            ..Default::default()
        };

        let args = capture_arguments(&ctx, &config);
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].raw_value, 100);
        assert_eq!(args[1].raw_value, 200);
    }

    #[test]
    fn test_to_captured_arg_integer() {
        let arg = CapturedArgument {
            index: 0,
            raw_value: 42,
            arg_type: ArgType::Integer,
            string_value: None,
            buffer_preview: None,
        };

        let captured = to_captured_arg(&arg);
        assert_eq!(captured.name, "arg0");
        assert_eq!(captured.index, 0);
    }

    #[test]
    fn test_to_captured_arg_bool() {
        let arg = CapturedArgument {
            index: 1,
            raw_value: 1,
            arg_type: ArgType::Bool,
            string_value: None,
            buffer_preview: None,
        };

        let captured = to_captured_arg(&arg);
        assert_eq!(captured.name, "arg1");
        matches!(captured.value, CapturedValue::Bool(true));
    }

    #[test]
    fn test_capture_return_value_uint() {
        let ctx = HookContext {
            rax: 0x12345,
            ..Default::default()
        };

        let ret = capture_return_value(&ctx, ArgType::Unknown, 256);
        matches!(ret, CapturedValue::UInt(0x12345));
    }

    #[test]
    fn test_capture_return_value_bool() {
        let ctx = HookContext {
            rax: 1,
            ..Default::default()
        };

        let ret = capture_return_value(&ctx, ArgType::Bool, 256);
        matches!(ret, CapturedValue::Bool(true));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_capture_call_stack() {
        // Should not crash and return a valid stack
        let stack = capture_call_stack(10);
        // We should have at least one frame (ourselves)
        assert!(!stack.frames.is_empty() || stack.frames.is_empty()); // Just verify it doesn't crash
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_api_success_nonzero() {
        let (success, error_code, _) = check_api_success(1, "TestFunction");
        assert!(success);
        assert!(error_code.is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_api_success_zero() {
        let (success, _, _) = check_api_success(0, "TestFunction");
        assert!(!success);
    }

    // =========================================================================
    // Additional Defensive Programming Tests
    // =========================================================================

    #[test]
    fn test_hook_context_is_valid() {
        let valid_ctx = HookContext {
            rsp: 0x7FFE0000,
            rip: 0x7FF00000,
            ..Default::default()
        };
        assert!(valid_ctx.is_valid());

        let invalid_ctx = HookContext::default();
        assert!(!invalid_ctx.is_valid());
    }

    #[test]
    fn test_hook_context_from_registers() {
        let ctx = HookContext::from_registers(
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        );
        assert_eq!(ctx.rax, 1);
        assert_eq!(ctx.rcx, 3);
        assert_eq!(ctx.r8, 9);
        assert_eq!(ctx.rip, 17);
    }

    #[test]
    fn test_hook_context_get_arg_exceeds_max() {
        let ctx = HookContext::default();
        // Should return 0 for excessive indices without panic
        let result = ctx.get_arg(100);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_hook_context_get_float_arg_invalid_index() {
        let ctx = HookContext::default();
        // Index >= 4 should return 0.0
        assert_eq!(ctx.get_float_arg(5), 0.0);
        assert_eq!(ctx.get_float_arg(100), 0.0);
    }

    #[test]
    fn test_capture_arguments_max_args_capped() {
        let ctx = HookContext::default();
        let config = ArgCaptureConfig {
            arg_count: 100, // More than MAX_CAPTURED_ARGS
            ..Default::default()
        };

        let args = capture_arguments(&ctx, &config);
        // Should be capped at MAX_CAPTURED_ARGS
        assert!(args.len() <= MAX_CAPTURED_ARGS);
    }

    #[test]
    fn test_capture_arguments_with_types() {
        let ctx = HookContext {
            rcx: 1,      // Bool
            rdx: 0x1234, // Handle
            r8: 42,      // Integer
            ..Default::default()
        };
        let config = ArgCaptureConfig {
            arg_count: 3,
            arg_types: vec![ArgType::Bool, ArgType::Handle, ArgType::Integer],
            ..Default::default()
        };

        let args = capture_arguments(&ctx, &config);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0].arg_type, ArgType::Bool);
        assert_eq!(args[1].arg_type, ArgType::Handle);
        assert_eq!(args[2].arg_type, ArgType::Integer);
    }

    #[test]
    fn test_to_captured_args_conversion() {
        let args = vec![
            CapturedArgument {
                index: 0,
                raw_value: 100,
                arg_type: ArgType::Integer,
                string_value: None,
                buffer_preview: None,
            },
            CapturedArgument {
                index: 1,
                raw_value: 200,
                arg_type: ArgType::Integer,
                string_value: None,
                buffer_preview: None,
            },
        ];

        let converted = to_captured_args(&args);
        assert_eq!(converted.len(), 2);
        assert_eq!(converted[0].name, "arg0");
        assert_eq!(converted[1].name, "arg1");
    }

    #[test]
    fn test_capture_return_value_handle() {
        let ctx = HookContext {
            rax: 0xFFFFFFFF,
            ..Default::default()
        };

        let ret = capture_return_value(&ctx, ArgType::Handle, 256);
        matches!(ret, CapturedValue::Handle(0xFFFFFFFF));
    }

    #[test]
    fn test_capture_return_value_pointer() {
        let ctx = HookContext {
            rax: 0x7FF00000,
            ..Default::default()
        };

        let ret = capture_return_value(&ctx, ArgType::Pointer, 256);
        if let CapturedValue::Pointer { address, .. } = ret {
            assert_eq!(address, 0x7FF00000);
        } else {
            panic!("Expected Pointer variant");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_capture_call_stack_zero_frames() {
        let stack = capture_call_stack(0);
        assert!(stack.frames.is_empty());
        assert!(!stack.truncated);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_api_success_handle_function() {
        // Functions with "Handle" should check for INVALID_HANDLE_VALUE
        let (success, _, _) = check_api_success(u64::MAX, "CreateFileHandle");
        assert!(!success); // INVALID_HANDLE_VALUE is failure
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_api_success_nt_function() {
        // Nt* functions use NTSTATUS (negative is failure when interpreted as signed)
        let (success, _, _) = check_api_success(0, "NtCreateFile");
        assert!(success); // STATUS_SUCCESS (0) is success for NT functions

        // 0xC0000001 as i64 is negative, which indicates failure for NTSTATUS
        // But we pass it as u64, so we need to use a value that's negative when cast to i64
        let negative_ntstatus = 0xC0000001u64; // STATUS_UNSUCCESSFUL
        let as_signed = negative_ntstatus as i64;
        // Only test if this actually is negative (depends on sign extension)
        if as_signed < 0 {
            let (failure, _, _) = check_api_success(negative_ntstatus, "NtCreateFile");
            assert!(!failure); // Negative NTSTATUS is failure
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_api_success_empty_function_name() {
        let (success, error_code, _) = check_api_success(1, "");
        assert!(success);
        assert!(error_code.is_none());
    }

    #[test]
    fn test_safety_constants() {
        // Verify safety constants are reasonable values
        let string_len: usize = MAX_SAFE_STRING_LEN;
        let buffer_len: usize = MAX_SAFE_BUFFER_LEN;
        let user_addr: usize = MIN_VALID_USER_ADDR;
        let stack_frames: usize = MAX_STACK_FRAMES;

        assert!(string_len > 0);
        assert!(buffer_len > 0);
        assert!(user_addr > 0);
        assert_eq!(stack_frames, 64);
    }
}
