//! Direct execution & API calls types

use serde::{Deserialize, Serialize};

/// Calling convention for function calls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CallingConvention {
    /// C calling convention (caller cleans stack)
    Cdecl,
    /// Standard calling convention (callee cleans stack)
    Stdcall,
    /// Fast calling convention (first args in registers)
    Fastcall,
    /// Microsoft x64 calling convention (default for 64-bit Windows)
    #[default]
    Win64,
    /// System V AMD64 ABI (Linux/macOS x64)
    SysV64,
    /// Thiscall (ECX = this pointer, used for C++ methods)
    Thiscall,
}

impl CallingConvention {
    /// Parse calling convention from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cdecl" | "c" => Some(Self::Cdecl),
            "stdcall" | "std" | "winapi" => Some(Self::Stdcall),
            "fastcall" | "fast" => Some(Self::Fastcall),
            "win64" | "x64" | "ms64" => Some(Self::Win64),
            "sysv64" | "sysv" | "linux64" => Some(Self::SysV64),
            "thiscall" | "this" => Some(Self::Thiscall),
            _ => None,
        }
    }
}

/// Function argument for API calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FunctionArg {
    /// Integer value (u64)
    Int(u64),
    /// Floating point value
    Float(f64),
    /// Pointer to a memory address
    Pointer(usize),
    /// String (will be allocated and passed as pointer)
    String(String),
    /// Wide string (UTF-16, will be allocated and passed as pointer)
    WideString(String),
    /// Raw bytes (will be allocated and passed as pointer)
    Bytes(Vec<u8>),
    /// Null pointer
    Null,
}

impl FunctionArg {
    /// Get the u64 representation for register/stack passing
    pub fn as_u64(&self) -> u64 {
        match self {
            Self::Int(v) => *v,
            Self::Float(v) => v.to_bits(),
            Self::Pointer(v) => *v as u64,
            Self::Null => 0,
            // String/WideString/Bytes require allocation first
            Self::String(_) | Self::WideString(_) | Self::Bytes(_) => 0,
        }
    }
}

/// Result of a function call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallResult {
    /// Return value (RAX on x64)
    pub return_value: u64,
    /// Secondary return value (RDX on x64, for 128-bit returns)
    pub return_value_high: Option<u64>,
    /// Floating point return value (XMM0)
    pub float_return: Option<f64>,
    /// Out parameters that were modified (index, new value)
    pub out_params: Vec<(usize, Vec<u8>)>,
    /// Whether the call succeeded without exceptions
    pub success: bool,
    /// Error message if call failed
    pub error: Option<String>,
    /// Execution time in microseconds
    pub duration_us: u64,
}

/// Options for function calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallOptions {
    /// Calling convention to use
    pub convention: CallingConvention,
    /// Arguments to pass
    pub args: Vec<FunctionArg>,
    /// Whether to capture out-parameters
    pub capture_out_params: bool,
    /// Timeout in milliseconds (0 = no timeout)
    pub timeout_ms: u64,
    /// Whether to call in a new thread
    pub new_thread: bool,
}

impl Default for FunctionCallOptions {
    fn default() -> Self {
        Self {
            convention: CallingConvention::Win64,
            args: Vec::new(),
            capture_out_params: false,
            timeout_ms: 0,
            new_thread: false,
        }
    }
}

/// Shellcode execution method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShellcodeExecMethod {
    /// Execute in current thread context (direct call)
    #[default]
    CurrentThread,
    /// Execute via CreateThread
    NewThread,
    /// Execute via NtCreateThreadEx (stealthier)
    NtCreateThreadEx,
    /// Execute via APC injection to a thread
    ApcInjection,
    /// Execute via thread hijacking (suspend, modify RIP, resume)
    ThreadHijack,
    /// Execute via fiber
    Fiber,
    /// Execute via callback (e.g., EnumWindows callback)
    Callback,
}

impl ShellcodeExecMethod {
    /// Parse execution method from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "current" | "direct" | "call" => Some(Self::CurrentThread),
            "thread" | "newthread" | "createthread" => Some(Self::NewThread),
            "ntcreate" | "ntcreatethreadex" => Some(Self::NtCreateThreadEx),
            "apc" | "apcinjection" => Some(Self::ApcInjection),
            "hijack" | "threadhijack" => Some(Self::ThreadHijack),
            "fiber" => Some(Self::Fiber),
            "callback" | "enum" => Some(Self::Callback),
            _ => None,
        }
    }
}

/// Options for shellcode execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeExecOptions {
    /// Execution method
    pub method: ShellcodeExecMethod,
    /// Target thread ID (for APC injection or thread hijacking)
    pub target_tid: Option<u32>,
    /// Wait for completion
    pub wait: bool,
    /// Timeout in milliseconds (0 = no timeout)
    pub timeout_ms: u64,
    /// Memory protection for shellcode (default: RWX)
    pub protection: Option<u32>,
    /// Whether to free memory after execution
    pub free_after: bool,
    /// Parameter to pass to shellcode (in RCX on x64)
    pub parameter: Option<u64>,
}

impl Default for ShellcodeExecOptions {
    fn default() -> Self {
        Self {
            method: ShellcodeExecMethod::CurrentThread,
            target_tid: None,
            wait: true,
            timeout_ms: 30000,
            protection: None,
            free_after: true,
            parameter: None,
        }
    }
}

/// Result of shellcode execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeExecResult {
    /// Return value from shellcode
    pub return_value: u64,
    /// Thread ID that executed the shellcode (if new thread)
    pub thread_id: Option<u32>,
    /// Address where shellcode was written
    pub shellcode_address: usize,
    /// Whether execution succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution time in microseconds
    pub duration_us: u64,
}

/// Code cave information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeCave {
    /// Base address of the cave
    pub address: usize,
    /// Size of the cave in bytes
    pub size: usize,
    /// Module containing the cave (if any)
    pub module: Option<String>,
    /// Section name (if known)
    pub section: Option<String>,
    /// Whether the cave is currently in use
    pub in_use: bool,
}

/// Options for finding code caves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeCaveOptions {
    /// Minimum cave size in bytes
    pub min_size: usize,
    /// Only search in executable regions
    pub executable_only: bool,
    /// Specific module to search in
    pub module: Option<String>,
    /// Preferred cave alignment
    pub alignment: usize,
    /// Maximum number of caves to return
    pub max_results: usize,
}

impl Default for CodeCaveOptions {
    fn default() -> Self {
        Self {
            min_size: 64,
            executable_only: true,
            module: None,
            alignment: 16,
            max_results: 100,
        }
    }
}

/// Allocated code cave with tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatedCave {
    /// Cave ID for tracking
    pub id: u32,
    /// Cave information
    pub cave: CodeCave,
    /// Amount of cave currently used
    pub bytes_used: usize,
    /// Description/purpose
    pub description: Option<String>,
}

/// Remote execution target (for cross-process execution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteExecTarget {
    /// Target process ID
    pub pid: u32,
    /// Target thread ID (optional, for thread-specific operations)
    pub tid: Option<u32>,
}

/// Result of remote thread creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteThreadResult {
    /// Created thread ID
    pub thread_id: u32,
    /// Thread handle (as usize)
    pub handle: usize,
    /// Remote memory address where code/data was written
    pub remote_address: usize,
    /// Whether thread completed (if waited)
    pub completed: bool,
    /// Exit code (if waited and completed)
    pub exit_code: Option<u32>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Method for invoking syscalls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SyscallMethod {
    /// Use the `syscall` instruction (default for x64)
    #[default]
    Syscall,
    /// Use `int 2e` (legacy, works on older systems)
    Int2e,
    /// Use `sysenter` (x86 only)
    Sysenter,
}

impl SyscallMethod {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "syscall" | "default" => Some(Self::Syscall),
            "int2e" | "int 2e" | "legacy" => Some(Self::Int2e),
            "sysenter" => Some(Self::Sysenter),
            _ => None,
        }
    }
}

/// Syscall information for direct invocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    /// Syscall number
    pub number: u32,
    /// Syscall name
    pub name: String,
    /// Number of arguments
    pub arg_count: usize,
    /// Module where syscall stub is located
    pub module: String,
}

/// Result of a syscall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResult {
    /// NTSTATUS return value
    pub status: i32,
    /// Whether status indicates success (NT_SUCCESS)
    pub success: bool,
    /// Human-readable status description
    pub status_name: String,
    /// Output parameters (if any)
    pub out_params: Vec<u64>,
    /// Error message if syscall setup failed
    pub error: Option<String>,
}
