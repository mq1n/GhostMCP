//! Extended Hooking Types
//!
//! Types for comprehensive hooking support including inline hooks, IAT/EAT hooks,
//! advanced hook methods, shellcode support, and hook management.

use serde::{Deserialize, Serialize};

/// Unique identifier for a hook
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HookId(pub u32);

impl std::fmt::Display for HookId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hook_{}", self.0)
    }
}

/// Types of hooks supported (extended hooking methods)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedHookType {
    /// Trampoline-based detour (5-byte relative or 14-byte absolute jump)
    InlineTrampoline,
    /// Mid-function hook (hook at arbitrary offset within function)
    InlineMidFunction,
    /// Relative call/jmp patching
    InlineRelativePatch,
    /// Hot-patching (MOV EDI, EDI prologue style)
    InlineHotPatch,
    /// INT3 breakpoint-based hook
    InlineInt3,
    /// Import Address Table hook
    IatHook,
    /// Export Address Table hook
    EatHook,
    /// Delayed import hook
    DelayedImportHook,
    /// VEH/PAGE_GUARD based hook
    VehPageGuard,
    /// Single-step trap flag based hook
    SingleStep,
    /// Syscall stub hook (ntdll patching)
    Syscall,
    /// APC injection hook
    ApcInjection,
    /// KernelCallback table hook
    KernelCallback,
    /// WOW64 transition hook (Heaven's Gate)
    Wow64Transition,
    /// EPT hypervisor-based hook (requires driver)
    EptHook,
}

impl std::fmt::Display for ExtendedHookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendedHookType::InlineTrampoline => write!(f, "Inline Trampoline"),
            ExtendedHookType::InlineMidFunction => write!(f, "Mid-Function"),
            ExtendedHookType::InlineRelativePatch => write!(f, "Relative Patch"),
            ExtendedHookType::InlineHotPatch => write!(f, "Hot-Patch"),
            ExtendedHookType::InlineInt3 => write!(f, "INT3 Hook"),
            ExtendedHookType::IatHook => write!(f, "IAT Hook"),
            ExtendedHookType::EatHook => write!(f, "EAT Hook"),
            ExtendedHookType::DelayedImportHook => write!(f, "Delayed Import"),
            ExtendedHookType::VehPageGuard => write!(f, "VEH/PAGE_GUARD"),
            ExtendedHookType::SingleStep => write!(f, "Single-Step"),
            ExtendedHookType::Syscall => write!(f, "Syscall"),
            ExtendedHookType::ApcInjection => write!(f, "APC Injection"),
            ExtendedHookType::KernelCallback => write!(f, "KernelCallback"),
            ExtendedHookType::Wow64Transition => write!(f, "WOW64 Transition"),
            ExtendedHookType::EptHook => write!(f, "EPT Hook"),
        }
    }
}

/// Hook state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookState {
    /// Hook is active and intercepting calls
    Enabled,
    /// Hook is installed but temporarily disabled
    Disabled,
    /// Hook has been removed
    Removed,
    /// Hook failed to install
    Failed,
}

/// Information about an installed hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInfo {
    /// Unique hook identifier
    pub id: HookId,
    /// Type of hook
    pub hook_type: ExtendedHookType,
    /// Target address (function entry or IAT/EAT slot)
    pub target_address: u64,
    /// Callback/detour address
    pub callback_address: u64,
    /// Trampoline address for calling original
    pub trampoline_address: Option<u64>,
    /// Original bytes that were overwritten
    pub original_bytes: Vec<u8>,
    /// Current hook state
    pub state: HookState,
    /// Module name (if applicable)
    pub module_name: Option<String>,
    /// Function name (if applicable)
    pub function_name: Option<String>,
    /// Number of times hook was triggered
    pub hit_count: u64,
    /// Timestamp when hook was installed
    pub installed_at: u64,
    /// Chain index (for multiple hooks on same target)
    pub chain_index: u32,
}

/// Request to create an inline hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineHookRequest {
    /// Target function address
    pub target_address: u64,
    /// Detour function address
    pub callback_address: u64,
    /// Preferred hook type (auto-selected if None)
    pub hook_type: Option<ExtendedHookType>,
    /// Offset from function start for mid-function hooks
    pub offset: Option<u32>,
    /// Whether to enable the hook immediately
    pub enable: bool,
}

/// Request to create an IAT hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatHookRequest {
    /// Module containing the import
    pub module_name: String,
    /// Imported function to hook
    pub function_name: String,
    /// DLL the function is imported from
    pub import_module: String,
    /// Replacement function address
    pub callback_address: u64,
    /// Whether to enable the hook immediately
    pub enable: bool,
}

/// Request to create an EAT hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EatHookRequest {
    /// Module containing the export
    pub module_name: String,
    /// Exported function to hook
    pub function_name: String,
    /// Replacement function address
    pub callback_address: u64,
    /// Whether to enable the hook immediately
    pub enable: bool,
}

/// Request to create a VEH/PAGE_GUARD hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehHookRequest {
    /// Target address to monitor
    pub target_address: u64,
    /// Size of monitored region
    pub size: u32,
    /// Trigger on execute
    pub on_execute: bool,
    /// Trigger on read
    pub on_read: bool,
    /// Trigger on write
    pub on_write: bool,
    /// Callback address
    pub callback_address: u64,
}

/// Request to create a syscall hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallHookRequest {
    /// Syscall number to hook
    pub syscall_number: u32,
    /// Or function name (e.g., "NtCreateFile")
    pub function_name: Option<String>,
    /// Callback address
    pub callback_address: u64,
    /// Hook before syscall execution
    pub pre_hook: bool,
    /// Hook after syscall execution
    pub post_hook: bool,
}

/// Result of hook operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Hook ID if created
    pub hook_id: Option<HookId>,
    /// Hook info if available
    pub hook_info: Option<HookInfo>,
    /// Error message if failed
    pub error: Option<String>,
}

/// IAT entry information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatEntry {
    /// Module containing this import
    pub module_name: String,
    /// DLL being imported from
    pub import_dll: String,
    /// Function name (or ordinal)
    pub function_name: String,
    /// Ordinal number (if imported by ordinal)
    pub ordinal: Option<u16>,
    /// Address of the IAT slot
    pub iat_slot_address: u64,
    /// Current value in the IAT slot (function address)
    pub current_address: u64,
    /// Original address (if hooked)
    pub original_address: Option<u64>,
    /// Whether this entry is currently hooked
    pub is_hooked: bool,
}

/// EAT entry information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EatEntry {
    /// Module containing this export
    pub module_name: String,
    /// Exported function name
    pub function_name: String,
    /// Ordinal number
    pub ordinal: u16,
    /// Address of the EAT slot
    pub eat_slot_address: u64,
    /// RVA stored in EAT
    pub rva: u32,
    /// Actual function address
    pub function_address: u64,
    /// Whether this is a forwarded export
    pub is_forwarded: bool,
    /// Forwarder string if forwarded
    pub forwarder: Option<String>,
    /// Whether this entry is currently hooked
    pub is_hooked: bool,
}

// ============================================================================
// Shellcode Types
// ============================================================================

/// Types of shellcode templates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellcodeTemplate {
    /// Call a function with arguments
    CallFunction,
    /// Load a library (LoadLibraryA/W)
    LoadLibrary,
    /// Get procedure address
    GetProcAddress,
    /// Allocate memory
    AllocateMemory,
    /// Free memory
    FreeMemory,
    /// Create thread
    CreateThread,
    /// MessageBox (for testing)
    MessageBox,
    /// Exit thread
    ExitThread,
    /// NOP sled
    NopSled,
    /// Infinite loop (for debugging)
    InfiniteLoop,
    /// Custom (user-provided)
    Custom,
}

/// Request to generate shellcode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeRequest {
    /// Template type
    pub template: ShellcodeTemplate,
    /// Target architecture (x86 or x64)
    pub arch: ShellcodeArch,
    /// Template-specific parameters
    pub params: ShellcodeParams,
    /// Whether to encode the shellcode
    pub encode: bool,
    /// Encoder type if encoding
    pub encoder: Option<ShellcodeEncoder>,
    /// Bad characters to avoid
    pub bad_chars: Vec<u8>,
}

/// Shellcode architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellcodeArch {
    X86,
    X64,
}

/// Shellcode parameters for templates
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellcodeParams {
    /// Function address (for CallFunction)
    pub function_address: Option<u64>,
    /// Arguments (for CallFunction)
    pub arguments: Vec<u64>,
    /// String parameter (for LoadLibrary, MessageBox)
    pub string_param: Option<String>,
    /// Second string (for MessageBox title)
    pub string_param2: Option<String>,
    /// Size parameter (for AllocateMemory)
    pub size: Option<u64>,
    /// Address parameter (for FreeMemory)
    pub address: Option<u64>,
    /// NOP count (for NopSled)
    pub nop_count: Option<u32>,
    /// Custom bytes
    pub custom_bytes: Option<Vec<u8>>,
}

/// Shellcode encoder types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellcodeEncoder {
    /// XOR with single byte key
    XorSingle,
    /// XOR with multi-byte key
    XorMulti,
    /// Alpha-numeric encoding
    AlphaNumeric,
    /// Unicode-safe encoding
    UnicodeSafe,
    /// Custom encoder
    Custom,
}

/// Generated shellcode result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeResult {
    /// Whether generation succeeded
    pub success: bool,
    /// Generated shellcode bytes
    pub shellcode: Vec<u8>,
    /// Size of shellcode
    pub size: usize,
    /// Entry point offset (usually 0)
    pub entry_offset: u32,
    /// Whether shellcode is position-independent
    pub is_pic: bool,
    /// Encoder used (if any)
    pub encoder: Option<ShellcodeEncoder>,
    /// Decoder stub size (if encoded)
    pub decoder_size: Option<u32>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Request to inject shellcode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeInjectRequest {
    /// Shellcode bytes
    pub shellcode: Vec<u8>,
    /// Target address (None = allocate new)
    pub target_address: Option<u64>,
    /// Whether to execute immediately
    pub execute: bool,
    /// Wait for completion
    pub wait: bool,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u32>,
}

/// Shellcode injection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeInjectResult {
    /// Whether injection succeeded
    pub success: bool,
    /// Address where shellcode was written
    pub address: u64,
    /// Thread ID if executed
    pub thread_id: Option<u32>,
    /// Return value if waited
    pub return_value: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// ROP Gadget Types
// ============================================================================

/// Type of ROP gadget
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GadgetType {
    /// Ends with RET
    Ret,
    /// Ends with RET N
    RetN,
    /// Ends with JMP reg
    JmpReg,
    /// Ends with CALL reg
    CallReg,
    /// Syscall gadget
    Syscall,
    /// INT 0x2E (legacy syscall)
    Int2e,
}

/// A ROP gadget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopGadget {
    /// Gadget address
    pub address: u64,
    /// Module containing the gadget
    pub module: String,
    /// Gadget bytes
    pub bytes: Vec<u8>,
    /// Disassembly
    pub disasm: String,
    /// Gadget type
    pub gadget_type: GadgetType,
    /// Registers modified
    pub registers_modified: Vec<String>,
    /// Stack adjustment (for RET N)
    pub stack_delta: i32,
}

/// Request to find ROP gadgets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopGadgetRequest {
    /// Modules to search (empty = all)
    pub modules: Vec<String>,
    /// Maximum gadget length in instructions
    pub max_instructions: u32,
    /// Gadget types to find
    pub gadget_types: Vec<GadgetType>,
    /// Bad characters to avoid
    pub bad_chars: Vec<u8>,
    /// Maximum results
    pub max_results: u32,
    /// Filter by pattern (regex)
    pub pattern: Option<String>,
}

/// ROP gadget search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopGadgetResult {
    /// Whether search succeeded
    pub success: bool,
    /// Found gadgets
    pub gadgets: Vec<RopGadget>,
    /// Total gadgets found (before limit)
    pub total_found: u32,
    /// Modules searched
    pub modules_searched: Vec<String>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Hook Management Types
// ============================================================================

/// Hook chain information (multiple hooks on same target)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookChain {
    /// Target address
    pub target_address: u64,
    /// Hooks in chain (in execution order)
    pub hooks: Vec<HookId>,
    /// Original function address
    pub original_address: u64,
}

/// Hook transaction for atomic multi-hook operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookTransaction {
    /// Transaction ID
    pub id: u32,
    /// Hooks to install
    pub hooks_to_install: Vec<InlineHookRequest>,
    /// Hooks to remove
    pub hooks_to_remove: Vec<HookId>,
    /// Whether transaction is committed
    pub committed: bool,
    /// Rollback info if needed
    pub rollback_data: Vec<HookRollbackEntry>,
}

/// Rollback entry for a hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRollbackEntry {
    /// Hook ID
    pub hook_id: HookId,
    /// Address to restore
    pub address: u64,
    /// Original bytes to restore
    pub original_bytes: Vec<u8>,
}

/// Hook enumeration filter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookFilter {
    /// Filter by hook type
    pub hook_type: Option<ExtendedHookType>,
    /// Filter by module
    pub module: Option<String>,
    /// Filter by state
    pub state: Option<HookState>,
    /// Filter by address range
    pub address_range: Option<(u64, u64)>,
}

/// Summary of installed hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookSummary {
    /// Total hooks installed
    pub total_hooks: u32,
    /// Hooks by type
    pub by_type: std::collections::HashMap<String, u32>,
    /// Hooks by module
    pub by_module: std::collections::HashMap<String, u32>,
    /// Active hooks count
    pub active_count: u32,
    /// Disabled hooks count
    pub disabled_count: u32,
    /// Total hit count across all hooks
    pub total_hits: u64,
}

// ============================================================================
// VEH Hook Types
// ============================================================================

/// VEH handler registration info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehHandlerInfo {
    /// Handler address
    pub handler_address: u64,
    /// Whether it's first handler
    pub is_first: bool,
    /// Handler ID for our tracking
    pub handler_id: u32,
}

/// PAGE_GUARD hook info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageGuardHook {
    /// Hook ID
    pub hook_id: HookId,
    /// Base address of guarded page(s)
    pub base_address: u64,
    /// Size of guarded region
    pub size: u64,
    /// Original protection
    pub original_protection: u32,
    /// Trigger conditions
    pub trigger_on_execute: bool,
    pub trigger_on_read: bool,
    pub trigger_on_write: bool,
    /// Callback address
    pub callback_address: u64,
    /// Hit count
    pub hit_count: u64,
}

// ============================================================================
// Syscall Hook Types
// ============================================================================

/// Syscall hook information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallHookInfo {
    /// Syscall number
    pub number: u32,
    /// Function name
    pub name: String,
    /// Number of arguments
    pub arg_count: u32,
    /// ntdll stub address
    pub stub_address: u64,
    /// Whether currently hooked
    pub is_hooked: bool,
}

/// Syscall table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallTableEntry {
    /// Syscall number
    pub number: u32,
    /// Associated Nt function name
    pub nt_function: String,
    /// Associated Zw function name
    pub zw_function: String,
    /// Number of parameters
    pub param_count: u32,
}
