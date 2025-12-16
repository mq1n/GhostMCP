//! What Writes/Accesses Types
//!
//! Types for monitoring memory accesses - tracking what instructions read from
//! or write to specific addresses, and what addresses specific instructions access.

use serde::{Deserialize, Serialize};

/// Unique identifier for a watch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WatchId(pub u32);

impl std::fmt::Display for WatchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "watch_{}", self.0)
    }
}

// ============================================================================
// Address Watch Types
// ============================================================================

/// Type of memory access to watch for
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchAccessType {
    /// Watch for read accesses
    Read,
    /// Watch for write accesses
    Write,
    /// Watch for both read and write
    ReadWrite,
    /// Watch for execute (instruction fetch)
    Execute,
}

/// Request to create an address watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAddressWatchRequest {
    /// Address to watch
    pub address: u64,
    /// Size of watched region (1, 2, 4, or 8 bytes typically)
    pub size: usize,
    /// Type of access to watch for
    pub access_type: WatchAccessType,
    /// Maximum number of hits to record (0 = unlimited)
    pub max_hits: u32,
    /// Whether to capture registers on each hit
    pub capture_registers: bool,
    /// Whether to capture stack snapshot on each hit
    pub capture_stack: bool,
    /// Stack capture size in bytes
    pub stack_capture_size: usize,
    /// Whether to auto-disassemble around RIP on hit
    pub auto_disassemble: bool,
    /// Number of instructions to disassemble before hit
    pub disasm_before: u32,
    /// Number of instructions to disassemble after hit
    pub disasm_after: u32,
    /// Optional name/description for this watch
    pub name: Option<String>,
}

/// State of a watch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchState {
    /// Watch is active
    Active,
    /// Watch is paused
    Paused,
    /// Watch has been removed
    Removed,
    /// Watch failed to install
    Failed,
}

/// Information about an installed address watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressWatchInfo {
    /// Watch identifier
    pub id: WatchId,
    /// Watched address
    pub address: u64,
    /// Size of watched region
    pub size: usize,
    /// Access type being watched
    pub access_type: WatchAccessType,
    /// Current state
    pub state: WatchState,
    /// Total hit count
    pub hit_count: u64,
    /// Maximum hits to record
    pub max_hits: u32,
    /// Whether capturing registers
    pub capture_registers: bool,
    /// Whether capturing stack
    pub capture_stack: bool,
    /// Whether auto-disassembling
    pub auto_disassemble: bool,
    /// Optional name
    pub name: Option<String>,
    /// Timestamp when watch was created
    pub created_at: u64,
}

/// CPU registers captured at a hit
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapturedRegisters {
    // General purpose registers (x64)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Instruction pointer
    pub rip: u64,
    // Flags
    pub rflags: u64,
    // Segment registers
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

/// A disassembled instruction in context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledContext {
    /// Address of instruction
    pub address: u64,
    /// Raw bytes
    pub bytes: Vec<u8>,
    /// Mnemonic
    pub mnemonic: String,
    /// Operands
    pub operands: String,
    /// Whether this is the hit instruction
    pub is_hit: bool,
}

/// A single hit record for an address watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressWatchHit {
    /// Hit number (1-indexed)
    pub hit_number: u64,
    /// Timestamp of hit
    pub timestamp: u64,
    /// Thread ID that caused the hit
    pub thread_id: u32,
    /// Instruction address that accessed the watched address
    pub instruction_address: u64,
    /// Type of access that occurred
    pub access_type: WatchAccessType,
    /// Value at the watched address (before write, current for read)
    pub value_before: Vec<u8>,
    /// Value written (for write accesses)
    pub value_after: Option<Vec<u8>>,
    /// Captured registers (if enabled)
    pub registers: Option<CapturedRegisters>,
    /// Stack snapshot (if enabled)
    pub stack_snapshot: Option<Vec<u8>>,
    /// Stack base address
    pub stack_base: Option<u64>,
    /// Disassembled context (if enabled)
    pub disassembly: Option<Vec<DisassembledContext>>,
    /// Module name containing the instruction
    pub module_name: Option<String>,
    /// Function name (if symbols available)
    pub function_name: Option<String>,
    /// Offset from function start
    pub function_offset: Option<u64>,
}

/// Result of creating an address watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAddressWatchResult {
    /// Whether creation succeeded
    pub success: bool,
    /// Watch ID if created
    pub watch_id: Option<WatchId>,
    /// Watch info if created
    pub watch_info: Option<AddressWatchInfo>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Request to get hits from a watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetWatchHitsRequest {
    /// Watch ID
    pub watch_id: WatchId,
    /// Starting hit number (1-indexed)
    pub start: u64,
    /// Maximum number of hits to return
    pub count: u32,
    /// Filter by thread ID (None = all)
    pub thread_filter: Option<u32>,
    /// Filter by access type (None = all)
    pub access_type_filter: Option<WatchAccessType>,
}

/// Result of getting watch hits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetWatchHitsResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Watch ID
    pub watch_id: WatchId,
    /// Total hits recorded
    pub total_hits: u64,
    /// Hits returned
    pub hits: Vec<AddressWatchHit>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Instruction Watch Types
// ============================================================================

/// Request to create an instruction watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInstructionWatchRequest {
    /// Address of instruction to watch
    pub instruction_address: u64,
    /// Track read accesses
    pub track_reads: bool,
    /// Track write accesses
    pub track_writes: bool,
    /// Maximum number of unique addresses to track (0 = unlimited)
    pub max_addresses: u32,
    /// Optional name/description
    pub name: Option<String>,
}

/// Information about an instruction watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionWatchInfo {
    /// Watch identifier
    pub id: WatchId,
    /// Watched instruction address
    pub instruction_address: u64,
    /// Disassembly of the instruction
    pub disassembly: String,
    /// Track reads
    pub track_reads: bool,
    /// Track writes
    pub track_writes: bool,
    /// Current state
    pub state: WatchState,
    /// Total execution count
    pub execution_count: u64,
    /// Number of unique addresses accessed
    pub unique_addresses: u32,
    /// Optional name
    pub name: Option<String>,
    /// Module containing instruction
    pub module_name: Option<String>,
    /// Function containing instruction
    pub function_name: Option<String>,
    /// Timestamp when created
    pub created_at: u64,
}

/// An accessed address record from instruction watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessedAddress {
    /// Address that was accessed
    pub address: u64,
    /// Type of access
    pub access_type: WatchAccessType,
    /// Number of times this address was accessed
    pub access_count: u64,
    /// First access timestamp
    pub first_access: u64,
    /// Last access timestamp
    pub last_access: u64,
    /// Sample value (last accessed value)
    pub sample_value: Vec<u8>,
    /// Module containing this address (if applicable)
    pub module_name: Option<String>,
}

/// Result of creating an instruction watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInstructionWatchResult {
    /// Whether creation succeeded
    pub success: bool,
    /// Watch ID if created
    pub watch_id: Option<WatchId>,
    /// Watch info if created
    pub watch_info: Option<InstructionWatchInfo>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Request to get accessed addresses from instruction watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAccessedAddressesRequest {
    /// Watch ID
    pub watch_id: WatchId,
    /// Filter by access type (None = all)
    pub access_type_filter: Option<WatchAccessType>,
    /// Minimum access count filter
    pub min_count: Option<u64>,
    /// Sort by count (descending)
    pub sort_by_count: bool,
    /// Maximum results
    pub max_results: u32,
}

/// Result of getting accessed addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAccessedAddressesResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Watch ID
    pub watch_id: WatchId,
    /// Total execution count
    pub total_executions: u64,
    /// Accessed addresses
    pub addresses: Vec<AccessedAddress>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Quick Actions
// ============================================================================

/// Quick action types available after a hit
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuickActionType {
    /// Add the hit instruction address to an address list
    AddToAddressList,
    /// Create a hook at the hit instruction
    CreateHook,
    /// Copy AOB signature around the instruction
    CopyAobSignature,
    /// Set a breakpoint at the instruction
    SetBreakpoint,
    /// Disassemble the function containing the instruction
    DisassembleFunction,
    /// Find all xrefs to the instruction
    FindXrefs,
}

/// Request to perform a quick action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickActionRequest {
    /// Action type
    pub action_type: QuickActionType,
    /// Source watch ID
    pub watch_id: WatchId,
    /// Hit number (for address watches)
    pub hit_number: Option<u64>,
    /// Target address (for instruction watches)
    pub target_address: Option<u64>,
    /// Additional options
    pub options: QuickActionOptions,
}

/// Options for quick actions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuickActionOptions {
    /// Address list name (for AddToAddressList)
    pub list_name: Option<String>,
    /// Hook type (for CreateHook)
    pub hook_type: Option<String>,
    /// Signature bytes before instruction (for CopyAobSignature)
    pub sig_bytes_before: Option<usize>,
    /// Signature bytes after instruction (for CopyAobSignature)
    pub sig_bytes_after: Option<usize>,
    /// Include wildcards in signature (for CopyAobSignature)
    pub sig_wildcards: Option<bool>,
}

/// Result of quick action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickActionResult {
    /// Whether action succeeded
    pub success: bool,
    /// Action performed
    pub action_type: QuickActionType,
    /// Result data (varies by action)
    pub result_data: Option<String>,
    /// Created ID (hook ID, breakpoint ID, etc.)
    pub created_id: Option<u32>,
    /// AOB signature (for CopyAobSignature)
    pub aob_signature: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Watch Management
// ============================================================================

/// Filter for listing watches
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchFilter {
    /// Filter by state
    pub state: Option<WatchState>,
    /// Filter by access type
    pub access_type: Option<WatchAccessType>,
    /// Filter by address range
    pub address_range: Option<(u64, u64)>,
    /// Filter by name pattern
    pub name_pattern: Option<String>,
}

/// Summary of all watches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSummary {
    /// Total address watches
    pub address_watch_count: u32,
    /// Total instruction watches
    pub instruction_watch_count: u32,
    /// Active watches
    pub active_count: u32,
    /// Paused watches
    pub paused_count: u32,
    /// Total hits across all watches
    pub total_hits: u64,
}

/// Result of listing watches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListWatchesResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Address watches
    pub address_watches: Vec<AddressWatchInfo>,
    /// Instruction watches
    pub instruction_watches: Vec<InstructionWatchInfo>,
    /// Summary
    pub summary: WatchSummary,
    /// Error message if failed
    pub error: Option<String>,
}

/// Result of watch operation (pause, resume, remove)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchOperationResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Watch ID
    pub watch_id: WatchId,
    /// New state
    pub new_state: Option<WatchState>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Request to clear hits from a watch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearWatchHitsRequest {
    /// Watch ID
    pub watch_id: WatchId,
    /// Clear hits older than this timestamp (None = all)
    pub older_than: Option<u64>,
}

/// Result of clearing hits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearWatchHitsResult {
    /// Whether operation succeeded
    pub success: bool,
    /// Watch ID
    pub watch_id: WatchId,
    /// Number of hits cleared
    pub hits_cleared: u64,
    /// Error message if failed
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_id_display() {
        let id = WatchId(123);
        assert_eq!(format!("{}", id), "watch_123");
    }

    #[test]
    fn test_captured_registers_default() {
        let regs = CapturedRegisters::default();
        assert_eq!(regs.rax, 0);
        assert_eq!(regs.rip, 0);
    }

    #[test]
    fn test_watch_access_type_serialization() {
        let access = WatchAccessType::ReadWrite;
        let json = serde_json::to_string(&access).unwrap();
        assert!(json.contains("read_write"));
    }

    #[test]
    fn test_watch_state_variants() {
        assert_ne!(WatchState::Active, WatchState::Paused);
        assert_ne!(WatchState::Paused, WatchState::Removed);
    }
}
