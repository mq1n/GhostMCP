//! Core trait definitions for Ghost-MCP
//!
//! These traits define the abstract interface for all RE primitives.
//! Different implementations (in-process DLL vs external EXE) implement these traits.

use crate::pattern_scanner::ResolvedScanResult;
use ghost_common::{
    Breakpoint, BreakpointId, BreakpointType, Export, Import, Instruction, MemoryRegion, Module,
    Pattern, Registers, Result, ScanResult, StackFrame, Thread, ValueType,
};

/// Memory access operations (Cheat Engine-like)
pub trait MemoryAccess: Send + Sync {
    /// Read bytes from the specified address
    fn read(&self, addr: usize, size: usize) -> Result<Vec<u8>>;

    /// Write bytes to the specified address
    fn write(&self, addr: usize, data: &[u8]) -> Result<()>;

    /// Query all memory regions
    fn query_regions(&self) -> Result<Vec<MemoryRegion>>;

    /// Search for a value in memory
    fn search_value(
        &self,
        value: &[u8],
        value_type: ValueType,
        start: Option<usize>,
        end: Option<usize>,
    ) -> Result<Vec<ScanResult>>;

    /// Search for an AOB pattern (with wildcards)
    fn search_pattern(&self, pattern: &str) -> Result<Vec<ScanResult>>;

    /// Search for an AOB pattern with pointer resolution support
    ///
    /// # Arguments
    /// * `pattern` - Pattern specification including pattern string and resolution type
    /// * `start` - Optional start address for the scan
    /// * `end` - Optional end address for the scan
    ///
    /// # Returns
    /// Vector of resolved scan results containing both match address and resolved target address
    fn search_pattern_ex(
        &self,
        pattern: &Pattern,
        start: Option<usize>,
        end: Option<usize>,
    ) -> Result<Vec<ResolvedScanResult>>;
}

/// Process control operations
pub trait ProcessControl: Send + Sync {
    /// Get list of loaded modules
    fn get_modules(&self) -> Result<Vec<Module>>;

    /// Get module by name
    fn get_module(&self, name: &str) -> Result<Option<Module>>;

    /// Get list of threads
    fn get_threads(&self) -> Result<Vec<Thread>>;

    /// Suspend a thread
    fn suspend_thread(&self, tid: u32) -> Result<()>;

    /// Resume a thread
    fn resume_thread(&self, tid: u32) -> Result<()>;

    /// Get process ID
    fn get_pid(&self) -> u32;

    /// Get process name
    fn get_process_name(&self) -> Result<String>;
}

/// Debugging operations (x64dbg-like)
pub trait Debugging: Send + Sync {
    /// Set a breakpoint at the specified address
    fn set_breakpoint(&self, addr: usize, bp_type: BreakpointType) -> Result<BreakpointId>;

    /// Remove a breakpoint
    fn remove_breakpoint(&self, id: BreakpointId) -> Result<()>;

    /// List all breakpoints
    fn list_breakpoints(&self) -> Result<Vec<Breakpoint>>;

    /// Enable/disable a breakpoint
    fn set_breakpoint_enabled(&self, id: BreakpointId, enabled: bool) -> Result<()>;

    /// Get registers for a thread
    fn get_registers(&self, tid: u32) -> Result<Registers>;

    /// Set registers for a thread
    fn set_registers(&self, tid: u32, regs: &Registers) -> Result<()>;

    /// Continue execution
    fn continue_execution(&self) -> Result<()>;

    /// Step into (single instruction)
    fn step_into(&self, tid: u32) -> Result<()>;

    /// Step over (skip calls)
    fn step_over(&self, tid: u32) -> Result<()>;

    /// Walk the stack for a thread
    fn stack_walk(&self, tid: u32) -> Result<Vec<StackFrame>>;
}

/// Static analysis operations (IDA-like)
pub trait StaticAnalysis: Send + Sync {
    /// Disassemble instructions at address
    fn disassemble(&self, addr: usize, count: usize) -> Result<Vec<Instruction>>;

    /// Disassemble a function (until RET or max instructions)
    fn disassemble_function(&self, addr: usize) -> Result<Vec<Instruction>>;

    /// Get exports for a module
    fn get_exports(&self, module: &str) -> Result<Vec<Export>>;

    /// Get imports for a module
    fn get_imports(&self, module: &str) -> Result<Vec<Import>>;

    /// Resolve symbol name to address
    fn resolve_symbol(&self, name: &str) -> Result<Option<usize>>;

    /// Get symbol name for address
    fn get_symbol(&self, addr: usize) -> Result<Option<String>>;

    /// Find cross-references to address
    fn find_xrefs_to(&self, addr: usize) -> Result<Vec<usize>>;

    /// Extract strings from a module
    fn extract_strings(&self, module: &str, min_length: usize) -> Result<Vec<(usize, String)>>;
}

/// Code injection and hooking operations
pub trait CodeInjection: Send + Sync {
    /// Write bytes directly (patch)
    fn patch_bytes(&self, addr: usize, bytes: &[u8]) -> Result<Vec<u8>>;

    /// NOP out instructions
    fn nop_region(&self, addr: usize, count: usize) -> Result<Vec<u8>>;

    /// Assemble instruction(s) at address
    fn assemble(&self, code: &str, addr: usize) -> Result<Vec<u8>>;

    /// Create a hook (returns hook ID)
    fn create_hook(&self, target: usize, callback: usize) -> Result<u32>;

    /// Remove a hook
    fn remove_hook(&self, hook_id: u32) -> Result<()>;

    /// Execute a function call
    fn call_function(&self, addr: usize, args: &[u64]) -> Result<u64>;
}

/// Combined interface for all capabilities
pub trait GhostBackend:
    MemoryAccess + ProcessControl + Debugging + StaticAnalysis + CodeInjection
{
    /// Get agent status
    fn status(&self) -> Result<ghost_common::ipc::AgentStatus>;
}
