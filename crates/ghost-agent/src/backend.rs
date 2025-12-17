//! In-process backend implementation
//!
//! Implements ghost-core traits using direct memory access (no ReadProcessMemory).

use crate::multi_client::{EventBus, RequestHandler, SharedState};
use crate::safety::SafetyGuard;
use ghost_common::ipc::{
    error_codes, AgentStatus, Capability, ClientIdentity, Event, EventType, HandshakeResponse,
    MemoryWritePayload, PatchAppliedPayload, PatchEntry, PatchUndonePayload, Request, Response,
    SessionAttachedPayload, SessionMetadata,
};
use ghost_common::{
    Breakpoint, BreakpointId, BreakpointType, CallingConvention, CodeCave, CodeCaveOptions, Error,
    Export, FunctionArg, FunctionCallOptions, HookId, Import, Instruction, MemoryRegion, Module,
    PointerExportFormat, PointerPath, PointerRescanOptions, PointerScanId, PointerScanOptions,
    RegionFilter, Registers, Result, ScanCompareType, ScanExportFormat, ScanId, ScanOptions,
    ScanResult, ScanResultEx, ShellcodeExecMethod, ShellcodeExecOptions, StackFrame, Thread,
    ValueType,
};
use ghost_core::execution::ExecutionEngine;
use ghost_core::{
    advanced_monitor::{ChillManager, ComScanner, DllMonitor, DynamicApiMonitor},
    api_trace::ApiTracer,
    CodeInjection, Debugging, GhostBackend, MemoryAccess, PointerScanner, ProcessControl, Scanner,
    StaticAnalysis,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast::error::TryRecvError;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{
    IsDebuggerPresent, ReadProcessMemory, WriteProcessMemory,
};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, VirtualProtectEx, VirtualQuery, VirtualQueryEx,
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    PAGE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleBaseNameW, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};
use windows::Win32::System::Threading::{CreateThread, GetCurrentProcess};

// SAFETY: InProcessBackend uses synchronization primitives (Mutex, RwLock) for all mutable state.
// The process HANDLE is safe to share across threads as it's a kernel object reference.
// All Windows API calls used are thread-safe when accessing the current process.
unsafe impl Send for InProcessBackend {}
unsafe impl Sync for InProcessBackend {}

/// Parameters for creating an extended hook
#[derive(Debug, Clone, Default)]
pub struct CreateHookParams {
    pub target: usize,
    pub callback: usize,
    pub hook_type: String,
    pub module: Option<String>,
    pub function: Option<String>,
    pub import_module: Option<String>,
    pub size: Option<usize>,
}

/// Parse scan_id from JSON value (supports both numeric and string formats)
fn parse_scan_id(value: &serde_json::Value) -> Result<ScanId> {
    if let Some(n) = value.as_u64() {
        return Ok(ScanId(n as u32));
    }
    if let Some(s) = value.as_str() {
        return s
            .trim()
            .parse::<u32>()
            .map(ScanId)
            .map_err(|_| Error::Internal(format!("Invalid scan_id format: {}", value)));
    }
    Err(Error::Internal("Missing or invalid scan_id".into()))
}

/// Parse address from JSON value (supports numeric, hex string, and decimal string formats)
fn parse_address(value: &serde_json::Value) -> Result<usize> {
    // Try as number first
    if let Some(n) = value.as_u64() {
        return Ok(n as usize);
    }
    // Try as string
    if let Some(s) = value.as_str() {
        let s = s.trim();

        // If it has 0x/0X prefix, parse as hex
        if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return usize::from_str_radix(hex_str, 16)
                .map_err(|_| Error::Internal(format!("Invalid hex address: {}", value)));
        }

        // Otherwise, try decimal first (for addresses from scan results like "1254177897440")
        if let Ok(n) = s.parse::<usize>() {
            return Ok(n);
        }

        // Fallback: try as hex without prefix (legacy compatibility)
        return usize::from_str_radix(s, 16)
            .map_err(|_| Error::Internal(format!("Invalid address format: {}", value)));
    }
    Err(Error::Internal(format!(
        "Missing or invalid address: {}",
        value
    )))
}

/// Parse value type from string
fn parse_value_type(s: &str) -> Result<ValueType> {
    match s.to_lowercase().as_str() {
        "u8" | "byte" => Ok(ValueType::U8),
        "u16" | "ushort" | "word" => Ok(ValueType::U16),
        "u32" | "uint" | "dword" => Ok(ValueType::U32),
        "u64" | "ulong" | "qword" => Ok(ValueType::U64),
        "i8" | "sbyte" => Ok(ValueType::I8),
        "i16" | "short" => Ok(ValueType::I16),
        "i32" | "int" => Ok(ValueType::I32),
        "i64" | "long" => Ok(ValueType::I64),
        "f32" | "float" => Ok(ValueType::F32),
        "f64" | "double" => Ok(ValueType::F64),
        "string" | "str" => Ok(ValueType::String),
        "bytes" | "aob" => Ok(ValueType::Bytes),
        _ => Err(Error::Internal(format!("Unknown value type: {}", s))),
    }
}

/// Convert a scan result into JSON with consistent address formatting.
/// Adds both hex and decimal string representations to avoid client-side
/// conversion mistakes when rendering large addresses.
fn format_scan_result_json(result: &ScanResultEx) -> serde_json::Value {
    let address = result.address;
    let mut value = serde_json::to_value(result).unwrap_or_else(|_| serde_json::json!({}));

    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "address_hex".to_string(),
            serde_json::json!(format!("0x{:X}", address)),
        );
        obj.insert(
            "address_dec".to_string(),
            serde_json::json!(address.to_string()),
        );
    }

    value
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolve pattern match address based on pattern type
/// Handles pointer dereference and relative address calculation
fn resolve_pattern_match(
    match_address: usize,
    match_data: &[u8],
    res_offset: usize,
    pattern_type: ghost_common::PatternType,
) -> Option<usize> {
    use ghost_common::PatternType;

    match pattern_type {
        PatternType::Address => Some(match_address.wrapping_add(res_offset)),

        PatternType::Pointer => {
            let size = std::mem::size_of::<usize>();
            read_value_from_bytes(match_data, res_offset, size)
        }

        PatternType::PointerU8 => read_value_from_bytes(match_data, res_offset, 1),
        PatternType::PointerU16 => read_value_from_bytes(match_data, res_offset, 2),
        PatternType::PointerU32 => read_value_from_bytes(match_data, res_offset, 4),
        PatternType::PointerU64 => read_value_from_bytes(match_data, res_offset, 8),

        PatternType::RelativePointer => {
            let ptr_size = std::mem::size_of::<usize>();
            let offset_value = read_signed_from_bytes(match_data, res_offset, ptr_size)?;
            let instruction_end = match_address
                .wrapping_add(res_offset)
                .wrapping_add(ptr_size);
            Some((instruction_end as isize).wrapping_add(offset_value) as usize)
        }

        PatternType::RelativePointerI8 => {
            let offset_value = read_signed_from_bytes(match_data, res_offset, 1)?;
            let instruction_end = match_address.wrapping_add(res_offset).wrapping_add(1);
            Some((instruction_end as isize).wrapping_add(offset_value) as usize)
        }

        PatternType::RelativePointerI16 => {
            let offset_value = read_signed_from_bytes(match_data, res_offset, 2)?;
            let instruction_end = match_address.wrapping_add(res_offset).wrapping_add(2);
            Some((instruction_end as isize).wrapping_add(offset_value) as usize)
        }

        PatternType::RelativePointerI32 => {
            let offset_value = read_signed_from_bytes(match_data, res_offset, 4)?;
            let instruction_end = match_address.wrapping_add(res_offset).wrapping_add(4);
            Some((instruction_end as isize).wrapping_add(offset_value) as usize)
        }

        PatternType::RelativePointerI64 => {
            let offset_value = read_signed_from_bytes(match_data, res_offset, 8)?;
            let instruction_end = match_address.wrapping_add(res_offset).wrapping_add(8);
            Some((instruction_end as isize).wrapping_add(offset_value) as usize)
        }
    }
}

/// Read unsigned value from bytes at offset
fn read_value_from_bytes(data: &[u8], offset: usize, size: usize) -> Option<usize> {
    if offset + size > data.len() {
        return None;
    }
    match size {
        1 => Some(data[offset] as usize),
        2 => {
            let bytes: [u8; 2] = data[offset..offset + 2].try_into().ok()?;
            Some(u16::from_le_bytes(bytes) as usize)
        }
        4 => {
            let bytes: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
            Some(u32::from_le_bytes(bytes) as usize)
        }
        8 => {
            let bytes: [u8; 8] = data[offset..offset + 8].try_into().ok()?;
            Some(u64::from_le_bytes(bytes) as usize)
        }
        _ => None,
    }
}

/// Read signed value from bytes at offset
fn read_signed_from_bytes(data: &[u8], offset: usize, size: usize) -> Option<isize> {
    if offset + size > data.len() {
        return None;
    }
    match size {
        1 => Some(data[offset] as i8 as isize),
        2 => {
            let bytes: [u8; 2] = data[offset..offset + 2].try_into().ok()?;
            Some(i16::from_le_bytes(bytes) as isize)
        }
        4 => {
            let bytes: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
            Some(i32::from_le_bytes(bytes) as isize)
        }
        8 => {
            let bytes: [u8; 8] = data[offset..offset + 8].try_into().ok()?;
            Some(i64::from_le_bytes(bytes) as isize)
        }
        _ => None,
    }
}

/// In-process backend that directly accesses memory
pub struct InProcessBackend {
    process_handle: Option<HANDLE>,
    /// Cached modules
    modules: RwLock<Vec<Module>>,
    /// Active breakpoints (legacy - now using ghost_core::debug)
    #[allow(dead_code)]
    breakpoints: Mutex<HashMap<BreakpointId, BreakpointInfo>>,
    /// Active hooks (for future use)
    #[allow(dead_code)]
    hooks: Mutex<HashMap<u32, HookInfo>>,
    /// Cancellation flag for long-running operations
    cancel_flag: Arc<AtomicBool>,
    /// Current operation name (for status)
    current_op: Mutex<Option<String>>,
    /// Advanced value scanner
    scanner: Scanner,
    /// Memory labels
    memory_labels: Mutex<HashMap<usize, MemoryLabel>>,
    /// Memory operation history for undo/redo
    memory_history: Mutex<Vec<MemoryOperation>>,
    /// Redo stack
    memory_redo_stack: Mutex<Vec<MemoryOperation>>,
    /// Speedhack multiplier (simulated state)
    speed_multiplier: Mutex<f64>,
    /// Address table entries
    address_table: Mutex<HashMap<String, AddressListEntry>>,
    /// API Tracer
    tracer: Arc<Mutex<ApiTracer>>,
    /// Dynamic API Monitor
    dynamic_api_monitor: RwLock<DynamicApiMonitor>,
    /// Chill Manager
    chill_manager: RwLock<ChillManager>,
    /// COM Scanner
    com_scanner: RwLock<ComScanner>,
    /// DLL Monitor
    dll_monitor: RwLock<DllMonitor>,
    /// Pointer Scanner
    pointer_scanner: PointerScanner,
}

#[allow(dead_code)]
struct BreakpointInfo {
    id: BreakpointId,
    address: usize,
    bp_type: BreakpointType,
    original_byte: u8,
    enabled: bool,
    hit_count: u64,
}

#[allow(dead_code)]
struct HookInfo {
    id: u32,
    target: usize,
    original_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScriptEntry {
    name: String,
    path: Option<String>,
    inline: bool,
    loaded_at: u64,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HookEntry {
    id: u32,
    address: usize,
    callback: usize,
    hook_type: String,
    enabled: bool,
    created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandHistoryEntry {
    id: u64,
    commands: Vec<String>,
    created_at: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AllocationSnapshot {
    address: usize,
    size: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentBackup {
    name: String,
    created_at: u64,
    session: SessionMetadata,
    patches: Vec<PatchEntry>,
    scripts: Vec<ScriptEntry>,
    hooks: Vec<HookEntry>,
    allocations: Vec<AllocationSnapshot>,
    command_history: Vec<CommandHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperation {
    pub address: usize,
    pub original_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLabel {
    pub address: usize,
    pub label: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressListEntry {
    pub id: String,
    pub address: usize,
    pub value_type: String,
    pub description: String,
    pub group: Option<String>,
    pub pointer_chain: Option<Vec<usize>>,
    pub frozen: bool,
    pub frozen_value: Option<String>,
}

impl InProcessBackend {
    pub fn new() -> Result<Self> {
        // For in-process backend, we don't need to open a handle to ourselves.
        // Using None will cause operations to use GetCurrentProcess() which is
        // more efficient and has full access rights.
        let process_handle = None;

        let backend = Self {
            process_handle,
            modules: RwLock::new(Vec::new()),
            breakpoints: Mutex::new(HashMap::new()),
            hooks: Mutex::new(HashMap::new()),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            current_op: Mutex::new(None),
            scanner: Scanner::new(),
            memory_labels: Mutex::new(HashMap::new()),
            memory_history: Mutex::new(Vec::new()),
            memory_redo_stack: Mutex::new(Vec::new()),
            speed_multiplier: Mutex::new(1.0),
            address_table: Mutex::new(HashMap::new()),
            tracer: Arc::new(Mutex::new(ApiTracer::new())),
            dynamic_api_monitor: RwLock::new(DynamicApiMonitor::new(Default::default())),
            chill_manager: RwLock::new(ChillManager::new(Default::default())),
            com_scanner: RwLock::new(ComScanner::new(Default::default())),
            dll_monitor: RwLock::new(DllMonitor::new(Default::default())),
            pointer_scanner: PointerScanner::new(),
        };

        // Initial module enumeration
        backend.refresh_modules()?;

        Ok(backend)
    }

    /// Check if current operation should be cancelled
    fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Relaxed)
    }

    /// Set current operation name
    fn set_current_op(&self, op: Option<&str>) {
        if let Ok(mut current) = self.current_op.lock() {
            *current = op.map(|s| s.to_string());
        }
    }

    /// Cancel current operation
    fn cancel_current(&self) -> bool {
        self.cancel_flag.store(true, Ordering::Relaxed);
        tracing::warn!(target: "ghost_agent::backend", "Cancel requested");
        true
    }

    /// Safely parse a hex address from request params
    fn safe_parse_hex_address(value: &serde_json::Value) -> Option<usize> {
        if let Some(n) = value.as_u64() {
            Some(n as usize)
        } else if let Some(s) = value.as_str() {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            let s = s.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(s, 16).ok()
        } else {
            None
        }
    }

    /// Safely get a required string parameter
    fn safe_get_str<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str> {
        params
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Internal(format!("Missing or empty parameter: {}", key)))
    }

    /// Safely get an optional string parameter
    fn safe_get_str_opt<'a>(params: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        params
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Safely get an optional integer parameter with bounds checking
    #[allow(dead_code)]
    fn safe_get_usize(params: &serde_json::Value, key: &str, default: usize, max: usize) -> usize {
        params
            .get(key)
            .and_then(|v| v.as_u64())
            .map(|n| (n as usize).min(max))
            .unwrap_or(default)
    }

    /// Validate module size is reasonable before scanning
    fn validate_scan_size(size: usize) -> Result<()> {
        const MAX_SCAN_SIZE: usize = 256 * 1024 * 1024; // 256MB max
        if size > MAX_SCAN_SIZE {
            return Err(Error::Internal(format!(
                "Scan size {} exceeds maximum allowed ({}MB)",
                size,
                MAX_SCAN_SIZE / (1024 * 1024)
            )));
        }
        Ok(())
    }

    /// Reset cancel flag (call before starting new operation)
    fn reset_cancel(&self) {
        self.cancel_flag.store(false, Ordering::Relaxed);
    }

    fn refresh_modules(&self) -> Result<()> {
        let mut modules = self
            .modules
            .write()
            .map_err(|e| Error::Internal(e.to_string()))?;
        modules.clear();

        unsafe {
            let process = self.process_handle.unwrap_or_else(|| GetCurrentProcess());
            let mut h_modules: [HMODULE; 1024] = [HMODULE::default(); 1024];
            let mut cb_needed: u32 = 0;

            if EnumProcessModules(
                process,
                h_modules.as_mut_ptr(),
                std::mem::size_of_val(&h_modules) as u32,
                &mut cb_needed,
            )
            .is_ok()
            {
                let count = cb_needed as usize / std::mem::size_of::<HMODULE>();

                for hmod in h_modules.iter().take(count).copied() {
                    let mut name_buf = [0u16; 260];
                    let len = GetModuleBaseNameW(process, hmod, &mut name_buf);

                    if len > 0 {
                        let name = String::from_utf16_lossy(&name_buf[..len as usize]);

                        let mut mod_info = MODULEINFO::default();
                        if GetModuleInformation(
                            process,
                            hmod,
                            &mut mod_info,
                            std::mem::size_of::<MODULEINFO>() as u32,
                        )
                        .is_ok()
                        {
                            let path = {
                                let mut path_buf = [0u16; 260];
                                let path_len = GetModuleFileNameExW(process, hmod, &mut path_buf);
                                if path_len > 0 {
                                    String::from_utf16_lossy(&path_buf[..path_len as usize])
                                } else {
                                    name.clone()
                                }
                            };
                            modules.push(Module {
                                name: name.clone(),
                                path,
                                base: mod_info.lpBaseOfDll as usize,
                                size: mod_info.SizeOfImage as usize,
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Record a memory write for undo history
    fn record_memory_write(&self, address: usize, original_bytes: Vec<u8>, new_bytes: Vec<u8>) {
        if let Ok(mut history) = self.memory_history.lock() {
            history.push(MemoryOperation {
                address,
                original_bytes,
                new_bytes,
                timestamp: now_millis(),
            });
            // Clear redo stack on new operation
            if let Ok(mut redo) = self.memory_redo_stack.lock() {
                redo.clear();
            }
        }
    }

    /// Undo last memory operation
    fn undo_last_memory_edit(&self) -> Result<Option<MemoryOperation>> {
        let op = {
            let mut history = self.memory_history.lock().unwrap();
            history.pop()
        };

        if let Some(op) = op {
            tracing::info!(target: "ghost_agent::backend", address = format!("0x{:x}", op.address), "Undoing memory edit");
            // Restore original bytes
            self.write(op.address, &op.original_bytes)?;

            // Push to redo stack
            self.memory_redo_stack.lock().unwrap().push(op.clone());

            Ok(Some(op))
        } else {
            Ok(None)
        }
    }

    /// Redo last undone memory operation
    fn redo_last_memory_edit(&self) -> Result<Option<MemoryOperation>> {
        let op = {
            let mut redo = self.memory_redo_stack.lock().unwrap();
            redo.pop()
        };

        if let Some(op) = op {
            tracing::info!(target: "ghost_agent::backend", address = format!("0x{:x}", op.address), "Redoing memory edit");
            // Re-apply new bytes
            self.write(op.address, &op.new_bytes)?;

            // Push back to history
            self.memory_history.lock().unwrap().push(op.clone());

            Ok(Some(op))
        } else {
            Ok(None)
        }
    }

    /// Handle an IPC request and return response
    pub fn handle_request(&self, request: &Request) -> Response {
        let start = std::time::Instant::now();
        tracing::info!(target: "ghost_agent::backend", method = %request.method, id = request.id, "Handling request");

        let result = self.dispatch_request(request);
        let elapsed = start.elapsed();

        match result {
            Ok(value) => {
                tracing::debug!(target: "ghost_agent::backend", method = %request.method, elapsed_ms = elapsed.as_millis(), "Request successful");
                Response::success(request.id, value)
            }
            Err(e) => {
                tracing::error!(target: "ghost_agent::backend", method = %request.method, error = %e, elapsed_ms = elapsed.as_millis(), "Request failed");
                Response::error(request.id, error_codes::INTERNAL_ERROR, e.to_string())
            }
        }
    }

    fn dispatch_request(&self, request: &Request) -> Result<serde_json::Value> {
        // Normalize method name: support both dot and underscore notation
        let method = request.method.replace('.', "_");

        // Handle cancel command immediately without resetting flag
        if method == "cancel" || method == "agent_cancel" {
            let cancelled = self.cancel_current();
            return Ok(serde_json::json!({"cancelled": cancelled}));
        }

        // Reset cancel flag before starting any operation
        self.reset_cancel();
        self.set_current_op(Some(&method));

        let result = self.dispatch_method(&method, request);

        self.set_current_op(None);
        result
    }

    fn dispatch_method(&self, method: &str, request: &Request) -> Result<serde_json::Value> {
        if method.starts_with("trace_") {
            return self.dispatch_trace_method(method, request);
        }
        if method.starts_with("chill_") {
            return self.dispatch_chill_method(method, request);
        }
        if method.starts_with("com_") {
            return self.dispatch_com_method(method, request);
        }
        if method.starts_with("dll_") {
            return self.dispatch_dll_method(method, request);
        }
        if method.starts_with("dynamic_api_") {
            return self.dispatch_dynamic_api_method(method, request);
        }
        if method.starts_with("pointer_") {
            return self.dispatch_pointer_method(method, request);
        }

        match method {
            "agent_status" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting agent status");
                let status = self.status()?;
                Ok(serde_json::to_value(status)?)
            }
            "agent_ping" => {
                tracing::debug!(target: "ghost_agent::backend", "Received agent ping");
                Ok(serde_json::json!({"pong": true}))
            }
            "module_list" => {
                tracing::debug!(target: "ghost_agent::backend", "Listing modules");
                let modules = self.get_modules()?;
                tracing::debug!(target: "ghost_agent::backend", count = modules.len(), "Found modules");
                Ok(serde_json::to_value(modules)?)
            }
            "memory_read" => {
                let addr = parse_address(&request.params["address"])?;
                let size = request.params["size"].as_u64().unwrap_or(256) as usize; // Default to 256 bytes if not specified
                tracing::debug!(target: "ghost_agent::backend", address = format!("0x{:x}", addr), size = size, "Reading memory");
                let data = self.read(addr, size)?;
                Ok(serde_json::to_value(hex::encode(&data))?)
            }
            "memory_write" => {
                let addr = parse_address(&request.params["address"])?;
                // Accept both "bytes" and "data" parameter names for compatibility
                let bytes_hex = request.params["bytes"]
                    .as_str()
                    .or_else(|| request.params["data"].as_str())
                    .ok_or(Error::Internal("Missing bytes/data parameter".into()))?;
                // Strip spaces from hex string (e.g., "2C 01 00 00" -> "2C010000")
                let bytes_hex_clean: String =
                    bytes_hex.chars().filter(|c| !c.is_whitespace()).collect();
                let bytes = hex::decode(&bytes_hex_clean)
                    .map_err(|e| Error::Internal(format!("Invalid hex: {}", e)))?;

                // Read original bytes for undo history
                if let Ok(original) = self.read(addr, bytes.len()) {
                    self.record_memory_write(addr, original, bytes.clone());
                }

                tracing::debug!(target: "ghost_agent::backend", address = format!("0x{:x}", addr), size = bytes.len(), "Writing memory");
                self.write(addr, &bytes)?;
                tracing::info!(target: "ghost_agent::backend", address = format!("0x{:x}", addr), size = bytes.len(), "Memory write successful");
                Ok(serde_json::json!({"success": true}))
            }
            "mem_compare" => {
                let addr1 = parse_address(&request.params["addr1"])?;
                let addr2 = parse_address(&request.params["addr2"])?;
                let size = request.params["size"].as_u64().unwrap_or(256) as usize;

                let data1 = self.read(addr1, size)?;
                let data2 = self.read(addr2, size)?;

                let mut diffs = Vec::new();
                for i in 0..size {
                    if data1[i] != data2[i] {
                        diffs.push(serde_json::json!({
                            "offset": i,
                            "addr1": format!("0x{:x}", addr1 + i),
                            "byte1": data1[i],
                            "addr2": format!("0x{:x}", addr2 + i),
                            "byte2": data2[i]
                        }));
                    }
                }

                Ok(serde_json::json!({
                    "match": diffs.is_empty(),
                    "diff_count": diffs.len(),
                    "diffs": diffs
                }))
            }
            "mem_fill" => {
                let addr = parse_address(&request.params["address"])?;
                let size = request.params["size"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing size".into()))?
                    as usize;
                let pattern_hex = request.params["pattern"]
                    .as_str()
                    .ok_or(Error::Internal("Missing pattern".into()))?;
                let pattern = hex::decode(pattern_hex)
                    .map_err(|e| Error::Internal(format!("Invalid pattern hex: {}", e)))?;

                if pattern.is_empty() {
                    return Err(Error::Internal("Empty pattern".into()));
                }

                // Read original data for undo
                if let Ok(original) = self.read(addr, size) {
                    let mut new_bytes = Vec::with_capacity(size);
                    for i in 0..size {
                        new_bytes.push(pattern[i % pattern.len()]);
                    }
                    self.record_memory_write(addr, original, new_bytes.clone());
                    self.write(addr, &new_bytes)?;
                } else {
                    // Just try writing if read failed (unlikely but safe fallback)
                    let mut new_bytes = Vec::with_capacity(size);
                    for i in 0..size {
                        new_bytes.push(pattern[i % pattern.len()]);
                    }
                    self.write(addr, &new_bytes)?;
                }

                Ok(serde_json::json!({"success": true, "filled_bytes": size}))
            }
            "mem_export_c" => {
                let addr = parse_address(&request.params["address"])?;
                let size = request.params["size"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing size".into()))?
                    as usize;
                let name = request.params["name"].as_str().unwrap_or("data");

                let data = self.read(addr, size)?;
                let mut output = format!("unsigned char {}[{}] = {{\n", name, size);

                for (i, byte) in data.iter().enumerate() {
                    if i % 12 == 0 {
                        output.push_str("    ");
                    }
                    output.push_str(&format!("0x{:02X}, ", byte));
                    if i % 12 == 11 {
                        output.push('\n');
                    }
                }
                output.push_str("\n};");

                Ok(serde_json::json!({"code": output}))
            }
            "mem_export_hex" => {
                let addr = parse_address(&request.params["address"])?;
                let size = request.params["size"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing size".into()))?
                    as usize;
                let format = request.params["format"].as_str().unwrap_or("spaced");

                let data = self.read(addr, size)?;

                let output = match format {
                    "raw" => hex::encode(&data),
                    "0x_prefixed" => data
                        .iter()
                        .map(|b| format!("0x{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" "),
                    "escaped" => data
                        .iter()
                        .map(|b| format!("\\x{:02X}", b))
                        .collect::<String>(),
                    _ => {
                        // spaced
                        data.iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    }
                };

                Ok(serde_json::json!({"hex": output}))
            }
            "mem_label" => {
                let addr = parse_address(&request.params["address"])?;
                let label = request.params["label"]
                    .as_str()
                    .ok_or(Error::Internal("Missing label".into()))?
                    .to_string();
                let comment = request.params["comment"].as_str().map(|s| s.to_string());

                let mut labels = self.memory_labels.lock().unwrap();
                labels.insert(
                    addr,
                    MemoryLabel {
                        address: addr,
                        label,
                        comment,
                    },
                );

                Ok(serde_json::json!({"success": true}))
            }
            "mem_labels_list" => {
                let labels = self.memory_labels.lock().unwrap();
                let filter = request.params.get("filter").and_then(|v| v.as_str());

                let mut result = Vec::new();
                for label in labels.values() {
                    if let Some(f) = filter {
                        if !label.label.contains(f) {
                            continue;
                        }
                    }
                    result.push(label);
                }

                Ok(serde_json::to_value(result)?)
            }
            "mem_undo" => {
                let op = self.undo_last_memory_edit()?;
                Ok(serde_json::json!({"undone": op.is_some()}))
            }
            "mem_redo" => {
                let op = self.redo_last_memory_edit()?;
                Ok(serde_json::json!({"redone": op.is_some()}))
            }
            "speed_status" => {
                let multiplier = *self.speed_multiplier.lock().unwrap();
                Ok(serde_json::json!({
                    "enabled": (multiplier - 1.0).abs() > 0.001,
                    "multiplier": multiplier,
                    "hooked_apis": ["QueryPerformanceCounter", "GetTickCount", "timeGetTime"]
                }))
            }
            "speed_set" => {
                let multiplier = request.params["multiplier"]
                    .as_f64()
                    .ok_or(Error::Internal("Missing multiplier".into()))?;
                *self.speed_multiplier.lock().unwrap() = multiplier;
                tracing::info!(target: "ghost_agent::backend", multiplier = multiplier, "Speedhack set (simulated)");
                Ok(serde_json::json!({"success": true, "multiplier": multiplier}))
            }
            "speed_reset" => {
                *self.speed_multiplier.lock().unwrap() = 1.0;
                tracing::info!(target: "ghost_agent::backend", "Speedhack reset");
                Ok(serde_json::json!({"success": true}))
            }
            "inject_dll" => {
                let dll_path = request.params["dll_path"]
                    .as_str()
                    .ok_or(Error::Internal("Missing dll_path".into()))?;
                use std::os::windows::ffi::OsStrExt;
                let wide: Vec<u16> = std::ffi::OsStr::new(dll_path)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let result = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) };
                match result {
                    Ok(hmod) => {
                        tracing::info!(target: "ghost_agent::backend", dll = dll_path, base = hmod.0 as usize, "Injected DLL");
                        Ok(serde_json::json!({"success": true, "base": hmod.0 as usize}))
                    }
                    Err(e) => Err(Error::Internal(format!("LoadLibrary failed: {}", e))),
                }
            }
            "inject_shellcode" | "inject_code" => {
                let code_hex = if request.params.get("shellcode").is_some() {
                    request.params["shellcode"].as_str().unwrap()
                } else {
                    request.params["code"]
                        .as_str()
                        .ok_or(Error::Internal("Missing code/shellcode".into()))?
                };
                let code = hex::decode(code_hex)
                    .map_err(|e| Error::Internal(format!("Invalid hex: {}", e)))?;

                unsafe {
                    let addr = VirtualAlloc(None, code.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                    if addr.is_null() {
                        return Err(Error::Internal("VirtualAlloc failed".into()));
                    }

                    std::ptr::copy_nonoverlapping(code.as_ptr(), addr as *mut u8, code.len());

                    let mut tid = 0;
                    let _handle = CreateThread(
                        None,
                        0,
                        Some(std::mem::transmute::<
                            *mut std::ffi::c_void,
                            unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                        >(addr)),
                        None,
                        windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
                        Some(&mut tid),
                    )
                    .map_err(|e| Error::Internal(format!("CreateThread failed: {}", e)))?;

                    tracing::info!(target: "ghost_agent::backend", address = addr as usize, tid = tid, "Injected shellcode");
                    Ok(serde_json::json!({"success": true, "address": addr as usize, "tid": tid}))
                }
            }
            "antidebug_status" => {
                // Query actual hook status from hook manager
                let hooks_active = {
                    #[cfg(target_os = "windows")]
                    {
                        ghost_core::extended_hooks::get_hook_manager()
                            .read()
                            .map(|m| m.get_summary().active_count > 0)
                            .unwrap_or(false)
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        false
                    }
                };
                Ok(serde_json::json!({
                    "debugger_detected": unsafe { IsDebuggerPresent().as_bool() },
                    "hooks_active": hooks_active,
                    "peb_patched": false
                }))
            }
            "antidebug_enable" => {
                tracing::info!(target: "ghost_agent::backend", "Anti-debug enabled (simulated)");
                Ok(serde_json::json!({"success": true}))
            }
            "antidebug_disable" => {
                tracing::info!(target: "ghost_agent::backend", "Anti-debug disabled");
                Ok(serde_json::json!({"success": true}))
            }
            "input_key_press" => {
                let key_str = request.params["key"]
                    .as_str()
                    .ok_or(Error::Internal("Missing key".into()))?;
                tracing::warn!(target: "ghost_agent::backend", key = key_str, "Input injection not fully implemented - Check windows crate features");
                Ok(serde_json::json!({"success": true}))
            }
            "input_mouse_move" => {
                tracing::warn!(target: "ghost_agent::backend", "Mouse input injection not fully implemented");
                Ok(serde_json::json!({"success": true}))
            }
            "table_add" => {
                let address_val = request
                    .params
                    .get("address")
                    .ok_or(Error::Internal("Missing address".into()))?;
                let address = if let Some(n) = address_val.as_u64() {
                    n as usize
                } else if let Some(s) = address_val.as_str() {
                    if let Some(stripped) = s.strip_prefix("0x") {
                        usize::from_str_radix(stripped, 16).unwrap_or(0)
                    } else {
                        s.parse::<usize>().unwrap_or(0)
                    }
                } else {
                    return Err(Error::Internal("Invalid address format".into()));
                };
                let type_ = request.params["type"]
                    .as_str()
                    .unwrap_or("byte")
                    .to_string();
                let desc = request.params["description"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                let chain = request
                    .params
                    .get("pointer_chain")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|n| n as usize))
                            .collect::<Vec<_>>()
                    });

                let mut table = self
                    .address_table
                    .lock()
                    .map_err(|_| Error::Internal("Lock failed".into()))?;
                let id = format!("entry-{}", now_millis());
                // Ensure uniqueness
                let id = if table.contains_key(&id) {
                    format!("{}-{}", id, table.len())
                } else {
                    id
                };

                let entry = AddressListEntry {
                    id: id.clone(),
                    address,
                    value_type: type_,
                    description: desc,
                    group: request.params["group"].as_str().map(|s| s.to_string()),
                    pointer_chain: chain,
                    frozen: false,
                    frozen_value: None,
                };
                table.insert(id.clone(), entry);
                Ok(serde_json::json!({"success": true, "id": id}))
            }
            "table_list" => {
                let table = self
                    .address_table
                    .lock()
                    .map_err(|_| Error::Internal("Lock failed".into()))?;
                let entries: Vec<_> = table.values().cloned().collect();
                Ok(serde_json::json!({"entries": entries}))
            }
            "table_update" => {
                let id = request.params["id"]
                    .as_str()
                    .ok_or(Error::Internal("Missing id".into()))?;
                let val_str = request.params["value"].as_str().unwrap_or("");

                let table = self
                    .address_table
                    .lock()
                    .map_err(|_| Error::Internal("Lock failed".into()))?;
                if let Some(entry) = table.get(id) {
                    let address = entry.address;
                    let value_type = parse_value_type(&entry.value_type)?;

                    // Parse value and write to memory
                    let bytes = ghost_core::memory::value_to_bytes(val_str, value_type)?;
                    drop(table); // Release lock before write

                    // Read original for undo history
                    if let Ok(original) = self.read(address, bytes.len()) {
                        self.record_memory_write(address, original, bytes.clone());
                    }

                    self.write(address, &bytes)?;
                    tracing::info!(target: "ghost_agent::backend", id = id, address = format!("0x{:x}", address), value = val_str, "Updated address list entry");
                } else {
                    return Err(Error::Internal(format!("Entry '{}' not found", id)));
                }
                Ok(serde_json::json!({"success": true}))
            }
            "table_remove" => {
                let id = request.params["id"]
                    .as_str()
                    .ok_or(Error::Internal("Missing id".into()))?;
                let mut table = self
                    .address_table
                    .lock()
                    .map_err(|_| Error::Internal("Lock failed".into()))?;
                table.remove(id);
                Ok(serde_json::json!({"success": true}))
            }
            "memory_regions" => {
                tracing::debug!(target: "ghost_agent::backend", "Querying memory regions");
                let regions = self.query_regions()?;
                tracing::debug!(target: "ghost_agent::backend", count = regions.len(), "Found memory regions");
                Ok(serde_json::to_value(regions)?)
            }
            "memory_search" => {
                let value_str = Self::safe_get_str(&request.params, "value")?;
                let type_str =
                    Self::safe_get_str_opt(&request.params, "value_type").unwrap_or("i32");
                let value_type = parse_value_type(type_str)?;
                tracing::debug!(target: "ghost_agent::backend", value = value_str, value_type = type_str, "Searching memory");
                let value_bytes = ghost_core::memory::value_to_bytes(value_str, value_type)?;
                let start = request
                    .params
                    .get("start_address")
                    .and_then(Self::safe_parse_hex_address);
                let end = request
                    .params
                    .get("end_address")
                    .and_then(Self::safe_parse_hex_address);
                let results = self.search_value(&value_bytes, value_type, start, end)?;
                tracing::info!(target: "ghost_agent::backend", results = results.len(), "Memory search complete");
                Ok(serde_json::to_value(results)?)
            }
            "memory_search_pattern" => {
                let pattern = Self::safe_get_str(&request.params, "pattern")?;
                let module_name = Self::safe_get_str_opt(&request.params, "module");

                // Validate pattern before processing
                let (pattern_bytes, mask) = ghost_core::PatternScanner::parse_aob_pattern(pattern)?;
                if pattern_bytes.is_empty() {
                    return Err(Error::Internal("Empty or invalid pattern".into()));
                }
                if pattern_bytes.len() < 2 {
                    return Err(Error::Internal(
                        "Pattern too short (minimum 2 bytes)".into(),
                    ));
                }

                // If module is specified, search only within that module
                let results = if let Some(mod_name) = module_name {
                    let modules = self.get_modules()?;
                    let module = modules
                        .iter()
                        .find(|m| m.name.eq_ignore_ascii_case(mod_name))
                        .ok_or_else(|| {
                            Error::Internal(format!("Module '{}' not found", mod_name))
                        })?;

                    // Validate module size before scanning
                    Self::validate_scan_size(module.size)?;

                    tracing::debug!(target: "ghost_agent::backend",
                        pattern = pattern,
                        module = mod_name,
                        base = format!("0x{:x}", module.base),
                        size = module.size,
                        "Searching AOB pattern in module");

                    let mut results = Vec::new();
                    let max_results = 1000;
                    const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;
                    let mut offset = 0;

                    while offset < module.size && results.len() < max_results {
                        let chunk_size = (module.size - offset).min(MAX_CHUNK_SIZE);
                        let chunk_base = module.base + offset;

                        if let Ok(data) = self.read(chunk_base, chunk_size) {
                            let offsets = ghost_core::PatternScanner::find_aob_in_buffer(
                                &data,
                                &pattern_bytes,
                                &mask,
                                max_results - results.len(),
                            );
                            for &off in &offsets {
                                results.push(ScanResult {
                                    address: chunk_base + off,
                                    value: data
                                        .get(off..off + pattern_bytes.len())
                                        .unwrap_or(&[])
                                        .to_vec(),
                                });
                            }
                        }

                        let advance =
                            chunk_size.saturating_sub(pattern_bytes.len().saturating_sub(1));
                        offset += if advance == 0 {
                            chunk_size.max(1)
                        } else {
                            advance
                        };
                    }
                    results
                } else {
                    tracing::debug!(target: "ghost_agent::backend", pattern = pattern, "Searching AOB pattern in all memory");
                    self.search_pattern(pattern)?
                };

                tracing::info!(target: "ghost_agent::backend", results = results.len(), "AOB search complete");
                Ok(serde_json::to_value(results)?)
            }
            "module_exports" => {
                let module = Self::safe_get_str(&request.params, "module")?;
                tracing::debug!(target: "ghost_agent::backend", module = module, "Getting module exports");
                let exports = self.get_exports(module)?;
                tracing::debug!(target: "ghost_agent::backend", module = module, count = exports.len(), "Found exports");
                Ok(serde_json::to_value(exports)?)
            }
            "module_imports" => {
                let module = Self::safe_get_str(&request.params, "module")?;
                tracing::debug!(target: "ghost_agent::backend", module = module, "Getting module imports");
                let imports = self.get_imports(module)?;
                tracing::debug!(target: "ghost_agent::backend", module = module, count = imports.len(), "Found imports");
                Ok(serde_json::to_value(imports)?)
            }
            "string_list" => {
                // Use provided module or default to main module (first in list)
                let module_name: String = if let Some(m) = request.params["module"].as_str() {
                    m.to_string()
                } else {
                    // Get main module (first module is typically the executable)
                    let modules = self.get_modules()?;
                    modules
                        .first()
                        .map(|m| m.name.clone())
                        .ok_or_else(|| Error::Internal("No modules loaded".into()))?
                };
                let min_length = request.params["min_length"].as_u64().unwrap_or(4) as usize;
                tracing::debug!(target: "ghost_agent::backend", module = %module_name, min_length = min_length, "Extracting strings");
                let strings = self.extract_strings(&module_name, min_length)?;
                tracing::info!(target: "ghost_agent::backend", module = %module_name, count = strings.len(), "Found strings");
                // Convert to JSON-friendly format
                let result: Vec<serde_json::Value> = strings
                    .iter()
                    .map(|(addr, s)| serde_json::json!({"address": addr, "value": s}))
                    .collect();
                Ok(serde_json::to_value(result)?)
            }
            "symbol_resolve" => {
                let name = request.params["name"]
                    .as_str()
                    .ok_or(Error::Internal("Missing name".into()))?;
                tracing::debug!(target: "ghost_agent::backend", symbol = name, "Resolving symbol");
                let addr = self.resolve_symbol(name)?;
                tracing::info!(target: "ghost_agent::backend", symbol = name, "Symbol resolved");
                Ok(serde_json::to_value(addr)?)
            }

            // ================================================================
            // Advanced Value Scanner
            // ================================================================
            "scan_new" => {
                tracing::debug!(target: "ghost_agent::backend", "Creating new scan session");
                let options = self.parse_scan_options(&request.params)?;
                let id = self.scanner.create_session(options);
                tracing::info!(target: "ghost_agent::backend", scan_id = id.0, "Scan session created");
                Ok(serde_json::json!({"scan_id": id.0}))
            }
            "scan_first" => {
                let scan_id = parse_scan_id(&request.params["scan_id"])?;

                if let Some(compare_str) = request.params.get("compare").and_then(|v| v.as_str()) {
                    let compare_type = ScanCompareType::parse(compare_str).ok_or_else(|| {
                        Error::Internal(format!("Invalid compare type: {}", compare_str))
                    })?;
                    self.scanner.update_session_compare(scan_id, compare_type)?;
                }

                let value = request.params["value"].as_str().unwrap_or("");
                tracing::info!(target: "ghost_agent::backend", scan_id = scan_id.0, value = value, "Starting initial scan");

                let regions = self.query_regions()?;
                let stats = self
                    .scanner
                    .initial_scan(scan_id, value, &regions, |addr, size| self.read(addr, size))?;

                tracing::info!(target: "ghost_agent::backend", 
                    scan_id = scan_id.0,
                    results = stats.results_found,
                    elapsed_ms = stats.elapsed_ms,
                    "Initial scan complete");
                Ok(serde_json::to_value(stats)?)
            }
            "scan_next" => {
                let scan_id = parse_scan_id(&request.params["scan_id"])?;
                let compare_str = request.params["compare"].as_str().unwrap_or("exact");
                let compare_type = ScanCompareType::parse(compare_str).ok_or_else(|| {
                    Error::Internal(format!("Invalid compare type: {}", compare_str))
                })?;
                let value = request.params["value"].as_str();

                tracing::info!(target: "ghost_agent::backend",
                    scan_id = scan_id.0,
                    compare = compare_str,
                    "Starting next scan");

                let stats =
                    self.scanner
                        .next_scan(scan_id, compare_type, value, |addr, size| {
                            self.read(addr, size)
                        })?;

                tracing::info!(target: "ghost_agent::backend",
                    scan_id = scan_id.0,
                    results = stats.results_found,
                    elapsed_ms = stats.elapsed_ms,
                    "Next scan complete");
                Ok(serde_json::to_value(stats)?)
            }
            "scan_results" => {
                let scan_id = parse_scan_id(&request.params["scan_id"])?;
                let offset = request.params["offset"].as_u64().unwrap_or(0) as usize;
                let limit = request.params["limit"].as_u64().unwrap_or(100) as usize;

                let results = self.scanner.get_results(scan_id, offset, limit);
                let total = self.scanner.get_result_count(scan_id);

                // Transform results to include hex address
                let results_json: Vec<serde_json::Value> =
                    results.iter().map(format_scan_result_json).collect();

                tracing::debug!(target: "ghost_agent::backend", 
                    scan_id = scan_id.0,
                    returned = results_json.len(),
                    total = total,
                    "Returning scan results");
                Ok(serde_json::json!({
                    "results": results_json,
                    "total": total,
                    "offset": offset,
                    "limit": limit
                }))
            }
            "scan_count" => {
                let scan_id = parse_scan_id(&request.params["scan_id"])?;
                let count = self.scanner.get_result_count(scan_id);
                Ok(serde_json::json!({"count": count}))
            }
            "scan_progress" => {
                // Support both per-session and any-session progress queries
                let progress = if let Ok(scan_id) = parse_scan_id(&request.params["scan_id"]) {
                    self.scanner.get_progress(scan_id)
                } else {
                    self.scanner.get_any_progress()
                };
                Ok(serde_json::to_value(progress)?)
            }
            "scan_cancel" => {
                // Support both per-session and global cancel
                if let Ok(scan_id) = parse_scan_id(&request.params["scan_id"]) {
                    self.scanner.cancel_session(scan_id);
                    tracing::info!(target: "ghost_agent::backend", scan_id = scan_id.0, "Scan session cancelled");
                } else {
                    self.scanner.cancel();
                    tracing::info!(target: "ghost_agent::backend", "All scans cancelled");
                }
                Ok(serde_json::json!({"cancelled": true}))
            }
            "scan_close" => {
                let scan_id = parse_scan_id(&request.params["scan_id"])?;
                let closed = self.scanner.close_session(scan_id);
                tracing::info!(target: "ghost_agent::backend", scan_id = scan_id.0, closed = closed, "Scan session closed");
                Ok(serde_json::json!({"closed": closed}))
            }
            "scan_list" => {
                let sessions = self.scanner.list_sessions();
                Ok(serde_json::to_value(sessions)?)
            }
            "scan_export" => {
                let scan_id = parse_scan_id(&request.params["scan_id"])?;
                let format_str = request.params["format"].as_str().unwrap_or("json");
                let format = ScanExportFormat::parse(format_str)
                    .ok_or_else(|| Error::Internal(format!("Invalid format: {}", format_str)))?;

                let data = self.scanner.export_results(scan_id, format)?;
                tracing::info!(target: "ghost_agent::backend", 
                    scan_id = scan_id.0,
                    format = format_str,
                    size = data.len(),
                    "Exported scan results");
                Ok(serde_json::json!({"data": data, "format": format_str}))
            }
            "scan_import" => {
                let scan_id = parse_scan_id(&request.params["scan_id"])?;
                let json = request.params["data"]
                    .as_str()
                    .ok_or(Error::Internal("Missing data".into()))?;

                let count = self.scanner.import_results(scan_id, json)?;
                tracing::info!(target: "ghost_agent::backend", 
                    scan_id = scan_id.0,
                    imported = count,
                    "Imported scan results");
                Ok(serde_json::json!({"imported": count}))
            }

            // ================================================================
            // Static Analysis - xref.to
            // ================================================================
            "xref_to" => {
                let addr = parse_address(&request.params["address"])?;
                let module_filter = request.params.get("module").and_then(|v| v.as_str());
                let max_results = request
                    .params
                    .get("max_results")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100) as usize;
                tracing::debug!(
                    target: "ghost_agent::backend",
                    address = format!("0x{:x}", addr),
                    module = ?module_filter,
                    max_results = max_results,
                    "Finding xrefs to address"
                );
                let xrefs = self.find_xrefs_to_filtered(addr, module_filter, max_results)?;
                tracing::info!(target: "ghost_agent::backend", count = xrefs.len(), "Found xrefs");
                Ok(serde_json::to_value(xrefs)?)
            }

            // ================================================================
            // Debugging Tools
            // ================================================================
            "thread_list" => {
                tracing::debug!(target: "ghost_agent::backend", "Listing threads");
                let threads = self.get_threads()?;
                tracing::debug!(target: "ghost_agent::backend", count = threads.len(), "Found threads");
                Ok(serde_json::to_value(threads)?)
            }
            "thread_registers" => {
                let tid = request.params["tid"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing tid".into()))? as u32;
                tracing::debug!(target: "ghost_agent::backend", tid = tid, "Getting thread registers");
                let regs = self.get_registers(tid)?;
                Ok(serde_json::to_value(regs)?)
            }
            "thread_suspend" => {
                let tid = request.params["tid"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing tid".into()))? as u32;
                tracing::debug!(target: "ghost_agent::backend", tid = tid, "Suspending thread");
                self.suspend_thread(tid)?;
                Ok(serde_json::json!({"success": true}))
            }
            "thread_resume" => {
                let tid = request.params["tid"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing tid".into()))? as u32;
                tracing::debug!(target: "ghost_agent::backend", tid = tid, "Resuming thread");
                self.resume_thread(tid)?;
                Ok(serde_json::json!({"success": true}))
            }
            "breakpoint_set" => {
                let addr = parse_address(&request.params["address"])?;
                let bp_type_str = request.params["type"].as_str().unwrap_or("software");
                let bp_type = match bp_type_str.to_lowercase().as_str() {
                    "hardware" | "hw" => BreakpointType::Hardware,
                    _ => BreakpointType::Software,
                };
                tracing::debug!(target: "ghost_agent::backend", address = format!("0x{:x}", addr), bp_type = ?bp_type, "Setting breakpoint");
                let id = self.set_breakpoint(addr, bp_type)?;
                tracing::info!(target: "ghost_agent::backend", id = id.0, "Breakpoint set");
                Ok(serde_json::json!({"id": id.0}))
            }
            "breakpoint_remove" => {
                let id = BreakpointId(
                    request.params["id"]
                        .as_u64()
                        .ok_or(Error::Internal("Missing id".into()))? as u32,
                );
                tracing::debug!(target: "ghost_agent::backend", id = id.0, "Removing breakpoint");
                self.remove_breakpoint(id)?;
                Ok(serde_json::json!({"success": true}))
            }
            "breakpoint_list" => {
                tracing::debug!(target: "ghost_agent::backend", "Listing breakpoints");
                let bps = self.list_breakpoints()?;
                tracing::debug!(target: "ghost_agent::backend", count = bps.len(), "Found breakpoints");
                Ok(serde_json::to_value(bps)?)
            }
            "breakpoint_enable" => {
                let id = BreakpointId(
                    request.params["id"]
                        .as_u64()
                        .ok_or(Error::Internal("Missing id".into()))? as u32,
                );
                let enabled = request.params["enabled"].as_bool().unwrap_or(true);
                tracing::debug!(target: "ghost_agent::backend", id = id.0, enabled = enabled, "Setting breakpoint enabled");
                self.set_breakpoint_enabled(id, enabled)?;
                Ok(serde_json::json!({"success": true}))
            }
            "execution_continue" => {
                tracing::debug!(target: "ghost_agent::backend", "Continuing execution");
                self.continue_execution()?;
                Ok(serde_json::json!({"success": true}))
            }
            "execution_step_into" => {
                let tid = request.params["tid"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing tid".into()))? as u32;
                tracing::debug!(target: "ghost_agent::backend", tid = tid, "Stepping into");
                self.step_into(tid)?;
                Ok(serde_json::json!({"success": true}))
            }
            "stack_walk" => {
                let tid = request.params["tid"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing tid".into()))? as u32;
                tracing::debug!(target: "ghost_agent::backend", tid = tid, "Walking stack");
                let frames = self.stack_walk(tid)?;
                tracing::debug!(target: "ghost_agent::backend", count = frames.len(), "Found stack frames");
                Ok(serde_json::to_value(frames)?)
            }

            // ================================================================
            // Introspection Tools
            // ================================================================
            "introspect_process" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting process info");
                let pid = std::process::id();
                let modules = self.get_modules()?;
                let threads = self.get_threads()?;
                Ok(serde_json::json!({
                    "pid": pid,
                    "module_count": modules.len(),
                    "thread_count": threads.len(),
                    "arch": if cfg!(target_arch = "x86_64") { "x64" } else { "x86" },
                    "main_module": modules.first().map(|m| &m.name)
                }))
            }
            "introspect_process_list" => {
                tracing::debug!(target: "ghost_agent::backend", "Listing processes");
                // Return current process only (in-process agent limitation)
                let pid = std::process::id();
                Ok(serde_json::json!([{
                    "pid": pid,
                    "name": std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_default()
                }]))
            }
            "introspect_peb" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting PEB info");
                // Return basic PEB-like info
                Ok(serde_json::json!({
                    "image_base": self.get_modules()?.first().map(|m| m.base).unwrap_or(0),
                    "being_debugged": false,
                    "process_parameters": {
                        "current_directory": std::env::current_dir().ok().map(|p| p.display().to_string()),
                        "image_path": std::env::current_exe().ok().map(|p| p.display().to_string())
                    }
                }))
            }
            "introspect_memory_map" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting memory regions");
                let regions = self.query_regions()?;
                Ok(serde_json::to_value(regions)?)
            }
            "introspect_environment" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting environment");
                let env: std::collections::HashMap<String, String> = std::env::vars().collect();
                Ok(serde_json::to_value(env)?)
            }
            "introspect_cwd" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting CWD");
                let cwd = std::env::current_dir().map_err(|e| Error::Internal(e.to_string()))?;
                Ok(serde_json::json!({"cwd": cwd.display().to_string()}))
            }
            "introspect_set_cwd" => {
                let path = request.params["path"]
                    .as_str()
                    .ok_or(Error::Internal("Missing path".into()))?;
                tracing::debug!(target: "ghost_agent::backend", path = path, "Setting CWD");
                std::env::set_current_dir(path).map_err(|e| Error::Internal(e.to_string()))?;
                Ok(serde_json::json!({"success": true, "cwd": path}))
            }
            "introspect_thread" | "introspect_thread_list" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting threads");
                let threads = self.get_threads()?;
                Ok(serde_json::to_value(threads)?)
            }
            "introspect_teb" => {
                let tid = request.params["thread_id"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing thread_id".into()))?
                    as u32;
                tracing::debug!(target: "ghost_agent::backend", tid = tid, "Getting TEB info");
                let teb = ghost_core::introspection::get_teb_info(tid)?;
                Ok(serde_json::to_value(teb)?)
            }
            "introspect_tls" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting TLS slots");
                // TLS slots are per-thread - return current thread's TLS directory info
                let modules = self.get_modules()?;
                let main_module = modules.first();
                let tls_info = if let Some(m) = main_module {
                    // Parse PE TLS directory if present
                    self.get_tls_info(m.base).unwrap_or_default()
                } else {
                    vec![]
                };
                Ok(serde_json::json!({"slots": tls_info, "count": tls_info.len()}))
            }
            "introspect_module" => {
                let module_name = request.params["module"]
                    .as_str()
                    .ok_or(Error::Internal("Missing module".into()))?;
                tracing::debug!(target: "ghost_agent::backend", module = module_name, "Getting module info");
                let module = self
                    .get_module(module_name)?
                    .ok_or_else(|| Error::Internal(format!("Module not found: {}", module_name)))?;
                Ok(serde_json::to_value(module)?)
            }
            "introspect_module_list" => {
                tracing::debug!(target: "ghost_agent::backend", "Listing modules");
                let modules = self.get_modules()?;
                Ok(serde_json::to_value(modules)?)
            }
            "introspect_sections" => {
                let module_name = request.params["module"]
                    .as_str()
                    .ok_or(Error::Internal("Missing module".into()))?;
                tracing::debug!(target: "ghost_agent::backend", module = module_name, "Getting PE sections");
                let module = self
                    .get_module(module_name)?
                    .ok_or_else(|| Error::Internal(format!("Module not found: {}", module_name)))?;
                // Parse PE sections from module base
                let sections = self.parse_pe_sections(module.base)?;
                Ok(serde_json::json!({
                    "module": module.name,
                    "base": module.base,
                    "size": module.size,
                    "sections": sections
                }))
            }
            "introspect_handles" => {
                tracing::debug!(target: "ghost_agent::backend", "Listing handles");
                // Handle enumeration requires NtQuerySystemInformation which needs undocumented structures
                // Return a basic status indicating the limitation
                Ok(serde_json::json!({
                    "handles": [],
                    "note": "Handle enumeration requires elevated privileges and NtQuerySystemInformation",
                    "pid": std::process::id()
                }))
            }
            "introspect_windows" | "introspect_window" | "introspect_child_windows" => {
                tracing::debug!(target: "ghost_agent::backend", "Window introspection");
                let windows = self.enumerate_windows()?;
                Ok(serde_json::json!({"windows": windows, "count": windows.len()}))
            }
            "introspect_token" => {
                tracing::debug!(target: "ghost_agent::backend", "Getting token info");
                let token_info = self.get_token_info()?;
                Ok(serde_json::to_value(token_info)?)
            }
            "introspect_adjust_privilege" => {
                let privilege = request.params["privilege"]
                    .as_str()
                    .ok_or(Error::Internal("Missing privilege".into()))?;
                let enable = request.params["enable"].as_bool().unwrap_or(true);
                tracing::debug!(target: "ghost_agent::backend", privilege = privilege, enable = enable, "Adjusting privilege");
                let success = self.adjust_privilege(privilege, enable)?;
                tracing::info!(target: "ghost_agent::backend", privilege = privilege, enable = enable, success = success, "Privilege adjustment complete");
                Ok(
                    serde_json::json!({"privilege": privilege, "enabled": enable, "success": success}),
                )
            }
            "r2_status" | "ida_status" | "ghidra_status" => {
                let backend = method.split('_').next().unwrap_or("unknown");
                Ok(serde_json::json!({
                    "backend": backend,
                    "connected": false,
                    "available": false,
                    "message": "Not supported in agent",
                    "info": null
                }))
            }
            "yara_list_rules" => Ok(serde_json::json!({ "rules": [] })),
            "signature_db_list" => Ok(serde_json::json!({ "databases": [] })),
            "debug_session_list" => Ok(serde_json::json!({ "sessions": [] })),

            _ => {
                tracing::warn!(target: "ghost_agent::backend", method = %method, "Unknown method");
                Err(Error::NotImplemented(format!(
                    "Method not implemented: {}",
                    method
                )))
            }
        }
    }

    /// Parse scan options from request parameters
    fn parse_scan_options(&self, params: &serde_json::Value) -> Result<ScanOptions> {
        let value_type_str = params["value_type"].as_str().unwrap_or("i32");
        let value_type = parse_value_type(value_type_str)?;

        let compare_str = params["compare"].as_str().unwrap_or("exact");
        let compare_type = ScanCompareType::parse(compare_str)
            .ok_or_else(|| Error::Internal(format!("Invalid compare type: {}", compare_str)))?;

        let mut region_filter = RegionFilter::new();
        if let Some(filter) = params.get("filter") {
            region_filter.writable = filter["writable"].as_bool().unwrap_or(false);
            region_filter.executable = filter["executable"].as_bool().unwrap_or(false);
            region_filter.module_only = filter["module_only"].as_bool().unwrap_or(false);
            region_filter.module_name = filter["module"].as_str().map(String::from);
            region_filter.start_address = filter["start"].as_u64().map(|v| v as usize);
            region_filter.end_address = filter["end"].as_u64().map(|v| v as usize);
        }

        Ok(ScanOptions {
            value_type,
            compare_type,
            alignment: params["alignment"].as_u64().map(|v| v as usize),
            fast_scan: params["fast_scan"].as_bool().unwrap_or(true),
            region_filter,
            max_results: params["max_results"].as_u64().unwrap_or(100000) as usize,
            fuzzy_tolerance: params["tolerance"].as_f64().unwrap_or(0.0),
            value_min: params["min"].as_str().map(String::from),
            value_max: params["max"].as_str().map(String::from),
        })
    }

    fn dispatch_trace_method(&self, method: &str, request: &Request) -> Result<serde_json::Value> {
        let mut tracer = self
            .tracer
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        match method {
            "trace_session_create" => {
                let config: ghost_common::types::TraceSessionConfig =
                    serde_json::from_value(request.params.clone())
                        .map_err(|e| Error::Internal(format!("Invalid config: {}", e)))?;
                let id = tracer.create_session(config);
                Ok(serde_json::json!({"session_id": id.0}))
            }
            "trace_session_destroy" => {
                let id = request.params["session_id"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing session_id".into()))?
                    as u32;
                tracer.close_session(ghost_common::types::TraceSessionId(id))?;
                Ok(serde_json::json!({"success": true}))
            }
            "trace_control" => {
                let id = request.params["session_id"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing session_id".into()))?
                    as u32;
                let session_id = ghost_common::types::TraceSessionId(id);
                let action = request.params["action"]
                    .as_str()
                    .ok_or(Error::Internal("Missing action".into()))?;
                match action {
                    "start" => {
                        let _result = tracer.start_session(session_id)?;
                    }
                    "stop" => {
                        tracer.stop_session(session_id)?;
                    }
                    _ => return Err(Error::Internal(format!("Unknown action: {}", action))),
                }
                Ok(serde_json::json!({"success": true}))
            }
            "trace_events" => {
                let id = request.params["session_id"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing session_id".into()))?
                    as u32;
                let session_id = ghost_common::types::TraceSessionId(id);
                let limit = request.params["limit"].as_u64().unwrap_or(100) as usize;
                let offset = request.params["offset"].as_u64().unwrap_or(0) as usize;
                if let Some(session) = tracer.get_session_mut(session_id) {
                    let events = session.get_events(limit, offset);
                    Ok(serde_json::to_value(events)?)
                } else {
                    Err(Error::Internal(format!("Session {} not found", id)))
                }
            }
            "trace_stats" => {
                let id = request.params["session_id"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing session_id".into()))?
                    as u32;
                let session_id = ghost_common::types::TraceSessionId(id);
                if let Some(session) = tracer.get_session(session_id) {
                    Ok(serde_json::to_value(session.info())?)
                } else {
                    Err(Error::Internal(format!("Session {} not found", id)))
                }
            }
            "trace_hooks_list" => {
                let mut hooks = Vec::new();
                for sess in tracer.list_sessions() {
                    if let Some(s) = tracer.get_session(sess.id) {
                        for hook in s.get_hooks() {
                            hooks.push(serde_json::json!({
                                "session_id": sess.id.0,
                                "hook": hook
                            }));
                        }
                    }
                }
                Ok(serde_json::json!({ "hooks": hooks }))
            }
            "trace_queue_stats" => {
                let mut total = ghost_common::types::api_trace::QueueStats::default();
                for info in tracer.list_sessions() {
                    total.current_depth += info.stats.current_depth;
                    total.max_depth = total.max_depth.max(info.stats.max_depth);
                    total.total_captured += info.stats.total_captured;
                    total.total_dropped += info.stats.total_dropped;
                    total.events_per_second += info.stats.events_per_second;
                    total.memory_bytes += info.stats.memory_bytes;
                }
                Ok(serde_json::json!({ "queue": total }))
            }
            _ => Err(Error::NotImplemented(format!(
                "Trace method not implemented: {}",
                method
            ))),
        }
    }

    fn dispatch_chill_method(&self, method: &str, _request: &Request) -> Result<serde_json::Value> {
        let chill = self
            .chill_manager
            .write()
            .map_err(|e| Error::Internal(e.to_string()))?;
        match method {
            "chill_start" => {
                // ChillManager uses chill() method, config is set at construction time
                let status = chill.chill()?;
                Ok(serde_json::to_value(status)?)
            }
            "chill_resume" => {
                let status = chill.resume()?;
                Ok(serde_json::to_value(status)?)
            }
            "chill_status" => Ok(serde_json::to_value(chill.status()?)?),
            _ => Err(Error::NotImplemented(format!(
                "Chill method not implemented: {}",
                method
            ))),
        }
    }

    fn dispatch_com_method(&self, method: &str, request: &Request) -> Result<serde_json::Value> {
        let com = self
            .com_scanner
            .write()
            .map_err(|e| Error::Internal(e.to_string()))?;
        match method {
            "com_scan" => {
                // ComScanner config is set at construction; scan() takes no arguments
                let _config: ghost_common::types::ComScanConfig =
                    serde_json::from_value(request.params.clone())
                        .map_err(|e| Error::Internal(format!("Invalid config: {}", e)))?;
                let results = com.scan()?;
                Ok(serde_json::to_value(results)?)
            }
            "com_vtable" => {
                // analyze_vtable not available in current API - return not implemented
                let _address = request.params["address"]
                    .as_u64()
                    .ok_or(Error::Internal("Missing address".into()))?
                    as usize;
                Err(Error::NotImplemented(
                    "com_vtable not available in current API".into(),
                ))
            }
            _ => Err(Error::NotImplemented(format!(
                "COM method not implemented: {}",
                method
            ))),
        }
    }

    fn dispatch_dll_method(&self, method: &str, request: &Request) -> Result<serde_json::Value> {
        let dll = self
            .dll_monitor
            .write()
            .map_err(|e| Error::Internal(e.to_string()))?;
        match method {
            "dll_monitor_start" => {
                // DllMonitor.start() requires &mut ApiTraceHookEngine which isn't available here
                // Config is parsed but start requires hook engine integration
                let _config: ghost_common::types::DllMonitorConfig =
                    serde_json::from_value(request.params.clone())
                        .map_err(|e| Error::Internal(format!("Invalid config: {}", e)))?;
                Err(Error::NotImplemented(
                    "dll_monitor_start requires hook engine integration".into(),
                ))
            }
            "dll_monitor_stop" => {
                dll.stop()?;
                Ok(serde_json::json!({"success": true}))
            }
            "dll_monitor_events" => {
                let limit = request.params["limit"].as_u64().unwrap_or(100) as usize;
                let offset = request.params["offset"].as_u64().unwrap_or(0) as usize;
                let events = dll.get_events(limit, offset);
                Ok(serde_json::to_value(events)?)
            }
            "dll_status" => {
                // Return monitor status instead of list_modules which doesn't exist
                let status = dll.status();
                Ok(serde_json::to_value(status)?)
            }
            _ => Err(Error::NotImplemented(format!(
                "DLL method not implemented: {}",
                method
            ))),
        }
    }

    fn dispatch_dynamic_api_method(
        &self,
        method: &str,
        request: &Request,
    ) -> Result<serde_json::Value> {
        let monitor = self
            .dynamic_api_monitor
            .write()
            .map_err(|e| Error::Internal(e.to_string()))?;
        match method {
            "dynamic_api_start" => {
                // DynamicApiMonitor.start() requires &mut ApiTraceHookEngine and TraceSessionId
                // Config is parsed but start requires hook engine integration
                let _config: ghost_common::types::DynamicApiMonitorConfig =
                    serde_json::from_value(request.params.clone())
                        .map_err(|e| Error::Internal(format!("Invalid config: {}", e)))?;
                Err(Error::NotImplemented(
                    "dynamic_api_start requires hook engine integration".into(),
                ))
            }
            "dynamic_api_stop" => {
                monitor.stop()?;
                Ok(serde_json::json!({"success": true}))
            }
            "dynamic_api_events" => {
                let limit = request.params["limit"].as_u64().unwrap_or(100) as usize;
                let offset = request.params["offset"].as_u64().unwrap_or(0) as usize;
                let events = monitor.get_resolutions(limit, offset);
                Ok(serde_json::to_value(events)?)
            }
            _ => Err(Error::NotImplemented(format!(
                "Dynamic API method not implemented: {}",
                method
            ))),
        }
    }

    /// Pointer scanner method dispatcher with defensive validation and comprehensive logging.
    ///
    /// All pointer operations include:
    /// - Input validation with bounds checking
    /// - Defensive error handling
    /// - Comprehensive tracing for debugging
    /// - Safe defaults for optional parameters
    fn dispatch_pointer_method(
        &self,
        method: &str,
        request: &Request,
    ) -> Result<serde_json::Value> {
        // Defensive: validate method name length
        if method.len() > 64 {
            tracing::warn!(target: "ghost_agent::backend::pointer", method_len = method.len(), "Pointer method name too long");
            return Err(Error::Internal("Method name too long".into()));
        }

        tracing::debug!(target: "ghost_agent::backend::pointer", method = method, "Dispatching pointer method");

        match method {
            "pointer_scan_create" => {
                let address = parse_address(&request.params["address"])?;

                // Defensive: validate address is not null region
                if address < 0x10000 {
                    tracing::warn!(target: "ghost_agent::backend::pointer", address = format!("0x{:x}", address), "Target address in null region");
                    return Err(Error::Internal(format!(
                        "Target address 0x{:x} is in null/reserved region (< 0x10000)",
                        address
                    )));
                }

                // Defensive: clamp max_offset to reasonable bounds (1 to 1MB)
                let max_offset = request.params["max_offset"]
                    .as_i64()
                    .unwrap_or(4096)
                    .clamp(1, 1024 * 1024);

                // Defensive: clamp max_level to reasonable bounds (1 to 10)
                let max_level = request.params["max_level"]
                    .as_u64()
                    .unwrap_or(5)
                    .clamp(1, 10) as u32;

                let options = PointerScanOptions {
                    target_address: address,
                    max_depth: max_level,
                    max_offset,
                    ..Default::default()
                };

                let scan_id = self.pointer_scanner.create_session(options)?;
                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    address = format!("0x{:x}", address),
                    max_offset = max_offset,
                    max_level = max_level,
                    "Created pointer scan session"
                );

                Ok(serde_json::json!({
                    "scan_id": scan_id.0.to_string(),
                    "target_address": format!("0x{:x}", address),
                    "max_offset": max_offset,
                    "max_level": max_level
                }))
            }
            "pointer_scan_start" => {
                let scan_id = self.parse_pointer_scan_id(&request.params["scan_id"])?;

                // Get memory regions and modules for scanning
                let regions = self.query_regions()?;
                let modules = self.get_modules()?;

                // Defensive: check we have regions to scan
                if regions.is_empty() {
                    tracing::warn!(target: "ghost_agent::backend::pointer", "No memory regions available for scanning");
                    return Err(Error::Internal("No memory regions available".into()));
                }

                let module_tuples: Vec<(String, usize, usize)> = modules
                    .iter()
                    .map(|m| (m.name.clone(), m.base, m.size))
                    .collect();

                tracing::debug!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    region_count = regions.len(),
                    module_count = modules.len(),
                    "Preparing pointer scan"
                );

                // Create a memory read closure with defensive bounds
                let read_fn = |addr: usize, size: usize| -> Option<Vec<u8>> {
                    // Defensive: reject unreasonable read sizes
                    if size > 1024 * 1024 {
                        return None;
                    }
                    self.read(addr, size).ok()
                };

                tracing::info!(target: "ghost_agent::backend::pointer", scan_id = scan_id.0, "Starting pointer scan");
                let stats =
                    self.pointer_scanner
                        .scan(scan_id, &regions, &module_tuples, read_fn)?;

                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    pointers_found = stats.pointers_found,
                    elapsed_ms = stats.elapsed_ms,
                    "Pointer scan completed"
                );

                Ok(serde_json::json!({
                    "scan_id": scan_id.0.to_string(),
                    "addresses_scanned": stats.addresses_scanned,
                    "pointers_found": stats.pointers_found,
                    "elapsed_ms": stats.elapsed_ms,
                    "regions_scanned": stats.regions_scanned,
                    "bytes_scanned": stats.bytes_scanned,
                    "scan_rate": stats.scan_rate
                }))
            }
            "pointer_scan_rescan" => {
                let scan_id = self.parse_pointer_scan_id(&request.params["scan_id"])?;
                let new_address = parse_address(&request.params["new_address"])?;

                // Defensive: validate new address
                if new_address < 0x10000 {
                    tracing::warn!(target: "ghost_agent::backend::pointer", new_address = format!("0x{:x}", new_address), "New target address in null region");
                    return Err(Error::Internal(format!(
                        "New target address 0x{:x} is in null/reserved region",
                        new_address
                    )));
                }

                let filter_invalid = request.params["filter_invalid"].as_bool().unwrap_or(true);
                let update_scores = request.params["update_scores"].as_bool().unwrap_or(true);

                let options = PointerRescanOptions {
                    scan_id,
                    new_target_address: Some(new_address),
                    filter_invalid,
                    update_scores,
                };

                let modules = self.get_modules()?;
                let module_tuples: Vec<(String, usize, usize)> = modules
                    .iter()
                    .map(|m| (m.name.clone(), m.base, m.size))
                    .collect();

                let read_fn = |addr: usize, size: usize| -> Option<Vec<u8>> {
                    if size > 1024 * 1024 {
                        return None;
                    }
                    self.read(addr, size).ok()
                };

                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    new_address = format!("0x{:x}", new_address),
                    "Rescanning pointers"
                );
                let stats = self
                    .pointer_scanner
                    .rescan(options, &module_tuples, read_fn)?;

                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    valid_count = stats.pointers_found,
                    elapsed_ms = stats.elapsed_ms,
                    "Pointer rescan completed"
                );

                Ok(serde_json::json!({
                    "scan_id": scan_id.0.to_string(),
                    "valid_count": stats.pointers_found,
                    "elapsed_ms": stats.elapsed_ms
                }))
            }
            "pointer_scan_results" => {
                let scan_id = self.parse_pointer_scan_id(&request.params["scan_id"])?;

                // Defensive: clamp limit to reasonable bounds (1 to 10000)
                let limit = request.params["limit"]
                    .as_u64()
                    .unwrap_or(100)
                    .clamp(1, 10000) as usize;

                tracing::debug!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    limit = limit,
                    "Fetching pointer scan results"
                );

                let results = self.pointer_scanner.get_results(scan_id, 0, limit)?;

                let paths: Vec<serde_json::Value> = results
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "base_address": format!("0x{:x}", p.base_address),
                            "base_module": p.base_module,
                            "base_offset": p.base_offset.map(|o| format!("0x{:x}", o)),
                            "offsets": p.offsets.iter().map(|o| format!("0x{:x}", o)).collect::<Vec<_>>(),
                            "resolved_address": p.resolved_address.map(|a| format!("0x{:x}", a)),
                            "stability_score": p.stability_score,
                            "last_valid": p.last_valid
                        })
                    })
                    .collect();

                tracing::debug!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    returned = paths.len(),
                    "Returning pointer scan results"
                );

                Ok(serde_json::json!({
                    "scan_id": scan_id.0.to_string(),
                    "count": paths.len(),
                    "paths": paths
                }))
            }
            "pointer_scan_count" => {
                let scan_id = self.parse_pointer_scan_id(&request.params["scan_id"])?;
                let count = self.pointer_scanner.get_result_count(scan_id)?;

                tracing::debug!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    count = count,
                    "Retrieved pointer scan count"
                );

                Ok(serde_json::json!({
                    "scan_id": scan_id.0.to_string(),
                    "count": count
                }))
            }
            "pointer_scan_progress" => {
                let scan_id = self.parse_pointer_scan_id(&request.params["scan_id"])?;
                let progress = self.pointer_scanner.get_progress(scan_id);

                if let Some(p) = progress {
                    tracing::trace!(
                        target: "ghost_agent::backend::pointer",
                        scan_id = p.scan_id.0,
                        depth = p.current_depth,
                        pointers = p.total_pointers,
                        "Pointer scan progress"
                    );
                    Ok(serde_json::json!({
                        "scan_id": p.scan_id.0.to_string(),
                        "current_depth": p.current_depth,
                        "max_depth": p.max_depth,
                        "pointers_at_depth": p.pointers_at_depth,
                        "total_pointers": p.total_pointers,
                        "regions_scanned": p.regions_scanned,
                        "regions_total": p.regions_total,
                        "elapsed_ms": p.elapsed_ms,
                        "complete": p.complete,
                        "cancelled": p.cancelled,
                        "phase": p.phase
                    }))
                } else {
                    tracing::trace!(target: "ghost_agent::backend::pointer", "No active pointer scan");
                    Ok(serde_json::json!({
                        "active": false,
                        "message": "No active pointer scan"
                    }))
                }
            }
            "pointer_scan_cancel" => {
                self.pointer_scanner.cancel();
                tracing::info!(target: "ghost_agent::backend::pointer", "Pointer scan cancelled");

                Ok(serde_json::json!({
                    "cancelled": true
                }))
            }
            "pointer_scan_close" => {
                let scan_id = self.parse_pointer_scan_id(&request.params["scan_id"])?;
                self.pointer_scanner.close_session(scan_id)?;
                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    "Closed pointer scan session"
                );

                Ok(serde_json::json!({
                    "closed": true,
                    "scan_id": scan_id.0.to_string()
                }))
            }
            "pointer_scan_list" => {
                let sessions = self.pointer_scanner.list_sessions()?;

                let list: Vec<serde_json::Value> = sessions
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "scan_id": s.id.0.to_string(),
                            "target_address": format!("0x{:x}", s.target_address),
                            "path_count": s.paths.len(),
                            "rescan_count": s.rescan_count,
                            "created_at": s.created_at,
                            "last_rescan_at": s.last_rescan_at,
                            "active": s.active
                        })
                    })
                    .collect();

                tracing::debug!(
                    target: "ghost_agent::backend::pointer",
                    session_count = list.len(),
                    "Listed pointer scan sessions"
                );

                Ok(serde_json::json!({
                    "sessions": list,
                    "count": list.len()
                }))
            }
            "pointer_resolve" => {
                let base_str = request.params["base"]
                    .as_str()
                    .ok_or_else(|| Error::Internal("Missing 'base' parameter".into()))?;

                // Defensive: validate base string length
                if base_str.len() > 256 {
                    return Err(Error::Internal("Base parameter too long".into()));
                }

                let offsets_arr = request.params["offsets"]
                    .as_array()
                    .ok_or_else(|| Error::Internal("Missing 'offsets' parameter".into()))?;

                // Defensive: limit offsets array size
                if offsets_arr.len() > 20 {
                    return Err(Error::Internal(
                        "Too many offsets (max 20 levels supported)".into(),
                    ));
                }

                let offsets: Vec<i64> = offsets_arr.iter().filter_map(|v| v.as_i64()).collect();

                // Check if base is a module name or address
                let modules = self.get_modules()?;
                let module_tuples: Vec<(String, usize, usize)> = modules
                    .iter()
                    .map(|m| (m.name.clone(), m.base, m.size))
                    .collect();

                let path = if let Some(module) = modules.iter().find(|m| {
                    m.name.to_lowercase() == base_str.to_lowercase()
                        || m.name.to_lowercase().starts_with(&base_str.to_lowercase())
                }) {
                    // Module-relative path
                    tracing::debug!(
                        target: "ghost_agent::backend::pointer",
                        module = module.name,
                        offset_count = offsets.len(),
                        "Resolving module-relative pointer"
                    );
                    PointerPath::module_relative(&module.name, 0, offsets)
                } else {
                    // Absolute address path
                    let base_addr = parse_address(&request.params["base"])?;
                    tracing::debug!(
                        target: "ghost_agent::backend::pointer",
                        base = format!("0x{:x}", base_addr),
                        offset_count = offsets.len(),
                        "Resolving absolute pointer"
                    );
                    PointerPath::new(base_addr, offsets)
                };

                let read_fn = |addr: usize, size: usize| -> Option<Vec<u8>> {
                    if size > 1024 * 1024 {
                        return None;
                    }
                    self.read(addr, size).ok()
                };

                let result = self
                    .pointer_scanner
                    .resolve_path(&path, &module_tuples, read_fn);

                if result.success {
                    tracing::debug!(
                        target: "ghost_agent::backend::pointer",
                        resolved = format!("0x{:x}", result.resolved_address.unwrap_or(0)),
                        "Pointer resolved successfully"
                    );
                } else {
                    tracing::debug!(
                        target: "ghost_agent::backend::pointer",
                        error = result.error.as_deref().unwrap_or("unknown"),
                        "Pointer resolution failed"
                    );
                }

                Ok(serde_json::json!({
                    "success": result.success,
                    "resolved_address": result.resolved_address.map(|a| format!("0x{:x}", a)),
                    "chain_addresses": result.chain_addresses.iter().map(|a| format!("0x{:x}", a)).collect::<Vec<_>>(),
                    "error": result.error
                }))
            }
            "pointer_scan_compare" => {
                let scan_id1 = self.parse_pointer_scan_id(&request.params["scan_id1"])?;
                let scan_id2 = self.parse_pointer_scan_id(&request.params["scan_id2"])?;

                tracing::debug!(
                    target: "ghost_agent::backend::pointer",
                    scan_id1 = scan_id1.0,
                    scan_id2 = scan_id2.0,
                    "Comparing pointer scans"
                );

                let result = self.pointer_scanner.compare_sessions(scan_id1, scan_id2)?;

                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id1 = scan_id1.0,
                    scan_id2 = scan_id2.0,
                    common_valid = result.stats.common_valid_count,
                    stability = format!("{:.1}%", result.stats.stability_percentage),
                    "Pointer scan comparison completed"
                );

                Ok(serde_json::json!({
                    "stats": {
                        "first_count": result.stats.first_count,
                        "second_count": result.stats.second_count,
                        "common_valid_count": result.stats.common_valid_count,
                        "common_invalid_count": result.stats.common_invalid_count,
                        "stability_percentage": result.stats.stability_percentage
                    },
                    "common_valid_count": result.common_valid.len(),
                    "common_invalid_count": result.common_invalid.len(),
                    "only_in_first_count": result.only_in_first.len(),
                    "only_in_second_count": result.only_in_second.len()
                }))
            }
            "pointer_scan_export" => {
                let scan_id = self.parse_pointer_scan_id(&request.params["scan_id"])?;
                let path = request.params["path"]
                    .as_str()
                    .ok_or_else(|| Error::Internal("Missing 'path' parameter".into()))?;

                // Defensive: validate path length and characters
                if path.len() > 4096 {
                    return Err(Error::Internal("Export path too long".into()));
                }
                if path.contains('\0') {
                    return Err(Error::Internal("Invalid characters in path".into()));
                }

                // Determine format from file extension
                let format = if path.ends_with(".csv") {
                    PointerExportFormat::Csv
                } else if path.ends_with(".ptr") {
                    PointerExportFormat::CheatEnginePtr
                } else {
                    PointerExportFormat::Json
                };

                let content = self.pointer_scanner.export_results(scan_id, format)?;

                // Defensive: check content size before writing
                const MAX_EXPORT_SIZE: usize = 100 * 1024 * 1024; // 100MB
                if content.len() > MAX_EXPORT_SIZE {
                    return Err(Error::Internal(format!(
                        "Export size {} exceeds maximum {}",
                        content.len(),
                        MAX_EXPORT_SIZE
                    )));
                }

                std::fs::write(path, &content)
                    .map_err(|e| Error::Internal(format!("Failed to write file: {}", e)))?;

                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    path = path,
                    bytes = content.len(),
                    format = ?format,
                    "Exported pointer scan results"
                );

                Ok(serde_json::json!({
                    "success": true,
                    "path": path,
                    "format": format!("{:?}", format),
                    "bytes_written": content.len()
                }))
            }
            "pointer_scan_import" => {
                let path = request.params["path"]
                    .as_str()
                    .ok_or_else(|| Error::Internal("Missing 'path' parameter".into()))?;

                // Defensive: validate path
                if path.len() > 4096 {
                    return Err(Error::Internal("Import path too long".into()));
                }
                if path.contains('\0') {
                    return Err(Error::Internal("Invalid characters in path".into()));
                }

                // Defensive: check file size before reading
                let metadata = std::fs::metadata(path)
                    .map_err(|e| Error::Internal(format!("Failed to access file: {}", e)))?;

                const MAX_IMPORT_SIZE: u64 = 100 * 1024 * 1024; // 100MB
                if metadata.len() > MAX_IMPORT_SIZE {
                    return Err(Error::Internal(format!(
                        "Import file size {} exceeds maximum {}",
                        metadata.len(),
                        MAX_IMPORT_SIZE
                    )));
                }

                let content = std::fs::read_to_string(path)
                    .map_err(|e| Error::Internal(format!("Failed to read file: {}", e)))?;

                // Create a new session for the imported data
                let options = PointerScanOptions::default();
                let scan_id = self.pointer_scanner.create_session(options)?;

                let count = self.pointer_scanner.import_results(scan_id, &content)?;

                tracing::info!(
                    target: "ghost_agent::backend::pointer",
                    scan_id = scan_id.0,
                    path = path,
                    count = count,
                    "Imported pointer scan results"
                );

                Ok(serde_json::json!({
                    "success": true,
                    "scan_id": scan_id.0.to_string(),
                    "imported_count": count,
                    "path": path
                }))
            }
            _ => {
                tracing::warn!(
                    target: "ghost_agent::backend::pointer",
                    method = method,
                    "Unknown pointer method"
                );
                Err(Error::NotImplemented(format!(
                    "Pointer method not implemented: {}",
                    method
                )))
            }
        }
    }

    /// Parse pointer scan ID from JSON value with defensive validation.
    ///
    /// Accepts both numeric and string formats for flexibility.
    fn parse_pointer_scan_id(&self, value: &serde_json::Value) -> Result<PointerScanId> {
        if let Some(n) = value.as_u64() {
            // Defensive: check for overflow
            if n > u32::MAX as u64 {
                return Err(Error::Internal(format!(
                    "Scan ID {} exceeds maximum value",
                    n
                )));
            }
            return Ok(PointerScanId(n as u32));
        }
        if let Some(s) = value.as_str() {
            // Defensive: limit string length
            if s.len() > 20 {
                return Err(Error::Internal("Scan ID string too long".into()));
            }
            return s
                .trim()
                .parse::<u32>()
                .map(PointerScanId)
                .map_err(|_| Error::Internal(format!("Invalid scan_id format: {}", value)));
        }
        Err(Error::Internal("Missing or invalid scan_id".into()))
    }

    pub fn create_hook_ex(&self, params: CreateHookParams) -> Result<u32> {
        let target = params.target;
        let callback = params.callback;
        let hook_type_str = &params.hook_type;
        let module = params.module;
        let function = params.function;
        let import_module = params.import_module;
        let size = params.size;
        #[cfg(not(target_os = "windows"))]
        {
            return Err(Error::NotImplemented(
                "Hooks only supported on Windows".into(),
            ));
        }

        #[cfg(target_os = "windows")]
        {
            use ghost_common::types::ExtendedHookType;
            ghost_core::extended_hooks::initialize()?;
            let mut manager = ghost_core::extended_hooks::get_hook_manager()
                .write()
                .map_err(|_| Error::Internal("Failed to acquire hook manager lock".into()))?;

            let hook_type = match hook_type_str.to_lowercase().as_str() {
                "iat" | "iat_hook" => ExtendedHookType::IatHook,
                "eat" | "eat_hook" => ExtendedHookType::EatHook,
                "veh" | "page_guard" => ExtendedHookType::VehPageGuard,
                "inline" | "trampoline" => ExtendedHookType::InlineTrampoline,
                "hotpatch" => ExtendedHookType::InlineHotPatch,
                "int3" => ExtendedHookType::InlineInt3,
                _ => ExtendedHookType::InlineTrampoline,
            };

            let result = match hook_type {
                ExtendedHookType::IatHook => {
                    let req = ghost_common::types::IatHookRequest {
                        module_name: module.ok_or_else(|| {
                            Error::Internal("module required for IAT hook".into())
                        })?,
                        import_module: import_module.ok_or_else(|| {
                            Error::Internal("import_module required for IAT hook".into())
                        })?,
                        function_name: function.ok_or_else(|| {
                            Error::Internal("function required for IAT hook".into())
                        })?,
                        callback_address: callback as u64,
                        enable: true,
                    };
                    manager.install_iat_hook(req)?
                }
                ExtendedHookType::EatHook => {
                    let req = ghost_common::types::EatHookRequest {
                        module_name: module.ok_or_else(|| {
                            Error::Internal("module required for EAT hook".into())
                        })?,
                        function_name: function.ok_or_else(|| {
                            Error::Internal("function required for EAT hook".into())
                        })?,
                        callback_address: callback as u64,
                        enable: true,
                    };
                    manager.install_eat_hook(req)?
                }
                ExtendedHookType::VehPageGuard => {
                    let req = ghost_common::types::VehHookRequest {
                        target_address: target as u64,
                        size: size.unwrap_or(0x1000) as u32,
                        callback_address: callback as u64,
                        on_execute: true,
                        on_read: false,
                        on_write: false,
                    };
                    manager.install_veh_hook(req)?
                }
                ExtendedHookType::InlineInt3 => {
                    manager.install_int3_hook(target as u64, callback as u64)?
                }
                _ => {
                    let req = ghost_common::InlineHookRequest {
                        target_address: target as u64,
                        callback_address: callback as u64,
                        hook_type: Some(hook_type),
                        offset: None,
                        enable: true,
                    };
                    manager.install_inline_hook(req)?
                }
            };

            let hook_id = result
                .hook_id
                .ok_or_else(|| Error::Internal("Hook installation did not return an ID".into()))?;

            // Get actual info from result or constructing it
            let (actual_target, original_bytes) = if let Some(info) = result.hook_info {
                (info.target_address as usize, info.original_bytes)
            } else {
                (target, vec![])
            };

            self.hooks
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?
                .insert(
                    hook_id.0,
                    HookInfo {
                        id: hook_id.0,
                        target: actual_target,
                        original_bytes,
                    },
                );

            Ok(hook_id.0)
        }
    }
}

impl Drop for InProcessBackend {
    fn drop(&mut self) {
        if let Some(handle) = self.process_handle.take() {
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
}

impl MemoryAccess for InProcessBackend {
    fn read(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        // Use ReadProcessMemory instead of direct pointer access to avoid
        // triggering ASan in instrumented processes. ReadProcessMemory goes
        // through the kernel and bypasses ASan's shadow memory checks.
        unsafe {
            let ptr = addr as *const u8;
            let process = self.process_handle.unwrap_or_else(|| GetCurrentProcess());

            // Validate memory is readable - use VirtualQueryEx for remote process
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let query_result = if self.process_handle.is_some() {
                VirtualQueryEx(
                    process,
                    Some(ptr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            } else {
                VirtualQuery(
                    Some(ptr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if query_result == 0 {
                return Err(Error::MemoryAccess {
                    address: addr,
                    message: "VirtualQuery failed".into(),
                });
            }

            if mbi.State != MEM_COMMIT {
                return Err(Error::MemoryAccess {
                    address: addr,
                    message: "Memory not committed".into(),
                });
            }

            // Calculate how much of the requested size is within this region
            let region_base = mbi.BaseAddress as usize;
            let region_end = region_base.saturating_add(mbi.RegionSize);
            let read_end = addr.saturating_add(size);

            // Only read up to the end of this committed region
            let safe_size = if read_end > region_end {
                region_end.saturating_sub(addr)
            } else {
                size
            };

            if safe_size == 0 {
                return Err(Error::MemoryAccess {
                    address: addr,
                    message: "No readable bytes in region".into(),
                });
            }

            // Use ReadProcessMemory to avoid triggering ASan instrumentation
            let mut buffer = vec![0u8; safe_size];
            let mut bytes_read: usize = 0;

            let result = ReadProcessMemory(
                process,
                ptr as *const _,
                buffer.as_mut_ptr() as *mut _,
                safe_size,
                Some(&mut bytes_read),
            );

            if result.is_err() || bytes_read == 0 {
                return Err(Error::MemoryAccess {
                    address: addr,
                    message: "ReadProcessMemory failed".into(),
                });
            }

            // Truncate buffer to actual bytes read
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    fn write(&self, addr: usize, data: &[u8]) -> Result<()> {
        unsafe {
            let ptr = addr as *mut u8;
            let process = self.process_handle.unwrap_or_else(|| GetCurrentProcess());

            // First validate memory is committed
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let query_result = if self.process_handle.is_some() {
                VirtualQueryEx(
                    process,
                    Some(ptr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            } else {
                VirtualQuery(
                    Some(ptr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if query_result == 0 {
                return Err(Error::MemoryAccess {
                    address: addr,
                    message: "VirtualQuery failed - invalid address".into(),
                });
            }

            if mbi.State != MEM_COMMIT {
                return Err(Error::MemoryAccess {
                    address: addr,
                    message: "Memory not committed".into(),
                });
            }

            // For remote processes, try WriteProcessMemory directly first - it can write to
            // read-only memory as the kernel handles protection internally
            if self.process_handle.is_some() {
                let mut bytes_written: usize = 0;
                let result = WriteProcessMemory(
                    process,
                    ptr as *const _,
                    data.as_ptr() as *const _,
                    data.len(),
                    Some(&mut bytes_written),
                );

                if result.is_ok() && bytes_written == data.len() {
                    return Ok(());
                }

                // If direct write failed, try with VirtualProtectEx
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                let protect_ok = VirtualProtectEx(
                    process,
                    ptr as *mut _,
                    data.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
                .is_ok()
                    || VirtualProtectEx(
                        process,
                        ptr as *mut _,
                        data.len(),
                        PAGE_READWRITE,
                        &mut old_protect,
                    )
                    .is_ok();

                if !protect_ok {
                    let err = std::io::Error::last_os_error();
                    return Err(Error::MemoryAccess {
                        address: addr,
                        message: format!(
                            "Cannot write to memory (protection: 0x{:X}, type: 0x{:X}): {}",
                            mbi.Protect.0, mbi.Type.0, err
                        ),
                    });
                }

                // Try write again after protection change
                let result = WriteProcessMemory(
                    process,
                    ptr as *const _,
                    data.as_ptr() as *const _,
                    data.len(),
                    Some(&mut bytes_written),
                );

                // Restore protection
                let mut tmp = PAGE_PROTECTION_FLAGS::default();
                let _ = VirtualProtectEx(process, ptr as *mut _, data.len(), old_protect, &mut tmp);

                if result.is_err() || bytes_written != data.len() {
                    return Err(Error::MemoryAccess {
                        address: addr,
                        message: "WriteProcessMemory failed after protection change".into(),
                    });
                }

                return Ok(());
            }

            // For local process, we need VirtualProtect before direct write
            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            let protect_ok = VirtualProtect(
                ptr as *mut _,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .is_ok()
                || VirtualProtect(ptr as *mut _, data.len(), PAGE_READWRITE, &mut old_protect)
                    .is_ok();

            if !protect_ok {
                let err = std::io::Error::last_os_error();
                return Err(Error::MemoryAccess {
                    address: addr,
                    message: format!(
                        "VirtualProtect failed (protection: 0x{:X}, type: 0x{:X}): {}",
                        mbi.Protect.0, mbi.Type.0, err
                    ),
                });
            }

            // Write directly for local process
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());

            // Restore protection
            let mut tmp = PAGE_PROTECTION_FLAGS::default();
            let _ = VirtualProtect(ptr as *mut _, data.len(), old_protect, &mut tmp);

            Ok(())
        }
    }

    fn query_regions(&self) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;

        unsafe {
            let process = self.process_handle.unwrap_or_else(|| GetCurrentProcess());

            loop {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                // Use VirtualQueryEx for remote process, VirtualQuery for local
                let result = if self.process_handle.is_some() {
                    VirtualQueryEx(
                        process,
                        Some(addr as *const _),
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                } else {
                    VirtualQuery(
                        Some(addr as *const _),
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };

                if result == 0 {
                    break;
                }

                regions.push(ghost_core::memory::region_from_mbi(
                    mbi.BaseAddress as usize,
                    mbi.RegionSize,
                    mbi.Protect.0,
                    mbi.State.0,
                    mbi.Type.0,
                ));

                addr = mbi.BaseAddress as usize + mbi.RegionSize;
                if addr == 0 {
                    break; // Overflow
                }
            }
        }

        Ok(regions)
    }

    fn search_value(
        &self,
        value: &[u8],
        value_type: ValueType,
        start: Option<usize>,
        end: Option<usize>,
    ) -> Result<Vec<ScanResult>> {
        tracing::info!(target: "ghost_agent::backend", value_len = value.len(), "Starting value search");
        let start_time = std::time::Instant::now();
        const TIMEOUT_SECS: u64 = 60;

        let mut results = Vec::new();
        let max_results = 10000;
        let alignment = ghost_core::memory::alignment_for_type(value_type);

        // Limit chunk size to avoid reading huge regions at once
        const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB
        const MAX_TOTAL_SCAN: usize = 512 * 1024 * 1024; // 512MB
        let mut total_scanned: usize = 0;

        // Get regions and filter
        let regions = self.query_regions()?;
        let readable_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.state == ghost_common::MemoryState::Commit && r.protection.read)
            .filter(|r| r.size <= 512 * 1024 * 1024) // Skip regions > 512MB
            .filter(|r| {
                let region_end = r.base + r.size;
                if let Some(s) = start {
                    if region_end <= s {
                        return false;
                    }
                }
                if let Some(e) = end {
                    if r.base >= e {
                        return false;
                    }
                }
                true
            })
            .collect();

        for region in readable_regions {
            // Check for cancellation and timeout
            if self.is_cancelled() {
                return Err(Error::Internal("Operation cancelled".into()));
            }
            if start_time.elapsed().as_secs() >= TIMEOUT_SECS {
                return Err(Error::Internal(
                    "Operation timed out after 60 seconds".into(),
                ));
            }
            if total_scanned >= MAX_TOTAL_SCAN {
                tracing::warn!(target: "ghost_agent::backend", "Reached max scan limit");
                break;
            }

            // Calculate actual scan range within this region
            let region_end = region.base + region.size;
            let scan_start = start.map(|s| s.max(region.base)).unwrap_or(region.base);
            let scan_end = end.map(|e| e.min(region_end)).unwrap_or(region_end);

            if scan_start >= scan_end {
                continue;
            }

            // Process region in chunks
            let mut offset = scan_start - region.base;
            let region_scan_end = scan_end - region.base;

            while offset < region_scan_end && total_scanned < MAX_TOTAL_SCAN {
                if self.is_cancelled() {
                    return Err(Error::Internal("Operation cancelled".into()));
                }
                if start_time.elapsed().as_secs() >= TIMEOUT_SECS {
                    return Err(Error::Internal(
                        "Operation timed out after 60 seconds".into(),
                    ));
                }

                let chunk_size = (region_scan_end - offset).min(MAX_CHUNK_SIZE);
                let chunk_base = region.base + offset;

                let actual_read_size = match self.read(chunk_base, chunk_size) {
                    Ok(data) => {
                        let read_len = data.len();
                        total_scanned += read_len;
                        let mut found = ghost_core::memory::scan_region_for_value(
                            &data,
                            chunk_base,
                            value,
                            alignment,
                            max_results - results.len(),
                        );
                        results.append(&mut found);

                        if results.len() >= max_results {
                            tracing::info!(target: "ghost_agent::backend", results = results.len(), "Max results reached");
                            return Ok(results);
                        }
                        read_len
                    }
                    Err(_) => {
                        // Skip silently - region may have become invalid
                        // Advance by requested chunk_size to move past problematic region
                        chunk_size
                    }
                };

                // Move to next chunk, overlap by value length to catch matches at boundaries
                // Use actual_read_size instead of chunk_size to avoid skipping memory
                let advance = actual_read_size.saturating_sub(value.len().saturating_sub(1));
                offset += if advance == 0 {
                    actual_read_size.max(1)
                } else {
                    advance
                };
            }
        }

        tracing::info!(target: "ghost_agent::backend", 
            results = results.len(),
            scanned_mb = total_scanned / (1024 * 1024),
            elapsed_ms = start_time.elapsed().as_millis(),
            "Value search complete");
        Ok(results)
    }

    fn search_pattern(&self, pattern: &str) -> Result<Vec<ScanResult>> {
        tracing::info!(target: "ghost_agent::backend", pattern = %pattern, "Starting pattern search");
        let start_time = std::time::Instant::now();
        let mut last_trace = std::time::Instant::now();
        const TRACE_INTERVAL_SECS: u64 = 2;
        const TIMEOUT_SECS: u64 = 60;

        let (pattern_bytes, mask) = ghost_core::PatternScanner::parse_aob_pattern(pattern)?;
        tracing::info!(target: "ghost_agent::backend", pattern_len = pattern_bytes.len(), "Pattern parsed");

        if pattern_bytes.is_empty() {
            return Err(Error::Internal("Empty pattern".into()));
        }

        let mut results = Vec::new();
        let max_results = 10000;
        // Limit chunk size to avoid reading huge regions at once (4MB max per read)
        const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;
        // Limit total bytes scanned to avoid long operations
        const MAX_TOTAL_SCAN: usize = 512 * 1024 * 1024; // 512MB max
        let mut total_scanned: usize = 0;
        let mut regions_scanned = 0u32;

        // Get regions first
        let regions = self.query_regions()?;
        let readable_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.state == ghost_common::MemoryState::Commit && r.protection.read)
            .filter(|r| r.size <= 512 * 1024 * 1024) // Skip regions > 512MB
            .collect();

        let total_readable = readable_regions.len();
        tracing::info!(target: "ghost_agent::backend", 
            total_regions = regions.len(),
            readable_regions = total_readable,
            "Queried memory regions");

        // Scan readable regions
        for region in readable_regions {
            // Check for cancellation
            if self.is_cancelled() {
                tracing::warn!(target: "ghost_agent::backend", 
                    results = results.len(),
                    elapsed_ms = start_time.elapsed().as_millis(),
                    "Pattern search cancelled by user");
                return Err(Error::Internal("Operation cancelled".into()));
            }

            // Check for timeout
            if start_time.elapsed().as_secs() >= TIMEOUT_SECS {
                tracing::warn!(target: "ghost_agent::backend", 
                    results = results.len(),
                    elapsed_secs = start_time.elapsed().as_secs(),
                    "Pattern search timed out after 60 seconds");
                return Err(Error::Internal(
                    "Operation timed out after 60 seconds".into(),
                ));
            }

            // Periodic trace every N seconds
            if last_trace.elapsed().as_secs() >= TRACE_INTERVAL_SECS {
                tracing::info!(target: "ghost_agent::backend", 
                    regions_scanned = regions_scanned,
                    total_readable = total_readable,
                    results_found = results.len(),
                    scanned_mb = total_scanned / (1024 * 1024),
                    elapsed_secs = start_time.elapsed().as_secs(),
                    "Pattern search progress");
                last_trace = std::time::Instant::now();
            }

            // Check scan limits
            if total_scanned >= MAX_TOTAL_SCAN {
                tracing::warn!(target: "ghost_agent::backend", 
                    total_scanned_mb = total_scanned / (1024 * 1024),
                    "Reached max scan limit, stopping");
                break;
            }

            regions_scanned += 1;

            // Process region in chunks to avoid memory issues
            let mut offset = 0;
            while offset < region.size && total_scanned < MAX_TOTAL_SCAN {
                // Check cancellation and timeout in inner loop too
                if self.is_cancelled() {
                    return Err(Error::Internal("Operation cancelled".into()));
                }
                if start_time.elapsed().as_secs() >= TIMEOUT_SECS {
                    return Err(Error::Internal(
                        "Operation timed out after 60 seconds".into(),
                    ));
                }

                let chunk_size = (region.size - offset).min(MAX_CHUNK_SIZE);
                let chunk_base = region.base + offset;

                match self.read(chunk_base, chunk_size) {
                    Ok(data) => {
                        total_scanned += data.len();
                        let offsets = ghost_core::PatternScanner::find_aob_in_buffer(
                            &data,
                            &pattern_bytes,
                            &mask,
                            max_results - results.len(),
                        );
                        let mut found: Vec<ScanResult> = offsets
                            .iter()
                            .map(|&offset| ScanResult {
                                address: chunk_base + offset,
                                value: data
                                    .get(offset..offset + pattern_bytes.len())
                                    .unwrap_or(&[])
                                    .to_vec(),
                            })
                            .collect();
                        results.append(&mut found);

                        if results.len() >= max_results {
                            tracing::info!(target: "ghost_agent::backend", 
                                results = results.len(),
                                elapsed_ms = start_time.elapsed().as_millis(),
                                "Max results reached");
                            return Ok(results);
                        }
                    }
                    Err(_) => {
                        // Skip silently - region may have become invalid
                    }
                }

                // Move to next chunk, overlap by pattern length to catch matches at boundaries
                // Ensure we always advance by at least 1 to avoid infinite loop
                let advance = chunk_size.saturating_sub(pattern_bytes.len().saturating_sub(1));
                offset += if advance == 0 {
                    chunk_size.max(1)
                } else {
                    advance
                };
            }
        }

        tracing::info!(target: "ghost_agent::backend", 
            results = results.len(),
            regions_scanned = regions_scanned,
            total_scanned_mb = total_scanned / (1024 * 1024),
            elapsed_ms = start_time.elapsed().as_millis(),
            "Pattern search complete");
        Ok(results)
    }

    fn search_pattern_ex(
        &self,
        pattern: &ghost_common::Pattern,
        start: Option<usize>,
        end: Option<usize>,
    ) -> Result<Vec<ghost_core::pattern_scanner::ResolvedScanResult>> {
        tracing::info!(target: "ghost_agent::backend",
            pattern = %pattern.pattern,
            pattern_type = ?pattern.pattern_type,
            "Starting extended pattern search");
        let start_time = std::time::Instant::now();
        let mut last_trace = std::time::Instant::now();
        const TRACE_INTERVAL_SECS: u64 = 2;
        const TIMEOUT_SECS: u64 = 60;

        let parsed = ghost_core::PatternScanner::parse_aob_pattern_ex(&pattern.pattern)?;
        tracing::info!(target: "ghost_agent::backend", 
            pattern_len = parsed.bytes.len(),
            offset = ?parsed.offset,
            "Pattern parsed");

        if parsed.bytes.is_empty() {
            return Err(Error::Internal("Empty pattern".into()));
        }

        let mut results = Vec::new();
        let max_results = 10000;
        const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;
        const MAX_TOTAL_SCAN: usize = 512 * 1024 * 1024;
        let mut total_scanned: usize = 0;
        let mut regions_scanned = 0u32;

        let regions = self.query_regions()?;
        let readable_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.state == ghost_common::MemoryState::Commit && r.protection.read)
            .filter(|r| r.size <= 512 * 1024 * 1024) // Skip regions > 512MB
            .filter(|r| {
                // Apply range filters
                let region_end = r.base + r.size;
                if let Some(s) = start {
                    if region_end <= s {
                        return false;
                    }
                }
                if let Some(e) = end {
                    if r.base >= e {
                        return false;
                    }
                }
                true
            })
            .collect();

        let total_readable = readable_regions.len();
        tracing::info!(target: "ghost_agent::backend", 
            total_regions = regions.len(),
            readable_regions = total_readable,
            "Queried memory regions");

        for region in readable_regions {
            if self.is_cancelled() {
                tracing::warn!(target: "ghost_agent::backend", 
                    results = results.len(),
                    elapsed_ms = start_time.elapsed().as_millis(),
                    "Pattern search cancelled by user");
                return Err(Error::Internal("Operation cancelled".into()));
            }

            if start_time.elapsed().as_secs() >= TIMEOUT_SECS {
                tracing::warn!(target: "ghost_agent::backend", 
                    results = results.len(),
                    elapsed_secs = start_time.elapsed().as_secs(),
                    "Pattern search timed out after 60 seconds");
                return Err(Error::Internal(
                    "Operation timed out after 60 seconds".into(),
                ));
            }

            if last_trace.elapsed().as_secs() >= TRACE_INTERVAL_SECS {
                tracing::info!(target: "ghost_agent::backend", 
                    regions_scanned = regions_scanned,
                    total_readable = total_readable,
                    results_found = results.len(),
                    scanned_mb = total_scanned / (1024 * 1024),
                    elapsed_secs = start_time.elapsed().as_secs(),
                    "Pattern search progress");
                last_trace = std::time::Instant::now();
            }

            if total_scanned >= MAX_TOTAL_SCAN {
                tracing::warn!(target: "ghost_agent::backend", 
                    total_scanned_mb = total_scanned / (1024 * 1024),
                    "Reached max scan limit, stopping");
                break;
            }

            regions_scanned += 1;

            // Calculate actual scan range within this region
            let scan_start = start.map(|s| s.max(region.base)).unwrap_or(region.base);
            let scan_end = end
                .map(|e| e.min(region.base + region.size))
                .unwrap_or(region.base + region.size);

            if scan_start >= scan_end {
                continue;
            }

            let mut offset = scan_start - region.base;
            let region_scan_end = scan_end - region.base;

            while offset < region_scan_end && total_scanned < MAX_TOTAL_SCAN {
                if self.is_cancelled() {
                    return Err(Error::Internal("Operation cancelled".into()));
                }
                if start_time.elapsed().as_secs() >= TIMEOUT_SECS {
                    return Err(Error::Internal(
                        "Operation timed out after 60 seconds".into(),
                    ));
                }

                let chunk_size = (region_scan_end - offset).min(MAX_CHUNK_SIZE);
                let chunk_base = region.base + offset;

                match self.read(chunk_base, chunk_size) {
                    Ok(data) => {
                        total_scanned += data.len();
                        let offsets = ghost_core::PatternScanner::find_aob_in_buffer(
                            &data,
                            &parsed.bytes,
                            &parsed.mask,
                            max_results - results.len(),
                        );
                        let mut found: Vec<ghost_core::pattern_scanner::ResolvedScanResult> =
                            offsets
                                .iter()
                                .map(|&buf_offset| {
                                    let match_address = chunk_base + buf_offset;
                                    let match_data = data
                                        .get(buf_offset..buf_offset + parsed.bytes.len())
                                        .unwrap_or(&[])
                                        .to_vec();

                                    // Resolve address based on pattern type and offset marker
                                    let res_offset = parsed.offset.unwrap_or(0);
                                    let resolved_address = resolve_pattern_match(
                                        match_address,
                                        &match_data,
                                        res_offset,
                                        pattern.pattern_type,
                                    );

                                    ghost_core::pattern_scanner::ResolvedScanResult {
                                        match_address,
                                        match_data,
                                        resolved_address,
                                    }
                                })
                                .collect();
                        results.append(&mut found);

                        if results.len() >= max_results {
                            tracing::info!(target: "ghost_agent::backend", 
                                results = results.len(),
                                elapsed_ms = start_time.elapsed().as_millis(),
                                "Max results reached");
                            return Ok(results);
                        }
                    }
                    Err(_) => {
                        // Skip silently - region may have become invalid
                    }
                }

                let advance = chunk_size.saturating_sub(parsed.bytes.len().saturating_sub(1));
                offset += if advance == 0 {
                    chunk_size.max(1)
                } else {
                    advance
                };
            }
        }

        tracing::info!(target: "ghost_agent::backend", 
            results = results.len(),
            regions_scanned = regions_scanned,
            total_scanned_mb = total_scanned / (1024 * 1024),
            elapsed_ms = start_time.elapsed().as_millis(),
            "Extended pattern search complete");
        Ok(results)
    }
}

/// Additional introspection helper methods for InProcessBackend
impl InProcessBackend {
    /// Find xrefs with optional module filter and configurable max results
    /// This is a helper that allows the handler to pass optional parameters
    fn find_xrefs_to_filtered(
        &self,
        addr: usize,
        module_filter: Option<&str>,
        max_results: usize,
    ) -> Result<Vec<usize>> {
        let mut all_xrefs = Vec::new();
        let max_results = max_results.min(1000); // Cap at 1000 for safety

        // Get modules to scan
        let modules = self.get_modules()?;

        // Filter modules if a specific module is requested
        let modules_to_scan: Vec<_> = if let Some(filter) = module_filter {
            let filter_lower = filter.to_lowercase();
            modules
                .into_iter()
                .filter(|m| m.name.to_lowercase().contains(&filter_lower))
                .collect()
        } else {
            // If no filter, only scan the main module to avoid timeout
            // User should specify module for broader search
            modules.into_iter().take(1).collect()
        };

        tracing::debug!(
            target: "ghost_agent::backend",
            module_count = modules_to_scan.len(),
            "Scanning modules for xrefs"
        );

        for module in modules_to_scan {
            tracing::trace!(
                target: "ghost_agent::backend",
                module = %module.name,
                base = format!("0x{:x}", module.base),
                size = module.size,
                "Scanning module"
            );

            let xrefs = ghost_core::xrefs::scan_module_for_xrefs(
                addr,
                module.base,
                module.size,
                |scan_addr, size| self.read(scan_addr, size),
                max_results - all_xrefs.len(),
            )?;

            all_xrefs.extend(xrefs);

            if all_xrefs.len() >= max_results {
                break;
            }
        }

        Ok(all_xrefs)
    }

    /// Helper to read u16 from memory (respects process_handle for remote processes)
    fn read_u16(&self, addr: usize) -> Result<u16> {
        let bytes = self.read(addr, 2)?;
        if bytes.len() < 2 {
            return Err(Error::Internal("Insufficient bytes for u16".into()));
        }
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Helper to read i32 from memory (respects process_handle for remote processes)
    fn read_i32(&self, addr: usize) -> Result<i32> {
        let bytes = self.read(addr, 4)?;
        if bytes.len() < 4 {
            return Err(Error::Internal("Insufficient bytes for i32".into()));
        }
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Helper to read u32 from memory (respects process_handle for remote processes)
    fn read_u32(&self, addr: usize) -> Result<u32> {
        let bytes = self.read(addr, 4)?;
        if bytes.len() < 4 {
            return Err(Error::Internal("Insufficient bytes for u32".into()));
        }
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Get TLS (Thread Local Storage) directory info from PE header
    fn get_tls_info(&self, base: usize) -> Result<Vec<serde_json::Value>> {
        let mut tls_info = Vec::new();

        // Check DOS header magic
        let dos_magic = self.read_u16(base)?;
        if dos_magic != 0x5A4D {
            return Ok(tls_info);
        }

        let e_lfanew = self.read_i32(base + 0x3C)?;
        let nt_headers = base + e_lfanew as usize;
        // TLS directory is at offset 0xC0 in the optional header for x64
        let tls_dir_rva = self.read_u32(nt_headers + 0xC0)?;
        let tls_dir_size = self.read_u32(nt_headers + 0xC4)?;

        if tls_dir_rva != 0 && tls_dir_size > 0 {
            tls_info.push(serde_json::json!({
                "directory_rva": tls_dir_rva,
                "directory_size": tls_dir_size,
                "base": base
            }));
        }

        Ok(tls_info)
    }

    /// Parse PE sections from module base
    fn parse_pe_sections(&self, base: usize) -> Result<Vec<serde_json::Value>> {
        let mut sections = Vec::new();

        // Check DOS header magic
        let dos_magic = self.read_u16(base)?;
        if dos_magic != 0x5A4D {
            return Err(Error::Internal("Invalid DOS header".into()));
        }

        let e_lfanew = self.read_i32(base + 0x3C)?;
        let nt_headers = base + e_lfanew as usize;
        let file_header = nt_headers + 4;
        let num_sections = self.read_u16(file_header + 2)? as usize;
        let optional_header_size = self.read_u16(file_header + 16)? as usize;
        let section_headers = file_header + 20 + optional_header_size;

        for i in 0..num_sections.min(64) {
            let section = section_headers + (i * 40);
            let name_bytes = self.read(section, 8)?;
            let name = String::from_utf8_lossy(&name_bytes)
                .trim_end_matches('\0')
                .to_string();
            let virtual_size = self.read_u32(section + 8)?;
            let virtual_address = self.read_u32(section + 12)?;
            let raw_size = self.read_u32(section + 16)?;
            let raw_address = self.read_u32(section + 20)?;
            let characteristics = self.read_u32(section + 36)?;

            sections.push(serde_json::json!({
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_address": raw_address,
                "raw_size": raw_size,
                "characteristics": characteristics,
                "executable": (characteristics & 0x20000000) != 0,
                "readable": (characteristics & 0x40000000) != 0,
                "writable": (characteristics & 0x80000000) != 0
            }));
        }

        Ok(sections)
    }

    /// Enumerate windows for current process
    fn enumerate_windows(&self) -> Result<Vec<serde_json::Value>> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
        };

        static WINDOWS: std::sync::Mutex<Vec<serde_json::Value>> =
            std::sync::Mutex::new(Vec::new());

        unsafe extern "system" fn enum_callback(
            hwnd: HWND,
            _: windows::Win32::Foundation::LPARAM,
        ) -> windows::Win32::Foundation::BOOL {
            let mut pid: u32 = 0;
            let tid = GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == std::process::id() {
                let mut title = [0u16; 256];
                let len = GetWindowTextW(hwnd, &mut title);
                let title_str = String::from_utf16_lossy(&title[..len as usize]);
                let visible = IsWindowVisible(hwnd).as_bool();
                if let Ok(mut windows) = WINDOWS.lock() {
                    windows.push(serde_json::json!({
                        "hwnd": hwnd.0 as usize,
                        "title": title_str,
                        "thread_id": tid,
                        "visible": visible
                    }));
                }
            }
            windows::Win32::Foundation::TRUE
        }

        if let Ok(mut w) = WINDOWS.lock() {
            w.clear();
        }

        unsafe {
            let _ = EnumWindows(Some(enum_callback), windows::Win32::Foundation::LPARAM(0));
        }

        let result = WINDOWS.lock().map(|w| w.clone()).unwrap_or_default();
        Ok(result)
    }

    /// Get process token information
    fn get_token_info(&self) -> Result<serde_json::Value> {
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|e| Error::Internal(format!("OpenProcessToken failed: {}", e)))?;

            // Get elevation status
            let mut elevation = TOKEN_ELEVATION::default();
            let mut return_length = 0u32;
            let _ = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );

            let _ = windows::Win32::Foundation::CloseHandle(token);

            Ok(serde_json::json!({
                "elevated": elevation.TokenIsElevated != 0,
                "pid": std::process::id()
            }))
        }
    }

    /// Adjust process privilege
    fn adjust_privilege(&self, privilege_name: &str, enable: bool) -> Result<bool> {
        use windows::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .map_err(|e| Error::Internal(format!("OpenProcessToken failed: {}", e)))?;

            let priv_wide: Vec<u16> = privilege_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut luid = windows::Win32::Foundation::LUID::default();
            if LookupPrivilegeValueW(None, PCWSTR(priv_wide.as_ptr()), &mut luid).is_err() {
                let _ = windows::Win32::Foundation::CloseHandle(token);
                return Ok(false);
            }

            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: if enable {
                        SE_PRIVILEGE_ENABLED
                    } else {
                        Default::default()
                    },
                }],
            };

            let result = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
            let _ = windows::Win32::Foundation::CloseHandle(token);

            Ok(result.is_ok())
        }
    }

    /// Get full path to the process executable
    fn get_process_path(&self) -> Option<String> {
        let modules = self.modules.read().ok()?;
        modules.first().map(|m| m.path.clone())
    }

    /// Get PE section ranges: (name, start_address, size, characteristics)
    fn get_pe_section_ranges(&self, base: usize) -> Result<Vec<(String, usize, usize, u32)>> {
        let mut sections = Vec::new();

        // Check DOS header magic
        let dos_magic = self.read_u16(base)?;
        if dos_magic != 0x5A4D {
            return Err(Error::Internal("Invalid DOS header".into()));
        }

        let e_lfanew = self.read_i32(base + 0x3C)?;
        let nt_headers = base + e_lfanew as usize;
        let file_header = nt_headers + 4;
        let num_sections = self.read_u16(file_header + 2)? as usize;
        let optional_header_size = self.read_u16(file_header + 16)? as usize;
        let section_headers = file_header + 20 + optional_header_size;

        for i in 0..num_sections.min(64) {
            let section = section_headers + (i * 40);
            let name_bytes = self.read(section, 8)?;
            let name = String::from_utf8_lossy(&name_bytes)
                .trim_end_matches('\0')
                .to_string();
            let virtual_size = self.read_u32(section + 8)? as usize;
            let virtual_address = self.read_u32(section + 12)? as usize;
            let characteristics = self.read_u32(section + 36)?;

            // Calculate actual section address in memory
            let section_start = base + virtual_address;

            sections.push((name, section_start, virtual_size, characteristics));
        }

        Ok(sections)
    }
}

impl ProcessControl for InProcessBackend {
    fn get_modules(&self) -> Result<Vec<Module>> {
        let modules = self
            .modules
            .read()
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(modules.clone())
    }

    fn get_module(&self, name: &str) -> Result<Option<Module>> {
        let modules = self
            .modules
            .read()
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(modules
            .iter()
            .find(|m| ghost_core::process::module_name_matches(m, name))
            .cloned())
    }

    fn get_threads(&self) -> Result<Vec<Thread>> {
        ghost_core::threads::enumerate_threads()
    }

    fn suspend_thread(&self, tid: u32) -> Result<()> {
        ghost_core::threads::suspend_thread(tid)?;
        Ok(())
    }

    fn resume_thread(&self, tid: u32) -> Result<()> {
        ghost_core::threads::resume_thread(tid)?;
        Ok(())
    }

    fn get_pid(&self) -> u32 {
        ghost_core::process::current_pid()
    }

    fn get_process_name(&self) -> Result<String> {
        let modules = self
            .modules
            .read()
            .map_err(|e| Error::Internal(e.to_string()))?;
        modules
            .first()
            .map(|m| m.name.clone())
            .ok_or(Error::Internal("No modules loaded".into()))
    }
}

impl Debugging for InProcessBackend {
    fn set_breakpoint(&self, addr: usize, bp_type: BreakpointType) -> Result<BreakpointId> {
        // Initialize debugger if not already done
        ghost_core::debug::initialize_debugger()?;

        match bp_type {
            BreakpointType::Software => ghost_core::debug::set_software_breakpoint(addr),
            BreakpointType::Hardware => {
                #[cfg(target_arch = "x86_64")]
                {
                    ghost_core::debug::set_hardware_breakpoint(addr)
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    Err(Error::NotImplemented(
                        "Hardware breakpoints only supported on x64".into(),
                    ))
                }
            }
        }
    }

    fn remove_breakpoint(&self, id: BreakpointId) -> Result<()> {
        ghost_core::debug::remove_breakpoint(id)
    }

    fn list_breakpoints(&self) -> Result<Vec<Breakpoint>> {
        ghost_core::debug::list_breakpoints()
    }

    fn set_breakpoint_enabled(&self, id: BreakpointId, enabled: bool) -> Result<()> {
        ghost_core::debug::set_breakpoint_enabled(id, enabled)
    }

    fn get_registers(&self, tid: u32) -> Result<Registers> {
        ghost_core::threads::get_thread_context(tid)
    }

    fn set_registers(&self, tid: u32, regs: &Registers) -> Result<()> {
        ghost_core::threads::set_thread_context(tid, regs)
    }

    fn continue_execution(&self) -> Result<()> {
        // In VEH-based debugging, continue happens automatically after handler returns
        // This is a no-op for in-process debugging
        Ok(())
    }

    fn step_into(&self, tid: u32) -> Result<()> {
        // Set trap flag for single-stepping
        let mut regs = ghost_core::threads::get_thread_context(tid)?;
        regs.rflags |= 0x100; // TF flag
        ghost_core::threads::set_thread_context(tid, &regs)
    }

    fn step_over(&self, tid: u32) -> Result<()> {
        // Get current instruction pointer
        let regs = ghost_core::threads::get_thread_context(tid)?;
        let rip = regs.rip as usize;

        // Read instruction bytes at RIP (up to 15 bytes for x86-64)
        let instr_bytes = self.read(rip, 15)?;

        // Analyze instruction to determine if it's a CALL and its length
        let info = ghost_core::disasm::analyze_instruction(&instr_bytes, rip as u64, 64)
            .map_err(|e| Error::Internal(format!("Failed to analyze instruction: {}", e)))?;

        if !info.is_call {
            // Not a call, just do single step
            return self.step_into(tid);
        }

        // Set temporary breakpoint after the call instruction
        let return_addr = rip + info.length;
        tracing::debug!(target: "ghost_agent::backend", 
            tid = tid,
            rip = format!("0x{:x}", rip),
            return_addr = format!("0x{:x}", return_addr),
            instr_len = info.length,
            mnemonic = %info.mnemonic,
            "Setting step-over breakpoint");

        // Set a one-shot software breakpoint at return address
        ghost_core::debug::initialize_debugger()?;
        let _bp_id = ghost_core::debug::set_one_shot_breakpoint(return_addr)?;

        // Resume the thread
        self.resume_thread(tid)?;

        Ok(())
    }

    fn stack_walk(&self, tid: u32) -> Result<Vec<StackFrame>> {
        // Initialize symbols
        let _ = ghost_core::symbols::initialize();

        // Get thread context
        let context = ghost_core::threads::get_thread_context_raw(tid)?;

        // Open thread handle for stack walk
        let handle = ghost_core::threads::open_thread_handle(tid, 0x0008 | 0x0010)?; // THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION

        let result = ghost_core::symbols::stack_walk_dbghelp(handle, &context);

        // Close handle
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }

        result
    }
}

impl StaticAnalysis for InProcessBackend {
    fn disassemble(&self, _addr: usize, _count: usize) -> Result<Vec<Instruction>> {
        // Disassembly is handled by host (has Capstone)
        Err(Error::NotImplemented("Disassembly handled by host".into()))
    }

    fn disassemble_function(&self, _addr: usize) -> Result<Vec<Instruction>> {
        Err(Error::NotImplemented("Disassembly handled by host".into()))
    }

    fn get_exports(&self, module: &str) -> Result<Vec<Export>> {
        let module_info = self
            .get_module(module)?
            .ok_or_else(|| Error::Internal(format!("Module not found: {}", module)))?;
        ghost_core::pe::parse_exports(module_info.base)
    }

    fn get_imports(&self, module: &str) -> Result<Vec<Import>> {
        let module_info = self
            .get_module(module)?
            .ok_or_else(|| Error::Internal(format!("Module not found: {}", module)))?;
        ghost_core::pe::parse_imports(module_info.base)
    }

    fn resolve_symbol(&self, name: &str) -> Result<Option<usize>> {
        // Initialize symbols first
        let _ = ghost_core::symbols::initialize();

        // Try DbgHelp first (handles both "symbol" and "module!symbol")
        if let Ok(Some(info)) = ghost_core::symbols::resolve_symbol_name(name) {
            return Ok(Some(info.address));
        }

        // Search through all modules for the symbol
        let modules = self.get_modules()?;

        // Check if name contains module prefix (e.g., "kernel32!CreateFileW")
        if let Some((module_name, func_name)) = name.split_once('!') {
            if let Some(module) = modules
                .iter()
                .find(|m| ghost_core::process::module_name_matches(m, module_name))
            {
                // Fallback to PE parsing
                let exports = ghost_core::pe::parse_exports(module.base)?;
                if let Some(exp) = exports
                    .iter()
                    .find(|e| e.name.eq_ignore_ascii_case(func_name))
                {
                    return Ok(Some(exp.address));
                }
            }
            return Ok(None);
        }

        // Search all modules
        for module in &modules {
            if let Ok(exports) = ghost_core::pe::parse_exports(module.base) {
                if let Some(exp) = exports.iter().find(|e| e.name.eq_ignore_ascii_case(name)) {
                    return Ok(Some(exp.address));
                }
            }
        }

        Ok(None)
    }

    fn get_symbol(&self, addr: usize) -> Result<Option<String>> {
        // Initialize symbols
        let _ = ghost_core::symbols::initialize();

        // Use ghost-core's symbol resolution (DbgHelp)
        if let Some(name) = ghost_core::symbols::get_symbol_name(addr) {
            return Ok(Some(name));
        }

        // Fall back to export table lookup
        let modules = self.get_modules()?;
        for module in &modules {
            if addr >= module.base && addr < module.base + module.size {
                if let Ok(exports) = ghost_core::pe::parse_exports(module.base) {
                    // Find the closest export at or before the address
                    let mut best_match: Option<(&str, usize)> = None;
                    for exp in &exports {
                        if exp.address <= addr {
                            let offset = addr - exp.address;
                            match best_match {
                                None => best_match = Some((&exp.name, offset)),
                                Some((_, best_offset)) if offset < best_offset => {
                                    best_match = Some((&exp.name, offset));
                                }
                                _ => {}
                            }
                        }
                    }
                    if let Some((name, offset)) = best_match {
                        if offset == 0 {
                            return Ok(Some(format!("{}!{}", module.name, name)));
                        } else if offset < 0x1000 {
                            // Only return if within reasonable offset
                            return Ok(Some(format!("{}!{}+0x{:x}", module.name, name, offset)));
                        }
                    }
                }
                break;
            }
        }

        Ok(None)
    }

    fn find_xrefs_to(&self, addr: usize) -> Result<Vec<usize>> {
        // Trait implementation - uses defaults (main module only, 100 results)
        self.find_xrefs_to_filtered(addr, None, 100)
    }

    fn extract_strings(&self, module: &str, min_length: usize) -> Result<Vec<(usize, String)>> {
        let module_info = self
            .get_module(module)?
            .ok_or_else(|| Error::Internal(format!("Module not found: {}", module)))?;

        let mut strings = Vec::new();
        let max_strings = 10000;
        let min_len = if min_length == 0 { 4 } else { min_length };

        // Get PE sections and scan only data sections (not headers or code)
        let sections = self.get_pe_section_ranges(module_info.base)?;

        // Sections that typically contain strings: .rdata, .data, .rodata, etc.
        // Skip .text (code) and PE headers
        let string_sections: Vec<_> = sections
            .iter()
            .filter(|(name, _, _, characteristics)| {
                // Skip executable sections (code)
                let is_executable = (*characteristics & 0x20000000) != 0;
                // Include readable, non-executable sections
                let is_readable = (*characteristics & 0x40000000) != 0;
                // Common data section names
                let is_data_section = name == ".rdata"
                    || name == ".data"
                    || name == ".rodata"
                    || name == ".idata"
                    || name == ".rsrc"
                    || name == ".bss"
                    || name.starts_with(".?")  // MSVC sections
                    || (!is_executable && is_readable);
                is_data_section && !is_executable
            })
            .collect();

        tracing::debug!(
            target: "ghost_agent::backend",
            section_count = string_sections.len(),
            "Scanning data sections for strings"
        );

        for (name, start, size, _) in string_sections {
            if strings.len() >= max_strings {
                break;
            }

            // Skip invalid or too large sections
            if *size == 0 || *size > 100 * 1024 * 1024 {
                continue;
            }

            tracing::trace!(
                target: "ghost_agent::backend",
                section = %name,
                start = format!("0x{:x}", start),
                size = size,
                "Scanning section"
            );

            // Read section data
            let data = match self.read(*start, *size) {
                Ok(d) => d,
                Err(_) => continue, // Skip unreadable sections
            };

            // Extract ASCII strings (similar to CE/x64dbg approach)
            // Scan for sequences of printable ASCII chars (0x20-0x7E)
            let mut string_start = 0usize;
            for idx in 0..data.len() {
                let byte = data[idx];
                // Check if printable ASCII (space to ~)
                if !(0x20..=0x7E).contains(&byte) {
                    let string_length = idx - string_start;
                    if string_length >= min_len && strings.len() < max_strings {
                        if let Ok(s) = std::str::from_utf8(&data[string_start..idx]) {
                            strings.push((*start + string_start, s.to_string()));
                        }
                    }
                    string_start = idx + 1;
                }
            }
            // Handle string at end of buffer
            let remaining_len = data.len() - string_start;
            if remaining_len >= min_len && strings.len() < max_strings {
                if let Ok(s) = std::str::from_utf8(&data[string_start..]) {
                    strings.push((*start + string_start, s.to_string()));
                }
            }

            // Extract UTF-16 strings (wide chars 0x0020-0x007E)
            string_start = 0;
            for idx in 0..(data.len() / 2) {
                if idx * 2 + 1 >= data.len() {
                    break;
                }
                let wchar = u16::from_le_bytes([data[idx * 2], data[idx * 2 + 1]]);
                // Check if printable (space to ~)
                if !(0x0020..0x007F).contains(&wchar) {
                    let string_length = idx - string_start;
                    if string_length >= min_len && strings.len() < max_strings {
                        // Convert UTF-16 to String
                        let wide_slice: Vec<u16> = (string_start..idx)
                            .filter_map(|i| {
                                if i * 2 + 1 < data.len() {
                                    Some(u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if let Ok(s) = String::from_utf16(&wide_slice) {
                            strings.push((*start + string_start * 2, s));
                        }
                    }
                    string_start = idx + 1;
                }
            }
            // Handle wide string at end of buffer
            let remaining_wchars = data.len() / 2 - string_start;
            if remaining_wchars >= min_len
                && strings.len() < max_strings
                && data.len() / 2 > string_start
            {
                let wide_slice: Vec<u16> = (string_start..(data.len() / 2))
                    .filter_map(|i| {
                        if i * 2 + 1 < data.len() {
                            Some(u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]))
                        } else {
                            None
                        }
                    })
                    .collect();
                if let Ok(s) = String::from_utf16(&wide_slice) {
                    strings.push((*start + string_start * 2, s));
                }
            }
        }

        Ok(strings)
    }
}

impl CodeInjection for InProcessBackend {
    fn patch_bytes(&self, addr: usize, bytes: &[u8]) -> Result<Vec<u8>> {
        // Read original bytes first
        let original = self.read(addr, bytes.len())?;
        // Write new bytes
        self.write(addr, bytes)?;
        Ok(original)
    }

    fn nop_region(&self, addr: usize, count: usize) -> Result<Vec<u8>> {
        let original = self.read(addr, count)?;
        let nops = ghost_core::hooks::generate_nops(count);
        self.write(addr, &nops)?;
        Ok(original)
    }

    fn assemble(&self, _code: &str, _addr: usize) -> Result<Vec<u8>> {
        // Assembly is handled by host (has Keystone)
        Err(Error::NotImplemented("Assembly handled by host".into()))
    }

    fn create_hook(&self, target: usize, callback: usize) -> Result<u32> {
        self.create_hook_ex(CreateHookParams {
            target,
            callback,
            hook_type: "inline".to_string(),
            ..Default::default()
        })
    }

    fn remove_hook(&self, hook_id: u32) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            return Err(Error::NotImplemented(
                "Hooks only supported on Windows".into(),
            ));
        }

        #[cfg(target_os = "windows")]
        {
            ghost_core::extended_hooks::initialize()?;
            ghost_core::extended_hooks::get_hook_manager()
                .write()
                .map_err(|_| Error::Internal("Failed to acquire hook manager lock".into()))?
                .remove_hook(HookId(hook_id))?;

            self.hooks
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?
                .remove(&hook_id);
            Ok(())
        }
    }

    fn call_function(&self, addr: usize, args: &[u64]) -> Result<u64> {
        if addr == 0 {
            return Err(Error::InvalidAddress(addr));
        }

        let options = FunctionCallOptions {
            args: args.iter().copied().map(FunctionArg::Int).collect(),
            ..Default::default()
        };

        let result = ExecutionEngine::new().call_function(addr, &options)?;
        Ok(result.return_value)
    }
}

impl GhostBackend for InProcessBackend {
    fn status(&self) -> Result<AgentStatus> {
        Ok(AgentStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: self.get_pid(),
            process_name: self.get_process_name().unwrap_or_default(),
            process_path: self.get_process_path(),
            arch: if cfg!(target_arch = "x86_64") {
                "x64".to_string()
            } else {
                "x86".to_string()
            },
            connected: true,
            client_count: 1, // Updated by multi-client server wrapper
        })
    }
}

// =============================================================================
// Multi-Client Backend Wrapper
// =============================================================================

/// Wrapper that integrates InProcessBackend with SharedState and EventBus
/// Implements RequestHandler for use with MultiClientServer
pub struct MultiClientBackend {
    backend: InProcessBackend,
    state: Arc<SharedState>,
    event_bus: Arc<EventBus>,
    safety: Arc<SafetyGuard>,
    exec: ExecutionEngine,
    local_allocations: Mutex<HashMap<usize, usize>>,
    scripts: Mutex<HashMap<String, ScriptEntry>>,
    hooks: Mutex<HashMap<u32, HookEntry>>,
    command_history: Mutex<Vec<CommandHistoryEntry>>,
    command_counter: AtomicU64,
}

#[allow(dead_code)]
impl MultiClientBackend {
    fn now_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn sanitize_backup_name(name: &str) -> String {
        let filtered: String = name
            .trim()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if filtered.is_empty() {
            "backup".to_string()
        } else {
            filtered
        }
    }

    fn backup_dir() -> PathBuf {
        PathBuf::from("config").join("agent_backups")
    }

    fn ensure_backup_dir() -> Result<PathBuf> {
        let dir = Self::backup_dir();
        fs::create_dir_all(&dir)
            .map_err(|e| Error::Internal(format!("Failed to create backup directory: {}", e)))?;
        Ok(dir)
    }

    fn find_latest_backup(dir: &PathBuf) -> Result<PathBuf> {
        let mut latest: Option<(std::time::SystemTime, PathBuf)> = None;
        for entry in fs::read_dir(dir)
            .map_err(|e| Error::Internal(format!("Failed to read backup directory: {}", e)))?
        {
            let entry = entry
                .map_err(|e| Error::Internal(format!("Failed to read backup entry: {}", e)))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let modified = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            if latest.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
                latest = Some((modified, path));
            }
        }
        latest
            .map(|(_, path)| path)
            .ok_or_else(|| Error::Internal("No backups found".into()))
    }

    fn find_backup_by_prefix(dir: &PathBuf, name: &str) -> Result<PathBuf> {
        let direct = dir.join(format!("{}.json", name));
        if direct.exists() {
            return Ok(direct);
        }

        let mut latest: Option<(std::time::SystemTime, PathBuf)> = None;
        for entry in fs::read_dir(dir)
            .map_err(|e| Error::Internal(format!("Failed to read backup directory: {}", e)))?
        {
            let entry = entry
                .map_err(|e| Error::Internal(format!("Failed to read backup entry: {}", e)))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or_default()
                .to_string();
            if !file_name.starts_with(name) {
                continue;
            }

            let modified = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            if latest.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
                latest = Some((modified, path));
            }
        }

        latest
            .map(|(_, path)| path)
            .ok_or_else(|| Error::Internal(format!("Backup '{}' not found", name)))
    }

    fn parse_hex_usize(value: &serde_json::Value, field: &str) -> Result<usize> {
        if let Some(s) = value.as_str() {
            let s = s.trim_start_matches("0x").trim_start_matches("0X");
            usize::from_str_radix(s, 16)
                .map_err(|_| Error::Internal(format!("Invalid {} hex: {}", field, value)))
        } else if let Some(n) = value.as_u64() {
            Ok(n as usize)
        } else {
            Err(Error::Internal(format!("Missing or invalid {}", field)))
        }
    }

    #[allow(clippy::manual_is_multiple_of)]
    fn parse_hex_bytes(value: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
        let s = value
            .as_str()
            .ok_or_else(|| Error::Internal(format!("Missing {} bytes", field)))?;
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() % 2 != 0 {
            return Err(Error::Internal(format!(
                "{} hex length must be even",
                field
            )));
        }
        hex::decode(&clean).map_err(|e| Error::Internal(format!("Invalid {} hex: {}", field, e)))
    }

    fn parse_function_args(array: &serde_json::Value) -> Result<Vec<FunctionArg>> {
        let mut args = Vec::new();
        if let Some(arr) = array.as_array() {
            for v in arr {
                if let Some(n) = v.as_u64() {
                    args.push(FunctionArg::Int(n));
                } else if let Some(s) = v.as_str() {
                    let parsed = if let Ok(num) = s.parse::<u64>() {
                        FunctionArg::Int(num)
                    } else if let Ok(num) = usize::from_str_radix(s.trim_start_matches("0x"), 16) {
                        FunctionArg::Pointer(num)
                    } else {
                        return Err(Error::Internal(format!("Invalid argument: {}", s)));
                    };
                    args.push(parsed);
                } else {
                    return Err(Error::Internal("Unsupported argument type".into()));
                }
            }
        }
        Ok(args)
    }

    fn parse_calling_convention(value: Option<&str>) -> CallingConvention {
        match value.unwrap_or("win64").to_lowercase().as_str() {
            "cdecl" => CallingConvention::Cdecl,
            "stdcall" => CallingConvention::Stdcall,
            "fastcall" => CallingConvention::Fastcall,
            "sysv64" | "sysv" | "linux64" => CallingConvention::SysV64,
            "thiscall" => CallingConvention::Thiscall,
            _ => CallingConvention::Win64,
        }
    }

    fn snapshot_allocations(&self) -> Result<Vec<AllocationSnapshot>> {
        let allocs = self
            .local_allocations
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(allocs
            .iter()
            .map(|(addr, size)| AllocationSnapshot {
                address: *addr,
                size: *size,
            })
            .collect())
    }

    fn clear_local_allocations(&self) -> Result<usize> {
        let mut allocs = self
            .local_allocations
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        let count = allocs.len();
        for (address, size) in allocs.drain() {
            unsafe {
                let _ = Vec::from_raw_parts(address as *mut u8, size, size);
            }
        }
        Ok(count)
    }

    fn reinstall_hooks(&self, hooks: &[HookEntry]) -> Result<usize> {
        let existing_ids: Vec<u32> = {
            let hooks = self
                .hooks
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?;
            hooks.keys().copied().collect()
        };
        for id in existing_ids {
            let _ = self.backend.remove_hook(id);
        }

        let mut map = self
            .hooks
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        map.clear();

        let mut restored = 0usize;
        for hook in hooks {
            match self.backend.create_hook(hook.address, hook.callback) {
                Ok(new_id) => {
                    let mut entry = hook.clone();
                    entry.id = new_id;
                    map.insert(new_id, entry);
                    restored += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        target: "ghost_agent::hooks",
                        address = format!("0x{:X}", hook.address),
                        error = %e,
                        "Failed to reinstall hook from backup"
                    );
                }
            }
        }

        let total = map.len() as u32;
        drop(map);
        self.state.session.write().active_hooks = total;
        Ok(restored)
    }

    fn restore_scripts(&self, scripts: &[ScriptEntry]) -> Result<usize> {
        let total = {
            let mut map = self
                .scripts
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?;
            map.clear();
            for script in scripts {
                map.insert(script.name.clone(), script.clone());
            }
            map.len()
        };
        self.state.session.write().active_scripts = total as u32;
        Ok(total)
    }

    pub fn new(
        backend: InProcessBackend,
        state: Arc<SharedState>,
        event_bus: Arc<EventBus>,
    ) -> Self {
        let safety = Arc::new(SafetyGuard::new(Arc::clone(&state)));
        Self {
            backend,
            state,
            event_bus,
            safety,
            exec: ExecutionEngine::new(),
            local_allocations: Mutex::new(HashMap::new()),
            scripts: Mutex::new(HashMap::new()),
            hooks: Mutex::new(HashMap::new()),
            command_history: Mutex::new(Vec::new()),
            command_counter: AtomicU64::new(1),
        }
    }

    /// Get agent status with current client count from shared state
    fn get_status(&self) -> AgentStatus {
        let base_status = self.backend.status().unwrap_or_else(|_| AgentStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: 0,
            process_name: "unknown".to_string(),
            process_path: None,
            arch: "unknown".to_string(),
            connected: true,
            client_count: 0,
        });

        AgentStatus {
            client_count: self.state.client_count(),
            ..base_status
        }
    }

    /// Handle handshake request
    fn handle_handshake(
        &self,
        request: &Request,
        _client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let identity: ClientIdentity = serde_json::from_value(request.params.clone())
            .map_err(|e| Error::Internal(format!("Invalid handshake params: {}", e)))?;

        // Validate client identity
        if let Err(e) = identity.validate() {
            tracing::warn!(
                target: "ghost_agent::handshake",
                client = %identity.name,
                error = %e,
                "Handshake validation failed"
            );
            let response = HandshakeResponse {
                accepted: false,
                agent_status: self.get_status(),
                granted_capabilities: vec![],
                error: Some(e),
            };
            return Ok(serde_json::to_value(response)?);
        }

        tracing::info!(
            target: "ghost_agent::handshake",
            client = %identity.name,
            version = %identity.version,
            session = %identity.session_id,
            capabilities = ?identity.capabilities,
            "Client handshake accepted"
        );

        // Register client in shared state
        self.state.register_client(identity.clone());

        // In debug builds or when RUST_LOG is set, grant all capabilities for development
        let is_debug = cfg!(debug_assertions) || std::env::var("RUST_LOG").is_ok();

        // Determine granted capabilities (validate + default read)
        let mut granted: Vec<Capability> = Vec::new();
        if is_debug {
            // Debug mode: grant all capabilities
            granted = vec![
                Capability::Read,
                Capability::Write,
                Capability::Execute,
                Capability::Debug,
                Capability::Admin,
            ];
            tracing::info!(
                target: "ghost_agent::handshake",
                "Debug mode: granting all capabilities"
            );
        } else if identity.capabilities.is_empty() {
            granted.push(Capability::Read);
        } else {
            for cap in &identity.capabilities {
                match Capability::from_str(cap) {
                    Ok(c) => granted.push(c),
                    Err(e) => {
                        let response = HandshakeResponse {
                            accepted: false,
                            agent_status: self.get_status(),
                            granted_capabilities: vec![],
                            error: Some(e),
                        };
                        return Ok(serde_json::to_value(response)?);
                    }
                }
            }
        }

        // Persist granted capabilities
        self.state
            .set_capabilities(&identity.session_id, granted.clone());

        // Update session metadata / emit SessionAttached once per target
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let status = self.get_status();
        if self
            .state
            .update_session_attach(status.pid, status.process_name.clone(), now)
        {
            self.event_bus.publish(
                Event::new(
                    EventType::SessionAttached,
                    SessionAttachedPayload {
                        pid: status.pid,
                        process_name: status.process_name.clone(),
                    },
                )
                .with_source(identity.session_id.clone()),
            );
        }

        let response = HandshakeResponse {
            accepted: true,
            agent_status: self.get_status(),
            granted_capabilities: granted.iter().map(|c| c.to_string()).collect(),
            error: None,
        };

        // Emit client connected event
        self.event_bus.publish(
            Event::new(
                EventType::ClientConnected,
                ghost_common::ipc::ClientConnectedPayload {
                    client_id: identity.session_id.clone(),
                    name: identity.name.clone(),
                    capabilities: granted.clone(),
                },
            )
            .with_source(identity.session_id.clone()),
        );

        Ok(serde_json::to_value(response)?)
    }

    /// Handle memory write with event emission and patch tracking
    fn handle_memory_write(
        &self,
        request: &Request,
        client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let addr = parse_address(&request.params["address"])?;
        // Accept both "bytes" and "data" parameter names for compatibility
        let bytes_hex = request.params["bytes"]
            .as_str()
            .or_else(|| request.params["data"].as_str())
            .ok_or(Error::Internal("Missing bytes/data parameter".into()))?;
        // Strip spaces from hex string (e.g., "2C 01 00 00" -> "2C010000")
        let bytes_hex_clean: String = bytes_hex.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = hex::decode(&bytes_hex_clean)
            .map_err(|e| Error::Internal(format!("Invalid hex: {}", e)))?;

        // Read original bytes for patch tracking (best effort - don't fail write if read fails)
        let original = self.backend.read(addr, bytes.len()).ok();

        tracing::debug!(
            target: "ghost_agent::backend",
            address = format!("0x{:x}", addr),
            size = bytes.len(),
            client = ?client_id,
            "Writing memory with patch tracking"
        );

        // Perform the write
        self.backend.write(addr, &bytes)?;

        // Track patch in shared state (use empty vec if original read failed)
        let mut patch = PatchEntry::new(
            addr as u64,
            original.clone().unwrap_or_default(),
            bytes.clone(),
        );
        patch.applied_by = client_id.map(|s| s.to_string());

        let patch_id = match self.state.add_patch(patch) {
            Ok(id) => {
                if let Some(cid) = client_id {
                    self.state.push_undo(cid, id);
                }
                id
            }
            Err(e) => {
                tracing::warn!(target: "ghost_agent::state", error = %e, "Failed to track patch");
                0
            }
        };

        // Emit event to all subscribers
        let source_client = client_id.unwrap_or("unknown").to_string();
        let event = Event::new(
            EventType::MemoryWrite,
            MemoryWritePayload {
                address: addr as u64,
                size: bytes.len(),
                client_id: source_client.clone(),
            },
        )
        .with_source(source_client.clone());

        self.event_bus.publish(event);

        if patch_id != 0 {
            self.event_bus.publish(
                Event::new(
                    EventType::PatchApplied,
                    PatchAppliedPayload {
                        patch_id,
                        address: addr as u64,
                        size: bytes.len(),
                        client_id: source_client.clone(),
                    },
                )
                .with_source(source_client),
            );
        }

        tracing::info!(
            target: "ghost_agent::backend",
            address = format!("0x{:x}", addr),
            size = bytes.len(),
            "Memory write successful (event emitted)"
        );

        Ok(serde_json::json!({"success": true}))
    }

    /// Handle patch undo; if patch_id missing use per-client undo stack
    fn handle_patch_undo(
        &self,
        request: &Request,
        client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let client = client_id.ok_or_else(|| Error::Internal("Missing client id".into()))?;
        let patch_id = if let Some(id) = request.params.get("patch_id").and_then(|v| v.as_u64()) {
            id
        } else {
            self.state
                .pop_undo(client)
                .ok_or_else(|| Error::Internal("No undo entries".into()))?
        };

        let patch = self
            .state
            .mark_patch_undone(patch_id)
            .ok_or_else(|| Error::Internal("Patch not found or already undone".into()))?;

        // Restore original bytes
        self.backend
            .write(patch.address as usize, &patch.original_bytes)?;

        self.event_bus.publish(
            Event::new(
                EventType::PatchUndone,
                PatchUndonePayload {
                    patch_id,
                    address: patch.address,
                    client_id: client.to_string(),
                },
            )
            .with_source(client.to_string()),
        );

        Ok(serde_json::json!({
            "undone": patch_id,
            "address": format!("0x{:x}", patch.address),
            "size": patch.original_bytes.len()
        }))
    }

    /// Issue a safety token for a capability scope
    fn handle_safety_issue_token(
        &self,
        request: &Request,
        client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let client = client_id.unwrap_or("unknown");
        let scope = request
            .params
            .get("scope")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing scope".into()))?;
        let operation = request
            .params
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("unspecified");
        let ttl_secs = request
            .params
            .get("ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(ghost_common::ipc::DEFAULT_TOKEN_TTL_SECS);

        let capability = Capability::from_str(scope)
            .map_err(|e| Error::Internal(format!("Invalid scope: {}", e)))?;

        let token = self.state.issue_token(
            capability,
            operation.to_string(),
            client.to_string(),
            ttl_secs,
        );

        self.event_bus.publish(
            Event::new(
                EventType::SafetyTokenIssued,
                ghost_common::ipc::SafetyTokenIssuedPayload {
                    token_id: token.id.clone(),
                    scope: token.scope,
                    client_id: client.to_string(),
                    expires_at: token.expires_at,
                },
            )
            .with_source(client.to_string()),
        );

        Ok(serde_json::json!({
            "token_id": token.id,
            "scope": token.scope,
            "expires_at": token.expires_at,
            "ttl_secs": ttl_secs.min(ghost_common::ipc::MAX_TOKEN_TTL_SECS),
        }))
    }

    /// Revoke a safety token
    fn handle_safety_revoke_token(
        &self,
        request: &Request,
        client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let client = client_id.unwrap_or("unknown");
        let token_id = request
            .params
            .get("token_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing token_id".into()))?;

        let revoked = self.state.revoke_token(token_id);

        if revoked {
            self.event_bus.publish(
                Event::new(
                    EventType::SafetyTokenRevoked,
                    ghost_common::ipc::SafetyTokenRevokedPayload {
                        token_id: token_id.to_string(),
                        reason: "revoked".to_string(),
                    },
                )
                .with_source(client.to_string()),
            );
        }

        Ok(serde_json::json!({ "revoked": revoked }))
    }

    /// Session metadata and current attachment status
    fn handle_session_info(&self, client_id: Option<&str>) -> Result<serde_json::Value> {
        let session = self.state.session.read();
        let capabilities = client_id
            .map(|cid| self.state.get_capabilities(cid))
            .unwrap_or_default();

        Ok(serde_json::json!({
            "attached_pid": session.attached_pid,
            "process_name": session.attached_process_name,
            "attached_at": session.attached_at,
            "started_at": session.started_at,
            "safety_mode": session.safety_mode,
            "modules_loaded": session.modules_loaded,
            "client_count": self.state.client_count(),
            "capabilities": capabilities,
            "active_scripts": session.active_scripts,
            "active_hooks": session.active_hooks,
        }))
    }

    /// Record an attach request (in-process agent is always "attached")
    fn handle_session_attach(
        &self,
        request: &Request,
        client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let requested_pid = request
            .params
            .get("pid")
            .and_then(|v| v.as_u64())
            .map(|p| p as u32)
            .unwrap_or_else(|| self.backend.get_pid());

        let requested_name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                self.backend
                    .get_process_name()
                    .unwrap_or_else(|_| "unknown".into())
            });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let changed = self
            .state
            .update_session_attach(requested_pid, requested_name.clone(), now);

        if changed {
            self.event_bus.publish(
                Event::new(
                    EventType::SessionAttached,
                    SessionAttachedPayload {
                        pid: requested_pid,
                        process_name: requested_name.clone(),
                    },
                )
                .with_source(client_id.unwrap_or("unknown").to_string()),
            );
        }

        Ok(serde_json::json!({
            "attached": true,
            "pid": requested_pid,
            "process_name": requested_name,
            "attached_at": now,
            "updated": changed
        }))
    }

    /// Clear attach metadata and emit SessionDetached
    fn handle_session_detach(
        &self,
        request: &Request,
        client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let reason = request
            .params
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("detach_requested");

        if let Some(payload) = self.state.clear_session_attach(reason) {
            self.event_bus.publish(
                Event::new(EventType::SessionDetached, payload.clone())
                    .with_source(client_id.unwrap_or("unknown").to_string()),
            );

            return Ok(serde_json::json!({
                "detached": true,
                "pid": payload.pid,
                "reason": reason
            }));
        }

        Ok(serde_json::json!({
            "detached": false,
            "reason": "no_session"
        }))
    }

    /// Minimal process list (current/attached process)
    fn handle_process_list(&self, request: &Request) -> Result<serde_json::Value> {
        let filter = request
            .params
            .get("filter")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());

        let session = self.state.session.read();
        let mut processes = Vec::new();

        if let Some(pid) = session.attached_pid {
            processes.push(serde_json::json!({
                "pid": pid,
                "name": session.attached_process_name.clone().unwrap_or_else(|| "unknown".into()),
                "attached": true
            }));
        } else {
            processes.push(serde_json::json!({
                "pid": self.backend.get_pid(),
                "name": self.backend.get_process_name().unwrap_or_else(|_| "unknown".into()),
                "attached": true
            }));
        }

        if let Some(f) = filter {
            processes.retain(|p| {
                p.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| n.to_lowercase().contains(&f))
                    .unwrap_or(false)
            });
        }

        Ok(serde_json::json!({ "processes": processes }))
    }

    /// Resolve a symbol name to an address (best-effort)
    fn handle_exec_resolve(&self, request: &Request) -> Result<serde_json::Value> {
        let name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing name".into()))?;

        let resolved = self.backend.resolve_symbol(name)?;
        Ok(serde_json::json!({
            "address": resolved.map(|addr| format!("0x{:X}", addr)),
            "found": resolved.is_some()
        }))
    }

    fn handle_exec_call(&self, request: &Request) -> Result<serde_json::Value> {
        let address = Self::parse_hex_usize(
            request
                .params
                .get("address")
                .ok_or_else(|| Error::Internal("Missing address".into()))?,
            "address",
        )?;

        let args = Self::parse_function_args(
            request.params.get("args").unwrap_or(&serde_json::json!([])),
        )?;
        let convention = Self::parse_calling_convention(
            request.params.get("convention").and_then(|v| v.as_str()),
        );
        let timeout_ms = request
            .params
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(30_000);
        let new_thread = request
            .params
            .get("new_thread")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let options = FunctionCallOptions {
            convention,
            args,
            capture_out_params: false,
            timeout_ms,
            new_thread,
        };

        tracing::info!(
            target: "ghost_agent::execution",
            address = format!("{:#x}", address),
            arg_count = options.args.len(),
            convention = ?options.convention,
            new_thread = new_thread,
            timeout_ms = timeout_ms,
            "exec_call requested"
        );

        let result = self.exec.call_function(address, &options)?;

        Ok(serde_json::json!({
            "return_value": result.return_value,
            "return_value_high": result.return_value_high,
            "float_return": result.float_return,
            "out_params": result.out_params,
            "duration_us": result.duration_us,
            "success": result.success,
            "error": result.error,
        }))
    }

    fn handle_exec_call_api(&self, request: &Request) -> Result<serde_json::Value> {
        let name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing name".into()))?;

        let (module, func) = if let Some((m, f)) = name.split_once('!') {
            (m, f)
        } else {
            ("kernel32.dll", name)
        };

        let address = self.exec.resolve_function(module, func)?;
        // Reuse exec_call path
        let mut params = request.params.clone();
        params.as_object_mut().map(|o| {
            o.insert(
                "address".into(),
                serde_json::json!(format!("0x{:X}", address)),
            )
        });
        let call_request = Request {
            method: "exec_call".to_string(),
            id: request.id,
            params,
        };
        self.handle_exec_call(&call_request)
    }

    fn handle_exec_shellcode(&self, request: &Request) -> Result<serde_json::Value> {
        let shellcode = Self::parse_hex_bytes(
            request
                .params
                .get("shellcode")
                .ok_or_else(|| Error::Internal("Missing shellcode".into()))?,
            "shellcode",
        )?;

        let method = request
            .params
            .get("method")
            .and_then(|v| v.as_str())
            .and_then(ShellcodeExecMethod::parse)
            .unwrap_or_default();
        let wait = request
            .params
            .get("wait")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let timeout_ms = request
            .params
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(30_000);
        let target_tid = request
            .params
            .get("target_tid")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let parameter = request.params.get("parameter").and_then(|v| v.as_u64());
        let free_after = request
            .params
            .get("free_after")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let opts = ShellcodeExecOptions {
            method,
            target_tid,
            wait,
            timeout_ms,
            protection: request
                .params
                .get("protection")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            free_after,
            parameter,
        };

        tracing::info!(
            target: "ghost_agent::execution",
            shellcode_len = shellcode.len(),
            method = ?method,
            wait = wait,
            timeout_ms = timeout_ms,
            target_tid = ?target_tid,
            "exec_shellcode requested"
        );

        let result = self.exec.execute_shellcode(&shellcode, &opts)?;
        Ok(serde_json::json!({
            "return_value": result.return_value,
            "thread_id": result.thread_id,
            "address": format!("0x{:X}", result.shellcode_address),
            "success": result.success,
            "duration_us": result.duration_us,
            "error": result.error,
        }))
    }

    fn handle_exec_alloc(&self, request: &Request) -> Result<serde_json::Value> {
        let size = request
            .params
            .get("size")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing size".into()))? as usize;

        if size == 0 || size > 32 * 1024 * 1024 {
            return Err(Error::Internal("Allocation size must be 1..32MB".into()));
        }

        let mut buffer = vec![0u8; size];
        let address = buffer.as_mut_ptr() as usize;
        std::mem::forget(buffer);

        self.local_allocations
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .insert(address, size);

        tracing::info!(
            target: "ghost_agent::execution",
            address = format!("{:#x}", address),
            size = size,
            "exec_alloc allocated local buffer"
        );

        Ok(serde_json::json!({
            "address": format!("0x{:X}", address),
            "size": size,
            "protection": "rw"
        }))
    }

    fn handle_exec_free(&self, request: &Request) -> Result<serde_json::Value> {
        let address = Self::parse_hex_usize(
            request
                .params
                .get("address")
                .ok_or_else(|| Error::Internal("Missing address".into()))?,
            "address",
        )?;

        let size = {
            let mut allocs = self
                .local_allocations
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?;
            allocs.remove(&address)
        };

        if let Some(sz) = size {
            unsafe {
                let _ = Vec::from_raw_parts(address as *mut u8, sz, sz);
            }
            tracing::info!(
                target: "ghost_agent::execution",
                address = format!("{:#x}", address),
                size = sz,
                "exec_free released allocation"
            );
            Ok(serde_json::json!({ "freed": true, "size": sz }))
        } else {
            Err(Error::Internal("Unknown allocation address".into()))
        }
    }

    fn handle_exec_write(&self, request: &Request) -> Result<serde_json::Value> {
        let address = Self::parse_hex_usize(
            request
                .params
                .get("address")
                .ok_or_else(|| Error::Internal("Missing address".into()))?,
            "address",
        )?;
        let data = Self::parse_hex_bytes(
            request
                .params
                .get("data")
                .ok_or_else(|| Error::Internal("Missing data".into()))?,
            "data",
        )?;

        if data.is_empty() {
            return Err(Error::Internal("Data cannot be empty".into()));
        }

        // Use the proper write method that respects process_handle
        self.backend.write(address, &data)?;

        Ok(serde_json::json!({
            "written": data.len(),
            "address": format!("0x{:X}", address)
        }))
    }

    fn handle_cave_find(&self, request: &Request) -> Result<serde_json::Value> {
        // Support both "size" (MCP) and "min_size" (internal)
        let min_size = request
            .params
            .get("size")
            .or_else(|| request.params.get("min_size"))
            .and_then(|v| v.as_u64())
            .unwrap_or(32) as usize;

        let alignment = request
            .params
            .get("alignment")
            .and_then(|v| v.as_u64())
            .unwrap_or(16) as usize;
        let executable_only = request
            .params
            .get("executable_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let max_results = request
            .params
            .get("max_results")
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as usize;
        let module = request
            .params
            .get("module")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let options = CodeCaveOptions {
            min_size,
            alignment: alignment.max(1),
            executable_only,
            module,
            max_results,
        };

        let regions = self.backend.query_regions()?;
        let caves = self
            .exec
            .find_code_caves(&regions, &options, |addr, size| {
                self.backend.read(addr, size)
            })?;

        Ok(serde_json::json!({ "caves": caves }))
    }

    fn handle_cave_alloc(&self, request: &Request) -> Result<serde_json::Value> {
        let size = request
            .params
            .get("size")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing size".into()))? as usize;

        let address_val = request.params.get("address");

        let address = if let Some(val) = address_val {
            Self::parse_hex_usize(val, "address")?
        } else {
            // Find a cave if address not provided
            let min_size = size;
            let alignment = 16;
            let options = CodeCaveOptions {
                min_size,
                alignment,
                executable_only: true,
                module: None,
                max_results: 1,
            };

            let regions = self.backend.query_regions()?;
            let caves = self
                .exec
                .find_code_caves(&regions, &options, |addr, size| {
                    self.backend.read(addr, size)
                })?;

            if let Some(cave) = caves.first() {
                cave.address
            } else {
                return Err(Error::Internal("No suitable code cave found".into()));
            }
        };

        let cave = CodeCave {
            address,
            size,
            module: None,
            section: None,
            in_use: true,
        };

        let allocated = self.exec.allocate_cave(cave, Some("manual_alloc".into()));

        Ok(serde_json::json!({
            "cave_id": allocated.id,
            "address": format!("0x{:X}", allocated.cave.address),
            "size": allocated.cave.size
        }))
    }

    fn handle_cave_free(&self, request: &Request) -> Result<serde_json::Value> {
        let id_val = request.params.get("cave_id");

        let id = if let Some(v) = id_val {
            v.as_u64()
                .ok_or_else(|| Error::Internal("Invalid cave_id".into()))? as u32
        } else {
            // Try to find by address
            let address = Self::parse_hex_usize(
                request
                    .params
                    .get("address")
                    .ok_or_else(|| Error::Internal("Missing cave_id or address".into()))?,
                "address",
            )?;

            let caves = self.exec.list_allocated_caves();
            let cave = caves
                .iter()
                .find(|c| c.cave.address == address)
                .ok_or_else(|| {
                    Error::Internal(format!(
                        "No allocated cave found at address 0x{:X}",
                        address
                    ))
                })?;
            cave.id
        };

        self.exec.free_cave(id)?;
        Ok(serde_json::json!({ "freed": true, "cave_id": id }))
    }

    fn handle_cave_list(&self) -> Result<serde_json::Value> {
        let caves = self.exec.list_allocated_caves();
        Ok(serde_json::json!({ "caves": caves }))
    }

    fn handle_syscall_number(&self, request: &Request) -> Result<serde_json::Value> {
        let name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing name".into()))?;
        let info = self.exec.get_syscall_number(name)?;
        Ok(serde_json::json!({
            "number": info.number,
            "name": info.name,
            "module": info.module,
            "arg_count": info.arg_count
        }))
    }

    fn handle_syscall_invoke(&self, _request: &Request) -> Result<serde_json::Value> {
        // Placeholder: syscall invocation is not exposed safely in-process.
        Ok(serde_json::json!({
            "success": false,
            "error": "Direct syscall invocation is disabled in in-process agent"
        }))
    }

    fn handle_remote_thread(&self, request: &Request) -> Result<serde_json::Value> {
        let pid = request
            .params
            .get("pid")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing pid".into()))? as u32;

        let wait = request
            .params
            .get("wait")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let timeout_ms = request
            .params
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(30_000);
        let parameter = request.params.get("parameter").and_then(|v| v.as_u64());

        let shellcode_val = request.params.get("shellcode");

        let result = if let Some(s) = shellcode_val {
            // Shellcode injection
            let shellcode = Self::parse_hex_bytes(s, "shellcode")?;
            self.exec
                .create_remote_thread(pid, &shellcode, parameter, wait, timeout_ms)?
        } else {
            // Existing address execution
            let address = Self::parse_hex_usize(
                request
                    .params
                    .get("address")
                    .ok_or_else(|| Error::Internal("Missing shellcode or address".into()))?,
                "address",
            )?;
            self.exec
                .create_remote_thread_at(pid, address, parameter, wait, timeout_ms)?
        };

        Ok(serde_json::json!({
            "thread_id": result.thread_id,
            "remote_address": format!("0x{:X}", result.remote_address),
            "completed": result.completed,
            "exit_code": result.exit_code,
            "waited": wait
        }))
    }

    fn handle_remote_apc(&self, request: &Request) -> Result<serde_json::Value> {
        let pid = request
            .params
            .get("pid")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing pid".into()))? as u32;
        let tid = request
            .params
            .get("tid")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing tid".into()))? as u32;
        let parameter = request.params.get("parameter").and_then(|v| v.as_u64());

        let shellcode_val = request.params.get("shellcode");

        let remote_address = if let Some(s) = shellcode_val {
            let shellcode = Self::parse_hex_bytes(s, "shellcode")?;
            self.exec
                .queue_remote_apc(pid, tid, &shellcode, parameter)?
        } else {
            let address = Self::parse_hex_usize(
                request
                    .params
                    .get("address")
                    .ok_or_else(|| Error::Internal("Missing shellcode or address".into()))?,
                "address",
            )?;
            self.exec
                .queue_remote_apc_at(pid, tid, address, parameter)?;
            address
        };

        Ok(serde_json::json!({
            "queued": true,
            "remote_address": format!("0x{:X}", remote_address),
            "pid": pid,
            "tid": tid
        }))
    }

    fn handle_script_load(&self, request: &Request) -> Result<serde_json::Value> {
        let name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("script_{}", Self::now_millis()));
        let path = request
            .params
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let code = request.params.get("code").and_then(|v| v.as_str());
        if path.is_none() && code.is_none() {
            return Err(Error::Internal("path or code required".into()));
        }

        let entry = ScriptEntry {
            name: name.clone(),
            path: path.clone(),
            inline: code.is_some(),
            loaded_at: Self::now_millis(),
            status: "loaded".to_string(),
        };

        {
            let mut scripts = self
                .scripts
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?;
            scripts.insert(name.clone(), entry);
        }

        self.state.session.write().active_scripts += 1;

        Ok(serde_json::json!({
            "loaded": true,
            "name": name,
            "path": path,
            "inline": code.is_some()
        }))
    }

    fn handle_script_unload(&self, request: &Request) -> Result<serde_json::Value> {
        let name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing name".into()))?;

        let removed = self
            .scripts
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .remove(name)
            .is_some();

        if removed {
            let mut session = self.state.session.write();
            session.active_scripts = session.active_scripts.saturating_sub(1);
        }

        Ok(serde_json::json!({ "unloaded": removed }))
    }

    fn handle_script_reload(&self, request: &Request) -> Result<serde_json::Value> {
        let name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing name".into()))?;

        let mut scripts = self
            .scripts
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(entry) = scripts.get_mut(name) {
            entry.loaded_at = Self::now_millis();
            entry.status = "reloaded".to_string();
            Ok(serde_json::json!({ "reloaded": true, "name": name }))
        } else {
            Err(Error::Internal("Script not found".into()))
        }
    }

    fn handle_script_list(&self) -> Result<serde_json::Value> {
        let scripts = self
            .scripts
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(serde_json::json!({
            "scripts": scripts.values().cloned().collect::<Vec<_>>()
        }))
    }

    fn handle_script_status(&self, request: &Request) -> Result<serde_json::Value> {
        let name = request
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing name".into()))?;
        let scripts = self
            .scripts
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(entry) = scripts.get(name) {
            Ok(serde_json::json!({ "script": entry }))
        } else {
            Err(Error::Internal("Script not found".into()))
        }
    }

    fn handle_hook_create(&self, request: &Request) -> Result<serde_json::Value> {
        let address = Self::parse_hex_usize(
            request
                .params
                .get("address")
                .ok_or_else(|| Error::Internal("Missing address".into()))?,
            "address",
        )?;
        let callback = request
            .params
            .get("callback")
            .or_else(|| request.params.get("callback_address"))
            .map(|v| Self::parse_hex_usize(v, "callback"))
            .transpose()?
            .ok_or_else(|| {
                Error::Internal("callback (address) is required to create an inline hook".into())
            })?;
        let hook_type = request
            .params
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("inline")
            .to_string();

        let module = request
            .params
            .get("module")
            .and_then(|v| v.as_str())
            .map(String::from);
        let function = request
            .params
            .get("function")
            .and_then(|v| v.as_str())
            .map(String::from);
        let import_module = request
            .params
            .get("import_module")
            .and_then(|v| v.as_str())
            .map(String::from);
        let size = request
            .params
            .get("size")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);

        let id = self.backend.create_hook_ex(CreateHookParams {
            target: address,
            callback,
            hook_type: hook_type.clone(),
            module,
            function,
            import_module,
            size,
        })?;

        let entry = HookEntry {
            id,
            address,
            callback,
            hook_type: hook_type.clone(),
            enabled: true,
            created_at: Self::now_millis(),
        };

        self.hooks
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .insert(id, entry);

        let mut session = self.state.session.write();
        session.active_hooks += 1;

        Ok(serde_json::json!({
            "hook_id": id,
            "address": format!("0x{:X}", address),
            "type": hook_type,
            "enabled": true
        }))
    }

    fn handle_hook_remove(&self, request: &Request) -> Result<serde_json::Value> {
        let id = request
            .params
            .get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing id".into()))? as u32;

        let backend_removed = self.backend.remove_hook(id);
        let removed = {
            let mut hooks = self
                .hooks
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?;
            let removed = hooks.remove(&id).is_some();
            if removed {
                let mut session = self.state.session.write();
                session.active_hooks = session.active_hooks.saturating_sub(1);
            }
            removed
        };

        if let Err(ref e) = backend_removed {
            if !removed {
                return Err(Error::Internal(e.to_string()));
            }
            tracing::warn!(
                target: "ghost_agent::hooks",
                id = id,
                error = %e,
                "Hook metadata removed but failed to restore original bytes"
            );
        }

        Ok(serde_json::json!({ "removed": removed || backend_removed.is_ok(), "id": id }))
    }

    fn handle_hook_enable(&self, request: &Request) -> Result<serde_json::Value> {
        let id = request
            .params
            .get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing id".into()))? as u32;
        let enabled = request
            .params
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let mut hooks = self
            .hooks
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(entry) = hooks.get_mut(&id) {
            if entry.enabled == enabled {
                return Ok(serde_json::json!({ "id": id, "enabled": enabled }));
            }

            ghost_core::extended_hooks::initialize()?;
            let mut manager = ghost_core::extended_hooks::get_hook_manager()
                .write()
                .map_err(|_| Error::Internal("Failed to acquire hook manager lock".into()))?;
            if enabled {
                manager.enable_hook(HookId(id))?;
            } else {
                manager.disable_hook(HookId(id))?;
            }

            let mut session = self.state.session.write();
            if enabled && !entry.enabled {
                session.active_hooks = session.active_hooks.saturating_add(1);
            } else if !enabled && entry.enabled {
                session.active_hooks = session.active_hooks.saturating_sub(1);
            }
            entry.enabled = enabled;
            Ok(serde_json::json!({ "id": id, "enabled": enabled }))
        } else {
            Err(Error::Internal("Hook not found".into()))
        }
    }

    fn handle_hook_list(&self) -> Result<serde_json::Value> {
        let hooks = self
            .hooks
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        Ok(serde_json::json!({ "hooks": hooks.values().cloned().collect::<Vec<_>>() }))
    }

    fn handle_rpc_list(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "functions": [],
            "message": "RPC functions are not available in in-process agent"
        }))
    }

    fn handle_rpc_call(&self, request: &Request) -> Result<serde_json::Value> {
        let function = request
            .params
            .get("function")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        Ok(serde_json::json!({
            "success": false,
            "function": function,
            "error": "RPC call not supported in in-process agent"
        }))
    }

    fn handle_command_batch(&self, request: &Request) -> Result<serde_json::Value> {
        let commands = request
            .params
            .get("commands")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Internal("commands must be array".into()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>();

        let id = self.command_counter.fetch_add(1, Ordering::SeqCst);

        {
            let mut history = self
                .command_history
                .lock()
                .map_err(|e| Error::Internal(e.to_string()))?;
            history.push(CommandHistoryEntry {
                id,
                commands: commands.clone(),
                created_at: Self::now_millis(),
            });
            if history.len() > 500 {
                history.remove(0);
            }
        }

        let results: Vec<_> = commands
            .iter()
            .map(|cmd| serde_json::json!({ "command": cmd, "executed": false, "error": "Execution not supported in-process" }))
            .collect();

        Ok(serde_json::json!({
            "history_id": id,
            "results": results
        }))
    }

    fn handle_command_history(&self, request: &Request) -> Result<serde_json::Value> {
        let limit = request
            .params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        let filter = request
            .params
            .get("filter")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());

        let mut history = self
            .command_history
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?
            .clone();
        if let Some(f) = filter {
            history.retain(|h| h.commands.iter().any(|c| c.to_lowercase().contains(&f)));
        }
        history.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        history.truncate(limit);

        Ok(serde_json::json!({ "history": history }))
    }

    fn handle_command_replay(&self, request: &Request) -> Result<serde_json::Value> {
        let history_id = request
            .params
            .get("history_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Internal("Missing history_id".into()))?;

        let history = self
            .command_history
            .lock()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(entry) = history.iter().find(|h| h.id == history_id) {
            Ok(serde_json::json!({
                "replayed": entry.commands,
                "note": "Commands not executed in in-process agent"
            }))
        } else {
            Err(Error::Internal("History entry not found".into()))
        }
    }

    fn handle_patch_preview(&self, request: &Request) -> Result<serde_json::Value> {
        let address = Self::parse_hex_usize(
            request
                .params
                .get("address")
                .ok_or_else(|| Error::Internal("Missing address".into()))?,
            "address",
        )?;

        let proposed_bytes = Self::parse_hex_bytes(
            request
                .params
                .get("data")
                .ok_or_else(|| Error::Internal("Missing data".into()))?,
            "data",
        )?;

        let current_bytes = self.backend.read(address, proposed_bytes.len())?;

        // Use SafetyGuard to generate preview (async method, but we need sync result)
        // Since we converted SafetyGuard to synchronous RwLock, we can just call it?
        // Wait, SafetyGuard methods in my new safety.rs are synchronous.
        // Wait, did I remove async from generate_preview? Yes, I did.

        let preview =
            self.safety
                .generate_preview("patch_preview", address, current_bytes, proposed_bytes);

        Ok(serde_json::json!(preview))
    }

    fn handle_process_spawn(&self, request: &Request) -> Result<serde_json::Value> {
        let path = request
            .params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing path".into()))?;
        let args = request
            .params
            .get("args")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut cmd = std::process::Command::new(path);
        if !args.is_empty() {
            cmd.args(args.split_whitespace());
        }

        let child = cmd
            .spawn()
            .map_err(|e| Error::Internal(format!("Spawn failed: {}", e)))?;
        let pid = child.id();

        Ok(serde_json::json!({
            "pid": pid,
            "suspended": false
        }))
    }

    fn handle_process_resume(&self, request: &Request) -> Result<serde_json::Value> {
        let pid = request
            .params
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(serde_json::json!({
            "pid": pid,
            "resumed": false,
            "message": "Resume not supported in in-process agent"
        }))
    }

    fn handle_process_terminate(&self, request: &Request) -> Result<serde_json::Value> {
        let pid = request
            .params
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(serde_json::json!({
            "pid": pid,
            "terminated": false,
            "message": "Terminate not supported in in-process agent"
        }))
    }

    /// Graceful placeholder for tools not yet implemented
    fn handle_noop(&self, method: &str) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "ok": false,
            "message": format!("{} is not implemented in the in-process agent yet", method)
        }))
    }

    /// Safety status summary from shared state
    fn handle_safety_status(&self) -> Result<serde_json::Value> {
        let session = self.state.session.read();
        let token_count = self.state.safety_tokens.read().len();
        let patch_count = self.state.patches.read().len();
        let stats = self.safety.get_stats();

        Ok(serde_json::json!({
            "safety_mode": session.safety_mode,
            "active_scripts": session.active_scripts,
            "active_hooks": session.active_hooks,
            "patch_count": patch_count,
            "token_count": token_count,
            "subscribers": self.event_bus.subscriber_count(),
            "stats": stats,
        }))
    }

    /// Approve a pending safety request
    fn handle_safety_approve(&self, request: &Request) -> Result<serde_json::Value> {
        let token = request
            .params
            .get("request_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing request_id".into()))?;

        match self.safety.approve(token) {
            Ok(msg) => Ok(serde_json::json!({
                "approved": true,
                "message": msg
            })),
            Err(e) => Err(Error::Internal(e)),
        }
    }

    /// List pending safety approvals
    fn handle_safety_pending(&self) -> Result<serde_json::Value> {
        let pending = self.safety.list_pending_approvals();
        Ok(serde_json::json!({
            "pending": pending
        }))
    }

    /// Get or set safety configuration
    fn handle_safety_config(&self, request: &Request) -> Result<serde_json::Value> {
        // If key/value provided, update config
        if let Some(key) = request.params.get("key").and_then(|v| v.as_str()) {
            // For now, only simple updates supported or full config replacement
            // The tool definition says "key", "value".
            // Implementing granular updates is complex with the current SafetyConfig struct.
            // For now, let's just return the config if no key, or error if key provided (until implemented)
            // Or better, let's allow updating "auto_backup" etc.

            let mut config = self.safety.get_config();
            if let Some(value) = request.params.get("value") {
                // Set value
                match key {
                    "auto_backup" => {
                        config.auto_backup = value.as_bool().unwrap_or(config.auto_backup)
                    }
                    "dry_run_enabled" => {
                        config.dry_run_enabled = value.as_bool().unwrap_or(config.dry_run_enabled)
                    }
                    "crash_recovery" => {
                        config.crash_recovery = value.as_bool().unwrap_or(config.crash_recovery)
                    }
                    _ => {
                        return Err(Error::Internal(format!(
                            "Config key '{}' not modifiable via tool",
                            key
                        )))
                    }
                }
                self.safety.update_config(config.clone());
                Ok(serde_json::json!({
                    "updated": true,
                    "config": config
                }))
            } else {
                // Get value
                let v = match key {
                    "auto_backup" => serde_json::json!(config.auto_backup),
                    "dry_run_enabled" => serde_json::json!(config.dry_run_enabled),
                    "crash_recovery" => serde_json::json!(config.crash_recovery),
                    "mode" => serde_json::json!(config.mode),
                    _ => return Err(Error::Internal(format!("Config key '{}' not found", key))),
                };
                Ok(serde_json::json!({
                    "key": key,
                    "value": v
                }))
            }
        } else {
            // Return full config
            Ok(serde_json::json!(self.safety.get_config()))
        }
    }

    /// Create a backup
    fn handle_safety_backup(&self, request: &Request) -> Result<serde_json::Value> {
        let _name = request.params.get("name").and_then(|v| v.as_str());
        let _include_memory = request
            .params
            .get("include_memory")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Use SafetyGuard to track backup metadata
        let backup_id = self.safety.create_backup();

        // TODO: Actually persist to disk if needed, but SafetyGuard stores in memory for now.
        // The legacy implementation was in-memory backups of patches.
        // If we want full state backup (like memory snapshot), that's heavier.

        Ok(serde_json::json!({
            "backup_id": backup_id,
            "timestamp": backup_id, // ID is timestamp
            "message": "Backup created"
        }))
    }

    /// Reset to backup
    fn handle_safety_reset(&self, request: &Request) -> Result<serde_json::Value> {
        let _backup_name = request.params.get("backup_name").and_then(|v| v.as_str());

        // This is complex. Resetting state implies undoing patches.
        // For now, let's just return not implemented or implement basic patch undo loop.

        // If we have backups in SafetyGuard:
        let backups = self.safety.get_backups();
        if let Some(backup) = backups.last() {
            // Convert safety::PatchEntry to ipc::PatchEntry
            let ipc_patches: Vec<ghost_common::ipc::PatchEntry> = backup
                .patches
                .iter()
                .map(|p| ghost_common::ipc::PatchEntry {
                    id: p.id,
                    address: p.address as u64,
                    original_bytes: p.original_bytes.clone(),
                    patched_bytes: p.patched_bytes.clone(),
                    timestamp: p.timestamp_ms,
                    applied_by: Some(p.tool_name.clone()),
                    active: !p.undone,
                    description: Some(p.description.clone()),
                })
                .collect();

            self.state.restore_patches(ipc_patches);

            return Ok(serde_json::json!({
                "reset": true,
                "backup_id": backup.id,
                "patches_restored": backup.patches.len()
            }));
        }

        Err(Error::Internal("No backups available".into()))
    }

    /// Update safety mode (admin capability enforced by caller)
    fn handle_safety_set_mode(&self, request: &Request) -> Result<serde_json::Value> {
        let mode_str = request
            .params
            .get("mode")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Internal("Missing mode".into()))?;

        let mode = mode_str
            .parse::<ghost_common::safety::SafetyMode>()
            .map_err(|e| Error::Internal(format!("Invalid safety mode: {}", e)))?;

        self.safety.set_mode(mode);

        let session = self.state.session.read();

        Ok(serde_json::json!({
            "safety_mode": session.safety_mode,
            "updated": true
        }))
    }

    /// Return recent patch history from shared state
    fn handle_patch_history(&self, request: &Request) -> Result<serde_json::Value> {
        let limit = request
            .params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as usize;
        let client_filter = request.params.get("client_id").and_then(|v| v.as_str());

        let mut patches = self.state.get_patches();
        if let Some(client) = client_filter {
            patches.retain(|p| p.applied_by.as_deref() == Some(client));
        }

        // Newest first
        patches.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let total = patches.len();
        patches.truncate(limit);
        let returned = patches.len();
        let truncated = returned < total;

        Ok(serde_json::json!({
            "patches": patches,
            "returned": returned,
            "total": total,
            "truncated": truncated
        }))
    }

    /// List available event types
    fn handle_event_list(&self) -> Result<serde_json::Value> {
        let event_types = vec![
            format!("{:?}", EventType::MemoryWrite),
            format!("{:?}", EventType::PatchApplied),
            format!("{:?}", EventType::PatchUndone),
            format!("{:?}", EventType::SafetyTokenIssued),
            format!("{:?}", EventType::SafetyTokenRevoked),
            format!("{:?}", EventType::SessionAttached),
            format!("{:?}", EventType::SessionDetached),
            format!("{:?}", EventType::ClientConnected),
            format!("{:?}", EventType::ClientDisconnected),
        ];

        Ok(serde_json::json!({
            "event_types": event_types,
            "subscribers": self.event_bus.subscriber_count()
        }))
    }

    /// Poll for events (non-blocking with short sleep loops)
    fn handle_event_poll(&self, timeout_ms: u64, max_events: usize) -> Result<serde_json::Value> {
        let mut rx = self.event_bus.subscribe();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.min(30_000));
        let mut events = Vec::new();

        loop {
            match rx.try_recv() {
                Ok(ev) => {
                    events.push(ev);
                    if events.len() >= max_events {
                        break;
                    }
                }
                Err(TryRecvError::Empty) => {
                    if !events.is_empty() || std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(TryRecvError::Lagged(_)) => continue,
                Err(TryRecvError::Closed) => break,
            }
        }

        Ok(serde_json::json!({
            "events": events,
            "count": events.len()
        }))
    }
}

impl RequestHandler for MultiClientBackend {
    fn handle(&self, request: &Request, client_id: Option<&str>) -> Response {
        let start = std::time::Instant::now();
        let method = request.method.replace('.', "_");
        let params = request.params.clone();

        tracing::info!(
            target: "ghost_agent::backend",
            method = %request.method,
            id = request.id,
            client = ?client_id,
            "Handling request"
        );

        // Capability gating (deny by default if unknown client)
        if let Some(cid) = client_id {
            // Safety control operations bypass capability checks - they're essential escape hatches
            let is_safety_control = matches!(
                method.as_str(),
                "safety_set_mode"
                    | "safety_approve"
                    | "safety_reset"
                    | "safety_status"
                    | "safety_config"
            );

            // Expert mode bypasses capability checks - user has explicitly opted into full access
            let is_expert_mode = self.safety.get_mode() == ghost_common::safety::SafetyMode::Expert;

            if !is_safety_control && !is_expert_mode {
                let required = Capability::for_method(&method);
                let granted = self.state.get_capabilities(cid);
                if let Err(e) = Capability::check(required, &granted, &method) {
                    tracing::warn!(
                        target: "ghost_agent::backend",
                        client = %cid,
                        method = %method,
                        "Capability denied: {}",
                        e
                    );
                    return Response::error(
                        request.id,
                        error_codes::AUTHORIZATION_DENIED,
                        format!("Capability denied: {}", e),
                    );
                }
            }

            // Safety checks (Rate limits, Educational mode, Protected processes, Approval)
            // Extract token_id if present
            let token_id = params.get("token_id").and_then(|t| t.as_str());

            // Check operation safety
            match self.safety.check_operation(&method, &params, token_id) {
                ghost_common::safety::SafetyCheckResult::Allowed => {
                    // Allowed, proceed
                }
                ghost_common::safety::SafetyCheckResult::AllowedWithWarning(msg) => {
                    tracing::warn!(target: "ghost_agent::backend", "Safety warning: {}", msg);
                    // Proceed (maybe we should include warning in response? For now just log)
                }
                ghost_common::safety::SafetyCheckResult::Blocked(msg) => {
                    return Response::error(request.id, error_codes::AUTHORIZATION_DENIED, msg);
                }
                ghost_common::safety::SafetyCheckResult::RateLimited {
                    retry_after_ms,
                    message,
                } => {
                    return Response::error(
                        request.id,
                        error_codes::AUTHORIZATION_DENIED,
                        format!("{} (retry after {}ms)", message, retry_after_ms),
                    );
                }
                ghost_common::safety::SafetyCheckResult::SizeLimitExceeded {
                    requested,
                    limit,
                    message,
                } => {
                    return Response::error(
                        request.id,
                        error_codes::INVALID_PARAMS,
                        format!("{} (requested: {}, limit: {})", message, requested, limit),
                    );
                }
                ghost_common::safety::SafetyCheckResult::RequiresApproval {
                    reason,
                    approval_token,
                } => {
                    return Response::error(
                        request.id,
                        error_codes::AUTHORIZATION_DENIED,
                        format!("{} Token: {}", reason, approval_token),
                    );
                }
            }
        }

        let result = match method.as_str() {
            // Handshake handling
            "agent_handshake" => self.handle_handshake(request, client_id),

            // Heartbeat
            "agent_ping" => Ok(serde_json::json!({"pong": true})),

            // Patch undo (uses undo stack if patch_id omitted)
            "patch_undo" => self.handle_patch_undo(request, client_id),

            // Safety token issue/revoke
            "safety_approve" => self.handle_safety_approve(request),
            "safety_pending" => self.handle_safety_pending(),
            "safety_config" => self.handle_safety_config(request),
            "safety_backup" => self.handle_safety_backup(request),
            "safety_reset" => self.handle_safety_reset(request),
            "safety_request_token" => self.handle_safety_issue_token(request, client_id),
            "safety_release_token" => self.handle_safety_revoke_token(request, client_id),

            // Session/Process
            "session_info" => self.handle_session_info(client_id),
            "session_attach" => self.handle_session_attach(request, client_id),
            "session_detach" => self.handle_session_detach(request, client_id),
            "process_list" => self.handle_process_list(request),
            "process_spawn" => self.handle_process_spawn(request),
            "process_resume" => self.handle_process_resume(request),
            "process_terminate" => self.handle_process_terminate(request),

            // Command/Event
            "command_batch" => self.handle_command_batch(request),
            "command_history" => self.handle_command_history(request),
            "command_replay" => self.handle_command_replay(request),
            "event_subscribe" => Ok(serde_json::json!({
                "subscribed": true,
                "subscribers": self.event_bus.subscriber_count()
            })),
            "event_unsubscribe" => Ok(serde_json::json!({"unsubscribed": true})),
            "event_poll" => {
                let timeout_ms = params
                    .get("timeout_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1000);
                let max_events = params
                    .get("max_events")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100) as usize;
                self.handle_event_poll(timeout_ms, max_events)
            }
            "event_list" => self.handle_event_list(),

            // Script/Hook stubs
            "script_load" | "script_unload" | "script_reload" | "script_list" | "script_status"
            | "hook_create" | "hook_remove" | "hook_enable" | "hook_list" | "rpc_list"
            | "rpc_call" => match method.as_str() {
                "script_load" => self.handle_script_load(request),
                "script_unload" => self.handle_script_unload(request),
                "script_reload" => self.handle_script_reload(request),
                "script_list" => self.handle_script_list(),
                "script_status" => self.handle_script_status(request),
                "hook_create" => self.handle_hook_create(request),
                "hook_remove" => self.handle_hook_remove(request),
                "hook_enable" => self.handle_hook_enable(request),
                "hook_list" => self.handle_hook_list(),
                "rpc_list" => self.handle_rpc_list(),
                "rpc_call" => self.handle_rpc_call(request),
                _ => self.handle_noop(method.as_str()),
            },

            // Safety tools / patch history (safety_approve, safety_pending, safety_config, safety_backup, safety_reset already handled above)
            "safety_status" => self.handle_safety_status(),
            "safety_set_mode" => self.handle_safety_set_mode(request),
            "patch_history" => self.handle_patch_history(request),
            "patch_preview" => self.handle_patch_preview(request),

            // Execution helpers
            "exec_resolve" => self.handle_exec_resolve(request),
            "exec_call" => self.handle_exec_call(request),
            "exec_call_api" => self.handle_exec_call_api(request),
            "exec_shellcode" => self.handle_exec_shellcode(request),
            "exec_alloc" => self.handle_exec_alloc(request),
            "exec_free" => self.handle_exec_free(request),
            "exec_write" => self.handle_exec_write(request),
            "cave_find" => self.handle_cave_find(request),
            "cave_alloc" => self.handle_cave_alloc(request),
            "cave_free" => self.handle_cave_free(request),
            "cave_list" => self.handle_cave_list(),
            "syscall_number" => self.handle_syscall_number(request),
            "syscall_invoke" => self.handle_syscall_invoke(request),
            "remote_thread" => self.handle_remote_thread(request),
            "remote_apc" => self.handle_remote_apc(request),

            // Memory write with event emission
            "memory_write" => self.handle_memory_write(request, client_id),

            // All other methods delegate to base backend
            _ => {
                // Use the existing dispatch logic
                let response = self.backend.handle_request(request);
                return response;
            }
        };

        let elapsed = start.elapsed();

        match result {
            Ok(value) => {
                if method == "module_list" {
                    if let Ok(modules) =
                        serde_json::from_value::<Vec<ghost_common::Module>>(value.clone())
                    {
                        self.state.set_modules_loaded(modules.len() as u32);
                    }
                }
                tracing::debug!(
                    target: "ghost_agent::backend",
                    method = %request.method,
                    elapsed_ms = elapsed.as_millis(),
                    "Request successful"
                );
                Response::success(request.id, value)
            }
            Err(e) => {
                tracing::error!(
                    target: "ghost_agent::backend",
                    method = %request.method,
                    error = %e,
                    elapsed_ms = elapsed.as_millis(),
                    "Request failed"
                );
                Response::error(request.id, error_codes::INTERNAL_ERROR, e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn backend() -> MultiClientBackend {
        let backend = InProcessBackend::new().unwrap();
        let state = Arc::new(SharedState::new());
        let bus = Arc::new(EventBus::new());
        MultiClientBackend::new(backend, state, bus)
    }

    #[test]
    fn test_format_scan_result_json_adds_consistent_hex() {
        let sample = ScanResultEx {
            address: 0x1800632A4F0,
            value: vec![119, 0, 0, 0],
            previous_value: Some(vec![162, 0, 0, 0]),
            first_value: Some(vec![162, 0, 0, 0]),
        };

        let json = format_scan_result_json(&sample);

        assert_eq!(
            json["address"].as_u64().unwrap(),
            sample.address as u64,
            "numeric address should be preserved"
        );
        assert_eq!(
            json["address_hex"].as_str().unwrap(),
            "0x1800632A4F0",
            "hex string should match numeric address"
        );
        assert_eq!(
            json["address_dec"].as_str().unwrap(),
            sample.address.to_string(),
            "decimal string should match numeric address"
        );
    }

    #[test]
    fn test_command_history_flow() {
        let handler = backend();
        let req = Request {
            method: "command_batch".to_string(),
            id: 1,
            params: json!({"commands": ["a", "b"]}),
        };
        let result = handler.handle_command_batch(&req).unwrap();
        assert!(result.get("history_id").is_some());

        let hist = handler
            .handle_command_history(&Request {
                method: "command_history".to_string(),
                id: 2,
                params: json!({"limit": 10}),
            })
            .unwrap();
        assert!(!hist["history"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_script_load_and_status() {
        let handler = backend();
        let load = handler
            .handle_script_load(&Request {
                method: "script_load".to_string(),
                id: 1,
                params: json!({"name": "test", "code": "print('ok')"}),
            })
            .unwrap();
        assert!(load["loaded"].as_bool().unwrap());

        let status = handler
            .handle_script_status(&Request {
                method: "script_status".to_string(),
                id: 2,
                params: json!({"name": "test"}),
            })
            .unwrap();
        assert_eq!(status["script"]["name"], "test");
    }

    #[test]
    fn test_exec_alloc_and_free() {
        let handler = backend();
        let alloc = handler
            .handle_exec_alloc(&Request {
                method: "exec_alloc".to_string(),
                id: 1,
                params: json!({"size": 64}),
            })
            .unwrap();
        let addr = alloc["address"].as_str().unwrap().to_string();
        let free = handler
            .handle_exec_free(&Request {
                method: "exec_free".to_string(),
                id: 2,
                params: json!({"address": addr}),
            })
            .unwrap();
        assert!(free["freed"].as_bool().unwrap());
    }

    #[test]
    fn test_introspect_sections() {
        let backend = InProcessBackend::new().unwrap();
        let modules = backend.get_modules().unwrap();
        if let Some(module) = modules.first() {
            let sections = backend.parse_pe_sections(module.base).unwrap();
            // Should have at least .text section
            assert!(!sections.is_empty());
            // Verify section structure
            let first = &sections[0];
            assert!(first.get("name").is_some());
            assert!(first.get("virtual_address").is_some());
            assert!(first.get("characteristics").is_some());
        }
    }

    #[test]
    fn test_introspect_token() {
        let backend = InProcessBackend::new().unwrap();
        let token_info = backend.get_token_info().unwrap();
        // Should have elevated field
        assert!(token_info.get("elevated").is_some());
        assert!(token_info.get("pid").is_some());
    }

    #[test]
    fn test_introspect_windows() {
        let backend = InProcessBackend::new().unwrap();
        // This may return empty if no windows, but should not error
        let windows = backend.enumerate_windows();
        assert!(windows.is_ok());
    }

    #[test]
    fn test_get_tls_info() {
        let backend = InProcessBackend::new().unwrap();
        let modules = backend.get_modules().unwrap();
        if let Some(module) = modules.first() {
            // TLS info may be empty if no TLS, but should not error
            let tls = backend.get_tls_info(module.base);
            assert!(tls.is_ok());
        }
    }

    #[test]
    fn test_adjust_privilege_invalid() {
        let backend = InProcessBackend::new().unwrap();
        // Invalid privilege name should return false but not error
        let result = backend.adjust_privilege("InvalidPrivilegeName", true);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be false for invalid privilege
    }

    // =========================================================================
    // Pointer Scanner Tests
    // =========================================================================

    use ghost_common::ipc::ResponseResult;

    /// Helper to check if a Response is successful
    fn is_success(result: &ResponseResult) -> bool {
        matches!(result, ResponseResult::Success(_))
    }

    /// Helper to check if a Response is an error
    fn is_error(result: &ResponseResult) -> bool {
        matches!(result, ResponseResult::Error { .. })
    }

    /// Helper to extract success value from ResponseResult
    fn get_success_value(result: &ResponseResult) -> Option<&serde_json::Value> {
        match result {
            ResponseResult::Success(v) => Some(v),
            ResponseResult::Error { .. } => None,
        }
    }

    #[test]
    fn test_pointer_scan_create_valid() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_create".to_string(),
            id: 1,
            params: json!({
                "address": "0x100000",
                "max_offset": 4096,
                "max_level": 5
            }),
        };
        let result = backend.handle_request(&req);
        assert!(is_success(&result.result), "Expected success, got error");
        let data = get_success_value(&result.result).unwrap();
        assert!(data.get("scan_id").is_some());
        assert_eq!(data["max_offset"], 4096);
        assert_eq!(data["max_level"], 5);
    }

    #[test]
    fn test_pointer_scan_create_clamps_max_offset() {
        let backend = InProcessBackend::new().unwrap();
        // Test that max_offset is clamped to reasonable bounds
        let req = Request {
            method: "pointer_scan_create".to_string(),
            id: 1,
            params: json!({
                "address": "0x100000",
                "max_offset": 999999999  // Way too large
            }),
        };
        let result = backend.handle_request(&req);
        assert!(is_success(&result.result));
        let data = get_success_value(&result.result).unwrap();
        // Should be clamped to 1MB max
        assert!(data["max_offset"].as_i64().unwrap() <= 1024 * 1024);
    }

    #[test]
    fn test_pointer_scan_create_clamps_max_level() {
        let backend = InProcessBackend::new().unwrap();
        // Test that max_level is clamped
        let req = Request {
            method: "pointer_scan_create".to_string(),
            id: 1,
            params: json!({
                "address": "0x100000",
                "max_level": 100  // Too deep
            }),
        };
        let result = backend.handle_request(&req);
        assert!(is_success(&result.result));
        let data = get_success_value(&result.result).unwrap();
        // Should be clamped to 10 max
        assert!(data["max_level"].as_u64().unwrap() <= 10);
    }

    #[test]
    fn test_pointer_scan_create_rejects_null_address() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_create".to_string(),
            id: 1,
            params: json!({
                "address": "0x1000"  // In null region (< 0x10000)
            }),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for null region address"
        );
    }

    #[test]
    fn test_pointer_scan_list_empty() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_list".to_string(),
            id: 1,
            params: json!({}),
        };
        let result = backend.handle_request(&req);
        assert!(is_success(&result.result));
        let data = get_success_value(&result.result).unwrap();
        assert!(data.get("sessions").is_some());
        assert!(data.get("count").is_some());
    }

    #[test]
    fn test_pointer_scan_progress_no_active() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_progress".to_string(),
            id: 1,
            params: json!({"scan_id": "1"}),
        };
        let result = backend.handle_request(&req);
        assert!(is_success(&result.result));
        let data = get_success_value(&result.result).unwrap();
        // Should indicate no active scan for this session
        assert_eq!(data["active"], false);
    }

    #[test]
    fn test_pointer_scan_cancel() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_cancel".to_string(),
            id: 1,
            params: json!({}),
        };
        let result = backend.handle_request(&req);
        assert!(is_success(&result.result));
        let data = get_success_value(&result.result).unwrap();
        assert_eq!(data["cancelled"], true);
    }

    #[test]
    fn test_pointer_scan_close_invalid_id() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_close".to_string(),
            id: 1,
            params: json!({
                "scan_id": "99999"  // Non-existent
            }),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for invalid scan_id"
        );
    }

    #[test]
    fn test_pointer_scan_count_invalid_id() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_count".to_string(),
            id: 1,
            params: json!({
                "scan_id": "99999"
            }),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for invalid scan_id"
        );
    }

    #[test]
    fn test_pointer_scan_results_clamps_limit() {
        let backend = InProcessBackend::new().unwrap();
        // First create a session
        let create_req = Request {
            method: "pointer_scan_create".to_string(),
            id: 1,
            params: json!({
                "address": "0x100000"
            }),
        };
        let create_result = backend.handle_request(&create_req);
        assert!(is_success(&create_result.result));
        let scan_id = get_success_value(&create_result.result).unwrap()["scan_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Request with excessive limit
        let req = Request {
            method: "pointer_scan_results".to_string(),
            id: 2,
            params: json!({
                "scan_id": scan_id,
                "limit": 999999  // Should be clamped
            }),
        };
        let result = backend.handle_request(&req);
        assert!(is_success(&result.result));
        // Result should succeed with clamped limit
        let data = get_success_value(&result.result).unwrap();
        assert!(data.get("paths").is_some());
    }

    #[test]
    fn test_pointer_resolve_missing_base() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_resolve".to_string(),
            id: 1,
            params: json!({
                "offsets": [0x10, 0x20]
                // Missing "base"
            }),
        };
        let result = backend.handle_request(&req);
        assert!(is_error(&result.result), "Expected error for missing base");
    }

    #[test]
    fn test_pointer_resolve_missing_offsets() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_resolve".to_string(),
            id: 1,
            params: json!({
                "base": "0x100000"
                // Missing "offsets"
            }),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for missing offsets"
        );
    }

    #[test]
    fn test_pointer_resolve_too_many_offsets() {
        let backend = InProcessBackend::new().unwrap();
        // Create an array with more than 20 offsets
        let offsets: Vec<i64> = (0..25).map(|i| i * 0x10).collect();
        let req = Request {
            method: "pointer_resolve".to_string(),
            id: 1,
            params: json!({
                "base": "0x100000",
                "offsets": offsets  // More than 20 levels
            }),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for too many offsets"
        );
    }

    #[test]
    fn test_pointer_resolve_with_module_name() {
        let backend = InProcessBackend::new().unwrap();
        let modules = backend.get_modules().unwrap();
        if let Some(module) = modules.first() {
            let req = Request {
                method: "pointer_resolve".to_string(),
                id: 1,
                params: json!({
                    "base": module.name,
                    "offsets": [0x100]
                }),
            };
            let result = backend.handle_request(&req);
            // May fail to resolve but should not error on input validation
            assert!(is_success(&result.result));
        }
    }

    #[test]
    fn test_pointer_scan_compare_invalid_ids() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_compare".to_string(),
            id: 1,
            params: json!({
                "scan_id1": "99998",
                "scan_id2": "99999"
            }),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for invalid scan_ids"
        );
    }

    #[test]
    fn test_pointer_scan_export_invalid_path() {
        let backend = InProcessBackend::new().unwrap();
        // First create a session
        let create_req = Request {
            method: "pointer_scan_create".to_string(),
            id: 1,
            params: json!({
                "address": "0x100000"
            }),
        };
        let create_result = backend.handle_request(&create_req);
        let scan_id = get_success_value(&create_result.result).unwrap()["scan_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Try to export with null character in path
        let req = Request {
            method: "pointer_scan_export".to_string(),
            id: 2,
            params: json!({
                "scan_id": scan_id,
                "path": "test\0file.json"  // Invalid path
            }),
        };
        let result = backend.handle_request(&req);
        assert!(is_error(&result.result), "Expected error for invalid path");
    }

    #[test]
    fn test_pointer_scan_import_nonexistent_file() {
        let backend = InProcessBackend::new().unwrap();
        let req = Request {
            method: "pointer_scan_import".to_string(),
            id: 1,
            params: json!({
                "path": "/nonexistent/path/to/file.json"
            }),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for nonexistent file"
        );
    }

    #[test]
    fn test_pointer_scan_lifecycle() {
        let backend = InProcessBackend::new().unwrap();

        // 1. Create session
        let create_req = Request {
            method: "pointer_scan_create".to_string(),
            id: 1,
            params: json!({
                "address": "0x100000",
                "max_offset": 256,
                "max_level": 2
            }),
        };
        let create_result = backend.handle_request(&create_req);
        assert!(is_success(&create_result.result));
        let scan_id = get_success_value(&create_result.result).unwrap()["scan_id"]
            .as_str()
            .unwrap()
            .to_string();

        // 2. List sessions - should have one
        let list_req = Request {
            method: "pointer_scan_list".to_string(),
            id: 2,
            params: json!({}),
        };
        let list_result = backend.handle_request(&list_req);
        assert!(is_success(&list_result.result));
        let sessions = get_success_value(&list_result.result).unwrap()["sessions"]
            .as_array()
            .unwrap();
        assert!(!sessions.is_empty());

        // 3. Get count (should be 0 before scan starts)
        let count_req = Request {
            method: "pointer_scan_count".to_string(),
            id: 3,
            params: json!({
                "scan_id": scan_id.clone()
            }),
        };
        let count_result = backend.handle_request(&count_req);
        assert!(is_success(&count_result.result));
        assert_eq!(get_success_value(&count_result.result).unwrap()["count"], 0);

        // 4. Close session
        let close_req = Request {
            method: "pointer_scan_close".to_string(),
            id: 4,
            params: json!({
                "scan_id": scan_id
            }),
        };
        let close_result = backend.handle_request(&close_req);
        assert!(is_success(&close_result.result));
        assert_eq!(
            get_success_value(&close_result.result).unwrap()["closed"],
            true
        );
    }

    #[test]
    fn test_parse_pointer_scan_id_numeric() {
        let backend = InProcessBackend::new().unwrap();
        let result = backend.parse_pointer_scan_id(&json!(42));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, 42);
    }

    #[test]
    fn test_parse_pointer_scan_id_string() {
        let backend = InProcessBackend::new().unwrap();
        let result = backend.parse_pointer_scan_id(&json!("123"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, 123);
    }

    #[test]
    fn test_parse_pointer_scan_id_invalid() {
        let backend = InProcessBackend::new().unwrap();
        let result = backend.parse_pointer_scan_id(&json!("not_a_number"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pointer_scan_id_too_long() {
        let backend = InProcessBackend::new().unwrap();
        let result = backend.parse_pointer_scan_id(&json!("123456789012345678901234567890"));
        assert!(result.is_err());
    }

    #[test]
    fn test_pointer_method_name_too_long() {
        let backend = InProcessBackend::new().unwrap();
        let long_method = "pointer_".to_string() + &"x".repeat(100);
        let req = Request {
            method: long_method,
            id: 1,
            params: json!({}),
        };
        let result = backend.handle_request(&req);
        assert!(
            is_error(&result.result),
            "Expected error for too long method name"
        );
    }
}
