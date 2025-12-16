//! API Call Tracing & Monitoring types
//!
//! Rohitab API Monitor-style tracing: capture, filter, and analyze Win32 API calls
//! with full argument decoding.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Identifiers
// ============================================================================

/// Unique identifier for an API trace session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceSessionId(pub u32);

/// Unique identifier for a trace filter preset
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FilterPresetId(pub u32);

/// Unique identifier for an API definition pack
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiPackId(pub String);

/// Unique identifier for a captured API call event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiEventId(pub u64);

// ============================================================================
// Event Pipeline Types
// ============================================================================

/// Backpressure strategy when ring buffer is full
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BackpressureStrategy {
    /// Drop oldest events to make room for new ones (default)
    #[default]
    DropOldest,
    /// Block until space is available (may cause target slowdown)
    Block,
    /// Sample events (keep 1 in N)
    Sample { rate: u32 },
}

/// Event serialization format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EventSerializationFormat {
    /// Compact binary format (smaller, faster)
    Binary,
    /// JSON Lines format (human-readable, larger)
    #[default]
    JsonLines,
}

/// Ring buffer configuration for captured events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingBufferConfig {
    /// Maximum number of events to buffer
    pub max_events: usize,
    /// Maximum memory size in bytes (0 = unlimited)
    pub max_memory_bytes: usize,
    /// Backpressure strategy when buffer is full
    pub backpressure: BackpressureStrategy,
    /// Serialization format for events
    pub format: EventSerializationFormat,
}

impl Default for RingBufferConfig {
    fn default() -> Self {
        Self {
            max_events: 10000,
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            backpressure: BackpressureStrategy::DropOldest,
            format: EventSerializationFormat::JsonLines,
        }
    }
}

/// Queue statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueueStats {
    /// Current number of events in queue
    pub current_depth: usize,
    /// Maximum depth reached
    pub max_depth: usize,
    /// Total events captured
    pub total_captured: u64,
    /// Total events dropped due to backpressure
    pub total_dropped: u64,
    /// Events per second (rolling average)
    pub events_per_second: f64,
    /// Current memory usage in bytes
    pub memory_bytes: usize,
}

// ============================================================================
// API Definition System Types
// ============================================================================

/// Primitive types for API parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiPrimitiveType {
    Void,
    Bool,
    Char,
    WChar,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    IntPtr,
    UIntPtr,
    Float,
    Double,
    Handle,
    HResult,
    NtStatus,
}

/// String encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StringEncoding {
    /// ANSI (single-byte characters)
    #[default]
    Ansi,
    /// Unicode UTF-16 (Windows wide strings)
    Unicode,
    /// UTF-8 encoding
    Utf8,
}

/// Parameter direction (in/out/inout)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ParamDirection {
    /// Input parameter (read by function)
    #[default]
    In,
    /// Output parameter (written by function)
    Out,
    /// Input/output parameter (read and written)
    InOut,
}

/// Type definition for API parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiType {
    /// Primitive type
    Primitive(ApiPrimitiveType),
    /// Pointer to another type
    Pointer {
        inner: Box<ApiType>,
        /// Size hint for buffer (can reference another parameter)
        size_hint: Option<SizeHint>,
        /// Whether null is a valid value
        nullable: bool,
    },
    /// String type
    String {
        encoding: StringEncoding,
        /// Maximum length to capture (0 = auto-detect)
        max_length: usize,
    },
    /// Fixed-size array
    Array {
        element_type: Box<ApiType>,
        count: usize,
    },
    /// Buffer with size from another parameter
    Buffer {
        /// Parameter index or name that contains the size
        size_param: String,
    },
    /// Struct reference
    Struct { name: String },
    /// Enum type
    Enum {
        name: String,
        base_type: ApiPrimitiveType,
    },
    /// Flags (bitmask enum)
    Flags {
        name: String,
        base_type: ApiPrimitiveType,
    },
    /// GUID type
    Guid,
    /// Unknown/opaque type (capture as raw bytes)
    Unknown { size: usize },
}

/// Size hint for buffers and pointers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SizeHint {
    /// Fixed size in bytes
    Fixed(usize),
    /// Size comes from another parameter (by index)
    ParamIndex(usize),
    /// Size comes from another parameter (by name)
    ParamName(String),
    /// Null-terminated (for strings)
    NullTerminated,
    /// Size is return value * element size
    ReturnValue { element_size: usize },
}

/// API parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiParamDef {
    /// Parameter name
    pub name: String,
    /// Parameter type
    #[serde(alias = "type")]
    pub param_type: ApiType,
    /// Parameter direction
    pub direction: ParamDirection,
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
}

/// API function definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFunctionDef {
    /// Function name
    pub name: String,
    /// Module where function is exported (e.g., "kernel32.dll")
    pub module: String,
    /// Ordinal (if exported by ordinal)
    #[serde(default)]
    pub ordinal: Option<u16>,
    /// Parameters
    pub params: Vec<ApiParamDef>,
    /// Return type
    pub return_type: ApiType,
    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
    /// Category for grouping (e.g., "File", "Memory", "Process")
    #[serde(default)]
    pub category: Option<String>,
    /// Whether this API is dangerous/sensitive
    #[serde(default)]
    pub sensitive: bool,
}

/// Struct field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructFieldDef {
    /// Field name
    pub name: String,
    /// Field type
    #[serde(alias = "type")]
    pub field_type: ApiType,
    /// Offset from struct start (in bytes)
    #[serde(default)]
    pub offset: usize,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
}

/// Struct type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructDef {
    /// Struct name
    pub name: String,
    /// Total size in bytes
    #[serde(default)]
    pub size: usize,
    /// Fields
    #[serde(default)]
    pub fields: Vec<StructFieldDef>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
}

/// Enum value definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumValueDef {
    /// Value name
    pub name: String,
    /// Numeric value
    pub value: i64,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
}

/// Enum type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumDef {
    /// Enum name
    pub name: String,
    /// Base type (defaults to UInt32)
    #[serde(default = "default_enum_base_type")]
    pub base_type: ApiPrimitiveType,
    /// Values
    pub values: Vec<EnumValueDef>,
    /// Whether this is a flags enum (bitmask)
    #[serde(default)]
    pub is_flags: bool,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
}

fn default_enum_base_type() -> ApiPrimitiveType {
    ApiPrimitiveType::UInt32
}

/// API definition pack (collection of APIs from a module)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiPack {
    /// Pack identifier
    pub id: ApiPackId,
    /// Pack name (e.g., "kernel32", "ntdll")
    pub name: String,
    /// Pack version
    pub version: String,
    /// Pack description
    #[serde(default)]
    pub description: Option<String>,
    /// Module name (e.g., "kernel32.dll")
    pub module: String,
    /// Function definitions
    #[serde(default)]
    pub functions: Vec<ApiFunctionDef>,
    /// Struct definitions
    #[serde(default)]
    pub structs: Vec<StructDef>,
    /// Enum definitions
    #[serde(default)]
    pub enums: Vec<EnumDef>,
}

/// API pack metadata (without full definitions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiPackInfo {
    /// Pack identifier
    pub id: ApiPackId,
    /// Pack name
    pub name: String,
    /// Pack version
    pub version: String,
    /// Description
    pub description: Option<String>,
    /// Module name
    pub module: String,
    /// Number of functions defined
    pub function_count: usize,
    /// Whether pack is currently loaded
    pub loaded: bool,
    /// Whether pack is built-in or custom
    pub builtin: bool,
}

// ============================================================================
// Captured Event Types
// ============================================================================

/// Captured argument value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapturedValue {
    /// Null pointer
    Null,
    /// Boolean value
    Bool(bool),
    /// Signed integer
    Int(i64),
    /// Unsigned integer
    UInt(u64),
    /// Floating point
    Float(f64),
    /// String value
    String(String),
    /// Raw bytes (for buffers/unknown types)
    Bytes(Vec<u8>),
    /// Struct with named fields
    Struct(HashMap<String, CapturedValue>),
    /// Array of values
    Array(Vec<CapturedValue>),
    /// GUID value
    Guid([u8; 16]),
    /// Handle value
    Handle(u64),
    /// Enum/flags with symbolic name
    Named { value: i64, name: String },
    /// Pointer with dereferenced value
    Pointer {
        address: u64,
        value: Option<Box<CapturedValue>>,
    },
    /// Capture error (failed to read)
    Error(String),
    /// Truncated (value was too large)
    Truncated {
        captured: Box<CapturedValue>,
        total_size: usize,
    },
}

/// Call stack frame for API call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiStackFrame {
    /// Return address
    pub address: u64,
    /// Module name (if resolved)
    pub module: Option<String>,
    /// Offset within module
    pub offset: u64,
    /// Symbol name (if resolved)
    pub symbol: Option<String>,
    /// Symbol offset
    pub symbol_offset: u64,
}

/// Captured API call event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallEvent {
    /// Unique event ID
    pub id: ApiEventId,
    /// Sequence number (monotonically increasing)
    pub sequence: u64,
    /// Thread ID that made the call
    pub thread_id: u32,
    /// Timestamp (microseconds since session start)
    pub timestamp_us: u64,
    /// API function name
    pub function_name: String,
    /// Module name
    pub module_name: String,
    /// Captured arguments (before call)
    pub args_before: Vec<CapturedArg>,
    /// Captured output arguments (after call, for OUT params)
    pub args_after: Option<Vec<CapturedArg>>,
    /// Return value
    pub return_value: Option<CapturedValue>,
    /// Call duration in microseconds
    pub duration_us: Option<u64>,
    /// Call stack (if captured)
    pub call_stack: Option<Vec<ApiStackFrame>>,
    /// Whether call succeeded (based on return value)
    pub success: Option<bool>,
    /// Error code (if call failed)
    pub error_code: Option<u32>,
    /// Error message (if available)
    pub error_message: Option<String>,
}

/// Captured argument with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedArg {
    /// Parameter name
    pub name: String,
    /// Parameter index
    pub index: usize,
    /// Captured value
    pub value: CapturedValue,
    /// Parameter direction
    pub direction: ParamDirection,
}

// ============================================================================
// Filter Types
// ============================================================================

/// String match pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringPattern {
    /// Exact match
    Exact(String),
    /// Prefix match
    Prefix(String),
    /// Suffix match
    Suffix(String),
    /// Contains substring
    Contains(String),
    /// Regex pattern
    Regex(String),
    /// Wildcard pattern (*, ?)
    Wildcard(String),
}

/// Value comparison for filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValueComparison {
    /// Equal to value
    Equal(i64),
    /// Not equal to value
    NotEqual(i64),
    /// Less than value
    LessThan(i64),
    /// Less than or equal
    LessOrEqual(i64),
    /// Greater than value
    GreaterThan(i64),
    /// Greater than or equal
    GreaterOrEqual(i64),
    /// Between (inclusive)
    Between(i64, i64),
    /// Has specific bits set
    HasBits(u64),
    /// Matches any of the values
    InSet(Vec<i64>),
}

/// Argument filter condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgFilter {
    /// Parameter name or index
    pub param: String,
    /// Value comparison
    pub comparison: ValueComparison,
}

/// Thread filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreadFilter {
    /// Include specific thread IDs
    Include(Vec<u32>),
    /// Exclude specific thread IDs
    Exclude(Vec<u32>),
}

/// API trace filter configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TraceFilter {
    /// Include APIs matching these patterns (empty = include all)
    pub include_apis: Vec<StringPattern>,
    /// Exclude APIs matching these patterns
    pub exclude_apis: Vec<StringPattern>,
    /// Include APIs from these modules only (empty = all modules)
    pub include_modules: Vec<StringPattern>,
    /// Exclude APIs from these modules
    pub exclude_modules: Vec<StringPattern>,
    /// Thread filter
    pub thread_filter: Option<ThreadFilter>,
    /// Argument value filters
    pub arg_filters: Vec<ArgFilter>,
    /// Return value filter
    pub return_filter: Option<ValueComparison>,
    /// Only capture failed calls
    pub failed_only: bool,
    /// Only capture successful calls
    pub success_only: bool,
    /// Sampling rate (1 = capture all, N = capture 1 in N)
    pub sample_rate: u32,
    /// Maximum events per second (0 = unlimited)
    pub max_events_per_second: u32,
    /// Categories to include (empty = all)
    pub include_categories: Vec<String>,
    /// Categories to exclude
    pub exclude_categories: Vec<String>,
}

/// Filter preset for saving/loading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterPreset {
    /// Preset ID
    pub id: FilterPresetId,
    /// Preset name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Filter configuration
    pub filter: TraceFilter,
    /// Whether preset is built-in
    pub builtin: bool,
}

// ============================================================================
// Call Stack Capture Configuration
// ============================================================================

/// Call stack capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackCaptureConfig {
    /// Whether to capture call stack
    pub enabled: bool,
    /// Maximum number of frames to capture (1-64)
    pub max_depth: usize,
    /// Whether to resolve symbols
    pub resolve_symbols: bool,
    /// Whether to include module names
    pub include_modules: bool,
}

impl Default for StackCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 16,
            resolve_symbols: true,
            include_modules: true,
        }
    }
}

// ============================================================================
// Safe Argument Capture Configuration
// ============================================================================

/// Safe argument capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Maximum bytes to read per argument
    pub max_arg_size: usize,
    /// Maximum string length to capture
    pub max_string_length: usize,
    /// Maximum buffer size to capture
    pub max_buffer_size: usize,
    /// Maximum struct depth to follow
    pub max_struct_depth: usize,
    /// Maximum pointer chain depth
    pub max_pointer_depth: usize,
    /// Timeout for memory reads (microseconds)
    pub read_timeout_us: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            max_arg_size: 4096,
            max_string_length: 1024,
            max_buffer_size: 16384,
            max_struct_depth: 4,
            max_pointer_depth: 2,
            read_timeout_us: 1000,
        }
    }
}

// ============================================================================
// Trace Session Types
// ============================================================================

/// Trace session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TraceSessionState {
    /// Session created but not started
    #[default]
    Idle,
    /// Session is actively tracing
    Active,
    /// Session is paused
    Paused,
    /// Session has stopped
    Stopped,
    /// Session encountered an error
    Error,
}

/// Trace session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSessionConfig {
    /// Session name
    pub name: String,
    /// Ring buffer configuration
    pub buffer: RingBufferConfig,
    /// Filter configuration
    pub filter: TraceFilter,
    /// Stack capture configuration
    pub stack: StackCaptureConfig,
    /// Argument capture configuration
    pub capture: CaptureConfig,
    /// API packs to use
    pub api_packs: Vec<ApiPackId>,
    /// Whether to capture call duration
    pub capture_duration: bool,
    /// Whether to capture output parameters
    pub capture_output: bool,
}

impl Default for TraceSessionConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            buffer: RingBufferConfig::default(),
            filter: TraceFilter::default(),
            stack: StackCaptureConfig::default(),
            capture: CaptureConfig::default(),
            api_packs: vec![],
            capture_duration: true,
            capture_output: true,
        }
    }
}

/// Trace session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSessionInfo {
    /// Session ID
    pub id: TraceSessionId,
    /// Session name
    pub name: String,
    /// Current state
    pub state: TraceSessionState,
    /// When session was created (Unix timestamp ms)
    pub created_at: u64,
    /// When session was started (Unix timestamp ms)
    pub started_at: Option<u64>,
    /// Queue statistics
    pub stats: QueueStats,
    /// Number of hooks installed
    pub hooks_installed: usize,
    /// Active filter preset (if any)
    pub filter_preset: Option<FilterPresetId>,
}

// ============================================================================
// Statistics Types
// ============================================================================

/// Per-API call statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiCallStats {
    /// Total call count
    pub call_count: u64,
    /// Successful call count
    pub success_count: u64,
    /// Failed call count
    pub failure_count: u64,
    /// Average duration (microseconds)
    pub avg_duration_us: f64,
    /// Min duration (microseconds)
    pub min_duration_us: u64,
    /// Max duration (microseconds)
    pub max_duration_us: u64,
    /// Last call timestamp
    pub last_call_ms: u64,
}

/// Overall tracing statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TraceStats {
    /// Queue statistics
    pub queue: QueueStats,
    /// Per-API statistics
    pub per_api: HashMap<String, ApiCallStats>,
    /// Per-module call counts
    pub per_module: HashMap<String, u64>,
    /// Per-thread call counts
    pub per_thread: HashMap<u32, u64>,
    /// Per-category call counts
    pub per_category: HashMap<String, u64>,
    /// Total unique APIs called
    pub unique_apis: usize,
    /// Session uptime in milliseconds
    pub uptime_ms: u64,
}

// ============================================================================
// API Result Types
// ============================================================================

/// Result of starting a trace session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStartResult {
    /// Session ID
    pub session_id: TraceSessionId,
    /// Number of hooks installed
    pub hooks_installed: usize,
    /// APIs that failed to hook
    pub failed_hooks: Vec<String>,
    /// Warning messages
    pub warnings: Vec<String>,
}

/// Result of querying events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEventsResult {
    /// Events
    pub events: Vec<ApiCallEvent>,
    /// Total events matching filter
    pub total_count: u64,
    /// Whether there are more events
    pub has_more: bool,
    /// Continuation token for pagination
    pub continuation: Option<String>,
}

/// API hook status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiHookStatus {
    /// API function name
    pub function_name: String,
    /// Module name
    pub module: String,
    /// Whether hook is active
    pub active: bool,
    /// Hook address
    pub hook_address: Option<u64>,
    /// Original address
    pub original_address: Option<u64>,
    /// Call count
    pub call_count: u64,
    /// Error message if hook failed
    pub error: Option<String>,
}

// ============================================================================
// Dynamic API Monitoring Types
// ============================================================================

/// Dynamic API resolution event (GetProcAddress, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicApiResolution {
    /// Thread that resolved the API
    pub thread_id: u32,
    /// Timestamp of resolution
    pub timestamp_us: u64,
    /// Module being queried (e.g., "kernel32.dll")
    pub module_name: String,
    /// Function name or ordinal being resolved
    pub function_name: String,
    /// Resolved address (if successful)
    pub resolved_address: Option<u64>,
    /// Whether resolution succeeded
    pub success: bool,
    /// Call stack at resolution point
    pub call_stack: Option<Vec<ApiStackFrame>>,
}

/// Dynamic API monitor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicApiMonitorConfig {
    /// Hook GetProcAddress
    pub hook_getprocaddress: bool,
    /// Hook LdrGetProcedureAddress
    pub hook_ldr_getprocedureaddress: bool,
    /// Hook GetProcAddressForCaller
    pub hook_getprocaddressforcaller: bool,
    /// Capture call stacks for resolutions
    pub capture_call_stacks: bool,
    /// Filter: only track specific modules
    pub module_filter: Vec<StringPattern>,
    /// Filter: only track specific function names
    pub function_filter: Vec<StringPattern>,
}

impl Default for DynamicApiMonitorConfig {
    fn default() -> Self {
        Self {
            hook_getprocaddress: true,
            hook_ldr_getprocedureaddress: true,
            hook_getprocaddressforcaller: false,
            capture_call_stacks: true,
            module_filter: vec![],
            function_filter: vec![],
        }
    }
}

// ============================================================================
// Chill Process Types (Process Freeze/Resume)
// ============================================================================

/// Chill (freeze) mode for process analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChillMode {
    /// Freeze all threads except current
    #[default]
    AllExceptCurrent,
    /// Freeze specific threads
    SpecificThreads,
    /// Freeze all threads in process
    AllThreads,
    /// Freeze threads matching a filter
    Filtered,
}

/// Chill process configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChillConfig {
    /// Chill mode
    pub mode: ChillMode,
    /// Specific thread IDs to freeze (when mode is SpecificThreads)
    pub thread_ids: Vec<u32>,
    /// Thread name patterns to match (when mode is Filtered)
    pub thread_patterns: Vec<StringPattern>,
    /// Maximum chill duration in milliseconds (0 = unlimited)
    pub max_duration_ms: u64,
    /// Auto-resume on timeout
    pub auto_resume: bool,
}

impl Default for ChillConfig {
    fn default() -> Self {
        Self {
            mode: ChillMode::AllExceptCurrent,
            thread_ids: vec![],
            thread_patterns: vec![],
            max_duration_ms: 30000, // 30 seconds default
            auto_resume: true,
        }
    }
}

/// Chill session status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChillStatus {
    /// Whether process is currently chilled
    pub is_chilled: bool,
    /// Number of frozen threads
    pub frozen_thread_count: usize,
    /// List of frozen thread IDs
    pub frozen_threads: Vec<u32>,
    /// When chill started (timestamp)
    pub started_at: Option<u64>,
    /// Time remaining before auto-resume (ms)
    pub time_remaining_ms: Option<u64>,
}

// ============================================================================
// COM Object Scanning Types
// ============================================================================

/// COM object information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComObjectInfo {
    /// Interface pointer address
    pub interface_ptr: u64,
    /// VTable pointer address
    pub vtable_ptr: u64,
    /// CLSID if known
    pub clsid: Option<String>,
    /// IID (Interface ID)
    pub iid: Option<String>,
    /// Friendly interface name if resolved
    pub interface_name: Option<String>,
    /// Number of methods in vtable
    pub method_count: usize,
    /// Reference count if accessible
    pub ref_count: Option<u32>,
    /// Module containing the vtable
    pub module_name: Option<String>,
}

/// COM vtable method entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComMethodEntry {
    /// Method index in vtable
    pub index: usize,
    /// Method address
    pub address: u64,
    /// Method name if resolved from symbols
    pub name: Option<String>,
    /// Module containing the method
    pub module: Option<String>,
}

/// COM scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComScanConfig {
    /// Scan heap for COM objects
    pub scan_heap: bool,
    /// Scan stack for COM objects
    pub scan_stack: bool,
    /// Scan global data sections
    pub scan_globals: bool,
    /// Maximum objects to return
    pub max_results: usize,
    /// Filter by known CLSIDs
    pub clsid_filter: Vec<String>,
    /// Filter by known IIDs
    pub iid_filter: Vec<String>,
    /// Resolve method names from symbols
    pub resolve_symbols: bool,
}

impl Default for ComScanConfig {
    fn default() -> Self {
        Self {
            scan_heap: true,
            scan_stack: false,
            scan_globals: true,
            max_results: 1000,
            clsid_filter: vec![],
            iid_filter: vec![],
            resolve_symbols: true,
        }
    }
}

/// COM scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComScanResult {
    /// Found COM objects
    pub objects: Vec<ComObjectInfo>,
    /// Scan statistics
    pub regions_scanned: usize,
    /// Bytes scanned
    pub bytes_scanned: u64,
    /// Duration in microseconds
    pub duration_us: u64,
}

// ============================================================================
// DLL Monitoring Types
// ============================================================================

/// DLL load/unload event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllEvent {
    /// Event type
    pub event_type: DllEventType,
    /// Thread that triggered the event
    pub thread_id: u32,
    /// Timestamp
    pub timestamp_us: u64,
    /// DLL path
    pub path: String,
    /// DLL base address
    pub base_address: u64,
    /// DLL size
    pub size: u64,
    /// Entry point address
    pub entry_point: Option<u64>,
    /// Call stack at load/unload
    pub call_stack: Option<Vec<ApiStackFrame>>,
    /// Load reason (for LdrLoadDll)
    pub load_reason: Option<String>,
}

/// DLL event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DllEventType {
    /// DLL loaded
    Load,
    /// DLL unloaded
    Unload,
    /// DLL load attempted but failed
    LoadFailed,
    /// Delayed load triggered
    DelayLoad,
    /// Delayed load failed
    DelayLoadFailed,
}

/// DLL monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllMonitorConfig {
    /// Monitor LoadLibrary calls
    pub hook_loadlibrary: bool,
    /// Monitor LdrLoadDll
    pub hook_ldr_loaddll: bool,
    /// Monitor FreeLibrary/unload
    pub hook_freelibrary: bool,
    /// Monitor delayed imports (__delayLoadHelper2)
    pub hook_delay_load: bool,
    /// Capture call stacks
    pub capture_call_stacks: bool,
    /// Include system DLLs
    pub include_system_dlls: bool,
    /// Filter: only track specific DLL patterns
    pub dll_filter: Vec<StringPattern>,
    /// Exclude patterns
    pub dll_exclude: Vec<StringPattern>,
}

impl Default for DllMonitorConfig {
    fn default() -> Self {
        Self {
            hook_loadlibrary: true,
            hook_ldr_loaddll: true,
            hook_freelibrary: true,
            hook_delay_load: true,
            capture_call_stacks: true,
            include_system_dlls: false,
            dll_filter: vec![],
            dll_exclude: vec![],
        }
    }
}

/// DLL monitor status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllMonitorStatus {
    /// Whether monitoring is active
    pub active: bool,
    /// Number of DLL load events captured
    pub load_count: u64,
    /// Number of DLL unload events captured
    pub unload_count: u64,
    /// Number of delayed load events
    pub delay_load_count: u64,
    /// Number of failed loads
    pub failed_load_count: u64,
    /// Currently loaded DLLs being monitored
    pub monitored_dlls: Vec<String>,
}

/// Delayed DLL load info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayedDllInfo {
    /// DLL name that will be delay-loaded
    pub dll_name: String,
    /// Import descriptor address
    pub import_descriptor: u64,
    /// Functions that trigger delay load
    pub pending_imports: Vec<String>,
    /// Whether DLL has been loaded
    pub is_loaded: bool,
    /// Load timestamp if loaded
    pub loaded_at: Option<u64>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_session_id_serialization() {
        let id = TraceSessionId(42);
        let json = serde_json::to_string(&id).unwrap();
        let parsed: TraceSessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.0, 42);
    }

    #[test]
    fn test_api_pack_id_serialization() {
        let id = ApiPackId("kernel32".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ApiPackId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.0, "kernel32");
    }

    #[test]
    fn test_backpressure_strategy_serialization() {
        let strategy = BackpressureStrategy::Sample { rate: 10 };
        let json = serde_json::to_string(&strategy).unwrap();
        let parsed: BackpressureStrategy = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, BackpressureStrategy::Sample { rate: 10 }));
    }

    #[test]
    fn test_api_type_serialization() {
        let ptr_type = ApiType::Pointer {
            inner: Box::new(ApiType::Primitive(ApiPrimitiveType::UInt32)),
            size_hint: Some(SizeHint::Fixed(4)),
            nullable: true,
        };
        let json = serde_json::to_string(&ptr_type).unwrap();
        let parsed: ApiType = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ApiType::Pointer { .. }));
    }

    #[test]
    fn test_captured_value_serialization() {
        let val = CapturedValue::Named {
            value: 0x80000000u32 as i64,
            name: "GENERIC_READ".to_string(),
        };
        let json = serde_json::to_string(&val).unwrap();
        let parsed: CapturedValue = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CapturedValue::Named { .. }));
    }

    #[test]
    fn test_trace_filter_serialization() {
        let filter = TraceFilter {
            include_apis: vec![StringPattern::Prefix("Create".to_string())],
            failed_only: true,
            sample_rate: 5,
            ..Default::default()
        };
        let json = serde_json::to_string(&filter).unwrap();
        let parsed: TraceFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sample_rate, 5);
        assert!(parsed.failed_only);
    }

    #[test]
    fn test_api_call_event_serialization() {
        let event = ApiCallEvent {
            id: ApiEventId(1),
            sequence: 1,
            thread_id: 1234,
            timestamp_us: 12345678,
            function_name: "CreateFileW".to_string(),
            module_name: "kernel32.dll".to_string(),
            args_before: vec![],
            args_after: None,
            return_value: Some(CapturedValue::Handle(0x100)),
            duration_us: Some(50),
            call_stack: None,
            success: Some(true),
            error_code: None,
            error_message: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: ApiCallEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.function_name, "CreateFileW");
    }

    #[test]
    fn test_ring_buffer_config_default() {
        let config = RingBufferConfig::default();
        assert_eq!(config.max_events, 10000);
        assert_eq!(config.max_memory_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn test_trace_session_config_default() {
        let config = TraceSessionConfig::default();
        assert_eq!(config.name, "default");
        assert!(config.capture_duration);
        assert!(config.capture_output);
    }

    #[test]
    fn test_queue_stats_default() {
        let stats = QueueStats::default();
        assert_eq!(stats.current_depth, 0);
        assert_eq!(stats.total_captured, 0);
        assert_eq!(stats.total_dropped, 0);
    }

    #[test]
    fn test_string_pattern_serialization() {
        let pattern = StringPattern::Regex(r"Create.*W$".to_string());
        let json = serde_json::to_string(&pattern).unwrap();
        let parsed: StringPattern = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, StringPattern::Regex(_)));
    }

    #[test]
    fn test_value_comparison_serialization() {
        let cmp = ValueComparison::Between(0, 100);
        let json = serde_json::to_string(&cmp).unwrap();
        let parsed: ValueComparison = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ValueComparison::Between(0, 100)));
    }
}
