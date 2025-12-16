//! API Override & Conditional Breakpoints types
//!
//! Types for parameter modification, return value override, conditional API breakpoints,
//! and audit trail logging.

use serde::{Deserialize, Serialize};

// ============================================================================
// Identifiers
// ============================================================================

/// Unique identifier for a conditional API breakpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiBreakpointId(pub u32);

/// Unique identifier for an override rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OverrideRuleId(pub u32);

/// Unique identifier for an audit log entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEntryId(pub u64);

// ============================================================================
// Conditional API Breakpoint Types
// ============================================================================

/// When the breakpoint should trigger
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BreakpointTiming {
    /// Break before the API call executes
    #[default]
    BeforeCall,
    /// Break after the API call returns
    AfterCall,
    /// Break both before and after
    Both,
}

/// Condition for triggering a breakpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BreakpointCondition {
    /// Always trigger
    Always,
    /// Trigger when argument matches condition
    Argument {
        /// Parameter index (0-based)
        index: usize,
        /// Comparison to apply
        comparison: ArgumentComparison,
    },
    /// Trigger when return value matches condition
    ReturnValue(ArgumentComparison),
    /// Trigger for specific thread IDs
    ThreadId(Vec<u32>),
    /// Trigger when caller is from specific module
    CallerModule(String),
    /// Trigger when caller address is in range
    CallerAddress { start: u64, end: u64 },
    /// Trigger on Nth call (hit count)
    HitCount {
        /// Trigger on this hit number
        count: u64,
        /// Whether to reset counter after trigger
        reset_after: bool,
    },
    /// Trigger every Nth call
    HitCountModulo(u64),
    /// Combine multiple conditions with AND
    And(Vec<BreakpointCondition>),
    /// Combine multiple conditions with OR
    Or(Vec<BreakpointCondition>),
    /// Negate a condition
    Not(Box<BreakpointCondition>),
}

/// Comparison operations for argument/return value conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArgumentComparison {
    /// Equal to value
    Equal(ComparisonValue),
    /// Not equal to value
    NotEqual(ComparisonValue),
    /// Less than value
    LessThan(i64),
    /// Less than or equal
    LessOrEqual(i64),
    /// Greater than value
    GreaterThan(i64),
    /// Greater than or equal
    GreaterOrEqual(i64),
    /// Value is in range (inclusive)
    InRange { min: i64, max: i64 },
    /// Value has specific bits set
    HasBits(u64),
    /// Value does not have specific bits set
    ClearBits(u64),
    /// Pointer is null
    IsNull,
    /// Pointer is not null
    IsNotNull,
    /// String equals (for string parameters)
    StringEquals { value: String, case_sensitive: bool },
    /// String contains (for string parameters)
    StringContains { value: String, case_sensitive: bool },
    /// String matches regex
    StringMatches(String),
    /// Buffer contains bytes
    BufferContains(Vec<u8>),
}

/// Value for comparison operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonValue {
    /// Integer value
    Int(i64),
    /// Unsigned integer
    UInt(u64),
    /// Float value
    Float(f64),
    /// Boolean value
    Bool(bool),
    /// String value
    String(String),
    /// Pointer/address value
    Address(u64),
}

/// Configuration for a conditional API breakpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiBreakpointConfig {
    /// Breakpoint ID (assigned by system)
    #[serde(default)]
    pub id: Option<ApiBreakpointId>,
    /// API function name to break on
    pub function_name: String,
    /// Module containing the function (None = auto-detect)
    #[serde(default)]
    pub module: Option<String>,
    /// When to break
    #[serde(default)]
    pub timing: BreakpointTiming,
    /// Condition for triggering
    #[serde(default = "default_condition")]
    pub condition: BreakpointCondition,
    /// Whether breakpoint is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether to remove after first hit (one-shot)
    #[serde(default)]
    pub one_shot: bool,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
    /// Associated override rules (applied when breakpoint hits)
    #[serde(default)]
    pub override_rules: Vec<OverrideRuleId>,
}

/// Status of an API breakpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiBreakpointStatus {
    /// Breakpoint configuration
    pub config: ApiBreakpointConfig,
    /// Current hit count
    pub hit_count: u64,
    /// Whether currently installed
    pub installed: bool,
    /// Last hit timestamp (Unix milliseconds)
    pub last_hit_time: Option<u64>,
    /// Last hit thread ID
    pub last_hit_thread: Option<u32>,
}

// ============================================================================
// Pause Mechanism Types
// ============================================================================

/// Configuration for pause behavior when breakpoint hits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseConfig {
    /// Whether to pause the calling thread
    #[serde(default = "default_true")]
    pub pause_thread: bool,
    /// Timeout in milliseconds (0 = wait forever, auto-continue after timeout)
    #[serde(default = "default_pause_timeout")]
    pub timeout_ms: u64,
    /// Action to take on timeout
    #[serde(default)]
    pub timeout_action: TimeoutAction,
    /// Whether to capture full context on pause
    #[serde(default = "default_true")]
    pub capture_context: bool,
}

/// Action to take when pause times out
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TimeoutAction {
    /// Continue execution normally
    #[default]
    Continue,
    /// Apply default overrides and continue
    ApplyDefaultsAndContinue,
    /// Skip the API call entirely (return default value)
    SkipCall,
}

/// Notification sent when a breakpoint is hit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakNotification {
    /// Unique notification ID
    pub notification_id: u64,
    /// Breakpoint that was hit
    pub breakpoint_id: ApiBreakpointId,
    /// Thread that hit the breakpoint
    pub thread_id: u32,
    /// API function name
    pub function_name: String,
    /// Timing (before or after call)
    pub timing: BreakpointTiming,
    /// Captured arguments (before call)
    pub arguments: Vec<CapturedArgument>,
    /// Return value (after call only)
    pub return_value: Option<CapturedReturnValue>,
    /// Call stack
    pub call_stack: Vec<ApiBreakStackFrame>,
    /// Timestamp (Unix milliseconds)
    pub timestamp_ms: u64,
    /// Whether response is required
    pub requires_response: bool,
    /// Deadline for response (Unix milliseconds)
    pub response_deadline_ms: Option<u64>,
}

/// Captured argument for break notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedArgument {
    /// Parameter name
    pub name: String,
    /// Parameter index
    pub index: usize,
    /// Raw value (as u64)
    pub raw_value: u64,
    /// Interpreted value (if available)
    pub interpreted: Option<String>,
    /// Dereferenced string value (for string params)
    pub string_value: Option<String>,
    /// Dereferenced buffer (for buffer params, truncated)
    pub buffer_preview: Option<Vec<u8>>,
}

/// Captured return value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedReturnValue {
    /// Raw return value
    pub raw_value: u64,
    /// Interpreted value
    pub interpreted: Option<String>,
    /// Whether call succeeded (based on return value)
    pub success: Option<bool>,
    /// Error code if failed
    pub error_code: Option<u32>,
    /// Error message if available
    pub error_message: Option<String>,
}

/// Stack frame in break notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiBreakStackFrame {
    /// Return address
    pub address: u64,
    /// Module name
    pub module: Option<String>,
    /// Offset within module
    pub offset: u64,
    /// Symbol name
    pub symbol: Option<String>,
}

/// Response to a break notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakResponse {
    /// Notification ID being responded to
    pub notification_id: u64,
    /// Action to take
    pub action: BreakAction,
    /// Parameter overrides to apply (before call only)
    #[serde(default)]
    pub param_overrides: Vec<ParameterOverride>,
    /// Return value override (after call, or for skip)
    #[serde(default)]
    pub return_override: Option<ReturnOverride>,
}

/// Action to take after a breakpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BreakAction {
    /// Continue execution normally
    #[default]
    Continue,
    /// Continue with specified overrides
    ContinueWithOverrides,
    /// Skip the API call entirely
    SkipCall,
    /// Single-step the API call
    StepInto,
}

// ============================================================================
// Parameter Override Types
// ============================================================================

/// Override for a function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterOverride {
    /// Parameter index to override
    pub param_index: usize,
    /// New value to set
    pub new_value: OverrideValue,
}

/// Value types for overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverrideValue {
    /// Integer value (8/16/32/64-bit based on parameter type)
    Int(i64),
    /// Unsigned integer
    UInt(u64),
    /// Boolean (0 or 1)
    Bool(bool),
    /// Float value
    Float(f32),
    /// Double value
    Double(f64),
    /// Pointer value (raw address)
    Pointer(u64),
    /// Null pointer
    NullPointer,
    /// String value (will allocate buffer in target)
    StringAnsi(String),
    /// Unicode string (will allocate buffer in target)
    StringUnicode(String),
    /// Raw buffer (will allocate buffer in target)
    Buffer(Vec<u8>),
    /// Redirect pointer to agent-allocated buffer with contents
    RedirectBuffer {
        /// Contents to write to buffer
        contents: Vec<u8>,
        /// Size to allocate (if larger than contents, zero-filled)
        size: usize,
    },
}

/// Override rule that can be saved and reused
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideRule {
    /// Rule ID
    pub id: OverrideRuleId,
    /// Rule name
    pub name: String,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// API function this rule applies to
    pub function_name: String,
    /// Module (None = auto-detect)
    #[serde(default)]
    pub module: Option<String>,
    /// Condition for applying this rule
    #[serde(default = "default_condition")]
    pub condition: BreakpointCondition,
    /// Parameter overrides to apply
    #[serde(default)]
    pub param_overrides: Vec<ParameterOverride>,
    /// Return value override
    #[serde(default)]
    pub return_override: Option<ReturnOverride>,
    /// Whether rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ============================================================================
// Return Value Override Types
// ============================================================================

/// Override for return value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnOverride {
    /// New return value
    pub return_value: OverrideValue,
    /// Whether to also set LastError
    #[serde(default)]
    pub set_last_error: Option<u32>,
    /// Output parameter modifications
    #[serde(default)]
    pub output_params: Vec<OutputParamOverride>,
}

/// Override for an output parameter (written after call)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputParamOverride {
    /// Parameter index
    pub param_index: usize,
    /// Value to write (will be written to the pointer)
    pub value: OverrideValue,
}

/// Common HRESULT values for easy override
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommonHResult {
    SOk,
    SFalse,
    EFail,
    EInvalidArg,
    ENotImpl,
    EOutOfMemory,
    EAccessDenied,
    EAbort,
    EPointer,
    EHandle,
    EUnexpected,
    Custom(i32),
}

impl CommonHResult {
    pub fn value(&self) -> i32 {
        match self {
            Self::SOk => 0,
            Self::SFalse => 1,
            Self::EFail => -2147467259,         // 0x80004005
            Self::EInvalidArg => -2147024809,   // 0x80070057
            Self::ENotImpl => -2147467263,      // 0x80004001
            Self::EOutOfMemory => -2147024882,  // 0x8007000E
            Self::EAccessDenied => -2147024891, // 0x80070005
            Self::EAbort => -2147467260,        // 0x80004004
            Self::EPointer => -2147467261,      // 0x80004003
            Self::EHandle => -2147024890,       // 0x80070006
            Self::EUnexpected => -2147418113,   // 0x8000FFFF
            Self::Custom(v) => *v,
        }
    }
}

/// Common NTSTATUS values for easy override
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommonNtStatus {
    Success,
    Unsuccessful,
    NotImplemented,
    InvalidHandle,
    InvalidParameter,
    AccessDenied,
    BufferTooSmall,
    ObjectNameNotFound,
    ObjectPathNotFound,
    NoMemory,
    Custom(i32),
}

impl CommonNtStatus {
    pub fn value(&self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Unsuccessful => -1073741823,       // 0xC0000001
            Self::NotImplemented => -1073741822,     // 0xC0000002
            Self::InvalidHandle => -1073741816,      // 0xC0000008
            Self::InvalidParameter => -1073741811,   // 0xC000000D
            Self::AccessDenied => -1073741790,       // 0xC0000022
            Self::BufferTooSmall => -1073741789,     // 0xC0000023
            Self::ObjectNameNotFound => -1073741772, // 0xC0000034
            Self::ObjectPathNotFound => -1073741767, // 0xC0000039
            Self::NoMemory => -1073741801,           // 0xC0000017
            Self::Custom(v) => *v,
        }
    }
}

// ============================================================================
// Audit Trail Types
// ============================================================================

/// Audit log entry for parameter/return modifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID
    pub id: AuditEntryId,
    /// Timestamp (Unix milliseconds)
    pub timestamp_ms: u64,
    /// Type of modification
    pub entry_type: AuditEntryType,
    /// API function affected
    pub function_name: String,
    /// Module
    pub module: Option<String>,
    /// Thread that made the call
    pub thread_id: u32,
    /// Breakpoint that triggered this (if any)
    pub breakpoint_id: Option<ApiBreakpointId>,
    /// Override rule that was applied (if any)
    pub override_rule_id: Option<OverrideRuleId>,
    /// Details of the modification
    pub details: AuditDetails,
    /// Call stack at time of modification
    pub call_stack: Vec<ApiBreakStackFrame>,
}

/// Type of audit entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEntryType {
    /// Parameter was modified
    ParameterOverride,
    /// Return value was modified
    ReturnOverride,
    /// API call was skipped
    CallSkipped,
    /// Breakpoint was hit (informational)
    BreakpointHit,
    /// LastError was modified
    LastErrorOverride,
    /// Output parameter was modified
    OutputParamOverride,
}

/// Details of an audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDetails {
    /// Parameter index (for param overrides)
    pub param_index: Option<usize>,
    /// Parameter name
    pub param_name: Option<String>,
    /// Original value before modification
    pub original_value: Option<AuditValue>,
    /// New value after modification
    pub new_value: Option<AuditValue>,
    /// Additional context
    pub context: Option<String>,
}

/// Value representation in audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditValue {
    /// Integer value
    Int(i64),
    /// Unsigned integer
    UInt(u64),
    /// Float value
    Float(f64),
    /// String value
    String(String),
    /// Raw bytes (hex encoded in display)
    Bytes(Vec<u8>),
    /// Pointer address
    Pointer(u64),
    /// Null
    Null,
}

/// Configuration for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum entries to keep in memory
    #[serde(default = "default_max_audit_entries")]
    pub max_entries: usize,
    /// Whether to include call stacks
    #[serde(default = "default_true")]
    pub capture_call_stacks: bool,
    /// Whether to log breakpoint hits (not just modifications)
    #[serde(default)]
    pub log_breakpoint_hits: bool,
    /// File to write audit log to (None = memory only)
    #[serde(default)]
    pub log_file: Option<String>,
}

/// Export format for audit trail
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuditExportFormat {
    /// JSON format
    #[default]
    Json,
    /// JSON Lines format (one entry per line)
    JsonLines,
    /// CSV format
    Csv,
}

/// Request to export audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportRequest {
    /// Format to export as
    #[serde(default)]
    pub format: AuditExportFormat,
    /// Filter by function name (None = all)
    #[serde(default)]
    pub function_filter: Option<String>,
    /// Filter by entry type (None = all)
    #[serde(default)]
    pub type_filter: Option<Vec<AuditEntryType>>,
    /// Start time filter (Unix milliseconds)
    #[serde(default)]
    pub start_time: Option<u64>,
    /// End time filter (Unix milliseconds)
    #[serde(default)]
    pub end_time: Option<u64>,
    /// Maximum entries to export
    #[serde(default)]
    pub max_entries: Option<usize>,
}

/// Result of audit export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportResult {
    /// Exported data (JSON string, CSV string, etc.)
    pub data: String,
    /// Number of entries exported
    pub entry_count: usize,
    /// Format used
    pub format: AuditExportFormat,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn default_condition() -> BreakpointCondition {
    BreakpointCondition::Always
}

fn default_true() -> bool {
    true
}

fn default_pause_timeout() -> u64 {
    30000 // 30 seconds
}

fn default_max_audit_entries() -> usize {
    10000
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_condition_serialization() {
        let cond = BreakpointCondition::Argument {
            index: 0,
            comparison: ArgumentComparison::Equal(ComparisonValue::Int(42)),
        };
        let json = serde_json::to_string(&cond).unwrap();
        let parsed: BreakpointCondition = serde_json::from_str(&json).unwrap();
        match parsed {
            BreakpointCondition::Argument { index, .. } => assert_eq!(index, 0),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_override_value_types() {
        let val = OverrideValue::StringAnsi("test".to_string());
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("StringAnsi"));
    }

    #[test]
    fn test_hresult_values() {
        assert_eq!(CommonHResult::SOk.value(), 0);
        assert_eq!(CommonHResult::EFail.value(), -2147467259);
    }

    #[test]
    fn test_ntstatus_values() {
        assert_eq!(CommonNtStatus::Success.value(), 0);
        assert_eq!(CommonNtStatus::AccessDenied.value(), -1073741790);
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            id: AuditEntryId(1),
            timestamp_ms: 1234567890,
            entry_type: AuditEntryType::ParameterOverride,
            function_name: "CreateFileW".to_string(),
            module: Some("kernel32.dll".to_string()),
            thread_id: 1234,
            breakpoint_id: Some(ApiBreakpointId(1)),
            override_rule_id: None,
            details: AuditDetails {
                param_index: Some(0),
                param_name: Some("lpFileName".to_string()),
                original_value: Some(AuditValue::String("C:\\test.txt".to_string())),
                new_value: Some(AuditValue::String("C:\\fake.txt".to_string())),
                context: None,
            },
            call_stack: vec![],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.function_name, "CreateFileW");
    }

    #[test]
    fn test_compound_conditions() {
        let cond = BreakpointCondition::And(vec![
            BreakpointCondition::ThreadId(vec![1234]),
            BreakpointCondition::HitCount {
                count: 5,
                reset_after: false,
            },
        ]);
        let json = serde_json::to_string(&cond).unwrap();
        assert!(json.contains("And"));
        assert!(json.contains("ThreadId"));
        assert!(json.contains("HitCount"));
    }
}
