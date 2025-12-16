//! Safety & Guardrails Types
//!
//! Comprehensive safety types for preventing accidental damage.
//! Includes safety modes, rate limiting configs, and patch history types.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Safety mode determines the level of restrictions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafetyMode {
    /// Local-only/Educational mode - maximum restrictions, no dangerous ops
    Educational,
    /// Standard mode - normal restrictions with confirmations
    #[default]
    Standard,
    /// Expert mode - reduced restrictions for experienced users
    Expert,
}

impl SafetyMode {
    /// Check if this mode allows dangerous operations
    pub fn allows_dangerous_ops(&self) -> bool {
        matches!(self, SafetyMode::Expert)
    }

    /// Check if this mode requires explicit approval for writes
    pub fn requires_write_approval(&self) -> bool {
        matches!(self, SafetyMode::Educational | SafetyMode::Standard)
    }

    /// Check if this mode is educational (most restrictive)
    pub fn is_educational(&self) -> bool {
        matches!(self, SafetyMode::Educational)
    }
}

impl std::fmt::Display for SafetyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyMode::Educational => write!(f, "educational"),
            SafetyMode::Standard => write!(f, "standard"),
            SafetyMode::Expert => write!(f, "expert"),
        }
    }
}

impl std::str::FromStr for SafetyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "educational" | "local" | "safe" => Ok(SafetyMode::Educational),
            "standard" | "normal" | "default" => Ok(SafetyMode::Standard),
            "expert" | "advanced" | "unrestricted" => Ok(SafetyMode::Expert),
            _ => Err(format!("Unknown safety mode: {}", s)),
        }
    }
}

/// Operation category for safety classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationCategory {
    /// Read-only operations (safe)
    Read,
    /// Debug control operations (suspend, breakpoints)
    Debug,
    /// Write/patch operations (dangerous)
    Write,
    /// Code injection/execution (very dangerous)
    Execute,
    /// Hook installation (dangerous)
    Hook,
    /// System-level operations (critical)
    System,
}

impl OperationCategory {
    /// Get the danger level (0 = safe, higher = more dangerous)
    pub fn danger_level(&self) -> u8 {
        match self {
            OperationCategory::Read => 0,
            OperationCategory::Debug => 1,
            OperationCategory::Write => 2,
            OperationCategory::Hook => 3,
            OperationCategory::Execute => 4,
            OperationCategory::System => 5,
        }
    }

    /// Check if this operation is considered dangerous
    pub fn is_dangerous(&self) -> bool {
        self.danger_level() >= 2
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum operations per second (0 = unlimited)
    pub ops_per_second: u32,
    /// Maximum operations per minute (0 = unlimited)
    pub ops_per_minute: u32,
    /// Maximum write operations per minute
    pub writes_per_minute: u32,
    /// Burst allowance (extra ops allowed in short bursts)
    pub burst_allowance: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ops_per_second: 100,
            ops_per_minute: 1000,
            writes_per_minute: 60,
            burst_allowance: 10,
        }
    }
}

/// Scan and memory limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum bytes to scan in a single operation
    pub max_scan_size: usize,
    /// Maximum bytes to read in a single operation
    pub max_read_size: usize,
    /// Maximum bytes to write in a single operation
    pub max_write_size: usize,
    /// Maximum memory allocation per request
    pub max_alloc_size: usize,
    /// Maximum total allocations
    pub max_total_allocs: usize,
    /// Maximum disassembly instructions
    pub max_disasm_instructions: usize,
    /// Maximum search results
    pub max_search_results: usize,
    /// Warning threshold (percentage of limit)
    pub warning_threshold_percent: u8,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_scan_size: 256 * 1024 * 1024, // 256 MB
            max_read_size: 16 * 1024 * 1024,  // 16 MB
            max_write_size: 1024 * 1024,      // 1 MB
            max_alloc_size: 64 * 1024 * 1024, // 64 MB
            max_total_allocs: 100,
            max_disasm_instructions: 10000,
            max_search_results: 100000,
            warning_threshold_percent: 80,
        }
    }
}

/// Protected process configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedProcessConfig {
    /// List of protected process names (case-insensitive)
    pub protected_names: HashSet<String>,
    /// Warn when targeting system processes
    pub warn_system_processes: bool,
    /// Block operations on critical system processes
    pub block_critical_processes: bool,
}

impl Default for ProtectedProcessConfig {
    fn default() -> Self {
        let mut protected = HashSet::new();
        // Windows critical processes
        protected.insert("csrss.exe".to_string());
        protected.insert("smss.exe".to_string());
        protected.insert("wininit.exe".to_string());
        protected.insert("services.exe".to_string());
        protected.insert("lsass.exe".to_string());
        protected.insert("svchost.exe".to_string());
        protected.insert("system".to_string());
        protected.insert("registry".to_string());
        protected.insert("dwm.exe".to_string());
        protected.insert("winlogon.exe".to_string());
        // Security software
        protected.insert("msmpeng.exe".to_string());
        protected.insert("mssense.exe".to_string());

        Self {
            protected_names: protected,
            warn_system_processes: true,
            block_critical_processes: true,
        }
    }
}

/// Main safety configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    /// Current safety mode
    pub mode: SafetyMode,
    /// Rate limiting settings
    pub rate_limits: RateLimitConfig,
    /// Size and count limits
    pub limits: LimitsConfig,
    /// Protected process settings
    pub protected_processes: ProtectedProcessConfig,
    /// Enable dry-run mode for patches
    pub dry_run_enabled: bool,
    /// Auto-backup before major changes
    pub auto_backup: bool,
    /// Maximum patch history entries to keep
    pub max_patch_history: usize,
    /// Enable crash recovery
    pub crash_recovery: bool,
    /// Operations requiring explicit approval
    pub require_approval: HashSet<String>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        let mut require_approval = HashSet::new();
        require_approval.insert("memory_write".to_string());
        require_approval.insert("patch_bytes".to_string());
        require_approval.insert("patch_nop".to_string());
        require_approval.insert("hook_create".to_string());
        require_approval.insert("exec_shellcode".to_string());
        require_approval.insert("exec_call".to_string());

        Self {
            mode: SafetyMode::default(),
            rate_limits: RateLimitConfig::default(),
            limits: LimitsConfig::default(),
            protected_processes: ProtectedProcessConfig::default(),
            dry_run_enabled: false,
            auto_backup: true,
            max_patch_history: 100,
            crash_recovery: true,
            require_approval,
        }
    }
}

/// A single patch operation that can be undone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchEntry {
    /// Unique patch ID
    pub id: u64,
    /// Address where patch was applied
    pub address: usize,
    /// Original bytes before patch
    pub original_bytes: Vec<u8>,
    /// New bytes that were written
    pub patched_bytes: Vec<u8>,
    /// Description of what was patched
    pub description: String,
    /// Timestamp (Unix millis)
    pub timestamp_ms: u64,
    /// Whether this patch has been undone
    pub undone: bool,
    /// Tool that created this patch
    pub tool_name: String,
}

impl PatchEntry {
    /// Create a new patch entry
    pub fn new(
        id: u64,
        address: usize,
        original: Vec<u8>,
        patched: Vec<u8>,
        description: String,
        tool_name: String,
    ) -> Self {
        Self {
            id,
            address,
            original_bytes: original,
            patched_bytes: patched,
            description,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            undone: false,
            tool_name,
        }
    }

    /// Get the size of this patch in bytes
    pub fn size(&self) -> usize {
        self.patched_bytes.len()
    }
}

/// Safety check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyCheckResult {
    /// Operation is allowed
    Allowed,
    /// Operation is allowed but with a warning
    AllowedWithWarning(String),
    /// Operation requires explicit approval
    RequiresApproval {
        reason: String,
        approval_token: String,
    },
    /// Operation is blocked
    Blocked(String),
    /// Rate limit exceeded
    RateLimited {
        retry_after_ms: u64,
        message: String,
    },
    /// Size limit exceeded
    SizeLimitExceeded {
        requested: usize,
        limit: usize,
        message: String,
    },
}

impl SafetyCheckResult {
    /// Check if the result allows the operation to proceed
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            SafetyCheckResult::Allowed | SafetyCheckResult::AllowedWithWarning(_)
        )
    }

    /// Check if the result blocks the operation
    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            SafetyCheckResult::Blocked(_)
                | SafetyCheckResult::RateLimited { .. }
                | SafetyCheckResult::SizeLimitExceeded { .. }
        )
    }

    /// Check if approval is required
    pub fn requires_approval(&self) -> bool {
        matches!(self, SafetyCheckResult::RequiresApproval { .. })
    }

    /// Get the warning or error message if any
    pub fn message(&self) -> Option<&str> {
        match self {
            SafetyCheckResult::Allowed => None,
            SafetyCheckResult::AllowedWithWarning(msg) => Some(msg),
            SafetyCheckResult::RequiresApproval { reason, .. } => Some(reason),
            SafetyCheckResult::Blocked(msg) => Some(msg),
            SafetyCheckResult::RateLimited { message, .. } => Some(message),
            SafetyCheckResult::SizeLimitExceeded { message, .. } => Some(message),
        }
    }
}

/// Dry-run preview result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunPreview {
    /// Tool that would be called
    pub tool_name: String,
    /// Address affected
    pub address: usize,
    /// Size of change
    pub size: usize,
    /// Current bytes at location
    pub current_bytes: Vec<u8>,
    /// Bytes that would be written
    pub proposed_bytes: Vec<u8>,
    /// Human-readable diff
    pub diff_text: String,
    /// Warnings about the operation
    pub warnings: Vec<String>,
    /// Estimated reversibility
    pub reversible: bool,
}

/// Backup entry for crash recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    /// Unique backup ID
    pub id: u64,
    /// Session ID this backup belongs to
    pub session_id: String,
    /// Timestamp (Unix millis)
    pub timestamp_ms: u64,
    /// All patches that were applied
    pub patches: Vec<PatchEntry>,
    /// State checksum for validation
    pub checksum: String,
}

/// Safety statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SafetyStats {
    /// Total operations checked
    pub total_checks: u64,
    /// Operations allowed
    pub allowed: u64,
    /// Operations blocked
    pub blocked: u64,
    /// Operations that required approval
    pub approvals_requested: u64,
    /// Approvals granted
    pub approvals_granted: u64,
    /// Rate limit hits
    pub rate_limit_hits: u64,
    /// Size limit hits
    pub size_limit_hits: u64,
    /// Patches created
    pub patches_created: u64,
    /// Patches undone
    pub patches_undone: u64,
    /// Warnings issued
    pub warnings_issued: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_mode_parsing() {
        assert_eq!(
            "educational".parse::<SafetyMode>().unwrap(),
            SafetyMode::Educational
        );
        assert_eq!(
            "standard".parse::<SafetyMode>().unwrap(),
            SafetyMode::Standard
        );
        assert_eq!("expert".parse::<SafetyMode>().unwrap(), SafetyMode::Expert);
        assert_eq!(
            "safe".parse::<SafetyMode>().unwrap(),
            SafetyMode::Educational
        );
        assert_eq!(
            "normal".parse::<SafetyMode>().unwrap(),
            SafetyMode::Standard
        );
        assert!("invalid".parse::<SafetyMode>().is_err());
    }

    #[test]
    fn test_safety_mode_properties() {
        assert!(!SafetyMode::Educational.allows_dangerous_ops());
        assert!(!SafetyMode::Standard.allows_dangerous_ops());
        assert!(SafetyMode::Expert.allows_dangerous_ops());

        assert!(SafetyMode::Educational.requires_write_approval());
        assert!(SafetyMode::Standard.requires_write_approval());
        assert!(!SafetyMode::Expert.requires_write_approval());
    }

    #[test]
    fn test_operation_category_danger_levels() {
        assert_eq!(OperationCategory::Read.danger_level(), 0);
        assert_eq!(OperationCategory::Debug.danger_level(), 1);
        assert_eq!(OperationCategory::Write.danger_level(), 2);
        assert_eq!(OperationCategory::Execute.danger_level(), 4);

        assert!(!OperationCategory::Read.is_dangerous());
        assert!(!OperationCategory::Debug.is_dangerous());
        assert!(OperationCategory::Write.is_dangerous());
        assert!(OperationCategory::Execute.is_dangerous());
    }

    #[test]
    fn test_safety_check_result() {
        assert!(SafetyCheckResult::Allowed.is_allowed());
        assert!(SafetyCheckResult::AllowedWithWarning("test".to_string()).is_allowed());
        assert!(!SafetyCheckResult::Blocked("test".to_string()).is_allowed());

        assert!(SafetyCheckResult::Blocked("test".to_string()).is_blocked());
        assert!(SafetyCheckResult::RateLimited {
            retry_after_ms: 1000,
            message: "test".to_string()
        }
        .is_blocked());
    }

    #[test]
    fn test_patch_entry() {
        let entry = PatchEntry::new(
            1,
            0x1000,
            vec![0x90, 0x90],
            vec![0xCC, 0xCC],
            "Test patch".to_string(),
            "test_tool".to_string(),
        );
        assert_eq!(entry.size(), 2);
        assert!(!entry.undone);
        assert!(entry.timestamp_ms > 0);
    }

    #[test]
    fn test_default_protected_processes() {
        let config = ProtectedProcessConfig::default();
        assert!(config.protected_names.contains("lsass.exe"));
        assert!(config.protected_names.contains("csrss.exe"));
        assert!(config.warn_system_processes);
        assert!(config.block_critical_processes);
    }
}
