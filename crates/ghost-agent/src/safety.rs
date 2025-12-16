//! Safety Guard Implementation
//!
//! Comprehensive safety guardrails to prevent accidents.
//! Implements rate limiting, safety mode enforcement, and size checks.

use crate::multi_client::SharedState;
use ghost_common::ipc::Capability;
use ghost_common::safety::{
    BackupEntry, DryRunPreview, OperationCategory, PatchEntry, SafetyCheckResult, SafetyConfig,
    SafetyMode, SafetyStats,
};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Tool to operation category mapping
pub fn get_tool_category(tool_name: &str) -> OperationCategory {
    match tool_name {
        // Read operations
        "agent_status"
        | "module_list"
        | "module_exports"
        | "module_imports"
        | "memory_read"
        | "memory_regions"
        | "memory_search"
        | "memory_search_pattern"
        | "disasm_at"
        | "disasm_function"
        | "decompile"
        | "symbol_resolve"
        | "xref_to"
        | "xref_from"
        | "string_list"
        | "string_search"
        | "breakpoint_list"
        | "thread_list"
        | "thread_registers"
        | "stack_walk"
        | "mcp_capabilities"
        | "mcp_documentation"
        | "mcp_version"
        | "mcp_health"
        | "session_info"
        | "action_last"
        | "action_verify"
        | "r2_info"
        | "r2_functions"
        | "r2_imports"
        | "r2_exports"
        | "r2_strings"
        | "r2_sections"
        | "r2_symbols"
        | "r2_disasm"
        | "r2_analyze"
        | "ida_info"
        | "ida_functions"
        | "ida_imports"
        | "ida_exports"
        | "ghidra_info"
        | "ghidra_functions"
        | "ghidra_imports"
        | "ghidra_exports"
        | "command_history"
        | "event_list"
        | "event_poll"
        | "ai_summarize"
        | "ai_diff"
        | "ai_explain_error"
        | "ai_patterns_list"
        | "debug_session_info"
        | "debug_session_list"
        | "cave_list"
        | "syscall_number"
        | "safety_status"
        | "safety_config"
        | "patch_history"
        | "patch_preview" => OperationCategory::Read,

        // Debug operations
        "breakpoint_set"
        | "breakpoint_remove"
        | "breakpoint_enable"
        | "breakpoint_disable"
        | "execution_continue"
        | "execution_step_into"
        | "execution_step_over"
        | "execution_step_out"
        | "thread_suspend"
        | "thread_resume"
        | "debug_session_create"
        | "debug_session_update"
        | "debug_session_close"
        | "ai_recommend_breakpoints" => OperationCategory::Debug,

        // Write operations
        "memory_write" | "patch_bytes" | "patch_nop" | "patch_undo" | "patch_redo" => {
            OperationCategory::Write
        }

        // Hook operations
        "hook_create" | "hook_remove" | "hook_enable" | "hook_disable" | "hook_list" => {
            OperationCategory::Hook
        }

        // Execute operations
        "exec_call" | "exec_call_api" | "exec_shellcode" | "exec_alloc" | "exec_free"
        | "exec_write" | "exec_resolve" | "cave_find" | "cave_alloc" | "cave_free"
        | "syscall_invoke" | "remote_thread" | "remote_apc" | "process_spawn"
        | "process_terminate" => OperationCategory::Execute,

        // System operations
        "agent_reconnect"
        | "safety_set_mode"
        | "safety_approve"
        | "safety_reset"
        | "safety_request_token"
        | "safety_release_token" => OperationCategory::System,

        // Default to read for unknown tools (safe default)
        _ => OperationCategory::Read,
    }
}

/// Rate limiter using token bucket algorithm
struct RateLimiter {
    tokens: AtomicU64,
    max_tokens: u64,
    refill_rate: f64,
    last_refill: Mutex<Instant>,
}

impl RateLimiter {
    fn new(max_tokens: u64, refill_rate: f64) -> Self {
        Self {
            tokens: AtomicU64::new(max_tokens),
            max_tokens,
            refill_rate,
            last_refill: Mutex::new(Instant::now()),
        }
    }

    fn try_acquire(&self) -> bool {
        // Refill tokens based on elapsed time
        let mut last = self.last_refill.lock();
        let elapsed = last.elapsed().as_secs_f64();
        let refill = (elapsed * self.refill_rate) as u64;

        if refill > 0 {
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + refill).min(self.max_tokens);
            self.tokens.store(new_tokens, Ordering::Relaxed);
            *last = Instant::now();
        }
        drop(last);

        // Try to consume a token
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if self
                .tokens
                .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn tokens_available(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }
}

use serde::Serialize;

/// Pending approval request
#[derive(Debug, Clone, Serialize)]
pub struct PendingApproval {
    pub token: String,
    pub tool_name: String,
    pub operation: String,
    pub reason: String,
    /// Created at timestamp (Unix millis) - Instant is not serializable
    pub created_at_ms: u64,
    /// Expires at timestamp (Unix millis) - Instant is not serializable
    pub expires_at_ms: u64,
}

/// Safety Guard - main safety enforcement component
pub struct SafetyGuard {
    config: RwLock<SafetyConfig>,
    stats: RwLock<SafetyStats>,

    // Rate limiters
    global_limiter: RateLimiter,
    write_limiter: RateLimiter,

    // Shared state reference (for patches, tokens)
    state: Arc<SharedState>,

    // Pending approvals (local cache/tracking)
    pending_approvals: RwLock<HashMap<String, PendingApproval>>,

    // Backup storage
    backups: RwLock<Vec<BackupEntry>>,

    // Current target process info
    target_process: RwLock<Option<String>>,
}

impl SafetyGuard {
    /// Create a new SafetyGuard with default configuration
    pub fn new(state: Arc<SharedState>) -> Self {
        info!(target: "ghost_agent::safety", "Initializing SafetyGuard with default configuration");
        let config = SafetyConfig::default();
        let rate_config = &config.rate_limits;
        trace!(target: "ghost_agent::safety",
            ops_per_minute = rate_config.ops_per_minute,
            writes_per_minute = rate_config.writes_per_minute,
            "Rate limits configured"
        );

        Self {
            global_limiter: RateLimiter::new(
                rate_config.ops_per_minute as u64 + rate_config.burst_allowance as u64,
                rate_config.ops_per_minute as f64 / 60.0,
            ),
            write_limiter: RateLimiter::new(
                rate_config.writes_per_minute as u64,
                rate_config.writes_per_minute as f64 / 60.0,
            ),
            config: RwLock::new(config),
            stats: RwLock::new(SafetyStats::default()),
            state,
            pending_approvals: RwLock::new(HashMap::new()),
            backups: RwLock::new(Vec::new()),
            target_process: RwLock::new(None),
        }
    }

    /// Set the current target process
    pub fn set_target_process(&self, process_name: Option<String>) {
        let mut target = self.target_process.write();
        if let Some(ref name) = process_name {
            debug!(target: "ghost_agent::safety", process = %name, "Target process set");
        }
        *target = process_name;
    }

    /// Get current safety mode
    pub fn get_mode(&self) -> SafetyMode {
        self.config.read().mode
    }

    /// Set safety mode
    pub fn set_mode(&self, mode: SafetyMode) {
        let mut config = self.config.write();
        config.mode = mode;
        info!(target: "ghost_agent::safety", mode = %mode, "Safety mode changed");

        // Sync with shared state
        let mut session = self.state.session.write();
        session.safety_mode = mode.to_string();
    }

    /// Get current configuration
    pub fn get_config(&self) -> SafetyConfig {
        self.config.read().clone()
    }

    /// Update configuration
    pub fn update_config(&self, new_config: SafetyConfig) {
        let mut config = self.config.write();
        *config = new_config;
        info!(target: "ghost_agent::safety", "Safety configuration updated");
    }

    /// Get current statistics
    pub fn get_stats(&self) -> SafetyStats {
        self.stats.read().clone()
    }

    /// Reset all statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write();
        *stats = SafetyStats::default();
        info!(target: "ghost_agent::safety", "Statistics reset");
    }

    /// Get rate limiter status
    pub fn get_rate_limit_status(&self) -> (u64, u64) {
        (
            self.global_limiter.tokens_available(),
            self.write_limiter.tokens_available(),
        )
    }

    /// Check if an operation is allowed
    pub fn check_operation(
        &self,
        tool_name: &str,
        args: &serde_json::Value,
        token_id: Option<&str>,
    ) -> SafetyCheckResult {
        let mut stats = self.stats.write();
        stats.total_checks += 1;
        drop(stats);

        let config = self.config.read();
        let category = get_tool_category(tool_name);
        let mode = config.mode;

        debug!(
            target: "ghost_agent::safety",
            tool = %tool_name,
            category = ?category,
            mode = %mode,
            "Checking operation"
        );

        // 1. Check if blocked in educational mode
        if mode.is_educational() && category.is_dangerous() {
            warn!(target: "ghost_agent::safety",
                tool = %tool_name,
                category = ?category,
                "Operation blocked in educational mode"
            );
            let mut stats = self.stats.write();
            stats.blocked += 1;
            drop(stats);

            return SafetyCheckResult::Blocked(format!(
                "Operation '{}' is blocked in educational mode. \
                 Switch to 'standard' or 'expert' mode to enable dangerous operations.",
                tool_name
            ));
        }

        // 2. Check protected processes
        if let Some(ref target) = *self.target_process.read() {
            let target_lower = target.to_lowercase();
            if config
                .protected_processes
                .protected_names
                .contains(&target_lower)
            {
                if config.protected_processes.block_critical_processes && category.is_dangerous() {
                    let mut stats = self.stats.write();
                    stats.blocked += 1;
                    return SafetyCheckResult::Blocked(format!(
                        "Target process '{}' is protected. Dangerous operations are blocked.",
                        target
                    ));
                } else if config.protected_processes.warn_system_processes {
                    let mut stats = self.stats.write();
                    stats.warnings_issued += 1;
                    // We don't return here, just warning
                }
            }
        }

        // 3. Check rate limits
        if !self.global_limiter.try_acquire() {
            warn!(target: "ghost_agent::safety", tool = %tool_name, "Global rate limit exceeded");
            let mut stats = self.stats.write();
            stats.rate_limit_hits += 1;
            return SafetyCheckResult::RateLimited {
                retry_after_ms: 1000,
                message: "Global rate limit exceeded. Please wait before retrying.".to_string(),
            };
        }

        // Check write rate limit for write operations
        if category.is_dangerous() && !self.write_limiter.try_acquire() {
            warn!(target: "ghost_agent::safety", tool = %tool_name, "Write rate limit exceeded");
            let mut stats = self.stats.write();
            stats.rate_limit_hits += 1;
            return SafetyCheckResult::RateLimited {
                retry_after_ms: 5000,
                message: "Write operation rate limit exceeded. Please wait before retrying."
                    .to_string(),
            };
        }

        // 4. Check size limits
        if let Some(size) = extract_size_from_args(args) {
            let limit = match tool_name {
                "memory_read" => config.limits.max_read_size,
                "memory_write" | "patch_bytes" => config.limits.max_write_size,
                "memory_search" | "memory_search_pattern" => config.limits.max_scan_size,
                "exec_alloc" => config.limits.max_alloc_size,
                _ => usize::MAX,
            };

            if size > limit {
                warn!(target: "ghost_agent::safety",
                    tool = %tool_name,
                    requested = size,
                    limit = limit,
                    "Size limit exceeded"
                );
                let mut stats = self.stats.write();
                stats.size_limit_hits += 1;
                return SafetyCheckResult::SizeLimitExceeded {
                    requested: size,
                    limit,
                    message: format!(
                        "Requested size {} exceeds limit {} for operation '{}'",
                        size, limit, tool_name
                    ),
                };
            }

            // Warn if approaching limit
            let threshold =
                (limit as f64 * config.limits.warning_threshold_percent as f64 / 100.0) as usize;
            if size > threshold {
                let mut stats = self.stats.write();
                stats.warnings_issued += 1;
                drop(stats);
                drop(config);
                return SafetyCheckResult::AllowedWithWarning(format!(
                    "Warning: Operation size {} is {}% of the limit {}",
                    size,
                    (size as f64 / limit as f64 * 100.0) as u32,
                    limit
                ));
            }
        }

        // 5. Check if approval is required
        let tool_normalized = tool_name.replace('.', "_");
        if config.require_approval.contains(&tool_normalized)
            && config.mode.requires_write_approval()
        {
            // If token provided and valid, allow operation
            if let Some(id) = token_id {
                let required_cap = Capability::for_method(tool_name);
                if self.state.validate_token(id, required_cap).is_ok() {
                    let mut stats = self.stats.write();
                    stats.allowed += 1;
                    return SafetyCheckResult::Allowed;
                }
                warn!(target: "ghost_agent::safety", token = %id, "Invalid or expired safety token");
            }

            let mut stats = self.stats.write();
            stats.approvals_requested += 1;
            drop(stats);

            let token = generate_approval_token();
            let mut approvals = self.pending_approvals.write();
            approvals.insert(
                token.clone(),
                PendingApproval {
                    token: token.clone(),
                    tool_name: tool_name.to_string(),
                    operation: format!("{:?}", args),
                    reason: format!(
                        "Tool '{}' requires approval in {} mode",
                        tool_name, config.mode
                    ),
                    created_at_ms: now_millis(),
                    expires_at_ms: now_millis() + 300_000, // 5 min expiry
                },
            );

            return SafetyCheckResult::RequiresApproval {
                reason: format!(
                    "Operation '{}' requires explicit approval. Use safety_approve with token to proceed.",
                    tool_name
                ),
                approval_token: token,
            };
        }

        let mut stats = self.stats.write();
        stats.allowed += 1;
        SafetyCheckResult::Allowed
    }

    /// Approve a pending operation
    pub fn approve(&self, token: &str) -> Result<String, String> {
        let mut approvals = self.pending_approvals.write();

        if let Some(approval) = approvals.remove(token) {
            if now_millis() > approval.expires_at_ms {
                return Err("Approval token has expired".to_string());
            }

            let mut stats = self.stats.write();
            stats.approvals_granted += 1;

            // Also register in SharedState for MultiClientBackend validation
            let token = self.state.issue_token(
                Capability::Write, // Assume write for now, or derive from tool
                approval.operation.clone(),
                "safety_admin",
                300,
            );

            Ok(format!(
                "Approved: {} - {}. Token: {}",
                approval.tool_name, approval.operation, token.id
            ))
        } else {
            Err("Invalid or expired approval token".to_string())
        }
    }

    /// Check if a token has been approved
    pub fn is_approved(&self, token: &str) -> bool {
        let approvals = self.pending_approvals.read();
        !approvals.contains_key(token)
    }

    /// List pending approvals
    pub fn list_pending_approvals(&self) -> Vec<PendingApproval> {
        let approvals = self.pending_approvals.read();
        let now = now_millis();
        approvals
            .values()
            .filter(|a| now < a.expires_at_ms)
            .cloned()
            .collect()
    }

    // Backup methods
    pub fn create_backup(&self) -> u64 {
        // In this implementation, we get patches from shared state
        let ipc_patches = self.state.get_patches();

        // Convert IPC patches to Safety patches
        let patches: Vec<PatchEntry> = ipc_patches
            .into_iter()
            .map(|p| PatchEntry {
                id: p.id,
                address: p.address as usize,
                original_bytes: p.original_bytes,
                patched_bytes: p.patched_bytes,
                description: p.description.unwrap_or_default(),
                timestamp_ms: p.timestamp,
                undone: !p.active,
                tool_name: p.applied_by.unwrap_or_else(|| "unknown".to_string()),
            })
            .collect();

        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let checksum = format!("{:x}", patches.len());

        // We need session_id, get it from state session metadata (client_sessions[0]?)
        // Or just use a placeholder since SafetyGuard doesn't own a session_id anymore
        let session_id = "agent".to_string();

        let backup = BackupEntry {
            id,
            session_id,
            timestamp_ms: id,
            patches,
            checksum,
        };

        let mut backups = self.backups.write();
        backups.push(backup);

        info!(target: "ghost_agent::safety", backup_id = id, "Backup created");
        id
    }

    pub fn get_backups(&self) -> Vec<BackupEntry> {
        self.backups.read().clone()
    }

    /// Generate a dry-run preview for a patch operation
    pub fn generate_preview(
        &self,
        tool_name: &str,
        address: usize,
        current_bytes: Vec<u8>,
        proposed_bytes: Vec<u8>,
    ) -> DryRunPreview {
        let diff_text = generate_hex_diff(&current_bytes, &proposed_bytes, address);
        let mut warnings = Vec::new();

        // Check for potential issues
        if proposed_bytes.iter().all(|&b| b == 0x90) {
            warnings.push("All bytes are NOPs - this will create dead code".to_string());
        }
        if proposed_bytes.iter().all(|&b| b == 0x00) {
            warnings.push("Warning: All bytes are null - this may crash the process".to_string());
        }
        if proposed_bytes.iter().all(|&b| b == 0xCC) {
            warnings.push("All bytes are INT3 - this will trigger breakpoints".to_string());
        }

        DryRunPreview {
            tool_name: tool_name.to_string(),
            address,
            size: proposed_bytes.len(),
            current_bytes,
            proposed_bytes,
            diff_text,
            warnings,
            reversible: true,
        }
    }

    /// Clean up expired approvals
    pub fn cleanup_expired(&self) {
        let mut approvals = self.pending_approvals.write();
        let now = now_millis();
        approvals.retain(|_, v| now < v.expires_at_ms);
    }
}

/// Extract size from common argument patterns
fn extract_size_from_args(args: &serde_json::Value) -> Option<usize> {
    // Try common size field names
    for field in &["size", "length", "count", "bytes", "len"] {
        if let Some(size) = args.get(field).and_then(|v| v.as_u64()) {
            return Some(size as usize);
        }
    }

    // Check for bytes array
    if let Some(bytes) = args.get("bytes").and_then(|v| v.as_array()) {
        return Some(bytes.len());
    }

    // Check for hex string
    if let Some(hex) = args.get("bytes").and_then(|v| v.as_str()) {
        let clean = hex.replace(" ", "").replace("0x", "");
        return Some(clean.len() / 2);
    }

    None
}

/// Generate a hex diff between two byte sequences
fn generate_hex_diff(original: &[u8], patched: &[u8], base_addr: usize) -> String {
    let mut diff = String::new();
    let max_len = original.len().max(patched.len());

    diff.push_str(&format!("Address: 0x{:08x}\n", base_addr));
    diff.push_str(&format!("Size: {} bytes\n\n", max_len));

    diff.push_str("Original: ");
    for b in original {
        diff.push_str(&format!("{:02x} ", b));
    }
    diff.push('\n');

    diff.push_str("Patched:  ");
    for b in patched {
        diff.push_str(&format!("{:02x} ", b));
    }
    diff.push('\n');

    // Show differences
    diff.push_str("Changes:  ");
    for i in 0..max_len {
        let orig = original.get(i).copied().unwrap_or(0);
        let patch = patched.get(i).copied().unwrap_or(0);
        if orig != patch {
            diff.push_str("^^ ");
        } else {
            diff.push_str("   ");
        }
    }
    diff.push('\n');

    diff
}

/// Generate a random-ish approval token
fn generate_approval_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("approve-{:08x}", (timestamp & 0xFFFFFFFF) as u32)
}

/// Get current time in milliseconds since Unix epoch
fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
