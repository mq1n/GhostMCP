//! API Override & Conditional Breakpoints
//!
//! Parameter modification, return value override, conditional API breakpoints,
//! and audit trail logging.
//!
//! # Features
//! - Conditional API Breakpoints (before/after call, conditions on args/return/thread/caller/hit count)
//! - Pause Mechanism (thread coordination, timeout, break notification)
//! - Parameter Override (integers, booleans, pointers, strings, buffers, NULL injection)
//! - Return Value Override (return code, HRESULT/NTSTATUS, SetLastError, output params)
//! - Audit Trail (log modifications, before/after values, export)

use ghost_common::types::{
    ApiBreakStackFrame, ApiBreakpointConfig, ApiBreakpointId, ApiBreakpointStatus,
    ArgumentComparison, AuditConfig, AuditDetails, AuditEntry, AuditEntryId, AuditEntryType,
    AuditExportFormat, AuditExportRequest, AuditExportResult, BreakNotification, BreakResponse,
    BreakpointCondition, BreakpointTiming, CapturedArgument, CapturedReturnValue, ComparisonValue,
    OverrideRule, OverrideRuleId, OverrideValue, ParameterOverride, PauseConfig, ReturnOverride,
    TimeoutAction,
};
use ghost_common::{Error, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace};

/// Maximum breakpoints allowed
const MAX_BREAKPOINTS: usize = 1000;
/// Maximum override rules
const MAX_OVERRIDE_RULES: usize = 1000;
/// Maximum audit entries to keep in memory
const DEFAULT_MAX_AUDIT_ENTRIES: usize = 10000;
/// Default pause timeout in milliseconds
const DEFAULT_PAUSE_TIMEOUT_MS: u64 = 30000;

/// API Override Engine
pub struct ApiOverrideEngine {
    /// Next breakpoint ID
    next_breakpoint_id: AtomicU32,
    /// Next override rule ID
    next_override_rule_id: AtomicU32,
    /// Next audit entry ID
    next_audit_entry_id: AtomicU64,
    /// Next notification ID
    next_notification_id: AtomicU64,
    /// Registered breakpoints
    breakpoints: RwLock<HashMap<ApiBreakpointId, BreakpointState>>,
    /// Override rules
    override_rules: RwLock<HashMap<OverrideRuleId, OverrideRule>>,
    /// Audit trail
    audit_trail: RwLock<Vec<AuditEntry>>,
    /// Audit configuration
    audit_config: RwLock<AuditConfig>,
    /// Pending break notifications awaiting response
    pending_breaks: RwLock<HashMap<u64, PendingBreak>>,
    /// Pause configuration
    pause_config: RwLock<PauseConfig>,
}

/// Internal state for a breakpoint
struct BreakpointState {
    /// Configuration
    config: ApiBreakpointConfig,
    /// Current hit count
    hit_count: u64,
    /// Whether currently installed
    installed: bool,
    /// Last hit timestamp
    last_hit_time: Option<u64>,
    /// Last hit thread ID
    last_hit_thread: Option<u32>,
}

/// A pending break awaiting response
#[allow(dead_code)]
struct PendingBreak {
    /// Notification that was sent
    notification: BreakNotification,
    /// When the break was created
    created: Instant,
    /// Thread that is paused
    thread_id: u32,
}

impl Default for ApiOverrideEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiOverrideEngine {
    pub fn new() -> Self {
        Self {
            next_breakpoint_id: AtomicU32::new(1),
            next_override_rule_id: AtomicU32::new(1),
            next_audit_entry_id: AtomicU64::new(1),
            next_notification_id: AtomicU64::new(1),
            breakpoints: RwLock::new(HashMap::new()),
            override_rules: RwLock::new(HashMap::new()),
            audit_trail: RwLock::new(Vec::new()),
            audit_config: RwLock::new(AuditConfig {
                enabled: true,
                max_entries: DEFAULT_MAX_AUDIT_ENTRIES,
                capture_call_stacks: true,
                log_breakpoint_hits: false,
                log_file: None,
            }),
            pending_breaks: RwLock::new(HashMap::new()),
            pause_config: RwLock::new(PauseConfig {
                pause_thread: true,
                timeout_ms: DEFAULT_PAUSE_TIMEOUT_MS,
                timeout_action: TimeoutAction::Continue,
                capture_context: true,
            }),
        }
    }

    // ========================================================================
    // Breakpoint Management
    // ========================================================================

    /// Register a new conditional API breakpoint
    pub fn add_breakpoint(&self, mut config: ApiBreakpointConfig) -> Result<ApiBreakpointId> {
        let breakpoints = self
            .breakpoints
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if breakpoints.len() >= MAX_BREAKPOINTS {
            return Err(Error::Internal(format!(
                "Maximum breakpoints ({}) reached",
                MAX_BREAKPOINTS
            )));
        }
        drop(breakpoints);

        let id = ApiBreakpointId(self.next_breakpoint_id.fetch_add(1, Ordering::SeqCst));
        config.id = Some(id);

        let state = BreakpointState {
            config,
            hit_count: 0,
            installed: false,
            last_hit_time: None,
            last_hit_thread: None,
        };

        let mut breakpoints = self
            .breakpoints
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        breakpoints.insert(id, state);

        info!("Added API breakpoint {:?}", id);
        Ok(id)
    }

    /// Remove a breakpoint
    pub fn remove_breakpoint(&self, id: ApiBreakpointId) -> Result<()> {
        let mut breakpoints = self
            .breakpoints
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if breakpoints.remove(&id).is_some() {
            info!("Removed API breakpoint {:?}", id);
            Ok(())
        } else {
            Err(Error::Internal(format!("Breakpoint {:?} not found", id)))
        }
    }

    /// Enable or disable a breakpoint
    pub fn set_breakpoint_enabled(&self, id: ApiBreakpointId, enabled: bool) -> Result<()> {
        let mut breakpoints = self
            .breakpoints
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if let Some(state) = breakpoints.get_mut(&id) {
            state.config.enabled = enabled;
            debug!("Breakpoint {:?} enabled={}", id, enabled);
            Ok(())
        } else {
            Err(Error::Internal(format!("Breakpoint {:?} not found", id)))
        }
    }

    /// Get breakpoint status
    pub fn get_breakpoint_status(&self, id: ApiBreakpointId) -> Result<ApiBreakpointStatus> {
        let breakpoints = self
            .breakpoints
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if let Some(state) = breakpoints.get(&id) {
            Ok(ApiBreakpointStatus {
                config: state.config.clone(),
                hit_count: state.hit_count,
                installed: state.installed,
                last_hit_time: state.last_hit_time,
                last_hit_thread: state.last_hit_thread,
            })
        } else {
            Err(Error::Internal(format!("Breakpoint {:?} not found", id)))
        }
    }

    /// List all breakpoints
    pub fn list_breakpoints(&self) -> Result<Vec<ApiBreakpointStatus>> {
        let breakpoints = self
            .breakpoints
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        Ok(breakpoints
            .values()
            .map(|state| ApiBreakpointStatus {
                config: state.config.clone(),
                hit_count: state.hit_count,
                installed: state.installed,
                last_hit_time: state.last_hit_time,
                last_hit_thread: state.last_hit_thread,
            })
            .collect())
    }

    // ========================================================================
    // Condition Evaluation
    // ========================================================================

    /// Evaluate if a breakpoint condition is satisfied
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_condition(
        &self,
        condition: &BreakpointCondition,
        args: &[CapturedArgument],
        return_value: Option<&CapturedReturnValue>,
        thread_id: u32,
        caller_module: Option<&str>,
        caller_address: u64,
        hit_count: u64,
    ) -> bool {
        match condition {
            BreakpointCondition::Always => true,

            BreakpointCondition::Argument { index, comparison } => {
                if let Some(arg) = args.get(*index) {
                    self.evaluate_argument_comparison(&arg.raw_value, comparison)
                } else {
                    false
                }
            }

            BreakpointCondition::ReturnValue(comparison) => {
                if let Some(rv) = return_value {
                    self.evaluate_argument_comparison(&rv.raw_value, comparison)
                } else {
                    false
                }
            }

            BreakpointCondition::ThreadId(ids) => ids.contains(&thread_id),

            BreakpointCondition::CallerModule(module) => caller_module
                .map(|m| m.to_lowercase().contains(&module.to_lowercase()))
                .unwrap_or(false),

            BreakpointCondition::CallerAddress { start, end } => {
                caller_address >= *start && caller_address <= *end
            }

            BreakpointCondition::HitCount { count, .. } => hit_count == *count,

            BreakpointCondition::HitCountModulo(n) => *n > 0 && hit_count % *n == 0,

            BreakpointCondition::And(conditions) => conditions.iter().all(|c| {
                self.evaluate_condition(
                    c,
                    args,
                    return_value,
                    thread_id,
                    caller_module,
                    caller_address,
                    hit_count,
                )
            }),

            BreakpointCondition::Or(conditions) => conditions.iter().any(|c| {
                self.evaluate_condition(
                    c,
                    args,
                    return_value,
                    thread_id,
                    caller_module,
                    caller_address,
                    hit_count,
                )
            }),

            BreakpointCondition::Not(inner) => !self.evaluate_condition(
                inner,
                args,
                return_value,
                thread_id,
                caller_module,
                caller_address,
                hit_count,
            ),
        }
    }

    /// Evaluate an argument comparison
    fn evaluate_argument_comparison(
        &self,
        raw_value: &u64,
        comparison: &ArgumentComparison,
    ) -> bool {
        let value = *raw_value as i64;

        match comparison {
            ArgumentComparison::Equal(cv) => self.compare_value(value, cv, |a, b| a == b),
            ArgumentComparison::NotEqual(cv) => self.compare_value(value, cv, |a, b| a != b),
            ArgumentComparison::LessThan(v) => value < *v,
            ArgumentComparison::LessOrEqual(v) => value <= *v,
            ArgumentComparison::GreaterThan(v) => value > *v,
            ArgumentComparison::GreaterOrEqual(v) => value >= *v,
            ArgumentComparison::InRange { min, max } => value >= *min && value <= *max,
            ArgumentComparison::HasBits(bits) => (*raw_value & bits) == *bits,
            ArgumentComparison::ClearBits(bits) => (*raw_value & bits) == 0,
            ArgumentComparison::IsNull => *raw_value == 0,
            ArgumentComparison::IsNotNull => *raw_value != 0,
            // String comparisons would need actual string data
            ArgumentComparison::StringEquals { .. } => false, // Would need string capture
            ArgumentComparison::StringContains { .. } => false,
            ArgumentComparison::StringMatches(_) => false,
            ArgumentComparison::BufferContains(_) => false,
        }
    }

    fn compare_value<F>(&self, value: i64, cv: &ComparisonValue, cmp: F) -> bool
    where
        F: Fn(i64, i64) -> bool,
    {
        match cv {
            ComparisonValue::Int(v) => cmp(value, *v),
            ComparisonValue::UInt(v) => cmp(value as u64 as i64, *v as i64),
            ComparisonValue::Float(v) => cmp(value, *v as i64),
            ComparisonValue::Bool(v) => cmp(value, if *v { 1 } else { 0 }),
            ComparisonValue::Address(v) => cmp(value as u64 as i64, *v as i64),
            ComparisonValue::String(_) => false, // Can't compare raw value to string
        }
    }

    // ========================================================================
    // Override Rule Management
    // ========================================================================

    /// Add an override rule
    pub fn add_override_rule(&self, mut rule: OverrideRule) -> Result<OverrideRuleId> {
        let rules = self
            .override_rules
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if rules.len() >= MAX_OVERRIDE_RULES {
            return Err(Error::Internal(format!(
                "Maximum override rules ({}) reached",
                MAX_OVERRIDE_RULES
            )));
        }
        drop(rules);

        let id = OverrideRuleId(self.next_override_rule_id.fetch_add(1, Ordering::SeqCst));
        rule.id = id;

        let mut rules = self
            .override_rules
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        rules.insert(id, rule);

        info!("Added override rule {:?}", id);
        Ok(id)
    }

    /// Remove an override rule
    pub fn remove_override_rule(&self, id: OverrideRuleId) -> Result<()> {
        let mut rules = self
            .override_rules
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if rules.remove(&id).is_some() {
            info!("Removed override rule {:?}", id);
            Ok(())
        } else {
            Err(Error::Internal(format!("Override rule {:?} not found", id)))
        }
    }

    /// Get an override rule
    pub fn get_override_rule(&self, id: OverrideRuleId) -> Result<OverrideRule> {
        let rules = self
            .override_rules
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        rules
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::Internal(format!("Override rule {:?} not found", id)))
    }

    /// List all override rules
    pub fn list_override_rules(&self) -> Result<Vec<OverrideRule>> {
        let rules = self
            .override_rules
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        Ok(rules.values().cloned().collect())
    }

    // ========================================================================
    // Break Notification Handling
    // ========================================================================

    /// Create a break notification (called when breakpoint hits)
    #[allow(clippy::too_many_arguments)]
    pub fn create_break_notification(
        &self,
        breakpoint_id: ApiBreakpointId,
        thread_id: u32,
        function_name: &str,
        timing: BreakpointTiming,
        arguments: Vec<CapturedArgument>,
        return_value: Option<CapturedReturnValue>,
        call_stack: Vec<ApiBreakStackFrame>,
    ) -> Result<BreakNotification> {
        let notification_id = self.next_notification_id.fetch_add(1, Ordering::SeqCst);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let pause_config = self
            .pause_config
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        let deadline = if pause_config.timeout_ms > 0 {
            Some(timestamp_ms + pause_config.timeout_ms)
        } else {
            None
        };

        let notification = BreakNotification {
            notification_id,
            breakpoint_id,
            thread_id,
            function_name: function_name.to_string(),
            timing,
            arguments,
            return_value,
            call_stack,
            timestamp_ms,
            requires_response: true,
            response_deadline_ms: deadline,
        };

        // Store pending break
        let mut pending = self
            .pending_breaks
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        pending.insert(
            notification_id,
            PendingBreak {
                notification: notification.clone(),
                created: Instant::now(),
                thread_id,
            },
        );

        // Update breakpoint state
        let mut breakpoints = self
            .breakpoints
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if let Some(state) = breakpoints.get_mut(&breakpoint_id) {
            state.hit_count += 1;
            state.last_hit_time = Some(timestamp_ms);
            state.last_hit_thread = Some(thread_id);

            // Handle one-shot breakpoints
            if state.config.one_shot {
                state.config.enabled = false;
            }
        }

        Ok(notification)
    }

    /// Process a break response
    pub fn process_break_response(&self, response: &BreakResponse) -> Result<()> {
        let mut pending = self
            .pending_breaks
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;

        if pending.remove(&response.notification_id).is_none() {
            return Err(Error::Internal(format!(
                "No pending break with notification ID {}",
                response.notification_id
            )));
        }

        debug!(
            "Processed break response for notification {}: action={:?}",
            response.notification_id, response.action
        );

        Ok(())
    }

    /// Check for timed-out pending breaks
    pub fn check_timeouts(&self) -> Vec<(u64, TimeoutAction)> {
        let pause_config = self.pause_config.read().ok();
        let (timeout_ms, timeout_action) = pause_config
            .map(|c| (c.timeout_ms, c.timeout_action))
            .unwrap_or((DEFAULT_PAUSE_TIMEOUT_MS, TimeoutAction::Continue));

        if timeout_ms == 0 {
            return Vec::new();
        }

        let mut timed_out = Vec::new();
        let pending = self.pending_breaks.read().ok();

        if let Some(pending) = pending {
            for (id, pb) in pending.iter() {
                if pb.created.elapsed().as_millis() as u64 >= timeout_ms {
                    timed_out.push((*id, timeout_action));
                }
            }
        }

        timed_out
    }

    // ========================================================================
    // Parameter Override Application
    // ========================================================================

    /// Apply parameter overrides to arguments
    ///
    /// Returns a list of (param_index, old_value, new_value) for audit logging
    pub fn apply_param_overrides(
        &self,
        overrides: &[ParameterOverride],
        args: &mut [u64],
    ) -> Vec<(usize, u64, u64)> {
        let mut changes = Vec::new();

        for override_item in overrides {
            if override_item.param_index < args.len() {
                let old_value = args[override_item.param_index];
                let new_value = self.override_value_to_u64(&override_item.new_value);

                args[override_item.param_index] = new_value;
                changes.push((override_item.param_index, old_value, new_value));

                trace!(
                    "Applied param override: arg[{}] {} -> {}",
                    override_item.param_index,
                    old_value,
                    new_value
                );
            }
        }

        changes
    }

    /// Convert an override value to u64
    fn override_value_to_u64(&self, value: &OverrideValue) -> u64 {
        match value {
            OverrideValue::Int(v) => *v as u64,
            OverrideValue::UInt(v) => *v,
            OverrideValue::Bool(v) => {
                if *v {
                    1
                } else {
                    0
                }
            }
            OverrideValue::Float(v) => (*v).to_bits() as u64,
            OverrideValue::Double(v) => (*v).to_bits(),
            OverrideValue::Pointer(v) => *v,
            OverrideValue::NullPointer => 0,
            // For string/buffer types, would need to allocate memory - return 0 as placeholder
            OverrideValue::StringAnsi(_) => 0,
            OverrideValue::StringUnicode(_) => 0,
            OverrideValue::Buffer(_) => 0,
            OverrideValue::RedirectBuffer { .. } => 0,
        }
    }

    /// Apply return value override
    pub fn apply_return_override(&self, override_info: &ReturnOverride) -> u64 {
        self.override_value_to_u64(&override_info.return_value)
    }

    // ========================================================================
    // Audit Trail
    // ========================================================================

    /// Log an audit entry
    #[allow(clippy::too_many_arguments)]
    pub fn log_audit_entry(
        &self,
        entry_type: AuditEntryType,
        function_name: &str,
        module: Option<&str>,
        thread_id: u32,
        breakpoint_id: Option<ApiBreakpointId>,
        override_rule_id: Option<OverrideRuleId>,
        details: AuditDetails,
        call_stack: Vec<ApiBreakStackFrame>,
    ) -> Result<AuditEntryId> {
        let config = self
            .audit_config
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        if !config.enabled {
            return Ok(AuditEntryId(0));
        }

        // Skip breakpoint hits if not configured to log them
        if entry_type == AuditEntryType::BreakpointHit && !config.log_breakpoint_hits {
            return Ok(AuditEntryId(0));
        }

        let max_entries = config.max_entries;
        drop(config);

        let id = AuditEntryId(self.next_audit_entry_id.fetch_add(1, Ordering::SeqCst));
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let entry = AuditEntry {
            id,
            timestamp_ms,
            entry_type,
            function_name: function_name.to_string(),
            module: module.map(|s| s.to_string()),
            thread_id,
            breakpoint_id,
            override_rule_id,
            details,
            call_stack,
        };

        let mut trail = self
            .audit_trail
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;

        // Trim if over limit
        while trail.len() >= max_entries {
            trail.remove(0);
        }

        trail.push(entry);

        Ok(id)
    }

    /// Get audit entries
    pub fn get_audit_entries(&self, offset: usize, limit: usize) -> Result<Vec<AuditEntry>> {
        let trail = self
            .audit_trail
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        Ok(trail.iter().skip(offset).take(limit).cloned().collect())
    }

    /// Get audit entry count
    pub fn get_audit_count(&self) -> Result<usize> {
        let trail = self
            .audit_trail
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        Ok(trail.len())
    }

    /// Clear audit trail
    pub fn clear_audit_trail(&self) -> Result<()> {
        let mut trail = self
            .audit_trail
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        trail.clear();
        info!("Cleared audit trail");
        Ok(())
    }

    /// Export audit trail
    pub fn export_audit_trail(&self, request: &AuditExportRequest) -> Result<AuditExportResult> {
        let trail = self
            .audit_trail
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;

        // Apply filters
        let filtered: Vec<_> = trail
            .iter()
            .filter(|e| {
                // Function filter
                if let Some(ref filter) = request.function_filter {
                    if !e
                        .function_name
                        .to_lowercase()
                        .contains(&filter.to_lowercase())
                    {
                        return false;
                    }
                }
                // Type filter
                if let Some(ref types) = request.type_filter {
                    if !types.contains(&e.entry_type) {
                        return false;
                    }
                }
                // Time filters
                if let Some(start) = request.start_time {
                    if e.timestamp_ms < start {
                        return false;
                    }
                }
                if let Some(end) = request.end_time {
                    if e.timestamp_ms > end {
                        return false;
                    }
                }
                true
            })
            .take(request.max_entries.unwrap_or(usize::MAX))
            .cloned()
            .collect();

        let entry_count = filtered.len();

        let data = match request.format {
            AuditExportFormat::Json => serde_json::to_string_pretty(&filtered).unwrap_or_default(),
            AuditExportFormat::JsonLines => filtered
                .iter()
                .filter_map(|e| serde_json::to_string(e).ok())
                .collect::<Vec<_>>()
                .join("\n"),
            AuditExportFormat::Csv => {
                let mut csv =
                    String::from("id,timestamp_ms,entry_type,function_name,module,thread_id\n");
                for e in &filtered {
                    csv.push_str(&format!(
                        "{},{},{:?},{},{},{}\n",
                        e.id.0,
                        e.timestamp_ms,
                        e.entry_type,
                        e.function_name,
                        e.module.as_deref().unwrap_or(""),
                        e.thread_id
                    ));
                }
                csv
            }
        };

        Ok(AuditExportResult {
            data,
            entry_count,
            format: request.format,
        })
    }

    /// Configure audit settings
    pub fn configure_audit(&self, config: AuditConfig) -> Result<()> {
        let mut current = self
            .audit_config
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        *current = config;
        info!("Updated audit configuration");
        Ok(())
    }

    /// Get current audit configuration
    pub fn get_audit_config(&self) -> Result<AuditConfig> {
        let config = self
            .audit_config
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        Ok(config.clone())
    }

    // ========================================================================
    // Pause Configuration
    // ========================================================================

    /// Configure pause behavior
    pub fn configure_pause(&self, config: PauseConfig) -> Result<()> {
        let mut current = self
            .pause_config
            .write()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        *current = config;
        info!("Updated pause configuration");
        Ok(())
    }

    /// Get current pause configuration
    pub fn get_pause_config(&self) -> Result<PauseConfig> {
        let config = self
            .pause_config
            .read()
            .map_err(|_| Error::Internal("Lock poisoned".into()))?;
        Ok(config.clone())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::AuditValue;

    #[test]
    fn test_add_breakpoint() {
        let engine = ApiOverrideEngine::new();
        let config = ApiBreakpointConfig {
            id: None,
            function_name: "CreateFileW".to_string(),
            module: Some("kernel32.dll".to_string()),
            timing: BreakpointTiming::BeforeCall,
            condition: BreakpointCondition::Always,
            enabled: true,
            one_shot: false,
            description: None,
            override_rules: vec![],
        };

        let id = engine.add_breakpoint(config).unwrap();
        assert_eq!(id.0, 1);

        let status = engine.get_breakpoint_status(id).unwrap();
        assert_eq!(status.config.function_name, "CreateFileW");
        assert_eq!(status.hit_count, 0);
    }

    #[test]
    fn test_evaluate_condition_always() {
        let engine = ApiOverrideEngine::new();
        assert!(engine.evaluate_condition(
            &BreakpointCondition::Always,
            &[],
            None,
            1234,
            None,
            0,
            0
        ));
    }

    #[test]
    fn test_evaluate_condition_thread_id() {
        let engine = ApiOverrideEngine::new();
        let cond = BreakpointCondition::ThreadId(vec![1234, 5678]);

        assert!(engine.evaluate_condition(&cond, &[], None, 1234, None, 0, 0));
        assert!(!engine.evaluate_condition(&cond, &[], None, 9999, None, 0, 0));
    }

    #[test]
    fn test_evaluate_condition_hit_count() {
        let engine = ApiOverrideEngine::new();
        let cond = BreakpointCondition::HitCount {
            count: 5,
            reset_after: false,
        };

        assert!(!engine.evaluate_condition(&cond, &[], None, 0, None, 0, 4));
        assert!(engine.evaluate_condition(&cond, &[], None, 0, None, 0, 5));
        assert!(!engine.evaluate_condition(&cond, &[], None, 0, None, 0, 6));
    }

    #[test]
    fn test_evaluate_condition_and() {
        let engine = ApiOverrideEngine::new();
        let cond = BreakpointCondition::And(vec![
            BreakpointCondition::ThreadId(vec![1234]),
            BreakpointCondition::HitCountModulo(2),
        ]);

        assert!(engine.evaluate_condition(&cond, &[], None, 1234, None, 0, 2));
        assert!(!engine.evaluate_condition(&cond, &[], None, 1234, None, 0, 3));
        assert!(!engine.evaluate_condition(&cond, &[], None, 9999, None, 0, 2));
    }

    #[test]
    fn test_add_override_rule() {
        let engine = ApiOverrideEngine::new();
        let rule = OverrideRule {
            id: OverrideRuleId(0),
            name: "Test Rule".to_string(),
            description: None,
            function_name: "CreateFileW".to_string(),
            module: None,
            condition: BreakpointCondition::Always,
            param_overrides: vec![],
            return_override: None,
            enabled: true,
        };

        let id = engine.add_override_rule(rule).unwrap();
        assert_eq!(id.0, 1);

        let retrieved = engine.get_override_rule(id).unwrap();
        assert_eq!(retrieved.name, "Test Rule");
    }

    #[test]
    fn test_audit_trail() {
        let engine = ApiOverrideEngine::new();

        let id = engine
            .log_audit_entry(
                AuditEntryType::ParameterOverride,
                "CreateFileW",
                Some("kernel32.dll"),
                1234,
                None,
                None,
                AuditDetails {
                    param_index: Some(0),
                    param_name: Some("lpFileName".to_string()),
                    original_value: Some(AuditValue::Pointer(0x12345678)),
                    new_value: Some(AuditValue::Pointer(0x87654321)),
                    context: None,
                },
                vec![],
            )
            .unwrap();

        assert!(id.0 > 0);

        let count = engine.get_audit_count().unwrap();
        assert_eq!(count, 1);

        let entries = engine.get_audit_entries(0, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].function_name, "CreateFileW");
    }

    #[test]
    fn test_apply_param_overrides() {
        let engine = ApiOverrideEngine::new();
        let mut args = [100u64, 200, 300];

        let overrides = vec![
            ParameterOverride {
                param_index: 0,
                new_value: OverrideValue::UInt(999),
            },
            ParameterOverride {
                param_index: 2,
                new_value: OverrideValue::NullPointer,
            },
        ];

        let changes = engine.apply_param_overrides(&overrides, &mut args);

        assert_eq!(args[0], 999);
        assert_eq!(args[1], 200);
        assert_eq!(args[2], 0);
        assert_eq!(changes.len(), 2);
    }
}
