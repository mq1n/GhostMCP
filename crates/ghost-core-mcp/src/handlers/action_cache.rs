//! Action caching for tool call verification
//!
//! Provides caching of tool call results for action_last and action_verify tools.
//!
//! # Features
//! - Thread-safe action caching with RwLock
//! - Action verification with configurable checks
//! - Defensive input validation

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

/// Maximum tool name length for defensive validation
const MAX_TOOL_NAME_LEN: usize = 128;
/// Maximum argument size in bytes
const MAX_ARGS_SIZE: usize = 1024 * 1024; // 1MB
/// Maximum number of actions to retain in history
const MAX_HISTORY: usize = 50;

/// Result of an action (success or error)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionResult {
    Success(serde_json::Value),
    Error(String),
}

/// Cached action information
#[derive(Debug, Clone)]
pub struct CachedAction {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub result: ActionResult,
    pub timestamp: Option<Instant>,
    pub duration_ms: u64,
}

impl CachedAction {
    /// Check if action was successful
    pub fn is_success(&self) -> bool {
        matches!(self.result, ActionResult::Success(_))
    }

    /// Get age in seconds since action was cached
    pub fn age_seconds(&self) -> u64 {
        self.timestamp.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }
}

/// Thread-safe action cache
#[derive(Clone)]
pub struct ActionCache {
    last_action: Arc<RwLock<Option<CachedAction>>>,
    history: Arc<RwLock<VecDeque<CachedAction>>>,
}

impl Default for ActionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionCache {
    /// Create a new action cache
    pub fn new() -> Self {
        Self {
            last_action: Arc::new(RwLock::new(None)),
            history: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Cache an action result
    ///
    /// # Arguments
    /// * `tool_name` - Name of the tool (max 128 chars)
    /// * `arguments` - Tool arguments (max 1MB serialized)
    /// * `result` - Action result (success or error)
    /// * `duration_ms` - Execution duration in milliseconds
    pub async fn cache(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        result: ActionResult,
        duration_ms: u64,
    ) {
        // Defensive: validate tool name length
        let tool_name = if tool_name.len() > MAX_TOOL_NAME_LEN {
            warn!(target: "ghost_core_mcp::cache", len = tool_name.len(), "Tool name truncated");
            &tool_name[..MAX_TOOL_NAME_LEN]
        } else {
            tool_name
        };

        // Defensive: validate arguments size
        let args_size = arguments.to_string().len();
        let arguments = if args_size > MAX_ARGS_SIZE {
            warn!(target: "ghost_core_mcp::cache", size = args_size, "Arguments truncated for caching");
            serde_json::json!({"_truncated": true, "_original_size": args_size})
        } else {
            arguments
        };

        let action = CachedAction {
            tool_name: tool_name.to_string(),
            arguments,
            result: result.clone(),
            timestamp: Some(Instant::now()),
            duration_ms,
        };

        debug!(
            target: "ghost_core_mcp::cache",
            tool = %tool_name,
            success = matches!(result, ActionResult::Success(_)),
            duration_ms = duration_ms,
            "Action cached"
        );

        {
            let mut history = self.history.write().await;
            history.push_front(action.clone());
            while history.len() > MAX_HISTORY {
                history.pop_back();
            }
        }

        let mut cache = self.last_action.write().await;
        *cache = Some(action);
    }

    /// Get the last cached action
    pub async fn get_last(&self) -> Option<CachedAction> {
        if let Some(action) = self.history.read().await.front() {
            return Some(action.clone());
        }
        self.last_action.read().await.clone()
    }

    /// Get the most recent N cached actions (newest first)
    pub async fn get_recent(&self, count: usize) -> Vec<CachedAction> {
        let count = count.clamp(1, MAX_HISTORY);
        self.history
            .read()
            .await
            .iter()
            .take(count)
            .cloned()
            .collect()
    }

    /// Handle action_last tool call
    ///
    /// Returns the last N cached actions (newest first).
    pub async fn handle_action_last(&self, count: usize) -> serde_json::Value {
        trace!(target: "ghost_core_mcp::cache", count = count, "action_last requested");

        // Defensive: clamp count to reasonable range
        let count = count.clamp(1, 100);
        let actions = self.get_recent(count).await;

        if actions.is_empty() {
            return serde_json::json!({
                "content": [{ "type": "text", "text": "No action cached yet." }]
            });
        }

        let mut chunks = Vec::new();
        for (idx, action) in actions.iter().enumerate() {
            chunks.push(format!(
                "Action {}:\n  Tool: {}\n  Success: {}\n  Duration: {}ms\n  Age: {}s\n  Args: {}\n  Result: {:?}",
                idx + 1,
                action.tool_name,
                action.is_success(),
                action.duration_ms,
                action.age_seconds(),
                action.arguments,
                action.result
            ));
        }

        serde_json::json!({
            "content": [{
                "type": "text",
                "text": chunks.join("\n\n")
            }]
        })
    }

    /// Handle action_verify tool call
    ///
    /// Verifies the last action against expected criteria.
    ///
    /// # Arguments (from args)
    /// * `expect_success` - Expected success state (default: true)
    /// * `expect_tool` - Expected tool name (optional)
    /// * `contains` - Text that should be in result (optional)
    pub async fn handle_action_verify(&self, args: &serde_json::Value) -> serde_json::Value {
        trace!(target: "ghost_core_mcp::cache", "action_verify requested");

        let last_action = self.get_last().await;

        match last_action {
            Some(action) => {
                let expected_success = args
                    .get("expect_success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let expected_tool = args.get("expect_tool").and_then(|v| v.as_str());
                let contains_text = args.get("contains").and_then(|v| v.as_str());

                let mut checks = Vec::new();
                let mut all_passed = true;

                // Check if action was success/error as expected
                let success_check = action.is_success() == expected_success;
                checks.push(format!(
                    "Success check: {} (expected: {}, actual: {})",
                    if success_check { "PASS" } else { "FAIL" },
                    expected_success,
                    action.is_success()
                ));
                all_passed &= success_check;

                // Check tool name if specified
                if let Some(expected) = expected_tool {
                    let tool_check = action.tool_name == expected;
                    checks.push(format!(
                        "Tool check: {} (expected: {}, actual: {})",
                        if tool_check { "PASS" } else { "FAIL" },
                        expected,
                        action.tool_name
                    ));
                    all_passed &= tool_check;
                }

                // Check if result contains text
                if let Some(text) = contains_text {
                    let result_str = match &action.result {
                        ActionResult::Success(v) => v.to_string(),
                        ActionResult::Error(e) => e.clone(),
                    };
                    let contains_check = result_str.contains(text);
                    checks.push(format!(
                        "Contains check: {} (looking for: '{}')",
                        if contains_check { "PASS" } else { "FAIL" },
                        text
                    ));
                    all_passed &= contains_check;
                }

                let status_label = if all_passed { "PASSED" } else { "FAILED" };
                let summary = format!(
                    "Verification {}\n\nLast Action: {}\nDuration: {}ms\nAge: {}s\n\nChecks:\n{}",
                    status_label,
                    action.tool_name,
                    action.duration_ms,
                    action.age_seconds(),
                    checks.join("\n")
                );

                serde_json::json!({
                    "content": [{ "type": "text", "text": summary }],
                    "verification": {
                        "passed": all_passed,
                        "tool": action.tool_name,
                        "success": action.is_success(),
                        "duration_ms": action.duration_ms,
                        "age_seconds": action.age_seconds(),
                        "checks": checks
                    }
                })
            }
            None => {
                serde_json::json!({
                    "content": [{ "type": "text", "text": "No action cached. Execute a tool first." }],
                    "verification": {
                        "passed": false,
                        "error": "no_action_cached"
                    }
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_action_cache() {
        let cache = ActionCache::new();

        // Initially empty
        assert!(cache.get_last().await.is_none());

        // Cache an action
        cache
            .cache(
                "test_tool",
                serde_json::json!({"arg": "value"}),
                ActionResult::Success(serde_json::json!({"result": "ok"})),
                100,
            )
            .await;

        // Retrieve cached action
        let action = cache.get_last().await.unwrap();
        assert_eq!(action.tool_name, "test_tool");
        assert!(action.is_success());
        assert_eq!(action.duration_ms, 100);
    }

    #[tokio::test]
    async fn test_action_last() {
        let cache = ActionCache::new();

        // No action cached
        let result = cache.handle_action_last(1).await;
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("No action cached"));

        // Cache an action
        cache
            .cache(
                "memory_read",
                serde_json::json!({}),
                ActionResult::Success(serde_json::json!("data")),
                50,
            )
            .await;

        let result = cache.handle_action_last(1).await;
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("memory_read"));
    }

    #[tokio::test]
    async fn test_action_verify_success() {
        let cache = ActionCache::new();

        // Cache a successful action
        cache
            .cache(
                "memory_write",
                serde_json::json!({"address": "0x1000"}),
                ActionResult::Success(serde_json::json!({"written": 4})),
                25,
            )
            .await;

        // Verify with matching expectations
        let result = cache
            .handle_action_verify(&serde_json::json!({
                "expect_success": true,
                "expect_tool": "memory_write"
            }))
            .await;

        assert!(result["verification"]["passed"].as_bool().unwrap());
        assert_eq!(result["verification"]["tool"], "memory_write");
    }

    #[tokio::test]
    async fn test_action_verify_failure() {
        let cache = ActionCache::new();

        // Cache a failed action
        cache
            .cache(
                "memory_read",
                serde_json::json!({}),
                ActionResult::Error("Access denied".to_string()),
                10,
            )
            .await;

        // Verify expecting success (should fail)
        let result = cache
            .handle_action_verify(&serde_json::json!({"expect_success": true}))
            .await;

        assert!(!result["verification"]["passed"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_action_verify_no_action() {
        let cache = ActionCache::new();

        // Verify with no cached action
        let result = cache.handle_action_verify(&serde_json::json!({})).await;

        assert!(!result["verification"]["passed"].as_bool().unwrap());
        assert_eq!(result["verification"]["error"], "no_action_cached");
    }

    #[tokio::test]
    async fn test_action_verify_contains() {
        let cache = ActionCache::new();

        cache
            .cache(
                "disasm_at",
                serde_json::json!({}),
                ActionResult::Success(serde_json::json!("nop\nmov eax, ebx")),
                100,
            )
            .await;

        // Should pass - contains "nop"
        let result = cache
            .handle_action_verify(&serde_json::json!({"contains": "nop"}))
            .await;
        assert!(result["verification"]["passed"].as_bool().unwrap());

        // Should fail - does not contain "ret"
        let result = cache
            .handle_action_verify(&serde_json::json!({"contains": "ret"}))
            .await;
        assert!(!result["verification"]["passed"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_cache_truncates_long_tool_name() {
        let cache = ActionCache::new();
        let long_name = "a".repeat(200);

        cache
            .cache(
                &long_name,
                serde_json::json!({}),
                ActionResult::Success(serde_json::json!("ok")),
                1,
            )
            .await;

        let action = cache.get_last().await.unwrap();
        assert_eq!(action.tool_name.len(), MAX_TOOL_NAME_LEN);
    }

    #[test]
    fn test_action_result_is_success() {
        let success = ActionResult::Success(serde_json::json!("data"));
        let error = ActionResult::Error("failed".to_string());

        // ActionResult doesn't have is_success, but CachedAction does
        let cached_success = CachedAction {
            tool_name: "test".to_string(),
            arguments: serde_json::json!({}),
            result: success,
            timestamp: None,
            duration_ms: 0,
        };
        let cached_error = CachedAction {
            tool_name: "test".to_string(),
            arguments: serde_json::json!({}),
            result: error,
            timestamp: None,
            duration_ms: 0,
        };

        assert!(cached_success.is_success());
        assert!(!cached_error.is_success());
    }
}
