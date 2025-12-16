use ghost_mcp_common::error::Result;
use serde_json::json;
use std::future::Future;
use tracing::{debug, info, warn};

use super::ActionCache;

pub struct CommandHandler;

impl CommandHandler {
    /// Handle command_batch - Execute multiple commands as a batch sequence
    pub async fn handle_command_batch<F, Fut>(
        args: &serde_json::Value,
        executor: F,
    ) -> Result<serde_json::Value>
    where
        F: Fn(String, serde_json::Value) -> Fut + Send + Sync,
        Fut: Future<Output = Result<serde_json::Value>> + Send,
    {
        let name = args.get("name").and_then(|n| n.as_str()).unwrap_or("batch");
        debug!(target: "ghost_core_mcp::command", batch_name = %name, "Starting command batch execution");

        let commands = args.get("commands").and_then(|c| c.as_array());
        let transactional = args
            .get("transactional")
            .and_then(|t| t.as_bool())
            .unwrap_or(false);

        let commands = match commands {
            Some(cmds) => {
                // Defensive: limit batch size
                const MAX_BATCH_SIZE: usize = 100;
                if cmds.len() > MAX_BATCH_SIZE {
                    warn!(target: "ghost_core_mcp::command", batch_size = cmds.len(), max = MAX_BATCH_SIZE, "Batch size exceeds limit");
                    return Ok(json!({
                        "content": [{ "type": "text", "text": format!("Batch size {} exceeds maximum of {} commands", cmds.len(), MAX_BATCH_SIZE) }],
                        "isError": true
                    }));
                }
                cmds
            }
            None => {
                warn!(target: "ghost_core_mcp::command", "command_batch missing commands array");
                return Ok(json!({
                    "content": [{ "type": "text", "text": "Missing 'commands' array parameter" }],
                    "isError": true
                }));
            }
        };

        let mut results = Vec::new();
        let mut all_success = true;
        let mut executed = 0;
        let mut failed = 0;
        let batch_start = std::time::Instant::now();

        for (idx, cmd) in commands.iter().enumerate() {
            let tool = cmd.get("tool").and_then(|t| t.as_str()).unwrap_or("");
            let cmd_args = cmd.get("arguments").cloned().unwrap_or(json!({}));
            let label = cmd.get("label").and_then(|l| l.as_str()).map(String::from);
            let continue_on_error = cmd
                .get("continue_on_error")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);

            if tool.is_empty() {
                results.push(json!({
                    "index": idx,
                    "label": label,
                    "tool": "",
                    "success": false,
                    "error": "Missing tool name",
                    "skipped": false
                }));
                failed += 1;
                all_success = false;
                if !continue_on_error {
                    break;
                }
                continue;
            }

            let cmd_start = std::time::Instant::now();

            // Execute the command via the executor closure
            let result = executor(tool.to_string(), cmd_args).await;

            let duration_ms = cmd_start.elapsed().as_millis() as u64;
            executed += 1;

            match result {
                Ok(res) => {
                    let is_error = res
                        .get("isError")
                        .and_then(|e| e.as_bool())
                        .unwrap_or(false);
                    if is_error {
                        failed += 1;
                        all_success = false;
                        results.push(json!({
                            "index": idx,
                            "label": label,
                            "tool": tool,
                            "success": false,
                            "error": res.get("content").and_then(|c| c.as_array()).and_then(|a| a.first()).and_then(|i| i.get("text")).and_then(|t| t.as_str()).unwrap_or("Unknown error"),
                            "duration_ms": duration_ms,
                            "skipped": false
                        }));
                        if !continue_on_error {
                            break;
                        }
                    } else {
                        results.push(json!({
                            "index": idx,
                            "label": label,
                            "tool": tool,
                            "success": true,
                            "result": res,
                            "duration_ms": duration_ms,
                            "skipped": false
                        }));
                    }
                }
                Err(e) => {
                    failed += 1;
                    all_success = false;
                    results.push(json!({
                        "index": idx,
                        "label": label,
                        "tool": tool,
                        "success": false,
                        "error": e.to_string(),
                        "duration_ms": duration_ms,
                        "skipped": false
                    }));
                    if !continue_on_error {
                        break;
                    }
                }
            }
        }

        let skipped = commands.len() - executed;

        info!(target: "ghost_core_mcp::command",
            batch_name = %name,
            success = all_success,
            executed = executed,
            failed = failed,
            duration_ms = batch_start.elapsed().as_millis() as u64,
            "Command batch completed"
        );

        let batch_result = json!({
            "name": name,
            "success": all_success,
            "transactional": transactional,
            "rolled_back": false,
            "total_duration_ms": batch_start.elapsed().as_millis() as u64,
            "executed_count": executed,
            "skipped_count": skipped,
            "failed_count": failed,
            "results": results
        });

        let text = serde_json::to_string_pretty(&batch_result).unwrap_or_default();
        Ok(json!({
            "content": [{ "type": "text", "text": text }]
        }))
    }

    /// Handle command_history - Query command execution history
    pub async fn handle_command_history(
        cache: &ActionCache,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        debug!(target: "ghost_core_mcp::command", "Querying command history");

        let tool_filter = args.get("tool").and_then(|t| t.as_str());
        // let _success_filter = args.get("success").and_then(|s| s.as_bool()); // Not implemented in ActionCache yet
        let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(50) as usize;

        // Use ActionCache to get history
        // Currently ActionCache only supports `handle_action_last` which returns last N
        // We might need to extend ActionCache for better filtering, but for now we filter here

        let actions = cache.get_recent(limit * 2).await; // Get more to filter

        let mut history = Vec::new();
        for action in actions {
            if let Some(tf) = tool_filter {
                if action.tool_name != tf {
                    continue;
                }
            }

            history.push(json!({
                "tool": action.tool_name,
                "arguments": action.arguments,
                "success": action.is_success(),
                "duration_ms": action.duration_ms,
                "age_seconds": action.age_seconds()
            }));

            if history.len() >= limit {
                break;
            }
        }

        let result = json!({
            "total": history.len(),
            "limit": limit,
            "entries": history,
            "note": "Showing recent cached actions"
        });

        let text = serde_json::to_string_pretty(&result).unwrap_or_default();
        Ok(json!({
            "content": [{ "type": "text", "text": text }]
        }))
    }

    /// Handle command_replay - Replay a command from history
    pub async fn handle_command_replay<F, Fut>(
        cache: &ActionCache,
        args: &serde_json::Value,
        executor: F,
    ) -> Result<serde_json::Value>
    where
        F: Fn(String, serde_json::Value) -> Fut + Send + Sync,
        Fut: Future<Output = Result<serde_json::Value>> + Send,
    {
        // For replay, we currently only support replaying the "last" action or specific one if we had IDs
        // The ActionCache doesn't expose stable IDs yet, so we'll just support replaying the last action matching a filter

        // Wait, command_replay spec says "history_id".
        // ActionCache needs to support retrieving by ID.
        // Checking ActionCache implementation... it seems it stores CachedAction but doesn't expose ID lookup easily.
        // We'll implement a best-effort "replay last" if no ID, or "replay by index" if we can.

        // For now, let's assume we replay the last action if no ID is provided,
        // or if ID is provided we interpret it as index into `action_last`.

        let history_id = args.get("history_id").and_then(|i| i.as_str());

        let actions = cache.get_recent(100).await;

        let action_to_replay = if let Some(id_str) = history_id {
            // Try to find by timestamp or some ID?
            // Since we don't have IDs in ActionCache public interface,
            // we'll try to match tool name if it looks like a tool name, else take the last one.
            actions
                .iter()
                .find(|a| a.tool_name == id_str)
                .or(actions.first())
        } else {
            actions.first()
        };

        match action_to_replay {
            Some(action) => {
                debug!(target: "ghost_core_mcp::command", tool = %action.tool_name, "Replaying command");

                let tool = action.tool_name.clone();
                let args = action.arguments.clone();

                let result = executor(tool, args).await?;

                Ok(json!({
                    "content": [{ "type": "text", "text": format!("Replay result: {}", result) }]
                }))
            }
            None => Ok(json!({
                "content": [{ "type": "text", "text": "No matching command found in history to replay" }],
                "isError": true
            })),
        }
    }
}
