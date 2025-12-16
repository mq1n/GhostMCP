//! Extended capabilities handler for ghost-extended-mcp
//!
//! Routes tool calls to the agent with proper validation and defensive programming.

use ghost_mcp_common::{
    error::{McpError, Result},
    ipc::SharedAgentClient,
};
use std::time::Duration;
use tracing::{debug, error, trace, warn};

/// Maximum time to wait for agent connection
const AGENT_CONNECT_TIMEOUT_MS: u64 = 5000;

/// Maximum number of connection retry attempts
const MAX_CONNECT_RETRIES: u32 = 3;

/// Handler for extended capability tools
pub struct ExtendedHandler;

impl ExtendedHandler {
    /// Handle a tool call by forwarding to the agent
    ///
    /// # Errors
    /// Returns an error if:
    /// - Agent connection fails after retries
    /// - Agent request fails
    /// - Response parsing fails
    pub async fn handle_tool(
        agent: &SharedAgentClient,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        trace!(target: "ghost_extended_mcp", tool = %name, "Handling extended tool");

        // Defensive: validate tool name is not empty
        if name.is_empty() {
            warn!(target: "ghost_extended_mcp", "Empty tool name received");
            return Err(McpError::InvalidParams("Tool name cannot be empty".into()));
        }

        // Ensure agent connection with retry logic
        if !agent.is_connected() {
            debug!(target: "ghost_extended_mcp", "Agent not connected, attempting connection...");

            let mut attempts = 0;
            let mut last_error = None;

            while attempts < MAX_CONNECT_RETRIES {
                attempts += 1;
                match tokio::time::timeout(
                    Duration::from_millis(AGENT_CONNECT_TIMEOUT_MS),
                    agent.connect(),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        debug!(target: "ghost_extended_mcp", "Agent connected on attempt {}", attempts);
                        break;
                    }
                    Ok(Err(e)) => {
                        warn!(
                            target: "ghost_extended_mcp",
                            attempt = attempts,
                            error = %e,
                            "Agent connection attempt failed"
                        );
                        last_error = Some(e.to_string());
                    }
                    Err(_) => {
                        warn!(
                            target: "ghost_extended_mcp",
                            attempt = attempts,
                            "Agent connection timed out"
                        );
                        last_error = Some("Connection timeout".to_string());
                    }
                }

                if attempts < MAX_CONNECT_RETRIES {
                    tokio::time::sleep(Duration::from_millis(500 * attempts as u64)).await;
                }
            }

            if !agent.is_connected() {
                let err_msg = last_error.unwrap_or_else(|| "Unknown error".to_string());
                error!(
                    target: "ghost_extended_mcp",
                    tool = %name,
                    error = %err_msg,
                    "Failed to connect to agent after {} attempts",
                    MAX_CONNECT_RETRIES
                );
                return Err(McpError::Handler(format!(
                    "Agent connection failed: {}",
                    err_msg
                )));
            }
        }

        // Forward to agent with error handling
        trace!(target: "ghost_extended_mcp", tool = %name, "Forwarding to agent");
        let response = agent
            .request_with_reconnect(name, args.clone())
            .await
            .map_err(|e| {
                error!(
                    target: "ghost_extended_mcp",
                    tool = %name,
                    error = %e,
                    "Agent request failed"
                );
                McpError::Handler(e.to_string())
            })?;

        trace!(target: "ghost_extended_mcp", tool = %name, "Agent response received");
        Ok(response)
    }

    /// Check if a tool is an extended capability tool
    pub fn is_extended_tool(name: &str) -> bool {
        // Injection tools
        name.starts_with("inject_")
            || name.starts_with("remote_")
            || name.starts_with("hollow_")
            // Anti-debug tools
            || name.starts_with("antidebug_")
            || name.starts_with("bypass_")
            || name.starts_with("hide_")
            // Input tools
            || name.starts_with("input_")
            || name.starts_with("key_")
            || name.starts_with("mouse_")
            || name.starts_with("msg_")
            // Address list tools
            || name.starts_with("table_")
            || name.starts_with("entry_")
            // Memory tools
            || name.starts_with("mem_")
            // Speedhack tools
            || name.starts_with("speed_")
            || name.starts_with("time_")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_extended_tool() {
        assert!(ExtendedHandler::is_extended_tool("inject_dll"));
        assert!(ExtendedHandler::is_extended_tool("antidebug_status"));
        assert!(ExtendedHandler::is_extended_tool("input_key"));
        assert!(ExtendedHandler::is_extended_tool("table_add"));
        assert!(ExtendedHandler::is_extended_tool("speed_set"));
        assert!(!ExtendedHandler::is_extended_tool("memory_read"));
        assert!(!ExtendedHandler::is_extended_tool("r2_disasm"));
    }
}
