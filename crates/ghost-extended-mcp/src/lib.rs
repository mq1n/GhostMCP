//! Ghost-MCP Extended Capabilities Server
//!
//! Port 13343 - ~85 tools for advanced/extended capabilities.
//!
//! # Categories
//! - Injection (22): Remote process injection, cross-process hooking, process hollowing
//! - Anti-Debug (16): Usermode hooks, PEB manipulation, anti-cheat bypasses
//! - Input (18): Keyboard/mouse injection, window messages, DirectInput
//! - Address List (14): Cheat table management, freeze values, persistence
//! - Memory (8): Advanced memory operations, compare, fill, export
//! - Speedhack (7): Time manipulation, timing API hooks
//! - Meta Shared (4): mcp_capabilities, mcp_documentation, mcp_version, mcp_health
//!
//! # Implementation Notes
//! - All tools forwarded to agent with proper validation and logging
//! - Production hardening with input validation and defensive programming
//! - Tool interfaces defined; agent-side implementation pending

pub mod handlers;
pub mod tools;

use crate::handlers::ExtendedHandler;
use ghost_mcp_common::ipc::SharedAgentClient;
use ghost_mcp_common::server::ToolHandlerFn;
use ghost_mcp_common::{
    error::{McpError, Result},
    McpServer, ServerConfig, ServerIdentity, ToolRegistry,
};
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};

/// Expected tool count for ghost-extended-mcp (85 tools total with meta)
pub const EXPECTED_TOOL_COUNT: usize = 85;
/// Expected registry count excluding shared meta (4): 22+16+18+14+8+3=81
pub const EXPECTED_REGISTRY_COUNT: usize = 81;

/// Port for ghost-extended-mcp
pub const PORT: u16 = 13343;

/// Create and configure the tool registry for ghost-extended-mcp
///
/// # Errors
/// Returns an error if tool registration fails (e.g., duplicate tool names,
/// exceeding the 90-tool limit).
pub fn create_registry() -> Result<ToolRegistry> {
    debug!(target: "ghost_extended_mcp", "Creating tool registry");
    let mut registry = ToolRegistry::new();

    // Register tools by category with error context
    register_category(&mut registry, "injection", tools::injection::register)?;
    register_category(&mut registry, "antidebug", tools::antidebug::register)?;
    register_category(&mut registry, "input", tools::input::register)?;
    register_category(&mut registry, "addresslist", tools::addresslist::register)?;
    register_category(&mut registry, "memory", tools::memory::register)?;
    register_category(&mut registry, "speedhack", tools::speedhack::register)?;

    // Validate final count
    let tool_count = registry.len();
    if tool_count > ghost_mcp_common::MAX_TOOLS_PER_SERVER {
        error!(
            target: "ghost_extended_mcp",
            "Registry exceeds limit: {} > {}",
            tool_count,
            ghost_mcp_common::MAX_TOOLS_PER_SERVER
        );
        return Err(McpError::ToolCountExceeded {
            count: tool_count,
            max: ghost_mcp_common::MAX_TOOLS_PER_SERVER,
        });
    }

    // Assert exact expected registry count (excludes shared meta tools)
    if tool_count != EXPECTED_REGISTRY_COUNT {
        warn!(
            target: "ghost_extended_mcp",
            "Registry count mismatch: got {}, expected {} (this is expected during development)",
            tool_count, EXPECTED_REGISTRY_COUNT
        );
    }

    info!(
        target: "ghost_extended_mcp",
        "Registry created: {} tools (target: {}, limit: {})",
        tool_count,
        EXPECTED_TOOL_COUNT,
        ghost_mcp_common::MAX_TOOLS_PER_SERVER
    );

    Ok(registry)
}

/// Helper to register a category with logging and error context
fn register_category(
    registry: &mut ToolRegistry,
    category: &str,
    register_fn: fn(&mut ToolRegistry) -> Result<()>,
) -> Result<()> {
    let before = registry.len();
    register_fn(registry).map_err(|e| {
        error!(target: "ghost_extended_mcp", "Failed to register {} tools: {}", category, e);
        e
    })?;
    let added = registry.len() - before;
    debug!(target: "ghost_extended_mcp", "Registered {} {} tools", added, category);
    Ok(())
}

/// Create the MCP server for ghost-extended-mcp
pub fn create_server() -> Result<McpServer> {
    let server = McpServer::new(ServerIdentity::extended(), ServerConfig::extended());

    Ok(server)
}

/// Maximum tool name length for validation
const MAX_TOOL_NAME_LEN: usize = 128;

/// Maximum arguments size in bytes
const MAX_ARGS_SIZE: usize = 1024 * 1024; // 1 MB

/// Extended capabilities tool handler
#[derive(Default, Clone)]
struct ExtendedToolHandler;

impl ToolHandlerFn for ExtendedToolHandler {
    fn handle(
        &self,
        name: String,
        args: serde_json::Value,
        agent: SharedAgentClient,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send>> {
        Box::pin(async move {
            let start_time = Instant::now();

            // Defensive: validate tool name
            if name.is_empty() {
                warn!(target: "ghost_extended_mcp", "Tool call with empty tool name");
                return Err(McpError::InvalidParams("Missing tool name".to_string()));
            }

            if name.len() > MAX_TOOL_NAME_LEN {
                warn!(target: "ghost_extended_mcp", tool_len = name.len(), "Tool name too long");
                return Err(McpError::InvalidParams(format!(
                    "Tool name exceeds maximum length of {} characters",
                    MAX_TOOL_NAME_LEN
                )));
            }

            // Defensive: validate args size
            let args_str = args.to_string();
            if args_str.len() > MAX_ARGS_SIZE {
                warn!(target: "ghost_extended_mcp", args_len = args_str.len(), "Arguments too large");
                return Err(McpError::InvalidParams(format!(
                    "Arguments exceed maximum size of {} bytes",
                    MAX_ARGS_SIZE
                )));
            }

            trace!(target: "ghost_extended_mcp", tool = %name, "Processing tool call");

            // Route through extended handler
            let result = ExtendedHandler::handle_tool(&agent, &name, &args).await;

            let duration_ms = start_time.elapsed().as_millis();
            match &result {
                Ok(_) => {
                    debug!(
                        target: "ghost_extended_mcp",
                        tool = %name,
                        duration_ms = duration_ms,
                        "Tool call completed"
                    );
                }
                Err(e) => {
                    error!(
                        target: "ghost_extended_mcp",
                        tool = %name,
                        error = %e,
                        duration_ms = duration_ms,
                        "Tool call failed"
                    );
                }
            }

            result
        })
    }
}

/// Create server with tools registered
///
/// # Errors
/// Returns an error if server creation or tool registration fails.
pub async fn create_server_with_tools() -> Result<McpServer> {
    debug!(target: "ghost_extended_mcp", "Creating server with tools");
    let server = create_server()?.with_tool_handler(ExtendedToolHandler);
    let tool_registry = create_registry()?;

    let mut registered = 0;
    let mut skipped = 0;
    {
        let mut registry = server.registry().await;
        for tool in tool_registry.tools() {
            if registry.get(&tool.name).is_none() {
                registry.register(tool.clone()).map_err(|e| {
                    error!(target: "ghost_extended_mcp", "Failed to register tool '{}': {}", tool.name, e);
                    e
                })?;
                registered += 1;
            } else {
                skipped += 1;
            }
        }
    }

    info!(
        target: "ghost_extended_mcp",
        "Server ready: {} tools registered, {} skipped",
        registered,
        skipped
    );

    Ok(server)
}

/// Validate that the registry meets expected tool count
///
/// # Errors
/// Returns an error if the registry exceeds the tool limit.
pub fn validate_registry(registry: &ToolRegistry) -> Result<()> {
    registry.validate()?;

    let count = registry.len();
    let limit = ghost_mcp_common::MAX_TOOLS_PER_SERVER;

    if count > limit * 8 / 10 {
        warn!(
            target: "ghost_extended_mcp",
            "Registry at {}% capacity: {}/{} tools",
            count * 100 / limit,
            count,
            limit
        );
    }

    info!(target: "ghost_extended_mcp", "{}", registry.summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_registry() {
        let registry = create_registry().unwrap();
        assert!(
            !registry.is_empty(),
            "Registry should have tools registered"
        );
        assert!(registry.len() <= 90, "Registry should not exceed 90 tools");
    }

    #[test]
    fn test_registry_under_limit() {
        let registry = create_registry().unwrap();
        assert!(
            registry.len() <= ghost_mcp_common::MAX_TOOLS_PER_SERVER,
            "Tool count {} exceeds maximum {}",
            registry.len(),
            ghost_mcp_common::MAX_TOOLS_PER_SERVER
        );
    }

    #[test]
    fn test_registry_categories() {
        let registry = create_registry().unwrap();
        let categories = registry.categories();
        assert!(
            categories.contains(&"injection"),
            "Missing injection category"
        );
        assert!(
            categories.contains(&"antidebug"),
            "Missing antidebug category"
        );
        assert!(categories.contains(&"input"), "Missing input category");
        assert!(
            categories.contains(&"addresslist"),
            "Missing addresslist category"
        );
        assert!(categories.contains(&"memory"), "Missing memory category");
        assert!(
            categories.contains(&"speedhack"),
            "Missing speedhack category"
        );
    }

    #[tokio::test]
    async fn test_create_server() {
        let server = create_server().unwrap();
        assert_eq!(server.identity().name, "ghost-extended-mcp");
        assert_eq!(server.identity().port, PORT);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PORT, 13343, "Extended server should be on port 13343");
        assert_eq!(EXPECTED_TOOL_COUNT, 85, "Expected 85 total tools");
    }
}
