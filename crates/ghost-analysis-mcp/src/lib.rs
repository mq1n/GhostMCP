//! Ghost-MCP Analysis Server
//!
//! Port 13341 - 82 tools for memory analysis, scanning, structures, and introspection.
//!
//! # Categories
//! - Scanner (11): scan_new, scan_first, scan_next, scan_results, scan_count, scan_progress, scan_cancel, scan_close, scan_list, scan_export, scan_import
//! - Pointer Scanner (13): pointer_scan_*
//! - Watch (10): watch_*
//! - Dump (13): dump_*, pe_*
//! - Structure (11): struct_*, enum_create
//! - Introspection (20): introspect_*
//! - Meta Shared (4): mcp_capabilities, mcp_documentation, mcp_version, mcp_health
//!
//! # Implementation Notes
//! - Dump tools integrate with agent's centralized patch history
//! - All tools forwarded to agent with proper validation and logging
//! - Production hardening with input validation and defensive programming

pub mod handlers;
pub mod tools;

use crate::handlers::DumpHandler;
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

/// Expected tool count for ghost-analysis-mcp (82 tools)
pub const EXPECTED_TOOL_COUNT: usize = 82;
/// Expected registry count excluding shared meta (4)
pub const EXPECTED_REGISTRY_COUNT: usize = 78;

/// Port for ghost-analysis-mcp
pub const PORT: u16 = 13341;

/// Create and configure the tool registry for ghost-analysis-mcp
///
/// # Errors
/// Returns an error if tool registration fails (e.g., duplicate tool names,
/// exceeding the 90-tool limit).
pub fn create_registry() -> Result<ToolRegistry> {
    debug!(target: "ghost_analysis_mcp", "Creating tool registry");
    let mut registry = ToolRegistry::new();

    // Register tools by category with error context
    register_category(&mut registry, "scanner", tools::scanner::register)?;
    register_category(&mut registry, "pointer", tools::pointer::register)?;
    register_category(&mut registry, "watch", tools::watch::register)?;
    register_category(&mut registry, "dump", tools::dump::register)?;
    register_category(&mut registry, "structure", tools::structure::register)?;
    register_category(&mut registry, "introspect", tools::introspect::register)?;

    // Validate final count
    let tool_count = registry.len();
    if tool_count > ghost_mcp_common::MAX_TOOLS_PER_SERVER {
        error!(
            target: "ghost_analysis_mcp",
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
        return Err(McpError::Registry(format!(
            "Registry count mismatch: got {}, expected {} (registry only, shared meta not included)",
            tool_count, EXPECTED_REGISTRY_COUNT
        )));
    }

    info!(
        target: "ghost_analysis_mcp",
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
        error!(target: "ghost_analysis_mcp", "Failed to register {} tools: {}", category, e);
        e
    })?;
    let added = registry.len() - before;
    debug!(target: "ghost_analysis_mcp", "Registered {} {} tools", added, category);
    Ok(())
}

/// Create the MCP server for ghost-analysis-mcp
pub fn create_server() -> Result<McpServer> {
    let server = McpServer::new(ServerIdentity::analysis(), ServerConfig::analysis());

    Ok(server)
}

/// Maximum tool name length for validation
const MAX_TOOL_NAME_LEN: usize = 128;

/// Maximum arguments size in bytes
const MAX_ARGS_SIZE: usize = 1024 * 1024; // 1 MB

/// Analysis tool handler with specialized dump handling and patch history integration
///
/// Dump tools must query centralized patch history from agent.
#[derive(Default, Clone)]
struct AnalysisToolHandler;

impl ToolHandlerFn for AnalysisToolHandler {
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
                warn!(target: "ghost_analysis_mcp", "Tool call with empty tool name");
                return Err(McpError::InvalidParams("Missing tool name".to_string()));
            }

            if name.len() > MAX_TOOL_NAME_LEN {
                warn!(target: "ghost_analysis_mcp", tool_len = name.len(), "Tool name too long");
                return Err(McpError::InvalidParams(format!(
                    "Tool name exceeds maximum length of {} characters",
                    MAX_TOOL_NAME_LEN
                )));
            }

            // Defensive: validate args size
            let args_str = args.to_string();
            if args_str.len() > MAX_ARGS_SIZE {
                warn!(target: "ghost_analysis_mcp", args_len = args_str.len(), "Arguments too large");
                return Err(McpError::InvalidParams(format!(
                    "Arguments exceed maximum size of {} bytes",
                    MAX_ARGS_SIZE
                )));
            }

            trace!(target: "ghost_analysis_mcp", tool = %name, "Processing tool call");

            // Route to specialized handlers for dump tools (patch history integration)
            let result = match name.as_str() {
                // Dump tools with patch history integration
                "dump_create" => DumpHandler::handle_dump_create(&agent, &args).await,
                "dump_region" => DumpHandler::handle_dump_region(&agent, &args).await,
                "dump_info" => DumpHandler::handle_dump_info(&agent, &args).await,
                "dump_compare" => DumpHandler::handle_dump_compare(&agent, &args).await,
                "dump_annotate" => DumpHandler::handle_dump_annotate(&agent, &args).await,

                // All other tools: forward to agent
                _ => {
                    if !agent.is_connected() {
                        let _ = agent.connect().await;
                    }

                    let response = agent
                        .request_with_reconnect(&name, args.clone())
                        .await
                        .map_err(|e| McpError::Handler(e.to_string()))?;

                    // Format response for MCP
                    Ok(serde_json::json!({
                        "content": [{ "type": "text", "text": response.to_string() }]
                    }))
                }
            };

            let duration_ms = start_time.elapsed().as_millis();
            match &result {
                Ok(_) => {
                    debug!(
                        target: "ghost_analysis_mcp",
                        tool = %name,
                        duration_ms = duration_ms,
                        "Tool call completed"
                    );
                }
                Err(e) => {
                    error!(
                        target: "ghost_analysis_mcp",
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
    debug!(target: "ghost_analysis_mcp", "Creating server with tools");
    let server = create_server()?.with_tool_handler(AnalysisToolHandler);
    let tool_registry = create_registry()?;

    let mut registered = 0;
    let mut skipped = 0;
    {
        let mut registry = server.registry().await;
        for tool in tool_registry.tools() {
            if registry.get(&tool.name).is_none() {
                registry.register(tool.clone()).map_err(|e| {
                    error!(target: "ghost_analysis_mcp", "Failed to register tool '{}': {}", tool.name, e);
                    e
                })?;
                registered += 1;
            } else {
                skipped += 1;
            }
        }
    }

    info!(
        target: "ghost_analysis_mcp",
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
            target: "ghost_analysis_mcp",
            "Registry at {}% capacity: {}/{} tools",
            count * 100 / limit,
            count,
            limit
        );
    }

    info!(target: "ghost_analysis_mcp", "{}", registry.summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_mcp_common::ipc::create_agent_client;

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
    fn test_registry_expected_count() {
        let registry = create_registry().unwrap();
        assert_eq!(
            registry.len(),
            EXPECTED_REGISTRY_COUNT,
            "Registry count mismatch: expected {} tools in registry (excluding 4 shared meta)",
            EXPECTED_REGISTRY_COUNT
        );
    }

    #[test]
    fn test_registry_categories() {
        let registry = create_registry().unwrap();
        let categories = registry.categories();
        assert!(categories.contains(&"scanner"), "Missing scanner category");
        assert!(categories.contains(&"pointer"), "Missing pointer category");
        assert!(categories.contains(&"watch"), "Missing watch category");
        assert!(categories.contains(&"dump"), "Missing dump category");
        assert!(
            categories.contains(&"structure"),
            "Missing structure category"
        );
        assert!(
            categories.contains(&"introspect"),
            "Missing introspect category"
        );
    }

    #[test]
    fn test_registry_tool_counts_per_category() {
        let registry = create_registry().unwrap();

        // Per Appendix A in roadmap
        assert_eq!(
            registry.by_category("scanner").len(),
            11,
            "Scanner should have 11 tools"
        );
        assert_eq!(
            registry.by_category("pointer").len(),
            13,
            "Pointer should have 13 tools"
        );
        assert_eq!(
            registry.by_category("watch").len(),
            10,
            "Watch should have 10 tools"
        );
        assert_eq!(
            registry.by_category("dump").len(),
            13,
            "Dump should have 13 tools"
        );
        assert_eq!(
            registry.by_category("structure").len(),
            11,
            "Structure should have 11 tools"
        );
        assert_eq!(
            registry.by_category("introspect").len(),
            20,
            "Introspect should have 20 tools"
        );
    }

    #[test]
    fn test_total_tool_count_matches_roadmap() {
        // Target: 82 tools total (78 registry + 4 shared meta)
        let registry = create_registry().unwrap();
        let registry_count = registry.len();
        let shared_meta_count = 4; // mcp_capabilities, mcp_documentation, mcp_version, mcp_health
        let total = registry_count + shared_meta_count;

        assert_eq!(
            total, EXPECTED_TOOL_COUNT,
            "Total tool count should be {} (registry {} + shared meta {})",
            EXPECTED_TOOL_COUNT, registry_count, shared_meta_count
        );
    }

    #[test]
    fn test_dump_tools_exist() {
        // Verify dump tools for patch history integration
        let registry = create_registry().unwrap();

        assert!(
            registry.get("dump_create").is_some(),
            "dump_create should exist"
        );
        assert!(
            registry.get("dump_region").is_some(),
            "dump_region should exist"
        );
        assert!(
            registry.get("dump_info").is_some(),
            "dump_info should exist"
        );
        assert!(
            registry.get("dump_compare").is_some(),
            "dump_compare should exist"
        );
        assert!(
            registry.get("dump_annotate").is_some(),
            "dump_annotate should exist"
        );
    }

    #[tokio::test]
    async fn test_invalid_tool_name_returns_error() {
        let handler = AnalysisToolHandler;
        let agent = create_agent_client(ServerConfig::analysis());
        let result = handler
            .handle("".to_string(), serde_json::json!({}), agent)
            .await;

        assert!(matches!(result, Err(McpError::InvalidParams(_))));
    }

    #[tokio::test]
    async fn test_create_server() {
        let server = create_server().unwrap();
        assert_eq!(server.identity().name, "ghost-analysis-mcp");
        assert_eq!(server.identity().port, PORT);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PORT, 13341, "Analysis server should be on port 13341");
        assert_eq!(EXPECTED_TOOL_COUNT, 82, "Expected 82 total tools");
        assert_eq!(EXPECTED_REGISTRY_COUNT, 78, "Expected 78 registry tools");
    }
}
