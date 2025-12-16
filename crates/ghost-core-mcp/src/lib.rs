//! Ghost-MCP Core Runtime Server
//!
//! Port 13340 - 85 tools for live process interaction, debugging, safety, and coordination.
//!
//! # Categories
//! - Memory (5): memory_read, memory_write, memory_search, memory_search_pattern, memory_regions
//! - Module (5): module_list, module_exports, module_imports, string_list, symbol_resolve
//! - Debug/Thread (11): thread_*, breakpoint_*, execution_*, stack_walk
//! - Session/Process (7): session_*, process_*
//! - Script/Hook (11): script_*, hook_*, rpc_*
//! - Execution (15): exec_*, cave_*, syscall_*, remote_*
//! - Safety (10): safety_*, patch_*
//! - Command/Event (7): command_*, event_*
//! - Disassembly (5): disasm_*, decompile, assemble*
//! - Cross-refs (1): xref_to
//! - Meta Shared (4): mcp_capabilities, mcp_documentation, mcp_version, mcp_health
//! - Meta Core-only (4): action_last, action_verify, agent_status, agent_reconnect

pub mod handlers;
pub mod tools;

use crate::handlers::{ActionCache, ActionResult, DecompileHandler, DisasmHandler};
use ghost_mcp_common::ipc::SharedAgentClient;
use ghost_mcp_common::server::ToolHandlerFn;
use ghost_mcp_common::{
    error::{McpError, Result},
    McpServer, ServerConfig, ServerIdentity, ToolRegistry,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Expected tool count for ghost-core-mcp (85 tools)
pub const EXPECTED_TOOL_COUNT: usize = 85;
/// Expected registry count excluding shared meta (4)
pub const EXPECTED_REGISTRY_COUNT: usize = 81;

/// Port for ghost-core-mcp
pub const PORT: u16 = 13340;

/// Create and configure the tool registry for ghost-core-mcp
///
/// # Errors
/// Returns an error if tool registration fails (e.g., duplicate tool names,
/// exceeding the 90-tool limit).
pub fn create_registry() -> Result<ToolRegistry> {
    debug!(target: "ghost_core_mcp", "Creating tool registry");
    let mut registry = ToolRegistry::new();

    // Register tools by category with error context
    // Shared meta tools (4) are registered automatically by McpServer::new()

    register_category(&mut registry, "meta (core-only)", tools::meta::register)?;
    register_category(&mut registry, "memory", tools::memory::register)?;
    register_category(&mut registry, "module", tools::module::register)?;
    register_category(&mut registry, "debug", tools::debug::register)?;
    register_category(&mut registry, "session", tools::session::register)?;
    register_category(&mut registry, "script", tools::script::register)?;
    register_category(&mut registry, "execution", tools::execution::register)?;
    register_category(&mut registry, "safety", tools::safety::register)?;
    register_category(&mut registry, "command", tools::command::register)?;
    register_category(&mut registry, "disasm", tools::disasm::register)?;
    register_category(&mut registry, "xrefs", tools::xrefs::register)?;

    // Validate final count
    let tool_count = registry.len();
    if tool_count > ghost_mcp_common::MAX_TOOLS_PER_SERVER {
        error!(
            target: "ghost_core_mcp",
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
        target: "ghost_core_mcp",
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
        error!(target: "ghost_core_mcp", "Failed to register {} tools: {}", category, e);
        e
    })?;
    let added = registry.len() - before;
    debug!(target: "ghost_core_mcp", "Registered {} {} tools", added, category);
    Ok(())
}

/// Create the MCP server for ghost-core-mcp
pub fn create_server() -> Result<McpServer> {
    let server = McpServer::new(ServerIdentity::core(), ServerConfig::core());

    Ok(server)
}

/// Core tool handler with local tool support and action caching
#[derive(Clone)]
struct CoreToolHandler {
    action_cache: Arc<ActionCache>,
}

impl Default for CoreToolHandler {
    fn default() -> Self {
        Self {
            action_cache: Arc::new(ActionCache::new()),
        }
    }
}

impl ToolHandlerFn for CoreToolHandler {
    fn handle(
        &self,
        name: String,
        args: serde_json::Value,
        agent: SharedAgentClient,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send>> {
        let cache = self.action_cache.clone();

        Box::pin(async move {
            let start_time = Instant::now();

            // Route to appropriate handler based on tool name
            let result = match name.as_str() {
                // Local tools: action caching
                "action_last" => {
                    let count = args.get("count").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
                    Ok(cache.handle_action_last(count).await)
                }
                "action_verify" => Ok(cache.handle_action_verify(&args).await),

                // Local tools: disassembly (uses Capstone locally)
                "disasm_at" => DisasmHandler::handle_disasm_at(&agent, &args)
                    .await
                    .map_err(McpError::Handler),
                "disasm_function" => DisasmHandler::handle_disasm_function(&agent, &args)
                    .await
                    .map_err(McpError::Handler),
                "decompile" => DecompileHandler::handle_decompile(&agent, &args)
                    .await
                    .map_err(McpError::Handler),

                // Agent-forwarded tools (everything else)
                _ => {
                    // Ensure connection (best-effort reconnect)
                    if !agent.is_connected() {
                        let _ = agent.connect().await;
                    }

                    let result = agent
                        .request_with_reconnect(&name, args.clone())
                        .await
                        .map_err(|e| McpError::Handler(e.to_string()))?;

                    // Format response for MCP
                    Ok(serde_json::json!({
                        "content": [{ "type": "text", "text": result.to_string() }]
                    }))
                }
            };

            // Cache action result (except for action_* tools themselves)
            if !name.starts_with("action_") {
                let duration_ms = start_time.elapsed().as_millis() as u64;
                match &result {
                    Ok(v) => {
                        let is_error = v.get("isError").and_then(|e| e.as_bool()).unwrap_or(false);
                        if is_error {
                            cache
                                .cache(
                                    &name,
                                    args,
                                    ActionResult::Error("Tool returned error".to_string()),
                                    duration_ms,
                                )
                                .await;
                        } else {
                            cache
                                .cache(&name, args, ActionResult::Success(v.clone()), duration_ms)
                                .await;
                        }
                    }
                    Err(e) => {
                        cache
                            .cache(&name, args, ActionResult::Error(e.to_string()), duration_ms)
                            .await;
                    }
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
    debug!(target: "ghost_core_mcp", "Creating server with tools");
    let server = create_server()?.with_tool_handler(CoreToolHandler::default());

    // Get tool definitions from our registry (excluding shared meta which McpServer adds)
    let tool_registry = create_registry()?;

    // Register all tools from our registry
    let mut registered = 0;
    let mut skipped = 0;
    {
        let mut registry = server.registry().await;
        for tool in tool_registry.tools() {
            // Skip if already registered (e.g., shared meta tools)
            if registry.get(&tool.name).is_none() {
                registry.register(tool.clone()).map_err(|e| {
                    error!(target: "ghost_core_mcp", "Failed to register tool '{}': {}", tool.name, e);
                    e
                })?;
                registered += 1;
            } else {
                skipped += 1;
            }
        }
    }

    info!(
        target: "ghost_core_mcp",
        "Server ready: {} tools registered, {} skipped (already present)",
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

    // Warn if approaching limit
    if count > limit * 8 / 10 {
        warn!(
            target: "ghost_core_mcp",
            "Registry at {}% capacity: {}/{} tools",
            count * 100 / limit,
            count,
            limit
        );
    }

    info!(target: "ghost_core_mcp", "{}", registry.summary());

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
    fn test_registry_expected_count() {
        let registry = create_registry().unwrap();
        assert_eq!(
            registry.len(),
            EXPECTED_REGISTRY_COUNT,
            "Registry count mismatch"
        );
    }

    #[test]
    fn test_registry_has_core_meta() {
        let registry = create_registry().unwrap();
        assert!(registry.get("action_last").is_some());
        assert!(registry.get("action_verify").is_some());
        assert!(registry.get("agent_status").is_some());
        assert!(registry.get("agent_reconnect").is_some());
    }

    #[test]
    fn test_registry_categories() {
        let registry = create_registry().unwrap();
        let categories = registry.categories();
        assert!(categories.contains(&"memory"));
        assert!(categories.contains(&"module"));
        assert!(categories.contains(&"debug"));
        assert!(categories.contains(&"safety"));
    }

    #[tokio::test]
    async fn test_create_server() {
        let server = create_server().unwrap();
        assert_eq!(server.identity().name, "ghost-core-mcp");
        assert_eq!(server.identity().port, PORT);
    }
}
