//! Shared Meta Tools
//!
//! Meta tools that must exist on every MCP server:
//! - mcp_capabilities: List tools organized by category
//! - mcp_documentation: Get detailed docs for a tool
//! - mcp_version: Get server version information
//! - mcp_health: Check health of all components

use crate::error::Result;
use crate::ipc::AgentClient;
use crate::registry::PropertySchema;
use crate::registry::{ToolDefinition, ToolInputSchema, ToolRegistry};
use crate::types::{HealthStatus, ServerCapabilities, ServerHealth, ToolResult};
use crate::VERSION;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Server identity for meta tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentity {
    /// Server name (e.g., "ghost-core-mcp")
    pub name: String,
    /// Server description
    pub description: String,
    /// Server port
    pub port: u16,
    /// Categories of tools provided
    pub categories: Vec<String>,
    /// Whether this server requires agent connection
    pub requires_agent: bool,
}

impl ServerIdentity {
    /// Create identity for ghost-core-mcp
    pub fn core() -> Self {
        Self {
            name: "ghost-core-mcp".to_string(),
            description: "Core runtime tools for live process interaction, debugging, and safety"
                .to_string(),
            port: 13340,
            categories: vec![
                "memory".to_string(),
                "module".to_string(),
                "debug".to_string(),
                "session".to_string(),
                "script".to_string(),
                "execution".to_string(),
                "safety".to_string(),
                "command".to_string(),
                "disasm".to_string(),
                "xref".to_string(),
                "meta".to_string(),
            ],
            requires_agent: true,
        }
    }

    /// Create identity for ghost-analysis-mcp
    pub fn analysis() -> Self {
        Self {
            name: "ghost-analysis-mcp".to_string(),
            description: "Analysis and scanning tools for memory analysis and structures"
                .to_string(),
            port: 13341,
            categories: vec![
                "scanner".to_string(),
                "pointer".to_string(),
                "watch".to_string(),
                "dump".to_string(),
                "structure".to_string(),
                "introspect".to_string(),
                "meta".to_string(),
            ],
            requires_agent: true,
        }
    }

    /// Create identity for ghost-static-mcp
    pub fn static_analysis() -> Self {
        Self {
            name: "ghost-static-mcp".to_string(),
            description: "Static analysis tools with RE backends and AI assistance".to_string(),
            port: 13342,
            categories: vec![
                "radare2".to_string(),
                "ida".to_string(),
                "ghidra".to_string(),
                "trace".to_string(),
                "ai".to_string(),
                "yara".to_string(),
                "meta".to_string(),
            ],
            requires_agent: false,
        }
    }

    /// Create identity for ghost-extended-mcp
    pub fn extended() -> Self {
        Self {
            name: "ghost-extended-mcp".to_string(),
            description:
                "Extended capabilities for injection, anti-debug, input automation, and more"
                    .to_string(),
            port: 13343,
            categories: vec![
                "injection".to_string(),
                "antidebug".to_string(),
                "input".to_string(),
                "addresslist".to_string(),
                "memory".to_string(),
                "speedhack".to_string(),
                "meta".to_string(),
            ],
            requires_agent: true,
        }
    }
}

/// Shared meta tools that are registered on every server
pub struct SharedMetaTools {
    identity: ServerIdentity,
}

impl SharedMetaTools {
    /// Create shared meta tools for a server
    pub fn new(identity: ServerIdentity) -> Self {
        Self { identity }
    }

    /// Get the four shared meta tool definitions
    pub fn tool_definitions(&self) -> Vec<ToolDefinition> {
        vec![
            self.mcp_capabilities_def(),
            self.mcp_documentation_def(),
            self.mcp_version_def(),
            self.mcp_health_def(),
        ]
    }

    /// Register shared meta tools into a registry
    pub fn register(&self, registry: &mut ToolRegistry) -> Result<()> {
        for tool in self.tool_definitions() {
            registry.register(tool)?;
        }
        Ok(())
    }

    fn mcp_capabilities_def(&self) -> ToolDefinition {
        let mut properties = HashMap::new();
        properties.insert(
            "category".to_string(),
            PropertySchema {
                prop_type: "string".to_string(),
                description: Some("Filter by category name".to_string()),
                default: None,
                enum_values: None,
            },
        );

        ToolDefinition::new(
            "mcp_capabilities",
            "List all available tools organized by category",
            "meta",
        )
        .with_schema(ToolInputSchema {
            schema_type: "object".to_string(),
            properties,
            required: vec![],
            additional_properties: false,
        })
    }

    fn mcp_documentation_def(&self) -> ToolDefinition {
        let mut properties = HashMap::new();
        properties.insert(
            "tool".to_string(),
            PropertySchema {
                prop_type: "string".to_string(),
                description: Some("Name of the tool to get documentation for".to_string()),
                default: None,
                enum_values: None,
            },
        );

        ToolDefinition::new(
            "mcp_documentation",
            "Get detailed documentation for a specific tool",
            "meta",
        )
        .with_schema(ToolInputSchema {
            schema_type: "object".to_string(),
            properties,
            required: vec!["tool".to_string()],
            additional_properties: false,
        })
    }

    fn mcp_version_def(&self) -> ToolDefinition {
        ToolDefinition::new(
            "mcp_version",
            "Get server version and capability information",
            "meta",
        )
        .with_schema(ToolInputSchema::empty())
    }

    fn mcp_health_def(&self) -> ToolDefinition {
        ToolDefinition::new(
            "mcp_health",
            "Check health status of server and all components",
            "meta",
        )
        .with_schema(ToolInputSchema::empty())
    }

    /// Handle mcp_capabilities
    pub fn handle_capabilities(
        &self,
        args: &serde_json::Value,
        registry: &ToolRegistry,
    ) -> Result<serde_json::Value> {
        let filter_category = args.get("category").and_then(|c| c.as_str());

        // Validate category if provided
        if let Some(cat) = filter_category {
            if !cat.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Ok(ToolResult::error(
                    "Invalid category format. Use alphanumeric characters only.",
                )
                .to_value());
            }
        }

        debug!(filter = ?filter_category, "Loading tool categories");

        // Build category map from registry
        let mut categories: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
        for tool in registry.tools() {
            categories
                .entry(tool.category.clone())
                .or_default()
                .push(serde_json::json!({
                    "name": tool.name,
                    "description": tool.description
                }));
        }

        let output = if let Some(cat) = filter_category {
            if let Some(tools) = categories.get(cat) {
                serde_json::json!({
                    "category": cat,
                    "tools": tools,
                    "count": tools.len()
                })
            } else {
                let valid_cats: Vec<_> = categories.keys().collect();
                return Ok(ToolResult::error(format!(
                    "Unknown category: {}. Valid categories: {:?}",
                    cat, valid_cats
                ))
                .to_value());
            }
        } else {
            let summary: HashMap<_, _> = categories
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        serde_json::json!({
                            "count": v.len(),
                            "tools": v
                        }),
                    )
                })
                .collect();
            serde_json::json!({
                "server": self.identity.name,
                "total_tools": registry.len(),
                "tool_count": registry.len(),
                "categories": summary
            })
        };

        Ok(ToolResult::json(&output)?.to_value())
    }

    /// Handle mcp_documentation
    pub fn handle_documentation(
        &self,
        args: &serde_json::Value,
        registry: &ToolRegistry,
    ) -> Result<serde_json::Value> {
        let tool_name = args.get("tool").and_then(|t| t.as_str()).ok_or_else(|| {
            crate::error::McpError::InvalidParams("Missing 'tool' parameter".to_string())
        })?;

        if tool_name.is_empty() {
            return Ok(ToolResult::error("Tool name cannot be empty").to_value());
        }

        if tool_name.len() > 64 {
            return Ok(
                ToolResult::error("Tool name exceeds maximum length of 64 characters").to_value(),
            );
        }

        match registry.get(tool_name) {
            Some(tool) => {
                let doc = if let Some(ref docs) = tool.documentation {
                    format!(
                        "# {}\n\n**Category:** {}\n\n## Description\n{}\n\n## Details\n{}\n\n## Examples\n{}\n\n## Related Tools\n{}",
                        docs.name,
                        docs.category,
                        docs.description,
                        docs.help,
                        docs.examples.iter().map(|e| format!(
                            "- **{}**\n  ```json\n  {}\n  ```\n  Expected: {}",
                            e.description,
                            serde_json::to_string_pretty(&e.arguments).unwrap_or_default(),
                            e.expected
                        )).collect::<Vec<_>>().join("\n"),
                        docs.related.join(", ")
                    )
                } else {
                    format!(
                        "# {}\n\n**Category:** {}\n\n## Description\n{}\n\n## Input Schema\n```json\n{}\n```",
                        tool.name,
                        tool.category,
                        tool.description,
                        serde_json::to_string_pretty(&tool.input_schema).unwrap_or_default()
                    )
                };
                Ok(ToolResult::text(doc).to_value())
            }
            None => Ok(ToolResult::error(format!(
                "No documentation found for tool: {}",
                tool_name
            ))
            .to_value()),
        }
    }

    /// Handle mcp_version
    pub fn handle_version(&self, registry: &ToolRegistry) -> Result<serde_json::Value> {
        let capabilities = ServerCapabilities {
            name: self.identity.name.clone(),
            version: VERSION.to_string(),
            description: self.identity.description.clone(),
            port: self.identity.port,
            tool_count: registry.len(),
            categories: self.identity.categories.clone(),
            requires_agent: self.identity.requires_agent,
        };

        Ok(ToolResult::json(&capabilities)?.to_value())
    }

    /// Handle mcp_health
    pub async fn handle_health(
        &self,
        agent: Option<&Arc<AgentClient>>,
        registry: &ToolRegistry,
    ) -> Result<serde_json::Value> {
        let check_start = Instant::now();
        let mut components = Vec::new();
        let mut diagnostics = Vec::new();
        let mut all_healthy = true;

        // Check agent connection
        let agent_connected = agent.map(|a| a.is_connected()).unwrap_or(false);
        let agent_status = if let Some(a) = agent {
            a.status().await
        } else {
            None
        };

        if self.identity.requires_agent && !agent_connected {
            all_healthy = false;
            diagnostics.push(
                "Agent not connected - run agent_reconnect or inject into target".to_string(),
            );
        }

        components.push(HealthStatus {
            name: "agent".to_string(),
            ok: agent_connected || !self.identity.requires_agent,
            message: if agent_connected {
                format!(
                    "Connected to {} (PID {})",
                    agent_status
                        .as_ref()
                        .map(|s| s.process_name.as_str())
                        .unwrap_or("unknown"),
                    agent_status.as_ref().map(|s| s.pid).unwrap_or(0)
                )
            } else if self.identity.requires_agent {
                "Not connected".to_string()
            } else {
                "Not required".to_string()
            },
            details: agent_status.and_then(|s| serde_json::to_value(s).ok()),
        });

        // Check tool registry
        components.push(HealthStatus {
            name: "registry".to_string(),
            ok: !registry.is_empty(),
            message: format!("{} tools registered", registry.len()),
            details: None,
        });

        let checked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let health = ServerHealth {
            healthy: all_healthy,
            checked_at,
            check_duration_ms: check_start.elapsed().as_millis() as u64,
            components,
            diagnostics,
        };

        Ok(ToolResult::json(&health)?.to_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_identity_core() {
        let identity = ServerIdentity::core();
        assert_eq!(identity.name, "ghost-core-mcp");
        assert_eq!(identity.port, 13340);
        assert!(identity.requires_agent);
    }

    #[test]
    fn test_server_identity_static() {
        let identity = ServerIdentity::static_analysis();
        assert_eq!(identity.name, "ghost-static-mcp");
        assert_eq!(identity.port, 13342);
        assert!(!identity.requires_agent);
    }

    #[test]
    fn test_shared_meta_tools_count() {
        let meta = SharedMetaTools::new(ServerIdentity::core());
        let tools = meta.tool_definitions();
        assert_eq!(tools.len(), 4);
    }

    #[test]
    fn test_shared_meta_tools_register() {
        let meta = SharedMetaTools::new(ServerIdentity::core());
        let mut registry = ToolRegistry::new();
        meta.register(&mut registry).unwrap();
        assert_eq!(registry.len(), 4);
        assert!(registry.get("mcp_capabilities").is_some());
        assert!(registry.get("mcp_documentation").is_some());
        assert!(registry.get("mcp_version").is_some());
        assert!(registry.get("mcp_health").is_some());
    }

    #[test]
    fn test_handle_capabilities() {
        let meta = SharedMetaTools::new(ServerIdentity::core());
        let mut registry = ToolRegistry::new();
        meta.register(&mut registry).unwrap();

        let result = meta
            .handle_capabilities(&serde_json::json!({}), &registry)
            .unwrap();
        assert!(result.get("content").is_some());
    }

    #[test]
    fn test_handle_version() {
        let meta = SharedMetaTools::new(ServerIdentity::core());
        let mut registry = ToolRegistry::new();
        meta.register(&mut registry).unwrap();

        let result = meta.handle_version(&registry).unwrap();
        assert!(result.get("content").is_some());
    }
}
