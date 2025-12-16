//! Core-only meta tools for ghost-core-mcp
//!
//! 4 tools: action_last, action_verify, agent_status, agent_reconnect
//! (The 4 shared meta tools are registered by McpServer automatically)

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Core-only meta tools (4 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        action_last(),
        action_verify(),
        agent_status(),
        agent_reconnect(),
    ])
}

fn action_last() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "count".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Number of recent actions to retrieve (default: 10)".to_string()),
            default: Some(serde_json::json!(10)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "action_last",
        "Get the last N actions performed (for debugging/verification)",
        "meta",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn action_verify() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "expect_success".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Expected success state (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "expect_tool".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Expected tool name (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "contains".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Substring that should appear in the result".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "action_verify",
        "Verify that an action completed successfully",
        "meta",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn agent_status() -> ToolDefinition {
    ToolDefinition::new(
        "agent_status",
        "Get detailed agent status (connection health, client count, capabilities)",
        "meta",
    )
    .with_schema(ToolInputSchema::empty())
}

fn agent_reconnect() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "force".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Force reconnect even if already connected".to_string()),
            default: Some(serde_json::json!(false)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "agent_reconnect",
        "Force reconnection to the agent (requires admin capability)",
        "meta",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_meta_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 4);
    }
}
