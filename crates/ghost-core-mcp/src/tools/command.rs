//! Command/Event tools for ghost-core-mcp
//!
//! 7 tools: command_batch, command_history, command_replay,
//!          event_subscribe, event_unsubscribe, event_poll, event_list

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Command/Event tools (7 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        command_batch(),
        command_history(),
        command_replay(),
        event_subscribe(),
        event_unsubscribe(),
        event_poll(),
        event_list(),
    ])
}

fn command_batch() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "commands".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Array of commands to execute in sequence".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "stop_on_error".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Stop batch execution on first error (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "command_batch",
        "Execute multiple commands in a batch",
        "command",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["commands".to_string()],
        additional_properties: false,
    })
}

fn command_history() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum entries to return (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by command name pattern (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "command_history",
        "View command execution history",
        "command",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn command_replay() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "history_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("History entry ID to replay".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("command_replay", "Replay a command from history", "command").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["history_id".to_string()],
            additional_properties: false,
        },
    )
}

fn event_subscribe() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "event_types".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Event types to subscribe to".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "event_subscribe",
        "Subscribe to agent events (MemoryWrite, PatchApplied, etc.)",
        "command",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["event_types".to_string()],
        additional_properties: false,
    })
}

fn event_unsubscribe() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "event_types".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Event types to unsubscribe from (empty = all)".to_string()),
            default: Some(serde_json::json!([])),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "event_unsubscribe",
        "Unsubscribe from agent events",
        "command",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn event_poll() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "timeout_ms".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Timeout in milliseconds (default: 1000)".to_string()),
            default: Some(serde_json::json!(1000)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "max_events".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum events to return (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("event_poll", "Poll for subscribed events", "command").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn event_list() -> ToolDefinition {
    ToolDefinition::new("event_list", "List all available event types", "command")
        .with_schema(ToolInputSchema::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_command_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 7);
    }
}
