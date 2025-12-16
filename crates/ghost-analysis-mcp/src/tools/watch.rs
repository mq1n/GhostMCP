//! Watch tools for ghost-analysis-mcp
//!
//! 10 tools: watch_address_create, watch_instruction_create, watch_list,
//!           watch_hits_get, watch_accessed_get, watch_pause, watch_resume,
//!           watch_remove, watch_clear_hits, watch_quick_action

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Watch tools (10 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        watch_address_create(),
        watch_instruction_create(),
        watch_list(),
        watch_hits_get(),
        watch_accessed_get(),
        watch_pause(),
        watch_resume(),
        watch_remove(),
        watch_clear_hits(),
        watch_quick_action(),
    ])
}

fn watch_address_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to watch".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Size of memory region to watch".to_string()),
            default: Some(serde_json::json!(4)),
            enum_values: None,
        },
    );
    props.insert(
        "type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Watch type".to_string()),
            default: Some(serde_json::json!("write")),
            enum_values: Some(vec![
                serde_json::json!("read"),
                serde_json::json!("write"),
                serde_json::json!("access"),
            ]),
        },
    );

    ToolDefinition::new(
        "watch_address_create",
        "Create a memory address watchpoint",
        "watch",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn watch_instruction_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Instruction address to watch".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "count".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Number of instructions to watch (default: 1)".to_string()),
            default: Some(serde_json::json!(1)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "watch_instruction_create",
        "Create an instruction execution watchpoint",
        "watch",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn watch_list() -> ToolDefinition {
    ToolDefinition::new("watch_list", "List all active watchpoints", "watch")
        .with_schema(ToolInputSchema::empty())
}

fn watch_hits_get() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "watch_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Watchpoint ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum hits to return (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "watch_hits_get",
        "Get hit records for a watchpoint",
        "watch",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["watch_id".to_string()],
        additional_properties: false,
    })
}

fn watch_accessed_get() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "watch_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Watchpoint ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "watch_accessed_get",
        "Get addresses that accessed a watchpoint",
        "watch",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["watch_id".to_string()],
        additional_properties: false,
    })
}

fn watch_pause() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "watch_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Watchpoint ID (omit to pause all)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("watch_pause", "Pause a watchpoint", "watch").with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn watch_resume() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "watch_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Watchpoint ID (omit to resume all)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("watch_resume", "Resume a paused watchpoint", "watch").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn watch_remove() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "watch_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Watchpoint ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("watch_remove", "Remove a watchpoint", "watch").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["watch_id".to_string()],
            additional_properties: false,
        },
    )
}

fn watch_clear_hits() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "watch_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Watchpoint ID (omit to clear all)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "watch_clear_hits",
        "Clear hit records for a watchpoint",
        "watch",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn watch_quick_action() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to find what accesses/writes".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "action".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Quick action type".to_string()),
            default: None,
            enum_values: Some(vec![
                serde_json::json!("find_what_writes"),
                serde_json::json!("find_what_reads"),
                serde_json::json!("find_what_accesses"),
            ]),
        },
    );

    ToolDefinition::new(
        "watch_quick_action",
        "Quick action to find what accesses an address",
        "watch",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string(), "action".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_watch_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 10);
    }
}
