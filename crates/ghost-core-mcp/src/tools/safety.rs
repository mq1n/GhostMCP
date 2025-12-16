//! Safety tools for ghost-core-mcp
//!
//! 10 tools: safety_status, safety_set_mode, safety_approve, safety_pending,
//!           safety_config, safety_backup, safety_reset,
//!           patch_history, patch_undo, patch_preview

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Safety tools (10 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        safety_status(),
        safety_set_mode(),
        safety_approve(),
        safety_pending(),
        safety_config(),
        safety_backup(),
        safety_reset(),
        patch_history(),
        patch_undo(),
        patch_preview(),
    ])
}

fn safety_status() -> ToolDefinition {
    ToolDefinition::new(
        "safety_status",
        "Get current safety mode and statistics",
        "safety",
    )
    .with_schema(ToolInputSchema::empty())
}

fn safety_set_mode() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "mode".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Safety mode to set".to_string()),
            default: None,
            enum_values: Some(vec![
                serde_json::json!("educational"),
                serde_json::json!("standard"),
                serde_json::json!("expert"),
            ]),
            items: None,
        },
    );

    ToolDefinition::new(
        "safety_set_mode",
        "Set safety mode (requires admin capability)",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["mode".to_string()],
        additional_properties: false,
    })
}

fn safety_approve() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "request_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Request ID to approve".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "safety_approve",
        "Approve a pending safety request",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["request_id".to_string()],
        additional_properties: false,
    })
}

fn safety_pending() -> ToolDefinition {
    ToolDefinition::new(
        "safety_pending",
        "List pending safety approval requests",
        "safety",
    )
    .with_schema(ToolInputSchema::empty())
}

fn safety_config() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "key".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Config key to get or set".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "value".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Value to set (omit to get current value)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "safety_config",
        "Get or set safety configuration values",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn safety_backup() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some(
                "Backup name (optional, auto-generated if not specified)".to_string(),
            ),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "include_memory".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Include full memory snapshot (large!)".to_string()),
            default: Some(serde_json::json!(false)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "safety_backup",
        "Create a backup/snapshot of current state",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn safety_reset() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "backup_name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Backup to restore from (optional, uses latest)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "safety_reset",
        "Reset to a previous backup state (requires admin capability)",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn patch_history() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum entries to return (default: 50)".to_string()),
            default: Some(serde_json::json!(50)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "client_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by client ID (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "patch_history",
        "View history of memory patches with full audit trail",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn patch_undo() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "patch_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Specific patch ID to undo".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "count".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some(
                "Number of recent patches to undo (alternative to patch_id)".to_string(),
            ),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "patch_undo",
        "Undo memory patches (requires write capability)",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn patch_preview() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to preview patch at".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "data".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Data to write (hex string)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "patch_preview",
        "Preview a patch without applying it (shows before/after)",
        "safety",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string(), "data".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_safety_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 10);
    }
}
