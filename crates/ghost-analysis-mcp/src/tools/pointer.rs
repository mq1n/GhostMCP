//! Pointer Scanner tools for ghost-analysis-mcp
//!
//! 13 tools: pointer_scan_create, pointer_scan_start, pointer_scan_rescan,
//!           pointer_scan_results, pointer_scan_count, pointer_scan_progress,
//!           pointer_scan_cancel, pointer_scan_close, pointer_scan_list, pointer_resolve,
//!           pointer_scan_compare, pointer_scan_export, pointer_scan_import

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Pointer Scanner tools (13 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        pointer_scan_create(),
        pointer_scan_start(),
        pointer_scan_rescan(),
        pointer_scan_results(),
        pointer_scan_count(),
        pointer_scan_progress(),
        pointer_scan_cancel(),
        pointer_scan_close(),
        pointer_scan_list(),
        pointer_resolve(),
        pointer_scan_compare(),
        pointer_scan_export(),
        pointer_scan_import(),
    ])
}

fn pointer_scan_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Target address to find pointers to".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "max_offset".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum offset per level (default: 4096)".to_string()),
            default: Some(serde_json::json!(4096)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "max_level".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum pointer chain depth (default: 5)".to_string()),
            default: Some(serde_json::json!(5)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_create",
        "Create a pointer scan session",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_start() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("pointer_scan_start", "Start pointer scan", "pointer").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string()],
            additional_properties: false,
        },
    )
}

fn pointer_scan_rescan() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "new_address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("New address to filter pointer paths".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "filter_invalid".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Remove invalid paths (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "update_scores".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Update stability scores (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_rescan",
        "Rescan with new target address",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string(), "new_address".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_results() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum results (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_results",
        "Get pointer scan results",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_count() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_count",
        "Get number of pointer paths found",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_progress() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_progress",
        "Get pointer scan progress",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_cancel() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("pointer_scan_cancel", "Cancel pointer scan", "pointer").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string()],
            additional_properties: false,
        },
    )
}

fn pointer_scan_close() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_close",
        "Close pointer scan session",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_list() -> ToolDefinition {
    ToolDefinition::new(
        "pointer_scan_list",
        "List all pointer scan sessions",
        "pointer",
    )
    .with_schema(ToolInputSchema::empty())
}

fn pointer_resolve() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "base".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Base address or module name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "offsets".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Array of offsets in the pointer chain".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_resolve",
        "Resolve a pointer path to current address",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["base".to_string(), "offsets".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_compare() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id1".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("First pointer scan ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "scan_id2".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Second pointer scan ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_compare",
        "Compare two pointer scans",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id1".to_string(), "scan_id2".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_export() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pointer scan session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Export file path".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_export",
        "Export pointer scan results",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string(), "path".to_string()],
        additional_properties: false,
    })
}

fn pointer_scan_import() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Import file path".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "pointer_scan_import",
        "Import pointer scan results",
        "pointer",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["path".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_pointer_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 13);
    }
}
