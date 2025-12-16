//! Scanner tools for ghost-analysis-mcp
//!
//! 11 tools: scan_new, scan_first, scan_next, scan_results, scan_count,
//!           scan_progress, scan_cancel, scan_close, scan_list, scan_export, scan_import

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Scanner tools (11 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        scan_new(),
        scan_first(),
        scan_next(),
        scan_results(),
        scan_count(),
        scan_progress(),
        scan_cancel(),
        scan_close(),
        scan_list(),
        scan_export(),
        scan_import(),
    ])
}

fn scan_new() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session name (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "value_type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Value type to scan for".to_string()),
            default: Some(serde_json::json!("i32")),
            enum_values: Some(vec![
                serde_json::json!("i8"),
                serde_json::json!("i16"),
                serde_json::json!("i32"),
                serde_json::json!("i64"),
                serde_json::json!("f32"),
                serde_json::json!("f64"),
                serde_json::json!("string"),
                serde_json::json!("bytes"),
            ]),
        },
    );
    props.insert(
        "compare".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Comparison type".to_string()),
            default: Some(serde_json::json!("exact")),
            enum_values: Some(vec![
                serde_json::json!("exact"),
                serde_json::json!("greater"),
                serde_json::json!("less"),
                serde_json::json!("between"),
                serde_json::json!("unknown"),
            ]),
        },
    );

    ToolDefinition::new("scan_new", "Create a new memory scan session", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn scan_first() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "value".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Value to search for".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "compare".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Comparison type".to_string()),
            default: Some(serde_json::json!("exact")),
            enum_values: Some(vec![
                serde_json::json!("exact"),
                serde_json::json!("greater"),
                serde_json::json!("less"),
                serde_json::json!("between"),
                serde_json::json!("unknown"),
            ]),
        },
    );

    ToolDefinition::new("scan_first", "Perform initial scan", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string(), "value".to_string()],
            additional_properties: false,
        },
    )
}

fn scan_next() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "value".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("New value to filter by".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "compare".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Comparison type".to_string()),
            default: Some(serde_json::json!("exact")),
            enum_values: Some(vec![
                serde_json::json!("exact"),
                serde_json::json!("increased"),
                serde_json::json!("decreased"),
                serde_json::json!("changed"),
                serde_json::json!("unchanged"),
            ]),
        },
    );

    ToolDefinition::new(
        "scan_next",
        "Perform next scan to filter results",
        "scanner",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string()],
        additional_properties: false,
    })
}

fn scan_results() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "offset".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Result offset (default: 0)".to_string()),
            default: Some(serde_json::json!(0)),
            enum_values: None,
        },
    );
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum results (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
        },
    );

    ToolDefinition::new("scan_results", "Get scan results", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string()],
            additional_properties: false,
        },
    )
}

fn scan_count() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("scan_count", "Get number of results in scan", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string()],
            additional_properties: false,
        },
    )
}

fn scan_progress() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("scan_progress", "Get scan progress (0-100%)", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string()],
            additional_properties: false,
        },
    )
}

fn scan_cancel() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("scan_cancel", "Cancel an in-progress scan", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string()],
            additional_properties: false,
        },
    )
}

fn scan_close() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "scan_close",
        "Close a scan session and free resources",
        "scanner",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["scan_id".to_string()],
        additional_properties: false,
    })
}

fn scan_list() -> ToolDefinition {
    ToolDefinition::new("scan_list", "List all active scan sessions", "scanner")
        .with_schema(ToolInputSchema::empty())
}

fn scan_export() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scan_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Scan session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Path to export to".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("scan_export", "Export scan results to file", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scan_id".to_string(), "path".to_string()],
            additional_properties: false,
        },
    )
}

fn scan_import() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Path to import from".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("scan_import", "Import scan results from file", "scanner").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_scanner_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 11);
    }
}
