//! Dump tools for ghost-analysis-mcp
//!
//! 13 tools: dump_create, dump_region, dump_module, dump_minidump,
//!           dump_list, dump_info, dump_compare, dump_search,
//!           dump_annotate, dump_incremental, dump_delete, pe_reconstruct, pe_validate

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Dump tools (13 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        dump_create(),
        dump_region(),
        dump_module(),
        dump_minidump(),
        dump_list(),
        dump_info(),
        dump_compare(),
        dump_search(),
        dump_annotate(),
        dump_incremental(),
        dump_delete(),
        pe_reconstruct(),
        pe_validate(),
    ])
}

fn dump_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Dump name (optional, auto-generated)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Dump type".to_string()),
            default: Some(serde_json::json!("full")),
            enum_values: Some(vec![
                serde_json::json!("full"),
                serde_json::json!("heap"),
                serde_json::json!("stack"),
            ]),
        },
    );

    ToolDefinition::new("dump_create", "Create a full memory dump", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn dump_region() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Start address".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Size in bytes".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Output file path (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("dump_region", "Dump a specific memory region", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string(), "size".to_string()],
            additional_properties: false,
        },
    )
}

fn dump_module() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module name to dump".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Output file path (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("dump_module", "Dump a module from memory", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["module".to_string()],
            additional_properties: false,
        },
    )
}

fn dump_minidump() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Output file path".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Minidump type".to_string()),
            default: Some(serde_json::json!("normal")),
            enum_values: Some(vec![
                serde_json::json!("normal"),
                serde_json::json!("with_data"),
                serde_json::json!("full"),
            ]),
        },
    );

    ToolDefinition::new("dump_minidump", "Create a Windows minidump file", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

fn dump_list() -> ToolDefinition {
    ToolDefinition::new("dump_list", "List all saved dumps", "dump")
        .with_schema(ToolInputSchema::empty())
}

fn dump_info() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "dump_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Dump ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("dump_info", "Get information about a dump", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["dump_id".to_string()],
            additional_properties: false,
        },
    )
}

fn dump_compare() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "dump_id1".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("First dump ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "dump_id2".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Second dump ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("dump_compare", "Compare two dumps for differences", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["dump_id1".to_string(), "dump_id2".to_string()],
            additional_properties: false,
        },
    )
}

fn dump_search() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "dump_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Dump ID to search".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "pattern".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pattern to search for".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("dump_search", "Search within a dump", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["dump_id".to_string(), "pattern".to_string()],
            additional_properties: false,
        },
    )
}

fn dump_annotate() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "dump_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Dump ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to annotate".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "note".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Annotation text".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("dump_annotate", "Add annotation to dump location", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![
                "dump_id".to_string(),
                "address".to_string(),
                "note".to_string(),
            ],
            additional_properties: false,
        },
    )
}

fn dump_incremental() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "base_dump_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Base dump ID to compare against".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "dump_incremental",
        "Create incremental dump (only changes)",
        "dump",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["base_dump_id".to_string()],
        additional_properties: false,
    })
}

fn dump_delete() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "dump_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Dump ID to delete".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("dump_delete", "Delete a saved dump", "dump").with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["dump_id".to_string()],
        additional_properties: false,
    })
}

fn pe_reconstruct() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module to reconstruct".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "output".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Output file path".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "fix_iat".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Attempt to fix IAT (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
        },
    );

    ToolDefinition::new("pe_reconstruct", "Reconstruct PE file from memory", "dump").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["module".to_string(), "output".to_string()],
            additional_properties: false,
        },
    )
}

fn pe_validate() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("PE file path to validate".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("pe_validate", "Validate a PE file structure", "dump").with_schema(
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
    fn test_register_dump_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 13);
    }
}
