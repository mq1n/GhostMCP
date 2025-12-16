//! Structure tools for ghost-analysis-mcp
//!
//! 11 tools: struct_create, struct_list, struct_get, struct_delete,
//!           struct_read, struct_edit_field, struct_export,
//!           struct_auto_analyze, struct_save, struct_load, enum_create

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Structure tools (11 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        struct_create(),
        struct_list(),
        struct_get(),
        struct_delete(),
        struct_read(),
        struct_edit_field(),
        struct_export(),
        struct_auto_analyze(),
        struct_save(),
        struct_load(),
        enum_create(),
    ])
}

fn struct_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Structure name".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "fields".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some(
                "Array of field definitions [{name, type, offset, size}]".to_string(),
            ),
            default: Some(serde_json::json!([])),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "struct_create",
        "Create a new structure definition",
        "structure",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn struct_list() -> ToolDefinition {
    ToolDefinition::new("struct_list", "List all defined structures", "structure")
        .with_schema(ToolInputSchema::empty())
}

fn struct_get() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Structure name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("struct_get", "Get structure definition", "structure").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string()],
            additional_properties: false,
        },
    )
}

fn struct_delete() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Structure name to delete".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "struct_delete",
        "Delete a structure definition",
        "structure",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn struct_read() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Structure name".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to read structure from".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("struct_read", "Read memory as a structure", "structure").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string(), "address".to_string()],
            additional_properties: false,
        },
    )
}

fn struct_edit_field() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Structure name".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "field".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Field name to edit".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "new_type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("New field type (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "new_name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("New field name (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "struct_edit_field",
        "Edit a field in a structure",
        "structure",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string(), "field".to_string()],
        additional_properties: false,
    })
}

fn struct_export() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Structure name (optional, exports all)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "format".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Export format".to_string()),
            default: Some(serde_json::json!("c")),
            enum_values: Some(vec![
                serde_json::json!("c"),
                serde_json::json!("rust"),
                serde_json::json!("json"),
            ]),
        },
    );

    ToolDefinition::new(
        "struct_export",
        "Export structure as C/Rust/JSON",
        "structure",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn struct_auto_analyze() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to analyze".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Size to analyze".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "struct_auto_analyze",
        "Auto-detect structure from memory",
        "structure",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string(), "size".to_string()],
        additional_properties: false,
    })
}

fn struct_save() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("File path to save to".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("struct_save", "Save all structures to file", "structure").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

fn struct_load() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("File path to load from".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("struct_load", "Load structures from file", "structure").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

fn enum_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Enum name".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "values".to_string(),
        PropertySchema {
            prop_type: "object".to_string(),
            description: Some("Enum values as {name: value} pairs".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("enum_create", "Create an enum type definition", "structure").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string(), "values".to_string()],
            additional_properties: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_structure_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 11);
    }
}
