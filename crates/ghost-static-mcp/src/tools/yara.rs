//! YARA/Pattern tools for ghost-static-mcp
//!
//! 13 tools: yara_create_rule, yara_load_rules, yara_scan_memory, yara_list_rules,
//!           find_instructions, signature_db_create, signature_db_add, signature_db_list,
//!           signature_db_scan, signature_db_export, signature_db_import,
//!           signature_db_version, signature_auto_generate

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register YARA/Pattern tools (13 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        yara_create_rule(),
        yara_load_rules(),
        yara_scan_memory(),
        yara_list_rules(),
        find_instructions(),
        signature_db_create(),
        signature_db_add(),
        signature_db_list(),
        signature_db_scan(),
        signature_db_export(),
        signature_db_import(),
        signature_db_version(),
        signature_auto_generate(),
    ])
}

fn yara_create_rule() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Rule name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "rule".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("YARA rule content".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("yara_create_rule", "Create a YARA rule", "yara").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string(), "rule".to_string()],
            additional_properties: false,
        },
    )
}

fn yara_load_rules() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Path to YARA rules file or directory".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("yara_load_rules", "Load YARA rules from file", "yara").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

fn yara_scan_memory() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "rules".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Rule names to use (empty = all)".to_string()),
            default: Some(serde_json::json!([])),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Limit scan to specific module".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "yara_scan_memory",
        "Scan process memory with YARA rules",
        "yara",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn yara_list_rules() -> ToolDefinition {
    ToolDefinition::new("yara_list_rules", "List loaded YARA rules", "yara")
        .with_schema(ToolInputSchema::empty())
}

fn find_instructions() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pattern".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Instruction pattern (e.g., 'call *', 'mov *, [*]')".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module to search in".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "max_results".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum results (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "find_instructions",
        "Find instructions matching pattern",
        "yara",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["pattern".to_string()],
        additional_properties: false,
    })
}

fn signature_db_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Database name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "description".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Database description".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("signature_db_create", "Create a signature database", "yara").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string()],
            additional_properties: false,
        },
    )
}

fn signature_db_add() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "db".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Database name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Signature name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "pattern".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Byte pattern with wildcards".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("signature_db_add", "Add signature to database", "yara").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["db".to_string(), "name".to_string(), "pattern".to_string()],
            additional_properties: false,
        },
    )
}

fn signature_db_list() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "db".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Database name (optional, lists all DBs if omitted)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("signature_db_list", "List signatures in database", "yara").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn signature_db_scan() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "db".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Database name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module to scan (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "signature_db_scan",
        "Scan memory with signature database",
        "yara",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["db".to_string()],
        additional_properties: false,
    })
}

fn signature_db_export() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "db".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Database name".to_string()),
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

    ToolDefinition::new("signature_db_export", "Export signature database", "yara").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["db".to_string(), "path".to_string()],
            additional_properties: false,
        },
    )
}

fn signature_db_import() -> ToolDefinition {
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

    ToolDefinition::new("signature_db_import", "Import signature database", "yara").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

fn signature_db_version() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "db".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Database name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "signature_db_version",
        "Get signature database version",
        "yara",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["db".to_string()],
        additional_properties: false,
    })
}

fn signature_auto_generate() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to generate signature for".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Size of region (default: auto-detect function)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "signature_auto_generate",
        "Auto-generate signature from code",
        "yara",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_yara_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 13);
    }
}
