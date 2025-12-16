//! Memory tools for ghost-core-mcp
//!
//! 5 tools: memory_read, memory_write, memory_search, memory_search_pattern, memory_regions

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Memory tools (5 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        memory_read(),
        memory_write(),
        memory_search(),
        memory_search_pattern(),
        memory_regions(),
    ])
}

fn memory_read() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some(
                "Memory address to read from (hex string, e.g., '0x7FF6A0000000')".to_string(),
            ),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Number of bytes to read (default: 256, max: 16MB)".to_string()),
            default: Some(serde_json::json!(256)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "format".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Output format".to_string()),
            default: Some(serde_json::json!("hex")),
            enum_values: Some(vec![
                serde_json::json!("hex"),
                serde_json::json!("bytes"),
                serde_json::json!("string"),
            ]),
            items: None,
        },
    );

    ToolDefinition::new(
        "memory_read",
        "Read bytes from target process memory",
        "memory",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn memory_write() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Memory address to write to (hex string)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "data".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Data to write (hex string, e.g., '90 90 90' for NOPs)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "safety_token".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some(
                "Safety token for write authorization (required in standard/expert mode)"
                    .to_string(),
            ),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "memory_write",
        "Write bytes to target process memory (requires write capability and safety token)",
        "memory",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string(), "data".to_string()],
        additional_properties: false,
    })
}

fn memory_search() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "value".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Value to search for".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "value_type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Type of value".to_string()),
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
            items: None,
        },
    );
    props.insert(
        "start_address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Start address for search range (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "end_address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("End address for search range (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "memory_search",
        "Search for a value in target process memory",
        "memory",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["value".to_string()],
        additional_properties: false,
    })
}

fn memory_search_pattern() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pattern".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Byte pattern with wildcards (e.g., '48 8B ?? ?? 00')".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Limit search to specific module (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "memory_search_pattern",
        "Search for a byte pattern with wildcards in memory",
        "memory",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["pattern".to_string()],
        additional_properties: false,
    })
}

fn memory_regions() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by protection (e.g., 'rwx', 'r-x')".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "include_mapped".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Include memory-mapped files".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "memory_regions",
        "List memory regions in target process with protection info",
        "memory",
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
    fn test_register_memory_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 5);
        assert!(registry.get("memory_read").is_some());
        assert!(registry.get("memory_write").is_some());
        assert!(registry.get("memory_search").is_some());
        assert!(registry.get("memory_search_pattern").is_some());
        assert!(registry.get("memory_regions").is_some());
    }
}
