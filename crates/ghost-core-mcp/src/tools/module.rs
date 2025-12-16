//! Module tools for ghost-core-mcp
//!
//! 5 tools: module_list, module_exports, module_imports, string_list, symbol_resolve

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Module tools (5 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        module_list(),
        module_exports(),
        module_imports(),
        string_list(),
        symbol_resolve(),
    ])
}

fn module_list() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter modules by name pattern (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "module_list",
        "List all loaded modules in target process",
        "module",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn module_exports() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module name (e.g., 'kernel32.dll')".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter exports by name pattern (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "module_exports",
        "List exported functions from a module",
        "module",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["module".to_string()],
        additional_properties: false,
    })
}

fn module_imports() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module name (e.g., 'target.exe')".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter imports by name pattern (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "module_imports",
        "List imported functions for a module",
        "module",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["module".to_string()],
        additional_properties: false,
    })
}

fn string_list() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some(
                "Module name to scan for strings (optional, defaults to main module)".to_string(),
            ),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "min_length".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Minimum string length (default: 4)".to_string()),
            default: Some(serde_json::json!(4)),
            enum_values: None,
        },
    );
    props.insert(
        "encoding".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("String encoding".to_string()),
            default: Some(serde_json::json!("utf8")),
            enum_values: Some(vec![
                serde_json::json!("utf8"),
                serde_json::json!("utf16"),
                serde_json::json!("ascii"),
            ]),
        },
    );

    ToolDefinition::new(
        "string_list",
        "Extract strings from a module's memory",
        "module",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn symbol_resolve() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to resolve (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Symbol name to resolve (e.g., 'kernel32!CreateFileW')".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "symbol_resolve",
        "Resolve address to symbol name or symbol name to address",
        "module",
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
    fn test_register_module_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 5);
    }
}
