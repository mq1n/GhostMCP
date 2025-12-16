//! IDA Pro tools for ghost-static-mcp
//!
//! 11 tools (consolidated): ida_session, ida_status, ida_info, ida_functions, ida_function,
//!           ida_disasm, ida_decompile, ida_strings, ida_imports, ida_exports, ida_xref

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register IDA Pro tools (11 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        ida_session(),
        ida_status(),
        ida_info(),
        ida_functions(),
        ida_function(),
        ida_disasm(),
        ida_decompile(),
        ida_strings(),
        ida_imports(),
        ida_exports(),
        ida_xref(),
    ])
}

fn ida_session() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "action".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Session action".to_string()),
            default: None,
            enum_values: Some(vec![serde_json::json!("open"), serde_json::json!("close")]),
            items: None,
        },
    );
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Binary or IDB path (required for open)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_session", "Open or close IDA Pro session", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["action".to_string()],
            additional_properties: false,
        },
    )
}

fn ida_status() -> ToolDefinition {
    ToolDefinition::new("ida_status", "Get IDA Pro session status", "ida")
        .with_schema(ToolInputSchema::empty())
}

fn ida_info() -> ToolDefinition {
    ToolDefinition::new("ida_info", "Get binary info from IDA", "ida")
        .with_schema(ToolInputSchema::empty())
}

fn ida_functions() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by function name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum number of functions to return (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_functions", "List all functions from IDA", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn ida_function() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function address".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_function", "Get function details from IDA", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![], // One of address or name required (validated in handler)
            additional_properties: false,
        },
    )
}

fn ida_disasm() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to disassemble".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "count".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Number of instructions".to_string()),
            default: Some(serde_json::json!(20)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_disasm", "Disassemble at address using IDA", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string()],
            additional_properties: false,
        },
    )
}

fn ida_decompile() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function address to decompile".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_decompile", "Decompile function using Hex-Rays", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string()],
            additional_properties: false,
        },
    )
}

fn ida_strings() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "min_length".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Minimum string length (default: 4)".to_string()),
            default: Some(serde_json::json!(4)),
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by string content".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum number of strings to return (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_strings", "List strings from IDA", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn ida_imports() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by import name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_imports", "List imports from IDA", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn ida_exports() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by export name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ida_exports", "List exports from IDA", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn ida_xref() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to get xrefs for".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "direction".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Xref direction".to_string()),
            default: Some(serde_json::json!("to")),
            enum_values: Some(vec![serde_json::json!("to"), serde_json::json!("from")]),
            items: None,
        },
    );

    ToolDefinition::new("ida_xref", "Get cross-references from IDA", "ida").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string()],
            additional_properties: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_ida_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 11);
    }
}
