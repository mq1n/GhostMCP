//! Ghidra tools for ghost-static-mcp
//!
//! 11 tools (consolidated): ghidra_session, ghidra_status, ghidra_info, ghidra_functions,
//!           ghidra_function, ghidra_disasm, ghidra_decompile, ghidra_strings,
//!           ghidra_imports, ghidra_exports, ghidra_xref

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Ghidra tools (11 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        ghidra_session(),
        ghidra_status(),
        ghidra_info(),
        ghidra_functions(),
        ghidra_function(),
        ghidra_disasm(),
        ghidra_decompile(),
        ghidra_strings(),
        ghidra_imports(),
        ghidra_exports(),
        ghidra_xref(),
    ])
}

fn ghidra_session() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "action".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Session action".to_string()),
            default: None,
            enum_values: Some(vec![serde_json::json!("open"), serde_json::json!("close")]),
        },
    );
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Binary or Ghidra project path".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("ghidra_session", "Open or close Ghidra session", "ghidra").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["action".to_string()],
            additional_properties: false,
        },
    )
}

fn ghidra_status() -> ToolDefinition {
    ToolDefinition::new("ghidra_status", "Get Ghidra session status", "ghidra")
        .with_schema(ToolInputSchema::empty())
}

fn ghidra_info() -> ToolDefinition {
    ToolDefinition::new("ghidra_info", "Get binary info from Ghidra", "ghidra")
        .with_schema(ToolInputSchema::empty())
}

fn ghidra_functions() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by function name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "ghidra_functions",
        "List all functions from Ghidra",
        "ghidra",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn ghidra_function() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function address".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "ghidra_function",
        "Get function details from Ghidra",
        "ghidra",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn ghidra_disasm() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to disassemble".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "count".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Number of instructions".to_string()),
            default: Some(serde_json::json!(20)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "ghidra_disasm",
        "Disassemble at address using Ghidra",
        "ghidra",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn ghidra_decompile() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function address to decompile".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "ghidra_decompile",
        "Decompile function using Ghidra",
        "ghidra",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn ghidra_strings() -> ToolDefinition {
    ToolDefinition::new("ghidra_strings", "List strings from Ghidra", "ghidra")
        .with_schema(ToolInputSchema::empty())
}

fn ghidra_imports() -> ToolDefinition {
    ToolDefinition::new("ghidra_imports", "List imports from Ghidra", "ghidra")
        .with_schema(ToolInputSchema::empty())
}

fn ghidra_exports() -> ToolDefinition {
    ToolDefinition::new("ghidra_exports", "List exports from Ghidra", "ghidra")
        .with_schema(ToolInputSchema::empty())
}

fn ghidra_xref() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to get xrefs for".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "direction".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Xref direction".to_string()),
            default: Some(serde_json::json!("to")),
            enum_values: Some(vec![serde_json::json!("to"), serde_json::json!("from")]),
        },
    );

    ToolDefinition::new("ghidra_xref", "Get cross-references from Ghidra", "ghidra").with_schema(
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
    fn test_register_ghidra_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 11);
    }
}
