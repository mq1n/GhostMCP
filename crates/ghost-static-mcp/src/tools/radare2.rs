//! Radare2 tools for ghost-static-mcp
//!
//! 14 tools (consolidated): r2_session, r2_status, r2_info, r2_functions, r2_function,
//!           r2_disasm, r2_disasm_function, r2_decompile, r2_strings,
//!           r2_imports, r2_exports, r2_xref, r2_read, r2_cmd

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Radare2 tools (14 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        r2_session(),
        r2_status(),
        r2_info(),
        r2_functions(),
        r2_function(),
        r2_disasm(),
        r2_disasm_function(),
        r2_decompile(),
        r2_strings(),
        r2_imports(),
        r2_exports(),
        r2_xref(),
        r2_read(),
        r2_cmd(),
    ])
}

fn r2_session() -> ToolDefinition {
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
            description: Some("Binary file path (required for open)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("r2_session", "Open or close Radare2 session", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["action".to_string()],
            additional_properties: false,
        },
    )
}

fn r2_status() -> ToolDefinition {
    ToolDefinition::new("r2_status", "Get Radare2 session status", "radare2")
        .with_schema(ToolInputSchema::empty())
}

fn r2_info() -> ToolDefinition {
    ToolDefinition::new(
        "r2_info",
        "Get binary info (architecture, format, etc.)",
        "radare2",
    )
    .with_schema(ToolInputSchema::empty())
}

fn r2_functions() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by function name pattern".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("r2_functions", "List all functions", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn r2_function() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function name".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function address (alternative to name)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("r2_function", "Get function details", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn r2_disasm() -> ToolDefinition {
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
            description: Some("Number of instructions (default: 20)".to_string()),
            default: Some(serde_json::json!(20)),
            enum_values: None,
        },
    );

    ToolDefinition::new("r2_disasm", "Disassemble at address", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string()],
            additional_properties: false,
        },
    )
}

fn r2_disasm_function() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "r2_disasm_function",
        "Disassemble entire function",
        "radare2",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn r2_decompile() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "r2_decompile",
        "Decompile function to pseudo-C (using r2ghidra)",
        "radare2",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn r2_strings() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "min_length".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Minimum string length (default: 4)".to_string()),
            default: Some(serde_json::json!(4)),
            enum_values: None,
        },
    );

    ToolDefinition::new("r2_strings", "List strings in binary", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn r2_imports() -> ToolDefinition {
    ToolDefinition::new("r2_imports", "List imported functions", "radare2")
        .with_schema(ToolInputSchema::empty())
}

fn r2_exports() -> ToolDefinition {
    ToolDefinition::new("r2_exports", "List exported functions", "radare2")
        .with_schema(ToolInputSchema::empty())
}

fn r2_xref() -> ToolDefinition {
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

    ToolDefinition::new("r2_xref", "Get cross-references to/from address", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string()],
            additional_properties: false,
        },
    )
}

fn r2_read() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to read from".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Bytes to read (default: 256)".to_string()),
            default: Some(serde_json::json!(256)),
            enum_values: None,
        },
    );

    ToolDefinition::new("r2_read", "Read bytes from binary", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string()],
            additional_properties: false,
        },
    )
}

fn r2_cmd() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "command".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Radare2 command to execute".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("r2_cmd", "Execute raw Radare2 command", "radare2").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["command".to_string()],
            additional_properties: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_radare2_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 14);
    }
}
