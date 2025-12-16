//! Disassembly tools for ghost-core-mcp
//!
//! 5 tools: disasm_at, disasm_function, decompile, assemble, assemble_shellcode

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Disassembly tools (5 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        disasm_at(),
        disasm_function(),
        decompile(),
        assemble(),
        assemble_shellcode(),
    ])
}

fn disasm_at() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to disassemble at (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "count".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Number of instructions to disassemble (default: 20)".to_string()),
            default: Some(serde_json::json!(20)),
            enum_values: None,
        },
    );
    props.insert(
        "arch".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Architecture".to_string()),
            default: Some(serde_json::json!("x64")),
            enum_values: Some(vec![serde_json::json!("x64"), serde_json::json!("x86")]),
        },
    );

    ToolDefinition::new("disasm_at", "Disassemble instructions at address", "disasm").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string()],
            additional_properties: false,
        },
    )
}

fn disasm_function() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function start address (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function name (alternative to address)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "max_instructions".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum instructions (default: 500)".to_string()),
            default: Some(serde_json::json!(500)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "disasm_function",
        "Disassemble an entire function",
        "disasm",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn decompile() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function address to decompile (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function name (alternative to address)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "decompile",
        "Decompile a function to pseudo-C (requires external backend)",
        "disasm",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn assemble() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "code".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Assembly code to assemble".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Base address for assembly (affects relative jumps)".to_string()),
            default: Some(serde_json::json!("0x0")),
            enum_values: None,
        },
    );
    props.insert(
        "arch".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Architecture".to_string()),
            default: Some(serde_json::json!("x64")),
            enum_values: Some(vec![serde_json::json!("x64"), serde_json::json!("x86")]),
        },
    );

    ToolDefinition::new(
        "assemble",
        "Assemble instructions to machine code",
        "disasm",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["code".to_string()],
        additional_properties: false,
    })
}

fn assemble_shellcode() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "code".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Assembly code for shellcode".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "null_free".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Generate null-free shellcode (default: false)".to_string()),
            default: Some(serde_json::json!(false)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "assemble_shellcode",
        "Assemble position-independent shellcode",
        "disasm",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["code".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_disasm_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 5);
    }
}
