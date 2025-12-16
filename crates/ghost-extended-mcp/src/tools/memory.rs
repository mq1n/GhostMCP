//! Advanced memory tools for ghost-extended-mcp
//!
//! Phase 5.20: Advanced Memory Tools (8 tools)
//! - Memory comparison
//! - Pattern filling
//! - Export/labeling
//! - Undo/redo

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register advanced memory tools (8 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        mem_compare(),
        mem_fill(),
        mem_export_c(),
        mem_export_hex(),
        mem_label(),
        mem_labels_list(),
        mem_undo(),
        mem_redo(),
    ])
}

fn mem_compare() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert("addr1".to_string(), PropertySchema::string("First address"));
    props.insert(
        "addr2".to_string(),
        PropertySchema::string("Second address"),
    );
    props.insert(
        "size".to_string(),
        PropertySchema::integer("Size to compare in bytes"),
    );

    ToolDefinition::new(
        "mem_compare",
        "Compare two memory blocks and show differences",
        "memory",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["addr1".to_string(), "addr2".to_string(), "size".to_string()],
        additional_properties: false,
    })
}

fn mem_fill() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema::string("Start address"),
    );
    props.insert(
        "size".to_string(),
        PropertySchema::integer("Size to fill in bytes"),
    );
    props.insert(
        "pattern".to_string(),
        PropertySchema::string("Pattern to fill (hex string, e.g., '90' for NOP or 'DEADBEEF')"),
    );
    props.insert(
        "token_id".to_string(),
        PropertySchema::string("Safety token for write operation"),
    );

    ToolDefinition::new(
        "mem_fill",
        "Fill memory range with repeating pattern",
        "memory",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "address".to_string(),
            "size".to_string(),
            "pattern".to_string(),
        ],
        additional_properties: false,
    })
}

fn mem_export_c() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema::string("Start address"),
    );
    props.insert("size".to_string(), PropertySchema::integer("Size in bytes"));
    props.insert(
        "name".to_string(),
        PropertySchema::string("Variable name for the array").with_default("data"),
    );
    props.insert(
        "format".to_string(),
        PropertySchema::string_enum("Output format", vec!["c", "rust", "python"]).with_default("c"),
    );

    ToolDefinition::new(
        "mem_export_c",
        "Export memory as C/Rust/Python array",
        "memory",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string(), "size".to_string()],
        additional_properties: false,
    })
}

fn mem_export_hex() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema::string("Start address"),
    );
    props.insert("size".to_string(), PropertySchema::integer("Size in bytes"));
    props.insert(
        "format".to_string(),
        PropertySchema::string_enum(
            "Hex format",
            vec!["raw", "spaced", "0x_prefixed", "escaped"],
        )
        .with_default("spaced"),
    );

    ToolDefinition::new("mem_export_hex", "Export memory as hex string", "memory").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string(), "size".to_string()],
            additional_properties: false,
        },
    )
}

fn mem_label() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema::string("Address to label"),
    );
    props.insert("label".to_string(), PropertySchema::string("Label name"));
    props.insert(
        "comment".to_string(),
        PropertySchema::string("Optional comment"),
    );

    ToolDefinition::new("mem_label", "Add label/bookmark to an address", "memory").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string(), "label".to_string()],
            additional_properties: false,
        },
    )
}

fn mem_labels_list() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema::string("Filter labels by name pattern"),
    );

    ToolDefinition::new("mem_labels_list", "List all memory labels", "memory").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn mem_undo() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "count".to_string(),
        PropertySchema::integer("Number of operations to undo").with_default(1),
    );

    ToolDefinition::new("mem_undo", "Undo last memory edit(s)", "memory").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn mem_redo() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "count".to_string(),
        PropertySchema::integer("Number of operations to redo").with_default(1),
    );

    ToolDefinition::new("mem_redo", "Redo undone memory edit(s)", "memory").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_memory_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 8);
    }
}
