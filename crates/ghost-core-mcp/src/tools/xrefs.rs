//! Cross-reference tools for ghost-core-mcp
//!
//! 1 tool: xref_to

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Cross-refs tools (1 tool)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(xref_to())
}

fn xref_to() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to find references to (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Limit search to specific module (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "max_results".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum results to return (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
        },
    );

    ToolDefinition::new("xref_to", "Find cross-references to an address", "xrefs").with_schema(
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
    fn test_register_xrefs_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 1);
    }
}
