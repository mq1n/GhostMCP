//! Script/Hook tools for ghost-core-mcp
//!
//! 11 tools: script_load, script_unload, script_reload, script_list, script_status,
//!           hook_create, hook_remove, hook_enable, hook_list, rpc_list, rpc_call

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Script/Hook tools (11 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        script_load(),
        script_unload(),
        script_reload(),
        script_list(),
        script_status(),
        hook_create(),
        hook_remove(),
        hook_enable(),
        hook_list(),
        rpc_list(),
        rpc_call(),
    ])
}

fn script_load() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Path to script file".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "code".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Inline script code (alternative to path)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Script name identifier".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("script_load", "Load and execute a Lua script", "script").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn script_unload() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Script name to unload".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("script_unload", "Unload a loaded script", "script").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string()],
            additional_properties: false,
        },
    )
}

fn script_reload() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Script name to reload".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("script_reload", "Reload a script from disk", "script").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string()],
            additional_properties: false,
        },
    )
}

fn script_list() -> ToolDefinition {
    ToolDefinition::new("script_list", "List all loaded scripts", "script")
        .with_schema(ToolInputSchema::empty())
}

fn script_status() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Script name to get status for".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "script_status",
        "Get detailed status for a script",
        "script",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn hook_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to hook (hex string)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "callback".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Lua callback function name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Hook type".to_string()),
            default: Some(serde_json::json!("inline")),
            enum_values: Some(vec![
                serde_json::json!("inline"),
                serde_json::json!("iat"),
                serde_json::json!("vmt"),
            ]),
            items: None,
        },
    );

    ToolDefinition::new(
        "hook_create",
        "Create a function hook (requires execute capability)",
        "script",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string(), "callback".to_string()],
        additional_properties: false,
    })
}

fn hook_remove() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Hook ID to remove".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("hook_remove", "Remove a hook", "script").with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["id".to_string()],
        additional_properties: false,
    })
}

fn hook_enable() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Hook ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "enabled".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Enable (true) or disable (false)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("hook_enable", "Enable or disable a hook", "script").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["id".to_string()],
            additional_properties: false,
        },
    )
}

fn hook_list() -> ToolDefinition {
    ToolDefinition::new("hook_list", "List all active hooks", "script")
        .with_schema(ToolInputSchema::empty())
}

fn rpc_list() -> ToolDefinition {
    ToolDefinition::new(
        "rpc_list",
        "List available RPC functions from loaded scripts",
        "script",
    )
    .with_schema(ToolInputSchema::empty())
}

fn rpc_call() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "function".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("RPC function name to call".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "args".to_string(),
        PropertySchema {
            prop_type: "object".to_string(),
            description: Some("Arguments to pass to the function".to_string()),
            default: Some(serde_json::json!({})),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("rpc_call", "Call an RPC function from a script", "script").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["function".to_string()],
            additional_properties: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_script_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 11);
    }
}
