//! Introspection tools for ghost-analysis-mcp
//!
//! 20 tools: introspect_process, introspect_process_list, introspect_peb,
//!           introspect_memory_map, introspect_environment, introspect_cwd,
//!           introspect_set_cwd, introspect_thread, introspect_thread_list,
//!           introspect_teb, introspect_tls, introspect_module,
//!           introspect_module_list, introspect_sections, introspect_handles,
//!           introspect_windows, introspect_window, introspect_child_windows,
//!           introspect_token, introspect_adjust_privilege

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Introspection tools (20 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        introspect_process(),
        introspect_process_list(),
        introspect_peb(),
        introspect_memory_map(),
        introspect_environment(),
        introspect_cwd(),
        introspect_set_cwd(),
        introspect_thread(),
        introspect_thread_list(),
        introspect_teb(),
        introspect_tls(),
        introspect_module(),
        introspect_module_list(),
        introspect_sections(),
        introspect_handles(),
        introspect_windows(),
        introspect_window(),
        introspect_child_windows(),
        introspect_token(),
        introspect_adjust_privilege(),
    ])
}

fn introspect_process() -> ToolDefinition {
    ToolDefinition::new(
        "introspect_process",
        "Get detailed info about current process",
        "introspect",
    )
    .with_schema(ToolInputSchema::empty())
}

fn introspect_process_list() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "include_threads".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Include thread info (default: false)".to_string()),
            default: Some(serde_json::json!(false)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_process_list",
        "List all processes with details",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn introspect_peb() -> ToolDefinition {
    ToolDefinition::new(
        "introspect_peb",
        "Get Process Environment Block (PEB) info",
        "introspect",
    )
    .with_schema(ToolInputSchema::empty())
}

fn introspect_memory_map() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "include_mapped".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Include mapped files (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_memory_map",
        "Get detailed memory map",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn introspect_environment() -> ToolDefinition {
    ToolDefinition::new(
        "introspect_environment",
        "Get process environment variables",
        "introspect",
    )
    .with_schema(ToolInputSchema::empty())
}

fn introspect_cwd() -> ToolDefinition {
    ToolDefinition::new(
        "introspect_cwd",
        "Get current working directory",
        "introspect",
    )
    .with_schema(ToolInputSchema::empty())
}

fn introspect_set_cwd() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("New working directory path".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_set_cwd",
        "Set current working directory",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["path".to_string()],
        additional_properties: false,
    })
}

fn introspect_thread() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_thread",
        "Get detailed thread info",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["thread_id".to_string()],
        additional_properties: false,
    })
}

fn introspect_thread_list() -> ToolDefinition {
    ToolDefinition::new(
        "introspect_thread_list",
        "List all threads with details",
        "introspect",
    )
    .with_schema(ToolInputSchema::empty())
}

fn introspect_teb() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID (optional, uses current)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_teb",
        "Get Thread Environment Block (TEB)",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn introspect_tls() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_tls",
        "Get Thread Local Storage slots",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn introspect_module() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_module",
        "Get detailed module info",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["module".to_string()],
        additional_properties: false,
    })
}

fn introspect_module_list() -> ToolDefinition {
    ToolDefinition::new(
        "introspect_module_list",
        "List all modules with PE info",
        "introspect",
    )
    .with_schema(ToolInputSchema::empty())
}

fn introspect_sections() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_sections",
        "Get PE sections for a module",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["module".to_string()],
        additional_properties: false,
    })
}

fn introspect_handles() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "type_filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by handle type (File, Key, Section, etc.)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("introspect_handles", "List process handles", "introspect").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn introspect_windows() -> ToolDefinition {
    ToolDefinition::new("introspect_windows", "List top-level windows", "introspect")
        .with_schema(ToolInputSchema::empty())
}

fn introspect_window() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hwnd".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Window handle (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("introspect_window", "Get window details", "introspect").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["hwnd".to_string()],
            additional_properties: false,
        },
    )
}

fn introspect_child_windows() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hwnd".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Parent window handle (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_child_windows",
        "List child windows",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["hwnd".to_string()],
        additional_properties: false,
    })
}

fn introspect_token() -> ToolDefinition {
    ToolDefinition::new(
        "introspect_token",
        "Get process token info (privileges, groups)",
        "introspect",
    )
    .with_schema(ToolInputSchema::empty())
}

fn introspect_adjust_privilege() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "privilege".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Privilege name (e.g., SeDebugPrivilege)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "enable".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Enable or disable (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "introspect_adjust_privilege",
        "Adjust process privilege",
        "introspect",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["privilege".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_introspect_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 20);
    }
}
