//! Debug/Thread tools for ghost-core-mcp
//!
//! 11 tools: thread_list, thread_registers, thread_suspend, thread_resume,
//!           breakpoint_set, breakpoint_remove, breakpoint_list, breakpoint_enable,
//!           execution_continue, execution_step_into, stack_walk

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Debug/Thread tools (11 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        thread_list(),
        thread_registers(),
        thread_suspend(),
        thread_resume(),
        breakpoint_set(),
        breakpoint_remove(),
        breakpoint_list(),
        breakpoint_enable(),
        execution_continue(),
        execution_step_into(),
        stack_walk(),
    ])
}

fn thread_list() -> ToolDefinition {
    ToolDefinition::new(
        "thread_list",
        "List all threads in target process with state info",
        "debug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn thread_registers() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID to get registers for".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "thread_registers",
        "Get CPU registers for a thread (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["thread_id".to_string()],
        additional_properties: false,
    })
}

fn thread_suspend() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID to suspend".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "thread_suspend",
        "Suspend a thread (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["thread_id".to_string()],
        additional_properties: false,
    })
}

fn thread_resume() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID to resume".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "thread_resume",
        "Resume a suspended thread (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["thread_id".to_string()],
        additional_properties: false,
    })
}

fn breakpoint_set() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to set breakpoint at (hex string)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "type".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Breakpoint type".to_string()),
            default: Some(serde_json::json!("software")),
            enum_values: Some(vec![
                serde_json::json!("software"),
                serde_json::json!("hardware"),
            ]),
            items: None,
        },
    );
    props.insert(
        "condition".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Conditional expression (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "breakpoint_set",
        "Set a breakpoint at address (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn breakpoint_remove() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Breakpoint ID to remove".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "breakpoint_remove",
        "Remove a breakpoint (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["id".to_string()],
        additional_properties: false,
    })
}

fn breakpoint_list() -> ToolDefinition {
    ToolDefinition::new("breakpoint_list", "List all active breakpoints", "debug")
        .with_schema(ToolInputSchema::empty())
}

fn breakpoint_enable() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Breakpoint ID".to_string()),
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

    ToolDefinition::new(
        "breakpoint_enable",
        "Enable or disable a breakpoint (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["id".to_string()],
        additional_properties: false,
    })
}

fn execution_continue() -> ToolDefinition {
    ToolDefinition::new(
        "execution_continue",
        "Continue execution after breakpoint (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn execution_step_into() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID to step (optional, uses current)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "execution_step_into",
        "Single-step one instruction (requires debug capability)",
        "debug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn stack_walk() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "thread_id".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID to walk stack for".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "max_frames".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum frames to return (default: 50)".to_string()),
            default: Some(serde_json::json!(50)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("stack_walk", "Walk the call stack for a thread", "debug").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["thread_id".to_string()],
            additional_properties: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_debug_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 11);
    }
}
