//! Session/Process tools for ghost-core-mcp
//!
//! 7 tools: session_info, session_attach, session_detach,
//!          process_list, process_spawn, process_resume, process_terminate

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Session/Process tools (7 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        session_info(),
        session_attach(),
        session_detach(),
        process_list(),
        process_spawn(),
        process_resume(),
        process_terminate(),
    ])
}

fn session_info() -> ToolDefinition {
    ToolDefinition::new(
        "session_info",
        "Get information about the current session (attached process, capabilities, etc.)",
        "session",
    )
    .with_schema(ToolInputSchema::empty())
}

fn session_attach() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pid".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Process ID to attach to".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Process name to attach to (alternative to pid)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "session_attach",
        "Attach to a process by PID or name",
        "session",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn session_detach() -> ToolDefinition {
    ToolDefinition::new(
        "session_detach",
        "Detach from the current process",
        "session",
    )
    .with_schema(ToolInputSchema::empty())
}

fn process_list() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter by process name pattern (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "process_list",
        "List running processes on the system",
        "session",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn process_spawn() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Path to executable".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "args".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Command line arguments (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "suspended".to_string(),
        PropertySchema {
            prop_type: "boolean".to_string(),
            description: Some("Start process suspended (default: true)".to_string()),
            default: Some(serde_json::json!(true)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "process_spawn",
        "Spawn a new process (optionally suspended for injection)",
        "session",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["path".to_string()],
        additional_properties: false,
    })
}

fn process_resume() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pid".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some(
                "Process ID to resume (optional, uses current if attached)".to_string(),
            ),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("process_resume", "Resume a suspended process", "session").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn process_terminate() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pid".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some(
                "Process ID to terminate (optional, uses current if attached)".to_string(),
            ),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "exit_code".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Exit code (default: 0)".to_string()),
            default: Some(serde_json::json!(0)),
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "process_terminate",
        "Terminate a process (requires admin capability)",
        "session",
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
    fn test_register_session_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 7);
    }
}
