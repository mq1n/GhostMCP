//! Execution tools for ghost-core-mcp
//!
//! 15 tools: exec_resolve, exec_call, exec_call_api, exec_shellcode,
//!           exec_alloc, exec_free, exec_write,
//!           cave_find, cave_alloc, cave_free, cave_list,
//!           syscall_number, syscall_invoke, remote_thread, remote_apc

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register Execution tools (15 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        exec_resolve(),
        exec_call(),
        exec_call_api(),
        exec_shellcode(),
        exec_alloc(),
        exec_free(),
        exec_write(),
        cave_find(),
        cave_alloc(),
        cave_free(),
        cave_list(),
        syscall_number(),
        syscall_invoke(),
        remote_thread(),
        remote_apc(),
    ])
}

fn exec_resolve() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some(
                "Function name to resolve (e.g., 'kernel32!CreateFileW')".to_string(),
            ),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "exec_resolve",
        "Resolve a function address by name",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn exec_call() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function address to call (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "args".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Arguments to pass (as hex strings or integers)".to_string()),
            default: Some(serde_json::json!([])),
            enum_values: None,
        },
    );
    props.insert(
        "convention".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Calling convention".to_string()),
            default: Some(serde_json::json!("fastcall")),
            enum_values: Some(vec![
                serde_json::json!("fastcall"),
                serde_json::json!("stdcall"),
                serde_json::json!("cdecl"),
            ]),
        },
    );

    ToolDefinition::new(
        "exec_call",
        "Call a function at address (requires execute capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn exec_call_api() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("API name (e.g., 'kernel32!MessageBoxW')".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "args".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Arguments to pass".to_string()),
            default: Some(serde_json::json!([])),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "exec_call_api",
        "Call a Windows API by name (requires execute capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn exec_shellcode() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "shellcode".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Shellcode bytes as hex string".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some(
                "Address to execute at (optional, allocates if not specified)".to_string(),
            ),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "exec_shellcode",
        "Execute shellcode in target process (requires execute capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["shellcode".to_string()],
        additional_properties: false,
    })
}

fn exec_alloc() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Size in bytes to allocate".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "protection".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Memory protection".to_string()),
            default: Some(serde_json::json!("rwx")),
            enum_values: Some(vec![
                serde_json::json!("rw"),
                serde_json::json!("rx"),
                serde_json::json!("rwx"),
            ]),
        },
    );

    ToolDefinition::new(
        "exec_alloc",
        "Allocate memory in target process (requires write capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["size".to_string()],
        additional_properties: false,
    })
}

fn exec_free() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to free (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "exec_free",
        "Free allocated memory (requires write capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn exec_write() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Address to write to (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "data".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Data to write (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "exec_write",
        "Write data to allocated memory (requires write capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string(), "data".to_string()],
        additional_properties: false,
    })
}

fn cave_find() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Minimum size of code cave needed".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "module".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Module to search in (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "cave_find",
        "Find code caves (unused executable memory regions)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["size".to_string()],
        additional_properties: false,
    })
}

fn cave_alloc() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "size".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Size of code cave to allocate".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Specific address to mark as allocated (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "near".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Allocate near this address (for short jumps)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "cave_alloc",
        "Allocate a code cave (finds one if address not specified)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["size".to_string()],
        additional_properties: false,
    })
}

fn cave_free() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Code cave address to free".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("cave_free", "Free a code cave", "execution").with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["address".to_string()],
        additional_properties: false,
    })
}

fn cave_list() -> ToolDefinition {
    ToolDefinition::new("cave_list", "List all allocated code caves", "execution")
        .with_schema(ToolInputSchema::empty())
}

fn syscall_number() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Syscall name (e.g., 'NtReadVirtualMemory')".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "syscall_number",
        "Get the syscall number for an NT function",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn syscall_invoke() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "number".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Syscall number".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "args".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Syscall arguments".to_string()),
            default: Some(serde_json::json!([])),
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "syscall_invoke",
        "Invoke a syscall directly (requires execute capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["number".to_string()],
        additional_properties: false,
    })
}

fn remote_thread() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pid".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Target Process ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "shellcode".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Shellcode to inject (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Start address (if no shellcode provided)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "parameter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Parameter to pass (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "remote_thread",
        "Create a remote thread in target process (requires execute capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["pid".to_string()],
        additional_properties: false,
    })
}

fn remote_apc() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pid".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Target Process ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "tid".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Thread ID to queue APC to".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "shellcode".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Shellcode to inject (hex string)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "address".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("APC function address (if no shellcode provided)".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "parameter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Parameter to pass (optional)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "remote_apc",
        "Queue an APC to a thread (requires execute capability)",
        "execution",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["pid".to_string(), "tid".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_execution_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 15);
    }
}
