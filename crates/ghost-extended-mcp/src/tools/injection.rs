//! Remote injection tools for ghost-extended-mcp
//!
//! Phase 5.5b: Agent-Based Remote Injection (22 tools)
//! - Remote process injection (DLL, shellcode, code)
//! - Cross-process hooking
//! - Process hollowing & ghosting
//! - Multi-process orchestration

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register injection tools (22 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        // Remote Process Injection
        inject_dll(),
        inject_shellcode(),
        inject_code(),
        remote_alloc(),
        remote_write(),
        remote_read(),
        remote_free(),
        inject_remote_thread(),
        // Injection Methods
        inject_loadlibrary(),
        inject_manual_map(),
        inject_reflective(),
        inject_apc(),
        inject_hijack(),
        inject_section(),
        // Cross-Process Hooking
        remote_hook_iat(),
        remote_hook_eat(),
        remote_hook_inline(),
        // Process Hollowing & Ghosting
        hollow_create(),
        hollow_inject(),
        doppelgang_create(),
        ghost_create(),
        // Multi-Process Orchestration
        orchestrate_chain(),
    ])
}

fn inject_dll() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "dll_path".to_string(),
        PropertySchema::string("Path to DLL to inject"),
    );
    props.insert(
        "method".to_string(),
        PropertySchema::string_enum(
            "Injection method",
            vec!["loadlibrary", "manual_map", "reflective"],
        )
        .with_default("loadlibrary"),
    );

    ToolDefinition::new("inject_dll", "Inject DLL into remote process", "injection").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["target".to_string(), "dll_path".to_string()],
            additional_properties: false,
        },
    )
}

fn inject_shellcode() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "shellcode".to_string(),
        PropertySchema::string("Shellcode as hex string"),
    );
    props.insert(
        "method".to_string(),
        PropertySchema::string_enum(
            "Execution method",
            vec!["thread", "apc", "hijack", "section"],
        )
        .with_default("thread"),
    );

    ToolDefinition::new(
        "inject_shellcode",
        "Inject and execute shellcode in remote process",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "shellcode".to_string()],
        additional_properties: false,
    })
}

fn inject_code() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "code".to_string(),
        PropertySchema::string("Assembly code to inject"),
    );

    ToolDefinition::new(
        "inject_code",
        "Inject assembled code into remote process",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "code".to_string()],
        additional_properties: false,
    })
}

fn remote_alloc() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "size".to_string(),
        PropertySchema::integer("Size to allocate"),
    );
    props.insert(
        "protection".to_string(),
        PropertySchema::string_enum("Memory protection", vec!["rwx", "rw", "rx", "r"])
            .with_default("rw"),
    );

    ToolDefinition::new(
        "remote_alloc",
        "Allocate memory in remote process (VirtualAllocEx)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "size".to_string()],
        additional_properties: false,
    })
}

fn remote_write() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "address".to_string(),
        PropertySchema::string("Address to write to"),
    );
    props.insert(
        "data".to_string(),
        PropertySchema::string("Data as hex string"),
    );

    ToolDefinition::new(
        "remote_write",
        "Write memory in remote process (WriteProcessMemory)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "target".to_string(),
            "address".to_string(),
            "data".to_string(),
        ],
        additional_properties: false,
    })
}

fn remote_read() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "address".to_string(),
        PropertySchema::string("Address to read from"),
    );
    props.insert(
        "size".to_string(),
        PropertySchema::integer("Number of bytes to read"),
    );

    ToolDefinition::new(
        "remote_read",
        "Read memory from remote process (ReadProcessMemory)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "target".to_string(),
            "address".to_string(),
            "size".to_string(),
        ],
        additional_properties: false,
    })
}

fn remote_free() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "address".to_string(),
        PropertySchema::string("Address to free"),
    );

    ToolDefinition::new(
        "remote_free",
        "Free memory in remote process (VirtualFreeEx)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "address".to_string()],
        additional_properties: false,
    })
}

fn inject_remote_thread() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "address".to_string(),
        PropertySchema::string("Thread start address"),
    );
    props.insert(
        "parameter".to_string(),
        PropertySchema::string("Thread parameter (optional)"),
    );

    ToolDefinition::new(
        "inject_remote_thread",
        "Create remote thread (CreateRemoteThread/NtCreateThreadEx)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "address".to_string()],
        additional_properties: false,
    })
}

fn inject_loadlibrary() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "dll_path".to_string(),
        PropertySchema::string("Path to DLL"),
    );

    ToolDefinition::new(
        "inject_loadlibrary",
        "Inject DLL via LoadLibrary remote thread",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "dll_path".to_string()],
        additional_properties: false,
    })
}

fn inject_manual_map() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "dll_path".to_string(),
        PropertySchema::string("Path to DLL"),
    );
    props.insert(
        "wipe_headers".to_string(),
        PropertySchema::boolean("Wipe PE headers after mapping").with_default(false),
    );

    ToolDefinition::new(
        "inject_manual_map",
        "Inject DLL via manual mapping (no LoadLibrary)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "dll_path".to_string()],
        additional_properties: false,
    })
}

fn inject_reflective() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "dll_path".to_string(),
        PropertySchema::string("Path to reflective DLL"),
    );

    ToolDefinition::new(
        "inject_reflective",
        "Inject DLL via reflective loading",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "dll_path".to_string()],
        additional_properties: false,
    })
}

fn inject_apc() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "thread_id".to_string(),
        PropertySchema::integer("Target thread ID (0 = all alertable threads)"),
    );
    props.insert(
        "shellcode".to_string(),
        PropertySchema::string("Shellcode as hex string"),
    );

    ToolDefinition::new("inject_apc", "Inject via APC (QueueUserAPC)", "injection").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["target".to_string(), "shellcode".to_string()],
            additional_properties: false,
        },
    )
}

fn inject_hijack() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "thread_id".to_string(),
        PropertySchema::integer("Thread ID to hijack"),
    );
    props.insert(
        "shellcode".to_string(),
        PropertySchema::string("Shellcode as hex string"),
    );

    ToolDefinition::new(
        "inject_hijack",
        "Inject via thread hijacking (suspend, modify context, resume)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "target".to_string(),
            "thread_id".to_string(),
            "shellcode".to_string(),
        ],
        additional_properties: false,
    })
}

fn inject_section() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "shellcode".to_string(),
        PropertySchema::string("Shellcode as hex string"),
    );

    ToolDefinition::new(
        "inject_section",
        "Inject via NtMapViewOfSection",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target".to_string(), "shellcode".to_string()],
        additional_properties: false,
    })
}

fn remote_hook_iat() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "module".to_string(),
        PropertySchema::string("Module containing IAT"),
    );
    props.insert(
        "function".to_string(),
        PropertySchema::string("Function name to hook"),
    );
    props.insert(
        "hook_address".to_string(),
        PropertySchema::string("Address of hook function"),
    );

    ToolDefinition::new(
        "remote_hook_iat",
        "Patch IAT entry in remote process",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "target".to_string(),
            "module".to_string(),
            "function".to_string(),
            "hook_address".to_string(),
        ],
        additional_properties: false,
    })
}

fn remote_hook_eat() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "module".to_string(),
        PropertySchema::string("Module containing EAT"),
    );
    props.insert(
        "function".to_string(),
        PropertySchema::string("Exported function name"),
    );
    props.insert(
        "hook_address".to_string(),
        PropertySchema::string("Address of hook function"),
    );

    ToolDefinition::new(
        "remote_hook_eat",
        "Patch EAT entry in remote process",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "target".to_string(),
            "module".to_string(),
            "function".to_string(),
            "hook_address".to_string(),
        ],
        additional_properties: false,
    })
}

fn remote_hook_inline() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target".to_string(),
        PropertySchema::string("Target process (PID or name)"),
    );
    props.insert(
        "address".to_string(),
        PropertySchema::string("Address to hook"),
    );
    props.insert(
        "hook_address".to_string(),
        PropertySchema::string("Address of hook function"),
    );

    ToolDefinition::new(
        "remote_hook_inline",
        "Install inline hook in remote process",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "target".to_string(),
            "address".to_string(),
            "hook_address".to_string(),
        ],
        additional_properties: false,
    })
}

fn hollow_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target_exe".to_string(),
        PropertySchema::string("Path to legitimate executable to hollow"),
    );
    props.insert(
        "payload_exe".to_string(),
        PropertySchema::string("Path to payload executable"),
    );

    ToolDefinition::new(
        "hollow_create",
        "Create hollowed process (process hollowing)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target_exe".to_string(), "payload_exe".to_string()],
        additional_properties: false,
    })
}

fn hollow_inject() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pid".to_string(),
        PropertySchema::integer("PID of suspended process"),
    );
    props.insert(
        "payload".to_string(),
        PropertySchema::string("Payload PE as base64"),
    );

    ToolDefinition::new(
        "hollow_inject",
        "Inject payload into hollowed process",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["pid".to_string(), "payload".to_string()],
        additional_properties: false,
    })
}

fn doppelgang_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "target_exe".to_string(),
        PropertySchema::string("Path to target executable"),
    );
    props.insert(
        "payload_exe".to_string(),
        PropertySchema::string("Path to payload executable"),
    );

    ToolDefinition::new(
        "doppelgang_create",
        "Create doppelganger process (process doppelganging)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["target_exe".to_string(), "payload_exe".to_string()],
        additional_properties: false,
    })
}

fn ghost_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "payload_exe".to_string(),
        PropertySchema::string("Path to payload executable"),
    );

    ToolDefinition::new(
        "ghost_create",
        "Create ghosted process (process ghosting via delete-pending)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["payload_exe".to_string()],
        additional_properties: false,
    })
}

fn orchestrate_chain() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "chain".to_string(),
        PropertySchema::array("Chain of injection steps"),
    );

    ToolDefinition::new(
        "orchestrate_chain",
        "Execute chain of injections (A -> B -> C)",
        "injection",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["chain".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_injection_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 22);
    }
}
