//! Anti-debug bypass tools for ghost-extended-mcp
//!
//! Phase 5.6: Anti-Debug / Anti-Cheat Bypass (16 tools)
//! - Usermode anti-anti-debug hooks
//! - PEB manipulation
//! - Common anti-debug bypasses
//! - Anti-cheat evasion

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register anti-debug tools (16 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        // Status & Control
        antidebug_status(),
        antidebug_enable(),
        antidebug_disable(),
        // NtQuery Hooks
        bypass_query_process(),
        bypass_query_object(),
        bypass_query_system(),
        bypass_set_thread(),
        bypass_context(),
        bypass_close(),
        // PEB Manipulation
        hide_debugger_peb(),
        hide_global_flag(),
        hide_heap_flags(),
        // Timing Evasion
        bypass_timing(),
        // Detection Evasion
        bypass_int_scans(),
        bypass_self_debug(),
        // Module/Thread Hiding
        hide_from_enum(),
    ])
}

fn antidebug_status() -> ToolDefinition {
    ToolDefinition::new(
        "antidebug_status",
        "Get anti-debug bypass status (enabled hooks, PEB state)",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn antidebug_enable() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "preset".to_string(),
        PropertySchema::string_enum(
            "Bypass preset",
            vec!["minimal", "standard", "aggressive", "custom"],
        )
        .with_default("standard"),
    );
    props.insert(
        "hooks".to_string(),
        PropertySchema::array("Specific hooks to enable (for custom preset)"),
    );

    ToolDefinition::new(
        "antidebug_enable",
        "Enable anti-debug bypasses",
        "antidebug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn antidebug_disable() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hooks".to_string(),
        PropertySchema::array("Specific hooks to disable (empty = all)"),
    );

    ToolDefinition::new(
        "antidebug_disable",
        "Disable anti-debug bypasses",
        "antidebug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn bypass_query_process() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "classes".to_string(),
        PropertySchema::array(
            "Info classes to hook: ProcessDebugFlags, ProcessDebugPort, ProcessDebugObjectHandle",
        ),
    );

    ToolDefinition::new(
        "bypass_query_process",
        "Hook NtQueryInformationProcess to hide debug info",
        "antidebug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn bypass_query_object() -> ToolDefinition {
    ToolDefinition::new(
        "bypass_query_object",
        "Hook NtQueryObject to hide DebugObject class",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn bypass_query_system() -> ToolDefinition {
    ToolDefinition::new(
        "bypass_query_system",
        "Hook NtQuerySystemInformation for SystemKernelDebuggerInformation",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn bypass_set_thread() -> ToolDefinition {
    ToolDefinition::new(
        "bypass_set_thread",
        "Hook NtSetInformationThread to block ThreadHideFromDebugger",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn bypass_context() -> ToolDefinition {
    ToolDefinition::new(
        "bypass_context",
        "Hook NtGetContextThread/NtSetContextThread to protect hardware breakpoints",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn bypass_close() -> ToolDefinition {
    ToolDefinition::new(
        "bypass_close",
        "Hook NtClose to suppress debug exceptions on invalid handles",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn hide_debugger_peb() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "value".to_string(),
        PropertySchema::boolean("Set BeingDebugged to 0").with_default(true),
    );

    ToolDefinition::new(
        "hide_debugger_peb",
        "Clear PEB.BeingDebugged flag",
        "antidebug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn hide_global_flag() -> ToolDefinition {
    ToolDefinition::new(
        "hide_global_flag",
        "Clear PEB.NtGlobalFlag debug bits (FLG_HEAP_*)",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn hide_heap_flags() -> ToolDefinition {
    ToolDefinition::new(
        "hide_heap_flags",
        "Clear debug heap flags (ForceFlags, Flags)",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn bypass_timing() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "apis".to_string(),
        PropertySchema::array(
            "Timing APIs to hook: rdtsc, QueryPerformanceCounter, GetTickCount, timeGetTime",
        ),
    );
    props.insert(
        "mode".to_string(),
        PropertySchema::string_enum("Bypass mode", vec!["normalize", "freeze", "accelerate"])
            .with_default("normalize"),
    );

    ToolDefinition::new(
        "bypass_timing",
        "Hook timing APIs to evade timing-based anti-debug",
        "antidebug",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn bypass_int_scans() -> ToolDefinition {
    ToolDefinition::new(
        "bypass_int_scans",
        "Evade INT 2D / INT 3 self-scan detection",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn bypass_self_debug() -> ToolDefinition {
    ToolDefinition::new(
        "bypass_self_debug",
        "Evade self-debugging detection techniques",
        "antidebug",
    )
    .with_schema(ToolInputSchema::empty())
}

fn hide_from_enum() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hide_modules".to_string(),
        PropertySchema::boolean("Hide from module enumeration").with_default(true),
    );
    props.insert(
        "hide_threads".to_string(),
        PropertySchema::boolean("Hide from thread enumeration").with_default(true),
    );
    props.insert(
        "hide_memory".to_string(),
        PropertySchema::boolean("Hide from memory scans").with_default(false),
    );

    ToolDefinition::new(
        "hide_from_enum",
        "Hide agent from enumeration APIs",
        "antidebug",
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
    fn test_register_antidebug_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 16);
    }
}
