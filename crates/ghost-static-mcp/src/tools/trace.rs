//! API Trace tools for ghost-static-mcp
//!
//! 19 tools (consolidated): trace_session_create, trace_control, trace_session_close,
//!           trace_session_list, trace_session_info, trace_events, trace_events_clear,
//!           trace_stats, trace_queue_stats, trace_filter_set, trace_preset_list,
//!           trace_preset_apply, trace_preset_create, trace_preset_delete,
//!           trace_pack_list, trace_pack_info, trace_pack_load, trace_pack_unload,
//!           trace_hooks_list

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register API Trace tools (19 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        trace_session_create(),
        trace_control(),
        trace_session_close(),
        trace_session_list(),
        trace_session_info(),
        trace_events(),
        trace_events_clear(),
        trace_stats(),
        trace_queue_stats(),
        trace_filter_set(),
        trace_preset_list(),
        trace_preset_apply(),
        trace_preset_create(),
        trace_preset_delete(),
        trace_pack_list(),
        trace_pack_info(),
        trace_pack_load(),
        trace_pack_unload(),
        trace_hooks_list(),
    ])
}

fn trace_session_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "trace_session_create",
        "Create a new API trace session",
        "trace",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn trace_control() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "action".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Control action".to_string()),
            default: None,
            enum_values: Some(vec![
                serde_json::json!("start"),
                serde_json::json!("stop"),
                serde_json::json!("pause"),
                serde_json::json!("resume"),
            ]),
        },
    );

    ToolDefinition::new(
        "trace_control",
        "Control trace session (start/stop/pause/resume)",
        "trace",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["session_id".to_string(), "action".to_string()],
        additional_properties: false,
    })
}

fn trace_session_close() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_session_close", "Close trace session", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_session_list() -> ToolDefinition {
    ToolDefinition::new("trace_session_list", "List all trace sessions", "trace")
        .with_schema(ToolInputSchema::empty())
}

fn trace_session_info() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_session_info", "Get trace session info", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_events() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "limit".to_string(),
        PropertySchema {
            prop_type: "integer".to_string(),
            description: Some("Maximum events to return (default: 100)".to_string()),
            default: Some(serde_json::json!(100)),
            enum_values: None,
        },
    );
    props.insert(
        "filter".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Filter events by API name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_events", "Get traced API events", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_events_clear() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_events_clear", "Clear traced events", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_stats() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_stats", "Get trace statistics", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_queue_stats() -> ToolDefinition {
    ToolDefinition::new("trace_queue_stats", "Get trace queue statistics", "trace")
        .with_schema(ToolInputSchema::empty())
}

fn trace_filter_set() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "include".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("APIs to include (patterns)".to_string()),
            default: Some(serde_json::json!([])),
            enum_values: None,
        },
    );
    props.insert(
        "exclude".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("APIs to exclude (patterns)".to_string()),
            default: Some(serde_json::json!([])),
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_filter_set", "Set trace filter rules", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_preset_list() -> ToolDefinition {
    ToolDefinition::new("trace_preset_list", "List available trace presets", "trace")
        .with_schema(ToolInputSchema::empty())
}

fn trace_preset_apply() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Trace session ID".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "preset".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Preset name (file, registry, network, crypto, etc.)".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_preset_apply", "Apply a trace preset", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string(), "preset".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_preset_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Preset name".to_string()),
            default: None,
            enum_values: None,
        },
    );
    props.insert(
        "apis".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("APIs to include in preset".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new(
        "trace_preset_create",
        "Create a custom trace preset",
        "trace",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string(), "apis".to_string()],
        additional_properties: false,
    })
}

fn trace_preset_delete() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Preset name to delete".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_preset_delete", "Delete a trace preset", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_pack_list() -> ToolDefinition {
    ToolDefinition::new(
        "trace_pack_list",
        "List available API definition packs",
        "trace",
    )
    .with_schema(ToolInputSchema::empty())
}

fn trace_pack_info() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pack".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pack name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_pack_info", "Get info about an API pack", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["pack".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_pack_load() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pack".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pack name or path".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_pack_load", "Load an API definition pack", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["pack".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_pack_unload() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "pack".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pack name".to_string()),
            default: None,
            enum_values: None,
        },
    );

    ToolDefinition::new("trace_pack_unload", "Unload an API pack", "trace").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["pack".to_string()],
            additional_properties: false,
        },
    )
}

fn trace_hooks_list() -> ToolDefinition {
    ToolDefinition::new(
        "trace_hooks_list",
        "List all active API trace hooks",
        "trace",
    )
    .with_schema(ToolInputSchema::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_trace_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 19);
    }
}
