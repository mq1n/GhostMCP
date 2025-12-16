//! AI tools for ghost-static-mcp
//!
//! 12 tools: ai_summarize, ai_diff, ai_explain_error, ai_recommend_breakpoints,
//!           ai_analyze_vulnerability, ai_learn_pattern, ai_patterns_list,
//!           debug_session_create, debug_session_info, debug_session_update,
//!           debug_session_close, debug_session_list

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register AI tools (12 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        ai_summarize(),
        ai_diff(),
        ai_explain_error(),
        ai_recommend_breakpoints(),
        ai_analyze_vulnerability(),
        ai_learn_pattern(),
        ai_patterns_list(),
        debug_session_create(),
        debug_session_info(),
        debug_session_update(),
        debug_session_close(),
        debug_session_list(),
    ])
}

fn ai_summarize() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "content".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some(
                "Content to summarize (disassembly, decompiled code, etc.)".to_string(),
            ),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "context".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Additional context for summarization".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "ai_summarize",
        "AI-powered summarization of code or analysis",
        "ai",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["content".to_string()],
        additional_properties: false,
    })
}

fn ai_diff() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "before".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Original code/data".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "after".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Modified code/data".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ai_diff", "AI-powered diff analysis", "ai").with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["before".to_string(), "after".to_string()],
        additional_properties: false,
    })
}

fn ai_explain_error() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "error".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Error message or crash info".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "context".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Stack trace or surrounding code".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("ai_explain_error", "AI explanation of error or crash", "ai").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["error".to_string()],
            additional_properties: false,
        },
    )
}

fn ai_recommend_breakpoints() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "function".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Function code (disassembly or decompiled)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "goal".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("What you're trying to find/debug".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "ai_recommend_breakpoints",
        "AI-recommended breakpoint locations",
        "ai",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["function".to_string()],
        additional_properties: false,
    })
}

fn ai_analyze_vulnerability() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "code".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Code to analyze for vulnerabilities".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "ai_analyze_vulnerability",
        "AI vulnerability analysis",
        "ai",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["code".to_string()],
        additional_properties: false,
    })
}

fn ai_learn_pattern() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Pattern name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "examples".to_string(),
        PropertySchema {
            prop_type: "array".to_string(),
            description: Some("Example code snippets".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "description".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("What this pattern represents".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "ai_learn_pattern",
        "Teach AI to recognize a code pattern",
        "ai",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string(), "examples".to_string()],
        additional_properties: false,
    })
}

fn ai_patterns_list() -> ToolDefinition {
    ToolDefinition::new("ai_patterns_list", "List learned AI patterns", "ai")
        .with_schema(ToolInputSchema::empty())
}

fn debug_session_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Debug session name".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "goal".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("What you're trying to achieve".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "debug_session_create",
        "Create an AI-assisted debug session",
        "ai",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["goal".to_string()],
        additional_properties: false,
    })
}

fn debug_session_info() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Debug session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "debug_session_info",
        "Get debug session info and progress",
        "ai",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["session_id".to_string()],
        additional_properties: false,
    })
}

fn debug_session_update() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Debug session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "findings".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("New findings to add to session".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new(
        "debug_session_update",
        "Update debug session with findings",
        "ai",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["session_id".to_string(), "findings".to_string()],
        additional_properties: false,
    })
}

fn debug_session_close() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "session_id".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Debug session ID".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );
    props.insert(
        "summary".to_string(),
        PropertySchema {
            prop_type: "string".to_string(),
            description: Some("Final summary (optional)".to_string()),
            default: None,
            enum_values: None,
            items: None,
        },
    );

    ToolDefinition::new("debug_session_close", "Close debug session", "ai").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["session_id".to_string()],
            additional_properties: false,
        },
    )
}

fn debug_session_list() -> ToolDefinition {
    ToolDefinition::new("debug_session_list", "List all debug sessions", "ai")
        .with_schema(ToolInputSchema::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_ai_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 12);
    }
}
