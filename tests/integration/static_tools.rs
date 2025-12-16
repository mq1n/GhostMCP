//! Static Analysis Tool Integration Tests
//!
//! Tests for ghost-static-mcp tools including RE backends (Radare2, IDA, Ghidra),
//! API trace, AI tools, and YARA/pattern tools.
//!
//! # Implementation
//! These tests validate that:
//! - All 80 registry tools are properly registered
//! - Tool schemas are well-formed
//! - RE backend routing works correctly
//! - Input validation is defensive

/// Verify all Radare2 tools are registered with correct schemas
#[test]
fn test_radare2_tools_complete() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let r2_tools = [
        "r2_session",
        "r2_status",
        "r2_info",
        "r2_functions",
        "r2_function",
        "r2_disasm",
        "r2_disasm_function",
        "r2_decompile",
        "r2_strings",
        "r2_imports",
        "r2_exports",
        "r2_xref",
        "r2_read",
        "r2_cmd",
    ];

    for tool_name in r2_tools {
        let tool = registry.get(tool_name);
        assert!(tool.is_some(), "Missing Radare2 tool: {}", tool_name);

        let tool = tool.unwrap();
        assert_eq!(tool.category, "radare2", "Wrong category for {}", tool_name);
        assert!(
            !tool.description.is_empty(),
            "Empty description for {}",
            tool_name
        );
    }

    assert_eq!(
        registry.by_category("radare2").len(),
        14,
        "Radare2 should have exactly 14 tools"
    );
}

/// Verify all IDA Pro tools are registered with correct schemas
#[test]
fn test_ida_tools_complete() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let ida_tools = [
        "ida_session",
        "ida_status",
        "ida_info",
        "ida_functions",
        "ida_function",
        "ida_disasm",
        "ida_decompile",
        "ida_strings",
        "ida_imports",
        "ida_exports",
        "ida_xref",
    ];

    for tool_name in ida_tools {
        let tool = registry.get(tool_name);
        assert!(tool.is_some(), "Missing IDA tool: {}", tool_name);

        let tool = tool.unwrap();
        assert_eq!(tool.category, "ida", "Wrong category for {}", tool_name);
    }

    assert_eq!(
        registry.by_category("ida").len(),
        11,
        "IDA should have exactly 11 tools"
    );
}

/// Verify all Ghidra tools are registered with correct schemas
#[test]
fn test_ghidra_tools_complete() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let ghidra_tools = [
        "ghidra_session",
        "ghidra_status",
        "ghidra_info",
        "ghidra_functions",
        "ghidra_function",
        "ghidra_disasm",
        "ghidra_decompile",
        "ghidra_strings",
        "ghidra_imports",
        "ghidra_exports",
        "ghidra_xref",
    ];

    for tool_name in ghidra_tools {
        let tool = registry.get(tool_name);
        assert!(tool.is_some(), "Missing Ghidra tool: {}", tool_name);

        let tool = tool.unwrap();
        assert_eq!(tool.category, "ghidra", "Wrong category for {}", tool_name);
    }

    assert_eq!(
        registry.by_category("ghidra").len(),
        11,
        "Ghidra should have exactly 11 tools"
    );
}

/// Verify all API trace tools are registered
#[test]
fn test_trace_tools_complete() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let trace_tools = [
        "trace_session_create",
        "trace_control",
        "trace_session_close",
        "trace_session_list",
        "trace_session_info",
        "trace_events",
        "trace_events_clear",
        "trace_stats",
        "trace_queue_stats",
        "trace_filter_set",
        "trace_preset_list",
        "trace_preset_apply",
        "trace_preset_create",
        "trace_preset_delete",
        "trace_pack_list",
        "trace_pack_info",
        "trace_pack_load",
        "trace_pack_unload",
        "trace_hooks_list",
    ];

    for tool_name in trace_tools {
        let tool = registry.get(tool_name);
        assert!(tool.is_some(), "Missing trace tool: {}", tool_name);

        let tool = tool.unwrap();
        assert_eq!(tool.category, "trace", "Wrong category for {}", tool_name);
    }

    assert_eq!(
        registry.by_category("trace").len(),
        19,
        "Trace should have exactly 19 tools"
    );
}

/// Verify all AI tools are registered
#[test]
fn test_ai_tools_complete() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let ai_tools = [
        "ai_summarize",
        "ai_diff",
        "ai_explain_error",
        "ai_recommend_breakpoints",
        "ai_analyze_vulnerability",
        "ai_learn_pattern",
        "ai_patterns_list",
        "debug_session_create",
        "debug_session_info",
        "debug_session_update",
        "debug_session_close",
        "debug_session_list",
    ];

    for tool_name in ai_tools {
        let tool = registry.get(tool_name);
        assert!(tool.is_some(), "Missing AI tool: {}", tool_name);

        let tool = tool.unwrap();
        assert_eq!(tool.category, "ai", "Wrong category for {}", tool_name);
    }

    assert_eq!(
        registry.by_category("ai").len(),
        12,
        "AI should have exactly 12 tools"
    );
}

/// Verify all YARA/Pattern tools are registered
#[test]
fn test_yara_tools_complete() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let yara_tools = [
        "yara_create_rule",
        "yara_load_rules",
        "yara_scan_memory",
        "yara_list_rules",
        "find_instructions",
        "signature_db_create",
        "signature_db_add",
        "signature_db_list",
        "signature_db_scan",
        "signature_db_export",
        "signature_db_import",
        "signature_db_version",
        "signature_auto_generate",
    ];

    for tool_name in yara_tools {
        let tool = registry.get(tool_name);
        assert!(tool.is_some(), "Missing YARA tool: {}", tool_name);

        let tool = tool.unwrap();
        assert_eq!(tool.category, "yara", "Wrong category for {}", tool_name);
    }

    assert_eq!(
        registry.by_category("yara").len(),
        13,
        "YARA should have exactly 13 tools"
    );
}

/// Verify tool schema integrity
#[test]
fn test_tool_schemas_valid() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    for tool in registry.tools() {
        // Tool name should be valid
        assert!(!tool.name.is_empty(), "Tool has empty name");
        assert!(tool.name.len() <= 128, "Tool name too long: {}", tool.name);

        // Description should exist
        assert!(
            !tool.description.is_empty(),
            "Tool {} has empty description",
            tool.name
        );

        // Category should be valid
        assert!(
            !tool.category.is_empty(),
            "Tool {} has empty category",
            tool.name
        );

        // Schema should be object type
        assert_eq!(
            tool.input_schema.schema_type, "object",
            "Tool {} schema type should be 'object'",
            tool.name
        );
    }
}

/// Verify consolidated session tools have action parameter
#[test]
fn test_session_tools_have_action_param() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let session_tools = ["r2_session", "ida_session", "ghidra_session"];

    for tool_name in session_tools {
        let tool = registry
            .get(tool_name)
            .unwrap_or_else(|| panic!("Missing {}", tool_name));

        assert!(
            tool.input_schema.properties.contains_key("action"),
            "{} should have 'action' parameter",
            tool_name
        );

        let action_prop = &tool.input_schema.properties["action"];
        assert!(
            action_prop.enum_values.is_some(),
            "{} action should have enum values",
            tool_name
        );

        let enum_vals = action_prop.enum_values.as_ref().unwrap();
        assert!(
            enum_vals.iter().any(|v| v == "open"),
            "{} should support 'open' action",
            tool_name
        );
        assert!(
            enum_vals.iter().any(|v| v == "close"),
            "{} should support 'close' action",
            tool_name
        );
    }
}

/// Verify consolidated xref tools have direction parameter
#[test]
fn test_xref_tools_have_direction_param() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let xref_tools = ["r2_xref", "ida_xref", "ghidra_xref"];

    for tool_name in xref_tools {
        let tool = registry
            .get(tool_name)
            .unwrap_or_else(|| panic!("Missing {}", tool_name));

        assert!(
            tool.input_schema.properties.contains_key("direction"),
            "{} should have 'direction' parameter",
            tool_name
        );

        assert!(
            tool.input_schema.properties.contains_key("address"),
            "{} should have 'address' parameter",
            tool_name
        );
    }
}

/// Verify trace_control has action parameter with correct values
#[test]
fn test_trace_control_actions() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    let tool = registry
        .get("trace_control")
        .expect("Missing trace_control");

    assert!(
        tool.input_schema.properties.contains_key("action"),
        "trace_control should have 'action' parameter"
    );

    let action_prop = &tool.input_schema.properties["action"];
    assert!(
        action_prop.enum_values.is_some(),
        "trace_control action should have enum values"
    );

    let enum_vals = action_prop.enum_values.as_ref().unwrap();
    let expected_actions = ["start", "stop", "pause", "resume"];

    for action in expected_actions {
        assert!(
            enum_vals.iter().any(|v| v == action),
            "trace_control should support '{}' action",
            action
        );
    }
}

/// Test RE handler routing logic
#[test]
fn test_re_handler_tool_detection() {
    use ghost_static_mcp::handlers::ReHandler;

    // RE tools should be detected
    assert!(ReHandler::is_re_tool("r2_disasm"));
    assert!(ReHandler::is_re_tool("ida_decompile"));
    assert!(ReHandler::is_re_tool("ghidra_functions"));

    // Non-RE tools should not be detected
    assert!(!ReHandler::is_re_tool("trace_events"));
    assert!(!ReHandler::is_re_tool("ai_summarize"));
    assert!(!ReHandler::is_re_tool("yara_scan_memory"));
}

/// Test RE backend detection from tool name
#[test]
fn test_re_backend_detection() {
    use ghost_static_mcp::handlers::ReHandler;

    // This is tested via ReHandler::is_re_tool
    // The internal ReBackend::from_tool_name is tested in re_handler.rs unit tests
    assert!(ReHandler::is_re_tool("r2_cmd"));
    assert!(ReHandler::is_re_tool("ida_status"));
    assert!(ReHandler::is_re_tool("ghidra_info"));
}

/// Verify all categories have correct tool counts per roadmap
#[test]
fn test_category_counts_match_roadmap() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    // Per MCP_MODULARIZATION_ROADMAP.md Appendix A
    let expected = [
        ("radare2", 14),
        ("ida", 11),
        ("ghidra", 11),
        ("trace", 19),
        ("ai", 12),
        ("yara", 13),
    ];

    for (category, expected_count) in expected {
        let actual = registry.by_category(category).len();
        assert_eq!(
            actual, expected_count,
            "Category '{}' has {} tools, expected {}",
            category, actual, expected_count
        );
    }
}

/// Verify total registry count matches expected target
#[test]
fn test_total_registry_count() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create registry");

    assert_eq!(
        registry.len(),
        80,
        "Registry should have exactly 80 tools (excluding 4 shared meta)"
    );

    // With shared meta, total should be 84
    let total_with_meta = registry.len() + 4;
    assert_eq!(
        total_with_meta, 84,
        "Total tools (with shared meta) should be 84"
    );
}
