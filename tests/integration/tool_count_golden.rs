//! Tool Count Golden Snapshot Tests
//!
//! Validates that each server maintains its expected tool count and stays under the 90 tool limit.
//! These tests serve as regression guards against accidental tool count changes.

/// Maximum tools allowed per server (MCP client limitation)
pub const MAX_TOOLS_PER_SERVER: usize = 90;

/// Expected tool counts per server (golden snapshots)
/// Update these when intentionally adding/removing tools
///
/// Note: These counts are for the tools registered via create_registry(),
/// which EXCLUDES the 4 shared meta tools (mcp_capabilities, mcp_documentation,
/// mcp_version, mcp_health) that McpServer adds automatically.
/// The full server count = registry count + 4 shared meta tools.
pub mod expected_counts {
    /// ghost-core-mcp registry tool count (excludes 4 shared meta)
    /// Categories: Memory(5) + Module(5) + Debug(11) + Session(7) + Script(11) +
    ///             Execution(15) + Safety(10) + Command(7) + Disasm(5) + Xrefs(1) + CoreMeta(4) = 81
    pub const CORE_REGISTRY: usize = 81;

    /// ghost-core-mcp full count (with shared meta)
    pub const CORE: usize = 85;

    /// ghost-analysis-mcp registry tool count (excludes 4 shared meta)
    /// Categories: Scanner(11) + Pointer(13) + Watch(10) + Dump(13) + Structure(11) + Introspect(20) = 78
    pub const ANALYSIS_REGISTRY: usize = 78;

    /// ghost-analysis-mcp full count (with shared meta)
    pub const ANALYSIS: usize = 82;

    /// ghost-static-mcp registry tool count (excludes 4 shared meta)
    /// Categories: Radare2(14) + IDA(11) + Ghidra(11) + Trace(19) + AI(12) + YARA(13) = 80
    pub const STATIC_REGISTRY: usize = 80;

    /// ghost-static-mcp full count (with shared meta)
    pub const STATIC: usize = 84;

    /// ghost-extended-mcp registry tool count (excludes 4 shared meta)
    /// Categories: Injection(22) + AntiDebug(16) + Input(18) + AddressList(14) + Memory(8) + Speedhack(3) = 81
    pub const EXTENDED_REGISTRY: usize = 81;

    /// ghost-extended-mcp full count (with shared meta)
    pub const EXTENDED: usize = 85;

    /// Shared meta tools (added by McpServer, not in create_registry)
    pub const META_TOOLS: usize = 4;
}

// =============================================================================
// Golden Snapshot Validation Tests
// =============================================================================

#[test]
fn test_expected_counts_under_limit() {
    assert!(
        expected_counts::CORE <= MAX_TOOLS_PER_SERVER,
        "Core expected count {} exceeds limit {}",
        expected_counts::CORE,
        MAX_TOOLS_PER_SERVER
    );

    assert!(
        expected_counts::ANALYSIS <= MAX_TOOLS_PER_SERVER,
        "Analysis expected count {} exceeds limit {}",
        expected_counts::ANALYSIS,
        MAX_TOOLS_PER_SERVER
    );

    assert!(
        expected_counts::STATIC <= MAX_TOOLS_PER_SERVER,
        "Static expected count {} exceeds limit {}",
        expected_counts::STATIC,
        MAX_TOOLS_PER_SERVER
    );

    assert!(
        expected_counts::EXTENDED <= MAX_TOOLS_PER_SERVER,
        "Extended expected count {} exceeds limit {}",
        expected_counts::EXTENDED,
        MAX_TOOLS_PER_SERVER
    );
}

#[test]
fn test_meta_tools_included_in_counts() {
    // Each server count should include the 4 shared meta tools
    assert!(
        expected_counts::CORE >= expected_counts::META_TOOLS,
        "Core count should include meta tools"
    );
    assert!(
        expected_counts::ANALYSIS >= expected_counts::META_TOOLS,
        "Analysis count should include meta tools"
    );
    assert!(
        expected_counts::STATIC >= expected_counts::META_TOOLS,
        "Static count should include meta tools"
    );
    assert!(
        expected_counts::EXTENDED >= expected_counts::META_TOOLS,
        "Extended count should include meta tools"
    );
}

#[test]
fn test_total_tools_reasonable() {
    // Total across all servers based on registry counts (shared meta counted once)
    let registry_total = expected_counts::CORE_REGISTRY
        + expected_counts::ANALYSIS_REGISTRY
        + expected_counts::STATIC_REGISTRY
        + expected_counts::EXTENDED_REGISTRY;
    let total_unique = registry_total + expected_counts::META_TOOLS;

    // Expected around 324 based on registry + shared meta (81+78+80+81+4=324)
    let expected_total = total_unique;

    assert!(
        total_unique >= 310 && total_unique <= 340,
        "Total unique tools {} should be around {}",
        total_unique,
        expected_total
    );

    println!(
        "Total unique tools across all servers (registry + shared meta once): {}",
        total_unique
    );
}

// =============================================================================
// Server-Specific Count Tests (require server crates)
// =============================================================================

/// Validate core server tool count matches golden snapshot
#[test]
fn test_core_tool_count_snapshot() {
    let registry = ghost_core_mcp::create_registry().expect("Failed to create core registry");

    assert_eq!(
        registry.len(),
        expected_counts::CORE_REGISTRY,
        "Core tool count changed! Expected {}, got {}. Update golden snapshot if intentional.",
        expected_counts::CORE_REGISTRY,
        registry.len()
    );
}

/// Validate analysis server tool count matches golden snapshot
#[test]
fn test_analysis_tool_count_snapshot() {
    let registry =
        ghost_analysis_mcp::create_registry().expect("Failed to create analysis registry");

    assert_eq!(
        registry.len(),
        expected_counts::ANALYSIS_REGISTRY,
        "Analysis tool count changed! Expected {}, got {}. Update golden snapshot if intentional.",
        expected_counts::ANALYSIS_REGISTRY,
        registry.len()
    );
}

/// Validate static server tool count matches golden snapshot
#[test]
fn test_static_tool_count_snapshot() {
    let registry = ghost_static_mcp::create_registry().expect("Failed to create static registry");

    assert_eq!(
        registry.len(),
        expected_counts::STATIC_REGISTRY,
        "Static tool count changed! Expected {}, got {}. Update golden snapshot if intentional.",
        expected_counts::STATIC_REGISTRY,
        registry.len()
    );
}

/// Validate extended server tool count matches golden snapshot
#[test]
fn test_extended_tool_count_snapshot() {
    let registry =
        ghost_extended_mcp::create_registry().expect("Failed to create extended registry");

    assert_eq!(
        registry.len(),
        expected_counts::EXTENDED_REGISTRY,
        "Extended tool count changed! Expected {}, got {}. Update golden snapshot if intentional.",
        expected_counts::EXTENDED_REGISTRY,
        registry.len()
    );
}

/// Validate all servers stay under the 90 tool limit
#[test]
fn test_all_servers_under_limit() {
    let registries = [
        ("ghost-core-mcp", ghost_core_mcp::create_registry()),
        ("ghost-analysis-mcp", ghost_analysis_mcp::create_registry()),
        ("ghost-static-mcp", ghost_static_mcp::create_registry()),
        ("ghost-extended-mcp", ghost_extended_mcp::create_registry()),
    ];

    for (name, result) in registries {
        let registry = result.expect(&format!("Failed to create {} registry", name));
        assert!(
            registry.len() <= MAX_TOOLS_PER_SERVER,
            "{} has {} tools, exceeds limit of {}!",
            name,
            registry.len(),
            MAX_TOOLS_PER_SERVER
        );
        println!(
            "{}: {} tools (limit: {})",
            name,
            registry.len(),
            MAX_TOOLS_PER_SERVER
        );
    }
}

// =============================================================================
// Registry Validation Tests (using ghost-mcp-common)
// =============================================================================

#[test]
fn test_registry_max_tools_constant() {
    // Verify the constant is correctly set
    assert_eq!(
        ghost_mcp_common::MAX_TOOLS_PER_SERVER,
        MAX_TOOLS_PER_SERVER,
        "MAX_TOOLS_PER_SERVER mismatch between test and library"
    );
}

#[test]
fn test_registry_enforces_limit() {
    use ghost_mcp_common::registry::{ToolDefinition, ToolRegistry};

    // Create a registry with a small limit for testing
    let mut registry = ToolRegistry::with_max_tools(3);

    // Add tools up to the limit
    for i in 0..3 {
        let tool = ToolDefinition::new(format!("test_tool_{}", i), "Test description", "test");
        registry
            .register(tool)
            .expect("Should register successfully");
    }

    // Adding one more should fail
    let overflow_tool = ToolDefinition::new("overflow", "desc", "test");
    let result = registry.register(overflow_tool);

    assert!(result.is_err(), "Registry should reject tools beyond limit");
}

#[test]
fn test_registry_duplicate_detection() {
    use ghost_mcp_common::registry::{ToolDefinition, ToolRegistry};

    let mut registry = ToolRegistry::new();

    let tool1 = ToolDefinition::new("duplicate_test", "First", "test");
    let tool2 = ToolDefinition::new("duplicate_test", "Second", "test");

    registry
        .register(tool1)
        .expect("First registration should succeed");

    let result = registry.register(tool2);
    assert!(
        result.is_err(),
        "Registry should reject duplicate tool names"
    );
}

#[test]
fn test_registry_category_tracking() {
    use ghost_mcp_common::registry::{ToolDefinition, ToolRegistry};

    let mut registry = ToolRegistry::new();

    registry
        .register(ToolDefinition::new("mem_read", "Read", "memory"))
        .unwrap();
    registry
        .register(ToolDefinition::new("mem_write", "Write", "memory"))
        .unwrap();
    registry
        .register(ToolDefinition::new("mod_list", "List", "module"))
        .unwrap();

    let memory_tools = registry.by_category("memory");
    assert_eq!(memory_tools.len(), 2);

    let categories = registry.categories();
    assert!(categories.contains(&"memory"));
    assert!(categories.contains(&"module"));
}

// =============================================================================
// CLI Validation Flag Tests
// =============================================================================

/// Test structure for --validate-registry CLI flag
#[test]
fn test_validate_registry_flag_concept() {
    // The --validate-registry flag should:
    // 1. Create the server's registry
    // 2. Call registry.validate()
    // 3. Print tool count summary
    // 4. Exit with code 0 if valid, 1 if invalid

    // This test just verifies the concept compiles
    use ghost_mcp_common::registry::ToolRegistry;

    let registry = ToolRegistry::new();
    let validation_result = registry.validate();

    assert!(validation_result.is_ok(), "Empty registry should validate");

    let summary = registry.summary();
    assert!(!summary.is_empty(), "Summary should be non-empty");
}

// =============================================================================
// Golden Snapshot Update Helper
// =============================================================================

/// Prints current tool counts for updating golden snapshots
/// Run with: cargo test print_current_counts -- --nocapture --ignored
#[test]
#[ignore = "helper test for updating golden snapshots"]
fn print_current_counts() {
    println!("\n=== Current Tool Count Golden Snapshots ===\n");
    println!("Update expected_counts in tool_count_golden.rs if these are intentional changes:\n");

    #[cfg(feature = "ghost-core-mcp")]
    {
        if let Ok(registry) = ghost_core_mcp::create_registry() {
            println!("pub const CORE: usize = {};", registry.len());
        }
    }

    #[cfg(feature = "ghost-analysis-mcp")]
    {
        if let Ok(registry) = ghost_analysis_mcp::create_registry() {
            println!("pub const ANALYSIS: usize = {};", registry.len());
        }
    }

    #[cfg(feature = "ghost-static-mcp")]
    {
        if let Ok(registry) = ghost_static_mcp::create_registry() {
            println!("pub const STATIC: usize = {};", registry.len());
        }
    }

    #[cfg(feature = "ghost-extended-mcp")]
    {
        if let Ok(registry) = ghost_extended_mcp::create_registry() {
            println!("pub const EXTENDED: usize = {};", registry.len());
        }
    }

    println!("\n===========================================\n");
}
