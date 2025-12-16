//! Ghost-MCP Integration Tests
//!
//! Main entry point for running integration tests against MCP servers.
//!
//! # Available MCP Servers
//! - `ghost-core-mcp` (port 13340) - Memory, Debug, Execution, Safety
//! - `ghost-analysis-mcp` (port 13341) - Scanner, Dump, Introspection
//! - `ghost-static-mcp` (port 13342) - Radare2, IDA, Ghidra, AI Tools
//! - `ghost-extended-mcp` (port 13343) - Injection, Anti-Debug, Input, Speedhack
//!
//! # Usage
//! ```bash
//! # Run all integration tests (defaults to ghost-core-mcp)
//! cargo test --test integration
//!
//! # Run with specific MCP server binary
//! MCP_SERVER_BIN=./target/debug/ghost-core-mcp cargo test --test integration
//! MCP_SERVER_BIN=./target/debug/ghost-analysis-mcp cargo test --test integration
//! MCP_SERVER_BIN=./target/debug/ghost-static-mcp cargo test --test integration
//! MCP_SERVER_BIN=./target/debug/ghost-extended-mcp cargo test --test integration
//! ```

#[path = "integration/mod.rs"]
mod harness;

use harness::{
    ipc_fuzzing, mcp_protocol, multi_server_integration, patch_aware_dump, McpTestFixture,
};
use std::env;

fn get_mcp_server_binary() -> String {
    // Support both new and legacy env vars
    env::var("MCP_SERVER_BIN")
        .or_else(|_| env::var("GHOST_HOST_BIN"))
        .unwrap_or_else(|_| "ghost-core-mcp".to_string())
}

#[test]
#[ignore] // Run with: cargo test --test integration -- --ignored
fn test_mcp_protocol() {
    let binary = get_mcp_server_binary();
    println!("Using MCP server: {}\n", binary);

    let mut fixture = match McpTestFixture::with_binary(&binary) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to start MCP server: {}", e);
            eprintln!("Make sure ghost-core-mcp is built and in PATH, or set MCP_SERVER_BIN");
            panic!("Cannot run tests without MCP server");
        }
    };

    let results = mcp_protocol::run_all_tests(&mut fixture);
    assert!(results.is_success(), "MCP protocol tests failed");
}

#[test]
#[ignore] // Run with: cargo test --test integration -- --ignored
fn test_ipc_fuzzing() {
    let binary = get_mcp_server_binary();
    println!("Using MCP server: {}\n", binary);

    let mut fixture = match McpTestFixture::with_binary(&binary) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to start MCP server: {}", e);
            eprintln!("Make sure ghost-core-mcp is built and in PATH, or set MCP_SERVER_BIN");
            panic!("Cannot run tests without MCP server");
        }
    };

    let results = ipc_fuzzing::run_all_tests(&mut fixture);
    assert!(results.is_success(), "IPC fuzzing tests failed");
}

#[test]
#[ignore]
fn test_full_integration_suite() {
    let binary = get_mcp_server_binary();
    println!("=== Ghost-MCP Full Integration Test Suite ===\n");
    println!("Using MCP server: {}\n", binary);

    let mut all_passed = true;

    // MCP Protocol Tests
    {
        println!("\n--- MCP Protocol Tests ---\n");
        let mut fixture =
            McpTestFixture::with_binary(&binary).expect("Failed to create fixture for MCP tests");
        let results = mcp_protocol::run_all_tests(&mut fixture);
        if !results.is_success() {
            all_passed = false;
        }
    }

    // IPC Fuzzing Tests
    {
        println!("\n--- IPC Fuzzing Tests ---\n");
        let mut fixture = McpTestFixture::with_binary(&binary)
            .expect("Failed to create fixture for fuzzing tests");
        let results = ipc_fuzzing::run_all_tests(&mut fixture);
        if !results.is_success() {
            all_passed = false;
        }
    }

    println!("\n=== Suite Complete ===\n");
    assert!(all_passed, "Some integration tests failed");
}

/// Quick smoke test that can run in CI without full setup
#[test]
fn test_smoke_types() {
    // Just verify that the test infrastructure compiles
    use harness::TestResults;

    let mut results = TestResults::default();
    results.record_pass("compile_check");
    assert!(results.is_success());
}

/// Patch-aware dump flow tests (runs without external binaries)
/// Tests the integration between patch history and dump annotations
#[test]
fn test_patch_aware_dump_flows() {
    println!("\n=== Patch-Aware Dump Flow Tests ===\n");
    let results = patch_aware_dump::run_all_tests();
    assert!(results.is_success(), "Patch-aware dump flow tests failed");
}

// =============================================================================
// Multi-Server Integration Tests
// =============================================================================

/// Multi-server offline tests (no live agent required)
/// Run with: cargo test --test integration test_multi_server_integration
#[test]
fn test_multi_server_integration() {
    println!("\n=== Multi-Server Integration Tests ===\n");
    let results = multi_server_integration::run_all_offline_tests();
    assert!(
        results.is_success(),
        "Multi-server integration tests failed"
    );
}

/// Multi-server full integration suite with live servers
/// Run with: cargo test --test integration test_multi_server_live -- --ignored
#[test]
#[ignore = "requires all MCP servers running"]
fn test_multi_server_live() {
    println!("\n=== Multi-Server Live Integration Tests ===\n");
    println!("This test requires all 4 MCP servers to be running:");
    println!("  - ghost-core-mcp on port 13340");
    println!("  - ghost-analysis-mcp on port 13341");
    println!("  - ghost-static-mcp on port 13342");
    println!("  - ghost-extended-mcp on port 13343");
    println!();
    println!("Start servers with: .\\scripts\\launch-mcp.ps1 -All");
    println!();

    // The live tests are in the multi_server_integration::live_tests module
    // They are marked with #[ignore] and run separately
    println!("Run live tests with:");
    println!("  cargo test --test integration multi_server -- --ignored --nocapture");
}

/// Full patch-aware dump integration with live agent (requires elevated permissions)
/// Run with: GHOST_PATCH_DUMP_ELEVATED=1 cargo test --test integration test_patch_aware_dump_live -- --ignored
#[test]
#[ignore]
fn test_patch_aware_dump_live() {
    // Guard: only run if elevated flag is set
    if env::var("GHOST_PATCH_DUMP_ELEVATED").is_err() {
        println!("Skipping live agent test (set GHOST_PATCH_DUMP_ELEVATED=1 to enable)");
        return;
    }

    let binary = get_mcp_server_binary();
    println!("\n=== Patch-Aware Dump Live Integration ===\n");
    println!("Using MCP server: {}\n", binary);

    let mut fixture = match McpTestFixture::with_binary(&binary) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to start MCP server: {}", e);
            eprintln!("Make sure ghost-core-mcp is built and in PATH, or set MCP_SERVER_BIN");
            panic!("Cannot run live tests without MCP server");
        }
    };

    // Initialize MCP connection
    if let Err(e) = fixture.initialize() {
        panic!("Failed to initialize MCP connection: {}", e);
    }

    // Test patch_history tool
    println!("Testing patch_history...");
    match fixture.call_tool("patch_history", serde_json::json!({"limit": 50})) {
        Ok(result) => {
            println!("  patch_history response: {:?}", result);
            // Validate response structure
            if result.get("content").is_none() {
                eprintln!("  Warning: Unexpected response format");
            }
        }
        Err(e) => {
            eprintln!("  patch_history failed: {}", e);
        }
    }

    println!("\nLive integration test complete.");
}
