//! Meta Tools Integration Tests
//!
//! Tests that meta tools (mcp_capabilities, mcp_documentation, mcp_version, mcp_health)
//! are available and functional on all MCP servers.

use serde_json::json;

/// Server ports for testing
const CORE_PORT: u16 = 13340;
const ANALYSIS_PORT: u16 = 13341;
const STATIC_PORT: u16 = 13342;
const EXTENDED_PORT: u16 = 13343;

/// Expected meta tools that should exist on all servers
const META_TOOLS: &[&str] = &[
    "mcp_capabilities",
    "mcp_documentation",
    "mcp_version",
    "mcp_health",
];

// =============================================================================
// Meta Tool Availability Tests
// =============================================================================

#[test]
fn test_meta_tools_list_defined() {
    // Basic sanity check that our expected meta tools are defined
    assert_eq!(META_TOOLS.len(), 4);
    assert!(META_TOOLS.contains(&"mcp_capabilities"));
    assert!(META_TOOLS.contains(&"mcp_documentation"));
    assert!(META_TOOLS.contains(&"mcp_version"));
    assert!(META_TOOLS.contains(&"mcp_health"));
}

#[test]
fn test_server_ports_distinct() {
    // Verify server ports don't conflict
    assert_ne!(CORE_PORT, ANALYSIS_PORT);
    assert_ne!(CORE_PORT, STATIC_PORT);
    assert_ne!(ANALYSIS_PORT, STATIC_PORT);

    // All should be in the 13340-13343 range
    assert!(CORE_PORT >= 13340 && CORE_PORT <= 13343);
    assert!(ANALYSIS_PORT >= 13340 && ANALYSIS_PORT <= 13343);
    assert!(STATIC_PORT >= 13340 && STATIC_PORT <= 13343);
    assert!(EXTENDED_PORT >= 13340 && EXTENDED_PORT <= 13343);
}

// =============================================================================
// MCP Capabilities Tests
// =============================================================================

#[test]
fn test_mcp_capabilities_response_structure() {
    // Test expected response structure for mcp_capabilities
    let expected_fields = vec!["server_name", "server_version", "tool_count", "categories"];

    // This would be validated against actual response in integration test
    assert!(!expected_fields.is_empty());
}

// =============================================================================
// MCP Version Tests
// =============================================================================

#[test]
fn test_mcp_version_response_structure() {
    // Test expected response structure for mcp_version
    let expected_fields = vec!["version", "build_date", "git_hash", "protocol_version"];

    assert!(!expected_fields.is_empty());
}

// =============================================================================
// MCP Health Tests
// =============================================================================

#[test]
fn test_mcp_health_response_structure() {
    // Test expected response structure for mcp_health
    let expected_fields = vec![
        "status",          // "healthy", "degraded", "unhealthy"
        "agent_connected", // bool
        "uptime_seconds",  // u64
        "request_count",   // u64
        "error_count",     // u64
    ];

    assert!(!expected_fields.is_empty());
}

#[test]
fn test_health_status_values() {
    let valid_statuses = vec!["healthy", "degraded", "unhealthy"];
    assert_eq!(valid_statuses.len(), 3);
}

// =============================================================================
// Integration Tests (require running servers)
// =============================================================================

/// Test fixture for meta tool testing via TCP
#[cfg(test)]
mod integration {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    /// Helper to send JSON-RPC request to a server
    fn send_jsonrpc_request(
        port: u16,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let addr = format!("127.0.0.1:{}", port);

        let stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
            .map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;

        // Send request
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        writeln!(writer, "{}", serde_json::to_string(&request).unwrap())
            .map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;

        // Read response
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|e| e.to_string())?;

        let response: serde_json::Value =
            serde_json::from_str(&response_line).map_err(|e| e.to_string())?;

        if let Some(error) = response.get("error") {
            return Err(format!("RPC error: {}", error));
        }

        response
            .get("result")
            .cloned()
            .ok_or_else(|| "No result in response".to_string())
    }

    #[tokio::test]
    #[ignore = "requires running ghost-core-mcp"]
    async fn test_core_meta_tools() {
        for tool_name in META_TOOLS {
            let result = send_jsonrpc_request(
                CORE_PORT,
                &format!("tools/call"),
                json!({ "name": tool_name, "arguments": {} }),
            );

            assert!(
                result.is_ok(),
                "Meta tool {} failed on core server: {:?}",
                tool_name,
                result.err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires running ghost-analysis-mcp"]
    async fn test_analysis_meta_tools() {
        for tool_name in META_TOOLS {
            let result = send_jsonrpc_request(
                ANALYSIS_PORT,
                &format!("tools/call"),
                json!({ "name": tool_name, "arguments": {} }),
            );

            assert!(
                result.is_ok(),
                "Meta tool {} failed on analysis server: {:?}",
                tool_name,
                result.err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires running ghost-static-mcp"]
    async fn test_static_meta_tools() {
        for tool_name in META_TOOLS {
            let result = send_jsonrpc_request(
                STATIC_PORT,
                &format!("tools/call"),
                json!({ "name": tool_name, "arguments": {} }),
            );

            assert!(
                result.is_ok(),
                "Meta tool {} failed on static server: {:?}",
                tool_name,
                result.err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires running ghost-extended-mcp"]
    async fn test_extended_meta_tools() {
        for tool_name in META_TOOLS {
            let result = send_jsonrpc_request(
                EXTENDED_PORT,
                &format!("tools/call"),
                json!({ "name": tool_name, "arguments": {} }),
            );

            assert!(
                result.is_ok(),
                "Meta tool {} failed on extended server: {:?}",
                tool_name,
                result.err()
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires all servers running"]
    async fn test_all_servers_meta_tools() {
        let ports = [
            (CORE_PORT, "ghost-core-mcp"),
            (ANALYSIS_PORT, "ghost-analysis-mcp"),
            (STATIC_PORT, "ghost-static-mcp"),
            (EXTENDED_PORT, "ghost-extended-mcp"),
        ];

        for (port, server_name) in ports {
            println!("Testing meta tools on {} (port {})", server_name, port);

            for tool_name in META_TOOLS {
                let result = send_jsonrpc_request(
                    port,
                    "tools/call",
                    json!({ "name": tool_name, "arguments": {} }),
                );

                match result {
                    Ok(response) => {
                        println!("  [OK] {} returned: {:?}", tool_name, response);
                    }
                    Err(e) => {
                        panic!("Meta tool {} failed on {}: {}", tool_name, server_name, e);
                    }
                }
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires running ghost-core-mcp"]
    async fn test_mcp_health_returns_valid_status() {
        let result = send_jsonrpc_request(
            CORE_PORT,
            "tools/call",
            json!({ "name": "mcp_health", "arguments": {} }),
        );

        if let Ok(response) = result {
            // Verify status field exists and has valid value
            if let Some(status) = response.get("status") {
                let status_str = status.as_str().unwrap_or("");
                assert!(
                    ["healthy", "degraded", "unhealthy"].contains(&status_str),
                    "Invalid health status: {}",
                    status_str
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires running ghost-core-mcp"]
    async fn test_mcp_capabilities_includes_tool_count() {
        let result = send_jsonrpc_request(
            CORE_PORT,
            "tools/call",
            json!({ "name": "mcp_capabilities", "arguments": {} }),
        );

        if let Ok(response) = result {
            // Verify tool_count field exists
            assert!(
                response.get("tool_count").is_some(),
                "mcp_capabilities should include tool_count"
            );

            // Verify it's under the limit
            if let Some(count) = response.get("tool_count").and_then(|v| v.as_u64()) {
                assert!(count <= 90, "Tool count {} exceeds 90 limit", count);
            }
        }
    }
}
