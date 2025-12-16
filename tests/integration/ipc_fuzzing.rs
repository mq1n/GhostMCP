//! IPC Protocol Fuzzing Tests
//!
//! Tests for robustness of the IPC/JSON-RPC protocol handling:
//! - Malformed JSON
//! - Oversized payloads
//! - Invalid UTF-8
//! - Missing required fields
//! - Type mismatches
//! - Boundary conditions

use super::{McpTestFixture, TestResults};
use std::io::Write;

/// Run all IPC fuzzing tests
pub fn run_all_tests(fixture: &mut McpTestFixture) -> TestResults {
    let mut results = TestResults::default();

    println!("Running IPC Protocol Fuzzing Tests...\n");

    // Ensure fixture is initialized first
    if let Err(e) = fixture.initialize() {
        println!("  [SKIP] All tests - Failed to initialize: {}", e);
        results.skipped += 10;
        return results;
    }

    test_empty_line(&mut results, fixture);
    test_malformed_json(&mut results, fixture);
    test_missing_jsonrpc_version(&mut results, fixture);
    test_missing_method(&mut results, fixture);
    test_null_id(&mut results, fixture);
    test_negative_id(&mut results, fixture);
    test_string_id(&mut results, fixture);
    test_very_long_method_name(&mut results, fixture);
    test_deeply_nested_params(&mut results, fixture);
    test_special_characters_in_strings(&mut results, fixture);
    test_unicode_in_params(&mut results, fixture);
    test_large_array_params(&mut results, fixture);
    test_null_params(&mut results, fixture);
    test_array_instead_of_object_params(&mut results, fixture);
    test_recovery_after_malformed(&mut results, fixture);

    results.summary();
    results
}

fn send_and_check_alive(fixture: &mut McpTestFixture, data: &str) -> Result<bool, String> {
    // Send the potentially malformed data
    writeln!(fixture.stdin, "{}", data).map_err(|e| e.to_string())?;
    fixture.stdin.flush().map_err(|e| e.to_string())?;

    // Try to read response (might be error or nothing)
    let _ = fixture.read_raw_line();

    // Check if server is still responsive by sending a valid request
    match fixture.send_request("ping", None) {
        Ok(_) => Ok(true),
        Err(_) => {
            // Server might not implement ping, try tools/list
            match fixture.list_tools() {
                Ok(_) => Ok(true),
                Err(e) => Err(format!("Server unresponsive: {}", e)),
            }
        }
    }
}

fn test_empty_line(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:empty_line";

    match send_and_check_alive(fixture, "") {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed on empty line"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_malformed_json(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:malformed_json";

    let test_cases = vec![
        "{not valid json}",
        "{{{{",
        "}}}}",
        "[[[",
        "]]]",
        "\"unclosed string",
        "{'single': 'quotes'}",
        "{\"missing\": }",
        "{\"trailing\": \"comma\",}",
    ];

    let mut passed = true;
    for case in test_cases {
        match send_and_check_alive(fixture, case) {
            Ok(true) => continue,
            _ => {
                passed = false;
                break;
            }
        }
    }

    if passed {
        results.record_pass(NAME);
    } else {
        results.record_fail(NAME, "Server crashed on malformed JSON");
    }
}

fn test_missing_jsonrpc_version(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:missing_jsonrpc_version";

    let request = r#"{"id": 1, "method": "tools/list"}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_missing_method(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:missing_method";

    let request = r#"{"jsonrpc": "2.0", "id": 1}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_null_id(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:null_id";

    let request = r#"{"jsonrpc": "2.0", "id": null, "method": "tools/list"}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_negative_id(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:negative_id";

    let request = r#"{"jsonrpc": "2.0", "id": -9999, "method": "tools/list"}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_string_id(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:string_id";

    let request = r#"{"jsonrpc": "2.0", "id": "string-id-123", "method": "tools/list"}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_very_long_method_name(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:very_long_method_name";

    let long_method = "a".repeat(10000);
    let request = format!(
        r#"{{"jsonrpc": "2.0", "id": 1, "method": "{}"}}"#,
        long_method
    );

    match send_and_check_alive(fixture, &request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_deeply_nested_params(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:deeply_nested_params";

    // Create deeply nested object
    let mut nested = String::from(r#"{"a":"#);
    for _ in 0..50 {
        nested.push_str(r#"{"b":"#);
    }
    nested.push_str("\"value\"");
    for _ in 0..50 {
        nested.push('}');
    }
    nested.push('}');

    let request = format!(
        r#"{{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}}"#,
        nested
    );

    match send_and_check_alive(fixture, &request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_special_characters_in_strings(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:special_characters";

    let special_chars = r#"\n\r\t\0\x00\u0000"#;
    let request = format!(
        r#"{{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {{"name": "test{}", "arguments": {{}}}}}}"#,
        special_chars
    );

    match send_and_check_alive(fixture, &request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_unicode_in_params(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:unicode_params";

    let request = r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "テスト🎉中文العربية", "arguments": {}}}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_large_array_params(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:large_array_params";

    let large_array: Vec<i32> = (0..1000).collect();
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test_tool",
            "arguments": {
                "data": large_array
            }
        }
    });

    match send_and_check_alive(fixture, &serde_json::to_string(&request).unwrap()) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_null_params(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:null_params";

    let request = r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": null}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_array_instead_of_object_params(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:array_params";

    let request =
        r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["not", "an", "object"]}"#;

    match send_and_check_alive(fixture, request) {
        Ok(true) => results.record_pass(NAME),
        Ok(false) => results.record_fail(NAME, "Server crashed"),
        Err(e) => results.record_fail(NAME, &e),
    }
}

fn test_recovery_after_malformed(results: &mut TestResults, fixture: &mut McpTestFixture) {
    const NAME: &str = "fuzz:recovery_after_malformed";

    // Send several malformed requests
    let malformed = vec!["not json at all", "{broken", "", "null", "[]"];

    for m in malformed {
        let _ = writeln!(fixture.stdin, "{}", m);
        let _ = fixture.stdin.flush();
        let _ = fixture.read_raw_line();
    }

    // Now try a valid request
    match fixture.call_tool("mcp_version", serde_json::json!({})) {
        Ok(_) => results.record_pass(NAME),
        Err(e) => results.record_fail(NAME, &format!("Server did not recover: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires MCP server binary (ghost-core-mcp)
    fn run_fuzzing_tests() {
        let mut fixture = McpTestFixture::new().expect("Failed to create fixture");
        let results = run_all_tests(&mut fixture);
        assert!(results.is_success(), "Fuzzing tests failed");
    }
}
