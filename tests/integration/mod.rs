//! Ghost-MCP Integration Test Harness
//!
//! Provides infrastructure for running integration tests against MCP servers
//! and ghost-agent. Tests can be run with or without a live agent connection.
//!
//! # Usage
//! ```bash
//! cargo test --test integration
//! ```
//!
//! # Tests
//! - `multi_client`: Multi-client handshake, event fanout, capability gating
//! - `meta_tools`: Meta tools availability on all servers
//! - `tool_count_golden`: Tool count golden snapshots for regression prevention

pub mod ipc_fuzzing;
pub mod mcp_protocol;
pub mod multi_server_integration;
pub mod patch_aware_dump;
pub mod static_tools;

// These modules require additional dependencies and are conditionally compiled
#[cfg(feature = "full_integration_tests")]
pub mod meta_tools;
#[cfg(feature = "full_integration_tests")]
pub mod multi_client;
#[cfg(feature = "full_integration_tests")]
pub mod tool_count_golden;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global request ID counter
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Test fixture for MCP server testing
pub struct McpTestFixture {
    process: Child,
    stdin: std::io::BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    initialized: bool,
}

impl McpTestFixture {
    /// Create a new test fixture by launching MCP server
    pub fn new() -> Result<Self, String> {
        Self::with_binary("ghost-core-mcp")
    }

    /// Create a test fixture with a specific binary path
    pub fn with_binary(binary: &str) -> Result<Self, String> {
        let mut process = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to launch {}: {}", binary, e))?;

        let stdin = process.stdin.take().ok_or("Failed to get stdin")?;
        let stdout = process.stdout.take().ok_or("Failed to get stdout")?;

        Ok(Self {
            process,
            stdin: std::io::BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
            initialized: false,
        })
    }

    /// Initialize the MCP connection
    pub fn initialize(&mut self) -> Result<serde_json::Value, String> {
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": { "listChanged": true }
            },
            "clientInfo": {
                "name": "ghost-mcp-test",
                "version": "0.1.0"
            }
        });

        let response = self.send_request("initialize", Some(params))?;

        // Send initialized notification
        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialized"
        });
        writeln!(self.stdin, "{}", serde_json::to_string(&notif).unwrap())
            .map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;

        self.initialized = true;
        Ok(response)
    }

    /// Send a JSON-RPC request and receive response
    pub fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let id = REQUEST_ID.fetch_add(1, Ordering::SeqCst);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });

        let request_str = serde_json::to_string(&request).map_err(|e| e.to_string())?;

        writeln!(self.stdin, "{}", request_str).map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;

        // Read response
        let mut response_str = String::new();
        self.stdout
            .read_line(&mut response_str)
            .map_err(|e| e.to_string())?;

        let response: serde_json::Value =
            serde_json::from_str(&response_str).map_err(|e| e.to_string())?;

        // Check for error
        if let Some(error) = response.get("error") {
            return Err(format!("JSON-RPC error: {}", error));
        }

        response
            .get("result")
            .cloned()
            .ok_or_else(|| "No result in response".to_string())
    }

    /// Send raw bytes (for fuzzing)
    #[allow(dead_code)]
    pub fn send_raw(&mut self, data: &[u8]) -> Result<(), String> {
        self.stdin.write_all(data).map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())
    }

    /// Read raw line (for fuzzing)
    pub fn read_raw_line(&mut self) -> Result<String, String> {
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        Ok(line)
    }

    /// Call a tool
    pub fn call_tool(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        if !self.initialized {
            self.initialize()?;
        }

        let params = serde_json::json!({
            "name": name,
            "arguments": arguments
        });

        self.send_request("tools/call", Some(params))
    }

    /// List tools
    pub fn list_tools(&mut self) -> Result<serde_json::Value, String> {
        if !self.initialized {
            self.initialize()?;
        }
        self.send_request("tools/list", None)
    }

    /// Check if process is still running
    #[allow(dead_code)]
    pub fn is_running(&mut self) -> bool {
        matches!(self.process.try_wait(), Ok(None))
    }
}

impl Drop for McpTestFixture {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Test result tracking
#[derive(Default)]
pub struct TestResults {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

impl TestResults {
    pub fn record_pass(&mut self, name: &str) {
        self.passed += 1;
        println!("  [PASS] {}", name);
    }

    pub fn record_fail(&mut self, name: &str, reason: &str) {
        self.failed += 1;
        self.errors.push(format!("{}: {}", name, reason));
        println!("  [FAIL] {} - {}", name, reason);
    }

    #[allow(dead_code)]
    pub fn record_skip(&mut self, name: &str, reason: &str) {
        self.skipped += 1;
        println!("  [SKIP] {} - {}", name, reason);
    }

    pub fn summary(&self) {
        println!();
        println!(
            "Test Results: {} passed, {} failed, {} skipped",
            self.passed, self.failed, self.skipped
        );

        if !self.errors.is_empty() {
            println!();
            println!("Failures:");
            for error in &self.errors {
                println!("  - {}", error);
            }
        }
    }

    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
}

/// Helper macro for running a test
#[macro_export]
macro_rules! run_test {
    ($results:expr, $name:expr, $fixture:expr, $test:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $test)) {
            Ok(Ok(())) => $results.record_pass($name),
            Ok(Err(e)) => $results.record_fail($name, &e),
            Err(_) => $results.record_fail($name, "panic"),
        }
    };
}
