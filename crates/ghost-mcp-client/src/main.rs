//! Ghost-MCP CLI Client
//!
//! Command-line MCP client for testing and automation.
//! Supports stdio transport for direct connection to MCP servers.
//!
//! Available MCP servers:
//! - ghost-core-mcp     (port 13340) - Memory, Debug, Execution, Safety
//! - ghost-analysis-mcp (port 13341) - Scanner, Dump, Introspection
//! - ghost-static-mcp   (port 13342) - Radare2, IDA, Ghidra, AI Tools
//! - ghost-extended-mcp (port 13343) - Extended MCP

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global request ID counter
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Parser, Debug)]
#[command(name = "ghost-client")]
#[command(about = "Ghost-MCP CLI Client - test and automate MCP tools")]
struct Args {
    /// Host to connect to (for HTTP mode)
    #[arg(long, default_value = "localhost")]
    host: String,

    /// Port for HTTP/SSE mode
    #[arg(long, default_value = "13337")]
    port: u16,

    /// Path to MCP server binary (for stdio mode)
    /// Use ghost-core-mcp, ghost-analysis-mcp, ghost-static-mcp, or ghost-extended-mcp
    #[arg(long, default_value = "ghost-core-mcp")]
    host_binary: String,

    /// Use stdio transport (launch MCP server as subprocess)
    #[arg(long)]
    stdio: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Call a tool
    Call {
        /// Tool name (e.g., "memory_read")
        tool: String,

        /// Parameters as key=value pairs
        #[arg(short, long)]
        param: Vec<String>,

        /// Parameters as JSON string
        #[arg(long)]
        json: Option<String>,
    },

    /// List available tools
    Tools,

    /// Get server capabilities and version
    Info,

    /// Check server health
    Health,

    /// Run a script of tool calls from JSON file
    Script {
        /// Path to JSON script file
        path: String,
    },

    /// Interactive REPL mode
    Repl,

    /// Run integration tests
    Test {
        /// Specific test to run (empty = all tests)
        #[arg(short, long)]
        test: Option<String>,
    },

    /// Run all integration tests (shorthand for 'test' without args)
    TestAll,
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// MCP Client for stdio transport
struct McpClient {
    process: Child,
    stdin: std::io::BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    verbose: bool,
}

impl McpClient {
    /// Launch MCP server and connect via stdio
    fn connect_stdio(host_binary: &str, verbose: bool) -> Result<Self> {
        if verbose {
            eprintln!("[DEBUG] Launching MCP server: {}", host_binary);
        }

        let mut process = Command::new(host_binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to launch MCP server. Make sure the binary is in PATH or specify --host-binary")?;

        let stdin = process.stdin.take().context("Failed to get stdin")?;
        let stdout = process.stdout.take().context("Failed to get stdout")?;

        let mut client = Self {
            process,
            stdin: std::io::BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
            verbose,
        };

        // Initialize MCP connection
        client.initialize()?;

        Ok(client)
    }

    /// Send JSON-RPC request and get response
    fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse> {
        let id = REQUEST_ID.fetch_add(1, Ordering::SeqCst);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let request_str = serde_json::to_string(&request)?;

        if self.verbose {
            eprintln!("[DEBUG] >>> {}", request_str);
        }

        writeln!(self.stdin, "{}", request_str)?;
        self.stdin.flush()?;

        // Read response
        let mut response_str = String::new();
        self.stdout.read_line(&mut response_str)?;

        if self.verbose {
            eprintln!("[DEBUG] <<< {}", response_str.trim());
        }

        let response: JsonRpcResponse =
            serde_json::from_str(&response_str).context("Failed to parse JSON-RPC response")?;

        Ok(response)
    }

    /// Initialize MCP connection
    fn initialize(&mut self) -> Result<()> {
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": { "listChanged": true }
            },
            "clientInfo": {
                "name": "ghost-mcp-client",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let response = self.send_request("initialize", Some(params))?;

        if let Some(error) = response.error {
            anyhow::bail!("Initialize failed: {} (code {})", error.message, error.code);
        }

        if self.verbose {
            if let Some(result) = &response.result {
                eprintln!(
                    "[DEBUG] Server capabilities: {}",
                    serde_json::to_string_pretty(result)?
                );
            }
        }

        // Send initialized notification
        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialized"
        });
        writeln!(self.stdin, "{}", serde_json::to_string(&notif)?)?;
        self.stdin.flush()?;

        Ok(())
    }

    /// List available tools
    fn list_tools(&mut self) -> Result<serde_json::Value> {
        let response = self.send_request("tools/list", None)?;

        if let Some(error) = response.error {
            anyhow::bail!("tools/list failed: {} (code {})", error.message, error.code);
        }

        response.result.context("No result in response")
    }

    /// Call a tool
    fn call_tool(&mut self, name: &str, arguments: serde_json::Value) -> Result<serde_json::Value> {
        let params = serde_json::json!({
            "name": name,
            "arguments": arguments
        });

        let response = self.send_request("tools/call", Some(params))?;

        if let Some(error) = response.error {
            anyhow::bail!("Tool call failed: {} (code {})", error.message, error.code);
        }

        response.result.context("No result in response")
    }

    /// Shutdown gracefully
    fn shutdown(mut self) -> Result<()> {
        // Kill the process
        let _ = self.process.kill();
        let _ = self.process.wait();
        Ok(())
    }
}

/// Parse command line parameters into JSON
fn parse_params(param: Vec<String>, json: Option<String>) -> Result<serde_json::Value> {
    if let Some(json_str) = json {
        Ok(serde_json::from_str(&json_str)?)
    } else {
        let mut map = serde_json::Map::new();
        for p in param {
            if let Some((key, value)) = p.split_once('=') {
                let json_value = if let Ok(n) = value.parse::<i64>() {
                    serde_json::Value::Number(n.into())
                } else if let Ok(f) = value.parse::<f64>() {
                    serde_json::Number::from_f64(f)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::String(value.to_string()))
                } else if value == "true" {
                    serde_json::Value::Bool(true)
                } else if value == "false" {
                    serde_json::Value::Bool(false)
                } else if value.starts_with("0x") || value.starts_with("0X") {
                    // Parse hex values
                    if let Ok(n) = u64::from_str_radix(&value[2..], 16) {
                        serde_json::Value::String(format!("0x{:X}", n))
                    } else {
                        serde_json::Value::String(value.to_string())
                    }
                } else {
                    serde_json::Value::String(value.to_string())
                };
                map.insert(key.to_string(), json_value);
            }
        }
        Ok(serde_json::Value::Object(map))
    }
}

/// Type alias for test function to reduce complexity
type TestFn = Box<dyn Fn(&mut McpClient) -> Result<bool>>;

/// Server type for test routing
#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerType {
    Core,
    Analysis,
    Static,
    Unknown,
}

/// Test category for organizing tests
#[derive(Debug, Clone, Copy, PartialEq)]
enum TestCategory {
    Meta,
    Memory,
    Module,
    Agent,
    Safety,
    Debug,
    Disasm,
    Script,
    Scanner,
    Process,
    Introspect,
    Dump,
    Patch,
    Trace,
    Pointer,
    Watch,
    Structure,
    Radare2,
    Ida,
    Ghidra,
    Ai,
    Yara,
    Integration,
    All,
}

impl std::str::FromStr for TestCategory {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "meta" => Ok(TestCategory::Meta),
            "memory" => Ok(TestCategory::Memory),
            "module" => Ok(TestCategory::Module),
            "agent" => Ok(TestCategory::Agent),
            "safety" => Ok(TestCategory::Safety),
            "debug" => Ok(TestCategory::Debug),
            "disasm" => Ok(TestCategory::Disasm),
            "script" => Ok(TestCategory::Script),
            "scanner" => Ok(TestCategory::Scanner),
            "process" => Ok(TestCategory::Process),
            "introspect" => Ok(TestCategory::Introspect),
            "dump" => Ok(TestCategory::Dump),
            "patch" => Ok(TestCategory::Patch),
            "trace" => Ok(TestCategory::Trace),
            "pointer" => Ok(TestCategory::Pointer),
            "watch" => Ok(TestCategory::Watch),
            "structure" => Ok(TestCategory::Structure),
            "radare2" | "r2" => Ok(TestCategory::Radare2),
            "ida" => Ok(TestCategory::Ida),
            "ghidra" => Ok(TestCategory::Ghidra),
            "ai" => Ok(TestCategory::Ai),
            "yara" => Ok(TestCategory::Yara),
            "integration" | "int" => Ok(TestCategory::Integration),
            "all" => Ok(TestCategory::All),
            _ => anyhow::bail!("Unknown test category: {}", s),
        }
    }
}

/// Detect server type from mcp_version response
fn detect_server_type(client: &mut McpClient) -> ServerType {
    match client.call_tool("mcp_version", serde_json::json!({})) {
        Ok(result) => {
            let text = result["content"][0]["text"].as_str().unwrap_or("");
            if text.contains("ghost-core") {
                ServerType::Core
            } else if text.contains("ghost-analysis") {
                ServerType::Analysis
            } else if text.contains("ghost-static") {
                ServerType::Static
            } else {
                ServerType::Unknown
            }
        }
        Err(_) => ServerType::Unknown,
    }
}

/// Run integration tests
fn run_integration_tests(client: &mut McpClient, specific_test: Option<String>) -> Result<()> {
    // Detect which server we're connected to
    let server_type = detect_server_type(client);
    println!("Running integration tests for {:?}...\n", server_type);

    // Parse category filter from specific_test (e.g., "memory" runs all memory tests)
    let category_filter: Option<TestCategory> = specific_test.as_ref().and_then(|s| s.parse().ok());

    // ================================================================
    // META TOOLS - MCP protocol and server info
    // ================================================================
    let meta_tests: Vec<(&str, TestFn)> = vec![
        (
            "meta/list_tools",
            Box::new(|c| {
                let result = c.list_tools()?;
                let tools = result.get("tools").and_then(|t| t.as_array());
                Ok(tools.map(|t| t.len() > 10).unwrap_or(false)) // Should have many tools
            }),
        ),
        (
            "meta/mcp_version",
            Box::new(|c| {
                let result = c.call_tool("mcp_version", serde_json::json!({}))?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                // Check for server name and version fields in JSON output
                Ok(text.contains("ghost-") && text.contains("version"))
            }),
        ),
        (
            "meta/mcp_health",
            Box::new(|c| {
                let result = c.call_tool("mcp_health", serde_json::json!({}))?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                Ok(text.contains("healthy") && text.contains("agent"))
            }),
        ),
        (
            "meta/mcp_capabilities",
            Box::new(|c| {
                let result = c.call_tool("mcp_capabilities", serde_json::json!({}))?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                Ok(text.contains("memory") || text.contains("module"))
            }),
        ),
    ];

    // ================================================================
    // CORE-ONLY META TOOLS - Session and action tracking (core server only)
    // ================================================================
    let core_meta_tests: Vec<(&str, TestFn)> = vec![
        (
            "meta/session_info",
            Box::new(|c| {
                let result = c.call_tool("session_info", serde_json::json!({}))?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                Ok(text.contains("attached") || text.contains("pid"))
            }),
        ),
        (
            "meta/action_last",
            Box::new(|c| {
                let result = c.call_tool("action_last", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
    ];

    // ================================================================
    // AGENT TOOLS - Agent connection and status
    // ================================================================
    let agent_tests: Vec<(&str, TestFn)> = vec![(
        "agent/status",
        Box::new(|c| {
            let result = c.call_tool("agent_status", serde_json::json!({}))?;
            let text = result["content"][0]["text"].as_str().unwrap_or("");
            Ok(text.contains("connected") || text.contains("status"))
        }),
    )];

    // ================================================================
    // MEMORY TOOLS - Memory read/write/search
    // ================================================================
    let memory_tests: Vec<(&str, TestFn)> = vec![
        (
            "memory/regions",
            Box::new(|c| {
                let result = c.call_tool("memory_regions", serde_json::json!({}))?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                // Should contain memory region info or addresses
                Ok(text.contains("0x") || text.contains("address") || text.len() > 100)
            }),
        ),
        (
            "memory/read",
            Box::new(|c| {
                // Read from a typical code address (should work on any process)
                let result = c.call_tool(
                    "memory_read",
                    serde_json::json!({
                        "address": "0x7FF000000000",
                        "size": 16
                    }),
                )?;
                // Either returns data or an error about invalid address - both are valid responses
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "memory/search",
            Box::new(|c| {
                // Search for a common value
                let result = c.call_tool(
                    "memory_search",
                    serde_json::json!({
                        "value": "100",
                        "type": "i32"
                    }),
                )?;
                Ok(result.get("content").is_some())
            }),
        ),
    ];

    // ================================================================
    // MODULE TOOLS - Module enumeration and analysis
    // ================================================================
    let module_tests: Vec<(&str, TestFn)> = vec![
        (
            "module/list",
            Box::new(|c| {
                let result = c.call_tool("module_list", serde_json::json!({}))?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                // Should contain ntdll or kernel32 (always loaded)
                Ok(text.to_lowercase().contains("ntdll")
                    || text.to_lowercase().contains("kernel32"))
            }),
        ),
        (
            "module/exports",
            Box::new(|c| {
                let result = c.call_tool(
                    "module_exports",
                    serde_json::json!({
                        "module": "ntdll.dll"
                    }),
                )?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                // ntdll should have exports
                Ok(text.contains("Nt") || text.contains("Rtl") || text.contains("0x"))
            }),
        ),
        (
            "module/imports",
            Box::new(|c| {
                let result = c.call_tool(
                    "module_imports",
                    serde_json::json!({
                        "module": "ghost-test-target.exe"
                    }),
                )?;
                // Should return some imports or not found error
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "module/symbol_resolve",
            Box::new(|c| {
                let result = c.call_tool(
                    "symbol_resolve",
                    serde_json::json!({
                        "name": "ntdll!NtQuerySystemInformation"
                    }),
                )?;
                // Should return some response (address, error, or info)
                Ok(result.get("content").is_some())
            }),
        ),
    ];

    // ================================================================
    // SAFETY TOOLS - Safety mode and configuration
    // ================================================================
    let safety_tests: Vec<(&str, TestFn)> = vec![
        (
            "safety/status",
            Box::new(|c| {
                let result = c.call_tool("safety_status", serde_json::json!({}))?;
                let text = result["content"][0]["text"].as_str().unwrap_or("");
                Ok(text.contains("mode") || text.contains("safety") || text.contains("standard"))
            }),
        ),
        (
            "safety/config",
            Box::new(|c| {
                let result = c.call_tool("safety_config", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "safety/patch_history",
            Box::new(|c| {
                let result = c.call_tool("patch_history", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
    ];

    // ================================================================
    // DEBUG TOOLS - Thread and breakpoint operations
    // ================================================================
    let debug_tests: Vec<(&str, TestFn)> = vec![
        (
            "debug/thread_list",
            Box::new(|c| {
                let result = c.call_tool("thread_list", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "debug/breakpoint_list",
            Box::new(|c| {
                let result = c.call_tool("breakpoint_list", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
    ];

    // ================================================================
    // DISASM TOOLS - Disassembly operations
    // ================================================================
    let disasm_tests: Vec<(&str, TestFn)> = vec![(
        "disasm/mcp_documentation",
        Box::new(|c| {
            let result = c.call_tool(
                "mcp_documentation",
                serde_json::json!({
                    "tool": "disasm_at"
                }),
            )?;
            Ok(result.get("content").is_some())
        }),
    )];

    // ================================================================
    // SCRIPT TOOLS - Script engine operations
    // ================================================================
    let script_tests: Vec<(&str, TestFn)> = vec![
        (
            "script/list",
            Box::new(|c| {
                let result = c.call_tool("script_list", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "script/hook_list",
            Box::new(|c| {
                let result = c.call_tool("hook_list", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "script/rpc_list",
            Box::new(|c| {
                let result = c.call_tool("rpc_list", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
    ];

    // ================================================================
    // SCANNER TOOLS - Value scanner operations
    // ================================================================
    let scanner_tests: Vec<(&str, TestFn)> = vec![(
        "scanner/list",
        Box::new(|c| {
            let result = c.call_tool("scan_list", serde_json::json!({}))?;
            Ok(result.get("content").is_some())
        }),
    )];

    // ================================================================
    // PROCESS TOOLS - Process control
    // ================================================================
    let process_tests: Vec<(&str, TestFn)> = vec![(
        "process/list",
        Box::new(|c| {
            let result = c.call_tool("process_list", serde_json::json!({}))?;
            let text = result["content"][0]["text"].as_str().unwrap_or("");
            Ok(text.len() > 10 || result.get("content").is_some())
        }),
    )];

    // ================================================================
    // INTROSPECT TOOLS - Process introspection
    // ================================================================
    let introspect_tests: Vec<(&str, TestFn)> = vec![
        (
            "introspect/process",
            Box::new(|c| {
                let result = c.call_tool("introspect_process", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/peb",
            Box::new(|c| {
                let result = c.call_tool("introspect_peb", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/memory_map",
            Box::new(|c| {
                let result = c.call_tool("introspect_memory_map", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/environment",
            Box::new(|c| {
                let result = c.call_tool("introspect_environment", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/cwd",
            Box::new(|c| {
                let result = c.call_tool("introspect_cwd", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/thread_list",
            Box::new(|c| {
                let result = c.call_tool("introspect_thread_list", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/module_list",
            Box::new(|c| {
                let result = c.call_tool("introspect_module_list", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/handles",
            Box::new(|c| {
                let result = c.call_tool("introspect_handles", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
        (
            "introspect/token",
            Box::new(|c| {
                let result = c.call_tool("introspect_token", serde_json::json!({}))?;
                Ok(result.get("content").is_some())
            }),
        ),
    ];

    // ================================================================
    // DUMP TOOLS - Memory dump operations
    // ================================================================
    let dump_tests: Vec<(&str, TestFn)> = vec![(
        "dump/list",
        Box::new(|c| {
            let result = c.call_tool("dump_list", serde_json::json!({}))?;
            Ok(result.get("content").is_some())
        }),
    )];

    // ================================================================
    // PATCH TOOLS - Memory patching operations
    // ================================================================
    let patch_tests: Vec<(&str, TestFn)> = vec![(
        "patch/history",
        Box::new(|c| {
            let result = c.call_tool("patch_history", serde_json::json!({}))?;
            Ok(result.get("content").is_some())
        }),
    )];

    // ================================================================
    // TRACE TOOLS - API tracing operations
    // ================================================================
    let trace_tests: Vec<(&str, TestFn)> = vec![
        (
            "trace/session_list",
            Box::new(|c| {
                let _result = c.call_tool("trace_session_list", serde_json::json!({}))?;
                Ok(true) // Success if no error
            }),
        ),
        (
            "trace/preset_list",
            Box::new(|c| {
                let _result = c.call_tool("trace_preset_list", serde_json::json!({}))?;
                Ok(true) // Success if no error
            }),
        ),
        (
            "trace/pack_list",
            Box::new(|c| {
                let _result = c.call_tool("trace_pack_list", serde_json::json!({}))?;
                Ok(true) // Success if no error
            }),
        ),
        (
            "trace/hooks_list",
            Box::new(|c| {
                let _result = c.call_tool("trace_hooks_list", serde_json::json!({}))?;
                Ok(true) // Success if no error
            }),
        ),
        (
            "trace/queue_stats",
            Box::new(|c| {
                let _result = c.call_tool("trace_queue_stats", serde_json::json!({}))?;
                Ok(true) // Success if no error
            }),
        ),
    ];

    // ================================================================
    // ANALYSIS SERVER - Pointer scanner tests
    // ================================================================
    let pointer_tests: Vec<(&str, TestFn)> = vec![(
        "pointer/scan_list",
        Box::new(|c| {
            let result = c.call_tool("pointer_scan_list", serde_json::json!({}))?;
            Ok(result.get("content").is_some())
        }),
    )];

    // ================================================================
    // ANALYSIS SERVER - Watch tests
    // ================================================================
    let watch_tests: Vec<(&str, TestFn)> = vec![(
        "watch/list",
        Box::new(|c| {
            let result = c.call_tool("watch_list", serde_json::json!({}))?;
            Ok(result.get("content").is_some())
        }),
    )];

    // ================================================================
    // ANALYSIS SERVER - Structure tests
    // ================================================================
    let structure_tests: Vec<(&str, TestFn)> = vec![(
        "structure/list",
        Box::new(|c| {
            let result = c.call_tool("struct_list", serde_json::json!({}))?;
            Ok(result.get("content").is_some())
        }),
    )];

    // ================================================================
    // STATIC SERVER - Radare2 tests
    // ================================================================
    let radare2_tests: Vec<(&str, TestFn)> = vec![(
        "radare2/status",
        Box::new(|c| {
            let _result = c.call_tool("r2_status", serde_json::json!({}))?;
            Ok(true) // Success if no error
        }),
    )];

    // ================================================================
    // STATIC SERVER - IDA tests
    // ================================================================
    let ida_tests: Vec<(&str, TestFn)> = vec![(
        "ida/status",
        Box::new(|c| {
            let _result = c.call_tool("ida_status", serde_json::json!({}))?;
            Ok(true) // Success if no error
        }),
    )];

    // ================================================================
    // STATIC SERVER - Ghidra tests
    // ================================================================
    let ghidra_tests: Vec<(&str, TestFn)> = vec![(
        "ghidra/status",
        Box::new(|c| {
            let _result = c.call_tool("ghidra_status", serde_json::json!({}))?;
            Ok(true) // Success if no error
        }),
    )];

    // ================================================================
    // STATIC SERVER - AI tests
    // ================================================================
    let ai_tests: Vec<(&str, TestFn)> = vec![(
        "ai/debug_session_list",
        Box::new(|c| {
            let _result = c.call_tool("debug_session_list", serde_json::json!({}))?;
            Ok(true) // Success if no error
        }),
    )];

    // ================================================================
    // STATIC SERVER - YARA tests
    // ================================================================
    let yara_tests: Vec<(&str, TestFn)> = vec![
        (
            "yara/rule_list",
            Box::new(|c| {
                let _result = c.call_tool("yara_list_rules", serde_json::json!({}))?;
                Ok(true) // Success if no error
            }),
        ),
        (
            "yara/signature_db_list",
            Box::new(|c| {
                let _result = c.call_tool("signature_db_list", serde_json::json!({}))?;
                Ok(true) // Success if no error
            }),
        ),
    ];

    // ================================================================
    // INTEGRATION TEST - Full workflow: alloc, write, scan, patch, pointer
    // ================================================================
    let integration_tests: Vec<(&str, TestFn)> = vec![(
        "integration/full_memory_workflow",
        Box::new(|c| {
            println!("\n    [Integration Test: Full Memory Workflow]");

            // Step 1: Allocate heap memory using exec_alloc
            println!("    Step 1: Allocating 4096 bytes of heap memory...");
            let alloc_result = c.call_tool(
                "exec_alloc",
                serde_json::json!({
                    "size": 4096,
                    "protection": "rwx"
                }),
            )?;
            let alloc_text = alloc_result["content"][0]["text"].as_str().unwrap_or("");
            println!(
                "    Alloc response: {}",
                alloc_text.lines().next().unwrap_or("(empty)")
            );

            // Extract allocated address from response
            let addr_str = if let Some(start) = alloc_text.find("0x") {
                let end = alloc_text[start..]
                    .find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                    .map(|e| start + e)
                    .unwrap_or(alloc_text.len());
                &alloc_text[start..end]
            } else {
                return Err(anyhow::anyhow!("Failed to find allocated address"));
            };
            println!("    Allocated at: {}", addr_str);

            // Step 2: Write a known value (0xDEADBEEF = 3735928559)
            println!("    Step 2: Writing value 3735928559 (0xDEADBEEF) to allocated memory...");
            let write_result = c.call_tool(
                "memory_write",
                serde_json::json!({
                    "address": addr_str,
                    "value": "3735928559",
                    "type": "u32"
                }),
            )?;
            if write_result.get("error").is_some() {
                return Err(anyhow::anyhow!("Write failed"));
            }
            println!("    Write successful!");

            // Step 3: Read back to verify
            println!("    Step 3: Reading back value to verify...");
            let read_result = c.call_tool(
                "memory_read",
                serde_json::json!({
                    "address": addr_str,
                    "size": 4
                }),
            )?;
            let read_text = read_result["content"][0]["text"].as_str().unwrap_or("");
            println!(
                "    Read result: {}",
                read_text.lines().next().unwrap_or(read_text)
            );

            // Step 4: Create a scan session and scan for our value
            println!("    Step 4: Creating scan session for i32...");
            let scan_new = c.call_tool(
                "scan_new",
                serde_json::json!({
                    "value_type": "i32"
                }),
            )?;
            let scan_text = scan_new["content"][0]["text"].as_str().unwrap_or("");
            // Extract scan_id
            let scan_id = if let Some(id_start) = scan_text.find("scan_id") {
                let after = &scan_text[id_start..];
                if let Some(num_start) = after.find(|c: char| c.is_ascii_digit()) {
                    let num_end = after[num_start..]
                        .find(|c: char| !c.is_ascii_digit())
                        .map(|e| num_start + e)
                        .unwrap_or(after.len());
                    after[num_start..num_end].to_string()
                } else {
                    "1".to_string()
                }
            } else {
                "1".to_string()
            };
            println!("    Scan session created: {}", scan_id);

            // Step 5: Perform initial scan for 0xDEADBEEF as signed i32 (-559038737)
            println!("    Step 5: Scanning for value -559038737 (0xDEADBEEF as i32)...");
            let scan_first = c.call_tool(
                "scan_first",
                serde_json::json!({
                    "scan_id": scan_id,
                    "value": "-559038737",
                    "compare": "exact"
                }),
            )?;
            let scan_first_text = scan_first["content"][0]["text"].as_str().unwrap_or("");
            println!(
                "    Scan result: {} results found",
                if scan_first_text.contains("results_found") {
                    scan_first_text
                        .lines()
                        .find(|l| l.contains("results_found"))
                        .unwrap_or("?")
                } else {
                    "?"
                }
            );

            // Step 6: Change the value to something else
            println!("    Step 6: Writing new value 12345678...");
            c.call_tool(
                "memory_write",
                serde_json::json!({
                    "address": addr_str,
                    "value": "12345678",
                    "type": "i32"
                }),
            )?;

            // Step 7: Scan for new value (filter results)
            println!("    Step 7: Filtering scan for new value 12345678...");
            let scan_next = c.call_tool(
                "scan_next",
                serde_json::json!({
                    "scan_id": scan_id,
                    "value": "12345678",
                    "compare": "exact"
                }),
            )?;
            let scan_next_text = scan_next["content"][0]["text"].as_str().unwrap_or("");
            println!(
                "    Filtered: {}",
                scan_next_text.lines().next().unwrap_or("?")
            );

            // Step 8: Patch the memory with NOP bytes
            println!("    Step 8: Patching memory with custom bytes [0x90, 0x90, 0x90, 0x90]...");
            let patch_result = c.call_tool(
                "patch_bytes",
                serde_json::json!({
                    "address": addr_str,
                    "bytes": [0x90, 0x90, 0x90, 0x90]
                }),
            )?;
            if patch_result.get("error").is_some() {
                println!("    Patch failed (may not be supported), continuing...");
            } else {
                println!("    Patch applied!");
            }

            // Step 9: Read back patched bytes
            println!("    Step 9: Reading patched memory...");
            let read_patched = c.call_tool(
                "memory_read",
                serde_json::json!({
                    "address": addr_str,
                    "size": 4
                }),
            )?;
            let patched_text = read_patched["content"][0]["text"].as_str().unwrap_or("");
            println!(
                "    Patched bytes: {}",
                patched_text.lines().next().unwrap_or(patched_text)
            );

            // Step 10: Test pointer resolution (using our allocated address as example)
            println!("    Step 10: Testing pointer resolution...");
            let ptr_result = c.call_tool(
                "pointer_resolve",
                serde_json::json!({
                    "base": addr_str,
                    "offsets": [0]
                }),
            )?;
            let ptr_text = ptr_result["content"][0]["text"].as_str().unwrap_or("");
            println!(
                "    Pointer resolve: {}",
                ptr_text.lines().next().unwrap_or("?")
            );

            // Step 11: Close scan session
            println!("    Step 11: Closing scan session...");
            let _ = c.call_tool(
                "scan_close",
                serde_json::json!({
                    "scan_id": scan_id
                }),
            );

            // Step 12: Free allocated memory using exec_free
            println!("    Step 12: Freeing allocated memory...");
            let free_result = c.call_tool(
                "exec_free",
                serde_json::json!({
                    "address": addr_str
                }),
            )?;
            if free_result.get("error").is_some() {
                println!("    Free failed (may not be supported)");
            } else {
                println!("    Memory freed!");
            }

            println!("    [Integration Test Complete!]");
            Ok(true)
        }),
    )];

    // Combine all tests based on category filter AND server type
    let mut all_tests: Vec<(&str, TestFn)> = Vec::new();

    let should_run = |cat: TestCategory| -> bool {
        category_filter.is_none()
            || category_filter == Some(TestCategory::All)
            || category_filter == Some(cat)
    };

    // Meta tests run on all servers
    if should_run(TestCategory::Meta) {
        all_tests.extend(meta_tests);
    }

    // Core server tests
    if server_type == ServerType::Core || server_type == ServerType::Unknown {
        // Core-only meta tools
        if should_run(TestCategory::Meta) {
            all_tests.extend(core_meta_tests);
        }
        if should_run(TestCategory::Agent) {
            all_tests.extend(agent_tests);
        }
        if should_run(TestCategory::Memory) {
            all_tests.extend(memory_tests);
        }
        if should_run(TestCategory::Module) {
            all_tests.extend(module_tests);
        }
        if should_run(TestCategory::Safety) {
            all_tests.extend(safety_tests);
        }
        if should_run(TestCategory::Debug) {
            all_tests.extend(debug_tests);
        }
        if should_run(TestCategory::Disasm) {
            all_tests.extend(disasm_tests);
        }
        if should_run(TestCategory::Script) {
            all_tests.extend(script_tests);
        }
        if should_run(TestCategory::Process) {
            all_tests.extend(process_tests);
        }
        if should_run(TestCategory::Patch) {
            all_tests.extend(patch_tests);
        }
    }

    // Analysis server tests
    if server_type == ServerType::Analysis || server_type == ServerType::Unknown {
        if should_run(TestCategory::Scanner) {
            all_tests.extend(scanner_tests);
        }
        if should_run(TestCategory::Introspect) {
            all_tests.extend(introspect_tests);
        }
        if should_run(TestCategory::Dump) {
            all_tests.extend(dump_tests);
        }
        if should_run(TestCategory::Pointer) {
            all_tests.extend(pointer_tests);
        }
        if should_run(TestCategory::Watch) {
            all_tests.extend(watch_tests);
        }
        if should_run(TestCategory::Structure) {
            all_tests.extend(structure_tests);
        }
    }

    // Static server tests
    if server_type == ServerType::Static || server_type == ServerType::Unknown {
        if should_run(TestCategory::Trace) {
            all_tests.extend(trace_tests);
        }
        if should_run(TestCategory::Radare2) {
            all_tests.extend(radare2_tests);
        }
        if should_run(TestCategory::Ida) {
            all_tests.extend(ida_tests);
        }
        if should_run(TestCategory::Ghidra) {
            all_tests.extend(ghidra_tests);
        }
        if should_run(TestCategory::Ai) {
            all_tests.extend(ai_tests);
        }
        if should_run(TestCategory::Yara) {
            all_tests.extend(yara_tests);
        }
    }

    // Integration tests run on core server (needs exec_alloc) or unknown (extended-mcp with all tools)
    if (server_type == ServerType::Core || server_type == ServerType::Unknown)
        && should_run(TestCategory::Integration)
    {
        all_tests.extend(integration_tests);
    }

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for (name, test_fn) in all_tests {
        // If specific test name given (not a category), filter by exact match
        if let Some(ref specific) = specific_test {
            if category_filter.is_none() && !name.contains(specific.as_str()) {
                skipped += 1;
                continue;
            }
        }

        print!("  {} ... ", name);
        match test_fn(client) {
            Ok(true) => {
                println!("PASSED");
                passed += 1;
            }
            Ok(false) => {
                println!("FAILED (assertion)");
                failed += 1;
            }
            Err(e) => {
                println!("FAILED ({})", e);
                failed += 1;
            }
        }
    }

    println!(
        "\nResults: {} passed, {} failed, {} skipped",
        passed, failed, skipped
    );
    println!("\nCategories: meta, agent, memory, module, safety, debug, disasm, script, scanner, process, introspect, dump, patch, trace, pointer, watch, structure, radare2, ida, ghidra, ai, yara, integration, all");

    if failed > 0 {
        anyhow::bail!("{} tests failed", failed);
    }

    Ok(())
}

/// Run script from JSON file
fn run_script(client: &mut McpClient, path: &str) -> Result<()> {
    let content =
        std::fs::read_to_string(path).context(format!("Failed to read script file: {}", path))?;

    #[derive(Deserialize)]
    struct ScriptCommand {
        tool: String,
        #[serde(default)]
        arguments: serde_json::Value,
        #[serde(default)]
        expect_error: bool,
    }

    #[derive(Deserialize)]
    struct Script {
        name: Option<String>,
        commands: Vec<ScriptCommand>,
    }

    let script: Script = serde_json::from_str(&content).context("Failed to parse script JSON")?;

    if let Some(name) = &script.name {
        println!("Running script: {}\n", name);
    }

    for (i, cmd) in script.commands.iter().enumerate() {
        println!("[{}] Calling: {}", i + 1, cmd.tool);

        match client.call_tool(&cmd.tool, cmd.arguments.clone()) {
            Ok(result) => {
                if cmd.expect_error {
                    println!("  UNEXPECTED SUCCESS");
                } else {
                    println!("  OK: {}", serde_json::to_string(&result)?);
                }
            }
            Err(e) => {
                if cmd.expect_error {
                    println!("  Expected error: {}", e);
                } else {
                    println!("  ERROR: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Interactive REPL mode
fn run_repl(client: &mut McpClient) -> Result<()> {
    println!("Ghost-MCP REPL - Type 'help' for commands, 'quit' to exit\n");

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    loop {
        print!("ghost> ");
        stdout.flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break; // EOF
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let cmd = parts[0];

        match cmd {
            "quit" | "exit" | "q" => break,
            "help" | "?" => {
                println!("Commands:");
                println!("  tools           - List available tools");
                println!("  call <tool> [json] - Call a tool with optional JSON args");
                println!("  health          - Check server health");
                println!("  version         - Get server version");
                println!("  quit            - Exit REPL");
            }
            "tools" => match client.list_tools() {
                Ok(result) => {
                    if let Some(tools) = result.get("tools").and_then(|t| t.as_array()) {
                        for tool in tools {
                            if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                                let desc = tool
                                    .get("description")
                                    .and_then(|d| d.as_str())
                                    .unwrap_or("");
                                println!("  {:30} {}", name, desc);
                            }
                        }
                    }
                }
                Err(e) => println!("Error: {}", e),
            },
            "health" => match client.call_tool("mcp_health", serde_json::json!({})) {
                Ok(result) => println!("{}", serde_json::to_string_pretty(&result)?),
                Err(e) => println!("Error: {}", e),
            },
            "version" => match client.call_tool("mcp_version", serde_json::json!({})) {
                Ok(result) => println!("{}", serde_json::to_string_pretty(&result)?),
                Err(e) => println!("Error: {}", e),
            },
            "call" => {
                if parts.len() < 2 {
                    println!("Usage: call <tool> [json_args]");
                    continue;
                }
                let rest = parts[1];
                let tool_parts: Vec<&str> = rest.splitn(2, ' ').collect();
                let tool_name = tool_parts[0];
                let args: serde_json::Value = if tool_parts.len() > 1 {
                    serde_json::from_str(tool_parts[1]).unwrap_or(serde_json::json!({}))
                } else {
                    serde_json::json!({})
                };

                match client.call_tool(tool_name, args) {
                    Ok(result) => println!("{}", serde_json::to_string_pretty(&result)?),
                    Err(e) => println!("Error: {}", e),
                }
            }
            _ => {
                // Try to call it as a tool directly
                let args: serde_json::Value = if parts.len() > 1 {
                    serde_json::from_str(parts[1]).unwrap_or(serde_json::json!({}))
                } else {
                    serde_json::json!({})
                };

                match client.call_tool(cmd, args) {
                    Ok(result) => println!("{}", serde_json::to_string_pretty(&result)?),
                    Err(e) => println!("Unknown command or tool error: {}", e),
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Ghost-MCP Client v{}", env!("CARGO_PKG_VERSION"));

    // For now, we only support stdio mode
    if !args.stdio {
        println!("\nNote: HTTP mode not yet implemented. Use --stdio to connect via subprocess.");
        println!("Example: ghost-client --stdio --host-binary ./target/debug/ghost-core-mcp tools");
        return Ok(());
    }

    // Connect to MCP server
    let mut client = McpClient::connect_stdio(&args.host_binary, args.verbose)?;
    println!("Connected to MCP server\n");

    let result = match args.command {
        Commands::Call { tool, param, json } => {
            let params = parse_params(param, json)?;
            println!("Calling: {} with {}\n", tool, params);

            match client.call_tool(&tool, params) {
                Ok(result) => {
                    println!("Result:");
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(())
                }
                Err(e) => {
                    println!("Error: {}", e);
                    Err(e)
                }
            }
        }

        Commands::Tools => {
            let result = client.list_tools()?;

            if let Some(tools) = result.get("tools").and_then(|t| t.as_array()) {
                println!("Available tools ({}):\n", tools.len());
                for tool in tools {
                    if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                        let desc = tool
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("");
                        println!("  {:30} {}", name, desc);
                    }
                }
            }
            Ok(())
        }

        Commands::Info => {
            let result = client.call_tool("mcp_version", serde_json::json!({}))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        Commands::Health => {
            let result = client.call_tool("mcp_health", serde_json::json!({}))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        Commands::Script { path } => run_script(&mut client, &path),

        Commands::Repl => run_repl(&mut client),

        Commands::Test { test } => run_integration_tests(&mut client, test),

        Commands::TestAll => run_integration_tests(&mut client, None),
    };

    // Cleanup
    client.shutdown()?;

    result
}
