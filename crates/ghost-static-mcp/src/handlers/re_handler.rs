//! RE (Reverse Engineering) handler for ghost-static-mcp
//!
//! Provides specialized handling for RE backend tools (Radare2, IDA Pro, Ghidra).
//! Routes tools to appropriate backends and handles session management.

use ghost_mcp_common::error::{McpError, Result};
use ghost_mcp_common::ipc::SharedAgentClient;
#[cfg(any(feature = "radare2", feature = "ghidra", feature = "ida"))]
use serde_json::json;
use serde_json::Value;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

#[cfg(feature = "ghidra")]
use ghost_re_backends::GhidraBackend;
#[cfg(feature = "ida")]
use ghost_re_backends::IdaBackend;
#[cfg(any(feature = "radare2", feature = "ghidra", feature = "ida"))]
use ghost_re_backends::ReBackend as ReBackendTrait;
#[cfg(feature = "radare2")]
use ghost_re_backends::{BinaryInfo, Radare2Backend};
#[cfg(any(feature = "radare2", feature = "ghidra"))]
use once_cell::sync::Lazy;
#[cfg(feature = "ida")]
use once_cell::sync::Lazy;
#[cfg(feature = "ghidra")]
use std::env;
#[cfg(any(feature = "radare2", feature = "ghidra"))]
use tokio::sync::Mutex;
#[cfg(feature = "ida")]
use tokio::sync::Mutex;

/// Maximum path length for binary files
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum command length for raw commands (r2_cmd, etc.)
pub const MAX_CMD_LEN: usize = 8192;

/// Maximum filter/pattern length
pub const MAX_FILTER_LEN: usize = 1024;

/// Minimum valid address for operations
pub const MIN_VALID_ADDRESS: u64 = 0x1000;

/// RE backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReBackend {
    Radare2,
    IdaPro,
    Ghidra,
}

impl ReBackend {
    /// Get backend name for logging
    pub fn name(&self) -> &'static str {
        match self {
            ReBackend::Radare2 => "radare2",
            ReBackend::IdaPro => "ida",
            ReBackend::Ghidra => "ghidra",
        }
    }

    /// Agent tool prefix for the backend
    pub fn agent_prefix(&self) -> &'static str {
        match self {
            ReBackend::Radare2 => "r2",
            ReBackend::IdaPro => "ida",
            ReBackend::Ghidra => "ghidra",
        }
    }

    /// Infer backend from tool name prefix
    pub fn from_tool_name(name: &str) -> Option<ReBackend> {
        if name.starts_with("r2_") {
            Some(ReBackend::Radare2)
        } else if name.starts_with("ida_") {
            Some(ReBackend::IdaPro)
        } else if name.starts_with("ghidra_") {
            Some(ReBackend::Ghidra)
        } else {
            None
        }
    }
}

/// Parse and require address from args for RE tools
#[cfg(any(feature = "radare2", feature = "ghidra", feature = "ida"))]
fn require_address(args: &Value, context: &str) -> Result<u64> {
    ReHandler::validate_address(args)?.ok_or_else(|| {
        McpError::InvalidParams(format!("Missing 'address' parameter for {}", context))
    })
}

#[cfg(feature = "radare2")]
static RADARE2_BACKEND: Lazy<Mutex<Radare2Backend>> =
    Lazy::new(|| Mutex::new(Radare2Backend::new()));

#[cfg(feature = "ghidra")]
fn create_ghidra_backend() -> GhidraBackend {
    // Prefer JSON-RPC mode when GHIDRA_RPC_HOST is set, otherwise headless
    if let Ok(host) = env::var("GHIDRA_RPC_HOST") {
        let port = env::var("GHIDRA_RPC_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(13100);
        if let Ok(b) = GhidraBackend::connect_rpc(&host, port) {
            return b;
        }
        warn!(
            "Failed to connect to ghidra-pipe at {}:{}, falling back to headless mode",
            host, port
        );
    }
    GhidraBackend::new().expect("Failed to create Ghidra backend")
}

#[cfg(feature = "ghidra")]
static GHIDRA_BACKEND: Lazy<Mutex<GhidraBackend>> =
    Lazy::new(|| Mutex::new(create_ghidra_backend()));

#[cfg(feature = "ida")]
static IDA_BACKEND: Lazy<Mutex<IdaBackend>> =
    Lazy::new(|| Mutex::new(IdaBackend::new().expect("Failed to initialize IDA backend")));

/// RE handler for static analysis tools
pub struct ReHandler;

impl ReHandler {
    /// Validate path parameter
    pub fn validate_path(args: &Value) -> Result<Option<String>> {
        if let Some(path) = args.get("path").and_then(|p| p.as_str()) {
            if path.len() > MAX_PATH_LEN {
                return Err(McpError::InvalidParams(format!(
                    "Path exceeds maximum length of {} characters",
                    MAX_PATH_LEN
                )));
            }
            // Basic path validation - no null bytes
            if path.contains('\0') {
                return Err(McpError::InvalidParams(
                    "Path contains invalid null character".to_string(),
                ));
            }
            Ok(Some(path.to_string()))
        } else {
            Ok(None)
        }
    }

    /// Validate address parameter
    pub fn validate_address(args: &Value) -> Result<Option<u64>> {
        match args.get("address") {
            Some(Value::String(s)) => {
                let s = s.trim();
                let s = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                let addr = u64::from_str_radix(s, 16).map_err(|e| {
                    McpError::InvalidParams(format!("Invalid hex address '{}': {}", s, e))
                })?;
                if addr < MIN_VALID_ADDRESS {
                    return Err(McpError::InvalidParams(format!(
                        "Address 0x{:x} is below minimum valid address 0x{:x}",
                        addr, MIN_VALID_ADDRESS
                    )));
                }
                Ok(Some(addr))
            }
            Some(Value::Number(n)) => {
                let addr = n.as_u64().ok_or_else(|| {
                    McpError::InvalidParams("Address must be a positive integer".to_string())
                })?;
                if addr < MIN_VALID_ADDRESS {
                    return Err(McpError::InvalidParams(format!(
                        "Address 0x{:x} is below minimum valid address 0x{:x}",
                        addr, MIN_VALID_ADDRESS
                    )));
                }
                Ok(Some(addr))
            }
            None => Ok(None),
            _ => Err(McpError::InvalidParams(
                "Address must be a string or number".to_string(),
            )),
        }
    }

    /// Validate command parameter (for raw commands like r2_cmd)
    pub fn validate_command(args: &Value) -> Result<String> {
        let cmd = args
            .get("command")
            .and_then(|c| c.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'command' parameter".to_string()))?;

        if cmd.is_empty() {
            return Err(McpError::InvalidParams(
                "Command cannot be empty".to_string(),
            ));
        }

        if cmd.len() > MAX_CMD_LEN {
            return Err(McpError::InvalidParams(format!(
                "Command exceeds maximum length of {} characters",
                MAX_CMD_LEN
            )));
        }

        Ok(cmd.to_string())
    }

    /// Validate filter/pattern parameter
    pub fn validate_filter(args: &Value, param_name: &str) -> Result<Option<String>> {
        if let Some(filter) = args.get(param_name).and_then(|f| f.as_str()) {
            if filter.len() > MAX_FILTER_LEN {
                return Err(McpError::InvalidParams(format!(
                    "{} exceeds maximum length of {} characters",
                    param_name, MAX_FILTER_LEN
                )));
            }
            Ok(Some(filter.to_string()))
        } else {
            Ok(None)
        }
    }

    /// Validate session action parameter
    pub fn validate_session_action(args: &Value) -> Result<String> {
        let action = args
            .get("action")
            .and_then(|a| a.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'action' parameter".to_string()))?;

        match action {
            "open" | "close" => Ok(action.to_string()),
            _ => Err(McpError::InvalidParams(format!(
                "Invalid action '{}'. Must be 'open' or 'close'",
                action
            ))),
        }
    }

    /// Validate xref direction parameter
    pub fn validate_xref_direction(args: &Value) -> Result<String> {
        let direction = args
            .get("direction")
            .and_then(|d| d.as_str())
            .unwrap_or("to");

        match direction {
            "to" | "from" => Ok(direction.to_string()),
            _ => Err(McpError::InvalidParams(format!(
                "Invalid direction '{}'. Must be 'to' or 'from'",
                direction
            ))),
        }
    }

    #[cfg(feature = "radare2")]
    async fn radare2_backend() -> tokio::sync::MutexGuard<'static, Radare2Backend> {
        RADARE2_BACKEND.lock().await
    }

    #[cfg(feature = "radare2")]
    fn map_r2_err<T>(result: ghost_re_backends::Result<T>) -> Result<T> {
        result.map_err(|e| McpError::Handler(format!("Radare2 backend error: {}", e)))
    }

    #[cfg(feature = "radare2")]
    async fn ensure_radare2_session() -> Result<()> {
        let backend = RADARE2_BACKEND.lock().await;
        if backend.is_connected() {
            Ok(())
        } else {
            Err(McpError::Handler(
                "Radare2 session is not open. Call r2_session with action \"open\" first."
                    .to_string(),
            ))
        }
    }

    #[cfg(feature = "radare2")]
    fn parse_min_length(args: &Value, default_len: usize) -> usize {
        args.get("min_length")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_len)
            .max(1)
    }

    #[cfg(feature = "ghidra")]
    async fn ghidra_backend() -> tokio::sync::MutexGuard<'static, GhidraBackend> {
        GHIDRA_BACKEND.lock().await
    }

    #[cfg(feature = "ghidra")]
    fn map_ghidra_err<T>(result: ghost_re_backends::Result<T>) -> Result<T> {
        result.map_err(|e| McpError::Handler(format!("Ghidra backend error: {}", e)))
    }

    #[cfg(feature = "ghidra")]
    async fn ensure_ghidra_session() -> Result<()> {
        let backend = GHIDRA_BACKEND.lock().await;
        if backend.is_connected() {
            Ok(())
        } else {
            Err(McpError::Handler(
                "Ghidra session is not open. Call ghidra_session with action \"open\" first."
                    .to_string(),
            ))
        }
    }

    #[cfg(feature = "ida")]
    async fn ida_backend() -> tokio::sync::MutexGuard<'static, IdaBackend> {
        IDA_BACKEND.lock().await
    }

    #[cfg(feature = "ida")]
    fn map_ida_err<T>(result: ghost_re_backends::Result<T>) -> Result<T> {
        result.map_err(|e| McpError::Handler(format!("IDA backend error: {}", e)))
    }

    #[cfg(feature = "ida")]
    async fn ensure_ida_session() -> Result<()> {
        let backend = Self::ida_backend().await;
        if backend.is_connected() {
            Ok(())
        } else {
            Err(McpError::Handler(
                "IDA session is not open. Call ida_session with action \"open\" first.".to_string(),
            ))
        }
    }

    /// Handle RE session tools (open/close)
    pub async fn handle_session(
        agent: &SharedAgentClient,
        backend: ReBackend,
        args: &Value,
    ) -> Result<Value> {
        let action = Self::validate_session_action(args)?;
        let start_time = Instant::now();

        info!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            action = %action,
            "Handling RE session"
        );

        // Validate path for open action
        if action == "open" {
            let path = Self::validate_path(args)?;
            if path.is_none() {
                return Err(McpError::InvalidParams(
                    "Missing 'path' parameter for open action".to_string(),
                ));
            }
        }

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let tool_name = match backend {
            ReBackend::Radare2 => match action.as_str() {
                "open" => "r2_open",
                "close" => "r2_close",
                _ => unreachable!("validated action"),
            },
            ReBackend::IdaPro => match action.as_str() {
                "open" => "ida_open",
                "close" => "ida_close",
                _ => unreachable!("validated action"),
            },
            ReBackend::Ghidra => match action.as_str() {
                "open" => "ghidra_open",
                "close" => "ghidra_close",
                _ => unreachable!("validated action"),
            },
        };
        let response = agent
            .request_with_reconnect(tool_name, args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("{} session failed: {}", backend.name(), e)))?;

        debug!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            action = %action,
            duration_ms = start_time.elapsed().as_millis(),
            "RE session completed"
        );

        Ok(response)
    }

    /// Handle RE disassembly tools
    pub async fn handle_disasm(
        agent: &SharedAgentClient,
        backend: ReBackend,
        args: &Value,
    ) -> Result<Value> {
        let address = Self::validate_address(args)?;
        let start_time = Instant::now();

        if address.is_none() {
            return Err(McpError::InvalidParams(
                "Missing 'address' parameter for disassembly".to_string(),
            ));
        }

        let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(20);

        // Validate reasonable count
        if count > 10000 {
            return Err(McpError::InvalidParams(
                "Count exceeds maximum of 10000 instructions".to_string(),
            ));
        }

        trace!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            address = format!("0x{:x}", address.unwrap()),
            count = count,
            "Handling disassembly"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let tool_name = format!("{}_disasm", backend.agent_prefix());
        let response = agent
            .request_with_reconnect(&tool_name, args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("{} disasm failed: {}", backend.name(), e)))?;

        debug!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            duration_ms = start_time.elapsed().as_millis(),
            "Disassembly completed"
        );

        Ok(response)
    }

    /// Handle RE decompile tools
    pub async fn handle_decompile(
        agent: &SharedAgentClient,
        backend: ReBackend,
        args: &Value,
    ) -> Result<Value> {
        let start_time = Instant::now();

        // Either address or name is required depending on backend
        let address = Self::validate_address(args)?;
        let name = args.get("name").and_then(|n| n.as_str());

        if address.is_none() && name.is_none() {
            return Err(McpError::InvalidParams(
                "Missing 'address' or 'name' parameter for decompilation".to_string(),
            ));
        }

        trace!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            address = ?address.map(|a| format!("0x{:x}", a)),
            name = ?name,
            "Handling decompilation"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let tool_name = format!("{}_decompile", backend.agent_prefix());
        let response = agent
            .request_with_reconnect(&tool_name, args.clone())
            .await
            .map_err(|e| {
                McpError::Handler(format!("{} decompile failed: {}", backend.name(), e))
            })?;

        info!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            duration_ms = start_time.elapsed().as_millis(),
            "Decompilation completed"
        );

        Ok(response)
    }

    /// Handle RE xref tools
    pub async fn handle_xref(
        agent: &SharedAgentClient,
        backend: ReBackend,
        args: &Value,
    ) -> Result<Value> {
        let address = Self::validate_address(args)?;
        let direction = Self::validate_xref_direction(args)?;

        if address.is_none() {
            return Err(McpError::InvalidParams(
                "Missing 'address' parameter for xref".to_string(),
            ));
        }

        trace!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            address = format!("0x{:x}", address.unwrap()),
            direction = %direction,
            "Handling xref"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let tool_name = match (backend, direction.as_str()) {
            (ReBackend::Radare2, "to") => "r2_xrefs_to",
            (ReBackend::Radare2, "from") => "r2_xrefs_from",
            (ReBackend::IdaPro, "to") => "ida_xrefs_to",
            (ReBackend::IdaPro, "from") => "ida_xrefs_from",
            (ReBackend::Ghidra, "to") => "ghidra_xrefs_to",
            (ReBackend::Ghidra, "from") => "ghidra_xrefs_from",
            _ => unreachable!("validated direction"),
        };
        let response = agent
            .request_with_reconnect(tool_name, args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("{} xref failed: {}", backend.name(), e)))?;

        Ok(response)
    }

    /// Handle r2_cmd raw command
    pub async fn handle_r2_cmd(agent: &SharedAgentClient, args: &Value) -> Result<Value> {
        let cmd = Self::validate_command(args)?;
        let start_time = Instant::now();

        // Warn about potentially dangerous commands
        let dangerous_prefixes = ["!", "=!", "=+", "o-", "oo"];
        for prefix in dangerous_prefixes {
            if cmd.starts_with(prefix) {
                warn!(
                    target: "ghost_static_mcp::re",
                    command = %cmd,
                    "Executing potentially dangerous r2 command"
                );
                break;
            }
        }

        debug!(
            target: "ghost_static_mcp::re",
            command = %cmd,
            "Executing r2 command"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let response = agent
            .request_with_reconnect("r2_cmd", args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("r2_cmd failed: {}", e)))?;

        debug!(
            target: "ghost_static_mcp::re",
            duration_ms = start_time.elapsed().as_millis(),
            "r2 command completed"
        );

        Ok(response)
    }

    /// Generic handler for simple RE tools that just need forwarding
    pub async fn handle_forward(
        agent: &SharedAgentClient,
        tool_name: &str,
        args: &Value,
    ) -> Result<Value> {
        let backend = ReBackend::from_tool_name(tool_name);
        let start_time = Instant::now();

        trace!(
            target: "ghost_static_mcp::re",
            tool = tool_name,
            backend = ?backend.map(|b| b.name()),
            "Forwarding RE tool"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let response = agent
            .request_with_reconnect(tool_name, args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("{} failed: {}", tool_name, e)))?;

        debug!(
            target: "ghost_static_mcp::re",
            tool = tool_name,
            duration_ms = start_time.elapsed().as_millis(),
            "RE tool completed"
        );

        Ok(response)
    }

    /// Handle Radare2 tools locally via ghost-re-backends (when enabled)
    #[cfg(feature = "radare2")]
    pub async fn handle_radare2_tool(name: &str, args: &Value) -> Result<Value> {
        match name {
            "r2_session" => {
                let action = Self::validate_session_action(args)?;
                match action.as_str() {
                    "open" => {
                        let path = Self::validate_path(args)?.ok_or_else(|| {
                            McpError::InvalidParams(
                                "Missing 'path' parameter for r2_session open".to_string(),
                            )
                        })?;
                        let mut backend = Self::radare2_backend().await;
                        let info: BinaryInfo = Self::map_r2_err(backend.open(&path).await)?;
                        Ok(json!({
                            "status": "opened",
                            "path": &path,
                            "binary": info
                        }))
                    }
                    "close" => {
                        let mut backend = Self::radare2_backend().await;
                        Self::map_r2_err(backend.close().await)?;
                        Ok(json!({ "status": "closed" }))
                    }
                    _ => unreachable!("validated action"),
                }
            }
            "r2_status" => {
                let backend = Self::radare2_backend().await;
                let connected = backend.is_connected();
                let info = if connected {
                    Self::map_r2_err(backend.get_binary_info().await).ok()
                } else {
                    None
                };
                Ok(json!({
                    "backend": "radare2",
                    "connected": connected,
                    "info": info
                }))
            }
            "r2_info" => {
                Self::ensure_radare2_session().await?;
                let backend = Self::radare2_backend().await;
                let info = Self::map_r2_err(backend.get_binary_info().await)?;
                Ok(json!({ "binary": info }))
            }
            "r2_functions" => {
                Self::ensure_radare2_session().await?;
                let backend = Self::radare2_backend().await;
                let mut functions = Self::map_r2_err(backend.list_functions().await)?;
                if let Some(filter) = args.get("filter").and_then(|f| f.as_str()) {
                    let filter_lower = filter.to_lowercase();
                    functions.retain(|f| f.name.to_lowercase().contains(&filter_lower));
                }
                Ok(json!({
                    "functions": functions,
                    "count": functions.len()
                }))
            }
            "r2_function" => {
                Self::ensure_radare2_session().await?;
                let address = Self::validate_address(args)?;
                let backend = Self::radare2_backend().await;
                let result = if let Some(addr) = address {
                    Self::map_r2_err(backend.get_function(addr).await)?
                } else if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
                    Self::map_r2_err(backend.get_function_by_name(name).await)?
                } else {
                    return Err(McpError::InvalidParams(
                        "Provide either 'address' or 'name' for r2_function".to_string(),
                    ));
                };

                Ok(json!({ "function": result }))
            }
            "r2_disasm" => {
                Self::ensure_radare2_session().await?;
                let address = require_address(args, "r2_disasm")?;
                let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(20);
                if count > 10_000 {
                    return Err(McpError::InvalidParams(
                        "Count exceeds maximum of 10000 instructions".to_string(),
                    ));
                }
                let backend = Self::radare2_backend().await;
                let instructions =
                    Self::map_r2_err(backend.disassemble(address, count as usize).await)?;
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "instructions": instructions
                }))
            }
            "r2_disasm_function" => {
                Self::ensure_radare2_session().await?;
                let address = require_address(args, "r2_disasm_function")?;
                let backend = Self::radare2_backend().await;
                let instructions = Self::map_r2_err(backend.disassemble_function(address).await)?;
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "instructions": instructions
                }))
            }
            "r2_decompile" => {
                Self::ensure_radare2_session().await?;
                let address = require_address(args, "r2_decompile")?;
                let backend = Self::radare2_backend().await;
                let func = Self::map_r2_err(backend.decompile(address).await)?;
                Ok(json!({ "function": func }))
            }
            "r2_strings" => {
                Self::ensure_radare2_session().await?;
                let min_length = Self::parse_min_length(args, 4);
                let backend = Self::radare2_backend().await;
                let strings = Self::map_r2_err(backend.list_strings(min_length).await)?;
                Ok(json!({ "strings": strings, "count": strings.len() }))
            }
            "r2_imports" => {
                Self::ensure_radare2_session().await?;
                let backend = Self::radare2_backend().await;
                let imports = Self::map_r2_err(backend.list_imports().await)?;
                Ok(json!({ "imports": imports, "count": imports.len() }))
            }
            "r2_exports" => {
                Self::ensure_radare2_session().await?;
                let backend = Self::radare2_backend().await;
                let exports = Self::map_r2_err(backend.list_exports().await)?;
                Ok(json!({ "exports": exports, "count": exports.len() }))
            }
            "r2_xref" => {
                Self::ensure_radare2_session().await?;
                let address = require_address(args, "r2_xref")?;
                let direction = Self::validate_xref_direction(args)?;
                let backend = Self::radare2_backend().await;
                let xrefs = match direction.as_str() {
                    "from" => Self::map_r2_err(backend.get_xrefs_from(address).await)?,
                    _ => Self::map_r2_err(backend.get_xrefs_to(address).await)?,
                };
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "direction": direction,
                    "xrefs": xrefs,
                    "count": xrefs.len()
                }))
            }
            "r2_read" => {
                Self::ensure_radare2_session().await?;
                let address = require_address(args, "r2_read")?;
                let size = args
                    .get("size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(256)
                    .min(1024 * 1024) as usize;
                let backend = Self::radare2_backend().await;
                let bytes = Self::map_r2_err(backend.read_bytes(address, size).await)?;
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "size": bytes.len(),
                    "bytes": hex::encode(&bytes)
                }))
            }
            "r2_cmd" => {
                Self::ensure_radare2_session().await?;
                let cmd = Self::validate_command(args)?;
                let mut backend = Self::radare2_backend().await;
                let output = Self::map_r2_err(backend.raw_command(&cmd).await)?;
                Ok(json!({
                    "command": cmd,
                    "output": output
                }))
            }
            other => Err(McpError::ToolNotFound(other.to_string())),
        }
    }

    /// Handle Ghidra tools locally via ghost-re-backends (when enabled)
    #[cfg(feature = "ghidra")]
    pub async fn handle_ghidra_tool(name: &str, args: &Value) -> Result<Value> {
        match name {
            "ghidra_session" => {
                let action = Self::validate_session_action(args)?;
                match action.as_str() {
                    "open" => {
                        let path = Self::validate_path(args)?.ok_or_else(|| {
                            McpError::InvalidParams(
                                "Missing 'path' parameter for ghidra_session open".to_string(),
                            )
                        })?;
                        let mut backend = Self::ghidra_backend().await;
                        let info: ghost_re_backends::BinaryInfo =
                            Self::map_ghidra_err(backend.open(&path).await)?;
                        Ok(json!({
                            "status": "opened",
                            "path": &path,
                            "binary": info
                        }))
                    }
                    "close" => {
                        let mut backend = Self::ghidra_backend().await;
                        Self::map_ghidra_err(backend.close().await)?;
                        Ok(json!({ "status": "closed" }))
                    }
                    _ => unreachable!("validated action"),
                }
            }
            "ghidra_status" => {
                let backend = Self::ghidra_backend().await;
                let connected = backend.is_connected();
                let info = if connected {
                    Self::map_ghidra_err(backend.get_binary_info().await).ok()
                } else {
                    None
                };
                Ok(json!({
                    "backend": "ghidra",
                    "connected": connected,
                    "info": info
                }))
            }
            "ghidra_info" => {
                Self::ensure_ghidra_session().await?;
                let backend = Self::ghidra_backend().await;
                let info = Self::map_ghidra_err(backend.get_binary_info().await)?;
                Ok(json!({ "binary": info }))
            }
            "ghidra_functions" => {
                Self::ensure_ghidra_session().await?;
                let backend = Self::ghidra_backend().await;
                let mut functions = Self::map_ghidra_err(backend.list_functions().await)?;
                if let Some(filter) = args.get("filter").and_then(|f| f.as_str()) {
                    let filter_lower = filter.to_lowercase();
                    functions.retain(|f| f.name.to_lowercase().contains(&filter_lower));
                }
                Ok(json!({
                    "functions": functions,
                    "count": functions.len()
                }))
            }
            "ghidra_function" => {
                Self::ensure_ghidra_session().await?;
                let address = require_address(args, "ghidra_function")?;
                let backend = Self::ghidra_backend().await;
                let func = Self::map_ghidra_err(backend.get_function(address).await)?;
                Ok(json!({ "function": func }))
            }
            "ghidra_disasm" => {
                Self::ensure_ghidra_session().await?;
                let address = require_address(args, "ghidra_disasm")?;
                let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(20);
                if count > 10_000 {
                    return Err(McpError::InvalidParams(
                        "Count exceeds maximum of 10000 instructions".to_string(),
                    ));
                }
                let backend = Self::ghidra_backend().await;
                let instructions =
                    Self::map_ghidra_err(backend.disassemble(address, count as usize).await)?;
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "instructions": instructions
                }))
            }
            "ghidra_decompile" => {
                Self::ensure_ghidra_session().await?;
                let address = require_address(args, "ghidra_decompile")?;
                let backend = Self::ghidra_backend().await;
                let func = Self::map_ghidra_err(backend.decompile(address).await)?;
                Ok(json!({ "function": func }))
            }
            "ghidra_strings" => {
                Self::ensure_ghidra_session().await?;
                let backend = Self::ghidra_backend().await;
                let strings = Self::map_ghidra_err(backend.list_strings(4).await)?;
                Ok(json!({ "strings": strings, "count": strings.len() }))
            }
            "ghidra_imports" => {
                Self::ensure_ghidra_session().await?;
                let backend = Self::ghidra_backend().await;
                let imports = Self::map_ghidra_err(backend.list_imports().await)?;
                Ok(json!({ "imports": imports, "count": imports.len() }))
            }
            "ghidra_exports" => {
                Self::ensure_ghidra_session().await?;
                let backend = Self::ghidra_backend().await;
                let exports = Self::map_ghidra_err(backend.list_exports().await)?;
                Ok(json!({ "exports": exports, "count": exports.len() }))
            }
            "ghidra_xref" => {
                Self::ensure_ghidra_session().await?;
                let address = require_address(args, "ghidra_xref")?;
                let direction = Self::validate_xref_direction(args)?;
                let backend = Self::ghidra_backend().await;
                let xrefs = match direction.as_str() {
                    "from" => Self::map_ghidra_err(backend.get_xrefs_from(address).await)?,
                    _ => Self::map_ghidra_err(backend.get_xrefs_to(address).await)?,
                };
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "direction": direction,
                    "xrefs": xrefs,
                    "count": xrefs.len()
                }))
            }
            other => Err(McpError::ToolNotFound(other.to_string())),
        }
    }

    /// Handle IDA tools locally via ghost-re-backends (when enabled)
    #[cfg(feature = "ida")]
    pub async fn handle_ida_tool(name: &str, args: &Value) -> Result<Value> {
        match name {
            "ida_session" => {
                let action = Self::validate_session_action(args)?;
                match action.as_str() {
                    "open" => {
                        let path = Self::validate_path(args)?.ok_or_else(|| {
                            McpError::InvalidParams(
                                "Missing 'path' parameter for ida_session open".to_string(),
                            )
                        })?;
                        let mut backend = Self::ida_backend().await;
                        let info: ghost_re_backends::BinaryInfo =
                            Self::map_ida_err(backend.open(&path).await)?;
                        Ok(json!({
                            "status": "opened",
                            "path": &path,
                            "binary": info
                        }))
                    }
                    "close" => {
                        let mut backend = Self::ida_backend().await;
                        let _ = Self::map_ida_err(backend.close().await)?;
                        Ok(json!({ "status": "closed" }))
                    }
                    _ => unreachable!("validated action"),
                }
            }
            "ida_status" => {
                let mut backend = Self::ida_backend().await;
                let connected = backend.is_connected();
                let info = if connected {
                    Self::map_ida_err(backend.get_binary_info().await).ok()
                } else {
                    None
                };
                Ok(json!({
                    "backend": "ida",
                    "connected": connected,
                    "info": info
                }))
            }
            "ida_info" => {
                Self::ensure_ida_session().await?;
                let mut backend = Self::ida_backend().await;
                let info = Self::map_ida_err(backend.get_binary_info().await)?;
                Ok(json!({ "binary": info }))
            }
            "ida_functions" => {
                Self::ensure_ida_session().await?;
                let mut backend = Self::ida_backend().await;
                let mut functions = Self::map_ida_err(backend.list_functions().await)?;
                if let Some(filter) = args.get("filter").and_then(|f| f.as_str()) {
                    let filter_lower = filter.to_lowercase();
                    functions.retain(|f| f.name.to_lowercase().contains(&filter_lower));
                }
                Ok(json!({
                    "functions": functions,
                    "count": functions.len()
                }))
            }
            "ida_function" => {
                Self::ensure_ida_session().await?;
                let address = require_address(args, "ida_function")?;
                let mut backend = Self::ida_backend().await;
                let func = Self::map_ida_err(backend.get_function(address).await)?;
                Ok(json!({ "function": func }))
            }
            "ida_disasm" => {
                Self::ensure_ida_session().await?;
                let address = require_address(args, "ida_disasm")?;
                let count = args.get("count").and_then(|c| c.as_u64()).unwrap_or(20);
                if count > 10_000 {
                    return Err(McpError::InvalidParams(
                        "Count exceeds maximum of 10000 instructions".to_string(),
                    ));
                }
                let mut backend = Self::ida_backend().await;
                let instructions =
                    Self::map_ida_err(backend.disassemble(address, count as usize).await)?;
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "instructions": instructions
                }))
            }
            "ida_decompile" => {
                Self::ensure_ida_session().await?;
                let address = require_address(args, "ida_decompile")?;
                let mut backend = Self::ida_backend().await;
                let func = Self::map_ida_err(backend.decompile(address).await)?;
                Ok(json!({ "function": func }))
            }
            "ida_strings" => {
                Self::ensure_ida_session().await?;
                let mut backend = Self::ida_backend().await;
                let strings = Self::map_ida_err(backend.list_strings(4).await)?;
                Ok(json!({ "strings": strings, "count": strings.len() }))
            }
            "ida_imports" => {
                Self::ensure_ida_session().await?;
                let mut backend = Self::ida_backend().await;
                let imports = Self::map_ida_err(backend.list_imports().await)?;
                Ok(json!({ "imports": imports, "count": imports.len() }))
            }
            "ida_exports" => {
                Self::ensure_ida_session().await?;
                let mut backend = Self::ida_backend().await;
                let exports = Self::map_ida_err(backend.list_exports().await)?;
                Ok(json!({ "exports": exports, "count": exports.len() }))
            }
            "ida_xref" => {
                Self::ensure_ida_session().await?;
                let address = require_address(args, "ida_xref")?;
                let direction = Self::validate_xref_direction(args)?;
                let mut backend = Self::ida_backend().await;
                let xrefs = match direction.as_str() {
                    "from" => Self::map_ida_err(backend.get_xrefs_from(address).await)?,
                    _ => Self::map_ida_err(backend.get_xrefs_to(address).await)?,
                };
                Ok(json!({
                    "address": format!("0x{:X}", address),
                    "direction": direction,
                    "xrefs": xrefs,
                    "count": xrefs.len()
                }))
            }
            other => Err(McpError::ToolNotFound(other.to_string())),
        }
    }

    /// Fallback Radare2 handler when backend is disabled
    #[cfg(not(feature = "radare2"))]
    pub async fn handle_radare2_tool(name: &str, _args: &Value) -> Result<Value> {
        Err(McpError::Handler(format!(
            "Radare2 backend support is disabled. Rebuild ghost-static-mcp with the 'radare2' feature to use {}",
            name
        )))
    }

    /// Fallback Ghidra handler when backend is disabled
    #[cfg(not(feature = "ghidra"))]
    pub async fn handle_ghidra_tool(name: &str, _args: &Value) -> Result<Value> {
        Err(McpError::Handler(format!(
            "Ghidra backend support is disabled. Rebuild ghost-static-mcp with the 'ghidra' feature to use {}",
            name
        )))
    }

    /// Fallback IDA handler when backend is disabled
    #[cfg(not(feature = "ida"))]
    pub async fn handle_ida_tool(name: &str, _args: &Value) -> Result<Value> {
        Err(McpError::Handler(format!(
            "IDA backend support is disabled. Rebuild ghost-static-mcp with the 'ida' feature to use {}",
            name
        )))
    }

    /// Check if a tool is an RE backend tool
    pub fn is_re_tool(name: &str) -> bool {
        name.starts_with("r2_") || name.starts_with("ida_") || name.starts_with("ghidra_")
    }

    /// Handle status tools locally (no agent required)
    pub async fn handle_status(backend: ReBackend) -> Result<Value> {
        // Status tools return local state - RE backends are optional
        // Return "not configured" status since these are optional integrations
        let status = serde_json::json!({
            "backend": backend.name(),
            "available": false,
            "message": format!("{} backend is not configured. Install and configure the {} integration to enable these features.",
                match backend {
                    ReBackend::Radare2 => "Radare2",
                    ReBackend::IdaPro => "IDA Pro",
                    ReBackend::Ghidra => "Ghidra",
                },
                backend.name()
            ),
            "session": null
        });

        debug!(
            target: "ghost_static_mcp::re",
            backend = backend.name(),
            "Returning RE backend status (not configured)"
        );

        Ok(status)
    }

    /// Handle info tools locally (no agent required)
    pub async fn handle_info(backend: ReBackend) -> Result<Value> {
        // Info tools return backend capabilities
        let info = serde_json::json!({
            "backend": backend.name(),
            "available": false,
            "version": null,
            "capabilities": match backend {
                ReBackend::Radare2 => vec!["disasm", "decompile", "xref", "strings", "functions", "imports", "exports", "cmd"],
                ReBackend::IdaPro => vec!["disasm", "decompile", "xref", "strings", "functions", "imports", "exports"],
                ReBackend::Ghidra => vec!["disasm", "decompile", "xref", "strings", "functions", "imports", "exports"],
            },
            "message": format!("{} backend not configured", backend.name())
        });

        Ok(info)
    }

    /// Route RE tool to appropriate handler
    pub async fn route_re_tool(
        agent: &SharedAgentClient,
        name: &str,
        args: &Value,
    ) -> Result<Value> {
        let backend = ReBackend::from_tool_name(name);

        match (backend, name) {
            // Radare2 tools handled locally when enabled
            (Some(ReBackend::Radare2), _) => Self::handle_radare2_tool(name, args).await,

            // Ghidra tools handled locally when enabled
            (Some(ReBackend::Ghidra), _) => Self::handle_ghidra_tool(name, args).await,

            // IDA tools handled locally when enabled
            (Some(ReBackend::IdaPro), _) => Self::handle_ida_tool(name, args).await,

            // // Status tools - handled locally (no agent needed)
            // (Some(b), n) if n.ends_with("_status") => Self::handle_status(b).await,

            // // Info tools - handled locally (no agent needed)
            // (Some(b), n) if n.ends_with("_info") => Self::handle_info(b).await,

            // // Session tools
            // (Some(b), n) if n.ends_with("_session") => Self::handle_session(agent, b, args).await,

            // // Disasm tools
            // (Some(b), n) if n.ends_with("_disasm") => Self::handle_disasm(agent, b, args).await,

            // // Decompile tools
            // (Some(b), n) if n.ends_with("_decompile") => {
            //     Self::handle_decompile(agent, b, args).await
            // }

            // // Xref tools
            // (Some(b), n) if n.ends_with("_xref") => Self::handle_xref(agent, b, args).await,

            // All other RE tools - simple forward (should not happen)
            _ => Self::handle_forward(agent, name, args).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_backend_from_tool_name() {
        assert_eq!(
            ReBackend::from_tool_name("r2_disasm"),
            Some(ReBackend::Radare2)
        );
        assert_eq!(
            ReBackend::from_tool_name("ida_decompile"),
            Some(ReBackend::IdaPro)
        );
        assert_eq!(
            ReBackend::from_tool_name("ghidra_functions"),
            Some(ReBackend::Ghidra)
        );
        assert_eq!(ReBackend::from_tool_name("trace_events"), None);
    }

    #[test]
    fn test_backend_name() {
        assert_eq!(ReBackend::Radare2.name(), "radare2");
        assert_eq!(ReBackend::IdaPro.name(), "ida");
        assert_eq!(ReBackend::Ghidra.name(), "ghidra");
    }

    #[test]
    fn test_validate_path_valid() {
        let args = json!({ "path": "/tmp/binary.exe" });
        let result = ReHandler::validate_path(&args).unwrap();
        assert_eq!(result, Some("/tmp/binary.exe".to_string()));
    }

    #[test]
    fn test_validate_path_missing() {
        let args = json!({});
        let result = ReHandler::validate_path(&args).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_validate_path_too_long() {
        let long_path = "a".repeat(MAX_PATH_LEN + 1);
        let args = json!({ "path": long_path });
        assert!(ReHandler::validate_path(&args).is_err());
    }

    #[test]
    fn test_validate_path_null_char() {
        let args = json!({ "path": "test\0path" });
        assert!(ReHandler::validate_path(&args).is_err());
    }

    #[test]
    fn test_validate_address_hex_string() {
        let args = json!({ "address": "0x12345678" });
        let result = ReHandler::validate_address(&args).unwrap();
        assert_eq!(result, Some(0x12345678));
    }

    #[test]
    fn test_validate_address_number() {
        let args = json!({ "address": 0x12345678_u64 });
        let result = ReHandler::validate_address(&args).unwrap();
        assert_eq!(result, Some(0x12345678));
    }

    #[test]
    fn test_validate_address_too_low() {
        let args = json!({ "address": "0x100" });
        assert!(ReHandler::validate_address(&args).is_err());
    }

    #[test]
    fn test_validate_address_missing() {
        let args = json!({});
        let result = ReHandler::validate_address(&args).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_validate_command_valid() {
        let args = json!({ "command": "afl" });
        let result = ReHandler::validate_command(&args).unwrap();
        assert_eq!(result, "afl");
    }

    #[test]
    fn test_validate_command_missing() {
        let args = json!({});
        assert!(ReHandler::validate_command(&args).is_err());
    }

    #[test]
    fn test_validate_command_empty() {
        let args = json!({ "command": "" });
        assert!(ReHandler::validate_command(&args).is_err());
    }

    #[test]
    fn test_validate_command_too_long() {
        let long_cmd = "a".repeat(MAX_CMD_LEN + 1);
        let args = json!({ "command": long_cmd });
        assert!(ReHandler::validate_command(&args).is_err());
    }

    #[test]
    fn test_validate_session_action_open() {
        let args = json!({ "action": "open" });
        let result = ReHandler::validate_session_action(&args).unwrap();
        assert_eq!(result, "open");
    }

    #[test]
    fn test_validate_session_action_close() {
        let args = json!({ "action": "close" });
        let result = ReHandler::validate_session_action(&args).unwrap();
        assert_eq!(result, "close");
    }

    #[test]
    fn test_validate_session_action_invalid() {
        let args = json!({ "action": "invalid" });
        assert!(ReHandler::validate_session_action(&args).is_err());
    }

    #[test]
    fn test_validate_xref_direction_to() {
        let args = json!({ "direction": "to" });
        let result = ReHandler::validate_xref_direction(&args).unwrap();
        assert_eq!(result, "to");
    }

    #[test]
    fn test_validate_xref_direction_from() {
        let args = json!({ "direction": "from" });
        let result = ReHandler::validate_xref_direction(&args).unwrap();
        assert_eq!(result, "from");
    }

    #[test]
    fn test_validate_xref_direction_default() {
        let args = json!({});
        let result = ReHandler::validate_xref_direction(&args).unwrap();
        assert_eq!(result, "to");
    }

    #[test]
    fn test_validate_xref_direction_invalid() {
        let args = json!({ "direction": "both" });
        assert!(ReHandler::validate_xref_direction(&args).is_err());
    }

    #[test]
    fn test_is_re_tool() {
        assert!(ReHandler::is_re_tool("r2_disasm"));
        assert!(ReHandler::is_re_tool("ida_decompile"));
        assert!(ReHandler::is_re_tool("ghidra_functions"));
        assert!(!ReHandler::is_re_tool("trace_events"));
        assert!(!ReHandler::is_re_tool("ai_summarize"));
    }

    #[test]
    fn test_validate_filter_valid() {
        let args = json!({ "filter": "main*" });
        let result = ReHandler::validate_filter(&args, "filter").unwrap();
        assert_eq!(result, Some("main*".to_string()));
    }

    #[test]
    fn test_validate_filter_missing() {
        let args = json!({});
        let result = ReHandler::validate_filter(&args, "filter").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_validate_filter_too_long() {
        let long_filter = "a".repeat(MAX_FILTER_LEN + 1);
        let args = json!({ "filter": long_filter });
        assert!(ReHandler::validate_filter(&args, "filter").is_err());
    }
}
