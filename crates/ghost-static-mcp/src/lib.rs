//! Ghost-MCP Static Analysis Server
//!
//! Port 13342 - 84 tools for static RE, AI assistance, and API tracing.
//!
//! # Categories (consolidated per roadmap)
//! - Radare2 (14): r2_session, r2_status, r2_info, r2_functions, r2_function, r2_disasm, r2_disasm_function, r2_decompile, r2_strings, r2_imports, r2_exports, r2_xref, r2_read, r2_cmd
//! - IDA Pro (11): ida_session, ida_status, ida_info, ida_functions, ida_function, ida_disasm, ida_decompile, ida_strings, ida_imports, ida_exports, ida_xref
//! - Ghidra (11): ghidra_session, ghidra_status, ghidra_info, ghidra_functions, ghidra_function, ghidra_disasm, ghidra_decompile, ghidra_strings, ghidra_imports, ghidra_exports, ghidra_xref
//! - API Trace (19): trace_session_*, trace_control, trace_events*, trace_stats*, trace_filter*, trace_preset*, trace_pack*, trace_hooks_list
//! - AI Tools (12): ai_*, debug_session_*
//! - YARA/Pattern (13): yara_*, find_instructions, signature_db_*
//! - Meta Shared (4): mcp_capabilities, mcp_documentation, mcp_version, mcp_health
//!
//! # Implementation Notes
//! - RE backend routing for Radare2, IDA Pro, and Ghidra tools
//! - All tools forwarded to agent with proper validation and logging
//! - Production hardening with input validation and defensive programming

pub mod handlers;
pub mod tools;

use crate::handlers::ReHandler;
#[cfg(feature = "yara")]
use ghost_common::types::pattern::YaraScanOptions;
use ghost_common::types::{
    ai::{
        AiError, AiSummary, BreakpointRecommendation, ChangeReport, ChangeType, LearnedPattern,
        LearnedPatternType, VulnerabilityReport, VulnerabilityType,
    },
    api_trace::{StringPattern, TraceFilter, TraceSessionConfig, TraceSessionId},
    breakpoint::BreakpointType,
    memory::{MemoryRegion, MemoryState, MemoryType},
    pattern::{PatternScanOptions, PatternScanType, SignatureDatabase, SignaturePattern, YaraRule},
};
use ghost_common::{Error as GhostError, Instruction, Protection};
use ghost_core::{api_trace::ApiTracer, disasm, PatternScanner};
use ghost_mcp_common::ipc::SharedAgentClient;
use ghost_mcp_common::server::ToolHandlerFn;
use ghost_mcp_common::{
    error::{McpError, Result},
    McpServer, ServerConfig, ServerIdentity, ToolRegistry,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};

/// Expected tool count for ghost-static-mcp (84 tools)
pub const EXPECTED_TOOL_COUNT: usize = 84;
/// Expected registry count excluding shared meta (4)
pub const EXPECTED_REGISTRY_COUNT: usize = 80;

/// Port for ghost-static-mcp
pub const PORT: u16 = 13342;

/// Create and configure the tool registry for ghost-static-mcp
///
/// # Errors
/// Returns an error if tool registration fails (e.g., duplicate tool names,
/// exceeding the 90-tool limit).
pub fn create_registry() -> Result<ToolRegistry> {
    debug!(target: "ghost_static_mcp", "Creating tool registry");
    let mut registry = ToolRegistry::new();

    // Register tools by category with error context
    register_category(&mut registry, "radare2", tools::radare2::register)?;
    register_category(&mut registry, "ida", tools::ida::register)?;
    register_category(&mut registry, "ghidra", tools::ghidra::register)?;
    register_category(&mut registry, "trace", tools::trace::register)?;
    register_category(&mut registry, "ai", tools::ai::register)?;
    register_category(&mut registry, "yara", tools::yara::register)?;

    // Validate final count
    let tool_count = registry.len();
    if tool_count > ghost_mcp_common::MAX_TOOLS_PER_SERVER {
        error!(
            target: "ghost_static_mcp",
            "Registry exceeds limit: {} > {}",
            tool_count,
            ghost_mcp_common::MAX_TOOLS_PER_SERVER
        );
        return Err(McpError::ToolCountExceeded {
            count: tool_count,
            max: ghost_mcp_common::MAX_TOOLS_PER_SERVER,
        });
    }

    // Assert exact expected registry count (excludes shared meta tools)
    if tool_count != EXPECTED_REGISTRY_COUNT {
        return Err(McpError::Registry(format!(
            "Registry count mismatch: got {}, expected {} (registry only, shared meta not included)",
            tool_count, EXPECTED_REGISTRY_COUNT
        )));
    }

    info!(
        target: "ghost_static_mcp",
        "Registry created: {} tools (target: {}, limit: {})",
        tool_count,
        EXPECTED_TOOL_COUNT,
        ghost_mcp_common::MAX_TOOLS_PER_SERVER
    );

    Ok(registry)
}

/// Helper to register a category with logging and error context
fn register_category(
    registry: &mut ToolRegistry,
    category: &str,
    register_fn: fn(&mut ToolRegistry) -> Result<()>,
) -> Result<()> {
    let before = registry.len();
    register_fn(registry).map_err(|e| {
        error!(target: "ghost_static_mcp", "Failed to register {} tools: {}", category, e);
        e
    })?;
    let added = registry.len() - before;
    debug!(target: "ghost_static_mcp", "Registered {} {} tools", added, category);
    Ok(())
}

/// Create the MCP server for ghost-static-mcp
pub fn create_server() -> Result<McpServer> {
    let server = McpServer::new(
        ServerIdentity::static_analysis(),
        ServerConfig::static_analysis(),
    );

    Ok(server)
}

/// Maximum tool name length for validation
const MAX_TOOL_NAME_LEN: usize = 128;

/// Maximum arguments size in bytes
const MAX_ARGS_SIZE: usize = 1024 * 1024; // 1 MB

/// Maximum bytes we will read from a module for pattern/YARA scanning
const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024; // 32 MB cap to avoid abuse

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DebugSession {
    id: String,
    name: Option<String>,
    goal: String,
    findings: Vec<String>,
    created_at: u64,
    updated_at: u64,
    summary: Option<String>,
    closed: bool,
}

impl DebugSession {
    fn new(id: String, goal: String, name: Option<String>) -> Self {
        let now = now_millis();
        Self {
            id,
            name,
            goal,
            findings: Vec::new(),
            created_at: now,
            updated_at: now,
            summary: None,
            closed: false,
        }
    }
}

#[derive(Default, Debug)]
struct AiState {
    patterns: HashMap<String, LearnedPattern>,
    next_pattern_id: u32,
    debug_sessions: HashMap<String, DebugSession>,
    next_debug_id: u32,
}

#[derive(Default)]
struct LocalState {
    tracer: ApiTracer,
    scanner: PatternScanner,
    ai: AiState,
    yara_rules: HashMap<String, YaraRule>,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[allow(dead_code)]
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[allow(dead_code)]
fn next_id(prefix: &str) -> String {
    format!("{}-{}", prefix, NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

fn parse_trace_session_id(value: &serde_json::Value) -> Result<TraceSessionId> {
    if let Some(n) = value.as_u64() {
        return Ok(TraceSessionId(n as u32));
    }

    if let Some(s) = value.as_str() {
        if let Ok(id) = s.parse::<u32>() {
            return Ok(TraceSessionId(id));
        }
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        if let Ok(id) = digits.parse::<u32>() {
            return Ok(TraceSessionId(id));
        }
    }

    Err(McpError::InvalidParams(
        "Invalid or missing session_id".to_string(),
    ))
}

fn string_patterns_from_value(value: &serde_json::Value) -> Vec<StringPattern> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| {
                    if s.contains('*') || s.contains('?') {
                        StringPattern::Wildcard(s.to_string())
                    } else {
                        StringPattern::Prefix(s.to_string())
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn read_module_bytes(module: &str) -> Result<Vec<u8>> {
    let path = Path::new(module);
    if !path.exists() {
        return Err(McpError::InvalidParams(format!(
            "Module path not found: {}",
            module
        )));
    }
    let metadata = fs::metadata(path)
        .map_err(|e| McpError::Handler(format!("Failed to read metadata for {}: {}", module, e)))?;
    if metadata.len() as usize > MAX_SCAN_BYTES {
        return Err(McpError::Handler(format!(
            "Module too large ({} bytes > {} max)",
            metadata.len(),
            MAX_SCAN_BYTES
        )));
    }
    fs::read(path)
        .map_err(|e| McpError::Handler(format!("Failed to read module '{}': {}", module, e)))
}

fn memory_region_for_len(len: usize) -> MemoryRegion {
    MemoryRegion {
        base: 0,
        size: len,
        protection: Protection::new(true, false, false),
        state: MemoryState::Commit,
        region_type: MemoryType::Private,
    }
}

fn read_buffer<'a>(data: &'a [u8]) -> impl Fn(usize, usize) -> ghost_common::Result<Vec<u8>> + 'a {
    move |addr, size| {
        if addr >= data.len() {
            return Err(GhostError::Internal("Read out of range".into()));
        }
        let end = min(data.len(), addr.saturating_add(size));
        Ok(data[addr..end].to_vec())
    }
}

fn bump_version(current: &str) -> String {
    let mut parts: Vec<u32> = current
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();
    while parts.len() < 3 {
        parts.push(0);
    }
    if let Some(last) = parts.last_mut() {
        *last = last.saturating_add(1);
    }
    format!("{}.{}.{}", parts[0], parts[1], parts[2])
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut regex_pattern = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex_pattern.push_str(".*"),
            '?' => regex_pattern.push('.'),
            _ => regex_pattern.push_str(&regex::escape(&ch.to_string())),
        }
    }
    regex_pattern.push('$');
    Regex::new(&regex_pattern)
        .map(|r| r.is_match(text))
        .unwrap_or(false)
}

fn disassemble_buffer(
    data: &[u8],
    base: u64,
    bitness: u32,
    max_instructions: usize,
) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut ip = base;
    while offset < data.len() && out.len() < max_instructions {
        let remaining = &data[offset..];
        match disasm::analyze_instruction(remaining, ip, bitness) {
            Ok(info) => {
                let len = info.length.max(1);
                out.push(Instruction {
                    address: info.address as usize,
                    bytes: info.bytes.clone(),
                    mnemonic: info.mnemonic.clone(),
                    operands: info.operands.clone(),
                });
                offset = offset.saturating_add(len);
                ip = ip.saturating_add(len as u64);
            }
            Err(_) => {
                // Skip one byte and retry to avoid infinite loops on undecodable sequences
                offset += 1;
                ip = ip.saturating_add(1);
            }
        }
    }
    out
}

/// Static analysis tool handler with RE backend routing
///
/// RE backend routing for Radare2, IDA Pro, and Ghidra tools.
#[derive(Clone)]
struct StaticToolHandler {
    state: Arc<Mutex<LocalState>>,
}

impl Default for StaticToolHandler {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(LocalState::default())),
        }
    }
}

impl StaticToolHandler {
    #[allow(clippy::if_same_then_else)]
    fn unsupported_reason(_name: &str) -> Option<&'static str> {
        // All tools supported - kept for future extension
        None
    }
}

impl ToolHandlerFn for StaticToolHandler {
    fn handle(
        &self,
        name: String,
        args: serde_json::Value,
        agent: SharedAgentClient,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send>> {
        let state = self.state.clone();
        Box::pin(async move {
            let start_time = Instant::now();

            // Defensive: validate tool name
            if name.is_empty() {
                warn!(target: "ghost_static_mcp", "Tool call with empty tool name");
                return Err(McpError::InvalidParams("Missing tool name".to_string()));
            }

            if name.len() > MAX_TOOL_NAME_LEN {
                warn!(target: "ghost_static_mcp", tool_len = name.len(), "Tool name too long");
                return Err(McpError::InvalidParams(format!(
                    "Tool name exceeds maximum length of {} characters",
                    MAX_TOOL_NAME_LEN
                )));
            }

            // Defensive: validate args size
            let args_str = args.to_string();
            if args_str.len() > MAX_ARGS_SIZE {
                warn!(target: "ghost_static_mcp", args_len = args_str.len(), "Arguments too large");
                return Err(McpError::InvalidParams(format!(
                    "Arguments exceed maximum size of {} bytes",
                    MAX_ARGS_SIZE
                )));
            }

            trace!(target: "ghost_static_mcp", tool = %name, "Processing tool call");

            // Route to specialized handlers
            let result = if ReHandler::is_re_tool(&name) {
                // RE tools (Radare2, IDA Pro, Ghidra) - route through ReHandler
                ReHandler::route_re_tool(&agent, &name, &args).await
            } else if name.starts_with("trace_") {
                StaticToolHandler::handle_trace_tool(&state, &name, &args).await
            } else if name.starts_with("ai_") || name.starts_with("debug_session_") {
                StaticToolHandler::handle_ai_tool(&state, &name, &args).await
            } else if name.starts_with("yara_")
                || name.starts_with("signature_db_")
                || name == "find_instructions"
            {
                StaticToolHandler::handle_yara_tool(&state, &name, &args).await
            } else if let Some(reason) = StaticToolHandler::unsupported_reason(&name) {
                Err(McpError::Handler(reason.to_string()))
            } else {
                // All other tools (trace, ai, yara) - forward to agent
                if !agent.is_connected() {
                    let _ = agent.connect().await;
                }

                let response = agent
                    .request_with_reconnect(&name, args.clone())
                    .await
                    .map_err(|e| McpError::Handler(e.to_string()))?;

                Ok(response)
            };

            let duration_ms = start_time.elapsed().as_millis();
            match &result {
                Ok(_) => {
                    debug!(
                        target: "ghost_static_mcp",
                        tool = %name,
                        duration_ms = duration_ms,
                        "Tool call completed"
                    );
                }
                Err(e) => {
                    error!(
                        target: "ghost_static_mcp",
                        tool = %name,
                        error = %e,
                        duration_ms = duration_ms,
                        "Tool call failed"
                    );
                }
            }

            result
        })
    }
}

impl StaticToolHandler {
    async fn handle_trace_tool(
        state: &Arc<Mutex<LocalState>>,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut st = state.lock().await;
        match name {
            "trace_session_create" => {
                let mut config = TraceSessionConfig::default();
                if let Some(n) = args.get("name").and_then(|v| v.as_str()) {
                    config.name = n.to_string();
                }
                let id = st.tracer.create_session(config);
                let info = st.tracer.get_session(id).map(|s| s.info());
                Ok(json!({
                    "session_id": id.0.to_string(),
                    "session": info
                }))
            }
            "trace_control" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                let action = args
                    .get("action")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing action".to_string()))?;

                let result = match action {
                    "start" => st
                        .tracer
                        .start_session(session_id)
                        .map(|res| json!({ "session_id": session_id.0.to_string(), "started": true, "hooks_installed": res.hooks_installed, "failed_hooks": res.failed_hooks })),
                    "stop" => st.tracer.stop_session(session_id).map(|_| {
                        json!({ "session_id": session_id.0.to_string(), "stopped": true })
                    }),
                    "pause" => st.tracer.pause_session(session_id).map(|_| {
                        json!({ "session_id": session_id.0.to_string(), "paused": true })
                    }),
                    "resume" => st.tracer.resume_session(session_id).map(|_| {
                        json!({ "session_id": session_id.0.to_string(), "resumed": true })
                    }),
                    _ => Err(GhostError::Internal(format!(
                        "Unsupported action '{}'",
                        action
                    ))),
                }
                .map_err(|e| McpError::Handler(e.to_string()))?;

                Ok(result)
            }
            "trace_session_close" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                st.tracer
                    .remove_session_traces(session_id)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                let closed = st
                    .tracer
                    .close_session(session_id)
                    .map(|_| true)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "session_id": session_id.0.to_string(), "closed": closed }))
            }
            "trace_session_list" => {
                let sessions = st.tracer.list_sessions();
                Ok(json!({ "sessions": sessions }))
            }
            "trace_session_info" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                if let Some(sess) = st.tracer.get_session(session_id) {
                    Ok(json!({ "session": sess.info() }))
                } else {
                    Err(McpError::ToolNotFound(session_id.0.to_string()))
                }
            }
            "trace_events" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                let filter = args
                    .get("filter")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let session = st
                    .tracer
                    .get_session_mut(session_id)
                    .ok_or_else(|| McpError::ToolNotFound(session_id.0.to_string()))?;

                let mut events = session.get_events(limit, 0);
                if let Some(f) = filter {
                    let matched: Vec<_> = events
                        .events
                        .into_iter()
                        .filter(|e| wildcard_match(&f, &e.function_name))
                        .collect();
                    let total = matched.len() as u64;
                    events = ghost_common::types::api_trace::TraceEventsResult {
                        events: matched,
                        total_count: total,
                        has_more: false,
                        continuation: None,
                    };
                }

                Ok(json!({
                    "session_id": session_id.0.to_string(),
                    "events": events.events,
                    "count": events.total_count,
                    "has_more": events.has_more,
                    "continuation": events.continuation
                }))
            }
            "trace_events_clear" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                let session = st
                    .tracer
                    .get_session_mut(session_id)
                    .ok_or_else(|| McpError::ToolNotFound(session_id.0.to_string()))?;
                let existing = session.get_events(usize::MAX, 0).total_count;
                session.clear_events();
                Ok(json!({ "cleared": true, "count": existing }))
            }
            "trace_stats" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                let stats = st
                    .tracer
                    .get_stats(session_id)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "session_id": session_id.0.to_string(), "stats": stats }))
            }
            "trace_queue_stats" => {
                let mut total = ghost_common::types::api_trace::QueueStats::default();
                for info in st.tracer.list_sessions() {
                    total.current_depth += info.stats.current_depth;
                    total.max_depth = total.max_depth.max(info.stats.max_depth);
                    total.total_captured += info.stats.total_captured;
                    total.total_dropped += info.stats.total_dropped;
                    total.events_per_second += info.stats.events_per_second;
                    total.memory_bytes += info.stats.memory_bytes;
                }
                Ok(json!({ "queue": total }))
            }
            "trace_filter_set" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                let include = string_patterns_from_value(args.get("include").unwrap_or(&json!([])));
                let exclude = string_patterns_from_value(args.get("exclude").unwrap_or(&json!([])));

                let session = st
                    .tracer
                    .get_session_mut(session_id)
                    .ok_or_else(|| McpError::ToolNotFound(session_id.0.to_string()))?;
                let filter = TraceFilter {
                    include_apis: include,
                    exclude_apis: exclude,
                    ..TraceFilter::default()
                };
                session.update_filter(filter.clone());
                Ok(json!({ "session_id": session_id.0.to_string(), "filter": filter }))
            }
            "trace_preset_list" => {
                let presets: Vec<_> = st
                    .tracer
                    .list_presets()
                    .into_iter()
                    .map(|p| json!({ "id": p.id.0, "name": p.name, "builtin": p.builtin }))
                    .collect();
                Ok(json!({ "presets": presets }))
            }
            "trace_preset_apply" => {
                let session_value = args
                    .get("session_id")
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let session_id = parse_trace_session_id(session_value)?;
                let preset_name = args
                    .get("preset")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing preset".to_string()))?;

                let preset = st
                    .tracer
                    .list_presets()
                    .into_iter()
                    .find(|p| p.name.eq_ignore_ascii_case(preset_name))
                    .ok_or_else(|| McpError::ToolNotFound(preset_name.to_string()))?
                    .clone();

                st.tracer
                    .apply_preset(session_id, preset.id)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "session_id": session_id.0.to_string(), "preset": preset.name }))
            }
            "trace_preset_create" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing name".to_string()))?;
                let apis = string_patterns_from_value(args.get("apis").unwrap_or(&json!([])));
                let filter = TraceFilter {
                    include_apis: apis,
                    ..TraceFilter::default()
                };
                let id = st
                    .tracer
                    .create_preset(name.to_string(), None, filter.clone());
                Ok(json!({ "preset_id": id.0, "name": name, "filter": filter }))
            }
            "trace_preset_delete" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing name".to_string()))?;
                let preset = st
                    .tracer
                    .list_presets()
                    .into_iter()
                    .find(|p| p.name.eq_ignore_ascii_case(name))
                    .cloned()
                    .ok_or_else(|| McpError::ToolNotFound(name.to_string()))?;
                st.tracer
                    .delete_preset(preset.id)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "deleted": true, "name": preset.name }))
            }
            "trace_pack_list" => {
                let packs = st.tracer.list_packs();
                Ok(json!({ "packs": packs }))
            }
            "trace_pack_info" => {
                let pack_name = args
                    .get("pack")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing pack".to_string()))?;
                let info = st
                    .tracer
                    .list_packs()
                    .into_iter()
                    .find(|p| p.id.0 == pack_name || p.name.eq_ignore_ascii_case(pack_name))
                    .ok_or_else(|| McpError::ToolNotFound(pack_name.to_string()))?;
                Ok(json!({ "pack": info }))
            }
            "trace_pack_load" => {
                let pack = args
                    .get("pack")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing pack".to_string()))?;
                let path = Path::new(pack);
                if path.exists() {
                    let id = st
                        .tracer
                        .pack_manager_mut()
                        .load_pack_from_file(path)
                        .map_err(|e| McpError::Handler(e.to_string()))?;
                    Ok(json!({ "loaded": true, "pack": id }))
                } else {
                    Err(McpError::InvalidParams(format!(
                        "Pack file not found: {}",
                        pack
                    )))
                }
            }
            "trace_pack_unload" => {
                let pack = args
                    .get("pack")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing pack".to_string()))?;
                st.tracer
                    .pack_manager_mut()
                    .unload_pack(&ghost_common::types::api_trace::ApiPackId(pack.to_string()))
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "unloaded": true, "pack": pack }))
            }
            "trace_hooks_list" => {
                let mut hooks = Vec::new();
                for sess in st.tracer.list_sessions() {
                    if let Some(s) = st.tracer.get_session(sess.id) {
                        for hook in s.get_hooks() {
                            hooks.push(json!({
                                "session_id": sess.id.0,
                                "hook": hook
                            }));
                        }
                    }
                }
                Ok(json!({ "hooks": hooks }))
            }
            _ => Err(McpError::ToolNotFound(name.to_string())),
        }
    }

    async fn handle_ai_tool(
        state: &Arc<Mutex<LocalState>>,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut st = state.lock().await;
        match name {
            "ai_summarize" => {
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if content.is_empty() {
                    return Err(McpError::InvalidParams(
                        "content is required for ai_summarize".to_string(),
                    ));
                }
                let context = args.get("context").and_then(|v| v.as_str());
                let lines: Vec<_> = content.lines().collect();
                let brief = format!("{} lines, {} chars", lines.len(), content.len());
                let mut key_points = lines
                    .iter()
                    .filter_map(|l| {
                        let t = l.trim();
                        if t.is_empty() {
                            None
                        } else {
                            Some(t.chars().take(160).collect::<String>())
                        }
                    })
                    .take(4)
                    .collect::<Vec<_>>();
                if key_points.is_empty() {
                    key_points.push("No obvious highlights extracted".to_string());
                }
                let suggestions = vec![
                    "Set breakpoints on control-flow boundaries".to_string(),
                    "Capture inputs to confirm assumptions".to_string(),
                    "Compare against known-good paths".to_string(),
                ];
                let detailed = format!(
                    "Summary derived from {} lines{}.",
                    lines.len(),
                    context
                        .map(|c| format!(" with context '{}'", c))
                        .unwrap_or_default()
                );
                let summary = AiSummary {
                    brief,
                    detailed,
                    key_points,
                    suggestions,
                    related_tools: vec![
                        "trace_session_create".to_string(),
                        "trace_events".to_string(),
                        "find_instructions".to_string(),
                    ],
                    confidence: 0.62,
                };
                Ok(json!({ "summary": summary }))
            }
            "ai_diff" => {
                let before = args.get("before").and_then(|v| v.as_str()).unwrap_or("");
                let after = args.get("after").and_then(|v| v.as_str()).unwrap_or("");
                let before_set: HashSet<_> = before.lines().collect();
                let after_set: HashSet<_> = after.lines().collect();

                let added: Vec<_> = after_set
                    .difference(&before_set)
                    .take(50)
                    .map(|s| json!(*s))
                    .collect();
                let removed: Vec<_> = before_set
                    .difference(&after_set)
                    .take(50)
                    .map(|s| json!(*s))
                    .collect();
                let unchanged_count = before_set.intersection(&after_set).count();

                let summary = format!(
                    "{} added, {} removed, {} unchanged",
                    added.len(),
                    removed.len(),
                    unchanged_count
                );
                let report = ChangeReport {
                    change_type: ChangeType::Custom,
                    added,
                    removed,
                    modified: Vec::new(),
                    unchanged_count,
                    summary,
                };
                Ok(json!({ "report": report }))
            }
            "ai_explain_error" => {
                let error = args
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if error.is_empty() {
                    return Err(McpError::InvalidParams(
                        "error is required for ai_explain_error".to_string(),
                    ));
                }
                let lower = error.to_lowercase();
                let mut possible = Vec::new();
                if lower.contains("access violation") || lower.contains("0xc0000005") {
                    possible.push("Null or invalid pointer dereference".to_string());
                    possible.push("Use-after-free or double free".to_string());
                }
                if lower.contains("timeout") {
                    possible.push("Deadlock or long-running loop".to_string());
                }
                if possible.is_empty() {
                    possible.push("Unhandled edge case or bad input".to_string());
                }
                let ai_error = AiError {
                    code: "ANALYZED".to_string(),
                    message: error.to_string(),
                    explanation: "Heuristic analysis of error string".to_string(),
                    possible_causes: possible.clone(),
                    suggested_fixes: vec![
                        "Enable symbols and gather a stack trace".to_string(),
                        "Add argument validation before the failing call".to_string(),
                    ],
                    documentation: None,
                    recoverable: true,
                };
                Ok(json!({ "analysis": ai_error }))
            }
            "ai_recommend_breakpoints" => {
                let function_text = args
                    .get("function")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if function_text.is_empty() {
                    return Err(McpError::InvalidParams(
                        "function is required for ai_recommend_breakpoints".to_string(),
                    ));
                }
                let goal = args
                    .get("goal")
                    .and_then(|v| v.as_str())
                    .unwrap_or("instrument critical paths");
                let addr_re = Regex::new(r"0x[0-9a-fA-F]+").ok();
                let mut recs = Vec::new();
                for line in function_text.lines().take(5) {
                    if let Some(re) = &addr_re {
                        if let Some(m) = re.find(line) {
                            let addr = usize::from_str_radix(&m.as_str()[2..], 16).unwrap_or(0);
                            recs.push(BreakpointRecommendation {
                                address: addr,
                                bp_type: BreakpointType::Software,
                                reason: format!("Entry/branch candidate: {}", line.trim()),
                                confidence: 0.55,
                                observation_hints: vec![goal.to_string()],
                                symbol: None,
                            });
                        }
                    }
                }
                if recs.is_empty() {
                    recs.push(BreakpointRecommendation {
                        address: 0,
                        bp_type: BreakpointType::Software,
                        reason: "Entry point (no explicit address found)".to_string(),
                        confidence: 0.4,
                        observation_hints: vec![goal.to_string()],
                        symbol: None,
                    });
                }
                Ok(json!({ "recommendations": recs }))
            }
            "ai_analyze_vulnerability" => {
                let code = args
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if code.is_empty() {
                    return Err(McpError::InvalidParams(
                        "code is required for ai_analyze_vulnerability".to_string(),
                    ));
                }
                let lower = code.to_lowercase();
                let mut vuln_type = VulnerabilityType::Other;
                let mut severity = 3;
                let mut description = "No obvious unsafe constructs detected".to_string();

                let dangerous_calls = ["strcpy", "sprintf", "gets", "memcpy", "strcat"];
                if dangerous_calls.iter().any(|c| lower.contains(c)) {
                    vuln_type = VulnerabilityType::BufferOverflow;
                    severity = 7;
                    description = "Potential unsafe buffer usage detected".to_string();
                } else if lower.contains("null") && lower.contains("pointer") {
                    vuln_type = VulnerabilityType::NullPointerDeref;
                    severity = 5;
                    description = "Potential null pointer dereference".to_string();
                }

                let report = VulnerabilityReport {
                    vuln_type,
                    severity,
                    address: 0,
                    description: description.clone(),
                    analysis: "Heuristic static pass over provided snippet".to_string(),
                    poc: None,
                    remediation: vec![
                        "Validate input sizes and avoid unsafe copies".to_string(),
                        "Add assertions around pointers".to_string(),
                    ],
                    confidence: 0.48,
                    cwe_id: None,
                };
                Ok(json!({ "report": report }))
            }
            "ai_learn_pattern" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing name".to_string()))?;
                let examples = args
                    .get("examples")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let desc = args
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("User-provided pattern");

                st.ai.next_pattern_id = st.ai.next_pattern_id.saturating_add(1);
                let pattern = LearnedPattern {
                    id: st.ai.next_pattern_id,
                    name: name.to_string(),
                    description: desc.to_string(),
                    pattern_type: LearnedPatternType::CodeSequence,
                    data: json!({ "examples": examples }),
                    observation_count: examples.len() as u32,
                    confidence: 0.6,
                    created_at: now_millis(),
                    last_seen_at: now_millis(),
                };
                st.ai.patterns.insert(name.to_string(), pattern.clone());
                Ok(json!({ "pattern_id": pattern.id, "name": name }))
            }
            "ai_patterns_list" => {
                let patterns: Vec<_> = st.ai.patterns.values().cloned().collect();
                Ok(json!({ "patterns": patterns }))
            }
            "debug_session_create" => {
                let goal = args
                    .get("goal")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing goal".to_string()))?;
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                st.ai.next_debug_id = st.ai.next_debug_id.saturating_add(1);
                let id = format!("dbg-{}", st.ai.next_debug_id);
                let session = DebugSession::new(id.clone(), goal.to_string(), name.clone());
                st.ai.debug_sessions.insert(id.clone(), session.clone());
                Ok(json!({ "session_id": id, "session": session }))
            }
            "debug_session_info" => {
                let id = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                if let Some(sess) = st.ai.debug_sessions.get(id) {
                    Ok(json!({ "session": sess }))
                } else {
                    Err(McpError::ToolNotFound(id.to_string()))
                }
            }
            "debug_session_update" => {
                let id = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                let findings = args
                    .get("findings")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if let Some(sess) = st.ai.debug_sessions.get_mut(id) {
                    if !findings.is_empty() {
                        sess.findings.push(findings.to_string());
                    }
                    sess.updated_at = now_millis();
                    Ok(json!({ "updated": true, "session": sess }))
                } else {
                    Err(McpError::ToolNotFound(id.to_string()))
                }
            }
            "debug_session_close" => {
                let id = args
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing session_id".to_string()))?;
                if let Some(sess) = st.ai.debug_sessions.get_mut(id) {
                    sess.closed = true;
                    if let Some(summary) = args.get("summary").and_then(|v| v.as_str()) {
                        sess.summary = Some(summary.to_string());
                    }
                    sess.updated_at = now_millis();
                    Ok(json!({ "closed": true, "session": sess }))
                } else {
                    Err(McpError::ToolNotFound(id.to_string()))
                }
            }
            "debug_session_list" => {
                let sessions: Vec<_> = st.ai.debug_sessions.values().cloned().collect();
                Ok(json!({ "sessions": sessions }))
            }
            _ => Err(McpError::ToolNotFound(name.to_string())),
        }
    }

    async fn handle_yara_tool(
        state: &Arc<Mutex<LocalState>>,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut st = state.lock().await;
        match name {
            "yara_create_rule" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing name".to_string()))?;
                let rule = args
                    .get("rule")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing rule".to_string()))?;
                st.yara_rules
                    .insert(name.to_string(), YaraRule::new(name, rule));
                #[cfg(feature = "yara")]
                {
                    let rules: Vec<_> = st.yara_rules.values().cloned().collect();
                    st.scanner
                        .load_yara_rules(&rules)
                        .map_err(|e: ghost_common::Error| McpError::Handler(e.to_string()))?;
                }
                Ok(json!({ "created": true, "name": name, "rule_count": st.yara_rules.len() }))
            }
            "yara_load_rules" => {
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing path".to_string()))?;
                let content = fs::read_to_string(path).map_err(|e| {
                    McpError::Handler(format!("Failed to read YARA file '{}': {}", path, e))
                })?;
                let name = Path::new(path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(path);
                st.yara_rules
                    .insert(name.to_string(), YaraRule::from_file(name, path));
                #[cfg(feature = "yara")]
                {
                    let rules: Vec<_> = st.yara_rules.values().cloned().collect();
                    st.scanner
                        .load_yara_rules(&rules)
                        .map_err(|e: ghost_common::Error| McpError::Handler(e.to_string()))?;
                }
                Ok(json!({ "loaded": true, "name": name, "bytes": content.len() }))
            }
            "yara_scan_memory" => {
                #[cfg(not(feature = "yara"))]
                {
                    Err(McpError::Handler(
                        "YARA support not compiled in; rebuild with --features yara".to_string(),
                    ))
                }
                #[cfg(feature = "yara")]
                {
                    if st.yara_rules.is_empty() {
                        return Err(McpError::Handler(
                            "No YARA rules loaded; load or create rules first".to_string(),
                        ));
                    }
                    let module_path =
                        args.get("module").and_then(|v| v.as_str()).ok_or_else(|| {
                            McpError::InvalidParams("module is required for scanning".to_string())
                        })?;
                    let data = read_module_bytes(module_path)?;
                    let region = memory_region_for_len(data.len());
                    let mut options = YaraScanOptions::new();
                    options.modules.push(module_path.to_string());
                    let (matches, stats) = st
                        .scanner
                        .scan_yara(&[region], &options, read_buffer(&data))
                        .map_err(|e: ghost_common::Error| McpError::Handler(e.to_string()))?;
                    Ok(json!({ "matches": matches, "stats": stats }))
                }
            }
            "yara_list_rules" => {
                let rules: Vec<_> = st
                    .yara_rules
                    .values()
                    .map(|r| {
                        json!({
                            "name": r.name,
                            "namespace": r.namespace,
                            "file_path": r.file_path
                        })
                    })
                    .collect();
                Ok(json!({ "rules": rules }))
            }
            "find_instructions" => {
                let pattern = args
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing pattern".to_string()))?;
                let module_path = args
                    .get("module")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing module".to_string()))?;
                let max_results = args
                    .get("max_results")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100) as usize;
                let data = read_module_bytes(module_path)?;
                let instrs = disassemble_buffer(&data, 0, 64, max_results.saturating_mul(5));
                let mut results = Vec::new();
                for ins in instrs {
                    let text = format!("{} {}", ins.mnemonic, ins.operands)
                        .trim()
                        .to_string();
                    if wildcard_match(pattern, &text) {
                        results.push(json!({
                            "address": ins.address,
                            "mnemonic": ins.mnemonic,
                            "operands": ins.operands,
                            "bytes": hex::encode(&ins.bytes)
                        }));
                    }
                    if results.len() >= max_results {
                        break;
                    }
                }
                Ok(json!({ "results": results, "count": results.len() }))
            }
            "signature_db_create" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing name".to_string()))?;
                let mut db = SignatureDatabase::new(name);
                if let Some(desc) = args.get("description").and_then(|v| v.as_str()) {
                    db.description = Some(desc.to_string());
                }
                st.scanner
                    .load_database(db)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "created": true, "name": name }))
            }
            "signature_db_add" => {
                let name = args
                    .get("db")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing db".to_string()))?;
                let entry_name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing name".to_string()))?;
                let pattern = args
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing pattern".to_string()))?;
                let mut db = st
                    .scanner
                    .get_database(name)
                    .ok_or_else(|| McpError::ToolNotFound(name.to_string()))?;
                db.add_signature(SignaturePattern::new(entry_name, pattern));
                db.version = bump_version(&db.version);
                st.scanner
                    .load_database(db)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "added": true, "db": name, "entry": entry_name }))
            }
            "signature_db_list" => {
                if let Some(db_name) = args.get("db").and_then(|v| v.as_str()) {
                    if let Some(db) = st.scanner.get_database(db_name) {
                        return Ok(json!({ "databases": [json!({
                            "name": db.name,
                            "entries": db.signatures.len(),
                            "version": db.version
                        })]}));
                    }
                    return Err(McpError::ToolNotFound(db_name.to_string()));
                }
                let dbs: Vec<_> = st
                    .scanner
                    .list_databases()
                    .iter()
                    .filter_map(|n| st.scanner.get_database(n))
                    .map(|db| {
                        json!({
                            "name": db.name,
                            "entries": db.signatures.len(),
                            "version": db.version
                        })
                    })
                    .collect();
                Ok(json!({ "databases": dbs }))
            }
            "signature_db_scan" => {
                let db = args
                    .get("db")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing db".to_string()))?;
                let module_path = args
                    .get("module")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing module".to_string()))?;
                let data = read_module_bytes(module_path)?;
                let region = memory_region_for_len(data.len());
                let options = PatternScanOptions {
                    scan_type: PatternScanType::Aob,
                    ..PatternScanOptions::default()
                };
                let (matches, stats) = st
                    .scanner
                    .scan_signatures(db, &[region], &options, read_buffer(&data))
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "matches": matches, "stats": stats }))
            }
            "signature_db_export" => {
                let name = args
                    .get("db")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing db".to_string()))?;
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing path".to_string()))?;
                let db = st
                    .scanner
                    .get_database(name)
                    .ok_or_else(|| McpError::ToolNotFound(name.to_string()))?;
                let serialized = serde_json::to_string_pretty(&db)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                fs::write(path, serialized).map_err(|e| {
                    McpError::Handler(format!("Failed to export database to {}: {}", path, e))
                })?;
                Ok(json!({ "exported": true, "db": name, "path": path }))
            }
            "signature_db_import" => {
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing path".to_string()))?;
                let content = fs::read_to_string(path).map_err(|e| {
                    McpError::Handler(format!("Failed to read database file '{}': {}", path, e))
                })?;
                let db: SignatureDatabase = serde_json::from_str(&content)
                    .map_err(|e| McpError::Handler(format!("Invalid database JSON: {}", e)))?;
                let name = db.name.clone();
                st.scanner
                    .load_database(db)
                    .map_err(|e| McpError::Handler(e.to_string()))?;
                Ok(json!({ "imported": true, "db": name }))
            }
            "signature_db_version" => {
                let name = args
                    .get("db")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing db".to_string()))?;
                if let Some(db) = st.scanner.get_database(name) {
                    Ok(json!({ "db": name, "version": db.version }))
                } else {
                    Err(McpError::ToolNotFound(name.to_string()))
                }
            }
            "signature_auto_generate" => {
                let address_str = args
                    .get("address")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| McpError::InvalidParams("Missing address".to_string()))?;
                let module_path = args.get("module").and_then(|v| v.as_str()).ok_or_else(|| {
                    McpError::InvalidParams(
                        "module is required for signature_auto_generate".to_string(),
                    )
                })?;
                let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(32) as usize;
                let address = if let Some(stripped) = address_str.strip_prefix("0x") {
                    usize::from_str_radix(stripped, 16).unwrap_or(0)
                } else {
                    address_str.parse::<usize>().unwrap_or(0)
                };
                let data = read_module_bytes(module_path)?;
                if address >= data.len() {
                    return Err(McpError::InvalidParams(
                        "Address outside module bounds".to_string(),
                    ));
                }
                let end = min(data.len(), address.saturating_add(size));
                let slice = &data[address..end];
                let sig =
                    PatternScanner::generate_signature(&format!("sig_{:x}", address), slice, &[]);
                Ok(json!({ "generated": true, "pattern": sig.pattern }))
            }
            _ => Err(McpError::ToolNotFound(name.to_string())),
        }
    }
}

/// Create server with tools registered
///
/// # Errors
/// Returns an error if server creation or tool registration fails.
pub async fn create_server_with_tools() -> Result<McpServer> {
    debug!(target: "ghost_static_mcp", "Creating server with tools");
    let server = create_server()?.with_tool_handler(StaticToolHandler::default());
    let tool_registry = create_registry()?;

    let mut registered = 0;
    let mut skipped = 0;
    {
        let mut registry = server.registry().await;
        for tool in tool_registry.tools() {
            if registry.get(&tool.name).is_none() {
                registry.register(tool.clone()).map_err(|e| {
                    error!(target: "ghost_static_mcp", "Failed to register tool '{}': {}", tool.name, e);
                    e
                })?;
                registered += 1;
            } else {
                skipped += 1;
            }
        }
    }

    info!(
        target: "ghost_static_mcp",
        "Server ready: {} tools registered, {} skipped",
        registered,
        skipped
    );

    Ok(server)
}

/// Validate that the registry meets expected tool count
///
/// # Errors
/// Returns an error if the registry exceeds the tool limit.
pub fn validate_registry(registry: &ToolRegistry) -> Result<()> {
    registry.validate()?;

    let count = registry.len();
    let limit = ghost_mcp_common::MAX_TOOLS_PER_SERVER;

    if count > limit * 8 / 10 {
        warn!(
            target: "ghost_static_mcp",
            "Registry at {}% capacity: {}/{} tools",
            count * 100 / limit,
            count,
            limit
        );
    }

    info!(target: "ghost_static_mcp", "{}", registry.summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_registry() {
        let registry = create_registry().unwrap();
        assert!(
            !registry.is_empty(),
            "Registry should have tools registered"
        );
        assert!(registry.len() <= 90, "Registry should not exceed 90 tools");
    }

    #[test]
    fn test_registry_under_limit() {
        let registry = create_registry().unwrap();
        assert!(
            registry.len() <= ghost_mcp_common::MAX_TOOLS_PER_SERVER,
            "Tool count {} exceeds maximum {}",
            registry.len(),
            ghost_mcp_common::MAX_TOOLS_PER_SERVER
        );
    }

    #[test]
    fn test_registry_expected_count() {
        let registry = create_registry().unwrap();
        assert_eq!(
            registry.len(),
            EXPECTED_REGISTRY_COUNT,
            "Registry count mismatch: expected {} tools in registry (excluding 4 shared meta)",
            EXPECTED_REGISTRY_COUNT
        );
    }

    #[test]
    fn test_registry_categories() {
        let registry = create_registry().unwrap();
        let categories = registry.categories();
        assert!(categories.contains(&"radare2"), "Missing radare2 category");
        assert!(categories.contains(&"ida"), "Missing ida category");
        assert!(categories.contains(&"ghidra"), "Missing ghidra category");
        assert!(categories.contains(&"trace"), "Missing trace category");
        assert!(categories.contains(&"ai"), "Missing ai category");
        assert!(categories.contains(&"yara"), "Missing yara category");
    }

    #[test]
    fn test_registry_tool_counts_per_category() {
        let registry = create_registry().unwrap();

        // Per Appendix A in roadmap
        assert_eq!(
            registry.by_category("radare2").len(),
            14,
            "Radare2 should have 14 tools"
        );
        assert_eq!(
            registry.by_category("ida").len(),
            11,
            "IDA should have 11 tools"
        );
        assert_eq!(
            registry.by_category("ghidra").len(),
            11,
            "Ghidra should have 11 tools"
        );
        assert_eq!(
            registry.by_category("trace").len(),
            19,
            "Trace should have 19 tools"
        );
        assert_eq!(
            registry.by_category("ai").len(),
            12,
            "AI should have 12 tools"
        );
        assert_eq!(
            registry.by_category("yara").len(),
            13,
            "YARA should have 13 tools"
        );
    }

    #[test]
    fn test_total_tool_count_matches_roadmap() {
        // Target: 84 tools total (80 registry + 4 shared meta)
        let registry = create_registry().unwrap();
        let registry_count = registry.len();
        let shared_meta_count = 4; // mcp_capabilities, mcp_documentation, mcp_version, mcp_health
        let total = registry_count + shared_meta_count;

        assert_eq!(
            total, EXPECTED_TOOL_COUNT,
            "Total tool count should be {} (registry {} + shared meta {})",
            EXPECTED_TOOL_COUNT, registry_count, shared_meta_count
        );
    }

    #[test]
    fn test_re_tools_exist() {
        // Verify RE backend tools
        let registry = create_registry().unwrap();

        // Radare2 consolidated tools
        assert!(
            registry.get("r2_session").is_some(),
            "r2_session should exist"
        );
        assert!(
            registry.get("r2_disasm").is_some(),
            "r2_disasm should exist"
        );
        assert!(
            registry.get("r2_decompile").is_some(),
            "r2_decompile should exist"
        );
        assert!(registry.get("r2_xref").is_some(), "r2_xref should exist");
        assert!(registry.get("r2_cmd").is_some(), "r2_cmd should exist");

        // IDA consolidated tools
        assert!(
            registry.get("ida_session").is_some(),
            "ida_session should exist"
        );
        assert!(
            registry.get("ida_disasm").is_some(),
            "ida_disasm should exist"
        );
        assert!(
            registry.get("ida_decompile").is_some(),
            "ida_decompile should exist"
        );
        assert!(registry.get("ida_xref").is_some(), "ida_xref should exist");

        // Ghidra consolidated tools
        assert!(
            registry.get("ghidra_session").is_some(),
            "ghidra_session should exist"
        );
        assert!(
            registry.get("ghidra_disasm").is_some(),
            "ghidra_disasm should exist"
        );
        assert!(
            registry.get("ghidra_decompile").is_some(),
            "ghidra_decompile should exist"
        );
        assert!(
            registry.get("ghidra_xref").is_some(),
            "ghidra_xref should exist"
        );
    }

    #[test]
    fn test_trace_tools_exist() {
        let registry = create_registry().unwrap();

        // Consolidated trace tools
        assert!(
            registry.get("trace_session_create").is_some(),
            "trace_session_create should exist"
        );
        assert!(
            registry.get("trace_control").is_some(),
            "trace_control should exist"
        );
        assert!(
            registry.get("trace_events").is_some(),
            "trace_events should exist"
        );
        assert!(
            registry.get("trace_preset_apply").is_some(),
            "trace_preset_apply should exist"
        );
    }

    #[test]
    fn test_ai_tools_exist() {
        let registry = create_registry().unwrap();

        assert!(
            registry.get("ai_summarize").is_some(),
            "ai_summarize should exist"
        );
        assert!(registry.get("ai_diff").is_some(), "ai_diff should exist");
        assert!(
            registry.get("ai_explain_error").is_some(),
            "ai_explain_error should exist"
        );
        assert!(
            registry.get("debug_session_create").is_some(),
            "debug_session_create should exist"
        );
    }

    #[test]
    fn test_yara_tools_exist() {
        let registry = create_registry().unwrap();

        assert!(
            registry.get("yara_create_rule").is_some(),
            "yara_create_rule should exist"
        );
        assert!(
            registry.get("yara_scan_memory").is_some(),
            "yara_scan_memory should exist"
        );
        assert!(
            registry.get("signature_db_create").is_some(),
            "signature_db_create should exist"
        );
        assert!(
            registry.get("find_instructions").is_some(),
            "find_instructions should exist"
        );
    }

    #[tokio::test]
    async fn test_create_server() {
        let server = create_server().unwrap();
        assert_eq!(server.identity().name, "ghost-static-mcp");
        assert_eq!(server.identity().port, PORT);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PORT, 13342, "Static server should be on port 13342");
        assert_eq!(EXPECTED_TOOL_COUNT, 84, "Expected 84 total tools");
        assert_eq!(EXPECTED_REGISTRY_COUNT, 80, "Expected 80 registry tools");
    }

    #[test]
    fn test_max_tool_name_len() {
        assert_eq!(MAX_TOOL_NAME_LEN, 128, "Max tool name length should be 128");
    }

    #[test]
    fn test_max_args_size() {
        assert_eq!(MAX_ARGS_SIZE, 1024 * 1024, "Max args size should be 1MB");
    }
}
