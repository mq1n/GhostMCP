# ghost-static-mcp

Static Analysis MCP Server for Ghost-MCP - Port 13342

## Overview

`ghost-static-mcp` is one of three specialized MCP servers in the Ghost-MCP modularization architecture. It provides **84 tools** (80 registry + 4 shared meta) for static reverse engineering, AI-assisted analysis, API tracing, and pattern matching.

## Tool Categories

| Category | Count | Description |
|----------|-------|-------------|
| **Radare2** | 14 | Radare2 RE backend integration |
| **IDA Pro** | 11 | IDA Pro RE backend integration |
| **Ghidra** | 11 | Ghidra RE backend integration |
| **API Trace** | 19 | API call tracing and monitoring |
| **AI Tools** | 12 | AI-powered analysis assistance |
| **YARA/Pattern** | 13 | YARA rules and signature scanning |

### Radare2 Tools (14)
- `r2_session` - Open/close Radare2 session (consolidated)
- `r2_status` - Get session status
- `r2_info` - Binary info (architecture, format)
- `r2_functions` - List all functions
- `r2_function` - Get function details
- `r2_disasm` - Disassemble at address
- `r2_disasm_function` - Disassemble entire function
- `r2_decompile` - Decompile to pseudo-C (r2ghidra)
- `r2_strings` - List strings
- `r2_imports` - List imports
- `r2_exports` - List exports
- `r2_xref` - Cross-references (consolidated to/from)
- `r2_read` - Read bytes
- `r2_cmd` - Execute raw r2 command

### IDA Pro Tools (11)
- `ida_session` - Open/close IDA session (consolidated)
- `ida_status` - Get session status
- `ida_info` - Binary info
- `ida_functions` - List functions
- `ida_function` - Get function details
- `ida_disasm` - Disassemble at address
- `ida_decompile` - Decompile (Hex-Rays)
- `ida_strings` - List strings
- `ida_imports` - List imports
- `ida_exports` - List exports
- `ida_xref` - Cross-references (consolidated)

### Ghidra Tools (11)
- `ghidra_session` - Open/close Ghidra session (consolidated)
- `ghidra_status` - Get session status
- `ghidra_info` - Binary info
- `ghidra_functions` - List functions
- `ghidra_function` - Get function details
- `ghidra_disasm` - Disassemble at address
- `ghidra_decompile` - Decompile function
- `ghidra_strings` - List strings
- `ghidra_imports` - List imports
- `ghidra_exports` - List exports
- `ghidra_xref` - Cross-references (consolidated)

### API Trace Tools (19)
- `trace_session_create` - Create trace session
- `trace_control` - Control session (start/stop/pause/resume)
- `trace_session_close` - Close session
- `trace_session_list` - List sessions
- `trace_session_info` - Get session info
- `trace_events` - Get traced events
- `trace_events_clear` - Clear events
- `trace_stats` - Get statistics
- `trace_queue_stats` - Get queue statistics
- `trace_filter_set` - Set filter rules
- `trace_preset_list` - List presets
- `trace_preset_apply` - Apply preset
- `trace_preset_create` - Create preset
- `trace_preset_delete` - Delete preset
- `trace_pack_list` - List API packs
- `trace_pack_info` - Get pack info
- `trace_pack_load` - Load pack
- `trace_pack_unload` - Unload pack
- `trace_hooks_list` - List active hooks

### AI Tools (12)
- `ai_summarize` - AI code summarization
- `ai_diff` - AI diff analysis
- `ai_explain_error` - AI error explanation
- `ai_recommend_breakpoints` - AI breakpoint recommendations
- `ai_analyze_vulnerability` - AI vulnerability analysis
- `ai_learn_pattern` - Teach AI patterns
- `ai_patterns_list` - List learned patterns
- `debug_session_create` - Create debug session
- `debug_session_info` - Get session info
- `debug_session_update` - Update session
- `debug_session_close` - Close session
- `debug_session_list` - List sessions

### YARA/Pattern Tools (13)
- `yara_create_rule` - Create YARA rule
- `yara_load_rules` - Load rules from file
- `yara_scan_memory` - Scan memory
- `yara_list_rules` - List loaded rules
- `find_instructions` - Find instruction patterns
- `signature_db_create` - Create signature DB
- `signature_db_add` - Add signature
- `signature_db_list` - List signatures
- `signature_db_scan` - Scan with DB
- `signature_db_export` - Export DB
- `signature_db_import` - Import DB
- `signature_db_version` - Get DB version
- `signature_auto_generate` - Auto-generate signature

## Architecture

### RE Backend Routing

The server uses `ReHandler` to route RE tools to appropriate backends:

```rust
// Tool routing based on prefix
r2_*     → Radare2 backend
ida_*    → IDA Pro backend  
ghidra_* → Ghidra backend
```

### Consolidation Rules Applied

Per the MCP Modularization Roadmap, tools were consolidated to reduce count:

1. **Session consolidation**: `*_open` + `*_close` → `*_session(action: "open" | "close")`
2. **Xref consolidation**: `*_xrefs_to` + `*_xrefs_from` → `*_xref(direction: "to" | "from")`
3. **Trace control**: start/stop/pause/resume → `trace_control(action: "...")`

## Usage

### CLI Options

```bash
# Start server on default TCP port (13342)
ghost-static-mcp

# Start on custom port
ghost-static-mcp --port 13350

# Use stdio transport (for MCP clients)
ghost-static-mcp --transport stdio

# Validate registry (CI check)
ghost-static-mcp --validate-registry

# Show all tools
ghost-static-mcp --show-tools
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "ghost-static": {
      "command": "ghost-static-mcp.exe",
      "args": ["--port", "13342"]
    }
  }
}
```

## Production Hardening

- **Defensive Programming**: Input validation for paths, addresses, commands
- **Size Limits**: MAX_PATH_LEN (4096), MAX_CMD_LEN (8192), MAX_FILTER_LEN (1024)
- **Address Validation**: MIN_VALID_ADDRESS (0x1000) prevents null pointer operations
- **Dangerous Command Warnings**: r2_cmd warns on shell escapes (!, =!, etc.)
- **Comprehensive Logging**: tracing integration at debug/trace/warn/error levels
- **Error Handling**: Graceful McpError responses, no panics

## Testing

```bash
# Run unit tests
cargo test --package ghost-static-mcp

# Run with verbose output
cargo test --package ghost-static-mcp -- --nocapture

# Validate tool counts
cargo run --package ghost-static-mcp -- --validate-registry
```

## Dependencies

- `ghost-mcp-common` - Shared MCP server infrastructure
- `ghost-common` - Common types and IPC
- `tokio` - Async runtime
- `tracing` - Structured logging
- `clap` - CLI parsing
- `serde_json` - JSON handling

## License

MIT
