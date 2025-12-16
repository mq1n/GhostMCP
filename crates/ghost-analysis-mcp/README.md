# ghost-analysis-mcp

**Ghost-MCP Analysis Server** - Port 13341

Memory analysis, scanning, structures, and introspection tools for the Ghost-MCP modular architecture.

## Overview

`ghost-analysis-mcp` is one of three specialized MCP servers in the Ghost-MCP ecosystem:

| Server | Port | Tools | Purpose |
|--------|------|-------|---------|
| ghost-core-mcp | 13340 | 85 | Core runtime, debugging, safety |
| **ghost-analysis-mcp** | **13341** | **82** | **Memory analysis, scanning** |
| ghost-static-mcp | 13342 | 84 | Static analysis, RE backends |
| ghost-extended-mcp | 13343 | 84 | Extended tools |

## Tool Categories (78 registry + 4 shared meta = 82 total)

### Scanner (11 tools)
Memory value scanning with first/next scan workflow:
- `scan_new` - Create scan session
- `scan_first` - Initial scan
- `scan_next` - Filter results
- `scan_results`, `scan_count`, `scan_progress`
- `scan_cancel`, `scan_close`, `scan_list`
- `scan_export`, `scan_import`

### Pointer Scanner (13 tools)
Find pointer paths to dynamic addresses:
- `pointer_scan_create`, `pointer_scan_start`, `pointer_scan_rescan`
- `pointer_scan_results`, `pointer_scan_count`, `pointer_scan_progress`
- `pointer_scan_cancel`, `pointer_scan_close`, `pointer_scan_list`
- `pointer_resolve`, `pointer_scan_compare`
- `pointer_scan_export`, `pointer_scan_import`

### Watch (10 tools)
Memory/instruction watchpoints:
- `watch_address_create`, `watch_instruction_create`
- `watch_list`, `watch_hits_get`, `watch_accessed_get`
- `watch_pause`, `watch_resume`, `watch_remove`
- `watch_clear_hits`, `watch_quick_action`

### Dump (13 tools)
Memory dumps with **patch history integration**:
- `dump_create`, `dump_region`, `dump_module`, `dump_minidump`
- `dump_list`, `dump_info`, `dump_compare`, `dump_search`
- `dump_annotate`, `dump_incremental`, `dump_delete`
- `pe_reconstruct`, `pe_validate`

> **Note**: Dump tools integrate with the agent's centralized patch history to annotate dumps with information about patches that affect each memory region and highlight patch-caused differences in comparisons.

### Structure (11 tools)
Custom structure definitions:
- `struct_create`, `struct_list`, `struct_get`, `struct_delete`
- `struct_read`, `struct_edit_field`, `struct_export`
- `struct_auto_analyze`, `struct_save`, `struct_load`
- `enum_create`

### Introspection (20 tools)
Deep process/thread/module inspection:
- Process: `introspect_process`, `introspect_process_list`, `introspect_peb`
- Memory: `introspect_memory_map`, `introspect_environment`, `introspect_cwd`, `introspect_set_cwd`
- Thread: `introspect_thread`, `introspect_thread_list`, `introspect_teb`, `introspect_tls`
- Module: `introspect_module`, `introspect_module_list`, `introspect_sections`
- System: `introspect_handles`, `introspect_windows`, `introspect_window`, `introspect_child_windows`
- Security: `introspect_token`, `introspect_adjust_privilege`

### Shared Meta (4 tools)
Available on all Ghost-MCP servers:
- `mcp_capabilities`, `mcp_documentation`, `mcp_version`, `mcp_health`

## Usage

### CLI Flags

```bash
# Run with TCP transport (default)
ghost-analysis-mcp --port 13341

# Run with stdio transport
ghost-analysis-mcp --transport stdio

# Validate registry (for CI)
ghost-analysis-mcp --validate-registry

# Show all tools
ghost-analysis-mcp --show-tools
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "ghost-analysis": {
      "command": "ghost-analysis-mcp.exe",
      "args": ["--port", "13341"]
    }
  }
}
```

## Architecture

```
ghost-analysis-mcp/
├── src/
│   ├── main.rs           # CLI entry point
│   ├── lib.rs            # Registry, server factory, AnalysisToolHandler
│   ├── handlers/
│   │   ├── mod.rs
│   │   └── dump_handler.rs   # Dump tools with patch history integration
│   └── tools/
│       ├── mod.rs
│       ├── scanner.rs    # 11 tools
│       ├── pointer.rs    # 13 tools
│       ├── watch.rs      # 10 tools
│       ├── dump.rs       # 13 tools
│       ├── structure.rs  # 11 tools
│       └── introspect.rs # 20 tools
└── Cargo.toml
```

## Implementation Details

### AnalysisToolHandler

Routes tool calls to appropriate handlers:
- **Dump tools** → `DumpHandler` (local processing with patch history)
- **All other tools** → Agent forwarding via IPC

### Patch History Integration

Dump tools query the agent's centralized patch history:

```rust
// Query patch history (limit/client_id supported; optional range filtering)
let history = DumpHandler::query_patch_history(&agent, Some((start, end)), None, None).await?;

// Annotate dump metadata with patches and counts
response["patches_in_range"] = json!(history.patches);
response["patch_count"] = json!(history.patches.len());
response["patches_total"] = json!(history.total);
response["patches_truncated"] = json!(history.truncated);
```

### Patch-Aware Dump Compare

`dump_compare` now returns patch-aware annotations:

- Computes changed regions from agent diff response.
- Fetches patch history for the affected address window.
- Marks which changes overlap applied patches and reports counts (`patch_caused_differences`, `patches_considered`, `patches_total`, `patches_truncated`).

### Defensive Programming

- Input validation for addresses (min 0x10000)
- Size limits (max 256MB dumps)
- Tool name length limits (128 chars)
- Arguments size limits (1MB)
- Comprehensive error handling with `McpError::InvalidParams`

## Testing

```bash
# Run unit tests
cargo test --package ghost-analysis-mcp

# Run with verbose output
cargo test --package ghost-analysis-mcp -- --nocapture

# Validate tool counts
cargo run --package ghost-analysis-mcp -- --validate-registry
```

### Test Coverage
- 34 unit tests covering:
  - Registry creation and validation
  - Tool count per category
  - Handler input validation
  - Address parsing
  - Dump parameter validation
  - Patch history helpers (range overlap, diff extraction, patch-aware annotations)

## Dependencies

- `ghost-mcp-common` - Shared MCP server infrastructure
- `ghost-common` - Shared types and IPC
- `serde`, `serde_json` - Serialization
- `tokio` - Async runtime
- `tracing` - Logging

## License

See repository root for license information.
