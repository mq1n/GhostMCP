# Ghost-MCP Tests

This directory contains integration and end-to-end tests for Ghost-MCP.

## Directory Structure

```
tests/
├── integration.rs           # Main integration test entry point
└── integration/             # Integration test modules
    ├── mod.rs               # Test harness and fixtures
    ├── mcp_protocol.rs      # MCP protocol compliance tests
    ├── ipc_fuzzing.rs       # IPC protocol fuzzing tests
    ├── patch_aware_dump.rs           # Patch-aware dump flow tests
    ├── multi_server_integration.rs   # Multi-server integration tests
    ├── static_tools.rs      # Static analysis tools tests
    ├── meta_tools.rs        # Meta tools availability tests
    ├── multi_client.rs      # Multi-client handshake tests
    └── tool_count_golden.rs # Tool count golden snapshot tests
```

## Running Tests

### Unit Tests
```bash
# Run all unit tests
cargo test --workspace
```

### Integration Tests

Integration tests use the modular MCP servers (ghost-host is DEPRECATED):

**Available MCP Servers:**
- `ghost-core-mcp` (port 13340) - Memory, Debug, Execution, Safety
- `ghost-analysis-mcp` (port 13341) - Scanner, Dump, Introspection
- `ghost-static-mcp` (port 13342) - Radare2, IDA, Ghidra, AI Tools
- `ghost-extended-mcp` (port 13343) - Injection, Anti-Debug, Input, Speedhack

```bash
# 1. Build everything
cargo build --release

# 2. Run integration tests (defaults to ghost-core-mcp)
MCP_SERVER_BIN=./target/release/ghost-core-mcp cargo test --test integration -- --ignored

# Run specific test
MCP_SERVER_BIN=./target/release/ghost-core-mcp cargo test --test integration test_mcp_protocol -- --ignored

# Run fuzzing tests
MCP_SERVER_BIN=./target/release/ghost-core-mcp cargo test --test integration test_ipc_fuzzing -- --ignored
```

### Using ghost-mcp-client

The CLI client can test any of the 4 MCP servers:

```bash
# Test ghost-core-mcp (memory, debug, execution tools)
ghost-client --stdio --host-binary ./target/release/ghost-core-mcp tools

# Test ghost-analysis-mcp (scanner, dump, introspection tools)
ghost-client --stdio --host-binary ./target/release/ghost-analysis-mcp tools

# Test ghost-static-mcp (radare2, IDA, ghidra, AI tools)
ghost-client --stdio --host-binary ./target/release/ghost-static-mcp tools

# Test ghost-extended-mcp (injection, anti-debug, input, speedhack)
ghost-client --stdio --host-binary ./target/release/ghost-extended-mcp tools

# Interactive REPL mode
ghost-client --stdio --host-binary ./target/release/ghost-core-mcp repl

# Run a test script
ghost-client --stdio --host-binary ./target/release/ghost-core-mcp script test_script.json
```

## Multi-Server Integration Tests

Tests for the multi-server architecture (Core, Analysis, Static, Extended):

```bash
# Run multi-server offline tests (no live agent required)
cargo test --test integration test_multi_server_integration -- --nocapture

# Run all multi-server tests including live tests (requires servers running)
cargo test --test integration multi_server -- --ignored --nocapture
```

### Test Coverage

The `multi_server_integration` module tests:
- **Tool count limits**: All servers <= 90 tools
- **Registry validation**: Golden snapshot counts (Core: 81, Analysis: 78, Static: 80, Extended: 81)
- **No tool overlap**: No duplicate tools across servers
- **Total tool count**: ~324 unique tools
- **Port configuration**: Agent 13338, servers 13340-13343
- **Category distribution**: All expected categories present
- **Consolidation rules**: Session/xref/trace consolidation applied

### Live Tests (require running servers)

```bash
# Start servers first
.\scripts\launch-mcp.ps1 -All

# Then run live tests
cargo test --test integration multi_server -- --ignored --nocapture
```

- `test_concurrent_agent_access` - Multi-server concurrent connections
- `test_meta_tools_all_servers` - Shared meta tools on all 4 servers
- `test_capabilities_tool_count` - mcp_capabilities returns <= 90
- `test_patch_history_accessible` - patch_history tool accessible

## Patch-Aware Dump Flow Tests

Integration tests for the patch history → dump annotation integration path:

```bash
# Run patch-aware dump flow tests (no external binaries needed)
cargo test --test integration test_patch_aware_dump_flows

# Run with live agent (requires elevated permissions)
GHOST_PATCH_DUMP_ELEVATED=1 cargo test --test integration test_patch_aware_dump_live -- --ignored
```

### Test Coverage

The `patch_aware_dump` module tests:
- **patch_history**: Returns seeded patches with correct `returned`/`total` counts
- **dump_create**: Includes `patch_annotations` with `patch_count > 0`
- **dump_region**: Filters patches by range (includes in-range, excludes out-of-range)
- **dump_compare**: Annotates `patch_caused_differences > 0` with correct patch IDs

### Test Harness

`PatchDumpTestHarness` seeds two patches for testing:
- Overlapping patch at `0x140001500` (inside target range `0x140001000-0x140002000`)
- Non-overlapping patch at `0x140003000` (outside target range)

## Test Coverage

Target: >80% coverage on ghost-core

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --packages ghost-core --out Html
```
