# ghost-core-mcp

MCP server for live process interaction (Port 13340).

## Tools (85 total)

- **Memory** (5): memory_read, memory_write, memory_search, memory_search_pattern, memory_regions
- **Module** (5): module_list, module_exports, module_imports, string_list, symbol_resolve
- **Debug/Thread** (11): thread_*, breakpoint_*, execution_*, stack_walk
- **Session/Process** (7): session_*, process_*
- **Script/Hook** (11): script_*, hook_*, rpc_*
- **Execution** (15): exec_*, cave_*, syscall_*, remote_*
- **Safety** (10): safety_*, patch_*
- **Command/Event** (7): command_*, event_*
- **Disasm** (5): disasm_*, decompile, assemble*
- **Xrefs** (1): xref_to
- **Meta** (4): mcp_capabilities, mcp_documentation, mcp_version, mcp_health

## Build

```bash
cargo build -p ghost-core-mcp --release
```

## Usage

```bash
ghost-core-mcp.exe --transport stdio
```

Or via Claude Desktop config:

```json
{
  "mcpServers": {
    "ghost-core": {
      "command": "path/to/ghost-core-mcp.exe",
      "args": ["--transport", "stdio"]
    }
  }
}
```
