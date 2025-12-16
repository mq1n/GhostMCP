# ghost-mcp-client

CLI MCP client for testing and automation.

## Usage

```bash
# List available tools
ghost-client --stdio --host-binary ./ghost-host tools

# Call a tool
ghost-client --stdio --host-binary ./ghost-host call mcp_version

# Interactive REPL
ghost-client --stdio --host-binary ./ghost-host repl
```

## Features

- Tool discovery and invocation
- JSON-RPC protocol support
- Interactive REPL mode
- Scripted automation

## Build

```bash
cargo build -p ghost-mcp-client --release
```
