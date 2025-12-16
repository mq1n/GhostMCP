# ghost-mcp-common

Shared MCP server infrastructure for Ghost-MCP modular servers.

## Overview

This crate provides the common foundation for all Ghost-MCP servers (`ghost-core-mcp`, `ghost-analysis-mcp`, `ghost-static-mcp`, `ghost-extended-mcp`). It implements:

- **Shared Meta Tools**: `mcp_capabilities`, `mcp_documentation`, `mcp_version`, `mcp_health`
- **Tool Registry**: Registration with <90 tool limit enforcement
- **IPC Client**: Communication with `ghost-agent` via TCP with retries and reconnection
- **Server Template**: Reusable MCP server with stdio and TCP transports
- **Common Types**: Shared types, errors, and configuration structures

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Client (Claude)                       │
└─────────────────────────┬───────────────────────────────────┘
                          │ JSON-RPC (stdio/TCP)
          ┌───────────────┼───────────────┬───────────────
          ▼               ▼               ▼               ▼
   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────────┐
   │ghost-core  │  │ghost-      │  │ghost-static│  │ghost-extended │
   │-mcp :13340 │  │analysis-mcp│  │-mcp :13342 │  │-mcp :13344    │
   │  80 tools  │  │:13341      │  │  89 tools  │  │  81 tools     │
   └─────┬──────┘  │  83 tools  │  └─────┬──────┘  └───────────────┘
         │         └─────┬──────┘        │
         │               │               │
         └───────────────┼───────────────┘
                         │ IPC (TCP :13338)
                         ▼
              ┌─────────────────────┐
              │    ghost-agent      │
              │  (target process)   │
              └─────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `config` | Server configuration with retry and heartbeat settings |
| `error` | Unified error types with JSON-RPC code mapping |
| `ipc` | Agent client with connection management, retries, timeouts |
| `meta` | Shared meta tool implementations |
| `registry` | Tool registration with validation and categorization |
| `server` | MCP server template with stdio/TCP transports |
| `types` | Common data structures for tools and health status |

## Usage

### Creating a Server

```rust
use ghost_mcp_common::{McpServer, Transport, ServerIdentity, ServerConfig};

#[tokio::main]
async fn main() -> ghost_mcp_common::Result<()> {
    // Create a core server (port 13340)
    let server = McpServer::core();
    
    // Or create with custom identity
    let server = McpServer::new(
        ServerIdentity::core(),
        ServerConfig::core(),
    );
    
    // Register custom tools
    {
        let mut registry = server.registry().await;
        registry.register(my_tool_definition)?;
    }
    
    // Run in stdio mode (for Claude Desktop)
    server.serve(Transport::Stdio).await
}
```

### Registering Tools

```rust
use ghost_mcp_common::{ToolDefinition, ToolInputSchema, PropertySchema};

let tool = ToolDefinition::new(
    "my_tool",
    "Does something useful",
)
.with_category("custom")
.with_param(PropertySchema {
    name: "address".to_string(),
    description: "Memory address".to_string(),
    type_name: "string".to_string(),
    required: true,
    default: None,
});

registry.register(tool)?;
```

### Using the Agent Client

```rust
use ghost_mcp_common::AgentClient;

let client = AgentClient::new();

// Try to connect (silent failure)
if client.try_connect().await {
    // Send request
    let result = client.request("memory.read", serde_json::json!({
        "address": "0x12345678",
        "size": 256
    })).await?;
}
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_TOOLS_PER_SERVER` | 90 | Maximum tools per server (MCP client limit) |
| `DEFAULT_AGENT_PORT` | 13338 | Default ghost-agent TCP port |
| `VERSION` | `CARGO_PKG_VERSION` | Server version from Cargo.toml |

## Server Configurations

| Server | Port | Tools | Requires Agent |
|--------|------|-------|----------------|
| ghost-core-mcp | 13340 | 80 | Yes |
| ghost-analysis-mcp | 13341 | 83 | Yes |
| ghost-static-mcp | 13342 | 89 | No |
| ghost-extended-mcp | 13343 | ~85 (planned) | Yes |

## Multi-Client Protocol

The IPC client supports the multi-client protocol for connecting to agents that handle multiple MCP servers simultaneously.

### Handshake Protocol

```rust
use ghost_common::ipc::ClientIdentity;
use ghost_mcp_common::AgentClient;

// Client automatically performs handshake on connect
let client = AgentClient::new();
client.connect().await?;

// Access identity
let identity = client.identity();
println!("Connected as: {} v{}", identity.name, identity.version);
```

### Protocol Types (ghost-common)

| Type | Description |
|------|-------------|
| `ClientIdentity` | Client name, version, capabilities, session ID |
| `HandshakeResponse` | Agent acceptance, status, granted capabilities |
| `Event` / `EventType` | Event bus messages for state changes |
| `PatchEntry` | Memory patch history entry |
| `SafetyToken` | Approval token for dangerous operations |
| `SessionMetadata` | Current session state |

### Validation Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_CLIENT_NAME_LENGTH` | 128 | Maximum client name length |
| `MAX_CAPABILITY_LENGTH` | 64 | Maximum capability string length |
| `MAX_CAPABILITIES` | 32 | Maximum capabilities per client |
| `MAX_PATCH_SIZE` | 4096 | Maximum patch size in bytes |

## Defensive Programming

The crate implements defensive programming practices:

- **Request size limits**: Max 1MB per request
- **Method name validation**: Empty/too long method names rejected
- **Timeout handling**: Configurable timeouts for all IPC operations
- **Bounds checking**: Tool count enforcement at registration time
- **Structured logging**: All operations logged with targets (`ghost_mcp::*`)
- **Input validation**: ClientIdentity, PatchEntry validated with bounds checking
- **Graceful degradation**: Falls back to legacy protocol if handshake fails

## Testing

```bash
# Run all tests
cargo test -p ghost-mcp-common

# Run with verbose output
cargo test -p ghost-mcp-common --verbose
```

## License

See workspace root LICENSE file.
