# ghost-common

Shared types, IPC protocol, and capability system used across Ghost-MCP.

## Contents

- **IPC Protocol**: Length-prefixed JSON messaging between host and agent
- **Types**: Scanner, pointer scanner, dump, structure definitions
- **Capability System**: Read/write/execute/debug/admin scopes
- **Safety**: Tokens, modes, rate limiting, protected processes
- **Events**: Memory write, patch applied, session events

## Usage

```toml
[dependencies]
ghost-common = { path = "../ghost-common" }
```

## Key Types

- `Request` / `Response` - IPC message types
- `Capability` - Permission scopes
- `SafetyToken` - Authorization tokens
- `PatchEntry` - Patch history records
- `ScanProgress` - Scanner state
