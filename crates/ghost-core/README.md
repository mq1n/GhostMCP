# ghost-core

Static library with reverse engineering primitives.

## Features

- **Memory**: Read/write/search/scan operations
- **Disassembly**: Capstone-based disassembler
- **Debugging**: Breakpoints, stepping, register access
- **Hooks**: Inline, IAT/EAT, VEH hooks
- **Execution**: Shellcode, function calls, code caves
- **Scanner**: Cheat Engine-style value scanner
- **Pointer Scanner**: Multi-level pointer path finder

## Usage

```toml
[dependencies]
ghost-core = { path = "../ghost-core" }
```

## Build

```bash
cargo build -p ghost-core --release
```

Used as a dependency by ghost-agent and MCP servers.
