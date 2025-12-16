# ghost-agent

Injectable DLL that runs inside the target process.

## Purpose

Provides the in-process backend for Ghost-MCP. Gets injected into the target process and exposes memory, debugging, and execution capabilities over IPC.

## Features

- Multi-client TCP server on port 13338
- Handshake protocol with client identity
- Event bus with fan-out to subscribers
- Centralized shared state (patches, safety tokens, session metadata)

## Build

```bash
cargo build -p ghost-agent --release
```

Output: `target/release/ghost_agent.dll`

## Usage

Inject using `ghost-loader`:

```bash
ghost-loader.exe --target game.exe
```

The agent starts listening on `127.0.0.1:13338` once injected.
