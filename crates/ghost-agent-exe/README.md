# ghost-agent-exe

Standalone executable version of the ghost-agent.

## Purpose

Allows running ghost-agent as a normal process instead of an injected DLL. Useful for testing and development.

## Build

```bash
cargo build -p ghost-agent-exe --release
```

## Usage

```bash
ghost-agent-exe.exe
```

Listens on `127.0.0.1:13338` like the DLL version.
