# ghost-loader

Multi-method DLL injector for Ghost-MCP.

## Injection Methods

- LoadLibraryExW (standard)
- Manual mapping (planned)

## Usage

```bash
# Inject into running process
ghost-loader.exe --target game.exe

# Inject by PID
ghost-loader.exe --pid 1234

# Launch and inject
ghost-loader.exe --launch "C:\path\to\game.exe"
```

## Launch Modes

- **Normal**: Standard process launch
- **Suspended**: Launch suspended, inject, resume
- **Debug**: Attach as debugger
- **Delayed**: Wait N seconds before injection
- **WaitForModule**: Wait for specific DLL to load

## Build

```bash
cargo build -p ghost-loader --release
```
