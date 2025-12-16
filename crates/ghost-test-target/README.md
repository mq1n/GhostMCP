# ghost-test-target

Test application with known memory layout for integration testing.

## Purpose

Provides a predictable target for testing Ghost-MCP functionality:

- Known memory addresses
- Exported functions
- Debug symbols
- Predictable behavior

## Build

```bash
cargo build -p ghost-test-target --release
```

## Usage

```bash
# Run the test target
ghost-test-target.exe

# Then inject ghost-agent
ghost-loader.exe --target ghost-test-target.exe
```

## Test Scenarios

- Memory read/write verification
- Pattern scanning tests
- Breakpoint testing
- Hook validation
