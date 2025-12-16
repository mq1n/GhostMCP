# ghost-re-backends

Reverse engineering tool communication backends for Ghost-MCP.

## Overview

This crate provides a unified interface for communicating with reverse engineering tools. Supports multiple backends with a trait-based architecture:

- **Radare2** - Cross-platform, via `r2pipe` crate
- **IDA Pro** - Via `idalib` crate (requires IDA v9.x)
- **Ghidra** - Via `fugue-ghidra` crate (Linux/macOS only)

## Features

- **Unified `ReBackend` trait** - Common interface for all RE tools
- **Multiple backends** - Choose the best tool for your needs
- **Thread-safe** - Uses `Mutex`/`RwLock` for safe concurrent access
- **Production-ready** - Comprehensive logging, input validation, error handling
- **Async-ready** - All operations are async-compatible

## Requirements

### Radare2 Backend (cross-platform)

- [radare2](https://rada.re/n/) must be installed and available in PATH
- For decompilation: `r2ghidra` or `r2dec` plugin recommended

### IDA Pro Backend (requires license)

- IDA Pro v9.x installation
- `IDADIR` environment variable pointing to IDA installation
- LLVM/Clang for building (idalib uses bindgen)

### Ghidra Backend (Linux/macOS only)

- Ghidra installation (9.x or later)
- GMP/MPFR libraries
- **NOT available on Windows MSVC** (use MinGW or Linux/macOS)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
# Radare2 only (cross-platform)
ghost-re-backends = { path = "../ghost-re-backends", features = ["radare2"] }

# IDA Pro only (requires IDA v9.x)
# ghost-re-backends = { path = "../ghost-re-backends", features = ["ida"] }

# Ghidra only (Linux/macOS)
# ghost-re-backends = { path = "../ghost-re-backends", features = ["ghidra"] }

# All backends (only on supported platforms)
# ghost-re-backends = { path = "../ghost-re-backends", features = ["all"] }
```

### Basic Example

```rust
use ghost_re_backends::{Radare2Backend, ReBackend};

#[tokio::main]
async fn main() -> ghost_re_backends::Result<()> {
    // Create backend
    let mut backend = Radare2Backend::new();
    
    // Open a binary
    let info = backend.open("/path/to/binary").await?;
    println!("Architecture: {}", info.architecture);
    println!("Entry point: 0x{:x}", info.entry_point);
    
    // List functions
    let functions = backend.list_functions().await?;
    for func in functions.iter().take(10) {
        println!("  0x{:x}: {}", func.address, func.name);
    }
    
    // Disassemble
    let instructions = backend.disassemble(info.entry_point, 20).await?;
    for insn in &instructions {
        println!("  0x{:x}: {}", insn.address, insn.disasm);
    }
    
    // Close when done
    backend.close().await?;
    Ok(())
}
```

### Connection Methods

```rust
// Spawn local r2 instance (default)
let mut backend = Radare2Backend::new();
backend.open("/path/to/binary").await?;

// Connect to r2 HTTP server
let backend = Radare2Backend::connect_http("localhost", 9090)?;

// Connect to r2 TCP server  
let backend = Radare2Backend::connect_tcp("localhost", 9091)?;

// Spawn with custom options
use r2pipe::R2PipeSpawnOptions;
let options = R2PipeSpawnOptions { /* ... */ };
let backend = Radare2Backend::with_options("/path/to/binary", options)?;
```

## API Overview

The `ReBackend` trait provides these operations:

| Category | Methods |
|----------|---------|
| **Lifecycle** | `open`, `close`, `is_connected` |
| **Binary Info** | `get_binary_info` |
| **Functions** | `list_functions`, `get_function`, `get_function_by_name` |
| **Disassembly** | `disassemble`, `disassemble_function` |
| **CFG** | `get_basic_blocks` |
| **Decompilation** | `decompile` |
| **Cross-refs** | `get_xrefs_to`, `get_xrefs_from` |
| **Data** | `list_strings`, `list_imports`, `list_exports` |
| **Memory** | `read_bytes` |
| **Annotations** | `rename`, `add_comment` |
| **Raw** | `raw_command` |

## Common Types

```rust
// Binary information
pub struct BinaryInfo {
    pub path: String,
    pub format: String,        // PE, ELF, Mach-O, etc.
    pub architecture: String,  // x86, x86_64, ARM, etc.
    pub bits: u32,             // 32 or 64
    pub endian: Endianness,
    pub entry_point: u64,
    pub base_address: u64,
    pub sections: Vec<SectionInfo>,
}

// Function information
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub end_address: Option<u64>,
    pub size: Option<u64>,
    pub is_external: bool,
    pub signature: Option<String>,
    pub calling_convention: Option<String>,
    pub attributes: HashMap<String, String>,
}

// Disassembled instruction
pub struct DisassembledInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub disasm: String,
    pub size: u64,
    pub comment: Option<String>,
}
```

## Error Handling

All operations return `Result<T, Error>` with detailed error types:

```rust
pub enum Error {
    BackendNotAvailable(String),
    Connection(String),
    CommandFailed(String),
    Analysis(String),
    FileNotFound(String),
    InvalidAddress(u64),
    Parse(String),
    Timeout,
    Internal(String),
}
```

## Logging

The crate uses `tracing` for structured logging. Enable with:

```rust
tracing_subscriber::fmt()
    .with_env_filter("ghost_re_backends=debug")
    .init();
```

## Platform Compatibility

| Backend | Windows MSVC | Windows MinGW | Linux | macOS |
|---------|--------------|---------------|-------|-------|
| **Radare2** | ✅ | ✅ | ✅ | ✅ |
| **IDA Pro** | ⚠️ Requires SDK | ⚠️ Requires SDK | ✅ | ✅ |
| **Ghidra** | ✅ Headless/RPC | ✅ | ✅ | ✅ |

### Ghidra Modes

The Ghidra backend supports two modes:

1. **Headless Mode** (default) - Spawns `analyzeHeadless` to analyze binaries
   - Requires `GHIDRA_INSTALL_DIR` environment variable
   - Best for batch analysis of static files
   - Exports: functions, strings, imports, exports

2. **JSON-RPC Mode** - Connects to [ghidra-pipe](https://github.com/Nalen98/ghidra-pipe) server
   - Requires ghidra-pipe plugin installed in Ghidra
   - Supports live analysis: disassembly, decompilation, xrefs
   - Best for interactive analysis

## Production Notes

- All backends implement comprehensive `tracing` logging
- Input validation on all public APIs (path validation, address bounds)
- Thread-safe with `Mutex`/`RwLock` for concurrent access
- Graceful error handling with detailed error messages
- Shell command injection prevention in raw command APIs

## Future Plans

- Binary Ninja support
- Cutter integration
- Remote debugging support

## License

MIT
