# Ghost-MCP 👻

**Talk to your binaries.** Point the AI at a process and let him cook.

Ghost-MCP is an injectable MCP (Model Context Protocol) server for vibe reverse engineering assistant on Windows. It combines memory inspection, disassembly, debugging, and code injection into a single tool that any MCP-compatible AI client can use. Inject it into a target process and interact through natural conversation.

> ⚠️ **EXPERIMENTAL**: This project is highly experimental and under development. APIs may change without notice, features may be incomplete or unstable, and documentation may not reflect the current state. Use at your own risk.

## What Can You Do With It?

Ask your AI assistant things like:
- *"Find the health value in this game and freeze it at 100"*
- *"Show me all functions that reference this string"*
- *"Set a breakpoint on MessageBoxA and tell me when it gets called"*
- *"Disassemble the function at this address and explain what it does"*
- *"Find all pointers that lead to this address"*

The AI handles the technical details. You just describe what you want.

## Multi-Server Architecture

Ghost-MCP uses a modular multi-server architecture to provide 250+ tools while staying under MCP client limits:

| Server | Port | Tools | Purpose |
|--------|------|-------|--------|
| **ghost-core-mcp** | 13340 | 85 | Memory, debugging, execution, safety |
| **ghost-analysis-mcp** | 13341 | 82 | Scanning, pointers, dumps, structures |
| **ghost-static-mcp** | 13342 | 84 | Radare2, IDA, Ghidra, AI, YARA |
| **ghost-extended-mcp** | 13343 | 85 | Injection, anti-debug, input, speedhack |

**Quick Setup:**
- Agent listens on `13338`; core server uses `stdio`, analysis/static on TCP
- `scripts/launch-mcp.ps1` starts one or all servers
- Destructive operations require safety tokens: call `safety_request_token`, then include `token_id`

## Features

### Memory Operations (Cheat Engine-style)
Everything you need to hunt down values and manipulate memory:
- **Read/write memory** with automatic type conversion (integers, floats, strings, bytes)
- **Region enumeration** with protection flags (readable, writable, executable)
- **Pattern scanning** with AOB wildcards (`48 8B ?? ?? 90`)
- **Pointer chain resolution** for complex data structures

### Pattern Scanning & YARA
Advanced pattern matching for malware analysis and signature scanning:
- **AOB scanning** for Array of Bytes with wildcard support
- **String scanning** for ASCII, Unicode (UTF-16), and UTF-8 patterns
- **Regex patterns** with byte-level matching (requires `yara` feature)
- **YARA integration** to load and run rules against memory
- **Signature databases** to store, import, and export named patterns
- **Named signatures** to organize patterns with tags and descriptions

### Memory Dump & Analysis
Full process memory dumping with PE reconstruction:
- **Full process dumps** to capture all committed memory regions
- **Selective region dumps** for specific address ranges
- **Module dumps** to extract DLLs/EXEs with PE reconstruction
- **Minidump creation** in WinDbg-compatible format
- **Incremental dumps** to track changes between snapshots
- **Binary diff** to compare dumps and find modifications
- **Pattern search** within dumps using AOB patterns
- **Annotations** to bookmark and label interesting locations
- **PE reconstruction** with Scylla-style import table rebuilding
- **Dump catalog** to organize and manage multiple dumps

### Advanced Value Scanner
A full Cheat Engine-style scanner with session management:
- **12 scan modes** including exact, changed, unchanged, increased, decreased, greater, less, between, unknown initial, fuzzy, and more
- **Iterative scanning** to refine results across multiple scans
- **Smart filtering** for writable-only, executable, module-only, custom address ranges
- **Fast scan mode** with alignment-based skipping for 4x+ speedup
- **Live progress** with real-time tracking and cancellation
- **Export/Import** to save results as JSON, CSV, or Cheat Engine XML

### Pointer Scanner (Cheat Engine-style)
Find stable pointer paths to dynamic addresses:
- **Multi-level scanning** with configurable depth (1-10 levels) to find pointer chains
- **Static base filtering** to only include module-relative pointers that survive restarts
- **Offset constraints** with configurable max offset and alignment options
- **Pointer rescanning** to validate paths after process restart with stability scoring
- **Stability scoring** that tracks pointer validity across rescans (0.0-1.0 score)
- **Session comparison** to find common valid pointers between scan sets
- **Pointer resolution** to follow chains and read values at resolved addresses
- **Export/Import** in JSON, CSV, or Cheat Engine pointer format (.ptr)
- **Pagination** for large result sets with configurable limits
- **Progress tracking** with real-time updates and cancellation support

### Static Analysis (IDA Pro-style)
Navigate code like a pro:
- **Disassembly** via Capstone engine (`disasm_at`, `disasm_function`)
- **Decompilation** with Hex-Rays style pseudo-C generation
- **Module inspection** to list all DLLs, their exports and imports
- **Symbol resolution** via PDB loading with DbgHelp and full stack walking support
- **Cross-references** to find all CALL/JMP/LEA references to any address
- **String extraction** to pull ASCII/Unicode strings from any module

### Dynamic Debugging (x64dbg-style)
Full in-process debugging without an external debugger:
- **Software breakpoints** using INT3 injection with automatic byte restoration
- **Hardware breakpoints** via DR0-DR3 debug registers (4 slots)
- **Single stepping** with trap flag based instruction-by-instruction execution
- **Thread control** to list, suspend, resume any thread
- **Register access** to read/write all x64 registers (RAX-R15, RIP, RFLAGS)
- **Stack walking** for full call stack with symbol resolution

### Direct Execution & Code Injection
Run arbitrary code inside the target process:
- **Assembler** for x86/x64 text-to-bytes assembly using iced-x86 (pure Rust, actively maintained)
  - Supports common instructions: MOV, ADD, SUB, XOR, PUSH, POP, CALL, JMP, conditional jumps, etc.
  - Multiple syntax options: newline or semicolon-separated instructions
  - Hex immediates: `0x1234` or `1234h` format
  - Shellcode generation helpers for function calls (x64 Windows ABI)
- **Function calling** with full calling convention support (cdecl, stdcall, fastcall, win64, thiscall)
- **Dynamic resolution** with GetProcAddress-style lookups and caching
- **Shellcode execution** with multiple methods:
  - Direct call in current thread
  - New thread (CreateThread, NtCreateThreadEx)
  - APC injection
  - Thread hijacking
- **Memory management** to allocate, write, and free executable memory
- **Code caves** to find and use unused executable space
- **Syscall extraction** to get syscall numbers directly from ntdll stubs
- **Remote execution** to inject code into other processes

### Process & Session Management
Full control over target processes:
- **Process listing** to enumerate running processes with filtering
- **Process spawning** to launch processes (normal or suspended)
- **Attach/detach** to connect to processes by name or PID
- **Multiple launch modes** including Normal, Suspended, Debug, Delayed, WaitForModule

### Process & System Introspection
Deep visibility into process internals:
- **Process details** including PID, path, architecture, thread/handle counts, PEB address
- **PEB access** for BeingDebugged flag, image base, loader data, OS version info
- **Memory maps** showing complete virtual memory layout with protection and region types
- **Thread introspection** with enumeration, TEB access, TLS slots, priority info
- **Module details** with base address, size, entry point, version info
- **Window enumeration** with title, class, styles, hierarchy and filtering
- **Token analysis** for user SID, privileges, elevation status, integrity level
- **Privilege manipulation** to enable/disable privileges like SeDebugPrivilege
- **Environment access** to read environment variables and working directory

### MCP Meta Commands
Self-discovery and introspection:
- **Capability discovery** to list all available tools with categories
- **Documentation** to get detailed help and examples for any tool
- **Health checks** to verify agent connection and script engine status
- **Version info** for server version and build information

### AI/LLM Bidirectional Command Support
Seamless integration for AI-assisted analysis:
- **Command batching** to execute multi-step command sequences with conditions
- **Command history** to query and replay previous commands
- **Event subscriptions** for breakpoint hits, exceptions, memory changes, hook triggers
- **AI-friendly summaries** with context-aware summarization of operation results
- **Diff reporting** to compare states (memory, registers, modules) with structured diffs
- **Error explanations** with natural language messages and suggested fixes
- **Debug sessions** for conversational debugging with findings, hypotheses, and next steps
- **Breakpoint recommendations** with AI-driven suggestions for breakpoint locations
- **Vulnerability analysis** for automated security pattern detection
- **Pattern learning** to save and recall code patterns, behaviors, and data structures

### Extended Hooking Methods
Comprehensive hooking toolkit for function interception:
- **Inline hooks** with trampoline-based detours (5/14-byte jumps), mid-function hooks, hot-patching, INT3 breakpoint hooks
- **IAT/EAT hooks** for Import and Export Address Table hooking with enumeration
- **VEH/PAGE_GUARD hooks** for hardware-less memory breakpoints via vectored exception handling
- **Syscall hooks** via ntdll stub patching for syscall interception
- **Shellcode generation** for position-independent code templates (call function, load library, etc.)
- **Shellcode encoding** with XOR encoder and decoder stub generation
- **ROP gadget finder** to search loaded modules for return-oriented programming gadgets
- **Hook management** with enable/disable, chaining, and transactions for atomic multi-hook operations

### API Call Tracing & Monitoring (Rohitab API Monitor-style)
Full Win32 API call tracing with argument decoding:
- **Trace sessions** to create, start, stop, pause, resume tracing
- **Event pipeline** with configurable ring buffer and backpressure strategies (drop oldest, block, sample)
- **API packs** with JSON-based definitions for kernel32, user32, ntdll, ws2_32, advapi32
- **Server-side filtering** to include/exclude by API name, module, thread, return value
- **Pattern matching** with prefix, suffix, contains, wildcard, and regex support
- **Filter presets** including built-in presets (File Ops, Network, Registry, Errors Only) plus custom
- **Statistics** for per-API call counts, durations, success/failure rates
- **Queue monitoring** for depth, drops, events per second

### Advanced Process Monitoring
Extended monitoring capabilities for deep analysis:
- **Dynamic API monitoring** to track GetProcAddress/LdrGetProcedureAddress resolutions
- **Process chill** to freeze/resume threads for static analysis (all, specific, or filtered)
- **COM object scanning** to detect and enumerate COM interfaces with vtable analysis
- **DLL monitoring** to capture LoadLibrary/FreeLibrary events with call stacks
- **Delayed imports** to scan and monitor delayed DLL loads (__delayLoadHelper2)

### API Override & Conditional Breakpoints
Full parameter and return value manipulation with conditional control:
- **Conditional breakpoints** with before/after call timing, argument/return conditions, thread ID filters
- **Compound conditions** using AND/OR/NOT logic, hit count triggers (Nth call, every Nth call)
- **Parameter override** to modify integers, booleans, pointers, strings (ANSI/Unicode), buffers, NULL injection
- **Return value override** for return code modification, HRESULT/NTSTATUS helpers, SetLastError control
- **Pause mechanism** for thread coordination, configurable timeouts with auto-continue
- **Audit trail** with full logging of all modifications, before/after values, export to JSON/CSV

### Advanced Pattern Matching
Powerful instruction-level search capabilities:
- **Instruction sequences** to find code patterns with wildcard mnemonics and operand matching
- **Operand search** to find instructions by register type, immediate values, memory operands
- **Immediate search** to locate values in code/data with range matching and alignment options
- **String search** for ASCII/UTF-16 pattern matching with case sensitivity control
- **Cross-reference search** to find all code/data references to addresses
- **Unified search** with cursor pagination for large result sets

### Safety & Guardrails
Comprehensive safety system to prevent accidents:
- **Safety modes** with Educational (blocks dangerous ops), Standard (requires approval), Expert (minimal restrictions)
- **Protected processes** with automatic detection and blocking for system processes (csrss, lsass, svchost, etc.)
- **Rate limiting** using token bucket algorithm for global ops and write-specific throttling
- **Size limits** with configurable limits for read/write/scan operations and warnings at 80% threshold
- **Approval workflow** requiring explicit token-based approval for dangerous operations
- **Patch history** with full undo capability via `patch_undo` tool
- **Dry-run preview** to preview patches before applying with `patch_preview`
- **Auto-backup** for automatic state backup and crash recovery

### DLL Injection (via ghost-loader)
Flexible injection options:
- **LoadLibraryExW** for standard Windows injection
- **Process attachment** by PID, name, or wait-for-process
- **Launch modes** including Normal, Suspended, Debug, Delayed, WaitForModule
- **x86/x64 support** for both 32-bit and 64-bit processes

### External RE Tool Integration
Connect to your favorite reverse engineering tools:
- **Radare2** with full r2pipe integration (cross-platform)
- **Ghidra** via headless mode or JSON-RPC through ghidra-pipe
- **IDA Pro** via idalib (requires IDA v9.x)
- **Unified API** providing a consistent interface across all backends

## Architecture

Ghost-MCP uses a modular multi-server architecture to stay under MCP's ~100 tool limit while providing 250+ tools:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AI CLIENTS                                      │
│              Claude Desktop │ Cursor │ Windsurf │ Custom                     │
└───────┬─────────────┬─────────────┬─────────────┬───────────────────────────┘
        │             │             │             │
        ▼             ▼             ▼             ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│ghost-core-mcp │ │ghost-analysis │ │ghost-static   │ │ghost-extended │
│  Port 13340   │ │  Port 13341   │ │  Port 13342   │ │  Port 13343   │
│   85 tools    │ │   82 tools    │ │   84 tools    │ │   85 tools    │
│ Memory, Debug │ │ Scanner, Dump │ │ R2, IDA, AI   │ │ Inject, Input │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │                 │
        └─────────────────┴─────────────────┴─────────────────┘
                                  │ IPC (TCP localhost:13338)
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                LAYER 2: INJECTED AGENT                          │
│                     ghost-agent.dll                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │               ghost-core (static library)                 │  │
│  │    Memory │ Disasm │ Debug │ Hooks │ Scanner │ Exec      │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬─────────────────────────────────┘
                                │ Direct Access
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TARGET PROCESS                             │
│                   (game.exe, app.exe, etc.)                     │
└─────────────────────────────────────────────────────────────────┘
```

### Modular Servers

| Server | Port | Tools | Purpose |
|--------|------|-------|---------|
| **ghost-core-mcp** | 13340 | 85 | Live process: memory, debugging, execution, safety |
| **ghost-analysis-mcp** | 13341 | 82 | Analysis: scanning, pointers, dumps, structures |
| **ghost-static-mcp** | 13342 | 84 | Static RE: Radare2, IDA, Ghidra, AI, YARA |
| **ghost-extended-mcp** | 13343 | 85 | Extended: injection, anti-debug, input, speedhack |

Each server includes 4 shared meta tools (`mcp_capabilities`, `mcp_documentation`, `mcp_version`, `mcp_health`) and stays under the 90-tool MCP limit.

**Why this design?**
- **Safety** because the agent is tiny and crash-resistant; heavy lifting happens in the host
- **Flexibility** since the same core works as injected DLL or standalone EXE
- **AI-friendly** with structured JSON responses, pagination, clear error messages

## Quick Start

### 1. Build
```bash
cargo build --release
```

### 2. Inject into target
```bash
ghost-loader.exe --target game.exe
```

### 3. Connect your AI client

Add to your Claude Desktop config (`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ghost-core": {
      "command": "path/to/ghost-core-mcp.exe",
      "args": ["--transport", "stdio"]
    },
    "ghost-analysis": {
      "command": "path/to/ghost-analysis-mcp.exe",
      "args": ["--port", "13341"]
    },
    "ghost-static": {
      "command": "path/to/ghost-static-mcp.exe",
      "args": ["--port", "13342"]
    },
    "ghost-extended": {
      "command": "path/to/ghost-extended-mcp.exe",
      "args": ["--port", "13343"]
    }
  }
}
```

Start chatting with your favorite AI about your target process.

### 4. Verify Setup

```powershell
# Validate all server registries
.\scripts\launch-mcp.ps1 -ValidateOnly

# Or launch everything with one command
.\scripts\launch-mcp.ps1 -Target game.exe
```

## Components

| Component | Description |
|-----------|-------------|
| **ghost-host** | MCP server that talks to AI clients and routes commands |
| **ghost-core** | Static library with all the RE primitives |
| **ghost-agent** | Injected DLL that runs inside the target process |
| **ghost-loader** | Multi-method DLL injector |
| **ghost-common** | Shared types, IPC protocol, capability system |
| **ghost-mcp-common** | Shared MCP server infrastructure (registry, config, health) |
| **ghost-core-mcp** | Modular MCP server for live process tools (85 tools, port 13340) |
| **ghost-analysis-mcp** | Modular MCP server for analysis tools (82 tools, port 13341) |
| **ghost-static-mcp** | Modular MCP server for static RE tools (84 tools, port 13342) |
| **ghost-extended-mcp** | Modular MCP server for extended capabilities (85 tools, port 13343) |
| **ghost-re-backends** | Integrations with Radare2, Ghidra, IDA |
| **ghost-test-target** | Test application with known memory layout |
| **ghost-mcp-client** | CLI MCP client for testing and automation |

## Development & Testing

```bash
# Run all tests (370+ unit tests)
cargo test --workspace

# Build release binaries
cargo build --release

# Format and lint
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
```

### Testing Stack

We use a multi-layered testing approach:

- **Unit tests** Core modules have comprehensive tests for memory ops, pattern matching, disassembly, hooks, IPC, and type conversions
- **Integration tests** `tests/integration/` validates end-to-end flows: injection, memory R/W, pattern scans, breakpoints, hooks
- **IPC fuzzing** `tests/integration/ipc_fuzzing.rs` stress-tests the protocol with malformed/random messages
- **CI pipeline** GitHub Actions runs the full test suite on every push

### Test Targets

| Component | What's Tested |
|-----------|---------------|
| `ghost-test-target` | Dummy app with known memory layout, exported functions, debug symbols |
| `ghost-mcp-client` | CLI for manual testing, scripted automation, and regression checks |

```bash
# CLI testing examples
ghost-client --stdio --host-binary ./target/release/ghost-host tools
ghost-client --stdio --host-binary ./target/release/ghost-host call mcp_version
ghost-client --stdio --host-binary ./target/release/ghost-host repl
```

### Design Principles
1. **Safety First** so we never crash the target process
2. **AI-First** with structured outputs, clear errors, pagination
3. **Modular** with clean separation between host, core, and agent
4. **Extensible** via trait-based design for easy backend swapping

## Security Model

Ghost-MCP uses a capability-based security model with comprehensive safety guardrails:

### Capability Scopes

| Capability | Risk | Operations |
|------------|------|------------|
| **read** | Low | Memory reads, module listings, introspection (default) |
| **write** | Medium | Memory writes, patch operations |
| **execute** | High | Function calls, shellcode, remote threads |
| **debug** | Medium | Breakpoints, thread suspend/resume, stepping |
| **admin** | High | Safety mode changes, agent reconnect |

### Safety Tokens

Destructive operations require **safety tokens** for authorization:
1. Client requests token: `safety_request_token(scope: "write", ttl_secs: 300)`
2. Agent validates client has required capability and issues token
3. Client includes `token_id` in subsequent write operations
4. Token auto-expires or client releases it explicitly

Tokens have configurable TTL (max 24 hours) and are one-time use for maximum safety.

### Safety Modes

| Mode | Description | Dangerous Ops |
|------|-------------|---------------|
| **Educational** | Maximum restrictions for learning | Blocked |
| **Standard** | Default mode with approval workflow | Requires approval |
| **Expert** | Minimal restrictions for experienced users | Allowed |

### Safety Tools

| Tool | Description |
|------|-------------|
| `safety_status` | View current mode, stats, and pending approvals |
| `safety_set_mode` | Switch between educational/standard/expert |
| `safety_approve` | Approve a pending dangerous operation |
| `patch_history` | View all patches applied this session |
| `patch_undo` | Restore original bytes for any patch |
| `patch_preview` | Dry-run preview before applying patches |

Dangerous operations require explicit confirmation in Standard mode. Use `safety_set_mode expert` to disable approval requirements.

## Use Cases

- **Security Research** for vulnerability analysis, exploit development, fuzzing
- **Malware Analysis** for dynamic analysis, unpacking, anti-debug bypass
- **Game Hacking** for value scanning, pointer resolution, trainers
- **Software Testing** for fault injection, behavior modification, coverage analysis
- **Learning** to understand how programs work at the binary level

## Responsible Use

Ghost-MCP is a powerful tool that provides deep access to process internals. With that power comes responsibility.

### Intended Use

- **Educational purposes** to learn reverse engineering and understand how software works at the binary level
- **Security research** to analyze vulnerabilities in software you own or have explicit authorization to test
- **Game modding** to modify single-player and offline games for personal enjoyment
- **Software development** to debug your own applications, test edge cases, analyze performance

### Prohibited Use

- **Online multiplayer cheating** - do not use this tool to gain unfair advantages in online games
- **Circumventing protections illegally** - do not bypass DRM, licensing, or security measures on software you don't own
- **Malicious activities** - do not use for malware development, unauthorized access, or any illegal purposes
- **Violating terms of service** - respect the EULA and ToS of software you interact with

**You are solely responsible for ensuring your use complies with applicable laws and regulations in your jurisdiction.**

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Run `cargo fmt --all` and `cargo clippy --workspace -- -D warnings` before submitting.

## License

MIT
