# ghost-extended-mcp

Extended capabilities MCP server for Ghost-MCP. Port **13343**.

## Overview

This server provides advanced/extended tools that go beyond basic analysis:

| Category | Tools | Description |
|----------|-------|-------------|
| **Injection** | 22 | Remote process injection, cross-process hooking, process hollowing |
| **Anti-Debug** | 16 | Usermode hooks, PEB manipulation, anti-cheat bypasses |
| **Input** | 18 | Keyboard/mouse injection, window messages, DirectInput |
| **Address List** | 14 | Cheat table management, freeze values, persistence |
| **Memory** | 8 | Advanced memory operations, compare, fill, export |
| **Speedhack** | 7 | Time manipulation, timing API hooks |
| **Meta** | 4 | Shared MCP meta tools |

**Total: ~85 tools** (staying under the 90-tool MCP limit)

## Categories

### Injection (Phase 5.5b)
Agent-based remote injection capabilities:
- `inject_dll` - Inject DLL into remote process
- `inject_shellcode` - Inject and execute shellcode
- `inject_code` - Inject assembled code
- Remote memory operations (alloc, write, thread creation)
- Cross-process hooking (IAT/EAT patching, trampolines)
- Process hollowing, doppelganging, ghosting

### Anti-Debug Bypass (Phase 5.6)
ScyllaHide/TitanHide-style bypasses:
- NtQueryInformationProcess hooks
- PEB manipulation (BeingDebugged, NtGlobalFlag, Heap flags)
- Timing check evasion
- Debug register protection

### Input Injection (Phase 5.12)
Input automation capabilities:
- Keyboard simulation (SendInput, scan codes, WM_KEY*)
- Mouse injection (movement, clicks, scroll)
- Window message injection (PostMessage, SendMessage)
- DirectInput/XInput support

### Address List (Phase 5.18)
Cheat Engine-style table management:
- Add/edit/remove entries
- Freeze values at interval
- Group management
- Save/load project files

### Advanced Memory (Phase 5.20)
Extended memory operations:
- Memory block comparison (diff)
- Fill range with pattern
- Export as C array / hex string
- Label addresses
- Undo/redo for edits

### Speedhack (Phase 5.23)
Time manipulation:
- Speed multiplier (0.1x - 10x)
- Hook timing APIs (QPC, GetTickCount, timeGetTime)
- Sleep acceleration

## Usage

```bash
# Run with stdio transport (default)
ghost-extended-mcp

# Run with TCP transport
ghost-extended-mcp --transport tcp --port 13343

# Validate registry
ghost-extended-mcp --validate-registry

# Show all tools
ghost-extended-mcp --show-tools
```

## Configuration

Add to Claude Desktop config:
```json
{
  "mcpServers": {
    "ghost-extended": {
      "command": "path/to/ghost-extended-mcp.exe",
      "args": ["--transport", "stdio"]
    }
  }
}
```

## Implementation Status

This server defines tool interfaces for planned features. Agent-side implementation is pending for most tools.

| Phase | Status |
|-------|--------|
| 5.5b: Remote Injection | Not Started |
| 5.6: Anti-Debug Bypass | Not Started |
| 5.12: Input Injection | Not Started |
| 5.18: Address List | Not Started |
| 5.20: Advanced Memory | Not Started |
| 5.23: Speedhack | Not Started |
