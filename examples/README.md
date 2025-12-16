# Examples

Quick scripts and examples for testing Ghost-MCP functionality.

## Quick Checks

| Script | Purpose |
|--------|---------|
| `check_build.ps1` | Verify project builds without errors |
| `check_tools.ps1` | List all registered tools across servers |
| `check_registry.ps1` | Validate tool registries match expected counts |

## Usage

```powershell
# Run from project root
.\examples\check_build.ps1
.\examples\check_tools.ps1
.\examples\check_registry.ps1
```

## Tool Categories

### ghost-core-mcp (Port 13340)
- Memory: `memory_read`, `memory_write`, `memory_search`, `memory_regions`
- Module: `module_list`, `module_exports`, `module_imports`
- Debug: `breakpoint_set`, `breakpoint_list`, `thread_list`
- Safety: `safety_status`, `safety_set_mode`, `patch_history`

### ghost-analysis-mcp (Port 13341)
- Scanner: `scan_new`, `scan_first`, `scan_next`, `scan_results`
- Pointer: `pointer_scan_start`, `pointer_scan_results`
- Dump: `dump_create`, `dump_region`, `dump_compare`

### ghost-static-mcp (Port 13342)
- Radare2: `r2_session`, `r2_disasm`, `r2_functions`
- IDA: `ida_session`, `ida_disasm`, `ida_decompile`
- Ghidra: `ghidra_session`, `ghidra_disasm`
- YARA: `yara_scan_memory`, `yara_create_rule`

### ghost-extended-mcp (Port 13343)
- Injection: `inject_dll`, `inject_shellcode`, `inject_remote_thread`
- Anti-Debug: `antidebug_status`, `antidebug_enable`, `bypass_peb`
- Input: `input_key_press`, `input_mouse_click`, `input_send_message`
- Speedhack: `speed_status`, `speed_set`, `speed_reset`

## Example Tool Calls

```json
// Read memory
{"method": "tools/call", "params": {"name": "memory_read", "arguments": {"address": "0x7FF00000", "size": 64}}}

// List modules
{"method": "tools/call", "params": {"name": "module_list", "arguments": {}}}

// Start a scan
{"method": "tools/call", "params": {"name": "scan_new", "arguments": {"value_type": "i32"}}}
```
