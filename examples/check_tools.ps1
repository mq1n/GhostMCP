# check_tools.ps1 - List all registered tools across Ghost-MCP servers
# Run from project root: .\examples\check_tools.ps1

$ErrorActionPreference = "Stop"

Write-Host "Ghost-MCP Tool Inventory" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Expected tool counts
$expected = @{
    "ghost-core-mcp" = 85
    "ghost-analysis-mcp" = 82
    "ghost-static-mcp" = 84
    "ghost-extended-mcp" = 85
}

$total = 0

foreach ($server in $expected.Keys) {
    Write-Host "[$server]" -ForegroundColor Yellow
    Write-Host "  Expected: $($expected[$server]) tools"
    $total += $expected[$server]
}

Write-Host ""
Write-Host "Total tools across all servers: $total" -ForegroundColor Green
Write-Host "(Note: 4 shared meta tools on each server: mcp_capabilities, mcp_documentation, mcp_version, mcp_health)"
Write-Host ""

# Server ports
Write-Host "Server Ports:" -ForegroundColor Cyan
Write-Host "  Agent:    13338 (IPC endpoint)"
Write-Host "  Core:     13340 (ghost-core-mcp)"
Write-Host "  Analysis: 13341 (ghost-analysis-mcp)"
Write-Host "  Static:   13342 (ghost-static-mcp)"
Write-Host "  Extended: 13343 (ghost-extended-mcp)"
Write-Host ""

# Quick reference for common tools
Write-Host "Quick Reference - Common Tools:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Memory Operations:" -ForegroundColor Yellow
Write-Host "    memory_read, memory_write, memory_search, memory_regions"
Write-Host ""
Write-Host "  Scanning:" -ForegroundColor Yellow
Write-Host "    scan_new, scan_first, scan_next, scan_results, scan_cancel"
Write-Host ""
Write-Host "  Debugging:" -ForegroundColor Yellow
Write-Host "    breakpoint_set, breakpoint_remove, thread_list, stack_walk"
Write-Host ""
Write-Host "  Safety:" -ForegroundColor Yellow
Write-Host "    safety_status, safety_set_mode, patch_history, patch_undo"
Write-Host ""
Write-Host "  Extended (Injection, Anti-Debug, Input, Speedhack):" -ForegroundColor Yellow
Write-Host "    inject_dll, inject_shellcode, antidebug_enable, input_key_press, speed_set"
Write-Host ""
Write-Host "  Meta:" -ForegroundColor Yellow
Write-Host "    mcp_capabilities, mcp_documentation, mcp_version, mcp_health"
