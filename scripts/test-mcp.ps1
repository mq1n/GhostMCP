# Ghost-MCP Quick Test Script
# Tests ALL 4 MCP servers communication directly

param(
    [switch]$Verbose,
    [switch]$CoreOnly,
    [switch]$AnalysisOnly,
    [switch]$StaticOnly,
    [switch]$ExtendedOnly
)

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ReleasePath = Join-Path $ProjectRoot "target\release"

# All 4 MCP servers
$servers = @(
    @{ Name = "ghost-core-mcp";     Exe = Join-Path $ReleasePath "ghost-core-mcp.exe";     Port = 13340; ToolTarget = 85 },
    @{ Name = "ghost-analysis-mcp"; Exe = Join-Path $ReleasePath "ghost-analysis-mcp.exe"; Port = 13341; ToolTarget = 82 },
    @{ Name = "ghost-static-mcp";   Exe = Join-Path $ReleasePath "ghost-static-mcp.exe";   Port = 13342; ToolTarget = 84 },
    @{ Name = "ghost-extended-mcp"; Exe = Join-Path $ReleasePath "ghost-extended-mcp.exe"; Port = 13343; ToolTarget = 85 }
)

# Determine which servers to test
$testCore = $CoreOnly -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly)
$testAnalysis = $AnalysisOnly -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly)
$testStatic = $StaticOnly -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly)
$testExtended = $ExtendedOnly -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Ghost-MCP Server Test Suite (4 Servers)" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$totalPassed = 0
$totalFailed = 0

function Test-McpServer {
    param($Server)
    
    Write-Host "--- Testing $($Server.Name) (port $($Server.Port), target $($Server.ToolTarget) tools) ---" -ForegroundColor Cyan
    
    if (-not (Test-Path $Server.Exe)) {
        Write-Host "  [SKIP] Binary not found. Run: cargo build --release --package $($Server.Name)" -ForegroundColor Yellow
        return @{ Passed = 0; Failed = 1 }
    }
    
    $passed = 0
    $failed = 0
    
    # Test 1: Initialize
    Write-Host "  [Test 1] Initialize..." -ForegroundColor Yellow
    $initRequest = '{"jsonrpc":"2.0","id":"test-1","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
    try {
        $response = echo $initRequest | & $Server.Exe 2>$null | Select-Object -First 1
        $json = $response | ConvertFrom-Json
        if ($json.result.serverInfo) {
            Write-Host "    PASS: Server responded" -ForegroundColor Green
            Write-Host "    Server: $($json.result.serverInfo.name) v$($json.result.serverInfo.version)" -ForegroundColor Gray
            $passed++
        } else {
            Write-Host "    FAIL: Invalid response" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "    FAIL: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
    
    # Test 2: List Tools
    Write-Host "  [Test 2] List Tools..." -ForegroundColor Yellow
    $listRequest = '{"jsonrpc":"2.0","id":"test-2","method":"tools/list","params":{}}'
    try {
        $response = echo $listRequest | & $Server.Exe 2>$null | Select-Object -First 1
        $json = $response | ConvertFrom-Json
        $toolCount = $json.result.tools.Count
        if ($toolCount -gt 0) {
            $status = if ($toolCount -ge $Server.ToolTarget) { "Green" } else { "Yellow" }
            Write-Host "    PASS: Found $toolCount tools (target: $($Server.ToolTarget))" -ForegroundColor $status
            $passed++
            if ($Verbose) {
                foreach ($tool in $json.result.tools | Select-Object -First 10) {
                    Write-Host "      - $($tool.name)" -ForegroundColor Gray
                }
                if ($toolCount -gt 10) {
                    Write-Host "      ... and $($toolCount - 10) more" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "    FAIL: No tools returned" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "    FAIL: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
    
    Write-Host ""
    return @{ Passed = $passed; Failed = $failed }
}

# Test each server
foreach ($server in $servers) {
    $shouldTest = ($server.Name -eq "ghost-core-mcp" -and $testCore) -or
                  ($server.Name -eq "ghost-analysis-mcp" -and $testAnalysis) -or
                  ($server.Name -eq "ghost-static-mcp" -and $testStatic) -or
                  ($server.Name -eq "ghost-extended-mcp" -and $testExtended)
    
    if ($shouldTest) {
        $result = Test-McpServer -Server $server
        $totalPassed += $result.Passed
        $totalFailed += $result.Failed
    }
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Results: $totalPassed passed, $totalFailed failed" -ForegroundColor $(if ($totalFailed -eq 0) { "Green" } else { "Red" })
Write-Host "================================================" -ForegroundColor Cyan
