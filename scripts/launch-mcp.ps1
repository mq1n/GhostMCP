# Ghost-MCP Launch Script
# Builds, launches target, injects agent, and prepares for MCP interaction
# Supports multi-server architecture (core, analysis, static)

param(
    [Parameter(Position=0)]
    [string]$Target = "ghost-test-target.exe",
    
    [switch]$Build,
    [switch]$SkipInjection,
    [switch]$ShowOutput,
    
    # Multi-server options
    [switch]$CoreOnly,      # Only start ghost-core-mcp
    [switch]$AnalysisOnly,  # Only start ghost-analysis-mcp
    [switch]$StaticOnly,    # Only start ghost-static-mcp
    [switch]$ExtendedOnly,  # Only start ghost-extended-mcp
    [switch]$All,           # Start all servers (default behavior)
    [switch]$ValidateOnly   # Only validate registries, don't start servers
)

$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ghost-MCP Launch Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Paths
$ReleasePath = Join-Path $ProjectRoot "target\release"
$TestTargetExe = Join-Path $ReleasePath "ghost-test-target.exe"
$LoaderExe = Join-Path $ReleasePath "ghost-loader.exe"
$AgentDll = Join-Path $ReleasePath "ghost_agent.dll"

# Multi-server paths
$CoreMcpExe = Join-Path $ReleasePath "ghost-core-mcp.exe"
$AnalysisMcpExe = Join-Path $ReleasePath "ghost-analysis-mcp.exe"
$StaticMcpExe = Join-Path $ReleasePath "ghost-static-mcp.exe"
$ExtendedMcpExe = Join-Path $ReleasePath "ghost-extended-mcp.exe"

# Server configuration
$servers = @(
    @{ Name = "ghost-core-mcp";     Port = 13340; Exe = $CoreMcpExe;     Transport = "stdio"; ToolTarget = 85 },
    @{ Name = "ghost-analysis-mcp"; Port = 13341; Exe = $AnalysisMcpExe; Transport = "tcp";   ToolTarget = 82 },
    @{ Name = "ghost-static-mcp";   Port = 13342; Exe = $StaticMcpExe;   Transport = "tcp";   ToolTarget = 84 },
    @{ Name = "ghost-extended-mcp"; Port = 13343; Exe = $ExtendedMcpExe; Transport = "tcp";   ToolTarget = 85 }
)

# Handle ValidateOnly mode
if ($ValidateOnly) {
    Write-Host "[Validate Mode] Checking tool registries..." -ForegroundColor Cyan
    $allValid = $true
    foreach ($server in $servers) {
        if (Test-Path $server.Exe) {
            Write-Host "  Validating $($server.Name)..." -ForegroundColor Yellow
            & $server.Exe --validate-registry
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [OK] Registry valid" -ForegroundColor Green
            } else {
                Write-Host "    [FAIL] Registry validation failed" -ForegroundColor Red
                $allValid = $false
            }
        } else {
            Write-Host "  [SKIP] $($server.Name) not built" -ForegroundColor Gray
        }
    }
    if ($allValid) {
        Write-Host "`nAll registries valid!" -ForegroundColor Green
    } else {
        Write-Host "`nSome registries failed validation!" -ForegroundColor Red
        exit 1
    }
    exit 0
}

# Determine which servers to launch (default: all)
$startCore = $CoreOnly -or $All -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly -and -not $All -and -not $ValidateOnly)
$startAnalysis = $AnalysisOnly -or $All -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly -and -not $All -and -not $ValidateOnly)
$startStatic = $StaticOnly -or $All -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly -and -not $All -and -not $ValidateOnly)
$startExtended = $ExtendedOnly -or $All -or (-not $CoreOnly -and -not $AnalysisOnly -and -not $StaticOnly -and -not $ExtendedOnly -and -not $All -and -not $ValidateOnly)

# Step 1: Check if binaries exist
$allExist = (Test-Path $TestTargetExe) -and (Test-Path $LoaderExe) -and (Test-Path $AgentDll) -and 
            (Test-Path $CoreMcpExe) -and (Test-Path $AnalysisMcpExe) -and (Test-Path $StaticMcpExe) -and (Test-Path $ExtendedMcpExe)

if ($Build -or -not $allExist) {
    Write-Host "[1/5] Building release binaries..." -ForegroundColor Yellow
    Push-Location $ProjectRoot
    try {
        # Run cargo build, ignore stderr warnings
        $output = cmd /c "cargo build --workspace --release --features radare2,ghidra 2>&1"
        $buildFailed = $LASTEXITCODE -ne 0
        
        if ($buildFailed) {
            # Check if it's just a file lock issue
            if ($output -match "Access is denied") {
                Write-Host "  Warning: Some binaries are in use (probably by Claude Desktop)" -ForegroundColor Yellow
                Write-Host "  Using existing binaries..." -ForegroundColor Yellow
            } else {
                Write-Host "Build failed!" -ForegroundColor Red
                Write-Host $output -ForegroundColor Gray
                exit 1
            }
        } else {
            Write-Host "  Build complete!" -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[1/5] Binaries already built (use -Build to rebuild)" -ForegroundColor Gray
}

# Verify all binaries exist
# Required binaries for modular server architecture
$binaries = @{
    "ghost-test-target.exe" = $TestTargetExe
    "ghost-loader.exe" = $LoaderExe
    "ghost_agent.dll" = $AgentDll
    "ghost-core-mcp.exe" = $CoreMcpExe
    "ghost-analysis-mcp.exe" = $AnalysisMcpExe
    "ghost-static-mcp.exe" = $StaticMcpExe
    "ghost-extended-mcp.exe" = $ExtendedMcpExe
}

Write-Host ""
Write-Host "[2/5] Verifying binaries..." -ForegroundColor Yellow
foreach ($bin in $binaries.GetEnumerator()) {
    if (Test-Path $bin.Value) {
        Write-Host "  [OK] $($bin.Key)" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $($bin.Key)" -ForegroundColor Red
        Write-Host "Run with -Build flag to build missing binaries" -ForegroundColor Yellow
        exit 1
    }
}

# Step 3: Launch target process
Write-Host ""
Write-Host "[3/5] Launching target process..." -ForegroundColor Yellow

$targetProcess = $null
$targetPid = $null

if ($Target -eq "ghost-test-target.exe") {
    # Launch our test target
    Write-Host "  Starting ghost-test-target.exe..."
    $targetProcess = Start-Process -FilePath $TestTargetExe -PassThru
    $targetPid = $targetProcess.Id
    Write-Host "  Started with PID: $targetPid" -ForegroundColor Green
    Start-Sleep -Milliseconds 500  # Give it time to initialize
} else {
    # Check if Target is a PID (numeric) or process name
    if ($Target -match '^\d+$') {
        # Target is a PID
        $proc = Get-Process -Id ([int]$Target) -ErrorAction SilentlyContinue
        if ($proc) {
            $targetPid = $proc.Id
            Write-Host "  Found process by PID: $($proc.ProcessName) (PID: $targetPid)" -ForegroundColor Green
        } else {
            Write-Host "  Process with PID '$Target' not found. Please check the PID." -ForegroundColor Red
            exit 1
        }
    } else {
        # Find existing process by name
        $proc = Get-Process -Name ($Target -replace '\.exe$','') -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) {
            $targetPid = $proc.Id
            Write-Host "  Found existing process: $Target (PID: $targetPid)" -ForegroundColor Green
        } else {
            Write-Host "  Process '$Target' not found. Please start it first." -ForegroundColor Red
            exit 1
        }
    }
}

# Step 4: Inject agent DLL
if (-not $SkipInjection) {
    Write-Host ""
    Write-Host "[4/5] Injecting ghost-agent.dll..." -ForegroundColor Yellow
    
    $injectArgs = @("-t", $targetPid.ToString(), "-d", $AgentDll)
    & $LoaderExe $injectArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Injection failed!" -ForegroundColor Red
        if ($targetProcess) {
            Write-Host "  Stopping target process..."
            Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
        }
        exit 1
    }
    
    Write-Host "  Agent injected successfully!" -ForegroundColor Green
    Start-Sleep -Seconds 1  # Give agent time to start TCP server
} else {
    Write-Host ""
    Write-Host "[4/5] Skipping injection (--SkipInjection)" -ForegroundColor Gray
}

# Step 5: Start MCP servers (Core/Analysis/Static)
Write-Host ""
Write-Host "[5/5] Starting MCP servers..." -ForegroundColor Yellow
$serverProcs = @()

foreach ($server in $servers) {
    $shouldStart = ($server.Name -eq "ghost-core-mcp" -and $startCore) -or
                   ($server.Name -eq "ghost-analysis-mcp" -and $startAnalysis) -or
                   ($server.Name -eq "ghost-static-mcp" -and $startStatic) -or
                   ($server.Name -eq "ghost-extended-mcp" -and $startExtended)

    if (-not $shouldStart) { continue }

    if (-not (Test-Path $server.Exe)) {
        Write-Host "  [MISSING] $($server.Name) binary not found at $($server.Exe)" -ForegroundColor Red
        continue
    }

    $args = @("--transport", $server.Transport)
    if ($server.Transport -eq "tcp") {
        $args += @("--port", $server.Port)
        Write-Host "  Launching $($server.Name) on tcp:$($server.Port) (target $($server.ToolTarget) tools)..." -ForegroundColor Cyan
    } else {
        Write-Host "  Launching $($server.Name) on stdio (target $($server.ToolTarget) tools)..." -ForegroundColor Cyan
    }
    $proc = Start-Process -FilePath $server.Exe -ArgumentList $args -PassThru -WindowStyle Hidden
    if ($proc) {
        $serverProcs += $proc
        Write-Host "    [OK] PID $($proc.Id)" -ForegroundColor Green
    } else {
        Write-Host "    [FAIL] Could not start $($server.Name)" -ForegroundColor Red
    }
}

# Step 6: Start Claude Desktop
Write-Host ""
Write-Host "[6/6] Starting Claude Desktop..." -ForegroundColor Yellow

$claudePath = "$env:LOCALAPPDATA\AnthropicClaude\claude.exe"
if (Test-Path $claudePath) {
    Start-Process $claudePath
    Write-Host "  Claude Desktop started!" -ForegroundColor Green
    Start-Sleep -Seconds 2  # Give Claude time to launch MCP server
} else {
    Write-Host "  Claude Desktop not found at: $claudePath" -ForegroundColor Yellow
    Write-Host "  Please start Claude Desktop manually." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target Process: $Target (PID: $targetPid)" -ForegroundColor White
Write-Host "Agent DLL: Injected and running" -ForegroundColor White
Write-Host ""
Write-Host "Server Ports:" -ForegroundColor Cyan
Write-Host "  Agent:    13338 (TCP)" -ForegroundColor White
Write-Host "  Core:     13340 (stdio/tcp) - 85 tools" -ForegroundColor White
Write-Host "  Analysis: 13341 (tcp)       - 82 tools" -ForegroundColor White
Write-Host "  Static:   13342 (tcp)       - 84 tools" -ForegroundColor White
Write-Host "  Extended: 13343 (tcp)       - 85 tools" -ForegroundColor White
Write-Host ""
Write-Host "Claude Desktop is running - ghost-mcp tools are ready!" -ForegroundColor Green
Write-Host "Use -ValidateOnly to check tool registries" -ForegroundColor Gray
Write-Host ""
Write-Host "Press Ctrl+C to stop and cleanup..." -ForegroundColor Yellow

# Wait for user interrupt
try {
    while ($true) {
        # Check if target is still running
        if ($targetProcess -and $targetProcess.HasExited) {
            Write-Host ""
            Write-Host "Target process has exited." -ForegroundColor Yellow
            break
        }
        Start-Sleep -Seconds 1
    }
} finally {
    # Cleanup
    if ($targetProcess -and -not $targetProcess.HasExited) {
        Write-Host ""
        Write-Host "Stopping target process..." -ForegroundColor Yellow
        Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
    }
    foreach ($proc in $serverProcs) {
        if ($proc -and -not $proc.HasExited) {
            Write-Host "Stopping $($proc.ProcessName) (PID $($proc.Id))..." -ForegroundColor Yellow
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "Done." -ForegroundColor Green
}
