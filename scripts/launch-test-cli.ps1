<#
.SYNOPSIS
    Ghost-MCP Test CLI - All-in-one testing and development tool

.DESCRIPTION
    Builds, launches target process, injects agent, and runs ghost-mcp-client.
    Auto-terminates all components on exit. Supports CI/CD integration.

.PARAMETER Target
    Target process name or path (default: ghost-test-target.exe)

.PARAMETER NoBuild
    Skip cargo build step (use existing binaries)

.PARAMETER SkipInjection
    Skip DLL injection (for already-injected targets)

.PARAMETER Test
    Run integration tests (default category)

.PARAMETER TestAll
    Run ALL test categories (comprehensive)

.PARAMETER TestCategory
    Run specific test category: meta, memory, module, agent, safety, all

.PARAMETER Tools
    List available MCP tools and exit

.PARAMETER Call
    Call a specific tool and exit

.PARAMETER Script
    Run a JSON script file and exit

.PARAMETER ShowDebug
    Enable verbose debug output

.PARAMETER Quiet
    Minimal output (for CI/CD)

.PARAMETER Help
    Show this help message

.PARAMETER ForceBuild
    Force rebuild by killing any locked processes first

.PARAMETER ForceClose
    Force close all ghost processes before starting

.EXAMPLE
    .\launch-test-cli.ps1
    # Interactive REPL mode with auto-build

.EXAMPLE
    .\launch-test-cli.ps1 -TestAll
    # Run comprehensive test suite

.EXAMPLE
    .\launch-test-cli.ps1 -TestCategory memory -Quiet
    # Run memory tests in CI mode

.EXAMPLE
    .\launch-test-cli.ps1 notepad.exe -SkipInjection
    # Attach to existing process
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Target = "ghost-test-target.exe",
    
    [switch]$NoBuild,
    [switch]$SkipInjection,
    [switch]$Test,
    [switch]$TestAll,
    [ValidateSet("meta", "memory", "module", "agent", "safety", "all")]
    [string]$TestCategory,
    [switch]$Tools,
    [switch]$ShowDebug,
    [switch]$Quiet,
    [switch]$Help,
    [string]$Call,
    [string]$Script,
    
    # Server selection (default: core)
    [ValidateSet("core", "analysis", "static", "extended")]
    [string]$Server = "core",
    
    # Force options
    [switch]$ForceBuild,
    [switch]$ForceClose
)

# ============================================================================
# Configuration
# ============================================================================
$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"
$script:ExitCode = 0
$script:ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:SpawnedProcesses = @()
$script:StartTime = Get-Date

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    if (-not $Quiet) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        switch ($Level) {
            "SUCCESS" { Write-Host $Message -ForegroundColor Green }
            "WARNING" { Write-Host $Message -ForegroundColor Yellow }
            "ERROR"   { Write-Host $Message -ForegroundColor Red }
            "DEBUG"   { if ($ShowDebug) { Write-Host "[$timestamp] $Message" -ForegroundColor Gray } }
            "STEP"    { Write-Host $Message -ForegroundColor Yellow }
            "HEADER"  { Write-Host $Message -ForegroundColor Cyan }
            default   { Write-Host $Message -ForegroundColor $Color }
        }
    }
}

function Write-Banner {
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "  +=========================================+" -ForegroundColor Cyan
        Write-Host "  |     Ghost-MCP Test CLI v$script:Version        |" -ForegroundColor Cyan
        Write-Host "  |     All-in-One Development Tool       |" -ForegroundColor Cyan
        Write-Host "  +=========================================+" -ForegroundColor Cyan
        Write-Host ""
    }
}

function global:Write-Summary {
    param(
        [string]$Status,
        [int]$ExitCode
    )
    $duration = ((Get-Date) - $script:StartTime).TotalSeconds
    Write-Host ""
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  | Summary                                   |" -ForegroundColor Cyan
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    $statusColor = if ($ExitCode -eq 0) { "Green" } else { "Red" }
    Write-Host "  | Status:   $($Status.PadRight(31))|" -ForegroundColor $statusColor
    Write-Host "  | Duration: $("{0:N2}s" -f $duration)$(' ' * (31 - ("{0:N2}s" -f $duration).Length))|" -ForegroundColor White
    Write-Host "  | Exit:     $("$ExitCode".PadRight(31))|" -ForegroundColor White
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Cleanup-AllProcesses {
    param([string]$Reason = "Cleanup requested")
    
    Write-Log "" 
    Write-Log "[$Reason] Cleaning up..." -Level "WARNING"
    
    foreach ($proc in $script:SpawnedProcesses) {
        if ($proc -and -not $proc.HasExited) {
            try {
                Write-Log "  Stopping $($proc.ProcessName) (PID: $($proc.Id))..." -Level "DEBUG"
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            } catch { }
        }
    }
    
    # Stop any orphaned MCP servers (all 4 types)
    @("ghost-core-mcp", "ghost-analysis-mcp", "ghost-static-mcp", "ghost-extended-mcp", "ghost-client", "ghost-test-target") | ForEach-Object {
        Get-Process -Name $_ -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "  Stopping orphaned $($_.ProcessName) (PID: $($_.Id))..." -Level "DEBUG"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Show-Help {
    Get-Help $PSCommandPath -Detailed
    exit 0
}

function Test-Prerequisites {
    # Check for cargo
    if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
        Write-Log "ERROR: Rust/Cargo not found in PATH" -Level "ERROR"
        Write-Log "Install from: https://rustup.rs" -Level "INFO"
        return $false
    }
    return $true
}

# ============================================================================
# Main Script
# ============================================================================

# Show help if requested
if ($Help) { Show-Help }

# Register cleanup handler
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Cleanup-AllProcesses -Reason "PowerShell exiting"
} -ErrorAction SilentlyContinue

Write-Banner

# Force close all ghost processes if requested
if ($ForceClose) {
    Write-Log "[0/5] Force closing all ghost processes..." -Level "STEP"
    @("ghost-core-mcp", "ghost-analysis-mcp", "ghost-static-mcp", "ghost-extended-mcp", "ghost-client", "ghost-test-target", "ghost-loader") | ForEach-Object {
        Get-Process -Name $_ -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "  Killing $($_.ProcessName) (PID: $($_.Id))..." -Level "WARNING"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
    Write-Log "  All ghost processes terminated." -Level "SUCCESS"
}

# Paths
$ReleasePath = Join-Path $script:ProjectRoot "target\release"
$TestTargetExe = Join-Path $ReleasePath "ghost-test-target.exe"
$LoaderExe = Join-Path $ReleasePath "ghost-loader.exe"
$AgentDll = Join-Path $ReleasePath "ghost_agent.dll"
$ClientExe = Join-Path $ReleasePath "ghost-client.exe"

# All 4 MCP servers
$CoreMcpExe = Join-Path $ReleasePath "ghost-core-mcp.exe"
$AnalysisMcpExe = Join-Path $ReleasePath "ghost-analysis-mcp.exe"
$StaticMcpExe = Join-Path $ReleasePath "ghost-static-mcp.exe"
$ExtendedMcpExe = Join-Path $ReleasePath "ghost-extended-mcp.exe"

# Select server based on parameter
$SelectedMcpExe = switch ($Server) {
    "core"     { $CoreMcpExe }
    "analysis" { $AnalysisMcpExe }
    "static"   { $StaticMcpExe }
    "extended" { $ExtendedMcpExe }
}
$SelectedServerName = "ghost-$Server-mcp"
Write-Log "Using MCP server: $SelectedServerName" -Level "DEBUG"

# Step 1: Build unless -NoBuild specified
if (-not $NoBuild) {
    Write-Log "[1/5] Building release binaries..." -Level "STEP"
    
    if (-not (Test-Prerequisites)) {
        Write-Summary -Status "FAILED (no cargo)" -ExitCode 1
        exit 1
    }
    
    # Force build: kill locked processes first
    if ($ForceBuild) {
        Write-Log "  Force build: killing locked processes..." -Level "WARNING"
        @("ghost-core-mcp", "ghost-analysis-mcp", "ghost-static-mcp", "ghost-extended-mcp", "ghost-client", "ghost-test-target", "ghost-loader") | ForEach-Object {
            Get-Process -Name $_ -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Log "    Killing $($_.ProcessName) (PID: $($_.Id))..." -Level "DEBUG"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
        Start-Sleep -Milliseconds 500
    }
    
    Push-Location $script:ProjectRoot
    try {
        $output = cmd /c "cargo build --workspace --release --features radare2,ghidra 2>&1"
        $buildFailed = $LASTEXITCODE -ne 0
        
        if ($buildFailed) {
            if ($output -match "Access is denied") {
                if ($ForceBuild) {
                    Write-Log "  Build still failed after force close!" -Level "ERROR"
                    Write-Summary -Status "BUILD FAILED (locked)" -ExitCode 1
                    exit 1
                }
                Write-Log "  Warning: Some binaries are in use" -Level "WARNING"
                Write-Log "  Tip: Use -ForceBuild to kill locked processes" -Level "WARNING"
                Write-Log "  Using existing binaries..." -Level "WARNING"
            } else {
                Write-Log "  Build failed!" -Level "ERROR"
                if ($ShowDebug) { Write-Log $output -Level "DEBUG" }
                Write-Summary -Status "BUILD FAILED" -ExitCode 1
                exit 1
            }
        } else {
            Write-Log "  Build complete!" -Level "SUCCESS"
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Log "[1/5] Skipping build (-NoBuild)" -Level "DEBUG"
}

# Step 2: Verify binaries
$binaries = @{
    "ghost-test-target.exe" = $TestTargetExe
    "ghost-loader.exe" = $LoaderExe
    "ghost_agent.dll" = $AgentDll
    "ghost-core-mcp.exe" = $CoreMcpExe
    "ghost-analysis-mcp.exe" = $AnalysisMcpExe
    "ghost-static-mcp.exe" = $StaticMcpExe
    "ghost-extended-mcp.exe" = $ExtendedMcpExe
    "ghost-client.exe" = $ClientExe
}

Write-Log ""
Write-Log "[2/5] Verifying binaries..." -Level "STEP"
$allExist = $true
foreach ($bin in $binaries.GetEnumerator()) {
    if (Test-Path $bin.Value) {
        Write-Log "  [OK] $($bin.Key)" -Level "SUCCESS"
    } else {
        Write-Log "  [MISSING] $($bin.Key)" -Level "ERROR"
        $allExist = $false
    }
}
if (-not $allExist) {
    Write-Log "Run without -NoBuild to build missing binaries" -Level "WARNING"
    Write-Summary -Status "MISSING BINARIES" -ExitCode 1
    exit 1
}

# Step 3: Launch target process
Write-Log ""
Write-Log "[3/5] Launching target process..." -Level "STEP"

$targetProcess = $null
$targetPid = $null
$weOwnTarget = $false

if ($Target -eq "ghost-test-target.exe") {
    Write-Log "  Starting ghost-test-target.exe..."
    try {
        $targetProcess = Start-Process -FilePath $TestTargetExe -PassThru
        $targetPid = $targetProcess.Id
        $weOwnTarget = $true
        $script:SpawnedProcesses += $targetProcess
        Write-Log "  Started with PID: $targetPid" -Level "SUCCESS"
        Start-Sleep -Milliseconds 500
    } catch {
        Write-Log "  Failed to start target: $_" -Level "ERROR"
        Write-Summary -Status "TARGET LAUNCH FAILED" -ExitCode 1
        exit 1
    }
} else {
    $proc = Get-Process -Name ($Target -replace '\.exe$','') -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) {
        $targetPid = $proc.Id
        $targetProcess = $proc
        Write-Log "  Found: $Target (PID: $targetPid)" -Level "SUCCESS"
        Write-Log "  Note: External process - will NOT be terminated" -Level "DEBUG"
    } else {
        Write-Log "  Process '$Target' not found" -Level "ERROR"
        Write-Summary -Status "TARGET NOT FOUND" -ExitCode 1
        exit 1
    }
}

# Step 4: Inject agent DLL
if (-not $SkipInjection) {
    Write-Log ""
    Write-Log "[4/5] Injecting ghost-agent.dll..." -Level "STEP"
    
    $injectArgs = @("-t", $targetPid.ToString(), "-d", $AgentDll)
    & $LoaderExe $injectArgs 2>&1 | ForEach-Object {
        if (-not $Quiet) { Write-Host "  $_" -ForegroundColor Gray }
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Log "  Injection failed!" -Level "ERROR"
        Cleanup-AllProcesses -Reason "Injection failed"
        Write-Summary -Status "INJECTION FAILED" -ExitCode 1
        exit 1
    }
    
    Write-Log "  Agent injected!" -Level "SUCCESS"
    Write-Log "  Waiting for agent to initialize..." -Level "DEBUG"
    Start-Sleep -Seconds 2
} else {
    Write-Log ""
    Write-Log "[4/5] Skipping injection (-SkipInjection)" -Level "DEBUG"
}

# Step 5: Run ghost-mcp-client
Write-Log ""
Write-Log "[5/5] Running ghost-mcp-client with $SelectedServerName..." -Level "STEP"

$clientArgs = @("--stdio", "--host-binary", $SelectedMcpExe)
if ($ShowDebug) { $clientArgs += "-v" }

# Determine mode
$mode = "repl"
$testArg = $null
if ($TestAll) {
    $mode = "test"; $testArg = "all"
} elseif ($TestCategory) {
    $mode = "test"; $testArg = $TestCategory
} elseif ($Test) {
    $mode = "test"
} elseif ($Tools) {
    $mode = "tools"
} elseif ($Call) {
    $mode = "call"
} elseif ($Script) {
    $mode = "script"
}

# Show setup info
if (-not $Quiet) {
    Write-Host ""
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  | Ready                                     |" -ForegroundColor Cyan
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  | Target: $($Target.PadRight(33))|" -ForegroundColor White
    Write-Host "  | PID:    $("$targetPid".PadRight(33))|" -ForegroundColor White
    Write-Host "  | Port:   $("13338 (TCP)".PadRight(33))|" -ForegroundColor White
    Write-Host "  | Mode:   $($mode.ToUpper().PadRight(33))|" -ForegroundColor Green
    Write-Host "  +-------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

try {
    $clientExitCode = 0
    $totalPassed = 0
    $totalFailed = 0
    
    # If TestAll, run tests for ALL servers sequentially
    if ($TestAll) {
        Write-Log "Running tests for ALL servers..." -Level "HEADER"
        Write-Host ""
        
        $servers = @(
            @{ Name = "core"; Exe = $CoreMcpExe; DisplayName = "ghost-core-mcp" },
            @{ Name = "analysis"; Exe = $AnalysisMcpExe; DisplayName = "ghost-analysis-mcp" },
            @{ Name = "static"; Exe = $StaticMcpExe; DisplayName = "ghost-static-mcp" },
            @{ Name = "extended"; Exe = $ExtendedMcpExe; DisplayName = "ghost-extended-mcp" }
        )
        
        foreach ($srv in $servers) {
            Write-Host ""
            Write-Host "  =============================================" -ForegroundColor Cyan
            Write-Host "  Testing: $($srv.DisplayName)" -ForegroundColor Cyan
            Write-Host "  =============================================" -ForegroundColor Cyan
            Write-Host ""
            
            $srvClientArgs = @("--stdio", "--host-binary", $srv.Exe)
            if ($ShowDebug) { $srvClientArgs += "-v" }
            
            & $ClientExe $srvClientArgs test --test all
            $srvExitCode = $LASTEXITCODE
            
            if ($srvExitCode -ne 0) {
                $clientExitCode = $srvExitCode
            }
        }
    } else {
        switch ($mode) {
            "test" {
                if ($testArg) {
                    Write-Log "Running tests (category: $testArg)..." -Level "HEADER"
                    & $ClientExe $clientArgs test --test $testArg
                } else {
                    Write-Log "Running tests (all categories)..." -Level "HEADER"
                    & $ClientExe $clientArgs test
                }
                $clientExitCode = $LASTEXITCODE
            }
            "tools" {
                Write-Log "Listing tools..." -Level "HEADER"
                & $ClientExe $clientArgs tools
                $clientExitCode = $LASTEXITCODE
            }
            "call" {
                Write-Log "Calling: $Call" -Level "HEADER"
                & $ClientExe $clientArgs call $Call
                $clientExitCode = $LASTEXITCODE
            }
            "script" {
                Write-Log "Running script: $Script" -Level "HEADER"
                & $ClientExe $clientArgs script $Script
                $clientExitCode = $LASTEXITCODE
            }
            default {
                Write-Log "Starting REPL (type 'help' for commands, 'quit' to exit)" -Level "HEADER"
                Write-Host ""
                & $ClientExe $clientArgs repl
                $clientExitCode = $LASTEXITCODE
            }
        }
    }
    
    $script:ExitCode = $clientExitCode
    Cleanup-AllProcesses -Reason "Completed"
    
    if ($clientExitCode -eq 0) {
        Write-Summary -Status "SUCCESS" -ExitCode 0
    } else {
        Write-Summary -Status "TESTS FAILED" -ExitCode $clientExitCode
    }
    
} catch {
    Write-Log "Error: $_" -Level "ERROR"
    Cleanup-AllProcesses -Reason "Error"
    Write-Summary -Status "ERROR" -ExitCode 1
    $script:ExitCode = 1
} finally {
    if ($weOwnTarget -and $targetProcess -and -not $targetProcess.HasExited) {
        Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
    }
    Unregister-Event -SourceIdentifier PowerShell.Exiting -ErrorAction SilentlyContinue
}

exit $script:ExitCode
