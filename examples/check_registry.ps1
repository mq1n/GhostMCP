# check_registry.ps1 - Validate tool registries match expected counts
# Run from project root: .\examples\check_registry.ps1

$ErrorActionPreference = "Stop"

Write-Host "Ghost-MCP Registry Validation" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Run the integration test that validates registries
Write-Host "Running registry validation tests..." -ForegroundColor Yellow
Write-Host ""

$testOutput = cargo test --test integration test_multi_server_registry_tool_counts -- --nocapture 2>&1
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "Registry validation PASSED" -ForegroundColor Green
} else {
    Write-Host "Registry validation FAILED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Output:" -ForegroundColor Yellow
    Write-Host $testOutput
}

Write-Host ""
Write-Host "Expected Registry Counts:" -ForegroundColor Cyan
Write-Host "  ghost-core-mcp:     81 tools (+ 4 shared meta = 85 total)"
Write-Host "  ghost-analysis-mcp: 78 tools (+ 4 shared meta = 82 total)"
Write-Host "  ghost-static-mcp:   80 tools (+ 4 shared meta = 84 total)"
Write-Host "  ghost-extended-mcp: 81 tools (+ 4 shared meta = 85 total)"
Write-Host ""
Write-Host "Run 'cargo test --test integration test_multi_server' for full validation"
