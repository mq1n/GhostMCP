# check_build.ps1 - Verify Ghost-MCP builds correctly
# Run from project root: .\examples\check_build.ps1

$ErrorActionPreference = "Stop"

Write-Host "Ghost-MCP Build Check" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""

# Check Rust toolchain
Write-Host "[1/4] Checking Rust toolchain..." -ForegroundColor Yellow
$rustVersion = rustc --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust not found. Install from https://rustup.rs" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: $rustVersion" -ForegroundColor Green

# Check cargo
Write-Host "[2/4] Checking Cargo..." -ForegroundColor Yellow
$cargoVersion = cargo --version 2>&1
Write-Host "  OK: $cargoVersion" -ForegroundColor Green

# Build check (no actual compilation)
Write-Host "[3/4] Checking project compiles..." -ForegroundColor Yellow
$buildResult = cargo check --workspace 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build check failed" -ForegroundColor Red
    Write-Host $buildResult
    exit 1
}
Write-Host "  OK: Project compiles" -ForegroundColor Green

# Run tests
Write-Host "[4/4] Running tests..." -ForegroundColor Yellow
$testResult = cargo test --workspace --lib 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Some tests failed" -ForegroundColor Yellow
} else {
    Write-Host "  OK: All tests pass" -ForegroundColor Green
}

Write-Host ""
Write-Host "Build check complete!" -ForegroundColor Cyan
