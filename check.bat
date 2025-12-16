@echo off
setlocal EnableExtensions EnableDelayedExpansion

if not exist "Cargo.toml" (
    echo [check] Please run this script from the repository root.
    exit /b 1
)

REM Kill any running instances of built executables to avoid file locking
echo [CLEANUP] Killing existing processes...
taskkill /F /IM ghost-core-mcp.exe 2>nul
taskkill /F /IM ghost-analysis-mcp.exe 2>nul
taskkill /F /IM ghost-static-mcp.exe 2>nul
taskkill /F /IM ghost-extended-mcp.exe 2>nul
taskkill /F /IM ghost-loader.exe 2>nul
taskkill /F /IM ghost-client.exe 2>nul
taskkill /F /IM ghost-agent-exe.exe 2>nul
taskkill /F /IM ghost-test-target.exe 2>nul
echo [CLEANUP] Done.

REM Use specific features instead of --all-features since IDA requires LLVM/Clang setup
REM To include IDA: set LIBCLANG_PATH and use --all-features
set "FEATURES=--features radare2,ghidra"
set "TARGETS=--all-targets"
set "WORKSPACE=--workspace"

call :run "cargo fmt --all --check" || exit /b
call :run "cargo clippy %WORKSPACE% %TARGETS% %FEATURES% -- --deny warnings" || exit /b
call :run "cargo check %WORKSPACE% %TARGETS% %FEATURES% --locked" || exit /b
call :run "cargo build %WORKSPACE% %FEATURES% --locked" || exit /b
call :run "cargo test %WORKSPACE% %FEATURES% --verbose --locked" || exit /b

echo(
echo All checks passed.
exit /b 0

:run
set "CMD=%~1"
echo(
echo [RUN] !CMD!
call !CMD!
set "STATUS=!ERRORLEVEL!"
if not "!STATUS!"=="0" (
    echo [FAIL] !CMD! (exit !STATUS!)
)
exit /b !STATUS!
