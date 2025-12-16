@echo off
REM ============================================================================
REM Ghost-MCP Test CLI v1.0.0 - All-in-One Launch Script
REM ============================================================================
REM
REM Usage: launch-test-cli.bat [target] [options]
REM
REM Servers (default: core):
REM   -Server core           - Use ghost-core-mcp (Memory, Debug, Execution, Safety)
REM   -Server analysis       - Use ghost-analysis-mcp (Scanner, Dump, Introspection)
REM   -Server static         - Use ghost-static-mcp (Radare2, IDA, Ghidra, AI Tools)
REM   -Server extended       - Use ghost-extended-mcp (Injection, Anti-Debug, Input)
REM
REM Modes:
REM   (default)              - Interactive REPL mode
REM   -Test                  - Run integration tests
REM   -TestAll               - Run ALL test categories
REM   -TestCategory <name>   - Run specific category (meta,memory,module,agent,safety)
REM   -Tools                 - List available MCP tools
REM   -Call <tool>           - Call a specific tool
REM   -Help                  - Show detailed help
REM
REM Options:
REM   -NoBuild               - Skip cargo build (use existing binaries)
REM   -SkipInjection         - Skip DLL injection
REM   -ShowDebug             - Enable verbose output
REM   -Quiet                 - Minimal output (CI/CD mode)
REM
REM Examples:
REM   launch-test-cli.bat                          # REPL with ghost-core-mcp
REM   launch-test-cli.bat -Server analysis -Tools  # List analysis tools
REM   launch-test-cli.bat -Server static -Tools    # List static analysis tools
REM   launch-test-cli.bat -Server extended -Tools  # List extended capability tools
REM   launch-test-cli.bat -TestAll                 # Run all tests
REM   launch-test-cli.bat -TestAll -Quiet          # CI mode (exit code only)
REM   launch-test-cli.bat notepad.exe              # Attach to notepad
REM
REM Exit codes: 0=success, 1=error, >1=test failures
REM ============================================================================

cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "scripts\launch-test-cli.ps1" %*
exit /b %ERRORLEVEL%
