@echo off
REM Ghost-MCP Launch Script Wrapper (Multi-Server Architecture)
REM Usage: launch-mcp.bat [target] [options]
REM   launch-mcp.bat                    - Launch with test target (all servers)
REM   launch-mcp.bat notepad.exe        - Attach to notepad
REM   launch-mcp.bat -Build             - Build and launch
REM   launch-mcp.bat -CoreOnly          - Launch only ghost-core-mcp
REM   launch-mcp.bat -AnalysisOnly      - Launch only ghost-analysis-mcp
REM   launch-mcp.bat -StaticOnly        - Launch only ghost-static-mcp
REM   launch-mcp.bat -ExtendedOnly      - Launch only ghost-extended-mcp
REM   launch-mcp.bat -ValidateOnly      - Validate tool registries only
REM
REM Servers:
REM   ghost-core-mcp     (port 13340, 85 tools)  - Memory, Debug, Execution, Safety
REM   ghost-analysis-mcp (port 13341, 82 tools)  - Scanner, Dump, Introspection
REM   ghost-static-mcp   (port 13342, 84 tools)  - Radare2, IDA, Ghidra, AI Tools
REM   ghost-extended-mcp (port 13343, 85 tools)  - Injection, Anti-Debug, Input, Speedhack
REM

REM Kill Claude Desktop to release MCP server locks
echo Closing Claude Desktop...
taskkill /F /IM claude.exe >nul 2>&1
timeout /t 2 /nobreak >nul

cd /d "%~dp0"
set RUST_LOG=debug
powershell -ExecutionPolicy Bypass -File "scripts\launch-mcp.ps1" -Build %*
