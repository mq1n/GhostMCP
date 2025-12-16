//! Ghost-MCP Standalone Agent (External Mode)
//!
//! This is a future component that will use ReadProcessMemory/WriteProcessMemory
//! to interact with target processes externally, without injection.
//!
//! Currently a placeholder.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ghost-agent-exe")]
#[command(about = "Ghost-MCP External Agent - standalone process mode")]
struct Args {
    /// Target process name or PID
    #[arg(short, long)]
    target: String,

    /// Pipe name for host communication
    #[arg(long, default_value = r"\\.\pipe\ghost-mcp")]
    pipe: String,
}

fn main() {
    let args = Args::parse();

    eprintln!("Ghost-MCP External Agent v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Target: {}", args.target);
    eprintln!();
    eprintln!("ERROR: External mode is not yet implemented.");
    eprintln!("External mode is planned for a future release.");
    eprintln!();
    eprintln!("For now, use the DLL injection mode:");
    eprintln!("  1. ghost-loader --target {}", args.target);
    eprintln!("  2. Start MCP servers (or use scripts/launch-mcp.ps1):");
    eprintln!("     - ghost-core-mcp     (port 13340) - Memory, Debug, Execution, Safety");
    eprintln!("     - ghost-analysis-mcp (port 13341) - Scanner, Dump, Introspection");
    eprintln!("     - ghost-static-mcp   (port 13342) - Radare2, IDA, Ghidra, AI Tools");
    eprintln!("     - ghost-extended-mcp (port 13343) - External mode");

    std::process::exit(1);
}
