//! Ghost-MCP Core Runtime Server
//!
//! Entry point for the ghost-core-mcp binary.
//! Supports stdio (default) and TCP transports.

use clap::Parser;
use ghost_core_mcp::{create_server_with_tools, validate_registry, PORT};
use ghost_mcp_common::{error::Result, Transport};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "ghost-core-mcp")]
#[command(about = "Ghost-MCP Core Runtime Server - Port 13340")]
#[command(version)]
struct Args {
    /// Transport mode: "stdio" or "tcp"
    #[arg(short, long, default_value = "stdio")]
    transport: String,

    /// TCP port (only used when transport = "tcp")
    #[arg(short, long, default_value_t = PORT)]
    port: u16,

    /// Validate registry and exit (for CI)
    #[arg(long)]
    validate_registry: bool,

    /// Show tool count and exit
    #[arg(long)]
    show_tools: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing - MUST use stderr for stdio transport (stdout is for JSON-RPC)
    let is_stdio = args.transport != "tcp";
    if is_stdio {
        // For stdio mode: logs to stderr only
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_level(true)
                    .with_writer(std::io::stderr),
            )
            .with(EnvFilter::from_default_env().add_directive("ghost_mcp=info".parse().unwrap()))
            .init();
    } else {
        // For TCP mode: logs can go to stdout
        tracing_subscriber::registry()
            .with(fmt::layer().with_target(true).with_level(true))
            .with(EnvFilter::from_default_env().add_directive("ghost_mcp=info".parse().unwrap()))
            .init();
    }

    // Handle validation mode
    if args.validate_registry {
        info!("Validating ghost-core-mcp registry...");
        let registry = ghost_core_mcp::create_registry()?;
        validate_registry(&registry)?;
        println!(
            "Registry valid: {} tools (max {})",
            registry.len(),
            ghost_mcp_common::MAX_TOOLS_PER_SERVER
        );
        return Ok(());
    }

    // Handle show tools mode
    if args.show_tools {
        let registry = ghost_core_mcp::create_registry()?;
        println!("ghost-core-mcp tools ({}):", registry.len());
        for cat in registry.categories() {
            let tools = registry.by_category(cat);
            println!("\n  {} ({}):", cat, tools.len());
            for tool in tools {
                println!("    - {}: {}", tool.name, tool.description);
            }
        }
        return Ok(());
    }

    // Create server with tools
    let server = create_server_with_tools().await?;

    // Determine transport
    let transport = match args.transport.as_str() {
        "tcp" => Transport::Tcp(args.port),
        _ => Transport::Stdio,
    };

    info!(
        "Starting ghost-core-mcp on {:?}",
        match transport {
            Transport::Stdio => "stdio".to_string(),
            Transport::Tcp(p) => format!("tcp:{}", p),
        }
    );

    // Run server
    server.serve(transport).await
}
