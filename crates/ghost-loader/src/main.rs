//! Ghost-MCP DLL Injector
//!
//! Injects ghost-agent.dll into a target process.
//!
//! Supports multiple attachment modes:
//! - Attach to running process by PID or name
//! - Wait for process to start, then attach
//! - Launch process ourselves (normal, suspended, debug mode)
//! - Delayed injection with configurable timing

mod injector;
pub mod process;

use clap::{Parser, Subcommand, ValueEnum};
use ghost_common::init_host_logging;
use ghost_common::{AttachMode, ProcessLaunchConfig, ProcessStartMode};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ghost-loader")]
#[command(about = "Ghost-MCP DLL Injector - inject ghost-agent into target process")]
#[command(version)]
struct Args {
    /// Path to ghost-agent.dll (default: same directory as loader)
    #[arg(short, long, global = true)]
    dll: Option<PathBuf>,

    /// Maximum retries on injection failure
    #[arg(long, global = true, default_value = "0")]
    retries: u32,

    /// Delay between retries in milliseconds
    #[arg(long, global = true, default_value = "1000")]
    retry_delay: u64,

    #[command(subcommand)]
    command: Option<Command>,

    /// Legacy: Target process name or PID (use subcommands for more options)
    #[arg(short, long)]
    target: Option<String>,

    /// Legacy: Wait for process to start if not found
    #[arg(short, long)]
    wait: bool,

    /// Timeout in seconds when waiting for process
    #[arg(long, default_value = "60")]
    timeout: u64,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Attach to a running process by PID
    Pid {
        /// Process ID to attach to
        pid: u32,
    },

    /// Attach to a running process by name
    Name {
        /// Process name (e.g., "game.exe")
        name: String,
    },

    /// Wait for a process to start, then attach
    Wait {
        /// Process name to wait for
        name: String,

        /// Timeout in seconds (0 = wait forever)
        #[arg(short, long, default_value = "60")]
        timeout: u64,

        /// Delay after process detection before injection (ms)
        #[arg(short, long)]
        delay: Option<u64>,
    },

    /// Launch a process and inject
    Launch {
        /// Path to executable
        executable: String,

        /// Arguments to pass to the executable
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Working directory
        #[arg(short, long)]
        workdir: Option<String>,

        /// Start mode for the process
        #[arg(short, long, value_enum, default_value = "normal")]
        mode: StartMode,

        /// Delay before injection (ms) - for delayed mode or additional delay
        #[arg(short, long)]
        inject_delay: Option<u64>,

        /// Module to wait for before injection (for wait-module mode)
        #[arg(long)]
        wait_module: Option<String>,

        /// Timeout for waiting operations (ms)
        #[arg(long, default_value = "30000")]
        wait_timeout: u64,
    },
}

#[derive(ValueEnum, Clone, Debug, Default)]
enum StartMode {
    /// Start normally, inject immediately
    #[default]
    Normal,
    /// Start suspended, inject, then resume (earliest injection point)
    Suspended,
    /// Start normally, wait for main module, then inject
    WaitMain,
    /// Start normally, wait specified delay, then inject
    Delayed,
    /// Start with debugger attached
    Debug,
    /// Start normally, wait for specific module, then inject
    WaitModule,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_host_logging();
    let args = Args::parse();

    println!("Ghost-MCP Loader v{}", env!("CARGO_PKG_VERSION"));

    // Determine DLL path
    let dll_path = match &args.dll {
        Some(path) => path.clone(),
        None => {
            let exe_dir = match std::env::current_exe()?.parent() {
                Some(p) => p.to_path_buf(),
                None => std::env::current_dir()?,
            };
            exe_dir.join("ghost_agent.dll")
        }
    };

    if !dll_path.exists() {
        eprintln!("Error: DLL not found: {}", dll_path.display());
        eprintln!("Build the agent DLL first: cargo build -p ghost-agent --release");
        std::process::exit(1);
    }

    println!("DLL: {}", dll_path.display());

    // Build attach mode from command or legacy arguments
    let attach_mode = build_attach_mode(&args)?;

    // Perform injection
    let result = if args.retries > 0 {
        injector::attach_with_retry(&attach_mode, &dll_path, args.retries, args.retry_delay)
    } else {
        injector::attach_and_inject(&attach_mode, &dll_path)
    };

    match result {
        Ok(attach_result) => {
            println!(
                "Successfully injected ghost-agent.dll into PID {}!",
                attach_result.pid
            );
            println!();
            println!("Agent should now be running. Start MCP servers to connect:");
            println!("  Use: scripts/launch-mcp.ps1 -All");
            println!("  Or start individually:");
            println!("    - ghost-core-mcp     (port 13340) - Memory, Debug, Execution, Safety");
            println!("    - ghost-analysis-mcp (port 13341) - Scanner, Dump, Introspection");
            println!("    - ghost-static-mcp   (port 13342) - Radare2, IDA, Ghidra, AI Tools");
            println!("    - ghost-extended-mcp (port 13343) - Extended MCP");

            if attach_result.launched {
                println!();
                println!("Process was launched by ghost-loader.");
            }
        }
        Err(e) => {
            eprintln!("Injection failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Build AttachMode from CLI arguments
fn build_attach_mode(args: &Args) -> Result<AttachMode, Box<dyn std::error::Error>> {
    // If a subcommand is specified, use it
    if let Some(ref cmd) = args.command {
        return Ok(match cmd {
            Command::Pid { pid } => AttachMode::Pid(*pid),

            Command::Name { name } => AttachMode::ProcessName(name.clone()),

            Command::Wait {
                name,
                timeout,
                delay,
            } => AttachMode::WaitForProcess {
                name: name.clone(),
                timeout_secs: if *timeout == 0 { None } else { Some(*timeout) },
                attach_delay_ms: *delay,
            },

            Command::Launch {
                executable,
                args: exec_args,
                workdir,
                mode,
                inject_delay,
                wait_module,
                wait_timeout,
            } => {
                let start_mode = match mode {
                    StartMode::Normal => ProcessStartMode::Normal,
                    StartMode::Suspended => ProcessStartMode::Suspended,
                    StartMode::WaitMain => ProcessStartMode::WaitForMainModule,
                    StartMode::Delayed => ProcessStartMode::Delayed {
                        delay_ms: inject_delay.unwrap_or(1000),
                    },
                    StartMode::Debug => ProcessStartMode::Debug,
                    StartMode::WaitModule => {
                        let module = wait_module
                            .clone()
                            .unwrap_or_else(|| "user32.dll".to_string());
                        ProcessStartMode::WaitForModule {
                            module_name: module,
                            timeout_ms: *wait_timeout,
                        }
                    }
                };

                let config = ProcessLaunchConfig {
                    executable: executable.clone(),
                    args: exec_args.clone(),
                    working_dir: workdir.clone(),
                    env: Vec::new(),
                    start_mode,
                    inject_delay_ms: *inject_delay,
                };

                AttachMode::Launch(config)
            }
        });
    }

    // Legacy mode: use --target
    if let Some(ref target) = args.target {
        println!("Target: {}", target);

        // Check if target is a PID
        if let Ok(pid) = target.parse::<u32>() {
            return Ok(AttachMode::Pid(pid));
        }

        // It's a process name
        if args.wait {
            return Ok(AttachMode::WaitForProcess {
                name: target.clone(),
                timeout_secs: Some(args.timeout),
                attach_delay_ms: None,
            });
        } else {
            return Ok(AttachMode::ProcessName(target.clone()));
        }
    }

    // No target specified
    eprintln!("Error: No target specified. Use --target or a subcommand.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  ghost-loader --target game.exe");
    eprintln!("  ghost-loader pid 1234");
    eprintln!("  ghost-loader name game.exe");
    eprintln!("  ghost-loader wait game.exe --timeout 60");
    eprintln!("  ghost-loader launch C:\\path\\to\\game.exe --mode suspended");
    std::process::exit(1);
}
