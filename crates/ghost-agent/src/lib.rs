//! Ghost-MCP Agent DLL
//!
//! Injectable DLL that runs inside the target process.
//! Provides in-process implementation of ghost-core traits.
//!
//! # Safety
//! This DLL is designed to be injected into arbitrary processes.
//! DllMain returns immediately and spawns a worker thread for initialization.
//!
//! # Multi-Client Support
//! The agent supports multiple concurrent TCP connections from MCP servers.
//! Features include:
//! - Async listener with per-connection tasks
//! - Event bus with fan-out to subscribers
//! - Centralized shared state (patches, safety tokens, session metadata)
//! - Handshake protocol with client identity/version

pub mod backend;
mod ipc;
pub mod multi_client;
pub mod safety;

use ghost_common::{error, info, init_agent_logging};
use multi_client::MultiClientServer;
use std::ffi::c_void;
use std::panic;
use std::thread;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

/// Global state for the agent
static mut AGENT_RUNNING: bool = false;

/// Install custom panic handler for crash reporting
fn install_panic_handler() {
    panic::set_hook(Box::new(|panic_info| {
        let payload = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };

        let location = panic_info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        error!(
            target: "ghost_agent::panic",
            message = %payload,
            location = %location,
            "PANIC in ghost-agent"
        );
    }));
}

/// DLL entry point
///
/// # Safety
/// Called by Windows loader. Must return quickly and not call LoadLibrary.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hinst: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    match reason {
        DLL_PROCESS_ATTACH => {
            // Spawn worker thread immediately - don't block DllMain
            thread::spawn(|| {
                // Initialize logging first
                init_agent_logging();

                // Install panic handler for crash reporting
                install_panic_handler();

                info!(target: "ghost_agent", "Agent thread started");

                if let Err(e) = agent_main() {
                    error!(target: "ghost_agent", error = %e, "Agent initialization failed");
                }

                info!(target: "ghost_agent", "Agent thread exiting");
            });
            1 // TRUE
        }
        DLL_PROCESS_DETACH => {
            // Signal shutdown
            AGENT_RUNNING = false;
            info!(target: "ghost_agent", "Agent detaching");
            1 // TRUE
        }
        _ => 1, // TRUE
    }
}

/// Main agent initialization and run loop
fn agent_main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        AGENT_RUNNING = true;
    }

    info!(target: "ghost_agent", "Initializing backend");

    // Initialize backend
    let backend = match backend::InProcessBackend::new() {
        Ok(b) => b,
        Err(e) => {
            error!(target: "ghost_agent", error = %e, "Failed to initialize backend");
            return Err(e.into());
        }
    };

    info!(target: "ghost_agent", "Backend initialized successfully");

    // Create tokio runtime for async multi-client server
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(target: "ghost_agent", error = %e, "Failed to create tokio runtime");
            return Err(e.into());
        }
    };

    info!(target: "ghost_agent", "Tokio runtime created");

    // Run multi-client server
    runtime.block_on(async { run_multi_client_server(backend).await })
}

/// Run the multi-client server
async fn run_multi_client_server(
    backend: backend::InProcessBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(target: "ghost_agent", "Creating multi-client IPC server");

    // Create server with shared state and event bus (takes ownership of backend)
    let server = MultiClientServer::new_with_backend(backend);

    info!(target: "ghost_agent",
        port = multi_client::AGENT_PORT,
        max_clients = multi_client::MAX_CLIENTS,
        "Multi-client server starting"
    );

    // Run server - it handles its own reconnection internally
    loop {
        if !unsafe { AGENT_RUNNING } {
            server.stop();
            break;
        }

        match server.run().await {
            Ok(()) => {
                info!(target: "ghost_agent", "Multi-client server stopped normally");
                break;
            }
            Err(e) => {
                error!(target: "ghost_agent::ipc", error = %e, "Multi-client server error, restarting...");
                // Wait before retrying
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }

    info!(target: "ghost_agent", "Agent shutting down");
    Ok(())
}
