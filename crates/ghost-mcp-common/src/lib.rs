//! Ghost-MCP Common Infrastructure
//!
//! Shared MCP server infrastructure for all Ghost-MCP modular servers.
//! Provides:
//! - Tool registry with <90 tools enforcement
//! - Shared meta tools (mcp_capabilities, mcp_documentation, mcp_version, mcp_health)
//! - IPC client with retries, heartbeats, and reconnection
//! - Server template with stdio and TCP transports
//! - Common types and handler utilities

pub mod config;
pub mod error;
pub mod ipc;
pub mod meta;
pub mod registry;
pub mod server;
pub mod types;

pub use config::ServerConfig;
pub use error::{McpError, Result};
pub use ipc::AgentClient;
pub use meta::{ServerIdentity, SharedMetaTools};
pub use registry::{PropertySchema, ToolDefinition, ToolRegistry};
pub use server::{McpServer, Transport};
pub use types::*;

// Re-export tracing for convenience
pub use tracing::{debug, error, info, trace, warn};

/// Maximum number of tools per server (MCP client constraint)
pub const MAX_TOOLS_PER_SERVER: usize = 90;

/// Ghost-MCP version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
