//! Ghost-MCP Common Types
//!
//! Shared types and IPC protocol definitions used by all Ghost-MCP components.

pub mod error;
pub mod ipc;
pub mod logging;
pub mod safety;
pub mod types;

pub use error::{Error, Result};
pub use logging::{
    init_agent_logging, init_debug_logging, init_host_logging, init_logging,
    init_logging_from_file, LogConfig,
};
pub use types::*;

// Re-export tracing macros for convenience
pub use tracing::{debug, error, info, trace, warn};
