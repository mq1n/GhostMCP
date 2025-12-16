//! Handlers module for ghost-analysis-mcp
//!
//! Provides specialized handlers for analysis tools that require local processing
//! or integration with agent's centralized state (e.g., patch history for dumps).

mod dump_handler;

pub use dump_handler::{DumpHandler, PatchHistoryClient};
