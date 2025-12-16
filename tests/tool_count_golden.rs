//! Tool Count Golden Snapshot Tests
//!
//! Standalone test target for validating tool counts across MCP servers.
//! Run with: cargo test --test tool_count_golden -- --nocapture

#[path = "integration/tool_count_golden.rs"]
mod tool_count_golden;

pub use tool_count_golden::*;
