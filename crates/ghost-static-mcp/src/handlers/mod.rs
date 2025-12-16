//! Handlers module for ghost-static-mcp
//!
//! Provides specialized handlers for static analysis tools that require
//! local processing or RE backend routing (Radare2, IDA Pro, Ghidra).

mod re_handler;

pub use re_handler::ReHandler;
