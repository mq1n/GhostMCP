//! Ghost-MCP Core Library
//!
//! Static library providing trait-based interfaces for all reverse engineering primitives.
//! This library is linked by both ghost-agent (DLL) and ghost-agent-exe for different
//! implementation strategies.

pub mod advanced_monitor;
pub mod advanced_pattern_search;
pub mod api_override;
pub mod api_trace;
pub mod api_trace_hooks;
pub mod assembler;
pub mod debug;
pub mod disasm;
pub mod dump;
pub mod execution;
pub mod extended_hooks;
pub mod hooks;
pub mod introspection;
pub mod memory;
pub mod pattern_scanner;
pub mod pe;
pub mod pointer_scanner;
pub mod process;
pub mod scanner;
pub mod structure;
pub mod symbols;
pub mod threads;
pub mod traits;
pub mod watch;
pub mod xrefs;

pub use advanced_pattern_search::AdvancedPatternSearch;
pub use ghost_common::{Error, Result};
pub use pattern_scanner::PatternScanner;
pub use pointer_scanner::PointerScanner;
pub use scanner::Scanner;
pub use structure::StructureManager;
pub use traits::*;
pub use watch::WatchManager;
