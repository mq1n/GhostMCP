//! Common types used across Ghost-MCP components
//!
//! This module is organized into submodules by functionality:
//! - `memory` - Memory protection, regions, and state types
//! - `module` - Module, export, and import types
//! - `thread` - Thread state and CPU registers
//! - `breakpoint` - Breakpoint types and IDs
//! - `instruction` - Disassembled instruction types
//! - `scan` - Basic scan result and value types
//! - `pattern` - Pattern scanning and YARA types
//! - `process` - Process attachment and launch types
//! - `script` - Scripting engine types
//! - `mcp` - MCP meta command types
//! - `scanner` - Advanced value scanner types
//! - `execution` - Direct execution and API call types
//! - `command` - AI/LLM command types
//! - `event` - Agent-to-AI event types
//! - `ai` - AI-friendly output types
//! - `debug_session` - AI-assisted debugging types
//! - `dump` - Memory dump and analysis types
//! - `pe` - PE reconstruction types
//! - `introspection` - Process & system introspection types
//! - `api_trace` - API call tracing & monitoring types
//! - `hooks` - Extended hooking types
//! - `api_override` - API override & conditional breakpoints types
//! - `pattern_search` - Advanced pattern matching types
//! - `structure` - Structure analysis types
//! - `watch` - What writes/accesses types
//! - `pointer_scanner` - Pointer scanner types

pub mod ai;
pub mod api_override;
pub mod api_trace;
pub mod breakpoint;
pub mod command;
pub mod debug_session;
pub mod dump;
pub mod event;
pub mod execution;
pub mod hooks;
pub mod instruction;
pub mod introspection;
pub mod mcp;
pub mod memory;
pub mod module;
pub mod pattern;
pub mod pattern_search;
pub mod pe;
pub mod pointer_scanner;
pub mod process;
pub mod scan;
pub mod scanner;
pub mod script;
pub mod structure;
pub mod thread;
pub mod watch;

// Re-export all types at the module level for backwards compatibility
pub use ai::*;
pub use api_override::*;
pub use api_trace::*;
pub use breakpoint::*;
pub use command::*;
pub use debug_session::*;
pub use dump::*;
pub use event::*;
pub use execution::*;
pub use hooks::*;
pub use instruction::*;
pub use introspection::*;
pub use mcp::*;
pub use memory::*;
pub use module::*;
pub use pattern::*;
pub use pattern_search::*;
pub use pe::*;
pub use pointer_scanner::*;
pub use process::*;
pub use scan::*;
pub use scanner::*;
pub use script::*;
pub use structure::*;
pub use thread::*;
pub use watch::*;
