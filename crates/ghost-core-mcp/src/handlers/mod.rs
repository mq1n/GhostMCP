//! Tool call handlers for ghost-core-mcp
//!
//! Handles both local tools (disasm, decompile) and agent-forwarded tools.

pub mod action_cache;
pub mod command;
pub mod decompile;
pub mod disasm;

pub use action_cache::{ActionCache, ActionResult, CachedAction};
pub use command::CommandHandler;
pub use decompile::DecompileHandler;
pub use disasm::DisasmHandler;
