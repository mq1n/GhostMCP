//! Ghost RE Backends - Reverse Engineering Tool Communication
//!
//! Provides unified interfaces for communicating with reverse engineering tools:
//! - **Radare2** via `r2pipe` crate (cross-platform)
//! - **IDA Pro** via `idalib` crate (requires IDA v9.x)
//! - **Ghidra** via `fugue-ghidra` crate (Linux/macOS, not Windows MSVC)
//!
//! ## Feature Flags
//!
//! - `radare2` - Enable Radare2 backend (requires radare2 installed)
//! - `ida` - Enable IDA Pro backend (requires IDA v9.x and IDADIR env var)
//! - `ghidra` - Enable Ghidra backend (requires GMP/MPFR, not available on Windows MSVC)
//! - `all` - Enable all backends (only on supported platforms)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ghost_re_backends::{Radare2Backend, ReBackend};
//!
//! #[tokio::main]
//! async fn main() -> ghost_re_backends::Result<()> {
//!     let mut backend = Radare2Backend::new();
//!     let info = backend.open("/path/to/binary").await?;
//!     println!("Architecture: {}", info.architecture);
//!     
//!     let functions = backend.list_functions().await?;
//!     for func in functions.iter().take(10) {
//!         println!("  0x{:x}: {}", func.address, func.name);
//!     }
//!     
//!     backend.close().await?;
//!     Ok(())
//! }
//! ```

pub mod common;
pub mod error;

#[cfg(feature = "radare2")]
pub mod radare2;

#[cfg(feature = "ida")]
pub mod ida;

#[cfg(feature = "ghidra")]
pub mod ghidra;

pub use common::*;
pub use error::{Error, Result};

#[cfg(feature = "radare2")]
pub use radare2::Radare2Backend;

#[cfg(feature = "ida")]
pub use ida::IdaBackend;

#[cfg(feature = "ghidra")]
pub use ghidra::GhidraBackend;
