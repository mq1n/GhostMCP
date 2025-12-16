//! Error types for RE backends

use thiserror::Error;

/// Result type for RE backend operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for RE backend operations
#[derive(Debug, Error)]
pub enum Error {
    /// Backend not available (feature not enabled or tool not installed)
    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Command execution error
    #[error("Command failed: {0}")]
    CommandFailed(String),

    /// Analysis error
    #[error("Analysis error: {0}")]
    Analysis(String),

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Invalid address
    #[error("Invalid address: 0x{0:x}")]
    InvalidAddress(u64),

    /// Parse error
    #[error("Parse error: {0}")]
    Parse(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Radare2-specific error
    #[cfg(feature = "radare2")]
    #[error("Radare2 error: {0}")]
    Radare2(String),

    /// IDA-specific error
    #[cfg(feature = "ida")]
    #[error("IDA error: {0}")]
    Ida(String),

    /// Ghidra-specific error
    #[cfg(feature = "ghidra")]
    #[error("Ghidra error: {0}")]
    Ghidra(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Internal(e.to_string())
    }
}
