//! Error types for Ghost-MCP

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Memory access error at {address:#x}: {message}")]
    MemoryAccess { address: usize, message: String },

    #[error("Invalid address: {0:#x}")]
    InvalidAddress(usize),

    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),

    #[error("Breakpoint error: {0}")]
    Breakpoint(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_access_error_display() {
        let err = Error::MemoryAccess {
            address: 0x140001000,
            message: "Access denied".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("0x140001000"));
        assert!(msg.contains("Access denied"));
    }

    #[test]
    fn test_invalid_address_error_display() {
        let err = Error::InvalidAddress(0xDEADBEEF);
        let msg = format!("{}", err);
        assert!(msg.contains("0xdeadbeef"));
    }

    #[test]
    fn test_module_not_found_error_display() {
        let err = Error::ModuleNotFound("test.dll".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("test.dll"));
    }

    #[test]
    fn test_symbol_not_found_error_display() {
        let err = Error::SymbolNotFound("CreateFileW".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("CreateFileW"));
    }

    #[test]
    fn test_breakpoint_error_display() {
        let err = Error::Breakpoint("No free hardware breakpoints".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("No free hardware breakpoints"));
    }

    #[test]
    fn test_ipc_error_display() {
        let err = Error::Ipc("Connection refused".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Connection refused"));
    }

    #[test]
    fn test_not_implemented_error_display() {
        let err = Error::NotImplemented("feature_x".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("feature_x"));
    }

    #[test]
    fn test_internal_error_display() {
        let err = Error::Internal("unexpected state".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("unexpected state"));
    }

    #[test]
    fn test_authorization_denied_error_display() {
        let err = Error::AuthorizationDenied("patch scope required".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("patch scope required"));
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<i32>("not a number").unwrap_err();
        let err: Error = json_err.into();
        match err {
            Error::Serialization(msg) => assert!(!msg.is_empty()),
            _ => panic!("Expected Serialization error"),
        }
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_ok() -> Result<i32> {
            Ok(42)
        }
        fn returns_err() -> Result<i32> {
            Err(Error::Internal("test".to_string()))
        }
        assert_eq!(returns_ok().unwrap(), 42);
        assert!(returns_err().is_err());
    }
}
