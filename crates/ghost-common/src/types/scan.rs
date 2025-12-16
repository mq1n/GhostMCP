//! Basic scan types

use serde::{Deserialize, Serialize};

/// Scan result for memory searches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub address: usize,
    pub value: Vec<u8>,
}

/// Value type for memory operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    String,
    Bytes,
}

/// Capability scopes for authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    Read,
    Debug,
    Patch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_serialization() {
        let result = ScanResult {
            address: 0x140001000,
            value: vec![0x64, 0x00, 0x00, 0x00],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.address, 0x140001000);
        assert_eq!(parsed.value.len(), 4);
    }

    #[test]
    fn test_value_type_variants() {
        assert_ne!(ValueType::U8, ValueType::I8);
        assert_ne!(ValueType::U32, ValueType::F32);
        assert_ne!(ValueType::String, ValueType::Bytes);
    }

    #[test]
    fn test_scope_ordering() {
        assert!(Scope::Read < Scope::Debug);
        assert!(Scope::Debug < Scope::Patch);
        assert!(Scope::Read < Scope::Patch);
    }
}
