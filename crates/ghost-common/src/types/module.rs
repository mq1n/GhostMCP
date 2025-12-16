//! Module-related types

use serde::{Deserialize, Serialize};

/// Module information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base: usize,
    pub size: usize,
}

/// Export entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub address: usize,
    pub ordinal: u16,
}

/// Import entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub module: String,
    pub address: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_serialization() {
        let module = Module {
            name: "test.dll".to_string(),
            path: "C:\\test.dll".to_string(),
            base: 0x10000,
            size: 0x5000,
        };
        let json = serde_json::to_string(&module).unwrap();
        let parsed: Module = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test.dll");
        assert_eq!(parsed.base, 0x10000);
    }

    #[test]
    fn test_export_serialization() {
        let exp = Export {
            name: "TestFunc".to_string(),
            address: 0x140001000,
            ordinal: 1,
        };
        let json = serde_json::to_string(&exp).unwrap();
        let parsed: Export = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "TestFunc");
        assert_eq!(parsed.ordinal, 1);
    }
}
