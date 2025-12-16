//! Memory operations implementation helpers
//!
//! Note: Pattern scanning has been moved to `pattern_scanner` module.
//! This module now contains only value scanning and memory region utilities.

use ghost_common::{
    MemoryRegion, MemoryState, MemoryType, Protection, Result, ScanResult, ValueType,
};

/// Convert value to bytes based on type
pub fn value_to_bytes(value: &str, value_type: ValueType) -> Result<Vec<u8>> {
    match value_type {
        ValueType::U8 => {
            let v: u8 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid u8 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::U16 => {
            let v: u16 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid u16 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::U32 => {
            let v: u32 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid u32 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::U64 => {
            let v: u64 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid u64 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::I8 => {
            let v: i8 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid i8 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::I16 => {
            let v: i16 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid i16 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::I32 => {
            let v: i32 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid i32 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::I64 => {
            let v: i64 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid i64 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::F32 => {
            let v: f32 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid f32 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::F64 => {
            let v: f64 = value.parse().map_err(|_| {
                ghost_common::Error::Internal(format!("Invalid f64 value: {}", value))
            })?;
            Ok(v.to_le_bytes().to_vec())
        }
        ValueType::String => Ok(value.as_bytes().to_vec()),
        ValueType::Bytes => {
            // Parse hex string "48 8B 05"
            let mut bytes = Vec::new();
            for part in value.split_whitespace() {
                let byte = u8::from_str_radix(part, 16).map_err(|_| {
                    ghost_common::Error::Internal(format!("Invalid hex byte: {}", part))
                })?;
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
}

/// Scan memory region for exact value
pub fn scan_region_for_value(
    data: &[u8],
    base: usize,
    value: &[u8],
    alignment: usize,
    max_results: usize,
) -> Vec<ScanResult> {
    let mut results = Vec::new();

    if data.len() < value.len() || value.is_empty() {
        return results;
    }

    let step = if alignment > 0 { alignment } else { 1 };

    let mut i = 0;
    while i <= data.len() - value.len() {
        if &data[i..i + value.len()] == value {
            results.push(ScanResult {
                address: base + i,
                value: value.to_vec(),
            });

            if results.len() >= max_results {
                break;
            }
        }
        i += step;
    }

    results
}

/// Get default alignment for a value type
pub fn alignment_for_type(value_type: ValueType) -> usize {
    match value_type {
        ValueType::U8 | ValueType::I8 => 1,
        ValueType::U16 | ValueType::I16 => 2,
        ValueType::U32 | ValueType::I32 | ValueType::F32 => 4,
        ValueType::U64 | ValueType::I64 | ValueType::F64 => 8,
        ValueType::String | ValueType::Bytes => 1,
    }
}

/// Create MemoryRegion from Windows MEMORY_BASIC_INFORMATION
pub fn region_from_mbi(
    base: usize,
    size: usize,
    protect: u32,
    state: u32,
    mem_type: u32,
) -> MemoryRegion {
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_IMAGE: u32 = 0x1000000;
    const MEM_MAPPED: u32 = 0x40000;
    #[allow(dead_code)]
    const MEM_PRIVATE: u32 = 0x20000;

    let state = if state == MEM_COMMIT {
        MemoryState::Commit
    } else if state == MEM_RESERVE {
        MemoryState::Reserve
    } else {
        MemoryState::Free
    };

    let region_type = if mem_type & MEM_IMAGE != 0 {
        MemoryType::Image
    } else if mem_type & MEM_MAPPED != 0 {
        MemoryType::Mapped
    } else {
        MemoryType::Private
    };

    MemoryRegion {
        base,
        size,
        protection: Protection::from_windows(protect),
        state,
        region_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_region_for_value() {
        let data = vec![0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00];
        let value = 100i32.to_le_bytes();
        let results = scan_region_for_value(&data, 0x1000, &value, 4, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].address, 0x1000);
        assert_eq!(results[1].address, 0x1004);
    }

    #[test]
    fn test_value_to_bytes_i32() {
        let bytes = value_to_bytes("100", ValueType::I32).unwrap();
        assert_eq!(bytes, 100i32.to_le_bytes().to_vec());
    }

    #[test]
    fn test_value_to_bytes_f32() {
        let bytes = value_to_bytes("2.5", ValueType::F32).unwrap();
        assert_eq!(bytes, 2.5f32.to_le_bytes().to_vec());
    }

    #[test]
    fn test_value_to_bytes_string() {
        let bytes = value_to_bytes("hello", ValueType::String).unwrap();
        assert_eq!(bytes, b"hello".to_vec());
    }

    #[test]
    fn test_alignment_for_type() {
        assert_eq!(alignment_for_type(ValueType::U8), 1);
        assert_eq!(alignment_for_type(ValueType::U16), 2);
        assert_eq!(alignment_for_type(ValueType::U32), 4);
        assert_eq!(alignment_for_type(ValueType::U64), 8);
        assert_eq!(alignment_for_type(ValueType::F32), 4);
        assert_eq!(alignment_for_type(ValueType::F64), 8);
    }
}
