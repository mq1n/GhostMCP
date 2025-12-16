//! Memory-related types

use serde::{Deserialize, Serialize};

/// Memory protection flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Protection {
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    pub fn from_windows(protect: u32) -> Self {
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
        const PAGE_READONLY: u32 = 0x02;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_WRITECOPY: u32 = 0x08;

        let execute = matches!(
            protect,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );
        let read = matches!(
            protect,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        );
        let write = matches!(
            protect,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );

        Self {
            read,
            write,
            execute,
        }
    }
}

/// Memory region information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: usize,
    pub size: usize,
    pub protection: Protection,
    pub state: MemoryState,
    pub region_type: MemoryType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryType {
    Image,
    Mapped,
    Private,
}

/// Type of memory access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryAccessType {
    Read,
    Write,
    Execute,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_new() {
        let prot = Protection::new(true, false, true);
        assert!(prot.read);
        assert!(!prot.write);
        assert!(prot.execute);
    }

    #[test]
    fn test_protection_from_windows_readonly() {
        let prot = Protection::from_windows(0x02); // PAGE_READONLY
        assert!(prot.read);
        assert!(!prot.write);
        assert!(!prot.execute);
    }

    #[test]
    fn test_protection_from_windows_readwrite() {
        let prot = Protection::from_windows(0x04); // PAGE_READWRITE
        assert!(prot.read);
        assert!(prot.write);
        assert!(!prot.execute);
    }

    #[test]
    fn test_protection_from_windows_execute_read() {
        let prot = Protection::from_windows(0x20); // PAGE_EXECUTE_READ
        assert!(prot.read);
        assert!(!prot.write);
        assert!(prot.execute);
    }

    #[test]
    fn test_protection_from_windows_execute_readwrite() {
        let prot = Protection::from_windows(0x40); // PAGE_EXECUTE_READWRITE
        assert!(prot.read);
        assert!(prot.write);
        assert!(prot.execute);
    }

    #[test]
    fn test_memory_state_variants() {
        assert_ne!(MemoryState::Commit, MemoryState::Reserve);
        assert_ne!(MemoryState::Reserve, MemoryState::Free);
        assert_ne!(MemoryState::Commit, MemoryState::Free);
    }

    #[test]
    fn test_memory_type_variants() {
        assert_ne!(MemoryType::Image, MemoryType::Mapped);
        assert_ne!(MemoryType::Mapped, MemoryType::Private);
    }
}
