//! Breakpoint-related types

use serde::{Deserialize, Serialize};

/// Breakpoint type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointType {
    Software,
    Hardware,
}

/// Breakpoint ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BreakpointId(pub u32);

/// Breakpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakpoint {
    pub id: BreakpointId,
    pub address: usize,
    pub bp_type: BreakpointType,
    pub enabled: bool,
    pub hit_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_id_equality() {
        let id1 = BreakpointId(1);
        let id2 = BreakpointId(1);
        let id3 = BreakpointId(2);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_breakpoint_type_variants() {
        assert_ne!(BreakpointType::Software, BreakpointType::Hardware);
    }
}
