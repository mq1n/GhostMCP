//! Hooking implementation helpers

use std::sync::atomic::{AtomicU32, Ordering};

/// Counter for generating unique hook IDs
static HOOK_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Generate a new unique hook ID
pub fn next_hook_id() -> u32 {
    HOOK_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Information about an installed hook
pub struct HookInfo {
    pub id: u32,
    pub target: usize,
    pub callback: usize,
    pub trampoline: usize,
    pub original_bytes: Vec<u8>,
}

/// x64 absolute jump instruction (14 bytes)
/// FF 25 00 00 00 00 [8-byte address]
pub const X64_ABS_JMP_SIZE: usize = 14;

/// Generate x64 absolute jump to target address
pub fn generate_abs_jump(target: usize) -> [u8; X64_ABS_JMP_SIZE] {
    let mut bytes = [0u8; X64_ABS_JMP_SIZE];

    // FF 25 00 00 00 00 = JMP [RIP+0] (jump to address stored after this instruction)
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    bytes[2] = 0x00;
    bytes[3] = 0x00;
    bytes[4] = 0x00;
    bytes[5] = 0x00;

    // 8-byte target address
    let addr_bytes = (target as u64).to_le_bytes();
    bytes[6..14].copy_from_slice(&addr_bytes);

    bytes
}

/// x64 relative jump instruction (5 bytes, ±2GB range)
pub const X64_REL_JMP_SIZE: usize = 5;

/// Generate x64 relative jump if target is within range
pub fn generate_rel_jump(from: usize, to: usize) -> Option<[u8; X64_REL_JMP_SIZE]> {
    let offset = to as i64 - (from as i64 + X64_REL_JMP_SIZE as i64);

    // Check if offset fits in i32
    if offset >= i32::MIN as i64 && offset <= i32::MAX as i64 {
        let mut bytes = [0u8; X64_REL_JMP_SIZE];
        bytes[0] = 0xE9; // JMP rel32
        bytes[1..5].copy_from_slice(&(offset as i32).to_le_bytes());
        Some(bytes)
    } else {
        None
    }
}

/// NOP instruction
pub const NOP: u8 = 0x90;

/// Generate NOP sled
pub fn generate_nops(count: usize) -> Vec<u8> {
    vec![NOP; count]
}

/// Minimum bytes needed for a hook (must fit at least a relative jump)
pub const MIN_HOOK_SIZE: usize = X64_REL_JMP_SIZE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_hook_id() {
        let id1 = next_hook_id();
        let id2 = next_hook_id();
        assert!(id2 > id1);
    }

    #[test]
    fn test_generate_abs_jump() {
        let target: usize = 0x00007FF712345678;
        let bytes = generate_abs_jump(target);

        // Check JMP [RIP+0] opcode
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(bytes[1], 0x25);
        assert_eq!(bytes[2..6], [0x00, 0x00, 0x00, 0x00]);

        // Check target address (little-endian)
        let addr = u64::from_le_bytes(bytes[6..14].try_into().unwrap());
        assert_eq!(addr, target as u64);
    }

    #[test]
    fn test_generate_rel_jump_in_range() {
        let from: usize = 0x140001000;
        let to: usize = 0x140001100;
        let result = generate_rel_jump(from, to);
        assert!(result.is_some());

        let bytes = result.unwrap();
        assert_eq!(bytes[0], 0xE9); // JMP rel32 opcode
    }

    #[test]
    fn test_generate_rel_jump_out_of_range() {
        let from: usize = 0x140001000;
        let to: usize = 0x7FF700000000; // Way out of ±2GB range
        let result = generate_rel_jump(from, to);
        assert!(result.is_none());
    }

    #[test]
    fn test_generate_nops() {
        let nops = generate_nops(5);
        assert_eq!(nops.len(), 5);
        assert!(nops.iter().all(|&b| b == NOP));
    }
}
