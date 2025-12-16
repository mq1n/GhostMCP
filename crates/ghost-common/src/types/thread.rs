//! Thread-related types

use serde::{Deserialize, Serialize};

/// Thread information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    pub id: u32,
    pub base_priority: i32,
    pub state: ThreadState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadState {
    Running,
    Suspended,
    Waiting,
    Unknown,
}

/// CPU registers (x64)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// Stack frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub index: u32,
    pub address: usize,
    pub return_address: usize,
    pub symbol: Option<String>,
    pub module: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_state_variants() {
        assert_ne!(ThreadState::Running, ThreadState::Suspended);
        assert_ne!(ThreadState::Suspended, ThreadState::Waiting);
        assert_ne!(ThreadState::Waiting, ThreadState::Unknown);
    }

    #[test]
    fn test_registers_default() {
        let regs = Registers::default();
        assert_eq!(regs.rax, 0);
        assert_eq!(regs.rip, 0);
        assert_eq!(regs.rsp, 0);
    }
}
