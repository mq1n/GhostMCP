//! Instruction/disassembly types

use serde::{Deserialize, Serialize};

/// Disassembled instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_serialization() {
        let insn = Instruction {
            address: 0x140001000,
            bytes: vec![0x48, 0x89, 0x5C],
            mnemonic: "mov".to_string(),
            operands: "qword ptr [rsp+8], rbx".to_string(),
        };
        let json = serde_json::to_string(&insn).unwrap();
        let parsed: Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.address, 0x140001000);
        assert_eq!(parsed.mnemonic, "mov");
    }
}
