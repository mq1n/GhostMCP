//! Disassembly implementation helpers
//!
//! Note: Actual disassembly is done by the host using Capstone.
//! This module provides utilities for instruction analysis.

use ghost_common::{Error, Result};
use iced_x86::{Decoder, DecoderOptions, Formatter, Mnemonic};

/// Information about a disassembled instruction
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    pub address: u64,
    pub length: usize,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
    pub is_call: bool,
    pub is_ret: bool,
    pub is_syscall: bool,
    pub is_jump: bool,
    pub is_unconditional_jump: bool,
    pub target_address: Option<u64>,
}

/// Analyze a single instruction from bytes
pub fn analyze_instruction(data: &[u8], ip: u64, bitness: u32) -> Result<InstructionInfo> {
    let mut decoder = Decoder::with_ip(bitness, data, ip, DecoderOptions::NONE);

    if let Some(instruction) = decoder.iter().next() {
        if instruction.is_invalid() {
            return Err(Error::Internal("Invalid instruction".into()));
        }

        // Format instruction
        let mut output = String::new();
        let mut formatter = iced_x86::NasmFormatter::new();
        formatter.format(&instruction, &mut output);

        let (mnemonic_str, operands_str) = output.split_once(' ').unwrap_or((&output, ""));

        // Determine properties
        let mnemonic = instruction.mnemonic();
        let flow_control = instruction.flow_control();

        let is_call = mnemonic == Mnemonic::Call;
        let is_ret = matches!(
            mnemonic,
            Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq
        );
        let is_syscall = matches!(
            mnemonic,
            Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int
        ); // Treat int as syscall-like
        let is_jump = matches!(
            flow_control,
            iced_x86::FlowControl::UnconditionalBranch
                | iced_x86::FlowControl::ConditionalBranch
                | iced_x86::FlowControl::IndirectBranch
        );
        let is_unconditional_jump = flow_control == iced_x86::FlowControl::UnconditionalBranch;

        // Try to get target address
        let target_address = match instruction.op0_kind() {
            iced_x86::OpKind::NearBranch16
            | iced_x86::OpKind::NearBranch32
            | iced_x86::OpKind::NearBranch64 => Some(instruction.near_branch_target()),
            _ => None,
        };

        let length = instruction.len();

        Ok(InstructionInfo {
            address: ip,
            length,
            mnemonic: mnemonic_str.to_string(),
            operands: operands_str.trim().to_string(),
            bytes: data[..length].to_vec(),
            is_call,
            is_ret,
            is_syscall,
            is_jump,
            is_unconditional_jump,
            target_address,
        })
    } else {
        Err(Error::Internal("Failed to decode instruction".into()))
    }
}

/// Maximum instructions to disassemble for a function
pub const MAX_FUNCTION_INSTRUCTIONS: usize = 1000;

/// Maximum instructions per disassembly request
pub const MAX_DISASM_INSTRUCTIONS: usize = 100;

/// Check if instruction is a return instruction
pub fn is_return_instruction(mnemonic: &str) -> bool {
    matches!(mnemonic.to_uppercase().as_str(), "RET" | "RETN" | "RETF")
}

/// Check if instruction is a call
pub fn is_call_instruction(mnemonic: &str) -> bool {
    mnemonic.to_uppercase().starts_with("CALL")
}

/// Check if instruction is a jump
pub fn is_jump_instruction(mnemonic: &str) -> bool {
    let upper = mnemonic.to_uppercase();
    upper.starts_with("J") || upper == "JMP"
}

/// Check if instruction is unconditional jump
pub fn is_unconditional_jump(mnemonic: &str) -> bool {
    mnemonic.to_uppercase() == "JMP"
}

/// Extract target address from jump/call operand if immediate
pub fn extract_target_address(operands: &str) -> Option<usize> {
    // Simple parsing for immediate addresses like "0x140001000"
    let trimmed = operands.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        usize::from_str_radix(&trimmed[2..], 16).ok()
    } else {
        trimmed.parse().ok()
    }
}

/// Minimum string length for extraction
pub const MIN_STRING_LENGTH: usize = 4;

/// Check if byte sequence looks like an ASCII string
pub fn is_ascii_string(data: &[u8], min_length: usize) -> Option<String> {
    let mut chars = Vec::new();

    for &byte in data {
        if byte == 0 {
            break;
        }
        if byte.is_ascii_graphic() || byte == b' ' {
            chars.push(byte as char);
        } else {
            return None;
        }
    }

    if chars.len() >= min_length {
        Some(chars.into_iter().collect())
    } else {
        None
    }
}

/// Check if byte sequence looks like a UTF-16 string
pub fn is_utf16_string(data: &[u8], min_length: usize) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let mut chars = Vec::new();

    for chunk in data.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let wchar = u16::from_le_bytes([chunk[0], chunk[1]]);
        if wchar == 0 {
            break;
        }
        if let Some(c) = char::from_u32(wchar as u32) {
            if c.is_ascii_graphic() || c == ' ' {
                chars.push(c);
            } else {
                return None;
            }
        } else {
            return None;
        }
    }

    if chars.len() >= min_length {
        Some(chars.into_iter().collect())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_return_instruction() {
        assert!(is_return_instruction("ret"));
        assert!(is_return_instruction("RET"));
        assert!(is_return_instruction("retn"));
        assert!(is_return_instruction("retf"));
        assert!(!is_return_instruction("call"));
        assert!(!is_return_instruction("jmp"));
    }

    #[test]
    fn test_is_call_instruction() {
        assert!(is_call_instruction("call"));
        assert!(is_call_instruction("CALL"));
        assert!(!is_call_instruction("ret"));
        assert!(!is_call_instruction("jmp"));
    }

    #[test]
    fn test_is_jump_instruction() {
        assert!(is_jump_instruction("jmp"));
        assert!(is_jump_instruction("JMP"));
        assert!(is_jump_instruction("je"));
        assert!(is_jump_instruction("jne"));
        assert!(is_jump_instruction("jz"));
        assert!(!is_jump_instruction("call"));
        assert!(!is_jump_instruction("ret"));
    }

    #[test]
    fn test_is_unconditional_jump() {
        assert!(is_unconditional_jump("jmp"));
        assert!(is_unconditional_jump("JMP"));
        assert!(!is_unconditional_jump("je"));
        assert!(!is_unconditional_jump("jne"));
    }

    #[test]
    fn test_extract_target_address() {
        assert_eq!(extract_target_address("0x140001000"), Some(0x140001000));
        assert_eq!(extract_target_address("0X140001000"), Some(0x140001000));
        assert_eq!(extract_target_address("12345"), Some(12345));
        assert_eq!(extract_target_address("invalid"), None);
    }

    #[test]
    fn test_is_ascii_string() {
        let data = b"Hello World\0extra";
        assert_eq!(is_ascii_string(data, 4), Some("Hello World".to_string()));
        assert_eq!(is_ascii_string(data, 20), None); // Too short
        assert_eq!(is_ascii_string(b"\x01\x02\x03", 1), None); // Non-printable
    }

    #[test]
    fn test_is_utf16_string() {
        // "Hi" in UTF-16 LE
        let data = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        assert_eq!(is_utf16_string(&data, 2), Some("Hi".to_string()));
        assert_eq!(is_utf16_string(&data, 10), None); // Too short
    }
}
