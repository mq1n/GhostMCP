//! Cross-reference analysis
//!
//! Provides functionality to find code that references a specific address.

use ghost_common::{Instruction, Result};

/// Cross-reference entry
#[derive(Debug, Clone)]
pub struct XRef {
    /// Address where the reference originates
    pub from_address: usize,
    /// Address being referenced
    pub to_address: usize,
    /// Type of reference
    pub ref_type: XRefType,
    /// Instruction at the reference location (if code)
    pub instruction: Option<String>,
}

/// Type of cross-reference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XRefType {
    /// Direct call instruction
    Call,
    /// Direct jump instruction
    Jump,
    /// Conditional jump
    ConditionalJump,
    /// Memory read reference
    Read,
    /// Memory write reference
    Write,
    /// LEA or address calculation
    Lea,
    /// Unknown/other reference
    Unknown,
}

impl std::fmt::Display for XRefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XRefType::Call => write!(f, "call"),
            XRefType::Jump => write!(f, "jmp"),
            XRefType::ConditionalJump => write!(f, "jcc"),
            XRefType::Read => write!(f, "read"),
            XRefType::Write => write!(f, "write"),
            XRefType::Lea => write!(f, "lea"),
            XRefType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Find cross-references to a target address within a memory range
///
/// Scans executable memory for instructions that reference the target address.
/// This includes:
/// - Direct calls (CALL rel32)
/// - Direct jumps (JMP rel32, Jcc rel32)
/// - RIP-relative addressing (LEA, MOV, etc.)
/// - Absolute addresses in instruction operands
///
/// # Arguments
/// * `target` - The address being referenced
/// * `code` - The code bytes to scan
/// * `base_address` - Base address of the code buffer
/// * `max_results` - Maximum number of results to return
///
/// # Returns
/// Vector of addresses that reference the target
pub fn find_xrefs_to(
    target: usize,
    code: &[u8],
    base_address: usize,
    max_results: usize,
) -> Vec<usize> {
    let mut results = Vec::new();

    if code.len() < 5 {
        return results;
    }

    // Scan for relative call/jump patterns
    let mut i = 0;
    while i + 5 <= code.len() && results.len() < max_results {
        let addr = base_address + i;

        // Check for E8 (CALL rel32)
        if code[i] == 0xE8 && i + 5 <= code.len() {
            let rel32 = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let call_target = (addr as i64 + 5 + rel32 as i64) as usize;
            if call_target == target {
                results.push(addr);
                i += 5;
                continue;
            }
        }

        // Check for E9 (JMP rel32)
        if code[i] == 0xE9 && i + 5 <= code.len() {
            let rel32 = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let jmp_target = (addr as i64 + 5 + rel32 as i64) as usize;
            if jmp_target == target {
                results.push(addr);
                i += 5;
                continue;
            }
        }

        // Check for 0F 8x (Jcc rel32 - conditional jumps)
        if code[i] == 0x0F && i + 6 <= code.len() && (code[i + 1] & 0xF0) == 0x80 {
            let rel32 = i32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
            let jcc_target = (addr as i64 + 6 + rel32 as i64) as usize;
            if jcc_target == target {
                results.push(addr);
                i += 6;
                continue;
            }
        }

        // Check for RIP-relative addressing with 4-byte displacement
        // Common patterns: 48 8B 0D [disp32], 48 8D 05 [disp32], etc.
        // This is a simplified check - in practice you'd use a disassembler
        if i + 7 <= code.len() {
            // LEA reg, [rip+disp32] patterns
            if (code[i] == 0x48 || code[i] == 0x4C)
                && code[i + 1] == 0x8D
                && (code[i + 2] & 0xC7) == 0x05
            {
                let rel32 =
                    i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                let lea_target = (addr as i64 + 7 + rel32 as i64) as usize;
                if lea_target == target {
                    results.push(addr);
                    i += 7;
                    continue;
                }
            }

            // MOV reg, [rip+disp32] patterns
            if (code[i] == 0x48 || code[i] == 0x4C)
                && code[i + 1] == 0x8B
                && (code[i + 2] & 0xC7) == 0x05
            {
                let rel32 =
                    i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                let mov_target = (addr as i64 + 7 + rel32 as i64) as usize;
                if mov_target == target {
                    results.push(addr);
                    i += 7;
                    continue;
                }
            }
        }

        i += 1;
    }

    results
}

/// Find cross-references to a target address using disassembled instructions
///
/// More accurate than raw byte scanning as it uses proper disassembly.
pub fn find_xrefs_from_instructions(
    target: usize,
    instructions: &[Instruction],
    max_results: usize,
) -> Vec<XRef> {
    let mut results = Vec::new();

    for insn in instructions {
        if results.len() >= max_results {
            break;
        }

        // Parse the operands to check for target address references
        let operands_lower = insn.operands.to_lowercase();
        let mnemonic_lower = insn.mnemonic.to_lowercase();

        // Check if operands contain the target address (as hex)
        let target_hex = format!("0x{:x}", target);
        let target_hex_alt = format!("{:x}", target);

        if operands_lower.contains(&target_hex) || operands_lower.contains(&target_hex_alt) {
            let ref_type = classify_instruction(&mnemonic_lower);
            results.push(XRef {
                from_address: insn.address,
                to_address: target,
                ref_type,
                instruction: Some(format!("{} {}", insn.mnemonic, insn.operands)),
            });
        }

        // Also check for relative addressing that might resolve to target
        // This would require computing the actual target from rel32 values
    }

    results
}

/// Classify an instruction mnemonic into an XRef type
fn classify_instruction(mnemonic: &str) -> XRefType {
    match mnemonic {
        "call" => XRefType::Call,
        "jmp" => XRefType::Jump,
        m if m.starts_with('j') => XRefType::ConditionalJump,
        "lea" => XRefType::Lea,
        "mov" | "movzx" | "movsx" | "movsxd" => XRefType::Read,
        _ => XRefType::Unknown,
    }
}

/// Scan a module's executable sections for xrefs to target
pub fn scan_module_for_xrefs<F>(
    target: usize,
    module_base: usize,
    module_size: usize,
    read_fn: F,
    max_results: usize,
) -> Result<Vec<usize>>
where
    F: Fn(usize, usize) -> Result<Vec<u8>>,
{
    let mut all_results = Vec::new();

    // Read module in chunks to avoid memory issues
    const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
    let mut offset = 0;

    while offset < module_size && all_results.len() < max_results {
        let chunk_size = (module_size - offset).min(CHUNK_SIZE);
        let chunk_base = module_base + offset;

        match read_fn(chunk_base, chunk_size) {
            Ok(data) => {
                let remaining = max_results - all_results.len();
                let mut found = find_xrefs_to(target, &data, chunk_base, remaining);
                all_results.append(&mut found);
            }
            Err(_) => {
                // Skip unreadable regions
            }
        }

        // Overlap by a small amount to catch xrefs at chunk boundaries
        offset += chunk_size.saturating_sub(16);
    }

    Ok(all_results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_call_xref() {
        // E8 xx xx xx xx = CALL rel32
        // If we're at address 0x1000 and call target is 0x2000:
        // rel32 = 0x2000 - (0x1000 + 5) = 0xFFB
        let base = 0x1000usize;
        let target = 0x2000usize;
        let rel32 = (target as i64 - (base as i64 + 5)) as i32;
        let rel_bytes = rel32.to_le_bytes();

        let code = vec![0xE8, rel_bytes[0], rel_bytes[1], rel_bytes[2], rel_bytes[3]];

        let results = find_xrefs_to(target, &code, base, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], base);
    }

    #[test]
    fn test_find_jmp_xref() {
        // E9 xx xx xx xx = JMP rel32
        let base = 0x1000usize;
        let target = 0x3000usize;
        let rel32 = (target as i64 - (base as i64 + 5)) as i32;
        let rel_bytes = rel32.to_le_bytes();

        let code = vec![0xE9, rel_bytes[0], rel_bytes[1], rel_bytes[2], rel_bytes[3]];

        let results = find_xrefs_to(target, &code, base, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], base);
    }

    #[test]
    fn test_no_false_positives() {
        // Random bytes that don't form valid xrefs
        let code = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let results = find_xrefs_to(0x5000, &code, 0x1000, 100);
        assert!(results.is_empty());
    }

    #[test]
    fn test_classify_instruction() {
        assert_eq!(classify_instruction("call"), XRefType::Call);
        assert_eq!(classify_instruction("jmp"), XRefType::Jump);
        assert_eq!(classify_instruction("je"), XRefType::ConditionalJump);
        assert_eq!(classify_instruction("jne"), XRefType::ConditionalJump);
        assert_eq!(classify_instruction("lea"), XRefType::Lea);
        assert_eq!(classify_instruction("mov"), XRefType::Read);
    }
}
