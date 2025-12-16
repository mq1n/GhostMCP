//! Assembler Module using iced-x86
//!
//! Provides x86/x64 assembly functionality including:
//! - Text-to-bytes assembly using iced-x86's CodeAssembler
//! - Support for both 32-bit and 64-bit modes
//! - Position-dependent code assembly at specific addresses
//! - Common instruction patterns and shellcode generation

use ghost_common::{Error, Result};
use iced_x86::code_asm::*;
use tracing::{info, trace};

fn inv_arg(msg: String) -> Error {
    Error::Internal(msg)
}

/// Assembler bitness mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblerMode {
    X86,
    X64,
}

impl Default for AssemblerMode {
    fn default() -> Self {
        #[cfg(target_pointer_width = "64")]
        return Self::X64;
        #[cfg(target_pointer_width = "32")]
        return Self::X86;
    }
}

impl AssemblerMode {
    pub fn bitness(&self) -> u32 {
        match self {
            AssemblerMode::X86 => 32,
            AssemblerMode::X64 => 64,
        }
    }
}

/// Result of assembly operation
#[derive(Debug, Clone)]
pub struct AssemblyResult {
    pub bytes: Vec<u8>,
    pub address: u64,
    pub instruction_count: usize,
    pub mode: AssemblerMode,
}

/// x86/x64 Assembler using iced-x86
pub struct Assembler {
    mode: AssemblerMode,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new(AssemblerMode::default())
    }
}

fn asm_err(e: IcedError) -> Error {
    Error::Internal(format!("Assembly error: {}", e))
}

impl Assembler {
    pub fn new(mode: AssemblerMode) -> Self {
        info!(target: "ghost_core::assembler", mode = ?mode, "Creating assembler");
        Self { mode }
    }

    pub fn mode(&self) -> AssemblerMode {
        self.mode
    }

    pub fn x64() -> Self {
        Self::new(AssemblerMode::X64)
    }

    pub fn x86() -> Self {
        Self::new(AssemblerMode::X86)
    }

    /// Assemble text to bytes at specified address
    pub fn assemble(&self, text: &str, address: u64) -> Result<AssemblyResult> {
        let mut asm = CodeAssembler::new(self.mode.bitness()).map_err(asm_err)?;
        self.parse_and_emit(&mut asm, text)?;
        let bytes = asm.assemble(address).map_err(asm_err)?;
        Ok(AssemblyResult {
            instruction_count: asm.instructions().len(),
            bytes,
            address,
            mode: self.mode,
        })
    }

    /// Assemble using builder pattern for complex sequences
    pub fn assemble_with_builder<F>(&self, address: u64, builder: F) -> Result<AssemblyResult>
    where
        F: FnOnce(&mut CodeAssembler) -> std::result::Result<(), IcedError>,
    {
        let mut asm = CodeAssembler::new(self.mode.bitness()).map_err(asm_err)?;
        builder(&mut asm).map_err(asm_err)?;
        let bytes = asm.assemble(address).map_err(asm_err)?;
        Ok(AssemblyResult {
            instruction_count: asm.instructions().len(),
            bytes,
            address,
            mode: self.mode,
        })
    }

    fn parse_and_emit(&self, asm: &mut CodeAssembler, text: &str) -> Result<()> {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with("//")
                || line.starts_with(';')
            {
                continue;
            }
            // Handle semicolon-separated instructions
            for part in line.split(';') {
                let part = part.trim();
                if !part.is_empty() && !part.starts_with('#') {
                    self.emit_instruction(asm, part)?;
                }
            }
        }
        Ok(())
    }

    fn emit_instruction(&self, asm: &mut CodeAssembler, text: &str) -> Result<()> {
        let text = text.trim().to_lowercase();
        let parts: Vec<&str> = text.splitn(2, char::is_whitespace).collect();
        let mnemonic = parts[0];
        let operands_str = parts.get(1).unwrap_or(&"").trim();
        let ops: Vec<&str> = operands_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        trace!(target: "ghost_core::assembler", mnemonic = %mnemonic, operands = ?ops, "Emitting instruction");

        match mnemonic {
            // No operands
            "nop" => asm.nop().map_err(asm_err)?,
            "ret" | "retn" => asm.ret().map_err(asm_err)?,
            "int3" => asm.int3().map_err(asm_err)?,
            "leave" => asm.leave().map_err(asm_err)?,
            "syscall" => asm.syscall().map_err(asm_err)?,
            "cdq" => asm.cdq().map_err(asm_err)?,
            "cqo" => asm.cqo().map_err(asm_err)?,
            "pushfq" => asm.pushfq().map_err(asm_err)?,
            "popfq" => asm.popfq().map_err(asm_err)?,
            "pushfd" => asm.pushfd().map_err(asm_err)?,
            "popfd" => asm.popfd().map_err(asm_err)?,

            // Single operand
            "push" => self.emit_push(asm, &ops)?,
            "pop" => self.emit_pop(asm, &ops)?,
            "call" => self.emit_call(asm, &ops)?,
            "jmp" => self.emit_jmp(asm, &ops)?,
            "inc" => self.emit_inc(asm, &ops)?,
            "dec" => self.emit_dec(asm, &ops)?,
            "not" => self.emit_not(asm, &ops)?,
            "neg" => self.emit_neg(asm, &ops)?,

            // Two operands
            "mov" => self.emit_mov(asm, &ops)?,
            "add" => self.emit_add(asm, &ops)?,
            "sub" => self.emit_sub(asm, &ops)?,
            "xor" => self.emit_xor(asm, &ops)?,
            "and" => self.emit_and(asm, &ops)?,
            "or" => self.emit_or(asm, &ops)?,
            "cmp" => self.emit_cmp(asm, &ops)?,
            "test" => self.emit_test(asm, &ops)?,
            "lea" => self.emit_lea(asm, &ops)?,
            "shl" | "sal" => self.emit_shl(asm, &ops)?,
            "shr" => self.emit_shr(asm, &ops)?,
            "imul" => self.emit_imul(asm, &ops)?,
            "xchg" => self.emit_xchg(asm, &ops)?,

            // Conditional jumps
            "je" | "jz" => {
                let v = self.parse_imm(ops[0])?;
                asm.je(v).map_err(asm_err)?;
            }
            "jne" | "jnz" => {
                let v = self.parse_imm(ops[0])?;
                asm.jne(v).map_err(asm_err)?;
            }
            "jl" => {
                let v = self.parse_imm(ops[0])?;
                asm.jl(v).map_err(asm_err)?;
            }
            "jle" => {
                let v = self.parse_imm(ops[0])?;
                asm.jle(v).map_err(asm_err)?;
            }
            "jg" => {
                let v = self.parse_imm(ops[0])?;
                asm.jg(v).map_err(asm_err)?;
            }
            "jge" => {
                let v = self.parse_imm(ops[0])?;
                asm.jge(v).map_err(asm_err)?;
            }
            "ja" => {
                let v = self.parse_imm(ops[0])?;
                asm.ja(v).map_err(asm_err)?;
            }
            "jae" => {
                let v = self.parse_imm(ops[0])?;
                asm.jae(v).map_err(asm_err)?;
            }
            "jb" => {
                let v = self.parse_imm(ops[0])?;
                asm.jb(v).map_err(asm_err)?;
            }
            "jbe" => {
                let v = self.parse_imm(ops[0])?;
                asm.jbe(v).map_err(asm_err)?;
            }

            _ => return Err(inv_arg(format!("Unsupported instruction: {}", mnemonic))),
        }
        Ok(())
    }

    fn emit_push(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("push requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.push(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.push(r).map_err(asm_err)?;
        } else {
            let v = self.parse_imm(op)? as i32;
            asm.push(v).map_err(asm_err)?;
        }
        Ok(())
    }

    fn emit_pop(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("pop requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.pop(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.pop(r).map_err(asm_err)?;
        } else {
            return Err(inv_arg("pop requires register".into()));
        }
        Ok(())
    }

    fn emit_call(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("call requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.call(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.call(r).map_err(asm_err)?;
        } else {
            let v = self.parse_imm(op)?;
            asm.call(v).map_err(asm_err)?;
        }
        Ok(())
    }

    fn emit_jmp(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("jmp requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.jmp(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.jmp(r).map_err(asm_err)?;
        } else {
            let v = self.parse_imm(op)?;
            asm.jmp(v).map_err(asm_err)?;
        }
        Ok(())
    }

    fn emit_inc(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("inc requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.inc(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.inc(r).map_err(asm_err)?;
        } else {
            return Err(inv_arg("inc requires register".into()));
        }
        Ok(())
    }

    fn emit_dec(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("dec requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.dec(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.dec(r).map_err(asm_err)?;
        } else {
            return Err(inv_arg("dec requires register".into()));
        }
        Ok(())
    }

    fn emit_not(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("not requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.not(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.not(r).map_err(asm_err)?;
        } else {
            return Err(inv_arg("not requires register".into()));
        }
        Ok(())
    }

    fn emit_neg(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let op = ops
            .first()
            .ok_or_else(|| inv_arg("neg requires operand".into()))?;
        if let Some(r) = self.parse_reg64(op) {
            asm.neg(r).map_err(asm_err)?;
        } else if let Some(r) = self.parse_reg32(op) {
            asm.neg(r).map_err(asm_err)?;
        } else {
            return Err(inv_arg("neg requires register".into()));
        }
        Ok(())
    }

    fn emit_mov(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "mov")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.mov(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)?;
                asm.mov(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.mov(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as u32;
                asm.mov(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("mov destination must be register".into()));
        }
        Ok(())
    }

    fn emit_add(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "add")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.add(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.add(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.add(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.add(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("add destination must be register".into()));
        }
        Ok(())
    }

    fn emit_sub(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "sub")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.sub(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.sub(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.sub(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.sub(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("sub destination must be register".into()));
        }
        Ok(())
    }

    fn emit_xor(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "xor")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.xor(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.xor(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.xor(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.xor(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("xor destination must be register".into()));
        }
        Ok(())
    }

    fn emit_and(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "and")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.and(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.and(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.and(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.and(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("and destination must be register".into()));
        }
        Ok(())
    }

    fn emit_or(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "or")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.or(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.or(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.or(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.or(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("or destination must be register".into()));
        }
        Ok(())
    }

    fn emit_cmp(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "cmp")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.cmp(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.cmp(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.cmp(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.cmp(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("cmp destination must be register".into()));
        }
        Ok(())
    }

    fn emit_test(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "test")?;
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.test(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.test(rd, v).map_err(asm_err)?;
            }
        } else if let Some(rd) = self.parse_reg32(dst) {
            if let Some(rs) = self.parse_reg32(src) {
                asm.test(rd, rs).map_err(asm_err)?;
            } else {
                let v = self.parse_imm(src)? as i32;
                asm.test(rd, v).map_err(asm_err)?;
            }
        } else {
            return Err(inv_arg("test destination must be register".into()));
        }
        Ok(())
    }

    fn emit_lea(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "lea")?;
        let src = src.trim_start_matches('[').trim_end_matches(']');
        if let Some(rd) = self.parse_reg64(dst) {
            if let Some(rs) = self.parse_reg64(src) {
                asm.lea(rd, ptr(rs)).map_err(asm_err)?;
            } else {
                return Err(inv_arg("lea source must be memory reference".into()));
            }
        } else {
            return Err(inv_arg("lea destination must be 64-bit register".into()));
        }
        Ok(())
    }

    fn emit_shl(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "shl")?;
        let count = self.parse_imm(src)? as u32;
        if let Some(rd) = self.parse_reg64(dst) {
            asm.shl(rd, count).map_err(asm_err)?;
        } else if let Some(rd) = self.parse_reg32(dst) {
            asm.shl(rd, count).map_err(asm_err)?;
        } else {
            return Err(inv_arg("shl destination must be register".into()));
        }
        Ok(())
    }

    fn emit_shr(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "shr")?;
        let count = self.parse_imm(src)? as u32;
        if let Some(rd) = self.parse_reg64(dst) {
            asm.shr(rd, count).map_err(asm_err)?;
        } else if let Some(rd) = self.parse_reg32(dst) {
            asm.shr(rd, count).map_err(asm_err)?;
        } else {
            return Err(inv_arg("shr destination must be register".into()));
        }
        Ok(())
    }

    fn emit_imul(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        if ops.len() == 1 {
            let op = ops[0];
            if let Some(r) = self.parse_reg64(op) {
                asm.imul(r).map_err(asm_err)?;
            } else if let Some(r) = self.parse_reg32(op) {
                asm.imul(r).map_err(asm_err)?;
            }
        } else {
            let (dst, src) = self.get_two_ops(ops, "imul")?;
            if let Some(rd) = self.parse_reg64(dst) {
                if let Some(rs) = self.parse_reg64(src) {
                    asm.imul_2(rd, rs).map_err(asm_err)?;
                } else {
                    let v = self.parse_imm(src)? as i32;
                    asm.imul_3(rd, rd, v).map_err(asm_err)?;
                }
            } else if let Some(rd) = self.parse_reg32(dst) {
                if let Some(rs) = self.parse_reg32(src) {
                    asm.imul_2(rd, rs).map_err(asm_err)?;
                } else {
                    let v = self.parse_imm(src)? as i32;
                    asm.imul_3(rd, rd, v).map_err(asm_err)?;
                }
            }
        }
        Ok(())
    }

    fn emit_xchg(&self, asm: &mut CodeAssembler, ops: &[&str]) -> Result<()> {
        let (dst, src) = self.get_two_ops(ops, "xchg")?;
        if let (Some(rd), Some(rs)) = (self.parse_reg64(dst), self.parse_reg64(src)) {
            asm.xchg(rd, rs).map_err(asm_err)?;
        } else if let (Some(rd), Some(rs)) = (self.parse_reg32(dst), self.parse_reg32(src)) {
            asm.xchg(rd, rs).map_err(asm_err)?;
        } else {
            return Err(inv_arg("xchg requires two registers of same size".into()));
        }
        Ok(())
    }

    fn get_two_ops<'a>(&self, ops: &[&'a str], name: &str) -> Result<(&'a str, &'a str)> {
        if ops.len() < 2 {
            return Err(inv_arg(format!("{} requires two operands", name)));
        }
        Ok((ops[0], ops[1]))
    }

    fn parse_reg64(&self, s: &str) -> Option<AsmRegister64> {
        match s.trim().to_lowercase().as_str() {
            "rax" => Some(rax),
            "rbx" => Some(rbx),
            "rcx" => Some(rcx),
            "rdx" => Some(rdx),
            "rsi" => Some(rsi),
            "rdi" => Some(rdi),
            "rbp" => Some(rbp),
            "rsp" => Some(rsp),
            "r8" => Some(r8),
            "r9" => Some(r9),
            "r10" => Some(r10),
            "r11" => Some(r11),
            "r12" => Some(r12),
            "r13" => Some(r13),
            "r14" => Some(r14),
            "r15" => Some(r15),
            _ => None,
        }
    }

    fn parse_reg32(&self, s: &str) -> Option<AsmRegister32> {
        match s.trim().to_lowercase().as_str() {
            "eax" => Some(eax),
            "ebx" => Some(ebx),
            "ecx" => Some(ecx),
            "edx" => Some(edx),
            "esi" => Some(esi),
            "edi" => Some(edi),
            "ebp" => Some(ebp),
            "esp" => Some(esp),
            "r8d" => Some(r8d),
            "r9d" => Some(r9d),
            "r10d" => Some(r10d),
            "r11d" => Some(r11d),
            "r12d" => Some(r12d),
            "r13d" => Some(r13d),
            "r14d" => Some(r14d),
            "r15d" => Some(r15d),
            _ => None,
        }
    }

    fn parse_imm(&self, s: &str) -> Result<u64> {
        let s = s.trim().to_lowercase();
        if let Some(hex) = s.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).map_err(|_| inv_arg(format!("Invalid hex: {}", s)))
        } else if let Some(hex) = s.strip_suffix('h') {
            u64::from_str_radix(hex, 16).map_err(|_| inv_arg(format!("Invalid hex: {}", s)))
        } else {
            s.parse::<i64>()
                .map(|v| v as u64)
                .map_err(|_| inv_arg(format!("Invalid number: {}", s)))
        }
    }

    // ========== Shellcode Helpers ==========

    /// Generate shellcode for calling a function with any number of arguments (x64 Windows calling convention)
    pub fn generate_call_shellcode(&self, func_addr: u64, args: &[u64]) -> Result<Vec<u8>> {
        if self.mode != AssemblerMode::X64 {
            return Err(inv_arg("Call shellcode only supports x64".into()));
        }
        self.assemble_with_builder(0, |asm| {
            // Standard prologue
            asm.push(rbp)?;
            asm.mov(rbp, rsp)?;

            // Calculate stack space needed
            // Shadow space (32 bytes) + arguments > 4
            let num_stack_args = if args.len() > 4 { args.len() - 4 } else { 0 };
            let mut stack_size = 32 + (num_stack_args * 8);

            // Ensure 16-byte alignment
            // After 'push rbp; mov rbp, rsp', RSP is 16-byte aligned (assuming call pushed ret addr).
            // We need RSP to be 16-byte aligned before 'call func'.
            // So stack_size must be a multiple of 16.
            if stack_size % 16 != 0 {
                stack_size += 8;
            }

            asm.sub(rsp, stack_size as i32)?;

            // Set up stack arguments (Arg 5+)
            // They go at RSP + 32 + (i-4)*8
            for (i, arg) in args.iter().enumerate().skip(4) {
                let offset = 32 + (i - 4) * 8;
                asm.mov(rax, *arg)?;
                asm.mov(ptr(rsp + offset as i32), rax)?;
            }

            // Set up register arguments
            if !args.is_empty() {
                asm.mov(rcx, args[0])?;
            }
            if args.len() > 1 {
                asm.mov(rdx, args[1])?;
            }
            if args.len() > 2 {
                asm.mov(r8, args[2])?;
            }
            if args.len() > 3 {
                asm.mov(r9, args[3])?;
            }

            // Call
            asm.mov(rax, func_addr)?;
            asm.call(rax)?;

            // Epilogue
            asm.leave()?;
            asm.ret()?;
            Ok(())
        })
        .map(|r| r.bytes)
    }

    /// Generate NOP sled of specified size
    pub fn generate_nop_sled(&self, size: usize) -> Vec<u8> {
        vec![0x90u8; size]
    }

    /// Generate INT3 breakpoint
    pub fn generate_int3(&self) -> Vec<u8> {
        vec![0xCC]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Basic Instruction Tests ==========

    #[test]
    fn test_assemble_nop() {
        let asm = Assembler::x64();
        let result = asm.assemble("nop", 0).unwrap();
        assert_eq!(result.bytes, vec![0x90]);
        assert_eq!(result.instruction_count, 1);
    }

    #[test]
    fn test_assemble_ret() {
        let asm = Assembler::x64();
        let result = asm.assemble("ret", 0).unwrap();
        assert_eq!(result.bytes, vec![0xC3]);
    }

    #[test]
    fn test_assemble_int3() {
        let asm = Assembler::x64();
        let result = asm.assemble("int3", 0).unwrap();
        assert_eq!(result.bytes, vec![0xCC]);
    }

    #[test]
    fn test_assemble_syscall() {
        let asm = Assembler::x64();
        let result = asm.assemble("syscall", 0).unwrap();
        assert_eq!(result.bytes, vec![0x0F, 0x05]);
    }

    // ========== MOV Instruction Tests ==========

    #[test]
    fn test_assemble_mov_reg_imm() {
        let asm = Assembler::x64();
        let result = asm.assemble("mov rax, 0x1234", 0).unwrap();
        assert!(!result.bytes.is_empty());
        assert_eq!(result.instruction_count, 1);
    }

    #[test]
    fn test_assemble_mov_reg_reg() {
        let asm = Assembler::x64();
        let result = asm.assemble("mov rax, rbx", 0).unwrap();
        assert_eq!(result.bytes, vec![0x48, 0x89, 0xD8]);
    }

    #[test]
    fn test_assemble_mov_32bit() {
        let asm = Assembler::x64();
        let result = asm.assemble("mov eax, ebx", 0).unwrap();
        assert_eq!(result.bytes, vec![0x89, 0xD8]);
    }

    // ========== XOR Instruction Tests ==========

    #[test]
    fn test_assemble_xor_reg_reg() {
        let asm = Assembler::x64();
        let result = asm.assemble("xor rax, rax", 0).unwrap();
        assert_eq!(result.bytes, vec![0x48, 0x31, 0xC0]);
    }

    #[test]
    fn test_assemble_xor_32bit() {
        let asm = Assembler::x64();
        let result = asm.assemble("xor eax, eax", 0).unwrap();
        assert_eq!(result.bytes, vec![0x31, 0xC0]);
    }

    // ========== Stack Operations Tests ==========

    #[test]
    fn test_assemble_push_pop() {
        let asm = Assembler::x64();
        let result = asm.assemble("push rax\npop rbx", 0).unwrap();
        assert_eq!(result.instruction_count, 2);
        assert_eq!(result.bytes[0], 0x50); // push rax
    }

    #[test]
    fn test_assemble_push_imm() {
        let asm = Assembler::x64();
        let result = asm.assemble("push 0x10", 0).unwrap();
        assert!(!result.bytes.is_empty());
    }

    // ========== Arithmetic Tests ==========

    #[test]
    fn test_assemble_add() {
        let asm = Assembler::x64();
        let result = asm.assemble("add rax, rbx", 0).unwrap();
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_assemble_sub() {
        let asm = Assembler::x64();
        let result = asm.assemble("sub rsp, 0x28", 0).unwrap();
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_assemble_inc_dec() {
        let asm = Assembler::x64();
        let result = asm.assemble("inc rax\ndec rbx", 0).unwrap();
        assert_eq!(result.instruction_count, 2);
    }

    // ========== Multiple Instructions Tests ==========

    #[test]
    fn test_assemble_multiple() {
        let asm = Assembler::x64();
        let result = asm
            .assemble("push rbp\nmov rbp, rsp\npop rbp\nret", 0)
            .unwrap();
        assert_eq!(result.instruction_count, 4);
    }

    #[test]
    fn test_assemble_semicolon_separated() {
        let asm = Assembler::x64();
        let result = asm.assemble("nop; nop; ret", 0).unwrap();
        assert_eq!(result.instruction_count, 3);
    }

    #[test]
    fn test_assemble_with_comments() {
        let asm = Assembler::x64();
        let result = asm.assemble("nop # comment\nret", 0).unwrap();
        assert_eq!(result.instruction_count, 2);
    }

    // ========== Immediate Value Parsing Tests ==========

    #[test]
    fn test_parse_hex_0x() {
        let asm = Assembler::x64();
        let result = asm.assemble("mov rax, 0xDEADBEEF", 0).unwrap();
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_parse_hex_h_suffix() {
        let asm = Assembler::x64();
        let result = asm.assemble("mov rax, DEADh", 0).unwrap();
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_parse_decimal() {
        let asm = Assembler::x64();
        let result = asm.assemble("mov rax, 12345", 0).unwrap();
        assert!(!result.bytes.is_empty());
    }

    #[test]
    fn test_parse_negative() {
        let asm = Assembler::x64();
        let result = asm.assemble("add rax, -1", 0).unwrap();
        assert!(!result.bytes.is_empty());
    }

    // ========== Shellcode Generation Tests ==========

    #[test]
    fn test_call_shellcode() {
        let asm = Assembler::x64();
        let shellcode = asm.generate_call_shellcode(0x7FFE0000, &[1, 2]).unwrap();
        assert!(!shellcode.is_empty());
    }

    #[test]
    fn test_call_shellcode_no_args() {
        let asm = Assembler::x64();
        let shellcode = asm.generate_call_shellcode(0x7FFE0000, &[]).unwrap();
        assert!(!shellcode.is_empty());
    }

    #[test]
    fn test_call_shellcode_four_args() {
        let asm = Assembler::x64();
        let shellcode = asm
            .generate_call_shellcode(0x7FFE0000, &[1, 2, 3, 4])
            .unwrap();
        assert!(!shellcode.is_empty());
    }

    #[test]
    fn test_nop_sled() {
        let asm = Assembler::x64();
        let sled = asm.generate_nop_sled(10);
        assert_eq!(sled.len(), 10);
        assert!(sled.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_int3_generation() {
        let asm = Assembler::x64();
        let breakpoint = asm.generate_int3();
        assert_eq!(breakpoint, vec![0xCC]);
    }

    // ========== Error Handling Tests ==========

    #[test]
    fn test_invalid_instruction() {
        let asm = Assembler::x64();
        let result = asm.assemble("invalidinstr rax", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_operand() {
        let asm = Assembler::x64();
        let result = asm.assemble("push", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex() {
        let asm = Assembler::x64();
        let result = asm.assemble("mov rax, 0xGGGG", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_input() {
        let asm = Assembler::x64();
        let result = asm.assemble("", 0).unwrap();
        assert!(result.bytes.is_empty());
        assert_eq!(result.instruction_count, 0);
    }

    #[test]
    fn test_only_comments() {
        let asm = Assembler::x64();
        let result = asm
            .assemble("# just a comment\n// another comment", 0)
            .unwrap();
        assert!(result.bytes.is_empty());
    }

    // ========== Mode Tests ==========

    #[test]
    fn test_x86_mode() {
        let asm = Assembler::x86();
        assert_eq!(asm.mode.bitness(), 32);
    }

    #[test]
    fn test_x64_mode() {
        let asm = Assembler::x64();
        assert_eq!(asm.mode.bitness(), 64);
    }

    #[test]
    fn test_default_mode() {
        let asm = Assembler::default();
        #[cfg(target_pointer_width = "64")]
        assert_eq!(asm.mode, AssemblerMode::X64);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(asm.mode, AssemblerMode::X86);
    }

    // ========== Address-dependent Assembly Tests ==========

    #[test]
    fn test_assemble_at_address() {
        let asm = Assembler::x64();
        let result = asm.assemble("nop", 0x140001000).unwrap();
        assert_eq!(result.address, 0x140001000);
    }

    // ========== Builder Pattern Tests ==========

    #[test]
    fn test_builder_pattern() {
        let asm = Assembler::x64();
        let result = asm
            .assemble_with_builder(0, |a| {
                a.xor(rax, rax)?;
                a.ret()?;
                Ok(())
            })
            .unwrap();
        assert_eq!(result.instruction_count, 2);
    }
}
