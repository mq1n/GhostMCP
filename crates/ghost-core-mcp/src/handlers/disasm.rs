//! Disassembly tools using Capstone
//!
//! Provides local disassembly capabilities for disasm_at and disasm_function tools.
//!
//! # Architecture
//! - Memory is read from agent via IPC
//! - Disassembly is performed locally using Capstone
//! - Results are formatted and returned to the MCP client
//!
//! # Defensive Programming
//! - Input validation for addresses and counts
//! - Size limits to prevent memory exhaustion
//! - Graceful error handling with informative messages

use capstone::prelude::*;
use ghost_common::Instruction;
use ghost_mcp_common::ipc::SharedAgentClient;
use tracing::{debug, error, trace, warn};

/// Maximum number of instructions to disassemble
const MAX_INSTRUCTION_COUNT: usize = 1000;
/// Maximum memory read size in bytes
const MAX_READ_SIZE: usize = 64 * 1024; // 64KB
/// Minimum valid address (to catch null/low addresses)
const MIN_VALID_ADDRESS: u64 = 0x1000;

/// Disassembler wrapper for x64/x86 code
pub struct Disassembler {
    cs: Capstone,
}

impl Disassembler {
    /// Create a new x64 disassembler
    pub fn new_x64() -> Result<Self, capstone::Error> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?;
        Ok(Self { cs })
    }

    /// Create a new x86 (32-bit) disassembler
    #[allow(dead_code)]
    pub fn new_x86() -> Result<Self, capstone::Error> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()?;
        Ok(Self { cs })
    }

    /// Disassemble bytes at a given address
    ///
    /// # Arguments
    /// * `bytes` - Raw bytes to disassemble
    /// * `address` - Virtual address of first byte
    /// * `count` - Maximum instructions to disassemble
    ///
    /// # Returns
    /// Vector of disassembled instructions (may be empty on error)
    pub fn disassemble(&self, bytes: &[u8], address: u64, count: usize) -> Vec<Instruction> {
        // Defensive: clamp count
        let count = count.min(MAX_INSTRUCTION_COUNT);

        if bytes.is_empty() {
            warn!(target: "ghost_core_mcp::disasm", "Empty byte buffer for disassembly");
            return Vec::new();
        }

        let mut instructions = Vec::new();

        match self.cs.disasm_count(bytes, address, count) {
            Ok(insns) => {
                trace!(target: "ghost_core_mcp::disasm",
                    address = %format!("0x{:X}", address),
                    requested = count,
                    actual = insns.len(),
                    "Disassembly complete"
                );
                for insn in insns.iter() {
                    instructions.push(Instruction {
                        address: insn.address() as usize,
                        bytes: insn.bytes().to_vec(),
                        mnemonic: insn.mnemonic().unwrap_or("???").to_string(),
                        operands: insn.op_str().unwrap_or("").to_string(),
                    });
                }
            }
            Err(e) => {
                warn!(target: "ghost_core_mcp::disasm",
                    error = %e,
                    address = %format!("0x{:X}", address),
                    "Disassembly failed"
                );
            }
        }

        instructions
    }

    /// Disassemble a function (until RET or max instructions)
    ///
    /// Continues disassembly until a return instruction is found or
    /// the maximum instruction count is reached.
    pub fn disassemble_function(&self, bytes: &[u8], address: u64) -> Vec<Instruction> {
        if bytes.is_empty() {
            warn!(target: "ghost_core_mcp::disasm", "Empty byte buffer for function disassembly");
            return Vec::new();
        }

        let mut instructions = Vec::new();

        match self.cs.disasm_all(bytes, address) {
            Ok(insns) => {
                for insn in insns.iter().take(MAX_INSTRUCTION_COUNT) {
                    let mnemonic = insn.mnemonic().unwrap_or("???");

                    instructions.push(Instruction {
                        address: insn.address() as usize,
                        bytes: insn.bytes().to_vec(),
                        mnemonic: mnemonic.to_string(),
                        operands: insn.op_str().unwrap_or("").to_string(),
                    });

                    // Stop at RET instruction
                    if mnemonic.eq_ignore_ascii_case("ret")
                        || mnemonic.eq_ignore_ascii_case("retn")
                        || mnemonic.eq_ignore_ascii_case("retf")
                    {
                        trace!(target: "ghost_core_mcp::disasm",
                            instructions = instructions.len(),
                            "Function disassembly complete (found RET)"
                        );
                        break;
                    }
                }

                if instructions.len() == MAX_INSTRUCTION_COUNT {
                    warn!(target: "ghost_core_mcp::disasm",
                        max = MAX_INSTRUCTION_COUNT,
                        "Function disassembly hit instruction limit"
                    );
                }
            }
            Err(e) => {
                error!(target: "ghost_core_mcp::disasm",
                    error = %e,
                    address = %format!("0x{:X}", address),
                    "Function disassembly failed"
                );
            }
        }

        instructions
    }
}

/// Format instructions for display
pub fn format_instructions(instructions: &[Instruction]) -> String {
    let mut output = String::new();

    for insn in instructions {
        let bytes_hex: String = insn
            .bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        output.push_str(&format!(
            "0x{:016X}  {:24}  {} {}\n",
            insn.address, bytes_hex, insn.mnemonic, insn.operands
        ));
    }

    output
}

/// Disassembly handler for ghost-core-mcp
pub struct DisasmHandler;

impl DisasmHandler {
    /// Handle disasm_at tool call
    ///
    /// Disassembles N instructions at the specified address.
    ///
    /// # Arguments (from args)
    /// * `address` - Memory address (hex string or integer)
    /// * `count` - Number of instructions (default: 20, max: 100)
    /// * `arch` - Architecture: "x64" or "x86" (default: x64)
    pub async fn handle_disasm_at(
        agent: &SharedAgentClient,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let address = Self::parse_address(args)?;

        // Defensive: validate address is in reasonable range
        if address < MIN_VALID_ADDRESS {
            warn!(target: "ghost_core_mcp::disasm", address = %format!("0x{:X}", address), "Suspicious low address");
            return Err(format!(
                "Address 0x{:X} is suspiciously low (< 0x{:X})",
                address, MIN_VALID_ADDRESS
            ));
        }

        // Defensive: clamp count to safe range
        let count = args
            .get("count")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(100) as usize;
        let arch = args.get("arch").and_then(|v| v.as_str()).unwrap_or("x64");

        // Validate arch parameter
        if arch != "x64" && arch != "x86" {
            return Err(format!(
                "Invalid architecture '{}'. Use 'x64' or 'x86'",
                arch
            ));
        }

        debug!(target: "ghost_core_mcp::disasm",
            address = %format!("0x{:X}", address),
            count = count,
            arch = arch,
            "disasm_at request"
        );

        // Calculate read size (~15 bytes per instruction max for x64)
        let read_size = (count * 15).min(MAX_READ_SIZE);

        // Read memory from agent
        let bytes = Self::read_memory(agent, address, read_size).await?;

        if bytes.is_empty() {
            return Ok(serde_json::json!({
                "content": [{ "type": "text", "text": "No bytes read from memory" }],
                "isError": true
            }));
        }

        // Create disassembler
        let disasm = if arch == "x86" {
            Disassembler::new_x86().map_err(|e| format!("Capstone error: {}", e))?
        } else {
            Disassembler::new_x64().map_err(|e| format!("Capstone error: {}", e))?
        };

        // Disassemble
        let instructions = disasm.disassemble(&bytes, address, count);

        if instructions.is_empty() {
            return Ok(serde_json::json!({
                "content": [{ "type": "text", "text": format!("No valid instructions at 0x{:X}", address) }],
                "isError": true
            }));
        }

        let output = format_instructions(&instructions);
        debug!(target: "ghost_core_mcp::disasm",
            instructions = instructions.len(),
            "disasm_at complete"
        );

        Ok(serde_json::json!({
            "content": [{ "type": "text", "text": output }]
        }))
    }

    /// Handle disasm_function tool call
    ///
    /// Disassembles an entire function starting at the specified address.
    /// Continues until a RET instruction or max instruction limit.
    ///
    /// # Arguments (from args)
    /// * `address` - Function start address (hex string or integer)
    /// * `max_instructions` - Maximum instructions (default: 500)
    pub async fn handle_disasm_function(
        agent: &SharedAgentClient,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let address = Self::parse_address(args)?;

        // Defensive: validate address
        if address < MIN_VALID_ADDRESS {
            warn!(target: "ghost_core_mcp::disasm", address = %format!("0x{:X}", address), "Suspicious low address");
            return Err(format!("Address 0x{:X} is suspiciously low", address));
        }

        let max_instructions = args
            .get("max_instructions")
            .and_then(|v| v.as_u64())
            .unwrap_or(500)
            .min(MAX_INSTRUCTION_COUNT as u64) as usize;

        debug!(target: "ghost_core_mcp::disasm",
            address = %format!("0x{:X}", address),
            max_instructions = max_instructions,
            "disasm_function request"
        );

        // Read more memory for function disassembly (capped at MAX_READ_SIZE)
        let read_size = (max_instructions * 15).min(MAX_READ_SIZE);
        let bytes = Self::read_memory(agent, address, read_size).await?;

        if bytes.is_empty() {
            return Ok(serde_json::json!({
                "content": [{ "type": "text", "text": "No bytes read from memory" }],
                "isError": true
            }));
        }

        // Create x64 disassembler
        let disasm = Disassembler::new_x64().map_err(|e| format!("Capstone error: {}", e))?;

        // Disassemble function
        let instructions = disasm.disassemble_function(&bytes, address);

        if instructions.is_empty() {
            return Ok(serde_json::json!({
                "content": [{ "type": "text", "text": format!("No valid instructions at 0x{:X}", address) }],
                "isError": true
            }));
        }

        let output = format_instructions(&instructions);
        debug!(target: "ghost_core_mcp::disasm",
            instructions = instructions.len(),
            "disasm_function complete"
        );

        Ok(serde_json::json!({
            "content": [{ "type": "text", "text": output }]
        }))
    }

    /// Parse address from arguments (supports hex strings and integers)
    fn parse_address(args: &serde_json::Value) -> Result<u64, String> {
        if let Some(addr_str) = args.get("address").and_then(|v| v.as_str()) {
            // Parse hex string (with or without 0x prefix)
            let addr_str = addr_str
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X");
            u64::from_str_radix(addr_str, 16)
                .map_err(|_| format!("Invalid address format: {}", addr_str))
        } else if let Some(addr) = args.get("address").and_then(|v| v.as_u64()) {
            Ok(addr)
        } else {
            Err("Missing address parameter".to_string())
        }
    }

    /// Read memory from agent
    ///
    /// Handles connection management and response parsing.
    #[allow(clippy::manual_is_multiple_of)]
    async fn read_memory(
        agent: &SharedAgentClient,
        address: u64,
        size: usize,
    ) -> Result<Vec<u8>, String> {
        // Defensive: validate size
        let size = size.min(MAX_READ_SIZE);
        if size == 0 {
            return Err("Read size cannot be zero".to_string());
        }

        trace!(target: "ghost_core_mcp::disasm",
            address = %format!("0x{:X}", address),
            size = size,
            "Reading memory from agent"
        );

        // Attempt connection if needed
        if !agent.is_connected() {
            debug!(target: "ghost_core_mcp::disasm", "Agent not connected, attempting connection");
            if let Err(e) = agent.connect().await {
                warn!(target: "ghost_core_mcp::disasm", error = %e, "Connection attempt failed");
            }
        }

        if !agent.is_connected() {
            return Err("Agent not connected. Ensure target process is attached.".to_string());
        }

        let result = agent
            .request(
                "memory_read",
                serde_json::json!({
                    "address": format!("0x{:X}", address),
                    "size": size,
                    "format": "hex"
                }),
            )
            .await
            .map_err(|e| {
                error!(target: "ghost_core_mcp::disasm", error = %e, "Memory read IPC failed");
                format!("Memory read failed: {}", e)
            })?;

        // Check if agent returned an error response
        if let Some(code) = result.get("code").and_then(|c| c.as_i64()) {
            let message = result
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            warn!(target: "ghost_core_mcp::disasm",
                code = code,
                message = %message,
                address = %format!("0x{:X}", address),
                "Agent returned error for memory read"
            );
            return Err(format!("Memory read error: {}", message));
        }

        // Decode hex bytes from agent response (handle multiple formats)
        let hex_str = result
            .as_str()
            .or_else(|| result.get("data").and_then(|d| d.as_str()))
            .or_else(|| result.get("bytes").and_then(|d| d.as_str()))
            .ok_or_else(|| {
                error!(target: "ghost_core_mcp::disasm", response = %result, "Unexpected memory response format");
                "Invalid memory response format".to_string()
            })?;

        // Remove any whitespace from hex string
        let hex_clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();

        // Defensive: validate hex string length (must be even)
        if hex_clean.len() % 2 != 0 {
            return Err("Invalid hex string length (odd number of characters)".to_string());
        }

        hex::decode(&hex_clean).map_err(|e| {
            error!(target: "ghost_core_mcp::disasm", error = %e, "Hex decode failed");
            format!("Hex decode error: {}", e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembler_creation() {
        let disasm = Disassembler::new_x64();
        assert!(disasm.is_ok());
    }

    #[test]
    fn test_disassemble_nops() {
        let disasm = Disassembler::new_x64().unwrap();
        let nops = vec![0x90, 0x90, 0x90]; // NOP NOP NOP
        let instructions = disasm.disassemble(&nops, 0x1000, 3);

        assert_eq!(instructions.len(), 3);
        for insn in &instructions {
            assert_eq!(insn.mnemonic, "nop");
        }
    }

    #[test]
    fn test_format_instructions() {
        let instructions = vec![Instruction {
            address: 0x1000,
            bytes: vec![0x90],
            mnemonic: "nop".to_string(),
            operands: "".to_string(),
        }];
        let output = format_instructions(&instructions);
        assert!(output.contains("0x0000000000001000"));
        assert!(output.contains("nop"));
    }

    #[test]
    fn test_parse_address_hex_string() {
        let args = serde_json::json!({"address": "0x7FF6A0000000"});
        let addr = DisasmHandler::parse_address(&args).unwrap();
        assert_eq!(addr, 0x7FF6A0000000);
    }

    #[test]
    fn test_parse_address_integer() {
        let args = serde_json::json!({"address": 4096});
        let addr = DisasmHandler::parse_address(&args).unwrap();
        assert_eq!(addr, 4096);
    }
}
