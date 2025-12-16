//! Decompilation tools - generates pseudo-C code from disassembly
//!
//! Provides Hex-Rays style decompilation output by analyzing x64 assembly
//! and generating human-readable pseudo-C code.
//!
//! # Limitations
//! - Best-effort pseudo-code generation (not production decompiler)
//! - Limited control flow analysis
//! - No type inference beyond basic patterns

use ghost_common::Instruction;
use ghost_mcp_common::ipc::SharedAgentClient;
use std::collections::HashMap;
use tracing::{debug, error, trace, warn};

use super::disasm::Disassembler;

/// Maximum function name length
const MAX_FUNC_NAME_LEN: usize = 64;
/// Maximum memory read for decompilation
const MAX_DECOMPILE_READ: usize = 16 * 1024; // 16KB
/// Minimum valid address
const MIN_VALID_ADDRESS: u64 = 0x1000;

/// Decompile handler for ghost-core-mcp
pub struct DecompileHandler;

impl DecompileHandler {
    /// Handle decompile tool call
    ///
    /// Generates pseudo-C code from disassembled instructions.
    ///
    /// # Arguments (from args)
    /// * `address` - Function start address (hex string or integer)
    /// * `name` - Function name for output (default: "sub")
    /// * `style` - Output style: "c", "simplified", or "verbose" (default: "c")
    pub async fn handle_decompile(
        agent: &SharedAgentClient,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let address = Self::parse_address(args)?;

        // Defensive: validate address
        if address < MIN_VALID_ADDRESS {
            warn!(target: "ghost_core_mcp::decompile", address = %format!("0x{:X}", address), "Suspicious low address");
            return Err(format!("Address 0x{:X} is suspiciously low", address));
        }

        // Defensive: sanitize and truncate function name
        let func_name = args.get("name").and_then(|v| v.as_str()).unwrap_or("sub");
        let func_name = if func_name.len() > MAX_FUNC_NAME_LEN {
            warn!(target: "ghost_core_mcp::decompile", len = func_name.len(), "Function name truncated");
            &func_name[..MAX_FUNC_NAME_LEN]
        } else {
            func_name
        };
        // Sanitize: only allow alphanumeric and underscore
        let func_name: String = func_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let func_name = if func_name.is_empty() {
            "sub".to_string()
        } else {
            func_name
        };

        let style = args.get("style").and_then(|v| v.as_str()).unwrap_or("c");

        // Validate style parameter
        if !["c", "simplified", "verbose"].contains(&style) {
            return Ok(serde_json::json!({
                "content": [{ "type": "text", "text": "Invalid style. Use 'c', 'simplified', or 'verbose'." }],
                "isError": true
            }));
        }

        debug!(target: "ghost_core_mcp::decompile",
            address = %format!("0x{:X}", address),
            func_name = %func_name,
            style = style,
            "decompile request"
        );

        // Read function bytes from agent
        let read_size = MAX_DECOMPILE_READ;
        let bytes = Self::read_memory(agent, address, read_size).await?;

        if bytes.is_empty() {
            return Ok(serde_json::json!({
                "content": [{ "type": "text", "text": "No bytes read from memory" }],
                "isError": true
            }));
        }

        // Disassemble using Capstone
        let disasm = Disassembler::new_x64().map_err(|e| format!("Capstone error: {}", e))?;
        let instructions = disasm.disassemble_function(&bytes, address);

        if instructions.is_empty() {
            return Ok(serde_json::json!({
                "content": [{ "type": "text", "text": format!("No valid instructions at 0x{:X}", address) }],
                "isError": true
            }));
        }

        trace!(target: "ghost_core_mcp::decompile",
            instructions = instructions.len(),
            "Generating pseudo-code"
        );

        // Generate pseudo-C code from instructions
        let pseudo_code = generate_pseudo_code(&instructions, &func_name, address, style);

        debug!(target: "ghost_core_mcp::decompile",
            instructions = instructions.len(),
            output_len = pseudo_code.len(),
            "decompile complete"
        );

        Ok(serde_json::json!({
            "content": [{ "type": "text", "text": pseudo_code }]
        }))
    }

    /// Parse address from arguments
    fn parse_address(args: &serde_json::Value) -> Result<u64, String> {
        if let Some(addr_str) = args.get("address").and_then(|v| v.as_str()) {
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
        let size = size.min(MAX_DECOMPILE_READ);
        if size == 0 {
            return Err("Read size cannot be zero".to_string());
        }

        trace!(target: "ghost_core_mcp::decompile",
            address = %format!("0x{:X}", address),
            size = size,
            "Reading memory for decompilation"
        );

        // Attempt connection if needed
        if !agent.is_connected() {
            debug!(target: "ghost_core_mcp::decompile", "Agent not connected, attempting connection");
            if let Err(e) = agent.connect().await {
                warn!(target: "ghost_core_mcp::decompile", error = %e, "Connection attempt failed");
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
                error!(target: "ghost_core_mcp::decompile", error = %e, "Memory read failed");
                format!("Memory read failed: {}", e)
            })?;

        let hex_str = result
            .as_str()
            .or_else(|| result.get("data").and_then(|d| d.as_str()))
            .or_else(|| result.get("bytes").and_then(|d| d.as_str()))
            .ok_or_else(|| {
                error!(target: "ghost_core_mcp::decompile", response = %result, "Unexpected response format");
                "Invalid memory response format".to_string()
            })?;

        let hex_clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();

        // Defensive: validate hex string (must be even length)
        if hex_clean.len() % 2 != 0 {
            return Err("Invalid hex string length (odd number of characters)".to_string());
        }

        hex::decode(&hex_clean).map_err(|e| {
            error!(target: "ghost_core_mcp::decompile", error = %e, "Hex decode failed");
            format!("Hex decode error: {}", e)
        })
    }
}

/// Generate pseudo-C code from disassembled instructions
pub fn generate_pseudo_code(
    instructions: &[Instruction],
    func_name: &str,
    base_addr: u64,
    style: &str,
) -> String {
    let mut output = String::new();
    let mut locals = LocalVariables::new();
    let mut control_flow = ControlFlowAnalyzer::new();

    // Analyze instructions for control flow
    control_flow.analyze(instructions);

    // Generate function signature
    let func_name_full = format!("{}_{:X}", func_name, base_addr);
    output.push_str(&format!("// Function at 0x{:X}\n", base_addr));

    if style == "verbose" {
        output.push_str("// Decompiled by Ghost-MCP\n");
        output.push_str(&format!(
            "// {} instructions analyzed\n",
            instructions.len()
        ));
        output.push('\n');
    }

    // Detect calling convention and parameters
    let (return_type, params) = analyze_function_signature(instructions);
    output.push_str(&format!(
        "{} {}({})\n{{\n",
        return_type, func_name_full, params
    ));

    // Generate local variable declarations
    locals.analyze(instructions);
    if !locals.vars.is_empty() {
        for (name, var_type) in &locals.vars {
            output.push_str(&format!("    {} {};\n", var_type, name));
        }
        output.push('\n');
    }

    // Generate pseudo-code body
    let body = generate_body(instructions, style, &control_flow, &locals);
    output.push_str(&body);

    output.push_str("}\n");

    output
}

/// Analyze function signature from prologue
fn analyze_function_signature(instructions: &[Instruction]) -> (String, String) {
    let mut params = Vec::new();
    let mut has_return = false;

    // Check for common x64 Windows calling convention (rcx, rdx, r8, r9)
    for insn in instructions.iter().take(20) {
        let ops = insn.operands.to_lowercase();

        // Look for parameter usage
        if (ops.contains("rcx") || ops.contains("ecx")) && !params.contains(&"arg1".to_string()) {
            params.push("arg1".to_string());
        }
        if (ops.contains("rdx") || ops.contains("edx")) && !params.contains(&"arg2".to_string()) {
            params.push("arg2".to_string());
        }
        if ops.contains("r8") && !params.contains(&"arg3".to_string()) {
            params.push("arg3".to_string());
        }
        if ops.contains("r9") && !params.contains(&"arg4".to_string()) {
            params.push("arg4".to_string());
        }

        // Check for return value
        if insn.mnemonic == "mov" && (ops.starts_with("eax") || ops.starts_with("rax")) {
            has_return = true;
        }
    }

    let return_type = if has_return { "int64_t" } else { "void" };
    let param_str = if params.is_empty() {
        "void".to_string()
    } else {
        params
            .iter()
            .map(|p| format!("int64_t {}", p))
            .collect::<Vec<_>>()
            .join(", ")
    };

    (return_type.to_string(), param_str)
}

/// Local variable tracker
struct LocalVariables {
    vars: HashMap<String, String>,
    stack_vars: HashMap<i64, String>,
}

impl LocalVariables {
    fn new() -> Self {
        Self {
            vars: HashMap::new(),
            stack_vars: HashMap::new(),
        }
    }

    fn analyze(&mut self, instructions: &[Instruction]) {
        let mut var_counter = 0;

        for insn in instructions {
            let ops = &insn.operands;

            // Detect stack variable access patterns: [rbp-XX] or [rsp+XX]
            if ops.contains("[rbp") || ops.contains("[rsp") {
                if let Some(offset) = extract_stack_offset(ops) {
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        self.stack_vars.entry(offset)
                    {
                        let var_name = format!("var_{:X}", var_counter);
                        var_counter += 1;
                        e.insert(var_name.clone());
                        self.vars.insert(var_name, "int64_t".to_string());
                    }
                }
            }
        }
    }
}

/// Extract stack offset from operand string
fn extract_stack_offset(operand: &str) -> Option<i64> {
    // Match patterns like [rbp-0x10] or [rsp+0x20]
    if let Some(start) = operand.find("[rbp") {
        let rest = &operand[start + 4..];
        if let Some(end) = rest.find(']') {
            let offset_str = &rest[..end];
            return parse_offset(offset_str);
        }
    }
    if let Some(start) = operand.find("[rsp") {
        let rest = &operand[start + 4..];
        if let Some(end) = rest.find(']') {
            let offset_str = &rest[..end];
            return parse_offset(offset_str);
        }
    }
    None
}

fn parse_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }

    let (sign, num_str) = if let Some(stripped) = s.strip_prefix('-') {
        (-1i64, stripped)
    } else if let Some(stripped) = s.strip_prefix('+') {
        (1i64, stripped)
    } else {
        (1i64, s)
    };

    let num_str = num_str.trim();
    let value = if let Some(hex_str) = num_str.strip_prefix("0x") {
        i64::from_str_radix(hex_str, 16).ok()?
    } else {
        num_str.parse().ok()?
    };

    Some(sign * value)
}

/// Control flow analyzer
struct ControlFlowAnalyzer {
    jumps: HashMap<usize, usize>,
    labels: HashMap<usize, String>,
    loop_starts: Vec<usize>,
    #[allow(dead_code)]
    if_targets: Vec<usize>,
}

impl ControlFlowAnalyzer {
    fn new() -> Self {
        Self {
            jumps: HashMap::new(),
            labels: HashMap::new(),
            loop_starts: Vec::new(),
            if_targets: Vec::new(),
        }
    }

    fn analyze(&mut self, instructions: &[Instruction]) {
        let mut label_counter = 0;

        for insn in instructions.iter() {
            let mnemonic = insn.mnemonic.to_lowercase();

            // Detect jumps
            if mnemonic.starts_with('j') {
                if let Some(target) = parse_jump_target(&insn.operands) {
                    self.jumps.insert(insn.address, target);

                    // Create label for target
                    if let std::collections::hash_map::Entry::Vacant(e) = self.labels.entry(target)
                    {
                        e.insert(format!("label_{}", label_counter));
                        label_counter += 1;
                    }

                    // Detect backward jumps (loops)
                    if target < insn.address {
                        self.loop_starts.push(target);
                    } else {
                        self.if_targets.push(target);
                    }
                }
            }
        }
    }

    fn get_label(&self, addr: usize) -> Option<&String> {
        self.labels.get(&addr)
    }

    fn is_loop_start(&self, addr: usize) -> bool {
        self.loop_starts.contains(&addr)
    }
}

fn parse_jump_target(operand: &str) -> Option<usize> {
    let operand = operand.trim();

    // Handle hex addresses like 0x1234
    if let Some(hex_str) = operand.strip_prefix("0x") {
        return usize::from_str_radix(hex_str, 16).ok();
    }

    // Handle plain decimal
    operand.parse().ok()
}

/// Generate the function body pseudo-code
fn generate_body(
    instructions: &[Instruction],
    style: &str,
    control_flow: &ControlFlowAnalyzer,
    locals: &LocalVariables,
) -> String {
    let mut output = String::new();
    let mut indent = 1;

    for insn in instructions {
        let addr = insn.address;

        // Add label if needed
        if let Some(label) = control_flow.get_label(addr) {
            output.push_str(&format!("{}:\n", label));
        }

        // Check for loop start
        if control_flow.is_loop_start(addr) && style != "simplified" {
            output.push_str(&format!(
                "{}while (/* condition */) {{\n",
                "    ".repeat(indent)
            ));
            indent += 1;
        }

        // Convert instruction to pseudo-C
        let pseudo = instruction_to_pseudo_c(insn, style, locals);
        if !pseudo.is_empty() {
            if style == "verbose" {
                output.push_str(&format!(
                    "{}/* 0x{:X}: {} {} */\n",
                    "    ".repeat(indent),
                    addr,
                    insn.mnemonic,
                    insn.operands
                ));
            }
            output.push_str(&format!("{}{}\n", "    ".repeat(indent), pseudo));
        }
    }

    output
}

/// Convert a single instruction to pseudo-C
fn instruction_to_pseudo_c(insn: &Instruction, style: &str, locals: &LocalVariables) -> String {
    let mnemonic = insn.mnemonic.to_lowercase();
    let operands = &insn.operands;

    // Replace stack references with variable names
    let operands = replace_stack_refs(operands, locals);

    match mnemonic.as_str() {
        // Data movement
        "mov" | "movzx" | "movsx" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!("{} = {};", clean_operand(parts[0]), clean_operand(parts[1]))
            } else {
                String::new()
            }
        }

        "lea" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "{} = &{};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        // Arithmetic
        "add" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "{} += {};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        "sub" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "{} -= {};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        "inc" => format!("{}++;", clean_operand(&operands)),
        "dec" => format!("{}--;", clean_operand(&operands)),

        "imul" | "mul" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                format!(
                    "{} *= {};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                format!("rax *= {};", clean_operand(&operands))
            }
        }

        "idiv" | "div" => format!("rax /= {};", clean_operand(&operands)),

        // Bitwise
        "and" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "{} &= {};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        "or" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "{} |= {};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        "xor" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                if parts[0] == parts[1] {
                    format!("{} = 0;", clean_operand(parts[0]))
                } else {
                    format!(
                        "{} ^= {};",
                        clean_operand(parts[0]),
                        clean_operand(parts[1])
                    )
                }
            } else {
                String::new()
            }
        }

        "shl" | "sal" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "{} <<= {};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        "shr" | "sar" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "{} >>= {};",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        "not" => format!(
            "{} = ~{};",
            clean_operand(&operands),
            clean_operand(&operands)
        ),
        "neg" => format!(
            "{} = -{};",
            clean_operand(&operands),
            clean_operand(&operands)
        ),

        // Comparisons
        "cmp" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "// compare {} with {}",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        "test" => {
            let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                format!(
                    "// test {} & {}",
                    clean_operand(parts[0]),
                    clean_operand(parts[1])
                )
            } else {
                String::new()
            }
        }

        // Control flow
        "jmp" => format!("goto {};", clean_operand(&operands)),
        "je" | "jz" => format!("if (/* == 0 */) goto {};", clean_operand(&operands)),
        "jne" | "jnz" => format!("if (/* != 0 */) goto {};", clean_operand(&operands)),
        "jg" | "jnle" => format!("if (/* > */) goto {};", clean_operand(&operands)),
        "jge" | "jnl" => format!("if (/* >= */) goto {};", clean_operand(&operands)),
        "jl" | "jnge" => format!("if (/* < */) goto {};", clean_operand(&operands)),
        "jle" | "jng" => format!("if (/* <= */) goto {};", clean_operand(&operands)),
        "ja" | "jnbe" => format!("if (/* unsigned > */) goto {};", clean_operand(&operands)),
        "jae" | "jnb" | "jnc" => {
            format!("if (/* unsigned >= */) goto {};", clean_operand(&operands))
        }
        "jb" | "jnae" | "jc" => format!("if (/* unsigned < */) goto {};", clean_operand(&operands)),
        "jbe" | "jna" => format!("if (/* unsigned <= */) goto {};", clean_operand(&operands)),

        // Function calls
        "call" => format!("{}();", clean_operand(&operands)),

        // Return
        "ret" | "retn" | "retf" => "return;".to_string(),

        // Stack operations
        "push" => {
            if style == "verbose" {
                format!("// push {}", clean_operand(&operands))
            } else {
                String::new()
            }
        }
        "pop" => {
            if style == "verbose" {
                format!("// pop {}", clean_operand(&operands))
            } else {
                String::new()
            }
        }

        // NOP
        "nop" => {
            if style == "verbose" {
                "// nop".to_string()
            } else {
                String::new()
            }
        }

        // Default - skip or show as comment
        _ => {
            if style == "verbose" {
                format!("// {} {}", mnemonic, operands)
            } else {
                String::new()
            }
        }
    }
}

/// Replace stack references with variable names
fn replace_stack_refs(operands: &str, locals: &LocalVariables) -> String {
    let mut result = operands.to_string();

    // Replace [rbp-XX] patterns
    for (offset, var_name) in &locals.stack_vars {
        let patterns = vec![
            format!("[rbp-0x{:x}]", offset.unsigned_abs()),
            format!("[rbp+0x{:x}]", offset.unsigned_abs()),
            format!("[rbp-{}]", offset.unsigned_abs()),
            format!("[rbp+{}]", offset.unsigned_abs()),
        ];

        for pattern in patterns {
            if result.contains(&pattern) {
                result = result.replace(&pattern, var_name);
            }
        }
    }

    result
}

/// Clean operand for pseudo-C output
fn clean_operand(operand: &str) -> String {
    let operand = operand.trim();

    // Handle memory references
    if let Some(rest) = operand.strip_prefix("qword ptr") {
        return format!("*(int64_t*)({})", rest.trim());
    }
    if let Some(rest) = operand.strip_prefix("dword ptr") {
        return format!("*(int32_t*)({})", rest.trim());
    }
    if let Some(rest) = operand.strip_prefix("word ptr") {
        return format!("*(int16_t*)({})", rest.trim());
    }
    if let Some(rest) = operand.strip_prefix("byte ptr") {
        return format!("*(int8_t*)({})", rest.trim());
    }

    // Handle brackets
    if let Some(inner) = operand.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return format!("*({})", inner);
    }

    operand.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_offset() {
        assert_eq!(parse_offset("-0x10"), Some(-16));
        assert_eq!(parse_offset("+0x20"), Some(32));
        assert_eq!(parse_offset(""), Some(0));
    }

    #[test]
    fn test_clean_operand() {
        assert_eq!(clean_operand("rax"), "rax");
        assert_eq!(
            clean_operand("qword ptr [rbp-0x10]"),
            "*(int64_t*)([rbp-0x10])"
        );
    }

    #[test]
    fn test_empty_instructions() {
        let result = generate_pseudo_code(&[], "test", 0x1000, "c");
        assert!(result.contains("test_1000"));
        assert!(result.contains("void"));
    }

    #[test]
    fn test_simple_mov() {
        let insns = vec![Instruction {
            address: 0x1000,
            bytes: vec![0x48, 0x89, 0xC8],
            mnemonic: "mov".to_string(),
            operands: "rax, rcx".to_string(),
        }];
        let result = generate_pseudo_code(&insns, "func", 0x1000, "c");
        assert!(result.contains("rax = rcx;"));
    }
}
