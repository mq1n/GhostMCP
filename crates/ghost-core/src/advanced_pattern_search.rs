//! Advanced Pattern Matching
//!
//! Instruction sequence search, operand search, immediate value search,
//! and unified advanced search capabilities.
//!
//! # Features
//! - `find.instructions` : Find instruction sequence(s) in code
//! - `find.operands` : Find instructions with specific operand values
//! - `find.immediates` : Search for immediate values in code/data
//! - `search.advanced` : Unified search with cursor pagination

use ghost_common::types::{
    AddressRange, AdvancedSearchId, AdvancedSearchRequest, AdvancedSearchResult,
    AdvancedSearchType, DataPatternMatch, FindImmediatesRequest, FindInstructionsRequest,
    FindOperandsRequest, ImmediateMatch, ImmediateMatchType, ImmediatePattern,
    ImmediateSearchScope, ImmediateSearchValue, InstructionPattern, InstructionSequenceMatch,
    MatchedInstruction, OperandMatch, OperandPattern, RegisterType, SearchCursor, SearchResultItem,
    SearchStats, StringMatch, StringSearchEncoding, XrefMatch, XrefSearchType, XrefType,
};
use ghost_common::{Error, Instruction, MemoryRegion, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, trace};

/// Maximum instructions to scan in one search
#[allow(dead_code)]
const MAX_INSTRUCTIONS_PER_SEARCH: usize = 1_000_000;
/// Maximum results to return
const MAX_RESULTS: usize = 10_000;
/// Default page size for paginated results
#[allow(dead_code)]
const DEFAULT_PAGE_SIZE: usize = 100;

/// Advanced Pattern Search Engine
pub struct AdvancedPatternSearch {
    /// Next search ID
    next_search_id: AtomicU32,
    /// Active searches (for pagination)
    #[allow(dead_code)]
    active_searches: RwLock<HashMap<AdvancedSearchId, ActiveSearch>>,
    /// Cancel flag
    cancel_flag: Arc<AtomicBool>,
}

/// An active search session (for pagination)
#[allow(dead_code)]
struct ActiveSearch {
    /// Search request
    request: AdvancedSearchRequest,
    /// Cached results
    results: Vec<SearchResultItem>,
    /// Current offset
    offset: usize,
    /// Statistics
    stats: SearchStats,
    /// Creation time
    created: Instant,
}

impl Default for AdvancedPatternSearch {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvancedPatternSearch {
    pub fn new() -> Self {
        Self {
            next_search_id: AtomicU32::new(1),
            active_searches: RwLock::new(HashMap::new()),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get cancel flag for external cancellation
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel_flag.clone()
    }

    /// Cancel current search
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }

    /// Reset cancel flag
    pub fn reset_cancel(&self) {
        self.cancel_flag.store(false, Ordering::SeqCst);
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::SeqCst)
    }

    // ========================================================================
    // Instruction Sequence Search (find.instructions)
    // ========================================================================

    /// Find instruction sequences matching the given patterns
    ///
    /// # Arguments
    /// * `request` - Search request with patterns and constraints
    /// * `disasm_fn` - Function to disassemble memory at an address
    /// * `regions` - Memory regions to search
    /// * `get_module` - Function to get module name for an address
    pub fn find_instructions<F, G>(
        &self,
        request: &FindInstructionsRequest,
        disasm_fn: F,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<Vec<InstructionSequenceMatch>>
    where
        F: Fn(usize, usize) -> Result<Vec<Instruction>>,
        G: Fn(usize) -> Option<(String, u64)>,
    {
        self.reset_cancel();
        let start_time = Instant::now();

        if request.patterns.is_empty() {
            return Err(Error::Internal("No patterns specified".into()));
        }

        let mut results = Vec::new();
        let mut instructions_checked = 0u64;

        // Filter regions to search
        let search_regions: Vec<_> = regions
            .iter()
            .filter(|r| {
                // Only executable regions
                if !r.protection.execute {
                    return false;
                }
                // Apply address range filter
                if let Some(range) = &request.address_range {
                    let region_end = r.base + r.size;
                    if r.base >= range.end as usize || region_end <= range.start as usize {
                        return false;
                    }
                }
                // Apply module filter
                if let Some(ref module) = request.module {
                    if let Some((mod_name, _)) = get_module(r.base) {
                        if !mod_name.to_lowercase().contains(&module.to_lowercase()) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .collect();

        debug!(
            "Searching {} executable regions for instruction sequence",
            search_regions.len()
        );

        for region in search_regions {
            if self.is_cancelled() {
                break;
            }

            let region_start = if let Some(range) = &request.address_range {
                region.base.max(range.start as usize)
            } else {
                region.base
            };
            let region_end = if let Some(range) = &request.address_range {
                (region.base + region.size).min(range.end as usize)
            } else {
                region.base + region.size
            };

            // Disassemble the region
            let size = region_end.saturating_sub(region_start);
            if size == 0 {
                continue;
            }

            match disasm_fn(region_start, size.min(0x100000)) {
                Ok(instructions) => {
                    instructions_checked += instructions.len() as u64;

                    // Search for pattern matches
                    let matches =
                        self.find_pattern_in_instructions(&request.patterns, &instructions);

                    for matched_instructions in matches {
                        if results.len() >= request.max_results {
                            break;
                        }

                        let addr = matched_instructions[0].address;
                        let (module, offset) = get_module(addr as usize)
                            .map(|(m, o)| (Some(m), o))
                            .unwrap_or((None, addr));

                        results.push(InstructionSequenceMatch {
                            address: addr,
                            instructions: matched_instructions,
                            module,
                            function: None, // Would need symbol resolution
                            module_offset: offset,
                        });
                    }
                }
                Err(e) => {
                    trace!("Failed to disassemble region at {:#x}: {}", region_start, e);
                }
            }

            if results.len() >= request.max_results {
                break;
            }
        }

        info!(
            "Instruction search complete: {} results, {} instructions checked in {:?}",
            results.len(),
            instructions_checked,
            start_time.elapsed()
        );

        Ok(results)
    }

    /// Find pattern matches within a list of instructions
    fn find_pattern_in_instructions(
        &self,
        patterns: &[InstructionPattern],
        instructions: &[Instruction],
    ) -> Vec<Vec<MatchedInstruction>> {
        let mut results = Vec::new();

        for i in 0..instructions.len() {
            if let Some(matched) = self.try_match_sequence(patterns, instructions, i) {
                results.push(matched);
            }
        }

        results
    }

    /// Try to match a pattern sequence starting at the given index
    fn try_match_sequence(
        &self,
        patterns: &[InstructionPattern],
        instructions: &[Instruction],
        start_idx: usize,
    ) -> Option<Vec<MatchedInstruction>> {
        let mut matched = Vec::new();
        let mut inst_idx = start_idx;
        let mut pattern_idx = 0;

        while pattern_idx < patterns.len() && inst_idx < instructions.len() {
            let pattern = &patterns[pattern_idx];
            let instruction = &instructions[inst_idx];

            // Check max gap constraint
            if pattern_idx > 0 {
                if let Some(max_gap) = pattern.max_gap {
                    let gap = inst_idx - (start_idx + matched.len());
                    if gap > max_gap {
                        if pattern.optional {
                            pattern_idx += 1;
                            continue;
                        }
                        return None;
                    }
                }
            }

            if self.instruction_matches_pattern(instruction, pattern) {
                matched.push(MatchedInstruction {
                    address: instruction.address as u64,
                    bytes: instruction.bytes.clone(),
                    mnemonic: instruction.mnemonic.clone(),
                    operands: instruction.operands.clone(),
                    pattern_index: pattern_idx,
                });
                pattern_idx += 1;
            } else if pattern.optional {
                pattern_idx += 1;
                continue;
            } else if pattern.max_gap.is_some() {
                // Allow gap - continue to next instruction
            } else {
                return None;
            }

            inst_idx += 1;
        }

        // Check if all non-optional patterns were matched
        while pattern_idx < patterns.len() {
            if !patterns[pattern_idx].optional {
                return None;
            }
            pattern_idx += 1;
        }

        if matched.is_empty() {
            None
        } else {
            Some(matched)
        }
    }

    /// Check if an instruction matches a pattern
    fn instruction_matches_pattern(
        &self,
        instruction: &Instruction,
        pattern: &InstructionPattern,
    ) -> bool {
        // Match mnemonic
        if pattern.mnemonic != "*" && !instruction.mnemonic.eq_ignore_ascii_case(&pattern.mnemonic)
        {
            return false;
        }

        // Match operands if specified
        if !pattern.operands.is_empty() {
            let operand_parts: Vec<&str> = instruction.operands.split(',').collect();

            for (i, op_pattern) in pattern.operands.iter().enumerate() {
                let operand = operand_parts.get(i).map(|s| s.trim()).unwrap_or("");

                if !self.operand_matches_pattern(operand, op_pattern) {
                    return false;
                }
            }
        }

        true
    }

    /// Check if an operand matches a pattern
    fn operand_matches_pattern(&self, operand: &str, pattern: &OperandPattern) -> bool {
        match pattern {
            OperandPattern::Any => true,
            OperandPattern::Register(reg) => operand.eq_ignore_ascii_case(reg),
            OperandPattern::RegisterType(reg_type) => self.is_register_of_type(operand, *reg_type),
            OperandPattern::Immediate(imm_pattern) => {
                self.operand_matches_immediate(operand, imm_pattern)
            }
            OperandPattern::Memory(_mem_pattern) => {
                // Memory operands contain brackets
                operand.contains('[')
            }
            OperandPattern::Exact(exact) => operand == exact,
            OperandPattern::Contains(substr) => {
                operand.to_lowercase().contains(&substr.to_lowercase())
            }
            OperandPattern::Regex(regex_str) => {
                if let Ok(re) = regex::Regex::new(regex_str) {
                    re.is_match(operand)
                } else {
                    false
                }
            }
        }
    }

    /// Check if operand is a register of the given type
    fn is_register_of_type(&self, operand: &str, reg_type: RegisterType) -> bool {
        let op = operand.to_lowercase();
        match reg_type {
            RegisterType::GeneralPurpose => {
                matches!(
                    op.as_str(),
                    "rax"
                        | "rbx"
                        | "rcx"
                        | "rdx"
                        | "rsi"
                        | "rdi"
                        | "rbp"
                        | "rsp"
                        | "r8"
                        | "r9"
                        | "r10"
                        | "r11"
                        | "r12"
                        | "r13"
                        | "r14"
                        | "r15"
                )
            }
            RegisterType::GeneralPurpose32 => {
                matches!(
                    op.as_str(),
                    "eax"
                        | "ebx"
                        | "ecx"
                        | "edx"
                        | "esi"
                        | "edi"
                        | "ebp"
                        | "esp"
                        | "r8d"
                        | "r9d"
                        | "r10d"
                        | "r11d"
                        | "r12d"
                        | "r13d"
                        | "r14d"
                        | "r15d"
                )
            }
            RegisterType::GeneralPurpose16 => {
                matches!(
                    op.as_str(),
                    "ax" | "bx"
                        | "cx"
                        | "dx"
                        | "si"
                        | "di"
                        | "bp"
                        | "sp"
                        | "r8w"
                        | "r9w"
                        | "r10w"
                        | "r11w"
                        | "r12w"
                        | "r13w"
                        | "r14w"
                        | "r15w"
                )
            }
            RegisterType::GeneralPurpose8 => {
                matches!(
                    op.as_str(),
                    "al" | "ah"
                        | "bl"
                        | "bh"
                        | "cl"
                        | "ch"
                        | "dl"
                        | "dh"
                        | "sil"
                        | "dil"
                        | "bpl"
                        | "spl"
                        | "r8b"
                        | "r9b"
                        | "r10b"
                        | "r11b"
                        | "r12b"
                        | "r13b"
                        | "r14b"
                        | "r15b"
                )
            }
            RegisterType::Xmm => op.starts_with("xmm"),
            RegisterType::Ymm => op.starts_with("ymm"),
            RegisterType::Zmm => op.starts_with("zmm"),
            RegisterType::Segment => {
                matches!(op.as_str(), "cs" | "ds" | "es" | "fs" | "gs" | "ss")
            }
            RegisterType::Control => op.starts_with("cr"),
            RegisterType::Debug => op.starts_with("dr"),
        }
    }

    /// Check if operand matches an immediate pattern
    fn operand_matches_immediate(&self, operand: &str, pattern: &ImmediatePattern) -> bool {
        // Try to parse the operand as a number
        let value = if operand.starts_with("0x") || operand.starts_with("0X") {
            i64::from_str_radix(&operand[2..], 16).ok()
        } else if operand.starts_with('-') {
            operand.parse::<i64>().ok()
        } else {
            operand
                .parse::<i64>()
                .ok()
                .or_else(|| u64::from_str_radix(operand, 16).ok().map(|v| v as i64))
        };

        let Some(value) = value else {
            return false;
        };

        match pattern {
            ImmediatePattern::Exact(expected) => value == *expected,
            ImmediatePattern::Range { min, max } => value >= *min && value <= *max,
            ImmediatePattern::Any => true,
            ImmediatePattern::HasBits(bits) => (value as u64 & bits) == *bits,
            ImmediatePattern::ClearBits(bits) => (value as u64 & bits) == 0,
            ImmediatePattern::Aligned(align) => *align > 0 && (value as u64) % *align == 0,
        }
    }

    // ========================================================================
    // Operand Search (find.operands)
    // ========================================================================

    /// Find instructions with specific operand values
    pub fn find_operands<F, G>(
        &self,
        request: &FindOperandsRequest,
        disasm_fn: F,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<Vec<OperandMatch>>
    where
        F: Fn(usize, usize) -> Result<Vec<Instruction>>,
        G: Fn(usize) -> Option<(String, u64)>,
    {
        self.reset_cancel();
        let start_time = Instant::now();

        let mut results = Vec::new();

        // Filter to executable regions
        let search_regions: Vec<_> = regions
            .iter()
            .filter(|r| {
                if !r.protection.execute {
                    return false;
                }
                if let Some(range) = &request.address_range {
                    let region_end = r.base + r.size;
                    if r.base >= range.end as usize || region_end <= range.start as usize {
                        return false;
                    }
                }
                if let Some(ref module) = request.module {
                    if let Some((mod_name, _)) = get_module(r.base) {
                        if !mod_name.to_lowercase().contains(&module.to_lowercase()) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .collect();

        for region in search_regions {
            if self.is_cancelled() || results.len() >= request.max_results {
                break;
            }

            let size = region.size.min(0x100000);
            match disasm_fn(region.base, size) {
                Ok(instructions) => {
                    for instruction in instructions {
                        if self.is_cancelled() || results.len() >= request.max_results {
                            break;
                        }

                        // Check mnemonic filter
                        if let Some(ref mnemonic) = request.mnemonic {
                            if !instruction.mnemonic.eq_ignore_ascii_case(mnemonic) {
                                continue;
                            }
                        }

                        // Check operands
                        let operand_parts: Vec<&str> =
                            instruction.operands.split(',').map(|s| s.trim()).collect();

                        for (i, operand) in operand_parts.iter().enumerate() {
                            // Check operand index filter
                            if let Some(idx) = request.operand_index {
                                if i != idx {
                                    continue;
                                }
                            }

                            if self.operand_matches_pattern(operand, &request.operand) {
                                let (module, offset) = get_module(instruction.address)
                                    .map(|(m, o)| (Some(m), o))
                                    .unwrap_or((None, instruction.address as u64));

                                results.push(OperandMatch {
                                    address: instruction.address as u64,
                                    bytes: instruction.bytes.clone(),
                                    mnemonic: instruction.mnemonic.clone(),
                                    operands: instruction.operands.clone(),
                                    matched_operand_index: i,
                                    matched_operand: operand.to_string(),
                                    module,
                                    module_offset: offset,
                                });
                                break; // Only one match per instruction
                            }
                        }
                    }
                }
                Err(e) => {
                    trace!("Failed to disassemble region at {:#x}: {}", region.base, e);
                }
            }
        }

        info!(
            "Operand search complete: {} results in {:?}",
            results.len(),
            start_time.elapsed()
        );

        Ok(results)
    }

    // ========================================================================
    // Immediate Value Search (find.immediates)
    // ========================================================================

    /// Search for immediate values in code or data
    pub fn find_immediates<F, R, G>(
        &self,
        request: &FindImmediatesRequest,
        disasm_fn: F,
        read_fn: R,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<Vec<ImmediateMatch>>
    where
        F: Fn(usize, usize) -> Result<Vec<Instruction>>,
        R: Fn(usize, usize) -> Result<Vec<u8>>,
        G: Fn(usize) -> Option<(String, u64)>,
    {
        self.reset_cancel();
        let start_time = Instant::now();

        let mut results = Vec::new();

        let search_code = matches!(
            request.search_in,
            ImmediateSearchScope::CodeOnly | ImmediateSearchScope::Both
        );
        let search_data = matches!(
            request.search_in,
            ImmediateSearchScope::DataOnly | ImmediateSearchScope::Both
        );

        for region in regions {
            if self.is_cancelled() || results.len() >= request.max_results {
                break;
            }

            // Apply address range filter
            if let Some(range) = &request.address_range {
                let region_end = region.base + region.size;
                if region.base >= range.end as usize || region_end <= range.start as usize {
                    continue;
                }
            }

            // Apply module filter
            if let Some(ref module) = request.module {
                if let Some((mod_name, _)) = get_module(region.base) {
                    if !mod_name.to_lowercase().contains(&module.to_lowercase()) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // Search in code (instruction immediates)
            if search_code && region.protection.execute {
                let size = region.size.min(0x100000);
                if let Ok(instructions) = disasm_fn(region.base, size) {
                    for instruction in instructions {
                        if results.len() >= request.max_results {
                            break;
                        }

                        // Check for immediate values in the operands
                        if let Some(imm_match) =
                            self.find_immediate_in_instruction(&instruction, &request.value)
                        {
                            let (module, offset) = get_module(instruction.address)
                                .map(|(m, o)| (Some(m), o))
                                .unwrap_or((None, instruction.address as u64));

                            results.push(ImmediateMatch {
                                address: instruction.address as u64,
                                value: imm_match.0,
                                size: imm_match.1,
                                match_type: imm_match.2,
                                context: format!(
                                    "{} {}",
                                    instruction.mnemonic, instruction.operands
                                ),
                                module,
                                module_offset: offset,
                            });
                        }
                    }
                }
            }

            // Search in data
            if search_data && !region.protection.execute && region.protection.read {
                if let Ok(data) = read_fn(region.base, region.size.min(0x100000)) {
                    self.find_immediates_in_data(
                        &data,
                        region.base,
                        &request.value,
                        request.alignment,
                        &get_module,
                        &mut results,
                        request.max_results,
                    );
                }
            }
        }

        info!(
            "Immediate search complete: {} results in {:?}",
            results.len(),
            start_time.elapsed()
        );

        Ok(results)
    }

    /// Find immediate value in an instruction's operands
    fn find_immediate_in_instruction(
        &self,
        instruction: &Instruction,
        search_value: &ImmediateSearchValue,
    ) -> Option<(i64, u8, ImmediateMatchType)> {
        // Parse operands looking for immediate values
        for operand in instruction.operands.split(',') {
            let operand = operand.trim();

            // Check for displacement in memory operands
            if operand.contains('[') {
                // Try to extract displacement
                if let Some(disp) = self.extract_displacement(operand) {
                    if self.immediate_matches(disp, search_value) {
                        let size = if disp.abs() <= 0x7F {
                            1
                        } else if disp.abs() <= 0x7FFF {
                            2
                        } else {
                            4
                        };
                        return Some((disp, size, ImmediateMatchType::InstructionDisplacement));
                    }
                }
            } else {
                // Check if it's an immediate
                if let Some(value) = self.parse_immediate(operand) {
                    if self.immediate_matches(value, search_value) {
                        let size = if (-128..=127).contains(&value) {
                            1
                        } else if (-32768..=32767).contains(&value) {
                            2
                        } else if (-2147483648..=2147483647).contains(&value) {
                            4
                        } else {
                            8
                        };
                        return Some((value, size, ImmediateMatchType::InstructionImmediate));
                    }
                }
            }
        }

        None
    }

    /// Extract displacement from a memory operand like [rbp-0x10]
    fn extract_displacement(&self, operand: &str) -> Option<i64> {
        // Look for +/- followed by a number
        let re = regex::Regex::new(r"([+-])\s*(0x[0-9a-fA-F]+|\d+)\s*\]").ok()?;
        if let Some(caps) = re.captures(operand) {
            let sign = if caps.get(1)?.as_str() == "-" { -1 } else { 1 };
            let value_str = caps.get(2)?.as_str();
            let value = if let Some(hex) = value_str.strip_prefix("0x") {
                i64::from_str_radix(hex, 16).ok()?
            } else {
                value_str.parse().ok()?
            };
            return Some(sign * value);
        }
        None
    }

    /// Parse an immediate value from an operand string
    fn parse_immediate(&self, operand: &str) -> Option<i64> {
        let operand = operand.trim();
        if let Some(hex) = operand
            .strip_prefix("0x")
            .or_else(|| operand.strip_prefix("0X"))
        {
            i64::from_str_radix(hex, 16).ok()
        } else if operand.chars().all(|c| c.is_ascii_digit() || c == '-') {
            operand.parse().ok()
        } else {
            None
        }
    }

    /// Check if an immediate value matches the search criteria
    fn immediate_matches(&self, value: i64, search: &ImmediateSearchValue) -> bool {
        match search {
            ImmediateSearchValue::Exact(expected) => value == *expected,
            ImmediateSearchValue::ExactUnsigned(expected) => value as u64 == *expected,
            ImmediateSearchValue::Float { value: f, epsilon } => {
                let as_float = f32::from_bits(value as u32);
                (as_float - f).abs() <= *epsilon
            }
            ImmediateSearchValue::Double { value: d, epsilon } => {
                let as_double = f64::from_bits(value as u64);
                (as_double - d).abs() <= *epsilon
            }
            ImmediateSearchValue::Range { min, max } => value >= *min && value <= *max,
            ImmediateSearchValue::Address(addr) => value as u64 == *addr,
        }
    }

    /// Search for immediate values in raw data
    #[allow(clippy::too_many_arguments)]
    fn find_immediates_in_data<G>(
        &self,
        data: &[u8],
        base_addr: usize,
        search_value: &ImmediateSearchValue,
        alignment: usize,
        get_module: G,
        results: &mut Vec<ImmediateMatch>,
        max_results: usize,
    ) where
        G: Fn(usize) -> Option<(String, u64)>,
    {
        let alignment = alignment.max(1);

        // Determine sizes to check based on search value
        let sizes: Vec<usize> = match search_value {
            ImmediateSearchValue::Float { .. } => vec![4],
            ImmediateSearchValue::Double { .. } => vec![8],
            _ => vec![1, 2, 4, 8],
        };

        for offset in (0..data.len()).step_by(alignment) {
            if results.len() >= max_results || self.is_cancelled() {
                break;
            }

            for &size in &sizes {
                if offset + size > data.len() {
                    continue;
                }

                let value = match size {
                    1 => data[offset] as i8 as i64,
                    2 => i16::from_le_bytes([data[offset], data[offset + 1]]) as i64,
                    4 => i32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as i64,
                    8 => i64::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]),
                    _ => continue,
                };

                if self.immediate_matches(value, search_value) {
                    let addr = base_addr + offset;
                    let (module, mod_offset) = get_module(addr)
                        .map(|(m, o)| (Some(m), o))
                        .unwrap_or((None, addr as u64));

                    // Create hex dump context
                    let context_start = offset.saturating_sub(8);
                    let context_end = (offset + size + 8).min(data.len());
                    let context_bytes = &data[context_start..context_end];
                    let context = context_bytes
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ");

                    results.push(ImmediateMatch {
                        address: addr as u64,
                        value,
                        size: size as u8,
                        match_type: ImmediateMatchType::Data,
                        context,
                        module,
                        module_offset: mod_offset,
                    });
                    break; // Only report largest match per address
                }
            }
        }
    }

    // ========================================================================
    // Unified Advanced Search (search.advanced)
    // ========================================================================

    /// Perform a unified advanced search with pagination support
    pub fn search_advanced<F, R, G>(
        &self,
        request: &AdvancedSearchRequest,
        disasm_fn: F,
        read_fn: R,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<AdvancedSearchResult>
    where
        F: Fn(usize, usize) -> Result<Vec<Instruction>> + Clone,
        R: Fn(usize, usize) -> Result<Vec<u8>> + Clone,
        G: Fn(usize) -> Option<(String, u64)> + Clone,
    {
        let search_id = AdvancedSearchId(self.next_search_id.fetch_add(1, Ordering::SeqCst));
        let start_time = Instant::now();
        self.reset_cancel();

        // Collect all results
        let results = self.execute_search_type(
            &request.search_type,
            &request.address_range,
            &request.modules,
            disasm_fn,
            read_fn,
            regions,
            get_module,
        )?;

        let total_count = results.len();
        let page_size = request.page_size.min(MAX_RESULTS);

        // Apply pagination
        let offset = request.cursor.as_ref().map(|c| c.offset).unwrap_or(0);
        let page_results: Vec<_> = results.into_iter().skip(offset).take(page_size).collect();
        let has_more = offset + page_results.len() < total_count;

        let stats = SearchStats {
            bytes_searched: 0, // Would need to track
            instructions_checked: 0,
            regions_searched: regions.len(),
            elapsed_ms: start_time.elapsed().as_millis() as u64,
            cancelled: self.is_cancelled(),
        };

        let next_cursor = if has_more {
            Some(SearchCursor {
                offset: offset + page_results.len(),
                search_id,
                has_more: true,
            })
        } else {
            None
        };

        Ok(AdvancedSearchResult {
            search_id,
            results: page_results,
            total_count,
            next_cursor,
            stats,
        })
    }

    /// Execute a specific search type
    #[allow(clippy::too_many_arguments)]
    fn execute_search_type<F, R, G>(
        &self,
        search_type: &AdvancedSearchType,
        address_range: &Option<AddressRange>,
        modules: &[String],
        disasm_fn: F,
        read_fn: R,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<Vec<SearchResultItem>>
    where
        F: Fn(usize, usize) -> Result<Vec<Instruction>> + Clone,
        R: Fn(usize, usize) -> Result<Vec<u8>> + Clone,
        G: Fn(usize) -> Option<(String, u64)> + Clone,
    {
        match search_type {
            AdvancedSearchType::Instructions(patterns) => {
                let request = FindInstructionsRequest {
                    patterns: patterns.clone(),
                    address_range: *address_range,
                    module: modules.first().cloned(),
                    max_results: MAX_RESULTS,
                    functions_only: false,
                };
                let matches = self.find_instructions(&request, disasm_fn, regions, get_module)?;
                Ok(matches
                    .into_iter()
                    .map(SearchResultItem::InstructionSequence)
                    .collect())
            }
            AdvancedSearchType::Operand {
                mnemonic,
                pattern,
                operand_index,
            } => {
                let request = FindOperandsRequest {
                    mnemonic: mnemonic.clone(),
                    operand: pattern.clone(),
                    operand_index: *operand_index,
                    address_range: *address_range,
                    module: modules.first().cloned(),
                    max_results: MAX_RESULTS,
                };
                let matches = self.find_operands(&request, disasm_fn, regions, get_module)?;
                Ok(matches
                    .into_iter()
                    .map(SearchResultItem::Instruction)
                    .collect())
            }
            AdvancedSearchType::Immediate(value) => {
                let request = FindImmediatesRequest {
                    value: value.clone(),
                    search_in: ImmediateSearchScope::Both,
                    address_range: *address_range,
                    module: modules.first().cloned(),
                    max_results: MAX_RESULTS,
                    alignment: 1,
                };
                let matches =
                    self.find_immediates(&request, disasm_fn, read_fn, regions, get_module)?;
                Ok(matches
                    .into_iter()
                    .map(SearchResultItem::Immediate)
                    .collect())
            }
            AdvancedSearchType::String {
                pattern,
                case_sensitive,
                encoding,
            } => {
                let matches = self.find_strings(
                    pattern,
                    *case_sensitive,
                    *encoding,
                    address_range,
                    read_fn,
                    regions,
                    get_module,
                )?;
                Ok(matches.into_iter().map(SearchResultItem::String).collect())
            }
            AdvancedSearchType::CrossReference { target, ref_type } => {
                let matches = self.find_xrefs(
                    *target,
                    *ref_type,
                    address_range,
                    disasm_fn,
                    regions,
                    get_module,
                )?;
                Ok(matches
                    .into_iter()
                    .map(SearchResultItem::CrossReference)
                    .collect())
            }
            AdvancedSearchType::DataPattern { pattern } => {
                let matches =
                    self.find_data_pattern(pattern, address_range, read_fn, regions, get_module)?;
                Ok(matches
                    .into_iter()
                    .map(SearchResultItem::DataPattern)
                    .collect())
            }
            AdvancedSearchType::Combined(searches) => {
                let mut all_results = Vec::new();
                for search in searches {
                    let results = self.execute_search_type(
                        search,
                        address_range,
                        modules,
                        disasm_fn.clone(),
                        read_fn.clone(),
                        regions,
                        get_module.clone(),
                    )?;
                    all_results.extend(results);
                    if all_results.len() >= MAX_RESULTS {
                        all_results.truncate(MAX_RESULTS);
                        break;
                    }
                }
                Ok(all_results)
            }
        }
    }

    /// Find strings in memory
    #[allow(clippy::too_many_arguments)]
    fn find_strings<R, G>(
        &self,
        pattern: &str,
        case_sensitive: bool,
        encoding: StringSearchEncoding,
        address_range: &Option<AddressRange>,
        read_fn: R,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<Vec<StringMatch>>
    where
        R: Fn(usize, usize) -> Result<Vec<u8>>,
        G: Fn(usize) -> Option<(String, u64)>,
    {
        let mut results = Vec::new();
        let pattern_lower = pattern.to_lowercase();

        for region in regions {
            if self.is_cancelled() || results.len() >= MAX_RESULTS {
                break;
            }

            if !region.protection.read {
                continue;
            }

            if let Some(range) = address_range {
                let region_end = region.base + region.size;
                if region.base >= range.end as usize || region_end <= range.start as usize {
                    continue;
                }
            }

            if let Ok(data) = read_fn(region.base, region.size.min(0x100000)) {
                // Search for ASCII strings
                if matches!(
                    encoding,
                    StringSearchEncoding::Ascii | StringSearchEncoding::All
                ) {
                    self.find_ascii_strings(
                        &data,
                        region.base,
                        pattern,
                        &pattern_lower,
                        case_sensitive,
                        &get_module,
                        &mut results,
                    );
                }

                // Search for UTF-16 strings
                if matches!(
                    encoding,
                    StringSearchEncoding::Utf16Le | StringSearchEncoding::All
                ) {
                    self.find_utf16_strings(
                        &data,
                        region.base,
                        pattern,
                        &pattern_lower,
                        case_sensitive,
                        &get_module,
                        &mut results,
                    );
                }
            }
        }

        Ok(results)
    }

    #[allow(clippy::too_many_arguments)]
    fn find_ascii_strings<G>(
        &self,
        data: &[u8],
        base_addr: usize,
        pattern: &str,
        pattern_lower: &str,
        case_sensitive: bool,
        get_module: &G,
        results: &mut Vec<StringMatch>,
    ) where
        G: Fn(usize) -> Option<(String, u64)>,
    {
        let pattern_bytes = pattern.as_bytes();

        for i in 0..data.len().saturating_sub(pattern_bytes.len()) {
            if results.len() >= MAX_RESULTS {
                break;
            }

            let matches = if case_sensitive {
                data[i..].starts_with(pattern_bytes)
            } else {
                data[i..i + pattern_bytes.len()]
                    .iter()
                    .zip(pattern_lower.bytes())
                    .all(|(a, b)| a.to_ascii_lowercase() == b)
            };

            if matches {
                // Find the full string (until null terminator)
                let end = data[i..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| i + p)
                    .unwrap_or(data.len().min(i + 256));

                if let Ok(s) = std::str::from_utf8(&data[i..end]) {
                    let addr = base_addr + i;
                    let (module, offset) = get_module(addr)
                        .map(|(m, o)| (Some(m), o))
                        .unwrap_or((None, addr as u64));

                    results.push(StringMatch {
                        address: addr as u64,
                        value: s.to_string(),
                        encoding: StringSearchEncoding::Ascii,
                        byte_length: end - i,
                        module,
                        module_offset: offset,
                    });
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn find_utf16_strings<G>(
        &self,
        data: &[u8],
        base_addr: usize,
        pattern: &str,
        pattern_lower: &str,
        case_sensitive: bool,
        get_module: &G,
        results: &mut Vec<StringMatch>,
    ) where
        G: Fn(usize) -> Option<(String, u64)>,
    {
        let pattern_utf16: Vec<u8> = pattern
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        for i in (0..data.len().saturating_sub(pattern_utf16.len())).step_by(2) {
            if results.len() >= MAX_RESULTS {
                break;
            }

            let matches = if case_sensitive {
                data[i..].starts_with(&pattern_utf16)
            } else {
                // Case-insensitive UTF-16 comparison
                let chunk = &data[i..i + pattern_utf16.len()];
                chunk
                    .chunks(2)
                    .zip(pattern_lower.chars())
                    .all(|(bytes, c)| {
                        if bytes.len() == 2 {
                            let wchar = u16::from_le_bytes([bytes[0], bytes[1]]);
                            if let Some(ch) = char::from_u32(wchar as u32) {
                                ch.to_ascii_lowercase() == c
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    })
            };

            if matches {
                // Find full string
                let mut end = i;
                while end + 1 < data.len() {
                    if data[end] == 0 && data[end + 1] == 0 {
                        break;
                    }
                    end += 2;
                    if end - i > 512 {
                        break;
                    }
                }

                let utf16_data: Vec<u16> = data[i..end]
                    .chunks(2)
                    .filter_map(|c| {
                        if c.len() == 2 {
                            Some(u16::from_le_bytes([c[0], c[1]]))
                        } else {
                            None
                        }
                    })
                    .collect();

                if let Ok(s) = String::from_utf16(&utf16_data) {
                    let addr = base_addr + i;
                    let (module, offset) = get_module(addr)
                        .map(|(m, o)| (Some(m), o))
                        .unwrap_or((None, addr as u64));

                    results.push(StringMatch {
                        address: addr as u64,
                        value: s,
                        encoding: StringSearchEncoding::Utf16Le,
                        byte_length: end - i,
                        module,
                        module_offset: offset,
                    });
                }
            }
        }
    }

    /// Find cross-references to an address
    fn find_xrefs<F, G>(
        &self,
        target: u64,
        ref_type: XrefSearchType,
        address_range: &Option<AddressRange>,
        disasm_fn: F,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<Vec<XrefMatch>>
    where
        F: Fn(usize, usize) -> Result<Vec<Instruction>>,
        G: Fn(usize) -> Option<(String, u64)>,
    {
        let mut results = Vec::new();
        let search_code = matches!(ref_type, XrefSearchType::Code | XrefSearchType::All);
        // Note: Data xref search not yet implemented - tracked for future enhancement
        let _search_data = matches!(ref_type, XrefSearchType::Data | XrefSearchType::All);

        for region in regions {
            if self.is_cancelled() || results.len() >= MAX_RESULTS {
                break;
            }

            if let Some(range) = address_range {
                let region_end = region.base + region.size;
                if region.base >= range.end as usize || region_end <= range.start as usize {
                    continue;
                }
            }

            if search_code && region.protection.execute {
                if let Ok(instructions) = disasm_fn(region.base, region.size.min(0x100000)) {
                    for instruction in instructions {
                        if results.len() >= MAX_RESULTS {
                            break;
                        }

                        if let Some(xref_type) = self.get_xref_type(&instruction, target) {
                            let (module, _) = get_module(instruction.address)
                                .map(|(m, o)| (Some(m), o))
                                .unwrap_or((None, 0));

                            results.push(XrefMatch {
                                from_address: instruction.address as u64,
                                to_address: target,
                                ref_type: xref_type,
                                instruction: Some(format!(
                                    "{} {}",
                                    instruction.mnemonic, instruction.operands
                                )),
                                module,
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Determine if an instruction references a target address
    fn get_xref_type(&self, instruction: &Instruction, target: u64) -> Option<XrefType> {
        let mnemonic = instruction.mnemonic.to_uppercase();

        // Check if operands contain the target address
        let operands = &instruction.operands;
        let target_str = format!("{:#x}", target);
        let target_str_upper = format!("{:#X}", target);

        if !operands.contains(&target_str) && !operands.contains(&target_str_upper) {
            // Try without 0x prefix
            let target_hex = format!("{:x}", target);
            if !operands.to_lowercase().contains(&target_hex) {
                return None;
            }
        }

        if mnemonic.starts_with("CALL") {
            Some(XrefType::Call)
        } else if mnemonic == "JMP" {
            Some(XrefType::Jump)
        } else if mnemonic.starts_with('J') {
            Some(XrefType::ConditionalJump)
        } else if mnemonic == "LEA" {
            Some(XrefType::Lea)
        } else if mnemonic.starts_with("MOV") || mnemonic.starts_with("CMP") {
            // Check if it's a read or write
            if operands.starts_with('[') {
                Some(XrefType::Write)
            } else {
                Some(XrefType::Read)
            }
        } else {
            Some(XrefType::Other)
        }
    }

    /// Find data patterns (AOB)
    fn find_data_pattern<R, G>(
        &self,
        pattern: &str,
        address_range: &Option<AddressRange>,
        read_fn: R,
        regions: &[MemoryRegion],
        get_module: G,
    ) -> Result<Vec<DataPatternMatch>>
    where
        R: Fn(usize, usize) -> Result<Vec<u8>>,
        G: Fn(usize) -> Option<(String, u64)>,
    {
        let mut results = Vec::new();

        // Parse AOB pattern
        let (pattern_bytes, mask) =
            crate::pattern_scanner::PatternScanner::parse_aob_pattern(pattern)?;

        for region in regions {
            if self.is_cancelled() || results.len() >= MAX_RESULTS {
                break;
            }

            if !region.protection.read {
                continue;
            }

            if let Some(range) = address_range {
                let region_end = region.base + region.size;
                if region.base >= range.end as usize || region_end <= range.start as usize {
                    continue;
                }
            }

            if let Ok(data) = read_fn(region.base, region.size.min(0x100000)) {
                let matches = crate::pattern_scanner::PatternScanner::find_aob_in_buffer(
                    &data,
                    &pattern_bytes,
                    &mask,
                    MAX_RESULTS,
                );

                for offset in matches {
                    if results.len() >= MAX_RESULTS {
                        break;
                    }

                    let addr = region.base + offset;
                    let (module, mod_offset) = get_module(addr)
                        .map(|(m, o)| (Some(m), o))
                        .unwrap_or((None, addr as u64));

                    let matched_bytes = data[offset..offset + pattern_bytes.len()].to_vec();

                    results.push(DataPatternMatch {
                        address: addr as u64,
                        bytes: matched_bytes,
                        module,
                        module_offset: mod_offset,
                    });
                }
            }
        }

        Ok(results)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_register_of_type() {
        let search = AdvancedPatternSearch::new();
        assert!(search.is_register_of_type("rax", RegisterType::GeneralPurpose));
        assert!(search.is_register_of_type("eax", RegisterType::GeneralPurpose32));
        assert!(search.is_register_of_type("xmm0", RegisterType::Xmm));
        assert!(!search.is_register_of_type("rax", RegisterType::Xmm));
    }

    #[test]
    fn test_parse_immediate() {
        let search = AdvancedPatternSearch::new();
        assert_eq!(search.parse_immediate("0x1234"), Some(0x1234));
        assert_eq!(search.parse_immediate("42"), Some(42));
        assert_eq!(search.parse_immediate("-10"), Some(-10));
        assert_eq!(search.parse_immediate("rax"), None);
    }

    #[test]
    fn test_immediate_matches() {
        let search = AdvancedPatternSearch::new();

        assert!(search.immediate_matches(42, &ImmediateSearchValue::Exact(42)));
        assert!(!search.immediate_matches(43, &ImmediateSearchValue::Exact(42)));

        assert!(search.immediate_matches(50, &ImmediateSearchValue::Range { min: 40, max: 60 }));
        assert!(!search.immediate_matches(30, &ImmediateSearchValue::Range { min: 40, max: 60 }));
    }

    #[test]
    fn test_operand_matches_pattern() {
        let search = AdvancedPatternSearch::new();

        assert!(search.operand_matches_pattern("rax", &OperandPattern::Any));
        assert!(search.operand_matches_pattern("rax", &OperandPattern::Register("rax".to_string())));
        assert!(search.operand_matches_pattern(
            "rax",
            &OperandPattern::RegisterType(RegisterType::GeneralPurpose)
        ));
        assert!(search
            .operand_matches_pattern("[rbp+0x10]", &OperandPattern::Contains("rbp".to_string())));
    }

    #[test]
    fn test_instruction_matches_pattern() {
        let search = AdvancedPatternSearch::new();

        let instruction = Instruction {
            address: 0x1000,
            bytes: vec![0x48, 0x89, 0xE5],
            mnemonic: "mov".to_string(),
            operands: "rbp, rsp".to_string(),
        };

        let pattern = InstructionPattern {
            mnemonic: "mov".to_string(),
            operands: vec![
                OperandPattern::Register("rbp".to_string()),
                OperandPattern::Register("rsp".to_string()),
            ],
            optional: false,
            max_gap: None,
        };

        assert!(search.instruction_matches_pattern(&instruction, &pattern));

        let pattern_any = InstructionPattern {
            mnemonic: "*".to_string(),
            operands: vec![],
            optional: false,
            max_gap: None,
        };

        assert!(search.instruction_matches_pattern(&instruction, &pattern_any));
    }
}
