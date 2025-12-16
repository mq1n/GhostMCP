//! Advanced Pattern Matching types
//!
//! Types for instruction sequence search, operand search, immediate value search,
//! and unified advanced search capabilities.

use serde::{Deserialize, Serialize};

// ============================================================================
// Identifiers
// ============================================================================

/// Unique identifier for an advanced search session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdvancedSearchId(pub u32);

/// Cursor for paginated search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchCursor {
    /// Current offset in results
    pub offset: usize,
    /// Search ID this cursor belongs to
    pub search_id: AdvancedSearchId,
    /// Whether there are more results
    pub has_more: bool,
}

// ============================================================================
// Instruction Search Types (find.instructions)
// ============================================================================

/// Instruction pattern for sequence matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionPattern {
    /// Mnemonic to match (e.g., "mov", "push", "call")
    /// Supports wildcards: "*" matches any mnemonic
    pub mnemonic: String,
    /// Operand patterns (optional, empty = match any operands)
    /// Supports wildcards: "*" matches any operand, "r*" matches any register
    #[serde(default)]
    pub operands: Vec<OperandPattern>,
    /// Whether this instruction is optional in the sequence
    #[serde(default)]
    pub optional: bool,
    /// Maximum gap (in instructions) allowed before this pattern
    /// 0 = must be immediately after previous, None = any gap
    #[serde(default)]
    pub max_gap: Option<usize>,
}

/// Pattern for matching instruction operands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperandPattern {
    /// Match any operand
    Any,
    /// Match specific register (e.g., "rax", "eax", "r8")
    Register(String),
    /// Match any register of a type (e.g., "gpr" for general purpose, "xmm" for SSE)
    RegisterType(RegisterType),
    /// Match immediate value
    Immediate(ImmediatePattern),
    /// Match memory operand
    Memory(MemoryOperandPattern),
    /// Match exact operand string
    Exact(String),
    /// Match operand containing substring
    Contains(String),
    /// Match operand with regex
    Regex(String),
}

/// Register type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterType {
    /// General purpose registers (rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15)
    GeneralPurpose,
    /// 32-bit general purpose (eax, ebx, etc.)
    GeneralPurpose32,
    /// 16-bit general purpose (ax, bx, etc.)
    GeneralPurpose16,
    /// 8-bit registers (al, ah, bl, etc.)
    GeneralPurpose8,
    /// SSE registers (xmm0-xmm15)
    Xmm,
    /// AVX registers (ymm0-ymm15)
    Ymm,
    /// AVX-512 registers (zmm0-zmm31)
    Zmm,
    /// Segment registers (cs, ds, es, fs, gs, ss)
    Segment,
    /// Control registers (cr0-cr15)
    Control,
    /// Debug registers (dr0-dr7)
    Debug,
}

/// Pattern for matching immediate values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImmediatePattern {
    /// Match exact value
    Exact(i64),
    /// Match value in range (inclusive)
    Range { min: i64, max: i64 },
    /// Match any immediate
    Any,
    /// Match value with specific bits set
    HasBits(u64),
    /// Match value with specific bits clear
    ClearBits(u64),
    /// Match aligned value (divisible by alignment)
    Aligned(u64),
}

/// Pattern for matching memory operands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperandPattern {
    /// Base register pattern (None = any or no base)
    #[serde(default)]
    pub base: Option<String>,
    /// Index register pattern (None = any or no index)
    #[serde(default)]
    pub index: Option<String>,
    /// Scale value (1, 2, 4, 8) or None for any
    #[serde(default)]
    pub scale: Option<u8>,
    /// Displacement pattern
    #[serde(default)]
    pub displacement: Option<ImmediatePattern>,
    /// Memory size in bytes (None = any)
    #[serde(default)]
    pub size: Option<u8>,
}

/// Request to find instruction sequences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindInstructionsRequest {
    /// Sequence of instruction patterns to match
    pub patterns: Vec<InstructionPattern>,
    /// Address range to search (None = all executable memory)
    #[serde(default)]
    pub address_range: Option<AddressRange>,
    /// Module to search in (None = all modules)
    #[serde(default)]
    pub module: Option<String>,
    /// Maximum results to return
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Whether to search only in functions (vs. all executable memory)
    #[serde(default)]
    pub functions_only: bool,
}

/// Address range for search
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

/// Result of instruction sequence search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionSequenceMatch {
    /// Start address of the matched sequence
    pub address: u64,
    /// Matched instructions
    pub instructions: Vec<MatchedInstruction>,
    /// Module containing the match
    pub module: Option<String>,
    /// Function containing the match (if known)
    pub function: Option<String>,
    /// Offset within module
    pub module_offset: u64,
}

/// A matched instruction in a sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedInstruction {
    /// Address of instruction
    pub address: u64,
    /// Raw bytes
    pub bytes: Vec<u8>,
    /// Mnemonic
    pub mnemonic: String,
    /// Operands string
    pub operands: String,
    /// Which pattern index this matched (for patterns with gaps)
    pub pattern_index: usize,
}

// ============================================================================
// Operand Search Types (find.operands)
// ============================================================================

/// Request to find instructions by operand values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindOperandsRequest {
    /// Mnemonic filter (None = any instruction)
    #[serde(default)]
    pub mnemonic: Option<String>,
    /// Operand pattern to match
    pub operand: OperandPattern,
    /// Which operand position to match (None = any position)
    #[serde(default)]
    pub operand_index: Option<usize>,
    /// Address range to search
    #[serde(default)]
    pub address_range: Option<AddressRange>,
    /// Module to search in
    #[serde(default)]
    pub module: Option<String>,
    /// Maximum results
    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

/// Result of operand search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandMatch {
    /// Address of instruction
    pub address: u64,
    /// Full instruction bytes
    pub bytes: Vec<u8>,
    /// Mnemonic
    pub mnemonic: String,
    /// Full operands string
    pub operands: String,
    /// Index of matched operand
    pub matched_operand_index: usize,
    /// The matched operand value
    pub matched_operand: String,
    /// Module containing the match
    pub module: Option<String>,
    /// Offset within module
    pub module_offset: u64,
}

// ============================================================================
// Immediate Value Search Types (find.immediates)
// ============================================================================

/// Request to find immediate values in code or data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindImmediatesRequest {
    /// Value to search for
    pub value: ImmediateSearchValue,
    /// Where to search
    #[serde(default)]
    pub search_in: ImmediateSearchScope,
    /// Address range to search
    #[serde(default)]
    pub address_range: Option<AddressRange>,
    /// Module to search in
    #[serde(default)]
    pub module: Option<String>,
    /// Maximum results
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Alignment requirement for data searches (1, 2, 4, 8)
    #[serde(default = "default_alignment")]
    pub alignment: usize,
}

/// Value to search for in immediate search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImmediateSearchValue {
    /// Exact value (any size)
    Exact(i64),
    /// Unsigned value
    ExactUnsigned(u64),
    /// Float value (with epsilon tolerance)
    Float { value: f32, epsilon: f32 },
    /// Double value (with epsilon tolerance)
    Double { value: f64, epsilon: f64 },
    /// Range of values
    Range { min: i64, max: i64 },
    /// Address/pointer value
    Address(u64),
}

/// Where to search for immediate values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ImmediateSearchScope {
    /// Search in instruction immediates only
    CodeOnly,
    /// Search in data sections only
    DataOnly,
    /// Search in both code and data
    #[default]
    Both,
}

/// Result of immediate value search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmediateMatch {
    /// Address where value was found
    pub address: u64,
    /// The matched value
    pub value: i64,
    /// Size of the value in bytes
    pub size: u8,
    /// Type of match
    pub match_type: ImmediateMatchType,
    /// Context (instruction disassembly or hex dump)
    pub context: String,
    /// Module containing the match
    pub module: Option<String>,
    /// Offset within module
    pub module_offset: u64,
}

/// Type of immediate match
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImmediateMatchType {
    /// Found in instruction immediate operand
    InstructionImmediate,
    /// Found in instruction displacement
    InstructionDisplacement,
    /// Found in data section
    Data,
    /// Found in relocation table
    Relocation,
}

// ============================================================================
// Unified Advanced Search Types (search.advanced)
// ============================================================================

/// Unified advanced search request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedSearchRequest {
    /// Search type
    pub search_type: AdvancedSearchType,
    /// Address range to search
    #[serde(default)]
    pub address_range: Option<AddressRange>,
    /// Modules to search in (empty = all)
    #[serde(default)]
    pub modules: Vec<String>,
    /// Maximum results per page
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    /// Continue from cursor (for pagination)
    #[serde(default)]
    pub cursor: Option<SearchCursor>,
}

/// Types of advanced searches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdvancedSearchType {
    /// Search for instruction sequences
    Instructions(Vec<InstructionPattern>),
    /// Search for operand values
    Operand {
        mnemonic: Option<String>,
        pattern: OperandPattern,
        operand_index: Option<usize>,
    },
    /// Search for immediate values
    Immediate(ImmediateSearchValue),
    /// Search for strings (ASCII/Unicode)
    String {
        pattern: String,
        case_sensitive: bool,
        encoding: StringSearchEncoding,
    },
    /// Search for cross-references to address
    CrossReference {
        target: u64,
        ref_type: XrefSearchType,
    },
    /// Search for data patterns (AOB)
    DataPattern { pattern: String },
    /// Combined search (all results matching ANY of the sub-searches)
    Combined(Vec<AdvancedSearchType>),
}

/// String encoding for search
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StringSearchEncoding {
    #[default]
    Ascii,
    Utf16Le,
    Utf16Be,
    Utf8,
    All,
}

/// Cross-reference search type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum XrefSearchType {
    /// Code references (call, jmp)
    #[default]
    Code,
    /// Data references (load, store)
    Data,
    /// All references
    All,
}

/// Unified search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedSearchResult {
    /// Search ID
    pub search_id: AdvancedSearchId,
    /// Results for this page
    pub results: Vec<SearchResultItem>,
    /// Total results found (may be estimate for large searches)
    pub total_count: usize,
    /// Cursor for next page
    pub next_cursor: Option<SearchCursor>,
    /// Search statistics
    pub stats: SearchStats,
}

/// Individual search result item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SearchResultItem {
    /// Instruction sequence match
    InstructionSequence(InstructionSequenceMatch),
    /// Single instruction/operand match
    Instruction(OperandMatch),
    /// Immediate value match
    Immediate(ImmediateMatch),
    /// String match
    String(StringMatch),
    /// Cross-reference match
    CrossReference(XrefMatch),
    /// Data pattern match
    DataPattern(DataPatternMatch),
}

/// String search match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    /// Address of string
    pub address: u64,
    /// The matched string
    pub value: String,
    /// Encoding of the string
    pub encoding: StringSearchEncoding,
    /// Length in bytes
    pub byte_length: usize,
    /// Module containing the match
    pub module: Option<String>,
    /// Offset within module
    pub module_offset: u64,
}

/// Cross-reference match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefMatch {
    /// Address of the reference
    pub from_address: u64,
    /// Target address being referenced
    pub to_address: u64,
    /// Type of reference
    pub ref_type: XrefType,
    /// Instruction at the reference (if code ref)
    pub instruction: Option<String>,
    /// Module containing the reference
    pub module: Option<String>,
}

/// Type of cross-reference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XrefType {
    /// Direct call
    Call,
    /// Direct jump
    Jump,
    /// Conditional jump
    ConditionalJump,
    /// Memory read
    Read,
    /// Memory write
    Write,
    /// LEA (load effective address)
    Lea,
    /// Unknown/other
    Other,
}

/// Data pattern match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPatternMatch {
    /// Address of match
    pub address: u64,
    /// Matched bytes
    pub bytes: Vec<u8>,
    /// Module containing the match
    pub module: Option<String>,
    /// Offset within module
    pub module_offset: u64,
}

/// Search statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SearchStats {
    /// Bytes searched
    pub bytes_searched: u64,
    /// Instructions disassembled
    pub instructions_checked: u64,
    /// Regions searched
    pub regions_searched: usize,
    /// Time elapsed in milliseconds
    pub elapsed_ms: u64,
    /// Whether search was cancelled
    pub cancelled: bool,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn default_max_results() -> usize {
    1000
}

fn default_page_size() -> usize {
    100
}

fn default_alignment() -> usize {
    1
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_pattern_serialization() {
        let pattern = InstructionPattern {
            mnemonic: "mov".to_string(),
            operands: vec![
                OperandPattern::Register("rax".to_string()),
                OperandPattern::Any,
            ],
            optional: false,
            max_gap: Some(2),
        };
        let json = serde_json::to_string(&pattern).unwrap();
        let parsed: InstructionPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mnemonic, "mov");
        assert_eq!(parsed.max_gap, Some(2));
    }

    #[test]
    fn test_immediate_pattern() {
        let pattern = ImmediatePattern::Range { min: 0, max: 100 };
        let json = serde_json::to_string(&pattern).unwrap();
        assert!(json.contains("Range"));
    }

    #[test]
    fn test_advanced_search_type() {
        let search = AdvancedSearchType::Immediate(ImmediateSearchValue::Exact(0x12345678));
        let json = serde_json::to_string(&search).unwrap();
        assert!(json.contains("Immediate"));
    }

    #[test]
    fn test_search_cursor() {
        let cursor = SearchCursor {
            offset: 100,
            search_id: AdvancedSearchId(1),
            has_more: true,
        };
        let json = serde_json::to_string(&cursor).unwrap();
        let parsed: SearchCursor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.offset, 100);
        assert!(parsed.has_more);
    }
}
