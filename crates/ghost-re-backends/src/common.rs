//! Common types and traits for RE backends

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about a function in the binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Function name
    pub name: String,
    /// Start address
    pub address: u64,
    /// End address (if known)
    pub end_address: Option<u64>,
    /// Size in bytes
    pub size: Option<u64>,
    /// Whether this is a library/external function
    pub is_external: bool,
    /// Function signature/prototype
    pub signature: Option<String>,
    /// Calling convention
    pub calling_convention: Option<String>,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
}

/// Information about a basic block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Start address
    pub address: u64,
    /// End address
    pub end_address: u64,
    /// Size in bytes
    pub size: u64,
    /// Addresses of successor blocks
    pub successors: Vec<u64>,
    /// Addresses of predecessor blocks
    pub predecessors: Vec<u64>,
}

/// A disassembled instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledInstruction {
    /// Address
    pub address: u64,
    /// Raw bytes
    pub bytes: Vec<u8>,
    /// Mnemonic (e.g., "mov", "call")
    pub mnemonic: String,
    /// Operands as string
    pub operands: String,
    /// Full disassembly text
    pub disasm: String,
    /// Size in bytes
    pub size: u64,
    /// Comment if any
    pub comment: Option<String>,
}

/// Cross-reference (xref) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReference {
    /// Source address
    pub from: u64,
    /// Target address
    pub to: u64,
    /// Type of reference
    pub xref_type: XRefType,
}

/// Type of cross-reference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XRefType {
    /// Code call
    Call,
    /// Code jump
    Jump,
    /// Data read
    Read,
    /// Data write
    Write,
    /// Unknown/other
    Unknown,
}

/// Decompiled function output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledFunction {
    /// Function name
    pub name: String,
    /// Function address
    pub address: u64,
    /// Decompiled source code
    pub code: String,
    /// Language (C, C++, etc.)
    pub language: String,
}

/// String found in binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryString {
    /// Address
    pub address: u64,
    /// String content
    pub value: String,
    /// String type (ascii, unicode, etc.)
    pub string_type: StringType,
    /// Length in bytes
    pub length: usize,
}

/// Type of string encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringType {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Unknown,
}

/// Import information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    /// Import name
    pub name: String,
    /// Library/module name
    pub library: String,
    /// Address in IAT
    pub address: u64,
    /// Ordinal if applicable
    pub ordinal: Option<u32>,
}

/// Export information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    /// Export name
    pub name: String,
    /// Address
    pub address: u64,
    /// Ordinal if applicable
    pub ordinal: Option<u32>,
    /// Whether it's forwarded
    pub forwarded: Option<String>,
}

/// Section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name
    pub name: String,
    /// Virtual address
    pub virtual_address: u64,
    /// Virtual size
    pub virtual_size: u64,
    /// Raw size on disk
    pub raw_size: u64,
    /// Characteristics/flags
    pub characteristics: u32,
    /// Is executable
    pub executable: bool,
    /// Is writable
    pub writable: bool,
    /// Is readable
    pub readable: bool,
}

/// Binary metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// File path
    pub path: String,
    /// File format (PE, ELF, Mach-O, etc.)
    pub format: String,
    /// Architecture (x86, x86_64, ARM, etc.)
    pub architecture: String,
    /// Bits (32, 64)
    pub bits: u32,
    /// Endianness
    pub endian: Endianness,
    /// Entry point address
    pub entry_point: u64,
    /// Base address
    pub base_address: u64,
    /// Sections
    pub sections: Vec<SectionInfo>,
}

/// Endianness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

/// Unified trait for reverse engineering tool backends
#[allow(async_fn_in_trait)]
pub trait ReBackend: Send + Sync {
    /// Get backend name
    fn name(&self) -> &'static str;

    /// Check if backend is connected/ready
    fn is_connected(&self) -> bool;

    /// Open/load a binary file for analysis
    async fn open(&mut self, path: &str) -> Result<BinaryInfo>;

    /// Close the current binary
    async fn close(&mut self) -> Result<()>;

    /// Get binary metadata
    async fn get_binary_info(&self) -> Result<BinaryInfo>;

    /// List all functions
    async fn list_functions(&self) -> Result<Vec<FunctionInfo>>;

    /// Get function at address
    async fn get_function(&self, address: u64) -> Result<FunctionInfo>;

    /// Get function by name
    async fn get_function_by_name(&self, name: &str) -> Result<FunctionInfo>;

    /// Disassemble at address
    async fn disassemble(&self, address: u64, count: usize)
        -> Result<Vec<DisassembledInstruction>>;

    /// Disassemble a function
    async fn disassemble_function(&self, address: u64) -> Result<Vec<DisassembledInstruction>>;

    /// Get basic blocks for a function
    async fn get_basic_blocks(&self, function_address: u64) -> Result<Vec<BasicBlock>>;

    /// Decompile function (if supported)
    async fn decompile(&self, address: u64) -> Result<DecompiledFunction>;

    /// Get cross-references to an address
    async fn get_xrefs_to(&self, address: u64) -> Result<Vec<CrossReference>>;

    /// Get cross-references from an address
    async fn get_xrefs_from(&self, address: u64) -> Result<Vec<CrossReference>>;

    /// List strings in binary
    async fn list_strings(&self, min_length: usize) -> Result<Vec<BinaryString>>;

    /// List imports
    async fn list_imports(&self) -> Result<Vec<ImportInfo>>;

    /// List exports
    async fn list_exports(&self) -> Result<Vec<ExportInfo>>;

    /// Read bytes at address
    async fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>>;

    /// Rename a function or address
    async fn rename(&self, address: u64, new_name: &str) -> Result<()>;

    /// Add a comment at address
    async fn add_comment(&self, address: u64, comment: &str) -> Result<()>;

    /// Execute a raw command (tool-specific)
    async fn raw_command(&mut self, command: &str) -> Result<String>;
}

/// Backend type enumeration for runtime selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendType {
    /// IDA Pro
    Ida,
    /// Ghidra
    Ghidra,
    /// Radare2
    Radare2,
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendType::Ida => write!(f, "IDA Pro"),
            BackendType::Ghidra => write!(f, "Ghidra"),
            BackendType::Radare2 => write!(f, "Radare2"),
        }
    }
}

impl std::str::FromStr for BackendType {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ida" | "idapro" | "ida pro" => Ok(BackendType::Ida),
            "ghidra" => Ok(BackendType::Ghidra),
            "radare2" | "r2" | "radare" => Ok(BackendType::Radare2),
            _ => Err(crate::Error::Parse(format!("Unknown backend type: {}", s))),
        }
    }
}

/// Configuration for creating backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend type
    pub backend_type: BackendType,
    /// Path to the tool executable (if needed)
    pub tool_path: Option<String>,
    /// Host for remote connections
    pub host: Option<String>,
    /// Port for remote connections
    pub port: Option<u16>,
    /// Additional options
    pub options: HashMap<String, String>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            backend_type: BackendType::Radare2,
            tool_path: None,
            host: None,
            port: None,
            options: HashMap::new(),
        }
    }
}
