//! Radare2 backend implementation using r2pipe
//!
//! This module provides a production-ready backend for communicating with
//! radare2 via r2pipe. It supports spawning local r2 instances or connecting
//! to remote r2 servers via HTTP or TCP.
//!
//! # Requirements
//!
//! - radare2 must be installed and available in PATH
//! - For decompilation, r2ghidra or r2dec plugin is recommended
//!
//! # Thread Safety
//!
//! The backend uses `Mutex` for interior mutability, making it safe to share
//! across threads. However, r2pipe commands are executed sequentially.

use crate::common::*;
use crate::error::{Error, Result};
use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};

/// Radare2 backend using r2pipe
///
/// Uses Mutex for thread-safe interior mutability since r2pipe requires &mut self
/// for command execution but our trait uses &self.
pub struct Radare2Backend {
    pipe: Mutex<Option<R2Pipe>>,
    binary_path: Mutex<Option<String>>,
    binary_info: Mutex<Option<BinaryInfo>>,
}

impl Radare2Backend {
    /// Create a new Radare2 backend instance
    pub fn new() -> Self {
        Self {
            pipe: Mutex::new(None),
            binary_path: Mutex::new(None),
            binary_info: Mutex::new(None),
        }
    }

    /// Create with custom spawn options
    pub fn with_options(path: &str, options: R2PipeSpawnOptions) -> Result<Self> {
        let pipe = R2Pipe::spawn(path, Some(options))
            .map_err(|e| Error::Connection(format!("Failed to spawn r2: {:?}", e)))?;

        Ok(Self {
            pipe: Mutex::new(Some(pipe)),
            binary_path: Mutex::new(Some(path.to_string())),
            binary_info: Mutex::new(None),
        })
    }

    /// Connect to an existing r2 HTTP server
    pub fn connect_http(host: &str, port: u16) -> Result<Self> {
        let url = format!("http://{}:{}", host, port);
        let pipe = R2Pipe::http(&url);

        Ok(Self {
            pipe: Mutex::new(Some(pipe)),
            binary_path: Mutex::new(None),
            binary_info: Mutex::new(None),
        })
    }

    /// Connect to an existing r2 TCP server
    pub fn connect_tcp(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        let pipe = R2Pipe::tcp(&addr)
            .map_err(|e| Error::Connection(format!("Failed to connect to r2 TCP: {:?}", e)))?;

        Ok(Self {
            pipe: Mutex::new(Some(pipe)),
            binary_path: Mutex::new(None),
            binary_info: Mutex::new(None),
        })
    }

    /// Execute a radare2 command and return the output as a string.
    ///
    /// # Arguments
    /// * `command` - The r2 command to execute
    ///
    /// # Errors
    /// Returns an error if not connected or if the command fails.
    #[instrument(skip(self), level = "debug")]
    fn cmd(&self, command: &str) -> Result<String> {
        // Validate command is not empty
        if command.trim().is_empty() {
            warn!("Empty command provided");
            return Err(Error::CommandFailed("Empty command".into()));
        }

        let mut pipe_guard = self.pipe.lock().map_err(|e| {
            error!(error = %e, "Failed to acquire pipe lock");
            Error::Internal(format!("Lock error: {}", e))
        })?;

        let pipe = pipe_guard.as_mut().ok_or_else(|| {
            warn!("Command attempted on disconnected backend");
            Error::Connection("Not connected to radare2".into())
        })?;

        match pipe.cmd(command) {
            Ok(output) => {
                debug!(output_len = output.len(), "Command completed");
                Ok(output)
            }
            Err(e) => {
                error!(error = ?e, command = command, "Command failed");
                Err(Error::CommandFailed(format!("{:?}", e)))
            }
        }
    }

    /// Execute a radare2 command and parse the JSON output.
    ///
    /// # Type Parameters
    /// * `T` - The type to deserialize the JSON into
    ///
    /// # Arguments
    /// * `command` - The r2 command to execute (should produce JSON output)
    ///
    /// # Errors
    /// Returns an error if not connected, command fails, or JSON parsing fails.
    #[instrument(skip(self), level = "debug")]
    fn cmdj<T: for<'de> Deserialize<'de>>(&self, command: &str) -> Result<T> {
        // Validate command is not empty
        if command.trim().is_empty() {
            warn!("Empty command provided");
            return Err(Error::CommandFailed("Empty command".into()));
        }

        let mut pipe_guard = self.pipe.lock().map_err(|e| {
            error!(error = %e, "Failed to acquire pipe lock");
            Error::Internal(format!("Lock error: {}", e))
        })?;

        let pipe = pipe_guard.as_mut().ok_or_else(|| {
            warn!("JSON command attempted on disconnected backend");
            Error::Connection("Not connected to radare2".into())
        })?;

        let json = pipe.cmdj(command).map_err(|e| {
            error!(error = ?e, command = command, "JSON command failed");
            Error::CommandFailed(format!("{:?}", e))
        })?;

        serde_json::from_value(json).map_err(|e| {
            error!(error = %e, command = command, "Failed to parse JSON response");
            Error::Parse(format!("JSON parse error for '{}': {}", command, e))
        })
    }
}

impl Default for Radare2Backend {
    fn default() -> Self {
        Self::new()
    }
}

// JSON structures for r2 output parsing
#[derive(Debug, Deserialize)]
struct R2BinInfo {
    arch: Option<String>,
    bits: Option<u32>,
    bintype: Option<String>,
    #[serde(rename = "endian")]
    endian: Option<String>,
    baddr: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct R2CoreInfo {
    file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct R2Info {
    bin: Option<R2BinInfo>,
    core: Option<R2CoreInfo>,
}

#[derive(Debug, Deserialize)]
struct R2Function {
    name: Option<String>,
    offset: Option<u64>,
    size: Option<u64>,
    #[serde(rename = "is-pure")]
    #[allow(dead_code)]
    is_pure: Option<String>,
    #[allow(dead_code)]
    realsz: Option<u64>,
    signature: Option<String>,
    cc: Option<String>,
}

#[derive(Debug, Deserialize)]
struct R2Instruction {
    offset: Option<u64>,
    size: Option<u64>,
    opcode: Option<String>,
    disasm: Option<String>,
    bytes: Option<String>,
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct R2Xref {
    from: Option<u64>,
    to: Option<u64>,
    #[serde(rename = "type")]
    xref_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct R2String {
    vaddr: Option<u64>,
    paddr: Option<u64>,
    length: Option<usize>,
    #[serde(rename = "type")]
    string_type: Option<String>,
    string: Option<String>,
}

#[derive(Debug, Deserialize)]
struct R2Import {
    name: Option<String>,
    libname: Option<String>,
    plt: Option<u64>,
    ordinal: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct R2Export {
    name: Option<String>,
    #[serde(rename = "vaddr")]
    vaddr: Option<u64>,
    #[serde(rename = "paddr")]
    paddr: Option<u64>,
    ordinal: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct R2Section {
    name: Option<String>,
    size: Option<u64>,
    vsize: Option<u64>,
    vaddr: Option<u64>,
    #[allow(dead_code)]
    paddr: Option<u64>,
    perm: Option<String>,
    flags: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct R2BasicBlock {
    addr: Option<u64>,
    size: Option<u64>,
    jump: Option<u64>,
    fail: Option<u64>,
}

impl ReBackend for Radare2Backend {
    fn name(&self) -> &'static str {
        "Radare2"
    }

    fn is_connected(&self) -> bool {
        self.pipe.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    #[instrument(skip(self), level = "info")]
    async fn open(&mut self, path: &str) -> Result<BinaryInfo> {
        // Validate path
        if path.trim().is_empty() {
            error!("Empty path provided");
            return Err(Error::FileNotFound("Empty path".into()));
        }

        let file_path = Path::new(path);
        if !file_path.exists() {
            error!(path = path, "File does not exist");
            return Err(Error::FileNotFound(path.to_string()));
        }

        if !file_path.is_file() {
            error!(path = path, "Path is not a file");
            return Err(Error::FileNotFound(format!("Not a file: {}", path)));
        }

        info!(path = path, "Opening binary with Radare2");

        // Spawn r2 with the binary
        let pipe = R2Pipe::spawn(path, None).map_err(|e| {
            error!(error = ?e, path = path, "Failed to spawn radare2");
            Error::Connection(format!("Failed to spawn r2: {:?}", e))
        })?;

        *self
            .pipe
            .lock()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))? = Some(pipe);
        *self
            .binary_path
            .lock()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))? = Some(path.to_string());

        // Analyze the binary
        info!("Running analysis (this may take a while for large binaries)");
        self.cmd("aaa")?;

        // Get binary info
        let info = self.get_binary_info().await?;
        *self
            .binary_info
            .lock()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))? = Some(info.clone());

        info!(
            arch = %info.architecture,
            bits = info.bits,
            format = %info.format,
            "Binary opened successfully"
        );

        Ok(info)
    }

    #[instrument(skip(self), level = "info")]
    async fn close(&mut self) -> Result<()> {
        info!("Closing radare2 session");

        if let Some(mut pipe) = self
            .pipe
            .lock()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?
            .take()
        {
            pipe.close();
            debug!("Pipe closed");
        }

        *self
            .binary_path
            .lock()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))? = None;
        *self
            .binary_info
            .lock()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))? = None;

        info!("Session closed successfully");
        Ok(())
    }

    async fn get_binary_info(&self) -> Result<BinaryInfo> {
        if let Some(info) = self
            .binary_info
            .lock()
            .map_err(|e| Error::Internal(format!("Lock error: {}", e)))?
            .as_ref()
        {
            return Ok(info.clone());
        }

        // Get info JSON
        let info: R2Info = self.cmdj("ij")?;

        // Get sections
        let sections: Vec<R2Section> = self.cmdj("iSj").unwrap_or_default();

        let bin = info.bin.unwrap_or(R2BinInfo {
            arch: None,
            bits: None,
            bintype: None,
            endian: None,
            baddr: None,
        });

        Ok(BinaryInfo {
            path: info.core.and_then(|c| c.file).unwrap_or_default(),
            format: bin.bintype.unwrap_or_else(|| "unknown".into()),
            architecture: bin.arch.unwrap_or_else(|| "unknown".into()),
            bits: bin.bits.unwrap_or(64),
            endian: match bin.endian.as_deref() {
                Some("big") => Endianness::Big,
                _ => Endianness::Little,
            },
            entry_point: {
                let entry_str = self.cmd("ieq").unwrap_or_default();
                u64::from_str_radix(entry_str.trim().trim_start_matches("0x"), 16).unwrap_or(0)
            },
            base_address: bin.baddr.unwrap_or(0),
            sections: sections
                .into_iter()
                .map(|s| {
                    let perm = s.perm.unwrap_or_default();
                    SectionInfo {
                        name: s.name.unwrap_or_default(),
                        virtual_address: s.vaddr.unwrap_or(0),
                        virtual_size: s.vsize.unwrap_or(0),
                        raw_size: s.size.unwrap_or(0),
                        characteristics: s.flags.unwrap_or(0),
                        executable: perm.contains('x'),
                        writable: perm.contains('w'),
                        readable: perm.contains('r'),
                    }
                })
                .collect(),
        })
    }

    async fn list_functions(&self) -> Result<Vec<FunctionInfo>> {
        let funcs: Vec<R2Function> = self.cmdj("aflj")?;

        Ok(funcs
            .into_iter()
            .map(|f| {
                let is_external = f
                    .name
                    .as_ref()
                    .map(|n| n.starts_with("sym.imp."))
                    .unwrap_or(false);
                FunctionInfo {
                    name: f
                        .name
                        .unwrap_or_else(|| format!("fcn_{:x}", f.offset.unwrap_or(0))),
                    address: f.offset.unwrap_or(0),
                    end_address: f.offset.and_then(|o| f.size.map(|s| o + s)),
                    size: f.size,
                    is_external,
                    signature: f.signature,
                    calling_convention: f.cc,
                    attributes: HashMap::new(),
                }
            })
            .collect())
    }

    async fn get_function(&self, address: u64) -> Result<FunctionInfo> {
        // Seek to address and get function info
        self.cmd(&format!("s {}", address))?;
        let funcs: Vec<R2Function> = self.cmdj("afij")?;

        funcs
            .into_iter()
            .next()
            .map(|f| {
                let is_external = f
                    .name
                    .as_ref()
                    .map(|n| n.starts_with("sym.imp."))
                    .unwrap_or(false);
                FunctionInfo {
                    name: f.name.unwrap_or_else(|| format!("fcn_{:x}", address)),
                    address: f.offset.unwrap_or(address),
                    end_address: f.offset.and_then(|o| f.size.map(|s| o + s)),
                    size: f.size,
                    is_external,
                    signature: f.signature,
                    calling_convention: f.cc,
                    attributes: HashMap::new(),
                }
            })
            .ok_or(Error::InvalidAddress(address))
    }

    async fn get_function_by_name(&self, name: &str) -> Result<FunctionInfo> {
        let functions = self.list_functions().await?;
        functions
            .into_iter()
            .find(|f| f.name == name || f.name.ends_with(&format!(".{}", name)))
            .ok_or_else(|| Error::Analysis(format!("Function not found: {}", name)))
    }

    async fn disassemble(
        &self,
        address: u64,
        count: usize,
    ) -> Result<Vec<DisassembledInstruction>> {
        let instrs: Vec<R2Instruction> = self.cmdj(&format!("pdj {} @ {}", count, address))?;

        Ok(instrs
            .into_iter()
            .map(|i| {
                let bytes_str = i.bytes.unwrap_or_default();
                DisassembledInstruction {
                    address: i.offset.unwrap_or(0),
                    bytes: hex::decode(&bytes_str).unwrap_or_default(),
                    mnemonic: i
                        .opcode
                        .clone()
                        .unwrap_or_default()
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    operands: i
                        .opcode
                        .clone()
                        .unwrap_or_default()
                        .split_whitespace()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(" "),
                    disasm: i.disasm.or(i.opcode).unwrap_or_default(),
                    size: i.size.unwrap_or(0),
                    comment: i.comment,
                }
            })
            .collect())
    }

    async fn disassemble_function(&self, address: u64) -> Result<Vec<DisassembledInstruction>> {
        let instrs: Vec<R2Instruction> = self.cmdj(&format!("pdfj @ {}", address))?;

        Ok(instrs
            .into_iter()
            .map(|i| {
                let bytes_str = i.bytes.unwrap_or_default();
                DisassembledInstruction {
                    address: i.offset.unwrap_or(0),
                    bytes: hex::decode(&bytes_str).unwrap_or_default(),
                    mnemonic: i
                        .opcode
                        .clone()
                        .unwrap_or_default()
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    operands: i
                        .opcode
                        .clone()
                        .unwrap_or_default()
                        .split_whitespace()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(" "),
                    disasm: i.disasm.or(i.opcode).unwrap_or_default(),
                    size: i.size.unwrap_or(0),
                    comment: i.comment,
                }
            })
            .collect())
    }

    async fn get_basic_blocks(&self, function_address: u64) -> Result<Vec<BasicBlock>> {
        let blocks: Vec<R2BasicBlock> = self.cmdj(&format!("afbj @ {}", function_address))?;

        Ok(blocks
            .into_iter()
            .map(|b| {
                let addr = b.addr.unwrap_or(0);
                let size = b.size.unwrap_or(0);
                let mut successors = Vec::new();
                if let Some(j) = b.jump {
                    successors.push(j);
                }
                if let Some(f) = b.fail {
                    successors.push(f);
                }
                BasicBlock {
                    address: addr,
                    end_address: addr + size,
                    size,
                    successors,
                    predecessors: Vec::new(),
                }
            })
            .collect())
    }

    async fn decompile(&self, address: u64) -> Result<DecompiledFunction> {
        // Use r2ghidra or r2dec if available
        let code = self
            .cmd(&format!("pdg @ {}", address))
            .or_else(|_| self.cmd(&format!("pdd @ {}", address)))?;

        let func = self.get_function(address).await?;

        Ok(DecompiledFunction {
            name: func.name,
            address,
            code,
            language: "C".to_string(),
        })
    }

    async fn get_xrefs_to(&self, address: u64) -> Result<Vec<CrossReference>> {
        let xrefs: Vec<R2Xref> = self
            .cmdj(&format!("axtj @ {}", address))
            .unwrap_or_default();

        Ok(xrefs
            .into_iter()
            .map(|x| CrossReference {
                from: x.from.unwrap_or(0),
                to: address,
                xref_type: match x.xref_type.as_deref() {
                    Some("CALL") | Some("call") => XRefType::Call,
                    Some("JMP") | Some("jmp") => XRefType::Jump,
                    Some("DATA") | Some("data") => XRefType::Read,
                    _ => XRefType::Unknown,
                },
            })
            .collect())
    }

    async fn get_xrefs_from(&self, address: u64) -> Result<Vec<CrossReference>> {
        let xrefs: Vec<R2Xref> = self
            .cmdj(&format!("axfj @ {}", address))
            .unwrap_or_default();

        Ok(xrefs
            .into_iter()
            .map(|x| CrossReference {
                from: address,
                to: x.to.unwrap_or(0),
                xref_type: match x.xref_type.as_deref() {
                    Some("CALL") | Some("call") => XRefType::Call,
                    Some("JMP") | Some("jmp") => XRefType::Jump,
                    Some("DATA") | Some("data") => XRefType::Read,
                    _ => XRefType::Unknown,
                },
            })
            .collect())
    }

    async fn list_strings(&self, min_length: usize) -> Result<Vec<BinaryString>> {
        // Configure minimum string length
        self.cmd(&format!("e bin.minstr={}", min_length))?;

        let strings: Vec<R2String> = self.cmdj("izj")?;

        Ok(strings
            .into_iter()
            .filter_map(|s| {
                Some(BinaryString {
                    address: s.vaddr.or(s.paddr)?,
                    value: s.string?,
                    string_type: match s.string_type.as_deref() {
                        Some("ascii") => StringType::Ascii,
                        Some("utf8") => StringType::Utf8,
                        Some("utf16le") => StringType::Utf16Le,
                        Some("utf16be") => StringType::Utf16Be,
                        _ => StringType::Unknown,
                    },
                    length: s.length.unwrap_or(0),
                })
            })
            .collect())
    }

    async fn list_imports(&self) -> Result<Vec<ImportInfo>> {
        let imports: Vec<R2Import> = self.cmdj("iij")?;

        Ok(imports
            .into_iter()
            .map(|i| ImportInfo {
                name: i.name.unwrap_or_default(),
                library: i.libname.unwrap_or_default(),
                address: i.plt.unwrap_or(0),
                ordinal: i.ordinal,
            })
            .collect())
    }

    async fn list_exports(&self) -> Result<Vec<ExportInfo>> {
        let exports: Vec<R2Export> = self.cmdj("iEj")?;

        Ok(exports
            .into_iter()
            .map(|e| ExportInfo {
                name: e.name.unwrap_or_default(),
                address: e.vaddr.or(e.paddr).unwrap_or(0),
                ordinal: e.ordinal,
                forwarded: None,
            })
            .collect())
    }

    async fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let hex_str = self.cmd(&format!("p8 {} @ {}", size, address))?;
        hex::decode(hex_str.trim()).map_err(|e: hex::FromHexError| Error::Parse(e.to_string()))
    }

    async fn rename(&self, address: u64, new_name: &str) -> Result<()> {
        self.cmd(&format!("afn {} @ {}", new_name, address))?;
        Ok(())
    }

    async fn add_comment(&self, address: u64, comment: &str) -> Result<()> {
        self.cmd(&format!("CC {} @ {}", comment, address))?;
        Ok(())
    }

    async fn raw_command(&mut self, command: &str) -> Result<String> {
        self.cmd(command)
    }
}

impl Drop for Radare2Backend {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.pipe.lock() {
            if let Some(mut pipe) = guard.take() {
                pipe.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_creation() {
        let backend = Radare2Backend::new();
        assert!(!backend.is_connected());
        assert_eq!(backend.name(), "Radare2");
    }

    #[test]
    fn test_backend_default() {
        let backend = Radare2Backend::default();
        assert!(!backend.is_connected());
        assert_eq!(backend.name(), "Radare2");
    }

    #[test]
    fn test_backend_type_parsing() {
        assert_eq!(
            "radare2".parse::<BackendType>().unwrap(),
            BackendType::Radare2
        );
        assert_eq!("r2".parse::<BackendType>().unwrap(), BackendType::Radare2);
        assert_eq!(
            "radare".parse::<BackendType>().unwrap(),
            BackendType::Radare2
        );
    }

    #[test]
    fn test_backend_type_display() {
        assert_eq!(format!("{}", BackendType::Radare2), "Radare2");
    }

    #[test]
    fn test_cmd_on_disconnected() {
        let backend = Radare2Backend::new();
        let result = backend.cmd("?");
        assert!(result.is_err());
        match result {
            Err(Error::Connection(_)) => {}
            _ => panic!("Expected Connection error"),
        }
    }

    #[test]
    fn test_cmd_empty_command() {
        let backend = Radare2Backend::new();
        // First we need to be "connected" to test empty command validation
        // But since we're not connected, we'll get Connection error first
        let result = backend.cmd("");
        assert!(result.is_err());
    }

    #[test]
    fn test_xref_type_serialization() {
        let xref = CrossReference {
            from: 0x1000,
            to: 0x2000,
            xref_type: XRefType::Call,
        };
        let json = serde_json::to_string(&xref).unwrap();
        assert!(json.contains("Call"));
    }

    #[test]
    fn test_string_type_serialization() {
        let s = BinaryString {
            address: 0x1000,
            value: "test".to_string(),
            string_type: StringType::Ascii,
            length: 4,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("Ascii"));
    }

    #[test]
    fn test_function_info_default_attributes() {
        let func = FunctionInfo {
            name: "test".to_string(),
            address: 0x1000,
            end_address: Some(0x1100),
            size: Some(256),
            is_external: false,
            signature: None,
            calling_convention: None,
            attributes: std::collections::HashMap::new(),
        };
        assert!(func.attributes.is_empty());
    }

    #[test]
    fn test_section_info_permissions() {
        let section = SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_size: 0x1000,
            characteristics: 0,
            executable: true,
            writable: false,
            readable: true,
        };
        assert!(section.executable);
        assert!(section.readable);
        assert!(!section.writable);
    }

    #[test]
    fn test_endianness_serialization() {
        let little = Endianness::Little;
        let big = Endianness::Big;
        assert_eq!(serde_json::to_string(&little).unwrap(), "\"Little\"");
        assert_eq!(serde_json::to_string(&big).unwrap(), "\"Big\"");
    }

    #[test]
    fn test_backend_config_default() {
        let config = BackendConfig::default();
        assert_eq!(config.backend_type, BackendType::Radare2);
        assert!(config.tool_path.is_none());
        assert!(config.host.is_none());
        assert!(config.port.is_none());
        assert!(config.options.is_empty());
    }

    #[test]
    fn test_basic_block_structure() {
        let block = BasicBlock {
            address: 0x1000,
            end_address: 0x1020,
            size: 32,
            successors: vec![0x1020, 0x1050],
            predecessors: vec![0x0F00],
        };
        assert_eq!(block.successors.len(), 2);
        assert_eq!(block.predecessors.len(), 1);
    }

    #[test]
    fn test_decompiled_function() {
        let decomp = DecompiledFunction {
            name: "main".to_string(),
            address: 0x1000,
            code: "int main() { return 0; }".to_string(),
            language: "C".to_string(),
        };
        assert_eq!(decomp.language, "C");
        assert!(decomp.code.contains("main"));
    }

    #[test]
    fn test_import_info() {
        let import = ImportInfo {
            name: "printf".to_string(),
            library: "libc.so.6".to_string(),
            address: 0x1000,
            ordinal: Some(1),
        };
        assert_eq!(import.name, "printf");
        assert!(import.ordinal.is_some());
    }

    #[test]
    fn test_export_info() {
        let export = ExportInfo {
            name: "my_function".to_string(),
            address: 0x2000,
            ordinal: None,
            forwarded: None,
        };
        assert!(export.ordinal.is_none());
        assert!(export.forwarded.is_none());
    }
}
