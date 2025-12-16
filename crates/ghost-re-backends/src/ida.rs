//! IDA Pro backend implementation using idalib
//!
//! This module provides a backend for communicating with IDA Pro using the
//! `idalib` crate. It requires IDA Pro v9.x to be installed and the `IDADIR`
//! environment variable to be set.
//!
//! # Requirements
//!
//! - IDA Pro v9.x installation
//! - `IDADIR` environment variable pointing to IDA installation
//! - LLVM/Clang for building (idalib uses bindgen)
//!
//! # Platform Support
//!
//! - Windows (with MSVC or MinGW)
//! - Linux
//! - macOS

use crate::common::*;
use crate::error::{Error, Result};
use idalib::idb::IDB;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

/// IDA Pro backend using idalib
pub struct IdaBackend {
    idb: Arc<RwLock<Option<IDB>>>,
    binary_path: Arc<RwLock<Option<String>>>,
    binary_info: Arc<RwLock<Option<BinaryInfo>>>,
}

impl IdaBackend {
    /// Create a new IDA backend instance
    ///
    /// Note: This does NOT initialize the IDA library. Call `open()` to load a binary.
    pub fn new() -> Result<Self> {
        // Initialize IDA library
        idalib::ida::init().map_err(|e| {
            Error::BackendNotAvailable(format!("Failed to initialize IDA: {:?}", e))
        })?;

        Ok(Self {
            idb: Arc::new(RwLock::new(None)),
            binary_path: Arc::new(RwLock::new(None)),
            binary_info: Arc::new(RwLock::new(None)),
        })
    }

    /// Helper to get IDB or return error
    async fn get_idb(&self) -> Result<tokio::sync::RwLockReadGuard<'_, Option<IDB>>> {
        let guard = self.idb.read().await;
        if guard.is_none() {
            return Err(Error::Connection("No IDB loaded".into()));
        }
        Ok(guard)
    }
}

impl Default for IdaBackend {
    fn default() -> Self {
        Self::new().expect("Failed to initialize IDA backend")
    }
}

impl ReBackend for IdaBackend {
    fn name(&self) -> &'static str {
        "IDA Pro"
    }

    fn is_connected(&self) -> bool {
        // Check synchronously using try_read
        self.idb.try_read().map(|g| g.is_some()).unwrap_or(false)
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

        info!(path = path, "Opening binary with IDA Pro");

        // Open the IDB
        let idb = IDB::open(path)
            .map_err(|e| Error::Connection(format!("Failed to open IDB: {:?}", e)))?;

        *self.idb.write().await = Some(idb);
        *self.binary_path.write().await = Some(path.to_string());

        // Get binary info
        let info = self.get_binary_info().await?;
        *self.binary_info.write().await = Some(info.clone());

        info!(
            arch = %info.architecture,
            bits = info.bits,
            format = %info.format,
            "Binary opened successfully with IDA"
        );

        Ok(info)
    }

    #[instrument(skip(self), level = "info")]
    async fn close(&mut self) -> Result<()> {
        info!("Closing IDA session");

        *self.idb.write().await = None;
        *self.binary_path.write().await = None;
        *self.binary_info.write().await = None;

        info!("IDA session closed");
        Ok(())
    }

    async fn get_binary_info(&self) -> Result<BinaryInfo> {
        if let Some(info) = self.binary_info.read().await.as_ref() {
            return Ok(info.clone());
        }

        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        // Get processor info
        let proc_name = idb
            .processor()
            .map(|p| p.name().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let bits = if idb.is_64bit() { 64 } else { 32 };

        // Get segments/sections
        let mut sections = Vec::new();
        if let Ok(segs) = idb.segments() {
            for seg in segs {
                if let (Ok(name), Ok(start), Ok(end), Ok(perm)) =
                    (seg.name(), seg.start_ea(), seg.end_ea(), seg.perm())
                {
                    sections.push(SectionInfo {
                        name: name.to_string(),
                        virtual_address: start,
                        virtual_size: end - start,
                        raw_size: end - start,
                        characteristics: perm as u32,
                        executable: (perm & 1) != 0, // SEGPERM_EXEC
                        writable: (perm & 2) != 0,   // SEGPERM_WRITE
                        readable: (perm & 4) != 0,   // SEGPERM_READ
                    });
                }
            }
        }

        let path = self.binary_path.read().await.clone().unwrap_or_default();
        let entry = idb.entry_point().unwrap_or(0);
        let base = idb.min_ea().unwrap_or(0);

        Ok(BinaryInfo {
            path,
            format: "IDB".to_string(),
            architecture: proc_name,
            bits,
            endian: Endianness::Little, // IDA doesn't easily expose this
            entry_point: entry,
            base_address: base,
            sections,
        })
    }

    async fn list_functions(&self) -> Result<Vec<FunctionInfo>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let mut functions = Vec::new();

        if let Ok(funcs) = idb.functions() {
            for func in funcs {
                if let (Ok(name), Ok(start), Ok(end)) =
                    (func.name(), func.start_ea(), func.end_ea())
                {
                    functions.push(FunctionInfo {
                        name: name.to_string(),
                        address: start,
                        end_address: Some(end),
                        size: Some(end - start),
                        is_external: name.starts_with("__imp_") || name.starts_with("j_"),
                        signature: func.type_().ok().map(|t| t.to_string()),
                        calling_convention: None,
                        attributes: HashMap::new(),
                    });
                }
            }
        }

        Ok(functions)
    }

    async fn get_function(&self, address: u64) -> Result<FunctionInfo> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let func = idb
            .function_at(address)
            .map_err(|_| Error::InvalidAddress(address))?;

        let name = func.name().map_err(|_| Error::InvalidAddress(address))?;
        let start = func
            .start_ea()
            .map_err(|_| Error::InvalidAddress(address))?;
        let end = func.end_ea().map_err(|_| Error::InvalidAddress(address))?;

        Ok(FunctionInfo {
            name: name.to_string(),
            address: start,
            end_address: Some(end),
            size: Some(end - start),
            is_external: name.starts_with("__imp_") || name.starts_with("j_"),
            signature: func.type_().ok().map(|t| t.to_string()),
            calling_convention: None,
            attributes: HashMap::new(),
        })
    }

    async fn get_function_by_name(&self, name: &str) -> Result<FunctionInfo> {
        let functions = self.list_functions().await?;
        functions
            .into_iter()
            .find(|f| f.name == name || f.name.ends_with(&format!("_{}", name)))
            .ok_or_else(|| Error::Analysis(format!("Function not found: {}", name)))
    }

    async fn disassemble(
        &self,
        address: u64,
        count: usize,
    ) -> Result<Vec<DisassembledInstruction>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let mut instructions = Vec::new();
        let mut ea = address;

        for _ in 0..count {
            if let Ok(insn) = idb.insn_at(ea) {
                let mnem = insn.mnemonic().unwrap_or_default().to_string();
                let size = insn.size() as u64;
                let bytes = idb.read_bytes(ea, size as usize).unwrap_or_default();

                instructions.push(DisassembledInstruction {
                    address: ea,
                    bytes,
                    mnemonic: mnem.clone(),
                    operands: insn.operands_str().unwrap_or_default(),
                    disasm: format!("{} {}", mnem, insn.operands_str().unwrap_or_default()),
                    size,
                    comment: idb.get_cmt(ea, false).ok(),
                });

                ea += size;
            } else {
                break;
            }
        }

        Ok(instructions)
    }

    async fn disassemble_function(&self, address: u64) -> Result<Vec<DisassembledInstruction>> {
        let func = self.get_function(address).await?;
        let size = func.size.unwrap_or(4096);
        let count = (size / 4) as usize; // Approximate instruction count
        self.disassemble(address, count.max(100)).await
    }

    async fn get_basic_blocks(&self, function_address: u64) -> Result<Vec<BasicBlock>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let func = idb
            .function_at(function_address)
            .map_err(|_| Error::InvalidAddress(function_address))?;

        let mut blocks = Vec::new();

        if let Ok(flowchart) = func.flowchart() {
            for bb in flowchart {
                if let (Ok(start), Ok(end)) = (bb.start_ea(), bb.end_ea()) {
                    let mut successors = Vec::new();
                    if let Ok(succs) = bb.succs() {
                        for s in succs {
                            if let Ok(saddr) = s.start_ea() {
                                successors.push(saddr);
                            }
                        }
                    }

                    let mut predecessors = Vec::new();
                    if let Ok(preds) = bb.preds() {
                        for p in preds {
                            if let Ok(paddr) = p.start_ea() {
                                predecessors.push(paddr);
                            }
                        }
                    }

                    blocks.push(BasicBlock {
                        address: start,
                        end_address: end,
                        size: end - start,
                        successors,
                        predecessors,
                    });
                }
            }
        }

        Ok(blocks)
    }

    async fn decompile(&self, address: u64) -> Result<DecompiledFunction> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let func = idb
            .function_at(address)
            .map_err(|_| Error::InvalidAddress(address))?;

        let name = func.name().unwrap_or_else(|_| format!("sub_{:x}", address));

        // Try to get decompiled code via Hex-Rays
        let code = match func.decompile() {
            Ok(cfunc) => cfunc.to_string(),
            Err(_) => {
                // Fall back to disassembly
                warn!("Hex-Rays decompilation not available, returning disassembly");
                let instrs = self.disassemble_function(address).await?;
                instrs
                    .iter()
                    .map(|i| format!("  {:08x}: {}", i.address, i.disasm))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        };

        Ok(DecompiledFunction {
            name,
            address,
            code,
            language: "C".to_string(),
        })
    }

    async fn get_xrefs_to(&self, address: u64) -> Result<Vec<CrossReference>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let mut xrefs = Vec::new();

        if let Ok(refs) = idb.xrefs_to(address) {
            for xref in refs {
                if let (Ok(from), Ok(xtype)) = (xref.from(), xref.type_()) {
                    xrefs.push(CrossReference {
                        from,
                        to: address,
                        xref_type: match xtype {
                            0..=3 => XRefType::Data,
                            16..=21 => XRefType::Call,
                            _ => XRefType::Unknown,
                        },
                    });
                }
            }
        }

        Ok(xrefs)
    }

    async fn get_xrefs_from(&self, address: u64) -> Result<Vec<CrossReference>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let mut xrefs = Vec::new();

        if let Ok(refs) = idb.xrefs_from(address) {
            for xref in refs {
                if let (Ok(to), Ok(xtype)) = (xref.to(), xref.type_()) {
                    xrefs.push(CrossReference {
                        from: address,
                        to,
                        xref_type: match xtype {
                            0..=3 => XRefType::Data,
                            16..=21 => XRefType::Call,
                            _ => XRefType::Unknown,
                        },
                    });
                }
            }
        }

        Ok(xrefs)
    }

    async fn list_strings(&self, min_length: usize) -> Result<Vec<BinaryString>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let mut strings = Vec::new();

        if let Ok(strs) = idb.strings() {
            for s in strs {
                if let (Ok(ea), Ok(value), Ok(len)) = (s.ea(), s.str(), s.length()) {
                    if len >= min_length {
                        strings.push(BinaryString {
                            address: ea,
                            value: value.to_string(),
                            string_type: StringType::Unknown,
                            length: len,
                        });
                    }
                }
            }
        }

        Ok(strings)
    }

    async fn list_imports(&self) -> Result<Vec<ImportInfo>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let mut imports = Vec::new();

        if let Ok(imps) = idb.imports() {
            for imp in imps {
                if let (Ok(name), Ok(ea)) = (imp.name(), imp.ea()) {
                    imports.push(ImportInfo {
                        name: name.to_string(),
                        library: imp.module().ok().unwrap_or_default(),
                        address: ea,
                        ordinal: imp.ordinal().ok(),
                    });
                }
            }
        }

        Ok(imports)
    }

    async fn list_exports(&self) -> Result<Vec<ExportInfo>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        let mut exports = Vec::new();

        if let Ok(exps) = idb.exports() {
            for exp in exps {
                if let (Ok(name), Ok(ea)) = (exp.name(), exp.ea()) {
                    exports.push(ExportInfo {
                        name: name.to_string(),
                        address: ea,
                        ordinal: exp.ordinal().ok(),
                        forwarded: None,
                    });
                }
            }
        }

        Ok(exports)
    }

    async fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        idb.read_bytes(address, size)
            .map_err(|e| Error::Analysis(format!("Failed to read bytes: {:?}", e)))
    }

    async fn rename(&self, address: u64, new_name: &str) -> Result<()> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        idb.set_name(address, new_name)
            .map_err(|e| Error::Analysis(format!("Failed to rename: {:?}", e)))
    }

    async fn add_comment(&self, address: u64, comment: &str) -> Result<()> {
        let guard = self.get_idb().await?;
        let idb = guard.as_ref().unwrap();

        idb.set_cmt(address, comment, false)
            .map_err(|e| Error::Analysis(format!("Failed to add comment: {:?}", e)))
    }

    async fn raw_command(&mut self, _command: &str) -> Result<String> {
        // IDA doesn't have a raw command interface like r2
        Err(Error::BackendNotAvailable(
            "Raw commands not supported in IDA backend. Use IDC/IDAPython via IDA directly.".into(),
        ))
    }
}

impl Drop for IdaBackend {
    fn drop(&mut self) {
        // IDA cleanup is handled by idalib
        debug!("IDA backend dropped");
    }
}
