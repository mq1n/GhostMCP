//! Ghidra backend implementation
//!
//! This module provides two approaches for Ghidra integration:
//!
//! 1. **Headless Mode** - Spawns Ghidra's `analyzeHeadless` to analyze binaries
//!    and export results to JSON files which are then parsed.
//!
//! 2. **ghidra-pipe JSON-RPC** - Connects to a running ghidra-pipe server
//!    which exposes Ghidra's API over TCP + JSON-RPC v2.
//!
//! # Requirements
//!
//! - Ghidra installation (10.x or later recommended)
//! - `GHIDRA_INSTALL_DIR` environment variable pointing to Ghidra installation
//! - For JSON-RPC mode: ghidra-pipe plugin installed and server running
//!
//! # Platform Support
//!
//! - Windows (full support)
//! - Linux (full support)
//! - macOS (full support)

use crate::common::*;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

/// Connection mode for Ghidra backend
#[derive(Debug, Clone, Default)]
pub enum GhidraMode {
    /// Use Ghidra Headless analyzer (spawns process)
    #[default]
    Headless,
    /// Connect to ghidra-pipe JSON-RPC server
    JsonRpc { host: String, port: u16 },
}

/// JSON-RPC request structure
#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    params: serde_json::Value,
}

/// JSON-RPC response structure
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    #[allow(dead_code)]
    code: i32,
    message: String,
}

/// Ghidra backend supporting both Headless and JSON-RPC modes
pub struct GhidraBackend {
    mode: GhidraMode,
    ghidra_dir: Option<PathBuf>,
    project_dir: PathBuf,
    binary_path: Arc<RwLock<Option<String>>>,
    binary_info: Arc<RwLock<Option<BinaryInfo>>>,
    analysis_cache: Arc<RwLock<Option<AnalysisCache>>>,
    rpc_stream: Arc<RwLock<Option<TcpStream>>>,
    request_id: AtomicU64,
}

/// Cached analysis data from Ghidra (for Headless mode)
#[derive(Debug, Clone, Default)]
struct AnalysisCache {
    functions: Vec<FunctionInfo>,
    strings: Vec<BinaryString>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
}

/// Ghidra export script output format
#[derive(Debug, Deserialize)]
struct GhidraExport {
    binary_info: Option<ExportedBinaryInfo>,
    functions: Option<Vec<ExportedFunction>>,
    strings: Option<Vec<ExportedString>>,
    imports: Option<Vec<ExportedImport>>,
    exports: Option<Vec<ExportedExport>>,
}

#[derive(Debug, Deserialize)]
struct ExportedBinaryInfo {
    #[allow(dead_code)]
    name: String,
    format: String,
    architecture: String,
    bits: u32,
    endian: String,
    entry_point: String,
    base_address: String,
    #[serde(default)]
    sections: Vec<ExportedSection>,
}

#[derive(Debug, Deserialize)]
struct ExportedSection {
    name: String,
    start: String,
    size: String,
    permissions: String,
}

#[derive(Debug, Deserialize)]
struct ExportedFunction {
    name: String,
    address: String,
    size: Option<String>,
    #[serde(default)]
    is_external: bool,
    signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportedString {
    address: String,
    value: String,
    length: usize,
}

#[derive(Debug, Deserialize)]
struct ExportedImport {
    name: String,
    library: String,
    address: String,
}

#[derive(Debug, Deserialize)]
struct ExportedExport {
    name: String,
    address: String,
}

impl GhidraBackend {
    /// Create a new Ghidra backend in Headless mode
    pub fn new() -> Result<Self> {
        Self::with_mode(GhidraMode::Headless)
    }

    /// Create a Ghidra backend with specified mode
    pub fn with_mode(mode: GhidraMode) -> Result<Self> {
        let ghidra_dir = std::env::var("GHIDRA_INSTALL_DIR")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.exists());

        if ghidra_dir.is_none() && matches!(mode, GhidraMode::Headless) {
            warn!("GHIDRA_INSTALL_DIR not set or invalid - Headless mode may not work");
        }

        let project_dir = std::env::temp_dir().join("ghost-ghidra-projects");
        std::fs::create_dir_all(&project_dir)
            .map_err(|e| Error::Internal(format!("Failed to create project dir: {}", e)))?;

        Ok(Self {
            mode,
            ghidra_dir,
            project_dir,
            binary_path: Arc::new(RwLock::new(None)),
            binary_info: Arc::new(RwLock::new(None)),
            analysis_cache: Arc::new(RwLock::new(None)),
            rpc_stream: Arc::new(RwLock::new(None)),
            request_id: AtomicU64::new(1),
        })
    }

    /// Create a Ghidra backend connected to ghidra-pipe server
    pub fn connect_rpc(host: &str, port: u16) -> Result<Self> {
        let backend = Self::with_mode(GhidraMode::JsonRpc {
            host: host.to_string(),
            port,
        })?;

        // Try to connect immediately
        backend.ensure_rpc_connection()?;

        Ok(backend)
    }

    /// Get Ghidra headless analyzer path
    fn get_headless_path(&self) -> Result<PathBuf> {
        let ghidra_dir = self.ghidra_dir.as_ref().ok_or_else(|| {
            Error::BackendNotAvailable(
                "GHIDRA_INSTALL_DIR not set. Please set it to your Ghidra installation path."
                    .into(),
            )
        })?;

        #[cfg(windows)]
        let script_name = "analyzeHeadless.bat";
        #[cfg(not(windows))]
        let script_name = "analyzeHeadless";

        let headless_path = ghidra_dir.join("support").join(script_name);

        if !headless_path.exists() {
            return Err(Error::BackendNotAvailable(format!(
                "Ghidra headless analyzer not found at: {}",
                headless_path.display()
            )));
        }

        Ok(headless_path)
    }

    /// Ensure JSON-RPC connection is established
    fn ensure_rpc_connection(&self) -> Result<()> {
        if let GhidraMode::JsonRpc { ref host, port } = self.mode {
            let mut stream_guard = self
                .rpc_stream
                .try_write()
                .map_err(|_| Error::Connection("Failed to acquire RPC lock".into()))?;

            if stream_guard.is_none() {
                info!(host = %host, port = port, "Connecting to ghidra-pipe server");
                let stream = TcpStream::connect((host.as_str(), port)).map_err(|e| {
                    Error::Connection(format!("Failed to connect to ghidra-pipe: {}", e))
                })?;
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                    .ok();
                stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                    .ok();
                *stream_guard = Some(stream);
                info!("Connected to ghidra-pipe server");
            }
        }
        Ok(())
    }

    /// Send JSON-RPC request and get response
    fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let stream_guard = self
            .rpc_stream
            .try_read()
            .map_err(|_| Error::Connection("Failed to acquire RPC lock".into()))?;

        let stream = stream_guard
            .as_ref()
            .ok_or_else(|| Error::Connection("Not connected to ghidra-pipe".into()))?;

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: self.request_id.fetch_add(1, Ordering::SeqCst),
            method: method.to_string(),
            params,
        };

        let request_json = serde_json::to_string(&request)
            .map_err(|e| Error::Internal(format!("Failed to serialize request: {}", e)))?;

        debug!(method = method, "Sending JSON-RPC request");

        // Write request
        let mut stream_clone = stream
            .try_clone()
            .map_err(|e| Error::Connection(format!("Failed to clone stream: {}", e)))?;

        writeln!(stream_clone, "{}", request_json)
            .map_err(|e| Error::Connection(format!("Failed to send request: {}", e)))?;
        stream_clone
            .flush()
            .map_err(|e| Error::Connection(format!("Failed to flush: {}", e)))?;

        // Read response
        let mut reader = BufReader::new(stream_clone);
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|e| Error::Connection(format!("Failed to read response: {}", e)))?;

        let response: JsonRpcResponse = serde_json::from_str(&response_line)
            .map_err(|e| Error::Internal(format!("Failed to parse response: {}", e)))?;

        if let Some(err) = response.error {
            return Err(Error::Analysis(err.message));
        }

        response
            .result
            .ok_or_else(|| Error::Internal("Empty response from ghidra-pipe".into()))
    }

    /// Run Ghidra Headless analyzer on binary
    async fn run_headless_analysis(&self, binary_path: &str) -> Result<GhidraExport> {
        let headless = self.get_headless_path()?;
        let binary_name = Path::new(binary_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("binary");

        let project_name = format!("ghost_{}", binary_name);
        let export_path = self
            .project_dir
            .join(format!("{}_export.json", binary_name));

        // Create export script inline (Ghidra Python/Jython)
        let script_path = self.project_dir.join("ghost_export.py");
        let export_script = r#"
# Ghost-MCP Ghidra Export Script
import json
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.app.decompiler import DecompInterface

def get_binary_info():
    prog = getCurrentProgram()
    lang = prog.getLanguage()
    memory = prog.getMemory()
    
    sections = []
    for block in memory.getBlocks():
        perms = ""
        if block.isRead(): perms += "r"
        if block.isWrite(): perms += "w"  
        if block.isExecute(): perms += "x"
        sections.append({
            "name": block.getName(),
            "start": "0x%x" % block.getStart().getOffset(),
            "size": "0x%x" % block.getSize(),
            "permissions": perms
        })
    
    return {
        "name": prog.getName(),
        "format": prog.getExecutableFormat(),
        "architecture": lang.getProcessor().toString(),
        "bits": lang.getLanguageDescription().getSize(),
        "endian": "big" if lang.isBigEndian() else "little",
        "entry_point": "0x%x" % (prog.getSymbolTable().getExternalEntryPointIterator().next().getOffset() if prog.getSymbolTable().getExternalEntryPointIterator().hasNext() else 0),
        "base_address": "0x%x" % prog.getImageBase().getOffset(),
        "sections": sections
    }

def get_functions():
    funcs = []
    fm = getCurrentProgram().getFunctionManager()
    for func in fm.getFunctions(True):
        funcs.append({
            "name": func.getName(),
            "address": "0x%x" % func.getEntryPoint().getOffset(),
            "size": "0x%x" % func.getBody().getNumAddresses() if func.getBody() else None,
            "is_external": func.isExternal(),
            "signature": func.getSignature().getPrototypeString() if func.getSignature() else None
        })
    return funcs

def get_strings():
    strings = []
    data_iter = getCurrentProgram().getListing().getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if data.hasStringValue():
            try:
                val = data.getValue()
                if val and len(str(val)) >= 4:
                    strings.append({
                        "address": "0x%x" % data.getAddress().getOffset(),
                        "value": str(val),
                        "length": len(str(val))
                    })
            except: pass
    return strings

def get_imports():
    imports = []
    st = getCurrentProgram().getSymbolTable()
    for sym in st.getExternalSymbols():
        if sym.getSymbolType() == SymbolType.FUNCTION:
            imports.append({
                "name": sym.getName(),
                "library": sym.getParentNamespace().getName() if sym.getParentNamespace() else "",
                "address": "0x%x" % sym.getAddress().getOffset()
            })
    return imports

def get_exports():
    exports = []
    st = getCurrentProgram().getSymbolTable()
    for sym in st.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            exports.append({
                "name": sym.getName(),
                "address": "0x%x" % sym.getAddress().getOffset()
            })
    return exports

# Main export
export_data = {
    "binary_info": get_binary_info(),
    "functions": get_functions(),
    "strings": get_strings(),
    "imports": get_imports(),
    "exports": get_exports()
}

# Write to file (path passed via script args)
import os
output_path = os.environ.get("GHOST_EXPORT_PATH", "export.json")
with open(output_path, "w") as f:
    json.dump(export_data, f, indent=2)

print("Export complete: " + output_path)
"#;

        std::fs::write(&script_path, export_script)
            .map_err(|e| Error::Internal(format!("Failed to write export script: {}", e)))?;

        info!(binary = binary_path, "Running Ghidra headless analysis");

        // Build command
        let mut cmd = Command::new(&headless);
        cmd.arg(&self.project_dir)
            .arg(&project_name)
            .arg("-import")
            .arg(binary_path)
            .arg("-postScript")
            .arg(&script_path)
            .arg("-scriptPath")
            .arg(&self.project_dir)
            .arg("-deleteProject") // Clean up after export
            .env("GHOST_EXPORT_PATH", &export_path);

        debug!(cmd = ?cmd, "Executing Ghidra headless");

        let output = cmd
            .output()
            .map_err(|e| Error::BackendNotAvailable(format!("Failed to run Ghidra: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(stderr = %stderr, "Ghidra headless failed");
            return Err(Error::Analysis(format!(
                "Ghidra analysis failed: {}",
                stderr
            )));
        }

        // Read export file
        let export_json = std::fs::read_to_string(&export_path)
            .map_err(|e| Error::Internal(format!("Failed to read export: {}", e)))?;

        let export: GhidraExport = serde_json::from_str(&export_json)
            .map_err(|e| Error::Internal(format!("Failed to parse export: {}", e)))?;

        // Clean up
        let _ = std::fs::remove_file(&export_path);
        let _ = std::fs::remove_file(&script_path);

        info!("Ghidra headless analysis complete");
        Ok(export)
    }

    /// Parse hex address string to u64
    fn parse_addr(s: &str) -> u64 {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(s, 16).unwrap_or(0)
    }

    /// Convert exported data to internal format
    fn convert_export(
        &self,
        export: GhidraExport,
        path: &str,
    ) -> Result<(BinaryInfo, AnalysisCache)> {
        let info_export = export
            .binary_info
            .ok_or_else(|| Error::Analysis("No binary info in export".into()))?;

        let sections: Vec<SectionInfo> = info_export
            .sections
            .iter()
            .map(|s| {
                let perms = &s.permissions;
                SectionInfo {
                    name: s.name.clone(),
                    virtual_address: Self::parse_addr(&s.start),
                    virtual_size: Self::parse_addr(&s.size),
                    raw_size: Self::parse_addr(&s.size),
                    characteristics: 0,
                    readable: perms.contains('r'),
                    writable: perms.contains('w'),
                    executable: perms.contains('x'),
                }
            })
            .collect();

        let binary_info = BinaryInfo {
            path: path.to_string(),
            format: info_export.format,
            architecture: info_export.architecture,
            bits: info_export.bits,
            endian: if info_export.endian == "big" {
                Endianness::Big
            } else {
                Endianness::Little
            },
            entry_point: Self::parse_addr(&info_export.entry_point),
            base_address: Self::parse_addr(&info_export.base_address),
            sections,
        };

        let functions: Vec<FunctionInfo> = export
            .functions
            .unwrap_or_default()
            .into_iter()
            .map(|f| FunctionInfo {
                name: f.name,
                address: Self::parse_addr(&f.address),
                end_address: None,
                size: f.size.map(|s| Self::parse_addr(&s)),
                is_external: f.is_external,
                signature: f.signature,
                calling_convention: None,
                attributes: HashMap::new(),
            })
            .collect();

        let strings: Vec<BinaryString> = export
            .strings
            .unwrap_or_default()
            .into_iter()
            .map(|s| BinaryString {
                address: Self::parse_addr(&s.address),
                value: s.value,
                string_type: StringType::Unknown,
                length: s.length,
            })
            .collect();

        let imports: Vec<ImportInfo> = export
            .imports
            .unwrap_or_default()
            .into_iter()
            .map(|i| ImportInfo {
                name: i.name,
                library: i.library,
                address: Self::parse_addr(&i.address),
                ordinal: None,
            })
            .collect();

        let exports: Vec<ExportInfo> = export
            .exports
            .unwrap_or_default()
            .into_iter()
            .map(|e| ExportInfo {
                name: e.name,
                address: Self::parse_addr(&e.address),
                ordinal: None,
                forwarded: None,
            })
            .collect();

        let cache = AnalysisCache {
            functions,
            strings,
            imports,
            exports,
        };

        Ok((binary_info, cache))
    }
}

impl Default for GhidraBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create Ghidra backend")
    }
}

impl ReBackend for GhidraBackend {
    fn name(&self) -> &'static str {
        "Ghidra"
    }

    fn is_connected(&self) -> bool {
        match &self.mode {
            GhidraMode::Headless => self
                .binary_path
                .try_read()
                .map(|p| p.is_some())
                .unwrap_or(false),
            GhidraMode::JsonRpc { .. } => self
                .rpc_stream
                .try_read()
                .map(|s| s.is_some())
                .unwrap_or(false),
        }
    }

    #[instrument(skip(self), level = "info")]
    async fn open(&mut self, path: &str) -> Result<BinaryInfo> {
        if path.trim().is_empty() {
            return Err(Error::FileNotFound("Empty path".into()));
        }

        let file_path = Path::new(path);
        if !file_path.exists() {
            return Err(Error::FileNotFound(path.to_string()));
        }

        info!(path = path, mode = ?self.mode, "Opening binary with Ghidra");

        match &self.mode {
            GhidraMode::Headless => {
                let export = self.run_headless_analysis(path).await?;
                let (info, cache) = self.convert_export(export, path)?;

                *self.binary_path.write().await = Some(path.to_string());
                *self.binary_info.write().await = Some(info.clone());
                *self.analysis_cache.write().await = Some(cache);

                Ok(info)
            }
            GhidraMode::JsonRpc { .. } => {
                self.ensure_rpc_connection()?;
                let result = self.rpc_call("openProgram", serde_json::json!({ "path": path }))?;

                let info: BinaryInfo = serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Failed to parse binary info: {}", e)))?;

                *self.binary_path.write().await = Some(path.to_string());
                *self.binary_info.write().await = Some(info.clone());

                Ok(info)
            }
        }
    }

    #[instrument(skip(self), level = "info")]
    async fn close(&mut self) -> Result<()> {
        info!("Closing Ghidra session");

        if let GhidraMode::JsonRpc { .. } = &self.mode {
            if let Ok(mut stream) = self.rpc_stream.try_write() {
                *stream = None;
            }
        }

        *self.binary_path.write().await = None;
        *self.binary_info.write().await = None;
        *self.analysis_cache.write().await = None;

        Ok(())
    }

    async fn get_binary_info(&self) -> Result<BinaryInfo> {
        self.binary_info
            .read()
            .await
            .clone()
            .ok_or_else(|| Error::Connection("No binary loaded".into()))
    }

    async fn list_functions(&self) -> Result<Vec<FunctionInfo>> {
        match &self.mode {
            GhidraMode::Headless => {
                let cache = self.analysis_cache.read().await;
                Ok(cache
                    .as_ref()
                    .map(|c| c.functions.clone())
                    .unwrap_or_default())
            }
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call("getFunctions", serde_json::json!({}))?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn get_function(&self, address: u64) -> Result<FunctionInfo> {
        let funcs = self.list_functions().await?;
        funcs
            .into_iter()
            .find(|f| f.address == address)
            .ok_or(Error::InvalidAddress(address))
    }

    async fn get_function_by_name(&self, name: &str) -> Result<FunctionInfo> {
        let funcs = self.list_functions().await?;
        funcs
            .into_iter()
            .find(|f| f.name == name)
            .ok_or_else(|| Error::Analysis(format!("Function not found: {}", name)))
    }

    async fn disassemble(
        &self,
        address: u64,
        count: usize,
    ) -> Result<Vec<DisassembledInstruction>> {
        match &self.mode {
            GhidraMode::Headless => {
                // Headless mode doesn't support live disassembly
                // Return empty - user should re-run analysis or use JSON-RPC mode
                warn!("Disassembly not available in Headless mode - use JSON-RPC mode for live analysis");
                Ok(vec![])
            }
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call(
                    "disassemble",
                    serde_json::json!({ "address": format!("0x{:x}", address), "count": count }),
                )?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn disassemble_function(&self, address: u64) -> Result<Vec<DisassembledInstruction>> {
        self.disassemble(address, 500).await
    }

    async fn get_basic_blocks(&self, _function_address: u64) -> Result<Vec<BasicBlock>> {
        match &self.mode {
            GhidraMode::Headless => {
                warn!("Basic blocks not available in Headless mode");
                Ok(vec![])
            }
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call(
                    "getBasicBlocks",
                    serde_json::json!({ "address": format!("0x{:x}", _function_address) }),
                )?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn decompile(&self, address: u64) -> Result<DecompiledFunction> {
        match &self.mode {
            GhidraMode::Headless => {
                // For headless, we'd need to run another analysis pass
                // Return placeholder
                Ok(DecompiledFunction {
                    name: format!("FUN_{:08x}", address),
                    address,
                    code: "// Decompilation requires JSON-RPC mode or re-running headless with decompile script".to_string(),
                    language: "C".to_string(),
                })
            }
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call(
                    "decompile",
                    serde_json::json!({ "address": format!("0x{:x}", address) }),
                )?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn get_xrefs_to(&self, address: u64) -> Result<Vec<CrossReference>> {
        match &self.mode {
            GhidraMode::Headless => Ok(vec![]),
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call(
                    "getXrefsTo",
                    serde_json::json!({ "address": format!("0x{:x}", address) }),
                )?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn get_xrefs_from(&self, address: u64) -> Result<Vec<CrossReference>> {
        match &self.mode {
            GhidraMode::Headless => Ok(vec![]),
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call(
                    "getXrefsFrom",
                    serde_json::json!({ "address": format!("0x{:x}", address) }),
                )?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn list_strings(&self, min_length: usize) -> Result<Vec<BinaryString>> {
        match &self.mode {
            GhidraMode::Headless => {
                let cache = self.analysis_cache.read().await;
                Ok(cache
                    .as_ref()
                    .map(|c| {
                        c.strings
                            .iter()
                            .filter(|s| s.length >= min_length)
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default())
            }
            GhidraMode::JsonRpc { .. } => {
                let result =
                    self.rpc_call("getStrings", serde_json::json!({ "minLength": min_length }))?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn list_imports(&self) -> Result<Vec<ImportInfo>> {
        match &self.mode {
            GhidraMode::Headless => {
                let cache = self.analysis_cache.read().await;
                Ok(cache
                    .as_ref()
                    .map(|c| c.imports.clone())
                    .unwrap_or_default())
            }
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call("getImports", serde_json::json!({}))?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn list_exports(&self) -> Result<Vec<ExportInfo>> {
        match &self.mode {
            GhidraMode::Headless => {
                let cache = self.analysis_cache.read().await;
                Ok(cache
                    .as_ref()
                    .map(|c| c.exports.clone())
                    .unwrap_or_default())
            }
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call("getExports", serde_json::json!({}))?;
                serde_json::from_value(result)
                    .map_err(|e| Error::Internal(format!("Parse error: {}", e)))
            }
        }
    }

    async fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        match &self.mode {
            GhidraMode::Headless => Err(Error::BackendNotAvailable(
                "read_bytes not available in Headless mode".into(),
            )),
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call(
                    "readBytes",
                    serde_json::json!({ "address": format!("0x{:x}", address), "size": size }),
                )?;
                let hex_str = result.as_str().unwrap_or("");
                hex::decode(hex_str)
                    .map_err(|e| Error::Internal(format!("Failed to decode bytes: {}", e)))
            }
        }
    }

    async fn rename(&self, address: u64, new_name: &str) -> Result<()> {
        match &self.mode {
            GhidraMode::Headless => Err(Error::BackendNotAvailable(
                "rename not available in Headless mode".into(),
            )),
            GhidraMode::JsonRpc { .. } => {
                self.rpc_call(
                    "rename",
                    serde_json::json!({ "address": format!("0x{:x}", address), "name": new_name }),
                )?;
                Ok(())
            }
        }
    }

    async fn add_comment(&self, address: u64, comment: &str) -> Result<()> {
        match &self.mode {
            GhidraMode::Headless => Err(Error::BackendNotAvailable(
                "add_comment not available in Headless mode".into(),
            )),
            GhidraMode::JsonRpc { .. } => {
                self.rpc_call(
                    "setComment",
                    serde_json::json!({ "address": format!("0x{:x}", address), "comment": comment }),
                )?;
                Ok(())
            }
        }
    }

    async fn raw_command(&mut self, command: &str) -> Result<String> {
        match &self.mode {
            GhidraMode::Headless => Err(Error::BackendNotAvailable(
                "raw_command not available in Headless mode. Use JSON-RPC mode.".into(),
            )),
            GhidraMode::JsonRpc { .. } => {
                let result = self.rpc_call("execute", serde_json::json!({ "script": command }))?;
                Ok(result.to_string())
            }
        }
    }
}

impl Drop for GhidraBackend {
    fn drop(&mut self) {
        debug!("Ghidra backend dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_mode_default() {
        let mode = GhidraMode::default();
        assert!(matches!(mode, GhidraMode::Headless));
    }

    #[test]
    fn test_ghidra_mode_json_rpc() {
        let mode = GhidraMode::JsonRpc {
            host: "localhost".to_string(),
            port: 18489,
        };
        if let GhidraMode::JsonRpc { host, port } = mode {
            assert_eq!(host, "localhost");
            assert_eq!(port, 18489);
        } else {
            panic!("Expected JsonRpc mode");
        }
    }

    #[test]
    fn test_backend_creation() {
        // Should succeed even without GHIDRA_INSTALL_DIR (just warns)
        let backend = GhidraBackend::new();
        assert!(backend.is_ok());
    }

    #[test]
    fn test_backend_with_headless_mode() {
        let backend = GhidraBackend::with_mode(GhidraMode::Headless);
        assert!(backend.is_ok());
        let backend = backend.unwrap();
        assert!(!backend.is_connected());
    }

    #[test]
    fn test_backend_not_connected_initially() {
        let backend = GhidraBackend::new().unwrap();
        assert!(!backend.is_connected());
    }

    #[test]
    fn test_backend_name() {
        let backend = GhidraBackend::new().unwrap();
        assert_eq!(backend.name(), "Ghidra");
    }

    #[test]
    fn test_parse_addr_hex() {
        assert_eq!(GhidraBackend::parse_addr("0x1000"), 0x1000);
        assert_eq!(GhidraBackend::parse_addr("0X1000"), 0x1000);
        assert_eq!(GhidraBackend::parse_addr("1000"), 0x1000);
        assert_eq!(GhidraBackend::parse_addr("0xDEADBEEF"), 0xDEADBEEF);
    }

    #[test]
    fn test_parse_addr_invalid() {
        // Invalid hex should return 0
        assert_eq!(GhidraBackend::parse_addr("invalid"), 0);
        assert_eq!(GhidraBackend::parse_addr(""), 0);
    }

    #[test]
    fn test_analysis_cache_default() {
        let cache = AnalysisCache::default();
        assert!(cache.functions.is_empty());
        assert!(cache.strings.is_empty());
        assert!(cache.imports.is_empty());
        assert!(cache.exports.is_empty());
    }

    #[test]
    fn test_json_rpc_request_serialization() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "test".to_string(),
            params: serde_json::json!({}),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"test\""));
    }

    #[test]
    fn test_json_rpc_response_deserialization() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"test":"value"}}"#;
        let response: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_json_rpc_error_response() {
        let json =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}"#;
        let response: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().message, "Invalid Request");
    }

    #[test]
    fn test_exported_binary_info_deserialization() {
        let json = r#"{
            "name": "test.exe",
            "format": "PE",
            "architecture": "x86",
            "bits": 32,
            "endian": "little",
            "entry_point": "0x1000",
            "base_address": "0x400000",
            "sections": []
        }"#;
        let info: ExportedBinaryInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.format, "PE");
        assert_eq!(info.bits, 32);
    }

    #[test]
    fn test_exported_function_deserialization() {
        let json = r#"{
            "name": "main",
            "address": "0x1000",
            "size": "0x100",
            "is_external": false,
            "signature": "int main()"
        }"#;
        let func: ExportedFunction = serde_json::from_str(json).unwrap();
        assert_eq!(func.name, "main");
        assert!(!func.is_external);
    }

    #[test]
    fn test_exported_string_deserialization() {
        let json = r#"{
            "address": "0x2000",
            "value": "Hello World",
            "length": 11
        }"#;
        let s: ExportedString = serde_json::from_str(json).unwrap();
        assert_eq!(s.value, "Hello World");
        assert_eq!(s.length, 11);
    }

    #[test]
    fn test_ghidra_export_deserialization() {
        let json = r#"{
            "binary_info": {
                "name": "test",
                "format": "ELF",
                "architecture": "ARM",
                "bits": 64,
                "endian": "little",
                "entry_point": "0x1000",
                "base_address": "0x0",
                "sections": []
            },
            "functions": [],
            "strings": [],
            "imports": [],
            "exports": []
        }"#;
        let export: GhidraExport = serde_json::from_str(json).unwrap();
        assert!(export.binary_info.is_some());
        assert!(export.functions.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_binary_info_no_binary() {
        let backend = GhidraBackend::new().unwrap();
        let result = backend.get_binary_info().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_functions_no_binary() {
        let backend = GhidraBackend::new().unwrap();
        let result = backend.list_functions().await;
        // In headless mode with no binary, returns empty
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_strings_no_binary() {
        let backend = GhidraBackend::new().unwrap();
        let result = backend.list_strings(4).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_open_nonexistent_file() {
        let mut backend = GhidraBackend::new().unwrap();
        let result = backend.open("/nonexistent/path/to/binary").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_empty_path() {
        let mut backend = GhidraBackend::new().unwrap();
        let result = backend.open("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_without_open() {
        let mut backend = GhidraBackend::new().unwrap();
        // Close should succeed even if nothing is open
        let result = backend.close().await;
        assert!(result.is_ok());
    }
}
