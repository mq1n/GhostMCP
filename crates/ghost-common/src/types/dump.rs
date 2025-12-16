//! Memory dump & analysis types

use serde::{Deserialize, Serialize};

use super::memory::{MemoryType, Protection};

/// Unique identifier for a memory dump
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DumpId(pub u32);

/// Type of memory dump
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DumpType {
    /// Full process memory dump (all committed regions)
    FullProcess,
    /// Selective region dump (specific address range)
    Region,
    /// Single module dump with PE structure
    Module,
    /// Minidump format (compatible with WinDbg)
    Minidump,
    /// Incremental dump (only changed regions since last dump)
    Incremental,
    /// Differential dump (differences between two dumps)
    Differential,
}

impl DumpType {
    /// Parse dump type from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "full" | "fullprocess" | "process" => Some(Self::FullProcess),
            "region" | "selective" => Some(Self::Region),
            "module" | "pe" => Some(Self::Module),
            "mini" | "minidump" => Some(Self::Minidump),
            "incremental" | "inc" => Some(Self::Incremental),
            "differential" | "diff" => Some(Self::Differential),
            _ => None,
        }
    }
}

/// Options for creating a memory dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpOptions {
    /// Type of dump to create
    pub dump_type: DumpType,
    /// Start address (for region dumps)
    pub start_address: Option<usize>,
    /// End address or size (for region dumps)
    pub end_address: Option<usize>,
    /// Module name (for module dumps)
    pub module_name: Option<String>,
    /// Output file path (None = return in memory)
    pub output_path: Option<String>,
    /// Whether to include PE headers in module dumps
    pub include_headers: bool,
    /// Whether to reconstruct PE for module dumps
    pub reconstruct_pe: bool,
    /// Base dump ID for incremental/differential dumps
    pub base_dump_id: Option<DumpId>,
    /// Whether to compress the dump
    pub compress: bool,
    /// Include only committed memory
    pub committed_only: bool,
    /// Include executable regions only
    pub executable_only: bool,
    /// Add annotations/bookmarks
    pub annotations: Vec<DumpAnnotation>,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            dump_type: DumpType::FullProcess,
            start_address: None,
            end_address: None,
            module_name: None,
            output_path: None,
            include_headers: true,
            reconstruct_pe: false,
            base_dump_id: None,
            compress: false,
            committed_only: true,
            executable_only: false,
            annotations: Vec::new(),
        }
    }
}

impl DumpOptions {
    /// Create options for a full process dump
    pub fn full_process() -> Self {
        Self::default()
    }

    /// Create options for a region dump
    pub fn region(start: usize, end: usize) -> Self {
        Self {
            dump_type: DumpType::Region,
            start_address: Some(start),
            end_address: Some(end),
            ..Default::default()
        }
    }

    /// Create options for a module dump
    pub fn module(name: impl Into<String>) -> Self {
        Self {
            dump_type: DumpType::Module,
            module_name: Some(name.into()),
            ..Default::default()
        }
    }

    /// Create options for a minidump
    pub fn minidump() -> Self {
        Self {
            dump_type: DumpType::Minidump,
            ..Default::default()
        }
    }

    /// Set output path
    pub fn with_output(mut self, path: impl Into<String>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    /// Enable PE reconstruction
    pub fn with_pe_reconstruction(mut self) -> Self {
        self.reconstruct_pe = true;
        self
    }

    /// Enable compression
    pub fn with_compression(mut self) -> Self {
        self.compress = true;
        self
    }
}

/// Annotation/bookmark for a dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpAnnotation {
    /// Address relative to dump start
    pub offset: usize,
    /// Annotation label/name
    pub label: String,
    /// Description
    pub description: Option<String>,
    /// Color for visualization (hex)
    pub color: Option<String>,
}

impl DumpAnnotation {
    pub fn new(offset: usize, label: impl Into<String>) -> Self {
        Self {
            offset,
            label: label.into(),
            description: None,
            color: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Memory region within a dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpRegion {
    /// Base address in the original process
    pub base_address: usize,
    /// Offset within the dump file
    pub file_offset: usize,
    /// Size of the region
    pub size: usize,
    /// Memory protection
    pub protection: Protection,
    /// Memory type
    pub memory_type: MemoryType,
    /// Associated module (if any)
    pub module: Option<String>,
}

/// Memory dump metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpInfo {
    /// Unique dump identifier
    pub id: DumpId,
    /// Dump type
    pub dump_type: DumpType,
    /// Process ID that was dumped
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Creation timestamp (Unix epoch ms)
    pub created_at: u64,
    /// Total size of dump in bytes
    pub size: u64,
    /// Number of regions in dump
    pub region_count: u32,
    /// File path (if saved to file)
    pub file_path: Option<String>,
    /// Whether dump is compressed
    pub compressed: bool,
    /// Base dump ID (for incremental/differential)
    pub base_dump_id: Option<DumpId>,
    /// Description/notes
    pub description: Option<String>,
    /// Checksum (SHA256)
    pub checksum: Option<String>,
    /// Regions in this dump
    pub regions: Vec<DumpRegion>,
    /// Annotations/bookmarks
    pub annotations: Vec<DumpAnnotation>,
}

/// Result of a dump operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpResult {
    /// Dump information
    pub info: DumpInfo,
    /// Raw dump data (if not saved to file)
    pub data: Option<Vec<u8>>,
    /// Whether operation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Dump comparison result (for differential dumps)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpDiff {
    /// First dump ID
    pub dump_a: DumpId,
    /// Second dump ID
    pub dump_b: DumpId,
    /// Changed regions
    pub changes: Vec<DumpChange>,
    /// Total bytes changed
    pub bytes_changed: u64,
    /// Number of regions changed
    pub regions_changed: u32,
}

/// A single change between two dumps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpChange {
    /// Address of the change
    pub address: usize,
    /// Size of the changed region
    pub size: usize,
    /// Original bytes (from dump_a)
    pub old_bytes: Vec<u8>,
    /// New bytes (from dump_b)
    pub new_bytes: Vec<u8>,
    /// Type of change
    pub change_type: DumpChangeType,
}

/// Type of change in a dump diff
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DumpChangeType {
    /// Bytes were modified
    Modified,
    /// New region was added
    Added,
    /// Region was removed
    Removed,
}

/// Search result within a dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpSearchResult {
    /// Dump ID
    pub dump_id: DumpId,
    /// Address in original process
    pub address: usize,
    /// Offset in dump file
    pub file_offset: usize,
    /// Matched bytes
    pub matched_bytes: Vec<u8>,
    /// Context (bytes before and after)
    pub context: Option<Vec<u8>>,
}

/// Options for searching within dumps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpSearchOptions {
    /// Pattern to search (hex bytes with ?? wildcards)
    pub pattern: String,
    /// Maximum results to return
    pub max_results: usize,
    /// Include context bytes
    pub include_context: bool,
    /// Context size (bytes before and after)
    pub context_size: usize,
}

impl Default for DumpSearchOptions {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            max_results: 1000,
            include_context: false,
            context_size: 16,
        }
    }
}

/// Minidump stream type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinidumpStreamType {
    /// Thread list stream
    ThreadList,
    /// Module list stream
    ModuleList,
    /// Memory list stream
    MemoryList,
    /// Exception stream
    Exception,
    /// System info stream
    SystemInfo,
    /// Thread info list stream
    ThreadInfoList,
    /// Handle data stream
    HandleData,
    /// Unloaded module list
    UnloadedModuleList,
    /// Memory info list (full memory info)
    MemoryInfoList,
    /// Full memory dump
    Memory64List,
}

/// Options for minidump creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinidumpOptions {
    /// Include thread information
    pub include_threads: bool,
    /// Include module information
    pub include_modules: bool,
    /// Include full memory
    pub include_memory: bool,
    /// Include handle information
    pub include_handles: bool,
    /// Include unloaded modules
    pub include_unloaded_modules: bool,
    /// Output file path
    pub output_path: String,
}

impl Default for MinidumpOptions {
    fn default() -> Self {
        Self {
            include_threads: true,
            include_modules: true,
            include_memory: true,
            include_handles: false,
            include_unloaded_modules: false,
            output_path: String::new(),
        }
    }
}

/// Dump catalog entry for indexing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpCatalogEntry {
    /// Dump ID
    pub id: DumpId,
    /// Dump type
    pub dump_type: DumpType,
    /// Process name
    pub process_name: String,
    /// PID
    pub pid: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// File path
    pub file_path: String,
    /// File size
    pub file_size: u64,
    /// Description
    pub description: Option<String>,
    /// Tags for organization
    pub tags: Vec<String>,
}

/// Dump catalog for managing multiple dumps
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DumpCatalog {
    /// All catalog entries
    pub entries: Vec<DumpCatalogEntry>,
    /// Next available dump ID
    pub next_id: u32,
    /// Catalog file path
    pub catalog_path: Option<String>,
}

impl DumpCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry to the catalog
    pub fn add_entry(&mut self, entry: DumpCatalogEntry) {
        let entry_id = entry.id.0;
        self.entries.push(entry);
        self.next_id = self.next_id.max(entry_id + 1);
    }

    /// Get next dump ID
    pub fn next_dump_id(&mut self) -> DumpId {
        let id = DumpId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Find entries by tag
    pub fn find_by_tag(&self, tag: &str) -> Vec<&DumpCatalogEntry> {
        self.entries
            .iter()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Find entries by process name
    pub fn find_by_process(&self, name: &str) -> Vec<&DumpCatalogEntry> {
        let name_lower = name.to_lowercase();
        self.entries
            .iter()
            .filter(|e| e.process_name.to_lowercase().contains(&name_lower))
            .collect()
    }
}
