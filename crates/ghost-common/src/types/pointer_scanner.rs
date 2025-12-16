//! Pointer scanner types for Cheat Engine-style pointer scanning
//!
//! This module provides types for:
//! - Multi-level pointer scanning to find stable pointer paths
//! - Pointer rescanning after process restart
//! - Pointer stability scoring and comparison
//! - Pointer chain resolution and management

use serde::{Deserialize, Serialize};

/// Unique identifier for a pointer scan session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PointerScanId(pub u32);

/// A single pointer path (chain of offsets from a base address)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerPath {
    /// Base address (typically a module base or static address)
    pub base_address: usize,
    /// Module name if base is within a module (for relocatable pointers)
    pub base_module: Option<String>,
    /// Offset from module base (if base_module is set)
    pub base_offset: Option<usize>,
    /// Chain of offsets to follow from the base
    pub offsets: Vec<i64>,
    /// The resolved final address (current value)
    pub resolved_address: Option<usize>,
    /// Stability score (0.0-1.0, higher = more stable across restarts)
    pub stability_score: f64,
    /// Number of times this path has been validated
    pub validation_count: u32,
    /// Whether this path was valid in the last rescan
    pub last_valid: bool,
}

impl PointerPath {
    /// Create a new pointer path
    pub fn new(base_address: usize, offsets: Vec<i64>) -> Self {
        Self {
            base_address,
            base_module: None,
            base_offset: None,
            offsets,
            resolved_address: None,
            stability_score: 0.0,
            validation_count: 0,
            last_valid: false,
        }
    }

    /// Create a module-relative pointer path
    pub fn module_relative(module: impl Into<String>, offset: usize, offsets: Vec<i64>) -> Self {
        Self {
            base_address: 0,
            base_module: Some(module.into()),
            base_offset: Some(offset),
            offsets,
            resolved_address: None,
            stability_score: 0.0,
            validation_count: 0,
            last_valid: false,
        }
    }

    /// Get the depth of this pointer path (number of dereferences)
    pub fn depth(&self) -> usize {
        self.offsets.len()
    }

    /// Check if this is a static pointer (module-relative base)
    pub fn is_static(&self) -> bool {
        self.base_module.is_some()
    }
}

/// Options for pointer scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerScanOptions {
    /// Target address to find pointers to
    pub target_address: usize,
    /// Maximum pointer depth (1-10 recommended, higher = slower)
    pub max_depth: u32,
    /// Maximum offset from pointer (positive and negative)
    pub max_offset: i64,
    /// Offset alignment (typically 4 or 8)
    pub offset_alignment: u32,
    /// Only include static bases (module-relative)
    pub static_only: bool,
    /// Include heap regions in scan
    pub include_heap: bool,
    /// Include stack regions in scan
    pub include_stack: bool,
    /// Specific modules to use as bases (empty = all modules)
    pub base_modules: Vec<String>,
    /// Maximum results to return
    pub max_results: usize,
    /// Use multiple threads for scanning
    pub multi_threaded: bool,
    /// Number of threads to use (0 = auto)
    pub thread_count: u32,
}

impl Default for PointerScanOptions {
    fn default() -> Self {
        Self {
            target_address: 0,
            max_depth: 5,
            max_offset: 0x1000,
            offset_alignment: 4,
            static_only: true,
            include_heap: true,
            include_stack: false,
            base_modules: Vec::new(),
            max_results: 10000,
            multi_threaded: true,
            thread_count: 0,
        }
    }
}

impl PointerScanOptions {
    /// Create options for scanning to a specific address
    pub fn for_address(target: usize) -> Self {
        Self {
            target_address: target,
            ..Default::default()
        }
    }

    /// Set maximum depth
    pub fn with_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth.min(10);
        self
    }

    /// Set maximum offset
    pub fn with_max_offset(mut self, offset: i64) -> Self {
        self.max_offset = offset;
        self
    }

    /// Limit to specific modules as bases
    pub fn with_base_modules(mut self, modules: Vec<String>) -> Self {
        self.base_modules = modules;
        self
    }
}

/// Options for pointer rescanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerRescanOptions {
    /// Scan ID to rescan
    pub scan_id: PointerScanId,
    /// New target address (if changed after restart)
    pub new_target_address: Option<usize>,
    /// Only keep paths that still resolve
    pub filter_invalid: bool,
    /// Update stability scores
    pub update_scores: bool,
}

impl PointerRescanOptions {
    pub fn new(scan_id: PointerScanId) -> Self {
        Self {
            scan_id,
            new_target_address: None,
            filter_invalid: true,
            update_scores: true,
        }
    }

    pub fn with_new_target(mut self, target: usize) -> Self {
        self.new_target_address = Some(target);
        self
    }
}

/// Pointer scan session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerScanSession {
    /// Unique session identifier
    pub id: PointerScanId,
    /// Original scan options
    pub options: PointerScanOptions,
    /// Found pointer paths
    pub paths: Vec<PointerPath>,
    /// Target address scanned for
    pub target_address: usize,
    /// Number of rescans performed
    pub rescan_count: u32,
    /// Timestamp of initial scan (Unix epoch)
    pub created_at: u64,
    /// Timestamp of last rescan (Unix epoch)
    pub last_rescan_at: u64,
    /// Whether the session is active
    pub active: bool,
}

/// Pointer scan progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerScanProgress {
    /// Scan session ID
    pub scan_id: PointerScanId,
    /// Current scan depth
    pub current_depth: u32,
    /// Maximum depth
    pub max_depth: u32,
    /// Pointers found at current depth
    pub pointers_at_depth: u64,
    /// Total pointers found so far
    pub total_pointers: u64,
    /// Regions scanned
    pub regions_scanned: u32,
    /// Total regions
    pub regions_total: u32,
    /// Elapsed time in milliseconds
    pub elapsed_ms: u64,
    /// Whether scan is complete
    pub complete: bool,
    /// Whether scan was cancelled
    pub cancelled: bool,
    /// Current phase description
    pub phase: String,
}

/// Pointer scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerScanStats {
    /// Total addresses scanned
    pub addresses_scanned: u64,
    /// Total pointers found
    pub pointers_found: u64,
    /// Paths found per depth level
    pub paths_per_depth: Vec<u64>,
    /// Time spent scanning (milliseconds)
    pub elapsed_ms: u64,
    /// Memory regions scanned
    pub regions_scanned: u32,
    /// Bytes scanned
    pub bytes_scanned: u64,
    /// Scan rate (addresses per second)
    pub scan_rate: u64,
}

/// Result of resolving a pointer chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerResolveResult {
    /// The pointer path that was resolved
    pub path: PointerPath,
    /// Whether resolution was successful
    pub success: bool,
    /// The final resolved address
    pub resolved_address: Option<usize>,
    /// Value at the resolved address (if requested)
    pub value: Option<Vec<u8>>,
    /// Addresses at each step of the chain (for debugging)
    pub chain_addresses: Vec<usize>,
    /// Error message if resolution failed
    pub error: Option<String>,
}

/// Comparison result between two pointer scan sets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerCompareResult {
    /// Paths that exist in both scans and still resolve
    pub common_valid: Vec<PointerPath>,
    /// Paths that exist in both but no longer resolve
    pub common_invalid: Vec<PointerPath>,
    /// Paths only in the first scan
    pub only_in_first: Vec<PointerPath>,
    /// Paths only in the second scan
    pub only_in_second: Vec<PointerPath>,
    /// Summary statistics
    pub stats: PointerCompareStats,
}

/// Statistics for pointer comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerCompareStats {
    /// Total paths in first scan
    pub first_count: usize,
    /// Total paths in second scan
    pub second_count: usize,
    /// Common valid count
    pub common_valid_count: usize,
    /// Common invalid count
    pub common_invalid_count: usize,
    /// Stability percentage (common_valid / min(first, second))
    pub stability_percentage: f64,
}

/// Request to add a resolved pointer to an address table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPointerEntryRequest {
    /// Pointer path to add
    pub path: PointerPath,
    /// Value type for display
    pub value_type: String,
    /// Description for the entry
    pub description: String,
    /// Whether to freeze the value
    pub freeze: bool,
}

/// Export format for pointer scan results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointerExportFormat {
    /// JSON format
    Json,
    /// CSV format
    Csv,
    /// Cheat Engine pointer file format
    CheatEnginePtr,
}

impl PointerExportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "ptr" | "ce" | "cheatengine" => Some(Self::CheatEnginePtr),
            _ => None,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::CheatEnginePtr => "ptr",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_scan_id() {
        let id1 = PointerScanId(1);
        let id2 = PointerScanId(1);
        let id3 = PointerScanId(2);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_pointer_path_new() {
        let path = PointerPath::new(0x140000000, vec![0x10, 0x20, 0x30]);
        assert_eq!(path.base_address, 0x140000000);
        assert_eq!(path.offsets, vec![0x10, 0x20, 0x30]);
        assert_eq!(path.depth(), 3);
        assert!(!path.is_static());
    }

    #[test]
    fn test_pointer_path_module_relative() {
        let path = PointerPath::module_relative("game.exe", 0x1000, vec![0x10, 0x20]);
        assert!(path.is_static());
        assert_eq!(path.base_module, Some("game.exe".to_string()));
        assert_eq!(path.base_offset, Some(0x1000));
        assert_eq!(path.depth(), 2);
    }

    #[test]
    fn test_pointer_scan_options_default() {
        let options = PointerScanOptions::default();
        assert_eq!(options.max_depth, 5);
        assert_eq!(options.max_offset, 0x1000);
        assert_eq!(options.offset_alignment, 4);
        assert!(options.static_only);
        assert!(options.include_heap);
        assert!(!options.include_stack);
    }

    #[test]
    fn test_pointer_scan_options_builder() {
        let options = PointerScanOptions::for_address(0x12345678)
            .with_depth(7)
            .with_max_offset(0x2000);
        assert_eq!(options.target_address, 0x12345678);
        assert_eq!(options.max_depth, 7);
        assert_eq!(options.max_offset, 0x2000);
    }

    #[test]
    fn test_pointer_rescan_options() {
        let options = PointerRescanOptions::new(PointerScanId(1)).with_new_target(0xABCDEF);
        assert_eq!(options.scan_id, PointerScanId(1));
        assert_eq!(options.new_target_address, Some(0xABCDEF));
        assert!(options.filter_invalid);
    }

    #[test]
    fn test_pointer_export_format_parse() {
        assert_eq!(
            PointerExportFormat::parse("json"),
            Some(PointerExportFormat::Json)
        );
        assert_eq!(
            PointerExportFormat::parse("csv"),
            Some(PointerExportFormat::Csv)
        );
        assert_eq!(
            PointerExportFormat::parse("ptr"),
            Some(PointerExportFormat::CheatEnginePtr)
        );
        assert_eq!(
            PointerExportFormat::parse("ce"),
            Some(PointerExportFormat::CheatEnginePtr)
        );
        assert_eq!(PointerExportFormat::parse("invalid"), None);
    }

    #[test]
    fn test_pointer_export_format_extension() {
        assert_eq!(PointerExportFormat::Json.extension(), "json");
        assert_eq!(PointerExportFormat::Csv.extension(), "csv");
        assert_eq!(PointerExportFormat::CheatEnginePtr.extension(), "ptr");
    }

    #[test]
    fn test_pointer_path_serialization() {
        let path = PointerPath::module_relative("test.exe", 0x1000, vec![0x10, 0x20]);
        let json = serde_json::to_string(&path).unwrap();
        let parsed: PointerPath = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.base_module, Some("test.exe".to_string()));
        assert_eq!(parsed.base_offset, Some(0x1000));
        assert_eq!(parsed.offsets, vec![0x10, 0x20]);
    }

    #[test]
    fn test_pointer_scan_session_serialization() {
        let session = PointerScanSession {
            id: PointerScanId(1),
            options: PointerScanOptions::default(),
            paths: vec![],
            target_address: 0x12345678,
            rescan_count: 0,
            created_at: 1234567890,
            last_rescan_at: 0,
            active: true,
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: PointerScanSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, PointerScanId(1));
        assert_eq!(parsed.target_address, 0x12345678);
        assert!(parsed.active);
    }
}
