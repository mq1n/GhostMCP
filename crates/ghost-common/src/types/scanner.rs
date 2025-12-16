//! Advanced value scanner types

use serde::{Deserialize, Serialize};

use super::scan::ValueType;

/// Unique identifier for a scan session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScanId(pub u32);

/// Scan comparison type for filtering results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanCompareType {
    /// Exact value match
    Exact,
    /// Value changed from previous scan
    Changed,
    /// Value unchanged from previous scan
    Unchanged,
    /// Value increased from previous scan
    Increased,
    /// Value decreased from previous scan
    Decreased,
    /// Value greater than specified
    GreaterThan,
    /// Value less than specified
    LessThan,
    /// Value between min and max (inclusive)
    Between,
    /// Unknown initial value (captures all addresses for first scan)
    UnknownInitial,
    /// Same as first scan value
    SameAsFirst,
    /// Same as previous scan value
    SameAsPrevious,
    /// Fuzzy match within tolerance range
    Fuzzy,
}

impl ScanCompareType {
    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "exact" | "eq" | "=" | "==" => Some(Self::Exact),
            "changed" | "chg" | "!=" => Some(Self::Changed),
            "unchanged" | "same" => Some(Self::Unchanged),
            "increased" | "inc" | ">" => Some(Self::Increased),
            "decreased" | "dec" | "<" => Some(Self::Decreased),
            "greater" | "gt" | ">=" => Some(Self::GreaterThan),
            "less" | "lt" | "<=" => Some(Self::LessThan),
            "between" | "range" => Some(Self::Between),
            "unknown" | "first" | "initial" => Some(Self::UnknownInitial),
            "sameasfirst" | "first_value" => Some(Self::SameAsFirst),
            "sameasprevious" | "prev_value" => Some(Self::SameAsPrevious),
            "fuzzy" | "approx" | "~" => Some(Self::Fuzzy),
            _ => None,
        }
    }

    /// Check if this comparison requires a previous scan
    pub fn requires_previous(&self) -> bool {
        matches!(
            self,
            Self::Changed
                | Self::Unchanged
                | Self::Increased
                | Self::Decreased
                | Self::SameAsFirst
                | Self::SameAsPrevious
        )
    }

    /// Check if this is an initial scan type
    pub fn is_initial(&self) -> bool {
        matches!(
            self,
            Self::Exact | Self::UnknownInitial | Self::Between | Self::Fuzzy
        )
    }
}

/// Region filter options for scanning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegionFilter {
    /// Only scan committed memory
    pub committed: bool,
    /// Only scan writable regions
    pub writable: bool,
    /// Only scan executable regions  
    pub executable: bool,
    /// Only scan regions belonging to loaded modules
    pub module_only: bool,
    /// Specific module name to scan (None = all)
    pub module_name: Option<String>,
    /// Custom start address (None = process start)
    pub start_address: Option<usize>,
    /// Custom end address (None = process end)
    pub end_address: Option<usize>,
}

impl RegionFilter {
    pub fn new() -> Self {
        Self {
            committed: true,
            writable: false,
            executable: false,
            module_only: false,
            module_name: None,
            start_address: None,
            end_address: None,
        }
    }

    /// Filter for writable memory (typical for game values)
    pub fn writable() -> Self {
        Self {
            committed: true,
            writable: true,
            executable: false,
            module_only: false,
            module_name: None,
            start_address: None,
            end_address: None,
        }
    }

    /// Filter for a specific module
    pub fn module(name: impl Into<String>) -> Self {
        Self {
            committed: true,
            writable: false,
            executable: false,
            module_only: true,
            module_name: Some(name.into()),
            start_address: None,
            end_address: None,
        }
    }
}

/// Scan options for controlling scan behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Value type to scan for
    pub value_type: ValueType,
    /// Comparison type
    pub compare_type: ScanCompareType,
    /// Custom alignment (None = use type default)
    pub alignment: Option<usize>,
    /// Fast scan mode (skip by alignment, may miss unaligned values)
    pub fast_scan: bool,
    /// Region filter
    pub region_filter: RegionFilter,
    /// Maximum results to return (0 = unlimited)
    pub max_results: usize,
    /// Tolerance for fuzzy scans (as percentage, e.g., 0.1 = 10%)
    pub fuzzy_tolerance: f64,
    /// Secondary value for between comparisons (min)
    pub value_min: Option<String>,
    /// Secondary value for between comparisons (max)
    pub value_max: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            value_type: ValueType::I32,
            compare_type: ScanCompareType::Exact,
            alignment: None,
            fast_scan: true,
            region_filter: RegionFilter::new(),
            max_results: 100000,
            fuzzy_tolerance: 0.0,
            value_min: None,
            value_max: None,
        }
    }
}

/// Extended scan result with previous value tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultEx {
    /// Memory address
    pub address: usize,
    /// Current value bytes
    pub value: Vec<u8>,
    /// Previous value bytes (for iterative scans)
    pub previous_value: Option<Vec<u8>>,
    /// First scan value bytes (for SameAsFirst comparison)
    pub first_value: Option<Vec<u8>>,
}

/// Scan session state for iterative scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    /// Unique session identifier
    pub id: ScanId,
    /// Scan options used
    pub options: ScanOptions,
    /// Current results
    pub results: Vec<ScanResultEx>,
    /// Number of scans performed
    pub scan_count: u32,
    /// Timestamp of first scan (Unix epoch)
    pub started_at: u64,
    /// Timestamp of last scan (Unix epoch)
    pub last_scan_at: u64,
    /// Whether the session is active
    pub active: bool,
}

/// Scan progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Scan session ID
    pub scan_id: ScanId,
    /// Current phase description
    pub phase: String,
    /// Regions scanned so far
    pub regions_scanned: u32,
    /// Total regions to scan
    pub regions_total: u32,
    /// Bytes scanned so far
    pub bytes_scanned: u64,
    /// Total bytes to scan
    pub bytes_total: u64,
    /// Results found so far
    pub results_found: u32,
    /// Elapsed time in milliseconds
    pub elapsed_ms: u64,
    /// Whether the scan is complete
    pub complete: bool,
    /// Whether the scan was cancelled
    pub cancelled: bool,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total addresses checked
    pub addresses_checked: u64,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Number of regions scanned
    pub regions_scanned: u32,
    /// Time elapsed in milliseconds
    pub elapsed_ms: u64,
    /// Results found
    pub results_found: u32,
    /// Scan rate (addresses per second)
    pub scan_rate: u64,
}

/// Export format for scan results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanExportFormat {
    /// JSON format
    Json,
    /// CSV format
    Csv,
    /// Cheat Engine XML format
    CheatEngineXml,
}

impl ScanExportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "xml" | "ce" | "cheatengine" => Some(Self::CheatEngineXml),
            _ => None,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::CheatEngineXml => "xml",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_id_equality() {
        let id1 = ScanId(1);
        let id2 = ScanId(1);
        let id3 = ScanId(2);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_scan_compare_type_parse() {
        assert_eq!(
            ScanCompareType::parse("exact"),
            Some(ScanCompareType::Exact)
        );
        assert_eq!(
            ScanCompareType::parse("EXACT"),
            Some(ScanCompareType::Exact)
        );
        assert_eq!(ScanCompareType::parse("=="), Some(ScanCompareType::Exact));
        assert_eq!(
            ScanCompareType::parse("changed"),
            Some(ScanCompareType::Changed)
        );
        assert_eq!(ScanCompareType::parse("!="), Some(ScanCompareType::Changed));
        assert_eq!(
            ScanCompareType::parse("increased"),
            Some(ScanCompareType::Increased)
        );
        assert_eq!(
            ScanCompareType::parse("decreased"),
            Some(ScanCompareType::Decreased)
        );
        assert_eq!(
            ScanCompareType::parse("between"),
            Some(ScanCompareType::Between)
        );
        assert_eq!(
            ScanCompareType::parse("unknown"),
            Some(ScanCompareType::UnknownInitial)
        );
        assert_eq!(
            ScanCompareType::parse("fuzzy"),
            Some(ScanCompareType::Fuzzy)
        );
        assert_eq!(ScanCompareType::parse("invalid"), None);
    }

    #[test]
    fn test_scan_compare_type_requires_previous() {
        assert!(!ScanCompareType::Exact.requires_previous());
        assert!(ScanCompareType::Changed.requires_previous());
        assert!(ScanCompareType::Unchanged.requires_previous());
        assert!(ScanCompareType::Increased.requires_previous());
        assert!(ScanCompareType::Decreased.requires_previous());
        assert!(ScanCompareType::SameAsFirst.requires_previous());
        assert!(ScanCompareType::SameAsPrevious.requires_previous());
    }

    #[test]
    fn test_scan_compare_type_is_initial() {
        assert!(ScanCompareType::Exact.is_initial());
        assert!(ScanCompareType::UnknownInitial.is_initial());
        assert!(ScanCompareType::Between.is_initial());
        assert!(ScanCompareType::Fuzzy.is_initial());
        assert!(!ScanCompareType::Changed.is_initial());
    }

    #[test]
    fn test_region_filter_default() {
        let filter = RegionFilter::default();
        assert!(!filter.committed);
        assert!(!filter.writable);
        assert!(!filter.executable);
        assert!(!filter.module_only);
        assert!(filter.module_name.is_none());
        assert!(filter.start_address.is_none());
        assert!(filter.end_address.is_none());
    }

    #[test]
    fn test_region_filter_new() {
        let filter = RegionFilter::new();
        assert!(filter.committed);
        assert!(!filter.writable);
    }

    #[test]
    fn test_region_filter_writable() {
        let filter = RegionFilter::writable();
        assert!(filter.committed);
        assert!(filter.writable);
        assert!(!filter.executable);
    }

    #[test]
    fn test_region_filter_module() {
        let filter = RegionFilter::module("game.exe");
        assert!(filter.committed);
        assert!(filter.module_only);
        assert_eq!(filter.module_name, Some("game.exe".to_string()));
    }

    #[test]
    fn test_scan_options_default() {
        let options = ScanOptions::default();
        assert_eq!(options.value_type, ValueType::I32);
        assert_eq!(options.compare_type, ScanCompareType::Exact);
        assert!(options.alignment.is_none());
        assert!(options.fast_scan);
        assert_eq!(options.max_results, 100000);
        assert_eq!(options.fuzzy_tolerance, 0.0);
    }

    #[test]
    fn test_scan_result_ex_serialization() {
        let result = ScanResultEx {
            address: 0x1000,
            value: vec![100, 0, 0, 0],
            previous_value: Some(vec![99, 0, 0, 0]),
            first_value: Some(vec![50, 0, 0, 0]),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScanResultEx = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.address, 0x1000);
        assert_eq!(parsed.value, vec![100, 0, 0, 0]);
        assert_eq!(parsed.previous_value, Some(vec![99, 0, 0, 0]));
    }

    #[test]
    fn test_scan_session_serialization() {
        let session = ScanSession {
            id: ScanId(1),
            options: ScanOptions::default(),
            results: vec![],
            scan_count: 5,
            started_at: 1234567890,
            last_scan_at: 1234567899,
            active: true,
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: ScanSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, ScanId(1));
        assert_eq!(parsed.scan_count, 5);
        assert!(parsed.active);
    }

    #[test]
    fn test_scan_progress_serialization() {
        let progress = ScanProgress {
            scan_id: ScanId(1),
            phase: "Scanning".to_string(),
            regions_scanned: 50,
            regions_total: 100,
            bytes_scanned: 1024 * 1024,
            bytes_total: 2 * 1024 * 1024,
            results_found: 150,
            elapsed_ms: 500,
            complete: false,
            cancelled: false,
        };
        let json = serde_json::to_string(&progress).unwrap();
        let parsed: ScanProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.regions_scanned, 50);
        assert_eq!(parsed.results_found, 150);
        assert!(!parsed.complete);
    }

    #[test]
    fn test_scan_stats_serialization() {
        let stats = ScanStats {
            addresses_checked: 1000000,
            bytes_scanned: 4000000,
            regions_scanned: 50,
            elapsed_ms: 1500,
            results_found: 25,
            scan_rate: 666666,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: ScanStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.addresses_checked, 1000000);
        assert_eq!(parsed.results_found, 25);
    }

    #[test]
    fn test_scan_export_format_parse() {
        assert_eq!(
            ScanExportFormat::parse("json"),
            Some(ScanExportFormat::Json)
        );
        assert_eq!(
            ScanExportFormat::parse("JSON"),
            Some(ScanExportFormat::Json)
        );
        assert_eq!(ScanExportFormat::parse("csv"), Some(ScanExportFormat::Csv));
        assert_eq!(
            ScanExportFormat::parse("xml"),
            Some(ScanExportFormat::CheatEngineXml)
        );
        assert_eq!(
            ScanExportFormat::parse("ce"),
            Some(ScanExportFormat::CheatEngineXml)
        );
        assert_eq!(
            ScanExportFormat::parse("cheatengine"),
            Some(ScanExportFormat::CheatEngineXml)
        );
        assert_eq!(ScanExportFormat::parse("invalid"), None);
    }

    #[test]
    fn test_scan_export_format_extension() {
        assert_eq!(ScanExportFormat::Json.extension(), "json");
        assert_eq!(ScanExportFormat::Csv.extension(), "csv");
        assert_eq!(ScanExportFormat::CheatEngineXml.extension(), "xml");
    }
}
