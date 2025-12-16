//! Pattern scanning and YARA types

use serde::{Deserialize, Serialize};

/// Pattern resolution type for AOB scanning
/// Determines how the matched address is resolved to a final result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PatternType {
    /// Return the raw matched address (no resolution)
    #[default]
    Address,
    /// Dereference as pointer (platform-sized)
    Pointer,
    /// Dereference as u8
    PointerU8,
    /// Dereference as u16
    PointerU16,
    /// Dereference as u32
    PointerU32,
    /// Dereference as u64
    PointerU64,
    /// Resolve RIP-relative pointer (platform-sized offset)
    RelativePointer,
    /// Resolve RIP-relative with i8 offset
    RelativePointerI8,
    /// Resolve RIP-relative with i16 offset
    RelativePointerI16,
    /// Resolve RIP-relative with i32 offset (most common for x64)
    RelativePointerI32,
    /// Resolve RIP-relative with i64 offset
    RelativePointerI64,
}

impl PatternType {
    /// Parse pattern type from string representation
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "address" | "addr" => Some(Self::Address),
            "pointer" | "ptr" => Some(Self::Pointer),
            "ptr8" | "pointeru8" => Some(Self::PointerU8),
            "ptr16" | "pointeru16" => Some(Self::PointerU16),
            "ptr32" | "pointeru32" => Some(Self::PointerU32),
            "ptr64" | "pointeru64" => Some(Self::PointerU64),
            "rel" | "relative" | "relptr" => Some(Self::RelativePointer),
            "rel8" | "reli8" => Some(Self::RelativePointerI8),
            "rel16" | "reli16" => Some(Self::RelativePointerI16),
            "rel32" | "reli32" => Some(Self::RelativePointerI32),
            "rel64" | "reli64" => Some(Self::RelativePointerI64),
            _ => None,
        }
    }

    /// Get the size of the offset type for relative pointers
    pub fn offset_size(&self) -> usize {
        match self {
            Self::Address => 0,
            Self::Pointer | Self::RelativePointer => std::mem::size_of::<usize>(),
            Self::PointerU8 | Self::RelativePointerI8 => 1,
            Self::PointerU16 | Self::RelativePointerI16 => 2,
            Self::PointerU32 | Self::RelativePointerI32 => 4,
            Self::PointerU64 | Self::RelativePointerI64 => 8,
        }
    }

    /// Check if this is a relative pointer type
    pub fn is_relative(&self) -> bool {
        matches!(
            self,
            Self::RelativePointer
                | Self::RelativePointerI8
                | Self::RelativePointerI16
                | Self::RelativePointerI32
                | Self::RelativePointerI64
        )
    }

    /// Check if this requires dereferencing
    pub fn needs_dereference(&self) -> bool {
        !matches!(self, Self::Address)
    }
}

/// Pattern specification for AOB scanning with resolution type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// The pattern string (e.g., "48 8B [?? ?? ?? ??] 48 89")
    /// Use `[` to mark the offset position for pointer resolution
    pub pattern: String,
    /// How to resolve the matched address
    pub pattern_type: PatternType,
}

impl Pattern {
    pub fn new(pattern: impl Into<String>, pattern_type: PatternType) -> Self {
        Self {
            pattern: pattern.into(),
            pattern_type,
        }
    }

    /// Create a simple address pattern (no resolution)
    pub fn address(pattern: impl Into<String>) -> Self {
        Self::new(pattern, PatternType::Address)
    }

    /// Create a pattern with RIP-relative i32 resolution (common for x64)
    pub fn relative32(pattern: impl Into<String>) -> Self {
        Self::new(pattern, PatternType::RelativePointerI32)
    }
}

/// Named signature pattern for pattern scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePattern {
    /// Unique name for the signature
    pub name: String,
    /// Pattern bytes (hex string with wildcards like "48 8B ?? ?? 48 89")
    pub pattern: String,
    /// Description of what this pattern matches
    pub description: Option<String>,
    /// Category/tags for organization
    pub tags: Vec<String>,
    /// Pattern type for resolution
    pub pattern_type: PatternType,
    /// Offset adjustment after match
    pub offset: i32,
    /// Module filter (None = all modules)
    pub module_filter: Option<String>,
}

impl SignaturePattern {
    pub fn new(name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pattern: pattern.into(),
            description: None,
            tags: Vec::new(),
            pattern_type: PatternType::Address,
            offset: 0,
            module_filter: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_offset(mut self, offset: i32) -> Self {
        self.offset = offset;
        self
    }
}

/// Result of a signature pattern match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    /// Signature name that matched
    pub signature_name: String,
    /// Address where pattern was found
    pub address: usize,
    /// Resolved address (after pattern_type resolution and offset)
    pub resolved_address: usize,
    /// Module where match was found
    pub module: Option<String>,
    /// Matched bytes
    pub matched_bytes: Vec<u8>,
}

/// YARA rule for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    /// Rule name/identifier
    pub name: String,
    /// Rule source code
    pub source: String,
    /// Rule file path (if loaded from file)
    pub file_path: Option<String>,
    /// Rule namespace
    pub namespace: Option<String>,
    /// Whether rule is enabled
    pub enabled: bool,
}

impl YaraRule {
    pub fn new(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: source.into(),
            file_path: None,
            namespace: None,
            enabled: true,
        }
    }

    pub fn from_file(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: String::new(),
            file_path: Some(path.into()),
            namespace: None,
            enabled: true,
        }
    }

    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }
}

/// YARA match string information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchString {
    /// String identifier (e.g., "$s1")
    pub identifier: String,
    /// Offset where string was found
    pub offset: usize,
    /// Matched data
    pub data: Vec<u8>,
    /// XOR key if string was XOR'd
    pub xor_key: Option<u8>,
}

/// Result of a YARA scan match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Rule that matched
    pub rule_name: String,
    /// Rule namespace
    pub namespace: Option<String>,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: Vec<(String, String)>,
    /// Matched strings
    pub strings: Vec<YaraMatchString>,
    /// Module where match was found (if scanning modules)
    pub module: Option<String>,
    /// Base address of scanned region
    pub base_address: usize,
}

/// YARA scan options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct YaraScanOptions {
    /// Scan only specific modules (empty = all memory)
    pub modules: Vec<String>,
    /// Maximum matches per rule (0 = unlimited)
    pub max_matches_per_rule: usize,
    /// Timeout in seconds (0 = no timeout)
    pub timeout_secs: u64,
    /// Scan committed memory only
    pub committed_only: bool,
    /// Include private memory
    pub include_private: bool,
    /// Include mapped memory
    pub include_mapped: bool,
    /// Include image memory (loaded modules)
    pub include_image: bool,
    /// Fast scan mode (may miss some matches)
    pub fast_mode: bool,
}

impl YaraScanOptions {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            max_matches_per_rule: 0,
            timeout_secs: 300,
            committed_only: true,
            include_private: true,
            include_mapped: true,
            include_image: true,
            fast_mode: false,
        }
    }

    /// Scan only the main executable module
    pub fn main_module_only() -> Self {
        Self {
            modules: Vec::new(), // Will be populated at scan time
            committed_only: true,
            include_image: true,
            include_private: false,
            include_mapped: false,
            ..Default::default()
        }
    }
}

/// Signature database for storing named patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignatureDatabase {
    /// Database name
    pub name: String,
    /// Database version
    pub version: String,
    /// Database description
    pub description: Option<String>,
    /// Signatures in the database
    pub signatures: Vec<SignaturePattern>,
    /// YARA rules in the database
    pub yara_rules: Vec<YaraRule>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
}

impl SignatureDatabase {
    pub fn new(name: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            name: name.into(),
            version: "1.0.0".to_string(),
            description: None,
            signatures: Vec::new(),
            yara_rules: Vec::new(),
            created_at: now,
            modified_at: now,
        }
    }

    pub fn add_signature(&mut self, sig: SignaturePattern) {
        self.signatures.push(sig);
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    pub fn add_yara_rule(&mut self, rule: YaraRule) {
        self.yara_rules.push(rule);
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// Pattern scan type for different matching modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PatternScanType {
    /// Array of bytes with wildcards
    #[default]
    Aob,
    /// Regular expression on bytes
    Regex,
    /// Instruction sequence pattern
    InstructionSequence,
    /// ASCII string
    StringAscii,
    /// Unicode (UTF-16) string
    StringUnicode,
    /// UTF-8 string
    StringUtf8,
}

impl PatternScanType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aob" | "bytes" | "hex" => Some(Self::Aob),
            "regex" | "regexp" => Some(Self::Regex),
            "instructions" | "insn" | "code" => Some(Self::InstructionSequence),
            "ascii" | "string" => Some(Self::StringAscii),
            "unicode" | "utf16" | "wide" => Some(Self::StringUnicode),
            "utf8" => Some(Self::StringUtf8),
            _ => None,
        }
    }
}

/// Options for pattern scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternScanOptions {
    /// Type of pattern scan
    pub scan_type: PatternScanType,
    /// Maximum results to return (0 = unlimited)
    pub max_results: usize,
    /// Scan only specific modules (empty = all memory)
    pub modules: Vec<String>,
    /// Region filter
    pub region_filter: super::scanner::RegionFilter,
    /// Case insensitive for string patterns
    pub case_insensitive: bool,
    /// Pattern type for resolution
    pub pattern_type: PatternType,
    /// Offset adjustment after match
    pub offset: i32,
}

impl Default for PatternScanOptions {
    fn default() -> Self {
        Self {
            scan_type: PatternScanType::Aob,
            max_results: 1000,
            modules: Vec::new(),
            region_filter: super::scanner::RegionFilter::new(),
            case_insensitive: false,
            pattern_type: PatternType::Address,
            offset: 0,
        }
    }
}

/// Result of a pattern scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternScanResult {
    /// Address where pattern was found
    pub address: usize,
    /// Resolved address (after pattern_type resolution and offset)
    pub resolved_address: usize,
    /// Module where match was found (if applicable)
    pub module: Option<String>,
    /// Matched bytes
    pub matched_bytes: Vec<u8>,
    /// Pattern that matched (for named scans)
    pub pattern_name: Option<String>,
}

/// Statistics for pattern scanning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PatternScanStats {
    /// Number of patterns scanned
    pub patterns_scanned: u32,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Number of regions scanned
    pub regions_scanned: u32,
    /// Total matches found
    pub matches_found: u32,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
    /// Scan rate (MB/s)
    pub scan_rate_mbps: f64,
}

// ============================================================================
// Code Pattern Matching (Instruction Sequences)
// ============================================================================
// NOTE: Core instruction pattern types are in pattern_search.rs:
// - InstructionPattern, OperandPattern, MatchedInstruction, InstructionSequenceMatch
// - FindInstructionsRequest, AddressRange
// This module provides additional named pattern database support.

/// Named code pattern for pattern database
/// Uses InstructionPattern from pattern_search.rs for the actual patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedCodePattern {
    /// Pattern name
    pub name: String,
    /// Description of what this pattern detects
    pub description: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Sequence of instruction patterns (serialized for storage)
    pub pattern_json: String,
}

impl NamedCodePattern {
    pub fn new(name: impl Into<String>, pattern_json: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            tags: Vec::new(),
            pattern_json: pattern_json.into(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Code pattern database for storing named instruction sequence patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodePatternDatabase {
    /// Database name
    pub name: String,
    /// Database version
    pub version: String,
    /// Description
    pub description: Option<String>,
    /// Named patterns
    pub patterns: Vec<NamedCodePattern>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
}

impl CodePatternDatabase {
    pub fn new(name: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            name: name.into(),
            version: "1.0.0".to_string(),
            description: None,
            patterns: Vec::new(),
            created_at: now,
            modified_at: now,
        }
    }

    pub fn add_pattern(&mut self, pattern: NamedCodePattern) {
        self.patterns.push(pattern);
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

// ============================================================================
// YARA Rule Creation API
// ============================================================================

/// Request to create a new YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleCreateRequest {
    /// Rule name (identifier)
    pub name: String,
    /// Rule namespace (optional)
    pub namespace: Option<String>,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata as key-value pairs
    pub metadata: Vec<(String, String)>,
    /// String definitions
    pub strings: Vec<YaraStringDef>,
    /// Condition expression
    pub condition: String,
}

impl YaraRuleCreateRequest {
    pub fn new(name: impl Into<String>, condition: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: None,
            tags: Vec::new(),
            metadata: Vec::new(),
            strings: Vec::new(),
            condition: condition.into(),
        }
    }

    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn add_string(&mut self, def: YaraStringDef) {
        self.strings.push(def);
    }

    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.push((key.into(), value.into()));
    }

    /// Generate YARA rule source code
    pub fn to_source(&self) -> String {
        let mut source = String::new();

        // Rule declaration with tags
        source.push_str("rule ");
        source.push_str(&self.name);
        if !self.tags.is_empty() {
            source.push_str(" : ");
            source.push_str(&self.tags.join(" "));
        }
        source.push_str(" {\n");

        // Metadata section
        if !self.metadata.is_empty() {
            source.push_str("    meta:\n");
            for (key, value) in &self.metadata {
                source.push_str(&format!("        {} = \"{}\"\n", key, value));
            }
        }

        // Strings section
        if !self.strings.is_empty() {
            source.push_str("    strings:\n");
            for string_def in &self.strings {
                source.push_str(&format!("        {}\n", string_def.to_yara()));
            }
        }

        // Condition section
        source.push_str("    condition:\n");
        source.push_str(&format!("        {}\n", self.condition));

        source.push_str("}\n");
        source
    }
}

/// YARA string definition types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YaraStringType {
    /// Text string (e.g., "hello")
    Text,
    /// Hex string (e.g., { 48 8B ?? })
    Hex,
    /// Regular expression (e.g., /abc[0-9]+/)
    Regex,
}

/// YARA string definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringDef {
    /// String identifier (e.g., "$s1")
    pub identifier: String,
    /// String value
    pub value: String,
    /// String type
    pub string_type: YaraStringType,
    /// Modifiers (nocase, wide, ascii, fullword, etc.)
    pub modifiers: Vec<String>,
}

impl YaraStringDef {
    pub fn text(id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            identifier: id.into(),
            value: value.into(),
            string_type: YaraStringType::Text,
            modifiers: Vec::new(),
        }
    }

    pub fn hex(id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            identifier: id.into(),
            value: value.into(),
            string_type: YaraStringType::Hex,
            modifiers: Vec::new(),
        }
    }

    pub fn regex(id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            identifier: id.into(),
            value: value.into(),
            string_type: YaraStringType::Regex,
            modifiers: Vec::new(),
        }
    }

    pub fn with_modifiers(mut self, modifiers: Vec<String>) -> Self {
        self.modifiers = modifiers;
        self
    }

    pub fn nocase(mut self) -> Self {
        self.modifiers.push("nocase".to_string());
        self
    }

    pub fn wide(mut self) -> Self {
        self.modifiers.push("wide".to_string());
        self
    }

    pub fn ascii(mut self) -> Self {
        self.modifiers.push("ascii".to_string());
        self
    }

    pub fn fullword(mut self) -> Self {
        self.modifiers.push("fullword".to_string());
        self
    }

    /// Convert to YARA syntax
    pub fn to_yara(&self) -> String {
        let value_str = match self.string_type {
            YaraStringType::Text => format!("\"{}\"", self.value),
            YaraStringType::Hex => format!("{{ {} }}", self.value),
            YaraStringType::Regex => format!("/{}/", self.value),
        };

        let modifiers_str = if self.modifiers.is_empty() {
            String::new()
        } else {
            format!(" {}", self.modifiers.join(" "))
        };

        format!("{} = {}{}", self.identifier, value_str, modifiers_str)
    }
}

// ============================================================================
// Signature Versioning
// ============================================================================

/// Signature version information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignatureVersion {
    /// Major version (breaking changes)
    pub major: u32,
    /// Minor version (new signatures)
    pub minor: u32,
    /// Patch version (bug fixes)
    pub patch: u32,
    /// Build/revision number
    pub build: Option<u32>,
    /// Pre-release tag (e.g., "alpha", "beta", "rc1")
    pub prerelease: Option<String>,
}

impl SignatureVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            build: None,
            prerelease: None,
        }
    }

    pub fn parse(version_str: &str) -> Option<Self> {
        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() < 3 {
            return None;
        }
        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].split('-').next()?.parse().ok()?,
            build: None,
            prerelease: version_str.split('-').nth(1).map(|s| s.to_string()),
        })
    }

    /// Format version as string
    fn format_version(&self) -> String {
        let mut s = format!("{}.{}.{}", self.major, self.minor, self.patch);
        if let Some(ref pre) = self.prerelease {
            s.push('-');
            s.push_str(pre);
        }
        if let Some(build) = self.build {
            s.push('+');
            s.push_str(&build.to_string());
        }
        s
    }

    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    pub fn is_newer_than(&self, other: &Self) -> bool {
        (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)
    }
}

impl std::fmt::Display for SignatureVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_version())
    }
}

/// Versioned signature database with change history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedSignatureDatabase {
    /// Database name
    pub name: String,
    /// Current version
    pub version: SignatureVersion,
    /// Database description
    pub description: Option<String>,
    /// Signatures in the database
    pub signatures: Vec<SignaturePattern>,
    /// YARA rules in the database
    pub yara_rules: Vec<YaraRule>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
    /// Author information
    pub author: Option<String>,
    /// License information
    pub license: Option<String>,
    /// Changelog entries
    pub changelog: Vec<ChangelogEntry>,
}

impl VersionedSignatureDatabase {
    pub fn new(name: impl Into<String>, version: SignatureVersion) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            name: name.into(),
            version,
            description: None,
            signatures: Vec::new(),
            yara_rules: Vec::new(),
            created_at: now,
            modified_at: now,
            author: None,
            license: None,
            changelog: Vec::new(),
        }
    }

    pub fn bump_major(&mut self, description: impl Into<String>) {
        self.version.major += 1;
        self.version.minor = 0;
        self.version.patch = 0;
        self.add_changelog(description);
    }

    pub fn bump_minor(&mut self, description: impl Into<String>) {
        self.version.minor += 1;
        self.version.patch = 0;
        self.add_changelog(description);
    }

    pub fn bump_patch(&mut self, description: impl Into<String>) {
        self.version.patch += 1;
        self.add_changelog(description);
    }

    pub fn add_changelog(&mut self, description: impl Into<String>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.changelog.push(ChangelogEntry {
            version: self.version.clone(),
            timestamp: now,
            description: description.into(),
            changes: Vec::new(),
        });
        self.modified_at = now;
    }
}

/// Changelog entry for signature database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangelogEntry {
    /// Version for this entry
    pub version: SignatureVersion,
    /// Timestamp of the change
    pub timestamp: u64,
    /// Description of changes
    pub description: String,
    /// Individual changes (added/removed/modified signatures)
    pub changes: Vec<SignatureChange>,
}

/// Individual signature change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureChange {
    /// Change type
    pub change_type: SignatureChangeType,
    /// Signature name
    pub signature_name: String,
    /// Details of the change
    pub details: Option<String>,
}

/// Type of signature change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureChangeType {
    Added,
    Removed,
    Modified,
    Deprecated,
}
