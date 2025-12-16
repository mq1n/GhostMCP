//! Pattern Scanning & YARA Integration
//!
//! Comprehensive pattern scanning with support for:
//! - AOB (Array of Bytes) with wildcards
//! - Regex-based byte pattern matching
//! - Code pattern matching (instruction sequences)
//! - String pattern matching (ASCII/Unicode/UTF-8)
//! - Signature scanning with named patterns
//! - YARA rule loading, compilation, and scanning
//! - Signature database management
//!
//! # Safety
//! All memory operations are guarded with defensive programming:
//! - Bounds checking on all slice operations
//! - Error handling for memory read failures
//! - Timeout support for long-running scans

use ghost_common::{
    Error, MemoryRegion, MemoryState, MemoryType, PatternScanOptions, PatternScanResult,
    PatternScanStats, PatternScanType, PatternType, RegionFilter, Result, SignatureDatabase,
    SignatureMatch, SignaturePattern,
};
#[cfg(feature = "yara")]
use ghost_common::{YaraMatch, YaraMatchString, YaraRule, YaraScanOptions};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, trace};

/// Maximum pattern length to prevent abuse
const MAX_PATTERN_LENGTH: usize = 4096;
/// Maximum signature database size
const MAX_SIGNATURES: usize = 10000;
/// Default scan timeout in seconds
#[allow(dead_code)]
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Parsed pattern with bytes, mask, and offset position
#[derive(Debug, Clone)]
pub struct ParsedPattern {
    /// Pattern bytes (wildcards are 0)
    pub bytes: Vec<u8>,
    /// Mask: true = must match, false = wildcard
    pub mask: Vec<bool>,
    /// Byte offset within pattern where resolution should occur (marked by `[`)
    /// None means resolve from start of match
    pub offset: Option<usize>,
}

/// Extended scan result with resolved address
#[derive(Debug, Clone)]
pub struct ResolvedScanResult {
    /// Original match address
    pub match_address: usize,
    /// Matched bytes
    pub match_data: Vec<u8>,
    /// Resolved target address (after applying pattern type resolution)
    pub resolved_address: Option<usize>,
}

/// Pattern Scanner with YARA integration
pub struct PatternScanner {
    /// Loaded signature databases
    databases: RwLock<HashMap<String, SignatureDatabase>>,
    /// Cancel flag for long-running scans
    cancel_flag: Arc<AtomicBool>,
    /// Compiled YARA rules (when yara feature is enabled)
    #[cfg(feature = "yara")]
    yara_compiler: RwLock<Option<yara::Compiler>>,
    #[cfg(feature = "yara")]
    yara_rules: RwLock<Option<yara::Rules>>,
}

impl Default for PatternScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternScanner {
    pub fn new() -> Self {
        Self {
            databases: RwLock::new(HashMap::new()),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "yara")]
            yara_compiler: RwLock::new(None),
            #[cfg(feature = "yara")]
            yara_rules: RwLock::new(None),
        }
    }

    /// Get cancel flag for external cancellation
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel_flag.clone()
    }

    /// Cancel current scan
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
    // AOB Pattern Scanning
    // ========================================================================

    /// Parse AOB pattern string into bytes and mask (simple format)
    /// Pattern format: "48 8B ?? ?? 48 89" where ?? is wildcard
    pub fn parse_aob_pattern(pattern: &str) -> Result<(Vec<u8>, Vec<bool>)> {
        let parsed = Self::parse_aob_pattern_ex(pattern)?;
        Ok((parsed.bytes, parsed.mask))
    }

    /// Parse AOB pattern string with offset marker support.
    ///
    /// Pattern format: `"48 8B [?? ?? ?? ??] 48 89"` where:
    /// - `??` or `?` is wildcard
    /// - `[` marks the offset position for pointer resolution
    /// - `]` is optional end marker (ignored)
    ///
    /// Also supports compact format: `"488B[????????]4889"`
    pub fn parse_aob_pattern_ex(pattern: &str) -> Result<ParsedPattern> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Err(Error::Internal("Empty pattern".into()));
        }
        if pattern.len() > MAX_PATTERN_LENGTH {
            return Err(Error::Internal(format!(
                "Pattern too long (max {} chars)",
                MAX_PATTERN_LENGTH
            )));
        }

        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        let mut offset: Option<usize> = None;
        let mut chars = pattern.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                // Offset marker
                '[' => {
                    offset = Some(bytes.len());
                }
                // End marker (ignored)
                ']' => {}
                // Whitespace
                ' ' | '\t' | '\r' | '\n' => {}
                // Wildcard
                '?' => {
                    // Consume second ? if present
                    if chars.peek() == Some(&'?') {
                        chars.next();
                    }
                    bytes.push(0);
                    mask.push(false);
                }
                // Hex byte
                c if c.is_ascii_hexdigit() => {
                    let hi = c.to_digit(16).unwrap() as u8;
                    let lo = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or_else(|| Error::Internal("Incomplete hex byte in pattern".into()))?;
                    bytes.push((hi << 4) | (lo as u8));
                    mask.push(true);
                }
                _ => {
                    return Err(Error::Internal(format!(
                        "Invalid character in pattern: '{}'",
                        c
                    )));
                }
            }
        }

        if bytes.is_empty() {
            return Err(Error::Internal("No bytes in pattern".into()));
        }

        Ok(ParsedPattern {
            bytes,
            mask,
            offset,
        })
    }

    /// Search for AOB pattern in memory buffer
    pub fn find_aob_in_buffer(
        data: &[u8],
        pattern_bytes: &[u8],
        mask: &[bool],
        max_results: usize,
    ) -> Vec<usize> {
        if pattern_bytes.is_empty() || data.len() < pattern_bytes.len() {
            return Vec::new();
        }

        let mut results = Vec::new();
        let pattern_len = pattern_bytes.len();
        let search_len = data.len().saturating_sub(pattern_len - 1);

        'outer: for i in 0..search_len {
            for j in 0..pattern_len {
                // Skip wildcards (mask[j] == false means wildcard)
                if mask.get(j).copied().unwrap_or(false) && data.get(i + j) != pattern_bytes.get(j)
                {
                    continue 'outer;
                }
            }
            results.push(i);
            if max_results > 0 && results.len() >= max_results {
                break;
            }
        }

        results
    }

    /// Scan memory regions for AOB pattern
    pub fn scan_aob<F>(
        &self,
        pattern: &str,
        regions: &[MemoryRegion],
        options: &PatternScanOptions,
        read_memory: F,
    ) -> Result<(Vec<PatternScanResult>, PatternScanStats)>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        self.reset_cancel();
        let start_time = Instant::now();

        let (pattern_bytes, mask) = Self::parse_aob_pattern(pattern)?;

        info!(
            target: "ghost_core::pattern_scanner",
            pattern_len = pattern_bytes.len(),
            regions = regions.len(),
            "Starting AOB scan"
        );

        let mut results = Vec::new();
        let mut stats = PatternScanStats::default();

        for region in regions {
            if self.is_cancelled() {
                debug!(target: "ghost_core::pattern_scanner", "Scan cancelled");
                break;
            }

            // Apply region filter
            if !Self::region_matches_filter(region, &options.region_filter) {
                continue;
            }

            stats.regions_scanned += 1;

            // Read region memory
            match read_memory(region.base, region.size) {
                Ok(data) => {
                    stats.bytes_scanned += data.len() as u64;

                    let remaining = if options.max_results > 0 {
                        options.max_results.saturating_sub(results.len())
                    } else {
                        usize::MAX
                    };

                    let matches = Self::find_aob_in_buffer(&data, &pattern_bytes, &mask, remaining);

                    for offset in matches {
                        let address = region.base.saturating_add(offset);
                        let resolved = self.resolve_address(
                            address,
                            &data,
                            offset,
                            options.pattern_type,
                            options.offset,
                            &read_memory,
                        )?;

                        let matched_bytes = data
                            .get(offset..offset.saturating_add(pattern_bytes.len()))
                            .unwrap_or(&[])
                            .to_vec();

                        results.push(PatternScanResult {
                            address,
                            resolved_address: resolved,
                            module: None, // TODO: resolve module name
                            matched_bytes,
                            pattern_name: None,
                        });

                        stats.matches_found += 1;

                        if options.max_results > 0 && results.len() >= options.max_results {
                            break;
                        }
                    }
                }
                Err(e) => {
                    trace!(
                        target: "ghost_core::pattern_scanner",
                        base = format!("0x{:X}", region.base),
                        error = %e,
                        "Failed to read region"
                    );
                }
            }

            if options.max_results > 0 && results.len() >= options.max_results {
                break;
            }
        }

        stats.patterns_scanned = 1;
        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        if stats.duration_ms > 0 {
            stats.scan_rate_mbps =
                (stats.bytes_scanned as f64 / 1_000_000.0) / (stats.duration_ms as f64 / 1000.0);
        }

        info!(
            target: "ghost_core::pattern_scanner",
            matches = stats.matches_found,
            duration_ms = stats.duration_ms,
            "AOB scan complete"
        );

        Ok((results, stats))
    }

    // ========================================================================
    // String Pattern Scanning
    // ========================================================================

    /// Convert string to search bytes based on encoding
    pub fn string_to_bytes(s: &str, scan_type: PatternScanType) -> Vec<u8> {
        match scan_type {
            PatternScanType::StringAscii => s.as_bytes().to_vec(),
            PatternScanType::StringUnicode => {
                // UTF-16 LE encoding
                s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
            }
            PatternScanType::StringUtf8 => s.as_bytes().to_vec(),
            _ => s.as_bytes().to_vec(),
        }
    }

    /// Scan for string pattern in memory
    pub fn scan_string<F>(
        &self,
        pattern: &str,
        regions: &[MemoryRegion],
        options: &PatternScanOptions,
        read_memory: F,
    ) -> Result<(Vec<PatternScanResult>, PatternScanStats)>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        self.reset_cancel();
        let start_time = Instant::now();

        let search_bytes = Self::string_to_bytes(pattern, options.scan_type);
        let search_bytes_lower = if options.case_insensitive {
            pattern.to_lowercase()
        } else {
            pattern.to_string()
        };
        let search_bytes_lower = Self::string_to_bytes(&search_bytes_lower, options.scan_type);

        info!(
            target: "ghost_core::pattern_scanner",
            pattern = %pattern,
            encoding = ?options.scan_type,
            case_insensitive = options.case_insensitive,
            "Starting string scan"
        );

        let mut results = Vec::new();
        let mut stats = PatternScanStats::default();

        for region in regions {
            if self.is_cancelled() {
                break;
            }

            if !Self::region_matches_filter(region, &options.region_filter) {
                continue;
            }

            stats.regions_scanned += 1;

            match read_memory(region.base, region.size) {
                Ok(data) => {
                    stats.bytes_scanned += data.len() as u64;

                    let matches = if options.case_insensitive {
                        Self::find_string_case_insensitive(&data, &search_bytes_lower, options)
                    } else {
                        Self::find_string_exact(&data, &search_bytes, options.max_results)
                    };

                    for offset in matches {
                        let address = region.base.saturating_add(offset);
                        let matched_bytes = data
                            .get(offset..offset.saturating_add(search_bytes.len()))
                            .unwrap_or(&[])
                            .to_vec();

                        results.push(PatternScanResult {
                            address,
                            resolved_address: address, // No resolution for strings
                            module: None,
                            matched_bytes,
                            pattern_name: None,
                        });

                        stats.matches_found += 1;

                        if options.max_results > 0 && results.len() >= options.max_results {
                            break;
                        }
                    }
                }
                Err(e) => {
                    trace!(
                        target: "ghost_core::pattern_scanner",
                        error = %e,
                        "Failed to read region for string scan"
                    );
                }
            }

            if options.max_results > 0 && results.len() >= options.max_results {
                break;
            }
        }

        stats.patterns_scanned = 1;
        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        if stats.duration_ms > 0 {
            stats.scan_rate_mbps =
                (stats.bytes_scanned as f64 / 1_000_000.0) / (stats.duration_ms as f64 / 1000.0);
        }

        Ok((results, stats))
    }

    fn find_string_exact(data: &[u8], pattern: &[u8], max_results: usize) -> Vec<usize> {
        let mut results = Vec::new();
        if pattern.is_empty() || data.len() < pattern.len() {
            return results;
        }

        let mut pos: usize = 0;
        while pos <= data.len().saturating_sub(pattern.len()) {
            if let Some(slice) = data.get(pos..pos + pattern.len()) {
                if slice == pattern {
                    results.push(pos);
                    if max_results > 0 && results.len() >= max_results {
                        break;
                    }
                }
            }
            pos += 1;
        }
        results
    }

    fn find_string_case_insensitive(
        data: &[u8],
        pattern_lower: &[u8],
        options: &PatternScanOptions,
    ) -> Vec<usize> {
        if pattern_lower.is_empty() || data.len() < pattern_lower.len() {
            return Vec::new();
        }

        // For ASCII case-insensitive matching
        if options.scan_type == PatternScanType::StringAscii {
            let data_lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
            return Self::find_string_exact(&data_lower, pattern_lower, options.max_results);
        }

        // For other encodings, do byte-by-byte comparison
        Self::find_string_exact(data, pattern_lower, options.max_results)
    }

    // ========================================================================
    // Regex Pattern Scanning
    // ========================================================================

    /// Scan memory using regex pattern on hex representation
    #[cfg(feature = "yara")]
    pub fn scan_regex<F>(
        &self,
        pattern: &str,
        regions: &[MemoryRegion],
        options: &PatternScanOptions,
        read_memory: F,
    ) -> Result<(Vec<PatternScanResult>, PatternScanStats)>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        use regex::bytes::Regex;

        self.reset_cancel();
        let start_time = Instant::now();

        let regex = Regex::new(pattern)
            .map_err(|e| Error::InvalidArgument(format!("Invalid regex: {}", e)))?;

        info!(
            target: "ghost_core::pattern_scanner",
            pattern = %pattern,
            "Starting regex scan"
        );

        let mut results = Vec::new();
        let mut stats = PatternScanStats::default();

        for region in regions {
            if self.is_cancelled() {
                break;
            }

            if !Self::region_matches_filter(region, &options.region_filter) {
                continue;
            }

            stats.regions_scanned += 1;

            match read_memory(region.base, region.size) {
                Ok(data) => {
                    stats.bytes_scanned += data.len() as u64;

                    for mat in regex.find_iter(&data) {
                        let offset = mat.start();
                        let address = region.base.saturating_add(offset);

                        results.push(PatternScanResult {
                            address,
                            resolved_address: address,
                            module: None,
                            matched_bytes: mat.as_bytes().to_vec(),
                            pattern_name: None,
                        });

                        stats.matches_found += 1;

                        if options.max_results > 0 && results.len() >= options.max_results {
                            break;
                        }
                    }
                }
                Err(e) => {
                    trace!(
                        target: "ghost_core::pattern_scanner",
                        error = %e,
                        "Failed to read region for regex scan"
                    );
                }
            }

            if options.max_results > 0 && results.len() >= options.max_results {
                break;
            }
        }

        stats.patterns_scanned = 1;
        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        if stats.duration_ms > 0 {
            stats.scan_rate_mbps =
                (stats.bytes_scanned as f64 / 1_000_000.0) / (stats.duration_ms as f64 / 1000.0);
        }

        Ok((results, stats))
    }

    // ========================================================================
    // Signature Database Management
    // ========================================================================

    /// Load a signature database
    pub fn load_database(&self, db: SignatureDatabase) -> Result<()> {
        if db.signatures.len() > MAX_SIGNATURES {
            return Err(Error::Internal(format!(
                "Database has too many signatures (max {})",
                MAX_SIGNATURES
            )));
        }

        let name = db.name.clone();
        if let Ok(mut databases) = self.databases.write() {
            databases.insert(name.clone(), db);
            info!(target: "ghost_core::pattern_scanner", database = %name, "Loaded signature database");
            Ok(())
        } else {
            Err(Error::Internal("Failed to acquire database lock".into()))
        }
    }

    /// Get a signature database by name
    pub fn get_database(&self, name: &str) -> Option<SignatureDatabase> {
        self.databases.read().ok()?.get(name).cloned()
    }

    /// List all loaded databases
    pub fn list_databases(&self) -> Vec<String> {
        self.databases
            .read()
            .map(|dbs| dbs.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove a signature database
    pub fn unload_database(&self, name: &str) -> bool {
        self.databases
            .write()
            .map(|mut dbs| dbs.remove(name).is_some())
            .unwrap_or(false)
    }

    /// Scan using signatures from a database
    pub fn scan_signatures<F>(
        &self,
        database_name: &str,
        regions: &[MemoryRegion],
        options: &PatternScanOptions,
        read_memory: F,
    ) -> Result<(Vec<SignatureMatch>, PatternScanStats)>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        let database = self
            .get_database(database_name)
            .ok_or_else(|| Error::Internal(format!("Database '{}' not found", database_name)))?;

        self.reset_cancel();
        let start_time = Instant::now();

        info!(
            target: "ghost_core::pattern_scanner",
            database = %database_name,
            signatures = database.signatures.len(),
            "Starting signature scan"
        );

        let mut results = Vec::new();
        let mut stats = PatternScanStats::default();

        // Pre-parse all patterns
        let parsed_patterns: Vec<_> = database
            .signatures
            .iter()
            .filter_map(|sig| {
                Self::parse_aob_pattern(&sig.pattern)
                    .ok()
                    .map(|(bytes, mask)| (sig, bytes, mask))
            })
            .collect();

        stats.patterns_scanned = parsed_patterns.len() as u32;

        for region in regions {
            if self.is_cancelled() {
                break;
            }

            if !Self::region_matches_filter(region, &options.region_filter) {
                continue;
            }

            stats.regions_scanned += 1;

            match read_memory(region.base, region.size) {
                Ok(data) => {
                    stats.bytes_scanned += data.len() as u64;

                    for (sig, pattern_bytes, mask) in &parsed_patterns {
                        // Apply module filter
                        if sig.module_filter.is_some() {
                            // TODO: Check if region belongs to specified module
                            continue;
                        }

                        let matches = Self::find_aob_in_buffer(&data, pattern_bytes, mask, 1);

                        for offset in matches {
                            let address = region.base.saturating_add(offset);
                            let resolved = self
                                .resolve_address(
                                    address,
                                    &data,
                                    offset,
                                    sig.pattern_type,
                                    sig.offset,
                                    &read_memory,
                                )
                                .unwrap_or(address);

                            let matched_bytes = data
                                .get(offset..offset.saturating_add(pattern_bytes.len()))
                                .unwrap_or(&[])
                                .to_vec();

                            results.push(SignatureMatch {
                                signature_name: sig.name.clone(),
                                address,
                                resolved_address: resolved,
                                module: None,
                                matched_bytes,
                            });

                            stats.matches_found += 1;
                        }
                    }
                }
                Err(e) => {
                    trace!(
                        target: "ghost_core::pattern_scanner",
                        error = %e,
                        "Failed to read region for signature scan"
                    );
                }
            }
        }

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        if stats.duration_ms > 0 {
            stats.scan_rate_mbps =
                (stats.bytes_scanned as f64 / 1_000_000.0) / (stats.duration_ms as f64 / 1000.0);
        }

        info!(
            target: "ghost_core::pattern_scanner",
            matches = stats.matches_found,
            duration_ms = stats.duration_ms,
            "Signature scan complete"
        );

        Ok((results, stats))
    }

    // ========================================================================
    // YARA Integration
    // ========================================================================

    /// Load YARA rules from source
    #[cfg(feature = "yara")]
    pub fn load_yara_rules(&self, rules: &[YaraRule]) -> Result<()> {
        let mut compiler = yara::Compiler::new()
            .map_err(|e| Error::Internal(format!("Failed to create YARA compiler: {}", e)))?;

        for rule in rules {
            if !rule.enabled {
                continue;
            }

            if let Some(ref path) = rule.file_path {
                compiler = compiler.add_rules_file(path).map_err(|e| {
                    Error::InvalidArgument(format!("Failed to load YARA file '{}': {}", path, e))
                })?;
            } else {
                let namespace = rule.namespace.as_deref().unwrap_or("default");
                compiler = compiler
                    .add_rules_str_with_namespace(&rule.source, namespace)
                    .map_err(|e| {
                        Error::InvalidArgument(format!(
                            "Failed to compile YARA rule '{}': {}",
                            rule.name, e
                        ))
                    })?;
            }
        }

        let compiled_rules = compiler
            .compile_rules()
            .map_err(|e| Error::Internal(format!("Failed to compile YARA rules: {}", e)))?;

        if let Ok(mut yara_rules) = self.yara_rules.write() {
            *yara_rules = Some(compiled_rules);
            info!(target: "ghost_core::pattern_scanner", rules = rules.len(), "YARA rules loaded");
            Ok(())
        } else {
            Err(Error::Internal("Failed to acquire YARA rules lock".into()))
        }
    }

    /// Scan memory with loaded YARA rules
    #[cfg(feature = "yara")]
    pub fn scan_yara<F>(
        &self,
        regions: &[MemoryRegion],
        options: &YaraScanOptions,
        read_memory: F,
    ) -> Result<(Vec<YaraMatch>, PatternScanStats)>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        let rules = self
            .yara_rules
            .read()
            .map_err(|_| Error::Internal("Failed to acquire YARA rules lock".into()))?;

        let rules = rules
            .as_ref()
            .ok_or_else(|| Error::NotFound("No YARA rules loaded".into()))?;

        self.reset_cancel();
        let start_time = Instant::now();

        info!(
            target: "ghost_core::pattern_scanner",
            regions = regions.len(),
            "Starting YARA scan"
        );

        let mut results = Vec::new();
        let mut stats = PatternScanStats::default();

        for region in regions {
            if self.is_cancelled() {
                break;
            }

            // Apply filters
            if options.committed_only && region.state != MemoryState::Commit {
                continue;
            }
            if !options.include_private && region.region_type == MemoryType::Private {
                continue;
            }
            if !options.include_mapped && region.region_type == MemoryType::Mapped {
                continue;
            }
            if !options.include_image && region.region_type == MemoryType::Image {
                continue;
            }

            stats.regions_scanned += 1;

            match read_memory(region.base, region.size) {
                Ok(data) => {
                    stats.bytes_scanned += data.len() as u64;

                    let scan_results = rules
                        .scan_mem(&data, options.timeout_secs as i32)
                        .map_err(|e| Error::Internal(format!("YARA scan failed: {}", e)))?;

                    for rule_match in scan_results {
                        let strings: Vec<YaraMatchString> = rule_match
                            .strings
                            .iter()
                            .flat_map(|s| {
                                s.matches.iter().map(|m| YaraMatchString {
                                    identifier: s.identifier.to_string(),
                                    offset: m.offset,
                                    data: m.data.to_vec(),
                                    xor_key: m.xor_key,
                                })
                            })
                            .collect();

                        let metadata: Vec<(String, String)> = rule_match
                            .metadatas
                            .iter()
                            .map(|m| {
                                let value = match m.value {
                                    yara::MetadataValue::Integer(i) => i.to_string(),
                                    yara::MetadataValue::String(s) => s.to_string(),
                                    yara::MetadataValue::Boolean(b) => b.to_string(),
                                };
                                (m.identifier.to_string(), value)
                            })
                            .collect();

                        results.push(YaraMatch {
                            rule_name: rule_match.identifier.to_string(),
                            namespace: Some(rule_match.namespace.to_string()),
                            tags: rule_match.tags.iter().map(|t| t.to_string()).collect(),
                            metadata,
                            strings,
                            module: None,
                            base_address: region.base,
                        });

                        stats.matches_found += 1;

                        if options.max_matches_per_rule > 0
                            && results.len() >= options.max_matches_per_rule
                        {
                            break;
                        }
                    }
                }
                Err(e) => {
                    trace!(
                        target: "ghost_core::pattern_scanner",
                        error = %e,
                        "Failed to read region for YARA scan"
                    );
                }
            }
        }

        stats.patterns_scanned = 1; // YARA handles multiple rules internally
        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        if stats.duration_ms > 0 {
            stats.scan_rate_mbps =
                (stats.bytes_scanned as f64 / 1_000_000.0) / (stats.duration_ms as f64 / 1000.0);
        }

        info!(
            target: "ghost_core::pattern_scanner",
            matches = stats.matches_found,
            duration_ms = stats.duration_ms,
            "YARA scan complete"
        );

        Ok((results, stats))
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    /// Check if a region matches the filter criteria
    fn region_matches_filter(region: &MemoryRegion, filter: &RegionFilter) -> bool {
        // Check if committed
        if filter.committed && region.state != MemoryState::Commit {
            return false;
        }

        // Check protection flags
        if filter.writable && !region.protection.write {
            return false;
        }
        if filter.executable && !region.protection.execute {
            return false;
        }

        // Check address range
        if let Some(start) = filter.start_address {
            if region.base < start {
                return false;
            }
        }
        if let Some(end) = filter.end_address {
            if region.base.saturating_add(region.size) > end {
                return false;
            }
        }

        // Check module filter
        if filter.module_only && region.region_type != MemoryType::Image {
            return false;
        }

        true
    }

    /// Resolve address based on pattern type
    /// Handles all pointer types including relative addressing for x64 RIP-relative instructions
    fn resolve_address<F>(
        &self,
        match_address: usize,
        match_data: &[u8],
        res_offset: usize,
        pattern_type: PatternType,
        extra_offset: i32,
        _read_memory: &F,
    ) -> Result<usize>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        // Apply extra offset first
        let base_address = if extra_offset >= 0 {
            match_address.saturating_add(extra_offset as usize)
        } else {
            match_address.saturating_sub(extra_offset.unsigned_abs() as usize)
        };

        match pattern_type {
            PatternType::Address => Ok(base_address.wrapping_add(res_offset)),

            PatternType::Pointer => {
                // Dereference as platform pointer
                Self::read_value_at(match_data, res_offset, std::mem::size_of::<usize>())
                    .ok_or_else(|| Error::Internal("Failed to read pointer".into()))
            }

            PatternType::PointerU8 => Self::read_value_at(match_data, res_offset, 1)
                .ok_or_else(|| Error::Internal("Failed to read u8 pointer".into())),

            PatternType::PointerU16 => Self::read_value_at(match_data, res_offset, 2)
                .ok_or_else(|| Error::Internal("Failed to read u16 pointer".into())),

            PatternType::PointerU32 => Self::read_value_at(match_data, res_offset, 4)
                .ok_or_else(|| Error::Internal("Failed to read u32 pointer".into())),

            PatternType::PointerU64 => Self::read_value_at(match_data, res_offset, 8)
                .ok_or_else(|| Error::Internal("Failed to read u64 pointer".into())),

            PatternType::RelativePointer => {
                // RIP-relative: address + offset_value + sizeof(offset)
                let ptr_size = std::mem::size_of::<usize>();
                let offset_value = Self::read_signed_value_at(match_data, res_offset, ptr_size)
                    .ok_or_else(|| Error::Internal("Failed to read relative pointer".into()))?;
                let instruction_end = base_address.wrapping_add(res_offset).wrapping_add(ptr_size);
                Ok((instruction_end as isize).wrapping_add(offset_value) as usize)
            }

            PatternType::RelativePointerI8 => {
                let offset_value = Self::read_signed_value_at(match_data, res_offset, 1)
                    .ok_or_else(|| Error::Internal("Failed to read i8 offset".into()))?;
                let instruction_end = base_address.wrapping_add(res_offset).wrapping_add(1);
                Ok((instruction_end as isize).wrapping_add(offset_value) as usize)
            }

            PatternType::RelativePointerI16 => {
                let offset_value = Self::read_signed_value_at(match_data, res_offset, 2)
                    .ok_or_else(|| Error::Internal("Failed to read i16 offset".into()))?;
                let instruction_end = base_address.wrapping_add(res_offset).wrapping_add(2);
                Ok((instruction_end as isize).wrapping_add(offset_value) as usize)
            }

            PatternType::RelativePointerI32 => {
                // Most common: x64 RIP-relative addressing with 32-bit displacement
                let offset_value = Self::read_signed_value_at(match_data, res_offset, 4)
                    .ok_or_else(|| Error::Internal("Failed to read i32 offset".into()))?;
                let instruction_end = base_address.wrapping_add(res_offset).wrapping_add(4);
                Ok((instruction_end as isize).wrapping_add(offset_value) as usize)
            }

            PatternType::RelativePointerI64 => {
                let offset_value = Self::read_signed_value_at(match_data, res_offset, 8)
                    .ok_or_else(|| Error::Internal("Failed to read i64 offset".into()))?;
                let instruction_end = base_address.wrapping_add(res_offset).wrapping_add(8);
                Ok((instruction_end as isize).wrapping_add(offset_value) as usize)
            }
        }
    }

    /// Read unsigned value from bytes at offset
    fn read_value_at(data: &[u8], offset: usize, size: usize) -> Option<usize> {
        if offset + size > data.len() {
            return None;
        }
        match size {
            1 => Some(data[offset] as usize),
            2 => {
                let bytes: [u8; 2] = data[offset..offset + 2].try_into().ok()?;
                Some(u16::from_le_bytes(bytes) as usize)
            }
            4 => {
                let bytes: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
                Some(u32::from_le_bytes(bytes) as usize)
            }
            8 => {
                let bytes: [u8; 8] = data[offset..offset + 8].try_into().ok()?;
                Some(u64::from_le_bytes(bytes) as usize)
            }
            _ => None,
        }
    }

    /// Read signed value from bytes at offset
    fn read_signed_value_at(data: &[u8], offset: usize, size: usize) -> Option<isize> {
        if offset + size > data.len() {
            return None;
        }
        match size {
            1 => Some(data[offset] as i8 as isize),
            2 => {
                let bytes: [u8; 2] = data[offset..offset + 2].try_into().ok()?;
                Some(i16::from_le_bytes(bytes) as isize)
            }
            4 => {
                let bytes: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
                Some(i32::from_le_bytes(bytes) as isize)
            }
            8 => {
                let bytes: [u8; 8] = data[offset..offset + 8].try_into().ok()?;
                Some(i64::from_le_bytes(bytes) as isize)
            }
            _ => None,
        }
    }

    /// Auto-generate signature from a code sample
    pub fn generate_signature(
        name: &str,
        bytes: &[u8],
        wildcard_positions: &[usize],
    ) -> SignaturePattern {
        let mut pattern_parts = Vec::new();
        for (i, byte) in bytes.iter().enumerate() {
            if wildcard_positions.contains(&i) {
                pattern_parts.push("??".to_string());
            } else {
                pattern_parts.push(format!("{:02X}", byte));
            }
        }

        SignaturePattern::new(name, pattern_parts.join(" "))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Pattern Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_aob_pattern() {
        let (bytes, mask) = PatternScanner::parse_aob_pattern("48 8B ?? 48 89").unwrap();
        assert_eq!(bytes, vec![0x48, 0x8B, 0x00, 0x48, 0x89]);
        assert_eq!(mask, vec![true, true, false, true, true]);
    }

    #[test]
    fn test_parse_aob_pattern_invalid() {
        assert!(PatternScanner::parse_aob_pattern("").is_err());
        assert!(PatternScanner::parse_aob_pattern("GG").is_err());
    }

    #[test]
    fn test_parse_aob_pattern_ex_with_offset() {
        let parsed = PatternScanner::parse_aob_pattern_ex("48 8B [?? ?? ?? ??] 48 89").unwrap();
        assert_eq!(
            parsed.bytes,
            vec![0x48, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89]
        );
        assert_eq!(
            parsed.mask,
            vec![true, true, false, false, false, false, true, true]
        );
        assert_eq!(parsed.offset, Some(2));
    }

    #[test]
    fn test_parse_aob_pattern_ex_compact() {
        let parsed = PatternScanner::parse_aob_pattern_ex("488B[????????]4889").unwrap();
        assert_eq!(
            parsed.bytes,
            vec![0x48, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89]
        );
        assert_eq!(parsed.offset, Some(2));
    }

    #[test]
    fn test_parse_aob_pattern_ex_single_wildcard() {
        let parsed = PatternScanner::parse_aob_pattern_ex("48 ? 05").unwrap();
        assert_eq!(parsed.bytes, vec![0x48, 0x00, 0x05]);
        assert_eq!(parsed.mask, vec![true, false, true]);
    }

    #[test]
    fn test_parse_aob_pattern_ex_no_offset() {
        let parsed = PatternScanner::parse_aob_pattern_ex("48 8B 05").unwrap();
        assert_eq!(parsed.bytes, vec![0x48, 0x8B, 0x05]);
        assert_eq!(parsed.mask, vec![true, true, true]);
        assert_eq!(parsed.offset, None);
    }

    #[test]
    fn test_parse_aob_pattern_lowercase() {
        let (bytes, mask) = PatternScanner::parse_aob_pattern("48 8b ?? 00 ff").unwrap();
        assert_eq!(bytes, vec![0x48, 0x8B, 0x00, 0x00, 0xFF]);
        assert_eq!(mask, vec![true, true, false, true, true]);
    }

    // ========================================================================
    // Buffer Scanning Tests
    // ========================================================================

    #[test]
    fn test_find_aob_in_buffer() {
        let data = vec![0x48, 0x8B, 0x05, 0x48, 0x89, 0x48, 0x8B, 0x07, 0x48, 0x89];
        let pattern = vec![0x48, 0x8B, 0x00, 0x48, 0x89];
        let mask = vec![true, true, false, true, true];

        let results = PatternScanner::find_aob_in_buffer(&data, &pattern, &mask, 10);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], 0);
        assert_eq!(results[1], 5);
    }

    #[test]
    fn test_find_aob_in_buffer_empty_pattern() {
        let data = vec![0x48, 0x8B, 0x05];
        let pattern: Vec<u8> = vec![];
        let mask: Vec<bool> = vec![];
        let results = PatternScanner::find_aob_in_buffer(&data, &pattern, &mask, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_aob_in_buffer_pattern_too_long() {
        let data = vec![0x48, 0x8B];
        let pattern = vec![0x48, 0x8B, 0x05, 0x00];
        let mask = vec![true, true, true, true];
        let results = PatternScanner::find_aob_in_buffer(&data, &pattern, &mask, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_aob_in_buffer_max_results() {
        let data = vec![0x48, 0x48, 0x48, 0x48, 0x48];
        let pattern = vec![0x48];
        let mask = vec![true];
        let results = PatternScanner::find_aob_in_buffer(&data, &pattern, &mask, 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_aob_in_buffer_no_match() {
        let data = vec![0x48, 0x8B, 0x05, 0x00, 0xFF];
        let pattern = vec![0x90, 0x90, 0x90];
        let mask = vec![true, true, true];
        let results = PatternScanner::find_aob_in_buffer(&data, &pattern, &mask, 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_aob_in_buffer_all_wildcards() {
        let data = vec![0x48, 0x8B, 0x05, 0x00, 0xFF];
        let pattern = vec![0x00, 0x00, 0x00];
        let mask = vec![false, false, false];
        let results = PatternScanner::find_aob_in_buffer(&data, &pattern, &mask, 10);
        // All wildcards should match at every position
        assert_eq!(results.len(), 3); // positions 0, 1, 2
    }

    // ========================================================================
    // String Conversion Tests
    // ========================================================================

    #[test]
    fn test_string_to_bytes_ascii() {
        let bytes = PatternScanner::string_to_bytes("test", PatternScanType::StringAscii);
        assert_eq!(bytes, vec![0x74, 0x65, 0x73, 0x74]);
    }

    #[test]
    fn test_string_to_bytes_unicode() {
        let bytes = PatternScanner::string_to_bytes("AB", PatternScanType::StringUnicode);
        assert_eq!(bytes, vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn test_string_to_bytes_utf8() {
        let bytes = PatternScanner::string_to_bytes("hello", PatternScanType::StringUtf8);
        assert_eq!(bytes, vec![0x68, 0x65, 0x6C, 0x6C, 0x6F]);
    }

    #[test]
    fn test_string_to_bytes_empty() {
        let bytes = PatternScanner::string_to_bytes("", PatternScanType::StringAscii);
        assert!(bytes.is_empty());
    }

    // ========================================================================
    // Signature Generation Tests
    // ========================================================================

    #[test]
    fn test_generate_signature() {
        let bytes = vec![0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78];
        let sig = PatternScanner::generate_signature("test_sig", &bytes, &[2, 3, 4, 5, 6]);
        assert_eq!(sig.pattern, "48 8B ?? ?? ?? ?? ??");
    }

    #[test]
    fn test_generate_signature_no_wildcards() {
        let bytes = vec![0x48, 0x8B, 0x05];
        let sig = PatternScanner::generate_signature("test_sig", &bytes, &[]);
        assert_eq!(sig.pattern, "48 8B 05");
    }

    // ========================================================================
    // Database Operations Tests
    // ========================================================================

    #[test]
    fn test_signature_database() {
        let mut db = SignatureDatabase::new("test_db");
        db.add_signature(SignaturePattern::new("sig1", "48 8B ??"));
        assert_eq!(db.signatures.len(), 1);
    }

    #[test]
    fn test_pattern_scanner_database_operations() {
        let scanner = PatternScanner::new();
        let db = SignatureDatabase::new("test");
        scanner.load_database(db).unwrap();
        assert!(scanner.get_database("test").is_some());
        assert!(scanner.unload_database("test"));
        assert!(scanner.get_database("test").is_none());
    }

    #[test]
    fn test_pattern_scanner_cancellation() {
        let scanner = PatternScanner::new();
        assert!(!scanner.is_cancelled());
        scanner.cancel();
        assert!(scanner.is_cancelled());
        scanner.reset_cancel();
        assert!(!scanner.is_cancelled());
    }

    // ========================================================================
    // Value Reading Tests
    // ========================================================================

    #[test]
    fn test_read_value_at() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

        // Read u8
        assert_eq!(PatternScanner::read_value_at(&data, 0, 1), Some(0x10));

        // Read u16 LE
        assert_eq!(PatternScanner::read_value_at(&data, 0, 2), Some(0x2010));

        // Read u32 LE
        assert_eq!(PatternScanner::read_value_at(&data, 0, 4), Some(0x40302010));

        // Out of bounds
        assert_eq!(PatternScanner::read_value_at(&data, 7, 4), None);
    }

    #[test]
    fn test_read_signed_value_at() {
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF]; // -1 as i32

        // Read i8
        assert_eq!(PatternScanner::read_signed_value_at(&data, 0, 1), Some(-1));

        // Read i16
        assert_eq!(PatternScanner::read_signed_value_at(&data, 0, 2), Some(-1));

        // Read i32
        assert_eq!(PatternScanner::read_signed_value_at(&data, 0, 4), Some(-1));
    }
}
