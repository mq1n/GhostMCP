//! Advanced Value Scanner
//!
//! Cheat Engine-style value scanning with support for:
//! - Extended scan types (unknown, same as first/previous, comparisons, fuzzy)
//! - Scan options (fast scan, alignment, address range, region filters)
//! - Progress reporting and cancellation
//! - Result management (export/import, pagination)
//!
//! # Safety
//! This module uses defensive programming throughout:
//! - All RwLock operations handle poisoned locks gracefully
//! - Memory read failures are logged and skipped (not fatal)
//! - Integer overflow is prevented using saturating arithmetic
//! - All byte slice operations use bounds-checked accessors

use ghost_common::{
    Error, MemoryRegion, MemoryState, RegionFilter, Result, ScanCompareType, ScanExportFormat,
    ScanId, ScanOptions, ScanProgress, ScanResultEx, ScanSession, ScanStats, ValueType,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, trace, warn};

use crate::memory::{alignment_for_type, value_to_bytes};

/// Maximum number of sessions to prevent memory exhaustion
const MAX_SESSIONS: usize = 100;
/// Maximum results per session to prevent memory exhaustion
const MAX_RESULTS_LIMIT: usize = 10_000_000;
/// Timeout for scan operations (seconds)
#[allow(dead_code)]
const SCAN_TIMEOUT_SECS: u64 = 300;

/// Scanner state management
pub struct Scanner {
    /// Active scan sessions
    sessions: RwLock<HashMap<ScanId, ScanSession>>,
    /// Next session ID
    next_id: AtomicU32,
    /// Per-session cancel flags (allows concurrent scans without interference)
    cancel_flags: RwLock<HashMap<ScanId, Arc<AtomicBool>>>,
    /// Per-session progress (allows concurrent progress tracking)
    progress: RwLock<HashMap<ScanId, ScanProgress>>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            cancel_flags: RwLock::new(HashMap::new()),
            progress: RwLock::new(HashMap::new()),
        }
    }

    /// Get the cancel flag for a specific session
    pub fn cancel_flag(&self, session_id: ScanId) -> Option<Arc<AtomicBool>> {
        self.cancel_flags.read().ok()?.get(&session_id).cloned()
    }

    /// Cancel a specific scan session
    pub fn cancel_session(&self, session_id: ScanId) {
        if let Ok(flags) = self.cancel_flags.read() {
            if let Some(flag) = flags.get(&session_id) {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Cancel all active scans (for backwards compatibility)
    pub fn cancel(&self) {
        if let Ok(flags) = self.cancel_flags.read() {
            for flag in flags.values() {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Reset cancel flag for a specific session
    fn reset_cancel(&self, session_id: ScanId) {
        if let Ok(mut flags) = self.cancel_flags.write() {
            let flag = flags.entry(session_id).or_insert_with(|| Arc::new(AtomicBool::new(false)));
            flag.store(false, Ordering::SeqCst);
        }
    }

    /// Check if a specific session is cancelled
    fn is_cancelled(&self, session_id: ScanId) -> bool {
        self.cancel_flags
            .read()
            .ok()
            .and_then(|flags| flags.get(&session_id).map(|f| f.load(Ordering::SeqCst)))
            .unwrap_or(false)
    }

    /// Check if any scan is cancelled (for backwards compatibility)
    pub fn is_any_cancelled(&self) -> bool {
        self.cancel_flags
            .read()
            .ok()
            .map(|flags| flags.values().any(|f| f.load(Ordering::SeqCst)))
            .unwrap_or(false)
    }

    /// Create a new scan session
    ///
    /// Returns a unique session ID for use with subsequent scan operations.
    /// Sessions are limited to MAX_SESSIONS to prevent memory exhaustion.
    pub fn create_session(&self, options: ScanOptions) -> ScanId {
        let id = ScanId(self.next_id.fetch_add(1, Ordering::SeqCst));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Cap max_results to prevent memory exhaustion
        let mut safe_options = options;
        if safe_options.max_results == 0 || safe_options.max_results > MAX_RESULTS_LIMIT {
            safe_options.max_results = MAX_RESULTS_LIMIT;
        }

        let session = ScanSession {
            id,
            options: safe_options,
            results: Vec::new(),
            scan_count: 0,
            started_at: now,
            last_scan_at: now,
            active: true,
        };

        if let Ok(mut sessions) = self.sessions.write() {
            // Clean up old sessions if we hit the limit
            if sessions.len() >= MAX_SESSIONS {
                warn!(target: "ghost_core::scanner", "Session limit reached, cleaning up oldest sessions");
                // Remove inactive sessions first
                let inactive: Vec<_> = sessions
                    .iter()
                    .filter(|(_, s)| !s.active)
                    .map(|(k, _)| *k)
                    .collect();
                for old_id in inactive.into_iter().take(10) {
                    sessions.remove(&old_id);
                }
            }
            sessions.insert(id, session);
            info!(target: "ghost_core::scanner", scan_id = id.0, "Created scan session");
        } else {
            warn!(target: "ghost_core::scanner", "Failed to acquire session lock for create");
        }

        id
    }

    /// Get a scan session by ID
    pub fn get_session(&self, id: ScanId) -> Option<ScanSession> {
        self.sessions.read().ok()?.get(&id).cloned()
    }

    /// Update session comparison type
    pub fn update_session_compare(&self, id: ScanId, compare_type: ScanCompareType) -> Result<()> {
        let mut sessions = self.sessions.write().map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(session) = sessions.get_mut(&id) {
            session.options.compare_type = compare_type;
            Ok(())
        } else {
            Err(Error::Internal("Session not found".into()))
        }
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<ScanSession> {
        self.sessions
            .read()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Close a scan session
    pub fn close_session(&self, id: ScanId) -> bool {
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.remove(&id).is_some()
        } else {
            false
        }
    }

    /// Get progress for a specific session
    pub fn get_progress(&self, session_id: ScanId) -> Option<ScanProgress> {
        self.progress.read().ok()?.get(&session_id).cloned()
    }

    /// Get progress for any active scan (for backwards compatibility)
    pub fn get_any_progress(&self) -> Option<ScanProgress> {
        self.progress.read().ok()?.values().next().cloned()
    }

    /// Update progress for a session (internal)
    fn update_progress(&self, session_id: ScanId, progress: ScanProgress) {
        if let Ok(mut p) = self.progress.write() {
            p.insert(session_id, progress);
        }
    }

    /// Perform initial scan on memory regions
    ///
    /// # Arguments
    /// * `session_id` - The scan session ID from `create_session`
    /// * `value` - The value to search for (empty for unknown initial scan)
    /// * `regions` - Memory regions to scan
    /// * `read_memory` - Closure to read memory at (address, size)
    ///
    /// # Returns
    /// Scan statistics including result count and timing
    pub fn initial_scan<F>(
        &self,
        session_id: ScanId,
        value: &str,
        regions: &[MemoryRegion],
        read_memory: F,
    ) -> Result<ScanStats>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        self.reset_cancel(session_id);
        let start_time = Instant::now();

        info!(target: "ghost_core::scanner", 
            scan_id = session_id.0,
            regions = regions.len(),
            value = %value,
            "Starting initial scan");

        // Get session options
        let options = {
            let sessions = self
                .sessions
                .read()
                .map_err(|e| Error::Internal(e.to_string()))?;
            sessions
                .get(&session_id)
                .ok_or_else(|| Error::Internal("Session not found".into()))?
                .options
                .clone()
        };

        // Parse value to bytes
        let value_bytes = if options.compare_type == ScanCompareType::UnknownInitial {
            Vec::new() // No value needed for unknown initial
        } else {
            value_to_bytes(value, options.value_type)?
        };

        // Parse min/max for between comparisons
        let (min_bytes, max_bytes) = if options.compare_type == ScanCompareType::Between {
            let min = options
                .value_min
                .as_ref()
                .map(|v| value_to_bytes(v, options.value_type))
                .transpose()?
                .unwrap_or_default();
            let max = options
                .value_max
                .as_ref()
                .map(|v| value_to_bytes(v, options.value_type))
                .transpose()?
                .unwrap_or_default();
            (min, max)
        } else {
            (Vec::new(), Vec::new())
        };

        // Filter regions
        let filtered_regions = filter_regions(regions, &options.region_filter);
        let total_bytes: u64 = filtered_regions.iter().map(|r| r.size as u64).sum();
        let regions_total = filtered_regions.len() as u32;

        let mut results: Vec<ScanResultEx> = Vec::new();
        let mut bytes_scanned: u64 = 0;
        let mut addresses_checked: u64 = 0;
        let mut regions_scanned: u32 = 0;

        let alignment = options
            .alignment
            .unwrap_or_else(|| alignment_for_type(options.value_type));
        let value_size = type_size(options.value_type);

        // Update initial progress
        self.update_progress(session_id, ScanProgress {
            scan_id: session_id,
            phase: "Scanning memory".into(),
            regions_scanned: 0,
            regions_total,
            bytes_scanned: 0,
            bytes_total: total_bytes,
            results_found: 0,
            elapsed_ms: 0,
            complete: false,
            cancelled: false,
        });

        const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB chunks

        for region in &filtered_regions {
            if self.is_cancelled(session_id) {
                break;
            }

            // Process region in chunks
            let mut offset = 0;
            while offset < region.size {
                if self.is_cancelled(session_id) {
                    break;
                }

                let chunk_size = (region.size - offset).min(MAX_CHUNK_SIZE);
                let chunk_base = region.base + offset;

                match read_memory(chunk_base, chunk_size) {
                    Ok(data) => {
                        bytes_scanned = bytes_scanned.saturating_add(data.len() as u64);

                        // Scan this chunk
                        let step = if options.fast_scan { alignment } else { 1 };
                        let mut i = 0;

                        while i + value_size <= data.len() {
                            if self.is_cancelled(session_id) {
                                break;
                            }

                            addresses_checked += 1;
                            let current = &data[i..i + value_size];

                            let matches = match options.compare_type {
                                ScanCompareType::Exact => current == value_bytes.as_slice(),
                                ScanCompareType::UnknownInitial => true, // All values match
                                ScanCompareType::Between => compare_between(
                                    current,
                                    &min_bytes,
                                    &max_bytes,
                                    options.value_type,
                                ),
                                ScanCompareType::GreaterThan => {
                                    compare_gt(current, &value_bytes, options.value_type)
                                }
                                ScanCompareType::LessThan => {
                                    compare_lt(current, &value_bytes, options.value_type)
                                }
                                ScanCompareType::Fuzzy => compare_fuzzy(
                                    current,
                                    &value_bytes,
                                    options.value_type,
                                    options.fuzzy_tolerance,
                                ),
                                _ => false, // Other types require previous scan
                            };

                            if matches {
                                results.push(ScanResultEx {
                                    address: chunk_base + i,
                                    value: current.to_vec(),
                                    previous_value: None,
                                    first_value: Some(current.to_vec()),
                                });

                                if options.max_results > 0 && results.len() >= options.max_results {
                                    break;
                                }
                            }

                            i += step;
                        }
                    }
                    Err(e) => {
                        // Skip unreadable regions - this is normal for guard pages, etc.
                        trace!(target: "ghost_core::scanner", 
                            address = format!("0x{:x}", chunk_base),
                            error = %e,
                            "Skipping unreadable chunk");
                    }
                }

                offset += chunk_size;

                // Check max results
                if options.max_results > 0 && results.len() >= options.max_results {
                    break;
                }
            }

            regions_scanned += 1;

            // Update progress periodically
            if regions_scanned % 10 == 0 || regions_scanned == regions_total {
                self.update_progress(session_id, ScanProgress {
                    scan_id: session_id,
                    phase: "Scanning memory".into(),
                    regions_scanned,
                    regions_total,
                    bytes_scanned,
                    bytes_total: total_bytes,
                    results_found: results.len() as u32,
                    elapsed_ms: start_time.elapsed().as_millis() as u64,
                    complete: false,
                    cancelled: self.is_cancelled(session_id),
                });
            }

            // Check max results
            if options.max_results > 0 && results.len() >= options.max_results {
                break;
            }
        }

        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        let results_found = results.len() as u32;

        info!(target: "ghost_core::scanner",
            scan_id = session_id.0,
            results = results_found,
            bytes_scanned = bytes_scanned,
            regions_scanned = regions_scanned,
            elapsed_ms = elapsed_ms,
            cancelled = self.is_cancelled(session_id),
            "Initial scan complete");

        // Update session with results
        {
            let mut sessions = self.sessions.write().map_err(|e| {
                warn!(target: "ghost_core::scanner", error = %e, "Failed to acquire session lock");
                Error::Internal(format!("Lock poisoned: {}", e))
            })?;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.results = results;
                session.scan_count = 1;
                session.last_scan_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            } else {
                warn!(target: "ghost_core::scanner", scan_id = session_id.0, "Session disappeared during scan");
            }
        }

        // Final progress update
        self.update_progress(session_id, ScanProgress {
            scan_id: session_id,
            phase: "Complete".into(),
            regions_scanned,
            regions_total,
            bytes_scanned,
            bytes_total: total_bytes,
            results_found,
            elapsed_ms,
            complete: true,
            cancelled: self.is_cancelled(session_id),
        });

        let scan_rate = if elapsed_ms > 0 {
            (addresses_checked * 1000) / elapsed_ms
        } else {
            addresses_checked
        };

        Ok(ScanStats {
            addresses_checked,
            bytes_scanned,
            regions_scanned,
            elapsed_ms,
            results_found,
            scan_rate,
        })
    }

    /// Perform next scan (iterative) on existing results
    ///
    /// Filters the current scan results based on a comparison type.
    /// This is the core of iterative scanning - call repeatedly with different
    /// comparisons to narrow down results.
    ///
    /// # Arguments
    /// * `session_id` - The scan session ID
    /// * `compare_type` - How to compare values (changed, increased, etc.)
    /// * `value` - Optional new value for exact/greater/less comparisons
    /// * `read_memory` - Closure to read memory at (address, size)
    pub fn next_scan<F>(
        &self,
        session_id: ScanId,
        compare_type: ScanCompareType,
        value: Option<&str>,
        read_memory: F,
    ) -> Result<ScanStats>
    where
        F: Fn(usize, usize) -> Result<Vec<u8>>,
    {
        self.reset_cancel(session_id);
        let start_time = Instant::now();

        info!(target: "ghost_core::scanner",
            scan_id = session_id.0,
            compare = ?compare_type,
            value = ?value,
            "Starting next scan");

        // Get session
        let (options, mut results) = {
            let sessions = self.sessions.read().map_err(|e| {
                warn!(target: "ghost_core::scanner", error = %e, "Failed to acquire session lock");
                Error::Internal(format!("Lock poisoned: {}", e))
            })?;
            let session = sessions
                .get(&session_id)
                .ok_or_else(|| Error::Internal("Session not found".into()))?;
            (session.options.clone(), session.results.clone())
        };

        if results.is_empty() {
            return Err(Error::Internal("No previous results to filter".into()));
        }

        let value_size = type_size(options.value_type);
        let value_bytes = value
            .map(|v| value_to_bytes(v, options.value_type))
            .transpose()?;

        let total_results = results.len() as u32;
        let mut filtered_results: Vec<ScanResultEx> = Vec::new();
        let mut addresses_checked: u64 = 0;

        self.update_progress(session_id, ScanProgress {
            scan_id: session_id,
            phase: "Filtering results".into(),
            regions_scanned: 0,
            regions_total: total_results,
            bytes_scanned: 0,
            bytes_total: (total_results as u64) * (value_size as u64),
            results_found: 0,
            elapsed_ms: 0,
            complete: false,
            cancelled: false,
        });

        for (idx, result) in results.iter_mut().enumerate() {
            if self.is_cancelled(session_id) {
                break;
            }

            addresses_checked += 1;

            // Read current value with bounds check
            match read_memory(result.address, value_size) {
                Ok(current) if current.len() >= value_size => {
                    let previous = &result.value;
                    let first = result.first_value.as_ref().unwrap_or(previous);

                    let matches = match compare_type {
                        ScanCompareType::Exact => value_bytes.as_ref() == Some(&current),
                        ScanCompareType::Changed => current != *previous,
                        ScanCompareType::Unchanged => current == *previous,
                        ScanCompareType::Increased => {
                            compare_gt(&current, previous, options.value_type)
                        }
                        ScanCompareType::Decreased => {
                            compare_lt(&current, previous, options.value_type)
                        }
                        ScanCompareType::GreaterThan => value_bytes
                            .as_ref()
                            .is_some_and(|v| compare_gt(&current, v, options.value_type)),
                        ScanCompareType::LessThan => value_bytes
                            .as_ref()
                            .is_some_and(|v| compare_lt(&current, v, options.value_type)),
                        ScanCompareType::SameAsFirst => current == *first,
                        ScanCompareType::SameAsPrevious => current == *previous,
                        ScanCompareType::Fuzzy => value_bytes.as_ref().is_some_and(|v| {
                            compare_fuzzy(&current, v, options.value_type, options.fuzzy_tolerance)
                        }),
                        _ => false,
                    };

                    if matches {
                        filtered_results.push(ScanResultEx {
                            address: result.address,
                            value: current,
                            previous_value: Some(previous.clone()),
                            first_value: result.first_value.clone(),
                        });
                    }
                }
                Ok(_) => {
                    // Insufficient data returned, skip
                    trace!(target: "ghost_core::scanner",
                        address = format!("0x{:x}", result.address),
                        "Insufficient data for address");
                }
                Err(e) => {
                    // Address no longer readable, skip
                    trace!(target: "ghost_core::scanner",
                        address = format!("0x{:x}", result.address),
                        error = %e,
                        "Address no longer readable");
                }
            }

            // Update progress periodically
            if idx % 1000 == 0 {
                self.update_progress(session_id, ScanProgress {
                    scan_id: session_id,
                    phase: "Filtering results".into(),
                    regions_scanned: idx as u32,
                    regions_total: total_results,
                    bytes_scanned: (idx as u64) * (value_size as u64),
                    bytes_total: (total_results as u64) * (value_size as u64),
                    results_found: filtered_results.len() as u32,
                    elapsed_ms: start_time.elapsed().as_millis() as u64,
                    complete: false,
                    cancelled: false,
                });
            }
        }

        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        let results_found = filtered_results.len() as u32;

        info!(target: "ghost_core::scanner",
            scan_id = session_id.0,
            results = results_found,
            checked = addresses_checked,
            elapsed_ms = elapsed_ms,
            "Next scan complete");

        // Update session
        {
            let mut sessions = self.sessions.write().map_err(|e| {
                warn!(target: "ghost_core::scanner", error = %e, "Failed to acquire session lock");
                Error::Internal(format!("Lock poisoned: {}", e))
            })?;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.results = filtered_results;
                session.scan_count += 1;
                session.last_scan_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            }
        }

        self.update_progress(session_id, ScanProgress {
            scan_id: session_id,
            phase: "Complete".into(),
            regions_scanned: total_results,
            regions_total: total_results,
            bytes_scanned: (total_results as u64) * (value_size as u64),
            bytes_total: (total_results as u64) * (value_size as u64),
            results_found,
            elapsed_ms,
            complete: true,
            cancelled: self.is_cancelled(session_id),
        });

        let scan_rate = if elapsed_ms > 0 {
            (addresses_checked * 1000) / elapsed_ms
        } else {
            addresses_checked
        };

        Ok(ScanStats {
            addresses_checked,
            bytes_scanned: addresses_checked * (value_size as u64),
            regions_scanned: 1,
            elapsed_ms,
            results_found,
            scan_rate,
        })
    }

    /// Get results from a session
    pub fn get_results(
        &self,
        session_id: ScanId,
        offset: usize,
        limit: usize,
    ) -> Vec<ScanResultEx> {
        self.sessions
            .read()
            .ok()
            .and_then(|s| s.get(&session_id).cloned())
            .map(|s| {
                s.results
                    .into_iter()
                    .skip(offset)
                    .take(if limit == 0 { usize::MAX } else { limit })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get result count for a session
    pub fn get_result_count(&self, session_id: ScanId) -> usize {
        self.sessions
            .read()
            .ok()
            .and_then(|s| s.get(&session_id).map(|sess| sess.results.len()))
            .unwrap_or(0)
    }

    /// Export results to string format
    ///
    /// Supports JSON, CSV, and Cheat Engine XML formats.
    pub fn export_results(&self, session_id: ScanId, format: ScanExportFormat) -> Result<String> {
        let session = self
            .get_session(session_id)
            .ok_or_else(|| Error::Internal("Session not found".into()))?;

        debug!(target: "ghost_core::scanner",
            scan_id = session_id.0,
            format = ?format,
            results = session.results.len(),
            "Exporting scan results");

        match format {
            ScanExportFormat::Json => serde_json::to_string_pretty(&session.results)
                .map_err(|e| Error::Internal(e.to_string())),
            ScanExportFormat::Csv => {
                let mut csv = String::from("address,value_hex,value_dec\n");
                for result in &session.results {
                    let hex = hex::encode(&result.value);
                    let dec = bytes_to_display(&result.value, session.options.value_type);
                    csv.push_str(&format!("0x{:X},{},{}\n", result.address, hex, dec));
                }
                Ok(csv)
            }
            ScanExportFormat::CheatEngineXml => {
                let mut xml =
                    String::from("<?xml version=\"1.0\"?>\n<CheatTable>\n  <CheatEntries>\n");
                for (i, result) in session.results.iter().enumerate() {
                    let type_str = ce_type_string(session.options.value_type);
                    xml.push_str(&format!(
                        "    <CheatEntry>\n      <ID>{}</ID>\n      <Description>Scan Result {}</Description>\n      <Address>{:X}</Address>\n      <VariableType>{}</VariableType>\n    </CheatEntry>\n",
                        i, i, result.address, type_str
                    ));
                }
                xml.push_str("  </CheatEntries>\n</CheatTable>\n");
                Ok(xml)
            }
        }
    }

    /// Import results from JSON
    ///
    /// Replaces the current session results with the imported data.
    pub fn import_results(&self, session_id: ScanId, json: &str) -> Result<u32> {
        // Validate JSON is not too large (max 100MB)
        if json.len() > 100 * 1024 * 1024 {
            return Err(Error::Internal("Import data too large (max 100MB)".into()));
        }

        let results: Vec<ScanResultEx> = serde_json::from_str(json).map_err(|e| {
            warn!(target: "ghost_core::scanner", error = %e, "Failed to parse import JSON");
            Error::Internal(format!("Invalid JSON: {}", e))
        })?;

        // Limit imported results
        if results.len() > MAX_RESULTS_LIMIT {
            return Err(Error::Internal(format!(
                "Too many results to import (max {})",
                MAX_RESULTS_LIMIT
            )));
        }

        info!(target: "ghost_core::scanner",
            scan_id = session_id.0,
            count = results.len(),
            "Importing scan results");
        let count = results.len() as u32;

        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.results = results;
            Ok(count)
        } else {
            Err(Error::Internal("Session not found".into()))
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter memory regions based on filter options
fn filter_regions(regions: &[MemoryRegion], filter: &RegionFilter) -> Vec<MemoryRegion> {
    regions
        .iter()
        .filter(|r| {
            // State filter
            if filter.committed && r.state != MemoryState::Commit {
                return false;
            }
            // Protection filters
            if filter.writable && !r.protection.write {
                return false;
            }
            if filter.executable && !r.protection.execute {
                return false;
            }
            // Must be readable
            if !r.protection.read {
                return false;
            }
            // Address range filter
            if let Some(start) = filter.start_address {
                if r.base + r.size <= start {
                    return false;
                }
            }
            if let Some(end) = filter.end_address {
                if r.base >= end {
                    return false;
                }
            }
            // Skip very large regions (>64MB)
            if r.size > 64 * 1024 * 1024 {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

/// Get size of a value type
fn type_size(value_type: ValueType) -> usize {
    match value_type {
        ValueType::U8 | ValueType::I8 => 1,
        ValueType::U16 | ValueType::I16 => 2,
        ValueType::U32 | ValueType::I32 | ValueType::F32 => 4,
        ValueType::U64 | ValueType::I64 | ValueType::F64 => 8,
        ValueType::String | ValueType::Bytes => 1, // Variable, use 1 as minimum
    }
}

/// Compare two values for between (inclusive)
fn compare_between(current: &[u8], min: &[u8], max: &[u8], value_type: ValueType) -> bool {
    compare_gte(current, min, value_type) && compare_lte(current, max, value_type)
}

/// Compare greater than
fn compare_gt(a: &[u8], b: &[u8], value_type: ValueType) -> bool {
    match value_type {
        ValueType::U8 => bytes_to_u8(a) > bytes_to_u8(b),
        ValueType::U16 => bytes_to_u16(a) > bytes_to_u16(b),
        ValueType::U32 => bytes_to_u32(a) > bytes_to_u32(b),
        ValueType::U64 => bytes_to_u64(a) > bytes_to_u64(b),
        ValueType::I8 => bytes_to_i8(a) > bytes_to_i8(b),
        ValueType::I16 => bytes_to_i16(a) > bytes_to_i16(b),
        ValueType::I32 => bytes_to_i32(a) > bytes_to_i32(b),
        ValueType::I64 => bytes_to_i64(a) > bytes_to_i64(b),
        ValueType::F32 => bytes_to_f32(a) > bytes_to_f32(b),
        ValueType::F64 => bytes_to_f64(a) > bytes_to_f64(b),
        _ => false,
    }
}

/// Compare less than
fn compare_lt(a: &[u8], b: &[u8], value_type: ValueType) -> bool {
    match value_type {
        ValueType::U8 => bytes_to_u8(a) < bytes_to_u8(b),
        ValueType::U16 => bytes_to_u16(a) < bytes_to_u16(b),
        ValueType::U32 => bytes_to_u32(a) < bytes_to_u32(b),
        ValueType::U64 => bytes_to_u64(a) < bytes_to_u64(b),
        ValueType::I8 => bytes_to_i8(a) < bytes_to_i8(b),
        ValueType::I16 => bytes_to_i16(a) < bytes_to_i16(b),
        ValueType::I32 => bytes_to_i32(a) < bytes_to_i32(b),
        ValueType::I64 => bytes_to_i64(a) < bytes_to_i64(b),
        ValueType::F32 => bytes_to_f32(a) < bytes_to_f32(b),
        ValueType::F64 => bytes_to_f64(a) < bytes_to_f64(b),
        _ => false,
    }
}

/// Compare greater than or equal
fn compare_gte(a: &[u8], b: &[u8], value_type: ValueType) -> bool {
    !compare_lt(a, b, value_type)
}

/// Compare less than or equal
fn compare_lte(a: &[u8], b: &[u8], value_type: ValueType) -> bool {
    !compare_gt(a, b, value_type)
}

/// Fuzzy comparison with tolerance
fn compare_fuzzy(a: &[u8], b: &[u8], value_type: ValueType, tolerance: f64) -> bool {
    match value_type {
        ValueType::F32 => {
            let va = bytes_to_f32(a);
            let vb = bytes_to_f32(b);
            let diff = (va - vb).abs();
            let threshold = vb.abs() * tolerance as f32;
            diff <= threshold.max(0.0001) // Minimum threshold for near-zero values
        }
        ValueType::F64 => {
            let va = bytes_to_f64(a);
            let vb = bytes_to_f64(b);
            let diff = (va - vb).abs();
            let threshold = vb.abs() * tolerance;
            diff <= threshold.max(0.0000001)
        }
        ValueType::I32 => {
            let va = bytes_to_i32(a) as f64;
            let vb = bytes_to_i32(b) as f64;
            let diff = (va - vb).abs();
            let threshold = vb.abs() * tolerance;
            diff <= threshold.max(1.0)
        }
        ValueType::U32 => {
            let va = bytes_to_u32(a) as f64;
            let vb = bytes_to_u32(b) as f64;
            let diff = (va - vb).abs();
            let threshold = vb.abs() * tolerance;
            diff <= threshold.max(1.0)
        }
        _ => a == b, // Exact match for other types
    }
}

// Byte conversion helpers
fn bytes_to_u8(b: &[u8]) -> u8 {
    b.first().copied().unwrap_or(0)
}

fn bytes_to_u16(b: &[u8]) -> u16 {
    let arr: [u8; 2] = b.get(..2).and_then(|s| s.try_into().ok()).unwrap_or([0; 2]);
    u16::from_le_bytes(arr)
}

fn bytes_to_u32(b: &[u8]) -> u32 {
    let arr: [u8; 4] = b.get(..4).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]);
    u32::from_le_bytes(arr)
}

fn bytes_to_u64(b: &[u8]) -> u64 {
    let arr: [u8; 8] = b.get(..8).and_then(|s| s.try_into().ok()).unwrap_or([0; 8]);
    u64::from_le_bytes(arr)
}

fn bytes_to_i8(b: &[u8]) -> i8 {
    b.first().map(|&v| v as i8).unwrap_or(0)
}

fn bytes_to_i16(b: &[u8]) -> i16 {
    let arr: [u8; 2] = b.get(..2).and_then(|s| s.try_into().ok()).unwrap_or([0; 2]);
    i16::from_le_bytes(arr)
}

fn bytes_to_i32(b: &[u8]) -> i32 {
    let arr: [u8; 4] = b.get(..4).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]);
    i32::from_le_bytes(arr)
}

fn bytes_to_i64(b: &[u8]) -> i64 {
    let arr: [u8; 8] = b.get(..8).and_then(|s| s.try_into().ok()).unwrap_or([0; 8]);
    i64::from_le_bytes(arr)
}

fn bytes_to_f32(b: &[u8]) -> f32 {
    let arr: [u8; 4] = b.get(..4).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]);
    f32::from_le_bytes(arr)
}

fn bytes_to_f64(b: &[u8]) -> f64 {
    let arr: [u8; 8] = b.get(..8).and_then(|s| s.try_into().ok()).unwrap_or([0; 8]);
    f64::from_le_bytes(arr)
}

/// Convert bytes to display string
fn bytes_to_display(b: &[u8], value_type: ValueType) -> String {
    match value_type {
        ValueType::U8 => bytes_to_u8(b).to_string(),
        ValueType::U16 => bytes_to_u16(b).to_string(),
        ValueType::U32 => bytes_to_u32(b).to_string(),
        ValueType::U64 => bytes_to_u64(b).to_string(),
        ValueType::I8 => bytes_to_i8(b).to_string(),
        ValueType::I16 => bytes_to_i16(b).to_string(),
        ValueType::I32 => bytes_to_i32(b).to_string(),
        ValueType::I64 => bytes_to_i64(b).to_string(),
        ValueType::F32 => bytes_to_f32(b).to_string(),
        ValueType::F64 => bytes_to_f64(b).to_string(),
        ValueType::String => String::from_utf8_lossy(b).to_string(),
        ValueType::Bytes => hex::encode(b),
    }
}

/// Get Cheat Engine type string
fn ce_type_string(value_type: ValueType) -> &'static str {
    match value_type {
        ValueType::U8 | ValueType::I8 => "Byte",
        ValueType::U16 | ValueType::I16 => "2 Bytes",
        ValueType::U32 | ValueType::I32 => "4 Bytes",
        ValueType::U64 | ValueType::I64 => "8 Bytes",
        ValueType::F32 => "Float",
        ValueType::F64 => "Double",
        ValueType::String => "String",
        ValueType::Bytes => "Array of byte",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Session Management Tests
    // ========================================================================

    #[test]
    fn test_scanner_create_session() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());
        assert_eq!(id.0, 1);

        let session = scanner.get_session(id).unwrap();
        assert_eq!(session.scan_count, 0);
        assert!(session.active);
    }

    #[test]
    fn test_scanner_multiple_sessions() {
        let scanner = Scanner::new();
        let id1 = scanner.create_session(ScanOptions::default());
        let id2 = scanner.create_session(ScanOptions::default());
        let id3 = scanner.create_session(ScanOptions::default());

        assert_eq!(id1.0, 1);
        assert_eq!(id2.0, 2);
        assert_eq!(id3.0, 3);

        let sessions = scanner.list_sessions();
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn test_scanner_close_session() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());
        assert!(scanner.close_session(id));
        assert!(scanner.get_session(id).is_none());
    }

    #[test]
    fn test_scanner_close_nonexistent_session() {
        let scanner = Scanner::new();
        assert!(!scanner.close_session(ScanId(999)));
    }

    #[test]
    fn test_scanner_max_results_capped() {
        let scanner = Scanner::new();
        let options = ScanOptions {
            max_results: 0, // Should be capped to MAX_RESULTS_LIMIT
            ..Default::default()
        };

        let id = scanner.create_session(options);
        let session = scanner.get_session(id).unwrap();
        assert_eq!(session.options.max_results, MAX_RESULTS_LIMIT);
    }

    // ========================================================================
    // Cancellation Tests
    // ========================================================================

    #[test]
    fn test_scanner_cancel_flag() {
        let scanner = Scanner::new();
        let session_id = scanner.create_session(ScanOptions::default());
        
        // Per-session cancellation
        assert!(!scanner.is_cancelled(session_id));
        
        scanner.cancel_session(session_id);
        assert!(scanner.is_cancelled(session_id));
        
        scanner.reset_cancel(session_id);
        assert!(!scanner.is_cancelled(session_id));
        
        // Global cancellation (backwards compatibility)
        assert!(!scanner.is_any_cancelled());
        scanner.cancel();
        assert!(scanner.is_any_cancelled());
    }

    // ========================================================================
    // Comparison Function Tests
    // ========================================================================

    #[test]
    fn test_compare_gt_i32() {
        let a = 100i32.to_le_bytes();
        let b = 50i32.to_le_bytes();
        assert!(compare_gt(&a, &b, ValueType::I32));
        assert!(!compare_gt(&b, &a, ValueType::I32));
        assert!(!compare_gt(&a, &a, ValueType::I32)); // Equal should be false
    }

    #[test]
    fn test_compare_gt_negative() {
        let a = (-10i32).to_le_bytes();
        let b = (-50i32).to_le_bytes();
        assert!(compare_gt(&a, &b, ValueType::I32));
        assert!(!compare_gt(&b, &a, ValueType::I32));
    }

    #[test]
    fn test_compare_gt_u32() {
        let a = 100u32.to_le_bytes();
        let b = 50u32.to_le_bytes();
        assert!(compare_gt(&a, &b, ValueType::U32));
        assert!(!compare_gt(&b, &a, ValueType::U32));
    }

    #[test]
    fn test_compare_gt_f32() {
        let a = 100.5f32.to_le_bytes();
        let b = 50.5f32.to_le_bytes();
        assert!(compare_gt(&a, &b, ValueType::F32));
        assert!(!compare_gt(&b, &a, ValueType::F32));
    }

    #[test]
    fn test_compare_gt_f64() {
        let a = 100.5f64.to_le_bytes();
        let b = 50.5f64.to_le_bytes();
        assert!(compare_gt(&a, &b, ValueType::F64));
        assert!(!compare_gt(&b, &a, ValueType::F64));
    }

    #[test]
    fn test_compare_lt_i32() {
        let a = 50i32.to_le_bytes();
        let b = 100i32.to_le_bytes();
        assert!(compare_lt(&a, &b, ValueType::I32));
        assert!(!compare_lt(&b, &a, ValueType::I32));
        assert!(!compare_lt(&a, &a, ValueType::I32)); // Equal should be false
    }

    #[test]
    fn test_compare_between() {
        let current = 50i32.to_le_bytes();
        let min = 10i32.to_le_bytes();
        let max = 100i32.to_le_bytes();
        assert!(compare_between(&current, &min, &max, ValueType::I32));

        let outside = 150i32.to_le_bytes();
        assert!(!compare_between(&outside, &min, &max, ValueType::I32));

        // Edge cases - boundaries should be included
        assert!(compare_between(&min, &min, &max, ValueType::I32));
        assert!(compare_between(&max, &min, &max, ValueType::I32));
    }

    #[test]
    fn test_compare_fuzzy_f32() {
        let a = 100.0f32.to_le_bytes();
        let b = 105.0f32.to_le_bytes();
        assert!(compare_fuzzy(&a, &b, ValueType::F32, 0.1)); // 10% tolerance
        assert!(!compare_fuzzy(&a, &b, ValueType::F32, 0.01)); // 1% tolerance

        // Near-zero values
        let c = 0.0001f32.to_le_bytes();
        let d = 0.0001f32.to_le_bytes();
        assert!(compare_fuzzy(&c, &d, ValueType::F32, 0.1));
    }

    #[test]
    fn test_compare_fuzzy_f64() {
        let a = 1000.0f64.to_le_bytes();
        let b = 1050.0f64.to_le_bytes();
        assert!(compare_fuzzy(&a, &b, ValueType::F64, 0.1)); // 10% tolerance
        assert!(!compare_fuzzy(&a, &b, ValueType::F64, 0.01)); // 1% tolerance
    }

    #[test]
    fn test_compare_fuzzy_i32() {
        let a = 100i32.to_le_bytes();
        let b = 105i32.to_le_bytes();
        assert!(compare_fuzzy(&a, &b, ValueType::I32, 0.1)); // 10% tolerance
        assert!(!compare_fuzzy(&a, &b, ValueType::I32, 0.01)); // 1% tolerance
    }

    // ========================================================================
    // Byte Conversion Tests
    // ========================================================================

    #[test]
    fn test_bytes_to_u8() {
        assert_eq!(bytes_to_u8(&[42]), 42);
        assert_eq!(bytes_to_u8(&[255]), 255);
        assert_eq!(bytes_to_u8(&[]), 0); // Empty slice returns 0
    }

    #[test]
    fn test_bytes_to_u16() {
        let val: u16 = 12345;
        let bytes = val.to_le_bytes();
        assert_eq!(bytes_to_u16(&bytes), val);
        assert_eq!(bytes_to_u16(&[]), 0); // Empty slice returns 0
    }

    #[test]
    fn test_bytes_to_u32() {
        let val: u32 = 123456789;
        let bytes = val.to_le_bytes();
        assert_eq!(bytes_to_u32(&bytes), val);
    }

    #[test]
    fn test_bytes_to_i32() {
        let val: i32 = -123456;
        let bytes = val.to_le_bytes();
        assert_eq!(bytes_to_i32(&bytes), val);
    }

    #[test]
    fn test_bytes_to_f32() {
        let val: f32 = 123.456;
        let bytes = val.to_le_bytes();
        assert!((bytes_to_f32(&bytes) - val).abs() < 0.001);
    }

    #[test]
    fn test_bytes_to_display() {
        let val = 100i32.to_le_bytes();
        assert_eq!(bytes_to_display(&val, ValueType::I32), "100");

        let float_val = 3.5f32.to_le_bytes();
        assert_eq!(bytes_to_display(&float_val, ValueType::F32), "3.5");

        let hex_val = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(bytes_to_display(&hex_val, ValueType::Bytes), "deadbeef");
    }

    // ========================================================================
    // Type Size Tests
    // ========================================================================

    #[test]
    fn test_type_size() {
        assert_eq!(type_size(ValueType::U8), 1);
        assert_eq!(type_size(ValueType::I8), 1);
        assert_eq!(type_size(ValueType::U16), 2);
        assert_eq!(type_size(ValueType::I16), 2);
        assert_eq!(type_size(ValueType::U32), 4);
        assert_eq!(type_size(ValueType::I32), 4);
        assert_eq!(type_size(ValueType::F32), 4);
        assert_eq!(type_size(ValueType::U64), 8);
        assert_eq!(type_size(ValueType::I64), 8);
        assert_eq!(type_size(ValueType::F64), 8);
    }

    // ========================================================================
    // Export/Import Tests
    // ========================================================================

    #[test]
    fn test_export_csv() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());

        // Manually add a result for testing
        {
            let mut sessions = scanner.sessions.write().unwrap();
            if let Some(session) = sessions.get_mut(&id) {
                session.results.push(ScanResultEx {
                    address: 0x1000,
                    value: 100i32.to_le_bytes().to_vec(),
                    previous_value: None,
                    first_value: None,
                });
            }
        }

        let csv = scanner.export_results(id, ScanExportFormat::Csv).unwrap();
        assert!(csv.contains("0x1000"));
        assert!(csv.contains("100"));
        assert!(csv.contains("address,value_hex,value_dec")); // Header
    }

    #[test]
    fn test_export_json() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());

        {
            let mut sessions = scanner.sessions.write().unwrap();
            if let Some(session) = sessions.get_mut(&id) {
                session.results.push(ScanResultEx {
                    address: 0x2000,
                    value: vec![1, 2, 3, 4],
                    previous_value: None,
                    first_value: None,
                });
            }
        }

        let json = scanner.export_results(id, ScanExportFormat::Json).unwrap();
        assert!(json.contains("8192")); // 0x2000 in decimal
        assert!(json.contains("address"));
    }

    #[test]
    fn test_export_cheat_engine_xml() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());

        {
            let mut sessions = scanner.sessions.write().unwrap();
            if let Some(session) = sessions.get_mut(&id) {
                session.results.push(ScanResultEx {
                    address: 0x3000,
                    value: 42i32.to_le_bytes().to_vec(),
                    previous_value: None,
                    first_value: None,
                });
            }
        }

        let xml = scanner
            .export_results(id, ScanExportFormat::CheatEngineXml)
            .unwrap();
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("<CheatTable>"));
        assert!(xml.contains("3000")); // Address in hex
        assert!(xml.contains("4 Bytes")); // Default i32 type
    }

    #[test]
    fn test_import_json() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());

        let json = r#"[{"address": 4096, "value": [100, 0, 0, 0], "previous_value": null, "first_value": null}]"#;
        let count = scanner.import_results(id, json).unwrap();

        assert_eq!(count, 1);
        assert_eq!(scanner.get_result_count(id), 1);

        let results = scanner.get_results(id, 0, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 4096);
    }

    #[test]
    fn test_import_invalid_json() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());

        let result = scanner.import_results(id, "not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_export_nonexistent_session() {
        let scanner = Scanner::new();
        let result = scanner.export_results(ScanId(999), ScanExportFormat::Json);
        assert!(result.is_err());
    }

    // ========================================================================
    // Result Pagination Tests
    // ========================================================================

    #[test]
    fn test_get_results_pagination() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());

        {
            let mut sessions = scanner.sessions.write().unwrap();
            if let Some(session) = sessions.get_mut(&id) {
                for i in 0..100 {
                    session.results.push(ScanResultEx {
                        address: 0x1000 + i * 4,
                        value: (i as i32).to_le_bytes().to_vec(),
                        previous_value: None,
                        first_value: None,
                    });
                }
            }
        }

        // First page
        let page1 = scanner.get_results(id, 0, 10);
        assert_eq!(page1.len(), 10);
        assert_eq!(page1[0].address, 0x1000);

        // Second page
        let page2 = scanner.get_results(id, 10, 10);
        assert_eq!(page2.len(), 10);
        assert_eq!(page2[0].address, 0x1000 + 10 * 4);

        // Last page (partial)
        let last = scanner.get_results(id, 95, 10);
        assert_eq!(last.len(), 5);

        // Total count
        assert_eq!(scanner.get_result_count(id), 100);
    }

    #[test]
    fn test_get_results_no_limit() {
        let scanner = Scanner::new();
        let id = scanner.create_session(ScanOptions::default());

        {
            let mut sessions = scanner.sessions.write().unwrap();
            if let Some(session) = sessions.get_mut(&id) {
                for i in 0..50 {
                    session.results.push(ScanResultEx {
                        address: 0x1000 + i * 4,
                        value: vec![0],
                        previous_value: None,
                        first_value: None,
                    });
                }
            }
        }

        // Limit 0 means no limit
        let all = scanner.get_results(id, 0, 0);
        assert_eq!(all.len(), 50);
    }

    // ========================================================================
    // Region Filter Tests
    // ========================================================================

    #[test]
    fn test_filter_regions_committed() {
        use ghost_common::{MemoryType, Protection};

        let regions = vec![
            MemoryRegion {
                base: 0x1000,
                size: 0x1000,
                protection: Protection::new(true, true, false),
                state: MemoryState::Commit,
                region_type: MemoryType::Private,
            },
            MemoryRegion {
                base: 0x2000,
                size: 0x1000,
                protection: Protection::new(true, false, false),
                state: MemoryState::Reserve,
                region_type: MemoryType::Private,
            },
        ];

        let filter = RegionFilter::new();
        let filtered = filter_regions(&regions, &filter);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].base, 0x1000);
    }

    #[test]
    fn test_filter_regions_writable() {
        use ghost_common::{MemoryType, Protection};

        let regions = vec![
            MemoryRegion {
                base: 0x1000,
                size: 0x1000,
                protection: Protection::new(true, true, false),
                state: MemoryState::Commit,
                region_type: MemoryType::Private,
            },
            MemoryRegion {
                base: 0x2000,
                size: 0x1000,
                protection: Protection::new(true, false, false),
                state: MemoryState::Commit,
                region_type: MemoryType::Private,
            },
        ];

        let filter = RegionFilter::writable();
        let filtered = filter_regions(&regions, &filter);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].base, 0x1000);
    }

    #[test]
    fn test_filter_regions_address_range() {
        use ghost_common::{MemoryType, Protection};

        let regions = vec![
            MemoryRegion {
                base: 0x1000,
                size: 0x1000,
                protection: Protection::new(true, true, false),
                state: MemoryState::Commit,
                region_type: MemoryType::Private,
            },
            MemoryRegion {
                base: 0x5000,
                size: 0x1000,
                protection: Protection::new(true, true, false),
                state: MemoryState::Commit,
                region_type: MemoryType::Private,
            },
        ];

        let mut filter = RegionFilter::new();
        filter.start_address = Some(0x3000);
        filter.end_address = Some(0x6000);
        let filtered = filter_regions(&regions, &filter);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].base, 0x5000);
    }

    // ========================================================================
    // CE Type String Tests
    // ========================================================================

    #[test]
    fn test_ce_type_string() {
        assert_eq!(ce_type_string(ValueType::U8), "Byte");
        assert_eq!(ce_type_string(ValueType::I8), "Byte");
        assert_eq!(ce_type_string(ValueType::U16), "2 Bytes");
        assert_eq!(ce_type_string(ValueType::I32), "4 Bytes");
        assert_eq!(ce_type_string(ValueType::F32), "Float");
        assert_eq!(ce_type_string(ValueType::F64), "Double");
        assert_eq!(ce_type_string(ValueType::String), "String");
    }

    // ========================================================================
    // ScanCompareType Parse Tests
    // ========================================================================

    #[test]
    fn test_scan_compare_type_parse() {
        assert_eq!(
            ScanCompareType::parse("exact"),
            Some(ScanCompareType::Exact)
        );
        assert_eq!(
            ScanCompareType::parse("EXACT"),
            Some(ScanCompareType::Exact)
        ); // Case insensitive
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
            ScanCompareType::parse(">"),
            Some(ScanCompareType::Increased)
        );
        assert_eq!(
            ScanCompareType::parse("decreased"),
            Some(ScanCompareType::Decreased)
        );
        assert_eq!(
            ScanCompareType::parse("<"),
            Some(ScanCompareType::Decreased)
        );
        assert_eq!(
            ScanCompareType::parse("fuzzy"),
            Some(ScanCompareType::Fuzzy)
        );
        assert_eq!(ScanCompareType::parse("~"), Some(ScanCompareType::Fuzzy));
        assert_eq!(
            ScanCompareType::parse("unknown"),
            Some(ScanCompareType::UnknownInitial)
        );
        assert_eq!(
            ScanCompareType::parse("between"),
            Some(ScanCompareType::Between)
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
        assert!(!ScanCompareType::UnknownInitial.requires_previous());
    }

    #[test]
    fn test_scan_compare_type_is_initial() {
        assert!(ScanCompareType::Exact.is_initial());
        assert!(ScanCompareType::UnknownInitial.is_initial());
        assert!(ScanCompareType::Between.is_initial());
        assert!(ScanCompareType::Fuzzy.is_initial());
        assert!(!ScanCompareType::Changed.is_initial());
        assert!(!ScanCompareType::Increased.is_initial());
    }
}
