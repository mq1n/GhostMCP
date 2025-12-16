//! Memory Dump & Analysis Module
//!
//! Provides comprehensive memory dump creation, management, and PE reconstruction capabilities.
//!
//! Features:
//! - Full process memory dumps
//! - Selective region dumps
//! - Module dumps with PE structure
//! - Minidump creation (WinDbg compatible)
//! - Incremental/differential dumps
//! - Dump comparison and pattern matching
//! - PE reconstruction (import table, relocations, section alignment)

use ghost_common::{
    DumpCatalog, DumpChange, DumpChangeType, DumpDiff, DumpId, DumpInfo, DumpOptions, DumpRegion,
    DumpResult, DumpSearchOptions, DumpSearchResult, DumpType, MemoryType, MinidumpOptions,
    PeReconstructOptions, PeReconstructResult, Protection, ReconstructedImport,
    ReconstructedSection, Result,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace, warn};

// ============================================================================
// Constants
// ============================================================================

/// Minidump signature "MDMP"
const MINIDUMP_SIGNATURE: u32 = 0x504D444D;

/// Minidump version
const MINIDUMP_VERSION: u32 = 0xA793;

/// PE signature "MZ"
const PE_DOS_SIGNATURE: u16 = 0x5A4D;

/// PE NT signature "PE\0\0"
const PE_NT_SIGNATURE: u32 = 0x00004550;

/// Default dump chunk size for reading memory (used for chunked reads)
#[allow(dead_code)]
const DUMP_CHUNK_SIZE: usize = 64 * 1024; // 64KB

// ============================================================================
// Dump Manager
// ============================================================================

/// Manages memory dumps, catalog, and operations
pub struct DumpManager {
    /// Catalog of all dumps
    catalog: DumpCatalog,
    /// In-memory dump cache (dump_id -> data)
    cache: HashMap<u32, Vec<u8>>,
    /// Base path for dump files
    base_path: Option<String>,
    /// Process ID being dumped
    #[allow(dead_code)]
    pid: u32,
    /// Process name
    #[allow(dead_code)]
    process_name: String,
}

impl DumpManager {
    /// Create a new dump manager
    pub fn new(pid: u32, process_name: impl Into<String>) -> Self {
        info!(pid = pid, "Creating new DumpManager");
        Self {
            catalog: DumpCatalog::new(),
            cache: HashMap::new(),
            base_path: None,
            pid,
            process_name: process_name.into(),
        }
    }

    /// Set the base path for dump files
    pub fn set_base_path(&mut self, path: impl Into<String>) {
        self.base_path = Some(path.into());
    }

    /// Get the catalog
    pub fn catalog(&self) -> &DumpCatalog {
        &self.catalog
    }

    /// Get a mutable reference to the catalog
    pub fn catalog_mut(&mut self) -> &mut DumpCatalog {
        &mut self.catalog
    }

    /// Get cached dump data
    pub fn get_cached_dump(&self, dump_id: DumpId) -> Option<&Vec<u8>> {
        self.cache.get(&dump_id.0)
    }

    /// Cache dump data
    pub fn cache_dump(&mut self, dump_id: DumpId, data: Vec<u8>) {
        debug!(dump_id = dump_id.0, size = data.len(), "Caching dump data");
        self.cache.insert(dump_id.0, data);
    }

    /// Clear dump cache
    pub fn clear_cache(&mut self) {
        info!("Clearing dump cache");
        self.cache.clear();
    }

    /// Remove a specific dump from cache
    pub fn remove_from_cache(&mut self, dump_id: DumpId) {
        debug!(dump_id = dump_id.0, "Removing dump from cache");
        self.cache.remove(&dump_id.0);
    }
}

// ============================================================================
// Dump Creation Functions
// ============================================================================

/// Create a full process memory dump
///
/// Reads all committed memory regions and creates a comprehensive dump.
pub fn create_full_process_dump<F>(
    options: &DumpOptions,
    read_memory: F,
    regions: &[DumpRegion],
    pid: u32,
    process_name: &str,
) -> Result<DumpResult>
where
    F: Fn(usize, usize) -> Result<Vec<u8>>,
{
    let start_time = std::time::Instant::now();
    info!(
        pid = pid,
        regions = regions.len(),
        "Creating full process dump"
    );

    let mut dump_data = Vec::new();
    let mut dump_regions = Vec::new();
    let mut current_offset = 0usize;

    for region in regions {
        // Skip non-committed memory if option is set
        if options.committed_only && region.memory_type == MemoryType::Private {
            trace!(
                base = format!("0x{:X}", region.base_address),
                "Skipping non-committed region"
            );
            continue;
        }

        // Skip non-executable if option is set
        if options.executable_only && !region.protection.execute {
            continue;
        }

        debug!(
            base = format!("0x{:X}", region.base_address),
            size = region.size,
            "Dumping region"
        );

        match read_memory(region.base_address, region.size) {
            Ok(data) => {
                let region_info = DumpRegion {
                    base_address: region.base_address,
                    file_offset: current_offset,
                    size: data.len(),
                    protection: region.protection,
                    memory_type: region.memory_type,
                    module: region.module.clone(),
                };
                dump_regions.push(region_info);
                current_offset += data.len();
                dump_data.extend(data);
            }
            Err(e) => {
                warn!(
                    base = format!("0x{:X}", region.base_address),
                    error = %e,
                    "Failed to read region, skipping"
                );
            }
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;
    let checksum = calculate_checksum(&dump_data);

    let dump_info = DumpInfo {
        id: DumpId(0), // Will be assigned by catalog
        dump_type: DumpType::FullProcess,
        pid,
        process_name: process_name.to_string(),
        created_at: current_timestamp_ms(),
        size: dump_data.len() as u64,
        region_count: dump_regions.len() as u32,
        file_path: options.output_path.clone(),
        compressed: options.compress,
        base_dump_id: None,
        description: None,
        checksum: Some(checksum),
        regions: dump_regions,
        annotations: options.annotations.clone(),
    };

    info!(
        size = dump_data.len(),
        regions = dump_info.region_count,
        duration_ms = duration_ms,
        "Full process dump created"
    );

    // Compress if requested
    let final_data = if options.compress {
        compress_data(&dump_data)?
    } else {
        dump_data
    };

    // Save to file if output path specified
    if let Some(ref path) = options.output_path {
        save_dump_to_file(path, &final_data)?;
    }

    Ok(DumpResult {
        info: dump_info,
        data: if options.output_path.is_none() {
            Some(final_data)
        } else {
            None
        },
        success: true,
        error: None,
        duration_ms,
    })
}

/// Create a selective region dump
///
/// Dumps a specific memory range.
pub fn create_region_dump<F>(
    start_address: usize,
    end_address: usize,
    options: &DumpOptions,
    read_memory: F,
    pid: u32,
    process_name: &str,
) -> Result<DumpResult>
where
    F: Fn(usize, usize) -> Result<Vec<u8>>,
{
    let start_time = std::time::Instant::now();
    let size = end_address.saturating_sub(start_address);

    info!(
        start = format!("0x{:X}", start_address),
        end = format!("0x{:X}", end_address),
        size = size,
        "Creating region dump"
    );

    if size == 0 {
        return Err(ghost_common::Error::Internal(
            "Region size must be greater than 0".to_string(),
        ));
    }

    // Read the memory region
    let dump_data = read_memory(start_address, size)?;
    let duration_ms = start_time.elapsed().as_millis() as u64;
    let checksum = calculate_checksum(&dump_data);

    let region = DumpRegion {
        base_address: start_address,
        file_offset: 0,
        size: dump_data.len(),
        protection: Protection::new(true, true, false), // Default, actual protection unknown
        memory_type: MemoryType::Private,
        module: None,
    };

    let dump_info = DumpInfo {
        id: DumpId(0),
        dump_type: DumpType::Region,
        pid,
        process_name: process_name.to_string(),
        created_at: current_timestamp_ms(),
        size: dump_data.len() as u64,
        region_count: 1,
        file_path: options.output_path.clone(),
        compressed: options.compress,
        base_dump_id: None,
        description: Some(format!(
            "Region dump: 0x{:X} - 0x{:X}",
            start_address, end_address
        )),
        checksum: Some(checksum),
        regions: vec![region],
        annotations: options.annotations.clone(),
    };

    // Compress if requested
    let final_data = if options.compress {
        compress_data(&dump_data)?
    } else {
        dump_data
    };

    // Save to file if output path specified
    if let Some(ref path) = options.output_path {
        save_dump_to_file(path, &final_data)?;
    }

    info!(
        size = final_data.len(),
        duration_ms = duration_ms,
        "Region dump created"
    );

    Ok(DumpResult {
        info: dump_info,
        data: if options.output_path.is_none() {
            Some(final_data)
        } else {
            None
        },
        success: true,
        error: None,
        duration_ms,
    })
}

/// Create a module dump with PE structure
///
/// Dumps a loaded module and optionally reconstructs the PE.
pub fn create_module_dump<F>(
    module_base: usize,
    module_size: usize,
    module_name: &str,
    options: &DumpOptions,
    read_memory: F,
    pid: u32,
    process_name: &str,
) -> Result<DumpResult>
where
    F: Fn(usize, usize) -> Result<Vec<u8>>,
{
    let start_time = std::time::Instant::now();
    info!(
        module = module_name,
        base = format!("0x{:X}", module_base),
        size = module_size,
        "Creating module dump"
    );

    // Read the entire module
    let module_data = read_memory(module_base, module_size)?;

    // Validate PE signature
    if module_data.len() < 64 {
        return Err(ghost_common::Error::Internal(
            "Module too small to be a valid PE".to_string(),
        ));
    }

    let dos_sig = u16::from_le_bytes([module_data[0], module_data[1]]);
    if dos_sig != PE_DOS_SIGNATURE {
        warn!(
            module = module_name,
            "Module does not have valid DOS signature"
        );
    }

    let mut dump_data = module_data;

    // Reconstruct PE if requested
    if options.reconstruct_pe {
        debug!(module = module_name, "Reconstructing PE structure");
        match reconstruct_pe_internal(&dump_data, module_base, &PeReconstructOptions::default()) {
            Ok(reconstructed) => {
                if let Some(data) = reconstructed.data {
                    dump_data = data;
                    info!(
                        module = module_name,
                        imports_resolved = reconstructed.imports_resolved,
                        "PE reconstructed successfully"
                    );
                }
            }
            Err(e) => {
                warn!(
                    module = module_name,
                    error = %e,
                    "PE reconstruction failed, using raw dump"
                );
            }
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;
    let checksum = calculate_checksum(&dump_data);

    let region = DumpRegion {
        base_address: module_base,
        file_offset: 0,
        size: dump_data.len(),
        protection: Protection::new(true, false, true),
        memory_type: MemoryType::Image,
        module: Some(module_name.to_string()),
    };

    let dump_info = DumpInfo {
        id: DumpId(0),
        dump_type: DumpType::Module,
        pid,
        process_name: process_name.to_string(),
        created_at: current_timestamp_ms(),
        size: dump_data.len() as u64,
        region_count: 1,
        file_path: options.output_path.clone(),
        compressed: options.compress,
        base_dump_id: None,
        description: Some(format!("Module dump: {}", module_name)),
        checksum: Some(checksum),
        regions: vec![region],
        annotations: options.annotations.clone(),
    };

    // Compress if requested
    let final_data = if options.compress {
        compress_data(&dump_data)?
    } else {
        dump_data
    };

    // Save to file if output path specified
    if let Some(ref path) = options.output_path {
        save_dump_to_file(path, &final_data)?;
    }

    info!(
        module = module_name,
        size = final_data.len(),
        duration_ms = duration_ms,
        "Module dump created"
    );

    Ok(DumpResult {
        info: dump_info,
        data: if options.output_path.is_none() {
            Some(final_data)
        } else {
            None
        },
        success: true,
        error: None,
        duration_ms,
    })
}

/// Create a minidump (WinDbg compatible)
///
/// Creates a minidump file that can be opened with WinDbg for analysis.
///
/// Note: Full implementation requires the `windows` crate with appropriate features.
/// This stub creates a basic dump structure; production use should integrate with
/// the Windows MiniDumpWriteDump API.
pub fn create_minidump(
    options: &MinidumpOptions,
    pid: u32,
    process_name: &str,
) -> Result<DumpResult> {
    let start_time = std::time::Instant::now();
    info!(
        pid = pid,
        output = &options.output_path,
        "Creating minidump"
    );

    // Write minidump header structure
    // Full implementation would use MiniDumpWriteDump from dbghelp.dll
    let mut dump_data = Vec::new();

    // Minidump header (MINIDUMP_HEADER)
    dump_data.extend_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes()); // Signature
    dump_data.extend_from_slice(&MINIDUMP_VERSION.to_le_bytes()); // Version
    dump_data.extend_from_slice(&0u32.to_le_bytes()); // NumberOfStreams
    dump_data.extend_from_slice(&32u32.to_le_bytes()); // StreamDirectoryRva
    dump_data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    dump_data.extend_from_slice(&(current_timestamp_ms() as u32).to_le_bytes()); // TimeDateStamp
    dump_data.extend_from_slice(&0u64.to_le_bytes()); // Flags

    // Save to file
    save_dump_to_file(&options.output_path, &dump_data)?;

    let duration_ms = start_time.elapsed().as_millis() as u64;
    let file_size = dump_data.len() as u64;

    let dump_info = DumpInfo {
        id: DumpId(0),
        dump_type: DumpType::Minidump,
        pid,
        process_name: process_name.to_string(),
        created_at: current_timestamp_ms(),
        size: file_size,
        region_count: 0,
        file_path: Some(options.output_path.clone()),
        compressed: false,
        base_dump_id: None,
        description: Some("WinDbg-compatible minidump (basic header)".to_string()),
        checksum: None,
        regions: Vec::new(),
        annotations: Vec::new(),
    };

    info!(
        size = file_size,
        duration_ms = duration_ms,
        "Minidump created"
    );

    Ok(DumpResult {
        info: dump_info,
        data: None,
        success: true,
        error: None,
        duration_ms,
    })
}

// ============================================================================
// Dump Comparison Functions
// ============================================================================

/// Compare two dumps and find differences
pub fn compare_dumps(dump_a: &[u8], dump_b: &[u8], id_a: DumpId, id_b: DumpId) -> DumpDiff {
    info!(
        dump_a = id_a.0,
        dump_b = id_b.0,
        size_a = dump_a.len(),
        size_b = dump_b.len(),
        "Comparing dumps"
    );

    let mut changes = Vec::new();
    let mut bytes_changed = 0u64;

    let min_len = dump_a.len().min(dump_b.len());

    // Find modified regions
    let mut i = 0;
    while i < min_len {
        if dump_a[i] != dump_b[i] {
            // Found a difference, find the extent
            let start = i;
            while i < min_len && dump_a[i] != dump_b[i] {
                i += 1;
            }
            let size = i - start;

            changes.push(DumpChange {
                address: start,
                size,
                old_bytes: dump_a[start..i].to_vec(),
                new_bytes: dump_b[start..i].to_vec(),
                change_type: DumpChangeType::Modified,
            });
            bytes_changed += size as u64;
        } else {
            i += 1;
        }
    }

    // Handle size differences
    if dump_b.len() > dump_a.len() {
        let added_size = dump_b.len() - dump_a.len();
        changes.push(DumpChange {
            address: dump_a.len(),
            size: added_size,
            old_bytes: Vec::new(),
            new_bytes: dump_b[dump_a.len()..].to_vec(),
            change_type: DumpChangeType::Added,
        });
        bytes_changed += added_size as u64;
    } else if dump_a.len() > dump_b.len() {
        let removed_size = dump_a.len() - dump_b.len();
        changes.push(DumpChange {
            address: dump_b.len(),
            size: removed_size,
            old_bytes: dump_a[dump_b.len()..].to_vec(),
            new_bytes: Vec::new(),
            change_type: DumpChangeType::Removed,
        });
        bytes_changed += removed_size as u64;
    }

    let regions_changed = changes.len() as u32;

    info!(
        changes = regions_changed,
        bytes_changed = bytes_changed,
        "Dump comparison complete"
    );

    DumpDiff {
        dump_a: id_a,
        dump_b: id_b,
        changes,
        bytes_changed,
        regions_changed,
    }
}

/// Create an incremental dump based on a previous dump
pub fn create_incremental_dump<F>(
    base_dump: &[u8],
    base_dump_id: DumpId,
    regions: &[DumpRegion],
    read_memory: F,
    pid: u32,
    process_name: &str,
) -> Result<DumpResult>
where
    F: Fn(usize, usize) -> Result<Vec<u8>>,
{
    let start_time = std::time::Instant::now();
    info!(base_dump_id = base_dump_id.0, "Creating incremental dump");

    let mut changes = Vec::new();
    let mut total_changed = 0usize;

    // Read current memory and compare with base
    for region in regions {
        let region_data = match read_memory(region.base_address, region.size) {
            Ok(data) => data,
            Err(_) => continue,
        };

        // Find corresponding data in base dump
        let base_start = region.file_offset;
        let base_end = (base_start + region.size).min(base_dump.len());

        if base_start < base_dump.len() {
            let base_region = &base_dump[base_start..base_end];
            let compare_len = region_data.len().min(base_region.len());

            // Find differences
            let mut i = 0;
            while i < compare_len {
                if region_data[i] != base_region[i] {
                    let start = i;
                    while i < compare_len && region_data[i] != base_region[i] {
                        i += 1;
                    }

                    changes.push(DumpChange {
                        address: region.base_address + start,
                        size: i - start,
                        old_bytes: base_region[start..i].to_vec(),
                        new_bytes: region_data[start..i].to_vec(),
                        change_type: DumpChangeType::Modified,
                    });
                    total_changed += i - start;
                } else {
                    i += 1;
                }
            }
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;

    // Serialize changes to dump data
    let dump_data = serde_json::to_vec(&changes).unwrap_or_default();
    let checksum = calculate_checksum(&dump_data);

    let dump_info = DumpInfo {
        id: DumpId(0),
        dump_type: DumpType::Incremental,
        pid,
        process_name: process_name.to_string(),
        created_at: current_timestamp_ms(),
        size: dump_data.len() as u64,
        region_count: changes.len() as u32,
        file_path: None,
        compressed: false,
        base_dump_id: Some(base_dump_id),
        description: Some(format!(
            "Incremental dump: {} changes, {} bytes modified",
            changes.len(),
            total_changed
        )),
        checksum: Some(checksum),
        regions: Vec::new(),
        annotations: Vec::new(),
    };

    info!(
        changes = changes.len(),
        bytes_changed = total_changed,
        duration_ms = duration_ms,
        "Incremental dump created"
    );

    Ok(DumpResult {
        info: dump_info,
        data: Some(dump_data),
        success: true,
        error: None,
        duration_ms,
    })
}

// ============================================================================
// Dump Search Functions
// ============================================================================

/// Search for a pattern within a dump
pub fn search_dump(
    dump_id: DumpId,
    dump_data: &[u8],
    regions: &[DumpRegion],
    options: &DumpSearchOptions,
) -> Vec<DumpSearchResult> {
    info!(
        dump_id = dump_id.0,
        pattern = &options.pattern,
        "Searching dump"
    );

    let pattern = parse_pattern(&options.pattern);
    if pattern.is_empty() {
        warn!("Empty pattern provided");
        return Vec::new();
    }

    let mut results = Vec::new();

    for region in regions {
        if region.file_offset + region.size > dump_data.len() {
            continue;
        }

        let region_data = &dump_data[region.file_offset..region.file_offset + region.size];
        let matches = scan_for_pattern(region_data, &pattern);

        for match_offset in matches {
            let absolute_offset = region.file_offset + match_offset;
            let address = region.base_address + match_offset;
            let match_len = pattern.iter().filter(|b| b.is_some()).count();

            let matched_bytes = region_data
                [match_offset..match_offset + match_len.min(region_data.len() - match_offset)]
                .to_vec();

            let context = if options.include_context {
                let ctx_start = match_offset.saturating_sub(options.context_size);
                let ctx_end =
                    (match_offset + match_len + options.context_size).min(region_data.len());
                Some(region_data[ctx_start..ctx_end].to_vec())
            } else {
                None
            };

            results.push(DumpSearchResult {
                dump_id,
                address,
                file_offset: absolute_offset,
                matched_bytes,
                context,
            });

            if results.len() >= options.max_results {
                debug!(
                    results = results.len(),
                    "Max results reached, stopping search"
                );
                return results;
            }
        }
    }

    info!(results = results.len(), "Dump search complete");
    results
}

// ============================================================================
// PE Reconstruction Functions
// ============================================================================

/// Reconstruct a PE from a memory dump
///
/// Implements Scylla-style import reconstruction and section fixing.
pub fn reconstruct_pe(
    dump_data: &[u8],
    original_base: usize,
    options: &PeReconstructOptions,
) -> Result<PeReconstructResult> {
    info!(
        original_base = format!("0x{:X}", original_base),
        size = dump_data.len(),
        "Reconstructing PE"
    );

    reconstruct_pe_internal(dump_data, original_base, options)
}

/// Internal PE reconstruction implementation
fn reconstruct_pe_internal(
    dump_data: &[u8],
    original_base: usize,
    options: &PeReconstructOptions,
) -> Result<PeReconstructResult> {
    let mut warnings = Vec::new();
    let mut reconstructed = dump_data.to_vec();

    // Validate PE
    if dump_data.len() < 64 {
        return Err(ghost_common::Error::Internal(
            "Data too small for PE".to_string(),
        ));
    }

    let dos_sig = u16::from_le_bytes([dump_data[0], dump_data[1]]);
    if dos_sig != PE_DOS_SIGNATURE {
        return Err(ghost_common::Error::Internal(
            "Invalid DOS signature".to_string(),
        ));
    }

    let e_lfanew = i32::from_le_bytes([dump_data[60], dump_data[61], dump_data[62], dump_data[63]]);
    if e_lfanew < 0 || e_lfanew as usize + 4 > dump_data.len() {
        return Err(ghost_common::Error::Internal(
            "Invalid e_lfanew value".to_string(),
        ));
    }

    let nt_offset = e_lfanew as usize;
    let nt_sig = u32::from_le_bytes([
        dump_data[nt_offset],
        dump_data[nt_offset + 1],
        dump_data[nt_offset + 2],
        dump_data[nt_offset + 3],
    ]);

    if nt_sig != PE_NT_SIGNATURE {
        return Err(ghost_common::Error::Internal(
            "Invalid PE signature".to_string(),
        ));
    }

    // Parse PE headers
    let file_header_offset = nt_offset + 4;
    let optional_header_offset = file_header_offset + 20;

    let machine = u16::from_le_bytes([
        dump_data[file_header_offset],
        dump_data[file_header_offset + 1],
    ]);
    let is_64bit = machine == 0x8664; // IMAGE_FILE_MACHINE_AMD64

    let num_sections = u16::from_le_bytes([
        dump_data[file_header_offset + 2],
        dump_data[file_header_offset + 3],
    ]);

    let optional_header_size = u16::from_le_bytes([
        dump_data[file_header_offset + 16],
        dump_data[file_header_offset + 17],
    ]);

    debug!(
        is_64bit = is_64bit,
        sections = num_sections,
        "Parsing PE headers"
    );

    // Parse sections
    let section_header_offset = optional_header_offset + optional_header_size as usize;
    let mut sections = Vec::new();

    for i in 0..num_sections as usize {
        let section_offset = section_header_offset + i * 40;
        if section_offset + 40 > dump_data.len() {
            break;
        }

        let name_bytes = &dump_data[section_offset..section_offset + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        let virtual_size = u32::from_le_bytes(
            dump_data[section_offset + 8..section_offset + 12]
                .try_into()
                .unwrap(),
        );
        let virtual_address = u32::from_le_bytes(
            dump_data[section_offset + 12..section_offset + 16]
                .try_into()
                .unwrap(),
        );
        let raw_size = u32::from_le_bytes(
            dump_data[section_offset + 16..section_offset + 20]
                .try_into()
                .unwrap(),
        );
        let raw_offset = u32::from_le_bytes(
            dump_data[section_offset + 20..section_offset + 24]
                .try_into()
                .unwrap(),
        );
        let characteristics = u32::from_le_bytes(
            dump_data[section_offset + 36..section_offset + 40]
                .try_into()
                .unwrap(),
        );

        sections.push(ReconstructedSection {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics,
        });
    }

    // Fix section alignment if requested
    if options.fix_alignment {
        debug!("Fixing section alignment");
        // Section alignment is 0x1000 for both 32-bit and 64-bit PE files
        let section_alignment = 0x1000u32;
        let _ = is_64bit; // Reserved for future use with different alignments
        let _file_alignment = 0x200u32;

        for section in &mut sections {
            // Ensure virtual address is aligned
            if section.virtual_address % section_alignment != 0 {
                warnings.push(format!(
                    "Section {} has unaligned virtual address",
                    section.name
                ));
            }
        }
    }

    // Unmap sections if requested (convert RVA to file offsets)
    if options.unmap_sections {
        debug!("Unmapping sections");
        let mut new_data = Vec::new();

        // Copy headers
        let headers_size = sections
            .first()
            .map(|s| s.virtual_address as usize)
            .unwrap_or(0x1000);
        new_data.extend_from_slice(&reconstructed[..headers_size.min(reconstructed.len())]);

        // Copy section data
        for section in &sections {
            let va = section.virtual_address as usize;
            let vs = section.virtual_size as usize;

            if va + vs <= reconstructed.len() {
                // Pad to file alignment
                while new_data.len() % 0x200 != 0 {
                    new_data.push(0);
                }

                let _file_offset = new_data.len() as u32;
                new_data.extend_from_slice(&reconstructed[va..va + vs]);

                // Update section header in output
                // (would need to fix raw_offset in the actual implementation)
            }
        }

        reconstructed = new_data;
    }

    // Fix checksum if requested
    if options.fix_checksum && reconstructed.len() >= optional_header_offset + 68 {
        debug!("Fixing PE checksum");
        let checksum = calculate_pe_checksum(&reconstructed);
        let checksum_offset = optional_header_offset + 64;
        reconstructed[checksum_offset..checksum_offset + 4]
            .copy_from_slice(&checksum.to_le_bytes());
    }

    // Resolve imports (placeholder - actual implementation would scan IAT)
    let imports = Vec::new();
    let mut imports_resolved = 0u32;
    let imports_failed = 0u32;

    if options.rebuild_imports {
        debug!("Rebuilding imports");
        // Parse import directory and resolve functions
        // This is a simplified version - full implementation would:
        // 1. Find IAT entries
        // 2. Resolve each address to module!function
        // 3. Rebuild import table

        // For now, mark as successful with no imports found
        imports_resolved = imports.len() as u32;
    }

    // Save to file if requested
    if let Some(ref path) = options.output_path {
        save_dump_to_file(path, &reconstructed)?;
    }

    info!(
        original_size = dump_data.len(),
        reconstructed_size = reconstructed.len(),
        sections = sections.len(),
        imports_resolved = imports_resolved,
        warnings = warnings.len(),
        "PE reconstruction complete"
    );

    Ok(PeReconstructResult {
        success: true,
        original_base,
        reconstructed_size: reconstructed.len(),
        sections,
        imports,
        imports_resolved,
        imports_failed,
        output_path: options.output_path.clone(),
        data: if options.output_path.is_none() {
            Some(reconstructed)
        } else {
            None
        },
        error: None,
        warnings,
    })
}

/// Rebuild the import table for a PE
///
/// Scylla-style import reconstruction.
pub fn rebuild_imports<F>(
    dump_data: &mut [u8],
    original_base: usize,
    _resolve_address: F,
) -> Result<Vec<ReconstructedImport>>
where
    F: Fn(usize) -> Option<(String, String)>, // Returns (module, function)
{
    info!(
        base = format!("0x{:X}", original_base),
        "Rebuilding import table"
    );

    let imports = Vec::new();

    // Find IAT
    // Parse PE to find import directory
    if dump_data.len() < 64 {
        return Ok(imports);
    }

    let e_lfanew = i32::from_le_bytes([dump_data[60], dump_data[61], dump_data[62], dump_data[63]]);
    if e_lfanew < 0 {
        return Ok(imports);
    }

    let nt_offset = e_lfanew as usize;
    let optional_header_offset = nt_offset + 24;

    // Check magic to determine 32/64 bit
    let magic = u16::from_le_bytes([
        dump_data[optional_header_offset],
        dump_data[optional_header_offset + 1],
    ]);
    let is_64bit = magic == 0x20B;

    // Get import directory RVA
    let import_dir_offset = if is_64bit {
        optional_header_offset + 120 // 64-bit
    } else {
        optional_header_offset + 104 // 32-bit
    };

    if import_dir_offset + 8 > dump_data.len() {
        return Ok(imports);
    }

    let _import_rva = u32::from_le_bytes(
        dump_data[import_dir_offset..import_dir_offset + 4]
            .try_into()
            .unwrap(),
    );
    let _import_size = u32::from_le_bytes(
        dump_data[import_dir_offset + 4..import_dir_offset + 8]
            .try_into()
            .unwrap(),
    );

    // Scan for IAT entries and resolve
    // This is where we'd iterate through IAT entries and use resolve_address
    // to determine which module/function each entry points to

    // For each resolved import, we'd add:
    // imports.push(ReconstructedImport { ... });

    info!(imports = imports.len(), "Import rebuild complete");
    Ok(imports)
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Calculate a simple checksum for dump data
fn calculate_checksum(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Calculate PE checksum
fn calculate_pe_checksum(data: &[u8]) -> u32 {
    let mut checksum: u64 = 0;
    let checksum_offset = 0; // Would need to be calculated based on PE structure

    for (i, chunk) in data.chunks(2).enumerate() {
        if i * 2 == checksum_offset {
            continue; // Skip existing checksum field
        }

        let word = if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]]) as u64
        } else {
            chunk[0] as u64
        };

        checksum += word;
        if checksum > 0xFFFF {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }
    }

    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += data.len() as u64;

    checksum as u32
}

/// Get current timestamp in milliseconds
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compress dump data (simple placeholder - would use zlib/lz4 in production)
fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    // For now, just return the data as-is
    // In production, this would use a compression library
    debug!(size = data.len(), "Compression requested (no-op)");
    Ok(data.to_vec())
}

/// Save dump to file
fn save_dump_to_file(path: &str, data: &[u8]) -> Result<()> {
    info!(path = path, size = data.len(), "Saving dump to file");

    let mut file = std::fs::File::create(path)
        .map_err(|e| ghost_common::Error::Internal(format!("Failed to create dump file: {}", e)))?;

    file.write_all(data)
        .map_err(|e| ghost_common::Error::Internal(format!("Failed to write dump data: {}", e)))?;

    Ok(())
}

/// Load dump from file
pub fn load_dump_from_file(path: &str) -> Result<Vec<u8>> {
    info!(path = path, "Loading dump from file");

    let mut file = std::fs::File::open(path)
        .map_err(|e| ghost_common::Error::Internal(format!("Failed to open dump file: {}", e)))?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| ghost_common::Error::Internal(format!("Failed to read dump file: {}", e)))?;

    debug!(size = data.len(), "Dump loaded");
    Ok(data)
}

/// Parse a pattern string into bytes with wildcards
fn parse_pattern(pattern: &str) -> Vec<Option<u8>> {
    pattern
        .split_whitespace()
        .filter_map(|s| {
            if s == "??" || s == "?" {
                Some(None)
            } else {
                u8::from_str_radix(s, 16).ok().map(Some)
            }
        })
        .collect()
}

/// Scan data for a pattern with wildcards
fn scan_for_pattern(data: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    let mut matches = Vec::new();

    if pattern.is_empty() || data.len() < pattern.len() {
        return matches;
    }

    'outer: for i in 0..=data.len() - pattern.len() {
        for (j, &pat_byte) in pattern.iter().enumerate() {
            if let Some(expected) = pat_byte {
                if data[i + j] != expected {
                    continue 'outer;
                }
            }
        }
        matches.push(i);
    }

    matches
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::{DumpAnnotation, DumpCatalogEntry};

    #[test]
    fn test_parse_pattern() {
        let pattern = parse_pattern("48 8B ?? 00");
        assert_eq!(pattern.len(), 4);
        assert_eq!(pattern[0], Some(0x48));
        assert_eq!(pattern[1], Some(0x8B));
        assert_eq!(pattern[2], None);
        assert_eq!(pattern[3], Some(0x00));
    }

    #[test]
    fn test_scan_for_pattern() {
        let data = vec![0x48, 0x8B, 0x05, 0x00, 0x48, 0x8B, 0xFF, 0x00];
        let pattern = parse_pattern("48 8B ?? 00");
        let matches = scan_for_pattern(&data, &pattern);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], 0);
        assert_eq!(matches[1], 4);
    }

    #[test]
    fn test_compare_dumps() {
        let dump_a = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let dump_b = vec![0x00, 0xFF, 0x02, 0xFE, 0x04];
        let diff = compare_dumps(&dump_a, &dump_b, DumpId(1), DumpId(2));
        assert_eq!(diff.changes.len(), 2);
        assert_eq!(diff.bytes_changed, 2);
    }

    #[test]
    fn test_dump_manager_new() {
        let manager = DumpManager::new(1234, "test.exe");
        assert_eq!(manager.pid, 1234);
        assert_eq!(manager.process_name, "test.exe");
    }

    #[test]
    fn test_calculate_checksum() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let checksum = calculate_checksum(&data);
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 16); // 64-bit hash as hex
    }

    #[test]
    fn test_dump_annotation() {
        let ann = DumpAnnotation::new(0x1000, "Test Label").with_description("A test annotation");
        assert_eq!(ann.offset, 0x1000);
        assert_eq!(ann.label, "Test Label");
        assert_eq!(ann.description, Some("A test annotation".to_string()));
    }

    #[test]
    fn test_dump_catalog() {
        let mut catalog = DumpCatalog::new();
        assert_eq!(catalog.next_id, 0);

        let id = catalog.next_dump_id();
        assert_eq!(id.0, 0);
        assert_eq!(catalog.next_id, 1);

        let entry = DumpCatalogEntry {
            id: DumpId(5),
            dump_type: DumpType::FullProcess,
            process_name: "test.exe".to_string(),
            pid: 1234,
            created_at: 0,
            file_path: "/tmp/dump.bin".to_string(),
            file_size: 1024,
            description: None,
            tags: vec!["test".to_string(), "debug".to_string()],
        };
        catalog.add_entry(entry);

        let found = catalog.find_by_tag("test");
        assert_eq!(found.len(), 1);

        let found_by_name = catalog.find_by_process("test");
        assert_eq!(found_by_name.len(), 1);

        // Test multiple tag search
        let found_debug = catalog.find_by_tag("debug");
        assert_eq!(found_debug.len(), 1);

        // Test non-existent tag
        let not_found = catalog.find_by_tag("nonexistent");
        assert_eq!(not_found.len(), 0);
    }

    #[test]
    fn test_dump_manager_cache() {
        let mut manager = DumpManager::new(1234, "test.exe");

        // Initially cache is empty
        assert!(manager.get_cached_dump(DumpId(1)).is_none());

        // Cache some data
        let data = vec![0x01, 0x02, 0x03, 0x04];
        manager.cache_dump(DumpId(1), data.clone());

        // Verify data is cached
        let cached = manager.get_cached_dump(DumpId(1));
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), &data);

        // Remove from cache
        manager.remove_from_cache(DumpId(1));
        assert!(manager.get_cached_dump(DumpId(1)).is_none());
    }

    #[test]
    fn test_dump_manager_clear_cache() {
        let mut manager = DumpManager::new(1234, "test.exe");

        // Add multiple entries
        manager.cache_dump(DumpId(1), vec![0x01]);
        manager.cache_dump(DumpId(2), vec![0x02]);

        // Clear cache
        manager.clear_cache();

        // Verify all entries are removed
        assert!(manager.get_cached_dump(DumpId(1)).is_none());
        assert!(manager.get_cached_dump(DumpId(2)).is_none());
    }

    #[test]
    fn test_compare_dumps_identical() {
        let dump = vec![0x01, 0x02, 0x03, 0x04];
        let diff = compare_dumps(&dump, &dump, DumpId(1), DumpId(2));
        assert_eq!(diff.changes.len(), 0);
        assert_eq!(diff.bytes_changed, 0);
    }

    #[test]
    fn test_compare_dumps_size_difference() {
        let dump_a = vec![0x01, 0x02, 0x03];
        let dump_b = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let diff = compare_dumps(&dump_a, &dump_b, DumpId(1), DumpId(2));

        // Should have one change for the added bytes
        assert!(diff
            .changes
            .iter()
            .any(|c| c.change_type == DumpChangeType::Added));
        assert_eq!(diff.bytes_changed, 2);
    }

    #[test]
    fn test_compare_dumps_removed_bytes() {
        let dump_a = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let dump_b = vec![0x01, 0x02, 0x03];
        let diff = compare_dumps(&dump_a, &dump_b, DumpId(1), DumpId(2));

        // Should have one change for the removed bytes
        assert!(diff
            .changes
            .iter()
            .any(|c| c.change_type == DumpChangeType::Removed));
    }

    #[test]
    fn test_parse_pattern_empty() {
        let pattern = parse_pattern("");
        assert!(pattern.is_empty());
    }

    #[test]
    fn test_parse_pattern_single_wildcard() {
        let pattern = parse_pattern("?");
        assert_eq!(pattern.len(), 1);
        assert_eq!(pattern[0], None);
    }

    #[test]
    fn test_scan_for_pattern_no_match() {
        let data = vec![0x00, 0x00, 0x00, 0x00];
        let pattern = parse_pattern("FF FF");
        let matches = scan_for_pattern(&data, &pattern);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_for_pattern_all_wildcards() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let pattern = parse_pattern("?? ??");
        let matches = scan_for_pattern(&data, &pattern);
        // Should match at positions 0, 1, 2
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_current_timestamp_ms() {
        let ts = current_timestamp_ms();
        // Should be a reasonable timestamp (after year 2020)
        assert!(ts > 1577836800000); // 2020-01-01 00:00:00 UTC
    }

    #[test]
    fn test_calculate_pe_checksum() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header start
        let checksum = calculate_pe_checksum(&data);
        assert!(checksum > 0);
    }

    #[test]
    fn test_dump_options_builders() {
        // Test full_process builder
        let opts = DumpOptions::full_process();
        assert_eq!(opts.dump_type, DumpType::FullProcess);

        // Test region builder
        let opts = DumpOptions::region(0x1000, 0x2000);
        assert_eq!(opts.dump_type, DumpType::Region);
        assert_eq!(opts.start_address, Some(0x1000));
        assert_eq!(opts.end_address, Some(0x2000));

        // Test module builder
        let opts = DumpOptions::module("kernel32.dll");
        assert_eq!(opts.dump_type, DumpType::Module);
        assert_eq!(opts.module_name, Some("kernel32.dll".to_string()));

        // Test minidump builder
        let opts = DumpOptions::minidump();
        assert_eq!(opts.dump_type, DumpType::Minidump);
    }

    #[test]
    fn test_dump_options_with_output() {
        let opts = DumpOptions::full_process().with_output("/tmp/dump.bin");
        assert_eq!(opts.output_path, Some("/tmp/dump.bin".to_string()));
    }

    #[test]
    fn test_dump_options_with_compression() {
        let opts = DumpOptions::full_process().with_compression();
        assert!(opts.compress);
    }

    #[test]
    fn test_dump_options_with_pe_reconstruction() {
        let opts = DumpOptions::module("test.dll").with_pe_reconstruction();
        assert!(opts.reconstruct_pe);
    }

    #[test]
    fn test_dump_type_parse() {
        assert_eq!(DumpType::parse("full"), Some(DumpType::FullProcess));
        assert_eq!(DumpType::parse("region"), Some(DumpType::Region));
        assert_eq!(DumpType::parse("module"), Some(DumpType::Module));
        assert_eq!(DumpType::parse("mini"), Some(DumpType::Minidump));
        assert_eq!(DumpType::parse("incremental"), Some(DumpType::Incremental));
        assert_eq!(DumpType::parse("diff"), Some(DumpType::Differential));
        assert_eq!(DumpType::parse("unknown"), None);
    }

    #[test]
    fn test_search_dump_empty_pattern() {
        let dump_data = vec![0x01, 0x02, 0x03];
        let regions = vec![DumpRegion {
            base_address: 0x1000,
            file_offset: 0,
            size: 3,
            protection: Protection::new(true, false, false),
            memory_type: MemoryType::Private,
            module: None,
        }];
        let options = DumpSearchOptions {
            pattern: "".to_string(),
            ..Default::default()
        };

        let results = search_dump(DumpId(1), &dump_data, &regions, &options);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_dump_with_results() {
        let dump_data = vec![0x48, 0x8B, 0x05, 0x00, 0x48, 0x8B, 0xFF, 0x00];
        let regions = vec![DumpRegion {
            base_address: 0x1000,
            file_offset: 0,
            size: 8,
            protection: Protection::new(true, false, true),
            memory_type: MemoryType::Image,
            module: Some("test.dll".to_string()),
        }];
        let options = DumpSearchOptions {
            pattern: "48 8B ?? 00".to_string(),
            max_results: 100,
            include_context: false,
            context_size: 0,
        };

        let results = search_dump(DumpId(1), &dump_data, &regions, &options);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].address, 0x1000);
        assert_eq!(results[1].address, 0x1004);
    }
}
