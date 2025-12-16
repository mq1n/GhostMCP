//! What Writes/Accesses Core
//!
//! Provides address and instruction watching functionality to track what code
//! accesses specific memory addresses, and what addresses specific instructions access.

use ghost_common::{
    AccessedAddress, AddressWatchHit, AddressWatchInfo, CapturedRegisters, ClearWatchHitsRequest,
    ClearWatchHitsResult, CreateAddressWatchRequest, CreateAddressWatchResult,
    CreateInstructionWatchRequest, CreateInstructionWatchResult, DisassembledContext,
    GetAccessedAddressesRequest, GetAccessedAddressesResult, GetWatchHitsRequest,
    GetWatchHitsResult, InstructionWatchInfo, ListWatchesResult, QuickActionRequest,
    QuickActionResult, QuickActionType, WatchAccessType, WatchFilter, WatchId,
    WatchOperationResult, WatchState, WatchSummary,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace, warn};

/// Maximum number of hits to store per watch
const MAX_HITS_PER_WATCH: usize = 100_000;
/// Maximum number of unique addresses per instruction watch
const MAX_ADDRESSES_PER_WATCH: usize = 50_000;
/// Maximum watch size in bytes (hardware limitation)
const MAX_WATCH_SIZE: usize = 8;

static NEXT_WATCH_ID: AtomicU32 = AtomicU32::new(1);

/// Address watch internal state
struct AddressWatch {
    info: AddressWatchInfo,
    hits: Vec<AddressWatchHit>,
    #[allow(dead_code)]
    config: AddressWatchConfig,
}

#[derive(Clone)]
#[allow(dead_code)]
struct AddressWatchConfig {
    capture_registers: bool,
    capture_stack: bool,
    stack_capture_size: usize,
    auto_disassemble: bool,
    disasm_before: u32,
    disasm_after: u32,
}

/// Instruction watch internal state
struct InstructionWatch {
    info: InstructionWatchInfo,
    accessed: HashMap<u64, AccessedAddressInternal>,
}

struct AccessedAddressInternal {
    address: u64,
    access_type: WatchAccessType,
    count: AtomicU64,
    first_access: u64,
    last_access: AtomicU64,
    sample_value: Vec<u8>,
    module_name: Option<String>,
}

/// Watch Manager for tracking memory accesses
pub struct WatchManager {
    address_watches: HashMap<WatchId, AddressWatch>,
    instruction_watches: HashMap<WatchId, InstructionWatch>,
    #[allow(dead_code)]
    is_64bit: bool,
}

impl WatchManager {
    pub fn new(is_64bit: bool) -> Self {
        info!("Creating WatchManager (64-bit: {})", is_64bit);
        Self {
            address_watches: HashMap::new(),
            instruction_watches: HashMap::new(),
            is_64bit,
        }
    }

    fn next_watch_id() -> WatchId {
        WatchId(NEXT_WATCH_ID.fetch_add(1, Ordering::SeqCst))
    }

    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    // ========================================================================
    // Address Watch
    // ========================================================================

    /// Create an address watch to monitor read/write accesses
    pub fn create_address_watch(
        &mut self,
        request: CreateAddressWatchRequest,
    ) -> CreateAddressWatchResult {
        info!(address = %format!("{:#x}", request.address), size = request.size, access_type = ?request.access_type, "Creating address watch");

        // Validate watch size (hardware breakpoints support 1, 2, 4, 8 bytes)
        if request.size == 0 {
            warn!("Address watch creation failed: zero size");
            return CreateAddressWatchResult {
                success: false,
                watch_id: None,
                watch_info: None,
                error: Some("Watch size cannot be zero".into()),
            };
        }
        if request.size > MAX_WATCH_SIZE {
            warn!(
                size = request.size,
                max = MAX_WATCH_SIZE,
                "Address watch creation failed: size too large"
            );
            return CreateAddressWatchResult {
                success: false,
                watch_id: None,
                watch_info: None,
                error: Some(format!(
                    "Watch size too large: {} (max {})",
                    request.size, MAX_WATCH_SIZE
                )),
            };
        }
        if !matches!(request.size, 1 | 2 | 4 | 8) {
            warn!(
                size = request.size,
                "Address watch creation failed: invalid size"
            );
            return CreateAddressWatchResult {
                success: false,
                watch_id: None,
                watch_info: None,
                error: Some("Watch size must be 1, 2, 4, or 8 bytes".into()),
            };
        }

        // Validate address alignment
        if request.address % (request.size as u64) != 0 {
            debug!(address = %format!("{:#x}", request.address), size = request.size, "Address not aligned to watch size");
            // Just a warning - hardware may still work
        }

        let id = Self::next_watch_id();
        let now = Self::timestamp();

        let info = AddressWatchInfo {
            id,
            address: request.address,
            size: request.size,
            access_type: request.access_type,
            state: WatchState::Active,
            hit_count: 0,
            max_hits: request.max_hits,
            capture_registers: request.capture_registers,
            capture_stack: request.capture_stack,
            auto_disassemble: request.auto_disassemble,
            name: request.name.clone(),
            created_at: now,
        };

        let config = AddressWatchConfig {
            capture_registers: request.capture_registers,
            capture_stack: request.capture_stack,
            stack_capture_size: request.stack_capture_size,
            auto_disassemble: request.auto_disassemble,
            disasm_before: request.disasm_before,
            disasm_after: request.disasm_after,
        };

        let watch = AddressWatch {
            info: info.clone(),
            hits: Vec::new(),
            config,
        };

        self.address_watches.insert(id, watch);
        info!(watch_id = %id, address = %format!("{:#x}", request.address), "Address watch created successfully");

        CreateAddressWatchResult {
            success: true,
            watch_id: Some(id),
            watch_info: Some(info),
            error: None,
        }
    }

    /// Record a hit on an address watch (called from hardware breakpoint handler)
    ///
    /// # Arguments
    /// * `watch_id` - The watch to record a hit for
    /// * `thread_id` - Thread that caused the access
    /// * `instruction_address` - RIP at time of access
    /// * `access_type` - Type of access (read/write)
    /// * `value_before` - Value at address before write (or current for read)
    /// * `value_after` - Value written (for writes)
    /// * `registers` - CPU registers at time of hit
    /// * `stack_snapshot` - Stack memory snapshot
    /// * `stack_base` - RSP value
    /// * `disassembly` - Disassembled instructions around hit
    /// * `module_name` - Module containing the instruction
    /// * `function_name` - Function name if available
    /// * `function_offset` - Offset from function start
    ///
    /// # Returns
    /// `true` if hit was recorded, `false` if watch not found/inactive/full
    #[allow(clippy::too_many_arguments)]
    pub fn record_address_hit(
        &mut self,
        watch_id: WatchId,
        thread_id: u32,
        instruction_address: u64,
        access_type: WatchAccessType,
        value_before: Vec<u8>,
        value_after: Option<Vec<u8>>,
        registers: Option<CapturedRegisters>,
        stack_snapshot: Option<Vec<u8>>,
        stack_base: Option<u64>,
        disassembly: Option<Vec<DisassembledContext>>,
        module_name: Option<String>,
        function_name: Option<String>,
        function_offset: Option<u64>,
    ) -> bool {
        let watch = match self.address_watches.get_mut(&watch_id) {
            Some(w) => w,
            None => {
                warn!(watch_id = %watch_id, "Address watch not found for hit recording");
                return false;
            }
        };

        if watch.info.state != WatchState::Active {
            trace!(watch_id = %watch_id, state = ?watch.info.state, "Ignoring hit on inactive watch");
            return false;
        }

        // Check max hits limit
        if watch.info.max_hits > 0 && watch.info.hit_count >= watch.info.max_hits as u64 {
            trace!(watch_id = %watch_id, hits = watch.info.hit_count, max = watch.info.max_hits, "Watch reached max hits");
            return false;
        }

        // Safety limit to prevent memory exhaustion
        if watch.hits.len() >= MAX_HITS_PER_WATCH {
            warn!(watch_id = %watch_id, "Watch hit storage limit reached, discarding oldest hits");
            // Remove oldest 10% of hits
            let remove_count = MAX_HITS_PER_WATCH / 10;
            watch.hits.drain(0..remove_count);
        }

        watch.info.hit_count += 1;
        let hit_number = watch.info.hit_count;

        let hit = AddressWatchHit {
            hit_number,
            timestamp: Self::timestamp(),
            thread_id,
            instruction_address,
            access_type,
            value_before,
            value_after,
            registers,
            stack_snapshot,
            stack_base,
            disassembly,
            module_name,
            function_name,
            function_offset,
        };

        watch.hits.push(hit);
        debug!(watch_id = %watch_id, hit = hit_number, instruction = %format!("{:#x}", instruction_address), thread = thread_id, "Recorded address watch hit");
        true
    }

    /// Get hits from an address watch
    pub fn get_address_watch_hits(&self, request: GetWatchHitsRequest) -> GetWatchHitsResult {
        let watch = match self.address_watches.get(&request.watch_id) {
            Some(w) => w,
            None => {
                return GetWatchHitsResult {
                    success: false,
                    watch_id: request.watch_id,
                    total_hits: 0,
                    hits: vec![],
                    error: Some(format!("Watch {} not found", request.watch_id)),
                };
            }
        };

        let hits: Vec<_> = watch
            .hits
            .iter()
            .filter(|h| {
                if let Some(tid) = request.thread_filter {
                    if h.thread_id != tid {
                        return false;
                    }
                }
                if let Some(at) = &request.access_type_filter {
                    if h.access_type != *at {
                        return false;
                    }
                }
                true
            })
            .skip(request.start.saturating_sub(1) as usize)
            .take(request.count as usize)
            .cloned()
            .collect();

        GetWatchHitsResult {
            success: true,
            watch_id: request.watch_id,
            total_hits: watch.info.hit_count,
            hits,
            error: None,
        }
    }

    /// Get address watch info
    pub fn get_address_watch(&self, watch_id: WatchId) -> Option<&AddressWatchInfo> {
        self.address_watches.get(&watch_id).map(|w| &w.info)
    }

    // ========================================================================
    // Instruction Watch
    // ========================================================================

    /// Create an instruction watch to monitor what addresses an instruction accesses
    pub fn create_instruction_watch(
        &mut self,
        request: CreateInstructionWatchRequest,
    ) -> CreateInstructionWatchResult {
        info!(address = %format!("{:#x}", request.instruction_address), track_reads = request.track_reads, track_writes = request.track_writes, "Creating instruction watch");

        // Validate at least one access type is tracked
        if !request.track_reads && !request.track_writes {
            warn!("Instruction watch creation failed: no access types selected");
            return CreateInstructionWatchResult {
                success: false,
                watch_id: None,
                watch_info: None,
                error: Some("Must track at least reads or writes".into()),
            };
        }

        let id = Self::next_watch_id();
        let now = Self::timestamp();

        let info = InstructionWatchInfo {
            id,
            instruction_address: request.instruction_address,
            disassembly: String::new(), // Will be filled by caller with disasm
            track_reads: request.track_reads,
            track_writes: request.track_writes,
            state: WatchState::Active,
            execution_count: 0,
            unique_addresses: 0,
            name: request.name.clone(),
            module_name: None,
            function_name: None,
            created_at: now,
        };

        let watch = InstructionWatch {
            info: info.clone(),
            accessed: HashMap::new(),
        };

        self.instruction_watches.insert(id, watch);
        info!(watch_id = %id, address = %format!("{:#x}", request.instruction_address), "Instruction watch created successfully");

        CreateInstructionWatchResult {
            success: true,
            watch_id: Some(id),
            watch_info: Some(info),
            error: None,
        }
    }

    /// Record an access from an instruction watch
    ///
    /// # Arguments
    /// * `watch_id` - The instruction watch
    /// * `accessed_address` - Address that was accessed
    /// * `access_type` - Type of access
    /// * `sample_value` - Value at the accessed address
    /// * `module_name` - Module containing the address
    ///
    /// # Returns
    /// `true` if recorded, `false` if watch not found/inactive/filtered
    pub fn record_instruction_access(
        &mut self,
        watch_id: WatchId,
        accessed_address: u64,
        access_type: WatchAccessType,
        sample_value: Vec<u8>,
        module_name: Option<String>,
    ) -> bool {
        let watch = match self.instruction_watches.get_mut(&watch_id) {
            Some(w) => w,
            None => {
                trace!(watch_id = %watch_id, "Instruction watch not found");
                return false;
            }
        };

        if watch.info.state != WatchState::Active {
            trace!(watch_id = %watch_id, "Instruction watch not active");
            return false;
        }

        // Filter by tracked access types
        match access_type {
            WatchAccessType::Read if !watch.info.track_reads => return false,
            WatchAccessType::Write if !watch.info.track_writes => return false,
            _ => {}
        }

        // Safety limit for unique addresses
        if watch.accessed.len() >= MAX_ADDRESSES_PER_WATCH
            && !watch.accessed.contains_key(&accessed_address)
        {
            // At limit and this is a new address - skip it
            trace!(watch_id = %watch_id, "Address limit reached, skipping new address");
            return false;
        }

        watch.info.execution_count += 1;
        let now = Self::timestamp();

        if let Some(existing) = watch.accessed.get_mut(&accessed_address) {
            existing.count.fetch_add(1, Ordering::Relaxed);
            existing.last_access.store(now, Ordering::Relaxed);
            // Only update sample value if not too large
            if sample_value.len() <= 64 {
                existing.sample_value = sample_value;
            }
        } else {
            watch.accessed.insert(
                accessed_address,
                AccessedAddressInternal {
                    address: accessed_address,
                    access_type,
                    count: AtomicU64::new(1),
                    first_access: now,
                    last_access: AtomicU64::new(now),
                    sample_value: if sample_value.len() <= 64 {
                        sample_value
                    } else {
                        sample_value[..64].to_vec()
                    },
                    module_name,
                },
            );
            watch.info.unique_addresses += 1;
        }

        true
    }

    /// Get accessed addresses from an instruction watch
    pub fn get_accessed_addresses(
        &self,
        request: GetAccessedAddressesRequest,
    ) -> GetAccessedAddressesResult {
        let watch = match self.instruction_watches.get(&request.watch_id) {
            Some(w) => w,
            None => {
                return GetAccessedAddressesResult {
                    success: false,
                    watch_id: request.watch_id,
                    total_executions: 0,
                    addresses: vec![],
                    error: Some(format!("Watch {} not found", request.watch_id)),
                };
            }
        };

        let mut addresses: Vec<AccessedAddress> = watch
            .accessed
            .values()
            .filter(|a| {
                if let Some(at) = &request.access_type_filter {
                    if a.access_type != *at {
                        return false;
                    }
                }
                if let Some(min) = request.min_count {
                    if a.count.load(Ordering::Relaxed) < min {
                        return false;
                    }
                }
                true
            })
            .map(|a| AccessedAddress {
                address: a.address,
                access_type: a.access_type,
                access_count: a.count.load(Ordering::Relaxed),
                first_access: a.first_access,
                last_access: a.last_access.load(Ordering::Relaxed),
                sample_value: a.sample_value.clone(),
                module_name: a.module_name.clone(),
            })
            .collect();

        if request.sort_by_count {
            addresses.sort_by(|a, b| b.access_count.cmp(&a.access_count));
        }

        addresses.truncate(request.max_results as usize);

        GetAccessedAddressesResult {
            success: true,
            watch_id: request.watch_id,
            total_executions: watch.info.execution_count,
            addresses,
            error: None,
        }
    }

    /// Get instruction watch info
    pub fn get_instruction_watch(&self, watch_id: WatchId) -> Option<&InstructionWatchInfo> {
        self.instruction_watches.get(&watch_id).map(|w| &w.info)
    }

    // ========================================================================
    // Watch Management
    // ========================================================================

    /// Pause a watch
    pub fn pause_watch(&mut self, watch_id: WatchId) -> WatchOperationResult {
        if let Some(w) = self.address_watches.get_mut(&watch_id) {
            w.info.state = WatchState::Paused;
            return WatchOperationResult {
                success: true,
                watch_id,
                new_state: Some(WatchState::Paused),
                error: None,
            };
        }
        if let Some(w) = self.instruction_watches.get_mut(&watch_id) {
            w.info.state = WatchState::Paused;
            return WatchOperationResult {
                success: true,
                watch_id,
                new_state: Some(WatchState::Paused),
                error: None,
            };
        }
        WatchOperationResult {
            success: false,
            watch_id,
            new_state: None,
            error: Some("Watch not found".into()),
        }
    }

    /// Resume a watch
    pub fn resume_watch(&mut self, watch_id: WatchId) -> WatchOperationResult {
        if let Some(w) = self.address_watches.get_mut(&watch_id) {
            w.info.state = WatchState::Active;
            return WatchOperationResult {
                success: true,
                watch_id,
                new_state: Some(WatchState::Active),
                error: None,
            };
        }
        if let Some(w) = self.instruction_watches.get_mut(&watch_id) {
            w.info.state = WatchState::Active;
            return WatchOperationResult {
                success: true,
                watch_id,
                new_state: Some(WatchState::Active),
                error: None,
            };
        }
        WatchOperationResult {
            success: false,
            watch_id,
            new_state: None,
            error: Some("Watch not found".into()),
        }
    }

    /// Remove a watch
    pub fn remove_watch(&mut self, watch_id: WatchId) -> WatchOperationResult {
        if self.address_watches.remove(&watch_id).is_some() {
            info!("Removed address watch {}", watch_id);
            return WatchOperationResult {
                success: true,
                watch_id,
                new_state: Some(WatchState::Removed),
                error: None,
            };
        }
        if self.instruction_watches.remove(&watch_id).is_some() {
            info!("Removed instruction watch {}", watch_id);
            return WatchOperationResult {
                success: true,
                watch_id,
                new_state: Some(WatchState::Removed),
                error: None,
            };
        }
        WatchOperationResult {
            success: false,
            watch_id,
            new_state: None,
            error: Some("Watch not found".into()),
        }
    }

    /// Clear hits from a watch
    pub fn clear_hits(&mut self, request: ClearWatchHitsRequest) -> ClearWatchHitsResult {
        if let Some(w) = self.address_watches.get_mut(&request.watch_id) {
            let before = w.hits.len();
            if let Some(ts) = request.older_than {
                w.hits.retain(|h| h.timestamp >= ts);
            } else {
                w.hits.clear();
            }
            let cleared = before - w.hits.len();
            w.info.hit_count = w.hits.len() as u64;
            return ClearWatchHitsResult {
                success: true,
                watch_id: request.watch_id,
                hits_cleared: cleared as u64,
                error: None,
            };
        }
        if let Some(w) = self.instruction_watches.get_mut(&request.watch_id) {
            let cleared = w.accessed.len();
            w.accessed.clear();
            w.info.unique_addresses = 0;
            w.info.execution_count = 0;
            return ClearWatchHitsResult {
                success: true,
                watch_id: request.watch_id,
                hits_cleared: cleared as u64,
                error: None,
            };
        }
        ClearWatchHitsResult {
            success: false,
            watch_id: request.watch_id,
            hits_cleared: 0,
            error: Some("Watch not found".into()),
        }
    }

    /// List all watches
    pub fn list_watches(&self, filter: Option<WatchFilter>) -> ListWatchesResult {
        let filter = filter.unwrap_or_default();

        let address_watches: Vec<_> = self
            .address_watches
            .values()
            .filter(|w| {
                if let Some(state) = &filter.state {
                    if w.info.state != *state {
                        return false;
                    }
                }
                if let Some(at) = &filter.access_type {
                    if w.info.access_type != *at {
                        return false;
                    }
                }
                if let Some((lo, hi)) = &filter.address_range {
                    if w.info.address < *lo || w.info.address > *hi {
                        return false;
                    }
                }
                true
            })
            .map(|w| w.info.clone())
            .collect();

        let instruction_watches: Vec<_> = self
            .instruction_watches
            .values()
            .filter(|w| {
                if let Some(state) = &filter.state {
                    if w.info.state != *state {
                        return false;
                    }
                }
                if let Some((lo, hi)) = &filter.address_range {
                    if w.info.instruction_address < *lo || w.info.instruction_address > *hi {
                        return false;
                    }
                }
                true
            })
            .map(|w| w.info.clone())
            .collect();

        let active = address_watches
            .iter()
            .filter(|w| w.state == WatchState::Active)
            .count()
            + instruction_watches
                .iter()
                .filter(|w| w.state == WatchState::Active)
                .count();
        let paused = address_watches
            .iter()
            .filter(|w| w.state == WatchState::Paused)
            .count()
            + instruction_watches
                .iter()
                .filter(|w| w.state == WatchState::Paused)
                .count();
        let total_hits: u64 = address_watches.iter().map(|w| w.hit_count).sum();

        ListWatchesResult {
            success: true,
            address_watches,
            instruction_watches,
            summary: WatchSummary {
                address_watch_count: self.address_watches.len() as u32,
                instruction_watch_count: self.instruction_watches.len() as u32,
                active_count: active as u32,
                paused_count: paused as u32,
                total_hits,
            },
            error: None,
        }
    }

    // ========================================================================
    // Quick Actions
    // ========================================================================

    /// Perform a quick action based on a watch hit
    pub fn quick_action(&self, request: QuickActionRequest) -> QuickActionResult {
        match request.action_type {
            QuickActionType::CopyAobSignature => self.quick_action_copy_aob(&request),
            QuickActionType::AddToAddressList => QuickActionResult {
                success: true,
                action_type: request.action_type,
                result_data: Some("Address would be added to list".into()),
                created_id: None,
                aob_signature: None,
                error: None,
            },
            QuickActionType::CreateHook => QuickActionResult {
                success: true,
                action_type: request.action_type,
                result_data: Some("Hook creation pending".into()),
                created_id: None,
                aob_signature: None,
                error: None,
            },
            QuickActionType::SetBreakpoint => QuickActionResult {
                success: true,
                action_type: request.action_type,
                result_data: Some("Breakpoint creation pending".into()),
                created_id: None,
                aob_signature: None,
                error: None,
            },
            QuickActionType::DisassembleFunction | QuickActionType::FindXrefs => {
                QuickActionResult {
                    success: true,
                    action_type: request.action_type,
                    result_data: Some("Operation pending".into()),
                    created_id: None,
                    aob_signature: None,
                    error: None,
                }
            }
        }
    }

    fn quick_action_copy_aob(&self, request: &QuickActionRequest) -> QuickActionResult {
        // Get the instruction address from the hit
        let instr_addr = if let Some(hit_num) = request.hit_number {
            if let Some(w) = self.address_watches.get(&request.watch_id) {
                w.hits
                    .get(hit_num.saturating_sub(1) as usize)
                    .map(|h| h.instruction_address)
            } else {
                None
            }
        } else {
            request.target_address
        };

        let addr = match instr_addr {
            Some(a) => a,
            None => {
                return QuickActionResult {
                    success: false,
                    action_type: request.action_type.clone(),
                    result_data: None,
                    created_id: None,
                    aob_signature: None,
                    error: Some("Could not determine instruction address".into()),
                }
            }
        };

        // Generate placeholder AOB signature
        let _bytes_before = request.options.sig_bytes_before.unwrap_or(8);
        let _bytes_after = request.options.sig_bytes_after.unwrap_or(8);

        QuickActionResult {
            success: true,
            action_type: request.action_type.clone(),
            result_data: Some(format!("AOB signature for {:#x}", addr)),
            created_id: None,
            aob_signature: Some(format!("?? ?? ?? ?? ?? ?? ?? ?? @ {:#x}", addr)),
            error: None,
        }
    }
}

// ============================================================================
// Hardware Breakpoint Integration
// ============================================================================

/// Hardware breakpoint type for watch implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBreakpointType {
    Execute,
    Write,
    ReadWrite,
}

/// Hardware breakpoint size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBreakpointSize {
    Byte,
    Word,
    Dword,
    Qword,
}

impl HwBreakpointSize {
    pub fn from_size(size: usize) -> Option<Self> {
        match size {
            1 => Some(Self::Byte),
            2 => Some(Self::Word),
            4 => Some(Self::Dword),
            8 => Some(Self::Qword),
            _ => None,
        }
    }

    pub fn to_dr7_len(&self) -> u64 {
        match self {
            Self::Byte => 0b00,
            Self::Word => 0b01,
            Self::Dword => 0b11,
            Self::Qword => 0b10,
        }
    }
}

impl HwBreakpointType {
    pub fn to_dr7_rw(&self) -> u64 {
        match self {
            Self::Execute => 0b00,
            Self::Write => 0b01,
            Self::ReadWrite => 0b11,
        }
    }
}

/// Convert watch access type to hardware breakpoint type
pub fn access_type_to_hw_bp(access_type: WatchAccessType) -> HwBreakpointType {
    match access_type {
        WatchAccessType::Read => HwBreakpointType::ReadWrite, // x86 doesn't support read-only
        WatchAccessType::Write => HwBreakpointType::Write,
        WatchAccessType::ReadWrite => HwBreakpointType::ReadWrite,
        WatchAccessType::Execute => HwBreakpointType::Execute,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::QuickActionOptions;

    fn default_address_watch_request(address: u64, size: usize) -> CreateAddressWatchRequest {
        CreateAddressWatchRequest {
            address,
            size,
            access_type: WatchAccessType::Write,
            max_hits: 100,
            capture_registers: false,
            capture_stack: false,
            stack_capture_size: 0,
            auto_disassemble: false,
            disasm_before: 0,
            disasm_after: 0,
            name: None,
        }
    }

    #[test]
    fn test_create_address_watch() {
        let mut mgr = WatchManager::new(true);
        let req = CreateAddressWatchRequest {
            address: 0x1000,
            size: 4,
            access_type: WatchAccessType::Write,
            max_hits: 100,
            capture_registers: true,
            capture_stack: false,
            stack_capture_size: 0,
            auto_disassemble: true,
            disasm_before: 5,
            disasm_after: 5,
            name: Some("test".into()),
        };
        let res = mgr.create_address_watch(req);
        assert!(res.success);
        assert!(res.watch_id.is_some());
        assert!(res.watch_info.is_some());
        let info = res.watch_info.unwrap();
        assert_eq!(info.address, 0x1000);
        assert_eq!(info.size, 4);
        assert_eq!(info.state, WatchState::Active);
    }

    #[test]
    fn test_create_address_watch_invalid_size() {
        let mut mgr = WatchManager::new(true);

        // Zero size
        let req = default_address_watch_request(0x1000, 0);
        let res = mgr.create_address_watch(req);
        assert!(!res.success);
        assert!(res.error.unwrap().contains("zero"));

        // Invalid size (not 1, 2, 4, or 8)
        let req = default_address_watch_request(0x1000, 3);
        let res = mgr.create_address_watch(req);
        assert!(!res.success);
        assert!(res.error.unwrap().contains("1, 2, 4, or 8"));

        // Too large
        let req = default_address_watch_request(0x1000, 16);
        let res = mgr.create_address_watch(req);
        assert!(!res.success);
    }

    #[test]
    fn test_create_instruction_watch() {
        let mut mgr = WatchManager::new(true);
        let req = CreateInstructionWatchRequest {
            instruction_address: 0x401000,
            track_reads: true,
            track_writes: true,
            max_addresses: 1000,
            name: Some("test_instr".into()),
        };
        let res = mgr.create_instruction_watch(req);
        assert!(res.success);
        assert!(res.watch_info.is_some());
    }

    #[test]
    fn test_create_instruction_watch_no_tracking() {
        let mut mgr = WatchManager::new(true);
        let req = CreateInstructionWatchRequest {
            instruction_address: 0x401000,
            track_reads: false,
            track_writes: false,
            max_addresses: 1000,
            name: None,
        };
        let res = mgr.create_instruction_watch(req);
        assert!(!res.success);
        assert!(res.error.unwrap().contains("at least"));
    }

    #[test]
    fn test_record_address_hit() {
        let mut mgr = WatchManager::new(true);
        let req = default_address_watch_request(0x1000, 4);
        let res = mgr.create_address_watch(req);
        let id = res.watch_id.unwrap();

        let recorded = mgr.record_address_hit(
            id,
            1234,
            0x401000,
            WatchAccessType::Write,
            vec![0, 0, 0, 0],
            Some(vec![1, 0, 0, 0]),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(recorded);

        let info = mgr.get_address_watch(id).unwrap();
        assert_eq!(info.hit_count, 1);
    }

    #[test]
    fn test_record_hit_max_hits() {
        let mut mgr = WatchManager::new(true);
        let mut req = default_address_watch_request(0x1000, 4);
        req.max_hits = 2;
        let res = mgr.create_address_watch(req);
        let id = res.watch_id.unwrap();

        // First two should succeed
        assert!(mgr.record_address_hit(
            id,
            1,
            0x401000,
            WatchAccessType::Write,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        ));
        assert!(mgr.record_address_hit(
            id,
            1,
            0x401000,
            WatchAccessType::Write,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        ));
        // Third should fail (max reached)
        assert!(!mgr.record_address_hit(
            id,
            1,
            0x401000,
            WatchAccessType::Write,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        ));
    }

    #[test]
    fn test_get_watch_hits() {
        let mut mgr = WatchManager::new(true);
        let req = default_address_watch_request(0x1000, 4);
        let res = mgr.create_address_watch(req);
        let id = res.watch_id.unwrap();

        // Record some hits
        for i in 0..5 {
            mgr.record_address_hit(
                id,
                i,
                0x401000 + i as u64,
                WatchAccessType::Write,
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );
        }

        let hits = mgr.get_address_watch_hits(GetWatchHitsRequest {
            watch_id: id,
            start: 1,
            count: 3,
            thread_filter: None,
            access_type_filter: None,
        });
        assert!(hits.success);
        assert_eq!(hits.total_hits, 5);
        assert_eq!(hits.hits.len(), 3);
    }

    #[test]
    fn test_record_instruction_access() {
        let mut mgr = WatchManager::new(true);
        let req = CreateInstructionWatchRequest {
            instruction_address: 0x401000,
            track_reads: true,
            track_writes: true,
            max_addresses: 1000,
            name: None,
        };
        let res = mgr.create_instruction_watch(req);
        let id = res.watch_id.unwrap();

        // Record accesses
        assert!(mgr.record_instruction_access(
            id,
            0x7FFE0000,
            WatchAccessType::Read,
            vec![1, 2, 3, 4],
            None
        ));
        assert!(mgr.record_instruction_access(
            id,
            0x7FFE0000,
            WatchAccessType::Read,
            vec![5, 6, 7, 8],
            None
        )); // Same address
        assert!(mgr.record_instruction_access(
            id,
            0x7FFE0100,
            WatchAccessType::Write,
            vec![9],
            None
        )); // Different address

        let info = mgr.get_instruction_watch(id).unwrap();
        assert_eq!(info.execution_count, 3);
        assert_eq!(info.unique_addresses, 2);
    }

    #[test]
    fn test_get_accessed_addresses() {
        let mut mgr = WatchManager::new(true);
        let req = CreateInstructionWatchRequest {
            instruction_address: 0x401000,
            track_reads: true,
            track_writes: true,
            max_addresses: 1000,
            name: None,
        };
        let res = mgr.create_instruction_watch(req);
        let id = res.watch_id.unwrap();

        // Record multiple accesses
        for _ in 0..10 {
            mgr.record_instruction_access(id, 0x7FFE0000, WatchAccessType::Read, vec![], None);
        }
        for _ in 0..5 {
            mgr.record_instruction_access(id, 0x7FFE0100, WatchAccessType::Write, vec![], None);
        }

        let result = mgr.get_accessed_addresses(GetAccessedAddressesRequest {
            watch_id: id,
            access_type_filter: None,
            min_count: None,
            sort_by_count: true,
            max_results: 100,
        });
        assert!(result.success);
        assert_eq!(result.addresses.len(), 2);
        // Should be sorted by count (10 > 5)
        assert_eq!(result.addresses[0].access_count, 10);
        assert_eq!(result.addresses[1].access_count, 5);
    }

    #[test]
    fn test_watch_pause_resume() {
        let mut mgr = WatchManager::new(true);
        let req = default_address_watch_request(0x1000, 4);
        let res = mgr.create_address_watch(req);
        let id = res.watch_id.unwrap();

        let pause_res = mgr.pause_watch(id);
        assert!(pause_res.success);
        assert_eq!(pause_res.new_state, Some(WatchState::Paused));

        // Hits should be ignored when paused
        assert!(!mgr.record_address_hit(
            id,
            1,
            0x401000,
            WatchAccessType::Write,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        ));

        let resume_res = mgr.resume_watch(id);
        assert!(resume_res.success);
        assert_eq!(resume_res.new_state, Some(WatchState::Active));

        // Hits should work again
        assert!(mgr.record_address_hit(
            id,
            1,
            0x401000,
            WatchAccessType::Write,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        ));
    }

    #[test]
    fn test_remove_watch() {
        let mut mgr = WatchManager::new(true);
        let req = default_address_watch_request(0x1000, 4);
        let res = mgr.create_address_watch(req);
        let id = res.watch_id.unwrap();

        let remove_res = mgr.remove_watch(id);
        assert!(remove_res.success);
        assert_eq!(remove_res.new_state, Some(WatchState::Removed));

        // Should be gone
        assert!(mgr.get_address_watch(id).is_none());

        // Remove again should fail
        let remove_res2 = mgr.remove_watch(id);
        assert!(!remove_res2.success);
    }

    #[test]
    fn test_clear_hits() {
        let mut mgr = WatchManager::new(true);
        let req = default_address_watch_request(0x1000, 4);
        let res = mgr.create_address_watch(req);
        let id = res.watch_id.unwrap();

        // Record some hits
        for _ in 0..5 {
            mgr.record_address_hit(
                id,
                1,
                0x401000,
                WatchAccessType::Write,
                vec![],
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );
        }

        let clear_res = mgr.clear_hits(ClearWatchHitsRequest {
            watch_id: id,
            older_than: None,
        });
        assert!(clear_res.success);
        assert_eq!(clear_res.hits_cleared, 5);

        let info = mgr.get_address_watch(id).unwrap();
        assert_eq!(info.hit_count, 0);
    }

    #[test]
    fn test_list_watches() {
        let mut mgr = WatchManager::new(true);

        // Create some watches
        mgr.create_address_watch(default_address_watch_request(0x1000, 4));
        mgr.create_address_watch(default_address_watch_request(0x2000, 8));
        mgr.create_instruction_watch(CreateInstructionWatchRequest {
            instruction_address: 0x401000,
            track_reads: true,
            track_writes: true,
            max_addresses: 100,
            name: None,
        });

        let list = mgr.list_watches(None);
        assert!(list.success);
        assert_eq!(list.address_watches.len(), 2);
        assert_eq!(list.instruction_watches.len(), 1);
        assert_eq!(list.summary.address_watch_count, 2);
        assert_eq!(list.summary.instruction_watch_count, 1);
        assert_eq!(list.summary.active_count, 3);
    }

    #[test]
    fn test_quick_action() {
        let mut mgr = WatchManager::new(true);
        let req = default_address_watch_request(0x1000, 4);
        let res = mgr.create_address_watch(req);
        let id = res.watch_id.unwrap();

        // Record a hit
        mgr.record_address_hit(
            id,
            1,
            0x401000,
            WatchAccessType::Write,
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        let action_res = mgr.quick_action(QuickActionRequest {
            action_type: QuickActionType::CopyAobSignature,
            watch_id: id,
            hit_number: Some(1),
            target_address: None,
            options: QuickActionOptions::default(),
        });
        assert!(action_res.success);
        assert!(action_res.aob_signature.is_some());
    }

    #[test]
    fn test_hw_breakpoint_type_conversion() {
        assert_eq!(
            access_type_to_hw_bp(WatchAccessType::Write),
            HwBreakpointType::Write
        );
        assert_eq!(
            access_type_to_hw_bp(WatchAccessType::Execute),
            HwBreakpointType::Execute
        );
        assert_eq!(
            access_type_to_hw_bp(WatchAccessType::Read),
            HwBreakpointType::ReadWrite
        );
        assert_eq!(
            access_type_to_hw_bp(WatchAccessType::ReadWrite),
            HwBreakpointType::ReadWrite
        );
    }

    #[test]
    fn test_hw_breakpoint_size() {
        assert_eq!(HwBreakpointSize::from_size(1), Some(HwBreakpointSize::Byte));
        assert_eq!(HwBreakpointSize::from_size(2), Some(HwBreakpointSize::Word));
        assert_eq!(
            HwBreakpointSize::from_size(4),
            Some(HwBreakpointSize::Dword)
        );
        assert_eq!(
            HwBreakpointSize::from_size(8),
            Some(HwBreakpointSize::Qword)
        );
        assert_eq!(HwBreakpointSize::from_size(3), None);
        assert_eq!(HwBreakpointSize::from_size(16), None);
    }

    #[test]
    fn test_dr7_values() {
        assert_eq!(HwBreakpointSize::Byte.to_dr7_len(), 0b00);
        assert_eq!(HwBreakpointSize::Word.to_dr7_len(), 0b01);
        assert_eq!(HwBreakpointSize::Dword.to_dr7_len(), 0b11);
        assert_eq!(HwBreakpointSize::Qword.to_dr7_len(), 0b10);

        assert_eq!(HwBreakpointType::Execute.to_dr7_rw(), 0b00);
        assert_eq!(HwBreakpointType::Write.to_dr7_rw(), 0b01);
        assert_eq!(HwBreakpointType::ReadWrite.to_dr7_rw(), 0b11);
    }
}
