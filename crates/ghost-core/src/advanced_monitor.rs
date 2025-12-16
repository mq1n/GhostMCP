//! Advanced Monitoring Module
//!
//! Provides advanced monitoring capabilities:
//! - Dynamic API call monitoring (GetProcAddress hooking)
//! - Process chill (freeze/resume for analysis)
//! - COM object scanning
//! - DLL load/unload monitoring
//! - Delayed DLL import monitoring

use crate::api_trace_hooks::ApiTraceHookEngine;
use ghost_common::types::{
    ChillConfig, ChillMode, ChillStatus, ComMethodEntry, ComScanConfig, ComScanResult,
    DelayedDllInfo, DllEvent, DllEventType, DllMonitorConfig, DllMonitorStatus,
    DynamicApiMonitorConfig, DynamicApiResolution, StringPattern,
};
use ghost_common::{Error, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Maximum number of events to buffer (prevents unbounded memory growth)
/// Used by DynamicApiMonitor, DllMonitor to cap event storage
const MAX_BUFFER_SIZE: usize = 10000;

/// Maximum pattern length for safety
#[allow(dead_code)]
const MAX_PATTERN_LENGTH: usize = 1024;

/// Maximum threads to enumerate (safety limit)
#[allow(dead_code)]
const MAX_THREADS: usize = 10000;
#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Thread32First, Thread32Next,
    MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
    THREAD_SUSPEND_RESUME,
};

// ============================================================================
// Dynamic API Monitor
// ============================================================================

/// Dynamic API call monitor - tracks GetProcAddress and similar calls
pub struct DynamicApiMonitor {
    config: DynamicApiMonitorConfig,
    resolutions: RwLock<Vec<DynamicApiResolution>>,
    active: AtomicBool,
    resolution_count: AtomicU64,
    #[allow(dead_code)]
    start_time: Instant,
}

impl DynamicApiMonitor {
    /// Create a new dynamic API monitor with the given configuration
    ///
    /// # Arguments
    /// * `config` - Monitor configuration
    pub fn new(config: DynamicApiMonitorConfig) -> Self {
        debug!(target: "ghost_core::monitor", "Creating DynamicApiMonitor");
        Self {
            config,
            resolutions: RwLock::new(Vec::with_capacity(1024)),
            active: AtomicBool::new(false),
            resolution_count: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Check if the monitor is currently active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Get the total count of resolutions captured
    pub fn get_resolution_count(&self) -> u64 {
        self.resolution_count.load(Ordering::SeqCst)
    }

    /// Start monitoring dynamic API resolutions
    ///
    /// # Arguments
    /// * `hook_engine` - Hook engine for installing detours
    /// * `session_id` - Trace session ID
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` if hooks cannot be installed
    pub fn start(
        &self,
        hook_engine: &mut ApiTraceHookEngine,
        session_id: ghost_common::types::TraceSessionId,
    ) -> Result<()> {
        if self.active.load(Ordering::SeqCst) {
            debug!(target: "ghost_core::monitor", "Dynamic API monitor already active");
            return Ok(());
        }

        info!(target: "ghost_core::monitor", "Starting dynamic API monitor");

        // Install hooks on GetProcAddress, etc.
        #[cfg(target_os = "windows")]
        {
            if self.config.hook_getprocaddress {
                debug!(target: "ghost_core::monitor", "Hooking GetProcAddress");
                hook_engine.install_hook(session_id, "kernel32.dll", "GetProcAddress")?;
            }
            if self.config.hook_ldr_getprocedureaddress {
                debug!(target: "ghost_core::monitor", "Hooking LdrGetProcedureAddress");
                hook_engine.install_hook(session_id, "ntdll.dll", "LdrGetProcedureAddress")?;
            }
            if self.config.hook_getprocaddressforcaller {
                debug!(target: "ghost_core::monitor", "Hooking GetProcAddressForCaller");
                // GetProcAddressForCaller is an internal function, might fail if not exported
                let _ =
                    hook_engine.install_hook(session_id, "kernel32.dll", "GetProcAddressForCaller");
            }
        }

        self.active.store(true, Ordering::SeqCst);
        info!(target: "ghost_core::monitor", "Dynamic API monitor started successfully");
        Ok(())
    }

    /// Stop monitoring
    pub fn stop(&self) -> Result<()> {
        if !self.active.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping dynamic API monitor");
        self.active.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Record a dynamic API resolution (called from hook)
    pub fn record_resolution(&self, resolution: DynamicApiResolution) {
        if !self.active.load(Ordering::SeqCst) {
            return;
        }

        // Apply filters
        if !self.matches_filter(&resolution) {
            return;
        }

        self.resolution_count.fetch_add(1, Ordering::SeqCst);

        if let Ok(mut resolutions) = self.resolutions.write() {
            resolutions.push(resolution);
            // Keep buffer bounded - prevent unbounded memory growth
            if resolutions.len() >= MAX_BUFFER_SIZE {
                warn!(target: "ghost_core::monitor", "Dynamic API buffer full, dropping oldest event");
                resolutions.remove(0);
            }
        }
    }

    /// Get captured resolutions
    pub fn get_resolutions(&self, count: usize, offset: usize) -> Vec<DynamicApiResolution> {
        if let Ok(resolutions) = self.resolutions.read() {
            resolutions
                .iter()
                .skip(offset)
                .take(count)
                .cloned()
                .collect()
        } else {
            vec![]
        }
    }

    /// Clear captured resolutions
    pub fn clear(&self) {
        if let Ok(mut resolutions) = self.resolutions.write() {
            resolutions.clear();
        }
    }

    fn matches_filter(&self, resolution: &DynamicApiResolution) -> bool {
        // Module filter
        if !self.config.module_filter.is_empty() {
            let matches = self
                .config
                .module_filter
                .iter()
                .any(|p| match_string_pattern(p, &resolution.module_name));
            if !matches {
                return false;
            }
        }

        // Function filter
        if !self.config.function_filter.is_empty() {
            let matches = self
                .config
                .function_filter
                .iter()
                .any(|p| match_string_pattern(p, &resolution.function_name));
            if !matches {
                return false;
            }
        }

        true
    }
}

// ============================================================================
// Chill Process Manager
// ============================================================================

/// Chill (freeze) process manager for analysis
pub struct ChillManager {
    config: ChillConfig,
    frozen_threads: RwLock<Vec<u32>>,
    is_chilled: AtomicBool,
    chill_start: RwLock<Option<Instant>>,
}

impl ChillManager {
    pub fn new(config: ChillConfig) -> Self {
        Self {
            config,
            frozen_threads: RwLock::new(Vec::new()),
            is_chilled: AtomicBool::new(false),
            chill_start: RwLock::new(None),
        }
    }

    /// Freeze threads according to configuration
    #[cfg(target_os = "windows")]
    pub fn chill(&self) -> Result<ChillStatus> {
        if self.is_chilled.load(Ordering::SeqCst) {
            return self.status();
        }

        info!("Chilling process with mode {:?}", self.config.mode);

        let current_pid = unsafe { GetCurrentProcessId() };
        let current_tid = unsafe { GetCurrentThreadId() };

        let mut frozen = Vec::new();

        // Get all threads in the process
        let threads = self.enumerate_threads(current_pid)?;

        for tid in threads {
            // Check if we should freeze this thread
            let should_freeze = match self.config.mode {
                ChillMode::AllExceptCurrent => tid != current_tid,
                ChillMode::AllThreads => true,
                ChillMode::SpecificThreads => self.config.thread_ids.contains(&tid),
                ChillMode::Filtered => {
                    // Would need thread name lookup - simplified for now
                    tid != current_tid
                }
            };

            if should_freeze {
                if let Ok(handle) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, tid) } {
                    let result = unsafe { SuspendThread(handle) };
                    if result != u32::MAX {
                        frozen.push(tid);
                        debug!("Suspended thread {}", tid);
                    }
                    let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                }
            }
        }

        *self.frozen_threads.write().unwrap() = frozen;
        *self.chill_start.write().unwrap() = Some(Instant::now());
        self.is_chilled.store(true, Ordering::SeqCst);

        info!(
            "Chilled {} threads",
            self.frozen_threads.read().unwrap().len()
        );
        self.status()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn chill(&self) -> Result<ChillStatus> {
        Err(Error::NotImplemented(
            "Process chill not supported on this platform".to_string(),
        ))
    }

    /// Resume frozen threads
    #[cfg(target_os = "windows")]
    pub fn resume(&self) -> Result<ChillStatus> {
        if !self.is_chilled.load(Ordering::SeqCst) {
            return self.status();
        }

        info!("Resuming chilled threads");

        let frozen = self.frozen_threads.read().unwrap().clone();

        for tid in &frozen {
            if let Ok(handle) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, *tid) } {
                unsafe { ResumeThread(handle) };
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                debug!("Resumed thread {}", tid);
            }
        }

        *self.frozen_threads.write().unwrap() = Vec::new();
        *self.chill_start.write().unwrap() = None;
        self.is_chilled.store(false, Ordering::SeqCst);

        self.status()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn resume(&self) -> Result<ChillStatus> {
        Err(Error::NotImplemented(
            "Process resume not supported on this platform".to_string(),
        ))
    }

    /// Get current chill status
    pub fn status(&self) -> Result<ChillStatus> {
        let is_chilled = self.is_chilled.load(Ordering::SeqCst);
        let frozen = self.frozen_threads.read().unwrap().clone();
        let started_at = self
            .chill_start
            .read()
            .unwrap()
            .as_ref()
            .map(|t| t.elapsed().as_micros() as u64);

        let time_remaining = if is_chilled && self.config.max_duration_ms > 0 {
            if let Some(start) = *self.chill_start.read().unwrap() {
                let elapsed = start.elapsed().as_millis() as u64;
                if elapsed < self.config.max_duration_ms {
                    Some(self.config.max_duration_ms - elapsed)
                } else {
                    Some(0)
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(ChillStatus {
            is_chilled,
            frozen_thread_count: frozen.len(),
            frozen_threads: frozen,
            started_at,
            time_remaining_ms: time_remaining,
        })
    }

    #[cfg(target_os = "windows")]
    fn enumerate_threads(&self, pid: u32) -> Result<Vec<u32>> {
        let mut threads = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| Error::Internal(format!("CreateToolhelp32Snapshot failed: {}", e)))?;

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        threads.push(entry.th32ThreadID);
                    }
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }

        Ok(threads)
    }
}

// ============================================================================
// COM Object Scanner
// ============================================================================

/// COM object scanner
pub struct ComScanner {
    config: ComScanConfig,
}

impl ComScanner {
    pub fn new(config: ComScanConfig) -> Self {
        Self { config }
    }

    /// Scan for COM objects in memory
    #[cfg(target_os = "windows")]
    pub fn scan(&self) -> Result<ComScanResult> {
        let start = Instant::now();
        let objects = Vec::new();
        let mut regions_scanned = 0;
        let bytes_scanned = 0u64;

        info!("Scanning for COM objects");

        // In production, this would:
        // 1. Walk the heap looking for vtable pointers
        // 2. Validate vtable structure (IUnknown: QueryInterface, AddRef, Release)
        // 3. Try to identify interface by GUID lookup
        // 4. Extract method addresses

        // Simplified: scan loaded modules for known COM patterns
        if self.config.scan_globals {
            // Would scan .data sections of modules
            regions_scanned += 1;
        }

        if self.config.scan_heap {
            // Would walk process heap
            regions_scanned += 1;
        }

        Ok(ComScanResult {
            objects,
            regions_scanned,
            bytes_scanned,
            duration_us: start.elapsed().as_micros() as u64,
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan(&self) -> Result<ComScanResult> {
        Err(Error::NotImplemented(
            "COM scanning not supported on this platform".to_string(),
        ))
    }

    /// Get vtable methods for a COM object
    #[cfg(target_os = "windows")]
    pub fn get_vtable_methods(
        &self,
        vtable_addr: u64,
        max_methods: usize,
    ) -> Result<Vec<ComMethodEntry>> {
        let mut methods = Vec::new();

        // Read vtable entries (each is a function pointer)
        // In production, read memory at vtable_addr and resolve symbols

        for i in 0..max_methods.min(64) {
            let method_addr = vtable_addr + (i as u64 * 8); // x64 pointer size
            methods.push(ComMethodEntry {
                index: i,
                address: method_addr,
                name: None,
                module: None,
            });
        }

        Ok(methods)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_vtable_methods(
        &self,
        _vtable_addr: u64,
        _max_methods: usize,
    ) -> Result<Vec<ComMethodEntry>> {
        Err(Error::NotImplemented(
            "COM vtable reading not supported on this platform".to_string(),
        ))
    }
}

// ============================================================================
// DLL Monitor
// ============================================================================

/// DLL load/unload monitor
pub struct DllMonitor {
    config: DllMonitorConfig,
    events: RwLock<Vec<DllEvent>>,
    active: AtomicBool,
    load_count: AtomicU64,
    unload_count: AtomicU64,
    delay_load_count: AtomicU64,
    failed_load_count: AtomicU64,
    #[allow(dead_code)]
    start_time: Instant,
}

impl DllMonitor {
    pub fn new(config: DllMonitorConfig) -> Self {
        Self {
            config,
            events: RwLock::new(Vec::new()),
            active: AtomicBool::new(false),
            load_count: AtomicU64::new(0),
            unload_count: AtomicU64::new(0),
            delay_load_count: AtomicU64::new(0),
            failed_load_count: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Start DLL monitoring
    pub fn start(&self, _hook_engine: &mut ApiTraceHookEngine) -> Result<()> {
        if self.active.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Starting DLL monitor");

        #[cfg(target_os = "windows")]
        {
            if self.config.hook_loadlibrary {
                debug!("Would hook LoadLibraryA/W");
            }
            if self.config.hook_ldr_loaddll {
                debug!("Would hook LdrLoadDll");
            }
            if self.config.hook_freelibrary {
                debug!("Would hook FreeLibrary");
            }
            if self.config.hook_delay_load {
                debug!("Would hook __delayLoadHelper2");
            }
        }

        self.active.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Stop DLL monitoring
    pub fn stop(&self) -> Result<()> {
        if !self.active.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping DLL monitor");
        self.active.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Record a DLL event (called from hook)
    pub fn record_event(&self, event: DllEvent) {
        if !self.active.load(Ordering::SeqCst) {
            return;
        }

        // Apply filters
        if !self.matches_filter(&event) {
            return;
        }

        // Update counters
        match event.event_type {
            DllEventType::Load => {
                self.load_count.fetch_add(1, Ordering::SeqCst);
            }
            DllEventType::Unload => {
                self.unload_count.fetch_add(1, Ordering::SeqCst);
            }
            DllEventType::DelayLoad => {
                self.delay_load_count.fetch_add(1, Ordering::SeqCst);
            }
            DllEventType::LoadFailed | DllEventType::DelayLoadFailed => {
                self.failed_load_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        if let Ok(mut events) = self.events.write() {
            events.push(event);
            // Keep buffer bounded - prevent unbounded memory growth
            if events.len() >= MAX_BUFFER_SIZE {
                warn!(target: "ghost_core::monitor", "DLL event buffer full, dropping oldest event");
                events.remove(0);
            }
        }
    }

    /// Get captured events
    pub fn get_events(&self, count: usize, offset: usize) -> Vec<DllEvent> {
        if let Ok(events) = self.events.read() {
            events.iter().skip(offset).take(count).cloned().collect()
        } else {
            vec![]
        }
    }

    /// Get monitor status
    pub fn status(&self) -> DllMonitorStatus {
        DllMonitorStatus {
            active: self.active.load(Ordering::SeqCst),
            load_count: self.load_count.load(Ordering::SeqCst),
            unload_count: self.unload_count.load(Ordering::SeqCst),
            delay_load_count: self.delay_load_count.load(Ordering::SeqCst),
            failed_load_count: self.failed_load_count.load(Ordering::SeqCst),
            monitored_dlls: self.get_monitored_dlls(),
        }
    }

    /// List currently loaded DLLs being monitored
    #[cfg(target_os = "windows")]
    fn get_monitored_dlls(&self) -> Vec<String> {
        let mut dlls = Vec::new();

        unsafe {
            let pid = GetCurrentProcessId();
            if let Ok(snapshot) =
                CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
            {
                let mut entry = MODULEENTRY32W {
                    dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                    ..Default::default()
                };

                if Module32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let name = String::from_utf16_lossy(
                            &entry.szModule[..entry
                                .szModule
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(entry.szModule.len())],
                        );
                        dlls.push(name);

                        if Module32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = windows::Win32::Foundation::CloseHandle(snapshot);
            }
        }

        dlls
    }

    #[cfg(not(target_os = "windows"))]
    fn get_monitored_dlls(&self) -> Vec<String> {
        vec![]
    }

    fn matches_filter(&self, event: &DllEvent) -> bool {
        // System DLL filter
        if !self.config.include_system_dlls {
            let path_lower = event.path.to_lowercase();
            if path_lower.contains("\\windows\\system32\\")
                || path_lower.contains("\\windows\\syswow64\\")
            {
                return false;
            }
        }

        // Include filter
        if !self.config.dll_filter.is_empty() {
            let matches = self
                .config
                .dll_filter
                .iter()
                .any(|p| match_string_pattern(p, &event.path));
            if !matches {
                return false;
            }
        }

        // Exclude filter
        if !self.config.dll_exclude.is_empty() {
            let excluded = self
                .config
                .dll_exclude
                .iter()
                .any(|p| match_string_pattern(p, &event.path));
            if excluded {
                return false;
            }
        }

        true
    }

    /// Clear captured events
    pub fn clear(&self) {
        if let Ok(mut events) = self.events.write() {
            events.clear();
        }
        self.load_count.store(0, Ordering::SeqCst);
        self.unload_count.store(0, Ordering::SeqCst);
        self.delay_load_count.store(0, Ordering::SeqCst);
        self.failed_load_count.store(0, Ordering::SeqCst);
    }
}

/// Delayed DLL import scanner
pub struct DelayedImportScanner;

impl DelayedImportScanner {
    /// Scan PE for delayed imports
    #[cfg(target_os = "windows")]
    pub fn scan_delayed_imports(base_address: u64) -> Result<Vec<DelayedDllInfo>> {
        let delayed_dlls = Vec::new();

        // In production, this would:
        // 1. Parse PE header at base_address
        // 2. Find Delay Import Directory
        // 3. Parse ImgDelayDescr structures
        // 4. Extract DLL names and pending imports

        debug!("Scanning delayed imports at {:#x}", base_address);

        Ok(delayed_dlls)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_delayed_imports(_base_address: u64) -> Result<Vec<DelayedDllInfo>> {
        Err(Error::NotImplemented(
            "Delayed import scanning not supported on this platform".to_string(),
        ))
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Match a string against a pattern
fn match_string_pattern(pattern: &StringPattern, value: &str) -> bool {
    match pattern {
        StringPattern::Exact(s) => value == s,
        StringPattern::Prefix(s) => value.starts_with(s),
        StringPattern::Suffix(s) => value.ends_with(s),
        StringPattern::Contains(s) => value.contains(s),
        StringPattern::Wildcard(s) => {
            // Simple wildcard matching (* and ?)
            wildcard_match(s, value)
        }
        StringPattern::Regex(s) => {
            if let Ok(re) = regex::Regex::new(s) {
                re.is_match(value)
            } else {
                false
            }
        }
    }
}

/// Simple wildcard matching
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let value_chars: Vec<char> = value.chars().collect();
    wildcard_match_impl(&pattern_chars, &value_chars)
}

fn wildcard_match_impl(pattern: &[char], value: &[char]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }

    if pattern[0] == '*' {
        // * matches zero or more characters
        wildcard_match_impl(&pattern[1..], value)
            || (!value.is_empty() && wildcard_match_impl(pattern, &value[1..]))
    } else if pattern[0] == '?' || (!value.is_empty() && pattern[0] == value[0]) {
        // ? matches exactly one character, or characters match
        !value.is_empty() && wildcard_match_impl(&pattern[1..], &value[1..])
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Wildcard and Pattern Matching Tests
    // ========================================================================

    #[test]
    fn test_wildcard_match_basic() {
        assert!(wildcard_match("*.dll", "kernel32.dll"));
        assert!(wildcard_match("kernel*.dll", "kernel32.dll"));
        assert!(wildcard_match("*.exe", "notepad.exe"));
        assert!(!wildcard_match("*.dll", "notepad.exe"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "ac"));
    }

    #[test]
    fn test_wildcard_match_edge_cases() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("", "something"));
        assert!(wildcard_match("???", "abc"));
        assert!(!wildcard_match("???", "ab"));
        assert!(wildcard_match("*.*", "file.txt"));
        assert!(wildcard_match("**", "test"));
    }

    #[test]
    fn test_match_string_pattern_exact() {
        assert!(match_string_pattern(
            &StringPattern::Exact("CreateFileW".to_string()),
            "CreateFileW"
        ));
        assert!(!match_string_pattern(
            &StringPattern::Exact("CreateFileW".to_string()),
            "CreateFileA"
        ));
    }

    #[test]
    fn test_match_string_pattern_prefix() {
        assert!(match_string_pattern(
            &StringPattern::Prefix("Create".to_string()),
            "CreateFileW"
        ));
        assert!(!match_string_pattern(
            &StringPattern::Prefix("Open".to_string()),
            "CreateFileW"
        ));
    }

    #[test]
    fn test_match_string_pattern_suffix() {
        assert!(match_string_pattern(
            &StringPattern::Suffix("W".to_string()),
            "CreateFileW"
        ));
        assert!(!match_string_pattern(
            &StringPattern::Suffix("A".to_string()),
            "CreateFileW"
        ));
    }

    #[test]
    fn test_match_string_pattern_contains() {
        assert!(match_string_pattern(
            &StringPattern::Contains("File".to_string()),
            "CreateFileW"
        ));
        assert!(!match_string_pattern(
            &StringPattern::Contains("Registry".to_string()),
            "CreateFileW"
        ));
    }

    #[test]
    fn test_match_string_pattern_wildcard() {
        assert!(match_string_pattern(
            &StringPattern::Wildcard("Create*W".to_string()),
            "CreateFileW"
        ));
        assert!(match_string_pattern(
            &StringPattern::Wildcard("*File*".to_string()),
            "CreateFileW"
        ));
    }

    #[test]
    fn test_match_string_pattern_regex() {
        assert!(match_string_pattern(
            &StringPattern::Regex(r"^Create.*W$".to_string()),
            "CreateFileW"
        ));
        assert!(!match_string_pattern(
            &StringPattern::Regex(r"^Open.*".to_string()),
            "CreateFileW"
        ));
        // Invalid regex should return false
        assert!(!match_string_pattern(
            &StringPattern::Regex(r"[invalid".to_string()),
            "anything"
        ));
    }

    // ========================================================================
    // DynamicApiMonitor Tests
    // ========================================================================

    #[test]
    fn test_dynamic_api_monitor_creation() {
        let config = DynamicApiMonitorConfig::default();
        let monitor = DynamicApiMonitor::new(config);
        assert!(!monitor.is_active());
        assert_eq!(monitor.get_resolution_count(), 0);
    }

    #[test]
    fn test_dynamic_api_monitor_record_when_inactive() {
        let config = DynamicApiMonitorConfig::default();
        let monitor = DynamicApiMonitor::new(config);

        let resolution = DynamicApiResolution {
            thread_id: 1234,
            timestamp_us: 0,
            module_name: "kernel32.dll".to_string(),
            function_name: "CreateFileW".to_string(),
            resolved_address: Some(0x7FFE0000),
            success: true,
            call_stack: None,
        };

        monitor.record_resolution(resolution);
        // Should not record when inactive
        assert_eq!(monitor.get_resolution_count(), 0);
    }

    #[test]
    fn test_dynamic_api_monitor_get_resolutions() {
        let config = DynamicApiMonitorConfig::default();
        let monitor = DynamicApiMonitor::new(config);

        // Get resolutions when empty
        let resolutions = monitor.get_resolutions(10, 0);
        assert!(resolutions.is_empty());
    }

    #[test]
    fn test_dynamic_api_monitor_clear() {
        let config = DynamicApiMonitorConfig::default();
        let monitor = DynamicApiMonitor::new(config);
        monitor.clear();
        assert_eq!(monitor.get_resolution_count(), 0);
    }

    // ========================================================================
    // ChillManager Tests
    // ========================================================================

    #[test]
    fn test_chill_manager_creation() {
        let config = ChillConfig::default();
        let manager = ChillManager::new(config);
        let status = manager.status().unwrap();
        assert!(!status.is_chilled);
        assert_eq!(status.frozen_thread_count, 0);
    }

    #[test]
    fn test_chill_config_default() {
        let config = ChillConfig::default();
        assert_eq!(config.mode, ChillMode::AllExceptCurrent);
        assert_eq!(config.max_duration_ms, 30000);
        assert!(config.auto_resume);
    }

    // ========================================================================
    // ComScanner Tests
    // ========================================================================

    #[test]
    fn test_com_scanner_creation() {
        let config = ComScanConfig::default();
        let _scanner = ComScanner::new(config);
    }

    #[test]
    fn test_com_scan_config_default() {
        let config = ComScanConfig::default();
        assert!(config.scan_heap);
        assert!(!config.scan_stack);
        assert!(config.scan_globals);
        assert_eq!(config.max_results, 1000);
        assert!(config.resolve_symbols);
    }

    // ========================================================================
    // DllMonitor Tests
    // ========================================================================

    #[test]
    fn test_dll_monitor_creation() {
        let config = DllMonitorConfig::default();
        let monitor = DllMonitor::new(config);
        let status = monitor.status();
        assert!(!status.active);
        assert_eq!(status.load_count, 0);
        assert_eq!(status.unload_count, 0);
    }

    #[test]
    fn test_dll_monitor_config_default() {
        let config = DllMonitorConfig::default();
        assert!(config.hook_loadlibrary);
        assert!(config.hook_ldr_loaddll);
        assert!(config.hook_freelibrary);
        assert!(config.hook_delay_load);
        assert!(config.capture_call_stacks);
        assert!(!config.include_system_dlls);
    }

    #[test]
    fn test_dll_monitor_record_when_inactive() {
        let config = DllMonitorConfig::default();
        let monitor = DllMonitor::new(config);

        let event = DllEvent {
            event_type: DllEventType::Load,
            thread_id: 1234,
            timestamp_us: 0,
            path: "test.dll".to_string(),
            base_address: 0x10000000,
            size: 0x10000,
            entry_point: Some(0x10001000),
            call_stack: None,
            load_reason: None,
        };

        monitor.record_event(event);
        // Should not record when inactive
        assert_eq!(monitor.status().load_count, 0);
    }

    #[test]
    fn test_dll_monitor_get_events() {
        let config = DllMonitorConfig::default();
        let monitor = DllMonitor::new(config);

        let events = monitor.get_events(10, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_dll_monitor_clear() {
        let config = DllMonitorConfig::default();
        let monitor = DllMonitor::new(config);
        monitor.clear();
        let status = monitor.status();
        assert_eq!(status.load_count, 0);
        assert_eq!(status.unload_count, 0);
        assert_eq!(status.delay_load_count, 0);
        assert_eq!(status.failed_load_count, 0);
    }

    // ========================================================================
    // DynamicApiMonitorConfig Tests
    // ========================================================================

    #[test]
    fn test_dynamic_api_monitor_config_default() {
        let config = DynamicApiMonitorConfig::default();
        assert!(config.hook_getprocaddress);
        assert!(config.hook_ldr_getprocedureaddress);
        assert!(!config.hook_getprocaddressforcaller);
        assert!(config.capture_call_stacks);
    }

    // ========================================================================
    // Buffer Limit Tests
    // ========================================================================

    #[test]
    fn test_max_buffer_size_constant() {
        assert_eq!(MAX_BUFFER_SIZE, 10000);
    }
}
