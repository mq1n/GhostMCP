//! API Call Tracing & Monitoring
//!
//! Rohitab API Monitor-style tracing: capture, filter, and analyze Win32 API calls
//! with full argument decoding.

use ghost_common::types::{
    ApiCallEvent, ApiHookStatus, ApiPack, ApiPackId, ApiPackInfo, BackpressureStrategy,
    CapturedValue, FilterPreset, FilterPresetId, QueueStats, RingBufferConfig, StringPattern,
    TraceEventsResult, TraceFilter, TraceSessionConfig, TraceSessionId, TraceSessionInfo,
    TraceSessionState, TraceStartResult, TraceStats, ValueComparison,
};
use ghost_common::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// Ring buffer for storing captured API call events
pub struct EventRingBuffer {
    events: VecDeque<ApiCallEvent>,
    config: RingBufferConfig,
    stats: QueueStats,
    sample_counter: u64,
}

impl EventRingBuffer {
    pub fn new(config: RingBufferConfig) -> Self {
        Self {
            events: VecDeque::with_capacity(config.max_events.min(1000)),
            config,
            stats: QueueStats::default(),
            sample_counter: 0,
        }
    }

    pub fn push(&mut self, event: ApiCallEvent) -> bool {
        if self.events.len() >= self.config.max_events {
            match self.config.backpressure {
                BackpressureStrategy::DropOldest => {
                    self.events.pop_front();
                    self.stats.total_dropped += 1;
                }
                BackpressureStrategy::Block => {
                    self.stats.total_dropped += 1;
                    return false;
                }
                BackpressureStrategy::Sample { rate } => {
                    self.sample_counter += 1;
                    if !self.sample_counter.is_multiple_of(rate as u64) {
                        self.stats.total_dropped += 1;
                        return false;
                    }
                    self.events.pop_front();
                }
            }
        }

        self.events.push_back(event);
        self.stats.total_captured += 1;
        self.stats.current_depth = self.events.len();
        self.stats.max_depth = self.stats.max_depth.max(self.events.len());
        true
    }

    pub fn drain(&mut self, count: usize) -> Vec<ApiCallEvent> {
        let count = count.min(self.events.len());
        let events: Vec<_> = self.events.drain(..count).collect();
        self.stats.current_depth = self.events.len();
        events
    }

    pub fn peek(&self, count: usize, offset: usize) -> Vec<&ApiCallEvent> {
        self.events.iter().skip(offset).take(count).collect()
    }

    pub fn clear(&mut self) {
        self.events.clear();
        self.stats.current_depth = 0;
    }

    pub fn stats(&self) -> &QueueStats {
        &self.stats
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// API Pack Manager - loads and manages API definition packs from JSON files
pub struct ApiPackManager {
    packs: HashMap<ApiPackId, ApiPack>,
    builtin_packs: Vec<ApiPackId>,
    pack_dir: Option<std::path::PathBuf>,
}

impl ApiPackManager {
    /// Creates a new ApiPackManager instance
    pub fn new() -> Self {
        Self {
            packs: HashMap::new(),
            builtin_packs: Vec::new(),
            pack_dir: None,
        }
    }

    /// Creates a new ApiPackManager with a specific pack directory
    pub fn with_pack_dir(pack_dir: std::path::PathBuf) -> Self {
        Self {
            packs: HashMap::new(),
            builtin_packs: Vec::new(),
            pack_dir: Some(pack_dir),
        }
    }

    /// Loads all built-in API packs from the api_packs directory
    pub fn load_builtin_packs(&mut self) -> Result<()> {
        info!("Loading built-in API packs from JSON files");

        let builtin_names = ["kernel32", "user32", "ntdll", "ws2_32", "advapi32"];
        let mut loaded = 0;
        let mut errors = Vec::new();

        for name in &builtin_names {
            match self.load_builtin_pack(name) {
                Ok(_) => {
                    loaded += 1;
                    debug!("Loaded {} API pack", name);
                }
                Err(e) => {
                    tracing::warn!("Failed to load {} API pack: {}", name, e);
                    errors.push(format!("{}: {}", name, e));
                }
            }
        }

        info!(
            "Loaded {}/{} built-in API packs",
            loaded,
            builtin_names.len()
        );

        if loaded == 0 && !errors.is_empty() {
            return Err(Error::Internal(format!(
                "Failed to load any API packs: {}",
                errors.join(", ")
            )));
        }

        Ok(())
    }

    /// Loads a single built-in pack by name
    fn load_builtin_pack(&mut self, name: &str) -> Result<()> {
        let pack = self.load_pack_from_json(name, true)?;
        let id = pack.id.clone();
        self.packs.insert(id.clone(), pack);
        self.builtin_packs.push(id);
        Ok(())
    }

    /// Loads a pack from a JSON file
    fn load_pack_from_json(&self, name: &str, is_builtin: bool) -> Result<ApiPack> {
        let json_path = self.resolve_pack_path(name)?;

        let content = std::fs::read_to_string(&json_path).map_err(|e| {
            Error::Internal(format!(
                "Failed to read API pack file '{}': {}",
                json_path.display(),
                e
            ))
        })?;

        let pack: ApiPack = serde_json::from_str(&content).map_err(|e| {
            Error::Serialization(format!(
                "Failed to parse API pack '{}': {} (line {}, col {})",
                name,
                e,
                e.line(),
                e.column()
            ))
        })?;

        self.validate_pack(&pack)?;

        if is_builtin {
            debug!(
                "Loaded built-in pack '{}' with {} functions",
                pack.name,
                pack.functions.len()
            );
        } else {
            info!(
                "Loaded custom pack '{}' with {} functions",
                pack.name,
                pack.functions.len()
            );
        }

        Ok(pack)
    }

    /// Resolves the path to a pack JSON file
    fn resolve_pack_path(&self, name: &str) -> Result<std::path::PathBuf> {
        if let Some(ref dir) = self.pack_dir {
            let path = dir.join(format!("{}.json", name));
            if path.exists() {
                return Ok(path);
            }
        }

        let mut candidates: Vec<std::path::PathBuf> = vec![
            std::path::PathBuf::from(format!("data/api_packs/{}.json", name)),
            std::path::PathBuf::from(format!("../../data/api_packs/{}.json", name)),
            std::path::PathBuf::from(format!(
                "crates/ghost-static-mcp/data/api_packs/{}.json",
                name
            )),
        ];

        // Add compile-time workspace root path (ghost-core is at crates/ghost-core)
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        if let Some(workspace_root) = manifest_dir.parent().and_then(|p| p.parent()) {
            candidates.push(
                workspace_root
                    .join("data")
                    .join("api_packs")
                    .join(format!("{}.json", name)),
            );
        }

        for candidate in &candidates {
            if candidate.exists() {
                return Ok(candidate.clone());
            }
        }

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let path = exe_dir
                    .join("data")
                    .join("api_packs")
                    .join(format!("{}.json", name));
                if path.exists() {
                    return Ok(path);
                }
            }
        }

        Err(Error::Internal(format!(
            "API pack file not found: {}.json (searched in data/api_packs and executable directory)",
            name
        )))
    }

    /// Validates a loaded pack for consistency
    fn validate_pack(&self, pack: &ApiPack) -> Result<()> {
        if pack.id.0.is_empty() {
            return Err(Error::Internal("API pack has empty ID".to_string()));
        }
        if pack.name.is_empty() {
            return Err(Error::Internal("API pack has empty name".to_string()));
        }
        if pack.module.is_empty() {
            return Err(Error::Internal("API pack has empty module".to_string()));
        }

        for func in &pack.functions {
            if func.name.is_empty() {
                return Err(Error::Internal(format!(
                    "API pack '{}' contains function with empty name",
                    pack.name
                )));
            }
        }

        Ok(())
    }

    /// Loads a custom pack from a file path
    pub fn load_pack_from_file(&mut self, path: &std::path::Path) -> Result<ApiPackId> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Internal(format!(
                "Failed to read pack file '{}': {}",
                path.display(),
                e
            ))
        })?;

        let pack: ApiPack = serde_json::from_str(&content).map_err(|e| {
            Error::Serialization(format!(
                "Failed to parse pack file '{}': {}",
                path.display(),
                e
            ))
        })?;

        self.validate_pack(&pack)?;

        if self.packs.contains_key(&pack.id) {
            return Err(Error::Internal(format!(
                "API pack already loaded: {}",
                pack.id.0
            )));
        }

        let id = pack.id.clone();
        info!(
            "Loaded custom API pack '{}' with {} functions",
            pack.name,
            pack.functions.len()
        );
        self.packs.insert(id.clone(), pack);
        Ok(id)
    }

    /// Loads a custom pack from an ApiPack struct
    pub fn load_custom_pack(&mut self, pack: ApiPack) -> Result<()> {
        self.validate_pack(&pack)?;

        if self.packs.contains_key(&pack.id) {
            return Err(Error::Internal(format!(
                "API pack already loaded: {}",
                pack.id.0
            )));
        }

        info!(
            "Loaded custom API pack '{}' with {} functions",
            pack.name,
            pack.functions.len()
        );
        self.packs.insert(pack.id.clone(), pack);
        Ok(())
    }

    /// Unloads a custom pack (built-in packs cannot be unloaded)
    pub fn unload_pack(&mut self, id: &ApiPackId) -> Result<()> {
        if self.builtin_packs.contains(id) {
            return Err(Error::Internal(
                "Cannot unload built-in pack. Built-in packs are required for core functionality."
                    .to_string(),
            ));
        }

        self.packs
            .remove(id)
            .ok_or_else(|| Error::Internal(format!("Pack not found: {}", id.0)))?;

        info!("Unloaded API pack: {}", id.0);
        Ok(())
    }

    /// Gets a pack by ID
    pub fn get_pack(&self, id: &ApiPackId) -> Option<&ApiPack> {
        self.packs.get(id)
    }

    /// Lists all loaded packs with their info
    pub fn list_packs(&self) -> Vec<ApiPackInfo> {
        self.packs
            .values()
            .map(|p| ApiPackInfo {
                id: p.id.clone(),
                name: p.name.clone(),
                version: p.version.clone(),
                description: p.description.clone(),
                module: p.module.clone(),
                function_count: p.functions.len(),
                loaded: true,
                builtin: self.builtin_packs.contains(&p.id),
            })
            .collect()
    }

    /// Gets all functions from all loaded packs
    pub fn get_all_functions(&self) -> Vec<(&ApiPack, &ghost_common::types::ApiFunctionDef)> {
        self.packs
            .values()
            .flat_map(|p| p.functions.iter().map(move |f| (p, f)))
            .collect()
    }

    /// Returns the number of loaded packs
    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }

    /// Returns the total number of functions across all packs
    pub fn function_count(&self) -> usize {
        self.packs.values().map(|p| p.functions.len()).sum()
    }
}

impl Default for ApiPackManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter matcher for API call events
pub struct FilterMatcher {
    filter: TraceFilter,
    regex_cache: HashMap<String, regex::Regex>,
}

impl FilterMatcher {
    pub fn new(filter: TraceFilter) -> Self {
        Self {
            filter,
            regex_cache: HashMap::new(),
        }
    }

    pub fn matches(&mut self, event: &ApiCallEvent) -> bool {
        if !self.matches_api_name(&event.function_name) {
            return false;
        }
        if !self.matches_module(&event.module_name) {
            return false;
        }
        if let Some(ref thread_filter) = self.filter.thread_filter {
            if !self.matches_thread(event.thread_id, thread_filter) {
                return false;
            }
        }
        if self.filter.failed_only && event.success != Some(false) {
            return false;
        }
        if self.filter.success_only && event.success != Some(true) {
            return false;
        }
        if let Some(ref return_filter) = self.filter.return_filter {
            if let Some(ref ret_val) = event.return_value {
                if !self.matches_return_value(ret_val, return_filter) {
                    return false;
                }
            }
        }
        true
    }

    fn matches_api_name(&mut self, name: &str) -> bool {
        let exclude_apis: Vec<_> = self.filter.exclude_apis.clone();
        let include_apis: Vec<_> = self.filter.include_apis.clone();

        for pattern in &exclude_apis {
            if self.pattern_matches(pattern, name) {
                return false;
            }
        }
        if include_apis.is_empty() {
            return true;
        }
        for pattern in &include_apis {
            if self.pattern_matches(pattern, name) {
                return true;
            }
        }
        false
    }

    fn matches_module(&mut self, module: &str) -> bool {
        let exclude_modules: Vec<_> = self.filter.exclude_modules.clone();
        let include_modules: Vec<_> = self.filter.include_modules.clone();

        for pattern in &exclude_modules {
            if self.pattern_matches(pattern, module) {
                return false;
            }
        }
        if include_modules.is_empty() {
            return true;
        }
        for pattern in &include_modules {
            if self.pattern_matches(pattern, module) {
                return true;
            }
        }
        false
    }

    fn matches_thread(&self, tid: u32, filter: &ghost_common::types::ThreadFilter) -> bool {
        match filter {
            ghost_common::types::ThreadFilter::Include(tids) => tids.contains(&tid),
            ghost_common::types::ThreadFilter::Exclude(tids) => !tids.contains(&tid),
        }
    }

    fn matches_return_value(&self, value: &CapturedValue, comparison: &ValueComparison) -> bool {
        let int_val = match value {
            CapturedValue::Int(v) => *v,
            CapturedValue::UInt(v) => *v as i64,
            CapturedValue::Handle(v) => *v as i64,
            CapturedValue::Bool(v) => *v as i64,
            _ => return true,
        };
        self.compare_value(int_val, comparison)
    }

    fn compare_value(&self, value: i64, comparison: &ValueComparison) -> bool {
        match comparison {
            ValueComparison::Equal(v) => value == *v,
            ValueComparison::NotEqual(v) => value != *v,
            ValueComparison::LessThan(v) => value < *v,
            ValueComparison::LessOrEqual(v) => value <= *v,
            ValueComparison::GreaterThan(v) => value > *v,
            ValueComparison::GreaterOrEqual(v) => value >= *v,
            ValueComparison::Between(lo, hi) => value >= *lo && value <= *hi,
            ValueComparison::HasBits(bits) => (value as u64 & bits) == *bits,
            ValueComparison::InSet(set) => set.contains(&value),
        }
    }

    fn pattern_matches(&mut self, pattern: &StringPattern, text: &str) -> bool {
        match pattern {
            StringPattern::Exact(s) => text.eq_ignore_ascii_case(s),
            StringPattern::Prefix(s) => text.to_lowercase().starts_with(&s.to_lowercase()),
            StringPattern::Suffix(s) => text.to_lowercase().ends_with(&s.to_lowercase()),
            StringPattern::Contains(s) => text.to_lowercase().contains(&s.to_lowercase()),
            StringPattern::Wildcard(pattern) => self.wildcard_matches(pattern, text),
            StringPattern::Regex(pattern) => {
                if let Some(re) = self.regex_cache.get(pattern) {
                    re.is_match(text)
                } else if let Ok(re) = regex::Regex::new(pattern) {
                    let matches = re.is_match(text);
                    self.regex_cache.insert(pattern.clone(), re);
                    matches
                } else {
                    false
                }
            }
        }
    }

    fn wildcard_matches(&self, pattern: &str, text: &str) -> bool {
        let regex_pattern = pattern
            .replace('.', r"\.")
            .replace('*', ".*")
            .replace('?', ".");
        if let Ok(re) = regex::Regex::new(&format!("(?i)^{}$", regex_pattern)) {
            re.is_match(text)
        } else {
            false
        }
    }
}

/// A single trace session
pub struct TraceSession {
    id: TraceSessionId,
    name: String,
    state: TraceSessionState,
    config: TraceSessionConfig,
    buffer: EventRingBuffer,
    filter_matcher: FilterMatcher,
    stats: TraceStats,
    hooks: HashMap<String, ApiHookStatus>,
    created_at: u64,
    started_at: Option<u64>,
    sequence_counter: AtomicU64,
    start_instant: Option<Instant>,
}

impl TraceSession {
    pub fn new(id: TraceSessionId, config: TraceSessionConfig) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id,
            name: config.name.clone(),
            state: TraceSessionState::Idle,
            filter_matcher: FilterMatcher::new(config.filter.clone()),
            buffer: EventRingBuffer::new(config.buffer.clone()),
            config,
            stats: TraceStats::default(),
            hooks: HashMap::new(),
            created_at: now,
            started_at: None,
            sequence_counter: AtomicU64::new(0),
            start_instant: None,
        }
    }

    pub fn id(&self) -> TraceSessionId {
        self.id
    }

    pub fn state(&self) -> TraceSessionState {
        self.state
    }

    pub fn info(&self) -> TraceSessionInfo {
        TraceSessionInfo {
            id: self.id,
            name: self.name.clone(),
            state: self.state,
            created_at: self.created_at,
            started_at: self.started_at,
            stats: self.buffer.stats().clone(),
            hooks_installed: self.hooks.len(),
            filter_preset: None,
        }
    }

    pub fn start(&mut self) -> Result<TraceStartResult> {
        if self.state == TraceSessionState::Active {
            return Err(Error::Internal("Session already active".to_string()));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.state = TraceSessionState::Active;
        self.started_at = Some(now);
        self.start_instant = Some(Instant::now());

        info!("Started trace session: {} ({})", self.name, self.id.0);

        Ok(TraceStartResult {
            session_id: self.id,
            hooks_installed: self.hooks.len(),
            failed_hooks: vec![],
            warnings: vec![],
        })
    }

    pub fn stop(&mut self) {
        self.state = TraceSessionState::Stopped;
        info!("Stopped trace session: {} ({})", self.name, self.id.0);
    }

    pub fn pause(&mut self) {
        if self.state == TraceSessionState::Active {
            self.state = TraceSessionState::Paused;
            debug!("Paused trace session: {}", self.id.0);
        }
    }

    pub fn resume(&mut self) {
        if self.state == TraceSessionState::Paused {
            self.state = TraceSessionState::Active;
            debug!("Resumed trace session: {}", self.id.0);
        }
    }

    pub fn record_event(&mut self, mut event: ApiCallEvent) -> bool {
        if self.state != TraceSessionState::Active {
            return false;
        }

        if !self.filter_matcher.matches(&event) {
            return false;
        }

        event.sequence = self.sequence_counter.fetch_add(1, Ordering::SeqCst);
        if let Some(start) = self.start_instant {
            event.timestamp_us = start.elapsed().as_micros() as u64;
        }

        self.update_stats(&event);
        self.buffer.push(event)
    }

    fn update_stats(&mut self, event: &ApiCallEvent) {
        let api_stats = self
            .stats
            .per_api
            .entry(event.function_name.clone())
            .or_default();
        api_stats.call_count += 1;
        if event.success == Some(true) {
            api_stats.success_count += 1;
        } else if event.success == Some(false) {
            api_stats.failure_count += 1;
        }
        if let Some(duration) = event.duration_us {
            let total = api_stats.avg_duration_us * (api_stats.call_count - 1) as f64;
            api_stats.avg_duration_us = (total + duration as f64) / api_stats.call_count as f64;
            api_stats.min_duration_us = api_stats.min_duration_us.min(duration);
            api_stats.max_duration_us = api_stats.max_duration_us.max(duration);
        }

        *self
            .stats
            .per_module
            .entry(event.module_name.clone())
            .or_default() += 1;
        *self.stats.per_thread.entry(event.thread_id).or_default() += 1;
    }

    pub fn get_events(&mut self, count: usize, offset: usize) -> TraceEventsResult {
        let total = self.buffer.len() as u64;
        let events: Vec<ApiCallEvent> = self
            .buffer
            .peek(count, offset)
            .into_iter()
            .cloned()
            .collect();
        let has_more = offset + events.len() < total as usize;

        TraceEventsResult {
            events,
            total_count: total,
            has_more,
            continuation: if has_more {
                Some(format!("{}", offset + count))
            } else {
                None
            },
        }
    }

    pub fn drain_events(&mut self, count: usize) -> Vec<ApiCallEvent> {
        self.buffer.drain(count)
    }

    pub fn clear_events(&mut self) {
        self.buffer.clear();
    }

    pub fn stats(&self) -> &TraceStats {
        &self.stats
    }

    pub fn queue_stats(&self) -> &QueueStats {
        self.buffer.stats()
    }

    pub fn update_filter(&mut self, filter: TraceFilter) {
        self.config.filter = filter.clone();
        self.filter_matcher = FilterMatcher::new(filter);
    }

    pub fn add_hook(&mut self, status: ApiHookStatus) {
        self.hooks.insert(status.function_name.clone(), status);
    }

    pub fn get_hooks(&self) -> Vec<&ApiHookStatus> {
        self.hooks.values().collect()
    }
}

/// Main API Tracer - manages sessions, packs, and filter presets
pub struct ApiTracer {
    sessions: HashMap<TraceSessionId, TraceSession>,
    pack_manager: ApiPackManager,
    filter_presets: HashMap<FilterPresetId, FilterPreset>,
    next_session_id: u32,
    next_preset_id: u32,
    /// Hook engine for API interception (optional, lazy-initialized)
    hook_engine: Option<crate::api_trace_hooks::ApiTraceHookEngine>,
    /// Default trace method for new traces
    default_trace_method: crate::api_trace_hooks::TraceMethod,
}

impl ApiTracer {
    pub fn new() -> Self {
        let mut tracer = Self {
            sessions: HashMap::new(),
            pack_manager: ApiPackManager::new(),
            filter_presets: HashMap::new(),
            next_session_id: 1,
            next_preset_id: 1,
            hook_engine: None,
            default_trace_method: crate::api_trace_hooks::TraceMethod::default(),
        };
        if let Err(e) = tracer.pack_manager.load_builtin_packs() {
            tracing::warn!("Failed to load built-in API packs: {}", e);
        }
        tracer.load_builtin_presets();
        tracer
    }

    /// Create tracer with a specific default trace method
    pub fn with_trace_method(method: crate::api_trace_hooks::TraceMethod) -> Self {
        let mut tracer = Self::new();
        tracer.default_trace_method = method;
        tracer
    }

    /// Initialize the hook engine (lazy initialization)
    pub fn init_hook_engine(&mut self) -> Result<()> {
        if self.hook_engine.is_some() {
            return Ok(());
        }
        let mut engine =
            crate::api_trace_hooks::ApiTraceHookEngine::with_method(self.default_trace_method);
        engine.initialize()?;
        self.hook_engine = Some(engine);
        info!("Initialized API trace hook engine");
        Ok(())
    }

    /// Set the default trace method
    pub fn set_trace_method(&mut self, method: crate::api_trace_hooks::TraceMethod) {
        self.default_trace_method = method;
        if let Some(ref mut engine) = self.hook_engine {
            engine.set_default_method(method);
        }
    }

    /// Get the default trace method
    pub fn trace_method(&self) -> crate::api_trace_hooks::TraceMethod {
        self.default_trace_method
    }

    /// Install a trace on an API function for a session
    pub fn install_trace(
        &mut self,
        session_id: TraceSessionId,
        module_name: &str,
        function_name: &str,
        method: Option<crate::api_trace_hooks::TraceMethod>,
    ) -> Result<crate::api_trace_hooks::TracePointInfo> {
        // Ensure hook engine is initialized
        self.init_hook_engine()?;

        let engine = self
            .hook_engine
            .as_ref()
            .ok_or_else(|| Error::Internal("Hook engine not initialized".into()))?;

        let trace_info = engine.install_trace(session_id, module_name, function_name, method)?;

        // Record in session
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.add_hook(ApiHookStatus {
                function_name: function_name.to_string(),
                module: module_name.to_string(),
                active: trace_info.active,
                hook_address: Some(trace_info.target_address),
                original_address: None,
                call_count: 0,
                error: None,
            });
        }

        Ok(trace_info)
    }

    /// Remove a trace by ID
    pub fn remove_trace(
        &mut self,
        trace_id: u64,
        method: crate::api_trace_hooks::TraceMethod,
    ) -> Result<()> {
        if let Some(ref engine) = self.hook_engine {
            engine.remove_trace(trace_id, method)?;
        }
        Ok(())
    }

    /// Remove all traces for a session
    pub fn remove_session_traces(&mut self, session_id: TraceSessionId) -> Result<()> {
        if let Some(ref engine) = self.hook_engine {
            engine.remove_session_traces(session_id)?;
        }
        Ok(())
    }

    /// Get all trace points for a session
    pub fn get_session_trace_points(
        &self,
        session_id: TraceSessionId,
    ) -> Vec<crate::api_trace_hooks::TracePointInfo> {
        if let Some(ref engine) = self.hook_engine {
            engine.get_session_traces(session_id)
        } else {
            Vec::new()
        }
    }

    /// Enable/disable tracing globally
    pub fn set_tracing_enabled(&self, enabled: bool) {
        if let Some(ref engine) = self.hook_engine {
            engine.set_tracing_enabled(enabled);
        }
    }

    /// Check if tracing is enabled
    pub fn is_tracing_enabled(&self) -> bool {
        if let Some(ref engine) = self.hook_engine {
            engine.is_tracing_enabled()
        } else {
            false
        }
    }

    fn load_builtin_presets(&mut self) {
        let file_ops = FilterPreset {
            id: FilterPresetId(self.next_preset_id),
            name: "File Operations".to_string(),
            description: Some("Trace file I/O operations".to_string()),
            filter: TraceFilter {
                include_apis: vec![
                    StringPattern::Prefix("Create".to_string()),
                    StringPattern::Prefix("Read".to_string()),
                    StringPattern::Prefix("Write".to_string()),
                    StringPattern::Prefix("Close".to_string()),
                    StringPattern::Prefix("Delete".to_string()),
                ],
                include_modules: vec![StringPattern::Exact("kernel32.dll".to_string())],
                ..Default::default()
            },
            builtin: true,
        };
        self.filter_presets.insert(file_ops.id, file_ops);
        self.next_preset_id += 1;

        let network_ops = FilterPreset {
            id: FilterPresetId(self.next_preset_id),
            name: "Network Operations".to_string(),
            description: Some("Trace network/socket operations".to_string()),
            filter: TraceFilter {
                include_modules: vec![StringPattern::Exact("ws2_32.dll".to_string())],
                ..Default::default()
            },
            builtin: true,
        };
        self.filter_presets.insert(network_ops.id, network_ops);
        self.next_preset_id += 1;

        let registry_ops = FilterPreset {
            id: FilterPresetId(self.next_preset_id),
            name: "Registry Operations".to_string(),
            description: Some("Trace registry operations".to_string()),
            filter: TraceFilter {
                include_apis: vec![StringPattern::Prefix("Reg".to_string())],
                include_modules: vec![StringPattern::Exact("advapi32.dll".to_string())],
                ..Default::default()
            },
            builtin: true,
        };
        self.filter_presets.insert(registry_ops.id, registry_ops);
        self.next_preset_id += 1;

        let errors_only = FilterPreset {
            id: FilterPresetId(self.next_preset_id),
            name: "Errors Only".to_string(),
            description: Some("Only capture failed API calls".to_string()),
            filter: TraceFilter {
                failed_only: true,
                ..Default::default()
            },
            builtin: true,
        };
        self.filter_presets.insert(errors_only.id, errors_only);
        self.next_preset_id += 1;
    }

    pub fn create_session(&mut self, config: TraceSessionConfig) -> TraceSessionId {
        let id = TraceSessionId(self.next_session_id);
        self.next_session_id += 1;
        let session = TraceSession::new(id, config);
        info!("Created trace session: {}", id.0);
        self.sessions.insert(id, session);
        id
    }

    pub fn get_session(&self, id: TraceSessionId) -> Option<&TraceSession> {
        self.sessions.get(&id)
    }

    pub fn get_session_mut(&mut self, id: TraceSessionId) -> Option<&mut TraceSession> {
        self.sessions.get_mut(&id)
    }

    pub fn close_session(&mut self, id: TraceSessionId) -> Result<()> {
        self.sessions
            .remove(&id)
            .ok_or_else(|| Error::Internal(format!("Session not found: {}", id.0)))?;
        info!("Closed trace session: {}", id.0);
        Ok(())
    }

    pub fn list_sessions(&self) -> Vec<TraceSessionInfo> {
        self.sessions.values().map(|s| s.info()).collect()
    }

    pub fn start_session(&mut self, id: TraceSessionId) -> Result<TraceStartResult> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| Error::Internal(format!("Session not found: {}", id.0)))?;
        session.start()
    }

    pub fn stop_session(&mut self, id: TraceSessionId) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| Error::Internal(format!("Session not found: {}", id.0)))?;
        session.stop();
        Ok(())
    }

    pub fn pause_session(&mut self, id: TraceSessionId) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| Error::Internal(format!("Session not found: {}", id.0)))?;
        session.pause();
        Ok(())
    }

    pub fn resume_session(&mut self, id: TraceSessionId) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| Error::Internal(format!("Session not found: {}", id.0)))?;
        session.resume();
        Ok(())
    }

    pub fn pack_manager(&self) -> &ApiPackManager {
        &self.pack_manager
    }

    pub fn pack_manager_mut(&mut self) -> &mut ApiPackManager {
        &mut self.pack_manager
    }

    pub fn list_packs(&self) -> Vec<ApiPackInfo> {
        self.pack_manager.list_packs()
    }

    pub fn list_presets(&self) -> Vec<&FilterPreset> {
        self.filter_presets.values().collect()
    }

    pub fn get_preset(&self, id: FilterPresetId) -> Option<&FilterPreset> {
        self.filter_presets.get(&id)
    }

    pub fn create_preset(
        &mut self,
        name: String,
        description: Option<String>,
        filter: TraceFilter,
    ) -> FilterPresetId {
        let id = FilterPresetId(self.next_preset_id);
        self.next_preset_id += 1;
        let preset = FilterPreset {
            id,
            name,
            description,
            filter,
            builtin: false,
        };
        self.filter_presets.insert(id, preset);
        id
    }

    pub fn delete_preset(&mut self, id: FilterPresetId) -> Result<()> {
        if let Some(preset) = self.filter_presets.get(&id) {
            if preset.builtin {
                return Err(Error::Internal("Cannot delete built-in preset".to_string()));
            }
        }
        self.filter_presets
            .remove(&id)
            .ok_or_else(|| Error::Internal(format!("Preset not found: {}", id.0)))?;
        Ok(())
    }

    pub fn apply_preset(
        &mut self,
        session_id: TraceSessionId,
        preset_id: FilterPresetId,
    ) -> Result<()> {
        let preset = self
            .filter_presets
            .get(&preset_id)
            .ok_or_else(|| Error::Internal(format!("Preset not found: {}", preset_id.0)))?
            .clone();

        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| Error::Internal(format!("Session not found: {}", session_id.0)))?;

        session.update_filter(preset.filter);
        Ok(())
    }

    pub fn get_stats(&self, session_id: TraceSessionId) -> Result<TraceStats> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| Error::Internal(format!("Session not found: {}", session_id.0)))?;
        Ok(session.stats().clone())
    }
}

impl Default for ApiTracer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::ApiEventId;

    #[test]
    fn test_ring_buffer_push_and_drain() {
        let config = RingBufferConfig {
            max_events: 5,
            ..Default::default()
        };
        let mut buffer = EventRingBuffer::new(config);

        for i in 0..3 {
            let event = create_test_event(i);
            assert!(buffer.push(event));
        }

        assert_eq!(buffer.len(), 3);
        let drained = buffer.drain(2);
        assert_eq!(drained.len(), 2);
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn test_ring_buffer_overflow_drop_oldest() {
        let config = RingBufferConfig {
            max_events: 3,
            backpressure: BackpressureStrategy::DropOldest,
            ..Default::default()
        };
        let mut buffer = EventRingBuffer::new(config);

        for i in 0..5 {
            buffer.push(create_test_event(i));
        }

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.stats().total_dropped, 2);
    }

    #[test]
    fn test_filter_matcher_api_name() {
        let filter = TraceFilter {
            include_apis: vec![StringPattern::Prefix("Create".to_string())],
            ..Default::default()
        };
        let mut matcher = FilterMatcher::new(filter);

        let event = create_test_event_named("CreateFileW", "kernel32.dll");
        assert!(matcher.matches(&event));

        let event = create_test_event_named("ReadFile", "kernel32.dll");
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_filter_matcher_module() {
        let filter = TraceFilter {
            include_modules: vec![StringPattern::Exact("kernel32.dll".to_string())],
            ..Default::default()
        };
        let mut matcher = FilterMatcher::new(filter);

        let event = create_test_event_named("CreateFileW", "kernel32.dll");
        assert!(matcher.matches(&event));

        let event = create_test_event_named("NtCreateFile", "ntdll.dll");
        assert!(!matcher.matches(&event));
    }

    #[test]
    fn test_trace_session_lifecycle() {
        let config = TraceSessionConfig::default();
        let mut session = TraceSession::new(TraceSessionId(1), config);

        assert_eq!(session.state(), TraceSessionState::Idle);
        session.start().unwrap();
        assert_eq!(session.state(), TraceSessionState::Active);
        session.pause();
        assert_eq!(session.state(), TraceSessionState::Paused);
        session.resume();
        assert_eq!(session.state(), TraceSessionState::Active);
        session.stop();
        assert_eq!(session.state(), TraceSessionState::Stopped);
    }

    #[test]
    fn test_api_tracer_session_management() {
        let mut tracer = ApiTracer::new();

        let config = TraceSessionConfig::default();
        let id = tracer.create_session(config);

        assert!(tracer.get_session(id).is_some());
        assert_eq!(tracer.list_sessions().len(), 1);

        tracer.close_session(id).unwrap();
        assert!(tracer.get_session(id).is_none());
    }

    #[test]
    fn test_api_pack_manager_new() {
        let manager = ApiPackManager::new();
        assert_eq!(manager.pack_count(), 0);
    }

    #[test]
    fn test_api_pack_manager_custom_pack() {
        let mut manager = ApiPackManager::new();

        let pack = ApiPack {
            id: ApiPackId("test_pack".to_string()),
            name: "Test Pack".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Test description".to_string()),
            module: "test.dll".to_string(),
            functions: vec![],
            structs: vec![],
            enums: vec![],
        };

        assert!(manager.load_custom_pack(pack).is_ok());
        assert_eq!(manager.pack_count(), 1);

        let loaded = manager.get_pack(&ApiPackId("test_pack".to_string()));
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "Test Pack");
    }

    fn create_test_event(seq: u64) -> ApiCallEvent {
        ApiCallEvent {
            id: ApiEventId(seq),
            sequence: seq,
            thread_id: 1234,
            timestamp_us: seq * 1000,
            function_name: format!("TestFunc{}", seq),
            module_name: "test.dll".to_string(),
            args_before: vec![],
            args_after: None,
            return_value: Some(CapturedValue::Int(0)),
            duration_us: Some(100),
            call_stack: None,
            success: Some(true),
            error_code: None,
            error_message: None,
        }
    }

    fn create_test_event_named(name: &str, module: &str) -> ApiCallEvent {
        ApiCallEvent {
            id: ApiEventId(1),
            sequence: 1,
            thread_id: 1234,
            timestamp_us: 1000,
            function_name: name.to_string(),
            module_name: module.to_string(),
            args_before: vec![],
            args_after: None,
            return_value: Some(CapturedValue::Int(0)),
            duration_us: Some(100),
            call_stack: None,
            success: Some(true),
            error_code: None,
            error_message: None,
        }
    }
}
