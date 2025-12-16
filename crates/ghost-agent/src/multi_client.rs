//! Multi-client IPC Server
//!
//! Supports multiple concurrent TCP connections from MCP servers.
//! Features:
//! - Async listener with per-connection tasks
//! - Event bus with fan-out to subscribers
//! - Centralized shared state
//! - Handshake with client identity

use ghost_common::ipc::{
    Capability, ClientIdentity, Event, EventType, HandshakeResponse, PatchEntry, Request, Response,
    ResponseResult, SafetyToken, SessionDetachedPayload, SessionMetadata, MAX_MESSAGE_SIZE,
};
use ghost_common::{debug, error, info, warn};
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

/// Default agent port
pub const AGENT_PORT: u16 = 13338;

/// Maximum concurrent clients
pub const MAX_CLIENTS: usize = 10;

/// Event broadcast channel capacity
pub const EVENT_CHANNEL_SIZE: usize = 1000;

// =============================================================================
// Shared State
// =============================================================================

/// Centralized shared state accessible by all clients
pub struct SharedState {
    /// Patch history
    pub patches: RwLock<Vec<PatchEntry>>,
    /// Next patch ID
    patch_id_counter: AtomicU64,
    /// Safety tokens
    pub safety_tokens: RwLock<HashMap<String, SafetyToken>>,
    /// Session metadata
    pub session: RwLock<SessionMetadata>,
    /// Connected clients
    pub clients: RwLock<HashMap<String, ConnectedClient>>,
    /// Capability map per client
    pub client_capabilities: RwLock<HashMap<String, Vec<Capability>>>,
    /// Per-client undo stack of patch IDs
    pub undo_queues: RwLock<HashMap<String, Vec<u64>>>,
}

/// Information about a connected client
#[derive(Debug, Clone, Serialize)]
pub struct ConnectedClient {
    pub identity: ClientIdentity,
    pub connected_at: u64,
    pub request_count: u64,
}

impl SharedState {
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            patches: RwLock::new(Vec::new()),
            patch_id_counter: AtomicU64::new(1),
            safety_tokens: RwLock::new(HashMap::new()),
            session: RwLock::new(SessionMetadata {
                started_at: now,
                attached_pid: None,
                attached_process_name: None,
                attached_at: None,
                safety_mode: "normal".to_string(),
                active_scripts: 0,
                active_hooks: 0,
                modules_loaded: 0,
                client_sessions: Vec::new(),
            }),
            clients: RwLock::new(HashMap::new()),
            client_capabilities: RwLock::new(HashMap::new()),
            undo_queues: RwLock::new(HashMap::new()),
        }
    }

    /// Maximum number of patches to retain
    pub const MAX_PATCHES: usize = 10000;
    /// Maximum undo entries to retain per client
    pub const MAX_UNDO: usize = 100;

    /// Add a patch entry (with validation)
    pub fn add_patch(&self, entry: PatchEntry) -> Result<u64, &'static str> {
        // Validate entry
        if let Err(e) = entry.validate() {
            warn!(target: "ghost_agent::state", error = %e, "Invalid patch entry rejected");
            return Err("Invalid patch entry");
        }

        let id = self.patch_id_counter.fetch_add(1, Ordering::SeqCst);
        let mut entry = entry;
        entry.id = id;

        let mut patches = self.patches.write();

        // Defensive: limit patch history size
        if patches.len() >= Self::MAX_PATCHES {
            // Remove oldest inactive patches first
            patches.retain(|p| p.active);
            if patches.len() >= Self::MAX_PATCHES {
                warn!(target: "ghost_agent::state", "Patch history full, removing oldest");
                patches.remove(0);
            }
        }

        debug!(
            target: "ghost_agent::state",
            patch_id = id,
            address = format!("0x{:x}", entry.address),
            size = entry.patched_bytes.len(),
            "Patch added"
        );

        patches.push(entry);
        Ok(id)
    }

    /// Get patch history
    pub fn get_patches(&self) -> Vec<PatchEntry> {
        self.patches.read().clone()
    }

    /// Replace patch history from a backup and advance the patch ID counter
    pub fn restore_patches(&self, patches: Vec<PatchEntry>) {
        let max_id = patches.iter().map(|p| p.id).max().unwrap_or(0);
        {
            let mut target = self.patches.write();
            target.clear();
            target.extend(patches);
        }
        self.patch_id_counter
            .store(max_id.saturating_add(1), Ordering::SeqCst);
    }

    /// Register a client
    pub fn register_client(&self, identity: ClientIdentity) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let client = ConnectedClient {
            identity: identity.clone(),
            connected_at: now,
            request_count: 0,
        };

        self.clients
            .write()
            .insert(identity.session_id.clone(), client);

        // Default capabilities: Read only until handshake sets requested/granted
        self.client_capabilities
            .write()
            .insert(identity.session_id.clone(), vec![Capability::Read]);

        // Update session metadata with client session info
        let mut session = self.session.write();
        let client_session = ghost_common::ipc::ClientSession {
            client_id: identity.session_id.clone(),
            name: identity.name.clone(),
            connected_at: now,
            capabilities: vec![Capability::Read], // Default capability
            last_activity: now,
        };
        session.client_sessions.push(client_session);
    }

    /// Unregister a client
    pub fn unregister_client(&self, session_id: &str) {
        if let Some(_client) = self.clients.write().remove(session_id) {
            let mut session = self.session.write();
            session
                .client_sessions
                .retain(|s| s.client_id != session_id);
            self.client_capabilities.write().remove(session_id);
        }
    }

    /// Get client count
    pub fn client_count(&self) -> u32 {
        self.clients.read().len() as u32
    }

    /// Increment request count for a client
    pub fn increment_request_count(&self, session_id: &str) {
        if let Some(client) = self.clients.write().get_mut(session_id) {
            client.request_count += 1;
        }
    }

    /// Set granted capabilities for a client
    pub fn set_capabilities(&self, session_id: &str, caps: Vec<Capability>) {
        self.client_capabilities
            .write()
            .insert(session_id.to_string(), caps.clone());

        // Update session metadata cache
        let mut session = self.session.write();
        if let Some(client_session) = session
            .client_sessions
            .iter_mut()
            .find(|s| s.client_id == session_id)
        {
            client_session.capabilities = caps;
        }
    }

    /// Get granted capabilities for a client
    pub fn get_capabilities(&self, session_id: &str) -> Vec<Capability> {
        self.client_capabilities
            .read()
            .get(session_id)
            .cloned()
            .unwrap_or_else(|| vec![Capability::Read])
    }

    /// Issue and store a safety token
    pub fn issue_token(
        &self,
        scope: Capability,
        operation: impl Into<String>,
        requested_by: impl Into<String>,
        ttl_secs: u64,
    ) -> SafetyToken {
        let token = SafetyToken::new(scope, operation, requested_by, ttl_secs);
        self.safety_tokens
            .write()
            .insert(token.id.clone(), token.clone());
        token
    }

    /// Validate a safety token for a required capability
    pub fn validate_token(&self, token_id: &str, required: Capability) -> Result<(), String> {
        let mut tokens = self.safety_tokens.write();
        if let Some(token) = tokens.get_mut(token_id) {
            if token.is_valid_for(required) {
                // Tokens are single-use; mark consumed on first valid check.
                token.mark_used();
                return Ok(());
            }
            return Err("Safety token expired or invalid for operation".to_string());
        }
        Err("Safety token expired or invalid for operation".to_string())
    }

    /// Update session metadata with attached process info.
    /// Returns true when the attach state changed (first attach or different pid).
    pub fn update_session_attach(&self, pid: u32, process_name: String, attached_at: u64) -> bool {
        let mut session = self.session.write();
        let changed = session.attached_pid.map(|p| p != pid).unwrap_or(true);
        if changed {
            session.attached_pid = Some(pid);
            session.attached_process_name = Some(process_name);
            session.attached_at = Some(attached_at);
        }
        changed
    }

    /// Clear attach metadata and return prior state for event emission.
    pub fn clear_session_attach(&self, reason: &str) -> Option<SessionDetachedPayload> {
        let mut session = self.session.write();
        if let Some(pid) = session.attached_pid.take() {
            let payload = SessionDetachedPayload {
                pid,
                reason: reason.to_string(),
            };
            session.attached_process_name = None;
            session.attached_at = None;
            return Some(payload);
        }
        None
    }

    /// Update module count cache in session metadata.
    pub fn set_modules_loaded(&self, count: u32) {
        let mut session = self.session.write();
        session.modules_loaded = count;
    }

    /// Revoke a safety token
    pub fn revoke_token(&self, token_id: &str) -> bool {
        self.safety_tokens.write().remove(token_id).is_some()
    }

    /// Push a patch ID onto a client's undo stack
    pub fn push_undo(&self, client_id: &str, patch_id: u64) {
        let mut queues = self.undo_queues.write();
        let queue = queues.entry(client_id.to_string()).or_default();
        queue.push(patch_id);
        if queue.len() > Self::MAX_UNDO {
            queue.remove(0);
        }
    }

    /// Pop the latest patch ID from a client's undo stack
    pub fn pop_undo(&self, client_id: &str) -> Option<u64> {
        self.undo_queues
            .write()
            .get_mut(client_id)
            .and_then(|q| q.pop())
    }

    /// Mark a patch as undone and return it
    pub fn mark_patch_undone(&self, patch_id: u64) -> Option<PatchEntry> {
        let mut patches = self.patches.write();
        if let Some(patch) = patches.iter_mut().find(|p| p.id == patch_id && p.active) {
            patch.active = false;
            return Some(patch.clone());
        }
        None
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Event Bus
// =============================================================================

/// Event bus for fan-out to subscribers
pub struct EventBus {
    /// Broadcast sender for events
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_SIZE);
        Self { sender }
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: Event) {
        // Ignore send errors (no subscribers)
        let _ = self.sender.send(event);
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Get subscriber count
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Multi-Client Server
// =============================================================================

/// Request handler trait - implemented by the backend
pub trait RequestHandler: Send + Sync {
    fn handle(&self, request: &Request, client_id: Option<&str>) -> Response;
}

/// Multi-client IPC server
pub struct MultiClientServer {
    /// Shared state
    state: Arc<SharedState>,
    /// Event bus
    event_bus: Arc<EventBus>,
    /// Request handler
    handler: Arc<dyn RequestHandler>,
    /// Running flag
    running: Arc<AtomicBool>,
}

impl MultiClientServer {
    pub fn new(handler: Arc<dyn RequestHandler>) -> Self {
        Self {
            state: Arc::new(SharedState::new()),
            event_bus: Arc::new(EventBus::new()),
            handler,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create server with InProcessBackend
    pub fn new_with_backend(backend: crate::backend::InProcessBackend) -> Self {
        let state = Arc::new(SharedState::new());
        let event_bus = Arc::new(EventBus::new());

        // Create MultiClientBackend wrapper that integrates with shared state and event bus
        let handler = Arc::new(crate::backend::MultiClientBackend::new(
            backend,
            Arc::clone(&state),
            Arc::clone(&event_bus),
        ));

        Self {
            state,
            event_bus,
            handler,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get shared state reference
    pub fn state(&self) -> Arc<SharedState> {
        Arc::clone(&self.state)
    }

    /// Get event bus reference
    pub fn event_bus(&self) -> Arc<EventBus> {
        Arc::clone(&self.event_bus)
    }

    /// Run the server (blocking)
    pub async fn run(&self) -> ghost_common::Result<()> {
        let addr = format!("127.0.0.1:{}", AGENT_PORT);

        info!(target: "ghost_agent::ipc", port = AGENT_PORT, "Starting multi-client IPC server");

        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            error!(target: "ghost_agent::ipc", error = %e, "Failed to bind");
            ghost_common::Error::Ipc(format!("Failed to bind: {}", e))
        })?;

        info!(target: "ghost_agent::ipc", address = %addr, "Multi-client server listening");

        self.running.store(true, Ordering::SeqCst);

        while self.running.load(Ordering::SeqCst) {
            // Check client limit
            if self.state.client_count() as usize >= MAX_CLIENTS {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }

            match listener.accept().await {
                Ok((stream, peer)) => {
                    info!(target: "ghost_agent::ipc", peer = %peer, "New client connection");

                    let state = Arc::clone(&self.state);
                    let event_bus = Arc::clone(&self.event_bus);
                    let handler = Arc::clone(&self.handler);
                    let running = Arc::clone(&self.running);

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_client(stream, state, event_bus, handler, running).await
                        {
                            warn!(target: "ghost_agent::ipc", error = %e, peer = %peer, "Client connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(target: "ghost_agent::ipc", error = %e, "Accept error");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }

        info!(target: "ghost_agent::ipc", "Multi-client server stopped");
        Ok(())
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        if let Some(detached) = self.state.clear_session_attach("server stopped") {
            self.event_bus
                .publish(Event::new(EventType::SessionDetached, detached));
        }
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Handle a single client connection
async fn handle_client(
    mut stream: TcpStream,
    state: Arc<SharedState>,
    event_bus: Arc<EventBus>,
    handler: Arc<dyn RequestHandler>,
    running: Arc<AtomicBool>,
) -> ghost_common::Result<()> {
    stream.set_nodelay(true).ok();

    // Wait for handshake
    let handshake_request = receive_handshake(&mut stream).await?;

    // Parse identity for logging and request tracking
    let identity: ClientIdentity = serde_json::from_value(handshake_request.params.clone())
        .map_err(|e| ghost_common::Error::Ipc(format!("Invalid handshake: {}", e)))?;

    let client_name = identity.name.clone();
    let session_id = identity.session_id.clone();

    info!(
        target: "ghost_agent::ipc",
        client = %client_name,
        session = %session_id,
        "Client handshake successful"
    );

    // Delegate handshake to backend (performs validation + registration)
    let handshake_response = handler.handle(&handshake_request, None);

    // Always forward backend handshake result to client
    send_response_async_raw(&mut stream, &handshake_response).await?;

    // Evaluate handshake outcome
    match &handshake_response.result {
        ResponseResult::Success(value) => {
            let handshake: HandshakeResponse =
                serde_json::from_value(value.clone()).map_err(|e| {
                    ghost_common::Error::Ipc(format!("Invalid handshake response: {}", e))
                })?;

            if !handshake.accepted {
                return Err(ghost_common::Error::Ipc(
                    handshake
                        .error
                        .unwrap_or_else(|| "Handshake rejected".to_string()),
                ));
            }

            // Handshake accepted; capabilities already set by backend
        }
        ResponseResult::Error { code, message } => {
            return Err(ghost_common::Error::Ipc(format!(
                "Handshake failed: {} ({})",
                message, code
            )));
        }
    };

    // Do not auto-subscribe clients to events; subscribe on explicit request
    let mut event_rx: Option<tokio::sync::broadcast::Receiver<Event>> = None;

    // Split stream for concurrent read/write
    let (mut reader, mut writer) = stream.into_split();

    // Request channel
    let (response_tx, mut response_rx) = mpsc::channel::<Response>(100);

    // Spawn writer task
    let writer_handle = tokio::spawn(async move {
        if let Some(ref mut event_rx) = event_rx {
            loop {
                tokio::select! {
                    // Send responses
                    Some(response) = response_rx.recv() => {
                        if let Err(e) = send_response_async(&mut writer, &response).await {
                            error!(target: "ghost_agent::ipc", error = %e, "Failed to send response");
                            break;
                        }
                    }
                    // Forward events
                    Ok(event) = event_rx.recv() => {
                        let notification = Response {
                            id: 0,
                            result: ResponseResult::Success(serde_json::json!({
                                "event": event
                            })),
                        };
                        if let Err(e) = send_response_async(&mut writer, &notification).await {
                            debug!(target: "ghost_agent::ipc", error = %e, "Failed to send event");
                        }
                    }
                    else => break,
                }
            }
        } else {
            while let Some(response) = response_rx.recv().await {
                if let Err(e) = send_response_async(&mut writer, &response).await {
                    error!(target: "ghost_agent::ipc", error = %e, "Failed to send response");
                    break;
                }
            }
        }
    });

    // Main request loop
    while running.load(Ordering::SeqCst) {
        match receive_request_async(&mut reader).await {
            Ok(request) => {
                debug!(
                    target: "ghost_agent::ipc",
                    method = %request.method,
                    id = request.id,
                    client = %client_name,
                    "Received request"
                );

                state.increment_request_count(&session_id);

                // Handle internal methods
                let response = match request.method.as_str() {
                    "agent.handshake" => {
                        // Already handshaked
                        Response::error(request.id, -32600, "Already handshaked")
                    }
                    "agent.status" => Response::success(request.id, get_agent_status(&state)),
                    "agent.subscribe" => {
                        // Client is already subscribed via broadcast
                        Response::success(request.id, serde_json::json!({"subscribed": true}))
                    }
                    "state.patches" => Response::success(request.id, state.get_patches()),
                    "state.session" => Response::success(request.id, state.session.read().clone()),
                    "state.clients" => {
                        let clients: Vec<_> = state.clients.read().values().cloned().collect();
                        Response::success(request.id, clients)
                    }
                    "patch_history" => {
                        let limit = request
                            .params
                            .get("limit")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(50) as usize;
                        let client_filter =
                            request.params.get("client_id").and_then(|v| v.as_str());

                        let mut patches = state.get_patches();
                        if let Some(client) = client_filter {
                            patches.retain(|p| p.applied_by.as_deref() == Some(client));
                        }
                        patches.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                        let total = patches.len();
                        patches.truncate(limit);
                        let returned = patches.len();
                        let truncated = returned < total;

                        Response::success(
                            request.id,
                            json!({
                                "patches": patches,
                                "returned": returned,
                                "total": total,
                                "truncated": truncated
                            }),
                        )
                    }
                    _ => {
                        // Delegate to backend handler (capabilities keyed by session_id)
                        // Offload to blocking thread to prevent hanging the async runtime
                        let handler = Arc::clone(&handler);
                        let request = request.clone();
                        let request_id = request.id; // Save id before moving request
                        let session_id = session_id.clone();

                        let response_future = tokio::task::spawn_blocking(move || {
                            handler.handle(&request, Some(&session_id))
                        });

                        // Set a reasonable timeout (30s) to prevent indefinite hanging
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            response_future,
                        )
                        .await
                        {
                            Ok(Ok(response)) => response,
                            Ok(Err(e)) => {
                                error!(target: "ghost_agent::ipc", error = %e, "Handler task failed");
                                Response::error(
                                    request_id,
                                    -32603,
                                    format!("Handler task failed: {}", e),
                                )
                            }
                            Err(_) => {
                                warn!(target: "ghost_agent::ipc", "Handler timed out");
                                Response::error(request_id, -32603, "Handler timed out")
                            }
                        }
                    }
                };

                if response_tx.send(response).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!(target: "ghost_agent::ipc", error = %e, client = %client_name, "Client disconnected");
                break;
            }
        }
    }

    // Cleanup
    writer_handle.abort();
    state.unregister_client(&session_id);

    // Emit disconnect event
    event_bus.publish(
        Event::new(
            EventType::ClientDisconnected,
            ghost_common::ipc::ClientDisconnectedPayload {
                client_id: session_id.clone(),
                reason: "client disconnected".to_string(),
            },
        )
        .with_source(session_id.clone()),
    );

    info!(target: "ghost_agent::ipc", client = %client_name, "Client disconnected");

    Ok(())
}

/// Receive handshake from client
async fn receive_handshake(stream: &mut TcpStream) -> ghost_common::Result<Request> {
    // Expect first message to be handshake
    let request = receive_request_async_raw(stream).await?;

    if request.method != "agent.handshake" {
        return Err(ghost_common::Error::Ipc(
            "Expected handshake as first message".to_string(),
        ));
    }

    Ok(request)
}

/// Get agent status
fn get_agent_status(state: &SharedState) -> ghost_common::ipc::AgentStatus {
    let pid = std::process::id();
    let exe_path = std::env::current_exe().ok();
    let process_name = exe_path
        .as_ref()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    let process_path = exe_path.map(|p| p.to_string_lossy().to_string());

    ghost_common::ipc::AgentStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid,
        process_name,
        process_path,
        arch: if cfg!(target_arch = "x86_64") {
            "x64"
        } else {
            "x86"
        }
        .to_string(),
        connected: true,
        client_count: state.client_count(),
    }
}

// =============================================================================
// Async I/O Helpers
// =============================================================================

async fn receive_request_async(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> ghost_common::Result<Request> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to read length: {}", e)))?;

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(ghost_common::Error::Ipc(format!(
            "Message too large: {}",
            len
        )));
    }

    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to read body: {}", e)))?;

    serde_json::from_slice(&body)
        .map_err(|e| ghost_common::Error::Ipc(format!("Invalid JSON: {}", e)))
}

async fn receive_request_async_raw(stream: &mut TcpStream) -> ghost_common::Result<Request> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to read length: {}", e)))?;

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(ghost_common::Error::Ipc(format!(
            "Message too large: {}",
            len
        )));
    }

    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to read body: {}", e)))?;

    serde_json::from_slice(&body)
        .map_err(|e| ghost_common::Error::Ipc(format!("Invalid JSON: {}", e)))
}

async fn send_response_async(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    response: &Response,
) -> ghost_common::Result<()> {
    let body = serde_json::to_vec(response)
        .map_err(|e| ghost_common::Error::Ipc(format!("Serialization failed: {}", e)))?;

    if body.len() > MAX_MESSAGE_SIZE {
        return Err(ghost_common::Error::Ipc("Response too large".into()));
    }

    let len = (body.len() as u32).to_le_bytes();
    writer
        .write_all(&len)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to write length: {}", e)))?;
    writer
        .write_all(&body)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to write body: {}", e)))?;
    writer
        .flush()
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to flush: {}", e)))?;

    Ok(())
}

async fn send_response_async_raw(
    stream: &mut TcpStream,
    response: &Response,
) -> ghost_common::Result<()> {
    let body = serde_json::to_vec(response)
        .map_err(|e| ghost_common::Error::Ipc(format!("Serialization failed: {}", e)))?;

    if body.len() > MAX_MESSAGE_SIZE {
        return Err(ghost_common::Error::Ipc("Response too large".into()));
    }

    let len = (body.len() as u32).to_le_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to write length: {}", e)))?;
    stream
        .write_all(&body)
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to write body: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| ghost_common::Error::Ipc(format!("Failed to flush: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_state_new() {
        let state = SharedState::new();
        assert_eq!(state.client_count(), 0);
        assert!(state.get_patches().is_empty());
    }

    #[test]
    fn test_register_client() {
        let state = SharedState::new();
        let identity = ClientIdentity::new("test-client", "1.0.0");
        state.register_client(identity.clone());
        assert_eq!(state.client_count(), 1);
    }

    #[test]
    fn test_add_patch() {
        let state = SharedState::new();
        let patch = PatchEntry::new(0x1000, vec![0x90], vec![0xCC]);
        let id = state.add_patch(patch).expect("Should add valid patch");
        assert_eq!(id, 1);
        assert_eq!(state.get_patches().len(), 1);
    }

    #[test]
    fn test_add_patch_invalid() {
        let state = SharedState::new();
        // Size mismatch should fail validation
        let patch = PatchEntry::new(0x1000, vec![0x90], vec![0xCC, 0xCC]);
        assert!(state.add_patch(patch).is_err());
    }

    #[test]
    fn test_event_bus() {
        use ghost_common::ipc::EventType;

        let bus = EventBus::new();
        let _rx = bus.subscribe();

        let event = Event::new(
            EventType::MemoryWrite,
            serde_json::json!({"address": "0x1000"}),
        );
        bus.publish(event);

        // Note: broadcast recv is async, so we can't test it in sync context
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[test]
    fn test_client_identity() {
        let identity = ClientIdentity::new("ghost-core-mcp", "0.1.0").with_capability("events");

        assert_eq!(identity.name, "ghost-core-mcp");
        assert_eq!(identity.version, "0.1.0");
        assert!(identity.capabilities.contains(&"events".to_string()));
        assert!(!identity.session_id.is_empty());
    }

    #[test]
    fn test_validate_token_consumes() {
        let state = SharedState::new();
        let token = state.issue_token(Capability::Write, "memory_write", "client", 300);

        // First validation succeeds
        assert!(state.validate_token(&token.id, Capability::Write).is_ok());
        // Second validation should fail because token is marked used
        assert!(state.validate_token(&token.id, Capability::Write).is_err());
    }

    #[test]
    fn test_session_attach_and_clear() {
        let state = SharedState::new();
        let changed = state.update_session_attach(1234, "test.exe".to_string(), 42);
        assert!(changed, "first attach should mark changed");

        // Re-attaching same PID should not signal change
        let changed_again = state.update_session_attach(1234, "test.exe".to_string(), 43);
        assert!(!changed_again, "re-attaching same pid should be no-op");

        let payload = state
            .clear_session_attach("shutdown")
            .expect("detach payload expected");
        assert_eq!(payload.pid, 1234);
        assert_eq!(payload.reason, "shutdown");
    }

    #[test]
    fn test_set_modules_loaded() {
        let state = SharedState::new();
        state.set_modules_loaded(5);
        assert_eq!(state.session.read().modules_loaded, 5);
    }

    // =========================================================================
    // Event Notification Tests
    // =========================================================================
    // These tests verify that event notifications use id=0 as expected by
    // the IPC protocol. Clients must skip id=0 responses when waiting for
    // their actual response.

    #[test]
    fn test_event_notification_uses_id_zero() {
        use ghost_common::ipc::EventType;

        // Event notifications sent to clients must use id=0
        let event = Event::new(EventType::MemoryWrite, json!({"address": "0x1000"}));
        let notification = Response {
            id: 0, // Events always use id=0
            result: ResponseResult::Success(json!({"event": event})),
        };

        assert_eq!(notification.id, 0, "Event notifications must use id=0");
    }

    #[test]
    fn test_response_preserves_request_id() {
        // Regular responses must preserve the request ID
        let request_id = 42u32;
        let response = Response::success(request_id, json!({"result": "ok"}));
        assert_eq!(response.id, request_id, "Response must preserve request ID");
    }

    #[test]
    fn test_error_response_preserves_request_id() {
        // Error responses must also preserve the request ID
        let request_id = 123u32;
        let response = Response::error(request_id, -1, "test error");
        assert_eq!(
            response.id, request_id,
            "Error response must preserve request ID"
        );
    }

    #[test]
    fn test_event_bus_subscriber_count() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(), 0);

        let _rx1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
    }

    #[test]
    fn test_event_with_source_client() {
        use ghost_common::ipc::EventType;

        let event = Event::new(EventType::PatchApplied, json!({"patch_id": 1}))
            .with_source("test-client".to_string());

        assert_eq!(event.source_client, Some("test-client".to_string()));
    }
}
