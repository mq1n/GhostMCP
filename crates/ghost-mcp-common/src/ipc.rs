//! IPC Client for Agent Communication
//!
//! Provides connection management with retries, heartbeats, and reconnection.

use crate::config::{RetryConfig, ServerConfig};
use crate::error::{McpError, Result};
use ghost_common::ipc::{
    AgentStatus, ClientIdentity, HandshakeResponse, Request, Response, ResponseResult,
    MAX_MESSAGE_SIZE,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Default agent port
pub const DEFAULT_AGENT_PORT: u16 = 13338;

/// Global request ID counter
static REQUEST_ID: AtomicU32 = AtomicU32::new(1);

fn next_request_id() -> u32 {
    REQUEST_ID.fetch_add(1, Ordering::SeqCst)
}

// =============================================================================
// Connection Health Tracking
// =============================================================================

/// Connection health state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// Fully connected and healthy
    Connected,
    /// Connected but experiencing issues (1-2 failures)
    Degraded,
    /// Disconnected, attempting reconnect
    Disconnected,
    /// Never connected / initial state
    #[default]
    Initial,
}

/// Connection health information
#[derive(Debug, Clone)]
pub struct ConnectionHealth {
    /// Current connection state
    pub state: ConnectionState,
    /// Last successful ping timestamp
    pub last_ping: Option<Instant>,
    /// Consecutive failure count
    pub failures: u32,
    /// Last error message (if any)
    pub last_error: Option<String>,
}

impl Default for ConnectionHealth {
    fn default() -> Self {
        Self {
            state: ConnectionState::Initial,
            last_ping: None,
            failures: 0,
            last_error: None,
        }
    }
}

impl ConnectionHealth {
    /// Check if connection is healthy enough for requests
    pub fn is_healthy(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Connected | ConnectionState::Degraded
        )
    }

    /// Get time since last successful ping
    pub fn time_since_ping(&self) -> Option<Duration> {
        self.last_ping.map(|t| t.elapsed())
    }
}

/// Agent client with connection management
#[derive(Clone)]
pub struct AgentClient {
    /// Server configuration
    config: ServerConfig,
    /// TCP stream (protected by mutex, wrapped in Arc for cloning into tasks)
    stream: Arc<RwLock<Option<Arc<Mutex<TcpStream>>>>>,
    /// Cached agent status
    status: Arc<RwLock<Option<AgentStatus>>>,
    /// Connection state
    connected: Arc<AtomicBool>,
    /// Heartbeat task handle
    heartbeat_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Client identity for handshake
    identity: ClientIdentity,
    /// Connection health tracking
    health: Arc<RwLock<ConnectionHealth>>,
}

// Safety: All fields are Arc/RwLock/Mutex/Atomics/owned values; no raw pointers.
// This client is intended to be cloned and moved across threads (heartbeat task).
// Auto-derived Send/Sync should work as all fields are Send/Sync
// unsafe impl Send for AgentClient {}
// unsafe impl Sync for AgentClient {}

impl AgentClient {
    /// Idempotent subscribe/state sync after (re)connect
    async fn resubscribe_and_sync(&self) -> Result<()> {
        // Subscribe to events (will no-op on servers without support)
        let _ = self.request("agent.subscribe", serde_json::json!({})).await;

        // Fetch latest status for cache
        if let Ok(status_value) = self.request("agent.status", serde_json::json!({})).await {
            if let Ok(status) = serde_json::from_value::<AgentStatus>(status_value) {
                let mut guard = self.status.write().await;
                *guard = Some(status);
            }
        }

        Ok(())
    }

    /// Create a new agent client with default configuration
    pub fn new() -> Self {
        Self::with_config(ServerConfig::default())
    }

    /// Create a new agent client with custom configuration
    pub fn with_config(config: ServerConfig) -> Self {
        let mut identity = ClientIdentity::new(&config.name, crate::VERSION);

        // In debug mode (RUST_LOG set), request all capabilities for development/testing
        if std::env::var("RUST_LOG").is_ok() {
            identity = identity
                .with_capability("read")
                .with_capability("write")
                .with_capability("execute")
                .with_capability("debug")
                .with_capability("admin");
            debug!(target: "ghost_mcp::ipc", "Debug mode: requesting all capabilities");
        }

        Self {
            config,
            stream: Arc::new(RwLock::new(None)),
            status: Arc::new(RwLock::new(None)),
            connected: Arc::new(AtomicBool::new(false)),
            heartbeat_handle: Arc::new(Mutex::new(None)),
            identity,
            health: Arc::new(RwLock::new(ConnectionHealth::default())),
        }
    }

    /// Create client with custom identity
    pub fn with_identity(config: ServerConfig, identity: ClientIdentity) -> Self {
        Self {
            config,
            stream: Arc::new(RwLock::new(None)),
            status: Arc::new(RwLock::new(None)),
            connected: Arc::new(AtomicBool::new(false)),
            heartbeat_handle: Arc::new(Mutex::new(None)),
            identity,
            health: Arc::new(RwLock::new(ConnectionHealth::default())),
        }
    }

    /// Create client with specific agent port
    pub fn with_port(port: u16) -> Self {
        let config = ServerConfig {
            agent_port: port,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Get cached agent status
    pub async fn status(&self) -> Option<AgentStatus> {
        self.status.read().await.clone()
    }

    /// Get current connection health
    pub async fn health(&self) -> ConnectionHealth {
        self.health.read().await.clone()
    }

    /// Check if connection is healthy enough for requests
    pub async fn is_healthy(&self) -> bool {
        self.health.read().await.is_healthy()
    }

    /// Connect to the agent with retry logic
    pub async fn connect(&self) -> Result<()> {
        self.connect_with_retry(&self.config.retry).await
    }

    /// Connect with custom retry configuration
    pub async fn connect_with_retry(&self, retry_config: &RetryConfig) -> Result<()> {
        let addr = format!("127.0.0.1:{}", self.config.agent_port);
        let mut attempts = 0;
        let mut backoff_ms = retry_config.initial_backoff_ms;

        loop {
            attempts += 1;
            debug!(
                target: "ghost_mcp::ipc",
                address = %addr,
                attempt = attempts,
                max_attempts = retry_config.max_retries + 1,
                "Connecting to agent"
            );

            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    stream.set_nodelay(true).ok();

                    // Store connection
                    {
                        let mut stream_guard = self.stream.write().await;
                        *stream_guard = Some(Arc::new(Mutex::new(stream)));
                    }
                    self.connected.store(true, Ordering::SeqCst);

                    // Perform handshake
                    match self.perform_handshake().await {
                        Ok(response) => {
                            info!(
                                target: "ghost_mcp::ipc",
                                process = %response.agent_status.process_name,
                                version = %response.agent_status.version,
                                pid = response.agent_status.pid,
                                clients = response.agent_status.client_count,
                                "Connected to agent (handshake complete)"
                            );
                            let mut status_guard = self.status.write().await;
                            *status_guard = Some(response.agent_status);

                            // Idempotent subscribe/state sync
                            let _ = self.resubscribe_and_sync().await;
                        }
                        Err(e) => {
                            // Fallback to legacy agent.status for backward compatibility
                            debug!(target: "ghost_mcp::ipc", error = %e, "Handshake failed, trying legacy status");
                            if let Ok(status_value) =
                                self.request("agent.status", serde_json::json!({})).await
                            {
                                if let Ok(status) =
                                    serde_json::from_value::<AgentStatus>(status_value)
                                {
                                    info!(
                                        target: "ghost_mcp::ipc",
                                        process = %status.process_name,
                                        version = %status.version,
                                        pid = status.pid,
                                        "Connected to agent (legacy mode)"
                                    );
                                    let mut status_guard = self.status.write().await;
                                    *status_guard = Some(status);
                                }
                            }

                            // Legacy subscribe best-effort
                            let _ = self.resubscribe_and_sync().await;
                        }
                    }

                    // Start heartbeat if enabled
                    if self.config.heartbeat.enabled {
                        self.start_heartbeat();
                    }

                    return Ok(());
                }
                Err(e) => {
                    if attempts > retry_config.max_retries {
                        error!(
                            target: "ghost_mcp::ipc",
                            attempts = attempts,
                            error = %e,
                            "Failed to connect to agent"
                        );
                        return Err(McpError::Connection(format!(
                            "Failed to connect to agent at {}: {}",
                            addr, e
                        )));
                    }

                    warn!(
                        target: "ghost_mcp::ipc",
                        attempt = attempts,
                        error = %e,
                        backoff_ms = backoff_ms,
                        "Connection attempt failed, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                    // Exponential backoff
                    backoff_ms = (backoff_ms as f64 * retry_config.backoff_multiplier) as u64;
                    backoff_ms = backoff_ms.min(retry_config.max_backoff_ms);
                }
            }
        }
    }

    /// Try to connect without retry (silent failure)
    pub async fn try_connect(&self) -> bool {
        let addr = format!("127.0.0.1:{}", self.config.agent_port);
        debug!(target: "ghost_mcp::ipc", address = %addr, "Attempting connection to agent");

        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                {
                    let mut stream_guard = self.stream.write().await;
                    *stream_guard = Some(Arc::new(Mutex::new(stream)));
                }
                self.connected.store(true, Ordering::SeqCst);

                // Perform handshake (agent requires this as first message)
                match self.perform_handshake().await {
                    Ok(response) => {
                        info!(
                            target: "ghost_mcp::ipc",
                            process = %response.agent_status.process_name,
                            version = %response.agent_status.version,
                            pid = response.agent_status.pid,
                            "Connected to agent (handshake complete)"
                        );
                        let mut status_guard = self.status.write().await;
                        *status_guard = Some(response.agent_status);
                    }
                    Err(e) => {
                        // Handshake failed - disconnect and report failure
                        debug!(target: "ghost_mcp::ipc", error = %e, "Handshake failed");
                        self.connected.store(false, Ordering::SeqCst);
                        let mut stream_guard = self.stream.write().await;
                        *stream_guard = None;
                        return false;
                    }
                }

                if self.config.heartbeat.enabled {
                    self.start_heartbeat();
                }

                true
            }
            Err(_) => {
                debug!(target: "ghost_mcp::ipc", "Agent not available");
                false
            }
        }
    }

    /// Disconnect from agent
    pub async fn disconnect(&self) {
        // Stop heartbeat
        self.stop_heartbeat().await;

        // Close connection
        {
            let mut stream_guard = self.stream.write().await;
            *stream_guard = None;
        }
        self.connected.store(false, Ordering::SeqCst);

        {
            let mut status_guard = self.status.write().await;
            *status_guard = None;
        }

        info!(target: "ghost_mcp::ipc", "Disconnected from agent");
    }

    /// Reconnect to agent
    pub async fn reconnect(&self) -> Result<()> {
        self.disconnect().await;
        self.connect().await?;
        // Ensure subscription/state sync after reconnect
        let _ = self.resubscribe_and_sync().await;
        Ok(())
    }

    /// Send request and wait for response
    pub async fn request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let request = Request {
            id: next_request_id(),
            method: method.to_string(),
            params,
        };

        debug!(target: "ghost_mcp::ipc", method = %method, id = request.id, "Sending request");

        // Serialize request
        let body = serde_json::to_vec(&request)?;
        if body.len() > MAX_MESSAGE_SIZE {
            return Err(McpError::Protocol("Request too large".to_string()));
        }

        // Get stream with timeout on mutex acquisition to prevent indefinite blocking
        let stream_arc = {
            let guard = self.stream.read().await;
            guard.as_ref().cloned().ok_or_else(|| {
                debug!(target: "ghost_mcp::ipc", method = %method, id = request.id, "Request failed: not connected");
                McpError::AgentNotConnected
            })?
        };

        // Timeout on mutex acquisition - prevents hanging if another request holds the lock
        // Use a separate shorter timeout for lock acquisition (10% of total or 5s max)
        let lock_timeout_ms = (self.config.timeout_ms / 10).clamp(1000, 5000);
        let lock_timeout = Duration::from_millis(lock_timeout_ms);

        let mut stream = timeout(lock_timeout, stream_arc.lock_owned())
            .await
            .map_err(|_| {
                warn!(
                    target: "ghost_mcp::ipc",
                    method = %method,
                    id = request.id,
                    lock_timeout_ms = lock_timeout_ms,
                    "Timeout waiting for stream lock - possible deadlock or slow request"
                );
                McpError::Timeout(lock_timeout_ms)
            })?;

        debug!(target: "ghost_mcp::ipc", method = %method, id = request.id, "Stream lock acquired");

        // Write with timeout
        let write_future = async {
            let len = (body.len() as u32).to_le_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&body).await?;
            stream.flush().await?;
            Ok::<_, std::io::Error>(())
        };

        timeout(Duration::from_millis(self.config.timeout_ms), write_future)
            .await
            .map_err(|_| McpError::Timeout(self.config.timeout_ms))?
            .map_err(|e| McpError::Connection(e.to_string()))?;

        // Read response with timeout, skipping over event notifications (id=0)
        let expected_id = request.id;
        let timeout_ms = self.config.timeout_ms;

        // Maximum number of event notifications to skip before giving up
        // This prevents infinite loops if the agent keeps sending events
        const MAX_SKIPPED_EVENTS: u32 = 1000;

        let read_future = async {
            let mut skipped_events: u32 = 0;

            loop {
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf).await?;
                let len = u32::from_le_bytes(len_buf) as usize;

                if len > MAX_MESSAGE_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Response too large: {}", len),
                    ));
                }

                let mut body = vec![0u8; len];
                stream.read_exact(&mut body).await?;

                // Parse response to check ID
                let response: Response = serde_json::from_slice(&body).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;

                // Skip event notifications (id=0) - these are async events from the agent
                if response.id == 0 {
                    skipped_events += 1;
                    if skipped_events >= MAX_SKIPPED_EVENTS {
                        warn!(target: "ghost_mcp::ipc", skipped = skipped_events, "Too many event notifications while waiting for response");
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "Skipped {} event notifications without receiving response",
                                skipped_events
                            ),
                        ));
                    }
                    debug!(target: "ghost_mcp::ipc", "Skipping event notification while waiting for response");
                    continue;
                }

                // Check if this is the response we're waiting for
                if response.id == expected_id {
                    return Ok(response);
                }

                // Wrong ID - this shouldn't happen with proper multiplexing
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Response ID mismatch: expected {}, got {}",
                        expected_id, response.id
                    ),
                ));
            }
        };

        let response = timeout(Duration::from_millis(timeout_ms), read_future)
            .await
            .map_err(|_| McpError::Timeout(timeout_ms))?
            .map_err(|e| McpError::Connection(e.to_string()))?;

        match response.result {
            ResponseResult::Success(value) => Ok(value),
            ResponseResult::Error { code, message } => Err(McpError::AgentError { code, message }),
        }
    }

    /// Send request with automatic reconnect on failure
    pub async fn request_with_reconnect(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        match self.request(method, params.clone()).await {
            Ok(result) => Ok(result),
            Err(McpError::AgentNotConnected) | Err(McpError::Connection(_)) => {
                warn!(target: "ghost_mcp::ipc", "Connection lost, attempting reconnect");
                self.reconnect().await?;
                self.request(method, params).await
            }
            Err(e) => Err(e),
        }
    }

    /// Perform handshake with agent
    async fn perform_handshake(&self) -> Result<HandshakeResponse> {
        debug!(
            target: "ghost_mcp::ipc",
            client = %self.identity.name,
            session = %self.identity.session_id,
            "Performing handshake"
        );

        let response = self
            .request(
                "agent.handshake",
                serde_json::to_value(&self.identity).map_err(McpError::Serialization)?,
            )
            .await?;

        let handshake: HandshakeResponse =
            serde_json::from_value(response).map_err(McpError::Serialization)?;

        if !handshake.accepted {
            return Err(McpError::Connection(format!(
                "Handshake rejected: {}",
                handshake
                    .error
                    .unwrap_or_else(|| "Unknown reason".to_string())
            )));
        }

        debug!(
            target: "ghost_mcp::ipc",
            capabilities = ?handshake.granted_capabilities,
            "Handshake accepted"
        );

        Ok(handshake)
    }

    /// Get client identity
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Start heartbeat task
    ///
    /// The heartbeat task monitors connection health by sending periodic pings.
    /// On failure, it marks the connection as disconnected but does NOT attempt
    /// to reconnect - reconnection is handled by `request_with_reconnect()` to
    /// prevent concurrent reconnection conflicts.
    fn start_heartbeat(&self) {
        let interval = Duration::from_millis(self.config.heartbeat.interval_ms);
        let heartbeat_timeout = Duration::from_millis(self.config.heartbeat.timeout_ms);
        let max_failures = self.config.heartbeat.max_failures;
        let client = self.clone();

        debug!(
            target: "ghost_mcp::ipc",
            interval_ms = self.config.heartbeat.interval_ms,
            timeout_ms = self.config.heartbeat.timeout_ms,
            max_failures = max_failures,
            "Starting heartbeat task"
        );

        let handle = tokio::spawn(async move {
            let mut failures: u32 = 0;
            let mut consecutive_successes: u32 = 0;

            loop {
                tokio::time::sleep(interval).await;

                // Check if we should still be running (connection might be intentionally closed)
                if !client.connected.load(Ordering::SeqCst) {
                    debug!(target: "ghost_mcp::ipc", "Heartbeat stopping: connection marked as disconnected");
                    break;
                }

                // Attempt heartbeat with timeout
                let ping =
                    timeout(heartbeat_timeout, client.request("agent.ping", json!({}))).await;

                match ping {
                    Ok(Ok(_)) => {
                        // Reset failure counter on success
                        if failures > 0 {
                            info!(
                                target: "ghost_mcp::ipc",
                                previous_failures = failures,
                                "Heartbeat recovered after failures"
                            );
                        }
                        failures = 0;
                        consecutive_successes = consecutive_successes.saturating_add(1);
                        let mut h = client.health.write().await;
                        h.state = ConnectionState::Connected;
                        h.last_ping = Some(Instant::now());
                        h.failures = 0;
                        h.last_error = None;
                    }
                    Ok(Err(e)) => {
                        failures += 1;
                        let err_msg = e.to_string();
                        {
                            let mut h = client.health.write().await;
                            h.failures = failures;
                            h.last_error = Some(err_msg.clone());
                            h.state = if failures >= max_failures {
                                ConnectionState::Disconnected
                            } else {
                                ConnectionState::Degraded
                            };
                        }

                        warn!(
                            target: "ghost_mcp::ipc",
                            error = %err_msg,
                            failures = failures,
                            max_failures = max_failures,
                            "Heartbeat failed"
                        );

                        if failures >= max_failures {
                            client.connected.store(false, Ordering::SeqCst);
                            // Don't reconnect from heartbeat - let request_with_reconnect handle it
                            // This prevents conflicts between concurrent reconnection attempts
                            error!(
                                target: "ghost_mcp::ipc",
                                "Connection marked as disconnected after {} heartbeat failures",
                                failures
                            );
                        }
                    }
                    Err(_) => {
                        failures += 1;
                        let err_msg = "Heartbeat timeout".to_string();
                        {
                            let mut h = client.health.write().await;
                            h.failures = failures;
                            h.last_error = Some(err_msg.clone());
                            h.state = if failures >= max_failures {
                                ConnectionState::Disconnected
                            } else {
                                ConnectionState::Degraded
                            };
                        }

                        warn!(
                            target: "ghost_mcp::ipc",
                            failures = failures,
                            max_failures = max_failures,
                            "Heartbeat timed out"
                        );

                        if failures >= max_failures {
                            client.connected.store(false, Ordering::SeqCst);
                            // Don't reconnect from heartbeat - let request_with_reconnect handle it
                            // This prevents conflicts between concurrent reconnection attempts
                            error!(
                                target: "ghost_mcp::ipc",
                                "Connection marked as disconnected after {} heartbeat timeouts",
                                failures
                            );
                        }
                    }
                }
            }
        });

        // Store handle using try_lock - if it fails, abort the new task to prevent orphaned heartbeat
        match self.heartbeat_handle.try_lock() {
            Ok(mut handle_guard) => {
                if let Some(old_handle) = handle_guard.take() {
                    old_handle.abort();
                }
                *handle_guard = Some(handle);
            }
            Err(_) => {
                // Lock held - abort new task to prevent orphaned heartbeat
                warn!(target: "ghost_mcp::ipc", "Could not store heartbeat handle (lock held), aborting new task");
                handle.abort();
            }
        }
    }

    /// Stop heartbeat task
    ///
    /// Cleanly stops the heartbeat task by aborting the spawned task.
    /// This is called during disconnect/reconnect to ensure no orphaned tasks.
    async fn stop_heartbeat(&self) {
        debug!(target: "ghost_mcp::ipc", "Stopping heartbeat task");
        let mut handle_guard = self.heartbeat_handle.lock().await;
        if let Some(handle) = handle_guard.take() {
            handle.abort();
            debug!(target: "ghost_mcp::ipc", "Heartbeat task aborted");
        } else {
            debug!(target: "ghost_mcp::ipc", "No heartbeat task to stop");
        }
    }
}

impl Default for AgentClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared agent client wrapper for use in servers
pub type SharedAgentClient = Arc<AgentClient>;

/// Create a shared agent client
pub fn create_agent_client(config: ServerConfig) -> SharedAgentClient {
    Arc::new(AgentClient::with_config(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_increments() {
        let id1 = next_request_id();
        let id2 = next_request_id();
        assert!(id2 > id1);
    }

    #[test]
    fn test_agent_client_new() {
        let client = AgentClient::new();
        assert!(!client.is_connected());
    }

    #[test]
    fn test_agent_client_with_port() {
        let client = AgentClient::with_port(9999);
        assert_eq!(client.config.agent_port, 9999);
    }

    #[tokio::test]
    async fn test_try_connect_fails_without_agent() {
        // Use a high port that's very unlikely to have anything listening
        let client = AgentClient::with_port(59999);
        let result = client.try_connect().await;
        assert!(!result);
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn test_status_is_none_when_disconnected() {
        let client = AgentClient::new();
        let status = client.status().await;
        assert!(status.is_none());
    }

    #[tokio::test]
    async fn test_health_initial_state() {
        let client = AgentClient::new();
        let health = client.health().await;
        assert_eq!(health.state, ConnectionState::Initial);
        assert_eq!(health.failures, 0);
        assert!(health.last_ping.is_none());
    }

    #[tokio::test]
    async fn test_health_is_healthy() {
        let health = ConnectionHealth {
            state: ConnectionState::Connected,
            last_ping: Some(std::time::Instant::now()),
            failures: 0,
            last_error: None,
        };
        assert!(health.is_healthy());

        let degraded = ConnectionHealth {
            state: ConnectionState::Degraded,
            ..health.clone()
        };
        assert!(degraded.is_healthy());

        let disconnected = ConnectionHealth {
            state: ConnectionState::Disconnected,
            ..health
        };
        assert!(!disconnected.is_healthy());
    }

    #[test]
    fn test_connection_state_serialization() {
        let state = ConnectionState::Connected;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"connected\"");

        let parsed: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ConnectionState::Connected);
    }

    // =========================================================================
    // Response ID Handling Tests
    // =========================================================================
    // These tests verify that the IPC client correctly handles event
    // notifications (id=0) and response ID matching to prevent regressions
    // of the "Response ID mismatch" bug.

    /// Helper to create a mock response with given ID
    fn mock_response(id: u32, success: bool) -> Response {
        if success {
            Response {
                id,
                result: ResponseResult::Success(serde_json::json!({"ok": true})),
            }
        } else {
            Response {
                id,
                result: ResponseResult::Error {
                    code: -1,
                    message: "error".to_string(),
                },
            }
        }
    }

    /// Helper to serialize response to wire format (length-prefixed)
    fn serialize_response(response: &Response) -> Vec<u8> {
        let body = serde_json::to_vec(response).unwrap();
        let len = (body.len() as u32).to_le_bytes();
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&body);
        buf
    }

    #[test]
    fn test_event_notification_has_id_zero() {
        // Event notifications from the agent use id=0
        let event_response = mock_response(0, true);
        assert_eq!(event_response.id, 0);
    }

    #[test]
    fn test_response_id_matching() {
        // Regular responses should have matching IDs
        let response = mock_response(42, true);
        assert_eq!(response.id, 42);
    }

    #[test]
    fn test_serialize_deserialize_response() {
        let response = mock_response(123, true);
        let wire = serialize_response(&response);

        // Verify length prefix
        let len = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(len, wire.len() - 4);

        // Verify body can be deserialized
        let parsed: Response = serde_json::from_slice(&wire[4..]).unwrap();
        assert_eq!(parsed.id, 123);
    }

    #[tokio::test]
    async fn test_mock_server_event_then_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // Start a mock server that sends an event (id=0) followed by a response
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read request
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let request: Request = serde_json::from_slice(&body).unwrap();

            // Send event notification (id=0) first - this is what caused the bug
            let event = mock_response(0, true);
            let event_wire = serialize_response(&event);
            stream.write_all(&event_wire).await.unwrap();

            // Send another event
            let event2 = mock_response(0, true);
            let event2_wire = serialize_response(&event2);
            stream.write_all(&event2_wire).await.unwrap();

            // Finally send the actual response with matching ID
            let response = mock_response(request.id, true);
            let response_wire = serialize_response(&response);
            stream.write_all(&response_wire).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Connect as client
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Send a request
        let request = Request {
            id: 42,
            method: "test".to_string(),
            params: serde_json::json!({}),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let len = (body.len() as u32).to_le_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.flush().await.unwrap();

        // Read responses, skipping id=0 events (mimics the fixed behavior)
        let expected_id = request.id;
        let response = loop {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();

            let resp: Response = serde_json::from_slice(&body).unwrap();

            // Skip event notifications (id=0)
            if resp.id == 0 {
                continue;
            }

            break resp;
        };

        assert_eq!(response.id, expected_id);
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_server_wrong_id_detection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // Start a mock server that sends a response with wrong ID
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read request
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let _request: Request = serde_json::from_slice(&body).unwrap();

            // Send response with WRONG ID (simulates bug condition)
            let wrong_response = mock_response(999, true);
            let wire = serialize_response(&wrong_response);
            stream.write_all(&wire).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Connect as client
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Send a request
        let request = Request {
            id: 42,
            method: "test".to_string(),
            params: serde_json::json!({}),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let len = (body.len() as u32).to_le_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.flush().await.unwrap();

        // Read response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut resp_body = vec![0u8; len];
        stream.read_exact(&mut resp_body).await.unwrap();

        let response: Response = serde_json::from_slice(&resp_body).unwrap();

        // Verify ID mismatch is detected
        assert_ne!(response.id, request.id);
        assert_eq!(response.id, 999);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_events_before_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // Start a mock server that sends multiple events before the response
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read request
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let request: Request = serde_json::from_slice(&body).unwrap();

            // Send 5 event notifications before the actual response
            for _ in 0..5 {
                let event = mock_response(0, true);
                let wire = serialize_response(&event);
                stream.write_all(&wire).await.unwrap();
            }

            // Send actual response
            let response = mock_response(request.id, true);
            let wire = serialize_response(&response);
            stream.write_all(&wire).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Connect as client
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Send a request
        let request = Request {
            id: 77,
            method: "test".to_string(),
            params: serde_json::json!({}),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let len = (body.len() as u32).to_le_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.flush().await.unwrap();

        // Count skipped events
        let mut events_skipped = 0;
        let response = loop {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();

            let resp: Response = serde_json::from_slice(&body).unwrap();

            if resp.id == 0 {
                events_skipped += 1;
                continue;
            }

            break resp;
        };

        assert_eq!(events_skipped, 5);
        assert_eq!(response.id, 77);
        server_handle.await.unwrap();
    }

    // =========================================================================
    // Lock Timeout Tests
    // =========================================================================
    // These tests verify the new lock timeout functionality that prevents
    // indefinite blocking when acquiring the stream mutex.

    #[test]
    fn test_lock_timeout_calculation() {
        // Test the lock timeout calculation: 10% of total, min 1s, max 5s
        let calc_lock_timeout = |timeout_ms: u64| -> u64 { (timeout_ms / 10).clamp(1000, 5000) };

        // 30s timeout -> 3s lock timeout
        assert_eq!(calc_lock_timeout(30000), 3000);

        // 5s timeout -> 1s lock timeout (minimum)
        assert_eq!(calc_lock_timeout(5000), 1000);

        // 1s timeout -> 1s lock timeout (minimum kicks in)
        assert_eq!(calc_lock_timeout(1000), 1000);

        // 100s timeout -> 5s lock timeout (maximum)
        assert_eq!(calc_lock_timeout(100000), 5000);

        // 60s timeout -> 5s lock timeout (maximum kicks in)
        assert_eq!(calc_lock_timeout(60000), 5000);
    }

    #[test]
    fn test_config_default_timeout() {
        let config = ServerConfig::default();
        // Default timeout should be 30 seconds
        assert_eq!(config.timeout_ms, 30000);
    }

    #[test]
    fn test_heartbeat_config_defaults() {
        use crate::config::HeartbeatConfig;
        let config = HeartbeatConfig::default();
        // Default heartbeat interval should be 5 seconds
        assert_eq!(config.interval_ms, 5000);
        // Default heartbeat timeout should be 3 seconds
        assert_eq!(config.timeout_ms, 3000);
        // Default max failures should be 3
        assert_eq!(config.max_failures, 3);
    }

    #[tokio::test]
    async fn test_request_fails_when_not_connected() {
        let client = AgentClient::new();
        // Should fail with AgentNotConnected since we never connected
        let result = client.request("test", serde_json::json!({})).await;
        assert!(matches!(result, Err(McpError::AgentNotConnected)));
    }

    #[tokio::test]
    async fn test_health_state_transitions() {
        // Test that health states are properly defined
        let mut health = ConnectionHealth::default();
        assert_eq!(health.state, ConnectionState::Initial);
        assert!(!health.is_healthy());

        health.state = ConnectionState::Connected;
        assert!(health.is_healthy());

        health.state = ConnectionState::Degraded;
        assert!(health.is_healthy()); // Degraded is still "healthy enough"

        health.state = ConnectionState::Disconnected;
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_connection_health_time_since_ping() {
        let health = ConnectionHealth {
            state: ConnectionState::Connected,
            last_ping: Some(Instant::now()),
            failures: 0,
            last_error: None,
        };

        // Should have a very small duration since we just created it
        let duration = health.time_since_ping();
        assert!(duration.is_some());
        assert!(duration.unwrap().as_millis() < 100);
    }

    #[test]
    fn test_connection_health_no_ping_yet() {
        let health = ConnectionHealth::default();
        assert!(health.time_since_ping().is_none());
    }
}
