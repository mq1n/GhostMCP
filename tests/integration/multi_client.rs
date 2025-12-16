//! Multi-client Integration Tests
//!
//! Tests for multi-client handshake, event fanout, and capability gating.

use ghost_agent::backend::InProcessBackend;
use ghost_agent::multi_client::{MultiClientServer, AGENT_PORT};
use ghost_common::ipc::{
    Capability, ClientIdentity, ClientSession, EventType, MemoryWritePayload, PatchAppliedPayload,
    SafetyToken, SessionMetadata,
};
use ghost_mcp_common::config::ServerConfig;
use ghost_mcp_common::ipc::{AgentClient, ConnectionState};
use serde_json::json;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{Mutex, MutexGuard};
use tokio::task::JoinHandle;

/// Helper to create a test client identity
fn test_identity(name: &str) -> ClientIdentity {
    ClientIdentity::new(name, "0.1.0-test")
        .with_capability("read")
        .with_capability("write")
}

/// Helper to create a test config
fn test_config() -> ServerConfig {
    ServerConfig {
        name: "test-client".to_string(),
        agent_port: AGENT_PORT,
        ..Default::default()
    }
}

/// Spawn an in-process test agent using the multi-client server.
async fn spawn_test_agent() -> (
    MutexGuard<'static, ()>,
    Arc<MultiClientServer>,
    JoinHandle<()>,
) {
    static AGENT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = AGENT_LOCK.get_or_init(|| Mutex::new(())).lock().await;

    let server = Arc::new(MultiClientServer::new_with_backend(
        InProcessBackend::new().expect("backend init failed"),
    ));
    let runner = server.clone();
    let handle = tokio::spawn(async move {
        let _ = runner.run().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (guard, server, handle)
}

// =============================================================================
// Multi-Client Handshake Tests
// =============================================================================

#[tokio::test]
async fn test_multi_client_handshake() {
    let (guard, server, handle) = spawn_test_agent().await;
    let config = test_config();
    let client1 = AgentClient::with_identity(config.clone(), test_identity("client-1"));
    let client2 = AgentClient::with_identity(config, test_identity("client-2"));

    client1.connect().await.expect("client1 connect failed");
    client2.connect().await.expect("client2 connect failed");

    assert!(client1.is_connected());
    assert!(client2.is_connected());

    // Query agent status from client1 - should show 2 clients
    let status = client1
        .request("agent.status", json!({}))
        .await
        .expect("status request failed");

    assert_eq!(status["client_count"], 2);

    client1.disconnect().await;
    client2.disconnect().await;
    server.stop();
    handle.abort();
    drop(guard);
}

#[tokio::test]
async fn test_handshake_identity_validation() {
    let (guard, server, handle) = spawn_test_agent().await;
    let config = test_config();

    let valid_identity = ClientIdentity::new("valid-client", "1.0.0");
    let client = AgentClient::with_identity(config.clone(), valid_identity);

    client.connect().await.expect("connect failed");
    assert!(client.is_connected());
    client.disconnect().await;
    server.stop();
    handle.abort();
    drop(guard);
}

#[tokio::test]
async fn test_client_session_tracking() {
    let (guard, server, handle) = spawn_test_agent().await;
    let config = test_config();
    let identity = test_identity("session-test");
    let client = AgentClient::with_identity(config, identity);

    client.connect().await.expect("connect failed");

    // Request session metadata
    let metadata = client.request("state.session", json!({})).await;

    if let Ok(meta_value) = metadata {
        let meta: SessionMetadata =
            serde_json::from_value(meta_value).expect("failed to parse session metadata");

        assert!(
            !meta.client_sessions.is_empty(),
            "No client sessions recorded"
        );

        let our_session = meta
            .client_sessions
            .iter()
            .find(|s| s.name == "session-test");
        assert!(our_session.is_some(), "Our session not found in metadata");
    }

    client.disconnect().await;
    server.stop();
    handle.abort();
    drop(guard);
}

// =============================================================================
// Event Fanout Tests
// =============================================================================

#[tokio::test]
async fn test_event_subscription_registered() {
    let (guard, server, handle) = spawn_test_agent().await;
    let config = test_config();
    let client = AgentClient::with_identity(config, test_identity("observer"));

    client.connect().await.expect("client connect failed");
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        server.event_bus().subscriber_count() >= 1,
        "Client should be subscribed to events"
    );

    client.disconnect().await;
    server.stop();
    handle.abort();
    drop(guard);
}

#[tokio::test]
#[ignore = "requires running agent"]
async fn test_event_types_serialization() {
    // Test that event types serialize correctly
    let event_type = EventType::MemoryWrite;
    let json = serde_json::to_string(&event_type).unwrap();
    assert_eq!(json, "\"memory_write\"");

    let event_type = EventType::PatchApplied;
    let json = serde_json::to_string(&event_type).unwrap();
    assert_eq!(json, "\"patch_applied\"");

    let event_type = EventType::ClientConnected;
    let json = serde_json::to_string(&event_type).unwrap();
    assert_eq!(json, "\"client_connected\"");
}

// =============================================================================
// Capability Gating Tests
// =============================================================================

#[test]
fn test_capability_for_method_mapping() {
    // Read operations
    assert_eq!(Capability::for_method("memory_read"), Capability::Read);
    assert_eq!(Capability::for_method("module_list"), Capability::Read);
    assert_eq!(Capability::for_method("agent.status"), Capability::Read);

    // Write operations
    assert_eq!(Capability::for_method("memory_write"), Capability::Write);
    assert_eq!(Capability::for_method("patch_apply"), Capability::Write);
    assert_eq!(Capability::for_method("patch_undo"), Capability::Write);

    // Execute operations
    assert_eq!(Capability::for_method("exec_call"), Capability::Execute);
    assert_eq!(
        Capability::for_method("exec_shellcode"),
        Capability::Execute
    );
    assert_eq!(Capability::for_method("remote_thread"), Capability::Execute);

    // Debug operations
    assert_eq!(Capability::for_method("breakpoint_set"), Capability::Debug);
    assert_eq!(Capability::for_method("thread_suspend"), Capability::Debug);
    assert_eq!(
        Capability::for_method("execution_step_into"),
        Capability::Debug
    );

    // Admin operations
    assert_eq!(Capability::for_method("safety_set_mode"), Capability::Admin);
    assert_eq!(Capability::for_method("agent_reconnect"), Capability::Admin);
}

#[test]
fn test_capability_granting() {
    let granted = vec![Capability::Read, Capability::Write];

    // Read should be granted
    assert!(Capability::Read.is_granted_by(&granted));

    // Write should be granted
    assert!(Capability::Write.is_granted_by(&granted));

    // Execute should NOT be granted
    assert!(!Capability::Execute.is_granted_by(&granted));

    // Admin grants everything
    let admin_granted = vec![Capability::Admin];
    assert!(Capability::Read.is_granted_by(&admin_granted));
    assert!(Capability::Write.is_granted_by(&admin_granted));
    assert!(Capability::Execute.is_granted_by(&admin_granted));
    assert!(Capability::Debug.is_granted_by(&admin_granted));
}

#[tokio::test]
async fn test_capability_denied_without_grant() {
    let (guard, server, handle) = spawn_test_agent().await;
    let config = test_config();

    let identity = ClientIdentity::new("read-only-client", "1.0.0").with_capability("read");

    let client = AgentClient::with_identity(config, identity);
    client.connect().await.expect("connect failed");

    let result = client
        .request(
            "memory_write",
            json!({
                "address": "0x1000",
                "bytes": "90"
            }),
        )
        .await;

    assert!(
        result.is_err(),
        "Write should be denied for read-only client"
    );

    client.disconnect().await;
    server.stop();
    handle.abort();
    drop(guard);
}

// =============================================================================
// Safety Token Tests
// =============================================================================

#[test]
fn test_safety_token_creation() {
    let token = SafetyToken::new(
        Capability::Write,
        "memory_write",
        "test-client",
        300, // 5 minute TTL
    );

    assert!(token.id.starts_with("tok_"));
    assert_eq!(token.scope, Capability::Write);
    assert_eq!(token.operation, "memory_write");
    assert!(!token.is_expired());
    assert!(!token.used);
}

#[test]
fn test_safety_token_expiry() {
    let mut token = SafetyToken::new(
        Capability::Write,
        "patch_apply",
        "test-client",
        0, // No expiry
    );

    assert!(!token.is_expired());

    // Create an already-expired token by manipulating expires_at
    token.expires_at = 1; // Unix timestamp 1 is definitely in the past
    assert!(token.is_expired());
}

#[test]
fn test_safety_token_validity() {
    let token = SafetyToken::new(Capability::Write, "memory_write", "test-client", 300);

    // Should be valid for Write
    assert!(token.is_valid_for(Capability::Write));

    // Should NOT be valid for Execute (different scope)
    assert!(!token.is_valid_for(Capability::Execute));

    // Admin token should be valid for everything
    let admin_token = SafetyToken::new(Capability::Admin, "any_operation", "admin-client", 300);
    assert!(admin_token.is_valid_for(Capability::Write));
    assert!(admin_token.is_valid_for(Capability::Execute));
}

// =============================================================================
// Connection Health Tests
// =============================================================================

#[tokio::test]
async fn test_connection_health_initial() {
    let client = AgentClient::new();
    let health = client.health().await;

    assert_eq!(health.state, ConnectionState::Initial);
    assert_eq!(health.failures, 0);
    assert!(health.last_ping.is_none());
    assert!(!health.is_healthy());
}

#[tokio::test]
async fn test_connection_health_after_connect() {
    let (guard, server, handle) = spawn_test_agent().await;
    let client = AgentClient::new();

    client.connect().await.expect("connect failed");
    let health = client.health().await;
    assert_eq!(health.state, ConnectionState::Connected);
    assert!(health.is_healthy());
    client.disconnect().await;
    server.stop();
    handle.abort();
    drop(guard);
}

// =============================================================================
// Event Payload Tests
// =============================================================================

#[test]
fn test_memory_write_payload_serialization() {
    let payload = MemoryWritePayload {
        address: 0x7FF00000,
        size: 16,
        client_id: "test-client".to_string(),
    };

    let json = serde_json::to_string(&payload).unwrap();
    let parsed: MemoryWritePayload = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.address, 0x7FF00000);
    assert_eq!(parsed.size, 16);
    assert_eq!(parsed.client_id, "test-client");
}

#[test]
fn test_patch_applied_payload_serialization() {
    let payload = PatchAppliedPayload {
        patch_id: 42,
        address: 0x1000,
        size: 4,
        client_id: "patcher".to_string(),
    };

    let json = serde_json::to_string(&payload).unwrap();
    let parsed: PatchAppliedPayload = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.patch_id, 42);
    assert_eq!(parsed.address, 0x1000);
}

#[test]
fn test_client_session_serialization() {
    let session = ClientSession {
        client_id: "sess_123".to_string(),
        name: "ghost-core-mcp".to_string(),
        connected_at: 1234567890,
        capabilities: vec![Capability::Read, Capability::Write],
        last_activity: 1234567900,
    };

    let json = serde_json::to_string(&session).unwrap();
    let parsed: ClientSession = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.client_id, "sess_123");
    assert_eq!(parsed.capabilities.len(), 2);
    assert!(parsed.capabilities.contains(&Capability::Read));
}
