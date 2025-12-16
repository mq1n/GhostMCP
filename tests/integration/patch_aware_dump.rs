//! Patch-Aware Dump Flow Integration Tests
//!
//! Drives `DumpHandler` against a stubbed agent to verify that patch history
//! data flows through dump_create/region/info/compare responses with the
//! structured counts expected by the roadmap (patches/returned/total/truncated).

use async_trait::async_trait;
use ghost_analysis_mcp::handlers::{DumpHandler, PatchHistoryClient};
use ghost_common::ipc::PatchEntry;
use ghost_mcp_common::error::{McpError, Result as McpResult};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_test::block_on;

/// Fixed target range for patch-aware dumps
const TARGET_START: u64 = 0x0001_4000_1000;
const TARGET_END: u64 = 0x0001_4000_2000;

/// Fixture data shared by the stub agent and tests
#[derive(Clone)]
struct PatchDumpFixture {
    patches: Vec<PatchEntry>,
    overlapping_patch_id: u64,
    outside_patch_id: u64,
}

impl PatchDumpFixture {
    fn new() -> Self {
        let overlapping_patch = PatchEntry {
            id: 1,
            address: TARGET_START + 0x500,
            original_bytes: vec![0x90, 0x90, 0x90, 0x90],
            patched_bytes: vec![0xCC, 0xCC, 0xCC, 0xCC],
            timestamp: now_ms(),
            applied_by: Some("test-client".to_string()),
            active: true,
            description: Some("Test patch inside target range".to_string()),
        };

        let outside_patch = PatchEntry {
            id: 2,
            address: TARGET_END + 0x1000,
            original_bytes: vec![0x48, 0x89, 0x5C, 0x24],
            patched_bytes: vec![0x90, 0x90, 0x90, 0x90],
            timestamp: now_ms(),
            applied_by: Some("test-client".to_string()),
            active: true,
            description: Some("Test patch outside target range".to_string()),
        };

        Self {
            patches: vec![overlapping_patch, outside_patch],
            overlapping_patch_id: 1,
            outside_patch_id: 2,
        }
    }
}

/// Stub agent that satisfies the `PatchHistoryClient` contract with static data
#[derive(Clone)]
struct PatchDumpStubAgent {
    fixture: PatchDumpFixture,
    connected: Arc<AtomicBool>,
    connect_calls: Arc<AtomicUsize>,
}

impl PatchDumpStubAgent {
    fn new() -> Self {
        Self {
            fixture: PatchDumpFixture::new(),
            connected: Arc::new(AtomicBool::new(false)),
            connect_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn patch_history_response(&self, params: &Value) -> Value {
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.fixture.patches.len() as u64) as usize;

        let total = self.fixture.patches.len();
        let returned = total.min(limit);
        let truncated = returned < total;
        let patches: Vec<_> = self
            .fixture
            .patches
            .iter()
            .take(returned)
            .cloned()
            .collect();

        json!({
            "patches": patches,
            "returned": returned,
            "total": total,
            "truncated": truncated
        })
    }

    fn dump_create_response(&self) -> Value {
        json!({
            "dump_id": "test_dump",
            "name": "test_dump",
            "created_at": now_ms(),
            "size": 4096,
            "type": "full"
        })
    }

    fn dump_region_response(&self) -> Value {
        json!({
            "dump_id": "region_001",
            "address": format!("0x{:x}", TARGET_START),
            "size": (TARGET_END - TARGET_START) as usize,
            "data": "00".repeat(32)
        })
    }

    fn dump_info_response(&self) -> Value {
        json!({
            "dump_id": "info_001",
            "start_address": TARGET_START,
            "end_address": TARGET_END,
            "name": "info_dump",
            "size": (TARGET_END - TARGET_START) as usize
        })
    }

    fn dump_compare_response(&self) -> Value {
        json!({
            "dump_id1": "before",
            "dump_id2": "after",
            "changes": [
                {
                    "address": TARGET_START + 0x500,
                    "size": 4,
                    "old_bytes": [0x90, 0x90, 0x90, 0x90],
                    "new_bytes": [0xCC, 0xCC, 0xCC, 0xCC]
                }
            ]
        })
    }

    fn overlapping_patch_id(&self) -> u64 {
        self.fixture.overlapping_patch_id
    }

    fn outside_patch_id(&self) -> u64 {
        self.fixture.outside_patch_id
    }
}

#[async_trait]
impl PatchHistoryClient for PatchDumpStubAgent {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    async fn connect(&self) -> McpResult<()> {
        self.connected.store(true, Ordering::SeqCst);
        self.connect_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn request_with_reconnect(&self, method: &str, params: Value) -> McpResult<Value> {
        let response = match method {
            "patch_history" => self.patch_history_response(&params),
            "dump_create" => self.dump_create_response(),
            "dump_region" => self.dump_region_response(),
            "dump_info" => self.dump_info_response(),
            "dump_compare" => self.dump_compare_response(),
            "dump_annotate" => json!({"ok": true}),
            other => return Err(McpError::Handler(format!("unexpected method '{}'", other))),
        };

        Ok(response)
    }
}

/// Get current timestamp in milliseconds
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// =============================================================================
// Integration Tests (stub agent)
// =============================================================================

async fn test_patch_history_counts(agent: &PatchDumpStubAgent) -> Result<(), String> {
    let history = DumpHandler::query_patch_history(agent, None, None, Some(1))
        .await
        .map_err(|e| e.to_string())?;

    if history.returned != 1 || history.total != 2 || !history.truncated {
        return Err(format!(
            "expected returned=1,total=2,truncated=true got {}/{}/{}",
            history.returned, history.total, history.truncated
        ));
    }

    Ok(())
}

async fn test_dump_create_includes_patch_annotations(
    agent: &PatchDumpStubAgent,
) -> Result<(), String> {
    let response = DumpHandler::handle_dump_create(agent, &json!({"name": "test_dump"}))
        .await
        .map_err(|e| e.to_string())?;

    let annotations = response
        .get("patch_annotations")
        .ok_or("Missing patch_annotations")?;
    let patches = annotations
        .get("patches")
        .and_then(|p| p.as_array())
        .ok_or("Missing patches array")?;

    if patches.len() != agent.fixture.patches.len() {
        return Err(format!(
            "expected {} patches, got {}",
            agent.fixture.patches.len(),
            patches.len()
        ));
    }

    let returned = annotations
        .get("returned")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total = annotations
        .get("total")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let truncated = annotations
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if returned != total || truncated {
        return Err(format!(
            "expected full history returned, got returned={}, total={}, truncated={}",
            returned, total, truncated
        ));
    }

    Ok(())
}

async fn test_dump_region_filters_patches(agent: &PatchDumpStubAgent) -> Result<(), String> {
    let response = DumpHandler::handle_dump_region(
        agent,
        &json!({"address": format!("0x{:x}", TARGET_START), "size": TARGET_END - TARGET_START}),
    )
    .await
    .map_err(|e| e.to_string())?;

    let annotations = response
        .get("patch_annotations")
        .ok_or("Missing patch_annotations")?;
    let patches = annotations
        .get("patches")
        .and_then(|p| p.as_array())
        .ok_or("Missing patches array")?;

    let has_overlapping = patches
        .iter()
        .any(|p| p.get("id").and_then(|id| id.as_u64()) == Some(agent.overlapping_patch_id()));
    let has_outside = patches
        .iter()
        .any(|p| p.get("id").and_then(|id| id.as_u64()) == Some(agent.outside_patch_id()));

    if !has_overlapping {
        return Err("expected overlapping patch to be included".to_string());
    }
    if has_outside {
        return Err("expected outside patch to be excluded".to_string());
    }

    Ok(())
}

async fn test_dump_info_annotations(agent: &PatchDumpStubAgent) -> Result<(), String> {
    let response = DumpHandler::handle_dump_info(agent, &json!({"dump_id": "info_001"}))
        .await
        .map_err(|e| e.to_string())?;

    let annotations = response
        .get("patch_annotations")
        .ok_or("Missing patch_annotations")?;
    let patches = annotations
        .get("patches")
        .and_then(|p| p.as_array())
        .ok_or("Missing patches array")?;

    if patches.is_empty() {
        return Err("expected at least one patch in dump_info annotations".to_string());
    }

    Ok(())
}

async fn test_dump_compare_annotates_changes(agent: &PatchDumpStubAgent) -> Result<(), String> {
    let response = DumpHandler::handle_dump_compare(
        agent,
        &json!({"dump_id1": "before", "dump_id2": "after"}),
    )
    .await
    .map_err(|e| e.to_string())?;

    let annotations = response
        .get("patch_annotations")
        .ok_or("Missing patch_annotations")?;

    let patch_caused = annotations
        .get("patch_caused_differences")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if patch_caused == 0 {
        return Err("expected patch_caused_differences > 0".to_string());
    }

    let changes = annotations
        .get("changes")
        .and_then(|c| c.as_array())
        .ok_or("Missing changes array")?;

    let references_patch = changes.iter().any(|c| {
        c.get("patch_ids")
            .and_then(|ids| ids.as_array())
            .map(|ids| {
                ids.iter()
                    .any(|id| id.as_u64() == Some(agent.overlapping_patch_id()))
            })
            .unwrap_or(false)
    });

    if !references_patch {
        return Err("expected change annotations to reference overlapping patch".to_string());
    }

    Ok(())
}

/// Run all patch-aware dump tests against the stub agent
pub fn run_all_tests() -> super::TestResults {
    let mut results = super::TestResults::default();
    let agent = PatchDumpStubAgent::new();

    println!("Running Patch-Aware Dump Flow Tests with stub agent...\n");

    block_on(async {
        match test_patch_history_counts(&agent).await {
            Ok(()) => results.record_pass("patch_history_counts"),
            Err(e) => results.record_fail("patch_history_counts", &e),
        }

        match test_dump_create_includes_patch_annotations(&agent).await {
            Ok(()) => results.record_pass("dump_create_includes_patch_annotations"),
            Err(e) => results.record_fail("dump_create_includes_patch_annotations", &e),
        }

        match test_dump_region_filters_patches(&agent).await {
            Ok(()) => results.record_pass("dump_region_filters_patches_by_range"),
            Err(e) => results.record_fail("dump_region_filters_patches_by_range", &e),
        }

        match test_dump_info_annotations(&agent).await {
            Ok(()) => results.record_pass("dump_info_includes_annotations"),
            Err(e) => results.record_fail("dump_info_includes_annotations", &e),
        }

        match test_dump_compare_annotates_changes(&agent).await {
            Ok(()) => results.record_pass("dump_compare_annotates_patch_changes"),
            Err(e) => results.record_fail("dump_compare_annotates_patch_changes", &e),
        }
    });

    results.summary();
    results
}

// =============================================================================
// Live Agent Integration (optional feature)
// =============================================================================

#[cfg(feature = "live_agent_tests")]
pub mod live_agent {
    use super::*;
    use ghost_agent::multi_client::SharedState;

    /// Create SharedState with seeded patches for live testing
    pub fn create_seeded_state() -> Arc<SharedState> {
        let state = Arc::new(SharedState::new());
        let fixture = PatchDumpFixture::new();

        let patch1 = PatchEntry::new(
            fixture.patches[0].address,
            fixture.patches[0].original_bytes.clone(),
            fixture.patches[0].patched_bytes.clone(),
        );
        state.add_patch(patch1).expect("Failed to seed patch 1");

        let patch2 = PatchEntry::new(
            fixture.patches[1].address,
            fixture.patches[1].original_bytes.clone(),
            fixture.patches[1].patched_bytes.clone(),
        );
        state.add_patch(patch2).expect("Failed to seed patch 2");

        state
    }

    /// Test patch_history retrieval from live SharedState
    pub fn test_live_patch_history(state: &SharedState) -> Result<(), String> {
        let patches = state.get_patches();

        if patches.len() < 2 {
            return Err(format!(
                "Expected at least 2 seeded patches, got {}",
                patches.len()
            ));
        }

        // Verify patch IDs are assigned
        for patch in &patches {
            if patch.id == 0 {
                return Err("Patch ID should not be 0 after seeding".to_string());
            }
        }

        Ok(())
    }

    /// Run live agent tests
    pub fn run_live_tests() -> super::super::TestResults {
        let mut results = super::super::TestResults::default();
        let state = create_seeded_state();

        println!("Running Live Agent Patch-Aware Dump Tests...\n");

        match test_live_patch_history(&state) {
            Ok(()) => results.record_pass("live_patch_history"),
            Err(e) => results.record_fail("live_patch_history", &e),
        }

        results.summary();
        results
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_creation() {
        let fixture = PatchDumpFixture::new();
        assert_eq!(fixture.patches.len(), 2);
        assert_eq!(fixture.overlapping_patch_id, 1);
        assert_eq!(fixture.outside_patch_id, 2);
    }

    #[test]
    fn test_stub_patch_history_truncates() {
        let agent = PatchDumpStubAgent::new();
        let response = agent.patch_history_response(&json!({"limit": 1}));
        assert_eq!(response["returned"], json!(1));
        assert_eq!(response["total"], json!(2));
        assert_eq!(response["truncated"], json!(true));
    }
}
