//! Dump handler for ghost-analysis-mcp
//!
//! Provides specialized handling for dump tools that need to integrate with
//! the agent's centralized patch history.
//! Dump tools must query centralized patch history from agent.

use async_trait::async_trait;
use ghost_common::ipc::PatchEntry;
use ghost_common::safety::SafetyConfig;
use ghost_mcp_common::error::{McpError, Result};
use ghost_mcp_common::ipc::SharedAgentClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tracing::{debug, info};

/// Maximum dump size in bytes (256 MB)
pub const MAX_DUMP_SIZE: usize = 256 * 1024 * 1024;

/// Maximum dump name length
pub const MAX_DUMP_NAME_LEN: usize = 256;

/// Minimum valid memory address (avoid null pointer region)
pub const MIN_VALID_ADDRESS: u64 = 0x10000;

/// Dump handler for analysis tools that need patch history integration
pub struct DumpHandler;

/// Minimal agent interface required for patch-aware dump handling.
#[async_trait]
pub trait PatchHistoryClient: Send + Sync {
    /// Check if the client is currently connected
    fn is_connected(&self) -> bool;
    /// Establish a connection if needed
    async fn connect(&self) -> Result<()>;
    /// Send an agent request with reconnect semantics
    async fn request_with_reconnect(&self, method: &str, params: Value) -> Result<Value>;
}

#[async_trait]
impl PatchHistoryClient for SharedAgentClient {
    fn is_connected(&self) -> bool {
        (**self).is_connected()
    }

    async fn connect(&self) -> Result<()> {
        (**self).connect().await
    }

    async fn request_with_reconnect(&self, method: &str, params: Value) -> Result<Value> {
        (**self).request_with_reconnect(method, params).await
    }
}

/// Patch history fetched from the agent (filtered for the requested range)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchHistoryResult {
    pub patches: Vec<PatchEntry>,
    pub returned: usize,
    pub total: usize,
    pub truncated: bool,
}

/// Dump metadata with patch annotations
/// Note: Currently used for documentation/type reference; will be instantiated
/// when dump_info response parsing is implemented.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpInfo {
    pub dump_id: String,
    pub name: Option<String>,
    pub created_at: u64,
    pub size: usize,
    pub dump_type: String,
    pub patches_in_range: Vec<PatchEntry>,
}

/// Patch entry as returned by the agent. Uses aliases to accept legacy field
/// names (`patch_id`, `old_bytes`, `new_bytes`, `client_id`, `timestamp_ms`)
/// while mapping into the canonical `PatchEntry` shape used by shared state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentPatchEntry {
    #[serde(alias = "patch_id")]
    pub id: u64,
    pub address: u64,
    #[serde(alias = "old_bytes", alias = "original_bytes")]
    pub original_bytes: Vec<u8>,
    #[serde(alias = "new_bytes", alias = "patched_bytes")]
    pub patched_bytes: Vec<u8>,
    #[serde(default, alias = "timestamp_ms")]
    pub timestamp: u64,
    #[serde(default, alias = "client_id")]
    pub applied_by: Option<String>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DumpDiffChange {
    address: u64,
    size: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ChangeAnnotation {
    address: u64,
    size: u64,
    patch_ids: Vec<u64>,
}

fn default_true() -> bool {
    true
}

impl From<AgentPatchEntry> for PatchEntry {
    fn from(p: AgentPatchEntry) -> Self {
        PatchEntry {
            id: p.id,
            address: p.address,
            original_bytes: p.original_bytes,
            patched_bytes: p.patched_bytes,
            timestamp: p.timestamp,
            applied_by: p.applied_by,
            active: p.active,
            description: p.description,
        }
    }
}

impl DumpHandler {
    /// Validate dump parameters before creation
    pub fn validate_dump_params(args: &Value) -> Result<()> {
        // Validate name length if provided
        if let Some(name) = args.get("name").and_then(|n| n.as_str()) {
            if name.len() > MAX_DUMP_NAME_LEN {
                return Err(McpError::InvalidParams(format!(
                    "Dump name exceeds maximum length of {} characters",
                    MAX_DUMP_NAME_LEN
                )));
            }
            // Check for invalid characters in name
            if name.contains(['/', '\\', '\0', ':']) {
                return Err(McpError::InvalidParams(
                    "Dump name contains invalid characters".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate region dump parameters
    pub fn validate_region_params(args: &Value) -> Result<(u64, usize)> {
        let address = Self::parse_address(args.get("address"))?;
        let size = args
            .get("size")
            .and_then(|s| s.as_u64())
            .ok_or_else(|| McpError::InvalidParams("Missing 'size' parameter".to_string()))?
            as usize;

        // Validate address
        if address < MIN_VALID_ADDRESS {
            return Err(McpError::InvalidParams(format!(
                "Address 0x{:x} is below minimum valid address 0x{:x}",
                address, MIN_VALID_ADDRESS
            )));
        }

        // Validate size
        if size == 0 {
            return Err(McpError::InvalidParams("Size cannot be zero".to_string()));
        }
        if size > MAX_DUMP_SIZE {
            return Err(McpError::InvalidParams(format!(
                "Size {} exceeds maximum dump size of {} bytes",
                size, MAX_DUMP_SIZE
            )));
        }

        // Check for overflow
        if address.checked_add(size as u64).is_none() {
            return Err(McpError::InvalidParams(
                "Address + size overflows".to_string(),
            ));
        }

        Ok((address, size))
    }

    /// Parse address from string or integer
    pub fn parse_address(value: Option<&Value>) -> Result<u64> {
        match value {
            Some(Value::String(s)) => {
                let s = s.trim();
                let s = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                u64::from_str_radix(s, 16).map_err(|e| {
                    McpError::InvalidParams(format!("Invalid hex address '{}': {}", s, e))
                })
            }
            Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
                McpError::InvalidParams("Address must be a positive integer".to_string())
            }),
            None => Err(McpError::InvalidParams(
                "Missing 'address' parameter".to_string(),
            )),
            _ => Err(McpError::InvalidParams(
                "Address must be a string or number".to_string(),
            )),
        }
    }

    fn patch_history_limit(limit: Option<usize>) -> usize {
        limit.unwrap_or_else(|| SafetyConfig::default().max_patch_history.max(50))
    }

    fn patch_size(entry: &PatchEntry) -> u64 {
        let max_len = entry
            .original_bytes
            .len()
            .max(entry.patched_bytes.len())
            .max(1);
        max_len as u64
    }

    fn patch_overlaps_range(entry: &PatchEntry, start: u64, end: u64) -> bool {
        let patch_end = entry.address.saturating_add(Self::patch_size(entry));
        entry.address < end && patch_end > start
    }

    fn extract_diff_changes(response: &Value) -> Vec<DumpDiffChange> {
        let candidates = response
            .get("changes")
            .or_else(|| response.get("differences"))
            .and_then(|v| v.as_array());

        candidates
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let address = v.get("address").and_then(|a| a.as_u64())?;
                        let size = v
                            .get("size")
                            .and_then(|s| s.as_u64())
                            .or_else(|| {
                                v.get("old_bytes")
                                    .and_then(|b| b.as_array())
                                    .map(|b| b.len() as u64)
                            })
                            .or_else(|| {
                                v.get("new_bytes")
                                    .and_then(|b| b.as_array())
                                    .map(|b| b.len() as u64)
                            })
                            .unwrap_or(1);

                        Some(DumpDiffChange { address, size })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn annotate_diff_changes(
        changes: &[DumpDiffChange],
        patches: &[PatchEntry],
    ) -> Vec<ChangeAnnotation> {
        changes
            .iter()
            .map(|change| {
                let start = change.address;
                let end = change.address.saturating_add(change.size.max(1));
                let patch_ids = patches
                    .iter()
                    .filter(|p| Self::patch_overlaps_range(p, start, end))
                    .map(|p| p.id)
                    .collect();

                ChangeAnnotation {
                    address: change.address,
                    size: change.size,
                    patch_ids,
                }
            })
            .collect()
    }

    /// Query patch history from agent for a given address range
    pub async fn query_patch_history(
        agent: &impl PatchHistoryClient,
        range: Option<(u64, u64)>,
        client_id: Option<&str>,
        limit: Option<usize>,
    ) -> Result<PatchHistoryResult> {
        debug!(
            target: "ghost_analysis_mcp::dump",
            range = ?range,
            client_id = client_id.unwrap_or(""),
            "Querying patch history"
        );

        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let mut payload = Map::new();
        payload.insert("limit".to_string(), json!(Self::patch_history_limit(limit)));
        if let Some(client) = client_id {
            payload.insert("client_id".to_string(), json!(client));
        }

        let response = agent
            .request_with_reconnect("patch_history", Value::Object(payload))
            .await
            .map_err(|e| McpError::Handler(format!("Failed to query patch history: {}", e)))?;

        let patches_value = response.get("patches").ok_or_else(|| {
            McpError::Handler("patch_history response missing 'patches' field".to_string())
        })?;

        let mut patches: Vec<PatchEntry> =
            serde_json::from_value::<Vec<AgentPatchEntry>>(patches_value.clone())
                .map(|items| items.into_iter().map(PatchEntry::from).collect())
                .map_err(|e| {
                    McpError::Handler(format!("Failed to deserialize patch history: {}", e))
                })?;

        let returned = response
            .get("returned")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(patches.len());
        let total = response
            .get("total")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(patches.len());

        let truncated = response
            .get("truncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(returned < total);

        if let Some((start_address, end_address)) = range {
            patches.retain(|p| Self::patch_overlaps_range(p, start_address, end_address));
        }

        debug!(
            target: "ghost_analysis_mcp::dump",
            patch_count = patches.len(),
            returned,
            total,
            truncated,
            "Patch history query completed"
        );

        Ok(PatchHistoryResult {
            patches,
            returned,
            total,
            truncated,
        })
    }

    /// Handle dump_create with patch history annotation
    pub async fn handle_dump_create(
        agent: &impl PatchHistoryClient,
        args: &Value,
    ) -> Result<Value> {
        Self::validate_dump_params(args)?;

        info!(target: "ghost_analysis_mcp::dump", "Creating dump");

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let response = agent
            .request_with_reconnect("dump_create", args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("dump_create failed: {}", e)))?;

        // If successful, query patch history to annotate the dump
        if let Some(dump_id) = response.get("dump_id").and_then(|d| d.as_str()) {
            debug!(
                target: "ghost_analysis_mcp::dump",
                dump_id = dump_id,
                "Dump created, querying patch history for annotations"
            );

            // For full dumps, we query all patches
            let history = Self::query_patch_history(agent, None, None, None).await?;
            let patch_count = history.patches.len();

            let patch_annotations = json!({
                "patches": history.patches,
                "patch_count": patch_count,
                "returned": history.returned,
                "total": history.total,
                "truncated": history.truncated,
            });

            if patch_count > 0 || history.truncated {
                info!(
                    target: "ghost_analysis_mcp::dump",
                    dump_id = dump_id,
                    patch_count = patch_count,
                    truncated = history.truncated,
                    "Dump annotated with patch history"
                );
            }

            let mut annotated_dump = response.clone();
            annotated_dump["patch_annotations"] = patch_annotations.clone();

            return Ok(json!({
                "content": [{ "type": "text", "text": annotated_dump.to_string() }],
                "dump": annotated_dump,
                "patch_annotations": patch_annotations,
            }));
        }

        Ok(json!({
            "content": [{ "type": "text", "text": response.to_string() }]
        }))
    }

    /// Handle dump_region with patch history for specific range
    pub async fn handle_dump_region(
        agent: &impl PatchHistoryClient,
        args: &Value,
    ) -> Result<Value> {
        let (address, size) = Self::validate_region_params(args)?;
        let end_address = address + size as u64;

        info!(
            target: "ghost_analysis_mcp::dump",
            address = format!("0x{:x}", address),
            size = size,
            "Creating region dump"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let response = agent
            .request_with_reconnect("dump_region", args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("dump_region failed: {}", e)))?;

        // Query patches that affect this region
        let history =
            Self::query_patch_history(agent, Some((address, end_address)), None, None).await?;

        let patch_annotations = json!({
            "range": {
                "start": format!("0x{:x}", address),
                "end": format!("0x{:x}", end_address),
            },
            "patches": history.patches,
            "patch_count": history.patches.len(),
            "returned": history.returned,
            "total": history.total,
            "truncated": history.truncated,
        });

        let mut annotated_dump = response.clone();
        annotated_dump["patch_annotations"] = patch_annotations.clone();

        Ok(json!({
            "content": [{ "type": "text", "text": annotated_dump.to_string() }],
            "dump": annotated_dump,
            "patch_annotations": patch_annotations,
        }))
    }

    /// Handle dump_info with patch annotations
    pub async fn handle_dump_info(agent: &impl PatchHistoryClient, args: &Value) -> Result<Value> {
        let dump_id = args
            .get("dump_id")
            .and_then(|d| d.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'dump_id' parameter".to_string()))?;

        debug!(
            target: "ghost_analysis_mcp::dump",
            dump_id = dump_id,
            "Getting dump info with patch annotations"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let response = agent
            .request_with_reconnect("dump_info", args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("dump_info failed: {}", e)))?;

        // Extract range from dump info and query patches
        if let (Some(start), Some(end)) = (
            response.get("start_address").and_then(|a| a.as_u64()),
            response.get("end_address").and_then(|a| a.as_u64()),
        ) {
            let history = Self::query_patch_history(agent, Some((start, end)), None, None).await?;

            let patch_annotations = json!({
                "range": {
                    "start": format!("0x{:x}", start),
                    "end": format!("0x{:x}", end),
                },
                "patches": history.patches,
                "patch_count": history.patches.len(),
                "patches_total": history.total,
                "patches_truncated": history.truncated,
            });

            let mut enhanced = response.clone();
            enhanced["patch_annotations"] = patch_annotations.clone();

            return Ok(json!({
                "content": [{ "type": "text", "text": enhanced.to_string() }],
                "dump": enhanced,
                "patch_annotations": patch_annotations,
            }));
        }

        Ok(json!({
            "content": [{ "type": "text", "text": response.to_string() }]
        }))
    }

    /// Handle dump_compare with patch-aware diff
    pub async fn handle_dump_compare(
        agent: &impl PatchHistoryClient,
        args: &Value,
    ) -> Result<Value> {
        let dump_id1 = args
            .get("dump_id1")
            .and_then(|d| d.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'dump_id1' parameter".to_string()))?;
        let dump_id2 = args
            .get("dump_id2")
            .and_then(|d| d.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'dump_id2' parameter".to_string()))?;

        info!(
            target: "ghost_analysis_mcp::dump",
            dump_id1 = dump_id1,
            dump_id2 = dump_id2,
            "Comparing dumps with patch awareness"
        );

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let response = agent
            .request_with_reconnect("dump_compare", args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("dump_compare failed: {}", e)))?;

        let changes = Self::extract_diff_changes(&response);
        if changes.is_empty() {
            return Ok(json!({
                "content": [{ "type": "text", "text": response.to_string() }]
            }));
        }

        let min_address = changes
            .iter()
            .map(|c| c.address)
            .min()
            .unwrap_or(MIN_VALID_ADDRESS);
        let max_address = changes
            .iter()
            .map(|c| c.address.saturating_add(c.size.max(1)))
            .max()
            .unwrap_or(min_address);

        let history =
            Self::query_patch_history(agent, Some((min_address, max_address)), None, None).await?;

        let annotations = Self::annotate_diff_changes(&changes, &history.patches);
        let patch_caused = annotations
            .iter()
            .filter(|a| !a.patch_ids.is_empty())
            .count();
        let patch_count = history.patches.len();

        debug!(
            target: "ghost_analysis_mcp::dump",
            change_count = changes.len(),
            patch_caused,
            patch_count = patch_count,
            "Annotated dump diff with patch history"
        );

        let patch_annotations = json!({
            "change_count": changes.len(),
            "patch_caused_differences": patch_caused,
            "patches_considered": patch_count,
            "patches_total": history.total,
            "patches_truncated": history.truncated,
            "changes": annotations,
            "patches": history.patches,
            "patch_count": patch_count,
        });

        let mut enhanced = response.clone();
        enhanced["patch_annotations"] = patch_annotations.clone();

        Ok(json!({
            "content": [{ "type": "text", "text": enhanced.to_string() }],
            "diff": enhanced,
            "patch_annotations": patch_annotations,
        }))
    }

    /// Handle dump_annotate - add annotation to dump
    pub async fn handle_dump_annotate(
        agent: &impl PatchHistoryClient,
        args: &Value,
    ) -> Result<Value> {
        // Validate address if provided
        if let Some(addr) = args.get("address") {
            let address = Self::parse_address(Some(addr))?;
            if address < MIN_VALID_ADDRESS {
                return Err(McpError::InvalidParams(format!(
                    "Address 0x{:x} is below minimum valid address",
                    address
                )));
            }
        }

        // Validate note length
        if let Some(note) = args.get("note").and_then(|n| n.as_str()) {
            const MAX_NOTE_LEN: usize = 4096;
            if note.len() > MAX_NOTE_LEN {
                return Err(McpError::InvalidParams(format!(
                    "Annotation note exceeds maximum length of {} characters",
                    MAX_NOTE_LEN
                )));
            }
        }

        // Forward to agent
        if !agent.is_connected() {
            let _ = agent.connect().await;
        }

        let response = agent
            .request_with_reconnect("dump_annotate", args.clone())
            .await
            .map_err(|e| McpError::Handler(format!("dump_annotate failed: {}", e)))?;

        Ok(json!({
            "content": [{ "type": "text", "text": response.to_string() }]
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::ipc::PatchEntry;
    use serde_json::json;

    #[test]
    fn test_validate_dump_params_valid() {
        let args = json!({ "name": "test_dump", "type": "full" });
        assert!(DumpHandler::validate_dump_params(&args).is_ok());
    }

    #[test]
    fn test_validate_dump_params_long_name() {
        let long_name = "a".repeat(MAX_DUMP_NAME_LEN + 1);
        let args = json!({ "name": long_name });
        assert!(DumpHandler::validate_dump_params(&args).is_err());
    }

    #[test]
    fn test_validate_dump_params_invalid_chars() {
        let args = json!({ "name": "test/dump" });
        assert!(DumpHandler::validate_dump_params(&args).is_err());

        let args = json!({ "name": "test\\dump" });
        assert!(DumpHandler::validate_dump_params(&args).is_err());
    }

    #[test]
    fn test_parse_address_hex_string() {
        let addr = DumpHandler::parse_address(Some(&json!("0x12345678"))).unwrap();
        assert_eq!(addr, 0x12345678);
    }

    #[test]
    fn test_parse_address_hex_string_uppercase() {
        let addr = DumpHandler::parse_address(Some(&json!("0X12345678"))).unwrap();
        assert_eq!(addr, 0x12345678);
    }

    #[test]
    fn test_parse_address_number() {
        let addr = DumpHandler::parse_address(Some(&json!(0x12345678_u64))).unwrap();
        assert_eq!(addr, 0x12345678);
    }

    #[test]
    fn test_parse_address_missing() {
        assert!(DumpHandler::parse_address(None).is_err());
    }

    #[test]
    fn test_validate_region_params_valid() {
        let args = json!({
            "address": "0x100000",
            "size": 4096
        });
        let (addr, size) = DumpHandler::validate_region_params(&args).unwrap();
        assert_eq!(addr, 0x100000);
        assert_eq!(size, 4096);
    }

    #[test]
    fn test_validate_region_params_too_small_address() {
        let args = json!({
            "address": "0x1000",
            "size": 4096
        });
        assert!(DumpHandler::validate_region_params(&args).is_err());
    }

    #[test]
    fn test_validate_region_params_zero_size() {
        let args = json!({
            "address": "0x100000",
            "size": 0
        });
        assert!(DumpHandler::validate_region_params(&args).is_err());
    }

    #[test]
    fn test_validate_region_params_too_large_size() {
        let args = json!({
            "address": "0x100000",
            "size": MAX_DUMP_SIZE + 1
        });
        assert!(DumpHandler::validate_region_params(&args).is_err());
    }

    #[test]
    fn test_validate_region_params_overflow() {
        let args = json!({
            "address": "0xFFFFFFFFFFFFFF00",
            "size": 4096
        });
        assert!(DumpHandler::validate_region_params(&args).is_err());
    }

    #[test]
    fn test_patch_history_limit_defaults_to_safety_config() {
        let expected = SafetyConfig::default().max_patch_history.max(50);
        assert_eq!(DumpHandler::patch_history_limit(None), expected);
        assert_eq!(DumpHandler::patch_history_limit(Some(10)), 10);
    }

    #[test]
    fn test_patch_overlaps_range() {
        let patch = PatchEntry {
            id: 1,
            address: 0x1000,
            original_bytes: vec![0; 4],
            patched_bytes: vec![1; 4],
            timestamp: 0,
            applied_by: None,
            active: true,
            description: None,
        };

        assert!(DumpHandler::patch_overlaps_range(&patch, 0x0, 0x2000));
        assert!(DumpHandler::patch_overlaps_range(&patch, 0x1002, 0x1004));
        assert!(!DumpHandler::patch_overlaps_range(&patch, 0x2000, 0x3000));
    }

    #[test]
    fn test_agent_patch_entry_aliases() {
        let value = json!({
            "patch_id": 42,
            "address": 0x4000,
            "old_bytes": [0, 1],
            "new_bytes": [2, 3],
            "client_id": "client-1",
            "timestamp_ms": 1234,
            "active": false,
            "description": "legacy schema"
        });

        let entry: AgentPatchEntry = serde_json::from_value(value).unwrap();
        let patch: PatchEntry = entry.into();

        assert_eq!(patch.id, 42);
        assert_eq!(patch.address, 0x4000);
        assert_eq!(patch.original_bytes, vec![0, 1]);
        assert_eq!(patch.patched_bytes, vec![2, 3]);
        assert_eq!(patch.applied_by.as_deref(), Some("client-1"));
        assert_eq!(patch.timestamp, 1234);
        assert!(!patch.active);
        assert_eq!(patch.description.as_deref(), Some("legacy schema"));
    }

    #[test]
    fn test_patch_size_uses_max_len() {
        let mut patch = PatchEntry {
            id: 1,
            address: 0x1000,
            original_bytes: vec![0; 2],
            patched_bytes: vec![1; 4],
            timestamp: 0,
            applied_by: None,
            active: true,
            description: None,
        };
        assert_eq!(DumpHandler::patch_size(&patch), 4);
        patch.patched_bytes = vec![1; 1];
        patch.original_bytes = vec![0; 8];
        assert_eq!(DumpHandler::patch_size(&patch), 8);
    }

    #[test]
    fn test_extract_diff_changes_supports_changes() {
        let response = json!({
            "changes": [
                { "address": 0x10, "size": 4 },
                { "address": 0x20, "old_bytes": [1,2,3] }
            ]
        });

        let changes = DumpHandler::extract_diff_changes(&response);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].address, 0x10);
        assert_eq!(changes[0].size, 4);
        assert_eq!(changes[1].address, 0x20);
        assert_eq!(changes[1].size, 3);
    }

    #[test]
    fn test_extract_diff_changes_supports_differences() {
        let response = json!({
            "differences": [
                { "address": 0x30, "new_bytes": [1,2] }
            ]
        });

        let changes = DumpHandler::extract_diff_changes(&response);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].address, 0x30);
        assert_eq!(changes[0].size, 2);
    }

    #[test]
    fn test_annotate_diff_changes_maps_patch_ids() {
        let changes = vec![DumpDiffChange {
            address: 0x1000,
            size: 4,
        }];

        let patches = vec![
            PatchEntry {
                id: 1,
                address: 0x1002,
                original_bytes: vec![0; 2],
                patched_bytes: vec![1; 2],
                timestamp: 0,
                applied_by: None,
                active: true,
                description: None,
            },
            PatchEntry {
                id: 2,
                address: 0x2000,
                original_bytes: vec![0; 2],
                patched_bytes: vec![1; 2],
                timestamp: 0,
                applied_by: None,
                active: true,
                description: None,
            },
        ];

        let annotations = DumpHandler::annotate_diff_changes(&changes, &patches);
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0].patch_ids, vec![1]);
    }
}
