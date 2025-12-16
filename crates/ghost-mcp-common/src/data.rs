//! Embedded JSON data management
//!
//! Handles loading and validation of embedded JSON data files for tools,
//! categories, resources, prompts, and documentation.

use crate::types::ToolDocumentation;
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{debug, error};

// ============================================================================
// Embedded JSON Data (compile-time inclusion for zero runtime file I/O)
// ============================================================================

// Note: Paths are relative to this file (src/data.rs)
// This file is in crates/ghost-mcp-common/src/data.rs
// Data is in data/

/// Tools definitions loaded from data/tools.json
pub static TOOLS_JSON: &str = include_str!("../../../data/tools.json");
/// Tool categories loaded from data/categories.json  
pub static CATEGORIES_JSON: &str = include_str!("../../../data/categories.json");
/// Tool documentation loaded from data/tool_docs.json
pub static TOOL_DOCS_JSON: &str = include_str!("../../../data/tool_docs.json");
/// MCP resources loaded from data/resources.json
pub static RESOURCES_JSON: &str = include_str!("../../../data/resources.json");
/// MCP prompts loaded from data/prompts.json
pub static PROMPTS_JSON: &str = include_str!("../../../data/prompts.json");

/// Parsed tool documentation (lazy initialized on first access)
pub static TOOL_DOCS: OnceLock<HashMap<String, ToolDocumentation>> = OnceLock::new();

/// Get tool documentation map
pub fn get_tool_docs() -> &'static HashMap<String, ToolDocumentation> {
    TOOL_DOCS.get_or_init(|| serde_json::from_str(TOOL_DOCS_JSON).unwrap_or_default())
}

/// Validate that embedded JSON data is parseable (called during server init)
pub fn validate_embedded_json() -> Result<(), String> {
    // Validate tools.json
    let _: serde_json::Value =
        serde_json::from_str(TOOLS_JSON).map_err(|e| format!("Invalid tools.json: {}", e))?;

    // Validate categories.json
    let _: serde_json::Value = serde_json::from_str(CATEGORIES_JSON)
        .map_err(|e| format!("Invalid categories.json: {}", e))?;

    // Validate resources.json
    let _: serde_json::Value = serde_json::from_str(RESOURCES_JSON)
        .map_err(|e| format!("Invalid resources.json: {}", e))?;

    // Validate prompts.json
    let _: serde_json::Value =
        serde_json::from_str(PROMPTS_JSON).map_err(|e| format!("Invalid prompts.json: {}", e))?;

    // Validate tool_docs.json (more strict - must parse to HashMap)
    let _: HashMap<String, ToolDocumentation> = serde_json::from_str(TOOL_DOCS_JSON)
        .map_err(|e| format!("Invalid tool_docs.json: {}", e))?;

    Ok(())
}

/// Parse tools list from embedded JSON
pub fn parse_tools_list() -> Result<serde_json::Value, anyhow::Error> {
    debug!(target: "ghost_mcp_common::data", "Parsing tools list");
    serde_json::from_str(TOOLS_JSON).map_err(|e| {
        error!(target: "ghost_mcp_common::data", error = %e, "Failed to parse embedded tools.json");
        anyhow::anyhow!("Failed to parse tools.json: {}", e)
    })
}

/// Parse resources list from embedded JSON
pub fn parse_resources_list() -> Result<serde_json::Value, anyhow::Error> {
    debug!(target: "ghost_mcp_common::data", "Parsing resources list");
    serde_json::from_str(RESOURCES_JSON).map_err(|e| {
        error!(target: "ghost_mcp_common::data", error = %e, "Failed to parse embedded resources.json");
        anyhow::anyhow!("Failed to parse resources.json: {}", e)
    })
}

/// Parse prompts list from embedded JSON
pub fn parse_prompts_list() -> Result<serde_json::Value, anyhow::Error> {
    debug!(target: "ghost_mcp_common::data", "Parsing prompts list");
    serde_json::from_str(PROMPTS_JSON).map_err(|e| {
        error!(target: "ghost_mcp_common::data", error = %e, "Failed to parse embedded prompts.json");
        anyhow::anyhow!("Failed to parse prompts.json: {}", e)
    })
}

/// Parse categories from embedded JSON
pub fn parse_categories() -> Result<serde_json::Value, anyhow::Error> {
    debug!(target: "ghost_mcp_common::data", "Parsing categories");
    serde_json::from_str(CATEGORIES_JSON).map_err(|e| {
        error!(target: "ghost_mcp_common::data", error = %e, "Failed to parse embedded categories.json");
        anyhow::anyhow!("Failed to parse categories.json: {}", e)
    })
}
