//! Common types for MCP servers
//!
//! Shared type definitions used across all Ghost-MCP servers.

use serde::{Deserialize, Serialize};

/// Tool parameter schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameter {
    /// Parameter name
    pub name: String,
    /// JSON Schema type (string, number, boolean, object, array)
    #[serde(rename = "type")]
    pub param_type: String,
    /// Human-readable description
    pub description: String,
    /// Whether the parameter is required
    #[serde(default)]
    pub required: bool,
    /// Default value if not provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// Enum values for constrained parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
}

/// Tool example for documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExample {
    /// Example description
    pub description: String,
    /// Example arguments as JSON
    pub arguments: serde_json::Value,
    /// Expected result description
    pub expected: String,
}

/// Tool documentation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDocumentation {
    /// Tool name
    pub name: String,
    /// Category (memory, module, debug, etc.)
    pub category: String,
    /// Short description
    pub description: String,
    /// Detailed help text
    pub help: String,
    /// Usage examples
    #[serde(default)]
    pub examples: Vec<ToolExample>,
    /// Related tool names
    #[serde(default)]
    pub related: Vec<String>,
}

/// MCP tool call result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Content blocks for the result
    pub content: Vec<ContentBlock>,
    /// Whether this is an error result
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[serde(rename = "isError")]
    pub is_error: bool,
}

/// Content block in a tool result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    /// Text content
    #[serde(rename = "text")]
    Text { text: String },
    /// Image content (base64 encoded)
    #[serde(rename = "image")]
    Image { data: String, mime_type: String },
    /// Resource reference
    #[serde(rename = "resource")]
    Resource { uri: String },
}

impl ToolResult {
    /// Create a successful text result
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::Text {
                text: content.into(),
            }],
            is_error: false,
        }
    }

    /// Create a successful JSON result
    pub fn json<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        let text = serde_json::to_string_pretty(value)?;
        Ok(Self::text(text))
    }

    /// Create an error result
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::Text {
                text: message.into(),
            }],
            is_error: true,
        }
    }

    /// Convert to JSON value for MCP protocol
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "content": self.content,
            "isError": self.is_error
        })
    }
}

/// Health check status for a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Component name
    pub name: String,
    /// Whether component is healthy
    pub ok: bool,
    /// Status message
    pub message: String,
    /// Optional additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Overall server health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHealth {
    /// Whether all components are healthy
    pub healthy: bool,
    /// Timestamp of health check (Unix seconds)
    pub checked_at: u64,
    /// Duration of health check in milliseconds
    pub check_duration_ms: u64,
    /// Individual component statuses
    pub components: Vec<HealthStatus>,
    /// Diagnostic messages
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

/// Server capability advertisement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Server name
    pub name: String,
    /// Server version
    pub version: String,
    /// Server description
    pub description: String,
    /// Default port
    pub port: u16,
    /// Tool count
    pub tool_count: usize,
    /// Categories of tools provided
    pub categories: Vec<String>,
    /// Whether agent connection is required
    pub requires_agent: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_result_text() {
        let result = ToolResult::text("Hello, world!");
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
    }

    #[test]
    fn test_tool_result_error() {
        let result = ToolResult::error("Something went wrong");
        assert!(result.is_error);
    }

    #[test]
    fn test_tool_result_json() {
        let data = serde_json::json!({"key": "value"});
        let result = ToolResult::json(&data).unwrap();
        assert!(!result.is_error);
    }

    #[test]
    fn test_tool_parameter_serialization() {
        let param = ToolParameter {
            name: "address".to_string(),
            param_type: "string".to_string(),
            description: "Memory address".to_string(),
            required: true,
            default: None,
            enum_values: None,
        };
        let json = serde_json::to_string(&param).unwrap();
        assert!(json.contains("\"type\":\"string\""));
    }
}
