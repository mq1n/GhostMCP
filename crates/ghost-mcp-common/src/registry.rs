//! Tool Registry
//!
//! Manages tool registration with <90 tools enforcement per server.
//! Provides compile-time and runtime validation.

use crate::error::{McpError, Result};
use crate::types::{ToolDocumentation, ToolParameter};
use crate::MAX_TOOLS_PER_SERVER;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Tool handler function type
pub type ToolHandler = Arc<
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send>>
        + Send
        + Sync,
>;

/// Tool definition with metadata and handler
#[derive(Clone)]
pub struct ToolDefinition {
    /// Tool name (must be unique within registry)
    pub name: String,
    /// Short description for MCP discovery
    pub description: String,
    /// Category for organization
    pub category: String,
    /// Input schema for the tool
    pub input_schema: ToolInputSchema,
    /// Full documentation
    pub documentation: Option<ToolDocumentation>,
    /// Handler function (None for tools that need agent)
    handler: Option<ToolHandler>,
}

impl std::fmt::Debug for ToolDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolDefinition")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("category", &self.category)
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

/// JSON Schema for tool input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInputSchema {
    /// Schema type (always "object" for tool inputs)
    #[serde(rename = "type")]
    pub schema_type: String,
    /// Property definitions
    #[serde(default)]
    pub properties: HashMap<String, PropertySchema>,
    /// Required property names
    #[serde(default)]
    pub required: Vec<String>,
    /// Additional properties allowed
    #[serde(default = "default_additional_properties")]
    #[serde(rename = "additionalProperties")]
    pub additional_properties: bool,
}

fn default_additional_properties() -> bool {
    false
}

/// Property schema within tool input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySchema {
    /// JSON Schema type
    #[serde(rename = "type")]
    pub prop_type: String,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Default value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// Enum values
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<serde_json::Value>>,
}

impl PropertySchema {
    /// Create a string property
    pub fn string(description: &str) -> Self {
        Self {
            prop_type: "string".to_string(),
            description: Some(description.to_string()),
            default: None,
            enum_values: None,
        }
    }

    /// Create an integer property
    pub fn integer(description: &str) -> Self {
        Self {
            prop_type: "integer".to_string(),
            description: Some(description.to_string()),
            default: None,
            enum_values: None,
        }
    }

    /// Create a number property
    pub fn number(description: &str) -> Self {
        Self {
            prop_type: "number".to_string(),
            description: Some(description.to_string()),
            default: None,
            enum_values: None,
        }
    }

    /// Create a boolean property
    pub fn boolean(description: &str) -> Self {
        Self {
            prop_type: "boolean".to_string(),
            description: Some(description.to_string()),
            default: None,
            enum_values: None,
        }
    }

    /// Create an array property
    pub fn array(description: &str) -> Self {
        Self {
            prop_type: "array".to_string(),
            description: Some(description.to_string()),
            default: None,
            enum_values: None,
        }
    }

    /// Create an object property
    pub fn object(description: &str) -> Self {
        Self {
            prop_type: "object".to_string(),
            description: Some(description.to_string()),
            default: None,
            enum_values: None,
        }
    }

    /// Create a string property with enum values
    pub fn string_enum(description: &str, values: Vec<&str>) -> Self {
        Self {
            prop_type: "string".to_string(),
            description: Some(description.to_string()),
            default: None,
            enum_values: Some(values.into_iter().map(|v| serde_json::json!(v)).collect()),
        }
    }

    /// Add a default value
    pub fn with_default<T: Into<serde_json::Value>>(mut self, value: T) -> Self {
        self.default = Some(value.into());
        self
    }
}

impl ToolInputSchema {
    /// Create an empty schema (no parameters)
    pub fn empty() -> Self {
        Self {
            schema_type: "object".to_string(),
            properties: HashMap::new(),
            required: Vec::new(),
            additional_properties: false,
        }
    }

    /// Create a schema from parameters
    pub fn from_params(params: Vec<ToolParameter>) -> Self {
        let mut properties = HashMap::new();
        let mut required = Vec::new();

        for param in params {
            if param.required {
                required.push(param.name.clone());
            }
            properties.insert(
                param.name,
                PropertySchema {
                    prop_type: param.param_type,
                    description: Some(param.description),
                    default: param.default,
                    enum_values: param
                        .enum_values
                        .map(|v| v.into_iter().map(serde_json::Value::String).collect()),
                },
            );
        }

        Self {
            schema_type: "object".to_string(),
            properties,
            required,
            additional_properties: false,
        }
    }
}

impl ToolDefinition {
    /// Create a new tool definition
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            category: category.into(),
            input_schema: ToolInputSchema::empty(),
            documentation: None,
            handler: None,
        }
    }

    /// Set the input schema
    pub fn with_schema(mut self, schema: ToolInputSchema) -> Self {
        self.input_schema = schema;
        self
    }

    /// Set the handler function
    pub fn with_handler<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(serde_json::Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<serde_json::Value>> + Send + 'static,
    {
        self.handler = Some(Arc::new(move |args| Box::pin(handler(args))));
        self
    }

    /// Set documentation
    pub fn with_docs(mut self, docs: ToolDocumentation) -> Self {
        self.documentation = Some(docs);
        self
    }

    /// Check if tool has a handler
    pub fn has_handler(&self) -> bool {
        self.handler.is_some()
    }

    /// Get the handler if present
    pub fn handler(&self) -> Option<&ToolHandler> {
        self.handler.as_ref()
    }

    /// Convert to MCP tool schema format
    pub fn to_mcp_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema
        })
    }
}

/// Tool registry with count enforcement
#[derive(Debug, Default)]
pub struct ToolRegistry {
    /// Registered tools by name
    tools: HashMap<String, ToolDefinition>,
    /// Tools organized by category
    categories: HashMap<String, Vec<String>>,
    /// Maximum allowed tools
    max_tools: usize,
}

impl ToolRegistry {
    /// Create a new registry with default max tools
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            categories: HashMap::new(),
            max_tools: MAX_TOOLS_PER_SERVER,
        }
    }

    /// Create a registry with custom max tools limit
    pub fn with_max_tools(max_tools: usize) -> Self {
        Self {
            tools: HashMap::new(),
            categories: HashMap::new(),
            max_tools,
        }
    }

    /// Register a tool
    pub fn register(&mut self, tool: ToolDefinition) -> Result<()> {
        // Check for duplicates
        if self.tools.contains_key(&tool.name) {
            return Err(McpError::DuplicateTool(tool.name));
        }

        // Check tool count
        if self.tools.len() >= self.max_tools {
            return Err(McpError::ToolCountExceeded {
                count: self.tools.len() + 1,
                max: self.max_tools,
            });
        }

        // Add to category index
        self.categories
            .entry(tool.category.clone())
            .or_default()
            .push(tool.name.clone());

        // Add tool
        self.tools.insert(tool.name.clone(), tool);

        Ok(())
    }

    /// Register multiple tools at once
    pub fn register_all(&mut self, tools: Vec<ToolDefinition>) -> Result<()> {
        // Pre-check count
        let new_total = self.tools.len() + tools.len();
        if new_total > self.max_tools {
            return Err(McpError::ToolCountExceeded {
                count: new_total,
                max: self.max_tools,
            });
        }

        for tool in tools {
            self.register(tool)?;
        }

        Ok(())
    }

    /// Get a tool by name
    pub fn get(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.get(name)
    }

    /// Get all tools
    pub fn tools(&self) -> impl Iterator<Item = &ToolDefinition> {
        self.tools.values()
    }

    /// Get tools by category
    pub fn by_category(&self, category: &str) -> Vec<&ToolDefinition> {
        self.categories
            .get(category)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| self.tools.get(name))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all category names
    pub fn categories(&self) -> Vec<&str> {
        self.categories.keys().map(|s| s.as_str()).collect()
    }

    /// Get tool count
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        self.max_tools.saturating_sub(self.tools.len())
    }

    /// Validate registry (for CI/build checks)
    pub fn validate(&self) -> Result<()> {
        if self.tools.len() > self.max_tools {
            return Err(McpError::ToolCountExceeded {
                count: self.tools.len(),
                max: self.max_tools,
            });
        }
        Ok(())
    }

    /// Export tool list for MCP discovery
    pub fn to_mcp_tools(&self) -> Vec<serde_json::Value> {
        self.tools.values().map(|t| t.to_mcp_schema()).collect()
    }

    /// Get summary for logging
    pub fn summary(&self) -> String {
        let cats: Vec<_> = self
            .categories
            .iter()
            .map(|(cat, tools)| format!("{}: {}", cat, tools.len()))
            .collect();
        format!(
            "{} tools registered ({}/{}): [{}]",
            self.tools.len(),
            self.tools.len(),
            self.max_tools,
            cats.join(", ")
        )
    }
}

/// Compile-time tool count validation macro
#[macro_export]
macro_rules! assert_tool_count {
    ($registry:expr) => {
        assert!(
            $registry.len() <= $crate::MAX_TOOLS_PER_SERVER,
            "Tool count {} exceeds maximum {}",
            $registry.len(),
            $crate::MAX_TOOLS_PER_SERVER
        );
    };
    ($registry:expr, $max:expr) => {
        assert!(
            $registry.len() <= $max,
            "Tool count {} exceeds maximum {}",
            $registry.len(),
            $max
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.remaining_capacity(), MAX_TOOLS_PER_SERVER);
    }

    #[test]
    fn test_register_tool() {
        let mut registry = ToolRegistry::new();
        let tool = ToolDefinition::new("test_tool", "A test tool", "test");
        registry.register(tool).unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_duplicate_tool_error() {
        let mut registry = ToolRegistry::new();
        let tool1 = ToolDefinition::new("test_tool", "First", "test");
        let tool2 = ToolDefinition::new("test_tool", "Second", "test");
        registry.register(tool1).unwrap();
        let result = registry.register(tool2);
        assert!(matches!(result, Err(McpError::DuplicateTool(_))));
    }

    #[test]
    fn test_max_tools_enforcement() {
        let mut registry = ToolRegistry::with_max_tools(3);
        for i in 0..3 {
            let tool = ToolDefinition::new(format!("tool_{}", i), "desc", "test");
            registry.register(tool).unwrap();
        }
        let tool = ToolDefinition::new("overflow_tool", "desc", "test");
        let result = registry.register(tool);
        assert!(matches!(result, Err(McpError::ToolCountExceeded { .. })));
    }

    #[test]
    fn test_categories() {
        let mut registry = ToolRegistry::new();
        registry
            .register(ToolDefinition::new("mem_read", "Read memory", "memory"))
            .unwrap();
        registry
            .register(ToolDefinition::new("mem_write", "Write memory", "memory"))
            .unwrap();
        registry
            .register(ToolDefinition::new("mod_list", "List modules", "module"))
            .unwrap();

        let memory_tools = registry.by_category("memory");
        assert_eq!(memory_tools.len(), 2);

        let cats = registry.categories();
        assert!(cats.contains(&"memory"));
        assert!(cats.contains(&"module"));
    }

    #[test]
    fn test_to_mcp_schema() {
        let tool = ToolDefinition::new("test", "Test tool", "test");
        let schema = tool.to_mcp_schema();
        assert_eq!(schema["name"], "test");
        assert_eq!(schema["description"], "Test tool");
    }

    #[test]
    fn test_input_schema_from_params() {
        let params = vec![
            ToolParameter {
                name: "address".to_string(),
                param_type: "string".to_string(),
                description: "Memory address".to_string(),
                required: true,
                default: None,
                enum_values: None,
            },
            ToolParameter {
                name: "size".to_string(),
                param_type: "integer".to_string(),
                description: "Size in bytes".to_string(),
                required: false,
                default: Some(serde_json::json!(256)),
                enum_values: None,
            },
        ];

        let schema = ToolInputSchema::from_params(params);
        assert_eq!(schema.required.len(), 1);
        assert!(schema.required.contains(&"address".to_string()));
        assert_eq!(schema.properties.len(), 2);
    }
}
