//! Error types for ghost-mcp-common
//!
//! Provides unified error handling across all MCP servers.

use thiserror::Error;

/// Result type alias for MCP operations
pub type Result<T> = std::result::Result<T, McpError>;

/// MCP error types
#[derive(Debug, Error)]
pub enum McpError {
    /// Tool registry errors
    #[error("Registry error: {0}")]
    Registry(String),

    /// Tool count exceeds maximum
    #[error("Tool count {count} exceeds maximum {max}")]
    ToolCountExceeded { count: usize, max: usize },

    /// Duplicate tool registration
    #[error("Duplicate tool: {0}")]
    DuplicateTool(String),

    /// Tool not found
    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    /// Prompt not found
    #[error("Prompt not found: {0}")]
    PromptNotFound(String),

    /// IPC connection error
    #[error("IPC connection error: {0}")]
    Connection(String),

    /// IPC request timeout
    #[error("IPC request timeout after {0}ms")]
    Timeout(u64),

    /// IPC protocol error
    #[error("IPC protocol error: {0}")]
    Protocol(String),

    /// Agent not connected
    #[error("Agent not connected")]
    AgentNotConnected,

    /// Agent error response
    #[error("Agent error [{code}]: {message}")]
    AgentError { code: i32, message: String },

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Handler error
    #[error("Handler error: {0}")]
    Handler(String),

    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl McpError {
    /// Convert to JSON-RPC error code
    pub fn to_jsonrpc_code(&self) -> i32 {
        match self {
            McpError::InvalidParams(_) => -32602,
            McpError::ToolNotFound(_) | McpError::PromptNotFound(_) => -32601,
            McpError::Protocol(_) | McpError::Serialization(_) => -32700,
            McpError::AgentNotConnected | McpError::Connection(_) => -32003,
            McpError::Timeout(_) => -32004,
            McpError::AgentError { code, .. } => *code,
            _ => -32603,
        }
    }

    /// Create a handler error
    pub fn handler(msg: impl Into<String>) -> Self {
        McpError::Handler(msg.into())
    }

    /// Create an invalid params error
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        McpError::InvalidParams(msg.into())
    }

    /// Create a connection error
    pub fn connection(msg: impl Into<String>) -> Self {
        McpError::Connection(msg.into())
    }
}

impl From<anyhow::Error> for McpError {
    fn from(err: anyhow::Error) -> Self {
        McpError::Internal(err.to_string())
    }
}
