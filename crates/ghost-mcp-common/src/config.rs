//! Server configuration
//!
//! Configuration handling for MCP servers.

use crate::error::{McpError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server name
    pub name: String,
    /// TCP port to listen on
    #[serde(default = "default_port")]
    pub port: u16,
    /// Agent TCP port
    #[serde(default = "default_agent_port")]
    pub agent_port: u16,
    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,
    /// Connection timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,
    /// Heartbeat configuration
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
}

/// Retry configuration for IPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    /// Backoff multiplier
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

/// Heartbeat configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Enable heartbeats
    #[serde(default = "default_heartbeat_enabled")]
    pub enabled: bool,
    /// Heartbeat interval in milliseconds
    #[serde(default = "default_heartbeat_interval_ms")]
    pub interval_ms: u64,
    /// Heartbeat timeout in milliseconds
    #[serde(default = "default_heartbeat_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum consecutive failures before triggering reconnect
    #[serde(default = "default_heartbeat_max_failures")]
    pub max_failures: u32,
}

// Default value functions
fn default_port() -> u16 {
    13340
}

fn default_agent_port() -> u16 {
    13338
}

fn default_timeout_ms() -> u64 {
    30000
}

fn default_max_retries() -> u32 {
    3
}

fn default_initial_backoff_ms() -> u64 {
    2000
}

fn default_max_backoff_ms() -> u64 {
    30000
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

fn default_heartbeat_enabled() -> bool {
    true
}

fn default_heartbeat_interval_ms() -> u64 {
    5000
}

fn default_heartbeat_timeout_ms() -> u64 {
    3000
}

fn default_heartbeat_max_failures() -> u32 {
    3
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "ghost-mcp".to_string(),
            port: default_port(),
            agent_port: default_agent_port(),
            verbose: false,
            timeout_ms: default_timeout_ms(),
            retry: RetryConfig::default(),
            heartbeat: HeartbeatConfig::default(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            backoff_multiplier: default_backoff_multiplier(),
        }
    }
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: default_heartbeat_enabled(),
            interval_ms: default_heartbeat_interval_ms(),
            timeout_ms: default_heartbeat_timeout_ms(),
            max_failures: default_heartbeat_max_failures(),
        }
    }
}

impl ServerConfig {
    /// Create a new config with the given name and port
    pub fn new(name: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            port,
            ..Default::default()
        }
    }

    /// Load configuration from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| McpError::Config(format!("Failed to read config file: {}", e)))?;
        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| McpError::Config(format!("Failed to parse config: {}", e)))
    }

    /// Create configuration for a specific server
    pub fn for_server(name: &str, port: u16) -> Self {
        Self::new(name, port)
    }
}

/// Pre-defined server configurations
impl ServerConfig {
    /// Configuration for ghost-core-mcp (port 13340)
    pub fn core() -> Self {
        Self::new("ghost-core-mcp", 13340)
    }

    /// Configuration for ghost-analysis-mcp (port 13341)
    pub fn analysis() -> Self {
        Self::new("ghost-analysis-mcp", 13341)
    }

    /// Configuration for ghost-static-mcp (port 13342)
    pub fn static_analysis() -> Self {
        Self::new("ghost-static-mcp", 13342)
    }

    /// Configuration for ghost-extended-mcp (port 13343)
    pub fn extended() -> Self {
        Self::new("ghost-extended-mcp", 13343)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 13340);
        assert_eq!(config.agent_port, 13338);
        assert!(!config.verbose);
    }

    #[test]
    fn test_server_configs() {
        assert_eq!(ServerConfig::core().port, 13340);
        assert_eq!(ServerConfig::analysis().port, 13341);
        assert_eq!(ServerConfig::static_analysis().port, 13342);
        assert_eq!(ServerConfig::extended().port, 13343);
    }

    #[test]
    fn test_from_toml() {
        let toml = r#"
            name = "test-server"
            port = 9999
            agent_port = 8888
            verbose = true
        "#;
        let config = ServerConfig::from_toml(toml).unwrap();
        assert_eq!(config.name, "test-server");
        assert_eq!(config.port, 9999);
        assert_eq!(config.agent_port, 8888);
        assert!(config.verbose);
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_ms, 2000);
        assert_eq!(config.max_backoff_ms, 30000);
    }

    #[test]
    fn test_heartbeat_config_defaults() {
        let config = HeartbeatConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_ms, 5000);
    }
}
