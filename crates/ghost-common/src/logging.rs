//! Logging utilities for Ghost-MCP
//!
//! Provides consistent logging configuration across all crates.
//! Supports both console and file logging with configurable options.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Global file logger handle
static FILE_LOGGER: Mutex<Option<File>> = Mutex::new(None);

/// Logging configuration matching config file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Enable console logging
    #[serde(default = "default_true")]
    pub console_enabled: bool,

    /// Enable file logging
    #[serde(default)]
    pub file_enabled: bool,

    /// Log file path
    #[serde(default = "default_log_path")]
    pub file_path: String,

    /// Include timestamps
    #[serde(default = "default_true")]
    pub timestamps: bool,

    /// Include file/line info
    #[serde(default)]
    pub file_info: bool,

    /// Include module target
    #[serde(default = "default_true")]
    pub show_target: bool,

    /// Use ANSI colors
    #[serde(default = "default_true")]
    pub ansi_colors: bool,

    /// Log level as string
    #[serde(default = "default_level")]
    pub level: String,
}

fn default_true() -> bool {
    true
}

fn default_log_path() -> String {
    "ghost-mcp.log".to_string()
}

fn default_level() -> String {
    "info".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            console_enabled: true,
            file_enabled: false,
            file_path: "ghost-mcp.log".to_string(),
            timestamps: true,
            file_info: false,
            show_target: true,
            ansi_colors: true,
            level: "info".to_string(),
        }
    }
}

impl LogConfig {
    /// Create a debug configuration with verbose output
    pub fn debug() -> Self {
        Self {
            level: "debug".to_string(),
            file_info: true,
            ..Default::default()
        }
    }

    /// Create a minimal configuration for DLL injection
    pub fn minimal() -> Self {
        Self {
            console_enabled: true,
            file_enabled: false,
            file_path: String::new(),
            timestamps: false,
            file_info: false,
            show_target: false,
            ansi_colors: false,
            level: "info".to_string(),
        }
    }

    /// Create config with file logging enabled
    pub fn with_file(mut self, path: &str) -> Self {
        self.file_enabled = true;
        self.file_path = path.to_string();
        self
    }

    /// Create config with console disabled (file only)
    pub fn file_only(path: &str) -> Self {
        Self {
            console_enabled: false,
            file_enabled: true,
            file_path: path.to_string(),
            ..Default::default()
        }
    }

    /// Set log level
    pub fn with_level(mut self, level: &str) -> Self {
        self.level = level.to_string();
        self
    }

    /// Parse level string to tracing Level
    pub fn get_level(&self) -> Level {
        match self.level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" | "warning" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    }
}

/// Initialize logging with the given configuration
///
/// Supports both console and file output. Can be called multiple times
/// but only the first call takes effect for the subscriber.
pub fn init_logging(config: &LogConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    // Set up file logging if enabled
    if config.file_enabled && !config.file_path.is_empty() {
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.file_path)
        {
            if let Ok(mut guard) = FILE_LOGGER.lock() {
                *guard = Some(file);
            }
        }
    }

    // Build subscriber based on configuration
    if config.console_enabled && config.file_enabled {
        // Both console and file
        let console_layer = fmt::layer()
            .with_ansi(config.ansi_colors)
            .with_target(config.show_target)
            .with_file(config.file_info)
            .with_line_number(config.file_info)
            .with_writer(std::io::stderr);

        let file_layer = fmt::layer()
            .with_ansi(false)
            .with_target(config.show_target)
            .with_file(config.file_info)
            .with_line_number(config.file_info)
            .with_writer(move || -> Box<dyn Write + Send> {
                if let Ok(guard) = FILE_LOGGER.lock() {
                    if let Some(ref file) = *guard {
                        if let Ok(f) = file.try_clone() {
                            return Box::new(f);
                        }
                    }
                }
                Box::new(std::io::sink())
            });

        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(console_layer)
            .with(file_layer);

        let _ = tracing::subscriber::set_global_default(subscriber);
    } else if config.file_enabled {
        // File only
        let file_layer = fmt::layer()
            .with_ansi(false)
            .with_target(config.show_target)
            .with_file(config.file_info)
            .with_line_number(config.file_info)
            .with_writer(move || -> Box<dyn Write + Send> {
                if let Ok(guard) = FILE_LOGGER.lock() {
                    if let Some(ref file) = *guard {
                        if let Ok(f) = file.try_clone() {
                            return Box::new(f);
                        }
                    }
                }
                Box::new(std::io::sink())
            });

        let subscriber = tracing_subscriber::registry().with(filter).with(file_layer);

        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        // Console only (default)
        let builder = fmt::Subscriber::builder()
            .with_env_filter(filter)
            .with_ansi(config.ansi_colors)
            .with_target(config.show_target)
            .with_file(config.file_info)
            .with_line_number(config.file_info);

        let result = if config.timestamps {
            builder.with_writer(std::io::stderr).try_init()
        } else {
            builder
                .without_time()
                .with_writer(std::io::stderr)
                .try_init()
        };

        let _ = result;
    }
}

/// Initialize logging for the agent (DLL context)
///
/// Enables file logging to {cwd}/ghost-agent-{pid}.log
pub fn init_agent_logging() {
    let mut config = LogConfig::minimal();

    // Enable file logging in current working directory with PID to avoid conflicts
    let mut path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    path.push(format!("ghost-agent-{}.log", std::process::id()));

    config.file_enabled = true;
    config.file_path = path.to_string_lossy().to_string();

    // Enable useful metadata for file logs
    config.timestamps = true;
    config.show_target = true;

    init_logging(&config);
}

/// Initialize logging for the host with default settings
pub fn init_host_logging() {
    init_logging(&LogConfig::default());
}

/// Initialize debug logging
pub fn init_debug_logging() {
    init_logging(&LogConfig::debug());
}

/// Initialize logging from a config file path
pub fn init_logging_from_file(path: &str) -> Result<(), String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read config file: {}", e))?;

    #[derive(Deserialize)]
    struct ConfigWrapper {
        #[serde(default)]
        logging: LogConfig,
        #[serde(default)]
        server: ServerConfig,
    }

    #[derive(Deserialize, Default)]
    struct ServerConfig {
        #[serde(default = "default_level")]
        log_level: String,
    }

    let wrapper: ConfigWrapper =
        toml::from_str(&content).map_err(|e| format!("Failed to parse config file: {}", e))?;

    // Use server.log_level if logging.level not set
    let mut config = wrapper.logging;
    if config.level == "info" && wrapper.server.log_level != "info" {
        config.level = wrapper.server.log_level;
    }

    init_logging(&config);
    Ok(())
}

/// Get the log file path if file logging is active
pub fn get_log_file_path() -> Option<PathBuf> {
    if let Ok(guard) = FILE_LOGGER.lock() {
        if guard.is_some() {
            return Some(PathBuf::from("ghost-mcp.log"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert!(config.console_enabled);
        assert!(!config.file_enabled);
        assert!(config.timestamps);
        assert!(!config.file_info);
        assert_eq!(config.level, "info");
    }

    #[test]
    fn test_log_config_debug() {
        let config = LogConfig::debug();
        assert_eq!(config.level, "debug");
        assert!(config.file_info);
    }

    #[test]
    fn test_log_config_minimal() {
        let config = LogConfig::minimal();
        assert!(!config.timestamps);
        assert!(!config.file_info);
        assert!(!config.show_target);
    }

    #[test]
    fn test_log_config_with_file() {
        let config = LogConfig::default().with_file("test.log");
        assert!(config.file_enabled);
        assert_eq!(config.file_path, "test.log");
    }

    #[test]
    fn test_log_config_file_only() {
        let config = LogConfig::file_only("test.log");
        assert!(!config.console_enabled);
        assert!(config.file_enabled);
    }

    #[test]
    fn test_get_level() {
        assert_eq!(LogConfig::default().get_level(), Level::INFO);
        assert_eq!(LogConfig::debug().get_level(), Level::DEBUG);
        assert_eq!(
            LogConfig::default().with_level("trace").get_level(),
            Level::TRACE
        );
        assert_eq!(
            LogConfig::default().with_level("error").get_level(),
            Level::ERROR
        );
    }

    #[test]
    fn test_config_serialization() {
        let config = LogConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: LogConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.console_enabled, config.console_enabled);
        assert_eq!(parsed.level, config.level);
    }
}
