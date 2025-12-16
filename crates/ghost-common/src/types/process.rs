//! Process attachment and launch types

use serde::{Deserialize, Serialize};

/// How to attach to the target process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttachMode {
    /// Attach to an already running process by PID
    Pid(u32),

    /// Attach to an already running process by name
    ProcessName(String),

    /// Wait for a process with the given name to start, then attach
    WaitForProcess {
        name: String,
        /// Timeout in seconds (None = wait forever)
        timeout_secs: Option<u64>,
        /// Delay after process is detected before attaching (ms)
        attach_delay_ms: Option<u64>,
    },

    /// Launch the process ourselves, then attach
    Launch(ProcessLaunchConfig),
}

impl Default for AttachMode {
    fn default() -> Self {
        Self::ProcessName("target.exe".to_string())
    }
}

/// Configuration for launching a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLaunchConfig {
    /// Path to the executable
    pub executable: String,

    /// Command line arguments
    pub args: Vec<String>,

    /// Working directory (None = inherit from loader)
    pub working_dir: Option<String>,

    /// Environment variables to set (in addition to inherited)
    pub env: Vec<(String, String)>,

    /// How to start the process
    pub start_mode: ProcessStartMode,

    /// Delay before injection after process start (ms)
    pub inject_delay_ms: Option<u64>,
}

impl ProcessLaunchConfig {
    pub fn new(executable: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            args: Vec::new(),
            working_dir: None,
            env: Vec::new(),
            start_mode: ProcessStartMode::Normal,
            inject_delay_ms: None,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    pub fn with_start_mode(mut self, mode: ProcessStartMode) -> Self {
        self.start_mode = mode;
        self
    }

    pub fn with_inject_delay(mut self, delay_ms: u64) -> Self {
        self.inject_delay_ms = Some(delay_ms);
        self
    }
}

/// How to start a launched process
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProcessStartMode {
    /// Start normally, inject immediately after process creation
    #[default]
    Normal,

    /// Start suspended (CREATE_SUSPENDED), inject, then resume
    /// Best for early injection before any target code runs
    Suspended,

    /// Start normally but wait for main module to load before injecting
    WaitForMainModule,

    /// Start normally, wait for a specific delay, then inject
    Delayed {
        /// Delay in milliseconds after process creation
        delay_ms: u64,
    },

    /// Start with DEBUG_PROCESS flag for debugging control
    /// Allows breaking at entry point
    Debug,

    /// Start and wait for specific module to load before injecting
    WaitForModule {
        /// Module name to wait for (e.g., "user32.dll")
        module_name: String,
        /// Timeout in milliseconds
        timeout_ms: u64,
    },
}

/// Result of a process launch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    /// Process ID of the launched process
    pub pid: u32,
    /// Thread ID of the main thread
    pub tid: u32,
    /// Whether the process is currently suspended
    pub suspended: bool,
    /// Base address of the main module (if available)
    pub main_module_base: Option<usize>,
}

/// Options for delayed attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayedAttachConfig {
    /// Initial delay before first attachment attempt (ms)
    pub initial_delay_ms: u64,
    /// Retry interval if attachment fails (ms)
    pub retry_interval_ms: u64,
    /// Maximum number of retries (None = infinite)
    pub max_retries: Option<u32>,
    /// Wait for specific module before attaching
    pub wait_for_module: Option<String>,
}

/// Process information for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// Executable path
    pub path: Option<String>,
    /// Architecture (x86, x64)
    pub arch: String,
    /// Whether the process is 64-bit
    pub is_64bit: bool,
    /// Number of threads
    pub thread_count: u32,
    /// Session ID
    pub session_id: u32,
}

/// Process spawn options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpawnOptions {
    /// Command line arguments
    pub args: Vec<String>,
    /// Working directory
    pub working_dir: Option<String>,
    /// Environment variables (key=value)
    pub env: Vec<(String, String)>,
    /// Start suspended
    pub suspended: bool,
    /// Inject agent after spawn
    pub inject: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attach_mode_pid() {
        let mode = AttachMode::Pid(1234);
        if let AttachMode::Pid(pid) = mode {
            assert_eq!(pid, 1234);
        } else {
            panic!("Expected Pid variant");
        }
    }

    #[test]
    fn test_attach_mode_process_name() {
        let mode = AttachMode::ProcessName("game.exe".to_string());
        if let AttachMode::ProcessName(name) = mode {
            assert_eq!(name, "game.exe");
        } else {
            panic!("Expected ProcessName variant");
        }
    }

    #[test]
    fn test_attach_mode_wait_for_process() {
        let mode = AttachMode::WaitForProcess {
            name: "target.exe".to_string(),
            timeout_secs: Some(60),
            attach_delay_ms: Some(1000),
        };
        if let AttachMode::WaitForProcess {
            name,
            timeout_secs,
            attach_delay_ms,
        } = mode
        {
            assert_eq!(name, "target.exe");
            assert_eq!(timeout_secs, Some(60));
            assert_eq!(attach_delay_ms, Some(1000));
        } else {
            panic!("Expected WaitForProcess variant");
        }
    }

    #[test]
    fn test_attach_mode_default() {
        let mode = AttachMode::default();
        if let AttachMode::ProcessName(name) = mode {
            assert_eq!(name, "target.exe");
        } else {
            panic!("Expected default to be ProcessName");
        }
    }

    #[test]
    fn test_process_launch_config_new() {
        let config = ProcessLaunchConfig::new("C:\\game\\game.exe");
        assert_eq!(config.executable, "C:\\game\\game.exe");
        assert!(config.args.is_empty());
        assert!(config.working_dir.is_none());
        assert!(config.env.is_empty());
        assert_eq!(config.start_mode, ProcessStartMode::Normal);
        assert!(config.inject_delay_ms.is_none());
    }

    #[test]
    fn test_process_launch_config_builder_pattern() {
        let config = ProcessLaunchConfig::new("test.exe")
            .with_args(vec!["--arg1".to_string()])
            .with_working_dir("C:\\work")
            .with_start_mode(ProcessStartMode::Suspended)
            .with_inject_delay(500);

        assert_eq!(config.executable, "test.exe");
        assert_eq!(config.args, vec!["--arg1"]);
        assert_eq!(config.working_dir, Some("C:\\work".to_string()));
        assert_eq!(config.start_mode, ProcessStartMode::Suspended);
        assert_eq!(config.inject_delay_ms, Some(500));
    }

    #[test]
    fn test_process_start_mode_variants() {
        assert_eq!(ProcessStartMode::default(), ProcessStartMode::Normal);
        assert_ne!(ProcessStartMode::Normal, ProcessStartMode::Suspended);
        assert_ne!(ProcessStartMode::Suspended, ProcessStartMode::Debug);
    }

    #[test]
    fn test_process_start_mode_delayed() {
        let mode = ProcessStartMode::Delayed { delay_ms: 5000 };
        if let ProcessStartMode::Delayed { delay_ms } = mode {
            assert_eq!(delay_ms, 5000);
        } else {
            panic!("Expected Delayed variant");
        }
    }

    #[test]
    fn test_process_start_mode_wait_for_module() {
        let mode = ProcessStartMode::WaitForModule {
            module_name: "user32.dll".to_string(),
            timeout_ms: 30000,
        };
        if let ProcessStartMode::WaitForModule {
            module_name,
            timeout_ms,
        } = mode
        {
            assert_eq!(module_name, "user32.dll");
            assert_eq!(timeout_ms, 30000);
        } else {
            panic!("Expected WaitForModule variant");
        }
    }

    #[test]
    fn test_launch_result_fields() {
        let result = LaunchResult {
            pid: 1234,
            tid: 5678,
            suspended: true,
            main_module_base: Some(0x140000000),
        };
        assert_eq!(result.pid, 1234);
        assert_eq!(result.tid, 5678);
        assert!(result.suspended);
        assert_eq!(result.main_module_base, Some(0x140000000));
    }

    #[test]
    fn test_delayed_attach_config() {
        let config = DelayedAttachConfig {
            initial_delay_ms: 1000,
            retry_interval_ms: 500,
            max_retries: Some(5),
            wait_for_module: Some("kernel32.dll".to_string()),
        };
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.retry_interval_ms, 500);
        assert_eq!(config.max_retries, Some(5));
        assert_eq!(config.wait_for_module, Some("kernel32.dll".to_string()));
    }

    #[test]
    fn test_attach_mode_serialization() {
        let mode = AttachMode::Pid(42);
        let json = serde_json::to_string(&mode).unwrap();
        let parsed: AttachMode = serde_json::from_str(&json).unwrap();
        if let AttachMode::Pid(pid) = parsed {
            assert_eq!(pid, 42);
        } else {
            panic!("Deserialization failed");
        }
    }

    #[test]
    fn test_process_launch_config_serialization() {
        let config =
            ProcessLaunchConfig::new("test.exe").with_start_mode(ProcessStartMode::Suspended);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ProcessLaunchConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.executable, "test.exe");
        assert_eq!(parsed.start_mode, ProcessStartMode::Suspended);
    }

    #[test]
    fn test_spawn_options_default() {
        let opts = SpawnOptions::default();
        assert!(opts.args.is_empty());
        assert!(opts.working_dir.is_none());
        assert!(!opts.suspended);
        assert!(!opts.inject);
    }

    #[test]
    fn test_process_info_serialization() {
        let info = ProcessInfo {
            pid: 1234,
            name: "test.exe".to_string(),
            parent_pid: Some(100),
            path: Some("C:\\test.exe".to_string()),
            arch: "x64".to_string(),
            is_64bit: true,
            thread_count: 10,
            session_id: 1,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ProcessInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, 1234);
        assert!(parsed.is_64bit);
    }
}
