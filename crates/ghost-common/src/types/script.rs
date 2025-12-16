//! Scripting engine types

use serde::{Deserialize, Serialize};

use super::thread::Registers;

/// Unique identifier for a loaded script
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScriptId(pub u32);

/// Script execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptStatus {
    /// Script is loaded but not yet started
    Loaded,
    /// Script is currently running
    Running,
    /// Script is paused
    Paused,
    /// Script has been stopped
    Stopped,
    /// Script encountered an error
    Error,
}

/// Information about a loaded script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInfo {
    /// Unique script identifier
    pub id: ScriptId,
    /// Script name (filename or user-provided)
    pub name: String,
    /// Script source (file path or "inline")
    pub source: String,
    /// Current status
    pub status: ScriptStatus,
    /// Number of active hooks from this script
    pub hook_count: u32,
    /// Number of exported RPC functions
    pub rpc_count: u32,
    /// Load timestamp (Unix epoch seconds)
    pub loaded_at: u64,
    /// Last error message if status is Error
    pub last_error: Option<String>,
}

/// Script hook type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookType {
    /// Inline hook (detour)
    Inline,
    /// Import Address Table hook
    IAT,
    /// Virtual Method Table hook
    VMT,
    /// Hardware breakpoint hook
    Hardware,
}

/// Hook callback type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallbackType {
    /// Called when entering the hooked function
    OnEnter,
    /// Called when leaving the hooked function
    OnLeave,
    /// Called when an exception occurs
    OnException,
}

/// Information about a script hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptHook {
    /// Hook identifier
    pub id: u32,
    /// Script that owns this hook
    pub script_id: ScriptId,
    /// Target address
    pub address: usize,
    /// Hook type
    pub hook_type: HookType,
    /// Whether the hook is currently enabled
    pub enabled: bool,
    /// Hit count
    pub hit_count: u64,
    /// Registered callbacks
    pub callbacks: Vec<CallbackType>,
}

/// Hook callback context passed to script callbacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookContext {
    /// Hook identifier
    pub hook_id: u32,
    /// Current CPU registers
    pub registers: Registers,
    /// Return address (for onEnter)
    pub return_address: Option<usize>,
    /// Return value (for onLeave, register-based)
    pub return_value: Option<u64>,
    /// Thread ID that triggered the hook
    pub thread_id: u32,
    /// Stack snapshot (top N bytes)
    pub stack: Vec<u8>,
}

/// Script RPC function information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptRpc {
    /// RPC function name
    pub name: String,
    /// Script that exports this RPC
    pub script_id: ScriptId,
    /// Parameter names (for documentation)
    pub params: Vec<String>,
    /// Description
    pub description: Option<String>,
}

/// Result of an RPC call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResult {
    /// Success flag
    pub success: bool,
    /// Return value (JSON)
    pub value: serde_json::Value,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution time in microseconds
    pub duration_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_id_equality() {
        let id1 = ScriptId(1);
        let id2 = ScriptId(1);
        let id3 = ScriptId(2);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_script_status_variants() {
        assert_ne!(ScriptStatus::Loaded, ScriptStatus::Running);
        assert_ne!(ScriptStatus::Running, ScriptStatus::Paused);
        assert_ne!(ScriptStatus::Paused, ScriptStatus::Stopped);
        assert_ne!(ScriptStatus::Stopped, ScriptStatus::Error);
    }

    #[test]
    fn test_script_info_serialization() {
        let info = ScriptInfo {
            id: ScriptId(1),
            name: "test_script.js".to_string(),
            source: "/scripts/test_script.js".to_string(),
            status: ScriptStatus::Running,
            hook_count: 5,
            rpc_count: 2,
            loaded_at: 1234567890,
            last_error: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ScriptInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, ScriptId(1));
        assert_eq!(parsed.name, "test_script.js");
        assert_eq!(parsed.status, ScriptStatus::Running);
    }

    #[test]
    fn test_hook_type_variants() {
        assert_ne!(HookType::Inline, HookType::IAT);
        assert_ne!(HookType::IAT, HookType::VMT);
        assert_ne!(HookType::VMT, HookType::Hardware);
    }

    #[test]
    fn test_callback_type_variants() {
        assert_ne!(CallbackType::OnEnter, CallbackType::OnLeave);
        assert_ne!(CallbackType::OnLeave, CallbackType::OnException);
    }

    #[test]
    fn test_script_hook_serialization() {
        let hook = ScriptHook {
            id: 1,
            script_id: ScriptId(1),
            address: 0x140001000,
            hook_type: HookType::Inline,
            enabled: true,
            hit_count: 100,
            callbacks: vec![CallbackType::OnEnter, CallbackType::OnLeave],
        };
        let json = serde_json::to_string(&hook).unwrap();
        let parsed: ScriptHook = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.address, 0x140001000);
        assert!(parsed.enabled);
    }

    #[test]
    fn test_rpc_result_success() {
        let result = RpcResult {
            success: true,
            value: serde_json::json!({"data": "test"}),
            error: None,
            duration_us: 1500,
        };
        assert!(result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_rpc_result_error() {
        let result = RpcResult {
            success: false,
            value: serde_json::Value::Null,
            error: Some("Function not found".to_string()),
            duration_us: 100,
        };
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
