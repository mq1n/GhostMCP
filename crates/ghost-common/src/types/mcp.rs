//! MCP meta command types

use serde::{Deserialize, Serialize};

/// Tool category for organization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolCategory {
    /// Memory operations (read, write, search)
    Memory,
    /// Module operations (list, exports, imports)
    Module,
    /// Debugging operations (breakpoints, stepping)
    Debug,
    /// Disassembly operations
    Disasm,
    /// Scripting operations
    Script,
    /// Session management
    Session,
    /// Process control
    Process,
    /// Meta/utility commands
    Meta,
}

/// Tool documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDocumentation {
    /// Tool name
    pub name: String,
    /// Category
    pub category: ToolCategory,
    /// Short description
    pub description: String,
    /// Detailed help text
    pub help: String,
    /// Usage examples
    pub examples: Vec<ToolExample>,
    /// Related tools
    pub related: Vec<String>,
}

/// Tool usage example
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExample {
    /// Example description
    pub description: String,
    /// Example arguments (JSON)
    pub arguments: serde_json::Value,
    /// Expected output description
    pub expected: String,
}

/// Server health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health (true if all components ok)
    pub healthy: bool,
    /// Agent connection status
    pub agent_connected: bool,
    /// Agent version (if connected)
    pub agent_version: Option<String>,
    /// Script engine status
    pub script_engine: ComponentStatus,
    /// IPC status
    pub ipc: ComponentStatus,
    /// Last health check timestamp
    pub checked_at: u64,
    /// Diagnostic messages
    pub diagnostics: Vec<String>,
}

/// Component status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// Component name
    pub name: String,
    /// Whether the component is operational
    pub ok: bool,
    /// Status message
    pub message: String,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session identifier
    pub session_id: String,
    /// Whether attached to a process
    pub attached: bool,
    /// Target process ID (if attached)
    pub pid: Option<u32>,
    /// Target process name (if attached)
    pub process_name: Option<String>,
    /// Target architecture
    pub arch: Option<String>,
    /// Session start time (Unix epoch)
    pub started_at: u64,
    /// Number of loaded scripts
    pub script_count: u32,
    /// Number of active hooks
    pub hook_count: u32,
    /// Number of active breakpoints
    pub breakpoint_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_category_variants() {
        assert_ne!(ToolCategory::Memory, ToolCategory::Module);
        assert_ne!(ToolCategory::Debug, ToolCategory::Script);
        assert_ne!(ToolCategory::Session, ToolCategory::Process);
    }

    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus {
            healthy: true,
            agent_connected: true,
            agent_version: Some("0.1.0".to_string()),
            script_engine: ComponentStatus {
                name: "script_engine".to_string(),
                ok: true,
                message: "Running".to_string(),
            },
            ipc: ComponentStatus {
                name: "ipc".to_string(),
                ok: true,
                message: "Connected".to_string(),
            },
            checked_at: 1234567890,
            diagnostics: vec![],
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: HealthStatus = serde_json::from_str(&json).unwrap();
        assert!(parsed.healthy);
        assert!(parsed.agent_connected);
    }

    #[test]
    fn test_session_info_serialization() {
        let info = SessionInfo {
            session_id: "sess_123".to_string(),
            attached: true,
            pid: Some(1234),
            process_name: Some("game.exe".to_string()),
            arch: Some("x64".to_string()),
            started_at: 1234567890,
            script_count: 2,
            hook_count: 5,
            breakpoint_count: 3,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: SessionInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.attached);
        assert_eq!(parsed.pid, Some(1234));
    }

    #[test]
    fn test_tool_documentation_serialization() {
        let doc = ToolDocumentation {
            name: "memory_read".to_string(),
            category: ToolCategory::Memory,
            description: "Read memory".to_string(),
            help: "Detailed help text".to_string(),
            examples: vec![ToolExample {
                description: "Read 4 bytes".to_string(),
                arguments: serde_json::json!({"address": "0x1000", "size": 4}),
                expected: "Hex bytes".to_string(),
            }],
            related: vec!["memory_write".to_string()],
        };
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: ToolDocumentation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "memory_read");
        assert_eq!(parsed.category, ToolCategory::Memory);
    }
}
