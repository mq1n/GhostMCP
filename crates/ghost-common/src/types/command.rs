//! AI/LLM bi-directional command types

use serde::{Deserialize, Serialize};

/// Unique identifier for a command sequence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommandSequenceId(pub u32);

/// A single command in a command sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    /// Tool name to execute
    pub tool: String,
    /// Arguments for the tool (JSON object)
    pub arguments: serde_json::Value,
    /// Optional label for referencing in conditions
    pub label: Option<String>,
    /// Condition for execution (references previous command labels)
    pub condition: Option<CommandCondition>,
    /// Whether to continue sequence on error
    pub continue_on_error: bool,
    /// Timeout in milliseconds (0 = default)
    pub timeout_ms: u64,
}

impl Command {
    pub fn new(tool: impl Into<String>, arguments: serde_json::Value) -> Self {
        Self {
            tool: tool.into(),
            arguments,
            label: None,
            condition: None,
            continue_on_error: false,
            timeout_ms: 0,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_condition(mut self, condition: CommandCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    pub fn continue_on_error(mut self) -> Self {
        self.continue_on_error = true;
        self
    }
}

/// Condition for conditional command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandCondition {
    /// Execute if previous command succeeded
    PreviousSuccess,
    /// Execute if previous command failed
    PreviousFailed,
    /// Execute if labeled command succeeded
    LabelSuccess(String),
    /// Execute if labeled command failed
    LabelFailed(String),
    /// Execute if result contains string
    ResultContains { label: String, pattern: String },
    /// Execute if result matches JSON path expression
    ResultMatch {
        label: String,
        json_path: String,
        expected: serde_json::Value,
    },
    /// Always execute
    Always,
    /// Never execute (skip)
    Never,
    /// Logical AND of conditions
    And(Vec<CommandCondition>),
    /// Logical OR of conditions
    Or(Vec<CommandCondition>),
    /// Logical NOT of condition
    Not(Box<CommandCondition>),
}

/// Command sequence for multi-step operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSequence {
    /// Unique sequence identifier
    pub id: CommandSequenceId,
    /// Sequence name/description
    pub name: String,
    /// Commands to execute in order
    pub commands: Vec<Command>,
    /// Whether to execute as a transaction (rollback on failure)
    pub transactional: bool,
    /// Maximum total execution time in milliseconds
    pub timeout_ms: u64,
    /// Created timestamp (Unix epoch)
    pub created_at: u64,
}

impl CommandSequence {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: CommandSequenceId(0),
            name: name.into(),
            commands: Vec::new(),
            transactional: false,
            timeout_ms: 0,
            created_at: 0,
        }
    }

    pub fn add_command(mut self, command: Command) -> Self {
        self.commands.push(command);
        self
    }

    pub fn transactional(mut self) -> Self {
        self.transactional = true;
        self
    }
}

/// Result of a single command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Command index in sequence
    pub index: usize,
    /// Command label (if any)
    pub label: Option<String>,
    /// Tool that was executed
    pub tool: String,
    /// Whether command succeeded
    pub success: bool,
    /// Result data (on success)
    pub result: Option<serde_json::Value>,
    /// Error message (on failure)
    pub error: Option<String>,
    /// Execution time in milliseconds
    pub duration_ms: u64,
    /// Whether command was skipped due to condition
    pub skipped: bool,
}

/// Result of executing a command sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceResult {
    /// Sequence ID
    pub id: CommandSequenceId,
    /// Sequence name
    pub name: String,
    /// Results for each command
    pub results: Vec<CommandResult>,
    /// Overall success (all commands succeeded or skipped appropriately)
    pub success: bool,
    /// Total execution time in milliseconds
    pub total_duration_ms: u64,
    /// Number of commands executed
    pub executed_count: usize,
    /// Number of commands skipped
    pub skipped_count: usize,
    /// Number of commands failed
    pub failed_count: usize,
    /// Whether sequence was rolled back (if transactional)
    pub rolled_back: bool,
}

/// Command history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandHistoryEntry {
    /// Unique entry ID
    pub id: u64,
    /// Tool name
    pub tool: String,
    /// Arguments used
    pub arguments: serde_json::Value,
    /// Result summary
    pub result: CommandResult,
    /// Timestamp (Unix epoch milliseconds)
    pub timestamp_ms: u64,
    /// Part of sequence (if any)
    pub sequence_id: Option<CommandSequenceId>,
}

/// Command history query options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandHistoryQuery {
    /// Filter by tool name
    pub tool: Option<String>,
    /// Filter by success/failure
    pub success: Option<bool>,
    /// Start timestamp (inclusive)
    pub from_timestamp: Option<u64>,
    /// End timestamp (inclusive)
    pub to_timestamp: Option<u64>,
    /// Maximum entries to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_sequence_id_serialization() {
        let id = CommandSequenceId(42);
        let json = serde_json::to_string(&id).unwrap();
        let parsed: CommandSequenceId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.0, 42);
    }

    #[test]
    fn test_command_new() {
        let cmd = Command::new("memory_read", serde_json::json!({"address": "0x1000"}));
        assert_eq!(cmd.tool, "memory_read");
        assert!(cmd.label.is_none());
        assert!(cmd.condition.is_none());
        assert!(!cmd.continue_on_error);
        assert_eq!(cmd.timeout_ms, 0);
    }

    #[test]
    fn test_command_builder_pattern() {
        let cmd = Command::new("memory_write", serde_json::json!({}))
            .with_label("write_step")
            .continue_on_error();
        assert_eq!(cmd.label, Some("write_step".to_string()));
        assert!(cmd.continue_on_error);
    }

    #[test]
    fn test_command_condition_serialization() {
        let cond = CommandCondition::PreviousSuccess;
        let json = serde_json::to_string(&cond).unwrap();
        let parsed: CommandCondition = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CommandCondition::PreviousSuccess));

        let cond = CommandCondition::LabelSuccess("step1".to_string());
        let json = serde_json::to_string(&cond).unwrap();
        let parsed: CommandCondition = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CommandCondition::LabelSuccess(ref s) if s == "step1"));
    }

    #[test]
    fn test_command_sequence_new() {
        let seq = CommandSequence::new("Test Sequence")
            .add_command(Command::new("module_list", serde_json::json!({})))
            .transactional();
        assert_eq!(seq.name, "Test Sequence");
        assert_eq!(seq.commands.len(), 1);
        assert!(seq.transactional);
    }
}
