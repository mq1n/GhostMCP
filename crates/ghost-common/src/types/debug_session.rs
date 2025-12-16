//! AI-assisted debugging types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a debugging session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DebugSessionId(pub u32);

/// Conversational debugging session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSession {
    /// Session ID
    pub id: DebugSessionId,
    /// Session name/description
    pub name: String,
    /// Current debugging goal
    pub goal: Option<String>,
    /// Session state
    pub state: DebugSessionState,
    /// Discovered information
    pub findings: Vec<DebugFinding>,
    /// Active hypotheses
    pub hypotheses: Vec<DebugHypothesis>,
    /// Recommended next steps
    pub next_steps: Vec<DebugStep>,
    /// Session history
    pub history: Vec<DebugAction>,
    /// Session context (key-value pairs for AI reference)
    pub context: HashMap<String, serde_json::Value>,
    /// Created timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub updated_at: u64,
}

/// Debug session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DebugSessionState {
    /// Session is active
    #[default]
    Active,
    /// Waiting for user input
    WaitingForInput,
    /// Waiting for breakpoint hit
    WaitingForBreakpoint,
    /// Analyzing data
    Analyzing,
    /// Session paused
    Paused,
    /// Session completed
    Completed,
}

/// A finding discovered during debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugFinding {
    /// Finding type
    pub finding_type: FindingType,
    /// Brief description
    pub description: String,
    /// Detailed information
    pub details: serde_json::Value,
    /// Confidence level (0.0-1.0)
    pub confidence: f64,
    /// Related addresses
    pub addresses: Vec<usize>,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Types of debug findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingType {
    /// Potential vulnerability
    Vulnerability,
    /// Interesting function
    InterestingFunction,
    /// Anti-debug detected
    AntiDebug,
    /// Encryption/encoding detected
    Crypto,
    /// Network activity
    Network,
    /// File operation
    FileOp,
    /// Registry operation
    RegistryOp,
    /// Memory pattern
    MemoryPattern,
    /// Control flow anomaly
    ControlFlowAnomaly,
    /// Custom finding
    Custom,
}

/// A hypothesis being investigated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugHypothesis {
    /// Hypothesis ID
    pub id: u32,
    /// Description
    pub description: String,
    /// Status
    pub status: HypothesisStatus,
    /// Supporting evidence
    pub evidence_for: Vec<String>,
    /// Contradicting evidence
    pub evidence_against: Vec<String>,
    /// Tests to perform
    pub tests: Vec<String>,
    /// Confidence level
    pub confidence: f64,
}

/// Hypothesis status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HypothesisStatus {
    /// Not yet tested
    #[default]
    Untested,
    /// Currently being tested
    Testing,
    /// Confirmed by evidence
    Confirmed,
    /// Disproven by evidence
    Disproven,
    /// Inconclusive
    Inconclusive,
}

/// A recommended debugging step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugStep {
    /// Step description
    pub description: String,
    /// Tool to use
    pub tool: String,
    /// Suggested arguments
    pub arguments: serde_json::Value,
    /// Rationale for this step
    pub rationale: String,
    /// Priority (higher = more important)
    pub priority: u32,
    /// Expected outcome
    pub expected_outcome: String,
}

/// A debugging action taken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugAction {
    /// Action ID
    pub id: u64,
    /// Tool used
    pub tool: String,
    /// Arguments used
    pub arguments: serde_json::Value,
    /// Result
    pub result: serde_json::Value,
    /// Success flag
    pub success: bool,
    /// AI interpretation of result
    pub interpretation: Option<String>,
    /// Timestamp
    pub timestamp_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_session_id_serialization() {
        let id = DebugSessionId(999);
        let json = serde_json::to_string(&id).unwrap();
        let parsed: DebugSessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.0, 999);
    }

    #[test]
    fn test_debug_session_state_default() {
        let state = DebugSessionState::default();
        assert_eq!(state, DebugSessionState::Active);
    }

    #[test]
    fn test_hypothesis_status_default() {
        let status = HypothesisStatus::default();
        assert_eq!(status, HypothesisStatus::Untested);
    }

    #[test]
    fn test_finding_type_serialization() {
        let finding = FindingType::Vulnerability;
        let json = serde_json::to_string(&finding).unwrap();
        let parsed: FindingType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, FindingType::Vulnerability);
    }
}
