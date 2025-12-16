//! AI-friendly output types

use serde::{Deserialize, Serialize};

use super::breakpoint::BreakpointType;

/// Paginated result wrapper for large result sets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResult<T> {
    /// Current page items
    pub items: Vec<T>,
    /// Total item count
    pub total_count: usize,
    /// Current page (0-indexed)
    pub page: usize,
    /// Items per page
    pub page_size: usize,
    /// Total pages
    pub total_pages: usize,
    /// Whether there are more pages
    pub has_more: bool,
}

impl<T> PaginatedResult<T> {
    pub fn new(items: Vec<T>, total_count: usize, page: usize, page_size: usize) -> Self {
        let total_pages = if page_size > 0 {
            total_count.div_ceil(page_size)
        } else {
            1
        };
        Self {
            items,
            total_count,
            page,
            page_size,
            total_pages,
            has_more: page + 1 < total_pages,
        }
    }
}

/// Context-aware summary for AI consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSummary {
    /// Brief one-line summary
    pub brief: String,
    /// Detailed summary
    pub detailed: String,
    /// Key findings/observations
    pub key_points: Vec<String>,
    /// Suggested next actions
    pub suggestions: Vec<String>,
    /// Related tools that might be useful
    pub related_tools: Vec<String>,
    /// Confidence level (0.0-1.0)
    pub confidence: f64,
}

/// Diff-based change report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeReport {
    /// Type of change
    pub change_type: ChangeType,
    /// Items added
    pub added: Vec<serde_json::Value>,
    /// Items removed
    pub removed: Vec<serde_json::Value>,
    /// Items modified (old, new)
    pub modified: Vec<(serde_json::Value, serde_json::Value)>,
    /// Unchanged count
    pub unchanged_count: usize,
    /// Summary of changes
    pub summary: String,
}

/// Types of changes for diff reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Memory,
    Registers,
    Modules,
    Threads,
    Breakpoints,
    Hooks,
    ScanResults,
    Custom,
}

/// Natural language error with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiError {
    /// Error code
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Detailed explanation
    pub explanation: String,
    /// Possible causes
    pub possible_causes: Vec<String>,
    /// Suggested fixes
    pub suggested_fixes: Vec<String>,
    /// Related documentation
    pub documentation: Option<String>,
    /// Whether error is recoverable
    pub recoverable: bool,
}

/// Breakpoint recommendation from AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointRecommendation {
    /// Recommended address
    pub address: usize,
    /// Breakpoint type
    pub bp_type: BreakpointType,
    /// Reason for recommendation
    pub reason: String,
    /// Confidence level
    pub confidence: f64,
    /// What to look for when hit
    pub observation_hints: Vec<String>,
    /// Related function/symbol
    pub symbol: Option<String>,
}

/// Vulnerability detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    /// Vulnerability type
    pub vuln_type: VulnerabilityType,
    /// Severity (1-10)
    pub severity: u32,
    /// Location (address)
    pub address: usize,
    /// Description
    pub description: String,
    /// Detailed analysis
    pub analysis: String,
    /// Proof of concept (if available)
    pub poc: Option<String>,
    /// Remediation suggestions
    pub remediation: Vec<String>,
    /// Confidence level
    pub confidence: f64,
    /// Related CWE ID (if applicable)
    pub cwe_id: Option<String>,
}

/// Types of vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilityType {
    BufferOverflow,
    UseAfterFree,
    IntegerOverflow,
    FormatString,
    NullPointerDeref,
    DoubleFree,
    HeapCorruption,
    StackCorruption,
    TypeConfusion,
    RaceCondition,
    InformationLeak,
    CodeInjection,
    Other,
}

/// Pattern learning entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    /// Pattern ID
    pub id: u32,
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Pattern type
    pub pattern_type: LearnedPatternType,
    /// Pattern data (signature, behavior, etc.)
    pub data: serde_json::Value,
    /// Times pattern was observed
    pub observation_count: u32,
    /// Confidence level
    pub confidence: f64,
    /// Created timestamp
    pub created_at: u64,
    /// Last seen timestamp
    pub last_seen_at: u64,
}

/// Types of learned patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearnedPatternType {
    /// Code pattern (instruction sequence)
    CodeSequence,
    /// Memory layout pattern
    MemoryLayout,
    /// Behavior pattern (API call sequence)
    Behavior,
    /// Data structure pattern
    DataStructure,
    /// User action pattern
    UserAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginated_result_new() {
        let items = vec![1, 2, 3, 4, 5];
        let result = PaginatedResult::new(items, 25, 0, 5);
        assert_eq!(result.total_count, 25);
        assert_eq!(result.page, 0);
        assert_eq!(result.page_size, 5);
        assert_eq!(result.total_pages, 5);
        assert!(result.has_more);
        assert_eq!(result.items.len(), 5);
    }

    #[test]
    fn test_paginated_result_last_page() {
        let items = vec![21, 22, 23, 24, 25];
        let result = PaginatedResult::new(items, 25, 4, 5);
        assert!(!result.has_more);
    }

    #[test]
    fn test_paginated_result_zero_page_size() {
        let items: Vec<i32> = vec![];
        let result = PaginatedResult::new(items, 0, 0, 0);
        assert_eq!(result.total_pages, 1);
    }

    #[test]
    fn test_change_type_serialization() {
        let change = ChangeType::Memory;
        let json = serde_json::to_string(&change).unwrap();
        let parsed: ChangeType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ChangeType::Memory);
    }

    #[test]
    fn test_vulnerability_type_serialization() {
        let vuln = VulnerabilityType::BufferOverflow;
        let json = serde_json::to_string(&vuln).unwrap();
        let parsed: VulnerabilityType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, VulnerabilityType::BufferOverflow);
    }

    #[test]
    fn test_learned_pattern_type_serialization() {
        let pattern = LearnedPatternType::CodeSequence;
        let json = serde_json::to_string(&pattern).unwrap();
        let parsed: LearnedPatternType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, LearnedPatternType::CodeSequence);
    }

    #[test]
    fn test_ai_summary_serialization() {
        let summary = AiSummary {
            brief: "Test brief".to_string(),
            detailed: "Test detailed".to_string(),
            key_points: vec!["Point 1".to_string()],
            suggestions: vec!["Suggestion 1".to_string()],
            related_tools: vec!["tool1".to_string()],
            confidence: 0.85,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: AiSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.brief, "Test brief");
        assert_eq!(parsed.confidence, 0.85);
    }

    #[test]
    fn test_ai_error_serialization() {
        let error = AiError {
            code: "ERR001".to_string(),
            message: "Test error".to_string(),
            explanation: "Detailed explanation".to_string(),
            possible_causes: vec!["Cause 1".to_string()],
            suggested_fixes: vec!["Fix 1".to_string()],
            documentation: Some("https://docs.example.com".to_string()),
            recoverable: true,
        };
        let json = serde_json::to_string(&error).unwrap();
        let parsed: AiError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "ERR001");
        assert!(parsed.recoverable);
    }

    #[test]
    fn test_breakpoint_recommendation_serialization() {
        let rec = BreakpointRecommendation {
            address: 0x140001000,
            bp_type: BreakpointType::Software,
            reason: "Entry point".to_string(),
            confidence: 0.9,
            observation_hints: vec!["Check RAX".to_string()],
            symbol: Some("main".to_string()),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: BreakpointRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.address, 0x140001000);
        assert_eq!(parsed.confidence, 0.9);
    }
}
