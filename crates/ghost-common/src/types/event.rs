//! Agent-to-AI event types

use serde::{Deserialize, Serialize};

use super::breakpoint::BreakpointId;
use super::instruction::Instruction;
use super::memory::MemoryAccessType;
use super::module::Module;
use super::script::{CallbackType, ScriptId};
use super::thread::{Registers, StackFrame};

/// Unique identifier for an event subscription
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventSubscriptionId(pub u32);

/// Event types that can be sent from agent to AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEvent {
    /// Breakpoint was hit
    BreakpointHit(BreakpointHitEvent),
    /// Exception occurred
    Exception(ExceptionEvent),
    /// Memory was modified (from watch)
    MemoryChanged(MemoryChangeEvent),
    /// Hook was triggered
    HookTriggered(HookTriggerEvent),
    /// Process/thread state changed
    StateChanged(StateChangeEvent),
    /// Module loaded/unloaded
    ModuleEvent(ModuleEventData),
    /// Custom event from script
    Custom(CustomEvent),
}

/// Breakpoint hit event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointHitEvent {
    /// Breakpoint ID
    pub breakpoint_id: BreakpointId,
    /// Address where breakpoint hit
    pub address: usize,
    /// Thread ID that hit the breakpoint
    pub thread_id: u32,
    /// CPU registers at breakpoint
    pub registers: Registers,
    /// Hit count for this breakpoint
    pub hit_count: u64,
    /// Stack trace (if available)
    pub stack_trace: Option<Vec<StackFrame>>,
    /// Disassembly context (surrounding instructions)
    pub disasm_context: Option<Vec<Instruction>>,
    /// Timestamp (Unix epoch milliseconds)
    pub timestamp_ms: u64,
}

/// Exception event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionEvent {
    /// Exception code
    pub code: u32,
    /// Exception name/description
    pub name: String,
    /// Address where exception occurred
    pub address: usize,
    /// Thread ID
    pub thread_id: u32,
    /// CPU registers
    pub registers: Registers,
    /// Whether exception is first chance
    pub first_chance: bool,
    /// Whether exception is continuable
    pub continuable: bool,
    /// Additional exception parameters
    pub parameters: Vec<u64>,
    /// Stack trace
    pub stack_trace: Option<Vec<StackFrame>>,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Memory change event (from memory watch)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryChangeEvent {
    /// Watch ID that triggered
    pub watch_id: u32,
    /// Address that was accessed/modified
    pub address: usize,
    /// Size of access
    pub size: usize,
    /// Type of access (read/write)
    pub access_type: MemoryAccessType,
    /// Old value (for writes)
    pub old_value: Option<Vec<u8>>,
    /// New value (for writes)
    pub new_value: Option<Vec<u8>>,
    /// Instruction that caused the access
    pub instruction_address: usize,
    /// Thread ID
    pub thread_id: u32,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Hook trigger event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookTriggerEvent {
    /// Hook ID
    pub hook_id: u32,
    /// Hook address
    pub address: usize,
    /// Callback type that triggered
    pub callback_type: CallbackType,
    /// Thread ID
    pub thread_id: u32,
    /// Function arguments (for onEnter)
    pub arguments: Option<Vec<u64>>,
    /// Return value (for onLeave)
    pub return_value: Option<u64>,
    /// CPU registers
    pub registers: Registers,
    /// Script-provided data
    pub script_data: Option<serde_json::Value>,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Process/thread state change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChangeEvent {
    /// Type of state change
    pub change_type: StateChangeType,
    /// Affected entity ID (PID or TID)
    pub entity_id: u32,
    /// Additional details
    pub details: serde_json::Value,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Types of state changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateChangeType {
    ThreadCreated,
    ThreadExited,
    ThreadSuspended,
    ThreadResumed,
    ProcessExiting,
    DebugStringOutput,
}

/// Module load/unload event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEventData {
    /// Event type
    pub event_type: ModuleEventType,
    /// Module information
    pub module: Module,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Module event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleEventType {
    Loaded,
    Unloaded,
}

/// Custom event from script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEvent {
    /// Event name
    pub name: String,
    /// Event data
    pub data: serde_json::Value,
    /// Source script ID
    pub script_id: Option<ScriptId>,
    /// Timestamp
    pub timestamp_ms: u64,
}

/// Event subscription configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubscription {
    /// Subscription ID
    pub id: EventSubscriptionId,
    /// Event types to subscribe to
    pub event_types: Vec<EventFilter>,
    /// Whether subscription is active
    pub active: bool,
    /// Maximum events to buffer (0 = unlimited)
    pub buffer_size: usize,
    /// Created timestamp
    pub created_at: u64,
}

/// Filter for event subscriptions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventFilter {
    /// All events
    All,
    /// Breakpoint events only
    Breakpoint,
    /// Exception events only
    Exception,
    /// Memory change events only
    MemoryChange,
    /// Hook trigger events only
    HookTrigger,
    /// State change events only
    StateChange,
    /// Module events only
    Module,
    /// Custom events only
    Custom,
    /// Events matching a pattern
    Pattern {
        event_type: String,
        filter: serde_json::Value,
    },
}

/// Buffered events for AI consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBuffer {
    /// Subscription ID
    pub subscription_id: EventSubscriptionId,
    /// Buffered events
    pub events: Vec<AgentEvent>,
    /// Whether buffer overflowed (events were dropped)
    pub overflow: bool,
    /// Dropped event count
    pub dropped_count: u64,
    /// Buffer timestamp
    pub timestamp_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_subscription_id_serialization() {
        let id = EventSubscriptionId(123);
        let json = serde_json::to_string(&id).unwrap();
        let parsed: EventSubscriptionId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.0, 123);
    }

    #[test]
    fn test_agent_event_serialization() {
        let event = AgentEvent::Custom(CustomEvent {
            name: "test_event".to_string(),
            data: serde_json::json!({"key": "value"}),
            script_id: None,
            timestamp_ms: 12345,
        });
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AgentEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentEvent::Custom(_)));
    }

    #[test]
    fn test_state_change_type_serialization() {
        let change = StateChangeType::ThreadCreated;
        let json = serde_json::to_string(&change).unwrap();
        let parsed: StateChangeType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, StateChangeType::ThreadCreated);
    }

    #[test]
    fn test_event_filter_serialization() {
        let filter = EventFilter::Breakpoint;
        let json = serde_json::to_string(&filter).unwrap();
        let parsed: EventFilter = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, EventFilter::Breakpoint));
    }
}
