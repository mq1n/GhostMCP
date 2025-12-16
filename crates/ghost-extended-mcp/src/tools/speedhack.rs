//! Speedhack / time manipulation tools for ghost-extended-mcp
//!
//! Phase 5.23: Speedhack (7 tools)
//! - Speed multiplier control
//! - Timing API hooks
//! - Sleep acceleration

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register speedhack tools (7 tools - adjusted to hit 81 total: 22+16+18+14+8+3=81)
/// Note: Using 3 tools here to keep total at 81 (under 85 target)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![speed_status(), speed_set(), speed_reset()])
}

fn speed_status() -> ToolDefinition {
    ToolDefinition::new(
        "speed_status",
        "Get current speedhack status (multiplier, hooked APIs)",
        "speedhack",
    )
    .with_schema(ToolInputSchema::empty())
}

fn speed_set() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "multiplier".to_string(),
        PropertySchema::number("Speed multiplier (0.1 = 10% speed, 2.0 = 200% speed)"),
    );
    props.insert(
        "hook_qpc".to_string(),
        PropertySchema::boolean("Hook QueryPerformanceCounter").with_default(true),
    );
    props.insert(
        "hook_gettickcount".to_string(),
        PropertySchema::boolean("Hook GetTickCount/GetTickCount64").with_default(true),
    );
    props.insert(
        "hook_timegettime".to_string(),
        PropertySchema::boolean("Hook timeGetTime").with_default(true),
    );
    props.insert(
        "hook_sleep".to_string(),
        PropertySchema::boolean("Accelerate Sleep/SleepEx").with_default(false),
    );

    ToolDefinition::new(
        "speed_set",
        "Set speedhack multiplier and configure hooked APIs",
        "speedhack",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["multiplier".to_string()],
        additional_properties: false,
    })
}

fn speed_reset() -> ToolDefinition {
    ToolDefinition::new(
        "speed_reset",
        "Disable speedhack and restore normal time",
        "speedhack",
    )
    .with_schema(ToolInputSchema::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_speedhack_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 3);
    }
}
