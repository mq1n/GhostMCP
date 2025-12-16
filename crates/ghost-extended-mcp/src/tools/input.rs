//! Input injection tools for ghost-extended-mcp
//!
//! Phase 5.12: Input Injection & Automation (18 tools)
//! - Keyboard injection
//! - Mouse injection
//! - Window message injection
//! - Game/application input (DirectInput, XInput)

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register input tools (18 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        // Keyboard
        input_key_press(),
        input_key_down(),
        input_key_up(),
        input_key_sequence(),
        input_key_scancode(),
        input_key_message(),
        // Mouse
        input_mouse_move(),
        input_mouse_click(),
        input_mouse_scroll(),
        input_mouse_drag(),
        input_mouse_message(),
        // Window Messages
        input_post_message(),
        input_send_message(),
        input_message_queue(),
        // DirectInput/XInput
        input_dinput_state(),
        input_dinput_set(),
        input_xinput_state(),
        input_xinput_set(),
    ])
}

fn input_key_press() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "key".to_string(),
        PropertySchema::string("Virtual key code or key name (e.g., 'A', 'VK_RETURN', '0x0D')"),
    );
    props.insert(
        "modifiers".to_string(),
        PropertySchema::array("Modifier keys: 'ctrl', 'alt', 'shift', 'win'"),
    );
    props.insert(
        "hwnd".to_string(),
        PropertySchema::string("Target window handle (optional, 0 = foreground)"),
    );

    ToolDefinition::new("input_key_press", "Simulate key press (down + up)", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["key".to_string()],
            additional_properties: false,
        },
    )
}

fn input_key_down() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "key".to_string(),
        PropertySchema::string("Virtual key code or key name"),
    );

    ToolDefinition::new("input_key_down", "Simulate key down event", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["key".to_string()],
            additional_properties: false,
        },
    )
}

fn input_key_up() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "key".to_string(),
        PropertySchema::string("Virtual key code or key name"),
    );

    ToolDefinition::new("input_key_up", "Simulate key up event", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["key".to_string()],
            additional_properties: false,
        },
    )
}

fn input_key_sequence() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert("text".to_string(), PropertySchema::string("Text to type"));
    props.insert(
        "delay_ms".to_string(),
        PropertySchema::integer("Delay between keys in milliseconds").with_default(50),
    );

    ToolDefinition::new(
        "input_key_sequence",
        "Type a sequence of characters",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["text".to_string()],
        additional_properties: false,
    })
}

fn input_key_scancode() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "scancode".to_string(),
        PropertySchema::integer("Hardware scan code"),
    );
    props.insert(
        "extended".to_string(),
        PropertySchema::boolean("Extended key flag").with_default(false),
    );
    props.insert(
        "key_up".to_string(),
        PropertySchema::boolean("Key up event").with_default(false),
    );

    ToolDefinition::new("input_key_scancode", "Send raw scan code input", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["scancode".to_string()],
            additional_properties: false,
        },
    )
}

fn input_key_message() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hwnd".to_string(),
        PropertySchema::string("Target window handle"),
    );
    props.insert(
        "message".to_string(),
        PropertySchema::string_enum("Message type", vec!["WM_KEYDOWN", "WM_KEYUP", "WM_CHAR"]),
    );
    props.insert(
        "wparam".to_string(),
        PropertySchema::string("wParam value (virtual key or char)"),
    );
    props.insert(
        "lparam".to_string(),
        PropertySchema::string("lParam value (optional, auto-generated if omitted)"),
    );

    ToolDefinition::new(
        "input_key_message",
        "Send keyboard message directly to window",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "hwnd".to_string(),
            "message".to_string(),
            "wparam".to_string(),
        ],
        additional_properties: false,
    })
}

fn input_mouse_move() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert("x".to_string(), PropertySchema::integer("X coordinate"));
    props.insert("y".to_string(), PropertySchema::integer("Y coordinate"));
    props.insert(
        "absolute".to_string(),
        PropertySchema::boolean("Absolute coordinates (vs relative)").with_default(true),
    );
    props.insert(
        "normalized".to_string(),
        PropertySchema::boolean("Coordinates are 0-65535 normalized").with_default(false),
    );

    ToolDefinition::new("input_mouse_move", "Move mouse cursor", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["x".to_string(), "y".to_string()],
            additional_properties: false,
        },
    )
}

fn input_mouse_click() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "button".to_string(),
        PropertySchema::string_enum("Mouse button", vec!["left", "right", "middle", "x1", "x2"])
            .with_default("left"),
    );
    props.insert(
        "x".to_string(),
        PropertySchema::integer("X coordinate (optional, current position if omitted)"),
    );
    props.insert(
        "y".to_string(),
        PropertySchema::integer("Y coordinate (optional)"),
    );
    props.insert(
        "double".to_string(),
        PropertySchema::boolean("Double click").with_default(false),
    );

    ToolDefinition::new("input_mouse_click", "Simulate mouse click", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn input_mouse_scroll() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "delta".to_string(),
        PropertySchema::integer("Scroll amount (positive = up, negative = down)"),
    );
    props.insert(
        "horizontal".to_string(),
        PropertySchema::boolean("Horizontal scroll").with_default(false),
    );

    ToolDefinition::new("input_mouse_scroll", "Simulate mouse scroll", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["delta".to_string()],
            additional_properties: false,
        },
    )
}

fn input_mouse_drag() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "start_x".to_string(),
        PropertySchema::integer("Start X coordinate"),
    );
    props.insert(
        "start_y".to_string(),
        PropertySchema::integer("Start Y coordinate"),
    );
    props.insert(
        "end_x".to_string(),
        PropertySchema::integer("End X coordinate"),
    );
    props.insert(
        "end_y".to_string(),
        PropertySchema::integer("End Y coordinate"),
    );
    props.insert(
        "button".to_string(),
        PropertySchema::string_enum("Mouse button", vec!["left", "right"]).with_default("left"),
    );
    props.insert(
        "steps".to_string(),
        PropertySchema::integer("Number of intermediate steps").with_default(10),
    );

    ToolDefinition::new("input_mouse_drag", "Simulate mouse drag operation", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![
                "start_x".to_string(),
                "start_y".to_string(),
                "end_x".to_string(),
                "end_y".to_string(),
            ],
            additional_properties: false,
        },
    )
}

fn input_mouse_message() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hwnd".to_string(),
        PropertySchema::string("Target window handle"),
    );
    props.insert(
        "message".to_string(),
        PropertySchema::string("Mouse message (WM_LBUTTONDOWN, WM_MOUSEMOVE, etc.)"),
    );
    props.insert("x".to_string(), PropertySchema::integer("X coordinate"));
    props.insert("y".to_string(), PropertySchema::integer("Y coordinate"));

    ToolDefinition::new(
        "input_mouse_message",
        "Send mouse message directly to window",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![
            "hwnd".to_string(),
            "message".to_string(),
            "x".to_string(),
            "y".to_string(),
        ],
        additional_properties: false,
    })
}

fn input_post_message() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hwnd".to_string(),
        PropertySchema::string("Target window handle"),
    );
    props.insert(
        "message".to_string(),
        PropertySchema::string("Message ID (numeric or name)"),
    );
    props.insert("wparam".to_string(), PropertySchema::string("wParam value"));
    props.insert("lparam".to_string(), PropertySchema::string("lParam value"));

    ToolDefinition::new(
        "input_post_message",
        "Post message to window (async, non-blocking)",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["hwnd".to_string(), "message".to_string()],
        additional_properties: false,
    })
}

fn input_send_message() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hwnd".to_string(),
        PropertySchema::string("Target window handle"),
    );
    props.insert("message".to_string(), PropertySchema::string("Message ID"));
    props.insert("wparam".to_string(), PropertySchema::string("wParam value"));
    props.insert("lparam".to_string(), PropertySchema::string("lParam value"));

    ToolDefinition::new(
        "input_send_message",
        "Send message to window (sync, blocking)",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["hwnd".to_string(), "message".to_string()],
        additional_properties: false,
    })
}

fn input_message_queue() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "hwnd".to_string(),
        PropertySchema::string("Window handle to monitor"),
    );
    props.insert(
        "filter_min".to_string(),
        PropertySchema::integer("Minimum message ID filter"),
    );
    props.insert(
        "filter_max".to_string(),
        PropertySchema::integer("Maximum message ID filter"),
    );

    ToolDefinition::new(
        "input_message_queue",
        "Monitor window message queue",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["hwnd".to_string()],
        additional_properties: false,
    })
}

fn input_dinput_state() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "device_index".to_string(),
        PropertySchema::integer("DirectInput device index").with_default(0),
    );

    ToolDefinition::new(
        "input_dinput_state",
        "Get DirectInput device state",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec![],
        additional_properties: false,
    })
}

fn input_dinput_set() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "device_index".to_string(),
        PropertySchema::integer("DirectInput device index"),
    );
    props.insert(
        "state".to_string(),
        PropertySchema::object("Device state to inject"),
    );

    ToolDefinition::new(
        "input_dinput_set",
        "Inject DirectInput device state",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["state".to_string()],
        additional_properties: false,
    })
}

fn input_xinput_state() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "user_index".to_string(),
        PropertySchema::integer("XInput user index (0-3)").with_default(0),
    );

    ToolDefinition::new("input_xinput_state", "Get XInput controller state", "input").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn input_xinput_set() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "user_index".to_string(),
        PropertySchema::integer("XInput user index (0-3)"),
    );
    props.insert(
        "buttons".to_string(),
        PropertySchema::integer("Button flags"),
    );
    props.insert(
        "left_trigger".to_string(),
        PropertySchema::integer("Left trigger (0-255)"),
    );
    props.insert(
        "right_trigger".to_string(),
        PropertySchema::integer("Right trigger (0-255)"),
    );
    props.insert(
        "left_thumb_x".to_string(),
        PropertySchema::integer("Left thumbstick X (-32768 to 32767)"),
    );
    props.insert(
        "left_thumb_y".to_string(),
        PropertySchema::integer("Left thumbstick Y"),
    );
    props.insert(
        "right_thumb_x".to_string(),
        PropertySchema::integer("Right thumbstick X"),
    );
    props.insert(
        "right_thumb_y".to_string(),
        PropertySchema::integer("Right thumbstick Y"),
    );

    ToolDefinition::new(
        "input_xinput_set",
        "Inject XInput controller state",
        "input",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["user_index".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_input_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 18);
    }
}
