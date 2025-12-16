//! Address list (cheat table) tools for ghost-extended-mcp
//!
//! Phase 5.18: Address List Management (14 tools)
//! - Entry management
//! - Value freezing
//! - Group organization
//! - Project persistence

use ghost_mcp_common::{
    error::Result,
    registry::{PropertySchema, ToolInputSchema},
    ToolDefinition, ToolRegistry,
};
use std::collections::HashMap;

/// Register address list tools (14 tools)
pub fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_all(vec![
        // Entry Management
        table_add(),
        table_remove(),
        table_list(),
        table_get(),
        table_update(),
        table_freeze(),
        table_unfreeze(),
        // Group Management
        table_group_create(),
        table_group_delete(),
        table_group_toggle(),
        table_group_list(),
        // Persistence
        table_save(),
        table_load(),
        table_autosave(),
    ])
}

fn table_add() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "address".to_string(),
        PropertySchema::string("Memory address"),
    );
    props.insert(
        "type".to_string(),
        PropertySchema::string_enum(
            "Value type",
            vec![
                "byte", "int16", "int32", "int64", "float", "double", "string", "aob",
            ],
        ),
    );
    props.insert(
        "description".to_string(),
        PropertySchema::string("Description/label for this entry"),
    );
    props.insert(
        "group".to_string(),
        PropertySchema::string("Group name (optional)"),
    );
    props.insert(
        "pointer_chain".to_string(),
        PropertySchema::array("Pointer offsets if this is a pointer (e.g., [0x10, 0x20])"),
    );

    ToolDefinition::new("table_add", "Add entry to address table", "addresslist").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["address".to_string(), "type".to_string()],
            additional_properties: false,
        },
    )
}

fn table_remove() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "id".to_string(),
        PropertySchema::string("Entry ID to remove"),
    );

    ToolDefinition::new(
        "table_remove",
        "Remove entry from address table",
        "addresslist",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["id".to_string()],
        additional_properties: false,
    })
}

fn table_list() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "group".to_string(),
        PropertySchema::string("Filter by group (optional)"),
    );
    props.insert(
        "frozen_only".to_string(),
        PropertySchema::boolean("Show only frozen entries").with_default(false),
    );

    ToolDefinition::new("table_list", "List all table entries", "addresslist").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec![],
            additional_properties: false,
        },
    )
}

fn table_get() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert("id".to_string(), PropertySchema::string("Entry ID"));

    ToolDefinition::new(
        "table_get",
        "Get entry details and current value",
        "addresslist",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["id".to_string()],
        additional_properties: false,
    })
}

fn table_update() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert("id".to_string(), PropertySchema::string("Entry ID"));
    props.insert(
        "value".to_string(),
        PropertySchema::string("New value to write"),
    );

    ToolDefinition::new(
        "table_update",
        "Update entry value (write to memory)",
        "addresslist",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["id".to_string(), "value".to_string()],
        additional_properties: false,
    })
}

fn table_freeze() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "id".to_string(),
        PropertySchema::string("Entry ID to freeze"),
    );
    props.insert(
        "value".to_string(),
        PropertySchema::string("Value to freeze at (optional, uses current if omitted)"),
    );
    props.insert(
        "interval_ms".to_string(),
        PropertySchema::integer("Freeze interval in milliseconds").with_default(100),
    );

    ToolDefinition::new(
        "table_freeze",
        "Freeze entry value (continuously write)",
        "addresslist",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["id".to_string()],
        additional_properties: false,
    })
}

fn table_unfreeze() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "id".to_string(),
        PropertySchema::string("Entry ID to unfreeze"),
    );

    ToolDefinition::new("table_unfreeze", "Stop freezing entry value", "addresslist").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["id".to_string()],
            additional_properties: false,
        },
    )
}

fn table_group_create() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert("name".to_string(), PropertySchema::string("Group name"));
    props.insert(
        "description".to_string(),
        PropertySchema::string("Group description (optional)"),
    );

    ToolDefinition::new(
        "table_group_create",
        "Create a new group for organizing entries",
        "addresslist",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string()],
        additional_properties: false,
    })
}

fn table_group_delete() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "name".to_string(),
        PropertySchema::string("Group name to delete"),
    );
    props.insert(
        "delete_entries".to_string(),
        PropertySchema::boolean("Also delete entries in group").with_default(false),
    );

    ToolDefinition::new("table_group_delete", "Delete a group", "addresslist").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["name".to_string()],
            additional_properties: false,
        },
    )
}

fn table_group_toggle() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert("name".to_string(), PropertySchema::string("Group name"));
    props.insert(
        "enabled".to_string(),
        PropertySchema::boolean("Enable (true) or disable (false) group"),
    );

    ToolDefinition::new(
        "table_group_toggle",
        "Enable or disable all entries in a group",
        "addresslist",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["name".to_string(), "enabled".to_string()],
        additional_properties: false,
    })
}

fn table_group_list() -> ToolDefinition {
    ToolDefinition::new("table_group_list", "List all groups", "addresslist")
        .with_schema(ToolInputSchema::empty())
}

fn table_save() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema::string("File path to save (.json or .ct for CE format)"),
    );
    props.insert(
        "format".to_string(),
        PropertySchema::string_enum("Export format", vec!["json", "ct"]).with_default("json"),
    );

    ToolDefinition::new("table_save", "Save table to file", "addresslist").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

fn table_load() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "path".to_string(),
        PropertySchema::string("File path to load"),
    );
    props.insert(
        "merge".to_string(),
        PropertySchema::boolean("Merge with existing table (vs replace)").with_default(false),
    );

    ToolDefinition::new("table_load", "Load table from file", "addresslist").with_schema(
        ToolInputSchema {
            schema_type: "object".to_string(),
            properties: props,
            required: vec!["path".to_string()],
            additional_properties: false,
        },
    )
}

fn table_autosave() -> ToolDefinition {
    let mut props = HashMap::new();
    props.insert(
        "enabled".to_string(),
        PropertySchema::boolean("Enable auto-save"),
    );
    props.insert(
        "interval_sec".to_string(),
        PropertySchema::integer("Auto-save interval in seconds").with_default(60),
    );
    props.insert(
        "path".to_string(),
        PropertySchema::string("Auto-save file path"),
    );

    ToolDefinition::new(
        "table_autosave",
        "Configure auto-save settings",
        "addresslist",
    )
    .with_schema(ToolInputSchema {
        schema_type: "object".to_string(),
        properties: props,
        required: vec!["enabled".to_string()],
        additional_properties: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_addresslist_tools() {
        let mut registry = ToolRegistry::new();
        register(&mut registry).unwrap();
        assert_eq!(registry.len(), 14);
    }
}
