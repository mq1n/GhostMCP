//! Build script for ghost-mcp-common
//!
//! Validates embedded JSON data files at compile time to catch errors early.
//! This ensures malformed JSON will fail the build rather than causing runtime errors.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn main() {
    // Tell Cargo to rerun if any JSON files change
    println!("cargo::rerun-if-changed=../../data/tools.json");
    println!("cargo::rerun-if-changed=../../data/categories.json");
    println!("cargo::rerun-if-changed=../../data/tool_docs.json");
    println!("cargo::rerun-if-changed=../../data/resources.json");
    println!("cargo::rerun-if-changed=../../data/prompts.json");

    let data_dir = Path::new("../../data");

    // Validate tools.json
    validate_tools_json(data_dir);

    // Validate categories.json
    validate_categories_json(data_dir);

    // Validate tool_docs.json
    validate_tool_docs_json(data_dir);

    // Validate resources.json
    validate_resources_json(data_dir);

    // Validate prompts.json
    validate_prompts_json(data_dir);

    println!("cargo::warning=All JSON data files validated successfully");
}

fn validate_tools_json(data_dir: &Path) {
    let path = data_dir.join("tools.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

    let tools: Vec<serde_json::Value> = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e));

    assert!(!tools.is_empty(), "tools.json must not be empty");

    for (i, tool) in tools.iter().enumerate() {
        let name = tool
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Tool {} missing 'name' field", i));

        assert!(
            tool.get("description").is_some(),
            "Tool '{}' missing 'description' field",
            name
        );

        let schema = tool
            .get("inputSchema")
            .unwrap_or_else(|| panic!("Tool '{}' missing 'inputSchema' field", name));

        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "Tool '{}' inputSchema.type must be 'object'",
            name
        );

        assert!(
            schema.get("properties").is_some(),
            "Tool '{}' inputSchema missing 'properties'",
            name
        );
    }
}

fn validate_categories_json(data_dir: &Path) {
    let path = data_dir.join("categories.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

    let categories: HashMap<String, serde_json::Value> = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e));

    // Expected categories
    let expected = [
        "memory",
        "module",
        "debug",
        "disasm",
        "script",
        "session",
        "process",
        "meta",
        "scanner",
        "command",
        "event",
        "ai",
        "api_trace",
    ];

    for cat in expected {
        let cat_obj = categories
            .get(cat)
            .unwrap_or_else(|| panic!("categories.json missing category: {}", cat));

        assert!(
            cat_obj.get("description").is_some(),
            "Category '{}' missing 'description'",
            cat
        );

        let tools = cat_obj
            .get("tools")
            .unwrap_or_else(|| panic!("Category '{}' missing 'tools'", cat));

        assert!(
            tools.is_array(),
            "Category '{}' tools must be an array",
            cat
        );
    }
}

fn validate_tool_docs_json(data_dir: &Path) {
    let path = data_dir.join("tool_docs.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

    let docs: HashMap<String, serde_json::Value> = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e));

    assert!(!docs.is_empty(), "tool_docs.json must not be empty");

    for (name, doc) in &docs {
        assert!(
            doc.get("name").is_some(),
            "Tool doc '{}' missing 'name'",
            name
        );
        assert!(
            doc.get("category").is_some(),
            "Tool doc '{}' missing 'category'",
            name
        );
        assert!(
            doc.get("description").is_some(),
            "Tool doc '{}' missing 'description'",
            name
        );
        assert!(
            doc.get("help").is_some(),
            "Tool doc '{}' missing 'help'",
            name
        );
        assert!(
            doc.get("examples").is_some(),
            "Tool doc '{}' missing 'examples'",
            name
        );
        assert!(
            doc.get("related").is_some(),
            "Tool doc '{}' missing 'related'",
            name
        );

        // Validate examples structure
        if let Some(examples) = doc.get("examples").and_then(|v| v.as_array()) {
            for (i, example) in examples.iter().enumerate() {
                assert!(
                    example.get("description").is_some(),
                    "Tool doc '{}' example {} missing 'description'",
                    name,
                    i
                );
                assert!(
                    example.get("arguments").is_some(),
                    "Tool doc '{}' example {} missing 'arguments'",
                    name,
                    i
                );
                assert!(
                    example.get("expected").is_some(),
                    "Tool doc '{}' example {} missing 'expected'",
                    name,
                    i
                );
            }
        }
    }
}

fn validate_resources_json(data_dir: &Path) {
    let path = data_dir.join("resources.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

    let resources: Vec<serde_json::Value> = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e));

    assert!(!resources.is_empty(), "resources.json must not be empty");

    for (i, resource) in resources.iter().enumerate() {
        let uri = resource
            .get("uri")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Resource {} missing 'uri' field", i));

        assert!(
            resource.get("name").is_some(),
            "Resource '{}' missing 'name' field",
            uri
        );
        assert!(
            resource.get("description").is_some(),
            "Resource '{}' missing 'description' field",
            uri
        );
    }
}

fn validate_prompts_json(data_dir: &Path) {
    let path = data_dir.join("prompts.json");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

    let prompts: Vec<serde_json::Value> = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e));

    assert!(!prompts.is_empty(), "prompts.json must not be empty");

    for (i, prompt) in prompts.iter().enumerate() {
        let name = prompt
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Prompt {} missing 'name' field", i));

        assert!(
            prompt.get("description").is_some(),
            "Prompt '{}' missing 'description' field",
            name
        );
    }
}
