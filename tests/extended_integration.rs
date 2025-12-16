use ghost_agent::backend::InProcessBackend;
use ghost_common::ipc::{Request, ResponseResult};

#[test]
fn test_integration_memory_flow() {
    let backend = InProcessBackend::new().expect("Failed to create backend");

    // Simulate table_add
    let params = serde_json::json!({
        "address": "0x12345678",
        "type": "byte",
        "description": "Health",
        "pointer_chain": [0x10, 0x20]
    });

    let req = Request {
        id: 1,
        method: "table_add".to_string(),
        params,
    };

    let res = backend.handle_request(&req);
    match res.result {
        ResponseResult::Success(val) => {
            assert!(val["success"].as_bool().unwrap_or(false));
            assert!(val["id"].is_string());
        }
        ResponseResult::Error { code, message } => {
            panic!("Request failed: {} ({})", message, code);
        }
    }
}

#[test]
fn test_integration_input_flow() {
    let backend = InProcessBackend::new().expect("Failed to create backend");

    // Simulate input_key_press (stubbed)
    let params = serde_json::json!({
        "key": "0x41" // 'A'
    });

    let req = Request {
        id: 2,
        method: "input_key_press".to_string(),
        params,
    };

    let res = backend.handle_request(&req);
    match res.result {
        ResponseResult::Success(val) => {
            assert!(val["success"].as_bool().unwrap_or(false));
        }
        ResponseResult::Error { code, message } => {
            panic!("Request failed: {} ({})", message, code);
        }
    }
}
