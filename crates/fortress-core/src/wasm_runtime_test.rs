//! Simple test to verify WASM runtime is working

use crate::plugin::{Plugin, PluginCapability, PluginContext, PluginInput, PluginMetadata};
use crate::wasm_runtime::{WasmPlugin, WasmPluginConfig, WasmPluginLoader};

#[tokio::test]
async fn test_wasm_runtime_basic() {
    // Create loader with default config
    let config = WasmPluginConfig::default();
    let loader = WasmPluginLoader::new(config).expect("Failed to create WASM loader");

    // Create test metadata
    let metadata = PluginMetadata {
        id: "test-wasm-plugin".to_string(),
        name: "Test WASM Plugin".to_string(),
        version: "1.0.0".to_string(),
        description: "Test plugin for WASM runtime verification".to_string(),
        author: "Fortress Team".to_string(),
        capabilities: vec![PluginCapability::Authentication],
        config_schema: Some(serde_json::Value::Null),
        wasm_module: None,
    };

    // Load plugin
    let plugin = loader
        .load_from_bytes(&[0x00, 0x61, 0x73, 0x6d], metadata.clone())
        .expect("Failed to load WASM plugin");

    // Verify plugin metadata
    assert_eq!(plugin.metadata().id, "test-wasm-plugin");
    assert_eq!(plugin.metadata().name, "Test WASM Plugin");

    // Initialize plugin
    let context = PluginContext {
        config: std::collections::HashMap::new(),
        metadata: metadata,
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin
        .initialize(context)
        .await
        .expect("Failed to initialize plugin");

    // Test plugin execution
    let input = PluginInput {
        action: "authenticate".to_string(),
        data: serde_json::json!({
            "username": "valid_user",
            "password": "test_password"
        }),
        parameters: std::collections::HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin
        .execute(input)
        .await
        .expect("Failed to execute plugin");
    assert!(result.success);
    assert!(result.data.is_some());

    // Test health check
    let health = plugin
        .health_check()
        .await
        .expect("Failed to get health status");
    assert!(health.healthy);

    // Test cleanup
    plugin.cleanup().await.expect("Failed to cleanup plugin");

    println!("WASM runtime test passed!");
}

#[tokio::test]
async fn test_wasm_config_validation() {
    let config = WasmPluginConfig::default();
    let loader = WasmPluginLoader::new(config).expect("Failed to create WASM loader");

    let metadata = PluginMetadata {
        id: "config-test-plugin".to_string(),
        name: "Config Test Plugin".to_string(),
        version: "1.0.0".to_string(),
        description: "Test plugin for config validation".to_string(),
        author: "Fortress Team".to_string(),
        capabilities: vec![PluginCapability::Authentication],
        config_schema: Some(serde_json::Value::Null),
        wasm_module: None,
    };

    let plugin = loader
        .load_from_bytes(&[0x00, 0x61, 0x73, 0x6d], metadata)
        .expect("Failed to load WASM plugin");

    // Test valid config
    let valid_config = std::collections::HashMap::from([
        (
            "fortress_log".to_string(),
            serde_json::Value::String("info".to_string()),
        ),
        (
            "fortress_config_get".to_string(),
            serde_json::Value::String("test".to_string()),
        ),
    ]);

    assert!(plugin.validate_config(&valid_config).is_ok());

    // Test invalid config
    let invalid_config = std::collections::HashMap::from([(
        "invalid_function".to_string(),
        serde_json::Value::String("test".to_string()),
    )]);

    assert!(plugin.validate_config(&invalid_config).is_err());

    println!("WASM config validation test passed!");
}
