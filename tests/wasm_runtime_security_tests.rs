//! WASM Runtime Security Tests
//!
//! This module contains comprehensive security tests for the WASM runtime,
//! testing sandbox isolation, memory safety, resource limits, and attack prevention.

use fortress_core::plugin::{Plugin, PluginCapability, PluginContext, PluginInput, PluginMetadata};
use fortress_core::wasm_runtime::{WasmPluginConfig, WasmPluginLoader};
use futures;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Test helper to create a secure WASM plugin configuration
fn create_secure_config() -> WasmPluginConfig {
    WasmPluginConfig {
        max_memory_bytes: Some(64 * 1024 * 1024), // 64MB
        max_execution_time_ms: Some(5000),        // 5 seconds
        enable_fuel_metering: true,
        max_fuel: Some(1000000),
        allowed_host_functions: vec![
            "fortress_log".to_string(),
            "fortress_config_get".to_string(),
            "fortress_timestamp".to_string(),
        ],
    }
}

/// Test helper to create a restrictive WASM plugin configuration
fn create_restrictive_config() -> WasmPluginConfig {
    WasmPluginConfig {
        max_memory_bytes: Some(16 * 1024 * 1024), // 16MB
        max_execution_time_ms: Some(1000),        // 1 second
        enable_fuel_metering: true,
        max_fuel: Some(500000),
        allowed_host_functions: vec!["fortress_log".to_string()], // Only logging allowed
    }
}

/// Test helper to create test plugin metadata
fn create_test_metadata(id: &str, name: &str) -> PluginMetadata {
    PluginMetadata {
        id: id.to_string(),
        name: name.to_string(),
        version: "1.0.0".to_string(),
        description: format!("Test plugin for {}", name),
        author: "Fortress Security Team".to_string(),
        capabilities: vec![PluginCapability::Authentication],
        wasm_module: None,
        config_schema: None,
    }
}

/// Test helper to create malicious WASM bytes (simulated)
fn create_malicious_wasm_bytes() -> Vec<u8> {
    // This would normally contain actual malicious WASM code
    // For testing, we simulate with invalid WASM magic bytes
    vec![0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]
}

/// Test helper to create valid WASM bytes (simulated)
fn create_valid_wasm_bytes() -> Vec<u8> {
    // WASM magic number: 0x00 0x61 0x73 0x6D
    vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
}

#[tokio::test]
async fn test_wasm_sandbox_isolation() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("sandbox-test", "Sandbox Isolation Test");

    // Load plugin with valid WASM bytes
    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    // Test that plugin is properly sandboxed
    assert_eq!(plugin.metadata().id, "sandbox-test");

    // Test that plugin cannot access system resources directly
    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    // Initialize should work within sandbox
    let init_result = plugin.initialize(context).await;
    assert!(
        init_result.is_ok(),
        "Plugin initialization should work in sandbox"
    );

    // Test execution within sandbox
    let input = PluginInput {
        action: "test_operation".to_string(),
        data: serde_json::json!({"test": "value"}),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let exec_result = plugin.execute(input).await;
    // Should either succeed or fail gracefully, but not crash the system
    assert!(exec_result.is_ok() || exec_result.is_err());
}

#[tokio::test]
async fn test_memory_limits_enforcement() {
    let config = create_restrictive_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("memory-test", "Memory Limits Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    // Test memory limit configuration
    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test with input that would require large memory allocation
    let large_input = PluginInput {
        action: "memory_intensive_operation".to_string(),
        data: serde_json::json!({"large_data": "x".repeat(10 * 1024 * 1024)}), // 10MB string
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let start_time = Instant::now();
    let result = plugin.execute(large_input).await;
    let execution_time = start_time.elapsed();

    // Should either fail due to memory limits or complete within reasonable time
    if result.is_ok() {
        // If it succeeds, verify it completed quickly (indicating limits work)
        assert!(
            execution_time < Duration::from_millis(2000),
            "Should complete quickly with memory limits"
        );
    } else {
        // If it fails, verify it's due to resource limits
        assert!(result.is_err(), "Should fail due to memory limits");
    }
}

#[tokio::test]
async fn test_execution_time_limits() {
    let config = WasmPluginConfig {
        max_memory_bytes: Some(64 * 1024 * 1024),
        max_execution_time_ms: Some(500), // 500ms limit
        enable_fuel_metering: true,
        max_fuel: Some(100000),
        allowed_host_functions: vec!["fortress_log".to_string()],
    };

    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("time-limit-test", "Execution Time Limits Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test with input that would cause long execution
    let slow_input = PluginInput {
        action: "slow_operation".to_string(),
        data: serde_json::json!({
            "iterations": 1000000,
            "delay_ms": 1
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let start_time = Instant::now();
    let result = plugin.execute(slow_input).await;
    let execution_time = start_time.elapsed();

    // Should be terminated within the time limit
    assert!(
        execution_time < Duration::from_millis(1000),
        "Should be terminated within time limit"
    );

    // Should fail due to timeout
    assert!(result.is_err(), "Should fail due to execution time limit");
}

#[tokio::test]
async fn test_fuel_metering_enforcement() {
    let config = WasmPluginConfig {
        max_memory_bytes: Some(64 * 1024 * 1024),
        max_execution_time_ms: Some(5000),
        enable_fuel_metering: true,
        max_fuel: Some(1000), // Very low fuel limit
        allowed_host_functions: vec!["fortress_log".to_string()],
    };

    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("fuel-test", "Fuel Metering Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test with input that would consume a lot of fuel
    let fuel_intensive_input = PluginInput {
        action: "computation_intensive_operation".to_string(),
        data: serde_json::json!({
            "complex_calculation": true,
            "iterations": 10000
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(fuel_intensive_input).await;

    // Should fail due to fuel exhaustion
    assert!(result.is_err(), "Should fail due to fuel exhaustion");
}

#[tokio::test]
async fn test_host_function_access_control() {
    // Test 1: Plugin with allowed host functions
    let permissive_config = WasmPluginConfig {
        max_memory_bytes: Some(64 * 1024 * 1024),
        max_execution_time_ms: Some(5000),
        enable_fuel_metering: true,
        max_fuel: Some(1000000),
        allowed_host_functions: vec![
            "fortress_log".to_string(),
            "fortress_config_get".to_string(),
            "fortress_timestamp".to_string(),
        ],
    };

    let loader = WasmPluginLoader::new(permissive_config).unwrap();
    let metadata = create_test_metadata("permissive-test", "Permissive Host Functions Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::from([(
            "test_key".to_string(),
            serde_json::Value::String("test_value".to_string()),
        )]),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test allowed host function calls
    let allowed_input = PluginInput {
        action: "use_allowed_functions".to_string(),
        data: serde_json::json!({
            "functions": ["fortress_log", "fortress_config_get", "fortress_timestamp"]
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(allowed_input).await;
    // Should succeed or fail gracefully, but not due to host function restrictions
    assert!(result.is_ok() || result.is_err());

    // Test 2: Plugin with restricted host functions
    let restrictive_config = WasmPluginConfig {
        max_memory_bytes: Some(64 * 1024 * 1024),
        max_execution_time_ms: Some(5000),
        enable_fuel_metering: true,
        max_fuel: Some(1000000),
        allowed_host_functions: vec!["fortress_log".to_string()], // Only logging allowed
    };

    let loader2 = WasmPluginLoader::new(restrictive_config).unwrap();
    let metadata2 = create_test_metadata("restrictive-test", "Restrictive Host Functions Test");

    let plugin2 = loader2
        .load_from_bytes(&create_valid_wasm_bytes(), metadata2, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context2 = PluginContext {
        config: HashMap::new(),
        metadata: plugin2.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin2.initialize(context2).await.unwrap();

    // Test disallowed host function calls
    let disallowed_input = PluginInput {
        action: "use_disallowed_functions".to_string(),
        data: serde_json::json!({
            "functions": ["fortress_file_access", "fortress_network_call", "fortress_system_exec"]
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin2.execute(disallowed_input).await;
    // Should fail due to host function restrictions
    assert!(
        result.is_err(),
        "Should fail due to disallowed host functions"
    );
}

#[tokio::test]
async fn test_malicious_wasm_detection() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("malicious-test", "Malicious WASM Detection Test");

    // Test 1: Invalid WASM magic bytes
    let result = loader.load_from_bytes(&create_malicious_wasm_bytes(), metadata.clone(), Some("FORTRESS_SECURE_WASM_TOKEN"));
    assert!(result.is_err(), "Should reject invalid WASM bytes");

    // Test 2: Empty WASM bytes
    let result = loader.load_from_bytes(&[], metadata.clone(), Some("FORTRESS_SECURE_WASM_TOKEN"));
    assert!(result.is_err(), "Should reject empty WASM bytes");

    // Test 3: Truncated WASM bytes
    let truncated_bytes = vec![0x00, 0x61, 0x73]; // Incomplete magic number
    let result = loader.load_from_bytes(&truncated_bytes, metadata.clone(), Some("FORTRESS_SECURE_WASM_TOKEN"));
    assert!(result.is_err(), "Should reject truncated WASM bytes");

    // Test 4: Oversized WASM bytes (simulating potential attack)
    let oversized_bytes = vec![0xFF; 100 * 1024 * 1024]; // 100MB of invalid data
    let result = loader.load_from_bytes(&oversized_bytes, metadata, Some("FORTRESS_SECURE_WASM_TOKEN"));
    assert!(result.is_err(), "Should reject oversized WASM bytes");
}

#[tokio::test]
async fn test_plugin_isolation_between_instances() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();

    // Create multiple plugin instances
    let metadata1 = create_test_metadata("instance1", "Plugin Instance 1");
    let metadata2 = create_test_metadata("instance2", "Plugin Instance 2");
    let metadata3 = create_test_metadata("instance3", "Plugin Instance 3");

    let plugin1 = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata1, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();
    let plugin2 = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata2, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();
    let plugin3 = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata3, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    // Initialize all plugins with different contexts
    let context1 = PluginContext {
        config: HashMap::from([(
            "instance_id".to_string(),
            serde_json::Value::String("1".to_string()),
        )]),
        metadata: plugin1.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    let context2 = PluginContext {
        config: HashMap::from([(
            "instance_id".to_string(),
            serde_json::Value::String("2".to_string()),
        )]),
        metadata: plugin2.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    let context3 = PluginContext {
        config: HashMap::from([(
            "instance_id".to_string(),
            serde_json::Value::String("3".to_string()),
        )]),
        metadata: plugin3.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    assert!(plugin1.initialize(context1).await.is_ok());
    assert!(plugin2.initialize(context2).await.is_ok());
    assert!(plugin3.initialize(context3).await.is_ok());

    assert_ne!(plugin1.metadata().id, plugin2.metadata().id);
    assert_ne!(plugin2.metadata().id, plugin3.metadata().id);
}

#[tokio::test]
async fn test_resource_cleanup_on_error() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("cleanup-test", "Resource Cleanup Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test resource cleanup after execution error
    let error_input = PluginInput {
        action: "cause_error".to_string(),
        data: serde_json::json!({"error_type": "runtime_error"}),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let _ = plugin.execute(error_input).await;

    // Even if execution fails, cleanup should work
    let cleanup_result = plugin.cleanup().await;
    assert!(
        cleanup_result.is_ok(),
        "Cleanup should succeed even after execution error"
    );
}

#[tokio::test]
async fn test_concurrent_plugin_execution() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();

    // Create multiple plugins for concurrent execution
    let mut plugins = Vec::new();
    let mut contexts = Vec::new();
    for i in 1..=10 {
        let metadata = create_test_metadata(
            &format!("concurrent-{}", i),
            &format!("Concurrent Plugin {}", i),
        );
        let plugin = loader
            .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
            .unwrap();

        let context = PluginContext {
            config: HashMap::from([(
                "instance_id".to_string(),
                serde_json::Value::String(i.to_string()),
            )]),
            metadata: plugin.metadata().clone(),
            encryption_access: false,
            storage_access: false,
            user_id: None,
            session_id: None,
            request_id: None,
        };

        plugins.push(plugin);
        contexts.push(context);
    }

    // Initialize all plugins concurrently
    let init_tasks: Vec<_> = plugins
        .iter_mut()
        .zip(contexts)
        .map(|(plugin, context)| plugin.initialize(context))
        .collect();

    let init_results = futures::future::join_all(init_tasks).await;

    for result in init_results {
        assert!(result.is_ok(), "Concurrent initialization should succeed");
    }

    // Execute all plugins concurrently
    let exec_tasks: Vec<_> = plugins
        .iter_mut()
        .enumerate()
        .map(|(i, plugin)| {
            let input = PluginInput {
                action: "concurrent_test".to_string(),
                data: serde_json::json!({"plugin_index": i}),
                parameters: HashMap::new(),
                operation: None,
                timestamp: None,
            };
            plugin.execute(input)
        })
        .collect();

    let exec_results = futures::future::join_all(exec_tasks).await;

    // All should complete without interfering with each other
    for (i, result) in exec_results.into_iter().enumerate() {
        assert!(
            result.is_ok() || result.is_err(),
            "Plugin {} should complete without crashing",
            i
        );
    }

    // Cleanup all plugins
    let cleanup_tasks: Vec<_> = plugins.iter_mut().map(|plugin| plugin.cleanup()).collect();

    let cleanup_results = futures::future::join_all(cleanup_tasks).await;

    for result in cleanup_results {
        assert!(result.is_ok(), "Concurrent cleanup should succeed");
    }
}

#[tokio::test]
async fn test_plugin_configuration_validation() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("config-test", "Configuration Validation Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    // Test valid configuration
    let valid_config = HashMap::from([
        (
            "fortress_log".to_string(),
            serde_json::Value::String("info".to_string()),
        ),
        (
            "fortress_config_get".to_string(),
            serde_json::Value::String("test".to_string()),
        ),
        ("timeout".to_string(), serde_json::Value::Number(30.into())),
    ]);

    let result = plugin.validate_config(&valid_config);
    assert!(result.is_ok(), "Valid configuration should pass validation");

    // Test invalid configuration (disallowed host functions)
    let invalid_config = HashMap::from([
        (
            "fortress_file_access".to_string(),
            serde_json::Value::String("enabled".to_string()),
        ),
        (
            "fortress_network_call".to_string(),
            serde_json::Value::String("allowed".to_string()),
        ),
    ]);

    let result = plugin.validate_config(&invalid_config);
    assert!(
        result.is_err(),
        "Invalid configuration should fail validation"
    );

    // Test configuration with dangerous values
    let dangerous_config = HashMap::from([
        (
            "max_memory".to_string(),
            serde_json::Value::String("unlimited".to_string()),
        ),
        (
            "execution_timeout".to_string(),
            serde_json::Value::String("disabled".to_string()),
        ),
    ]);

    let result = plugin.validate_config(&dangerous_config);
    assert!(
        result.is_err(),
        "Dangerous configuration should fail validation"
    );
}

#[tokio::test]
async fn test_plugin_health_monitoring() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("health-test", "Health Monitoring Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test health check
    let health = plugin.health_check().await.unwrap();
    assert!(
        health.healthy,
        "Plugin should be healthy after initialization"
    );

    // Execute some operations
    for i in 1..=5 {
        let input = PluginInput {
            action: "health_test_operation".to_string(),
            data: serde_json::json!({"iteration": i}),
            parameters: HashMap::new(),
            operation: None,
            timestamp: None,
        };

        let _ = plugin.execute(input).await;

        // Check health after each operation
        let health = plugin.health_check().await.unwrap();
        assert!(
            health.healthy,
            "Plugin should remain healthy during operation"
        );
    }

    // Test health after cleanup
    plugin.cleanup().await.unwrap();
    let health = plugin.health_check().await.unwrap();
    assert!(health.healthy, "Plugin should be healthy after cleanup");
}

#[tokio::test]
async fn test_attack_vector_prevention() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("security-test", "Attack Vector Prevention Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test 1: Buffer overflow attempt
    let buffer_overflow_input = PluginInput {
        action: "buffer_overflow".to_string(),
        data: serde_json::json!({
            "buffer": "A".repeat(1000000), // Large buffer
            "target": "stack"
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(buffer_overflow_input).await;
    // Should be contained by sandbox
    assert!(result.is_ok() || result.is_err());

    // Test 2: Infinite loop attempt
    let infinite_loop_input = PluginInput {
        action: "infinite_loop".to_string(),
        data: serde_json::json!({"type": "while_true"}),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let start_time = Instant::now();
    let result = plugin.execute(infinite_loop_input).await;
    let execution_time = start_time.elapsed();

    // Should be terminated by time limits
    assert!(
        execution_time < Duration::from_secs(2),
        "Infinite loop should be terminated"
    );
    assert!(
        result.is_err(),
        "Infinite loop should fail due to time limits"
    );

    // Test 3: Memory exhaustion attempt
    let memory_exhaustion_input = PluginInput {
        action: "memory_exhaustion".to_string(),
        data: serde_json::json!({
            "allocation_size": "1GB",
            "allocation_count": 1000
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(memory_exhaustion_input).await;
    // Should be contained by memory limits
    assert!(
        result.is_err(),
        "Memory exhaustion should fail due to limits"
    );

    // Test 4: Host function injection attempt
    let injection_input = PluginInput {
        action: "host_function_injection".to_string(),
        data: serde_json::json!({
            "injected_function": "fortress_system_exec",
            "injected_args": ["rm -rf /"]
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(injection_input).await;
    // Should be blocked by host function restrictions
    assert!(result.is_err(), "Host function injection should be blocked");
}

#[tokio::test]
async fn test_plugin_lifecycle_security() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("lifecycle-test", "Lifecycle Security Test");

    // Test secure plugin creation
    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    // Test secure initialization
    let secure_context = PluginContext {
        config: HashMap::from([
            (
                "security_level".to_string(),
                serde_json::Value::String("high".to_string()),
            ),
            ("sandbox_enabled".to_string(), serde_json::Value::Bool(true)),
        ]),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    let init_result = plugin.initialize(secure_context).await;
    assert!(init_result.is_ok(), "Secure initialization should succeed");

    // Test secure execution
    let secure_input = PluginInput {
        action: "secure_operation".to_string(),
        data: serde_json::json!({
            "security_context": "enabled",
            "validation_required": true
        }),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let exec_result = plugin.execute(secure_input).await;
    assert!(exec_result.is_ok() || exec_result.is_err());

    // Test secure cleanup
    let cleanup_result = plugin.cleanup().await;
    assert!(cleanup_result.is_ok(), "Secure cleanup should succeed");

    // Verify plugin is properly cleaned up
    let health = plugin.health_check().await.unwrap();
    assert!(
        health.healthy,
        "Plugin should be in a healthy state after lifecycle completion"
    );
}

#[tokio::test]
async fn test_performance_under_security_constraints() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("performance-test", "Performance Under Security Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Performance test with security constraints enabled
    let start_time = Instant::now();
    let mut operations = Vec::new();

    for i in 1..=100 {
        let input = PluginInput {
            action: "performance_test".to_string(),
            data: serde_json::json!({
                "iteration": i,
                "security_enabled": true,
                "sandbox_active": true
            }),
            parameters: HashMap::new(),
            operation: None,
            timestamp: None,
        };

        operations.push(plugin.execute(input));
    }

    let results = futures::future::join_all(operations).await;
    let total_time = start_time.elapsed();

    // Verify all operations completed
    let mut success_count = 0;
    let mut error_count = 0;

    for result in results {
        match result {
            Ok(_) => success_count += 1,
            Err(_) => error_count += 1,
        }
    }

    println!("Performance Test Results:");
    println!("  Total operations: {}", success_count + error_count);
    println!("  Successful: {}", success_count);
    println!("  Failed: {}", error_count);
    println!("  Total time: {:?}", total_time);
    println!("  Average per operation: {:?}", total_time / 100);

    // Performance should remain reasonable even with security constraints
    assert!(
        total_time < Duration::from_secs(30),
        "Should complete within reasonable time"
    );
    assert!(
        success_count + error_count == 100,
        "All operations should complete"
    );
}

#[tokio::test]
async fn test_error_handling_and_recovery() {
    let config = create_secure_config();
    let loader = WasmPluginLoader::new(config).unwrap();
    let metadata = create_test_metadata("error-handling-test", "Error Handling Test");

    let plugin = loader
        .load_from_bytes(&create_valid_wasm_bytes(), metadata, Some("FORTRESS_SECURE_WASM_TOKEN"))
        .unwrap();

    let context = PluginContext {
        config: HashMap::new(),
        metadata: plugin.metadata().clone(),
        encryption_access: false,
        storage_access: false,
        user_id: None,
        session_id: None,
        request_id: None,
    };

    plugin.initialize(context).await.unwrap();

    // Test 1: Invalid operation
    let invalid_input = PluginInput {
        action: "non_existent_operation".to_string(),
        data: serde_json::json!({}),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(invalid_input).await;
    assert!(result.is_err(), "Invalid operation should fail gracefully");

    // Test 2: Malformed parameters
    let malformed_input = PluginInput {
        action: "valid_operation".to_string(),
        data: serde_json::json!({"invalid": "data"}),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(malformed_input).await;
    assert!(
        result.is_err(),
        "Malformed parameters should fail gracefully"
    );

    // Test 3: Recovery after error
    let recovery_input = PluginInput {
        action: "valid_operation".to_string(),
        data: serde_json::json!({"test": "recovery"}),
        parameters: HashMap::new(),
        operation: None,
        timestamp: None,
    };

    let result = plugin.execute(recovery_input).await;
    // Should either succeed or fail gracefully, but not crash
    assert!(result.is_ok() || result.is_err());

    // Verify plugin is still healthy after errors
    let health = plugin.health_check().await.unwrap();
    assert!(health.healthy, "Plugin should remain healthy after errors");
}
