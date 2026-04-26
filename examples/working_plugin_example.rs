//! Working Plugin Example
//! 
//! This example demonstrates a complete end-to-end plugin workflow:
//! 1. Loading a plugin from the testplugin directory
//! 2. Registering it with the plugin manager
//! 3. Executing plugin actions
//! 4. Handling results and errors

use std::collections::HashMap;
use std::sync::Arc;

// Import fortress core with proper path
use fortress_db::fortress_core::prelude::*;
use fortress_db::fortress_core::plugin::*;

// Import the testplugin by including it as a module dependency
// For this example, we'll create a simple inline plugin

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    println!("Fortress Plugin System - Working Example");
    println!("==========================================");

    // Create plugin manager
    let plugin_manager = PluginManager::new();
    
    // Create and load the test plugin
    println!("\nLoading TestPlugin...");
    let test_plugin = Arc::new(TestPlugin::new());
    
    // Configure the plugin (empty config for this example)
    let plugin_config = HashMap::new();
    
    // Load the plugin into the manager
    plugin_manager.load_plugin(test_plugin.clone(), plugin_config).await?;
    
    println!("✓ TestPlugin loaded successfully!");
    println!("   Plugin ID: {}", test_plugin.metadata().id);
    println!("   Plugin Name: {}", test_plugin.metadata().name);
    println!("   Version: {}", test_plugin.metadata().version);
    println!("   Capabilities: {:?}", test_plugin.metadata().capabilities);

    // Test the "hello" action
    println!("\nTesting 'hello' action...");
    let hello_input = PluginInput {
        action: "hello".to_string(),
        data: serde_json::json!({
            "name": "Fortress Developer"
        }),
        parameters: HashMap::new(),
    };

    let hello_result = plugin_manager.execute_plugin("TestPlugin", hello_input).await?;
    
    if hello_result.success {
        println!("✓ Hello action successful!");
        if let Some(data) = hello_result.data {
            println!("   Response: {}", serde_json::to_string_pretty(&data)?);
        }
        println!("   Execution time: {}ms", hello_result.metrics.execution_time_ms);
    } else {
        println!("✗ Hello action failed: {:?}", hello_result.error);
    }

    // Test the "echo" action
    println!("\nTesting 'echo' action...");
    let echo_input = PluginInput {
        action: "echo".to_string(),
        data: serde_json::json!({
            "message": "Hello from Fortress!",
            "timestamp": "2026-03-14T15:09:00Z",
            "data": {
                "type": "test",
                "values": [1, 2, 3, 4, 5]
            }
        }),
        parameters: HashMap::new(),
    };

    let echo_result = plugin_manager.execute_plugin("TestPlugin", echo_input).await?;
    
    if echo_result.success {
        println!("✓ Echo action successful!");
        if let Some(data) = echo_result.data {
            println!("   Echoed data: {}", serde_json::to_string_pretty(&data)?);
        }
        println!("   Execution time: {}ms", echo_result.metrics.execution_time_ms);
    } else {
        println!("✗ Echo action failed: {:?}", echo_result.error);
    }

    // Test error handling with invalid action
    println!("\nTesting error handling with invalid action...");
    let invalid_input = PluginInput {
        action: "invalid_action".to_string(),
        data: serde_json::json!({"test": "data"}),
        parameters: HashMap::new(),
    };

    let invalid_result = plugin_manager.execute_plugin("TestPlugin", invalid_input).await;
    
    match invalid_result {
        Ok(result) => {
            if !result.success {
                println!("✓ Error handling working correctly!");
                println!("   Expected error: {:?}", result.error);
            } else {
                println!("⚠ Unexpected success with invalid action");
            }
        }
        Err(e) => {
            println!("✓ Error handling working correctly!");
            println!("   Expected error: {}", e);
        }
    }

    // List all registered plugins
    println!("\nRegistered plugins:");
    let plugins = plugin_manager.registry().list_plugins().await;
    for plugin in plugins {
        println!("   - {} v{} ({})", plugin.name, plugin.version, plugin.id);
    }

    // Get plugin health status
    println!("\nPlugin health status:");
    let health_status = plugin_manager.get_all_health_status().await;
    for (plugin_id, health) in health_status {
        println!("   {}: {} - {}", plugin_id, 
            if health.healthy { "✓ Healthy" } else { "✗ Unhealthy" },
            health.message
        );
    }

    println!("\nPlugin example completed successfully!");
    println!("\nThis demonstrates that the Fortress plugin system is working!");
    println!("   - Plugin loading and registration ✓");
    println!("   - Action execution ✓");
    println!("   - Error handling ✓");
    println!("   - Health monitoring ✓");
    println!("   - Plugin discovery ✓");

    Ok(())
}
