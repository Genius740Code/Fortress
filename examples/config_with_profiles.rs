//! Configuration with Performance Profiles Example
//!
//! This example demonstrates how to load and use Fortress configuration
//! with performance profiles from a TOML file.

use fortress_core::prelude::*;

fn main() -> Result<()> {
    println!("🔧 Fortress Configuration with Performance Profiles\n");

    // Load configuration from file
    let config_path = "examples/performance_profile_config.toml";
    println!("📁 Loading configuration from: {}", config_path);
    
    let config = match Config::from_file(config_path) {
        Ok(config) => {
            println!("✅ Configuration loaded successfully!");
            config
        }
        Err(e) => {
            println!("❌ Failed to load configuration: {}", e);
            println!("💡 Using default configuration instead...");
            Config::default()
        }
    };

    println!();

    // Display basic configuration info
    println!("📋 Configuration Summary:");
    println!("Database Path: {}", config.database.path);
    println!("Default Algorithm: {}", config.encryption.default_algorithm);
    println!("Available Profiles: {}", config.encryption.profiles.len());
    println!();

    // Display profile information
    println!("🎯 Available Performance Profiles:");
    for (name, profile) in &config.encryption.profiles {
        println!("📝 Profile: {} ({:?})", name, profile.performance_profile);
        println!("   Algorithm: {}", profile.algorithm);
        println!("   Key Rotation: {:?}", profile.key_rotation_interval);
        if !profile.parameters.is_empty() {
            println!("   Parameters: {} custom settings", profile.parameters.len());
        }
        println!();
    }

    // Now demonstrate the new performance profile system
    println!("🚀 Advanced Performance Profile System:");
    demonstrate_performance_profiles()?;

    // Show how to create a custom configuration
    println!("🛠️  Creating Custom Configuration:");
    create_custom_config_example()?;

    println!("✅ Configuration example completed successfully!");
    Ok(())
}

fn demonstrate_performance_profiles() -> Result<()> {
    let manager = ProfileManager::new();
    
    println!("📋 Available Advanced Profiles:");
    for profile_name in manager.list_profiles() {
        let profile = manager.get_profile(profile_name).unwrap();
        println!("📝 {} ({})", profile.name, profile.profile_type);
        if let Some(description) = &profile.description {
            println!("   Description: {}", description);
        }
        println!("   Memory: {}MB, CPU: {}%, Threads: {}", 
                 profile.resources.max_memory_mb,
                 profile.resources.max_cpu_percent,
                 profile.resources.thread_pool_size);
        println!("   Algorithm: {}, KDF: {} ({}MB, {} iterations)",
                 profile.encryption.algorithm,
                 profile.encryption.kdf,
                 profile.encryption.kdf_memory_cost / 1024,
                 profile.encryption.kdf_iterations);
        println!();
    }

    // Demonstrate profile selection based on use case
    println!("🎮 Profile Selection Examples:");
    demonstrate_profile_selection()?;

    Ok(())
}

fn demonstrate_profile_selection() -> Result<()> {
    let use_cases = vec![
        ("Gaming Server", "gaming"),
        ("Web Application", "balanced"),
        ("Financial System", "fortress"),
        ("Development Environment", "balanced"),
        ("High-Frequency Trading", "lightning"),
    ];

    for (use_case, recommended_profile) in use_cases {
        println!("📌 {}: Recommended profile = '{}'", use_case, recommended_profile);
        
        match recommended_profile {
            "gaming" => {
                println!("   Reason: High performance with low latency requirements");
                println!("   Settings: Fast encryption, no compression, large buffers");
            }
            "balanced" => {
                println!("   Reason: Good balance of performance and security");
                println!("   Settings: Moderate encryption, LZ4 compression, normal sync");
            }
            "fortress" => {
                println!("   Reason: Maximum security required");
                println!("   Settings: Strong encryption, maximum compression, full sync");
            }
            "lightning" => {
                println!("   Reason: Maximum throughput required");
                println!("   Settings: Fastest encryption, no compression, async writes");
            }
            _ => {
                println!("   Reason: Custom configuration needed");
            }
        }
        println!();
    }

    Ok(())
}

fn create_custom_config_example() -> Result<()> {
    // Create a custom profile for IoT devices
    let mut iot_profile = PerformanceProfileConfig::new("iot_device".to_string());
    iot_profile.description = Some("Optimized for IoT devices with limited resources".to_string());
    iot_profile.tags = vec!["iot".to_string(), "embedded".to_string(), "low-power".to_string()];
    
    // Configure for resource-constrained IoT devices
    iot_profile.resources = ResourceLimits {
        max_memory_mb: 128,       // Very limited memory
        max_cpu_percent: 30,       // Low CPU usage
        max_concurrent_ops: 10,    // Low concurrency
        thread_pool_size: 1,       // Single thread
        cache_size_mb: 16,         // Small cache
    };
    
    iot_profile.encryption = EncryptionSettings {
        algorithm: "chacha20poly1305".to_string(), // Efficient encryption
        kdf: "argon2id".to_string(),
        kdf_memory_cost: 4096,    // Very low memory usage
        kdf_iterations: 1,        // Fast key derivation
        kdf_parallelism: 1,
        hardware_acceleration: false, // May not be available
        simd_optimizations: false,  // May not be available
        batch_size: 64,            // Small batches
    };
    
    iot_profile.storage = StorageSettings {
        compression: "none".to_string(), // No compression to save CPU
        compression_level: 0,
        enable_wal: false,      // Save storage space
        sync_mode: SyncMode::Normal,
        page_size: 1024,         // Small pages
        cache_pages: 32,
        async_writes: true,
        batch_write_size: 5,     // Very small batches
    };
    
    iot_profile.network = NetworkSettings {
        connection_timeout_secs: 10,
        request_timeout_secs: 30,
        max_connections: 5,
        connection_pool_size: 1,
        keep_alive: true,
        compression: false,       // Save CPU
        buffer_size: 1024,       // Small buffers
    };

    println!("🔧 IoT Device Profile:");
    println!("{}", iot_profile.summary());
    println!("   Memory usage: {}MB (very low)", iot_profile.resources.max_memory_mb);
    println!("   CPU usage: {}% (conservative)", iot_profile.resources.max_cpu_percent);
    println!("   Storage: No compression, small pages to save space");
    println!("   Network: Small buffers, limited connections");
    println!();

    // Validate the custom profile
    match iot_profile.validate() {
        Ok(_) => println!("✅ IoT profile validation passed"),
        Err(e) => println!("❌ IoT profile validation failed: {}", e),
    }

    // Create a profile manager and add the custom profile
    let mut manager = ProfileManager::new();
    match manager.add_profile(iot_profile) {
        Ok(_) => {
            println!("✅ IoT profile added to manager");
            println!("📋 Total profiles available: {}", manager.list_profiles().len());
        }
        Err(e) => println!("❌ Failed to add IoT profile: {}", e),
    }

    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_loading() {
        // Test that we can create a default config
        let config = Config::default();
        assert!(!config.encryption.profiles.is_empty());
        assert!(config.encryption.profiles.contains_key("balanced"));
    }

    #[test]
    fn test_custom_profile_creation() {
        let profile = PerformanceProfileConfig::new("test".to_string());
        assert_eq!(profile.name, "test");
        assert_eq!(profile.profile_type, PerformanceProfile::Custom);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_iot_profile() {
        let mut iot_profile = PerformanceProfileConfig::new("iot_test".to_string());
        iot_profile.resources.max_memory_mb = 128;
        iot_profile.resources.max_cpu_percent = 30;
        
        assert!(iot_profile.validate().is_ok());
        assert_eq!(iot_profile.resources.max_memory_mb, 128);
        assert_eq!(iot_profile.resources.max_cpu_percent, 30);
    }
}
