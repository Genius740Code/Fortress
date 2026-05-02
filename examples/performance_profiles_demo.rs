//! Performance Profiles Demo
//!
//! This example demonstrates how to use Fortress performance profiles
//! to optimize the system for different use cases.

use fortress_core::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Fortress Performance Profiles Demo\n");

    // Initialize profile manager
    let mut profile_manager = ProfileManager::new();
    
    println!("Available Profiles:");
    for profile_name in profile_manager.list_profiles() {
        let profile = profile_manager.get_profile(profile_name).unwrap();
        println!("  • {} ({})", profile.name, profile.profile_type);
    }
    println!();

    // Demonstrate preset profiles
    demo_preset_profiles(&profile_manager)?;

    // Create and demonstrate custom profiles
    demo_custom_profiles(&mut profile_manager)?;

    // Demonstrate auto-optimization
    demo_auto_optimization(&mut profile_manager)?;

    // Demonstrate profile management
    demo_profile_management(&mut profile_manager)?;

    println!("✅ Performance profiles demo completed successfully!");
    Ok(())
}

fn demo_preset_profiles(manager: &ProfileManager) -> Result<()> {
    println!("Preset Profile Demonstrations:\n");
    println!("=================================");

    // Lightning Profile
    let lightning = manager.get_profile("lightning").unwrap();
    println!("Lightning Profile:");
    println!("{}", lightning.summary());
    println!("  Description: {}", lightning.description.as_ref().unwrap_or(&"No description".to_string()));
    println!("  Tags: {}", lightning.tags.join(", "));
    println!();

    // Balanced Profile
    let balanced = manager.get_profile("balanced").unwrap();
    println!("Balanced Profile:");
    println!("{}", balanced.summary());
    println!("  Description: {}", balanced.description.as_ref().unwrap_or(&"No description".to_string()));
    println!("  Tags: {}", balanced.tags.join(", "));
    println!();

    // Fortress Profile
    let fortress = manager.get_profile("fortress").unwrap();
    println!("Fortress Profile:");
    println!("{}", fortress.summary());
    println!("  Description: {}", fortress.description.as_ref().unwrap_or(&"No description".to_string()));
    println!("  Tags: {}", fortress.tags.join(", "));
    println!();

    Ok(())
}

fn demo_custom_profiles(manager: &mut ProfileManager) -> Result<()> {
    println!("Custom Profile Creation (Game-like Settings):");
    println!("=================================================");

    // Gaming Profile - High Performance
    let mut gaming_profile = PerformanceProfileConfig::new("gaming".to_string());
    gaming_profile.description = Some("Optimized for gaming applications with high performance requirements".to_string());
    gaming_profile.tags = vec!["gaming".to_string(), "high-performance".to_string(), "low-latency".to_string()];
    
    // Configure for gaming - similar to Lightning but with gaming-specific tweaks
    gaming_profile.resources = ResourceLimits {
        max_memory_mb: 2048,      // Allow more memory for gaming
        max_cpu_percent: 90,      // Use more CPU
        max_concurrent_ops: 200,  // Higher concurrency
        thread_pool_size: 6,      // More threads
        cache_size_mb: 512,       // Larger cache
    };
    
    gaming_profile.encryption = EncryptionSettings {
        algorithm: "chacha20poly1305".to_string(), // Fast encryption
        kdf: "argon2id".to_string(),
        kdf_memory_cost: 32768,  // Balanced memory usage
        kdf_iterations: 2,       // Lower iterations for speed
        kdf_parallelism: 4,
        hardware_acceleration: true,
        simd_optimizations: true,
        batch_size: 4096,        // Large batches for gaming
    };
    
    gaming_profile.storage = StorageSettings {
        compression: "lz4".to_string(), // Fast compression
        compression_level: 2,   // Light compression for speed
        enable_wal: false,      // Disable WAL for speed
        sync_mode: SyncMode::Off,
        page_size: 16384,       // Large pages
        cache_pages: 2048,
        async_writes: true,
        batch_write_size: 500,  // Large batches
    };
    
    gaming_profile.network = NetworkSettings {
        connection_timeout_secs: 5,   // Fast timeout
        request_timeout_secs: 15,
        max_connections: 200,
        connection_pool_size: 20,
        keep_alive: true,
        compression: false,           // No compression for latency
        buffer_size: 32768,          // Large buffers
    };

    println!("Adding Gaming Profile...");
    manager.add_profile(gaming_profile.clone())?;
    println!("✓ Gaming profile added successfully");
    println!("{}", gaming_profile.summary());
    println!();

    // Streaming Profile - Balanced for media
    let mut streaming_profile = PerformanceProfileConfig::new("streaming".to_string());
    streaming_profile.description = Some("Optimized for media streaming applications".to_string());
    streaming_profile.tags = vec!["streaming".to_string(), "media".to_string(), "bandwidth".to_string()];
    
    streaming_profile.resources = ResourceLimits {
        max_memory_mb: 1536,
        max_cpu_percent: 75,
        max_concurrent_ops: 150,
        thread_pool_size: 4,
        cache_size_mb: 384,
    };
    
    streaming_profile.network = NetworkSettings {
        connection_timeout_secs: 15,
        request_timeout_secs: 45,
        max_connections: 300,      // More connections for streaming
        connection_pool_size: 30,
        keep_alive: true,
        compression: true,         // Enable compression for bandwidth
        buffer_size: 65536,        // Very large buffers for media
    };

    println!("Adding Streaming Profile...");
    manager.add_profile(streaming_profile)?;
    println!("✓ Streaming profile added successfully");
    println!();

    // Development Profile - Resource Conscious
    let mut dev_profile = PerformanceProfileConfig::new("development".to_string());
    dev_profile.description = Some("Optimized for development environments".to_string());
    dev_profile.tags = vec!["development".to_string(), "debugging".to_string(), "testing".to_string()];
    
    dev_profile.resources = ResourceLimits {
        max_memory_mb: 512,        // Conservative memory usage
        max_cpu_percent: 50,       // Don't overwhelm development machine
        max_concurrent_ops: 50,
        thread_pool_size: 2,
        cache_size_mb: 128,
    };
    
    dev_profile.storage = StorageSettings {
        compression: "none".to_string(), // No compression for debugging
        compression_level: 0,
        enable_wal: true,
        sync_mode: SyncMode::Normal,
        page_size: 4096,
        cache_pages: 256,
        async_writes: false,       // Synchronous for debugging
        batch_write_size: 10,      // Small batches
    };

    println!("Adding Development Profile...");
    manager.add_profile(dev_profile)?;
    println!("✓ Development profile added successfully");
    println!();

    Ok(())
}

fn demo_auto_optimization(manager: &mut ProfileManager) -> Result<()> {
    println!("Auto-Optimization Demo:");
    println!("=========================");

    // Simulate different system configurations
    let system_configs = vec![
        ("High-End Gaming PC", SystemInfo {
            total_memory_gb: 32,
            available_memory_gb: 24,
            cpu_cores: 16,
            cpu_arch: "x86_64".to_string(),
            available_disk_gb: 2000,
            network_bandwidth_mbps: Some(10000),
        }),
        ("Mid-Range Laptop", SystemInfo {
            total_memory_gb: 16,
            available_memory_gb: 8,
            cpu_cores: 8,
            cpu_arch: "x86_64".to_string(),
            available_disk_gb: 500,
            network_bandwidth_mbps: Some(1000),
        }),
        ("Low-End Device", SystemInfo {
            total_memory_gb: 4,
            available_memory_gb: 2,
            cpu_cores: 2,
            cpu_arch: "x86_64".to_string(),
            available_disk_gb: 128,
            network_bandwidth_mbps: Some(100),
        }),
        ("ARM Server", SystemInfo {
            total_memory_gb: 64,
            available_memory_gb: 48,
            cpu_cores: 32,
            cpu_arch: "aarch64".to_string(),
            available_disk_gb: 4000,
            network_bandwidth_mbps: Some(40000),
        }),
    ];

    for (name, system_info) in system_configs {
        println!("{}", name);
        println!("   Memory: {}GB, CPU: {} cores, Arch: {}", 
                 system_info.total_memory_gb, 
                 system_info.cpu_cores, 
                 system_info.cpu_arch);
        
        let capabilities = system_info.capabilities();
        println!("   Capabilities: HW Accel: {}, SIMD: {}, High Mem: {}, Multi-core: {}",  
                 capabilities.supports_hardware_acceleration,
                 capabilities.supports_simd,
                 capabilities.high_memory,
                 capabilities.multi_core);
        
        let recommended_profile = manager.auto_optimize(&system_info)?;
        let profile = manager.get_profile(&recommended_profile).unwrap();
        println!("   Recommended Profile: {} ({})", recommended_profile, profile.profile_type);
        println!("   Reason: {}", profile.description.as_ref().unwrap_or(&"No description".to_string()));
        println!();
    }

    Ok(())
}

fn demo_profile_management(manager: &mut ProfileManager) -> Result<()> {
    println!("Profile Management Demo:");
    println!("===========================");

    // List all profiles
    println!("All Available Profiles:");
    for profile_name in manager.list_profiles() {
        let profile = manager.get_profile(profile_name).unwrap();
        println!("  • {} - {} ({})", 
                 profile.name, 
                 profile.profile_type,
                 profile.tags.join(", "));
    }
    println!();

    // Find profiles by tags
    println!("🏷️  Profiles by Tag:");
    let tags_to_search = vec!["gaming", "security", "performance"];
    
    for tag in tags_to_search {
        let profiles = manager.find_profiles_by_tag(tag);
        if !profiles.is_empty() {
            println!("  Tag '{}':", tag);
            for profile in profiles {
                println!("    - {}", profile.name);
            }
        }
    }
    println!();

    // Change default profile
    println!("🔄 Default Profile Management:");
    println!("Current default: {}", manager.get_default_profile().unwrap().name);
    
    manager.set_default_profile("gaming")?;
    println!("New default: {}", manager.get_default_profile().unwrap().name);
    
    manager.set_default_profile("balanced")?;
    println!("Reset to: {}", manager.get_default_profile().unwrap().name);
    println!();

    // Profile validation demo
    println!("Profile Validation:");
    let mut invalid_profile = PerformanceProfileConfig::new("invalid".to_string());
    invalid_profile.resources.max_cpu_percent = 150; // Invalid
    
    match invalid_profile.validate() {
        Ok(_) => println!("  Profile is valid"),
        Err(e) => println!("  Profile validation failed: {}", e),
    }
    
    // Try to add invalid profile
    match manager.add_profile(invalid_profile) {
        Ok(_) => println!("  Invalid profile added (unexpected)"),
        Err(e) => println!("  Expected error adding invalid profile: {}", e),
    }
    println!();

    // Remove a custom profile
    println!("Profile Removal:");
    println!("Removing 'gaming' profile...");
    manager.remove_profile("gaming")?;
    println!("✓ Profile removed successfully");
    
    let remaining_profiles = manager.list_profiles();
    println!("Remaining profiles: {}", remaining_profiles.len());
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation() {
        let profile = PerformanceProfileConfig::lightning("test".to_string());
        assert_eq!(profile.profile_type, PerformanceProfile::Lightning);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_profile_manager() {
        let mut manager = ProfileManager::new();
        assert!(manager.get_profile("balanced").is_some());
        
        let custom = PerformanceProfileConfig::new("custom".to_string());
        manager.add_profile(custom).unwrap();
        assert!(manager.get_profile("custom").is_some());
    }

    #[test]
    fn test_system_capabilities() {
        let system_info = SystemInfo {
            total_memory_gb: 16,
            available_memory_gb: 8,
            cpu_cores: 8,
            cpu_arch: "x86_64".to_string(),
            available_disk_gb: 500,
            network_bandwidth_mbps: Some(1000),
        };
        
        let capabilities = system_info.capabilities();
        assert!(capabilities.supports_hardware_acceleration);
        assert!(capabilities.supports_simd);
        assert!(!capabilities.high_memory);
        assert!(capabilities.multi_core);
    }
}
