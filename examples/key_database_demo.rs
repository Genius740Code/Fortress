//! Demonstration of the new key database and preloading system
//!
//! This example shows how to use the DatabaseKeyManager with
//! persistent storage, intelligent preloading, and high-performance caching.

use fortress_core::prelude::*;
use tokio;
use fortress_core::encryption::PerformanceProfile;
use chrono::{Utc, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Fortress Key Database & Preloading Demo");
    println!("==========================================");

    // Create configuration for the database key manager
    let config = DatabaseKeyManagerConfig {
        database: KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: "sqlite::memory:".to_string(), // In-memory database for demo
            max_connections: 10,
            connection_timeout_seconds: 30,
            encrypt_at_rest: true,
            master_key: Some("demo_master_key_12345".to_string()),
        },
        preloader: KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: false,
            preload_frequently_used: true,
            preload_by_purpose: true,
            max_keys_to_preload: 100,
            max_memory_usage_bytes: 50 * 1024 * 1024, // 50MB
            preload_expiring_soon: Duration::hours(24),
            priority_purposes: vec![
                "encryption".to_string(),
                "authentication".to_string(),
                "session".to_string(),
            ],
            priority_performance_profiles: vec![
                "lightning".to_string(),
                "balanced".to_string(),
            ],
            enable_background_preload: true,
            background_preload_interval: Duration::minutes(30),
            track_preload_stats: true,
        },
        cache: KeyCacheConfig {
            max_keys: 1000,
            max_memory_bytes: 100 * 1024 * 1024, // 100MB
            enable_lru_eviction: true,
            enable_time_eviction: true,
            eviction_time_seconds: 3600, // 1 hour
            track_access_frequency: true,
            enable_stats: true,
            enable_cache_warming: false,
            background_cleanup_interval_seconds: 300, // 5 minutes
            hit_ratio_threshold: 0.8,
        },
        enable_auto_rotation: false, // Disable for demo
        rotation_interval_hours: 24,
        enable_rotation_backup: true,
        enable_performance_monitoring: true,
    };

    println!("Configuration created");
    println!("   - Database: SQLite with encryption at rest");
    println!("   - Preloading: Enabled with intelligent strategies");
    println!("   - Cache: 1000 keys, 100MB memory limit");
    println!("   - Monitoring: Performance tracking enabled");

    // Create the database key manager
    println!("\nInitializing Database Key Manager...");
    let key_manager = DatabaseKeyManager::new(config).await?;
    println!("✓ Key manager initialized successfully");

    // Demonstrate key generation and storage
    println!("\nGenerating and storing keys...");
    let algorithm = Aegis256::new();
    
    for i in 1..=10 {
        let key_id = format!("demo_key_{}", i);
        let key = key_manager.generate_key(&algorithm).await?;
        
        let metadata = KeyMetadata::new(
            key_id.clone(),
            "aegis256".to_string(),
            1,
            Utc::now(),
            Utc::now() + chrono::Duration::days(90),
            if i <= 3 { "encryption".to_string() } else { "general".to_string() },
            PerformanceProfile::Balanced,
        );
        
        key_manager.store_key(&key_id, &key, &metadata).await?;
        println!("   ✓ Stored key: {}", key_id);
    }

    // Demonstrate key retrieval with caching
    println!("\nTesting key retrieval with caching...");
    let start_time = std::time::Instant::now();
    
    // First access (should hit database)
    let _ = key_manager.retrieve_key(&"demo_key_1".to_string()).await?;
    let first_access_time = start_time.elapsed();
    println!("   First access (database): {:?}", first_access_time);
    
    // Second access (should hit cache)
    let start_time = std::time::Instant::now();
    let _ = key_manager.retrieve_key(&"demo_key_1".to_string()).await?;
    let second_access_time = start_time.elapsed();
    println!("   Second access (cache): {:?}", second_access_time);
    
    let speedup = first_access_time.as_nanos() as f64 / second_access_time.as_nanos() as f64;
    println!("   Cache speedup: {:.2}x faster", speedup);

    // Demonstrate preloading
    println!("\nTesting key preloading...");
    let preload_result = key_manager.force_preload_key(&"demo_key_5".to_string()).await?;
    println!("   ✓ Force preloaded demo_key_5: {}", preload_result);
    
    // Access preloaded key
    let start_time = std::time::Instant::now();
    let _ = key_manager.retrieve_key(&"demo_key_5".to_string()).await?;
    let preload_access_time = start_time.elapsed();
    println!("   Preloaded key access: {:?}", preload_access_time);

    // Get comprehensive statistics
    println!("\nPerformance Statistics:");
    let stats = key_manager.get_detailed_stats().await?;
    
    println!("   Database:");
    println!("     - Total keys: {}", stats.database.total_keys);
    println!("     - Database size: {} bytes", stats.database.database_size_bytes);
    println!("     - Active connections: {}", stats.database.active_connections);
    
    println!("   Cache:");
    println!("     - Cache hits: {}", stats.cache.hits);
    println!("     - Cache misses: {}", stats.cache.misses);
    println!("     - Hit ratio: {:.2}%", stats.cache.hit_ratio * 100.0);
    println!("     - Current keys: {}", stats.cache.current_keys);
    println!("     - Memory usage: {} bytes", stats.cache.current_memory_bytes);
    
    println!("   Preloader:");
    println!("     - Preloaded keys: {}", stats.preloader.total_preloaded_keys);
    println!("     - Memory usage: {} bytes", stats.preloader.total_memory_usage_bytes);
    println!("     - Success rate: {:.2}%", stats.preloader.preload_success_rate * 100.0);
    
    println!("   Overall:");
    println!("     - Total operations: {}", stats.metrics.total_operations);
    println!("     - Success rate: {:.2}%", 
        (stats.metrics.successful_operations as f64 / stats.metrics.total_operations as f64) * 100.0);
    println!("     - Avg operation time: {:.2} ms", stats.metrics.avg_operation_time_ms);
    println!("     - Managed keys: {}", stats.metrics.managed_keys);
    println!("     - Memory usage: {} bytes", stats.metrics.memory_usage_bytes);

    // Get performance recommendations
    println!("\nPerformance Recommendations:");
    let recommendations = key_manager.get_performance_recommendations().await;
    if recommendations.is_empty() {
        println!("   ✓ No recommendations - system is performing optimally!");
    } else {
        for (i, rec) in recommendations.iter().enumerate() {
            println!("   {}. {}", i + 1, rec);
        }
    }

    // Demonstrate cache eviction
    println!("\nTesting cache eviction...");
    let evicted = key_manager.evict_from_cache(&"demo_key_2".to_string()).await?;
    println!("   ✓ Evicted demo_key_2 from cache: {}", evicted);
    
    // Verify eviction
    let cache_stats = key_manager.get_metrics().await;
    println!("   Cache hit ratio after eviction: {:.2}%", cache_stats.cache_hit_ratio * 100.0);

    // List all keys
    println!("\nAll stored keys:");
    let all_keys = key_manager.list_keys().await?;
    for (key_id, metadata) in all_keys {
        println!("   - {} ({}): v{}, purpose: {}", 
            key_id, 
            metadata.algorithm, 
            metadata.version, 
            metadata.purpose
        );
    }

    // Cleanup
    println!("\nCleaning up...");
    key_manager.clear_caches().await?;
    key_manager.shutdown().await?;
    println!("   Shutdown completed");

    println!("\nFortress Key Database Demo completed successfully!");
    println!("Key features demonstrated:");
    println!("   Persistent key storage with SQLite");
    println!("   Intelligent key preloading");
    println!("   High-performance LRU caching");
    println!("   Performance monitoring and recommendations");
    println!("   Cache eviction and management");
    println!("   Comprehensive statistics");

    Ok(())
}
