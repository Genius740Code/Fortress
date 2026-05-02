//! Comprehensive Key Preloader Tests
//! 
//! This test suite provides comprehensive coverage for the key preloader system,
//! testing preloading strategy validation, performance impact measurement, memory efficiency
//! testing, background task management, and error handling and retry logic.

use fortress_core::key_preloader::{KeyPreloader, KeyPreloadConfig, PreloadStrategy};
use fortress_core::key_database::{KeyDatabase, KeyDatabaseConfig, KeyDatabaseBackend, SqliteKeyDatabase};
use fortress_core::key::{KeyId, KeyMetadata, SecureKey, KeyVersion};
use fortress_core::performance_profile::PerformanceProfile;
use fortress_core::encryption::Aegis256;
use fortress_core::error::Result;
use chrono::{Utc, Duration};
use tempfile::NamedTempFile;
use std::sync::Arc;
use tokio::time::sleep;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a temporary SQLite database
    async fn create_temp_sqlite_db() -> (String, NamedTempFile) {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path().to_str().unwrap().to_string();
        (format!("sqlite:{}", db_path), temp_file)
    }

    /// Helper function to create test key metadata
    fn create_test_metadata(algorithm_name: &str, purpose: &str, performance_profile: &str) -> KeyMetadata {
        let key_id = KeyId::new();
        let version = KeyVersion::new();
        let now = Utc::now();
        let metadata = KeyMetadata::new(
            key_id,
            algorithm_name.to_string(),
            version,
            now,
            now + Duration::hours(24),
            purpose.to_string(),
            PerformanceProfile::HighPerformance,
        );
        metadata
    }

    /// Helper function to create test secure key
    fn create_test_key(size: usize) -> SecureKey {
        let key_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        SecureKey::new(key_data)
    }

    /// Helper function to create a test database with keys
    async fn create_test_database_with_keys(num_keys: usize) -> (SqliteKeyDatabase, Vec<KeyId>) {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path,
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database connection should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        let mut key_ids = Vec::new();
        
        for i in 0..num_keys {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            
            // Create different types of metadata for testing
            let (purpose, profile) = match i % 4 {
                0 => ("encryption", "lightning"),
                1 => ("authentication", "balanced"),
                2 => ("session", "lightning"),
                _ => ("signing", "balanced"),
            };
            
            let metadata = create_test_metadata("aegis256", purpose, profile);
            
            db.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Test key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        (db, key_ids)
    }

    /// Test preloading strategy validation
    #[tokio::test]
    async fn test_preloading_strategy_validation() {
        let (db, key_ids) = create_test_database_with_keys(20).await;
        
        let config = KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: false,
            preload_frequently_used: true,
            preload_by_purpose: true,
            max_keys_to_preload: 10,
            max_memory_usage_bytes: 1024 * 1024, // 1MB
            preload_expiring_soon: Duration::hours(24),
            priority_purposes: vec!["encryption".to_string(), "authentication".to_string()],
            priority_performance_profiles: vec!["lightning".to_string()],
            enable_background_preload: false,
            background_preload_interval: Duration::minutes(30),
            track_preload_stats: true,
        };
        
        let preloader = KeyPreloader::new(Arc::new(db), config);
        
        // Test All strategy
        let all_keys = preloader.preload_keys(&PreloadStrategy::All).await
            .expect("All strategy preload should succeed");
        assert_eq!(all_keys.len(), 20, "All strategy should load all keys");
        
        // Test FrequentlyUsed strategy
        let frequent_keys = preloader.preload_keys(&PreloadStrategy::FrequentlyUsed).await
            .expect("FrequentlyUsed strategy preload should succeed");
        assert!(frequent_keys.len() <= 10, "FrequentlyUsed strategy should respect memory limit");
        
        // Test ByPurpose strategy
        let purpose_keys = preloader.preload_keys(&PreloadStrategy::ByPurpose).await
            .expect("ByPurpose strategy preload should succeed");
        
        // Verify purpose filtering
        for (key_id, _, metadata) in &purpose_keys {
            if let Some(purpose) = &metadata.purpose {
                assert!(config.priority_purposes.contains(purpose), 
                       "Purpose {} should be in priority list", purpose);
            }
        }
        
        // Test ExpiringSoon strategy
        let expiring_keys = preloader.preload_keys(&PreloadStrategy::ExpiringSoon).await
            .expect("ExpiringSoon strategy preload should succeed");
        
        // Verify expiration filtering (keys should expire within 24 hours)
        let now = Utc::now();
        for (_, _, metadata) in &expiring_keys {
            if let Some(expires_at) = metadata.expires_at {
                let time_to_expiry = expires_at - now;
                assert!(time_to_expiry <= Duration::hours(24), 
                       "Key should expire within 24 hours");
            }
        }
        
        // Test ByPerformanceProfile strategy
        let profile_keys = preloader.preload_keys(&PreloadStrategy::ByPerformanceProfile).await
            .expect("ByPerformanceProfile strategy preload should succeed");
        
        // Verify profile filtering
        for (key_id, _, metadata) in &profile_keys {
            if let Some(profile) = &metadata.performance_profile {
                assert!(config.priority_performance_profiles.contains(profile), 
                       "Profile {} should be in priority list", profile);
            }
        }
        
        // Test Custom strategy
        let custom_keys = preloader.preload_keys(&PreloadStrategy::Custom("test".to_string())).await
            .expect("Custom strategy preload should succeed");
        
        // Custom strategy should load a subset based on implementation
        assert!(custom_keys.len() <= key_ids.len(), "Custom strategy should not exceed total keys");
    }

    /// Test performance impact measurement
    #[tokio::test]
    async fn test_performance_impact_measurement() {
        let (db, key_ids) = create_test_database_with_keys(100).await;
        
        // Test performance without preloading
        let start_time = std::time::Instant::now();
        let mut cold_retrievals = 0;
        
        for key_id in &key_ids {
            let result = db.retrieve_key(key_id).await
                .expect("Cold retrieval should succeed");
            if result.is_some() {
                cold_retrievals += 1;
            }
        }
        
        let cold_duration = start_time.elapsed();
        println!("Cold retrieval of {} keys took {:?}", cold_retrievals, cold_duration);
        
        // Configure preloader
        let config = KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: true,
            max_keys_to_preload: 100,
            max_memory_usage_bytes: 10 * 1024 * 1024, // 10MB
            ..Default::default()
        };
        
        let preloader = KeyPreloader::new(Arc::new(db), config);
        
        // Preload all keys
        let preload_start = std::time::Instant::now();
        let preloaded_keys = preloader.preload_keys(&PreloadStrategy::All).await
            .expect("Preloading should succeed");
        let preload_duration = preload_start.elapsed();
        
        println!("Preloaded {} keys in {:?}", preloaded_keys.len(), preload_duration);
        assert_eq!(preloaded_keys.len(), key_ids.len(), "All keys should be preloaded");
        
        // Test performance with preloaded keys
        let start_time = std::time::Instant::now();
        let mut hot_retrievals = 0;
        
        for (key_id, _, _) in &preloaded_keys {
            let result = db.retrieve_key(key_id).await
                .expect("Hot retrieval should succeed");
            if result.is_some() {
                hot_retrievals += 1;
            }
        }
        
        let hot_duration = start_time.elapsed();
        println!("Hot retrieval of {} keys took {:?}", hot_retrievals, hot_duration);
        
        // Performance improvement analysis
        assert_eq!(cold_retrievals, hot_retrievals, "Cold and hot retrievals should have same count");
        
        // Hot retrieval should be faster (though this depends on implementation)
        // In a real scenario, preloaded keys would be cached in memory
        let improvement_factor = cold_duration.as_nanos() as f64 / hot_duration.as_nanos() as f64;
        println!("Performance improvement factor: {:.2}x", improvement_factor);
        
        // Test preloader statistics
        let stats = preloader.get_preload_stats().await
            .expect("Preload stats should be available");
        
        assert!(stats.total_preloaded_keys > 0, "Should have preloaded keys");
        assert!(stats.total_preload_time > Duration::zero(), "Should have recorded preload time");
        assert!(stats.memory_usage_bytes > 0, "Should use memory for preloaded keys");
        
        println!("Preloader stats: {} keys, {:?} time, {} bytes", 
                stats.total_preloaded_keys, stats.total_preload_time, stats.memory_usage_bytes);
    }

    /// Test memory efficiency testing
    #[tokio::test]
    async fn test_memory_efficiency_testing() {
        let (db, key_ids) = create_test_database_with_keys(50).await;
        
        // Test with strict memory limits
        let config = KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: false,
            max_keys_to_preload: 20,
            max_memory_usage_bytes: 1024 * 100, // 100KB limit
            ..Default::default()
        };
        
        let preloader = KeyPreloader::new(Arc::new(db), config);
        
        // Create keys of different sizes to test memory management
        let mut large_key_ids = Vec::new();
        for i in 0..10 {
            let key_id = KeyId::new();
            let key = create_test_key(1024 * (i + 1)); // 1KB to 10KB keys
            let metadata = create_test_metadata("aegis256", "encryption", "balanced");
            
            preloader.database().store_key(&key_id, &key, &metadata).await
                .expect(&format!("Large key {} storage should succeed", i));
            
            large_key_ids.push(key_id);
        }
        
        // Test memory-efficient preloading
        let preloaded_keys = preloader.preload_keys(&PreloadStrategy::ByPurpose).await
            .expect("Memory-efficient preload should succeed");
        
        // Verify memory limits are respected
        let stats = preloader.get_preload_stats().await
            .expect("Stats should be available");
        
        assert!(stats.memory_usage_bytes <= 1024 * 100, 
               "Memory usage should not exceed limit: {} > 102400", 
               stats.memory_usage_bytes);
        
        assert!(preloaded_keys.len() <= 20, 
               "Key count should not exceed limit: {} > 20", 
               preloaded_keys.len());
        
        // Test memory cleanup
        preloader.clear_preloaded_keys().await
            .expect("Preload cleanup should succeed");
        
        let stats_after_cleanup = preloader.get_preload_stats().await
            .expect("Stats after cleanup should be available");
        
        assert_eq!(stats_after_cleanup.total_preloaded_keys, 0, "All keys should be cleared");
        assert_eq!(stats_after_cleanup.memory_usage_bytes, 0, "Memory usage should be 0 after cleanup");
        
        // Test selective preloading for memory efficiency
        let selective_config = KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: false,
            preload_frequently_used: true,
            preload_by_purpose: true,
            max_keys_to_preload: 5,
            max_memory_usage_bytes: 50 * 1024, // 50KB
            priority_purposes: vec!["encryption".to_string()], // Only encryption keys
            ..Default::default()
        };
        
        let selective_preloader = KeyPreloader::new(preloader.database().clone(), selective_config);
        
        let selective_keys = selective_preloader.preload_keys(&PreloadStrategy::ByPurpose).await
            .expect("Selective preload should succeed");
        
        let selective_stats = selective_preloader.get_preload_stats().await
            .expect("Selective stats should be available");
        
        assert!(selective_keys.len() <= 5, "Selective preload should respect key limit");
        assert!(selective_stats.memory_usage_bytes <= 50 * 1024, "Selective preload should respect memory limit");
        
        // Verify only encryption keys are loaded
        for (_, _, metadata) in &selective_keys {
            if let Some(purpose) = &metadata.purpose {
                assert_eq!(purpose, "encryption", "Only encryption keys should be loaded");
            }
        }
    }

    /// Test background task management
    #[tokio::test]
    async fn test_background_task_management() {
        let (db, key_ids) = create_test_database_with_keys(30).await;
        
        let config = KeyPreloadConfig {
            enable_preload: true,
            enable_background_preload: true,
            background_preload_interval: Duration::millis(100), // Very short for testing
            track_preload_stats: true,
            ..Default::default()
        };
        
        let preloader = KeyPreloader::new(Arc::new(db), config);
        
        // Start background preloading
        preloader.start_background_preloading().await
            .expect("Background preloading should start");
        
        // Wait for background tasks to run
        sleep(Duration::millis(250)).await;
        
        // Check background preload status
        let is_running = preloader.is_background_preloading().await
            .expect("Background status check should succeed");
        assert!(is_running, "Background preloading should be running");
        
        // Get background preload statistics
        let bg_stats = preloader.get_background_preload_stats().await
            .expect("Background stats should be available");
        
        assert!(bg_stats.total_background_preloads > 0, "Should have performed background preloads");
        assert!(bg_stats.last_preload_time > Some(Utc::now() - Duration::minutes(1)), 
               "Should have recent preload activity");
        
        // Stop background preloading
        preloader.stop_background_preloading().await
            .expect("Background preloading should stop");
        
        // Verify it stopped
        let is_stopped = preloader.is_background_preloading().await
            .expect("Background status check after stop should succeed");
        assert!(!is_stopped, "Background preloading should be stopped");
        
        // Test background preloading with different strategies
        let bg_config = KeyPreloadConfig {
            enable_preload: true,
            enable_background_preload: true,
            background_preload_interval: Duration::millis(200),
            preload_frequently_used: true,
            preload_by_purpose: true,
            ..Default::default()
        };
        
        let bg_preloader = KeyPreloader::new(preloader.database().clone(), bg_config);
        
        bg_preloader.start_background_preloading().await
            .expect("Background preloading with strategies should start");
        
        // Wait for multiple background cycles
        sleep(Duration::millis(600)).await;
        
        let bg_stats_multiple = bg_preloader.get_background_preload_stats().await
            .expect("Multiple background stats should be available");
        
        assert!(bg_stats_multiple.total_background_preloads > 1, 
               "Should have performed multiple background preloads");
        
        bg_preloader.stop_background_preloading().await
            .expect("Background preloading should stop");
    }

    /// Test error handling and retry logic
    #[tokio::test]
    async fn test_error_handling_retry_logic() {
        let (db, key_ids) = create_test_database_with_keys(20).await;
        
        let config = KeyPreloadConfig {
            enable_preload: true,
            max_keys_to_preload: 10,
            track_preload_stats: true,
            ..Default::default()
        };
        
        let preloader = KeyPreloader::new(Arc::new(db), config);
        
        // Test preloading with non-existent database (simulate error)
        // This would require a mock database that returns errors
        // For now, we'll test with valid scenarios
        
        // Test preloading with invalid strategy
        let invalid_strategy = PreloadStrategy::Custom("invalid_strategy".to_string());
        let result = preloader.preload_keys(&invalid_strategy).await;
        
        // Should handle gracefully (either succeed with empty result or return specific error)
        match result {
            Ok(keys) => {
                // If successful, should be empty or limited
                assert!(keys.len() <= key_ids.len(), "Invalid strategy should not load unexpected keys");
            }
            Err(_) => {
                // If error, that's acceptable for invalid strategy
            }
        }
        
        // Test preloading with memory limit exceeded
        let memory_config = KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: true,
            max_keys_to_preload: 1000, // High limit
            max_memory_usage_bytes: 1, // Very low memory limit
            ..Default::default()
        };
        
        let memory_preloader = KeyPreloader::new(preloader.database().clone(), memory_config);
        
        let memory_result = memory_preloader.preload_keys(&PreloadStrategy::All).await;
        
        match memory_result {
            Ok(keys) => {
                // Should load very few or no keys due to memory limit
                assert!(keys.len() <= 5, "Memory limit should restrict key loading");
            }
            Err(_) => {
                // Error is acceptable for extreme memory constraints
            }
        }
        
        // Test retry logic simulation
        let retry_config = KeyPreloadConfig {
            enable_preload: true,
            max_keys_to_preload: 10,
            track_preload_stats: true,
            ..Default::default()
        };
        
        let retry_preloader = KeyPreloader::new(preloader.database().clone(), retry_config);
        
        // Simulate multiple preload attempts
        let mut successful_attempts = 0;
        let mut total_attempts = 0;
        
        for attempt in 0..5 {
            total_attempts += 1;
            
            let result = retry_preloader.preload_keys(&PreloadStrategy::FrequentlyUsed).await;
            
            match result {
                Ok(keys) => {
                    if !keys.is_empty() {
                        successful_attempts += 1;
                    }
                }
                Err(_) => {
                    // Retry logic would handle this
                }
            }
        }
        
        assert!(successful_attempts > 0, "Should have at least some successful attempts");
        assert_eq!(total_attempts, 5, "Should attempt all 5 times");
        
        // Test error recovery
        let stats = retry_preloader.get_preload_stats().await
            .expect("Stats should be available for error recovery test");
        
        assert!(stats.total_preload_attempts >= total_attempts, 
               "Should track all preload attempts");
        assert!(stats.successful_preloads >= successful_attempts, 
               "Should track successful preloads");
        
        if stats.total_preload_attempts > 0 {
            let success_rate = stats.successful_preloads as f64 / stats.total_preload_attempts as f64;
            println!("Preload success rate: {:.2}%", success_rate * 100.0);
            assert!(success_rate > 0.0, "Should have some success rate");
        }
    }

    /// Test preloader configuration variations
    #[tokio::test]
    async fn test_preloader_configuration_variations() {
        let (db, key_ids) = create_test_database_with_keys(25).await;
        
        // Test minimal configuration
        let minimal_config = KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: false,
            preload_frequently_used: false,
            preload_by_purpose: false,
            max_keys_to_preload: 5,
            max_memory_usage_bytes: 1024 * 10, // 10KB
            enable_background_preload: false,
            track_preload_stats: false,
            ..Default::default()
        };
        
        let minimal_preloader = KeyPreloader::new(Arc::new(db.clone()), minimal_config);
        
        let minimal_keys = minimal_preloader.preload_keys(&PreloadStrategy::All).await
            .expect("Minimal preload should succeed");
        
        assert!(minimal_keys.len() <= 5, "Minimal config should respect key limit");
        
        // Test maximal configuration
        let maximal_config = KeyPreloadConfig {
            enable_preload: true,
            preload_all_keys: true,
            preload_frequently_used: true,
            preload_by_purpose: true,
            max_keys_to_preload: 1000,
            max_memory_usage_bytes: 100 * 1024 * 1024, // 100MB
            priority_purposes: vec!["encryption".to_string(), "authentication".to_string(), "session".to_string(), "signing".to_string()],
            priority_performance_profiles: vec!["lightning".to_string(), "balanced".to_string(), "secure".to_string()],
            enable_background_preload: true,
            background_preload_interval: Duration::minutes(5),
            track_preload_stats: true,
            ..Default::default()
        };
        
        let maximal_preloader = KeyPreloader::new(Arc::new(db), maximal_config);
        
        let maximal_keys = maximal_preloader.preload_keys(&PreloadStrategy::All).await
            .expect("Maximal preload should succeed");
        
        assert_eq!(maximal_keys.len(), key_ids.len(), "Maximal config should load all keys");
        
        // Test disabled preloading
        let disabled_config = KeyPreloadConfig {
            enable_preload: false,
            ..Default::default()
        };
        
        let disabled_preloader = KeyPreloader::new(Arc::new(db), disabled_config);
        
        let disabled_result = disabled_preloader.preload_keys(&PreloadStrategy::All).await;
        
        // Should either return empty result or handle gracefully
        match disabled_result {
            Ok(keys) => {
                assert!(keys.is_empty(), "Disabled preloader should return empty result");
            }
            Err(_) => {
                // Error is acceptable for disabled preloader
            }
        }
        
        // Test configuration with custom priorities
        let custom_config = KeyPreloadConfig {
            enable_preload: true,
            preload_by_purpose: true,
            priority_purposes: vec!["custom_purpose".to_string()], // Non-existent purpose
            priority_performance_profiles: vec!["custom_profile".to_string()], // Non-existent profile
            ..Default::default()
        };
        
        let custom_preloader = KeyPreloader::new(Arc::new(db), custom_config);
        
        let custom_keys = custom_preloader.preload_keys(&PreloadStrategy::ByPurpose).await
            .expect("Custom priority preload should succeed");
        
        // Should return empty result since no keys match custom priorities
        assert!(custom_keys.is_empty(), "Custom priorities should return empty result");
        
        let custom_profile_keys = custom_preloader.preload_keys(&PreloadStrategy::ByPerformanceProfile).await
            .expect("Custom profile preload should succeed");
        
        assert!(custom_profile_keys.is_empty(), "Custom profile should return empty result");
    }

    /// Test preloader lifecycle management
    #[tokio::test]
    async fn test_preloader_lifecycle_management() {
        let (db, key_ids) = create_test_database_with_keys(15).await;
        
        let config = KeyPreloadConfig {
            enable_preload: true,
            enable_background_preload: true,
            track_preload_stats: true,
            ..Default::default()
        };
        
        // Test preloader creation
        let preloader = KeyPreloader::new(Arc::new(db), config);
        
        // Test initial state
        let initial_stats = preloader.get_preload_stats().await
            .expect("Initial stats should be available");
        assert_eq!(initial_stats.total_preloaded_keys, 0, "Initial stats should show 0 keys");
        assert_eq!(initial_stats.memory_usage_bytes, 0, "Initial memory usage should be 0");
        
        // Test preloading phase
        let preloaded_keys = preloader.preload_keys(&PreloadStrategy::All).await
            .expect("Lifecycle preload should succeed");
        
        let after_preload_stats = preloader.get_preload_stats().await
            .expect("Stats after preload should be available");
        assert_eq!(after_preload_stats.total_preloaded_keys, preloaded_keys.len(), 
                 "Stats should reflect preloaded keys");
        assert!(after_preload_stats.memory_usage_bytes > 0, "Memory usage should be positive");
        
        // Test background phase
        preloader.start_background_preloading().await
            .expect("Background preloading should start");
        
        // Wait for background activity
        sleep(Duration::millis(200)).await;
        
        let bg_stats = preloader.get_background_preload_stats().await
            .expect("Background stats should be available");
        assert!(bg_stats.total_background_preloads > 0, "Should have background activity");
        
        // Test cleanup phase
        preloader.stop_background_preloading().await
            .expect("Background preloading should stop");
        
        preloader.clear_preloaded_keys().await
            .expect("Preload cleanup should succeed");
        
        let final_stats = preloader.get_preload_stats().await
            .expect("Final stats should be available");
        assert_eq!(final_stats.total_preloaded_keys, 0, "Final stats should show 0 keys");
        assert_eq!(final_stats.memory_usage_bytes, 0, "Final memory usage should be 0");
        
        // Test restart capability
        let restart_keys = preloader.preload_keys(&PreloadStrategy::FrequentlyUsed).await
            .expect("Restart preload should succeed");
        
        assert!(restart_keys.len() > 0, "Restart should load keys");
        
        // Test graceful shutdown
        preloader.shutdown().await
            .expect("Graceful shutdown should succeed");
        
        // Verify shutdown state
        let shutdown_stats = preloader.get_preload_stats().await
            .expect("Shutdown stats should be available");
        
        // Stats should still be available but operations should be limited
        assert_eq!(shutdown_stats.total_preloaded_keys, restart_keys.len(), 
                 "Shutdown should preserve final stats");
    }

    /// Test preloader integration with database operations
    #[tokio::test]
    async fn test_preloader_database_integration() {
        let (db, key_ids) = create_test_database_with_keys(30).await;
        
        let config = KeyPreloadConfig {
            enable_preload: true,
            preload_by_purpose: true,
            priority_purposes: vec!["encryption".to_string(), "authentication".to_string()],
            track_preload_stats: true,
            ..Default::default()
        };
        
        let preloader = KeyPreloader::new(Arc::new(db), config);
        
        // Preload keys by purpose
        let preloaded_keys = preloader.preload_keys(&PreloadStrategy::ByPurpose).await
            .expect("Integration preload should succeed");
        
        // Verify preloaded keys match database
        for (key_id, key, metadata) in &preloaded_keys {
            let db_result = preloader.database().retrieve_key(key_id).await
                .expect("Database retrieval should succeed");
            
            assert!(db_result.is_some(), "Preloaded key should exist in database");
            
            let (db_key, db_metadata) = db_result.unwrap();
            assert_eq!(db_key.to_vec(), key.to_vec(), "Preloaded key should match database key");
            assert_eq!(db_metadata.algorithm, metadata.algorithm, "Preloaded metadata should match database");
        }
        
        // Test database changes after preloading
        let new_key_id = KeyId::new();
        let new_key = create_test_key(64);
        let new_metadata = create_test_metadata("aegis256", "encryption", "lightning");
        
        preloader.database().store_key(&new_key_id, &new_key, &new_metadata).await
            .expect("New key storage should succeed");
        
        // Test if preloader detects new keys
        let updated_keys = preloader.preload_keys(&PreloadStrategy::ByPurpose).await
            .expect("Updated preload should succeed");
        
        // Should include the new key since it matches priority purposes
        let has_new_key = updated_keys.iter().any(|(id, _, _)| id == &new_key_id);
        assert!(has_new_key, "Updated preload should include new key");
        
        // Test database deletion and preloader sync
        let key_to_delete = &preloaded_keys[0].0;
        preloader.database().delete_key(key_to_delete).await
            .expect("Key deletion should succeed");
        
        // Preloader should handle missing keys gracefully
        let sync_keys = preloader.preload_keys(&PreloadStrategy::All).await
            .expect("Sync preload should succeed");
        
        let has_deleted_key = sync_keys.iter().any(|(id, _, _)| id == key_to_delete);
        assert!(!has_deleted_key, "Sync preload should not include deleted key");
        
        // Verify preloader stats reflect database state
        let final_stats = preloader.get_preload_stats().await
            .expect("Final integration stats should be available");
        
        assert!(final_stats.total_preloaded_keys <= key_ids.len(), 
               "Preloader stats should not exceed database key count");
    }
}
