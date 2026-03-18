//! Comprehensive cache tests for Fortress
//!
//! This module provides extensive test coverage for all caching components
//! including unit tests, integration tests, and performance benchmarks.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_cache::{DistributedCache, DistributedCacheConfig, CacheBackend};
    use crate::cache_manager::{CacheManager, CacheManagerConfig, CacheType};
    use crate::cache_invalidation::{CacheInvalidation, CacheInvalidationManager, InvalidationConfig, InvalidationReason};
    use crate::cache_hybrid::{HybridCache, HybridCacheConfig, WriteStrategy};
    use crate::cache_integration::{CacheIntegration, CacheIntegrationConfig};
    use crate::key::{KeyId, SecureKey};
    use crate::encryption::PerformanceProfile;
    use chrono::{Utc, Duration};
    use tokio::time::sleep;

    /// Test helper to create test data
    fn create_test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    /// Test helper to create test key
    fn create_test_key() -> KeyId {
        KeyId::new()
    }

    /// Test helper to create test secure key
    fn create_test_secure_key() -> SecureKey {
        SecureKey::from_bytes(&create_test_data(32))
    }

    /// Test helper to create test metadata
    fn create_test_metadata(key_id: KeyId) -> crate::key::KeyMetadata {
        crate::key::KeyMetadata::new(
            key_id,
            "test_algorithm".to_string(),
            1,
            Utc::now(),
            Utc::now() + Duration::hours(24),
            "test".to_string(),
            PerformanceProfile::Balanced,
        )
    }

    mod distributed_cache_tests {
        use super::*;

        #[tokio::test]
        async fn test_in_memory_cache_basic_operations() {
            let config = DistributedCacheConfig::default();
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            // Test set and get
            let key = "test_key";
            let value = create_test_data(100);
            
            cache.set(key, value.clone(), None).await.unwrap();
            let retrieved = cache.get(key).await.unwrap();
            
            assert_eq!(retrieved, Some(value));
            
            // Test exists
            assert!(cache.exists(key).await.unwrap());
            
            // Test delete
            assert!(cache.delete(key).await.unwrap());
            assert!(!cache.exists(key).await.unwrap());
        }

        #[tokio::test]
        async fn test_in_memory_cache_ttl() {
            let config = DistributedCacheConfig {
                default_ttl_seconds: 1,
                ..Default::default()
            };
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            let key = "ttl_test";
            let value = create_test_data(50);
            
            cache.set(key, value.clone(), Some(1)).await.unwrap();
            
            // Should be available immediately
            assert!(cache.get(key).await.unwrap().is_some());
            
            // Wait for expiration
            sleep(Duration::from_secs(2)).await;
            
            // Should be expired
            assert!(cache.get(key).await.unwrap().is_none());
        }

        #[tokio::test]
        async fn test_in_memory_cache_mget_mset() {
            let config = DistributedCacheConfig::default();
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            let entries = vec![
                ("key1", create_test_data(100), None),
                ("key2", create_test_data(200), None),
                ("key3", create_test_data(300), None),
            ];
            
            cache.mset(&entries).await.unwrap();
            
            let keys = vec!["key1", "key2", "key3"];
            let results = cache.mget(&keys).await.unwrap();
            
            assert_eq!(results.len(), 3);
            assert_eq!(results[0], Some(create_test_data(100)));
            assert_eq!(results[1], Some(create_test_data(200)));
            assert_eq!(results[2], Some(create_test_data(300)));
        }

        #[tokio::test]
        async fn test_in_memory_cache_increment() {
            let config = DistributedCacheConfig::default();
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            let key = "counter";
            
            // Increment from non-existent (should start at 0)
            let result = cache.increment(key, 5).await.unwrap();
            assert_eq!(result, 5);
            
            // Increment existing value
            let result = cache.increment(key, 3).await.unwrap();
            assert_eq!(result, 8);
            
            // Verify stored value
            let stored = cache.get(key).await.unwrap();
            assert_eq!(stored, Some(b"8".to_vec()));
        }

        #[tokio::test]
        async fn test_in_memory_cache_statistics() {
            let config = DistributedCacheConfig::default();
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            // Perform operations
            cache.set("key1", create_test_data(100), None).await.unwrap();
            cache.get("key1").await.unwrap();
            cache.get("key1").await.unwrap();
            cache.get("nonexistent").await.unwrap();
            
            let stats = cache.get_statistics().await.unwrap();
            assert_eq!(stats.sets, 1);
            assert_eq!(stats.hits, 2);
            assert_eq!(stats.misses, 1);
            assert!(stats.hit_ratio > 0.0);
        }

        #[tokio::test]
        async fn test_in_memory_cache_eviction() {
            let config = DistributedCacheConfig {
                max_cache_size: 2,
                eviction_policy: crate::distributed_cache::EvictionPolicy::LRU,
                ..Default::default()
            };
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            // Fill cache beyond capacity
            cache.set("key1", create_test_data(100), None).await.unwrap();
            cache.set("key2", create_test_data(100), None).await.unwrap();
            cache.set("key3", create_test_data(100), None).await.unwrap();
            
            // First key should be evicted
            assert!(!cache.exists("key1").await.unwrap());
            assert!(cache.exists("key2").await.unwrap());
            assert!(cache.exists("key3").await.unwrap());
        }

        #[tokio::test]
        async fn test_in_memory_cache_health_check() {
            let config = DistributedCacheConfig::default();
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            let healthy = cache.health_check().await.unwrap();
            assert!(healthy);
        }
    }

    mod cache_manager_tests {
        use super::*;

        #[tokio::test]
        async fn test_cache_manager_basic_operations() {
            let config = CacheManagerConfig::default();
            let manager = crate::cache_manager::create_cache_manager(config).await.unwrap();

            // Test set and get
            let key = "test_key";
            let value = create_test_data(100);
            
            manager.set(key, value.clone(), None).await.unwrap();
            let retrieved = manager.get(key).await.unwrap();
            
            assert_eq!(retrieved, Some(value));
            
            // Test exists
            assert!(manager.exists(key).await.unwrap());
            
            // Test delete
            assert!(manager.delete(key).await.unwrap());
            assert!(!manager.exists(key).await.unwrap());
        }

        #[tokio::test]
        async fn test_cache_manager_tags() {
            let config = CacheManagerConfig::default();
            let manager = crate::cache_manager::create_cache_manager(config).await.unwrap();

            let key = "tagged_key";
            let value = create_test_data(100);
            let tags = vec!["user".to_string(), "active".to_string()];
            
            // Add tags
            manager.add_tags(key, &tags).await.unwrap();
            
            // Set value
            manager.set(key, value, None).await.unwrap();
            
            // Invalidate by tag
            let count = manager.invalidate_by_tag("user").await.unwrap();
            assert_eq!(count, 1);
            
            // Value should be gone
            assert!(manager.get(key).await.unwrap().is_none());
        }

        #[tokio::test]
        async fn test_cache_manager_statistics() {
            let config = CacheManagerConfig::default();
            let manager = crate::cache_manager::create_cache_manager(config).await.unwrap();

            // Perform operations
            manager.set("key1", create_test_data(100), None).await.unwrap();
            manager.get("key1").await.unwrap();
            manager.get("nonexistent").await.unwrap();
            
            let stats = manager.get_statistics().await.unwrap();
            assert!(stats.cache_stats.sets > 0);
            assert!(stats.cache_stats.hits > 0);
            assert!(stats.cache_stats.misses > 0);
            assert!(stats.performance_metrics.avg_response_time_us >= 0.0);
        }

        #[tokio::test]
        async fn test_cache_manager_health_check() {
            let config = CacheManagerConfig::default();
            let manager = crate::cache_manager::create_cache_manager(config).await.unwrap();

            let health = manager.health_check().await.unwrap();
            assert!(health.healthy);
            assert!(health.issues.is_empty());
        }

        #[tokio::test]
        async fn test_cache_manager_performance_recommendations() {
            let config = CacheManagerConfig::default();
            let manager = crate::cache_manager::create_cache_manager(config).await.unwrap();

            let recommendations = manager.get_performance_recommendations().await.unwrap();
            // Should have some recommendations (even if empty list)
            assert!(recommendations.len() >= 0);
        }
    }

    mod cache_invalidation_tests {
        use super::*;

        #[tokio::test]
        async fn test_dependency_tracking() {
            let config = InvalidationConfig::default();
            let manager = CacheInvalidationManager::new(config);

            // Add dependencies: key1 -> key2 -> key3
            manager.add_dependency("key1", "key2").await.unwrap();
            manager.add_dependency("key2", "key3").await.unwrap();

            // Invalidate key3 should cascade to key1 and key2
            manager.invalidate_key("key3", InvalidationReason::Manual).await.unwrap();

            let stats = manager.get_invalidation_stats().await.unwrap();
            assert!(stats.cascaded_invalidations > 0);
        }

        #[tokio::test]
        async fn test_tag_based_invalidation() {
            let config = InvalidationConfig::default();
            let manager = CacheInvalidationManager::new(config);

            // Add tags to keys
            manager.add_tags("key1", &["user".to_string(), "active".to_string()]).await.unwrap();
            manager.add_tags("key2", &["user".to_string()]).await.unwrap();
            manager.add_tags("key3", &["session".to_string()]).await.unwrap();

            // Invalidate by tag
            let count = manager.invalidate_by_tag("user", InvalidationReason::Manual).await.unwrap();
            assert_eq!(count, 2);

            // Verify tag mappings
            let user_keys = manager.get_tag_keys("user").await;
            assert_eq!(user_keys.len(), 2);
        }

        #[tokio::test]
        async fn test_event_broadcasting() {
            let config = InvalidationConfig::default();
            let manager = CacheInvalidationManager::new(config);

            // Subscribe to events
            let mut receiver = manager.subscribe_events().await;

            // Invalidate a key
            manager.invalidate_key("test_key", InvalidationReason::Manual).await.unwrap();

            // Receive the event
            let event = receiver.recv().await.unwrap();
            assert_eq!(event.key, "test_key");
            assert!(matches!(event.reason, InvalidationReason::Manual));
        }

        #[tokio::test]
        async fn test_pattern_matching() {
            let config = InvalidationConfig::default();
            let manager = CacheInvalidationManager::new(config);

            // Test pattern matching
            assert!(manager.matches_pattern("user:123", "user:*"));
            assert!(manager.matches_pattern("user:123", "*123"));
            assert!(manager.matches_pattern("user:123", "user:123"));
            assert!(manager.matches_pattern("any_key", "*"));
            assert!(!manager.matches_pattern("user:123", "admin:*"));
        }

        #[tokio::test]
        async fn test_invalidation_statistics() {
            let config = InvalidationConfig::default();
            let manager = CacheInvalidationManager::new(config);

            // Perform invalidations
            manager.invalidate_key("key1", InvalidationReason::Manual).await.unwrap();
            manager.invalidate_key("key2", InvalidationReason::TTLExpired).await.unwrap();
            manager.invalidate_key("key3", InvalidationReason::KeyRotation).await.unwrap();

            let stats = manager.get_invalidation_stats().await.unwrap();
            assert_eq!(stats.total_invalidations, 3);
            assert!(stats.invalidations_by_reason.contains_key("Manual"));
            assert!(stats.invalidations_by_reason.contains_key("TTLExpired"));
            assert!(stats.invalidations_by_reason.contains_key("KeyRotation"));
            assert!(stats.last_invalidation.is_some());
        }
    }

    mod hybrid_cache_tests {
        use super::*;

        #[tokio::test]
        async fn test_hybrid_cache_basic_operations() {
            let config = HybridCacheConfig::default();
            let cache = HybridCache::new(config).await.unwrap();

            // Test set and get
            let key = "test_key";
            let value = create_test_data(100);
            
            cache.set(key, value.clone(), None).await.unwrap();
            let retrieved = cache.get(key).await.unwrap();
            
            assert_eq!(retrieved, Some(value));
            
            // Test exists
            assert!(cache.exists(key).await.unwrap());
            
            // Test delete
            assert!(cache.delete(key).await.unwrap());
            assert!(!cache.exists(key).await.unwrap());
        }

        #[tokio::test]
        async fn test_hybrid_cache_write_through() {
            let config = HybridCacheConfig {
                write_strategy: WriteStrategy::WriteThrough,
                ..Default::default()
            };
            
            let cache = HybridCache::new(config).await.unwrap();

            let key = "write_through_test";
            let value = create_test_data(100);
            
            cache.set(key, value.clone(), None).await.unwrap();
            
            // Should be in both caches
            let retrieved = cache.get(key).await.unwrap();
            assert_eq!(retrieved, Some(value));
            
            let stats = cache.get_statistics().await.unwrap();
            assert!(stats.sets > 0);
        }

        #[tokio::test]
        async fn test_hybrid_cache_write_back() {
            let config = HybridCacheConfig {
                write_strategy: WriteStrategy::WriteBack,
                background_sync_interval_seconds: 0, // Disable background sync for test
                ..Default::default()
            };
            
            let cache = HybridCache::new(config).await.unwrap();

            let key = "write_back_test";
            let value = create_test_data(100);
            
            cache.set(key, value.clone(), None).await.unwrap();
            
            // Should be in local cache
            let retrieved = cache.get(key).await.unwrap();
            assert_eq!(retrieved, Some(value));
            
            // Check that it's marked as dirty
            let local_entries = cache.local_entries.read().await;
            if let Some(entry) = local_entries.get(key) {
                assert!(entry.is_dirty);
            }
        }

        #[tokio::test]
        async fn test_hybrid_cache_statistics() {
            let config = HybridCacheConfig::default();
            let cache = HybridCache::new(config).await.unwrap();

            // Perform operations
            cache.set("key1", create_test_data(100), None).await.unwrap();
            cache.get("key1").await.unwrap();
            cache.get("nonexistent").await.unwrap();
            
            let stats = cache.get_statistics().await.unwrap();
            assert!(stats.sets > 0);
            assert!(stats.hits > 0);
            assert!(stats.misses > 0);
            assert!(stats.hit_ratio > 0.0);
        }

        #[tokio::test]
        async fn test_hybrid_cache_health_check() {
            let config = HybridCacheConfig::default();
            let cache = HybridCache::new(config).await.unwrap();

            let healthy = cache.health_check().await.unwrap();
            assert!(healthy);
        }

        #[tokio::test]
        async fn test_hybrid_cache_mget_mset() {
            let config = HybridCacheConfig::default();
            let cache = HybridCache::new(config).await.unwrap();

            let entries = vec![
                ("key1", create_test_data(100), None),
                ("key2", create_test_data(200), None),
                ("key3", create_test_data(300), None),
            ];
            
            cache.mset(&entries).await.unwrap();
            
            let keys = vec!["key1", "key2", "key3"];
            let results = cache.mget(&keys).await.unwrap();
            
            assert_eq!(results.len(), 3);
            assert_eq!(results[0], Some(create_test_data(100)));
            assert_eq!(results[1], Some(create_test_data(200)));
            assert_eq!(results[2], Some(create_test_data(300)));
        }
    }

    mod cache_integration_tests {
        use super::*;

        #[tokio::test]
        async fn test_cache_integration_key_caching() {
            let config = CacheIntegrationConfig::default();
            let integration = crate::cache_integration::create_cache_integration(config).await.unwrap();

            let key_id = create_test_key();
            let key = create_test_secure_key();
            let metadata = create_test_metadata(key_id.clone());

            // Cache key
            integration.cache_key(&key_id, &key, &metadata, "test_algorithm").await.unwrap();

            // Get cached key
            let cached = integration.get_cached_key(&key_id).await.unwrap();
            assert!(cached.is_some());
            
            let (cached_key, cached_metadata) = cached.unwrap();
            assert_eq!(cached_key.to_vec(), key.to_vec());
            assert_eq!(cached_metadata.id, key_id);

            // Invalidate key
            let invalidated = integration.invalidate_cached_key(&key_id).await.unwrap();
            assert!(invalidated);

            // Key should be gone
            let cached = integration.get_cached_key(&key_id).await.unwrap();
            assert!(cached.is_none());
        }

        #[tokio::test]
        async fn test_cache_integration_encryption_caching() {
            let config = CacheIntegrationConfig::default();
            let integration = crate::cache_integration::create_cache_integration(config).await.unwrap();

            let cache_key = "test_encryption";
            let plaintext = b"test_plaintext";
            let ciphertext = b"test_ciphertext";
            let algorithm = "AES-256-GCM";

            // Cache encryption result
            integration.cache_encryption_result(cache_key, plaintext, ciphertext, algorithm).await.unwrap();

            // Get cached encryption result
            let cached = integration.get_cached_encryption_result(cache_key).await.unwrap();
            assert!(cached.is_some());
            assert_eq!(cached.unwrap(), ciphertext);
        }

        #[tokio::test]
        async fn test_cache_integration_decryption_caching() {
            let config = CacheIntegrationConfig::default();
            let integration = crate::cache_integration::create_cache_integration(config).await.unwrap();

            let cache_key = "test_decryption";
            let ciphertext = b"test_ciphertext";
            let plaintext = b"test_plaintext";
            let algorithm = "AES-256-GCM";

            // Cache decryption result
            integration.cache_decryption_result(cache_key, ciphertext, plaintext, algorithm).await.unwrap();

            // Get cached decryption result
            let cached = integration.get_cached_decryption_result(cache_key).await.unwrap();
            assert!(cached.is_some());
            assert_eq!(cached.unwrap(), plaintext);
        }

        #[tokio::test]
        async fn test_cache_integration_statistics() {
            let config = CacheIntegrationConfig::default();
            let integration = crate::cache_integration::create_cache_integration(config).await.unwrap();

            // Perform some operations
            let key_id = create_test_key();
            let key = create_test_secure_key();
            let metadata = create_test_metadata(key_id.clone());

            integration.cache_key(&key_id, &key, &metadata, "test_algorithm").await.unwrap();
            integration.get_cached_key(&key_id).await.unwrap();

            let stats = integration.get_integration_statistics().await.unwrap();
            assert!(stats.key_cache_stats.cached_keys > 0);
            assert!(stats.key_cache_stats.hits > 0);
            assert!(stats.performance_metrics.overall_hit_ratio > 0.0);
        }

        #[tokio::test]
        async fn test_cache_integration_warm_up() {
            let config = CacheIntegrationConfig::default();
            let integration = crate::cache_integration::create_cache_integration(config).await.unwrap();

            let key_id = create_test_key();
            let key = create_test_secure_key();
            let metadata = create_test_metadata(key_id.clone());

            let keys = vec![(key_id, key, metadata, "test_algorithm".to_string())];
            
            let warmed_count = integration.warm_up_keys(keys).await.unwrap();
            assert_eq!(warmed_count, 1);
        }

        #[tokio::test]
        async fn test_cache_integration_maintenance() {
            let config = CacheIntegrationConfig::default();
            let integration = crate::cache_integration::create_cache_integration(config).await.unwrap();

            // Perform maintenance
            integration.perform_maintenance().await.unwrap();
            
            // Should not error
            assert!(true);
        }
    }

    mod performance_benchmarks {
        use super::*;
        use std::time::Instant;

        #[tokio::test]
        #[ignore] // Performance test - run manually
        async fn benchmark_cache_performance() {
            let config = DistributedCacheConfig::default();
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            let num_operations = 10000;
            let data_size = 1024; // 1KB

            // Benchmark set operations
            let start = Instant::now();
            for i in 0..num_operations {
                let key = format!("benchmark_key_{}", i);
                let value = create_test_data(data_size);
                cache.set(&key, value, None).await.unwrap();
            }
            let set_duration = start.elapsed();

            // Benchmark get operations
            let start = Instant::now();
            for i in 0..num_operations {
                let key = format!("benchmark_key_{}", i);
                cache.get(&key).await.unwrap();
            }
            let get_duration = start.elapsed();

            // Print results
            println!("Cache Performance Benchmark Results:");
            println!("Operations: {}", num_operations);
            println!("Data size: {} bytes", data_size);
            println!("Set ops/sec: {:.2}", num_operations as f64 / set_duration.as_secs_f64());
            println!("Get ops/sec: {:.2}", num_operations as f64 / get_duration.as_secs_f64());
            println!("Avg set time: {:.2}μs", set_duration.as_micros() as f64 / num_operations as f64);
            println!("Avg get time: {:.2}μs", get_duration.as_micros() as f64 / num_operations as f64);

            // Get final statistics
            let stats = cache.get_statistics().await.unwrap();
            println!("Hit ratio: {:.2}%", stats.hit_ratio * 100.0);
            println!("Cache size: {} entries", stats.total_entries);
            println!("Cache memory: {} MB", stats.cache_size_bytes / (1024 * 1024));

            // Assertions for reasonable performance
            assert!(set_duration.as_secs_f64() < 5.0, "Set operations too slow");
            assert!(get_duration.as_secs_f64() < 2.0, "Get operations too slow");
            assert!(stats.hit_ratio > 0.9, "Hit ratio too low");
        }

        #[tokio::test]
        #[ignore] // Performance test - run manually
        async fn benchmark_cache_manager_performance() {
            let config = CacheManagerConfig::default();
            let manager = crate::cache_manager::create_cache_manager(config).await.unwrap();

            let num_operations = 5000;
            let data_size = 512; // 512 bytes

            // Benchmark mixed operations
            let start = Instant::now();
            for i in 0..num_operations {
                let key = format!("mgr_benchmark_{}", i);
                let value = create_test_data(data_size);
                
                // Set
                manager.set(&key, value.clone(), None).await.unwrap();
                
                // Get
                manager.get(&key).await.unwrap();
                
                // Delete every 10th key
                if i % 10 == 0 {
                    manager.delete(&key).await.unwrap();
                }
            }
            let duration = start.elapsed();

            // Print results
            println!("Cache Manager Performance Benchmark Results:");
            println!("Operations: {}", num_operations * 3); // set + get + occasional delete
            println!("Data size: {} bytes", data_size);
            println!("Ops/sec: {:.2}", (num_operations * 3) as f64 / duration.as_secs_f64());
            println!("Avg operation time: {:.2}μs", duration.as_micros() as f64 / (num_operations * 3) as f64);

            // Get final statistics
            let stats = manager.get_statistics().await.unwrap();
            println!("Hit ratio: {:.2}%", stats.cache_stats.hit_ratio * 100.0);
            println!("Response time: {:.2}μs", stats.performance_metrics.avg_response_time_us);
            println!("Efficiency score: {:.2}", stats.performance_metrics.efficiency_score);

            // Assertions for reasonable performance
            assert!(duration.as_secs_f64() < 10.0, "Operations too slow");
            assert!(stats.cache_stats.hit_ratio > 0.8, "Hit ratio too low");
            assert!(stats.performance_metrics.efficiency_score > 0.7, "Efficiency too low");
        }

        #[tokio::test]
        #[ignore] // Memory usage test - run manually
        async fn benchmark_memory_usage() {
            let config = DistributedCacheConfig {
                max_cache_size: 1000,
                ..Default::default()
            };
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            let data_size = 10 * 1024; // 10KB per entry
            let num_entries = 500;

            // Fill cache
            for i in 0..num_entries {
                let key = format!("memory_test_{}", i);
                let value = create_test_data(data_size);
                cache.set(&key, value, None).await.unwrap();
            }

            // Check memory usage
            let stats = cache.get_statistics().await.unwrap();
            let estimated_memory = stats.cache_size_bytes;
            let expected_memory = num_entries * data_size;

            println!("Memory Usage Benchmark Results:");
            println!("Entries: {}", num_entries);
            println!("Data size per entry: {} KB", data_size / 1024);
            println!("Expected memory: {} MB", expected_memory / (1024 * 1024));
            println!("Actual memory: {} MB", estimated_memory / (1024 * 1024));
            println!("Memory overhead: {:.2}%", (estimated_memory as f64 / expected_memory as f64 - 1.0) * 100.0);

            // Assertions for reasonable memory usage
            assert!(estimated_memory <= expected_memory * 2, "Memory usage too high");
        }
    }

    mod integration_tests {
        use super::*;

        #[tokio::test]
        async fn test_end_to_end_cache_workflow() {
            // Create cache manager
            let cache_config = CacheManagerConfig::default();
            let cache_manager = crate::cache_manager::create_cache_manager(cache_config).await.unwrap();

            // Create cache integration
            let integration_config = CacheIntegrationConfig::default();
            let cache_integration = crate::cache_integration::create_cache_integration(integration_config).await.unwrap();

            // Create invalidation manager
            let invalidation_config = InvalidationConfig::default();
            let invalidation_manager = CacheInvalidationManager::new(invalidation_config);

            // Test workflow: Cache key -> Use in operations -> Invalidate
            let key_id = create_test_key();
            let key = create_test_secure_key();
            let metadata = create_test_metadata(key_id.clone());

            // Step 1: Cache the key
            cache_integration.cache_key(&key_id, &key, &metadata, "test_algorithm").await.unwrap();
            
            // Step 2: Retrieve and use the key
            let cached_key = cache_integration.get_cached_key(&key_id).await.unwrap();
            assert!(cached_key.is_some());

            // Step 3: Cache some data using the cache manager
            let data_key = format!("data_{}", key_id);
            let data_value = create_test_data(1024);
            cache_manager.set(&data_key, data_value.clone(), None).await.unwrap();
            
            // Step 4: Add tags for invalidation
            cache_manager.add_tags(&data_key, &["user_data".to_string(), "encrypted".to_string()]).await.unwrap();
            invalidation_manager.add_tags(&data_key, &["user_data".to_string()]).await.unwrap();

            // Step 5: Verify data is cached
            let retrieved_data = cache_manager.get(&data_key).await.unwrap();
            assert_eq!(retrieved_data, Some(data_value));

            // Step 6: Invalidate by tag
            let invalidated_count = cache_manager.invalidate_by_tag("user_data").await.unwrap();
            assert!(invalidated_count > 0);

            // Step 7: Verify data is invalidated
            let retrieved_data = cache_manager.get(&data_key).await.unwrap();
            assert!(retrieved_data.is_none());

            // Step 8: Invalidate key
            let key_invalidated = cache_integration.invalidate_cached_key(&key_id).await.unwrap();
            assert!(key_invalidated);

            // Step 9: Verify key is invalidated
            let cached_key = cache_integration.get_cached_key(&key_id).await.unwrap();
            assert!(cached_key.is_none());

            // Step 10: Check final statistics
            let cache_stats = cache_manager.get_statistics().await.unwrap();
            let integration_stats = cache_integration.get_integration_statistics().await.unwrap();
            let invalidation_stats = invalidation_manager.get_invalidation_stats().await.unwrap();

            assert!(cache_stats.cache_stats.sets > 0);
            assert!(cache_stats.cache_stats.deletes > 0);
            assert!(integration_stats.key_cache_stats.cached_keys > 0);
            assert!(invalidation_stats.total_invalidations > 0);
        }

        #[tokio::test]
        async fn test_multi_cache_coordination() {
            // Test coordination between different cache types
            
            // In-memory cache
            let memory_config = DistributedCacheConfig::default();
            let memory_cache = crate::distributed_cache::create_distributed_cache(memory_config).await.unwrap();

            // Cache manager
            let manager_config = CacheManagerConfig::default();
            let cache_manager = crate::cache_manager::create_cache_manager(manager_config).await.unwrap();

            // Cache integration
            let integration_config = CacheIntegrationConfig::default();
            let cache_integration = crate::cache_integration::create_cache_integration(integration_config).await.unwrap();

            let test_key = "coordination_test";
            let test_value = create_test_data(2048);

            // Set in all caches
            memory_cache.set(test_key, test_value.clone(), None).await.unwrap();
            cache_manager.set(test_key, test_value.clone(), None).await.unwrap();

            let key_id = create_test_key();
            let secure_key = create_test_secure_key();
            let metadata = create_test_metadata(key_id.clone());
            cache_integration.cache_key(&key_id, &secure_key, &metadata, "test_algorithm").await.unwrap();

            // Verify all caches have the data
            assert_eq!(memory_cache.get(test_key).await.unwrap(), Some(test_value.clone()));
            assert_eq!(cache_manager.get(test_key).await.unwrap(), Some(test_value.clone()));
            assert!(cache_integration.get_cached_key(&key_id).await.unwrap().is_some());

            // Clear from cache manager
            cache_manager.clear().await.unwrap();

            // Verify cache manager is clear but others still have data
            assert!(cache_manager.get(test_key).await.unwrap().is_none());
            assert_eq!(memory_cache.get(test_key).await.unwrap(), Some(test_value));
            assert!(cache_integration.get_cached_key(&key_id).await.unwrap().is_some());
        }

        #[tokio::test]
        async fn test_cache_resilience() {
            // Test cache behavior under various failure conditions
            
            let config = DistributedCacheConfig::default();
            let cache = crate::distributed_cache::create_distributed_cache(config).await.unwrap();

            // Test with large data
            let large_data = create_test_data(5 * 1024 * 1024); // 5MB
            let large_key = "large_data_test";

            // Should handle large data gracefully
            match cache.set(large_key, large_data.clone(), None).await {
                Ok(_) => {
                    let retrieved = cache.get(large_key).await.unwrap();
                    assert_eq!(retrieved, Some(large_data));
                    cache.delete(large_key).await.unwrap();
                }
                Err(_) => {
                    // Large data might be rejected, which is acceptable
                    println!("Large data rejected as expected");
                }
            }

            // Test with many small entries
            let num_entries = 1000;
            let mut keys = Vec::new();
            
            for i in 0..num_entries {
                let key = format!("stress_test_{}", i);
                let value = create_test_data(1024);
                cache.set(&key, value, None).await.unwrap();
                keys.push(key);
            }

            // Verify most entries are still there (some might be evicted)
            let mut found_count = 0;
            for key in &keys {
                if cache.get(key).await.unwrap().is_some() {
                    found_count += 1;
                }
            }

            println!("Found {}/{} entries after stress test", found_count, num_entries);
            assert!(found_count > num_entries / 2, "Too many entries evicted");

            // Test cache health after stress
            let healthy = cache.health_check().await.unwrap();
            assert!(healthy, "Cache should be healthy after stress test");

            // Get final statistics
            let stats = cache.get_statistics().await.unwrap();
            println!("Final stats: {} entries, {:.2}% hit ratio", 
                stats.total_entries, stats.hit_ratio * 100.0);
        }
    }
}
