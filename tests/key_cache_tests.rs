//! Comprehensive Key Cache Tests
//! 
//! This test suite provides comprehensive coverage for the key cache system,
//! testing caching performance, invalidation strategies, memory usage optimization,
//! cache hit/miss ratio testing, and concurrent cache access.

use fortress_core::key_cache::{KeyCache, KeyCacheConfig, CacheStats};
use fortress_core::key::{KeyId, KeyMetadata, SecureKey};
use fortress_core::encryption::Aegis256;
use fortress_core::error::Result;
use chrono::{Utc, Duration};
use std::sync::Arc;
use tokio::time::sleep;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create test key metadata
    fn create_test_metadata(algorithm_name: &str) -> KeyMetadata {
        let mut metadata = KeyMetadata::new(&Aegis256::new());
        metadata.algorithm = algorithm_name.to_string();
        metadata.created_at = Utc::now();
        metadata.expires_at = Some(Utc::now() + Duration::hours(24));
        metadata.tags.insert("test".to_string(), "true".to_string());
        metadata.tags.insert("cache".to_string(), "test".to_string());
        metadata
    }

    /// Helper function to create test secure key
    fn create_test_key(size: usize) -> SecureKey {
        let key_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        SecureKey::new(key_data)
    }

    /// Test basic cache functionality
    #[tokio::test]
    async fn test_basic_cache_functionality() {
        let config = KeyCacheConfig::default();
        let cache = KeyCache::new(config);
        
        // Test cache miss
        let key_id = KeyId::new();
        let result = cache.get(&key_id).await;
        assert!(result.is_ok(), "Cache get should not error");
        assert!(result.unwrap().is_none(), "Cache miss should return None");
        
        // Test cache put
        let key = create_test_key(32);
        let metadata = create_test_metadata("aegis256");
        
        cache.put(&key_id, &key, &metadata).await
            .expect("Cache put should succeed");
        
        // Test cache hit
        let result = cache.get(&key_id).await
            .expect("Cache get should succeed");
        assert!(result.is_some(), "Cached key should be found");
        
        let (cached_key, cached_metadata) = result.unwrap();
        assert_eq!(cached_key.to_vec(), key.to_vec(), "Cached key should match original");
        assert_eq!(cached_metadata.algorithm, metadata.algorithm, "Cached metadata should match");
        
        // Test cache contains
        let contains = cache.contains(&key_id).await
            .expect("Cache contains should succeed");
        assert!(contains, "Cache should contain the key");
        
        // Test cache remove
        cache.remove(&key_id).await
            .expect("Cache remove should succeed");
        
        // Verify removal
        let result = cache.get(&key_id).await
            .expect("Cache get after remove should succeed");
        assert!(result.is_none(), "Removed key should not be found");
        
        let contains_after_remove = cache.contains(&key_id).await
            .expect("Cache contains after remove should succeed");
        assert!(!contains_after_remove, "Cache should not contain removed key");
    }

    /// Test LRU eviction strategy
    #[tokio::test]
    async fn test_lru_eviction_strategy() {
        let mut config = KeyCacheConfig::default();
        config.max_keys = 3; // Small cache to trigger eviction
        config.enable_lru_eviction = true;
        config.enable_time_eviction = false; // Disable time-based eviction
        
        let cache = KeyCache::new(config);
        
        // Fill cache to capacity
        let mut key_ids = Vec::new();
        for i in 0..3 {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("lru_key_{}", i));
            
            cache.put(&key_id, &key, &metadata).await
                .expect(&format!("LRU key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        // Verify all keys are cached
        for key_id in &key_ids {
            let contains = cache.contains(key_id).await
                .expect("Cache contains should succeed");
            assert!(contains, "Cache should contain key {}", key_id);
        }
        
        // Access the first key to make it most recently used
        cache.get(&key_ids[0]).await
            .expect("Cache access should succeed");
        
        // Add a new key to trigger eviction
        let new_key_id = KeyId::new();
        let new_key = create_test_key(32);
        let new_metadata = create_test_metadata("new_lru_key");
        
        cache.put(&new_key_id, &new_key, &new_metadata).await
            .expect("New key storage should trigger eviction");
        
        // Verify LRU eviction: the least recently used key should be evicted
        // (key_ids[1] should be evicted since key_ids[0] was accessed)
        let contains_evicted = cache.contains(&key_ids[1]).await
            .expect("Cache contains should succeed");
        assert!(!contains_evicted, "LRU key should be evicted");
        
        // Verify other keys are still cached
        let contains_first = cache.contains(&key_ids[0]).await
            .expect("Cache contains should succeed");
        assert!(contains_first, "Recently accessed key should remain");
        
        let contains_third = cache.contains(&key_ids[2]).await
            .expect("Cache contains should succeed");
        assert!(contains_third, "Third key should remain");
        
        let contains_new = cache.contains(&new_key_id).await
            .expect("Cache contains should succeed");
        assert!(contains_new, "New key should be cached");
        
        // Verify cache size limit is maintained
        let stats = cache.get_stats().await
            .expect("Stats retrieval should succeed");
        assert_eq!(stats.total_keys, 3, "Cache should maintain size limit");
    }

    /// Test time-based eviction
    #[tokio::test]
    async fn test_time_based_eviction() {
        let mut config = KeyCacheConfig::default();
        config.max_keys = 100;
        config.enable_lru_eviction = false;
        config.enable_time_eviction = true;
        config.eviction_time_seconds = 2; // 2 seconds TTL
        
        let cache = KeyCache::new(config);
        
        // Store a key
        let key_id = KeyId::new();
        let key = create_test_key(32);
        let metadata = create_test_metadata("time_eviction_test");
        
        cache.put(&key_id, &key, &metadata).await
            .expect("Key storage should succeed");
        
        // Verify key is cached immediately
        let contains_immediately = cache.contains(&key_id).await
            .expect("Cache contains should succeed");
        assert!(contains_immediately, "Key should be cached immediately");
        
        // Wait for eviction time
        sleep(tokio::time::Duration::from_secs(3)).await;
        
        // Trigger cleanup (this might be automatic depending on implementation)
        let _ = cache.cleanup_expired().await;
        
        // Verify key has been evicted
        let contains_after_ttl = cache.contains(&key_id).await
            .expect("Cache contains should succeed");
        assert!(!contains_after_ttl, "Key should be evicted after TTL");
        
        let result_after_ttl = cache.get(&key_id).await
            .expect("Cache get after TTL should succeed");
        assert!(result_after_ttl.is_none(), "Evicted key should not be retrievable");
    }

    /// Test memory usage optimization
    #[tokio::test]
    async fn test_memory_usage_optimization() {
        let mut config = KeyCacheConfig::default();
        config.max_keys = 10;
        config.max_memory_bytes = 1024; // 1KB limit
        config.enable_lru_eviction = true;
        
        let cache = KeyCache::new(config);
        
        // Store keys with increasing sizes
        let mut key_ids = Vec::new();
        for i in 0..5 {
            let key_id = KeyId::new();
            let key = create_test_key(200 * (i + 1)); // Increasing sizes: 200, 400, 600, 800, 1000 bytes
            let metadata = create_test_metadata(&format!("memory_key_{}", i));
            
            cache.put(&key_id, &key, &metadata).await
                .expect(&format!("Memory key {} storage should succeed", i));
            
            key_ids.push(key_id);
            
            // Check memory usage
            let stats = cache.get_stats().await
                .expect("Stats retrieval should succeed");
            
            if i > 0 {
                // Memory usage should be within limits
                assert!(stats.memory_usage_bytes <= config.max_memory_bytes, 
                       "Memory usage should not exceed limit after key {}", i);
            }
        }
        
        // Verify cache respects memory limits
        let final_stats = cache.get_stats().await
            .expect("Final stats retrieval should succeed");
        assert!(final_stats.memory_usage_bytes <= config.max_memory_bytes, 
               "Final memory usage should be within limits");
        assert!(final_stats.total_keys <= config.max_keys, 
               "Key count should be within limits");
    }

    /// Test cache hit/miss ratio
    #[tokio::test]
    async fn test_cache_hit_miss_ratio() {
        let config = KeyCacheConfig::default();
        let cache = KeyCache::new(config);
        
        // Store some keys
        let mut key_ids = Vec::new();
        for i in 0..10 {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("ratio_key_{}", i));
            
            cache.put(&key_id, &key, &metadata).await
                .expect(&format!("Ratio key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        // Perform cache hits
        for key_id in &key_ids {
            let result = cache.get(key_id).await
                .expect("Cache hit should succeed");
            assert!(result.is_some(), "Cache hit should return key");
        }
        
        // Perform cache misses
        for i in 0..5 {
            let non_existent_id = KeyId::new();
            let result = cache.get(&non_existent_id).await
                .expect("Cache miss should succeed");
            assert!(result.is_none(), "Cache miss should return None");
        }
        
        // Check statistics
        let stats = cache.get_stats().await
            .expect("Stats retrieval should succeed");
        
        assert_eq!(stats.cache_hits, 10, "Should have 10 cache hits");
        assert_eq!(stats.cache_misses, 5, "Should have 5 cache misses");
        assert_eq!(stats.total_requests, 15, "Should have 15 total requests");
        
        let hit_ratio = stats.hit_ratio();
        let expected_ratio = 10.0 / 15.0;
        assert!((hit_ratio - expected_ratio).abs() < 0.001, 
               "Hit ratio should be {:.3}, got {:.3}", expected_ratio, hit_ratio);
    }

    /// Test concurrent cache access
    #[tokio::test]
    async fn test_concurrent_cache_access() {
        let config = KeyCacheConfig::default();
        let cache = Arc::new(KeyCache::new(config));
        
        // Pre-populate cache with some keys
        let mut key_ids = Vec::new();
        for i in 0..20 {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("concurrent_key_{}", i));
            
            cache.put(&key_id, &key, &metadata).await
                .expect(&format!("Concurrent key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        // Test concurrent reads
        let num_concurrent_readers = 10;
        let mut read_handles = Vec::new();
        
        for reader_id in 0..num_concurrent_readers {
            let cache_clone = Arc::clone(&cache);
            let key_ids_clone = key_ids.clone();
            
            let handle = tokio::spawn(async move {
                let mut successful_reads = 0;
                
                for key_id in &key_ids_clone {
                    let result = cache_clone.get(key_id).await
                        .expect("Concurrent read should succeed");
                    
                    if result.is_some() {
                        successful_reads += 1;
                    }
                }
                
                successful_reads
            });
            read_handles.push(handle);
        }
        
        // Wait for all reads to complete
        let mut total_successful_reads = 0;
        for handle in read_handles {
            let successful_reads = handle.await.expect("Read task should complete");
            total_successful_reads += successful_reads;
        }
        
        let expected_reads = num_concurrent_readers * key_ids.len();
        assert_eq!(total_successful_reads, expected_reads, 
                 "All concurrent reads should succeed");
        
        // Test concurrent writes
        let num_concurrent_writers = 5;
        let mut write_handles = Vec::new();
        
        for writer_id in 0..num_concurrent_writers {
            let cache_clone = Arc::clone(&cache);
            
            let handle = tokio::spawn(async move {
                let mut successful_writes = 0;
                
                for i in 0..10 {
                    let key_id = KeyId::new();
                    let key = create_test_key(32);
                    let metadata = create_test_metadata(&format!("concurrent_write_{}_{}", writer_id, i));
                    
                    cache_clone.put(&key_id, &key, &metadata).await
                        .expect("Concurrent write should succeed");
                    
                    successful_writes += 1;
                }
                
                successful_writes
            });
            write_handles.push(handle);
        }
        
        // Wait for all writes to complete
        let mut total_successful_writes = 0;
        for handle in write_handles {
            let successful_writes = handle.await.expect("Write task should complete");
            total_successful_writes += successful_writes;
        }
        
        let expected_writes = num_concurrent_writers * 10;
        assert_eq!(total_successful_writes, expected_writes, 
                 "All concurrent writes should succeed");
        
        // Test mixed concurrent operations
        let num_mixed_operations = 8;
        let mut mixed_handles = Vec::new();
        
        for op_id in 0..num_mixed_operations {
            let cache_clone = Arc::clone(&cache);
            let existing_key_ids = key_ids.clone();
            
            let handle = tokio::spawn(async move {
                // Mix of reads, writes, and removes
                for i in 0..5 {
                    // Read existing key
                    if let Some(key_id) = existing_key_ids.get(i % existing_key_ids.len()) {
                        let _ = cache_clone.get(key_id).await;
                    }
                    
                    // Write new key
                    let new_key_id = KeyId::new();
                    let new_key = create_test_key(32);
                    let new_metadata = create_test_metadata(&format!("mixed_op_{}_{}", op_id, i));
                    let _ = cache_clone.put(&new_key_id, &new_key, &new_metadata).await;
                    
                    // Check contains
                    let _ = cache_clone.contains(&new_key_id).await;
                    
                    // Remove the key we just added
                    let _ = cache_clone.remove(&new_key_id).await;
                }
            });
            mixed_handles.push(handle);
        }
        
        // Wait for all mixed operations to complete
        for handle in mixed_handles {
            handle.await.expect("Mixed operation task should complete");
        }
        
        // Verify cache is still functional
        let final_stats = cache.get_stats().await
            .expect("Final stats should succeed");
        assert!(final_stats.total_keys >= key_ids.len(), 
               "Original keys should still be cached");
    }

    /// Test cache invalidation strategies
    #[tokio::test]
    async fn test_cache_invalidation_strategies() {
        let config = KeyCacheConfig::default();
        let cache = KeyCache::new(config);
        
        // Store multiple keys
        let mut key_ids = Vec::new();
        for i in 0..10 {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("invalidation_key_{}", i));
            
            cache.put(&key_id, &key, &metadata).await
                .expect(&format!("Invalidation key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        // Verify all keys are cached
        for key_id in &key_ids {
            let contains = cache.contains(key_id).await
                .expect("Cache contains should succeed");
            assert!(contains, "Key {} should be cached", key_id);
        }
        
        // Test individual invalidation
        let key_to_invalidate = &key_ids[0];
        cache.remove(key_to_invalidate).await
            .expect("Individual invalidation should succeed");
        
        let contains_after_remove = cache.contains(key_to_invalidate).await
            .expect("Cache contains after remove should succeed");
        assert!(!contains_after_remove, "Invalidated key should not be cached");
        
        // Test bulk invalidation
        let keys_to_invalidate = &key_ids[1..5];
        for key_id in keys_to_invalidate {
            cache.remove(key_id).await
                .expect("Bulk invalidation should succeed");
        }
        
        for key_id in keys_to_invalidate {
            let contains_after_bulk = cache.contains(key_id).await
                .expect("Cache contains after bulk should succeed");
            assert!(!contains_after_bulk, "Bulk invalidated key should not be cached");
        }
        
        // Test cache clear
        cache.clear().await
            .expect("Cache clear should succeed");
        
        // Verify all keys are invalidated
        for key_id in &key_ids {
            let contains_after_clear = cache.contains(key_id).await
                .expect("Cache contains after clear should succeed");
            assert!(!contains_after_clear, "Cleared key should not be cached");
        }
        
        let stats_after_clear = cache.get_stats().await
            .expect("Stats after clear should succeed");
        assert_eq!(stats_after_clear.total_keys, 0, "Cache should be empty after clear");
        assert_eq!(stats_after_clear.memory_usage_bytes, 0, "Memory usage should be 0 after clear");
    }

    /// Test cache performance with many operations
    #[tokio::test]
    async fn test_cache_performance_many_operations() {
        let mut config = KeyCacheConfig::default();
        config.max_keys = 10000;
        config.max_memory_bytes = 100 * 1024 * 1024; // 100MB
        config.enable_stats = true;
        
        let cache = KeyCache::new(config);
        
        let num_operations = 1000;
        let mut key_ids = Vec::new();
        
        // Test write performance
        let start_time = std::time::Instant::now();
        
        for i in 0..num_operations {
            let key_id = KeyId::new();
            let key = create_test_key(64);
            let metadata = create_test_metadata(&format!("perf_key_{}", i));
            
            cache.put(&key_id, &key, &metadata).await
                .expect(&format!("Performance key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        let write_duration = start_time.elapsed();
        println!("Cached {} keys in {:?}", num_operations, write_duration);
        
        // Test read performance
        let start_time = std::time::Instant::now();
        let mut successful_reads = 0;
        
        for key_id in &key_ids {
            let result = cache.get(key_id).await
                .expect("Performance read should succeed");
            
            if result.is_some() {
                successful_reads += 1;
            }
        }
        
        let read_duration = start_time.elapsed();
        println!("Read {} cached keys in {:?}", successful_reads, read_duration);
        
        // Test contains performance
        let start_time = std::time::Instant::now();
        let mut successful_contains = 0;
        
        for key_id in &key_ids {
            let contains = cache.contains(key_id).await
                .expect("Performance contains should succeed");
            
            if contains {
                successful_contains += 1;
            }
        }
        
        let contains_duration = start_time.elapsed();
        println!("Checked contains for {} keys in {:?}", successful_contains, contains_duration);
        
        // Verify all operations succeeded
        assert_eq!(successful_reads, num_operations, "All reads should succeed");
        assert_eq!(successful_contains, num_operations, "All contains checks should succeed");
        
        // Performance assertions
        assert!(write_duration.as_millis() < 5000, "Write operations should complete in reasonable time");
        assert!(read_duration.as_millis() < 1000, "Read operations should be fast");
        assert!(contains_duration.as_millis() < 500, "Contains operations should be very fast");
        
        // Check final statistics
        let stats = cache.get_stats().await
            .expect("Final stats should succeed");
        assert_eq!(stats.total_keys, num_operations, "Should have all keys cached");
        assert!(stats.memory_usage_bytes > 0, "Should use memory");
        assert_eq!(stats.cache_hits, successful_reads, "Should track cache hits");
    }

    /// Test cache statistics and monitoring
    #[tokio::test]
    async fn test_cache_statistics_monitoring() {
        let config = KeyCacheConfig::default();
        let cache = KeyCache::new(config);
        
        // Test initial statistics
        let initial_stats = cache.get_stats().await
            .expect("Initial stats should succeed");
        assert_eq!(initial_stats.total_keys, 0, "Initial stats should show 0 keys");
        assert_eq!(initial_stats.cache_hits, 0, "Initial stats should show 0 hits");
        assert_eq!(initial_stats.cache_misses, 0, "Initial stats should show 0 misses");
        assert_eq!(initial_stats.total_requests, 0, "Initial stats should show 0 requests");
        assert_eq!(initial_stats.memory_usage_bytes, 0, "Initial stats should show 0 memory usage");
        
        // Store some keys
        let num_keys = 50;
        let mut key_ids = Vec::new();
        
        for i in 0..num_keys {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("stats_key_{}", i));
            
            cache.put(&key_id, &key, &metadata).await
                .expect(&format!("Stats key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        // Perform various operations
        let hits = 0;
        let misses = 0;
        
        // Generate hits and misses
        for i in 0..num_keys {
            // Hit
            let _ = cache.get(&key_ids[i]).await;
            
            // Miss
            let non_existent_id = KeyId::new();
            let _ = cache.get(&non_existent_id).await;
        }
        
        // Check statistics after operations
        let stats_after_ops = cache.get_stats().await
            .expect("Stats after operations should succeed");
        assert_eq!(stats_after_ops.total_keys, num_keys, "Should have all keys");
        assert!(stats_after_ops.cache_hits > 0, "Should have cache hits");
        assert!(stats_after_ops.cache_misses > 0, "Should have cache misses");
        assert!(stats_after_ops.total_requests > 0, "Should have total requests");
        assert!(stats_after_ops.memory_usage_bytes > 0, "Should use memory");
        
        let hit_ratio = stats_after_ops.hit_ratio();
        assert!(hit_ratio > 0.0 && hit_ratio <= 1.0, "Hit ratio should be between 0 and 1");
        
        // Test statistics reset
        cache.reset_stats().await
            .expect("Stats reset should succeed");
        
        let reset_stats = cache.get_stats().await
            .expect("Reset stats should succeed");
        assert_eq!(reset_stats.cache_hits, 0, "Hits should be reset");
        assert_eq!(reset_stats.cache_misses, 0, "Misses should be reset");
        assert_eq!(reset_stats.total_requests, 0, "Requests should be reset");
        
        // Keys should still be cached
        assert_eq!(reset_stats.total_keys, num_keys, "Keys should remain after stats reset");
        assert_eq!(reset_stats.memory_usage_bytes, stats_after_ops.memory_usage_bytes, 
                 "Memory usage should remain after stats reset");
    }

    /// Test cache configuration variations
    #[tokio::test]
    async fn test_cache_configuration_variations() {
        // Test LRU-only configuration
        let mut lru_config = KeyCacheConfig::default();
        lru_config.enable_lru_eviction = true;
        lru_config.enable_time_eviction = false;
        lru_config.max_keys = 5;
        
        let lru_cache = KeyCache::new(lru_config);
        
        // Fill beyond capacity
        let mut lru_key_ids = Vec::new();
        for i in 0..7 {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("lru_config_{}", i));
            
            lru_cache.put(&key_id, &key, &metadata).await
                .expect(&format!("LRU config key {} storage should succeed", i));
            
            lru_key_ids.push(key_id);
        }
        
        let lru_stats = lru_cache.get_stats().await
            .expect("LRU stats should succeed");
        assert_eq!(lru_stats.total_keys, 5, "LRU cache should respect max_keys");
        
        // Test time-only configuration
        let mut time_config = KeyCacheConfig::default();
        time_config.enable_lru_eviction = false;
        time_config.enable_time_eviction = true;
        time_config.eviction_time_seconds = 1;
        time_config.max_keys = 100;
        
        let time_cache = KeyCache::new(time_config);
        
        // Store a key
        let time_key_id = KeyId::new();
        let time_key = create_test_key(32);
        let time_metadata = create_test_metadata("time_config_test");
        
        time_cache.put(&time_key_id, &time_key, &time_metadata).await
            .expect("Time config key storage should succeed");
        
        // Verify it's cached
        let contains_immediately = time_cache.contains(&time_key_id).await
            .expect("Time cache contains should succeed");
        assert!(contains_immediately, "Key should be cached immediately");
        
        // Wait for eviction
        sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Trigger cleanup
        let _ = time_cache.cleanup_expired().await;
        
        // Verify eviction
        let contains_after_ttl = time_cache.contains(&time_key_id).await
            .expect("Time cache contains after TTL should succeed");
        assert!(!contains_after_ttl, "Key should be evicted by time");
        
        // Test disabled eviction
        let mut no_eviction_config = KeyCacheConfig::default();
        no_eviction_config.enable_lru_eviction = false;
        no_eviction_config.enable_time_eviction = false;
        no_eviction_config.max_keys = 3;
        
        let no_eviction_cache = KeyCache::new(no_eviction_config);
        
        // Store keys beyond capacity
        for i in 0..5 {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("no_eviction_{}", i));
            
            no_eviction_cache.put(&key_id, &key, &metadata).await
                .expect(&format!("No eviction key {} storage should succeed", i));
        }
        
        let no_eviction_stats = no_eviction_cache.get_stats().await
            .expect("No eviction stats should succeed");
        // With eviction disabled, cache might grow beyond max_keys
        assert!(no_eviction_stats.total_keys >= 3, "Cache should hold keys without eviction");
    }

    /// Test cache edge cases and error handling
    #[tokio::test]
    async fn test_cache_edge_cases_error_handling() {
        let config = KeyCacheConfig::default();
        let cache = KeyCache::new(config);
        
        // Test operations with non-existent keys
        let non_existent_id = KeyId::new();
        
        let get_result = cache.get(&non_existent_id).await;
        assert!(get_result.is_ok(), "Get non-existent key should not error");
        assert!(get_result.unwrap().is_none(), "Non-existent key should return None");
        
        let contains_result = cache.contains(&non_existent_id).await;
        assert!(contains_result.is_ok(), "Contains non-existent key should not error");
        assert!(!contains_result.unwrap(), "Non-existent key should not be contained");
        
        let remove_result = cache.remove(&non_existent_id).await;
        assert!(remove_result.is_ok(), "Remove non-existent key should not error");
        
        // Test empty cache operations
        cache.clear().await
            .expect("Clear empty cache should succeed");
        
        let empty_stats = cache.get_stats().await
            .expect("Empty cache stats should succeed");
        assert_eq!(empty_stats.total_keys, 0, "Empty cache should have 0 keys");
        
        // Test very large keys
        let large_key_id = KeyId::new();
        let large_key = create_test_key(1024 * 1024); // 1MB key
        let large_metadata = create_test_metadata("large_key");
        
        let large_put_result = cache.put(&large_key_id, &large_key, &large_metadata).await;
        // This might succeed or fail depending on memory limits
        match large_put_result {
            Ok(_) => {
                // If successful, verify retrieval
                let large_get_result = cache.get(&large_key_id).await;
                assert!(large_get_result.is_ok(), "Large key retrieval should not error");
                
                if let Some((retrieved_key, _)) = large_get_result.unwrap() {
                    assert_eq!(retrieved_key.to_vec(), large_key.to_vec(), "Large key should match");
                }
            }
            Err(_) => {
                // If failed due to memory limits, that's acceptable
            }
        }
        
        // Test duplicate key storage (overwrite)
        let duplicate_key_id = KeyId::new();
        let key1 = create_test_key(32);
        let metadata1 = create_test_metadata("duplicate_1");
        
        cache.put(&duplicate_key_id, &key1, &metadata1).await
            .expect("First duplicate key storage should succeed");
        
        let key2 = create_test_key(64);
        let metadata2 = create_test_metadata("duplicate_2");
        
        cache.put(&duplicate_key_id, &key2, &metadata2).await
            .expect("Second duplicate key storage should succeed");
        
        let duplicate_result = cache.get(&duplicate_key_id).await
            .expect("Duplicate key retrieval should succeed");
        assert!(duplicate_result.is_some(), "Duplicate key should be retrievable");
        
        let (retrieved_key, retrieved_metadata) = duplicate_result.unwrap();
        assert_eq!(retrieved_key.to_vec(), key2.to_vec(), "Should get latest key");
        assert_eq!(retrieved_metadata.algorithm, metadata2.algorithm, "Should get latest metadata");
    }
}
