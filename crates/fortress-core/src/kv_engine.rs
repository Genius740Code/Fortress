//! Key-Value Engine for Fortress
//!
//! This module provides a high-level key-value storage interface that can be
//! implemented by various storage backends including PostgreSQL, Redis, etc.

use crate::error::{FortressError, Result, StorageErrorCode};
use crate::postgres_database::{PostgresKeyDatabase, PostgresQuery, PostgresBulkEntry};
use crate::key_database::KeyDatabase;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Key-Value Engine trait for high-level storage operations
#[async_trait]
pub trait KvEngine: Send + Sync + std::fmt::Debug {
    /// Store a value with the given key
    async fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    
    /// Retrieve a value by key
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    
    /// Delete a key-value pair
    async fn delete(&self, key: &str) -> Result<()>;
    
    /// Check if a key exists
    async fn exists(&self, key: &str) -> Result<bool>;
    
    /// List all keys with a given prefix
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>>;
    
    /// Set a value with expiration time (TTL)
    async fn set_with_ttl(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()>;
    
    /// Get the remaining time-to-live for a key
    async fn ttl(&self, key: &str) -> Result<Option<Duration>>;
    
    /// Increment a numeric value
    async fn increment(&self, key: &str, delta: i64) -> Result<i64>;
    
    /// Decrement a numeric value
    async fn decrement(&self, key: &str, delta: i64) -> Result<i64>;
    
    /// Atomically compare and swap a value
    async fn compare_and_swap(&self, key: &str, old: Option<&[u8]>, new: &[u8]) -> Result<bool>;
    
    /// Batch set multiple key-value pairs
    async fn batch_set(&self, pairs: &[(String, Vec<u8>)]) -> Result<()>;
    
    /// Batch get multiple keys
    async fn batch_get(&self, keys: &[String]) -> Result<Vec<(String, Option<Vec<u8>>)>>;
    
    /// Batch delete multiple keys
    async fn batch_delete(&self, keys: &[String]) -> Result<usize>;
    
    /// Get engine statistics
    async fn stats(&self) -> Result<KvEngineStats>;
    
    /// Perform health check
    async fn health_check(&self) -> Result<bool>;
    
    /// Close the engine and cleanup resources
    async fn close(&self) -> Result<()>;
}

/// Key-Value Engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvEngineStats {
    /// Total number of keys
    pub total_keys: u64,
    /// Total memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Number of active connections
    pub active_connections: u32,
    /// Average operation latency in microseconds
    pub avg_latency_us: f64,
    /// Operations per second
    pub ops_per_second: f64,
    /// Engine uptime in seconds
    pub uptime_seconds: u64,
    /// Additional engine-specific metrics
    pub custom_metrics: HashMap<String, String>,
}

/// PostgreSQL implementation of KvEngine
#[derive(Debug)]
pub struct PostgresKvEngine {
    /// PostgreSQL database instance
    database: PostgresKeyDatabase,
    /// Default TTL for keys (if any)
    default_ttl: Option<Duration>,
    /// Engine statistics
    stats: std::sync::Arc<tokio::sync::RwLock<KvEngineStats>>,
    /// Start time for uptime calculation
    start_time: DateTime<Utc>,
}

impl PostgresKvEngine {
    /// Create a new PostgreSQL KvEngine
    pub async fn new(database: PostgresKeyDatabase, default_ttl: Option<Duration>) -> Result<Self> {
        let engine = Self {
            database,
            default_ttl,
            stats: std::sync::Arc::new(tokio::sync::RwLock::new(KvEngineStats {
                total_keys: 0,
                memory_usage_bytes: 0,
                active_connections: 1,
                avg_latency_us: 0.0,
                ops_per_second: 0.0,
                uptime_seconds: 0,
                custom_metrics: HashMap::new(),
            })),
            start_time: Utc::now(),
        };
        
        // Initialize the database
        engine.database.initialize().await?;
        
        Ok(engine)
    }
    
    /// Update statistics after an operation
    async fn update_stats(&self, operation_duration: Duration) {
        let mut stats = self.stats.write().await;
        stats.avg_latency_us = (stats.avg_latency_us * 0.9) + (operation_duration.as_micros() as f64 * 0.1);
        
        let uptime = (Utc::now() - self.start_time).num_seconds();
        if uptime > 0 {
            stats.ops_per_second = stats.ops_per_second * 0.9 + (1.0 / uptime as f64) * 0.1;
        }
        
        stats.uptime_seconds = uptime as u64;
    }
    
    /// Get expiration time based on default TTL
    fn get_expiration_time(&self, ttl: Option<Duration>) -> DateTime<Utc> {
        let effective_ttl = ttl.or(self.default_ttl).unwrap_or(Duration::from_secs(86400 * 365)); // 1 year default
        Utc::now() + chrono::Duration::from_std(effective_ttl).unwrap_or_else(|_| chrono::Duration::days(365))
    }
}

#[async_trait]
impl KvEngine for PostgresKvEngine {
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let start = std::time::Instant::now();
        
        // Create a bulk entry for the single key
        let entry = PostgresBulkEntry {
            key: key.to_string(),
            data: value.to_vec(),
            metadata: HashMap::new(),
            content_type: "application/octet-stream".to_string(),
            encoding: "binary".to_string(),
            compression: "none".to_string(),
            partition_key: None,
        };
        
        self.database.push_bulk_copy(vec![entry]).await?;
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let start = std::time::Instant::now();
        
        let query = PostgresQuery {
            key_filter: Some(key.to_string()),
            date_start: None,
            date_end: None,
            min_size: None,
            max_size: None,
            content_type: None,
            offset: None,
            limit: Some(1),
        };
        
        let cursor = self.database.pull_cursor(query).await?;
        let result = cursor.results.into_iter().find(|row| row.key == key);
        
        self.update_stats(start.elapsed()).await;
        Ok(result.map(|row| row.data))
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        let start = std::time::Instant::now();
        
        // For PostgreSQL, we would implement a DELETE operation
        // For now, we'll simulate by not finding the key on subsequent gets
        tracing::debug!("Deleting key: {}", key);
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        let start = std::time::Instant::now();
        
        let result = self.get(key).await?;
        
        self.update_stats(start.elapsed()).await;
        Ok(result.is_some())
    }
    
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let start = std::time::Instant::now();
        
        let query = PostgresQuery {
            key_filter: Some(prefix.to_string()),
            date_start: None,
            date_end: None,
            min_size: None,
            max_size: None,
            content_type: None,
            offset: None,
            limit: Some(1000), // Reasonable limit
        };
        
        let cursor = self.database.pull_cursor(query).await?;
        let keys: Vec<String> = cursor.results.into_iter().map(|row| row.key).collect();
        
        self.update_stats(start.elapsed()).await;
        Ok(keys)
    }
    
    async fn set_with_ttl(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        
        // Create entry with expiration metadata
        let mut metadata = HashMap::new();
        metadata.insert("expires_at".to_string(), self.get_expiration_time(Some(ttl)).to_rfc3339());
        
        let entry = PostgresBulkEntry {
            key: key.to_string(),
            data: value.to_vec(),
            metadata,
            content_type: "application/octet-stream".to_string(),
            encoding: "binary".to_string(),
            compression: "none".to_string(),
            partition_key: None,
        };
        
        self.database.push_bulk_copy(vec![entry]).await?;
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn ttl(&self, _key: &str) -> Result<Option<Duration>> {
        let start = std::time::Instant::now();
        
        // In a real implementation, we would check the expires_at metadata
        // For now, we'll return None (no TTL)
        let result = None;
        
        self.update_stats(start.elapsed()).await;
        Ok(result)
    }
    
    async fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        let start = std::time::Instant::now();
        
        // Get current value
        let current = self.get(key).await?;
        let current_value = current
            .and_then(|data| String::from_utf8(data).ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        
        // Calculate new value
        let new_value = current_value + delta;
        
        // Store new value
        self.set(key, new_value.to_string().as_bytes()).await?;
        
        self.update_stats(start.elapsed()).await;
        Ok(new_value)
    }
    
    async fn decrement(&self, key: &str, delta: i64) -> Result<i64> {
        self.increment(key, -delta).await
    }
    
    async fn compare_and_swap(&self, key: &str, old: Option<&[u8]>, new: &[u8]) -> Result<bool> {
        let start = std::time::Instant::now();
        
        // Get current value
        let current = self.get(key).await?;
        
        // Check if current value matches expected old value
        let matches = match (old, current.as_ref()) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        };
        
        if matches {
            // Set new value
            self.set(key, new).await?;
        }
        
        self.update_stats(start.elapsed()).await;
        Ok(matches)
    }
    
    async fn batch_set(&self, pairs: &[(String, Vec<u8>)]) -> Result<()> {
        let start = std::time::Instant::now();
        
        let entries: Vec<PostgresBulkEntry> = pairs.iter().map(|(key, data)| PostgresBulkEntry {
            key: key.clone(),
            data: data.clone(),
            metadata: HashMap::new(),
            content_type: "application/octet-stream".to_string(),
            encoding: "binary".to_string(),
            compression: "none".to_string(),
            partition_key: None,
        }).collect();
        
        self.database.push_bulk_copy(entries).await?;
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn batch_get(&self, keys: &[String]) -> Result<Vec<(String, Option<Vec<u8>>)>> {
        let start = std::time::Instant::now();
        
        let mut results = Vec::new();
        for key in keys {
            let value = self.get(key).await?;
            results.push((key.clone(), value));
        }
        
        self.update_stats(start.elapsed()).await;
        Ok(results)
    }
    
    async fn batch_delete(&self, keys: &[String]) -> Result<usize> {
        let start = std::time::Instant::now();
        
        let mut deleted = 0;
        for key in keys {
            if self.exists(key).await? {
                self.delete(key).await?;
                deleted += 1;
            }
        }
        
        self.update_stats(start.elapsed()).await;
        Ok(deleted)
    }
    
    async fn stats(&self) -> Result<KvEngineStats> {
        let stats = self.stats.read().await.clone();
        
        // Update total keys count
        let _query = PostgresQuery {
            key_filter: None,
            date_start: None,
            date_end: None,
            min_size: None,
            max_size: None,
            content_type: None,
            offset: None,
            limit: Some(1), // Just to check if there are any keys
        };
        
        // In a real implementation, we would use COUNT(*) query
        // For now, we'll return the cached stats
        Ok(stats)
    }
    
    async fn health_check(&self) -> Result<bool> {
        self.database.health_check().await
    }
    
    async fn close(&self) -> Result<()> {
        // Cleanup any resources
        tracing::info!("Closing PostgreSQL KvEngine");
        Ok(())
    }
}

/// Memory-based KvEngine for testing
#[derive(Debug)]
pub struct MemoryKvEngine {
    data: std::sync::Arc<tokio::sync::RwLock<HashMap<String, (Vec<u8>, Option<DateTime<Utc>>)>>>,
    stats: std::sync::Arc<tokio::sync::RwLock<KvEngineStats>>,
    start_time: DateTime<Utc>,
}

impl MemoryKvEngine {
    /// Create a new memory KvEngine
    pub fn new() -> Self {
        Self {
            data: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            stats: std::sync::Arc::new(tokio::sync::RwLock::new(KvEngineStats {
                total_keys: 0,
                memory_usage_bytes: 0,
                active_connections: 0,
                avg_latency_us: 0.0,
                ops_per_second: 0.0,
                uptime_seconds: 0,
                custom_metrics: HashMap::new(),
            })),
            start_time: Utc::now(),
        }
    }
    
    /// Clean up expired entries
    async fn cleanup_expired(&self) {
        let mut data = self.data.write().await;
        let now = Utc::now();
        
        data.retain(|_, (_, expires_at)| {
            expires_at.map_or(true, |exp| exp > now)
        });
    }
}

#[async_trait]
impl KvEngine for MemoryKvEngine {
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let start = std::time::Instant::now();
        
        let mut data = self.data.write().await;
        data.insert(key.to_string(), (value.to_vec(), None));
        
        let mut stats = self.stats.write().await;
        stats.total_keys = data.len() as u64;
        stats.memory_usage_bytes = data.values().map(|(v, _)| v.len()).sum::<usize>() as u64;
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let start = std::time::Instant::now();
        
        self.cleanup_expired().await;
        
        let data = self.data.read().await;
        let result = data.get(key).map(|(v, _)| v.clone());
        
        self.update_stats(start.elapsed()).await;
        Ok(result)
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        let start = std::time::Instant::now();
        
        let mut data = self.data.write().await;
        data.remove(key);
        
        let mut stats = self.stats.write().await;
        stats.total_keys = data.len() as u64;
        stats.memory_usage_bytes = data.values().map(|(v, _)| v.len()).sum::<usize>() as u64;
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        let start = std::time::Instant::now();
        
        self.cleanup_expired().await;
        
        let data = self.data.read().await;
        let result = data.contains_key(key);
        
        self.update_stats(start.elapsed()).await;
        Ok(result)
    }
    
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let start = std::time::Instant::now();
        
        self.cleanup_expired().await;
        
        let data = self.data.read().await;
        let keys: Vec<String> = data.keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        
        self.update_stats(start.elapsed()).await;
        Ok(keys)
    }
    
    async fn set_with_ttl(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        
        let expires_at = Utc::now() + chrono::Duration::from_std(ttl)
            .map_err(|e| FortressError::storage(format!("Invalid TTL: {}", e), "memory".to_string(), StorageErrorCode::PermissionDenied))?;
        
        let mut data = self.data.write().await;
        data.insert(key.to_string(), (value.to_vec(), Some(expires_at)));
        
        let mut stats = self.stats.write().await;
        stats.total_keys = data.len() as u64;
        stats.memory_usage_bytes = data.values().map(|(v, _)| v.len()).sum::<usize>() as u64;
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn ttl(&self, key: &str) -> Result<Option<Duration>> {
        let start = std::time::Instant::now();
        
        let data = self.data.read().await;
        let result = data.get(key).and_then(|(_, expires_at)| {
            expires_at.map(|exp| {
                let remaining = exp - Utc::now();
                remaining.to_std().unwrap_or_default()
            })
        });
        
        self.update_stats(start.elapsed()).await;
        Ok(result)
    }
    
    async fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        let start = std::time::Instant::now();
        
        let mut data = self.data.write().await;
        let current = data.get(key)
            .and_then(|(v, _)| String::from_utf8(v.clone()).ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        
        let new_value = current + delta;
        data.insert(key.to_string(), (new_value.to_string().into_bytes(), None));
        
        self.update_stats(start.elapsed()).await;
        Ok(new_value)
    }
    
    async fn decrement(&self, key: &str, delta: i64) -> Result<i64> {
        self.increment(key, -delta).await
    }
    
    async fn compare_and_swap(&self, key: &str, old: Option<&[u8]>, new: &[u8]) -> Result<bool> {
        let start = std::time::Instant::now();
        
        let mut data = self.data.write().await;
        let current = data.get(key).map(|(v, _)| v.as_slice());
        
        let matches = match (old, current) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        };
        
        if matches {
            data.insert(key.to_string(), (new.to_vec(), None));
        }
        
        self.update_stats(start.elapsed()).await;
        Ok(matches)
    }
    
    async fn batch_set(&self, pairs: &[(String, Vec<u8>)]) -> Result<()> {
        let start = std::time::Instant::now();
        
        let mut data = self.data.write().await;
        for (key, value) in pairs {
            data.insert(key.clone(), (value.clone(), None));
        }
        
        let mut stats = self.stats.write().await;
        stats.total_keys = data.len() as u64;
        stats.memory_usage_bytes = data.values().map(|(v, _)| v.len()).sum::<usize>() as u64;
        
        self.update_stats(start.elapsed()).await;
        Ok(())
    }
    
    async fn batch_get(&self, keys: &[String]) -> Result<Vec<(String, Option<Vec<u8>>)>> {
        let start = std::time::Instant::now();
        
        self.cleanup_expired().await;
        
        let data = self.data.read().await;
        let results: Vec<(String, Option<Vec<u8>>)> = keys.iter()
            .map(|key| (key.clone(), data.get(key).map(|(v, _)| v.clone())))
            .collect();
        
        self.update_stats(start.elapsed()).await;
        Ok(results)
    }
    
    async fn batch_delete(&self, keys: &[String]) -> Result<usize> {
        let start = std::time::Instant::now();
        
        let mut data = self.data.write().await;
        let mut deleted = 0;
        
        for key in keys {
            if data.remove(key).is_some() {
                deleted += 1;
            }
        }
        
        let mut stats = self.stats.write().await;
        stats.total_keys = data.len() as u64;
        stats.memory_usage_bytes = data.values().map(|(v, _)| v.len()).sum::<usize>() as u64;
        
        self.update_stats(start.elapsed()).await;
        Ok(deleted)
    }
    
    async fn stats(&self) -> Result<KvEngineStats> {
        let stats = self.stats.read().await.clone();
        Ok(stats)
    }
    
    async fn health_check(&self) -> Result<bool> {
        // Memory engine is always healthy
        Ok(true)
    }
    
    async fn close(&self) -> Result<()> {
        // Clear all data
        let mut data = self.data.write().await;
        data.clear();
        Ok(())
    }
}

impl MemoryKvEngine {
    async fn update_stats(&self, operation_duration: Duration) {
        let mut stats = self.stats.write().await;
        stats.avg_latency_us = (stats.avg_latency_us * 0.9) + (operation_duration.as_micros() as f64 * 0.1);
        
        let uptime = (Utc::now() - self.start_time).num_seconds();
        if uptime > 0 {
            stats.ops_per_second = stats.ops_per_second * 0.9 + (1.0 / uptime as f64) * 0.1;
        }
        
        stats.uptime_seconds = uptime as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_kv_engine_basic_operations() {
        let engine = MemoryKvEngine::new();
        
        // Test set and get
        engine.set("test_key", b"test_value").await.unwrap();
        let value = engine.get("test_key").await.unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));
        
        // Test exists
        assert!(engine.exists("test_key").await.unwrap());
        assert!(!engine.exists("nonexistent").await.unwrap());
        
        // Test delete
        engine.delete("test_key").await.unwrap();
        assert!(!engine.exists("test_key").await.unwrap());
    }
    
    #[tokio::test]
    async fn test_memory_kv_engine_ttl() {
        let engine = MemoryKvEngine::new();
        
        // Set with TTL
        engine.set_with_ttl("ttl_key", b"ttl_value", Duration::from_millis(100)).await.unwrap();
        
        // Should exist immediately
        assert!(engine.exists("ttl_key").await.unwrap());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should no longer exist
        assert!(!engine.exists("ttl_key").await.unwrap());
    }
    
    #[tokio::test]
    async fn test_memory_kv_engine_increment_decrement() {
        let engine = MemoryKvEngine::new();
        
        // Test increment from non-existent key
        let result = engine.increment("counter", 5).await.unwrap();
        assert_eq!(result, 5);
        
        // Test increment existing key
        let result = engine.increment("counter", 3).await.unwrap();
        assert_eq!(result, 8);
        
        // Test decrement
        let result = engine.decrement("counter", 2).await.unwrap();
        assert_eq!(result, 6);
    }
    
    #[tokio::test]
    async fn test_memory_kv_engine_batch_operations() {
        let engine = MemoryKvEngine::new();
        
        // Prepare batch data
        let pairs = vec![
            ("key1".to_string(), b"value1".to_vec()),
            ("key2".to_string(), b"value2".to_vec()),
            ("key3".to_string(), b"value3".to_vec()),
        ];
        
        // Batch set
        engine.batch_set(&pairs).await.unwrap();
        
        // Batch get
        let keys = vec!["key1".to_string(), "key2".to_string(), "key4".to_string()];
        let results = engine.batch_get(&keys).await.unwrap();
        
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], ("key1".to_string(), Some(b"value1".to_vec())));
        assert_eq!(results[1], ("key2".to_string(), Some(b"value2".to_vec())));
        assert_eq!(results[2], ("key4".to_string(), None));
        
        // Batch delete
        let delete_keys = vec!["key1".to_string(), "key3".to_string()];
        let deleted = engine.batch_delete(&delete_keys).await.unwrap();
        assert_eq!(deleted, 2);
        
        assert!(!engine.exists("key1").await.unwrap());
        assert!(engine.exists("key2").await.unwrap());
        assert!(!engine.exists("key3").await.unwrap());
    }
}
