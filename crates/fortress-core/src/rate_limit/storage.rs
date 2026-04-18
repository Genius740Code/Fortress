//! Rate Limiting Storage Backends
//! 
//! This module provides storage implementations for rate limiting
//! including memory, Redis, and database backends.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use crate::error::{FortressError, Result};
use crate::rate_limit::{RateLimitAlgorithm, RateLimitRule, RateLimitResult, RateLimitContext};
use async_trait::async_trait;

/// In-memory storage implementation
pub struct MemoryStorage {
    counters: Arc<RwLock<HashMap<String, CounterEntry>>>,
}

/// Counter entry for in-memory storage
#[derive(Debug, Clone)]
struct CounterEntry {
    value: u64,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    ttl: Option<Duration>,
}

impl MemoryStorage {
    /// Create a new memory storage
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate storage key
    fn generate_key(&self, key: &str, rule_name: &str) -> String {
        format!("{}:{}", rule_name, key)
    }

    /// Cleanup expired entries
    async fn cleanup_expired(&self) {
        let mut counters = self.counters.write().await;
        let now = Utc::now();
        
        counters.retain(|_, entry| {
            if let Some(expires_at) = entry.expires_at {
                expires_at > now
            } else {
                true
            }
        });
    }
}

#[async_trait::async_trait]
impl RateLimitStorage for MemoryStorage {
    fn name(&self) -> &str {
        "memory"
    }

    async fn get_counter(&self, key: &str, rule_name: &str) -> Result<Option<u64>> {
        let storage_key = self.generate_key(key, rule_name);
        let counters = self.counters.read().await;
        
        Ok(counters.get(&storage_key).map(|entry| entry.value))
    }

    async fn set_counter(&self, key: str, rule_name: str, value: u64, ttl: Option<Duration>) -> Result<()> {
        let storage_key = self.generate_key(&key, &rule_name);
        let mut counters = self.counters.write().await;
        
        let now = Utc::now();
        let expires_at = ttl.map(|duration| now + duration);
        
        counters.insert(storage_key, CounterEntry {
            value,
            created_at: now,
            expires_at,
            ttl,
        });
        
        Ok(())
    }

    async fn increment_counter(&self, key: str, rule_name: str, amount: u64, ttl: Option<Duration>) -> Result<u64> {
        let storage_key = self.generate_key(&key, &rule_name);
        let mut counters = self.counters.write().await;
        
        let now = Utc::now();
        let expires_at = ttl.map(|duration| now + duration);
        
        let entry = counters.entry(storage_key).or_insert_with(|| CounterEntry {
            value: 0,
            created_at: now,
            expires_at,
            ttl,
        });
        
        entry.value += amount;
        
        // Update TTL if provided
        if ttl.is_some() {
            entry.ttl = ttl;
            entry.expires_at = expires_at;
        }
        
        Ok(entry.value)
    }

    async fn decrement_counter(&self, key: str, rule_name: str, amount: u64) -> Result<u64> {
        let storage_key = self.generate_key(&key, &rule_name);
        let mut counters = self.counters.write().await;
        
        if let Some(entry) = counters.get_mut(&storage_key) {
            entry.value = entry.value.saturating_sub(amount);
            Ok(entry.value)
        } else {
            Ok(0)
        }
    }

    async fn delete_counter(&self, key: &str, rule_name: &str) -> Result<()> {
        let storage_key = self.generate_key(key, rule_name);
        let mut counters = self.counters.write().await;
        
        counters.remove(&storage_key);
        Ok(())
    }

    async fn get_keys(&self, rule_name: &str) -> Result<Vec<String>> {
        let counters = self.counters.read().await;
        let prefix = format!("{}:", rule_name);
        
        let keys: Vec<String> = counters.keys()
            .filter(|key| key.starts_with(&prefix))
            .map(|key| key.strip_prefix(&prefix).unwrap_or(key).to_string())
            .collect();
        
        Ok(keys)
    }

    async fn cleanup(&self) -> Result<()> {
        self.cleanup_expired().await;
        Ok(())
    }
}

/// Redis storage implementation (temporarily disabled)
#[cfg(feature = "redis")]
pub struct RedisStorage {
    client: Option<Arc<redis::Client>>,
    key_prefix: String,
    default_ttl: Duration,
}

impl RedisStorage {
    /// Create a new Redis storage
    pub fn new() -> Self {
        let client = redis::Client::open("redis://localhost:6379")
            .ok()
            .map(Arc::new);
        
        Self {
            client,
            key_prefix: "fortress:rate_limit".to_string(),
            default_ttl: Duration::hours(24),
        }
    }

    /// Create Redis storage with custom configuration
    pub fn with_config(redis_url: &str, key_prefix: String, default_ttl: Duration) -> Self {
        let client = redis::Client::open(redis_url)
            .ok()
            .map(Arc::new);
        
        Self {
            client,
            key_prefix,
            default_ttl,
        }
    }

    /// Generate storage key with prefix
    fn generate_key(&self, key: &str, rule_name: &str) -> String {
        format!("{}:{}:{}", self.key_prefix, rule_name, key)
    }

    /// Get Redis connection
    async fn get_connection(&self) -> Result<Option<redis::aio::Connection>> {
        match &self.client {
            Some(client) => {
                let conn = client.get_async_connection()
                    .await
                    .map_err(|e| FortressError::rate_limit(format!("Failed to get Redis connection: {}", e)))?;
                Ok(Some(conn))
            }
            None => Ok(None)
        }
    }
}

#[async_trait::async_trait]
impl RateLimitStorage for RedisStorage {
    fn name(&self) -> &str {
        "redis"
    }

    async fn get_counter(&self, key: &str, rule_name: &str) -> Result<Option<u64>> {
        let storage_key = self.generate_key(key, rule_name);
        let mut conn = match self.get_connection().await? {
            Some(conn) => conn,
            None => return Ok(None),
        };
        
        let value: Option<u64> = redis::cmd("GET")
            .arg(&storage_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| FortressError::rate_limit(format!("Redis GET failed: {}", e)))?;
        
        Ok(value)
    }

    async fn set_counter(&self, key: str, rule_name: str, value: u64, ttl: Option<Duration>) -> Result<()> {
        let storage_key = self.generate_key(&key, &rule_name);
        let mut conn = match self.get_connection().await? {
            Some(conn) => conn,
            None => return Ok(()),
        };
        
        let now = Utc::now();
        let expires_at = ttl.map(|duration| now + duration);
        
        redis::cmd("SET")
            .arg(&storage_key)
            .arg(value)
            .arg("EXAT")
            .arg(expires_at.unwrap_or_else(|| now + Duration::hours(24)))
            .query_async(&mut conn)
            .await
            .map_err(|e| FortressError::rate_limit(format!("Redis SET failed: {}", e)))?;
        
        Ok(())
    }

    async fn increment_counter(&self, key: str, rule_name: str, amount: u64, ttl: Option<Duration>) -> Result<u64> {
        let storage_key = self.generate_key(&key, &rule_name);
        let mut conn = match self.get_connection().await? {
            Some(conn) => conn,
            None => return Ok(0),
        };
        
        let now = Utc::now();
        let expires_at = ttl.map(|duration| now + duration);
        
        let entry = conn.entry(storage_key).or_insert_with(|| CounterEntry {
            value: 0,
            created_at: now,
            expires_at,
            ttl,
        });
        
        entry.value += amount;
        
        // Update TTL if provided
        if ttl.is_some() {
            entry.ttl = ttl;
            entry.expires_at = expires_at;
        }
        
        Ok(entry.value)
    }

    async fn decrement_counter(&self, key: str, rule_name: str, amount: u64) -> Result<u64> {
        let storage_key = self.generate_key(&key, &rule_name);
        let mut conn = match self.get_connection().await? {
            Some(conn) => conn,
            None => return Ok(0),
        };
        
        if let Some(entry) = conn.get_mut(&storage_key) {
            entry.value = entry.value.saturating_sub(amount);
            Ok(entry.value)
        } else {
            Ok(0)
        }
    }

    async fn delete_counter(&self, key: &str, rule_name: &str) -> Result<()> {
        let storage_key = self.generate_key(key, rule_name);
        let mut conn = match self.get_connection().await? {
            Some(conn) => conn,
            None => return Ok(()),
        };
        
        conn.del(&storage_key).await
            .map_err(|e| FortressError::rate_limit(format!("Redis DEL failed: {}", e)))?;
        
        Ok(())
    }

    async fn get_keys(&self, rule_name: &str) -> Result<Vec<String>> {
        let conn = match self.get_connection().await? {
            Some(conn) => conn,
            None => return Ok(Vec::new()),
        };
        
        let prefix = format!("{}:", rule_name);
        
        let keys: Vec<String> = conn.keys(&prefix).await
            .map_err(|e| FortressError::rate_limit(format!("Redis KEYS failed: {}", e)))?;
        
        Ok(keys)
    }

    async fn cleanup(&self) -> Result<()> {
        // Redis handles TTL cleanup automatically
        Ok(())
    }
}

/// Database storage implementation (placeholder)
pub struct DatabaseStorage {
    // Database connection pool would go here
    connection_string: String,
    table_name: String,
}

impl DatabaseStorage {
    /// Create a new database storage
    pub fn new() -> Self {
        Self {
            connection_string: "postgresql://localhost/fortress".to_string(),
            table_name: "rate_limit_counters".to_string(),
        }
    }

    /// Create database storage with custom configuration
    pub fn with_config(connection_string: String, table_name: String) -> Self {
        Self {
            connection_string,
            table_name,
        }
    }

    /// Generate storage key
    fn generate_key(&self, key: &str, rule_name: &str) -> String {
        format!("{}:{}", rule_name, key)
    }
}

#[async_trait::async_trait]
impl RateLimitStorage for DatabaseStorage {
    fn name(&self) -> &str {
        "database"
    }

    async fn get_counter(&self, key: &str, rule_name: &str) -> Result<Option<u64>> {
        // Placeholder implementation - would use actual database queries
        tracing::warn!("Database storage not implemented yet");
        Ok(None)
    }

    async fn set_counter(&self, key: str, rule_name: str, value: u64, ttl: Option<Duration>) -> Result<()> {
        // Placeholder implementation - would use actual database queries
        tracing::warn!("Database storage not implemented yet");
        Ok(())
    }

    async fn increment_counter(&self, key: str, rule_name: str, amount: u64, ttl: Option<Duration>) -> Result<u64> {
        // Placeholder implementation - would use actual database queries
        tracing::warn!("Database storage not implemented yet");
        Ok(0)
    }

    async fn decrement_counter(&self, key: str, rule_name: str, amount: u64) -> Result<u64> {
        // Placeholder implementation - would use actual database queries
        tracing::warn!("Database storage not implemented yet");
        Ok(0)
    }

    async fn delete_counter(&self, _key: &str, _rule_name: &str) -> Result<()> {
        // Placeholder implementation - would use actual database queries
        tracing::warn!("Database storage not implemented yet");
        Ok(())
    }

    async fn get_keys(&self, _rule_name: &str) -> Result<Vec<String>> {
        // Placeholder implementation - would use actual database queries
        tracing::warn!("Database storage not implemented yet");
        Ok(Vec::new())
    }

    async fn cleanup(&self) -> Result<()> {
        // Placeholder implementation - would clean up expired entries
        tracing::warn!("Database storage not implemented yet");
        Ok(())
    }
}

/// Distributed storage implementation (placeholder)
pub struct DistributedStorage {
    // Distributed cache configuration would go here
    nodes: Vec<String>,
    replication_factor: u32,
}

impl DistributedStorage {
    /// Create a new distributed storage
    pub fn new() -> Self {
        Self {
            nodes: vec!["localhost:6379".to_string()],
            replication_factor: 2,
        }
    }

    /// Create distributed storage with custom configuration
    pub fn with_config(nodes: Vec<String>, replication_factor: u32) -> Self {
        Self {
            nodes,
            replication_factor,
        }
    }

    /// Generate storage key
    fn generate_key(&self, key: &str, rule_name: &str) -> String {
        format!("{}:{}", rule_name, key)
    }

    /// Get node for key using consistent hashing
    fn get_node_for_key(&self, key: &str) -> &str {
        // Simple hash-based selection - would use consistent hashing in production
        let hash = key.chars().map(|c| c as u32).sum::<u32>();
        let node_index = hash % self.nodes.len() as u32;
        &self.nodes[node_index as usize]
    }
}

#[async_trait::async_trait]
impl RateLimitStorage for DistributedStorage {
    fn name(&self) -> &str {
        "distributed"
    }

    async fn get_counter(&self, key: &str, rule_name: &str) -> Result<Option<u64>> {
        // Placeholder implementation - would use distributed cache
        tracing::warn!("Distributed storage not implemented yet");
        Ok(None)
    }

    async fn set_counter(&self, key: str, rule_name: str, value: u64, ttl: Option<Duration>) -> Result<()> {
        // Placeholder implementation - would use distributed cache
        tracing::warn!("Distributed storage not implemented yet");
        Ok(())
    }

    async fn increment_counter(&self, key: str, rule_name: str, amount: u64, ttl: Option<Duration>) -> Result<u64> {
        // Placeholder implementation - would use distributed cache
        tracing::warn!("Distributed storage not implemented yet");
        Ok(0)
    }

    async fn decrement_counter(&self, key: str, rule_name: str, amount: u64) -> Result<u64> {
        // Placeholder implementation - would use distributed cache
        tracing::warn!("Distributed storage not implemented yet");
        Ok(0)
    }

    async fn delete_counter(&self, key: &str, rule_name: &str) -> Result<()> {
        // Placeholder implementation - would use distributed cache
        tracing::warn!("Distributed storage not implemented yet");
        Ok(())
    }

    async fn get_keys(&self, rule_name: &str) -> Result<Vec<String>> {
        // Placeholder implementation - would use distributed cache
        tracing::warn!("Distributed storage not implemented yet");
        Ok(Vec::new())
    }

    async fn cleanup(&self) -> Result<()> {
        // Placeholder implementation - would clean up expired entries
        tracing::warn!("Distributed storage not implemented yet");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::new();
        
        // Test set and get
        storage.set_counter("test_key", "test_rule", 10, None).await.unwrap();
        let value = storage.get_counter("test_key", "test_rule").await.unwrap();
        assert_eq!(value, Some(10));
        
        // Test increment
        let new_value = storage.increment_counter("test_key", "test_rule", 5, None).await.unwrap();
        assert_eq!(new_value, 15);
        
        let value = storage.get_counter("test_key", "test_rule").await.unwrap();
        assert_eq!(value, Some(15));
        
        // Test decrement
        let new_value = storage.decrement_counter("test_key", "test_rule", 3).await.unwrap();
        assert_eq!(new_value, 12);
        
        // Test delete
        storage.delete_counter("test_key", "test_rule").await.unwrap();
        let value = storage.get_counter("test_key", "test_rule").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_memory_storage_ttl() {
        let storage = MemoryStorage::new();
        
        // Set with TTL
        storage.set_counter("test_key", "test_rule", 10, Some(Duration::seconds(1))).await.unwrap();
        
        // Should exist immediately
        let value = storage.get_counter("test_key", "test_rule").await.unwrap();
        assert_eq!(value, Some(10));
        
        // Wait for expiration
        tokio::time::sleep(Duration::seconds(2)).await;
        
        // Cleanup expired entries
        storage.cleanup().await.unwrap();
        
        // Should be gone after cleanup
        let value = storage.get_counter("test_key", "test_rule").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_memory_storage_get_keys() {
        let storage = MemoryStorage::new();
        
        // Add multiple counters
        storage.set_counter("key1", "test_rule", 10, None).await.unwrap();
        storage.set_counter("key2", "test_rule", 20, None).await.unwrap();
        storage.set_counter("key3", "other_rule", 30, None).await.unwrap();
        
        // Get keys for test_rule
        let keys = storage.get_keys("test_rule").await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(!keys.contains(&"key3".to_string()));
    }

    #[tokio::test]
    async fn test_redis_storage_creation() {
        let storage = RedisStorage::new();
        assert_eq!(storage.name(), "redis");
        assert_eq!(storage.key_prefix, "fortress:rate_limit");
    }

    #[tokio::test]
    async fn test_redis_storage_with_config() {
        let storage = RedisStorage::with_config(
            "redis://localhost:6379".to_string(),
            "custom:prefix".to_string(),
            Duration::hours(12)
        );
        assert_eq!(storage.name(), "redis");
        assert_eq!(storage.key_prefix, "custom:prefix");
        assert_eq!(storage.default_ttl, Duration::hours(12));
    }

    #[tokio::test]
    async fn test_database_storage_creation() {
        let storage = DatabaseStorage::new();
        assert_eq!(storage.name(), "database");
        assert_eq!(storage.connection_string, "postgresql://localhost/fortress");
        assert_eq!(storage.table_name, "rate_limit_counters");
    }

    #[tokio::test]
    async fn test_distributed_storage_creation() {
        let storage = DistributedStorage::new();
        assert_eq!(storage.name(), "distributed");
        assert_eq!(storage.nodes, vec!["localhost:6379".to_string()]);
        assert_eq!(storage.replication_factor, 2);
    }

    #[tokio::test]
    async fn test_distributed_storage_with_config() {
        let nodes = vec![
            "node1:6379".to_string(),
            "node2:6379".to_string(),
            "node3:6379".to_string(),
        ];
        let storage = DistributedStorage::with_config(nodes, 3);
        assert_eq!(storage.name(), "distributed");
        assert_eq!(storage.nodes.len(), 3);
        assert_eq!(storage.replication_factor, 3);
    }

    #[tokio::test]
    async fn test_storage_key_generation() {
        let memory_storage = MemoryStorage::new();
        let redis_storage = RedisStorage::new();
        let db_storage = DatabaseStorage::new();
        let distributed_storage = DistributedStorage::new();
        
        // Test key generation
        let key = "test_key";
        let rule_name = "test_rule";
        
        assert_eq!(memory_storage.generate_key(key, rule_name), "test_rule:test_key");
        assert_eq!(redis_storage.generate_key(key, rule_name), "fortress:rate_limit:test_rule:test_key");
        assert_eq!(db_storage.generate_key(key, rule_name), "test_rule:test_key");
        assert_eq!(distributed_storage.generate_key(key, rule_name), "test_rule:test_key");
    }
}
