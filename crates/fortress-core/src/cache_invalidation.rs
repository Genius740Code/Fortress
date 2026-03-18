//! Advanced cache invalidation strategies for Fortress
//!
//! This module provides intelligent cache invalidation with support for
//! dependency tracking, event-driven invalidation, and distributed invalidation.

use crate::error::{FortressError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use chrono::{DateTime, Utc, Duration};

/// Invalidation reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvalidationReason {
    /// Manual invalidation
    Manual,
    /// TTL expiration
    TTLExpired,
    /// Key rotation
    KeyRotation,
    /// Data updated
    DataUpdated,
    /// Dependency invalidated
    DependencyInvalidated,
    /// Memory pressure
    MemoryPressure,
    /// Cache size limit
    SizeLimit,
    /// Security policy
    SecurityPolicy,
}

/// Invalidation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationEvent {
    /// Cache key that was invalidated
    pub key: String,
    /// Reason for invalidation
    pub reason: InvalidationReason,
    /// Timestamp of invalidation
    pub timestamp: DateTime<Utc>,
    /// Optional metadata
    pub metadata: HashMap<String, String>,
    /// Source of invalidation (node ID, service, etc.)
    pub source: String,
}

/// Cache dependency graph
#[derive(Debug, Clone)]
pub struct CacheDependency {
    /// Keys that depend on this key
    pub dependents: HashSet<String>,
    /// Keys this key depends on
    pub dependencies: HashSet<String>,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// Invalidation strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationConfig {
    /// Enable automatic dependency tracking
    pub enable_dependency_tracking: bool,
    /// Enable event-driven invalidation
    pub enable_event_driven: bool,
    /// Enable distributed invalidation
    pub enable_distributed: bool,
    /// Maximum dependency depth
    pub max_dependency_depth: usize,
    /// Invalidation batch size
    pub batch_size: usize,
    /// Invalidation timeout in seconds
    pub timeout_seconds: u64,
    /// Retry attempts for failed invalidations
    pub max_retries: u32,
    /// Enable invalidation logging
    pub enable_logging: bool,
    /// Grace period for cascading invalidations (ms)
    pub grace_period_ms: u64,
}

impl Default for InvalidationConfig {
    fn default() -> Self {
        Self {
            enable_dependency_tracking: true,
            enable_event_driven: true,
            enable_distributed: false,
            max_dependency_depth: 10,
            batch_size: 100,
            timeout_seconds: 30,
            max_retries: 3,
            enable_logging: true,
            grace_period_ms: 100,
        }
    }
}

/// Trait for cache invalidation strategies
#[async_trait]
pub trait CacheInvalidation: Send + Sync + std::fmt::Debug {
    /// Invalidate a specific key
    async fn invalidate_key(&self, key: &str, reason: InvalidationReason) -> Result<()>;

    /// Invalidate multiple keys
    async fn invalidate_keys(&self, keys: &[String], reason: InvalidationReason) -> Result<()>;

    /// Invalidate all keys matching a pattern
    async fn invalidate_pattern(&self, pattern: &str, reason: InvalidationReason) -> Result<usize>;

    /// Invalidate keys by tag
    async fn invalidate_by_tag(&self, tag: &str, reason: InvalidationReason) -> Result<usize>;

    /// Add dependency between keys
    async fn add_dependency(&self, key: &str, depends_on: &str) -> Result<()>;

    /// Remove dependency between keys
    async fn remove_dependency(&self, key: &str, depends_on: &str) -> Result<()>;

    /// Add tags to a key
    async fn add_tags(&self, key: &str, tags: &[String]) -> Result<()>;

    /// Remove tags from a key
    async fn remove_tags(&self, key: &str, tags: &[String]) -> Result<()>;

    /// Get invalidation statistics
    async fn get_invalidation_stats(&self) -> Result<InvalidationStats>;

    /// Subscribe to invalidation events
    async fn subscribe_events(&self) -> broadcast::Receiver<InvalidationEvent>;
}

/// Invalidation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationStats {
    /// Total invalidations
    pub total_invalidations: u64,
    /// Invalidations by reason
    pub invalidations_by_reason: HashMap<String, u64>,
    /// Average invalidation time in microseconds
    pub avg_invalidation_time_us: f64,
    /// Failed invalidations
    pub failed_invalidations: u64,
    /// Cascaded invalidations
    pub cascaded_invalidations: u64,
    /// Dependencies tracked
    pub dependencies_tracked: usize,
    /// Last invalidation time
    pub last_invalidation: Option<DateTime<Utc>>,
}

/// Advanced cache invalidation manager
#[derive(Debug)]
pub struct CacheInvalidationManager {
    config: InvalidationConfig,
    /// Dependency graph
    dependencies: Arc<RwLock<HashMap<String, CacheDependency>>>,
    /// Key to tags mapping
    key_tags: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Tag to keys mapping
    tag_keys: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Invalidation statistics
    stats: Arc<RwLock<InvalidationStats>>,
    /// Event broadcaster
    event_sender: broadcast::Sender<InvalidationEvent>,
    /// Invalidation history
    history: Arc<RwLock<Vec<InvalidationEvent>>>,
}

impl CacheInvalidationManager {
    /// Create a new invalidation manager
    pub fn new(config: InvalidationConfig) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        
        Self {
            config,
            dependencies: Arc::new(RwLock::new(HashMap::new())),
            key_tags: Arc::new(RwLock::new(HashMap::new())),
            tag_keys: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(InvalidationStats {
                total_invalidations: 0,
                invalidations_by_reason: HashMap::new(),
                avg_invalidation_time_us: 0.0,
                failed_invalidations: 0,
                cascaded_invalidations: 0,
                dependencies_tracked: 0,
                last_invalidation: None,
            })),
            event_sender,
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add tags to a key
    pub async fn add_tags(&self, key: &str, tags: &[String]) -> Result<()> {
        let mut key_tags = self.key_tags.write().await;
        let mut tag_keys = self.tag_keys.write().await;

        // Add tags to key
        let key_entry = key_tags.entry(key.to_string()).or_insert_with(HashSet::new);
        for tag in tags {
            key_entry.insert(tag.clone());
            
            // Add key to tag
            let tag_entry = tag_keys.entry(tag.clone()).or_insert_with(HashSet::new);
            tag_entry.insert(key.to_string());
        }

        Ok(())
    }

    /// Remove tags from a key
    pub async fn remove_tags(&self, key: &str, tags: &[String]) -> Result<()> {
        let mut key_tags = self.key_tags.write().await;
        let mut tag_keys = self.tag_keys.write().await;

        if let Some(key_entry) = key_tags.get_mut(key) {
            for tag in tags {
                key_entry.remove(tag);
                
                // Remove key from tag
                if let Some(tag_entry) = tag_keys.get_mut(tag) {
                    tag_entry.remove(key);
                }
            }
        }

        Ok(())
    }

    /// Get all tags for a key
    pub async fn get_key_tags(&self, key: &str) -> HashSet<String> {
        let key_tags = self.key_tags.read().await;
        key_tags.get(key).cloned().unwrap_or_default()
    }

    /// Get all keys for a tag
    pub async fn get_tag_keys(&self, tag: &str) -> HashSet<String> {
        let tag_keys = self.tag_keys.read().await;
        tag_keys.get(tag).cloned().unwrap_or_default()
    }

    /// Record invalidation event
    async fn record_invalidation(&self, event: InvalidationEvent) {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_invalidations += 1;
            
            let reason_key = format!("{:?}", event.reason);
            *stats.invalidations_by_reason.entry(reason_key).or_insert(0) += 1;
            stats.last_invalidation = Some(event.timestamp);
        }

        // Add to history
        {
            let mut history = self.history.write().await;
            history.push(event.clone());
            
            // Keep only last 1000 events
            if history.len() > 1000 {
                history.remove(0);
            }
        }

        // Broadcast event
        let _ = self.event_sender.send(event);
    }

    /// Get dependent keys for invalidation
    async fn get_dependent_keys(&self, key: &str, visited: &mut HashSet<String>) -> Vec<String> {
        if visited.contains(key) {
            return Vec::new();
        }
        visited.insert(key.to_string());

        let dependencies = self.dependencies.read().await;
        let mut dependents = Vec::new();

        if let Some(dep) = dependencies.get(key) {
            for dependent in &dep.dependents {
                dependents.push(dependent.clone());
                // Recursively get dependents
                let sub_dependents = Box::pin(self.get_dependent_keys(dependent, visited)).await;
                dependents.extend(sub_dependents);
            }
        }

        dependents
    }

    /// Invalidate key with cascading
    async fn invalidate_key_cascade(&self, key: &str, reason: InvalidationReason) -> Result<Vec<String>> {
        let mut invalidated_keys = Vec::new();
        let mut visited = HashSet::new();
        
        // Get all dependent keys
        let dependents = self.get_dependent_keys(key, &mut visited).await;
        
        // Invalidate the key itself
        invalidated_keys.push(key.to_string());
        
        // Add dependents
        for dependent in dependents {
            if !invalidated_keys.contains(&dependent) {
                invalidated_keys.push(dependent);
            }
        }

        // Record cascaded invalidations
        if invalidated_keys.len() > 1 {
            let mut stats = self.stats.write().await;
            stats.cascaded_invalidations += (invalidated_keys.len() - 1) as u64;
        }

        Ok(invalidated_keys)
    }

    /// Match pattern against keys
    fn matches_pattern(&self, key: &str, pattern: &str) -> bool {
        // Simple glob pattern matching
        if pattern == "*" {
            return true;
        }
        
        if pattern.ends_with("*") {
            let prefix = &pattern[..pattern.len() - 1];
            return key.starts_with(prefix);
        }
        
        if pattern.starts_with("*") {
            let suffix = &pattern[1..];
            return key.ends_with(suffix);
        }
        
        if pattern.contains("*") {
            // More complex pattern matching could be implemented here
            return key.contains(pattern.replace("*", "").as_str());
        }
        
        key == pattern
    }
}

#[async_trait]
impl CacheInvalidation for CacheInvalidationManager {
    async fn invalidate_key(&self, key: &str, reason: InvalidationReason) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        let invalidated_keys = if self.config.enable_dependency_tracking {
            self.invalidate_key_cascade(key, reason.clone()).await?
        } else {
            vec![key.to_string()]
        };

        // Record invalidation events
        for invalidated_key in &invalidated_keys {
            let event = InvalidationEvent {
                key: invalidated_key.clone(),
                reason: reason.clone(),
                timestamp: Utc::now(),
                metadata: HashMap::new(),
                source: "cache_invalidation_manager".to_string(),
            };
            
            self.record_invalidation(event).await;
        }

        // Update performance stats
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        {
            let mut stats = self.stats.write().await;
            stats.avg_invalidation_time_us = (stats.avg_invalidation_time_us * (stats.total_invalidations - 1) as f64 + elapsed_us) / stats.total_invalidations as f64;
        }

        Ok(())
    }

    async fn invalidate_keys(&self, keys: &[String], reason: InvalidationReason) -> Result<()> {
        for chunk in keys.chunks(self.config.batch_size) {
            for key in chunk {
                self.invalidate_key(key, reason.clone()).await?;
            }
            
            // Small delay between batches to prevent overwhelming
            if self.config.grace_period_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.config.grace_period_ms)).await;
            }
        }
        Ok(())
    }

    async fn invalidate_pattern(&self, _pattern: &str, _reason: InvalidationReason) -> Result<usize> {
        // This would need access to the actual cache keys
        // For now, we'll return 0 as a placeholder
        Ok(0)
    }

    async fn invalidate_by_tag(&self, tag: &str, reason: InvalidationReason) -> Result<usize> {
        let keys = self.get_tag_keys(tag).await;
        let key_list: Vec<String> = keys.into_iter().collect();
        
        self.invalidate_keys(&key_list, reason).await?;
        
        Ok(key_list.len())
    }

    async fn add_dependency(&self, key: &str, depends_on: &str) -> Result<()> {
        // Create copies of the strings before modifying dependencies
        let key_string = key.to_string();
        let depends_on_string = depends_on.to_string();
        
        // Use entry API to avoid double borrow issues
        {
            let mut dependencies = self.dependencies.write().await;
            
            // Initialize dependency entries if they don't exist
            let key_dep = dependencies.entry(key_string.clone()).or_insert_with(|| CacheDependency {
                dependents: HashSet::new(),
                dependencies: HashSet::new(),
                last_updated: Utc::now(),
            });
            
            // Add dependency relationship
            key_dep.dependencies.insert(depends_on_string.clone());
            key_dep.last_updated = Utc::now();
        }
        
        // Now add the reverse dependency
        {
            let mut dependencies = self.dependencies.write().await;
            let depends_on_dep = dependencies.entry(depends_on_string).or_insert_with(|| CacheDependency {
                dependents: HashSet::new(),
                dependencies: HashSet::new(),
                last_updated: Utc::now(),
            });
            
            depends_on_dep.dependents.insert(key_string);
            depends_on_dep.last_updated = Utc::now();
            
            // Update statistics
            let mut stats = self.stats.write().await;
            stats.dependencies_tracked = dependencies.len();
        }
        
        Ok(())
    }

    async fn remove_dependency(&self, key: &str, depends_on: &str) -> Result<()> {
        let mut dependencies = self.dependencies.write().await;
        
        if let Some(key_dep) = dependencies.get_mut(key) {
            key_dep.dependencies.remove(depends_on);
            key_dep.last_updated = Utc::now();
        }
        
        if let Some(depends_on_dep) = dependencies.get_mut(depends_on) {
            depends_on_dep.dependents.remove(key);
            depends_on_dep.last_updated = Utc::now();
        }
        
        Ok(())
    }

    async fn add_tags(&self, key: &str, tags: &[String]) -> Result<()> {
        let mut key_tags = self.key_tags.write().await;
        let mut tag_keys = self.tag_keys.write().await;
        
        // Add tags to key
        let key_tag_set = key_tags.entry(key.to_string()).or_insert_with(HashSet::new);
        for tag in tags {
            key_tag_set.insert(tag.clone());
            
            // Add key to tag mapping
            let tag_key_set = tag_keys.entry(tag.clone()).or_insert_with(HashSet::new);
            tag_key_set.insert(key.to_string());
        }
        
        Ok(())
    }

    async fn remove_tags(&self, key: &str, tags: &[String]) -> Result<()> {
        let mut key_tags = self.key_tags.write().await;
        let mut tag_keys = self.tag_keys.write().await;
        
        // Remove tags from key
        if let Some(key_tag_set) = key_tags.get_mut(key) {
            for tag in tags {
                key_tag_set.remove(tag);
                
                // Remove key from tag mapping
                if let Some(tag_key_set) = tag_keys.get_mut(tag) {
                    tag_key_set.remove(key);
                }
            }
        }
        
        Ok(())
    }

    async fn get_invalidation_stats(&self) -> Result<InvalidationStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    async fn subscribe_events(&self) -> broadcast::Receiver<InvalidationEvent> {
        self.event_sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

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
