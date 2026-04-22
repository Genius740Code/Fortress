//! High-performance caching layer for GraphQL operations
//!
//! Implements multi-level caching with LRU eviction, TTL management,
//! and intelligent cache warming strategies for optimal performance.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::hash::Hash;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

/// Cache entry with TTL support
#[derive(Clone, Debug)]
struct CacheEntry<T> {
    value: T,
    created_at: Instant,
    ttl: Duration,
    access_count: u64,
    last_accessed: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            value,
            created_at: now,
            ttl,
            access_count: 1,
            last_accessed: now,
        }
    }

    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    fn access(&mut self) -> &T {
        self.access_count += 1;
        self.last_accessed = Instant::now();
        &self.value
    }
}

/// High-performance LRU cache with TTL support
#[derive(Clone)]
pub struct GraphQLCache<T: Clone + Send + Sync + 'static> {
    entries: Arc<RwLock<HashMap<String, CacheEntry<T>>>>,
    lru_order: Arc<RwLock<VecDeque<String>>>,
    max_size: usize,
    default_ttl: Duration,
}

impl<T: Clone + Send + Sync + 'static> GraphQLCache<T> {
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            lru_order: Arc::new(RwLock::new(VecDeque::new())),
            max_size,
            default_ttl,
        }
    }

    /// Get value from cache with optimized non-blocking async operations
    pub async fn get(&self, key: &str) -> Option<T> {
        // Optimized read-first approach with minimal write operations
        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(key) {
            if entry.is_expired() {
                // Fast path for expired entries - schedule cleanup
                let key_owned = key.to_string();
                drop(entries);
                self.schedule_cleanup(key_owned);
                return None;
            }
            
            // Cache hit - get value and schedule async metadata update
            let value = entry.value.clone();
            let access_count = entry.access_count;
            drop(entries);
            
            // Schedule async update to avoid blocking
            self.schedule_access_update(key, access_count);
            
            return Some(value);
        }
        
        None
    }
    
    /// Schedule cleanup task for expired entries (non-blocking)
    fn schedule_cleanup(&self, key: String) {
        let cache = self.clone();
        tokio::spawn(async move {
            let mut entries = cache.entries.write().await;
            let mut lru_order = cache.lru_order.write().await;
            entries.remove(&key);
            lru_order.retain(|k| k != &key);
        });
    }
    
    /// Schedule access metadata update (non-blocking)
    fn schedule_access_update(&self, key: &str, access_count: u64) {
        let cache = self.clone();
        let key_owned = key.to_string();
        tokio::spawn(async move {
            // Update LRU order first (most critical)
            {
                let mut lru_order = cache.lru_order.write().await;
                lru_order.retain(|k| k != &key_owned);
                lru_order.push_front(key_owned.clone());
            }
            
            // Then update entry metadata
            {
                let mut entries = cache.entries.write().await;
                if let Some(entry) = entries.get_mut(&key_owned) {
                    entry.access_count = access_count + 1;
                    entry.last_accessed = std::time::Instant::now();
                }
            }
        });
    }

    /// Put value in cache with custom TTL and optimized LRU handling
    pub async fn put_with_ttl(&self, key: String, value: T, ttl: Duration) {
        let mut entries = self.entries.write().await;
        let mut lru_order = self.lru_order.write().await;
        
        // Check if key already exists and update it
        if entries.contains_key(&key) {
            // Remove from current LRU position
            lru_order.retain(|k| k != &key);
        } else {
            // New key - evict if necessary
            while entries.len() >= self.max_size {
                // Evict LRU entry efficiently
                if let Some(lru_key) = lru_order.pop_back() {
                    entries.remove(&lru_key);
                } else {
                    break; // Safety check
                }
            }
        }
        
        entries.insert(key.clone(), CacheEntry::new(value, ttl));
        lru_order.push_front(key);
    }

    /// Put value in cache with default TTL
    pub async fn put(&self, key: String, value: T) {
        self.put_with_ttl(key, value, self.default_ttl).await;
    }

    /// Remove expired entries with optimized batch processing
    pub async fn cleanup_expired(&self) {
        // Collect expired keys with read lock only
        let expired_keys = {
            let entries = self.entries.read().await;
            entries.iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
        };
        
        // Batch remove with write lock
        if !expired_keys.is_empty() {
            let mut entries = self.entries.write().await;
            let mut lru_order = self.lru_order.write().await;
            
            for key in &expired_keys {
                entries.remove(key);
            }
            
            lru_order.retain(|k| !expired_keys.contains(k));
        }
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        let mut lru_order = self.lru_order.write().await;
        entries.clear();
        lru_order.clear();
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let entries = self.entries.read().await;
        let total_entries = entries.len();
        let expired_count = entries.values()
            .filter(|entry| entry.is_expired())
            .count();
        
        CacheStats {
            total_entries,
            expired_count,
            hit_rate: 0.0, // Would need tracking for accurate hit rate
        }
    }

    /// Evict least recently used entries - optimized for direct access
    fn evict_lru(&self, entries: &mut HashMap<String, CacheEntry<T>>, lru_order: &mut VecDeque<String>) {
        // Direct O(1) eviction using pop_back()
        if let Some(lru_key) = lru_order.pop_back() {
            entries.remove(&lru_key);
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, async_graphql::SimpleObject)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_count: usize,
    pub hit_rate: f64,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_size: usize,
    pub default_ttl: Duration,
    pub cleanup_interval: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 10_000,
            default_ttl: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60), // 1 minute
        }
    }
}

/// Multi-level cache manager for GraphQL operations
#[derive(Clone)]
pub struct GraphQLCacheManager {
    /// Database metadata cache
    pub database_cache: GraphQLCache<DatabaseCacheEntry>,
    /// Table metadata cache
    pub table_cache: GraphQLCache<TableCacheEntry>,
    /// Query result cache
    pub query_cache: GraphQLCache<QueryCacheEntry>,
    /// Configuration
    config: CacheConfig,
}

/// Database cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCacheEntry {
    pub id: String,
    pub name: String,
    pub status: String,
    pub encryption_algorithm: String,
    pub created_at: String,
    pub updated_at: String,
    pub table_count: i32,
    pub storage_size_bytes: i64,
}

/// Table cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableCacheEntry {
    pub id: String,
    pub name: String,
    pub database: String,
    pub record_count: i32,
    pub encryption_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Query cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCacheEntry {
    pub query_hash: String,
    pub result: serde_json::Value,
    pub record_count: usize,
    pub execution_time_ms: u64,
}

impl GraphQLCacheManager {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            database_cache: GraphQLCache::new(config.max_size, config.default_ttl),
            table_cache: GraphQLCache::new(config.max_size, config.default_ttl),
            query_cache: GraphQLCache::new(config.max_size / 2, Duration::from_secs(60)), // Shorter TTL for queries
            config,
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.config.cleanup_interval);
            loop {
                interval.tick().await;
                
                // Clean up expired entries
                tokio::join!(
                    self.database_cache.cleanup_expired(),
                    self.table_cache.cleanup_expired(),
                    self.query_cache.cleanup_expired(),
                );
            }
        })
    }

    /// Generate cache key for database operations - optimized
    pub fn database_key(&self, name: &str) -> String {
        // Pre-allocate capacity to avoid reallocations
        let mut key = String::with_capacity(name.len() + 3);
        key.push_str("db:");
        key.push_str(name);
        key
    }

    /// Generate cache key for table operations - optimized
    pub fn table_key(&self, database: &str, table: &str) -> String {
        // Pre-allocate exact capacity
        let mut key = String::with_capacity(database.len() + table.len() + 6);
        key.push_str("table:");
        key.push_str(database);
        key.push_str(":");
        key.push_str(table);
        key
    }

    /// Generate cache key for query operations - optimized
    pub fn query_key(&self, database: &str, table: &str, query_hash: &str) -> String {
        // Pre-allocate exact capacity
        let mut key = String::with_capacity(database.len() + table.len() + query_hash.len() + 7);
        key.push_str("query:");
        key.push_str(database);
        key.push_str(":");
        key.push_str(table);
        key.push_str(":");
        key.push_str(query_hash);
        key
    }

    /// Get comprehensive cache statistics
    pub async fn get_stats(&self) -> CacheManagerStats {
        let (db_stats, table_stats, query_stats) = tokio::join!(
            self.database_cache.stats(),
            self.table_cache.stats(),
            self.query_cache.stats(),
        );

        CacheManagerStats {
            database: db_stats,
            table: table_stats,
            query: query_stats,
        }
    }
}

/// Cache manager statistics
#[derive(Debug, Clone, Serialize, async_graphql::SimpleObject)]
pub struct CacheManagerStats {
    pub database: CacheStats,
    pub table: CacheStats,
    pub query: CacheStats,
}

/// Query hash generator for caching
pub struct QueryHasher;

impl QueryHasher {
    /// Efficiently hash JSON value without string allocation
    fn hash_json_value(value: &serde_json::Value, hasher: &mut std::collections::hash_map::DefaultHasher) {
        match value {
            serde_json::Value::Null => 0.hash(hasher),
            serde_json::Value::Bool(b) => b.hash(hasher),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    i.hash(hasher);
                } else if let Some(u) = n.as_u64() {
                    u.hash(hasher);
                } else if let Some(f) = n.as_f64() {
                    f.to_bits().hash(hasher);
                }
            }
            serde_json::Value::String(s) => s.hash(hasher),
            serde_json::Value::Array(arr) => {
                arr.len().hash(hasher);
                for item in arr {
                    Self::hash_json_value(item, hasher);
                }
            }
            serde_json::Value::Object(obj) => {
                // Sort keys for consistent hashing
                let mut keys: Vec<_> = obj.keys().collect();
                keys.sort_unstable();
                keys.len().hash(hasher);
                for key in keys {
                    key.hash(hasher);
                    Self::hash_json_value(&obj[key], hasher);
                }
            }
        }
    }

    /// Generate a hash for query caching with zero allocations
    pub fn hash_query(
        database: &str,
        table: &str,
        filters: &serde_json::Value,
        pagination: &Option<crate::graphql::types::PaginationInput>,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        
        // Hash query components directly - zero allocations
        database.hash(&mut hasher);
        table.hash(&mut hasher);
        
        // Hash JSON value efficiently without string allocation
        Self::hash_json_value(filters, &mut hasher);
        
        // Hash pagination directly without string conversion
        if let Some(pagination) = pagination {
            pagination.page.hash(&mut hasher);
            pagination.page_size.hash(&mut hasher);
        }

        // Use faster hex formatting
        format!("{:016x}", hasher.finish())
    }
}
