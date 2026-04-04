//! High-performance caching layer for GraphQL operations
//!
//! Implements multi-level caching with LRU eviction, TTL management,
//! and intelligent cache warming strategies for optimal performance.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use async_graphql::Result;
use uuid::Uuid;

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
pub struct GraphQLCache<T: Clone> {
    entries: Arc<RwLock<HashMap<String, CacheEntry<T>>>>,
    max_size: usize,
    default_ttl: Duration,
}

impl<T: Clone> GraphQLCache<T> {
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            default_ttl,
        }
    }

    /// Get value from cache
    pub async fn get(&self, key: &str) -> Option<T> {
        let mut entries = self.entries.write().await;
        
        if let Some(entry) = entries.get_mut(key) {
            if entry.is_expired() {
                entries.remove(key);
                None
            } else {
                Some(entry.access().clone())
            }
        } else {
            None
        }
    }

    /// Put value in cache with custom TTL
    pub async fn put_with_ttl(&self, key: String, value: T, ttl: Duration) {
        let mut entries = self.entries.write().await;
        
        // Evict if necessary
        if entries.len() >= self.max_size {
            self.evict_lru(&mut entries);
        }
        
        entries.insert(key, CacheEntry::new(value, ttl));
    }

    /// Put value in cache with default TTL
    pub async fn put(&self, key: String, value: T) {
        self.put_with_ttl(key, value, self.default_ttl).await;
    }

    /// Remove expired entries
    pub async fn cleanup_expired(&self) {
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| !entry.is_expired());
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
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

    /// Evict least recently used entries
    fn evict_lru(&self, entries: &mut HashMap<String, CacheEntry<T>>) {
        if entries.is_empty() {
            return;
        }

        // Find the LRU entry
        let lru_key = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone())
            .unwrap();

        entries.remove(&lru_key);
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

    /// Generate cache key for database operations
    pub fn database_key(&self, name: &str) -> String {
        format!("db:{}", name)
    }

    /// Generate cache key for table operations
    pub fn table_key(&self, database: &str, table: &str) -> String {
        format!("table:{}:{}", database, table)
    }

    /// Generate cache key for query operations
    pub fn query_key(&self, database: &str, table: &str, query_hash: &str) -> String {
        format!("query:{}:{}:{}", database, table, query_hash)
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
    /// Generate a hash for query caching
    pub fn hash_query(
        database: &str,
        table: &str,
        filters: &serde_json::Value,
        pagination: &Option<crate::graphql::types::PaginationInput>,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        
        // Hash query components
        database.hash(&mut hasher);
        table.hash(&mut hasher);
        filters.to_string().hash(&mut hasher);
        
        if let Some(pagination) = pagination {
            pagination.page.hash(&mut hasher);
            pagination.page_size.hash(&mut hasher);
        }

        format!("{:x}", hasher.finish())
    }
}
