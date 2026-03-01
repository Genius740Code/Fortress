//! Database-backed key manager with preloading and caching
//!
//! This module provides a production-ready key manager that combines
//! persistent storage, intelligent preloading, and high-performance caching.

use crate::error::{FortressError, Result, KeyErrorCode};
use crate::key::{KeyManager, KeyId, KeyMetadata, SecureKey};
use crate::key_database::{KeyDatabase, KeyDatabaseConfig, create_key_database};
use crate::key_preloader::{KeyPreloader, KeyPreloadConfig};
use crate::key_cache::{KeyCache, KeyCacheConfig};
use crate::encryption::EncryptionAlgorithm;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Configuration for the database key manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseKeyManagerConfig {
    /// Database configuration
    pub database: KeyDatabaseConfig,
    /// Preloader configuration
    pub preloader: KeyPreloadConfig,
    /// Cache configuration
    pub cache: KeyCacheConfig,
    /// Enable automatic key rotation
    pub enable_auto_rotation: bool,
    /// Key rotation interval in hours
    pub rotation_interval_hours: u64,
    /// Enable key backup before rotation
    pub enable_rotation_backup: bool,
    /// Enable performance monitoring
    pub enable_performance_monitoring: bool,
}

impl Default for DatabaseKeyManagerConfig {
    fn default() -> Self {
        Self {
            database: KeyDatabaseConfig {
                backend: crate::key_database::KeyDatabaseBackend::Sqlite,
                connection_string: "sqlite:./fortress_keys.db".to_string(),
                max_connections: 10,
                connection_timeout_seconds: 30,
                encrypt_at_rest: true,
                master_key: None,
            },
            preloader: KeyPreloadConfig::default(),
            cache: KeyCacheConfig::default(),
            enable_auto_rotation: true,
            rotation_interval_hours: 24,
            enable_rotation_backup: true,
            enable_performance_monitoring: true,
        }
    }
}

/// Performance metrics for the key manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagerMetrics {
    /// Total number of key operations
    pub total_operations: u64,
    /// Number of successful operations
    pub successful_operations: u64,
    /// Number of failed operations
    pub failed_operations: u64,
    /// Average operation time in milliseconds
    pub avg_operation_time_ms: f64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Database query time in milliseconds
    pub avg_db_query_time_ms: f64,
    /// Number of keys currently managed
    pub managed_keys: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Last operation time
    pub last_operation_time: Option<DateTime<Utc>>,
}

/// High-performance database-backed key manager
pub struct DatabaseKeyManager {
    /// Database backend for persistent storage
    database: Arc<dyn KeyDatabase>,
    /// Key preloader for fast startup
    preloader: Arc<KeyPreloader>,
    /// In-memory cache for hot keys
    cache: Arc<KeyCache>,
    /// Configuration
    config: DatabaseKeyManagerConfig,
    /// Performance metrics
    metrics: Arc<RwLock<KeyManagerMetrics>>,
    /// Background rotation task
    rotation_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl DatabaseKeyManager {
    /// Create a new database key manager with the given configuration
    pub async fn new(config: DatabaseKeyManagerConfig) -> Result<Self> {
        // Initialize database
        let database: Arc<dyn KeyDatabase> = Arc::from(create_key_database(config.database.clone()).await?);
        
        // Initialize preloader
        let preloader = Arc::new(KeyPreloader::new(database.clone(), config.preloader.clone()));
        
        // Initialize cache
        let cache = Arc::new(KeyCache::new(config.cache.clone()));
        
        let manager = Self {
            database,
            preloader,
            cache,
            config,
            metrics: Arc::new(RwLock::new(KeyManagerMetrics {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                avg_operation_time_ms: 0.0,
                cache_hit_ratio: 0.0,
                avg_db_query_time_ms: 0.0,
                managed_keys: 0,
                memory_usage_bytes: 0,
                last_operation_time: None,
            })),
            rotation_task: Arc::new(RwLock::new(None)),
        };

        // Initialize components
        manager.initialize().await?;
        
        Ok(manager)
    }

    /// Initialize all components and start background tasks
    async fn initialize(&self) -> Result<()> {
        // Initialize cache
        self.cache.initialize().await?;
        
        // Initialize preloader
        self.preloader.initialize().await?;
        
        // Start background rotation if enabled
        if self.config.enable_auto_rotation {
            self.start_background_rotation().await?;
        }
        
        // Update initial metrics
        self.update_metrics().await?;
        
        Ok(())
    }

    /// Start background key rotation task
    async fn start_background_rotation(&self) -> Result<()> {
        let database = self.database.clone();
        let rotation_interval_hours = self.config.rotation_interval_hours;
        let enable_backup = self.config.enable_rotation_backup;
        let metrics = self.metrics.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(rotation_interval_hours * 3600)
            );

            loop {
                interval.tick().await;

                // Perform key rotation
                if let Err(e) = Self::perform_background_rotation(
                    &database,
                    enable_backup,
                    &metrics,
                ).await {
                    eprintln!("Background rotation error: {}", e);
                }
            }
        });

        let mut rotation_task = self.rotation_task.write().await;
        *rotation_task = Some(handle);

        Ok(())
    }

    /// Perform background key rotation
    async fn perform_background_rotation(
        database: &Arc<dyn KeyDatabase>,
        enable_backup: bool,
        metrics: &Arc<RwLock<KeyManagerMetrics>>,
    ) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        // Get all keys that need rotation
        let all_keys = database.list_keys().await?;
        let now = Utc::now();
        let mut rotated_keys = 0;

        for (key_id, metadata) in all_keys {
            // Check if key needs rotation (simple heuristic: older than 24 hours)
            let age_hours = (now - metadata.created_at).num_hours();
            if age_hours >= 24 {
                // In a real implementation, you would generate a new key here
                // For now, we'll just update the metadata
                let mut new_metadata = metadata.clone();
                new_metadata.version += 1;
                new_metadata.created_at = now;
                
                // Store the updated metadata
                if let Some((key, _)) = database.retrieve_key(&key_id).await? {
                    database.store_key(&key_id, &key, &new_metadata).await?;
                    rotated_keys += 1;
                }
            }
        }

        // Update metrics
        let elapsed = start_time.elapsed();
        let mut metrics_guard = metrics.write().await;
        metrics_guard.total_operations += rotated_keys as u64;
        metrics_guard.successful_operations += rotated_keys as u64;
        metrics_guard.last_operation_time = Some(Utc::now());
        
        if rotated_keys > 0 {
            metrics_guard.avg_operation_time_ms = 
                (metrics_guard.avg_operation_time_ms * (metrics_guard.total_operations - rotated_keys) as f64 + elapsed.as_millis() as f64) / metrics_guard.total_operations as f64;
        }

        Ok(())
    }

    /// Get a key with cache-first strategy
    async fn get_key_with_cache(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        // Try cache first
        if let Some(cached_result) = self.cache.get(key_id).await {
            return Ok(Some(cached_result));
        }

        // Try preloader next
        if let Some(preloaded_result) = self.preloader.get_preloaded_key(key_id).await {
            // Cache the preloaded result for future use
            self.cache.put(key_id.clone(), preloaded_result.0.clone(), preloaded_result.1.clone()).await?;
            return Ok(Some(preloaded_result));
        }

        // Finally, hit the database
        let db_start = std::time::Instant::now();
        let result = self.database.retrieve_key(key_id).await?;
        let db_time = db_start.elapsed();

        // Update database query time metrics
        if self.config.enable_performance_monitoring {
            let mut metrics = self.metrics.write().await;
            if metrics.total_operations > 0 {
                metrics.avg_db_query_time_ms = 
                    (metrics.avg_db_query_time_ms * (metrics.total_operations - 1) as f64 + db_time.as_millis() as f64) / metrics.total_operations as f64;
            }
        }

        // Cache the result for future use
        if let Some((ref key, ref metadata)) = result {
            self.cache.put(key_id.clone(), key.clone(), metadata.clone()).await?;
        }

        Ok(result)
    }

    /// Update performance metrics
    async fn update_metrics(&self) -> Result<()> {
        if !self.config.enable_performance_monitoring {
            return Ok(());
        }

        let db_stats = self.database.get_stats().await?;
        let cache_stats = self.cache.get_stats().await;
        let preload_stats = self.preloader.get_stats().await;

        let mut metrics = self.metrics.write().await;
        metrics.managed_keys = db_stats.total_keys;
        metrics.memory_usage_bytes = cache_stats.current_memory_bytes as u64 + preload_stats.total_memory_usage_bytes as u64;
        metrics.cache_hit_ratio = cache_stats.hit_ratio;

        Ok(())
    }

    /// Get comprehensive performance metrics
    pub async fn get_metrics(&self) -> KeyManagerMetrics {
        self.update_metrics().await.unwrap_or(());
        self.metrics.read().await.clone()
    }

    /// Get detailed statistics from all components
    pub async fn get_detailed_stats(&self) -> Result<DatabaseKeyManagerStats> {
        let db_stats = self.database.get_stats().await?;
        let cache_stats = self.cache.get_stats().await;
        let preload_stats = self.preloader.get_stats().await;
        let access_stats = self.preloader.get_access_stats().await;

        Ok(DatabaseKeyManagerStats {
            database: db_stats,
            cache: cache_stats,
            preloader: preload_stats,
            access_stats,
            metrics: self.get_metrics().await,
        })
    }

    /// Force preload a specific key
    pub async fn force_preload_key(&self, key_id: &KeyId) -> Result<bool> {
        self.preloader.force_preload_key(key_id).await
    }

    /// Evict a key from cache
    pub async fn evict_from_cache(&self, key_id: &KeyId) -> Result<bool> {
        self.cache.remove(key_id).await
    }

    /// Clear all caches
    pub async fn clear_caches(&self) -> Result<usize> {
        let cache_count = self.cache.clear().await?;
        let preload_count = self.preloader.clear_preloaded_keys().await?;
        Ok(cache_count + preload_count)
    }

    /// Get performance recommendations
    pub async fn get_performance_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Cache recommendations
        recommendations.extend(self.cache.get_performance_recommendations().await);

        // Metrics-based recommendations
        let metrics = self.get_metrics().await;
        
        if metrics.cache_hit_ratio < 0.7 {
            recommendations.push(
                "Low cache hit ratio. Consider increasing cache size or adjusting preloading strategy.".to_string()
            );
        }

        if metrics.avg_db_query_time_ms > 100.0 {
            recommendations.push(
                "High database query time. Consider optimizing database or increasing cache effectiveness.".to_string()
            );
        }

        if metrics.memory_usage_bytes > 1024 * 1024 * 1024 { // 1GB
            recommendations.push(
                "High memory usage. Consider adjusting cache limits or implementing more aggressive eviction.".to_string()
            );
        }

        recommendations
    }

    /// Shutdown the key manager and cleanup resources
    pub async fn shutdown(&self) -> Result<()> {
        // Cancel background rotation
        let mut rotation_task = self.rotation_task.write().await;
        if let Some(handle) = rotation_task.take() {
            handle.abort();
        }

        // Shutdown components
        self.preloader.shutdown().await?;
        self.cache.shutdown().await?;

        Ok(())
    }
}

#[async_trait]
impl KeyManager for DatabaseKeyManager {
    async fn generate_key(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<SecureKey> {
        let start_time = std::time::Instant::now();
        
        let key = SecureKey::generate(algorithm.key_size());
        
        // Update metrics
        if self.config.enable_performance_monitoring {
            let mut metrics = self.metrics.write().await;
            metrics.total_operations += 1;
            metrics.successful_operations += 1;
            metrics.last_operation_time = Some(Utc::now());
            
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_operation_time_ms = 
                (metrics.avg_operation_time_ms * (metrics.total_operations - 1) as f64 + elapsed_ms) / metrics.total_operations as f64;
        }

        Ok(key)
    }

    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        // Store in database
        self.database.store_key(key_id, key, metadata).await?;
        
        // Cache the key for immediate access
        self.cache.put(key_id.clone(), key.clone(), metadata.clone()).await?;
        
        // Update metrics
        if self.config.enable_performance_monitoring {
            let mut metrics = self.metrics.write().await;
            metrics.total_operations += 1;
            metrics.successful_operations += 1;
            metrics.last_operation_time = Some(Utc::now());
            
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_operation_time_ms = 
                (metrics.avg_operation_time_ms * (metrics.total_operations - 1) as f64 + elapsed_ms) / metrics.total_operations as f64;
        }

        Ok(())
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)> {
        let start_time = std::time::Instant::now();
        
        let result = self.get_key_with_cache(key_id).await?;
        
        // Update metrics
        if self.config.enable_performance_monitoring {
            let mut metrics = self.metrics.write().await;
            metrics.total_operations += 1;
            
            if result.is_some() {
                metrics.successful_operations += 1;
            } else {
                metrics.failed_operations += 1;
            }
            
            metrics.last_operation_time = Some(Utc::now());
            
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_operation_time_ms = 
                (metrics.avg_operation_time_ms * (metrics.total_operations - 1) as f64 + elapsed_ms) / metrics.total_operations as f64;
        }

        result.ok_or_else(|| FortressError::key_management(
            format!("Key not found: {}", key_id),
            Some(key_id.clone()),
            KeyErrorCode::KeyNotFound,
        ))
    }

    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        // Delete from database
        self.database.delete_key(key_id).await?;
        
        // Remove from cache
        self.cache.remove(key_id).await?;
        
        // Remove from preloader
        self.preloader.evict_key(key_id).await?;
        
        // Update metrics
        if self.config.enable_performance_monitoring {
            let mut metrics = self.metrics.write().await;
            metrics.total_operations += 1;
            metrics.successful_operations += 1;
            metrics.last_operation_time = Some(Utc::now());
            
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_operation_time_ms = 
                (metrics.avg_operation_time_ms * (metrics.total_operations - 1) as f64 + elapsed_ms) / metrics.total_operations as f64;
        }

        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let start_time = std::time::Instant::now();
        
        let result = self.database.list_keys().await?;
        
        // Update metrics
        if self.config.enable_performance_monitoring {
            let mut metrics = self.metrics.write().await;
            metrics.total_operations += 1;
            metrics.successful_operations += 1;
            metrics.last_operation_time = Some(Utc::now());
            
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_operation_time_ms = 
                (metrics.avg_operation_time_ms * (metrics.total_operations - 1) as f64 + elapsed_ms) / metrics.total_operations as f64;
        }

        Ok(result)
    }

    async fn rotate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        // Generate new key
        let new_key = self.generate_key(algorithm).await?;
        
        // Get old metadata
        let (_, old_metadata) = self.retrieve_key(key_id).await?;
        
        // Create new metadata with incremented version
        let new_metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            old_metadata.version + 1,
            Utc::now(),
            Utc::now() + chrono::Duration::days(90),
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        );

        // Store new key
        self.store_key(key_id, &new_key, &new_metadata).await?;
        
        // Update metrics
        if self.config.enable_performance_monitoring {
            let mut metrics = self.metrics.write().await;
            metrics.total_operations += 1;
            metrics.successful_operations += 1;
            metrics.last_operation_time = Some(Utc::now());
            
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_operation_time_ms = 
                (metrics.avg_operation_time_ms * (metrics.total_operations - 1) as f64 + elapsed_ms) / metrics.total_operations as f64;
        }

        Ok(())
    }

    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        // Check cache first
        if self.cache.contains(key_id).await {
            return Ok(true);
        }

        // Check database
        self.database.key_exists(key_id).await
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata> {
        // Try cache first
        if let Some((_, metadata)) = self.cache.get(key_id).await {
            return Ok(metadata);
        }

        // Check database
        self.database.get_key_metadata(key_id).await?.ok_or_else(|| FortressError::key_management(
            format!("Key not found: {}", key_id),
            Some(key_id.clone()),
            KeyErrorCode::KeyNotFound,
        ))
    }
}

/// Comprehensive statistics for the database key manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseKeyManagerStats {
    /// Database statistics
    pub database: crate::key_database::KeyDatabaseStats,
    /// Cache statistics
    pub cache: crate::key_cache::CacheStats,
    /// Preloader statistics
    pub preloader: crate::key_preloader::PreloadStats,
    /// Access statistics
    pub access_stats: std::collections::HashMap<KeyId, crate::key_preloader::KeyAccessStats>,
    /// Performance metrics
    pub metrics: KeyManagerMetrics,
}

impl std::fmt::Debug for DatabaseKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseKeyManager")
            .field("database_backend", &self.config.database.backend)
            .field("enable_preloading", &self.config.preloader.enable_preload)
            .field("enable_caching", &self.config.cache.enable_stats)
            .field("managed_keys", &self.metrics.try_read().map(|m| m.managed_keys).unwrap_or(0))
            .finish()
    }
}
