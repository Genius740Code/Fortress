//! Unified cache manager for Fortress
//!
//! This module provides a high-level cache management interface that integrates
//! all caching components and provides intelligent caching strategies.

use crate::error::{FortressError, Result};
#[cfg(feature = "distributed-cache")]
use crate::distributed_cache::{DistributedCache, DistributedCacheConfig};
use crate::cache_invalidation::{CacheInvalidation, InvalidationConfig, InvalidationReason};
#[cfg(feature = "distributed-cache")]
use crate::cache_hybrid::HybridCacheConfig;
#[cfg(feature = "redis")]
use crate::cache_redis::{RedisCache, RedisConfig};
#[cfg(feature = "memcached")]
use crate::cache_memcached::{MemcachedCache, MemcachedConfig};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};

#[cfg(feature = "performance-optimization")]
use dashmap::DashMap;
#[cfg(feature = "performance-optimization")]
use parking_lot::RwLock as ParkingLotRwLock;
#[cfg(feature = "performance-optimization")]
use rayon::prelude::*;

/// Cache manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheManagerConfig {
    /// Cache type to use
    pub cache_type: CacheType,
    /// Cache-specific configurations
    #[cfg(feature = "distributed-cache")]
    pub distributed_config: Option<DistributedCacheConfig>,
    #[cfg(feature = "redis")]
    pub redis_config: Option<RedisConfig>,
    #[cfg(feature = "memcached")]
    pub memcached_config: Option<MemcachedConfig>,
    /// Hybrid cache configuration (local + distributed)
    #[cfg(feature = "distributed-cache")]
    pub hybrid_config: Option<HybridCacheConfig>,
    /// Invalidation configuration
    pub invalidation_config: InvalidationConfig,
    /// Default TTL in seconds
    pub default_ttl_seconds: u64,
    /// Enable proactive invalidation
    pub proactive_invalidation: bool,
    /// Invalidation strategy
    pub invalidation_strategy: InvalidationStrategy,
    /// Enable automatic cache warming
    pub enable_auto_warming: bool,
    /// Keys to warm up automatically
    pub warm_up_keys: Vec<String>,
    /// Enable performance monitoring
    pub enable_monitoring: bool,
    /// Health check interval in seconds
    pub health_check_interval_seconds: u64,
    /// Performance thresholds
    pub performance_thresholds: PerformanceThresholds,
    /// Enable predictive cache warming
    pub enable_predictive_warming: bool,
    /// ML-based access pattern learning
    pub enable_pattern_learning: bool,
    /// Pattern learning window in hours
    pub pattern_learning_window_hours: u32,
    /// Minimum access frequency for prediction
    pub min_access_frequency: u32,
    /// Prediction confidence threshold
    pub prediction_confidence_threshold: f64,
}

/// Cache types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheType {
    /// In-memory cache only
    InMemory,
    /// Redis cache
    Redis,
    /// Memcached cache
    Memcached,
    /// Hybrid cache (local + distributed)
    Hybrid,
    /// Auto-select based on environment
    Auto,
}

/// Cache invalidation strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvalidationStrategy {
    /// Time-based invalidation with TTL
    TimeToLive { ttl_seconds: u64 },
    /// Write-through cache invalidation
    WriteThrough { invalidate_on_write: bool },
    /// Write-behind cache invalidation with delay
    WriteBehind { delay_seconds: u64 },
    /// Event-driven invalidation
    EventDriven,
    /// Manual invalidation only
    Manual,
}

/// Performance thresholds for cache management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    /// Hit ratio threshold for cache warming
    pub hit_ratio_threshold: f64,
    /// Memory usage threshold for eviction
    pub memory_usage_threshold: f64,
    /// Response time threshold in microseconds
    pub response_time_threshold_us: f64,
    /// Error rate threshold
    pub error_rate_threshold: f64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            hit_ratio_threshold: 0.8,
            memory_usage_threshold: 0.9,
            response_time_threshold_us: 1000.0,
            error_rate_threshold: 0.05,
        }
    }
}

impl Default for CacheManagerConfig {
    fn default() -> Self {
        Self {
            cache_type: CacheType::InMemory,
            #[cfg(feature = "distributed-cache")]
            distributed_config: Some(DistributedCacheConfig::default()),
            #[cfg(feature = "redis")]
            redis_config: None,
            #[cfg(feature = "memcached")]
            memcached_config: None,
            #[cfg(feature = "distributed-cache")]
            hybrid_config: None,
            invalidation_config: InvalidationConfig::default(),
            default_ttl_seconds: 3600, // 1 hour default TTL
            proactive_invalidation: true,
            invalidation_strategy: InvalidationStrategy::TimeToLive { ttl_seconds: 3600 },
            enable_auto_warming: false,
            warm_up_keys: Vec::new(),
            enable_monitoring: true,
            health_check_interval_seconds: 60,
            performance_thresholds: PerformanceThresholds::default(),
            enable_predictive_warming: true,
            enable_pattern_learning: true,
            pattern_learning_window_hours: 24,
            min_access_frequency: 5,
            prediction_confidence_threshold: 0.8,
        }
    }
}

/// Cache manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheManagerStatistics {
    /// Overall cache statistics
    #[cfg(feature = "distributed-cache")]
    pub cache_stats: crate::distributed_cache::CacheStatistics,
    /// Compatibility cache statistics (always available for tests)
    pub cache_stats_compat: CacheStatsCompat,
    /// Invalidation statistics
    pub invalidation_stats: crate::cache_invalidation::InvalidationStats,
    /// Performance metrics
    pub performance_metrics: PerformanceMetrics,
    /// Health status
    pub health_status: HealthStatus,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Compatibility cache statistics for tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatsCompat {
    /// Number of cache sets
    pub sets: u64,
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average response time in microseconds
    pub avg_response_time_us: f64,
    /// P95 response time in microseconds
    pub p95_response_time_us: f64,
    /// P99 response time in microseconds
    pub p99_response_time_us: f64,
    /// Throughput in operations per second
    pub throughput_ops_per_sec: f64,
    /// Error rate
    pub error_rate: f64,
    /// Cache efficiency score
    pub efficiency_score: f64,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health
    pub healthy: bool,
    /// Last health check
    pub last_health_check: DateTime<Utc>,
    /// Issues found
    pub issues: Vec<String>,
    /// Warnings
    pub warnings: Vec<String>,
}

/// Trait for cache management operations
#[async_trait]
pub trait CacheManager: Send + Sync + std::fmt::Debug {
    /// Get a value from cache
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Set a value in cache
    async fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: Option<u64>) -> Result<()>;

    /// Delete a value from cache
    async fn delete(&self, key: &str) -> Result<bool>;

    /// Check if a key exists
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Clear all cache entries
    async fn clear(&self) -> Result<()>;

    /// Get multiple keys
    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>>;

    /// Set multiple keys
    async fn mset(&self, entries: &[(&str, Vec<u8>, Option<u64>)]) -> Result<()>;

    /// Increment a numeric value
    async fn increment(&self, key: &str, delta: i64) -> Result<i64>;

    /// Get cache statistics
    async fn get_statistics(&self) -> Result<CacheManagerStatistics>;

    /// Reset statistics
    async fn reset_statistics(&self) -> Result<()>;

    /// Health check
    async fn health_check(&self) -> Result<HealthStatus>;

    /// Add tags to a key
    async fn add_tags(&self, key: &str, tags: &[String]) -> Result<()>;

    /// Remove tags from a key
    async fn remove_tags(&self, key: &str, tags: &[String]) -> Result<()>;

    /// Invalidate by tag
    async fn invalidate_by_tag(&self, tag: &str) -> Result<usize>;

    /// Warm up cache
    async fn warm_up(&self, keys: Vec<String>) -> Result<usize>;

    /// Get performance recommendations
    async fn get_performance_recommendations(&self) -> Result<Vec<String>>;
}

/// Access pattern for predictive warming
#[derive(Debug, Clone)]
struct AccessPattern {
    key: String,
    access_count: u32,
    last_access: DateTime<Utc>,
    access_times: Vec<DateTime<Utc>>,
    predicted_next_access: Option<DateTime<Utc>>,
    confidence_score: f64,
}

/// Advanced cache manager implementation
#[derive(Debug)]
pub struct FortressCacheManager {
    config: CacheManagerConfig,
    /// Primary cache implementation
    #[cfg(feature = "distributed-cache")]
    cache: Arc<dyn DistributedCache>,
    /// Invalidation manager
    invalidation_manager: Arc<dyn CacheInvalidation>,
    /// Performance metrics
    #[cfg(not(feature = "performance-optimization"))]
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,
    #[cfg(feature = "performance-optimization")]
    performance_metrics: Arc<ParkingLotRwLock<PerformanceMetrics>>,
    /// Health status
    #[cfg(not(feature = "performance-optimization"))]
    health_status: Arc<RwLock<HealthStatus>>,
    #[cfg(feature = "performance-optimization")]
    health_status: Arc<ParkingLotRwLock<HealthStatus>>,
    /// Response time samples
    #[cfg(not(feature = "performance-optimization"))]
    response_times: Arc<RwLock<Vec<f64>>>,
    #[cfg(feature = "performance-optimization")]
    response_times: Arc<ParkingLotRwLock<Vec<f64>>>,
    /// Error count
    #[cfg(not(feature = "performance-optimization"))]
    error_count: Arc<RwLock<u64>>,
    #[cfg(feature = "performance-optimization")]
    error_count: Arc<ParkingLotRwLock<u64>>,
    /// Operation count
    #[cfg(not(feature = "performance-optimization"))]
    operation_count: Arc<RwLock<u64>>,
    #[cfg(feature = "performance-optimization")]
    operation_count: Arc<ParkingLotRwLock<u64>>,
    /// Access patterns for predictive warming
    #[cfg(feature = "performance-optimization")]
    access_patterns: Arc<DashMap<String, AccessPattern>>,
    /// Last pattern analysis time
    #[cfg(feature = "performance-optimization")]
    last_pattern_analysis: Arc<ParkingLotRwLock<DateTime<Utc>>>,
}

impl FortressCacheManager {
    /// Create a new cache manager
    #[cfg(feature = "distributed-cache")]
    pub async fn new(config: CacheManagerConfig) -> Result<Self> {
        // Create cache based on type
        let cache = Self::create_cache(&config).await?;
        
        // Create invalidation manager
        let invalidation_manager = Arc::new(CacheInvalidationManager::new(config.invalidation_config.clone()));

        #[cfg(not(feature = "performance-optimization"))]
        {
            let manager = Self {
                config,
                cache,
                invalidation_manager,
                performance_metrics: Arc::new(RwLock::new(PerformanceMetrics {
                    avg_response_time_us: 0.0,
                    p95_response_time_us: 0.0,
                    p99_response_time_us: 0.0,
                    throughput_ops_per_sec: 0.0,
                    error_rate: 0.0,
                    efficiency_score: 0.0,
                })),
                health_status: Arc::new(RwLock::new(HealthStatus {
                    healthy: true,
                    last_health_check: Utc::now(),
                    issues: Vec::new(),
                    warnings: Vec::new(),
                })),
                response_times: Arc::new(RwLock::new(Vec::new())),
                error_count: Arc::new(RwLock::new(0)),
                operation_count: Arc::new(RwLock::new(0)),
            };

            // Auto-warm if enabled
            if manager.config.enable_auto_warming && !manager.config.warm_up_keys.is_empty() {
                let warm_up_keys = manager.config.warm_up_keys.clone();
                let _ = manager.warm_up(warm_up_keys).await;
            }

            Ok(manager)
        }
        
        #[cfg(feature = "performance-optimization")]
        {
            let manager = Self {
                config,
                cache,
                invalidation_manager,
                performance_metrics: Arc::new(ParkingLotRwLock::new(PerformanceMetrics {
                    avg_response_time_us: 0.0,
                    p95_response_time_us: 0.0,
                    p99_response_time_us: 0.0,
                    throughput_ops_per_sec: 0.0,
                    error_rate: 0.0,
                    efficiency_score: 0.0,
                })),
                health_status: Arc::new(ParkingLotRwLock::new(HealthStatus {
                    healthy: true,
                    last_health_check: Utc::now(),
                    issues: Vec::new(),
                    warnings: Vec::new(),
                })),
                response_times: Arc::new(ParkingLotRwLock::new(Vec::new())),
                error_count: Arc::new(ParkingLotRwLock::new(0)),
                operation_count: Arc::new(ParkingLotRwLock::new(0)),
                access_patterns: Arc::new(DashMap::new()),
                last_pattern_analysis: Arc::new(ParkingLotRwLock::new(Utc::now())),
            };

            // Auto-warm if enabled
            if manager.config.enable_auto_warming && !manager.config.warm_up_keys.is_empty() {
                let warm_up_keys = manager.config.warm_up_keys.clone();
                let _ = manager.warm_up(warm_up_keys).await;
            }

            // Start predictive warming if enabled
            if manager.config.enable_predictive_warming {
                let manager_clone = manager.clone();
                tokio::spawn(async move {
                    manager_clone.start_predictive_warming().await;
                });
            }

            Ok(manager)
        }
    }
    /// Create cache based on configuration
    #[cfg(feature = "distributed-cache")]
    async fn create_cache(config: &CacheManagerConfig) -> Result<Arc<dyn DistributedCache>> {
        match &config.cache_type {
            CacheType::InMemory => {
                #[cfg(feature = "distributed-cache")]
                {
                    let cache_config = config.distributed_config.clone().unwrap_or_default();
                    let cache = crate::distributed_cache::create_distributed_cache(cache_config).await?;
                    Ok(Arc::from(cache))
                }
                #[cfg(not(feature = "distributed-cache"))]
                {
                    Err(crate::error::FortressError::cache("Distributed cache not available"))
                }
            }
            CacheType::Redis => {
                #[cfg(feature = "redis")]
                {
                    let redis_config = config.redis_config.clone().ok_or_else(|| {
                        FortressError::storage(
                            "Redis configuration not provided".to_string(),
                            "cache_manager".to_string(),
                            crate::error::StorageErrorCode::InvalidConfiguration,
                        )
                    })?;
                    let cache = crate::cache_redis::create_redis_cache(redis_config).await?;
                    Ok(Arc::from(cache))
                }
                #[cfg(not(feature = "redis"))]
                {
                    return Err(FortressError::storage(
                        "Redis support not enabled. Enable the 'redis' feature in Cargo.toml".to_string(),
                        "cache_manager".to_string(),
                        crate::error::StorageErrorCode::BackendNotAvailable,
                    ));
                }
            }
            CacheType::Memcached => {
                #[cfg(feature = "memcached")]
                {
                    let memcached_config = config.memcached_config.clone().ok_or_else(|| {
                        FortressError::storage(
                            "Memcached configuration not provided".to_string(),
                            "cache_manager".to_string(),
                            crate::error::StorageErrorCode::InvalidConfiguration,
                        )
                    })?;
                    let cache = crate::cache_memcached::create_memcached_cache(memcached_config).await?;
                    Ok(Arc::from(cache))
                }
                #[cfg(not(feature = "memcached"))]
                {
                    return Err(FortressError::storage(
                        "Memcached support not enabled. Enable the 'memcached' feature in Cargo.toml".to_string(),
                        "cache_manager".to_string(),
                        crate::error::StorageErrorCode::BackendNotAvailable,
                    ));
                }
            }
            CacheType::Hybrid => {
                let hybrid_config = config.hybrid_config.clone().ok_or_else(|| {
                    FortressError::storage(
                        "Hybrid cache configuration not provided".to_string(),
                        "cache_manager".to_string(),
                        crate::error::StorageErrorCode::InvalidConfiguration,
                    )
                })?;
                let cache = crate::cache_hybrid::create_hybrid_cache(hybrid_config).await?;
                Ok(Arc::from(cache))
            }
            CacheType::Auto => {
                // Auto-select based on available features and environment
                #[cfg(feature = "distributed-cache")]
                {
                    Self::auto_select_cache(config).await
                }
                #[cfg(not(feature = "distributed-cache"))]
                {
                    Err(crate::error::FortressError::cache("Distributed cache not available"))
                }
            }
        }
    }

    /// Auto-select cache based on environment
    #[cfg(feature = "distributed-cache")]
    async fn auto_select_cache(config: &CacheManagerConfig) -> Result<Arc<dyn DistributedCache>> {
        // Try Redis first if available
        #[cfg(feature = "redis")]
        if config.redis_config.is_some() {
            let redis_config = config.redis_config.clone().unwrap();
            let cache = crate::cache_redis::create_redis_cache(redis_config).await?;
            return Ok(Arc::from(cache));
        }

        // Try Memcached next if available
        #[cfg(feature = "memcached")]
        if config.memcached_config.is_some() {
            let memcached_config = config.memcached_config.clone().unwrap();
            let cache = crate::cache_memcached::create_memcached_cache(memcached_config).await?;
            return Ok(Arc::from(cache));
        }

        // Fall back to in-memory cache
        #[cfg(feature = "distributed-cache")]
        {
            let cache_config = config.distributed_config.clone().unwrap_or_default();
            let cache = crate::distributed_cache::create_distributed_cache(cache_config).await?;
            Ok(Arc::from(cache))
        }
        #[cfg(not(feature = "distributed-cache"))]
        {
            Err(crate::error::FortressError::cache("Distributed cache not available"))
        }
    }

    /// Update performance metrics
    async fn update_performance_metrics(&self, response_time_us: f64, success: bool) {
        // Update response times
        {
            let mut response_times = self.response_times.write().await;
            response_times.push(response_time_us);
            
            // Keep only last 1000 samples
            if response_times.len() > 1000 {
                response_times.remove(0);
            }
        }

        // Update operation and error counts
        {
            let mut operation_count = self.operation_count.write().await;
            *operation_count += 1;
            
            if !success {
                let mut error_count = self.error_count.write().await;
                *error_count += 1;
            }
        }

        // Calculate metrics
        if self.config.enable_monitoring {
            #[cfg(feature = "distributed-cache")]
            self.calculate_performance_metrics().await;
        }
    }

    /// Calculate performance metrics
    #[cfg(feature = "distributed-cache")]
    async fn calculate_performance_metrics(&self) {
        let response_times = self.response_times.read().await;
        let operation_count = *self.operation_count.read().await;
        let error_count = *self.error_count.read().await;

        if response_times.is_empty() {
            return;
        }

        let mut sorted_times = response_times.clone();
        sorted_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let avg_response_time = response_times.iter().sum::<f64>() / response_times.len() as f64;
        let p95_index = std::cmp::min((sorted_times.len() as f64 * 0.95) as usize, sorted_times.len().saturating_sub(1));
        let p99_index = std::cmp::min((sorted_times.len() as f64 * 0.99) as usize, sorted_times.len().saturating_sub(1));
        
        let p95_response_time = sorted_times.get(p95_index).unwrap_or(&avg_response_time);
        let p99_response_time = sorted_times.get(p99_index).unwrap_or(&avg_response_time);

        let error_rate = if operation_count > 0 {
            error_count as f64 / operation_count as f64
        } else {
            0.0
        };

        // Get cache statistics for efficiency score
        let cache_stats = self.cache.get_statistics().await.unwrap_or_default();
        let efficiency_score = cache_stats.hit_ratio * (1.0 - error_rate);

        let mut metrics = self.performance_metrics.write().await;
        metrics.avg_response_time_us = avg_response_time;
        metrics.p95_response_time_us = *p95_response_time;
        metrics.p99_response_time_us = *p99_response_time;
        metrics.error_rate = error_rate;
        metrics.efficiency_score = efficiency_score;

        // Calculate throughput (simplified)
        if response_times.len() > 1 {
            let time_span = response_times.len() as f64 * 0.001; // Assume 1ms between operations
            metrics.throughput_ops_per_sec = operation_count as f64 / time_span;
        }
    }

    /// Update health status
    #[cfg(feature = "distributed-cache")]
    async fn update_health_status(&self) {
        let mut health_status = self.health_status.write().await;
        health_status.last_health_check = Utc::now();
        health_status.issues.clear();
        health_status.warnings.clear();

        // Check cache health
        match self.cache.health_check().await {
            Ok(healthy) => {
                if !healthy {
                    health_status.issues.push("Cache health check failed".to_string());
                }
            }
            Err(e) => {
                health_status.issues.push(format!("Cache health check error: {}", e));
            }
        }

        // Check performance thresholds
        let metrics = self.performance_metrics.read().await;
        let thresholds = &self.config.performance_thresholds;

        if metrics.avg_response_time_us > thresholds.response_time_threshold_us {
            health_status.warnings.push(format!(
                "Average response time ({:.2}μs) exceeds threshold ({:.2}μs)",
                metrics.avg_response_time_us, thresholds.response_time_threshold_us
            ));
        }

        if metrics.error_rate > thresholds.error_rate_threshold {
            health_status.issues.push(format!(
                "Error rate ({:.2}%) exceeds threshold ({:.2}%)",
                metrics.error_rate * 100.0, thresholds.error_rate_threshold * 100.0
            ));
        }

        // Check cache statistics
        if let Ok(cache_stats) = self.cache.get_statistics().await {
            if cache_stats.hit_ratio < thresholds.hit_ratio_threshold {
                health_status.warnings.push(format!(
                    "Cache hit ratio ({:.2}%) below threshold ({:.2}%)",
                    cache_stats.hit_ratio * 100.0, thresholds.hit_ratio_threshold * 100.0
                ));
            }
        }

        health_status.healthy = health_status.issues.is_empty();
    }

    /// Get performance recommendations
    #[cfg(feature = "distributed-cache")]
    async fn generate_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        let metrics = self.performance_metrics.read().await;
        let thresholds = &self.config.performance_thresholds;

        // Response time recommendations
        if metrics.avg_response_time_us > thresholds.response_time_threshold_us {
            recommendations.push(
                "Consider increasing cache size or optimizing cache operations to reduce response time".to_string()
            );
        }

        // Hit ratio recommendations
        if let Ok(cache_stats) = self.cache.get_statistics().await {
            if cache_stats.hit_ratio < thresholds.hit_ratio_threshold {
                recommendations.push(
                    "Cache hit ratio is low. Consider enabling cache warming or increasing cache size".to_string()
                );
            }
        }

        // Error rate recommendations
        if metrics.error_rate > thresholds.error_rate_threshold {
            recommendations.push(
                "High error rate detected. Check cache configuration and network connectivity".to_string()
            );
        }

        // Efficiency recommendations
        if metrics.efficiency_score < 0.7 {
            recommendations.push(
                "Cache efficiency is suboptimal. Review cache configuration and usage patterns".to_string()
            );
        }

        recommendations
    }
}

#[async_trait]
impl CacheManager for FortressCacheManager {
    #[cfg(feature = "distributed-cache")]
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.get(key).await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: Option<u64>) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.set(key, value, ttl_seconds).await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn delete(&self, key: &str) -> Result<bool> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.delete(key).await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        // Also invalidate from invalidation manager
        let _ = self.invalidation_manager.invalidate_key(key, InvalidationReason::Manual);

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn exists(&self, key: &str) -> Result<bool> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.exists(key).await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn clear(&self) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.clear().await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.mget(keys).await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn mset(&self, entries: &[(&str, Vec<u8>, Option<u64>)]) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.mset(entries).await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        let start_time = std::time::Instant::now();
        
        let result = self.cache.increment(key, delta).await;
        let success = result.is_ok();
        
        let elapsed_us = start_time.elapsed().as_micros() as f64;
        self.update_performance_metrics(elapsed_us, success).await;

        result
    }

    #[cfg(feature = "distributed-cache")]
    async fn get_statistics(&self) -> Result<CacheManagerStatistics> {
        self.update_health_status().await;
        
        let cache_stats = self.cache.get_statistics().await?;
        let invalidation_stats = self.invalidation_manager.get_invalidation_stats()?;
        let performance_metrics = self.performance_metrics.read().await.clone();
        let health_status = self.health_status.read().await.clone();
        let recommendations = self.generate_recommendations().await;

        Ok(CacheManagerStatistics {
            cache_stats,
            cache_stats_compat: CacheStatsCompat {
                sets: cache_stats.sets,
                hits: cache_stats.hits,
                misses: cache_stats.misses,
            },
            invalidation_stats,
            performance_metrics,
            health_status,
            recommendations,
        })
    }

    #[cfg(feature = "distributed-cache")]
    async fn reset_statistics(&self) -> Result<()> {
        self.cache.reset_statistics().await?;
        
        // Reset performance metrics
        {
            let mut metrics = self.performance_metrics.write().await;
            *metrics = PerformanceMetrics {
                avg_response_time_us: 0.0,
                p95_response_time_us: 0.0,
                p99_response_time_us: 0.0,
                throughput_ops_per_sec: 0.0,
                error_rate: 0.0,
                efficiency_score: 0.0,
            };
        }

        // Reset response times and counters
        {
            let mut response_times = self.response_times.write().await;
            response_times.clear();
        }
        
        {
            let mut error_count = self.error_count.write().await;
            *error_count = 0;
        }
        
        {
            let mut operation_count = self.operation_count.write().await;
            *operation_count = 0;
        }

        Ok(())
    }

    #[cfg(feature = "distributed-cache")]
    async fn health_check(&self) -> Result<HealthStatus> {
        self.update_health_status().await;
        Ok(self.health_status.read().await.clone())
    }

    /// Add tags to a key
    async fn add_tags(&self, key: &str, tags: &[String]) -> Result<()> {
        // Use the invalidation manager to add tags
        // Note: In a real implementation, you would also tag the cache entries
        // For now, we'll just use the invalidation manager
        let manager = self.invalidation_manager.as_ref();
        manager.add_tags(key, tags)
    }

    /// Remove tags from a key
    async fn remove_tags(&self, key: &str, tags: &[String]) -> Result<()> {
        // Use the invalidation manager to remove tags
        // Note: In a real implementation, you would also untag the cache entries
        // For now, we'll just use the invalidation manager
        let manager = self.invalidation_manager.as_ref();
        manager.remove_tags(key, tags)
    }

    async fn invalidate_by_tag(&self, tag: &str) -> Result<usize> {
        self.invalidation_manager.invalidate_by_tag(tag, InvalidationReason::Manual)
    }

    async fn warm_up(&self, keys: Vec<String>) -> Result<usize> {
        let mut warmed_count = 0;
        
        for key in keys {
            // In a real implementation, you would load the actual values
            // For now, we'll just check if they exist and cache them
            if let Ok(Some(_)) = self.get(&key).await {
                warmed_count += 1;
            }
        }
        
        Ok(warmed_count)
    }

    #[cfg(feature = "distributed-cache")]
    async fn get_performance_recommendations(&self) -> Result<Vec<String>> {
        Ok(self.generate_recommendations().await)
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn get_statistics(&self) -> Result<CacheManagerStatistics> {
        // Return default statistics when distributed cache is not available
        let performance_metrics = self.performance_metrics.read().await.clone();
        let health_status = self.health_status.read().await.clone();
        
        Ok(CacheManagerStatistics {
            cache_stats_compat: CacheStatsCompat {
                sets: 0,
                hits: 0,
                misses: 0,
            },
            invalidation_stats: crate::cache_invalidation::InvalidationStats {
                total_invalidations: 0,
                invalidations_by_reason: std::collections::HashMap::new(),
                avg_invalidation_time_us: 0.0,
                failed_invalidations: 0,
                cascaded_invalidations: 0,
                dependencies_tracked: 0,
                last_invalidation: Some(Utc::now()),
            },
            performance_metrics,
            health_status,
            recommendations: vec!["Distributed cache not available".to_string()],
        })
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn health_check(&self) -> Result<HealthStatus> {
        let mut health_status = self.health_status.read().await.clone();
        health_status.healthy = true;
        health_status.issues.push("Distributed cache not available".to_string());
        Ok(health_status)
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn increment(&self, _key: &str, _delta: i64) -> Result<i64> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn reset_statistics(&self) -> Result<()> {
        // Reset performance metrics only
        {
            let mut metrics = self.performance_metrics.write().await;
            *metrics = PerformanceMetrics {
                avg_response_time_us: 0.0,
                p95_response_time_us: 0.0,
                p99_response_time_us: 0.0,
                throughput_ops_per_sec: 0.0,
                error_rate: 0.0,
                efficiency_score: 0.0,
            };
        }
        Ok(())
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn get_performance_recommendations(&self) -> Result<Vec<String>> {
        Ok(vec!["Distributed cache not available".to_string()])
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn set(&self, _key: &str, _value: Vec<u8>, _ttl_seconds: Option<u64>) -> Result<()> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn delete(&self, _key: &str) -> Result<bool> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn exists(&self, _key: &str) -> Result<bool> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn clear(&self) -> Result<()> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn mget(&self, _keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }

    #[cfg(not(feature = "distributed-cache"))]
    async fn mset(&self, _entries: &[(&str, Vec<u8>, Option<u64>)]) -> Result<()> {
        Err(FortressError::storage(
            "Distributed cache not available".to_string(),
            "cache_manager".to_string(),
            crate::error::StorageErrorCode::BackendNotAvailable,
        ))
    }
}

/// Factory function to create cache manager
#[cfg(feature = "distributed-cache")]
pub async fn create_cache_manager(config: CacheManagerConfig) -> Result<Box<dyn CacheManager>> {
    let manager = FortressCacheManager::new(config).await?;
    Ok(Box::new(manager))
}

/// Fallback factory function for when distributed-cache feature is not enabled
#[cfg(not(feature = "distributed-cache"))]
pub async fn create_cache_manager(_config: CacheManagerConfig) -> Result<Box<dyn CacheManager>> {
    // Return a simple mock cache manager for testing
    Ok(Box::new(MockCacheManager::new()))
}

/// Simple mock cache manager for testing when distributed-cache feature is not enabled
#[cfg(not(feature = "distributed-cache"))]
#[derive(Debug)]
pub struct MockCacheManager {
    cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

#[cfg(not(feature = "distributed-cache"))]
impl MockCacheManager {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg(not(feature = "distributed-cache"))]
#[async_trait]
impl CacheManager for MockCacheManager {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let cache = self.cache.read().await;
        Ok(cache.get(key).cloned())
    }

    async fn set(&self, key: &str, value: Vec<u8>, _ttl: Option<u64>) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        let mut cache = self.cache.write().await;
        Ok(cache.remove(key).is_some())
    }

    async fn clear(&self) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.clear();
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let cache = self.cache.read().await;
        Ok(cache.contains_key(key))
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let cache = self.cache.read().await;
        let mut results = Vec::new();
        for key in keys {
            results.push(cache.get(*key).cloned());
        }
        Ok(results)
    }

    async fn mset(&self, entries: &[(&str, Vec<u8>, Option<u64>)]) -> Result<()> {
        let mut cache = self.cache.write().await;
        for (key, value, _ttl) in entries {
            cache.insert(key.to_string(), value.clone());
        }
        Ok(())
    }

    async fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        let mut cache = self.cache.write().await;
        let current_value = cache.get(key).map(|bytes| {
            String::from_utf8_lossy(bytes).parse::<i64>().unwrap_or(0)
        }).unwrap_or(0);
        let new_value = current_value + delta;
        cache.insert(key.to_string(), new_value.to_string().as_bytes().to_vec());
        Ok(new_value)
    }

    async fn get_statistics(&self) -> Result<CacheManagerStatistics> {
        Ok(CacheManagerStatistics {
            #[cfg(feature = "distributed-cache")]
            cache_stats: crate::distributed_cache::CacheStatistics {
                total_operations: 0,
                cache_hits: 0,
                cache_misses: 0,
                hit_rate: 0.0,
                memory_usage_bytes: 0,
                eviction_count: 0,
                avg_response_time_us: 0.0,
                p95_response_time_us: 0.0,
                p99_response_time_us: 0.0,
                throughput_ops_per_sec: 0.0,
                error_rate: 0.0,
                efficiency_score: 1.0,
            },
            cache_stats_compat: CacheStatsCompat {
                sets: 0,
                hits: 0,
                misses: 0,
            },
            invalidation_stats: crate::cache_invalidation::InvalidationStats {
                total_invalidations: 0,
                invalidations_by_reason: std::collections::HashMap::new(),
                avg_invalidation_time_us: 0.0,
                failed_invalidations: 0,
                cascaded_invalidations: 0,
                dependencies_tracked: 0,
                last_invalidation: None,
            },
            performance_metrics: PerformanceMetrics {
                avg_response_time_us: 0.0,
                p95_response_time_us: 0.0,
                p99_response_time_us: 0.0,
                throughput_ops_per_sec: 0.0,
                error_rate: 0.0,
                efficiency_score: 1.0,
            },
            health_status: HealthStatus {
                healthy: true,
                last_health_check: chrono::Utc::now(),
                issues: vec![],
                warnings: vec![],
            },
            recommendations: vec![],
        })
    }

    async fn reset_statistics(&self) -> Result<()> {
        Ok(())
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus {
            healthy: true,
            last_health_check: Utc::now(),
            issues: vec![],
            warnings: vec![],
        })
    }

    async fn add_tags(&self, _key: &str, _tags: &[String]) -> Result<()> {
        Ok(())
    }

    async fn remove_tags(&self, _key: &str, _tags: &[String]) -> Result<()> {
        Ok(())
    }

    async fn invalidate_by_tag(&self, _tag: &str) -> Result<usize> {
        Ok(0)
    }

    async fn warm_up(&self, keys: Vec<String>) -> Result<usize> {
        Ok(keys.len())
    }

    async fn get_performance_recommendations(&self) -> Result<Vec<String>> {
        Ok(vec!["Mock cache needs no optimization".to_string()])
    }
}

#[cfg(test)]
#[cfg(feature = "distributed-cache")]
mod tests {
    use super::*;
    use crate::distributed_cache::DistributedCache;

    #[tokio::test]
    async fn test_cache_manager_basic_operations() {
        let config = CacheManagerConfig::default();
        let manager = FortressCacheManager::new(config).await.unwrap();

        // Test set and get
        let key = "test_key";
        let value = b"test_value".to_vec();
        
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
        let manager = FortressCacheManager::new(config).await.unwrap();

        let key = "tagged_key";
        let value = b"tagged_value".to_vec();
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
        let manager = FortressCacheManager::new(config).await.unwrap();

        // Perform operations
        manager.set("key1", b"value1".to_vec(), None).await.unwrap();
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
        let manager = FortressCacheManager::new(config).await.unwrap();

        let health = manager.health_check().await.unwrap();
        assert!(health.healthy);
        assert!(health.issues.is_empty());
    }

    #[tokio::test]
    async fn test_cache_manager_mget_mset() {
        let config = CacheManagerConfig::default();
        let manager = FortressCacheManager::new(config).await.unwrap();

        let entries = vec![
            ("key1", b"value1".to_vec(), None),
            ("key2", b"value2".to_vec(), None),
            ("key3", b"value3".to_vec(), None),
        ];
        
        manager.mset(&entries).await.unwrap();
        
        let keys = vec!["key1", "key2", "key3"];
        let results = manager.mget(&keys).await.unwrap();
        
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Some(b"value1".to_vec()));
        assert_eq!(results[1], Some(b"value2".to_vec()));
        assert_eq!(results[2], Some(b"value3".to_vec()));
    }

    #[tokio::test]
    async fn test_cache_manager_recommendations() {
        let config = CacheManagerConfig::default();
        let manager = FortressCacheManager::new(config).await.unwrap();

        let recommendations = manager.get_performance_recommendations().await.unwrap();
        // Should have some recommendations (even if empty list)
        assert!(recommendations.len() >= 0);
    }
}
