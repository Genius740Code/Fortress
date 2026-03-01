//! Key preloading system for high-performance key access
//!
//! This module provides configurable key preloading capabilities to minimize
//! decryption overhead during runtime operations.

use crate::error::Result;
use crate::key::{KeyId, KeyMetadata, SecureKey};
use crate::key_database::KeyDatabase;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for key preloading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPreloadConfig {
    /// Enable key preloading on startup
    pub enable_preload: bool,
    /// Preload all keys (use with caution for large key sets)
    pub preload_all_keys: bool,
    /// Preload frequently used keys based on access patterns
    pub preload_frequently_used: bool,
    /// Preload keys based on their purpose/classification
    pub preload_by_purpose: bool,
    /// Maximum number of keys to preload (memory limit)
    pub max_keys_to_preload: usize,
    /// Maximum memory usage for preloaded keys in bytes
    pub max_memory_usage_bytes: usize,
    /// Preload keys that expire within this duration
    pub preload_expiring_soon: Duration,
    /// Key purposes to prioritize for preloading
    pub priority_purposes: Vec<String>,
    /// Preload keys with specific performance profiles
    pub priority_performance_profiles: Vec<String>,
    /// Enable background preloading
    pub enable_background_preload: bool,
    /// Background preload interval
    pub background_preload_interval: Duration,
    /// Preload statistics tracking
    pub track_preload_stats: bool,
}

impl Default for KeyPreloadConfig {
    fn default() -> Self {
        Self {
            enable_preload: true,
            preload_all_keys: false,
            preload_frequently_used: true,
            preload_by_purpose: true,
            max_keys_to_preload: 1000,
            max_memory_usage_bytes: 100 * 1024 * 1024, // 100MB
            preload_expiring_soon: Duration::hours(24),
            priority_purposes: vec![
                "encryption".to_string(),
                "authentication".to_string(),
                "session".to_string(),
            ],
            priority_performance_profiles: vec![
                "lightning".to_string(),
                "balanced".to_string(),
            ],
            enable_background_preload: true,
            background_preload_interval: Duration::minutes(30),
            track_preload_stats: true,
        }
    }
}

/// Preloading strategy for different key types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PreloadStrategy {
    /// Preload all keys regardless of type
    All,
    /// Preload only frequently used keys
    FrequentlyUsed,
    /// Preload keys by purpose/classification
    ByPurpose,
    /// Preload keys that will expire soon
    ExpiringSoon,
    /// Preload keys with specific performance profiles
    ByPerformanceProfile,
    /// Custom preloading logic
    Custom(String),
}

impl PreloadStrategy {
    /// Get a string representation of the strategy
    pub fn as_str(&self) -> &str {
        match self {
            PreloadStrategy::All => "all",
            PreloadStrategy::FrequentlyUsed => "frequently_used",
            PreloadStrategy::ByPurpose => "by_purpose",
            PreloadStrategy::ExpiringSoon => "expiring_soon",
            PreloadStrategy::ByPerformanceProfile => "by_performance_profile",
            PreloadStrategy::Custom(name) => name,
        }
    }
}

/// Key access statistics for preloading decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAccessStats {
    /// Number of times the key was accessed
    pub access_count: u64,
    /// Last access time
    pub last_accessed: DateTime<Utc>,
    /// First access time
    pub first_accessed: DateTime<Utc>,
    /// Average access frequency (accesses per hour)
    pub access_frequency: f64,
    /// Key size in bytes
    pub key_size_bytes: usize,
    /// Whether the key is currently preloaded
    pub is_preloaded: bool,
}

/// Preloading statistics and metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreloadStats {
    /// Total number of keys preloaded
    pub total_preloaded_keys: usize,
    /// Total memory used for preloaded keys
    pub total_memory_usage_bytes: usize,
    /// Number of keys that couldn't be preloaded due to limits
    pub skipped_keys_due_to_limits: usize,
    /// Preloading success rate
    pub preload_success_rate: f64,
    /// Average preloading time in milliseconds
    pub avg_preload_time_ms: f64,
    /// Last preload time
    pub last_preload_time: Option<DateTime<Utc>>,
    /// Keys preloaded by strategy
    pub keys_by_strategy: HashMap<PreloadStrategy, usize>,
    /// Memory usage by strategy
    pub memory_by_strategy: HashMap<PreloadStrategy, usize>,
}

/// Advanced key preloader with configurable strategies
pub struct KeyPreloader {
    database: Arc<dyn KeyDatabase>,
    config: KeyPreloadConfig,
    access_stats: Arc<RwLock<HashMap<KeyId, KeyAccessStats>>>,
    preloaded_keys: Arc<RwLock<HashMap<KeyId, SecureKey>>>,
    preload_metadata: Arc<RwLock<HashMap<KeyId, KeyMetadata>>>,
    stats: Arc<RwLock<PreloadStats>>,
    background_task: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl KeyPreloader {
    /// Create a new key preloader
    pub fn new(database: Arc<dyn KeyDatabase>, config: KeyPreloadConfig) -> Self {
        Self {
            database,
            config,
            access_stats: Arc::new(RwLock::new(HashMap::new())),
            preloaded_keys: Arc::new(RwLock::new(HashMap::new())),
            preload_metadata: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PreloadStats {
                total_preloaded_keys: 0,
                total_memory_usage_bytes: 0,
                skipped_keys_due_to_limits: 0,
                preload_success_rate: 0.0,
                avg_preload_time_ms: 0.0,
                last_preload_time: None,
                keys_by_strategy: HashMap::new(),
                memory_by_strategy: HashMap::new(),
            })),
            background_task: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize the preloader and start background tasks
    pub async fn initialize(&self) -> Result<()> {
        if self.config.enable_preload {
            // Perform initial preload
            self.perform_initial_preload().await?;

            // Start background preloading if enabled
            if self.config.enable_background_preload {
                self.start_background_preloading().await?;
            }
        }
        Ok(())
    }

    /// Perform initial preloading based on configuration
    async fn perform_initial_preload(&self) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        if self.config.preload_all_keys {
            self.preload_all_keys().await?;
        } else {
            // Load keys based on strategies
            if self.config.preload_frequently_used {
                self.preload_frequently_used_keys().await?;
            }
            
            if self.config.preload_by_purpose {
                self.preload_keys_by_purpose().await?;
            }
            
            self.preload_expiring_keys().await?;
        }

        let elapsed = start_time.elapsed();
        self.update_preload_stats(elapsed).await;
        
        Ok(())
    }

    /// Preload all keys from the database
    async fn preload_all_keys(&self) -> Result<usize> {
        let all_keys = self.database.preload_keys().await?;
        let mut preloaded_count = 0;
        let mut current_memory = 0;

        for (key_id, key, metadata) in all_keys {
            if current_memory + key.len() > self.config.max_memory_usage_bytes {
                break;
            }
            
            if preloaded_count >= self.config.max_keys_to_preload {
                break;
            }

            let key_len = key.len();
            self.preload_key(key_id, key, metadata, PreloadStrategy::All).await?;
            preloaded_count += 1;
            current_memory += key_len;
        }

        Ok(preloaded_count)
    }

    /// Preload frequently used keys based on access statistics
    async fn preload_frequently_used_keys(&self) -> Result<usize> {
        let stats = self.access_stats.read().await;
        let mut frequent_keys: Vec<_> = stats
            .iter()
            .filter(|(_, access_stats)| access_stats.access_frequency > 1.0) // More than 1 access per hour
            .collect();
        
        // Sort by access frequency (descending)
        frequent_keys.sort_by(|a, b| b.1.access_frequency.partial_cmp(&a.1.access_frequency).unwrap());

        let mut preloaded_count = 0;
        let mut current_memory = 0;

        for (key_id, _) in frequent_keys {
            if current_memory > self.config.max_memory_usage_bytes {
                break;
            }
            
            if preloaded_count >= self.config.max_keys_to_preload {
                break;
            }

            if let Some((key, metadata)) = self.database.retrieve_key(key_id).await? {
                if current_memory + key.len() > self.config.max_memory_usage_bytes {
                    break;
                }

                let key_len = key.len();
                self.preload_key(key_id.clone(), key, metadata, PreloadStrategy::FrequentlyUsed).await?;
                preloaded_count += 1;
                current_memory += key_len;
            }
        }

        Ok(preloaded_count)
    }

    /// Preload keys by their purpose
    async fn preload_keys_by_purpose(&self) -> Result<usize> {
        let all_keys = self.database.list_keys().await?;
        let mut preloaded_count = 0;
        let mut current_memory = 0;

        for (key_id, metadata) in all_keys {
            if current_memory > self.config.max_memory_usage_bytes {
                break;
            }
            
            if preloaded_count >= self.config.max_keys_to_preload {
                break;
            }

            // Check if this key's purpose is in our priority list
            if self.config.priority_purposes.contains(&metadata.purpose) {
                if let Some((key, _)) = self.database.retrieve_key(&key_id).await? {
                    if current_memory + key.len() > self.config.max_memory_usage_bytes {
                        break;
                    }

                    let key_len = key.len();
                    self.preload_key(key_id.clone(), key, metadata, PreloadStrategy::ByPurpose).await?;
                    preloaded_count += 1;
                    current_memory += key_len;
                }
            }
        }

        Ok(preloaded_count)
    }

    /// Preload keys that will expire soon
    async fn preload_expiring_keys(&self) -> Result<usize> {
        let all_keys = self.database.list_keys().await?;
        let now = Utc::now();
        let mut preloaded_count = 0;
        let mut current_memory = 0;

        for (key_id, metadata) in all_keys {
            if current_memory > self.config.max_memory_usage_bytes {
                break;
            }
            
            if preloaded_count >= self.config.max_keys_to_preload {
                break;
            }

            // Check if key expires within the configured threshold
            if metadata.expires_at - now < self.config.preload_expiring_soon {
                if let Some((key, _)) = self.database.retrieve_key(&key_id).await? {
                    if current_memory + key.len() > self.config.max_memory_usage_bytes {
                        break;
                    }

                    let key_len = key.len();
                    self.preload_key(key_id.clone(), key, metadata, PreloadStrategy::ExpiringSoon).await?;
                    preloaded_count += 1;
                    current_memory += key_len;
                }
            }
        }

        Ok(preloaded_count)
    }

    /// Preload a specific key into memory
    async fn preload_key(&self, key_id: KeyId, key: SecureKey, metadata: KeyMetadata, strategy: PreloadStrategy) -> Result<()> {
        let mut preloaded_keys = self.preloaded_keys.write().await;
        let mut preload_metadata = self.preload_metadata.write().await;
        let mut access_stats = self.access_stats.write().await;

        // Store the preloaded key and metadata
        preloaded_keys.insert(key_id.clone(), key);
        preload_metadata.insert(key_id.clone(), metadata.clone());

        // Update access statistics
        let stats = access_stats.entry(key_id.clone()).or_insert(KeyAccessStats {
            access_count: 0,
            last_accessed: Utc::now(),
            first_accessed: Utc::now(),
            access_frequency: 0.0,
            key_size_bytes: metadata.algorithm.len(), // Approximate size
            is_preloaded: true,
        });
        stats.is_preloaded = true;

        // Update strategy statistics
        if self.config.track_preload_stats {
            let mut stats_guard = self.stats.write().await;
            *stats_guard.keys_by_strategy.entry(strategy.clone()).or_insert(0) += 1;
            *stats_guard.memory_by_strategy.entry(strategy).or_insert(0) += metadata.algorithm.len();
        }

        Ok(())
    }

    /// Get a preloaded key if available
    pub async fn get_preloaded_key(&self, key_id: &KeyId) -> Option<(SecureKey, KeyMetadata)> {
        // Record access
        self.record_key_access(key_id).await;

        let preloaded_keys = self.preloaded_keys.read().await;
        let preload_metadata = self.preload_metadata.read().await;

        if let Some(key) = preloaded_keys.get(key_id) {
            if let Some(metadata) = preload_metadata.get(key_id) {
                return Some((key.clone(), metadata.clone()));
            }
        }

        None
    }

    /// Record key access for statistics
    async fn record_key_access(&self, key_id: &KeyId) {
        if !self.config.track_preload_stats {
            return;
        }

        let mut stats = self.access_stats.write().await;
        let now = Utc::now();
        
        let entry = stats.entry(key_id.clone()).or_insert(KeyAccessStats {
            access_count: 0,
            last_accessed: now,
            first_accessed: now,
            access_frequency: 0.0,
            key_size_bytes: 0,
            is_preloaded: false,
        });

        entry.access_count += 1;
        entry.last_accessed = now;

        // Calculate access frequency (accesses per hour)
        let duration_hours = (now - entry.first_accessed).num_hours() as f64;
        if duration_hours > 0.0 {
            entry.access_frequency = entry.access_count as f64 / duration_hours;
        }
    }

    /// Start background preloading task
    async fn start_background_preloading(&self) -> Result<()> {
        let database = self.database.clone();
        let config = self.config.clone();
        let access_stats = self.access_stats.clone();
        let preloaded_keys = self.preloaded_keys.clone();
        let preload_metadata = self.preload_metadata.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.background_preload_interval.to_std().unwrap());
            
            loop {
                interval.tick().await;
                
                // Perform background preload
                if let Err(e) = Self::background_preload_task(
                    &database,
                    &config,
                    &access_stats,
                    &preloaded_keys,
                    &preload_metadata,
                ).await {
                    eprintln!("Background preload error: {}", e);
                }
            }
        });

        let mut background_task = self.background_task.write().await;
        *background_task = Some(handle);

        Ok(())
    }

    /// Background preload task implementation
    async fn background_preload_task(
        database: &Arc<dyn KeyDatabase>,
        config: &KeyPreloadConfig,
        access_stats: &Arc<RwLock<HashMap<KeyId, KeyAccessStats>>>,
        preloaded_keys: &Arc<RwLock<HashMap<KeyId, SecureKey>>>,
        preload_metadata: &Arc<RwLock<HashMap<KeyId, KeyMetadata>>>,
    ) -> Result<()> {
        // Get current memory usage
        let current_keys = preloaded_keys.read().await;
        let current_memory: usize = current_keys.values().map(|key| key.len()).sum();
        drop(current_keys);

        // If we're under memory limits, preload more keys
        if current_memory < config.max_memory_usage_bytes {
            // Find keys that should be preloaded but aren't
            let all_keys = database.list_keys().await?;
            let preloaded_set: HashSet<_> = preloaded_keys.read().await.keys().cloned().collect();
            
            for (key_id, metadata) in all_keys {
                if preloaded_set.contains(&key_id) {
                    continue;
                }

                // Check if this key should be preloaded
                if Self::should_preload_key(&key_id, &metadata, config, access_stats).await? {
                    if let Some((key, _)) = database.retrieve_key(&key_id).await? {
                        // Check memory limit
                        if current_memory + key.len() > config.max_memory_usage_bytes {
                            break;
                        }

                        // Preload the key
                        let mut preloaded = preloaded_keys.write().await;
                        let mut preloaded_meta = preload_metadata.write().await;
                        preloaded.insert(key_id.clone(), key);
                        preloaded_meta.insert(key_id.clone(), metadata);
                    }
                }
            }
        }

        Ok(())
    }

    /// Determine if a key should be preloaded
    async fn should_preload_key(
        key_id: &KeyId,
        metadata: &KeyMetadata,
        config: &KeyPreloadConfig,
        access_stats: &Arc<RwLock<HashMap<KeyId, KeyAccessStats>>>,
    ) -> Result<bool> {
        // Check priority purposes
        if config.priority_purposes.contains(&metadata.purpose) {
            return Ok(true);
        }

        // Check if key expires soon
        let now = Utc::now();
        if metadata.expires_at - now < config.preload_expiring_soon {
            return Ok(true);
        }

        // Check access frequency
        if config.preload_frequently_used {
            let stats = access_stats.read().await;
            if let Some(access_stats) = stats.get(key_id) {
                if access_stats.access_frequency > 1.0 {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Update preloading statistics
    async fn update_preload_stats(&self, elapsed: std::time::Duration) {
        let mut stats = self.stats.write().await;
        
        let preloaded_keys = self.preloaded_keys.read().await;
        stats.total_preloaded_keys = preloaded_keys.len();
        stats.total_memory_usage_bytes = preloaded_keys.values().map(|key| key.len()).sum();
        stats.last_preload_time = Some(Utc::now());
        
        let elapsed_ms = elapsed.as_millis() as f64;
        if stats.total_preloaded_keys > 0 {
            stats.avg_preload_time_ms = elapsed_ms / stats.total_preloaded_keys as f64;
        }
        
        stats.preload_success_rate = if stats.total_preloaded_keys > 0 {
            1.0 // All attempted preloads were successful
        } else {
            0.0
        };
    }

    /// Get current preloading statistics
    pub async fn get_stats(&self) -> PreloadStats {
        self.stats.read().await.clone()
    }

    /// Get access statistics for all keys
    pub async fn get_access_stats(&self) -> HashMap<KeyId, KeyAccessStats> {
        self.access_stats.read().await.clone()
    }

    /// Force preload a specific key
    pub async fn force_preload_key(&self, key_id: &KeyId) -> Result<bool> {
        if let Some((key, metadata)) = self.database.retrieve_key(key_id).await? {
            self.preload_key(key_id.clone(), key, metadata, PreloadStrategy::Custom("force".to_string())).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Evict a key from the preload cache
    pub async fn evict_key(&self, key_id: &KeyId) -> Result<bool> {
        let mut preloaded_keys = self.preloaded_keys.write().await;
        let mut preload_metadata = self.preload_metadata.write().await;
        let mut access_stats = self.access_stats.write().await;

        let key_evicted = preloaded_keys.remove(key_id).is_some();
        preload_metadata.remove(key_id);
        
        if let Some(stats) = access_stats.get_mut(key_id) {
            stats.is_preloaded = false;
        }

        Ok(key_evicted)
    }

    /// Clear all preloaded keys
    pub async fn clear_preloaded_keys(&self) -> Result<usize> {
        let mut preloaded_keys = self.preloaded_keys.write().await;
        let mut preload_metadata = self.preload_metadata.write().await;
        let mut access_stats = self.access_stats.write().await;

        let count = preloaded_keys.len();
        preloaded_keys.clear();
        preload_metadata.clear();
        
        // Update all access stats to reflect not preloaded
        for stats in access_stats.values_mut() {
            stats.is_preloaded = false;
        }

        Ok(count)
    }

    /// Shutdown the preloader and cleanup background tasks
    pub async fn shutdown(&self) -> Result<()> {
        // Cancel background task
        let mut background_task = self.background_task.write().await;
        if let Some(handle) = background_task.take() {
            handle.abort();
        }

        // Clear preloaded keys
        self.clear_preloaded_keys().await?;

        Ok(())
    }
}

impl std::fmt::Debug for KeyPreloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPreloader")
            .field("config", &self.config)
            .field("preloaded_keys_count", &self.preloaded_keys.try_read().map(|g| g.len()).unwrap_or(0))
            .field("access_stats_count", &self.access_stats.try_read().map(|g| g.len()).unwrap_or(0))
            .finish()
    }
}
