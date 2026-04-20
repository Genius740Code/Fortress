//! Predictive Cache Warming and Intelligent Cache Strategies
//!
//! This module implements advanced caching mechanisms including:
//! - Predictive cache warming based on access patterns
//! - Intelligent cache eviction policies
//! - Cache hit ratio optimization
//! - Machine learning-based cache prediction

use crate::error::{FortressError, Result};
use crate::cache::Cache;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Mutex};
use uuid::Uuid;

/// Access pattern data for cache prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    /// Cache key
    pub key: String,
    /// Access frequency (per hour)
    pub frequency: f64,
    /// Last access timestamp
    pub last_access: SystemTime,
    /// Access intervals (in seconds)
    pub intervals: VecDeque<u64>,
    /// Predicted next access time
    pub predicted_next_access: Option<SystemTime>,
    /// Cache priority score
    pub priority_score: f64,
    /// Seasonal pattern detected
    pub seasonal_pattern: bool,
}

impl AccessPattern {
    /// Create new access pattern
    pub fn new(key: String) -> Self {
        Self {
            key,
            frequency: 0.0,
            last_access: SystemTime::now(),
            intervals: VecDeque::with_capacity(10),
            predicted_next_access: None,
            priority_score: 0.0,
            seasonal_pattern: false,
        }
    }

    /// Record access and update pattern
    pub fn record_access(&mut self) {
        let now = SystemTime::now();
        
        // Update interval history
        if let Ok(duration) = now.duration_since(self.last_access) {
            let interval_secs = duration.as_secs();
            self.intervals.push_back(interval_secs);
            
            // Keep only last 10 intervals
            if self.intervals.len() > 10 {
                self.intervals.pop_front();
            }
            
            // Update frequency (exponential moving average)
            let new_frequency = 3600.0 / interval_secs as f64;
            if self.frequency == 0.0 {
                self.frequency = new_frequency;
            } else {
                self.frequency = 0.7 * self.frequency + 0.3 * new_frequency;
            }
        }
        
        self.last_access = now;
        self.update_priority_score();
        self.predict_next_access();
    }

    /// Update priority score based on multiple factors
    fn update_priority_score(&mut self) {
        let frequency_score = (self.frequency / 60.0).min(10.0); // Max 10 points for frequency
        let recency_score = if let Ok(duration) = SystemTime::now().duration_since(self.last_access) {
            let hours_ago = duration.as_secs() as f64 / 3600.0;
            (10.0 - hours_ago).max(0.0) // Decay over time
        } else {
            0.0
        };
        
        let consistency_score = if self.intervals.len() >= 3 {
            let intervals: Vec<u64> = self.intervals.iter().cloned().collect();
            let mean = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
            let variance = intervals.iter()
                .map(|&x| (x as f64 - mean).powi(2))
                .sum::<f64>() / intervals.len() as f64;
            let std_dev = variance.sqrt();
            
            // Higher score for more consistent access patterns
            (1.0 / (1.0 + std_dev / mean)).min(10.0) * 10.0
        } else {
            5.0 // Neutral score for insufficient data
        };
        
        self.priority_score = frequency_score + recency_score + consistency_score;
    }

    /// Predict next access time using pattern analysis
    fn predict_next_access(&mut self) {
        if self.intervals.len() < 3 {
            self.predicted_next_access = None;
            return;
        }

        let intervals: Vec<u64> = self.intervals.iter().cloned().collect();
        
        // Use weighted average of recent intervals
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        
        for (i, &interval) in intervals.iter().enumerate() {
            let weight = (i + 1) as f64; // More recent intervals have higher weight
            weighted_sum += interval as f64 * weight;
            total_weight += weight;
        }
        
        let predicted_interval = weighted_sum / total_weight;
        
        if let Ok(next_access) = self.last_access.duration_since(UNIX_EPOCH) {
            let next_access_timestamp = next_access.as_secs() + predicted_interval as u64;
            self.predicted_next_access = Some(UNIX_EPOCH + Duration::from_secs(next_access_timestamp));
        }
    }

    /// Check if cache should be warmed up
    pub fn should_warm_up(&self) -> bool {
        // High priority items should always be warmed
        if self.priority_score > 15.0 {
            return true;
        }

        // Check if predicted access is soon (within 5 minutes)
        if let Some(predicted) = self.predicted_next_access {
            if let Ok(duration) = predicted.duration_since(SystemTime::now()) {
                return duration.as_secs() < 300; // 5 minutes
            }
        }

        // Warm up frequently accessed items
        self.frequency > 10.0 // More than 10 accesses per hour
    }
}

/// Cache predictor trait for different prediction strategies
pub trait CachePredictor: Send + Sync {
    /// Predict which keys should be warmed up
    async fn predict_warmup_keys(&self, patterns: &HashMap<String, AccessPattern>) -> Vec<String>;
    
    /// Update predictor with new access data
    async fn update_patterns(&mut self, patterns: HashMap<String, AccessPattern>);
}

/// Simple frequency-based cache predictor
pub struct FrequencyPredictor {
    threshold: f64,
}

impl FrequencyPredictor {
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }
}

impl CachePredictor for FrequencyPredictor {
    async fn predict_warmup_keys(&self, patterns: &HashMap<String, AccessPattern>) -> Vec<String> {
        patterns
            .iter()
            .filter(|(_, pattern)| pattern.frequency > self.threshold)
            .map(|(key, _)| key.clone())
            .collect()
    }

    async fn update_patterns(&mut self, _patterns: HashMap<String, AccessPattern>) {
        // Frequency predictor doesn't need internal state updates
    }
}

/// ML-based cache predictor using pattern recognition
pub struct MLPredictor {
    model_weights: HashMap<String, f64>,
    learning_rate: f64,
}

impl MLPredictor {
    pub fn new() -> Self {
        Self {
            model_weights: HashMap::new(),
            learning_rate: 0.01,
        }
    }

    /// Calculate prediction score for a pattern
    fn calculate_score(&self, pattern: &AccessPattern) -> f64 {
        let mut score = 0.0;
        
        // Frequency weight
        score += pattern.frequency * self.model_weights.get("frequency").unwrap_or(&1.0);
        
        // Priority weight
        score += pattern.priority_score * self.model_weights.get("priority").unwrap_or(&0.5);
        
        // Recency weight
        if let Ok(duration) = SystemTime::now().duration_since(pattern.last_access) {
            let recency_score = (3600.0 - duration.as_secs() as f64).max(0.0) / 3600.0;
            score += recency_score * self.model_weights.get("recency").unwrap_or(&0.3);
        }
        
        // Consistency weight
        if pattern.intervals.len() >= 3 {
            let intervals: Vec<f64> = pattern.intervals.iter().map(|&x| x as f64).collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let variance = intervals.iter()
                .map(|&x| (x - mean).powi(2))
                .sum::<f64>() / intervals.len() as f64;
            let consistency = (1.0 / (1.0 + variance.sqrt())).min(1.0);
            score += consistency * self.model_weights.get("consistency").unwrap_or(&0.2);
        }
        
        score
    }

    /// Update model weights based on cache hit feedback
    fn update_weights(&mut self, hit_rate: f64) {
        let adjustment = if hit_rate < 0.8 { self.learning_rate } else { -self.learning_rate * 0.5 };
        
        for weight in self.model_weights.values_mut() {
            *weight += adjustment;
            *weight = weight.max(0.1).min(2.0); // Keep weights in reasonable range
        }
        
        // Initialize default weights if not present
        self.model_weights.entry("frequency".to_string()).or_insert(1.0);
        self.model_weights.entry("priority".to_string()).or_insert(0.5);
        self.model_weights.entry("recency".to_string()).or_insert(0.3);
        self.model_weights.entry("consistency".to_string()).or_insert(0.2);
    }
}

impl CachePredictor for MLPredictor {
    async fn predict_warmup_keys(&self, patterns: &HashMap<String, AccessPattern>) -> Vec<String> {
        let mut scored_keys: Vec<(String, f64)> = patterns
            .iter()
            .map(|(key, pattern)| (key.clone(), self.calculate_score(pattern)))
            .collect();
        
        // Sort by score (descending) and take top 20%
        scored_keys.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let take_count = (patterns.len() as f64 * 0.2).ceil() as usize;
        
        scored_keys
            .into_iter()
            .take(take_count)
            .map(|(key, _)| key)
            .collect()
    }

    async fn update_patterns(&mut self, patterns: HashMap<String, AccessPattern>) {
        // Calculate current hit rate based on patterns
        let hit_rate = if patterns.is_empty() {
            0.0
        } else {
            let high_priority_count = patterns.values()
                .filter(|p| p.priority_score > 10.0)
                .count();
            high_priority_count as f64 / patterns.len() as f64
        };
        
        self.update_weights(hit_rate);
    }
}

/// Predictive cache manager with intelligent warming
pub struct PredictiveCache {
    /// Access patterns for cache prediction
    access_patterns: Arc<RwLock<HashMap<String, AccessPattern>>>,
    /// Cache predictor strategy
    predictor: Arc<Mutex<Box<dyn CachePredictor>>>,
    /// Cache implementation
    cache: Arc<dyn crate::cache::Cache>,
    /// Warmup task handle
    warmup_handle: Option<tokio::task::JoinHandle<()>>,
    /// Configuration
    config: PredictiveCacheConfig,
}

/// Configuration for predictive cache
#[derive(Debug, Clone)]
pub struct PredictiveCacheConfig {
    /// Enable predictive warming
    pub enable_predictive_warming: bool,
    /// Warmup interval in seconds
    pub warmup_interval_secs: u64,
    /// Maximum keys to warm up per cycle
    pub max_warmup_keys: usize,
    /// Pattern retention duration in hours
    pub pattern_retention_hours: u64,
    /// Minimum access frequency for tracking
    pub min_access_frequency: f64,
}

impl Default for PredictiveCacheConfig {
    fn default() -> Self {
        Self {
            enable_predictive_warming: true,
            warmup_interval_secs: 300, // 5 minutes
            max_warmup_keys: 100,
            pattern_retention_hours: 24,
            min_access_frequency: 0.1, // At least 1 access per 10 hours
        }
    }
}

impl PredictiveCache {
    /// Create new predictive cache
    pub fn new(cache: Arc<dyn crate::cache::Cache>, config: PredictiveCacheConfig) -> Self {
        let predictor: Box<dyn CachePredictor> = Box::new(MLPredictor::new());
        
        Self {
            access_patterns: Arc::new(RwLock::new(HashMap::new())),
            predictor: Arc::new(Mutex::new(predictor)),
            cache,
            warmup_handle: None,
            config,
        }
    }

    /// Start predictive cache warming
    pub async fn start_warming(&mut self) -> Result<()> {
        if !self.config.enable_predictive_warming {
            return Ok(());
        }

        let access_patterns = self.access_patterns.clone();
        let predictor = self.predictor.clone();
        let cache = self.cache.clone();
        let config = self.config.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.warmup_interval_secs));
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::perform_warmup_cycle(&access_patterns, &predictor, &cache, &config).await {
                    tracing::error!("Cache warmup cycle failed: {}", e);
                }
            }
        });
        
        self.warmup_handle = Some(handle);
        tracing::info!("Predictive cache warming started");
        Ok(())
    }

    /// Perform one warmup cycle
    async fn perform_warmup_cycle(
        access_patterns: &Arc<RwLock<HashMap<String, AccessPattern>>>,
        predictor: &Arc<Mutex<Box<dyn CachePredictor>>>,
        cache: &Arc<dyn crate::cache::Cache>,
        config: &PredictiveCacheConfig,
    ) -> Result<()> {
        // Clean old patterns
        Self::cleanup_old_patterns(access_patterns, config.pattern_retention_hours).await;
        
        // Get patterns and predict warmup keys
        let patterns = access_patterns.read().await;
        let mut predictor_guard = predictor.lock().await;
        let warmup_keys = predictor_guard.predict_warmup_keys(&patterns).await;
        drop(predictor_guard);
        drop(patterns);
        
        // Limit number of keys to warm up
        let keys_to_warm: Vec<String> = warmup_keys
            .into_iter()
            .take(config.max_warmup_keys)
            .collect();
        
        tracing::info!("Warming up {} cache keys", keys_to_warm.len());
        
        // Warm up each key (this would trigger actual data loading)
        for key in keys_to_warm {
            if let Err(e) = Self::warm_cache_key(cache, &key).await {
                tracing::warn!("Failed to warm cache key '{}': {}", key, e);
            }
        }
        
        Ok(())
    }

    /// Warm up a specific cache key
    async fn warm_cache_key(cache: &Arc<dyn crate::cache::Cache>, key: &str) -> Result<()> {
        // This would trigger the actual data loading for the key
        // Implementation depends on the specific cache backend
        cache.get(key).await?;
        Ok(())
    }

    /// Clean up old access patterns
    async fn cleanup_old_patterns(
        access_patterns: &Arc<RwLock<HashMap<String, AccessPattern>>>,
        retention_hours: u64,
    ) {
        let mut patterns = access_patterns.write().await;
        let cutoff_time = SystemTime::now() - Duration::from_secs(retention_hours * 3600);
        
        patterns.retain(|_, pattern| {
            pattern.last_access > cutoff_time && pattern.frequency >= 0.1
        });
    }

    /// Record cache access for pattern learning
    pub async fn record_access(&self, key: &str) {
        let mut patterns = self.access_patterns.write().await;
        let pattern = patterns.entry(key.to_string()).or_insert_with(|| AccessPattern::new(key.to_string()));
        pattern.record_access();
    }

    /// Record cache miss for pattern learning
    pub async fn record_miss(&self, key: &str) {
        let mut patterns = self.access_patterns.write().await;
        let pattern = patterns.entry(key.to_string()).or_insert_with(|| AccessPattern::new(key.to_string()));
        
        // Reduce frequency for misses
        pattern.frequency = pattern.frequency * 0.9;
        pattern.update_priority_score();
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> PredictiveCacheStats {
        let patterns = self.access_patterns.read().await;
        let total_patterns = patterns.len();
        let high_priority_count = patterns.values().filter(|p| p.priority_score > 15.0).count();
        let avg_frequency = if total_patterns > 0 {
            patterns.values().map(|p| p.frequency).sum::<f64>() / total_patterns as f64
        } else {
            0.0
        };
        
        PredictiveCacheStats {
            total_patterns,
            high_priority_count,
            average_frequency: avg_frequency,
            warmup_enabled: self.config.enable_predictive_warming,
            warmup_interval_secs: self.config.warmup_interval_secs,
        }
    }

    /// Stop predictive warming
    pub async fn stop_warming(&mut self) {
        if let Some(handle) = self.warmup_handle.take() {
            handle.abort();
            tracing::info!("Predictive cache warming stopped");
        }
    }
}

/// Predictive cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictiveCacheStats {
    pub total_patterns: usize,
    pub high_priority_count: usize,
    pub average_frequency: f64,
    pub warmup_enabled: bool,
    pub warmup_interval_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_access_pattern_recording() {
        let mut pattern = AccessPattern::new("test_key".to_string());
        
        // Record multiple accesses
        for _ in 0..5 {
            pattern.record_access();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        assert!(pattern.frequency > 0.0);
        assert!(pattern.priority_score > 0.0);
        assert!(pattern.intervals.len() >= 4);
    }

    #[tokio::test]
    async fn test_frequency_predictor() {
        let mut patterns = HashMap::new();
        
        // Add high-frequency pattern
        let mut high_freq_pattern = AccessPattern::new("high_freq".to_string());
        for _ in 0..10 {
            high_freq_pattern.record_access();
        }
        patterns.insert("high_freq".to_string(), high_freq_pattern);
        
        // Add low-frequency pattern
        let mut low_freq_pattern = AccessPattern::new("low_freq".to_string());
        low_freq_pattern.record_access();
        patterns.insert("low_freq".to_string(), low_freq_pattern);
        
        let predictor = FrequencyPredictor::new(5.0);
        let warmup_keys = predictor.predict_warmup_keys(&patterns).await;
        
        assert_eq!(warmup_keys.len(), 1);
        assert_eq!(warmup_keys[0], "high_freq");
    }

    #[tokio::test]
    async fn test_ml_predictor() {
        let mut patterns = HashMap::new();
        
        // Add various patterns
        for i in 0..5 {
            let mut pattern = AccessPattern::new(format!("key_{}", i));
            for _ in 0..(i + 1) * 2 {
                pattern.record_access();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            patterns.insert(format!("key_{}", i), pattern);
        }
        
        let mut predictor = MLPredictor::new();
        predictor.update_patterns(patterns.clone()).await;
        
        let warmup_keys = predictor.predict_warmup_keys(&patterns).await;
        
        // Should predict some keys for warmup
        assert!(!warmup_keys.is_empty());
        assert!(warmup_keys.len() <= patterns.len());
    }

    #[tokio::test]
    async fn test_pattern_cleanup() {
        let mut patterns = HashMap::new();
        
        // Add old pattern
        let mut old_pattern = AccessPattern::new("old_key".to_string());
        old_pattern.last_access = SystemTime::now() - Duration::from_secs(25 * 3600); // 25 hours ago
        patterns.insert("old_key".to_string(), old_pattern);
        
        // Add recent pattern
        let mut recent_pattern = AccessPattern::new("recent_key".to_string());
        recent_pattern.record_access();
        patterns.insert("recent_key".to_string(), recent_pattern);
        
        let access_patterns = Arc::new(RwLock::new(patterns));
        PredictiveCache::cleanup_old_patterns(&access_patterns, 24).await;
        
        let patterns = access_patterns.read().await;
        assert_eq!(patterns.len(), 1);
        assert!(patterns.contains_key("recent_key"));
        assert!(!patterns.contains_key("old_key"));
    }
}
