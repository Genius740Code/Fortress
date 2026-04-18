//! Cache Protection Module
//!
//! This module provides protection against cache-based side-channel attacks
//! including cache timing attacks, access pattern analysis, and cache randomization.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};

/// Cache protection provider
pub struct CacheProtection {
    /// Configuration
    config: CacheProtectionConfig,
    /// Cache line size in bytes
    cache_line_size: usize,
    /// Cache sets
    cache_sets: Arc<RwLock<HashMap<u64, CacheSet>>>,
    /// Access pattern analyzer
    pattern_analyzer: Arc<RwLock<AccessPatternAnalyzer>>,
    /// Randomization engine
    randomizer: Arc<CacheRandomizer>,
    /// Protection metrics
    metrics: Arc<RwLock<CacheProtectionMetrics>>,
}

/// Cache protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheProtectionConfig {
    /// Cache randomization enabled
    pub randomization_enabled: bool,
    /// Access pattern analysis enabled
    pub pattern_analysis_enabled: bool,
    /// Cache line randomization interval
    pub randomization_interval_ms: u64,
    /// Access history size
    pub access_history_size: usize,
    /// Anomaly detection threshold
    pub anomaly_threshold: f64,
    /// Cache flush threshold
    pub cache_flush_threshold: f64,
    /// Prefetch randomization enabled
    pub prefetch_randomization: bool,
    /// Cache line randomization enabled
    pub cache_line_randomization_enabled: bool,
}

/// Cache set for managing cache lines
#[derive(Debug, Clone)]
pub struct CacheSet {
    /// Set identifier
    pub set_id: u64,
    /// Cache lines
    pub lines: Vec<CacheLine>,
    /// Access order for LRU
    pub access_order: Vec<usize>,
    /// Randomization counter
    pub randomization_counter: AtomicUsize,
}

/// Cache line with protection
#[derive(Debug, Clone)]
pub struct CacheLine {
    /// Line identifier
    pub line_id: u64,
    /// Data (simulated)
    pub data: Vec<u8>,
    /// Access count
    pub access_count: AtomicU64,
    /// Last access timestamp
    pub last_access: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
    /// Randomization state
    pub randomization_state: u8,
    /// Access patterns
    pub access_patterns: Arc<RwLock<Vec<AccessPattern>>>,
}

/// Access pattern for tracking cache behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    /// Pattern ID
    pub pattern_id: u64,
    /// Access timestamps
    pub access_timestamps: Vec<chrono::DateTime<chrono::Utc>>,
    /// Access intervals
    pub access_intervals: Vec<std::time::Duration>,
    /// Pattern type
    pub pattern_type: PatternType,
    /// Regularity score
    pub regularity_score: f64,
    /// Predictability score
    pub predictability_score: f64,
}

/// Pattern types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatternType {
    /// Sequential access
    Sequential,
    /// Random access
    Random,
    /// Strided access
    Strided,
    /// Burst access
    Burst,
    /// Unknown pattern
    Unknown,
}

/// Access pattern analyzer
pub struct AccessPatternAnalyzer {
    /// Configuration
    config: CacheProtectionConfig,
    /// Pattern history
    pattern_history: Arc<RwLock<HashMap<u64, Vec<AccessPattern>>>>,
    /// Anomaly detector
    anomaly_detector: Arc<RwLock<AnomalyDetector>>,
}

/// Anomaly detector for cache access patterns
pub struct AnomalyDetector {
    /// Configuration
    config: CacheProtectionConfig,
    /// Baseline patterns
    baseline_patterns: Arc<RwLock<HashMap<String, BaselinePattern>>>,
    /// Detection history
    detection_history: Arc<RwLock<Vec<AnomalyDetection>>>>,
}

/// Baseline pattern for normal access behavior
#[derive(Debug, Clone)]
pub struct BaselinePattern {
    /// Pattern identifier
    pub pattern_id: String,
    /// Expected intervals
    pub expected_intervals: Vec<std::time::Duration>,
    /// Regularity threshold
    pub regularity_threshold: f64,
    /// Predictability threshold
    pub predictability_threshold: f64,
}

/// Anomaly detection result
#[derive(Debug, Clone)]
pub struct AnomalyDetection {
    /// Anomaly detected
    pub anomaly_detected: bool,
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Confidence score
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Affected cache lines
    pub affected_lines: Vec<u64>,
    /// Recommended action
    pub recommended_action: String,
}

/// Anomaly types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyType {
    /// Timing attack
    TimingAttack,
    /// Access pattern attack
    AccessPatternAttack,
    /// Cache probing attack
    CacheProbingAttack,
    /// Flush attack
    FlushAttack,
    /// Prefetch attack
    PrefetchAttack,
}

/// Cache randomization engine
pub struct CacheRandomizer {
    /// Configuration
    config: CacheProtectionConfig,
    /// Random number generator
    rng: Arc<RwLock<crate::trng::SecureRandom>>,
    /// Randomization schedule
    schedule: Arc<RwLock<Vec<RandomizationTask>>>,
}

/// Randomization task
#[derive(Debug, Clone)]
pub struct RandomizationTask {
    /// Task ID
    pub task_id: u64,
    /// Cache set ID
    pub cache_set_id: u64,
    /// Line ID
    pub line_id: Option<u64>,
    /// Task type
    pub task_type: RandomizationType,
    /// Scheduled time
    pub scheduled_time: chrono::DateTime<chrono::Utc>,
    /// Completed flag
    pub completed: bool,
}

/// Randomization types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandomizationType {
    /// Randomize cache set
    RandomizeSet,
    /// Randomize cache line
    RandomizeLine,
    /// Randomize access order
    RandomizeAccessOrder,
    /// Flush cache set
    FlushSet,
}

/// Cache protection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheProtectionMetrics {
    /// Total protected accesses
    pub total_protected_accesses: u64,
    /// Cache randomizations performed
    pub cache_randomizations: u64,
    /// Cache flushes performed
    pub cache_flushes: u64,
    /// Access pattern analyses
    pub access_pattern_analyses: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// False positives
    pub false_positives: u64,
    /// Average randomization overhead (microseconds)
    pub avg_randomization_overhead_us: f64,
    /// Cache hit rate with protection
    pub protected_cache_hit_rate: f64,
    /// Cache miss rate with protection
    pub protected_cache_miss_rate: f64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl CacheProtection {
    /// Create a new cache protection provider
    pub fn new(config: CacheProtectionConfig) -> Result<Self> {
        Ok(Self {
            cache_line_size: 64, // Typical cache line size
            cache_sets: Arc::new(RwLock::new(HashMap::new())),
            pattern_analyzer: Arc::new(RwLock::new(AccessPatternAnalyzer::new(config.clone())?)),
            randomizer: Arc::new(CacheRandomizer::new(config.clone())?),
            metrics: Arc::new(RwLock::new(CacheProtectionMetrics::default())),
            config,
        })
    }

    /// Protect a cache access
    pub async fn protect_access<F, R>(&self, operation: F) -> Result<R>
    where
        F: std::future::Future<Output = Result<R>> + Send,
    {
        let start = std::time::Instant::now();
        
        // Add access pattern randomization if enabled
        if self.config.randomization_enabled {
            self.randomizer.randomize_access().await?;
        }
        
        // Execute the operation
        let result = operation.await;
        
        // Analyze access pattern if enabled
        if self.config.pattern_analysis_enabled {
            self.analyze_access_pattern().await?;
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_protected_accesses += 1;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_randomization_overhead_us = (metrics.avg_randomization_overhead_us * (metrics.total_protected_accesses - 1) as f64 + elapsed) / metrics.total_protected_accesses as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        result
    }

    /// Access cache line with protection
    pub async fn access_cache_line(&self, cache_set_id: u64, line_id: u64, data: Vec<u8>) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        
        // Get or create cache set
        let mut cache_sets = self.cache_sets.write().await;
        let cache_set = cache_sets.entry(cache_set_id).or_insert_with(|| {
            CacheSet::new(cache_set_id, self.cache_line_size)
        });
        
        // Access the cache line
        let result = cache_set.access_line(line_id, data).await?;
        
        // Record access pattern
        if self.config.pattern_analysis_enabled {
            self.pattern_analyzer.record_access(cache_set_id, line_id).await?;
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_randomization_overhead_us = (metrics.avg_randomization_overhead_us * (metrics.total_protected_accesses - 1) as f64 + elapsed) / metrics.total_protected_accesses as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        Ok(result)
    }

    /// Randomize cache access patterns
    pub async fn randomize_access(&self) -> Result<()> {
        if !self.config.randomization_enabled {
            return Ok(());
        }
        
        let start = std::time::Instant::now();
        
        // Randomize cache sets
        {
            let mut cache_sets = self.cache_sets.write().await;
            for cache_set in cache_sets.values_mut() {
                cache_set.randomize_access_order().await?;
            }
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.cache_randomizations += 1;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_randomization_overhead_us = (metrics.avg_randomization_overhead_us * (metrics.total_protected_accesses - 1) as f64 + elapsed) / metrics.total_protected_accesses as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        Ok(())
    }

    /// Detect cache-based attacks
    pub async fn detect_attacks(&self) -> Result<Vec<AnomalyDetection>> {
        let mut attacks = Vec::new();
        
        // Detect access pattern anomalies
        if self.config.pattern_analysis_enabled {
            let pattern_attacks = self.pattern_analyzer.detect_anomalies().await?;
            attacks.extend(pattern_attacks);
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.anomalies_detected += attacks.iter().filter(|a| a.anomaly_detected).count() as u64;
            metrics.false_positives += attacks.iter().filter(|a| !a.anomaly_detected && a.confidence > 0.5).count() as u64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        Ok(attacks)
    }

    /// Analyze current access patterns
    pub async fn analyze_access_pattern(&self) -> Result<()> {
        if !self.config.pattern_analysis_enabled {
            return Ok(());
        }
        
        let cache_sets = self.cache_sets.read().await;
        
        for cache_set in cache_sets.values() {
            cache_set.analyze_access_patterns().await?;
        }
        
        Ok(())
    }

    /// Flush cache sets with high anomaly scores
    pub async fn flush_anomalous_sets(&self) -> Result<usize> {
        let start = std::time::Instant::now();
        let mut flushed_count = 0;
        
        let anomalies = self.detect_attacks().await?;
        
        // Find cache sets with high anomaly scores
        let mut sets_to_flush = Vec::new();
        for anomaly in &anomalies {
            if anomaly.anomaly_type == AnomalyType::FlushAttack && anomaly.confidence > 0.7 {
                sets_to_flush.push(anomaly.affected_lines.clone());
            }
        }
        
        // Flush the identified cache sets
        {
            let mut cache_sets = self.cache_sets.write().await;
            for set_id in sets_to_flush {
                if let Some(cache_set) = cache_sets.get_mut(&set_id) {
                    cache_set.flush().await?;
                    flushed_count += 1;
                }
            }
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.cache_flushes += flushed_count as u64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        Ok(flushed_count)
    }

    /// Get cache protection metrics
    pub async fn get_metrics(&self) -> Result<CacheProtectionMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) -> Result<()> {
        {
            let mut metrics = self.metrics.write().await;
            *metrics = CacheProtectionMetrics::default();
        }
        
        Ok(())
    }

    /// Clear all cache sets
    pub async fn clear_cache(&self) -> Result<()> {
        let mut cache_sets = self.cache_sets.write().await;
        cache_sets.clear();
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.cache_flushes += 1;
            metrics.last_updated = chrono::Utc::now();
        }
        
        Ok(())
    }

    /// Get cache statistics
    pub async fn get_cache_statistics(&self) -> Result<CacheStatistics> {
        let cache_sets = self.cache_sets.read().await;
        
        let mut total_lines = 0;
        let mut total_accesses = 0u64;
        let mut total_size = 0usize;
        
        for cache_set in cache_sets.values() {
            total_lines += cache_set.lines.len();
            total_accesses += cache_set.get_total_accesses();
            total_size += cache_set.get_total_size();
        }
        
        Ok(CacheStatistics {
            total_cache_sets: cache_sets.len(),
            total_cache_lines,
            total_accesses,
            total_size_bytes: total_size,
            cache_line_size: self.cache_line_size,
        })
    }

    /// Shutdown the cache protection
    pub async fn shutdown(&self) -> Result<()> {
        // Clear sensitive data
        self.clear_cache().await?;
        
        // Clear pattern analyzer
        self.pattern_analyzer.write().await.clear_history().await?;
        
        // Clear randomizer
        self.randomizer.write().await.clear_schedule().await?;
        
        // Reset metrics
        self.reset_metrics().await?;
        
        Ok(())
    }
}

impl CacheSet {
    /// Create a new cache set
    pub fn new(set_id: u64, line_count: usize) -> Self {
        let mut lines = Vec::with_capacity(line_count);
        for i in 0..line_count {
            lines.push(CacheLine::new(i, Vec::new()));
        }
        
        Self {
            set_id,
            lines,
            access_order: (0..line_count).collect(),
            randomization_counter: AtomicUsize::new(0),
        }
    }

    /// Access a cache line
    pub async fn access_line(&mut self, line_id: u64, data: Vec<u8>) -> Result<Vec<u8>> {
        if line_id as usize >= self.lines.len() {
            return Err(FaultressError::side_channel("Invalid cache line ID", 
                format!("Line ID: {}, Max: {}", line_id, self.lines.len())));
        }
        
        let line = &mut self.lines[line_id as usize];
        
        // Update access information
        line.access_count.fetch_add(1, Ordering::Relaxed);
        {
            let mut last_access = line.last_access.write().await;
            *last_access = chrono::Utc::now();
        }
        
        // Update LRU order
        self.update_lru_order(line_id as usize);
        
        // Store new data
        line.data = data;
        
        // Return cached data
        Ok(line.data.clone())
    }

    /// Update LRU access order
    fn update_lru_order(&mut self, line_id: usize) {
        // Remove from current position
        if let Some(pos) = self.access_order.iter().position(|&id| *id == line_id) {
            self.access_order.remove(pos);
        }
        
        // Add to end (most recently used)
        self.access_order.push(line_id);
    }

    /// Randomize access order
    pub async fn randomize_access_order(&mut self) -> Result<()> {
        let mut rng = crate::trng::SecureRandom::new()?;
        let mut random_bytes = [0u8; self.lines.len()];
        rng.fill_bytes(&mut random_bytes)?;
        
        // Create random permutation
        let mut permutation: Vec<usize> = (0..self.lines.len()).collect();
        for i in 0..permutation.len() {
            let j = (i + (random_bytes[i] as usize) % (permutation.len() - i)) + i;
            permutation.swap(i, j);
        }
        
        // Apply permutation
        self.access_order = permutation;
        
        // Update line randomization state
        for line in &mut self.lines {
            line.randomization_state = line.randomization_state.wrapping_add(1);
        }
        
        Ok(())
    }

    /// Analyze access patterns
    pub async fn analyze_access_patterns(&mut self) -> Result<()> {
        for line in &mut self.lines {
            line.analyze_patterns().await?;
        }
        Ok(())
    }

    /// Get total accesses for this set
    pub fn get_total_accesses(&self) -> u64 {
        self.lines.iter().map(|line| line.access_count.load(Ordering::Relaxed)).sum()
    }

    /// Get total size for this set
    pub fn get_total_size(&self) -> usize {
        self.lines.iter().map(|line| line.data.len()).sum()
    }

    /// Flush the cache set
    pub async fn flush(&mut self) -> Result<()> {
        for line in &mut self.lines {
            line.data.clear();
            line.access_count.store(0, Ordering::Relaxed);
            {
                let mut last_access = line.last_access.write().await;
                *last_access = chrono::Utc::now();
            }
        }
        
        self.access_order.clear();
        self.randomization_counter.store(0, Ordering::Relaxed);
        
        Ok(())
    }
}

impl CacheLine {
    /// Create a new cache line
    pub fn new(line_id: u64, data: Vec<u8>) -> Self {
        Self {
            line_id,
            data,
            access_count: AtomicU64::new(0),
            last_access: Arc::new(RwLock::new(chrono::Utc::now())),
            randomization_state: 0,
            access_patterns: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Analyze access patterns for this line
    pub async fn analyze_patterns(&mut self) -> Result<()> {
        let now = chrono::Utc::now();
        
        // Record current access
        {
            let mut patterns = self.access_patterns.write().await;
            patterns.push(AccessPattern {
                pattern_id: self.line_id,
                access_timestamps: vec![now],
                access_intervals: Vec::new(),
                pattern_type: PatternType::Unknown,
                regularity_score: 0.0,
                predictability_score: 0.0,
            });
        }
        
        // Analyze existing patterns
        {
            let patterns = self.access_patterns.read().await;
            if patterns.len() > 1 {
                let intervals: Vec<std::time::Duration> = patterns.windows(2)
                    .map(|pair| pair[1].access_timestamps[0] - pair[0].access_timestamps[0])
                    .collect();
                
                // Calculate regularity score
                let avg_interval = intervals.iter().sum::<std::time::Duration>() / intervals.len() as u32;
                let variance: f64 = intervals.iter()
                    .map(|&interval| {
                        let diff = interval.as_nanos() as f64 - avg_interval.as_nanos() as f64;
                        diff * diff
                    })
                    .sum::<f64>() / intervals.len() as f64;
                let std_dev = variance.sqrt();
                let regularity_score = if avg_interval.as_nanos() > 0 {
                    1.0 - (std_dev / avg_interval.as_nanos() as f64)
                } else {
                    0.0
                };
                
                // Update pattern
                if let Some(latest_pattern) = patterns.last_mut() {
                    latest_pattern.access_intervals = intervals;
                    latest_pattern.regularity_score = regularity_score;
                    latest_pattern.predictability_score = self.calculate_predictability_score(&latest_pattern).await?;
                    
                    // Determine pattern type
                    latest_pattern.pattern_type = self.classify_pattern(&latest_pattern).await?;
                }
            }
        }
        
        Ok(())
    }

    /// Calculate predictability score
    async fn calculate_predictability_score(&self, pattern: &AccessPattern) -> Result<f64> {
        if pattern.access_timestamps.len() < 3 {
            return Ok(0.0);
        }
        
        // Simple predictability based on interval variance
        let intervals: Vec<std::time::Duration> = pattern.access_intervals.windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect();
        
        let avg_interval = intervals.iter().sum::<std::time::Duration>() / intervals.len() as u32;
        let variance: f64 = intervals.iter()
            .map(|&interval| {
                let diff = interval.as_nanos() as f64 - avg_interval.as_nanos() as f64;
                diff * diff
            })
            .sum::<f64>() / intervals.len() as f64;
        
        let std_dev = variance.sqrt();
        let predictability_score = if avg_interval.as_nanos() > 0 {
            1.0 - (std_dev / avg_interval.as_nanos() as f64)
        } else {
            0.0
        };
        
        Ok(predictability_score)
    }

    /// Classify access pattern type
    async fn classify_pattern(&self, pattern: &AccessPattern) -> Result<PatternType> {
        let intervals = &pattern.access_intervals;
        
        if intervals.len() < 2 {
            return Ok(PatternType::Unknown);
        }
        
        // Check for sequential pattern
        let is_sequential = intervals.windows(2).all(|pair| {
            pair[0].as_millis() == 1 && pair[1].as_millis() == 1
        });
        
        if is_sequential {
            return Ok(PatternType::Sequential);
        }
        
        // Check for random pattern
        let variance = intervals.iter()
            .map(|&interval| interval.as_nanos() as f64)
            .collect::<Vec<f64>>();
        let mean = variance.iter().sum::<f64>() / variance.len() as f64;
        let std_dev = variance.iter()
            .map(|&val| (val - mean).powi(2.0))
            .sum::<f64>() / variance.len() as f64;
        
        if std_dev > mean * 0.5 {
            return Ok(PatternType::Random);
        }
        
        // Check for burst pattern
        let mut burst_detected = false;
        let mut consecutive_short_intervals = 0;
        
        for interval in intervals {
            if interval.as_millis() <= 5 {
                consecutive_short_intervals += 1;
                if consecutive_short_intervals >= 5 {
                    burst_detected = true;
                    break;
                }
            } else {
                consecutive_short_intervals = 0;
            }
        }
        
        if burst_detected {
            return Ok(PatternType::Burst);
        }
        
        // Default to strided
        Ok(PatternType::Strided)
    }
}

impl AccessPatternAnalyzer {
    /// Create a new access pattern analyzer
    pub fn new(config: CacheProtectionConfig) -> Result<Self> {
        Ok(Self {
            config,
            pattern_history: Arc::new(RwLock::new(HashMap::new())),
            anomaly_detector: Arc::new(RwLock::new(AnomalyDetector::new(config.clone())?)),
        })
    }

    /// Record an access event
    pub async fn record_access(&self, cache_set_id: u64, line_id: u64) -> Result<()> {
        let now = chrono::Utc::now();
        
        let mut history = self.pattern_history.write().await;
        let patterns = history.entry(cache_set_id).or_insert_with(Vec::new);
        
        // Find or create pattern for this line
        let pattern = patterns.iter_mut()
            .find(|p| p.pattern_id == line_id)
            .or_else(|| {
                patterns.push(AccessPattern {
                    pattern_id: line_id,
                    access_timestamps: vec![now],
                    access_intervals: Vec::new(),
                    pattern_type: PatternType::Unknown,
                    regularity_score: 0.0,
                    predictability_score: 0.0,
                });
                patterns.last_mut()
            });
        
        // Update pattern
        if let Some(last_timestamp) = pattern.access_timestamps.last() {
            pattern.access_intervals.push(now - *last_timestamp);
        }
        pattern.access_timestamps.push(now);
        
        Ok(())
    }

    /// Detect anomalies in access patterns
    pub async fn detect_anomalies(&self) -> Result<Vec<AnomalyDetection>> {
        let mut anomalies = Vec::new();
        
        let history = self.pattern_history.read().await;
        
        for (cache_set_id, patterns) in history.iter() {
            if let Some(result) = self.anomaly_detector.detect_anomalies(cache_set_id, patterns).await? {
                anomalies.push(result);
            }
        }
        
        Ok(anomalies)
    }

    /// Clear pattern history
    pub async fn clear_history(&self) -> Result<()> {
        let mut history = self.pattern_history.write().await;
        history.clear();
        Ok(())
    }
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new(config: CacheProtectionConfig) -> Result<Self> {
        Ok(Self {
            config,
            baseline_patterns: Arc::new(RwLock::new(HashMap::new())),
            detection_history: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Detect anomalies in cache access patterns
    pub async fn detect_anomalies(&self, cache_set_id: u64, patterns: &[AccessPattern]) -> Result<Option<AnomalyDetection>> {
        let mut anomalies = Vec::new();
        
        for pattern in patterns {
            // Check for timing attacks
            if pattern.regularity_score > 0.8 && pattern.predictability_score > 0.8 {
                anomalies.push(AnomalyDetection {
                    anomaly_detected: true,
                    anomaly_type: AnomalyType::TimingAttack,
                    confidence: (pattern.regularity_score + pattern.predictability_score) / 2.0,
                    description: format!("Highly regular and predictable access pattern detected for line {}", pattern.pattern_id),
                    affected_lines: vec![cache_set_id],
                    recommended_action: "Consider adding access randomization".to_string(),
                });
            }
            
            // Check for cache probing
            if pattern.pattern_type == PatternType::Random && pattern.access_timestamps.len() > 100 {
                anomalies.push(AnomalyDetection {
                    anomaly_detected: true,
                    anomaly_type: AnomalyType::CacheProbingAttack,
                    confidence: 0.8,
                    description: format!("Random access pattern with many accesses detected for line {}", pattern.pattern_id),
                    affected_lines: vec![cache_set_id],
                    recommended_action: "Consider implementing cache protection".to_string(),
                });
            }
        }
        
        if anomalies.is_empty() {
            Ok(None)
        } else {
            // Return the highest confidence anomaly
            let best_anomaly = anomalies.iter()
                .max_by(|a| a.confidence);
            Ok(Some(best_anomaly.cloned()))
        }
    }
}

impl CacheRandomizer {
    /// Create a new cache randomizer
    pub fn new(config: CacheProtectionConfig) -> Result<Self> {
        Ok(Self {
            config,
            rng: Arc::new(RwLock::new(crate::trng::SecureRandom::new()?)),
            schedule: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Randomize cache access
    pub async fn randomize_access(&self) -> Result<()> {
        let mut schedule = self.schedule.write().await;
        
        // Add randomization tasks for all cache sets
        // (In a real implementation, this would be more sophisticated)
        let mut rng = self.rng.write().await;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes)?;
        
        let task_id = u64::from_le_bytes(random_bytes);
        schedule.push(RandomizationTask {
            task_id,
            cache_set_id: 0, // Would be actual cache set IDs
            line_id: None,
            task_type: RandomizationType::RandomizeAccessOrder,
            scheduled_time: chrono::Utc::now() + std::time::Duration::from_millis(
                self.config.randomization_interval_ms + (random_bytes[0] as u64 % 100)
            ),
            completed: false,
        });
        
        Ok(())
    }

    /// Clear randomization schedule
    pub async fn clear_schedule(&self) -> Result<()> {
        let mut schedule = self.schedule.write().await;
        schedule.clear();
        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStatistics {
    /// Total number of cache sets
    pub total_cache_sets: usize,
    /// Total number of cache lines
    pub total_cache_lines: usize,
    /// Total number of accesses
    pub total_accesses: u64,
    /// Total cache size in bytes
    pub total_size_bytes: usize,
    /// Cache line size in bytes
    pub cache_line_size: usize,
}

impl Default for CacheProtectionConfig {
    fn default() -> Self {
        Self {
            randomization_enabled: true,
            pattern_analysis_enabled: true,
            randomization_interval_ms: 1000,
            access_history_size: 1000,
            anomaly_threshold: 0.7,
            cache_flush_threshold: 0.8,
            prefetch_randomization: true,
            cache_line_randomization_enabled: true,
        }
    }
}

impl Default for CacheProtectionMetrics {
    fn default() -> Self {
        Self {
            total_protected_accesses: 0,
            cache_randomizations: 0,
            cache_flushes: 0,
            access_pattern_analyses: 0,
            anomalies_detected: 0,
            false_positives: 0,
            avg_randomization_overhead_us: 0.0,
            protected_cache_hit_rate: 0.0,
            protected_cache_miss_rate: 0.0,
            last_updated: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_protection() {
        let config = CacheProtectionConfig::default();
        let cache = CacheProtection::new(config).unwrap();
        
        // Test cache line access
        let data = vec![1, 2, 3, 4, 5];
        let result = cache.access_cache_line(1, 1, data).await.unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
        
        // Test metrics
        let metrics = cache.get_metrics().await.unwrap();
        assert_eq!(metrics.total_protected_accesses, 1);
    }

    #[tokio::test]
    async fn test_access_pattern_analysis() {
        let config = CacheProtectionConfig::default();
        let cache = CacheProtection::new(config).unwrap();
        
        // Simulate sequential access pattern
        for i in 0..10 {
            cache.access_cache_line(1, 1, vec![i]).await.unwrap();
        }
        
        // Analyze patterns
        cache.analyze_access_pattern().await.unwrap();
        
        let stats = cache.get_cache_statistics().await.unwrap();
        assert_eq!(stats.total_accesses, 10);
    }

    #[tokio::test]
    async fn test_attack_detection() {
        let config = CacheProtectionConfig::default();
        let cache = CacheProtection::new(config).unwrap();
        
        // Simulate regular access pattern (should trigger detection)
        for i in 0..20 {
            cache.access_cache_line(1, 1, vec![i]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        
        let attacks = cache.detect_attacks().await.unwrap();
        // Should detect timing attack due to regular pattern
        assert!(!attacks.is_empty());
    }

    #[tokio::test]
    async fn test_cache_randomization() {
        let config = CacheProtectionConfig::default();
        let cache = CacheProtection::new(config).unwrap();
        
        // Test randomization
        cache.randomize_access().await.unwrap();
        
        let metrics = cache.get_metrics().await.unwrap();
        assert!(metrics.cache_randomizations > 0);
    }

    #[tokio::test]
    async fn test_cache_flush() {
        let config = CacheProtectionConfig::default();
        let cache = CacheProtection::new(config).unwrap();
        
        // Add some data to cache
        for i in 0..5 {
            cache.access_cache_line(1, i, vec![i]).await.unwrap();
        }
        
        // Flush cache
        let flushed = cache.flush_anomalous_sets().await.unwrap();
        assert_eq!(flushed, 0); // No anomalies detected yet
    }
}
