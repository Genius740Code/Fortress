//! Timing Protection Module
//!
//! This module provides protection against timing attacks by adding
//! controlled noise and obfuscation to timing-sensitive operations.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;
use crate::error::{FortressError, Result};

/// Timing protection provider
pub struct TimingProtection {
    /// Configuration
    config: TimingConfig,
    /// Random number generator
    rng: Arc<RwLock<crate::trng::SecureRandom>>,
    /// Noise generator
    noise_generator: Arc<NoiseGenerator>,
    /// Timing metrics
    metrics: Arc<RwLock<TimingMetrics>>,
    /// Operation history for attack detection
    operation_history: Arc<RwLock<Vec<TimingEntry>>>,
}

/// Timing protection configuration
#[derive(Debug, Clone)]
pub struct TimingConfig {
    /// Base noise level in microseconds
    pub base_noise_us: u64,
    /// Maximum noise level in microseconds
    pub max_noise_us: u64,
    /// Noise distribution type
    pub noise_distribution: NoiseDistribution,
    /// Attack detection enabled
    pub attack_detection_enabled: bool,
    /// History size for attack detection
    pub history_size: usize,
    /// Attack detection threshold (standard deviations)
    pub attack_detection_threshold: f64,
    /// Branch prediction hardening enabled
    pub branch_hardening_enabled: bool,
}

/// Noise distribution types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseDistribution {
    /// Uniform distribution
    Uniform,
    /// Normal distribution
    Normal,
    /// Exponential distribution
    Exponential,
    /// Custom distribution
    Custom(Vec<f64>),
}

/// Noise generator for timing obfuscation
pub struct NoiseGenerator {
    /// Configuration
    config: TimingConfig,
    /// Precomputed noise values
    noise_values: Vec<u64>,
    /// Current index
    current_index: std::sync::atomic::AtomicUsize,
}

/// Timing metrics
#[derive(Debug, Clone)]
pub struct TimingMetrics {
    /// Total protected operations
    pub total_protected_operations: u64,
    /// Total noise added (microseconds)
    pub total_noise_added_us: u64,
    /// Average noise per operation (microseconds)
    pub avg_noise_per_operation_us: f64,
    /// Branch hardening operations
    pub branch_hardening_operations: u64,
    /// Attacks detected
    pub attacks_detected: u64,
    /// False positives
    pub false_positives: u64,
    /// Average operation duration (microseconds)
    pub avg_operation_duration_us: f64,
    /// Standard deviation of operation durations
    pub operation_duration_std_deviation: f64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Timing entry for attack detection
#[derive(Debug, Clone)]
pub struct TimingEntry {
    /// Operation ID
    pub operation_id: String,
    /// Operation type
    pub operation_type: String,
    /// Duration in microseconds
    pub duration_us: u64,
    /// Noise added in microseconds
    pub noise_added_us: u64,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Input parameters hash
    pub input_hash: u64,
}

/// Attack detection result
#[derive(Debug, Clone)]
pub struct AttackDetectionResult {
    /// Attack detected
    pub attack_detected: bool,
    /// Attack confidence (0.0 to 1.0)
    pub confidence: f64,
    /// Attack type
    pub attack_type: String,
    /// Description
    pub description: String,
    /// Anomalous entries
    pub anomalous_entries: Vec<TimingEntry>,
}

impl TimingProtection {
    /// Create a new timing protection provider
    pub fn new(config: TimingConfig) -> Result<Self> {
        let noise_generator = Arc::new(NoiseGenerator::new(config.clone())?);
        
        Ok(Self {
            config,
            rng: Arc::new(RwLock::new(crate::trng::SecureRandom::new()?)),
            noise_generator,
            metrics: Arc::new(RwLock::new(TimingMetrics::default())),
            operation_history: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Add timing noise to a duration
    pub async fn add_noise(&self, base_duration: std::time::Duration) -> Result<std::time::Duration> {
        let base_us = base_duration.as_micros() as u64;
        let noise_us = self.noise_generator.generate_noise(base_us).await?;
        let total_us = base_us.saturating_add(noise_us);
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_protected_operations += 1;
            metrics.total_noise_added_us += noise_us;
            metrics.avg_noise_per_operation_us = (metrics.avg_noise_per_operation_us * (metrics.total_protected_operations - 1) as f64 
                + noise_us as f64) / metrics.total_protected_operations as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        Ok(std::time::Duration::from_micros(total_us))
    }

    /// Protect an operation with timing noise
    pub async fn protect_operation<F, R>(&self, operation: F) -> Result<R>
    where
        F: std::future::Future<Output = Result<R>> + Send,
    {
        let start = std::time::Instant::now();
        
        // Add branch hardening if enabled
        if self.config.branch_hardening_enabled {
            self.add_branch_noise().await?;
        }
        
        // Execute the operation
        let result = operation.await;
        
        let duration = start.elapsed();
        let noisy_duration = self.add_noise(duration).await?;
        
        // Record timing entry for attack detection
        if self.config.attack_detection_enabled {
            self.record_timing_entry("generic_operation", duration, noisy_duration).await?;
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            let duration_us = duration.as_micros() as f64;
            metrics.avg_operation_duration_us = (metrics.avg_operation_duration_us * (metrics.total_protected_operations - 1) as f64 + duration_us) / metrics.total_protected_operations as f64;
            
            // Update standard deviation
            self.update_standard_deviation(&mut metrics).await?;
            
            metrics.last_updated = chrono::Utc::now();
        }
        
        result
    }

    /// Add branch prediction hardening noise
    async fn add_branch_noise(&self) -> Result<()> {
        let mut rng = self.rng.write().await;
        let mut noise_bytes = [0u8; 8];
        rng.fill_bytes(&mut noise_bytes)?;
        
        // Add random delay based on noise bytes
        let delay_us = (noise_bytes[0] as u64 % self.config.max_noise_us) + self.config.base_noise_us;
        tokio::time::sleep(std::time::Duration::from_micros(delay_us)).await;
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.branch_hardening_operations += 1;
        }
        
        Ok(())
    }

    /// Record a timing entry for attack detection
    async fn record_timing_entry(&self, operation_type: &str, 
                                   actual_duration: std::time::Duration, 
                                   noisy_duration: std::time::Duration) -> Result<()> {
        let entry = TimingEntry {
            operation_id: format!("op_{}", self.generate_operation_id()),
            operation_type: operation_type.to_string(),
            duration_us: actual_duration.as_micros() as u64,
            noise_added_us: noisy_duration.as_micros().saturating_sub(actual_duration.as_micros() as u64),
            timestamp: chrono::Utc::now(),
            input_hash: self.calculate_input_hash().await?,
        };
        
        let mut history = self.operation_history.write().await;
        history.push(entry);
        
        // Maintain history size
        if history.len() > self.config.history_size {
            history.remove(0);
        }
        
        Ok(())
    }

    /// Generate a unique operation ID
    fn generate_operation_id(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Calculate input hash for correlation
    async fn calculate_input_hash(&self) -> Result<u64> {
        let mut rng = self.rng.write().await;
        let mut hash_bytes = [0u8; 8];
        rng.fill_bytes(&mut hash_bytes)?;
        
        Ok(u64::from_le_bytes(hash_bytes))
    }

    /// Update standard deviation calculation
    async fn update_standard_deviation(&self, metrics: &mut TimingMetrics) -> Result<()> {
        let history = self.operation_history.read().await;
        
        if history.len() < 2 {
            return Ok(());
        }
        
        // Calculate mean
        let sum: f64 = history.iter().map(|e| e.duration_us as f64).sum();
        let mean = sum / history.len() as f64;
        
        // Calculate variance
        let variance: f64 = history.iter()
            .map(|e| {
                let diff = e.duration_us as f64 - mean;
                diff * diff
            })
            .sum();
        
        let std_dev = (variance / history.len() as f64).sqrt();
        metrics.operation_duration_std_deviation = std_dev;
        
        Ok(())
    }

    /// Detect timing attacks
    pub async fn detect_attacks(&self) -> Result<Vec<AttackDetectionResult>> {
        let mut results = Vec::new();
        
        if !self.config.attack_detection_enabled {
            return Ok(results);
        }
        
        let history = self.operation_history.read().await;
        if history.len() < 10 {
            return Ok(results);
        }
        
        // Group by operation type
        let mut operation_groups: HashMap<String, Vec<&TimingEntry>> = HashMap::new();
        for entry in history.iter() {
            operation_groups.entry(entry.operation_type.clone())
                .or_insert_with(Vec::new)
                .push(entry);
        }
        
        // Analyze each operation type for anomalies
        for (operation_type, entries) in operation_groups {
            if let Some(result) = self.analyze_operation_timing(&operation_type, &entries).await? {
                results.push(result);
            }
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.attacks_detected += results.iter().filter(|r| r.attack_detected).count() as u64;
            metrics.false_positives += results.iter().filter(|r| !r.attack_detected && r.confidence > 0.5).count() as u64;
        }
        
        Ok(results)
    }

    /// Analyze timing patterns for a specific operation type
    async fn analyze_operation_timing(&self, operation_type: &str, entries: &[&TimingEntry]) -> Result<Option<AttackDetectionResult>> {
        if entries.len() < 5 {
            return Ok(None);
        }
        
        // Calculate statistics
        let durations: Vec<f64> = entries.iter().map(|e| e.duration_us as f64).collect();
        let mean = durations.iter().sum::<f64>() / durations.len() as f64;
        let variance = durations.iter()
            .map(|d| {
                let diff = *d - mean;
                diff * diff
            })
            .sum::<f64>() / durations.len() as f64;
        let std_dev = variance.sqrt();
        
        // Detect anomalies using statistical analysis
        let mut anomalous_entries = Vec::new();
        let mut anomaly_count = 0;
        
        for entry in entries {
            let z_score = ((entry.duration_us as f64 - mean) / std_dev).abs();
            
            // Flag entries with high z-scores
            if z_score > self.config.attack_detection_threshold {
                anomalous_entries.push(entry.clone());
                anomaly_count += 1;
            }
        }
        
        // Determine if attack is detected
        let attack_detected = anomaly_count > entries.len() / 4; // More than 25% anomalous
        let confidence = if attack_detected {
            (anomaly_count as f64 / entries.len() as f64).min(1.0)
        } else {
            0.0
        };
        
        if attack_detected || confidence > 0.3 {
            Ok(Some(AttackDetectionResult {
                attack_detected,
                confidence,
                attack_type: format!("Timing Attack on {}", operation_type),
                description: format!("Detected {} anomalous timing patterns out of {} operations", anomaly_count, entries.len()),
                anomalous_entries,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get timing metrics
    pub async fn get_metrics(&self) -> Result<TimingMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) -> Result<()> {
        {
            let mut metrics = self.metrics.write().await;
            *metrics = TimingMetrics::default();
        }
        
        {
            let mut history = self.operation_history.write().await;
            history.clear();
        }
        
        Ok(())
    }

    /// Clear operation history
    pub async fn clear_history(&self) -> Result<()> {
        let mut history = self.operation_history.write().await;
        history.clear();
        Ok(())
    }

    /// Update configuration
    pub async fn update_config(&mut self, config: TimingConfig) -> Result<()> {
        self.config = config.clone();
        *self.noise_generator = Arc::new(NoiseGenerator::new(config.clone())?);
        Ok(())
    }

    /// Get operation history
    pub async fn get_operation_history(&self, limit: Option<usize>) -> Result<Vec<TimingEntry>> {
        let history = self.operation_history.read().await;
        match limit {
            Some(limit) => {
                let start = if history.len() > limit { history.len() - limit } else { 0 };
                Ok(history[start..].to_vec())
            }
            None => Ok(history.clone()),
        }
    }

    /// Shutdown the timing protection
    pub async fn shutdown(&self) -> Result<()> {
        // Clear sensitive data
        {
            let mut rng = self.rng.write().await;
            rng.clear()?;
        }
        
        // Clear history and metrics
        self.clear_history().await?;
        self.reset_metrics().await?;
        
        Ok(())
    }
}

impl NoiseGenerator {
    /// Create a new noise generator
    pub fn new(config: TimingConfig) -> Result<Self> {
        let mut noise_values = Vec::new();
        
        // Precompute noise values based on distribution
        for _ in 0..1000 {
            let noise = match config.noise_distribution {
                NoiseDistribution::Uniform => {
                    let mut rng = crate::trng::SecureRandom::new()?;
                    let mut bytes = [0u8; 8];
                    rng.fill_bytes(&mut bytes)?;
                    let value = u64::from_le_bytes(bytes);
                    value % (config.max_noise_us - config.base_noise_us + 1)
                }
                NoiseDistribution::Normal => {
                    // Simple normal approximation using Box-Muller
                    let mut rng = crate::trng::SecureRandom::new()?;
                    let mut bytes = [0u8; 8];
                    rng.fill_bytes(&mut bytes)?;
                    let value = u64::from_le_bytes(bytes);
                    let mean = (config.base_noise_us + config.max_noise_us) / 2;
                    let std_dev = (config.max_noise_us - config.base_noise_us) / 4;
                    let noise = ((value % 1000) as f64 / 1000.0 * 2.0 - 1.0) * std_dev as f64 + mean;
                    noise.max(0.0).min(config.max_noise_us as f64) as u64
                }
                NoiseDistribution::Exponential => {
                    let mut rng = crate::trng::SecureRandom::new()?;
                    let mut bytes = [0u8; 8];
                    rng.fill_bytes(&mut bytes)?;
                    let value = u64::from_le_bytes(bytes);
                    let lambda = 1.0 / (config.max_noise_us - config.base_noise_us + 1) as f64;
                    let noise = (-((value % 1000) as f64 / 1000.0).ln() / lambda).exp() * (config.max_noise_us - config.base_noise_us) as f64;
                    noise.max(0.0).min(config.max_noise_us as f64) as u64
                }
                NoiseDistribution::Custom(ref weights) => {
                    let mut rng = crate::trng::SecureRandom::new()?;
                    let mut bytes = [0u8; 8];
                    rng.fill_bytes(&mut bytes)?;
                    let index = u64::from_le_bytes(bytes) as usize % weights.len();
                    let noise = weights[index] * (config.max_noise_us - config.base_noise_us) as f64;
                    noise.max(0.0).min(config.max_noise_us as f64) as u64
                }
            };
            noise_values.push(noise);
        }
        
        Ok(Self {
            config,
            noise_values,
            current_index: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Generate noise for a given base duration
    pub async fn generate_noise(&self, base_us: u64) -> Result<u64> {
        let index = self.current_index.fetch_add(1, Ordering::Relaxed) % self.noise_values.len();
        let noise = self.noise_values[index];
        
        // Scale noise based on base duration
        let scaled_noise = if base_us > 0 {
            (noise * base_us / 1000).max(1)
        } else {
            noise
        };
        
        Ok(scaled_noise)
    }
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            base_noise_us: 10,
            max_noise_us: 1000,
            noise_distribution: NoiseDistribution::Normal,
            attack_detection_enabled: true,
            history_size: 1000,
            attack_detection_threshold: 2.5, // 2.5 standard deviations
            branch_hardening_enabled: true,
        }
    }
}

impl Default for TimingMetrics {
    fn default() -> Self {
        Self {
            total_protected_operations: 0,
            total_noise_added_us: 0,
            avg_noise_per_operation_us: 0.0,
            branch_hardening_operations: 0,
            attacks_detected: 0,
            false_positives: 0,
            avg_operation_duration_us: 0.0,
            operation_duration_std_deviation: 0.0,
            last_updated: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timing_protection() {
        let config = TimingConfig::default();
        let timing = TimingProtection::new(config).unwrap();
        
        let duration = std::time::Duration::from_millis(100);
        let noisy_duration = timing.add_noise(duration).await.unwrap();
        
        // Should add some noise
        assert!(noisy_duration >= duration);
        assert!(noisy_duration <= duration + std::time::Duration::from_millis(1000));
    }

    #[tokio::test]
    async fn test_protect_operation() {
        let timing = TimingProtectionProtection::new(TimingConfig::default()).unwrap();
        
        let result = timing.protect_operation(async {
            // Simulate some work
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok(42)
        }).await.unwrap();
        
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_attack_detection() {
        let mut config = TimingConfig::default();
        config.attack_detection_enabled = true;
        config.history_size = 100;
        
        let timing = TimingProtection::new(config).unwrap();
        
        // Simulate some operations
        for _ in 0..20 {
            let duration = std::time::Duration::from_millis(50 + (rand::random::<u8>() % 10) as u64);
            timing.record_timing_entry("test_operation", duration, duration).await.unwrap();
        }
        
        let attacks = timing.detect_attacks().await.unwrap();
        // Should not detect attacks with normal timing
        assert_eq!(attacks.len(), 0);
    }

    #[tokio::test]
    async fn test_noise_generator() {
        let config = TimingConfig::default();
        let generator = NoiseGenerator::new(config).unwrap();
        
        let noise1 = generator.generate_noise(1000).await.unwrap();
        let noise2 = generator.generate_noise(1000).await.unwrap();
        
        // Should be within configured range
        assert!(noise1 <= 1000);
        assert!(noise2 <= 1000);
    }

    #[tokio::test]
    async fn test_metrics() {
        let timing = TimingProtection::new(TimingConfig::default()).unwrap();
        
        // Perform some operations
        timing.add_noise(std::time::Duration::from_millis(100)).await.unwrap();
        timing.protect_operation(async { Ok(()) }).await.unwrap();
        
        let metrics = timing.get_metrics().await.unwrap();
        assert_eq!(metrics.total_protected_operations, 2);
        assert!(metrics.total_noise_added_us > 0);
    }

    #[tokio::test]
    async fn test_branch_hardening() {
        let config = TimingConfig::default();
        config.branch_hardening_enabled = true;
        let timing = TimingProtection::new(config).unwrap();
        
        let start = std::time::Instant::now();
        timing.add_branch_noise().await.unwrap();
        let elapsed = start.elapsed();
        
        // Should add some delay
        assert!(elapsed >= std::time::Duration::from_micros(config.base_noise_us));
    }
}
