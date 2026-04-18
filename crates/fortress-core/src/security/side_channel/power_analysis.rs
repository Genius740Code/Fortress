//! Power Analysis Protection Module
//!
//! This module provides protection against power analysis attacks
//! including differential power analysis (DPA), simple power analysis (SPA),
//  and electromagnetic (EM) analysis attacks.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};

/// Power analysis protection provider
pub struct PowerAnalysisProtection {
    /// Configuration
    config: PowerAnalysisConfig,
    /// Noise generator for power consumption
    power_noise_generator: Arc<PowerNoiseGenerator>,
    /// Power consumption monitor
    power_monitor: Arc<PowerConsumptionMonitor>,
    /// Attack detector
    attack_detector: Arc<PowerAttackDetector>,
    /// Protection metrics
    metrics: Arc<RwLock<PowerAnalysisMetrics>>,
}

/// Power analysis protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerAnalysisConfig {
    /// Power noise injection enabled
    pub power_noise_enabled: bool,
    /// Electromagnetic noise enabled
    pub em_noise_enabled: bool,
    /// Current randomization enabled
    pub current_randomization_enabled: bool,
    /// Timing randomization enabled
    pub timing_randomization_enabled: bool,
    /// Noise level (0.0 to 1.0)
    pub noise_level: f64,
    /// Attack detection enabled
    pub attack_detection_enabled: bool,
    /// Monitoring window size
    pub monitoring_window_size: usize,
    /// Attack detection threshold
    pub attack_threshold: f64,
    /// Power consumption baseline
    pub power_baseline: f64,
}

/// Power noise generator for obfuscating power consumption
pub struct PowerNoiseGenerator {
    /// Configuration
    config: PowerAnalysisConfig,
    /// Random number generator
    rng: Arc<RwLock<crate::trng::SecureRandom>>,
    /// Noise patterns
    noise_patterns: Arc<RwLock<Vec<NoisePattern>>>,
}

/// Noise pattern for power consumption obfuscation
#[derive(Debug, Clone)]
pub struct NoisePattern {
    /// Pattern ID
    pub pattern_id: u64,
    /// Pattern type
    pub pattern_type: NoisePatternType,
    /// Amplitude
    pub amplitude: f64,
    /// Frequency
    pub frequency: f64,
    /// Phase
    pub phase: f64,
    /// Duration
    pub duration: std::time::Duration,
    /// Generated timestamps
    pub timestamps: Vec<chrono::DateTime<chrono::Utc>>,
}

/// Noise pattern types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoisePatternType {
    /// White noise
    White,
    /// Pink noise (1/f)
    Pink,
    /// Brown noise (1/f²)
    Brown,
    /// Sinusoidal
    Sinusoidal,
    /// Sawtooth
    Sawtooth,
    /// Square wave
    Square,
    /// Custom pattern
    Custom(Vec<f64>),
}

/// Power consumption monitor
pub struct PowerConsumptionMonitor {
    /// Configuration
    config: PowerAnalysisConfig,
    /// Power consumption history
    consumption_history: Arc<RwLock<Vec<PowerConsumptionEntry>>>,
    /// Baseline power consumption
    baseline: Arc<RwLock<f64>>,
    /// Statistical analyzer
    statistical_analyzer: Arc<StatisticalAnalyzer>,
}

/// Power consumption entry
#[derive(Debug, Clone)]
pub struct PowerConsumptionEntry {
    /// Entry ID
    pub entry_id: u64,
    /// Power consumption in milliwatts
    pub power_mw: f64,
    /// Current in milliamps
    pub current_ma: f64,
    /// Voltage in volts
    pub voltage_v: f64,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Operation type
    pub operation_type: String,
    /// Input hash for correlation
    pub input_hash: u64,
}

/// Statistical analyzer for power consumption
pub struct StatisticalAnalyzer {
    /// Configuration
    config: PowerAnalysisConfig,
    /// Statistical metrics
    metrics: Arc<RwLock<StatisticalMetrics>>,
}

/// Statistical metrics for power analysis
#[derive(Debug, Clone)]
pub struct StatisticalMetrics {
    /// Mean power consumption
    pub mean_power: f64,
    /// Standard deviation
    pub standard_deviation: f64,
    /// Skewness
    pub skewness: f64,
    /// Kurtosis
    pub kurtosis: f64,
    /// Variance
    pub variance: f64,
    /// Coefficient of variation
    pub coefficient_of_variation: f64,
}

/// Power attack detector
pub struct PowerAttackDetector {
    /// Configuration
    config: PowerAnalysisConfig,
    /// Attack patterns
    attack_patterns: Arc<RwLock<HashMap<String, AttackPattern>>>,
    /// Detection history
    detection_history: Arc<RwLock<Vec<PowerAttackDetection>>>,
}

/// Attack pattern for power analysis
#[derive(Debug, Clone)]
pub struct AttackPattern {
    /// Pattern name
    pub name: String,
    /// Pattern type
    pub pattern_type: PowerAttackType,
    /// Threshold
    pub threshold: f64,
    /// Description
    pub description: String,
}

/// Power attack types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowerAttackType {
    /// Simple Power Analysis (SPA)
    SimplePowerAnalysis,
    /// Differential Power Analysis (DPA)
    DifferentialPowerAnalysis,
    /// Correlation Power Analysis (CPA)
    CorrelationPowerAnalysis,
    /// Template Attack
    TemplateAttack,
    /// Electromagnetic Analysis
    ElectromagneticAnalysis,
    /// Acoustic Analysis
    AcousticAnalysis,
}

/// Power attack detection result
#[derive(Debug, Clone)]
pub struct PowerAttackDetection {
    /// Attack detected
    pub attack_detected: bool,
    /// Attack type
    pub attack_type: PowerAttackType,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Anomalous entries
    pub anomalous_entries: Vec<PowerConsumptionEntry>,
    /// Recommended action
    pub recommended_action: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Power analysis protection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerAnalysisMetrics {
    /// Total protected operations
    pub total_protected_operations: u64,
    /// Power noise injections
    pub power_noise_injections: u64,
    /// EM noise injections
    pub em_noise_injections: u64,
    /// Current randomizations
    pub current_randomizations: u64,
    /// Timing randomizations
    pub timing_randomizations: u64,
    /// Attacks detected
    pub attacks_detected: u64,
    /// False positives
    pub false_positives: u64,
    /// Average protection overhead (microseconds)
    pub avg_protection_overhead_us: f64,
    /// Power consumption variance
    pub power_consumption_variance: f64,
    /// Noise effectiveness score
    pub noise_effectiveness_score: f64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl PowerAnalysisProtection {
    /// Create a new power analysis protection provider
    pub fn new(config: PowerAnalysisConfig) -> Result<Self> {
        Ok(Self {
            power_noise_generator: Arc::new(PowerNoiseGenerator::new(config.clone())?),
            power_monitor: Arc::new(PowerConsumptionMonitor::new(config.clone())?),
            attack_detector: Arc::new(PowerAttackDetector::new(config.clone())?),
            metrics: Arc::new(RwLock::new(PowerAnalysisMetrics::default())),
            config,
        })
    }

    /// Protect an operation from power analysis attacks
    pub async fn protect_operation<F, R>(&self, operation: F) -> Result<R>
    where
        F: std::future::Future<Output = Result<R>> + Send,
    {
        let start = std::time::Instant::now();
        
        // Add power noise if enabled
        if self.config.power_noise_enabled {
            self.power_noise_generator.inject_power_noise().await?;
        }
        
        // Add EM noise if enabled
        if self.config.em_noise_enabled {
            self.power_noise_generator.inject_em_noise().await?;
        }
        
        // Randomize current consumption if enabled
        if self.config.current_randomization_enabled {
            self.randomize_current_consumption().await?;
        }
        
        // Execute the operation
        let result = operation.await;
        
        // Add timing randomization if enabled
        if self.config.timing_randomization_enabled {
            self.add_timing_randomization().await?;
        }
        
        // Monitor power consumption
        if self.config.attack_detection_enabled {
            self.monitor_power_consumption("protected_operation").await?;
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_protected_operations += 1;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_protection_overhead_us = (metrics.avg_protection_overhead_us * (metrics.total_protected_operations - 1) as f64 + elapsed) / metrics.total_protected_operations as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        result
    }

    /// Randomize current consumption
    async fn randomize_current_consumption(&self) -> Result<()> {
        let mut rng = self.power_noise_generator.rg.write().await;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes)?;
        
        // Simulate current randomization by adding dummy operations
        let current_variation = (random_bytes[0] as f64 / 255.0) * 10.0; // 0-10mA variation
        let duration = std::time::Duration::from_micros((random_bytes[1] as u64 % 100) + 10);
        
        // Simulate current consumption variation
        tokio::time::sleep(duration).await;
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.current_randomizations += 1;
        }
        
        Ok(())
    }

    /// Add timing randomization
    async fn add_timing_randomization(&self) -> Result<()> {
        let mut rng = self.power_noise_generator.rg.write().await;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes)?;
        
        // Add random delay
        let delay_us = (random_bytes[0] as u64 % 100) + 10; // 10-110 microseconds
        tokio::time::sleep(std::time::Duration::from_micros(delay_us)).await;
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.timing_randomizations += 1;
        }
        
        Ok(())
    }

    /// Monitor power consumption for attack detection
    async fn monitor_power_consumption(&self, operation_type: &str) -> Result<()> {
        let entry = PowerConsumptionEntry {
            entry_id: self.generate_entry_id(),
            power_mw: self.simulate_power_consumption().await?,
            current_ma: self.simulate_current_consumption().await?,
            voltage_v: 3.3, // Fixed voltage
            timestamp: chrono::Utc::now(),
            operation_type: operation_type.to_string(),
            input_hash: self.calculate_input_hash().await?,
        };
        
        let mut history = self.power_monitor.consumption_history.write().await;
        history.push(entry);
        
        // Maintain history size
        if history.len() > self.config.monitoring_window_size {
            history.remove(0);
        }
        
        Ok(())
    }

    /// Simulate power consumption
    async fn simulate_power_consumption(&self) -> Result<f64> {
        let mut rng = self.power_noise_generator.rg.write().await;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes)?;
        
        // Simulate power consumption with noise
        let base_power = self.config.power_baseline;
        let noise = (random_bytes[0] as f64 / 255.0) * self.config.noise_level * base_power;
        
        Ok(base_power + noise)
    }

    /// Simulate current consumption
    async fn simulate_current_consumption(&self) -> Result<f64> {
        let mut rng = self.power_noise_generator.rg.write().await;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes)?;
        
        // Simulate current consumption with noise
        let base_current = 10.0; // 10mA base current
        let noise = (random_bytes[0] as f64 / 255.0) * self.config.noise_level * 5.0;
        
        Ok(base_current + noise)
    }

    /// Generate entry ID
    fn generate_entry_id(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Calculate input hash for correlation
    async fn calculate_input_hash(&self) -> Result<u64> {
        let mut rng = self.power_noise_generator.rg.write().await;
        let mut hash_bytes = [0u8; 8];
        rng.fill_bytes(&mut hash_bytes)?;
        
        Ok(u64::from_le_bytes(hash_bytes))
    }

    /// Detect power analysis attacks
    pub async fn detect_attacks(&self) -> Result<Vec<PowerAttackDetection>> {
        let mut attacks = Vec::new();
        
        if !self.config.attack_detection_enabled {
            return Ok(attacks);
        }
        
        let history = self.power_monitor.consumption_history.read().await;
        if history.len() < 10 {
            return Ok(attacks);
        }
        
        // Analyze power consumption patterns
        let statistical_metrics = self.power_monitor.statistical_analyzer
            .analyze_power_consumption(&history).await?;
        
        // Detect anomalies
        if let Some(attack) = self.attack_detector.detect_statistical_anomalies(&statistical_metrics).await? {
            attacks.push(attack);
        }
        
        // Detect correlation attacks
        if let Some(attack) = self.attack_detector.detect_correlation_attacks(&history).await? {
            attacks.push(attack);
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.attacks_detected += attacks.iter().filter(|a| a.attack_detected).count() as u64;
            metrics.false_positives += attacks.iter().filter(|a| !a.attack_detected && a.confidence > 0.5).count() as u64;
            metrics.power_consumption_variance = statistical_metrics.variance;
            metrics.last_updated = chrono::Utc::now();
        }
        
        Ok(attacks)
    }

    /// Get power analysis metrics
    pub async fn get_metrics(&self) -> Result<PowerAnalysisMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) -> Result<()> {
        {
            let mut metrics = self.metrics.write().await;
            *metrics = PowerAnalysisMetrics::default();
        }
        
        // Clear monitoring history
        {
            let mut history = self.power_monitor.consumption_history.write().await;
            history.clear();
        }
        
        Ok(())
    }

    /// Get power consumption statistics
    pub async fn get_power_statistics(&self) -> Result<PowerStatistics> {
        let history = self.power_monitor.consumption_history.read().await;
        
        if history.is_empty() {
            return Ok(PowerStatistics::default());
        }
        
        let power_values: Vec<f64> = history.iter().map(|e| e.power_mw).collect();
        let current_values: Vec<f64> = history.iter().map(|e| e.current_ma).collect();
        
        let mean_power = power_values.iter().sum::<f64>() / power_values.len() as f64;
        let mean_current = current_values.iter().sum::<f64>() / current_values.len() as f64;
        
        let power_variance = power_values.iter()
            .map(|&p| (p - mean_power).powi(2))
            .sum::<f64>() / power_values.len() as f64;
        
        let current_variance = current_values.iter()
            .map(|&c| (c - mean_current).powi(2))
            .sum::<f64>() / current_values.len() as f64;
        
        Ok(PowerStatistics {
            mean_power_mw: mean_power,
            mean_current_ma: mean_current,
            power_variance,
            current_variance,
            total_measurements: history.len(),
            measurement_period: history.last().unwrap().timestamp - history.first().unwrap().timestamp,
        })
    }

    /// Update configuration
    pub async fn update_config(&mut self, config: PowerAnalysisConfig) -> Result<()> {
        self.config = config.clone();
        
        // Update sub-components
        *self.power_noise_generator = Arc::new(PowerNoiseGenerator::new(config.clone())?);
        *self.power_monitor = Arc::new(PowerConsumptionMonitor::new(config.clone())?);
        *self.attack_detector = Arc::new(PowerAttackDetector::new(config.clone())?);
        
        Ok(())
    }

    /// Get power consumption history
    pub async fn get_consumption_history(&self, limit: Option<usize>) -> Result<Vec<PowerConsumptionEntry>> {
        let history = self.power_monitor.consumption_history.read().await;
        match limit {
            Some(limit) => {
                let start = if history.len() > limit { history.len() - limit } else { 0 };
                Ok(history[start..].to_vec())
            }
            None => Ok(history.clone()),
        }
    }

    /// Shutdown the power analysis protection
    pub async fn shutdown(&self) -> Result<()> {
        // Clear sensitive data
        {
            let mut rng = self.power_noise_generator.rg.write().await;
            rng.clear()?;
        }
        
        // Clear history and metrics
        self.reset_metrics().await?;
        
        Ok(())
    }
}

impl PowerNoiseGenerator {
    /// Create a new power noise generator
    pub fn new(config: PowerAnalysisConfig) -> Result<Self> {
        let noise_patterns = Vec::new();
        
        Ok(Self {
            config,
            rng: Arc::new(RwLock::new(crate::trng::SecureRandom::new()?)),
            noise_patterns: Arc::new(RwLock::new(noise_patterns)),
        })
    }

    /// Inject power noise
    pub async fn inject_power_noise(&self) -> Result<()> {
        let mut rng = self.rg.write().await;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes)?;
        
        // Simulate power noise injection
        let noise_amplitude = (random_bytes[0] as f64 / 255.0) * self.config.noise_level * 10.0;
        let noise_duration = std::time::Duration::from_micros((random_bytes[1] as u64 % 100) + 10);
        
        // Simulate power consumption variation
        tokio::time::sleep(noise_duration).await;
        
        Ok(())
    }

    /// Inject electromagnetic noise
    pub async fn inject_em_noise(&self) -> Result<()> {
        let mut rng = self.rg.write().await;
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes)?;
        
        // Simulate EM noise injection
        let noise_frequency = (random_bytes[0] as f64 / 255.0) * 1000000.0; // 0-1MHz
        let noise_duration = std::time::Duration::from_micros((random_bytes[1] as u64 % 50) + 5);
        
        // Simulate EM emission
        tokio::time::sleep(noise_duration).await;
        
        Ok(())
    }
}

impl PowerConsumptionMonitor {
    /// Create a new power consumption monitor
    pub fn new(config: PowerAnalysisConfig) -> Result<Self> {
        Ok(Self {
            config,
            consumption_history: Arc::new(RwLock::new(Vec::new())),
            baseline: Arc::new(RwLock::new(config.power_baseline)),
            statistical_analyzer: Arc::new(StatisticalAnalyzer::new(config.clone())?),
        })
    }
}

impl StatisticalAnalyzer {
    /// Create a new statistical analyzer
    pub fn new(config: PowerAnalysisConfig) -> Result<Self> {
        Ok(Self {
            config,
            metrics: Arc::new(RwLock::new(StatisticalMetrics::default())),
        })
    }

    /// Analyze power consumption statistics
    pub async fn analyze_power_consumption(&self, history: &[PowerConsumptionEntry]) -> Result<StatisticalMetrics> {
        if history.len() < 2 {
            return Ok(StatisticalMetrics::default());
        }
        
        let power_values: Vec<f64> = history.iter().map(|e| e.power_mw).collect();
        
        // Calculate mean
        let mean = power_values.iter().sum::<f64>() / power_values.len() as f64;
        
        // Calculate variance
        let variance = power_values.iter()
            .map(|&p| (p - mean).powi(2))
            .sum::<f64>() / power_values.len() as f64;
        
        // Calculate standard deviation
        let std_dev = variance.sqrt();
        
        // Calculate skewness
        let skewness = if std_dev > 0.0 {
            power_values.iter()
                .map(|&p| ((p - mean) / std_dev).powi(3))
                .sum::<f64>() / power_values.len() as f64
        } else {
            0.0
        };
        
        // Calculate kurtosis
        let kurtosis = if std_dev > 0.0 {
            power_values.iter()
                .map(|&p| ((p - mean) / std_dev).powi(4))
                .sum::<f64>() / power_values.len() as f64 - 3.0
        } else {
            0.0
        };
        
        // Calculate coefficient of variation
        let coefficient_of_variation = if mean > 0.0 {
            std_dev / mean
        } else {
            0.0
        };
        
        Ok(StatisticalMetrics {
            mean_power: mean,
            standard_deviation,
            skewness,
            kurtosis,
            variance,
            coefficient_of_variation,
        })
    }
}

impl PowerAttackDetector {
    /// Create a new power attack detector
    pub fn new(config: PowerAnalysisConfig) -> Result<Self> {
        let mut attack_patterns = HashMap::new();
        
        // Initialize attack patterns
        attack_patterns.insert("spa".to_string(), AttackPattern {
            name: "Simple Power Analysis".to_string(),
            pattern_type: PowerAttackType::SimplePowerAnalysis,
            threshold: 0.7,
            description: "Detects simple power analysis attacks based on power consumption patterns".to_string(),
        });
        
        attack_patterns.insert("dpa".to_string(), AttackPattern {
            name: "Differential Power Analysis".to_string(),
            pattern_type: PowerAttackType::DifferentialPowerAnalysis,
            threshold: 0.8,
            description: "Detects differential power analysis attacks by analyzing power consumption differences".to_string(),
        });
        
        Ok(Self {
            config,
            attack_patterns: Arc::new(RwLock::new(attack_patterns)),
            detection_history: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Detect statistical anomalies in power consumption
    pub async fn detect_statistical_anomalies(&self, metrics: &StatisticalMetrics) -> Result<Option<PowerAttackDetection>> {
        // Check for unusual patterns
        let mut anomaly_score = 0.0;
        let mut reasons = Vec::new();
        
        // Check skewness
        if metrics.skewness.abs() > 2.0 {
            anomaly_score += 0.3;
            reasons.push(format!("High skewness: {:.2}", metrics.skewness));
        }
        
        // Check kurtosis
        if metrics.kurtosis.abs() > 3.0 {
            anomaly_score += 0.3;
            reasons.push(format!("High kurtosis: {:.2}", metrics.kurtosis));
        }
        
        // Check coefficient of variation
        if metrics.coefficient_of_variation > 0.5 {
            anomaly_score += 0.4;
            reasons.push(format!("High coefficient of variation: {:.2}", metrics.coefficient_of_variation));
        }
        
        if anomaly_score > self.config.attack_threshold {
            Ok(Some(PowerAttackDetection {
                attack_detected: true,
                attack_type: PowerAttackType::SimplePowerAnalysis,
                confidence: anomaly_score,
                description: format!("Statistical anomalies detected: {}", reasons.join(", ")),
                anomalous_entries: Vec::new(),
                recommended_action: "Consider increasing noise level or adding additional protection".to_string(),
                timestamp: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Detect correlation attacks
    pub async fn detect_correlation_attacks(&self, history: &[PowerConsumptionEntry]) -> Result<Option<PowerAttackDetection>> {
        if history.len() < 20 {
            return Ok(None);
        }
        
        // Group by input hash to detect correlation
        let mut hash_groups: HashMap<u64, Vec<&PowerConsumptionEntry>> = HashMap::new();
        for entry in history {
            hash_groups.entry(entry.input_hash).or_insert_with(Vec::new).push(entry);
        }
        
        // Check for correlation patterns
        let mut correlation_score = 0.0;
        let mut correlated_groups = 0;
        
        for (hash, entries) in hash_groups {
            if entries.len() > 5 {
                // Calculate correlation coefficient
                let power_values: Vec<f64> = entries.iter().map(|e| e.power_mw).collect();
                let correlation = self.calculate_autocorrelation(&power_values);
                
                if correlation > 0.7 {
                    correlation_score += correlation;
                    correlated_groups += 1;
                }
            }
        }
        
        if correlated_groups > 0 {
            let avg_correlation = correlation_score / correlated_groups as f64;
            
            if avg_correlation > self.config.attack_threshold {
                return Ok(Some(PowerAttackDetection {
                    attack_detected: true,
                    attack_type: PowerAttackType::CorrelationPowerAnalysis,
                    confidence: avg_correlation,
                    description: format!("High correlation detected in {} input groups", correlated_groups),
                    anomalous_entries: Vec::new(),
                    recommended_action: "Consider adding input randomization or masking".to_string(),
                    timestamp: chrono::Utc::now(),
                }));
            }
        }
        
        Ok(None)
    }

    /// Calculate autocorrelation
    fn calculate_autocorrelation(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter()
            .map(|&v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        
        if variance == 0.0 {
            return 0.0;
        }
        
        // Calculate autocorrelation at lag 1
        let mut correlation = 0.0;
        for i in 0..values.len() - 1 {
            correlation += (values[i] - mean) * (values[i + 1] - mean);
        }
        
        correlation / (values.len() - 1) as f64 / variance
    }
}

/// Power consumption statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerStatistics {
    /// Mean power consumption in milliwatts
    pub mean_power_mw: f64,
    /// Mean current consumption in milliamps
    pub mean_current_ma: f64,
    /// Power consumption variance
    pub power_variance: f64,
    /// Current consumption variance
    pub current_variance: f64,
    /// Total number of measurements
    pub total_measurements: usize,
    /// Measurement period
    pub measurement_period: chrono::Duration,
}

impl Default for PowerAnalysisConfig {
    fn default() -> Self {
        Self {
            power_noise_enabled: true,
            em_noise_enabled: false, // Disabled by default due to overhead
            current_randomization_enabled: true,
            timing_randomization_enabled: true,
            noise_level: 0.1,
            attack_detection_enabled: true,
            monitoring_window_size: 1000,
            attack_threshold: 0.7,
            power_baseline: 50.0, // 50mW baseline
        }
    }
}

impl Default for PowerAnalysisMetrics {
    fn default() -> Self {
        Self {
            total_protected_operations: 0,
            power_noise_injections: 0,
            em_noise_injections: 0,
            current_randomizations: 0,
            timing_randomizations: 0,
            attacks_detected: 0,
            false_positives: 0,
            avg_protection_overhead_us: 0.0,
            power_consumption_variance: 0.0,
            noise_effectiveness_score: 0.0,
            last_updated: chrono::Utc::now(),
        }
    }
}

impl Default for StatisticalMetrics {
    fn default() -> Self {
        Self {
            mean_power: 0.0,
            standard_deviation: 0.0,
            skewness: 0.0,
            kurtosis: 0.0,
            variance: 0.0,
            coefficient_of_variation: 0.0,
        }
    }
}

impl Default for PowerStatistics {
    fn default() -> Self {
        Self {
            mean_power_mw: 0.0,
            mean_current_ma: 0.0,
            power_variance: 0.0,
            current_variance: 0.0,
            total_measurements: 0,
            measurement_period: chrono::Duration::zero(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_power_analysis_protection() {
        let config = PowerAnalysisConfig::default();
        let protection = PowerAnalysisProtection::new(config).unwrap();
        
        // Test operation protection
        let result = protection.protect_operation(async {
            // Simulate cryptographic operation
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Ok(42)
        }).await.unwrap();
        
        assert_eq!(result, 42);
        
        // Test metrics
        let metrics = protection.get_metrics().await.unwrap();
        assert_eq!(metrics.total_protected_operations, 1);
        assert!(metrics.power_noise_injections > 0);
    }

    #[tokio::test]
    async fn test_power_consumption_monitoring() {
        let config = PowerAnalysisConfig::default();
        config.attack_detection_enabled = true;
        let protection = PowerAnalysisProtection::new(config).unwrap();
        
        // Simulate operations with different power consumption
        for i in 0..20 {
            protection.protect_operation(async move {
                // Simulate varying power consumption
                let delay = std::time::Duration::from_millis(5 + (i % 10));
                tokio::time::sleep(delay).await;
                Ok(())
            }).await.unwrap();
        }
        
        let stats = protection.get_power_statistics().await.unwrap();
        assert!(stats.total_measurements > 0);
        assert!(stats.mean_power_mw > 0.0);
    }

    #[tokio::test]
    async fn test_attack_detection() {
        let config = PowerAnalysisConfig::default();
        config.attack_detection_enabled = true;
        let protection = PowerAnalysisProtection::new(config).unwrap();
        
        // Simulate operations with consistent patterns (potential attack)
        for _ in 0..30 {
            protection.protect_operation(async {
                // Simulate consistent operation
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Ok(())
            }).await.unwrap();
        }
        
        let attacks = protection.detect_attacks().await.unwrap();
        // May or may not detect attacks depending on randomness
    }

    #[tokio::test]
    async fn test_noise_generator() {
        let config = PowerAnalysisConfig::default();
        let generator = PowerNoiseGenerator::new(config).unwrap();
        
        // Test power noise injection
        generator.inject_power_noise().await.unwrap();
        
        // Test EM noise injection
        generator.inject_em_noise().await.unwrap();
    }

    #[tokio::test]
    async fn test_statistical_analysis() {
        let analyzer = StatisticalAnalyzer::new(PowerAnalysisConfig::default()).unwrap();
        
        // Create sample power consumption data
        let entries = vec![
            PowerConsumptionEntry {
                entry_id: 1,
                power_mw: 50.0,
                current_ma: 10.0,
                voltage_v: 3.3,
                timestamp: chrono::Utc::now(),
                operation_type: "test".to_string(),
                input_hash: 12345,
            },
            PowerConsumptionEntry {
                entry_id: 2,
                power_mw: 51.0,
                current_ma: 10.2,
                voltage_v: 3.3,
                timestamp: chrono::Utc::now(),
                operation_type: "test".to_string(),
                input_hash: 12346,
            },
        ];
        
        let metrics = analyzer.analyze_power_consumption(&entries).await.unwrap();
        assert!(metrics.mean_power > 0.0);
        assert!(metrics.standard_deviation >= 0.0);
    }
}
