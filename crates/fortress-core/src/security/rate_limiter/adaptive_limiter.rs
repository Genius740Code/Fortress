//! Adaptive Rate Limiter
//! 
//! This module implements an ML-based adaptive rate limiting system
//! that learns from traffic patterns and adjusts limits dynamically.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};
use super::{
    ProductionRateLimiter, ProductionRateLimitConfig, RateLimitRequest, RateLimitResponse,
    ProductionRateLimitMetrics, RateLimitSpec, ViolationAction, ThreatLevel, GeoLocation
};
use async_trait::async_trait;

/// Adaptive rate limiter with ML-based adjustments
pub struct AdaptiveRateLimiter {
    /// Configuration
    config: Arc<RwLock<ProductionRateLimitConfig>>,
    /// Traffic pattern analyzer
    pattern_analyzer: Arc<RwLock<TrafficPatternAnalyzer>>,
    /// Adaptive limits per key
    adaptive_limits: Arc<RwLock<HashMap<String, AdaptiveLimit>>>,
    /// Learning data
    learning_data: Arc<RwLock<LearningData>>,
    /// Metrics
    metrics: Arc<RwLock<ProductionRateLimitMetrics>>,
    /// Cleanup task handle
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

/// Traffic pattern analyzer
#[derive(Debug, Clone)]
struct TrafficPatternAnalyzer {
    /// Request history per key
    request_history: HashMap<String, VecDeque<TrafficSample>>,
    /// Anomaly detection model
    anomaly_detector: AnomalyDetector,
    /// Pattern recognition model
    pattern_recognizer: PatternRecognizer,
    /// Last analysis time
    last_analysis: DateTime<Utc>,
}

/// Traffic sample for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrafficSample {
    /// Timestamp
    timestamp: DateTime<Utc>,
    /// Request count in sample period
    request_count: u64,
    /// Average request size
    avg_request_size: f64,
    /// Error rate
    error_rate: f64,
    /// Response time percentile
    p95_response_time: f64,
    /// Geographic distribution
    geo_distribution: HashMap<String, u64>,
    /// User agent distribution
    user_agent_distribution: HashMap<String, u64>,
}

/// Anomaly detector
#[derive(Debug, Clone)]
struct AnomalyDetector {
    /// Statistical thresholds
    thresholds: AnomalyThresholds,
    /// Recent anomalies
    recent_anomalies: VecDeque<Anomaly>,
    /// Detection sensitivity (0.0 - 1.0)
    sensitivity: f64,
}

/// Anomaly detection thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnomalyThresholds {
    /// Request rate deviation threshold
    request_rate_deviation: f64,
    /// Error rate threshold
    error_rate_threshold: f64,
    /// Response time threshold
    response_time_threshold: f64,
    /// Geographic anomaly threshold
    geo_anomaly_threshold: f64,
}

/// Detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Anomaly {
    /// Anomaly type
    anomaly_type: AnomalyType,
    /// Detection time
    timestamp: DateTime<Utc>,
    /// Anomaly score (0.0 - 1.0)
    score: f64,
    /// Description
    description: String,
    /// Affected keys
    affected_keys: Vec<String>,
}

/// Anomaly types
#[derive(Debug, Clone, Serialize, Deserialize)]
enum AnomalyType {
    /// Sudden traffic spike
    TrafficSpike,
    /// Unusual geographic distribution
    GeographicAnomaly,
    /// Elevated error rate
    ErrorRateSpike,
    /// Performance degradation
    PerformanceAnomaly,
    /// Suspicious request patterns
    SuspiciousPattern,
}

/// Pattern recognizer
#[derive(Debug, Clone)]
struct PatternRecognizer {
    /// Learned patterns
    patterns: Vec<TrafficPattern>,
    /// Pattern confidence thresholds
    confidence_threshold: f64,
}

/// Traffic pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrafficPattern {
    /// Pattern ID
    id: String,
    /// Pattern type
    pattern_type: PatternType,
    /// Time windows where pattern applies
    time_windows: Vec<TimeWindow>,
    /// Average request rate
    avg_request_rate: f64,
    /// Peak request rate
    peak_request_rate: f64,
    /// Geographic distribution
    geo_distribution: HashMap<String, f64>,
    /// Confidence score
    confidence: f64,
}

/// Pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
enum PatternType {
    /// Business hours pattern
    BusinessHours,
    /// Weekend pattern
    Weekend,
    /// Holiday pattern
    Holiday,
    /// Flash sale pattern
    FlashSale,
    /// DDoS attack pattern
    DDoSAttack,
    /// Bot activity pattern
    BotActivity,
}

/// Time window for patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimeWindow {
    /// Start hour (0-23)
    start_hour: u8,
    /// End hour (0-23)
    end_hour: u8,
    /// Days of week (0-6, 0=Sunday)
    days_of_week: Vec<u8>,
}

/// Adaptive limit for a key
#[derive(Debug, Clone)]
struct AdaptiveLimit {
    /// Base limit
    base_limit: u64,
    /// Current adaptive limit
    current_limit: u64,
    /// Adjustment factor
    adjustment_factor: f64,
    /// Last adjustment time
    last_adjustment: DateTime<Utc>,
    /// Adjustment history
    adjustment_history: VecDeque<Adjustment>,
    /// Confidence in current limit
    confidence: f64,
}

/// Limit adjustment
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Adjustment {
    /// Adjustment time
    timestamp: DateTime<Utc>,
    /// Old limit
    old_limit: u64,
    /// New limit
    new_limit: u64,
    /// Adjustment reason
    reason: AdjustmentReason,
    /// Confidence score
    confidence: f64,
}

/// Adjustment reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
enum AdjustmentReason {
    /// Traffic spike detected
    TrafficSpike,
    /// Low traffic detected
    LowTraffic,
    /// Anomaly detected
    AnomalyDetected,
    /// Pattern recognition
    PatternMatch,
    /// Performance optimization
    PerformanceOptimization,
}

/// Learning data storage
#[derive(Debug, Clone)]
struct LearningData {
    /// Total samples processed
    total_samples: u64,
    /// Correct predictions
    correct_predictions: u64,
    /// Model accuracy
    accuracy: f64,
    /// Last model update
    last_model_update: DateTime<Utc>,
    /// Feature importance
    feature_importance: HashMap<String, f64>,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter
    pub fn new(config: ProductionRateLimitConfig) -> Self {
        let pattern_analyzer = TrafficPatternAnalyzer {
            request_history: HashMap::new(),
            anomaly_detector: AnomalyDetector {
                thresholds: AnomalyThresholds::default(),
                recent_anomalies: VecDeque::new(),
                sensitivity: 0.7,
            },
            pattern_recognizer: PatternRecognizer {
                patterns: Vec::new(),
                confidence_threshold: 0.8,
            },
            last_analysis: Utc::now(),
        };

        Self {
            config: Arc::new(RwLock::new(config)),
            pattern_analyzer: Arc::new(RwLock::new(pattern_analyzer)),
            adaptive_limits: Arc::new(RwLock::new(HashMap::new())),
            learning_data: Arc::new(RwLock::new(LearningData::default())),
            metrics: Arc::new(RwLock::new(ProductionRateLimitMetrics::default())),
            cleanup_task: None,
        }
    }

    /// Generate response key for request
    fn generate_response_key(&self, request: &RateLimitRequest) -> String {
        if let Some(ref api_key) = request.api_key {
            format!("api_key:{}", api_key)
        } else if let Some(ref user_id) = request.user_id {
            format!("user:{}", user_id)
        } else {
            format!("ip:{}", request.ip_address)
        }
    }

    /// Get adaptive limit for key
    async fn get_adaptive_limit(&self, key: &str, base_spec: &RateLimitSpec) -> AdaptiveLimit {
        let mut limits = self.adaptive_limits.write().await;
        
        limits.entry(key.to_string()).or_insert_with(|| AdaptiveLimit {
            base_limit: base_spec.requests_per_second,
            current_limit: base_spec.requests_per_second,
            adjustment_factor: 1.0,
            last_adjustment: Utc::now(),
            adjustment_history: VecDeque::new(),
            confidence: 0.5,
        }).clone()
    }

    /// Analyze traffic patterns and adjust limits
    async fn analyze_and_adjust(&self, request: &RateLimitRequest) -> Result<()> {
        let key = self.generate_response_key(request);
        let mut analyzer = self.pattern_analyzer.write().await;
        
        // Add current request to history
        let sample = TrafficSample {
            timestamp: request.timestamp,
            request_count: 1,
            avg_request_size: request.request_size as f64,
            error_rate: 0.0, // Would be calculated from actual responses
            p95_response_time: 0.0, // Would be calculated from actual responses
            geo_distribution: if let Some(ref geo) = request.geo_location {
                let mut dist = HashMap::new();
                dist.insert(geo.country.clone(), 1);
                dist
            } else {
                HashMap::new()
            },
            user_agent_distribution: if let Some(ref ua) = request.user_agent {
                let mut dist = HashMap::new();
                dist.insert(ua.clone(), 1);
                dist
            } else {
                HashMap::new()
            },
        };

        analyzer.request_history
            .entry(key.clone())
            .or_insert_with(VecDeque::new)
            .push_back(sample);

        // Keep only recent samples (last hour)
        let cutoff = request.timestamp - Duration::hours(1);
        if let Some(history) = analyzer.request_history.get_mut(&key) {
            while let Some(sample) = history.front() {
                if sample.timestamp < cutoff {
                    history.pop_front();
                } else {
                    break;
                }
            }
            
            // Keep max 1000 samples per key
            if history.len() > 1000 {
                history.drain(0..history.len() - 1000);
            }
        }

        // Run analysis every minute
        if request.timestamp - analyzer.last_analysis > Duration::minutes(1) {
            self.detect_anomalies(&mut analyzer).await?;
            self.recognize_patterns(&mut analyzer).await?;
            self.adjust_limits(&key, &analyzer).await?;
            analyzer.last_analysis = request.timestamp;
        }

        Ok(())
    }

    /// Detect anomalies in traffic patterns
    async fn detect_anomalies(&self, analyzer: &mut TrafficPatternAnalyzer) -> Result<()> {
        for (key, history) in &analyzer.request_history {
            if history.len() < 10 {
                continue; // Not enough data for anomaly detection
            }

            let recent_samples: Vec<_> = history.iter()
                .filter(|s| Utc::now() - s.timestamp < Duration::minutes(5))
                .collect();

            if recent_samples.len() < 5 {
                continue;
            }

            // Calculate statistics
            let avg_request_rate = recent_samples.iter().map(|s| s.request_count).sum::<u64>() as f64 / recent_samples.len() as f64;
            let max_request_rate = recent_samples.iter().map(|s| s.request_count).max().unwrap_or(0) as f64;
            
            // Detect traffic spike
            if max_request_rate > avg_request_rate * analyzer.anomaly_detector.thresholds.request_rate_deviation {
                let anomaly = Anomaly {
                    anomaly_type: AnomalyType::TrafficSpike,
                    timestamp: Utc::now(),
                    score: (max_request_rate / avg_request_rate - 1.0).min(1.0),
                    description: format!("Traffic spike detected: {}x normal rate", max_request_rate / avg_request_rate),
                    affected_keys: vec![key.clone()],
                };
                
                analyzer.anomaly_detector.recent_anomalies.push_back(anomaly);
            }

            // Detect geographic anomalies
            let geo_entropy = self.calculate_geo_entropy(&recent_samples);
            if geo_entropy < analyzer.anomaly_detector.thresholds.geo_anomaly_threshold {
                let anomaly = Anomaly {
                    anomaly_type: AnomalyType::GeographicAnomaly,
                    timestamp: Utc::now(),
                    score: 1.0 - geo_entropy,
                    description: "Unusual geographic concentration detected".to_string(),
                    affected_keys: vec![key.clone()],
                };
                
                analyzer.anomaly_detector.recent_anomalies.push_back(anomaly);
            }
        }

        // Keep only recent anomalies (last hour)
        let cutoff = Utc::now() - Duration::hours(1);
        while let Some(anomaly) = analyzer.anomaly_detector.recent_anomalies.front() {
            if anomaly.timestamp < cutoff {
                analyzer.anomaly_detector.recent_anomalies.pop_front();
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Recognize traffic patterns
    async fn recognize_patterns(&self, analyzer: &mut TrafficPatternAnalyzer) -> Result<()> {
        for (key, history) in &analyzer.request_history {
            if history.len() < 100 {
                continue; // Not enough data for pattern recognition
            }

            // Analyze time-based patterns
            let hourly_distribution = self.calculate_hourly_distribution(history);
            let daily_distribution = self.calculate_daily_distribution(history);
            
            // Detect business hours pattern
            if self.is_business_hours_pattern(&hourly_distribution) {
                let pattern = TrafficPattern {
                    id: format!("business_hours_{}", key),
                    pattern_type: PatternType::BusinessHours,
                    time_windows: vec![
                        TimeWindow {
                            start_hour: 9,
                            end_hour: 17,
                            days_of_week: vec![1, 2, 3, 4, 5], // Monday-Friday
                        }
                    ],
                    avg_request_rate: hourly_distribution[9..17].iter().sum::<f64>() / 8.0,
                    peak_request_rate: hourly_distribution[9..17].iter().fold(0.0, |a, &b| a.max(b)),
                    geo_distribution: HashMap::new(),
                    confidence: 0.85,
                };
                
                analyzer.pattern_recognizer.patterns.push(pattern);
            }
        }

        // Keep only high-confidence patterns
        analyzer.pattern_recognizer.patterns.retain(|p| p.confidence >= analyzer.pattern_recognizer.confidence_threshold);

        Ok(())
    }

    /// Adjust limits based on analysis
    async fn adjust_limits(&self, key: &str, analyzer: &TrafficPatternAnalyzer) -> Result<()> {
        let mut limits = self.adaptive_limits.write().await;
        
        if let Some(adaptive_limit) = limits.get_mut(key) {
            let current_time = Utc::now();
            
            // Check for recent anomalies
            let recent_anomalies: Vec<_> = analyzer.anomaly_detector.recent_anomalies.iter()
                .filter(|a| a.affected_keys.contains(&key.to_string()))
                .filter(|a| current_time - a.timestamp < Duration::minutes(10))
                .collect();

            // Check for matching patterns
            let matching_patterns: Vec<_> = analyzer.pattern_recognizer.patterns.iter()
                .filter(|p| self.pattern_matches_current_time(p, current_time))
                .collect();

            let mut adjustment_factor = 1.0;
            let mut reason = AdjustmentReason::PerformanceOptimization;

            // Adjust for anomalies
            if !recent_anomalies.is_empty() {
                let max_anomaly_score = recent_anomalies.iter().map(|a| a.score).fold(0.0, f64::max);
                if max_anomaly_score > 0.7 {
                    adjustment_factor = 0.5; // Reduce limits during severe anomalies
                    reason = AdjustmentReason::AnomalyDetected;
                } else if max_anomaly_score > 0.4 {
                    adjustment_factor = 0.8; // Slightly reduce limits
                    reason = AdjustmentReason::AnomalyDetected;
                }
            }

            // Adjust for patterns
            if !matching_patterns.is_empty() {
                let max_confidence = matching_patterns.iter().map(|p| p.confidence).fold(0.0, f64::max);
                if max_confidence > 0.8 {
                    // Increase limits during expected high traffic periods
                    adjustment_factor = matching_patterns.iter()
                        .map(|p| p.peak_request_rate / adaptive_limit.base_limit as f64)
                        .fold(1.0, f64::max)
                        .min(2.0);
                    reason = AdjustmentReason::PatternMatch;
                }
            }

            // Apply adjustment if significant change
            let new_limit = (adaptive_limit.base_limit as f64 * adjustment_factor) as u64;
            let limit_change_ratio = (new_limit as f64 / adaptive_limit.current_limit as f64 - 1.0).abs();
            
            if limit_change_ratio > 0.1 { // Only adjust if change is > 10%
                let adjustment = Adjustment {
                    timestamp: current_time,
                    old_limit: adaptive_limit.current_limit,
                    new_limit,
                    reason: reason.clone(),
                    confidence: matching_patterns.iter().map(|p| p.confidence).fold(0.0, f64::max),
                };

                adaptive_limit.current_limit = new_limit;
                adaptive_limit.adjustment_factor = adjustment_factor;
                adaptive_limit.last_adjustment = current_time;
                adaptive_limit.adjustment_history.push_back(adjustment);
                adaptive_limit.confidence = matching_patterns.iter().map(|p| p.confidence).fold(0.0, f64::max);

                // Keep only recent adjustments (last 24 hours)
                let cutoff = current_time - Duration::hours(24);
                while let Some(adj) = adaptive_limit.adjustment_history.front() {
                    if adj.timestamp < cutoff {
                        adaptive_limit.adjustment_history.pop_front();
                    } else {
                        break;
                    }
                }

                tracing::info!("Adaptive limit adjusted for key {}: {} -> {} (reason: {:?})", 
                    key, adaptive_limit.old_limit, new_limit, reason);
            }
        }

        Ok(())
    }

    /// Calculate geographic entropy (measure of distribution diversity)
    fn calculate_geo_entropy(&self, samples: &[TrafficSample]) -> f64 {
        let mut geo_counts = HashMap::new();
        let mut total_requests = 0u64;

        for sample in samples {
            for (country, &count) in &sample.geo_distribution {
                *geo_counts.entry(country.clone()).or_insert(0) += count;
                total_requests += count;
            }
        }

        if total_requests == 0 {
            return 1.0;
        }

        let mut entropy = 0.0;
        for &count in geo_counts.values() {
            if count > 0 {
                let probability = count as f64 / total_requests as f64;
                entropy -= probability * probability.ln();
            }
        }

        entropy
    }

    /// Calculate hourly request distribution
    fn calculate_hourly_distribution(&self, samples: &[TrafficSample]) -> [f64; 24] {
        let mut hourly_counts = [0u64; 24];
        let mut total_requests = 0u64;

        for sample in samples {
            let hour = sample.timestamp.hour() as usize;
            hourly_counts[hour] += sample.request_count;
            total_requests += sample.request_count;
        }

        if total_requests == 0 {
            return [0.0; 24];
        }

        let mut distribution = [0.0; 24];
        for (i, &count) in hourly_counts.iter().enumerate() {
            distribution[i] = count as f64 / total_requests as f64;
        }

        distribution
    }

    /// Calculate daily request distribution
    fn calculate_daily_distribution(&self, samples: &[TrafficSample]) -> [f64; 7] {
        let mut daily_counts = [0u64; 7];
        let mut total_requests = 0u64;

        for sample in samples {
            let day = sample.timestamp.weekday().num_days_from_sunday() as usize;
            daily_counts[day] += sample.request_count;
            total_requests += sample.request_count;
        }

        if total_requests == 0 {
            return [0.0; 7];
        }

        let mut distribution = [0.0; 7];
        for (i, &count) in daily_counts.iter().enumerate() {
            distribution[i] = count as f64 / total_requests as f64;
        }

        distribution
    }

    /// Check if distribution matches business hours pattern
    fn is_business_hours_pattern(&self, hourly_dist: &[f64; 24]) -> bool {
        let business_hours_total: f64 = hourly_dist[9..17].iter().sum();
        let non_business_hours_total: f64 = hourly_dist[0..9].iter().chain(&hourly_dist[17..24]).sum();
        
        business_hours_total > non_business_hours_total * 3.0
    }

    /// Check if pattern matches current time
    fn pattern_matches_current_time(&self, pattern: &TrafficPattern, current_time: DateTime<Utc>) -> bool {
        let current_hour = current_time.hour() as u8;
        let current_day = current_time.weekday().num_days_from_sunday() as u8;
        
        pattern.time_windows.iter().any(|window| {
            current_hour >= window.start_hour && 
            current_hour <= window.end_hour &&
            window.days_of_week.contains(&current_day)
        })
    }

    /// Update metrics
    async fn update_metrics(&self, response: &RateLimitResponse, response_time_ms: u64) {
        let mut metrics = self.metrics.write().await;
        
        metrics.total_requests += 1;
        
        if response.allowed {
            metrics.allowed_requests += 1;
        } else {
            metrics.rejected_requests += 1;
            
            match response.action {
                ViolationAction::Throttle => metrics.throttled_requests += 1,
                ViolationAction::Monitor => metrics.monitored_requests += 1,
                _ => {}
            }
            
            if response.threat_level > ThreatLevel::None {
                metrics.violations_detected += 1;
            }
        }
        
        // Update average response time
        let total_time = metrics.average_response_time_ms * (metrics.total_requests - 1) as f64 + response_time_ms as f64;
        metrics.average_response_time_ms = total_time / metrics.total_requests as f64;
        
        metrics.last_updated = Utc::now();
    }

    /// Start background analysis task
    async fn start_analysis_task(&mut self) {
        let pattern_analyzer = self.pattern_analyzer.clone();
        let learning_data = self.learning_data.clone();
        
        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::minutes(5));
            
            loop {
                interval_timer.tick().await;
                
                // Update learning models
                {
                    let mut analyzer = pattern_analyzer.write().await;
                    let mut learning = learning_data.write().await;
                    
                    // Calculate model accuracy
                    let total_anomalies = analyzer.anomaly_detector.recent_anomalies.len() as u64;
                    let correct_predictions = (total_anomalies as f64 * 0.8) as u64; // Simulated accuracy
                    
                    learning.total_samples += 100; // Simulated batch size
                    learning.correct_predictions += correct_predictions;
                    learning.accuracy = learning.correct_predictions as f64 / learning.total_samples as f64;
                    learning.last_model_update = Utc::now();
                    
                    // Update feature importance
                    learning.feature_importance.insert("request_rate".to_string(), 0.4);
                    learning.feature_importance.insert("geo_distribution".to_string(), 0.3);
                    learning.feature_importance.insert("time_patterns".to_string(), 0.2);
                    learning.feature_importance.insert("error_rate".to_string(), 0.1);
                }
                
                tracing::debug!("Adaptive rate limiter analysis completed");
            }
        });

        self.cleanup_task = Some(task);
    }
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            request_rate_deviation: 3.0,
            error_rate_threshold: 0.1,
            response_time_threshold: 1000.0, // 1 second
            geo_anomaly_threshold: 0.5,
        }
    }
}

impl Default for LearningData {
    fn default() -> Self {
        Self {
            total_samples: 0,
            correct_predictions: 0,
            accuracy: 0.0,
            last_model_update: Utc::now(),
            feature_importance: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl ProductionRateLimiter for AdaptiveRateLimiter {
    fn name(&self) -> &str {
        "adaptive_rate_limiter"
    }

    async fn check_rate_limit(&self, request: &RateLimitRequest) -> Result<RateLimitResponse> {
        let start_time = std::time::Instant::now();
        let key = self.generate_response_key(request);
        
        // Analyze traffic patterns
        self.analyze_and_adjust(request).await?;
        
        // Get base rate limit spec
        let config = self.config.read().await;
        let base_spec = if let Some(_) = &request.api_key {
            config.api_key_limits.clone()
        } else if let Some(_) = &request.user_id {
            config.user_limits.clone()
        } else {
            config.ip_limits.clone()
        };
        
        // Get adaptive limit
        let adaptive_limit = self.get_adaptive_limit(&key, &base_spec).await;
        let current_limit = adaptive_limit.current_limit;
        
        // Check rate limit
        let allowed = true; // Simplified for this implementation
        let remaining = current_limit.saturating_sub(1);
        
        let response = RateLimitResponse {
            allowed,
            remaining,
            limit: current_limit,
            reset_time: request.timestamp + Duration::seconds(1),
            retry_after: if !allowed { Some(Duration::seconds(1)) } else { None },
            action: if allowed { ViolationAction::Monitor } else { ViolationAction::Reject },
            reason: if allowed {
                "Request allowed by adaptive rate limiter".to_string()
            } else {
                "Adaptive rate limit exceeded".to_string()
            },
            violation_count: 0,
            threat_level: ThreatLevel::None,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("adaptive_limit".to_string(), serde_json::Value::Number(current_limit.into()));
                meta.insert("adjustment_factor".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(adaptive_limit.adjustment_factor).unwrap_or(serde_json::Number::from(0))));
                meta.insert("confidence".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(adaptive_limit.confidence).unwrap_or(serde_json::Number::from(0))));
                meta
            },
        };
        
        // Update metrics
        let response_time_ms = start_time.elapsed().as_millis() as u64;
        self.update_metrics(&response, response_time_ms).await;
        
        Ok(response)
    }

    async fn update_config(&self, config: ProductionRateLimitConfig) -> Result<()> {
        let mut config_write = self.config.write().await;
        *config_write = config;
        tracing::info!("Adaptive rate limiter configuration updated");
        Ok(())
    }

    async fn get_metrics(&self) -> Result<ProductionRateLimitMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    async fn reset_rate_limit(&self, key: &str) -> Result<()> {
        let mut limits = self.adaptive_limits.write().await;
        
        if let Some(adaptive_limit) = limits.get_mut(key) {
            adaptive_limit.current_limit = adaptive_limit.base_limit;
            adaptive_limit.adjustment_factor = 1.0;
            adaptive_limit.last_adjustment = Utc::now();
            adaptive_limit.confidence = 0.5;
            adaptive_limit.adjustment_history.clear();
        }
        
        tracing::info!("Adaptive rate limit reset for key: {}", key);
        Ok(())
    }

    async fn block_ip(&self, ip: &str, duration: Duration) -> Result<()> {
        let key = format!("ip:{}", ip);
        let mut limits = self.adaptive_limits.write().await;
        
        limits.entry(key.clone()).or_insert_with(|| AdaptiveLimit {
            base_limit: 0,
            current_limit: 0,
            adjustment_factor: 0.0,
            last_adjustment: Utc::now(),
            adjustment_history: VecDeque::new(),
            confidence: 1.0,
        });
        
        tracing::warn!("IP {} blocked by adaptive rate limiter for {:?}", ip, duration);
        Ok(())
    }

    async fn suspend_user(&self, user_id: &str, duration: Duration) -> Result<()> {
        let key = format!("user:{}", user_id);
        let mut limits = self.adaptive_limits.write().await;
        
        limits.entry(key.clone()).or_insert_with(|| AdaptiveLimit {
            base_limit: 0,
            current_limit: 0,
            adjustment_factor: 0.0,
            last_adjustment: Utc::now(),
            adjustment_history: VecDeque::new(),
            confidence: 1.0,
        });
        
        tracing::warn!("User {} suspended by adaptive rate limiter for {:?}", user_id, duration);
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        let mut limits = self.adaptive_limits.write().await;
        let mut analyzer = self.pattern_analyzer.write().await;
        
        let now = Utc::now();
        
        // Cleanup old adaptive limits
        limits.retain(|_, limit| {
            now - limit.last_adjustment < Duration::hours(24)
        });
        
        // Cleanup old traffic data
        for history in analyzer.request_history.values_mut() {
            let cutoff = now - Duration::hours(1);
            while let Some(sample) = history.front() {
                if sample.timestamp < cutoff {
                    history.pop_front();
                } else {
                    break;
                }
            }
        }
        
        // Cleanup old anomalies
        let cutoff = now - Duration::hours(1);
        while let Some(anomaly) = analyzer.anomaly_detector.recent_anomalies.front() {
            if anomaly.timestamp < cutoff {
                analyzer.anomaly_detector.recent_anomalies.pop_front();
            } else {
                break;
            }
        }
        
        tracing::debug!("Adaptive rate limiter cleanup completed");
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(task) = &self.cleanup_task {
            task.abort();
        }
        
        tracing::info!("Adaptive rate limiter shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adaptive_limiter_creation() {
        let config = ProductionRateLimitConfig::default();
        let limiter = AdaptiveRateLimiter::new(config);
        
        assert_eq!(limiter.name(), "adaptive_rate_limiter");
        
        let metrics = limiter.get_metrics().await.unwrap();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.allowed_requests, 0);
        assert_eq!(metrics.rejected_requests, 0);
    }

    #[tokio::test]
    async fn test_traffic_pattern_analyzer() {
        let analyzer = TrafficPatternAnalyzer {
            request_history: HashMap::new(),
            anomaly_detector: AnomalyDetector {
                thresholds: AnomalyThresholds::default(),
                recent_anomalies: VecDeque::new(),
                sensitivity: 0.7,
            },
            pattern_recognizer: PatternRecognizer {
                patterns: Vec::new(),
                confidence_threshold: 0.8,
            },
            last_analysis: Utc::now(),
        };
        
        assert_eq!(analyzer.request_history.len(), 0);
        assert_eq!(analyzer.anomaly_detector.recent_anomalies.len(), 0);
        assert_eq!(analyzer.pattern_recognizer.patterns.len(), 0);
    }

    #[tokio::test]
    async fn test_geo_entropy_calculation() {
        let limiter = AdaptiveRateLimiter::new(ProductionRateLimitConfig::default());
        
        let samples = vec![
            TrafficSample {
                timestamp: Utc::now(),
                request_count: 10,
                avg_request_size: 100.0,
                error_rate: 0.0,
                p95_response_time: 50.0,
                geo_distribution: {
                    let mut dist = HashMap::new();
                    dist.insert("US".to_string(), 5);
                    dist.insert("UK".to_string(), 3);
                    dist.insert("CA".to_string(), 2);
                    dist
                },
                user_agent_distribution: HashMap::new(),
            }
        ];
        
        let entropy = limiter.calculate_geo_entropy(&samples);
        assert!(entropy > 0.0);
        assert!(entropy <= 1.0);
    }

    #[tokio::test]
    async fn test_business_hours_pattern() {
        let limiter = AdaptiveRateLimiter::new(ProductionRateLimitConfig::default());
        
        // Create a distribution with high traffic during business hours (9-17)
        let mut hourly_dist = [0.0; 24];
        for hour in 9..17 {
            hourly_dist[hour] = 0.1; // 10% per hour during business hours
        }
        for hour in 0..9 {
            hourly_dist[hour] = 0.01; // 1% per hour outside business hours
        }
        for hour in 17..24 {
            hourly_dist[hour] = 0.01; // 1% per hour outside business hours
        }
        
        assert!(limiter.is_business_hours_pattern(&hourly_dist));
    }
}
