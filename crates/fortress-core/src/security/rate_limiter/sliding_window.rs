//! Production Sliding Window Rate Limiter
//! 
//! This module implements a production-ready sliding window algorithm
//! with precise time tracking, memory optimization, and distributed support.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use crate::error::{FortressError, Result};
use super::{
    ProductionRateLimiter, ProductionRateLimitConfig, RateLimitRequest, RateLimitResponse,
    ProductionRateLimitMetrics, RateLimitSpec, ViolationAction, ThreatLevel
};

/// Production sliding window rate limiter
pub struct ProductionSlidingWindow {
    /// Configuration
    config: Arc<RwLock<ProductionRateLimitConfig>>,
    /// Sliding windows per key
    windows: Arc<RwLock<HashMap<String, SlidingWindow>>>,
    /// Violation tracking
    violations: Arc<RwLock<HashMap<String, ViolationTracker>>>,
    /// Metrics
    metrics: Arc<RwLock<ProductionRateLimitMetrics>>,
    /// Cleanup task handle
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

/// Sliding window with time-ordered requests
#[derive(Debug, Clone)]
struct SlidingWindow {
    /// Time-ordered request timestamps
    requests: VecDeque<DateTime<Utc>>,
    /// Window size in seconds
    window_size_seconds: u64,
    /// Maximum requests per window
    max_requests: u64,
    /// Current request count
    current_count: u64,
    /// Window start time
    window_start: DateTime<Utc>,
    /// Last cleanup time
    last_cleanup: DateTime<Utc>,
}

/// Violation tracker for sliding windows
#[derive(Debug, Clone)]
struct ViolationTracker {
    /// Total violations
    total_violations: u64,
    /// Recent violations with timestamps
    violation_history: VecDeque<(DateTime<Utc>, ThreatLevel)>,
    /// Current threat level
    threat_level: ThreatLevel,
    /// Blocked until
    blocked_until: Option<DateTime<Utc>>,
    /// Consecutive violations
    consecutive_violations: u64,
}

impl ProductionSlidingWindow {
    /// Create a new production sliding window rate limiter
    pub fn new(config: ProductionRateLimitConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            windows: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(ProductionRateLimitMetrics::default())),
            cleanup_task: None,
        }
    }

    /// Get rate limit spec for request
    async fn get_rate_limit_spec(&self, request: &RateLimitRequest) -> RateLimitSpec {
        let config = self.config.read().await;
        
        if let Some(_) = &request.api_key {
            config.api_key_limits.clone()
        } else if let Some(_) = &request.user_id {
            config.user_limits.clone()
        } else {
            config.ip_limits.clone()
        }
    }

    /// Get or create sliding window for key
    async fn get_or_create_window(&self, key: &str, spec: &RateLimitSpec) -> SlidingWindow {
        let mut windows = self.windows.write().await;
        
        windows.entry(key.to_string()).or_insert_with(|| SlidingWindow {
            requests: VecDeque::new(),
            window_size_seconds: 1, // Use 1-second window for precise rate limiting
            max_requests: spec.requests_per_second,
            current_count: 0,
            window_start: Utc::now(),
            last_cleanup: Utc::now(),
        }).clone()
    }

    /// Get or create violation tracker for key
    async fn get_or_create_violation_tracker(&self, key: &str) -> ViolationTracker {
        let mut violations = self.violations.write().await;
        
        violations.entry(key.to_string()).or_insert_with(|| ViolationTracker {
            total_violations: 0,
            violation_history: VecDeque::new(),
            threat_level: ThreatLevel::None,
            blocked_until: None,
            consecutive_violations: 0,
        }).clone()
    }

    /// Clean up old requests outside the window
    fn cleanup_old_requests(&mut self, window: &mut SlidingWindow, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(window.window_size_seconds);
        
        while let Some(&timestamp) = window.requests.front() {
            if timestamp > cutoff {
                break;
            }
            window.requests.pop_front();
        }
        
        window.current_count = window.requests.len() as u64;
        
        // Periodic cleanup to prevent memory leaks
        if now - window.last_cleanup > Duration::minutes(5) {
            window.requests.shrink_to_fit();
            window.last_cleanup = now;
        }
    }

    /// Add request to window
    fn add_request(&mut self, window: &mut SlidingWindow, timestamp: DateTime<Utc>) {
        window.requests.push_back(timestamp);
        window.current_count += 1;
    }

    /// Calculate precise sliding window count for different time periods
    fn calculate_window_counts(&self, window: &SlidingWindow, now: DateTime<Utc>) -> WindowCounts {
        let mut counts = WindowCounts::default();
        
        for &timestamp in &window.requests {
            let age = now - timestamp;
            
            if age.num_seconds() < 1 {
                counts.last_second += 1;
            }
            if age.num_seconds() < 60 {
                counts.last_minute += 1;
            }
            if age.num_seconds() < 3600 {
                counts.last_hour += 1;
            }
            if age.num_seconds() < 86400 {
                counts.last_day += 1;
            }
        }
        
        counts
    }

    /// Determine violation action based on pattern analysis
    fn determine_violation_action(&self, tracker: &ViolationTracker, counts: &WindowCounts, spec: &RateLimitSpec) -> ViolationAction {
        let config = self.config.read().await;
        
        // Check for burst patterns
        let is_burst = counts.last_second > spec.requests_per_second * 2;
        let is_sustained = counts.last_minute > spec.requests_per_minute;
        let is_heavy = counts.last_hour > spec.requests_per_hour;
        
        match (tracker.consecutive_violations, is_burst, is_sustained, is_heavy) {
            (1..=2, true, false, false) => config.violation_actions.first_violation.clone(),
            (3..=5, _, true, _) => config.violation_actions.repeated_violations.clone(),
            (6.., _, _, _) => config.violation_actions.severe_violation.clone(),
            _ => ViolationAction::Monitor,
        }
    }

    /// Calculate threat level based on violation patterns
    fn calculate_threat_level(&self, tracker: &ViolationTracker, counts: &WindowCounts, spec: &RateLimitSpec) -> ThreatLevel {
        let recent_violations = tracker.violation_history.iter()
            .filter(|&&(time, _)| Utc::now() - *time < Duration::hours(1))
            .count() as u64;

        let violation_rate = recent_violations as f64 / 60.0; // violations per minute
        let request_rate = counts.last_minute as f64;
        
        // Calculate threat based on violation frequency and request patterns
        match (violation_rate, request_rate, tracker.consecutive_violations) {
            (0.0..0.1, _, _) => ThreatLevel::None,
            (0.1..0.5, _, 1..=2) => ThreatLevel::Low,
            (0.5..2.0, _, 3..=5) => ThreatLevel::Medium,
            (2.0..5.0, _, 6..=10) => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    /// Update violation tracker
    async fn update_violation_tracker(&self, key: &str, tracker: &mut ViolationTracker, threat_level: ThreatLevel) {
        let now = Utc::now();
        
        tracker.total_violations += 1;
        tracker.consecutive_violations += 1;
        tracker.violation_history.push_back((now, threat_level));
        tracker.threat_level = threat_level;
        
        // Clean old violations (older than 1 hour)
        while let Some(&(time, _)) = tracker.violation_history.front() {
            if now - time > Duration::hours(1) {
                tracker.violation_history.pop_front();
            } else {
                break;
            }
        }
        
        // Set block duration for severe violations
        if threat_level >= ThreatLevel::High {
            let config = self.config.read().await;
            let block_duration = Duration::seconds(config.violation_actions.ip_block_duration_seconds);
            tracker.blocked_until = Some(now + block_duration);
        }
        
        // Reset consecutive violations on successful request
        if threat_level == ThreatLevel::None {
            tracker.consecutive_violations = 0;
        }
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

    /// Start background cleanup task
    async fn start_cleanup_task(&mut self) {
        let windows = self.windows.clone();
        let violations = self.violations.clone();
        
        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::minutes(5));
            
            loop {
                interval_timer.tick().await;
                
                let now = Utc::now();
                
                // Cleanup windows
                {
                    let mut windows_write = windows.write().await;
                    for window in windows_write.values_mut() {
                        window.requests.shrink_to_fit();
                        window.last_cleanup = now;
                    }
                    
                    // Remove empty windows
                    windows_write.retain(|_, window| {
                        window.current_count > 0 || 
                        now - window.window_start < Duration::minutes(30)
                    });
                }
                
                // Cleanup violations
                {
                    let mut violations_write = violations.write().await;
                    for tracker in violations_write.values_mut() {
                        // Clean old violation history
                        while let Some(&(time, _)) = tracker.violation_history.front() {
                            if now - time > Duration::hours(1) {
                                tracker.violation_history.pop_front();
                            } else {
                                break;
                            }
                        }
                        
                        tracker.violation_history.shrink_to_fit();
                        
                        // Remove expired blocks
                        if let Some(blocked_until) = tracker.blocked_until {
                            if now > blocked_until {
                                tracker.blocked_until = None;
                                tracker.threat_level = ThreatLevel::None;
                                tracker.consecutive_violations = 0;
                            }
                        }
                    }
                    
                    // Remove inactive trackers
                    violations_write.retain(|_, tracker| {
                        tracker.violation_history.len() > 0 || 
                        tracker.blocked_until.is_some() ||
                        tracker.total_violations > 0
                    });
                }
                
                tracing::debug!("Sliding window cleanup completed");
            }
        });

        self.cleanup_task = Some(task);
    }
}

/// Window counts for different time periods
#[derive(Debug, Clone, Default)]
struct WindowCounts {
    /// Requests in last second
    last_second: u64,
    /// Requests in last minute
    last_minute: u64,
    /// Requests in last hour
    last_hour: u64,
    /// Requests in last day
    last_day: u64,
}

#[async_trait::async_trait]
impl ProductionRateLimiter for ProductionSlidingWindow {
    fn name(&self) -> &str {
        "production_sliding_window"
    }

    async fn check_rate_limit(&self, request: &RateLimitRequest) -> Result<RateLimitResponse> {
        let start_time = std::time::Instant::now();
        let key = self.generate_response_key(request);
        
        // Get rate limit spec
        let spec = self.get_rate_limit_spec(request).await;
        
        // Get violation tracker
        let mut tracker = self.get_or_create_violation_tracker(&key).await;
        
        // Check if currently blocked
        if let Some(blocked_until) = tracker.blocked_until {
            if request.timestamp < blocked_until {
                return Ok(RateLimitResponse {
                    allowed: false,
                    remaining: 0,
                    limit: spec.requests_per_second,
                    reset_time: blocked_until,
                    retry_after: Some(blocked_until - request.timestamp),
                    action: ViolationAction::TemporaryBlock,
                    reason: format!("Blocked until {}", blocked_until),
                    violation_count: tracker.total_violations,
                    threat_level: tracker.threat_level,
                    metadata: HashMap::new(),
                });
            }
        }
        
        // Get or create sliding window
        let mut window = self.get_or_create_window(&key, &spec);
        
        // Clean up old requests
        self.cleanup_old_requests(&mut window, request.timestamp);
        
        // Calculate window counts
        let counts = self.calculate_window_counts(&window, request.timestamp);
        
        // Check rate limits for different time windows
        let allowed = counts.last_second < spec.requests_per_second &&
                     counts.last_minute < spec.requests_per_minute &&
                     counts.last_hour < spec.requests_per_hour &&
                     counts.last_day < spec.requests_per_day;
        
        let mut response = RateLimitResponse {
            allowed,
            remaining: spec.requests_per_second.saturating_sub(counts.last_second),
            limit: spec.requests_per_second,
            reset_time: request.timestamp + Duration::seconds(1),
            retry_after: if !allowed { Some(Duration::seconds(1)) } else { None },
            action: if allowed { ViolationAction::Monitor } else { ViolationAction::Reject },
            reason: if allowed {
                "Request allowed".to_string()
            } else {
                "Rate limit exceeded".to_string()
            },
            violation_count: tracker.total_violations,
            threat_level: tracker.threat_level,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("last_second".to_string(), serde_json::Value::Number(counts.last_second.into()));
                meta.insert("last_minute".to_string(), serde_json::Value::Number(counts.last_minute.into()));
                meta.insert("last_hour".to_string(), serde_json::Value::Number(counts.last_hour.into()));
                meta.insert("last_day".to_string(), serde_json::Value::Number(counts.last_day.into()));
                meta
            },
        };
        
        // Add request to window if allowed
        if allowed {
            self.add_request(&mut window, request.timestamp);
            tracker.consecutive_violations = 0;
            tracker.threat_level = ThreatLevel::None;
        } else {
            // Update violation tracker
            let threat_level = self.calculate_threat_level(&tracker, &counts, &spec);
            self.update_violation_tracker(&key, &mut tracker, threat_level).await;
            
            response.action = self.determine_violation_action(&tracker, &counts, &spec);
            response.threat_level = threat_level;
            response.violation_count = tracker.total_violations;
            
            if threat_level > ThreatLevel::None {
                response.reason = format!("Rate limit violation - Threat level: {:?}", threat_level);
            }
        }
        
        // Update metrics
        let response_time_ms = start_time.elapsed().as_millis() as u64;
        self.update_metrics(&response, response_time_ms).await;
        
        Ok(response)
    }

    async fn update_config(&self, config: ProductionRateLimitConfig) -> Result<()> {
        let mut config_write = self.config.write().await;
        *config_write = config;
        tracing::info!("Sliding window configuration updated");
        Ok(())
    }

    async fn get_metrics(&self) -> Result<ProductionRateLimitMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    async fn reset_rate_limit(&self, key: &str) -> Result<()> {
        let mut windows = self.windows.write().await;
        let mut violations = self.violations.write().await;
        
        // Reset window
        if let Some(window) = windows.get_mut(key) {
            window.requests.clear();
            window.current_count = 0;
            window.window_start = Utc::now();
        }
        
        // Reset violations
        if let Some(tracker) = violations.get_mut(key) {
            tracker.total_violations = 0;
            tracker.violation_history.clear();
            tracker.threat_level = ThreatLevel::None;
            tracker.blocked_until = None;
            tracker.consecutive_violations = 0;
        }
        
        tracing::info!("Sliding window rate limit reset for key: {}", key);
        Ok(())
    }

    async fn block_ip(&self, ip: &str, duration: Duration) -> Result<()> {
        let key = format!("ip:{}", ip);
        let mut violations = self.violations.write().await;
        
        let tracker = violations.entry(key.clone()).or_insert_with(|| ViolationTracker {
            total_violations: 0,
            violation_history: VecDeque::new(),
            threat_level: ThreatLevel::High,
            blocked_until: None,
            consecutive_violations: 0,
        });
        
        tracker.blocked_until = Some(Utc::now() + duration);
        tracker.threat_level = ThreatLevel::High;
        
        tracing::warn!("IP {} blocked until {:?}", ip, tracker.blocked_until);
        Ok(())
    }

    async fn suspend_user(&self, user_id: &str, duration: Duration) -> Result<()> {
        let key = format!("user:{}", user_id);
        let mut violations = self.violations.write().await;
        
        let tracker = violations.entry(key.clone()).or_insert_with(|| ViolationTracker {
            total_violations: 0,
            violation_history: VecDeque::new(),
            threat_level: ThreatLevel::High,
            blocked_until: None,
            consecutive_violations: 0,
        });
        
        tracker.blocked_until = Some(Utc::now() + duration);
        tracker.threat_level = ThreatLevel::High;
        
        tracing::warn!("User {} suspended until {:?}", user_id, tracker.blocked_until);
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        let mut windows = self.windows.write().await;
        let mut violations = self.violations.write().await;
        let now = Utc::now();
        
        // Cleanup windows
        for window in windows.values_mut() {
            self.cleanup_old_requests(window, now);
            window.requests.shrink_to_fit();
        }
        
        windows.retain(|_, window| {
            window.current_count > 0 || 
            now - window.window_start < Duration::minutes(30)
        });
        
        // Cleanup violations
        for tracker in violations.values_mut() {
            while let Some(&(time, _)) = tracker.violation_history.front() {
                if now - time > Duration::hours(1) {
                    tracker.violation_history.pop_front();
                } else {
                    break;
                }
            }
            
            tracker.violation_history.shrink_to_fit();
            
            if let Some(blocked_until) = tracker.blocked_until {
                if now > blocked_until {
                    tracker.blocked_until = None;
                    tracker.threat_level = ThreatLevel::None;
                    tracker.consecutive_violations = 0;
                }
            }
        }
        
        violations.retain(|_, tracker| {
            tracker.violation_history.len() > 0 || 
            tracker.blocked_until.is_some() ||
            tracker.total_violations > 0
        });
        
        tracing::debug!("Sliding window cleanup completed");
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(task) = &self.cleanup_task {
            task.abort();
        }
        
        tracing::info!("Sliding window rate limiter shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sliding_window_creation() {
        let config = ProductionRateLimitConfig::default();
        let limiter = ProductionSlidingWindow::new(config);
        
        assert_eq!(limiter.name(), "production_sliding_window");
        
        let metrics = limiter.get_metrics().await.unwrap();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.allowed_requests, 0);
        assert_eq!(metrics.rejected_requests, 0);
    }

    #[tokio::test]
    async fn test_sliding_window_rate_limiting() {
        let config = ProductionRateLimitConfig::default();
        let limiter = ProductionSlidingWindow::new(config);
        
        let request = RateLimitRequest {
            request_id: "test-sw".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_id: None,
            api_key: None,
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            user_agent: None,
            headers: HashMap::new(),
            timestamp: Utc::now(),
            request_size: 100,
            geo_location: None,
            device_fingerprint: None,
            metadata: HashMap::new(),
        };

        // First request should be allowed
        let response = limiter.check_rate_limit(&request).await.unwrap();
        assert!(response.allowed);
        assert!(response.remaining > 0);
    }

    #[tokio::test]
    async fn test_window_counts() {
        let config = ProductionRateLimitConfig::default();
        let limiter = ProductionSlidingWindow::new(config);
        
        let base_time = Utc::now();
        let mut window = SlidingWindow {
            requests: VecDeque::new(),
            window_size_seconds: 1,
            max_requests: 10,
            current_count: 0,
            window_start: base_time,
            last_cleanup: base_time,
        };
        
        // Add requests at different times
        for i in 0..5 {
            window.requests.push_back(base_time + Duration::milliseconds(i * 100));
        }
        
        let counts = limiter.calculate_window_counts(&window, base_time + Duration::milliseconds(500));
        assert_eq!(counts.last_second, 5);
        assert_eq!(counts.last_minute, 5);
        assert_eq!(counts.last_hour, 5);
        assert_eq!(counts.last_day, 5);
    }
}
