//! Production Token Bucket Rate Limiter
//! 
//! This module implements a production-ready token bucket algorithm
//! with burst protection, adaptive refilling, and comprehensive metrics.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use crate::error::{FortressError, Result};
use super::{
    ProductionRateLimiter, ProductionRateLimitConfig, RateLimitRequest, RateLimitResponse,
    ProductionRateLimitMetrics, RateLimitSpec, ViolationAction, ThreatLevel, GeoLocation
};

/// Production token bucket rate limiter
pub struct ProductionTokenBucket {
    /// Configuration
    config: Arc<RwLock<ProductionRateLimitConfig>>,
    /// Token buckets per key
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Violation tracking
    violations: Arc<RwLock<HashMap<String, ViolationTracker>>>,
    /// Metrics
    metrics: Arc<RwLock<ProductionRateLimitMetrics>>,
    /// Cleanup task handle
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

/// Individual token bucket
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current token count
    tokens: u64,
    /// Maximum tokens
    max_tokens: u64,
    /// Refill rate per second
    refill_rate: u64,
    /// Last refill timestamp
    last_refill: DateTime<Utc>,
    /// Burst tokens available
    burst_tokens: u64,
    /// Maximum burst tokens
    max_burst: u64,
    /// Bucket creation time
    created_at: DateTime<Utc>,
}

/// Violation tracking for keys
#[derive(Debug, Clone)]
struct ViolationTracker {
    /// Total violations
    total_violations: u64,
    /// Recent violations (last hour)
    recent_violations: Vec<DateTime<Utc>>,
    /// First violation time
    first_violation: Option<DateTime<Utc>>,
    /// Last violation time
    last_violation: Option<DateTime<Utc>>,
    /// Current threat level
    threat_level: ThreatLevel,
    /// Blocked until
    blocked_until: Option<DateTime<Utc>>,
}

impl ProductionTokenBucket {
    /// Create a new production token bucket rate limiter
    pub fn new(config: ProductionRateLimitConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            buckets: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(ProductionRateLimitMetrics::default())),
            cleanup_task: None,
        }
    }

    /// Get rate limit spec for request
    async fn get_rate_limit_spec(&self, request: &RateLimitRequest) -> RateLimitSpec {
        let config = self.config.read().await;
        
        // Prioritize API key limits, then user limits, then IP limits
        if let Some(_) = &request.api_key {
            config.api_key_limits.clone()
        } else if let Some(_) = &request.user_id {
            config.user_limits.clone()
        } else {
            config.ip_limits.clone()
        }
    }

    /// Get or create token bucket for key
    async fn get_or_create_bucket(&self, key: &str, spec: &RateLimitSpec) -> TokenBucket {
        let mut buckets = self.buckets.write().await;
        
        buckets.entry(key.to_string()).or_insert_with(|| TokenBucket {
            tokens: spec.max_burst,
            max_tokens: spec.requests_per_second.max(spec.max_burst),
            refill_rate: spec.requests_per_second,
            last_refill: Utc::now(),
            burst_tokens: spec.max_burst,
            max_burst: spec.max_burst,
            created_at: Utc::now(),
        }).clone()
    }

    /// Get or create violation tracker for key
    async fn get_or_create_violation_tracker(&self, key: &str) -> ViolationTracker {
        let mut violations = self.violations.write().await;
        
        violations.entry(key.to_string()).or_insert_with(|| ViolationTracker {
            total_violations: 0,
            recent_violations: Vec::new(),
            first_violation: None,
            last_violation: None,
            threat_level: ThreatLevel::None,
            blocked_until: None,
        }).clone()
    }

    /// Refill tokens in bucket
    async fn refill_bucket(&self, bucket: &mut TokenBucket, spec: &RateLimitSpec) {
        let now = Utc::now();
        let elapsed = now - bucket.last_refill;
        
        if elapsed.num_seconds() > 0 {
            let elapsed_seconds = elapsed.num_seconds() as u64;
            let tokens_to_add = (elapsed_seconds * bucket.refill_rate).min(bucket.max_tokens - bucket.tokens);
            
            bucket.tokens += tokens_to_add;
            bucket.last_refill = now;
            
            // Refill burst tokens if they were consumed
            if bucket.burst_tokens < bucket.max_burst {
                bucket.burst_tokens = (bucket.burst_tokens + tokens_to_add).min(bucket.max_burst);
            }
        }
    }

    /// Consume tokens from bucket
    fn consume_tokens(&self, bucket: &mut TokenBucket, amount: u64) -> bool {
        let total_available = bucket.tokens + bucket.burst_tokens;
        
        if total_available >= amount {
            // Consume from regular tokens first, then burst tokens
            if bucket.tokens >= amount {
                bucket.tokens -= amount;
            } else {
                let remaining = amount - bucket.tokens;
                bucket.tokens = 0;
                bucket.burst_tokens -= remaining;
            }
            true
        } else {
            false
        }
    }

    /// Calculate threat level based on violations
    fn calculate_threat_level(&self, tracker: &ViolationTracker) -> ThreatLevel {
        let now = Utc::now();
        let recent_violations = tracker.recent_violations.iter()
            .filter(|&&time| now - time < Duration::hours(1))
            .count() as u64;

        match (tracker.total_violations, recent_violations) {
            (0, _) => ThreatLevel::None,
            (1..=5, 0..=2) => ThreatLevel::Low,
            (6..=20, 3..=10) => ThreatLevel::Medium,
            (21..=50, 11..=25) => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    /// Determine violation action based on threat level and history
    async fn determine_violation_action(&self, tracker: &ViolationTracker) -> ViolationAction {
        let config = self.config.read().await;
        let threat_level = tracker.threat_level;
        
        match threat_level {
            ThreatLevel::None => ViolationAction::Monitor,
            ThreatLevel::Low => config.violation_actions.first_violation.clone(),
            ThreatLevel::Medium => config.violation_actions.repeated_violations.clone(),
            ThreatLevel::High | ThreatLevel::Critical => config.violation_actions.severe_violation.clone(),
        }
    }

    /// Update violation tracker
    async fn update_violation_tracker(&self, key: &str, tracker: &mut ViolationTracker) {
        let now = Utc::now();
        
        tracker.total_violations += 1;
        tracker.recent_violations.push(now);
        tracker.last_violation = Some(now);
        
        if tracker.first_violation.is_none() {
            tracker.first_violation = Some(now);
        }
        
        // Clean old violations (older than 1 hour)
        tracker.recent_violations.retain(|&time| now - time < Duration::hours(1));
        
        // Update threat level
        tracker.threat_level = self.calculate_threat_level(tracker);
        
        // Set block duration for severe violations
        if tracker.threat_level >= ThreatLevel::High {
            let config = self.config.read().await;
            let block_duration = Duration::seconds(config.violation_actions.ip_block_duration_seconds);
            tracker.blocked_until = Some(now + block_duration);
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
            
            if response.action == ViolationAction::Throttle {
                metrics.throttled_requests += 1;
            } else if response.action == ViolationAction::Monitor {
                metrics.monitored_requests += 1;
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
        let buckets = self.buckets.clone();
        let violations = self.violations.clone();
        let config = self.config.clone();
        
        let interval = {
            let config_read = config.read().await;
            Duration::seconds(config_read.cleanup_interval_seconds)
        };

        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // Cleanup expired buckets
                {
                    let mut buckets_write = buckets.write().await;
                    let now = Utc::now();
                    
                    buckets_write.retain(|_, bucket| {
                        now - bucket.last_refill < Duration::minutes(30)
                    });
                }
                
                // Cleanup old violations
                {
                    let mut violations_write = violations.write().await;
                    let now = Utc::now();
                    
                    for tracker in violations_write.values_mut() {
                        tracker.recent_violations.retain(|&time| now - time < Duration::hours(1));
                        
                        // Remove block if expired
                        if let Some(blocked_until) = tracker.blocked_until {
                            if now > blocked_until {
                                tracker.blocked_until = None;
                                tracker.threat_level = ThreatLevel::None;
                            }
                        }
                    }
                    
                    // Remove trackers with no recent activity
                    violations_write.retain(|_, tracker| {
                        tracker.recent_violations.len() > 0 || 
                        tracker.blocked_until.is_some() ||
                        tracker.total_violations > 0
                    });
                }
                
                tracing::debug!("Token bucket cleanup completed");
            }
        });

        self.cleanup_task = Some(task);
    }
}

#[async_trait::async_trait]
impl ProductionRateLimiter for ProductionTokenBucket {
    fn name(&self) -> &str {
        "production_token_bucket"
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
        
        // Get or create token bucket
        let mut bucket = self.get_or_create_bucket(&key, &spec);
        
        // Refill tokens
        self.refill_bucket(&mut bucket, &spec).await;
        
        // Check rate limit
        let allowed = self.consume_tokens(&mut bucket, 1);
        let total_available = bucket.tokens + bucket.burst_tokens;
        
        let mut response = RateLimitResponse {
            allowed,
            remaining: total_available,
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
            metadata: HashMap::new(),
        };
        
        // Update violation tracker if not allowed
        if !allowed {
            self.update_violation_tracker(&key, &mut tracker).await;
            response.action = self.determine_violation_action(&tracker).await;
            response.threat_level = tracker.threat_level;
            response.violation_count = tracker.total_violations;
            
            if response.threat_level > ThreatLevel::None {
                response.reason = format!("Rate limit violation - Threat level: {:?}", response.threat_level);
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
        tracing::info!("Token bucket configuration updated");
        Ok(())
    }

    async fn get_metrics(&self) -> Result<ProductionRateLimitMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    async fn reset_rate_limit(&self, key: &str) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        let mut violations = self.violations.write().await;
        
        // Reset bucket
        if let Some(bucket) = buckets.get_mut(key) {
            let spec = self.get_rate_limit_spec(&RateLimitRequest {
                request_id: "reset".to_string(),
                ip_address: key.to_string(),
                user_id: None,
                api_key: None,
                path: "/reset".to_string(),
                method: "POST".to_string(),
                user_agent: None,
                headers: HashMap::new(),
                timestamp: Utc::now(),
                request_size: 0,
                geo_location: None,
                device_fingerprint: None,
                metadata: HashMap::new(),
            }).await;
            
            bucket.tokens = spec.max_burst;
            bucket.burst_tokens = spec.max_burst;
            bucket.last_refill = Utc::now();
        }
        
        // Reset violations
        if let Some(tracker) = violations.get_mut(key) {
            tracker.total_violations = 0;
            tracker.recent_violations.clear();
            tracker.first_violation = None;
            tracker.last_violation = None;
            tracker.threat_level = ThreatLevel::None;
            tracker.blocked_until = None;
        }
        
        tracing::info!("Rate limit reset for key: {}", key);
        Ok(())
    }

    async fn block_ip(&self, ip: &str, duration: Duration) -> Result<()> {
        let key = format!("ip:{}", ip);
        let mut violations = self.violations.write().await;
        
        let tracker = violations.entry(key.clone()).or_insert_with(|| ViolationTracker {
            total_violations: 0,
            recent_violations: Vec::new(),
            first_violation: None,
            last_violation: None,
            threat_level: ThreatLevel::High,
            blocked_until: None,
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
            recent_violations: Vec::new(),
            first_violation: None,
            last_violation: None,
            threat_level: ThreatLevel::High,
            blocked_until: None,
        });
        
        tracker.blocked_until = Some(Utc::now() + duration);
        tracker.threat_level = ThreatLevel::High;
        
        tracing::warn!("User {} suspended until {:?}", user_id, tracker.blocked_until);
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        let mut violations = self.violations.write().await;
        let now = Utc::now();
        
        // Cleanup old buckets
        buckets.retain(|_, bucket| {
            now - bucket.last_refill < Duration::minutes(30)
        });
        
        // Cleanup old violations
        for tracker in violations.values_mut() {
            tracker.recent_violations.retain(|&time| now - time < Duration::hours(1));
            
            if let Some(blocked_until) = tracker.blocked_until {
                if now > blocked_until {
                    tracker.blocked_until = None;
                    tracker.threat_level = ThreatLevel::None;
                }
            }
        }
        
        // Remove inactive trackers
        violations.retain(|_, tracker| {
            tracker.recent_violations.len() > 0 || 
            tracker.blocked_until.is_some() ||
            tracker.total_violations > 0
        });
        
        tracing::debug!("Token bucket cleanup completed");
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        // Stop cleanup task
        if let Some(task) = &self.cleanup_task {
            task.abort();
        }
        
        tracing::info!("Token bucket rate limiter shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_creation() {
        let config = ProductionRateLimitConfig::default();
        let limiter = ProductionTokenBucket::new(config);
        
        assert_eq!(limiter.name(), "production_token_bucket");
        
        let metrics = limiter.get_metrics().await.unwrap();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.allowed_requests, 0);
        assert_eq!(metrics.rejected_requests, 0);
    }

    #[tokio::test]
    async fn test_basic_rate_limiting() {
        let config = ProductionRateLimitConfig::default();
        let limiter = ProductionTokenBucket::new(config);
        
        let request = RateLimitRequest {
            request_id: "test-1".to_string(),
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
        assert_eq!(response.action, ViolationAction::Monitor);
        assert_eq!(response.threat_level, ThreatLevel::None);
    }

    #[tokio::test]
    async fn test_violation_tracking() {
        let config = ProductionRateLimitConfig::default();
        let limiter = ProductionTokenBucket::new(config);
        
        // Create a request that will exceed limits
        let request = RateLimitRequest {
            request_id: "test-violation".to_string(),
            ip_address: "192.168.1.2".to_string(),
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

        // Make multiple requests to trigger violations
        let mut violations = 0;
        for i in 0..100 {
            let mut req = request.clone();
            req.request_id = format!("test-{}", i);
            let response = limiter.check_rate_limit(&req).await.unwrap();
            if !response.allowed {
                violations += 1;
            }
        }

        assert!(violations > 0);
        
        let metrics = limiter.get_metrics().await.unwrap();
        assert!(metrics.rejected_requests > 0);
        assert!(metrics.violations_detected > 0);
    }

    #[tokio::test]
    async fn test_ip_blocking() {
        let config = ProductionRateLimitConfig::default();
        let limiter = ProductionTokenBucket::new(config);
        
        let ip = "192.168.1.3";
        let duration = Duration::minutes(5);
        
        // Block IP
        limiter.block_ip(ip, duration).await.unwrap();
        
        let request = RateLimitRequest {
            request_id: "blocked-test".to_string(),
            ip_address: ip.to_string(),
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

        // Request should be blocked
        let response = limiter.check_rate_limit(&request).await.unwrap();
        assert!(!response.allowed);
        assert_eq!(response.action, ViolationAction::TemporaryBlock);
        assert_eq!(response.threat_level, ThreatLevel::High);
    }
}
