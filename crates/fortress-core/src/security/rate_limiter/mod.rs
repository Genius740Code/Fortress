//! Production Rate Limiting Module
//! 
//! This module provides enterprise-grade rate limiting capabilities with
//! multiple algorithms, distributed support, and intelligent protection.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use crate::error::{FortressError, Result};

pub mod token_bucket;
pub mod sliding_window;
pub mod adaptive_limiter;
pub mod distributed_limiter;
pub mod middleware;

pub use token_bucket::ProductionTokenBucket;
pub use sliding_window::ProductionSlidingWindow;
pub use adaptive_limiter::AdaptiveRateLimiter;
pub use distributed_limiter::DistributedRateLimiter;
pub use middleware::RateLimitMiddleware;

/// Production rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionRateLimitConfig {
    /// Default limits per IP
    pub ip_limits: RateLimitSpec,
    /// Default limits per user
    pub user_limits: RateLimitSpec,
    /// Default limits per API key
    pub api_key_limits: RateLimitSpec,
    /// Burst protection multiplier
    pub burst_multiplier: f64,
    /// Adaptive rate limiting enabled
    pub adaptive_enabled: bool,
    /// Distributed rate limiting enabled
    pub distributed_enabled: bool,
    /// Threat intelligence integration
    pub threat_intelligence_enabled: bool,
    /// Rate limit violation actions
    pub violation_actions: ViolationActions,
    /// Cleanup interval in seconds
    pub cleanup_interval_seconds: u64,
    /// Metrics collection enabled
    pub metrics_enabled: bool,
}

/// Rate limit specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSpec {
    /// Requests per second
    pub requests_per_second: u64,
    /// Requests per minute
    pub requests_per_minute: u64,
    /// Requests per hour
    pub requests_per_hour: u64,
    /// Requests per day
    pub requests_per_day: u64,
    /// Maximum burst size
    pub max_burst: u64,
}

/// Violation actions configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationActions {
    /// Action on first violation
    pub first_violation: ViolationAction,
    /// Action on repeated violations
    pub repeated_violations: ViolationAction,
    /// Action on severe violations
    pub severe_violation: ViolationAction,
    /// IP blocking duration in seconds
    pub ip_block_duration_seconds: u64,
    /// User suspension duration in seconds
    pub user_suspension_duration_seconds: u64,
}

/// Violation action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationAction {
    /// Reject with HTTP 429
    Reject,
    /// Throttle requests
    Throttle,
    /// Add to monitoring queue
    Monitor,
    /// Temporary block
    TemporaryBlock,
    /// Escalate to security team
    Escalate,
}

/// Rate limit request context
#[derive(Debug, Clone)]
pub struct RateLimitRequest {
    /// Unique request ID
    pub request_id: String,
    /// Client IP address
    pub ip_address: String,
    /// User ID if authenticated
    pub user_id: Option<String>,
    /// API key if used
    pub api_key: Option<String>,
    /// Request path
    pub path: String,
    /// HTTP method
    pub method: String,
    /// User agent
    pub user_agent: Option<String>,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Request size in bytes
    pub request_size: u64,
    /// Geographic location
    pub geo_location: Option<GeoLocation>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Geographic location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Country code
    pub country: String,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// ISP
    pub isp: Option<String>,
    /// Autonomous system number
    pub asn: Option<u32>,
}

/// Enhanced rate limit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitResponse {
    /// Whether request is allowed
    pub allowed: bool,
    /// Remaining requests in current window
    pub remaining: u64,
    /// Total limit for current window
    pub limit: u64,
    /// When limit resets
    pub reset_time: DateTime<Utc>,
    /// Suggested retry after duration
    pub retry_after: Option<Duration>,
    /// Action taken
    pub action: ViolationAction,
    /// Reason for action
    pub reason: String,
    /// Violation count
    pub violation_count: u64,
    /// Threat level
    pub threat_level: ThreatLevel,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Threat level assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    /// No threat detected
    None,
    /// Low threat level
    Low,
    /// Medium threat level
    Medium,
    /// High threat level
    High,
    /// Critical threat level
    Critical,
}

/// Production rate limiting metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionRateLimitMetrics {
    /// Total requests processed
    pub total_requests: u64,
    /// Requests allowed
    pub allowed_requests: u64,
    /// Requests rejected
    pub rejected_requests: u64,
    /// Requests throttled
    pub throttled_requests: u64,
    /// Requests monitored
    pub monitored_requests: u64,
    /// Violations detected
    pub violations_detected: u64,
    /// IP addresses blocked
    pub ips_blocked: u64,
    /// Users suspended
    pub users_suspended: u64,
    /// Average response time in milliseconds
    pub average_response_time_ms: f64,
    /// Cache hit rate
    pub cache_hit_rate: f64,
    /// Distributed sync success rate
    pub distributed_sync_success_rate: f64,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// Trait for production rate limiting algorithms
pub trait ProductionRateLimiter: Send + Sync {
    /// Name of the rate limiter
    fn name(&self) -> &str;
    
    /// Check rate limit for a request
    async fn check_rate_limit(&self, request: &RateLimitRequest) -> Result<RateLimitResponse>;
    
    /// Update rate limit configuration
    async fn update_config(&self, config: ProductionRateLimitConfig) -> Result<()>;
    
    /// Get current metrics
    async fn get_metrics(&self) -> Result<ProductionRateLimitMetrics>;
    
    /// Reset rate limit for a specific key
    async fn reset_rate_limit(&self, key: &str) -> Result<()>;
    
    /// Block an IP address
    async fn block_ip(&self, ip: &str, duration: Duration) -> Result<()>;
    
    /// Suspend a user
    async fn suspend_user(&self, user_id: &str, duration: Duration) -> Result<()>;
    
    /// Cleanup expired data
    async fn cleanup(&self) -> Result<()>;
    
    /// Shutdown the rate limiter
    async fn shutdown(&self) -> Result<()>;
}

impl Default for ProductionRateLimitConfig {
    fn default() -> Self {
        Self {
            ip_limits: RateLimitSpec {
                requests_per_second: 10,
                requests_per_minute: 100,
                requests_per_hour: 1000,
                requests_per_day: 10000,
                max_burst: 50,
            },
            user_limits: RateLimitSpec {
                requests_per_second: 100,
                requests_per_minute: 1000,
                requests_per_hour: 10000,
                requests_per_day: 100000,
                max_burst: 500,
            },
            api_key_limits: RateLimitSpec {
                requests_per_second: 1000,
                requests_per_minute: 10000,
                requests_per_hour: 100000,
                requests_per_day: 1000000,
                max_burst: 5000,
            },
            burst_multiplier: 2.0,
            adaptive_enabled: true,
            distributed_enabled: false,
            threat_intelligence_enabled: true,
            violation_actions: ViolationActions {
                first_violation: ViolationAction::Monitor,
                repeated_violations: ViolationAction::Throttle,
                severe_violation: ViolationAction::TemporaryBlock,
                ip_block_duration_seconds: 3600, // 1 hour
                user_suspension_duration_seconds: 7200, // 2 hours
            },
            cleanup_interval_seconds: 300, // 5 minutes
            metrics_enabled: true,
        }
    }
}

impl Default for RateLimitSpec {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            requests_per_minute: 100,
            requests_per_hour: 1000,
            requests_per_day: 10000,
            max_burst: 50,
        }
    }
}

impl Default for ViolationActions {
    fn default() -> Self {
        Self {
            first_violation: ViolationAction::Monitor,
            repeated_violations: ViolationAction::Throttle,
            severe_violation: ViolationAction::TemporaryBlock,
            ip_block_duration_seconds: 3600,
            user_suspension_duration_seconds: 7200,
        }
    }
}

impl Default for ProductionRateLimitMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            allowed_requests: 0,
            rejected_requests: 0,
            throttled_requests: 0,
            monitored_requests: 0,
            violations_detected: 0,
            ips_blocked: 0,
            users_suspended: 0,
            average_response_time_ms: 0.0,
            cache_hit_rate: 0.0,
            distributed_sync_success_rate: 0.0,
            last_updated: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_rate_limit_config_default() {
        let config = ProductionRateLimitConfig::default();
        assert_eq!(config.ip_limits.requests_per_second, 10);
        assert_eq!(config.user_limits.requests_per_second, 100);
        assert_eq!(config.api_key_limits.requests_per_second, 1000);
        assert!(config.adaptive_enabled);
        assert!(!config.distributed_enabled);
        assert!(config.threat_intelligence_enabled);
    }

    #[test]
    fn test_rate_limit_spec_default() {
        let spec = RateLimitSpec::default();
        assert_eq!(spec.requests_per_second, 10);
        assert_eq!(spec.requests_per_minute, 100);
        assert_eq!(spec.requests_per_hour, 1000);
        assert_eq!(spec.requests_per_day, 10000);
        assert_eq!(spec.max_burst, 50);
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::None < ThreatLevel::Low);
        assert!(ThreatLevel::Low < ThreatLevel::Medium);
        assert!(ThreatLevel::Medium < ThreatLevel::High);
        assert!(ThreatLevel::High < ThreatLevel::Critical);
    }

    #[test]
    fn test_geo_location_creation() {
        let location = GeoLocation {
            country: "US".to_string(),
            region: Some("CA".to_string()),
            city: Some("San Francisco".to_string()),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            isp: Some("Example ISP".to_string()),
            asn: Some(12345),
        };
        
        assert_eq!(location.country, "US");
        assert_eq!(location.region, Some("CA".to_string()));
        assert_eq!(location.city, Some("San Francisco".to_string()));
        assert_eq!(location.latitude, Some(37.7749));
        assert_eq!(location.longitude, Some(-122.4194));
        assert_eq!(location.isp, Some("Example ISP".to_string()));
        assert_eq!(location.asn, Some(12345));
    }
}
