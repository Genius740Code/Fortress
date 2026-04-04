//! Simple test for rate limiting functionality

use fortress_server::middleware::{AdvancedRateLimiter, RateLimitAlgorithm};
use fortress_server::config::{RateLimitConfig, DdosProtectionConfig};
use fortress_server::error::ServerError;

#[tokio::test]
async fn test_basic_rate_limiting() {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_minute: 5,
        requests_per_hour: 100,
        burst_size: 3,
        algorithm: RateLimitAlgorithm::TokenBucket,
        ddos_protection: DdosProtectionConfig::default(),
    };
    
    let rate_limiter = AdvancedRateLimiter::new(config);
    
    // Should allow requests up to burst size
    for i in 0..3 {
        let result = rate_limiter.check_rate_limit("test_client").await;
        assert!(result.is_ok(), "Request {} should be allowed", i);
    }
    
    // Next request should be denied
    let result = rate_limiter.check_rate_limit("test_client").await;
    assert!(result.is_err(), "Request should be denied due to rate limit");
}

#[tokio::test]
async fn test_different_clients() {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_minute: 2,
        requests_per_hour: 10,
        burst_size: 2,
        algorithm: RateLimitAlgorithm::TokenBucket,
        ddos_protection: DdosProtectionConfig::default(),
    };
    
    let rate_limiter = AdvancedRateLimiter::new(config);
    
    // Exhaust client1's limit
    for i in 0..2 {
        let result = rate_limiter.check_rate_limit("client1").await;
        assert!(result.is_ok(), "Client1 request {} should be allowed", i);
    }
    
    // Client1 should be rate limited
    let result = rate_limiter.check_rate_limit("client1").await;
    assert!(result.is_err(), "Client1 should be rate limited");
    
    // Client2 should still be allowed
    let result = rate_limiter.check_rate_limit("client2").await;
    assert!(result.is_ok(), "Client2 should be allowed");
}

#[tokio::test]
async fn test_rate_limit_disabled() {
    let mut config = RateLimitConfig {
        enabled: true,
        requests_per_minute: 5,
        requests_per_hour: 100,
        burst_size: 3,
        algorithm: RateLimitAlgorithm::TokenBucket,
        ddos_protection: DdosProtectionConfig::default(),
    };
    config.enabled = false;
    
    let rate_limiter = AdvancedRateLimiter::new(config);
    
    // Should allow unlimited requests when disabled
    for i in 0..10 {
        let result = rate_limiter.check_rate_limit("test_client").await;
        assert!(result.is_ok(), "Request {} should be allowed when rate limiting is disabled", i);
    }
}

#[tokio::test]
async fn test_algorithms() {
    let algorithms = vec![
        RateLimitAlgorithm::TokenBucket,
        RateLimitAlgorithm::SlidingWindow,
        RateLimitAlgorithm::FixedWindow,
        RateLimitAlgorithm::LeakyBucket,
    ];
    
    for algorithm in algorithms {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_minute: 10,
            requests_per_hour: 100,
            burst_size: 5,
            algorithm: algorithm.clone(),
            ddos_protection: DdosProtectionConfig::default(),
        };
        
        let rate_limiter = AdvancedRateLimiter::new(config);
        
        // Should allow some requests
        let mut allowed_count = 0;
        for i in 0..15 {
            if rate_limiter.check_rate_limit(&format!("client_{:?}", algorithm)).await.is_ok() {
                allowed_count += 1;
            }
        }
        
        assert!(allowed_count > 0, "Algorithm {:?} should allow some requests", algorithm);
        assert!(allowed_count < 15, "Algorithm {:?} should block some requests", algorithm);
    }
}

#[tokio::test]
async fn test_metrics() {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_minute: 5,
        requests_per_hour: 100,
        burst_size: 3,
        algorithm: RateLimitAlgorithm::TokenBucket,
        ddos_protection: DdosProtectionConfig::default(),
    };
    
    let rate_limiter = AdvancedRateLimiter::new(config);
    
    // Make some requests
    for i in 0..10 {
        rate_limiter.check_rate_limit("test_client").await;
    }
    
    // Check metrics
    let metrics = rate_limiter.get_metrics();
    assert_eq!(metrics.total_requests, 10);
    assert!(metrics.allowed_requests > 0);
    assert!(metrics.blocked_requests > 0);
    assert_eq!(metrics.allowed_requests + metrics.blocked_requests, 10);
}

#[test]
fn test_config_serialization() {
    let config = RateLimitConfig {
        enabled: true,
        requests_per_minute: 60,
        requests_per_hour: 1000,
        burst_size: 10,
        algorithm: RateLimitAlgorithm::TokenBucket,
        ddos_protection: DdosProtectionConfig::default(),
    };
    
    // Test serialization
    let json = serde_json::to_string(&config).unwrap();
    assert!(!json.is_empty());
    
    // Test deserialization
    let deserialized: RateLimitConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.requests_per_minute, config.requests_per_minute);
    assert_eq!(deserialized.algorithm, config.algorithm);
}
