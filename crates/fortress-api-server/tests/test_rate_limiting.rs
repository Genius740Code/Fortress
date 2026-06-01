//! Tests for advanced rate limiting and DDoS protection

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use fortress_api_server::middleware::{AdvancedRateLimiter, RateLimitAlgorithm};
use fortress_api_server::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Create test rate limit configuration
fn create_test_config() -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        requests_per_minute: 10,
        requests_per_hour: 100,
        burst_size: 5,
        algorithm: RateLimitAlgorithm::TokenBucket,
        ddos_protection: DdosProtectionConfig {
            enabled: true,
            global_rps_threshold: Some(100),
            ip_rps_threshold: Some(10),
            auto_block_threshold: Some(20),
            block_duration_seconds: 60,
            reputation_decay_rate: 5,
        },
    }
}

/// Create test rate limit configuration for sliding window
fn create_sliding_window_config() -> RateLimitConfig {
    let mut config = create_test_config();
    config.algorithm = RateLimitAlgorithm::SlidingWindow;
    config
}

/// Create test rate limit configuration for fixed window
fn create_fixed_window_config() -> RateLimitConfig {
    let mut config = create_test_config();
    config.algorithm = RateLimitAlgorithm::FixedWindow;
    config
}

/// Create test rate limit configuration for leaky bucket
fn create_leaky_bucket_config() -> RateLimitConfig {
    let mut config = create_test_config();
    config.algorithm = RateLimitAlgorithm::LeakyBucket;
    config
}

#[tokio::test]
async fn test_token_bucket_rate_limiting() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client";

    // Should allow requests up to burst size
    for i in 0..5 {
        let result = rate_limiter.check_rate_limit(client_id).await;
        assert!(result.is_ok(), "Request {} should be allowed", i);
    }

    // Next request should be denied
    let result = rate_limiter.check_rate_limit(client_id).await;
    assert!(
        result.is_err(),
        "Request should be denied due to rate limit"
    );

    // Wait for token refill
    sleep(Duration::from_secs(2)).await;

    // Should allow one more request after refill
    let result = rate_limiter.check_rate_limit(client_id).await;
    assert!(
        result.is_ok(),
        "Request should be allowed after token refill"
    );
}

#[tokio::test]
async fn test_sliding_window_rate_limiting() {
    let config = create_sliding_window_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client_sliding";

    // Should allow requests up to limit
    for i in 0..10 {
        let result = rate_limiter.check_rate_limit(client_id).await;
        assert!(result.is_ok(), "Request {} should be allowed", i);
    }

    // Next request should be denied
    let result = rate_limiter.check_rate_limit(client_id).await;
    assert!(
        result.is_err(),
        "Request should be denied due to rate limit"
    );

    // Wait for window to slide
    sleep(Duration::from_secs(2)).await;

    // Some requests should be allowed as window slides
    let mut allowed_count = 0;
    for _ in 0..5 {
        if rate_limiter.check_rate_limit(client_id).await.is_ok() {
            allowed_count += 1;
        }
    }

    assert!(
        allowed_count > 0,
        "Some requests should be allowed as window slides"
    );
}

#[tokio::test]
async fn test_fixed_window_rate_limiting() {
    let config = create_fixed_window_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client_fixed";

    // Should allow requests up to limit
    for i in 0..10 {
        let result = rate_limiter.check_rate_limit(client_id).await;
        assert!(result.is_ok(), "Request {} should be allowed", i);
    }

    // Next request should be denied
    let result = rate_limiter.check_rate_limit(client_id).await;
    assert!(
        result.is_err(),
        "Request should be denied due to rate limit"
    );

    // Wait for window to reset
    sleep(Duration::from_secs(61)).await;

    // Should allow requests again after window reset
    let result = rate_limiter.check_rate_limit(client_id).await;
    assert!(
        result.is_ok(),
        "Request should be allowed after window reset"
    );
}

#[tokio::test]
async fn test_leaky_bucket_rate_limiting() {
    let config = create_leaky_bucket_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client_leaky";

    // Should allow requests up to burst size
    for i in 0..5 {
        let result = rate_limiter.check_rate_limit(client_id).await;
        assert!(result.is_ok(), "Request {} should be allowed", i);
    }

    // Next request should be denied
    let result = rate_limiter.check_rate_limit(client_id).await;
    assert!(
        result.is_err(),
        "Request should be denied due to rate limit"
    );

    // Wait for leak
    sleep(Duration::from_secs(2)).await;

    // Should allow one more request after leak
    let result = rate_limiter.check_rate_limit(client_id).await;
    assert!(result.is_ok(), "Request should be allowed after leak");
}

#[tokio::test]
async fn test_different_clients_isolated() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client1 = "client1";
    let client2 = "client2";

    // Exhaust client1's limit
    for i in 0..10 {
        let result = rate_limiter.check_rate_limit(client1).await;
        assert!(result.is_ok(), "Client1 request {} should be allowed", i);
    }

    // Client1 should be rate limited
    let result = rate_limiter.check_rate_limit(client1).await;
    assert!(result.is_err(), "Client1 should be rate limited");

    // Client2 should still be allowed
    let result = rate_limiter.check_rate_limit(client2).await;
    assert!(result.is_ok(), "Client2 should be allowed");
}

#[tokio::test]
async fn test_rate_limit_disabled() {
    let mut config = create_test_config();
    config.enabled = false;

    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client_disabled";

    // Should allow unlimited requests when disabled
    for i in 0..100 {
        let result = rate_limiter.check_rate_limit(client_id).await;
        assert!(
            result.is_ok(),
            "Request {} should be allowed when rate limiting is disabled",
            i
        );
    }
}

#[tokio::test]
async fn test_rate_limit_headers() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client_headers";

    // Make some requests
    for _ in 0..3 {
        rate_limiter.check_rate_limit(client_id).await.unwrap();
    }

    // Check headers
    let headers = rate_limiter.get_rate_limit_headers(client_id).await;
    assert!(headers.is_some(), "Should return rate limit headers");

    let (remaining, limit, reset) = headers.unwrap();
    assert_eq!(limit.to_str().unwrap(), "10");
    assert!(remaining.to_str().unwrap().parse::<u32>().unwrap() <= 7);
}

#[tokio::test]
async fn test_metrics_collection() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client_metrics";

    // Make some requests
    for i in 0..15 {
        rate_limiter.check_rate_limit(client_id).await;
    }

    // Check metrics
    let metrics = rate_limiter.get_metrics();
    assert_eq!(metrics.total_requests, 15);
    assert!(metrics.allowed_requests > 0);
    assert!(metrics.blocked_requests > 0);
}

#[tokio::test]
async fn test_cleanup_functionality() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    // Create activity for multiple clients
    for i in 0..10 {
        let client_id = format!("client_{}", i);
        rate_limiter.check_rate_limit(&client_id).await.unwrap();
    }

    // Run cleanup
    rate_limiter.cleanup().await;

    // Metrics should still be available
    let metrics = rate_limiter.get_metrics();
    assert!(metrics.total_requests > 0);
}

#[tokio::test]
async fn test_ddos_protection_basic() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let ip = "192.168.1.100";
    let client_id = format!("ip:{}", ip);

    // Make requests up to the IP threshold
    for i in 0..15 {
        let result = rate_limiter.check_rate_limit(&client_id).await;
        if i < 10 {
            assert!(result.is_ok(), "Request {} should be allowed", i);
        }
    }

    // Should eventually trigger DDoS protection
    let result = rate_limiter.check_rate_limit(&client_id).await;
    // This might be rate limited or DDoS blocked depending on the exact thresholds
    assert!(result.is_err(), "Should be blocked due to DDoS protection");
}

#[tokio::test]
async fn test_user_vs_ip_isolation() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let user_client = "user:user123";
    let ip_client = "ip:192.168.1.100";

    // Exhaust user limit
    for i in 0..10 {
        rate_limiter.check_rate_limit(user_client).await.unwrap();
    }

    // User should be rate limited
    assert!(rate_limiter.check_rate_limit(user_client).await.is_err());

    // IP should still be allowed (different tracking)
    assert!(rate_limiter.check_rate_limit(ip_client).await.is_ok());
}

#[tokio::test]
async fn test_burst_behavior() {
    let config = create_test_config();
    let rate_limiter = AdvancedRateLimiter::new(config);

    let client_id = "test_client_burst";

    // Should allow burst of requests
    for i in 0..5 {
        let result = rate_limiter.check_rate_limit(client_id).await;
        assert!(result.is_ok(), "Burst request {} should be allowed", i);
    }

    // Should be rate limited after burst
    assert!(rate_limiter.check_rate_limit(client_id).await.is_err());

    // Wait for gradual refill
    sleep(Duration::from_secs(1)).await;

    // Should allow some requests after refill
    let mut allowed = 0;
    for _ in 0..3 {
        if rate_limiter.check_rate_limit(client_id).await.is_ok() {
            allowed += 1;
        }
    }
    assert!(allowed > 0, "Should allow some requests after refill");
}

#[tokio::test]
async fn test_concurrent_requests() {
    let config = create_test_config();
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(config));

    let client_id = "test_client_concurrent";

    // Spawn multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..20 {
        let rate_limiter = rate_limiter.clone();
        let client_id = client_id.to_string();

        let handle = tokio::spawn(async move { rate_limiter.check_rate_limit(&client_id).await });

        handles.push(handle);
    }

    // Wait for all requests to complete
    let mut allowed_count = 0;
    let mut blocked_count = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => allowed_count += 1,
            Err(_) => blocked_count += 1,
        }
    }

    // Should have some allowed and some blocked requests
    assert!(allowed_count > 0, "Should have some allowed requests");
    assert!(blocked_count > 0, "Should have some blocked requests");
    assert_eq!(
        allowed_count + blocked_count,
        20,
        "Total requests should match"
    );
}

#[test]
fn test_rate_limit_config_serialization() {
    let config = create_test_config();

    // Test serialization
    let json = serde_json::to_string(&config).unwrap();
    assert!(!json.is_empty());

    // Test deserialization
    let deserialized: RateLimitConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.requests_per_minute, config.requests_per_minute);
    assert_eq!(deserialized.algorithm, config.algorithm);
    assert!(deserialized.ddos_protection.enabled);
}

#[test]
fn test_rate_limit_algorithm_serialization() {
    let algorithms = vec![
        RateLimitAlgorithm::TokenBucket,
        RateLimitAlgorithm::SlidingWindow,
        RateLimitAlgorithm::FixedWindow,
        RateLimitAlgorithm::LeakyBucket,
    ];

    for algorithm in algorithms {
        let json = serde_json::to_string(&algorithm).unwrap();
        let deserialized: RateLimitAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(algorithm, deserialized);
    }
}
