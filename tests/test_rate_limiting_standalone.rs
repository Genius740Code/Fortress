//! Standalone test for rate limiting functionality

use std::sync::Arc;
use serde::{Deserialize, Serialize};

// Copy the essential structures for testing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    LeakyBucket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosProtectionConfig {
    pub enabled: bool,
    pub global_rps_threshold: Option<u32>,
    pub ip_rps_threshold: Option<u32>,
    pub auto_block_threshold: Option<u32>,
    pub block_duration_seconds: u64,
    pub reputation_decay_rate: u8,
}

impl Default for DdosProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_rps_threshold: None,
            ip_rps_threshold: None,
            auto_block_threshold: None,
            block_duration_seconds: 300,
            reputation_decay_rate: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_size: u32,
    pub algorithm: RateLimitAlgorithm,
    pub ddos_protection: DdosProtectionConfig,
}

// Simplified rate limiter for testing
#[derive(Clone)]
pub struct TestRateLimiter {
    config: RateLimitConfig,
    storage: Arc<DashMap<String, u32>>,
}

impl TestRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            storage: Arc::new(DashMap::new()),
        }
    }

    pub async fn check_rate_limit(&self, client_id: &str) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut count = self.storage.entry(client_id.to_string()).or_insert(0);
        
        if *count >= self.config.requests_per_minute {
            return Err("Rate limit exceeded".to_string());
        }
        
        *count += 1;
        Ok(())
    }

    pub fn get_metrics(&self) -> RateLimitMetricsSnapshot {
        RateLimitMetricsSnapshot {
            total_requests: self.storage.iter().map(|entry| *entry.value()).sum(),
            allowed_requests: self.storage.iter().map(|entry| *entry.value()).sum(),
            blocked_requests: 0,
            ddos_blocks: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitMetricsSnapshot {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub ddos_blocks: u64,
}

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
    
    let rate_limiter = TestRateLimiter::new(config);
    
    // Should allow requests up to limit
    for i in 0..5 {
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
    
    let rate_limiter = TestRateLimiter::new(config);
    
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
    
    let rate_limiter = TestRateLimiter::new(config);
    
    // Should allow unlimited requests when disabled
    for i in 0..10 {
        let result = rate_limiter.check_rate_limit("test_client").await;
        assert!(result.is_ok(), "Request {} should be allowed when rate limiting is disabled", i);
    }
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

fn main() {
    println!("Running standalone rate limiting tests...");
    
    // Test basic functionality
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    rt.block_on(async {
        test_basic_rate_limiting().await;
        println!("✓ Basic rate limiting test passed");
        
        test_different_clients().await;
        println!("✓ Different clients test passed");
        
        test_rate_limit_disabled().await;
        println!("✓ Rate limit disabled test passed");
    });
    
    test_config_serialization();
    println!("✓ Configuration serialization test passed");
    
    println!("All rate limiting tests passed! 🎉");
}
