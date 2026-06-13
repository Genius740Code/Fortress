//! Rate Limiting Algorithms
//!
//! This module implements various rate limiting algorithms including
//! token bucket, sliding window, fixed window, and leaky bucket.

use crate::error::{FortressError, Result};
use crate::rate_limit::{
    RateLimitAction, RateLimitAlgorithm, RateLimitContext, RateLimitResult, RateLimitRule,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Token bucket algorithm implementation
pub struct TokenBucketAlgorithm {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

/// Token bucket state
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: u64,
    max_tokens: u64,
    refill_rate: u64,
    last_refill: DateTime<Utc>,
    burst_tokens: u64,
}

impl TokenBucketAlgorithm {
    /// Create a new token bucket algorithm
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a token bucket for a key
    async fn get_or_create_bucket(&self, key: &str, rule: &RateLimitRule) -> TokenBucket {
        let mut buckets = self.buckets.write().await;

        buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: rule.burst.unwrap_or(rule.limit),
                max_tokens: rule.limit,
                refill_rate: rule.limit / rule.window_seconds,
                last_refill: Utc::now(),
                burst_tokens: rule.burst.unwrap_or(rule.limit),
            })
            .clone()
    }

    /// Refill tokens in a bucket
    async fn refill_bucket(&self, bucket: &mut TokenBucket, rule: &RateLimitRule) {
        let now = Utc::now();
        let elapsed = now - bucket.last_refill;

        if elapsed.num_seconds() > 0 {
            let tokens_to_add = (elapsed.num_seconds() as u64 * bucket.refill_rate)
                .min(bucket.max_tokens - bucket.tokens);
            bucket.tokens += tokens_to_add;
            bucket.last_refill = now;

            // Also refill burst tokens if they were consumed
            if bucket.burst_tokens < rule.burst.unwrap_or(rule.limit) {
                bucket.burst_tokens =
                    (bucket.burst_tokens + tokens_to_add).min(rule.burst.unwrap_or(rule.limit));
            }
        }
    }

    /// Consume tokens from a bucket
    fn consume_tokens(&self, bucket: &mut TokenBucket, amount: u64) -> bool {
        if bucket.tokens >= amount {
            bucket.tokens -= amount;
            true
        } else {
            false
        }
    }
}

#[async_trait::async_trait]
impl RateLimitAlgorithm for TokenBucketAlgorithm {
    fn name(&self) -> &str {
        "token_bucket"
    }

    async fn check_rate_limit(
        &self,
        key: &str,
        rule: &RateLimitRule,
        _context: &RateLimitContext,
    ) -> Result<RateLimitResult> {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: rule.burst.unwrap_or(rule.limit),
                max_tokens: rule.limit,
                refill_rate: rule.limit / rule.window_seconds,
                last_refill: Utc::now(),
                burst_tokens: rule.burst.unwrap_or(rule.limit),
            });

        // Refill tokens based on elapsed time
        self.refill_bucket(bucket, rule).await;

        let now = Utc::now();
        let tokens_available = bucket.tokens + bucket.burst_tokens;
        let max_tokens = bucket.max_tokens;
        let refill_rate = bucket.refill_rate;
        let last_refill = bucket.last_refill;

        // Calculate when tokens will be available
        let reset_time = if tokens_available == 0 && refill_rate > 0 {
            let seconds_needed = (max_tokens / refill_rate) + 1;
            last_refill + Duration::seconds(seconds_needed)
        } else if tokens_available < max_tokens && refill_rate > 0 {
            let seconds_needed = ((max_tokens - tokens_available) / refill_rate) + 1;
            last_refill + Duration::seconds(seconds_needed)
        } else {
            last_refill + Duration::seconds(rule.window_seconds)
        };

        let allowed = self.consume_tokens(bucket, 1);
        let remaining = bucket.tokens + bucket.burst_tokens;

        Ok(RateLimitResult {
            allowed,
            limit: rule.limit,
            remaining,
            reset_time,
            retry_after: if !allowed {
                Some(Duration::seconds(1))
            } else {
                None
            },
            action: if allowed {
                RateLimitAction::Allow
            } else {
                RateLimitAction::Reject
            },
            rule_name: rule.name.clone(),
            message: if allowed {
                "Request allowed".to_string()
            } else {
                "Rate limit exceeded".to_string()
            },
        })
    }

    async fn reset_rate_limit(&self, key: &str, rule: &RateLimitRule) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        buckets.insert(
            key.to_string(),
            TokenBucket {
                tokens: rule.burst.unwrap_or(rule.limit),
                max_tokens: rule.limit,
                refill_rate: rule.limit / rule.window_seconds,
                last_refill: Utc::now(),
                burst_tokens: rule.burst.unwrap_or(rule.limit),
            },
        );
        Ok(())
    }

    async fn get_usage(&self, key: &str, rule: &RateLimitRule) -> Result<Option<u64>> {
        let buckets = self.buckets.read().await;
        if let Some(bucket) = buckets.get(key) {
            Ok(Some(bucket.tokens + bucket.burst_tokens))
        } else {
            Ok(None)
        }
    }

    async fn cleanup(&self) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        let now = Utc::now();

        // Remove expired buckets (older than 10 minutes)
        buckets
            .retain(|_, bucket| now.signed_duration_since(bucket.last_refill).num_seconds() < 600);

        Ok(())
    }
}

/// Sliding window algorithm implementation
pub struct SlidingWindowAlgorithm {
    windows: Arc<RwLock<HashMap<String, SlidingWindow>>>,
}

/// Sliding window state
#[derive(Debug, Clone)]
struct SlidingWindow {
    requests: Vec<DateTime<Utc>>,
    window_size: Duration,
    max_requests: u64,
}

impl SlidingWindowAlgorithm {
    /// Create a new sliding window algorithm
    pub fn new() -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a sliding window for a key
    async fn get_or_create_window(&self, key: &str, rule: &RateLimitRule) -> SlidingWindow {
        let mut windows = self.windows.write().await;

        windows
            .entry(key.to_string())
            .or_insert_with(|| SlidingWindow {
                requests: Vec::new(),
                window_size: Duration::seconds(rule.window_seconds as u64),
                max_requests: rule.limit,
            })
            .clone()
    }

    /// Clean up old requests outside the window
    fn cleanup_old_requests(&mut window: &mut SlidingWindow, now: DateTime<Utc>) {
        let cutoff = now - window.window_size;
        window.requests.retain(|&timestamp| timestamp > cutoff);
    }

    /// Count requests in the window
    fn count_requests(window: &SlidingWindow) -> u64 {
        window.requests.len() as u64
    }

    /// Add a request to window
    fn add_request(window: &mut SlidingWindow, timestamp: DateTime<Utc>) {
        window.requests.push(timestamp);
    }
}

#[async_trait::async_trait]
impl RateLimitAlgorithm for SlidingWindowAlgorithm {
    fn name(&self) -> &str {
        "sliding_window"
    }

    async fn check_rate_limit(
        &self,
        key: &str,
        rule: &RateLimitRule,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult> {
        let mut windows = self.windows.write().await;
        let window = windows
            .entry(key.to_string())
            .or_insert_with(|| SlidingWindow {
                requests: Vec::new(),
                window_size: Duration::seconds(rule.window_seconds as u64),
                max_requests: rule.limit,
            });

        let now = context.timestamp;

        // Clean up old requests
        Self::cleanup_old_requests(window, now);

        let current_count = Self::count_requests(window);
        let allowed = current_count < rule.max_requests;

        // Add current request to window if allowed
        if allowed {
            Self::add_request(window, now);
        }

        let remaining = rule.max_requests.saturating_sub(current_count + 1);
        let reset_time = now + window.window_size;

        Ok(RateLimitResult {
            allowed,
            limit: rule.max_requests,
            remaining,
            reset_time,
            retry_after: if !allowed {
                Some(window.window_size)
            } else {
                None
            },
            action: if allowed {
                RateLimitAction::Allow
            } else {
                RateLimitAction::Reject
            },
            rule_name: rule.name.clone(),
            message: if allowed {
                "Request allowed".to_string()
            } else {
                "Rate limit exceeded".to_string()
            },
        })
    }

    async fn reset_rate_limit(&self, key: &str, rule: &RateLimitRule) -> Result<()> {
        let mut windows = self.windows.write().await;
        windows.insert(
            key.to_string(),
            SlidingWindow {
                requests: Vec::new(),
                window_size: Duration::seconds(rule.window_seconds as u64),
                max_requests: rule.limit,
            },
        );
        Ok(())
    }

    async fn get_usage(&self, key: &str, rule: &RateLimitRule) -> Result<Option<u64>> {
        let windows = self.windows.read().await;
        if let Some(window) = windows.get(key) {
            Ok(Some(self.count_requests(window)))
        } else {
            Ok(None)
        }
    }

    async fn cleanup(&self) -> Result<()> {
        let mut windows = self.windows.write().await;
        let now = Utc::now();

        // Remove expired windows (older than 10 minutes)
        windows.retain(|_, window| {
            now.signed_duration_since(
                window
                    .requests
                    .last()
                    .unwrap_or_else(|| window.requests.first().unwrap_or_else(|| Utc::now())),
            )
            .num_seconds()
                < 600
        });

        Ok(())
    }
}

/// Fixed window algorithm implementation
pub struct FixedWindowAlgorithm {
    windows: Arc<RwLock<HashMap<String, FixedWindow>>>,
}

/// Fixed window state
#[derive(Debug, Clone)]
struct FixedWindow {
    count: u64,
    max_requests: u64,
    window_start: DateTime<Utc>,
    window_size: Duration,
    last_reset: DateTime<Utc>,
}

impl FixedWindowAlgorithm {
    /// Create a new fixed window algorithm
    pub fn new() -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a fixed window for a key
    async fn get_or_create_window(&self, key: &str, rule: &RateLimitRule) -> FixedWindow {
        let mut windows = self.windows.write().await;

        windows
            .entry(key.to_string())
            .or_insert_with(|| FixedWindow {
                count: 0,
                max_requests: rule.limit,
                window_start: Utc::now(),
                window_size: Duration::seconds(rule.window_seconds as u64),
                last_reset: Utc::now(),
            })
            .clone()
    }

    /// Reset window if needed
    fn reset_window_if_needed(window: &mut FixedWindow, now: DateTime<Utc>, rule: &RateLimitRule) {
        if now - window.window_start >= window.window_size {
            window.count = 0;
            window.window_start = now;
            window.last_reset = now;
        }
    }

    /// Increment count
    fn increment_count(window: &mut FixedWindow) {
        window.count += 1;
    }
}

#[async_trait::async_trait]
impl RateLimitAlgorithm for FixedWindowAlgorithm {
    fn name(&self) -> &str {
        "fixed_window"
    }

    async fn check_rate_limit(
        &self,
        key: &str,
        rule: &RateLimitRule,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult> {
        let mut windows = self.windows.write().await;
        let window = windows
            .entry(key.to_string())
            .or_insert_with(|| FixedWindow {
                count: 0,
                max_requests: rule.limit,
                window_start: Utc::now(),
                window_size: Duration::seconds(rule.window_seconds as u64),
                last_reset: Utc::now(),
            });

        let now = context.timestamp;

        // Reset window if needed
        Self::reset_window_if_needed(window, now, rule);

        let allowed = window.count < window.max_requests;

        // Increment count if allowed
        if allowed {
            Self::increment_count(window);
        }

        let remaining = window.max_requests.saturating_sub(window.count);
        let reset_time = window.window_start + window.window_size;

        Ok(RateLimitResult {
            allowed,
            limit: rule.max_requests,
            remaining,
            reset_time,
            retry_after: if !allowed {
                Some(window.window_size)
            } else {
                None
            },
            action: if allowed {
                RateLimitAction::Allow
            } else {
                RateLimitAction::Reject
            },
            rule_name: rule.name.clone(),
            message: if allowed {
                "Request allowed".to_string()
            } else {
                "Rate limit exceeded".to_string()
            },
        })
    }

    async fn reset_rate_limit(&self, key: &str, rule: &RateLimitRule) -> Result<()> {
        let mut windows = self.windows.write().await;
        windows.insert(
            key.to_string(),
            FixedWindow {
                count: 0,
                max_requests: rule.limit,
                window_start: Utc::now(),
                window_size: Duration::seconds(rule.window_seconds as u64),
                last_reset: Utc::now(),
            },
        );
        Ok(())
    }

    async fn get_usage(&self, key: &str, rule: &RateLimitRule) -> Result<Option<u64>> {
        let windows = self.windows.read().await;
        if let Some(window) = windows.get(key) {
            Ok(Some(window.count))
        } else {
            Ok(None)
        }
    }

    async fn cleanup(&self) -> Result<()> {
        let mut windows = self.windows.write().await;
        let now = Utc::now();

        // Remove expired windows (older than 10 minutes)
        windows
            .retain(|_, window| now.signed_duration_since(window.last_reset).num_seconds() < 600);

        Ok(())
    }
}

/// Leaky bucket algorithm implementation
pub struct LeakyBucketAlgorithm {
    buckets: Arc<RwLock<HashMap<String, LeakyBucket>>>,
}

/// Leaky bucket state
#[derive(Debug, Clone)]
struct LeakyBucket {
    capacity: u64,
    water: u64,
    leak_rate: u64,
    last_leak: DateTime<Utc>,
}

impl LeakyBucketAlgorithm {
    /// Create a new leaky bucket algorithm
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a leaky bucket for a key
    async fn get_or_create_bucket(&self, key: &str, rule: &RateLimitRule) -> LeakyBucket {
        let mut buckets = self.buckets.write().await;

        buckets
            .entry(key.to_string())
            .or_insert_with(|| LeakyBucket {
                capacity: rule.limit,
                water: rule.limit,
                leak_rate: rule.limit / rule.window_seconds,
                last_leak: Utc::now(),
            })
            .clone()
    }

    /// Leak water from bucket
    fn leak_water(bucket: &mut LeakyBucket, now: DateTime<Utc>) {
        let elapsed = now - bucket.last_leak;

        if elapsed.num_seconds() > 0 {
            let water_to_leak = (elapsed.num_seconds() as u64 * bucket.leak_rate).min(bucket.water);
            bucket.water -= water_to_leak;
            bucket.last_leak = now;
        }
    }

    /// Add water to bucket
    fn add_water(bucket: &mut LeakyBucket, amount: u64) -> bool {
        bucket.water += amount;
        bucket.water > bucket.capacity
    }
}

#[async_trait::async_trait]
impl RateLimitAlgorithm for LeakyBucketAlgorithm {
    fn name(&self) -> &str {
        "leaky_bucket"
    }

    async fn check_rate_limit(
        &self,
        key: &str,
        rule: &RateLimitRule,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult> {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| LeakyBucket {
                capacity: rule.limit,
                water: rule.limit,
                leak_rate: rule.limit / rule.window_seconds,
                last_leak: Utc::now(),
            });

        let now = context.timestamp;

        // Leak water based on elapsed time
        Self::leak_water(bucket, now);

        let allowed = Self::add_water(bucket, 1);
        let remaining = bucket.water;

        let reset_time = if remaining == 0 && bucket.leak_rate > 0 {
            let seconds_needed = (bucket.capacity / bucket.leak_rate) + 1;
            now + Duration::seconds(seconds_needed)
        } else {
            now + Duration::seconds(rule.window_seconds)
        };

        Ok(RateLimitResult {
            allowed,
            limit: rule.limit,
            remaining,
            reset_time,
            retry_after: if !allowed {
                Some(Duration::seconds(1))
            } else {
                None
            },
            action: if allowed {
                RateLimitAction::Allow
            } else {
                RateLimitAction::Reject
            },
            rule_name: rule.name.clone(),
            message: if allowed {
                "Request allowed".to_string()
            } else {
                "Rate limit exceeded".to_string()
            },
        })
    }

    async fn reset_rate_limit(&self, key: &str, rule: &RateLimitRule) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        buckets.insert(
            key.to_string(),
            LeakyBucket {
                capacity: rule.limit,
                water: rule.limit,
                leak_rate: rule.limit / rule.window_seconds,
                last_leak: Utc::now(),
            },
        );
        Ok(())
    }

    async fn get_usage(&self, key: &str, rule: &RateLimitRule) -> Result<Option<u64>> {
        let buckets = self.buckets.read().await;
        if let Some(bucket) = buckets.get(key) {
            Ok(Some(bucket.water))
        } else {
            Ok(None)
        }
    }

    async fn cleanup(&self) -> Result<()> {
        let mut buckets = self.buckets.write().await;
        let now = Utc::now();

        // Remove expired buckets (older than 10 minutes)
        buckets.retain(|_, bucket| now.signed_duration_since(bucket.last_leak).num_seconds() < 600);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_algorithm() {
        let algorithm = TokenBucketAlgorithm::new();

        let rule = RateLimitRule {
            name: "test-rule".to_string(),
            limit: 10,
            window_seconds: 60,
            burst: Some(5),
            key_extractor: crate::rate_limit::KeyExtractor::IP,
            conditions: Vec::new(),
            action: crate::rate_limit::RateLimitAction::Reject,
            priority: 100,
            enabled: true,
        };

        let context = RateLimitContext {
            request_id: "req-1".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_id: None,
            api_key: None,
            token: None,
            path: "/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };

        // First request should be allowed
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 14); // 10 + 5 burst

        // Second request should be allowed
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 13);

        // Exhaust all tokens
        for _ in 0..14 {
            algorithm
                .check_rate_limit("192.168.1.1", &rule, &context)
                .await
                .unwrap();
        }

        // Next request should be rejected
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn test_sliding_window_algorithm() {
        let algorithm = SlidingWindowAlgorithm::new();

        let rule = RateLimitRule {
            name: "test-rule".to_string(),
            limit: 5,
            window_seconds: 60,
            burst: None,
            key_extractor: crate::rate_limit::KeyExtractor::IP,
            conditions: Vec::new(),
            action: crate::rate_limit::RateLimitAction::Reject,
            priority: 100,
            enabled: true,
        };

        let context = RateLimitContext {
            request_id: "req-1".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_id: None,
            api_key: None,
            token: None,
            path: "/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };

        // First 5 requests should be allowed
        for i in 0..5 {
            let result = algorithm
                .check_rate_limit("192.168.1.1", &rule, &context)
                .await
                .unwrap();
            assert!(result.allowed, "Request {} should be allowed", i + 1);
        }

        // 6th request should be rejected
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(!result.allowed, "Request 6 should be rejected");
    }

    #[tokio::test]
    async fn test_fixed_window_algorithm() {
        let algorithm = FixedWindowAlgorithm::new();

        let rule = RateLimitRule {
            name: "test-rule".to_string(),
            limit: 3,
            window_seconds: 60,
            burst: None,
            key_extractor: crate::rate_limit::KeyExtractor::IP,
            conditions: Vec::new(),
            action: crate::rate_limit::RateLimitAction::Reject,
            priority: 100,
            enabled: true,
        };

        let context = RateLimitContext {
            request_id: "req-1".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_id: None,
            api_key: None,
            token: None,
            path: "/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };

        // First 3 requests should be allowed
        for i in 0..3 {
            let result = algorithm
                .check_rate_limit("192.168.1.1", &rule, &context)
                .await
                .unwrap();
            assert!(result.allowed, "Request {} should be allowed", i + 1);
        }

        // 4th request should be rejected
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(!result.allowed, "Request 4 should be rejected");
    }

    #[tokio::test]
    async fn test_leaky_bucket_algorithm() {
        let algorithm = LeakyBucketAlgorithm::new();

        let rule = RateLimitRule {
            name: "test-rule".to_string(),
            limit: 10,
            window_seconds: 60,
            burst: None,
            key_extractor: crate::rate_limit::KeyExtractor::IP,
            conditions: Vec::new(),
            action: crate::rate_limit::RateLimitAction::Reject,
            priority: 100,
            enabled: true,
        };

        let context = RateLimitContext {
            request_id: "req-1".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_id: None,
            api_key: None,
            token: None,
            path: "/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };

        // First request should be allowed
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 9);

        // Second request should be allowed
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(result.allowed);
        assert!(result.remaining, "{}", 8);

        // Wait for some leak
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Check if water leaked
        let result = algorithm
            .check_rate_limit("192.168.1.1", &rule, &context)
            .await
            .unwrap();
        assert!(result.allowed);
        assert!(result.remaining < 10); // Should have leaked some water
    }
}
