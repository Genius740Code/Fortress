//! Advanced Rate Limiting Module
//! 
//! This module provides enterprise-grade rate limiting capabilities
//! with multiple algorithms, storage backends, and middleware integration.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use crate::error::{FortressError, Result};
use async_trait::async_trait;

pub mod manager;
pub mod algorithms;
pub mod storage;
pub mod middleware;

pub use manager::RateLimitManager;
pub use algorithms::{TokenBucketAlgorithm, SlidingWindowAlgorithm, FixedWindowAlgorithm};
pub use storage::{MemoryStorage, RedisStorage, RateLimitStorage};
pub use middleware::RateLimitMiddleware;

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub algorithm: RateLimitAlgorithmType,
    pub storage: RateLimitStorageType,
    pub default_limits: HashMap<String, RateLimitRule>,
    pub cleanup_interval_seconds: u64,
    pub metrics_enabled: bool,
    pub distributed: bool,
    pub cluster_sync_enabled: bool,
}

/// Rate limit algorithm types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitAlgorithmType {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    LeakyBucket,
}

/// Rate limit storage types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitStorageType {
    Memory,
    Redis,
    Database,
    Distributed,
}

/// Rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub name: String,
    pub limit: u64,
    pub window_seconds: u64,
    pub burst: Option<u64>,
    pub key_extractor: KeyExtractor,
    pub conditions: Vec<RateLimitCondition>,
    pub action: RateLimitAction,
    pub priority: u32,
    pub enabled: bool,
}

/// Key extractor for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyExtractor {
    IP,
    User,
    APIKey,
    Token,
    Path,
    Method,
    Header(String),
    Custom(String),
    Composite(Vec<KeyExtractor>),
}

/// Rate limit condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
}

/// Condition operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    In,
    NotIn,
    Regex,
    GreaterThan,
    LessThan,
}

/// Rate limit action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitAction {
    Reject,
    Throttle,
    Queue,
    AllowWithWarning,
    Custom(serde_json::Value),
}

/// Rate limit request context
#[derive(Debug, Clone)]
pub struct RateLimitContext {
    pub request_id: String,
    pub ip_address: String,
    pub user_id: Option<String>,
    pub api_key: Option<String>,
    pub token: Option<String>,
    pub path: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Rate limit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u64,
    pub remaining: u64,
    pub reset_time: DateTime<Utc>,
    pub retry_after: Option<Duration>,
    pub action: RateLimitAction,
    pub rule_name: String,
    pub message: String,
}

/// Rate limit metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitMetrics {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub rejected_requests: u64,
    pub throttled_requests: u64,
    pub queued_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub average_response_time_ms: f64,
    pub last_updated: DateTime<Utc>,
}

/// Trait for rate limit algorithms
pub trait RateLimitAlgorithm: Send + Sync {
    /// Name of the algorithm
    fn name(&self) -> &str;
    
    /// Check if request is allowed
    async fn check_rate_limit(&self, key: &str, rule: &RateLimitRule, context: &RateLimitContext) -> Result<RateLimitResult>;
    
    /// Reset rate limit for a key
    async fn reset_rate_limit(&self, key: &str, rule: &RateLimitRule) -> Result<()>;
    
    /// Get current usage for a key
    async fn get_usage(&self, key: &str, rule: &RateLimitRule) -> Result<Option<u64>>;
    
    /// Cleanup expired data
    async fn cleanup(&self) -> Result<()>;
}

/// Trait for rate limit storage backends
pub trait RateLimitStorage: Send + Sync {
    /// Name of the storage backend
    fn name(&self) -> &str;
    
    /// Get counter value
    async fn get_counter(&self, key: &str, rule_name: &str) -> Result<Option<u64>>;
    
    /// Set counter value
    async fn set_counter(&self, key: str, rule_name: str, value: u64, ttl: Option<Duration>) -> Result<()>;
    
    /// Increment counter
    async fn increment_counter(&self, key: str, rule_name: str, amount: u64, ttl: Option<Duration>) -> Result<u64>;
    
    /// Decrement counter
    async fn decrement_counter(&self, key: str, rule_name: str, amount: u64) -> Result<u64>;
    
    /// Delete counter
    async fn delete_counter(&self, key: &str, rule_name: &str) -> Result<()>;
    
    /// Get all keys for a rule
    async fn get_keys(&self, rule_name: &str) -> Result<Vec<String>>;
    
    /// Cleanup expired data
    async fn cleanup(&self) -> Result<()>;
}

/// Rate limit manager
pub struct RateLimitManager {
    config: RateLimitConfig,
    algorithm: Arc<dyn RateLimitAlgorithm>,
    storage: Arc<dyn RateLimitStorage>,
    rules: Arc<RwLock<HashMap<String, RateLimitRule>>>,
    metrics: Arc<RwLock<RateLimitMetrics>>,
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

impl RateLimitManager {
    /// Create a new rate limit manager
    pub fn new(config: RateLimitConfig) -> Self {
        let algorithm: Arc<dyn RateLimitAlgorithm> = match config.algorithm {
            RateLimitAlgorithmType::TokenBucket => Arc::new(TokenBucketAlgorithm::new()),
            RateLimitAlgorithmType::SlidingWindow => Arc::new(SlidingWindowAlgorithm::new()),
            RateLimitAlgorithmType::FixedWindow => Arc::new(FixedWindowAlgorithm::new()),
            RateLimitAlgorithmType::LeakyBucket => Arc::new(TokenBucketAlgorithm::new()), // Reuse token bucket for now
        };

        let storage: Arc<dyn RateLimitStorage> = match config.storage {
            RateLimitStorageType::Memory => Arc::new(MemoryStorage::new()),
            RateLimitStorageType::Redis => Arc::new(RedisStorage::new()),
            RateLimitStorageType::Database => Arc::new(MemoryStorage::new()), // Placeholder
            RateLimitStorageType::Distributed => Arc::new(MemoryStorage::new()), // Placeholder
        };

        Self {
            config,
            algorithm,
            storage,
            rules: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RateLimitMetrics {
                total_requests: 0,
                allowed_requests: 0,
                rejected_requests: 0,
                throttled_requests: 0,
                queued_requests: 0,
                cache_hits: 0,
                cache_misses: 0,
                average_response_time_ms: 0.0,
                last_updated: Utc::now(),
            })),
            cleanup_task: None,
        }
    }

    /// Initialize the rate limit manager
    pub async fn initialize(&mut self) -> Result<()> {
        // Add default rules
        for (name, rule) in self.config.default_limits.clone() {
            self.add_rule(name, rule).await?;
        }

        // Start cleanup task
        self.start_cleanup_task().await?;

        tracing::info!("Rate limit manager initialized with {} rules", self.rules.read().await.len());
        Ok(())
    }

    /// Add a rate limit rule
    pub async fn add_rule(&self, name: String, rule: RateLimitRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.insert(name.clone(), rule);
        tracing::info!("Added rate limit rule: {}", name);
        Ok(())
    }

    /// Remove a rate limit rule
    pub async fn remove_rule(&self, name: &str) -> Result<bool> {
        let mut rules = self.rules.write().await;
        let removed = rules.remove(name).is_some();
        if removed {
            tracing::info!("Removed rate limit rule: {}", name);
        }
        Ok(removed)
    }

    /// Update a rate limit rule
    pub async fn update_rule(&self, name: &str, rule: RateLimitRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.insert(name.to_string(), rule);
        tracing::info!("Updated rate limit rule: {}", name);
        Ok(())
    }

    /// Get a rate limit rule
    pub async fn get_rule(&self, name: &str) -> Option<RateLimitRule> {
        let rules = self.rules.read().await;
        rules.get(name).cloned()
    }

    /// List all rate limit rules
    pub async fn list_rules(&self) -> Vec<(String, RateLimitRule)> {
        let rules = self.rules.read().await;
        rules.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Check rate limits for a request
    pub async fn check_rate_limits(&self, context: &RateLimitContext) -> Result<Vec<RateLimitResult>> {
        let rules = self.rules.read().await;
        let mut results = Vec::new();
        let start_time = std::time::Instant::now();

        // Sort rules by priority (higher priority first)
        let mut sorted_rules: Vec<_> = rules.values().collect();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in sorted_rules {
            if !rule.enabled {
                continue;
            }

            // Check conditions
            if !self.check_conditions(&rule.conditions, context) {
                continue;
            }

            // Extract key
            let key = self.extract_key(&rule.key_extractor, context);
            
            // Check rate limit
            let result = self.algorithm.check_rate_limit(&key, rule, context).await;
            
            // Update metrics
            {
                let mut metrics = self.metrics.write().await;
                metrics.total_requests += 1;
                
                if result.allowed {
                    metrics.allowed_requests += 1;
                } else {
                    metrics.rejected_requests += 1;
                }
                
                let response_time = start_time.elapsed().as_millis() as f64;
                metrics.average_response_time_ms = 
                    (metrics.average_response_time_ms * (metrics.total_requests - 1) as f64 + response_time) / metrics.total_requests as f64;
                metrics.last_updated = Utc::now();
            }

            results.push(result);

            // If the rule is rejecting and has high priority, stop checking further rules
            if !result.allowed && rule.priority >= 100 {
                break;
            }
        }

        Ok(results)
    }

    /// Reset rate limit for a specific key and rule
    pub async fn reset_rate_limit(&self, key: &str, rule_name: &str) -> Result<()> {
        let rules = self.rules.read().await;
        if let Some(rule) = rules.get(rule_name) {
            self.algorithm.reset_rate_limit(key, rule).await
        } else {
            Err(FortressError::rate_limit(format!("Rate limit rule '{}' not found", rule_name)))
        }
    }

    /// Reset all rate limits for a key
    pub async fn reset_all_rate_limits(&self, key: &str) -> Result<()> {
        let rules = self.rules.read().await;
        for rule in rules.values() {
            self.algorithm.reset_rate_limit(key, rule).await?;
        }
        Ok(())
    }

    /// Get current usage for a key and rule
    pub async fn get_usage(&self, key: &str, rule_name: &str) -> Result<Option<u64>> {
        let rules = self.rules.read().await;
        if let Some(rule) = rules.get(rule_name) {
            self.algorithm.get_usage(key, rule).await
        } else {
            Err(FortressError::rate_limit(format!("Rate limit rule '{}' not found", rule_name)))
        }
    }
    /// Get rate limit metrics
    pub async fn get_metrics(&self) -> RateLimitMetrics {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }

    fn check_conditions(&self, conditions: &[RateLimitCondition], context: &RateLimitContext) -> bool {
        conditions.iter().all(|condition| {
            let value = self.extract_field_value(&condition.field, context);
            self.evaluate_condition(&condition.operator, &value, &condition.value)
        })
    }

    /// Evaluate condition
    fn evaluate_condition(&self, operator: &ConditionOperator, actual: &str, expected: &str) -> bool {
        match operator {
            ConditionOperator::Equals => actual == expected,
            ConditionOperator::NotEquals => actual != expected,
            ConditionOperator::Contains => actual.contains(expected),
            ConditionOperator::NotContains => !actual.contains(expected),
            ConditionOperator::In => {
                expected.split(',').any(|v| actual.trim() == v.trim())
            }
            ConditionOperator::NotIn => {
                !expected.split(',').any(|v| actual.trim() == v.trim())
            }
            ConditionOperator::Regex => {
                // Simple regex evaluation (would need regex crate in production)
                actual == expected // Placeholder
            }
            ConditionOperator::GreaterThan => {
                actual.parse::<i64>().ok()
                    .map(|a| a > expected.parse().unwrap_or(0))
                    .unwrap_or(false)
            }
            ConditionOperator::LessThan => {
                actual.parse::<i64>().ok()
                    .map(|a| a < expected.parse().unwrap_or(i64::MAX))
                    .unwrap_or(false)
            }
        }
    }

    /// Extract key based on key extractor
    fn extract_key(&self, extractor: &KeyExtractor, context: &RateLimitContext) -> String {
        match extractor {
            KeyExtractor::IP => context.ip_address.clone(),
            KeyExtractor::User => context.user_id.clone().unwrap_or_else(|| "anonymous".to_string()),
            KeyExtractor::APIKey => context.api_key.clone().unwrap_or_default(),
            KeyExtractor::Token => context.token.clone().unwrap_or_default(),
            KeyExtractor::Path => context.path.clone(),
            KeyExtractor::Method => context.method.clone(),
            KeyExtractor::Header(header_name) => {
                context.headers.get(header_name).cloned().unwrap_or_default()
            }
            KeyExtractor::Custom(custom_key) => {
                context.metadata.get(custom_key)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string()
            }
            KeyExtractor::Composite(extractors) => {
                let parts: Vec<String> = extractors.iter()
                    .map(|e| self.extract_key(e, context))
                    .collect();
                parts.join(":")
            }
        }
    }

    /// Start background cleanup task
    async fn start_cleanup_task(&mut self) -> Result<()> {
        let storage = self.storage.clone();
        let algorithm = self.algorithm.clone();
        let interval = Duration::from_secs(self.config.cleanup_interval_seconds);

        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                tracing::debug!("Running rate limit cleanup task");
                
                // Cleanup storage
                if let Err(e) = storage.cleanup().await {
                    tracing::error!("Storage cleanup failed: {}", e);
                }
                
                // Cleanup algorithm
                if let Err(e) = algorithm.cleanup().await {
                    tracing::error!("Algorithm cleanup failed: {}", e);
                }
            }
        });

        self.cleanup_task = Some(task);
        Ok(())
    }

    /// Shutdown the rate limit manager
    pub async fn shutdown(&mut self) -> Result<()> {
        // Stop cleanup task
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }

        tracing::info!("Rate limit manager shutdown");
        Ok(())
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            algorithm: RateLimitAlgorithmType::TokenBucket,
            storage: RateLimitStorageType::Memory,
            default_rules: HashMap::new(),
            cleanup_interval_seconds: 300, // 5 minutes
            metrics_enabled: true,
            distributed: false,
            cluster_sync_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert!(matches!(config.algorithm, RateLimitAlgorithmType::TokenBucket));
        assert!(matches!(config.storage, RateLimitStorageType::Memory));
        assert_eq!(config.cleanup_interval_seconds, 300);
        assert!(config.metrics_enabled);
        assert!(!config.distributed);
    }

    #[test]
    fn test_rate_limit_rule_default() {
        let rule = RateLimitRule {
            name: "test-rule".to_string(),
            limit: 100,
            window_seconds: 60,
            burst: None,
            key_extractor: KeyExtractor::IP,
            conditions: Vec::new(),
            action: RateLimitAction::Reject,
            priority: 100,
            enabled: true,
        };
        
        assert_eq!(rule.name, "test-rule");
        assert_eq!(rule.limit, 100);
        assert_eq!(rule.window_seconds, 60);
        assert!(matches!(rule.key_extractor, KeyExtractor::IP));
        assert!(rule.conditions.is_empty());
        assert!(matches!(rule.action, RateLimitAction::Reject));
        assert_eq!(rule.priority, 100);
        assert!(rule.enabled);
    }

    #[test]
    fn test_rate_limit_context_creation() {
        let context = RateLimitContext {
            request_id: "req-123".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_id: Some("user-456".to_string()),
            api_key: Some("key-789".to_string()),
            token: Some("token-abc".to_string()),
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };
        
        assert_eq!(context.request_id, "req-123");
        assert_eq!(context.ip_address, "192.168.1.1");
        assert_eq!(context.user_id, Some("user-456"));
        assert_eq!(context.api_key, Some("key-789"));
        assert_eq!(context.token, Some("token-abc"));
        assert_eq!(context.path, "/api/test");
        assert_eq!(context.method, "GET");
    }

    #[test]
    fn test_key_extractor() {
        let context = RateLimitContext {
            request_id: "req-123".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_id: Some("user-456".to_string()),
            api_key: Some("key-789".to_string()),
            token: Some("token-abc".to_string()),
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        };

        let manager = RateLimitManager::new(RateLimitConfig::default());

        // Test IP extractor
        let key = manager.extract_key(&KeyExtractor::IP, &context);
        assert_eq!(key, "192.168.1.1");

        // Test User extractor
        let key = manager.extract_key(&KeyExtractor::User, &context);
        assert_eq!(key, "user-456");

        // Test Path extractor
        let key = manager.extract_key(&KeyExtractor::Path, &context);
        assert_eq!(key, "/api/test");

        // Test Method extractor
        let key = manager.extract_key(&KeyExtractor::Method, &context);
        assert_eq!(key, "GET");

        // Test composite extractor
        let key = manager.extract_key(&KeyExtractor::Composite(vec![
            KeyExtractor::IP,
            KeyExtractor::User,
            KeyExtractor::Path,
        ]), &context);
        assert_eq!(key, "192.168.1.1:user-456:/api/test");
    }

    #[test]
    fn test_condition_evaluation() {
        let manager = RateLimitManager::new(RateLimitConfig::default());

        // Test equals
        assert!(manager.evaluate_condition(&ConditionOperator::Equals, "test", "test"));
        assert!(!manager.evaluate_condition(&ConditionOperator::Equals, "test", "other"));

        // Test contains
        assert!(manager.evaluate_condition(&ConditionOperator::Contains, "hello world", "hello"));
        assert!(!manager.evaluate_condition(&ConditionOperator::Contains, "hello", "world"));

        // Test greater than
        assert!(manager.evaluate_condition(&ConditionOperator::GreaterThan, "100", "50"));
        assert!(!manager.evaluate_condition(&ConditionOperator::GreaterThan, "50", "100"));

        // Test less than
        assert!(manager.evaluate_condition(&ConditionOperator::LessThan, "50", "100"));
        assert!(!manager.evaluate_condition(&ConditionOperator::LessThan, "100", "50"));
    }

    #[tokio::test]
    async fn test_rate_limit_manager_creation() {
        let config = RateLimitConfig::default();
        let manager = RateLimitManager::new(config);
        
        let rules = manager.list_rules().await;
        assert!(rules.is_empty());
        
        let metrics = manager.get_metrics().await;
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.allowed_requests, 0);
        assert_eq!(metrics.rejected_requests, 0);
    }
}
