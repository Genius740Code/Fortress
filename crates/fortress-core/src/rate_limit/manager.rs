//! Rate Limiting Manager
//! 
//! This module provides the main rate limiting manager
//! that coordinates algorithms, storage, and configuration.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};
use super::{
    RateLimitAlgorithm, RateLimitStorage, RateLimitRule, RateLimitResult, RateLimitContext,
    RateLimitConfig, RateLimitAlgorithmType, RateLimitStorageType
};

/// Main rate limiting manager
pub struct RateLimitManager {
    /// Configuration
    config: Arc<RwLock<RateLimitConfig>>,
    /// Rate limiting algorithms
    algorithms: HashMap<RateLimitAlgorithmType, Arc<dyn RateLimitAlgorithm>>,
    /// Storage backends
    storage: HashMap<RateLimitStorageType, Arc<dyn RateLimitStorage>>,
    /// Active rules
    rules: Arc<RwLock<HashMap<String, RateLimitRule>>>,
}

impl RateLimitManager {
    /// Create a new rate limit manager
    pub fn new(config: RateLimitConfig) -> Self {
        let mut algorithms: HashMap<RateLimitAlgorithmType, Arc<dyn RateLimitAlgorithm>> = HashMap::new();
        algorithms.insert(RateLimitAlgorithmType::TokenBucket, Arc::new(super::algorithms::TokenBucketAlgorithm::new()));
        algorithms.insert(RateLimitAlgorithmType::SlidingWindow, Arc::new(super::algorithms::SlidingWindowAlgorithm::new()));
        algorithms.insert(RateLimitAlgorithmType::FixedWindow, Arc::new(super::algorithms::FixedWindowAlgorithm::new()));

        let mut storage: HashMap<RateLimitStorageType, Arc<dyn RateLimitStorage>> = HashMap::new();
        storage.insert(RateLimitStorageType::Memory, Arc::new(super::storage::MemoryStorage::new()));

        Self {
            config: Arc::new(RwLock::new(config)),
            algorithms,
            storage,
            rules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check rate limit for a request
    pub async fn check_rate_limit(
        &self,
        key: &str,
        rule_name: &str,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult> {
        let config = self.config.read().await;
        let rules = self.rules.read().await;
        
        // Get rule for this key
        let rule = rules.get(rule_name)
            .or_else(|| config.default_rules.get(rule_name))
            .ok_or_else(|| FortressError::rate_limit(format!("Rate limit rule '{}' not found", rule_name)))?;

        // Get algorithm
        let algorithm = self.algorithms.get(&config.algorithm)
            .ok_or_else(|| FortressError::rate_limit(format!("Rate limit algorithm '{:?}' not found", config.algorithm)))?;

        // Check rate limit
        algorithm.check_rate_limit(key, rule, context).await
    }

    /// Add or update a rate limit rule
    pub async fn add_rule(&self, rule: RateLimitRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.insert(rule.name.clone(), rule);
        Ok(())
    }

    /// Remove a rate limit rule
    pub async fn remove_rule(&self, rule_name: &str) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.remove(rule_name);
        Ok(())
    }

    /// Get all rules
    pub async fn get_rules(&self) -> Result<HashMap<String, RateLimitRule>> {
        let rules = self.rules.read().await;
        Ok(rules.clone())
    }

    /// Update configuration
    pub async fn update_config(&self, config: RateLimitConfig) -> Result<()> {
        let mut config_lock = self.config.write().await;
        *config_lock = config;
        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> Result<RateLimitConfig> {
        let config = self.config.read().await;
        Ok(config.clone())
    }
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_manager_creation() {
        let config = RateLimitConfig::default();
        let manager = RateLimitManager::new(config);
        
        let rules = manager.get_rules().await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_add_rule() {
        let config = RateLimitConfig::default();
        let manager = RateLimitManager::new(config);
        
        let rule = RateLimitRule {
            name: "test".to_string(),
            limit: 100,
            window_seconds: 60,
            burst: None,
            enabled: true,
            priority: 1,
            conditions: Vec::new(),
            action: super::RateLimitAction::Allow,
        };

        manager.add_rule(rule).await.unwrap();
        
        let rules = manager.get_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules.contains_key("test"));
    }
}
