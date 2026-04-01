//! WebAssembly Policy Evaluator System
//!
//! This module provides a comprehensive policy evaluation system using WebAssembly
//! plugins for custom policy logic, making Fortress the most extensible security platform.

use crate::error::{FortressError, Result};
use crate::plugin::{PluginMetadata, PluginCapability};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Policy evaluation context containing all relevant information for policy decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// Unique request ID for tracking
    pub request_id: String,
    /// User identity information
    pub user: UserContext,
    /// Resource being accessed
    pub resource: ResourceContext,
    /// Action being performed
    pub action: String,
    /// Request metadata
    pub request: RequestContext,
    /// Environment context
    pub environment: EnvironmentContext,
    /// Timestamp of evaluation
    pub timestamp: DateTime<Utc>,
}

/// User context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// Unique user identifier
    pub user_id: String,
    /// User roles and permissions
    pub roles: Vec<String>,
    /// User attributes for policy decisions
    pub attributes: HashMap<String, serde_json::Value>,
    /// Authentication method used
    pub auth_method: String,
    /// Session information
    pub session_id: Option<String>,
    /// User's security clearance level
    pub clearance_level: Option<String>,
}

/// Resource context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceContext {
    /// Unique resource identifier
    pub resource_id: String,
    /// Resource type (e.g., "database", "file", "api_endpoint")
    pub resource_type: String,
    /// Resource attributes for policy decisions
    pub attributes: HashMap<String, serde_json::Value>,
    /// Resource owner
    pub owner: Option<String>,
    /// Resource classification level
    pub classification: Option<String>,
    /// Resource tags
    pub tags: Vec<String>,
}

/// Request context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Source IP address
    pub source_ip: String,
    /// User agent string
    pub user_agent: Option<String>,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Request method (GET, POST, etc.)
    pub method: String,
    /// Request path or endpoint
    pub path: String,
}

/// Environment context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentContext {
    /// Current time
    pub current_time: DateTime<Utc>,
    /// Time zone
    pub timezone: String,
    /// Geolocation information
    pub geolocation: Option<GeoLocation>,
    /// Device information
    pub device: Option<DeviceContext>,
    /// Network context
    pub network: NetworkContext,
    /// Threat intelligence
    pub threat_intelligence: ThreatIntelligence,
}

/// Geolocation information
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
}

/// Device context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceContext {
    /// Device type (mobile, desktop, etc.)
    pub device_type: String,
    /// Operating system
    pub os: String,
    /// Browser information
    pub browser: Option<String>,
    /// Device fingerprint
    pub fingerprint: Option<String>,
    /// Whether device is trusted
    pub trusted: bool,
}

/// Network context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    /// Network type (corporate, public, vpn, etc.)
    pub network_type: String,
    /// Connection security level
    pub security_level: String,
    /// VPN information
    pub vpn_info: Option<VpnInfo>,
}

/// VPN information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnInfo {
    /// VPN provider
    pub provider: String,
    /// VPN endpoint location
    pub endpoint: String,
    /// Whether VPN is trusted
    pub trusted: bool,
}

/// Threat intelligence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    /// IP reputation score (0-100)
    pub ip_reputation_score: f64,
    /// Known malicious indicators
    pub malicious_indicators: Vec<String>,
    /// Risk level (low, medium, high, critical)
    pub risk_level: String,
    /// Last threat update timestamp
    pub last_updated: DateTime<Utc>,
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Whether access is allowed
    pub allow: bool,
    /// Policy decision reason
    pub reason: String,
    /// Policy effect (allow, deny, not_applicable)
    pub effect: PolicyEffect,
    /// Policy obligations that must be fulfilled
    pub obligations: Vec<PolicyObligation>,
    /// Additional advice or recommendations
    pub advice: Option<String>,
    /// Metrics about policy evaluation
    pub metrics: PolicyMetrics,
    /// TTL for caching this decision
    pub cache_ttl_seconds: Option<u64>,
}

/// Policy effect enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyEffect {
    Allow,
    Deny,
    NotApplicable,
}

/// Policy obligation that must be fulfilled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyObligation {
    /// Obligation type
    pub obligation_type: String,
    /// Obligation parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Whether obligation is mandatory
    pub mandatory: bool,
    /// Deadline for fulfilling obligation
    pub deadline: Option<DateTime<Utc>>,
}

/// Policy evaluation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetrics {
    /// Evaluation time in milliseconds
    pub evaluation_time_ms: u64,
    /// Number of policies evaluated
    pub policies_evaluated: u32,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Custom metrics from plugin
    pub custom_metrics: HashMap<String, serde_json::Value>,
}

/// WebAssembly policy evaluator
pub struct WasmPolicyEvaluator {
    /// Evaluator metadata
    metadata: PluginMetadata,
    /// Policy cache
    cache: Arc<RwLock<HashMap<String, CachedPolicyResult>>>,
    /// Configuration
    config: PolicyEvaluatorConfig,
}

/// Cached policy result
#[derive(Debug, Clone)]
struct CachedPolicyResult {
    result: PolicyResult,
    timestamp: DateTime<Utc>,
    ttl_seconds: u64,
}

/// Policy evaluator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluatorConfig {
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Default cache TTL in seconds
    pub default_cache_ttl_seconds: u64,
    /// Maximum evaluation time in milliseconds
    pub max_evaluation_time_ms: u64,
    /// Whether to enable metrics collection
    pub enable_metrics: bool,
}

impl Default for PolicyEvaluatorConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 10000,
            default_cache_ttl_seconds: 300, // 5 minutes
            max_evaluation_time_ms: 5000, // 5 seconds
            enable_metrics: true,
        }
    }
}

impl WasmPolicyEvaluator {
    /// Create a new WASM policy evaluator
    pub fn new(metadata: PluginMetadata, config: PolicyEvaluatorConfig) -> Self {
        Self {
            metadata,
            cache: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Evaluate policy for given context
    pub async fn evaluate(&self, context: PolicyContext) -> Result<PolicyResult> {
        let start_time = std::time::Instant::now();

        // Check cache first
        let cache_key = self.generate_cache_key(&context);
        if let Some(cached) = self.check_cache(&cache_key).await {
            return Ok(cached);
        }

        // Perform policy evaluation
        let result = self.evaluate_policy_internal(context).await?;

        // Cache the result
        self.cache_result(&cache_key, &result).await;

        // Update metrics
        let evaluation_time = start_time.elapsed().as_millis() as u64;
        tracing::debug!("Policy evaluation completed in {}ms", evaluation_time);

        Ok(result)
    }

    /// Generate cache key from policy context
    fn generate_cache_key(&self, context: &PolicyContext) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        context.user.user_id.hash(&mut hasher);
        context.resource.resource_id.hash(&mut hasher);
        context.action.hash(&mut hasher);
        context.request.source_ip.hash(&mut hasher);
        
        // Include relevant attributes in hash
        for (key, value) in &context.user.attributes {
            key.hash(&mut hasher);
            value.to_string().hash(&mut hasher);
        }

        format!("policy_{:x}", hasher.finish())
    }

    /// Check cache for existing result
    async fn check_cache(&self, cache_key: &str) -> Option<PolicyResult> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(cache_key) {
            let now = Utc::now();
            let elapsed = (now - cached.timestamp).num_seconds() as u64;
            
            if elapsed < cached.ttl_seconds {
                return Some(cached.result.clone());
            }
        }
        None
    }

    /// Cache policy result
    async fn cache_result(&self, cache_key: &str, result: &PolicyResult) {
        let ttl = result.cache_ttl_seconds.unwrap_or(self.config.default_cache_ttl_seconds);
        
        let cached = CachedPolicyResult {
            result: result.clone(),
            timestamp: Utc::now(),
            ttl_seconds: ttl,
        };

        let mut cache = self.cache.write().await;
        
        // Implement cache size limit (simple LRU)
        if cache.len() >= self.config.max_cache_size {
            // Remove oldest entries (simplified)
            if let Some(oldest_key) = cache.keys().next().cloned() {
                cache.remove(&oldest_key);
            }
        }
        
        cache.insert(cache_key.to_string(), cached);
    }

    /// Internal policy evaluation implementation
    async fn evaluate_policy_internal(&self, context: PolicyContext) -> Result<PolicyResult> {
        let start_time = std::time::Instant::now();

        // Create policy evaluation input
        let input = crate::plugin::PluginInput {
            action: "evaluate_policy".to_string(),
            data: serde_json::to_value(context)
                .map_err(|e| FortressError::plugin(format!("Failed to serialize policy context: {}", e)))?,
            parameters: HashMap::new(),
        };

        // This would integrate with the WASM runtime
        // For now, implement a basic policy evaluation
        let result = self.basic_policy_evaluation(&input).await?;

        let evaluation_time = start_time.elapsed().as_millis() as u64;

        Ok(PolicyResult {
            allow: result.allow,
            reason: result.reason,
            effect: result.effect,
            obligations: result.obligations,
            advice: result.advice,
            metrics: PolicyMetrics {
                evaluation_time_ms: evaluation_time,
                policies_evaluated: 1,
                memory_usage_bytes: 0, // Would be populated by WASM runtime
                custom_metrics: result.metrics.custom_metrics,
            },
            cache_ttl_seconds: Some(self.config.default_cache_ttl_seconds),
        })
    }

    /// Basic policy evaluation (fallback implementation)
    async fn basic_policy_evaluation(&self, input: &crate::plugin::PluginInput) -> Result<PolicyResult> {
        let context: PolicyContext = serde_json::from_value(input.data.clone())
            .map_err(|e| FortressError::plugin(format!("Failed to deserialize policy context: {}", e)))?;

        // Implement basic RBAC + ABAC logic
        let mut allow = false;
        let mut reason = String::new();

        // Check role-based access
        if context.user.roles.contains(&"admin".to_string()) {
            allow = true;
            reason = "Admin role granted access".to_string();
        } else if context.user.roles.contains(&"user".to_string()) {
            // Check resource ownership
            if let Some(owner) = &context.resource.owner {
                if owner == &context.user.user_id {
                    allow = true;
                    reason = "Resource owner granted access".to_string();
                } else {
                    reason = "User does not own the resource".to_string();
                }
            } else {
                reason = "Resource ownership not defined".to_string();
            }
        } else {
            reason = "User has insufficient roles".to_string();
        }

        // Additional ABAC checks
        if allow {
            // Check time-based access
            let current_hour = context.environment.current_time.hour();
            if current_hour < 9 || current_hour > 17 {
                allow = false;
                reason = "Access outside business hours".to_string();
            }

            // Check geolocation
            if let Some(geo) = &context.environment.geolocation {
                if geo.country != "US" && geo.country != "CA" {
                    allow = false;
                    reason = "Access from restricted country".to_string();
                }
            }

            // Check threat intelligence
            if context.environment.threat_intelligence.risk_level == "critical" {
                allow = false;
                reason = "High risk threat detected".to_string();
            }
        }

        let effect = if allow { PolicyEffect::Allow } else { PolicyEffect::Deny };

        Ok(PolicyResult {
            allow,
            reason,
            effect,
            obligations: vec![],
            advice: if allow {
                Some("Access granted. Follow security best practices.".to_string())
            } else {
                Some("Access denied. Contact administrator if this is unexpected.".to_string())
            },
            metrics: PolicyMetrics {
                evaluation_time_ms: 0,
                policies_evaluated: 1,
                memory_usage_bytes: 0,
                custom_metrics: HashMap::new(),
            },
            cache_ttl_seconds: Some(self.config.default_cache_ttl_seconds),
        })
    }

    /// Get evaluator metadata
    pub fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    /// Clear policy cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        CacheStats {
            size: cache.len(),
            max_size: self.config.max_cache_size,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Current cache size
    pub size: usize,
    /// Maximum cache size
    pub max_size: usize,
}

/// Policy evaluator registry for managing multiple evaluators
pub struct PolicyEvaluatorRegistry {
    evaluators: Arc<RwLock<HashMap<String, Arc<WasmPolicyEvaluator>>>>,
    default_evaluator: Option<String>,
}

impl PolicyEvaluatorRegistry {
    /// Create a new policy evaluator registry
    pub fn new() -> Self {
        Self {
            evaluators: Arc::new(RwLock::new(HashMap::new())),
            default_evaluator: None,
        }
    }

    /// Register a policy evaluator
    pub async fn register_evaluator(&self, id: String, evaluator: Arc<WasmPolicyEvaluator>) {
        let mut evaluators = self.evaluators.write().await;
        evaluators.insert(id, evaluator);
    }

    /// Get a policy evaluator by ID
    pub async fn get_evaluator(&self, id: &str) -> Option<Arc<WasmPolicyEvaluator>> {
        let evaluators = self.evaluators.read().await;
        evaluators.get(id).cloned()
    }

    /// Set default evaluator
    pub async fn set_default_evaluator(&self, id: String) {
        let evaluators = self.evaluators.read().await;
        if evaluators.contains_key(&id) {
            // This would need to be made atomic in a real implementation
            drop(evaluators);
            // Implementation note: In a real scenario, we'd need interior mutability
            // For now, this is a placeholder
        }
    }

    /// Get default evaluator
    pub async fn get_default_evaluator(&self) -> Option<Arc<WasmPolicyEvaluator>> {
        if let Some(ref default_id) = self.default_evaluator {
            self.get_evaluator(default_id).await
        } else {
            // Return first available evaluator as fallback
            let evaluators = self.evaluators.read().await;
            evaluators.values().next().cloned()
        }
    }

    /// List all registered evaluators
    pub async fn list_evaluators(&self) -> Vec<String> {
        let evaluators = self.evaluators.read().await;
        evaluators.keys().cloned().collect()
    }
}

impl Default for PolicyEvaluatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_evaluation() {
        let metadata = PluginMetadata {
            id: "test-policy".to_string(),
            name: "Test Policy Evaluator".to_string(),
            version: "1.0.0".to_string(),
            description: "Test policy evaluator".to_string(),
            author: "Test".to_string(),
            capabilities: vec![PluginCapability::Custom("policy_evaluation".to_string())],
            config_schema: None,
        };

        let config = PolicyEvaluatorConfig::default();
        let evaluator = WasmPolicyEvaluator::new(metadata, config);

        let context = PolicyContext {
            request_id: Uuid::new_v4().to_string(),
            user: UserContext {
                user_id: "user123".to_string(),
                roles: vec!["user".to_string()],
                attributes: HashMap::new(),
                auth_method: "password".to_string(),
                session_id: Some("session456".to_string()),
                clearance_level: Some("confidential".to_string()),
            },
            resource: ResourceContext {
                resource_id: "resource789".to_string(),
                resource_type: "document".to_string(),
                attributes: HashMap::new(),
                owner: Some("user123".to_string()),
                classification: Some("confidential".to_string()),
                tags: vec!["finance".to_string()],
            },
            action: "read".to_string(),
            request: RequestContext {
                source_ip: "192.168.1.100".to_string(),
                user_agent: Some("Mozilla/5.0".to_string()),
                headers: HashMap::new(),
                parameters: HashMap::new(),
                method: "GET".to_string(),
                path: "/api/documents/789".to_string(),
            },
            environment: EnvironmentContext {
                current_time: Utc::now(),
                timezone: "UTC".to_string(),
                geolocation: Some(GeoLocation {
                    country: "US".to_string(),
                    region: Some("CA".to_string()),
                    city: Some("San Francisco".to_string()),
                    latitude: Some(37.7749),
                    longitude: Some(-122.4194),
                }),
                device: Some(DeviceContext {
                    device_type: "desktop".to_string(),
                    os: "Windows".to_string(),
                    browser: Some("Chrome".to_string()),
                    fingerprint: None,
                    trusted: true,
                }),
                network: NetworkContext {
                    network_type: "corporate".to_string(),
                    security_level: "high".to_string(),
                    vpn_info: None,
                },
                threat_intelligence: ThreatIntelligence {
                    ip_reputation_score: 85.0,
                    malicious_indicators: vec![],
                    risk_level: "low".to_string(),
                    last_updated: Utc::now(),
                },
            },
            timestamp: Utc::now(),
        };

        let result = evaluator.evaluate(context).await;
        assert!(result.is_ok());

        let policy_result = result.unwrap();
        assert!(policy_result.allow);
        assert_eq!(policy_result.effect, PolicyEffect::Allow);
    }

    #[tokio::test]
    async fn test_policy_cache() {
        let metadata = PluginMetadata {
            id: "test-cache".to_string(),
            name: "Test Cache Policy".to_string(),
            version: "1.0.0".to_string(),
            description: "Test policy caching".to_string(),
            author: "Test".to_string(),
            capabilities: vec![PluginCapability::Custom("policy_evaluation".to_string())],
            config_schema: None,
        };

        let config = PolicyEvaluatorConfig::default();
        let evaluator = WasmPolicyEvaluator::new(metadata, config);

        let context = PolicyContext {
            request_id: Uuid::new_v4().to_string(),
            user: UserContext {
                user_id: "user123".to_string(),
                roles: vec!["user".to_string()],
                attributes: HashMap::new(),
                auth_method: "password".to_string(),
                session_id: None,
                clearance_level: None,
            },
            resource: ResourceContext {
                resource_id: "resource789".to_string(),
                resource_type: "document".to_string(),
                attributes: HashMap::new(),
                owner: Some("user123".to_string()),
                classification: None,
                tags: vec![],
            },
            action: "read".to_string(),
            request: RequestContext {
                source_ip: "192.168.1.100".to_string(),
                user_agent: None,
                headers: HashMap::new(),
                parameters: HashMap::new(),
                method: "GET".to_string(),
                path: "/test".to_string(),
            },
            environment: EnvironmentContext {
                current_time: Utc::now(),
                timezone: "UTC".to_string(),
                geolocation: None,
                device: None,
                network: NetworkContext {
                    network_type: "corporate".to_string(),
                    security_level: "high".to_string(),
                    vpn_info: None,
                },
                threat_intelligence: ThreatIntelligence {
                    ip_reputation_score: 100.0,
                    malicious_indicators: vec![],
                    risk_level: "low".to_string(),
                    last_updated: Utc::now(),
                },
            },
            timestamp: Utc::now(),
        };

        // First evaluation
        let result1 = evaluator.evaluate(context.clone()).await.unwrap();
        
        // Second evaluation (should hit cache)
        let result2 = evaluator.evaluate(context).await.unwrap();

        assert_eq!(result1.allow, result2.allow);
        assert_eq!(result1.reason, result2.reason);

        let stats = evaluator.cache_stats().await;
        assert_eq!(stats.size, 1);
    }
}
