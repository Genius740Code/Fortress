//! Service Mesh Integration Module
//! 
//! This module provides integration with various service mesh platforms
//! including Envoy, Istio, and Linkerd for enhanced traffic management,
//! security, and observability.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::error::{FortressError, Result};

pub mod envoy;
pub mod istio;
pub mod linkerd;

pub use envoy::EnvoyMesh;
pub use istio::IstioMesh;
pub use linkerd::LinkerdMesh;

/// Service mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub mesh_type: MeshType,
    pub enabled: bool,
    pub settings: HashMap<String, serde_json::Value>,
    pub discovery_integration: bool,
    pub traffic_management: bool,
    pub security_integration: bool,
    pub observability_enabled: bool,
}

/// Supported service mesh types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshType {
    Envoy,
    Istio,
    Linkerd,
    None,
}

/// Mesh node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNode {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub service_account: String,
    pub workload_name: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub ip_address: String,
    pub port: u16,
    pub mesh_type: MeshType,
    pub last_seen: DateTime<Utc>,
    pub health_status: MeshNodeHealthStatus,
}

/// Mesh node health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MeshNodeHealthStatus {
    Healthy,
    Unhealthy,
    Degraded,
    Unknown,
}

/// Traffic policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPolicy {
    pub name: String,
    pub namespace: String,
    pub selector: HashMap<String, String>,
    pub rules: Vec<TrafficRule>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Individual traffic rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRule {
    pub name: String,
    pub priority: u32,
    pub match_conditions: Vec<MatchCondition>,
    pub actions: Vec<TrafficAction>,
    pub timeout_seconds: Option<u64>,
    pub retries: Option<u32>,
}

/// Traffic matching condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCondition {
    pub field: String,
    pub operator: MatchOperator,
    pub value: String,
}

/// Match operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    In,
    NotIn,
    Regex,
}

/// Traffic action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAction {
    pub action_type: ActionType,
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Route,
    Redirect,
    Rewrite,
    FaultInjection,
    Retry,
    Timeout,
    Mirror,
}

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub name: String,
    pub namespace: String,
    pub selector: HashMap<String, String>,
    pub authentication_rules: Vec<AuthRule>,
    pub authorization_rules: Vec<AuthzRule>,
    pub mtls_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Authentication rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRule {
    pub name: String,
    pub method: AuthMethod,
    pub jwt_rules: Option<JwtRule>,
    pub peer_auth_method: Option<PeerAuthMethod>,
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    JWT,
    MutualTLS,
    OAuth2,
    APIKey,
    Anonymous,
}

/// JWT rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtRule {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub from_cookies: Vec<String>,
    pub from_headers: Vec<String>,
    pub output_payload_to_header: String,
}

/// Peer authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerAuthMethod {
    MTLS,
    JWT,
    Plain,
}

/// Authorization rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzRule {
    pub name: String,
    pub action: AuthzAction,
    pub when: Vec<AuthzCondition>,
    pub deny: bool,
}

/// Authorization actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthzAction {
    Allow,
    Deny,
}

/// Authorization condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzCondition {
    pub key: String,
    pub values: Vec<String>,
    pub not_values: Vec<String>,
}

/// Observability metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMetrics {
    pub request_count: u64,
    pub request_duration_ms: u64,
    pub request_error_count: u64,
    pub request_success_rate: f64,
    pub connection_count: u64,
    pub active_connections: u64,
    pub last_updated: DateTime<Utc>,
}

/// Trait for service mesh providers
#[async_trait::async_trait]
pub trait MeshProvider: Send + Sync {
    /// Name of the mesh provider
    fn name(&self) -> &str;
    
    /// Mesh type
    fn mesh_type(&self) -> MeshType;
    
    /// Initialize the mesh provider
    async fn initialize(&mut self, config: &MeshConfig) -> Result<()>;
    
    /// Get mesh nodes
    async fn get_mesh_nodes(&self) -> Result<Vec<MeshNode>>;
    
    /// Get traffic policies
    async fn get_traffic_policies(&self) -> Result<Vec<TrafficPolicy>>;
    
    /// Get security policies
    async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>>;
    
    /// Apply traffic policy
    async fn apply_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()>;
    
    /// Apply security policy
    async fn apply_security_policy(&self, policy: &SecurityPolicy) -> Result<()>;
    
    /// Get mesh metrics
    async fn get_metrics(&self) -> Result<MeshMetrics>;
    
    /// Check mesh health
    async fn check_mesh_health(&self) -> Result<MeshNodeHealthStatus>;
    
    /// Shutdown the mesh provider
    async fn shutdown(&mut self) -> Result<()>;
}

/// Main mesh manager that coordinates multiple mesh providers
pub struct MeshManager {
    providers: Arc<RwLock<HashMap<String, Box<dyn MeshProvider>>>>,
    config: MeshConfig,
    nodes: Arc<RwLock<HashMap<String, MeshNode>>>,
    traffic_policies: Arc<RwLock<HashMap<String, TrafficPolicy>>>,
    security_policies: Arc<RwLock<HashMap<String, SecurityPolicy>>>,
    metrics: Arc<RwLock<MeshMetrics>>,
}

impl MeshManager {
    /// Create a new mesh manager
    pub fn new(config: MeshConfig) -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            config,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            traffic_policies: Arc::new(RwLock::new(HashMap::new())),
            security_policies: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(MeshMetrics {
                request_count: 0,
                request_duration_ms: 0,
                request_error_count: 0,
                request_success_rate: 0.0,
                connection_count: 0,
                active_connections: 0,
                last_updated: Utc::now(),
            })),
        }
    }

    /// Add a mesh provider
    pub async fn add_provider(&mut self, name: String, provider: Box<dyn MeshProvider>) -> Result<()> {
        let mut providers = self.providers.write().await;
        providers.insert(name, provider);
        Ok(())
    }

    /// Initialize all providers
    pub async fn initialize(&mut self) -> Result<()> {
        let mut providers = self.providers.write().await;
        
        for (name, provider) in providers.iter_mut() {
            provider.initialize(&self.config).await
                .map_err(|e| FortressError::mesh(format!("Failed to initialize mesh provider {}: {}", name, e)))?;
        }

        Ok(())
    }

    /// Get mesh nodes from all providers
    pub async fn get_mesh_nodes(&self) -> Result<Vec<MeshNode>> {
        let providers = self.providers.read().await;
        let mut all_nodes = Vec::new();

        for (name, provider) in providers.iter() {
            match provider.get_mesh_nodes().await {
                Ok(mut nodes) => {
                    // Add provider tag to each node
                    for node in &mut nodes {
                        node.labels.insert("mesh_provider".to_string(), name.clone());
                    }
                    all_nodes.extend(nodes);
                }
                Err(e) => {
                    tracing::warn!("Provider {} failed to get mesh nodes: {}", name, e);
                }
            }
        }

        // Update nodes cache
        let mut nodes_cache = self.nodes.write().await;
        nodes_cache.clear();
        for node in &all_nodes {
            nodes_cache.insert(node.id.clone(), node.clone());
        }

        Ok(all_nodes)
    }

    /// Get traffic policies from all providers
    pub async fn get_traffic_policies(&self) -> Result<Vec<TrafficPolicy>> {
        let providers = self.providers.read().await;
        let mut all_policies = Vec::new();

        for (name, provider) in providers.iter() {
            match provider.get_traffic_policies().await {
                Ok(mut policies) => {
                    // Add provider tag to each policy
                    for policy in &mut policies {
                        policy.labels.insert("mesh_provider".to_string(), name.clone());
                    }
                    all_policies.extend(policies);
                }
                Err(e) => {
                    tracing::warn!("Provider {} failed to get traffic policies: {}", name, e);
                }
            }
        }

        // Update policies cache
        let mut policies_cache = self.traffic_policies.write().await;
        policies_cache.clear();
        for policy in &all_policies {
            policies_cache.insert(policy.name.clone(), policy.clone());
        }

        Ok(all_policies)
    }

    /// Get security policies from all providers
    pub async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>> {
        let providers = self.providers.read().await;
        let mut all_policies = Vec::new();

        for (name, provider) in providers.iter() {
            match provider.get_security_policies().await {
                Ok(mut policies) => {
                    // Add provider tag to each policy
                    for policy in &mut policies {
                        policy.labels.insert("mesh_provider".to_string(), name.clone());
                    }
                    all_policies.extend(policies);
                }
                Err(e) => {
                    tracing::warn!("Provider {} failed to get security policies: {}", name, e);
                }
            }
        }

        // Update policies cache
        let mut policies_cache = self.security_policies.write().await;
        policies_cache.clear();
        for policy in &all_policies {
            policies_cache.insert(policy.name.clone(), policy.clone());
        }

        Ok(all_policies)
    }

    /// Apply traffic policy to all providers
    pub async fn apply_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()> {
        let providers = self.providers.read().await;
        let mut errors = Vec::new();

        for (name, provider) in providers.iter() {
            if let Err(e) = provider.apply_traffic_policy(policy).await {
                errors.push(format!("Provider {}: {}", name, e));
            }
        }

        if !errors.is_empty() {
            return Err(FortressError::mesh(format!("Failed to apply traffic policy: {}", errors.join("; "))));
        }

        // Update cache
        let mut policies_cache = self.traffic_policies.write().await;
        policies_cache.insert(policy.name.clone(), policy.clone());

        Ok(())
    }

    /// Apply security policy to all providers
    pub async fn apply_security_policy(&self, policy: &SecurityPolicy) -> Result<()> {
        let providers = self.providers.read().await;
        let mut errors = Vec::new();

        for (name, provider) in providers.iter() {
            if let Err(e) = provider.apply_security_policy(policy).await {
                errors.push(format!("Provider {}: {}", name, e));
            }
        }

        if !errors.is_empty() {
            return Err(FortressError::mesh(format!("Failed to apply security policy: {}", errors.join("; "))));
        }

        // Update cache
        let mut policies_cache = self.security_policies.write().await;
        policies_cache.insert(policy.name.clone(), policy.clone());

        Ok(())
    }

    /// Get aggregated metrics from all providers
    pub async fn get_metrics(&self) -> Result<MeshMetrics> {
        let providers = self.providers.read().await;
        let mut aggregated_metrics = MeshMetrics {
            request_count: 0,
            request_duration_ms: 0,
            request_error_count: 0,
            request_success_rate: 0.0,
            connection_count: 0,
            active_connections: 0,
            last_updated: Utc::now(),
        };
        let mut provider_count = 0;

        for (name, provider) in providers.iter() {
            match provider.get_metrics().await {
                Ok(metrics) => {
                    aggregated_metrics.request_count += metrics.request_count;
                    aggregated_metrics.request_duration_ms += metrics.request_duration_ms;
                    aggregated_metrics.request_error_count += metrics.request_error_count;
                    aggregated_metrics.connection_count += metrics.connection_count;
                    aggregated_metrics.active_connections += metrics.active_connections;
                    provider_count += 1;
                }
                Err(e) => {
                    tracing::warn!("Provider {} failed to get metrics: {}", name, e);
                }
            }
        }

        // Calculate averages
        if provider_count > 0 {
            aggregated_metrics.request_duration_ms /= provider_count;
            aggregated_metrics.request_success_rate = if aggregated_metrics.request_count > 0 {
                (aggregated_metrics.request_count - aggregated_metrics.request_error_count) as f64 / aggregated_metrics.request_count as f64
            } else {
                0.0
            };
        }

        // Update metrics cache
        let mut metrics_cache = self.metrics.write().await;
        *metrics_cache = aggregated_metrics.clone();

        Ok(aggregated_metrics)
    }

    /// Check overall mesh health
    pub async fn check_mesh_health(&self) -> Result<MeshNodeHealthStatus> {
        let providers = self.providers.read().await;
        let mut healthy_count = 0;
        let mut total_count = 0;

        for (name, provider) in providers.iter() {
            total_count += 1;
            match provider.check_mesh_health().await {
                Ok(health) => {
                    if health == MeshNodeHealthStatus::Healthy {
                        healthy_count += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!("Provider {} health check failed: {}", name, e);
                }
            }
        }

        if total_count == 0 {
            return Ok(MeshNodeHealthStatus::Unknown);
        }

        let health_ratio = healthy_count as f64 / total_count as f64;
        if health_ratio >= 0.8 {
            Ok(MeshNodeHealthStatus::Healthy)
        } else if health_ratio >= 0.5 {
            Ok(MeshNodeHealthStatus::Degraded)
        } else {
            Ok(MeshNodeHealthStatus::Unhealthy)
        }
    }

    /// Shutdown the mesh manager
    pub async fn shutdown(&mut self) -> Result<()> {
        let mut providers = self.providers.write().await;
        
        for (name, provider) in providers.iter_mut() {
            if let Err(e) = provider.shutdown().await {
                tracing::warn!("Failed to shutdown mesh provider {}: {}", name, e);
            }
        }

        Ok(())
    }
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            mesh_type: MeshType::None,
            enabled: false,
            settings: HashMap::new(),
            discovery_integration: true,
            traffic_management: true,
            security_integration: true,
            observability_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_config_default() {
        let config = MeshConfig::default();
        assert!(matches!(config.mesh_type, MeshType::None));
        assert!(!config.enabled);
        assert!(config.discovery_integration);
        assert!(config.traffic_management);
        assert!(config.security_integration);
        assert!(config.observability_enabled);
    }

    #[test]
    fn test_mesh_node_health_status_equality() {
        assert_eq!(MeshNodeHealthStatus::Healthy, MeshNodeHealthStatus::Healthy);
        assert_ne!(MeshNodeHealthStatus::Healthy, MeshNodeHealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_mesh_manager_creation() {
        let config = MeshConfig::default();
        let manager = MeshManager::new(config);
        
        let nodes = manager.get_mesh_nodes().await;
        assert!(nodes.is_empty());
        
        let metrics = manager.get_metrics().await;
        assert_eq!(metrics.request_count, 0);
    }
}
