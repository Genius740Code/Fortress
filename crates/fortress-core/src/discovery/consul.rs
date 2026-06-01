//! Consul Discovery Provider
//!
//! This module provides automatic discovery of Fortress cluster nodes
//! through HashiCorp Consul's service discovery and health checking.

use crate::discovery::{DiscoveredNode, DiscoveryConfig, DiscoveryProvider, NodeHealthStatus};
use crate::error::{FortressError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Consul discovery provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulDiscoveryConfig {
    pub address: String,
    pub token: Option<String>,
    pub datacenter: Option<String>,
    pub service_name: String,
    pub tag: Option<String>,
    pub only_passing: bool,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub health_check_enabled: bool,
    pub health_check_interval_seconds: u64,
    pub use_cache: bool,
    pub cache_ttl_seconds: u64,
}

/// Consul service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulService {
    pub id: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub datacenter: Option<String>,
    pub node: String,
    pub service_address: String,
    pub service_port: u16,
    pub create_index: u64,
    pub modify_index: u64,
}

/// Consul health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsulHealthStatus {
    Passing,
    Warning,
    Critical,
    Unknown,
}

/// Consul discovery provider
pub struct ConsulDiscovery {
    config: ConsulDiscoveryConfig,
    client: Option<reqwest::Client>,
    initialized: bool,
    service_cache: Arc<tokio::sync::RwLock<HashMap<String, (DateTime<Utc>, Vec<DiscoveredNode>)>>>,
}

impl ConsulDiscovery {
    /// Create a new Consul discovery provider
    pub fn new(config: ConsulDiscoveryConfig) -> Self {
        Self {
            config,
            client: None,
            initialized: false,
            service_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Create HTTP client for Consul API
    fn create_client(&self) -> reqwest::Client {
        let mut client_builder =
            reqwest::Client::builder().timeout(Duration::from_secs(self.config.timeout_seconds));

        // Add authentication token if provided
        if let Some(ref token) = self.config.token {
            client_builder = client_builder.default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert("X-Consul-Token", token.parse().unwrap());
                headers
            });
        }

        client_builder
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    /// Build Consul API URL
    fn build_api_url(&self, endpoint: &str) -> String {
        let base_url = self.config.address.trim_end_matches('/');
        format!("{}/v1/{}", base_url, endpoint)
    }

    /// Query Consul for services
    async fn query_consul_services(&self) -> Result<Vec<ConsulService>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::discovery("Consul client not initialized"))?;

        let mut url = self.build_api_url(&format!("catalog/service/{}", self.config.service_name));

        // Add query parameters
        let mut params = Vec::new();

        if let Some(ref tag) = self.config.tag {
            params.push(format!("tag={}", tag));
        }

        if let Some(ref datacenter) = self.config.datacenter {
            params.push(format!("dc={}", datacenter));
        }

        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let response =
            client.get(&url).send().await.map_err(|e| {
                FortressError::discovery(format!("Consul API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(FortressError::discovery(format!(
                "Consul API returned status: {}",
                response.status()
            )));
        }

        let services: Vec<ConsulService> = response.json().await.map_err(|e| {
            FortressError::discovery(format!("Failed to parse Consul response: {}", e))
        })?;

        Ok(services)
    }

    /// Query Consul for service health
    async fn query_consul_health(&self) -> Result<HashMap<String, ConsulHealthStatus>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::discovery("Consul client not initialized"))?;

        let mut url = self.build_api_url(&format!("health/service/{}", self.config.service_name));

        // Add query parameters
        let mut params = Vec::new();

        if let Some(ref tag) = self.config.tag {
            params.push(format!("tag={}", tag));
        }

        if let Some(ref datacenter) = self.config.datacenter {
            params.push(format!("dc={}", datacenter));
        }

        if self.config.only_passing {
            params.push("passing=true".to_string());
        }

        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let response = client.get(&url).send().await.map_err(|e| {
            FortressError::discovery(format!("Consul health API request failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(FortressError::discovery(format!(
                "Consul health API returned status: {}",
                response.status()
            )));
        }

        // Parse health checks
        #[derive(Deserialize)]
        struct HealthCheck {
            #[serde(rename = "ServiceID")]
            service_id: String,
            #[serde(rename = "Status")]
            status: String,
        }

        let health_checks: Vec<HealthCheck> = response.json().await.map_err(|e| {
            FortressError::discovery(format!("Failed to parse Consul health response: {}", e))
        })?;

        let mut health_map = HashMap::new();
        for check in health_checks {
            let status = match check.status.as_str() {
                "passing" => ConsulHealthStatus::Passing,
                "warning" => ConsulHealthStatus::Warning,
                "critical" => ConsulHealthStatus::Critical,
                _ => ConsulHealthStatus::Unknown,
            };
            health_map.insert(check.service_id, status);
        }

        Ok(health_map)
    }

    /// Convert Consul service to discovered node
    fn consul_service_to_node(
        &self,
        service: &ConsulService,
        health_status: Option<ConsulHealthStatus>,
    ) -> Result<DiscoveredNode> {
        // Determine the actual address and port to use
        let (address, port) = if !service.service_address.is_empty() && service.service_port != 0 {
            (service.service_address.clone(), service.service_port)
        } else {
            (service.address.clone(), service.port)
        };

        // Create tags
        let mut tags = HashMap::new();
        tags.insert("discovery_type".to_string(), "consul".to_string());
        tags.insert("service".to_string(), service.name.clone());
        tags.insert("node".to_string(), service.node.clone());

        for tag in &service.tags {
            tags.insert(tag.clone(), "true".to_string());
        }

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.extend(service.meta.clone());
        metadata.insert("service_id".to_string(), service.id.clone());
        metadata.insert("create_index".to_string(), service.create_index.to_string());
        metadata.insert("modify_index".to_string(), service.modify_index.to_string());

        if let Some(ref dc) = service.datacenter {
            metadata.insert("datacenter".to_string(), dc.clone());
        }

        // Determine health status
        let health_status = match health_status {
            Some(ConsulHealthStatus::Passing) => NodeHealthStatus::Healthy,
            Some(ConsulHealthStatus::Warning) => NodeHealthStatus::Degraded,
            Some(ConsulHealthStatus::Critical) => NodeHealthStatus::Unhealthy,
            Some(ConsulHealthStatus::Unknown) | None => NodeHealthStatus::Unknown,
        };

        // Extract capabilities from tags or metadata
        let mut capabilities = vec!["consul_discovered".to_string()];
        if let Some(capability_list) = metadata.get("capabilities") {
            capabilities.extend(capability_list.split(',').map(|s| s.trim().to_string()));
        }

        Ok(DiscoveredNode {
            id: format!("consul-{}", service.id),
            address,
            port,
            region: service.datacenter.clone(),
            zone: None,
            tags,
            metadata,
            last_seen: Utc::now(),
            health_status,
            capabilities,
        })
    }

    /// Check if cached data is still valid
    async fn is_cache_valid(&self, cache_key: &str) -> bool {
        if !self.config.use_cache {
            return false;
        }

        let cache = self.service_cache.read().await;
        if let Some((timestamp, _)) = cache.get(cache_key) {
            let elapsed = Utc::now() - *timestamp;
            elapsed.num_seconds() < self.config.cache_ttl_seconds as i64
        } else {
            false
        }
    }

    /// Get cached services
    async fn get_cached_services(&self, cache_key: &str) -> Option<Vec<DiscoveredNode>> {
        let cache = self.service_cache.read().await;
        cache.get(cache_key).map(|(_, nodes)| nodes.clone())
    }

    /// Cache services
    async fn cache_services(&self, cache_key: &str, nodes: Vec<DiscoveredNode>) {
        if self.config.use_cache {
            let mut cache = self.service_cache.write().await;
            cache.insert(cache_key.to_string(), (Utc::now(), nodes));
        }
    }

    /// Generate cache key
    fn generate_cache_key(&self) -> String {
        let mut key = self.config.service_name.clone();

        if let Some(ref tag) = self.config.tag {
            key.push_str(&format!("_{}", tag));
        }

        if let Some(ref dc) = self.config.datacenter {
            key.push_str(&format!("_{}", dc));
        }

        key
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for ConsulDiscovery {
    fn name(&self) -> &str {
        "consul"
    }

    async fn initialize(&mut self, config: &DiscoveryConfig) -> Result<()> {
        // Extract Consul-specific config
        let consul_config: ConsulDiscoveryConfig =
            serde_json::from_value(serde_json::to_value(&config.settings).unwrap_or_default())
                .unwrap_or_default();

        self.config = consul_config;

        // Create HTTP client
        self.client = Some(self.create_client());
        self.initialized = true;

        tracing::info!(
            "Consul discovery provider initialized for service: {} at {}",
            self.config.service_name,
            self.config.address
        );
        Ok(())
    }

    async fn discover_nodes(&self) -> Result<Vec<DiscoveredNode>> {
        if !self.initialized {
            return Err(FortressError::discovery(
                "Consul discovery provider not initialized",
            ));
        }

        let cache_key = self.generate_cache_key();

        // Check cache first
        if self.is_cache_valid(&cache_key).await {
            if let Some(cached_nodes) = self.get_cached_services(&cache_key).await {
                tracing::debug!(
                    "Using cached Consul discovery results: {} nodes",
                    cached_nodes.len()
                );
                return Ok(cached_nodes);
            }
        }

        // Query Consul for services
        let services = self.query_consul_services().await?;

        // Query Consul for health status
        let health_status = match self.query_consul_health().await {
            Ok(health) => Some(health),
            Err(e) => {
                tracing::warn!("Failed to query Consul health: {}", e);
                None
            }
        };

        // Convert services to discovered nodes
        let mut nodes = Vec::new();
        for service in services {
            let service_health = health_status
                .as_ref()
                .and_then(|health| health.get(&service.id))
                .cloned();

            match self.consul_service_to_node(&service, service_health) {
                Ok(node) => nodes.push(node),
                Err(e) => {
                    tracing::warn!("Failed to convert Consul service to node: {}", e);
                }
            }
        }

        // Cache the results
        self.cache_services(&cache_key, nodes.clone()).await;

        tracing::debug!("Consul discovery found {} nodes", nodes.len());
        Ok(nodes)
    }

    async fn check_node_health(&self, node: &DiscoveredNode) -> Result<NodeHealthStatus> {
        if !self.initialized {
            return Err(FortressError::discovery(
                "Consul discovery provider not initialized",
            ));
        }

        // Extract service ID from node ID
        let service_id = node
            .id
            .strip_prefix("consul-")
            .ok_or_else(|| FortressError::discovery("Invalid Consul node ID"))?;

        // Query Consul for the specific service health
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::discovery("Consul client not initialized"))?;

        let mut url = self.build_api_url(&format!(
            "health/service/{}/{}",
            self.config.service_name, service_id
        ));

        if let Some(ref datacenter) = self.config.datacenter {
            url = format!("{}?dc={}", url, datacenter);
        }

        let response =
            client.get(&url).send().await.map_err(|e| {
                FortressError::discovery(format!("Consul health check failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Ok(NodeHealthStatus::Unknown);
        }

        #[derive(Deserialize)]
        struct HealthCheck {
            #[serde(rename = "Status")]
            status: String,
        }

        let health_checks: Vec<HealthCheck> = response.json().await.map_err(|e| {
            FortressError::discovery(format!("Failed to parse health check response: {}", e))
        })?;

        if health_checks.is_empty() {
            return Ok(NodeHealthStatus::Unknown);
        }

        // Determine overall health status based on all checks
        let mut overall_status = NodeHealthStatus::Healthy;
        for check in health_checks {
            match check.status.as_str() {
                "passing" => continue,
                "warning" => {
                    overall_status = NodeHealthStatus::Degraded;
                }
                "critical" => {
                    return Ok(NodeHealthStatus::Unhealthy);
                }
                _ => {
                    overall_status = NodeHealthStatus::Unknown;
                }
            }
        }

        Ok(overall_status)
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.client = None;
        self.initialized = false;

        // Clear cache
        let mut cache = self.service_cache.write().await;
        cache.clear();

        tracing::info!("Consul discovery provider shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consul_config_default() {
        let config = ConsulDiscoveryConfig::default();
        assert_eq!(config.service_name, "fortress");
        assert_eq!(config.timeout_seconds, 5);
        assert_eq!(config.retry_attempts, 3);
        assert!(config.health_check_enabled);
        assert!(config.use_cache);
        assert_eq!(config.cache_ttl_seconds, 300);
    }

    #[test]
    fn test_consul_discovery_creation() {
        let config = ConsulDiscoveryConfig::default();
        let discovery = ConsulDiscovery::new(config);

        assert_eq!(discovery.name(), "consul");
        assert!(!discovery.initialized);
        assert!(discovery.client.is_none());
    }

    #[test]
    fn test_build_api_url() {
        let config = ConsulDiscoveryConfig {
            address: "http://localhost:8500".to_string(),
            ..Default::default()
        };
        let discovery = ConsulDiscovery::new(config);

        let url = discovery.build_api_url("catalog/service/test");
        assert_eq!(url, "http://localhost:8500/v1/catalog/service/test");
    }

    #[test]
    fn test_generate_cache_key() {
        let mut config = ConsulDiscoveryConfig::default();
        let discovery = ConsulDiscovery::new(config.clone());

        // Basic service name
        let key = discovery.generate_cache_key();
        assert_eq!(key, "fortress");

        // With tag
        config.tag = Some("production".to_string());
        let discovery = ConsulDiscovery::new(config.clone());
        let key = discovery.generate_cache_key();
        assert_eq!(key, "fortress_production");

        // With datacenter
        config.datacenter = Some("dc1".to_string());
        let discovery = ConsulDiscovery::new(config);
        let key = discovery.generate_cache_key();
        assert_eq!(key, "fortress_production_dc1");
    }
}
