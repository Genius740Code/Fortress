//! Envoy Service Mesh Integration
//! 
//! This module provides integration with Envoy proxy for advanced
//! traffic management, security, and observability features.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::error::{FortressError, Result};
use crate::mesh::{MeshProvider, MeshConfig, MeshNode, MeshNodeHealthStatus, TrafficPolicy, SecurityPolicy, MeshMetrics, MeshType};

/// Envoy mesh provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyMeshConfig {
    pub admin_api_address: String,
    pub xds_server_address: Option<String>,
    pub node_id: String,
    pub cluster: String,
    pub namespace: String,
    pub service_discovery_enabled: bool,
    pub health_check_enabled: bool,
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
    pub access_log_enabled: bool,
}

impl Default for EnvoyMeshConfig {
    fn default() -> Self {
        Self {
            admin_api_address: "http://localhost:9901".to_string(),
            xds_server_address: None,
            node_id: "fortress-node".to_string(),
            cluster: "fortress-cluster".to_string(),
            namespace: "default".to_string(),
            service_discovery_enabled: true,
            health_check_enabled: true,
            metrics_enabled: true,
            tracing_enabled: true,
            access_log_enabled: true,
        }
    }
}

/// Envoy mesh provider
pub struct EnvoyMesh {
    config: EnvoyMeshConfig,
    client: Option<reqwest::Client>,
    initialized: bool,
    node_cache: Arc<tokio::sync::RwLock<HashMap<String, MeshNode>>>,
    policy_cache: Arc<tokio::sync::RwLock<HashMap<String, (DateTime<Utc>, serde_json::Value)>>>,
}

impl EnvoyMesh {
    /// Create a new Envoy mesh provider
    pub fn new(config: EnvoyMeshConfig) -> Self {
        Self {
            config,
            client: None,
            initialized: false,
            node_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            policy_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Create HTTP client for Envoy admin API
    fn create_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    /// Build Envoy admin API URL
    fn build_admin_url(&self, endpoint: &str) -> String {
        let base_url = self.config.admin_api_address.trim_end_matches('/');
        format!("{}/{}", base_url, endpoint)
    }

    /// Get Envoy stats
    async fn get_envoy_stats(&self) -> Result<EnvoyStats> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Envoy client not initialized"))?;

        let url = self.build_admin_url("stats");
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Envoy stats API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Envoy stats API returned status: {}", response.status())));
        }

        let stats_text = response.text()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to read Envoy stats response: {}", e)))?;

        self.parse_envoy_stats(&stats_text)
    }

    /// Parse Envoy stats from text format
    fn parse_envoy_stats(&self, stats_text: &str) -> Result<EnvoyStats> {
        let mut stats = EnvoyStats::default();

        for line in stats_text.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();

                match name {
                    "cluster_manager.active_clusters" => {
                        stats.active_clusters = value.parse().unwrap_or(0);
                    }
                    "cluster_manager.warming_clusters" => {
                        stats.warming_clusters = value.parse().unwrap_or(0);
                    }
                    "server.total_connections" => {
                        stats.total_connections = value.parse().unwrap_or(0);
                    }
                    "listener_manager.total_listeners" => {
                        stats.total_listeners = value.parse().unwrap_or(0);
                    }
                    _ => {
                        // Extract request metrics
                        if name.contains("request_total") {
                            stats.request_total += value.parse().unwrap_or(0);
                        }
                        if name.contains("request_success") {
                            stats.request_success += value.parse().unwrap_or(0);
                        }
                        if name.contains("request_failure") {
                            stats.request_failure += value.parse().unwrap_or(0);
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Get Envoy clusters
    async fn get_envoy_clusters(&self) -> Result<Vec<EnvoyCluster>> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Envoy client not initialized"))?;

        let url = self.build_admin_url("clusters");
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Envoy clusters API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Envoy clusters API returned status: {}", response.status())));
        }

        let clusters: Vec<EnvoyCluster> = response.json()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to parse Envoy clusters response: {}", e)))?;

        Ok(clusters)
    }

    /// Get Envoy listeners
    async fn get_envoy_listeners(&self) -> Result<Vec<EnvoyListener>> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Envoy client not initialized"))?;

        let url = self.build_admin_url("listeners");
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Envoy listeners API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Envoy listeners API returned status: {}", response.status())));
        }

        let listeners: Vec<EnvoyListener> = response.json()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to parse Envoy listeners response: {}", e)))?;

        Ok(listeners)
    }

    /// Convert Envoy cluster to mesh node
    fn envoy_cluster_to_mesh_node(&self, cluster: &EnvoyCluster) -> Result<MeshNode> {
        let node_id = format!("envoy-cluster-{}", cluster.name);
        
        // Extract IP address from cluster endpoints
        let ip_address = cluster.endpoints.first()
            .and_then(|endpoint| endpoint.address.as_ref())
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let port = cluster.endpoints.first()
            .map(|endpoint| endpoint.port)
            .unwrap_or(8080);

        // Create labels
        let mut labels = HashMap::new();
        labels.insert("mesh_provider".to_string(), "envoy".to_string());
        labels.insert("cluster_name".to_string(), cluster.name.clone());
        labels.insert("cluster_type".to_string(), cluster.cluster_type.clone());
        
        if let Some(ref service_name) = cluster.service_name {
            labels.insert("service_name".to_string(), service_name.clone());
        }

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("cluster_name".to_string(), cluster.name.clone());
        metadata.insert("cluster_type".to_string(), cluster.cluster_type.clone());
        metadata.insert("healthy_percentage".to_string(), cluster.healthy_percentage.to_string());
        metadata.insert("total_endpoints".to_string(), cluster.endpoints.len().to_string());

        // Determine health status
        let health_status = if cluster.healthy_percentage >= 80 {
            MeshNodeHealthStatus::Healthy
        } else if cluster.healthy_percentage >= 50 {
            MeshNodeHealthStatus::Degraded
        } else if cluster.healthy_percentage > 0 {
            MeshNodeHealthStatus::Unhealthy
        } else {
            MeshNodeHealthStatus::Unknown
        };

        Ok(MeshNode {
            id: node_id,
            name: cluster.name.clone(),
            namespace: self.config.namespace.clone(),
            service_account: "default".to_string(),
            workload_name: cluster.name.clone(),
            labels,
            annotations: HashMap::new(),
            ip_address,
            port,
            mesh_type: MeshType::Envoy,
            last_seen: Utc::now(),
            health_status,
        })
    }

    /// Apply traffic policy via Envoy configuration
    async fn apply_envoy_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()> {
        // Convert traffic policy to Envoy configuration
        let envoy_config = self.convert_traffic_policy_to_envoy_config(policy)?;
        
        // Apply configuration via Envoy admin API
        self.apply_envoy_config(&envoy_config).await
    }

    /// Apply security policy via Envoy configuration
    async fn apply_envoy_security_policy(&self, policy: &SecurityPolicy) -> Result<()> {
        // Convert security policy to Envoy configuration
        let envoy_config = self.convert_security_policy_to_envoy_config(policy)?;
        
        // Apply configuration via Envoy admin API
        self.apply_envoy_config(&envoy_config).await
    }

    /// Convert traffic policy to Envoy configuration
    fn convert_traffic_policy_to_envoy_config(&self, policy: &TrafficPolicy) -> Result<serde_json::Value> {
        let mut config = serde_json::json!({
            "version_info": "1.0.0",
            "resources": []
        });

        // Convert each traffic rule to Envoy route configuration
        for rule in &policy.rules {
            let route_config = serde_json::json!({
                "@type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
                "name": format!("{}-{}", policy.name, rule.name),
                "virtual_hosts": [{
                    "name": format!("{}-vh", policy.name),
                    "domains": ["*"],
                    "routes": [{
                        "match": {
                            "prefix": "/"
                        },
                        "route": {
                            "cluster": "fortress-cluster",
                            "timeout": format!("{}s", rule.timeout_seconds.unwrap_or(30)),
                            "retry_policy": {
                                "num_retries": rule.retries.unwrap_or(3),
                                "retry_on": "5xx,gateway-error,reset,connect-failure,refused-stream"
                            }
                        }
                    }]
                }]
            });

            config["resources"].as_array_mut()
                .unwrap()
                .push(route_config);
        }

        Ok(config)
    }

    /// Convert security policy to Envoy configuration
    fn convert_security_policy_to_envoy_config(&self, policy: &SecurityPolicy) -> Result<serde_json::Value> {
        let mut config = serde_json::json!({
            "version_info": "1.0.0",
            "resources": []
        });

        // Convert authentication rules to Envoy filter configuration
        for auth_rule in &policy.authentication_rules {
            let filter_config = match auth_rule.method {
                crate::mesh::AuthMethod::JWT => {
                    serde_json::json!({
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
                        "providers": {
                            "fortress-jwt": {
                                "issuer": auth_rule.jwt_rules.as_ref().map(|j| &j.issuer).unwrap_or("fortress"),
                                "audiences": auth_rule.jwt_rules.as_ref().map(|j| j.audiences.clone()).unwrap_or_default(),
                                "from_headers": auth_rule.jwt_rules.as_ref().map(|j| j.from_headers.clone()).unwrap_or_default(),
                                "from_cookies": auth_rule.jwt_rules.as_ref().map(|j| j.from_cookies.clone()).unwrap_or_default(),
                                "forward_payload_header": auth_rule.jwt_rules.as_ref().map(|j| &j.output_payload_to_header).unwrap_or("x-jwt-payload")
                            }
                        }
                    })
                }
                crate::mesh::AuthMethod::MutualTLS => {
                    serde_json::json!({
                        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                        "transport_socket": {
                            "name": "envoy.transport_sockets.tls",
                            "typed_config": {
                                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                                "require_tls_certificate": true,
                                "common_tls_context": {
                                    "tls_certificates": [{
                                        "certificate_chain": {
                                            "filename": "/etc/ssl/certs/tls.crt"
                                        },
                                        "private_key": {
                                            "filename": "/etc/ssl/private/tls.key"
                                        }
                                    }]
                                }
                            }
                        }
                    })
                }
                _ => {
                    serde_json::json!({})
                }
            };

            let listener_config = serde_json::json!({
                "@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
                "name": format!("{}-listener", policy.name),
                "address": {
                    "socket_address": {
                        "address": "0.0.0.0",
                        "port_value": 8080
                    }
                },
                "filter_chains": [{
                    "filters": [{
                        "name": "envoy.filters.network.http_connection_manager",
                        "typed_config": filter_config
                    }]
                }]
            });

            config["resources"].as_array_mut()
                .unwrap()
                .push(listener_config);
        }

        Ok(config)
    }

    /// Apply configuration to Envoy
    async fn apply_envoy_config(&self, config: &serde_json::Value) -> Result<()> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Envoy client not initialized"))?;

        let url = self.build_admin_url("config_dump");
        
        let response = client.post(&url)
            .json(config)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Envoy config API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Envoy config API returned status: {}", response.status())));
        }

        tracing::info!("Applied configuration to Envoy successfully");
        Ok(())
    }

    /// Get Envoy metrics
    async fn get_envoy_metrics(&self) -> Result<EnvoyMetrics> {
        let stats = self.get_envoy_stats().await?;
        
        Ok(EnvoyMetrics {
            request_count: stats.request_total,
            request_duration_ms: 0, // Would need to calculate from histogram stats
            request_error_count: stats.request_failure,
            request_success_rate: if stats.request_total > 0 {
                (stats.request_total - stats.request_failure) as f64 / stats.request_total as f64
            } else {
                0.0
            },
            connection_count: stats.total_connections,
            active_connections: stats.total_connections, // Approximation
            last_updated: Utc::now(),
        })
    }
}

#[async_trait::async_trait]
impl MeshProvider for EnvoyMesh {
    fn name(&self) -> &str {
        "envoy"
    }

    fn mesh_type(&self) -> MeshType {
        MeshType::Envoy
    }

    async fn initialize(&mut self, config: &MeshConfig) -> Result<()> {
        // Extract Envoy-specific config
        let envoy_config: EnvoyMeshConfig = serde_json::from_value(
            serde_json::to_value(&config.settings).unwrap_or_default()
        ).unwrap_or_default();

        self.config = envoy_config;

        // Create HTTP client
        self.client = Some(self.create_client());
        self.initialized = true;

        tracing::info!("Envoy mesh provider initialized with admin API at {}", self.config.admin_api_address);
        Ok(())
    }

    async fn get_mesh_nodes(&self) -> Result<Vec<MeshNode>> {
        if !self.initialized {
            return Err(FortressError::mesh("Envoy mesh provider not initialized"));
        }

        let mut nodes = Vec::new();

        // Get clusters and convert to mesh nodes
        match self.get_envoy_clusters().await {
            Ok(clusters) => {
                for cluster in clusters {
                    match self.envoy_cluster_to_mesh_node(&cluster) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!("Failed to convert Envoy cluster to mesh node: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Envoy clusters: {}", e);
            }
        }

        tracing::debug!("Envoy mesh found {} nodes", nodes.len());
        Ok(nodes)
    }

    async fn get_traffic_policies(&self) -> Result<Vec<TrafficPolicy>> {
        if !self.initialized {
            return Err(FortressError::mesh("Envoy mesh provider not initialized"));
        }

        // Envoy doesn't have a direct concept of traffic policies
        // They are embedded in the route configuration
        // For now, return empty list
        Ok(Vec::new())
    }

    async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>> {
        if !self.initialized {
            return Err(FortressError::mesh("Envoy mesh provider not initialized"));
        }

        // Envoy doesn't have a direct concept of security policies
        // They are embedded in the filter configuration
        // For now, return empty list
        Ok(Vec::new())
    }

    async fn apply_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()> {
        if !self.initialized {
            return Err(FortressError::mesh("Envoy mesh provider not initialized"));
        }

        self.apply_envoy_traffic_policy(policy).await
    }

    async fn apply_security_policy(&self, policy: &SecurityPolicy) -> Result<()> {
        if !self.initialized {
            return Err(FortressError::mesh("Envoy mesh provider not initialized"));
        }

        self.apply_envoy_security_policy(policy).await
    }

    async fn get_metrics(&self) -> Result<MeshMetrics> {
        if !self.initialized {
            return Err(FortressError::mesh("Envoy mesh provider not initialized"));
        }

        let envoy_metrics = self.get_envoy_metrics().await?;
        
        Ok(MeshMetrics {
            request_count: envoy_metrics.request_count,
            request_duration_ms: envoy_metrics.request_duration_ms,
            request_error_count: envoy_metrics.request_error_count,
            request_success_rate: envoy_metrics.request_success_rate,
            connection_count: envoy_metrics.connection_count,
            active_connections: envoy_metrics.active_connections,
            last_updated: envoy_metrics.last_updated,
        })
    }

    async fn check_mesh_health(&self) -> Result<MeshNodeHealthStatus> {
        if !self.initialized {
            return Err(FortressError::mesh("Envoy mesh provider not initialized"));
        }

        // Check if Envoy admin API is accessible
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Envoy client not initialized"))?;

        let url = self.build_admin_url("stats");
        
        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(MeshNodeHealthStatus::Healthy)
                } else {
                    Ok(MeshNodeHealthStatus::Unhealthy)
                }
            }
            Err(_) => Ok(MeshNodeHealthStatus::Unhealthy),
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.client = None;
        self.initialized = false;
        
        // Clear caches
        {
            let mut node_cache = self.node_cache.write().await;
            node_cache.clear();
        }
        {
            let mut policy_cache = self.policy_cache.write().await;
            policy_cache.clear();
        }
        
        tracing::info!("Envoy mesh provider shutdown");
        Ok(())
    }
}

/// Envoy cluster information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyCluster {
    pub name: String,
    pub cluster_type: String,
    pub service_name: Option<String>,
    pub endpoints: Vec<EnvoyEndpoint>,
    pub healthy_percentage: u32,
}

/// Envoy endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyEndpoint {
    pub address: Option<String>,
    pub port: u16,
    pub healthy: bool,
}

/// Envoy listener information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyListener {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub filter_chains: Vec<EnvoyFilterChain>,
}

/// Envoy filter chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyFilterChain {
    pub filters: Vec<EnvoyFilter>,
}

/// Envoy filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyFilter {
    pub name: String,
    pub config: serde_json::Value,
}

/// Envoy stats information
#[derive(Debug, Clone, Default)]
pub struct EnvoyStats {
    pub active_clusters: u64,
    pub warming_clusters: u64,
    pub total_connections: u64,
    pub total_listeners: u64,
    pub request_total: u64,
    pub request_success: u64,
    pub request_failure: u64,
}

/// Envoy metrics
#[derive(Debug, Clone)]
pub struct EnvoyMetrics {
    pub request_count: u64,
    pub request_duration_ms: u64,
    pub request_error_count: u64,
    pub request_success_rate: f64,
    pub connection_count: u64,
    pub active_connections: u64,
    pub last_updated: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envoy_config_default() {
        let config = EnvoyMeshConfig::default();
        assert_eq!(config.admin_api_address, "http://localhost:9901");
        assert_eq!(config.node_id, "fortress-node");
        assert_eq!(config.cluster, "fortress-cluster");
        assert_eq!(config.namespace, "default");
        assert!(config.service_discovery_enabled);
        assert!(config.health_check_enabled);
    }

    #[test]
    fn test_envoy_mesh_creation() {
        let config = EnvoyMeshConfig::default();
        let mesh = EnvoyMesh::new(config);
        
        assert_eq!(mesh.name(), "envoy");
        assert_eq!(mesh.mesh_type(), MeshType::Envoy);
        assert!(!mesh.initialized);
        assert!(mesh.client.is_none());
    }

    #[test]
    fn test_build_admin_url() {
        let config = EnvoyMeshConfig {
            admin_api_address: "http://localhost:9901".to_string(),
            ..Default::default()
        };
        let mesh = EnvoyMesh::new(config);
        
        let url = mesh.build_admin_url("stats");
        assert_eq!(url, "http://localhost:9901/stats");
    }
}
