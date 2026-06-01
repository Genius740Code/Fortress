//! Cluster Discovery Module
//!
//! This module provides automatic discovery of Fortress cluster nodes
//! through multiple mechanisms including Kubernetes, DNS, Consul, and static configuration.

use crate::error::{FortressError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod consul;
pub mod dns;
pub mod kubernetes;
pub mod static_config;

pub use consul::ConsulDiscovery;
pub use dns::DnsDiscovery;
pub use kubernetes::KubernetesDiscovery;
pub use static_config::StaticDiscovery;

/// Node information discovered by discovery mechanisms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredNode {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub tags: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
    pub last_seen: DateTime<Utc>,
    pub health_status: NodeHealthStatus,
    pub capabilities: Vec<String>,
}

/// Health status of a discovered node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeHealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
    Degraded,
}

/// Discovery mechanism configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub mechanism: DiscoveryMechanism,
    pub settings: HashMap<String, serde_json::Value>,
    pub poll_interval_seconds: u64,
    pub timeout_seconds: u64,
    pub enabled: bool,
}

/// Supported discovery mechanisms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMechanism {
    Kubernetes,
    Dns,
    Consul,
    Static,
}

/// Trait for discovery mechanisms
#[async_trait::async_trait]
pub trait DiscoveryProvider: Send + Sync {
    /// Name of the discovery provider
    fn name(&self) -> &str;

    /// Initialize the discovery provider
    async fn initialize(&mut self, config: &DiscoveryConfig) -> Result<()>;

    /// Discover nodes
    async fn discover_nodes(&self) -> Result<Vec<DiscoveredNode>>;

    /// Check if a node is healthy
    async fn check_node_health(&self, node: &DiscoveredNode) -> Result<NodeHealthStatus>;

    /// Shutdown the discovery provider
    async fn shutdown(&mut self) -> Result<()>;
}

/// Main discovery manager that coordinates multiple discovery mechanisms
pub struct DiscoveryManager {
    providers: Arc<RwLock<HashMap<String, Box<dyn DiscoveryProvider>>>>,
    config: DiscoveryConfig,
    nodes: Arc<RwLock<HashMap<String, DiscoveredNode>>>,
    last_discovery: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            config,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            last_discovery: Arc::new(RwLock::new(None)),
        }
    }

    /// Add a discovery provider
    pub async fn add_provider(
        &mut self,
        name: String,
        provider: Box<dyn DiscoveryProvider>,
    ) -> Result<()> {
        let mut providers = self.providers.write().await;
        providers.insert(name, provider);
        Ok(())
    }

    /// Initialize all providers
    pub async fn initialize(&mut self) -> Result<()> {
        let mut providers = self.providers.write().await;

        for (name, provider) in providers.iter_mut() {
            provider.initialize(&self.config).await.map_err(|e| {
                FortressError::discovery(format!("Failed to initialize provider {}: {}", name, e))
            })?;
        }

        Ok(())
    }

    /// Discover nodes from all providers
    pub async fn discover_nodes(&self) -> Result<Vec<DiscoveredNode>> {
        let providers = self.providers.read().await;
        let mut all_nodes = Vec::new();

        for (name, provider) in providers.iter() {
            match provider.discover_nodes().await {
                Ok(nodes) => {
                    for mut node in nodes {
                        // Add provider tag
                        node.tags.insert("provider".to_string(), name.clone());
                        all_nodes.push(node);
                    }
                }
                Err(e) => {
                    tracing::warn!("Provider {} failed to discover nodes: {}", name, e);
                }
            }
        }

        // Update nodes cache
        let mut nodes_cache = self.nodes.write().await;
        nodes_cache.clear();
        for node in &all_nodes {
            nodes_cache.insert(node.id.clone(), node.clone());
        }

        // Update last discovery time
        let mut last_discovery = self.last_discovery.write().await;
        *last_discovery = Some(Utc::now());

        Ok(all_nodes)
    }

    /// Get cached nodes
    pub async fn get_cached_nodes(&self) -> Vec<DiscoveredNode> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }

    /// Get nodes by region
    pub async fn get_nodes_by_region(&self, region: &str) -> Vec<DiscoveredNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|node| node.region.as_ref().map_or(false, |r| r == region))
            .cloned()
            .collect()
    }

    /// Get healthy nodes only
    pub async fn get_healthy_nodes(&self) -> Vec<DiscoveredNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|node| node.health_status == NodeHealthStatus::Healthy)
            .cloned()
            .collect()
    }

    /// Check health of all nodes
    pub async fn check_all_nodes_health(&self) -> Result<HashMap<String, NodeHealthStatus>> {
        let providers = self.providers.read().await;
        let mut health_results = HashMap::new();
        let nodes = self.nodes.read().await;

        for node in nodes.values() {
            // Find the provider that discovered this node
            if let Some(provider_name) = node.tags.get("provider") {
                if let Some(provider) = providers.get(provider_name) {
                    match provider.check_node_health(node).await {
                        Ok(status) => {
                            health_results.insert(node.id.clone(), status);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to check health for node {}: {}", node.id, e);
                            health_results.insert(node.id.clone(), NodeHealthStatus::Unknown);
                        }
                    }
                }
            }
        }

        // Update node health in cache
        let mut nodes_cache = self.nodes.write().await;
        for (node_id, status) in &health_results {
            if let Some(node) = nodes_cache.get_mut(node_id) {
                node.health_status = status.clone();
                node.last_seen = Utc::now();
            }
        }

        Ok(health_results)
    }

    /// Get last discovery time
    pub async fn get_last_discovery_time(&self) -> Option<DateTime<Utc>> {
        let last_discovery = self.last_discovery.read().await;
        *last_discovery
    }

    /// Start background discovery task
    pub async fn start_background_discovery(&self) -> Result<tokio::task::JoinHandle<()>> {
        let providers = self.providers.clone();
        let nodes = self.nodes.clone();
        let last_discovery = self.last_discovery.clone();
        let poll_interval = std::time::Duration::from_secs(self.config.poll_interval_seconds);

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);

            loop {
                interval.tick().await;

                tracing::debug!("Running background node discovery");

                let mut all_nodes = Vec::new();
                let providers_guard = providers.read().await;

                for (name, provider) in providers_guard.iter() {
                    match provider.discover_nodes().await {
                        Ok(mut discovered_nodes) => {
                            for node in &mut discovered_nodes {
                                node.tags.insert("provider".to_string(), name.clone());
                            }
                            all_nodes.extend(discovered_nodes);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Background discovery failed for provider {}: {}",
                                name,
                                e
                            );
                        }
                    }
                }

                // Update nodes cache
                {
                    let mut nodes_cache = nodes.write().await;
                    nodes_cache.clear();
                    for node in all_nodes {
                        nodes_cache.insert(node.id.clone(), node);
                    }
                }

                // Update last discovery time
                {
                    let mut last_discovery_guard = last_discovery.write().await;
                    *last_discovery_guard = Some(Utc::now());
                }

                tracing::debug!(
                    "Background discovery completed, found {} nodes",
                    all_nodes.len()
                );
            }
        });

        Ok(task)
    }

    /// Shutdown the discovery manager
    pub async fn shutdown(&mut self) -> Result<()> {
        let mut providers = self.providers.write().await;

        for (name, provider) in providers.iter_mut() {
            if let Err(e) = provider.shutdown().await {
                tracing::warn!("Failed to shutdown provider {}: {}", name, e);
            }
        }

        Ok(())
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mechanism: DiscoveryMechanism::Static,
            settings: HashMap::new(),
            poll_interval_seconds: 30,
            timeout_seconds: 10,
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert!(matches!(config.mechanism, DiscoveryMechanism::Static));
        assert_eq!(config.poll_interval_seconds, 30);
        assert_eq!(config.timeout_seconds, 10);
        assert!(config.enabled);
    }

    #[test]
    fn test_node_health_status_equality() {
        assert_eq!(NodeHealthStatus::Healthy, NodeHealthStatus::Healthy);
        assert_ne!(NodeHealthStatus::Healthy, NodeHealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_discovery_manager_creation() {
        let config = DiscoveryConfig::default();
        let manager = DiscoveryManager::new(config);

        let nodes = manager.get_cached_nodes().await;
        assert!(nodes.is_empty());

        let last_discovery = manager.get_last_discovery_time().await;
        assert!(last_discovery.is_none());
    }
}
