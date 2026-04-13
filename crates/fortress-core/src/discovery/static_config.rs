//! Static Configuration Discovery Provider
//! 
//! This module provides static node configuration for Fortress clusters
//! where nodes are manually configured rather than dynamically discovered.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::error::{FortressError, Result};
use crate::discovery::{DiscoveryProvider, DiscoveredNode, NodeHealthStatus, DiscoveryConfig};

/// Static discovery provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticDiscoveryConfig {
    pub nodes: Vec<StaticNodeConfig>,
    pub health_check_enabled: bool,
    pub health_check_interval_seconds: u64,
    pub health_check_timeout_seconds: u64,
    pub health_check_path: Option<String>,
}

/// Static node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticNodeConfig {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub tags: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
    pub capabilities: Vec<String>,
    pub enabled: bool,
    pub weight: Option<u32>,
}

impl Default for StaticNodeConfig {
    fn default() -> Self {
        Self {
            id: "node-1".to_string(),
            address: "127.0.0.1".to_string(),
            port: 8080,
            region: None,
            zone: None,
            tags: HashMap::new(),
            metadata: HashMap::new(),
            capabilities: vec!["static".to_string()],
            enabled: true,
            weight: None,
        }
    }
}

impl Default for StaticDiscoveryConfig {
    fn default() -> Self {
        Self {
            nodes: vec![StaticNodeConfig::default()],
            health_check_enabled: true,
            health_check_interval_seconds: 30,
            health_check_timeout_seconds: 5,
            health_check_path: Some("/health".to_string()),
        }
    }
}

/// Static discovery provider
pub struct StaticDiscovery {
    config: StaticDiscoveryConfig,
    initialized: bool,
    last_health_check: Arc<tokio::sync::RwLock<HashMap<String, DateTime<Utc>>>>,
    health_status_cache: Arc<tokio::sync::RwLock<HashMap<String, NodeHealthStatus>>>,
}

impl StaticDiscovery {
    /// Create a new static discovery provider
    pub fn new(config: StaticDiscoveryConfig) -> Self {
        Self {
            config,
            initialized: false,
            last_health_check: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            health_status_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Convert static node config to discovered node
    fn static_node_to_discovered_node(&self, static_node: &StaticNodeConfig) -> Result<DiscoveredNode> {
        if !static_node.enabled {
            return Err(FortressError::discovery("Static node is disabled"));
        }

        let mut tags = static_node.tags.clone();
        tags.insert("discovery_type".to_string(), "static".to_string());
        tags.insert("static".to_string(), "true".to_string());

        if let Some(weight) = static_node.weight {
            tags.insert("weight".to_string(), weight.to_string());
        }

        let mut metadata = static_node.metadata.clone();
        metadata.insert("configured_at".to_string(), Utc::now().to_rfc3339());
        metadata.insert("static_config".to_string(), "true".to_string());

        Ok(DiscoveredNode {
            id: static_node.id.clone(),
            address: static_node.address.clone(),
            port: static_node.port,
            region: static_node.region.clone(),
            zone: static_node.zone.clone(),
            tags,
            metadata,
            last_seen: Utc::now(),
            health_status: NodeHealthStatus::Unknown,
            capabilities: static_node.capabilities.clone(),
        })
    }

    /// Perform health check on a node
    async fn perform_health_check(&self, node: &DiscoveredNode) -> Result<NodeHealthStatus> {
        if !self.config.health_check_enabled {
            return Ok(NodeHealthStatus::Unknown);
        }

        // Check if we should perform health check (rate limiting)
        let node_id = &node.id;
        {
            let last_checks = self.last_health_check.read().await;
            if let Some(last_check) = last_checks.get(node_id) {
                let elapsed = Utc::now() - *last_check;
                if elapsed.num_seconds() < self.config.health_check_interval_seconds as i64 {
                    // Return cached health status
                    let health_cache = self.health_status_cache.read().await;
                    return Ok(health_cache.get(node_id).cloned().unwrap_or(NodeHealthStatus::Unknown));
                }
            }
        }

        // Update last health check time
        {
            let mut last_checks = self.last_health_check.write().await;
            last_checks.insert(node_id.clone(), Utc::now());
        }

        // Perform HTTP health check
        let health_check_path = self.config.health_check_path.as_deref().unwrap_or("/health");
        let url = format!("http://{}:{}{}", node.address, node.port, health_check_path);

        let client = reqwest::Client::new();
        let timeout = std::time::Duration::from_secs(self.config.health_check_timeout_seconds);

        let health_status = match client.get(&url).timeout(timeout).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    NodeHealthStatus::Healthy
                } else if response.status().is_server_error() {
                    NodeHealthStatus::Unhealthy
                } else {
                    NodeHealthStatus::Degraded
                }
            }
            Err(e) => {
                tracing::debug!("Health check failed for {}: {}", node.id, e);
                NodeHealthStatus::Unhealthy
            }
        };

        // Cache health status
        {
            let mut health_cache = self.health_status_cache.write().await;
            health_cache.insert(node_id.clone(), health_status.clone());
        }

        Ok(health_status)
    }

    /// Get enabled nodes only
    fn get_enabled_nodes(&self) -> Vec<&StaticNodeConfig> {
        self.config.nodes.iter()
            .filter(|node| node.enabled)
            .collect()
    }

    /// Validate node configuration
    fn validate_node_config(&self, node: &StaticNodeConfig) -> Result<()> {
        if node.id.is_empty() {
            return Err(FortressError::discovery("Static node ID cannot be empty"));
        }

        if node.address.is_empty() {
            return Err(FortressError::discovery("Static node address cannot be empty"));
        }

        if node.port == 0 {
            return Err(FortressError::discovery("Static node port must be greater than 0"));
        }

        // Validate IP address format
        if let Err(_) = node.address.parse::<std::net::IpAddr>() {
            // If it's not a valid IP, check if it's a valid hostname
            if node.address.contains('.') || node.address.contains('-') {
                // Accept as hostname
            } else {
                return Err(FortressError::discovery("Invalid static node address format"));
            }
        }

        Ok(())
    }

    /// Load configuration from file
    async fn load_from_file(&mut self, file_path: &str) -> Result<()> {
        let content = tokio::fs::read_to_string(file_path)
            .await
            .map_err(|e| FortressError::discovery(format!("Failed to read static config file: {}", e)))?;

        let config: StaticDiscoveryConfig = serde_json::from_str(&content)
            .map_err(|e| FortressError::discovery(format!("Failed to parse static config file: {}", e)))?;

        self.config = config;
        Ok(())
    }

    /// Save configuration to file
    async fn save_to_file(&self, file_path: &str) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.config)
            .map_err(|e| FortressError::discovery(format!("Failed to serialize static config: {}", e)))?;

        tokio::fs::write(file_path, content)
            .await
            .map_err(|e| FortressError::discovery(format!("Failed to write static config file: {}", e)))?;

        Ok(())
    }

    /// Add a new node to the configuration
    pub async fn add_node(&mut self, node: StaticNodeConfig) -> Result<()> {
        self.validate_node_config(&node)?;

        // Check for duplicate ID
        if self.config.nodes.iter().any(|n| n.id == node.id) {
            return Err(FortressError::discovery(format!("Node with ID '{}' already exists", node.id)));
        }

        self.config.nodes.push(node);
        Ok(())
    }

    /// Remove a node from the configuration
    pub async fn remove_node(&mut self, node_id: &str) -> Result<bool> {
        let initial_len = self.config.nodes.len();
        self.config.nodes.retain(|node| node.id != node_id);
        Ok(self.config.nodes.len() < initial_len)
    }

    /// Update a node in the configuration
    pub async fn update_node(&mut self, node_id: &str, updated_node: StaticNodeConfig) -> Result<()> {
        self.validate_node_config(&updated_node)?;

        if updated_node.id != node_id {
            return Err(FortressError::discovery("Node ID cannot be changed during update"));
        }

        let index = self.config.nodes.iter()
            .position(|node| node.id == node_id)
            .ok_or_else(|| FortressError::discovery(format!("Node with ID '{}' not found", node_id)))?;

        self.config.nodes[index] = updated_node;
        Ok(())
    }

    /// Get node by ID
    pub async fn get_node(&self, node_id: &str) -> Option<&StaticNodeConfig> {
        self.config.nodes.iter().find(|node| node.id == node_id)
    }

    /// List all nodes
    pub async fn list_nodes(&self) -> &Vec<StaticNodeConfig> {
        &self.config.nodes
    }

    /// Get enabled nodes count
    pub async fn enabled_nodes_count(&self) -> usize {
        self.get_enabled_nodes().len()
    }

    /// Get total nodes count
    pub async fn total_nodes_count(&self) -> usize {
        self.config.nodes.len()
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for StaticDiscovery {
    fn name(&self) -> &str {
        "static"
    }

    async fn initialize(&mut self, config: &DiscoveryConfig) -> Result<()> {
        // Extract static-specific config
        let static_config: StaticDiscoveryConfig = serde_json::from_value(
            serde_json::to_value(&config.settings).unwrap_or_default()
        ).unwrap_or_default();

        self.config = static_config;

        // Validate all node configurations
        for node in &self.config.nodes {
            self.validate_node_config(node)?;
        }

        self.initialized = true;

        tracing::info!("Static discovery provider initialized with {} nodes ({} enabled)", 
                      self.config.nodes.len(), self.get_enabled_nodes().len());
        Ok(())
    }

    async fn discover_nodes(&self) -> Result<Vec<DiscoveredNode>> {
        if !self.initialized {
            return Err(FortressError::discovery("Static discovery provider not initialized"));
        }

        let mut nodes = Vec::new();
        let enabled_nodes = self.get_enabled_nodes();

        for static_node in enabled_nodes {
            match self.static_node_to_discovered_node(static_node) {
                Ok(node) => nodes.push(node),
                Err(e) => {
                    tracing::warn!("Failed to convert static node to discovered node: {}", e);
                }
            }
        }

        tracing::debug!("Static discovery found {} nodes", nodes.len());
        Ok(nodes)
    }

    async fn check_node_health(&self, node: &DiscoveredNode) -> Result<NodeHealthStatus> {
        if !self.initialized {
            return Err(FortressError::discovery("Static discovery provider not initialized"));
        }

        // Perform health check if enabled
        self.perform_health_check(node).await
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.initialized = false;
        
        // Clear caches
        {
            let mut last_checks = self.last_health_check.write().await;
            last_checks.clear();
        }
        {
            let mut health_cache = self.health_status_cache.write().await;
            health_cache.clear();
        }
        
        tracing::info!("Static discovery provider shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_config_default() {
        let config = StaticDiscoveryConfig::default();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].id, "node-1");
        assert_eq!(config.nodes[0].address, "127.0.0.1");
        assert_eq!(config.nodes[0].port, 8080);
        assert!(config.health_check_enabled);
        assert_eq!(config.health_check_interval_seconds, 30);
        assert_eq!(config.health_check_timeout_seconds, 5);
    }

    #[test]
    fn test_static_node_config_default() {
        let config = StaticNodeConfig::default();
        assert_eq!(config.id, "node-1");
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert!(config.enabled);
        assert_eq!(config.capabilities, vec!["static"]);
    }

    #[test]
    fn test_static_discovery_creation() {
        let config = StaticDiscoveryConfig::default();
        let discovery = StaticDiscovery::new(config);
        
        assert_eq!(discovery.name(), "static");
        assert!(!discovery.initialized);
    }

    #[test]
    fn test_validate_node_config() {
        let config = StaticDiscoveryConfig::default();
        let discovery = StaticDiscovery::new(config);

        // Valid config
        let valid_node = StaticNodeConfig {
            id: "test-node".to_string(),
            address: "192.168.1.100".to_string(),
            port: 8080,
            ..Default::default()
        };
        assert!(discovery.validate_node_config(&valid_node).is_ok());

        // Invalid config - empty ID
        let invalid_node = StaticNodeConfig {
            id: "".to_string(),
            address: "192.168.1.100".to_string(),
            port: 8080,
            ..Default::default()
        };
        assert!(discovery.validate_node_config(&invalid_node).is_err());

        // Invalid config - empty address
        let invalid_node = StaticNodeConfig {
            id: "test-node".to_string(),
            address: "".to_string(),
            port: 8080,
            ..Default::default()
        };
        assert!(discovery.validate_node_config(&invalid_node).is_err());

        // Invalid config - port 0
        let invalid_node = StaticNodeConfig {
            id: "test-node".to_string(),
            address: "192.168.1.100".to_string(),
            port: 0,
            ..Default::default()
        };
        assert!(discovery.validate_node_config(&invalid_node).is_err());
    }

    #[tokio::test]
    async fn test_static_node_to_discovered_node() {
        let config = StaticDiscoveryConfig::default();
        let discovery = StaticDiscovery::new(config);

        let static_node = StaticNodeConfig {
            id: "test-node".to_string(),
            address: "192.168.1.100".to_string(),
            port: 8080,
            region: Some("us-west-2".to_string()),
            zone: Some("us-west-2a".to_string()),
            capabilities: vec!["test".to_string(), "static".to_string()],
            weight: Some(10),
            ..Default::default()
        };

        let discovered_node = discovery.static_node_to_discovered_node(&static_node).unwrap();
        
        assert_eq!(discovered_node.id, "test-node");
        assert_eq!(discovered_node.address, "192.168.1.100");
        assert_eq!(discovered_node.port, 8080);
        assert_eq!(discovered_node.region, Some("us-west-2".to_string()));
        assert_eq!(discovered_node.zone, Some("us-west-2a".to_string()));
        assert_eq!(discovered_node.capabilities, vec!["test", "static"]);
        assert_eq!(discovered_node.tags.get("weight"), Some(&"10".to_string()));
        assert_eq!(discovered_node.tags.get("discovery_type"), Some(&"static".to_string()));
    }

    #[tokio::test]
    async fn test_add_node() {
        let config = StaticDiscoveryConfig::default();
        let mut discovery = StaticDiscovery::new(config);

        let new_node = StaticNodeConfig {
            id: "new-node".to_string(),
            address: "192.168.1.200".to_string(),
            port: 9090,
            ..Default::default()
        };

        assert!(discovery.add_node(new_node.clone()).await.is_ok());
        assert_eq!(discovery.config.nodes.len(), 2);

        // Test duplicate ID
        assert!(discovery.add_node(new_node).await.is_err());
        assert_eq!(discovery.config.nodes.len(), 2);
    }

    #[tokio::test]
    async fn test_remove_node() {
        let config = StaticDiscoveryConfig::default();
        let mut discovery = StaticDiscovery::new(config);

        let initial_count = discovery.config.nodes.len();
        
        // Remove existing node
        let removed = discovery.remove_node("node-1").await.unwrap();
        assert!(removed);
        assert_eq!(discovery.config.nodes.len(), initial_count - 1);

        // Remove non-existing node
        let removed = discovery.remove_node("non-existing").await.unwrap();
        assert!(!removed);
        assert_eq!(discovery.config.nodes.len(), initial_count - 1);
    }

    #[tokio::test]
    async fn test_enabled_nodes_count() {
        let mut config = StaticDiscoveryConfig::default();
        config.nodes.push(StaticNodeConfig {
            id: "disabled-node".to_string(),
            address: "192.168.1.200".to_string(),
            port: 9090,
            enabled: false,
            ..Default::default()
        });

        let discovery = StaticDiscovery::new(config);
        
        assert_eq!(discovery.total_nodes_count().await, 2);
        assert_eq!(discovery.enabled_nodes_count().await, 1);
    }
}
