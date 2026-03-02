//! # Node Discovery Module
//!
//! This module handles automatic discovery and registration of cluster nodes,
//! enabling dynamic cluster formation and maintenance.

use crate::cluster::{ClusterError, ClusterResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Node discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery interval in seconds
    pub discovery_interval_secs: u64,
    /// Node timeout in seconds
    pub node_timeout_secs: u64,
    /// Maximum number of discovery attempts
    pub max_discovery_attempts: u32,
    /// Enable multicast discovery
    pub enable_multicast: bool,
    /// Multicast address
    pub multicast_address: String,
    /// Multicast port
    pub multicast_port: u16,
    /// Enable DNS-based discovery
    pub enable_dns_discovery: bool,
    /// DNS domain for cluster nodes
    pub dns_domain: Option<String>,
    /// Enable static seed nodes
    pub enable_static_seeds: bool,
    /// Static seed node addresses
    pub static_seed_nodes: Vec<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            discovery_interval_secs: 30,
            node_timeout_secs: 90,
            max_discovery_attempts: 3,
            enable_multicast: true,
            multicast_address: "239.255.0.1".to_string(),
            multicast_port: 8082,
            enable_dns_discovery: false,
            dns_domain: None,
            enable_static_seeds: true,
            static_seed_nodes: Vec::new(),
        }
    }
}

/// Node information for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Unique node identifier
    pub node_id: Uuid,
    /// Node address
    pub address: String,
    /// Node port
    pub port: u16,
    /// Node role in cluster
    pub role: String,
    /// Node capabilities
    pub capabilities: Vec<String>,
    /// Last seen timestamp
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Node metadata
    pub metadata: HashMap<String, String>,
}

/// Discovery message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    /// Node announcement
    NodeAnnouncement {
        node_info: NodeInfo,
    },
    
    /// Node discovery request
    DiscoveryRequest {
        requester_id: Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    
    /// Node discovery response
    DiscoveryResponse {
        requester_id: Uuid,
        known_nodes: Vec<NodeInfo>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    
    /// Node leave notification
    NodeLeave {
        node_id: Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
        reason: String,
    },
    
    /// Heartbeat message
    Heartbeat {
        node_id: Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
        term: u64,
    },
}

/// Discovery-specific errors
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("Network discovery failed: {0}")]
    NetworkDiscoveryFailed(String),
    
    #[error("DNS discovery failed: {0}")]
    DnsDiscoveryFailed(String),
    
    #[error("Invalid node address: {0}")]
    InvalidNodeAddress(String),
    
    #[error("Node already exists: {0}")]
    NodeAlreadyExists(Uuid),
    
    #[error("Node not found: {0}")]
    NodeNotFound(Uuid),
    
    #[error("Discovery timeout")]
    DiscoveryTimeout,
    
    #[error("Multicast error: {0}")]
    MulticastError(String),
}

/// Node discovery manager
pub struct NodeDiscovery {
    /// This node's information
    local_node_info: NodeInfo,
    /// Configuration
    config: DiscoveryConfig,
    /// Known nodes
    known_nodes: Arc<RwLock<HashMap<Uuid, NodeInfo>>>,
    /// Discovery callbacks
    callbacks: Arc<Mutex<Vec<Box<dyn NodeDiscoveryCallback + Send + Sync>>>>,
    /// Network sender
    network_sender: Arc<Mutex<dyn DiscoveryNetworkSender + Send + Sync>>,
}

/// Callback trait for node discovery events
#[async_trait::async_trait]
pub trait NodeDiscoveryCallback {
    async fn on_node_joined(&self, node_info: &NodeInfo);
    async fn on_node_left(&self, node_id: Uuid, reason: &str);
    async fn on_node_updated(&self, node_info: &NodeInfo);
}

/// Trait for network discovery operations
#[async_trait::async_trait]
pub trait DiscoveryNetworkSender {
    async fn send_discovery_message(&self, target: &str, message: DiscoveryMessage) -> ClusterResult<()>;
    async fn broadcast_discovery_message(&self, message: DiscoveryMessage) -> ClusterResult<()>;
    async fn receive_discovery_messages(&self) -> Vec<(String, DiscoveryMessage)>;
}

impl NodeDiscovery {
    /// Create a new node discovery manager
    pub fn new(
        local_node_info: NodeInfo,
        config: DiscoveryConfig,
        network_sender: Arc<Mutex<dyn DiscoveryNetworkSender + Send + Sync>>,
    ) -> Self {
        Self {
            local_node_info,
            config,
            known_nodes: Arc::new(RwLock::new(HashMap::new())),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            network_sender,
        }
    }

    /// Start the discovery service
    pub async fn start(&self) -> ClusterResult<()> {
        info!("Starting node discovery for {}", self.local_node_info.node_id);
        
        // Start discovery loop
        let discovery = self.clone();
        tokio::spawn(async move {
            discovery.discovery_loop().await;
        });

        // Start node cleanup loop
        let discovery = self.clone();
        tokio::spawn(async move {
            discovery.cleanup_loop().await;
        });

        // Initial discovery
        self.perform_initial_discovery().await?;

        Ok(())
    }

    /// Main discovery loop
    async fn discovery_loop(&self) {
        let mut interval = interval(Duration::from_secs(self.config.discovery_interval_secs));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.perform_discovery().await {
                error!("Discovery failed: {}", e);
            }
        }
    }

    /// Node cleanup loop
    async fn cleanup_loop(&self) {
        let mut interval = interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.cleanup_stale_nodes().await {
                error!("Node cleanup failed: {}", e);
            }
        }
    }

    /// Perform initial discovery
    async fn perform_initial_discovery(&self) -> ClusterResult<()> {
        info!("Performing initial node discovery");
        
        // Try static seed nodes first
        if self.config.enable_static_seeds {
            self.discover_static_seeds().await?;
        }

        // Try DNS discovery
        if self.config.enable_dns_discovery {
            self.discover_dns_nodes().await?;
        }

        // Try multicast discovery
        if self.config.enable_multicast {
            self.discover_multicast_nodes().await?;
        }

        Ok(())
    }

    /// Perform regular discovery
    async fn perform_discovery(&self) -> ClusterResult<()> {
        // Send discovery request
        let request = DiscoveryMessage::DiscoveryRequest {
            requester_id: self.local_node_info.node_id,
            timestamp: chrono::Utc::now(),
        };

        let sender = self.network_sender.lock().await;
        sender.broadcast_discovery_message(request).await?;

        Ok(())
    }

    /// Discover static seed nodes
    async fn discover_static_seeds(&self) -> ClusterResult<()> {
        info!("Discovering static seed nodes");
        
        for seed_address in &self.config.static_seed_nodes {
            let request = DiscoveryMessage::DiscoveryRequest {
                requester_id: self.local_node_info.node_id,
                timestamp: chrono::Utc::now(),
            };

            let sender = self.network_sender.lock().await;
            if let Err(e) = sender.send_discovery_message(seed_address, request).await {
                warn!("Failed to contact seed node {}: {}", seed_address, e);
            }
        }

        Ok(())
    }

    /// Discover nodes via DNS
    async fn discover_dns_nodes(&self) -> ClusterResult<()> {
        if let Some(domain) = &self.config.dns_domain {
            info!("Discovering nodes via DNS domain: {}", domain);
            
            // DNS SRV record lookup would go here
            // For now, this is a placeholder
            debug!("DNS discovery not yet implemented");
        }

        Ok(())
    }

    /// Discover nodes via multicast
    async fn discover_multicast_nodes(&self) -> ClusterResult<()> {
        info!("Discovering nodes via multicast");
        
        let announcement = DiscoveryMessage::NodeAnnouncement {
            node_info: self.local_node_info.clone(),
        };

        let multicast_address = format!("{}:{}", self.config.multicast_address, self.config.multicast_port);
        let sender = self.network_sender.lock().await;
        
        if let Err(e) = sender.send_discovery_message(&multicast_address, announcement).await {
            warn!("Failed to send multicast announcement: {}", e);
        }

        Ok(())
    }

    /// Clean up stale nodes
    async fn cleanup_stale_nodes(&self) -> ClusterResult<()> {
        let now = chrono::Utc::now();
        let timeout_duration = chrono::Duration::seconds(self.config.node_timeout_secs as i64);
        
        let mut nodes_to_remove = Vec::new();
        {
            let known_nodes = self.known_nodes.read().await;
            for (node_id, node_info) in known_nodes.iter() {
                if now.signed_duration_since(node_info.last_seen) > timeout_duration {
                    nodes_to_remove.push(*node_id);
                }
            }
        }

        for node_id in nodes_to_remove {
            self.remove_node(node_id, "timeout").await?;
        }

        Ok(())
    }

    /// Handle incoming discovery message
    pub async fn handle_message(&self, source: &str, message: DiscoveryMessage) -> ClusterResult<()> {
        match message {
            DiscoveryMessage::NodeAnnouncement { node_info } => {
                self.handle_node_announcement(node_info).await?;
            }
            DiscoveryMessage::DiscoveryRequest { requester_id, timestamp } => {
                self.handle_discovery_request(source, requester_id, timestamp).await?;
            }
            DiscoveryMessage::DiscoveryResponse { requester_id, known_nodes, timestamp } => {
                self.handle_discovery_response(requester_id, known_nodes, timestamp).await?;
            }
            DiscoveryMessage::NodeLeave { node_id, timestamp: _, reason } => {
                self.handle_node_leave(node_id, &reason).await?;
            }
            DiscoveryMessage::Heartbeat { node_id, timestamp, term: _ } => {
                self.handle_heartbeat(node_id, timestamp).await?;
            }
        }

        Ok(())
    }

    /// Handle node announcement
    async fn handle_node_announcement(&self, node_info: NodeInfo) -> ClusterResult<()> {
        let node_id = node_info.node_id;
        
        // Skip if it's our own announcement
        if node_id == self.local_node_info.node_id {
            return Ok(());
        }

        let mut known_nodes = self.known_nodes.write().await;
        
        if let Some(existing_info) = known_nodes.get_mut(&node_id) {
            // Update existing node
            if existing_info.last_seen < node_info.last_seen {
                *existing_info = node_info.clone();
                drop(known_nodes);
                
                // Notify callbacks
                let callbacks = self.callbacks.lock().await;
                for callback in callbacks.iter() {
                    callback.on_node_updated(&node_info).await;
                }
            }
        } else {
            // Add new node
            known_nodes.insert(node_id, node_info.clone());
            drop(known_nodes);
            
            info!("Discovered new node: {}", node_id);
            
            // Notify callbacks
            let callbacks = self.callbacks.lock().await;
            for callback in callbacks.iter() {
                callback.on_node_joined(&node_info).await;
            }
        }

        Ok(())
    }

    /// Handle discovery request
    async fn handle_discovery_request(&self, source: &str, requester_id: Uuid, timestamp: chrono::DateTime<chrono::Utc>) -> ClusterResult<()> {
        if requester_id == self.local_node_info.node_id {
            return Ok(());
        }

        let known_nodes = self.known_nodes.read().await;
        let nodes: Vec<NodeInfo> = known_nodes.values().cloned().collect();
        drop(known_nodes);

        let response = DiscoveryMessage::DiscoveryResponse {
            requester_id,
            known_nodes: nodes,
            timestamp,
        };

        let sender = self.network_sender.lock().await;
        sender.send_discovery_message(source, response).await?;

        Ok(())
    }

    /// Handle discovery response
    async fn handle_discovery_response(&self, requester_id: Uuid, known_nodes: Vec<NodeInfo>, timestamp: chrono::DateTime<chrono::Utc>) -> ClusterResult<()> {
        if requester_id != self.local_node_info.node_id {
            return Ok(());
        }

        for node_info in known_nodes {
            self.handle_node_announcement(node_info).await?;
        }

        Ok(())
    }

    /// Handle node leave
    async fn handle_node_leave(&self, node_id: Uuid, reason: &str) -> ClusterResult<()> {
        self.remove_node(node_id, reason).await
    }

    /// Handle heartbeat
    async fn handle_heartbeat(&self, node_id: Uuid, timestamp: chrono::DateTime<chrono::Utc>) -> ClusterResult<()> {
        let mut known_nodes = self.known_nodes.write().await;
        
        if let Some(node_info) = known_nodes.get_mut(&node_id) {
            node_info.last_seen = timestamp;
        }

        Ok(())
    }

    /// Remove a node from the known nodes
    async fn remove_node(&self, node_id: Uuid, reason: &str) -> ClusterResult<()> {
        let mut known_nodes = self.known_nodes.write().await;
        
        if known_nodes.remove(&node_id).is_some() {
            info!("Node {} left: {}", node_id, reason);
            drop(known_nodes);
            
            // Notify callbacks
            let callbacks = self.callbacks.lock().await;
            for callback in callbacks.iter() {
                callback.on_node_left(node_id, reason).await;
            }
        }

        Ok(())
    }

    /// Add a node discovery callback
    pub async fn add_callback(&self, callback: Box<dyn NodeDiscoveryCallback + Send + Sync>) {
        let mut callbacks = self.callbacks.lock().await;
        callbacks.push(callback);
    }

    /// Get all known nodes
    pub async fn get_known_nodes(&self) -> Vec<NodeInfo> {
        self.known_nodes.read().await.values().cloned().collect()
    }

    /// Get specific node information
    pub async fn get_node_info(&self, node_id: Uuid) -> Option<NodeInfo> {
        self.known_nodes.read().await.get(&node_id).cloned()
    }

    /// Send node leave notification
    pub async fn send_leave_notification(&self, reason: &str) -> ClusterResult<()> {
        let message = DiscoveryMessage::NodeLeave {
            node_id: self.local_node_info.node_id,
            timestamp: chrono::Utc::now(),
            reason: reason.to_string(),
        };

        let sender = self.network_sender.lock().await;
        sender.broadcast_discovery_message(message).await?;

        Ok(())
    }
}

impl Clone for NodeDiscovery {
    fn clone(&self) -> Self {
        Self {
            local_node_info: self.local_node_info.clone(),
            config: self.config.clone(),
            known_nodes: Arc::clone(&self.known_nodes),
            callbacks: Arc::clone(&self.callbacks),
            network_sender: Arc::clone(&self.network_sender),
        }
    }
}
