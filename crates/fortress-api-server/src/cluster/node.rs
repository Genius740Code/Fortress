//! # Cluster Node Module
//!
//! This module defines the cluster node structure and basic node operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Cluster node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Unique node identifier
    pub node_id: Uuid,
    /// Node name
    pub node_name: String,
    /// Node address
    pub address: String,
    /// Node port
    pub port: u16,
    /// Node role
    pub role: NodeRole,
    /// Node capabilities
    pub capabilities: Vec<String>,
    /// Node metadata
    pub metadata: HashMap<String, String>,
}

/// Node role in the cluster
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    /// Leader node
    Leader,
    /// Follower node
    Follower,
    /// Backup node
    Backup,
    /// Observer node (read-only)
    Observer,
}

/// Node status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is online and healthy
    Online,
    /// Node is offline
    Offline,
    /// Node is joining the cluster
    Joining,
    /// Node is leaving the cluster
    Leaving,
    /// Node is in maintenance mode
    Maintenance,
    /// Node is degraded (partial functionality)
    Degraded,
}

/// Cluster node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Node configuration
    pub config: NodeConfig,
    /// Current node status
    pub status: NodeStatus,
    /// Node health metrics
    pub health_metrics: NodeHealthMetrics,
    /// Last heartbeat timestamp
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    /// Node uptime in seconds
    pub uptime_secs: u64,
    /// Current term (for Raft)
    pub current_term: u64,
    /// Node version
    pub version: String,
}

/// Node health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealthMetrics {
    /// CPU usage percentage (0-100)
    pub cpu_usage: f64,
    /// Memory usage percentage (0-100)
    pub memory_usage: f64,
    /// Disk usage percentage (0-100)
    pub disk_usage: f64,
    /// Network I/O in bytes per second
    pub network_io: f64,
    /// Load average
    pub load_average: f64,
    /// Number of active connections
    pub active_connections: u32,
    /// Response time in milliseconds
    pub response_time_ms: f64,
    /// Error rate percentage (0-100)
    pub error_rate: f64,
}

impl Default for NodeHealthMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
            network_io: 0.0,
            load_average: 0.0,
            active_connections: 0,
            response_time_ms: 0.0,
            error_rate: 0.0,
        }
    }
}

impl ClusterNode {
    /// Create a new cluster node
    pub fn new(config: NodeConfig) -> Self {
        Self {
            config,
            status: NodeStatus::Joining,
            health_metrics: NodeHealthMetrics::default(),
            last_heartbeat: chrono::Utc::now(),
            uptime_secs: 0,
            current_term: 0,
            version: "0.1.0".to_string(),
        }
    }

    /// Get node ID
    pub fn node_id(&self) -> Uuid {
        self.config.node_id
    }

    /// Get node address
    pub fn address(&self) -> String {
        format!("{}:{}", self.config.address, self.config.port)
    }

    /// Check if node is healthy
    pub fn is_healthy(&self) -> bool {
        self.status == NodeStatus::Online && 
        self.health_metrics.cpu_usage < 90.0 &&
        self.health_metrics.memory_usage < 90.0 &&
        self.health_metrics.disk_usage < 95.0 &&
        self.health_metrics.error_rate < 5.0
    }

    /// Update node status
    pub fn update_status(&mut self, status: NodeStatus) {
        self.status = status;
        self.last_heartbeat = chrono::Utc::now();
    }

    /// Update health metrics
    pub fn update_health_metrics(&mut self, metrics: NodeHealthMetrics) {
        self.health_metrics = metrics;
        self.last_heartbeat = chrono::Utc::now();
    }

    /// Update heartbeat
    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = chrono::Utc::now();
        self.uptime_secs += 1;
    }

    /// Check if node is leader
    pub fn is_leader(&self) -> bool {
        self.config.role == NodeRole::Leader
    }

    /// Set node as leader
    pub fn set_as_leader(&mut self) {
        self.config.role = NodeRole::Leader;
        self.status = NodeStatus::Online;
    }

    /// Set node as follower
    pub fn set_as_follower(&mut self) {
        self.config.role = NodeRole::Follower;
        self.status = NodeStatus::Online;
    }

    /// Get node capabilities
    pub fn has_capability(&self, capability: &str) -> bool {
        self.config.capabilities.contains(&capability.to_string())
    }

    /// Add capability to node
    pub fn add_capability(&mut self, capability: String) {
        if !self.has_capability(&capability) {
            self.config.capabilities.push(capability);
        }
    }

    /// Remove capability from node
    pub fn remove_capability(&mut self, capability: &str) {
        self.config.capabilities.retain(|c| c != capability);
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.config.metadata.get(key)
    }

    /// Set metadata value
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.config.metadata.insert(key, value);
    }

    /// Remove metadata value
    pub fn remove_metadata(&mut self, key: &str) {
        self.config.metadata.remove(key);
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: Uuid::new_v4(),
            node_name: "fortress-node".to_string(),
            address: "127.0.0.1".to_string(),
            port: 8081,
            role: NodeRole::Follower,
            capabilities: vec![
                "storage".to_string(),
                "replication".to_string(),
                "encryption".to_string(),
            ],
            metadata: HashMap::new(),
        }
    }
}
