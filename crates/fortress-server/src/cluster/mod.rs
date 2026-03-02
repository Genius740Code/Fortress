//! # Fortress Clustering Module
//!
//! This module provides distributed clustering capabilities for Fortress,
//! implementing high availability through consensus algorithms and data replication.
//!
//! ## Features
//!
//! - **Raft Consensus**: Leader election and log replication
//! - **Node Discovery**: Automatic cluster member detection
//! - **Data Replication**: Consistent data distribution across nodes
//! - **Failover**: Automatic leader failover and recovery
//! - **Cluster Management**: Monitoring and administrative tools

pub mod raft;
pub mod node;
pub mod discovery;
pub mod replication;
pub mod failover;
pub mod management;
pub mod network;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::cluster::raft::{RaftNode, RaftConfig, RaftRole};
    pub use crate::cluster::node::{ClusterNode, NodeStatus, NodeConfig};
    pub use crate::cluster::discovery::{NodeDiscovery, DiscoveryConfig};
    pub use crate::cluster::replication::{DataReplicator, ReplicationConfig};
    pub use crate::cluster::failover::{FailoverManager, FailoverConfig};
    pub use crate::cluster::management::ClusterManager;
    pub use crate::cluster::network::{NetworkManager, NetworkConfig};
    pub use crate::cluster::{ClusterMessage, ClusterError, ClusterResult};
}

/// Cluster-wide message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterMessage {
    /// Raft consensus messages
    Raft(raft::RaftMessage),
    /// Node discovery messages
    Discovery(discovery::DiscoveryMessage),
    /// Data replication messages
    Replication(replication::ReplicationMessage),
    /// Failover coordination messages
    Failover(failover::FailoverMessage),
    /// Cluster management messages
    Management(management::ManagementMessage),
    /// Heartbeat messages
    Heartbeat {
        node_id: Uuid,
        timestamp: DateTime<Utc>,
        term: u64,
    },
}

/// Cluster-wide error types
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("Network error: {0}")]
    Network(#[from] network::NetworkError),
    
    #[error("Raft consensus error: {0}")]
    Raft(#[from] raft::RaftError),
    
    #[error("Node discovery error: {0}")]
    Discovery(#[from] discovery::DiscoveryError),
    
    #[error("Data replication error: {0}")]
    Replication(#[from] replication::ReplicationError),
    
    #[error("Failover error: {0}")]
    Failover(#[from] failover::FailoverError),
    
    #[error("Cluster management error: {0}")]
    Management(#[from] management::ManagementError),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Node not found: {0}")]
    NodeNotFound(Uuid),
    
    #[error("Cluster is not ready")]
    ClusterNotReady,
    
    #[error("Leadership transfer failed: {0}")]
    LeadershipTransferFailed(String),
}

/// Result type for cluster operations
pub type ClusterResult<T> = Result<T, ClusterError>;

/// Cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Unique identifier for this node
    pub node_id: Uuid,
    
    /// Address this node listens on
    pub listen_addr: String,
    
    /// Initial cluster members (if joining existing cluster)
    pub join_addresses: Vec<String>,
    
    /// Raft configuration
    pub raft: RaftConfig,
    
    /// Node discovery configuration
    pub discovery: DiscoveryConfig,
    
    /// Data replication configuration
    pub replication: ReplicationConfig,
    
    /// Failover configuration
    pub failover: FailoverConfig,
    
    /// Network configuration
    pub network: NetworkConfig,
    
    /// Election timeout in milliseconds
    pub election_timeout_ms: u64,
    
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,
    
    /// Maximum number of nodes in cluster
    pub max_nodes: usize,
    
    /// Enable TLS for cluster communication
    pub enable_tls: bool,
    
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    
    /// TLS private key path
    pub tls_key_path: Option<String>,
    
    /// CA certificate path for verification
    pub tls_ca_path: Option<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: Uuid::new_v4(),
            listen_addr: "0.0.0.0:8081".to_string(),
            join_addresses: Vec::new(),
            raft: RaftConfig::default(),
            discovery: DiscoveryConfig::default(),
            replication: ReplicationConfig::default(),
            failover: FailoverConfig::default(),
            network: NetworkConfig::default(),
            election_timeout_ms: 5000,
            heartbeat_interval_ms: 1000,
            max_nodes: 7,
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
        }
    }
}

/// Import specific configurations
use crate::cluster::raft::RaftConfig;
use crate::cluster::discovery::DiscoveryConfig;
use crate::cluster::replication::ReplicationConfig;
use crate::cluster::failover::FailoverConfig;
use crate::cluster::network::NetworkConfig;
use crate::cluster::management::{ManagementConfig, ClusterConfiguration};
