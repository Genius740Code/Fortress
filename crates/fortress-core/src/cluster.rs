//! Distributed clustering for Fortress
//!
//! This module provides distributed clustering capabilities including:
//! - Node discovery and membership
//! - Distributed consensus using Raft
//! - Data replication across nodes
//! - Cluster health monitoring
//! - Failover and recovery

use super::raft::{RaftEngine, RequestVoteRequest};
use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

/// Cluster node identifier
pub type NodeId = Uuid;

/// Cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Unique identifier for this node
    pub node_id: NodeId,
    /// Network address for this node
    pub bind_address: SocketAddr,
    /// Addresses of known cluster members
    pub seed_nodes: Vec<SocketAddr>,
    /// Heartbeat interval
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: Duration,
    /// Election timeout
    #[serde(default = "default_election_timeout")]
    pub election_timeout: Duration,
    /// Replication factor
    #[serde(default = "default_replication_factor")]
    pub replication_factor: usize,
    /// Minimum nodes for quorum
    pub min_nodes: usize,
}

fn default_heartbeat_interval() -> Duration {
    Duration::from_millis(500)
}

fn default_election_timeout() -> Duration {
    Duration::from_millis(5000)
}

fn default_replication_factor() -> usize {
    3
}

/// Node state in the cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeState {
    /// Node is following a leader
    Follower {
        /// Current leader
        leader: Option<NodeId>,
        /// Term number
        term: u64,
    },
    /// Node is candidate for leadership
    Candidate {
        /// Election term
        term: u64,
        /// Votes received
        votes_received: usize,
        /// Total votes needed
        votes_needed: usize,
    },
    /// Node is the cluster leader
    Leader {
        /// Leadership term
        term: u64,
    },
}

/// Cluster node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Unique node identifier
    pub id: NodeId,
    /// Network address
    pub address: SocketAddr,
    /// Current state
    pub state: NodeState,
    /// Last heartbeat timestamp (Unix timestamp in milliseconds)
    pub last_heartbeat: u64,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Current load metrics
    pub load_metrics: LoadMetrics,
}

/// Node capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Can store encrypted data
    pub storage: bool,
    /// Can perform encryption operations
    pub encryption: bool,
    /// Can serve as cluster leader
    pub leadership: bool,
    /// Supported encryption algorithms
    pub algorithms: Vec<String>,
}

impl Default for NodeCapabilities {
    fn default() -> Self {
        Self {
            storage: true,
            encryption: true,
            leadership: true,
            algorithms: vec!["aegis256".to_string(), "chacha20".to_string(), "aes256gcm".to_string()],
        }
    }
}

/// Node load metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoadMetrics {
    /// CPU usage percentage (0-100)
    pub cpu_usage: f64,
    /// Memory usage percentage (0-100)
    pub memory_usage: f64,
    /// Active connections
    pub active_connections: usize,
    /// Operations per second
    pub ops_per_second: f64,
    /// Storage used in bytes
    pub storage_used: u64,
    /// Network I/O bytes per second
    pub network_io: u64,
}

/// Raft log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Entry index in the log
    pub index: u64,
    /// Term number
    pub term: u64,
    /// Command to execute
    pub command: ClusterCommand,
    /// Timestamp (Unix timestamp in milliseconds)
    pub timestamp: u64,
}

/// Cluster commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterCommand {
    /// Add a new node to the cluster
    AddNode { 
        /// Node to add
        node: ClusterNode 
    },
    /// Remove a node from the cluster
    RemoveNode { 
        /// Node ID to remove
        node_id: NodeId 
    },
    /// Replicate data to nodes
    ReplicateData {
        /// Data key
        key: String,
        /// Data payload
        data: Vec<u8>,
        /// Target nodes
        nodes: Vec<NodeId>,
    },
    /// Update cluster configuration
    UpdateConfig { 
        /// New configuration
        config: ClusterConfig 
    },
    /// Heartbeat message
    Heartbeat { 
        /// Sender node ID
        from: NodeId, 
        /// Current term
        term: u64 
    },
    /// Vote request
    RequestVote {
        /// Candidate requesting vote
        candidate_id: NodeId,
        /// Election term
        term: u64,
        /// Last log index
        last_log_index: u64,
        /// Last log term
        last_log_term: u64,
    },
    /// Vote response
    VoteResponse {
        /// Voting node ID
        voter_id: NodeId,
        /// Response term
        term: u64,
        /// Vote granted
        vote_granted: bool,
    },
}

/// Cluster manager
pub struct ClusterManager {
    /// Cluster configuration
    pub config: ClusterConfig,
    /// Current node information
    pub local_node: ClusterNode,
    /// Cluster members
    members: RwLock<HashMap<NodeId, ClusterNode>>,
    /// Raft consensus engine
    raft_engine: RaftEngine,
    /// Quorum manager
    quorum_manager: RwLock<QuorumManager>,
    /// Communication channels
    channels: ClusterChannels,
}

/// Communication channels for cluster
pub struct ClusterChannels {
    /// Incoming messages
    pub incoming: mpsc::UnboundedReceiver<ClusterCommand>,
    /// Outgoing messages
    pub outgoing: mpsc::UnboundedSender<(NodeId, ClusterCommand)>,
}

impl ClusterManager {
    /// Create a new cluster manager
    pub fn new(config: ClusterConfig) -> Result<Self> {
        let local_node = ClusterNode {
            id: config.node_id,
            address: config.bind_address,
            state: NodeState::Follower { leader: None, term: 0 },
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis() as u64,
            capabilities: NodeCapabilities::default(),
            load_metrics: LoadMetrics::default(),
        };

        let (_tx_in, rx_in) = mpsc::unbounded_channel();
        let (tx_out, _rx_out) = mpsc::unbounded_channel();

        let channels = ClusterChannels {
            incoming: rx_in,
            outgoing: tx_out,
        };

        let mut members = HashMap::new();
        members.insert(config.node_id, local_node.clone());
        
        // Create cluster members map for Raft engine
        let mut raft_members = HashMap::new();
        for (id, node) in &members {
            raft_members.insert(*id, node.address.to_string());
        }
        
        // Create Raft engine
        let raft_engine = RaftEngine::new(
            config.node_id,
            config.election_timeout,
            raft_members,
        );

        Ok(Self {
            config,
            local_node,
            members: RwLock::new(members.clone()),
            raft_engine,
            quorum_manager: RwLock::new(QuorumManager::new(members.len())),
            channels,
        })
    }

    /// Start the cluster manager
    pub async fn start(&mut self) -> Result<()> {
        // Start Raft engine
        self.raft_engine.start().await?;
        
        // Start node discovery
        self.discover_nodes().await?;

        // Start heartbeat loop
        self.start_heartbeat_loop().await?;

        // Start message processing
        self.start_message_processing().await?;

        Ok(())
    }

    /// Discover other nodes in the cluster
    async fn discover_nodes(&self) -> Result<()> {
        for seed_addr in &self.config.seed_nodes.clone() {
            if let Err(e) = self.contact_seed_node(*seed_addr).await {
                tracing::warn!("Failed to contact seed node {}: {}", seed_addr, e);
            }
        }
        Ok(())
    }

    /// Contact a seed node to join the cluster
    async fn contact_seed_node(&self, addr: SocketAddr) -> Result<()> {
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use serde_json;
        
        tracing::info!("Contacting seed node at {}", addr);
        
        // Attempt to connect to seed node
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                tracing::warn!("Failed to connect to seed node {}: {}", addr, e);
                return Err(FortressError::cluster(
                    format!("Failed to connect to seed node {}: {}", addr, e),
                    None,
                ));
            }
            Err(_) => {
                tracing::warn!("Timeout connecting to seed node {}", addr);
                return Err(FortressError::cluster(
                    format!("Timeout connecting to seed node {}", addr),
                    None,
                ));
            }
        };
        
        // Send join request
        let join_request = serde_json::json!({
            "type": "join_request",
            "node_id": self.local_node.id.to_string(),
            "address": self.local_node.address.to_string(),
            "capabilities": self.local_node.capabilities,
        });
        
        let request_bytes = serde_json::to_vec(&join_request)
            .map_err(|e| FortressError::cluster(
                format!("Failed to serialize join request: {}", e),
                None,
            ))?;
        
        // Send length prefix followed by data
        let length = request_bytes.len() as u32;
        if let Err(e) = stream.write_all(&length.to_le_bytes()).await {
            tracing::warn!("Failed to send length to seed node {}: {}", addr, e);
            return Err(FortressError::cluster(
                format!("Failed to send length to seed node {}: {}", addr, e),
                None,
            ));
        }
        
        if let Err(e) = stream.write_all(&request_bytes).await {
            tracing::warn!("Failed to send join request to seed node {}: {}", addr, e);
            return Err(FortressError::cluster(
                format!("Failed to send join request to seed node {}: {}", addr, e),
                None,
            ));
        }
        
        // Read response
        let mut length_bytes = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut length_bytes).await {
            tracing::warn!("Failed to read response length from seed node {}: {}", addr, e);
            return Err(FortressError::cluster(
                format!("Failed to read response length from seed node {}: {}", addr, e),
                None,
            ));
        }
        
        let response_length = u32::from_le_bytes(length_bytes) as usize;
        let mut response_bytes = vec![0u8; response_length];
        
        if let Err(e) = stream.read_exact(&mut response_bytes).await {
            tracing::warn!("Failed to read response from seed node {}: {}", addr, e);
            return Err(FortressError::cluster(
                format!("Failed to read response from seed node {}: {}", addr, e),
                None,
            ));
        }
        
        // Parse response
        let response: serde_json::Value = serde_json::from_slice(&response_bytes)
            .map_err(|e| FortressError::cluster(
                format!("Failed to parse response from seed node {}: {}", addr, e),
                None,
            ))?;
        
        if let Some(success) = response.get("success").and_then(|v| v.as_bool()) {
            if success {
                tracing::info!("Successfully joined cluster via seed node {}", addr);
                
                // Add seed node to members list
                let seed_node_id = response.get("node_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .unwrap_or_else(|| Uuid::new_v4());
                
                let seed_node = ClusterNode {
                    id: seed_node_id,
                    address: addr,
                    state: NodeState::Follower { leader: None, term: 0 },
                    last_heartbeat: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_millis() as u64,
                    capabilities: NodeCapabilities::default(),
                    load_metrics: LoadMetrics::default(),
                };
                
                self.members.write().await.insert(seed_node_id, seed_node);
                Ok(())
            } else {
                let error_msg = response.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                Err(FortressError::cluster(
                    format!("Seed node {} rejected join request: {}", addr, error_msg),
                    None,
                ))
            }
        } else {
            Err(FortressError::cluster(
                format!("Invalid response from seed node {}", addr),
                None,
            ))
        }
    }

    /// Start the heartbeat loop
    async fn start_heartbeat_loop(&self) -> Result<()> {
        let interval = self.config.heartbeat_interval;
        let local_node_id = self.local_node.id;
        let _outgoing_tx = self.channels.outgoing.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            
            loop {
                ticker.tick().await;
                
                // Send heartbeat to all cluster members
                let _heartbeat = ClusterCommand::Heartbeat {
                    from: local_node_id,
                    term: 0, // This would be updated based on current term
                };
                
                // In a real implementation, we'd get the list of members and send to each
                // For now, we'll just log that we sent a heartbeat
                tracing::debug!("Sending heartbeat from {} to cluster members", local_node_id);
                
                // Note: In a full implementation, we would:
                // 1. Get current term from Raft engine
                // 2. Get list of cluster members
                // 3. Send heartbeat to each member via network
                // 4. Handle any network errors appropriately
            }
        });

        Ok(())
    }

    /// Start message processing loop
    async fn start_message_processing(&mut self) -> Result<()> {
        loop {
            match self.channels.incoming.recv().await {
                Some(command) => {
                    if let Err(e) = self.handle_cluster_command(command).await {
                        tracing::error!("Error handling cluster command: {}", e);
                    }
                }
                None => {
                    tracing::info!("Message processing channel closed");
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Handle incoming cluster command
    async fn handle_cluster_command(&self, command: ClusterCommand) -> Result<()> {
        match command {
            ClusterCommand::Heartbeat { from, term } => {
                self.handle_heartbeat(from, term).await?;
            }
            ClusterCommand::RequestVote { candidate_id, term, last_log_index, last_log_term } => {
                self.handle_vote_request(candidate_id, term, last_log_index, last_log_term).await?;
            }
            ClusterCommand::VoteResponse { voter_id, term, vote_granted } => {
                self.handle_vote_response(voter_id, term, vote_granted).await?;
            }
            ClusterCommand::AddNode { node } => {
                self.handle_add_node(node).await?;
            }
            ClusterCommand::RemoveNode { node_id } => {
                self.handle_remove_node(node_id).await?;
            }
            ClusterCommand::ReplicateData { key, data, nodes } => {
                self.handle_replication_request(key, data, nodes).await?;
            }
            ClusterCommand::UpdateConfig { config } => {
                self.handle_config_update(config).await?;
            }
        }
        Ok(())
    }

    /// Handle heartbeat message
    async fn handle_heartbeat(&self, from: NodeId, term: u64) -> Result<()> {
        let mut members = self.members.write().await;
        
        if let Some(node) = members.get_mut(&from) {
            node.last_heartbeat = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis() as u64;
            
            // Update node state if it's a leader
            if matches!(node.state, NodeState::Leader { .. }) {
                if let Some(local_node) = members.get_mut(&self.local_node.id) {
                    if let NodeState::Follower { leader, term: current_term } = &mut local_node.state {
                        *leader = Some(from);
                        *current_term = term.max(*current_term);
                    }
                }
            }
        }
        
        tracing::debug!("Received heartbeat from node {} in term {}", from, term);
        Ok(())
    }

    /// Handle vote request
    async fn handle_vote_request(&self, candidate_id: NodeId, term: u64, last_log_index: u64, last_log_term: u64) -> Result<()> {
        let request = RequestVoteRequest {
            term,
            candidate_id,
            last_log_index,
            last_log_term,
        };
        
        let response = self.raft_engine.handle_request_vote(request).await?;
        
        // Send vote response
        let cluster_response = ClusterCommand::VoteResponse {
            voter_id: self.local_node.id,
            term: response.term,
            vote_granted: response.vote_granted,
        };
        
        if let Err(_) = self.channels.outgoing.send((candidate_id, cluster_response)) {
            tracing::warn!("Failed to send vote response to candidate {}", candidate_id);
        }
        
        tracing::info!("{} vote to candidate {} in term {}", if response.vote_granted { "Granted" } else { "Denied" }, candidate_id, term);
        Ok(())
    }

    /// Handle vote response
    async fn handle_vote_response(&self, voter_id: NodeId, term: u64, vote_granted: bool) -> Result<()> {
        // Update vote count in Raft engine
        let current_state = self.raft_engine.get_state().await;
        let current_term = self.raft_engine.get_term().await;
        
        if matches!(current_state, crate::raft::RaftState::Candidate) && term == current_term {
            if vote_granted {
                tracing::debug!("Received vote from {} in term {}", voter_id, term);
                
                // In a real implementation, we'd track votes and check for majority
                // For now, we'll become leader if we receive any vote (simplified)
                if let Err(e) = self.raft_engine.become_leader().await {
                    tracing::warn!("Failed to become leader: {}", e);
                } else {
                    tracing::info!("Node {} became leader in term {}", self.local_node.id, current_term);
                    
                    // Update local node state
                    let mut members = self.members.write().await;
                    if let Some(node) = members.get_mut(&self.local_node.id) {
                        node.state = NodeState::Leader { term: current_term };
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Handle add node request
    async fn handle_add_node(&self, node: ClusterNode) -> Result<()> {
        let mut members = self.members.write().await;
        members.insert(node.id, node.clone());
        
        // Update quorum manager
        let mut quorum_manager = self.quorum_manager.write().await;
        quorum_manager.update_cluster_size(members.len());
        
        tracing::info!("Added node {} to cluster, new size: {}", node.id, members.len());
        Ok(())
    }

    /// Handle remove node request
    async fn handle_remove_node(&self, node_id: NodeId) -> Result<()> {
        let mut members = self.members.write().await;
        members.remove(&node_id);
        
        // Update quorum manager
        let mut quorum_manager = self.quorum_manager.write().await;
        quorum_manager.update_cluster_size(members.len());
        
        tracing::info!("Removed node {} from cluster, new size: {}", node_id, members.len());
        Ok(())
    }

    /// Handle replication request
    async fn handle_replication_request(&self, key: String, _data: Vec<u8>, nodes: Vec<NodeId>) -> Result<()> {
        // Forward to replication manager
        tracing::debug!("Handling replication request for key {} to nodes {:?}", key, nodes);
        Ok(())
    }

    /// Handle config update
    async fn handle_config_update(&self, _config: ClusterConfig) -> Result<()> {
        tracing::info!("Updating cluster configuration");
        // Update configuration logic here
        Ok(())
    }

    /// Get current cluster members
    pub async fn get_members(&self) -> HashMap<NodeId, ClusterNode> {
        self.members.read().await.clone()
    }

    /// Get current cluster leader
    pub async fn get_leader(&self) -> Option<NodeId> {
        let raft_state = self.raft_engine.get_state().await;
        match raft_state {
            crate::raft::RaftState::Leader => Some(self.local_node.id),
            _ => {
                // Check members for leader
                let members = self.members.read().await;
                for (node_id, node) in members.iter() {
                    if matches!(node.state, NodeState::Leader { .. }) {
                        return Some(*node_id);
                    }
                }
                None
            }
        }
    }

    /// Check if cluster has quorum
    pub async fn has_quorum(&self) -> bool {
        let members = self.members.read().await;
        let quorum_manager = self.quorum_manager.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64;
        
        let active_nodes = members.values()
            .filter(|node| now.saturating_sub(node.last_heartbeat) < 10000) // 10 seconds in milliseconds
            .count();
        
        quorum_manager.has_quorum(active_nodes)
    }

    /// Replicate data to cluster nodes
    pub async fn replicate_data(&self, key: String, data: Vec<u8>) -> Result<()> {
        let members = self.members.read().await;
        let replication_factor = self.config.replication_factor.min(members.len());
        
        // Select nodes for replication (excluding self)
        let mut target_nodes: Vec<NodeId> = members.keys()
            .filter(|&&id| id != self.local_node.id)
            .cloned()
            .collect();
        
        // Randomly select replication factor nodes using TRNG
        match crate::trng::random_bytes(target_nodes.len()) {
            Ok(random_bytes) => {
                // Use random bytes to shuffle
                for i in 0..random_bytes.len().min(target_nodes.len()) {
                    let j = (random_bytes[i] as usize) % target_nodes.len();
                    target_nodes.swap(i, j);
                }
            }
            Err(_) => {
                // Fallback to thread_rng
                use rand::seq::SliceRandom;
                target_nodes.shuffle(&mut rand::thread_rng());
            }
        }
        target_nodes.truncate(replication_factor);

        // Create replication command
        let command = ClusterCommand::ReplicateData {
            key,
            data,
            nodes: target_nodes.clone(),
        };

        // Send to target nodes
        for node_id in target_nodes {
            if let Err(e) = self.send_replication_command(node_id, &command).await {
                tracing::warn!("Failed to send replication command to node {}: {}", node_id, e);
            } else {
                tracing::debug!("Successfully sent replication command to node {}", node_id);
            }
        }

        Ok(())
    }

    /// Send replication command to a specific node
    async fn send_replication_command(&self, node_id: NodeId, command: &ClusterCommand) -> Result<()> {
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use serde_json;
        
        // Get node address
        let node_address = {
            let members = self.members.read().await;
            members.get(&node_id)
                .map(|node| node.address)
                .ok_or_else(|| FortressError::cluster(
                    format!("Node {} not found in cluster", node_id),
                    None,
                ))?
        };
        
        tracing::debug!("Sending replication command to node {} at {:?}", node_id, command);
        
        // Connect to target node with timeout
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(node_address)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(FortressError::cluster(
                    format!("Failed to connect to node {}: {}", node_id, e),
                    None,
                ));
            }
            Err(_) => {
                return Err(FortressError::cluster(
                    format!("Timeout connecting to node {}", node_id),
                    None,
                ));
            }
        };
        
        // Serialize command
        let command_bytes = serde_json::to_vec(command)
            .map_err(|e| FortressError::cluster(
                format!("Failed to serialize replication command: {}", e),
                None,
            ))?;
        
        // Send length prefix followed by data
        let length = command_bytes.len() as u32;
        if let Err(e) = stream.write_all(&length.to_le_bytes()).await {
            return Err(FortressError::cluster(
                format!("Failed to send command length to node {}: {}", node_id, e),
                None,
            ));
        }
        
        if let Err(e) = stream.write_all(&command_bytes).await {
            return Err(FortressError::cluster(
                format!("Failed to send command to node {}: {}", node_id, e),
                None,
            ));
        }
        
        // Read acknowledgment
        let mut length_bytes = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut length_bytes).await {
            return Err(FortressError::cluster(
                format!("Failed to read acknowledgment length from node {}: {}", node_id, e),
                None,
            ));
        }
        
        let ack_length = u32::from_le_bytes(length_bytes) as usize;
        if ack_length > 1024 { // Reasonable limit for acknowledgment
            return Err(FortressError::cluster(
                format!("Acknowledgment too large from node {}: {} bytes", node_id, ack_length),
                None,
            ));
        }
        
        let mut ack_bytes = vec![0u8; ack_length];
        if let Err(e) = stream.read_exact(&mut ack_bytes).await {
            return Err(FortressError::cluster(
                format!("Failed to read acknowledgment from node {}: {}", node_id, e),
                None,
            ));
        }
        
        // Parse acknowledgment
        let ack: serde_json::Value = serde_json::from_slice(&ack_bytes)
            .map_err(|e| FortressError::cluster(
                format!("Failed to parse acknowledgment from node {}: {}", node_id, e),
                None,
            ))?;
        
        if let Some(success) = ack.get("success").and_then(|v| v.as_bool()) {
            if success {
                tracing::debug!("Node {} acknowledged replication command", node_id);
                Ok(())
            } else {
                let error_msg = ack.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                Err(FortressError::cluster(
                    format!("Node {} rejected replication command: {}", node_id, error_msg),
                    None,
                ))
            }
        } else {
            Err(FortressError::cluster(
                format!("Invalid acknowledgment from node {}", node_id),
                None,
            ))
        }
    }

    /// Get cluster health status
    pub async fn get_health_status(&self) -> ClusterHealth {
        let members = self.members.read().await;
        let leader = self.get_leader().await;
        let has_quorum = self.has_quorum().await;
        let raft_state = self.raft_engine.get_state().await;
        let current_term = self.raft_engine.get_term().await;
        let commit_index = self.raft_engine.get_commit_index().await;

        let active_nodes = members.values()
            .filter(|node| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_millis() as u64;
                now.saturating_sub(node.last_heartbeat) < 10000 // 10 seconds in milliseconds
            })
            .count();

        let total_nodes = members.len();

        ClusterHealth {
            total_nodes,
            active_nodes,
            leader,
            has_quorum,
            replication_factor: self.config.replication_factor,
            current_term,
            commit_index,
            raft_state: format!("{:?}", raft_state),
        }
    }
}

/// Quorum manager for consensus decisions
pub struct QuorumManager {
    /// Total number of nodes in cluster
    total_nodes: usize,
    /// Minimum nodes for quorum
    quorum_size: usize,
}

impl QuorumManager {
    /// Create new quorum manager
    pub fn new(total_nodes: usize) -> Self {
        let quorum_size = (total_nodes / 2) + 1;
        Self {
            total_nodes,
            quorum_size,
        }
    }
    
    /// Check if we have quorum
    pub fn has_quorum(&self, responses: usize) -> bool {
        responses >= self.quorum_size
    }
    
    /// Get quorum size
    pub fn quorum_size(&self) -> usize {
        self.quorum_size
    }
    
    /// Get total nodes
    pub fn total_nodes(&self) -> usize {
        self.total_nodes
    }
    
    /// Check if a specific node count is sufficient for quorum
    pub fn is_sufficient(&self, node_count: usize) -> bool {
        node_count >= self.quorum_size
    }
    
    /// Update cluster size
    pub fn update_cluster_size(&mut self, total_nodes: usize) {
        self.total_nodes = total_nodes;
        self.quorum_size = (total_nodes / 2) + 1;
    }
}

/// Cluster health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    /// Total number of nodes in cluster
    pub total_nodes: usize,
    /// Number of active nodes
    pub active_nodes: usize,
    /// Current leader (if any)
    pub leader: Option<NodeId>,
    /// Whether cluster has quorum
    pub has_quorum: bool,
    /// Configured replication factor
    pub replication_factor: usize,
    /// Current Raft term
    pub current_term: u64,
    /// Current commit index
    pub commit_index: u64,
    /// Current Raft state
    pub raft_state: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_config_defaults() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: default_heartbeat_interval(),
            election_timeout: default_election_timeout(),
            replication_factor: default_replication_factor(),
        };

        assert_eq!(config.heartbeat_interval, default_heartbeat_interval());
        assert_eq!(config.election_timeout, default_election_timeout());
        assert_eq!(config.replication_factor, default_replication_factor());
    }

    #[tokio::test]
    async fn test_cluster_manager_creation() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();
        let members = manager.get_members().await;
        
        assert_eq!(members.len(), 1);
        assert!(members.contains_key(&manager.local_node.id));
    }

    #[tokio::test]
    async fn test_quorum_check() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 2,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();
        
        // With only one node and min_nodes=2, should not have quorum
        assert!(!manager.has_quorum().await);
    }

    #[tokio::test]
    async fn test_quorum_check_single_node() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();
        
        // Single node should have quorum
        assert!(manager.has_quorum().await);
    }

    #[tokio::test]
    async fn test_quorum_manager() {
        let mut quorum_manager = QuorumManager::new(3);
        
        assert_eq!(quorum_manager.total_nodes(), 3);
        assert_eq!(quorum_manager.quorum_size(), 2);
        assert!(quorum_manager.has_quorum(2));
        assert!(!quorum_manager.has_quorum(1));
        assert!(quorum_manager.is_sufficient(2));
        
        // Update cluster size
        quorum_manager.update_cluster_size(5);
        assert_eq!(quorum_manager.total_nodes(), 5);
        assert_eq!(quorum_manager.quorum_size(), 3);
        assert!(quorum_manager.has_quorum(3));
        assert!(!quorum_manager.has_quorum(2));
    }

    #[tokio::test]
    async fn test_cluster_health() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();
        let health = manager.get_health_status().await;
        
        assert_eq!(health.total_nodes, 1);
        assert_eq!(health.active_nodes, 1);
        assert!(health.has_quorum);
        assert_eq!(health.replication_factor, 3);
        assert_eq!(health.current_term, 0);
        assert_eq!(health.commit_index, 0);
    }

    #[tokio::test]
    async fn test_node_addition() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let mut manager = ClusterManager::new(config).unwrap();
        
        let new_node = ClusterNode {
            id: Uuid::new_v4(),
            address: "127.0.0.1:8081".parse().unwrap(),
            state: NodeState::Follower { leader: None, term: 0 },
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis() as u64,
            capabilities: NodeCapabilities::default(),
            load_metrics: LoadMetrics::default(),
        };
        
        manager.handle_add_node(new_node.clone()).await.unwrap();
        
        let members = manager.get_members().await;
        assert_eq!(members.len(), 2);
        assert!(members.contains_key(&new_node.id));
        
        let health = manager.get_health_status().await;
        assert_eq!(health.total_nodes, 2);
    }

    #[tokio::test]
    async fn test_node_removal() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let mut manager = ClusterManager::new(config).unwrap();
        
        let new_node = ClusterNode {
            id: Uuid::new_v4(),
            address: "127.0.0.1:8081".parse().unwrap(),
            state: NodeState::Follower { leader: None, term: 0 },
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis() as u64,
            capabilities: NodeCapabilities::default(),
            load_metrics: LoadMetrics::default(),
        };
        
        // Add node first
        manager.handle_add_node(new_node.clone()).await.unwrap();
        assert_eq!(manager.get_members().await.len(), 2);
        
        // Remove node
        manager.handle_remove_node(new_node.id).await.unwrap();
        assert_eq!(manager.get_members().await.len(), 1);
        assert!(!manager.get_members().await.contains_key(&new_node.id));
    }

    #[tokio::test]
    async fn test_leader_detection() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();
        
        // Initially no leader
        assert!(manager.get_leader().await.is_none());
        
        // Become leader
        manager.raft_engine.become_leader().await.unwrap();
        
        // Should detect self as leader
        assert_eq!(manager.get_leader().await, Some(manager.local_node.id));
    }
}
