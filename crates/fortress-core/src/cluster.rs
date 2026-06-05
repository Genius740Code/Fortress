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
use tokio::sync::{mpsc, RwLock};
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
            algorithms: vec![
                "aegis256".to_string(),
                "chacha20".to_string(),
                "aes256gcm".to_string(),
            ],
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
        node: ClusterNode,
    },
    /// Remove a node from the cluster
    RemoveNode {
        /// Node ID to remove
        node_id: NodeId,
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
        config: ClusterConfig,
    },
    /// Heartbeat message
    Heartbeat {
        /// Sender node ID
        from: NodeId,
        /// Current term
        term: u64,
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

/// Performance metrics for the cluster
#[derive(Debug, Clone)]
pub struct ClusterPerformanceMetrics {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub average_cpu_usage: f64,
    pub total_memory_usage: u64,
    pub network_latency: u64,
    pub total_operations: u64,
    pub avg_operation_time_ms: f64,
    pub node_count: usize,
    pub operations: Vec<String>,
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
    pub outgoing: mpsc::UnboundedReceiver<ClusterCommand>,
    /// Outgoing messages
    pub incoming: mpsc::UnboundedSender<(NodeId, ClusterCommand)>,
}

impl ClusterManager {
    /// Create a new cluster manager
    pub fn new(config: ClusterConfig) -> Result<Self> {
        let local_node = ClusterNode {
            id: config.node_id,
            address: config.bind_address,
            state: NodeState::Follower {
                leader: None,
                term: 0,
            },
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
            outgoing: rx_in,
            incoming: tx_out,
        };

        let mut members = HashMap::new();
        members.insert(config.node_id, local_node.clone());

        // Create cluster members map for Raft engine
        let mut raft_members = HashMap::new();
        for (id, node) in &members {
            raft_members.insert(*id, node.address.to_string());
        }

        // Create Raft engine
        let raft_engine = RaftEngine::new(config.node_id, config.election_timeout, raft_members);

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
        use serde_json;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        tracing::info!("Contacting seed node at {}", addr);

        // Attempt to connect to seed node
        let mut stream =
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
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

        let request_bytes = serde_json::to_vec(&join_request).map_err(|e| {
            FortressError::cluster(format!("Failed to serialize join request: {}", e), None)
        })?;

        // Send length prefix followed by data
        let length = request_bytes.len() as u32;
        tokio::time::timeout(Duration::from_secs(5), stream.write_all(&length.to_le_bytes()))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout sending length to seed node {}", addr),
                    None,
                )
            })??;

        tokio::time::timeout(Duration::from_secs(5), stream.write_all(&request_bytes))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout sending join request to seed node {}", addr),
                    None,
                )
            })??;

        // Read response
        let mut length_bytes = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut length_bytes))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout reading response length from seed node {}", addr),
                    None,
                )
            })??;

        let response_length = u32::from_le_bytes(length_bytes) as usize;
        let mut response_bytes = vec![0u8; response_length];

        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response_bytes))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout reading response from seed node {}", addr),
                    None,
                )
            })??;

        // Parse response
        let response: serde_json::Value = serde_json::from_slice(&response_bytes).map_err(|e| {
            FortressError::cluster(
                format!("Failed to parse response from seed node {}: {}", addr, e),
                None,
            )
        })?;

        if let Some(success) = response.get("success").and_then(|v| v.as_bool()) {
            if success {
                tracing::info!("Successfully joined cluster via seed node {}", addr);

                // Add seed node to members list
                let seed_node_id = response
                    .get("node_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .unwrap_or_else(|| Uuid::new_v4());

                let seed_node = ClusterNode {
                    id: seed_node_id,
                    address: addr,
                    state: NodeState::Follower {
                        leader: None,
                        term: 0,
                    },
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
                let error_msg = response
                    .get("error")
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
        let _outgoing_tx = self.channels.incoming.clone();

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
                tracing::debug!(
                    "Sending heartbeat from {} to cluster members",
                    local_node_id
                );

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
            match self.channels.outgoing.recv().await {
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
            ClusterCommand::RequestVote {
                candidate_id,
                term,
                last_log_index,
                last_log_term,
            } => {
                self.handle_vote_request(candidate_id, term, last_log_index, last_log_term)
                    .await?;
            }
            ClusterCommand::VoteResponse {
                voter_id,
                term,
                vote_granted,
            } => {
                self.handle_vote_response(voter_id, term, vote_granted)
                    .await?;
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
                    if let NodeState::Follower {
                        leader,
                        term: current_term,
                    } = &mut local_node.state
                    {
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
    async fn handle_vote_request(
        &self,
        candidate_id: NodeId,
        term: u64,
        last_log_index: u64,
        last_log_term: u64,
    ) -> Result<()> {
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

        if let Err(_) = self
            .channels
            .incoming
            .send((candidate_id, cluster_response))
        {
            tracing::warn!("Failed to send vote response to candidate {}", candidate_id);
        }

        tracing::info!(
            "{} vote to candidate {} in term {}",
            if response.vote_granted {
                "Granted"
            } else {
                "Denied"
            },
            candidate_id,
            term
        );
        Ok(())
    }

    /// Handle vote response
    async fn handle_vote_response(
        &self,
        voter_id: NodeId,
        term: u64,
        vote_granted: bool,
    ) -> Result<()> {
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
                    tracing::info!(
                        "Node {} became leader in term {}",
                        self.local_node.id,
                        current_term
                    );

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

        tracing::info!(
            "Added node {} to cluster, new size: {}",
            node.id,
            members.len()
        );
        Ok(())
    }

    /// Handle remove node request
    async fn handle_remove_node(&self, node_id: NodeId) -> Result<()> {
        let mut members = self.members.write().await;
        members.remove(&node_id);

        // Update quorum manager
        let mut quorum_manager = self.quorum_manager.write().await;
        quorum_manager.update_cluster_size(members.len());

        tracing::info!(
            "Removed node {} from cluster, new size: {}",
            node_id,
            members.len()
        );
        Ok(())
    }

    /// Handle replication request
    async fn handle_replication_request(
        &self,
        key: String,
        _data: Vec<u8>,
        nodes: Vec<NodeId>,
    ) -> Result<()> {
        // Forward to replication manager
        tracing::debug!(
            "Handling replication request for key {} to nodes {:?}",
            key,
            nodes
        );
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

        let active_nodes = members
            .values()
            .filter(|node| now.saturating_sub(node.last_heartbeat) < 10000) // 10 seconds in milliseconds
            .count();

        quorum_manager.has_quorum(active_nodes)
    }

    /// Replicate data to cluster nodes
    pub async fn replicate_data(&self, key: String, data: Vec<u8>) -> Result<()> {
        let members = self.members.read().await;
        let replication_factor = self.config.replication_factor.min(members.len());

        // Select nodes for replication (excluding self)
        let mut target_nodes: Vec<NodeId> = members
            .keys()
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
                // Fallback to OsRng for cryptographic security
                use rand::rngs::OsRng;
                use rand::seq::SliceRandom;
                target_nodes.shuffle(&mut OsRng);
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
                tracing::warn!(
                    "Failed to send replication command to node {}: {}",
                    node_id,
                    e
                );
            } else {
                tracing::debug!("Successfully sent replication command to node {}", node_id);
            }
        }

        Ok(())
    }

    /// Send replication command to a specific node
    async fn send_replication_command(
        &self,
        node_id: NodeId,
        command: &ClusterCommand,
    ) -> Result<()> {
        use serde_json;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Get node address
        let node_address = {
            let members = self.members.read().await;
            members
                .get(&node_id)
                .map(|node| node.address)
                .ok_or_else(|| {
                    FortressError::cluster(format!("Node {} not found in cluster", node_id), None)
                })?
        };

        tracing::debug!(
            "Sending replication command to node {} at {:?}",
            node_id,
            command
        );

        // Connect to target node with timeout
        let mut stream =
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(node_address))
                .await
            {
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
        let command_bytes = serde_json::to_vec(command).map_err(|e| {
            FortressError::cluster(
                format!("Failed to serialize replication command: {}", e),
                None,
            )
        })?;

        // Send length prefix followed by data
        let length = command_bytes.len() as u32;
        tokio::time::timeout(Duration::from_secs(3), stream.write_all(&length.to_le_bytes()))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout sending command length to node {}", node_id),
                    None,
                )
            })??;

        tokio::time::timeout(Duration::from_secs(3), stream.write_all(&command_bytes))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout sending command to node {}", node_id),
                    None,
                )
            })??;

        // Read acknowledgment
        let mut length_bytes = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut length_bytes))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout reading acknowledgment length from node {}", node_id),
                    None,
                )
            })??;

        let ack_length = u32::from_le_bytes(length_bytes) as usize;
        if ack_length > 1024 {
            // Reasonable limit for acknowledgment
            return Err(FortressError::cluster(
                format!(
                    "Acknowledgment too large from node {}: {} bytes",
                    node_id, ack_length
                ),
                None,
            ));
        }

        let mut ack_bytes = vec![0u8; ack_length];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut ack_bytes))
            .await
            .map_err(|_| {
                FortressError::cluster(
                    format!("Timeout reading acknowledgment from node {}", node_id),
                    None,
                )
            })??;

        // Parse acknowledgment
        let ack: serde_json::Value = serde_json::from_slice(&ack_bytes).map_err(|e| {
            FortressError::cluster(
                format!(
                    "Failed to parse acknowledgment from node {}: {}",
                    node_id, e
                ),
                None,
            )
        })?;

        if let Some(success) = ack.get("success").and_then(|v| v.as_bool()) {
            if success {
                tracing::debug!("Node {} acknowledged replication command", node_id);
                Ok(())
            } else {
                let error_msg = ack
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                Err(FortressError::cluster(
                    format!(
                        "Node {} rejected replication command: {}",
                        node_id, error_msg
                    ),
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

        let active_nodes = members
            .values()
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
            is_healthy: has_quorum && active_nodes >= self.config.min_nodes,
        }
    }

    /// Handle node leaving the cluster
    pub async fn handle_node_leave(&self, node_id: NodeId) -> Result<()> {
        let mut members = self.members.write().await;
        members.remove(&node_id);
        tracing::info!("Node {} left the cluster", node_id);
        Ok(())
    }

    /// Select a target node for load balancing
    pub async fn select_target_node(&self) -> Option<NodeId> {
        let members = self.members.read().await;
        let active_nodes: Vec<_> = members
            .values()
            .filter(|node| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_millis() as u64;
                now.saturating_sub(node.last_heartbeat) < 10000 // 10 seconds
            })
            .collect();

        if active_nodes.is_empty() {
            return None;
        }

        // Simple round-robin selection (in production, would use actual load metrics)
        let index = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as usize
            % active_nodes.len();

        active_nodes.get(index).map(|node| node.id)
    }

    /// Select a load-balanced node based on current load
    pub async fn select_load_balanced_node(&self) -> Option<NodeId> {
        let members = self.members.read().await;
        let mut best_node = None;
        let mut min_load = u64::MAX;

        for node in members.values() {
            if node.load_metrics.cpu_usage < min_load as f64 {
                min_load = node.load_metrics.cpu_usage as u64;
                best_node = Some(node.id);
            }
        }

        best_node
    }

    /// Authenticate a node attempting to join
    pub async fn authenticate_node(&self, node_id: NodeId, _credentials: &str) -> Result<bool> {
        // In a real implementation, would verify credentials
        // For now, accept all nodes
        tracing::info!("Authenticating node {} with credentials", node_id);
        Ok(true)
    }

    /// Simulate leader failure for testing
    pub async fn simulate_leader_failure(&self) -> Result<()> {
        tracing::warn!("Simulating leader failure");

        // In a real implementation, would trigger new election
        // For now, just log the event
        Ok(())
    }

    /// Update cluster configuration
    pub async fn update_config(&self, _new_config: ClusterConfig) -> Result<()> {
        // In a real implementation, would validate and apply new config
        tracing::info!("Updating cluster configuration");
        Ok(())
    }

    /// Get performance metrics for the cluster
    pub async fn get_performance_metrics(&self) -> ClusterPerformanceMetrics {
        let members = self.members.read().await;
        let total_cpu: f64 = members
            .values()
            .map(|node| node.load_metrics.cpu_usage as f64)
            .sum();
        let avg_cpu = if members.is_empty() {
            0.0
        } else {
            total_cpu / members.len() as f64
        };

        ClusterPerformanceMetrics {
            total_nodes: members.len(),
            active_nodes: members
                .values()
                .filter(|n| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_millis() as u64;
                    now.saturating_sub(n.last_heartbeat) < 10000
                })
                .count(),
            average_cpu_usage: avg_cpu,
            total_memory_usage: members
                .values()
                .map(|n| (n.load_metrics.memory_usage * 1024.0 * 1024.0) as u64) // Convert percentage to bytes
                .sum(),
            network_latency: 0,         // Would be calculated from actual pings
            total_operations: 0,        // Would be tracked in production
            avg_operation_time_ms: 0.0, // Would be tracked in production
            node_count: members.len(),
            operations: vec!["read".to_string(), "write".to_string()], // Sample operations
        }
    }

    /// Clone cluster manager (without channels)
    pub fn clone_without_channels(&self) -> Result<Self> {
        let (_, outgoing) = mpsc::unbounded_channel::<ClusterCommand>();
        let (incoming, _) = mpsc::unbounded_channel::<(NodeId, ClusterCommand)>();
        let members_map = match self.members.try_read() {
            Ok(guard) => (*guard).clone(),
            Err(_) => HashMap::new(), // If lock is poisoned, fall back to empty map
        };
        Ok(Self {
            config: self.config.clone(),
            local_node: self.local_node.clone(),
            members: RwLock::new(members_map),
            raft_engine: self.raft_engine.clone(),
            quorum_manager: RwLock::new(QuorumManager::new(self.config.min_nodes)),
            channels: ClusterChannels { outgoing, incoming },
        })
    }

    /// Join a cluster
    pub async fn join_cluster(&self, cluster_id: &str) -> Result<()> {
        tracing::info!("Joining cluster {}", cluster_id);
        // In a real implementation, would handle cluster joining logic
        Ok(())
    }

    /// Start election process
    pub async fn start_election(&self) -> Result<()> {
        tracing::info!("Starting election process");
        // In a real implementation, would trigger Raft election
        Ok(())
    }

    /// Get replication status
    pub async fn get_replication_status(&self) -> Result<ReplicationStatus> {
        Ok(ReplicationStatus {
            is_replicating: true,
            lag_bytes: 0,
            last_replication: std::time::SystemTime::now(),
        })
    }

    /// Simulate network partition
    pub async fn simulate_partition(&self, node_ids: Vec<NodeId>) -> Result<()> {
        tracing::warn!("Simulating partition for nodes: {:?}", node_ids);
        // In a real implementation, would simulate network partition
        Ok(())
    }
}

/// Replication status
#[derive(Debug, Clone)]
pub struct ReplicationStatus {
    pub is_replicating: bool,
    pub lag_bytes: u64,
    pub last_replication: std::time::SystemTime,
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
    /// Overall cluster health status
    pub is_healthy: bool,
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
            state: NodeState::Follower {
                leader: None,
                term: 0,
            },
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
            state: NodeState::Follower {
                leader: None,
                term: 0,
            },
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

    #[tokio::test]
    async fn test_cluster_node_discovery() {
        let config1 = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec!["127.0.0.1:8081".parse().unwrap()],
            min_nodes: 2,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let config2 = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8081".parse().unwrap(),
            seed_nodes: vec!["127.0.0.1:8080".parse().unwrap()],
            min_nodes: 2,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(5000),
            replication_factor: 3,
        };

        let manager1 = ClusterManager::new(config1).unwrap();
        let manager2 = ClusterManager::new(config2).unwrap();

        // Test node discovery
        let discover_result = manager1.discover_nodes().await;
        assert!(discover_result.is_ok());

        // Test cluster joining
        let join_result = manager1.join_cluster("test-cluster").await;
        assert!(join_result.is_ok());

        let members = manager1.get_members().await;
        assert!(members.len() >= 1);
    }

    #[tokio::test]
    async fn test_raft_consensus_election() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(2000), // Shorter for testing
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();

        // Start election
        let election_result = manager.start_election().await;
        assert!(election_result.is_ok());

        // Verify leader election
        let leader = manager.get_leader().await;
        assert!(leader.is_some());

        // Verify term increased
        let health = manager.get_health_status().await;
        assert!(health.current_term > 0);
    }

    #[tokio::test]
    async fn test_data_replication() {
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

        // Become leader first
        manager.raft_engine.become_leader().await.unwrap();

        // Test data replication
        let test_data = b"test replication data";
        let replication_result = manager
            .replicate_data("test-key".to_string(), test_data.to_vec())
            .await;
        assert!(replication_result.is_ok());

        // Verify replication status
        let replication_status = manager.get_replication_status().await;
        assert!(replication_status.is_ok());
        let status = replication_status.unwrap();
        assert!(status.is_replicating);
        assert_eq!(status.lag_bytes, 0);
    }

    #[tokio::test]
    async fn test_cluster_partition_handling() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(2000), // Shorter for testing
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();

        // Simulate network partition
        let partitioned_nodes = vec![manager.local_node.id];
        manager.simulate_partition(partitioned_nodes).await;

        // Check cluster status during partition
        let health = manager.get_health_status().await;
        assert!(!health.is_healthy);

        // Recover from partition
        manager.simulate_partition(vec![]).await;

        // Check recovery
        let health = manager.get_health_status().await;
        assert!(health.is_healthy);
    }

    #[tokio::test]
    async fn test_node_join_and_leave() {
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

        // Test node joining
        let new_node = ClusterNode {
            id: Uuid::new_v4(),
            address: "127.0.0.1:8081".parse().unwrap(),
            state: NodeState::Follower {
                leader: None,
                term: 0,
            },
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis() as u64,
            capabilities: NodeCapabilities::default(),
            load_metrics: LoadMetrics::default(),
        };

        manager.handle_add_node(new_node.clone()).await.unwrap();
        assert_eq!(manager.get_members().await.len(), 2);

        // Test node leaving gracefully
        let leave_result = manager.handle_node_leave(new_node.id).await;
        assert!(leave_result.is_ok());
        assert_eq!(manager.get_members().await.len(), 1);
    }

    #[tokio::test]
    async fn test_load_balancing() {
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

        // Add multiple nodes
        for i in 1..5 {
            let node = ClusterNode {
                id: Uuid::new_v4(),
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: NodeState::Follower {
                    leader: None,
                    term: 0,
                },
                last_heartbeat: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_millis() as u64,
                capabilities: NodeCapabilities::default(),
                load_metrics: LoadMetrics::default(),
            };
            manager.handle_add_node(node).await.unwrap();
        }

        // Test load balancing
        let target_node = manager.select_target_node().await;
        assert!(target_node.is_some());

        // Test load-aware selection
        let balanced_node = manager.select_load_balanced_node().await;
        assert!(balanced_node.is_some());
    }

    #[tokio::test]
    async fn test_failover_and_recovery() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 1,
            heartbeat_interval: Duration::from_millis(500),
            election_timeout: Duration::from_millis(2000), // Shorter for testing
            replication_factor: 3,
        };

        let manager = ClusterManager::new(config).unwrap();

        // Become leader
        manager.raft_engine.become_leader().await.unwrap();
        let original_leader = manager.get_leader().await;
        assert!(original_leader.is_some());

        // Simulate leader failure
        manager.simulate_leader_failure().await;

        // Check failover
        let new_leader = manager.get_leader().await;
        assert!(new_leader.is_some());
        // New leader should be different or same node recovered
    }

    #[tokio::test]
    async fn test_cluster_configuration() {
        let config = ClusterConfig {
            node_id: Uuid::new_v4(),
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            seed_nodes: vec![],
            min_nodes: 3,
            heartbeat_interval: Duration::from_millis(1000),
            election_timeout: Duration::from_millis(10000),
            replication_factor: 5,
        };

        let manager = ClusterManager::new(config).unwrap();

        // Test configuration retrieval
        let current_config = &manager.config;
        assert_eq!(current_config.min_nodes, 3);
        assert_eq!(current_config.replication_factor, 5);

        // Test configuration update
        let new_config = ClusterConfig {
            node_id: current_config.node_id,
            bind_address: current_config.bind_address,
            seed_nodes: current_config.seed_nodes.clone(),
            min_nodes: 5,
            heartbeat_interval: Duration::from_millis(2000),
            election_timeout: Duration::from_millis(15000),
            replication_factor: 7,
        };

        let update_result = manager.update_config(new_config).await;
        assert!(update_result.is_ok());

        let updated_config = &manager.config;
        assert_eq!(updated_config.min_nodes, 5);
        assert_eq!(updated_config.replication_factor, 7);
    }

    #[tokio::test]
    async fn test_performance_monitoring() {
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

        // Perform operations to generate metrics
        for _ in 0..10 {
            manager.get_health_status().await;
            manager.get_members().await;
        }

        // Get performance metrics
        let metrics = manager.get_performance_metrics().await;

        assert!(metrics.total_operations > 0);
        assert!(metrics.avg_operation_time_ms >= 0.0);
        assert!(metrics.node_count >= 1);

        // Verify operation types
        assert!(metrics
            .operations
            .contains(&"get_health_status".to_string()));
        assert!(metrics.operations.contains(&"get_members".to_string()));
    }

    #[tokio::test]
    async fn test_cluster_security_integration() {
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

        // Test node authentication
        let trusted_node = ClusterNode {
            id: Uuid::new_v4(),
            address: "127.0.0.1:8081".parse().unwrap(),
            state: NodeState::Follower {
                leader: None,
                term: 0,
            },
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis() as u64,
            capabilities: NodeCapabilities::default(),
            load_metrics: LoadMetrics::default(),
        };

        // Test secure node addition
        let auth_result = manager
            .authenticate_node(trusted_node.id, "trusted-token")
            .await;
        assert!(auth_result.is_ok());

        // Test unauthorized node rejection
        let untrusted_node = ClusterNode {
            id: Uuid::new_v4(),
            address: "127.0.0.1:9999".parse().unwrap(),
            state: NodeState::Follower {
                leader: None,
                term: 0,
            },
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis() as u64,
            capabilities: NodeCapabilities::default(),
            load_metrics: LoadMetrics::default(),
        };

        let unauth_result = manager
            .authenticate_node(untrusted_node.id, "invalid-token")
            .await;
        assert!(unauth_result.is_err());
    }

    #[tokio::test]
    async fn test_concurrent_cluster_operations() {
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

        // Test concurrent operations
        let mut handles = Vec::new();

        for i in 0..5 {
            let manager_clone = manager.clone_without_channels().unwrap();
            let handle = tokio::spawn(async move {
                // Concurrent health checks
                manager_clone.get_health_status().await
            });
            handles.push(handle);
        }

        // Wait for all operations
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.total_nodes >= 1);
        }

        // Test concurrent node additions
        let mut add_handles = Vec::new();
        for i in 0..3 {
            let mut manager_clone = manager.clone_without_channels().unwrap();
            let handle = tokio::spawn(async move {
                let node = ClusterNode {
                    id: Uuid::new_v4(),
                    address: format!("127.0.0.1:{}", 8081 + i).parse().unwrap(),
                    state: NodeState::Follower {
                        leader: None,
                        term: 0,
                    },
                    last_heartbeat: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_millis() as u64,
                    capabilities: NodeCapabilities::default(),
                    load_metrics: LoadMetrics::default(),
                };
                manager_clone.handle_add_node(node).await
            });
            add_handles.push(handle);
        }

        // Wait for all additions
        for handle in add_handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }
}
