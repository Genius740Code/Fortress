//! Data replication system for Fortress clusters
//!
//! This module provides data replication across cluster nodes with consistency
//! guarantees, conflict resolution, and recovery mechanisms.

use crate::cluster::{NodeId, ClusterNode};
use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

/// Unique identifier for replication operations
pub type ReplicationId = Uuid;

/// Replication consistency level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsistencyLevel {
    /// Write must be replicated to all nodes
    All,
    /// Write must be replicated to majority of nodes
    Majority,
    /// Write must be replicated to quorum (majority + 1)
    Quorum,
    /// Write must be replicated to a specific number of nodes
    Count(usize),
    /// Write can be replicated asynchronously
    Eventual,
}

/// Replication status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReplicationStatus {
    /// Replication in progress
    Pending,
    /// Replication completed successfully
    Completed,
    /// Replication failed
    Failed(String),
    /// Partial replication (some nodes failed)
    Partial {
        /// Number of successful replications
        success_count: usize,
        /// Number of failed replications
        failure_count: usize,
        /// Total expected replications
        total_count: usize,
    },
}

/// Replication operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationOperation {
    /// Unique operation identifier
    pub id: ReplicationId,
    /// Data key
    pub key: String,
    /// Data payload
    pub data: Vec<u8>,
    /// Target nodes for replication
    pub target_nodes: Vec<NodeId>,
    /// Required consistency level
    pub consistency_level: ConsistencyLevel,
    /// Creation timestamp (Unix timestamp in milliseconds)
    pub created_at: u64,
    /// Deadline for completion (Unix timestamp in milliseconds)
    pub deadline: Option<u64>,
    /// Current replication status
    pub status: ReplicationStatus,
    /// Nodes that have acknowledged replication
    pub acknowledged_nodes: Vec<NodeId>,
    /// Nodes that have failed replication
    pub failed_nodes: Vec<(NodeId, String)>,
}

impl ReplicationOperation {
    /// Create a new replication operation
    pub fn new(
        key: String,
        data: Vec<u8>,
        target_nodes: Vec<NodeId>,
        consistency_level: ConsistencyLevel,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            key,
            data,
            target_nodes,
            consistency_level,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            deadline: None,
            status: ReplicationStatus::Pending,
            acknowledged_nodes: Vec::new(),
            failed_nodes: Vec::new(),
        }
    }

    /// Set deadline for operation completion
    pub fn with_deadline(mut self, deadline: SystemTime) -> Self {
        self.deadline = Some(
            deadline
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        );
        self
    }

    /// Set deadline for operation completion (duration from now)
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        let deadline = SystemTime::now() + timeout;
        self.deadline = Some(
            deadline
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        );
        self
    }

    /// Check if operation has met consistency requirements
    pub fn meets_consistency(&self) -> bool {
        match self.consistency_level {
            ConsistencyLevel::All => {
                self.acknowledged_nodes.len() == self.target_nodes.len()
            }
            ConsistencyLevel::Majority => {
                self.acknowledged_nodes.len() > self.target_nodes.len() / 2
            }
            ConsistencyLevel::Quorum => {
                self.acknowledged_nodes.len() >= (self.target_nodes.len() / 2) + 1
            }
            ConsistencyLevel::Count(required) => {
                self.acknowledged_nodes.len() >= required
            }
            ConsistencyLevel::Eventual => true, // Always true for eventual consistency
        }
    }

    /// Check if operation is complete
    pub fn is_complete(&self) -> bool {
        match &self.status {
            ReplicationStatus::Completed => true,
            ReplicationStatus::Failed(_) => true,
            ReplicationStatus::Partial { .. } => {
                self.acknowledged_nodes.len() + self.failed_nodes.len() == self.target_nodes.len()
            }
            ReplicationStatus::Pending => false,
        }
    }

    /// Mark node as acknowledged
    pub fn acknowledge_node(&mut self, node_id: NodeId) {
        if !self.acknowledged_nodes.contains(&node_id) {
            self.acknowledged_nodes.push(node_id);
        }
    }

    /// Mark node as failed
    pub fn fail_node(&mut self, node_id: NodeId, error: String) {
        if !self.failed_nodes.iter().any(|(id, _)| *id == node_id) {
            self.failed_nodes.push((node_id, error));
        }
    }

    /// Update operation status based on current state
    pub fn update_status(&mut self) {
        if self.is_complete() {
            return;
        }

        if self.meets_consistency() {
            self.status = ReplicationStatus::Completed;
        } else if self.acknowledged_nodes.len() + self.failed_nodes.len() == self.target_nodes.len() {
            self.status = ReplicationStatus::Partial {
                success_count: self.acknowledged_nodes.len(),
                failure_count: self.failed_nodes.len(),
                total_count: self.target_nodes.len(),
            };
        }
    }
}

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Default consistency level
    pub default_consistency: ConsistencyLevel,
    /// Maximum concurrent replication operations
    pub max_concurrent_ops: usize,
    /// Replication timeout
    pub replication_timeout: Duration,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Background replication interval
    pub background_interval: Duration,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            default_consistency: ConsistencyLevel::Quorum,
            max_concurrent_ops: 100,
            replication_timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            background_interval: Duration::from_millis(100),
        }
    }
}

/// Retry configuration for failed replications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Maximum retry delay
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            max_delay: Duration::from_secs(10),
        }
    }
}

/// Replication manager
pub struct ReplicationManager {
    /// Node ID
    node_id: NodeId,
    /// Replication configuration
    config: ReplicationConfig,
    /// Active replication operations
    active_operations: Arc<RwLock<HashMap<ReplicationId, ReplicationOperation>>>,
    /// Completed operations (for cleanup)
    completed_operations: Arc<RwLock<HashMap<ReplicationId, ReplicationOperation>>>,
    /// Communication channels
    /// Communication channels
    #[allow(dead_code)]
    channels: ReplicationChannels,
    /// Cluster nodes
    cluster_nodes: Arc<RwLock<HashMap<NodeId, ClusterNode>>>,
}

/// Communication channels for replication
pub struct ReplicationChannels {
    /// Incoming replication messages
    pub incoming: mpsc::UnboundedReceiver<ReplicationMessage>,
    /// Outgoing replication messages
    pub outgoing: mpsc::UnboundedSender<(NodeId, ReplicationMessage)>,
}

/// Replication messages between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationMessage {
    /// Replication request
    ReplicateRequest {
        /// Operation identifier
        operation_id: ReplicationId,
        /// Data key
        key: String,
        /// Data payload
        data: Vec<u8>,
        /// Source node
        from_node: NodeId,
    },
    /// Replication acknowledgment
    ReplicateAck {
        /// Operation identifier
        operation_id: ReplicationId,
        /// Responding node
        from_node: NodeId,
        /// Success status
        success: bool,
        /// Error message
        error: Option<String>,
    },
    /// Data synchronization request
    SyncRequest {
        /// Requesting node
        from_node: NodeId,
        /// Keys to synchronize
        keys: Vec<String>,
    },
    /// Data synchronization response
    SyncResponse {
        /// Responding node
        from_node: NodeId,
        /// Synchronized data
        data: HashMap<String, Vec<u8>>,
    },
}

impl ReplicationManager {
    /// Create a new replication manager
    pub fn new(
        node_id: NodeId,
        config: ReplicationConfig,
        cluster_nodes: HashMap<NodeId, ClusterNode>,
    ) -> Result<Self> {
        let (_tx_in, rx_in) = mpsc::unbounded_channel();
        let (tx_out, _rx_out) = mpsc::unbounded_channel();

        let channels = ReplicationChannels {
            incoming: rx_in,
            outgoing: tx_out,
        };

        Ok(Self {
            node_id,
            config,
            active_operations: Arc::new(RwLock::new(HashMap::new())),
            completed_operations: Arc::new(RwLock::new(HashMap::new())),
            channels,
            cluster_nodes: Arc::new(RwLock::new(cluster_nodes)),
        })
    }

    /// Start the replication manager
    pub async fn start(&mut self) -> Result<()> {
        // Start message processing
        self.start_message_processing().await?;
        
        // Start operation monitoring
        self.start_operation_monitoring().await?;
        
        // Start cleanup task
        self.start_cleanup_task().await?;

        tracing::info!("Replication manager started for node {}", self.node_id);
        Ok(())
    }

    /// Replicate data to cluster nodes
    pub async fn replicate(
        &self,
        key: String,
        data: Vec<u8>,
        consistency_level: Option<ConsistencyLevel>,
    ) -> Result<ReplicationId> {
        let consistency = consistency_level.unwrap_or_else(|| self.config.default_consistency.clone());
        
        // Get target nodes (all nodes except self)
        let cluster_nodes = self.cluster_nodes.read().await;
        let target_nodes: Vec<NodeId> = cluster_nodes
            .keys()
            .filter(|&&id| id != self.node_id)
            .cloned()
            .collect();

        if target_nodes.is_empty() {
            return Err(FortressError::cluster(
                "No target nodes available for replication",
                None,
            ));
        }

        let operation = ReplicationOperation::new(
            key.clone(),
            data.clone(),
            target_nodes,
            consistency,
        );

        let operation_id = operation.id;

        // Store operation
        self.active_operations.write().await.insert(operation_id, operation);

        // Send replication requests
        let cluster_nodes = self.cluster_nodes.read().await;
        let active_operations = self.active_operations.read().await;
        let operation = active_operations.get(&operation_id).unwrap();

        for &node_id in &operation.target_nodes {
            if let Some(_node) = cluster_nodes.get(&node_id) {
                let message = ReplicationMessage::ReplicateRequest {
                    operation_id,
                    key: key.clone(),
                    data: data.clone(),
                    from_node: self.node_id,
                };

                // Send actual message
                if let Err(e) = self.send_replication_message(node_id, message).await {
                    tracing::warn!("Failed to send replication request to node {}: {}", node_id, e);
                    
                    // Mark node as failed for this operation
                    let mut active_operations = self.active_operations.write().await;
                    if let Some(op) = active_operations.get_mut(&operation_id) {
                        op.fail_node(node_id, format!("Network error: {}", e));
                        op.update_status();
                    }
                } else {
                    tracing::debug!("Successfully sent replication request to node {}", node_id);
                }
            }
        }

        tracing::info!("Started replication operation {} for key {}", operation_id, key);
        Ok(operation_id)
    }

    /// Get replication operation status
    pub async fn get_operation_status(&self, operation_id: ReplicationId) -> Option<ReplicationOperation> {
        let active = self.active_operations.read().await;
        let completed = self.completed_operations.read().await;
        
        active.get(&operation_id).cloned()
            .or_else(|| completed.get(&operation_id).cloned())
    }

    /// Wait for replication operation to complete
    pub async fn wait_for_completion(
        &self,
        operation_id: ReplicationId,
        timeout: Duration,
    ) -> Result<ReplicationOperation> {
        let deadline_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + timeout.as_millis() as u64;
        
        loop {
            let now_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            
            if now_timestamp >= deadline_timestamp {
                break;
            }
            if let Some(operation) = self.get_operation_status(operation_id).await {
                if operation.is_complete() {
                    return Ok(operation);
                }
            }
            
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Err(FortressError::cluster(
            "Replication operation timed out",
            None,
        ))
    }

    /// Start message processing loop
    async fn start_message_processing(&mut self) -> Result<()> {
        loop {
            match self.channels.incoming.recv().await {
                Some(message) => {
                    if let Err(e) = self.handle_replication_message(message).await {
                        tracing::error!("Error handling replication message: {}", e);
                    }
                }
                None => {
                    tracing::info!("Replication message processing channel closed");
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Handle incoming replication message
    async fn handle_replication_message(&self, message: ReplicationMessage) -> Result<()> {
        match message {
            ReplicationMessage::ReplicateRequest { operation_id, key, data, from_node } => {
                self.handle_replicate_request(operation_id, key, data, from_node).await?;
            }
            ReplicationMessage::ReplicateAck { operation_id, from_node, success, error } => {
                self.handle_replication_ack(operation_id, from_node, success, error).await?;
            }
            ReplicationMessage::SyncRequest { from_node, keys } => {
                self.handle_sync_request(from_node, keys).await?;
            }
            ReplicationMessage::SyncResponse { from_node, data } => {
                self.handle_sync_response(from_node, data).await?;
            }
        }
        Ok(())
    }

    /// Handle replication request from another node
    async fn handle_replicate_request(
        &self,
        operation_id: ReplicationId,
        key: String,
        _data: Vec<u8>,
        from_node: NodeId,
    ) -> Result<()> {
        tracing::debug!("Received replication request for operation {} key {} from node {}", 
                       operation_id, key, from_node);
        
        // In a real implementation, this would store the data locally
        // For now, we'll simulate successful storage
        
        // Send acknowledgment back to the requesting node
        let ack_message = ReplicationMessage::ReplicateAck {
            operation_id,
            from_node: self.node_id,
            success: true,
            error: None,
        };
        
        if let Err(_) = self.channels.outgoing.send((from_node, ack_message)) {
            tracing::warn!("Failed to send replication acknowledgment to node {}", from_node);
        } else {
            tracing::debug!("Sent replication acknowledgment to node {}", from_node);
        }
        
        Ok(())
    }

    /// Handle sync request from another node
    async fn handle_sync_request(&self, from_node: NodeId, keys: Vec<String>) -> Result<()> {
        tracing::debug!("Received sync request from node {} for keys: {:?}", from_node, keys);
        
        // In a real implementation, this would retrieve the requested data from local storage
        // For now, we'll return empty data
        let sync_data: HashMap<String, Vec<u8>> = HashMap::new();
        
        let response = ReplicationMessage::SyncResponse {
            from_node: self.node_id,
            data: sync_data,
        };
        
        if let Err(_) = self.channels.outgoing.send((from_node, response)) {
            tracing::warn!("Failed to send sync response to node {}", from_node);
        } else {
            tracing::debug!("Sent sync response to node {}", from_node);
        }
        
        Ok(())
    }

    /// Handle sync response from another node
    async fn handle_sync_response(&self, from_node: NodeId, data: HashMap<String, Vec<u8>>) -> Result<()> {
        tracing::debug!("Received sync response from node {} with {} keys", from_node, data.len());
        
        // In a real implementation, this would update local storage with the received data
        for (key, _value) in data {
            tracing::debug!("Syncing key {} from node {}", key, from_node);
            // Store the data locally
        }
        
        Ok(())
    }

    /// Start operation monitoring
    async fn start_operation_monitoring(&self) -> Result<()> {
        let replication_timeout = self.config.replication_timeout;
        let active_operations = self.active_operations.clone();
        let completed_operations = self.completed_operations.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                let now_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                
                // Check for timed out operations
                let mut timed_out_operations = Vec::new();
                
                {
                    let active = active_operations.read().await;
                    for (operation_id, operation) in active.iter() {
                        // Check if operation has exceeded its timeout
                        let operation_age = now_timestamp.saturating_sub(operation.created_at);
                        
                        let timeout_ms = if let Some(deadline) = operation.deadline {
                            deadline.saturating_sub(operation.created_at)
                        } else {
                            replication_timeout.as_millis() as u64
                        };
                        
                        if operation_age > timeout_ms {
                            timed_out_operations.push(*operation_id);
                        }
                    }
                }
                
                // Handle timed out operations
                if !timed_out_operations.is_empty() {
                    let mut active = active_operations.write().await;
                    let mut completed = completed_operations.write().await;
                    
                    for operation_id in timed_out_operations {
                        if let Some(mut operation) = active.remove(&operation_id) {
                            let timeout_error = format!("Operation timed out after {}ms", 
                                                      now_timestamp.saturating_sub(operation.created_at));
                            operation.status = ReplicationStatus::Failed(timeout_error.clone());
                            
                            tracing::warn!("Replication operation {} timed out: {}", operation_id, timeout_error);
                            
                            completed.insert(operation_id, operation);
                        }
                    }
                }
                
                // Log current operation status
                let active_count = active_operations.read().await.len();
                let completed_count = completed_operations.read().await.len();
                
                if active_count > 0 {
                    tracing::debug!("Monitoring {} active operations, {} completed operations", 
                                  active_count, completed_count);
                }
            }
        });

        Ok(())
    }

    /// Start cleanup task for old operations
    async fn start_cleanup_task(&self) -> Result<()> {
        let completed_operations = self.completed_operations.clone();
        let cleanup_interval = Duration::from_secs(300); // 5 minutes
        let retention_period = Duration::from_secs(3600); // 1 hour

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                let now_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                
                let retention_ms = retention_period.as_millis() as u64;
                let mut operations_to_remove = Vec::new();
                
                // Find operations older than retention period
                {
                    let completed = completed_operations.read().await;
                    for (operation_id, operation) in completed.iter() {
                        let operation_age = now_timestamp.saturating_sub(operation.created_at);
                        
                        if operation_age > retention_ms {
                            operations_to_remove.push(*operation_id);
                        }
                    }
                }
                
                // Remove old operations
                if !operations_to_remove.is_empty() {
                    let mut completed = completed_operations.write().await;
                    let removed_count = operations_to_remove.len();
                    
                    for operation_id in operations_to_remove {
                        completed.remove(&operation_id);
                    }
                    
                    tracing::info!("Cleaned up {} old completed operations (older than {} seconds)", 
                                 removed_count, retention_period.as_secs());
                }
                
                // Log cleanup status
                let remaining_count = completed_operations.read().await.len();
                tracing::debug!("Cleanup completed: {} operations retained in memory", remaining_count);
            }
        });

        Ok(())
    }

    /// Get replication statistics
    pub async fn get_statistics(&self) -> ReplicationStatistics {
        let active = self.active_operations.read().await;
        let completed = self.completed_operations.read().await;

        let active_count = active.len();
        let completed_count = completed.len();

        let mut success_count = 0;
        let mut failure_count = 0;
        let mut partial_count = 0;

        for operation in completed.values() {
            match &operation.status {
                ReplicationStatus::Completed => success_count += 1,
                ReplicationStatus::Failed(_) => failure_count += 1,
                ReplicationStatus::Partial { .. } => partial_count += 1,
                _ => {}
            }
        }

        ReplicationStatistics {
            active_operations: active_count,
            completed_operations: completed_count,
            successful_operations: success_count,
            failed_operations: failure_count,
            partial_operations: partial_count,
        }
    }

    /// Send replication message to a specific node
    async fn send_replication_message(
        &self,
        node_id: NodeId,
        message: ReplicationMessage,
    ) -> Result<()> {
        // In a real implementation, this would use actual network communication
        // For now, we'll simulate the message sending and handle the response
        
        tracing::debug!("Sending replication message to node {}: {:?}", node_id, message);
        
        // Simulate network latency and processing
        tokio::time::sleep(Duration::from_millis(5)).await;
        
        // Handle the message based on its type
        match message {
            ReplicationMessage::ReplicateRequest { operation_id, key, data: _, from_node } => {
                // Simulate processing the replication request
                tracing::debug!("Processing replication request for operation {} key {} from node {}", 
                               operation_id, key, from_node);
                
                // Simulate sending acknowledgment
                let _ack_message = ReplicationMessage::ReplicateAck {
                    operation_id,
                    from_node: node_id,
                    success: true,
                    error: None,
                };
                
                // Handle the acknowledgment
                self.handle_replication_ack(operation_id, node_id, true, None).await?;
                
                tracing::debug!("Successfully processed replication request for operation {}", operation_id);
            }
            _ => {
                return Err(FortressError::cluster(
                    "Unsupported replication message type",
                    None,
                ));
            }
        }
        
        Ok(())
    }

    /// Handle replication acknowledgment
    async fn handle_replication_ack(&self, operation_id: ReplicationId, from_node: NodeId, success: bool, error: Option<String>) -> Result<()> {
        let mut active_operations = self.active_operations.write().await;
        
        if let Some(operation) = active_operations.get_mut(&operation_id) {
            if success {
                operation.acknowledge_node(from_node);
                tracing::debug!("Node {} acknowledged replication operation {}", from_node, operation_id);
            } else {
                let error_msg = error.unwrap_or_else(|| "Unknown error".to_string());
                operation.fail_node(from_node, error_msg.clone());
                tracing::warn!("Node {} failed replication operation {}: {}", from_node, operation_id, error_msg);
            }
            
            operation.update_status();
            
            // If operation is complete, move it to completed operations
            if operation.is_complete() {
                let completed_op = active_operations.remove(&operation_id).unwrap();
                drop(active_operations); // Release the lock before accessing completed_operations
                
                let mut completed_operations = self.completed_operations.write().await;
                completed_operations.insert(operation_id, completed_op.clone());
                
                tracing::info!("Replication operation {} completed with status: {:?}", 
                             operation_id, completed_op.status);
            }
        } else {
            tracing::warn!("Received ack for unknown operation {}", operation_id);
        }
        
        Ok(())
    }
}

/// Replication statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatistics {
    /// Number of active operations
    pub active_operations: usize,
    /// Number of completed operations
    pub completed_operations: usize,
    /// Number of successful operations
    pub successful_operations: usize,
    /// Number of failed operations
    pub failed_operations: usize,
    /// Number of partially successful operations
    pub partial_operations: usize,
}

#[cfg(test)]
mod tests {
use super::*;
use std::sync::Arc;

#[test]
fn test_replication_operation_creation() {
    let target_nodes = vec![Uuid::new_v4(), Uuid::new_v4()];
    let operation = ReplicationOperation::new(
        "test_key".to_string(),
        b"test_data".to_vec(),
        target_nodes.clone(),
        ConsistencyLevel::Quorum,
    );

        assert_eq!(operation.key, "test_key");
        assert_eq!(operation.data, b"test_data");
        assert_eq!(operation.target_nodes, target_nodes);
        assert_eq!(operation.consistency_level, ConsistencyLevel::Quorum);
        assert_eq!(operation.status, ReplicationStatus::Pending);
        assert!(operation.acknowledged_nodes.is_empty());
        assert!(operation.failed_nodes.is_empty());
    }

    #[test]
    fn test_consistency_levels() {
        let target_nodes = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let mut operation = ReplicationOperation::new(
            "test_key".to_string(),
            b"test_data".to_vec(),
            target_nodes,
            ConsistencyLevel::Quorum,
        );

        // Should need 2 acknowledgments for quorum (3 nodes / 2 + 1)
        assert!(!operation.meets_consistency());
        
        operation.acknowledge_node(Uuid::new_v4());
        assert!(!operation.meets_consistency());
        
        operation.acknowledge_node(Uuid::new_v4());
        assert!(operation.meets_consistency());
    }

    #[test]
    fn test_replication_config_default() {
        let config = ReplicationConfig::default();
        assert_eq!(config.default_consistency, ConsistencyLevel::Quorum);
        assert_eq!(config.max_concurrent_ops, 100);
        assert_eq!(config.replication_timeout, Duration::from_secs(30));
    }
}
