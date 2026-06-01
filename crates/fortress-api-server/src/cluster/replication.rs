//! # Data Replication Module
//!
//! This module handles data replication across cluster nodes,
//! ensuring consistency and durability of stored data.

use crate::cluster::{ClusterError, ClusterResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Replication factor (number of copies)
    pub replication_factor: usize,
    /// Write consistency level
    pub write_consistency: ConsistencyLevel,
    /// Read consistency level
    pub read_consistency: ConsistencyLevel,
    /// Replication timeout in milliseconds
    pub replication_timeout_ms: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Enable anti-entropy repair
    pub enable_anti_entropy: bool,
    /// Anti-entropy interval in seconds
    pub anti_entropy_interval_secs: u64,
    /// Enable read repair
    pub enable_read_repair: bool,
    /// Batch size for replication
    pub batch_size: usize,
    /// Compression for replication data
    pub enable_compression: bool,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            write_consistency: ConsistencyLevel::Quorum,
            read_consistency: ConsistencyLevel::Quorum,
            replication_timeout_ms: 5000,
            max_retries: 3,
            enable_anti_entropy: true,
            anti_entropy_interval_secs: 3600, // 1 hour
            enable_read_repair: true,
            batch_size: 100,
            enable_compression: true,
        }
    }
}

/// Consistency levels for operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    /// Only one node needs to acknowledge
    One,
    /// Majority of nodes need to acknowledge
    Quorum,
    /// All nodes need to acknowledge
    All,
    /// Custom number of nodes
    Custom(usize),
}

impl ConsistencyLevel {
    /// Get the required number of acknowledgments
    pub fn required_acks(&self, total_nodes: usize) -> usize {
        match self {
            ConsistencyLevel::One => 1,
            ConsistencyLevel::Quorum => (total_nodes / 2) + 1,
            ConsistencyLevel::All => total_nodes,
            ConsistencyLevel::Custom(n) => std::cmp::min(*n, total_nodes),
        }
    }
}

/// Replication operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationOperation {
    /// Unique operation identifier
    pub operation_id: Uuid,
    /// Operation type
    pub operation_type: OperationType,
    /// Key being replicated
    pub key: String,
    /// Data value (for writes)
    pub value: Option<Vec<u8>>,
    /// Timestamp of operation
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Node that initiated the operation
    pub source_node: Uuid,
    /// Target nodes for replication
    pub target_nodes: Vec<Uuid>,
    /// Current replication status
    pub status: ReplicationStatus,
    /// Number of acknowledgments received
    pub ack_count: usize,
    /// Required acknowledgments
    pub required_acks: usize,
}

/// Operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    /// Write operation
    Write,
    /// Delete operation
    Delete,
    /// Read operation (for read repair)
    Read,
}

/// Replication status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationStatus {
    /// Operation is pending
    Pending,
    /// Operation is in progress
    InProgress,
    /// Operation completed successfully
    Completed,
    /// Operation failed
    Failed,
    /// Operation timed out
    TimedOut,
}

/// Replication message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationMessage {
    /// Replication request
    ReplicationRequest {
        /// The replication operation to perform
        operation: ReplicationOperation,
    },

    /// Replication response
    ReplicationResponse {
        /// Unique identifier for the operation
        operation_id: Uuid,
        /// ID of the responding node
        node_id: Uuid,
        /// Whether the operation was successful
        success: bool,
        /// When the response was generated
        timestamp: chrono::DateTime<chrono::Utc>,
        /// Error message if the operation failed
        error_message: Option<String>,
    },

    /// Anti-entropy request
    AntiEntropyRequest {
        /// ID of the requesting node
        node_id: Uuid,
        /// Optional key range for anti-entropy
        key_range: Option<(String, String)>,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Anti-entropy response
    AntiEntropyResponse {
        /// ID of the requesting node
        requester_id: Uuid,
        /// Data for anti-entropy repair
        data: Vec<(String, Vec<u8>, chrono::DateTime<chrono::Utc>)>,
        /// When the response was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Read repair request
    ReadRepairRequest {
        /// Key to repair
        key: String,
        /// ID of the requesting node
        node_id: Uuid,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Read repair response
    ReadRepairResponse {
        /// Key being repaired
        key: String,
        /// Value for the key (if available)
        value: Option<Vec<u8>>,
        /// When the response was sent
        timestamp: chrono::DateTime<chrono::Utc>,
        /// ID of the responding node
        node_id: Uuid,
    },
}

/// Replication-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    /// Replication operation failed
    #[error("Replication failed: {0}")]
    ReplicationFailed(String),

    /// Not enough replicas available
    #[error("Insufficient replicas: {0}/{1}")]
    InsufficientReplicas(usize, usize),

    /// Replication operation timed out
    #[error("Replication timeout")]
    ReplicationTimeout,

    /// Data inconsistency detected between replicas
    #[error("Data inconsistency detected")]
    DataInconsistency,

    /// Invalid replication factor specified
    #[error("Invalid replication factor: {0}")]
    InvalidReplicationFactor(usize),

    /// Node not available for replication
    #[error("Node not available for replication: {0}")]
    NodeNotAvailable(Uuid),

    /// Anti-entropy process failed
    #[error("Anti-entropy failed: {0}")]
    AntiEntropyFailed(String),
}

/// Data replicator
pub struct DataReplicator {
    /// This node's ID
    node_id: Uuid,
    /// Configuration
    config: ReplicationConfig,
    /// Known cluster nodes
    cluster_nodes: Arc<RwLock<HashSet<Uuid>>>,
    /// Pending operations
    pending_operations: Arc<RwLock<HashMap<Uuid, ReplicationOperation>>>,
    /// Replication callbacks
    callbacks: Arc<Mutex<Vec<Box<dyn ReplicationCallback + Send + Sync>>>>,
    /// Network sender
    network_sender: Arc<Mutex<dyn ReplicationNetworkSender + Send + Sync>>,
    /// Local storage interface
    storage: Arc<Mutex<dyn ReplicationStorage + Send + Sync>>,
}

/// Callback trait for replication events
#[async_trait::async_trait]
pub trait ReplicationCallback {
    /// Called when a replication operation completes successfully
    async fn on_replication_completed(&self, operation: &ReplicationOperation);

    /// Called when a replication operation fails
    async fn on_replication_failed(&self, operation: &ReplicationOperation, error: &str);

    /// Called when data inconsistency is detected
    async fn on_inconsistency_detected(&self, key: &str, conflicting_data: Vec<(Uuid, Vec<u8>)>);
}

/// Trait for network replication operations
#[async_trait::async_trait]
pub trait ReplicationNetworkSender {
    /// Send a replication message to a specific node
    async fn send_replication_message(
        &self,
        target: Uuid,
        message: ReplicationMessage,
    ) -> ClusterResult<()>;

    /// Broadcast a replication message to all nodes
    async fn broadcast_replication_message(&self, message: ReplicationMessage)
        -> ClusterResult<()>;
}

/// Trait for local storage operations
#[async_trait::async_trait]
pub trait ReplicationStorage {
    /// Get a value from storage
    async fn get(&self, key: &str) -> ClusterResult<Option<Vec<u8>>>;

    /// Put a value into storage
    async fn put(&self, key: &str, value: Vec<u8>) -> ClusterResult<()>;

    /// Delete a value from storage
    async fn delete(&self, key: &str) -> ClusterResult<()>;

    /// List keys with optional prefix
    async fn list_keys(&self, prefix: Option<&str>) -> ClusterResult<Vec<String>>;

    /// Get the timestamp for a key
    async fn get_timestamp(
        &self,
        key: &str,
    ) -> ClusterResult<Option<chrono::DateTime<chrono::Utc>>>;
}

impl DataReplicator {
    /// Create a new data replicator
    pub fn new(
        node_id: Uuid,
        config: ReplicationConfig,
        network_sender: Arc<Mutex<dyn ReplicationNetworkSender + Send + Sync>>,
        storage: Arc<Mutex<dyn ReplicationStorage + Send + Sync>>,
    ) -> Self {
        Self {
            node_id,
            config,
            cluster_nodes: Arc::new(RwLock::new(HashSet::new())),
            pending_operations: Arc::new(RwLock::new(HashMap::new())),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            network_sender,
            storage,
        }
    }

    /// Start the replicator
    pub async fn start(&self) -> ClusterResult<()> {
        info!("Starting data replicator for node {}", self.node_id);

        // Start operation timeout checker
        let replicator = self.clone();
        tokio::spawn(async move {
            replicator.timeout_checker().await;
        });

        // Start anti-entropy process
        if self.config.enable_anti_entropy {
            let replicator = self.clone();
            tokio::spawn(async move {
                replicator.anti_entropy_loop().await;
            });
        }

        Ok(())
    }

    /// Replicate a write operation
    pub async fn replicate_write(&self, key: &str, value: Vec<u8>) -> ClusterResult<()> {
        let operation_id = Uuid::new_v4();
        let target_nodes = self.select_replication_nodes(key).await?;

        let required_acks = self
            .config
            .write_consistency
            .required_acks(target_nodes.len() + 1); // +1 for local

        let operation = ReplicationOperation {
            operation_id,
            operation_type: OperationType::Write,
            key: key.to_string(),
            value: Some(value.clone()),
            timestamp: chrono::Utc::now(),
            source_node: self.node_id,
            target_nodes: target_nodes.clone(),
            status: ReplicationStatus::Pending,
            ack_count: 0,
            required_acks,
        };

        // Store locally first
        {
            let storage = self.storage.lock().await;
            storage.put(key, value).await?;
        }

        // Add to pending operations
        {
            let mut pending = self.pending_operations.write().await;
            pending.insert(operation_id, operation.clone());
        }

        // Send replication requests
        for target_node in target_nodes {
            let message = ReplicationMessage::ReplicationRequest {
                operation: operation.clone(),
            };

            let sender = self.network_sender.lock().await;
            if let Err(e) = sender.send_replication_message(target_node, message).await {
                warn!(
                    "Failed to send replication request to {}: {}",
                    target_node, e
                );
            }
        }

        // Wait for acknowledgments
        self.wait_for_replication_completion(operation_id).await
    }

    /// Replicate a delete operation
    pub async fn replicate_delete(&self, key: &str) -> ClusterResult<()> {
        let operation_id = Uuid::new_v4();
        let target_nodes = self.select_replication_nodes(key).await?;

        let required_acks = self
            .config
            .write_consistency
            .required_acks(target_nodes.len() + 1);

        let operation = ReplicationOperation {
            operation_id,
            operation_type: OperationType::Delete,
            key: key.to_string(),
            value: None,
            timestamp: chrono::Utc::now(),
            source_node: self.node_id,
            target_nodes: target_nodes.clone(),
            status: ReplicationStatus::Pending,
            ack_count: 0,
            required_acks,
        };

        // Delete locally first
        {
            let storage = self.storage.lock().await;
            storage.delete(key).await?;
        }

        // Add to pending operations
        {
            let mut pending = self.pending_operations.write().await;
            pending.insert(operation_id, operation.clone());
        }

        // Send replication requests
        for target_node in target_nodes {
            let message = ReplicationMessage::ReplicationRequest {
                operation: operation.clone(),
            };

            let sender = self.network_sender.lock().await;
            if let Err(e) = sender.send_replication_message(target_node, message).await {
                warn!(
                    "Failed to send delete replication request to {}: {}",
                    target_node, e
                );
            }
        }

        // Wait for acknowledgments
        self.wait_for_replication_completion(operation_id).await
    }

    /// Read with consistency guarantee
    pub async fn consistent_read(&self, key: &str) -> ClusterResult<Option<Vec<u8>>> {
        let target_nodes = self.select_replication_nodes(key).await?;
        let _required_reads = self
            .config
            .read_consistency
            .required_acks(target_nodes.len() + 1);

        // Read locally first
        let local_value = {
            let storage = self.storage.lock().await;
            storage.get(key).await?
        };

        let mut responses = Vec::new();
        responses.push((self.node_id, local_value.clone()));

        // Read from other nodes
        for target_node in target_nodes {
            let message = ReplicationMessage::ReadRepairRequest {
                key: key.to_string(),
                node_id: self.node_id,
                timestamp: chrono::Utc::now(),
            };

            let sender = self.network_sender.lock().await;
            if let Ok(_response) = sender.send_replication_message(target_node, message).await {
                // In a real implementation, we'd wait for responses
                // For now, this is simplified
            }
        }

        // Check for consistency and perform read repair if needed
        if self.config.enable_read_repair {
            self.perform_read_repair(key, &responses).await?;
        }

        Ok(local_value)
    }

    /// Select nodes for replication
    async fn select_replication_nodes(&self, key: &str) -> ClusterResult<Vec<Uuid>> {
        let cluster_nodes = self.cluster_nodes.read().await;
        let available_nodes: Vec<Uuid> = cluster_nodes.iter().cloned().collect();
        drop(cluster_nodes);

        if available_nodes.len() < self.config.replication_factor - 1 {
            return Err(ClusterError::Replication(
                ReplicationError::InsufficientReplicas(
                    available_nodes.len(),
                    self.config.replication_factor - 1,
                ),
            ));
        }

        // Simple hash-based selection for now
        // In a real implementation, this would use consistent hashing
        let mut nodes = Vec::new();
        let hash = self.hash_key(key);

        for (i, &node_id) in available_nodes.iter().enumerate() {
            if (hash as usize + i) % available_nodes.len() < self.config.replication_factor - 1 {
                nodes.push(node_id);
            }
        }

        Ok(nodes)
    }

    /// Simple hash function for key-based node selection
    fn hash_key(&self, key: &str) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as u32
    }

    /// Wait for replication completion
    async fn wait_for_replication_completion(&self, operation_id: Uuid) -> ClusterResult<()> {
        let timeout_duration = Duration::from_millis(self.config.replication_timeout_ms);

        let start_time = Instant::now();
        while start_time.elapsed() < timeout_duration {
            {
                let pending = self.pending_operations.read().await;
                if let Some(operation) = pending.get(&operation_id) {
                    if operation.status == ReplicationStatus::Completed {
                        return Ok(());
                    }
                    if operation.status == ReplicationStatus::Failed
                        || operation.status == ReplicationStatus::TimedOut
                    {
                        return Err(ClusterError::Replication(
                            ReplicationError::ReplicationFailed("Operation failed".to_string()),
                        ));
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Mark as timed out
        {
            let mut pending = self.pending_operations.write().await;
            if let Some(operation) = pending.get_mut(&operation_id) {
                operation.status = ReplicationStatus::TimedOut;
            }
        }

        Err(ClusterError::Replication(
            ReplicationError::ReplicationTimeout,
        ))
    }

    /// Handle incoming replication message
    pub async fn handle_message(
        &self,
        source: Uuid,
        message: ReplicationMessage,
    ) -> ClusterResult<Option<ReplicationMessage>> {
        match message {
            ReplicationMessage::ReplicationRequest { operation } => {
                self.handle_replication_request(source, operation).await
            }
            ReplicationMessage::ReplicationResponse {
                operation_id,
                node_id,
                success,
                timestamp,
                error_message,
            } => {
                self.handle_replication_response(
                    operation_id,
                    node_id,
                    success,
                    timestamp,
                    error_message,
                )
                .await?;
                Ok(None)
            }
            ReplicationMessage::AntiEntropyRequest {
                node_id,
                key_range,
                timestamp,
            } => {
                self.handle_anti_entropy_request(node_id, key_range, timestamp)
                    .await
            }
            ReplicationMessage::AntiEntropyResponse {
                requester_id,
                data,
                timestamp,
            } => {
                self.handle_anti_entropy_response(requester_id, data, timestamp)
                    .await?;
                Ok(None)
            }
            ReplicationMessage::ReadRepairRequest {
                key,
                node_id,
                timestamp,
            } => {
                self.handle_read_repair_request(key, node_id, timestamp)
                    .await
            }
            ReplicationMessage::ReadRepairResponse {
                key,
                value,
                timestamp,
                node_id,
            } => {
                self.handle_read_repair_response(key, value, timestamp, node_id)
                    .await?;
                Ok(None)
            }
        }
    }

    /// Handle replication request
    async fn handle_replication_request(
        &self,
        _source: Uuid,
        operation: ReplicationOperation,
    ) -> ClusterResult<Option<ReplicationMessage>> {
        let success = match operation.operation_type {
            OperationType::Write => {
                if let Some(value) = &operation.value {
                    let storage = self.storage.lock().await;
                    storage.put(&operation.key, value.clone()).await.is_ok()
                } else {
                    false
                }
            }
            OperationType::Delete => {
                let storage = self.storage.lock().await;
                storage.delete(&operation.key).await.is_ok()
            }
            OperationType::Read => {
                // Read operations are handled differently
                true
            }
        };

        let response = ReplicationMessage::ReplicationResponse {
            operation_id: operation.operation_id,
            node_id: self.node_id,
            success,
            timestamp: chrono::Utc::now(),
            error_message: if success {
                None
            } else {
                Some("Operation failed".to_string())
            },
        };

        Ok(Some(response))
    }

    /// Handle replication response
    async fn handle_replication_response(
        &self,
        operation_id: Uuid,
        _node_id: Uuid,
        success: bool,
        _timestamp: chrono::DateTime<chrono::Utc>,
        error_message: Option<String>,
    ) -> ClusterResult<()> {
        let mut pending = self.pending_operations.write().await;

        if let Some(operation) = pending.get_mut(&operation_id) {
            if success {
                operation.ack_count += 1;

                if operation.ack_count >= operation.required_acks {
                    operation.status = ReplicationStatus::Completed;

                    // Notify callbacks
                    let callbacks = self.callbacks.lock().await;
                    for callback in callbacks.iter() {
                        callback.on_replication_completed(operation).await;
                    }
                }
            } else {
                operation.status = ReplicationStatus::Failed;

                // Notify callbacks
                let callbacks = self.callbacks.lock().await;
                for callback in callbacks.iter() {
                    callback
                        .on_replication_failed(
                            operation,
                            error_message.as_deref().unwrap_or("Unknown error"),
                        )
                        .await;
                }
            }
        }

        Ok(())
    }

    /// Handle anti-entropy request
    async fn handle_anti_entropy_request(
        &self,
        node_id: Uuid,
        key_range: Option<(String, String)>,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<Option<ReplicationMessage>> {
        let storage = self.storage.lock().await;
        let keys = storage
            .list_keys(key_range.as_ref().map(|(start, _)| start.as_str()))
            .await?;
        drop(storage);

        let mut data = Vec::new();
        for key in keys {
            if let Some((start, end)) = &key_range {
                if key < *start || key > *end {
                    continue;
                }
            }

            let storage = self.storage.lock().await;
            if let Ok(Some(value)) = storage.get(&key).await {
                if let Ok(Some(ts)) = storage.get_timestamp(&key).await {
                    data.push((key, value, ts));
                }
            }
        }

        let response = ReplicationMessage::AntiEntropyResponse {
            requester_id: node_id,
            data,
            timestamp: chrono::Utc::now(),
        };

        Ok(Some(response))
    }

    /// Handle anti-entropy response
    async fn handle_anti_entropy_response(
        &self,
        _requester_id: Uuid,
        data: Vec<(String, Vec<u8>, chrono::DateTime<chrono::Utc>)>,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<()> {
        for (key, value, ts) in data {
            let storage = self.storage.lock().await;

            // Check if we need to update
            let should_update = match storage.get_timestamp(&key).await {
                Ok(Some(local_ts)) => ts > local_ts,
                Ok(None) => true,
                Err(_) => false,
            };

            if should_update {
                if let Err(e) = storage.put(&key, value).await {
                    error!("Failed to update key {} during anti-entropy: {}", key, e);
                }
            }
        }

        Ok(())
    }

    /// Handle read repair request
    async fn handle_read_repair_request(
        &self,
        key: String,
        _node_id: Uuid,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<Option<ReplicationMessage>> {
        let storage = self.storage.lock().await;
        let value = storage.get(&key).await?;
        drop(storage);

        let response = ReplicationMessage::ReadRepairResponse {
            key,
            value,
            timestamp: chrono::Utc::now(),
            node_id: self.node_id,
        };

        Ok(Some(response))
    }

    /// Handle read repair response
    async fn handle_read_repair_response(
        &self,
        key: String,
        _value: Option<Vec<u8>>,
        _timestamp: chrono::DateTime<chrono::Utc>,
        node_id: Uuid,
    ) -> ClusterResult<()> {
        // Read repair logic would go here
        // For now, this is a placeholder
        debug!(
            "Received read repair response for key {} from node {}",
            key, node_id
        );
        Ok(())
    }

    /// Perform read repair
    async fn perform_read_repair(
        &self,
        key: &str,
        responses: &[(Uuid, Option<Vec<u8>>)],
    ) -> ClusterResult<()> {
        // Simple read repair logic - in a real implementation, this would be more sophisticated
        let mut value_counts: HashMap<Option<Vec<u8>>, usize> = HashMap::new();

        for (_, value) in responses {
            *value_counts.entry(value.clone()).or_insert(0) += 1;
        }

        // Find the most common value
        let (most_common_value, _) = value_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(value, count)| (value.clone(), *count))
            .unwrap_or((None, 0));

        // Update nodes that have different values
        for (node_id, value) in responses {
            if *value != most_common_value {
                if let Some(ref correct_value) = most_common_value {
                    // Send correction to this node
                    let message = ReplicationMessage::ReadRepairResponse {
                        key: key.to_string(),
                        value: Some(correct_value.clone()),
                        timestamp: chrono::Utc::now(),
                        node_id: self.node_id,
                    };

                    let sender = self.network_sender.lock().await;
                    if let Err(e) = sender.send_replication_message(*node_id, message).await {
                        warn!("Failed to send read repair to {}: {}", node_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Timeout checker for pending operations
    async fn timeout_checker(&self) {
        let mut interval = interval(Duration::from_secs(1));

        loop {
            interval.tick().await;

            let now = chrono::Utc::now();
            let mut operations_to_remove = Vec::new();

            {
                let mut pending = self.pending_operations.write().await;
                for (operation_id, operation) in pending.iter_mut() {
                    let elapsed = now.signed_duration_since(operation.timestamp);
                    if elapsed.num_milliseconds() > self.config.replication_timeout_ms as i64 {
                        operation.status = ReplicationStatus::TimedOut;
                        operations_to_remove.push(*operation_id);
                    }
                }
            }

            for operation_id in operations_to_remove {
                let mut pending = self.pending_operations.write().await;
                if let Some(operation) = pending.remove(&operation_id) {
                    let callbacks = self.callbacks.lock().await;
                    for callback in callbacks.iter() {
                        callback
                            .on_replication_failed(&operation, "Operation timed out")
                            .await;
                    }
                }
            }
        }
    }

    /// Anti-entropy loop
    async fn anti_entropy_loop(&self) {
        let mut interval = interval(Duration::from_secs(self.config.anti_entropy_interval_secs));

        loop {
            interval.tick().await;

            if let Err(e) = self.perform_anti_entropy().await {
                error!("Anti-entropy failed: {}", e);
            }
        }
    }

    /// Perform anti-entropy repair
    async fn perform_anti_entropy(&self) -> ClusterResult<()> {
        let cluster_nodes = self.cluster_nodes.read().await;

        for &node_id in cluster_nodes.iter() {
            let message = ReplicationMessage::AntiEntropyRequest {
                node_id: self.node_id,
                key_range: None, // Repair all keys
                timestamp: chrono::Utc::now(),
            };

            let sender = self.network_sender.lock().await;
            if let Err(e) = sender.send_replication_message(node_id, message).await {
                warn!("Failed to send anti-entropy request to {}: {}", node_id, e);
            }
        }

        Ok(())
    }

    /// Add cluster node
    pub async fn add_node(&self, node_id: Uuid) {
        let mut nodes = self.cluster_nodes.write().await;
        nodes.insert(node_id);
    }

    /// Remove cluster node
    pub async fn remove_node(&self, node_id: Uuid) {
        let mut nodes = self.cluster_nodes.write().await;
        nodes.remove(&node_id);
    }

    /// Add replication callback
    pub async fn add_callback(&self, callback: Box<dyn ReplicationCallback + Send + Sync>) {
        let mut callbacks = self.callbacks.lock().await;
        callbacks.push(callback);
    }
}

impl Clone for DataReplicator {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            config: self.config.clone(),
            cluster_nodes: Arc::clone(&self.cluster_nodes),
            pending_operations: Arc::clone(&self.pending_operations),
            callbacks: Arc::clone(&self.callbacks),
            network_sender: Arc::clone(&self.network_sender),
            storage: Arc::clone(&self.storage),
        }
    }
}
