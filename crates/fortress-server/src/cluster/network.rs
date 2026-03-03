//! # Network Module
//!
//! This module handles network communication between cluster nodes,
//! providing reliable message delivery and connection management.

use crate::cluster::{ClusterError, ClusterResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listen address for cluster communication
    pub listen_addr: String,
    /// Port for cluster communication
    pub cluster_port: u16,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
    /// Keep-alive interval in seconds
    pub keep_alive_interval_secs: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Enable TLS
    pub enable_tls: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS private key path
    pub tls_key_path: Option<String>,
    /// TLS CA certificate path
    pub tls_ca_path: Option<String>,
    /// Enable compression
    pub enable_compression: bool,
    /// Connection pool size
    pub connection_pool_size: usize,
    /// Retry attempts for failed connections
    pub max_retry_attempts: u32,
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            cluster_port: 8081,
            connection_timeout_ms: 30000,
            keep_alive_interval_secs: 30,
            max_message_size: 1048576, // 1MB
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            enable_compression: true,
            connection_pool_size: 10,
            max_retry_attempts: 3,
            retry_delay_ms: 1000,
        }
    }
}

/// Network message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Unique message identifier
    pub message_id: Uuid,
    /// Source node ID
    pub source: Uuid,
    /// Destination node ID (None for broadcast)
    pub destination: Option<Uuid>,
    /// Message type
    pub message_type: MessageType,
    /// Serialized message payload
    pub payload: Vec<u8>,
    /// Timestamp when message was created
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Message priority
    pub priority: MessagePriority,
    /// Message TTL (time to live) in seconds
    pub ttl_secs: u64,
    /// Retry count
    pub retry_count: u32,
}

/// Message types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum MessageType {
    /// Raft consensus message
    Raft,
    /// Node discovery message
    Discovery,
    /// Data replication message
    Replication,
    /// Failover message
    Failover,
    /// Cluster management message
    Management,
    /// Heartbeat message
    Heartbeat,
    /// Network control message
    NetworkControl,
}

/// Message priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    /// Low priority
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority
    High = 2,
    /// Critical priority
    Critical = 3,
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Remote node ID
    pub node_id: Uuid,
    /// Remote address
    pub address: SocketAddr,
    /// Connection state
    pub state: ConnectionState,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Connection latency in milliseconds
    pub latency_ms: u64,
}

/// Connection state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is active
    Connected,
    /// Connection is disconnected
    Disconnected,
    /// Connection failed
    Failed,
}

/// Network-specific errors
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Connection establishment failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    /// Message sending failed
    #[error("Message send failed: {0}")]
    MessageSendFailed(String),
    
    /// Message receiving failed
    #[error("Message receive failed: {0}")]
    MessageReceiveFailed(String),
    
    /// Connection establishment timed out
    #[error("Connection timeout")]
    ConnectionTimeout,
    
    /// Message exceeds maximum size
    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),
    
    /// Message format is invalid
    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),
    
    /// TLS/SSL error occurred
    #[error("TLS error: {0}")]
    TlsError(String),
    
    /// Network partition detected
    #[error("Network partition detected")]
    NetworkPartition,
    
    /// Failed to resolve network address
    #[error("Address resolution failed: {0}")]
    AddressResolutionFailed(String),
}

/// Network manager
pub struct NetworkManager {
    /// This node's ID
    node_id: Uuid,
    /// Configuration
    config: NetworkConfig,
    /// Active connections
    connections: Arc<RwLock<HashMap<Uuid, ConnectionInfo>>>,
    /// Message handlers
    message_handlers: Arc<Mutex<HashMap<MessageType, Box<dyn MessageHandler + Send + Sync>>>>,
    /// Network callbacks
    callbacks: Arc<Mutex<Vec<Box<dyn NetworkCallback + Send + Sync>>>>,
    /// Message queue for outgoing messages
    outgoing_queue: Arc<Mutex<Vec<NetworkMessage>>>,
    /// Message queue for incoming messages
    incoming_queue: Arc<Mutex<Vec<NetworkMessage>>>,
    /// Network statistics
    statistics: Arc<RwLock<NetworkStatistics>>,
}

/// Network statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkStatistics {
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Active connections
    pub active_connections: usize,
    /// Failed connections
    pub failed_connections: u64,
    /// Average latency in milliseconds
    pub average_latency_ms: f64,
    /// Message loss rate
    pub message_loss_rate: f64,
}

/// Callback trait for network events
#[async_trait::async_trait]
pub trait NetworkCallback {
    /// Called when a new connection is established
    async fn on_connection_established(&self, node_id: Uuid, address: SocketAddr);
    
    /// Called when a connection is lost
    async fn on_connection_lost(&self, node_id: Uuid, reason: &str);
    
    /// Called when a message is sent
    async fn on_message_sent(&self, message: &NetworkMessage, success: bool);
    
    /// Called when a message is received
    async fn on_message_received(&self, message: &NetworkMessage);
    
    /// Called when a network partition is detected
    async fn on_network_partition(&self, affected_nodes: Vec<Uuid>);
}

/// Trait for handling specific message types
#[async_trait::async_trait]
pub trait MessageHandler {
    /// Handle a network message
    async fn handle_message(&self, message: NetworkMessage) -> ClusterResult<Option<NetworkMessage>>;
    
    /// Get the message type this handler processes
    fn message_type(&self) -> MessageType;
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new(node_id: Uuid, config: NetworkConfig) -> Self {
        Self {
            node_id,
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            message_handlers: Arc::new(Mutex::new(HashMap::new())),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            outgoing_queue: Arc::new(Mutex::new(Vec::new())),
            incoming_queue: Arc::new(Mutex::new(Vec::new())),
            statistics: Arc::new(RwLock::new(NetworkStatistics::default())),
        }
    }

    /// Start the network manager
    pub async fn start(&self) -> ClusterResult<()> {
        info!("Starting network manager for node {}", self.node_id);
        
        // Start message processing loop
        let manager = self.clone();
        tokio::spawn(async move {
            manager.message_processing_loop().await;
        });

        // Start connection management loop
        let manager = self.clone();
        tokio::spawn(async move {
            manager.connection_management_loop().await;
        });

        // Start statistics collection loop
        let manager = self.clone();
        tokio::spawn(async move {
            manager.statistics_collection_loop().await;
        });

        // Start network listener
        self.start_listener().await?;

        Ok(())
    }

    /// Start network listener
    async fn start_listener(&self) -> ClusterResult<()> {
        let listen_addr = format!("{}:{}", self.config.listen_addr, self.config.cluster_port);
        info!("Starting network listener on {}", listen_addr);
        
        // In a real implementation, this would start a TCP/TLS listener
        // For now, this is a placeholder
        
        Ok(())
    }

    /// Message processing loop
    async fn message_processing_loop(&self) {
        let mut interval = interval(Duration::from_millis(10));
        
        loop {
            interval.tick().await;
            
            // Process outgoing messages
            if let Err(e) = self.process_outgoing_messages().await {
                error!("Failed to process outgoing messages: {}", e);
            }
            
            // Process incoming messages
            if let Err(e) = self.process_incoming_messages().await {
                error!("Failed to process incoming messages: {}", e);
            }
        }
    }

    /// Connection management loop
    async fn connection_management_loop(&self) {
        let mut interval = interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.manage_connections().await {
                error!("Connection management failed: {}", e);
            }
        }
    }

    /// Statistics collection loop
    async fn statistics_collection_loop(&self) {
        let mut interval = interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.update_statistics().await {
                error!("Statistics collection failed: {}", e);
            }
        }
    }

    /// Process outgoing messages
    async fn process_outgoing_messages(&self) -> ClusterResult<()> {
        // Get messages from queue
        let messages: Vec<_> = {
            let mut queue = self.outgoing_queue.lock().await;
            queue.drain(..).collect()
        };

        for message in messages {
            if let Err(e) = self.send_message_internal(message).await {
                error!("Failed to send message: {}", e);
            }
        }

        Ok(())
    }

    /// Process incoming messages
    async fn process_incoming_messages(&self) -> ClusterResult<()> {
        // Get messages from queue
        let messages: Vec<_> = {
            let mut queue = self.incoming_queue.lock().await;
            queue.drain(..).collect()
        };

        for message in messages {
            if let Err(e) = self.handle_message_internal(message).await {
                error!("Failed to handle message: {}", e);
            }
        }

        Ok(())
    }

    /// Manage connections
    async fn manage_connections(&self) -> ClusterResult<()> {
        let now = Instant::now();
        let timeout_duration = Duration::from_secs(self.config.keep_alive_interval_secs);
        
        let mut connections_to_remove = Vec::new();
        
        {
            let connections = self.connections.read().await;
            for (node_id, conn_info) in connections.iter() {
                if now.duration_since(conn_info.last_activity) > timeout_duration {
                    connections_to_remove.push(*node_id);
                }
            }
        }

        // Remove stale connections
        for node_id in connections_to_remove {
            self.remove_connection(node_id, "timeout").await?;
        }

        // Update statistics
        {
            let mut stats = self.statistics.write().await;
            let connections = self.connections.read().await;
            stats.active_connections = connections.len();
        }

        Ok(())
    }

    /// Update network statistics
    async fn update_statistics(&self) -> ClusterResult<()> {
        let connections = self.connections.read().await;
        
        if !connections.is_empty() {
            let total_latency: u64 = connections.values()
                .map(|conn| conn.latency_ms)
                .sum();
            
            let average_latency = total_latency as f64 / connections.len() as f64;
            
            let mut stats = self.statistics.write().await;
            stats.average_latency_ms = average_latency;
        }

        Ok(())
    }

    /// Send a message to a specific node
    pub async fn send_message(&self, destination: Uuid, message_type: MessageType, payload: Vec<u8>, priority: MessagePriority) -> ClusterResult<()> {
        let message = NetworkMessage {
            message_id: Uuid::new_v4(),
            source: self.node_id,
            destination: Some(destination),
            message_type,
            payload,
            timestamp: chrono::Utc::now(),
            priority,
            ttl_secs: 60, // Default TTL
            retry_count: 0,
        };

        // Add to outgoing queue
        {
            let mut queue = self.outgoing_queue.lock().await;
            queue.push(message);
        }

        Ok(())
    }

    /// Broadcast a message to all nodes
    pub async fn broadcast_message(&self, message_type: MessageType, payload: Vec<u8>, priority: MessagePriority) -> ClusterResult<()> {
        let message = NetworkMessage {
            message_id: Uuid::new_v4(),
            source: self.node_id,
            destination: None, // None means broadcast
            message_type,
            payload,
            timestamp: chrono::Utc::now(),
            priority,
            ttl_secs: 60,
            retry_count: 0,
        };

        // Add to outgoing queue
        {
            let mut queue = self.outgoing_queue.lock().await;
            queue.push(message);
        }

        Ok(())
    }

    /// Send message internally
    async fn send_message_internal(&self, message: NetworkMessage) -> ClusterResult<()> {
        // Check TTL
        let elapsed = chrono::Utc::now().signed_duration_since(message.timestamp);
        if elapsed.num_seconds() > message.ttl_secs as i64 {
            warn!("Message {} expired, dropping", message.message_id);
            return Ok(());
        }

        match message.destination {
            Some(destination) => {
                // Send to specific node
                self.send_to_node(destination, message).await?;
            }
            None => {
                // Broadcast to all nodes
                self.broadcast_to_all_nodes(message).await?;
            }
        }

        Ok(())
    }

    /// Send message to specific node
    async fn send_to_node(&self, destination: Uuid, message: NetworkMessage) -> ClusterResult<()> {
        let connections = self.connections.read().await;
        
        if let Some(conn_info) = connections.get(&destination) {
            // Check if connection is active
            if conn_info.state == ConnectionState::Connected {
                // Send message
                if let Err(e) = self.transmit_message(conn_info.address, &message).await {
                    error!("Failed to transmit message to {}: {}", destination, e);
                    
                    // Update statistics
                    {
                        let mut stats = self.statistics.write().await;
                        stats.failed_connections += 1;
                    }
                    
                    return Err(e);
                }
                
                // Update connection statistics
                drop(connections);
                self.update_connection_stats(destination, message.payload.len(), true).await;
                
                // Update global statistics
                {
                    let mut stats = self.statistics.write().await;
                    stats.messages_sent += 1;
                    stats.bytes_sent += message.payload.len() as u64;
                }
                
                // Notify callbacks
                let callbacks = self.callbacks.lock().await;
                for callback in callbacks.iter() {
                    callback.on_message_sent(&message, true).await;
                }
            } else {
                // Connection not active, try to reconnect
                drop(connections);
                if let Err(e) = self.establish_connection(destination).await {
                    error!("Failed to establish connection to {}: {}", destination, e);
                    return Err(e);
                }
                
                // Retry sending with a boxed future to avoid recursion
                return Box::pin(self.send_to_node(destination, message)).await;
            }
        } else {
            // No connection exists, try to establish one
            if let Err(e) = self.establish_connection(destination).await {
                error!("Failed to establish connection to {}: {}", destination, e);
                return Err(e);
            }
            
            // Retry sending with a boxed future to avoid recursion
            return Box::pin(self.send_to_node(destination, message)).await;
        }

        Ok(())
    }

    /// Broadcast message to all nodes
    async fn broadcast_to_all_nodes(&self, message: NetworkMessage) -> ClusterResult<()> {
        let connections = self.connections.read().await;
        let node_ids: Vec<Uuid> = connections.keys().cloned().collect();
        drop(connections);

        for node_id in node_ids {
            if let Err(e) = self.send_to_node(node_id, message.clone()).await {
                warn!("Failed to broadcast to node {}: {}", node_id, e);
            }
        }

        Ok(())
    }

    /// Transmit message over network
    async fn transmit_message(&self, address: SocketAddr, message: &NetworkMessage) -> ClusterResult<()> {
        // Serialize message
        let serialized = serde_json::to_vec(message)
            .map_err(|e| ClusterError::Network(NetworkError::InvalidMessageFormat(e.to_string())))?;

        // Check message size
        if serialized.len() > self.config.max_message_size {
            return Err(ClusterError::Network(NetworkError::MessageTooLarge(serialized.len())));
        }

        // In a real implementation, this would send the message over TCP/TLS
        // For now, this is a placeholder
        
        debug!("Transmitting message {} to {}", message.message_id, address);
        
        Ok(())
    }

    /// Handle incoming message
    async fn handle_message_internal(&self, message: NetworkMessage) -> ClusterResult<()> {
        // Update statistics
        {
            let mut stats = self.statistics.write().await;
            stats.messages_received += 1;
            stats.bytes_received += message.payload.len() as u64;
        }

        // Update connection activity
        let source = message.source;
        self.update_connection_stats(source, message.payload.len(), false).await;

        // Notify callbacks
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            callback.on_message_received(&message).await;
        }

        // Route to appropriate handler
        let handlers = self.message_handlers.lock().await;
        if let Some(handler) = handlers.get(&message.message_type) {
            if let Err(e) = handler.handle_message(message).await {
                error!("Message handler failed: {}", e);
            }
        } else {
            warn!("No handler for message type: {:?}", message.message_type);
        }

        Ok(())
    }

    /// Establish connection to a node
    async fn establish_connection(&self, node_id: Uuid) -> ClusterResult<()> {
        info!("Establishing connection to node {}", node_id);
        
        // In a real implementation, this would resolve the node's address
        // and establish a TCP/TLS connection
        let address = format!("127.0.0.1:{}", self.config.cluster_port)
            .parse::<SocketAddr>()
            .map_err(|e| ClusterError::Network(NetworkError::AddressResolutionFailed(e.to_string())))?;

        let connection_info = ConnectionInfo {
            node_id,
            address,
            state: ConnectionState::Connected,
            last_activity: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: 0,
        };

        // Add connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(node_id, connection_info);
        }

        // Notify callbacks
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            callback.on_connection_established(node_id, address).await;
        }

        Ok(())
    }

    /// Remove connection
    async fn remove_connection(&self, node_id: Uuid, reason: &str) -> ClusterResult<()> {
        info!("Removing connection to node {}: {}", node_id, reason);
        
        let address = {
            let mut connections = self.connections.write().await;
            connections.remove(&node_id).map(|conn| conn.address)
        };

        if let Some(_address) = address {
            // Notify callbacks
            let callbacks = self.callbacks.lock().await;
            for callback in callbacks.iter() {
                callback.on_connection_lost(node_id, reason).await;
            }
        }

        Ok(())
    }

    /// Update connection statistics
    async fn update_connection_stats(&self, node_id: Uuid, bytes: usize, is_sent: bool) {
        let mut connections = self.connections.write().await;
        
        if let Some(conn_info) = connections.get_mut(&node_id) {
            conn_info.last_activity = Instant::now();
            
            if is_sent {
                conn_info.messages_sent += 1;
                conn_info.bytes_sent += bytes as u64;
            } else {
                conn_info.messages_received += 1;
                conn_info.bytes_received += bytes as u64;
            }
        }
    }

    /// Register message handler
    pub async fn register_handler(&self, handler: Box<dyn MessageHandler + Send + Sync>) {
        let mut handlers = self.message_handlers.lock().await;
        handlers.insert(handler.message_type(), handler);
    }

    /// Add network callback
    pub async fn add_callback(&self, callback: Box<dyn NetworkCallback + Send + Sync>) {
        let mut callbacks = self.callbacks.lock().await;
        callbacks.push(callback);
    }

    /// Get network statistics
    pub async fn get_statistics(&self) -> NetworkStatistics {
        self.statistics.read().await.clone()
    }

    /// Get connection information
    pub async fn get_connection_info(&self, node_id: Uuid) -> Option<ConnectionInfo> {
        self.connections.read().await.get(&node_id).cloned()
    }

    /// Get all connections
    pub async fn get_all_connections(&self) -> HashMap<Uuid, ConnectionInfo> {
        self.connections.read().await.clone()
    }
}

impl Clone for NetworkManager {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            config: self.config.clone(),
            connections: Arc::clone(&self.connections),
            message_handlers: Arc::clone(&self.message_handlers),
            callbacks: Arc::clone(&self.callbacks),
            outgoing_queue: Arc::clone(&self.outgoing_queue),
            incoming_queue: Arc::clone(&self.incoming_queue),
            statistics: Arc::clone(&self.statistics),
        }
    }
}
