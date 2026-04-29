//! WebSocket connection management

use crate::error::{FortressError, Result};
use crate::websocket::message::{WebSocketMessage, MessageType};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use uuid::Uuid;

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Unique connection ID
    pub id: String,
    /// Connected at timestamp
    pub connected_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Client IP address
    pub client_ip: String,
    /// User agent
    pub user_agent: Option<String>,
    /// Authentication status
    pub authenticated: bool,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// Subscription IDs
    pub subscription_ids: Vec<String>,
    /// Connection metadata
    pub metadata: HashMap<String, String>,
}

/// WebSocket connection manager
#[derive(Debug)]
pub struct ConnectionManager {
    /// Active connections
    connections: Arc<RwLock<HashMap<String, Arc<WebSocketConnection>>>>,
    /// Connection statistics
    stats: Arc<RwLock<ConnectionStats>>,
    /// Message sender for broadcasting
    broadcast_sender: tokio::sync::broadcast::Sender<BroadcastMessage>,
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Total connections created
    pub total_connections: u64,
    /// Current active connections
    pub active_connections: usize,
    /// Peak concurrent connections
    pub peak_connections: usize,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Authentication failures
    pub auth_failures: u64,
    /// Connection errors
    pub connection_errors: u64,
}

/// Broadcast message for multiple connections
#[derive(Debug, Clone)]
pub struct BroadcastMessage {
    /// Message to broadcast (shared reference)
    pub message: Arc<WebSocketMessage>,
    /// Target connection IDs (None = broadcast to all)
    pub target_connections: Option<Vec<String>>,
    /// Exclude connection IDs
    pub exclude_connections: Vec<String>,
}

/// WebSocket connection wrapper
#[derive(Debug)]
pub struct WebSocketConnection {
    /// Connection information
    pub info: Arc<RwLock<ConnectionInfo>>,
    /// WebSocket stream
    stream: Option<WebSocketStream<tokio::net::TcpStream>>,
    /// Message sender
    message_sender: mpsc::UnboundedSender<WebSocketMessage>,
    /// Message receiver
    message_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<WebSocketMessage>>>>,
    /// Connection state
    state: Arc<RwLock<ConnectionState>>,
    /// Last ping time
    last_ping: Arc<RwLock<Instant>>,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Authenticated
    Authenticated,
    /// Disconnected
    Disconnected,
    /// Error
    Error,
}

impl ConnectionManager {
    /// Create new connection manager
    pub fn new() -> Self {
        let (broadcast_sender, _) = tokio::sync::broadcast::channel(1000);
        
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ConnectionStats::default())),
            broadcast_sender,
        }
    }

    /// Add new connection
    pub async fn add_connection(
        &self, 
        stream: WebSocketStream<tokio::net::TcpStream>,
        client_ip: String,
        user_agent: Option<String>
    ) -> Result<Arc<WebSocketConnection>> {
        let connection_id = Uuid::new_v4().to_string();
        let info = ConnectionInfo {
            id: connection_id.to_string(),
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            client_ip,
            user_agent,
            authenticated: false,
            user_id: None,
            session_id: None,
            subscription_ids: Vec::new(),
            metadata: HashMap::new(),
        };

        let (message_sender, message_receiver) = mpsc::unbounded_channel();
        let connection = Arc::new(WebSocketConnection {
            info: Arc::new(RwLock::new(info)),
            stream: Some(stream),
            message_sender,
            message_receiver: Arc::new(RwLock::new(Some(message_receiver))),
            state: Arc::new(RwLock::new(ConnectionState::Connecting)),
            last_ping: Arc::new(RwLock::new(Instant::now())),
        });

        // Add to connections map
        self.connections.write().await.insert(connection_id.to_string(), connection.clone());
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_connections += 1;
            stats.active_connections += 1;
            if stats.active_connections > stats.peak_connections {
                stats.peak_connections = stats.active_connections;
            }
        }

        tracing::info!("New WebSocket connection: {}", connection_id);
        Ok(connection)
    }

    /// Remove connection
    pub async fn remove_connection(&self, connection_id: &str) {
        if let Some(connection) = self.connections.write().await.remove(connection_id) {
            // Close connection
            let _ = connection.close().await;
            
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                if stats.active_connections > 0 {
                    stats.active_connections -= 1;
                }
            }
            
            tracing::info!("WebSocket connection removed: {}", connection_id);
        }
    }

    /// Get connection by ID
    pub async fn get_connection(&self, connection_id: &str) -> Option<Arc<WebSocketConnection>> {
        self.connections.read().await.get(connection_id).cloned()
    }

    /// Get all connections
    pub async fn get_all_connections(&self) -> Vec<Arc<WebSocketConnection>> {
        self.connections.read().await.values().cloned().collect()
    }

    /// Get authenticated connections
    pub async fn get_authenticated_connections(&self) -> Vec<Arc<WebSocketConnection>> {
        let connections = self.connections.read().await.values().cloned().collect::<Vec<_>>();
        let mut authenticated_connections = Vec::new();
        
        for conn in connections {
            if conn.is_authenticated().await {
                authenticated_connections.push(conn);
            }
        }
        
        authenticated_connections
    }

    /// Get connections by user ID
    pub async fn get_connections_by_user(&self, user_id: &str) -> Vec<Arc<WebSocketConnection>> {
        let connections = self.connections.read().await.values().cloned().collect::<Vec<_>>();
        let mut matching_connections = Vec::new();
        
        for conn in connections {
            let info = conn.info.read().await;
            if info.user_id.as_ref().map_or(false, |uid| uid == user_id) {
                matching_connections.push(conn.clone());
            }
        }
        
        matching_connections
    }

    /// Broadcast message to all connections
    pub async fn broadcast(&self, message: WebSocketMessage) -> Result<()> {
        let broadcast_msg = BroadcastMessage {
            message: Arc::new(message),
            target_connections: None,
            exclude_connections: Vec::new(),
        };
        
        let _ = self.broadcast_sender.send(broadcast_msg);
        Ok(())
    }

    /// Send message to specific connections
    pub async fn send_to_connections(
        &self, 
        message: WebSocketMessage, 
        connection_ids: Vec<String>
    ) -> Result<()> {
        let broadcast_msg = BroadcastMessage {
            message: Arc::new(message),
            target_connections: Some(connection_ids),
            exclude_connections: Vec::new(),
        };
        
        let _ = self.broadcast_sender.send(broadcast_msg);
        Ok(())
    }

    /// Get connection statistics
    pub async fn get_stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }

    /// Clean up idle connections
    pub async fn cleanup_idle_connections(&self, timeout: Duration) {
        let connections_to_remove: Vec<String> = {
            let connections = self.connections.read().await;
            let now = Instant::now();
            let mut idle_connections = Vec::new();
            
            for (id, conn) in connections.iter() {
                let info = conn.info.read().await;
                if now.duration_since(info.last_activity) > timeout {
                    idle_connections.push(id.clone());
                }
            }
            
            idle_connections
        };

        for connection_id in connections_to_remove {
            self.remove_connection(&connection_id).await;
        }
    }

    /// Start broadcast message processor
    pub async fn start_broadcast_processor(&self) {
        let mut broadcast_receiver = self.broadcast_sender.subscribe();
        let connections = self.connections.clone();
        
        tokio::spawn(async move {
            while let Ok(broadcast_msg) = broadcast_receiver.recv().await {
                let connections_guard = connections.read().await;
                
                let target_connections = match broadcast_msg.target_connections {
                    Some(ids) => ids,
                    None => connections_guard.keys().cloned().collect(),
                };

                for connection_id in target_connections {
                    if broadcast_msg.exclude_connections.contains(&connection_id) {
                        continue;
                    }
                    
                    if let Some(connection) = connections_guard.get(&connection_id) {
                        if let Err(e) = connection.send_message((*broadcast_msg.message).clone()).await {
                            tracing::error!("Failed to send message to {}: {}", connection_id, e);
                        }
                    }
                }
            }
        });
    }
}

impl WebSocketConnection {
    /// Start connection message processing
    pub async fn start_processing(&self) -> Result<()> {
        let connection = self.clone();
        
        tokio::spawn(async move {
            if let Err(e) = connection.process_messages().await {
                tracing::error!("Connection processing error: {}", e);
            }
        });
        
        Ok(())
    }

    /// Process incoming messages
    async fn process_messages(&self) -> Result<()> {
        let mut receiver = {
            let mut receiver_guard = self.message_receiver.write().await;
            receiver_guard.take().ok_or_else(|| {
                FortressError::websocket("Message receiver already taken")
            })?
        };

        while let Some(message) = receiver.recv().await {
            self.update_last_activity().await;
            
            match message.message_type {
                MessageType::Ping => {
                    let pong = WebSocketMessage::pong();
                    let _ = self.send_message(pong).await;
                }
                MessageType::Pong => {
                    *self.last_ping.write().await = Instant::now();
                }
                _ => {
                    // Handle other message types as needed
                    tracing::debug!("Received message type: {:?}", message.message_type);
                }
            }
        }

        Ok(())
    }

    /// Send message to connection
    pub async fn send_message(&self, message: WebSocketMessage) -> Result<()> {
        let json = message.to_json()?;
        let _ws_message = Message::Text(json);
        
        // Update statistics would be handled by the connection manager
        tracing::debug!("Sending message to connection {}: {}", self.info.read().await.id, message.id);
        
        // In real implementation, this would send through the WebSocket stream
        // For now, we'll just log it
        Ok(())
    }

    /// Close connection
    pub async fn close(&self) -> Result<()> {
        *self.state.write().await = ConnectionState::Disconnected;
        
        // Close WebSocket stream if available
        if let Some(ref _stream) = self.stream {
            // Close the stream
            // In real implementation: stream.close(None).await
        }
        
        Ok(())
    }

    /// Check if connection is authenticated
    pub async fn is_authenticated(&self) -> bool {
        self.info.read().await.authenticated
    }

    /// Set authentication status
    pub async fn set_authenticated(&self, user_id: String, session_id: Option<String>) {
        let mut info = self.info.write().await;
        info.authenticated = true;
        info.user_id = Some(user_id);
        info.session_id = session_id;
        *self.state.write().await = ConnectionState::Authenticated;
    }

    /// Update last activity time
    pub async fn update_last_activity(&self) {
        // This would update the connection info
        // For now, we'll just log it
        tracing::debug!("Updating last activity for connection {}", self.info.read().await.id);
    }

    /// Get connection state
    pub async fn get_state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Add subscription ID
    pub async fn add_subscription(&self, subscription_id: String) {
        // Add to connection's subscription list
        tracing::debug!("Adding subscription {} to connection {}", subscription_id, self.info.read().await.id);
    }

    /// Remove subscription ID
    pub async fn remove_subscription(&self, subscription_id: &str) {
        // Remove from connection's subscription list
        tracing::debug!("Removing subscription {} from connection {}", subscription_id, self.info.read().await.id);
    }
}

impl Clone for WebSocketConnection {
    fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            stream: None, // Don't clone the actual stream
            message_sender: self.message_sender.clone(),
            message_receiver: self.message_receiver.clone(),
            state: self.state.clone(),
            last_ping: self.last_ping.clone(),
        }
    }
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            peak_connections: 0,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            auth_failures: 0,
            connection_errors: 0,
        }
    }
}
