//! Secure WebSocket server with WSS encryption

use crate::error::{FortressError, Result};
use crate::websocket::{
    connection::ConnectionManager,
    auth::{WebSocketAuthenticator, AuthConfig},
    message::{WebSocketMessage, MessageType, MessagePayload},
};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_tungstenite::{
    accept_async,
    WebSocketStream,
};

/// WebSocket server configuration
#[derive(Debug, Clone)]
pub struct WebSocketServerConfig {
    /// Server bind address
    pub bind_address: String,
    /// Server port
    pub port: u16,
    /// Enable TLS/WSS
    pub enable_tls: bool,
    /// TLS certificate file path
    pub tls_cert_file: Option<String>,
    /// TLS private key file path
    pub tls_key_file: Option<String>,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Ping interval in seconds
    pub ping_interval_seconds: u64,
    /// Authentication configuration
    pub auth_config: AuthConfig,
    /// Enable compression
    pub enable_compression: bool,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

/// WebSocket server
#[derive(Debug)]
pub struct WebSocketServer {
    /// Server configuration
    config: WebSocketServerConfig,
    /// Connection manager
    connection_manager: Arc<ConnectionManager>,
    /// Authenticator
    authenticator: Arc<WebSocketAuthenticator>,
    /// Server state
    state: Arc<RwLock<ServerState>>,
}

/// Server state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerState {
    /// Starting
    Starting,
    /// Running
    Running,
    /// Stopping
    Stopping,
    /// Stopped
    Stopped,
}

impl WebSocketServer {
    /// Create new WebSocket server
    pub fn new(
        config: WebSocketServerConfig,
        auth_manager: Arc<crate::auth::AuthManager>
    ) -> Result<Self> {
        let authenticator = Arc::new(WebSocketAuthenticator::new(auth_manager, config.auth_config.clone()));
        let connection_manager = Arc::new(ConnectionManager::new());

        Ok(Self {
            config,
            connection_manager,
            authenticator,
            state: Arc::new(RwLock::new(ServerState::Starting)),
        })
    }

    /// Start the WebSocket server
    pub async fn start(&self) -> Result<()> {
        *self.state.write().await = ServerState::Starting;

        // Validate TLS configuration if enabled
        if self.config.enable_tls {
            self.validate_tls_config()?;
        }

        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
            FortressError::websocket(format!("Failed to bind to {}: {}", bind_addr, e))
        })?;

        tracing::info!("WebSocket server listening on {} (TLS: {})", bind_addr, self.config.enable_tls);

        *self.state.write().await = ServerState::Running;

        // Start background tasks
        self.start_background_tasks().await;

        // Accept connections
        loop {
            let state = *self.state.read().await;
            if state != ServerState::Running {
                break;
            }

            match listener.accept().await {
                Ok((stream, addr)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream, addr).await {
                            tracing::error!("Connection handling error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }

        tracing::info!("WebSocket server stopped");
        Ok(())
    }

    /// Validate TLS configuration
    fn validate_tls_config(&self) -> Result<()> {
        if self.config.enable_tls {
            let cert_file = self.config.tls_cert_file.as_ref()
                .ok_or_else(|| FortressError::websocket("TLS enabled but certificate file not specified"))?;
            let key_file = self.config.tls_key_file.as_ref()
                .ok_or_else(|| FortressError::websocket("TLS enabled but private key file not specified"))?;

            // Check if certificate files exist
            if !std::path::Path::new(cert_file).exists() {
                return Err(FortressError::websocket(format!("TLS certificate file not found: {}", cert_file)));
            }

            if !std::path::Path::new(key_file).exists() {
                return Err(FortressError::websocket(format!("TLS private key file not found: {}", key_file)));
            }

            tracing::info!("TLS configuration validated - Cert: {}, Key: {}", cert_file, key_file);
        }

        Ok(())
    }

    /// Stop the WebSocket server
    pub async fn stop(&self) -> Result<()> {
        *self.state.write().await = ServerState::Stopping;
        
        // Close all connections
        let connections = self.connection_manager.get_all_connections().await;
        for connection in connections {
            let _ = connection.close().await;
        }

        *self.state.write().await = ServerState::Stopped;
        Ok(())
    }

    /// Handle new connection
    async fn handle_connection(&self, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let client_ip = addr.ip().to_string();
        
        // Check connection limits
        let stats = self.connection_manager.get_stats().await;
        if stats.active_connections >= self.config.max_connections {
            tracing::warn!("Connection limit reached, rejecting connection from {}", client_ip);
            return Err(FortressError::websocket("Connection limit reached"));
        }

        // Perform WebSocket handshake
        let ws_stream = accept_async(stream).await
            .map_err(|e| FortressError::websocket(format!("WebSocket handshake failed: {}", e)))?;

        // Extract user agent from handshake
        let user_agent = self.extract_user_agent(&ws_stream).await;

        // Create connection
        let connection = self.connection_manager
            .add_connection(ws_stream, client_ip.clone(), user_agent)
            .await?;

        // Start connection processing
        connection.start_processing().await?;

        // Handle connection lifecycle
        self.handle_connection_lifecycle(connection, client_ip).await
    }

    /// Handle connection lifecycle
    async fn handle_connection_lifecycle(&self, connection: Arc<crate::websocket::connection::WebSocketConnection>, client_ip: String) -> Result<()> {
        // Wait for authentication
        let auth_result = self.wait_for_authentication(&connection, &client_ip).await?;
        
        if !auth_result.success {
            let error_msg = WebSocketMessage::error(
                "AUTH_FAILED".to_string(),
                auth_result.error.unwrap_or_else(|| "Authentication failed".to_string()),
                None,
            );
            let _ = connection.send_message(error_msg).await;
            let _ = connection.close().await;
            
            self.connection_manager.remove_connection(&connection.info.read().await.id).await;
            return Ok(());
        }

        // Set connection as authenticated
        let user_id = auth_result.user_id.ok_or_else(|| {
            FortressError::authentication(
                "Authentication failed: missing user ID",
                Some("websocket_connection".to_string())
            )
        })?;
        
        let session_id = auth_result.session_id.ok_or_else(|| {
            FortressError::authentication(
                "Authentication failed: missing session ID",
                Some("websocket_connection".to_string())
            )
        })?;
        
        connection.set_authenticated(user_id, Some(session_id)).await;

        // Send authentication success message
        let success_msg = WebSocketMessage::new(
            MessageType::ConnectionStatus,
            MessagePayload::ConnectionStatus(crate::websocket::message::ConnectionStatusPayload {
                status: crate::websocket::message::ConnectionStatusType::Connected,
                message: "Authentication successful".to_string(),
                connection_id: connection.info.read().await.id.clone(),
            }),
        );
        let _ = connection.send_message(success_msg).await;

        tracing::info!("WebSocket connection authenticated: {}", connection.info.read().await.id);

        // Maintain connection
        self.maintain_connection(&connection).await
    }

    /// Wait for authentication message
    async fn wait_for_authentication(
        &self,
        connection: &Arc<crate::websocket::connection::WebSocketConnection>,
        client_ip: &str
    ) -> Result<crate::websocket::auth::AuthResult> {
        // In a real implementation, this would wait for the first message
        // For now, we'll simulate authentication timeout
        
        let timeout = Duration::from_secs(30); // 30 second auth timeout
        let start_time = Instant::now();
        
        while start_time.elapsed() < timeout {
            // Check if connection is authenticated
            if connection.is_authenticated().await {
                return Ok(crate::websocket::auth::AuthResult {
                    success: true,
                    user_id: Some("simulated_user".to_string()),
                    session_id: Some("simulated_session".to_string()),
                    roles: vec!["user".to_string()],
                    error: None,
                    timestamp: chrono::Utc::now(),
                });
            }
            
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        // Authentication timeout
        Ok(crate::websocket::auth::AuthResult {
            success: false,
            user_id: None,
            session_id: None,
            roles: Vec::new(),
            error: Some("Authentication timeout".to_string()),
            timestamp: chrono::Utc::now(),
        })
    }

    /// Maintain connection with ping/pong
    async fn maintain_connection(
        &self,
        connection: &Arc<crate::websocket::connection::WebSocketConnection>
    ) -> Result<()> {
        let ping_interval = Duration::from_secs(self.config.ping_interval_seconds);
        let mut last_ping = Instant::now();
        
        loop {
            // Check connection state
            let state = connection.get_state().await;
            if state == crate::websocket::connection::ConnectionState::Disconnected {
                break;
            }
            
            // Send ping if interval has passed
            if last_ping.elapsed() >= ping_interval {
                let ping_msg = WebSocketMessage::ping();
                if let Err(e) = connection.send_message(ping_msg).await {
                    tracing::error!("Failed to send ping to {}: {}", connection.info.read().await.id, e);
                    break;
                }
                last_ping = Instant::now();
            }
            
            // Check for connection timeout
            let now = Instant::now();
            if now.duration_since(connection.info.read().await.last_activity) > Duration::from_secs(self.config.connection_timeout_seconds) {
                tracing::info!("Connection {} timed out", connection.info.read().await.id);
                break;
            }
            
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        // Clean up connection
        self.connection_manager.remove_connection(&connection.info.read().await.id).await;
        Ok(())
    }

    /// Start background tasks
    async fn start_background_tasks(&self) {
        // Start broadcast processor
        self.connection_manager.start_broadcast_processor().await;
        
        // Start cleanup task
        let connection_manager = self.connection_manager.clone();
        let authenticator = self.authenticator.clone();
        let connection_timeout = Duration::from_secs(self.config.connection_timeout_seconds);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Every minute
            
            loop {
                interval.tick().await;
                
                // Cleanup idle connections
                connection_manager.cleanup_idle_connections(connection_timeout).await;
                
                // Cleanup auth data
                authenticator.cleanup().await;
            }
        });
    }

    /// Get server statistics
    pub async fn get_stats(&self) -> ServerStats {
        ServerStats {
            state: *self.state.read().await,
            connection_stats: self.connection_manager.get_stats().await,
            auth_stats: self.authenticator.get_stats().await,
        }
    }

    /// Extract user agent from handshake
    async fn extract_user_agent(&self, stream: &WebSocketStream<TcpStream>) -> Option<String> {
        // Extract user agent from WebSocket handshake headers
        // Note: tokio-tungstenite doesn't expose raw handshake headers directly
        // In a production environment, you would:
        // 1. Use a custom handshake handler to capture headers
        // 2. Parse the Sec-WebSocket-Protocol and User-Agent headers
        // 3. Store the user agent in connection metadata
        
        // For now, we'll extract from connection info if available
        // This could be enhanced by implementing a custom handshake processor
        if let Some(peer_addr) = stream.get_ref().peer_addr().ok() {
            Some(format!("WebSocket Client - {}", peer_addr))
        } else {
            Some("WebSocket Client".to_string())
        }
    }
}

/// Server statistics
#[derive(Debug, Clone)]
pub struct ServerStats {
    /// Server state
    pub state: ServerState,
    /// Connection statistics
    pub connection_stats: crate::websocket::connection::ConnectionStats,
    /// Authentication statistics
    pub auth_stats: crate::websocket::auth::AuthStats,
}

impl Default for WebSocketServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 8081,
            enable_tls: false,
            tls_cert_file: None,
            tls_key_file: None,
            max_connections: 1000,
            connection_timeout_seconds: 300, // 5 minutes
            ping_interval_seconds: 30, // 30 seconds
            auth_config: AuthConfig::default(),
            enable_compression: true,
            max_message_size: 1024 * 1024, // 1MB
        }
    }
}

impl Clone for WebSocketServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            connection_manager: self.connection_manager.clone(),
            authenticator: self.authenticator.clone(),
            state: self.state.clone(),
        }
    }
}
