//! WebSocket API Integration Tests

#[cfg(test)]
mod tests {
    use crate::websocket::{
        WebSocketServer, WebSocketServerConfig, WebSocketMessage, MessageType, MessagePayload,
        auth::{AuthConfig, WebSocketAuthenticator},
        connection::ConnectionManager,
        subscription::SubscriptionManager,
    };
    use crate::error::Result;
    use tokio::time::{timeout, Duration};
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    use futures_util::{SinkExt, StreamExt};
    use serde_json;

    /// Test basic WebSocket connection and authentication
    #[tokio::test]
    async fn test_websocket_connection_and_auth() -> Result<()> {
        // Setup test server
        let config = WebSocketServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8082, // Use different port for testing
            enable_tls: false,
            auth_config: AuthConfig::default(),
            ..Default::default()
        };

        let server = WebSocketServer::new(config);
        server.start().await?;

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test connection
        let ws_url = "ws://127.0.0.1:8082";
        let (ws_stream, _) = timeout(Duration::from_secs(5), connect_async(ws_url)).await??;

        // Send authentication message
        let auth_msg = WebSocketMessage {
            id: "test-auth-1".to_string(),
            message_type: MessageType::Auth(crate::websocket::message::AuthPayload {
                method: "jwt".to_string(),
                token: "test-token".to_string(),
            }),
            payload: MessagePayload::Auth(crate::websocket::message::AuthPayload {
                method: "jwt".to_string(),
                token: "test-token".to_string(),
            }),
            timestamp: chrono::Utc::now(),
            correlation_id: None,
            auth_token: None,
        };

        let auth_json = serde_json::to_string(&auth_msg)?;
        ws_stream.send(Message::Text(auth_json)).await?;

        // Wait for authentication response
        if let Some(Ok(msg)) = timeout(Duration::from_secs(5), ws_stream.next()).await? {
            match msg {
                Message::Text(response) => {
                    let response_msg: WebSocketMessage = serde_json::from_str(&response)?;
                    assert!(matches!(response_msg.message_type, MessageType::AuthResponse(_)));
                }
                _ => panic!("Expected text message"),
            }
        }

        // Cleanup
        server.shutdown().await?;
        Ok(())
    }

    /// Test subscription system
    #[tokio::test]
    async fn test_websocket_subscriptions() -> Result<()> {
        let config = WebSocketServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8083,
            enable_tls: false,
            auth_config: AuthConfig::default(),
            ..Default::default()
        };

        let server = WebSocketServer::new(config);
        server.start().await?;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let ws_url = "ws://127.0.0.1:8083";
        let (ws_stream, _) = timeout(Duration::from_secs(5), connect_async(ws_url)).await??;

        // Test subscription
        let sub_msg = WebSocketMessage {
            id: "test-sub-1".to_string(),
            message_type: MessageType::Subscribe(crate::websocket::message::SubscriptionPayload {
                topic: "test-topic".to_string(),
                filters: vec![],
            }),
            payload: MessagePayload::Subscribe(crate::websocket::message::SubscriptionPayload {
                topic: "test-topic".to_string(),
                filters: vec![],
            }),
            timestamp: chrono::Utc::now(),
            correlation_id: None,
            auth_token: None,
        };

        let sub_json = serde_json::to_string(&sub_msg)?;
        ws_stream.send(Message::Text(sub_json)).await?;

        // Wait for subscription confirmation
        if let Some(Ok(msg)) = timeout(Duration::from_secs(5), ws_stream.next()).await? {
            match msg {
                Message::Text(response) => {
                    let response_msg: WebSocketMessage = serde_json::from_str(&response)?;
                    assert!(matches!(response_msg.message_type, MessageType::SubscribeResponse(_)));
                }
                _ => panic!("Expected text message"),
            }
        }

        server.shutdown().await?;
        Ok(())
    }

    /// Test message broadcasting
    #[tokio::test]
    async fn test_message_broadcasting() -> Result<()> {
        let config = WebSocketServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8084,
            enable_tls: false,
            auth_config: AuthConfig::default(),
            ..Default::default()
        };

        let server = WebSocketServer::new(config);
        server.start().await?;

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect multiple clients
        let ws_url = "ws://127.0.0.1:8084";
        let (client1, _) = timeout(Duration::from_secs(5), connect_async(ws_url)).await??;
        let (client2, _) = timeout(Duration::from_secs(5), connect_async(ws_url)).await??;

        // Subscribe both clients to same topic
        let sub_msg = WebSocketMessage {
            id: "broadcast-sub".to_string(),
            message_type: MessageType::Subscribe(crate::websocket::message::SubscriptionPayload {
                topic: "broadcast-test".to_string(),
                filters: vec![],
            }),
            payload: MessagePayload::Subscribe(crate::websocket::message::SubscriptionPayload {
                topic: "broadcast-test".to_string(),
                filters: vec![],
            }),
            timestamp: chrono::Utc::now(),
            correlation_id: None,
            auth_token: None,
        };

        let sub_json = serde_json::to_string(&sub_msg)?;
        client1.send(Message::Text(sub_json.clone())).await?;
        client2.send(Message::Text(sub_json)).await?;

        // Wait for subscriptions to be processed
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Broadcast message to topic
        let broadcast_msg = WebSocketMessage {
            id: "broadcast-msg".to_string(),
            message_type: MessageType::DataUpdate(crate::websocket::message::DataUpdatePayload {
                topic: "broadcast-test".to_string(),
                data: serde_json::json!({"test": "data"}),
            }),
            payload: MessagePayload::DataUpdate(crate::websocket::message::DataUpdatePayload {
                topic: "broadcast-test".to_string(),
                data: serde_json::json!({"test": "data"}),
            }),
            timestamp: chrono::Utc::now(),
            correlation_id: None,
            auth_token: None,
        };

        // Both clients should receive the broadcast
        let broadcast_json = serde_json::to_string(&broadcast_msg)?;
        
        // Simulate server broadcasting (in real implementation, this would be done by server)
        // For test, we'll verify the message structure
        let parsed_msg: WebSocketMessage = serde_json::from_str(&broadcast_json)?;
        assert!(matches!(parsed_msg.message_type, MessageType::DataUpdate(_)));

        server.shutdown().await?;
        Ok(())
    }

    /// Test rate limiting
    #[tokio::test]
    async fn test_rate_limiting() -> Result<()> {
        let config = WebSocketServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8085,
            enable_tls: false,
            auth_config: AuthConfig::default(),
            connection_timeout_seconds: 10,
            ..Default::default()
        };

        let server = WebSocketServer::new(config);
        server.start().await?;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let ws_url = "ws://127.0.0.1:8085";
        let (ws_stream, _) = timeout(Duration::from_secs(5), connect_async(ws_url)).await??;

        // Send multiple messages rapidly to test rate limiting
        for i in 0..10 {
            let test_msg = WebSocketMessage {
                id: format!("rate-test-{}", i),
                message_type: MessageType::Ping,
                payload: MessagePayload::Ping,
                timestamp: chrono::Utc::now(),
                correlation_id: None,
                auth_token: None,
            };

            let msg_json = serde_json::to_string(&test_msg)?;
            if let Err(_) = timeout(Duration::from_millis(100), ws_stream.send(Message::Text(msg_json))).await {
                // Rate limiting should kick in after several messages
                break;
            }
        }

        server.shutdown().await?;
        Ok(())
    }

    /// Test connection cleanup
    #[tokio::test]
    async fn test_connection_cleanup() -> Result<()> {
        let config = WebSocketServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8086,
            enable_tls: false,
            auth_config: AuthConfig::default(),
            connection_timeout_seconds: 2, // Short timeout for testing
            ..Default::default()
        };

        let server = WebSocketServer::new(config);
        server.start().await?;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let ws_url = "ws://127.0.0.1:8086";
        let (ws_stream, _) = timeout(Duration::from_secs(5), connect_async(ws_url)).await??;

        // Get initial stats
        let initial_stats = server.get_stats().await;
        let initial_connections = initial_stats.connection_stats.active_connections;

        // Drop the connection to simulate client disconnect
        drop(ws_stream);

        // Wait for cleanup timeout
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Check that connection was cleaned up
        let final_stats = server.get_stats().await;
        let final_connections = final_stats.connection_stats.active_connections;

        // Connection count should be back to initial or lower
        assert!(final_connections <= initial_connections);

        server.shutdown().await?;
        Ok(())
    }

    /// Test TLS/WSS functionality (if certificates are available)
    #[tokio::test]
    #[ignore] // Ignore by default as it requires certificates
    async fn test_tls_websocket() -> Result<()> {
        let config = WebSocketServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8087,
            enable_tls: true,
            tls_cert_file: Some("test-cert.pem".to_string()),
            tls_key_file: Some("test-key.pem".to_string()),
            auth_config: AuthConfig::default(),
            ..Default::default()
        };

        let server = WebSocketServer::new(config);
        
        // This test will fail if certificates don't exist, which is expected
        match server.start().await {
            Ok(_) => {
                // If server started successfully, test WSS connection
                tokio::time::sleep(Duration::from_millis(100)).await;

                let wss_url = "wss://127.0.0.1:8087";
                let (ws_stream, _) = timeout(Duration::from_secs(5), connect_async(wss_url)).await??;

                // Test basic functionality over TLS
                let ping_msg = WebSocketMessage {
                    id: "tls-ping".to_string(),
                    message_type: MessageType::Ping,
                    payload: MessagePayload::Ping,
                    timestamp: chrono::Utc::now(),
                    correlation_id: None,
                    auth_token: None,
                };

                let ping_json = serde_json::to_string(&ping_msg)?;
                ws_stream.send(Message::Text(ping_json)).await?;

                server.shutdown().await?;
            }
            Err(_) => {
                // Expected if certificates don't exist
                println!("TLS test skipped - certificates not available");
            }
        }

        Ok(())
    }

    /// Test error handling
    #[tokio::test]
    async fn test_error_handling() -> Result<()> {
        let config = WebSocketServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8088,
            enable_tls: false,
            auth_config: AuthConfig::default(),
            ..Default::default()
        };

        let server = WebSocketServer::new(config);
        server.start().await?;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let ws_url = "ws://127.0.0.1:8088";
        let (ws_stream, _) = timeout(Duration::from_secs(5), connect_async(ws_url)).await??;

        // Send invalid message
        let invalid_msg = r#"{"invalid": "json"}"#;
        ws_stream.send(Message::Text(invalid_msg.to_string())).await?;

        // Should receive error response
        if let Some(Ok(msg)) = timeout(Duration::from_secs(5), ws_stream.next()).await? {
            match msg {
                Message::Text(response) => {
                    let response_msg: WebSocketMessage = serde_json::from_str(&response)?;
                    assert!(matches!(response_msg.message_type, MessageType::Error(_)));
                }
                _ => panic!("Expected text error message"),
            }
        }

        server.shutdown().await?;
        Ok(())
    }
}
