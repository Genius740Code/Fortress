//! WebSocket message types and handling

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// WebSocket message with type-based routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    /// Unique message ID
    pub id: String,
    /// Message type for routing
    #[serde(rename = "type")]
    pub message_type: MessageType,
    /// Message payload
    pub payload: MessagePayload,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Optional correlation ID for request/response matching
    pub correlation_id: Option<String>,
    /// Authentication token (if needed)
    pub auth_token: Option<String>,
}

/// Message types for routing and handling
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum MessageType {
    /// Authentication message
    Auth,
    /// Subscription request
    Subscribe,
    /// Unsubscription request
    Unsubscribe,
    /// Data update
    DataUpdate,
    /// System notification
    SystemNotification,
    /// Error message
    Error,
    /// Heartbeat/ping
    Ping,
    /// Heartbeat/pong response
    Pong,
    /// Connection status
    ConnectionStatus,
    /// Custom message type
    Custom(String),
}

/// Message payload content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum MessagePayload {
    /// Authentication payload
    Auth(AuthPayload),
    /// Subscription payload
    Subscribe(SubscribePayload),
    /// Unsubscription payload
    Unsubscribe(UnsubscribePayload),
    /// Data update payload
    DataUpdate(DataUpdatePayload),
    /// System notification payload
    SystemNotification(SystemNotificationPayload),
    /// Error payload
    Error(ErrorPayload),
    /// Empty payload (for ping/pong)
    Empty,
    /// Connection status payload
    ConnectionStatus(ConnectionStatusPayload),
    /// Custom JSON payload
    Custom(serde_json::Value),
}

/// Authentication message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    /// JWT token or API key
    pub token: String,
    /// Client identifier
    pub client_id: Option<String>,
    /// Authentication method
    pub method: AuthMethod,
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    /// JWT token
    JWT,
    /// API key
    APIKey,
    /// Session token
    Session,
}

/// Subscription message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribePayload {
    /// Subscription topic
    pub topic: String,
    /// Subscription filters
    pub filters: Vec<SubscriptionFilter>,
    /// Subscription options
    pub options: SubscriptionOptions,
}

/// Unsubscription message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribePayload {
    /// Subscription ID to unsubscribe
    pub subscription_id: String,
}

/// Data update message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataUpdatePayload {
    /// Update topic
    pub topic: String,
    /// Update data
    pub data: serde_json::Value,
    /// Update metadata
    pub metadata: HashMap<String, String>,
    /// Update version
    pub version: Option<u64>,
}

/// System notification payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemNotificationPayload {
    /// Notification level
    pub level: NotificationLevel,
    /// Notification title
    pub title: String,
    /// Notification message
    pub message: String,
    /// Additional data
    pub data: Option<serde_json::Value>,
}

/// Error message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Error details
    pub details: Option<HashMap<String, String>>,
}

/// Connection status payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStatusPayload {
    /// Connection status
    pub status: ConnectionStatusType,
    /// Status message
    pub message: String,
    /// Connection ID
    pub connection_id: String,
}

/// Subscription filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    /// Filter field
    pub field: String,
    /// Filter operator
    pub operator: FilterOperator,
    /// Filter value
    pub value: serde_json::Value,
}

/// Filter operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOperator {
    /// Equals
    Equals,
    /// Not equals
    NotEquals,
    /// Greater than
    GreaterThan,
    /// Less than
    LessThan,
    /// Contains
    Contains,
    /// In array
    In,
    /// Not in array
    NotIn,
}

/// Subscription options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionOptions {
    /// Enable compression
    pub compression: bool,
    /// Batch updates
    pub batch_updates: bool,
    /// Batch size
    pub batch_size: Option<usize>,
    /// Batch interval in milliseconds
    pub batch_interval_ms: Option<u64>,
    /// Enable history
    pub enable_history: bool,
    /// History limit
    pub history_limit: Option<usize>,
}

/// Notification levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationLevel {
    /// Info level
    Info,
    /// Warning level
    Warning,
    /// Error level
    Error,
    /// Critical level
    Critical,
}

/// Connection status types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatusType {
    /// Connected
    Connected,
    /// Disconnected
    Disconnected,
    /// Authentication failed
    AuthFailed,
    /// Rate limited
    RateLimited,
    /// Error
    Error,
}

impl WebSocketMessage {
    /// Create a new message
    pub fn new(message_type: MessageType, payload: MessagePayload) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            message_type,
            payload,
            timestamp: chrono::Utc::now(),
            correlation_id: None,
            auth_token: None,
        }
    }

    /// Create message with correlation ID
    pub fn with_correlation_id(
        message_type: MessageType, 
        payload: MessagePayload, 
        correlation_id: String
    ) -> Self {
        let mut msg = Self::new(message_type, payload);
        msg.correlation_id = Some(correlation_id);
        msg
    }

    /// Create authentication message
    pub fn auth(token: String, client_id: Option<String>, method: AuthMethod) -> Self {
        let payload = MessagePayload::Auth(AuthPayload {
            token,
            client_id,
            method,
        });
        Self::new(MessageType::Auth, payload)
    }

    /// Create subscription message
    pub fn subscribe(topic: String, filters: Vec<SubscriptionFilter>, options: SubscriptionOptions) -> Self {
        let payload = MessagePayload::Subscribe(SubscribePayload {
            topic,
            filters,
            options,
        });
        Self::new(MessageType::Subscribe, payload)
    }

    /// Create unsubscribe message
    pub fn unsubscribe(subscription_id: String) -> Self {
        let payload = MessagePayload::Unsubscribe(UnsubscribePayload {
            subscription_id,
        });
        Self::new(MessageType::Unsubscribe, payload)
    }

    /// Create data update message
    pub fn data_update(topic: String, data: serde_json::Value, metadata: HashMap<String, String>) -> Self {
        let payload = MessagePayload::DataUpdate(DataUpdatePayload {
            topic,
            data,
            metadata,
            version: None,
        });
        Self::new(MessageType::DataUpdate, payload)
    }

    /// Create error message
    pub fn error(code: String, message: String, details: Option<HashMap<String, String>>) -> Self {
        let payload = MessagePayload::Error(ErrorPayload {
            code,
            message,
            details,
        });
        Self::new(MessageType::Error, payload)
    }

    /// Create ping message
    pub fn ping() -> Self {
        let payload = MessagePayload::Empty;
        Self::new(MessageType::Ping, payload)
    }

    /// Create pong message
    pub fn pong() -> Self {
        let payload = MessagePayload::Empty;
        Self::new(MessageType::Pong, payload)
    }

    /// Serialize message to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| {
            FortressError::websocket(format!("Failed to serialize message: {}", e))
        })
    }

    /// Deserialize message from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            FortressError::websocket(format!("Failed to deserialize message: {}", e))
        })
    }

    /// Validate message structure
    pub fn validate(&self) -> Result<()> {
        match &self.message_type {
            MessageType::Auth => {
                if let MessagePayload::Auth(auth_payload) = &self.payload {
                    if auth_payload.token.is_empty() {
                        return Err(FortressError::websocket("Auth token cannot be empty"));
                    }
                }
            }
            MessageType::Subscribe => {
                if let MessagePayload::Subscribe(sub_payload) = &self.payload {
                    if sub_payload.topic.is_empty() {
                        return Err(FortressError::websocket("Subscription topic cannot be empty"));
                    }
                }
            }
            MessageType::Unsubscribe => {
                if let MessagePayload::Unsubscribe(unsub_payload) = &self.payload {
                    if unsub_payload.subscription_id.is_empty() {
                        return Err(FortressError::websocket("Subscription ID cannot be empty"));
                    }
                }
            }
            _ => {} // Other message types are valid as-is
        }
        Ok(())
    }
}

impl Default for SubscriptionOptions {
    fn default() -> Self {
        Self {
            compression: true,
            batch_updates: false,
            batch_size: None,
            batch_interval_ms: None,
            enable_history: false,
            history_limit: None,
        }
    }
}
