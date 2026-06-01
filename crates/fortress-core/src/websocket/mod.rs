//! WebSocket (WSS) API Implementation
//!
//! Provides secure WebSocket server with real-time capabilities,
//! authentication, subscription system, and monitoring.

pub mod auth;
pub mod connection;
pub mod message;
pub mod metrics;
pub mod server;
pub mod subscription;

pub use auth::{AuthConfig, AuthResult, WebSocketAuthenticator};
pub use connection::{ConnectionInfo, ConnectionManager, WebSocketConnection};
pub use message::{
    FilterOperator, MessagePayload, MessageType, SubscriptionFilter, WebSocketMessage,
};
pub use metrics::{
    ConnectionMetrics, ErrorMetrics, MessageMetrics, PerformanceMetrics, WebSocketMetrics,
};
pub use server::{WebSocketServer, WebSocketServerConfig};
pub use subscription::{
    Subscription, SubscriptionManager, SubscriptionOptions, SubscriptionStatus,
};
