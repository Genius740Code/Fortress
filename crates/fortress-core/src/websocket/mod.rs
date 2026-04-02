//! WebSocket (WSS) API Implementation
//!
//! Provides secure WebSocket server with real-time capabilities,
//! authentication, subscription system, and monitoring.

pub mod server;
pub mod connection;
pub mod auth;
pub mod subscription;
pub mod metrics;
pub mod message;

pub use server::{WebSocketServer, WebSocketServerConfig};
pub use connection::{WebSocketConnection, ConnectionInfo, ConnectionManager};
pub use auth::{WebSocketAuthenticator, AuthResult, AuthConfig};
pub use subscription::{SubscriptionManager, Subscription, SubscriptionOptions, SubscriptionStatus};
pub use metrics::{WebSocketMetrics, ConnectionMetrics, MessageMetrics, PerformanceMetrics, ErrorMetrics};
pub use message::{WebSocketMessage, MessageType, MessagePayload, SubscriptionFilter, FilterOperator};
