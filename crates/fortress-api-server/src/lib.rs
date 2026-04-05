//! # Fortress Server
//!
//! REST API server for Fortress secure database system.
//!
//! This crate provides a high-performance HTTP API that automatically handles
//! encryption and decryption of data, providing a simple interface for secure
//! data storage and retrieval.
//!
//! ## Features
//!
//! - **Automatic Encryption/Decryption**: All data is automatically encrypted
//!   before storage and decrypted after retrieval
//! - **RESTful API**: Standard HTTP methods with JSON payloads
//! - **Authentication & Authorization**: Built-in support for token-based auth
//! - **Audit Logging**: All operations are logged for security compliance
//! - **Health Monitoring**: Built-in health checks and metrics
//! - **Multi-tenant Support**: Isolated data per tenant/organization
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use fortress_server::{FortressServer, ServerConfig};
//! use fortress_core::prelude::*;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ServerConfig::default();
//! let server = FortressServer::new(config).await?;
//!
//! // Start the server
//! server.listen("127.0.0.1:8080").await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod server;
pub mod auth;
pub mod metrics;
pub mod health;
pub mod grpc;
pub mod cluster;
pub mod graphql;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::config::ServerConfig;
    pub use crate::error::{ServerError, ServerResult};
    pub use crate::server::FortressServer;
    pub use crate::models::*;
    pub use crate::auth::{AuthManager, TokenClaims};
    pub use crate::health::HealthChecker;
    pub use crate::metrics::MetricsCollector;
    pub use crate::middleware::AdvancedRateLimiter;
    pub use crate::config::RateLimitAlgorithm;
    pub use crate::middleware::RateLimitMetricsSnapshot;
    pub use crate::grpc::server::GrpcServer;
    pub use crate::grpc::service::FortressGrpcService;
}

/// Fortress server version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
