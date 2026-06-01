//! gRPC service implementation for Fortress
//!
//! This module provides the gRPC server and service implementations
//! for the Fortress secure storage system.

/// gRPC service module
pub mod service;

/// gRPC server module
pub mod server;

/// gRPC types module
pub mod types;

// Re-export types for convenience
pub use types::*;
