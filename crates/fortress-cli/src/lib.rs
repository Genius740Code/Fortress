//! Fortress CLI Library
//!
//! Command-line interface for Fortress secure database system.
//!
//! This library provides the main CLI functionality including:
//! - Data migration commands
//! - Key management operations
//! - Configuration management
//! - Cluster operations
//! - Health monitoring

// #![warn(missing_docs)] // Disabled to reduce warning count
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(dead_code)]

/// CLI command handlers
///
/// This module contains all the command implementations for the Fortress CLI,
/// including data migration, key management, configuration, and cluster operations.
pub mod commands;
/// Configuration management
///
/// Handles loading, validation, and management of Fortress configuration files
/// with support for multiple environments and configuration formats.
pub mod config_manager;
/// Utility functions
///
/// Common utility functions used throughout the CLI including formatting,
/// validation, and helper functions for various operations.
pub mod utils;
/// Type definitions
///
/// Common types and enums used across the CLI including command types,
/// configuration structures, and shared data structures.
pub mod types;

/// Configuration wizard
///
/// Interactive configuration setup with dialoguer for user-friendly configuration
pub mod config_wizard;

/// Progress bars
///
/// Progress tracking for long-running operations with indicatif
pub mod progress;

/// Shell completions
///
/// Auto-completion support for various shells with clap_complete
pub mod completions;

/// Enhanced error handling
///
/// Structured error reporting with documentation integration and troubleshooting guides
pub mod enhanced_error;

/// Error documentation
///
/// Detailed error documentation and troubleshooting guides
pub mod error_docs;

/// GraphQL subscriptions
///
/// Real-time GraphQL subscriptions for data changes, security events, and metrics
pub mod graphql_subscriptions;

/// Query optimization
///
/// GraphQL query optimization with caching, batching, and performance monitoring
pub mod query_optimizer;

/// API versioning
///
/// Backward-compatible API versioning system with migration support
pub mod api_versioning;

/// Integration tests
///
/// Comprehensive integration tests for all CLI enhancements
pub mod integration_tests;

// Re-export commonly used types
pub use color_eyre::eyre::{Result, Context};
pub use types::{Commands, KeyAction, ConfigAction};
pub use enhanced_error::FortressError;
pub use config_wizard::{ConfigurationWizard, FortressConfig};
