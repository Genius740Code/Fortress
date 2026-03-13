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

pub mod commands;
pub mod config_manager;
pub mod utils;
pub mod types;

// Re-export commonly used types
pub use color_eyre::eyre::{Result, Context};
pub use types::{Commands, KeyAction, ConfigAction};
