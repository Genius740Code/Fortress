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

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod commands;
pub mod config_manager;
pub mod utils;
pub mod types;

// Re-export commonly used types
pub use color_eyre::eyre::{Result, Context};
pub use types::{Commands, KeyAction, ConfigAction};
