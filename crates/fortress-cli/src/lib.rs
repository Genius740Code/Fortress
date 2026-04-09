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

// Re-export commonly used types
pub use color_eyre::eyre::{Result, Context};
pub use types::{Commands, KeyAction, ConfigAction};
