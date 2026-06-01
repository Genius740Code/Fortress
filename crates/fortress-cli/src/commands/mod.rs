/// Simple configuration creation command

///

/// Provides an interactive wizard for creating basic Fortress configurations

/// with sensible defaults for common use cases.
pub mod create_simple;

/// Server start command

///

/// Handles starting the Fortress server with various configuration options

/// including port, host, and data directory specifications.
pub mod start;

/// Status command

///

/// Displays the current status of Fortress services including health checks,

/// performance metrics, and operational state.
pub mod status;

/// Key management command

///

/// Provides comprehensive key management operations including generation,

/// rotation, rollback, and lifecycle management of cryptographic keys.
pub mod key;

/// Configuration management command

///

/// Handles configuration operations including validation, updates,

/// and management of Fortress configuration files.
pub mod config;

pub mod cluster;

pub mod tenant;

pub mod plugin;

/// Data migration command

///

/// Manages database migration operations including schema updates,

/// data transformations, and version management.
pub mod migrate;
