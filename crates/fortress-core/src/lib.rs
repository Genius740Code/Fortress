//! # Fortress Core

//!

//! Core library for Fortress secure database system.

//!

//! This library provides the fundamental building blocks for encrypted data storage:

//!

//! - **Encryption Abstractions**: Traits and implementations for various encryption algorithms

//! - **Key Management**: Secure key generation, rotation, and storage

//! - **Error Handling**: Comprehensive error types for security operations

//! - **Utilities**: Helper functions for cryptographic operations

//!

//! ## Quick Start

//!

//! ```rust,no_run

//! use fortress_core::{

//!     encryption::{Aegis256, EncryptionAlgorithm},

//!     key::KeyManager,

//! };

//!

//! # #[tokio::main]

//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {

//! let algorithm = Aegis256::new();

//! let key_manager = KeyManager::new();

//! let key = key_manager.generate_key(&algorithm)?;

//!

//! let plaintext = b"Hello, Fortress!";

//! let ciphertext = algorithm.encrypt(plaintext, &key)?;

//! let decrypted = algorithm.decrypt(&ciphertext, &key)?;

//!

//! assert_eq!(plaintext, decrypted);

//! # Ok(())

//! # }

//! ```



#![warn(missing_docs)]

#![warn(rust_2018_idioms)]

#![warn(clippy::all)]

#![allow(clippy::module_name_repetitions)]



/// Core error types

pub mod error;



/// Encryption algorithms and abstractions

pub mod encryption;



/// Key management and rotation

pub mod key;



/// Storage backend abstractions

pub mod storage;



/// Query engine and execution

pub mod query;



/// Configuration management

pub mod config;



/// Utility functions and helpers

pub mod utils;



/// Performance benchmarking suite

pub mod benchmark;



/// Policy engine and RBAC system

pub mod policy;



/// Hardware Security Module (HSM) support

pub mod hsm;



/// Multi-tenant isolation system

pub mod tenant;



/// Audit logging system

pub mod audit;



/// Audit log analysis tools

pub mod audit_analysis;



/// Audit log rotation and retention

pub mod audit_rotation;



/// Distributed clustering system

pub mod cluster;



/// Raft consensus algorithm

pub mod raft;



/// Data replication system

pub mod replication;

/// Per-field encryption with custom algorithm selection

pub mod field_encryption;

/// Field encryption manager implementations

pub mod field_encryption_manager;

/// Algorithm registry for easy management and discovery

pub mod algorithm_registry;

/// Performance profiles and optimization
pub mod performance_profile;

/// Backup and disaster recovery system
pub mod backup;

/// Simple backup manager for testing
pub mod simple_backup_manager;

/// AES-256-GCM wrapper implementation

pub mod aes256gcm_wrapper;

/// Key database management for persistent key storage

pub mod key_database;

/// Key preloading system for high-performance key access

pub mod key_preloader;

/// High-performance in-memory key cache with LRU eviction

pub mod key_cache;

/// Database-backed key manager with preloading and caching

pub mod database_key_manager;

/// Plugin system for extensible functionality

pub mod plugin;



#[cfg(test)]

mod policy_test;

#[cfg(test)]

mod key_rotation_test;



/// Re-export commonly used types

pub mod prelude {

    pub use crate::error::{FortressError, Result};

    pub use crate::encryption::{

        EncryptionAlgorithm, EncryptionProfile, Aegis256, ChaCha20Poly1305, Aes256Gcm,
        XChaCha20Poly1305, Blake3Encrypt, HmacSha512Encrypt, Aes256Ctr, Argon2idEncrypt, CompositeEncrypt,

    };

    pub use crate::key::{KeyManager, KeyId, KeyMetadata, SmartKeyRotationScheduler, RotationInterval, RotationMetrics};

    pub use crate::storage::StorageBackend;

    pub use crate::config::Config;

    pub use crate::benchmark::{AegisBenchmark, BenchmarkResults};

    pub use crate::policy::{PolicyEngine, Role, Permission, Resource};

    pub use crate::hsm::{HsmProvider, HsmConfig, HsmKeyManager, HsmProvider as HsmProviderTrait};

    pub use crate::audit::{AuditLogger, AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome};

    pub use crate::audit_analysis::{AuditAnalyzer, SecurityAnomaly, SecurityInsights, SecurityReport};

    pub use crate::audit_rotation::{LogRotationManager, RetentionPolicy, RotationStrategy, LogStatistics};

    pub use crate::cluster::{ClusterManager, ClusterConfig, ClusterNode, NodeState, ClusterHealth};

    pub use crate::raft::{RaftEngine, RaftState, AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};

    pub use crate::replication::{ReplicationManager, ReplicationConfig, ReplicationOperation, ConsistencyLevel, ReplicationStatus};

    pub use crate::field_encryption::{
        FieldEncryptionManager, FieldEncryptionConfig, FieldIdentifier, FieldEncryptionStrategy,
        FieldEncryptionMetadata, EncryptedField, DecryptedField, FieldAlgorithmSelector,
        DefaultAlgorithmSelector, FieldSensitivity, FieldConfigId
    };

    pub use crate::field_encryption_manager::{DefaultFieldEncryptionManager, FieldEncryptionManagerBuilder};

    pub use crate::algorithm_registry::{AlgorithmRegistry, AlgorithmMetadata, AlgorithmRequirements, AlgorithmStatistics};

    pub use crate::tenant::{
        TenantManager, InMemoryTenantManager, Tenant, TenantId, CreateTenantRequest, UpdateTenantRequest,
        TenantStats, TenantResourceLimits, TenantEncryptionConfig, ResourceIsolationManager,
        TenantResourceUsage, GlobalResourceLimits, GlobalResourceUsage
    };

    pub use crate::backup::{
        BackupManager, DisasterRecoveryManager, BackupMetadata, BackupItem, BackupManifest,
        BackupConfig, BackupStrategy, RetentionPolicy as BackupRetentionPolicy, VerificationLevel, DisasterRecoveryPlan,
        RecoveryStep, RecoveryPriority, RestoreStatus, RestoreOperationStatus, BackupStorageStats,
    };

    pub use crate::simple_backup_manager::{SimpleBackupManager};

    pub use crate::performance_profile::{
        PerformanceProfile, PerformanceProfileConfig, ProfileManager, ResourceLimits,
        EncryptionSettings, StorageSettings, NetworkSettings, SystemInfo, SyncMode,
    };

    pub use crate::key_database::{
        KeyDatabase, KeyDatabaseConfig, KeyDatabaseStats, KeyDatabaseBackend,
        SqliteKeyDatabase, create_key_database
    };

    pub use crate::key_preloader::{
        KeyPreloader, KeyPreloadConfig, PreloadStrategy, KeyAccessStats,
        PreloadStats
    };

    pub use crate::key_cache::{
        KeyCache, KeyCacheConfig, CacheStats
    };

    pub use crate::database_key_manager::{
        DatabaseKeyManager, DatabaseKeyManagerConfig, KeyManagerMetrics,
        DatabaseKeyManagerStats
    };

    pub use crate::plugin::{
        Plugin, PluginRegistry, PluginManager, PluginMetadata, PluginCapability,
        PluginContext, PluginResult, PluginInput, PluginHealth, PluginMetrics,
    };

}



/// Fortress version information

pub const VERSION: &str = env!("CARGO_PKG_VERSION");



/// Fortress build information

pub mod build {

    /// Build timestamp

    pub const TIMESTAMP: &str = match option_env!("VERGEN_BUILD_TIMESTAMP") {

        Some(val) => val,

        None => "unknown",

    };

    

    /// Git commit SHA

    pub const GIT_SHA: &str = match option_env!("VERGEN_GIT_SHA") {

        Some(val) => val,

        None => "unknown",

    };

    

    /// Rust version

    pub const RUST_VERSION: &str = match option_env!("VERGEN_RUSTC_SEMVER") {

        Some(val) => val,

        None => "unknown",

    };

    

    /// Target triple

    pub const TARGET: &str = match option_env!("VERGEN_CARGO_TARGET_TRIPLE") {

        Some(val) => val,

        None => "unknown",

    };

}



#[cfg(test)]

mod tests {

    use super::*;



    #[test]

    fn test_version() {

        assert!(!VERSION.is_empty());

    }



    #[test]

    fn test_build_info() {

        assert!(!build::TIMESTAMP.is_empty());

        assert!(!build::GIT_SHA.is_empty());

        assert!(!build::RUST_VERSION.is_empty());

        assert!(!build::TARGET.is_empty());

    }

}

