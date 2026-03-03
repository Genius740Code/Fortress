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

/// Backup manager implementation
pub mod backup_manager;

/// Disaster recovery manager implementation
pub mod disaster_recovery;

/// Automated backup scheduling system
pub mod backup_scheduler;

/// Cross-region replication manager
pub mod cross_region_replication;

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

/// Plugin marketplace and distribution system

pub mod plugin_marketplace;

/// True Random Number Generator (TRNG) system

pub mod trng;

/// Secure Multi-Party Computation (MPC) system

pub mod mpc;

/// MPC Manager implementation

pub mod mpc_manager;

/// MPC Party implementation

pub mod mpc_party;

/// MPC Network implementation

pub mod mpc_network;

/// Homomorphic encryption capabilities

pub mod homomorphic_encryption;

/// Quantum-resistant encryption options

pub mod quantum_resistant;

/// Advanced threat detection and response

pub mod threat_detection;

/// Advanced query optimization system

pub mod query_optimizer;

/// Distributed caching layer

pub mod distributed_cache;

/// Advanced connection pooling and load balancing

pub mod connection_pool;

/// Performance monitoring and profiling

pub mod performance_monitor;

/// Automatic performance tuning system

pub mod auto_tuning;

/// Advanced observability and monitoring system

pub mod observability;

/// Comprehensive compliance framework

pub mod compliance;

/// Audit event structures for compliance integration

pub mod audit_event;

/// Secrets engine system for Vault-compatible secret management

pub mod secrets;

/// KV (Key-Value) secrets engine implementation

pub mod secrets_kv;

/// MongoDB database backend for Fortress

pub mod mongodb_database;

/// Enhanced PostgreSQL database backend for Fortress

pub mod postgres_database;

/// Push/Pull operations for database synchronization

pub mod push_pull_operations;



#[cfg(test)]

mod policy_test;

#[cfg(test)]



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
        ConflictResolution, VerificationResult, VerificationStatus, BackupSchedule, ScheduledRunResult,
        CrossRegionConfig, ReplicationStrategy, ReplicationResult,
    };

    pub use crate::backup_manager::{DefaultBackupManager};
    
    pub use crate::disaster_recovery::{DefaultDisasterRecoveryManager};
    
    pub use crate::backup_scheduler::{BackupScheduler};
    
    pub use crate::cross_region_replication::{CrossRegionReplicationManager, ReplicationStats};

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

    pub use crate::plugin_marketplace::{
        PluginMarketplace, PluginRepository, PluginInstaller, PluginPackage,
        InstalledPlugin,
    };

    pub use crate::trng::{
        TrueRandomGenerator, TrngConfig, TrngHealth, EntropySource,
        init_global_trng, global_trng, random_bytes, random_u64, fill_random
    };

    pub use crate::mpc::{
        MpcProtocol, MpcParty, MpcNetwork, MpcManager, ComputationConfig, SessionId,
        PartyId, PartyRole, ComputationStatus, MpcMessage, ComputationResult,
        SecretShare, ShareId, SecretSharingScheme, ShamirSecretSharing,
    };

    pub use crate::mpc_manager::{DefaultMpcManager, MpcManagerBuilder};

    pub use crate::mpc_party::{InMemoryMpcParty, MpcPartyBuilder, MessageHandler};

    pub use crate::mpc_network::{InMemoryMpcNetwork, MpcNetworkBuilder, NetworkStats};

    pub use crate::homomorphic_encryption::{
        HomomorphicEncryption, HomomorphicScheme, HomomorphicOperation, HomomorphicCiphertext,
        HomomorphicManager, HomomorphicManagerBuilder, HomomorphicPerformance,
        PaillierHomomorphic,
    };

    pub use crate::quantum_resistant::{
        QuantumResistantEncryption, QuantumResistantScheme, QuantumResistantCiphertext,
        QuantumResistantManager, QuantumResistantManagerBuilder, QuantumPerformance,
        LweEncryption, HybridEncryption,
    };

    pub use crate::threat_detection::{
        ThreatDetectionEngine, ThreatResponseSystem, DetectionRule, SecurityEvent,
        ThreatDetection, SecurityIncident, ThreatSeverity, ThreatType, ResponseAction,
        DefaultThreatDetectionEngine, DefaultThreatResponseSystem,
        DetectionStatistics, ResponseStatistics,
    };

    pub use crate::query_optimizer::{
        QueryOptimizer, QueryOptimizerConfig, TableStatistics, ColumnStatistics,
        IndexStatistics, OptimizerStats, hash_query
    };

    pub use crate::distributed_cache::{
        DistributedCache, DistributedCacheConfig, CacheBackend, EvictionPolicy,
        CacheStatistics, InMemoryCache, create_distributed_cache
    };

    pub use crate::connection_pool::{
        ConnectionManager, ConnectionPoolConfig, ServerEndpoint, ConnectionStats,
        LoadBalanceAlgorithm, AdvancedConnectionPool, create_connection_pool
    };

    pub use crate::performance_monitor::{
        PerformanceMonitor, PerformanceMonitorConfig, ProfileSample, OperationType,
        AggregatedMetrics, PerformanceAlert, AlertSeverity, AlertType,
        TuningRecommendation, RecommendationType, ImplementationComplexity,
        RecommendationPriority, profile_operation
    };

    pub use crate::auto_tuning::{
        AutomaticPerformanceTuner, AutoTuningConfig, TuningParameter,
        ParameterType, ParameterCategory, ImpactLevel, AppliedChange,
        ChangeStatus, TuningStrategy, OptimizationGoal, TuningStatus
    };

    pub use crate::observability::{
        ObservabilityManager, ObservabilityConfig, SystemStatus,
        ObservabilityTracer, TraceConfig, SpanContext,
        AdvancedMetricsCollector, MetricsConfig, MetricType,
        StructuredLogger, LogConfig, LogFormat,
        HealthChecker, HealthConfig, HealthStatus,
        AlertManager, AlertConfig, AlertRule,
        DashboardManager, DashboardConfig, Widget,
    };

    pub use crate::compliance::{
        ComplianceManager, CompliancePolicy, ComplianceStandard, DataClassification,
        ComplianceRequirement, ImplementationStatus, DataSubjectRequest, GDPRDataSubjectRight,
        RequestStatus, ComplianceAuditEvent, ComplianceEventType, AuditOutcome,
        UserDataExport, HIPAAComplianceReport, SOC2Report, PCIDSSValidationReport,
        ComplianceAuditLogger, create_default_gdpr_policy, create_default_hipaa_policy,
        create_default_pci_dss_policy,
    };

    pub use crate::secrets::{
        SecretsEngine, SecretsEngineManager, Secret, SecretMetadata, LeaseInfo, 
        EngineType, EngineStatus, EngineStats, SecretsConfig,
    };

    pub use crate::secrets_kv::{
        KvEngine, KvConfig, VersionedSecret,
    };

    pub use crate::mongodb_database::{
        MongoConfig, MongoKeyDatabase, MongoStorage, MongoPullFilter, 
        MongoPipeline, MongoAggregationResult, MongoSearchResult,
        MongoBulkEntry, MongoReadPreference, MongoWriteConcern
    };

    pub use crate::postgres_database::{
        PostgresConfig, PostgresKeyDatabase, PostgresStorage, PostgresQuery,
        PostgresCursor, PostgresRow, PostgresSearchResult, PostgresBulkEntry,
        PostgresJsonbQuery, PostgresPartitioning, PostgresReplicationConfig,
        PostgresSyncMode
    };

    pub use crate::push_pull_operations::{
        PushPullManager, PushPullConfig, PushRequest, PullRequest, PushPullResult,
        PushFilter, PullFilter, StorageSource, StorageTarget, ConflictResolution,
        OperationType, ProgressUpdate, ConflictInfo, DataVersion, ConflictType
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

