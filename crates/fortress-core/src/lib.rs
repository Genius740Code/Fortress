//! # Fortress Core

//!

//! Core library for Fortress secure database system.

//!

//! This library provides the fundamental building blocks for encrypted data storage:

//!

//! - **Encryption Abstractions**: Traits and implementations for various encryption algorithms

//! - **Key Management**: Secure key generation, rotation, and storage

//! - **Caching System**: Advanced multi-tier caching with intelligent invalidation

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

// #![warn(missing_docs)] // Disabled to reduce warning count

#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(dead_code)]

/// Core error types
pub mod error;

/// Encryption algorithms and abstractions
pub mod encryption;

/// Key management and rotation
pub mod key;

pub use key::{KeyManager, KeyMetadata, SecureKey};

/// Input validation for security
pub mod input_validation;

/// Caching system
pub mod cache_manager;

/// Security fixes and enhancements
pub mod security_fixes;

pub use security_fixes::{CsrfProtection, InputValidator, SecureSessionGenerator, SecurityHeaders};

/// Security integration tests

#[cfg(test)]
pub mod security_integration_tests;

/// Security regression tests

#[cfg(test)]
pub mod security_regression_tests;

/// Security performance tests

#[cfg(test)]
pub mod security_performance_tests;

pub mod key_rotation_optimized;

pub use key_rotation_optimized::{
    OptimizedKeyRotationManager, OptimizedRotationConfig, RotationContext, RotationMetrics,
};

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

/// Cryptographically secure audit logging with Merkle trees
pub mod secure_audit_merkle;

/// Zero-knowledge proof system for audit verification
pub mod audit_zk_proofs;

/// Comprehensive tamper detection and alerting system
pub mod audit_tamper_detection;

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

/// Auto-Discovery and Service Mesh Integration (Phase 3)
#[cfg(feature = "discovery")]
pub mod discovery;
#[cfg(feature = "mesh")]
pub mod mesh;

/// Advanced Rate Limiting System (Phase 3)
#[cfg(feature = "rate-limiting")]
pub mod rate_limit;

/// Algorithm registry for easy management and discovery
pub mod algorithm_registry;

/// Performance profiles and optimization
pub mod performance_profile;

/// Backup and disaster recovery system
pub mod backup;

/// Backup manager implementation
pub mod backup_manager;

/// Enhanced backup manager with additional safety features
pub mod backup_manager_improvements;

/// Disaster recovery manager implementation
pub mod disaster_recovery;

/// Automated backup scheduling system
pub mod backup_scheduler;

/// Cross-region replication manager
pub mod cross_region_replication;

/// Simple backup manager for testing
// Note: Module temporarily removed - add back when implementation is ready
// pub mod simple_backup_manager;

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

/// Plugin system with WebAssembly support
pub mod plugin;

pub mod wasm_runtime;

#[cfg(test)]
mod wasm_runtime_test;

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

/// Production-ready homomorphic encryption
#[cfg(any(feature = "experimental", feature = "homomorphic-encryption"))]
pub mod homomorphic_encryption;

/// Quantum-resistant encryption options

// Quantum-resistant module is available under experimental feature

/// Advanced threat detection and response
pub mod threat_detection;

/// Advanced query optimization system
pub mod query_optimizer;

/// Memory optimization system
pub mod memory;

/// High-performance serialization system
pub mod serialization;

/// Performance optimization module with SIMD, async, and memory management
pub mod performance;

/// Distributed caching system (temporarily disabled)
#[cfg(feature = "distributed-cache")]
pub mod distributed_cache;

/// Advanced cache invalidation strategies
pub mod cache_invalidation;

/// Redis cache backend implementation
pub mod cache_redis;

/// Memcached cache backend implementation
pub mod cache_memcached;

/// Hybrid cache strategy (local + distributed)

#[cfg(feature = "distributed-cache")]
pub mod cache_hybrid;

/// Unified cache manager

/// Cache integration with key management and encryption
pub mod cache_integration;

/// Comprehensive cache tests
pub mod cache_tests;

/// Advanced connection pooling and load balancing
pub mod connection_pool;

/// Performance monitoring and profiling
pub mod performance_monitor;

/// Automatic performance tuning system
pub mod auto_tuning;

/// Advanced observability and monitoring system
pub mod observability;

/// WebSocket (WSS) API implementation
pub mod websocket;

/// Comprehensive compliance framework
pub mod compliance;

/// Audit event structures for compliance integration
pub mod audit_event;

/// Secrets engine system for Vault-compatible secret management
pub mod secrets;

/// KV (Key-Value) secrets engine implementation
pub mod secrets_kv;

/// Dynamic Database secrets engine implementation
pub mod database_secrets;

/// Dynamic Secrets Engine for cloud services and databases
pub mod dynamic_secrets;

/// Kubernetes authentication module with TokenReview support
pub mod kubernetes_auth;

/// OIDC Provider for internal services
pub mod oidc_provider;

/// Format-Preserving Encryption (FPE) module
pub mod format_preserving_encryption;

/// Secure audit logging system with tamper protection
pub mod secure_audit;

/// MongoDB database backend for Fortress
pub mod mongodb_database;

/// Enhanced PostgreSQL database backend for Fortress
pub mod postgres_database;

/// Enhanced MySQL database backend for Fortress

#[cfg(feature = "mysql")]
pub mod mysql_database;

/// Push/Pull operations for database synchronization
pub mod push_pull_operations;

/// Key-Value Engine for high-performance storage operations
pub mod kv_engine;

/// Transit Engine - Encryption as a Service with AEGIS-256
pub mod transit_engine;

/// Image encryption and processing system
pub mod image_encryption;

/// Authentication and authorization system
pub mod auth;

#[cfg(test)]
pub mod auth_advanced_tests;

/// Security audit logging system
pub mod security_audit;

/// Security headers middleware
pub mod security_headers;

/// Security monitoring and alerting
pub mod security_monitoring;

/// Comprehensive security module with memory safety and zero-knowledge proofs
pub mod security;

pub mod auth_plugin;

pub mod auth_plugin_manager;

pub mod auth_plugin_integration;

pub mod auth_service;

pub mod auth_api;

/// Seal/Unseal mechanism with Shamir Secret Sharing
pub mod seal;

pub mod shamir;

/// Advanced Token Management System
pub mod token;

/// HCL Policy Engine
pub mod policy_hcl;

/// Multi-Person Authorization (MPA) system
pub mod multi_person_auth;

/// MPA service layer
pub mod mpa_service;

/// MPA integration tests

#[cfg(test)]
pub mod mpa_integration_tests;

/// Simple MPA tests

#[cfg(test)]
pub mod mpa_simple_tests;

/// Trusted Execution Environments (TEE) integration
pub mod tee;

/// AWS Nitro Enclaves provider
pub mod tee_aws_nitro;

/// Intel SGX provider
pub mod tee_intel_sgx;

/// Secure enclave communication protocols
pub mod tee_communication;

/// TEE attestation verification
pub mod tee_attestation;

/// TEE-aware key management
pub mod tee_key_management;

/// Unified key management interface
pub mod key_management;

/// TEE integration tests

#[cfg(test)]
pub mod tee_integration_tests;

///! Fortress - Enterprise Security Platform

///

/// Fortress is a comprehensive security platform providing encryption, key management,

/// authentication, authorization, policy evaluation, and WebAssembly-based extensibility.

#[cfg(feature = "experimental")]
pub mod quantum_resistant;

// Re-export commonly used types

pub use crate::error::{FortressError, Result};

pub use crate::encryption::EncryptionAlgorithm;

pub use crate::plugin::{Plugin, PluginManager, PluginMetadata};

/// Re-export commonly used types

pub mod prelude {

    pub use crate::error::{FortressError, Result}; // Added Result type here

    pub use crate::encryption::{
        Aegis256, Aes256Ctr, Aes256Gcm, Argon2idEncrypt, Blake3Encrypt, ChaCha20Poly1305,
        CompositeEncrypt, EncryptionAlgorithm, EncryptionProfile, HmacSha512Encrypt,
        XChaCha20Poly1305,
    };

    pub use crate::key::{
        KeyId, KeyManager, KeyMetadata, KeyPurpose, RotationInterval, RotationMetrics,
        SmartKeyRotationScheduler,
    };

    pub use crate::key_management::UnifiedKeyManager;

    pub use crate::storage::StorageBackend;

    pub use crate::config::Config;

    pub use crate::benchmark::{AegisBenchmark, BenchmarkResults};

    pub use crate::policy::{PolicyEngine, PolicyRole, Resource};

    pub use crate::hsm::{HsmConfig, HsmProvider};

    pub use crate::audit::{
        log_event_with_metadata, AuditEntry, AuditEventType, AuditLogger, EventOutcome,
        SecurityLevel,
    };

    pub use crate::audit_analysis::{
        AuditAnalyzer, SecurityAnomaly, SecurityInsights, SecurityReport,
    };

    pub use crate::audit_rotation::{
        LogRotationManager, LogStatistics, RetentionPolicy, RotationStrategy,
    };

    pub use crate::cluster::{
        ClusterConfig, ClusterHealth, ClusterManager, ClusterNode, NodeState,
    };

    pub use crate::raft::{
        AppendEntriesRequest, AppendEntriesResponse, RaftEngine, RaftState, RequestVoteRequest,
        RequestVoteResponse,
    };

    pub use crate::replication::{
        ConsistencyLevel, ReplicationConfig, ReplicationManager, ReplicationOperation,
        ReplicationStatus,
    };

    pub use crate::field_encryption::{
        DecryptedField, DefaultAlgorithmSelector, EncryptedField, FieldAlgorithmSelector,
        FieldConfigId, FieldEncryptionConfig, FieldEncryptionManager, FieldEncryptionMetadata,
        FieldEncryptionStrategy, FieldIdentifier, FieldSensitivity,
    };

    pub use crate::field_encryption_manager::{
        DefaultFieldEncryptionManager, FieldEncryptionManagerBuilder,
    };

    pub use crate::algorithm_registry::{
        AlgorithmMetadata, AlgorithmRegistry, AlgorithmRequirements, AlgorithmStatistics,
    };

    pub use crate::tenant::{
        CreateTenantRequest, GlobalResourceLimits, GlobalResourceUsage, InMemoryTenantManager,
        ResourceIsolationManager, Tenant, TenantEncryptionConfig, TenantId, TenantManager,
        TenantResourceLimits, TenantResourceUsage, TenantStats, UpdateTenantRequest,
    };

    pub use crate::backup::{
        BackupConfig, BackupItem, BackupManager, BackupManifest, BackupMetadata, BackupSchedule,
        BackupStorageStats, BackupStrategy, ConflictResolution, CrossRegionConfig,
        DisasterRecoveryManager, DisasterRecoveryPlan, RecoveryPriority, RecoveryStep,
        ReplicationResult, ReplicationStrategy, RestoreOperationStatus, RestoreStatus,
        RetentionPolicy as BackupRetentionPolicy, ScheduledRunResult, VerificationLevel,
        VerificationResult, VerificationStatus,
    };

    pub use crate::backup_manager::DefaultBackupManager;

    pub use crate::disaster_recovery::DefaultDisasterRecoveryManager;

    pub use crate::backup_scheduler::BackupScheduler;

    pub use crate::cross_region_replication::{CrossRegionReplicationManager, ReplicationStats};

    // pub use crate::simple_backup_manager::{SimpleBackupManager};

    #[cfg(feature = "discovery")]
    pub use crate::discovery::{
        DiscoveredNode, DiscoveryConfig, DiscoveryManager, NodeHealthStatus,
    };

    #[cfg(feature = "mesh")]
    pub use crate::mesh::{
        MeshConfig, MeshManager, MeshMetrics, MeshNode, SecurityPolicy, TrafficPolicy,
    };

    #[cfg(feature = "rate-limiting")]
    pub use crate::rate_limit::{
        RateLimitConfig, RateLimitContext, RateLimitManager, RateLimitResult, RateLimitRule,
    };

    pub use crate::performance_profile::{
        EncryptionSettings, NetworkSettings, PerformanceProfile, PerformanceProfileConfig,
        ProfileManager, ResourceLimits, StorageSettings, SyncMode, SystemInfo,
    };

    pub use crate::aes256gcm_wrapper::Aes256GcmWrapper;

    pub use crate::key_database::{
        create_key_database, KeyDatabase, KeyDatabaseBackend, KeyDatabaseConfig, KeyDatabaseStats,
        SqliteKeyDatabase,
    };

    pub use crate::key_preloader::{
        KeyAccessStats, KeyPreloadConfig, KeyPreloader, PreloadStats, PreloadStrategy,
    };

    pub use crate::key_cache::{CacheStats, KeyCache, KeyCacheConfig};

    pub use crate::auth_plugin::{
        AuthMethod, AuthPlugin, AuthPluginCapabilities, AuthPluginMetadata,
    };

    pub use crate::auth_plugin_manager::HotSwappableAuthPluginManager;

    pub use crate::auth_plugin_integration::{
        AuthMethodMetrics, AuthPluginIntegrationService, IntegrationConfig,
    };

    pub use crate::plugin::{
        Plugin, PluginCapability, PluginContext, PluginHealth, PluginInput, PluginManager,
        PluginMetadata, PluginMetrics, PluginRegistry, PluginResult,
    };

    pub use crate::plugin_marketplace::{
        InstalledPlugin, PluginInstaller, PluginMarketplace, PluginPackage, PluginRepository,
    };

    pub use crate::trng::{
        fill_random, global_trng, init_global_trng, random_bytes, random_u64, EntropySeededRng,
        EntropySource, TrngConfig, TrngHealth,
    };

    pub use crate::mpc::{
        ComputationConfig, ComputationResult, ComputationStatus, MpcManager, MpcMessage,
        MpcNetwork, MpcParty, MpcProtocol, PartyId, PartyRole, SecretShare, SecretSharingScheme,
        SessionId, ShamirSecretSharing, ShareId,
    };

    pub use crate::mpc_manager::{DefaultMpcManager, MpcManagerBuilder};

    pub use crate::mpc_party::{InMemoryMpcParty, MessageHandler, MpcPartyBuilder};

    pub use crate::mpc_network::{InMemoryMpcNetwork, MpcNetworkBuilder, NetworkStats};

    #[cfg(any(feature = "experimental", feature = "homomorphic-encryption"))]
    pub use crate::homomorphic_encryption::{
        CkksHomomorphic, HomomorphicCiphertext, HomomorphicEncryption, HomomorphicManager,
        HomomorphicManagerBuilder, HomomorphicOperation, HomomorphicPerformance, HomomorphicScheme,
        PaillierHomomorphic,
    };

    // quantum_resistant module is available under experimental feature

    pub use crate::threat_detection::{
        DefaultThreatDetectionEngine, DefaultThreatResponseSystem, DetectionRule,
        DetectionStatistics, ResponseAction, ResponseStatistics, SecurityEvent, SecurityIncident,
        ThreatDetection, ThreatDetectionEngine, ThreatResponseSystem, ThreatSeverity, ThreatType,
    };

    pub use crate::query_optimizer::{
        hash_query, ColumnStatistics, IndexStatistics, OptimizerStats, QueryOptimizer,
        QueryOptimizerConfig, TableStatistics,
    };

    pub use crate::performance::{
        decrypt_data_async, encrypt_data_async, global_metrics, global_profiler, AdaptiveEncryptor,
        AsyncEncryptionService, BatchEncryptor, HighPerformanceEncryptor, MemoryMonitor,
        MemoryPool, MemoryStats, PerformanceConfig, PerformanceMetrics, PerformanceProfiler,
        PerformanceTimer, PerformanceUtils, PooledBuffer, SimdEncryptor, StandardEncryptor,
    };

    #[cfg(feature = "distributed-cache")]
    pub use crate::distributed_cache::{
        create_distributed_cache, CacheBackend, CacheStatistics, DistributedCache,
        DistributedCacheConfig, EvictionPolicy, InMemoryCache,
    };

    pub use crate::connection_pool::{
        create_connection_pool, AdvancedConnectionPool, ConnectionManager, ConnectionPoolConfig,
        ConnectionStats, LoadBalanceAlgorithm, ServerEndpoint,
    };

    pub use crate::performance_monitor::{
        AdvancedPerformanceMonitor, AggregatedMetrics, ImplementationComplexity, PerformanceAlert,
        PerformanceMonitorConfig, ProfileSample, RecommendationPriority, TuningRecommendation,
    };

    pub use crate::auto_tuning::{
        AppliedChange, AutoTuningConfig, AutomaticPerformanceTuner, ChangeStatus, ImpactLevel,
        OptimizationGoal, ParameterCategory, ParameterType, TuningParameter, TuningStatus,
        TuningStrategy,
    };

    pub use crate::observability::{
        AdvancedMetricsCollector, AlertManager, AlertRule, DashboardConfig, DashboardManager,
        HealthChecker, HealthStatus, LogConfig, LogFormat, MetricType, ObservabilityConfig,
        ObservabilityManager, ObservabilityTracer, SpanContext, StructuredLogger, SystemStatus,
        TraceConfig, Widget,
    };

    pub use crate::tee::{
        AttestationResult, EnclaveConfig, EnclaveInfo, EnclaveStatus, SecureChannel,
        SecurityPolicy, TeeAwareKeyManager, TeeCapabilities, TeeManager, TeeProvider, TeeType,
    };

    pub use crate::tee_aws_nitro::{
        AwsNitroProvider, NitroCliResponse, NitroEnclaveDescription, NitroMeasurements,
    };

    pub use crate::tee_intel_sgx::{
        IntelSgxProvider, SgxAttributes, SgxMeasurement, SgxQuote, SgxReportBody, SgxSignatureData,
    };

    pub use crate::tee_communication::{
        AuthData, ChannelState, EncryptedPayload, KeyExchangeData, ProtocolConfig, SecureMessage,
        SecureMessageHeader, SecureMessageType, SecureProtocolHandler,
    };

    pub use crate::tee_attestation::{
        AttestationVerifier, NitroAttestationDocument, TrustedDataStore,
        TrustedDataStore as TrustedDataStoreType, VerificationConfig, VerificationDetails,
    };

    pub use crate::tee_key_management::{
        CryptographicOperationRequest, CryptographicOperationResponse, EnclaveKeyInfo,
        KeyGenerationRequest, KeyGenerationResponse, KeyPolicy, KeyRotationRequest,
        KeyRotationResponse, KeyStatus, KeyUsageMetrics,
    };

    pub use crate::compliance::{
        AuditFilter, BusinessAssociate, ComplianceAssessment, ComplianceAuditLogger,
        ComplianceConfig, ComplianceConfigManager, ComplianceEvent, ComplianceEventOutcome,
        ComplianceFinding, ComplianceFramework, ComplianceIssue, ComplianceManager,
        ComplianceReport, ConsentRecord, CoveredEntity, DataSubject, EventSeverity, FindingStatus,
        GdprComplianceManager, HipaaComplianceManager, IntegrityReport, RightsRequest,
        RightsRequestType,
    };

    pub use crate::compliance::framework::{
        AccessControl, AccessControlConfig, BreachNotificationConfig, CardAccessEvent,
        CardholderData, ComplianceAuditConfig, DataClassification, EncryptionConfig,
        PasswordPolicy, PciRequirement, PhiType, ProtectedHealthInfo, RequestStatus,
    };

    pub use crate::secrets::{
        EngineStats, EngineStatus, EngineType, LeaseInfo, Secret, SecretMetadata, SecretsConfig,
        SecretsEngine, SecretsEngineManager,
    };

    pub use crate::secrets_kv::{KvConfig, KvEngine, VersionedSecret};

    pub use crate::database_secrets::{
        DatabaseConfig, DatabaseCredential, DatabaseEngine, DatabaseType,
    };

    pub use crate::dynamic_secrets::{
        AwsConfig, AwsIamCredential, DynamicSecretsConfig, DynamicSecretsEngine,
    };

    pub use crate::kubernetes_auth::{
        KubernetesAuth, KubernetesAuthConfig, PodAuthResult, TokenReviewRequest,
        TokenReviewResponse, TokenUserInfo,
    };

    pub use crate::oidc_provider::{
        JsonWebKey, JsonWebKeySet, JwksConfig, OidcAuthRequest, OidcClient, OidcConfig,
        OidcProvider, OidcTokenRequest, OidcTokenResponse, OidcUserInfo, RegoConfig,
        RegoPolicyEngine, TokenExpiration,
    };

    pub use crate::format_preserving_encryption::{
        DataFormat, FormatPreservingEncryption, FpeAlgorithm, FpeConfig, FpeMetadata, FpeResult,
    };

    pub use crate::secure_audit::{
        AuditOutcome, AuditOutput, AuditStats, SecureAuditConfig, SecureAuditEntry,
        SecureAuditEventType, SecureAuditLogger, SecureRotationStrategy,
    };

    pub use crate::mongodb_database::{
        MongoAggregationResult, MongoConfig, MongoKeyDatabase, MongoPipeline, MongoPullFilter,
        MongoReadPreference, MongoSearchResult, MongoStorage, MongoWriteConcern,
    };

    pub use crate::postgres_database::{
        PostgresBulkEntry, PostgresConfig, PostgresCursor, PostgresJsonbQuery, PostgresKeyDatabase,
        PostgresPartitioning, PostgresQuery, PostgresReplicationConfig, PostgresRow,
        PostgresSearchResult, PostgresStorage, PostgresSyncMode,
    };

    #[cfg(feature = "mysql")]
    pub use crate::mysql_database::{
        MySQLConfig, MySQLDatabase, MySQLPartitioning, MySQLPoolManager, MySQLReplicationConfig,
        MySQLStats,
    };

    pub use crate::push_pull_operations::{
        ConflictInfo, ConflictType, DataVersion, ProgressUpdate, PullFilter, PullRequest,
        PushFilter, PushPullConfig, PushPullConflictResolution, PushPullManager,
        PushPullOperationType, PushPullResult, PushRequest, StorageSource, StorageTarget,
    };

    pub use crate::image_encryption::{
        ChunkConfig, ColorSpace, CompressionInfo, EncryptedImage, EncryptedMetadata,
        EncryptedThumbnail, EncryptionMode, EncryptionOptions, ImageEncryptionError,
        ImageEncryptor, ImageFilter, ImageFormat, ImageFormatDetector, ImageFormatInfo, ImageInfo,
        ImageMetadata, ImageSearchResult, SearchCriteria, StreamingImageEncryptor,
        ThumbnailGenerator, ThumbnailSize,
    };

    pub use crate::auth::{
        AuthConfig, AuthManager, AuthPermission, AuthToken, BiometricType, HardwareTokenType,
        LoginRequest, LoginResponse, SessionManager, TokenClaims, User, UserId,
    };

    pub use crate::multi_person_auth::{
        ApprovalDecision, ApprovalRequest, ApprovalRequestId, ApprovalStatus, ControlGroup,
        ControlGroupId, ControlGroupMember, ControlGroupRole, Decision, MultiPersonAuthManager,
        MultiPersonOperationType,
    };

    pub use crate::mpa_service::MpaService;

    pub use crate::seal::{MasterKey, SealConfig, SealManager, SealState};

    pub use crate::shamir::{multi_byte, Polynomial, Share};

    pub use crate::token::{
        CreateTokenRequest, RenewTokenRequest, RevocationEntry, RevocationList, RevocationReason,
        RevokeTokenRequest, Token, TokenInfo, TokenLookupResult, TokenManager, TokenMetadata,
        TokenRole, TokenType, TokenValidationResult,
    };

    pub use crate::policy_hcl::{
        ConstraintOperator, HclPolicyEngine, InMemoryRoleStore, ParsedPolicy, PolicyConstraint,
        PolicyContext, PolicyEvaluationResult, PolicyFunction, PolicyResult, RoleStore,
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
