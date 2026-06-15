//! Error types for Fortress operations

//!

//! This module defines comprehensive error types for all Fortress operations,

//! with a focus on security and clarity.

use thiserror::Error;

/// Result type alias for Fortress operations

pub type Result<T> = std::result::Result<T, FortressError>;

/// Main error type for Fortress operations

///

/// This enum represents all possible errors that can occur during Fortress operations.

/// Each variant provides specific context about the error and its cause.

#[derive(Error, Debug, Clone)]

pub enum FortressError {
    /// Encryption-related errors

    #[error("Encryption error: {message}")]
    Encryption {
        /// Error message
        message: String,

        /// Algorithm that caused the error
        algorithm: String,

        /// Error code for programmatic handling
        code: EncryptionErrorCode,
    },

    /// Key management errors

    #[error("Key management error: {message}")]
    KeyManagement {
        /// Error message
        message: String,

        /// Key ID if applicable
        key_id: Option<String>,

        /// Error code for programmatic handling
        code: KeyErrorCode,
    },

    /// Storage-related errors

    #[error("Storage error: {message}")]
    Storage {
        /// Error message
        message: String,

        /// Backend that caused the error
        backend: String,

        /// Error code for programmatic handling
        code: StorageErrorCode,
    },

    /// Configuration errors

    #[error("Configuration error: {message}")]
    Configuration {
        /// Error message
        message: String,

        /// Configuration field that caused the error
        field: Option<String>,

        /// Error code for programmatic handling
        code: ConfigurationErrorCode,
    },

    /// Query execution errors

    #[error("Query execution error: {message}")]
    QueryExecution {
        /// Error message
        message: String,

        /// Query that caused the error (if available)
        query: Option<String>,

        /// Error code for programmatic handling
        code: QueryErrorCode,
    },

    /// Validation errors

    #[error("Validation error: {message}")]
    Validation {
        /// Error message
        message: String,

        /// Field that failed validation
        field: Option<String>,

        /// Value that failed validation
        value: Option<String>,
    },

    /// I/O errors

    #[error("I/O error: {message}")]
    Io {
        /// Error message
        message: String,

        /// Path that caused the error (if applicable)
        path: Option<String>,
    },

    /// Network errors

    #[error("Network error: {message}")]
    Network {
        /// Error message
        message: String,

        /// Host or endpoint that caused the error
        endpoint: Option<String>,
    },

    /// Authentication/authorization errors

    #[error("Authentication error: {message}")]
    Authentication {
        /// Error message
        message: String,

        /// User or service that failed authentication
        principal: Option<String>,
    },

    /// Rate limiting errors

    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        /// Error message
        message: String,

        /// Current rate limit
        current_limit: Option<u32>,

        /// Time until reset (in seconds)
        reset_time: Option<u64>,
    },

    /// Internal errors

    #[error("Internal error: {message}")]
    Internal {
        /// Error message
        message: String,

        /// Internal error code
        code: String,
    },

    /// Policy and authorization errors

    #[error("Policy error: {0}")]
    PolicyError(String),

    /// Token-related errors

    #[error("Token error: {message}")]
    Token {
        /// Error message
        message: String,

        /// Token ID if applicable
        token_id: Option<String>,

        /// Error code for programmatic handling
        code: TokenErrorCode,
    },

    /// Seal-related errors

    #[error("Seal error: {message}")]
    Seal {
        /// Error message
        message: String,

        /// Error code for programmatic handling
        code: SealErrorCode,
    },

    /// Cluster-related errors

    #[error("Cluster error: {message}")]
    Cluster {
        /// Error message
        message: String,

        /// Node ID if applicable
        node_id: Option<String>,
    },

    /// Plugin-related errors

    #[error("Plugin error: {message}")]
    Plugin {
        /// Error message
        message: String,

        /// Plugin ID if applicable
        plugin_id: Option<String>,
    },

    /// TEE-related errors

    #[error("TEE error: {message}")]
    Tee {
        /// Error message
        message: String,

        /// Function where error occurred
        function: String,
    },

    /// Compliance-related errors

    #[error("Compliance error: {message}")]
    Compliance {
        /// Error message
        message: String,

        /// Compliance standard if applicable
        standard: Option<String>,

        /// Error code for programmatic handling
        code: ComplianceErrorCode,
    },

    /// Secrets management errors

    #[error("Secrets error: {message}")]
    Secrets {
        /// Error message
        message: String,

        /// Secrets engine if applicable
        engine: Option<String>,

        /// Error code for programmatic handling
        code: SecretsErrorCode,
    },

    /// HSM-related errors

    #[error("HSM error: {message}")]
    Hsm {
        /// Error message
        message: String,

        /// HSM provider if applicable
        provider: Option<String>,

        /// Error code for programmatic handling
        code: HsmErrorCode,
    },

    /// Transaction-related errors

    #[error("Transaction error: {message}")]
    Transaction {
        /// Error message
        message: String,

        /// Transaction ID if applicable
        transaction_id: Option<String>,

        /// Error code for programmatic handling
        code: TransactionErrorCode,
    },

    /// Backup and restore errors

    #[error("Backup error: {message}")]
    Backup {
        /// Error message
        message: String,

        /// Backup ID if applicable
        backup_id: Option<String>,

        /// Error code for programmatic handling
        code: BackupErrorCode,
    },

    /// WebSocket-related errors

    #[error("WebSocket error: {message}")]
    WebSocket {
        /// Error message
        message: String,

        /// Connection ID if applicable
        connection_id: Option<String>,

        /// Error code for programmatic handling
        code: String,
    },

    /// Streaming errors

    #[error("Streaming error: {message}")]
    Streaming {
        /// Error message
        message: String,

        /// Stream ID if applicable
        stream_id: Option<String>,

        /// Error code for programmatic handling
        code: StreamingErrorCode,
    },

    /// Audit logging errors

    #[error("Audit error: {message}")]
    Audit {
        /// Error message
        message: String,

        /// Audit log ID if applicable
        log_id: Option<String>,

        /// Error code for programmatic handling
        code: AuditErrorCode,
    },

    /// Discovery errors

    #[error("Discovery error: {message}")]
    Discovery {
        /// Error message
        message: String,
    },

    /// Mesh errors

    #[error("Mesh error: {message}")]
    Mesh {
        /// Error message
        message: String,
    },
}

/// Encryption error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum EncryptionErrorCode {
    /// Invalid key length

    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Invalid nonce length

    #[error("Invalid nonce length")]
    InvalidNonceLength,

    /// Authentication failed (tampered data)

    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Algorithm not supported

    #[error("Algorithm not supported")]
    AlgorithmNotSupported,

    /// Buffer too small

    #[error("Buffer too small")]
    BufferTooSmall,

    /// Encryption operation failed

    #[error("Encryption failed")]
    EncryptionFailed,

    /// Decryption operation failed

    #[error("Decryption failed")]
    DecryptionFailed,

    /// Invalid input

    #[error("Invalid input")]
    InvalidInput,

    /// Key generation failed

    #[error("Key generation failed")]
    KeyGenerationFailed,
}

/// Key management error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum KeyErrorCode {
    /// Key not found

    #[error("Key not found")]
    KeyNotFound,

    /// Key already exists

    #[error("Key already exists")]
    KeyAlreadyExists,

    /// Key rotation failed

    #[error("Key rotation failed")]
    RotationFailed,

    /// Key derivation failed

    #[error("Key derivation failed")]
    DerivationFailed,

    /// Key is expired

    #[error("Key is expired")]
    KeyExpired,

    /// Key is not yet valid

    #[error("Key is not yet valid")]
    KeyNotYetValid,

    /// Invalid key format

    #[error("Invalid key format")]
    InvalidKeyFormat,

    /// Key access denied

    #[error("Key access denied")]
    AccessDenied,

    /// Provider error

    #[error("Provider error")]
    ProviderError,

    /// Storage error

    #[error("Storage error")]
    StorageError,

    /// Serialization error

    #[error("Serialization error")]
    SerializationError,

    /// Authentication error

    #[error("Authentication error")]
    AuthenticationError,

    /// Key generation error

    #[error("Key generation error")]
    KeyGenerationError,

    /// Key deletion error

    #[error("Key deletion error")]
    KeyDeletionError,

    /// Signing error

    #[error("Signing error")]
    SigningError,

    /// Verification error

    #[error("Verification error")]
    VerificationError,

    /// Encryption error

    #[error("Encryption error")]
    EncryptionError,

    /// Decryption error

    #[error("Decryption error")]
    DecryptionError,
}

/// Storage error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum StorageErrorCode {
    /// Connection failed

    #[error("Connection failed")]
    ConnectionFailed,

    /// Item not found

    #[error("Item not found")]
    NotFound,

    /// Item already exists

    #[error("Item already exists")]
    AlreadyExists,

    /// Permission denied

    #[error("Permission denied")]
    PermissionDenied,

    /// Authentication error

    #[error("Authentication error")]
    AuthenticationError,

    /// Read error

    #[error("Read error")]
    ReadError,

    /// Write error

    #[error("Write error")]
    WriteError,

    /// Delete error

    #[error("Delete error")]
    DeleteError,

    /// Quota exceeded

    #[error("Quota exceeded")]
    QuotaExceeded,

    /// Backend not available

    #[error("Backend not available")]
    BackendNotAvailable,

    /// Invalid configuration

    #[error("Invalid configuration")]
    InvalidConfiguration,

    /// Corrupted data

    #[error("Corrupted data")]
    CorruptedData,

    /// Serialization error

    #[error("Serialization error")]
    SerializationError,

    /// Operation failed

    #[error("Operation failed")]
    OperationFailed,

    /// Invalid data

    #[error("Invalid data")]
    InvalidData,

    /// Rate limited

    #[error("Rate limited")]
    RateLimited,

    /// Invalid operation

    #[error("Invalid operation")]
    InvalidOperation,

    /// Not implemented

    #[error("Not implemented")]
    NotImplemented,

    /// Corrupted data (duplicate, will be removed in next version)

    #[error("Corrupted data")]
    CorruptedDataDuplicate,

    /// Operation cancelled

    #[error("Operation cancelled")]
    OperationCancelled,

    /// I/O error

    #[error("I/O error")]
    IoError,
}

/// Configuration error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum ConfigurationErrorCode {
    /// Invalid configuration format

    #[error("Invalid configuration format")]
    InvalidFormat,

    /// Missing required field

    #[error("Missing required field")]
    MissingField,

    /// Invalid value for field

    #[error("Invalid value")]
    InvalidValue,

    /// File system error

    #[error("File system error")]
    FileSystem,

    /// Policy compilation failed

    #[error("Policy compilation failed")]
    PolicyCompilationFailed,

    /// Configuration file not found

    #[error("Configuration file not found")]
    FileNotFound,

    /// Parse error in configuration

    #[error("Configuration parse error")]
    ParseError,

    /// Permission denied for configuration file

    #[error("Configuration file access denied")]
    AccessDenied,

    /// Circular dependency in configuration

    #[error("Circular dependency")]
    CircularDependency,
}

/// Query error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum QueryErrorCode {
    /// Invalid SQL syntax

    #[error("Invalid SQL syntax")]
    InvalidSyntax,

    /// Table not found

    #[error("Table not found")]
    TableNotFound,

    /// Column not found

    #[error("Column not found")]
    ColumnNotFound,

    /// Invalid parameter

    #[error("Invalid parameter")]
    InvalidParameter,

    /// Query timeout

    #[error("Query timeout")]
    Timeout,

    /// Query cancelled

    #[error("Query cancelled")]
    Cancelled,

    /// Insufficient permissions

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    /// Invalid operation

    #[error("Invalid operation")]
    InvalidOperation,
}

/// Compliance error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum ComplianceErrorCode {
    /// Policy not found

    #[error("Policy not found")]
    PolicyNotFound,

    /// Requirement not met

    #[error("Requirement not met")]
    RequirementNotMet,

    /// Data subject request failed

    #[error("Data subject request failed")]
    DataSubjectRequestFailed,

    /// Compliance verification failed

    #[error("Compliance verification failed")]
    VerificationFailed,

    /// Invalid compliance standard

    #[error("Invalid compliance standard")]
    InvalidStandard,

    /// Access denied for compliance operation

    #[error("Access denied")]
    AccessDenied,

    /// Data retention violation

    #[error("Data retention violation")]
    DataRetentionViolation,

    /// Audit trail required

    #[error("Audit trail required")]
    AuditTrailRequired,
}

/// Secrets management error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum SecretsErrorCode {
    /// Secret not found

    #[error("Secret not found")]
    SecretNotFound,

    /// Lease not found

    #[error("Lease not found")]
    LeaseNotFound,

    /// Lease expired

    #[error("Lease expired")]
    LeaseExpired,

    /// Engine not found

    #[error("Engine not found")]
    EngineNotFound,

    /// Invalid path

    #[error("Invalid path")]
    InvalidPath,

    /// Version not found

    #[error("Version not found")]
    VersionNotFound,

    /// Access denied

    #[error("Access denied")]
    AccessDenied,

    /// Invalid configuration

    #[error("Invalid configuration")]
    InvalidConfiguration,

    /// Lease TTL exceeded

    #[error("Lease TTL exceeded")]
    LeaseTtlExceeded,

    /// Secret already exists

    #[error("Secret already exists")]
    SecretAlreadyExists,
}

/// HSM error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum HsmErrorCode {
    /// HSM not available

    #[error("HSM not available")]
    HsmNotAvailable,

    /// Connection failed

    #[error("Connection failed")]
    ConnectionFailed,

    /// Authentication failed

    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Key not found

    #[error("Key not found")]
    KeyNotFound,

    /// Key already exists

    #[error("Key already exists")]
    KeyAlreadyExists,

    /// Invalid key format

    #[error("Invalid key format")]
    InvalidKeyFormat,

    /// Operation not supported

    #[error("Operation not supported")]
    OperationNotSupported,

    /// Invalid algorithm

    #[error("Invalid algorithm")]
    InvalidAlgorithm,

    /// HSM provider error

    #[error("HSM provider error")]
    ProviderError,

    /// Timeout

    #[error("Timeout")]
    Timeout,

    /// Invalid configuration

    #[error("Invalid configuration")]
    InvalidConfiguration,

    /// Permission denied

    #[error("Permission denied")]
    PermissionDenied,

    /// Resource exhausted

    #[error("Resource exhausted")]
    ResourceExhausted,

    /// Quota exceeded

    #[error("Quota exceeded")]
    QuotaExceeded,
}

/// Transaction error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum TransactionErrorCode {
    /// Transaction not found

    #[error("Transaction not found")]
    TransactionNotFound,

    /// Transaction already exists

    #[error("Transaction already exists")]
    TransactionAlreadyExists,

    /// Transaction aborted

    #[error("Transaction aborted")]
    TransactionAborted,

    /// Transaction timeout

    #[error("Transaction timeout")]
    TransactionTimeout,

    /// Deadlock detected

    #[error("Deadlock detected")]
    DeadlockDetected,

    /// Transaction isolation violation

    #[error("Transaction isolation violation")]
    IsolationViolation,

    /// Transaction rollback failed

    #[error("Transaction rollback failed")]
    RollbackFailed,

    /// Transaction commit failed

    #[error("Transaction commit failed")]
    CommitFailed,

    /// Savepoint not found

    #[error("Savepoint not found")]
    SavepointNotFound,

    /// Invalid transaction state

    #[error("Invalid transaction state")]
    InvalidState,

    /// Transaction lock acquisition failed

    #[error("Transaction lock acquisition failed")]
    LockAcquisitionFailed,

    /// Transaction serialization error

    #[error("Transaction serialization error")]
    SerializationError,
}

/// Backup error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum BackupErrorCode {
    /// Backup not found

    #[error("Backup not found")]
    BackupNotFound,

    /// Backup already exists

    #[error("Backup already exists")]
    BackupAlreadyExists,

    /// Backup creation failed

    #[error("Backup creation failed")]
    CreationFailed,

    /// Backup restoration failed

    #[error("Backup restoration failed")]
    RestorationFailed,

    /// Backup corruption detected

    #[error("Backup corruption detected")]
    CorruptionDetected,

    /// Backup verification failed

    #[error("Backup verification failed")]
    VerificationFailed,

    /// Backup encryption failed

    #[error("Backup encryption failed")]
    EncryptionFailed,

    /// Backup decryption failed

    #[error("Backup decryption failed")]
    DecryptionFailed,

    /// Backup compression failed

    #[error("Backup compression failed")]
    CompressionFailed,

    /// Backup decompression failed

    #[error("Backup decompression failed")]
    DecompressionFailed,

    /// Backup storage quota exceeded

    #[error("Backup storage quota exceeded")]
    StorageQuotaExceeded,

    /// Backup schedule conflict

    #[error("Backup schedule conflict")]
    ScheduleConflict,

    /// Backup in progress

    #[error("Backup in progress")]
    BackupInProgress,

    /// Restore in progress

    #[error("Restore in progress")]
    RestoreInProgress,

    /// Invalid backup format

    #[error("Invalid backup format")]
    InvalidFormat,
}

/// Streaming error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum StreamingErrorCode {
    /// Stream not found

    #[error("Stream not found")]
    StreamNotFound,

    /// Stream already exists

    #[error("Stream already exists")]
    StreamAlreadyExists,

    /// Stream connection failed

    #[error("Stream connection failed")]
    ConnectionFailed,

    /// Stream disconnection failed

    #[error("Stream disconnection failed")]
    DisconnectionFailed,

    /// Stream timeout

    #[error("Stream timeout")]
    StreamTimeout,

    /// Stream buffer overflow

    #[error("Stream buffer overflow")]
    BufferOverflow,

    /// Stream protocol error

    #[error("Stream protocol error")]
    ProtocolError,

    /// Stream authentication failed

    #[error("Stream authentication failed")]
    AuthenticationFailed,

    /// Stream authorization failed

    #[error("Stream authorization failed")]
    AuthorizationFailed,

    /// Stream rate limit exceeded

    #[error("Stream rate limit exceeded")]
    RateLimitExceeded,

    /// Stream subscription failed

    #[error("Stream subscription failed")]
    SubscriptionFailed,

    /// Stream publication failed

    #[error("Stream publication failed")]
    PublicationFailed,

    /// Stream encoding error

    #[error("Stream encoding error")]
    EncodingError,

    /// Stream decoding error

    #[error("Stream decoding error")]
    DecodingError,

    /// Stream resumption failed

    #[error("Stream resumption failed")]
    ResumptionFailed,

    /// Stream cancellation failed

    #[error("Stream cancellation failed")]
    CancellationFailed,
}

/// Token error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum TokenErrorCode {
    /// Token not found

    #[error("Token not found")]
    NotFound,

    /// Token creation failed

    #[error("Token creation failed")]
    CreationFailed,

    /// Token validation failed

    #[error("Token validation failed")]
    ValidationFailed,

    /// Token expired

    #[error("Token expired")]
    Expired,

    /// Token revoked

    #[error("Token revoked")]
    Revoked,

    /// Invalid token format

    #[error("Invalid token format")]
    InvalidFormat,

    /// Insufficient token permissions

    #[error("Insufficient token permissions")]
    InsufficientPermissions,

    /// Token lease failed

    #[error("Token lease failed")]
    LeaseFailed,

    /// Token renewal failed

    #[error("Token renewal failed")]
    RenewalFailed,

    /// Token lease renewal failed

    #[error("Token lease renewal failed")]
    LeaseRenewalFailed,

    /// Token not found

    #[error("Token not found")]
    TokenNotFound,

    /// Token not renewable

    #[error("Token not renewable")]
    NotRenewable,

    /// Token expired

    #[error("Token expired")]
    TokenExpired,

    /// Lease not found

    #[error("Lease not found")]
    LeaseNotFound,
}

/// Seal error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum SealErrorCode {
    /// Invalid share

    #[error("Invalid share")]
    InvalidShare,

    /// Insufficient shares

    #[error("Insufficient shares")]
    InsufficientShares,

    /// Share verification failed

    #[error("Share verification failed")]
    ShareVerificationFailed,

    /// Seal operation failed

    #[error("Seal operation failed")]
    SealFailed,

    /// Unseal operation failed

    #[error("Unseal operation failed")]
    UnsealFailed,

    /// Invalid threshold

    #[error("Invalid threshold")]
    InvalidThreshold,

    /// Master key not found

    #[error("Master key not found")]
    MasterKeyNotFound,

    /// Reconstruction failed

    #[error("Reconstruction failed")]
    ReconstructionFailed,

    /// Already unsealed

    #[error("Already unsealed")]
    AlreadyUnsealed,

    /// Already sealed

    #[error("Already sealed")]
    AlreadySealed,
}

/// Audit error codes

#[derive(Error, Debug, Clone, PartialEq, Eq)]

pub enum AuditErrorCode {
    /// Audit log not found

    #[error("Audit log not found")]
    LogNotFound,

    /// Audit log creation failed

    #[error("Audit log creation failed")]
    LogCreationFailed,

    /// Audit log storage failed

    #[error("Audit log storage failed")]
    LogStorageFailed,

    /// Audit log retrieval failed

    #[error("Audit log retrieval failed")]
    LogRetrievalFailed,

    /// Audit log corruption detected

    #[error("Audit log corruption detected")]
    LogCorruptionDetected,

    /// Audit log encryption failed

    #[error("Audit log encryption failed")]
    LogEncryptionFailed,

    /// Audit log decryption failed

    #[error("Audit log decryption failed")]
    LogDecryptionFailed,

    /// Audit log compression failed

    #[error("Audit log compression failed")]
    LogCompressionFailed,

    /// Audit log decompression failed

    #[error("Audit log decompression failed")]
    LogDecompressionFailed,

    /// Audit log rotation failed

    #[error("Audit log rotation failed")]
    LogRotationFailed,

    /// Audit log export failed

    #[error("Audit log export failed")]
    LogExportFailed,

    /// Audit log import failed

    #[error("Audit log import failed")]
    LogImportFailed,

    /// Audit policy not found

    #[error("Audit policy not found")]
    PolicyNotFound,

    /// Audit policy creation failed

    #[error("Audit policy creation failed")]
    PolicyCreationFailed,

    /// Audit policy validation failed

    #[error("Audit policy validation failed")]
    PolicyValidationFailed,

    /// Audit retention policy violation

    #[error("Audit retention policy violation")]
    RetentionPolicyViolation,

    /// Audit tampering detected

    #[error("Audit tampering detected")]
    TamperingDetected,

    /// Audit log quota exceeded

    #[error("Audit log quota exceeded")]
    LogQuotaExceeded,

    /// Audit configuration error

    #[error("Audit configuration error")]
    ConfigurationError,

    /// Audit verification failed

    #[error("Audit verification failed")]
    VerificationFailed,

    /// System error

    #[error("System error")]
    SystemError,
}

impl FortressError {
    /// Create a new encryption error

    pub fn encryption<S: Into<String>>(
        message: S,

        algorithm: S,

        code: EncryptionErrorCode,
    ) -> Self {
        Self::Encryption {
            message: message.into(),

            algorithm: algorithm.into(),

            code,
        }
    }

    /// Create a new key management error

    pub fn key_management<S: Into<String>>(
        message: S,

        key_id: Option<String>,

        code: KeyErrorCode,
    ) -> Self {
        Self::KeyManagement {
            message: message.into(),

            key_id,

            code,
        }
    }

    /// Create a new storage error

    pub fn storage<S: Into<String>>(message: S, backend: S, code: StorageErrorCode) -> Self {
        Self::Storage {
            message: message.into(),

            backend: backend.into(),

            code,
        }
    }

    /// Create a new configuration error

    pub fn configuration<S: Into<String>>(
        message: S,

        field: Option<String>,

        code: ConfigurationErrorCode,
    ) -> Self {
        Self::Configuration {
            message: message.into(),

            field,

            code,
        }
    }

    /// Create a new policy error

    pub fn policy<S: Into<String>>(message: S) -> Self {
        Self::PolicyError(message.into())
    }

    /// Create a new policy evaluation error

    pub fn policy_evaluation<S: Into<String>>(message: S, details: Option<S>) -> Self {
        Self::Internal {
            message: format!("Policy evaluation error: {}", message.into()),
            code: details.map(|s| s.into()).unwrap_or_else(|| "PolicyEvaluationError".to_string()),
        }
    }

    /// Create a new token error

    pub fn token_with_id<S: Into<String>>(
        message: S,

        token_id: Option<String>,

        code: TokenErrorCode,
    ) -> Self {
        Self::Token {
            message: message.into(),

            token_id,

            code,
        }
    }

    /// Create a new seal error

    pub fn seal_with_code<S: Into<String>>(message: S, code: SealErrorCode) -> Self {
        Self::Seal {
            message: message.into(),

            code,
        }
    }

    /// Create a new query execution error

    pub fn query_execution<S: Into<String>>(
        message: S,

        query: Option<String>,

        code: QueryErrorCode,
    ) -> Self {
        Self::QueryExecution {
            message: message.into(),

            query,

            code,
        }
    }

    /// Create a new validation error

    pub fn validation<S: Into<String>>(
        message: S,

        field: Option<String>,

        value: Option<String>,
    ) -> Self {
        Self::Validation {
            message: message.into(),

            field,

            value,
        }
    }

    /// Create a new I/O error

    pub fn io<S: Into<String>>(message: S, path: Option<String>) -> Self {
        Self::Io {
            message: message.into(),

            path,
        }
    }

    /// Create a new network error

    pub fn network<S: Into<String>>(message: S, endpoint: Option<String>) -> Self {
        Self::Network {
            message: message.into(),

            endpoint,
        }
    }

    /// Create a new authentication error

    pub fn authentication<S: Into<String>>(message: S, principal: Option<String>) -> Self {
        Self::Authentication {
            message: message.into(),

            principal,
        }
    }

    /// Create a new rate limit error

    pub fn rate_limit<S: Into<String>>(
        message: S,

        current_limit: Option<u32>,

        reset_time: Option<u64>,
    ) -> Self {
        Self::RateLimit {
            message: message.into(),

            current_limit,

            reset_time,
        }
    }

    /// Create a new internal error

    pub fn internal<S: Into<String>>(message: S, code: S) -> Self {
        Self::Internal {
            message: message.into(),

            code: code.into(),
        }
    }

    /// Create a new plugin error

    pub fn plugin<S: Into<String>>(message: S) -> Self {
        Self::Plugin {
            message: message.into(),

            plugin_id: None,
        }
    }

    /// Create a new TEE error

    pub fn tee<S: Into<String>>(message: S, function: S) -> Self {
        Self::Tee {
            message: message.into(),

            function: function.into(),
        }
    }

    /// Create a new plugin error with plugin ID

    pub fn plugin_with_id<S: Into<String>>(message: S, plugin_id: S) -> Self {
        Self::Plugin {
            message: message.into(),

            plugin_id: Some(plugin_id.into()),
        }
    }

    /// Create a new cluster error

    pub fn cluster<S: Into<String>>(message: S, node_id: Option<String>) -> Self {
        Self::Cluster {
            message: message.into(),

            node_id,
        }
    }

    /// Create a new WebSocket error

    pub fn websocket<S: Into<String>>(message: S) -> Self {
        Self::WebSocket {
            message: message.into(),

            connection_id: None,

            code: "WEBSOCKET_ERROR".to_string(),
        }
    }

    /// Create a new WebSocket error with connection ID

    pub fn websocket_with_connection<S: Into<String>>(message: S, connection_id: String) -> Self {
        Self::WebSocket {
            message: message.into(),

            connection_id: Some(connection_id),

            code: "WEBSOCKET_ERROR".to_string(),
        }
    }

    /// Create a new compliance error

    pub fn compliance<S: Into<String>>(message: S) -> Self {
        Self::Compliance {
            message: message.into(),

            standard: None,

            code: ComplianceErrorCode::VerificationFailed,
        }
    }

    /// Create a new compliance error with standard and code

    pub fn compliance_with_code<S: Into<String>>(
        message: S,

        standard: Option<String>,

        code: ComplianceErrorCode,
    ) -> Self {
        Self::Compliance {
            message: message.into(),

            standard,

            code,
        }
    }

    /// Create a new secrets error

    pub fn secrets<S: Into<String>>(message: S) -> Self {
        Self::Secrets {
            message: message.into(),

            engine: None,

            code: SecretsErrorCode::SecretNotFound,
        }
    }

    /// Create a new secrets error with engine and code

    pub fn secrets_with_code<S: Into<String>>(
        message: S,

        engine: Option<String>,

        code: SecretsErrorCode,
    ) -> Self {
        Self::Secrets {
            message: message.into(),

            engine,

            code,
        }
    }

    /// Create a new HSM error

    pub fn hsm<S: Into<String>>(message: S) -> Self {
        Self::Hsm {
            message: message.into(),

            provider: None,

            code: HsmErrorCode::ProviderError,
        }
    }

    /// Create a new HSM error with provider and code

    pub fn hsm_with_code<S: Into<String>>(
        message: S,

        provider: Option<String>,

        code: HsmErrorCode,
    ) -> Self {
        Self::Hsm {
            message: message.into(),

            provider,

            code,
        }
    }

    /// Create a new transaction error

    pub fn transaction<S: Into<String>>(
        message: S,

        transaction_id: Option<String>,

        code: TransactionErrorCode,
    ) -> Self {
        Self::Transaction {
            message: message.into(),

            transaction_id,

            code,
        }
    }

    /// Create a new backup error

    pub fn backup<S: Into<String>>(
        message: S,

        backup_id: Option<String>,

        code: BackupErrorCode,
    ) -> Self {
        Self::Backup {
            message: message.into(),

            backup_id,

            code,
        }
    }

    /// Create a new streaming error

    pub fn streaming<S: Into<String>>(
        message: S,

        stream_id: Option<String>,

        code: StreamingErrorCode,
    ) -> Self {
        Self::Streaming {
            message: message.into(),

            stream_id,

            code,
        }
    }

    /// Create a new audit error

    pub fn audit<S: Into<String>>(
        message: S,

        log_id: Option<String>,

        code: AuditErrorCode,
    ) -> Self {
        Self::Audit {
            message: message.into(),

            log_id,

            code,
        }
    }

    /// Create a new serialization error

    pub fn serialization<S: Into<String>>(message: S, details: &str) -> Self {
        Self::Internal {
            message: format!("Serialization error: {}", message.into()),

            code: format!("SerializationError: {}", details),
        }
    }

    /// Create a new compression error

    pub fn compression<S: Into<String>>(message: S, details: &str) -> Self {
        Self::Internal {
            message: format!("Compression error: {}", message.into()),

            code: format!("CompressionError: {}", details),
        }
    }

    /// Create a new memory error

    pub fn memory<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: format!("Memory error: {}", message.into()),

            code: "MemoryError".to_string(),
        }
    }

    /// Create a new processor error

    pub fn processor_error<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: format!("Processor error: {}", message.into()),

            code: "ProcessorError".to_string(),
        }
    }

    /// Check if this error is retryable

    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network { .. }
            | Self::Storage {
                code: StorageErrorCode::ConnectionFailed,
                ..
            } => true,

            Self::RateLimit { .. } => true,

            Self::Io { .. } => true,

            Self::Cluster { .. } => true,

            Self::WebSocket { .. } => true,

            Self::Plugin { .. } => true,

            Self::Transaction {
                code: TransactionErrorCode::TransactionTimeout,
                ..
            } => true,

            Self::Transaction {
                code: TransactionErrorCode::DeadlockDetected,
                ..
            } => true,

            Self::Backup {
                code: BackupErrorCode::BackupInProgress,
                ..
            } => true,

            Self::Backup {
                code: BackupErrorCode::RestoreInProgress,
                ..
            } => true,

            Self::Streaming {
                code: StreamingErrorCode::StreamTimeout,
                ..
            } => true,

            Self::Streaming {
                code: StreamingErrorCode::ConnectionFailed,
                ..
            } => true,

            _ => false,
        }
    }

    /// Check if this error is a security-related error

    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::Encryption { .. }
                | Self::KeyManagement { .. }
                | Self::Authentication { .. }
                | Self::Compliance { .. }
                | Self::Secrets { .. }
                | Self::Audit {
                    code: AuditErrorCode::TamperingDetected,
                    ..
                }
                | Self::Audit {
                    code: AuditErrorCode::LogCorruptionDetected,
                    ..
                }
                | Self::Streaming {
                    code: StreamingErrorCode::AuthenticationFailed,
                    ..
                }
                | Self::Streaming {
                    code: StreamingErrorCode::AuthorizationFailed,
                    ..
                }
        )
    }

    /// Get the error category for logging/metrics

    pub fn category(&self) -> &'static str {
        match self {
            Self::Encryption { .. } => "encryption",

            Self::KeyManagement { .. } => "key_management",

            Self::Storage { .. } => "storage",

            Self::Configuration { .. } => "configuration",

            Self::QueryExecution { .. } => "query",

            Self::Validation { .. } => "validation",

            Self::Io { .. } => "io",

            Self::Network { .. } => "network",

            Self::Authentication { .. } => "authentication",

            Self::RateLimit { .. } => "rate_limit",

            Self::Internal { .. } => "internal",

            Self::PolicyError(_) => "policy",

            Self::Token { .. } => "token",

            Self::Seal { .. } => "seal",

            Self::Cluster { .. } => "cluster",

            Self::Plugin { .. } => "plugin",

            Self::Compliance { .. } => "compliance",

            Self::Secrets { .. } => "secrets",

            Self::Hsm { .. } => "hsm",

            Self::Transaction { .. } => "transaction",

            Self::Backup { .. } => "backup",

            Self::Streaming { .. } => "streaming",

            Self::Audit { .. } => "audit",

            Self::Discovery { .. } => "discovery",

            Self::Mesh { .. } => "mesh",

            Self::Tee { .. } => "tee",

            Self::WebSocket { .. } => "websocket",
        }
    }

    /// Create a new discovery error
    pub fn discovery<S: Into<String>>(message: S) -> Self {
        Self::Discovery {
            message: message.into(),
        }
    }

    /// Create a new mesh error
    pub fn mesh<S: Into<String>>(message: S) -> Self {
        Self::Mesh {
            message: message.into(),
        }
    }
}

// Implement conversions from standard error types

impl From<std::io::Error> for FortressError {
    fn from(err: std::io::Error) -> Self {
        Self::io(err.to_string(), None)
    }
}

impl From<serde_json::Error> for FortressError {
    fn from(err: serde_json::Error) -> Self {
        Self::configuration(
            format!("JSON serialization error: {}", err),
            None,
            ConfigurationErrorCode::InvalidFormat,
        )
    }
}

impl From<toml::de::Error> for FortressError {
    fn from(err: toml::de::Error) -> Self {
        Self::configuration(
            format!("TOML parsing error: {}", err),
            Some("toml_parse".to_string()),
            ConfigurationErrorCode::ParseError,
        )
    }
}

impl From<std::string::FromUtf8Error> for FortressError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::internal(
            format!("UTF-8 conversion error: {}", err),
            "Utf8Error".to_string(),
        )
    }
}

impl serde::de::Error for FortressError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        FortressError::internal(msg.to_string(), "CustomError".to_string())
    }
}

impl serde::ser::Error for FortressError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        FortressError::internal(msg.to_string(), "CustomError".to_string())
    }
}

#[cfg(test)]

mod tests {

    use super::*;

    #[test]

    fn test_error_creation() {
        let err = FortressError::encryption(
            "Invalid key",
            "AEGIS-256",
            EncryptionErrorCode::InvalidKeyLength,
        );

        assert!(matches!(err, FortressError::Encryption { .. }));

        assert_eq!(err.category(), "encryption");

        assert!(!err.is_retryable());

        assert!(err.is_security_error());
    }

    #[test]

    fn test_retryable_errors() {
        let network_err =
            FortressError::network("Connection failed", Some("api.example.com".to_string()));

        assert!(network_err.is_retryable());

        let encryption_err =
            FortressError::encryption("Failed", "AES", EncryptionErrorCode::EncryptionFailed);

        assert!(!encryption_err.is_retryable());
    }

    #[test]

    fn test_security_errors() {
        let auth_err = FortressError::authentication("Invalid token", Some("user123".to_string()));

        assert!(auth_err.is_security_error());

        let io_err = FortressError::io("File not found", Some("/path/to/file".to_string()));

        assert!(!io_err.is_security_error());
    }

    #[test]

    fn test_error_categories() {
        let storage_err = FortressError::storage("Not found", "local", StorageErrorCode::NotFound);

        assert_eq!(storage_err.category(), "storage");

        let config_err = FortressError::configuration(
            "Missing field",
            Some("port".to_string()),
            ConfigurationErrorCode::MissingField,
        );

        assert_eq!(config_err.category(), "configuration");
    }

    #[test]

    fn test_error_display() {
        let err = FortressError::validation(
            "Value too long",
            Some("username".to_string()),
            Some("very_long_username".to_string()),
        );

        let display = format!("{}", err);

        assert!(display.contains("Validation error"));

        assert!(display.contains("Value too long"));
    }
}
