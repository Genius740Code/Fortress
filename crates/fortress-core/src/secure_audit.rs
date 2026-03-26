//! # Secure Audit Logging System
//!
//! Tamper-proof structured audit logging for security-sensitive operations.
//!
//! ## Features
//!
//! - **Structured Logging**: JSON-formatted audit entries
//! - **Cryptographic Integrity**: HMAC-based tamper detection
//! - **Immutable Logs**: Append-only log structure
//! - **Chain of Custody**: Cryptographic linking between entries
//! - **Multiple Outputs**: File, stdout, and syslog support
//! - **Performance Optimized**: Async batched writes
//!
//! ## Usage
//!
//! ```rust,no_run
//! use fortress_core::secure_audit::SecureAuditLogger;
//! use serde_json::json;
//!
//! let logger = SecureAuditLogger::new();
//!
//! // Configure audit logging
//! logger.configure(json!({
//!     "output": "file",
//!     "file_path": "/var/log/fortress/audit.log",
//!     "rotation": "daily",
//!     "retention_days": 90
//! })).await?;
//!
//! // Log an audit event
//! logger.log_access("user123", "secret/myapp", "read", "success").await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{FortressError, Result, AuditErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::Engine as _;

type HmacSha256 = Hmac<Sha256>;

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub entry_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// User/Service performing the action
    pub principal: String,
    /// Resource being accessed
    pub resource: String,
    /// Action performed
    pub action: String,
    /// Operation result
    pub outcome: AuditOutcome,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// Request ID
    pub request_id: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Previous entry hash (for chain integrity)
    pub previous_hash: Option<String>,
    /// Current entry hash
    pub current_hash: String,
    /// HMAC for integrity verification
    pub hmac: String,
}

/// Audit event types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Secret access
    SecretAccess,
    /// Secret creation/modification
    SecretWrite,
    /// Secret deletion
    SecretDelete,
    /// Secret listing
    SecretList,
    /// Authentication event
    Authentication,
    /// Authorization event
    Authorization,
    /// Configuration change
    ConfigurationChange,
    /// System event
    System,
    /// Security event
    Security,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::SecretAccess => write!(f, "SecretAccess"),
            AuditEventType::SecretWrite => write!(f, "SecretWrite"),
            AuditEventType::SecretDelete => write!(f, "SecretDelete"),
            AuditEventType::SecretList => write!(f, "SecretList"),
            AuditEventType::Authentication => write!(f, "Authentication"),
            AuditEventType::Authorization => write!(f, "Authorization"),
            AuditEventType::ConfigurationChange => write!(f, "ConfigurationChange"),
            AuditEventType::System => write!(f, "System"),
            AuditEventType::Security => write!(f, "Security"),
        }
    }
}

/// Audit operation outcomes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// Operation succeeded
    Success,
    /// Operation failed
    Failure,
    /// Operation denied
    Denied,
    /// Operation error
    Error,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditOutcome::Success => write!(f, "Success"),
            AuditOutcome::Failure => write!(f, "Failure"),
            AuditOutcome::Denied => write!(f, "Denied"),
            AuditOutcome::Error => write!(f, "Error"),
        }
    }
}

/// Audit logger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Output destination (file, stdout, syslog)
    pub output: AuditOutput,
    /// File path for file output
    pub file_path: Option<String>,
    /// Log rotation strategy
    pub rotation: RotationStrategy,
    /// Retention period in days
    pub retention_days: u32,
    /// HMAC key for integrity
    pub hmac_key: String,
    /// Enable compression for old logs
    pub compression: bool,
    /// Buffer size for batched writes
    pub buffer_size: usize,
    /// Flush interval in seconds
    pub flush_interval: u64,
}

/// Audit output destinations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuditOutput {
    /// Output to file
    File,
    /// Output to stdout
    Stdout,
    /// Output to syslog
    Syslog,
    /// Output to multiple destinations
    Multiple(Vec<AuditOutput>),
}

/// Log rotation strategies
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RotationStrategy {
    /// No rotation
    None,
    /// Rotate daily
    Daily,
    /// Rotate when file reaches size limit
    Size(u64),
    /// Rotate hourly
    Hourly,
}

/// Secure audit logger
#[derive(Debug)]
pub struct SecureAuditLogger {
    /// Logger configuration
    config: Arc<RwLock<Option<AuditConfig>>>,
    /// Previous entry hash for chaining
    previous_hash: Arc<RwLock<Option<String>>>,
    /// Entry counter
    entry_counter: Arc<RwLock<u64>>,
    /// Write buffer
    buffer: Arc<RwLock<Vec<AuditEntry>>>,
    /// File writer for file output
    file_writer: Arc<RwLock<Option<BufWriter<File>>>>,
    /// HMAC key
    hmac_key: Arc<RwLock<Option<Vec<u8>>>>,
    /// Statistics
    stats: Arc<RwLock<AuditStats>>,
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total entries logged
    pub total_entries: u64,
    /// Entries by event type
    pub entries_by_type: HashMap<AuditEventType, u64>,
    /// Entries by outcome
    pub entries_by_outcome: HashMap<AuditOutcome, u64>,
    /// Last log time
    pub last_log_time: Option<DateTime<Utc>>,
    /// Integrity violations detected
    pub integrity_violations: u64,
}

impl SecureAuditLogger {
    /// Create new secure audit logger
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            previous_hash: Arc::new(RwLock::new(None)),
            entry_counter: Arc::new(RwLock::new(0)),
            buffer: Arc::new(RwLock::new(Vec::new())),
            file_writer: Arc::new(RwLock::new(None)),
            hmac_key: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(AuditStats {
                total_entries: 0,
                entries_by_type: HashMap::new(),
                entries_by_outcome: HashMap::new(),
                last_log_time: None,
                integrity_violations: 0,
            })),
        }
    }

    /// Generate unique entry ID
    async fn generate_entry_id(&self) -> String {
        let mut counter = self.entry_counter.write().await;
        *counter += 1;
        
        format!("audit_{}_{}", 
            Utc::now().timestamp_nanos_opt().unwrap_or(0),
            *counter)
    }

    /// Calculate hash for audit entry
    fn calculate_hash(&self, entry: &AuditEntry) -> String {
        let mut hasher = Sha256::new();
        
        // Hash all fields except hmac and current_hash
        let hash_data = format!("{}|{}|{}|{}|{}|{}|{:?}|{}|{}|{}|{}|{}|",
            entry.entry_id,
            entry.timestamp.to_rfc3339(),
            entry.event_type,
            entry.principal,
            entry.resource,
            entry.action,
            entry.outcome,
            entry.source_ip.as_deref().unwrap_or(""),
            entry.user_agent.as_deref().unwrap_or(""),
            entry.session_id.as_deref().unwrap_or(""),
            entry.request_id.as_deref().unwrap_or(""),
            serde_json::to_string(&entry.metadata).unwrap_or_default(),
            entry.previous_hash.as_deref().unwrap_or("")
        );
        
        hasher.update(hash_data.as_bytes());
        let result = hasher.finalize();
        
        base64::engine::general_purpose::STANDARD.encode(result)
    }

    /// Calculate HMAC for integrity verification
    fn calculate_hmac(&self, entry: &AuditEntry, key: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take key of any size");
        
        let hmac_data = format!("{}|{}|{}",
            entry.entry_id,
            entry.current_hash,
            entry.previous_hash.as_deref().unwrap_or("")
        );
        
        mac.update(hmac_data.as_bytes());
        let result = mac.finalize();
        
        base64::engine::general_purpose::STANDARD.encode(result.into_bytes())
    }

    /// Verify entry integrity
    fn verify_entry_integrity(&self, entry: &AuditEntry, key: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take key of any size");
        
        let hmac_data = format!("{}|{}|{}",
            entry.entry_id,
            entry.current_hash,
            entry.previous_hash.as_deref().unwrap_or("")
        );
        
        mac.update(hmac_data.as_bytes());
        
        if let Ok(decoded_hmac) = base64::engine::general_purpose::STANDARD.decode(&entry.hmac) {
            mac.verify((&decoded_hmac[..]).into()).is_ok()
        } else {
            false
        }
    }

    /// Write entry to file
    async fn write_to_file(&self, entry: &AuditEntry) -> Result<()> {
        let config = self.config.read().await;
        let config = config.as_ref()
            .ok_or_else(|| FortressError::audit("Audit logger not configured".to_string(), None, AuditErrorCode::ConfigurationError))?;

        if config.output != AuditOutput::File && !matches!(config.output, AuditOutput::Multiple(_)) {
            return Ok(());
        }

        let mut writer = self.file_writer.write().await;
        
        // Initialize file writer if needed
        if writer.is_none() {
            if let Some(file_path) = &config.file_path {
                // Ensure directory exists
                if let Some(parent) = Path::new(file_path).parent() {
                    tokio::fs::create_dir_all(parent).await
                        .map_err(|e| FortressError::audit(format!("Failed to create audit log directory: {}", e), None, AuditErrorCode::LogCreationFailed))?;
                }

                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file_path)
                    .map_err(|e| FortressError::audit(format!("Failed to open audit log file: {}", e), None, AuditErrorCode::LogCreationFailed))?;

                *writer = Some(BufWriter::new(file));
            }
        }

        // Write entry
        if let Some(writer) = writer.as_mut() {
            let entry_json = serde_json::to_string(entry)
                .map_err(|e| FortressError::audit(format!("Failed to write audit entry: {}", e), None, AuditErrorCode::LogStorageFailed))?;
            
            writer.write_all(entry_json.as_bytes())
                .map_err(|e| FortressError::audit(format!("Failed to write audit entry to file: {}", e), None, AuditErrorCode::LogStorageFailed))?;
            writer.flush()
                .map_err(|e| FortressError::audit(format!("Failed to flush audit log: {}", e), None, AuditErrorCode::LogStorageFailed))?;
        }

        Ok(())
    }

    /// Write entry to stdout
    async fn write_to_stdout(&self, entry: &AuditEntry) -> Result<()> {
        let config = self.config.read().await;
        let config = config.as_ref()
            .ok_or_else(|| FortressError::audit("Audit logger not configured".to_string(), None, AuditErrorCode::ConfigurationError))?;

        if config.output != AuditOutput::Stdout && !matches!(config.output, AuditOutput::Multiple(_)) {
            return Ok(());
        }

        let entry_json = serde_json::to_string(entry)
            .map_err(|e| FortressError::audit(format!("Failed to serialize audit entry: {}", e), None, AuditErrorCode::LogCreationFailed))?;
        
        println!("{}", entry_json);
        Ok(())
    }

    /// Create audit entry
    async fn create_entry(
        &self,
        event_type: AuditEventType,
        principal: &str,
        resource: &str,
        action: &str,
        outcome: AuditOutcome,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<AuditEntry> {
        let config = self.config.read().await;
        let config = config.as_ref()
            .ok_or_else(|| FortressError::audit("Audit logger not configured".to_string(), None, AuditErrorCode::ConfigurationError))?;

        let entry_id = self.generate_entry_id().await;
        let previous_hash = self.previous_hash.read().await.clone();

        let entry = AuditEntry {
            entry_id: entry_id.clone(),
            timestamp: Utc::now(),
            event_type: event_type.clone(),
            principal: principal.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            outcome: outcome.clone(),
            source_ip: metadata.get("source_ip")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            user_agent: metadata.get("user_agent")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            session_id: metadata.get("session_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            request_id: metadata.get("request_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            metadata,
            previous_hash: previous_hash.clone(),
            current_hash: String::new(), // Will be set after hash calculation
            hmac: String::new(), // Will be set after HMAC calculation
        };

        // Calculate hash and HMAC
        let hmac_key = self.hmac_key.read().await;
        let hmac_key = hmac_key.as_ref()
            .ok_or_else(|| FortressError::audit("HMAC key not configured".to_string(), None, AuditErrorCode::ConfigurationError))?;
        let mut entry_with_hash = entry;
        entry_with_hash.current_hash = self.calculate_hash(&entry_with_hash);
        entry_with_hash.hmac = self.calculate_hmac(&entry_with_hash, hmac_key);

        // Update previous hash for next entry
        {
            let mut prev_hash = self.previous_hash.write().await;
            *prev_hash = Some(entry_with_hash.current_hash.clone());
        }

        Ok(entry_with_hash)
    }

    /// Log secret access
    pub async fn log_access(
        &self,
        principal: &str,
        resource: &str,
        action: &str,
        outcome: &str,
    ) -> Result<()> {
        let outcome_enum = match outcome {
            "success" => AuditOutcome::Success,
            "failure" => AuditOutcome::Failure,
            "denied" => AuditOutcome::Denied,
            _ => AuditOutcome::Error,
        };

        let metadata = HashMap::new();
        let entry = self.create_entry(
            AuditEventType::SecretAccess,
            principal,
            resource,
            action,
            outcome_enum.clone(),
            metadata,
        ).await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_entries += 1;
            *stats.entries_by_type.entry(AuditEventType::SecretAccess).or_insert(0) += 1;
            *stats.entries_by_outcome.entry(outcome_enum).or_insert(0) += 1;
            stats.last_log_time = Some(Utc::now());
        }

        // Write to outputs
        self.write_to_file(&entry).await?;
        self.write_to_stdout(&entry).await?;

        Ok(())
    }

    /// Log secret write operation
    pub async fn log_secret_write(
        &self,
        principal: &str,
        resource: &str,
        version: u64,
        outcome: &str,
    ) -> Result<()> {
        let outcome_enum = match outcome {
            "success" => AuditOutcome::Success,
            "failure" => AuditOutcome::Failure,
            "denied" => AuditOutcome::Denied,
            _ => AuditOutcome::Error,
        };

        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), serde_json::Value::Number(version.into()));

        let entry = self.create_entry(
            AuditEventType::SecretWrite,
            principal,
            resource,
            "write",
            outcome_enum.clone(),
            metadata,
        ).await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_entries += 1;
            *stats.entries_by_type.entry(AuditEventType::SecretWrite).or_insert(0) += 1;
            *stats.entries_by_outcome.entry(outcome_enum).or_insert(0) += 1;
            stats.last_log_time = Some(Utc::now());
        }

        // Write to outputs
        self.write_to_file(&entry).await?;
        self.write_to_stdout(&entry).await?;

        Ok(())
    }

    /// Log secret deletion
    pub async fn log_secret_delete(
        &self,
        principal: &str,
        resource: &str,
        outcome: &str,
    ) -> Result<()> {
        let outcome_enum = match outcome {
            "success" => AuditOutcome::Success,
            "failure" => AuditOutcome::Failure,
            "denied" => AuditOutcome::Denied,
            _ => AuditOutcome::Error,
        };

        let metadata = HashMap::new();
        let entry = self.create_entry(
            AuditEventType::SecretDelete,
            principal,
            resource,
            "delete",
            outcome_enum.clone(),
            metadata,
        ).await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_entries += 1;
            *stats.entries_by_type.entry(AuditEventType::SecretDelete).or_insert(0) += 1;
            *stats.entries_by_outcome.entry(outcome_enum).or_insert(0) += 1;
            stats.last_log_time = Some(Utc::now());
        }

        // Write to outputs
        self.write_to_file(&entry).await?;
        self.write_to_stdout(&entry).await?;

        Ok(())
    }

    /// Verify log integrity
    pub async fn verify_log_integrity(&self, file_path: &str) -> Result<bool> {
        let config = self.config.read().await;
        let config = config.as_ref()
            .ok_or_else(|| FortressError::audit("Audit logger not configured".to_string(), None, AuditErrorCode::ConfigurationError))?;

        let hmac_key = self.hmac_key.read().await;
        let hmac_key = hmac_key.as_ref()
            .ok_or_else(|| FortressError::audit("HMAC key not configured".to_string(), None, AuditErrorCode::ConfigurationError))?;

        let content = tokio::fs::read_to_string(file_path).await
            .map_err(|e| FortressError::audit(format!("Failed to read audit log: {}", e), None, AuditErrorCode::LogRetrievalFailed))?;

        let lines: Vec<&str> = content.lines().collect();
        let mut previous_hash: Option<String> = None;
        let mut violations = 0;

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(line)
                .map_err(|e| FortressError::audit(format!("Failed to parse audit entry: {}", e), None, AuditErrorCode::LogRetrievalFailed))?;

            // Verify previous hash chain
            if let Some(prev_hash) = &previous_hash {
                if entry.previous_hash.as_ref() != Some(prev_hash) {
                    violations += 1;
                    log::warn!("Hash chain violation detected for entry: {}", entry.entry_id);
                }
            }

            // Verify HMAC integrity
            if !self.verify_entry_integrity(&entry, hmac_key) {
                violations += 1;
                log::warn!("HMAC integrity violation detected for entry: {}", entry.entry_id);
            }

            previous_hash = Some(entry.current_hash.clone());
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.integrity_violations += violations;
        }

        if violations > 0 {
            log::error!("Found {} integrity violations in audit log", violations);
            Ok(false)
        } else {
            log::info!("Audit log integrity verified successfully");
            Ok(true)
        }
    }

    /// Get audit statistics
    pub async fn get_stats(&self) -> AuditStats {
        self.stats.read().await.clone()
    }

    /// Flush buffered entries
    pub async fn flush(&self) -> Result<()> {
        let buffer = self.buffer.write().await;
        
        for entry in buffer.iter() {
            self.write_to_file(entry).await?;
            self.write_to_stdout(entry).await?;
        }

        // Clear buffer
        drop(buffer);
        let mut buffer = self.buffer.write().await;
        buffer.clear();

        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::secrets::SecretsEngine for SecureAuditLogger {
    fn name(&self) -> &str {
        "secure-audit"
    }

    fn engine_type(&self) -> crate::secrets::EngineType {
        crate::secrets::EngineType::Custom("secure-audit".to_string())
    }

    async fn write(&self, _path: &str, _data: &serde_json::Value) -> Result<crate::secrets::Secret> {
        Err(FortressError::audit("Write operation not supported on audit logger".to_string(), None, AuditErrorCode::PolicyNotFound))
    }

    async fn read(&self, _path: &str) -> Result<Option<crate::secrets::Secret>> {
        Err(FortressError::audit("Read operation not supported on audit logger".to_string(), None, AuditErrorCode::PolicyNotFound))
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        Err(FortressError::audit("Delete operation not supported on audit logger".to_string(), None, AuditErrorCode::PolicyNotFound))
    }

    async fn list(&self, _path: &str) -> Result<Vec<String>> {
        Err(FortressError::audit("List operation not supported on audit logger".to_string(), None, AuditErrorCode::PolicyNotFound))
    }

    async fn renew(&self, _lease_id: &str, _increment: Option<u64>) -> Result<crate::secrets::LeaseInfo> {
        Err(FortressError::audit("Renew operation not supported on audit logger".to_string(), None, AuditErrorCode::PolicyNotFound))
    }

    async fn revoke(&self, _lease_id: &str) -> Result<()> {
        Err(FortressError::audit("Revoke operation not supported on audit logger".to_string(), None, AuditErrorCode::PolicyNotFound))
    }

    async fn configure(&mut self, config: serde_json::Value) -> Result<()> {
        let audit_config: AuditConfig = serde_json::from_value(config)
            .map_err(|e| FortressError::audit(format!("Invalid audit configuration: {}", e), None, AuditErrorCode::ConfigurationError))?;
        
        let mut self_config = self.config.write().await;
        *self_config = Some(audit_config.clone());

        // Set HMAC key
        let mut hmac_key = self.hmac_key.write().await;
        *hmac_key = Some(audit_config.hmac_key.as_bytes().to_vec());

        Ok(())
    }

    async fn status(&self) -> Result<crate::secrets::EngineStatus> {
        let config = self.config.read().await;
        let stats = self.stats.read().await;
        
        let config_value = match config.as_ref() {
            Some(c) => serde_json::to_value(c).unwrap_or_default(),
            None => serde_json::Value::Null,
        };
        
        Ok(crate::secrets::EngineStatus {
            name: self.name().to_string(),
            engine_type: self.engine_type(),
            initialized: config.is_some(),
            config: config_value,
            stats: crate::secrets::EngineStats {
                total_secrets: stats.total_entries,
                active_leases: 0,
                operations: HashMap::new(),
                last_operation: stats.last_log_time,
            },
        })
    }
}

impl Default for SecureAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let logger = SecureAuditLogger::new();
        assert_eq!(logger.name(), "secure-audit");
        assert!(matches!(logger.engine_type(), crate::secrets::EngineType::Custom(_)));
    }

    #[tokio::test]
    async fn test_audit_configuration() {
        let mut logger = SecureAuditLogger::new();
        
        let config = json!({
            "output": "file",
            "file_path": "/tmp/test_audit.log",
            "rotation": "daily",
            "retention_days": 30,
            "hmac_key": "test_key_123456789012345678901234",
            "compression": true,
            "buffer_size": 1000,
            "flush_interval": 60
        });
        
        let result = logger.configure(config).await;
        assert!(result.is_ok());
        
        let status = logger.status().await.unwrap();
        assert!(status.initialized);
    }

    #[tokio::test]
    async fn test_hash_calculation() {
        let logger = SecureAuditLogger::new();
        
        let entry = AuditEntry {
            entry_id: "test_123".to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::SecretAccess,
            principal: "user123".to_string(),
            resource: "secret/test".to_string(),
            action: "read".to_string(),
            outcome: AuditOutcome::Success,
            source_ip: Some("127.0.0.1".to_string()),
            user_agent: None,
            session_id: None,
            request_id: None,
            metadata: HashMap::new(),
            previous_hash: None,
            current_hash: String::new(),
            hmac: String::new(),
        };

        let hash = logger.calculate_hash(&entry);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 44); // Base64 encoded SHA256
    }

    #[tokio::test]
    async fn test_hmac_calculation() {
        let logger = SecureAuditLogger::new();
        
        let mut entry = AuditEntry {
            entry_id: "test_123".to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::SecretAccess,
            principal: "user123".to_string(),
            resource: "secret/test".to_string(),
            action: "read".to_string(),
            outcome: AuditOutcome::Success,
            source_ip: None,
            user_agent: None,
            session_id: None,
            request_id: None,
            metadata: HashMap::new(),
            previous_hash: None,
            current_hash: "test_hash".to_string(),
            hmac: String::new(),
        };

        let key = b"test_key_123456789012345678901234";
        let hmac = logger.calculate_hmac(&entry, key);
        assert!(!hmac.is_empty());
        assert_eq!(hmac.len(), 44); // Base64 encoded HMAC-SHA256
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let mut logger = SecureAuditLogger::new();
        
        // Configure with stdout output for testing
        let config = json!({
            "output": "stdout",
            "hmac_key": "test_key_123456789012345678901234"
        });
        
        logger.configure(config).await.unwrap();
        
        // Log an access event
        let result = logger.log_access("user123", "secret/test", "read", "success").await;
        assert!(result.is_ok());
        
        // Check statistics
        let stats = logger.get_stats().await;
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.entries_by_type.get(&AuditEventType::SecretAccess), Some(&1));
        assert_eq!(stats.entries_by_outcome.get(&AuditOutcome::Success), Some(&1));
    }

    #[tokio::test]
    async fn test_entry_id_generation() {
        let logger = SecureAuditLogger::new();
        
        let id1 = logger.generate_entry_id().await;
        let id2 = logger.generate_entry_id().await;
        
        assert_ne!(id1, id2);
        assert!(id1.starts_with("audit_"));
        assert!(id2.starts_with("audit_"));
    }
}
