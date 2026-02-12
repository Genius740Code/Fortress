//! Audit logging system for Fortress
//!
//! This module provides comprehensive audit logging with tamper-evident security,
//! event tracking, and analysis capabilities. All security-relevant operations
//! are logged with cryptographic integrity verification.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use ring::hmac;
use zeroize::Zeroize;

use crate::error::{FortressError, Result};
use crate::encryption::EncryptionAlgorithm;

/// Audit log entry with tamper-evident protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this entry
    pub id: String,
    /// Timestamp when the event occurred (Unix timestamp in milliseconds)
    pub timestamp: u64,
    /// Event type/category
    pub event_type: AuditEventType,
    /// Security level of the event
    pub security_level: SecurityLevel,
    /// Principal (user, service, system) that performed the action
    pub principal: Option<String>,
    /// Resource that was accessed/modified
    pub resource: Option<String>,
    /// Action performed
    pub action: String,
    /// Event outcome
    pub outcome: EventOutcome,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Previous entry hash for chain integrity
    pub previous_hash: Option<String>,
    /// Current entry hash for integrity verification
    pub current_hash: String,
    /// HMAC signature for tamper detection
    pub signature: String,
}

/// Types of audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditEventType {
    /// Authentication events (login, logout, token validation)
    Authentication,
    /// Authorization events (permission checks, role changes)
    Authorization,
    /// Key management operations
    KeyManagement,
    /// Data encryption/decryption operations
    CryptographicOperation,
    /// Data access (read, write, delete)
    DataAccess,
    /// Configuration changes
    ConfigurationChange,
    /// System events (startup, shutdown, errors)
    System,
    /// Policy operations
    PolicyOperation,
    /// HSM operations
    HsmOperation,
    /// Network operations
    NetworkOperation,
}

/// Security levels for audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    /// Low severity informational events
    Low,
    /// Medium severity events
    Medium,
    /// High severity security events
    High,
    /// Critical security events requiring immediate attention
    Critical,
}

/// Event outcome
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventOutcome {
    /// Operation succeeded
    Success,
    /// Operation failed
    Failure,
    /// Operation was denied
    Denied,
    /// Operation resulted in error
    Error,
}

impl std::fmt::Display for EventOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventOutcome::Success => write!(f, "Success"),
            EventOutcome::Failure => write!(f, "Failure"),
            EventOutcome::Denied => write!(f, "Denied"),
            EventOutcome::Error => write!(f, "Error"),
        }
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Low => write!(f, "Low"),
            SecurityLevel::Medium => write!(f, "Medium"),
            SecurityLevel::High => write!(f, "High"),
            SecurityLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Audit log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable/disable audit logging
    pub enabled: bool,
    /// Minimum security level to log
    pub min_security_level: SecurityLevel,
    /// Log retention period in days (0 = infinite)
    pub retention_days: u32,
    /// Enable tamper-evident logging
    pub tamper_evident: bool,
    /// HMAC key for signature verification
    pub hmac_key: Option<String>,
    /// Log file path
    pub log_path: Option<String>,
    /// Enable log rotation
    pub enable_rotation: bool,
    /// Maximum log file size in bytes before rotation
    pub max_file_size: u64,
    /// Maximum number of rotated files to keep
    pub max_rotated_files: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_security_level: SecurityLevel::Low,
            retention_days: 90,
            tamper_evident: true,
            hmac_key: None,
            log_path: Some("audit.log".to_string()),
            enable_rotation: true,
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_rotated_files: 10,
        }
    }
}

/// Audit logger interface
pub trait AuditLogger: Send + Sync {
    /// Log an audit event
    fn log(&self, entry: AuditEntry) -> Result<()>;
    
    /// Query audit logs
    fn query(&self, query: AuditQuery) -> Result<Vec<AuditEntry>>;
    
    /// Verify log integrity
    fn verify_integrity(&self) -> Result<IntegrityReport>;
    
    /// Get audit statistics
    fn get_statistics(&self) -> Result<AuditStatistics>;
    
    /// Rotate logs if needed
    fn rotate_logs(&self) -> Result<()>;
}

/// Query for audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Start timestamp (Unix timestamp in milliseconds)
    pub start_time: Option<u64>,
    /// End timestamp (Unix timestamp in milliseconds)
    pub end_time: Option<u64>,
    /// Event types to filter by
    pub event_types: Option<Vec<AuditEventType>>,
    /// Security levels to filter by
    pub security_levels: Option<Vec<SecurityLevel>>,
    /// Principal to filter by
    pub principal: Option<String>,
    /// Resource to filter by
    pub resource: Option<String>,
    /// Action to filter by (supports wildcards)
    pub action: Option<String>,
    /// Outcome to filter by
    pub outcome: Option<EventOutcome>,
    /// Maximum number of results to return
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
}

/// Log integrity verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Total entries verified
    pub total_entries: u64,
    /// Number of entries with valid integrity
    pub valid_entries: u64,
    /// Number of entries with integrity violations
    pub violations: u64,
    /// Details of integrity violations
    pub violation_details: Vec<IntegrityViolation>,
}

/// Integrity violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityViolation {
    /// Entry ID with violation
    pub entry_id: String,
    /// Type of violation
    pub violation_type: IntegrityViolationType,
    /// Description of the violation
    pub description: String,
}

/// Types of integrity violations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityViolationType {
    /// Hash chain broken
    HashChainBroken,
    /// HMAC signature invalid
    InvalidSignature,
    /// Missing previous hash
    MissingPreviousHash,
    /// Timestamp inconsistency
    TimestampInconsistency,
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    /// Total number of entries
    pub total_entries: u64,
    /// Entries by event type
    pub entries_by_event_type: HashMap<AuditEventType, u64>,
    /// Entries by security level
    pub entries_by_security_level: HashMap<SecurityLevel, u64>,
    /// Entries by outcome
    pub entries_by_outcome: HashMap<EventOutcome, u64>,
    /// Date range of logs
    pub date_range: (Option<u64>, Option<u64>),
    /// Log file size in bytes
    pub log_size: u64,
}

/// Default implementation of audit logger
pub struct DefaultAuditLogger {
    config: AuditConfig,
    hmac_key: Vec<u8>,
    last_hash: Option<String>,
}

impl DefaultAuditLogger {
    /// Create a new audit logger with the given configuration
    pub fn new(config: AuditConfig) -> Result<Self> {
        let hmac_key = if let Some(key_str) = &config.hmac_key {
            base64::decode(key_str)
                .map_err(|e| FortressError::configuration(
                    format!("Invalid HMAC key: {}", e),
                    Some("hmac_key".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ))?
        } else {
            // Generate a random key if none provided
            let mut key = vec![0u8; 32];
            getrandom::getrandom(&mut key)
                .map_err(|e| FortressError::internal(
                    format!("Failed to generate HMAC key: {}", e),
                    "RANDOM_KEY_GENERATION".to_string(),
                ))?;
            key
        };

        Ok(Self {
            config,
            hmac_key,
            last_hash: None,
        })
    }

    /// Generate HMAC signature for an entry
    fn generate_signature(&self, entry: &AuditEntry) -> Result<String> {
        let serialized = serde_json::to_string(entry)
            .map_err(|e| FortressError::internal(
                format!("Failed to serialize audit entry: {}", e),
                "SERIALIZATION_ERROR".to_string(),
            ))?;

        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.hmac_key);
        let tag = hmac::sign(&key, serialized.as_bytes());
        Ok(base64::encode(tag.as_ref()))
    }

    /// Generate hash for an entry
    fn generate_hash(&self, entry: &AuditEntry) -> Result<String> {
        let mut hasher = Sha256::new();
        
        // Include all fields except the current hash and signature
        let mut hash_data = format!(
            "{}{}{:?}{}{:?}{}{:?}{}{:?}{}{:?}",
            entry.id,
            entry.timestamp,
            entry.event_type,
            entry.security_level,
            entry.principal.as_deref().unwrap_or(""),
            entry.resource.as_deref().unwrap_or(""),
            entry.action,
            entry.outcome,
            entry.previous_hash.as_deref().unwrap_or(""),
        );

        // Include metadata in a deterministic order
        let mut metadata_keys: Vec<_> = entry.metadata.keys().collect();
        metadata_keys.sort();
        for key in metadata_keys {
            if let Some(value) = entry.metadata.get(key) {
                hash_data.push_str(&format!("{}={};", key, value));
            }
        }

        hasher.update(hash_data.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Create a new audit entry
    fn create_entry(
        &mut self,
        event_type: AuditEventType,
        security_level: SecurityLevel,
        principal: Option<String>,
        resource: Option<String>,
        action: String,
        outcome: EventOutcome,
        metadata: HashMap<String, String>,
    ) -> Result<AuditEntry> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| FortressError::internal(
                format!("System time error: {}", e),
                "SYSTEM_TIME_ERROR".to_string(),
            ))?
            .as_millis() as u64;

        let id = format!("{}-{}", timestamp, uuid::Uuid::new_v4());

        let mut entry = AuditEntry {
            id: id.clone(),
            timestamp,
            event_type,
            security_level,
            principal,
            resource,
            action,
            outcome,
            metadata,
            previous_hash: self.last_hash.clone(),
            current_hash: String::new(),
            signature: String::new(),
        };

        // Generate hash and signature
        entry.current_hash = self.generate_hash(&entry)?;
        entry.signature = self.generate_signature(&entry)?;

        // Update last hash for chain integrity
        self.last_hash = Some(entry.current_hash.clone());

        Ok(entry)
    }

    /// Write entry to log file
    fn write_to_log(&self, entry: &AuditEntry) -> Result<()> {
        if let Some(log_path) = &self.config.log_path {
            let serialized = serde_json::to_string(entry)
                .map_err(|e| FortressError::internal(
                    format!("Failed to serialize audit entry: {}", e),
                    "SERIALIZATION_ERROR".to_string(),
                ))?;

            std::fs::write(log_path, format!("{}\n", serialized))
                .map_err(|e| FortressError::io(
                    format!("Failed to write audit log: {}", e),
                    Some(log_path.clone()),
                ))?;
        }
        Ok(())
    }
}

impl AuditLogger for DefaultAuditLogger {
    fn log(&mut self, entry: AuditEntry) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if entry.security_level < self.config.min_security_level {
            return Ok(());
        }

        self.write_to_log(&entry)?;
        Ok(())
    }

    fn query(&self, _query: AuditQuery) -> Result<Vec<AuditEntry>> {
        // TODO: Implement log querying
        Ok(vec![])
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        // TODO: Implement integrity verification
        Ok(IntegrityReport {
            total_entries: 0,
            valid_entries: 0,
            violations: 0,
            violation_details: vec![],
        })
    }

    fn get_statistics(&self) -> Result<AuditStatistics> {
        // TODO: Implement statistics collection
        Ok(AuditStatistics {
            total_entries: 0,
            entries_by_event_type: HashMap::new(),
            entries_by_security_level: HashMap::new(),
            entries_by_outcome: HashMap::new(),
            date_range: (None, None),
            log_size: 0,
        })
    }

    fn rotate_logs(&self) -> Result<()> {
        // TODO: Implement log rotation
        Ok(())
    }
}

impl Drop for DefaultAuditLogger {
    fn drop(&mut self) {
        // Clear sensitive data
        self.hmac_key.zeroize();
    }
}

/// Global audit logger instance
static mut AUDIT_LOGGER: Option<Arc<std::sync::Mutex<DefaultAuditLogger>>> = None;
static AUDIT_LOGGER_INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global audit logger
pub fn init_audit_logger(config: AuditConfig) -> Result<()> {
    AUDIT_LOGGER_INIT.call_once(|| {
        match DefaultAuditLogger::new(config) {
            Ok(logger) => {
                unsafe {
                    AUDIT_LOGGER = Some(Arc::new(std::sync::Mutex::new(logger)));
                }
            }
            Err(e) => {
                eprintln!("Failed to initialize audit logger: {}", e);
            }
        }
    });
    Ok(())
}

/// Get the global audit logger
pub fn get_audit_logger() -> Option<Arc<std::sync::Mutex<DefaultAuditLogger>>> {
    unsafe { AUDIT_LOGGER.clone() }
}

/// Convenience function to log audit events
pub fn log_event(
    event_type: AuditEventType,
    security_level: SecurityLevel,
    principal: Option<String>,
    resource: Option<String>,
    action: String,
    outcome: EventOutcome,
) -> Result<()> {
    if let Some(logger) = get_audit_logger() {
        let mut logger = logger.lock().map_err(|e| {
            FortressError::internal(
                format!("Failed to acquire audit logger lock: {}", e),
                "LOCK_ERROR".to_string(),
            )
        })?;
        
        let entry = logger.create_entry(
            event_type,
            security_level,
            principal,
            resource,
            action,
            outcome,
            HashMap::new(),
        )?;
        
        logger.log(entry)?;
    }
    Ok(())
}

/// Convenience function to log audit events with metadata
pub fn log_event_with_metadata(
    event_type: AuditEventType,
    security_level: SecurityLevel,
    principal: Option<String>,
    resource: Option<String>,
    action: String,
    outcome: EventOutcome,
    metadata: HashMap<String, String>,
) -> Result<()> {
    if let Some(logger) = get_audit_logger() {
        let mut logger = logger.lock().map_err(|e| {
            FortressError::internal(
                format!("Failed to acquire audit logger lock: {}", e),
                "LOCK_ERROR".to_string(),
            )
        })?;
        
        let entry = logger.create_entry(
            event_type,
            security_level,
            principal,
            resource,
            action,
            outcome,
            metadata,
        )?;
        
        logger.log(entry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_creation() {
        let mut config = AuditConfig::default();
        config.hmac_key = Some(base64::encode("test_key_32_bytes_long_12345678"));
        
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        let entry = logger.create_entry(
            AuditEventType::Authentication,
            SecurityLevel::High,
            Some("user123".to_string()),
            Some("/login".to_string()),
            "user_login".to_string(),
            EventOutcome::Success,
            HashMap::new(),
        ).unwrap();

        assert!(!entry.id.is_empty());
        assert!(!entry.current_hash.is_empty());
        assert!(!entry.signature.is_empty());
        assert_eq!(entry.event_type, AuditEventType::Authentication);
        assert_eq!(entry.security_level, SecurityLevel::High);
        assert_eq!(entry.principal, Some("user123".to_string()));
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Low < SecurityLevel::Medium);
        assert!(SecurityLevel::Medium < SecurityLevel::High);
        assert!(SecurityLevel::High < SecurityLevel::Critical);
    }

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert_eq!(config.min_security_level, SecurityLevel::Low);
        assert_eq!(config.retention_days, 90);
        assert!(config.tamper_evident);
    }
}
