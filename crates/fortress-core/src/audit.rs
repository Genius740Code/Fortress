//! Audit logging system for Fortress
//!
//! This module provides comprehensive audit logging with tamper-evident security,
//! event tracking, and analysis capabilities. All security-relevant operations
//! are logged with cryptographic integrity verification.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use ring::hmac;
use zeroize::Zeroize;
use tracing::debug;
use crate::error::{FortressError, Result, AuditErrorCode};

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
    /// Operation was blocked
    Blocked,
    /// Operation requires review
    RequiresReview,
}

impl std::fmt::Display for EventOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventOutcome::Success => write!(f, "Success"),
            EventOutcome::Failure => write!(f, "Failure"),
            EventOutcome::Blocked => write!(f, "Blocked"),
            EventOutcome::RequiresReview => write!(f, "RequiresReview"),
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
    fn log(&mut self, entry: AuditEntry) -> Result<()>;
    
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
    last_hash: Arc<Mutex<Option<String>>>,
}

impl DefaultAuditLogger {
    /// Create a new audit logger with the given configuration
    pub fn new(config: AuditConfig) -> Result<Self> {
        let hmac_key = if let Some(key_str) = &config.hmac_key {
            use base64::{Engine as _, engine::general_purpose};
            general_purpose::STANDARD.decode(key_str)
                .map_err(|e| FortressError::configuration(
                    format!("Invalid HMAC key: {}", e),
                    Some("hmac_key".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ))?
        } else {
            // Generate a random key if none provided
            match crate::trng::random_bytes(32) {
                Ok(key) => key,
                Err(_) => {
                    // Fallback to getrandom
                    let mut key = vec![0u8; 32];
                    getrandom::getrandom(&mut key)
                        .map_err(|e| FortressError::internal(
                            format!("Failed to generate HMAC key: {}", e),
                            "RANDOM_KEY_GENERATION".to_string(),
                        ))?;
                    key
                }
            }
        };

        Ok(Self {
            config,
            hmac_key,
            last_hash: Arc::new(Mutex::new(None)),
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
        use base64::{Engine as _, engine::general_purpose};
        Ok(general_purpose::STANDARD.encode(tag.as_ref()))
    }

    /// Generate hash for an entry
    fn generate_hash(&self, entry: &AuditEntry) -> Result<String> {
        let mut hasher = Sha256::new();
        
        // Include all fields except the current hash and signature
        let mut hash_data = format!(
            "{}{}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
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
    pub fn create_entry(
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
            previous_hash: {
                let last_hash_guard = self.last_hash.lock().map_err(|_| {
                    FortressError::audit(
                        "Audit system lock poisoned - possible concurrent access issue",
                        Some("audit_lock".to_string()),
                        crate::error::AuditErrorCode::SystemError
                    )
                })?;
                last_hash_guard.clone()
            },
            current_hash: String::new(),
            signature: String::new(),
        };

        // Generate hash and signature
        entry.current_hash = self.generate_hash(&entry)?;
        entry.signature = self.generate_signature(&entry)?;

        // Update last hash for chain integrity
        {
            let mut last_hash_guard = self.last_hash.lock().map_err(|_| {
                FortressError::audit(
                    "Audit system lock poisoned - possible concurrent access issue",
                    Some("audit_lock".to_string()),
                    crate::error::AuditErrorCode::SystemError
                )
            })?;
            *last_hash_guard = Some(entry.current_hash.clone());
        }

        Ok(entry)
    }

    /// Read audit entries from a log file
    fn read_log_file(&self, file_path: &str) -> Result<Vec<AuditEntry>> {
        let mut entries = Vec::new();
        
        let content = if file_path.ends_with(".gz") {
            // Read compressed file
            self.read_compressed_log_file(file_path)?
        } else {
            // Read regular file
            std::fs::read_to_string(file_path)
                .map_err(|e| FortressError::io(
                    format!("Failed to read audit log file: {}", e),
                    Some(file_path.to_string()),
                ))?
        };

        // Parse each line as a JSON audit entry
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            match serde_json::from_str::<AuditEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    // Log parsing error but continue with other entries
                    eprintln!("Failed to parse audit entry from {}: {}", file_path, e);
                }
            }
        }

        Ok(entries)
    }

    /// Read compressed log file using gzip
    fn read_compressed_log_file(&self, file_path: &str) -> Result<String> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let file = std::fs::File::open(file_path)
            .map_err(|e| FortressError::io(
                format!("Failed to open compressed log file: {}", e),
                Some(file_path.to_string()),
            ))?;

        let mut decoder = GzDecoder::new(file);
        let mut content = String::new();
        
        decoder.read_to_string(&mut content)
            .map_err(|e| FortressError::io(
                format!("Failed to decompress log file: {}", e),
                Some(file_path.to_string()),
            ))?;

        Ok(content)
    }

    /// Check if an audit entry matches the query criteria
    fn matches_query(&self, entry: &AuditEntry, query: &AuditQuery) -> bool {
        // Time range filter
        if let Some(start_time) = query.start_time {
            if entry.timestamp < start_time {
                return false;
            }
        }
        if let Some(end_time) = query.end_time {
            if entry.timestamp > end_time {
                return false;
            }
        }

        // Event type filter
        if let Some(event_types) = &query.event_types {
            if !event_types.contains(&entry.event_type) {
                return false;
            }
        }

        // Security level filter
        if let Some(security_levels) = &query.security_levels {
            if !security_levels.contains(&entry.security_level) {
                return false;
            }
        }

        // Principal filter
        if let Some(principal) = &query.principal {
            if entry.principal.as_ref().map_or(true, |p| !p.contains(principal)) {
                return false;
            }
        }

        // Resource filter
        if let Some(resource) = &query.resource {
            if entry.resource.as_ref().map_or(true, |r| !r.contains(resource)) {
                return false;
            }
        }

        // Action filter (supports wildcards)
        if let Some(action) = &query.action {
            if action.contains('*') {
                // Simple wildcard matching
                let pattern = action.replace('*', ".*");
                match regex::Regex::new(&pattern) {
                    Ok(regex) => {
                        if !regex.is_match(&entry.action) {
                            return false;
                        }
                    }
                    Err(_) => {
                        // Fallback to simple contains if regex is invalid
                        if !entry.action.contains(&action.replace('*', "")) {
                            return false;
                        }
                    }
                }
            } else if !entry.action.contains(action) {
                return false;
            }
        }

        // Outcome filter
        if let Some(outcome) = &query.outcome {
            if &entry.outcome != outcome {
                return false;
            }
        }

        true
    }

    /// Write entry to log file
    fn write_to_log(&self, entry: &AuditEntry) -> Result<()> {
        if let Some(log_path) = &self.config.log_path {
            let serialized = serde_json::to_string(entry)
                .map_err(|e| FortressError::internal(
                    format!("Failed to serialize audit entry: {}", e),
                    "SERIALIZATION_ERROR".to_string(),
                ))?;

            // Append to file (create if doesn't exist)
            use std::fs::OpenOptions;
            use std::io::Write;

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
                .map_err(|e| FortressError::io(
                    format!("Failed to open audit log file: {}", e),
                    Some(log_path.clone()),
                ))?;

            writeln!(file, "{}", serialized)
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

        // Create entry with hash chain
        let entry = self.create_entry(
            entry.event_type,
            entry.security_level,
            entry.principal,
            entry.resource,
            entry.action,
            entry.outcome,
            entry.metadata,
        )?;

        self.write_to_log(&entry)?;
        Ok(())
    }

    fn query(&self, query: AuditQuery) -> Result<Vec<AuditEntry>> {
        let log_path = match &self.config.log_path {
            Some(path) => path,
            None => return Ok(vec![]),
        };

        // Read all log files (current and rotated)
        let mut all_entries = Vec::new();
        
        // Read current log file
        if std::path::Path::new(log_path).exists() {
            let entries = self.read_log_file(log_path)?;
            all_entries.extend(entries);
        }

        // Read rotated log files
        if let Some(parent) = std::path::Path::new(log_path).parent() {
            if let Ok(dir_entries) = std::fs::read_dir(parent) {
                for entry in dir_entries.flatten() {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if file_name.starts_with("audit_") && 
                           (file_name.ends_with(".log") || file_name.ends_with(".log.gz")) {
                            // Skip the current log file as we already read it
                            if path.to_string_lossy() != *log_path {
                                let entries = self.read_log_file(&path.to_string_lossy())?;
                                all_entries.extend(entries);
                            }
                        }
                    }
                }
            }
        }

        // Apply filters
        let mut filtered_entries = Vec::new();
        for entry in all_entries {
            if self.matches_query(&entry, &query) {
                filtered_entries.push(entry);
            }
        }

        // Sort by timestamp (newest first)
        filtered_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply pagination
        let offset = query.offset.unwrap_or(0) as usize;
        let limit = query.limit.unwrap_or(u32::MAX) as usize;

        if offset >= filtered_entries.len() {
            return Ok(vec![]);
        }

        let end = std::cmp::min(offset + limit, filtered_entries.len());
        Ok(filtered_entries[offset..end].to_vec())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        let log_path = match &self.config.log_path {
            Some(path) => path,
            None => return Ok(IntegrityReport {
                total_entries: 0,
                valid_entries: 0,
                violations: 0,
                violation_details: vec![],
            }),
        };

        // Read all audit entries from all log files
        let mut all_entries = Vec::new();
        
        // Read current log file
        if std::path::Path::new(log_path).exists() {
            let entries = self.read_log_file(log_path)?;
            all_entries.extend(entries);
        }

        // Read rotated log files
        if let Some(parent) = std::path::Path::new(log_path).parent() {
            if let Ok(dir_entries) = std::fs::read_dir(parent) {
                let mut rotated_files: Vec<_> = dir_entries.flatten().collect();
                // Sort by filename to ensure chronological order
                rotated_files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
                
                for entry in rotated_files {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if file_name.starts_with("audit_") && 
                           (file_name.ends_with(".log") || file_name.ends_with(".log.gz")) {
                            // Skip current log file as we already read it
                            if path.to_string_lossy() != *log_path {
                                let entries = self.read_log_file(&path.to_string_lossy())?;
                                all_entries.extend(entries);
                            }
                        }
                    }
                }
            }
        }

        // Sort entries by timestamp to verify hash chain
        all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let total_entries = all_entries.len() as u64;
        let mut valid_entries = 0u64;
        let mut violations = Vec::new();
        let mut previous_hash: Option<String> = None;

        for (index, entry) in all_entries.iter().enumerate() {
            let mut entry_valid = true;

            // Verify hash chain
            if entry.previous_hash != previous_hash {
                violations.push(IntegrityViolation {
                    entry_id: entry.id.clone(),
                    violation_type: IntegrityViolationType::HashChainBroken,
                    description: format!(
                        "Hash chain broken at entry {}. Expected previous hash: {:?}, found: {:?}",
                        index,
                        previous_hash,
                        entry.previous_hash
                    ),
                });
                entry_valid = false;
            }

            // Verify current hash
            let expected_hash = self.generate_hash(entry)?;
            if entry.current_hash != expected_hash {
                violations.push(IntegrityViolation {
                    entry_id: entry.id.clone(),
                    violation_type: IntegrityViolationType::InvalidSignature,
                    description: format!(
                        "Invalid hash for entry {}. Expected: {}, found: {}",
                        index,
                        expected_hash,
                        entry.current_hash
                    ),
                });
                entry_valid = false;
            }

            // Verify HMAC signature
            let expected_signature = self.generate_signature(entry)?;
            if entry.signature != expected_signature {
                violations.push(IntegrityViolation {
                    entry_id: entry.id.clone(),
                    violation_type: IntegrityViolationType::InvalidSignature,
                    description: format!(
                        "Invalid HMAC signature for entry {}. Expected: {}, found: {}",
                        index,
                        expected_signature,
                        entry.signature
                    ),
                });
                entry_valid = false;
            }

            // Check timestamp consistency (should be increasing)
            if index > 0 {
                let prev_entry = &all_entries[index - 1];
                if entry.timestamp <= prev_entry.timestamp {
                    violations.push(IntegrityViolation {
                        entry_id: entry.id.clone(),
                        violation_type: IntegrityViolationType::TimestampInconsistency,
                        description: format!(
                            "Timestamp inconsistency at entry {}. Current: {}, Previous: {}",
                            index,
                            entry.timestamp,
                            prev_entry.timestamp
                        ),
                    });
                    entry_valid = false;
                }
            }

            if entry_valid {
                valid_entries += 1;
            }

            previous_hash = Some(entry.current_hash.clone());
        }

        Ok(IntegrityReport {
            total_entries,
            valid_entries,
            violations: violations.len() as u64,
            violation_details: violations,
        })
    }

    fn get_statistics(&self) -> Result<AuditStatistics> {
        let log_path = match &self.config.log_path {
            Some(path) => path,
            None => return Ok(AuditStatistics {
                total_entries: 0,
                entries_by_event_type: HashMap::new(),
                entries_by_security_level: HashMap::new(),
                entries_by_outcome: HashMap::new(),
                date_range: (None, None),
                log_size: 0,
            }),
        };

        // Read all audit entries from all log files
        let mut all_entries = Vec::new();
        
        // Read current log file
        if std::path::Path::new(log_path).exists() {
            let entries = self.read_log_file(log_path)?;
            all_entries.extend(entries);
        }

        // Read rotated log files
        if let Some(parent) = std::path::Path::new(log_path).parent() {
            if let Ok(dir_entries) = std::fs::read_dir(parent) {
                for entry in dir_entries.flatten() {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if file_name.starts_with("audit_") && 
                           (file_name.ends_with(".log") || file_name.ends_with(".log.gz")) {
                            // Skip current log file as we already read it
                            if path.to_string_lossy() != *log_path {
                                let entries = self.read_log_file(&path.to_string_lossy())?;
                                all_entries.extend(entries);
                            }
                        }
                    }
                }
            }
        }

        // Calculate statistics
        let total_entries = all_entries.len() as u64;
        let mut entries_by_event_type: HashMap<AuditEventType, u64> = HashMap::new();
        let mut entries_by_security_level: HashMap<SecurityLevel, u64> = HashMap::new();
        let mut entries_by_outcome: HashMap<EventOutcome, u64> = HashMap::new();
        let mut min_timestamp: Option<u64> = None;
        let mut max_timestamp: Option<u64> = None;
        let mut total_log_size = 0u64;

        // Calculate log file sizes
        if std::path::Path::new(log_path).exists() {
            if let Ok(metadata) = std::fs::metadata(log_path) {
                total_log_size += metadata.len();
            }
        }

        if let Some(parent) = std::path::Path::new(log_path).parent() {
            if let Ok(dir_entries) = std::fs::read_dir(parent) {
                for entry in dir_entries.flatten() {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if file_name.starts_with("audit_") && 
                           (file_name.ends_with(".log") || file_name.ends_with(".log.gz")) {
                            if let Ok(metadata) = std::fs::metadata(&path) {
                                total_log_size += metadata.len();
                            }
                        }
                    }
                }
            }
        }

        // Process entries
        for entry in &all_entries {
            // Count by event type
            *entries_by_event_type.entry(entry.event_type.clone()).or_insert(0) += 1;

            // Count by security level
            *entries_by_security_level.entry(entry.security_level.clone()).or_insert(0) += 1;

            // Count by outcome
            *entries_by_outcome.entry(entry.outcome.clone()).or_insert(0) += 1;

            // Track timestamp range
            min_timestamp = min_timestamp.map_or(Some(entry.timestamp), |min| Some(min.min(entry.timestamp)));
            max_timestamp = max_timestamp.map_or(Some(entry.timestamp), |max| Some(max.max(entry.timestamp)));
        }

        Ok(AuditStatistics {
            total_entries,
            entries_by_event_type,
            entries_by_security_level,
            entries_by_outcome,
            date_range: (min_timestamp, max_timestamp),
            log_size: total_log_size,
        })
    }

    fn rotate_logs(&self) -> Result<()> {
        use crate::audit_rotation::{LogRotationManager, RetentionPolicy, RotationStrategy};
        
        if !self.config.enable_rotation {
            return Ok(());
        }

        let retention_policy = RetentionPolicy {
            retention_days: self.config.retention_days,
            max_files: self.config.max_rotated_files,
            compress_old_logs: true,
            auto_delete: true,
        };

        let rotation_strategy = RotationStrategy::SizeBased; // Use size-based rotation

        let mut rotation_manager = LogRotationManager::new(
            self.config.clone(),
            retention_policy,
            rotation_strategy,
        )?;

        rotation_manager.force_rotation()
    }
}

impl Drop for DefaultAuditLogger {
    fn drop(&mut self) {
        // Clear sensitive data
        self.hmac_key.zeroize();
    }
}

/// Global audit logger instance using safe initialization
static AUDIT_LOGGER: std::sync::OnceLock<Arc<std::sync::Mutex<DefaultAuditLogger>>> = std::sync::OnceLock::new();

/// Initialize the global audit logger
pub fn init_audit_logger(config: AuditConfig) -> Result<()> {
    let logger = DefaultAuditLogger::new(config)?;
    AUDIT_LOGGER.set(Arc::new(std::sync::Mutex::new(logger)))
        .map_err(|_| FortressError::audit("Audit logger already initialized", None, AuditErrorCode::ConfigurationError))?;
    Ok(())
}

/// Get the global audit logger safely
fn get_audit_logger() -> Option<Arc<std::sync::Mutex<DefaultAuditLogger>>> {
    AUDIT_LOGGER.get().map(|logger| logger.clone())
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
    if let Some(logger_arc) = get_audit_logger() {
        let mut logger = logger_arc.lock().map_err(|_| FortressError::audit("Failed to lock audit logger", None, AuditErrorCode::LogRetrievalFailed))?;
        let entry = logger.create_entry(event_type, security_level, principal, resource, action, outcome, HashMap::new())?;
        logger.log(entry)
    } else {
        debug!("No audit logger available");
        Ok(())
    }
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
    if let Some(logger_arc) = get_audit_logger() {
        let mut logger = logger_arc.lock().map_err(|_| FortressError::audit("Failed to lock audit logger", None, AuditErrorCode::LogRetrievalFailed))?;
        let entry = logger.create_entry(event_type, security_level, principal, resource, action, outcome, metadata)?;
        logger.log(entry)
    } else {
        debug!("No audit logger available");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_audit_entry_creation() {
        let mut config = AuditConfig::default();
        config.hmac_key = Some(base64::engine::general_purpose::STANDARD.encode("test_key_32_bytes_long_12345678"));
        
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
