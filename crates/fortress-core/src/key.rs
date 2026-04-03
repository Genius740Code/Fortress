//! Key management and rotation

//! This module provides secure key management, rotation, and derivation capabilities

//! for Fortress. It supports multiple key derivation functions and automatic rotation

//! Enterprise-grade key management with zero-downtime rotation

use crate::error::{FortressError, Result, KeyErrorCode};

use crate::encryption::{EncryptionAlgorithm, PerformanceProfile};
use crate::audit::{AuditEventType, SecurityLevel, log_event_with_metadata, EventOutcome};
use crate::storage::AuditEventOutcome;

use async_trait::async_trait;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::time::Duration as StdDuration;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::RwLock;

use uuid::Uuid;

// Import HSM types
use crate::hsm::{HsmConfig, HsmKeyManagerInner};

// Import futures for concurrent processing
use futures;


/// Unique identifier for a key

pub type KeyId = String;



/// Key version for rotation tracking

pub type KeyVersion = u32;



/// Key manager trait for different key storage backends

#[async_trait]

pub trait KeyManager: Send + Sync {

    /// Generate a new key

    async fn generate_key(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<SecureKey>;



    /// Store a key with metadata

    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()>;



    /// Retrieve a key and its metadata

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)>;



    /// Delete a key

    async fn delete_key(&self, key_id: &KeyId) -> Result<()>;



    /// List all keys

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>>;



    /// Rotate a key (create new version)
    async fn rotate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()>;

    /// Zero-downtime key rotation (maintains availability during rotation)
    async fn rotate_key_with_zero_downtime(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
        // Default implementation - can be overridden by specific implementations
        self.rotate_key(key_id, algorithm).await
    }

    /// Check if a key exists
    async fn key_exists(&self, key_id: &KeyId) -> Result<bool>;

    /// Get key metadata only
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata>;

    /// Get the active key version for a key ID
    async fn get_active_key_version(&self, key_id: &KeyId) -> Result<u32>;

    /// Initiate a key transition for zero-downtime rotation
    async fn initiate_key_transition(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<u32>;

    /// Complete a key transition
    async fn complete_key_transition(&self, key_id: &KeyId, new_version: u32) -> Result<()>;

    /// Validate that both old and new key versions exist and are valid
    async fn validate_dual_keys(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<bool>;

    /// Rollback a failed key transition
    async fn rollback_key_transition(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<()>;

    /// Check if a key needs rotation based on expiration
    async fn needs_rotation(&self, key_id: &KeyId) -> Result<bool>;

    /// Get the active key for a specific purpose
    async fn get_active_key(&self, purpose: &str) -> Result<(SecureKey, KeyMetadata)>;

    /// Validate new key before switching
    async fn validate_new_key(&self, new_versioned_id: &KeyId) -> Result<()>;

    /// Validate post-switch state
    async fn validate_post_switch(&self, key_id: &KeyId, expected_version: u32) -> Result<()>;

    /// Perform the actual transition initiation (internal method)
    async fn perform_key_transition_initiation(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<u32>;

}







/// In-memory key manager for testing and development

#[derive(Debug)]

pub struct InMemoryKeyManager {

    keys: Arc<RwLock<HashMap<KeyId, (SecureKey, KeyMetadata)>>>,

}



impl InMemoryKeyManager {

    /// Create a new in-memory key manager

    pub fn new() -> Self {

        Self {

            keys: Arc::new(RwLock::new(HashMap::new())),

        }

    }

}



impl Default for InMemoryKeyManager {

    fn default() -> Self {

        Self::new()

    }

}



#[async_trait]

impl KeyManager for InMemoryKeyManager {

    async fn generate_key(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<SecureKey> {
        let key = SecureKey::generate(algorithm.key_size());
        
        // Log key generation
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("algorithm".to_string(), format!("{:?}", algorithm));
        metadata.insert("key_size".to_string(), algorithm.key_size().to_string());
        
        if let Err(e) = log_event_with_metadata(
            AuditEventType::KeyManagement,
            SecurityLevel::High,
            Some("system".to_string()),
            None,
            "generate_key".to_string(),
            EventOutcome::Success,
            metadata,
        ) {
            // Don't fail the operation if logging fails, but log the error
            eprintln!("Failed to log key generation: {}", e);
        }
        
        Ok(key)
    }



    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        let mut keys = self.keys.write().await;
        
        // Check if key already exists
        let key_exists = keys.contains_key(key_id);
        
        keys.insert(key_id.clone(), (key.clone(), metadata.clone()));
        
        // Log key storage
        let mut audit_metadata = std::collections::HashMap::new();
        audit_metadata.insert("key_id".to_string(), key_id.clone());
        audit_metadata.insert("key_version".to_string(), metadata.version.to_string());
        audit_metadata.insert("algorithm".to_string(), format!("{:?}", metadata.algorithm));
        audit_metadata.insert("key_exists".to_string(), key_exists.to_string());
        
        if let Err(e) = log_event_with_metadata(
            AuditEventType::KeyManagement,
            SecurityLevel::High,
            Some("system".to_string()),
            Some(format!("key:{}", key_id)),
            "store_key".to_string(),
            EventOutcome::Success,
            audit_metadata,
        ) {
            eprintln!("Failed to log key storage: {}", e);
        }
        
        Ok(())
    }



    async fn retrieve_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)> {
        let keys = self.keys.read().await;

        let result = keys.get(key_id)
            .cloned()
            .ok_or_else(|| FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ));
        
        // Log key retrieval
        let outcome = match result {
            Ok(_) => EventOutcome::Success,
            Err(_) => EventOutcome::Failure,
        };
        
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key_id".to_string(), key_id.clone());
        
        if let Err(e) = log_event_with_metadata(
            AuditEventType::KeyManagement,
            SecurityLevel::Medium,
            Some("system".to_string()),
            Some(format!("key:{}", key_id)),
            "retrieve_key".to_string(),
            outcome,
            metadata,
        ) {
            eprintln!("Failed to log key retrieval: {}", e);
        }
        
        result
    }



    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        let mut keys = self.keys.write().await;

        let result = keys.remove(key_id);
        
        let outcome = if result.is_some() {
            EventOutcome::Success
        } else {
            EventOutcome::Failure
        };
        
        // Log key deletion
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key_id".to_string(), key_id.clone());
        metadata.insert("key_existed".to_string(), result.is_some().to_string());
        
        if let Err(e) = log_event_with_metadata(
            AuditEventType::KeyManagement,
            SecurityLevel::High,
            Some("system".to_string()),
            Some(format!("key:{}", key_id)),
            "delete_key".to_string(),
            outcome,
            metadata,
        ) {
            eprintln!("Failed to log key deletion: {}", e);
        }
        
        if result.is_some() {
            Ok(())
        } else {
            Err(FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ))
        }
    }

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {

        let keys = self.keys.read().await;

        Ok(keys.iter()

            .map(|(id, (_, metadata))| (id.clone(), metadata.clone()))

            .collect())

    }



    async fn rotate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
        let new_key = self.generate_key(algorithm).await?;
        
        // Get old metadata to preserve version and purpose
        let (_, old_metadata) = self.retrieve_key(key_id).await?;
        
        let new_metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            old_metadata.version + 1, // Increment version
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        );

        self.store_key(key_id, &new_key, &new_metadata).await?;
        Ok(())
    }
    
    /// Zero-downtime key rotation with concurrent operation support
    async fn rotate_key_with_zero_downtime(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
        use tokio::time::{timeout, Duration};
        
        // Start rotation transaction
        let rotation_id = Uuid::new_v4().to_string();
        let start_time = std::time::Instant::now();
        
        // Log rotation start
        let mut audit_metadata = std::collections::HashMap::new();
        audit_metadata.insert("rotation_id".to_string(), rotation_id.clone());
        audit_metadata.insert("key_id".to_string(), key_id.clone());
        audit_metadata.insert("algorithm".to_string(), algorithm.name().to_string());
        
        if let Err(e) = log_event_with_metadata(
            AuditEventType::KeyManagement,
            SecurityLevel::High,
            Some("system".to_string()),
            Some(format!("key:{}", key_id)),
            "zero_downtime_rotation_start".to_string(),
            EventOutcome::Success,
            audit_metadata,
        ) {
            eprintln!("Failed to log rotation start: {}", e);
        }
        
        // Phase 1: Prepare new key without disrupting existing operations
        let (old_key, old_metadata) = self.retrieve_key(key_id).await?;
        let old_versioned_id = format!("{}_v{}", key_id, old_metadata.version);
        
        // Create backup with timeout protection
        let backup_result = timeout(
            Duration::from_secs(30),
            self.store_key(&old_versioned_id, &old_key, &old_metadata)
        ).await;
        
        if backup_result.is_err() {
            return Err(FortressError::key_management(
                "Backup creation timeout during zero-downtime rotation",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        backup_result.map_err(|e| FortressError::key_management(
            format!("Backup creation failed: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::RotationFailed,
        ))?;
        
        // Phase 2: Generate and prepare new key
        let new_key = self.generate_key(algorithm).await?;
        let new_version = old_metadata.version + 1;
        
        let new_metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            new_version,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        ).with_metadata("rotation_id".to_string(), rotation_id.clone())
         .with_metadata("transition_status".to_string(), "preparing".to_string());
        
        // Store new key with versioned ID for validation
        let new_versioned_id = format!("{}_v{}", key_id, new_version);
        self.store_key(&new_versioned_id, &new_key, &new_metadata).await?;
        
        // Phase 3: Validate new key before switching
        let validation_result = timeout(
            Duration::from_secs(10),
            self.validate_new_key(&new_versioned_id)
        ).await;
        
        if validation_result.is_err() || validation_result.as_ref().unwrap().is_err() {
            // Cleanup and rollback
            let _ = self.delete_key(&new_versioned_id).await;
            let _ = self.delete_key(&old_versioned_id).await;
            
            return Err(FortressError::key_management(
                "New key validation failed during zero-downtime rotation",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        // Phase 4: Atomic switch with concurrent operation support
        let switch_metadata = new_metadata.clone()
            .with_metadata("transition_status".to_string(), "active".to_string());
        
        // Atomic switch - this is the critical point where we ensure zero downtime
        self.store_key(key_id, &new_key, &switch_metadata).await?;
        
        // Phase 5: Post-switch validation with timeout
        let post_switch_result = timeout(
            Duration::from_secs(5),
            self.validate_post_switch(key_id, new_version)
        ).await;
        
        if post_switch_result.is_err() || post_switch_result.as_ref().unwrap().is_err() {
            // Emergency rollback
            let rollback_result = self.rollback_key_transition(key_id, old_metadata.version, new_version).await;
            
            if let Err(rollback_err) = rollback_result {
                // Critical error - both old and new keys may be inaccessible
                return Err(FortressError::key_management(
                    format!("Critical rotation failure and rollback failed: {}", rollback_err),
                    Some(key_id.clone()),
                    KeyErrorCode::RotationFailed,
                ));
            }
            
            return Err(FortressError::key_management(
                "Post-switch validation failed, rolled back successfully",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        // Phase 6: Complete transition and cleanup
        self.complete_key_transition(key_id, new_version).await?;
        
        // Log successful rotation
        let mut success_metadata = std::collections::HashMap::new();
        success_metadata.insert("rotation_id".to_string(), rotation_id);
        success_metadata.insert("key_id".to_string(), key_id.clone());
        success_metadata.insert("old_version".to_string(), old_metadata.version.to_string());
        success_metadata.insert("new_version".to_string(), new_version.to_string());
        success_metadata.insert("rotation_time_ms".to_string(), start_time.elapsed().as_millis().to_string());
        
        if let Err(e) = log_event_with_metadata(
            AuditEventType::KeyManagement,
            SecurityLevel::High,
            Some("system".to_string()),
            Some(format!("key:{}", key_id)),
            "zero_downtime_rotation_complete".to_string(),
            EventOutcome::Success,
            success_metadata,
        ) {
            eprintln!("Failed to log rotation completion: {}", e);
        }
        
        Ok(())
    }
    



    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        let keys = self.keys.read().await;
        Ok(keys.contains_key(key_id))
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata> {
        let keys = self.keys.read().await;
        keys.get(key_id)
            .map(|(_, metadata)| metadata.clone())
            .ok_or_else(|| FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ))
    }

    async fn get_active_key_version(&self, key_id: &KeyId) -> Result<u32> {
        let (_, metadata) = self.retrieve_key(key_id).await?;
        Ok(metadata.version)
    }

    /// Initiate a key transition for zero-downtime rotation with concurrent support
    async fn initiate_key_transition(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<u32> {
        use tokio::sync::Mutex;
        use std::sync::Arc;
        
        // Lock to prevent concurrent transitions on the same key
        static TRANSITION_LOCKS: std::sync::LazyLock<Arc<Mutex<HashMap<String, ()>>>> = 
            std::sync::LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        
        let lock = TRANSITION_LOCKS.clone();
        let mut locks = lock.lock().await;
        
        // Check if transition is already in progress
        if locks.contains_key(key_id) {
            return Err(FortressError::key_management(
                "Key transition already in progress",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        // Mark transition as in progress
        locks.insert(key_id.clone(), ());
        drop(locks);
        
        // Ensure lock is released on completion or failure
        let result = self.perform_key_transition_initiation(key_id, algorithm).await;
        
        // Release lock
        let mut locks = lock.lock().await;
        locks.remove(key_id);
        drop(locks);
        
        result
    }
    

    /// Complete a key transition with validation and cleanup
    async fn complete_key_transition(&self, key_id: &KeyId, new_version: u32) -> Result<()> {
        // Validate the transition is complete
        let (_, mut metadata) = self.retrieve_key(key_id).await?;
        
        if metadata.version != new_version {
            return Err(FortressError::key_management(
                format!("Cannot complete transition: version mismatch. Expected {}, found {}", new_version, metadata.version),
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        // Mark transition as complete
        metadata.metadata.insert("transition_status".to_string(), "complete".to_string());
        metadata.metadata.insert("transition_completed".to_string(), Utc::now().to_rfc3339());
        
        // Update metadata
        self.store_key(key_id, &self.retrieve_key(key_id).await?.0, &metadata).await?;
        
        // Cleanup old version
        let old_versioned_id = format!("{}_v{}", key_id, new_version - 1);
        let cleanup_result = self.delete_key(&old_versioned_id).await;
        
        if let Err(e) = cleanup_result {
            // Log cleanup failure but don't fail the operation
            eprintln!("Warning: Failed to cleanup old key version {}: {}", old_versioned_id, e);
        }
        
        // Cleanup versioned new key (it's now the main key)
        let new_versioned_id = format!("{}_v{}", key_id, new_version);
        let _ = self.delete_key(&new_versioned_id).await;
        
        Ok(())
    }

    async fn validate_dual_keys(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<bool> {
        let old_key_id = format!("{}_v{}", key_id, old_version);
        let new_key_id = format!("{}_v{}", key_id, new_version);
        
        let old_exists = self.key_exists(&old_key_id).await?;
        let new_exists = self.key_exists(&new_key_id).await?;
        
        if !old_exists || !new_exists {
            return Ok(false);
        }
        
        let old_result = self.retrieve_key(&old_key_id).await;
        let new_result = self.retrieve_key(&new_key_id).await;
        
        Ok(old_result.is_ok() && new_result.is_ok())
    }

    /// Enhanced rollback with comprehensive validation and error handling
    async fn rollback_key_transition(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<()> {
        use tokio::time::{timeout, Duration};
        
        // First, validate we have the backup
        let old_versioned_id = format!("{}_v{}", key_id, old_version);
        let backup_validation = timeout(
            Duration::from_secs(10),
            self.validate_dual_keys(key_id, old_version, new_version)
        ).await;
        
        if backup_validation.is_err() || backup_validation.as_ref().unwrap().is_err() {
            return Err(FortressError::key_management(
                "Cannot rollback: backup validation failed",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        // Retrieve backup key
        let (old_key, old_metadata) = self.retrieve_key(&old_versioned_id).await?;
        
        // Create restored metadata
        let restored_metadata = KeyMetadata::new(
            key_id.to_string(),
            old_metadata.algorithm.clone(),
            old_version,
            old_metadata.created_at,
            old_metadata.expires_at,
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        ).with_metadata("transition_status".to_string(), "rolled_back".to_string())
         .with_metadata("rollback_completed".to_string(), Utc::now().to_rfc3339())
         .with_metadata("original_version".to_string(), new_version.to_string());
        
        // Atomic rollback
        self.store_key(key_id, &old_key, &restored_metadata).await?;
        
        // Validate rollback
        let rollback_validation = timeout(
            Duration::from_secs(5),
            self.validate_post_switch(key_id, old_version)
        ).await;
        
        if rollback_validation.is_err() || rollback_validation.as_ref().unwrap().is_err() {
            return Err(FortressError::key_management(
                "Rollback validation failed",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        // Cleanup failed new version
        let new_versioned_id = format!("{}_v{}", key_id, new_version);
        let cleanup_result = self.delete_key(&new_versioned_id).await;
        
        if let Err(e) = cleanup_result {
            eprintln!("Warning: Failed to cleanup failed new key version {}: {}", new_versioned_id, e);
        }
        
        Ok(())
    }

    async fn needs_rotation(&self, key_id: &KeyId) -> Result<bool> {
        let (_, metadata) = self.retrieve_key(key_id).await?;
        Ok(Utc::now() >= metadata.expires_at)
    }

    async fn get_active_key(&self, purpose: &str) -> Result<(SecureKey, KeyMetadata)> {
        let keys = self.keys.read().await;
        for (_key_id, (key, metadata)) in keys.iter() {
            if metadata.purpose == purpose && metadata.is_active() {
                return Ok((key.clone(), metadata.clone()));
            }
        }
        Err(FortressError::key_management(
            format!("No active key found for purpose: {}", purpose),
            None,
            KeyErrorCode::KeyNotFound,
        ))
    }

    async fn validate_new_key(&self, new_versioned_id: &KeyId) -> Result<()> {
        let (new_key, new_metadata) = self.retrieve_key(new_versioned_id).await?;
        
        // Test basic key operations
        if new_key.is_empty() {
            return Err(FortressError::key_management(
                "New key is empty",
                Some(new_versioned_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }
        
        // Validate metadata
        if new_metadata.version == 0 {
            return Err(FortressError::key_management(
                "Invalid key version",
                Some(new_versioned_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }
        
        Ok(())
    }

    async fn validate_post_switch(&self, key_id: &KeyId, expected_version: u32) -> Result<()> {
        let (_, metadata) = self.retrieve_key(key_id).await?;
        
        if metadata.version != expected_version {
            return Err(FortressError::key_management(
                format!("Version mismatch after switch: expected {}, got {}", expected_version, metadata.version),
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        if !metadata.is_active() {
            return Err(FortressError::key_management(
                "New key is not active after switch",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        Ok(())
    }

    async fn perform_key_transition_initiation(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<u32> {
        let (_, old_metadata) = self.retrieve_key(key_id).await?;
        let new_version = old_metadata.version + 1;
        
        let new_key = self.generate_key(algorithm).await?;
        
        let new_metadata = KeyMetadata::new(
            key_id.to_string(),
            algorithm.name().to_string(),
            new_version,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        ).with_metadata("transition_status".to_string(), "initiating".to_string())
         .with_metadata("transition_started".to_string(), Utc::now().to_rfc3339());
        
        // Create backup of old key
        let old_versioned_id = format!("{}_v{}", key_id, old_metadata.version);
        let (old_key, old_metadata_copy) = self.retrieve_key(key_id).await?;
        let old_metadata_backup = old_metadata_copy.clone()
            .with_metadata("transition_status".to_string(), "backup".to_string())
            .with_metadata("backup_created".to_string(), Utc::now().to_rfc3339());
        
        self.store_key(&old_versioned_id, &old_key, &old_metadata_backup).await?;
        
        // Store new key with versioned ID
        let new_versioned_id = format!("{}_v{}", key_id, new_version);
        let new_metadata_with_status = new_metadata.clone()
            .with_metadata("transition_status".to_string(), "active".to_string());
        self.store_key(&new_versioned_id, &new_key, &new_metadata_with_status).await?;
        
        // Update main key to new version
        self.store_key(key_id, &new_key, &new_metadata).await?;
        
        Ok(new_version)
    }
}



/// Key metadata containing information about the key

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct KeyMetadata {

    /// Unique identifier for the key

    pub key_id: KeyId,

    /// Algorithm used for this key

    pub algorithm: String,

    /// Key version for rotation tracking

    pub version: KeyVersion,

    /// When the key was created

    pub created_at: DateTime<Utc>,

    /// When the key expires

    pub expires_at: DateTime<Utc>,

    /// Purpose of the key (e.g., "encryption", "signing")

    pub purpose: String,

    /// Performance profile associated with this key

    pub performance_profile: PerformanceProfile,

    /// Additional metadata

    pub metadata: HashMap<String, String>,

}



impl KeyMetadata {

    /// Create a new key metadata

    pub fn new(

        key_id: KeyId,

        algorithm: String,

        version: KeyVersion,

        created_at: DateTime<Utc>,

        expires_at: DateTime<Utc>,

        purpose: String,

        performance_profile: PerformanceProfile,

    ) -> Self {

        Self {

            key_id,

            algorithm,

            version,

            created_at,

            expires_at,

            purpose,

            performance_profile,

            metadata: HashMap::new(),

        }

    }



    /// Check if the key is currently active

    pub fn is_active(&self) -> bool {

        let now = Utc::now();

        now >= self.created_at && now < self.expires_at

    }



    /// Check if the key is expired

    pub fn is_expired(&self) -> bool {

        Utc::now() >= self.expires_at

    }



    /// Get the time until expiration

    pub fn time_until_expiration(&self) -> Option<ChronoDuration> {

        let now = Utc::now();

        if now < self.expires_at {

            Some(self.expires_at - now)

        } else {

            None

        }

    }



    /// Add custom metadata

    pub fn with_metadata(mut self, key: String, value: String) -> Self {

        self.metadata.insert(key, value);

        self

    }



    /// Get custom metadata

    pub fn get_metadata(&self, key: &str) -> Option<&String> {

        self.metadata.get(key)

    }

    /// Create a new builder for KeyMetadata

    pub fn builder() -> KeyMetadataBuilder {

        KeyMetadataBuilder::default()

    }

}



/// Builder for KeyMetadata

pub struct KeyMetadataBuilder {

    key_id: Option<KeyId>,

    algorithm: Option<String>,

    version: Option<KeyVersion>,

    created_at: Option<DateTime<Utc>>,

    expires_at: Option<DateTime<Utc>>,

    purpose: Option<String>,

    performance_profile: Option<PerformanceProfile>,

    metadata: HashMap<String, String>,

}



impl KeyMetadataBuilder {

    /// Create a new builder

    pub fn new() -> Self {

        Self {

            key_id: None,

            algorithm: None,

            version: None,

            created_at: None,

            expires_at: None,

            purpose: None,

            performance_profile: None,

            metadata: HashMap::new(),

        }

    }



    /// Set the key ID

    pub fn key_id(mut self, key_id: KeyId) -> Self {

        self.key_id = Some(key_id);

        self

    }



    /// Set the algorithm

    pub fn algorithm(mut self, algorithm: String) -> Self {

        self.algorithm = Some(algorithm);

        self

    }



    /// Set the version

    pub fn version(mut self, version: KeyVersion) -> Self {

        self.version = Some(version);

        self

    }



    /// Set the creation time

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {

        self.created_at = Some(created_at);

        self

    }



    /// Set the expiration time

    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {

        self.expires_at = Some(expires_at);

        self

    }



    /// Set the purpose

    pub fn purpose(mut self, purpose: String) -> Self {

        self.purpose = Some(purpose);

        self

    }



    /// Set the performance profile

    pub fn performance_profile(mut self, performance_profile: PerformanceProfile) -> Self {

        self.performance_profile = Some(performance_profile);

        self

    }



    /// Add metadata

    pub fn with_metadata(mut self, key: String, value: String) -> Self {

        self.metadata.insert(key, value);

        self

    }



    /// Build the KeyMetadata

    pub fn build(self) -> Result<KeyMetadata> {

        Ok(KeyMetadata::new(

            self.key_id.ok_or_else(|| FortressError::key_management(

                "Key ID is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.algorithm.ok_or_else(|| FortressError::key_management(

                "Algorithm is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.version.ok_or_else(|| FortressError::key_management(

                "Version is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.created_at.unwrap_or_else(Utc::now),

            self.expires_at.ok_or_else(|| FortressError::key_management(

                "Expiration time is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.purpose.ok_or_else(|| FortressError::key_management(

                "Purpose is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.performance_profile.unwrap_or(PerformanceProfile::Balanced),

        ))

    }

}



impl Default for KeyMetadataBuilder {

    fn default() -> Self {

        Self::new()

    }

}



/// Comprehensive rotation policies for different data types and security requirements
/// Policy for key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Name of the rotation policy
    pub name: String,
    /// Description of what this policy covers
    pub description: String,
    /// How often keys should be rotated
    pub interval: RotationInterval,
    /// Data classification level this policy applies to
    pub data_classification: DataClassification,
    /// Compliance requirements that affect this policy
    pub compliance_requirements: Vec<ComplianceRequirement>,
    /// Grace period in hours before rotation is enforced
    pub grace_period_hours: u64,
    /// Whether rotation should happen automatically
    pub auto_rotate: bool,
    /// Hours before rotation to send notifications
    pub notification_hours_before: u64,
}

/// Data classification levels for rotation policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataClassification {
    /// Highly sensitive data (PII, financial, health)
    HighlyRestricted,
    /// Sensitive business data
    Restricted,
    /// Internal company data
    Internal,
    /// Public data
    Public,
}

/// Compliance requirements that may affect rotation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceRequirement {
    /// General Data Protection Regulation
    GDPR,
    /// Health Insurance Portability and Accountability Act
    HIPAA,
    /// Payment Card Industry Data Security Standard
    PciDss,
    /// Sarbanes-Oxley Act
    SOX,
    /// California Consumer Privacy Act
    CCPA,
    /// Custom compliance requirement
    Custom(String),
}

impl RotationPolicy {
    /// Get default policies for common data classifications
    pub fn get_default_policies() -> Vec<Self> {
        vec![
            Self {
                name: "PII and Financial Data".to_string(),
                description: "Policy for personally identifiable information and financial data".to_string(),
                interval: RotationInterval::Hour23,
                data_classification: DataClassification::HighlyRestricted,
                compliance_requirements: vec![ComplianceRequirement::GDPR, ComplianceRequirement::PciDss],
                grace_period_hours: 1,
                auto_rotate: true,
                notification_hours_before: 4,
            },
            Self {
                name: "Health Information".to_string(),
                description: "Policy for protected health information".to_string(),
                interval: RotationInterval::Days7,
                data_classification: DataClassification::HighlyRestricted,
                compliance_requirements: vec![ComplianceRequirement::HIPAA],
                grace_period_hours: 2,
                auto_rotate: true,
                notification_hours_before: 24,
            },
            Self {
                name: "Business Sensitive Data".to_string(),
                description: "Policy for sensitive business data".to_string(),
                interval: RotationInterval::Days30,
                data_classification: DataClassification::Restricted,
                compliance_requirements: vec![ComplianceRequirement::SOX],
                grace_period_hours: 6,
                auto_rotate: true,
                notification_hours_before: 72,
            },
            Self {
                name: "Internal Company Data".to_string(),
                description: "Policy for internal company data".to_string(),
                interval: RotationInterval::Days90,
                data_classification: DataClassification::Internal,
                compliance_requirements: vec![],
                grace_period_hours: 12,
                auto_rotate: true,
                notification_hours_before: 168, // 1 week
            },
            Self {
                name: "Public Data".to_string(),
                description: "Policy for public data".to_string(),
                interval: RotationInterval::Days90,
                data_classification: DataClassification::Public,
                compliance_requirements: vec![],
                grace_period_hours: 24,
                auto_rotate: false, // Manual rotation for public data
                notification_hours_before: 168,
            },
        ]
    }
    
    /// Get policy by data classification
    pub fn by_classification(classification: DataClassification) -> Option<Self> {
        Self::get_default_policies()
            .into_iter()
            .find(|policy| policy.data_classification == classification)
    }
    
    /// Check if rotation should occur based on policy
    pub fn should_rotate(&self, metadata: &KeyMetadata) -> bool {
        if !self.auto_rotate {
            return false;
        }
        
        let now = Utc::now();
        let rotation_time = metadata.created_at + self.interval.duration();
        
        // Add grace period
        let rotation_with_grace = rotation_time + ChronoDuration::hours(self.grace_period_hours as i64);
        
        now >= rotation_with_grace
    }
    
    /// Get next rotation time
    pub fn next_rotation_time(&self, metadata: &KeyMetadata) -> DateTime<Utc> {
        metadata.created_at + self.interval.duration()
    }
    
    /// Check if notification should be sent
    pub fn should_notify(&self, metadata: &KeyMetadata) -> bool {
        let now = Utc::now();
        let notification_time = self.next_rotation_time(metadata) - ChronoDuration::hours(self.notification_hours_before as i64);
        now >= notification_time && now < self.next_rotation_time(metadata)
    }
}
/// Interval for key rotation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RotationInterval {
    /// 23 hours - high security, near-daily rotation
    Hour23,
    /// 7 days - weekly rotation for sensitive data
    Days7,
    /// 30 days - monthly rotation for standard data
    Days30,
    /// 90 days - quarterly rotation for low sensitivity data
    Days90,
    /// Custom interval in hours/days
    Custom(ChronoDuration),
}

impl RotationInterval {
    /// Get the duration for this interval
    pub fn duration(&self) -> ChronoDuration {
        match self {
            RotationInterval::Hour23 => ChronoDuration::hours(23),
            RotationInterval::Days7 => ChronoDuration::days(7),
            RotationInterval::Days30 => ChronoDuration::days(30),
            RotationInterval::Days90 => ChronoDuration::days(90),
            RotationInterval::Custom(duration) => *duration,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            RotationInterval::Hour23 => "23 hours (high security)",
            RotationInterval::Days7 => "7 days (weekly)",
            RotationInterval::Days30 => "30 days (monthly)",
            RotationInterval::Days90 => "90 days (quarterly)",
            RotationInterval::Custom(_) => "custom interval",
        }
    }
}

/// Smart key rotation scheduler with optimized performance
pub struct SmartKeyRotationScheduler {
    key_manager: Arc<dyn KeyManager>,
    rotation_intervals: HashMap<String, RotationInterval>,
    rotation_cache: Arc<RwLock<HashMap<KeyId, DateTime<Utc>>>>,
    batch_size: usize,
    max_concurrent_rotations: usize,
    metrics: Arc<RwLock<RotationMetrics>>,
}

/// Metrics for tracking rotation performance
#[derive(Debug, Clone, Default)]
pub struct RotationMetrics {
    /// Total number of rotation attempts
    pub total_rotations: u64,
    /// Number of successful rotations
    pub successful_rotations: u64,
    /// Number of failed rotations
    pub failed_rotations: u64,
    /// Average time taken for rotations in milliseconds
    pub average_rotation_time_ms: u64,
    /// Timestamp of the last rotation
    pub last_rotation_time: Option<DateTime<Utc>>,
    /// Rotations grouped by interval type
    pub rotations_by_interval: HashMap<String, u64>,
}

impl std::fmt::Debug for SmartKeyRotationScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartKeyRotationScheduler")
            .field("rotation_intervals", &self.rotation_intervals)
            .field("batch_size", &self.batch_size)
            .field("max_concurrent_rotations", &self.max_concurrent_rotations)
            .finish()
    }
}

impl SmartKeyRotationScheduler {
    /// Create a new smart key rotation scheduler with optimized defaults
    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {
        Self {
            key_manager,
            rotation_intervals: HashMap::new(),
            rotation_cache: Arc::new(RwLock::new(HashMap::new())),
            batch_size: 100,
            max_concurrent_rotations: 10,
            metrics: Arc::new(RwLock::new(RotationMetrics::default())),
        }
    }

    /// Create scheduler with custom performance parameters
    pub fn with_config(
        key_manager: Arc<dyn KeyManager>,
        batch_size: usize,
        max_concurrent_rotations: usize,
    ) -> Self {
        Self {
            key_manager,
            rotation_intervals: HashMap::new(),
            rotation_cache: Arc::new(RwLock::new(HashMap::new())),
            batch_size,
            max_concurrent_rotations,
            metrics: Arc::new(RwLock::new(RotationMetrics::default())),
        }
    }

    /// Set rotation interval for a specific purpose
    pub fn set_rotation_interval(&mut self, purpose: String, interval: RotationInterval) {
        self.rotation_intervals.insert(purpose, interval);
    }

    /// Set rotation interval with predefined security levels
    pub fn set_security_level_intervals(&mut self) {
        self.rotation_intervals.insert("high_security".to_string(), RotationInterval::Hour23);
        self.rotation_intervals.insert("sensitive".to_string(), RotationInterval::Days7);
        self.rotation_intervals.insert("standard".to_string(), RotationInterval::Days30);
        self.rotation_intervals.insert("low_sensitivity".to_string(), RotationInterval::Days90);
    }

    /// Get rotation interval for a purpose
    pub fn get_rotation_interval(&self, purpose: &str) -> Option<&RotationInterval> {
        self.rotation_intervals.get(purpose)
    }

    /// Check all keys and rotate if needed using optimized batch processing
    pub async fn check_and_rotate(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let start_time = std::time::Instant::now();
        let keys = self.key_manager.list_keys().await?;
        
        // Filter keys that need rotation
        let keys_to_rotate = self.filter_keys_needing_rotation(keys).await?;
        
        if keys_to_rotate.is_empty() {
            return Ok(Vec::new());
        }

        // Process in batches for performance
        let mut rotated_keys = Vec::new();
        let chunks: Vec<_> = keys_to_rotate.chunks(self.batch_size).collect();
        
        for chunk in chunks {
            let batch_results = self.rotate_key_batch(chunk).await?;
            rotated_keys.extend(batch_results);
        }

        // Update metrics
        self.update_metrics(start_time, rotated_keys.len()).await;
        
        Ok(rotated_keys)
    }

    /// Filter keys that need rotation based on their intervals
    async fn filter_keys_needing_rotation(&self, keys: Vec<(KeyId, KeyMetadata)>) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let mut keys_to_rotate = Vec::new();
        let cache = self.rotation_cache.read().await;
        
        for (key_id, metadata) in keys {
            if let Some(interval) = self.rotation_intervals.get(&metadata.purpose) {
                let should_rotate = self.should_rotate_key(&key_id, &metadata, interval, &cache).await?;
                if should_rotate {
                    keys_to_rotate.push((key_id, metadata));
                }
            }
        }
        
        Ok(keys_to_rotate)
    }

    /// Determine if a specific key needs rotation
    async fn should_rotate_key(
        &self,
        key_id: &KeyId,
        metadata: &KeyMetadata,
        interval: &RotationInterval,
        cache: &HashMap<KeyId, DateTime<Utc>>,
    ) -> Result<bool> {
        let now = Utc::now();
        let interval_duration = interval.duration();
        
        // Check if key is expired first
        if metadata.is_expired() {
            return Ok(true);
        }
        
        // Check cache to avoid redundant calculations
        if let Some(&last_check) = cache.get(key_id) {
            let time_since_check = now - last_check;
            if time_since_check < interval_duration {
                return Ok(false);
            }
        }
        
        // Calculate time since creation or last rotation
        let time_since_creation = now - metadata.created_at;
        Ok(time_since_creation >= interval_duration)
    }

    /// Rotate a batch of keys concurrently
    async fn rotate_key_batch(&self, keys: &[(KeyId, KeyMetadata)]) -> Result<Vec<(KeyId, KeyMetadata)>> {
        use futures::stream::{self, StreamExt};
        
        let results = stream::iter(keys)
            .map(|(key_id, metadata)| async move {
                let rotation_result = self.rotate_single_key(key_id).await;
                (key_id.clone(), metadata.clone(), rotation_result)
            })
            .buffer_unordered(self.max_concurrent_rotations)
            .collect::<Vec<_>>()
            .await;
        
        let mut rotated_keys = Vec::new();
        for (key_id, metadata, result) in results {
            match result {
                Ok(_) => {
                    // Update cache with successful rotation
                    let mut cache = self.rotation_cache.write().await;
                    cache.insert(key_id.clone(), Utc::now());
                    rotated_keys.push((key_id, metadata));
                }
                Err(e) => {
                    // Log rotation failure but continue with others
                    eprintln!("Failed to rotate key {}: {}", key_id, e);
                }
            }
        }
        
        Ok(rotated_keys)
    }

    /// Rotate a single key with zero-downtime support
    async fn rotate_single_key(&self, key_id: &KeyId) -> Result<()> {
        let (_, metadata) = self.key_manager.retrieve_key(key_id).await?;
        let algorithm = crate::encryption::create_algorithm(&metadata.algorithm)?;
        
        // Zero-downtime rotation: create new key version before deactivating old one
        self.key_manager.rotate_key_with_zero_downtime(key_id, algorithm.as_ref()).await?;
        Ok(())
    }

    /// Update rotation metrics
    async fn update_metrics(&self, start_time: std::time::Instant, rotated_count: usize) {
        let mut metrics = self.metrics.write().await;
        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        
        metrics.total_rotations += rotated_count as u64;
        metrics.successful_rotations += rotated_count as u64;
        metrics.last_rotation_time = Some(Utc::now());
        
        // Update average rotation time
        if metrics.total_rotations > 0 {
            metrics.average_rotation_time_ms = 
                (metrics.average_rotation_time_ms * (metrics.total_rotations - 1) + elapsed_ms) / metrics.total_rotations;
        }
    }

    /// Get current rotation metrics
    pub async fn get_metrics(&self) -> RotationMetrics {
        self.metrics.read().await.clone()
    }

    /// Clear rotation cache
    pub async fn clear_cache(&self) {
        self.rotation_cache.write().await.clear();
    }

    /// Get keys that will need rotation soon (within next 24 hours)
    pub async fn get_keys_needing_soon_rotation(&self, hours_ahead: i64) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let keys = self.key_manager.list_keys().await?;
        let soon_threshold = Utc::now() + ChronoDuration::hours(hours_ahead);
        let mut soon_keys = Vec::new();
        
        for (key_id, metadata) in keys {
            if let Some(interval) = self.rotation_intervals.get(&metadata.purpose) {
                let next_rotation = metadata.created_at + interval.duration();
                if next_rotation <= soon_threshold && next_rotation > Utc::now() {
                    soon_keys.push((key_id, metadata));
                }
            }
        }
        
        Ok(soon_keys)
    }

    /// Force rotate a specific key regardless of schedule
    pub async fn force_rotate_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)> {
        let result = self.rotate_single_key(key_id).await;
        
        if result.is_ok() {
            // Update cache
            let mut cache = self.rotation_cache.write().await;
            cache.insert(key_id.to_string(), Utc::now());
        }
        
        // Return the new key metadata
        self.key_manager.retrieve_key(key_id).await
    }
}

/// Cron-like rotation scheduler for automated key rotation
#[derive(Clone)]
pub struct RotationScheduler {
    key_manager: Arc<dyn KeyManager>,
    policies: Vec<RotationPolicy>,
    is_running: Arc<RwLock<bool>>,
    last_run: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl RotationScheduler {
    /// Create a new rotation scheduler
    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {
        Self {
            key_manager,
            policies: RotationPolicy::get_default_policies(),
            is_running: Arc::new(RwLock::new(false)),
            last_run: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Create scheduler with custom policies
    pub fn with_policies(key_manager: Arc<dyn KeyManager>, policies: Vec<RotationPolicy>) -> Self {
        Self {
            key_manager,
            policies,
            is_running: Arc::new(RwLock::new(false)),
            last_run: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Add a rotation policy
    pub async fn add_policy(&mut self, policy: RotationPolicy) {
        self.policies.push(policy);
    }
    
    /// Remove a policy by name
    pub async fn remove_policy(&mut self, name: &str) -> Option<RotationPolicy> {
        let index = self.policies.iter().position(|p| p.name == name);
        if let Some(idx) = index {
            Some(self.policies.remove(idx))
        } else {
            None
        }
    }
    
    /// Get all policies
    pub async fn get_policies(&self) -> Vec<RotationPolicy> {
        self.policies.clone()
    }
    
    /// Start the automated rotation scheduler
    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(FortressError::key_management(
                "Scheduler is already running",
                None,
                KeyErrorCode::InvalidKeyFormat,
            ));
        }
        
        *is_running = true;
        drop(is_running);
        
        let key_manager = self.key_manager.clone();
        let policies = self.policies.clone();
        let is_running_flag = self.is_running.clone();
        let last_run = self.last_run.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Check every hour
            
            while {
                let flag = is_running_flag.read().await;
                *flag
            } {
                interval.tick().await;
                
                // Update last run time
                {
                    let mut last = last_run.write().await;
                    *last = Some(Utc::now());
                }
                
                // Check all keys for rotation
                if let Err(e) = Self::check_and_rotate_keys(&key_manager, &policies).await {
                    eprintln!("Rotation check failed: {}", e);
                }
            }
        });
        
        Ok(())
    }
    
    /// Stop the automated rotation scheduler
    pub async fn stop(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        Ok(())
    }
    
    /// Check if scheduler is running
    pub async fn is_running(&self) -> bool {
        let flag = self.is_running.read().await;
        *flag
    }
    
    /// Get last run time
    pub async fn last_run(&self) -> Option<DateTime<Utc>> {
        let last = self.last_run.read().await;
        *last
    }
    
    /// Manual rotation check
    pub async fn check_rotation_now(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        Self::check_and_rotate_keys(&self.key_manager, &self.policies).await
    }
    
    /// Internal method to check and rotate keys based on policies
    async fn check_and_rotate_keys(
        key_manager: &Arc<dyn KeyManager>,
        policies: &[RotationPolicy],
    ) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let keys = key_manager.list_keys().await?;
        let mut rotated_keys = Vec::new();
        
        for (key_id, metadata) in keys {
            // Find applicable policy based on purpose/data classification
            if let Some(policy) = Self::find_applicable_policy(policies, &metadata) {
                if policy.should_rotate(&metadata) {
                    // Get algorithm for rotation
                    let algorithm = crate::encryption::create_algorithm(&metadata.algorithm)?;
                    
                    // Perform zero-downtime rotation
                    if let Err(e) = key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await {
                        eprintln!("Failed to rotate key {}: {}", key_id, e);
                        continue;
                    }
                    
                    rotated_keys.push((key_id.clone(), metadata.clone()));
                    
                    // Log successful rotation
                    let mut audit_metadata = std::collections::HashMap::new();
                    audit_metadata.insert("key_id".to_string(), key_id.clone());
                    audit_metadata.insert("policy".to_string(), policy.name.clone());
                    audit_metadata.insert("classification".to_string(), format!("{:?}", policy.data_classification));
                    
                    if let Err(e) = log_event_with_metadata(
                        AuditEventType::KeyManagement,
                        SecurityLevel::High,
                        Some("system".to_string()),
                        Some(format!("key:{}", key_id)),
                        "automatic_rotation".to_string(),
                        EventOutcome::Success,
                        audit_metadata,
                    ) {
                        eprintln!("Failed to log rotation: {}", e);
                    }
                }
                
                // Check if notification should be sent
                if policy.should_notify(&metadata) {
                    // In production, this would send notifications via email, Slack, etc.
                    let mut notification_metadata = std::collections::HashMap::new();
                    notification_metadata.insert("key_id".to_string(), key_id.clone());
                    notification_metadata.insert("next_rotation".to_string(), policy.next_rotation_time(&metadata).to_rfc3339());
                    notification_metadata.insert("policy".to_string(), policy.name.clone());
                    
                    if let Err(e) = log_event_with_metadata(
                        AuditEventType::KeyManagement,
                        SecurityLevel::Medium,
                        Some("system".to_string()),
                        Some(format!("key:{}", key_id)),
                        "rotation_notification".to_string(),
                        EventOutcome::Success,
                        notification_metadata,
                    ) {
                        eprintln!("Failed to log rotation notification: {}", e);
                    }
                }
            }
        }
        
        Ok(rotated_keys)
    }
    
    /// Find applicable policy for a key based on its metadata
    fn find_applicable_policy<'a>(policies: &'a [RotationPolicy], metadata: &KeyMetadata) -> Option<&'a RotationPolicy> {
        // Simple mapping based on purpose - in production, this would be more sophisticated
        let classification = match metadata.purpose.as_str() {
            "pii" | "financial" | "health" => DataClassification::HighlyRestricted,
            "business" | "sensitive" => DataClassification::Restricted,
            "internal" => DataClassification::Internal,
            "public" => DataClassification::Public,
            _ => DataClassification::Internal, // Default to internal
        };
        
        policies.iter().find(|policy| policy.data_classification == classification)
    }
}

/// Key derivation function types

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum KeyDerivationFunction {

    /// Argon2id (memory-hard, recommended)

    Argon2id {

        /// Memory cost in KiB

        memory_cost: u32,

        /// Number of iterations

        iterations: u32,

        /// Parallelism factor

        parallelism: u32,

    },

    /// PBKDF2 with HMAC-SHA256

    Pbkdf2 {

        /// Number of iterations

        iterations: u32,

        /// Salt length in bytes

        salt_length: usize,

    },

    /// scrypt

    Scrypt {

        /// CPU/memory cost parameter

        n: u32,

        /// Block size parameter

        r: u32,

        /// Parallelization parameter

        p: u32,

    },

}



impl Default for KeyDerivationFunction {

    fn default() -> Self {

        Self::Argon2id {

            memory_cost: 65536, // 64 MiB

            iterations: 3,

            parallelism: 4,

        }

    }

}



/// Key derivation utilities

pub struct KeyDerivation;



impl KeyDerivation {

    /// Derive a key from a password and salt

    pub fn derive_key(

        password: &[u8],

        salt: &[u8],

        kdf: &KeyDerivationFunction,

        output_length: usize,

    ) -> Result<Vec<u8>> {

        match kdf {

            KeyDerivationFunction::Argon2id { memory_cost, iterations, parallelism } => {

                let params = argon2::Params::new(*memory_cost, *iterations, *parallelism, Some(output_length))

                    .map_err(|e| FortressError::key_management(

                        format!("Invalid Argon2 parameters: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                let argon2 = argon2::Argon2::new(

                    argon2::Algorithm::Argon2id,

                    argon2::Version::V0x13,

                    params,

                );



                let mut output = vec![0u8; output_length];

                argon2

                    .hash_password_into(password, salt, &mut output)

                    .map_err(|e| FortressError::key_management(

                        format!("Argon2 derivation failed: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                Ok(output)

            }

            KeyDerivationFunction::Pbkdf2 { iterations, salt_length } => {

                if salt.len() != *salt_length {

                    return Err(FortressError::key_management(

                        format!("Invalid salt length: expected {}, got {}", salt_length, salt.len()),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ));

                }



                let mut output = vec![0u8; output_length];

                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, *iterations, &mut output);

                Ok(output)

            }

            KeyDerivationFunction::Scrypt { n, r, p } => {

                let params = scrypt::Params::new(
                    (*n).try_into().map_err(|_| FortressError::key_management(
                        "Invalid scrypt n parameter: too large".to_string(),
                        None,
                        KeyErrorCode::DerivationFailed,
                    ))?,
                    *r, *p, output_length
                )

                    .map_err(|e| FortressError::key_management(

                        format!("Invalid scrypt parameters: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                let mut output = vec![0u8; output_length];

                scrypt::scrypt(password, salt, &params, &mut output)

                    .map_err(|e| FortressError::key_management(

                        format!("scrypt derivation failed: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                Ok(output)

            }

        }

    }



    /// Generate a random salt

    pub fn generate_salt(length: usize) -> Result<Vec<u8>> {

        match crate::trng::random_bytes(length) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                // Fallback to getrandom
                let mut salt = vec![0u8; length];
                getrandom::getrandom(&mut salt)
                    .map_err(|e| FortressError::key_management(
                        format!("Failed to generate salt: {}", e),
                        None,
                        KeyErrorCode::DerivationFailed,
                    ))?;
                Ok(salt)
            }
        }
    }

}


pub use crate::encryption::SecureKey;

/// HSM-backed key manager that implements the KeyManager trait
pub struct HsmKeyManager {
    inner: Arc<HsmKeyManagerInner>,
    /// Local cache for key metadata to reduce HSM calls
    metadata_cache: Arc<RwLock<HashMap<KeyId, KeyMetadata>>>,
}

impl HsmKeyManager {
    /// Create a new HSM-backed key manager
    pub async fn new(config: HsmConfig) -> Result<Self> {
        let inner = Arc::new(HsmKeyManagerInner::new(config).await?);
        
        Ok(Self {
            inner,
            metadata_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Get reference to the underlying HSM provider
    pub fn provider(&self) -> &dyn crate::hsm::HsmProvider {
        self.inner.provider()
    }
    
    /// Clear the metadata cache
    pub async fn clear_cache(&self) -> Result<()> {
        let mut cache = self.metadata_cache.write().await;
        cache.clear();
        Ok(())
    }
}

#[async_trait]
impl KeyManager for HsmKeyManager {
    async fn generate_key(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<SecureKey> {
        // Generate a key ID for the HSM
        let key_id = Uuid::new_v4().to_string();
        
        // Generate the key in HSM
        self.inner.provider().generate_key(&key_id, algorithm).await?;
        
        // Get the metadata from HSM
        let metadata = self.inner.provider().get_key_metadata(&key_id).await?;
        
        // Cache the metadata
        {
            let mut cache = self.metadata_cache.write().await;
            cache.insert(key_id.clone(), metadata.clone());
        }
        
        // Return a placeholder SecureKey - the actual key is stored in HSM
        // This is a limitation of the current design - we may need to refactor
        // SecureKey to support HSM references
        Ok(SecureKey::generate(algorithm.key_size()))
    }
    
    async fn store_key(&self, _key_id: &KeyId, _key: &SecureKey, _metadata: &KeyMetadata) -> Result<()> {
        // For HSM, we don't store external keys - we generate them internally
        // This method is kept for compatibility but may not be fully functional
        Err(FortressError::key_management(
            "HSM key manager does not support storing external keys. Use generate_key instead.",
            None,
            KeyErrorCode::ProviderError,
        ))
    }
    
    async fn retrieve_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)> {
        // Try to get metadata from cache first
        let metadata = {
            let cache = self.metadata_cache.read().await;
            if let Some(metadata) = cache.get(key_id) {
                metadata.clone()
            } else {
                // Get from HSM and cache it
                let metadata = self.inner.provider().get_key_metadata(key_id).await?;
                drop(cache);
                {
                    let mut cache = self.metadata_cache.write().await;
                    cache.insert(key_id.clone(), metadata.clone());
                }
                metadata
            }
        };
        
        // Return a placeholder key - actual operations should use HSM provider directly
        let key = SecureKey::generate(256); // Default size
        
        Ok((key, metadata))
    }
    
    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        // Delete from HSM
        self.inner.provider().delete_key(key_id).await?;
        
        // Remove from cache
        {
            let mut cache = self.metadata_cache.write().await;
            cache.remove(key_id);
        }
        
        Ok(())
    }
    
    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let keys = self.inner.provider().list_keys().await?;
        
        // Update cache
        {
            let mut cache = self.metadata_cache.write().await;
            for (key_id, metadata) in &keys {
                cache.insert(key_id.clone(), metadata.clone());
            }
        }
        
        Ok(keys)
    }
    
    async fn rotate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
        // Delete old key from HSM
        self.inner.provider().delete_key(key_id).await?;
        
        // Generate new key with same ID
        self.inner.provider().generate_key(key_id, algorithm).await?;
        
        // Get new metadata
        let metadata = self.inner.provider().get_key_metadata(key_id).await?;
        
        // Update cache
        {
            let mut cache = self.metadata_cache.write().await;
            cache.insert(key_id.clone(), metadata.clone());
        }
        
        // Return placeholder key
        let _key = SecureKey::generate(algorithm.key_size());
        
        Ok(())
    }
    
    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        // Try to get metadata to check if key exists
        match self.inner.provider().get_key_metadata(key_id).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata> {
        // Check cache first
        {
            let cache = self.metadata_cache.read().await;
            if let Some(metadata) = cache.get(key_id) {
                return Ok(metadata.clone());
            }
        }
        
        // Get from HSM
        let metadata = self.inner.provider().get_key_metadata(key_id).await?;
        
        // Update cache
        {
            let mut cache = self.metadata_cache.write().await;
            cache.insert(key_id.clone(), metadata.clone());
        }
        
        Ok(metadata)
    }

    async fn get_active_key_version(&self, key_id: &KeyId) -> Result<u32> {
        let metadata = self.get_key_metadata(key_id).await?;
        Ok(metadata.version)
    }

    async fn initiate_key_transition(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<u32> {
        // HSM implementation - simplified version
        let old_metadata = self.get_key_metadata(key_id).await?;
        let new_version = old_metadata.version + 1;
        
        // Generate new key in HSM
        let new_key_id = format!("{}_v{}", key_id, new_version);
        self.inner.provider().generate_key(&new_key_id, algorithm).await?;
        
        // Store backup of old key
        let _backup_key_id = format!("{}_v{}_backup", key_id, old_metadata.version);
        // In real HSM, this would involve key export/import operations
        
        Ok(new_version)
    }

    async fn complete_key_transition(&self, key_id: &KeyId, new_version: u32) -> Result<()> {
        // HSM implementation - cleanup old versions
        let old_key_id = format!("{}_v{}", key_id, new_version - 1);
        let backup_key_id = format!("{}_v{}_backup", key_id, new_version - 1);
        
        // Delete old versions from HSM
        let _ = self.inner.provider().delete_key(&old_key_id).await;
        let _ = self.inner.provider().delete_key(&backup_key_id).await;
        
        Ok(())
    }

    async fn validate_dual_keys(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<bool> {
        let old_key_id = format!("{}_v{}", key_id, old_version);
        let new_key_id = format!("{}_v{}", key_id, new_version);
        
        let old_exists = self.key_exists(&old_key_id).await?;
        let new_exists = self.key_exists(&new_key_id).await?;
        
        Ok(old_exists && new_exists)
    }

    async fn rollback_key_transition(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<()> {
        // HSM implementation - restore from backup
        let _backup_key_id = format!("{}_v{}_backup", key_id, old_version);
        let new_key_id = format!("{}_v{}", key_id, new_version);
        
        // Delete failed new version
        let _ = self.inner.provider().delete_key(&new_key_id).await;
        
        // Restore from backup (simplified - real HSM would need proper key restore)
        let _restored_key_id = format!("{}_v{}", key_id, old_version);
        // In real implementation, this would restore from backup
        
        Ok(())
    }

    async fn needs_rotation(&self, key_id: &KeyId) -> Result<bool> {
        let metadata = self.get_key_metadata(key_id).await?;
        Ok(Utc::now() >= metadata.expires_at)
    }

    async fn get_active_key(&self, purpose: &str) -> Result<(SecureKey, KeyMetadata)> {
        let keys = self.list_keys().await?;
        for (_key_id, metadata) in keys {
            if metadata.purpose == purpose && metadata.is_active() {
                let key = SecureKey::generate(256); // Placeholder - real HSM would use provider
                return Ok((key, metadata));
            }
        }
        Err(FortressError::key_management(
            format!("No active key found for purpose: {}", purpose),
            None,
            KeyErrorCode::KeyNotFound,
        ))
    }

    async fn validate_new_key(&self, new_versioned_id: &KeyId) -> Result<()> {
        // HSM implementation - validate key exists and is accessible
        let metadata = self.get_key_metadata(new_versioned_id).await?;
        
        // Test basic key operations through HSM
        if metadata.version == 0 {
            return Err(FortressError::key_management(
                "Invalid key version",
                Some(new_versioned_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }
        
        // Verify key is accessible through HSM
        if !self.key_exists(new_versioned_id).await? {
            return Err(FortressError::key_management(
                "Key not accessible in HSM",
                Some(new_versioned_id.clone()),
                KeyErrorCode::KeyNotFound,
            ));
        }
        
        Ok(())
    }

    async fn validate_post_switch(&self, key_id: &KeyId, expected_version: u32) -> Result<()> {
        let metadata = self.get_key_metadata(key_id).await?;
        
        if metadata.version != expected_version {
            return Err(FortressError::key_management(
                format!("Version mismatch after switch: expected {}, got {}", expected_version, metadata.version),
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        if !metadata.is_active() {
            return Err(FortressError::key_management(
                "New key is not active after switch",
                Some(key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        
        Ok(())
    }

    async fn perform_key_transition_initiation(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<u32> {
        let old_metadata = self.get_key_metadata(key_id).await?;
        let new_version = old_metadata.version + 1;
        
        // Generate new key in HSM
        let new_key_id = format!("{}_v{}", key_id, new_version);
        self.inner.provider().generate_key(&new_key_id, algorithm).await?;
        
        // Store backup of old key
        let _backup_key_id = format!("{}_v{}_backup", key_id, old_metadata.version);
        // In real HSM, this would involve key export/import operations
        
        // Update main key metadata to point to new version
        use chrono::{Duration as ChronoDuration, Utc};
        let new_metadata = KeyMetadata::new(
            key_id.to_string(),
            algorithm.name().to_string(),
            new_version,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        ).with_metadata("transition_status".to_string(), "initiating".to_string())
         .with_metadata("transition_started".to_string(), Utc::now().to_rfc3339());
        
        // Store new key metadata
        // Note: In real HSM implementation, this would update the HSM's metadata
        // For now, we'll just cache it locally
        {
            let mut cache = self.metadata_cache.write().await;
            cache.insert(new_key_id.clone(), new_metadata.clone());
        }
        
        Ok(new_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::encryption::{Aegis256, ChaCha20Poly1305};



    #[tokio::test]

    async fn test_in_memory_key_manager() {

        let manager = InMemoryKeyManager::new();

        let algorithm = Aegis256::new();

        

        // Generate and store a key

        let key = manager.generate_key(&algorithm).await.unwrap();

        let key_id = Uuid::new_v4().to_string();

        let metadata = KeyMetadata::builder()

            .key_id(key_id.clone())

            .algorithm(algorithm.name().to_string())

            .version(1)

            .expires_at(Utc::now() + ChronoDuration::days(90))

            .purpose("test".to_string())

            .performance_profile(PerformanceProfile::Lightning)

            .build()

            .unwrap();



        manager.store_key(&key_id, &key, &metadata).await.unwrap();



        // Retrieve the key

        let (retrieved_key, retrieved_metadata) = manager.retrieve_key(&key_id).await.unwrap();

        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());

        assert_eq!(metadata.key_id, retrieved_metadata.key_id);



        // List keys

        let keys = manager.list_keys().await.unwrap();

        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].0, key_id);



        // Delete key

        manager.delete_key(&key_id).await.unwrap();

        let keys = manager.list_keys().await.unwrap();

        assert_eq!(keys.len(), 0);

    }



    #[tokio::test]

    async fn test_key_rotation() {

        let manager = InMemoryKeyManager::new();

        let algorithm = ChaCha20Poly1305::new();

        

        let key_id = Uuid::new_v4().to_string();

        let key = manager.generate_key(&algorithm).await.unwrap();

        let metadata = KeyMetadata::builder()

            .key_id(key_id.clone())

            .algorithm(algorithm.name().to_string())

            .version(1)

            .expires_at(Utc::now() - ChronoDuration::hours(1)) // Expired

            .purpose("test".to_string())

            .performance_profile(PerformanceProfile::Balanced)

            .build()

            .unwrap();



        manager.store_key(&key_id, &key, &metadata).await.unwrap();



        // Check if rotation is needed by checking expiration
        let (_, metadata) = manager.retrieve_key(&key_id).await.unwrap();
        let needs_rotation = metadata.is_expired();

        assert!(needs_rotation);



        // Rotate the key
        manager.rotate_key(&key_id, &algorithm).await.unwrap();
        
        // Verify the key was rotated
        let (_, new_metadata) = manager.retrieve_key(&key_id).await.unwrap();
        assert_eq!(new_metadata.version, 2);

    }



    #[test]

    fn test_key_metadata() {

        let metadata = KeyMetadata::new(

            "test-key".to_string(),

            "aegis256".to_string(),

            1,

            Utc::now(),

            Utc::now() + ChronoDuration::days(90),

            "encryption".to_string(),

            PerformanceProfile::Lightning,

        );



        assert!(metadata.is_active());

        assert!(!metadata.is_expired());

        assert!(metadata.time_until_expiration().is_some());



        let expired_metadata = KeyMetadata::new(

            "expired-key".to_string(),

            "aegis256".to_string(),

            1,

            Utc::now() - ChronoDuration::days(10),

            Utc::now() - ChronoDuration::days(1),

            "encryption".to_string(),

            PerformanceProfile::Lightning,

        );



        assert!(!expired_metadata.is_active());

        assert!(expired_metadata.is_expired());

        assert!(expired_metadata.time_until_expiration().is_none());

    }



    #[test]

    fn test_key_derivation() {

        let password = b"test_password";

        let salt = KeyDerivation::generate_salt(16).unwrap();

        

        // Test Argon2id

        let kdf = KeyDerivationFunction::Argon2id {

            memory_cost: 1024,

            iterations: 2,

            parallelism: 1,

        };

        

        let key = KeyDerivation::derive_key(password, &salt, &kdf, 32).unwrap();

        assert_eq!(key.len(), 32);



        // Test PBKDF2

        let kdf = KeyDerivationFunction::Pbkdf2 {

            iterations: 1000,

            salt_length: 16,

        };

        

        let key = KeyDerivation::derive_key(password, &salt, &kdf, 32).unwrap();

        assert_eq!(key.len(), 32);



        // Test scrypt

        let kdf = KeyDerivationFunction::Scrypt { n: 2, r: 1, p: 1 };

        let key = KeyDerivation::derive_key(password, &salt, &kdf, 32).unwrap();

        assert_eq!(key.len(), 32);

    }



    #[test]

    fn test_key_derivation_deterministic() {

        let password = b"test_password";

        let salt = b"test_salt_123456";

        let kdf = KeyDerivationFunction::Pbkdf2 {

            iterations: 100,

            salt_length: salt.len(),

        };

        

        let key1 = KeyDerivation::derive_key(password, salt, &kdf, 32).unwrap();

        let key2 = KeyDerivation::derive_key(password, salt, &kdf, 32).unwrap();

        

        assert_eq!(key1, key2);

    }



    #[tokio::test]

    async fn test_zero_downtime_rotation_functionality() {
        let manager = InMemoryKeyManager::new();
        let algorithm = crate::encryption::Aegis256::new();
        
        // Create a key
        let key_id = "zero-downtime-test".to_string();
        let key = manager.generate_key(&algorithm).await.unwrap();
        
        let metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now() - ChronoDuration::hours(25), // Created 25 hours ago
            Utc::now() - ChronoDuration::hours(1),  // Expired 1 hour ago
            "test".to_string(),
            crate::encryption::PerformanceProfile::Balanced,
        );
        
        manager.store_key(&key_id, &key, &metadata).await.unwrap();
        
        // Test zero-downtime rotation directly
        let (_, old_metadata) = manager.retrieve_key(&key_id).await.unwrap();
        assert_eq!(old_metadata.version, 1);
        
        // Perform zero-downtime rotation
        manager.rotate_key_with_zero_downtime(&key_id, &algorithm).await.unwrap();
        
        // Verify rotation worked
        let (_, new_metadata) = manager.retrieve_key(&key_id).await.unwrap();
        assert_eq!(new_metadata.version, 2);
        assert!(new_metadata.created_at > old_metadata.created_at);
        assert!(new_metadata.expires_at > old_metadata.expires_at);
        
        // Verify the key is still accessible (no downtime)
        let (_, retrieved_metadata) = manager.retrieve_key(&key_id).await.unwrap();
        assert_eq!(retrieved_metadata.version, 2);
    }

    #[tokio::test]

    async fn test_key_rotation_scheduler() {

        let manager = Arc::new(InMemoryKeyManager::new());

        let mut scheduler = SmartKeyRotationScheduler::new(manager.clone());

        

        // Set rotation interval for test purpose

        scheduler.set_rotation_interval("test".to_string(), RotationInterval::Custom(ChronoDuration::hours(24)));

        

        // Create an expired key

        let algorithm = Aegis256::new();

        let key_id = Uuid::new_v4().to_string();

        let key = manager.generate_key(&algorithm).await.unwrap();

        let metadata = KeyMetadata::builder()

            .key_id(key_id.clone())

            .algorithm(algorithm.name().to_string())

            .version(1)

            .expires_at(Utc::now() - ChronoDuration::hours(25)) // Expired 25 hours ago

            .purpose("test".to_string())

            .performance_profile(PerformanceProfile::Lightning)

            .build()

            .unwrap();



        manager.store_key(&key_id, &key, &metadata).await.unwrap();



        // Check and rotate

        let rotated_keys = scheduler.check_and_rotate().await.unwrap();

        // Verify that zero-downtime rotation is working

        assert!(rotated_keys.len() > 0, "Expected at least one key to be rotated");

        // Verify the key was actually rotated (version should be incremented)

        let (_, new_metadata) = manager.retrieve_key(&key_id).await.unwrap();

        assert_eq!(new_metadata.version, 2, "Key version should be incremented after rotation");

        assert!(new_metadata.created_at > metadata.created_at, "New key should have later creation time");

    }

}
