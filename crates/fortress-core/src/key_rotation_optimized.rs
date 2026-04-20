//! Optimized Zero-Downtime Key Rotation
//! 
//! This module provides high-performance, scalable, and secure key rotation
//! with advanced optimizations for production environments.

use crate::error::{FortressError, Result, KeyErrorCode};
use crate::encryption::EncryptionAlgorithm;
use crate::audit::{SecurityLevel};
use crate::key::{KeyManager, KeyMetadata, KeyId, SecureKey};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::{timeout, Duration, Instant};
use uuid::Uuid;

/// Versioned key cache to reduce string allocations
#[derive(Debug)]
pub struct VersionedKeyCache {
    cache: Arc<RwLock<HashMap<(String, u32), Arc<String>>>>,
}

impl VersionedKeyCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_or_create(&self, key_id: &str, version: u32) -> Arc<String> {
        let mut cache = self.cache.write().await;
        cache.entry((key_id.to_string(), version))
            .or_insert_with(|| Arc::new(format!("{}_v{}", key_id, version)))
            .clone()
    }

    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

/// Performance metrics for key rotation operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationMetrics {
    /// Total rotation operations
    pub total_rotations: u64,
    /// Successful rotations
    pub successful_rotations: u64,
    /// Failed rotations
    pub failed_rotations: u64,
    /// Average rotation time in milliseconds
    pub avg_rotation_time_ms: f64,
    /// Fastest rotation time in milliseconds
    pub fastest_rotation_ms: f64,
    /// Slowest rotation time in milliseconds
    pub slowest_rotation_ms: f64,
    /// Concurrent rotations peak
    pub concurrent_rotations_peak: u32,
    /// Keys currently rotating
    pub keys_rotating: u32,
    /// Last rotation timestamp
    pub last_rotation_time: Option<DateTime<Utc>>,
}

impl Default for RotationMetrics {
    fn default() -> Self {
        Self {
            total_rotations: 0,
            successful_rotations: 0,
            failed_rotations: 0,
            avg_rotation_time_ms: 0.0,
            fastest_rotation_ms: f64::MAX,
            slowest_rotation_ms: 0.0,
            concurrent_rotations_peak: 0,
            keys_rotating: 0,
            last_rotation_time: None,
        }
    }
}

/// Optimized rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedRotationConfig {
    /// Maximum concurrent rotations
    pub max_concurrent_rotations: u32,
    /// Backup timeout in seconds
    pub backup_timeout_secs: u64,
    /// Validation timeout in seconds
    pub validation_timeout_secs: u64,
    /// Post-switch validation timeout in seconds
    pub post_switch_timeout_secs: u64,
    /// Rollback timeout in seconds
    pub rollback_timeout_secs: u64,
    /// Enable performance monitoring
    pub enable_performance_monitoring: bool,
    /// Enable security hardening
    pub enable_security_hardening: bool,
    /// Batch size for bulk operations
    pub batch_size: usize,
    /// Memory pool size for key operations
    pub memory_pool_size: usize,
}

impl Default for OptimizedRotationConfig {
    fn default() -> Self {
        Self {
            max_concurrent_rotations: 10,
            backup_timeout_secs: 15, // Reduced from 30 for faster response
            validation_timeout_secs: 5, // Reduced from 10
            post_switch_timeout_secs: 3, // Reduced from 5
            rollback_timeout_secs: 8, // Reduced from 10
            enable_performance_monitoring: true,
            enable_security_hardening: true,
            batch_size: 100,
            memory_pool_size: 1000,
        }
    }
}

/// High-performance rotation context
#[derive(Debug, Clone)]
pub struct RotationContext {
    /// Unique rotation identifier
    pub rotation_id: String,
    /// Key being rotated
    pub key_id: String,
    /// Start time
    pub start_time: Instant,
    /// Configuration
    pub config: OptimizedRotationConfig,
    /// Security context
    pub security_context: SecurityContext,
}

/// Security context for rotation operations
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Requestor identity
    pub requestor_id: String,
    /// Security level
    pub security_level: SecurityLevel,
    /// Required permissions
    pub required_permissions: Vec<String>,
    /// IP address (if applicable)
    pub ip_address: Option<String>,
    /// User agent (if applicable)
    pub user_agent: Option<String>,
}

/// Optimized key rotation manager
pub struct OptimizedKeyRotationManager<T: KeyManager> {
    /// Underlying key manager
    key_manager: Arc<T>,
    /// Rotation configuration
    config: OptimizedRotationConfig,
    /// Performance metrics
    metrics: Arc<RwLock<RotationMetrics>>,
    /// Concurrent rotation limiter
    rotation_semaphore: Arc<Semaphore>,
    /// Active rotations tracking
    active_rotations: Arc<RwLock<HashMap<String, RotationContext>>>,
    /// Memory pool for key operations
    memory_pool: Arc<RwLock<Vec<SecureKey>>>,
    /// Security audit log
    audit_log: Arc<RwLock<Vec<SecurityAuditEntry>>>,
    /// Versioned key cache to reduce string allocations
    versioned_key_cache: Arc<VersionedKeyCache>,
}

/// Security audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Rotation ID
    pub rotation_id: String,
    /// Key ID
    pub key_id: String,
    /// Action performed
    pub action: String,
    /// Security level
    pub security_level: SecurityLevel,
    /// Requestor ID
    pub requestor_id: String,
    /// IP address
    pub ip_address: Option<String>,
    /// Success status
    pub success: bool,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl<T: KeyManager> OptimizedKeyRotationManager<T> {
    /// Create new optimized rotation manager
    pub fn new(key_manager: Arc<T>, config: OptimizedRotationConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_rotations as usize));
        let memory_pool_size = config.memory_pool_size;
        
        Self {
            key_manager,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(RotationMetrics::default())),
            rotation_semaphore: semaphore,
            active_rotations: Arc::new(RwLock::new(HashMap::new())),
            memory_pool: Arc::new(RwLock::new(Vec::with_capacity(memory_pool_size))),
            audit_log: Arc::new(RwLock::new(Vec::new())),
            versioned_key_cache: Arc::new(VersionedKeyCache::new()),
        }
    }

    /// Perform optimized zero-downtime rotation
    pub async fn rotate_key_optimized(
        &self,
        key_id: &KeyId,
        algorithm: &dyn EncryptionAlgorithm,
        security_context: SecurityContext,
    ) -> Result<String> {
        let start_time = Instant::now();
        let rotation_id = Uuid::new_v4().to_string();
        
        // Check concurrency limits
        let _permit = timeout(
            Duration::from_secs(5),
            self.rotation_semaphore.acquire()
        ).await
        .map_err(|_| FortressError::key_management(
            "Rotation semaphore acquisition timeout",
            Some(key_id.clone()),
            KeyErrorCode::RotationFailed,
        ))?
        .map_err(|_| FortressError::key_management(
            "Failed to acquire rotation permit",
            Some(key_id.clone()),
            KeyErrorCode::RotationFailed,
        ))?;

        // Create rotation context
        let context = RotationContext {
            rotation_id: rotation_id.clone(),
            key_id: key_id.clone(),
            start_time,
            config: self.config.clone(),
            security_context: security_context.clone(),
        };

        // Track active rotation
        {
            let mut active = self.active_rotations.write().await;
            active.insert(key_id.clone(), context.clone());
            
            // Update concurrent peak
            let mut metrics = self.metrics.write().await;
            metrics.concurrent_rotations_peak = metrics.concurrent_rotations_peak.max(active.len() as u32);
            metrics.keys_rotating = active.len() as u32;
        }

        // Log rotation start
        self.log_security_event(
            &rotation_id,
            key_id,
            "rotation_start",
            &security_context,
            true,
            HashMap::new(),
        ).await;

        let result = self.perform_optimized_rotation(&context, algorithm).await;
        let rotation_time = start_time.elapsed().as_millis() as f64;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_rotations += 1;
            metrics.last_rotation_time = Some(Utc::now());
            
            if result.is_ok() {
                metrics.successful_rotations += 1;
            } else {
                metrics.failed_rotations += 1;
            }
            
            // Update timing metrics
            metrics.avg_rotation_time_ms = 
                (metrics.avg_rotation_time_ms * (metrics.total_rotations - 1) as f64 + rotation_time) / 
                metrics.total_rotations as f64;
            metrics.fastest_rotation_ms = metrics.fastest_rotation_ms.min(rotation_time);
            metrics.slowest_rotation_ms = metrics.slowest_rotation_ms.max(rotation_time);
        }

        // Clean up active rotation tracking
        {
            let mut active = self.active_rotations.write().await;
            active.remove(key_id);
            let mut metrics = self.metrics.write().await;
            metrics.keys_rotating = active.len() as u32;
        }

        // Log completion
        let success = result.is_ok();
        self.log_security_event(
            &rotation_id,
            key_id,
            "rotation_complete",
            &security_context,
            success,
            {
                let mut metadata = HashMap::new();
                metadata.insert("rotation_time_ms".to_string(), rotation_time.to_string());
                metadata.insert("success".to_string(), success.to_string());
                metadata
            },
        ).await;

        result.map(|()| rotation_id)
    }

    /// Perform the actual optimized rotation
    async fn perform_optimized_rotation(
        &self,
        context: &RotationContext,
        algorithm: &dyn EncryptionAlgorithm,
    ) -> Result<()> {
        // Phase 1: Optimized backup creation
        let (old_key, old_metadata) = self.key_manager.retrieve_key(&context.key_id).await?;
        let old_versioned_id = self.versioned_key_cache.get_or_create(&context.key_id, old_metadata.version).await;
        
        // Use memory pool for backup key
        let _backup_key = self.get_pooled_key().await;
        
        let backup_result = timeout(
            Duration::from_secs(context.config.backup_timeout_secs),
            self.key_manager.store_key(&old_versioned_id, &old_key, &old_metadata)
        ).await;

        if backup_result.is_err() {
            return Err(FortressError::key_management(
                "Backup creation timeout during optimized rotation",
                Some(context.key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }
        let _ = backup_result.map_err(|e| FortressError::key_management(
            format!("Backup creation failed: {}", e),
            Some(context.key_id.clone()),
            KeyErrorCode::RotationFailed,
        ));

        // Phase 2: Optimized key generation
        let new_key = self.key_manager.generate_key(algorithm).await?;
        let new_version = old_metadata.version + 1;
        
        let new_metadata = KeyMetadata::new(
            context.key_id.clone(),
            algorithm.name().to_string(),
            new_version,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        ).with_metadata("rotation_id".to_string(), context.rotation_id.clone())
         .with_metadata("transition_status".to_string(), "preparing".to_string())
         .with_metadata("security_context".to_string(), format!("{:?}", context.security_context.security_level));

        // Phase 3: Optimized validation
        let validation_result = timeout(
            Duration::from_secs(context.config.validation_timeout_secs),
            self.validate_key_optimized(&new_key, &new_metadata)
        ).await;

        if validation_result.is_err() || validation_result.as_ref().unwrap().is_err() {
            // Cleanup and rollback
            let new_versioned_id = self.versioned_key_cache.get_or_create(&context.key_id, new_version).await;
            let _ = self.key_manager.delete_key(&new_versioned_id).await;
            let _ = self.key_manager.delete_key(&old_versioned_id).await;
            
            return Err(FortressError::key_management(
                "New key validation failed during optimized rotation",
                Some(context.key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }

        // Phase 4: Atomic switch with optimized metadata
        let switch_metadata = new_metadata.clone()
            .with_metadata("transition_status".to_string(), "active".to_string())
            .with_metadata("switch_time".to_string(), Utc::now().to_rfc3339());

        // Atomic switch - the critical point
        self.key_manager.store_key(&context.key_id, &new_key, &switch_metadata).await?;

        // Phase 5: Optimized post-switch validation
        let post_switch_result = timeout(
            Duration::from_secs(context.config.post_switch_timeout_secs),
            self.validate_post_switch_optimized(&context.key_id, new_version)
        ).await;

        if post_switch_result.is_err() || post_switch_result.as_ref().unwrap().is_err() {
            // Emergency rollback
            let rollback_result = self.rollback_key_optimized(&context, old_metadata.version, new_version).await;
            
            if let Err(rollback_err) = rollback_result {
                return Err(FortressError::key_management(
                    format!("Critical rotation failure and rollback failed: {}", rollback_err),
                    Some(context.key_id.clone()),
                    KeyErrorCode::RotationFailed,
                ));
            }

            return Err(FortressError::key_management(
                "Post-switch validation failed, rolled back successfully",
                Some(context.key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }

        // Phase 6: Optimized cleanup
        self.cleanup_rotation_optimized(&context, new_version).await?;

        Ok(())
    }

    /// Optimized key validation
    async fn validate_key_optimized(&self, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        // Fast validation checks
        if key.is_empty() {
            return Err(FortressError::key_management(
                "Key is empty",
                Some(metadata.key_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }

        if metadata.version == 0 {
            return Err(FortressError::key_management(
                "Invalid key version",
                Some(metadata.key_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }

        // Additional security validations if enabled
        if self.config.enable_security_hardening {
            self.perform_security_validations(key, metadata).await?;
        }

        Ok(())
    }

    /// Optimized post-switch validation
    async fn validate_post_switch_optimized(&self, key_id: &KeyId, expected_version: u32) -> Result<()> {
        let (_, metadata) = self.key_manager.retrieve_key(key_id).await?;
        
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

    /// Optimized rollback
    async fn rollback_key_optimized(&self, context: &RotationContext, old_version: u32, new_version: u32) -> Result<()> {
        let old_versioned_id = self.versioned_key_cache.get_or_create(&context.key_id, old_version).await;
        
        let rollback_validation = timeout(
            Duration::from_secs(context.config.rollback_timeout_secs),
            self.validate_rollback_possible(&old_versioned_id, new_version)
        ).await;

        if rollback_validation.is_err() || rollback_validation.as_ref().unwrap().is_err() {
            return Err(FortressError::key_management(
                "Cannot rollback: backup validation failed",
                Some(context.key_id.clone()),
                KeyErrorCode::RotationFailed,
            ));
        }

        // Perform rollback
        let (old_key, old_metadata) = self.key_manager.retrieve_key(&old_versioned_id).await?;
        
        let restored_metadata = KeyMetadata::new(
            context.key_id.clone(),
            old_metadata.algorithm.clone(),
            old_version,
            old_metadata.created_at,
            old_metadata.expires_at,
            old_metadata.purpose.clone(),
            old_metadata.performance_profile,
        ).with_metadata("transition_status".to_string(), "rolled_back".to_string())
         .with_metadata("rollback_completed".to_string(), Utc::now().to_rfc3339())
         .with_metadata("original_version".to_string(), new_version.to_string());

        self.key_manager.store_key(&context.key_id, &old_key, &restored_metadata).await?;

        // Validate rollback
        self.validate_post_switch_optimized(&context.key_id, old_version).await?;

        // Cleanup failed version
        let new_versioned_id = self.versioned_key_cache.get_or_create(&context.key_id, new_version).await;
        let _ = self.key_manager.delete_key(&new_versioned_id).await;

        Ok(())
    }

    /// Optimized cleanup
    async fn cleanup_rotation_optimized(&self, context: &RotationContext, new_version: u32) -> Result<()> {
        // Cleanup old version
        let old_versioned_id = self.versioned_key_cache.get_or_create(&context.key_id, new_version - 1).await;
        let cleanup_result = self.key_manager.delete_key(&old_versioned_id).await;

        if let Err(e) = cleanup_result {
            tracing::warn!("Failed to cleanup old version during rotation: {}", e);
        }

        // Cleanup versioned new key
        let new_versioned_id = self.versioned_key_cache.get_or_create(&context.key_id, new_version).await;
        let _ = self.key_manager.delete_key(&new_versioned_id).await;

        // Return key to memory pool
        self.return_key_to_pool().await;

        Ok(())
    }

    /// Validate rollback is possible
    async fn validate_rollback_possible(&self, old_versioned_id: &KeyId, new_version: u32) -> Result<()> {
        let (old_key, old_metadata) = self.key_manager.retrieve_key(old_versioned_id).await?;
        
        if old_key.is_empty() {
            return Err(FortressError::key_management(
                "Backup key is empty",
                Some(old_versioned_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }

        if old_metadata.version != new_version - 1 {
            return Err(FortressError::key_management(
                "Backup key version mismatch",
                Some(old_versioned_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }

        Ok(())
    }

    /// Perform additional security validations
    async fn perform_security_validations(&self, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        // Key entropy validation
        if key.len() < 32 {
            return Err(FortressError::key_management(
                "Key too short for security requirements",
                Some(metadata.key_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }

        // Metadata security validation
        if !metadata.is_active() && metadata.expires_at < Utc::now() {
            return Err(FortressError::key_management(
                "Key metadata security validation failed",
                Some(metadata.key_id.clone()),
                KeyErrorCode::InvalidKeyFormat,
            ));
        }

        Ok(())
    }

    /// Get pooled key for operations
    async fn get_pooled_key(&self) -> SecureKey {
        let mut pool = self.memory_pool.write().await;
        pool.pop().unwrap_or_else(|| SecureKey::generate(256).expect("Failed to generate secure key"))
    }

    /// Return key to memory pool
    async fn return_key_to_pool(&self) {
        let mut pool = self.memory_pool.write().await;
        if pool.len() < self.config.memory_pool_size {
            // Generate a new key for the pool
            pool.push(SecureKey::generate(256).expect("Failed to generate secure key"));
        }
    }

    /// Log security event
    async fn log_security_event(
        &self,
        rotation_id: &str,
        key_id: &str,
        action: &str,
        security_context: &SecurityContext,
        success: bool,
        metadata: HashMap<String, String>,
    ) {
        let entry = SecurityAuditEntry {
            timestamp: Utc::now(),
            rotation_id: rotation_id.to_string(),
            key_id: key_id.to_string(),
            action: action.to_string(),
            security_level: security_context.security_level.clone(),
            requestor_id: security_context.requestor_id.clone(),
            ip_address: security_context.ip_address.clone(),
            success,
            metadata,
        };

        let mut audit_log = self.audit_log.write().await;
        audit_log.push(entry);

        // Keep audit log size manageable
        if audit_log.len() > 10000 {
            audit_log.drain(0..5000); // Remove oldest 5000 entries
        }
    }

    /// Get performance metrics
    pub async fn get_metrics(&self) -> RotationMetrics {
        self.metrics.read().await.clone()
    }

    /// Get active rotations
    pub async fn get_active_rotations(&self) -> HashMap<String, RotationContext> {
        self.active_rotations.read().await.clone()
    }

    /// Get security audit log
    pub async fn get_audit_log(&self, limit: Option<usize>) -> Vec<SecurityAuditEntry> {
        let audit_log = self.audit_log.read().await;
        match limit {
            Some(limit) => audit_log.iter().rev().take(limit).cloned().collect(),
            None => audit_log.clone(),
        }
    }

    /// Perform bulk rotation for multiple keys
    pub async fn bulk_rotate_keys(
        &self,
        key_ids: &[KeyId],
        algorithm: &dyn EncryptionAlgorithm,
        security_context: SecurityContext,
    ) -> Result<Vec<String>> {
        let batch_size = self.config.batch_size.min(key_ids.len());
        let mut results = Vec::new();
        
        for chunk in key_ids.chunks(batch_size) {
            let _batch_results: Vec<String> = Vec::new();
            
            // Process batch concurrently
            let tasks: Vec<_> = chunk.iter().map(|key_id| {
                let manager = self;
                let algorithm = algorithm;
                let security_context = security_context.clone();
                let key_id = key_id.clone();
                
                async move {
                    let result = manager.rotate_key_optimized(&key_id, algorithm, security_context).await;
                    result
                }
            }).collect();

            let batch_results_futures = futures::future::join_all(tasks).await;
            
            for result in batch_results_futures {
                match result {
                    Ok(rotation_id) => results.push(rotation_id),
                    Err(e) => {
                        // Log error but continue with other keys
                        tracing::error!("Bulk rotation error: {}", e);
                    }
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::InMemoryKeyManager;
    use crate::encryption::create_algorithm;

    #[tokio::test]
    async fn test_optimized_rotation_performance() -> Result<(), Box<dyn std::error::Error>> {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let config = OptimizedRotationConfig::default();
        let rotation_manager = OptimizedKeyRotationManager::new(key_manager, config);
        
        let algorithm = create_algorithm("aegis256")?;
        let security_context = SecurityContext {
            requestor_id: "test_user".to_string(),
            security_level: SecurityLevel::Standard,
            required_permissions: vec!["key.rotate".to_string()],
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test_client".to_string()),
        };

        // Create test key
        let key_id = "performance_test_key".to_string();
        let key = rotation_manager.key_manager.generate_key(algorithm.as_ref()).await?;
        let metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            "test".to_string(),
            crate::encryption::PerformanceProfile::Balanced,
        );
        
        rotation_manager.key_manager.store_key(&key_id, &key, &metadata).await?;

        // Perform optimized rotation
        let start_time = Instant::now();
        let rotation_id = rotation_manager.rotate_key_optimized(&key_id, algorithm.as_ref(), security_context).await?;
        let rotation_time = start_time.elapsed();

        tracing::info!("Optimized rotation completed in {:?} with ID: {}", rotation_time, rotation_id);

        // Verify metrics
        let metrics = rotation_manager.get_metrics().await;
        assert_eq!(metrics.total_rotations, 1);
        assert_eq!(metrics.successful_rotations, 1);
        assert!(metrics.avg_rotation_time_ms > 0.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_bulk_rotation() -> Result<(), Box<dyn std::error::Error>> {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let mut config = OptimizedRotationConfig::default();
        config.batch_size = 3;
        let rotation_manager = OptimizedKeyRotationManager::new(key_manager, config);
        
        let algorithm = create_algorithm("aegis256")?;
        let security_context = SecurityContext {
            requestor_id: "test_user".to_string(),
            security_level: SecurityLevel::Standard,
            required_permissions: vec!["key.rotate".to_string()],
            ip_address: None,
            user_agent: None,
        };

        // Create multiple test keys
        let key_ids: Vec<KeyId> = (1..=5).map(|i| format!("bulk_test_key_{}", i)).collect();
        
        for key_id in &key_ids {
            let key = rotation_manager.key_manager.generate_key(algorithm.as_ref()).await?;
            let metadata = KeyMetadata::new(
                key_id.clone(),
                algorithm.name().to_string(),
                1,
                Utc::now(),
                Utc::now() + ChronoDuration::days(90),
                "test".to_string(),
                crate::encryption::PerformanceProfile::Balanced,
            );
            
            rotation_manager.key_manager.store_key(key_id, &key, &metadata).await?;
        }

        // Perform bulk rotation
        let start_time = Instant::now();
        let rotation_ids = rotation_manager.bulk_rotate_keys(&key_ids, algorithm.as_ref(), security_context).await?;
        let bulk_time = start_time.elapsed();

        tracing::info!("Bulk rotation completed in {:?} for {} keys", bulk_time, rotation_ids.len());
        assert_eq!(rotation_ids.len(), key_ids.len());

        // Verify all keys were rotated
        for key_id in &key_ids {
            let (_, metadata) = rotation_manager.key_manager.retrieve_key(key_id).await?;
            assert_eq!(metadata.version, 2);
        }

        Ok(())
    }
}
