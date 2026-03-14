//! Default backup manager implementation
//!
//! This module provides the default implementation of the BackupManager trait
//! with support for encryption, compression, and parallel processing.

use crate::backup::{
    BackupManager, BackupConfig, BackupStrategy, RetentionPolicy, VerificationLevel, BackupMetadata, BackupManifest, BackupItem,
    RestoreStatus, RestoreOperationStatus, BackupStorageStats,
    ConflictResolution, VerificationResult, VerificationStatus, BackupSchedule, ScheduledRunResult,
    CrossRegionConfig, ReplicationStrategy, ReplicationResult,
};
use crate::storage::StorageBackend;
use crate::error::{FortressError, Result};
use crate::backup::utils;
use crate::error::StorageErrorCode;
use chrono::{Utc, DateTime};
use sha2::Digest;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use futures::stream::StreamExt;
use async_trait::async_trait;

/// Default backup manager implementation
#[derive(Debug)]
pub struct DefaultBackupManager {
    /// Storage backend for backup data
    backup_storage: Arc<dyn StorageBackend>,
    /// Encryption algorithm (optional)
    encryption: Option<Arc<dyn crate::encryption::EncryptionAlgorithm>>,
    /// Backup configuration
    config: Arc<RwLock<BackupConfig>>,
    /// Semaphore for limiting parallel operations
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl DefaultBackupManager {
    /// Create a new backup manager
    pub fn new(
        backup_storage: Arc<dyn StorageBackend>,
        encryption: Option<Arc<dyn crate::encryption::EncryptionAlgorithm>>,
        config: BackupConfig,
    ) -> Result<Self> {
        // Validate configuration
        utils::validate_backup_config(&config)?;

        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            config.parallel_settings.max_workers as usize
        ));

        Ok(Self {
            backup_storage,
            encryption,
            config: Arc::new(RwLock::new(config)),
            semaphore,
        })
    }

    /// Get current configuration
    async fn get_config(&self) -> BackupConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    async fn update_config(&self, config: BackupConfig) -> Result<()> {
        utils::validate_backup_config(&config)?;
        *self.config.write().await = config;
        Ok(())
    }

    /// Process a single backup item
    async fn process_backup_item(
        &self,
        original_key: String,
        data: Vec<u8>,
        backup_id: &str,
        config: &BackupConfig,
    ) -> Result<BackupItem> {
        let backup_key = format!("{}/{}", backup_id, original_key);
        let mut processed_data = data;
        let mut encrypted = false;
        let mut compressed = false;

        // Calculate original checksum
        let original_checksum = utils::calculate_checksum(&processed_data);

        // Apply compression if configured
        if let Some(_compression_algo) = &config.compression_algorithm {
            processed_data = utils::compress_data(&processed_data)?;
            compressed = true;
        }

        // Apply encryption if configured
        if let Some(encryption) = &self.encryption {
            // Generate encryption key for this backup item
            let encryption_key = self.generate_backup_item_key(backup_id, &original_key)?;
            
            processed_data = encryption.encrypt(&processed_data, &encryption_key)?;
            encrypted = true;
        }

        // Calculate backup checksum
        let backup_checksum = utils::calculate_checksum(&processed_data);

        // Store the processed data
        self.backup_storage.put(&backup_key, &processed_data).await?;

        Ok(BackupItem {
            original_key,
            backup_key,
            size: processed_data.len() as u64,
            original_checksum,
            backup_checksum,
            backed_up_at: Utc::now(),
            encrypted,
            compressed,
        })
    }

    /// Generate encryption key for a backup item
    fn generate_backup_item_key(&self, backup_id: &str, original_key: &str) -> Result<Vec<u8>> {
        // Derive a key from the backup ID and original key
        let key_material = format!("{}:{}", backup_id, original_key);
        let mut hasher = sha2::Sha256::new();
        hasher.update(key_material.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    /// Backup a single key
    async fn backup_single_key(
        &self,
        source_storage: &dyn StorageBackend,
        key: &str,
        backup_id: &str,
        config: &BackupConfig,
    ) -> Result<BackupItem> {
        let data = source_storage.get(key).await?
            .ok_or_else(|| FortressError::storage(
                format!("Key not found: {}", key),
                "backup".to_string(),
                StorageErrorCode::NotFound,
            ))?;
        
        self.process_backup_item(key.to_string(), data, backup_id, config).await
    }

    /// Get changed keys since a backup
    async fn get_changed_keys_since_backup(
        &self,
        source_storage: &dyn StorageBackend,
        base_backup: &BackupMetadata,
    ) -> Result<Vec<String>> {
        let all_keys = source_storage.list_prefix("").await?;
        let mut changed_keys = Vec::new();
        
        // Load base backup manifest to get item metadata
        let base_manifest = self.load_manifest(&base_backup.backup_id).await?;
        let base_items: std::collections::HashMap<String, &BackupItem> = base_manifest
            .items
            .iter()
            .map(|item| (item.original_key.clone(), item))
            .collect();
        
        for key in all_keys {
            let current_data = source_storage.get(&key).await?;
            let current_checksum = current_data
                .as_ref()
                .map(|data| utils::calculate_checksum(data))
                .unwrap_or_else(|| "deleted".to_string());
            
            match base_items.get(&key) {
                Some(base_item) => {
                    // Key existed in base backup, check if changed
                    if current_checksum != base_item.original_checksum {
                        changed_keys.push(key);
                    }
                }
                None => {
                    // New key since base backup
                    changed_keys.push(key);
                }
            }
        }
        
        // Also check for deleted keys (optional - could be tracked separately)
        for base_key in base_items.keys() {
            if !source_storage.exists(base_key).await? {
                // Key was deleted - could be included in backup as deletion marker
                // For now, we'll skip deleted keys but this could be enhanced
            }
        }
        
        Ok(changed_keys)
    }

    /// Get point-in-time backup closest to target timestamp
    async fn get_point_in_time_backup(&self, target_time: DateTime<Utc>) -> Result<Option<BackupMetadata>> {
        let backups = self.list_backups().await?;
        
        // Find backup closest to target time (before or at the target)
        let closest_backup = backups
            .into_iter()
            .filter(|backup| backup.created_at <= target_time)
            .min_by(|a, b| {
                // Prefer backup with creation time closest to target
                let a_diff = (target_time - a.created_at).abs();
                let b_diff = (target_time - b.created_at).abs();
                a_diff.cmp(&b_diff)
            });
        
        Ok(closest_backup)
    }

    /// Restore to point-in-time by applying incremental backups
    async fn restore_to_point_in_time(
        &self,
        target_time: DateTime<Utc>,
        target_storage: &dyn StorageBackend,
        config: &BackupConfig,
    ) -> Result<RestoreStatus> {
        let restore_id = utils::generate_restore_id();
        let start_time = Utc::now();
        
        // Find the base full backup before target time
        let backups = self.list_backups().await?;
        let mut full_backups: Vec<_> = backups
            .iter()
            .filter(|backup| matches!(backup.strategy, BackupStrategy::Full))
            .filter(|backup| backup.created_at <= target_time)
            .collect();
        
        full_backups.sort_by(|a, b| b.created_at.cmp(&a.created_at)); // Most recent first
        
        let base_backup = full_backups
            .first()
            .ok_or_else(|| FortressError::storage(
                "No full backup found before target time".to_string(),
                "point_in_time_restore".to_string(),
                StorageErrorCode::NotFound,
            ))?;
        
        // Get all incremental backups between base backup and target time
        let mut incremental_backups: Vec<_> = backups
            .iter()
            .filter(|backup| {
                matches!(backup.strategy, BackupStrategy::Incremental { .. }) &&
                backup.created_at > base_backup.created_at &&
                backup.created_at <= target_time
            })
            .collect();
        
        incremental_backups.sort_by(|a, b| a.created_at.cmp(&b.created_at)); // Chronological order
        
        // Start with full backup restore
        let mut restore_status = self.restore_backup(
            &base_backup.backup_id,
            target_storage,
            config,
        ).await?;
        
        if !matches!(restore_status.status, RestoreOperationStatus::Completed) {
            return Ok(restore_status);
        }
        
        // Apply incremental backups in order
        let mut total_items = restore_status.total_items;
        let mut items_restored = restore_status.items_restored;
        let mut errors = restore_status.errors;
        
        for inc_backup in incremental_backups {
            let inc_restore_status = self.restore_backup(
                &inc_backup.backup_id,
                target_storage,
                config,
            ).await?;
            
            items_restored += inc_restore_status.items_restored;
            errors.extend(inc_restore_status.errors);
            
            if !matches!(inc_restore_status.status, RestoreOperationStatus::Completed) {
                break; // Stop on first failure
            }
        }
        
        Ok(RestoreStatus {
            restore_id,
            backup_id: format!("point_in_time_{}", target_time.timestamp()),
            status: if errors.is_empty() {
                RestoreOperationStatus::Completed
            } else {
                RestoreOperationStatus::Completed // Partial success
            },
            progress_percentage: 100.0,
            items_restored,
            total_items,
            started_at: start_time,
            estimated_completion: Some(Utc::now()),
            errors,
        })
    }

    /// Replicate backup to cross-region storage
    async fn replicate_backup_cross_region(
        &self,
        backup_id: &str,
        target_storage: &dyn StorageBackend,
    ) -> Result<()> {
        let manifest = self.load_manifest(backup_id).await?;
        
        // Replicate manifest
        let manifest_key = format!("{}/manifest.json", backup_id);
        let manifest_data = self.backup_storage.get(&manifest_key).await?
            .ok_or_else(|| FortressError::storage(
                format!("Backup manifest not found: {}", backup_id),
                "cross_region_replication".to_string(),
                StorageErrorCode::NotFound,
            ))?;
        
        target_storage.put(&manifest_key, &manifest_data).await?;
        
        // Replicate all backup items
        for item in manifest.items {
            let backup_data = self.backup_storage.get(&item.backup_key).await?
                .ok_or_else(|| FortressError::storage(
                    format!("Backup item not found: {}", item.backup_key),
                    "cross_region_replication".to_string(),
                    StorageErrorCode::NotFound,
                ))?;
            
            target_storage.put(&item.backup_key, &backup_data).await?;
        }
        
        Ok(())
    }

    /// Enhanced verification with integrity checks
    async fn verify_backup_comprehensive(&self, backup_id: &str) -> Result<VerificationResult> {
        let manifest = self.load_manifest(backup_id).await?;
        let mut result = VerificationResult {
            backup_id: backup_id.to_string(),
            verified_at: Utc::now(),
            manifest_valid: false,
            items_verified: 0,
            items_total: manifest.items.len(),
            corrupted_items: Vec::new(),
            missing_items: Vec::new(),
            encryption_valid: true,
            compression_valid: true,
            overall_status: VerificationStatus::Failed,
        };
        
        // Verify manifest checksum
        let manifest_data = serde_json::to_vec(&manifest)
            .map_err(|e| FortressError::storage(
                format!("Failed to serialize manifest for verification: {}", e),
                "backup_verification".to_string(),
                StorageErrorCode::InvalidOperation,
            ))?;
        
        let calculated_checksum = utils::calculate_checksum(&manifest_data);
        result.manifest_valid = calculated_checksum == manifest.metadata.manifest_checksum;
        
        if !result.manifest_valid {
            return Ok(result);
        }
        
        // Verify each item
        for item in &manifest.items {
            match self.backup_storage.get(&item.backup_key).await {
                Ok(Some(backup_data)) => {
                    // Verify backup checksum
                    if utils::verify_checksum(&backup_data, &item.backup_checksum) {
                        result.items_verified += 1;
                        
                        // If encrypted, verify decryption works
                        if item.encrypted {
                            if let Some(encryption) = &self.encryption {
                                let encryption_key = self.generate_backup_item_key(
                                    &item.backup_key.split('/').next().unwrap_or("unknown"),
                                    &item.original_key,
                                )?;
                                
                                match encryption.decrypt(&backup_data, &encryption_key) {
                                    Ok(decrypted_data) => {
                                        // Verify original checksum
                                        if !utils::verify_checksum(&decrypted_data, &item.original_checksum) {
                                            result.encryption_valid = false;
                                            result.corrupted_items.push(item.original_key.clone());
                                        }
                                        
                                        // If compressed, verify decompression
                                        if item.compressed {
                                            match utils::decompress_data(&decrypted_data) {
                                                Ok(_) => {}, // Decompression successful
                                                Err(_) => {
                                                    result.compression_valid = false;
                                                    result.corrupted_items.push(item.original_key.clone());
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        result.encryption_valid = false;
                                        result.corrupted_items.push(item.original_key.clone());
                                    }
                                }
                            }
                        } else if item.compressed {
                            // Verify compression without encryption
                            match utils::decompress_data(&backup_data) {
                                Ok(decompressed_data) => {
                                    if !utils::verify_checksum(&decompressed_data, &item.original_checksum) {
                                        result.compression_valid = false;
                                        result.corrupted_items.push(item.original_key.clone());
                                    }
                                }
                                Err(_) => {
                                    result.compression_valid = false;
                                    result.corrupted_items.push(item.original_key.clone());
                                }
                            }
                        }
                    } else {
                        result.corrupted_items.push(item.original_key.clone());
                    }
                }
                Ok(None) => {
                    result.missing_items.push(item.original_key.clone());
                }
                Err(e) => {
                    result.missing_items.push(item.original_key.clone());
                }
            }
        }
        
        // Determine overall status
        result.overall_status = if result.manifest_valid && 
            result.corrupted_items.is_empty() && 
            result.missing_items.is_empty() &&
            result.encryption_valid &&
            result.compression_valid {
            VerificationStatus::Passed
        } else if result.corrupted_items.len() > result.items_total / 2 {
            VerificationStatus::Failed
        } else {
            VerificationStatus::Warning
        };
        
        Ok(result)
    }

    /// Restore a single backup item
    async fn restore_backup_item(
        &self,
        item: &BackupItem,
        target_storage: &dyn StorageBackend,
        config: &BackupConfig,
    ) -> Result<()> {
        // Check for conflicts
        if target_storage.exists(&item.original_key).await? {
            match config.conflict_resolution {
                crate::backup::ConflictResolution::Skip => return Ok(()),
                crate::backup::ConflictResolution::Fail => {
                    return Err(FortressError::storage(
                        format!("Conflict detected for key: {}", item.original_key),
                        "backup_restore".to_string(),
                        StorageErrorCode::InvalidOperation,
                    ));
                }
                crate::backup::ConflictResolution::BackupAndOverwrite => {
                    // Create backup of existing item
                    let backup_key = format!("rollback_backup_{}", item.original_key);
                    if let Some(existing_data) = target_storage.get(&item.original_key).await? {
                        target_storage.put(&backup_key, &existing_data).await?;
                    }
                }
                crate::backup::ConflictResolution::Overwrite => {
                    // Continue with overwrite
                }
                crate::backup::ConflictResolution::Prompt => {
                    return Err(FortressError::storage(
                        "Prompt conflict resolution not available in automated mode".to_string(),
                        "backup_restore".to_string(),
                        StorageErrorCode::InvalidOperation,
                    ));
                }
            }
        }

        // Retrieve backup data
        let backup_data = self.backup_storage.get(&item.backup_key).await?
            .ok_or_else(|| FortressError::storage(
                format!("Backup item not found: {}", item.backup_key),
                "backup_restore".to_string(),
                StorageErrorCode::NotFound,
            ))?;

        let mut restored_data = backup_data;

        // Verify backup checksum
        if !utils::verify_checksum(&restored_data, &item.backup_checksum) {
            return Err(FortressError::storage(
                format!("Backup checksum mismatch for item: {}", item.original_key),
                "backup_restore".to_string(),
                StorageErrorCode::CorruptedData,
            ));
        }

        // Decrypt if encrypted
        if item.encrypted {
            if let Some(encryption) = &self.encryption {
                let encryption_key = self.generate_backup_item_key(
                    &item.backup_key.split('/').next().unwrap_or("unknown"),
                    &item.original_key,
                )?;
                
                restored_data = encryption.decrypt(&restored_data, &encryption_key)?;
            } else {
                return Err(FortressError::storage(
                    "Backup item is encrypted but no encryption algorithm available".to_string(),
                    "backup_restore".to_string(),
                    StorageErrorCode::InvalidOperation,
                ));
            }
        }

        // Decompress if compressed
        if item.compressed {
            restored_data = utils::decompress_data(&restored_data)?;
        }

        // Verify original checksum
        if !utils::verify_checksum(&restored_data, &item.original_checksum) {
            return Err(FortressError::storage(
                format!("Original checksum mismatch for item: {}", item.original_key),
                "backup_restore".to_string(),
                StorageErrorCode::CorruptedData,
            ));
        }

        // Store to target
        target_storage.put(&item.original_key, &restored_data).await?;

        Ok(())
    }

    /// Load backup manifest
    async fn load_manifest(&self, backup_id: &str) -> Result<BackupManifest> {
        let manifest_key = format!("{}/manifest.json", backup_id);
        let manifest_data = self.backup_storage.get(&manifest_key).await?
            .ok_or_else(|| FortressError::storage(
                format!("Backup manifest not found: {}", backup_id),
                "backup".to_string(),
                StorageErrorCode::NotFound,
            ))?;

        serde_json::from_slice(&manifest_data)
            .map_err(|e| FortressError::storage(
                format!("Failed to deserialize backup manifest: {}", e),
                "backup".to_string(),
                StorageErrorCode::CorruptedData,
            ))
    }

    /// Save backup manifest
    async fn save_manifest(&self, manifest: &BackupManifest) -> Result<()> {
        let manifest_key = format!("{}/manifest.json", manifest.metadata.backup_id);
        let manifest_data = serde_json::to_vec(manifest)
            .map_err(|e| FortressError::storage(
                format!("Failed to serialize backup manifest: {}", e),
                "backup".to_string(),
                StorageErrorCode::InvalidOperation,
            ))?;

        self.backup_storage.put(&manifest_key, &manifest_data).await?;
        Ok(())
    }
}

impl Clone for DefaultBackupManager {
    fn clone(&self) -> Self {
        Self {
            backup_storage: self.backup_storage.clone(),
            encryption: self.encryption.clone(),
            config: self.config.clone(),
            semaphore: self.semaphore.clone(),
        }
    }
}

#[async_trait]
impl BackupManager for DefaultBackupManager {
    fn create_backup<'a>(
        &'a self,
        source_storage: &'a dyn StorageBackend,
        config: &'a BackupConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackupMetadata>> + Send + 'a>> {
        Box::pin(async move {
            let backup_id = utils::generate_backup_id();
            let start_time = Utc::now();
            let mut items = Vec::new();
            let mut total_size = 0u64;

            // Determine keys to backup based on strategy
            let keys_to_backup = match &config.default_strategy {
                BackupStrategy::Full => {
                    utils::get_changed_keys(source_storage, None).await?
                }
                BackupStrategy::Incremental { base_backup_id } | 
                BackupStrategy::Differential { base_backup_id } => {
                    let base_metadata = self.get_backup_metadata(base_backup_id).await?
                        .ok_or_else(|| FortressError::storage(
                            format!("Base backup not found: {}", base_backup_id),
                            "backup".to_string(),
                            StorageErrorCode::NotFound,
                        ))?;
                    
                    // Get changed keys since base backup
                    self.get_changed_keys_since_backup(source_storage, &base_metadata).await?
                }
            };

            // Process each key in parallel if enabled
            if config.parallel_settings.enabled && keys_to_backup.len() > 1 {
                let stream = futures::stream::iter(keys_to_backup)
                    .map(|key| {
                        let manager = self.clone();
                        let backup_id = backup_id.clone();
                        let config = config.clone();
                        async move {
                            let permit = manager.semaphore.acquire().await.map_err(|e| FortressError::storage(
                                format!("Failed to acquire semaphore permit: {}", e),
                                "backup".to_string(),
                                StorageErrorCode::InvalidOperation,
                            ))?;
                            let result = manager.backup_single_key(source_storage, &key, &backup_id, &config).await;
                            drop(permit);
                            result
                        }
                    })
                    .buffer_unordered(config.parallel_settings.max_workers as usize);

                let backup_items = stream.collect::<Vec<_>>().await;
                
                for item_result in backup_items {
                    match item_result {
                        Ok(item) => {
                            total_size += item.size;
                            items.push(item);
                        }
                        Err(e) => {
                            return Err(FortressError::storage(
                                format!("Failed to backup key: {}", e),
                                "backup".to_string(),
                                StorageErrorCode::InvalidOperation,
                            ));
                        }
                    }
                }
            } else {
                // Sequential processing
                for key in keys_to_backup {
                    let item = self.backup_single_key(source_storage, &key, &backup_id, config).await?;
                    total_size += item.size;
                    items.push(item);
                }
            }

            // Create backup manifest
            let manifest = BackupManifest {
                metadata: BackupMetadata {
                    backup_id: backup_id.clone(),
                    strategy: config.default_strategy.clone(),
                    created_at: start_time,
                    total_size,
                    item_count: items.len() as u64,
                    encryption_algorithm: config.encryption_algorithm.clone(),
                    compression_algorithm: config.compression_algorithm.clone(),
                    manifest_checksum: String::new(), // Will be set below
                    fortress_version: env!("CARGO_PKG_VERSION").to_string(),
                    metadata: HashMap::new(),
                },
                items,
            };

            // Calculate and set manifest checksum
            let manifest_data = serde_json::to_vec(&manifest)
                .map_err(|e| FortressError::storage(
                    format!("Failed to serialize manifest: {}", e),
                    "backup".to_string(),
                    StorageErrorCode::InvalidOperation,
                ))?;
            
            let mut manifest_with_checksum = manifest;
            manifest_with_checksum.metadata.manifest_checksum = utils::calculate_checksum(&manifest_data);

            // Save manifest
            self.save_manifest(&manifest_with_checksum).await?;

            Ok(manifest_with_checksum.metadata)
        })
    }

    fn restore_backup<'a>(
        &'a self,
        backup_id: &'a str,
        target_storage: &'a dyn StorageBackend,
        config: &'a BackupConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<RestoreStatus>> + Send + 'a>> {
        Box::pin(async move {
            let restore_id = utils::generate_restore_id();
            let start_time = Utc::now();
            
            // Load backup manifest
            let manifest = self.load_manifest(backup_id).await?;
            let total_items = manifest.items.len() as u64;
            let mut items_restored = 0u64;
            let mut errors = Vec::new();

            // Process each item
            for (index, item) in manifest.items.iter().enumerate() {
                match self.restore_backup_item(item, target_storage, config).await {
                    Ok(()) => {
                        items_restored += 1;
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to restore item {}: {}", index, e);
                        errors.push(error_msg);
                        
                        // Continue with other items unless it's a critical error
                        if matches!(e, FortressError::Storage { .. }) {
                            continue;
                        } else {
                            break;
                        }
                    }
                }
            }

            let status = if errors.is_empty() {
                RestoreOperationStatus::Completed
            } else if items_restored == 0 {
                RestoreOperationStatus::Failed
            } else {
                RestoreOperationStatus::Completed // Partial success
            };

            Ok(RestoreStatus {
                restore_id,
                backup_id: backup_id.to_string(),
                status,
                progress_percentage: if total_items > 0 {
                    (items_restored as f32 / total_items as f32) * 100.0
                } else {
                    100.0
                },
                items_restored,
                total_items,
                started_at: start_time,
                estimated_completion: Some(Utc::now()),
                errors,
            })
        })
    }

    fn list_backups<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<BackupMetadata>>> + Send + 'a>> {
        Box::pin(async move {
            let backup_keys = self.backup_storage.list_prefix("").await?;
            let mut backups = Vec::new();

            for key in backup_keys {
                if key.ends_with("/manifest.json") {
                    let backup_id = key.strip_suffix("/manifest.json")
                        .unwrap_or("");
                    
                    if let Ok(Some(metadata)) = self.get_backup_metadata(backup_id).await {
                        backups.push(metadata);
                    }
                }
            }

            // Sort by creation time (newest first)
            backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(backups)
        })
    }

    fn get_backup_metadata<'a>(
        &'a self,
        backup_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<BackupMetadata>>> + Send + 'a>> {
        Box::pin(async move {
            match self.load_manifest(backup_id).await {
                Ok(manifest) => Ok(Some(manifest.metadata)),
                Err(FortressError::Storage { code: StorageErrorCode::NotFound, .. }) => Ok(None),
                Err(e) => Err(e),
            }
        })
    }

    fn delete_backup<'a>(
        &'a self,
        backup_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let manifest = self.load_manifest(backup_id).await?;
            
            // Delete all backup items
            for item in manifest.items {
                self.backup_storage.delete(&item.backup_key).await?;
            }
            
            // Delete manifest
            let manifest_key = format!("{}/manifest.json", backup_id);
            self.backup_storage.delete(&manifest_key).await?;
            
            Ok(())
        })
    }

    fn verify_backup<'a>(
        &'a self,
        backup_id: &'a str,
        level: VerificationLevel,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            let manifest = self.load_manifest(backup_id).await?;
            
            match level {
                VerificationLevel::None => Ok(true),
                VerificationLevel::Basic => {
                    // Verify manifest checksum
                    let manifest_data = serde_json::to_vec(&manifest)
                        .map_err(|e| FortressError::storage(
                            format!("Failed to serialize manifest for verification: {}", e),
                            "backup_verification".to_string(),
                            StorageErrorCode::InvalidOperation,
                        ))?;
                    
                    let calculated_checksum = utils::calculate_checksum(&manifest_data);
                    Ok(calculated_checksum == manifest.metadata.manifest_checksum)
                }
                VerificationLevel::Full => {
                    // Verify all item checksums
                    for item in &manifest.items {
                        let backup_data = self.backup_storage.get(&item.backup_key).await?
                            .ok_or_else(|| FortressError::storage(
                                format!("Backup item not found: {}", item.backup_key),
                                "backup_verification".to_string(),
                                StorageErrorCode::NotFound,
                            ))?;
                        
                        if !utils::verify_checksum(&backup_data, &item.backup_checksum) {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                VerificationLevel::Comprehensive => {
                    // Full verification + test restore to temporary storage
                    if !self.verify_backup(backup_id, VerificationLevel::Full).await? {
                        return Ok(false);
                    }
                    
                    // Test restore to in-memory storage
                    let test_storage = Arc::new(crate::storage::InMemoryStorage::new());
                    let config = BackupConfig::default();
                    
                    let restore_status = self.restore_backup(backup_id, &*test_storage, &config).await?;
                    
                    Ok(matches!(restore_status.status, RestoreOperationStatus::Completed))
                }
            }
        })
    }

    fn cleanup_old_backups<'a>(
        &'a self,
        policy: &'a RetentionPolicy,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u32>> + Send + 'a>> {
        Box::pin(async move {
            let backups = self.list_backups().await?;
            let mut deleted_count = 0u32;
            
            // Group backups by strategy
            let mut full_backups = Vec::new();
            let mut incremental_backups = Vec::new();
            let mut differential_backups = Vec::new();
            
            for backup in backups {
                match backup.strategy {
                    BackupStrategy::Full => full_backups.push(backup),
                    BackupStrategy::Incremental { .. } => incremental_backups.push(backup),
                    BackupStrategy::Differential { .. } => differential_backups.push(backup),
                }
            }
            
            // Sort by creation time (oldest first)
            full_backups.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            incremental_backups.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            differential_backups.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            
            let cutoff_date = Utc::now() - chrono::Duration::days(policy.max_age_days as i64);
            
            // Delete old full backups
            if full_backups.len() > policy.max_full_backups as usize {
                let to_delete = &full_backups[..full_backups.len() - policy.max_full_backups as usize];
                for backup in to_delete {
                    if backup.created_at < cutoff_date {
                        self.delete_backup(&backup.backup_id).await?;
                        deleted_count += 1;
                    }
                }
            }
            
            // Delete old incremental backups
            if incremental_backups.len() > policy.max_incremental_backups as usize {
                let to_delete = &incremental_backups[..incremental_backups.len() - policy.max_incremental_backups as usize];
                for backup in to_delete {
                    if backup.created_at < cutoff_date {
                        self.delete_backup(&backup.backup_id).await?;
                        deleted_count += 1;
                    }
                }
            }
            
            // Delete old differential backups
            for backup in &differential_backups {
                if backup.created_at < cutoff_date {
                    self.delete_backup(&backup.backup_id).await?;
                    deleted_count += 1;
                }
            }
            
            Ok(deleted_count)
        })
    }

    fn get_storage_stats<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackupStorageStats>> + Send + 'a>> {
        Box::pin(async move {
            let backups = self.list_backups().await?;
            
            if backups.is_empty() {
                return Ok(BackupStorageStats {
                    total_backups: 0,
                    total_storage_used: 0,
                    full_backup_storage: 0,
                    incremental_backup_storage: 0,
                    differential_backup_storage: 0,
                    oldest_backup: None,
                    newest_backup: None,
                    average_backup_size: 0,
                });
            }
            
            let mut stats = BackupStorageStats {
                total_backups: backups.len() as u64,
                total_storage_used: 0,
                full_backup_storage: 0,
                incremental_backup_storage: 0,
                differential_backup_storage: 0,
                oldest_backup: backups.last().map(|b| b.created_at),
                newest_backup: backups.first().map(|b| b.created_at),
                average_backup_size: 0,
            };
            
            for backup in &backups {
                stats.total_storage_used += backup.total_size;
                
                match backup.strategy {
                    BackupStrategy::Full => stats.full_backup_storage += backup.total_size,
                    BackupStrategy::Incremental { .. } => stats.incremental_backup_storage += backup.total_size,
                    BackupStrategy::Differential { .. } => stats.differential_backup_storage += backup.total_size,
                }
            }
            
            stats.average_backup_size = stats.total_storage_used / stats.total_backups;
            
            Ok(stats)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_backup_manager_creation() {
        let storage = Arc::new(InMemoryStorage::new());
        let config = BackupConfig::default();
        
        let manager = DefaultBackupManager::new(
            storage.clone(),
            None,
            config,
        );
        
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_backup_creation_full() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        
        // Add some test data
        source_storage.put("key1", b"data1").await.unwrap();
        source_storage.put("key2", b"data2").await.unwrap();
        
        let config = BackupConfig::default();
        let manager = DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap();
        
        let backup_metadata = manager.create_backup(&*source_storage, &manager.get_config().await).await.unwrap();
        
        assert_eq!(backup_metadata.item_count, 2);
        assert!(matches!(backup_metadata.strategy, BackupStrategy::Full));
    }

    #[tokio::test]
    async fn test_backup_restore() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let target_storage = Arc::new(InMemoryStorage::new());
        
        // Add test data
        source_storage.put("test_key", b"test_data").await.unwrap();
        
        let config = BackupConfig::default();
        let manager = DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap();
        
        // Create backup
        let backup_metadata = manager.create_backup(&*source_storage, &manager.get_config().await).await.unwrap();
        
        // Restore backup
        let restore_status = manager.restore_backup(
            &backup_metadata.backup_id,
            &*target_storage,
            &manager.get_config().await,
        ).await.unwrap();
        
        assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));
        assert_eq!(restore_status.items_restored, 1);
        
        // Verify restored data
        let restored_data = target_storage.get("test_key").await.unwrap();
        assert_eq!(restored_data, Some(b"test_data".to_vec()));
    }

    #[tokio::test]
    async fn test_backup_verification() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        
        source_storage.put("key1", b"data1").await.unwrap();
        
        let config = BackupConfig::default();
        let manager = DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap();
        
        let backup_metadata = manager.create_backup(&*source_storage, &manager.get_config().await).await.unwrap();
        
        // Test basic verification
        let is_valid = manager.verify_backup(&backup_metadata.backup_id, VerificationLevel::Basic).await.unwrap();
        assert!(is_valid);
        
        // Test full verification
        let is_valid = manager.verify_backup(&backup_metadata.backup_id, VerificationLevel::Full).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_backup_list_and_delete() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        
        source_storage.put("key1", b"data1").await.unwrap();
        
        let config = BackupConfig::default();
        let manager = DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap();
        
        // Create backup
        let backup_metadata = manager.create_backup(&*source_storage, &manager.get_config().await).await.unwrap();
        
        // List backups
        let backups = manager.list_backups().await.unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].backup_id, backup_metadata.backup_id);
        
        // Get backup metadata
        let metadata = manager.get_backup_metadata(&backup_metadata.backup_id).await.unwrap();
        assert!(metadata.is_some());
        assert_eq!(metadata.unwrap().backup_id, backup_metadata.backup_id);
        
        // Delete backup
        manager.delete_backup(&backup_metadata.backup_id).await.unwrap();
        
        // Verify deletion
        let backups = manager.list_backups().await.unwrap();
        assert_eq!(backups.len(), 0);
    }
}
