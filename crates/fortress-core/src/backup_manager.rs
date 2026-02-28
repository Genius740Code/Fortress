//! Default backup manager implementation
//!
//! This module provides the default implementation of the BackupManager trait
//! with support for encryption, compression, and parallel processing.

use super::*;
use crate::storage::StorageBackend;
use crate::prelude::*;
use crate::backup::{BackupConfig, BackupStrategy, RetentionPolicy, VerificationLevel, BackupMetadata, BackupManifest, BackupItem, RestoreStatus, RestoreOperationStatus, BackupStorageStats};
use crate::backup::utils;
use crate::error::StorageErrorCode;
use chrono::Utc;
use sha2::Digest;
use std::sync::Arc;
use futures::stream::{self, StreamExt};

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
