//! Simple backup manager implementation for testing
//!
//! This is a simplified version to get the system compiling.

use crate::storage::StorageBackend;
use crate::backup::{RetentionPolicy as BackupRetentionPolicy, utils, BackupManager, BackupItem, BackupStrategy, RestoreStatus};
use crate::error::{FortressError, StorageErrorCode, Result};
use crate::backup::{BackupConfig, BackupMetadata, BackupManifest, VerificationLevel, BackupStorageStats, RestoreOperationStatus};
use chrono::Utc;
use std::sync::Arc;

/// Simple backup manager for testing
#[derive(Debug)]
pub struct SimpleBackupManager {
    storage: Arc<dyn StorageBackend>,
}

impl SimpleBackupManager {
    /// Create a new simple backup manager
    /// 
    /// # Arguments
    /// 
    /// * `storage` - The storage backend to use for backups
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }
}

impl BackupManager for SimpleBackupManager {
    fn create_backup<'a>(
        &'a self,
        source_storage: &'a dyn StorageBackend,
        _config: &'a BackupConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackupMetadata>> + Send + 'a>> {
        Box::pin(async move {
            let backup_id = utils::generate_backup_id();
            let keys = source_storage.list_prefix("").await?;
            let mut total_size = 0u64;
            let mut items = Vec::new();

            for key in keys {
                if let Some(data) = source_storage.get(&key).await? {
                    let backup_key = format!("{}/{}", backup_id, key);
                    self.storage.put(&backup_key, &data).await?;
                    
                    let item = BackupItem {
                        original_key: key.clone(),
                        backup_key,
                        size: data.len() as u64,
                        original_checksum: utils::calculate_checksum(&data),
                        backup_checksum: utils::calculate_checksum(&data),
                        backed_up_at: Utc::now(),
                        encrypted: false,
                        compressed: false,
                    };
                    total_size += item.size;
                    items.push(item);
                }
            }

            let metadata = BackupMetadata {
                backup_id: backup_id.clone(),
                strategy: BackupStrategy::Full,
                created_at: Utc::now(),
                total_size,
                item_count: items.len() as u64,
                encryption_algorithm: None,
                compression_algorithm: None,
                manifest_checksum: String::new(),
                fortress_version: crate::VERSION.to_string(),
                metadata: std::collections::HashMap::new(),
            };

            // Save manifest
            let manifest = BackupManifest { metadata: metadata.clone(), items };
            let manifest_data = serde_json::to_vec(&manifest)
                .map_err(|e| FortressError::storage(
                    format!("Failed to serialize manifest: {}", e),
                    "backup".to_string(),
                    StorageErrorCode::InvalidOperation,
                ))?;
            
            let manifest_key = format!("{}/manifest.json", backup_id);
            self.storage.put(&manifest_key, &manifest_data).await?;

            Ok(metadata)
        })
    }

    fn restore_backup<'a>(
        &'a self,
        backup_id: &'a str,
        target_storage: &'a dyn StorageBackend,
        _config: &'a BackupConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<RestoreStatus>> + Send + 'a>> {
        Box::pin(async move {
            let manifest_key = format!("{}/manifest.json", backup_id);
            let manifest_data = self.storage.get(&manifest_key).await?
                .ok_or_else(|| FortressError::storage(
                    "Backup manifest not found".to_string(),
                    "backup".to_string(),
                    StorageErrorCode::NotFound,
                ))?;

            let manifest: BackupManifest = serde_json::from_slice(&manifest_data)
                .map_err(|e| FortressError::storage(
                    format!("Failed to deserialize manifest: {}", e),
                    "backup".to_string(),
                    StorageErrorCode::CorruptedData,
                ))?;

            let mut items_restored = 0u64;
            let items = manifest.items.clone();
            for item in items {
                if let Some(data) = self.storage.get(&item.backup_key).await? {
                    target_storage.put(&item.original_key, &data).await?;
                    items_restored += 1;
                }
            }

            let total_items = manifest.items.len() as u64;
            Ok(RestoreStatus {
                restore_id: utils::generate_restore_id(),
                backup_id: backup_id.to_string(),
                status: RestoreOperationStatus::Completed,
                progress_percentage: 100.0,
                items_restored,
                total_items,
                started_at: Utc::now(),
                estimated_completion: None,
                errors: Vec::new(),
            })
        })
    }

    fn list_backups<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<BackupMetadata>>> + Send + 'a>> {
        Box::pin(async move {
            let keys = self.storage.list_prefix("backup_").await?;
            let mut backups = Vec::new();

            for key in keys {
                if key.ends_with("/manifest.json") {
                    let backup_id = key.trim_end_matches("/manifest.json");
                    if let Some(metadata) = self.get_backup_metadata(backup_id).await.unwrap() {
                        backups.push(metadata);
                    }
                }
            }

            Ok(backups)
        })
    }

    fn get_backup_metadata<'a>(
        &'a self,
        backup_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<BackupMetadata>>> + Send + 'a>> {
        Box::pin(async move {
            let manifest_key = format!("{}/manifest.json", backup_id);
            if let Some(manifest_data) = self.storage.get(&manifest_key).await? {
                let manifest: BackupManifest = serde_json::from_slice(&manifest_data)
                    .map_err(|_| FortressError::storage(
                        "Corrupted manifest".to_string(),
                        "backup".to_string(),
                        StorageErrorCode::CorruptedData,
                    ))?;
                Ok(Some(manifest.metadata))
            } else {
                Ok(None)
            }
        })
    }

    fn delete_backup<'a>(
        &'a self,
        backup_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let keys = self.storage.list_prefix(&format!("{}/", backup_id)).await?;
            for key in keys {
                self.storage.delete(&key).await?;
            }
            Ok(())
        })
    }

    fn verify_backup<'a>(
        &'a self,
        backup_id: &'a str,
        _level: VerificationLevel,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            let manifest_key = format!("{}/manifest.json", backup_id);
            if let Some(manifest_data) = self.storage.get(&manifest_key).await? {
                let manifest: BackupManifest = serde_json::from_slice(&manifest_data)
                    .map_err(|_| FortressError::storage(
                        "Corrupted manifest".to_string(),
                        "backup".to_string(),
                        StorageErrorCode::CorruptedData,
                    ))?;
                
                // Verify all items exist and have correct checksums
                for item in manifest.items {
                    if let Some(data) = self.storage.get(&item.backup_key).await? {
                        if utils::calculate_checksum(&data) != item.backup_checksum {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                }
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    fn cleanup_old_backups<'a>(
        &'a self,
        _policy: &'a BackupRetentionPolicy,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u32>> + Send + 'a>> {
        Box::pin(async move {
            // Simple implementation - delete all backups for now
            let backups = self.list_backups().await?;
            let mut deleted = 0;
            for backup in backups {
                self.delete_backup(&backup.backup_id).await?;
                deleted += 1;
            }
            Ok(deleted)
        })
    }

    fn get_storage_stats<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<BackupStorageStats>> + Send + 'a>> {
        Box::pin(async move {
            let backups = self.list_backups().await?;
            let stats = BackupStorageStats {
                total_backups: backups.len() as u64,
                total_storage_used: backups.iter().map(|b| b.total_size).sum(),
                full_backup_storage: backups.iter().map(|b| b.total_size).sum(),
                incremental_backup_storage: 0,
                differential_backup_storage: 0,
                oldest_backup: backups.iter().map(|b| b.created_at).min(),
                newest_backup: backups.iter().map(|b| b.created_at).max(),
                average_backup_size: if backups.is_empty() { 0 } else { 
                    backups.iter().map(|b| b.total_size).sum::<u64>() / backups.len() as u64 
                },
            };
            Ok(stats)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;

    #[tokio::test]
    async fn test_simple_backup() {
        let source = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let target = Arc::new(InMemoryStorage::new());

        // Add test data
        source.put("test.txt", b"test data").await.unwrap();

        let manager = SimpleBackupManager::new(backup_storage.clone());
        let config = BackupConfig::default();

        // Create backup
        let backup = manager.create_backup(&*source, &config).await.unwrap();
        assert_eq!(backup.item_count, 1);

        // Restore backup
        let status = manager.restore_backup(&backup.backup_id, &*target, &config).await.unwrap();
        assert!(matches!(status.status, RestoreOperationStatus::Completed));

        // Verify restored data
        let restored = target.get("test.txt").await.unwrap();
        assert_eq!(restored, Some(b"test data".to_vec()));
    }
}
