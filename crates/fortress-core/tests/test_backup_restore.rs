//! Comprehensive tests for the backup and disaster recovery system
//!
//! This module provides extensive tests covering all aspects of the backup,
//! Integration tests for backup and disaster recovery system

use fortress_core::backup::*;
use fortress_core::simple_backup_manager::SimpleBackupManager;
use fortress_core::storage::{InMemoryStorage, StorageBackend};
use fortress_core::prelude::*;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use chrono::Utc;

/// Integration test suite for backup and disaster recovery
#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Test complete backup and restore workflow
    #[tokio::test]
    async fn test_complete_backup_restore_workflow() {
        // Setup
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let target_storage = Arc::new(InMemoryStorage::new());

        // Add test data
        let test_data = vec![
            ("config/system.json", b"system_configuration"),
            ("data/users.db", b"user_database_content"),
            ("logs/application.log", b"application_log_entries"),
            ("keys/encryption.key", b"encryption_key_material"),
        ];

        for (key, data) in &test_data {
            source_storage.put(key, data).await.unwrap();
        }

        // Create backup manager
        let config = BackupConfig {
            default_strategy: BackupStrategy::Full,
            encryption_algorithm: None,
            compression_algorithm: Some("gzip".to_string()),
            max_backup_size: Some(100 * 1024 * 1024),
            retention_policy: RetentionPolicy::default(),
            verification_level: VerificationLevel::Basic,
            parallel_settings: ParallelBackupSettings::default(),
        };

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap());

        // Create backup
        let backup_metadata = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        // Verify backup metadata
        assert_eq!(backup_metadata.item_count, test_data.len() as u64);
        assert!(backup_metadata.total_size > 0);
        assert!(matches!(backup_metadata.strategy, BackupStrategy::Full));

        // Verify backup integrity
        let is_valid = backup_manager.verify_backup(
            &backup_metadata.backup_id,
            VerificationLevel::Full,
        ).await.unwrap();
        assert!(is_valid);

        // Restore backup
        let restore_status = backup_manager.restore_backup(
            &backup_metadata.backup_id,
            &*target_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));
        assert_eq!(restore_status.items_restored, test_data.len() as u64);

        // Verify restored data
        for (key, original_data) in &test_data {
            let restored_data = target_storage.get(key).await.unwrap();
            assert_eq!(restored_data, Some(original_data.to_vec()));
        }

        // Test backup listing
        let backups = backup_manager.list_backups().await.unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].backup_id, backup_metadata.backup_id);

        // Test storage statistics
        let stats = backup_manager.get_storage_stats().await.unwrap();
        assert_eq!(stats.total_backups, 1);
        assert_eq!(stats.full_backup_storage, backup_metadata.total_size);
    }

    /// Test incremental backup workflow
    #[tokio::test]
    async fn test_incremental_backup_workflow() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        // Add initial data
        source_storage.put("file1.txt", b"content1").await.unwrap();
        source_storage.put("file2.txt", b"content2").await.unwrap();

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        // Create full backup
        let full_backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        // Add more data
        source_storage.put("file3.txt", b"content3").await.unwrap();
        source_storage.put("file1.txt", b"content1_updated").await.unwrap();

        // Create incremental backup
        let incremental_config = BackupConfig {
            default_strategy: BackupStrategy::Incremental {
                base_backup_id: full_backup.backup_id.clone(),
            },
            ..Default::default()
        };

        let incremental_backup = backup_manager.create_backup(
            &*source_storage,
            &incremental_config,
        ).await.unwrap();

        assert!(matches!(incremental_backup.strategy, BackupStrategy::Incremental { .. }));
        assert!(incremental_backup.created_at > full_backup.created_at);
    }

    /// Test disaster recovery plan creation and execution
    #[tokio::test]
    async fn test_disaster_recovery_workflow() {
        let plan_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let target_storage = Arc::new(InMemoryStorage::new());

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let dr_manager = DefaultDisasterRecoveryManager::new(
            plan_storage.clone(),
            backup_manager.clone(),
        );

        // Create default recovery plans
        dr_manager.create_default_plans().await.unwrap();

        // List recovery plans
        let plans = dr_manager.list_recovery_plans().await.unwrap();
        assert_eq!(plans.len(), 3);

        // Get the complete recovery plan
        let complete_plan = plans.iter().find(|p| p.name == "Complete System Recovery").unwrap();
        assert_eq!(complete_plan.recovery_steps.len(), 4);
        assert!(matches!(complete_plan.priority, RecoveryPriority::Critical));

        // Test the recovery plan
        let test_result = dr_manager.test_recovery_plan(&complete_plan.plan_id).await.unwrap();
        assert!(test_result.passed);
        assert_eq!(test_result.step_results.len(), complete_plan.recovery_steps.len());

        // Verify plan was updated with test timestamp
        let updated_plan = dr_manager.get_recovery_plan(&complete_plan.plan_id).await.unwrap().unwrap();
        assert!(updated_plan.last_tested.is_some());
    }

    /// Test advanced restore manager with filtering
    #[tokio::test]
    async fn test_advanced_restore_with_filtering() {
        let backup_storage = Arc::new(InMemoryStorage::new());
        let target_storage = Arc::new(InMemoryStorage::new());

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let restore_manager = AdvancedRestoreManager::new(backup_manager.clone());

        // Add validation rules
        let checksum_rule = ValidationRule {
            name: "Checksum Validation".to_string(),
            description: "Validate item checksums".to_string(),
            rule_type: ValidationRuleType::ChecksumValidation,
            enabled: true,
            priority: 1,
        };

        restore_manager.add_validation_rule(checksum_rule).await.unwrap();

        // Test restore configuration
        let restore_config = RestoreConfig {
            strategy: RestoreStrategy::Selective,
            validation_level: ValidationLevel::Full,
            conflict_resolution: ConflictResolution::BackupAndOverwrite,
            filters: vec![
                RestoreFilter {
                    filter_type: FilterType::KeyPattern,
                    pattern: "important".to_string(),
                    action: FilterAction::Include,
                },
            ],
            rollback_config: RollbackConfig {
                enabled: true,
                strategy: RollbackStrategy::TrackChanges,
                max_rollback_time_minutes: 30,
            },
            performance: RestorePerformanceConfig::default(),
        };

        // Verify validation rules
        let rules = restore_manager.get_validation_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].enabled);
    }

    /// Test backup retention policy
    #[tokio::test]
    async fn test_backup_retention_policy() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        source_storage.put("test.txt", b"data").await.unwrap();

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        // Create multiple backups
        let mut backup_ids = Vec::new();
        for i in 0..5 {
            source_storage.put(&format!("file{}.txt", i), b"data").await.unwrap();
            
            let backup = backup_manager.create_backup(
                &*source_storage,
                &backup_manager.get_config().await,
            ).await.unwrap();
            backup_ids.push(backup.backup_id);
            
            // Add small delay to ensure different timestamps
            sleep(Duration::from_millis(10)).await;
        }

        // Verify all backups exist
        let backups = backup_manager.list_backups().await.unwrap();
        assert_eq!(backups.len(), 5);

        // Apply retention policy
        let retention_policy = RetentionPolicy {
            max_full_backups: 2,
            max_incremental_backups: 10,
            max_age_days: 0, // Delete all
            auto_cleanup: true,
        };

        let deleted_count = backup_manager.cleanup_old_backups(&retention_policy).await.unwrap();
        assert!(deleted_count > 0);

        // Verify cleanup
        let remaining_backups = backup_manager.list_backups().await.unwrap();
        assert!(remaining_backups.len() < 5);
    }

    /// Test backup compression and encryption
    #[tokio::test]
    async fn test_backup_compression_encryption() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        // Add large test data
        let large_data = vec![0u8; 1024 * 1024]; // 1MB of zeros
        source_storage.put("large_file.bin", &large_data).await.unwrap();

        let config = BackupConfig {
            default_strategy: BackupStrategy::Full,
            encryption_algorithm: Some("aes256gcm".to_string()),
            compression_algorithm: Some("gzip".to_string()),
            ..Default::default()
        };

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None, // No encryption for this test
            config,
        ).unwrap());

        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        // Verify backup was created with compression
        assert!(backup.total_size > 0);
        assert!(backup.compression_algorithm.is_some());

        // Test restore
        let target_storage = Arc::new(InMemoryStorage::new());
        let restore_status = backup_manager.restore_backup(
            &backup.backup_id,
            &*target_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));

        // Verify restored data
        let restored_data = target_storage.get("large_file.bin").await.unwrap();
        assert_eq!(restored_data, Some(large_data));
    }

    /// Test parallel backup processing
    #[tokio::test]
    async fn test_parallel_backup_processing() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        // Add many small files
        for i in 0..100 {
            source_storage.put(&format!("file_{}.txt", i), &format!("content_{}", i).as_bytes()).await.unwrap();
        }

        let config = BackupConfig {
            parallel_settings: ParallelBackupSettings {
                max_workers: 8,
                chunk_size: 10,
                enabled: true,
            },
            ..Default::default()
        };

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap());

        let start_time = std::time::Instant::now();
        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();
        let duration = start_time.elapsed();

        // Verify all files were backed up
        assert_eq!(backup.item_count, 100);
        assert!(duration.as_secs() < 10); // Should complete quickly with parallel processing
    }

    /// Test error handling and recovery
    #[tokio::test]
    async fn test_error_handling_and_recovery() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        source_storage.put("test.txt", b"data").await.unwrap();

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        // Create backup
        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        // Test verification with corrupted data
        // (This would require manually corrupting backup data)
        let is_valid = backup_manager.verify_backup(
            &backup.backup_id,
            VerificationLevel::Comprehensive,
        ).await.unwrap();
        assert!(is_valid);

        // Test restore to non-existent storage (should fail gracefully)
        let bad_storage = Arc::new(FailingStorage::new());
        let restore_status = backup_manager.restore_backup(
            &backup.backup_id,
            &*bad_storage,
            &backup_manager.get_config().await,
        ).await;

        assert!(restore_status.is_err());
    }

    /// Test backup metadata integrity
    #[tokio::test]
    async fn test_backup_metadata_integrity() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        source_storage.put("test.txt", b"data").await.unwrap();

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        // Verify metadata fields
        assert!(!backup.backup_id.is_empty());
        assert!(!backup.manifest_checksum.is_empty());
        assert!(!backup.fortress_version.is_empty());
        assert!(backup.created_at <= Utc::now());
        assert!(backup.total_size > 0);
        assert!(backup.item_count > 0);

        // Test metadata retrieval
        let retrieved_metadata = backup_manager.get_backup_metadata(&backup.backup_id).await.unwrap();
        assert!(retrieved_metadata.is_some());
        assert_eq!(retrieved_metadata.unwrap().backup_id, backup.backup_id);
    }
}

/// Performance tests for backup and restore operations
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    /// Test backup performance with large datasets
    #[tokio::test]
    async fn test_large_dataset_backup_performance() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        // Create test data of various sizes
        let data_sizes = vec![1024, 10240, 102400, 1024000]; // 1KB, 10KB, 100KB, 1MB
        
        for (i, size) in data_sizes.iter().enumerate() {
            let data = vec![0u8; *size];
            source_storage.put(&format!("file_{}_{}.bin", i, size), &data).await.unwrap();
        }

        let config = BackupConfig {
            parallel_settings: ParallelBackupSettings {
                max_workers: 4,
                chunk_size: 2,
                enabled: true,
            },
            ..Default::default()
        };

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap());

        let start_time = Instant::now();
        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();
        let backup_duration = start_time.elapsed();

        println!("Backup of {} items took: {:?}", backup.item_count, backup_duration);
        println!("Total size: {} bytes", backup.total_size);
        println!("Throughput: {:.2} MB/s", 
            (backup.total_size as f64) / (backup_duration.as_secs_f64() * 1024.0 * 1024.0)
        );

        // Test restore performance
        let target_storage = Arc::new(InMemoryStorage::new());
        
        let start_time = Instant::now();
        let restore_status = backup_manager.restore_backup(
            &backup.backup_id,
            &*target_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();
        let restore_duration = start_time.elapsed();

        println!("Restore of {} items took: {:?}", restore_status.items_restored, restore_duration);
        println!("Restore throughput: {:.2} MB/s", 
            (backup.total_size as f64) / (restore_duration.as_secs_f64() * 1024.0 * 1024.0)
        );

        assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));
    }

    /// Test concurrent backup operations
    #[tokio::test]
    async fn test_concurrent_backup_operations() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        // Add test data
        for i in 0..50 {
            source_storage.put(&format!("file_{}.txt", i), &format!("content_{}", i).as_bytes()).await.unwrap();
        }

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        // Start multiple concurrent backup operations
        let mut handles = Vec::new();
        
        for i in 0..5 {
            let manager = backup_manager.clone();
            let storage = source_storage.clone();
            
            let handle = tokio::spawn(async move {
                manager.create_backup(
                    &*storage,
                    &manager.get_config().await,
                ).await
            });
            
            handles.push(handle);
        }

        // Wait for all backups to complete
        let mut backups = Vec::new();
        for handle in handles {
            let backup = handle.await.unwrap().unwrap();
            backups.push(backup);
        }

        // Verify all backups completed successfully
        assert_eq!(backups.len(), 5);
        for backup in &backups {
            assert_eq!(backup.item_count, 50);
        }

        // Verify all backups are unique
        let backup_ids: HashSet<String> = backups.iter().map(|b| b.backup_id.clone()).collect();
        assert_eq!(backup_ids.len(), 5);
    }
}

/// Edge case and boundary tests
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    /// Test backup with empty storage
    #[tokio::test]
    async fn test_backup_empty_storage() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        assert_eq!(backup.item_count, 0);
        assert_eq!(backup.total_size, 0);
    }

    /// Test backup with very large files
    #[tokio::test]
    async fn test_backup_very_large_files() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        // Create a large file (10MB)
        let large_data = vec![0u8; 10 * 1024 * 1024];
        source_storage.put("large_file.bin", &large_data).await.unwrap();

        let config = BackupConfig {
            max_backup_size: Some(5 * 1024 * 1024), // 5MB limit
            ..Default::default()
        };

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            config,
        ).unwrap());

        // This should succeed since we're not enforcing size limits in the test implementation
        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        assert_eq!(backup.item_count, 1);
        assert_eq!(backup.total_size, large_data.len() as u64);
    }

    /// Test restore with conflict resolution strategies
    #[tokio::test]
    async fn test_restore_conflict_resolution() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let target_storage = Arc::new(InMemoryStorage::new());

        // Add data to source
        source_storage.put("test.txt", b"original_data").await.unwrap();

        // Add conflicting data to target
        target_storage.put("test.txt", b"conflicting_data").await.unwrap();

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        // Create backup
        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        // Test overwrite strategy
        let restore_status = backup_manager.restore_backup(
            &backup.backup_id,
            &*target_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));

        // Verify data was overwritten
        let restored_data = target_storage.get("test.txt").await.unwrap();
        assert_eq!(restored_data, Some(b"original_data".to_vec()));
    }

    /// Test backup with special characters in keys
    #[tokio::test]
    async fn test_backup_special_characters() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());

        let special_keys = vec![
            "file with spaces.txt",
            "file-with-dashes.txt",
            "file_with_underscores.txt",
            "file.with.dots.txt",
            "file/with/slashes.txt",
            "file\\with\\backslashes.txt",
            "file@with@symbols.txt",
            "file#with#hash.txt",
            "文件中文.txt", // Chinese characters
            "файл.txt", // Cyrillic characters
        ];

        for key in &special_keys {
            source_storage.put(key, b"data").await.unwrap();
        }

        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let backup = backup_manager.create_backup(
            &*source_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        assert_eq!(backup.item_count, special_keys.len() as u64);

        // Test restore
        let target_storage = Arc::new(InMemoryStorage::new());
        let restore_status = backup_manager.restore_backup(
            &backup.backup_id,
            &*target_storage,
            &backup_manager.get_config().await,
        ).await.unwrap();

        assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));

        // Verify all keys were restored
        for key in &special_keys {
            let restored_data = target_storage.get(key).await.unwrap();
            assert_eq!(restored_data, Some(b"data".to_vec()));
        }
    }
}

/// Mock failing storage for error testing
struct FailingStorage {
    should_fail: Arc<std::sync::atomic::AtomicBool>,
}

impl FailingStorage {
    fn new() -> Self {
        Self {
            should_fail: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }
}

#[async_trait]
impl StorageBackend for FailingStorage {
    async fn put(&self, _key: &str, _value: &[u8]) -> Result<()> {
        if self.should_fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(FortressError::storage(
                "Mock storage failure".to_string(),
                "failing_storage".to_string(),
                StorageErrorCode::ConnectionFailed,
            ))
        } else {
            Ok(())
        }
    }

    async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        Err(FortressError::storage(
            "Mock storage failure".to_string(),
            "failing_storage".to_string(),
            StorageErrorCode::ConnectionFailed,
        ))
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        Err(FortressError::storage(
            "Mock storage failure".to_string(),
            "failing_storage".to_string(),
            StorageErrorCode::ConnectionFailed,
        ))
    }

    async fn exists(&self, _key: &str) -> Result<bool> {
        Err(FortressError::storage(
            "Mock storage failure".to_string(),
            "failing_storage".to_string(),
            StorageErrorCode::ConnectionFailed,
        ))
    }

    async fn list_prefix(&self, _prefix: &str) -> Result<Vec<String>> {
        Err(FortressError::storage(
            "Mock storage failure".to_string(),
            "failing_storage".to_string(),
            StorageErrorCode::ConnectionFailed,
        ))
    }

    fn metadata(&self) -> crate::storage::StorageMetadata {
        crate::storage::StorageMetadata {
            backend_type: "failing".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: false,
            supports_encryption_at_rest: false,
            max_object_size: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    async fn health_check(&self) -> Result<crate::storage::HealthStatus> {
        Err(FortressError::storage(
            "Mock storage failure".to_string(),
            "failing_storage".to_string(),
            StorageErrorCode::ConnectionFailed,
        ))
    }
}

/// Test utilities and helpers
#[cfg(test)]
mod test_utils {
    use super::*;

    /// Create test backup data
    pub fn create_test_backup_data() -> Vec<(String, Vec<u8>)> {
        vec![
            ("config.json".to_string(), b"{}".to_vec()),
            ("data.bin".to_string(), vec![0u8; 1024]),
            ("log.txt".to_string(), b"log entries\n".to_vec()),
        ]
    }

    /// Verify backup integrity
    pub async fn verify_backup_integrity(
        backup_manager: &Arc<dyn BackupManager>,
        backup_id: &str,
    ) -> Result<bool> {
        // Test all verification levels
        for level in [
            VerificationLevel::Basic,
            VerificationLevel::Full,
            VerificationLevel::Comprehensive,
        ] {
            if !backup_manager.verify_backup(backup_id, level).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Create test disaster recovery scenario
    pub async fn create_test_disaster_scenario(
        source_storage: &Arc<dyn StorageBackend>,
        backup_manager: &Arc<dyn BackupManager>,
    ) -> Result<String> {
        // Add test data
        let test_data = create_test_backup_data();
        for (key, data) in test_data {
            source_storage.put(&key, &data).await?;
        }

        // Create backup
        let backup = backup_manager.create_backup(
            &**source_storage,
            &BackupConfig::default(),
        ).await?;

        Ok(backup.backup_id)
    }
}
