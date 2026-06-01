//! Integration tests for backup and disaster recovery system

use fortress_core::backup::*;
use fortress_core::backup_manager::DefaultBackupManager;
use fortress_core::storage::{InMemoryStorage, StorageBackend};
use std::sync::Arc;

#[tokio::test]
async fn test_simple_backup_and_restore() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let target_storage = Arc::new(InMemoryStorage::new());

    // Add test data
    source_storage.put("test.txt", b"test data").await.unwrap();
    source_storage
        .put("data.json", b"{\"key\": \"value\"}")
        .await
        .unwrap();

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    // Create backup
    let backup = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();
    assert_eq!(backup.item_count, 2);
    assert!(matches!(backup.strategy, BackupStrategy::Full));

    // Restore backup
    let status = manager
        .restore_backup(&backup.backup_id, &*target_storage, &config)
        .await
        .unwrap();
    assert!(matches!(status.status, RestoreOperationStatus::Completed));

    // Verify restored data
    let restored_data = target_storage.get("test.txt").await.unwrap();
    assert_eq!(restored_data, Some(b"test data".to_vec()));

    let restored_json = target_storage.get("data.json").await.unwrap();
    assert_eq!(restored_json, Some(b"{\"key\": \"value\"}".to_vec()));
}

#[tokio::test]
async fn test_backup_verification() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());

    source_storage.put("key1", b"data1").await.unwrap();
    source_storage.put("key2", b"data2").await.unwrap();

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    let backup = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();

    // Test basic verification
    let is_valid = manager
        .verify_backup(&backup.backup_id, VerificationLevel::Basic)
        .await
        .unwrap();
    assert!(is_valid);

    // Test full verification
    let is_valid = manager
        .verify_backup(&backup.backup_id, VerificationLevel::Full)
        .await
        .unwrap();
    assert!(is_valid);
}

#[tokio::test]
async fn test_backup_list_and_delete() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());

    source_storage.put("key1", b"data1").await.unwrap();

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    // Create backup
    let backup = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();

    // List backups
    let backups = manager.list_backups().await.unwrap();
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0].backup_id, backup.backup_id);

    // Get backup metadata
    let metadata = manager
        .get_backup_metadata(&backup.backup_id)
        .await
        .unwrap();
    assert!(metadata.is_some());
    assert_eq!(metadata.unwrap().backup_id, backup.backup_id);

    // Delete backup
    manager.delete_backup(&backup.backup_id).await.unwrap();

    // Verify deletion
    let backups = manager.list_backups().await.unwrap();
    assert_eq!(backups.len(), 0);
}

#[tokio::test]
async fn test_storage_stats() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());

    source_storage.put("key1", b"data1").await.unwrap();
    source_storage.put("key2", b"data2").await.unwrap();

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    // Create backup
    let backup = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();

    // Get storage stats
    let stats = manager.get_storage_stats().await.unwrap();
    assert_eq!(stats.total_backups, 1);
    assert!(stats.total_storage_used > 0);
    assert!(stats.oldest_backup.is_some());
    assert!(stats.newest_backup.is_some());
}

#[tokio::test]
async fn test_empty_backup() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    // Create backup of empty storage
    let backup = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();
    assert_eq!(backup.item_count, 0);
    assert_eq!(backup.total_size, 0);

    // Restore empty backup
    let target_storage = Arc::new(InMemoryStorage::new());
    let status = manager
        .restore_backup(&backup.backup_id, &*target_storage, &config)
        .await
        .unwrap();
    assert!(matches!(status.status, RestoreOperationStatus::Completed));
    assert_eq!(status.items_restored, 0);
}

#[tokio::test]
async fn test_large_data_backup() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());

    // Create large test data (1MB)
    let large_data = vec![0u8; 1024 * 1024];
    source_storage.put("large_file", &large_data).await.unwrap();

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    // Create backup
    let backup = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();
    assert_eq!(backup.item_count, 1);
    assert_eq!(backup.total_size, large_data.len() as u64);

    // Restore backup
    let target_storage = Arc::new(InMemoryStorage::new());
    let status = manager
        .restore_backup(&backup.backup_id, &*target_storage, &config)
        .await
        .unwrap();
    assert!(matches!(status.status, RestoreOperationStatus::Completed));

    // Verify restored data
    let restored_data = target_storage.get("large_file").await.unwrap();
    assert_eq!(restored_data, Some(large_data));
}

#[tokio::test]
async fn test_special_characters_in_keys() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());

    // Test keys with special characters
    let test_keys = vec![
        "file with spaces.txt",
        "file-with-dashes.txt",
        "file_with_underscores.txt",
        "file.with.dots.txt",
        "file/with/slashes.txt",
        "file\\with\\backslashes.txt",
        "file@with@symbols.txt",
        "file#with#hash.txt",
        "文件.txt", // Chinese characters
        "файл.txt", // Cyrillic characters
    ];

    for key in &test_keys {
        source_storage
            .put(key, format!("data for {}", key).as_bytes())
            .await
            .unwrap();
    }

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    // Create backup
    let backup = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();
    assert_eq!(backup.item_count, test_keys.len() as u64);

    // Restore backup
    let target_storage = Arc::new(InMemoryStorage::new());
    let status = manager
        .restore_backup(&backup.backup_id, &*target_storage, &config)
        .await
        .unwrap();
    assert!(matches!(status.status, RestoreOperationStatus::Completed));
    assert_eq!(status.items_restored, test_keys.len() as u64);

    // Verify all data was restored correctly
    for key in &test_keys {
        let restored_data = target_storage.get(key).await.unwrap();
        let expected_data = format!("data for {}", key).into_bytes();
        assert_eq!(restored_data, Some(expected_data));
    }
}

#[tokio::test]
async fn test_multiple_backups() {
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());

    let config = BackupConfig::default();
    let manager = DefaultBackupManager::new(backup_storage.clone(), None, config.clone()).unwrap();

    // Create first backup
    source_storage.put("file1.txt", b"version1").await.unwrap();
    let backup1 = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();

    // Modify data and create second backup
    source_storage.put("file1.txt", b"version2").await.unwrap();
    source_storage.put("file2.txt", b"new file").await.unwrap();
    let backup2 = manager
        .create_backup(&*source_storage, &config)
        .await
        .unwrap();

    // List backups should show both
    let backups = manager.list_backups().await.unwrap();
    assert_eq!(backups.len(), 2);

    // Verify backup metadata
    let metadata1 = manager
        .get_backup_metadata(&backup1.backup_id)
        .await
        .unwrap();
    let metadata2 = manager
        .get_backup_metadata(&backup2.backup_id)
        .await
        .unwrap();
    assert!(metadata1.is_some());
    assert!(metadata2.is_some());

    // Restore from first backup
    let target1 = Arc::new(InMemoryStorage::new());
    let status1 = manager
        .restore_backup(&backup1.backup_id, &*target1, &config)
        .await
        .unwrap();
    assert!(matches!(status1.status, RestoreOperationStatus::Completed));

    let data1 = target1.get("file1.txt").await.unwrap();
    assert_eq!(data1, Some(b"version1".to_vec()));

    // Restore from second backup
    let target2 = Arc::new(InMemoryStorage::new());
    let status2 = manager
        .restore_backup(&backup2.backup_id, &*target2, &config)
        .await
        .unwrap();
    assert!(matches!(status2.status, RestoreOperationStatus::Completed));

    let data2 = target2.get("file1.txt").await.unwrap();
    assert_eq!(data2, Some(b"version2".to_vec()));

    let data3 = target2.get("file2.txt").await.unwrap();
    assert_eq!(data3, Some(b"new file".to_vec()));
}
