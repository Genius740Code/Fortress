//! Advanced backup system tests
//!
//! This module contains comprehensive tests for the enhanced backup system
//! including incremental/differential backups, point-in-time recovery,
//! cross-region replication, and automated scheduling.

use fortress_core::prelude::*;
use fortress_core::backup_manager::DefaultBackupManager;
use fortress_core::backup::BackupManager;
use fortress_core::disaster_recovery::DefaultDisasterRecoveryManager;
use fortress_core::backup_scheduler::BackupScheduler;
use fortress_core::cross_region_replication::CrossRegionReplicationManager;
use fortress_core::storage::{InMemoryStorage, StorageBackend};
use std::sync::Arc;
use chrono::Utc;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_incremental_backup_workflow() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    // Add initial data
    source_storage.put("key1", b"data1").await?;
    source_storage.put("key2", b"data2").await?;

    // Create full backup
    let full_config = BackupConfig {
        default_strategy: BackupStrategy::Full,
        ..BackupConfig::default()
    };
    let full_backup = backup_manager.create_backup(&*source_storage, &full_config).await?;
    assert_eq!(full_backup.item_count, 2);
    assert!(matches!(full_backup.strategy, BackupStrategy::Full));

    // Wait a bit to ensure different timestamps
    sleep(Duration::from_millis(10)).await;

    // Add new data and modify existing
    source_storage.put("key3", b"data3").await?;
    source_storage.put("key1", b"modified_data1").await?;

    // Create incremental backup
    let incremental_config = BackupConfig {
        default_strategy: BackupStrategy::Incremental {
            base_backup_id: full_backup.backup_id.clone(),
        },
        ..BackupConfig::default()
    };
    let incremental_backup = backup_manager.create_backup(&*source_storage, &incremental_config).await?;
    assert!(matches!(incremental_backup.strategy, BackupStrategy::Incremental { .. }));
    
    // Incremental backup should only contain changed keys
    assert!(incremental_backup.item_count <= 2); // key1 (modified) + key3 (new)

    // Test restore to new storage
    let target_storage = Arc::new(InMemoryStorage::new());
    
    // First restore full backup
    let restore_status = backup_manager.restore_backup(
        &full_backup.backup_id,
        &*target_storage,
        &BackupConfig::default(),
    ).await?;
    assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));
    assert_eq!(restore_status.items_restored, 2);

    // Then restore incremental backup
    let inc_restore_status = backup_manager.restore_backup(
        &incremental_backup.backup_id,
        &*target_storage,
        &BackupConfig::default(),
    ).await?;
    assert!(matches!(inc_restore_status.status, RestoreOperationStatus::Completed));

    // Verify final state
    let data1 = target_storage.get("key1").await?;
    assert_eq!(data1, Some(b"modified_data1".to_vec()));
    
    let data2 = target_storage.get("key2").await?;
    assert_eq!(data2, Some(b"data2".to_vec()));
    
    let data3 = target_storage.get("key3").await?;
    assert_eq!(data3, Some(b"data3".to_vec()));

    Ok(())
}

#[tokio::test]
async fn test_differential_backup_workflow() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    // Add initial data
    source_storage.put("key1", b"data1").await?;
    source_storage.put("key2", b"data2").await?;

    // Create full backup
    let full_config = BackupConfig {
        default_strategy: BackupStrategy::Full,
        ..BackupConfig::default()
    };
    let full_backup = backup_manager.create_backup(&*source_storage, &full_config).await?;

    // Wait for different timestamp
    sleep(Duration::from_millis(10)).await;

    // Add new data
    source_storage.put("key3", b"data3").await?;
    source_storage.put("key4", b"data4").await?;

    // Create differential backup
    let differential_config = BackupConfig {
        default_strategy: BackupStrategy::Differential {
            base_backup_id: full_backup.backup_id.clone(),
        },
        ..BackupConfig::default()
    };
    let differential_backup = backup_manager.create_backup(&*source_storage, &differential_config).await?;
    assert!(matches!(differential_backup.strategy, BackupStrategy::Differential { .. }));

    // Verify differential backup contains all changes since full backup
    assert_eq!(differential_backup.item_count, 2); // key3 + key4

    Ok(())
}

#[tokio::test]
async fn test_point_in_time_recovery() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    // Create timeline of data changes
    let time1 = Utc::now();
    
    source_storage.put("key1", b"version1").await?;
    
    let full_backup = backup_manager.create_backup(&*source_storage, &BackupConfig::default()).await?;
    
    sleep(Duration::from_millis(10)).await;
    let time2 = Utc::now();
    
    source_storage.put("key1", b"version2").await?;
    source_storage.put("key2", b"version1").await?;
    
    let incremental1 = backup_manager.create_backup(&*source_storage, &BackupConfig {
        default_strategy: BackupStrategy::Incremental {
            base_backup_id: full_backup.backup_id.clone(),
        },
        ..BackupConfig::default()
    }).await?;
    
    sleep(Duration::from_millis(10)).await;
    let time3 = Utc::now();
    
    source_storage.put("key1", b"version3").await?;
    source_storage.put("key3", b"version1").await?;
    
    let incremental2 = backup_manager.create_backup(&*source_storage, &BackupConfig {
        default_strategy: BackupStrategy::Incremental {
            base_backup_id: full_backup.backup_id.clone(),
        },
        ..BackupConfig::default()
    }).await?;

    // Test point-in-time recovery to time2 (after first incremental)
    let target_storage = Arc::new(InMemoryStorage::new());
    
    // This would be implemented in the backup manager
    // For now, we'll simulate by restoring full + incremental1
    let restore1 = backup_manager.restore_backup(
        &full_backup.backup_id,
        &*target_storage,
        &BackupConfig::default(),
    ).await?;
    
    let restore2 = backup_manager.restore_backup(
        &incremental1.backup_id,
        &*target_storage,
        &BackupConfig::default(),
    ).await?;
    
    assert!(matches!(restore1.status, RestoreOperationStatus::Completed));
    assert!(matches!(restore2.status, RestoreOperationStatus::Completed));
    
    // Verify state at time2
    let data1 = target_storage.get("key1").await?;
    assert_eq!(data1, Some(b"version2".to_vec()));
    
    let data2 = target_storage.get("key2").await?;
    assert_eq!(data2, Some(b"version1".to_vec()));
    
    // key3 should not exist at time2
    let data3 = target_storage.get("key3").await?;
    assert_eq!(data3, None);

    Ok(())
}

#[tokio::test]
async fn test_comprehensive_backup_verification() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    // Add test data
    source_storage.put("key1", b"test_data1").await?;
    source_storage.put("key2", b"test_data2").await?;

    // Create backup
    let backup = backup_manager.create_backup(&*source_storage, &BackupConfig::default()).await?;

    // Test different verification levels
    let basic_valid = backup_manager.verify_backup(&backup.backup_id, VerificationLevel::Basic).await?;
    assert!(basic_valid);

    let full_valid = backup_manager.verify_backup(&backup.backup_id, VerificationLevel::Full).await?;
    assert!(full_valid);

    let comprehensive_valid = backup_manager.verify_backup(&backup.backup_id, VerificationLevel::Comprehensive).await?;
    assert!(comprehensive_valid);

    Ok(())
}

#[tokio::test]
async fn test_backup_scheduler() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    let scheduler = BackupScheduler::new(backup_manager.clone(), source_storage.clone());

    // Create a schedule (disabled for testing)
    let schedule = BackupSchedule {
        schedule_id: "test_schedule".to_string(),
        name: "Test Schedule".to_string(),
        strategy: BackupStrategy::Full,
        cron_expression: "0 2 * * *".to_string(), // 2 AM daily
        enabled: false, // Don't start task for test
        timezone: "UTC".to_string(),
        max_retries: 2,
        retry_delay_seconds: 60,
        last_run: None,
        next_run: None,
        run_history: Vec::new(),
    };

    scheduler.add_schedule(schedule).await?;

    // List schedules
    let schedules = scheduler.list_schedules().await?;
    assert_eq!(schedules.len(), 1);
    assert_eq!(schedules[0].schedule_id, "test_schedule");

    // Get schedule
    let retrieved_schedule = scheduler.get_schedule("test_schedule").await?;
    assert!(retrieved_schedule.is_some());
    assert_eq!(retrieved_schedule.unwrap().name, "Test Schedule");

    // Remove schedule
    scheduler.remove_schedule("test_schedule").await?;
    
    let schedules_after = scheduler.list_schedules().await?;
    assert_eq!(schedules_after.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_cross_region_replication() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let target_storage1 = Arc::new(InMemoryStorage::new());
    let target_storage2 = Arc::new(InMemoryStorage::new());
    
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    let replication_manager = CrossRegionReplicationManager::new(
        backup_manager.clone(),
        1024 * 1024 * 100, // 100MB/s
    );

    // Add target regions
    replication_manager.add_target_region("us-east-1".to_string(), target_storage1.clone()).await?;
    replication_manager.add_target_region("us-west-2".to_string(), target_storage2.clone()).await?;

    // Create replication config (disabled for testing)
    let config = CrossRegionConfig {
        replication_id: "test_replication".to_string(),
        source_region: "primary".to_string(),
        target_regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
        strategy: ReplicationStrategy::Immediate,
        enabled: false, // Don't start task for test
        frequency_seconds: 300,
        max_bandwidth_bps: Some(1024 * 1024 * 10), // 10MB/s
        last_replication: None,
        replication_history: Vec::new(),
    };

    replication_manager.add_replication_config(config).await?;

    // List configs
    let configs = replication_manager.list_replication_configs().await?;
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].replication_id, "test_replication");

    // Get stats
    let stats = replication_manager.get_replication_stats().await?;
    assert_eq!(stats.target_regions, 2);
    assert_eq!(stats.active_replications, 0); // Disabled

    // Remove config
    replication_manager.remove_replication_config("test_replication").await?;
    
    let configs_after = replication_manager.list_replication_configs().await?;
    assert_eq!(configs_after.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_disaster_recovery_planning() -> Result<()> {
    // Setup
    let plan_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    let dr_manager = DefaultDisasterRecoveryManager::new(
        plan_storage.clone(),
        backup_manager,
    );

    // Create default plans
    dr_manager.create_default_plans().await?;

    // List plans
    let plans = dr_manager.list_recovery_plans().await?;
    assert_eq!(plans.len(), 3); // Complete, Partial, Maintenance

    // Test plan execution (simulated)
    let complete_plan = &plans[0]; // Should be the complete recovery plan
    assert_eq!(complete_plan.name, "Complete System Recovery");
    assert_eq!(complete_plan.priority, RecoveryPriority::Critical);

    // Test recovery plan
    let test_result = dr_manager.test_recovery_plan(&complete_plan.plan_id).await?;
    assert!(test_result.passed);

    // Get plan after test (should have last_tested updated)
    let updated_plan = dr_manager.get_recovery_plan(&complete_plan.plan_id).await?;
    assert!(updated_plan.unwrap().last_tested.is_some());

    Ok(())
}

#[tokio::test]
async fn test_backup_retention_policy() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    // Create multiple backups
    let mut backup_ids = Vec::new();
    for i in 0..5 {
        source_storage.put(&format!("key{}", i), format!("data{}", i).as_bytes()).await?;
        let backup = backup_manager.create_backup(&*source_storage, &BackupConfig::default()).await?;
        backup_ids.push(backup.backup_id);
        
        // Wait to ensure different timestamps
        sleep(Duration::from_millis(10)).await;
    }

    // Verify all backups exist
    let backups_before = backup_manager.list_backups().await?;
    assert_eq!(backups_before.len(), 5);

    // Apply retention policy (keep only 2 full backups)
    let retention_policy = RetentionPolicy {
        max_full_backups: 2,
        max_incremental_backups: 10,
        max_age_days: 90,
        auto_cleanup: true,
    };

    let deleted_count = backup_manager.cleanup_old_backups(&retention_policy).await?;
    assert!(deleted_count >= 3); // Should delete at least 3 old backups

    // Verify cleanup
    let backups_after = backup_manager.list_backups().await?;
    assert!(backups_after.len() <= 2);

    Ok(())
}

#[tokio::test]
async fn test_backup_storage_statistics() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    // Create different types of backups
    source_storage.put("key1", b"data1").await?;
    let full_backup = backup_manager.create_backup(&*source_storage, &BackupConfig::default()).await?;

    source_storage.put("key2", b"data2").await?;
    let incremental_backup = backup_manager.create_backup(&*source_storage, &BackupConfig {
        default_strategy: BackupStrategy::Incremental {
            base_backup_id: full_backup.backup_id.clone(),
        },
        ..BackupConfig::default()
    }).await?;

    // Get statistics
    let stats = backup_manager.get_storage_stats().await?;
    
    assert_eq!(stats.total_backups, 2);
    assert!(stats.total_storage_used > 0);
    assert!(stats.full_backup_storage > 0);
    assert!(stats.incremental_backup_storage > 0);
    assert!(stats.oldest_backup.is_some());
    assert!(stats.newest_backup.is_some());
    assert!(stats.average_backup_size > 0);

    Ok(())
}

#[tokio::test]
async fn test_encrypted_backup_verification() -> Result<()> {
    // Setup with encryption
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let encryption = Arc::new(Aes256Gcm::new());
    
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        Some(encryption),
        BackupConfig::default(),
    )?);

    // Add test data
    source_storage.put("secret_key", b"confidential_data").await?;

    // Create encrypted backup
    let backup = backup_manager.create_backup(&*source_storage, &BackupConfig::default()).await?;

    // Verify backup can be restored
    let target_storage = Arc::new(InMemoryStorage::new());
    let restore_status = backup_manager.restore_backup(
        &backup.backup_id,
        &*target_storage,
        &BackupConfig::default(),
    ).await?;

    assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));
    
    // Verify decrypted data
    let restored_data = target_storage.get("secret_key").await?;
    assert_eq!(restored_data, Some(b"confidential_data".to_vec()));

    // Test comprehensive verification
    let is_valid = backup_manager.verify_backup(&backup.backup_id, VerificationLevel::Comprehensive).await?;
    assert!(is_valid);

    Ok(())
}

#[tokio::test]
async fn test_backup_conflict_resolution() -> Result<()> {
    // Setup
    let source_storage = Arc::new(InMemoryStorage::new());
    let backup_storage = Arc::new(InMemoryStorage::new());
    let target_storage = Arc::new(InMemoryStorage::new());
    
    let backup_manager = Arc::new(DefaultBackupManager::new(
        backup_storage.clone(),
        None,
        BackupConfig::default(),
    )?);

    // Add data to source
    source_storage.put("key1", b"source_data").await?;
    let backup = backup_manager.create_backup(&*source_storage, &BackupConfig::default()).await?;

    // Add conflicting data to target
    target_storage.put("key1", b"target_data").await?;

    // Test different conflict resolution strategies
    
    // 1. Overwrite strategy
    let overwrite_config = BackupConfig {
        conflict_resolution: ConflictResolution::Overwrite,
        ..BackupConfig::default()
    };
    let restore_status = backup_manager.restore_backup(
        &backup.backup_id,
        &*target_storage,
        &overwrite_config,
    ).await?;
    assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));
    
    let data = target_storage.get("key1").await?;
    assert_eq!(data, Some(b"source_data".to_vec()));

    // Reset for next test
    target_storage.put("key1", b"target_data").await?;

    // 2. Skip strategy
    let skip_config = BackupConfig {
        conflict_resolution: ConflictResolution::Skip,
        ..BackupConfig::default()
    };
    let restore_status = backup_manager.restore_backup(
        &backup.backup_id,
        &*target_storage,
        &skip_config,
    ).await?;
    assert!(matches!(restore_status.status, RestoreOperationStatus::Completed));
    
    let data = target_storage.get("key1").await?;
    assert_eq!(data, Some(b"target_data".to_vec())); // Should remain unchanged

    Ok(())
}
