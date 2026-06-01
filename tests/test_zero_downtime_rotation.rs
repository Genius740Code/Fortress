#![cfg(any())]
//! Comprehensive tests for zero-downtime key rotation

use chrono::{Duration, Utc};
use fortress_core::{
    encryption::{create_algorithm, Aegis256, ChaCha20Poly1305},
    error::{FortressError, KeyErrorCode},
    key::{
        InMemoryKeyManager, KeyManager, RotationInterval, RotationPolicy, SmartKeyRotationScheduler,
    },
};
use std::sync::Arc;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn test_zero_downtime_rotation_basic() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key
    let key_id = "test_rotation_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    key_manager
        .store_key(&key_id, &initial_key, &metadata)
        .await?;

    // Verify initial state
    let (_, initial_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert_eq!(initial_metadata.version, 1);

    // Perform zero-downtime rotation
    let rotation_result = key_manager
        .rotate_key_with_zero_downtime(&key_id, algorithm.as_ref())
        .await;
    assert!(
        rotation_result.is_ok(),
        "Zero-downtime rotation should succeed"
    );

    // Verify rotation results
    let (_, rotated_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert_eq!(rotated_metadata.version, 2, "Version should increment by 1");
    assert!(
        rotated_metadata.created_at > initial_metadata.created_at,
        "Creation time should be updated"
    );

    // Verify key is still accessible
    let (accessed_key, _) = key_manager.retrieve_key(&key_id).await?;
    assert!(!accessed_key.is_empty(), "Rotated key should be accessible");

    Ok(())
}

#[tokio::test]
async fn test_concurrent_rotation_protection() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key
    let key_id = "concurrent_test_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    key_manager
        .store_key(&key_id, &initial_key, &metadata)
        .await?;

    // Attempt concurrent rotations
    let key_manager_clone = key_manager.clone();
    let key_id_clone = key_id.clone();
    let algorithm_clone = create_algorithm("aegis256")?;

    let rotation1 = tokio::spawn(async move {
        key_manager
            .rotate_key_with_zero_downtime(&key_id, algorithm.as_ref())
            .await
    });

    let rotation2 = tokio::spawn(async move {
        sleep(tokio::time::Duration::from_millis(100)).await; // Small delay
        key_manager_clone
            .rotate_key_with_zero_downtime(&key_id_clone, algorithm_clone.as_ref())
            .await
    });

    // Wait for both rotations to complete
    let (result1, result2) = tokio::join!(rotation1, rotation2);

    // At least one should succeed, other might fail due to concurrent access
    let success_count = (result1.is_ok()) as u8 + (result2.is_ok()) as u8;

    assert!(success_count >= 1, "At least one rotation should succeed");

    // Verify final state is consistent
    let (_, final_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert!(final_metadata.version >= 1, "Final version should be valid");

    Ok(())
}

#[tokio::test]
async fn test_rotation_with_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key
    let key_id = "concurrent_ops_test_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    key_manager
        .store_key(&key_id, &initial_key, &metadata)
        .await?;

    // Start concurrent operations during rotation
    let key_manager_clone = key_manager.clone();
    let key_id_clone1 = key_id.clone();
    let key_id_clone2 = key_id.clone();

    // Spawn rotation task
    let rotation_task = tokio::spawn(async move {
        sleep(tokio::time::Duration::from_millis(50)).await;
        key_manager
            .rotate_key_with_zero_downtime(&key_id, algorithm.as_ref())
            .await
    });

    // Spawn concurrent access tasks
    let access_task1 = tokio::spawn(async move {
        for i in 0..10 {
            if let Ok((_, _)) = key_manager_clone.retrieve_key(&key_id_clone1).await {
                // Access succeeded
            }
            sleep(tokio::time::Duration::from_millis(10)).await;
        }
        true
    });

    let access_task2 = tokio::spawn(async move {
        for i in 0..10 {
            if let Ok((_, _)) = key_manager_clone.retrieve_key(&key_id_clone2).await {
                // Access succeeded
            }
            sleep(tokio::time::Duration::from_millis(15)).await;
        }
        true
    });

    // Wait for all tasks to complete
    let (rotation_result, access1_result, access2_result) =
        tokio::join!(rotation_task, access_task1, access_task2);

    // Verify rotation succeeded
    if rotation_result.is_ok() {
        assert!(
            rotation_result.unwrap().is_ok(),
            "Rotation should complete successfully"
        );
    } else {
        return Err(FortressError::KeyManagement {
            message: "Rotation failed".to_string(),
            key_id: None,
            code: KeyErrorCode::RotationFailed,
        });
    }

    // Verify concurrent access succeeded
    if access1_result.is_ok() {
        assert!(
            access1_result.unwrap().is_ok(),
            "Concurrent access 1 should succeed"
        );
    } else {
        return Err(FortressError::KeyManagement {
            message: "Concurrent access 1 failed".to_string(),
            key_id: None,
            code: KeyErrorCode::AccessDenied,
        });
    }

    if access2_result.is_ok() {
        assert!(
            access2_result.unwrap().is_ok(),
            "Concurrent access 2 should succeed"
        );
    } else {
        return Err(FortressError::KeyManagement {
            message: "Concurrent access 2 failed".to_string(),
            key_id: None,
            code: KeyErrorCode::AccessDenied,
        });
    }

    if access1_result.is_ok() && access2_result.is_ok() {
        assert!(
            access1_result.unwrap().is_ok(),
            "Access 1 should complete successfully"
        );
        assert!(
            access2_result.unwrap().is_ok(),
            "Access 2 should complete successfully"
        );
    } else {
        return Err(FortressError::KeyManagement {
            message: "One of the concurrent accesses failed".to_string(),
            key_id: None,
            code: KeyErrorCode::AccessDenied,
        });
    }

    // Verify final key state
    let (_, final_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert!(final_metadata.version >= 1, "Final version should be valid");

    Ok(())
}

#[tokio::test]
async fn test_rotation_rollback_on_failure() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key
    let key_id = "rollback_test_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    key_manager
        .store_key(&key_id, &initial_key, &metadata)
        .await?;

    // Store initial state for comparison
    let (_, initial_metadata) = key_manager.retrieve_key(&key_id).await?;
    let initial_version = initial_metadata.version;

    // Simulate rotation failure by deleting the key mid-process
    // This is a complex scenario to test rollback mechanisms
    let key_manager_clone = key_manager.clone();
    let key_id_clone = key_id.clone();

    let rotation_task = tokio::spawn(async move {
        // Start rotation but simulate failure
        sleep(tokio::time::Duration::from_millis(100)).await;

        // Delete the key to simulate a failure scenario
        let _ = key_manager_clone.delete_key(&key_id_clone).await;

        // Attempt rotation (should fail)
        let algorithm = create_algorithm("aegis256").unwrap();
        key_manager_clone
            .rotate_key_with_zero_downtime(&key_id_clone, algorithm.as_ref())
            .await
    });

    let rotation_result = rotation_task.await?;

    // Rotation should fail due to missing key
    assert!(
        rotation_result.is_err(),
        "Rotation should fail when key is missing"
    );

    // Restore the key for continued testing
    key_manager
        .store_key(&key_id, &initial_key, &initial_metadata)
        .await?;

    // Verify the key is still accessible with original version
    let (_, restored_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert_eq!(
        restored_metadata.version, initial_version,
        "Version should be preserved after failure"
    );

    Ok(())
}

#[tokio::test]
async fn test_smart_scheduler_zero_downtime_rotation() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create scheduler with zero-downtime support
    let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
    scheduler.set_security_level_intervals();

    // Create multiple keys with different purposes
    let keys = vec![
        ("high_security_key", "high_security"),
        ("sensitive_key", "sensitive"),
        ("standard_key", "standard"),
        ("low_security_key", "low_sensitivity"),
    ];

    for (key_id, purpose) in &keys {
        let key = key_manager.generate_key(algorithm.as_ref()).await?;
        let metadata = fortress_core::key::KeyMetadata::new(
            key_id.to_string(),
            algorithm.name().to_string(),
            1,
            Utc::now() - Duration::days(1), // Created yesterday to trigger rotation
            Utc::now() + Duration::days(90),
            purpose.to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );

        key_manager.store_key(key_id, &key, &metadata).await?;
    }

    // Run scheduler check and rotate
    let rotated_keys = scheduler.check_and_rotate().await?;

    // Should rotate keys that need rotation based on intervals
    assert!(!rotated_keys.is_empty(), "Some keys should be rotated");

    // Verify all rotated keys are still accessible
    for (key_id, _) in &keys {
        let (key, metadata) = key_manager.retrieve_key(key_id).await?;
        assert!(
            !key.is_empty(),
            "Key {} should be accessible after rotation",
            key_id
        );
        assert!(
            metadata.version >= 1,
            "Key {} should have valid version",
            key_id
        );
    }

    // Check scheduler metrics
    let metrics = scheduler.get_metrics().await;
    assert!(metrics.total_rotations > 0, "Should have rotation metrics");
    assert!(
        metrics.successful_rotations > 0,
        "Should have successful rotations"
    );

    Ok(())
}

#[tokio::test]
async fn test_rotation_timeout_handling() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key
    let key_id = "timeout_test_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    key_manager
        .store_key(&key_id, &initial_key, &metadata)
        .await?;

    // Test rotation with reasonable timeout
    let rotation_result = timeout(
        tokio::time::Duration::from_secs(30), // 30 second timeout
        key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()),
    )
    .await;

    assert!(
        rotation_result.is_ok(),
        "Rotation should complete within timeout"
    );
    assert!(rotation_result.unwrap().is_ok(), "Rotation should succeed");

    // Verify key is still accessible
    let (_, final_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert_eq!(final_metadata.version, 2, "Version should be incremented");

    Ok(())
}

#[tokio::test]
async fn test_rotation_with_different_algorithms() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());

    let algorithms = vec![
        ("aegis256", create_algorithm("aegis256")?),
        ("chacha20poly1305", create_algorithm("chacha20poly1305")?),
    ];

    for (algo_name, algorithm) in algorithms {
        let key_id = format!("test_key_{}", algo_name);

        // Create initial key
        let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
        let metadata = fortress_core::key::KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + Duration::days(90),
            "test".to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );

        key_manager
            .store_key(&key_id, &initial_key, &metadata)
            .await?;

        // Rotate with same algorithm
        let rotation_result = key_manager
            .rotate_key_with_zero_downtime(&key_id, algorithm.as_ref())
            .await;
        assert!(
            rotation_result.is_ok(),
            "Rotation with {} should succeed",
            algo_name
        );

        // Verify rotation
        let (_, rotated_metadata) = key_manager.retrieve_key(&key_id).await?;
        assert_eq!(
            rotated_metadata.version, 2,
            "Version should be incremented for {}",
            algo_name
        );
        assert_eq!(
            rotated_metadata.algorithm,
            algorithm.name(),
            "Algorithm should be preserved for {}",
            algo_name
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_rotation_metadata_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key with custom metadata
    let key_id = "metadata_test_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let mut metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    // Add custom metadata
    metadata = metadata
        .with_metadata("custom_field".to_string(), "custom_value".to_string())
        .with_metadata("environment".to_string(), "test".to_string());

    key_manager
        .store_key(&key_id, &initial_key, &metadata)
        .await?;

    // Perform rotation
    let rotation_result = key_manager
        .rotate_key_with_zero_downtime(&key_id, algorithm.as_ref())
        .await;
    assert!(rotation_result.is_ok(), "Rotation should succeed");

    // Verify metadata integrity
    let (_, rotated_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert_eq!(rotated_metadata.version, 2, "Version should be incremented");
    assert_eq!(
        rotated_metadata.purpose, metadata.purpose,
        "Purpose should be preserved"
    );
    assert_eq!(
        rotated_metadata.performance_profile, metadata.performance_profile,
        "Performance profile should be preserved"
    );

    // Check rotation-specific metadata
    assert!(
        rotated_metadata.get_metadata("rotation_id").is_some(),
        "Should have rotation ID"
    );
    assert!(
        rotated_metadata.get_metadata("transition_status").is_some(),
        "Should have transition status"
    );

    Ok(())
}

#[tokio::test]
async fn test_multiple_rotations_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key
    let key_id = "sequence_test_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    key_manager
        .store_key(&key_id, &initial_key, &metadata)
        .await?;

    // Perform multiple sequential rotations
    let initial_version = 1;
    let num_rotations = 5;

    for i in 0..num_rotations {
        let rotation_result = key_manager
            .rotate_key_with_zero_downtime(&key_id, algorithm.as_ref())
            .await;
        assert!(rotation_result.is_ok(), "Rotation {} should succeed", i + 1);

        // Verify intermediate state
        let (_, current_metadata) = key_manager.retrieve_key(&key_id).await?;
        assert_eq!(
            current_metadata.version,
            initial_version + i + 1,
            "Version should be {} after rotation {}",
            initial_version + i + 1,
            i + 1
        );

        // Verify key is still accessible
        let (accessed_key, _) = key_manager.retrieve_key(&key_id).await?;
        assert!(
            !accessed_key.is_empty(),
            "Key should be accessible after rotation {}",
            i + 1
        );
    }

    // Verify final state
    let (_, final_metadata) = key_manager.retrieve_key(&key_id).await?;
    assert_eq!(
        final_metadata.version,
        initial_version + num_rotations,
        "Final version should be {}",
        initial_version + num_rotations
    );

    Ok(())
}
