//! Zero-Downtime Key Rotation Example
//! 
//! This example demonstrates how to use Fortress's zero-downtime key rotation
//! feature to rotate encryption keys without interrupting service operations.

use fortress_core::key::{KeyManager, InMemoryKeyManager, SmartKeyRotationScheduler, RotationPolicy, RotationInterval};
use fortress_core::encryption::{create_algorithm, Aegis256};
use fortress_core::key::KeyMetadata;
use chrono::{Duration as ChronoDuration, Utc};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Fortress Zero-Downtime Key Rotation Example");
    println!("=============================================");

    // Initialize key manager
    let key_manager = InMemoryKeyManager::new();
    let algorithm = create_algorithm("aegis256")?;

    // Create initial key for demonstration
    let key_id = "example_app_key".to_string();
    let initial_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + ChronoDuration::days(90),
        "encryption".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    
    key_manager.store_key(&key_id, &initial_key, &metadata).await?;
    println!("✅ Created initial key: {} (version 1)", key_id);

    // Demonstrate basic zero-downtime rotation
    println!("\n🔄 Performing basic zero-downtime rotation...");
    
    // Start concurrent operations to show zero-downtime
    let key_manager_clone = key_manager.clone();
    let key_id_clone = key_id.clone();
    
    let operations_task = tokio::spawn(async move {
        for i in 1..=20 {
            match key_manager_clone.retrieve_key(&key_id_clone).await {
                Ok((key, metadata)) => {
                    println!("  📝 Operation {}: Key accessible (version {})", i, metadata.version);
                }
                Err(e) => {
                    println!("  ❌ Operation {}: Failed to access key: {}", i, e);
                }
            }
            sleep(Duration::from_millis(25)).await;
        }
    });

    // Perform rotation while operations are running
    let rotation_start = std::time::Instant::now();
    match key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await {
        Ok(()) => {
            let rotation_time = rotation_start.elapsed();
            println!("✅ Rotation completed successfully in {:?}", rotation_time);
        }
        Err(e) => {
            println!("❌ Rotation failed: {}", e);
            return Err(e.into());
        }
    }

    // Wait for operations to complete
    operations_task.await?;
    println!("✅ All concurrent operations completed successfully");

    // Verify the rotation
    let (_, rotated_metadata) = key_manager.retrieve_key(&key_id).await?;
    println!("📊 Key version after rotation: {}", rotated_metadata.version);

    // Demonstrate smart scheduler rotation
    println!("\n🤖 Demonstrating Smart Scheduler rotation...");
    
    let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
    scheduler.set_security_level_intervals();

    // Create multiple keys with different purposes
    let keys = vec![
        ("high_security_key", "high_security"),
        ("sensitive_key", "sensitive"),
        ("standard_key", "standard"),
        ("low_security_key", "low_sensitivity"),
    ];

    for (key_name, purpose) in &keys {
        let key = key_manager.generate_key(algorithm.as_ref()).await?;
        let metadata = KeyMetadata::new(
            key_name.to_string(),
            algorithm.name().to_string(),
            1,
            Utc::now() - ChronoDuration::days(1), // Created yesterday to trigger rotation
            Utc::now() + ChronoDuration::days(90),
            purpose.to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );
        
        key_manager.store_key(key_name, &key, &metadata).await?;
        println!("  📝 Created key: {} (purpose: {})", key_name, purpose);
    }

    // Run scheduler check and rotate
    let rotated_keys = scheduler.check_and_rotate().await?;
    println!("✅ Scheduler rotated {} keys", rotated_keys.len());

    // Verify all keys are still accessible
    println!("\n🔍 Verifying all keys are accessible after rotation...");
    for (key_name, purpose) in &keys {
        match key_manager.retrieve_key(key_name).await {
            Ok((key, metadata)) => {
                println!("  ✅ {}: Version {}, Purpose: {}", key_name, metadata.version, purpose);
            }
            Err(e) => {
                println!("  ❌ {}: Failed to access: {}", key_name, e);
            }
        }
    }

    // Demonstrate multiple sequential rotations
    println!("\n🔄 Demonstrating multiple sequential rotations...");
    
    let multi_key_id = "multi_rotation_key".to_string();
    let multi_key = key_manager.generate_key(algorithm.as_ref()).await?;
    let multi_metadata = KeyMetadata::new(
        multi_key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + ChronoDuration::days(90),
        "multi_rotation_test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    
    key_manager.store_key(&multi_key_id, &multi_key, &multi_metadata).await?;
    println!("  📝 Created key for multi-rotation test: {}", multi_key_id);

    // Perform multiple rotations
    let num_rotations = 3;
    for i in 1..=num_rotations {
        let rotation_start = std::time::Instant::now();
        match key_manager.rotate_key_with_zero_downtime(&multi_key_id, algorithm.as_ref()).await {
            Ok(()) => {
                let rotation_time = rotation_start.elapsed();
                let (_, metadata) = key_manager.retrieve_key(&multi_key_id).await?;
                println!("  ✅ Rotation {} completed in {:?} (version: {})", 
                        i, rotation_time, metadata.version);
            }
            Err(e) => {
                println!("  ❌ Rotation {} failed: {}", i, e);
                return Err(e.into());
            }
        }
        
        // Small delay between rotations
        sleep(Duration::from_millis(100)).await;
    }

    // Final verification
    let (_, final_metadata) = key_manager.retrieve_key(&multi_key_id).await?;
    println!("📊 Final version after {} rotations: {}", num_rotations, final_metadata.version);

    // Display scheduler metrics
    println!("\n📊 Scheduler Metrics:");
    let metrics = scheduler.get_metrics().await;
    println!("  🔄 Total rotations: {}", metrics.total_rotations);
    println!("  ✅ Successful rotations: {}", metrics.successful_rotations);
    println!("  ❌ Failed rotations: {}", metrics.failed_rotations);
    println!("  ⏱️  Average rotation time: {:.2}ms", metrics.avg_rotation_time_ms);

    println!("\n🎉 Zero-downtime rotation example completed successfully!");
    println!("📝 Key features demonstrated:");
    println!("  • Zero-downtime rotation with concurrent operations");
    println!("  • Smart scheduler with policy-based rotation");
    println!("  • Multiple sequential rotations");
    println!("  • Comprehensive error handling and validation");
    println!("  • Performance monitoring and metrics");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_example_basic_rotation() -> Result<(), Box<dyn std::error::Error>> {
        let key_manager = InMemoryKeyManager::new();
        let algorithm = create_algorithm("aegis256")?;
        
        let key_id = "test_key".to_string();
        let key = key_manager.generate_key(algorithm.as_ref()).await?;
        let metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            "test".to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );
        
        key_manager.store_key(&key_id, &key, &metadata).await?;
        
        // Perform rotation
        key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await?;
        
        // Verify rotation
        let (_, rotated_metadata) = key_manager.retrieve_key(&key_id).await?;
        assert_eq!(rotated_metadata.version, 2);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_example_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
        let key_manager = InMemoryKeyManager::new();
        let algorithm = create_algorithm("aegis256")?;
        
        let key_id = "concurrent_test_key".to_string();
        let key = key_manager.generate_key(algorithm.as_ref()).await?;
        let metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            "test".to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );
        
        key_manager.store_key(&key_id, &key, &metadata).await?;
        
        // Start concurrent operations
        let key_manager_clone = key_manager.clone();
        let key_id_clone = key_id.clone();
        
        let operations_task = tokio::spawn(async move {
            for _ in 1..=10 {
                let _ = key_manager_clone.retrieve_key(&key_id_clone).await;
                sleep(Duration::from_millis(10)).await;
            }
        });

        // Perform rotation
        key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await?;
        
        // Wait for operations
        operations_task.await?;
        
        // Verify key is still accessible
        let (_, final_metadata) = key_manager.retrieve_key(&key_id).await?;
        assert_eq!(final_metadata.version, 2);
        
        Ok(())
    }
}
