//! Zero-Downtime Key Rotation Example
//! 
//! This example demonstrates the complete zero-downtime key rotation mechanism with:
//! - Dual-key validation during transition
//! - Graceful rollback on failure
//! - Concurrent access during rotation
//! - Status tracking and monitoring

use fortress_core::{
    key::{KeyManager, InMemoryKeyManager},
    encryption::{create_algorithm, EncryptionAlgorithm},
};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Fortress Zero-Downtime Key Rotation Example");
    println!("==============================================");

    // Create key manager
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("AES256-GCM")?;

    // Create a test key for rotation
    let key_id = "production_data_key".to_string();
    let key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        "AES256-GCM".to_string(),
        1,
        Utc::now() - Duration::hours(25), // Created 25h ago - needs rotation
        Utc::now() + Duration::days(90),
        "production".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    key_manager.store_key(&key_id, &key, &metadata).await?;

    println!("✅ Created initial key (version: {})", metadata.version);

    // Demonstrate zero-downtime rotation
    println!("\n⚡ Starting Zero-Downtime Rotation...");
    
    // Show initial state
    let (_, initial_metadata) = key_manager.retrieve_key(&key_id).await?;
    println!("📊 Initial state:");
    println!("   - Key ID: {}", key_id);
    println!("   - Version: {}", initial_metadata.version);
    println!("   - Created: {}", initial_metadata.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("   - Purpose: {}", initial_metadata.purpose);

    // Step 1: Initiate key transition
    println!("\n🔄 Step 1: Initiating key transition...");
    let start_time = std::time::Instant::now();
    
    let new_version = key_manager.initiate_key_transition(&key_id, algorithm.as_ref()).await?;
    println!("✅ Transition initiated - new version: {}", new_version);
    
    // Show transition state
    let (_, transition_metadata) = key_manager.retrieve_key(&key_id).await?;
    println!("📊 Transition state:");
    println!("   - Primary key version: {}", transition_metadata.version);
    println!("   - Transition status: {:?}", transition_metadata.get_metadata("transition_status"));

    // Step 2: Validate dual keys
    println!("\n🔍 Step 2: Validating dual keys...");
    let dual_valid = key_manager.validate_dual_keys(&key_id, 1, new_version).await?;
    println!("✅ Dual-key validation: {}", if dual_valid { "PASSED" } else { "FAILED" });

    if dual_valid {
        // Step 3: Complete transition
        println!("\n🎯 Step 3: Completing transition...");
        key_manager.complete_key_transition(&key_id, new_version).await?;
        
        let rotation_time = start_time.elapsed();
        println!("✅ Transition completed in {:?}", rotation_time);
        
        // Show final state
        let (_, final_metadata) = key_manager.retrieve_key(&key_id).await?;
        println!("📊 Final state:");
        println!("   - Key ID: {}", key_id);
        println!("   - New version: {}", final_metadata.version);
        println!("   - Created: {}", final_metadata.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("   - Transition status: {:?}", final_metadata.get_metadata("transition_status"));
    } else {
        println!("❌ Dual-key validation failed - rolling back...");
        key_manager.rollback_key_transition(&key_id, 1, new_version).await?;
        println!("✅ Rollback completed");
    }

    // Demonstrate concurrent access during rotation
    println!("\n🔄 Testing Concurrent Access During Rotation...");
    test_concurrent_access(key_manager.clone(), &key_id, algorithm.clone()).await?;

    // Demonstrate failure recovery
    println!("\n🚨 Testing Failure Recovery...");
    test_failure_recovery(key_manager.clone(), &key_id, algorithm.clone()).await?;

    println!("\n🎉 Zero-Downtime Key Rotation Example Complete!");
    println!("==============================================");

    Ok(())
}

/// Test concurrent access during zero-downtime rotation
async fn test_concurrent_access(
    key_manager: Arc<InMemoryKeyManager>,
    key_id: &str,
    algorithm: Arc<dyn EncryptionAlgorithm>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("📡 Simulating concurrent operations during rotation...");

    let key_manager_clone = key_manager.clone();
    let key_id_clone = key_id.to_string();
    let algorithm_clone = algorithm.clone();

    // Spawn rotation task
    let rotation_task = tokio::spawn(async move {
        println!("🔄 Starting rotation in background...");
        let result = key_manager_clone.rotate_key_with_zero_downtime(&key_id_clone, algorithm_clone.as_ref()).await;
        println!("✅ Background rotation completed: {:?}", result.is_ok());
        result
    });

    // Spawn concurrent read tasks
    let key_manager_read = key_manager.clone();
    let key_id_read = key_id.to_string();
    let read_task = tokio::spawn(async move {
        println!("📖 Starting concurrent read operations...");
        let mut successful_reads = 0;
        for i in 0..20 {
            let result = key_manager_read.retrieve_key(&key_id_read).await;
            match result {
                Ok((_, metadata)) => {
                    successful_reads += 1;
                    println!("   Read #{}: SUCCESS (version: {})", i + 1, metadata.version);
                }
                Err(e) => {
                    println!("   Read #{}: FAILED - {}", i + 1, e);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        println!("📊 Concurrent reads completed: {}/20 successful", successful_reads);
        successful_reads
    });

    // Wait for both tasks to complete
    let rotation_result = rotation_task.await.unwrap()?;
    let successful_reads = read_task.await.unwrap();

    println!("📈 Concurrent Access Results:");
    println!("   - Rotation successful: {}", rotation_result.is_ok());
    println!("   - Successful reads: {}/20", successful_reads);
    println!("   - Availability maintained: {}", successful_reads >= 18); // Allow for some edge cases

    Ok(())
}

/// Test failure recovery during zero-downtime rotation
async fn test_failure_recovery(
    key_manager: Arc<InMemoryKeyManager>,
    key_id: &str,
    algorithm: Arc<dyn EncryptionAlgorithm>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing failure recovery mechanism...");

    // Get current version
    let current_version = key_manager.get_active_key_version(key_id).await?;
    println!("📊 Current key version: {}", current_version);

    // Manually initiate transition
    let new_version = key_manager.initiate_key_transition(key_id, algorithm.as_ref()).await?;
    println!("🔄 Transition initiated - new version: {}", new_version);

    // Simulate failure by deleting the new key
    let new_key_id = format!("{}_v{}", key_id, new_version);
    key_manager.delete_key(&new_key_id).await?;
    println!("💥 Simulated failure: deleted new key version");

    // Attempt zero-downtime rotation (should fail and rollback)
    let result = key_manager.rotate_key_with_zero_downtime(key_id, algorithm.as_ref()).await;
    
    match result {
        Ok(_) => {
            println!("❌ Expected rotation to fail, but it succeeded");
        }
        Err(e) => {
            println!("✅ Rotation failed as expected: {}", e);
        }
    }

    // Verify rollback occurred
    let recovered_version = key_manager.get_active_key_version(key_id).await?;
    println!("🔄 Recovered key version: {}", recovered_version);

    if recovered_version == current_version {
        println!("✅ Rollback successful - key version restored");
    } else {
        println!("❌ Rollback failed - expected version {}, got {}", current_version, recovered_version);
    }

    // Verify key is still accessible
    let retrieve_result = key_manager.retrieve_key(key_id).await;
    match retrieve_result {
        Ok((_, metadata)) => {
            println!("✅ Key still accessible after rollback (version: {})", metadata.version);
        }
        Err(e) => {
            println!("❌ Key not accessible after rollback: {}", e);
        }
    }

    Ok(())
}
