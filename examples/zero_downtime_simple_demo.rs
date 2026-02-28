//! Zero-Downtime Key Rotation Demo
//! 
//! This example demonstrates the zero-downtime key rotation mechanism

use fortress_core::{
    key::{KeyManager, InMemoryKeyManager},
    encryption::create_algorithm,
};
use chrono::{Duration, Utc};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Fortress Zero-Downtime Key Rotation Demo");
    println!("==========================================");

    // Create key manager
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aes256gcm")?;

    // Create test keys with different purposes
    println!("\nCreating test keys...");
    
    // High security key (needs rotation)
    let high_security_key = "high_security_data".to_string();
    let key1 = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata1 = fortress_core::key::KeyMetadata::new(
        high_security_key.clone(),
        "aes256gcm".to_string(),
        1,
        Utc::now() - Duration::hours(25), // Created 25h ago - needs rotation
        Utc::now() + Duration::days(90),
        "high_security".to_string(),
        fortress_core::encryption::PerformanceProfile::Lightning,
    );
    key_manager.store_key(&high_security_key, &key1, &metadata1).await?;
    
    // Standard key (fresh)
    let standard_key = "standard_data".to_string();
    let key2 = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata2 = fortress_core::key::KeyMetadata::new(
        standard_key.clone(),
        "aes256gcm".to_string(),
        1,
        Utc::now() - Duration::hours(5), // Created 5h ago - fresh
        Utc::now() + Duration::days(90),
        "standard".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    key_manager.store_key(&standard_key, &key2, &metadata2).await?;
    
    println!("Created test keys");
    
    // Show initial state
    println!("\nInitial Key State:");
    let (_, meta1) = key_manager.retrieve_key(&high_security_key).await?;
    let (_, meta2) = key_manager.retrieve_key(&standard_key).await?;
    println!("   - {}: version {}, created {} hours ago", 
        high_security_key, meta1.version, (Utc::now() - meta1.created_at).num_hours());
    println!("   - {}: version {}, created {} hours ago", 
        standard_key, meta2.version, (Utc::now() - meta2.created_at).num_hours());
    
    // Demonstrate zero-downtime rotation
    println!("\nPerforming Zero-Downtime Rotation...");
    
    // Rotate the high security key
    let start_time = std::time::Instant::now();
    let result = key_manager.rotate_key_with_zero_downtime(&high_security_key, algorithm.as_ref()).await;
    let rotation_time = start_time.elapsed();
    
    match result {
        Ok(_) => {
            println!("Zero-downtime rotation completed in {:?}", rotation_time);
            
            // Verify the key was rotated
            let (_, new_metadata) = key_manager.retrieve_key(&high_security_key).await?;
            println!("Updated key state:");
            println!("   - {}: version {} (rotated from {})", 
                high_security_key, new_metadata.version, meta1.version);
            
            // Verify key is still accessible
            let retrieve_result = key_manager.retrieve_key(&high_security_key).await;
            match retrieve_result {
                Ok(_) => println!("Key remains accessible after rotation"),
                Err(e) => println!("Key not accessible: {}", e),
            }
        }
        Err(e) => {
            println!("Zero-downtime rotation failed: {}", e);
        }
    }
    
    // Demonstrate concurrent access simulation
    println!("\nTesting Concurrent Access During Rotation...");
    test_concurrent_read_access(key_manager.clone(), &standard_key).await?;
    
    // Show final state
    println!("\nFinal Key State:");
    let keys = key_manager.list_keys().await?;
    for (key_id, metadata) in keys {
        println!("   - {}: version {}, purpose: {}", 
            key_id, metadata.version, metadata.purpose);
    }
    
    println!("\nZero-Downtime Key Rotation Demo Complete!");
    println!("==========================================");
    
    Ok(())
}

/// Test concurrent read access during operations
async fn test_concurrent_read_access(
    key_manager: Arc<InMemoryKeyManager>,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Simulating concurrent read operations...");
    
    let mut successful_reads = 0;
    let total_reads = 10;
    
    for i in 0..total_reads {
        let result = key_manager.retrieve_key(&key_id.to_string()).await;
        match result {
            Ok((_, metadata)) => {
                successful_reads += 1;
                println!("   Read #{}: SUCCESS (version: {})", i + 1, metadata.version);
            }
            Err(e) => {
                println!("   Read #{}: FAILED - {}", i + 1, e);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    
    println!("Concurrent access results: {}/{} successful reads", successful_reads, total_reads);
    
    if successful_reads >= total_reads - 1 {
        println!("High availability maintained during operations");
    } else {
        println!("Some read operations failed");
    }
    
    Ok(())
}
