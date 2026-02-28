//! Simple zero-downtime rotation test

use fortress_core::{
    key::{KeyManager, InMemoryKeyManager},
    encryption::{create_algorithm, EncryptionAlgorithm},
};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Zero-Downtime Key Rotation");

    // Create key manager
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aes256gcm")?;

    // Create a test key
    let key_id = "test_key".to_string();
    let key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        "AES256-GCM".to_string(),
        1,
        Utc::now() - Duration::hours(25),
        Utc::now() + Duration::days(90),
        "test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    key_manager.store_key(&key_id, &key, &metadata).await?;

    println!("Created initial key (version: {})", metadata.version);

    // Test zero-downtime rotation
    println!("Starting zero-downtime rotation...");
    let start_time = std::time::Instant::now();
    
    let result = key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await;
    
    match result {
        Ok(_) => {
            let rotation_time = start_time.elapsed();
            println!("Zero-downtime rotation completed in {:?}", rotation_time);
            
            // Verify the key was rotated
            let (_, new_metadata) = key_manager.retrieve_key(&key_id).await?;
            println!("New key version: {}", new_metadata.version);
            
            if new_metadata.version > metadata.version {
                println!("Zero-downtime rotation successful!");
            } else {
                println!("Key version was not incremented");
            }
        }
        Err(e) => {
            println!("Zero-downtime rotation failed: {}", e);
        }
    }

    Ok(())
}
