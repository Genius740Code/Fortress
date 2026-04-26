//! Smart Key Rotation System Demo
//! 
//! This example demonstrates the complete smart key rotation system with:
//! - Zero-downtime rotation
//! - Comprehensive rotation policies
//! - Automated scheduling

use fortress_core::{
    key::{KeyManager, SmartKeyRotationScheduler, RotationScheduler, RotationPolicy, InMemoryKeyManager},
    encryption::{create_algorithm, Aegis256},
};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Fortress Smart Key Rotation System Demo");
    println!("==========================================");

    // Create key manager
    let key_manager = Arc::new(InMemoryKeyManager::new());
    
    // Demonstrate Smart Key Rotation Scheduler
    println!("\nSmart Key Rotation Scheduler");
    let mut smart_scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
    
    // Set security level intervals
    smart_scheduler.set_security_level_intervals();
    
    // Create test keys with different purposes
    let algorithm = create_algorithm("chacha20poly1305")?;
    
    // High security key (23h rotation)
    let high_security_key = "high_security_data".to_string();
    let key1 = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata1 = fortress_core::key::KeyMetadata::new(
        high_security_key.clone(),
        "ChaCha20Poly1305".to_string(),
        1,
        Utc::now() - Duration::hours(24), // Created 24h ago - should rotate
        Utc::now() + Duration::days(90),
        "high_security".to_string(),
        fortress_core::encryption::PerformanceProfile::Lightning,
    );
    key_manager.store_key(&high_security_key, &key1, &metadata1).await?;
    
    // Standard key (30d rotation)
    let standard_key = "standard_data".to_string();
    let key2 = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata2 = fortress_core::key::KeyMetadata::new(
        standard_key.clone(),
        "ChaCha20Poly1305".to_string(),
        1,
        Utc::now() - Duration::days(35), // Created 35d ago - should rotate
        Utc::now() + Duration::days(90),
        "standard".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    key_manager.store_key(&standard_key, &key2, &metadata2).await?;
    
    // Low sensitivity key (90d rotation)
    let low_sensitivity_key = "low_sensitivity_data".to_string();
    let key3 = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata3 = fortress_core::key::KeyMetadata::new(
        low_sensitivity_key.clone(),
        "ChaCha20Poly1305".to_string(),
        1,
        Utc::now() - Duration::days(30), // Created 30d ago - should NOT rotate
        Utc::now() + Duration::days(90),
        "low_sensitivity".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    key_manager.store_key(&low_sensitivity_key, &key3, &metadata3).await?;
    
    println!("Created test keys with different security levels");
    
    // Check and rotate keys
    println!("\nChecking and rotating keys...");
    let rotated_keys = smart_scheduler.check_and_rotate().await?;
    
    println!("Rotation Results:");
    println!("   Keys rotated: {}", rotated_keys.len());
    for (key_id, metadata) in &rotated_keys {
        println!("   - {} (purpose: {}, version: {})", key_id, metadata.purpose, metadata.version);
    }
    
    // Get rotation metrics
    let metrics = smart_scheduler.get_metrics().await;
    println!("\nRotation Metrics:");
    println!("   Total rotations: {}", metrics.total_rotations);
    println!("   Successful: {}", metrics.successful_rotations);
    println!("   Failed: {}", metrics.failed_rotations);
    
    // Demonstrate Policy-Based Rotation Scheduler
    println!("\nPolicy-Based Rotation Scheduler");
    let mut policy_scheduler = RotationScheduler::new(key_manager.clone());
    
    // Show default policies
    let policies = policy_scheduler.get_policies().await;
    println!("Default Rotation Policies:");
    for policy in &policies {
        println!("   - {}: {} ({})", 
            policy.name, 
            policy.description, 
            policy.interval.description()
        );
    }
    
    // Test policy-based rotation
    println!("\nRunning policy-based rotation check...");
    let policy_rotated_keys = policy_scheduler.check_rotation_now().await?;
    
    println!("Policy Rotation Results:");
    println!("   Keys rotated: {}", policy_rotated_keys.len());
    for (key_id, metadata) in &policy_rotated_keys {
        println!("   - {} (purpose: {}, version: {})", key_id, metadata.purpose, metadata.version);
    }
    
    // Demonstrate zero-downtime rotation
    println!("\nZero-Downtime Rotation Demo");
    let test_key = "zero_downtime_test".to_string();
    let key4 = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata4 = fortress_core::key::KeyMetadata::new(
        test_key.clone(),
        "ChaCha20Poly1305".to_string(),
        1,
        Utc::now() - Duration::hours(25), // Expired - should rotate
        Utc::now() + Duration::days(90),
        "pii".to_string(),
        fortress_core::encryption::PerformanceProfile::Lightning,
    );
    key_manager.store_key(&test_key, &key4, &metadata4).await?;
    
    println!("Created expired key for zero-downtime test");
    
    // Force rotate with zero-downtime
    let start_time = std::time::Instant::now();
    key_manager.rotate_key_with_zero_downtime(&test_key, algorithm.as_ref()).await?;
    let rotation_time = start_time.elapsed();
    
    println!("Zero-downtime rotation completed in {:?}", rotation_time);
    
    // Verify key is still available
    let (_, new_metadata) = key_manager.retrieve_key(&test_key).await?;
    println!("Key still available after rotation (new version: {})", new_metadata.version);
    
    println!("\nSmart Key Rotation System Demo Complete!");
    println!("==========================================");
    
    Ok(())
}
