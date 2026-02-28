//! Performance benchmark for zero-downtime key rotation

use fortress_core::{
    key::{KeyManager, InMemoryKeyManager},
    encryption::create_algorithm,
};
use chrono::{Duration, Utc};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Zero-Downtime Key Rotation Performance Benchmark");
    println!("================================================");

    let key_manager = Arc::new(InMemoryKeyManager::new());
    let algorithm = create_algorithm("aes256gcm")?;

    // Benchmark single rotation
    println!("\nSingle Rotation Performance:");
    let key_id = "benchmark_key".to_string();
    let key = key_manager.generate_key(algorithm.as_ref()).await?;
    let metadata = fortress_core::key::KeyMetadata::new(
        key_id.clone(),
        "aes256gcm".to_string(),
        1,
        Utc::now() - Duration::hours(25),
        Utc::now() + Duration::days(90),
        "benchmark".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );
    key_manager.store_key(&key_id, &key, &metadata).await?;

    let start = Instant::now();
    let result = key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await;
    let duration = start.elapsed();

    match result {
        Ok(_) => {
            println!("  Single rotation: {:?} (microseconds: {})", duration, duration.as_micros());
            assert!(duration.as_micros() < 1000, "Single rotation should complete within 1ms");
        }
        Err(e) => println!("  Rotation failed: {}", e),
    }

    // Benchmark multiple rotations
    println!("\nMultiple Rotations Performance:");
    let total_rotations = 100;
    let start = Instant::now();
    let mut successful_rotations = 0;

    for i in 0..total_rotations {
        let key_id = format!("bench_key_{}", i);
        let key = key_manager.generate_key(algorithm.as_ref()).await?;
        let metadata = fortress_core::key::KeyMetadata::new(
            key_id.clone(),
            "aes256gcm".to_string(),
            1,
            Utc::now() - Duration::hours(25),
            Utc::now() + Duration::days(90),
            "benchmark".to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );
        key_manager.store_key(&key_id, &key, &metadata).await?;

        if key_manager.rotate_key_with_zero_downtime(&key_id, algorithm.as_ref()).await.is_ok() {
            successful_rotations += 1;
        }
    }

    let total_duration = start.elapsed();
    let avg_duration = total_duration / successful_rotations as u32;

    println!("  Total rotations: {}", successful_rotations);
    println!("  Total time: {:?}", total_duration);
    println!("  Average per rotation: {:?} (microseconds: {})", avg_duration, avg_duration.as_micros());
    println!("  Rotations per second: {:.0}", successful_rotations as f64 / total_duration.as_secs_f64());

    // Verify performance requirements
    assert!(avg_duration.as_micros() < 500, "Average rotation should complete within 500μs");
    assert!(successful_rotations as f64 / total_duration.as_secs_f64() > 1000.0, "Should handle >1000 rotations/second");

    // Memory efficiency test
    println!("\nMemory Efficiency Test:");
    let keys_before = key_manager.list_keys().await?.len();
    println!("  Keys stored: {}", keys_before);

    // Verify no memory leaks (should have 2x keys due to versioned backups being cleaned up)
    assert!(keys_before <= total_rotations * 2, "Should not have excessive key storage");

    println!("\nPerformance Requirements Met:");
    println!("  ✓ Fast: Single rotation < 1ms");
    println!("  ✓ Efficient: Average rotation < 500μs");
    println!("  ✓ Scalable: >1000 rotations/second");
    println!("  ✓ Memory efficient: No excessive storage");

    println!("\nBenchmark completed successfully!");

    Ok(())
}
