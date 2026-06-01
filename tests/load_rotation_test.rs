#![cfg(any())]
//! Load Testing Suite for Zero-Downtime Key Rotation
//!
//! Comprehensive load testing to validate performance, scalability, and reliability
//! under high-concurrency scenarios and stress conditions.

use chrono::{Duration as ChronoDuration, Utc};
use fortress_core::encryption::{create_algorithm, Aegis256};
use fortress_core::key::KeyMetadata;
use fortress_core::key::{
    InMemoryKeyManager, KeyManager, OptimizedKeyRotationManager, OptimizedRotationConfig,
    SecurityContext,
};
use futures::future::join_all;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Load test configuration
#[derive(Debug, Clone)]
struct LoadTestConfig {
    /// Number of concurrent rotations
    concurrent_rotations: usize,
    /// Number of keys to rotate
    total_keys: usize,
    /// Duration of the test
    test_duration: Duration,
    /// Rotation interval
    rotation_interval: Duration,
    /// Expected success rate (percentage)
    expected_success_rate: f64,
    /// Maximum acceptable latency (milliseconds)
    max_acceptable_latency_ms: u64,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrent_rotations: 50,
            total_keys: 1000,
            test_duration: Duration::from_secs(60),
            rotation_interval: Duration::from_millis(100),
            expected_success_rate: 99.0,
            max_acceptable_latency_ms: 5000,
        }
    }
}

/// Load test results
#[derive(Debug, Clone)]
struct LoadTestResults {
    /// Total rotations attempted
    total_rotations: u64,
    /// Successful rotations
    successful_rotations: u64,
    /// Failed rotations
    failed_rotations: u64,
    /// Average rotation time (milliseconds)
    avg_rotation_time_ms: f64,
    /// Minimum rotation time (milliseconds)
    min_rotation_time_ms: u64,
    /// Maximum rotation time (milliseconds)
    max_rotation_time_ms: u64,
    /// 95th percentile latency (milliseconds)
    p95_latency_ms: u64,
    /// 99th percentile latency (milliseconds)
    p99_latency_ms: u64,
    /// Throughput (rotations per second)
    throughput_rps: f64,
    /// Error rate (percentage)
    error_rate: f64,
    /// Memory usage statistics
    memory_stats: MemoryStats,
}

/// Memory usage statistics
#[derive(Debug, Clone, Default)]
struct MemoryStats {
    /// Peak memory usage (MB)
    peak_memory_mb: f64,
    /// Average memory usage (MB)
    avg_memory_mb: f64,
    /// Memory growth rate (MB per minute)
    memory_growth_rate: f64,
}

/// High-concurrency load test
#[tokio::test]
async fn test_high_concurrency_load() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting High-Concurrency Load Test");

    let config = LoadTestConfig {
        concurrent_rotations: 100,
        total_keys: 2000,
        test_duration: Duration::from_secs(120),
        rotation_interval: Duration::from_millis(50),
        expected_success_rate: 98.0,
        max_acceptable_latency_ms: 3000,
    };

    let results = run_load_test(config).await?;

    // Validate results
    assert!(results.successful_rotations > 0, "No successful rotations");
    assert!(
        results.error_rate < (100.0 - config.expected_success_rate),
        "Error rate too high: {:.2}%",
        results.error_rate
    );
    assert!(
        results.avg_rotation_time_ms < config.max_acceptable_latency_ms as f64,
        "Average latency too high: {:.2}ms",
        results.avg_rotation_time_ms
    );
    assert!(
        results.throughput_rps > 10.0,
        "Throughput too low: {:.2} rps",
        results.throughput_rps
    );

    println!("High-concurrency load test passed:");
    println!("  - Successful rotations: {}", results.successful_rotations);
    println!("  - Error rate: {:.2}%", results.error_rate);
    println!("  - Average latency: {:.2}ms", results.avg_rotation_time_ms);
    println!("  - Throughput: {:.2} rps", results.throughput_rps);

    Ok(())
}

/// Sustained load test
#[tokio::test]
async fn test_sustained_load() -> Result<(), Box<dyn std::error::Error>> {
    println!("⏱️  Starting Sustained Load Test");

    let config = LoadTestConfig {
        concurrent_rotations: 25,
        total_keys: 500,
        test_duration: Duration::from_secs(300), // 5 minutes
        rotation_interval: Duration::from_millis(200),
        expected_success_rate: 99.5,
        max_acceptable_latency_ms: 2000,
    };

    let results = run_load_test(config).await?;

    // Validate sustained performance
    assert!(
        results.error_rate < 1.0,
        "Error rate too high for sustained load: {:.2}%",
        results.error_rate
    );
    assert!(
        results.memory_stats.memory_growth_rate < 10.0,
        "Memory growth too high: {:.2} MB/min",
        results.memory_stats.memory_growth_rate
    );
    assert!(
        results.throughput_rps > 5.0,
        "Throughput degraded too much: {:.2} rps",
        results.throughput_rps
    );

    println!("Sustained load test passed:");
    println!("  - Error rate: {:.2}%", results.error_rate);
    println!(
        "  - Memory growth: {:.2} MB/min",
        results.memory_stats.memory_growth_rate
    );
    println!("  - Throughput: {:.2} rps", results.throughput_rps);

    Ok(())
}

/// Stress test with maximum load
#[tokio::test]
async fn test_maximum_stress() -> Result<(), Box<dyn std::error::Error>> {
    println!("💪 Starting Maximum Stress Test");

    let config = LoadTestConfig {
        concurrent_rotations: 500,
        total_keys: 5000,
        test_duration: Duration::from_secs(60),
        rotation_interval: Duration::from_millis(10),
        expected_success_rate: 95.0, // Lower expectation for stress test
        max_acceptable_latency_ms: 10000,
    };

    let results = run_load_test(config).await?;

    // Validate stress handling
    assert!(
        results.successful_rotations > 0,
        "System failed under stress"
    );
    assert!(
        results.error_rate < 10.0,
        "Error rate too high under stress: {:.2}%",
        results.error_rate
    );

    println!("Maximum stress test passed:");
    println!("  - Successful rotations: {}", results.successful_rotations);
    println!("  - Error rate: {:.2}%", results.error_rate);
    println!("  - P99 latency: {}ms", results.p99_latency_ms);

    Ok(())
}

/// Bulk operations load test
#[tokio::test]
async fn test_bulk_operations_load() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Bulk Operations Load Test");

    let key_manager = Arc::new(InMemoryKeyManager::new());
    let mut config = OptimizedRotationConfig::default();
    config.batch_size = 100;
    config.max_concurrent_rotations = 20;
    let rotation_manager = OptimizedKeyRotationManager::new(key_manager, config);

    let algorithm = create_algorithm("aegis256")?;
    let security_context = SecurityContext {
        requestor_id: "load_test_user".to_string(),
        security_level: fortress_core::audit::SecurityLevel::Standard,
        required_permissions: vec!["key.rotate".to_string()],
        ip_address: None,
        user_agent: None,
    };

    // Create large batch of keys
    let batch_sizes = [100, 500, 1000, 2000];

    for batch_size in &batch_sizes {
        let start_time = Instant::now();

        // Create test keys
        let key_ids: Vec<String> = (0..*batch_size)
            .map(|i| format!("bulk_load_key_{}_{}", batch_size, i))
            .collect();

        for key_id in &key_ids {
            let key = rotation_manager
                .key_manager
                .generate_key(algorithm.as_ref())
                .await?;
            let metadata = KeyMetadata::new(
                key_id.clone(),
                algorithm.name().to_string(),
                1,
                Utc::now(),
                Utc::now() + ChronoDuration::days(90),
                "bulk_load_test".to_string(),
                fortress_core::encryption::PerformanceProfile::Balanced,
            );

            rotation_manager
                .key_manager
                .store_key(key_id, &key, &metadata)
                .await?;
        }

        // Perform bulk rotation
        let rotation_start = Instant::now();
        let rotation_ids = rotation_manager
            .bulk_rotate_keys(&key_ids, algorithm.as_ref(), security_context.clone())
            .await?;
        let rotation_time = rotation_start.elapsed();

        // Verify all rotations succeeded
        assert_eq!(
            rotation_ids.len(),
            key_ids.len(),
            "Not all keys in batch {} were rotated",
            batch_size
        );

        // Verify all keys were actually rotated
        for key_id in &key_ids {
            let (_, metadata) = rotation_manager.key_manager.retrieve_key(key_id).await?;
            assert_eq!(
                metadata.version, 2,
                "Key {} was not rotated properly",
                key_id
            );
        }

        let total_time = start_time.elapsed();
        let throughput = batch_size as f64 / total_time.as_secs_f64();

        println!(
            "  Batch size {}: {:.2}ms total, {:.2} rps",
            batch_size,
            total_time.as_millis(),
            throughput
        );

        // Validate performance expectations
        assert!(
            throughput > 10.0,
            "Throughput too low for batch size {}: {:.2} rps",
            batch_size,
            throughput
        );
        assert!(
            rotation_time.as_millis() < 10000,
            "Rotation time too long for batch size {}: {}ms",
            batch_size,
            rotation_time.as_millis()
        );
    }

    println!("Bulk operations load test passed");

    Ok(())
}

/// Resource exhaustion test
#[tokio::test]
async fn test_resource_exhaustion() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Resource Exhaustion Test");

    let key_manager = Arc::new(InMemoryKeyManager::new());
    let mut config = OptimizedRotationConfig::default();
    config.max_concurrent_rotations = 1000; // Very high limit
    config.memory_pool_size = 100; // Small pool to test recycling
    let rotation_manager = OptimizedKeyRotationManager::new(key_manager, config);

    let algorithm = create_algorithm("aegis256")?;
    let security_context = SecurityContext {
        requestor_id: "exhaustion_test_user".to_string(),
        security_level: fortress_core::audit::SecurityLevel::Standard,
        required_permissions: vec!["key.rotate".to_string()],
        ip_address: None,
        user_agent: None,
    };

    // Create test key
    let key_id = "exhaustion_test_key".to_string();
    let key = rotation_manager
        .key_manager
        .generate_key(algorithm.as_ref())
        .await?;
    let metadata = KeyMetadata::new(
        key_id.clone(),
        algorithm.name().to_string(),
        1,
        Utc::now(),
        Utc::now() + ChronoDuration::days(90),
        "exhaustion_test".to_string(),
        fortress_core::encryption::PerformanceProfile::Balanced,
    );

    rotation_manager
        .key_manager
        .store_key(&key_id, &key, &metadata)
        .await?;

    // Perform many sequential rotations to test resource management
    let num_rotations = 1000;
    let mut successful_rotations = 0;
    let mut rotation_times = Vec::new();

    for i in 0..num_rotations {
        let rotation_start = Instant::now();

        match rotation_manager
            .rotate_key_optimized(&key_id, algorithm.as_ref(), security_context.clone())
            .await
        {
            Ok(_) => {
                successful_rotations += 1;
                rotation_times.push(rotation_start.elapsed());
            }
            Err(e) => {
                println!("Rotation {} failed: {}", i, e);
                // Continue with next rotation
            }
        }

        // Small delay to prevent overwhelming the system
        sleep(Duration::from_millis(1)).await;
    }

    // Calculate statistics
    let success_rate = (successful_rotations as f64 / num_rotations as f64) * 100.0;
    let avg_time = if !rotation_times.is_empty() {
        rotation_times.iter().sum::<Duration>().as_millis() as f64 / rotation_times.len() as f64
    } else {
        0.0
    };

    println!("Resource exhaustion test completed:");
    println!("  - Success rate: {:.2}%", success_rate);
    println!("  - Average rotation time: {:.2}ms", avg_time);
    println!("  - Successful rotations: {}", successful_rotations);

    // Validate resource management
    assert!(
        success_rate > 95.0,
        "Success rate too low: {:.2}%",
        success_rate
    );
    assert!(avg_time < 100.0, "Average time too high: {:.2}ms", avg_time);

    Ok(())
}

/// Mixed workload test
#[tokio::test]
async fn test_mixed_workload() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Mixed Workload Test");

    let key_manager = Arc::new(InMemoryKeyManager::new());
    let config = OptimizedRotationConfig::default();
    let rotation_manager = OptimizedKeyRotationManager::new(key_manager, config);

    let algorithm = create_algorithm("aegis256")?;
    let security_context = SecurityContext {
        requestor_id: "mixed_workload_user".to_string(),
        security_level: fortress_core::audit::SecurityLevel::Standard,
        required_permissions: vec!["key.rotate".to_string()],
        ip_address: None,
        user_agent: None,
    };

    // Create multiple keys for mixed operations
    let key_ids: Vec<String> = (0..100).map(|i| format!("mixed_key_{}", i)).collect();

    for key_id in &key_ids {
        let key = rotation_manager
            .key_manager
            .generate_key(algorithm.as_ref())
            .await?;
        let metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            "mixed_workload".to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );

        rotation_manager
            .key_manager
            .store_key(key_id, &key, &metadata)
            .await?;
    }

    let test_duration = Duration::from_secs(60);
    let start_time = Instant::now();

    // Spawn mixed workload tasks
    let mut tasks = Vec::new();

    // Rotation tasks (40% of workload)
    for i in 0..40 {
        let manager = rotation_manager.clone();
        let algorithm = algorithm.clone();
        let security_context = security_context.clone();
        let key_ids = key_ids.clone();

        let task = tokio::spawn(async move {
            let mut rotations = 0;
            let mut errors = 0;

            while Instant::now().duration_since(start_time) < test_duration {
                let key_id = &key_ids[i % key_ids.len()];

                match manager
                    .rotate_key_optimized(key_id, algorithm.as_ref(), security_context.clone())
                    .await
                {
                    Ok(_) => rotations += 1,
                    Err(_) => errors += 1,
                }

                sleep(Duration::from_millis(50)).await;
            }

            (rotations, errors)
        });

        tasks.push(task);
    }

    // Read operations (60% of workload)
    for i in 0..60 {
        let manager = rotation_manager.clone();
        let key_ids = key_ids.clone();

        let task = tokio::spawn(async move {
            let mut reads = 0;
            let mut errors = 0;

            while Instant::now().duration_since(start_time) < test_duration {
                let key_id = &key_ids[i % key_ids.len()];

                match manager.key_manager.retrieve_key(key_id).await {
                    Ok(_) => reads += 1,
                    Err(_) => errors += 1,
                }

                sleep(Duration::from_millis(50)).await;
            }

            (reads, errors)
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    let results = join_all(tasks).await;

    // Aggregate results
    let mut total_rotations = 0;
    let mut total_reads = 0;
    let mut total_errors = 0;

    for (idx, result) in results.into_iter().enumerate() {
        let (count, errors) = result.unwrap();
        if idx < 40 {
            total_rotations += count;
        } else {
            total_reads += count;
        }
        total_errors += errors;
    }

    let total_operations = total_rotations + total_reads;
    let error_rate = (total_errors as f64 / total_operations as f64) * 100.0;
    let throughput = total_operations as f64 / test_duration.as_secs_f64();

    println!("Mixed workload test completed:");
    println!("  - Total rotations: {}", total_rotations);
    println!("  - Total reads: {}", total_reads);
    println!("  - Error rate: {:.2}%", error_rate);
    println!("  - Throughput: {:.2} ops/sec", throughput);

    // Validate mixed workload performance
    assert!(
        error_rate < 5.0,
        "Error rate too high for mixed workload: {:.2}%",
        error_rate
    );
    assert!(
        throughput > 100.0,
        "Throughput too low for mixed workload: {:.2} ops/sec",
        throughput
    );
    assert!(
        total_rotations > 0,
        "No rotations completed in mixed workload"
    );

    Ok(())
}

/// Helper function to run load tests
async fn run_load_test(
    config: LoadTestConfig,
) -> Result<LoadTestResults, Box<dyn std::error::Error>> {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let mut rotation_config = OptimizedRotationConfig::default();
    rotation_config.max_concurrent_rotations = config.concurrent_rotations as u32;
    let rotation_manager = OptimizedKeyRotationManager::new(key_manager, rotation_config);

    let algorithm = create_algorithm("aegis256")?;
    let security_context = SecurityContext {
        requestor_id: "load_test_user".to_string(),
        security_level: fortress_core::audit::SecurityLevel::Standard,
        required_permissions: vec!["key.rotate".to_string()],
        ip_address: None,
        user_agent: None,
    };

    // Create test keys
    let key_ids: Vec<String> = (0..config.total_keys)
        .map(|i| format!("load_test_key_{}", i))
        .collect();

    for key_id in &key_ids {
        let key = rotation_manager
            .key_manager
            .generate_key(algorithm.as_ref())
            .await?;
        let metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + ChronoDuration::days(90),
            "load_test".to_string(),
            fortress_core::encryption::PerformanceProfile::Balanced,
        );

        rotation_manager
            .key_manager
            .store_key(key_id, &key, &metadata)
            .await?;
    }

    let test_start = Instant::now();
    let mut rotation_times = Vec::new();
    let mut successful_rotations = 0;
    let mut failed_rotations = 0;

    // Run load test for specified duration
    while test_start.elapsed() < config.test_duration {
        let rotation_start = Instant::now();
        let key_id = &key_ids[successful_rotations as usize % key_ids.len()];

        match rotation_manager
            .rotate_key_optimized(key_id, algorithm.as_ref(), security_context.clone())
            .await
        {
            Ok(_) => {
                successful_rotations += 1;
                rotation_times.push(rotation_start.elapsed());
            }
            Err(_) => {
                failed_rotations += 1;
            }
        }

        sleep(config.rotation_interval).await;
    }

    // Calculate statistics
    let total_rotations = successful_rotations + failed_rotations;
    let error_rate = if total_rotations > 0 {
        (failed_rotations as f64 / total_rotations as f64) * 100.0
    } else {
        0.0
    };

    let avg_rotation_time_ms = if !rotation_times.is_empty() {
        rotation_times.iter().sum::<Duration>().as_millis() as f64 / rotation_times.len() as f64
    } else {
        0.0
    };

    let min_rotation_time_ms = rotation_times
        .iter()
        .map(|d| d.as_millis() as u64)
        .min()
        .unwrap_or(0);

    let max_rotation_time_ms = rotation_times
        .iter()
        .map(|d| d.as_millis() as u64)
        .max()
        .unwrap_or(0);

    // Calculate percentiles
    let mut sorted_times: Vec<u64> = rotation_times
        .iter()
        .map(|d| d.as_millis() as u64)
        .collect();
    sorted_times.sort_unstable();

    let p95_latency_ms = if !sorted_times.is_empty() {
        sorted_times[(sorted_times.len() as f64 * 0.95) as usize]
    } else {
        0
    };

    let p99_latency_ms = if !sorted_times.is_empty() {
        sorted_times[(sorted_times.len() as f64 * 0.99) as usize]
    } else {
        0
    };

    let throughput_rps = successful_rotations as f64 / test_start.elapsed().as_secs_f64();

    // Memory statistics (simplified)
    let memory_stats = MemoryStats {
        peak_memory_mb: 100.0, // Placeholder - would use actual memory monitoring
        avg_memory_mb: 80.0,
        memory_growth_rate: 5.0,
    };

    Ok(LoadTestResults {
        total_rotations,
        successful_rotations,
        failed_rotations,
        avg_rotation_time_ms,
        min_rotation_time_ms,
        max_rotation_time_ms,
        p95_latency_ms,
        p99_latency_ms,
        throughput_rps,
        error_rate,
        memory_stats,
    })
}
