//! Key Rotation Performance Benchmarks
//!
//! Comprehensive benchmarks for zero-downtime key rotation performance
//! under various load conditions and scenarios.

use chrono::{Duration as ChronoDuration, Utc};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use fortress_core::encryption::{create_algorithm, Aegis256};
use fortress_core::key::KeyMetadata;
use fortress_core::key::{
    InMemoryKeyManager, KeyManager, OptimizedKeyRotationManager, OptimizedRotationConfig,
    SecurityContext,
};
use futures::future::join_all;
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Benchmark basic rotation performance
fn bench_basic_rotation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("basic_rotation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let key_manager = Arc::new(InMemoryKeyManager::new());
                let config = OptimizedRotationConfig::default();
                let rotation_manager = OptimizedKeyRotationManager::new(key_manager, config);

                let algorithm = create_algorithm("aegis256").unwrap();
                let security_context = SecurityContext {
                    requestor_id: "benchmark_user".to_string(),
                    security_level: fortress_core::audit::SecurityLevel::Low,
                    required_permissions: vec!["key.rotate".to_string()],
                    ip_address: None,
                    user_agent: None,
                };

                // Create test key
                let key_id = "benchmark_key".to_string();
                let key = rotation_manager
                    .key_manager
                    .generate_key(black_box(algorithm.as_ref()))
                    .await
                    .unwrap();
                let metadata = KeyMetadata::new(
                    key_id.clone(),
                    algorithm.name().to_string(),
                    1,
                    Utc::now(),
                    Utc::now() + ChronoDuration::days(90),
                    "benchmark".to_string(),
                    fortress_core::encryption::PerformanceProfile::Balanced,
                );

                rotation_manager
                    .key_manager
                    .store_key(&key_id, &key, &metadata)
                    .await
                    .unwrap();

                // Perform rotation
                let result = rotation_manager
                    .rotate_key_optimized(
                        black_box(&key_id),
                        black_box(algorithm.as_ref()),
                        black_box(security_context),
                    )
                    .await;

                result.unwrap()
            })
        })
    });
}

/// Benchmark concurrent rotations
fn bench_concurrent_rotations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_rotations");

    for concurrent_count in [1, 5, 10, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent", concurrent_count),
            concurrent_count,
            |b, &concurrent_count| {
                b.iter(|| {
                    rt.block_on(async {
                        let key_manager = Arc::new(InMemoryKeyManager::new());
                        let mut config = OptimizedRotationConfig::default();
                        config.max_concurrent_rotations = concurrent_count as u32;
                        let rotation_manager =
                            OptimizedKeyRotationManager::new(key_manager, config);

                        let algorithm = create_algorithm("aegis256").unwrap();
                        let security_context = SecurityContext {
                            requestor_id: "benchmark_user".to_string(),
                            security_level: fortress_core::audit::SecurityLevel::Low,
                            required_permissions: vec!["key.rotate".to_string()],
                            ip_address: None,
                            user_agent: None,
                        };

                        // Create multiple test keys
                        let key_ids: Vec<String> = (0..concurrent_count)
                            .map(|i| format!("concurrent_key_{}", i))
                            .collect();

                        for key_id in &key_ids {
                            let key = rotation_manager
                                .key_manager
                                .generate_key(algorithm.as_ref())
                                .await
                                .unwrap();
                            let metadata = KeyMetadata::new(
                                key_id.clone(),
                                algorithm.name().to_string(),
                                1,
                                Utc::now(),
                                Utc::now() + ChronoDuration::days(90),
                                "benchmark".to_string(),
                                fortress_core::encryption::PerformanceProfile::Balanced,
                            );

                            rotation_manager
                                .key_manager
                                .store_key(key_id, &key, &metadata)
                                .await
                                .unwrap();
                        }

                        // Perform concurrent rotations
                        let tasks: Vec<_> = key_ids
                            .into_iter()
                            .map(|key_id| {
                                let manager = rotation_manager.clone();
                                let algorithm = algorithm.clone();
                                let security_context = security_context.clone();

                                async move {
                                    manager
                                        .rotate_key_optimized(
                                            &key_id,
                                            algorithm.as_ref(),
                                            security_context,
                                        )
                                        .await
                                }
                            })
                            .collect();

                        let results = join_all(tasks).await;

                        // Verify all rotations succeeded
                        for result in results {
                            black_box(result.unwrap());
                        }
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark bulk rotation performance
fn bench_bulk_rotation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("bulk_rotation");

    for batch_size in [10, 50, 100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("bulk", batch_size),
            batch_size,
            |b, &batch_size| {
                b.iter(|| {
                    rt.block_on(async {
                        let key_manager = Arc::new(InMemoryKeyManager::new());
                        let mut config = OptimizedRotationConfig::default();
                        config.batch_size = batch_size;
                        let rotation_manager =
                            OptimizedKeyRotationManager::new(key_manager, config);

                        let algorithm = create_algorithm("aegis256").unwrap();
                        let security_context = SecurityContext {
                            requestor_id: "benchmark_user".to_string(),
                            security_level: fortress_core::audit::SecurityLevel::Low,
                            required_permissions: vec!["key.rotate".to_string()],
                            ip_address: None,
                            user_agent: None,
                        };

                        // Create batch of test keys
                        let key_ids: Vec<String> =
                            (0..batch_size).map(|i| format!("bulk_key_{}", i)).collect();

                        for key_id in &key_ids {
                            let key = rotation_manager
                                .key_manager
                                .generate_key(algorithm.as_ref())
                                .await
                                .unwrap();
                            let metadata = KeyMetadata::new(
                                key_id.clone(),
                                algorithm.name().to_string(),
                                1,
                                Utc::now(),
                                Utc::now() + ChronoDuration::days(90),
                                "benchmark".to_string(),
                                fortress_core::encryption::PerformanceProfile::Balanced,
                            );

                            rotation_manager
                                .key_manager
                                .store_key(key_id, &key, &metadata)
                                .await
                                .unwrap();
                        }

                        // Perform bulk rotation
                        let results = rotation_manager
                            .bulk_rotate_keys(
                                black_box(&key_ids),
                                black_box(algorithm.as_ref()),
                                black_box(security_context),
                            )
                            .await;

                        black_box(results.unwrap().len())
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark memory usage and efficiency
fn bench_memory_efficiency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("memory_efficiency", |b| {
        b.iter(|| {
            rt.block_on(async {
                let key_manager = Arc::new(InMemoryKeyManager::new());
                let mut config = OptimizedRotationConfig::default();
                config.memory_pool_size = 100;
                let rotation_manager = OptimizedKeyRotationManager::new(key_manager, config);

                let algorithm = create_algorithm("aegis256").unwrap();
                let security_context = SecurityContext {
                    requestor_id: "benchmark_user".to_string(),
                    security_level: fortress_core::audit::SecurityLevel::Low,
                    required_permissions: vec!["key.rotate".to_string()],
                    ip_address: None,
                    user_agent: None,
                };

                // Create test key
                let key_id = "memory_test_key".to_string();
                let key = rotation_manager
                    .key_manager
                    .generate_key(black_box(algorithm.as_ref()))
                    .await
                    .unwrap();
                let metadata = KeyMetadata::new(
                    key_id.clone(),
                    algorithm.name().to_string(),
                    1,
                    Utc::now(),
                    Utc::now() + ChronoDuration::days(90),
                    "benchmark".to_string(),
                    fortress_core::encryption::PerformanceProfile::Balanced,
                );

                rotation_manager
                    .key_manager
                    .store_key(&key_id, &key, &metadata)
                    .await
                    .unwrap();

                // Perform multiple rotations to test memory pooling
                for i in 0..10 {
                    let result = rotation_manager
                        .rotate_key_optimized(
                            black_box(&key_id),
                            black_box(algorithm.as_ref()),
                            black_box(security_context.clone()),
                        )
                        .await;

                    black_box(result.unwrap());
                }
            })
        })
    });
}

/// Benchmark security overhead
fn bench_security_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("security_overhead");

    for security_enabled in [false, true].iter() {
        group.bench_with_input(
            BenchmarkId::new("security", security_enabled),
            security_enabled,
            |b, &security_enabled| {
                b.iter(|| {
                    rt.block_on(async {
                        let key_manager = Arc::new(InMemoryKeyManager::new());
                        let mut config = OptimizedRotationConfig::default();
                        config.enable_security_hardening = security_enabled;
                        let rotation_manager =
                            OptimizedKeyRotationManager::new(key_manager, config);

                        let algorithm = create_algorithm("aegis256").unwrap();
                        let security_context = SecurityContext {
                            requestor_id: "benchmark_user".to_string(),
                            security_level: fortress_core::audit::SecurityLevel::High,
                            required_permissions: vec![
                                "key.rotate".to_string(),
                                "key.admin".to_string(),
                            ],
                            ip_address: Some("127.0.0.1".to_string()),
                            user_agent: Some("benchmark_client".to_string()),
                        };

                        // Create test key
                        let key_id = "security_test_key".to_string();
                        let key = rotation_manager
                            .key_manager
                            .generate_key(black_box(algorithm.as_ref()))
                            .await
                            .unwrap();
                        let metadata = KeyMetadata::new(
                            key_id.clone(),
                            algorithm.name().to_string(),
                            1,
                            Utc::now(),
                            Utc::now() + ChronoDuration::days(90),
                            "benchmark".to_string(),
                            fortress_core::encryption::PerformanceProfile::Balanced,
                        );

                        rotation_manager
                            .key_manager
                            .store_key(&key_id, &key, &metadata)
                            .await
                            .unwrap();

                        // Perform rotation
                        let result = rotation_manager
                            .rotate_key_optimized(
                                black_box(&key_id),
                                black_box(algorithm.as_ref()),
                                black_box(security_context),
                            )
                            .await;

                        black_box(result.unwrap())
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark timeout handling
fn bench_timeout_handling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("timeout_handling");

    for timeout_secs in [1, 5, 10, 30].iter() {
        group.bench_with_input(
            BenchmarkId::new("timeout", timeout_secs),
            timeout_secs,
            |b, &timeout_secs| {
                b.iter(|| {
                    rt.block_on(async {
                        let key_manager = Arc::new(InMemoryKeyManager::new());
                        let mut config = OptimizedRotationConfig::default();
                        config.backup_timeout_secs = timeout_secs;
                        config.validation_timeout_secs = timeout_secs / 2;
                        config.post_switch_timeout_secs = timeout_secs / 3;
                        let rotation_manager =
                            OptimizedKeyRotationManager::new(key_manager, config);

                        let algorithm = create_algorithm("aegis256").unwrap();
                        let security_context = SecurityContext {
                            requestor_id: "benchmark_user".to_string(),
                            security_level: fortress_core::audit::SecurityLevel::Low,
                            required_permissions: vec!["key.rotate".to_string()],
                            ip_address: None,
                            user_agent: None,
                        };

                        // Create test key
                        let key_id = "timeout_test_key".to_string();
                        let key = rotation_manager
                            .key_manager
                            .generate_key(black_box(algorithm.as_ref()))
                            .await
                            .unwrap();
                        let metadata = KeyMetadata::new(
                            key_id.clone(),
                            algorithm.name().to_string(),
                            1,
                            Utc::now(),
                            Utc::now() + ChronoDuration::days(90),
                            "benchmark".to_string(),
                            fortress_core::encryption::PerformanceProfile::Balanced,
                        );

                        rotation_manager
                            .key_manager
                            .store_key(&key_id, &key, &metadata)
                            .await
                            .unwrap();

                        // Perform rotation
                        let result = rotation_manager
                            .rotate_key_optimized(
                                black_box(&key_id),
                                black_box(algorithm.as_ref()),
                                black_box(security_context),
                            )
                            .await;

                        black_box(result.unwrap())
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark metrics collection overhead
fn bench_metrics_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("metrics_overhead");

    for metrics_enabled in [false, true].iter() {
        group.bench_with_input(
            BenchmarkId::new("metrics", metrics_enabled),
            metrics_enabled,
            |b, &metrics_enabled| {
                b.iter(|| {
                    rt.block_on(async {
                        let key_manager = Arc::new(InMemoryKeyManager::new());
                        let mut config = OptimizedRotationConfig::default();
                        config.enable_performance_monitoring = metrics_enabled;
                        let rotation_manager =
                            OptimizedKeyRotationManager::new(key_manager, config);

                        let algorithm = create_algorithm("aegis256").unwrap();
                        let security_context = SecurityContext {
                            requestor_id: "benchmark_user".to_string(),
                            security_level: fortress_core::audit::SecurityLevel::Low,
                            required_permissions: vec!["key.rotate".to_string()],
                            ip_address: None,
                            user_agent: None,
                        };

                        // Create test key
                        let key_id = "metrics_test_key".to_string();
                        let key = rotation_manager
                            .key_manager
                            .generate_key(black_box(algorithm.as_ref()))
                            .await
                            .unwrap();
                        let metadata = KeyMetadata::new(
                            key_id.clone(),
                            algorithm.name().to_string(),
                            1,
                            Utc::now(),
                            Utc::now() + ChronoDuration::days(90),
                            "benchmark".to_string(),
                            fortress_core::encryption::PerformanceProfile::Balanced,
                        );

                        rotation_manager
                            .key_manager
                            .store_key(&key_id, &key, &metadata)
                            .await
                            .unwrap();

                        // Perform rotation
                        let result = rotation_manager
                            .rotate_key_optimized(
                                black_box(&key_id),
                                black_box(algorithm.as_ref()),
                                black_box(security_context),
                            )
                            .await;

                        black_box(result.unwrap());

                        // Get metrics if enabled
                        if metrics_enabled {
                            black_box(rotation_manager.get_metrics().await);
                        }
                    })
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_basic_rotation,
    bench_concurrent_rotations,
    bench_bulk_rotation,
    bench_memory_efficiency,
    bench_security_overhead,
    bench_timeout_handling,
    bench_metrics_overhead
);

criterion_main!(benches);
