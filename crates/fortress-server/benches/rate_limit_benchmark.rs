//! Benchmark tests for rate limiting performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fortress_server::prelude::*;
use fortress_server::middleware::{AdvancedRateLimiter, RateLimitAlgorithm};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Create benchmark configuration
fn create_benchmark_config() -> RateLimitConfig {
    RateLimitConfig {
        enabled: true,
        requests_per_minute: 1000,
        requests_per_hour: 60000,
        burst_size: 100,
        algorithm: RateLimitAlgorithm::TokenBucket,
        ddos_protection: DdosProtectionConfig {
            enabled: false, // Disable DDoS for pure rate limiting benchmarks
            global_rps_threshold: None,
            ip_rps_threshold: None,
            auto_block_threshold: None,
            block_duration_seconds: 300,
            reputation_decay_rate: 10,
        },
    }
}

fn create_benchmark_config_with_algorithm(algorithm: RateLimitAlgorithm) -> RateLimitConfig {
    let mut config = create_benchmark_config();
    config.algorithm = algorithm;
    config
}

/// Benchmark single request rate limiting
fn bench_single_request(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("single_request");
    
    for algorithm in [
        RateLimitAlgorithm::TokenBucket,
        RateLimitAlgorithm::SlidingWindow,
        RateLimitAlgorithm::FixedWindow,
        RateLimitAlgorithm::LeakyBucket,
    ] {
        let config = create_benchmark_config_with_algorithm(algorithm);
        let rate_limiter = rt.block_on(async {
            AdvancedRateLimiter::new(config)
        });
        
        group.bench_with_input(
            BenchmarkId::new("rate_limit_check", format!("{:?}", algorithm)),
            &rate_limiter,
            |b, rate_limiter| {
                b.to_async(&rt).iter(|| async {
                    let client_id = "benchmark_client";
                    black_box(rate_limiter.check_rate_limit(client_id).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark concurrent requests
fn bench_concurrent_requests(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("concurrent_requests");
    
    for concurrency in [10, 50, 100, 500] {
        let config = create_benchmark_config();
        let rate_limiter = Arc::new(rt.block_on(async {
            AdvancedRateLimiter::new(config)
        }));
        
        group.bench_with_input(
            BenchmarkId::new("concurrent_rate_limit", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = vec![];
                    
                    for i in 0..concurrency {
                        let rate_limiter = rate_limiter.clone();
                        let client_id = format!("client_{}", i % 10); // 10 different clients
                        
                        let handle = tokio::spawn(async move {
                            black_box(rate_limiter.check_rate_limit(&client_id).await);
                        });
                        
                        handles.push(handle);
                    }
                    
                    for handle in handles {
                        black_box(handle.await.unwrap());
                    }
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark rate limit headers
fn bench_rate_limit_headers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = create_benchmark_config();
    let rate_limiter = rt.block_on(async {
        AdvancedRateLimiter::new(config)
    });
    
    // Pre-populate some data
    rt.block_on(async {
        for i in 0..10 {
            let client_id = format!("client_{}", i);
            for _ in 0..5 {
                rate_limiter.check_rate_limit(&client_id).await.unwrap();
            }
        }
    });
    
    c.bench_function("rate_limit_headers", |b| {
        b.to_async(&rt).iter(|| async {
            let client_id = "benchmark_client";
            black_box(rate_limiter.get_rate_limit_headers(client_id).await);
        });
    });
}

/// Benchmark metrics collection
fn bench_metrics_collection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = create_benchmark_config();
    let rate_limiter = rt.block_on(async {
        AdvancedRateLimiter::new(config)
    });
    
    // Pre-populate with some activity
    rt.block_on(async {
        for i in 0..1000 {
            let client_id = format!("client_{}", i % 100);
            rate_limiter.check_rate_limit(&client_id).await;
        }
    });
    
    c.bench_function("metrics_collection", |b| {
        b.iter(|| {
            black_box(rate_limiter.get_metrics());
        });
    });
}

/// Benchmark cleanup operation
fn bench_cleanup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let config = create_benchmark_config();
    let rate_limiter = rt.block_on(async {
        AdvancedRateLimiter::new(config)
    });
    
    // Pre-populate with lots of data
    rt.block_on(async {
        for i in 0..10000 {
            let client_id = format!("client_{}", i);
            rate_limiter.check_rate_limit(&client_id).await.unwrap();
        }
    });
    
    c.bench_function("cleanup_operation", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(rate_limiter.cleanup().await);
        });
    });
}

/// Benchmark memory usage with different numbers of clients
fn bench_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("memory_usage");
    
    for client_count in [100, 1000, 10000, 50000] {
        let config = create_benchmark_config();
        let rate_limiter = rt.block_on(async {
            AdvancedRateLimiter::new(config)
        });
        
        group.bench_with_input(
            BenchmarkId::new("client_tracking", client_count),
            &client_count,
            |b, &client_count| {
                b.to_async(&rt).iter(|| async {
                    // Simulate tracking many clients
                    for i in 0..client_count {
                        let client_id = format!("client_{}", i);
                        black_box(rate_limiter.check_rate_limit(&client_id).await.unwrap());
                    }
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark DDoS protection overhead
fn bench_ddos_protection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("ddos_protection");
    
    // Test with DDoS protection disabled
    let mut config = create_benchmark_config();
    config.ddos_protection.enabled = false;
    let rate_limiter_no_ddos = Arc::new(rt.block_on(async {
        AdvancedRateLimiter::new(config)
    }));
    
    // Test with DDoS protection enabled
    config.ddos_protection.enabled = true;
    config.ddos_protection.global_rps_threshold = Some(1000);
    config.ddos_protection.ip_rps_threshold = Some(100);
    let rate_limiter_with_ddos = Arc::new(rt.block_on(async {
        AdvancedRateLimiter::new(config)
    }));
    
    group.bench_function("without_ddos_protection", |b| {
        b.to_async(&rt).iter(|| async {
            let client_id = "benchmark_client";
            black_box(rate_limiter_no_ddos.check_rate_limit(client_id).await.unwrap());
        });
    });
    
    group.bench_function("with_ddos_protection", |b| {
        b.to_async(&rt).iter(|| async {
            let client_id = "ip:192.168.1.100";
            black_box(rate_limiter_with_ddos.check_rate_limit(client_id).await.unwrap());
        });
    });
    
    group.finish();
}

/// Benchmark different request patterns
fn bench_request_patterns(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("request_patterns");
    
    let config = create_benchmark_config();
    let rate_limiter = Arc::new(rt.block_on(async {
        AdvancedRateLimiter::new(config)
    }));
    
    // Burst pattern
    group.bench_function("burst_pattern", |b| {
        b.to_async(&rt).iter(|| async {
            let client_id = "burst_client";
            // Send burst of requests
            for _ in 0..10 {
                black_box(rate_limiter.check_rate_limit(client_id).await);
            }
        });
    });
    
    // Steady pattern
    group.bench_function("steady_pattern", |b| {
        b.to_async(&rt).iter(|| async {
            // Send requests from different clients at steady rate
            for i in 0..10 {
                let client_id = format!("steady_client_{}", i);
                black_box(rate_limiter.check_rate_limit(&client_id).await.unwrap());
            }
        });
    });
    
    // Mixed pattern
    group.bench_function("mixed_pattern", |b| {
        b.to_async(&rt).iter(|| async {
            // Mix of different client patterns
            for i in 0..20 {
                let client_id = if i % 3 == 0 {
                    format!("burst_client_{}", i / 3)
                } else {
                    format!("steady_client_{}", i)
                };
                black_box(rate_limiter.check_rate_limit(&client_id).await);
            }
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_single_request,
    bench_concurrent_requests,
    bench_rate_limit_headers,
    bench_metrics_collection,
    bench_cleanup,
    bench_memory_usage,
    bench_ddos_protection,
    bench_request_patterns
);

criterion_main!(benches);
