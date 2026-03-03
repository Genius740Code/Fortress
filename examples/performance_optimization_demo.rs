//! Advanced Performance Optimization Example
//!
//! This example demonstrates the comprehensive performance optimization
//! capabilities of Fortress, including query optimization, distributed caching,
//! connection pooling, performance monitoring, and automatic tuning.

use fortress_core::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Fortress Advanced Performance Optimization Example");
    println!("=====================================================");

    // Initialize performance monitoring
    let perf_config = PerformanceMonitorConfig {
        enabled: true,
        sampling_rate: 1.0, // Sample all operations for demo
        enable_query_profiling: true,
        enable_resource_monitoring: true,
        ..Default::default()
    };
    let performance_monitor = Arc::new(PerformanceMonitor::new(perf_config));

    // Initialize distributed cache
    let cache_config = DistributedCacheConfig {
        backend: CacheBackend::InMemory,
        max_cache_size: 10000,
        eviction_policy: EvictionPolicy::LRU,
        enable_compression: true,
        enable_metrics: true,
        ..Default::default()
    };
    let distributed_cache = create_distributed_cache(cache_config).await?;

    // Initialize connection pool with load balancing
    let pool_config = ConnectionPoolConfig {
        max_connections: 50,
        min_connections: 5,
        load_balance_algorithm: LoadBalanceAlgorithm::LeastConnections,
        enable_failover: true,
        health_check_interval_seconds: 30,
        ..Default::default()
    };

    let endpoints = vec![
        ServerEndpoint {
            id: "db_node_1".to_string(),
            address: "localhost:5432".to_string(),
            weight: 1,
            max_connections: 25,
            available: true,
            region: Some("us-east-1".to_string()),
            tags: vec!["primary".to_string(), "fast".to_string()],
        },
        ServerEndpoint {
            id: "db_node_2".to_string(),
            address: "localhost:5433".to_string(),
            weight: 2,
            max_connections: 25,
            available: true,
            region: Some("us-east-1".to_string()),
            tags: vec!["secondary".to_string(), "reliable".to_string()],
        },
    ];

    let connection_pool = create_connection_pool(pool_config, endpoints);

    // Initialize query optimizer
    let optimizer_config = QueryOptimizerConfig {
        enable_cost_based_optimization: true,
        enable_plan_caching: true,
        enable_adaptive_optimization: true,
        max_cached_plans: 1000,
        ..Default::default()
    };

    let query_engine = Arc::new(crate::query::InMemoryQueryEngine::new());
    let query_optimizer = Arc::new(QueryOptimizer::new(
        optimizer_config,
        query_engine.clone(),
    ));

    // Initialize automatic performance tuner
    let tuning_config = AutoTuningConfig {
        enabled: true,
        tuning_interval_seconds: 60, // 1 minute for demo
        enable_auto_rollback: true,
        safety_mode: true,
        enable_gradual_changes: true,
        ..Default::default()
    };

    let auto_tuner = Arc::new(AutomaticPerformanceTuner::new(
        tuning_config,
        performance_monitor.clone(),
    ));

    println!("✅ Performance optimization components initialized");
    println!();

    // Demonstrate query optimization
    println!("🔍 Query Optimization Demo");
    println!("----------------------------");
    demonstrate_query_optimization(&query_optimizer).await?;
    println!();

    // Demonstrate distributed caching
    println!("💾 Distributed Caching Demo");
    println!("----------------------------");
    demonstrate_distributed_caching(&distributed_cache).await?;
    println!();

    // Demonstrate connection pooling
    println!("🔗 Connection Pooling Demo");
    println!("----------------------------");
    demonstrate_connection_pooling(&connection_pool).await?;
    println!();

    // Demonstrate performance monitoring
    println!("📊 Performance Monitoring Demo");
    println!("----------------------------");
    demonstrate_performance_monitoring(&performance_monitor).await?;
    println!();

    // Demonstrate automatic tuning
    println!("🎛️  Automatic Tuning Demo");
    println!("----------------------------");
    demonstrate_automatic_tuning(&auto_tuner).await?;
    println!();

    // Show comprehensive performance statistics
    println!("📈 Comprehensive Performance Statistics");
    println!("--------------------------------------");
    show_performance_statistics(
        &performance_monitor,
        &distributed_cache,
        &connection_pool,
        &query_optimizer,
        &auto_tuner,
    ).await?;

    println!();
    println!("🎉 Performance optimization demo completed successfully!");

    Ok(())
}

/// Demonstrate query optimization capabilities
async fn demonstrate_query_optimization(
    query_optimizer: &Arc<QueryOptimizer>,
) -> Result<()> {
    println!("Creating sample queries for optimization...");

    // Create a sample execution plan
    let sample_plan = ExecutionPlan {
        nodes: vec![
            PlanNode {
                node_type: PlanNodeType::TableScan,
                children: vec![],
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("table".to_string(), serde_json::Value::String("users".to_string()));
                    params.insert("filter".to_string(), serde_json::Value::String("age > 18".to_string()));
                    params
                },
                estimated_cost: 1000.0,
            },
            PlanNode {
                node_type: PlanNodeType::Filter,
                children: vec![],
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("predicate".to_string(), serde_json::Value::String("status = 'active'".to_string()));
                    params
                },
                estimated_cost: 500.0,
            },
        ],
        estimated_cost: 1500.0,
        metadata: HashMap::new(),
    };

    println!("Original plan cost: {:.2}", sample_plan.estimated_cost);

    // Optimize the plan
    let optimized_plan = query_optimizer.optimize_plan(sample_plan).await?;
    println!("Optimized plan cost: {:.2}", optimized_plan.estimated_cost);
    println!("Cost reduction: {:.1}%", 
        ((1500.0 - optimized_plan.estimated_cost) / 1500.0) * 100.0);

    // Show optimizer statistics
    let optimizer_stats = query_optimizer.get_optimizer_stats().await;
    println!("Optimizer statistics:");
    println!("  - Cached plans: {}", optimizer_stats.cached_plans_count);
    println!("  - Tables with stats: {}", optimizer_stats.tables_with_stats);
    println!("  - Cache hit ratio: {:.2}%", optimizer_stats.cache_hit_ratio * 100.0);

    Ok(())
}

/// Demonstrate distributed caching capabilities
async fn demonstrate_distributed_caching(
    distributed_cache: &Box<dyn DistributedCache>,
) -> Result<()> {
    println!("Performing cache operations...");

    let test_data = b"This is some test data for caching".to_vec();
    let cache_keys = vec![
        "user:123:profile",
        "user:456:profile", 
        "query:complex_aggregation",
        "config:system_settings",
        "session:abc123",
    ];

    // Set multiple cache entries
    let start_time = std::time::Instant::now();
    for (i, key) in cache_keys.iter().enumerate() {
        let ttl = Some(3600 + (i as u64 * 600)); // Different TTLs
        distributed_cache.set(key, test_data.clone(), ttl).await?;
        println!("  ✅ Cached: {} (TTL: {}s)", key, ttl.unwrap_or(0));
    }
    let set_time = start_time.elapsed();

    // Get cache entries
    let start_time = std::time::Instant::now();
    for key in &cache_keys {
        let retrieved = distributed_cache.get(key).await?;
        match retrieved {
            Some(data) => println!("  ✅ Retrieved: {} ({} bytes)", key, data.len()),
            None => println!("  ❌ Missed: {}", key),
        }
    }
    let get_time = start_time.elapsed();

    // Test multi-get operations
    let keys: Vec<&str> = cache_keys.iter().map(|s| s.as_str()).collect();
    let start_time = std::time::Instant::now();
    let results = distributed_cache.mget(&keys).await?;
    let mget_time = start_time.elapsed();

    println!("Multi-get results: {} hits", results.iter().filter(|r| r.is_some()).count());

    // Test increment operation
    let counter_key = "stats:api_calls";
    distributed_cache.set(counter_key, b"0".to_vec(), None).await?;
    
    for i in 1..=5 {
        let new_value = distributed_cache.increment(counter_key, 1).await?;
        println!("  📈 Incremented {}: {}", counter_key, new_value);
    }

    // Show cache statistics
    let stats = distributed_cache.get_statistics().await?;
    println!("\nCache Performance:");
    println!("  - Total entries: {}", stats.total_entries);
    println!("  - Cache size: {:.2} MB", stats.cache_size_bytes as f64 / 1024.0 / 1024.0);
    println!("  - Hit ratio: {:.2}%", stats.hit_ratio * 100.0);
    println!("  - Sets: {}", stats.sets);
    println!("  - Gets: {}", stats.hits + stats.misses);
    println!("  - Evictions: {}", stats.evictions);
    println!("  - Avg get time: {:.2} μs", stats.avg_get_time_us);
    println!("  - Avg set time: {:.2} μs", stats.avg_set_time_us);
    println!("  - Set batch time: {:.2} ms", set_time.as_millis());
    println!("  - Get batch time: {:.2} ms", get_time.as_millis());
    println!("  - Multi-get time: {:.2} ms", mget_time.as_millis());

    Ok(())
}

/// Demonstrate connection pooling capabilities
async fn demonstrate_connection_pooling(
    connection_pool: &Box<dyn ConnectionManager>,
) -> Result<()> {
    println!("Testing connection pool operations...");

    // Get multiple connections
    let mut connections = Vec::new();
    let start_time = std::time::Instant::now();

    for i in 0..10 {
        let conn = connection_pool.get_connection().await?;
        println!("  ✅ Acquired connection {}: {} (endpoint: {})", 
            i + 1, conn.id, conn.endpoint.id);
        connections.push(conn);
    }

    let acquisition_time = start_time.elapsed();
    println!("Connection acquisition time: {:.2} ms", acquisition_time.as_millis());

    // Simulate work with connections
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Return connections to pool
    let start_time = std::time::Instant::now();
    for (i, conn) in connections.into_iter().enumerate() {
        connection_pool.return_connection(conn).await?;
        println!("  ✅ Returned connection {}", i + 1);
    }
    let return_time = start_time.elapsed();
    println!("Connection return time: {:.2} ms", return_time.as_millis());

    // Test endpoint management
    let endpoints = connection_pool.get_endpoints().await?;
    println!("\nAvailable endpoints:");
    for endpoint in endpoints {
        println!("  - {} ({}): weight={}, available={}", 
            endpoint.id, endpoint.address, endpoint.weight, endpoint.available);
    }

    // Show connection pool statistics
    let stats = connection_pool.get_statistics().await?;
    println!("\nConnection Pool Statistics:");
    println!("  - Total connections: {}", stats.total_connections);
    println!("  - Active connections: {}", stats.active_connections);
    println!("  - Idle connections: {}", stats.idle_connections);
    println!("  - Failed connections: {}", stats.failed_connections);
    println!("  - Utilization: {:.1}%", stats.utilization * 100.0);
    println!("  - Avg connection lifetime: {:.1}s", stats.avg_connection_lifetime_seconds);

    // Perform health check
    let healthy = connection_pool.health_check().await?;
    println!("  - Health check: {}", if healthy { "✅ Healthy" } else { "❌ Unhealthy" });

    Ok(())
}

/// Demonstrate performance monitoring capabilities
async fn demonstrate_performance_monitoring(
    performance_monitor: &Arc<PerformanceMonitor>,
) -> Result<()> {
    println!("Starting performance monitoring...");

    // Profile different types of operations
    let operations = vec![
        (OperationType::KeyGeneration, "generate_aes_key"),
        (OperationType::Encryption, "encrypt_large_data"),
        (OperationType::DatabaseQuery, "complex_aggregation"),
        (OperationType::CacheOperation, "cache_lookup"),
        (OperationType::NetworkRequest, "api_call"),
    ];

    for (op_type, op_name) in operations {
        let operation_id = performance_monitor.start_operation(
            op_type,
            op_name.to_string(),
            HashMap::new(),
        ).await;

        // Simulate operation work
        let work_duration = match op_type {
            OperationType::KeyGeneration => Duration::from_millis(50),
            OperationType::Encryption => Duration::from_millis(200),
            OperationType::DatabaseQuery => Duration::from_millis(150),
            OperationType::CacheOperation => Duration::from_millis(5),
            OperationType::NetworkRequest => Duration::from_millis(100),
            _ => Duration::from_millis(10),
        };

        tokio::time::sleep(work_duration).await;

        // Add some metadata
        let mut metadata = HashMap::new();
        metadata.insert("data_size".to_string(), serde_json::Value::Number(serde_json::Number::from(1024)));
        metadata.insert("success".to_string(), serde_json::Value::Bool(true));

        performance_monitor.finish_operation(operation_id, false, metadata).await?;
        println!("  ✅ Profiled: {} ({:?})", op_name, op_type);
    }

    // Wait for metrics aggregation
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Show performance alerts
    let alerts = performance_monitor.get_alerts().await?;
    if !alerts.is_empty() {
        println!("\n🚨 Performance Alerts:");
        for alert in alerts {
            println!("  - {}: {} ({:?})", 
                alert.severity, alert.message, alert.alert_type);
        }
    } else {
        println!("\n✅ No performance alerts");
    }

    // Show tuning recommendations
    let recommendations = performance_monitor.get_recommendations().await?;
    if !recommendations.is_empty() {
        println!("\n💡 Tuning Recommendations:");
        for rec in recommendations {
            println!("  - {}: {} (Priority: {:?})", 
                rec.recommendation_type, rec.description, rec.priority);
        }
    } else {
        println!("\n✅ No tuning recommendations at this time");
    }

    Ok(())
}

/// Demonstrate automatic tuning capabilities
async fn demonstrate_automatic_tuning(
    auto_tuner: &Arc<AutomaticPerformanceTuner>,
) -> Result<()> {
    println!("Automatic tuning system status:");

    let tuning_status = auto_tuner.get_tuning_status().await?;
    println!("  - Enabled: {}", tuning_status.enabled);
    println!("  - Safety mode: {}", tuning_status.safety_mode);
    println!("  - Auto-rollback: {}", tuning_status.auto_rollback_enabled);
    println!("  - Active strategies: {}", tuning_status.active_strategies_count);
    println!("  - Recent changes: {}", tuning_status.recent_changes_count);
    println!("  - Last tuning cycle: {}", tuning_status.last_tuning_cycle.format("%H:%M:%S"));

    // Create a sample recommendation and apply it
    let sample_recommendation = TuningRecommendation {
        id: "sample_rec_001".to_string(),
        recommendation_type: RecommendationType::IncreaseCacheSize,
        description: "Increase cache size to improve hit ratio".to_string(),
        expected_improvement: "15-25% improvement in response times".to_string(),
        complexity: ImplementationComplexity::Low,
        priority: RecommendationPriority::Medium,
        parameters: {
            let mut params = HashMap::new();
            params.insert("current_size".to_string(), serde_json::Value::Number(serde_json::Number::from(1000)));
            params.insert("suggested_size".to_string(), serde_json::Value::Number(serde_json::Number::from(2000)));
            params
        },
    };

    println!("\nApplying sample tuning recommendation...");
    let change_id = auto_tuner.apply_recommendation(&sample_recommendation).await?;
    println!("  ✅ Applied change: {}", change_id);

    // Wait a bit for the change to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Show updated status
    let updated_status = auto_tuner.get_tuning_status().await?;
    println!("  Updated recent changes: {}", updated_status.recent_changes_count);

    Ok(())
}

/// Show comprehensive performance statistics
async fn show_performance_statistics(
    performance_monitor: &Arc<PerformanceMonitor>,
    distributed_cache: &Box<dyn DistributedCache>,
    connection_pool: &Box<dyn ConnectionManager>,
    query_optimizer: &Arc<QueryOptimizer>,
    auto_tuner: &Arc<AutomaticPerformanceTuner>,
) -> Result<()> {
    println!("Collecting comprehensive performance metrics...");

    // Performance metrics
    let metrics = performance_monitor.get_metrics().await?;
    println!("\n📊 Performance Metrics:");
    for (operation_type, aggregated_metrics) in metrics {
        println!("  {}:", operation_type);
        println!("    - Operations: {}", aggregated_metrics.total_operations);
        println!("    - Avg response time: {:.2} ms", aggregated_metrics.avg_response_time_ms);
        println!("    - P95 response time: {:.2} ms", aggregated_metrics.p95_response_time_ms);
        println!("    - Throughput: {:.2} ops/sec", aggregated_metrics.throughput);
        println!("    - Error rate: {:.2}%", aggregated_metrics.error_rate_percent);
        println!("    - Cache hit ratio: {:.2}%", aggregated_metrics.cache_stats.hit_ratio * 100.0);
    }

    // Cache statistics
    let cache_stats = distributed_cache.get_statistics().await?;
    println!("\n💾 Cache Statistics:");
    println!("  - Hit ratio: {:.2}%", cache_stats.hit_ratio * 100.0);
    println!("  - Total operations: {}", cache_stats.hits + cache_stats.misses);
    println!("  - Cache size: {:.2} MB", cache_stats.cache_size_bytes as f64 / 1024.0 / 1024.0);
    println!("  - Evictions: {}", cache_stats.evictions);

    // Connection pool statistics
    let pool_stats = connection_pool.get_statistics().await?;
    println!("\n🔗 Connection Pool Statistics:");
    println!("  - Total connections: {}", pool_stats.total_connections);
    println!("  - Active connections: {}", pool_stats.active_connections);
    println!("  - Utilization: {:.1}%", pool_stats.utilization * 100.0);
    println!("  - Avg query time: {:.2} ms", pool_stats.avg_query_time_ms);

    // Query optimizer statistics
    let optimizer_stats = query_optimizer.get_optimizer_stats().await?;
    println!("\n🔍 Query Optimizer Statistics:");
    println!("  - Cached plans: {}", optimizer_stats.cached_plans_count);
    println!("  - Cache hit ratio: {:.2}%", optimizer_stats.cache_hit_ratio * 100.0);
    println!("  - Tables with stats: {}", optimizer_stats.tables_with_stats);

    // Auto-tuner status
    let tuning_status = auto_tuner.get_tuning_status().await?;
    println!("\n🎛️  Auto-Tuning Status:");
    println!("  - Enabled: {}", tuning_status.enabled);
    println!("  - Safety mode: {}", tuning_status.safety_mode);
    println!("  - Active strategies: {}", tuning_status.active_strategies_count);
    println!("  - Recent changes: {}", tuning_status.recent_changes_count);

    // Calculate overall performance score
    let overall_score = calculate_performance_score(
        &cache_stats,
        &pool_stats,
        &optimizer_stats,
    );
    println!("\n🏆 Overall Performance Score: {:.1}/100", overall_score);

    if overall_score >= 90.0 {
        println!("  🌟 Excellent performance!");
    } else if overall_score >= 75.0 {
        println!("  ✅ Good performance");
    } else if overall_score >= 60.0 {
        println!("  ⚠️  Performance needs improvement");
    } else {
        println!("  ❌ Poor performance - optimization needed");
    }

    Ok(())
}

/// Calculate an overall performance score (0-100)
fn calculate_performance_score(
    cache_stats: &CacheStatistics,
    pool_stats: &ConnectionStats,
    optimizer_stats: &OptimizerStats,
) -> f64 {
    let cache_score = cache_stats.hit_ratio * 30.0; // 30 points max
    let pool_efficiency = (1.0 - pool_stats.utilization) * 25.0; // 25 points max
    let optimizer_efficiency = optimizer_stats.cache_hit_ratio * 25.0; // 25 points max
    let error_penalty = if pool_stats.failed_connections > 0 { -10.0 } else { 0.0 };
    let eviction_penalty = if cache_stats.evictions > cache_stats.total_entries / 10 { -5.0 } else { 0.0 };

    let base_score = 20.0; // Base score
    let total_score = base_score + cache_score + pool_efficiency + optimizer_efficiency + error_penalty + eviction_penalty;

    total_score.max(0.0).min(100.0)
}
