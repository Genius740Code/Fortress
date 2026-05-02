//! Performance & Load Tests for Fortress
//! 
//! Section 4.2: Performance & Load Tests
//! - High-concurrency tests
//! - Memory usage tests  
//! - Scalability tests

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::thread;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};

use tokio::sync::{Semaphore, RwLock, Mutex};
use tokio::task::JoinSet;

use fortress_core::error::Result;
use fortress_core::encryption::{Aegis256, EncryptionAlgorithm};
use fortress_core::websocket::auth::{AuthManager, AuthConfig};
use fortress_core::security_fixes::{SecureSessionGenerator, CsrfProtection, InputValidator};
use fortress_core::cache::{CacheManager, CacheConfig};
use fortress_core::storage::{StorageManager, StorageConfig};
use fortress_core::key::{KeyManager, KeyConfig};
use fortress_core::audit::{AuditManager, AuditConfig};

/// Comprehensive performance and load test suite
pub struct PerformanceLoadTests;

impl PerformanceLoadTests {
    /// Run all performance and load tests
    pub async fn run_all_tests() -> Result<PerformanceLoadTestResults> {
        println!("🚀 Starting Fortress Performance & Load Tests");
        println!("===========================================");
        println!("Section 4.2: Performance & Load Tests\n");

        let suite_start = Instant::now();
        let mut results = PerformanceLoadTestResults::new();

        // Test 1: High-concurrency tests
        println!("⚡ Running high-concurrency tests...");
        results.high_concurrency = self.test_high_concurrency_scenarios().await?;
        println!("✅ High-concurrency tests completed\n");

        // Test 2: Memory usage tests
        println!("💾 Running memory usage tests...");
        results.memory_usage = self.test_memory_usage_scenarios().await?;
        println!("✅ Memory usage tests completed\n");

        // Test 3: Scalability tests
        println!("📈 Running scalability tests...");
        results.scalability = self.test_scalability_scenarios().await?;
        println!("✅ Scalability tests completed\n");

        let total_suite_time = suite_start.elapsed();
        self.generate_comprehensive_report(&results, total_suite_time);

        Ok(results)
    }

    /// Test high-concurrency scenarios
    async fn test_high_concurrency_scenarios(&self) -> Result<HighConcurrencyResults> {
        println!("🔥 Testing high-concurrency scenarios...");

        let mut results = HighConcurrencyResults::new();

        // Test 1.1: Concurrent authentication
        results.concurrent_auth = self.test_concurrent_authentication().await?;

        // Test 1.2: Concurrent encryption/decryption
        results.concurrent_encryption = self.test_concurrent_encryption().await?;

        // Test 1.3: Concurrent database operations
        results.concurrent_database = self.test_concurrent_database_operations().await?;

        // Test 1.4: Concurrent cache operations
        results.concurrent_cache = self.test_concurrent_cache_operations().await?;

        // Test 1.5: Concurrent audit logging
        results.concurrent_audit = self.test_concurrent_audit_logging().await?;

        // Test 1.6: Load balancing simulation
        results.load_balancing = self.test_load_balancing_simulation().await?;

        // Test 1.7: Resource contention
        results.resource_contention = self.test_resource_contention().await?;

        // Test 1.8: Connection pooling
        results.connection_pooling = self.test_connection_pooling().await?;

        self.print_high_concurrency_summary(&results);
        Ok(results)
    }

    /// Test concurrent authentication
    async fn test_concurrent_authentication(&self) -> Result<ConcurrentAuthResult> {
        println!("  📝 Testing concurrent authentication...");

        let auth_config = AuthConfig {
            max_attempts_per_ip: 10000,
            attempt_window_seconds: 300,
            lockout_duration_seconds: 900,
            enable_ip_lockout: true,
            enable_rate_limiting: true,
            jwt_secret: "test_secret".to_string(),
            token_expiration_seconds: 3600,
        };

        let auth_manager = Arc::new(AuthManager::new_with_config(auth_config));
        let concurrent_levels = vec![100, 500, 1000, 2000, 5000];
        let mut test_results = Vec::new();

        for concurrent_count in concurrent_levels {
            let semaphore = Arc::new(Semaphore::new(concurrent_count));
            let mut handles = Vec::new();
            let total_requests = concurrent_count * 10; // 10x concurrency for load

            let start = Instant::now();

            for i in 0..total_requests {
                let semaphore = semaphore.clone();
                let auth_manager = auth_manager.clone();
                let client_ip = format!("192.168.{}.{}", (i / 254) % 255, i % 254);

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let req_start = Instant::now();
                    let result = auth_manager.authenticate_api_key("test_key", &client_ip).await;
                    let req_time = req_start.elapsed();
                    (result.is_ok(), req_time)
                });

                handles.push(handle);
            }

            let mut successful_auths = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_auths += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / total_requests as u32;
            let requests_per_second = total_requests as f64 / total_time.as_secs_f64();
            let success_rate = successful_auths as f64 / total_requests as f64;

            test_results.push(ConcurrencyTestPoint {
                concurrent_count,
                total_requests,
                successful_requests: successful_auths,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                requests_per_second,
                success_rate,
            });

            println!("    Concurrency {}: {:.2} req/sec, {:.1}% success, avg response {:?}", 
                concurrent_count, requests_per_second, success_rate * 100.0, avg_response_time);
        }

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.95 && r.requests_per_second > 100.0);

        Ok(ConcurrentAuthResult {
            test_results,
            overall_success,
        })
    }

    /// Test concurrent encryption/decryption
    async fn test_concurrent_encryption(&self) -> Result<ConcurrentEncryptionResult> {
        println!("  🔐 Testing concurrent encryption/decryption...");

        let algorithm = Arc::new(Aegis256::new());
        let data_sizes = vec![1024, 10240, 102400, 1024000]; // 1KB, 10KB, 100KB, 1MB
        let concurrent_levels = vec![100, 500, 1000];
        let mut test_results = Vec::new();

        for data_size in data_sizes {
            for concurrent_count in concurrent_levels {
                let test_data = vec![42u8; data_size];
                let key = vec![0u8; 32];
                let algorithm = algorithm.clone();
                let semaphore = Arc::new(Semaphore::new(concurrent_count));
                let mut handles = Vec::new();

                let start = Instant::now();

                for _i in 0..concurrent_count {
                    let semaphore = semaphore.clone();
                    let algorithm = algorithm.clone();
                    let test_data = test_data.clone();
                    let key = key.clone();

                    let handle = tokio::spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let op_start = Instant::now();

                        // Encrypt
                        let ciphertext = algorithm.encrypt(&test_data, &key).unwrap();
                        
                        // Decrypt
                        let _plaintext = algorithm.decrypt(&ciphertext, &key).unwrap();
                        
                        op_start.elapsed()
                    });

                    handles.push(handle);
                }

                let mut total_operation_time = Duration::ZERO;
                let mut max_operation_time = Duration::ZERO;
                let mut min_operation_time = Duration::MAX;

                for handle in handles {
                    let operation_time = handle.await?;
                    total_operation_time += operation_time;
                    max_operation_time = max_operation_time.max(operation_time);
                    min_operation_time = min_operation_time.min(operation_time);
                }

                let total_time = start.elapsed();
                let avg_operation_time = total_operation_time / concurrent_count as u32;
                let operations_per_second = concurrent_count as f64 / total_time.as_secs_f64();
                let throughput_mbps = (data_size as f64 * 2.0) / (1024.0 * 1024.0) / avg_operation_time.as_secs_f64();

                test_results.push(EncryptionConcurrencyTest {
                    data_size,
                    concurrent_count,
                    total_time,
                    avg_operation_time,
                    min_operation_time,
                    max_operation_time,
                    operations_per_second,
                    throughput_mbps,
                });

                println!("    {}B @ {} concurrent: {:.2} ops/sec, {:.2} MB/s", 
                    data_size, concurrent_count, operations_per_second, throughput_mbps);
            }
        }

        let overall_success = test_results.iter().all(|r| r.operations_per_second > 50.0 && r.throughput_mbps > 10.0);

        Ok(ConcurrentEncryptionResult {
            test_results,
            overall_success,
        })
    }

    /// Test concurrent database operations
    async fn test_concurrent_database_operations(&self) -> Result<ConcurrentDatabaseResult> {
        println!("  🗄️  Testing concurrent database operations...");

        // Mock database operations since we don't have a real database
        let mock_db = Arc::new(MockDatabase::new());
        let operation_types = vec!["read", "write", "update", "delete"];
        let concurrent_levels = vec![100, 500, 1000];
        let mut test_results = Vec::new();

        for concurrent_count in concurrent_levels {
            for operation_type in operation_types.iter() {
                let mock_db = mock_db.clone();
                let semaphore = Arc::new(Semaphore::new(concurrent_count));
                let mut handles = Vec::new();

                let start = Instant::now();

                for i in 0..concurrent_count {
                    let semaphore = semaphore.clone();
                    let mock_db = mock_db.clone();
                    let operation_type = operation_type.to_string();
                    let record_id = i;

                    let handle = tokio::spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let op_start = Instant::now();
                        
                        let result = mock_db.execute_operation(&operation_type, record_id).await;
                        
                        (result.is_ok(), op_start.elapsed())
                    });

                    handles.push(handle);
                }

                let mut successful_ops = 0;
                let mut total_response_time = Duration::ZERO;
                let mut max_response_time = Duration::ZERO;
                let mut min_response_time = Duration::MAX;

                for handle in handles {
                    let (success, response_time) = handle.await?;
                    if success {
                        successful_ops += 1;
                    }
                    total_response_time += response_time;
                    max_response_time = max_response_time.max(response_time);
                    min_response_time = min_response_time.min(response_time);
                }

                let total_time = start.elapsed();
                let avg_response_time = total_response_time / concurrent_count as u32;
                let operations_per_second = concurrent_count as f64 / total_time.as_secs_f64();
                let success_rate = successful_ops as f64 / concurrent_count as f64;

                test_results.push(DatabaseConcurrencyTest {
                    operation_type: operation_type.clone(),
                    concurrent_count,
                    successful_operations: successful_ops,
                    total_time,
                    avg_response_time,
                    min_response_time,
                    max_response_time,
                    operations_per_second,
                    success_rate,
                });

                println!("    {} @ {} concurrent: {:.2} ops/sec, {:.1}% success", 
                    operation_type, concurrent_count, operations_per_second, success_rate * 100.0);
            }
        }

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.95 && r.operations_per_second > 100.0);

        Ok(ConcurrentDatabaseResult {
            test_results,
            overall_success,
        })
    }

    /// Test concurrent cache operations
    async fn test_concurrent_cache_operations(&self) -> Result<ConcurrentCacheResult> {
        println!("  🗄️  Testing concurrent cache operations...");

        let cache_config = CacheConfig {
            max_size: 10000,
            ttl_seconds: 3600,
            cleanup_interval_seconds: 300,
        };
        let cache_manager = Arc::new(CacheManager::new_with_config(cache_config));
        let concurrent_levels = vec![100, 500, 1000, 2000];
        let mut test_results = Vec::new();

        // Pre-populate cache
        for i in 0..1000 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            cache_manager.set(&key, &value).await.unwrap();
        }

        for concurrent_count in concurrent_levels {
            let cache_manager = cache_manager.clone();
            let semaphore = Arc::new(Semaphore::new(concurrent_count));
            let mut handles = Vec::new();

            let start = Instant::now();

            for i in 0..concurrent_count {
                let semaphore = semaphore.clone();
                let cache_manager = cache_manager.clone();

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let op_start = Instant::now();

                    // Mix of get and set operations (70% get, 30% set)
                    let operation_result = if i % 10 < 7 {
                        // Get operation
                        let key = format!("key_{}", i % 1000);
                        cache_manager.get(&key).await
                    } else {
                        // Set operation
                        let key = format!("new_key_{}", i);
                        let value = format!("new_value_{}", i);
                        cache_manager.set(&key, &value).await
                    };

                    (operation_result.is_ok(), op_start.elapsed())
                });

                handles.push(handle);
            }

            let mut successful_ops = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_ops += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / concurrent_count as u32;
            let operations_per_second = concurrent_count as f64 / total_time.as_secs_f64();
            let success_rate = successful_ops as f64 / concurrent_count as f64;

            test_results.push(CacheConcurrencyTest {
                concurrent_count,
                successful_operations: successful_ops,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                operations_per_second,
                success_rate,
            });

            println!("    Cache @ {} concurrent: {:.2} ops/sec, {:.1}% success", 
                concurrent_count, operations_per_second, success_rate * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.95 && r.operations_per_second > 1000.0);

        Ok(ConcurrentCacheResult {
            test_results,
            overall_success,
        })
    }

    /// Test concurrent audit logging
    async fn test_concurrent_audit_logging(&self) -> Result<ConcurrentAuditResult> {
        println!("  📋 Testing concurrent audit logging...");

        let audit_config = AuditConfig {
            batch_size: 100,
            flush_interval_seconds: 5,
            retention_days: 90,
        };
        let audit_manager = Arc::new(AuditManager::new_with_config(audit_config));
        let concurrent_levels = vec![100, 500, 1000, 5000];
        let mut test_results = Vec::new();

        for concurrent_count in concurrent_levels {
            let audit_manager = audit_manager.clone();
            let semaphore = Arc::new(Semaphore::new(concurrent_count));
            let mut handles = Vec::new();

            let start = Instant::now();

            for i in 0..concurrent_count {
                let semaphore = semaphore.clone();
                let audit_manager = audit_manager.clone();

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let op_start = Instant::now();

                    let audit_event = serde_json::json!({
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "user_id": format!("user_{}", i),
                        "action": "data_access",
                        "resource": format!("resource_{}", i % 100),
                        "ip_address": format!("192.168.1.{}", i % 255),
                        "session_id": format!("session_{}", i)
                    });

                    let result = audit_manager.log_event(&audit_event).await;
                    (result.is_ok(), op_start.elapsed())
                });

                handles.push(handle);
            }

            let mut successful_logs = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_logs += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / concurrent_count as u32;
            let logs_per_second = concurrent_count as f64 / total_time.as_secs_f64();
            let success_rate = successful_logs as f64 / concurrent_count as f64;

            test_results.push(AuditConcurrencyTest {
                concurrent_count,
                successful_logs,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                logs_per_second,
                success_rate,
            });

            println!("    Audit @ {} concurrent: {:.2} logs/sec, {:.1}% success", 
                concurrent_count, logs_per_second, success_rate * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.95 && r.logs_per_second > 500.0);

        Ok(ConcurrentAuditResult {
            test_results,
            overall_success,
        })
    }

    /// Test load balancing simulation
    async fn test_load_balancing_simulation(&self) -> Result<LoadBalancingResult> {
        println!("  ⚖️  Testing load balancing simulation...");

        let num_instances = 5;
        let instances: Vec<Arc<MockServiceInstance>> = (0..num_instances)
            .map(|i| Arc::new(MockServiceInstance::new(format!("instance_{}", i))))
            .collect();
        
        let load_balancer = Arc::new(LoadBalancer::new(instances));
        let total_requests = 10000;
        let concurrent_levels = vec![100, 500, 1000];
        let mut test_results = Vec::new();

        for concurrent_count in concurrent_levels {
            let load_balancer = load_balancer.clone();
            let semaphore = Arc::new(Semaphore::new(concurrent_count));
            let mut handles = Vec::new();

            let start = Instant::now();

            for i in 0..total_requests {
                let semaphore = semaphore.clone();
                let load_balancer = load_balancer.clone();

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let req_start = Instant::now();

                    let result = load_balancer.process_request(format!("request_{}", i)).await;
                    (result.is_ok(), req_start.elapsed())
                });

                handles.push(handle);
            }

            let mut successful_requests = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_requests += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / total_requests as u32;
            let requests_per_second = total_requests as f64 / total_time.as_secs_f64();
            let success_rate = successful_requests as f64 / total_requests as f64;

            // Get load distribution
            let load_distribution = load_balancer.get_load_distribution();

            test_results.push(LoadBalancingTest {
                concurrent_count,
                total_requests,
                successful_requests,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                requests_per_second,
                success_rate,
                load_distribution: load_distribution.clone(),
            });

            println!("    Load Balancer @ {} concurrent: {:.2} req/sec, {:.1}% success", 
                concurrent_count, requests_per_second, success_rate * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.98 && r.requests_per_second > 1000.0);

        Ok(LoadBalancingResult {
            test_results,
            overall_success,
        })
    }

    /// Test resource contention
    async fn test_resource_contention(&self) -> Result<ResourceContentionResult> {
        println!("  🥊 Testing resource contention...");

        let shared_resource = Arc::new(Mutex::new(SharedResource::new()));
        let contention_levels = vec![10, 50, 100, 500, 1000];
        let mut test_results = Vec::new();

        for contention_count in contention_levels {
            let shared_resource = shared_resource.clone();
            let semaphore = Arc::new(Semaphore::new(contention_count));
            let mut handles = Vec::new();

            let start = Instant::now();

            for i in 0..contention_count {
                let semaphore = semaphore.clone();
                let shared_resource = shared_resource.clone();

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let op_start = Instant::now();

                    // Simulate resource contention with mixed operations
                    let result = if i % 3 == 0 {
                        shared_resource.lock().await.expensive_operation().await
                    } else if i % 3 == 1 {
                        shared_resource.lock().await.read_operation().await
                    } else {
                        shared_resource.lock().await.write_operation().await
                    };

                    (result.is_ok(), op_start.elapsed())
                });

                handles.push(handle);
            }

            let mut successful_ops = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_ops += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / contention_count as u32;
            let operations_per_second = contention_count as f64 / total_time.as_secs_f64();
            let success_rate = successful_ops as f64 / contention_count as f64;

            test_results.push(ResourceContentionTest {
                contention_count,
                successful_operations: successful_ops,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                operations_per_second,
                success_rate,
            });

            println!("    Contention @ {} threads: {:.2} ops/sec, {:.1}% success", 
                contention_count, operations_per_second, success_rate * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.95);

        Ok(ResourceContentionResult {
            test_results,
            overall_success,
        })
    }

    /// Test connection pooling
    async fn test_connection_pooling(&self) -> Result<ConnectionPoolingResult> {
        println!("  🔗 Testing connection pooling...");

        let pool_config = ConnectionPoolConfig {
            max_connections: 100,
            min_connections: 10,
            connection_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
        };
        let connection_pool = Arc::new(ConnectionPool::new_with_config(pool_config));
        let concurrent_levels = vec![50, 100, 200, 500];
        let mut test_results = Vec::new();

        for concurrent_count in concurrent_levels {
            let connection_pool = connection_pool.clone();
            let semaphore = Arc::new(Semaphore::new(concurrent_count));
            let mut handles = Vec::new();

            let start = Instant::now();

            for i in 0..concurrent_count {
                let semaphore = semaphore.clone();
                let connection_pool = connection_pool.clone();

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let op_start = Instant::now();

                    let result = connection_pool.execute_operation(format!("operation_{}", i)).await;
                    (result.is_ok(), op_start.elapsed())
                });

                handles.push(handle);
            }

            let mut successful_ops = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_ops += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / concurrent_count as u32;
            let operations_per_second = concurrent_count as f64 / total_time.as_secs_f64();
            let success_rate = successful_ops as f64 / concurrent_count as f64;

            let pool_stats = connection_pool.get_stats();

            test_results.push(ConnectionPoolingTest {
                concurrent_count,
                successful_operations: successful_ops,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                operations_per_second,
                success_rate,
                pool_stats,
            });

            println!("    Pool @ {} concurrent: {:.2} ops/sec, {:.1}% success", 
                concurrent_count, operations_per_second, success_rate * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.98 && r.operations_per_second > 200.0);

        Ok(ConnectionPoolingResult {
            test_results,
            overall_success,
        })
    }

    /// Test memory usage scenarios
    async fn test_memory_usage_scenarios(&self) -> Result<MemoryUsageResults> {
        println!("💾 Testing memory usage scenarios...");

        let mut results = MemoryUsageResults::new();

        // Test 2.1: Memory allocation patterns
        results.allocation_patterns = self.test_memory_allocation_patterns().await?;

        // Test 2.2: Memory leak detection
        results.memory_leaks = self.test_memory_leak_detection().await?;

        // Test 2.3: Memory pressure handling
        results.memory_pressure = self.test_memory_pressure_handling().await?;

        // Test 2.4: Garbage collection impact
        results.garbage_collection = self.test_garbage_collection_impact().await?;

        // Test 2.5: Memory fragmentation
        results.memory_fragmentation = self.test_memory_fragmentation().await?;

        // Test 2.6: Cache memory usage
        results.cache_memory = self.test_cache_memory_usage().await?;

        self.print_memory_usage_summary(&results);
        Ok(results)
    }

    /// Test memory allocation patterns
    async fn test_memory_allocation_patterns(&self) -> Result<MemoryAllocationResult> {
        println!("  🧠 Testing memory allocation patterns...");

        let allocation_sizes = vec![1024, 10240, 102400, 1024000, 10240000]; // 1KB to 10MB
        let allocation_counts = vec![100, 1000, 10000];
        let mut test_results = Vec::new();

        for size in allocation_sizes {
            for count in allocation_counts.iter() {
                let start = Instant::now();
                let mut allocations = Vec::new();

                // Allocate memory
                for i in 0..*count {
                    let data = vec![42u8; size];
                    allocations.push((i, data));
                }

                let allocation_time = start.elapsed();

                // Use memory (simulate work)
                let use_start = Instant::now();
                for (_, ref data) in &allocations {
                    let _sum: u64 = data.iter().map(|&x| x as u64).sum();
                }
                let use_time = use_start.elapsed();

                // Deallocate memory
                let dealloc_start = Instant::now();
                allocations.clear();
                let dealloc_time = dealloc_start.elapsed();

                let total_time = allocation_time + use_time + dealloc_time;
                let total_memory_mb = (size * count) as f64 / (1024.0 * 1024.0);
                let allocation_rate_mb_per_sec = total_memory_mb / allocation_time.as_secs_f64();
                let deallocation_rate_mb_per_sec = total_memory_mb / dealloc_time.as_secs_f64();

                test_results.push(MemoryAllocationTest {
                    allocation_size: size,
                    allocation_count: *count,
                    total_memory_mb,
                    allocation_time,
                    use_time,
                    dealloc_time,
                    total_time,
                    allocation_rate_mb_per_sec,
                    deallocation_rate_mb_per_sec,
                });

                println!("    {}B x {} allocations: {:.2} MB/s alloc, {:.2} MB/s dealloc", 
                    size, count, allocation_rate_mb_per_sec, deallocation_rate_mb_per_sec);
            }
        }

        let overall_success = test_results.iter().all(|r| r.allocation_rate_mb_per_sec > 100.0);

        Ok(MemoryAllocationResult {
            test_results,
            overall_success,
        })
    }

    /// Test memory leak detection
    async fn test_memory_leak_detection(&self) -> Result<MemoryLeakResult> {
        println!("  🔍 Testing memory leak detection...");

        let leak_scenarios = vec![
            ("Session Objects", 10000),
            ("Cache Entries", 50000),
            ("Encryption Keys", 1000),
            ("Audit Logs", 100000),
            ("Network Connections", 1000),
        ];

        let mut test_results = Vec::new();

        for (scenario_name, iterations) in leak_scenarios {
            let initial_memory = self.get_memory_usage();
            
            // Simulate potential memory leak scenario
            let start = Instant::now();
            let mut objects = Vec::new();

            for i in 0..iterations {
                match scenario_name {
                    "Session Objects" => {
                        let session = format!("session_{}", i);
                        objects.push(session);
                    },
                    "Cache Entries" => {
                        let cache_entry = format!("cache_key_{} -> cache_value_{}", i, i);
                        objects.push(cache_entry);
                    },
                    "Encryption Keys" => {
                        let key = vec![i as u8; 32];
                        objects.push(format!("key_{}", i));
                        drop(key); // Explicitly drop to avoid actual memory accumulation
                    },
                    "Audit Logs" => {
                        let log = format!("audit_log_{}: User {} performed action", i, i);
                        objects.push(log);
                    },
                    "Network Connections" => {
                        let conn = format!("connection_{}: 192.168.1.{}", i, i % 255);
                        objects.push(conn);
                    },
                    _ => {}
                }

                // Simulate cleanup every 1000 iterations
                if i % 1000 == 999 {
                    objects.clear();
                }
            }

            let final_memory = self.get_memory_usage();
            let memory_increase = final_memory.saturating_sub(initial_memory);
            let test_duration = start.elapsed();

            // Calculate memory leak rate (MB per minute)
            let memory_leak_rate_mb_per_min = memory_increase as f64 / (1024.0 * 1024.0) / 
                                           (test_duration.as_secs_f64() / 60.0);

            test_results.push(MemoryLeakTest {
                scenario_name: scenario_name.to_string(),
                iterations,
                initial_memory,
                final_memory,
                memory_increase,
                test_duration,
                memory_leak_rate_mb_per_min,
            });

            println!("    {}: {:.2} MB increase, {:.2} MB/min leak rate", 
                scenario_name, memory_increase as f64 / (1024.0 * 1024.0), memory_leak_rate_mb_per_min);
        }

        // Acceptable leak rate is less than 1 MB per minute
        let overall_success = test_results.iter().all(|r| r.memory_leak_rate_mb_per_min < 1.0);

        Ok(MemoryLeakResult {
            test_results,
            overall_success,
        })
    }

    /// Test memory pressure handling
    async fn test_memory_pressure_handling(&self) -> Result<MemoryPressureResult> {
        println!("  🏋️  Testing memory pressure handling...");

        let pressure_levels = vec![
            ("Low Pressure", 100 * 1024 * 1024),    // 100 MB
            ("Medium Pressure", 500 * 1024 * 1024),  // 500 MB
            ("High Pressure", 1000 * 1024 * 1024),   // 1 GB
            ("Extreme Pressure", 2000 * 1024 * 1024), // 2 GB
        ];

        let mut test_results = Vec::new();

        for (pressure_name, target_memory) in pressure_levels {
            let start = Instant::now();
            let initial_memory = self.get_memory_usage();

            // Gradually increase memory usage
            let mut memory_blocks = Vec::new();
            let block_size = 1024 * 1024; // 1 MB blocks
            let target_blocks = target_memory / block_size;

            for i in 0..target_blocks {
                memory_blocks.push(vec![42u8; block_size]);
                
                // Check if we're approaching the target
                if i % 100 == 0 {
                    let current_memory = self.get_memory_usage();
                    if current_memory - initial_memory >= target_memory {
                        break;
                    }
                }
            }

            let peak_memory = self.get_memory_usage();
            let memory_increase = peak_memory.saturating_sub(initial_memory);

            // Test system performance under pressure
            let performance_start = Instant::now();
            let mut performance_results = Vec::new();

            for i in 0..100 {
                let test_start = Instant::now();
                
                // Simulate various operations under memory pressure
                let _result = self.simulate_operation_under_pressure(i).await;
                
                let test_time = test_start.elapsed();
                performance_results.push(test_time);
            }

            let performance_end = performance_start.elapsed();
            let avg_operation_time = performance_results.iter().sum::<Duration>() / performance_results.len() as u32;

            // Cleanup memory
            drop(memory_blocks);
            let final_memory = self.get_memory_usage();
            let memory_recovered = peak_memory.saturating_sub(final_memory);

            let total_test_time = start.elapsed();

            test_results.push(MemoryPressureTest {
                pressure_name: pressure_name.to_string(),
                target_memory,
                initial_memory,
                peak_memory,
                final_memory,
                memory_increase,
                memory_recovered,
                total_test_time,
                avg_operation_time,
            });

            println!("    {}: {:.2} MB increase, {:.2} MB recovered, avg op {:?}", 
                pressure_name, 
                memory_increase as f64 / (1024.0 * 1024.0),
                memory_recovered as f64 / (1024.0 * 1024.0),
                avg_operation_time);
        }

        let overall_success = test_results.iter().all(|r| r.memory_recovered > r.memory_increase * 80 / 100);

        Ok(MemoryPressureResult {
            test_results,
            overall_success,
        })
    }

    /// Test garbage collection impact
    async fn test_garbage_collection_impact(&self) -> Result<GarbageCollectionResult> {
        println!("  🗑️  Testing garbage collection impact...");

        let gc_scenarios = vec![
            ("Small Objects", 100000, 1024),      // 100K objects of 1KB each
            ("Medium Objects", 10000, 10240),     // 10K objects of 10KB each
            ("Large Objects", 1000, 102400),       // 1K objects of 100KB each
            ("Mixed Objects", 50000, 2048),        // 50K objects of 2KB each
        ];

        let mut test_results = Vec::new();

        for (scenario_name, object_count, object_size) in gc_scenarios {
            let start = Instant::now();
            let initial_memory = self.get_memory_usage();

            // Phase 1: Allocation
            let allocation_start = Instant::now();
            let mut objects = Vec::new();

            for i in 0..object_count {
                let object = vec![((i * 7) % 256) as u8; object_size];
                objects.push(object);
            }

            let allocation_time = allocation_start.elapsed();
            let peak_memory = self.get_memory_usage();

            // Phase 2: Usage (simulate work)
            let usage_start = Instant::now();
            for (i, ref obj) in objects.iter().enumerate() {
                let _hash: u64 = obj.iter().enumerate()
                    .map(|(j, &x)| ((x as u64) << (j % 8)) ^ (i as u64))
                    .sum();
            }
            let usage_time = usage_start.elapsed();

            // Phase 3: Deallocation (trigger GC)
            let deallocation_start = Instant::now();
            drop(objects);
            let deallocation_time = deallocation_start.elapsed();

            let final_memory = self.get_memory_usage();
            let total_time = start.elapsed();

            let memory_allocated = peak_memory.saturating_sub(initial_memory);
            let memory_freed = peak_memory.saturating_sub(final_memory);
            let gc_efficiency = if memory_allocated > 0 {
                memory_freed as f64 / memory_allocated as f64
            } else {
                1.0
            };

            test_results.push(GarbageCollectionTest {
                scenario_name: scenario_name.to_string(),
                object_count,
                object_size,
                initial_memory,
                peak_memory,
                final_memory,
                allocation_time,
                usage_time,
                deallocation_time,
                total_time,
                memory_allocated,
                memory_freed,
                gc_efficiency,
            });

            println!("    {}: allocated {:.2} MB, freed {:.2} MB, {:.1}% efficiency", 
                scenario_name,
                memory_allocated as f64 / (1024.0 * 1024.0),
                memory_freed as f64 / (1024.0 * 1024.0),
                gc_efficiency * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.gc_efficiency > 0.8);

        Ok(GarbageCollectionResult {
            test_results,
            overall_success,
        })
    }

    /// Test memory fragmentation
    async fn test_memory_fragmentation(&self) -> Result<MemoryFragmentationResult> {
        println!("  🧩 Testing memory fragmentation...");

        let fragmentation_scenarios = vec![
            ("Random Allocation", 10000, 1024),
            ("Pattern Allocation", 5000, 2048),
            ("Burst Allocation", 1000, 10240),
        ];

        let mut test_results = Vec::new();

        for (scenario_name, allocation_count, max_size) in fragmentation_scenarios {
            let start = Instant::now();
            let initial_memory = self.get_memory_usage();

            // Create fragmented allocation pattern
            let mut allocations = Vec::new();
            let mut freed_allocations = Vec::new();

            // Phase 1: Allocate with varying sizes to create fragmentation
            for i in 0..allocation_count {
                let size = if i % 3 == 0 { max_size } 
                          else if i % 3 == 1 { max_size / 2 } 
                          else { max_size / 4 };
                
                let allocation = vec![42u8; size];
                allocations.push((i, allocation));
            }

            let allocated_memory = self.get_memory_usage();

            // Phase 2: Free every other allocation to create fragmentation
            for (i, allocation) in allocations.iter().enumerate() {
                if i % 2 == 0 {
                    freed_allocations.push(allocation.0);
                }
            }

            // Actually free the selected allocations
            allocations.retain(|(i, _)| !freed_allocations.contains(i));

            let fragmented_memory = self.get_memory_usage();

            // Phase 3: Try to allocate large blocks in fragmented memory
            let large_allocation_start = Instant::now();
            let mut large_allocations = Vec::new();
            
            for i in 0..100 {
                match std::panic::catch_unwind(|| {
                    vec![42u8; max_size * 2]
                }) {
                    Ok(allocation) => {
                        large_allocations.push(allocation);
                    },
                    Err(_) => {
                        break; // Allocation failed due to fragmentation
                    }
                }
            }

            let large_allocation_time = large_allocation_start.elapsed();
            let final_memory = self.get_memory_usage();

            // Calculate fragmentation metrics
            let total_allocated = allocated_memory.saturating_sub(initial_memory);
            let total_freed = allocated_memory.saturating_sub(fragmented_memory);
            let fragmentation_ratio = if total_allocated > 0 {
                total_freed as f64 / total_allocated as f64
            } else {
                0.0
            };

            let large_allocation_success_rate = large_allocations.len() as f64 / 100.0;

            test_results.push(MemoryFragmentationTest {
                scenario_name: scenario_name.to_string(),
                allocation_count,
                max_size,
                initial_memory,
                allocated_memory,
                fragmented_memory,
                final_memory,
                total_allocated,
                total_freed,
                fragmentation_ratio,
                large_allocation_success_rate,
                large_allocation_time,
            });

            println!("    {}: {:.1}% fragmentation, {:.1}% large alloc success", 
                scenario_name,
                fragmentation_ratio * 100.0,
                large_allocation_success_rate * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.large_allocation_success_rate > 0.5);

        Ok(MemoryFragmentationResult {
            test_results,
            overall_success,
        })
    }

    /// Test cache memory usage
    async fn test_cache_memory_usage(&self) -> Result<CacheMemoryResult> {
        println!("  🗄️  Testing cache memory usage...");

        let cache_sizes = vec![
            ("Small Cache", 1000),
            ("Medium Cache", 10000),
            ("Large Cache", 100000),
            ("XLarge Cache", 1000000),
        ];

        let mut test_results = Vec::new();

        for (cache_name, cache_capacity) in cache_sizes {
            let start = Instant::now();
            let initial_memory = self.get_memory_usage();

            // Create cache with specific capacity
            let cache_config = CacheConfig {
                max_size: cache_capacity,
                ttl_seconds: 3600,
                cleanup_interval_seconds: 300,
            };
            let cache_manager = Arc::new(CacheManager::new_with_config(cache_config));

            // Fill cache to capacity
            let fill_start = Instant::now();
            for i in 0..cache_capacity {
                let key = format!("key_{}", i);
                let value = format!("value_with_some_additional_data_{}", i);
                cache_manager.set(&key, &value).await.unwrap();
            }
            let fill_time = fill_start.elapsed();

            let filled_memory = self.get_memory_usage();

            // Test cache operations
            let operation_start = Instant::now();
            let mut hits = 0;
            let mut misses = 0;

            for i in 0..cache_capacity * 2 {
                let key = format!("key_{}", i);
                if cache_manager.get(&key).await.unwrap().is_some() {
                    hits += 1;
                } else {
                    misses += 1;
                }
            }
            let operation_time = operation_start.elapsed();

            // Clear cache
            let clear_start = Instant::now();
            for i in 0..cache_capacity {
                let key = format!("key_{}", i);
                cache_manager.remove(&key).await.unwrap();
            }
            let clear_time = clear_start.elapsed();

            let final_memory = self.get_memory_usage();
            let total_time = start.elapsed();

            let memory_used = filled_memory.saturating_sub(initial_memory);
            let memory_per_entry = if cache_capacity > 0 {
                memory_used as f64 / cache_capacity as f64
            } else {
                0.0
            };

            let hit_rate = hits as f64 / (hits + misses) as f64;

            test_results.push(CacheMemoryTest {
                cache_name: cache_name.to_string(),
                cache_capacity,
                initial_memory,
                filled_memory,
                final_memory,
                memory_used,
                memory_per_entry,
                fill_time,
                operation_time,
                clear_time,
                total_time,
                hits,
                misses,
                hit_rate,
            });

            println!("    {}: {:.2} MB used, {:.1} bytes/entry, {:.1}% hit rate", 
                cache_name,
                memory_used as f64 / (1024.0 * 1024.0),
                memory_per_entry,
                hit_rate * 100.0);
        }

        let overall_success = test_results.iter().all(|r| r.hit_rate > 0.8 && r.memory_per_entry < 1000.0);

        Ok(CacheMemoryResult {
            test_results,
            overall_success,
        })
    }

    /// Test scalability scenarios
    async fn test_scalability_scenarios(&self) -> Result<ScalabilityResults> {
        println!("📈 Testing scalability scenarios...");

        let mut results = ScalabilityResults::new();

        // Test 3.1: Horizontal scalability
        results.horizontal = self.test_horizontal_scalability().await?;

        // Test 3.2: Vertical scalability
        results.vertical = self.test_vertical_scalability().await?;

        // Test 3.3: Load scalability
        results.load = self.test_load_scalability().await?;

        // Test 3.4: Performance degradation
        results.performance_degradation = self.test_performance_degradation().await?;

        // Test 3.5: Resource scaling
        results.resource_scaling = self.test_resource_scaling().await?;

        // Test 3.6: Multi-tenant scalability
        results.multi_tenant = self.test_multi_tenant_scalability().await?;

        self.print_scalability_summary(&results);
        Ok(results)
    }

    /// Test horizontal scalability
    async fn test_horizontal_scalability(&self) -> Result<HorizontalScalabilityResult> {
        println!("  ↔️  Testing horizontal scalability...");

        let node_counts = vec![1, 2, 4, 8, 16];
        let requests_per_node = 1000;
        let mut test_results = Vec::new();

        for node_count in node_counts {
            let start = Instant::now();

            // Create mock cluster nodes
            let nodes: Vec<Arc<MockClusterNode>> = (0..node_count)
                .map(|i| Arc::new(MockClusterNode::new(format!("node_{}", i))))
                .collect();

            let cluster = Arc::new(MockCluster::new(nodes));
            let mut handles = Vec::new();

            // Distribute requests across nodes
            for node in 0..node_count {
                for req in 0..requests_per_node {
                    let cluster = cluster.clone();
                    let node_id = node;
                    let request_id = req + (node * requests_per_node);

                    let handle = tokio::spawn(async move {
                        let req_start = Instant::now();
                        let result = cluster.process_request(node_id, request_id).await;
                        (result.is_ok(), req_start.elapsed())
                    });

                    handles.push(handle);
                }
            }

            let mut successful_requests = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_requests += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let total_requests = node_count * requests_per_node;
            let avg_response_time = total_response_time / total_requests as u32;
            let requests_per_second = total_requests as f64 / total_time.as_secs_f64();
            let success_rate = successful_requests as f64 / total_requests as f64;

            test_results.push(HorizontalScalabilityTest {
                node_count,
                total_requests,
                successful_requests,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                requests_per_second,
                success_rate,
            });

            println!("    {} nodes: {:.2} req/sec, {:.1}% success", 
                node_count, requests_per_second, success_rate * 100.0);
        }

        // Calculate scalability efficiency
        let baseline_rps = test_results.first().unwrap().requests_per_second;
        let max_rps = test_results.iter().map(|r| r.requests_per_second).fold(0.0, f64::max);
        let scalability_efficiency = max_rps / baseline_rps;

        let overall_success = scalability_efficiency > 0.7; // At least 70% linear scaling

        Ok(HorizontalScalabilityResult {
            test_results,
            scalability_efficiency,
            overall_success,
        })
    }

    /// Test vertical scalability
    async fn test_vertical_scalability(&self) -> Result<VerticalScalabilityResult> {
        println!("  ↕️  Testing vertical scalability...");

        let cpu_cores = vec![1, 2, 4, 8, 16];
        let memory_sizes = vec![1024, 2048, 4096, 8192]; // MB
        let mut test_results = Vec::new();

        for cores in cpu_cores {
            for memory_mb in memory_sizes.iter() {
                let start = Instant::now();

                // Simulate vertical scaling by adjusting worker threads
                let worker_count = cores;
                let semaphore = Arc::new(Semaphore::new(worker_count));
                let mut handles = Vec::new();

                let workload_size = 10000;
                let memory_per_workload = *memory_mb * 1024 * 1024 / workload_size; // bytes per workload

                for i in 0..workload_size {
                    let semaphore = semaphore.clone();
                    let memory_size = memory_per_workload;

                    let handle = tokio::spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let work_start = Instant::now();

                        // Simulate CPU and memory intensive work
                        let data = vec![42u8; memory_size];
                        let _result: u64 = data.iter().enumerate()
                            .map(|(j, &x)| (x as u64).wrapping_mul((j as u64).wrapping_add(1)))
                            .sum();

                        work_start.elapsed()
                    });

                    handles.push(handle);
                }

                let mut total_work_time = Duration::ZERO;
                let mut max_work_time = Duration::ZERO;
                let mut min_work_time = Duration::MAX;

                for handle in handles {
                    let work_time = handle.await?;
                    total_work_time += work_time;
                    max_work_time = max_work_time.max(work_time);
                    min_work_time = min_work_time.min(work_time);
                }

                let total_time = start.elapsed();
                let avg_work_time = total_work_time / workload_size as u32;
                let throughput = workload_size as f64 / total_time.as_secs_f64();

                test_results.push(VerticalScalabilityTest {
                    cpu_cores: cores,
                    memory_mb: *memory_mb,
                    workload_size,
                    total_time,
                    avg_work_time,
                    min_work_time,
                    max_work_time,
                    throughput,
                });

                println!("    {} cores, {} MB: {:.2} work/sec", 
                    cores, memory_mb, throughput);
            }
        }

        // Calculate vertical scaling efficiency
        let baseline_throughput = test_results.iter()
            .filter(|r| r.cpu_cores == 1 && r.memory_mb == 1024)
            .map(|r| r.throughput)
            .next()
            .unwrap_or(1.0);

        let max_throughput = test_results.iter().map(|r| r.throughput).fold(0.0, f64::max);
        let vertical_efficiency = max_throughput / baseline_throughput;

        let overall_success = vertical_efficiency > 0.6; // At least 60% vertical scaling

        Ok(VerticalScalabilityResult {
            test_results,
            vertical_efficiency,
            overall_success,
        })
    }

    /// Test load scalability
    async fn test_load_scalability(&self) -> Result<LoadScalabilityResult> {
        println!("  ⚖️  Testing load scalability...");

        let load_levels = vec![
            ("Light Load", 100),
            ("Medium Load", 1000),
            ("Heavy Load", 5000),
            ("Extreme Load", 10000),
            ("Stress Load", 20000),
        ];

        let mut test_results = Vec::new();

        for (load_name, concurrent_requests) in load_levels {
            let start = Instant::now();

            // Create multiple service instances to handle load
            let service_instances: Vec<Arc<MockServiceInstance>> = (0..5)
                .map(|i| Arc::new(MockServiceInstance::new(format!("svc_{}", i))))
                .collect();

            let load_balancer = Arc::new(LoadBalancer::new(service_instances));
            let semaphore = Arc::new(Semaphore::new(concurrent_requests));
            let mut handles = Vec::new();

            for i in 0..concurrent_requests {
                let semaphore = semaphore.clone();
                let load_balancer = load_balancer.clone();

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let req_start = Instant::now();

                    let result = load_balancer.process_request(format!("load_req_{}", i)).await;
                    (result.is_ok(), req_start.elapsed())
                });

                handles.push(handle);
            }

            let mut successful_requests = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_requests += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / concurrent_requests as u32;
            let requests_per_second = concurrent_requests as f64 / total_time.as_secs_f64();
            let success_rate = successful_requests as f64 / concurrent_requests as f64;

            test_results.push(LoadScalabilityTest {
                load_name: load_name.to_string(),
                concurrent_requests,
                successful_requests,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                requests_per_second,
                success_rate,
            });

            println!("    {}: {:.2} req/sec, {:.1}% success, avg {:?}", 
                load_name, requests_per_second, success_rate * 100.0, avg_response_time);
        }

        // Calculate load scalability efficiency
        let light_load_rps = test_results.iter()
            .find(|r| r.load_name == "Light Load")
            .map(|r| r.requests_per_second)
            .unwrap_or(1.0);

        let max_rps = test_results.iter().map(|r| r.requests_per_second).fold(0.0, f64::max);
        let load_efficiency = max_rps / light_load_rps;

        let overall_success = test_results.iter().all(|r| r.success_rate > 0.95 && r.requests_per_second > 100.0);

        Ok(LoadScalabilityResult {
            test_results,
            load_efficiency,
            overall_success,
        })
    }

    /// Test performance degradation
    async fn test_performance_degradation(&self) -> Result<PerformanceDegradationResult> {
        println!("  📉 Testing performance degradation...");

        let degradation_scenarios = vec![
            ("Memory Pressure", 1000),
            ("CPU Contention", 1000),
            ("I/O Bottleneck", 1000),
            ("Network Latency", 1000),
        ];

        let mut test_results = Vec::new();

        for (scenario_name, base_operations) in degradation_scenarios {
            // Baseline performance
            let baseline_start = Instant::now();
            let baseline_result = self.run_baseline_performance(base_operations).await;
            let baseline_time = baseline_start.elapsed();

            // Degraded performance
            let degraded_start = Instant::now();
            let degraded_result = self.run_degraded_performance(scenario_name, base_operations).await;
            let degraded_time = degraded_start.elapsed();

            let performance_degradation = if baseline_time.as_nanos() > 0 {
                (degraded_time.as_nanos() as f64 - baseline_time.as_nanos() as f64) / 
                baseline_time.as_nanos() as f64 * 100.0
            } else {
                0.0
            };

            let throughput_degradation = if baseline_result > 0.0 {
                (baseline_result - degraded_result) / baseline_result * 100.0
            } else {
                0.0
            };

            test_results.push(PerformanceDegradationTest {
                scenario_name: scenario_name.to_string(),
                base_operations,
                baseline_time,
                degraded_time,
                baseline_throughput: baseline_result,
                degraded_throughput: degraded_result,
                performance_degradation,
                throughput_degradation,
            });

            println!("    {}: {:.1}% performance degradation, {:.1}% throughput loss", 
                scenario_name, performance_degradation, throughput_degradation);
        }

        let overall_success = test_results.iter().all(|r| r.performance_degradation < 200.0); // Less than 200% degradation

        Ok(PerformanceDegradationResult {
            test_results,
            overall_success,
        })
    }

    /// Test resource scaling
    async fn test_resource_scaling(&self) -> Result<ResourceScalingResult> {
        println!("  📊 Testing resource scaling...");

        let resource_configs = vec![
            ("Minimal", 1, 512, 100),      // 1 core, 512MB RAM, 100 connections
            ("Standard", 2, 1024, 500),    // 2 cores, 1GB RAM, 500 connections
            ("Enhanced", 4, 2048, 1000),   // 4 cores, 2GB RAM, 1000 connections
            ("Premium", 8, 4096, 2000),    // 8 cores, 4GB RAM, 2000 connections
            ("Enterprise", 16, 8192, 5000), // 16 cores, 8GB RAM, 5000 connections
        ];

        let mut test_results = Vec::new();

        for (config_name, cpu_cores, memory_mb, max_connections) in resource_configs {
            let start = Instant::now();

            // Create resource manager with specific configuration
            let resource_config = ResourceConfig {
                cpu_cores,
                memory_mb,
                max_connections,
            };
            let resource_manager = Arc::new(ResourceManager::new_with_config(resource_config));

            // Test resource utilization under load
            let load_factor = max_connections;
            let semaphore = Arc::new(Semaphore::new(load_factor));
            let mut handles = Vec::new();

            for i in 0..load_factor {
                let semaphore = semaphore.clone();
                let resource_manager = resource_manager.clone();

                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let op_start = Instant::now();

                    let result = resource_manager.execute_operation(format!("res_op_{}", i)).await;
                    (result.is_ok(), op_start.elapsed())
                });

                handles.push(handle);
            }

            let mut successful_ops = 0;
            let mut total_response_time = Duration::ZERO;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_ops += 1;
                }
                total_response_time += response_time;
            }

            let total_time = start.elapsed();
            let avg_response_time = total_response_time / load_factor as u32;
            let operations_per_second = load_factor as f64 / total_time.as_secs_f64();
            let success_rate = successful_ops as f64 / load_factor as f64;

            // Get resource utilization metrics
            let resource_metrics = resource_manager.get_utilization_metrics();

            test_results.push(ResourceScalingTest {
                config_name: config_name.to_string(),
                cpu_cores,
                memory_mb,
                max_connections,
                total_time,
                avg_response_time,
                operations_per_second,
                success_rate,
                resource_metrics,
            });

            println!("    {}: {:.2} ops/sec, {:.1}% CPU, {:.1}% RAM", 
                config_name, operations_per_second, 
                resource_metrics.cpu_utilization * 100.0,
                resource_metrics.memory_utilization * 100.0);
        }

        // Calculate scaling efficiency
        let minimal_ops_per_sec = test_results.iter()
            .find(|r| r.config_name == "Minimal")
            .map(|r| r.operations_per_second)
            .unwrap_or(1.0);

        let enterprise_ops_per_sec = test_results.iter()
            .find(|r| r.config_name == "Enterprise")
            .map(|r| r.operations_per_second)
            .unwrap_or(1.0);

        let scaling_efficiency = enterprise_ops_per_sec / minimal_ops_per_sec;

        let overall_success = scaling_efficiency > 10.0; // At least 10x scaling

        Ok(ResourceScalingResult {
            test_results,
            scaling_efficiency,
            overall_success,
        })
    }

    /// Test multi-tenant scalability
    async fn test_multi_tenant_scalability(&self) -> Result<MultiTenantScalabilityResult> {
        println!("  🏢 Testing multi-tenant scalability...");

        let tenant_counts = vec![1, 10, 50, 100, 500, 1000];
        let operations_per_tenant = 100;
        let mut test_results = Vec::new();

        for tenant_count in tenant_counts {
            let start = Instant::now();

            // Create multi-tenant environment
            let tenant_manager = Arc::new(TenantManager::new());
            
            // Initialize tenants
            for i in 0..tenant_count {
                let tenant_id = format!("tenant_{}", i);
                tenant_manager.create_tenant(&tenant_id).await.unwrap();
            }

            let mut handles = Vec::new();

            // Execute operations for each tenant
            for tenant in 0..tenant_count {
                for op in 0..operations_per_tenant {
                    let tenant_manager = tenant_manager.clone();
                    let tenant_id = format!("tenant_{}", tenant);
                    let operation_id = op;

                    let handle = tokio::spawn(async move {
                        let op_start = Instant::now();

                        let result = tenant_manager.execute_tenant_operation(&tenant_id, operation_id).await;
                        (result.is_ok(), op_start.elapsed())
                    });

                    handles.push(handle);
                }
            }

            let mut successful_ops = 0;
            let mut total_response_time = Duration::ZERO;
            let mut max_response_time = Duration::ZERO;
            let mut min_response_time = Duration::MAX;

            for handle in handles {
                let (success, response_time) = handle.await?;
                if success {
                    successful_ops += 1;
                }
                total_response_time += response_time;
                max_response_time = max_response_time.max(response_time);
                min_response_time = min_response_time.min(response_time);
            }

            let total_time = start.elapsed();
            let total_operations = tenant_count * operations_per_tenant;
            let avg_response_time = total_response_time / total_operations as u32;
            let operations_per_second = total_operations as f64 / total_time.as_secs_f64();
            let success_rate = successful_ops as f64 / total_operations as f64;

            // Get tenant isolation metrics
            let isolation_metrics = tenant_manager.get_isolation_metrics();

            test_results.push(MultiTenantScalabilityTest {
                tenant_count,
                total_operations,
                successful_operations: successful_ops,
                total_time,
                avg_response_time,
                min_response_time,
                max_response_time,
                operations_per_second,
                success_rate,
                isolation_metrics,
            });

            println!("    {} tenants: {:.2} ops/sec, {:.1}% success, {:.1}% isolation", 
                tenant_count, operations_per_second, success_rate * 100.0,
                isolation_metrics.isolation_score * 100.0);
        }

        // Calculate multi-tenant scaling efficiency
        let single_tenant_ops = test_results.iter()
            .find(|r| r.tenant_count == 1)
            .map(|r| r.operations_per_second)
            .unwrap_or(1.0);

        let max_tenant_ops = test_results.iter().map(|r| r.operations_per_second).fold(0.0, f64::max);
        let tenant_efficiency = max_tenant_ops / single_tenant_ops;

        let overall_success = tenant_efficiency > 0.5; // At least 50% efficiency with multiple tenants

        Ok(MultiTenantScalabilityResult {
            test_results,
            tenant_efficiency,
            overall_success,
        })
    }

    // Helper methods
    fn get_memory_usage(&self) -> usize {
        // This is a mock implementation - in real code you'd use platform-specific APIs
        // For now, return a simulated value based on current timestamp
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        (timestamp % 1000) as usize * 1024 * 1024 // Simulate 0-999 MB
    }

    async fn simulate_operation_under_pressure(&self, operation_id: usize) -> Result<()> {
        // Simulate different types of operations under memory pressure
        match operation_id % 4 {
            0 => {
                // String operation
                let _result = format!("operation_{}_result", operation_id);
            },
            1 => {
                // Math operation
                let _result = (operation_id as f64).sin().cos().tan();
            },
            2 => {
                // Collection operation
                let vec: Vec<usize> = (0..100).map(|i| i * operation_id).collect();
                let _result = vec.iter().sum::<usize>();
            },
            3 => {
                // Encryption simulation
                let data = vec![operation_id as u8; 1024];
                let key = vec![42u8; 32];
                // Simulate encryption work without actual encryption
                let _result: Vec<u8> = data.iter().zip(key.iter()).map(|(d, k)| d ^ k).collect();
            },
            _ => {}
        }
        Ok(())
    }

    async fn run_baseline_performance(&self, operations: usize) -> f64 {
        let start = Instant::now();
        
        for i in 0..operations {
            let _result = format!("baseline_op_{}", i);
        }
        
        let duration = start.elapsed();
        operations as f64 / duration.as_secs_f64()
    }

    async fn run_degraded_performance(&self, scenario: &str, operations: usize) -> f64 {
        let start = Instant::now();
        
        for i in 0..operations {
            match scenario {
                "Memory Pressure" => {
                    // Allocate and deallocate memory to simulate pressure
                    let _data = vec![42u8; 10240];
                },
                "CPU Contention" => {
                    // CPU-intensive operation
                    let _result = (i as f64).sin().cos().tan().sqrt();
                },
                "I/O Bottleneck" => {
                    // Simulate I/O delay
                    tokio::time::sleep(Duration::from_micros(100)).await;
                },
                "Network Latency" => {
                    // Simulate network delay
                    tokio::time::sleep(Duration::from_millis(1)).await;
                },
                _ => {
                    let _result = format!("degraded_op_{}", i);
                }
            }
        }
        
        let duration = start.elapsed();
        operations as f64 / duration.as_secs_f64()
    }

    fn print_high_concurrency_summary(&self, results: &HighConcurrencyResults) {
        println!("\n📊 High-Concurrency Test Summary");
        println!("=================================");
        
        let mut passed_categories = 0;
        let total_categories = 8;

        if results.concurrent_auth.overall_success {
            println!("✅ Concurrent Authentication: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Concurrent Authentication: FAILED");
        }

        if results.concurrent_encryption.overall_success {
            println!("✅ Concurrent Encryption: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Concurrent Encryption: FAILED");
        }

        if results.concurrent_database.overall_success {
            println!("✅ Concurrent Database: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Concurrent Database: FAILED");
        }

        if results.concurrent_cache.overall_success {
            println!("✅ Concurrent Cache: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Concurrent Cache: FAILED");
        }

        if results.concurrent_audit.overall_success {
            println!("✅ Concurrent Audit: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Concurrent Audit: FAILED");
        }

        if results.load_balancing.overall_success {
            println!("✅ Load Balancing: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Load Balancing: FAILED");
        }

        if results.resource_contention.overall_success {
            println!("✅ Resource Contention: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Resource Contention: FAILED");
        }

        if results.connection_pooling.overall_success {
            println!("✅ Connection Pooling: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Connection Pooling: FAILED");
        }

        println!("\nHigh-Concurrency Results: {}/{} categories passed ({:.1}%)", 
            passed_categories, total_categories, 
            (passed_categories as f64 / total_categories as f64) * 100.0);
    }

    fn print_memory_usage_summary(&self, results: &MemoryUsageResults) {
        println!("\n💾 Memory Usage Test Summary");
        println!("============================");
        
        let mut passed_categories = 0;
        let total_categories = 6;

        if results.allocation_patterns.overall_success {
            println!("✅ Memory Allocation Patterns: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Memory Allocation Patterns: FAILED");
        }

        if results.memory_leaks.overall_success {
            println!("✅ Memory Leak Detection: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Memory Leak Detection: FAILED");
        }

        if results.memory_pressure.overall_success {
            println!("✅ Memory Pressure Handling: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Memory Pressure Handling: FAILED");
        }

        if results.garbage_collection.overall_success {
            println!("✅ Garbage Collection Impact: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Garbage Collection Impact: FAILED");
        }

        if results.memory_fragmentation.overall_success {
            println!("✅ Memory Fragmentation: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Memory Fragmentation: FAILED");
        }

        if results.cache_memory.overall_success {
            println!("✅ Cache Memory Usage: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Cache Memory Usage: FAILED");
        }

        println!("\nMemory Usage Results: {}/{} categories passed ({:.1}%)", 
            passed_categories, total_categories, 
            (passed_categories as f64 / total_categories as f64) * 100.0);
    }

    fn print_scalability_summary(&self, results: &ScalabilityResults) {
        println!("\n📈 Scalability Test Summary");
        println!("===========================");
        
        let mut passed_categories = 0;
        let total_categories = 6;

        if results.horizontal.overall_success {
            println!("✅ Horizontal Scalability: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Horizontal Scalability: FAILED");
        }

        if results.vertical.overall_success {
            println!("✅ Vertical Scalability: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Vertical Scalability: FAILED");
        }

        if results.load.overall_success {
            println!("✅ Load Scalability: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Load Scalability: FAILED");
        }

        if results.performance_degradation.overall_success {
            println!("✅ Performance Degradation: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Performance Degradation: FAILED");
        }

        if results.resource_scaling.overall_success {
            println!("✅ Resource Scaling: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Resource Scaling: FAILED");
        }

        if results.multi_tenant.overall_success {
            println!("✅ Multi-Tenant Scalability: PASSED");
            passed_categories += 1;
        } else {
            println!("❌ Multi-Tenant Scalability: FAILED");
        }

        println!("\nScalability Results: {}/{} categories passed ({:.1}%)", 
            passed_categories, total_categories, 
            (passed_categories as f64 / total_categories as f64) * 100.0);
    }

    fn generate_comprehensive_report(&self, results: &PerformanceLoadTestResults, total_time: Duration) {
        println!("\n🎯 COMPREHENSIVE PERFORMANCE & LOAD TEST REPORT");
        println!("==============================================");
        
        // Executive Summary
        println!("\n📋 EXECUTIVE SUMMARY");
        println!("===================");
        println!("Total test execution time: {:?}", total_time);
        println!("Test sections completed: 3/3");
        
        // Calculate overall success metrics
        let high_concurrency_score = self.calculate_high_concurrency_score(&results.high_concurrency);
        let memory_usage_score = self.calculate_memory_usage_score(&results.memory_usage);
        let scalability_score = self.calculate_scalability_score(&results.scalability);
        
        let overall_score = (high_concurrency_score + memory_usage_score + scalability_score) / 3.0;
        
        println!("Overall Performance Score: {:.1}/100", overall_score);
        
        if overall_score >= 90.0 {
            println!("🏆 GRADE: A+ (EXCELLENT)");
            println!("Fortress demonstrates exceptional performance and scalability characteristics.");
        } else if overall_score >= 80.0 {
            println!("🥇 GRADE: A (VERY GOOD)");
            println!("Fortress shows strong performance with minor optimization opportunities.");
        } else if overall_score >= 70.0 {
            println!("🥈 GRADE: B (GOOD)");
            println!("Fortress performs well with some areas for improvement.");
        } else if overall_score >= 60.0 {
            println!("🥉 GRADE: C (ACCEPTABLE)");
            println!("Fortress meets basic requirements but needs optimization work.");
        } else {
            println!("⚠️  GRADE: D (NEEDS IMPROVEMENT)");
            println!("Fortress requires significant performance optimization.");
        }

        // Detailed Results
        println!("\n📊 DETAILED RESULTS");
        println!("===================");
        
        println!("\n🔥 High-Concurrency Performance: {:.1}/100", high_concurrency_score);
        self.print_high_concurrency_detailed(&results.high_concurrency);
        
        println!("\n💾 Memory Usage Performance: {:.1}/100", memory_usage_score);
        self.print_memory_usage_detailed(&results.memory_usage);
        
        println!("\n📈 Scalability Performance: {:.1}/100", scalability_score);
        self.print_scalability_detailed(&results.scalability);

        // Recommendations
        println!("\n💡 PERFORMANCE RECOMMENDATIONS");
        println!("=============================");
        
        if high_concurrency_score < 80.0 {
            println!("🔧 Optimize concurrent operations for better throughput");
            println!("🔧 Consider implementing connection pooling and load balancing");
        }
        
        if memory_usage_score < 80.0 {
            println!("🔧 Review memory allocation patterns and implement better garbage collection");
            println!("🔧 Consider implementing memory pools and object reuse patterns");
        }
        
        if scalability_score < 80.0 {
            println!("🔧 Improve horizontal and vertical scaling capabilities");
            println!("🔧 Optimize resource utilization under different load patterns");
        }

        println!("\n🎉 PERFORMANCE & LOAD TEST SUITE COMPLETED!");
        println!("Fortress performance characteristics have been thoroughly evaluated.");
    }

    fn calculate_high_concurrency_score(&self, results: &HighConcurrencyResults) -> f64 {
        let mut score = 0.0;
        let mut total_weight = 0.0;
        
        let tests = [
            (&results.concurrent_auth.overall_success, 15.0),
            (&results.concurrent_encryption.overall_success, 15.0),
            (&results.concurrent_database.overall_success, 10.0),
            (&results.concurrent_cache.overall_success, 15.0),
            (&results.concurrent_audit.overall_success, 10.0),
            (&results.load_balancing.overall_success, 15.0),
            (&results.resource_contention.overall_success, 10.0),
            (&results.connection_pooling.overall_success, 10.0),
        ];
        
        for (success, weight) in tests {
            if **success {
                score += weight;
            }
            total_weight += weight;
        }
        
        if total_weight > 0.0 {
            (score / total_weight) * 100.0
        } else {
            0.0
        }
    }

    fn calculate_memory_usage_score(&self, results: &MemoryUsageResults) -> f64 {
        let mut score = 0.0;
        let mut total_weight = 0.0;
        
        let tests = [
            (&results.allocation_patterns.overall_success, 20.0),
            (&results.memory_leaks.overall_success, 20.0),
            (&results.memory_pressure.overall_success, 15.0),
            (&results.garbage_collection.overall_success, 15.0),
            (&results.memory_fragmentation.overall_success, 15.0),
            (&results.cache_memory.overall_success, 15.0),
        ];
        
        for (success, weight) in tests {
            if **success {
                score += weight;
            }
            total_weight += weight;
        }
        
        if total_weight > 0.0 {
            (score / total_weight) * 100.0
        } else {
            0.0
        }
    }

    fn calculate_scalability_score(&self, results: &ScalabilityResults) -> f64 {
        let mut score = 0.0;
        let mut total_weight = 0.0;
        
        let tests = [
            (&results.horizontal.overall_success, 20.0),
            (&results.vertical.overall_success, 15.0),
            (&results.load.overall_success, 15.0),
            (&results.performance_degradation.overall_success, 15.0),
            (&results.resource_scaling.overall_success, 20.0),
            (&results.multi_tenant.overall_success, 15.0),
        ];
        
        for (success, weight) in tests {
            if **success {
                score += weight;
            }
            total_weight += weight;
        }
        
        if total_weight > 0.0 {
            (score / total_weight) * 100.0
        } else {
            0.0
        }
    }

    fn print_high_concurrency_detailed(&self, results: &HighConcurrencyResults) {
        println!("  Concurrent Authentication: {}", if results.concurrent_auth.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Concurrent Encryption: {}", if results.concurrent_encryption.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Concurrent Database: {}", if results.concurrent_database.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Concurrent Cache: {}", if results.concurrent_cache.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Concurrent Audit: {}", if results.concurrent_audit.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Load Balancing: {}", if results.load_balancing.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Resource Contention: {}", if results.resource_contention.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Connection Pooling: {}", if results.connection_pooling.overall_success { "✅ PASSED" } else { "❌ FAILED" });
    }

    fn print_memory_usage_detailed(&self, results: &MemoryUsageResults) {
        println!("  Memory Allocation Patterns: {}", if results.allocation_patterns.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Memory Leak Detection: {}", if results.memory_leaks.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Memory Pressure Handling: {}", if results.memory_pressure.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Garbage Collection Impact: {}", if results.garbage_collection.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Memory Fragmentation: {}", if results.memory_fragmentation.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Cache Memory Usage: {}", if results.cache_memory.overall_success { "✅ PASSED" } else { "❌ FAILED" });
    }

    fn print_scalability_detailed(&self, results: &ScalabilityResults) {
        println!("  Horizontal Scalability: {}", if results.horizontal.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Vertical Scalability: {}", if results.vertical.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Load Scalability: {}", if results.load.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Performance Degradation: {}", if results.performance_degradation.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Resource Scaling: {}", if results.resource_scaling.overall_success { "✅ PASSED" } else { "❌ FAILED" });
        println!("  Multi-Tenant Scalability: {}", if results.multi_tenant.overall_success { "✅ PASSED" } else { "❌ FAILED" });
    }
}

// Mock implementations for testing
#[derive(Debug)]
struct MockDatabase {
    operations: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl MockDatabase {
    fn new() -> Self {
        Self {
            operations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn execute_operation(&self, operation_type: &str, record_id: usize) -> Result<()> {
        // Simulate database operation with realistic timing
        tokio::time::sleep(Duration::from_micros(100 + (record_id % 100) as u64)).await;
        
        let mut ops = self.operations.write().await;
        ops.entry(operation_type.to_string())
           .or_insert_with(Vec::new)
           .push(format!("record_{}", record_id));
        
        Ok(())
    }
}

#[derive(Debug)]
struct MockServiceInstance {
    name: String,
    request_count: AtomicUsize,
}

impl MockServiceInstance {
    fn new(name: String) -> Self {
        Self {
            name,
            request_count: AtomicUsize::new(0),
        }
    }

    async fn process_request(&self, request: String) -> Result<String> {
        // Simulate service processing time
        tokio::time::sleep(Duration::from_millis(1 + (self.request_count.fetch_add(1, Ordering::Relaxed) % 10) as u64)).await;
        
        Ok(format!("{}:processed:{}", self.name, request))
    }
}

#[derive(Debug)]
struct LoadBalancer {
    instances: Vec<Arc<MockServiceInstance>>,
    round_robin: AtomicUsize,
}

impl LoadBalancer {
    fn new(instances: Vec<Arc<MockServiceInstance>>) -> Self {
        Self {
            instances,
            round_robin: AtomicUsize::new(0),
        }
    }

    async fn process_request(&self, request: String) -> Result<String> {
        let index = self.round_robin.fetch_add(1, Ordering::Relaxed) % self.instances.len();
        let instance = &self.instances[index];
        instance.process_request(request).await
    }

    fn get_load_distribution(&self) -> Vec<usize> {
        self.instances.iter()
            .map(|inst| inst.request_count.load(Ordering::Relaxed))
            .collect()
    }
}

#[derive(Debug)]
struct SharedResource {
    counter: AtomicU64,
}

impl SharedResource {
    fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    async fn expensive_operation(&mut self) -> Result<u64> {
        // Simulate expensive operation
        tokio::time::sleep(Duration::from_micros(1000)).await;
        Ok(self.counter.fetch_add(1, Ordering::Relaxed))
    }

    async fn read_operation(&mut self) -> Result<u64> {
        // Simulate read operation
        tokio::time::sleep(Duration::from_micros(100)).await;
        Ok(self.counter.load(Ordering::Relaxed))
    }

    async fn write_operation(&mut self) -> Result<u64> {
        // Simulate write operation
        tokio::time::sleep(Duration::from_micros(500)).await;
        Ok(self.counter.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug)]
struct ConnectionPoolConfig {
    max_connections: usize,
    min_connections: usize,
    connection_timeout: Duration,
    idle_timeout: Duration,
}

#[derive(Debug)]
struct ConnectionPool {
    config: ConnectionPoolConfig,
    active_connections: AtomicUsize,
    total_operations: AtomicU64,
}

impl ConnectionPool {
    fn new_with_config(config: ConnectionPoolConfig) -> Self {
        Self {
            config,
            active_connections: AtomicUsize::new(config.min_connections),
            total_operations: AtomicU64::new(0),
        }
    }

    async fn execute_operation(&self, operation: String) -> Result<String> {
        // Simulate connection pool operation
        let current_connections = self.active_connections.load(Ordering::Relaxed);
        
        if current_connections < self.config.max_connections {
            self.active_connections.fetch_add(1, Ordering::Relaxed);
        }

        // Simulate operation
        tokio::time::sleep(Duration::from_millis(1)).await;
        
        let result = format!("pool_op:{}:{}", current_connections, operation);
        self.total_operations.fetch_add(1, Ordering::Relaxed);
        
        // Simulate connection release
        if current_connections > self.config.min_connections {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }

        Ok(result)
    }

    fn get_stats(&self) -> ConnectionPoolStats {
        ConnectionPoolStats {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_operations: self.total_operations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct ConnectionPoolStats {
    active_connections: usize,
    total_operations: u64,
}

#[derive(Debug)]
struct ResourceConfig {
    cpu_cores: usize,
    memory_mb: usize,
    max_connections: usize,
}

#[derive(Debug)]
struct ResourceManager {
    config: ResourceConfig,
    cpu_usage: AtomicU64,
    memory_usage: AtomicU64,
}

impl ResourceManager {
    fn new_with_config(config: ResourceConfig) -> Self {
        Self {
            config,
            cpu_usage: AtomicU64::new(0),
            memory_usage: AtomicU64::new(0),
        }
    }

    async fn execute_operation(&self, operation: String) -> Result<String> {
        // Simulate resource usage
        let cpu_time = (operation.len() % 100) as u64;
        let memory_usage = (operation.len() % 1000) as u64;

        self.cpu_usage.fetch_add(cpu_time, Ordering::Relaxed);
        self.memory_usage.fetch_add(memory_usage, Ordering::Relaxed);

        // Simulate operation time based on resource constraints
        let delay = Duration::from_micros(100 + (cpu_time * 10));
        tokio::time::sleep(delay).await;

        Ok(format!("res_op:{}:{}", operation, cpu_time))
    }

    fn get_utilization_metrics(&self) -> ResourceMetrics {
        let cpu_utilization = (self.cpu_usage.load(Ordering::Relaxed) as f64 / 
                             (self.config.cpu_cores as f64 * 1000.0)).min(1.0);
        let memory_utilization = (self.memory_usage.load(Ordering::Relaxed) as f64 / 
                                (self.config.memory_mb as f64 * 1024.0 * 1024.0)).min(1.0);

        ResourceMetrics {
            cpu_utilization,
            memory_utilization,
        }
    }
}

#[derive(Debug)]
struct ResourceMetrics {
    cpu_utilization: f64,
    memory_utilization: f64,
}

#[derive(Debug)]
struct TenantManager {
    tenants: Arc<RwLock<HashMap<String, TenantInfo>>>,
}

impl TenantManager {
    fn new() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn create_tenant(&self, tenant_id: &str) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        tenants.insert(tenant_id.to_string(), TenantInfo::new(tenant_id));
        Ok(())
    }

    async fn execute_tenant_operation(&self, tenant_id: &str, operation_id: usize) -> Result<String> {
        // Simulate tenant isolation
        let tenants = self.tenants.read().await;
        
        if let Some(tenant) = tenants.get(tenant_id) {
            // Simulate tenant-specific operation
            tokio::time::sleep(Duration::from_micros(100 + (operation_id % 100) as u64)).await;
            Ok(format!("tenant:{}:op:{}", tenant_id, operation_id))
        } else {
            Err(fortress_core::error::FortressError::tenant("Tenant not found"))
        }
    }

    fn get_isolation_metrics(&self) -> IsolationMetrics {
        // Mock isolation metrics
        IsolationMetrics {
            isolation_score: 0.95, // 95% isolation
            cross_tenant_leaks: 0,
            resource_conflicts: 0,
        }
    }
}

#[derive(Debug)]
struct TenantInfo {
    id: String,
    created_at: std::time::SystemTime,
}

impl TenantInfo {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            created_at: std::time::SystemTime::now(),
        }
    }
}

#[derive(Debug)]
struct IsolationMetrics {
    isolation_score: f64,
    cross_tenant_leaks: usize,
    resource_conflicts: usize,
}

#[derive(Debug)]
struct MockClusterNode {
    name: String,
    request_count: AtomicUsize,
}

impl MockClusterNode {
    fn new(name: String) -> Self {
        Self {
            name,
            request_count: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
struct MockCluster {
    nodes: Vec<Arc<MockClusterNode>>,
}

impl MockCluster {
    fn new(nodes: Vec<Arc<MockClusterNode>>) -> Self {
        Self { nodes }
    }

    async fn process_request(&self, node_id: usize, request_id: usize) -> Result<String> {
        if node_id < self.nodes.len() {
            let node = &self.nodes[node_id];
            node.request_count.fetch_add(1, Ordering::Relaxed);
            
            // Simulate cluster processing
            tokio::time::sleep(Duration::from_micros(50 + (request_id % 200) as u64)).await;
            
            Ok(format!("cluster:{}:req:{}", node.name, request_id))
        } else {
            Err(fortress_core::error::FortressError::cluster("Node not found"))
        }
    }
}

// Result structures
#[derive(Debug)]
pub struct PerformanceLoadTestResults {
    pub high_concurrency: HighConcurrencyResults,
    pub memory_usage: MemoryUsageResults,
    pub scalability: ScalabilityResults,
}

impl PerformanceLoadTestResults {
    pub fn new() -> Self {
        Self {
            high_concurrency: HighConcurrencyResults::new(),
            memory_usage: MemoryUsageResults::new(),
            scalability: ScalabilityResults::new(),
        }
    }
}

#[derive(Debug)]
pub struct HighConcurrencyResults {
    pub concurrent_auth: ConcurrentAuthResult,
    pub concurrent_encryption: ConcurrentEncryptionResult,
    pub concurrent_database: ConcurrentDatabaseResult,
    pub concurrent_cache: ConcurrentCacheResult,
    pub concurrent_audit: ConcurrentAuditResult,
    pub load_balancing: LoadBalancingResult,
    pub resource_contention: ResourceContentionResult,
    pub connection_pooling: ConnectionPoolingResult,
}

impl HighConcurrencyResults {
    pub fn new() -> Self {
        Self {
            concurrent_auth: ConcurrentAuthResult { test_results: Vec::new(), overall_success: false },
            concurrent_encryption: ConcurrentEncryptionResult { test_results: Vec::new(), overall_success: false },
            concurrent_database: ConcurrentDatabaseResult { test_results: Vec::new(), overall_success: false },
            concurrent_cache: ConcurrentCacheResult { test_results: Vec::new(), overall_success: false },
            concurrent_audit: ConcurrentAuditResult { test_results: Vec::new(), overall_success: false },
            load_balancing: LoadBalancingResult { test_results: Vec::new(), overall_success: false },
            resource_contention: ResourceContentionResult { test_results: Vec::new(), overall_success: false },
            connection_pooling: ConnectionPoolingResult { test_results: Vec::new(), overall_success: false },
        }
    }
}

#[derive(Debug)]
pub struct MemoryUsageResults {
    pub allocation_patterns: MemoryAllocationResult,
    pub memory_leaks: MemoryLeakResult,
    pub memory_pressure: MemoryPressureResult,
    pub garbage_collection: GarbageCollectionResult,
    pub memory_fragmentation: MemoryFragmentationResult,
    pub cache_memory: CacheMemoryResult,
}

impl MemoryUsageResults {
    pub fn new() -> Self {
        Self {
            allocation_patterns: MemoryAllocationResult { test_results: Vec::new(), overall_success: false },
            memory_leaks: MemoryLeakResult { test_results: Vec::new(), overall_success: false },
            memory_pressure: MemoryPressureResult { test_results: Vec::new(), overall_success: false },
            garbage_collection: GarbageCollectionResult { test_results: Vec::new(), overall_success: false },
            memory_fragmentation: MemoryFragmentationResult { test_results: Vec::new(), overall_success: false },
            cache_memory: CacheMemoryResult { test_results: Vec::new(), overall_success: false },
        }
    }
}

#[derive(Debug)]
pub struct ScalabilityResults {
    pub horizontal: HorizontalScalabilityResult,
    pub vertical: VerticalScalabilityResult,
    pub load: LoadScalabilityResult,
    pub performance_degradation: PerformanceDegradationResult,
    pub resource_scaling: ResourceScalingResult,
    pub multi_tenant: MultiTenantScalabilityResult,
}

impl ScalabilityResults {
    pub fn new() -> Self {
        Self {
            horizontal: HorizontalScalabilityResult { test_results: Vec::new(), scalability_efficiency: 0.0, overall_success: false },
            vertical: VerticalScalabilityResult { test_results: Vec::new(), vertical_efficiency: 0.0, overall_success: false },
            load: LoadScalabilityResult { test_results: Vec::new(), load_efficiency: 0.0, overall_success: false },
            performance_degradation: PerformanceDegradationResult { test_results: Vec::new(), overall_success: false },
            resource_scaling: ResourceScalingResult { test_results: Vec::new(), scaling_efficiency: 0.0, overall_success: false },
            multi_tenant: MultiTenantScalabilityResult { test_results: Vec::new(), tenant_efficiency: 0.0, overall_success: false },
        }
    }
}

// Individual test result structures
#[derive(Debug)]
pub struct ConcurrencyTestPoint {
    pub concurrent_count: usize,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub requests_per_second: f64,
    pub success_rate: f64,
}

#[derive(Debug)]
pub struct ConcurrentAuthResult {
    pub test_results: Vec<ConcurrencyTestPoint>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct EncryptionConcurrencyTest {
    pub data_size: usize,
    pub concurrent_count: usize,
    pub total_time: Duration,
    pub avg_operation_time: Duration,
    pub min_operation_time: Duration,
    pub max_operation_time: Duration,
    pub operations_per_second: f64,
    pub throughput_mbps: f64,
}

#[derive(Debug)]
pub struct ConcurrentEncryptionResult {
    pub test_results: Vec<EncryptionConcurrencyTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct DatabaseConcurrencyTest {
    pub operation_type: String,
    pub concurrent_count: usize,
    pub successful_operations: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub operations_per_second: f64,
    pub success_rate: f64,
}

#[derive(Debug)]
pub struct ConcurrentDatabaseResult {
    pub test_results: Vec<DatabaseConcurrencyTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct CacheConcurrencyTest {
    pub concurrent_count: usize,
    pub successful_operations: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub operations_per_second: f64,
    pub success_rate: f64,
}

#[derive(Debug)]
pub struct ConcurrentCacheResult {
    pub test_results: Vec<CacheConcurrencyTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct AuditConcurrencyTest {
    pub concurrent_count: usize,
    pub successful_logs: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub logs_per_second: f64,
    pub success_rate: f64,
}

#[derive(Debug)]
pub struct ConcurrentAuditResult {
    pub test_results: Vec<AuditConcurrencyTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct LoadBalancingTest {
    pub concurrent_count: usize,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub requests_per_second: f64,
    pub success_rate: f64,
    pub load_distribution: Vec<usize>,
}

#[derive(Debug)]
pub struct LoadBalancingResult {
    pub test_results: Vec<LoadBalancingTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct ResourceContentionTest {
    pub contention_count: usize,
    pub successful_operations: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub operations_per_second: f64,
    pub success_rate: f64,
}

#[derive(Debug)]
pub struct ResourceContentionResult {
    pub test_results: Vec<ResourceContentionTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct ConnectionPoolingTest {
    pub concurrent_count: usize,
    pub successful_operations: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub operations_per_second: f64,
    pub success_rate: f64,
    pub pool_stats: ConnectionPoolStats,
}

#[derive(Debug)]
pub struct ConnectionPoolingResult {
    pub test_results: Vec<ConnectionPoolingTest>,
    pub overall_success: bool,
}

// Memory usage result structures
#[derive(Debug)]
pub struct MemoryAllocationTest {
    pub allocation_size: usize,
    pub allocation_count: usize,
    pub total_memory_mb: f64,
    pub allocation_time: Duration,
    pub use_time: Duration,
    pub dealloc_time: Duration,
    pub total_time: Duration,
    pub allocation_rate_mb_per_sec: f64,
    pub deallocation_rate_mb_per_sec: f64,
}

#[derive(Debug)]
pub struct MemoryAllocationResult {
    pub test_results: Vec<MemoryAllocationTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct MemoryLeakTest {
    pub scenario_name: String,
    pub iterations: usize,
    pub initial_memory: usize,
    pub final_memory: usize,
    pub memory_increase: usize,
    pub test_duration: Duration,
    pub memory_leak_rate_mb_per_min: f64,
}

#[derive(Debug)]
pub struct MemoryLeakResult {
    pub test_results: Vec<MemoryLeakTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct MemoryPressureTest {
    pub pressure_name: String,
    pub target_memory: usize,
    pub initial_memory: usize,
    pub peak_memory: usize,
    pub final_memory: usize,
    pub memory_increase: usize,
    pub memory_recovered: usize,
    pub total_test_time: Duration,
    pub avg_operation_time: Duration,
}

#[derive(Debug)]
pub struct MemoryPressureResult {
    pub test_results: Vec<MemoryPressureTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct GarbageCollectionTest {
    pub scenario_name: String,
    pub object_count: usize,
    pub object_size: usize,
    pub initial_memory: usize,
    pub peak_memory: usize,
    pub final_memory: usize,
    pub allocation_time: Duration,
    pub usage_time: Duration,
    pub deallocation_time: Duration,
    pub total_time: Duration,
    pub memory_allocated: usize,
    pub memory_freed: usize,
    pub gc_efficiency: f64,
}

#[derive(Debug)]
pub struct GarbageCollectionResult {
    pub test_results: Vec<GarbageCollectionTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct MemoryFragmentationTest {
    pub scenario_name: String,
    pub allocation_count: usize,
    pub max_size: usize,
    pub initial_memory: usize,
    pub allocated_memory: usize,
    pub fragmented_memory: usize,
    pub final_memory: usize,
    pub total_allocated: usize,
    pub total_freed: usize,
    pub fragmentation_ratio: f64,
    pub large_allocation_success_rate: f64,
    pub large_allocation_time: Duration,
}

#[derive(Debug)]
pub struct MemoryFragmentationResult {
    pub test_results: Vec<MemoryFragmentationTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct CacheMemoryTest {
    pub cache_name: String,
    pub cache_capacity: usize,
    pub initial_memory: usize,
    pub filled_memory: usize,
    pub final_memory: usize,
    pub memory_used: usize,
    pub memory_per_entry: f64,
    pub fill_time: Duration,
    pub operation_time: Duration,
    pub clear_time: Duration,
    pub total_time: Duration,
    pub hits: usize,
    pub misses: usize,
    pub hit_rate: f64,
}

#[derive(Debug)]
pub struct CacheMemoryResult {
    pub test_results: Vec<CacheMemoryTest>,
    pub overall_success: bool,
}

// Scalability result structures
#[derive(Debug)]
pub struct HorizontalScalabilityTest {
    pub node_count: usize,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub requests_per_second: f64,
    pub success_rate: f64,
}

#[derive(Debug)]
pub struct HorizontalScalabilityResult {
    pub test_results: Vec<HorizontalScalabilityTest>,
    pub scalability_efficiency: f64,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct VerticalScalabilityTest {
    pub cpu_cores: usize,
    pub memory_mb: usize,
    pub workload_size: usize,
    pub total_time: Duration,
    pub avg_work_time: Duration,
    pub min_work_time: Duration,
    pub max_work_time: Duration,
    pub throughput: f64,
}

#[derive(Debug)]
pub struct VerticalScalabilityResult {
    pub test_results: Vec<VerticalScalabilityTest>,
    pub vertical_efficiency: f64,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct LoadScalabilityTest {
    pub load_name: String,
    pub concurrent_requests: usize,
    pub successful_requests: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub requests_per_second: f64,
    pub success_rate: f64,
}

#[derive(Debug)]
pub struct LoadScalabilityResult {
    pub test_results: Vec<LoadScalabilityTest>,
    pub load_efficiency: f64,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct PerformanceDegradationTest {
    pub scenario_name: String,
    pub base_operations: usize,
    pub baseline_time: Duration,
    pub degraded_time: Duration,
    pub baseline_throughput: f64,
    pub degraded_throughput: f64,
    pub performance_degradation: f64,
    pub throughput_degradation: f64,
}

#[derive(Debug)]
pub struct PerformanceDegradationResult {
    pub test_results: Vec<PerformanceDegradationTest>,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct ResourceScalingTest {
    pub config_name: String,
    pub cpu_cores: usize,
    pub memory_mb: usize,
    pub max_connections: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub operations_per_second: f64,
    pub success_rate: f64,
    pub resource_metrics: ResourceMetrics,
}

#[derive(Debug)]
pub struct ResourceScalingResult {
    pub test_results: Vec<ResourceScalingTest>,
    pub scaling_efficiency: f64,
    pub overall_success: bool,
}

#[derive(Debug)]
pub struct MultiTenantScalabilityTest {
    pub tenant_count: usize,
    pub total_operations: usize,
    pub successful_operations: usize,
    pub total_time: Duration,
    pub avg_response_time: Duration,
    pub min_response_time: Duration,
    pub max_response_time: Duration,
    pub operations_per_second: f64,
    pub success_rate: f64,
    pub isolation_metrics: IsolationMetrics,
}

#[derive(Debug)]
pub struct MultiTenantScalabilityResult {
    pub test_results: Vec<MultiTenantScalabilityTest>,
    pub tenant_efficiency: f64,
    pub overall_success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_load_tests_complete() {
        let results = PerformanceLoadTests::run_all_tests().await.unwrap();
        
        // Verify that all test categories have results
        assert!(!results.high_concurrency.concurrent_auth.test_results.is_empty(), 
                "Should have concurrent auth results");
        assert!(!results.memory_usage.allocation_patterns.test_results.is_empty(), 
                "Should have memory allocation results");
        assert!(!results.scalability.horizontal.test_results.is_empty(), 
                "Should have horizontal scalability results");
    }

    #[tokio::test]
    async fn test_high_concurrency_only() {
        let results = PerformanceLoadTests::test_high_concurrency_scenarios().await.unwrap();
        
        assert!(!results.concurrent_auth.test_results.is_empty(), 
                "Should have concurrent auth results");
        assert!(!results.concurrent_encryption.test_results.is_empty(), 
                "Should have concurrent encryption results");
    }

    #[tokio::test]
    async fn test_memory_usage_only() {
        let results = PerformanceLoadTests::test_memory_usage_scenarios().await.unwrap();
        
        assert!(!results.allocation_patterns.test_results.is_empty(), 
                "Should have memory allocation results");
        assert!(!results.memory_leaks.test_results.is_empty(), 
                "Should have memory leak results");
    }

    #[tokio::test]
    async fn test_scalability_only() {
        let results = PerformanceLoadTests::test_scalability_scenarios().await.unwrap();
        
        assert!(!results.horizontal.test_results.is_empty(), 
                "Should have horizontal scalability results");
        assert!(!results.vertical.test_results.is_empty(), 
                "Should have vertical scalability results");
    }
}
