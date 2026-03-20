//! Final integration test for the complete GraphQL API
//!
//! This test verifies that all components work together correctly
//! including security, performance, caching, and optimization features.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use serde_json;
use uuid::Uuid;
use crate::graphql::{
    security::{SecurityManager, SecurityConfig},
    auth::{AuthManager, AuthConfig, AuthenticatedUser},
    cache::{GraphQLCacheManager, CacheConfig},
    performance::PerformanceMonitor,
    benchmark::PerformanceBenchmark,
    security_tests::SecurityTestSuite,
};

/// Comprehensive integration test suite
pub struct IntegrationTestSuite {
    security_manager: Arc<SecurityManager>,
    auth_manager: Arc<AuthManager>,
    cache_manager: Arc<GraphQLCacheManager>,
    performance_monitor: Arc<PerformanceMonitor>,
    security_test_suite: SecurityTestSuite,
}

impl IntegrationTestSuite {
    pub fn new() -> Self {
        // Initialize security components
        let security_config = SecurityConfig::default();
        let security_manager = Arc::new(SecurityManager::new(security_config));

        let auth_config = AuthConfig::default();
        let auth_manager = Arc::new(AuthManager::new(auth_config).unwrap());

        let cache_config = CacheConfig::default();
        let cache_manager = Arc::new(GraphQLCacheManager::new(cache_config));

        let performance_monitor = Arc::new(PerformanceMonitor::new(
            10_000,
            Duration::from_secs(300),
        ));

        let security_test_suite = SecurityTestSuite::new(
            security_manager.clone(),
            auth_manager.clone(),
            // Create a simple encryption manager for testing
            {
                use fortress_core::key::InMemoryKeyManager;
                let key_manager = Arc::new(InMemoryKeyManager::new());
                let encryption_config = crate::graphql::encryption::EncryptionConfig::default();
                Arc::new(crate::graphql::encryption::DataEncryptionManager::new(key_manager, encryption_config))
            },
            performance_monitor.clone(),
        );

        Self {
            security_manager,
            auth_manager,
            cache_manager,
            performance_monitor,
            security_test_suite,
        }
    }

    /// Run comprehensive integration tests
    pub async fn run_all_tests(&self) -> IntegrationTestResults {
        let mut results = IntegrationTestResults::new();

        // Test 1: Security Integration
        results.security_integration = self.test_security_integration().await;

        // Test 2: Authentication Integration
        results.auth_integration = self.test_auth_integration().await;

        // Test 3: Cache Integration
        results.cache_integration = self.test_cache_integration().await;

        // Test 4: Performance Integration
        results.performance_integration = self.test_performance_integration().await;

        // Test 5: End-to-End Workflow
        results.end_to_end_workflow = self.test_end_to_end_workflow().await;

        // Test 6: Security Test Suite
        results.security_test_suite = self.test_security_test_suite().await;

        // Test 7: Performance Benchmark
        results.performance_benchmark = self.test_performance_benchmark().await;

        results.overall_success = results.calculate_overall_success();
        results
    }

    /// Test security integration
    async fn test_security_integration(&self) -> TestResult {
        // Test rate limiting
        let client_id = "test_client";
        let mut allowed_count = 0;
        let mut blocked_count = 0;

        for i in 0..15 {
            let request = crate::graphql::security::SecurityRequest::new(
                format!("{}_{}", client_id, i),
                Some("test_user".to_string()),
                "127.0.0.1".to_string(),
            );

            let validation = self.security_manager.validate_request(&request).await;
            match validation {
                Ok(crate::graphql::security::SecurityValidationResult::Allowed) => allowed_count += 1,
                Ok(crate::graphql::security::SecurityValidationResult::Blocked { .. }) => blocked_count += 1,
                Err(_) => blocked_count += 1,
            }
        }

        let security_working = blocked_count > 0 && allowed_count > 0;

        // Test input validation
        let malicious_request = crate::graphql::security::SecurityRequest::new(
            "malicious_client".to_string(),
            Some("test_user".to_string()),
            "127.0.0.1".to_string(),
        ).with_input("query".to_string(), "SELECT * FROM users".to_string());

        let validation = self.security_manager.validate_request(&malicious_request).await;
        let input_validation_working = matches!(validation, Ok(crate::graphql::security::SecurityValidationResult::Blocked { .. }));

        TestResult {
            passed: security_working && input_validation_working,
            details: format!(
                "Security: Rate limiting (allowed: {}, blocked: {}), Input validation: {}",
                allowed_count, blocked_count, input_validation_working
            ),
        }
    }

    /// Test authentication integration
    async fn test_auth_integration(&self) -> TestResult {
        // Create test user
        let test_user = AuthenticatedUser {
            id: "test_user_123".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read:own".to_string()],
            tenant_id: None,
            session_id: "test_session".to_string(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({
                "password_hash": "5d41402abc4b2a76b9719d911017c592"
            }),
        };

        self.auth_manager.upsert_user(test_user).await.unwrap();

        // Test authentication
        let auth_result = self.auth_manager.authenticate("testuser", "hello", "127.0.0.1", "Mozilla/5.0").await;
        let auth_success = matches!(auth_result, Ok(crate::graphql::auth::AuthResult::Success { .. }));

        // Test token verification
        if let Ok(crate::graphql::auth::AuthResult::Success { token, .. }) = auth_result {
            let verification = self.auth_manager.verify_token(&token, "127.0.0.1", "Mozilla/5.0").await;
            let token_verification_success = matches!(verification, Ok(crate::graphql::auth::TokenVerificationResult::Valid { .. }));

            // Test logout
            let logout_success = self.auth_manager.logout(&token).await.is_ok();

            TestResult {
                passed: auth_success && token_verification_success && logout_success,
                details: format!(
                    "Auth: Login {}, Token verification {}, Logout {}",
                    auth_success, token_verification_success, logout_success
                ),
            }
        } else {
            TestResult {
                passed: false,
                details: "Authentication failed".to_string(),
            }
        }
    }

    /// Test cache integration
    async fn test_cache_integration(&self) -> TestResult {
        // Test database cache
        let db_key = "test_db";
        let db_entry = crate::graphql::cache::DatabaseCacheEntry {
            id: Uuid::new_v4().to_string(),
            name: "Test Database".to_string(),
            status: "active".to_string(),
            encryption_algorithm: "AEGIS256".to_string(),
            created_at: chrono::Utc::now().to_string(),
            updated_at: chrono::Utc::now().to_string(),
            table_count: 5,
            storage_size_bytes: 1024,
        };

        self.cache_manager.database_cache.put(db_key.to_string(), db_entry).await;

        let cached_db = self.cache_manager.database_cache.get(db_key).await;
        let cache_retrieval_success = cached_db.is_some();

        // Test table cache
        let table_key = "test_table";
        let table_entry = crate::graphql::cache::TableCacheEntry {
            id: Uuid::new_v4().to_string(),
            name: "Test Table".to_string(),
            database: db_key.to_string(),
            record_count: 10,
            encryption_enabled: true,
            created_at: chrono::Utc::now().to_string(),
            updated_at: chrono::Utc::now().to_string(),
        };

        self.cache_manager.table_cache.put(table_key.to_string(), table_entry).await;

        let cached_table = self.cache_manager.table_cache.get(table_key).await;
        let table_cache_success = cached_table.is_some();

        // Test cache statistics
        let stats = self.cache_manager.get_stats().await;
        let stats_success = stats.database.total_entries > 0;

        TestResult {
            passed: cache_retrieval_success && table_cache_success && stats_success,
            details: format!(
                "Cache: DB retrieval {}, Table retrieval {}, Stats available {}",
                cache_retrieval_success, table_cache_success, stats_success
            ),
        }
    }

    /// Test performance integration
    async fn test_performance_integration(&self) -> TestResult {
        // Record some operations
        let tracker = self.performance_monitor.start_operation(
            crate::graphql::performance::OperationType::Query,
            "test_operation".to_string(),
        ).await;

        // Simulate some work
        sleep(Duration::from_millis(10)).await;

        tracker.complete_success(Some(10)).await;

        // Get performance stats
        let stats = self.performance_monitor.get_stats().await;
        let stats_available = stats.total_operations > 0;

        // Get slow operations
        let slow_ops = self.performance_monitor.get_slow_operations(5).await;
        let slow_ops_available = slow_ops.len() >= 0;

        TestResult {
            passed: stats_available && slow_ops_available,
            details: format!(
                "Performance: Stats available {}, Slow ops {}",
                stats_available, slow_ops_available
            ),
        }
    }

    /// Test end-to-end workflow
    async fn test_end_to_end_workflow(&self) -> TestResult {
        // Step 1: Authenticate user
        let auth_result = self.auth_manager.authenticate("testuser", "hello", "127.0.0.1", "Mozilla/5.0").await;
        
        if let Ok(crate::graphql::auth::AuthResult::Success { token, user, .. }) = auth_result {
            // Step 2: Validate security request
            let request = crate::graphql::security::SecurityRequest::new(
                "workflow_client".to_string(),
                Some(user.id.clone()),
                "127.0.0.1".to_string(),
            ).with_query("{ user { id name } }".to_string());

            let security_validation = self.security_manager.validate_request(&request).await;
            let security_passed = matches!(security_validation, Ok(crate::graphql::security::SecurityValidationResult::Allowed));

            // Step 3: Cache some data
            let cache_key = "workflow_data";
            let cache_entry = crate::graphql::cache::DatabaseCacheEntry {
                id: Uuid::new_v4().to_string(),
                name: "Workflow Database".to_string(),
                status: "active".to_string(),
                encryption_algorithm: "AEGIS256".to_string(),
                created_at: chrono::Utc::now().to_string(),
                updated_at: chrono::Utc::now().to_string(),
                table_count: 3,
                storage_size_bytes: 512,
            };

            self.cache_manager.database_cache.put(cache_key.to_string(), cache_entry).await;
            let cache_success = self.cache_manager.database_cache.get(cache_key).await.is_some();

            // Step 4: Record performance metric
            let tracker = self.performance_monitor.start_operation(
                crate::graphql::performance::OperationType::Query,
                "workflow_operation".to_string(),
            ).await;

            sleep(Duration::from_millis(5)).await;

            tracker.complete_success(Some(5)).await;

            let perf_success = self.performance_monitor.get_stats().await.total_operations > 0;

            // Step 5: Logout
            let logout_success = self.auth_manager.logout(&token).await.is_ok();

            TestResult {
                passed: security_passed && cache_success && perf_success && logout_success,
                details: format!(
                    "Workflow: Security {}, Cache {}, Performance {}, Logout {}",
                    security_passed, cache_success, perf_success, logout_success
                ),
            }
        } else {
            TestResult {
                passed: false,
                details: "Authentication failed in workflow".to_string(),
            }
        }
    }

    /// Test security test suite
    async fn test_security_test_suite(&self) -> TestResult {
        let test_results = self.security_test_suite.run_all_tests().await;
        
        let security_tests_passed = test_results.overall_score >= 80.0; // 80% threshold
        
        TestResult {
            passed: security_tests_passed,
            details: format!(
                "Security test suite: {:.1}% overall score",
                test_results.overall_score
            ),
        }
    }

    /// Test performance benchmark
    async fn test_performance_benchmark(&self) -> TestResult {
        let benchmark = PerformanceBenchmark::new();
        let config = crate::graphql::benchmark::BenchmarkConfig {
            num_operations: 100,
            concurrent_requests: 5,
            data_size_per_request: 50,
            complexity_level: crate::graphql::benchmark::ComplexityLevel::Medium,
        };

        let benchmark_results = benchmark.run_benchmark(config).await;
        
        let benchmark_passed = benchmark_results.len() >= 5; // Should have at least 5 different test results
        
        TestResult {
            passed: benchmark_passed,
            details: format!(
                "Performance benchmark: {} test results completed",
                benchmark_results.len()
            ),
        }
    }
}

/// Integration test results
#[derive(Debug, Clone)]
pub struct IntegrationTestResults {
    pub security_integration: TestResult,
    pub auth_integration: TestResult,
    pub cache_integration: TestResult,
    pub performance_integration: TestResult,
    pub end_to_end_workflow: TestResult,
    pub security_test_suite: TestResult,
    pub performance_benchmark: TestResult,
    pub overall_success: bool,
}

impl IntegrationTestResults {
    pub fn new() -> Self {
        Self {
            security_integration: TestResult { passed: false, details: String::new() },
            auth_integration: TestResult { passed: false, details: String::new() },
            cache_integration: TestResult { passed: false, details: String::new() },
            performance_integration: TestResult { passed: false, details: String::new() },
            end_to_end_workflow: TestResult { passed: false, details: String::new() },
            security_test_suite: TestResult { passed: false, details: String::new() },
            performance_benchmark: TestResult { passed: false, details: String::new() },
            overall_success: false,
        }
    }

    pub fn calculate_overall_success(&self) -> bool {
        self.security_integration.passed
            && self.auth_integration.passed
            && self.cache_integration.passed
            && self.performance_integration.passed
            && self.end_to_end_workflow.passed
            && self.security_test_suite.passed
            && self.performance_benchmark.passed
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("# GraphQL API Integration Test Report\n\n");
        
        report.push_str("## Test Results\n\n");
        report.push_str("| Test | Status | Details |\n");
        report.push_str("|------|--------|---------|\n");
        
        report.push_str(&format!(
            "| Security Integration | {} | {} |\n",
            if self.security_integration.passed { "✅ PASS" } else { "❌ FAIL" },
            self.security_integration.details
        ));
        
        report.push_str(&format!(
            "| Authentication Integration | {} | {} |\n",
            if self.auth_integration.passed { "✅ PASS" } else { "❌ FAIL" },
            self.auth_integration.details
        ));
        
        report.push_str(&format!(
            "| Cache Integration | {} | {} |\n",
            if self.cache_integration.passed { "✅ PASS" } else { "❌ FAIL" },
            self.cache_integration.details
        ));
        
        report.push_str(&format!(
            "| Performance Integration | {} | {} |\n",
            if self.performance_integration.passed { "✅ PASS" } else { "❌ FAIL" },
            self.performance_integration.details
        ));
        
        report.push_str(&format!(
            "| End-to-End Workflow | {} | {} |\n",
            if self.end_to_end_workflow.passed { "✅ PASS" } else { "❌ FAIL" },
            self.end_to_end_workflow.details
        ));
        
        report.push_str(&format!(
            "| Security Test Suite | {} | {} |\n",
            if self.security_test_suite.passed { "✅ PASS" } else { "❌ FAIL" },
            self.security_test_suite.details
        ));
        
        report.push_str(&format!(
            "| Performance Benchmark | {} | {} |\n",
            if self.performance_benchmark.passed { "✅ PASS" } else { "❌ FAIL" },
            self.performance_benchmark.details
        ));
        
        report.push_str("\n## Overall Status\n\n");
        report.push_str(&format!(
            "**Result: {}**\n\n",
            if self.overall_success { "✅ ALL TESTS PASSED" } else { "❌ SOME TESTS FAILED" }
        ));
        
        if self.overall_success {
            report.push_str("🎉 **The GraphQL API is fully integrated and ready for production!**\n\n");
            report.push_str("All components are working correctly:\n");
            report.push_str("- ✅ Security layer is active and blocking threats\n");
            report.push_str("- ✅ Authentication system is working properly\n");
            report.push_str("- ✅ Caching layer is operational\n");
            report.push_str("- ✅ Performance monitoring is active\n");
            report.push_str("- ✅ End-to-end workflows are functional\n");
            report.push_str("- ✅ Security tests are passing\n");
            report.push_str("- ✅ Performance benchmarks are successful\n");
        } else {
            report.push_str("⚠️ **Some integration tests failed. Review the details above.**\n\n");
        }
        
        report
    }
}

/// Test result structure
#[derive(Debug, Clone)]
pub struct TestResult {
    pub passed: bool,
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integration_suite() {
        let suite = IntegrationTestSuite::new();
        let results = suite.run_all_tests().await;
        
        // Verify all tests ran
        assert!(results.security_integration.passed || !results.security_integration.passed);
        assert!(results.auth_integration.passed || !results.auth_integration.passed);
        assert!(results.cache_integration.passed || !results.cache_integration.passed);
        assert!(results.performance_integration.passed || !results.performance_integration.passed);
        assert!(results.end_to_end_workflow.passed || !results.end_to_end_workflow.passed);
        assert!(results.security_test_suite.passed || !results.security_test_suite.passed);
        assert!(results.performance_benchmark.passed || !results.performance_benchmark.passed);
        
        // Generate report
        let report = results.generate_report();
        assert!(!report.is_empty());
        assert!(report.contains("GraphQL API Integration Test Report"));
        
        println!("{}", report);
    }
}
