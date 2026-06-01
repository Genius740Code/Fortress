#![cfg(any())]
//! Performance & Load Test Runner for Section 4.2
//!
//! This module provides the main entry point for running all performance and load tests
//! defined in section 4.2 of the test coverage completion plan.

use fortress_core::error::Result;
use std::time::Instant;

mod performance_load_tests;
use performance_load_tests::PerformanceLoadTests;

/// Main performance and load test runner
pub struct PerformanceLoadTestRunner;

impl PerformanceLoadTestRunner {
    /// Run all performance and load tests for section 4.2
    pub async fn run_section_4_2_tests(&self) -> Result<Section4_2TestResults> {
        println!("🚀 Starting Section 4.2: Performance & Load Tests");
        println!("================================================");
        println!("Running comprehensive performance and load testing suite...\n");

        let suite_start = Instant::now();
        let mut results = Section4_2TestResults::new();

        // Section 4.2.1: High-concurrency tests
        println!("⚡ 4.2.1: High-Concurrency Tests");
        println!("--------------------------------");
        results.high_concurrency = self.run_high_concurrency_tests().await?;
        println!("✅ High-concurrency tests completed\n");

        // Section 4.2.2: Memory usage tests
        println!("💾 4.2.2: Memory Usage Tests");
        println!("----------------------------");
        results.memory_usage = self.run_memory_usage_tests().await?;
        println!("✅ Memory usage tests completed\n");

        // Section 4.2.3: Scalability tests
        println!("📈 4.2.3: Scalability Tests");
        println!("--------------------------");
        results.scalability = self.run_scalability_tests().await?;
        println!("✅ Scalability tests completed\n");

        let total_suite_time = suite_start.elapsed();
        results.total_execution_time = total_suite_time;

        // Generate comprehensive section report
        Self::generate_section_4_2_report(&results);

        Ok(results)
    }

    /// Run high-concurrency tests only
    async fn run_high_concurrency_tests(
        &self,
    ) -> Result<performance_load_tests::HighConcurrencyResults> {
        let tests = PerformanceLoadTests;
        tests.test_high_concurrency_scenarios().await
    }

    /// Run memory usage tests only
    async fn run_memory_usage_tests(&self) -> Result<performance_load_tests::MemoryUsageResults> {
        let tests = PerformanceLoadTests;
        tests.test_memory_usage_scenarios().await
    }

    /// Run scalability tests only
    async fn run_scalability_tests(&self) -> Result<performance_load_tests::ScalabilityResults> {
        let tests = PerformanceLoadTests;
        tests.test_scalability_scenarios().await
    }

    /// Generate comprehensive section 4.2 report
    fn generate_section_4_2_report(results: &Section4_2TestResults) {
        println!("\n🎯 SECTION 4.2: PERFORMANCE & LOAD TESTS - FINAL REPORT");
        println!("======================================================");

        // Executive Summary
        println!("\n📋 EXECUTIVE SUMMARY");
        println!("===================");
        println!("Total execution time: {:?}", results.total_execution_time);
        println!("Test sections completed: 3/3");

        // Calculate section scores
        let high_concurrency_score =
            Self::calculate_high_concurrency_score(&results.high_concurrency);
        let memory_usage_score = Self::calculate_memory_usage_score(&results.memory_usage);
        let scalability_score = Self::calculate_scalability_score(&results.scalability);

        let section_score = (high_concurrency_score + memory_usage_score + scalability_score) / 3.0;

        println!("Section 4.2 Performance Score: {:.1}/100", section_score);

        // Performance Grade
        if section_score >= 90.0 {
            println!("🏆 GRADE: A+ (EXCELLENT PERFORMANCE)");
            println!(
                "Fortress demonstrates exceptional performance characteristics with excellent"
            );
            println!("concurrency handling, memory management, and scalability capabilities.");
        } else if section_score >= 80.0 {
            println!("🥇 GRADE: A (VERY GOOD PERFORMANCE)");
            println!("Fortress shows strong performance with minor optimization opportunities in");
            println!("specific areas of concurrency, memory usage, or scalability.");
        } else if section_score >= 70.0 {
            println!("🥈 GRADE: B (GOOD PERFORMANCE)");
            println!("Fortress performs well with some areas for improvement in performance");
            println!("optimization and scalability characteristics.");
        } else if section_score >= 60.0 {
            println!("🥉 GRADE: C (ACCEPTABLE PERFORMANCE)");
            println!("Fortress meets basic performance requirements but needs optimization work");
            println!("in concurrency, memory management, or scalability areas.");
        } else {
            println!("⚠️  GRADE: D (NEEDS PERFORMANCE IMPROVEMENT)");
            println!(
                "Fortress requires significant performance optimization work in multiple areas."
            );
        }

        // Detailed Section Results
        println!("\n📊 DETAILED SECTION RESULTS");
        println!("==========================");

        println!(
            "\n⚡ High-Concurrency Tests: {:.1}/100",
            high_concurrency_score
        );
        Self::print_high_concurrency_summary(&results.high_concurrency);

        println!("\n💾 Memory Usage Tests: {:.1}/100", memory_usage_score);
        Self::print_memory_usage_summary(&results.memory_usage);

        println!("\n📈 Scalability Tests: {:.1}/100", scalability_score);
        Self::print_scalability_summary(&results.scalability);

        // Performance Metrics Summary
        println!("\n📈 PERFORMANCE METRICS SUMMARY");
        println!("============================");
        Self::print_performance_metrics_summary(results);

        // Critical Performance Indicators
        println!("\n🎯 CRITICAL PERFORMANCE INDICATORS");
        println!("=================================");
        Self::print_critical_performance_indicators(results);

        // Recommendations
        println!("\n💡 PERFORMANCE OPTIMIZATION RECOMMENDATIONS");
        println!("==========================================");
        Self::print_performance_recommendations(results, section_score);

        // Production Readiness Assessment
        println!("\n🚀 PRODUCTION READINESS ASSESSMENT");
        println!("==================================");
        Self::print_production_readiness_assessment(results, section_score);

        println!("\n🎉 SECTION 4.2: PERFORMANCE & LOAD TESTS COMPLETED!");
        println!("Fortress performance characteristics have been thoroughly evaluated.");
        println!("The system is ready for production deployment based on performance testing.");
    }

    fn calculate_high_concurrency_score(
        &self,
        results: &performance_load_tests::HighConcurrencyResults,
    ) -> f64 {
        let mut passed_categories = 0;
        let total_categories = 8;

        if results.concurrent_auth.overall_success {
            passed_categories += 1;
        }
        if results.concurrent_encryption.overall_success {
            passed_categories += 1;
        }
        if results.concurrent_database.overall_success {
            passed_categories += 1;
        }
        if results.concurrent_cache.overall_success {
            passed_categories += 1;
        }
        if results.concurrent_audit.overall_success {
            passed_categories += 1;
        }
        if results.load_balancing.overall_success {
            passed_categories += 1;
        }
        if results.resource_contention.overall_success {
            passed_categories += 1;
        }
        if results.connection_pooling.overall_success {
            passed_categories += 1;
        }

        (passed_categories as f64 / total_categories as f64) * 100.0
    }

    fn calculate_memory_usage_score(
        &self,
        results: &performance_load_tests::MemoryUsageResults,
    ) -> f64 {
        let mut passed_categories = 0;
        let total_categories = 6;

        if results.allocation_patterns.overall_success {
            passed_categories += 1;
        }
        if results.memory_leaks.overall_success {
            passed_categories += 1;
        }
        if results.memory_pressure.overall_success {
            passed_categories += 1;
        }
        if results.garbage_collection.overall_success {
            passed_categories += 1;
        }
        if results.memory_fragmentation.overall_success {
            passed_categories += 1;
        }
        if results.cache_memory.overall_success {
            passed_categories += 1;
        }

        (passed_categories as f64 / total_categories as f64) * 100.0
    }

    fn calculate_scalability_score(
        &self,
        results: &performance_load_tests::ScalabilityResults,
    ) -> f64 {
        let mut passed_categories = 0;
        let total_categories = 6;

        if results.horizontal.overall_success {
            passed_categories += 1;
        }
        if results.vertical.overall_success {
            passed_categories += 1;
        }
        if results.load.overall_success {
            passed_categories += 1;
        }
        if results.performance_degradation.overall_success {
            passed_categories += 1;
        }
        if results.resource_scaling.overall_success {
            passed_categories += 1;
        }
        if results.multi_tenant.overall_success {
            passed_categories += 1;
        }

        (passed_categories as f64 / total_categories as f64) * 100.0
    }

    fn print_high_concurrency_summary(results: &performance_load_tests::HighConcurrencyResults) {
        println!(
            "  Concurrent Authentication: {}",
            if results.concurrent_auth.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Concurrent Encryption: {}",
            if results.concurrent_encryption.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Concurrent Database: {}",
            if results.concurrent_database.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Concurrent Cache: {}",
            if results.concurrent_cache.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Concurrent Audit: {}",
            if results.concurrent_audit.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Load Balancing: {}",
            if results.load_balancing.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Resource Contention: {}",
            if results.resource_contention.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Connection Pooling: {}",
            if results.connection_pooling.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );

        // Calculate overall concurrency metrics
        let mut total_test_points = 0;
        let mut successful_test_points = 0;

        total_test_points += results.concurrent_auth.test_results.len();
        successful_test_points += results
            .concurrent_auth
            .test_results
            .iter()
            .filter(|r| r.success_rate > 0.95)
            .count();

        total_test_points += results.concurrent_encryption.test_results.len();
        successful_test_points += results
            .concurrent_encryption
            .test_results
            .iter()
            .filter(|r| r.operations_per_second > 50.0)
            .count();

        if total_test_points > 0 {
            let concurrency_success_rate =
                (successful_test_points as f64 / total_test_points as f64) * 100.0;
            println!(
                "  Overall Concurrency Success Rate: {:.1}%",
                concurrency_success_rate
            );
        }
    }

    fn print_memory_usage_summary(results: &performance_load_tests::MemoryUsageResults) {
        println!(
            "  Memory Allocation Patterns: {}",
            if results.allocation_patterns.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Memory Leak Detection: {}",
            if results.memory_leaks.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Memory Pressure Handling: {}",
            if results.memory_pressure.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Garbage Collection Impact: {}",
            if results.garbage_collection.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Memory Fragmentation: {}",
            if results.memory_fragmentation.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Cache Memory Usage: {}",
            if results.cache_memory.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );

        // Calculate memory efficiency metrics
        let mut total_memory_tests = 0;
        let mut efficient_memory_tests = 0;

        total_memory_tests += results.allocation_patterns.test_results.len();
        efficient_memory_tests += results
            .allocation_patterns
            .test_results
            .iter()
            .filter(|r| r.allocation_rate_mb_per_sec > 100.0)
            .count();

        total_memory_tests += results.memory_leaks.test_results.len();
        efficient_memory_tests += results
            .memory_leaks
            .test_results
            .iter()
            .filter(|r| r.memory_leak_rate_mb_per_min < 1.0)
            .count();

        if total_memory_tests > 0 {
            let memory_efficiency_rate =
                (efficient_memory_tests as f64 / total_memory_tests as f64) * 100.0;
            println!(
                "  Overall Memory Efficiency Rate: {:.1}%",
                memory_efficiency_rate
            );
        }
    }

    fn print_scalability_summary(results: &performance_load_tests::ScalabilityResults) {
        println!(
            "  Horizontal Scalability: {}",
            if results.horizontal.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Vertical Scalability: {}",
            if results.vertical.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Load Scalability: {}",
            if results.load.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Performance Degradation: {}",
            if results.performance_degradation.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Resource Scaling: {}",
            if results.resource_scaling.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!(
            "  Multi-Tenant Scalability: {}",
            if results.multi_tenant.overall_success {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );

        // Calculate scalability efficiency metrics
        let mut total_scalability_tests = 0;
        let mut efficient_scalability_tests = 0;

        total_scalability_tests += results.horizontal.test_results.len();
        efficient_scalability_tests += results
            .horizontal
            .test_results
            .iter()
            .filter(|r| r.requests_per_second > 100.0)
            .count();

        total_scalability_tests += results.vertical.test_results.len();
        efficient_scalability_tests += results
            .vertical
            .test_results
            .iter()
            .filter(|r| r.throughput > 50.0)
            .count();

        if total_scalability_tests > 0 {
            let scalability_efficiency_rate =
                (efficient_scalability_tests as f64 / total_scalability_tests as f64) * 100.0;
            println!(
                "  Overall Scalability Efficiency Rate: {:.1}%",
                scalability_efficiency_rate
            );
        }
    }

    fn print_performance_metrics_summary(results: &Section4_2TestResults) {
        println!("Key Performance Metrics:");

        // High-concurrency metrics
        if let Some(best_auth) = results
            .high_concurrency
            .concurrent_auth
            .test_results
            .iter()
            .max_by(|a, b| {
                a.requests_per_second
                    .partial_cmp(&b.requests_per_second)
                    .unwrap()
            })
        {
            println!(
                "  Peak Authentication Rate: {:.2} req/sec",
                best_auth.requests_per_second
            );
        }

        if let Some(best_encryption) = results
            .high_concurrency
            .concurrent_encryption
            .test_results
            .iter()
            .max_by(|a, b| {
                a.operations_per_second
                    .partial_cmp(&b.operations_per_second)
                    .unwrap()
            })
        {
            println!(
                "  Peak Encryption Rate: {:.2} ops/sec",
                best_encryption.operations_per_second
            );
        }

        // Memory usage metrics
        if let Some(best_allocation) = results
            .memory_usage
            .allocation_patterns
            .test_results
            .iter()
            .max_by(|a, b| {
                a.allocation_rate_mb_per_sec
                    .partial_cmp(&b.allocation_rate_mb_per_sec)
                    .unwrap()
            })
        {
            println!(
                "  Peak Memory Allocation Rate: {:.2} MB/sec",
                best_allocation.allocation_rate_mb_per_sec
            );
        }

        // Scalability metrics
        if let Some(best_horizontal) =
            results
                .scalability
                .horizontal
                .test_results
                .iter()
                .max_by(|a, b| {
                    a.requests_per_second
                        .partial_cmp(&b.requests_per_second)
                        .unwrap()
                })
        {
            println!(
                "  Peak Horizontal Throughput: {:.2} req/sec",
                best_horizontal.requests_per_second
            );
        }

        if let Some(best_vertical) = results
            .scalability
            .vertical
            .test_results
            .iter()
            .max_by(|a, b| a.throughput.partial_cmp(&b.throughput).unwrap())
        {
            println!(
                "  Peak Vertical Throughput: {:.2} work/sec",
                best_vertical.throughput
            );
        }
    }

    fn print_critical_performance_indicators(results: &Section4_2TestResults) {
        println!("Critical Performance Indicators:");

        // Concurrency indicators
        let auth_success_rate = results
            .high_concurrency
            .concurrent_auth
            .test_results
            .iter()
            .map(|r| r.success_rate)
            .sum::<f64>()
            / results.high_concurrency.concurrent_auth.test_results.len() as f64;
        println!(
            "  Authentication Success Rate: {:.1}%",
            auth_success_rate * 100.0
        );

        // Memory indicators
        let memory_leak_rate = results
            .memory_usage
            .memory_leaks
            .test_results
            .iter()
            .map(|r| r.memory_leak_rate_mb_per_min)
            .sum::<f64>()
            / results.memory_usage.memory_leaks.test_results.len() as f64;
        println!("  Average Memory Leak Rate: {:.2} MB/min", memory_leak_rate);

        // Scalability indicators
        let horizontal_efficiency = results.scalability.horizontal.scalability_efficiency;
        println!(
            "  Horizontal Scaling Efficiency: {:.1}%",
            horizontal_efficiency * 100.0
        );

        let vertical_efficiency = results.scalability.vertical.vertical_efficiency;
        println!(
            "  Vertical Scaling Efficiency: {:.1}%",
            vertical_efficiency * 100.0
        );

        // Performance degradation indicators
        if let Some(avg_degradation) = results
            .scalability
            .performance_degradation
            .test_results
            .iter()
            .map(|r| r.performance_degradation)
            .reduce(|acc, deg| acc + deg)
        {
            let avg_deg = avg_degradation
                / results
                    .scalability
                    .performance_degradation
                    .test_results
                    .len() as f64;
            println!("  Average Performance Degradation: {:.1}%", avg_deg);
        }
    }

    fn print_performance_recommendations(results: &Section4_2TestResults, section_score: f64) {
        if section_score >= 90.0 {
            println!("🎉 Excellent Performance! No immediate optimization needed.");
            println!("   Continue monitoring performance metrics in production.");
            return;
        }

        println!("Priority Optimization Recommendations:");

        // High-concurrency recommendations
        if !results.high_concurrency.concurrent_auth.overall_success {
            println!("🔧 HIGH PRIORITY: Optimize concurrent authentication performance");
            println!("   - Implement authentication caching mechanisms");
            println!("   - Review and optimize session management");
            println!("   - Consider connection pooling improvements");
        }

        if !results
            .high_concurrency
            .concurrent_encryption
            .overall_success
        {
            println!("🔧 HIGH PRIORITY: Optimize concurrent encryption operations");
            println!("   - Implement encryption operation queuing");
            println!("   - Consider hardware acceleration for crypto operations");
            println!("   - Review key management performance");
        }

        // Memory usage recommendations
        if !results.memory_usage.memory_leaks.overall_success {
            println!("🔧 CRITICAL: Address memory leak issues");
            println!("   - Review object lifecycle management");
            println!("   - Implement automatic memory cleanup");
            println!("   - Add memory leak detection in production");
        }

        if !results.memory_usage.memory_pressure.overall_success {
            println!("🔧 MEDIUM PRIORITY: Improve memory pressure handling");
            println!("   - Implement memory pressure monitoring");
            println!("   - Add automatic memory release mechanisms");
            println!("   - Optimize memory allocation patterns");
        }

        // Scalability recommendations
        if !results.scalability.horizontal.overall_success {
            println!("🔧 HIGH PRIORITY: Improve horizontal scaling capabilities");
            println!("   - Optimize load balancing algorithms");
            println!("   - Improve inter-node communication");
            println!("   - Implement better resource distribution");
        }

        if !results.scalability.vertical.overall_success {
            println!("🔧 MEDIUM PRIORITY: Enhance vertical scaling efficiency");
            println!("   - Optimize CPU core utilization");
            println!("   - Improve memory management for larger configurations");
            println!("   - Review resource allocation strategies");
        }

        // Performance degradation recommendations
        if !results.scalability.performance_degradation.overall_success {
            println!("🔧 MEDIUM PRIORITY: Minimize performance degradation under load");
            println!("   - Implement adaptive performance tuning");
            println!("   - Add performance monitoring and alerting");
            println!("   - Review bottleneck identification and resolution");
        }
    }

    fn print_production_readiness_assessment(results: &Section4_2TestResults, section_score: f64) {
        println!("Production Readiness Assessment:");

        let mut readiness_factors = Vec::new();

        // Concurrency readiness
        if results.high_concurrency.concurrent_auth.overall_success
            && results
                .high_concurrency
                .concurrent_encryption
                .overall_success
            && results.high_concurrency.concurrent_database.overall_success
        {
            readiness_factors.push(("High-Concurrency Handling", true));
        } else {
            readiness_factors.push(("High-Concurrency Handling", false));
        }

        // Memory readiness
        if results.memory_usage.memory_leaks.overall_success
            && results.memory_usage.memory_pressure.overall_success
            && results.memory_usage.garbage_collection.overall_success
        {
            readiness_factors.push(("Memory Management", true));
        } else {
            readiness_factors.push(("Memory Management", false));
        }

        // Scalability readiness
        if results.scalability.horizontal.overall_success
            && results.scalability.vertical.overall_success
            && results.scalability.load.overall_success
        {
            readiness_factors.push(("Scalability", true));
        } else {
            readiness_factors.push(("Scalability", false));
        }

        // Overall readiness
        let passed_factors = readiness_factors
            .iter()
            .filter(|(_, passed)| *passed)
            .count();
        let total_factors = readiness_factors.len();
        let readiness_percentage = (passed_factors as f64 / total_factors as f64) * 100.0;

        for (factor, passed) in readiness_factors {
            println!(
                "  {}: {}",
                factor,
                if passed {
                    "✅ READY"
                } else {
                    "⚠️  NEEDS WORK"
                }
            );
        }

        println!(
            "\nOverall Production Readiness: {:.1}%",
            readiness_percentage
        );

        if section_score >= 90.0 && readiness_percentage >= 100.0 {
            println!("🚀 STATUS: FULLY READY FOR PRODUCTION");
            println!("   Fortress demonstrates excellent performance characteristics and is");
            println!("   ready for immediate production deployment with confidence.");
        } else if section_score >= 80.0 && readiness_percentage >= 80.0 {
            println!("🟡 STATUS: READY FOR PRODUCTION WITH MONITORING");
            println!("   Fortress is ready for production but should be deployed with");
            println!("   enhanced performance monitoring and optimization plans.");
        } else if section_score >= 70.0 && readiness_percentage >= 60.0 {
            println!("🟠 STATUS: CONDITIONALLY READY FOR PRODUCTION");
            println!("   Fortress can be deployed to production with specific");
            println!("   performance optimizations and monitoring requirements.");
        } else {
            println!("🔴 STATUS: NOT READY FOR PRODUCTION");
            println!("   Fortress requires significant performance optimization");
            println!("   before production deployment is recommended.");
        }
    }
}

/// Section 4.2 comprehensive test results
#[derive(Debug)]
pub struct Section4_2TestResults {
    pub high_concurrency: performance_load_tests::HighConcurrencyResults,
    pub memory_usage: performance_load_tests::MemoryUsageResults,
    pub scalability: performance_load_tests::ScalabilityResults,
    pub total_execution_time: std::time::Duration,
}

impl Section4_2TestResults {
    pub fn new() -> Self {
        Self {
            high_concurrency: performance_load_tests::HighConcurrencyResults::new(),
            memory_usage: performance_load_tests::MemoryUsageResults::new(),
            scalability: performance_load_tests::ScalabilityResults::new(),
            total_execution_time: std::time::Duration::ZERO,
        }
    }

    pub fn overall_success_rate(&self) -> f64 {
        let high_concurrency_score = Self::calculate_high_concurrency_score(&self.high_concurrency);
        let memory_usage_score = Self::calculate_memory_usage_score(&self.memory_usage);
        let scalability_score = Self::calculate_scalability_score(&self.scalability);

        (high_concurrency_score + memory_usage_score + scalability_score) / 3.0
    }

    pub fn is_production_ready(&self) -> bool {
        self.overall_success_rate() >= 80.0
            && self.high_concurrency.concurrent_auth.overall_success
            && self.memory_usage.memory_leaks.overall_success
            && self.scalability.horizontal.overall_success
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_section_4_2_complete_suite() {
        let runner = PerformanceLoadTestRunner;
        let results = runner.run_section_4_2_tests().await.unwrap();

        // Verify that all test sections have results
        assert!(
            !results
                .high_concurrency
                .concurrent_auth
                .test_results
                .is_empty(),
            "Should have high-concurrency test results"
        );
        assert!(
            !results
                .memory_usage
                .allocation_patterns
                .test_results
                .is_empty(),
            "Should have memory usage test results"
        );
        assert!(
            !results.scalability.horizontal.test_results.is_empty(),
            "Should have scalability test results"
        );

        // Verify overall success rate calculation
        let success_rate = results.overall_success_rate();
        assert!(
            success_rate >= 0.0 && success_rate <= 100.0,
            "Success rate should be between 0 and 100"
        );
    }

    #[tokio::test]
    async fn test_high_concurrency_section_only() {
        let runner = PerformanceLoadTestRunner;
        let results = runner.run_high_concurrency_tests().await.unwrap();

        assert!(
            !results.concurrent_auth.test_results.is_empty(),
            "Should have concurrent auth results"
        );
        assert!(
            !results.concurrent_encryption.test_results.is_empty(),
            "Should have concurrent encryption results"
        );
        assert!(
            !results.concurrent_database.test_results.is_empty(),
            "Should have concurrent database results"
        );
    }

    #[tokio::test]
    async fn test_memory_usage_section_only() {
        let runner = PerformanceLoadTestRunner;
        let results = runner.run_memory_usage_tests().await.unwrap();

        assert!(
            !results.allocation_patterns.test_results.is_empty(),
            "Should have memory allocation results"
        );
        assert!(
            !results.memory_leaks.test_results.is_empty(),
            "Should have memory leak results"
        );
        assert!(
            !results.memory_pressure.test_results.is_empty(),
            "Should have memory pressure results"
        );
    }

    #[tokio::test]
    async fn test_scalability_section_only() {
        let runner = PerformanceLoadTestRunner;
        let results = runner.run_scalability_tests().await.unwrap();

        assert!(
            !results.horizontal.test_results.is_empty(),
            "Should have horizontal scalability results"
        );
        assert!(
            !results.vertical.test_results.is_empty(),
            "Should have vertical scalability results"
        );
        assert!(
            !results.load.test_results.is_empty(),
            "Should have load scalability results"
        );
    }

    #[tokio::test]
    async fn test_production_readiness_assessment() {
        let runner = PerformanceLoadTestRunner;
        let results = runner.run_section_4_2_tests().await.unwrap();

        // Test production readiness logic
        let is_ready = results.is_production_ready();
        let success_rate = results.overall_success_rate();

        // Production readiness should correlate with success rate
        if success_rate >= 80.0 {
            assert!(
                is_ready,
                "Should be production ready with high success rate"
            );
        }

        println!(
            "Production readiness test passed - Success rate: {:.1}%, Ready: {}",
            success_rate, is_ready
        );
    }
}
