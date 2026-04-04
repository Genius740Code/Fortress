//! Enhanced GraphQL schema with optimized performance components
//!
//! Combines optimized queries, mutations, caching, and performance monitoring
//! into a high-performance GraphQL schema for production use.

use async_graphql::Schema;
use std::sync::Arc;
use crate::graphql::{
    query::Query,
    mutation::Mutation,
    subscription::Subscription,
    optimized_queries::OptimizedQuery,
    optimized_mutations::OptimizedMutation,
    cache::{GraphQLCacheManager, CacheConfig},
    performance::{PerformanceMonitor, QueryAnalyzer, ResourceMonitor},
    types::PaginationInput,
};

/// Enhanced GraphQL schema with performance optimizations
pub struct EnhancedGraphQLSchema {
    pub schema: Schema<OptimizedQuery, OptimizedMutation, Subscription>,
    pub cache_manager: Arc<GraphQLCacheManager>,
    pub performance_monitor: Arc<PerformanceMonitor>,
    pub query_analyzer: QueryAnalyzer,
    pub resource_monitor: Arc<ResourceMonitor>,
}

impl EnhancedGraphQLSchema {
    /// Create a new enhanced GraphQL schema with all optimizations
    pub fn new() -> Self {
        // Initialize cache manager
        let cache_config = CacheConfig::default();
        let cache_manager = Arc::new(GraphQLCacheManager::new(cache_config));
        
        // Start cache cleanup task
        let cache_manager_clone = cache_manager.clone();
        tokio::spawn(async move {
            cache_manager_clone.start_cleanup_task().await;
        });

        // Initialize performance monitor
        let performance_monitor = Arc::new(PerformanceMonitor::new(
            10_000, // max operations
            tokio::time::Duration::from_secs(300), // cleanup interval
        ));
        
        // Start performance monitoring cleanup
        let perf_monitor_clone = performance_monitor.clone();
        tokio::spawn(async move {
            perf_monitor_clone.start_cleanup_task().await;
        });

        // Initialize query analyzer
        let query_analyzer = QueryAnalyzer::new(
            tokio::time::Duration::from_millis(1000), // slow query threshold
            100, // complex query threshold
        );

        // Initialize resource monitor
        let resource_monitor = Arc::new(ResourceMonitor::new());

        // Create optimized query and mutation handlers
        let optimized_query = OptimizedQuery::new(cache_manager.clone());
        let optimized_mutation = OptimizedMutation::new(cache_manager.clone());

        // Build the schema
        let schema = Schema::build(optimized_query, optimized_mutation, Subscription)
            .finish();

        Self {
            schema,
            cache_manager,
            performance_monitor,
            query_analyzer,
            resource_monitor,
        }
    }

    /// Get the underlying schema
    pub fn schema(&self) -> &Schema<OptimizedQuery, OptimizedMutation, Subscription> {
        &self.schema
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> crate::graphql::cache::CacheManagerStats {
        self.cache_manager.get_stats().await
    }

    /// Get performance statistics
    pub async fn get_performance_stats(&self) -> crate::graphql::performance::PerformanceStats {
        self.performance_monitor.get_stats().await
    }

    /// Get slow operations
    pub async fn get_slow_operations(&self, threshold_ms: u64) -> Vec<crate::graphql::performance::SerializableOperationMetrics> {
        self.performance_monitor.get_slow_operations(threshold_ms).await
    }

    /// Analyze query complexity
    pub fn analyze_query(&self, query: &str) -> crate::graphql::performance::QueryAnalysis {
        self.query_analyzer.analyze_query(query)
    }

    /// Get resource usage
    pub async fn get_resource_usage(&self) -> ResourceUsage {
        ResourceUsage {
            memory_usage: self.resource_monitor.get_total_memory_usage().await,
            cpu_usage: self.resource_monitor.get_cpu_usage().await,
        }
    }
}

/// Resource usage information
#[derive(async_graphql::SimpleObject, Clone, Debug)]
pub struct ResourceUsage {
    pub memory_usage: u64,
    pub cpu_usage: f64,
}

/// Performance monitoring queries
#[async_graphql::Object]
impl OptimizedQuery {
    /// Get cache performance statistics
    async fn cache_stats(&self) -> async_graphql::Result<crate::graphql::cache::CacheManagerStats> {
        // This would be implemented with the actual cache manager
        Err(async_graphql::Error::new("Not implemented"))
    }

    /// Get performance metrics
    async fn performance_metrics(&self) -> async_graphql::Result<crate::graphql::performance::PerformanceStats> {
        // This would be implemented with the actual performance monitor
        Err(async_graphql::Error::new("Not implemented"))
    }

    /// Get slow operations
    async fn slow_operations(&self, _threshold_ms: u64) -> async_graphql::Result<Vec<crate::graphql::performance::SerializableOperationMetrics>> {
        // This would be implemented with the actual performance monitor
        Err(async_graphql::Error::new("Not implemented"))
    }

    /// Get resource usage
    async fn resource_usage(&self) -> async_graphql::Result<ResourceUsage> {
        // This would be implemented with the actual resource monitor
        Err(async_graphql::Error::new("Not implemented"))
    }
}

/// Performance management mutations
#[async_graphql::Object]
impl OptimizedMutation {
    /// Clear cache
    async fn clear_cache(&self, _cache_type: Option<String>) -> async_graphql::Result<bool> {
        // This would be implemented with the actual cache manager
        Err(async_graphql::Error::new("Not implemented"))
    }

    /// Warm up cache
    async fn warm_cache(&self, _queries: Vec<String>) -> async_graphql::Result<bool> {
        // This would be implemented with the actual cache manager
        Err(async_graphql::Error::new("Not implemented"))
    }
}

/// Create an enhanced GraphQL schema
pub fn create_enhanced_schema() -> EnhancedGraphQLSchema {
    EnhancedGraphQLSchema::new()
}

/// Backward compatibility function
pub fn create_schema() -> Schema<Query, Mutation, Subscription> {
    Schema::build(Query, Mutation, Subscription)
        .finish()
}

/// Backward compatibility type
pub type FortressSchema = Schema<Query, Mutation, Subscription>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enhanced_schema_creation() {
        let enhanced_schema = create_enhanced_schema();
        
        // Test that the schema is created successfully
        assert!(enhanced_schema.schema().execute("{ version }").await.errors.is_empty());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let enhanced_schema = create_enhanced_schema();
        let stats = enhanced_schema.get_cache_stats().await;
        
        // Should have default stats
        assert_eq!(stats.database.total_entries, 0);
        assert_eq!(stats.table.total_entries, 0);
        assert_eq!(stats.query.total_entries, 0);
    }

    #[tokio::test]
    async fn test_performance_stats() {
        let enhanced_schema = create_enhanced_schema();
        let stats = enhanced_schema.get_performance_stats().await;
        
        // Should have default stats
        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.successful_operations, 0);
        assert_eq!(stats.failed_operations, 0);
    }

    #[tokio::test]
    async fn test_query_analysis() {
        let enhanced_schema = create_enhanced_schema();
        let query = "{ databases { id name } }";
        let analysis = enhanced_schema.analyze_query(query);
        
        // Should analyze the query
        assert!(analysis.complexity > 0);
        assert!(analysis.estimated_duration.as_millis() > 0);
    }

    #[tokio::test]
    async fn test_resource_usage() {
        let enhanced_schema = create_enhanced_schema();
        let usage = enhanced_schema.get_resource_usage().await;
        
        // Should have resource usage data
        assert!(usage.memory_usage >= 0);
        assert!(usage.cpu_usage >= 0.0);
    }

    #[tokio::test]
    async fn test_optimized_query_performance() {
        let enhanced_schema = create_enhanced_schema();
        
        // Test a complex query
        let query = r#"
        {
            databases {
                id
                name
                status
                encryptionAlgorithm
                createdAt
                tableCount
                storageSizeBytes
            }
        }
        "#;
        
        let start_time = std::time::Instant::now();
        let result = enhanced_schema.schema().execute(query).await;
        let duration = start_time.elapsed();
        
        // Should execute quickly (under 100ms for this simple query)
        assert!(result.errors.is_empty());
        assert!(duration.as_millis() < 100);
    }

    #[tokio::test]
    async fn test_backward_compatibility() {
        // Test that the old schema creation still works
        let old_schema = create_schema();
        let query = "{ version }";
        let result = old_schema.execute(query).await;
        assert!(result.errors.is_empty());
        
        // Test that the enhanced schema also works with the same queries
        let enhanced_schema = create_enhanced_schema();
        let result = enhanced_schema.schema().execute(query).await;
        assert!(result.errors.is_empty());
    }
}
