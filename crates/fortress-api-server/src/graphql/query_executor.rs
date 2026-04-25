//! Optimized Query Executor with caching and connection pooling
//! 
//! Provides high-performance query execution with intelligent caching,
//! connection pooling, and comprehensive performance monitoring.

use crate::graphql::{
    context::from_context,
    types::*,
};
use async_graphql::{Context, Result, Object};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::time::{Duration, Instant};
use futures::future::try_join_all;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMetrics {
    pub queries_executed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_execution_time: Duration,
    pub slow_queries: Vec<SlowQuery>,
    pub total_rows_processed: u64,
    pub total_bytes_processed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowQuery {
    pub query: String,
    pub execution_time: Duration,
    pub timestamp: DateTime<Utc>,
    pub rows_processed: u64,
    pub optimization_suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchQuery {
    pub query: String,
    pub parameters: Option<Vec<serde_json::Value>>,
    pub cache_ttl: Option<i32>,
    pub priority: QueryPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub rows: Vec<serde_json::Value>,
    pub affected_rows: u64,
    pub execution_time_ms: u64,
    pub cached: bool,
    pub query_hash: String,
    pub optimization_applied: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStatistics {
    pub queries_executed: u64,
    pub cache_hit_rate: f64,
    pub avg_execution_time_ms: f64,
    pub slow_queries: Vec<SlowQuery>,
    pub total_rows_processed: u64,
    pub optimization_effectiveness: f64,
}

pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Option<QueryResult>;
    async fn set(&self, key: &str, value: &QueryResult, ttl: Duration);
    async fn invalidate(&self, key: &str);
    async fn clear(&self);
    async fn stats(&self) -> CacheStats;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub memory_usage_bytes: u64,
}

pub trait QueryPlanner: Send + Sync {
    async fn optimize(&self, query: &str, parameters: &Option<Vec<serde_json::Value>>) -> Result<OptimizedPlan>;
    async fn explain(&self, query: &str) -> Result<QueryExplanation>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedPlan {
    pub optimized_query: String,
    pub execution_plan: String,
    pub estimated_cost: f64,
    pub optimization_applied: Vec<String>,
    pub indexes_used: Vec<String>,
    pub parallel_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExplanation {
    pub plan: Vec<PlanStep>,
    pub estimated_cost: f64,
    pub optimization_opportunities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_type: String,
    pub description: String,
    pub estimated_rows: u64,
    pub cost: f64,
    pub indexes: Vec<String>,
}

pub trait ConnectionPool: Send + Sync {
    async fn get_connection(&self) -> Result<Box<dyn DatabaseConnection>>;
    async fn return_connection(&self, conn: Box<dyn DatabaseConnection>);
    async fn stats(&self) -> PoolStats;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    pub total_connections: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
    pub waiting_requests: u32,
    pub avg_wait_time_ms: f64,
}

#[async_trait::async_trait]
pub trait DatabaseConnection: Send + Sync {
    async fn execute(&mut self, query: &str, params: &[serde_json::Value]) -> Result<QueryResult>;
    async fn execute_batch(&mut self, queries: &[BatchQuery]) -> Result<Vec<QueryResult>>;
    async fn prepare(&mut self, query: &str) -> Result<PreparedStatement>;
    fn connection_info(&self) -> ConnectionInfo;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub queries_executed: u64,
    pub total_execution_time: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedStatement {
    pub id: String,
    pub query: String,
    pub parameter_count: usize,
    pub prepared_at: DateTime<Utc>,
}

pub struct OptimizedQueryExecutor {
    cache: Arc<dyn Cache>,
    query_planner: Arc<dyn QueryPlanner>,
    connection_pool: Arc<dyn ConnectionPool>,
    metrics: Arc<RwLock<QueryMetrics>>,
    config: ExecutorConfig,
}

#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub cache_ttl_default: Duration,
    pub slow_query_threshold: Duration,
    pub max_concurrent_queries: usize,
    pub enable_query_optimization: bool,
    pub enable_parallel_execution: bool,
    pub cache_size_limit: u64,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            cache_ttl_default: Duration::from_secs(300), // 5 minutes
            slow_query_threshold: Duration::from_secs(1),
            max_concurrent_queries: 100,
            enable_query_optimization: true,
            enable_parallel_execution: true,
            cache_size_limit: 100_000_000, // 100MB
        }
    }
}

impl OptimizedQueryExecutor {
    pub fn new(
        cache: Arc<dyn Cache>,
        query_planner: Arc<dyn QueryPlanner>,
        connection_pool: Arc<dyn ConnectionPool>,
        config: ExecutorConfig,
    ) -> Self {
        Self {
            cache,
            query_planner,
            connection_pool,
            metrics: Arc::new(RwLock::new(QueryMetrics {
                queries_executed: 0,
                cache_hits: 0,
                cache_misses: 0,
                avg_execution_time: Duration::ZERO,
                slow_queries: Vec::new(),
                total_rows_processed: 0,
                total_bytes_processed: 0,
            })),
            config,
        }
    }

    fn generate_cache_key(&self, query: &str, parameters: &Option<Vec<serde_json::Value>>) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        query.hash(&mut hasher);

        if let Some(params) = parameters {
            for param in params {
                param.to_string().hash(&mut hasher);
            }
        }

        format!("query_{:x}", hasher.finish())
    }

    async fn update_cache_hit_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.cache_hits += 1;
    }

    async fn update_cache_miss_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.cache_misses += 1;
    }

    async fn update_execution_metrics(&self, execution_time: Duration, query: &str, rows_processed: u64, bytes_processed: u64) {
        let mut metrics = self.metrics.write().await;
        metrics.queries_executed += 1;
        metrics.total_rows_processed += rows_processed;
        metrics.total_bytes_processed += bytes_processed;

        // Update average execution time
        let total_time = metrics.avg_execution_time * (metrics.queries_executed - 1) as u32 + execution_time;
        metrics.avg_execution_time = total_time / metrics.queries_executed as u32;

        // Track slow queries
        if execution_time > self.config.slow_query_threshold {
            let slow_query = SlowQuery {
                query: query.to_string(),
                execution_time,
                timestamp: Utc::now(),
                rows_processed,
                optimization_suggestions: self.generate_optimization_suggestions(query),
            };

            metrics.slow_queries.push(slow_query);

            // Keep only last 100 slow queries
            if metrics.slow_queries.len() > 100 {
                metrics.slow_queries.remove(0);
            }
        }
    }

    fn generate_optimization_suggestions(&self, query: &str) -> Vec<String> {
        let mut suggestions = Vec::new();

        // Basic query analysis
        if query.to_lowercase().contains("select *") {
            suggestions.push("Consider specifying only the columns you need instead of using SELECT *".to_string());
        }

        if query.to_lowercase().contains("where") && !query.to_lowercase().contains("index") {
            suggestions.push("Ensure proper indexes exist for WHERE clause columns".to_string());
        }

        if query.to_lowercase().contains("order by") && !query.to_lowercase().contains("limit") {
            suggestions.push("Consider adding LIMIT to ORDER BY queries to reduce result set".to_string());
        }

        if query.to_lowercase().contains("join") && query.to_lowercase().matches("join").count() > 3 {
            suggestions.push("Consider breaking complex JOIN queries into multiple simpler queries".to_string());
        }

        suggestions
    }

    async fn validate_query_permissions(&self, user_context: &UserContext, query: &str) -> Result<()> {
        // Parse query to extract tables and operations
        let parsed_query = self.parse_query(query)?;

        // Check table-level permissions
        for table in &parsed_query.tables {
            if !user_context.has_table_permission(table, &parsed_query.operation) {
                return Err(async_graphql::Error::new(format!("Access denied to table: {}", table)));
            }
        }

        // Check for restricted operations
        if parsed_query.is_admin_operation && !user_context.has_permission("admin.query") {
            return Err(async_graphql::Error::new("Admin privileges required for this query"));
        }

        Ok(())
    }

    fn parse_query(&self, query: &str) -> Result<ParsedQuery> {
        // Simplified query parsing - in production, use a proper SQL parser
        let query_lower = query.to_lowercase();

        let operation = if query_lower.starts_with("select") {
            QueryOperation::Select
        } else if query_lower.starts_with("insert") {
            QueryOperation::Insert
        } else if query_lower.starts_with("update") {
            QueryOperation::Update
        } else if query_lower.starts_with("delete") {
            QueryOperation::Delete
        } else {
            QueryOperation::Other
        };

        let is_admin_operation = query_lower.contains("drop ") || 
                               query_lower.contains("truncate ") || 
                               query_lower.contains("alter ") ||
                               query_lower.contains("create ");

        // Extract table names (simplified)
        let mut tables = Vec::new();
        if operation == QueryOperation::Select {
            if let Some(from_part) = query_lower.split("from").nth(1) {
                if let Some(table_name) = from_part.split_whitespace().next() {
                    tables.push(table_name.to_string());
                }
            }
        }

        Ok(ParsedQuery {
            operation,
            tables,
            is_admin_operation,
        })
    }

    async fn execute_single_query(&self, query: &str, parameters: &Option<Vec<serde_json::Value>>) -> Result<QueryResult> {
        let start_time = Instant::now();
        
        // Get connection from pool
        let mut conn = self.connection_pool.get_connection().await?;
        
        // Execute query
        let result = conn.execute(query, &parameters.unwrap_or_default()).await?;
        
        // Return connection to pool
        self.connection_pool.return_connection(conn).await;
        
        let execution_time = start_time.elapsed();
        
        // Update metrics
        let rows_processed = result.rows.len() as u64;
        let bytes_processed = serde_json::to_vec(&result.rows).map(|v| v.len() as u64).unwrap_or(0);
        
        self.update_execution_metrics(execution_time, query, rows_processed, bytes_processed).await;
        
        Ok(QueryResult {
            execution_time_ms: execution_time.as_millis() as u64,
            rows_processed,
            ..result
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedQuery {
    operation: QueryOperation,
    tables: Vec<String>,
    is_admin_operation: bool,
}

#[derive(Debug, Clone)]
enum QueryOperation {
    Select,
    Insert,
    Update,
    Delete,
    Other,
}

#[Object]
impl OptimizedQueryExecutor {
    /// Execute optimized database query with caching
    async fn execute_query(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "SQL query to execute")] query: String,
        #[graphql(desc = "Query parameters")] parameters: Option<Vec<serde_json::Value>>,
        #[graphql(desc = "Cache TTL in seconds")] cache_ttl: Option<i32>
    ) -> Result<QueryResult> {
        let user_context = from_context::<UserContext>(ctx)?;
        
        // Validate query permissions
        self.validate_query_permissions(user_context, &query).await?;
        
        // Generate cache key
        let cache_key = self.generate_cache_key(&query, &parameters);
        
        // Check cache first
        if let Some(cached_result) = self.cache.get(&cache_key).await {
            self.update_cache_hit_metrics().await;
            return Ok(cached_result);
        }
        
        self.update_cache_miss_metrics().await;
        
        // Optimize query plan if enabled
        let optimized_query = if self.config.enable_query_optimization {
            let plan = self.query_planner.optimize(&query, &parameters).await?;
            plan.optimized_query
        } else {
            query.clone()
        };
        
        // Execute with connection pooling
        let result = self.execute_single_query(&optimized_query, &parameters).await?;
        
        // Cache result with TTL
        let ttl = Duration::from_secs(cache_ttl.unwrap_or(self.config.cache_ttl_default.as_secs() as u64));
        self.cache.set(&cache_key, &result, ttl).await;
        
        Ok(result)
    }

    /// Batch execute multiple queries efficiently
    async fn execute_batch_queries(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "List of queries to execute")] queries: Vec<BatchQuery>
    ) -> Result<Vec<QueryResult>> {
        let user_context = from_context::<UserContext>(ctx)?;
        
        // Validate all query permissions
        for batch_query in &queries {
            self.validate_query_permissions(user_context, &batch_query.query).await?;
        }
        
        // Group queries by priority for optimization
        let mut critical_queries = Vec::new();
        let mut high_queries = Vec::new();
        let mut normal_queries = Vec::new();
        let mut low_queries = Vec::new();
        
        for (index, batch_query) in queries.into_iter().enumerate() {
            match batch_query.priority {
                QueryPriority::Critical => critical_queries.push((index, batch_query)),
                QueryPriority::High => high_queries.push((index, batch_query)),
                QueryPriority::Normal => normal_queries.push((index, batch_query)),
                QueryPriority::Low => low_queries.push((index, batch_query)),
            }
        }
        
        // Execute queries in priority order
        let mut all_results = vec![QueryResult::default(); critical_queries.len() + high_queries.len() + normal_queries.len() + low_queries.len()];
        
        // Execute critical queries first (serially for consistency)
        for (index, batch_query) in critical_queries {
            let result = self.execute_single_query(&batch_query.query, &batch_query.parameters).await?;
            all_results[index] = result;
        }
        
        // Execute high priority queries in parallel
        if self.config.enable_parallel_execution && !high_queries.is_empty() {
            let high_futures: Vec<_> = high_queries.into_iter()
                .map(|(index, batch_query)| {
                    let executor = self.clone();
                    async move {
                        let result = executor.execute_single_query(&batch_query.query, &batch_query.parameters).await?;
                        Ok((index, result))
                    }
                })
                .collect();
            
            let high_results = try_join_all(high_futures).await?;
            for (index, result) in high_results {
                all_results[index] = result;
            }
        }
        
        // Execute normal and low priority queries
        let remaining_queries = normal_queries.into_iter().chain(low_queries);
        for (index, batch_query) in remaining_queries {
            let result = self.execute_single_query(&batch_query.query, &batch_query.parameters).await?;
            all_results[index] = result;
        }
        
        Ok(all_results)
    }

    /// Get query performance statistics
    async fn query_statistics(&self, ctx: &Context<'_>) -> Result<QueryStatistics> {
        let user_context = from_context::<UserContext>(ctx)?;
        
        if !user_context.has_permission("query.statistics") {
            return Err(async_graphql::Error::new("Insufficient permissions for query statistics"));
        }
        
        let metrics = self.metrics.read().await;
        let cache_stats = self.cache.stats().await;
        
        Ok(QueryStatistics {
            queries_executed: metrics.queries_executed,
            cache_hit_rate: if metrics.queries_executed > 0 {
                metrics.cache_hits as f64 / metrics.queries_executed as f64
            } else {
                0.0
            },
            avg_execution_time_ms: metrics.avg_execution_time.as_millis() as f64,
            slow_queries: metrics.slow_queries.clone(),
            total_rows_processed: metrics.total_rows_processed,
            optimization_effectiveness: self.calculate_optimization_effectiveness().await,
        })
    }

    /// Explain query execution plan
    async fn explain_query(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "SQL query to explain")] query: String
    ) -> Result<QueryExplanation> {
        let user_context = from_context::<UserContext>(ctx)?;
        
        if !user_context.has_permission("query.explain") {
            return Err(async_graphql::Error::new("Insufficient permissions for query explanation"));
        }
        
        self.query_planner.explain(&query).await
    }

    /// Clear query cache
    async fn clear_cache(&self, ctx: &Context<'_>) -> Result<bool> {
        let user_context = from_context::<UserContext>(ctx)?;
        
        if !user_context.has_permission("cache.clear") {
            return Err(async_graphql::Error::new("Insufficient permissions to clear cache"));
        }
        
        self.cache.clear().await;
        Ok(true)
    }

    /// Get cache statistics
    async fn cache_statistics(&self, ctx: &Context<'_>) -> Result<CacheStats> {
        let user_context = from_context::<UserContext>(ctx)?;
        
        if !user_context.has_permission("cache.stats") {
            return Err(async_graphql::Error::new("Insufficient permissions for cache statistics"));
        }
        
        self.cache.stats().await
    }

    /// Get connection pool statistics
    async fn pool_statistics(&self, ctx: &Context<'_>) -> Result<PoolStats> {
        let user_context = from_context::<UserContext>(ctx)?;
        
        if !user_context.has_permission("pool.stats") {
            return Err(async_graphql::Error::new("Insufficient permissions for pool statistics"));
        }
        
        self.connection_pool.stats().await
    }
}

impl OptimizedQueryExecutor {
    async fn calculate_optimization_effectiveness(&self) -> f64 {
        let metrics = self.metrics.read().await;
        
        if metrics.queries_executed == 0 {
            return 1.0;
        }
        
        // Calculate effectiveness based on cache hit rate and average execution time
        let cache_effectiveness = if metrics.queries_executed > 0 {
            metrics.cache_hits as f64 / metrics.queries_executed as f64
        } else {
            0.0
        };
        
        // Consider queries under 100ms as effectively optimized
        let performance_effectiveness = if metrics.avg_execution_time < Duration::from_millis(100) {
            1.0
        } else {
            100.0 / metrics.avg_execution_time.as_millis() as f64
        };
        
        (cache_effectiveness + performance_effectiveness) / 2.0
    }
}

impl Default for QueryResult {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            affected_rows: 0,
            execution_time_ms: 0,
            cached: false,
            query_hash: String::new(),
            optimization_applied: None,
        }
    }
}

impl Clone for OptimizedQueryExecutor {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
            query_planner: Arc::clone(&self.query_planner),
            connection_pool: Arc::clone(&self.connection_pool),
            metrics: Arc::clone(&self.metrics),
            config: self.config.clone(),
        }
    }
}
