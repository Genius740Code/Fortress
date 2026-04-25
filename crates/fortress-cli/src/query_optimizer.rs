use async_graphql::{Context, Result, Object, SimpleObject, Enum, InputObject};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::pin::Pin;
use std::future::Future;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use crate::graphql_subscriptions::UserContext;

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct QueryPlan {
    pub query_id: String,
    pub original_query: String,
    pub optimized_query: Option<String>,
    pub execution_plan: ExecutionPlan,
    pub estimated_cost: f64,
    pub estimated_rows: u64,
    pub optimization_suggestions: Vec<OptimizationSuggestion>,
    pub created_at: DateTime<Utc>,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct ExecutionPlan {
    pub steps: Vec<ExecutionStep>,
    pub parallelizable: bool,
    pub estimated_duration_ms: u64,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct ExecutionStep {
    pub step_type: StepType,
    pub description: String,
    pub estimated_cost: f64,
    pub estimated_rows: u64,
    pub dependencies: Vec<usize>,
}

#[derive(Enum, Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepType {
    TableScan,
    IndexScan,
    Filter,
    Sort,
    Aggregate,
    Join,
    Limit,
    Projection,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct OptimizationSuggestion {
    pub suggestion_type: SuggestionType,
    pub description: String,
    pub impact: ImpactLevel,
    pub estimated_improvement: f64,
}

#[derive(Enum, Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuggestionType {
    AddIndex,
    RewriteQuery,
    UseLimit,
    AvoidSelectStar,
    OptimizeJoin,
    CacheResult,
}

#[derive(Enum, Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QueryMetrics {
    pub query_id: String,
    pub execution_time_ms: u64,
    pub rows_returned: u64,
    pub cache_hit: bool,
    pub timestamp: DateTime<Utc>,
    pub error: Option<String>,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct SlowQuery {
    pub query: String,
    pub execution_time_secs: u64,
    pub timestamp: DateTime<Utc>,
    pub frequency: u32,
    pub optimization_applied: bool,
}

#[derive(InputObject, Serialize, Deserialize, Clone, Debug)]
pub struct BatchQuery {
    pub query: String,
    pub parameters: Option<Vec<serde_json::Value>>,
    pub cache_ttl: Option<i32>,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug, Default)]
pub struct QueryResult {
    pub rows: Vec<serde_json::Value>,
    pub affected_rows: u64,
    pub execution_time_ms: u64,
    pub cached: bool,
    pub query_id: String,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct QueryStatistics {
    pub queries_executed: u64,
    pub cache_hit_rate: f64,
    pub avg_execution_time_ms: f64,
    pub slow_queries: Vec<SlowQuery>,
    pub most_frequent_queries: Vec<QueryFrequency>,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct QueryFrequency {
    pub query_pattern: String,
    pub count: u32,
    pub avg_execution_time_ms: f64,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct ValidationError {
    pub message: String,
    pub severity: ValidationSeverity,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Enum, Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub size: usize,
    pub max_size: usize,
}

pub trait Cache: Send + Sync {
    fn get<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Option<QueryResult>> + Send + 'a>>;
    fn set<'a>(&'a self, key: &'a str, value: &'a QueryResult, ttl: std::time::Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    fn invalidate<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    fn clear<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    fn stats<'a>(&'a self) -> Pin<Box<dyn Future<Output = CacheStats> + Send + 'a>>;
}

pub trait ConnectionPool: Send + Sync {
    fn execute<'a>(&'a self, query: &'a str, params: &'a [serde_json::Value]) -> Pin<Box<dyn Future<Output = Result<QueryResult>> + Send + 'a>>;
    fn execute_batch<'a>(&'a self, queries: &'a [BatchQuery]) -> Pin<Box<dyn Future<Output = Result<Vec<QueryResult>>> + Send + 'a>>;
    fn get_connection_stats<'a>(&'a self) -> Pin<Box<dyn Future<Output = ConnectionStats> + Send + 'a>>;
}

#[derive(SimpleObject, Serialize, Deserialize, Clone, Debug)]
pub struct ConnectionStats {
    pub active_connections: u32,
    pub idle_connections: u32,
    pub total_connections: u32,
    pub max_connections: u32,
}

pub trait QueryPlanner: Send + Sync {
    fn optimize<'a>(&'a self, query: &'a str, params: &'a Option<Vec<serde_json::Value>>) -> Pin<Box<dyn Future<Output = Result<QueryPlan>> + Send + 'a>>;
    fn explain<'a>(&'a self, query: &'a str) -> Pin<Box<dyn Future<Output = Result<ExecutionPlan>> + Send + 'a>>;
    fn validate<'a>(&'a self, query: &'a str) -> Pin<Box<dyn Future<Output = Result<Vec<ValidationError>>> + Send + 'a>>;
}

pub struct OptimizedQueryExecutor {
    cache: Arc<dyn Cache>,
    query_planner: Arc<dyn QueryPlanner>,
    connection_pool: Arc<dyn ConnectionPool>,
    metrics: Arc<RwLock<QueryMetricsCollector>>,
}

#[derive(Debug, Default)]
pub struct QueryMetricsCollector {
    pub queries_executed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_execution_time: std::time::Duration,
    pub slow_queries: Vec<SlowQuery>,
    pub query_frequencies: HashMap<String, u32>,
}

impl QueryMetricsCollector {
    pub fn get_cache_hit_rate(&self) -> f64 {
        if self.cache_hits + self.cache_misses == 0 {
            0.0
        } else {
            self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64
        }
    }
}

impl OptimizedQueryExecutor {
    pub fn new(
        cache: Arc<dyn Cache>,
        query_planner: Arc<dyn QueryPlanner>,
        connection_pool: Arc<dyn ConnectionPool>,
    ) -> Self {
        Self {
            cache,
            query_planner,
            connection_pool,
            metrics: Arc::new(RwLock::new(QueryMetricsCollector::default())),
        }
    }
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
        let user_context = ctx.data::<UserContext>()
            .map_err(|_| async_graphql::Error::new("User context not available"))?;
        
        // Validate query permissions
        self.validate_query_permissions(user_context, &query).await?;
        
        // Generate cache key
        let cache_key = self.generate_cache_key(&query, &parameters).await;
        
        // Check cache first
        if let Some(cached_result) = self.cache.get(&cache_key).await {
            update_cache_hit_metrics(&self.metrics).await;
            return Ok(cached_result);
        }
        
        update_cache_miss_metrics(&self.metrics).await;
        
        // Execute query
        let start_time = std::time::Instant::now();
        let params = parameters.as_ref().map_or(&[][..], |p| p.as_slice());
        let result = self.connection_pool.execute(&query, params).await?;
        let execution_time = start_time.elapsed();
        
        // Update metrics
        update_execution_metrics(&self.metrics, execution_time, &query).await;
        
        // Cache result if TTL is specified
        if let Some(ttl) = cache_ttl {
            self.cache.set(&cache_key, &result, std::time::Duration::from_secs(ttl as u64)).await;
        }
        
        Ok(result)
    }
}

impl OptimizedQueryExecutor {
    // Helper methods (not GraphQL resolvers)
    async fn validate_query_permissions(&self, user_context: &UserContext, _query: &str) -> Result<()> {
        if user_context.has_permission("query.execute") {
            Ok(())
        } else {
            Err(async_graphql::Error::new("Insufficient permissions for query execution"))
        }
    }
    
    async fn generate_cache_key(&self, query: &str, parameters: &Option<Vec<serde_json::Value>>) -> String {
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
    
    async fn is_read_query(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        let query_lower = query_lower.trim();
        query_lower.starts_with("select") || 
        query_lower.starts_with("show") || 
        query_lower.starts_with("describe") || 
        query_lower.starts_with("explain")
    }
}

// Helper functions
async fn update_cache_hit_metrics(metrics: &Arc<RwLock<QueryMetricsCollector>>) {
    let mut metrics = metrics.write().await;
    metrics.cache_hits += 1;
}

async fn update_cache_miss_metrics(metrics: &Arc<RwLock<QueryMetricsCollector>>) {
    let mut metrics = metrics.write().await;
    metrics.cache_misses += 1;
}

async fn update_execution_metrics(metrics: &Arc<RwLock<QueryMetricsCollector>>, duration: std::time::Duration, query: &str) {
    let mut metrics = metrics.write().await;
    metrics.queries_executed += 1;
    metrics.avg_execution_time += duration;
    
    // Track slow queries
    if duration.as_millis() > 1000 {
        metrics.slow_queries.push(SlowQuery {
            query: query.to_string(),
            execution_time_secs: duration.as_secs(),
            timestamp: Utc::now(),
            frequency: 1,
            optimization_applied: false,
        });
    }
}

#[derive(Debug, Clone)]
struct ParsedQuery {
    operation: String,
    tables: Vec<String>,
    is_admin_operation: bool,
}

// User context extension for query permissions
impl UserContext {
    pub fn has_table_permission(&self, table: &str, operation: &str) -> bool {
        let permission = format!("table:{}:{}", operation.to_lowercase(), table);
        self.has_permission(&permission) ||
        self.has_permission(&format!("table:*:{}", table)) ||
        self.has_permission(&format!("table:{}:*", operation.to_lowercase())) ||
        self.has_permission("table:*:*") ||
        self.has_role("admin")
    }
}
