//! Optimized Query Executor with caching and connection pooling
//! 
//! Provides high-performance query execution with intelligent caching,
//! connection pooling, and comprehensive performance monitoring.

use crate::graphql::{
    context::{from_context, GraphQLContext},
};
use async_graphql::{Context, Result, Object};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::time::{Duration, Instant};
use futures::future::try_join_all;

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

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::InputObject)]
pub struct BatchQuery {
    pub query: String,
    pub parameters: Option<Vec<serde_json::Value>>,
    pub cache_ttl: Option<i32>,
    pub priority: QueryPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::Enum, Copy, Eq, PartialEq)]
pub enum QueryPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject)]
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

#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Option<QueryResult>;
    async fn set(&self, key: &str, value: &QueryResult, ttl: Duration);
    async fn invalidate(&self, key: &str);
    async fn clear(&self);
    async fn stats(&self) -> CacheStats;
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject, Default)]
pub struct CacheStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub memory_usage_bytes: u64,
}

#[async_trait]
pub trait QueryPlanner: Send + Sync {
    async fn optimize(&self, query: &str, parameters: &Option<Vec<serde_json::Value>>) -> Result<OptimizedPlan>;
    async fn explain(&self, query: &str) -> Result<QueryExplanation>;
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject)]
pub struct OptimizedPlan {
    pub optimized_query: String,
    pub execution_plan: String,
    pub estimated_cost: f64,
    pub optimization_applied: Vec<String>,
    pub indexes_used: Vec<String>,
    pub parallel_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject)]
pub struct QueryExplanation {
    pub plan: Vec<PlanStep>,
    pub estimated_cost: f64,
    pub optimization_opportunities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject)]
pub struct PlanStep {
    pub step_type: String,
    pub description: String,
    pub estimated_rows: u64,
    pub cost: f64,
    pub indexes: Vec<String>,
}

#[async_trait]
pub trait ConnectionPool: Send + Sync {
    async fn get_connection(&self) -> Result<Box<dyn DatabaseConnection>>;
    async fn return_connection(&self, conn: Box<dyn DatabaseConnection>);
    async fn stats(&self) -> PoolStats;
}

#[derive(Debug, Clone, Serialize, Deserialize, async_graphql::SimpleObject, Default)]
pub struct PoolStats {
    pub total_connections: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
    pub waiting_requests: u32,
    pub avg_wait_time_ms: f64,
}

#[async_trait]
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

    async fn validate_query_permissions(&self, user_context: &GraphQLContext, query: &str) -> Result<()> {
        // Parse query to extract tables and operations
        let parsed_query = self.parse_query(query)?;

        // Check table-level permissions
        for table in &parsed_query.tables {
            if !user_context.has_table_permission(table, &format!("{:?}", parsed_query.operation)) {
                return Err(async_graphql::Error::new(format!("Access denied to table: {}", table)));
            }
        }

        // Check for restricted operations
        if parsed_query.is_admin_operation && !user_context.has_permission("admin.query") {
            return Err(async_graphql::Error::new("Admin privileges required for this query"));
        }

        Ok(())
    }

    pub fn parse_query(&self, query: &str) -> Result<ParsedQuery> {
        // Production-ready SQL parser with comprehensive security validation
        let normalized_query = self.normalize_sql(query)?;
        
        // Validate against SQL injection patterns
        self.validate_sql_safety(&normalized_query)?;
        
        // Parse SQL tokens for accurate analysis
        let tokens = self.tokenize_sql(&normalized_query)?;
        
        // Extract operation type from first token
        let operation = self.extract_operation_type(&tokens)?;
        
        // Identify admin operations with comprehensive pattern matching
        let is_admin_operation = self.detect_admin_operations(&tokens)?;
        
        // Extract table names with proper SQL parsing
        let tables = self.extract_table_names(&tokens, &operation)?;
        
        Ok(ParsedQuery {
            operation,
            tables,
            is_admin_operation,
        })
    }
    
    fn normalize_sql(&self, query: &str) -> Result<String> {
        // Remove comments and normalize whitespace for secure parsing
        let normalized = query
            // Remove SQL comments (both -- and /* */ styles)
            .split("/*")
            .map(|part| part.split("*/").last().unwrap_or(part))
            .collect::<Vec<_>>()
            .join(" ")
            // Remove line comments
            .lines()
            .map(|line| line.split("--").next().unwrap_or(line))
            .collect::<Vec<_>>()
            .join(" ")
            // Normalize whitespace and trim
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
            
        if normalized.is_empty() {
            return Err(async_graphql::Error::new("Empty or invalid SQL query"));
        }
        
        Ok(normalized)
    }
    
    fn validate_sql_safety(&self, query: &str) -> Result<()> {
        // Comprehensive SQL injection detection patterns
        let dangerous_patterns = [
            // SQL injection patterns
            ("'", "Unclosed quotes detected"),
            (";", "Multiple statements detected"),
            ("--", "SQL comment detected"),
            ("/*", "Multi-line comment detected"),
            ("xp_", "Extended stored procedure detected"),
            ("sp_", "System stored procedure detected"),
            // Dangerous functions
            ("exec(", "Dynamic execution detected"),
            ("execute(", "Dynamic execution detected"),
            ("eval(", "Code evaluation detected"),
            ("system(", "System command execution detected"),
            ("shell(", "Shell command execution detected"),
            // File operations
            ("load_file(", "File operation detected"),
            ("into outfile", "File write operation detected"),
            ("dumpfile", "File dump operation detected"),
            // Information schema attacks
            ("information_schema", "System schema access detected"),
            ("mysql.user", "System table access detected"),
            ("pg_catalog", "System catalog access detected"),
            ("sys.tables", "System table access detected"),
            // Time-based attacks
            ("waitfor delay", "Timing attack detected"),
            ("sleep(", "Timing attack detected"),
            ("benchmark(", "Timing attack detected"),
            ("pg_sleep(", "Timing attack detected"),
        ];
        
        let query_lower = query.to_lowercase();
        
        for (pattern, description) in &dangerous_patterns {
            if query_lower.contains(pattern) {
                return Err(async_graphql::Error::new(format!(
                    "Security violation: {} (pattern: {})", 
                    description, 
                    pattern
                )));
            }
        }
        
        // Check for suspicious keyword combinations
        let suspicious_combinations = [
            ("union", "select"),
            ("or", "1=1"),
            ("and", "1=1"),
            ("'", "or"),
            ("'", "and"),
            ("'", "union"),
        ];
        
        for (first, second) in &suspicious_combinations {
            if query_lower.contains(first) && query_lower.contains(second) {
                return Err(async_graphql::Error::new(format!(
                    "Suspicious SQL pattern detected: {} + {}", 
                    first, 
                    second
                )));
            }
        }
        
        Ok(())
    }
    
    fn tokenize_sql(&self, query: &str) -> Result<Vec<String>> {
        // Production-ready SQL tokenization
        let mut tokens = Vec::new();
        let mut current_token = String::new();
        let mut in_quotes = false;
        let mut quote_char = '\0';
        let mut in_parentheses = 0;
        let mut chars = query.chars().peekable();
        
        while let Some(ch) = chars.next() {
            match ch {
                // Handle quoted strings
                '"' | '\'' if !in_quotes => {
                    in_quotes = true;
                    quote_char = ch;
                    current_token.push(ch);
                }
                '"' | '\'' if in_quotes && ch == quote_char => {
                    in_quotes = false;
                    current_token.push(ch);
                    tokens.push(current_token.clone());
                    current_token.clear();
                }
                _ if in_quotes => {
                    current_token.push(ch);
                }
                // Handle parentheses
                '(' => {
                    if !current_token.trim().is_empty() {
                        tokens.push(current_token.clone());
                        current_token.clear();
                    }
                    tokens.push("(".to_string());
                    in_parentheses += 1;
                }
                ')' => {
                    if !current_token.trim().is_empty() {
                        tokens.push(current_token.clone());
                        current_token.clear();
                    }
                    tokens.push(")".to_string());
                    if in_parentheses > 0 {
                        in_parentheses -= 1;
                    }
                }
                // Handle whitespace and separators
                ' ' | '\t' | '\n' | '\r' | ',' | ';' => {
                    if !current_token.trim().is_empty() {
                        tokens.push(current_token.clone());
                        current_token.clear();
                    }
                    if ch == ',' || ch == ';' {
                        tokens.push(ch.to_string());
                    }
                }
                // Regular characters
                _ => {
                    current_token.push(ch);
                }
            }
        }
        
        // Add final token if not empty
        if !current_token.trim().is_empty() {
            tokens.push(current_token);
        }
        
        if tokens.is_empty() {
            return Err(async_graphql::Error::new("No valid SQL tokens found"));
        }
        
        Ok(tokens)
    }
    
    fn extract_operation_type(&self, tokens: &[String]) -> Result<QueryOperation> {
        if tokens.is_empty() {
            return Err(async_graphql::Error::new("Empty SQL query"));
        }
        
        let first_token = tokens[0].to_lowercase();
        
        match first_token.as_str() {
            "select" => Ok(QueryOperation::Select),
            "insert" => Ok(QueryOperation::Insert),
            "update" => Ok(QueryOperation::Update),
            "delete" => Ok(QueryOperation::Delete),
            "create" => Ok(QueryOperation::Create),
            "drop" => Ok(QueryOperation::Drop),
            "alter" => Ok(QueryOperation::Alter),
            "truncate" => Ok(QueryOperation::Truncate),
            "grant" => Ok(QueryOperation::Grant),
            "revoke" => Ok(QueryOperation::Revoke),
            "with" => Ok(QueryOperation::With), // CTE
            _ => Ok(QueryOperation::Other),
        }
    }
    
    fn detect_admin_operations(&self, tokens: &[String]) -> Result<bool> {
        let tokens_lower: Vec<String> = tokens.iter().map(|t| t.to_lowercase()).collect();
        
        // Check for admin operation keywords
        let admin_keywords = [
            "drop", "truncate", "alter", "create", "grant", "revoke",
            "exec", "execute", "system", "shell", "xp_", "sp_"
        ];
        
        for keyword in &admin_keywords {
            if tokens_lower.contains(&keyword.to_string()) {
                return Ok(true);
            }
        }
        
        // Check for dangerous system functions
        let dangerous_functions = [
            "load_file", "into", "outfile", "dumpfile", "information_schema",
            "mysql.user", "pg_catalog", "sys.tables", "waitfor", "delay",
            "sleep", "benchmark", "pg_sleep"
        ];
        
        for func in &dangerous_functions {
            if tokens_lower.iter().any(|token| token.contains(func)) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    fn extract_table_names(&self, tokens: &[String], operation: &QueryOperation) -> Result<Vec<String>> {
        let mut tables = Vec::new();
        let tokens_lower: Vec<String> = tokens.iter().map(|t| t.to_lowercase()).collect();
        
        match operation {
            QueryOperation::Select => {
                // Find FROM clause and extract table names
                if let Some(from_index) = tokens_lower.iter().position(|t| t == "from") {
                    // Extract table name(s) after FROM
                    let mut i = from_index + 1;
                    while i < tokens.len() {
                        let token = &tokens[i];
                        
                        // Stop at WHERE, GROUP BY, HAVING, ORDER BY, LIMIT, etc.
                        if ["where", "group", "having", "order", "limit", "join", "inner", "left", "right", "full", "cross"]
                            .contains(&token.to_lowercase().as_str()) {
                            break;
                        }
                        
                        // Skip keywords and punctuation
                        if !["(", ")", ",", ";"].contains(&token.as_str()) && 
                           !token.to_lowercase().starts_with("select") {
                            // Clean table name (remove quotes if present)
                            let clean_table = token.trim_matches('"').trim_matches('\'').to_string();
                            if !clean_table.is_empty() && !tables.contains(&clean_table) {
                                tables.push(clean_table);
                            }
                        }
                        
                        i += 1;
                    }
                }
            },
            QueryOperation::Insert => {
                // Find INTO clause and extract table name
                if let Some(into_index) = tokens_lower.iter().position(|t| t == "into") {
                    if into_index + 1 < tokens.len() {
                        let table_name = tokens[into_index + 1].trim_matches('"').trim_matches('\'').to_string();
                        if !table_name.is_empty() {
                            tables.push(table_name);
                        }
                    }
                }
            },
            QueryOperation::Update => {
                // Table name comes after UPDATE
                if let Some(update_index) = tokens_lower.iter().position(|t| t == "update") {
                    if update_index + 1 < tokens.len() {
                        let table_name = tokens[update_index + 1].trim_matches('"').trim_matches('\'').to_string();
                        if !table_name.is_empty() {
                            tables.push(table_name);
                        }
                    }
                }
            },
            QueryOperation::Delete => {
                // Find FROM clause in DELETE statement
                if let Some(from_index) = tokens_lower.iter().position(|t| t == "from") {
                    if from_index + 1 < tokens.len() {
                        let table_name = tokens[from_index + 1].trim_matches('"').trim_matches('\'').to_string();
                        if !table_name.is_empty() {
                            tables.push(table_name);
                        }
                    }
                }
            },
            QueryOperation::Create | QueryOperation::Drop | QueryOperation::Alter | QueryOperation::Truncate => {
                // For DDL operations, extract object names
                for (i, token) in tokens.iter().enumerate() {
                    let token_lower = token.to_lowercase();
                    if ["table", "database", "schema", "index", "view", "procedure", "function"].contains(&token_lower.as_str()) {
                        if i + 1 < tokens.len() {
                            let object_name = tokens[i + 1].trim_matches('"').trim_matches('\'').to_string();
                            if !object_name.is_empty() {
                                tables.push(object_name);
                            }
                        }
                    }
                }
            },
            _ => {
                // For other operations, attempt basic extraction
                // This is a fallback for less common operations
            }
        }
        
        Ok(tables)
    }

    async fn execute_single_query(&self, query: &str, parameters: &Option<Vec<serde_json::Value>>) -> Result<QueryResult> {
        let start_time = Instant::now();
        
        // Get connection from pool
        let mut conn = self.connection_pool.get_connection().await?;
        
        // Execute query
        let result = conn.execute(query, &parameters.clone().unwrap_or_default()).await?;
        
        // Return connection to pool
        self.connection_pool.return_connection(conn).await;
        
        let execution_time = start_time.elapsed();
        
        // Update metrics
        let rows_processed = result.rows.len() as u64;
        let bytes_processed = serde_json::to_vec(&result.rows).map(|v| v.len() as u64).unwrap_or(0);
        
        self.update_execution_metrics(execution_time, query, rows_processed, bytes_processed).await;
        
        Ok(QueryResult {
            execution_time_ms: execution_time.as_millis() as u64,
            ..result
        })
    }
}

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    operation: QueryOperation,
    tables: Vec<String>,
    pub is_admin_operation: bool,
}

#[derive(Debug, Clone)]
enum QueryOperation {
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Drop,
    Alter,
    Truncate,
    Grant,
    Revoke,
    With,
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
        let user_context = from_context(ctx)?;
        
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
        let ttl = Duration::from_secs(cache_ttl.unwrap_or(self.config.cache_ttl_default.as_secs() as i32) as u64);
        self.cache.set(&cache_key, &result, ttl).await;
        
        Ok(result)
    }

    /// Batch execute multiple queries efficiently
    async fn execute_batch_queries(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "List of queries to execute")] queries: Vec<BatchQuery>
    ) -> Result<Vec<QueryResult>> {
        let user_context = from_context(ctx)?;
        
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
                        Ok::<(usize, QueryResult), async_graphql::Error>((index, result))
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

    /// Get query performance statistics (disabled - QueryStatistics contains non-GraphQL types)
    // async fn query_statistics(&self, ctx: &Context<'_>) -> Result<QueryStatistics> {
    //     let user_context = from_context(ctx)?;
    //     
    //     if !user_context.has_permission("query.statistics") {
    //         return Err(async_graphql::Error::new("Insufficient permissions for query statistics"));
    //     }
    //     
    //     let metrics = self.metrics.read().await;
    //     let _cache_stats = self.cache.stats().await;
    //     
    //     Ok(QueryStatistics {
    //         queries_executed: metrics.queries_executed,
    //         cache_hit_rate: if metrics.queries_executed > 0 {
    //             metrics.cache_hits as f64 / metrics.queries_executed as f64
    //         } else {
    //             0.0
    //         },
    //         avg_execution_time_ms: metrics.avg_execution_time.as_millis() as f64,
    //         slow_queries: metrics.slow_queries.clone(),
    //         total_rows_processed: metrics.total_rows_processed,
    //         optimization_effectiveness: self.calculate_optimization_effectiveness().await,
    //     })
    // }

    /// Explain query execution plan
    async fn explain_query(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "SQL query to explain")] query: String
    ) -> Result<QueryExplanation> {
        let user_context = from_context(ctx)?;
        
        if !user_context.has_permission("query.explain") {
            return Err(async_graphql::Error::new("Insufficient permissions for query explanation"));
        }
        
        self.query_planner.explain(&query).await
    }

    /// Clear query cache
    async fn clear_cache(&self, ctx: &Context<'_>) -> Result<bool> {
        let user_context = from_context(ctx)?;
        
        if !user_context.has_permission("cache.clear") {
            return Err(async_graphql::Error::new("Insufficient permissions to clear cache"));
        }
        
        self.cache.clear().await;
        Ok(true)
    }

    /// Get cache statistics
    async fn cache_statistics(&self, ctx: &Context<'_>) -> Result<CacheStats> {
        let user_context = from_context(ctx)?;
        
        if !user_context.has_permission("cache.stats") {
            return Err(async_graphql::Error::new("Insufficient permissions for cache statistics"));
        }
        
        Ok(self.cache.stats().await)
    }

    /// Get connection pool statistics
    async fn pool_statistics(&self, ctx: &Context<'_>) -> Result<PoolStats> {
        let user_context = from_context(ctx)?;
        
        if !user_context.has_permission("pool.stats") {
            return Err(async_graphql::Error::new("Insufficient permissions for pool statistics"));
        }
        
        Ok(self.connection_pool.stats().await)
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

