//! Advanced query optimizer for Fortress database operations
//!
//! This module provides sophisticated query optimization capabilities including
//! cost-based optimization, index selection, and query plan caching.

use crate::error::{FortressError, Result, QueryErrorCode};
use crate::query::{ExecutionPlan, PlanNode, PlanNodeType, QueryEngine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Query optimizer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOptimizerConfig {
    /// Enable cost-based optimization
    pub enable_cost_based_optimization: bool,
    /// Enable query plan caching
    pub enable_plan_caching: bool,
    /// Maximum number of cached plans
    pub max_cached_plans: usize,
    /// Statistics collection interval in seconds
    pub stats_collection_interval_secs: u64,
    /// Enable adaptive optimization
    pub enable_adaptive_optimization: bool,
    /// Minimum query cost for caching
    pub min_cache_cost_threshold: f64,
}

impl Default for QueryOptimizerConfig {
    fn default() -> Self {
        Self {
            enable_cost_based_optimization: true,
            enable_plan_caching: true,
            max_cached_plans: 1000,
            stats_collection_interval_secs: 60,
            enable_adaptive_optimization: true,
            min_cache_cost_threshold: 10.0,
        }
    }
}

/// Table statistics for cost-based optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableStatistics {
    /// Table name
    pub table_name: String,
    /// Number of rows
    pub row_count: u64,
    /// Average row size in bytes
    pub avg_row_size: f64,
    /// Column statistics
    pub column_stats: HashMap<String, ColumnStatistics>,
    /// Index statistics
    pub index_stats: HashMap<String, IndexStatistics>,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Column statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnStatistics {
    /// Column name
    pub name: String,
    /// Data type
    pub data_type: String,
    /// Number of distinct values
    pub distinct_count: u64,
    /// Number of null values
    pub null_count: u64,
    /// Minimum value (for numeric types)
    pub min_value: Option<serde_json::Value>,
    /// Maximum value (for numeric types)
    pub max_value: Option<serde_json::Value>,
    /// Histogram for value distribution
    pub histogram: Option<Vec<(f64, u64)>>,
}

/// Index statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStatistics {
    /// Index name
    pub name: String,
    /// Indexed columns
    pub columns: Vec<String>,
    /// Index type (B-tree, Hash, etc.)
    pub index_type: String,
    /// Number of index entries
    pub entry_count: u64,
    /// Index size in bytes
    pub size_bytes: u64,
    /// Selectivity (0.0 to 1.0, lower is more selective)
    pub selectivity: f64,
    /// Last used timestamp
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

/// Cached query plan
#[derive(Debug, Clone)]
pub struct CachedPlan {
    /// Original query hash
    pub query_hash: u64,
    /// Optimized execution plan
    pub plan: ExecutionPlan,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Number of times used
    pub use_count: u64,
    /// Total execution time
    pub total_execution_time_ms: u64,
    /// Last used timestamp
    pub last_used: chrono::DateTime<chrono::Utc>,
}

/// Advanced query optimizer
#[derive(Debug)]
pub struct QueryOptimizer {
    /// Configuration
    config: QueryOptimizerConfig,
    /// Table statistics
    table_stats: Arc<RwLock<HashMap<String, TableStatistics>>>,
    /// Cached query plans
    cached_plans: Arc<RwLock<HashMap<u64, CachedPlan>>>,
    /// Query engine reference
    query_engine: Arc<dyn QueryEngine>,
}

impl QueryOptimizer {
    /// Create a new query optimizer
    pub fn new(
        config: QueryOptimizerConfig,
        query_engine: Arc<dyn QueryEngine>,
    ) -> Self {
        Self {
            config,
            table_stats: Arc::new(RwLock::new(HashMap::new())),
            cached_plans: Arc::new(RwLock::new(HashMap::new())),
            query_engine,
        }
    }

    /// Optimize a query execution plan
    pub async fn optimize_plan(&self, plan: ExecutionPlan) -> Result<ExecutionPlan> {
        let mut optimized_plan = plan;

        // Apply optimization rules
        if self.config.enable_cost_based_optimization {
            optimized_plan = self.apply_cost_based_optimization(optimized_plan).await?;
        }

        optimized_plan = self.apply_predicate_pushdown(optimized_plan).await?;
        optimized_plan = self.apply_projection_pruning(optimized_plan).await?;
        optimized_plan = self.apply_join_reordering(optimized_plan).await?;

        Ok(optimized_plan)
    }

    /// Apply cost-based optimization
    async fn apply_cost_based_optimization(&self, mut plan: ExecutionPlan) -> Result<ExecutionPlan> {
        // Calculate current plan cost
        let current_cost = self.calculate_plan_cost(&plan).await?;

        // Try alternative access paths
        for (i, node) in plan.nodes.iter_mut().enumerate() {
            if node.node_type == PlanNodeType::TableScan {
                // Check if index scan would be better
                if let Some(index_scan_cost) = self.estimate_index_scan_cost(node).await? {
                    if index_scan_cost < node.estimated_cost {
                        node.node_type = PlanNodeType::IndexScan;
                        node.estimated_cost = index_scan_cost;
                    }
                }
            }
        }

        // Recalculate total cost
        plan.estimated_cost = self.calculate_plan_cost(&plan).await?;

        Ok(plan)
    }

    /// Apply predicate pushdown optimization
    async fn apply_predicate_pushdown(&self, mut plan: ExecutionPlan) -> Result<ExecutionPlan> {
        // Push filters as close to data sources as possible
        for node in &mut plan.nodes {
            if node.node_type == PlanNodeType::Filter {
                // Try to push filter down to child nodes
                for child in &mut node.children {
                    if child.node_type == PlanNodeType::TableScan || child.node_type == PlanNodeType::IndexScan {
                        // Merge filter parameters
                        for (key, value) in node.parameters.iter() {
                            child.parameters.insert(key.clone(), value.clone());
                        }
                        child.estimated_cost *= 0.5; // Assume 50% cost reduction
                    }
                }
            }
        }

        Ok(plan)
    }

    /// Apply projection pruning optimization
    async fn apply_projection_pruning(&self, mut plan: ExecutionPlan) -> Result<ExecutionPlan> {
        // Remove unused columns from projections
        let used_columns = self.analyze_used_columns(&plan).await?;
        for node in &mut plan.nodes {
            if node.node_type == PlanNodeType::Project {
                
                if let Some(columns) = node.parameters.get("columns") {
                    if let Ok(column_list) = serde_json::from_value::<Vec<String>>(columns.clone()) {
                        let pruned_columns: Vec<String> = column_list
                            .into_iter()
                            .filter(|col| used_columns.contains(col))
                            .collect();

                        node.parameters.insert("columns".to_string(), 
                            serde_json::to_value(pruned_columns).unwrap());
                        node.estimated_cost *= 0.8; // Assume 20% cost reduction
                    }
                }
            }
        }

        Ok(plan)
    }

    /// Apply join reordering optimization
    async fn apply_join_reordering(&self, mut plan: ExecutionPlan) -> Result<ExecutionPlan> {
        // Reorder joins based on table sizes and selectivity
        let join_nodes: Vec<usize> = plan.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.node_type == PlanNodeType::Join)
            .map(|(i, _)| i)
            .collect();

        if join_nodes.len() > 1 {
            // Sort join nodes by estimated cost (smaller tables first)
            let mut join_indices = join_nodes.clone();
            join_indices.sort_by(|&a, &b| {
                plan.nodes[a].estimated_cost.partial_cmp(&plan.nodes[b].estimated_cost).unwrap()
            });

            // Reorder nodes in the plan
            let mut new_nodes = Vec::new();
            for &idx in &join_indices {
                new_nodes.push(plan.nodes[idx].clone());
            }

            // Replace join nodes with reordered ones
            for (i, &node_idx) in join_indices.iter().enumerate() {
                plan.nodes[node_idx] = new_nodes[i].clone();
            }
        }

        Ok(plan)
    }

    /// Calculate the cost of an execution plan
    async fn calculate_plan_cost(&self, plan: &ExecutionPlan) -> Result<f64> {
        let mut total_cost = 0.0;

        for node in &plan.nodes {
            total_cost += node.estimated_cost;

            // Add costs for children
            for child in &node.children {
                total_cost += self.calculate_node_cost(child).await?;
            }
        }

        Ok(total_cost)
    }

    /// Calculate the cost of a single plan node
    async fn calculate_node_cost(&self, node: &PlanNode) -> Result<f64> {
        let mut cost = node.estimated_cost;

        match node.node_type {
            PlanNodeType::TableScan => {
                if let Some(table_name) = node.parameters.get("table") {
                    if let Ok(name) = serde_json::from_value::<String>(table_name.clone()) {
                        if let Some(stats) = self.table_stats.read().await.get(&name) {
                            cost = stats.row_count as f64 * stats.avg_row_size;
                        }
                    }
                }
            }
            PlanNodeType::IndexScan => {
                if let Some(table_name) = node.parameters.get("table") {
                    if let Ok(name) = serde_json::from_value::<String>(table_name.clone()) {
                        if let Some(stats) = self.table_stats.read().await.get(&name) {
                            // Index scans are typically much cheaper
                            cost = (stats.row_count as f64 * 0.1) * stats.avg_row_size;
                        }
                    }
                }
            }
            PlanNodeType::Join => {
                // Join cost depends on the sizes of both tables
                cost *= 2.0; // Simplified join cost model
            }
            _ => {}
        }

        Ok(cost)
    }

    /// Estimate the cost of an index scan for a given node
    async fn estimate_index_scan_cost(&self, node: &PlanNode) -> Result<Option<f64>> {
        if let Some(table_name) = node.parameters.get("table") {
            if let Ok(name) = serde_json::from_value::<String>(table_name.clone()) {
                if let Some(stats) = self.table_stats.read().await.get(&name) {
                    // Look for suitable indexes
                    for (_, index_stats) in &stats.index_stats {
                        if index_stats.selectivity < 0.5 {
                            // Index is selective enough to be useful
                            let index_cost = (stats.row_count as f64 * index_stats.selectivity) * stats.avg_row_size;
                            return Ok(Some(index_cost));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Analyze which columns are used in a plan
    async fn analyze_used_columns(&self, plan: &ExecutionPlan) -> Result<Vec<String>> {
        let mut used_columns = std::collections::HashSet::new();

        for node in &plan.nodes {
            match node.node_type {
                PlanNodeType::Filter => {
                    if let Some(predicate) = node.parameters.get("predicate") {
                        if let Ok(pred_str) = serde_json::from_value::<String>(predicate.clone()) {
                            // Extract column names from predicate (simplified)
                            let columns = self.extract_columns_from_predicate(&pred_str);
                            used_columns.extend(columns);
                        }
                    }
                }
                PlanNodeType::Project => {
                    if let Some(columns) = node.parameters.get("columns") {
                        if let Ok(column_list) = serde_json::from_value::<Vec<String>>(columns.clone()) {
                            used_columns.extend(column_list);
                        }
                    }
                }
                PlanNodeType::Join => {
                    if let Some(join_cols) = node.parameters.get("join_columns") {
                        if let Ok(join_col_list) = serde_json::from_value::<Vec<String>>(join_cols.clone()) {
                            used_columns.extend(join_col_list);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(used_columns.into_iter().collect())
    }

    /// Extract column names from a predicate string (simplified parser)
    fn extract_columns_from_predicate(&self, predicate: &str) -> Vec<String> {
        let mut columns = Vec::new();
        
        // Simple regex-based extraction (in production, use a proper SQL parser)
        for word in predicate.split_whitespace() {
            if word.contains('.') && !word.contains('(') {
                columns.push(word.to_string());
            }
        }

        columns
    }

    /// Get or create a cached plan for a query
    pub async fn get_cached_plan(&self, query_hash: u64) -> Option<CachedPlan> {
        let cached_plans = self.cached_plans.read().await;
        cached_plans.get(&query_hash).cloned()
    }

    /// Cache a query plan
    pub async fn cache_plan(&self, query_hash: u64, plan: ExecutionPlan) -> Result<()> {
        if !self.config.enable_plan_caching {
            return Ok(());
        }

        let mut cached_plans = self.cached_plans.write().await;
        
        // Check cache size limit
        if cached_plans.len() >= self.config.max_cached_plans {
            // Remove least recently used plan
            if let Some((lru_key, _)) = cached_plans
                .iter()
                .min_by_key(|(_, cached)| cached.last_used)
            {
                let key_to_remove = lru_key.clone();
                cached_plans.remove(&key_to_remove);
            }
        }

        let cached_plan = CachedPlan {
            query_hash,
            plan,
            created_at: chrono::Utc::now(),
            use_count: 0,
            total_execution_time_ms: 0,
            last_used: chrono::Utc::now(),
        };

        cached_plans.insert(query_hash, cached_plan);
        Ok(())
    }

    /// Update table statistics
    pub async fn update_table_statistics(&self, table_name: String, stats: TableStatistics) -> Result<()> {
        let mut table_stats = self.table_stats.write().await;
        table_stats.insert(table_name, stats);
        Ok(())
    }

    /// Get table statistics
    pub async fn get_table_statistics(&self, table_name: &str) -> Option<TableStatistics> {
        let table_stats = self.table_stats.read().await;
        table_stats.get(table_name).cloned()
    }

    /// Clear cached plans
    pub async fn clear_cache(&self) -> Result<()> {
        let mut cached_plans = self.cached_plans.write().await;
        cached_plans.clear();
        Ok(())
    }

    /// Get optimizer statistics
    pub async fn get_optimizer_stats(&self) -> OptimizerStats {
        let cached_plans = self.cached_plans.read().await;
        let table_stats = self.table_stats.read().await;

        OptimizerStats {
            cached_plans_count: cached_plans.len(),
            max_cached_plans: self.config.max_cached_plans,
            tables_with_stats: table_stats.len(),
            total_cache_hits: cached_plans.values().map(|p| p.use_count).sum(),
            cache_hit_ratio: if cached_plans.is_empty() { 0.0 } else {
                cached_plans.values().map(|p| p.use_count).sum::<u64>() as f64 / 
                (cached_plans.values().map(|p| p.use_count).sum::<u64>() + cached_plans.len() as u64) as f64
            },
        }
    }
}

/// Optimizer statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizerStats {
    /// Number of cached plans
    pub cached_plans_count: usize,
    /// Maximum cached plans
    pub max_cached_plans: usize,
    /// Number of tables with statistics
    pub tables_with_stats: usize,
    /// Total cache hits
    pub total_cache_hits: u64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
}

/// Hash function for query normalization
pub fn hash_query(query: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Normalize query (remove extra whitespace, convert to uppercase)
    let normalized = query
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .to_uppercase();

    let mut hasher = DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::*;

    #[test]
    fn test_query_hashing() {
        let query1 = "SELECT * FROM users WHERE id = 1";
        let query2 = "select   *   from   users   where   id = 1";
        let query3 = "SELECT * FROM orders WHERE id = 1";

        assert_eq!(hash_query(query1), hash_query(query2));
        assert_ne!(hash_query(query1), hash_query(query3));
    }

    #[test]
    fn test_optimizer_config_default() {
        let config = QueryOptimizerConfig::default();
        assert!(config.enable_cost_based_optimization);
        assert!(config.enable_plan_caching);
        assert_eq!(config.max_cached_plans, 1000);
    }

    #[tokio::test]
    async fn test_plan_caching() {
        let config = QueryOptimizerConfig::default();
        let engine = Arc::new(crate::query::InMemoryQueryEngine::new());
        let optimizer = QueryOptimizer::new(config, engine);

        let query_hash = hash_query("SELECT * FROM users");
        let plan = ExecutionPlan {
            nodes: vec![PlanNode {
                node_type: PlanNodeType::TableScan,
                children: Vec::new(),
                parameters: HashMap::new(),
                estimated_cost: 100.0,
            }],
            estimated_cost: 100.0,
            metadata: HashMap::new(),
        };

        // Cache the plan
        optimizer.cache_plan(query_hash, plan.clone()).await.unwrap();

        // Retrieve from cache
        let cached = optimizer.get_cached_plan(query_hash).await.unwrap();
        assert_eq!(cached.query_hash, query_hash);
        assert_eq!(cached.plan.estimated_cost, 100.0);
    }

    #[tokio::test]
    async fn test_table_statistics() {
        let config = QueryOptimizerConfig::default();
        let engine = Arc::new(crate::query::InMemoryQueryEngine::new());
        let optimizer = QueryOptimizer::new(config, engine);

        let stats = TableStatistics {
            table_name: "users".to_string(),
            row_count: 1000,
            avg_row_size: 256.0,
            column_stats: HashMap::new(),
            index_stats: HashMap::new(),
            last_updated: chrono::Utc::now(),
        };

        optimizer.update_table_statistics("users".to_string(), stats).await.unwrap();

        let retrieved = optimizer.get_table_statistics("users").await.unwrap();
        assert_eq!(retrieved.table_name, "users");
        assert_eq!(retrieved.row_count, 1000);
    }
}
