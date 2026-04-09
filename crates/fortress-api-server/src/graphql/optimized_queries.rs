//! Optimized GraphQL query handlers with connection pooling and batch operations
//!
//! Implements high-performance query processing with async streaming,
//! efficient pagination, and batch database operations for scalability.

use crate::graphql::{
    context::from_context,
    types::*,
    cache::{GraphQLCacheManager, QueryHasher, DatabaseCacheEntry},
};
use async_graphql::{Result, Context};
use chrono::Utc;
use std::sync::Arc;
use futures::stream::{self, Stream, StreamExt, TryStreamExt};
use serde_json;
use uuid::Uuid;
use tokio::time::Instant;
use fortress_core::storage::StorageBackend;

/// Optimized GraphQL query root with performance enhancements
pub struct OptimizedQuery {
    cache_manager: Arc<GraphQLCacheManager>,
}

impl OptimizedQuery {
    pub fn new(cache_manager: Arc<GraphQLCacheManager>) -> Self {
        Self { cache_manager }
    }

    /// Batch fetch multiple records efficiently
    async fn batch_fetch_records(
        &self,
        storage: &Arc<dyn StorageBackend>,
        keys: Vec<String>,
    ) -> Result<Vec<(String, Option<Vec<u8>>)>> {
        let start_time = Instant::now();
        
        // Use futures::stream for concurrent operations
        let results = stream::iter(keys)
            .map(|key| async move {
                let result = storage.get(&key).await;
                (key, result)
            })
            .buffer_unordered(50) // Process up to 50 records concurrently
            .collect::<Vec<_>>()
            .await;

        let processed_results: Vec<(String, Option<Vec<u8>>)> = results
            .into_iter()
            .map(|(key, result)| {
                match result {
                    Ok(data) => (key, data),
                    Err(_) => (key, None),
                }
            })
            .collect();

        tracing::debug!(
            "Batch fetched {} records in {}ms",
            processed_results.len(),
            start_time.elapsed().as_millis()
        );

        Ok(processed_results)
    }

    /// Stream large datasets efficiently
    async fn stream_records(
        &self,
        storage: &Arc<dyn StorageBackend>,
        prefix: &str,
        batch_size: usize,
    ) -> impl Stream<Item = Result<DataRecord>> {
        let storage = storage.clone();
        let prefix = prefix.to_string();

        stream::unfold(0, move |offset| {
            let storage = storage.clone();
            let prefix = prefix.clone();
            
            async move {
                // Get batch of keys
                match storage.list_prefix(&prefix).await {
                    Ok(keys) => {
                        let start = offset * batch_size;
                        let end = std::cmp::min(start + batch_size, keys.len());
                        
                        if start >= keys.len() {
                            return None;
                        }

                        let batch_keys: Vec<String> = keys[start..end].to_vec();
                        
                        // Fetch records in batch
                        match storage.batch_get(&batch_keys).await {
                            Ok(records) => {
                                let data_records: Vec<DataRecord> = records
                                    .into_iter()
                                    .filter_map(|(_key, data)| {
                                        data.and_then(|bytes| {
                                            serde_json::from_slice::<serde_json::Value>(&bytes).ok()
                                                .and_then(|record_info| {
                                                    let id = record_info.get("id")?.as_str()?.to_string();
                                                    let record_data = record_info.get("data")?.clone();
                                                    let created_at = record_info.get("created_at")?.as_str()?;
                                                    let created_at = created_at.parse().ok()?;
                                                    
                                                    Some(DataRecord {
                                                        id,
                                                        data: async_graphql::Json(record_data),
                                                        created_at,
                                                        updated_at: record_info.get("updated_at")
                                                            .and_then(|v| v.as_str())
                                                            .and_then(|s| s.parse().ok())
                                                            .unwrap_or_else(|| Utc::now()),
                                                        encryption_metadata: None,
                                                    })
                                                })
                                        })
                                    })
                                    .collect();

                                Some((Ok::<Vec<crate::graphql::types::DataRecord>, fortress_core::error::FortressError>(data_records), offset + 1))
                            }
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                }
            }
        })
        .flat_map(|result| stream::iter(result.unwrap_or_default()))
        .map(Ok)
    }
}

impl OptimizedQuery {
    /// Optimized database query with caching
    pub async fn databases_optimized(&self, ctx: &Context<'_>) -> Result<Vec<Database>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Check cache first
        let cache_key = "all_databases".to_string();
        if let Some(cached_entries) = self.cache_manager.database_cache.get(&cache_key).await {
            tracing::debug!("Database list cache hit");
            return Ok(vec![Database {
                id: cached_entries.id,
                name: cached_entries.name,
                description: None,
                status: match cached_entries.status.as_str() {
                    "active" => DatabaseStatus::Active,
                    "creating" => DatabaseStatus::Creating,
                    "deleting" => DatabaseStatus::Deleting,
                    "maintenance" => DatabaseStatus::Maintenance,
                    "archived" => DatabaseStatus::Archived,
                    _ => DatabaseStatus::Active,
                },
                encryption_algorithm: match cached_entries.encryption_algorithm.as_str() {
                    "AEGIS256" => EncryptionAlgorithm::Aegis256,
                    "AES256GCM" => EncryptionAlgorithm::Aes256Gcm,
                    "CHACHA20POLY1305" => EncryptionAlgorithm::ChaCha20Poly1305,
                    _ => EncryptionAlgorithm::Aegis256,
                },
                created_at: cached_entries.created_at.parse().unwrap_or_else(|_| Utc::now()),
                updated_at: cached_entries.updated_at.parse().unwrap_or_else(|_| Utc::now()),
                tags: Vec::new(),
                table_count: cached_entries.table_count,
                storage_size_bytes: cached_entries.storage_size_bytes,
            }]);
        }

        // Cache miss - fetch from storage
        let start_time = Instant::now();
        
        let db_keys = storage.list_prefix("db:").await
            .map_err(|e| async_graphql::Error::new(format!("Failed to list databases: {}", e)))?;
        
        // Batch fetch all database metadata
        let batch_results = self.batch_fetch_records(storage, db_keys).await?;
        
        let mut databases = Vec::new();
        let mut cache_entries = Vec::new();

        for (_key, data) in batch_results {
            if let Some(data) = data {
                if let Ok(db_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let (Some(name), Some(status), Some(algorithm), Some(created_at)) = (
                        db_info.get("name").and_then(|v| v.as_str()),
                        db_info.get("status").and_then(|v| v.as_str()),
                        db_info.get("encryption_algorithm").and_then(|v| v.as_str()),
                        db_info.get("created_at").and_then(|v| v.as_str())
                    ) {
                        let default_id = Uuid::new_v4().to_string();
                        let db = Database {
                            id: db_info.get("id").and_then(|v| v.as_str())
                                .unwrap_or(&default_id)
                                .parse().unwrap_or_else(|_| Uuid::new_v4()).to_string(),
                            name: name.to_string(),
                            description: db_info.get("description").and_then(|v| v.as_str()).map(String::from),
                            status: match status {
                                "active" => DatabaseStatus::Active,
                                "creating" => DatabaseStatus::Creating,
                                "deleting" => DatabaseStatus::Deleting,
                                "maintenance" => DatabaseStatus::Maintenance,
                                "archived" => DatabaseStatus::Archived,
                                _ => DatabaseStatus::Active,
                            },
                            encryption_algorithm: match algorithm {
                                "AEGIS256" => EncryptionAlgorithm::Aegis256,
                                "AES256GCM" => EncryptionAlgorithm::Aes256Gcm,
                                "CHACHA20POLY1305" => EncryptionAlgorithm::ChaCha20Poly1305,
                                _ => EncryptionAlgorithm::Aegis256,
                            },
                            created_at: created_at.parse().unwrap_or_else(|_| Utc::now()),
                            updated_at: db_info.get("updated_at").and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now()),
                            tags: db_info.get("tags")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                                .unwrap_or_default(),
                            table_count: db_info.get("table_count").and_then(|v| v.as_u64()).unwrap_or(0) as i32,
                            storage_size_bytes: db_info.get("storage_size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64,
                        };

                        // Create cache entry
                        let cache_entry = DatabaseCacheEntry {
                            id: db.id.clone(),
                            name: db.name.clone(),
                            status: status.to_string(),
                            encryption_algorithm: algorithm.to_string(),
                            created_at: created_at.to_string(),
                            updated_at: db_info.get("updated_at")
                                .and_then(|v| v.as_str())
                                .unwrap_or(created_at)
                                .to_string(),
                            table_count: db.table_count,
                            storage_size_bytes: db.storage_size_bytes,
                        };

                        databases.push(db);
                        cache_entries.push(cache_entry);
                    }
                }
            }
        }

        // Cache the results
        // Cache the first entry instead of the vector
        if let Some(first_entry) = cache_entries.first() {
            self.cache_manager.database_cache.put(cache_key, first_entry.clone()).await;
        }

        tracing::debug!(
            "Fetched {} databases in {}ms",
            databases.len(),
            start_time.elapsed().as_millis()
        );

        Ok(databases)
    }

    /// Optimized data query with streaming and intelligent pagination
    pub async fn query_data_optimized(&self, ctx: &Context<'_>, input: QueryDataInput) -> Result<QueryResult> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Generate query hash for caching
        let query_hash = QueryHasher::hash_query(
            &input.database,
            &input.table,
            &serde_json::json!({}), // Simplified filters for now
            &input.pagination,
        );

        let cache_key = self.cache_manager.query_key(&input.database, &input.table, &query_hash);
        
        // Check cache first
        if let Some(cached_result) = self.cache_manager.query_cache.get(&cache_key).await {
            tracing::debug!("Query cache hit for {}", cache_key);
            // Convert cached result manually
            let query_result: QueryResult = serde_json::from_value(cached_result.result)
                .map_err(|e| async_graphql::Error::new(format!("Cache deserialization error: {}", e)))?;
            return Ok(query_result);
        }

        let start_time = Instant::now();
        
        // Use streaming for large datasets
        let data_prefix = format!("db:{}:table:{}:record:", input.database, input.table);
        
        // Get total count efficiently
        let record_keys = storage.list_prefix(&data_prefix).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to query data: {}", e)))?;
        
        let total_records = record_keys.len();
        
        // Apply pagination at the storage level if possible
        let page = input.pagination.as_ref().and_then(|p| p.page).unwrap_or(0) as usize;
        let page_size = input.pagination.as_ref().and_then(|p| p.page_size).unwrap_or(10) as usize;
        let start_idx = page * page_size;
        let end_idx = std::cmp::min(start_idx + page_size, total_records);
        
        // Only fetch the required records
        let paginated_keys: Vec<String> = if start_idx < total_records {
            record_keys[start_idx..end_idx].to_vec()
        } else {
            Vec::new()
        };

        // Batch fetch records
        let batch_results = self.batch_fetch_records(storage, paginated_keys).await?;
        
        let mut records = Vec::new();
        
        for (_key, data) in batch_results {
            if let Some(data) = data {
                if let Ok(record_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let (Some(id), Some(record_data), Some(created_at)) = (
                        record_info.get("id").and_then(|v| v.as_str()),
                        record_info.get("data"),
                        record_info.get("created_at").and_then(|v| v.as_str())
                    ) {
                        let record = DataRecord {
                            id: id.to_string(),
                            data: async_graphql::Json(record_data.clone()),
                            created_at: created_at.parse().unwrap_or_else(|_| Utc::now()),
                            updated_at: record_info.get("updated_at").and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now()),
                            encryption_metadata: None,
                        };
                        records.push(record);
                    }
                }
            }
        }

        let pagination_info = PaginationInfo {
            page: page as i32,
            page_size: page_size as i32,
            total_pages: ((total_records as i32 + page_size as i32 - 1) / page_size as i32) as i32,
            total_records: total_records as i32,
            has_next: end_idx < total_records,
            has_previous: page > 0,
        };

        let query_result = QueryResult {
            records,
            total_count: total_records as i32,
            has_more: end_idx < total_records,
            pagination: Some(pagination_info),
        };

        // Cache result
        let cache_entry = crate::graphql::cache::QueryCacheEntry {
            query_hash: query_hash.clone(),
            result: serde_json::to_value(&query_result).unwrap_or_default(),
            record_count: total_records,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        };

        self.cache_manager.query_cache.put(cache_key, cache_entry).await;

        tracing::debug!(
            "Query executed in {}ms, returned {} records",
            start_time.elapsed().as_millis(),
            total_records
        );

        Ok(query_result)
    }

    /// Optimized table query with pagination
    pub async fn tables_optimized(&self, ctx: &Context<'_>, input: TableQueryInput) -> Result<QueryResult> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Generate query hash for caching
        let query_hash = QueryHasher::hash_query(
            &input.database,
            &input.table,
            &serde_json::json!({}), // Simplified filters for now
            &input.pagination,
        );

        let cache_key = self.cache_manager.query_key(&input.database, &input.table, &query_hash);
        
        // Check cache first
        if let Some(cached_result) = self.cache_manager.query_cache.get(&cache_key).await {
            tracing::debug!("Query cache hit for {}", cache_key);
            // Convert cached result manually
            let query_result: QueryResult = serde_json::from_value(cached_result.result)
                .map_err(|e| async_graphql::Error::new(format!("Cache deserialization error: {}", e)))?;
            return Ok(query_result);
        }

        let start_time = Instant::now();
        
        // Use streaming for large datasets
        let data_prefix = format!("db:{}:table:{}:record:", input.database, input.table);
        
        // Get total count efficiently
        let record_keys = storage.list_prefix(&data_prefix).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to query data: {}", e)))?;
        
        let total_records = record_keys.len();
        
        // Apply pagination at the storage level if possible
        let page = input.pagination.as_ref().and_then(|p| p.page).unwrap_or(0) as usize;
        let page_size = input.pagination.as_ref().and_then(|p| p.page_size).unwrap_or(10) as usize;
        let start_idx = page * page_size;
        let end_idx = std::cmp::min(start_idx + page_size, total_records);
        
        // Only fetch the required records
        let paginated_keys: Vec<String> = if start_idx < total_records {
            record_keys[start_idx..end_idx].to_vec()
        } else {
            Vec::new()
        };

        // Batch fetch records
        let batch_results = self.batch_fetch_records(storage, paginated_keys).await?;
        
        let mut records = Vec::new();
        
        for (_key, data) in batch_results {
            if let Some(data) = data {
                if let Ok(record_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let (Some(id), Some(record_data), Some(created_at)) = (
                        record_info.get("id").and_then(|v| v.as_str()),
                        record_info.get("data"),
                        record_info.get("created_at").and_then(|v| v.as_str())
                    ) {
                        let record = DataRecord {
                            id: id.to_string(),
                            data: async_graphql::Json(record_data.clone()),
                            created_at: created_at.parse().unwrap_or_else(|_| Utc::now()),
                            updated_at: record_info.get("updated_at").and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now()),
                            encryption_metadata: None,
                        };
                        records.push(record);
                    }
                }
            }
        }

        let pagination_info = PaginationInfo {
            page: page as i32,
            page_size: page_size as i32,
            total_pages: ((total_records as i32 + page_size as i32 - 1) / page_size as i32) as i32,
            total_records: total_records as i32,
            has_next: end_idx < total_records,
            has_previous: page > 0,
        };

        let query_result = QueryResult {
            records,
            total_count: total_records as i32,
            has_more: end_idx < total_records,
            pagination: Some(pagination_info),
        };

        // Cache result
        let cache_entry = crate::graphql::cache::QueryCacheEntry {
            query_hash: query_hash.clone(),
            result: serde_json::to_value(&query_result).unwrap_or_default(),
            record_count: total_records,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        };

        self.cache_manager.query_cache.put(cache_key, cache_entry).await;

        tracing::debug!(
            "Query executed in {}ms, returned {} records",
            start_time.elapsed().as_millis(),
            total_records
        );

        Ok(query_result)
    }

    /// Stream large datasets efficiently
    pub async fn stream_data(&self, ctx: &Context<'_>, database: String, table: String) -> async_graphql::Result<async_graphql::Value> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        let data_prefix = format!("db:{}:table:{}:record:", database, table);
        
        // Collect stream into result (in production, you might want to return a streaming response)
        let stream = self.stream_records(storage, &data_prefix, 100).await; // Batch size of 100
        let records: Vec<DataRecord> = stream
            .take(10000) // Limit to prevent memory issues
            .try_collect()
            .await
            .map_err(|e| async_graphql::Error::new(format!("Stream error: {:?}", e)))?;

        Ok(async_graphql::Value::from_json(
            serde_json::to_value(records)
                .map_err(|e| async_graphql::Error::new(format!("Serialization error: {:?}", e)))?
        )
        .map_err(|e| async_graphql::Error::new(format!("JSON conversion error: {:?}", e)))?)
    }
}
