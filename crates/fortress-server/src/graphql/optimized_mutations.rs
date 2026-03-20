//! Optimized GraphQL mutation handlers with batch operations and connection pooling
//!
//! Implements high-performance mutations with batch processing, async operations,
//! and efficient resource management for scalability.

use crate::graphql::{
    context::from_context,
    types::*,
    cache::{GraphQLCacheManager, QueryHasher},
};
use async_graphql::{Result, Object, Context};
use chrono::Utc;
use std::sync::Arc;
use futures::stream::{self, StreamExt};
use serde_json;
use uuid::Uuid;
use tokio::time::Instant;
use fortress_core::storage::StorageBackend;
use fortress_core::KeyManager;

/// Optimized GraphQL mutation root with performance enhancements
pub struct OptimizedMutation {
    cache_manager: Arc<GraphQLCacheManager>,
}

impl OptimizedMutation {
    pub fn new(cache_manager: Arc<GraphQLCacheManager>) -> Self {
        Self { cache_manager }
    }

    /// Batch insert records with parallel processing
    async fn batch_insert_records(
        &self,
        storage: &Arc<dyn StorageBackend>,
        table_key: &str,
        records: Vec<(String, serde_json::Value)>,
    ) -> Result<Vec<DataRecord>> {
        let start_time = Instant::now();
        
        // Process records in parallel with controlled concurrency
        let batch_size = 50; // Process 50 records at a time
        let results = stream::iter(records)
            .chunks(batch_size)
            .map(|batch| async move {
                let mut batch_results = Vec::new();
                
                for (record_id, record_data) in batch {
                    let record_metadata = serde_json::json!({
                        "id": record_id,
                        "data": record_data,
                        "created_at": Utc::now().to_rfc3339(),
                        "updated_at": Utc::now().to_rfc3339(),
                    });
                    
                    let record_key = format!("{}:record:{}", table_key, record_id);
                    
                    match storage.put(&record_key, &serde_json::to_vec(&record_metadata).unwrap()).await {
                        Ok(_) => {
                            let record = DataRecord {
                                id: record_id,
                                data: async_graphql::Json(record_data),
                                created_at: Utc::now(),
                                updated_at: Utc::now(),
                                encryption_metadata: None,
                            };
                            batch_results.push(record);
                        }
                        Err(e) => {
                            tracing::error!("Failed to insert record {}: {}", record_id, e);
                            // Continue processing other records
                        }
                    }
                }
                
                batch_results
            })
            .buffer_unordered(4) // Process up to 4 batches concurrently
            .collect::<Vec<_>>()
            .await;

        let all_records: Vec<DataRecord> = results.into_iter().flatten().collect();

        tracing::debug!(
            "Batch inserted {} records in {}ms",
            all_records.len(),
            start_time.elapsed().as_millis()
        );

        Ok(all_records)
    }

    /// Batch update records efficiently
    async fn batch_update_records(
        &self,
        storage: &Arc<dyn StorageBackend>,
        updates: Vec<(String, serde_json::Value)>,
    ) -> Result<Vec<DataRecord>> {
        let start_time = Instant::now();
        
        let results = stream::iter(updates)
            .map(|(record_id, update_data)| async move {
                let record_key = format!("record:{}", record_id);
                
                // Get existing record to preserve created_at
                match storage.get(&record_key).await {
                    Ok(Some(existing_data)) => {
                        if let Ok(mut record_info) = serde_json::from_slice::<serde_json::Value>(&existing_data) {
                            let original_created_at = record_info.get("created_at")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok())
                                .unwrap_or_else(|| Utc::now());
                            
                            // Update record
                            record_info["data"] = update_data;
                            record_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                            
                            match storage.put(&record_key, &serde_json::to_vec(&record_info).unwrap()).await {
                                Ok(_) => {
                                    let record = DataRecord {
                                        id: record_id,
                                        data: async_graphql::Json(record_info["data"].clone()),
                                        created_at: original_created_at,
                                        updated_at: Utc::now(),
                                        encryption_metadata: None,
                                    };
                                    Some(record)
                                }
                                Err(e) => {
                                    tracing::error!("Failed to update record {}: {}", record_id, e);
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })
            .buffer_unordered(20) // Process up to 20 updates concurrently
            .collect::<Vec<_>>()
            .await;

        let updated_records: Vec<DataRecord> = results.into_iter().flatten().collect();

        tracing::debug!(
            "Batch updated {} records in {}ms",
            updated_records.len(),
            start_time.elapsed().as_millis()
        );

        Ok(updated_records)
    }

    /// Invalidate cache entries for affected resources
    async fn invalidate_cache(&self, database: &str, table: Option<&str>) {
        // Invalidate database cache
        self.cache_manager.database_cache.clear().await;
        
        // Invalidate table cache if specified
        if let Some(table_name) = table {
            let _table_key = self.cache_manager.table_key(database, table_name);
            self.cache_manager.table_cache.clear().await;
        }
        
        // Invalidate query cache for affected resources
        self.cache_manager.query_cache.clear().await;
        
        tracing::debug!("Invalidated cache for database: {}, table: {:?}", database, table);
    }
}

impl OptimizedMutation {
    /// Optimized bulk insert with parallel processing
    pub async fn bulk_insert_optimized(
        &self, 
        ctx: &Context<'_>, 
        database: String, 
        table: String, 
        data: Vec<async_graphql::Json<serde_json::Value>>
    ) -> Result<ApiResponse<Vec<DataRecord>>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions
        graphql_ctx.require_any_role(&["admin", "database_admin", "bulk_writer"])?;

        let storage = &graphql_ctx.app_state.storage;
        
        // Check if table exists (with caching)
        let table_key = format!("db:{}:table:{}", database, table);
        let cache_key = self.cache_manager.table_key(&database, &table);
        
        let table_exists = if let Some(_) = self.cache_manager.table_cache.get(&cache_key).await {
            true // Cache hit means table exists
        } else {
            storage.exists(&table_key).await
                .map_err(|e| async_graphql::Error::new(format!("Failed to check table existence: {}", e)))?
        };

        if !table_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Table '{}' not found", table)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }

        let start_time = Instant::now();
        
        // Prepare records for batch insertion
        let records: Vec<(String, serde_json::Value)> = data
            .into_iter()
            .enumerate()
            .map(|(_index, item)| {
                let record_id = Uuid::new_v4().to_string();
                (record_id, item.0)
            })
            .collect();

        // Batch insert records
        let inserted_records = self.batch_insert_records(storage, &table_key, records).await?;

        // Update table record count efficiently
        if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Failed to get table data: {}", e)))? {
            if let Ok(mut table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                if let Some(record_count) = table_info.get_mut("record_count") {
                    *record_count = serde_json::Value::Number(serde_json::Number::from(
                        record_count.as_u64().unwrap_or(0) + inserted_records.len() as u64
                    ));
                    
                    table_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    
                    storage.put(&table_key, &serde_json::to_vec(&table_info).unwrap()).await
                        .map_err(|e| async_graphql::Error::new(format!("Failed to update table: {}", e)))?;
                }
            }
        }

        // Invalidate cache
        self.invalidate_cache(&database, Some(&table)).await;

        tracing::info!(
            "Bulk insert completed: {} records in {}ms",
            inserted_records.len(),
            start_time.elapsed().as_millis()
        );

        Ok(ApiResponse {
            success: true,
            data: Some(inserted_records),
            error_message: None,
            error_code: None,
        })
    }

    /// Optimized bulk update with parallel processing
    pub async fn bulk_update_optimized(
        &self,
        ctx: &Context<'_>,
        updates: Vec<async_graphql::Json<serde_json::Value>>,
    ) -> Result<ApiResponse<Vec<DataRecord>>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions
        graphql_ctx.require_any_role(&["admin", "database_admin", "data_writer"])?;

        let storage = &graphql_ctx.app_state.storage;
        
        let start_time = Instant::now();
        
        // Prepare updates
        let prepared_updates: Vec<(String, serde_json::Value)> = updates
            .into_iter()
            .filter_map(|item| {
                let update_data = item.0;
                let record_id = update_data.get("id")?.as_str()?.to_string();
                let data = update_data.get("data")?;
                Some((record_id, data.clone()))
            })
            .collect();

        // Batch update records
        let updated_records = self.batch_update_records(storage, prepared_updates).await?;

        // Invalidate cache (simplified - in production, be more selective)
        self.cache_manager.query_cache.clear().await;

        tracing::info!(
            "Bulk update completed: {} records in {}ms",
            updated_records.len(),
            start_time.elapsed().as_millis()
        );

        Ok(ApiResponse {
            success: true,
            data: Some(updated_records),
            error_message: None,
            error_code: None,
        })
    }

    /// Optimized bulk delete with parallel processing
    pub async fn bulk_delete_optimized(
        &self,
        ctx: &Context<'_>,
        database: String,
        table: String,
        record_ids: Vec<String>,
    ) -> Result<ApiResponse<i32>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions
        graphql_ctx.require_any_role(&["admin", "database_admin", "data_deleter"])?;

        let storage = &graphql_ctx.app_state.storage;
        
        let start_time = Instant::now();
        
        // Batch delete records
        let db_name = database.clone();
        let table_name = table.clone();
        let deleted_count = stream::iter(record_ids)
            .map(move |record_id| {
                let storage_clone = storage.clone();
                let db_clone = db_name.clone();
                let table_clone = table_name.clone();
                async move {
                    let record_key = format!("db:{}:table:{}:record:{}", db_clone, table_clone, record_id);
                    
                    match storage_clone.delete(&record_key).await {
                        Ok(_) => Some(1),
                        Err(e) => {
                            tracing::error!("Failed to delete record {}: {}", record_id, e);
                            Some(0)
                        }
                    }
                }
            })
            .buffer_unordered(50) // Delete up to 50 records concurrently
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .sum();

        // Update table record count
        let table_key = format!("db:{}:table:{}", database, table);
        if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Failed to get table data: {}", e)))? {
            if let Ok(mut table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                if let Some(record_count) = table_info.get_mut("record_count") {
                    let current_count = record_count.as_u64().unwrap_or(0);
                    *record_count = serde_json::Value::Number(serde_json::Number::from(
                        current_count.saturating_sub(deleted_count as u64)
                    ));
                    
                    table_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    
                    storage.put(&table_key, &serde_json::to_vec(&table_info).unwrap()).await
                        .map_err(|e| async_graphql::Error::new(format!("Failed to update table: {}", e)))?;
                }
            }
        }

        // Invalidate cache
        self.invalidate_cache(&database, Some(&table)).await;

        tracing::info!(
            "Bulk delete completed: {} records in {}ms",
            deleted_count,
            start_time.elapsed().as_millis()
        );

        Ok(ApiResponse {
            success: true,
            data: Some(deleted_count),
            error_message: None,
            error_code: None,
        })
    }

    /// Optimized database creation with caching
    async fn create_database_optimized(
        &self,
        ctx: &Context<'_>,
        input: CreateDatabaseInput,
    ) -> Result<ApiResponse<Database>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions
        graphql_ctx.require_role("admin")?;

        let storage = &graphql_ctx.app_state.storage;
        let key_manager = &graphql_ctx.app_state.key_manager;
        
        let start_time = Instant::now();
        
        // Generate database ID and algorithm
        let db_id = Uuid::new_v4();
        let algorithm = input.encryption_algorithm.unwrap_or(crate::graphql::types::EncryptionAlgorithm::Aegis256);
        
        // Convert to core algorithm
        let core_algorithm: Box<dyn fortress_core::encryption::EncryptionAlgorithm> = match algorithm {
            crate::graphql::types::EncryptionAlgorithm::Aegis256 => {
                Box::new(fortress_core::encryption::Aegis256::new())
            },
            crate::graphql::types::EncryptionAlgorithm::Aes256Gcm => {
                Box::new(fortress_core::encryption::Aes256Ctr::new())
            },
            crate::graphql::types::EncryptionAlgorithm::ChaCha20Poly1305 => {
                Box::new(fortress_core::encryption::ChaCha20Poly1305::new())
            },
            _ => Box::new(fortress_core::encryption::Aegis256::new()),
        };
        
        // Generate encryption key
        let encryption_key = key_manager.generate_key(core_algorithm.as_ref()).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to generate encryption key: {}", e)))?;
        
        // Create database metadata
        let db_metadata = serde_json::json!({
            "id": db_id.to_string(),
            "name": input.name,
            "description": input.description,
            "status": "active",
            "encryption_algorithm": match algorithm {
                crate::graphql::types::EncryptionAlgorithm::Aegis256 => "AEGIS256",
                crate::graphql::types::EncryptionAlgorithm::Aes256Gcm => "AES256GCM",
                crate::graphql::types::EncryptionAlgorithm::ChaCha20Poly1305 => "CHACHA20POLY1305",
                _ => "AEGIS256",
            },
            "created_at": Utc::now().to_rfc3339(),
            "updated_at": Utc::now().to_rfc3339(),
            "tags": input.tags.clone().unwrap_or_default(),
            "table_count": 0,
            "storage_size_bytes": 0,
            "key_id": hex::encode(encryption_key.as_bytes()),
        });
        
        // Store database metadata
        let db_key = format!("db:{}", input.name);
        storage.put(&db_key, &serde_json::to_vec(&db_metadata).unwrap_or_default()).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to create database: {}", e)))?;
        
        let database = Database {
            id: db_id.to_string(),
            name: input.name.clone(),
            description: input.description,
            status: DatabaseStatus::Active,
            encryption_algorithm: algorithm,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: input.tags.unwrap_or_default(),
            table_count: 0,
            storage_size_bytes: 0,
        };

        // Invalidate cache
        self.invalidate_cache(&input.name, None).await;

        tracing::info!(
            "Database created: {} in {}ms",
            input.name,
            start_time.elapsed().as_millis()
        );

        Ok(ApiResponse {
            success: true,
            data: Some(database),
            error_message: None,
            error_code: None,
        })
    }
}
