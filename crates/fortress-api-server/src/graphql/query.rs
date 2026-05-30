//! GraphQL query handlers
//!
//! Implements all GraphQL queries for database operations, data retrieval,
//! and system information.

use crate::graphql::{
    context::from_context,
    types::*,
    context::AuthenticatedUser,
};
use async_graphql::{Result, Object, Context};
use chrono::Utc;
use std::collections::HashMap;
use fortress_core::secrets::SecretsEngine;
use serde_json;
use uuid::Uuid;

/// GraphQL query root
pub struct Query;

#[Object]
impl Query {
    // ==================== Database Queries ====================

    /// Get all databases
    async fn databases(&self, ctx: &Context<'_>) -> Result<Vec<Database>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // List all database metadata entries
        let db_keys = storage.list_prefix("db:").await
            .map_err(|e| async_graphql::Error::new(format!("Database listing failed: {}", e)))?;
        
        // Batch fetch all database entries to reduce round trips
        let db_data = storage.batch_get(&db_keys).await
            .map_err(|e| async_graphql::Error::new(format!("Database batch retrieval failed: {}", e)))?;
        
        let mut databases = Vec::new();
        
        for (_key, data) in db_data {
            if let Some(data) = data {
                
                if let Ok(db_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let (Some(name), Some(status), Some(algorithm), Some(created_at)) = (
                        db_info.get("name").and_then(|v| v.as_str()),
                        db_info.get("status").and_then(|v| v.as_str()),
                        db_info.get("encryption_algorithm").and_then(|v| v.as_str()),
                        db_info.get("created_at").and_then(|v| v.as_str())
                    ) {
                        let db = Database {
                            id: db_info.get("id").and_then(|v| v.as_str())
                                .map(|s| s.parse().unwrap_or_else(|_| Uuid::new_v4()))
                                .unwrap_or_else(|| Uuid::new_v4()).to_string(),
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
                        databases.push(db);
                    }
                }
            }
        }
        
        Ok(databases)
    }

    /// Get a specific database by name
    async fn database(&self, ctx: &Context<'_>, name: String) -> Result<Option<Database>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Look up database by name
        let db_key = format!("db:{}", name);
        
        if let Some(data) = storage.get(&db_key).await
            .map_err(|e| async_graphql::Error::new(format!("Database retrieval failed: {}", e)))? {
            
            if let Ok(db_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let (Some(status), Some(algorithm), Some(created_at)) = (
                    db_info.get("status").and_then(|v| v.as_str()),
                    db_info.get("encryption_algorithm").and_then(|v| v.as_str()),
                    db_info.get("created_at").and_then(|v| v.as_str())
                ) {
                    let default_id = Uuid::new_v4().to_string();
                    let db = Database {
                        id: db_info.get("id").and_then(|v| v.as_str())
                            .unwrap_or(&default_id)
                            .parse().unwrap_or_else(|_| Uuid::new_v4()).to_string(),
                        name: name.clone(),
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
                    return Ok(Some(db));
                }
            }
        }
        
        Ok(None)
    }

    // ==================== Table Queries ====================

    /// Get all tables in a database
    async fn tables(&self, ctx: &Context<'_>, database: String) -> Result<Vec<Table>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // List all table metadata entries for this database
        let table_prefix = format!("db:{}:table:", database);
        let table_keys = storage.list_prefix(&table_prefix).await
            .map_err(|e| async_graphql::Error::new(format!("Table listing failed: {}", e)))?;
        
        let mut tables = Vec::new();
        
        for key in table_keys {
            if let Some(data) = storage.get(&key).await
                .map_err(|e| async_graphql::Error::new(format!("Table data retrieval failed: {}", e)))? {
                
                if let Ok(table_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let (Some(name), Some(created_at)) = (
                        table_info.get("name").and_then(|v| v.as_str()),
                        table_info.get("created_at").and_then(|v| v.as_str())
                    ) {
                        let table = Table {
                            id: table_info.get("id").and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .map(|s| s.parse().unwrap_or_else(|_| Uuid::new_v4()))
                                .unwrap_or_else(|| Uuid::new_v4()).to_string(),
                            name: name.to_string(),
                            database: database.clone(),
                            description: table_info.get("description").and_then(|v| v.as_str()).map(String::from),
                            // Parse fields from table_info
                            fields: if let Some(fields_array) = table_info.get("fields").and_then(|v| v.as_array()) {
                                fields_array.iter().filter_map(|field| {
                                    if let (Some(name), Some(field_type_str)) = (
                                        field.get("name").and_then(|v| v.as_str()),
                                        field.get("field_type").and_then(|v| v.as_str())
                                    ) {
                                        let field_type = match field_type_str {
                                            "Text" => crate::graphql::types::FieldType::Text,
                                            "Integer" => crate::graphql::types::FieldType::Integer,
                                            "Float" => crate::graphql::types::FieldType::Float,
                                            "Boolean" => crate::graphql::types::FieldType::Boolean,
                                            "DateTime" => crate::graphql::types::FieldType::DateTime,
                                            "Date" => crate::graphql::types::FieldType::DateTime,
                                            "Json" => crate::graphql::types::FieldType::Json,
                                            "Binary" => crate::graphql::types::FieldType::Binary,
                                            _ => crate::graphql::types::FieldType::Text,
                                        };
                                        Some(crate::graphql::types::Field {
                                            name: name.to_string(),
                                            field_type,
                                            required: field.get("required").and_then(|v| v.as_bool()).unwrap_or(false),
                                            description: field.get("description").and_then(|v| v.as_str()).map(String::from),
                                            default_value: field.get("default_value").and_then(|v| v.as_str()).map(String::from),
                                            encryption_algorithm: field.get("encryption_algorithm").and_then(|v| v.as_str()).and_then(|alg| match alg {
                                                "Aegis256" => Some(crate::graphql::types::EncryptionAlgorithm::Aegis256),
                                                "ChaCha20Poly1305" => Some(crate::graphql::types::EncryptionAlgorithm::ChaCha20Poly1305),
                                                "Aes256Gcm" => Some(crate::graphql::types::EncryptionAlgorithm::Aes256Gcm),
                                                "Rsa2048" => Some(crate::graphql::types::EncryptionAlgorithm::Rsa2048),
                                                "Rsa4096" => Some(crate::graphql::types::EncryptionAlgorithm::Rsa4096),
                                                "EcdsaP256" => Some(crate::graphql::types::EncryptionAlgorithm::EcdsaP256),
                                                "EcdsaP384" => Some(crate::graphql::types::EncryptionAlgorithm::EcdsaP384),
                                                _ => None,
                                            }),
                                            encrypted: field.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false),
                                        })
                                    } else {
                                        None
                                    }
                                }).collect::<Vec<_>>()
                            } else {
                                Vec::new()
                            },
                            // Parse primary_key from table_info
                            primary_key: if let Some(pk_array) = table_info.get("primary_key").and_then(|v| v.as_array()) {
                                pk_array.iter().filter_map(|pk| pk.as_str().map(String::from)).collect::<Vec<_>>()
                            } else {
                                Vec::new()
                            },
                            created_at: created_at.parse().unwrap_or_else(|_| Utc::now()),
                            updated_at: table_info.get("updated_at").and_then(|v| v.as_str())
                                .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now()),
                            record_count: table_info.get("record_count").and_then(|v| v.as_u64()).unwrap_or(0) as i32,
                            encryption_enabled: table_info.get("encryption_enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                        };
                        tables.push(table);
                    }
                }
            }
        }
        
        Ok(tables)
    }

    /// Get a specific table by name
    async fn table(&self, ctx: &Context<'_>, database: String, name: String) -> Result<Option<Table>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Look up table by database and name
        let table_key = format!("db:{}:table:{}", database, name);
        
        if let Some(data) = storage.get(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Table retrieval failed: {}", e)))? {
            
            if let Ok(table_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let Some(created_at) = table_info.get("created_at").and_then(|v| v.as_str()) {
                    let default_id = Uuid::new_v4().to_string();
                    let table = Table {
                        id: table_info.get("id").and_then(|v| v.as_str())
                            .unwrap_or(&default_id)
                            .parse().unwrap_or_else(|_| Uuid::new_v4()).to_string(),
                        name: name.clone(),
                        database: database.clone(),
                        description: table_info.get("description").and_then(|v| v.as_str()).map(String::from),
                        // Parse fields from table_info
                        fields: if let Some(fields_array) = table_info.get("fields").and_then(|v| v.as_array()) {
                            fields_array.iter().filter_map(|field| {
                                if let (Some(name), Some(field_type_str)) = (
                                    field.get("name").and_then(|v| v.as_str()),
                                    field.get("field_type").and_then(|v| v.as_str())
                                ) {
                                    let field_type = match field_type_str {
                                        "Text" => crate::graphql::types::FieldType::Text,
                                        "Integer" => crate::graphql::types::FieldType::Integer,
                                        "Float" => crate::graphql::types::FieldType::Float,
                                        "Boolean" => crate::graphql::types::FieldType::Boolean,
                                        "DateTime" => crate::graphql::types::FieldType::DateTime,
                                        "Date" => crate::graphql::types::FieldType::DateTime,
                                        "Json" => crate::graphql::types::FieldType::Json,
                                        "Binary" => crate::graphql::types::FieldType::Binary,
                                        _ => crate::graphql::types::FieldType::Text,
                                    };
                                    Some(crate::graphql::types::Field {
                                        name: name.to_string(),
                                        field_type,
                                        required: field.get("required").and_then(|v| v.as_bool()).unwrap_or(false),
                                        description: field.get("description").and_then(|v| v.as_str()).map(String::from),
                                        default_value: field.get("default_value").and_then(|v| v.as_str()).map(String::from),
                                        encryption_algorithm: field.get("encryption_algorithm").and_then(|v| v.as_str()).and_then(|alg| match alg {
                                            "Aegis256" => Some(crate::graphql::types::EncryptionAlgorithm::Aegis256),
                                            "ChaCha20Poly1305" => Some(crate::graphql::types::EncryptionAlgorithm::ChaCha20Poly1305),
                                            "Aes256Gcm" => Some(crate::graphql::types::EncryptionAlgorithm::Aes256Gcm),
                                            "Rsa2048" => Some(crate::graphql::types::EncryptionAlgorithm::Rsa2048),
                                            "Rsa4096" => Some(crate::graphql::types::EncryptionAlgorithm::Rsa4096),
                                            "EcdsaP256" => Some(crate::graphql::types::EncryptionAlgorithm::EcdsaP256),
                                            "EcdsaP384" => Some(crate::graphql::types::EncryptionAlgorithm::EcdsaP384),
                                            _ => None,
                                        }),
                                        encrypted: field.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false),
                                    })
                                } else {
                                    None
                                }
                            }).collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        },
                        // Parse primary_key from table_info
                        primary_key: if let Some(pk_array) = table_info.get("primary_key").and_then(|v| v.as_array()) {
                            pk_array.iter().filter_map(|pk| pk.as_str().map(String::from)).collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        },
                        created_at: created_at.parse().unwrap_or_else(|_| Utc::now()),
                        updated_at: table_info.get("updated_at").and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now()),
                        record_count: table_info.get("record_count").and_then(|v| v.as_u64()).unwrap_or(0) as i32,
                        encryption_enabled: table_info.get("encryption_enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                    };
                    return Ok(Some(table));
                }
            }
        }
        
        Ok(None)
    }

    // ==================== Data Queries ====================

    /// Query data from a table
    async fn query_data(&self, ctx: &Context<'_>, input: QueryDataInput) -> Result<QueryResult> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Query data records for the table
        let data_prefix = format!("db:{}:table:{}:record:", input.database, input.table);
        let record_keys = storage.list_prefix(&data_prefix).await
            .map_err(|e| async_graphql::Error::new(format!("Data query failed: {}", e)))?;
        
        let mut records = Vec::new();
        
        for key in record_keys {
            if let Some(data) = storage.get(&key).await
                .map_err(|e| async_graphql::Error::new(format!("Record retrieval failed: {}", e)))? {
                
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
        
        // Apply pagination
        let page = input.pagination.as_ref().and_then(|p| p.page).unwrap_or(0) as usize;
        let page_size = input.pagination.as_ref().and_then(|p| p.page_size).unwrap_or(10) as usize;
        let start_idx = page * page_size;
        let end_idx = std::cmp::min(start_idx + page_size, records.len());
        
        let paginated_records = if start_idx < records.len() {
            records[start_idx..end_idx].to_vec()
        } else {
            Vec::new()
        };
        
        let pagination_info = PaginationInfo {
            page: page as i32,
            page_size: page_size as i32,
            total_pages: ((records.len() as i32 + page_size as i32 - 1) / page_size as i32) as i32,
            total_records: records.len() as i32,
            has_next: end_idx < records.len(),
            has_previous: page > 0,
        };
        
        Ok(QueryResult {
            records: paginated_records,
            total_count: records.len() as i32,
            has_more: end_idx < records.len(),
            pagination: Some(pagination_info),
        })
    }

    /// Get a specific record by ID
    async fn get_record(&self, ctx: &Context<'_>, database: String, table: String, id: String) -> Result<Option<DataRecord>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Look up specific record
        let record_key = format!("db:{}:table:{}:record:{}", database, table, id);
        
        if let Some(data) = storage.get(&record_key).await
            .map_err(|e| async_graphql::Error::new(format!("Record details retrieval failed: {}", e)))? {
            
            if let Ok(record_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let (Some(record_id), Some(record_data), Some(created_at)) = (
                    record_info.get("id").and_then(|v| v.as_str()),
                    record_info.get("data"),
                    record_info.get("created_at").and_then(|v| v.as_str())
                ) {
                    let record = DataRecord {
                        id: record_id.to_string(),
                        data: async_graphql::Json(record_data.clone()),
                        created_at: created_at.parse().unwrap_or_else(|_| Utc::now()),
                        updated_at: record_info.get("updated_at").and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now()),
                        encryption_metadata: None,
                    };
                    return Ok(Some(record));
                }
            }
        }
        
        Ok(None)
    }

    // ==================== Encryption Queries ====================

    /// Get encryption metadata for a table
    async fn encryption_metadata(&self, ctx: &Context<'_>, database: String, table: String) -> Result<Vec<EncryptionMetadata>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Look up table encryption metadata
        let metadata_key = format!("db:{}:table:{}:encryption", database, table);
        
        if let Some(data) = storage.get(&metadata_key).await
            .map_err(|e| async_graphql::Error::new(format!("Encryption metadata retrieval failed: {}", e)))? {
            
            if let Ok(metadata_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let Some(fields) = metadata_info.get("fields").and_then(|v| v.as_array()) {
                    let mut encryption_metadata = Vec::new();
                    
                    for field in fields {
                        if let Some(field_name) = field.get("field_name").and_then(|v| v.as_str()) {
                            let metadata = EncryptionMetadata {
                                field_name: field_name.to_string(),
                                algorithm: field.get("algorithm").and_then(|v| v.as_str())
                                    .map(|s| match s {
                                        "AEGIS256" => EncryptionAlgorithm::Aegis256,
                                        "AES256GCM" => EncryptionAlgorithm::Aes256Gcm,
                                        "CHACHA20POLY1305" => EncryptionAlgorithm::ChaCha20Poly1305,
                                        _ => EncryptionAlgorithm::Aegis256,
                                    }).unwrap_or(EncryptionAlgorithm::Aegis256),
                                key_id: field.get("key_id").and_then(|v| v.as_str()).map(String::from).unwrap_or_default(),
                                key_version: field.get("key_version").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                                encrypted_at: field.get("encrypted_at").and_then(|v| v.as_str())
                                    .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now()),
                            };
                            encryption_metadata.push(metadata);
                        }
                    }
                    
                    return Ok(encryption_metadata);
                }
            }
        }
        
        Ok(Vec::new())
    }

    /// Get key rotation status
    async fn key_rotation_status(&self, ctx: &Context<'_>, database: String, table: String, rotation_id: String) -> Result<Option<KeyRotationStatus>> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Look up key rotation status
        let rotation_key = format!("db:{}:table:{}:rotation:{}", database, table, rotation_id);
        
        if let Some(data) = storage.get(&rotation_key).await
            .map_err(|e| async_graphql::Error::new(format!("Rotation status retrieval failed: {}", e)))? {
            
            if let Ok(rotation_info) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let Some(status) = rotation_info.get("status").and_then(|v| v.as_str()) {
                    let rotation_status = KeyRotationStatus {
                        id: rotation_id,
                        status: status.to_string(),
                        progress_percentage: rotation_info.get("progress_percentage").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        started_at: rotation_info.get("started_at").and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok()),
                        completed_at: rotation_info.get("completed_at").and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok()),
                        error_message: rotation_info.get("error_message").and_then(|v| v.as_str()).map(String::from),
                        records_processed: rotation_info.get("records_processed").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                        total_records: rotation_info.get("total_records").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                    };
                    return Ok(Some(rotation_status));
                }
            }
        }
        
        Ok(None)
    }

    // ==================== System Queries ====================

    /// Get system health status
    async fn health(&self, ctx: &Context<'_>) -> Result<HealthStatus> {
        let graphql_ctx = from_context(ctx)?;
        let storage = &graphql_ctx.app_state.storage;
        
        // Check storage health
        let storage_healthy = storage.health_check().await.is_ok();
        
        let mut services = HashMap::new();
        services.insert("database".to_string(), ServiceHealth {
            name: "database".to_string(),
            healthy: storage_healthy,
            response_time_ms: if storage_healthy { 5 } else { 1000 },
            details: HashMap::new(),
        });
        services.insert("encryption".to_string(), ServiceHealth {
            name: "encryption".to_string(),
            healthy: true, // Key manager is always healthy if initialized
            response_time_ms: 1,
            details: HashMap::new(),
        });
        services.insert("api".to_string(), ServiceHealth {
            name: "api".to_string(),
            healthy: true,
            response_time_ms: 2,
            details: HashMap::new(),
        });
        
        Ok(HealthStatus {
            healthy: storage_healthy,
            services,
            last_check: Utc::now(),
        })
    }

    /// Get API version information
    async fn version(&self, _ctx: &Context<'_>) -> Result<String> {
        Ok(crate::VERSION.to_string())
    }

    /// Get authenticated user information
    async fn me(&self, ctx: &Context<'_>) -> Result<Option<AuthenticatedUser>> {
        let graphql_ctx = from_context(ctx)?;
        Ok(graphql_ctx.user.clone())
    }

    // ==================== Dynamic Secrets Queries ====================

    /// Get dynamic secrets engine status
    async fn dynamic_secrets_status(&self, ctx: &Context<'_>) -> Result<DynamicSecretsStatus> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require at least user role
        graphql_ctx.require_role("user")?;

        let dynamic_secrets = &graphql_ctx.app_state.dynamic_secrets;
        let engine_status = dynamic_secrets.status().await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get dynamic secrets status: {}", e)))?;

        let supported_databases = vec![
            crate::graphql::types::DynamicDatabaseType::Postgresql,
            crate::graphql::types::DynamicDatabaseType::Mysql,
            crate::graphql::types::DynamicDatabaseType::Sqlserver,
        ];

        Ok(DynamicSecretsStatus {
            name: engine_status.name,
            initialized: engine_status.initialized,
            total_secrets: engine_status.stats.total_secrets,
            active_leases: engine_status.stats.active_leases,
            aws_configured: engine_status.config.get("aws").is_some(),
            supported_databases,
            default_ttl: engine_status.config.get("default_ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600),
            max_ttl: engine_status.config.get("max_ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(86400),
            auto_cleanup: engine_status.config.get("auto_cleanup")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
        })
    }

    /// List dynamic credentials
    async fn list_dynamic_credentials(&self, ctx: &Context<'_>, path: Option<String>) -> Result<Vec<String>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require at least user role
        graphql_ctx.require_role("user")?;

        let dynamic_secrets = &graphql_ctx.app_state.dynamic_secrets;
        let search_path = path.unwrap_or_else(|| "".to_string());
        
        dynamic_secrets.list(&search_path).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to list dynamic credentials: {}", e)))
    }

    /// Get a specific dynamic credential
    // TODO: This function is broken - DynamicSecretsEngine doesn't have a read method
    // Need to implement proper credential retrieval or use SecretsKvEngine for static secrets
    async fn get_dynamic_credential(&self, _ctx: &Context<'_>, _lease_id: String) -> Result<Option<SecretData>> {
        Err(async_graphql::Error::new("Dynamic credential retrieval not implemented - DynamicSecretsEngine doesn't have a read method"))
    }
}
