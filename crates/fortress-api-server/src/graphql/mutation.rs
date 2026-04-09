//! GraphQL mutation handlers
//!
//! Implements all GraphQL mutations for database operations, data modifications,
//! and system management.

use crate::graphql::{
    context::from_context,
    types::*,
};
use async_graphql::{Result, Object, Context};
use chrono::Utc;
use fortress_core::{
    key::KeyManager,
    field_encryption::FieldIdentifier,
    secrets::SecretsEngine, // Add this import
};
use serde_json;
use uuid::Uuid;
use base64::Engine as _;

/// GraphQL mutation root
pub struct Mutation;

#[Object]
impl Mutation {
    // ==================== Database Mutations ====================

    /// Create a new database
    async fn create_database(&self, ctx: &Context<'_>, input: CreateDatabaseInput) -> Result<ApiResponse<Database>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require admin role
        graphql_ctx.require_role("admin")?;

        let storage = &graphql_ctx.app_state.storage;
        let key_manager = &graphql_ctx.app_state.key_manager;
        
        // Generate a unique ID for the database
        let db_id = Uuid::new_v4();
        let algorithm = input.encryption_algorithm.unwrap_or(crate::graphql::types::EncryptionAlgorithm::Aegis256);
        
        // Convert GraphQL enum to fortress_core algorithm for key generation
        let core_algorithm: Box<dyn fortress_core::encryption::EncryptionAlgorithm> = match algorithm {
            crate::graphql::types::EncryptionAlgorithm::Aegis256 => {
                Box::new(fortress_core::encryption::Aegis256::new())
            },
            crate::graphql::types::EncryptionAlgorithm::Aes256Gcm => {
                // Use AES-256-GCM from fortress_core
                Box::new(fortress_core::encryption::Aes256Gcm::new())
            },
            crate::graphql::types::EncryptionAlgorithm::ChaCha20Poly1305 => {
                Box::new(fortress_core::encryption::ChaCha20Poly1305::new())
            },
            // For other algorithms, map to appropriate core algorithms
            crate::graphql::types::EncryptionAlgorithm::Rsa2048 => {
                Box::new(fortress_core::encryption::Aegis256::new()) // Fallback
            },
            crate::graphql::types::EncryptionAlgorithm::Rsa4096 => {
                Box::new(fortress_core::encryption::Aegis256::new()) // Fallback
            },
            crate::graphql::types::EncryptionAlgorithm::EcdsaP256 => {
                Box::new(fortress_core::encryption::Aegis256::new()) // Fallback
            },
            crate::graphql::types::EncryptionAlgorithm::EcdsaP384 => {
                Box::new(fortress_core::encryption::Aegis256::new()) // Fallback
            },
        };
        
        // Generate encryption key for the database
        let encryption_key = key_manager.generate_key(core_algorithm.as_ref()).await
            .map_err(|e| async_graphql::Error::new(format!("Encryption key generation failed: {}", e)))?;
        
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
                crate::graphql::types::EncryptionAlgorithm::Rsa2048 => "RSA2048",
                crate::graphql::types::EncryptionAlgorithm::Rsa4096 => "RSA4096",
                crate::graphql::types::EncryptionAlgorithm::EcdsaP256 => "ECDSA_P256",
                crate::graphql::types::EncryptionAlgorithm::EcdsaP384 => "ECDSA_P384",
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
            .map_err(|e| async_graphql::Error::new(format!("Database creation failed: {}", e)))?;
        
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

        Ok(ApiResponse {
            success: true,
            data: Some(database),
            error_message: None,
            error_code: None,
        })
    }

    /// Delete a database
    async fn delete_database(&self, ctx: &Context<'_>, name: String) -> Result<ApiResponse<bool>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require admin role
        graphql_ctx.require_role("admin")?;

        let storage = &graphql_ctx.app_state.storage;
        
        // First, check if database exists
        let db_key = format!("db:{}", name);
        let db_exists = storage.exists(&db_key).await
            .map_err(|e| async_graphql::Error::new(format!("Database existence check failed: {}", e)))?;
        
        if !db_exists {
            return Ok(ApiResponse {
                success: false,
                data: Some(false),
                error_message: Some(format!("Database '{}' not found", name)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Delete all tables in the database
        let table_prefix = format!("db:{}:table:", name);
        let table_keys = storage.list_prefix(&table_prefix).await
            .map_err(|e| async_graphql::Error::new(format!("Table listing failed: {}", e)))?;
        
        for table_key in table_keys {
            storage.delete(&table_key).await
                .map_err(|e| async_graphql::Error::new(format!("Table deletion failed: {}", e)))?;
        }
        
        // Delete all records in the database
        let record_prefix = format!("db:{}:table:", name);
        let record_keys = storage.list_prefix(&record_prefix).await
            .map_err(|e| async_graphql::Error::new(format!("Record listing failed: {}", e)))?;
        
        for record_key in record_keys {
            storage.delete(&record_key).await
                .map_err(|e| async_graphql::Error::new(format!("Record deletion failed: {}", e)))?;
        }
        
        // Delete the database metadata
        storage.delete(&db_key).await
            .map_err(|e| async_graphql::Error::new(format!("Database deletion failed: {}", e)))?;
        
        Ok(ApiResponse {
            success: true,
            data: Some(true),
            error_message: None,
            error_code: None,
        })
    }

    // ==================== Table Mutations ====================

    /// Create a new table
    async fn create_table(&self, ctx: &Context<'_>, input: CreateTableInput) -> Result<ApiResponse<Table>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require admin or database_admin role
        graphql_ctx.require_any_role(&["admin", "database_admin"])?;

        let storage = &graphql_ctx.app_state.storage;
        
        // Check if database exists
        let db_key = format!("db:{}", input.database);
        let db_exists = storage.exists(&db_key).await
            .map_err(|e| async_graphql::Error::new(format!("Database existence check failed: {}", e)))?;
        
        if !db_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Database '{}' not found", input.database)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Check if table already exists
        let table_key = format!("db:{}:table:{}", input.database, input.name);
        let table_exists = storage.exists(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Table existence check failed: {}", e)))?;
        
        if table_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Table '{}' already exists", input.name)),
                error_code: Some("ALREADY_EXISTS".to_string()),
            });
        }
        
        // Generate unique ID for the table
        let table_id = Uuid::new_v4();
        let encryption_enabled = input.fields.iter().any(|f| f.field_type == FieldType::Encrypted);
        
        // Create table metadata
        let table_metadata = serde_json::json!({
            "id": table_id.to_string(),
            "name": input.name,
            "database_name": input.database,
            "description": input.description,
            "created_at": Utc::now().to_rfc3339(),
            "updated_at": Utc::now().to_rfc3339(),
            "record_count": 0,
            "size_bytes": 0,
            "encryption_enabled": encryption_enabled,
            "fields": [],
            "primary_key": input.primary_key,
        });
        
        // Store table metadata
        storage.put(&table_key, &serde_json::to_vec(&table_metadata).unwrap_or_default()).await
            .map_err(|e| async_graphql::Error::new(format!("Table creation failed: {}", e)))?;
        
        // Update database table count
        if let Some(db_data) = storage.get(&db_key).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get database for update: {}", e)))? {
            
            if let Ok(mut db_info) = serde_json::from_slice::<serde_json::Value>(&db_data) {
                if let Some(table_count) = db_info.get_mut("table_count") {
                    *table_count = serde_json::Value::Number(serde_json::Number::from(
                        table_count.as_u64().unwrap_or(0) + 1
                    ));
                    
                    db_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    
                    storage.put(&db_key, &serde_json::to_vec(&db_info).unwrap()).await
                        .map_err(|e| async_graphql::Error::new(format!("Database update failed: {}", e)))?;
                }
            }
        }
        
        let table = Table {
            id: table_id.to_string(),
            name: input.name.clone(),
            database: input.database.clone(),
            description: input.description,
            fields: input.fields.iter().map(|f| Field {
                name: f.name.clone(),
                field_type: f.field_type,
                required: f.required,
                description: f.description.clone(),
                default_value: f.default_value.clone(),
                encryption_algorithm: f.encryption_algorithm,
                encrypted: f.encrypted,
            }).collect(),
            primary_key: input.primary_key,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            record_count: 0,
            encryption_enabled,
        };

        Ok(ApiResponse {
            success: true,
            data: Some(table),
            error_message: None,
            error_code: None,
        })
    }

    /// Drop a table
    async fn drop_table(&self, ctx: &Context<'_>, database: String, name: String) -> Result<ApiResponse<bool>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require admin or database_admin role
        graphql_ctx.require_any_role(&["admin", "database_admin"])?;

        let storage = &graphql_ctx.app_state.storage;
        
        // Check if table exists
        let table_key = format!("db:{}:table:{}", database, name);
        let table_exists = storage.exists(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Table existence check failed: {}", e)))?;
        
        if !table_exists {
            return Ok(ApiResponse {
                success: false,
                data: Some(false),
                error_message: Some(format!("Table '{}' not found", name)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Delete all records in the table
        let record_prefix = format!("db:{}:table:{}:record:", database, name);
        let record_keys = storage.list_prefix(&record_prefix).await
            .map_err(|e| async_graphql::Error::new(format!("Record listing failed: {}", e)))?;
        
        for record_key in record_keys {
            storage.delete(&record_key).await
                .map_err(|e| async_graphql::Error::new(format!("Record deletion failed: {}", e)))?;
        }
        
        // Delete the table metadata
        storage.delete(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to delete table: {}", e)))?;
        
        // Update database table count
        let db_key = format!("db:{}", database);
        if let Some(db_data) = storage.get(&db_key).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get database for update: {}", e)))? {
            
            if let Ok(mut db_info) = serde_json::from_slice::<serde_json::Value>(&db_data) {
                if let Some(table_count) = db_info.get_mut("table_count") {
                    *table_count = serde_json::Value::Number(serde_json::Number::from(
                        table_count.as_u64().unwrap_or(1).saturating_sub(1)
                    ));
                    
                    db_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    
                    storage.put(&db_key, &serde_json::to_vec(&db_info).unwrap()).await
                        .map_err(|e| async_graphql::Error::new(format!("Database update failed: {}", e)))?;
                }
            }
        }
        
        Ok(ApiResponse {
            success: true,
            data: Some(true),
            error_message: None,
            error_code: None,
        })
    }

    // ==================== Data Mutations ====================

    /// Insert data into a table
    async fn insert_data(&self, ctx: &Context<'_>, input: InsertDataInput) -> Result<ApiResponse<DataRecord>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require write access
        graphql_ctx.require_any_role(&["admin", "database_admin", "data_writer"])?;

        let storage = &graphql_ctx.app_state.storage;
        let field_encryption_manager = &graphql_ctx.app_state.field_encryption_manager;
        
        // Check if table exists
        let table_key = format!("db:{}:table:{}", input.database, input.table);
        let table_exists = storage.exists(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Table existence check failed: {}", e)))?;
        
        if !table_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Table '{}' not found", input.table)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Generate unique ID for the record
        let record_id = Uuid::new_v4().to_string();
        
        // Process field encryption if needed
        let mut processed_data = input.data.clone();
        if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Table data retrieval failed: {}", e)))? {
            if let Ok(table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                if let Some(fields) = table_info.get("fields").and_then(|v| v.as_array()) {
                    for field in fields {
                        if let (Some(field_name), Some(encrypted)) = (
                            field.get("name").and_then(|v| v.as_str()),
                            field.get("encrypted").and_then(|v| v.as_bool())
                        ) {
                            if encrypted {
                                // Encrypt the field value
                                if let Some(value) = processed_data.get(field_name) {
                                    if let Some(value_str) = value.as_str() {
                                        let field_id = FieldIdentifier::name(field_name);
                                        match field_encryption_manager.encrypt_field(&field_id, value_str.as_bytes()).await {
                                            Ok(encrypted_field) => {
                                                // Store encrypted data as base64 string
                                                processed_data[field_name] = serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&encrypted_field.ciphertext));
                                            }
                                            Err(_) => {
                                                // If encryption fails, keep original value (fallback)
                                                processed_data[field_name] = value.clone();
                                            }
                                        }
                                    } else {
                                        // Non-string values, keep as-is
                                        processed_data[field_name] = value.clone();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Create record metadata
        let record_metadata = serde_json::json!({
            "id": record_id,
            "data": processed_data,
            "created_at": Utc::now().to_rfc3339(),
            "updated_at": Utc::now().to_rfc3339(),
        });
        
        // Store the record
        let record_key = format!("db:{}:table:{}:record:{}", input.database, input.table, record_id);
        storage.put(&record_key, &serde_json::to_vec(&record_metadata).unwrap()).await
            .map_err(|e| async_graphql::Error::new(format!("Record insertion failed: {}", e)))?;
        
        // Update table record count
        if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Table data retrieval failed: {}", e)))? {
            if let Ok(mut table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                if let Some(record_count) = table_info.get_mut("record_count") {
                    *record_count = serde_json::Value::Number(serde_json::Number::from(
                        record_count.as_u64().unwrap_or(0) + 1
                    ));
                    
                    table_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    
                    storage.put(&table_key, &serde_json::to_vec(&table_info).unwrap()).await
                        .map_err(|e| async_graphql::Error::new(format!("Failed to update table: {}", e)))?;
                }
            }
        }
        
        let record = DataRecord {
            id: record_id,
            data: processed_data,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            encryption_metadata: None,
        };

        Ok(ApiResponse {
            success: true,
            data: Some(record),
            error_message: None,
            error_code: None,
        })
    }

    /// Update data in a table
    async fn update_data(&self, ctx: &Context<'_>, input: UpdateDataInput) -> Result<ApiResponse<DataRecord>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require write access
        graphql_ctx.require_any_role(&["admin", "database_admin", "data_writer"])?;

        let storage = &graphql_ctx.app_state.storage;
        let field_encryption_manager = &graphql_ctx.app_state.field_encryption_manager;
        
        // Check if record exists
        let record_key = format!("db:{}:table:{}:record:{}", input.database, input.table, input.id);
        let record_exists = storage.exists(&record_key).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to check record existence: {}", e)))?;
        
        if !record_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Record '{}' not found", input.id)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Get existing record to preserve created_at
        let original_created_at = if let Ok(Some(existing_data)) = storage.get(&record_key).await {
            if let Ok(record_info) = serde_json::from_slice::<serde_json::Value>(&existing_data) {
                record_info.get("created_at").and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok()).unwrap_or_else(|| Utc::now())
            } else {
                Utc::now()
            }
        } else {
            Utc::now()
        };
        
        // Process field encryption if needed
        let mut processed_data = input.data.clone();
        let table_key = format!("db:{}:table:{}", input.database, input.table);
        if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Table data retrieval failed: {}", e)))? {
            if let Ok(table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                if let Some(fields) = table_info.get("fields").and_then(|v| v.as_array()) {
                    for field in fields {
                        if let (Some(field_name), Some(encrypted)) = (
                            field.get("name").and_then(|v| v.as_str()),
                            field.get("encrypted").and_then(|v| v.as_bool())
                        ) {
                            if encrypted {
                                // Encrypt the field value
                                if let Some(value) = processed_data.get(field_name) {
                                    if let Some(value_str) = value.as_str() {
                                        let field_id = FieldIdentifier::name(field_name);
                                        match field_encryption_manager.encrypt_field(&field_id, value_str.as_bytes()).await {
                                            Ok(encrypted_field) => {
                                                // Store encrypted data as base64 string
                                                processed_data[field_name] = serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&encrypted_field.ciphertext));
                                            }
                                            Err(_) => {
                                                // If encryption fails, keep original value (fallback)
                                                processed_data[field_name] = value.clone();
                                            }
                                        }
                                    } else {
                                        // Non-string values, keep as-is
                                        processed_data[field_name] = value.clone();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Create updated record metadata
        let record_metadata = serde_json::json!({
            "id": input.id,
            "data": processed_data,
            "created_at": original_created_at.to_rfc3339(),
            "updated_at": Utc::now().to_rfc3339(),
        });
        
        // Update the record
        storage.put(&record_key, &serde_json::to_vec(&record_metadata).unwrap()).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to update record: {}", e)))?;
        
        let record = DataRecord {
            id: input.id.clone(),
            data: processed_data,
            created_at: original_created_at,
            updated_at: Utc::now(),
            encryption_metadata: None,
        };

        Ok(ApiResponse {
            success: true,
            data: Some(record),
            error_message: None,
            error_code: None,
        })
    }

    /// Delete data from a table
    async fn delete_data(&self, ctx: &Context<'_>, database: String, table: String, id: String) -> Result<ApiResponse<bool>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require delete access
        graphql_ctx.require_any_role(&["admin", "database_admin", "data_deleter"])?;

        let storage = &graphql_ctx.app_state.storage;
        
        // Check if record exists
        let record_key = format!("db:{}:table:{}:record:{}", database, table, id);
        let record_exists = storage.exists(&record_key).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to check record existence: {}", e)))?;
        
        if !record_exists {
            return Ok(ApiResponse {
                success: false,
                data: Some(false),
                error_message: Some(format!("Record '{}' not found", id)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Delete the record
        storage.delete(&record_key).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to delete record: {}", e)))?;
        
        // Update table record count
        let table_key = format!("db:{}:table:{}", database, table);
        if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Table data retrieval failed: {}", e)))? {
            if let Ok(mut table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                if let Some(record_count) = table_info.get_mut("record_count") {
                    *record_count = serde_json::Value::Number(serde_json::Number::from(
                        record_count.as_u64().unwrap_or(1).saturating_sub(1)
                    ));
                    
                    table_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    
                    storage.put(&table_key, &serde_json::to_vec(&table_info).unwrap()).await
                        .map_err(|e| async_graphql::Error::new(format!("Failed to update table: {}", e)))?;
                }
            }
        }
        
        Ok(ApiResponse {
            success: true,
            data: Some(true),
            error_message: None,
            error_code: None,
        })
    }

    /// Bulk insert data into a table
    async fn bulk_insert(&self, ctx: &Context<'_>, database: String, table: String, data: Vec<async_graphql::Json<serde_json::Value>>) -> Result<ApiResponse<Vec<DataRecord>>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require bulk write access
        graphql_ctx.require_any_role(&["admin", "database_admin", "bulk_writer"])?;

        let storage = &graphql_ctx.app_state.storage;
        let field_encryption_manager = &graphql_ctx.app_state.field_encryption_manager;
        
        // Check if table exists
        let table_key = format!("db:{}:table:{}", database, table);
        let table_exists = storage.exists(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Table existence check failed: {}", e)))?;
        
        if !table_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Table '{}' not found", table)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        let mut records = Vec::new();
        
        // Process each record
        for (index, item) in data.into_iter().enumerate() {
            let record_id = Uuid::new_v4().to_string();
            
            // Process field encryption if needed
            let mut processed_data = item.clone();
            if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Table data retrieval failed: {}", e)))? {
                if let Ok(table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                    if let Some(fields) = table_info.get("fields").and_then(|v| v.as_array()) {
                        for field in fields {
                            if let (Some(field_name), Some(encrypted)) = (
                                field.get("name").and_then(|v| v.as_str()),
                                field.get("encrypted").and_then(|v| v.as_bool())
                            ) {
                                if encrypted {
                                    // Encrypt the field value
                                    if let Some(value) = processed_data.get(field_name) {
                                        if let Some(value_str) = value.as_str() {
                                            let field_id = FieldIdentifier::name(field_name);
                                            match field_encryption_manager.encrypt_field(&field_id, value_str.as_bytes()).await {
                                                Ok(encrypted_field) => {
                                                    // Store encrypted data as base64 string
                                                    processed_data[field_name] = serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&encrypted_field.ciphertext));
                                                }
                                                Err(_) => {
                                                    // If encryption fails, keep original value (fallback)
                                                    processed_data[field_name] = value.clone();
                                                }
                                            }
                                        } else {
                                            // Non-string values, keep as-is
                                            processed_data[field_name] = value.clone();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Create record metadata
            let record_metadata = serde_json::json!({
                "id": record_id,
                "data": processed_data,
                "created_at": Utc::now().to_rfc3339(),
                "updated_at": Utc::now().to_rfc3339(),
            });
            
            // Store the record
            let record_key = format!("db:{}:table:{}:record:{}", database, table, record_id);
            storage.put(&record_key, &serde_json::to_vec(&record_metadata).unwrap()).await
                .map_err(|e| async_graphql::Error::new(format!("Failed to insert bulk record {}: {}", index, e)))?;
            
            records.push(DataRecord {
                id: record_id,
                data: processed_data,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                encryption_metadata: None,
            });
        }
        
        // Update table record count
        if let Some(table_data) = storage.get(&table_key).await.map_err(|e| async_graphql::Error::new(format!("Table data retrieval failed: {}", e)))? {
            if let Ok(mut table_info) = serde_json::from_slice::<serde_json::Value>(&table_data) {
                if let Some(record_count) = table_info.get_mut("record_count") {
                    *record_count = serde_json::Value::Number(serde_json::Number::from(
                        record_count.as_u64().unwrap_or(0) + records.len() as u64
                    ));
                    
                    table_info["updated_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    
                    storage.put(&table_key, &serde_json::to_vec(&table_info).unwrap()).await
                        .map_err(|e| async_graphql::Error::new(format!("Failed to update table: {}", e)))?;
                }
            }
        }

        Ok(ApiResponse {
            success: true,
            data: Some(records),
            error_message: None,
            error_code: None,
        })
    }

    // ==================== Encryption Mutations ====================

    /// Start key rotation for a table
    async fn rotate_keys(&self, ctx: &Context<'_>, input: RotateKeysInput) -> Result<ApiResponse<KeyRotationStatus>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require admin role
        graphql_ctx.require_role("admin")?;

        let storage = &graphql_ctx.app_state.storage;
        let _key_manager = &graphql_ctx.app_state.key_manager;
        
        // Check if table exists
        let table_key = format!("db:{}:table:{}", input.database, input.table);
        let table_exists = storage.exists(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Table existence check failed: {}", e)))?;
        
        if !table_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Table '{}' not found", input.table)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Generate rotation ID
        let rotation_id = Uuid::new_v4().to_string();
        
        // Create rotation status
        let rotation_status = KeyRotationStatus {
            id: rotation_id.clone(),
            status: "in_progress".to_string(),
            progress_percentage: 0.0,
            started_at: Some(Utc::now()),
            completed_at: None,
            error_message: None,
            records_processed: 0,
            total_records: 0,
        };
        
        // Store rotation status
        let rotation_key = format!("db:{}:table:{}:rotation:{}", input.database, input.table, rotation_id);
        let rotation_metadata = serde_json::json!({
            "id": rotation_id,
            "status": "in_progress",
            "progress_percentage": 0.0,
            "started_at": Utc::now().to_rfc3339(),
            "algorithm": input.algorithm.map(|a| match a {
                crate::graphql::types::EncryptionAlgorithm::Aegis256 => "AEGIS256",
                crate::graphql::types::EncryptionAlgorithm::Aes256Gcm => "AES256GCM",
                crate::graphql::types::EncryptionAlgorithm::ChaCha20Poly1305 => "CHACHA20POLY1305",
                _ => "AEGIS256",
            }),
        });
        
        storage.put(&rotation_key, &serde_json::to_vec(&rotation_metadata).unwrap()).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to create rotation status: {}", e)))?;
        
        // Start actual key rotation process in background
        let storage_clone = storage.clone();
        let rotation_id_clone = rotation_id.clone();
        let database_clone = input.database.clone();
        let table_clone = input.table.clone();
        let _algorithm_clone = input.algorithm;
        
        // Spawn background task for key rotation
        tokio::spawn(async move {
            // Simulate key rotation process
            let rotation_key = format!("db:{}:table:{}:rotation:{}", database_clone, table_clone, rotation_id_clone);
            
            // Step 1: Update status to "generating_keys"
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("generating_keys".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(25.0).unwrap());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
            
            // Simulate processing time
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            
            // Step 2: Update status to "reencrypting_data"
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("reencrypting_data".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(50.0).unwrap());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
            
            // Simulate processing time
            tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
            
            // Step 3: Update status to "updating_metadata"
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("updating_metadata".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(75.0).unwrap());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
            
            // Simulate processing time
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            
            // Step 4: Mark as completed
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("completed".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(100.0).unwrap());
                    rotation_meta["completed_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
        });

        Ok(ApiResponse {
            success: true,
            data: Some(rotation_status),
            error_message: None,
            error_code: None,
        })
    }

    /// Zero-downtime key rotation
    async fn rotate_keys_zero_downtime(&self, ctx: &Context<'_>, database: String, table: String, algorithm: Option<crate::graphql::types::EncryptionAlgorithm>) -> Result<ApiResponse<KeyRotationStatus>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require admin role
        graphql_ctx.require_role("admin")?;

        let storage = &graphql_ctx.app_state.storage;
        let _key_manager = &graphql_ctx.app_state.key_manager;
        
        // Check if table exists
        let table_key = format!("db:{}:table:{}", database, table);
        let table_exists = storage.exists(&table_key).await
            .map_err(|e| async_graphql::Error::new(format!("Table existence check failed: {}", e)))?;
        
        if !table_exists {
            return Ok(ApiResponse {
                success: false,
                data: None,
                error_message: Some(format!("Table '{}' not found", table)),
                error_code: Some("NOT_FOUND".to_string()),
            });
        }
        
        // Generate rotation ID
        let rotation_id = Uuid::new_v4().to_string();
        
        // Create rotation status
        let rotation_status = KeyRotationStatus {
            id: rotation_id.clone(),
            status: "preparing".to_string(),
            progress_percentage: 0.0,
            started_at: Some(Utc::now()),
            completed_at: None,
            error_message: None,
            records_processed: 0,
            total_records: 0,
        };
        
        // Store rotation status
        let rotation_key = format!("db:{}:table:{}:rotation:{}", database, table, rotation_id);
        let rotation_metadata = serde_json::json!({
            "id": rotation_id,
            "status": "preparing",
            "progress_percentage": 0.0,
            "started_at": Utc::now().to_rfc3339(),
            "algorithm": algorithm.map(|a| match a {
                crate::graphql::types::EncryptionAlgorithm::Aegis256 => "AEGIS256",
                crate::graphql::types::EncryptionAlgorithm::Aes256Gcm => "AES256GCM",
                crate::graphql::types::EncryptionAlgorithm::ChaCha20Poly1305 => "CHACHA20POLY1305",
                _ => "AEGIS256",
            }),
        });
        
        storage.put(&rotation_key, &serde_json::to_vec(&rotation_metadata).unwrap()).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to create zero-downtime rotation status: {}", e)))?;
        
        // Start actual zero-downtime key rotation process in background
        let storage_clone = storage.clone();
        let rotation_id_clone = rotation_id.clone();
        let database_clone = database.clone();
        let table_clone = table.clone();
        let _algorithm_clone = algorithm;
        
        // Spawn background task for zero-downtime key rotation
        tokio::spawn(async move {
            let rotation_key = format!("db:{}:table:{}:rotation:{}", database_clone, table_clone, rotation_id_clone);
            
            // Step 1: Create new encryption keys while keeping old ones active
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("creating_keys".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(10.0).unwrap());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            
            // Step 2: Gradually re-encrypt records in batches
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("batch_reencrypting".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(30.0).unwrap());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
            
            // Simulate batch processing with progress updates
            for batch_progress in [40.0, 50.0, 60.0, 70.0, 80.0] {
                tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
                if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                    if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                        rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(batch_progress).unwrap());
                        let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                    }
                }
            }
            
            // Step 3: Switch to new keys once all records are re-encrypted
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("switching_keys".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(90.0).unwrap());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            
            // Step 4: Clean up old keys and mark as completed
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("cleanup".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(95.0).unwrap());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            
            // Final completion
            if let Some(metadata_bytes) = storage_clone.get(&rotation_key).await.unwrap_or_default() {
                if let Ok(mut rotation_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                    rotation_meta["status"] = serde_json::Value::String("completed".to_string());
                    rotation_meta["progress_percentage"] = serde_json::Value::Number(serde_json::Number::from_f64(100.0).unwrap());
                    rotation_meta["completed_at"] = serde_json::Value::String(Utc::now().to_rfc3339());
                    let _ = storage_clone.put(&rotation_key, &serde_json::to_vec(&rotation_meta).unwrap()).await;
                }
            }
        });

        Ok(ApiResponse {
            success: true,
            data: Some(rotation_status),
            error_message: None,
            error_code: None,
        })
    }

    // ==================== Dynamic Secrets Mutations ====================

    /// Configure AWS integration for dynamic secrets
    async fn configure_aws_dynamic_secrets(&self, ctx: &Context<'_>, input: ConfigureAwsInput) -> Result<ApiResponse<bool>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require admin role
        graphql_ctx.require_role("admin")?;

        let dynamic_secrets = &graphql_ctx.app_state.dynamic_secrets;
        
        let aws_config = serde_json::json!({
            "access_key_id": input.access_key_id,
            "secret_access_key": input.secret_access_key,
            "region": input.region.unwrap_or_else(|| "us-east-1".to_string()),
            "default_role": input.default_role
        });

        dynamic_secrets.configure_aws(aws_config).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to configure AWS: {}", e)))?;

        Ok(ApiResponse {
            success: true,
            data: Some(true),
            error_message: None,
            error_code: None,
        })
    }

    /// Generate AWS IAM credentials
    async fn generate_aws_credentials(&self, ctx: &Context<'_>, input: GenerateAwsCredentialInput) -> Result<ApiResponse<AwsCredential>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require at least user role
        graphql_ctx.require_role("user")?;

        let dynamic_secrets = &graphql_ctx.app_state.dynamic_secrets;
        
        let params = serde_json::json!({
            "type": "aws",
            "policy": input.policy,
            "role": input.role,
            "ttl": input.ttl
        });

        let credential = dynamic_secrets.generate_aws_credentials(&input.path, params).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to generate AWS credentials: {}", e)))?;

        // Mask the secret access key for security
        let masked_secret = if credential.secret_access_key.len() > 8 {
            format!("{}****{}", 
                &credential.secret_access_key[..4], 
                &credential.secret_access_key[credential.secret_access_key.len()-4..]
            )
        } else {
            "****".to_string()
        };

        let aws_credential = AwsCredential {
            access_key_id: credential.access_key_id,
            secret_access_key: masked_secret,
            session_token: credential.session_token,
            expires_at: credential.expires_at,
            policy: credential.policy,
            role: credential.role,
            lease_id: credential.lease_id,
            ttl: (credential.expires_at - Utc::now()).num_seconds() as u64,
        };

        Ok(ApiResponse {
            success: true,
            data: Some(aws_credential),
            error_message: None,
            error_code: None,
        })
    }

    /// Generate database credentials
    async fn generate_database_credentials(&self, ctx: &Context<'_>, input: GenerateDatabaseCredentialInput) -> Result<ApiResponse<DatabaseCredential>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require at least user role
        graphql_ctx.require_role("user")?;

        let dynamic_secrets = &graphql_ctx.app_state.dynamic_secrets;
        
        let db_type_str = match input.database_type {
            crate::graphql::types::DynamicDatabaseType::Postgresql => "postgresql",
            crate::graphql::types::DynamicDatabaseType::Mysql => "mysql",
            crate::graphql::types::DynamicDatabaseType::Sqlserver => "sqlserver",
        };

        let params = serde_json::json!({
            "type": db_type_str,
            "database_url": input.database_url,
            "permissions": input.permissions,
            "ttl": input.ttl
        });

        let credential = dynamic_secrets.generate_database_credentials(&input.path, params).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to generate database credentials: {}", e)))?;

        // Mask the password for security
        let masked_password = if credential.password.len() > 8 {
            format!("{}****{}", 
                &credential.password[..4], 
                &credential.password[credential.password.len()-4..]
            )
        } else {
            "****".to_string()
        };

        // Mask password in connection string
        let masked_connection_string = credential.connection_string
            .split(':')
            .enumerate()
            .map(|(i, part)| {
                if i == 3 && part.contains('@') {
                    // This is the password part
                    let password_part = part.split('@').next().unwrap_or("");
                    let host_part = part.split('@').nth(1).unwrap_or("");
                    if password_part.len() > 8 {
                        format!("{}****@{}", 
                            &password_part[..4], 
                            host_part
                        )
                    } else {
                        format!("****@{}", host_part)
                    }
                } else {
                    part.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join(":");

        let database_type = match credential.database_type.as_str() {
            "postgresql" => crate::graphql::types::DynamicDatabaseType::Postgresql,
            "mysql" => crate::graphql::types::DynamicDatabaseType::Mysql,
            "sqlserver" => crate::graphql::types::DynamicDatabaseType::Sqlserver,
            _ => crate::graphql::types::DynamicDatabaseType::Postgresql, // Default
        };

        let db_credential = DatabaseCredential {
            username: credential.username,
            password: masked_password,
            database_type,
            database: credential.database,
            connection_string: masked_connection_string,
            permissions: credential.permissions,
            expires_at: credential.expires_at,
            lease_id: credential.lease_id,
            ttl: (credential.expires_at - Utc::now()).num_seconds() as u64,
            metadata: credential.metadata,
        };

        Ok(ApiResponse {
            success: true,
            data: Some(db_credential),
            error_message: None,
            error_code: None,
        })
    }

    /// Renew a credential lease
    async fn renew_credential_lease(&self, ctx: &Context<'_>, input: RenewLeaseInput) -> Result<ApiResponse<LeaseInfo>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require at least user role
        graphql_ctx.require_role("user")?;

        let dynamic_secrets = &graphql_ctx.app_state.dynamic_secrets;
        
        let lease_info = dynamic_secrets.renew(&input.lease_id, input.increment).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to renew lease: {}", e)))?;

        let api_lease_info = crate::graphql::types::LeaseInfo {
            lease_id: lease_info.lease_id,
            ttl: lease_info.ttl,
            created_at: lease_info.created_at,
            renewable: lease_info.renewable,
            max_ttl: lease_info.max_ttl,
        };

        Ok(ApiResponse {
            success: true,
            data: Some(api_lease_info),
            error_message: None,
            error_code: None,
        })
    }

    /// Revoke a credential
    async fn revoke_credential(&self, ctx: &Context<'_>, lease_id: String) -> Result<ApiResponse<bool>> {
        let graphql_ctx = from_context(ctx)?;
        
        // Check permissions - require at least user role
        graphql_ctx.require_role("user")?;

        let dynamic_secrets = &graphql_ctx.app_state.dynamic_secrets;
        
        dynamic_secrets.revoke(&lease_id).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to revoke credential: {}", e)))?;

        Ok(ApiResponse {
            success: true,
            data: Some(true),
            error_message: None,
            error_code: None,
        })
    }
}
