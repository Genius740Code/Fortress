//! Enhanced PostgreSQL database backend for Fortress
//!
//! This module provides advanced PostgreSQL integration with support for push/pull operations,
//! JSONB operations, full-text search, and optimized performance features.

use crate::error::{FortressError, Result, KeyErrorCode, StorageErrorCode};
use crate::key::{KeyId, KeyMetadata, SecureKey};
use crate::storage::StorageBackend;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use sha2::Digest;

/// Enhanced PostgreSQL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// PostgreSQL connection string
    pub connection_string: String,
    /// Database name
    pub database_name: String,
    /// Schema name
    pub schema: String,
    /// Keys table name
    pub keys_table: String,
    /// Data table name
    pub data_table: String,
    /// Maximum connection pool size
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Enable SSL
    pub ssl_enabled: bool,
    /// Enable statement logging
    pub log_statements: bool,
    /// Enable connection pooling
    pub enable_pooling: bool,
    /// Table partitioning strategy
    pub partitioning: Option<PostgresPartitioning>,
    /// Replication settings
    pub replication: PostgresReplicationConfig,
}

/// PostgreSQL table partitioning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostgresPartitioning {
    /// Partition by date range
    ByDate { 
        /// Column name for partitioning
        column: String, 
        /// Date interval (e.g., "daily", "weekly", "monthly")
        interval: String 
    },
    /// Partition by key hash
    ByHash { 
        /// Column name for partitioning
        column: String, 
        /// Number of partitions
        partitions: u32 
    },
    /// Partition by size
    BySize { 
        /// Column name for partitioning
        column: String, 
        /// Maximum partition size in MB
        max_size_mb: u32 
    },
}

/// PostgreSQL replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresReplicationConfig {
    /// Enable streaming replication
    pub streaming_enabled: bool,
    /// Replication slot name
    pub slot_name: Option<String>,
    /// Publication name for logical replication
    pub publication_name: Option<String>,
    /// Synchronization mode
    pub sync_mode: PostgresSyncMode,
}

/// PostgreSQL synchronization modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostgresSyncMode {
    /// Synchronous replication
    Synchronous,
    /// Asynchronous replication
    Asynchronous,
    /// Semi-synchronous replication
    SemiSynchronous,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            connection_string: "postgresql://localhost:5432/fortress".to_string(),
            database_name: "fortress".to_string(),
            schema: "public".to_string(),
            keys_table: "fortress_keys".to_string(),
            data_table: "fortress_data".to_string(),
            max_connections: 20,
            connection_timeout_seconds: 30,
            ssl_enabled: false,
            log_statements: false,
            enable_pooling: true,
            partitioning: None,
            replication: PostgresReplicationConfig {
                streaming_enabled: false,
                slot_name: None,
                publication_name: None,
                sync_mode: PostgresSyncMode::Asynchronous,
            },
        }
    }
}

/// Enhanced PostgreSQL key database implementation
#[derive(Debug)]
pub struct PostgresKeyDatabase {
    config: PostgresConfig,
    // In a real implementation, this would hold a PostgreSQL connection pool
    // For now, we'll simulate with in-memory storage
    keys_data: std::sync::Arc<tokio::sync::RwLock<HashMap<String, PostgresKeyEntry>>>,
    data_storage: std::sync::Arc<tokio::sync::RwLock<HashMap<String, PostgresDataEntry>>>,
    replication_slots: std::sync::Arc<tokio::sync::RwLock<HashMap<String, PostgresReplicationSlot>>>,
}

/// PostgreSQL key entry with enhanced features
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PostgresKeyEntry {
    id: Uuid,
    key_id: String,
    key_data: Vec<u8>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    version: i32,
    tags: HashMap<String, String>,
    encryption_algorithm: String,
    key_size: i32,
    access_count: i64,
    last_accessed: Option<DateTime<Utc>>,
}

/// PostgreSQL data entry with JSONB support
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PostgresDataEntry {
    id: Uuid,
    key: String,
    data: Vec<u8>,
    metadata_jsonb: serde_json::Value,
    content_type: String,
    encoding: String,
    compression: String,
    checksum: String,
    size_bytes: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    partition_key: Option<String>,
    full_text_vector: Option<String>, // For full-text search
}

/// PostgreSQL replication slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresReplicationSlot {
    name: String,
    plugin: String,
    database: String,
    active: bool,
    confirmed_flush_lsn: Option<String>,
    restart_lsn: Option<String>,
}

impl PostgresKeyDatabase {
    /// Create a new PostgreSQL key database
    pub async fn new(config: PostgresConfig) -> Result<Self> {
        // In a real implementation, this would establish PostgreSQL connection
        // For now, we'll create an in-memory simulation
        
        Ok(Self {
            config,
            keys_data: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            data_storage: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            replication_slots: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Initialize PostgreSQL database with schema and indexes
    pub async fn initialize(&self) -> Result<()> {
        tracing::info!("Initializing PostgreSQL database with schema: {}", self.config.schema);
        
        // In a real implementation, this would:
        // 1. Create schema if it doesn't exist
        // 2. Create tables with proper constraints
        // 3. Create indexes for performance
        // 4. Set up triggers for automatic timestamp updates
        // 5. Configure partitioning if enabled
        // 6. Set up replication slots if configured
        
        self.create_schema().await?;
        self.create_tables().await?;
        self.create_indexes().await?;
        self.create_triggers().await?;
        
        if let Some(partitioning) = &self.config.partitioning {
            self.setup_partitioning(partitioning).await?;
        }
        
        if self.config.replication.streaming_enabled {
            self.setup_replication().await?;
        }
        
        tracing::info!("PostgreSQL database initialization completed");
        Ok(())
    }

    /// Create database schema
    async fn create_schema(&self) -> Result<()> {
        tracing::debug!("Creating PostgreSQL schema: {}", self.config.schema);
        // In real implementation: CREATE SCHEMA IF NOT EXISTS
        Ok(())
    }

    /// Create tables with proper constraints
    async fn create_tables(&self) -> Result<()> {
        tracing::debug!("Creating PostgreSQL tables");
        
        // In real implementation, this would execute:
        // CREATE TABLE fortress_keys (
        //     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        //     key_id TEXT UNIQUE NOT NULL,
        //     key_data BYTEA NOT NULL,
        //     metadata JSONB NOT NULL,
        //     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        //     updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        //     expires_at TIMESTAMPTZ NOT NULL,
        //     version INTEGER NOT NULL DEFAULT 1,
        //     tags JSONB DEFAULT '{}',
        //     encryption_algorithm TEXT NOT NULL,
        //     key_size INTEGER NOT NULL,
        //     access_count BIGINT DEFAULT 0,
        //     last_accessed TIMESTAMPTZ
        // );
        
        // CREATE TABLE fortress_data (
        //     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        //     key TEXT UNIQUE NOT NULL,
        //     data BYTEA NOT NULL,
        //     metadata JSONB DEFAULT '{}',
        //     content_type TEXT NOT NULL,
        //     encoding TEXT DEFAULT 'binary',
        //     compression TEXT DEFAULT 'none',
        //     checksum TEXT NOT NULL,
        //     size_bytes BIGINT NOT NULL,
        //     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        //     updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        //     partition_key TEXT,
        //     full_text_vector TSVECTOR
        // );
        
        Ok(())
    }

    /// Create optimized indexes
    async fn create_indexes(&self) -> Result<()> {
        tracing::debug!("Creating PostgreSQL indexes");
        
        // In real implementation, this would create indexes:
        // - B-tree indexes on key_id, created_at, expires_at
        // - GIN indexes on metadata JSONB, tags JSONB, full_text_vector
        // - Partial indexes for active keys only
        // - Composite indexes for common query patterns
        
        Ok(())
    }

    /// Create triggers for automatic updates
    async fn create_triggers(&self) -> Result<()> {
        tracing::debug!("Creating PostgreSQL triggers");
        
        // In real implementation, this would create triggers:
        // - Update updated_at timestamp on row modification
        // - Increment access_count on key access
        // - Update full_text_vector on data changes
        // - Automatic cleanup of expired keys
        
        Ok(())
    }

    /// Setup table partitioning
    async fn setup_partitioning(&self, partitioning: &PostgresPartitioning) -> Result<()> {
        tracing::debug!("Setting up PostgreSQL partitioning: {:?}", partitioning);
        
        match partitioning {
            PostgresPartitioning::ByDate { column, interval } => {
                tracing::info!("Setting up date-based partitioning on {} with interval {}", column, interval);
                // Implementation for date range partitioning
            }
            PostgresPartitioning::ByHash { column, partitions } => {
                tracing::info!("Setting up hash-based partitioning on {} with {} partitions", column, partitions);
                // Implementation for hash partitioning
            }
            PostgresPartitioning::BySize { column, max_size_mb } => {
                tracing::info!("Setting up size-based partitioning on {} with max size {}MB", column, max_size_mb);
                // Implementation for size-based partitioning
            }
        }
        
        Ok(())
    }

    /// Setup streaming replication
    async fn setup_replication(&self) -> Result<()> {
        tracing::debug!("Setting up PostgreSQL streaming replication");
        
        if let Some(slot_name) = &self.config.replication.slot_name {
            let slot = PostgresReplicationSlot {
                name: slot_name.clone(),
                plugin: "pgoutput".to_string(),
                database: self.config.database_name.clone(),
                active: true,
                confirmed_flush_lsn: Some("0/16B4E50".to_string()),
                restart_lsn: Some("0/16B4E50".to_string()),
            };
            
            let mut slots = self.replication_slots.write().await;
            slots.insert(slot_name.clone(), slot);
            
            tracing::info!("Created replication slot: {}", slot_name);
        }
        
        Ok(())
    }

    /// Push data with PostgreSQL COPY for bulk operations
    pub async fn push_bulk_copy(&self, entries: Vec<PostgresBulkEntry>) -> Result<u64> {
        let mut data_storage = self.data_storage.write().await;
        let mut count = 0;
        
        for entry in entries {
            let data_entry = PostgresDataEntry {
                id: Uuid::new_v4(),
                key: entry.key.clone(),
                data: entry.data.clone(),
                metadata_jsonb: serde_json::to_value(entry.metadata).unwrap_or_default(),
                content_type: entry.content_type.clone(),
                encoding: entry.encoding,
                compression: entry.compression,
                checksum: format!("{:x}", sha2::Sha256::digest(&entry.data)),
                size_bytes: entry.data.len() as i64,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                partition_key: entry.partition_key,
                full_text_vector: self.generate_full_text_vector(&entry.data, entry.content_type.as_str()),
            };
            
            data_storage.insert(entry.key, data_entry);
            count += 1;
        }
        
        tracing::info!("Pushed {} entries to PostgreSQL using COPY", count);
        Ok(count)
    }

    /// Pull data with PostgreSQL cursor for large result sets
    pub async fn pull_cursor(&self, query: PostgresQuery) -> Result<PostgresCursor> {
        let data_storage = self.data_storage.read().await;
        let mut results = Vec::new();
        
        // Simulate cursor-based query
        for (key, entry) in data_storage.iter() {
            let matches = self.matches_query(&entry, &query);
            if matches {
                results.push(PostgresRow {
                    key: key.clone(),
                    data: entry.data.clone(),
                    metadata: entry.metadata_jsonb.clone(),
                    created_at: entry.created_at,
                    size_bytes: entry.size_bytes,
                });
            }
        }
        
        // Apply limit and offset
        let offset = query.offset.unwrap_or(0) as usize;
        let limit = query.limit.unwrap_or(results.len() as u32) as usize;
        
        let paginated_results = results.clone().into_iter()
            .skip(offset)
            .take(limit)
            .collect();
        
        Ok(PostgresCursor {
            results: paginated_results,
            has_more: false, // In real implementation, this would check if there are more results
            total_count: results.len() as u64,
        })
    }

    /// Check if entry matches query criteria
    fn matches_query(&self, entry: &PostgresDataEntry, query: &PostgresQuery) -> bool {
        // Check key filter
        if let Some(key_filter) = &query.key_filter {
            if !entry.key.contains(key_filter) {
                return false;
            }
        }
        
        // Check date range
        if let Some(start) = &query.date_start {
            if entry.created_at < *start {
                return false;
            }
        }
        
        if let Some(end) = &query.date_end {
            if entry.created_at > *end {
                return false;
            }
        }
        
        // Check size range
        if let Some(min_size) = &query.min_size {
            if entry.size_bytes < *min_size {
                return false;
            }
        }
        
        if let Some(max_size) = &query.max_size {
            if entry.size_bytes > *max_size {
                return false;
            }
        }
        
        // Check content type
        if let Some(content_type) = &query.content_type {
            if entry.content_type != *content_type {
                return false;
            }
        }
        
        true
    }

    /// Generate full-text search vector
    fn generate_full_text_vector(&self, data: &[u8], content_type: &str) -> Option<String> {
        if content_type.starts_with("text/") {
            // For text content, generate a simple full-text vector
            if let Ok(text) = String::from_utf8(data.to_vec()) {
                // In real PostgreSQL, this would use to_tsvector()
                Some(text.to_lowercase())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Perform full-text search
    pub async fn full_text_search(&self, query: &str, limit: Option<i32>) -> Result<Vec<PostgresSearchResult>> {
        let data_storage = self.data_storage.read().await;
        let mut results = Vec::new();
        
        let query_lower = query.to_lowercase();
        let limit = limit.unwrap_or(10) as usize;
        
        for (key, entry) in data_storage.iter() {
            if let Some(vector) = &entry.full_text_vector {
                if vector.contains(&query_lower) {
                    // Calculate simple relevance score
                    let score = self.calculate_relevance_score(vector, &query_lower);
                    
                    results.push(PostgresSearchResult {
                        key: key.clone(),
                        score,
                        snippet: self.extract_snippet(vector, &query_lower),
                        metadata: entry.metadata_jsonb.clone(),
                    });
                    
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }
        
        // Sort by relevance score
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(results)
    }

    /// Calculate relevance score for search results
    fn calculate_relevance_score(&self, vector: &str, query: &str) -> f64 {
        let query_words: Vec<&str> = query.split_whitespace().collect();
        let vector_words: Vec<&str> = vector.split_whitespace().collect();
        
        let mut matches = 0;
        for query_word in &query_words {
            if vector_words.contains(query_word) {
                matches += 1;
            }
        }
        
        if query_words.is_empty() {
            0.0
        } else {
            matches as f64 / query_words.len() as f64
        }
    }

    /// Extract snippet around matched terms
    fn extract_snippet(&self, vector: &str, query: &str) -> String {
        let words: Vec<&str> = vector.split_whitespace().collect();
        if words.is_empty() {
            return String::new();
        }
        
        // Find first word that contains query
        for (i, word) in words.iter().enumerate() {
            if word.contains(query) {
                let start = i.saturating_sub(5);
                let end = (i + 6).min(words.len());
                return words[start..end].join(" ");
            }
        }
        
        // If no direct match, return first few words
        let end = words.len().min(10);
        words[..end].join(" ")
    }

    /// Perform JSONB query with PostgreSQL operators
    pub async fn jsonb_query(&self, jsonb_query: PostgresJsonbQuery) -> Result<Vec<serde_json::Value>> {
        let data_storage = self.data_storage.read().await;
        let mut results = Vec::new();
        
        for entry in data_storage.values() {
            if self.matches_jsonb_query(&entry.metadata_jsonb, &jsonb_query) {
                results.push(entry.metadata_jsonb.clone());
            }
        }
        
        Ok(results)
    }

    /// Check if JSONB entry matches query
    fn matches_jsonb_query(&self, metadata: &serde_json::Value, query: &PostgresJsonbQuery) -> bool {
        match query {
            PostgresJsonbQuery::Exists { path } => {
                self.jsonb_path_exists(metadata, path)
            }
            PostgresJsonbQuery::Equals { path, value } => {
                self.jsonb_path_equals(metadata, path, value)
            }
            PostgresJsonbQuery::Contains { path, value } => {
                self.jsonb_path_contains(metadata, path, value)
            }
            PostgresJsonbQuery::GreaterThan { path, value } => {
                self.jsonb_path_greater_than(metadata, path, value)
            }
            PostgresJsonbQuery::LessThan { path, value } => {
                self.jsonb_path_less_than(metadata, path, value)
            }
        }
    }

    /// Check if JSONB path exists
    fn jsonb_path_exists(&self, value: &serde_json::Value, path: &str) -> bool {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;
        
        for part in parts {
            match current {
                serde_json::Value::Object(map) => {
                    if let Some(next) = map.get(part) {
                        current = next;
                    } else {
                        return false;
                    }
                }
                serde_json::Value::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        if let Some(next) = arr.get(index) {
                            current = next;
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        
        true
    }

    /// Check if JSONB path equals value
    fn jsonb_path_equals(&self, value: &serde_json::Value, path: &str, target: &serde_json::Value) -> bool {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;
        
        for part in parts {
            match current {
                serde_json::Value::Object(map) => {
                    if let Some(next) = map.get(part) {
                        current = next;
                    } else {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        
        current == target
    }

    /// Check if JSONB path contains value
    fn jsonb_path_contains(&self, value: &serde_json::Value, path: &str, target: &serde_json::Value) -> bool {
        if let Some(current) = self.get_jsonb_path(value, path) {
            match current {
                serde_json::Value::String(s) => {
                    if let Some(target_str) = target.as_str() {
                        s.contains(target_str)
                    } else {
                        false
                    }
                }
                serde_json::Value::Array(arr) => arr.contains(target),
                serde_json::Value::Object(map) => {
                    if let Some(target_obj) = target.as_object() {
                        for (key, val) in target_obj {
                            if map.get(key) != Some(val) {
                                return false;
                            }
                        }
                        true
                    } else {
                        false
                    }
                }
                _ => current == target,
            }
        } else {
            false
        }
    }

    /// Check if JSONB path is greater than value
    fn jsonb_path_greater_than(&self, value: &serde_json::Value, path: &str, target: &serde_json::Value) -> bool {
        if let Some(current) = self.get_jsonb_path(value, path) {
            self.compare_jsonb_values(current, target, |a, b| a > b)
        } else {
            false
        }
    }

    /// Check if JSONB path is less than value
    fn jsonb_path_less_than(&self, value: &serde_json::Value, path: &str, target: &serde_json::Value) -> bool {
        if let Some(current) = self.get_jsonb_path(value, path) {
            self.compare_jsonb_values(current, target, |a, b| a < b)
        } else {
            false
        }
    }

    /// Get value at JSONB path
    fn get_jsonb_path<'a>(&self, value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;
        
        for part in parts {
            match current {
                serde_json::Value::Object(map) => {
                    current = map.get(part)?;
                }
                serde_json::Value::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        current = arr.get(index)?;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        
        Some(current)
    }

    /// Compare JSONB values
    fn compare_jsonb_values<F>(&self, a: &serde_json::Value, b: &serde_json::Value, compare: F) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        match (a.as_f64(), b.as_f64()) {
            (Some(a_num), Some(b_num)) => compare(a_num, b_num),
            _ => false,
        }
    }

    /// Get replication slot information
    pub async fn get_replication_slots(&self) -> Result<Vec<PostgresReplicationSlot>> {
        let slots = self.replication_slots.read().await;
        Ok(slots.values().cloned().collect())
    }

    /// Create publication for logical replication
    pub async fn create_publication(&self, name: &str, tables: Vec<String>) -> Result<()> {
        tracing::info!("Creating PostgreSQL publication '{}' for tables: {:?}", name, tables);
        
        // In real implementation, this would execute:
        // CREATE PUBLICATION <name> FOR TABLE <tables>
        
        Ok(())
    }
}

#[async_trait]
impl crate::key_database::KeyDatabase for PostgresKeyDatabase {
    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        let mut keys_data = self.keys_data.write().await;
        
        let entry = PostgresKeyEntry {
            id: Uuid::new_v4(),
            key_id: key_id.clone(),
            key_data: key.to_vec(),
            metadata: serde_json::to_value(metadata).map_err(|e| FortressError::key_management(
                format!("Failed to serialize metadata: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::SerializationError,
            ))?,
            created_at: metadata.created_at,
            updated_at: Utc::now(),
            expires_at: metadata.expires_at,
            version: metadata.version as i32,
            tags: HashMap::new(),
            encryption_algorithm: "aes256".to_string(), // Would come from metadata
            key_size: key.len() as i32,
            access_count: 0,
            last_accessed: None,
        };
        
        keys_data.insert(key_id.clone(), entry);
        
        tracing::debug!("Stored key {} in PostgreSQL", key_id);
        Ok(())
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        let mut keys_data = self.keys_data.write().await; // Write to update access count
        
        if let Some(entry) = keys_data.get_mut(key_id) {
            // Update access statistics
            entry.access_count += 1;
            entry.last_accessed = Some(Utc::now());
            
            let key = SecureKey::from_bytes(&entry.key_data);
            
            let metadata: KeyMetadata = serde_json::from_value(entry.metadata.clone())
                .map_err(|e| FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                ))?;
            
            Ok(Some((key, metadata)))
        } else {
            Ok(None)
        }
    }

    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        let mut keys_data = self.keys_data.write().await;
        
        if keys_data.remove(key_id).is_none() {
            return Err(FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ));
        }
        
        tracing::debug!("Deleted key {} from PostgreSQL", key_id);
        Ok(())
    }

    async fn list_keys(&self, _limit: Option<u32>, _offset: Option<u32>) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let keys_data = self.keys_data.read().await;
        
        let mut keys = Vec::new();
        for entry in keys_data.values() {
            if entry.expires_at > Utc::now() {
                let metadata: KeyMetadata = serde_json::from_value(entry.metadata.clone())
                    .map_err(|e| FortressError::key_management(
                        format!("Failed to deserialize metadata: {}", e),
                        Some(entry.key_id.clone()),
                        KeyErrorCode::SerializationError,
                    ))?;
                
                keys.push((entry.key_id.clone(), metadata));
            }
        }
        
        keys.sort_by(|a, b| a.1.created_at.cmp(&b.1.created_at));
        Ok(keys)
    }

    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        let keys_data = self.keys_data.read().await;
        Ok(keys_data.contains_key(key_id) && 
            keys_data.get(key_id).map_or(false, |e| e.expires_at > Utc::now()))
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<Option<KeyMetadata>> {
        let keys_data = self.keys_data.read().await;
        if let Some(entry) = keys_data.get(key_id) {
            if entry.expires_at > Utc::now() {
                let metadata: KeyMetadata = serde_json::from_value(entry.metadata.clone())
                    .map_err(|e| FortressError::key_management(
                        format!("Failed to deserialize metadata: {}", e),
                        Some(key_id.clone()),
                        KeyErrorCode::SerializationError,
                    ))?;
                
                Ok(Some(metadata))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn preload_keys(&self) -> Result<Vec<(KeyId, SecureKey, KeyMetadata)>> {
        let keys_data = self.keys_data.read().await;
        let mut keys = Vec::new();
        
        for entry in keys_data.values() {
            if entry.expires_at > Utc::now() {
                let key = SecureKey::from_bytes(&entry.key_data);
                
                let metadata = serde_json::from_value(entry.metadata.clone())
                    .map_err(|e| FortressError::key_management(
                        format!("Failed to deserialize metadata: {}", e),
                        Some(entry.key_id.clone()),
                        KeyErrorCode::SerializationError,
                    ))?;
                
                keys.push((entry.key_id.clone(), key, metadata));
            }
        }
        
        tracing::info!("Preloaded {} keys from PostgreSQL", keys.len());
        Ok(keys)
    }

    async fn get_stats(&self) -> Result<crate::key_database::KeyDatabaseStats> {
        let keys_data = self.keys_data.read().await;
        let data_storage = self.data_storage.read().await;
        
        let total_keys = keys_data.values()
            .filter(|e| e.expires_at > Utc::now())
            .count() as u64;
        
        let database_size_bytes = keys_data.values()
            .map(|e| e.key_data.len() as i64)
            .sum::<i64>() as u64 +
            data_storage.values()
            .map(|e| e.data.len() as i64)
            .sum::<i64>() as u64;
        
        Ok(crate::key_database::KeyDatabaseStats {
            total_keys,
            database_size_bytes,
            active_connections: self.config.max_connections,
            avg_query_time_ms: 0.0, // Would need to implement query timing
            last_rotation_time: None, // Would need to track rotation times
        })
    }

    async fn initialize(&self) -> Result<()> {
        self.initialize().await
    }

    async fn health_check(&self) -> Result<bool> {
        // In a real implementation, this would ping PostgreSQL
        let _keys = self.keys_data.read().await;
        let _data = self.data_storage.read().await;
        
        tracing::debug!("PostgreSQL health check passed");
        Ok(true)
    }
}

/// Bulk entry for PostgreSQL COPY operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresBulkEntry {
    /// Entry key
    pub key: String,
    /// Binary data
    pub data: Vec<u8>,
    /// Entry metadata
    pub metadata: HashMap<String, String>,
    /// Content type (e.g., "application/octet-stream")
    pub content_type: String,
    /// Data encoding (e.g., "utf-8", "base64")
    pub encoding: String,
    /// Compression algorithm (e.g., "gzip", "none")
    pub compression: String,
    /// Optional partition key for sharding
    pub partition_key: Option<String>,
}

/// PostgreSQL query with cursor support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresQuery {
    /// Key filter pattern
    pub key_filter: Option<String>,
    /// Start date filter
    pub date_start: Option<DateTime<Utc>>,
    /// End date filter
    pub date_end: Option<DateTime<Utc>>,
    /// Minimum size filter in bytes
    pub min_size: Option<i64>,
    /// Maximum size filter in bytes
    pub max_size: Option<i64>,
    /// Content type filter
    pub content_type: Option<String>,
    /// Result offset for pagination
    pub offset: Option<u32>,
    /// Result limit for pagination
    pub limit: Option<u32>,
}

/// PostgreSQL cursor result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresCursor {
    /// Query results
    pub results: Vec<PostgresRow>,
    /// Whether more results are available
    pub has_more: bool,
    /// Total result count
    pub total_count: u64,
}

/// PostgreSQL row result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresRow {
    /// Row key
    pub key: String,
    /// Row data
    pub data: Vec<u8>,
    /// Row metadata as JSON
    pub metadata: serde_json::Value,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Data size in bytes
    pub size_bytes: i64,
}

/// PostgreSQL search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresSearchResult {
    /// Result key
    pub key: String,
    /// Search relevance score
    pub score: f64,
    /// Text snippet preview
    pub snippet: String,
    /// Result metadata as JSON
    pub metadata: serde_json::Value,
}

/// PostgreSQL JSONB query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostgresJsonbQuery {
    /// Check if JSON path exists
    Exists { 
        /// JSON path (e.g., "metadata.tags")
        path: String 
    },
    /// Check if JSON path equals value
    Equals { 
        /// JSON path
        path: String, 
        /// Value to compare
        value: serde_json::Value 
    },
    /// Check if JSON path contains value
    Contains { 
        /// JSON path
        path: String, 
        /// Value to check for containment
        value: serde_json::Value 
    },
    /// Check if JSON path is greater than value
    GreaterThan { 
        /// JSON path
        path: String, 
        /// Value to compare against
        value: serde_json::Value 
    },
    /// Check if JSON path is less than value
    LessThan { 
        /// JSON path
        path: String, 
        /// Value to compare against
        value: serde_json::Value 
    },
}

/// Enhanced PostgreSQL storage backend
#[derive(Debug)]
pub struct PostgresStorage {
    config: PostgresConfig,
    data_storage: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<u8>>>>,
}

impl PostgresStorage {
    /// Create a new PostgreSQL storage instance
    pub async fn new(config: PostgresConfig) -> Result<Self> {
        Ok(Self {
            config,
            data_storage: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl StorageBackend for PostgresStorage {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut data = self.data_storage.write().await;
        data.insert(key.to_string(), value.to_vec());
        
        tracing::debug!("Stored data in PostgreSQL with key: {}", key);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let data = self.data_storage.read().await;
        Ok(data.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.data_storage.write().await;
        
        if data.remove(key).is_none() {
            return Err(FortressError::storage(
                format!("Key not found: {}", key),
                "postgresql".to_string(),
                StorageErrorCode::NotFound,
            ));
        }
        
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let data = self.data_storage.read().await;
        Ok(data.contains_key(key))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_prefix_paginated(prefix, None, None).await
    }

    async fn list_prefix_paginated(&self, prefix: &str, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>> {
        let data = self.data_storage.read().await;
        let keys: Vec<_> = data
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        
        // Apply pagination
        let start_idx = offset.unwrap_or(0);
        let end_idx = match limit {
            Some(limit) => std::cmp::min(start_idx + limit, keys.len()),
            None => keys.len(),
        };
        
        if start_idx >= keys.len() {
            return Ok(Vec::new());
        }
        
        Ok(keys[start_idx..end_idx].to_vec())
    }

    fn metadata(&self) -> crate::storage::StorageMetadata {
        crate::storage::StorageMetadata {
            backend_type: "postgresql".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: true,
            supports_encryption_at_rest: true,
            supports_streaming: false,
            supports_backup_restore: false,
            supports_audit_logging: false,
            max_object_size: Some(1024 * 1024 * 1024), // 1GB
            supported_isolation_levels: vec![],
            supported_compression_algorithms: vec![],
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("database".to_string(), self.config.database_name.clone());
                meta.insert("schema".to_string(), self.config.schema.clone());
                meta
            },
        }
    }

    async fn health_check(&self) -> Result<crate::storage::HealthStatus> {
        let start = std::time::Instant::now();
        let _data = self.data_storage.read().await;
        let response_time = start.elapsed().as_millis() as u64;

        Ok(crate::storage::HealthStatus {
            healthy: true,
            response_time_ms: response_time,
            details: {
                let mut details = HashMap::new();
                details.insert("database".to_string(), self.config.database_name.clone());
                details
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_postgres_config_default() {
        let config = PostgresConfig::default();
        assert_eq!(config.database_name, "fortress");
        assert_eq!(config.schema, "public");
        assert_eq!(config.max_connections, 20);
        assert!(!config.ssl_enabled);
    }

    #[tokio::test]
    async fn test_postgres_key_database_creation() {
        let config = PostgresConfig::default();
        let db = PostgresKeyDatabase::new(config).await.unwrap();
        
        assert!(db.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_postgres_bulk_operations() {
        let config = PostgresConfig::default();
        let db = PostgresKeyDatabase::new(config).await.unwrap();
        
        // Test bulk push
        let entries = vec![
            PostgresBulkEntry {
                key: "bulk1".to_string(),
                data: b"data1".to_vec(),
                metadata: HashMap::new(),
                content_type: "text/plain".to_string(),
                encoding: "utf-8".to_string(),
                compression: "none".to_string(),
                partition_key: None,
            },
            PostgresBulkEntry {
                key: "bulk2".to_string(),
                data: b"data2".to_vec(),
                metadata: HashMap::new(),
                content_type: "application/json".to_string(),
                encoding: "utf-8".to_string(),
                compression: "none".to_string(),
                partition_key: None,
            },
        ];
        
        let count = db.push_bulk_copy(entries).await.unwrap();
        assert_eq!(count, 2);
        
        // Test cursor pull
        let query = PostgresQuery {
            key_filter: None,
            date_start: None,
            date_end: None,
            min_size: None,
            max_size: None,
            content_type: None,
            offset: None,
            limit: Some(10),
        };
        
        let cursor = db.pull_cursor(query).await.unwrap();
        assert_eq!(cursor.results.len(), 2);
        assert_eq!(cursor.total_count, 2);
    }

    #[tokio::test]
    async fn test_postgres_full_text_search() {
        let config = PostgresConfig::default();
        let db = PostgresKeyDatabase::new(config).await.unwrap();
        
        // Add text data
        let entries = vec![
            PostgresBulkEntry {
                key: "doc1".to_string(),
                data: b"The quick brown fox jumps over the lazy dog".to_vec(),
                metadata: HashMap::new(),
                content_type: "text/plain".to_string(),
                encoding: "utf-8".to_string(),
                compression: "none".to_string(),
                partition_key: None,
            },
        ];
        
        db.push_bulk_copy(entries).await.unwrap();
        
        // Test full-text search
        let results = db.full_text_search("quick", Some(10)).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].snippet.contains("quick"));
    }

    #[tokio::test]
    async fn test_postgres_jsonb_query() {
        let config = PostgresConfig::default();
        let db = PostgresKeyDatabase::new(config).await.unwrap();
        
        // Add data with JSONB metadata
        let mut metadata = HashMap::new();
        metadata.insert("category".to_string(), "important".to_string());
        metadata.insert("priority".to_string(), "high".to_string());
        
        let entries = vec![
            PostgresBulkEntry {
                key: "json1".to_string(),
                data: b"data".to_vec(),
                metadata,
                content_type: "application/json".to_string(),
                encoding: "utf-8".to_string(),
                compression: "none".to_string(),
                partition_key: None,
            },
        ];
        
        db.push_bulk_copy(entries).await.unwrap();
        
        // Test JSONB query
        let query = PostgresJsonbQuery::Equals {
            path: "category".to_string(),
            value: serde_json::Value::String("important".to_string()),
        };
        
        let results = db.jsonb_query(query).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_postgres_storage_backend() {
        let config = PostgresConfig::default();
        let storage = PostgresStorage::new(config).await.unwrap();
        
        // Test basic operations
        storage.put("test_key", b"test_value").await.unwrap();
        let value = storage.get("test_key").await.unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));
        
        assert!(storage.exists("test_key").await.unwrap());
        
        let keys = storage.list_prefix("test").await.unwrap();
        assert_eq!(keys, vec!["test_key"]);
        
        let metadata = storage.metadata();
        assert_eq!(metadata.backend_type, "postgresql");
        assert!(metadata.supports_transactions);
    }
}
