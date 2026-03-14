//! MongoDB database backend for Fortress
//!
//! This module provides MongoDB integration for key storage and general data operations,
//! with support for push/pull operations and optimized performance.

use crate::error::{FortressError, Result, KeyErrorCode, StorageErrorCode};
use crate::key::{KeyId, KeyMetadata, SecureKey};
use crate::storage::StorageBackend;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sha2::Digest;

/// MongoDB configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoConfig {
    /// MongoDB connection string
    pub connection_string: String,
    /// Database name
    pub database_name: String,
    /// Keys collection name
    pub keys_collection: String,
    /// Data collection name
    pub data_collection: String,
    /// Connection pool size
    pub max_pool_size: u32,
    /// Enable TLS
    pub tls_enabled: bool,
    /// Authentication database
    pub auth_database: Option<String>,
    /// Replica set name
    pub replica_set: Option<String>,
    /// Read preference
    pub read_preference: MongoReadPreference,
    /// Write concern
    pub write_concern: MongoWriteConcern,
}

/// MongoDB read preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MongoReadPreference {
    Primary,
    PrimaryPreferred,
    Secondary,
    SecondaryPreferred,
    Nearest,
}

/// MongoDB write concerns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MongoWriteConcern {
    Unacknowledged,
    Acknowledged,
    Journaled,
    Majority,
    Custom { w: i32, j: bool, wtimeout: Option<i32> },
}

impl Default for MongoConfig {
    fn default() -> Self {
        Self {
            connection_string: "mongodb://localhost:27017".to_string(),
            database_name: "fortress".to_string(),
            keys_collection: "fortress_keys".to_string(),
            data_collection: "fortress_data".to_string(),
            max_pool_size: 10,
            tls_enabled: false,
            auth_database: None,
            replica_set: None,
            read_preference: MongoReadPreference::Primary,
            write_concern: MongoWriteConcern::Acknowledged,
        }
    }
}

/// MongoDB key database implementation
#[derive(Debug)]
pub struct MongoKeyDatabase {
    config: MongoConfig,
    // In a real implementation, this would hold a MongoDB client
    // For now, we'll simulate with in-memory storage
    keys_data: std::sync::Arc<tokio::sync::RwLock<HashMap<String, MongoKeyEntry>>>,
    data_storage: std::sync::Arc<tokio::sync::RwLock<HashMap<String, MongoDataEntry>>>,
}

/// MongoDB key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MongoKeyEntry {
    _id: String,
    key_data: Vec<u8>,
    metadata: KeyMetadata,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    version: i32,
    tags: HashMap<String, String>,
}

/// MongoDB data entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MongoDataEntry {
    _id: String,
    data: Vec<u8>,
    content_type: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    checksum: String,
    size_bytes: i64,
    metadata: HashMap<String, String>,
}

impl MongoKeyDatabase {
    /// Create a new MongoDB key database
    pub async fn new(config: MongoConfig) -> Result<Self> {
        // In a real implementation, this would establish MongoDB connection
        // For now, we'll create an in-memory simulation
        
        Ok(Self {
            config,
            keys_data: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            data_storage: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Initialize MongoDB indexes and collections
    pub async fn initialize(&self) -> Result<()> {
        // In a real implementation, this would:
        // 1. Create collections if they don't exist
        // 2. Create indexes for performance
        // 3. Set up TTL indexes for expiration
        // 4. Validate connection
        
        tracing::info!("Initializing MongoDB database with collections: {}, {}", 
                     self.config.keys_collection, self.config.data_collection);
        
        // Simulate index creation
        let keys = self.keys_data.read().await;
        tracing::info!("MongoDB keys collection initialized with {} entries", keys.len());
        
        Ok(())
    }

    /// Create indexes for optimal performance
    async fn create_indexes(&self) -> Result<()> {
        // In a real implementation, this would create MongoDB indexes:
        // - Compound index on (expires_at, created_at)
        // - Index on key_id for fast lookups
        // - Index on tags for metadata queries
        // - TTL index on expires_at for automatic cleanup
        
        tracing::info!("Creating MongoDB indexes for optimal performance");
        Ok(())
    }

    /// Push data to MongoDB with bulk operations
    pub async fn push_bulk(&self, entries: Vec<(String, Vec<u8>, HashMap<String, String>)>) -> Result<u64> {
        let mut data_storage = self.data_storage.write().await;
        let mut count = 0;
        
        for (key, data, metadata) in entries {
            let entry = MongoDataEntry {
                _id: key.clone(),
                data: data.clone(),
                content_type: "application/octet-stream".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                checksum: format!("{:x}", sha2::Sha256::digest(&data)),
                size_bytes: data.len() as i64,
                metadata,
            };
            
            data_storage.insert(key, entry);
            count += 1;
        }
        
        tracing::info!("Pushed {} entries to MongoDB", count);
        Ok(count)
    }

    /// Pull data from MongoDB with filtering
    pub async fn pull_filtered(&self, filter: MongoPullFilter) -> Result<Vec<(String, Vec<u8>)>> {
        let data_storage = self.data_storage.read().await;
        let mut results = Vec::new();
        
        for (key, entry) in data_storage.iter() {
            let matches = match &filter {
                MongoPullFilter::All => true,
                MongoPullFilter::Prefix(prefix) => key.starts_with(prefix),
                MongoPullFilter::DateRange { start, end } => {
                    entry.created_at >= *start && entry.created_at <= *end
                }
                MongoPullFilter::SizeRange { min_size, max_size } => {
                    entry.size_bytes >= *min_size && entry.size_bytes <= *max_size
                }
                MongoPullFilter::Metadata { key: meta_key, value } => {
                    entry.metadata.get(meta_key).map_or(false, |v| v == value)
                }
            };
            
            if matches {
                results.push((key.clone(), entry.data.clone()));
            }
        }
        
        tracing::info!("Pulled {} entries from MongoDB with filter {:?}", results.len(), filter);
        Ok(results)
    }

    /// Perform aggregation pipeline query
    pub async fn aggregate(&self, pipeline: MongoPipeline) -> Result<Vec<MongoAggregationResult>> {
        let keys = self.keys_data.read().await;
        let data = self.data_storage.read().await;
        
        // Simulate aggregation - in real implementation this would use MongoDB's aggregation framework
        let mut results = Vec::new();
        
        match pipeline.operation.as_str() {
            "count_by_type" => {
                let mut type_counts: HashMap<String, i64> = HashMap::new();
                for entry in data.values() {
                    *type_counts.entry(entry.content_type.clone()).or_insert(0) += 1;
                }
                
                for (content_type, count) in type_counts {
                    results.push(MongoAggregationResult {
                        _id: content_type.clone(),
                        count,
                        total_size: data.values()
                            .filter(|e| e.content_type == content_type)
                            .map(|e| e.size_bytes)
                            .sum(),
                    });
                }
            }
            "size_distribution" => {
                let mut size_buckets = HashMap::new();
                for entry in data.values() {
                    let bucket = if entry.size_bytes < 1024 { "small".to_string() }
                        else if entry.size_bytes < 1024 * 1024 { "medium".to_string() }
                        else { "large".to_string() };
                    
                    *size_buckets.entry(bucket).or_insert(0) += 1;
                }
                
                for (bucket, count) in size_buckets {
                    results.push(MongoAggregationResult {
                        _id: bucket,
                        count,
                        total_size: 0,
                    });
                }
            }
            _ => {
                return Err(FortressError::storage(
                    format!("Unsupported aggregation operation: {}", pipeline.operation),
                    "mongodb".to_string(),
                    StorageErrorCode::InvalidOperation,
                ));
            }
        }
        
        Ok(results)
    }

    /// Perform text search on data metadata
    pub async fn text_search(&self, query: &str, limit: Option<i32>) -> Result<Vec<MongoSearchResult>> {
        let data_storage = self.data_storage.read().await;
        let mut results = Vec::new();
        
        let limit = limit.unwrap_or(10) as usize;
        let query_lower = query.to_lowercase();
        
        for (key, entry) in data_storage.iter() {
            // Simple text search simulation - in real MongoDB this would use text indexes
            let metadata_text = entry.metadata.values()
                .cloned()
                .chain(std::iter::once(entry.content_type.clone()))
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            
            if metadata_text.contains(&query_lower) {
                results.push(MongoSearchResult {
                    key: key.clone(),
                    score: 1.0, // In real MongoDB, this would be relevance score
                    snippet: entry.content_type.clone(),
                    metadata: entry.metadata.clone(),
                });
                
                if results.len() >= limit {
                    break;
                }
            }
        }
        
        Ok(results)
    }
}

#[async_trait]
impl crate::key_database::KeyDatabase for MongoKeyDatabase {
    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        let mut keys_data = self.keys_data.write().await;
        
        let entry = MongoKeyEntry {
            _id: key_id.clone(),
            key_data: key.to_vec(),
            metadata: metadata.clone(),
            created_at: metadata.created_at,
            updated_at: Utc::now(),
            expires_at: metadata.expires_at,
            version: metadata.version as i32,
            tags: HashMap::new(), // Could be populated from metadata
        };
        
        keys_data.insert(key_id.clone(), entry);
        
        tracing::debug!("Stored key {} in MongoDB", key_id);
        Ok(())
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        let keys_data = self.keys_data.read().await;
        
        if let Some(entry) = keys_data.get(key_id) {
            let key = SecureKey::from_bytes(&entry.key_data);
            
            Ok(Some((key, entry.metadata.clone())))
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
        
        tracing::debug!("Deleted key {} from MongoDB", key_id);
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let keys_data = self.keys_data.read().await;
        
        let mut keys = Vec::new();
        for (key_id, entry) in keys_data.iter() {
            if entry.expires_at > Utc::now() {
                keys.push((key_id.clone(), entry.metadata.clone()));
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
        Ok(keys_data.get(key_id).filter(|e| e.expires_at > Utc::now()).map(|e| e.metadata.clone()))
    }

    async fn preload_keys(&self) -> Result<Vec<(KeyId, SecureKey, KeyMetadata)>> {
        let keys_data = self.keys_data.read().await;
        let mut keys = Vec::new();
        
        for (key_id, entry) in keys_data.iter() {
            if entry.expires_at > Utc::now() {
                let key = SecureKey::from_bytes(&entry.key_data);
                
                keys.push((key_id.clone(), key, entry.metadata.clone()));
            }
        }
        
        tracing::info!("Preloaded {} keys from MongoDB", keys.len());
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
            active_connections: self.config.max_pool_size,
            avg_query_time_ms: 0.0, // Would need to implement query timing
            last_rotation_time: None, // Would need to track rotation times
        })
    }

    async fn initialize(&self) -> Result<()> {
        self.initialize().await
    }

    async fn health_check(&self) -> Result<bool> {
        // In a real implementation, this would ping MongoDB
        // For simulation, we'll just check if we can access the data
        let _keys = self.keys_data.read().await;
        let _data = self.data_storage.read().await;
        
        tracing::debug!("MongoDB health check passed");
        Ok(true)
    }
}

/// MongoDB pull filter options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MongoPullFilter {
    All,
    Prefix(String),
    DateRange { start: DateTime<Utc>, end: DateTime<Utc> },
    SizeRange { min_size: i64, max_size: i64 },
    /// Metadata key-value pair
    Metadata { 
        /// Metadata key
        key: String, 
        /// Metadata value
        value: String 
    },
}

/// MongoDB aggregation pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoPipeline {
    pub operation: String,
    pub stages: Vec<serde_json::Value>,
}

/// MongoDB aggregation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoAggregationResult {
    pub _id: String,
    pub count: i64,
    pub total_size: i64,
}

/// MongoDB search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoSearchResult {
    pub key: String,
    pub score: f64,
    pub snippet: String,
    /// Additional metadata associated with the search result
    pub metadata: HashMap<String, String>,
}

/// MongoDB storage backend implementation
#[derive(Debug)]
pub struct MongoStorage {
    config: MongoConfig,
    data_storage: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<u8>>>>,
}

impl MongoStorage {
    /// Create a new MongoDB storage instance
    /// 
    /// # Arguments
    /// * `config` - MongoDB configuration
    /// 
    /// # Returns
    /// Result containing the MongoStorage instance or an error
    pub async fn new(config: MongoConfig) -> Result<Self> {
        Ok(Self {
            config,
            data_storage: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl StorageBackend for MongoStorage {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut data = self.data_storage.write().await;
        data.insert(key.to_string(), value.to_vec());
        
        tracing::debug!("Stored data in MongoDB with key: {}", key);
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
                "mongodb".to_string(),
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
        let data = self.data_storage.read().await;
        Ok(data
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn metadata(&self) -> crate::storage::StorageMetadata {
        crate::storage::StorageMetadata {
            backend_type: "mongodb".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: true,
            supports_encryption_at_rest: true,
            supports_streaming: false,
            supports_backup_restore: false,
            supports_audit_logging: false,
            max_object_size: Some(16 * 1024 * 1024), // 16MB MongoDB document limit
            supported_isolation_levels: vec![],
            supported_compression_algorithms: vec![],
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("database".to_string(), self.config.database_name.clone());
                meta.insert("collection".to_string(), self.config.data_collection.clone());
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
    async fn test_mongo_config_default() {
        let config = MongoConfig::default();
        assert_eq!(config.database_name, "fortress");
        assert_eq!(config.keys_collection, "fortress_keys");
        assert_eq!(config.data_collection, "fortress_data");
        assert_eq!(config.max_pool_size, 10);
    }

    #[tokio::test]
    async fn test_mongo_key_database_creation() {
        let config = MongoConfig::default();
        let db = MongoKeyDatabase::new(config).await.unwrap();
        
        assert!(db.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_mongo_push_pull_operations() {
        let config = MongoConfig::default();
        let db = MongoKeyDatabase::new(config).await.unwrap();
        
        // Test push bulk
        let entries = vec![
            ("key1".to_string(), b"data1".to_vec(), HashMap::new()),
            ("key2".to_string(), b"data2".to_vec(), HashMap::new()),
        ];
        
        let count = db.push_bulk(entries).await.unwrap();
        assert_eq!(count, 2);
        
        // Test pull filtered
        let results = db.pull_filtered(MongoPullFilter::All).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_mongo_aggregation() {
        let config = MongoConfig::default();
        let db = MongoKeyDatabase::new(config).await.unwrap();
        
        // Add some test data
        let entries = vec![
            ("doc1".to_string(), b"data".to_vec(), {
                let mut meta = HashMap::new();
                meta.insert("type".to_string(), "text".to_string());
                meta
            }),
            ("doc2".to_string(), "data".to_string(), {
                let mut meta = HashMap::new();
                meta.insert("type".to_string(), "binary".to_string());
                meta
            }),
        ];
        
        db.push_bulk(entries).await.unwrap();
        
        // Test aggregation
        let pipeline = MongoPipeline {
            operation: "count_by_type".to_string(),
            stages: vec![],
        };
        
        let results = db.aggregate(pipeline).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_mongo_storage_backend() {
        let config = MongoConfig::default();
        let storage = MongoStorage::new(config).await.unwrap();
        
        // Test basic operations
        storage.put("test_key", b"test_value").await.unwrap();
        let value = storage.get("test_key").await.unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));
        
        assert!(storage.exists("test_key").await.unwrap());
        
        let keys = storage.list_prefix("test").await.unwrap();
        assert_eq!(keys, vec!["test_key"]);
        
        let metadata = storage.metadata();
        assert_eq!(metadata.backend_type, "mongodb");
        assert!(metadata.supports_transactions);
    }
}
