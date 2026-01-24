//! Storage backend abstractions
//!
//! This module provides traits and implementations for various storage backends
//! that Fortress can use to store encrypted data and metadata.

use crate::error::{FortressError, Result, StorageErrorCode};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Trait for storage backends
///
/// This trait defines the interface that all storage backends must implement.
/// It provides both synchronous and asynchronous methods for flexibility.
#[async_trait]
pub trait StorageBackend: Send + Sync + fmt::Debug {
    /// Store data with the given key
    async fn put(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Retrieve data by key
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete data by key
    async fn delete(&self, key: &str) -> Result<()>;

    /// Check if a key exists
    async fn exists(&self, key: &str) -> Result<bool>;

    /// List all keys with a given prefix
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>>;

    /// Get metadata about the storage backend
    fn metadata(&self) -> StorageMetadata;

    /// Check if the backend is healthy
    async fn health_check(&self) -> Result<HealthStatus>;
}

/// Storage metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    /// Backend type name
    pub backend_type: String,
    /// Backend version
    pub version: String,
    /// Whether the backend supports transactions
    pub supports_transactions: bool,
    /// Whether the backend supports encryption at rest
    pub supports_encryption_at_rest: bool,
    /// Maximum object size (if applicable)
    pub max_object_size: Option<usize>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Health status of the storage backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Whether the backend is healthy
    pub healthy: bool,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Additional health information
    pub details: HashMap<String, String>,
}

/// In-memory storage backend for testing and development
#[derive(Debug)]
pub struct InMemoryStorage {
    data: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryStorage {
    /// Create a new in-memory storage backend
    pub fn new() -> Self {
        Self {
            data: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for InMemoryStorage {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut data = self.data.write().await;
        data.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let data = self.data.read().await;
        Ok(data.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.data.write().await;
        data.remove(key)
            .ok_or_else(|| FortressError::storage(
                format!("Key not found: {}", key),
                "in_memory",
                StorageErrorCode::NotFound,
            ))?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let data = self.data.read().await;
        Ok(data.contains_key(key))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let data = self.data.read().await;
        Ok(data
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            backend_type: "in_memory".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: false,
            supports_encryption_at_rest: false,
            max_object_size: None,
            metadata: HashMap::new(),
        }
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let start = std::time::Instant::now();
        let _data = self.data.read().await;
        let response_time = start.elapsed().as_millis() as u64;

        Ok(HealthStatus {
            healthy: true,
            response_time_ms: response_time,
            details: HashMap::new(),
        })
    }
}

/// File system storage backend
#[derive(Debug)]
pub struct FileSystemStorage {
    base_path: std::path::PathBuf,
}

impl FileSystemStorage {
    /// Create a new file system storage backend
    pub fn new<P: Into<std::path::PathBuf>>(base_path: P) -> Result<Self> {
        let path = base_path.into();
        
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&path)
            .map_err(|e| FortressError::storage(
                format!("Failed to create directory: {}", e),
                "filesystem",
                StorageErrorCode::ConnectionFailed,
            ))?;

        Ok(Self { base_path: path })
    }

    /// Get the full path for a key
    fn get_path(&self, key: &str) -> std::path::PathBuf {
        // Use SHA256 to create a safe filename
        let hash = sha2::Sha256::digest(key.as_bytes());
        let filename = format!("{:x}.data", hash);
        self.base_path.join(filename)
    }

    /// Get the metadata path for a key
    fn get_metadata_path(&self, key: &str) -> std::path::PathBuf {
        let hash = sha2::Sha256::digest(key.as_bytes());
        let filename = format!("{:x}.meta", hash);
        self.base_path.join(filename)
    }

    /// Save metadata for a key
    async fn save_metadata(&self, key: &str, metadata: &FileMetadata) -> Result<()> {
        let meta_path = self.get_metadata_path(key);
        let json = serde_json::to_string(metadata)
            .map_err(|e| FortressError::storage(
                format!("Failed to serialize metadata: {}", e),
                "filesystem",
                StorageErrorCode::InvalidOperation,
            ))?;

        tokio::fs::write(&meta_path, json)
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to write metadata: {}", e),
                "filesystem",
                StorageErrorCode::InvalidOperation,
            ))?;

        Ok(())
    }

    /// Load metadata for a key
    async fn load_metadata(&self, key: &str) -> Result<Option<FileMetadata>> {
        let meta_path = self.get_metadata_path(key);
        
        match tokio::fs::read(&meta_path).await {
            Ok(data) => {
                let metadata = serde_json::from_slice(&data)
                    .map_err(|e| FortressError::storage(
                        format!("Failed to deserialize metadata: {}", e),
                        "filesystem",
                        StorageErrorCode::CorruptedData,
                    ))?;
                Ok(Some(metadata))
            }
            Err(_) => Ok(None),
        }
    }
}

#[async_trait]
impl StorageBackend for FileSystemStorage {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = self.get_path(key);
        
        // Write the data
        tokio::fs::write(&path, value)
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to write file: {}", e),
                "filesystem",
                StorageErrorCode::InvalidOperation,
            ))?;

        // Save metadata
        let metadata = FileMetadata {
            key: key.to_string(),
            size: value.len(),
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            checksum: Some(format!("{:x}", sha2::Sha256::digest(value))),
        };

        self.save_metadata(key, &metadata).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.get_path(key);
        
        match tokio::fs::read(&path).await {
            Ok(data) => {
                // Verify checksum if available
                if let Some(metadata) = self.load_metadata(key).await? {
                    if let Some(expected_checksum) = metadata.checksum {
                        let actual_checksum = format!("{:x}", sha2::Sha256::digest(&data));
                        if actual_checksum != expected_checksum {
                            return Err(FortressError::storage(
                                "Data corruption detected: checksum mismatch",
                                "filesystem",
                                StorageErrorCode::CorruptedData,
                            ));
                        }
                    }
                }
                Ok(Some(data))
            }
            Err(_) => Ok(None),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.get_path(key);
        let meta_path = self.get_metadata_path(key);

        // Delete data file
        if let Err(e) = tokio::fs::remove_file(&path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(FortressError::storage(
                    format!("Failed to delete file: {}", e),
                    "filesystem",
                    StorageErrorCode::InvalidOperation,
                ));
            }
        }

        // Delete metadata file
        if let Err(e) = tokio::fs::remove_file(&meta_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(FortressError::storage(
                    format!("Failed to delete metadata: {}", e),
                    "filesystem",
                    StorageErrorCode::InvalidOperation,
                ));
            }
        }

        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let path = self.get_path(key);
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let mut entries = tokio::fs::read_dir(&self.base_path)
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to read directory: {}", e),
                "filesystem",
                StorageErrorCode::ConnectionFailed,
            ))?;

        let mut keys = Vec::new();
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| FortressError::storage(
                format!("Failed to read directory entry: {}", e),
                "filesystem",
                StorageErrorCode::ConnectionFailed,
            ))? {
            
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("data") {
                // Try to load metadata to get the original key
                if let Some(metadata) = self.load_metadata(&path.to_string_lossy()).await? {
                    if metadata.key.starts_with(prefix) {
                        keys.push(metadata.key);
                    }
                }
            }
        }

        Ok(keys)
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            backend_type: "filesystem".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: false,
            supports_encryption_at_rest: false,
            max_object_size: Some(1024 * 1024 * 1024), // 1GB
            metadata: HashMap::new(),
        }
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let start = std::time::Instant::now();
        
        // Try to read the directory
        let _entries = tokio::fs::read_dir(&self.base_path)
            .await
            .map_err(|e| FortressError::storage(
                format!("Health check failed: {}", e),
                "filesystem",
                StorageErrorCode::ConnectionFailed,
            ))?;

        let response_time = start.elapsed().as_millis() as u64;

        Ok(HealthStatus {
            healthy: true,
            response_time_ms: response_time,
            details: HashMap::new(),
        })
    }
}

/// File metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileMetadata {
    key: String,
    size: usize,
    created_at: chrono::DateTime<chrono::Utc>,
    modified_at: chrono::DateTime<chrono::Utc>,
    checksum: Option<String>,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend type
    pub backend_type: StorageBackendType,
    /// Backend-specific configuration
    pub config: HashMap<String, serde_json::Value>,
}

/// Storage backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackendType {
    /// In-memory storage (for testing)
    InMemory,
    /// File system storage
    FileSystem {
        /// Base directory path
        base_path: String,
    },
    /// AWS S3 storage
    S3 {
        /// Bucket name
        bucket: String,
        /// Region
        region: String,
        /// Prefix
        prefix: Option<String>,
    },
    /// Azure Blob storage
    AzureBlob {
        /// Container name
        container: String,
        /// Account name
        account: String,
    },
    /// Google Cloud Storage
    Gcs {
        /// Bucket name
        bucket: String,
        /// Prefix
        prefix: Option<String>,
    },
}

/// Factory function to create storage backends
pub async fn create_storage_backend(config: StorageConfig) -> Result<Box<dyn StorageBackend>> {
    match config.backend_type {
        StorageBackendType::InMemory => {
            Ok(Box::new(InMemoryStorage::new()))
        }
        StorageBackendType::FileSystem { base_path } => {
            Ok(Box::new(FileSystemStorage::new(base_path)?))
        }
        StorageBackendType::S3 { bucket: _, region: _, prefix: _ } => {
            // TODO: Implement S3 backend
            Err(FortressError::storage(
                "S3 backend not yet implemented",
                "s3",
                StorageErrorCode::BackendNotAvailable,
            ))
        }
        StorageBackendType::AzureBlob { container: _, account: _ } => {
            // TODO: Implement Azure Blob backend
            Err(FortressError::storage(
                "Azure Blob backend not yet implemented",
                "azure_blob",
                StorageErrorCode::BackendNotAvailable,
            ))
        }
        StorageBackendType::Gcs { bucket: _, prefix: _ } => {
            // TODO: Implement GCS backend
            Err(FortressError::storage(
                "GCS backend not yet implemented",
                "gcs",
                StorageErrorCode::BackendNotAvailable,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();
        
        // Test put and get
        storage.put("test_key", b"test_value").await.unwrap();
        let value = storage.get("test_key").await.unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));

        // Test exists
        assert!(storage.exists("test_key").await.unwrap());
        assert!(!storage.exists("nonexistent").await.unwrap());

        // Test list prefix
        storage.put("test_prefix_key1", b"value1").await.unwrap();
        storage.put("test_prefix_key2", b"value2").await.unwrap();
        let keys = storage.list_prefix("test_prefix").await.unwrap();
        assert_eq!(keys.len(), 2);

        // Test delete
        storage.delete("test_key").await.unwrap();
        assert!(!storage.exists("test_key").await.unwrap());

        // Test health check
        let health = storage.health_check().await.unwrap();
        assert!(health.healthy);
    }

    #[tokio::test]
    async fn test_filesystem_storage() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = FileSystemStorage::new(temp_dir.path()).unwrap();
        
        // Test put and get
        storage.put("test_key", b"test_value").await.unwrap();
        let value = storage.get("test_key").await.unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));

        // Test exists
        assert!(storage.exists("test_key").await.unwrap());
        assert!(!storage.exists("nonexistent").await.unwrap());

        // Test delete
        storage.delete("test_key").await.unwrap();
        assert!(!storage.exists("test_key").await.unwrap());

        // Test health check
        let health = storage.health_check().await.unwrap();
        assert!(health.healthy);

        // Test metadata
        let metadata = storage.metadata();
        assert_eq!(metadata.backend_type, "filesystem");
        assert!(!metadata.supports_transactions);
    }

    #[tokio::test]
    async fn test_filesystem_storage_integrity() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = FileSystemStorage::new(temp_dir.path()).unwrap();
        
        // Store data
        let original_data = b"important data that must not be corrupted";
        storage.put("integrity_test", original_data).await.unwrap();

        // Retrieve data (should verify checksum)
        let retrieved_data = storage.get("integrity_test").await.unwrap();
        assert_eq!(retrieved_data, Some(original_data.to_vec()));

        // Test with corrupted data (simulate by writing directly to file)
        let path = storage.get_path("integrity_test");
        tokio::fs::write(&path, b"corrupted data").await.unwrap();

        // Should detect corruption
        let result = storage.get("integrity_test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FortressError::Storage { code: StorageErrorCode::CorruptedData, .. }
        ));
    }

    #[tokio::test]
    async fn test_create_storage_backend() {
        let config = StorageConfig {
            backend_type: StorageBackendType::InMemory,
            config: HashMap::new(),
        };

        let storage = create_storage_backend(config).await.unwrap();
        let metadata = storage.metadata();
        assert_eq!(metadata.backend_type, "in_memory");

        let temp_dir = tempfile::tempdir().unwrap();
        let config = StorageConfig {
            backend_type: StorageBackendType::FileSystem {
                base_path: temp_dir.path().to_string_lossy().to_string(),
            },
            config: HashMap::new(),
        };

        let storage = create_storage_backend(config).await.unwrap();
        let metadata = storage.metadata();
        assert_eq!(metadata.backend_type, "filesystem");
    }

    #[tokio::test]
    async fn test_storage_config_serialization() {
        let config = StorageConfig {
            backend_type: StorageBackendType::FileSystem {
                base_path: "/tmp/test".to_string(),
            },
            config: HashMap::new(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: StorageConfig = serde_json::from_str(&json).unwrap();

        match deserialized.backend_type {
            StorageBackendType::FileSystem { base_path } => {
                assert_eq!(base_path, "/tmp/test");
            }
            _ => panic!("Expected FileSystem backend type"),
        }
    }
}
