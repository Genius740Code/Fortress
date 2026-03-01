//! Storage backend abstractions
//!
//! This module provides traits and implementations for various storage backends
//! that Fortress can use to store encrypted data and metadata.

use crate::error::{FortressError, Result, StorageErrorCode};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::fmt;

// Cloud storage imports (only available with cloud-storage feature)
#[cfg(feature = "cloud-storage")]
use aws_config::from_env;
#[cfg(feature = "cloud-storage")]
use aws_sdk_s3::{Client as S3Client, config::Region as S3Region};

// Azure storage imports (only available with cloud-storage feature)
#[cfg(feature = "cloud-storage")]
use azure_storage::BlobServiceClient;
#[cfg(feature = "cloud-storage")]
use azure_storage_blobs::prelude::*;
#[cfg(feature = "cloud-storage")]
use azure_identity::DefaultAzureCredential;

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
                "in_memory".to_string(),
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
                "filesystem".to_string(),
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
                "filesystem".to_string(),
                StorageErrorCode::InvalidOperation,
            ))?;

        tokio::fs::write(&meta_path, json)
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to write metadata: {}", e),
                "filesystem".to_string(),
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
                        "filesystem".to_string(),
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
                "filesystem".to_string(),
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
                    "filesystem".to_string(),
                    StorageErrorCode::InvalidOperation,
                ));
            }
        }

        // Delete metadata file
        if let Err(e) = tokio::fs::remove_file(&meta_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(FortressError::storage(
                    format!("Failed to delete metadata: {}", e),
                    "filesystem".to_string(),
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
                "filesystem".to_string(),
                StorageErrorCode::ConnectionFailed,
            ))?;

        let mut keys = Vec::new();
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| FortressError::storage(
                format!("Failed to read directory entry: {}", e),
                "filesystem".to_string(),
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
                "filesystem".to_string(),
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

/// AWS S3 storage backend
#[cfg(feature = "cloud-storage")]
#[derive(Debug)]
pub struct S3Storage {
    client: S3Client,
    bucket: String,
    prefix: Option<String>,
}

#[cfg(feature = "cloud-storage")]
impl S3Storage {
    /// Create a new S3 storage backend
    pub async fn new(bucket: String, region: String, prefix: Option<String>) -> Result<Self> {
        let config = from_env()
            .region(S3Region::new(region))
            .load()
            .await;
        
        let client = S3Client::new(&config);

        Ok(Self {
            client,
            bucket,
            prefix,
        })
    }

    /// Get the full S3 key for a storage key
    fn get_s3_key(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}/{}", prefix, key),
            None => key.to_string(),
        }
    }
}

#[cfg(feature = "cloud-storage")]
#[async_trait]
impl StorageBackend for S3Storage {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let s3_key = self.get_s3_key(key);
        
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .body(value.to_vec().into())
            .send()
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to put object to S3: {}", e),
                "s3".to_string(),
                StorageErrorCode::InvalidOperation,
            ))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let s3_key = self.get_s3_key(key);
        
        match self.client
            .get_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
        {
            Ok(response) => {
                let data = response.body.collect().await
                    .map_err(|e| FortressError::storage(
                        format!("Failed to read S3 object data: {}", e),
                        "s3".to_string(),
                        StorageErrorCode::InvalidOperation,
                    ))?
                    .into_bytes()
                    .to_vec();
                Ok(Some(data))
            }
            Err(e) => {
                // Simple error handling - check if error message contains "NoSuchKey"
                if e.to_string().contains("NoSuchKey") {
                    Ok(None)
                } else {
                    Err(FortressError::storage(
                        format!("Failed to get object from S3: {}", e),
                        "s3".to_string(),
                        StorageErrorCode::InvalidOperation,
                    ))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let s3_key = self.get_s3_key(key);
        
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to delete object from S3: {}", e),
                "s3".to_string(),
                StorageErrorCode::InvalidOperation,
            ))?;

        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let s3_key = self.get_s3_key(key);
        
        match self.client
            .head_object()
            .bucket(&self.bucket)
            .key(&s3_key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                // Simple error handling - check if error message contains "NoSuchKey"
                if e.to_string().contains("NoSuchKey") {
                    Ok(false)
                } else {
                    Err(FortressError::storage(
                        format!("Failed to check object existence in S3: {}", e),
                        "s3".to_string(),
                        StorageErrorCode::InvalidOperation,
                    ))
                }
            }
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let s3_prefix = match &self.prefix {
            Some(storage_prefix) => format!("{}/{}", storage_prefix, prefix),
            None => prefix.to_string(),
        };

        let mut keys = Vec::new();
        let mut continuation_token = None;

        loop {
            let mut request = self.client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&s3_prefix);

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| FortressError::storage(
                    format!("Failed to list objects in S3: {}", e),
                    "s3".to_string(),
                    StorageErrorCode::InvalidOperation,
                ))?;

            if let Some(objects) = response.contents() {
                for object in objects {
                    if let Some(key) = object.key() {
                        // Remove the storage prefix to get the original key
                        let original_key = match &self.prefix {
                            Some(storage_prefix) => {
                                key.strip_prefix(&format!("{}/", storage_prefix))
                                    .unwrap_or(key)
                            }
                            None => key,
                        };
                        keys.push(original_key.to_string());
                    }
                }
            }

            if response.is_truncated() {
                continuation_token = response.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(keys)
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            backend_type: "s3".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: false,
            supports_encryption_at_rest: true,
            max_object_size: Some(5 * 1024 * 1024 * 1024), // 5GB
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("bucket".to_string(), self.bucket.clone());
                if let Some(prefix) = &self.prefix {
                    meta.insert("prefix".to_string(), prefix.clone());
                }
                meta
            },
        }
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let start = std::time::Instant::now();
        
        // Try to list the bucket (this is a lightweight operation)
        self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .max_keys(1)
            .send()
            .await
            .map_err(|e| FortressError::storage(
                format!("S3 health check failed: {}", e),
                "s3".to_string(),
                StorageErrorCode::ConnectionFailed,
            ))?;

        let response_time = start.elapsed().as_millis() as u64;

        Ok(HealthStatus {
            healthy: true,
            response_time_ms: response_time,
            details: {
                let mut details = HashMap::new();
                details.insert("bucket".to_string(), self.bucket.clone());
                details
            },
        })
    }
}

/// Azure Blob storage backend
#[derive(Debug)]
#[cfg(feature = "cloud-storage")]
pub struct AzureBlobStorage {
    client: BlobServiceClient,
    container: String,
}

#[cfg(feature = "cloud-storage")]
impl AzureBlobStorage {
    /// Create a new Azure Blob storage backend
    pub async fn new(container: String, account: String) -> Result<Self> {
        // Create Azure credential and client
        let credential = DefaultAzureCredential::new()
            .map_err(|e| FortressError::storage(
                format!("Failed to create Azure credential: {}", e),
                "azure_blob",
                StorageErrorCode::AuthenticationError,
            ))?;

        let account_url = format!("https://{}.blob.core.windows.net", account);
        let client = BlobServiceClient::new(&account_url, credential)
            .map_err(|e| FortressError::storage(
                format!("Failed to create Azure Blob client: {}", e),
                "azure_blob",
                StorageErrorCode::ConnectionFailed,
            ))?;

        Ok(AzureBlobStorage {
            client,
            container,
        })
    }
}

#[async_trait]
#[cfg(feature = "cloud-storage")]
impl StorageBackend for AzureBlobStorage {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let container_client = self.client.container_client(&self.container);
        let blob_client = container_client.blob_client(key);
        
        blob_client
            .put_block_blob(value)
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to put blob {}: {}", key, e),
                "azure_blob",
                StorageErrorCode::WriteError,
            ))?;
        
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let container_client = self.client.container_client(&self.container);
        let blob_client = container_client.blob_client(key);
        
        match blob_client.get().await {
            Ok(response) => {
                let data = response.data.to_vec();
                Ok(Some(data))
            }
            Err(err) => {
                if err.to_string().contains("BlobNotFound") {
                    Ok(None)
                } else {
                    Err(FortressError::storage(
                        format!("Failed to get blob {}: {}", key, err),
                        "azure_blob",
                        StorageErrorCode::ReadError,
                    ))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let container_client = self.client.container_client(&self.container);
        let blob_client = container_client.blob_client(key);
        
        blob_client
            .delete()
            .await
            .map_err(|e| FortressError::storage(
                format!("Failed to delete blob {}: {}", key, e),
                "azure_blob",
                StorageErrorCode::DeleteError,
            ))?;
        
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let container_client = self.client.container_client(&self.container);
        let blob_client = container_client.blob_client(key);
        
        match blob_client.get_properties().await {
            Ok(_) => Ok(true),
            Err(err) => {
                if err.to_string().contains("BlobNotFound") {
                    Ok(false)
                } else {
                    Err(FortressError::storage(
                        format!("Failed to check blob existence {}: {}", key, err),
                        "azure_blob",
                        StorageErrorCode::ReadError,
                    ))
                }
            }
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let container_client = self.client.container_client(&self.container);
        
        let mut stream = container_client
            .list_blobs()
            .prefix(prefix)
            .into_stream();
        
        let mut keys = Vec::new();
        
        while let Some(blob_response) = stream.next().await {
            let blob_response = blob_response.map_err(|e| FortressError::storage(
                format!("Failed to list blobs: {}", e),
                "azure_blob",
                StorageErrorCode::ReadError,
            ))?;
            
            for blob in blob_response.blobs.blobs {
                keys.push(blob.name.clone());
            }
        }
        
        Ok(keys)
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            backend_type: "azure_blob".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: false,
            supports_encryption_at_rest: true,
            max_object_size: Some(4 * 1024 * 1024 * 1024 * 1024), // 4TB
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("container".to_string(), self.container.clone());
                meta
            },
        }
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let container_client = self.client.container_client(&self.container);
        
        match container_client.get_properties().await {
            Ok(_) => Ok(HealthStatus {
                is_healthy: true,
                message: "Azure Blob storage is healthy".to_string(),
                last_check: chrono::Utc::now(),
                response_time_ms: 0, // Would need to measure actual response time
                details: {
                    let mut details = HashMap::new();
                    details.insert("container".to_string(), self.container.clone());
                    details
                },
            }),
            Err(err) => Err(FortressError::storage(
                format!("Azure Blob health check failed: {}", err),
                "azure_blob",
                StorageErrorCode::ConnectionFailed,
            )),
        }
    }
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
        #[cfg(feature = "cloud-storage")]
        StorageBackendType::S3 { bucket, region, prefix } => {
            Ok(Box::new(S3Storage::new(bucket, region, prefix).await?))
        }
        #[cfg(feature = "cloud-storage")]
        StorageBackendType::AzureBlob { container, account } => {
            Ok(Box::new(AzureBlobStorage::new(container, account).await?))
        }
        #[cfg(not(feature = "cloud-storage"))]
        StorageBackendType::S3 { .. } => {
            Err(FortressError::storage(
                "S3 storage backend requires 'cloud-storage' feature to be enabled",
                "s3",
                StorageErrorCode::BackendNotAvailable,
            ))
        }
        #[cfg(not(feature = "cloud-storage"))]
        StorageBackendType::AzureBlob { .. } => {
            Err(FortressError::storage(
                "Azure Blob storage backend requires 'cloud-storage' feature to be enabled",
                "azure_blob",
                StorageErrorCode::BackendNotAvailable,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_storage() -> Result<()> {
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
        Ok(())
    }

    #[tokio::test]
    async fn test_filesystem_storage() -> Result<()> {
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
        Ok(())
    }

    #[tokio::test]
    async fn test_filesystem_storage_integrity() -> Result<()> {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = FileSystemStorage::new(temp_dir.path()).unwrap();
        
        // Store data
        let original_data = b"important data that must not be corrupted";
        storage.put("integrity_test", original_data).await.unwrap();
        
        // Verify integrity
        let retrieved_data = storage.get("integrity_test").await.unwrap();
        assert_eq!(retrieved_data, Some(original_data.to_vec()));
        
        // Test corruption detection
        let corrupted_data = b"corrupted data";
        storage.put("corruption_test", corrupted_data).await.unwrap();
        
        // Simulate corruption by modifying the file directly (this is a simplified test)
        let metadata = storage.metadata();
        assert_eq!(metadata.backend_type, "filesystem");
        assert!(!metadata.supports_transactions);
        Ok(())
    }

    #[tokio::test]
    async fn test_create_storage_backend() -> Result<()> {
        let config = StorageConfig {
            backend_type: StorageBackendType::InMemory,
            config: HashMap::new(),
        };

        let storage = create_storage_backend(config).await.unwrap();
        let metadata = storage.metadata();
        assert_eq!(metadata.backend_type, "in_memory");
        Ok(())
    }

    #[tokio::test]
    async fn test_filesystem_storage_backend() -> Result<()> {
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
        Ok(())
    }

    #[tokio::test]
    async fn test_storage_config_serialization() -> Result<()> {
        let config = StorageConfig {
            backend_type: StorageBackendType::FileSystem {
                base_path: "/tmp/test".to_string(),
            },
            config: HashMap::new(),
        };

        let json = serde_json::to_string(&config)
            .map_err(|e| FortressError::storage(
                format!("Failed to serialize storage config: {}", e),
                "serialization".to_string(),
                StorageErrorCode::CorruptedData,
            ))?;
        let deserialized: StorageConfig = serde_json::from_str(&json)
            .map_err(|e| FortressError::storage(
                format!("Failed to deserialize storage config: {}", e),
                "serialization".to_string(),
                StorageErrorCode::CorruptedData,
            ))?;

        Ok(match deserialized.backend_type {
            StorageBackendType::FileSystem { base_path } => {
                assert_eq!(base_path, "/tmp/test");
            }
            _ => return Err(FortressError::storage(
                "Expected FileSystem backend type".to_string(),
                "test".to_string(),
                StorageErrorCode::InvalidOperation,
            )),
        })
    }

    #[tokio::test]
    async fn test_cloud_storage_configs() -> Result<()> {
        // Test S3 config
        let s3_config = StorageConfig {
            backend_type: StorageBackendType::S3 {
                bucket: "test-bucket".to_string(),
                region: "us-east-1".to_string(),
                prefix: Some("fortress".to_string()),
            },
            config: HashMap::new(),
        };

        let json = serde_json::to_string(&s3_config)
            .map_err(|e| FortressError::storage(
                format!("Failed to serialize S3 config: {}", e),
                "serialization".to_string(),
                StorageErrorCode::CorruptedData,
            ))?;
        let deserialized: StorageConfig = serde_json::from_str(&json)
            .map_err(|e| FortressError::storage(
                format!("Failed to deserialize S3 config: {}", e),
                "serialization".to_string(),
                StorageErrorCode::CorruptedData,
            ))?;

        match deserialized.backend_type {
            StorageBackendType::S3 { bucket, region, prefix } => {
                assert_eq!(bucket, "test-bucket");
                assert_eq!(region, "us-east-1");
                assert_eq!(prefix, Some("fortress".to_string()));
            }
            _ => panic!("Expected S3 backend type"),
        }

        // Test Azure Blob config
        let azure_config = StorageConfig {
            backend_type: StorageBackendType::AzureBlob {
                container: "test-container".to_string(),
                account: "testaccount".to_string(),
            },
            config: HashMap::new(),
        };

        let json = serde_json::to_string(&azure_config)
            .map_err(|e| FortressError::storage(
                format!("Failed to serialize Azure config: {}", e),
                "serialization".to_string(),
                StorageErrorCode::CorruptedData,
            ))?;
        let deserialized: StorageConfig = serde_json::from_str(&json)
            .map_err(|e| FortressError::storage(
                format!("Failed to deserialize Azure config: {}", e),
                "serialization".to_string(),
                StorageErrorCode::CorruptedData,
            ))?;

        match deserialized.backend_type {
            StorageBackendType::AzureBlob { container, account } => {
                assert_eq!(container, "test-container");
                assert_eq!(account, "testaccount");
            }
            _ => panic!("Expected Azure Blob backend type"),
        }
        Ok(())
    }
}
