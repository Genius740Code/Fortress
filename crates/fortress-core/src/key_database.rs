//! Key database management for persistent key storage
//!
//! This module provides database-backed key storage with support for SQLite and PostgreSQL,
//! along with preloading and caching capabilities for high performance.

use crate::error::{FortressError, Result, KeyErrorCode};
use crate::key::{KeyManager, KeyId, KeyMetadata, SecureKey};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Database, Pool, Row, Sqlite, SqlitePool, Postgres, PgPool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Configuration for key database backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDatabaseConfig {
    /// Database backend type
    pub backend: KeyDatabaseBackend,
    /// Connection string for the database
    pub connection_string: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Enable key encryption at rest
    pub encrypt_at_rest: bool,
    /// Master key for database encryption (if enabled)
    pub master_key: Option<String>,
}

/// Supported database backends
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyDatabaseBackend {
    /// SQLite for embedded deployments
    Sqlite,
    /// PostgreSQL for enterprise deployments
    Postgres,
}

/// Trait for key database operations
#[async_trait]
pub trait KeyDatabase: Send + Sync + std::fmt::Debug {
    /// Store a key with metadata
    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()>;

    /// Retrieve a key and its metadata
    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>>;

    /// Delete a key
    async fn delete_key(&self, key_id: &KeyId) -> Result<()>;

    /// List all keys
    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>>;

    /// Check if a key exists
    async fn key_exists(&self, key_id: &KeyId) -> Result<bool>;

    /// Get key metadata only
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<Option<KeyMetadata>>;

    /// Preload all keys for fast startup
    async fn preload_keys(&self) -> Result<Vec<(KeyId, SecureKey, KeyMetadata)>>;

    /// Get database statistics
    async fn get_stats(&self) -> Result<KeyDatabaseStats>;

    /// Initialize database schema
    async fn initialize(&self) -> Result<()>;

    /// Health check
    async fn health_check(&self) -> Result<bool>;
}

/// Database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDatabaseStats {
    /// Total number of keys
    pub total_keys: u64,
    /// Database size in bytes
    pub database_size_bytes: u64,
    /// Number of active connections
    pub active_connections: u32,
    /// Average query time in milliseconds
    pub avg_query_time_ms: f64,
    /// Last key rotation time
    pub last_rotation_time: Option<DateTime<Utc>>,
}

/// SQLite implementation of key database
#[derive(Debug)]
pub struct SqliteKeyDatabase {
    pool: Pool<Sqlite>,
    encrypt_at_rest: bool,
    master_key: Option<String>,
}

impl SqliteKeyDatabase {
    /// Create a new SQLite key database
    pub async fn new(config: KeyDatabaseConfig) -> Result<Self> {
        let pool = SqlitePool::connect(&config.connection_string)
            .await
            .map_err(|e| FortressError::key_management(
                format!("Failed to connect to SQLite: {}", e),
                None,
                KeyErrorCode::StorageError,
            ))?;

        Ok(Self {
            pool,
            encrypt_at_rest: config.encrypt_at_rest,
            master_key: config.master_key,
        })
    }

    /// Initialize database schema
    async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY,
                key_data BLOB NOT NULL,
                metadata TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            );
            
            CREATE INDEX IF NOT EXISTS idx_keys_expires_at ON keys(expires_at);
            CREATE INDEX IF NOT EXISTS idx_keys_created_at ON keys(created_at);
            CREATE INDEX IF NOT EXISTS idx_keys_version ON keys(version);
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to initialize SQLite schema: {}", e),
            None,
            KeyErrorCode::StorageError,
        ))?;

        Ok(())
    }

    /// Encrypt key data if encryption at rest is enabled
    fn encrypt_key_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.encrypt_at_rest {
            return Ok(data.to_vec());
        }

        // Simple XOR encryption for demonstration
        // In production, use proper encryption like AES-256-GCM
        if let Some(ref master_key) = self.master_key {
            let key_bytes = master_key.as_bytes();
            let mut encrypted = Vec::with_capacity(data.len());
            for (i, &byte) in data.iter().enumerate() {
                encrypted.push(byte ^ key_bytes[i % key_bytes.len()]);
            }
            Ok(encrypted)
        } else {
            Err(FortressError::key_management(
                "Encryption at rest enabled but no master key provided",
                None,
                KeyErrorCode::InvalidKeyFormat,
            ))
        }
    }

    /// Decrypt key data if encryption at rest is enabled
    fn decrypt_key_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.encrypt_at_rest {
            return Ok(data.to_vec());
        }

        if let Some(ref master_key) = self.master_key {
            let key_bytes = master_key.as_bytes();
            let mut decrypted = Vec::with_capacity(data.len());
            for (i, &byte) in data.iter().enumerate() {
                decrypted.push(byte ^ key_bytes[i % key_bytes.len()]);
            }
            Ok(decrypted)
        } else {
            Err(FortressError::key_management(
                "Encryption at rest enabled but no master key provided",
                None,
                KeyErrorCode::InvalidKeyFormat,
            ))
        }
    }
}

#[async_trait]
impl KeyDatabase for SqliteKeyDatabase {
    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        let encrypted_key_data = self.encrypt_key_data(&key.to_vec())?;
        let metadata_json = serde_json::to_string(metadata)
            .map_err(|e| FortressError::key_management(
                format!("Failed to serialize metadata: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::SerializationError,
            ))?;

        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO keys 
            (key_id, key_data, metadata, created_at, updated_at, expires_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(key_id)
        .bind(encrypted_key_data)
        .bind(metadata_json)
        .bind(metadata.created_at)
        .bind(now)
        .bind(metadata.expires_at)
        .bind(metadata.version)
        .execute(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to store key in SQLite: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        Ok(())
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        let row = sqlx::query(
            "SELECT key_data, metadata FROM keys WHERE key_id = ? AND expires_at > ?"
        )
        .bind(key_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to retrieve key from SQLite: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        if let Some(row) = row {
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data);

            let metadata_json: String = row.get("metadata");
            let metadata = serde_json::from_str(&metadata_json)
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
        let result = sqlx::query("DELETE FROM keys WHERE key_id = ?")
            .bind(key_id)
            .execute(&self.pool)
            .await
            .map_err(|e| FortressError::key_management(
                format!("Failed to delete key from SQLite: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::StorageError,
            ))?;

        if result.rows_affected() == 0 {
            return Err(FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ));
        }

        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let rows = sqlx::query(
            "SELECT key_id, metadata FROM keys WHERE expires_at > ? ORDER BY created_at"
        )
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to list keys from SQLite: {}", e),
            None,
            KeyErrorCode::StorageError,
        ))?;

        let mut keys = Vec::new();
        for row in rows {
            let key_id: String = row.get("key_id");
            let metadata_json: String = row.get("metadata");
            let metadata = serde_json::from_str(&metadata_json)
                .map_err(|e| FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                ))?;

            keys.push((key_id, metadata));
        }

        Ok(keys)
    }

    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        let result = sqlx::query(
            "SELECT 1 FROM keys WHERE key_id = ? AND expires_at > ? LIMIT 1"
        )
        .bind(key_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to check key existence in SQLite: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        Ok(result.is_some())
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<Option<KeyMetadata>> {
        let row = sqlx::query(
            "SELECT metadata FROM keys WHERE key_id = ? AND expires_at > ?"
        )
        .bind(key_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to get key metadata from SQLite: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        if let Some(row) = row {
            let metadata_json: String = row.get("metadata");
            let metadata = serde_json::from_str(&metadata_json)
                .map_err(|e| FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                ))?;

            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    async fn preload_keys(&self) -> Result<Vec<(KeyId, SecureKey, KeyMetadata)>> {
        let rows = sqlx::query(
            "SELECT key_id, key_data, metadata FROM keys WHERE expires_at > ? ORDER BY created_at"
        )
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to preload keys from SQLite: {}", e),
            None,
            KeyErrorCode::StorageError,
        ))?;

        let mut keys = Vec::new();
        for row in rows {
            let key_id: String = row.get("key_id");
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data);

            let metadata_json: String = row.get("metadata");
            let metadata = serde_json::from_str(&metadata_json)
                .map_err(|e| FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                ))?;

            keys.push((key_id, key, metadata));
        }

        Ok(keys)
    }

    async fn get_stats(&self) -> Result<KeyDatabaseStats> {
        let total_keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM keys WHERE expires_at > ?")
            .bind(Utc::now())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| FortressError::key_management(
                format!("Failed to get key count from SQLite: {}", e),
                None,
                KeyErrorCode::StorageError,
            ))?;

        // Get database size (SQLite specific)
        let database_size_bytes: i64 = sqlx::query_scalar("SELECT SUM(LENGTH(key_data) + LENGTH(metadata)) FROM keys")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        Ok(KeyDatabaseStats {
            total_keys: total_keys as u64,
            database_size_bytes: database_size_bytes as u64,
            active_connections: self.pool.size() as u32,
            avg_query_time_ms: 0.0, // Would need to implement query timing
            last_rotation_time: None, // Would need to track rotation times
        })
    }

    async fn initialize(&self) -> Result<()> {
        self.init_schema().await
    }

    async fn health_check(&self) -> Result<bool> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| true)
            .map_err(|e| FortressError::key_management(
                format!("Database health check failed: {}", e),
                None,
                KeyErrorCode::StorageError,
            ))
    }
}

/// PostgreSQL implementation of key database
#[cfg(feature = "postgres")]
#[derive(Debug)]
pub struct PostgresKeyDatabase {
    pool: sqlx::Pool<sqlx::Postgres>,
    encrypt_at_rest: bool,
    master_key: Option<String>,
}

#[cfg(feature = "postgres")]
impl PostgresKeyDatabase {
    /// Create a new PostgreSQL key database
    pub async fn new(config: KeyDatabaseConfig) -> Result<Self> {
        let pool = sqlx::postgres::PgPool::connect(&config.connection_string)
            .await
            .map_err(|e| FortressError::key_management(
                format!("Failed to connect to PostgreSQL: {}", e),
                None,
                KeyErrorCode::StorageError,
            ))?;

        Ok(Self {
            pool,
            encrypt_at_rest: config.encrypt_at_rest,
            master_key: config.master_key,
        })
    }

    /// Initialize database schema
    async fn init_schema(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY,
                key_data BYTEA NOT NULL,
                metadata JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            );
            
            CREATE INDEX IF NOT EXISTS idx_keys_expires_at ON keys(expires_at);
            CREATE INDEX IF NOT EXISTS idx_keys_created_at ON keys(created_at);
            CREATE INDEX IF NOT EXISTS idx_keys_version ON keys(version);
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to initialize PostgreSQL schema: {}", e),
            None,
            KeyErrorCode::StorageError,
        ))?;

        Ok(())
    }

    /// Encrypt key data if encryption at rest is enabled
    fn encrypt_key_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.encrypt_at_rest {
            return Ok(data.to_vec());
        }

        if let Some(ref master_key) = self.master_key {
            let key_bytes = master_key.as_bytes();
            let mut encrypted = Vec::with_capacity(data.len());
            for (i, &byte) in data.iter().enumerate() {
                encrypted.push(byte ^ key_bytes[i % key_bytes.len()]);
            }
            Ok(encrypted)
        } else {
            Err(FortressError::key_management(
                "Encryption at rest enabled but no master key provided",
                None,
                KeyErrorCode::InvalidKeyFormat,
            ))
        }
    }

    /// Decrypt key data if encryption at rest is enabled
    fn decrypt_key_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.encrypt_at_rest {
            return Ok(data.to_vec());
        }

        if let Some(ref master_key) = self.master_key {
            let key_bytes = master_key.as_bytes();
            let mut decrypted = Vec::with_capacity(data.len());
            for (i, &byte) in data.iter().enumerate() {
                decrypted.push(byte ^ key_bytes[i % key_bytes.len()]);
            }
            Ok(decrypted)
        } else {
            Err(FortressError::key_management(
                "Encryption at rest enabled but no master key provided",
                None,
                KeyErrorCode::InvalidKeyFormat,
            ))
        }
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl KeyDatabase for PostgresKeyDatabase {
    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
        let encrypted_key_data = self.encrypt_key_data(&key.to_vec())?;
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO keys 
            (key_id, key_data, metadata, created_at, updated_at, expires_at, version)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (key_id) DO UPDATE SET
                key_data = EXCLUDED.key_data,
                metadata = EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at,
                expires_at = EXCLUDED.expires_at,
                version = EXCLUDED.version
            "#
        )
        .bind(key_id)
        .bind(encrypted_key_data)
        .bind(serde_json::to_value(metadata).map_err(|e| FortressError::key_management(
            format!("Failed to serialize metadata: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::SerializationError,
        ))?)
        .bind(metadata.created_at)
        .bind(now)
        .bind(metadata.expires_at)
        .bind(metadata.version)
        .execute(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to store key in PostgreSQL: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        Ok(())
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        let row = sqlx::query(
            "SELECT key_data, metadata FROM keys WHERE key_id = $1 AND expires_at > $2"
        )
        .bind(key_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to retrieve key from PostgreSQL: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        if let Some(row) = row {
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data)
                .map_err(|e| FortressError::key_management(
                    format!("Failed to reconstruct key: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::InvalidKeyFormat,
                ))?;

            let metadata: KeyMetadata = serde_json::from_value(row.get("metadata"))
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
        let result = sqlx::query("DELETE FROM keys WHERE key_id = $1")
            .bind(key_id)
            .execute(&self.pool)
            .await
            .map_err(|e| FortressError::key_management(
                format!("Failed to delete key from PostgreSQL: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::StorageError,
            ))?;

        if result.rows_affected() == 0 {
            return Err(FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ));
        }

        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let rows = sqlx::query(
            "SELECT key_id, metadata FROM keys WHERE expires_at > $1 ORDER BY created_at"
        )
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to list keys from PostgreSQL: {}", e),
            None,
            KeyErrorCode::StorageError,
        ))?;

        let mut keys = Vec::new();
        for row in rows {
            let key_id: String = row.get("key_id");
            let metadata: KeyMetadata = serde_json::from_value(row.get("metadata"))
                .map_err(|e| FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                ))?;

            keys.push((key_id, metadata));
        }

        Ok(keys)
    }

    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        let result = sqlx::query(
            "SELECT 1 FROM keys WHERE key_id = $1 AND expires_at > $2 LIMIT 1"
        )
        .bind(key_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to check key existence in PostgreSQL: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        Ok(result.is_some())
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<Option<KeyMetadata>> {
        let row = sqlx::query(
            "SELECT metadata FROM keys WHERE key_id = $1 AND expires_at > $2"
        )
        .bind(key_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to get key metadata from PostgreSQL: {}", e),
            Some(key_id.clone()),
            KeyErrorCode::StorageError,
        ))?;

        if let Some(row) = row {
            let metadata: KeyMetadata = serde_json::from_value(row.get("metadata"))
                .map_err(|e| FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                ))?;

            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    async fn preload_keys(&self) -> Result<Vec<(KeyId, SecureKey, KeyMetadata)>> {
        let rows = sqlx::query(
            "SELECT key_id, key_data, metadata FROM keys WHERE expires_at > $1 ORDER BY created_at"
        )
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| FortressError::key_management(
            format!("Failed to preload keys from PostgreSQL: {}", e),
            None,
            KeyErrorCode::StorageError,
        ))?;

        let mut keys = Vec::new();
        for row in rows {
            let key_id: String = row.get("key_id");
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data)
                .map_err(|e| FortressError::key_management(
                    format!("Failed to reconstruct key: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::InvalidKeyFormat,
                ))?;

            let metadata: KeyMetadata = serde_json::from_value(row.get("metadata"))
                .map_err(|e| FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                ))?;

            keys.push((key_id, key, metadata));
        }

        Ok(keys)
    }

    async fn get_stats(&self) -> Result<KeyDatabaseStats> {
        let total_keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM keys WHERE expires_at > $1")
            .bind(Utc::now())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| FortressError::key_management(
                format!("Failed to get key count from PostgreSQL: {}", e),
                None,
                KeyErrorCode::StorageError,
            ))?;

        // Get database size
        let database_size_bytes: i64 = sqlx::query_scalar("SELECT SUM(LENGTH(key_data) + OCTET_LENGTH(metadata::text)) FROM keys")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        Ok(KeyDatabaseStats {
            total_keys: total_keys as u64,
            database_size_bytes: database_size_bytes as u64,
            active_connections: self.pool.size() as u32,
            avg_query_time_ms: 0.0,
            last_rotation_time: None,
        })
    }

    async fn initialize(&self) -> Result<()> {
        self.init_schema().await
    }

    async fn health_check(&self) -> Result<bool> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map(|_| true)
            .map_err(|e| FortressError::key_management(
                format!("Database health check failed: {}", e),
                None,
                KeyErrorCode::StorageError,
            ))
    }
}

/// Factory function to create key database based on configuration
pub async fn create_key_database(config: KeyDatabaseConfig) -> Result<Box<dyn KeyDatabase>> {
    match config.backend {
        KeyDatabaseBackend::Sqlite => {
            let db = SqliteKeyDatabase::new(config).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        #[cfg(feature = "postgres")]
        KeyDatabaseBackend::Postgres => {
            let db = PostgresKeyDatabase::new(config).await?;
            db.initialize().await?;
            Ok(Box::new(db))
        }
        #[cfg(not(feature = "postgres"))]
        KeyDatabaseBackend::Postgres => {
            Err(FortressError::key_management(
                "PostgreSQL support not enabled. Enable the 'postgres' feature.",
                None,
                KeyErrorCode::StorageError,
            ))
        }
    }
}
