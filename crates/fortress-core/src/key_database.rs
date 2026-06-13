//! Key database management for persistent key storage
//!
//! This module provides database-backed key storage with support for SQLite and PostgreSQL,
//! along with preloading and caching capabilities for high performance.

use crate::error::{FortressError, KeyErrorCode, Result};
use crate::key::{KeyId, KeyMetadata, SecureKey};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "postgres")]
use sqlx::{PgPool, Postgres};
use sqlx::{Pool, Row, Sqlite, SqlitePool};

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
    async fn store_key(
        &self,
        key_id: &KeyId,
        key: &SecureKey,
        metadata: &KeyMetadata,
    ) -> Result<()>;

    /// Retrieve a key and its metadata
    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>>;

    /// Delete a key
    async fn delete_key(&self, key_id: &KeyId) -> Result<()>;

    /// List all keys
    async fn list_keys(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<(KeyId, KeyMetadata)>>;

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
#[derive(Debug, Clone)]
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
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to connect to SQLite: {}", e),
                    None,
                    KeyErrorCode::StorageError,
                )
            })?;

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
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to initialize SQLite schema: {}", e),
                None,
                KeyErrorCode::StorageError,
            )
        })?;

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
    async fn store_key(
        &self,
        key_id: &KeyId,
        key: &SecureKey,
        metadata: &KeyMetadata,
    ) -> Result<()> {
        let encrypted_key_data = self.encrypt_key_data(&key.to_vec())?;
        let metadata_json = serde_json::to_string(metadata).map_err(|e| {
            FortressError::key_management(
                format!("Failed to serialize metadata: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::SerializationError,
            )
        })?;

        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO keys 
            (key_id, key_data, metadata, created_at, updated_at, expires_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
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
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to store key in SQLite: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::StorageError,
            )
        })?;

        Ok(())
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        let row =
            sqlx::query("SELECT key_data, metadata FROM keys WHERE key_id = ? AND expires_at > ?")
                .bind(key_id)
                .bind(Utc::now())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    FortressError::key_management(
                        format!("Failed to retrieve key from SQLite: {}", e),
                        Some(key_id.clone()),
                        KeyErrorCode::StorageError,
                    )
                })?;

        if let Some(row) = row {
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data);

            let metadata_json: String = row.get("metadata");
            let metadata = serde_json::from_str(&metadata_json).map_err(|e| {
                FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                )
            })?;

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
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to delete key from SQLite: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::StorageError,
                )
            })?;

        if result.rows_affected() == 0 {
            return Err(FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ));
        }

        Ok(())
    }

    async fn list_keys(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let limit = limit.unwrap_or(1000); // Default limit
        let offset = offset.unwrap_or(0);

        let rows = sqlx::query(
            "SELECT key_id, metadata FROM keys WHERE expires_at > ? ORDER BY created_at LIMIT ? OFFSET ?"
        )
        .bind(Utc::now())
        .bind(limit)
        .bind(offset)
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
            let metadata = serde_json::from_str(&metadata_json).map_err(|e| {
                FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                )
            })?;

            keys.push((key_id, metadata));
        }

        Ok(keys)
    }

    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        let result = sqlx::query("SELECT 1 FROM keys WHERE key_id = ? AND expires_at > ? LIMIT 1")
            .bind(key_id)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to check key existence in SQLite: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::StorageError,
                )
            })?;

        Ok(result.is_some())
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<Option<KeyMetadata>> {
        let row = sqlx::query("SELECT metadata FROM keys WHERE key_id = ? AND expires_at > ?")
            .bind(key_id)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to get key metadata from SQLite: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::StorageError,
                )
            })?;

        if let Some(row) = row {
            let metadata_json: String = row.get("metadata");
            let metadata = serde_json::from_str(&metadata_json).map_err(|e| {
                FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                )
            })?;

            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    async fn preload_keys(&self) -> Result<Vec<(KeyId, SecureKey, KeyMetadata)>> {
        let rows = sqlx::query(
            "SELECT key_id, key_data, metadata FROM keys WHERE expires_at > ? ORDER BY created_at",
        )
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to preload keys from SQLite: {}", e),
                None,
                KeyErrorCode::StorageError,
            )
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let key_id: String = row.get("key_id");
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data);

            let metadata_json: String = row.get("metadata");
            let metadata = serde_json::from_str(&metadata_json).map_err(|e| {
                FortressError::key_management(
                    format!("Failed to deserialize metadata: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::SerializationError,
                )
            })?;

            keys.push((key_id, key, metadata));
        }

        Ok(keys)
    }

    async fn get_stats(&self) -> Result<KeyDatabaseStats> {
        let total_keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM keys WHERE expires_at > ?")
            .bind(Utc::now())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to get key count from SQLite: {}", e),
                    None,
                    KeyErrorCode::StorageError,
                )
            })?;

        // Get database size (SQLite specific)
        let database_size_bytes: i64 =
            sqlx::query_scalar("SELECT SUM(LENGTH(key_data) + LENGTH(metadata)) FROM keys")
                .fetch_one(&self.pool)
                .await
                .unwrap_or(0);

        Ok(KeyDatabaseStats {
            total_keys: total_keys as u64,
            database_size_bytes: database_size_bytes as u64,
            active_connections: self.pool.size() as u32,
            avg_query_time_ms: 0.0,   // Would need to implement query timing
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
            .map_err(|e| {
                FortressError::key_management(
                    format!("Database health check failed: {}", e),
                    None,
                    KeyErrorCode::StorageError,
                )
            })
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
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to connect to PostgreSQL: {}", e),
                    None,
                    KeyErrorCode::StorageError,
                )
            })?;

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
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to initialize PostgreSQL schema: {}", e),
                None,
                KeyErrorCode::StorageError,
            )
        })?;

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
    async fn store_key(
        &self,
        key_id: &KeyId,
        key: &SecureKey,
        metadata: &KeyMetadata,
    ) -> Result<()> {
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
            "#,
        )
        .bind(key_id)
        .bind(encrypted_key_data)
        .bind(serde_json::to_value(metadata).map_err(|e| {
            FortressError::key_management(
                format!("Failed to serialize metadata: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::SerializationError,
            )
        })?)
        .bind(metadata.created_at)
        .bind(now)
        .bind(metadata.expires_at)
        .bind(metadata.version)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to store key in PostgreSQL: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::StorageError,
            )
        })?;

        Ok(())
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        let row = sqlx::query(
            "SELECT key_data, metadata FROM keys WHERE key_id = $1 AND expires_at > $2",
        )
        .bind(key_id)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to retrieve key from PostgreSQL: {}", e),
                Some(key_id.clone()),
                KeyErrorCode::StorageError,
            )
        })?;

        if let Some(row) = row {
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data).map_err(|e| {
                FortressError::key_management(
                    format!("Failed to reconstruct key: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::InvalidKeyFormat,
                )
            })?;

            let metadata: KeyMetadata =
                serde_json::from_value(row.get("metadata")).map_err(|e| {
                    FortressError::key_management(
                        format!("Failed to deserialize metadata: {}", e),
                        Some(key_id.clone()),
                        KeyErrorCode::SerializationError,
                    )
                })?;

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
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to delete key from PostgreSQL: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::StorageError,
                )
            })?;

        if result.rows_affected() == 0 {
            return Err(FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.clone()),
                KeyErrorCode::KeyNotFound,
            ));
        }

        Ok(())
    }

    async fn list_keys(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let limit = limit.unwrap_or(1000); // Default limit
        let offset = offset.unwrap_or(0);

        let rows = sqlx::query(
            "SELECT key_id, metadata FROM keys WHERE expires_at > $1 ORDER BY created_at LIMIT $2 OFFSET $3",
        )
        .bind(Utc::now())
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to list keys from PostgreSQL: {}", e),
                None,
                KeyErrorCode::StorageError,
            )
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let key_id: String = row.get("key_id");
            let metadata: KeyMetadata =
                serde_json::from_value(row.get("metadata")).map_err(|e| {
                    FortressError::key_management(
                        format!("Failed to deserialize metadata: {}", e),
                        Some(key_id.clone()),
                        KeyErrorCode::SerializationError,
                    )
                })?;

            keys.push((key_id, metadata));
        }

        Ok(keys)
    }

    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        let result =
            sqlx::query("SELECT 1 FROM keys WHERE key_id = $1 AND expires_at > $2 LIMIT 1")
                .bind(key_id)
                .bind(Utc::now())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    FortressError::key_management(
                        format!("Failed to check key existence in PostgreSQL: {}", e),
                        Some(key_id.clone()),
                        KeyErrorCode::StorageError,
                    )
                })?;

        Ok(result.is_some())
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<Option<KeyMetadata>> {
        let row = sqlx::query("SELECT metadata FROM keys WHERE key_id = $1 AND expires_at > $2")
            .bind(key_id)
            .bind(Utc::now())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to get key metadata from PostgreSQL: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::StorageError,
                )
            })?;

        if let Some(row) = row {
            let metadata: KeyMetadata =
                serde_json::from_value(row.get("metadata")).map_err(|e| {
                    FortressError::key_management(
                        format!("Failed to deserialize metadata: {}", e),
                        Some(key_id.clone()),
                        KeyErrorCode::SerializationError,
                    )
                })?;

            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    async fn preload_keys(&self) -> Result<Vec<(KeyId, SecureKey, KeyMetadata)>> {
        let rows = sqlx::query(
            "SELECT key_id, key_data, metadata FROM keys WHERE expires_at > $1 ORDER BY created_at",
        )
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            FortressError::key_management(
                format!("Failed to preload keys from PostgreSQL: {}", e),
                None,
                KeyErrorCode::StorageError,
            )
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let key_id: String = row.get("key_id");
            let encrypted_key_data: Vec<u8> = row.get("key_data");
            let key_data = self.decrypt_key_data(&encrypted_key_data)?;
            let key = SecureKey::from_bytes(&key_data).map_err(|e| {
                FortressError::key_management(
                    format!("Failed to reconstruct key: {}", e),
                    Some(key_id.clone()),
                    KeyErrorCode::InvalidKeyFormat,
                )
            })?;

            let metadata: KeyMetadata =
                serde_json::from_value(row.get("metadata")).map_err(|e| {
                    FortressError::key_management(
                        format!("Failed to deserialize metadata: {}", e),
                        Some(key_id.clone()),
                        KeyErrorCode::SerializationError,
                    )
                })?;

            keys.push((key_id, key, metadata));
        }

        Ok(keys)
    }

    async fn get_stats(&self) -> Result<KeyDatabaseStats> {
        let total_keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM keys WHERE expires_at > $1")
            .bind(Utc::now())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                FortressError::key_management(
                    format!("Failed to get key count from PostgreSQL: {}", e),
                    None,
                    KeyErrorCode::StorageError,
                )
            })?;

        // Get database size
        let database_size_bytes: i64 = sqlx::query_scalar(
            "SELECT SUM(LENGTH(key_data) + OCTET_LENGTH(metadata::text)) FROM keys",
        )
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
            .map_err(|e| {
                FortressError::key_management(
                    format!("Database health check failed: {}", e),
                    None,
                    KeyErrorCode::StorageError,
                )
            })
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
        KeyDatabaseBackend::Postgres => Err(FortressError::key_management(
            "PostgreSQL support not enabled. Enable the 'postgres' feature.",
            None,
            KeyErrorCode::StorageError,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes256gcm_wrapper::Aes256GcmWrapper;
    use crate::encryption::EncryptionAlgorithm;
    use crate::encryption::PerformanceProfile;
    use crate::error::{FortressError, Result, StorageErrorCode};
    use crate::key::{KeyId, KeyMetadata, KeyPurpose};
    use chrono::Utc;
    use std::path::Path;
    use tempfile::tempdir;

    /// Create a test database configuration
    async fn create_test_database() -> Result<SqliteKeyDatabase> {
        let temp_dir = tempdir().map_err(|e| {
            FortressError::storage(
                format!("Failed to create temp dir: {}", e),
                "tempdir".to_string(),
                StorageErrorCode::IoError,
            )
        })?;

        let db_path = temp_dir.path().join("test_keys.db");
        let connection_string = format!("sqlite:{}", db_path.display());

        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string,
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false, // Disable for testing
            master_key: None,
        };

        SqliteKeyDatabase::new(config).await
    }

    /// Create test key data
    fn create_test_key_data(id: &str, version: u32) -> (SecureKey, KeyMetadata) {
        let algorithm = Aes256GcmWrapper::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate test key");
        let metadata = KeyMetadata::new(
            id.to_string(),
            algorithm.name().to_string(),
            version,
            Utc::now(),
            Utc::now() + chrono::Duration::days(30),
            format!("{:?}", KeyPurpose::DataEncryption),
            PerformanceProfile::Balanced,
        );
        (key, metadata)
    }

    #[tokio::test]
    async fn test_sqlite_database_creation() -> Result<()> {
        let db = create_test_database().await?;

        // Initialize database
        db.initialize().await?;

        // Check initial stats
        let stats = db.get_stats().await?;
        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.active_connections, 1); // At least one connection for initialization

        // Health check
        let healthy = db.health_check().await?;
        assert!(healthy);

        Ok(())
    }

    #[tokio::test]
    async fn test_store_and_retrieve_key() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        let (key, metadata) = create_test_key_data("test_key_1", 1);
        let key_id = "test_key_1".to_string();

        // Store key
        db.store_key(&key_id, &key, &metadata).await?;

        // Retrieve key
        let result = db.retrieve_key(&key_id).await?;
        assert!(result.is_some());

        let (retrieved_key, retrieved_metadata) = result.unwrap();
        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());
        assert_eq!(metadata.algorithm, retrieved_metadata.algorithm);
        assert_eq!(metadata.version, retrieved_metadata.version);
        assert_eq!(metadata.purpose, retrieved_metadata.purpose);

        Ok(())
    }

    #[tokio::test]
    async fn test_key_exists() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        let (key, metadata) = create_test_key_data("exists_test", 1);
        let key_id = String::from("exists_test");

        // Key should not exist initially
        assert!(!db.key_exists(&key_id).await?);

        // Store key
        db.store_key(&key_id, &key, &metadata).await?;

        // Key should exist now
        assert!(db.key_exists(&key_id).await?);

        // Non-existent key should not exist
        assert!(!db.key_exists(&String::from("non_existent")).await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_key() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        let (key, metadata) = create_test_key_data("delete_test", 1);
        let key_id = String::from("delete_test");

        // Store key
        db.store_key(&key_id, &key, &metadata).await?;
        assert!(db.key_exists(&key_id).await?);

        // Delete key
        db.delete_key(&key_id).await?;
        assert!(!db.key_exists(&key_id).await?);

        // Verify retrieval fails
        let result = db.retrieve_key(&key_id).await?;
        assert!(result.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_list_keys() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        // Store multiple keys
        for i in 1..=5 {
            let (key, metadata) = create_test_key_data(&format!("list_test_{}", i), i);
            let key_id = String::from(&format!("list_test_{}", i));
            db.store_key(&key_id, &key, &metadata).await?;
        }

        // List all keys
        let keys = db.list_keys(None, None).await?;
        assert_eq!(keys.len(), 5);

        // List with limit
        let limited_keys = db.list_keys(Some(3), None).await?;
        assert_eq!(limited_keys.len(), 3);

        // List with offset
        let offset_keys = db.list_keys(None, Some(2)).await?;
        assert_eq!(offset_keys.len(), 3); // 5 total - 2 offset = 3 remaining

        // List with both limit and offset
        let paginated_keys = db.list_keys(Some(2), Some(1)).await?;
        assert_eq!(paginated_keys.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_key_metadata() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        let (key, metadata) = create_test_key_data("metadata_test", 1);
        let key_id = String::from("metadata_test");

        // Store key
        db.store_key(&key_id, &key, &metadata).await?;

        // Get metadata
        let retrieved_metadata = db.get_key_metadata(&key_id).await?;
        assert!(retrieved_metadata.is_some());

        let retrieved_metadata = retrieved_metadata.unwrap();
        assert_eq!(metadata.algorithm, retrieved_metadata.algorithm);
        assert_eq!(metadata.version, retrieved_metadata.version);
        assert_eq!(metadata.purpose, retrieved_metadata.purpose);
        assert_eq!(metadata.created_at, retrieved_metadata.created_at);

        // Get metadata for non-existent key
        let non_existent_metadata = db.get_key_metadata(&String::from("non_existent")).await?;
        assert!(non_existent_metadata.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_preload_keys() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        // Store multiple keys
        for i in 1..=5 {
            let (key, metadata) = create_test_key_data(&format!("preload_test_{}", i), i);
            let key_id = String::from(&format!("preload_test_{}", i));
            db.store_key(&key_id, &key, &metadata).await?;
        }

        // Preload all keys
        let preloaded_keys = db.preload_keys().await?;
        assert_eq!(preloaded_keys.len(), 5);

        // Verify all keys are present and correct
        for (i, (key_id, key, metadata)) in preloaded_keys.iter().enumerate() {
            let expected_id = format!("preload_test_{}", i + 1);
            assert_eq!(key_id.to_string(), expected_id);
            assert!(!key.is_empty());
            assert_eq!(metadata.version, (i + 1) as u32);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_database_stats() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        // Initial stats
        let initial_stats = db.get_stats().await?;
        assert_eq!(initial_stats.total_keys, 0);

        // Store some keys
        for i in 1..=3 {
            let (key, metadata) = create_test_key_data(&format!("stats_test_{}", i), i);
            let key_id = String::from(&format!("stats_test_{}", i));
            db.store_key(&key_id, &key, &metadata).await?;
        }

        // Updated stats
        let updated_stats = db.get_stats().await?;
        assert_eq!(updated_stats.total_keys, 3);
        assert!(updated_stats.database_size_bytes > 0);
        assert!(updated_stats.avg_query_time_ms >= 0.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_key_update() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        let (key1, metadata1) = create_test_key_data("update_test", 1);
        let (key2, metadata2) = create_test_key_data("update_test", 2);
        let key_id = String::from("update_test");

        // Store initial key
        db.store_key(&key_id, &key1, &metadata1).await?;

        // Retrieve and verify
        let result = db.retrieve_key(&key_id).await?;
        assert!(result.is_some());
        let (retrieved_key, retrieved_metadata) = result.unwrap();
        assert_eq!(retrieved_metadata.version, 1);

        // Update with new key and metadata
        db.store_key(&key_id, &key2, &metadata2).await?;

        // Retrieve and verify update
        let result = db.retrieve_key(&key_id).await?;
        assert!(result.is_some());
        let (updated_key, updated_metadata) = result.unwrap();
        assert_eq!(updated_metadata.version, 2);
        assert_ne!(retrieved_key.as_bytes(), updated_key.as_bytes());

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_operations() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        // Spawn multiple concurrent tasks
        let mut handles = Vec::new();

        for i in 0..10 {
            let db_clone = db.clone();
            let handle = tokio::spawn(async move {
                let (key, metadata) = create_test_key_data(&format!("concurrent_test_{}", i), i);
                let key_id = String::from(&format!("concurrent_test_{}", i));

                // Store key
                let store_result = db_clone.store_key(&key_id, &key, &metadata).await;
                assert!(store_result.is_ok());

                // Retrieve key
                let retrieve_result = db_clone.retrieve_key(&key_id).await;
                assert!(retrieve_result.is_ok());
                assert!(retrieve_result.unwrap().is_some());

                // Check existence
                let exists_result = db_clone.key_exists(&key_id).await;
                assert!(exists_result.is_ok());
                assert!(exists_result.unwrap());
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Verify all keys were stored
        let keys = db.list_keys(None, None).await?;
        assert_eq!(keys.len(), 10);

        Ok(())
    }

    #[tokio::test]
    async fn test_large_key_handling() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        // Create a large key
        let large_key_data = vec![0u8; 1024 * 1024]; // 1MB key
        let large_key = SecureKey::from_bytes(&large_key_data);

        let metadata = KeyMetadata::new(
            "test_key_2".to_string(),
            "AES-256-GCM".to_string(),
            1,
            Utc::now(),
            Utc::now() + chrono::Duration::days(30),
            format!("{:?}", KeyPurpose::DataEncryption),
            PerformanceProfile::Balanced,
        );

        // Store large key
        db.store_key(&String::from("large_key_test"), &large_key, &metadata)
            .await?;

        // Retrieve large key
        let result = db.retrieve_key(&String::from("large_key_test")).await?;
        assert!(result.is_some());

        let (retrieved_key, _) = result.unwrap();
        assert_eq!(retrieved_key.len(), large_key_data.len());
        assert_eq!(retrieved_key.as_bytes(), large_key_data);

        Ok(())
    }

    #[tokio::test]
    async fn test_special_characters_in_key_id() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        let special_ids = [
            "key-with-dashes",
            "key_with_underscores",
            "key.with.dots",
            "key/with/slashes",
            "key\\with\\backslashes",
            "key with spaces",
            "key@with@symbols",
            "key#with#hash",
            "key$with$dollar",
            "key%with%percent",
        ];

        for (i, special_id) in special_ids.iter().enumerate() {
            let (key, metadata) = create_test_key_data(special_id, i as u32 + 1);
            let key_id = (*special_id).to_string();

            // Store key
            db.store_key(&key_id, &key, &metadata).await?;

            // Retrieve key
            let result = db.retrieve_key(&key_id).await?;
            assert!(
                result.is_some(),
                "Failed to retrieve key with ID: {}",
                special_id
            );

            // Check existence
            assert!(
                db.key_exists(&key_id).await?,
                "Key should exist with ID: {}",
                special_id
            );
        }

        // Verify all keys are listed
        let keys = db.list_keys(None, None).await?;
        assert_eq!(keys.len(), special_ids.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_database_persistence() -> Result<()> {
        let db_path = {
            let temp_dir = tempdir().map_err(|e| {
                FortressError::storage(
                    format!("Failed to create temp dir: {}", e),
                    "tempdir".to_string(),
                    crate::error::StorageErrorCode::IoError,
                )
            })?;

            let db_path = temp_dir.path().join("persistence_test.db");
            let connection_string = format!("sqlite:{}", db_path.display());

            let config = KeyDatabaseConfig {
                backend: KeyDatabaseBackend::Sqlite,
                connection_string,
                max_connections: 5,
                connection_timeout_seconds: 30,
                encrypt_at_rest: false,
                master_key: None,
            };

            // Create database and store data
            let db = SqliteKeyDatabase::new(config).await?;
            db.initialize().await?;

            let (key, metadata) = create_test_key_data("persistence_test", 1);
            let key_id = String::from("persistence_test");
            db.store_key(&key_id, &key, &metadata).await?;

            // Return path for second database instance
            db_path.to_path_buf()
        };

        // Create new database instance with same file
        let connection_string = format!("sqlite:{}", db_path.display());
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string,
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };

        let db2 = SqliteKeyDatabase::new(config).await?;
        db2.initialize().await?;

        // Verify data persists
        assert!(db2.key_exists(&String::from("persistence_test")).await?);
        let result = db2.retrieve_key(&String::from("persistence_test")).await?;
        assert!(result.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_error_handling() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        // Test retrieving non-existent key
        let result = db.retrieve_key(&String::from("non_existent")).await?;
        assert!(result.is_none());

        // Test deleting non-existent key (should not error)
        let delete_result = db.delete_key(&String::from("non_existent")).await;
        assert!(delete_result.is_ok()); // Delete operations are typically idempotent

        // Test getting metadata for non-existent key
        let metadata_result = db.get_key_metadata(&String::from("non_existent")).await?;
        assert!(metadata_result.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_performance_with_many_keys() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        let start_time = std::time::Instant::now();

        // Store many keys
        for i in 1..=100 {
            let (key, metadata) = create_test_key_data(&format!("perf_test_{}", i), i);
            let key_id = String::from(&format!("perf_test_{}", i));
            db.store_key(&key_id, &key, &metadata).await?;
        }

        let store_time = start_time.elapsed();

        // Retrieve all keys
        let retrieve_start = std::time::Instant::now();
        for i in 1..=100 {
            let key_id = String::from(&format!("perf_test_{}", i));
            let result = db.retrieve_key(&key_id).await?;
            assert!(result.is_some());
        }
        let retrieve_time = retrieve_start.elapsed();

        // List all keys
        let list_start = std::time::Instant::now();
        let keys = db.list_keys(None, None).await?;
        let list_time = list_start.elapsed();

        // Verify performance
        assert_eq!(keys.len(), 100);
        assert!(
            store_time.as_millis() < 5000,
            "Store operation took too long: {:?}",
            store_time
        );
        assert!(
            retrieve_time.as_millis() < 5000,
            "Retrieve operations took too long: {:?}",
            retrieve_time
        );
        assert!(
            list_time.as_millis() < 1000,
            "List operation took too long: {:?}",
            list_time
        );

        // Check stats
        let stats = db.get_stats().await?;
        assert_eq!(stats.total_keys, 100);
        assert!(stats.avg_query_time_ms >= 0.0);

        Ok(())
    }

    #[tokio::test]
    async fn test_key_metadata_complex_values() -> Result<()> {
        let db = create_test_database().await?;
        db.initialize().await?;

        // Create metadata with complex values
        let algorithm = Aes256GcmWrapper::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate test key");

        let metadata = KeyMetadata::new(
            String::from("complex_metadata_test"),
            algorithm.name().to_string(),
            1,
            Utc::now(),
            Utc::now() + chrono::Duration::days(365), // Long expiration
            format!("{:?}", KeyPurpose::KeyEncryption), // Different purpose
            PerformanceProfile::HighPerformance,      // Different profile
        )
        .with_metadata("custom_field".to_string(), "custom_value".to_string())
        .with_metadata("number_field".to_string(), "42".to_string())
        .with_metadata("json_field".to_string(), r#"{"key": "value"}"#.to_string());

        // Store key with complex metadata
        db.store_key(&String::from("complex_metadata_test"), &key, &metadata)
            .await?;

        // Retrieve and verify complex metadata
        let result = db
            .retrieve_key(&String::from("complex_metadata_test"))
            .await?;
        assert!(result.is_some());

        let (_, retrieved_metadata) = result.unwrap();
        assert_eq!(
            retrieved_metadata.purpose,
            format!("{:?}", KeyPurpose::KeyEncryption)
        );
        assert_eq!(
            retrieved_metadata.performance_profile,
            PerformanceProfile::HighPerformance
        );
        assert!(retrieved_metadata.metadata.contains_key("custom_field"));
        assert_eq!(
            retrieved_metadata.metadata.get("custom_field"),
            Some(&"custom_value".to_string())
        );

        Ok(())
    }
}
