//! Enhanced MySQL database backend for Fortress
//!
//! This module provides advanced MySQL integration with support for push/pull operations,
//! JSON operations, full-text search, and optimized performance features.

use regex::Regex;
use crate::error::{FortressError, KeyErrorCode, Result, StorageErrorCode};
use crate::key::{KeyId, KeyMetadata, SecureKey};
use crate::storage::StorageBackend;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::Row;
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

/// Enhanced MySQL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySQLConfig {
    /// MySQL connection string
    pub connection_string: String,
    /// Database name
    pub database_name: String,
    /// Table prefix
    pub table_prefix: String,
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
    pub partitioning: Option<MySQLPartitioning>,
    /// Replication settings
    pub replication: MySQLReplicationConfig,
}

impl MySQLConfig {
    /// Validates the MySQL configuration, particularly table names, to prevent SQL injection.
    pub fn validate(&self) -> Result<()> {
        let identifier_regex = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").map_err(|e| {
            FortressError::storage(
                format!("Failed to compile regex for identifier validation: {}", e),
                "mysql".to_string(),
                StorageErrorCode::InvalidConfiguration,
            )
        })?;

        // Validate keys_table
        if !identifier_regex.is_match(&self.keys_table) {
            return Err(FortressError::storage(
                format!("Invalid characters in keys_table name: '{}'. Table names must be alphanumeric and can contain underscores, starting with a letter or underscore.", self.keys_table),
                "mysql".to_string(),
                StorageErrorCode::InvalidConfiguration,
            ));
        }
        if self.keys_table.len() > 64 { // Common max length for identifiers
            return Err(FortressError::storage(
                format!("keys_table name '{}' exceeds maximum allowed length of 64 characters.", self.keys_table),
                "mysql".to_string(),
                StorageErrorCode::InvalidConfiguration,
            ));
        }

        // Validate data_table
        if !identifier_regex.is_match(&self.data_table) {
            return Err(FortressError::storage(
                format!("Invalid characters in data_table name: '{}'. Table names must be alphanumeric and can contain underscores, starting with a letter or underscore.", self.data_table),
                "mysql".to_string(),
                StorageErrorCode::InvalidConfiguration,
            ));
        }
        if self.data_table.len() > 64 { // Common max length for identifiers
            return Err(FortressError::storage(
                format!("data_table name '{}' exceeds maximum allowed length of 64 characters.", self.data_table),
                "mysql".to_string(),
                StorageErrorCode::InvalidConfiguration,
            ));
        }

        Ok(())
    }
}

/// MySQL table partitioning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MySQLPartitioning {
    /// Partition by date range
    ByDate {
        /// Column name for partitioning
        column: String,
        /// Partition interval (daily, weekly, monthly)
        interval: String,
    },
    /// Partition by hash
    ByHash {
        /// Column name for partitioning
        column: String,
        /// Number of partitions
        partitions: u32,
    },
    /// Partition by key range
    ByRange {
        /// Column name for partitioning
        column: String,
        /// Partition ranges
        ranges: Vec<(String, String)>,
    },
}

/// MySQL replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySQLReplicationConfig {
    /// Enable replication
    pub enabled: bool,
    /// Replica connection strings
    pub replica_connections: Vec<String>,
    /// Replication lag tolerance in seconds
    pub lag_tolerance_seconds: u64,
    /// Enable automatic failover
    pub auto_failover: bool,
}

/// MySQL database backend
#[derive(Debug)]
pub struct MySQLDatabase {
    config: MySQLConfig,
    pool: sqlx::mysql::MySqlPool,
}

impl MySQLDatabase {
    /// Create a new MySQL database backend
    pub async fn new(config: MySQLConfig) -> Result<Self> {
        // Build connection options
        let mut options = sqlx::mysql::MySqlConnectOptions::from_str(&config.connection_string)
            .map_err(|e| {
                FortressError::storage(
                    format!("Invalid MySQL connection string: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ConnectionFailed,
                )
            })?;

        // Configure SSL if enabled
        if config.ssl_enabled {
            options = options.ssl_mode(sqlx::mysql::MySqlSslMode::Required);
        }

        // Create connection pool
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(std::time::Duration::from_secs(
                config.connection_timeout_seconds,
            ))
            .connect_with(options)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to connect to MySQL: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ConnectionFailed,
                )
            })?;

        let mut db = Self { config, pool };

        // Validate configuration
        db.config.validate()?;

        // Initialize database schema
        db.initialize_schema().await?;

        Ok(db)
    }

    /// Initialize database schema
    async fn initialize_schema(&self) -> Result<()> {
        // Create keys table
        let create_keys_table = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id VARCHAR(36) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                algorithm VARCHAR(50) NOT NULL,
                key_data LONGBLOB NOT NULL,
                metadata JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                version INT DEFAULT 1,
                status ENUM('active', 'inactive', 'deleted') DEFAULT 'active',
                INDEX idx_name (name),
                INDEX idx_created_at (created_at),
                INDEX idx_status (status),
                FULLTEXT INDEX ft_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
            self.config.keys_table
        );

        sqlx::query(&create_keys_table)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to create keys table: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::InvalidOperation,
                )
            })?;

        // Create data table
        let create_data_table = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id VARCHAR(36) PRIMARY KEY,
                key_id VARCHAR(36) NOT NULL,
                data LONGBLOB NOT NULL,
                checksum VARCHAR(64),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                version INT DEFAULT 1,
                metadata JSON,
                INDEX idx_key_id (key_id),
                INDEX idx_created_at (created_at),
                FOREIGN KEY (key_id) REFERENCES {}(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
            self.config.data_table, self.config.keys_table
        );

        sqlx::query(&create_data_table)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to create data table: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::InvalidOperation,
                )
            })?;

        // Apply partitioning if configured
        if let Some(partitioning) = &self.config.partitioning {
            self.apply_partitioning(partitioning).await?;
        }

        Ok(())
    }

    /// Apply table partitioning
    async fn apply_partitioning(&self, partitioning: &MySQLPartitioning) -> Result<()> {
        match partitioning {
            MySQLPartitioning::ByDate { column, interval } => {
                let partition_sql = format!(
                    r#"
                    ALTER TABLE {} PARTITION BY RANGE (TO_DAYS({})) (
                        PARTITION p_{} VALUES LESS THAN (TO_DAYS('{}')),
                        PARTITION p_future VALUES LESS THAN MAXVALUE
                    )
                    "#,
                    self.config.keys_table,
                    column,
                    interval,
                    Utc::now().format("%Y-%m-%d")
                );

                sqlx::query(&partition_sql)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        FortressError::storage(
                            format!("Failed to apply date partitioning: {}", e),
                            "mysql".to_string(),
                            StorageErrorCode::InvalidOperation,
                        )
                    })?;
            }
            MySQLPartitioning::ByHash { column, partitions } => {
                let partition_sql = format!(
                    "ALTER TABLE {} PARTITION BY HASH({}) PARTITIONS {}",
                    self.config.keys_table, column, partitions
                );

                sqlx::query(&partition_sql)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        FortressError::storage(
                            format!("Failed to apply hash partitioning: {}", e),
                            "mysql".to_string(),
                            StorageErrorCode::InvalidOperation,
                        )
                    })?;
            }
            MySQLPartitioning::ByRange { column, ranges } => {
                let mut partition_definitions = Vec::new();
                for (i, (start, end)) in ranges.iter().enumerate() {
                    partition_definitions
                        .push(format!("PARTITION p{} VALUES LESS THAN ({})", i, end));
                }
                partition_definitions.push("PARTITION p_max VALUES LESS THAN MAXVALUE".to_string());

                let partition_sql = format!(
                    "ALTER TABLE {} PARTITION BY RANGE ({}) ({})",
                    self.config.keys_table,
                    column,
                    partition_definitions.join(", ")
                );

                sqlx::query(&partition_sql)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        FortressError::storage(
                            format!("Failed to apply range partitioning: {}", e),
                            "mysql".to_string(),
                            StorageErrorCode::InvalidOperation,
                        )
                    })?;
            }
        }
        Ok(())
    }

    /// Store a key in the database
    pub async fn store_key(
        &self,
        key_id: &KeyId,
        key: &SecureKey,
        metadata: &KeyMetadata,
    ) -> Result<()> {
        let metadata_json = serde_json::to_string(metadata).map_err(|e| {
            FortressError::storage(
                format!("Failed to serialize metadata: {}", e),
                "mysql".to_string(),
                StorageErrorCode::SerializationError,
            )
        })?;

        let store_key_query = format!(
            r#"
            INSERT INTO {} (id, name, algorithm, key_data, metadata, created_at, updated_at, version, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
            name = VALUES(name),
            algorithm = VALUES(algorithm),
            key_data = VALUES(key_data),
            metadata = VALUES(metadata),
            updated_at = VALUES(updated_at),
            version = version + 1
            "#,
            self.config.keys_table
        );

        sqlx::query(&store_key_query)
            .bind(key_id.to_string())
            .bind(&metadata.key_id)
            .bind(&metadata.algorithm)
            .bind(key.as_bytes())
            .bind(&metadata_json)
            .bind(metadata.created_at)
            .bind(Utc::now())
            .bind(1)
            .bind("active")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to store key: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::WriteError,
                )
            })?;

        Ok(())
    }

    /// Retrieve a key from the database
    pub async fn get_key(&self, key_id: &KeyId) -> Result<Option<(SecureKey, KeyMetadata)>> {
        let get_key_query = format!(
            r#"
            SELECT name, algorithm, key_data, metadata, created_at, updated_at, version, status
            FROM {}
            WHERE id = ? AND status = 'active'
            "#,
            self.config.keys_table
        );

        let row = sqlx::query(&get_key_query)
            .bind(key_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to retrieve key: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        if let Some(row) = row {
            let key_data: Vec<u8> = row.get(2);
            let secure_key = SecureKey::from_bytes(&key_data);

            let metadata_str: String = row.get(3);
            let metadata: KeyMetadata = serde_json::from_str(&metadata_str).map_err(|e| {
                FortressError::storage(
                    format!("Failed to deserialize metadata: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::CorruptedData,
                )
            })?;

            Ok(Some((secure_key, metadata)))
        } else {
            Ok(None)
        }
    }

    /// Delete a key from the database
    pub async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        let delete_key_query = format!(
            "UPDATE {} SET status = 'deleted', updated_at = ? WHERE id = ?",
            self.config.keys_table
        );
        sqlx::query(&delete_key_query)
            .bind(Utc::now())
            .bind(key_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to delete key: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::DeleteError,
                )
            })?;

        Ok(())
    }

    /// List all keys with optional filtering
    pub async fn list_keys(
        &self,
        prefix: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let mut query = format!(
            "SELECT id, name, algorithm, metadata, created_at, updated_at, version, status FROM {} WHERE status = 'active'",
            self.config.keys_table
        );

        let mut params = Vec::new();

        if let Some(prefix) = prefix {
            query.push_str(" AND name LIKE ?");
            params.push(format!("{}%", prefix));
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(limit) = limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        let mut sql_query = sqlx::query(&query);
        for param in &params {
            sql_query = sql_query.bind(param);
        }

        let rows = sql_query.fetch_all(&self.pool).await.map_err(|e| {
            FortressError::storage(
                format!("Failed to list keys: {}", e),
                "mysql".to_string(),
                StorageErrorCode::ReadError,
            )
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let id_str: String = row.get(0);
            let key_id = KeyId::from_str(&id_str).map_err(|e| {
                FortressError::key_management(
                    format!("Invalid key ID: {}", e),
                    Some(id_str.clone()),
                    KeyErrorCode::InvalidKeyFormat,
                )
            })?;

            let metadata_str: String = row.get(3);
            let metadata: KeyMetadata = serde_json::from_str(&metadata_str).map_err(|e| {
                FortressError::storage(
                    format!("Failed to deserialize metadata: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::CorruptedData,
                )
            })?;

            keys.push((key_id, metadata));
        }

        Ok(keys)
    }

    /// Store encrypted data
    pub async fn store_data(
        &self,
        key_id: &KeyId,
        data: &[u8],
        metadata: Option<&serde_json::Value>,
    ) -> Result<String> {
        let data_id = Uuid::new_v4().to_string();
        let checksum = format!("{:x}", sha2::Sha256::digest(data));
        let metadata_json = metadata.map(|m| serde_json::to_string(m)).transpose()?;

        let store_data_query = format!(
            r#"
            INSERT INTO {} (id, key_id, data, checksum, metadata, created_at, updated_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            self.config.data_table
        );
        sqlx::query(&store_data_query)
            .bind(&data_id)
            .bind(key_id.to_string())
            .bind(data)
            .bind(&checksum)
            .bind(&metadata_json)
            .bind(Utc::now())
            .bind(Utc::now())
            .bind(1)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to store data: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::WriteError,
                )
            })?;

        Ok(data_id)
    }

    /// Retrieve encrypted data
    pub async fn get_data(&self, data_id: &str) -> Result<Option<Vec<u8>>> {
        let get_data_query = format!(
            "SELECT data, checksum FROM {} WHERE id = ?",
            self.config.data_table
        );
        let row = sqlx::query(&get_data_query)
            .bind(data_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to retrieve data: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        if let Some(row) = row {
            // Verify checksum
            let data_bytes: Vec<u8> = row.get(0);
            let stored_checksum: String = row.get(1);
            let actual_checksum = format!("{:x}", sha2::Sha256::digest(&data_bytes));
            if actual_checksum != stored_checksum {
                return Err(FortressError::storage(
                    "Data corruption detected: checksum mismatch",
                    "mysql",
                    StorageErrorCode::CorruptedData,
                ));
            }

            Ok(Some(data_bytes))
        } else {
            Ok(None)
        }
    }

    /// Perform full-text search on keys
    pub async fn search_keys(
        &self,
        query: &str,
        limit: Option<u32>,
    ) -> Result<Vec<(KeyId, KeyMetadata)>> {
        let mut sql_query = format!(
            r#"
            SELECT id, name, algorithm, metadata, created_at, updated_at, version, status,
                   MATCH(name) AGAINST(? IN NATURAL LANGUAGE MODE) as relevance
            FROM {}
            WHERE status = 'active' AND MATCH(name) AGAINST(? IN NATURAL LANGUAGE MODE)
            ORDER BY relevance DESC, created_at DESC
            "#,
            self.config.keys_table
        );

        if let Some(limit) = limit {
            sql_query.push_str(&format!(" LIMIT {}", limit));
        }

        let rows = sqlx::query(&sql_query)
            .bind(query)
            .bind(query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to search keys: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        let mut keys = Vec::new();
        for row in rows {
            let id_str: String = row.get(0);
            let key_id = KeyId::from_str(&id_str).map_err(|e| {
                FortressError::key_management(
                    format!("Invalid key ID: {}", e),
                    Some(id_str.clone()),
                    KeyErrorCode::InvalidKeyFormat,
                )
            })?;

            let metadata_str: String = row.get(3);
            let metadata: KeyMetadata = serde_json::from_str(&metadata_str).map_err(|e| {
                FortressError::storage(
                    format!("Failed to deserialize metadata: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::CorruptedData,
                )
            })?;

            keys.push((key_id, metadata));
        }

        Ok(keys)
    }

    /// Get database statistics
    pub async fn get_statistics(&self) -> Result<MySQLStats> {
        let key_count_query = format!(
            "SELECT COUNT(*) as count FROM {} WHERE status = 'active'",
            self.config.keys_table
        );
        let key_count_row = sqlx::query(&key_count_query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to get key count: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        let data_count_query = format!("SELECT COUNT(*) as count FROM {}", self.config.data_table);
        let data_count_row = sqlx::query(&data_count_query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to get data count: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        let size_query = format!(
            "SELECT SUM(LENGTH(key_data)) as total_size FROM {} WHERE status = 'active'",
            self.config.keys_table
        );
        let size_row = sqlx::query(&size_query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to get database size: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        Ok(MySQLStats {
            key_count: key_count_row.get::<i64, _>(0) as u64,
            data_count: data_count_row.get::<i64, _>(0) as u64,
            total_size_bytes: size_row.get::<Option<i64>, _>(0).unwrap_or(0) as u64,
        })
    }

    /// Close the database connection pool
    pub async fn close(&self) -> Result<()> {
        self.pool.close().await;
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for MySQLDatabase {
    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let checksum = format!("{:x}", sha2::Sha256::digest(value));

        let put_query = format!(
            r#"
            INSERT INTO {} (id, data, checksum, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
            self.config.data_table
        );
        sqlx::query(&put_query)
            .bind(key)
            .bind(value)
            .bind(&checksum)
            .bind(Utc::now())
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to put data: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::WriteError,
                )
            })?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let get_query = format!(
            "SELECT data, checksum FROM {} WHERE id = ?",
            self.config.data_table
        );
        let row = sqlx::query(&get_query)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to get data: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        if let Some(row) = row {
            // Verify checksum
            let data_bytes: Vec<u8> = row.get(0);
            let stored_checksum: String = row.get(1);
            let actual_checksum = format!("{:x}", sha2::Sha256::digest(&data_bytes));
            if actual_checksum != stored_checksum {
                return Err(FortressError::storage(
                    "Data corruption detected: checksum mismatch",
                    "mysql",
                    StorageErrorCode::CorruptedData,
                ));
            }

            Ok(Some(data_bytes))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let delete_query = format!("DELETE FROM {} WHERE id = ?", self.config.data_table);
        sqlx::query(&delete_query)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to delete data: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::DeleteError,
                )
            })?;

        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let existence_query = format!(
            "SELECT COUNT(*) as count FROM {} WHERE id = ?",
            self.config.data_table
        );
        let row = sqlx::query(&existence_query)
            .bind(key)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to check existence: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;

        let count: i64 = row.get(0);
        Ok(count > 0)
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_prefix_paginated(prefix, None, None).await
    }

    async fn list_prefix_paginated(
        &self,
        prefix: &str,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<String>> {
        let limit = limit.unwrap_or(1000) as u32; // Default limit
        let offset = offset.unwrap_or(0) as u32;

        let prefix_query = format!(
            "SELECT id FROM {} WHERE id LIKE ? LIMIT ? OFFSET ?",
            self.config.data_table
        );
        let rows = sqlx::query(&prefix_query)
            .bind(format!("{}%", prefix))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to list prefix: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect())
    }

    async fn list_prefix_with_legacy_params(
        &self,
        prefix: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<String>> {
        let limit = limit.unwrap_or(1000); // Default limit
        let offset = offset.unwrap_or(0);

        let prefix_query = format!(
            "SELECT id FROM {} WHERE id LIKE ? LIMIT ? OFFSET ?",
            self.config.data_table
        );
        let rows = sqlx::query(&prefix_query)
            .bind(format!("{}%", prefix))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("Failed to list prefix: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ReadError,
                )
            })?;
        Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect())
    }

    fn metadata(&self) -> crate::storage::StorageMetadata {
        crate::storage::StorageMetadata {
            backend_type: "mysql".to_string(),
            version: "1.0.0".to_string(),
            supports_transactions: true,
            supports_encryption_at_rest: true,
            supports_streaming: false,
            supports_backup_restore: true,
            supports_audit_logging: true,
            max_object_size: Some(4 * 1024 * 1024 * 1024), // 4GB for MySQL
            supported_isolation_levels: vec![
                crate::storage::IsolationLevel::ReadCommitted,
                crate::storage::IsolationLevel::RepeatableRead,
                crate::storage::IsolationLevel::Serializable,
            ],
            supported_compression_algorithms: vec![
                crate::storage::CompressionAlgorithm::None,
                crate::storage::CompressionAlgorithm::Lz4,
                crate::storage::CompressionAlgorithm::Gzip,
            ],
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("database".to_string(), self.config.database_name.clone());
                meta.insert("keys_table".to_string(), self.config.keys_table.clone());
                meta.insert("data_table".to_string(), self.config.data_table.clone());
                meta
            },
        }
    }

    async fn health_check(&self) -> Result<crate::storage::HealthStatus> {
        let start = std::time::Instant::now();

        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                FortressError::storage(
                    format!("MySQL health check failed: {}", e),
                    "mysql".to_string(),
                    StorageErrorCode::ConnectionFailed,
                )
            })?;

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

/// MySQL database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySQLStats {
    /// Total number of keys
    pub key_count: u64,
    /// Total number of data records
    pub data_count: u64,
    /// Total size of all data in bytes
    pub total_size_bytes: u64,
}

/// MySQL connection pool manager
#[derive(Debug)]
pub struct MySQLPoolManager {
    pools: HashMap<String, sqlx::mysql::MySqlPool>,
}

impl MySQLPoolManager {
    /// Create a new pool manager
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    /// Get or create a connection pool
    pub async fn get_pool(&mut self, config: &MySQLConfig) -> Result<sqlx::mysql::MySqlPool> {
        let pool_key = format!("{}:{}", config.database_name, config.connection_string);

        if let Some(pool) = self.pools.get(&pool_key) {
            Ok(pool.clone())
        } else {
            let pool = sqlx::mysql::MySqlPoolOptions::new()
                .max_connections(config.max_connections)
                .acquire_timeout(std::time::Duration::from_secs(
                    config.connection_timeout_seconds,
                ))
                .connect(&config.connection_string)
                .await
                .map_err(|e| {
                    FortressError::storage(
                        format!("Failed to create MySQL pool: {}", e),
                        "mysql".to_string(),
                        StorageErrorCode::ConnectionFailed,
                    )
                })?;

            self.pools.insert(pool_key, pool.clone());
            Ok(pool)
        }
    }

    /// Close all connection pools
    pub async fn close_all(&mut self) {
        for (_, pool) in self.pools.drain() {
            pool.close().await;
        }
    }
}

impl Default for MySQLPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::SecureKey;

    #[tokio::test]
    async fn test_mysql_config() {
        let config = MySQLConfig {
            connection_string: "mysql://user:pass@localhost/test".to_string(),
            database_name: "mysql".to_string(),
            table_prefix: "fortress_".to_string(),
            keys_table: "fortress_keys".to_string(),
            data_table: "fortress_data".to_string(),
            max_connections: 10,
            connection_timeout_seconds: 30,
            ssl_enabled: false,
            log_statements: false,
            enable_pooling: true,
            partitioning: None,
            replication: MySQLReplicationConfig {
                enabled: false,
                replica_connections: vec![],
                lag_tolerance_seconds: 60,
                auto_failover: false,
            },
        };

        assert_eq!(config.database_name, "test");
        assert_eq!(config.max_connections, 10);
        assert!(!config.ssl_enabled);
    }

    #[tokio::test]
    async fn test_mysql_partitioning() {
        let date_partitioning = MySQLPartitioning::ByDate {
            column: "created_at".to_string(),
            interval: "monthly".to_string(),
        };

        let hash_partitioning = MySQLPartitioning::ByHash {
            column: "id".to_string(),
            partitions: 8,
        };

        match date_partitioning {
            MySQLPartitioning::ByDate { column, interval } => {
                assert_eq!(column, "created_at");
                assert_eq!(interval, "monthly");
            }
            _ => panic!("Expected date partitioning"),
        }

        match hash_partitioning {
            MySQLPartitioning::ByHash { column, partitions } => {
                assert_eq!(column, "id");
                assert_eq!(partitions, 8);
            }
            _ => panic!("Expected hash partitioning"),
        }
    }

    #[tokio::test]
    async fn test_mysql_stats() {
        let stats = MySQLStats {
            key_count: 100,
            data_count: 500,
            total_size_bytes: 1024 * 1024,
        };

        assert_eq!(stats.key_count, 100);
        assert_eq!(stats.data_count, 500);
        assert_eq!(stats.total_size_bytes, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_mysql_pool_manager() {
        let mut manager = MySQLPoolManager::new();

        // Test that the manager is created correctly
        assert_eq!(manager.pools.len(), 0);

        // Close all pools (should not panic even when empty)
        manager.close_all().await;
        assert_eq!(manager.pools.len(), 0);
    }
}
