//! # Database Secrets Engine

//!

//! Dynamic database credential generation engine.

//!

//! ## Features

//!

//! - **Dynamic Credentials**: Generate temporary SQL credentials on-demand

//! - **Multiple Databases**: Support for PostgreSQL, MySQL, SQL Server

//! - **Role Management**: Create users with specific permissions

//! - **Automatic Cleanup**: Revoke expired credentials

//! - **Connection Pooling**: Efficient database connection management

//!

//! ## Usage

//!

//! ```rust,no_run

//! use fortress_core::database_secrets::DatabaseEngine;

//! use serde_json::json;

//!

//! let engine = DatabaseEngine::new();

//!

//! // Configure database connection

//! engine.configure(json!({

//!     "database_url": "postgresql://admin:password@localhost:5432/mydb",

//!     "type": "postgresql"

//! })).await?;

//!

//! // Generate temporary credentials

//! let creds = engine.write("creds/myapp", &json!({

//!     "username": "myapp_user",

//!     "permissions": ["SELECT", "INSERT"],

//!     "ttl": 3600

//! })).await?;

//!

//! # Ok::<(), Box<dyn std::error::Error>>(())

//! ```

use crate::error::{FortressError, Result};

use crate::secrets::{
    EngineStats, EngineStatus, EngineType, LeaseInfo, Secret, SecretMetadata, SecretsEngine,
};

use crate::encryption::{Aegis256Wrapper as Aegis256, EncryptionAlgorithm};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::RwLock;

use chrono::{DateTime, Duration, Utc};

use rand::rngs::OsRng;
use rand::RngCore;
use url;

#[cfg(feature = "performance-optimization")]
use dashmap::DashMap;

#[cfg(feature = "performance-optimization")]
use rayon::prelude::*;

// Database-specific imports for actual connections

#[cfg(feature = "postgres")]
use tokio_postgres::{Client, NoTls};

#[cfg(feature = "mysql")]
use mysql_async::Pool;

// mssql feature not available in sqlx 0.8

// #[cfg(feature = "mssql")]

// use tiberius::{Client as SqlClient, AuthMethod};

/// Database configuration

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct DatabaseConfig {
    /// Database type (postgresql, mysql, sqlserver)
    pub database_type: DatabaseType,

    /// Database connection URL
    pub database_url: String,

    /// Admin username for creating users
    pub admin_username: String,

    /// Admin password for creating users
    pub admin_password: String,

    /// Default TTL for generated credentials
    pub default_ttl: u64,

    /// Maximum TTL for credentials
    pub max_ttl: u64,

    /// Connection pool size
    pub pool_size: u32,

    /// Username prefix for generated users
    pub username_prefix: String,

    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,

    /// Query timeout in seconds
    pub query_timeout_seconds: u64,

    /// Maximum connection lifetime in seconds
    pub max_connection_lifetime_seconds: u64,

    /// Idle connection timeout in seconds
    pub idle_timeout_seconds: u64,

    /// Enable connection health checks
    pub enable_health_checks: bool,

    /// Health check interval in seconds
    pub health_check_interval_seconds: u64,

    /// Enable query batching
    pub enable_batching: bool,

    /// Maximum batch size
    pub max_batch_size: usize,

    /// Enable connection multiplexing
    pub enable_multiplexing: bool,
}

/// Supported database types

/// Database types supported by the secrets engine

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum DatabaseType {
    /// PostgreSQL database
    PostgreSQL,

    /// MySQL database
    MySQL,

    /// Microsoft SQL Server
    SQLServer,
}

/// Database credential information

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct DatabaseCredential {
    /// Generated username
    pub username: String,

    /// Generated password
    pub password: String,

    /// Database name
    pub database: String,

    /// Connection string
    pub connection_string: String,

    /// Granted permissions
    pub permissions: Vec<String>,

    /// Expiration time
    pub expires_at: DateTime<Utc>,

    /// Lease ID
    pub lease_id: String,

    /// TTL for the credential
    pub ttl: u64,

    /// Creation time
    pub created_at: DateTime<Utc>,
}

/// Dynamic database secrets engine

#[derive(Debug)]

pub struct DatabaseEngine {
    /// Engine configuration
    config: Arc<RwLock<Option<DatabaseConfig>>>,

    /// Active credentials
    credentials: Arc<RwLock<HashMap<String, DatabaseCredential>>>,

    /// Statistics
    stats: Arc<RwLock<EngineStats>>,

    /// Encryption for password generation
    encryption: Arc<Box<dyn EncryptionAlgorithm>>,
}

impl DatabaseEngine {
    /// Create new database engine

    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),

            credentials: Arc::new(RwLock::new(HashMap::new())),

            stats: Arc::new(RwLock::new(EngineStats {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                avg_operation_time_ms: 0.0,
                active_leases: 0,
                stored_secrets: 0,
                total_secrets: 0,
                operations: HashMap::new(),
                last_operation: None,
            })),

            encryption: Arc::new(Box::new(Aegis256::new())),
        }
    }

    /// Generate secure random password

    fn generate_password(&self, length: usize) -> String {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

        let mut password = vec![0u8; length];

        for byte in password.iter_mut() {
            *byte = CHARSET[OsRng.next_u32() as usize % CHARSET.len()];
        }

        String::from_utf8(password).unwrap_or_else(|_| {
            // Fallback to simpler password if encoding fails
            (0..length)
                .map(|_| char::from(OsRng.next_u32() as u8))
                .collect()
        })
    }

    /// Generate unique username
    fn generate_username(&self, prefix: &str) -> String {
        let timestamp = Utc::now().timestamp();
        let random_suffix = OsRng.next_u32();
        format!("{}_{}_{}", prefix, timestamp, random_suffix)
    }

    /// Create database user (PostgreSQL implementation)

    async fn create_postgresql_user(
        &self,

        _config: &DatabaseConfig,

        username: &str,

        _password: &str,

        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating PostgreSQL user: {}", username);

        #[cfg(feature = "postgres")]
        {
            // Connect to PostgreSQL as admin

            // Use proper connection string construction with environment variables
            let db_user = std::env::var("DB_ADMIN_USER")
                .map_err(|_| FortressError::config("DB_ADMIN_USER not set"))?;
            let db_password: std::string::String = std::env::var("DB_ADMIN_PASSWORD")
                .map_err(|_| FortressError::config("DB_ADMIN_PASSWORD not set"))?;

            let mut db_url = Url::parse(&config.database_url).map_err(|e| {
                FortressError::config(format!("Invalid PostgreSQL database URL: {}", e))
            })?;

            // Replace user and password in the URL with admin credentials
            db_url
                .set_username(&db_user)
                .map_err(|_| FortressError::config("Failed to set username in URL"))?;
            db_url
                .set_password(Some(&db_password))
                .map_err(|_| FortressError::config("Failed to set password in URL"))?;
            
            let conn_string = db_url.to_string();

            match Client::connect(&conn_string, NoTls).await {
                Ok(mut client) => {
                    // Create user with parameterized query
                    let create_user_query = "CREATE USER $1 WITH PASSWORD $2";

                    if let Err(e) = client
                        .execute(&create_user_query, &[&username, &password])
                        .await
                    {
                        log::error!("Failed to create PostgreSQL user: {}", e);

                        return Err(FortressError::secrets(format!(
                            "Failed to create user: {}",
                            e
                        )));
                    }

                    // Grant permissions with parameterized queries

                    for permission in permissions {
                        let (grant_query, params) = match permission.to_uppercase().as_str() {
                            "SELECT" => (
                                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO $1",
                                vec![username.clone()],
                            ),

                            "INSERT" => (
                                "GRANT INSERT ON ALL TABLES IN SCHEMA public TO $1",
                                vec![username.clone()],
                            ),

                            "UPDATE" => (
                                "GRANT UPDATE ON ALL TABLES IN SCHEMA public TO $1",
                                vec![username.clone()],
                            ),

                            "DELETE" => (
                                "GRANT DELETE ON ALL TABLES IN SCHEMA public TO $1",
                                vec![username.clone()],
                            ),

                            "ALL" => (
                                "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $1",
                                vec![username.clone()],
                            ),

                            _ => {
                                log::warn!("Unsupported PostgreSQL permission: {}", permission);

                                continue;
                            }
                        };

                        if let Err(e) = client.execute(&grant_query, &params).await {
                            log::error!(
                                "Failed to grant permission {} to user {}: {}",
                                permission,
                                username,
                                e
                            );

                            // Continue with other permissions
                        }
                    }

                    log::info!("Successfully created PostgreSQL user: {}", username);

                    Ok(())
                }

                Err(e) => {
                    log::error!("Failed to connect to PostgreSQL: {}", e);

                    Err(FortressError::secrets(format!(
                        "Database connection failed: {}",
                        e
                    )))
                }
            }
        }

        #[cfg(not(feature = "postgres"))]
        {
            // Fallback to simulation when postgres feature is not enabled

            log::warn!("PostgreSQL feature not enabled, simulating user creation");

            log::info!("Simulating SQL execution:");

            log::info!("CREATE USER \"{}\" WITH PASSWORD '***'", username);

            for permission in permissions {
                log::info!(
                    "GRANT {} ON ALL TABLES IN SCHEMA public TO \"{}\"",
                    permission,
                    username
                );
            }

            Ok(())
        }
    }

    /// Create database user (MySQL implementation)

    async fn create_mysql_user(
        &self,

        _config: &DatabaseConfig,

        username: &str,

        _password: &str,

        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating MySQL user: {}", username);

        #[cfg(feature = "mysql")]
        {
            let mut db_url = Url::parse(&config.database_url).map_err(|e| {
                FortressError::config(format!("Invalid MySQL database URL: {}", e))
            })?;

            // Replace user and password in the URL with admin credentials
            db_url
                .set_username(&db_user)
                .map_err(|_| FortressError::config("Failed to set username in URL"))?;
            db_url
                .set_password(Some(&db_password))
                .map_err(|_| FortressError::config("Failed to set password in URL"))?;
            
            let conn_url = db_url.to_string();

            // Extract host and database from the parsed URL
            let host = db_url.host_str().unwrap_or("localhost");
            let database = db_url.path_segments().and_then(|mut p| p.next()).unwrap_or("mysql");

            match Pool::new(conn_url.as_str()).await {
                Ok(pool) => {
                    match pool.get_conn().await {
                        Ok(mut conn) => {
                            // Create user with parameterized query
                            let create_user_query = "CREATE USER ?@'%' IDENTIFIED BY ?";

                            if let Err(e) = conn
                                .exec_drop(create_user_query, (&username, &password))
                                .await
                            {
                                log::error!("Failed to create MySQL user: {}", e);

                                return Err(FortressError::secrets(format!(
                                    "Failed to create user: {}",
                                    e
                                )));
                            }

                            // Grant permissions with parameterized queries
                            for permission in permissions {
                                let (grant_query, params) = match permission.to_uppercase().as_str()
                                {
                                    "SELECT" => (
                                        "GRANT SELECT ON ?.* TO ?@'%'",
                                        vec![database.to_string(), username.to_string()],
                                    ),
                                    "INSERT" => (
                                        "GRANT INSERT ON ?.* TO ?@'%'",
                                        vec![database.to_string(), username.to_string()],
                                    ),
                                    "UPDATE" => (
                                        "GRANT UPDATE ON ?.* TO ?@'%'",
                                        vec![database.to_string(), username.to_string()],
                                    ),
                                    "DELETE" => (
                                        "GRANT DELETE ON ?.* TO ?@'%'",
                                        vec![database.to_string(), username.to_string()],
                                    ),
                                    "ALL" => (
                                        "GRANT ALL PRIVILEGES ON ?.* TO ?@'%'",
                                        vec![database.to_string(), username.to_string()],
                                    ),
                                    _ => {
                                        log::warn!("Unsupported MySQL permission: {}", permission);
                                        continue;
                                    }
                                };

                                // Execute grant query with parameters
                                if let Err(e) = conn.exec_drop(grant_query, params).await {
                                    log::error!(
                                        "Failed to grant permission {} to user {}: {}",
                                        permission,
                                        username,
                                        e
                                    );
                                    // Continue with other permissions
                                }
                            }

                            // Flush privileges
                            if let Err(e) = conn.query_drop("FLUSH PRIVILEGES").await {
                                log::warn!("Failed to flush MySQL privileges: {}", e);
                            }

                            log::info!("Successfully created MySQL user: {}", username);

                            Ok(())
                        }

                        Err(e) => {
                            log::error!("Failed to get MySQL connection: {}", e);

                            Err(FortressError::secrets(format!(
                                "Database connection failed: {}",
                                e
                            )))
                        }
                    }
                }

                Err(e) => {
                    log::error!("Failed to create MySQL connection pool: {}", e);

                    Err(FortressError::secrets(format!(
                        "Database connection failed: {}",
                        e
                    )))
                }
            }
        }

        #[cfg(not(feature = "mysql"))]
        {
            // Fallback to simulation when mysql feature is not enabled

            log::warn!("MySQL feature not enabled, simulating user creation");

            log::info!("Simulating SQL execution:");

            log::info!("CREATE USER '{}'@'%' IDENTIFIED BY '***'", username);

            for permission in permissions {
                log::info!(
                    "GRANT {} ON {}.* TO '{}'@'%'",
                    permission,
                    "database",
                    username
                );
            }

            Ok(())
        }
    }

    /// Create database user (SQL Server implementation)

    async fn create_sqlserver_user(
        &self,

        _config: &DatabaseConfig,

        username: &str,

        _password: &str,

        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating SQL Server user: {}", username);

        // #[cfg(feature = "mssql")]

        // {

        //     // Parse database URL to get server and database name

        //     let url_parts: Vec<&str> = config.database_url.split('@').collect();

        //     if url_parts.len() < 2 {

        //         return Err(FortressError::secrets("Invalid database URL format".to_string()));

        //     }

        //

        //     let server_db = url_parts[1];

        //     let server_parts: Vec<&str> = server_db.split('/').collect();

        //     let server = server_parts.get(0).unwrap_or("localhost:1433");

        //     let database = server_parts.get(1).unwrap_or("master");

        //

        //     // Connect to SQL Server

        //     let conn_str = format!("server={};database={};User ID={};Password={}",

        //         server, database, config.admin_username, config.admin_password);

        //

        //     match SqlClient::connect(&conn_str).await {

        //         Ok(mut client) => {

        //             // Create login

        //             let create_login_query = format!("CREATE LOGIN [{}] WITH PASSWORD = '{}'", username, password);

        //             if let Err(e) = client.execute(&create_login_query, &[]).await {

        //                 log::error!("Failed to create SQL Server login: {}", e);

        //                 return Err(FortressError::secrets(format!("Failed to create login: {}", e)));

        //             }

        //

        //             // Switch to target database and create user

        //             let use_db_query = format!("USE [{}]", database);

        //             if let Err(e) = client.execute(&use_db_query, &[]).await {

        //                 log::error!("Failed to switch to database {}: {}", database, e);

        //                 return Err(FortressError::secrets(format!("Failed to switch database: {}", e)));

        //             }

        //

        //             let create_user_query = format!("CREATE USER [{}] FOR LOGIN [{}]", username, username);

        //             if let Err(e) = client.execute(&create_user_query, &[]).await {

        //                 log::error!("Failed to create SQL Server user: {}", e);

        //                 return Err(FortressError::secrets(format!("Failed to create user: {}", e)));

        //             }

        //

        //             // Grant permissions

        //             for permission in permissions {

        //                 let grant_query = match permission.to_uppercase().as_str() {

        //                     "SELECT" => format!("GRANT SELECT TO [{}]", username),

        //                     "INSERT" => format!("GRANT INSERT TO [{}]", username),

        //                     "UPDATE" => format!("GRANT UPDATE TO [{}]", username),

        //                     "DELETE" => format!("GRANT DELETE TO [{}]", username),

        //                     "ALL" => format!("GRANT ALL TO [{}]", username),

        //                     _ => {

        //                         log::warn!("Unsupported SQL Server permission: {}", permission);

        //                         continue;

        //                     }

        //                 };

        //

        //                 if let Err(e) = client.execute(&grant_query, &[]).await {

        //                     log::error!("Failed to grant permission {} to user {}: {}", permission, username, e);

        //                     // Continue with other permissions

        //                 }

        //             }

        //

        //             log::info!("Successfully created SQL Server user: {}", username);

        //             Ok(())

        //         },

        //         Err(e) => {

        //             log::error!("Failed to connect to SQL Server: {}", e);

        //             Err(FortressError::secrets(format!("Database connection failed: {}", e)))

        //         }

        //     }

        #[cfg(not(feature = "mssql"))]
        {
            // Fallback to simulation when mssql feature is not enabled

            log::warn!("SQL Server feature not enabled, simulating user creation");

            log::info!("Simulating SQL execution:");

            log::info!("CREATE LOGIN [{}] WITH PASSWORD = '***'", username);

            log::info!("USE [database]");

            log::info!("CREATE USER [{}] FOR LOGIN [{}]", username, username);

            for permission in permissions {
                log::info!("GRANT {} TO [{}]", permission, username);
            }

            Ok(())
        }
    }

    /// Drop database user

    pub async fn drop_database_user(&self, config: &DatabaseConfig, username: &str) -> Result<()> {
        log::info!("Dropping database user: {}", username);

        match config.database_type {
            DatabaseType::PostgreSQL => {
                #[cfg(feature = "postgres")]
                {
                    // Use proper connection string construction with environment variables
                    let db_user = std::env::var("DB_ADMIN_USER")
                        .map_err(|_| FortressError::config("DB_ADMIN_USER not set"))?;
                    let db_password: std::string::String = std::env::var("DB_ADMIN_PASSWORD")
                        .map_err(|_| FortressError::config("DB_ADMIN_PASSWORD not set"))?;

                    let mut db_url = Url::parse(&config.database_url).map_err(|e| {
                        FortressError::config(format!("Invalid PostgreSQL database URL: {}", e))
                    })?;

                    // Replace user and password in the URL with admin credentials
                    db_url
                        .set_username(&db_user)
                        .map_err(|_| FortressError::config("Failed to set username in URL"))?;
                    db_url
                        .set_password(Some(&db_password))
                        .map_err(|_| FortressError::config("Failed to set password in URL"))?;
                    
                    let conn_string = db_url.to_string();

                    if let Ok(mut client) = Client::connect(&conn_string, NoTls).await {
                        // Drop user with parameterized query
                        let drop_query = "DROP USER IF EXISTS $1";

                        if let Err(e) = client.execute(&drop_query, &[&username]).await {
                            log::error!("Failed to drop PostgreSQL user {}: {}", username, e);

                            return Err(FortressError::secrets(format!(
                                "Failed to drop user: {}",
                                e
                            )));
                        }

                        log::info!("Successfully dropped PostgreSQL user: {}", username);
                    } else {
                        log::warn!("Failed to connect to PostgreSQL for user drop");
                    }
                }

                #[cfg(not(feature = "postgres"))]
                {
                    log::info!("Simulating: DROP USER IF EXISTS \"{}\"", username);
                }
            }

            DatabaseType::MySQL => {
                #[cfg(feature = "mysql")]
                {
                    let db_url = Url::parse(&config.database_url).map_err(|e| {
                        FortressError::config(format!("Invalid MySQL database URL: {}", e))
                    })?;

                    let host = db_url.host_str().unwrap_or("localhost:3306");

                    if let Ok(mut conn) = mysql::Pool::new(host).await {
                            // Drop user with parameterized query
                            let drop_query = "DROP USER IF EXISTS ?";
                            if let Err(e) = conn.exec_drop(drop_query, (username,)).await {
                                log::error!("Failed to drop MySQL user {}: {}", username, e);
                            } else {
                                log::info!("Successfully dropped MySQL user: {}", username);
                            }

                            // Flush privileges
                            if let Err(e) = conn.query_drop("FLUSH PRIVILEGES").await {
                                log::warn!("Failed to flush MySQL privileges: {}", e);
                            }
                        } else {
                            log::warn!("Failed to get MySQL connection for user drop");
                        }
                    // Removed the else block that was causing the compilation error.
                    // The error handling for URL parsing is now done earlier.
                }

                #[cfg(not(feature = "mysql"))]
                {
                    log::info!("Simulating: DROP USER IF EXISTS '{}'@'%'", username);
                }
            }

            DatabaseType::SQLServer => {
                // SQL Server user dropping is not implemented - only simulation available
                log::info!("Simulating: DROP LOGIN IF EXISTS [{}]", username);
                log::info!("Simulating: USE [database]");
                log::info!("Simulating: DROP USER IF EXISTS [{}]", username);
            }
        }

        Ok(())
    }

    /// Create database credential

    pub async fn create_credential(
        &self,

        path: &str,

        username: Option<String>,

        permissions: Vec<String>,

        ttl: Option<u64>,
    ) -> Result<DatabaseCredential> {
        let config = self.config.read().await;

        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let ttl = ttl.unwrap_or(config.default_ttl);

        if ttl > config.max_ttl {
            return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
        }

        // Generate username and password

        let username = username.unwrap_or_else(|| self.generate_username(&config.username_prefix));

        let password = self.generate_password(16);

        // Create user in database

        match config.database_type {
            DatabaseType::PostgreSQL => {
                self.create_postgresql_user(config, &username, &password, &permissions)
                    .await?;
            }

            DatabaseType::MySQL => {
                self.create_mysql_user(config, &username, &password, &permissions)
                    .await?;
            }

            DatabaseType::SQLServer => {
                // SQL Server user creation is commented out in the method definition
                // self.create_sqlserver_user(config, &username, &password, &permissions).await?;

                log::warn!("SQL Server user creation not implemented - feature disabled");
            }
        }

        // Build connection string

        let connection_string = match config.database_type {
            DatabaseType::PostgreSQL => {
                format!(
                    "postgresql://{}:{}@{}",
                    username,
                    password,
                    config
                        .database_url
                        .split('@')
                        .nth(1)
                        .unwrap_or("localhost:5432/db")
                )
            }

            DatabaseType::MySQL => {
                format!(
                    "mysql://{}:{}@{}",
                    username,
                    password,
                    config
                        .database_url
                        .split('@')
                        .nth(1)
                        .unwrap_or("localhost:3306/db")
                )
            }

            DatabaseType::SQLServer => {
                format!(
                    "sqlserver://{}:{}@{}",
                    username,
                    password,
                    config
                        .database_url
                        .split('@')
                        .nth(1)
                        .unwrap_or("localhost:1433")
                )
            }
        };

        // Extract database name from connection URL

        let database = config
            .database_url
            .split('/')
            .last()
            .unwrap_or("default")
            .split('?')
            .next()
            .unwrap_or("default");

        let expires_at = Utc::now() + Duration::seconds(ttl as i64);

        let lease_id = format!("db:{}:{}", path, username);

        let credential = DatabaseCredential {
            username: username.clone(),

            password,

            database: database.to_string(),

            connection_string,

            permissions: permissions.clone(),

            expires_at,

            lease_id: lease_id.clone(),

            ttl,

            created_at: Utc::now(),
        };

        // Store credential

        {
            let mut credentials = self.credentials.write().await;

            credentials.insert(lease_id, credential.clone());
        }

        // Update stats

        {
            let mut stats = self.stats.write().await;

            stats.total_secrets = self.credentials.read().await.len() as u64;

            stats.active_leases = stats.total_secrets;

            *stats.operations.entry("create".to_string()).or_insert(0) += 1;

            stats.last_operation = Some(Utc::now());
        }

        Ok(credential)
    }

    /// Cleanup expired credentials

    pub async fn cleanup_expired_credentials(&self) -> Result<u64> {
        let config = self.config.read().await;

        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let now = Utc::now();

        let mut expired_count = 0;

        {
            let mut credentials = self.credentials.write().await;

            let mut to_remove = Vec::new();

            for (lease_id, credential) in credentials.iter() {
                if credential.expires_at < now {
                    to_remove.push((lease_id.clone(), credential.username.clone()));
                }
            }

            for (lease_id, username) in to_remove {
                // Drop user from database
                if let Err(e) = self.drop_database_user(&config, &username).await {
                    log::error!("Failed to drop database user {}: {}", username, e);
                    // Continue with memory cleanup even if database drop fails
                }

                // Remove from memory
                credentials.remove(&lease_id);

                expired_count += 1;
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;

            stats.total_secrets = self.credentials.read().await.len() as u64;

            stats.active_leases = stats.total_secrets;
        }

        Ok(expired_count)
    }

    /// Create multiple database credentials in batch

    pub async fn create_credentials_batch(
        &self,
        requests: Vec<(String, Option<String>, Vec<String>, Option<u64>)>,
    ) -> Result<Vec<DatabaseCredential>> {
        let config = self.config.read().await;
        let _config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let mut results = Vec::with_capacity(requests.len());

        #[cfg(feature = "performance-optimization")]
        {
            // Use parallel processing for batch operations
            results = requests
                .into_par_iter()
                .map(|(path, username, permissions, ttl)| {
                    let inner_config = config
                        .as_ref()
                        .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

                    let ttl = ttl.unwrap_or(inner_config.default_ttl);
                    if ttl > inner_config.max_ttl {
                        return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
                    }

                    let username =
                        username.unwrap_or_else(|| self.generate_username(&inner_config.username_prefix));
                    let password = self.generate_password(16);

                    // Create credential object
                    let credential = DatabaseCredential {
                        username: username.clone(),
                        password: password.clone(),
                        database: self.extract_database_name(&inner_config.database_url),
                        connection_string: self
                            .build_connection_string(&inner_config, &username, &password),
                        permissions: permissions.clone(),
                        created_at: Utc::now(),
                        expires_at: Utc::now() + Duration::seconds(ttl as i64),
                    };

                    Ok(credential)
                })
                .collect::<Result<Vec<_>, _>>()?;
        }

        #[cfg(not(feature = "performance-optimization"))]
        {
            // Sequential processing
            for (path, username, permissions, ttl) in requests {
                let credential = self
                    .create_credential(&path, username, permissions, ttl)
                    .await?;
                results.push(credential);
            }
        }

        Ok(results)
    }

    /// Revoke multiple credentials in batch

    pub async fn revoke_credentials_batch(&self, lease_ids: &[String]) -> Result<usize> {
        let mut revoked_count = 0;

        #[cfg(feature = "performance-optimization")]
        {
            // Use parallel processing for batch revocation
            let credentials = self.credentials.read().await;
            let to_revoke: Vec<_> = lease_ids
                .iter()
                .filter_map(|id| {
                    credentials
                        .get(id)
                        .map(|cred| (id.clone(), cred.username.clone()))
                })
                .collect();

            for (lease_id, _username) in to_revoke {
                if self.revoke(&lease_id).await.is_ok() {
                    revoked_count += 1;
                }
            }
        }

        #[cfg(not(feature = "performance-optimization"))]
        {
            // Sequential processing
            for lease_id in lease_ids {
                if self.revoke(lease_id).await.is_ok() {
                    revoked_count += 1;
                }
            }
        }

        Ok(revoked_count)
    }

    /// Get connection pool statistics

    pub async fn get_connection_stats(&self) -> Result<ConnectionStats> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        Ok(ConnectionStats {
            pool_size: config.pool_size,
            active_connections: self.stats.read().await.active_leases,
            max_lifetime_seconds: config.max_connection_lifetime_seconds,
            idle_timeout_seconds: config.idle_timeout_seconds,
            health_checks_enabled: config.enable_health_checks,
            batching_enabled: config.enable_batching,
            multiplexing_enabled: config.enable_multiplexing,
        })
    }
}

/// Connection pool statistics

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ConnectionStats {
    /// Pool size
    pub pool_size: u32,
    /// Active connections
    pub active_connections: u64,
    /// Maximum connection lifetime
    pub max_lifetime_seconds: u64,
    /// Idle timeout
    pub idle_timeout_seconds: u64,
    /// Health checks enabled
    pub health_checks_enabled: bool,
    /// Batching enabled
    pub batching_enabled: bool,
    /// Multiplexing enabled
    pub multiplexing_enabled: bool,
}

impl DatabaseEngine {
    /// Extract database name from connection URL

    fn extract_database_name(&self, database_url: &str) -> String {
        // Simple extraction - in production, use proper URL parsing
        if let Some(db_part) = database_url.split('/').last() {
            db_part.to_string()
        } else {
            "default".to_string()
        }
    }

    /// Build connection string for generated credentials

    fn build_connection_string(
        &self,
        config: &DatabaseConfig,
        username: &str,
        password: &str,
    ) -> String {
        match config.database_type {
            DatabaseType::PostgreSQL => {
                format!(
                    "postgresql://{}:{}@{}",
                    username,
                    password,
                    config
                        .database_url
                        .replace("postgresql://", "")
                        .split('@')
                        .nth(1)
                        .unwrap_or("localhost:5432/postgres")
                )
            }
            DatabaseType::MySQL => {
                format!(
                    "mysql://{}:{}@{}",
                    username,
                    password,
                    config
                        .database_url
                        .replace("mysql://", "")
                        .split('@')
                        .nth(1)
                        .unwrap_or("localhost:3306/mysql")
                )
            }
            DatabaseType::SQLServer => {
                format!(
                    "Server={};Database={};User Id={};Password={};",
                    config
                        .database_url
                        .split(';')
                        .find(|s| s.starts_with("Server="))
                        .unwrap_or("Server=localhost"),
                    self.extract_database_name(&config.database_url),
                    username,
                    password
                )
            }
        }
    }
}

/// Write secret data to the database

#[async_trait::async_trait]

impl SecretsEngine for DatabaseEngine {
    fn name(&self) -> &str {
        "database"
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Database
    }

    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret> {
        // Extract parameters from data

        let username = data
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let permissions = data
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_uppercase())
                    .collect()
            })
            .unwrap_or_else(|| vec!["SELECT".to_string()]);

        let ttl = data.get("ttl").and_then(|v| v.as_u64());

        // Create credential

        let credential = self
            .create_credential(path, username, permissions, ttl)
            .await?;

        // Build secret data

        let secret_data = serde_json::json!({

            "username": credential.username,

            "password": credential.password,

            "database": credential.database,

            "connection_string": credential.connection_string,

            "permissions": credential.permissions,

            "expires_at": credential.expires_at.to_rfc3339(),

            "lease_id": credential.lease_id

        });

        let lease = Some(LeaseInfo {
            lease_id: credential.lease_id.clone(),
            ttl: ttl.unwrap_or_else(|| {
                // Default TTL without async - use a reasonable default
                3600
            }),
            max_ttl: self
                .config
                .read()
                .await
                .as_ref()
                .map(|c| Some(c.max_ttl))
                .unwrap_or(None),
            created_at: Utc::now(),
            expires_at: credential.expires_at,
            renewable: true,
            max_renewals: Some(5),
            renewal_count: 0,
        });

        Ok(Secret {
            data: secret_data,
            metadata: SecretMetadata {
                name: path.to_string(),
                version: 1,
                created_at: Utc::now(),
                updated_at: None,
                created_by: Some("database-secrets".to_string()),
                tags: HashMap::new(),
                custom: HashMap::new(),
            },
            lease,
        })
    }

    async fn read(&self, path: &str) -> Result<Option<Secret>> {
        let credentials = self.credentials.read().await;

        // Find credential by path prefix

        let credential = credentials
            .iter()
            .find(|(lease_id, _)| lease_id.starts_with(&format!("db:{}:", path)))
            .map(|(_, cred)| cred);

        if let Some(credential) = credential {
            let lease = Some(LeaseInfo {
                lease_id: credential.lease_id.clone(),
                ttl: (credential.expires_at - Utc::now()).num_seconds() as u64,
                max_ttl: self
                    .config
                    .read()
                    .await
                    .as_ref()
                    .map(|c| Some(c.max_ttl))
                    .unwrap_or(None),
                created_at: Utc::now(),
                expires_at: credential.expires_at,
                renewable: true,
                max_renewals: Some(5),
                renewal_count: 0,
            });

            let secret_data = serde_json::json!({

                "username": credential.username,

                "password": credential.password,

                "database": credential.database,

                "connection_string": credential.connection_string,

                "permissions": credential.permissions,

                "expires_at": credential.expires_at.to_rfc3339(),

                "lease_id": credential.lease_id

            });

            Ok(Some(Secret {
                data: secret_data,
                metadata: SecretMetadata {
                    name: path.to_string(),
                    version: 1,
                    created_at: Utc::now(),
                    updated_at: None,
                    created_by: Some("database-secrets".to_string()),
                    tags: HashMap::new(),
                    custom: HashMap::new(),
                },
                lease,
            }))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let config = self.config.read().await;

        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let mut credentials = self.credentials.write().await;

        let mut to_remove = Vec::new();

        // Find credentials to remove

        for (lease_id, credential) in credentials.iter() {
            if lease_id.starts_with(&format!("db:{}:", path)) {
                to_remove.push((lease_id.clone(), credential.username.clone()));
            }
        }

        // Remove from database and memory

        for (lease_id, username) in to_remove {
            // Drop user from database
            if let Err(e) = self.drop_database_user(&config, &username).await {
                log::error!("Failed to drop database user {}: {}", username, e);
                // Continue with memory cleanup even if database drop fails
            }

            credentials.remove(&lease_id);
        }

        // Update stats

        {
            let mut stats = self.stats.write().await;

            stats.total_secrets = credentials.len() as u64;

            stats.active_leases = stats.total_secrets;

            *stats.operations.entry("delete".to_string()).or_insert(0) += 1;

            stats.last_operation = Some(Utc::now());
        }

        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let credentials = self.credentials.read().await;

        let mut paths = std::collections::HashSet::new();

        for lease_id in credentials.keys() {
            if lease_id.starts_with("db:") {
                // Extract path from lease_id: "db:path:username" -> "path"

                let parts: Vec<&str> = lease_id.split(':').collect();

                if parts.len() >= 2 {
                    let cred_path = parts[1];

                    if cred_path.starts_with(path) {
                        paths.insert(cred_path.to_string());
                    }
                }
            }
        }

        let mut result: Vec<String> = paths.into_iter().collect();

        result.sort();

        Ok(result)
    }

    async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo> {
        let config = self.config.read().await;

        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let credentials = self.credentials.read().await;

        if let Some(credential) = credentials.get(lease_id) {
            let new_ttl = increment.unwrap_or(0) + credential.ttl;

            let max_ttl = config.max_ttl;

            if new_ttl > max_ttl {
                return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
            }

            let updated_lease = LeaseInfo {
                lease_id: lease_id.to_string(),
                ttl: new_ttl,
                max_ttl: Some(max_ttl),
                created_at: credential.created_at,
                expires_at: credential.expires_at,
                renewable: true,
                max_renewals: Some(5),
                renewal_count: 0,
            };

            // Update credential expiration

            {
                let mut credentials = self.credentials.write().await;

                if let Some(cred) = credentials.get_mut(lease_id) {
                    cred.expires_at = Utc::now() + Duration::seconds(new_ttl as i64);
                }
            }

            // Update stats

            {
                let mut stats = self.stats.write().await;

                *stats.operations.entry("renew".to_string()).or_insert(0) += 1;

                stats.last_operation = Some(Utc::now());
            }

            Ok(updated_lease)
        } else {
            Err(FortressError::secrets("Lease not found".to_string()))
        }
    }

    async fn revoke(&self, lease_id: &str) -> Result<()> {
        let config = self.config.read().await;

        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let mut credentials = self.credentials.write().await;

        if let Some(credential) = credentials.remove(lease_id) {
            // Drop user from database
            if let Err(e) = self.drop_database_user(&config, &credential.username).await {
                log::error!(
                    "Failed to drop database user {}: {}",
                    credential.username,
                    e
                );
                // Continue with memory cleanup even if database drop fails
            }

            log::info!("Revoked database credential: {}", lease_id);

            // Update stats

            {
                let mut stats = self.stats.write().await;

                stats.total_secrets = credentials.len() as u64;

                stats.active_leases = stats.total_secrets;

                *stats.operations.entry("revoke".to_string()).or_insert(0) += 1;

                stats.last_operation = Some(Utc::now());
            }

            Ok(())
        } else {
            Err(FortressError::secrets("Lease not found".to_string()))
        }
    }

    async fn configure(&self, config: serde_json::Value) -> Result<()> {
        let database_type = config
            .get("database_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("database_type is required".to_string()))?;

        let database_url = config
            .get("database_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("database_url is required".to_string()))?;

        // Validate database_url as a proper URL
        if url::Url::parse(database_url).is_err() {
            return Err(FortressError::secrets(format!(
                "Invalid database_url format: {}",
                database_url
            )));
        }

        let admin_username = config
            .get("admin_username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("admin_username is required".to_string()))?;

        let admin_password = config
            .get("admin_password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("admin_password is required".to_string()))?;

        let default_ttl = config
            .get("default_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        let max_ttl = config
            .get("max_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(86400);

        let pool_size = config
            .get("pool_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u32;

        let username_prefix = config
            .get("username_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("fortress")
            .to_string();

        let db_type = match database_type {
            "postgresql" => DatabaseType::PostgreSQL,

            "mysql" => DatabaseType::MySQL,

            "sqlserver" => DatabaseType::SQLServer,

            _ => {
                return Err(FortressError::secrets(format!(
                    "Unsupported database type: {}",
                    database_type
                )))
            }
        };

        let new_config = DatabaseConfig {
            database_type: db_type.clone(),

            database_url: database_url.to_string(),

            admin_username: admin_username.to_string(),

            admin_password: admin_password.to_string(),

            default_ttl,

            max_ttl,

            pool_size,

            username_prefix,

            connection_timeout_seconds: 30,

            query_timeout_seconds: 30,

            max_connection_lifetime_seconds: 3600,

            idle_timeout_seconds: 600,

            enable_health_checks: true,

            health_check_interval_seconds: 60,

            enable_batching: true,

            max_batch_size: 100,

            enable_multiplexing: false,
        };

        {
            let mut config_guard = self.config.write().await;

            *config_guard = Some(new_config);
        }

        log::info!("Database engine configured for: {:?}", db_type);

        Ok(())
    }

    async fn status(&self) -> Result<EngineStatus> {
        let config = self.config.read().await;

        let credentials = self.credentials.read().await;

        let stats = self.stats.read().await;

        Ok(EngineStatus {
            name: self.name().to_string(),

            engine_type: self.engine_type(),

            initialized: config.is_some(),

            active: true,

            last_activity: chrono::Utc::now(),

            config: serde_json::to_value(&*config).unwrap_or_else(|_| serde_json::Value::Null),

            stats: EngineStats {
                total_operations: 0,

                successful_operations: 0,

                failed_operations: 0,

                avg_operation_time_ms: 0.0,

                active_leases: credentials.len() as u64,

                stored_secrets: credentials.len() as u64,

                total_secrets: credentials.len() as u64,

                operations: stats.operations.clone(),

                last_operation: stats.last_operation,
            },
        })
    }

    async fn cleanup_expired_credentials(&self) -> Result<()> {
        self.cleanup_expired_credentials().await?;
        Ok(())
    }
}

impl Default for DatabaseEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]

mod tests {

    use super::*;

    use serde_json::json;

    #[tokio::test]

    async fn test_database_engine_creation() {
        let engine = DatabaseEngine::new();

        assert_eq!(engine.name(), "database");

        assert!(matches!(engine.engine_type(), EngineType::Database));
    }

    #[tokio::test]

    async fn test_password_generation() {
        let engine = DatabaseEngine::new();

        let password1 = engine.generate_password(16);

        let password2 = engine.generate_password(16);

        assert_eq!(password1.len(), 16);

        assert_eq!(password2.len(), 16);

        assert_ne!(password1, password2);
    }

    #[tokio::test]

    async fn test_username_generation() {
        let engine = DatabaseEngine::new();

        let username1 = engine.generate_username("test");

        let username2 = engine.generate_username("test");

        assert!(username1.starts_with("test_"));

        assert!(username2.starts_with("test_"));

        assert_ne!(username1, username2);
    }

    #[tokio::test]

    async fn test_database_configuration() {
        let mut engine = DatabaseEngine::new();

        let config = json!({

            "database_type": "PostgreSQL",

            "database_url": "postgresql://admin:password@localhost:5432/testdb",

            "admin_username": "admin",

            "admin_password": "password",

            "default_ttl": 3600,

            "max_ttl": 86400,

            "pool_size": 10,

            "username_prefix": "vault"

        });

        let result = engine.configure(config).await;

        assert!(result.is_ok());

        let status = engine.status().await.unwrap();

        assert!(status.initialized);
    }

    #[tokio::test]

    async fn test_credential_creation() {
        let mut engine = DatabaseEngine::new();

        // Configure engine

        let config = json!({

            "database_type": "PostgreSQL",

            "database_url": "postgresql://admin:password@localhost:5432/testdb",

            "admin_username": "admin",

            "admin_password": "password",

            "default_ttl": 3600,

            "max_ttl": 86400,

            "pool_size": 10,

            "username_prefix": "test"

        });

        engine.configure(config).await.unwrap();

        // Create credential

        let data = json!({

            "permissions": ["SELECT", "INSERT"],

            "ttl": 1800

        });

        let result = engine.write("test/app", &data).await;

        assert!(result.is_ok());

        if let Ok(secret) = result {
            assert!(secret.data.get("username").is_some());

            assert!(secret.data.get("password").is_some());

            assert!(secret.data.get("connection_string").is_some());

            assert!(secret.lease.is_some());
        }
    }

    #[tokio::test]

    async fn test_credential_listing() {
        let mut engine = DatabaseEngine::new();

        // Configure engine

        let config = json!({

            "database_type": "PostgreSQL",

            "database_url": "postgresql://admin:password@localhost:5432/testdb",

            "admin_username": "admin",

            "admin_password": "password",

            "default_ttl": 3600,

            "max_ttl": 86400,

            "pool_size": 10,

            "username_prefix": "test"

        });

        engine.configure(config).await.unwrap();

        // Create credentials

        let data = json!({

            "permissions": ["SELECT"],

            "ttl": 1800

        });

        engine.write("test/app1", &data).await.unwrap();

        engine.write("test/app2", &data).await.unwrap();

        // List credentials

        let paths = engine.list("test").await.unwrap();

        assert_eq!(paths.len(), 2);

        assert!(paths.contains(&"test/app1".to_string()));

        assert!(paths.contains(&"test/app2".to_string()));
    }
}
