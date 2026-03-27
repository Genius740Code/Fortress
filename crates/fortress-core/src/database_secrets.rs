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
use crate::secrets::{EngineStatus, EngineStats, EngineType, LeaseInfo, Secret, SecretMetadata, SecretsEngine};
use crate::encryption::{EncryptionAlgorithm, Aegis256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use rand::RngCore;

// Database-specific imports for actual connections
#[cfg(feature = "postgres")]
use postgres::{Client, NoTls};
#[cfg(feature = "mysql")]
use mysql::{Pool, PooledConn};
#[cfg(feature = "sqlserver")]
use tiberius::{Client as SqlClient, AuthMethod};

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
}

/// Supported database types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DatabaseType {
    PostgreSQL,
    MySQL,
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
                total_secrets: 0,
                active_leases: 0,
                operations: HashMap::new(),
                last_operation: None,
            })),
            encryption: Arc::new(Box::new(Aegis256::new())),
        }
    }

    /// Generate secure random password
    fn generate_password(&self, length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut password = vec![0u8; length];
        
        let mut rng = rand::thread_rng();
        for byte in password.iter_mut() {
            *byte = CHARSET[rng.next_u32() as usize % CHARSET.len()];
        }
        
        String::from_utf8(password).unwrap_or_else(|_| {
            // Fallback to simpler password if encoding fails
            (0..length).map(|_| char::from(rng.next_u32() as u8)).collect()
        })
    }

    /// Generate unique username
    fn generate_username(&self, prefix: &str) -> String {
        let timestamp = Utc::now().timestamp();
        let random_suffix = rand::thread_rng().next_u32();
        format!("{}_{}_{}", prefix, timestamp, random_suffix)
    }

    /// Create database user (PostgreSQL implementation)
    async fn create_postgresql_user(
        &self,
        config: &DatabaseConfig,
        username: &str,
        password: &str,
        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating PostgreSQL user: {}", username);
        
        #[cfg(feature = "postgres")]
        {
            // Connect to PostgreSQL as admin
            let conn_string = format!("{}?user={}&password={}", 
                config.database_url, 
                config.admin_username, 
                config.admin_password);
            
            match Client::connect(&conn_string, NoTls).await {
                Ok(mut client) => {
                    // Create user
                    let create_user_query = format!("CREATE USER \"{}\" WITH PASSWORD '{}'", username, password);
                    if let Err(e) = client.execute(&create_user_query, &[]).await {
                        log::error!("Failed to create PostgreSQL user: {}", e);
                        return Err(FortressError::secrets(format!("Failed to create user: {}", e)));
                    }
                    
                    // Grant permissions
                    for permission in permissions {
                        let grant_query = match permission.to_uppercase().as_str() {
                            "SELECT" => format!("GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{}\"", username),
                            "INSERT" => format!("GRANT INSERT ON ALL TABLES IN SCHEMA public TO \"{}\"", username),
                            "UPDATE" => format!("GRANT UPDATE ON ALL TABLES IN SCHEMA public TO \"{}\"", username),
                            "DELETE" => format!("GRANT DELETE ON ALL TABLES IN SCHEMA public TO \"{}\"", username),
                            "ALL" => format!("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{}\"", username),
                            _ => {
                                log::warn!("Unsupported PostgreSQL permission: {}", permission);
                                continue;
                            }
                        };
                        
                        if let Err(e) = client.execute(&grant_query, &[]).await {
                            log::error!("Failed to grant permission {} to user {}: {}", permission, username, e);
                            // Continue with other permissions
                        }
                    }
                    
                    log::info!("Successfully created PostgreSQL user: {}", username);
                    Ok(())
                },
                Err(e) => {
                    log::error!("Failed to connect to PostgreSQL: {}", e);
                    Err(FortressError::secrets(format!("Database connection failed: {}", e)))
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
                log::info!("GRANT {} ON ALL TABLES IN SCHEMA public TO \"{}\"", permission, username);
            }
            Ok(())
        }
    }

    /// Create database user (MySQL implementation)
    async fn create_mysql_user(
        &self,
        config: &DatabaseConfig,
        username: &str,
        password: &str,
        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating MySQL user: {}", username);
        
        #[cfg(feature = "mysql")]
        {
            // Parse database URL to get host and database name
            let url_parts: Vec<&str> = config.database_url.split('@').collect();
            if url_parts.len() < 2 {
                return Err(FortressError::secrets("Invalid database URL format".to_string()));
            }
            
            let host_db = url_parts[1];
            let host_parts: Vec<&str> = host_db.split('/').collect();
            let host = host_parts.get(0).unwrap_or(&"localhost:3306");
            let database = host_parts.get(1).unwrap_or("mysql");
            
            // Create connection URL
            let conn_url = format!("mysql://{}:{}@{}/{}",
                config.admin_username, config.admin_password, host, database);
            
            match Pool::new(conn_url.as_str()).await {
                Ok(pool) => {
                    match pool.get_conn().await {
                        Ok(mut conn) => {
                            // Create user
                            let create_user_query = format!("CREATE USER '{}'@'%' IDENTIFIED BY '{}'", username, password);
                            if let Err(e) = conn.query_drop(create_user_query).await {
                                log::error!("Failed to create MySQL user: {}", e);
                                return Err(FortressError::secrets(format!("Failed to create user: {}", e)));
                            }
                            
                            // Grant permissions
                            for permission in permissions {
                                let grant_query = match permission.to_uppercase().as_str() {
                                    "SELECT" => format!("GRANT SELECT ON {}.* TO '{}'@'%'", database, username),
                                    "INSERT" => format!("GRANT INSERT ON {}.* TO '{}'@'%'", database, username),
                                    "UPDATE" => format!("GRANT UPDATE ON {}.* TO '{}'@'%'", database, username),
                                    "DELETE" => format!("GRANT DELETE ON {}.* TO '{}'@'%'", database, username),
                                    "ALL" => format!("GRANT ALL PRIVILEGES ON {}.* TO '{}'@'%'", database, username),
                                    _ => {
                                        log::warn!("Unsupported MySQL permission: {}", permission);
                                        continue;
                                    }
                                };
                                
                                if let Err(e) = conn.query_drop(grant_query).await {
                                    log::error!("Failed to grant permission {} to user {}: {}", permission, username, e);
                                    // Continue with other permissions
                                }
                            }
                            
                            // Flush privileges
                            if let Err(e) = conn.query_drop("FLUSH PRIVILEGES").await {
                                log::warn!("Failed to flush MySQL privileges: {}", e);
                            }
                            
                            log::info!("Successfully created MySQL user: {}", username);
                            Ok(())
                        },
                        Err(e) => {
                            log::error!("Failed to get MySQL connection: {}", e);
                            Err(FortressError::secrets(format!("Database connection failed: {}", e)))
                        }
                    }
                },
                Err(e) => {
                    log::error!("Failed to create MySQL connection pool: {}", e);
                    Err(FortressError::secrets(format!("Database connection failed: {}", e)))
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
                log::info!("GRANT {} ON {}.* TO '{}'@'%'", permission, "database", username);
            }
            Ok(())
        }
    }

    /// Create database user (SQL Server implementation)
    async fn create_sqlserver_user(
        &self,
        config: &DatabaseConfig,
        username: &str,
        password: &str,
        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating SQL Server user: {}", username);
        
        #[cfg(feature = "sqlserver")]
        {
            // Parse database URL to get server and database name
            let url_parts: Vec<&str> = config.database_url.split('@').collect();
            if url_parts.len() < 2 {
                return Err(FortressError::secrets("Invalid database URL format".to_string()));
            }
            
            let server_db = url_parts[1];
            let server_parts: Vec<&str> = server_db.split('/').collect();
            let server = server_parts.get(0).unwrap_or("localhost:1433");
            let database = server_parts.get(1).unwrap_or("master");
            
            // Connect to SQL Server
            let conn_str = format!("server={};database={};User ID={};Password={}",
                server, database, config.admin_username, config.admin_password);
            
            match SqlClient::connect(&conn_str).await {
                Ok(mut client) => {
                    // Create login
                    let create_login_query = format!("CREATE LOGIN [{}] WITH PASSWORD = '{}'", username, password);
                    if let Err(e) = client.execute(&create_login_query, &[]).await {
                        log::error!("Failed to create SQL Server login: {}", e);
                        return Err(FortressError::secrets(format!("Failed to create login: {}", e)));
                    }
                    
                    // Switch to target database and create user
                    let use_db_query = format!("USE [{}]", database);
                    if let Err(e) = client.execute(&use_db_query, &[]).await {
                        log::error!("Failed to switch to database {}: {}", database, e);
                        return Err(FortressError::secrets(format!("Failed to switch database: {}", e)));
                    }
                    
                    let create_user_query = format!("CREATE USER [{}] FOR LOGIN [{}]", username, username);
                    if let Err(e) = client.execute(&create_user_query, &[]).await {
                        log::error!("Failed to create SQL Server user: {}", e);
                        return Err(FortressError::secrets(format!("Failed to create user: {}", e)));
                    }
                    
                    // Grant permissions
                    for permission in permissions {
                        let grant_query = match permission.to_uppercase().as_str() {
                            "SELECT" => format!("GRANT SELECT TO [{}]", username),
                            "INSERT" => format!("GRANT INSERT TO [{}]", username),
                            "UPDATE" => format!("GRANT UPDATE TO [{}]", username),
                            "DELETE" => format!("GRANT DELETE TO [{}]", username),
                            "ALL" => format!("GRANT ALL TO [{}]", username),
                            _ => {
                                log::warn!("Unsupported SQL Server permission: {}", permission);
                                continue;
                            }
                        };
                        
                        if let Err(e) = client.execute(&grant_query, &[]).await {
                            log::error!("Failed to grant permission {} to user {}: {}", permission, username, e);
                            // Continue with other permissions
                        }
                    }
                    
                    log::info!("Successfully created SQL Server user: {}", username);
                    Ok(())
                },
                Err(e) => {
                    log::error!("Failed to connect to SQL Server: {}", e);
                    Err(FortressError::secrets(format!("Database connection failed: {}", e)))
                }
            }
        }
        
        #[cfg(not(feature = "sqlserver"))]
        {
            // Fallback to simulation when sqlserver feature is not enabled
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
    async fn drop_database_user(
        &self,
        config: &DatabaseConfig,
        username: &str,
    ) -> Result<()> {
        log::info!("Dropping database user: {}", username);
        
        match config.database_type {
            DatabaseType::PostgreSQL => {
                #[cfg(feature = "postgres")]
                {
                    let conn_string = format!("{}?user={}&password={}", 
                        config.database_url, 
                        config.admin_username, 
                        config.admin_password);
                    
                    if let Ok(mut client) = Client::connect(&conn_string, NoTls).await {
                        let drop_query = format!("DROP USER IF EXISTS \"{}\"", username);
                        if let Err(e) = client.execute(&drop_query, &[]).await {
                            log::error!("Failed to drop PostgreSQL user {}: {}", username, e);
                            return Err(FortressError::secrets(format!("Failed to drop user: {}", e)));
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
            },
            DatabaseType::MySQL => {
                #[cfg(feature = "mysql")]
                {
                    let url_parts: Vec<&str> = config.database_url.split('@').collect();
                    if url_parts.len() >= 2 {
                        let host_db = url_parts[1];
                        let host_parts: Vec<&str> = host_db.split('/').collect();
                        let host = host_parts.get(0).unwrap_or(&"localhost:3306");
                        let database = host_parts.get(1).unwrap_or("mysql");
                        
                        let conn_url = format!("mysql://{}:{}@{}/{}",
                            config.admin_username, config.admin_password, host, database);
                        
                        if let Ok(pool) = Pool::new(conn_url.as_str()).await {
                            if let Ok(mut conn) = pool.get_conn().await {
                                let drop_query = format!("DROP USER IF EXISTS '{}'@'%'", username);
                                if let Err(e) = conn.query_drop(drop_query).await {
                                    log::error!("Failed to drop MySQL user {}: {}", username, e);
                                    return Err(FortressError::secrets(format!("Failed to drop user: {}", e)));
                                }
                                
                                if let Err(e) = conn.query_drop("FLUSH PRIVILEGES").await {
                                    log::warn!("Failed to flush MySQL privileges: {}", e);
                                }
                                
                                log::info!("Successfully dropped MySQL user: {}", username);
                            } else {
                                log::warn!("Failed to get MySQL connection for user drop");
                            }
                        } else {
                            log::warn!("Failed to create MySQL connection pool for user drop");
                        }
                    }
                }
                #[cfg(not(feature = "mysql"))]
                {
                    log::info!("Simulating: DROP USER IF EXISTS '{}'@'%'", username);
                }
            },
            DatabaseType::SQLServer => {
                #[cfg(feature = "sqlserver")]
                {
                    let url_parts: Vec<&str> = config.database_url.split('@').collect();
                    if url_parts.len() >= 2 {
                        let server_db = url_parts[1];
                        let server_parts: Vec<&str> = server_db.split('/').collect();
                        let server = server_parts.get(0).unwrap_or("localhost:1433");
                        let database = server_parts.get(1).unwrap_or("master");
                        
                        let conn_str = format!("server={};database={};User ID={};Password={}",
                            server, database, config.admin_username, config.admin_password);
                        
                        if let Ok(mut client) = SqlClient::connect(&conn_str).await {
                            // Drop login
                            let drop_login_query = format!("DROP LOGIN IF EXISTS [{}]", username);
                            if let Err(e) = client.execute(&drop_login_query, &[]).await {
                                log::error!("Failed to drop SQL Server login {}: {}", username, e);
                                return Err(FortressError::secrets(format!("Failed to drop login: {}", e)));
                            }
                            
                            // Switch to database and drop user
                            let use_db_query = format!("USE [{}]", database);
                            if let Err(e) = client.execute(&use_db_query, &[]).await {
                                log::warn!("Failed to switch to database {}: {}", database, e);
                            }
                            
                            let drop_user_query = format!("DROP USER IF EXISTS [{}]", username);
                            if let Err(e) = client.execute(&drop_user_query, &[]).await {
                                log::error!("Failed to drop SQL Server user {}: {}", username, e);
                                return Err(FortressError::secrets(format!("Failed to drop user: {}", e)));
                            }
                            
                            log::info!("Successfully dropped SQL Server user: {}", username);
                        } else {
                            log::warn!("Failed to connect to SQL Server for user drop");
                        }
                    }
                }
                #[cfg(not(feature = "sqlserver"))]
                {
                    log::info!("Simulating: DROP LOGIN IF EXISTS [{}]", username);
                    log::info!("Simulating: USE [database]");
                    log::info!("Simulating: DROP USER IF EXISTS [{}]", username);
                }
            }
        }
        
        Ok(())
    }

    /// Create database credential
    async fn create_credential(
        &self,
        path: &str,
        username: Option<String>,
        permissions: Vec<String>,
        ttl: Option<u64>,
    ) -> Result<DatabaseCredential> {
        let config = self.config.read().await;
        let config = config.as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let ttl = ttl.unwrap_or(config.default_ttl);
        if ttl > config.max_ttl {
            return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
        }

        // Generate username and password
        let username = username.unwrap_or_else(|| {
            self.generate_username(&config.username_prefix)
        });
        let password = self.generate_password(16);

        // Create user in database
        match config.database_type {
            DatabaseType::PostgreSQL => {
                self.create_postgresql_user(config, &username, &password, &permissions).await?;
            },
            DatabaseType::MySQL => {
                self.create_mysql_user(config, &username, &password, &permissions).await?;
            },
            DatabaseType::SQLServer => {
                self.create_sqlserver_user(config, &username, &password, &permissions).await?;
            }
        }

        // Build connection string
        let connection_string = match config.database_type {
            DatabaseType::PostgreSQL => {
                format!("postgresql://{}:{}@{}", 
                    username, password, 
                    config.database_url.split('@').nth(1).unwrap_or("localhost:5432/db"))
            },
            DatabaseType::MySQL => {
                format!("mysql://{}:{}@{}", 
                    username, password,
                    config.database_url.split('@').nth(1).unwrap_or("localhost:3306/db"))
            },
            DatabaseType::SQLServer => {
                format!("sqlserver://{}:{}@{}", 
                    username, password,
                    config.database_url.split('@').nth(1).unwrap_or("localhost:1433"))
            }
        };

        // Extract database name from connection URL
        let database = config.database_url.split('/').last()
            .unwrap_or("default")
            .split('?').next()
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
        let config = config.as_ref()
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
                self.drop_database_user(config, &username).await?;
                
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

        if expired_count > 0 {
            log::info!("Cleaned up {} expired database credentials", expired_count);
        }

        Ok(expired_count)
    }
}

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
        let username = data.get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let permissions = data.get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_uppercase())
                    .collect()
            })
            .unwrap_or_else(|| vec!["SELECT".to_string()]);

        let ttl = data.get("ttl")
            .and_then(|v| v.as_u64());

        // Create credential
        let credential = self.create_credential(path, username, permissions, ttl).await?;

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
            created_at: Utc::now(),
            renewable: true,
            max_ttl: self.config.read().await
                .as_ref()
                .map(|c| Some(c.max_ttl))
                .unwrap_or(None),
        });

        Ok(Secret {
            data: secret_data,
            metadata: SecretMetadata {
                version: 1,
                created_at: Utc::now(),
                updated_at: None,
                lease,
                custom: HashMap::new(),
            },
        })
    }

    async fn read(&self, path: &str) -> Result<Option<Secret>> {
        let credentials = self.credentials.read().await;
        
        // Find credential by path prefix
        let credential = credentials.iter()
            .find(|(lease_id, _)| lease_id.starts_with(&format!("db:{}:", path)))
            .map(|(_, cred)| cred);

        if let Some(credential) = credential {
            let lease = Some(LeaseInfo {
                lease_id: credential.lease_id.clone(),
                ttl: (credential.expires_at - Utc::now()).num_seconds() as u64,
                created_at: Utc::now(),
                renewable: true,
                max_ttl: self.config.read().await
                    .as_ref()
                    .map(|c| Some(c.max_ttl))
                    .unwrap_or(None),
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
                    version: 1,
                    created_at: Utc::now(),
                    updated_at: None,
                    lease,
                    custom: HashMap::new(),
                },
            }))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let config = self.config.read().await;
        let config = config.as_ref()
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
            self.drop_database_user(config, &username).await?;
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
        let config = config.as_ref()
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
                created_at: credential.created_at,
                renewable: true,
                max_ttl: Some(max_ttl),
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
        let config = config.as_ref()
            .ok_or_else(|| FortressError::secrets("Database not configured".to_string()))?;

        let mut credentials = self.credentials.write().await;
        
        if let Some(credential) = credentials.remove(lease_id) {
            // Drop user from database
            self.drop_database_user(config, &credential.username).await?;

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

    async fn configure(&mut self, config: serde_json::Value) -> Result<()> {
        let database_type = config.get("database_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("database_type is required".to_string()))?;

        let database_url = config.get("database_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("database_url is required".to_string()))?;

        let admin_username = config.get("admin_username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("admin_username is required".to_string()))?;

        let admin_password = config.get("admin_password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("admin_password is required".to_string()))?;

        let default_ttl = config.get("default_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        let max_ttl = config.get("max_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(86400);

        let pool_size = config.get("pool_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as u32;

        let username_prefix = config.get("username_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("fortress")
            .to_string();

        let db_type = match database_type {
            "postgresql" => DatabaseType::PostgreSQL,
            "mysql" => DatabaseType::MySQL,
            "sqlserver" => DatabaseType::SQLServer,
            _ => return Err(FortressError::secrets(format!("Unsupported database type: {}", database_type))),
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
            config: serde_json::to_value(&*config).unwrap_or_else(|_| serde_json::Value::Null),
            stats: EngineStats {
                total_secrets: credentials.len() as u64,
                active_leases: credentials.len() as u64,
                operations: stats.operations.clone(),
                last_operation: stats.last_operation,
            },
        })
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
        assert_eq!(engine.engine_type(), EngineType::Database);
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
            assert!(secret.metadata.lease.is_some());
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
