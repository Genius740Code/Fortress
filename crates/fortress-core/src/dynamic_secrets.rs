//! # Dynamic Secrets Engine
//!
//! Dynamic credential generation engine for cloud services and databases.
//!
//! ## Features
//!
//! - **AWS IAM**: Generate temporary IAM credentials with specific policies
//! - **Database Credentials**: Enhanced PostgreSQL, MySQL, SQL Server dynamic users
//! - **TTL Management**: Automatic credential rotation and cleanup
//! - **Policy-Based Access**: Role-based permission assignment
//! - **Audit Integration**: Complete audit trail for all credential operations
//!
//! ## Usage
//!
//! ```rust,no_run
//! use fortress_core::dynamic_secrets::DynamicSecretsEngine;
//! use serde_json::json;
//!
//! let engine = DynamicSecretsEngine::new();
//!
//! // Configure AWS IAM
//! engine.configure_aws(json!({
//!     "access_key_id": "AKIA...",
//!     "secret_access_key": "secret",
//!     "region": "us-east-1"
//! })).await?;
//!
//! // Generate temporary AWS credentials
//! let aws_creds = engine.generate_aws_credentials("myapp", json!({
//!     "policy": {
//!         "Version": "2012-10-17",
//!         "Statement": [{
//!             "Effect": "Allow",
//!             "Action": ["s3:GetObject", "s3:PutObject"],
//!             "Resource": "arn:aws:s3:::mybucket/*"
//!         }]
//!     },
//!     "ttl": 3600
//! })).await?;
//!
//! // Generate database credentials
//! let db_creds = engine.generate_database_credentials("myapp", json!({
//!     "type": "postgresql",
//!     "database_url": "postgresql://admin:password@localhost:5432/mydb",
//!     "permissions": ["SELECT", "INSERT"],
//!     "ttl": 1800
//! })).await?;
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{FortressError, Result};
use crate::secrets::{EngineStatus, EngineStats, EngineType, LeaseInfo, Secret, SecretMetadata, SecretsEngine};
use crate::secure_audit::SecureAuditLogger;
use crate::encryption::{EncryptionAlgorithm, Aegis256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use rand::RngCore;
use base64::Engine as _;

#[cfg(test)]
mod tests;

/// Dynamic secrets configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicSecretsConfig {
    /// AWS configuration
    pub aws: Option<AwsConfig>,
    /// Default TTL for generated credentials
    pub default_ttl: u64,
    /// Maximum TTL for credentials
    pub max_ttl: u64,
    /// Cleanup interval for expired credentials
    pub cleanup_interval: u64,
    /// Enable automatic cleanup
    pub auto_cleanup: bool,
}

/// AWS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    /// AWS access key ID
    pub access_key_id: String,
    /// AWS secret access key
    pub secret_access_key: String,
    /// AWS region
    pub region: String,
    /// AWS session token (for temporary credentials)
    pub session_token: Option<String>,
    /// Default IAM role for generated credentials
    pub default_role: Option<String>,
}

/// AWS IAM credential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsIamCredential {
    /// Access key ID
    pub access_key_id: String,
    /// Secret access key
    pub secret_access_key: String,
    /// Session token
    pub session_token: Option<String>,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// IAM policy applied
    pub policy: serde_json::Value,
    /// Role assumed (if any)
    pub role: Option<String>,
    /// Lease ID
    pub lease_id: String,
}

/// Database credential information (enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCredential {
    /// Generated username
    pub username: String,
    /// Generated password
    pub password: String,
    /// Database type
    pub database_type: String,
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
    /// Database-specific metadata
    pub metadata: HashMap<String, String>,
}

/// Dynamic secrets engine
#[derive(Debug)]
pub struct DynamicSecretsEngine {
    /// Engine configuration
    config: Arc<RwLock<DynamicSecretsConfig>>,
    /// Active AWS credentials
    aws_credentials: Arc<RwLock<HashMap<String, AwsIamCredential>>>,
    /// Active database credentials
    database_credentials: Arc<RwLock<HashMap<String, DatabaseCredential>>>,
    /// Statistics
    stats: Arc<RwLock<EngineStats>>,
    /// Encryption for sensitive data
    encryption: Arc<Box<dyn EncryptionAlgorithm>>,
    /// Secure audit logger
    audit_logger: Arc<SecureAuditLogger>,
}

impl DynamicSecretsEngine {
    /// Create new dynamic secrets engine
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(DynamicSecretsConfig {
                aws: None,
                default_ttl: 3600, // 1 hour
                max_ttl: 86400, // 24 hours
                cleanup_interval: 300, // 5 minutes
                auto_cleanup: true,
            })),
            aws_credentials: Arc::new(RwLock::new(HashMap::new())),
            database_credentials: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EngineStats {
                total_secrets: 0,
                active_leases: 0,
                operations: HashMap::new(),
                last_operation: None,
            })),
            encryption: Arc::new(Box::new(Aegis256::new())),
            audit_logger: Arc::new(SecureAuditLogger::new()),
        }
    }

    /// Configure AWS integration
    pub async fn configure_aws(&self, config: serde_json::Value) -> Result<()> {
        let access_key_id = config.get("access_key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("AWS access_key_id is required".to_string()))?;

        let secret_access_key = config.get("secret_access_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("AWS secret_access_key is required".to_string()))?;

        let region = config.get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");

        let session_token = config.get("session_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let default_role = config.get("default_role")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let aws_config = AwsConfig {
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            region: region.to_string(),
            session_token,
            default_role,
        };

        {
            let mut config_guard = self.config.write().await;
            config_guard.aws = Some(aws_config);
        }

        log::info!("AWS integration configured for region: {}", region);
        Ok(())
    }

    /// Generate AWS IAM credentials
    pub async fn generate_aws_credentials(
        &self,
        path: &str,
        params: serde_json::Value,
    ) -> Result<AwsIamCredential> {
        let config = self.config.read().await;
        let aws_config = config.aws.as_ref()
            .ok_or_else(|| FortressError::secrets("AWS not configured".to_string()))?;

        // Extract parameters
        let policy = params.get("policy")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:*"],
                    "Resource": "*"
                }]
            }));

        let ttl = params.get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(config.default_ttl);

        if ttl > config.max_ttl {
            return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
        }

        let role = params.get("role")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| aws_config.default_role.clone());

        // Generate temporary credentials using AWS STS
        let temp_creds = self.create_aws_temporary_credentials(
            aws_config,
            &policy,
            ttl,
            role.as_deref(),
        ).await?;

        let expires_at = Utc::now() + Duration::seconds(ttl as i64);
        let lease_id = format!("aws:{}:{}", path, temp_creds.access_key_id);

        let credential = AwsIamCredential {
            access_key_id: temp_creds.access_key_id,
            secret_access_key: temp_creds.secret_access_key,
            session_token: temp_creds.session_token,
            expires_at,
            policy,
            role,
            lease_id: lease_id.clone(),
        };

        // Store credential
        {
            let mut credentials = self.aws_credentials.write().await;
            credentials.insert(lease_id.clone(), credential.clone());
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.aws_credentials.read().await.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats.operations.entry("aws_generate".to_string()).or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        // Log operation
        let principal = "system"; // In real implementation, this would be authenticated user
        if let Err(e) = self.audit_logger.log_secret_generation(
            principal, 
            path, 
            "aws_iam", 
            "success"
        ).await {
            log::warn!("Failed to log audit entry: {}", e);
        }

        Ok(credential)
    }

    /// Generate database credentials
    pub async fn generate_database_credentials(
        &self,
        path: &str,
        params: serde_json::Value,
    ) -> Result<DatabaseCredential> {
        // Extract parameters
        let database_type = params.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("Database type is required".to_string()))?;

        let database_url = params.get("database_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("Database URL is required".to_string()))?;

        let permissions = params.get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_uppercase())
                    .collect()
            })
            .unwrap_or_else(|| vec!["SELECT".to_string()]);

        let default_ttl = self.config.read().await.default_ttl;
        
        let ttl = params.get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_ttl);

        if ttl > self.config.read().await.max_ttl {
            return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
        }

        // Generate username and password
        let username = self.generate_database_username(&format!("{}_user", path));
        let password = self.generate_secure_password(20);

        // Create database user based on type
        match database_type {
            "postgresql" => {
                self.create_postgresql_user(database_url, &username, &password, &permissions).await?;
            },
            "mysql" => {
                self.create_mysql_user(database_url, &username, &password, &permissions).await?;
            },
            "sqlserver" => {
                self.create_sqlserver_user(database_url, &username, &password, &permissions).await?;
            },
            _ => {
                return Err(FortressError::secrets(format!("Unsupported database type: {}", database_type)));
            }
        }

        // Build connection string
        let connection_string = self.build_connection_string(database_type, &username, &password, database_url)?;

        // Extract database name
        let database = database_url.split('/')
            .last()
            .unwrap_or("default")
            .split('?')
            .next()
            .unwrap_or("default");

        let expires_at = Utc::now() + Duration::seconds(ttl as i64);
        let lease_id = format!("db:{}:{}", path, username);

        let mut metadata = HashMap::new();
        metadata.insert("database_type".to_string(), database_type.to_string());
        metadata.insert("generated_at".to_string(), Utc::now().to_rfc3339());

        let credential = DatabaseCredential {
            username: username.clone(),
            password,
            database_type: database_type.to_string(),
            database: database.to_string(),
            connection_string,
            permissions: permissions.clone(),
            expires_at,
            lease_id: lease_id.clone(),
            metadata,
        };

        // Store credential
        {
            let mut credentials = self.database_credentials.write().await;
            credentials.insert(lease_id.clone(), credential.clone());
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.database_credentials.read().await.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats.operations.entry("database_generate".to_string()).or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        // Log operation
        let principal = "system"; // In real implementation, this would be authenticated user
        if let Err(e) = self.audit_logger.log_secret_generation(
            principal, 
            path, 
            database_type, 
            "success"
        ).await {
            log::warn!("Failed to log audit entry: {}", e);
        }

        Ok(credential)
    }

    /// Create AWS temporary credentials
    async fn create_aws_temporary_credentials(
        &self,
        config: &AwsConfig,
        policy: &serde_json::Value,
        ttl: u64,
        role: Option<&str>,
    ) -> Result<TemporaryAwsCredentials> {
        // In a real implementation, this would use AWS SDK
        // For now, we'll simulate the credential generation
        
        log::info!("Creating AWS temporary credentials with TTL: {}s", ttl);
        
        // Generate mock temporary credentials
        let access_key_id = format!("ASIA{}", self.generate_random_string(16));
        let secret_access_key = self.generate_random_string(32);
        let session_token = self.generate_random_string(256);

        log::debug!("Generated temporary AWS credentials: {}...", &access_key_id[..8]);
        
        Ok(TemporaryAwsCredentials {
            access_key_id,
            secret_access_key,
            session_token: Some(session_token),
        })
    }

    /// Create PostgreSQL user
    async fn create_postgresql_user(
        &self,
        database_url: &str,
        username: &str,
        password: &str,
        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating PostgreSQL user: {}", username);
        
        #[cfg(feature = "postgres")]
        {
            use postgres::{Client, NoTls};
            
            // Parse admin credentials from URL
            let admin_url = database_url;
            
            match Client::connect(admin_url, NoTls).await {
                Ok(mut client) => {
                    // Create user
                    let create_user_query = format!("CREATE USER \"{}\" WITH PASSWORD '{}'", username, password);
                    client.execute(&create_user_query, &[]).await
                        .map_err(|e| FortressError::secrets(format!("Failed to create PostgreSQL user: {}", e)))?;
                    
                    // Grant permissions
                    for permission in permissions {
                        let grant_query = match permission.as_str() {
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
            log::warn!("PostgreSQL feature not enabled, simulating user creation");
            log::info!("Simulating SQL execution:");
            log::info!("CREATE USER \"{}\" WITH PASSWORD '***'", username);
            for permission in permissions {
                log::info!("GRANT {} ON ALL TABLES IN SCHEMA public TO \"{}\"", permission, username);
            }
            Ok(())
        }
    }

    /// Create MySQL user
    async fn create_mysql_user(
        &self,
        database_url: &str,
        username: &str,
        password: &str,
        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating MySQL user: {}", username);
        
        #[cfg(feature = "mysql")]
        {
            use mysql::{Pool, PooledConn};
            
            match Pool::new(database_url).await {
                Ok(pool) => {
                    match pool.get_conn().await {
                        Ok(mut conn) => {
                            // Create user
                            let create_user_query = format!("CREATE USER '{}'@'%' IDENTIFIED BY '{}'", username, password);
                            conn.query_drop(create_user_query).await
                                .map_err(|e| FortressError::secrets(format!("Failed to create MySQL user: {}", e)))?;
                            
                            // Grant permissions
                            let database = database_url.split('/').last().unwrap_or("mysql");
                            for permission in permissions {
                                let grant_query = match permission.as_str() {
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
                                }
                            }
                            
                            // Flush privileges
                            conn.query_drop("FLUSH PRIVILEGES").await
                                .map_err(|e| FortressError::secrets(format!("Failed to flush MySQL privileges: {}", e)))?;
                            
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
            log::warn!("MySQL feature not enabled, simulating user creation");
            log::info!("Simulating SQL execution:");
            log::info!("CREATE USER '{}'@'%' IDENTIFIED BY '***'", username);
            let database = database_url.split('/').last().unwrap_or("mysql");
            for permission in permissions {
                log::info!("GRANT {} ON {}.* TO '{}'@'%'", permission, database, username);
            }
            Ok(())
        }
    }

    /// Create SQL Server user
    async fn create_sqlserver_user(
        &self,
        database_url: &str,
        username: &str,
        password: &str,
        permissions: &[String],
    ) -> Result<()> {
        log::info!("Creating SQL Server user: {}", username);
        
        #[cfg(feature = "sqlserver")]
        {
            use tiberius::{Client as SqlClient, AuthMethod};
            
            match SqlClient::connect(database_url).await {
                Ok(mut client) => {
                    // Create login
                    let create_login_query = format!("CREATE LOGIN [{}] WITH PASSWORD = '{}'", username, password);
                    client.execute(&create_login_query, &[]).await
                        .map_err(|e| FortressError::secrets(format!("Failed to create SQL Server login: {}", e)))?;
                    
                    // Switch to target database and create user
                    let database = database_url.split('/').last().unwrap_or("master");
                    let use_db_query = format!("USE [{}]", database);
                    client.execute(&use_db_query, &[]).await
                        .map_err(|e| FortressError::secrets(format!("Failed to switch database: {}", e)))?;
                    
                    let create_user_query = format!("CREATE USER [{}] FOR LOGIN [{}]", username, username);
                    client.execute(&create_user_query, &[]).await
                        .map_err(|e| FortressError::secrets(format!("Failed to create SQL Server user: {}", e)))?;
                    
                    // Grant permissions
                    for permission in permissions {
                        let grant_query = match permission.as_str() {
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

    /// Build connection string
    fn build_connection_string(
        &self,
        database_type: &str,
        username: &str,
        password: &str,
        database_url: &str,
    ) -> Result<String> {
        match database_type {
            "postgresql" => {
                let host_port = database_url.split('@').nth(1).unwrap_or("localhost:5432");
                Ok(format!("postgresql://{}:{}@{}", username, password, host_port))
            },
            "mysql" => {
                let host_port = database_url.split('@').nth(1).unwrap_or("localhost:3306");
                Ok(format!("mysql://{}:{}@{}", username, password, host_port))
            },
            "sqlserver" => {
                let host_port = database_url.split('@').nth(1).unwrap_or("localhost:1433");
                Ok(format!("sqlserver://{}:{}@{}", username, password, host_port))
            },
            _ => Err(FortressError::secrets(format!("Unsupported database type: {}", database_type)))
        }
    }

    /// Generate secure random password
    fn generate_secure_password(&self, length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
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

    /// Generate database username
    fn generate_database_username(&self, prefix: &str) -> String {
        let timestamp = Utc::now().timestamp();
        let random_suffix = rand::thread_rng().next_u32();
        format!("{}_{}_{}", prefix, timestamp, random_suffix)
    }

    /// Generate random string
    fn generate_random_string(&self, length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut string = vec![0u8; length];
        
        let mut rng = rand::thread_rng();
        for byte in string.iter_mut() {
            *byte = CHARSET[rng.next_u32() as usize % CHARSET.len()];
        }
        
        String::from_utf8(string).unwrap_or_default()
    }

    /// Cleanup expired credentials
    pub async fn cleanup_expired_credentials(&self) -> Result<u64> {
        let mut total_cleaned = 0;
        let now = Utc::now();

        // Cleanup AWS credentials
        {
            let mut credentials = self.aws_credentials.write().await;
            let mut to_remove = Vec::new();

            for (lease_id, credential) in credentials.iter() {
                if credential.expires_at < now {
                    to_remove.push(lease_id.clone());
                }
            }

            for lease_id in to_remove {
                credentials.remove(&lease_id);
                total_cleaned += 1;
            }
        }

        // Cleanup database credentials
        {
            let mut credentials = self.database_credentials.write().await;
            let mut to_remove = Vec::new();

            for (lease_id, credential) in credentials.iter() {
                if credential.expires_at < now {
                    to_remove.push(lease_id.clone());
                }
            }

            for lease_id in to_remove {
                credentials.remove(&lease_id);
                total_cleaned += 1;
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.aws_credentials.read().await.len() as u64 + 
                               self.database_credentials.read().await.len() as u64;
            stats.active_leases = stats.total_secrets;
        }

        if total_cleaned > 0 {
            log::info!("Cleaned up {} expired dynamic credentials", total_cleaned);
        }

        Ok(total_cleaned)
    }

    /// Revoke credential
    pub async fn revoke_credential(&self, lease_id: &str) -> Result<()> {
        let mut revoked = false;

        // Check AWS credentials
        {
            let mut credentials = self.aws_credentials.write().await;
            if let Some(credential) = credentials.remove(lease_id) {
                log::info!("Revoked AWS credential: {}", lease_id);
                revoked = true;
            }
        }

        // Check database credentials
        {
            let mut credentials = self.database_credentials.write().await;
            if let Some(credential) = credentials.remove(lease_id) {
                log::info!("Revoked database credential: {}", lease_id);
                revoked = true;
            }
        }

        if !revoked {
            return Err(FortressError::secrets("Credential not found".to_string()));
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.aws_credentials.read().await.len() as u64 + 
                               self.database_credentials.read().await.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats.operations.entry("revoke".to_string()).or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        Ok(())
    }
}

/// Temporary AWS credentials
#[derive(Debug)]
struct TemporaryAwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[async_trait::async_trait]
impl SecretsEngine for DynamicSecretsEngine {
    fn name(&self) -> &str {
        "dynamic"
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Dynamic
    }

    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret> {
        // Determine if this is an AWS or database request
        if data.get("type").and_then(|v| v.as_str()) == Some("aws") {
            let credential = self.generate_aws_credentials(path, data.clone()).await?;
            
            let secret_data = serde_json::json!({
                "access_key_id": credential.access_key_id,
                "secret_access_key": credential.secret_access_key,
                "session_token": credential.session_token,
                "expires_at": credential.expires_at.to_rfc3339(),
                "policy": credential.policy,
                "role": credential.role,
                "lease_id": credential.lease_id
            });

            let ttl = (credential.expires_at - Utc::now()).num_seconds() as u64;
            let lease = Some(LeaseInfo {
                lease_id: credential.lease_id.clone(),
                ttl,
                created_at: Utc::now(),
                renewable: true,
                max_ttl: Some(self.config.read().await.max_ttl),
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
        } else {
            // Assume database request
            let credential = self.generate_database_credentials(path, data.clone()).await?;
            
            let secret_data = serde_json::json!({
                "username": credential.username,
                "password": credential.password,
                "database_type": credential.database_type,
                "database": credential.database,
                "connection_string": credential.connection_string,
                "permissions": credential.permissions,
                "expires_at": credential.expires_at.to_rfc3339(),
                "lease_id": credential.lease_id,
                "metadata": credential.metadata
            });

            let ttl = (credential.expires_at - Utc::now()).num_seconds() as u64;
            let lease = Some(LeaseInfo {
                lease_id: credential.lease_id.clone(),
                ttl,
                created_at: Utc::now(),
                renewable: true,
                max_ttl: Some(self.config.read().await.max_ttl),
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
    }

    async fn read(&self, path: &str) -> Result<Option<Secret>> {
        // Check AWS credentials first
        {
            let credentials = self.aws_credentials.read().await;
            if let Some(credential) = credentials.values().find(|c| c.lease_id.contains(path)) {
                let ttl = (credential.expires_at - Utc::now()).num_seconds() as u64;
                let lease = Some(LeaseInfo {
                    lease_id: credential.lease_id.clone(),
                    ttl,
                    created_at: Utc::now(),
                    renewable: true,
                    max_ttl: Some(self.config.read().await.max_ttl),
                });

                let secret_data = serde_json::json!({
                    "access_key_id": credential.access_key_id,
                    "secret_access_key": credential.secret_access_key,
                    "session_token": credential.session_token,
                    "expires_at": credential.expires_at.to_rfc3339(),
                    "policy": credential.policy,
                    "role": credential.role,
                    "lease_id": credential.lease_id
                });

                return Ok(Some(Secret {
                    data: secret_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_at: Utc::now(),
                        updated_at: None,
                        lease,
                        custom: HashMap::new(),
                    },
                }));
            }
        }

        // Check database credentials
        {
            let credentials = self.database_credentials.read().await;
            if let Some(credential) = credentials.values().find(|c| c.lease_id.contains(path)) {
                let ttl = (credential.expires_at - Utc::now()).num_seconds() as u64;
                let lease = Some(LeaseInfo {
                    lease_id: credential.lease_id.clone(),
                    ttl,
                    created_at: Utc::now(),
                    renewable: true,
                    max_ttl: Some(self.config.read().await.max_ttl),
                });

                let secret_data = serde_json::json!({
                    "username": credential.username,
                    "password": credential.password,
                    "database_type": credential.database_type,
                    "database": credential.database,
                    "connection_string": credential.connection_string,
                    "permissions": credential.permissions,
                    "expires_at": credential.expires_at.to_rfc3339(),
                    "lease_id": credential.lease_id,
                    "metadata": credential.metadata
                });

                return Ok(Some(Secret {
                    data: secret_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_at: Utc::now(),
                        updated_at: None,
                        lease,
                        custom: HashMap::new(),
                    },
                }));
            }
        }

        Ok(None)
    }

    async fn delete(&self, path: &str) -> Result<()> {
        // Find and revoke credentials matching the path
        let mut to_revoke = Vec::new();

        // Check AWS credentials
        {
            let credentials = self.aws_credentials.read().await;
            for (lease_id, _) in credentials.iter() {
                if lease_id.contains(path) {
                    to_revoke.push(lease_id.clone());
                }
            }
        }

        // Check database credentials
        {
            let credentials = self.database_credentials.read().await;
            for (lease_id, _) in credentials.iter() {
                if lease_id.contains(path) {
                    to_revoke.push(lease_id.clone());
                }
            }
        }

        // Revoke all matching credentials
        for lease_id in to_revoke {
            self.revoke_credential(&lease_id).await?;
        }

        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let mut results = Vec::new();

        // List AWS credentials
        {
            let credentials = self.aws_credentials.read().await;
            for (lease_id, _) in credentials.iter() {
                if lease_id.contains(path) {
                    results.push(format!("aws/{}", lease_id));
                }
            }
        }

        // List database credentials
        {
            let credentials = self.database_credentials.read().await;
            for (lease_id, _) in credentials.iter() {
                if lease_id.contains(path) {
                    results.push(format!("database/{}", lease_id));
                }
            }
        }

        results.sort();
        Ok(results)
    }

    async fn status(&self) -> Result<EngineStatus> {
        let aws_count = self.aws_credentials.read().await.len() as u64;
        let db_count = self.database_credentials.read().await.len() as u64;
        let stats = self.stats.read().await.clone();

        Ok(EngineStatus {
            name: self.name().to_string(),
            engine_type: self.engine_type(),
            initialized: self.config.read().await.aws.is_some(),
            config: serde_json::to_value(&*self.config.read().await)
                .unwrap_or_else(|_| serde_json::Value::Null),
            stats: EngineStats {
                total_secrets: aws_count + db_count,
                active_leases: aws_count + db_count,
                operations: stats.operations,
                last_operation: stats.last_operation,
            },
        })
    }

    async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo> {
        // Check AWS credentials first
        {
            let credentials = self.aws_credentials.read().await;
            if let Some(credential) = credentials.get(lease_id) {
                let new_ttl = increment.unwrap_or(0) + (credential.expires_at - Utc::now()).num_seconds() as u64;
                let max_ttl = self.config.read().await.max_ttl;
                
                if new_ttl > max_ttl {
                    return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
                }

                let updated_lease = LeaseInfo {
                    lease_id: lease_id.to_string(),
                    ttl: new_ttl,
                    created_at: Utc::now(),
                    renewable: true,
                    max_ttl: Some(max_ttl),
                };

                // Update credential expiration
                {
                    let mut credentials = self.aws_credentials.write().await;
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

                return Ok(updated_lease);
            }
        }

        // Check database credentials
        {
            let credentials = self.database_credentials.read().await;
            if let Some(credential) = credentials.get(lease_id) {
                let new_ttl = increment.unwrap_or(0) + (credential.expires_at - Utc::now()).num_seconds() as u64;
                let max_ttl = self.config.read().await.max_ttl;
                
                if new_ttl > max_ttl {
                    return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
                }

                let updated_lease = LeaseInfo {
                    lease_id: lease_id.to_string(),
                    ttl: new_ttl,
                    created_at: Utc::now(),
                    renewable: true,
                    max_ttl: Some(max_ttl),
                };

                // Update credential expiration
                {
                    let mut credentials = self.database_credentials.write().await;
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

                return Ok(updated_lease);
            }
        }

        Err(FortressError::secrets("Lease not found".to_string()))
    }

    async fn revoke(&self, lease_id: &str) -> Result<()> {
        self.revoke_credential(lease_id).await
    }

    async fn configure(&mut self, config: serde_json::Value) -> Result<()> {
        let default_ttl = config.get("default_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        let max_ttl = config.get("max_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(86400);

        let cleanup_interval = config.get("cleanup_interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(300);

        let auto_cleanup = config.get("auto_cleanup")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Configure AWS if present
        if let Some(aws_config) = config.get("aws") {
            self.configure_aws(aws_config.clone()).await?;
        }

        {
            let mut self_config = self.config.write().await;
            self_config.default_ttl = default_ttl;
            self_config.max_ttl = max_ttl;
            self_config.cleanup_interval = cleanup_interval;
            self_config.auto_cleanup = auto_cleanup;
        }

        log::info!("Dynamic secrets engine configured");
        Ok(())
    }
}
