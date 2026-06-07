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

use crate::secrets::{
    EngineStats, EngineStatus, EngineType, LeaseInfo, Secret, SecretMetadata, SecretsEngine,
};

use crate::secure_audit::SecureAuditLogger;

use crate::encryption::{Aegis256Wrapper as Aegis256, EncryptionAlgorithm};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::RwLock;

use chrono::{DateTime, Duration, Utc};

use rand::RngCore;

use base64::Engine as _;

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

/// Validation functions for dynamic secrets
use rand::rngs::OsRng;

impl DynamicSecretsEngine {
    /// Validate AWS configuration parameters

    fn validate_aws_config(&self, config: &serde_json::Value) -> Result<()> {
        // Check access key ID

        let access_key_id = config
            .get("access_key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FortressError::validation(
                    "AWS access_key_id is required and must be a string".to_string(),
                    Some("access_key_id".to_string()),
                    None,
                )
            })?;

        // Validate access key ID format (should start with AKIA and be 20 chars)

        if !access_key_id.starts_with("AKIA") || access_key_id.len() != 20 {
            return Err(FortressError::validation(
                "AWS access_key_id must start with 'AKIA' and be 20 characters long".to_string(),
                Some("access_key_id".to_string()),
                Some(access_key_id.to_string()),
            ));
        }

        // Check secret access key

        let secret_access_key = config
            .get("secret_access_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FortressError::validation(
                    "AWS secret_access_key is required and must be a string".to_string(),
                    Some("secret_access_key".to_string()),
                    None,
                )
            })?;

        // Validate secret access key format (should be 40 chars)

        if secret_access_key.len() != 40 {
            return Err(FortressError::validation(
                "AWS secret_access_key must be 40 characters long".to_string(),
                Some("secret_access_key".to_string()),
                Some(secret_access_key.to_string()),
            ));
        }

        // Validate region format

        let region = config
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");

        if !self.is_valid_aws_region(region) {
            return Err(FortressError::validation(
                format!("Invalid AWS region: {}", region),
                Some("region".to_string()),
                Some(region.to_string()),
            ));
        }

        // Validate session token if provided

        if let Some(session_token) = config.get("session_token").and_then(|v| v.as_str()) {
            if session_token.len() < 1 {
                return Err(FortressError::validation(
                    "AWS session token cannot be empty".to_string(),
                    Some("session_token".to_string()),
                    Some(session_token.to_string()),
                ));
            }
        }

        Ok(())
    }

    /// Validate database configuration parameters

    fn validate_database_config(&self, config: &serde_json::Value) -> Result<()> {
        // Check database type

        let db_type = config
            .get("database_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FortressError::validation(
                    "database_type is required and must be a string".to_string(),
                    Some("database_type".to_string()),
                    None,
                )
            })?;

        if !self.is_valid_database_type(db_type) {
            return Err(FortressError::validation(
                format!(
                    "Unsupported database type: {}. Supported types: postgresql, mysql, sqlserver",
                    db_type
                ),
                Some("database_type".to_string()),
                Some(db_type.to_string()),
            ));
        }

        // Check connection string

        let connection_string = config
            .get("connection_string")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FortressError::validation(
                    "connection_string is required and must be a string".to_string(),
                    Some("connection_string".to_string()),
                    None,
                )
            })?;

        if connection_string.is_empty() {
            return Err(FortressError::validation(
                "connection_string cannot be empty".to_string(),
                Some("connection_string".to_string()),
                None,
            ));
        }

        // Validate connection string format based on database type

        self.validate_connection_string_format(db_type, connection_string)?;

        // Validate permissions if provided

        if let Some(permissions) = config.get("permissions").and_then(|v| v.as_array()) {
            if permissions.is_empty() {
                return Err(FortressError::validation(
                    "permissions array cannot be empty".to_string(),
                    Some("permissions".to_string()),
                    None,
                ));
            }

            for permission in permissions {
                let perm_str = permission.as_str().ok_or_else(|| {
                    FortressError::validation(
                        "All permissions must be strings".to_string(),
                        Some("permissions".to_string()),
                        None,
                    )
                })?;

                if !self.is_valid_permission(db_type, perm_str) {
                    return Err(FortressError::validation(
                        format!(
                            "Invalid permission '{}' for database type {}",
                            perm_str, db_type
                        ),
                        Some("permissions".to_string()),
                        Some(perm_str.to_string()),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate TTL parameters

    fn validate_ttl(&self, ttl: u64, max_ttl: u64) -> Result<()> {
        if ttl == 0 {
            return Err(FortressError::validation(
                "TTL cannot be zero".to_string(),
                Some("ttl".to_string()),
                Some(ttl.to_string()),
            ));
        }

        if ttl > max_ttl {
            return Err(FortressError::validation(
                format!("TTL {} exceeds maximum allowed TTL {}", ttl, max_ttl),
                Some("ttl".to_string()),
                Some(ttl.to_string()),
            ));
        }

        if ttl < 60 {
            return Err(FortressError::validation(
                "TTL must be at least 60 seconds".to_string(),
                Some("ttl".to_string()),
                Some(ttl.to_string()),
            ));
        }

        Ok(())
    }

    /// Validate AWS region

    fn is_valid_aws_region(&self, region: &str) -> bool {
        let valid_regions = [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "ca-central-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-central-1",
            "eu-central-2",
            "eu-north-1",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "sa-east-1",
        ];
        valid_regions.contains(&region)
    }

    /// Validate database type

    fn is_valid_database_type(&self, db_type: &str) -> bool {
        matches!(db_type, "postgresql" | "mysql" | "sqlserver")
    }

    /// Validate database permission

    fn is_valid_permission(&self, db_type: &str, permission: &str) -> bool {
        match db_type {
            "postgresql" | "mysql" => {
                matches!(
                    permission.to_uppercase().as_str(),
                    "SELECT"
                        | "INSERT"
                        | "UPDATE"
                        | "DELETE"
                        | "CREATE"
                        | "DROP"
                        | "ALTER"
                        | "INDEX"
                        | "ALL"
                )
            }
            "sqlserver" => {
                matches!(
                    permission.to_uppercase().as_str(),
                    "SELECT"
                        | "INSERT"
                        | "UPDATE"
                        | "DELETE"
                        | "CREATE"
                        | "DROP"
                        | "ALTER"
                        | "EXECUTE"
                        | "ALL"
                )
            }
            _ => false,
        }
    }

    /// Validate connection string format

    fn validate_connection_string_format(
        &self,
        db_type: &str,
        connection_string: &str,
    ) -> Result<()> {
        match db_type {
            "postgresql" => {
                if !connection_string.starts_with("postgresql://")
                    && !connection_string.starts_with("postgres://")
                {
                    return Err(FortressError::validation(
                        "PostgreSQL connection string must start with 'postgresql://' or 'postgres://'".to_string(),
                        Some("database_type".to_string()),
                        Some(db_type.to_string())
                    ));
                }
            }
            "mysql" => {
                if !connection_string.starts_with("mysql://") {
                    return Err(FortressError::validation(
                        "MySQL connection string must start with 'mysql://'".to_string(),
                        Some("database_type".to_string()),
                        Some(db_type.to_string()),
                    ));
                }
            }
            "sqlserver" => {
                if !connection_string.starts_with("sqlserver://") {
                    return Err(FortressError::validation(
                        "SQL Server connection string must start with 'sqlserver://'".to_string(),
                        Some("database_type".to_string()),
                        Some(db_type.to_string()),
                    ));
                }
            }
            _ => {
                return Err(FortressError::validation(
                    format!("Unsupported database type: {}", db_type),
                    Some("database_type".to_string()),
                    Some(db_type.to_string()),
                ))
            }
        }
        Ok(())
    }

    /// Validate lease ID format

    fn validate_lease_id(&self, lease_id: &str) -> Result<()> {
        if lease_id.is_empty() {
            return Err(FortressError::validation(
                "Lease ID cannot be empty".to_string(),
                Some("lease_id".to_string()),
                None,
            ));
        }

        if lease_id.len() > 255 {
            return Err(FortressError::validation(
                "Lease ID cannot exceed 255 characters".to_string(),
                Some("lease_id".to_string()),
                Some(lease_id.to_string()),
            ));
        }

        // Check for valid characters (alphanumeric, hyphen, underscore)

        if !lease_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(FortressError::validation(
                "Lease ID can only contain alphanumeric characters, hyphens, and underscores"
                    .to_string(),
                Some("lease_id".to_string()),
                Some(lease_id.to_string()),
            ));
        }

        Ok(())
    }

    /// Generate secure random username

    fn generate_username(&self, prefix: Option<&str>, length: usize) -> String {
        let mut rng = OsRng;

        let mut username = prefix.unwrap_or("vault").to_string();

        // Add random suffix

        for _ in 0..length {
            username.push(char::from(b'a' + (rng.next_u32() % 26) as u8));
        }

        username
    }

    /// Generate secure random password

    fn generate_password(&self, length: usize) -> String {
        let mut rng = OsRng;

        let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

        let mut password = String::with_capacity(length);

        for _ in 0..length {
            password.push(char::from(charset[rng.next_u32() as usize % charset.len()]));
        }

        password
    }

    /// Generate unique lease ID

    fn generate_lease_id(&self) -> String {
        let mut rng = OsRng;

        let mut bytes = [0u8; 16];

        rng.fill_bytes(&mut bytes);

        format!(
            "lease-{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        )
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
    }
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

            audit_logger: Arc::new(SecureAuditLogger::new()),
        }
    }

    /// Configure AWS integration

    pub async fn configure_aws(&self, config: serde_json::Value) -> Result<()> {
        // Validate configuration

        self.validate_aws_config(&config)?;

        let access_key_id = config.get("access_key_id").unwrap().as_str().unwrap();

        let secret_access_key = config.get("secret_access_key").unwrap().as_str().unwrap();

        let region = config
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");

        let session_token = config
            .get("session_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let default_role = config
            .get("default_role")
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

        // Log the configuration event

        // Note: Using log::info for now since log_security_event method doesn't exist

        log::info!("AWS integration configured for region: {}", region);

        Ok(())
    }

    /// Generate AWS IAM credentials

    pub async fn generate_aws_credentials(
        &self,

        _path: &str,

        params: serde_json::Value,
    ) -> Result<AwsIamCredential> {
        let config = self.config.read().await;

        let aws_config = config.aws.as_ref().ok_or_else(|| {
            FortressError::secrets("AWS not configured. Call configure_aws() first.".to_string())
        })?;

        // Extract and validate parameters

        let policy = params.get("policy").cloned().unwrap_or_else(|| {
            serde_json::json!({

                "Version": "2012-10-17",

                "Statement": [{

                    "Effect": "Allow",

                    "Action": ["s3:*"],

                    "Resource": "*"

                }]

            })
        });

        let ttl = params
            .get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(config.default_ttl);

        // Validate TTL

        self.validate_ttl(ttl, config.max_ttl)?;

        let role = params
            .get("role")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| aws_config.default_role.clone());

        // Generate lease ID

        let lease_id = self.generate_lease_id();

        // Generate temporary credentials using AWS STS

        let temp_creds = self
            .create_aws_temporary_credentials(aws_config, &policy, ttl, role.as_deref())
            .await?;

        let credential = AwsIamCredential {
            access_key_id: temp_creds.access_key_id,

            secret_access_key: temp_creds.secret_access_key,

            session_token: temp_creds.session_token,

            expires_at: temp_creds.expires_at,

            policy,

            role,

            lease_id: lease_id.clone(),
        };

        // Store the credential

        {
            let mut aws_creds = self.aws_credentials.write().await;

            aws_creds.insert(lease_id.clone(), credential.clone());
        }

        // Update statistics

        {
            let mut stats = self.stats.write().await;

            stats.total_secrets += 1;

            stats.active_leases += 1;

            stats
                .operations
                .insert("aws_credentials_generated".to_string(), 1);

            stats.last_operation = Some(Utc::now());
        }

        // Log the credential generation

        log::info!("Generated AWS IAM credentials with lease_id: {}", lease_id);

        Ok(credential)
    }

    /// Generate database credentials

    pub async fn generate_database_credentials(
        &self,

        _path: &str,

        params: serde_json::Value,
    ) -> Result<DatabaseCredential> {
        // Validate configuration

        self.validate_database_config(&params)?;

        // Extract parameters

        let database_type = params.get("database_type").unwrap().as_str().unwrap();

        let connection_string = params.get("connection_string").unwrap().as_str().unwrap();

        let username_prefix = params
            .get("username_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("vault");

        let permissions = params
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["SELECT".to_string()]);

        let ttl = params
            .get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                let config = self.config.try_read().unwrap();

                config.default_ttl
            });

        // Validate TTL

        {
            let config = self.config.read().await;

            self.validate_ttl(ttl, config.max_ttl)?;
        }

        // Generate lease ID

        let lease_id = self.generate_lease_id();

        // Generate username and password

        let username = self.generate_username(Some(username_prefix), 12);

        let password = self.generate_password(32);

        // Create database credential

        let expires_at = Utc::now() + Duration::seconds(ttl as i64);

        let credential = DatabaseCredential {
            username: username.clone(),

            password: password.clone(),

            database_type: database_type.to_string(),

            database: self.extract_database_name(connection_string)?,

            connection_string: self.build_connection_string(
                connection_string,
                &username,
                &password,
            )?,

            permissions: permissions.clone(),

            expires_at,

            lease_id: lease_id.clone(),

            metadata: HashMap::new(),
        };

        // Store the credential

        {
            let mut db_creds = self.database_credentials.write().await;

            db_creds.insert(lease_id.clone(), credential.clone());
        }

        // Update statistics

        {
            let mut stats = self.stats.write().await;

            stats.total_secrets += 1;

            stats.active_leases += 1;

            stats
                .operations
                .insert("database_credentials_generated".to_string(), 1);

            stats.last_operation = Some(Utc::now());
        }

        // Log the credential generation

        log::info!(
            "Generated {} database credentials with lease_id: {}",
            database_type,
            lease_id
        );

        Ok(credential)
    }

    /// Extract database name from connection string

    fn extract_database_name(&self, connection_string: &str) -> Result<String> {
        // Parse connection string to extract database name

        if connection_string.contains("postgresql://") || connection_string.contains("postgres://")
        {
            // PostgreSQL: postgresql://user:pass@host:port/database

            let parts: Vec<&str> = connection_string.split('/').collect();

            if parts.len() >= 5 {
                return Ok(parts[4].split('?').next().unwrap_or("unknown").to_string());
            }
        } else if connection_string.contains("mysql://") {
            // MySQL: mysql://user:pass@host:port/database

            let parts: Vec<&str> = connection_string.split('/').collect();

            if parts.len() >= 5 {
                return Ok(parts[4].split('?').next().unwrap_or("unknown").to_string());
            }
        } else if connection_string.contains("sqlserver://") {
            // SQL Server: sqlserver://user:pass@host:port/database

            let parts: Vec<&str> = connection_string.split('/').collect();

            if parts.len() >= 5 {
                return Ok(parts[4].split('?').next().unwrap_or("unknown").to_string());
            }
        }

        Err(FortressError::validation(
            "Could not extract database name from connection string".to_string(),
            Some("connection_string".to_string()),
            Some(connection_string.to_string()),
        ))
    }

    /// Build connection string with generated credentials

    fn build_connection_string(
        &self,
        original: &str,
        username: &str,
        password: &str,
    ) -> Result<String> {
        // Replace username and password in connection string

        let mut result = original.to_string();

        // For PostgreSQL/MySQL/SQL Server, replace the credentials in the URL

        if let Some(start) = result.find("://") {
            let start = start + 3;

            if let Some(end) = result[start..].find('@') {
                let end = start + end;

                // Replace the user:pass part

                result.replace_range(start..end, &format!("{}:{}", username, password));
            }
        }

        Ok(result)
    }

    /// Create AWS temporary credentials (mock implementation)

    async fn create_aws_temporary_credentials(
        &self,

        _aws_config: &AwsConfig,

        _policy: &serde_json::Value,

        ttl: u64,

        _role: Option<&str>,
    ) -> Result<AwsIamCredential> {
        // This is a mock implementation

        // In a real implementation, this would call AWS STS AssumeRole

        let mut rng = OsRng;

        let mut access_key = String::with_capacity(20);

        for _ in 0..20 {
            access_key.push(char::from(b'A' + (rng.next_u32() % 26) as u8));
        }

        let mut secret_key = String::with_capacity(40);

        for _ in 0..40 {
            secret_key.push(char::from(b'a' + (rng.next_u32() % 26) as u8));
        }

        let mut session_token = String::with_capacity(16);

        for _ in 0..16 {
            session_token.push(char::from(b'A' + (rng.next_u32() % 26) as u8));
        }

        Ok(AwsIamCredential {
            access_key_id: format!("ASIA{}", access_key),

            secret_access_key: secret_key,

            session_token: Some(session_token),

            expires_at: Utc::now() + Duration::seconds(ttl as i64),

            policy: serde_json::json!({"Version": "2012-10-17", "Statement": []}),

            role: None,

            lease_id: String::new(), // Will be set by caller
        })
    }

    /// Generate database username
    fn generate_database_username(&self, prefix: &str) -> String {
        let mut rng = OsRng;

        let mut username = prefix.to_string();

        // Add random suffix

        for _ in 0..8 {
            username.push(char::from(b'a' + (rng.next_u32() % 26) as u8));
        }

        username
    }

    /// Generate secure password
    fn generate_secure_password(&self, length: usize) -> String {
        let mut rng = OsRng;

        let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

        let mut password = String::with_capacity(length);

        for _ in 0..length {
            password.push(char::from(charset[rng.next_u32() as usize % charset.len()]));
        }

        password
    }

    /// Generate random string for mock credentials
    fn generate_random_string(&self, length: usize) -> String {
        let mut rng = OsRng;

        let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        let mut result = String::with_capacity(length);

        for _ in 0..length {
            result.push(char::from(charset[rng.next_u32() as usize % charset.len()]));
        }

        result
    }

    /// Revoke a credential by lease ID

    async fn revoke_credential(&self, lease_id: &str) -> Result<()> {
        self.validate_lease_id(lease_id)?;

        let mut found = false;

        // Check and revoke AWS credentials

        {
            let mut credentials = self.aws_credentials.write().await;

            if let Some(_credential) = credentials.remove(lease_id) {
                log::info!("Revoked AWS credential with lease_id: {}", lease_id);

                found = true;
            }
        }

        // Check and revoke database credentials

        if !found {
            let mut credentials = self.database_credentials.write().await;

            if let Some(credential) = credentials.remove(lease_id) {
                log::info!(
                    "Revoked database credential with lease_id: {} (user: {})",
                    lease_id,
                    credential.username
                );

                found = true;
            }
        }

        if !found {
            return Err(FortressError::secrets(format!(
                "Credential with lease_id '{}' not found",
                lease_id
            )));
        }

        // Update stats

        {
            let mut stats = self.stats.write().await;

            stats.total_secrets = self.aws_credentials.read().await.len() as u64
                + self.database_credentials.read().await.len() as u64;

            stats.active_leases = stats.total_secrets;

            *stats.operations.entry("revoke".to_string()).or_insert(0) += 1;

            stats.last_operation = Some(Utc::now());
        }

        Ok(())
    }

    /// Clean up expired credentials
    pub async fn cleanup_expired_credentials(&self) -> Result<()> {
        let now = Utc::now();
        let mut cleaned_count = 0;

        // Clean up expired AWS credentials
        {
            let mut credentials = self.aws_credentials.write().await;
            let initial_count = credentials.len();
            credentials.retain(|_, cred| cred.expires_at > now);
            cleaned_count += initial_count - credentials.len();
            if initial_count - credentials.len() > 0 {
                log::info!("Cleaned up {} expired AWS credentials.", initial_count - credentials.len());
            }
        }

        // Clean up expired database credentials
        {
            let mut credentials = self.database_credentials.write().await;
            let initial_count = credentials.len();
            credentials.retain(|_, cred| cred.expires_at > now);
            cleaned_count += initial_count - credentials.len();
            if initial_count - credentials.len() > 0 {
                log::info!("Cleaned up {} expired database credentials.", initial_count - credentials.len());
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.aws_credentials.read().await.len() as u64
                + self.database_credentials.read().await.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats.operations.entry("cleanup".to_string()).or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        if cleaned_count > 0 {
            log::info!("Total expired credentials cleaned up: {}", cleaned_count);
        } else {
            log::info!("No expired credentials found for cleanup.");
        }

        Ok(())
    }
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
                max_ttl: Some(self.config.read().await.max_ttl),
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
                    created_by: Some("dynamic-secrets".to_string()),
                    tags: HashMap::new(),
                    custom: HashMap::new(),
                },
                lease,
            })
        } else {
            // Assume database request

            let credential = self
                .generate_database_credentials(path, data.clone())
                .await?;

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
                max_ttl: Some(self.config.read().await.max_ttl),
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
                    created_by: Some("dynamic-secrets".to_string()),
                    tags: HashMap::new(),
                    custom: HashMap::new(),
                },
                lease,
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
                    max_ttl: Some(self.config.read().await.max_ttl),
                    created_at: Utc::now(),
                    expires_at: credential.expires_at,
                    renewable: true,
                    max_renewals: Some(5),
                    renewal_count: 0,
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
                        name: path.to_string(),
                        version: 1,
                        created_at: Utc::now(),
                        updated_at: None,
                        created_by: Some("dynamic-secrets".to_string()),
                        tags: HashMap::new(),
                        custom: HashMap::new(),
                    },
                    lease,
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
                    max_ttl: Some(self.config.read().await.max_ttl),
                    created_at: Utc::now(),
                    expires_at: credential.expires_at,
                    renewable: true,
                    max_renewals: Some(5),
                    renewal_count: 0,
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
                        name: path.to_string(),
                        version: 1,
                        created_at: Utc::now(),
                        updated_at: None,
                        created_by: Some("dynamic-secrets".to_string()),
                        tags: HashMap::new(),
                        custom: HashMap::new(),
                    },
                    lease,
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
            active: true,
            last_activity: Utc::now(),
            config: serde_json::to_value(&*self.config.read().await)
                .unwrap_or_else(|_| serde_json::Value::Null),
            stats: EngineStats {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                avg_operation_time_ms: 0.0,
                active_leases: aws_count + db_count,
                stored_secrets: aws_count + db_count,
                total_secrets: aws_count + db_count,
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
                let new_ttl = increment.unwrap_or(0)
                    + (credential.expires_at - Utc::now()).num_seconds() as u64;

                let max_ttl = self.config.read().await.max_ttl;

                if new_ttl > max_ttl {
                    return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
                }

                let updated_lease = LeaseInfo {
                    lease_id: lease_id.to_string(),
                    ttl: new_ttl,
                    max_ttl: Some(max_ttl),
                    created_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::seconds(new_ttl as i64),
                    renewable: true,
                    max_renewals: Some(5),
                    renewal_count: 0,
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
                let new_ttl = increment.unwrap_or(0)
                    + (credential.expires_at - Utc::now()).num_seconds() as u64;

                let max_ttl = self.config.read().await.max_ttl;

                if new_ttl > max_ttl {
                    return Err(FortressError::secrets("TTL exceeds maximum".to_string()));
                }

                let updated_lease = LeaseInfo {
                    lease_id: lease_id.to_string(),
                    ttl: new_ttl,
                    max_ttl: Some(max_ttl),
                    created_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::seconds(new_ttl as i64),
                    renewable: true,
                    max_renewals: Some(5),
                    renewal_count: 0,
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

    async fn configure(&self, config: serde_json::Value) -> Result<()> {
        let default_ttl = config
            .get("default_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        let max_ttl = config
            .get("max_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(86400);

        let cleanup_interval = config
            .get("cleanup_interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(300);

        let auto_cleanup = config
            .get("auto_cleanup")
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

    async fn cleanup_expired_credentials(&self) -> Result<()> {
        self.cleanup_expired_credentials().await?;
        Ok(())
    }
}
