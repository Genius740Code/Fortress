//! Database secret engine for dynamic credential management

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::error::{FortressError, Result, SecretsErrorCode};
use super::base::*;
use super::types::*;
use chrono::{DateTime, Utc};

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub connection_url: String,
    pub username: String,
    pub password: String,
    pub max_open_connections: u32,
    pub connection_timeout: chrono::Duration,
    pub allowed_roles: Vec<String>,
}

/// Database role configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatabaseRoleConfig {
    pub db_name: String,
    pub creation_statements: Vec<String>,
    pub revocation_statements: Vec<String>,
    pub default_ttl: chrono::Duration,
    pub max_ttl: chrono::Duration,
}

/// Generated database credentials
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatabaseCredentials {
    pub username: String,
    pub password: String,
    pub db_name: String,
    pub lease_id: String,
    pub lease_duration: chrono::Duration,
    pub created_time: chrono::DateTime<chrono::Utc>,
    pub expires_time: chrono::DateTime<chrono::Utc>,
}

/// Database connection information
#[derive(Debug, Clone)]
pub struct DatabaseConnection {
    pub role: String,
    pub username: String,
    pub password: String,
    pub db_name: String,
    pub created_time: chrono::DateTime<chrono::Utc>,
    pub expires_time: chrono::DateTime<chrono::Utc>,
    pub lease_id: String,
}

/// Database secret engine
pub struct DatabaseEngine {
    config: DatabaseConfig,
    roles: Arc<RwLock<HashMap<String, DatabaseRoleConfig>>>,
    connections: Arc<RwLock<HashMap<String, DatabaseConnection>>>,
    name: String,
}

impl DatabaseEngine {
    /// Create a new database engine
    pub fn new(config: DatabaseConfig) -> Self {
        Self {
            config,
            roles: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            name: "database".to_string(),
        }
    }

    /// Create a database role
    pub async fn create_role(&self, role_name: &str, role_config: DatabaseRoleConfig) -> Result<()> {
        let mut roles = self.roles.write().await;
        
        // Validate role configuration
        if !self.config.allowed_roles.is_empty() && !self.config.allowed_roles.contains(&role_name.to_string()) {
            return Err(FortressError::secrets_with_code("Role not allowed by configuration".to_string(), Some("database".to_string()), SecretsErrorCode::PolicyViolation));
        }
        
        roles.insert(role_name.to_string(), role_config);
        tracing::info!("Created database role: {}", role_name);
        
        Ok(())
    }

    /// Generate database credentials
    pub async fn generate_credentials(&self, role_name: &str, ttl: Option<chrono::Duration>) -> Result<DatabaseCredentials> {
        let roles = self.roles.read().await;
        let role_config = roles.get(role_name)
            .ok_or_else(|| FortressError::secrets_with_code(format!("Role '{}' not found", role_name), Some("database".to_string()), SecretsErrorCode::RoleNotFound))?;
        
        // Generate random username and password
        let username = self.generate_username(role_name).await?;
        let password = self.generate_password().await?;
        
        // Calculate lease duration
        let lease_duration = ttl.unwrap_or(role_config.default_ttl);
        let now = chrono::Utc::now();
        let expires_time = now + lease_duration;
        
        // Create lease ID
        let lease_id = self.generate_lease_id().await?;
        let lease_id_for_logging = lease_id.clone();
        
        // In a real implementation, this would:
        // 1. Connect to the database
        // 2. Execute creation statements
        // 3. Store the credentials for later revocation
        
        let connection = DatabaseConnection {
            role: role_name.to_string(),
            username: username.clone(),
            password: password.clone(),
            db_name: role_config.db_name.clone(),
            created_time: now,
            expires_time,
            lease_id: lease_id.clone(),
        };
        
        // Store connection info
        let mut connections = self.connections.write().await;
        connections.insert(lease_id.clone(), connection);
        
        let credentials = DatabaseCredentials {
            username,
            password,
            db_name: role_config.db_name.clone(),
            lease_id,
            lease_duration,
            created_time: now,
            expires_time,
        };
        
        tracing::info!("Generated database credentials for role: {}, lease: {}", role_name, lease_id_for_logging);
        Ok(credentials)
    }

    /// Revoke database credentials
    pub async fn revoke_credentials(&self, lease_id: &str) -> Result<()> {
        let mut connections = self.connections.write().await;
        
        if let Some(connection) = connections.remove(lease_id) {
            // Get role configuration
            let roles = self.roles.read().await;
            if let Some(role_config) = roles.get(&connection.role) {
                // In a real implementation, this would:
                // 1. Connect to the database
                // 2. Execute revocation statements
                // 3. Drop the user
                
                tracing::info!("Revoked database credentials for lease: {}", lease_id);
                return Ok(());
            }
        }
        
        Err(FortressError::secrets_with_code(format!("Credentials not found for lease: {}", lease_id), Some("database".to_string()), SecretsErrorCode::LeaseNotFound))
    }

    /// List active connections
    pub async fn list_connections(&self) -> Result<Vec<DatabaseConnection>> {
        let connections = self.connections.read().await;
        let mut active_connections = Vec::new();
        
        let now = chrono::Utc::now();
        for connection in connections.values() {
            if connection.expires_time > now {
                active_connections.push(connection.clone());
            }
        }
        
        Ok(active_connections)
    }

    /// Clean up expired connections
    pub async fn cleanup_expired_connections(&self) -> Result<usize> {
        let mut connections = self.connections.write().await;
        let now = chrono::Utc::now();
        
        let initial_count = connections.len();
        connections.retain(|_, connection| connection.expires_time > now);
        let cleaned_count = initial_count - connections.len();
        
        if cleaned_count > 0 {
            tracing::info!("Cleaned up {} expired database connections", cleaned_count);
        }
        
        Ok(cleaned_count)
    }

    async fn generate_username(&self, role_name: &str) -> Result<String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let timestamp = chrono::Utc::now().timestamp();
        
        Ok(format!("v_{}_{}_{}", role_name, timestamp, counter))
    }

    async fn generate_password(&self) -> Result<String> {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        const PASSWORD_LEN: usize = 32;
        
        let mut rng = rand::thread_rng();
        let password: String = (0..PASSWORD_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        
        Ok(password)
    }

    async fn generate_lease_id(&self) -> Result<String> {
        use uuid::Uuid;
        Ok(format!("database/{}", Uuid::new_v4()))
    }
}

#[async_trait]
impl SecretsEngine for DatabaseEngine {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            supports_lease: true,
            supports_rotation: false,
            supports_dynamic_secrets: true,
            supports_signing: false,
            supports_encryption: false,
            supported_operations: vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
                "list".to_string(),
                "creds".to_string(),
                "roles".to_string(),
            ],
        }
    }

    async fn initialize(&mut self, config: &serde_json::Value) -> Result<()> {
        // Parse configuration
        if let Some(connection_url) = config.get("connection_url").and_then(|v| v.as_str()) {
            self.config.connection_url = connection_url.to_string();
        }
        
        if let Some(allowed_roles) = config.get("allowed_roles").and_then(|v| v.as_array()) {
            self.config.allowed_roles = allowed_roles.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect();
        }
        
        if let Some(max_connections) = config.get("max_open_connections").and_then(|v| v.as_u64()) {
            self.config.max_open_connections = max_connections as u32;
        }
        
        // Test database connection (simplified)
        tracing::info!("Database engine initialized with connection: {}", self.config.connection_url);
        
        // Start cleanup task
        let connections_cleanup = self.connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
            
            loop {
                interval.tick().await;
                
                let engine = DatabaseEngine {
                    config: DatabaseConfig {
                        connection_url: String::new(),
                        username: String::new(),
                        password: String::new(),
                        max_open_connections: 0,
                        connection_timeout: chrono::Duration::seconds(30),
                        allowed_roles: vec![],
                    },
                    roles: Arc::new(RwLock::new(HashMap::new())),
                    connections: connections_cleanup.clone(),
                    name: "database".to_string(),
                };
                
                if let Ok(count) = engine.cleanup_expired_connections().await {
                    if count > 0 {
                        tracing::debug!("Cleaned up {} expired database connections", count);
                    }
                }
            }
        });
        
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Revoke all active connections
        let connections = self.connections.read().await;
        let lease_ids: Vec<String> = connections.keys().cloned().collect();
        drop(connections);
        
        for lease_id in lease_ids {
            if let Err(e) = self.revoke_credentials(&lease_id).await {
                tracing::warn!("Failed to revoke credentials {}: {}", lease_id, e);
            }
        }
        
        tracing::info!("Database engine shutdown complete");
        Ok(())
    }

    async fn read_secret(&self, path: &str, _context: &Context) -> Result<Secret> {
        if path.starts_with("creds/") {
            let role_name = &path[6..]; // Remove "creds/" prefix
            
            let credentials = self.generate_credentials(role_name, None).await?;
            
            return Ok(Secret {
                data: serde_json::to_value(credentials)?,
                metadata: SecretMetadata {
                    created_by: "database-engine".to_string(),
                    ttl: Some(chrono::Duration::hours(1)),
                    max_versions: None,
                    cas_required: false,
                    custom_metadata: HashMap::new(),
                },
                lease_id: Some(format!("database/{}", path)),
                created_time: chrono::Utc::now(),
                updated_time: chrono::Utc::now(),
                version: 1,
            });
        }

        if path == "roles" {
            let roles = self.roles.read().await;
            let role_names: Vec<String> = roles.keys().cloned().collect();
            
            return Ok(Secret {
                data: serde_json::json!({ "roles": role_names }),
                metadata: SecretMetadata {
                    created_by: "database-engine".to_string(),
                    ttl: None,
                    max_versions: None,
                    cas_required: false,
                    custom_metadata: HashMap::new(),
                },
                lease_id: None,
                created_time: chrono::Utc::now(),
                updated_time: chrono::Utc::now(),
                version: 1,
            });
        }

        Err(FortressError::secrets_with_code(format!("Database secret not found: {}", path), Some("database".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn write_secret(&self, path: &str, data: &Secret, context: &Context) -> Result<()> {
        if path.starts_with("roles/") {
            let role_name = &path[6..]; // Remove "roles/" prefix
            
            let db_name = data.data.get("db_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FortressError::secrets_with_code("Missing db_name".to_string(), Some("database".to_string()), SecretsErrorCode::InvalidInput))?;
            
            let creation_statements = data.data.get("creation_statements")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();
            
            let revocation_statements = data.data.get("revocation_statements")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();
            
            let default_ttl = data.data.get("default_ttl")
                .and_then(|v| v.as_i64())
                .map(|s| chrono::Duration::seconds(s))
                .unwrap_or(chrono::Duration::hours(1));
            
            let max_ttl = data.data.get("max_ttl")
                .and_then(|v| v.as_i64())
                .map(|s| chrono::Duration::seconds(s))
                .unwrap_or(chrono::Duration::hours(24));
            
            let role_config = DatabaseRoleConfig {
                db_name: db_name.to_string(),
                creation_statements,
                revocation_statements,
                default_ttl,
                max_ttl,
            };
            
            self.create_role(role_name, role_config).await?;
            return Ok(());
        }

        Err(FortressError::secrets_with_code(format!("Invalid database operation: {}", path), Some("database".to_string()), SecretsErrorCode::InvalidOperation))
    }

    async fn delete_secret(&self, path: &str, _context: &Context) -> Result<()> {
        if path.starts_with("leases/") {
            let lease_id = &path[7..]; // Remove "leases/" prefix
            
            if self.revoke_credentials(lease_id).await.is_ok() {
                return Ok(());
            }
        }

        Err(FortressError::secrets_with_code(format!("Database secret not found for deletion: {}", path), Some("database".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn list_secrets(&self, path: &str, _context: &Context) -> Result<Vec<String>> {
        if path == "roles" {
            let roles = self.roles.read().await;
            return Ok(roles.keys().cloned().collect());
        }

        if path == "" {
            return Ok(vec!["roles".to_string(), "leases".to_string()]);
        }

        Ok(vec![])
    }

    async fn renew_lease(&self, lease_id: &str, increment: chrono::Duration, _context: &Context) -> Result<chrono::Duration> {
        let mut connections = self.connections.write().await;
        
        if let Some(connection) = connections.get_mut(lease_id) {
            connection.expires_time = chrono::Utc::now() + increment;
            tracing::info!("Renewed database lease {} for {} seconds", lease_id, increment.num_seconds());
            return Ok(increment);
        }

        Err(FortressError::secrets_with_code(format!("Lease not found: {}", lease_id), Some("database".to_string()), SecretsErrorCode::LeaseNotFound))
    }

    async fn revoke_lease(&self, lease_id: &str, _context: &Context) -> Result<()> {
        self.revoke_credentials(lease_id).await
    }

    async fn rotate_secret(&self, path: &str, _context: &Context) -> Result<Secret> {
        Err(FortressError::secrets_with_code(format!("Database engine does not support rotation for: {}", path), Some("database".to_string()), SecretsErrorCode::OperationNotSupported))
    }

    async fn get_secret_metadata(&self, path: &str, _context: &Context) -> Result<SecretMetadata> {
        if path.starts_with("creds/") {
            return Ok(SecretMetadata {
                created_by: "database-engine".to_string(),
                ttl: Some(chrono::Duration::hours(1)),
                max_versions: None,
                cas_required: false,
                custom_metadata: HashMap::new(),
            });
        }

        Err(FortressError::secrets_with_code(format!("Database secret metadata not found: {}", path), Some("database".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn health_check(&self) -> Result<EngineHealth> {
        let connections = self.connections.read().await;
        let active_count = connections.values()
            .filter(|conn| conn.expires_time > chrono::Utc::now())
            .count();
        
        Ok(EngineHealth {
            healthy: true,
            message: Some(format!("Database engine healthy with {} active connections", active_count)),
            last_check: chrono::Utc::now(),
            metrics: Some(EngineMetrics {
                operations_per_second: 0.0,
                average_response_time: chrono::Duration::milliseconds(100),
                error_rate: 0.0,
                active_connections: active_count as u64,
                memory_usage: (connections.len() * 512) as u64, // Estimate
            }),
        })
    }
}
