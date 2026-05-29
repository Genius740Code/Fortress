//! AWS secret engine for AWS service integration

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::error::{FortressError, Result, SecretsErrorCode};
use super::base::*;
use super::types::*;
use chrono::{DateTime, Utc};

/// AWS configuration
#[derive(Debug, Clone)]
pub struct AwsConfig {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub max_lease_ttl: chrono::Duration,
    pub allowed_roles: Vec<String>,
}

/// AWS IAM role configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AwsRoleConfig {
    pub role_arn: String,
    pub policy_arns: Vec<String>,
    pub ttl: chrono::Duration,
    pub max_ttl: chrono::Duration,
    pub policies: Vec<String>,
}

/// AWS credentials
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub region: String,
    pub lease_id: String,
    pub lease_duration: chrono::Duration,
    pub created_time: chrono::DateTime<chrono::Utc>,
    pub expires_time: chrono::DateTime<chrono::Utc>,
}

/// AWS session information
#[derive(Debug, Clone)]
pub struct AwsSession {
    pub role_name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub region: String,
    pub created_time: chrono::DateTime<chrono::Utc>,
    pub expires_time: chrono::DateTime<chrono::Utc>,
    pub lease_id: String,
}

/// AWS secret engine
pub struct AwsEngine {
    config: AwsConfig,
    roles: Arc<RwLock<HashMap<String, AwsRoleConfig>>>,
    sessions: Arc<RwLock<HashMap<String, AwsSession>>>,
    name: String,
}

impl AwsEngine {
    /// Create a new AWS engine
    pub fn new(config: AwsConfig) -> Self {
        Self {
            config,
            roles: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            name: "aws".to_string(),
        }
    }

    /// Create an AWS role
    pub async fn create_role(&self, role_name: &str, role_config: AwsRoleConfig) -> Result<()> {
        let mut roles = self.roles.write().await;
        
        // Validate role configuration
        if !self.config.allowed_roles.is_empty() && !self.config.allowed_roles.contains(&role_name.to_string()) {
            return Err(FortressError::secrets_with_code("Role not allowed by configuration".to_string(), Some("aws".to_string()), SecretsErrorCode::PolicyViolation));
        }
        
        // Validate role ARN format
        if !role_config.role_arn.starts_with("arn:aws:iam::") {
            return Err(FortressError::secrets_with_code("Invalid role ARN format".to_string(), Some("aws".to_string()), SecretsErrorCode::InvalidInput));
        }
        
        roles.insert(role_name.to_string(), role_config);
        tracing::info!("Created AWS role: {}", role_name);
        
        Ok(())
    }

    /// Generate AWS credentials
    pub async fn generate_credentials(&self, role_name: &str, ttl: Option<chrono::Duration>) -> Result<AwsCredentials> {
        let roles = self.roles.read().await;
        let role_config = roles.get(role_name)
            .ok_or_else(|| FortressError::secrets_with_code(format!("Role '{}' not found", role_name), Some("aws".to_string()), SecretsErrorCode::RoleNotFound))?;
        
        // Calculate lease duration
        let lease_duration = ttl.unwrap_or(role_config.ttl);
        if lease_duration > role_config.max_ttl {
            return Err(FortressError::secrets_with_code("Requested TTL exceeds maximum TTL for role".to_string(), Some("aws".to_string()), SecretsErrorCode::InvalidTtl));
        }
        
        let now = chrono::Utc::now();
        let expires_time = now + lease_duration;
        
        // Create lease ID
        let lease_id = self.generate_lease_id().await?;
        let lease_id_for_logging = lease_id.clone();
        
        // In a real implementation, this would:
        // 1. Use AWS STS to assume the role
        // 2. Get temporary credentials
        // 3. Store the session for later revocation
        
        let credentials = self.simulate_sts_assume_role(&role_config.role_arn, lease_duration).await?;
        
        let session = AwsSession {
            role_name: role_name.to_string(),
            access_key_id: credentials.access_key_id.clone(),
            secret_access_key: credentials.secret_access_key.clone(),
            session_token: credentials.session_token.clone(),
            region: self.config.region.clone(),
            created_time: now,
            expires_time,
            lease_id: lease_id.clone(),
        };
        
        // Store session info
        let mut sessions = self.sessions.write().await;
        sessions.insert(lease_id.clone(), session);
        
        let aws_credentials = AwsCredentials {
            access_key_id: credentials.access_key_id,
            secret_access_key: credentials.secret_access_key,
            session_token: credentials.session_token,
            region: self.config.region.clone(),
            lease_id,
            lease_duration,
            created_time: now,
            expires_time,
        };
        
        tracing::info!("Generated AWS credentials for role: {}, lease: {}", role_name, lease_id_for_logging);
        Ok(aws_credentials)
    }

    /// Revoke AWS credentials
    pub async fn revoke_credentials(&self, lease_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.remove(lease_id) {
            // In a real implementation, this would:
            // 1. Call AWS STS to invalidate the session if possible
            // 2. Remove any local references
            
            tracing::info!("Revoked AWS credentials for lease: {}", lease_id);
            return Ok(());
        }
        
        Err(FortressError::secrets_with_code(format!("Credentials not found for lease: {}", lease_id), Some("aws".to_string()), SecretsErrorCode::LeaseNotFound))
    }

    /// List active sessions
    pub async fn list_sessions(&self) -> Result<Vec<AwsSession>> {
        let sessions = self.sessions.read().await;
        let mut active_sessions = Vec::new();
        
        let now = chrono::Utc::now();
        for session in sessions.values() {
            if session.expires_time > now {
                active_sessions.push(session.clone());
            }
        }
        
        Ok(active_sessions)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        
        let initial_count = sessions.len();
        sessions.retain(|_, session| session.expires_time > now);
        let cleaned_count = initial_count - sessions.len();
        
        if cleaned_count > 0 {
            tracing::info!("Cleaned up {} expired AWS sessions", cleaned_count);
        }
        
        Ok(cleaned_count)
    }

    /// Generate STS credentials (simulated)
    async fn simulate_sts_assume_role(&self, role_arn: &str, duration: chrono::Duration) -> Result<AwsCredentials> {
        use rand::RngCore;
        use rand::rngs::OsRng;
        
        // Generate mock credentials using OsRng for consistency
        let mut access_key_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut access_key_bytes);
        let access_key_id = format!("AKIA{}", u64::from_be_bytes(access_key_bytes) % 9000000000000000u64 + 1000000000000000u64);
        
        let mut secret_key_bytes = [0u8; 40];
        OsRng.fill_bytes(&mut secret_key_bytes);
        let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let secret_key: String = secret_key_bytes
            .iter()
            .map(|&byte| charset[byte as usize % charset.len()] as char)
            .collect();
        
        let mut session_token_bytes = [0u8; 352];
        OsRng.fill_bytes(&mut session_token_bytes);
        let session_token: String = session_token_bytes
            .iter()
            .map(|&byte| charset[byte as usize % charset.len()] as char)
            .collect();
        
        Ok(AwsCredentials {
            access_key_id,
            secret_access_key: secret_key,
            session_token,
            region: self.config.region.clone(),
            lease_id: String::new(), // Will be set by caller
            lease_duration: duration,
            created_time: chrono::Utc::now(),
            expires_time: chrono::Utc::now() + duration,
        })
    }

    async fn generate_lease_id(&self) -> Result<String> {
        use uuid::Uuid;
        Ok(format!("aws/{}", Uuid::new_v4()))
    }
}

#[async_trait]
impl SecretsEngine for AwsEngine {
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
                "sts".to_string(),
            ],
        }
    }

    async fn initialize(&mut self, config: &serde_json::Value) -> Result<()> {
        // Parse configuration
        if let Some(region) = config.get("region").and_then(|v| v.as_str()) {
            self.config.region = region.to_string();
        }
        
        if let Some(access_key_id) = config.get("access_key_id").and_then(|v| v.as_str()) {
            self.config.access_key_id = access_key_id.to_string();
        }
        
        if let Some(secret_access_key) = config.get("secret_access_key").and_then(|v| v.as_str()) {
            self.config.secret_access_key = secret_access_key.to_string();
        }
        
        if let Some(allowed_roles) = config.get("allowed_roles").and_then(|v| v.as_array()) {
            self.config.allowed_roles = allowed_roles.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect();
        }
        
        if let Some(max_lease_ttl) = config.get("max_lease_ttl").and_then(|v| v.as_i64()) {
            self.config.max_lease_ttl = chrono::Duration::seconds(max_lease_ttl);
        }
        
        // Test AWS connection (simplified)
        tracing::info!("AWS engine initialized for region: {}", self.config.region);
        
        // Start cleanup task
        let sessions_cleanup = self.sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
            
            loop {
                interval.tick().await;
                
                let engine = AwsEngine {
                    config: AwsConfig {
                        region: String::new(),
                        access_key_id: String::new(),
                        secret_access_key: String::new(),
                        session_token: None,
                        max_lease_ttl: chrono::Duration::hours(1),
                        allowed_roles: vec![],
                    },
                    roles: Arc::new(RwLock::new(HashMap::new())),
                    sessions: sessions_cleanup.clone(),
                    name: "aws".to_string(),
                };
                
                if let Ok(count) = engine.cleanup_expired_sessions().await {
                    if count > 0 {
                        tracing::debug!("Cleaned up {} expired AWS sessions", count);
                    }
                }
            }
        });
        
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Revoke all active sessions
        let sessions = self.sessions.read().await;
        let lease_ids: Vec<String> = sessions.keys().cloned().collect();
        drop(sessions);
        
        for lease_id in lease_ids {
            if let Err(e) = self.revoke_credentials(&lease_id).await {
                tracing::warn!("Failed to revoke AWS credentials {}: {}", lease_id, e);
            }
        }
        
        tracing::info!("AWS engine shutdown complete");
        Ok(())
    }

    async fn read_secret(&self, path: &str, _context: &Context) -> Result<Secret> {
        if path.starts_with("creds/") {
            let role_name = &path[6..]; // Remove "creds/" prefix
            
            let credentials = self.generate_credentials(role_name, None).await?;
            
            return Ok(Secret {
                data: serde_json::to_value(credentials)?,
                metadata: SecretMetadata {
                    created_by: "aws-engine".to_string(),
                    ttl: Some(chrono::Duration::hours(1)),
                    max_versions: None,
                    cas_required: false,
                    custom_metadata: HashMap::new(),
                },
                lease_id: Some(format!("aws/{}", path)),
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
                    created_by: "aws-engine".to_string(),
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

        if path == "sts" {
            // Return STS configuration
            return Ok(Secret {
                data: serde_json::json!({
                    "region": self.config.region,
                    "max_lease_ttl": self.config.max_lease_ttl.num_seconds()
                }),
                metadata: SecretMetadata {
                    created_by: "aws-engine".to_string(),
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

        Err(FortressError::secrets_with_code(format!("AWS secret not found: {}", path), Some("aws".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn write_secret(&self, path: &str, data: &Secret, context: &Context) -> Result<()> {
        if path.starts_with("roles/") {
            let role_name = &path[6..]; // Remove "roles/" prefix
            
            let role_arn = data.data.get("role_arn")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FortressError::secrets_with_code("Missing role_arn".to_string(), Some("aws".to_string()), SecretsErrorCode::InvalidInput))?;
            
            let policy_arns = data.data.get("policy_arns")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();
            
            let policies = data.data.get("policies")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();
            
            let ttl = data.data.get("ttl")
                .and_then(|v| v.as_i64())
                .map(|s| chrono::Duration::seconds(s))
                .unwrap_or(chrono::Duration::hours(1));
            
            let max_ttl = data.data.get("max_ttl")
                .and_then(|v| v.as_i64())
                .map(|s| chrono::Duration::seconds(s))
                .unwrap_or(self.config.max_lease_ttl);
            
            let role_config = AwsRoleConfig {
                role_arn: role_arn.to_string(),
                policy_arns,
                ttl,
                max_ttl,
                policies,
            };
            
            self.create_role(role_name, role_config).await?;
            return Ok(());
        }

        Err(FortressError::secrets_with_code(format!("Invalid AWS operation: {}", path), Some("aws".to_string()), SecretsErrorCode::InvalidOperation))
    }

    async fn delete_secret(&self, path: &str, _context: &Context) -> Result<()> {
        if path.starts_with("leases/") {
            let lease_id = &path[7..]; // Remove "leases/" prefix
            
            if self.revoke_credentials(lease_id).await.is_ok() {
                return Ok(());
            }
        }

        Err(FortressError::secrets_with_code(format!("AWS secret not found for deletion: {}", path), Some("aws".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn list_secrets(&self, path: &str, _context: &Context) -> Result<Vec<String>> {
        if path == "roles" {
            let roles = self.roles.read().await;
            return Ok(roles.keys().cloned().collect());
        }

        if path == "" {
            return Ok(vec!["roles".to_string(), "leases".to_string(), "sts".to_string()]);
        }

        Ok(vec![])
    }

    async fn renew_lease(&self, lease_id: &str, increment: chrono::Duration, _context: &Context) -> Result<chrono::Duration> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(lease_id) {
            session.expires_time = chrono::Utc::now() + increment;
            tracing::info!("Renewed AWS lease {} for {} seconds", lease_id, increment.num_seconds());
            return Ok(increment);
        }

        Err(FortressError::secrets_with_code(format!("Lease not found: {}", lease_id), Some("aws".to_string()), SecretsErrorCode::LeaseNotFound))
    }

    async fn revoke_lease(&self, lease_id: &str, _context: &Context) -> Result<()> {
        self.revoke_credentials(lease_id).await
    }

    async fn rotate_secret(&self, path: &str, _context: &Context) -> Result<Secret> {
        Err(FortressError::secrets_with_code(format!("AWS engine does not support rotation for: {}", path), Some("aws".to_string()), SecretsErrorCode::OperationNotSupported))
    }

    async fn get_secret_metadata(&self, path: &str, _context: &Context) -> Result<SecretMetadata> {
        if path.starts_with("creds/") {
            return Ok(SecretMetadata {
                created_by: "aws-engine".to_string(),
                ttl: Some(chrono::Duration::hours(1)),
                max_versions: None,
                cas_required: false,
                custom_metadata: HashMap::new(),
            });
        }

        Err(FortressError::secrets_with_code(format!("AWS secret metadata not found: {}", path), Some("aws".to_string()), SecretsErrorCode::SecretNotFound))
    }

    async fn health_check(&self) -> Result<EngineHealth> {
        let sessions = self.sessions.read().await;
        let active_count = sessions.values()
            .filter(|session| session.expires_time > chrono::Utc::now())
            .count();
        
        Ok(EngineHealth {
            healthy: true,
            message: Some(format!("AWS engine healthy with {} active sessions", active_count)),
            last_check: chrono::Utc::now(),
            metrics: Some(EngineMetrics {
                operations_per_second: 0.0,
                average_response_time: chrono::Duration::milliseconds(200),
                error_rate: 0.0,
                active_connections: active_count as u64,
                memory_usage: (sessions.len() * 1024) as u64, // Estimate
            }),
        })
    }
}
