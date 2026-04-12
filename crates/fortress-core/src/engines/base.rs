//! Base trait for secret engines

use async_trait::async_trait;
use crate::error::{FortressError, Result};
use super::types::*;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

/// Base trait that all secret engines must implement
#[async_trait]
pub trait SecretsEngine: Send + Sync {
    /// Get the engine name
    fn name(&self) -> &str;
    
    /// Get the engine version
    fn version(&self) -> &str;
    
    /// Get engine capabilities
    fn capabilities(&self) -> EngineCapabilities;
    
    /// Initialize the engine with configuration
    async fn initialize(&mut self, config: &serde_json::Value) -> Result<()>;
    
    /// Shutdown the engine and cleanup resources
    async fn shutdown(&mut self) -> Result<()>;
    
    /// Read a secret
    async fn read_secret(&self, path: &str, context: &Context) -> Result<Secret>;
    
    /// Write a secret
    async fn write_secret(&self, path: &str, data: &Secret, context: &Context) -> Result<()>;
    
    /// Delete a secret
    async fn delete_secret(&self, path: &str, context: &Context) -> Result<()>;
    
    /// List secrets at a path
    async fn list_secrets(&self, path: &str, context: &Context) -> Result<Vec<String>>;
    
    /// Renew a lease
    async fn renew_lease(&self, lease_id: &str, increment: Duration, context: &Context) -> Result<Duration>;
    
    /// Revoke a lease
    async fn revoke_lease(&self, lease_id: &str, context: &Context) -> Result<()>;
    
    /// Rotate a secret
    async fn rotate_secret(&self, path: &str, context: &Context) -> Result<Secret>;
    
    /// Get secret metadata
    async fn get_secret_metadata(&self, path: &str, context: &Context) -> Result<SecretMetadata>;
    
    /// Health check for the engine
    async fn health_check(&self) -> Result<EngineHealth>;
}

/// Engine health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineHealth {
    pub healthy: bool,
    pub message: Option<String>,
    pub last_check: DateTime<Utc>,
    pub metrics: Option<EngineMetrics>,
}

/// Engine performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineMetrics {
    pub operations_per_second: f64,
    pub average_response_time: Duration,
    pub error_rate: f64,
    pub active_connections: u64,
    pub memory_usage: u64,
}

/// Default implementation for optional methods
#[async_trait]
pub trait SecretsEngineDefaults: SecretsEngine {
    /// Default lease renewal implementation
    async fn default_renew_lease(&self, _lease_id: &str, increment: Duration, _context: &Context) -> Result<Duration> {
        Ok(increment)
    }
    
    /// Default lease revocation implementation
    async fn default_revoke_lease(&self, _lease_id: &str, _context: &Context) -> Result<()> {
        Ok(())
    }
    
    /// Default rotation implementation
    async fn default_rotate_secret(&self, path: &str, context: &Context) -> Result<Secret> {
        // Read existing secret
        let mut secret = self.read_secret(path, context).await?;
        
        // Update with rotation metadata
        secret.updated_time = Utc::now();
        secret.version += 1;
        
        // Add rotation info to data
        if let Some(obj) = secret.data.as_object_mut() {
            obj.insert("rotated_at".to_string(), serde_json::Value::String(Utc::now().to_rfc3339()));
            obj.insert("rotated_by".to_string(), serde_json::Value::String(context.token.token.entity_id.clone()));
        }
        
        Ok(secret)
    }
    
    /// Default health check
    async fn default_health_check(&self) -> Result<EngineHealth> {
        Ok(EngineHealth {
            healthy: true,
            message: Some("Engine is operating normally".to_string()),
            last_check: Utc::now(),
            metrics: None,
        })
    }
}
