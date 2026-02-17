//! Multi-tenant isolation for Fortress
//!
//! This module provides tenant separation, resource isolation, and tenant management
//! capabilities for the Fortress database system. It ensures that different tenants
//! are completely isolated from each other while sharing the same underlying
//! infrastructure.

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptionAlgorithm, EncryptionProfile};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

/// Unique identifier for a tenant
pub type TenantId = Uuid;

/// Tenant configuration and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique tenant identifier
    pub id: TenantId,
    
    /// Tenant name for display purposes
    pub name: String,
    
    /// Tenant description
    pub description: Option<String>,
    
    /// Encryption configuration specific to this tenant
    pub encryption_config: Option<TenantEncryptionConfig>,
    
    /// Resource limits for this tenant
    pub resource_limits: TenantResourceLimits,
    
    /// Whether this tenant is active
    pub active: bool,
    
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Last modified timestamp
    pub modified_at: chrono::DateTime<chrono::Utc>,
}

/// Tenant-specific encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantEncryptionConfig {
    /// Encryption algorithm for this tenant
    pub algorithm: String,
    
    /// Encryption profile
    pub profile: String,
    
    /// Whether to use tenant-specific key management
    pub use_tenant_keys: bool,
    
    /// Key rotation interval (in seconds)
    pub key_rotation_interval: Option<u64>,
}

/// Resource limits for a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantResourceLimits {
    /// Maximum number of databases
    pub max_databases: Option<u32>,
    
    /// Maximum storage size in bytes
    pub max_storage_size: Option<u64>,
    
    /// Maximum number of connections
    pub max_connections: Option<u32>,
    
    /// CPU quota (percentage)
    pub cpu_quota: Option<f32>,
    
    /// Memory quota (percentage)
    pub memory_quota: Option<f32>,
}

/// Tenant manager for handling multi-tenant operations
pub trait TenantManager: Send + Sync {
    /// Create a new tenant
    async fn create_tenant(&self, tenant: CreateTenantRequest) -> Result<Tenant>;
    
    /// Get tenant by ID
    async fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<Tenant>>;
    
    /// Update tenant configuration
    async fn update_tenant(&self, tenant_id: &TenantId, update: UpdateTenantRequest) -> Result<Tenant>;
    
    /// Delete a tenant
    async fn delete_tenant(&self, tenant_id: &TenantId) -> Result<()>;
    
    /// List all tenants
    async fn list_tenants(&self) -> Result<Vec<Tenant>>;
    
    /// Get tenant statistics
    async fn get_tenant_stats(&self, tenant_id: &TenantId) -> Result<TenantStats>;
}

/// Request to create a new tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTenantRequest {
    /// Tenant name
    pub name: String,
    
    /// Tenant description
    pub description: Option<String>,
    
    /// Initial encryption configuration
    pub encryption_config: Option<TenantEncryptionConfig>,
    
    /// Initial resource limits
    pub resource_limits: Option<TenantResourceLimits>,
}

/// Request to update an existing tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTenantRequest {
    /// Updated name
    pub name: Option<String>,
    
    /// Updated description
    pub description: Option<String>,
    
    /// Updated encryption configuration
    pub encryption_config: Option<TenantEncryptionConfig>,
    
    /// Updated resource limits
    pub resource_limits: Option<TenantResourceLimits>,
}

/// Tenant statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantStats {
    /// Number of databases
    pub database_count: u32,
    
    /// Total storage used in bytes
    pub storage_used: u64,
    
    /// Number of active connections
    pub active_connections: u32,
    
    /// CPU usage percentage
    pub cpu_usage: f32,
    
    /// Memory usage percentage
    pub memory_usage: f32,
}

/// In-memory tenant manager implementation
#[derive(Debug)]
pub struct InMemoryTenantManager {
    tenants: Arc<tokio::sync::RwLock<HashMap<TenantId, Tenant>>>,
}

impl InMemoryTenantManager {
    /// Create a new in-memory tenant manager
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

impl TenantManager for InMemoryTenantManager {
    async fn create_tenant(&self, request: CreateTenantRequest) -> Result<Tenant> {
        let tenant_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        
        let tenant = Tenant {
            id: tenant_id,
            name: request.name.clone(),
            description: request.description.clone(),
            encryption_config: request.encryption_config.clone(),
            resource_limits: request.resource_limits.clone(),
            active: true,
            created_at: now,
            modified_at: now,
        };
        
        let mut tenants = self.tenants.write().await;
        tenants.insert(tenant_id, tenant);
        
        Ok(tenant)
    }
    
    async fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<Tenant>> {
        let tenants = self.tenants.read().await;
        Ok(tenants.get(tenant_id).cloned())
    }
    
    async fn update_tenant(&self, tenant_id: &TenantId, update: UpdateTenantRequest) -> Result<Tenant> {
        let mut tenants = self.tenants.write().await;
        
        if let Some(tenant) = tenants.get_mut(tenant_id) {
            if let Some(name) = &update.name {
                tenant.name = name.clone();
            }
            if let Some(description) = &update.description {
                tenant.description = description.clone();
            }
            if let Some(encryption_config) = &update.encryption_config {
                tenant.encryption_config = encryption_config.clone();
            }
            if let Some(resource_limits) = &update.resource_limits {
                tenant.resource_limits = resource_limits.clone();
            }
            tenant.modified_at = chrono::Utc::now();
        } else {
            return Err(FortressError::key_management(
                "Tenant not found".to_string(),
                Some(tenant_id.to_string()),
                crate::error::KeyErrorCode::KeyNotFound,
            ));
        }
        
        Ok(tenant)
    }
    
    async fn delete_tenant(&self, tenant_id: &TenantId) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        tenants.remove(tenant_id);
        Ok(())
    }
    
    async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let tenants = self.tenants.read().await;
        Ok(tenants.values().cloned().collect())
    }
    
    async fn get_tenant_stats(&self, tenant_id: &TenantId) -> Result<TenantStats> {
        // For now, return placeholder stats
        Ok(TenantStats {
            database_count: 0,
            storage_used: 0,
            active_connections: 0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_tenant_creation() {
        let manager = InMemoryTenantManager::new();
        let request = CreateTenantRequest {
            name: "test-tenant".to_string(),
            description: Some("Test tenant".to_string()),
            encryption_config: None,
            resource_limits: None,
        };
        
        let tenant = manager.create_tenant(request).await.unwrap();
        assert_eq!(tenant.name, "test-tenant");
        assert!(tenant.active);
    }
    
    #[tokio::test]
    async fn test_tenant_retrieval() {
        let manager = InMemoryTenantManager::new();
        let request = CreateTenantRequest {
            name: "test-tenant".to_string(),
            description: Some("Test tenant".to_string()),
            encryption_config: None,
            resource_limits: None,
        };
        
        let tenant = manager.create_tenant(request).await.unwrap();
        let retrieved = manager.get_tenant(&tenant.id).await.unwrap();
        assert_eq!(retrieved.id, tenant.id);
        assert_eq!(retrieved.name, tenant.name);
    }
}
