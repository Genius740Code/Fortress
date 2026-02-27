//! Multi-tenant isolation for Fortress
//!
//! This module provides tenant separation, resource isolation, and tenant management
//! capabilities for the Fortress database system. It ensures that different tenants
//! are completely isolated from each other while sharing the same underlying
//! infrastructure.

use crate::error::{FortressError, Result};
use crate::encryption::EncryptionProfile;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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

impl Default for TenantResourceLimits {
    fn default() -> Self {
        Self {
            max_databases: None,
            max_storage_size: None,
            max_connections: None,
            cpu_quota: None,
            memory_quota: None,
        }
    }
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

/// Resource isolation manager for enforcing tenant limits
#[derive(Debug)]
pub struct ResourceIsolationManager {
    /// Per-tenant resource usage tracking
    resource_usage: Arc<RwLock<HashMap<TenantId, TenantResourceUsage>>>,
    
    /// Global resource limits
    global_limits: GlobalResourceLimits,
}

/// Resource usage tracking for a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantResourceUsage {
    /// Current storage usage in bytes
    pub storage_used: u64,
    
    /// Current number of databases
    pub database_count: u32,
    
    /// Current active connections
    pub active_connections: u32,
    
    /// CPU usage (percentage points)
    pub cpu_usage: f32,
    
    /// Memory usage (percentage points)
    pub memory_usage: f32,
    
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Global resource limits for the entire system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalResourceLimits {
    /// Maximum total storage across all tenants
    pub max_total_storage: Option<u64>,
    
    /// Maximum total databases across all tenants
    pub max_total_databases: Option<u32>,
    
    /// Maximum total connections across all tenants
    pub max_total_connections: Option<u32>,
    
    /// Maximum CPU usage across all tenants (percentage)
    pub max_total_cpu: Option<f32>,
    
    /// Maximum memory usage across all tenants (percentage)
    pub max_total_memory: Option<f32>,
}

impl Default for GlobalResourceLimits {
    fn default() -> Self {
        Self {
            max_total_storage: None,
            max_total_databases: None,
            max_total_connections: None,
            max_total_cpu: None,
            max_total_memory: None,
        }
    }
}

impl Default for TenantResourceUsage {
    fn default() -> Self {
        let now = chrono::Utc::now();
        Self {
            storage_used: 0,
            database_count: 0,
            active_connections: 0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            last_updated: now,
        }
    }
}

impl ResourceIsolationManager {
    /// Create a new resource isolation manager
    pub fn new(global_limits: GlobalResourceLimits) -> Self {
        Self {
            resource_usage: Arc::new(RwLock::new(HashMap::new())),
            global_limits,
        }
    }
    
    /// Check if a tenant can create a new database
    pub async fn can_create_database(&self, tenant_id: &TenantId, tenant_limits: &TenantResourceLimits) -> Result<bool> {
        let usage = self.get_or_create_usage(tenant_id).await;
        
        // Check tenant-specific limits
        if let Some(max_databases) = tenant_limits.max_databases {
            if usage.database_count >= max_databases {
                return Ok(false);
            }
        }
        
        // Check global limits
        let all_usage = self.resource_usage.read().await;
        let total_databases: u32 = all_usage.values().map(|u| u.database_count).sum();
        
        if let Some(max_total) = self.global_limits.max_total_databases {
            if total_databases >= max_total {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Check if a tenant can allocate additional storage
    pub async fn can_allocate_storage(&self, tenant_id: &TenantId, additional_bytes: u64, tenant_limits: &TenantResourceLimits) -> Result<bool> {
        let usage = self.get_or_create_usage(tenant_id).await;
        
        // Check tenant-specific limits
        if let Some(max_storage) = tenant_limits.max_storage_size {
            if usage.storage_used + additional_bytes > max_storage {
                return Ok(false);
            }
        }
        
        // Check global limits
        let all_usage = self.resource_usage.read().await;
        let total_storage: u64 = all_usage.values().map(|u| u.storage_used).sum();
        
        if let Some(max_total) = self.global_limits.max_total_storage {
            if total_storage + additional_bytes > max_total {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Check if a tenant can establish a new connection
    pub async fn can_create_connection(&self, tenant_id: &TenantId, tenant_limits: &TenantResourceLimits) -> Result<bool> {
        let usage = self.get_or_create_usage(tenant_id).await;
        
        // Check tenant-specific limits
        if let Some(max_connections) = tenant_limits.max_connections {
            if usage.active_connections >= max_connections {
                return Ok(false);
            }
        }
        
        // Check global limits
        let all_usage = self.resource_usage.read().await;
        let total_connections: u32 = all_usage.values().map(|u| u.active_connections).sum();
        
        if let Some(max_total) = self.global_limits.max_total_connections {
            if total_connections >= max_total {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Record database creation for a tenant
    pub async fn record_database_creation(&self, tenant_id: &TenantId) -> Result<()> {
        let mut usage_map = self.resource_usage.write().await;
        let usage = usage_map.entry(*tenant_id).or_insert_with(TenantResourceUsage::default);
        usage.database_count += 1;
        usage.last_updated = chrono::Utc::now();
        Ok(())
    }
    
    /// Record storage allocation for a tenant
    pub async fn record_storage_allocation(&self, tenant_id: &TenantId, bytes: u64) -> Result<()> {
        let mut usage_map = self.resource_usage.write().await;
        let usage = usage_map.entry(*tenant_id).or_insert_with(TenantResourceUsage::default);
        usage.storage_used += bytes;
        usage.last_updated = chrono::Utc::now();
        Ok(())
    }
    
    /// Record connection creation for a tenant
    pub async fn record_connection_creation(&self, tenant_id: &TenantId) -> Result<()> {
        let mut usage_map = self.resource_usage.write().await;
        let usage = usage_map.entry(*tenant_id).or_insert_with(TenantResourceUsage::default);
        usage.active_connections += 1;
        usage.last_updated = chrono::Utc::now();
        Ok(())
    }
    
    /// Record connection termination for a tenant
    pub async fn record_connection_termination(&self, tenant_id: &TenantId) -> Result<()> {
        let mut usage_map = self.resource_usage.write().await;
        if let Some(usage) = usage_map.get_mut(tenant_id) {
            if usage.active_connections > 0 {
                usage.active_connections -= 1;
                usage.last_updated = chrono::Utc::now();
            }
        }
        Ok(())
    }
    
    /// Update CPU usage for a tenant
    pub async fn update_cpu_usage(&self, tenant_id: &TenantId, cpu_usage: f32) -> Result<()> {
        let mut usage_map = self.resource_usage.write().await;
        let usage = usage_map.entry(*tenant_id).or_insert_with(TenantResourceUsage::default);
        usage.cpu_usage = cpu_usage;
        usage.last_updated = chrono::Utc::now();
        Ok(())
    }
    
    /// Update memory usage for a tenant
    pub async fn update_memory_usage(&self, tenant_id: &TenantId, memory_usage: f32) -> Result<()> {
        let mut usage_map = self.resource_usage.write().await;
        let usage = usage_map.entry(*tenant_id).or_insert_with(TenantResourceUsage::default);
        usage.memory_usage = memory_usage;
        usage.last_updated = chrono::Utc::now();
        Ok(())
    }
    
    /// Get resource usage for a specific tenant
    pub async fn get_tenant_usage(&self, tenant_id: &TenantId) -> Result<Option<TenantResourceUsage>> {
        let usage_map = self.resource_usage.read().await;
        Ok(usage_map.get(tenant_id).cloned())
    }
    
    /// Get global resource usage across all tenants
    pub async fn get_global_usage(&self) -> Result<GlobalResourceUsage> {
        let usage_map = self.resource_usage.read().await;
        
        let total_storage: u64 = usage_map.values().map(|u| u.storage_used).sum();
        let total_databases: u32 = usage_map.values().map(|u| u.database_count).sum();
        let total_connections: u32 = usage_map.values().map(|u| u.active_connections).sum();
        let total_cpu: f32 = usage_map.values().map(|u| u.cpu_usage).sum();
        let total_memory: f32 = usage_map.values().map(|u| u.memory_usage).sum();
        
        Ok(GlobalResourceUsage {
            total_storage,
            total_databases,
            total_connections,
            total_cpu,
            total_memory,
        })
    }
    
    /// Get or create resource usage for a tenant
    async fn get_or_create_usage(&self, tenant_id: &TenantId) -> TenantResourceUsage {
        let mut usage_map = self.resource_usage.write().await;
        usage_map.entry(*tenant_id).or_insert_with(TenantResourceUsage::default).clone()
    }
}

/// Global resource usage across all tenants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalResourceUsage {
    /// Total storage used across all tenants
    pub total_storage: u64,
    
    /// Total databases across all tenants
    pub total_databases: u32,
    
    /// Total connections across all tenants
    pub total_connections: u32,
    
    /// Total CPU usage across all tenants
    pub total_cpu: f32,
    
    /// Total memory usage across all tenants
    pub total_memory: f32,
}

/// In-memory tenant manager implementation
#[derive(Debug)]
pub struct InMemoryTenantManager {
    tenants: Arc<RwLock<HashMap<TenantId, Tenant>>>,
    resource_isolation: ResourceIsolationManager,
}

impl InMemoryTenantManager {
    /// Create a new in-memory tenant manager
    pub fn new() -> Self {
        Self::with_global_limits(GlobalResourceLimits::default())
    }
    
    /// Create a new in-memory tenant manager with custom global limits
    pub fn with_global_limits(global_limits: GlobalResourceLimits) -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            resource_isolation: ResourceIsolationManager::new(global_limits),
        }
    }
    
    /// Get reference to the resource isolation manager
    pub fn resource_isolation(&self) -> &ResourceIsolationManager {
        &self.resource_isolation
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
            resource_limits: request.resource_limits.clone().unwrap_or_default(),
            active: true,
            created_at: now,
            modified_at: now,
        };
        
        let tenant_clone = tenant.clone();
        let mut tenants = self.tenants.write().await;
        tenants.insert(tenant_id, tenant);
        
        Ok(tenant_clone)
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
                tenant.description = Some(description.clone());
            }
            if let Some(encryption_config) = &update.encryption_config {
                tenant.encryption_config = Some(encryption_config.clone());
            }
            if let Some(resource_limits) = &update.resource_limits {
                tenant.resource_limits = resource_limits.clone();
            }
            tenant.modified_at = chrono::Utc::now();
            Ok(tenant.clone())
        } else {
            return Err(FortressError::key_management(
                "Tenant not found".to_string(),
                Some(tenant_id.to_string()),
                crate::error::KeyErrorCode::KeyNotFound,
            ));
        }
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
        let usage = self.resource_isolation.get_tenant_usage(tenant_id).await?;
        
        match usage {
            Some(usage) => Ok(TenantStats {
                database_count: usage.database_count,
                storage_used: usage.storage_used,
                active_connections: usage.active_connections,
                cpu_usage: usage.cpu_usage,
                memory_usage: usage.memory_usage,
            }),
            None => Ok(TenantStats {
                database_count: 0,
                storage_used: 0,
                active_connections: 0,
                cpu_usage: 0.0,
                memory_usage: 0.0,
            }),
        }
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
        assert_eq!(retrieved.as_ref().unwrap().id, tenant.id);
        assert_eq!(retrieved.as_ref().unwrap().name, tenant.name);
    }
    
    #[tokio::test]
    async fn test_resource_isolation_database_limits() {
        let global_limits = GlobalResourceLimits {
            max_total_databases: Some(10),
            ..Default::default()
        };
        let manager = InMemoryTenantManager::with_global_limits(global_limits);
        
        let tenant_limits = TenantResourceLimits {
            max_databases: Some(3),
            ..Default::default()
        };
        
        let request = CreateTenantRequest {
            name: "test-tenant".to_string(),
            description: None,
            encryption_config: None,
            resource_limits: Some(tenant_limits.clone()),
        };
        
        let tenant = manager.create_tenant(request).await.unwrap();
        let isolation = manager.resource_isolation();
        
        // Should be able to create databases up to the limit
        assert!(isolation.can_create_database(&tenant.id, &tenant_limits).await.unwrap());
        
        // Record database creation
        isolation.record_database_creation(&tenant.id).await.unwrap();
        isolation.record_database_creation(&tenant.id).await.unwrap();
        
        // Still should be able to create (2 < 3)
        assert!(isolation.can_create_database(&tenant.id, &tenant_limits).await.unwrap());
        
        // Record third database
        isolation.record_database_creation(&tenant.id).await.unwrap();
        
        // Now should not be able to create (3 >= 3)
        assert!(!isolation.can_create_database(&tenant.id, &tenant_limits).await.unwrap());
    }
    
    #[tokio::test]
    async fn test_resource_isolation_storage_limits() {
        let global_limits = GlobalResourceLimits {
            max_total_storage: Some(1000),
            ..Default::default()
        };
        let manager = InMemoryTenantManager::with_global_limits(global_limits);
        
        let tenant_limits = TenantResourceLimits {
            max_storage_size: Some(500),
            ..Default::default()
        };
        
        let request = CreateTenantRequest {
            name: "test-tenant".to_string(),
            description: None,
            encryption_config: None,
            resource_limits: Some(tenant_limits.clone()),
        };
        
        let tenant = manager.create_tenant(request).await.unwrap();
        let isolation = manager.resource_isolation();
        
        // Should be able to allocate storage up to the limit
        assert!(isolation.can_allocate_storage(&tenant.id, 400, &tenant_limits).await.unwrap());
        
        // Record storage allocation
        isolation.record_storage_allocation(&tenant.id, 400).await.unwrap();
        
        // Should not be able to allocate more than the limit
        assert!(!isolation.can_allocate_storage(&tenant.id, 200, &tenant_limits).await.unwrap());
        
        // Should be able to allocate within remaining space
        assert!(isolation.can_allocate_storage(&tenant.id, 100, &tenant_limits).await.unwrap());
    }
    
    #[tokio::test]
    async fn test_resource_isolation_connection_limits() {
        let global_limits = GlobalResourceLimits {
            max_total_connections: Some(5),
            ..Default::default()
        };
        let manager = InMemoryTenantManager::with_global_limits(global_limits);
        
        let tenant_limits = TenantResourceLimits {
            max_connections: Some(3),
            ..Default::default()
        };
        
        let request = CreateTenantRequest {
            name: "test-tenant".to_string(),
            description: None,
            encryption_config: None,
            resource_limits: Some(tenant_limits.clone()),
        };
        
        let tenant = manager.create_tenant(request).await.unwrap();
        let isolation = manager.resource_isolation();
        
        // Should be able to create connections up to the limit
        assert!(isolation.can_create_connection(&tenant.id, &tenant_limits).await.unwrap());
        
        // Record connection creation
        isolation.record_connection_creation(&tenant.id).await.unwrap();
        isolation.record_connection_creation(&tenant.id).await.unwrap();
        
        // Still should be able to create (2 < 3)
        assert!(isolation.can_create_connection(&tenant.id, &tenant_limits).await.unwrap());
        
        // Record third connection
        isolation.record_connection_creation(&tenant.id).await.unwrap();
        
        // Now should not be able to create (3 >= 3)
        assert!(!isolation.can_create_connection(&tenant.id, &tenant_limits).await.unwrap());
        
        // Record connection termination
        isolation.record_connection_termination(&tenant.id).await.unwrap();
        
        // Should be able to create again
        assert!(isolation.can_create_connection(&tenant.id, &tenant_limits).await.unwrap());
    }
    
    #[tokio::test]
    async fn test_tenant_stats_integration() {
        let manager = InMemoryTenantManager::new();
        
        let request = CreateTenantRequest {
            name: "test-tenant".to_string(),
            description: None,
            encryption_config: None,
            resource_limits: None,
        };
        
        let tenant = manager.create_tenant(request).await.unwrap();
        let isolation = manager.resource_isolation();
        
        // Record some activity
        isolation.record_database_creation(&tenant.id).await.unwrap();
        isolation.record_storage_allocation(&tenant.id, 1024).await.unwrap();
        isolation.record_connection_creation(&tenant.id).await.unwrap();
        isolation.update_cpu_usage(&tenant.id, 25.5).await.unwrap();
        isolation.update_memory_usage(&tenant.id, 45.2).await.unwrap();
        
        // Get stats
        let stats = manager.get_tenant_stats(&tenant.id).await.unwrap();
        
        assert_eq!(stats.database_count, 1);
        assert_eq!(stats.storage_used, 1024);
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.cpu_usage, 25.5);
        assert_eq!(stats.memory_usage, 45.2);
    }
    
    #[tokio::test]
    async fn test_global_resource_usage() {
        let global_limits = GlobalResourceLimits::default();
        let isolation = ResourceIsolationManager::new(global_limits);
        
        let tenant1_id = Uuid::new_v4();
        let tenant2_id = Uuid::new_v4();
        
        // Record activity for both tenants
        isolation.record_database_creation(&tenant1_id).await.unwrap();
        isolation.record_database_creation(&tenant2_id).await.unwrap();
        isolation.record_storage_allocation(&tenant1_id, 500).await.unwrap();
        isolation.record_storage_allocation(&tenant2_id, 300).await.unwrap();
        isolation.record_connection_creation(&tenant1_id).await.unwrap();
        isolation.record_connection_creation(&tenant2_id).await.unwrap();
        
        // Get global usage
        let global_usage = isolation.get_global_usage().await.unwrap();
        
        assert_eq!(global_usage.total_databases, 2);
        assert_eq!(global_usage.total_storage, 800);
        assert_eq!(global_usage.total_connections, 2);
    }
}
