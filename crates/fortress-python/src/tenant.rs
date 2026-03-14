//! Tenant management operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;

/// Python wrapper for TenantManager
#[pyclass]
pub struct TenantManager {
    manager: ManagerWrapper,
}

#[derive(Clone)]
struct ManagerWrapper {
    tenants: HashMap<String, TenantData>,
}

#[derive(Clone)]
struct TenantData {
    id: String,
    name: String,
    description: Option<String>,
    resource_limits: TenantResourceLimitsData,
    active: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    modified_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
struct TenantResourceLimitsData {
    max_storage_mb: Option<u64>,
    max_keys: Option<u64>,
    max_api_calls_per_hour: Option<u64>,
}

impl ManagerWrapper {
    fn new() -> Self {
        Self {
            tenants: HashMap::new(),
        }
    }

    fn create_tenant(&mut self, name: String, description: Option<String>, resource_limits: Option<TenantResourceLimitsData>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        
        let tenant = TenantData {
            id: id.clone(),
            name,
            description,
            resource_limits: resource_limits.unwrap_or_default(),
            active: true,
            created_at: now,
            modified_at: now,
        };
        
        self.tenants.insert(id.clone(), tenant);
        Ok(id)
    }

    fn get_tenant(&self, tenant_id: &str) -> Option<TenantData> {
        self.tenants.get(tenant_id).cloned()
    }

    fn update_tenant(&mut self, tenant_id: &str, name: Option<String>, description: Option<String>, resource_limits: Option<TenantResourceLimitsData>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(tenant) = self.tenants.get_mut(tenant_id) {
            if let Some(name) = name {
                tenant.name = name;
            }
            if let Some(description) = description {
                tenant.description = Some(description);
            }
            if let Some(resource_limits) = resource_limits {
                tenant.resource_limits = resource_limits;
            }
            tenant.modified_at = chrono::Utc::now();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn delete_tenant(&mut self, tenant_id: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.tenants.remove(tenant_id).is_some())
    }

    fn list_tenants(&self) -> Vec<String> {
        self.tenants.keys().cloned().collect()
    }

    fn activate_tenant(&mut self, tenant_id: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(tenant) = self.tenants.get_mut(tenant_id) {
            tenant.active = true;
            tenant.modified_at = chrono::Utc::now();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn deactivate_tenant(&mut self, tenant_id: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(tenant) = self.tenants.get_mut(tenant_id) {
            tenant.active = false;
            tenant.modified_at = chrono::Utc::now();
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Default for TenantResourceLimitsData {
    fn default() -> Self {
        Self {
            max_storage_mb: Some(1024), // 1GB default
            max_keys: Some(1000),
            max_api_calls_per_hour: Some(10000),
        }
    }
}

#[pymethods]
impl TenantManager {
    /// Create a new TenantManager
    #[new]
    fn new() -> Self {
        Self {
            manager: ManagerWrapper::new(),
        }
    }

    /// Create a new tenant
    #[pyo3(signature = (name, description=None, resource_limits=None))]
    fn create_tenant(&self, py: Python, name: String, description: Option<String>, resource_limits: Option<&PyDict>) -> PyResult<PyObject> {
        let limits_data = if let Some(limits_dict) = resource_limits {
            Some(parse_resource_limits(limits_dict)?)
        } else {
            None
        };

        let mut manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.create_tenant(name, description, limits_data) {
                Ok(tenant_id) => {
                    Ok(tenant_id.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create tenant: {}", e))),
            }
        })
    }

    /// Get tenant information
    fn get_tenant(&self, tenant_id: String) -> PyResult<Option<TenantWrapper>> {
        match self.manager.get_tenant(&tenant_id) {
            Some(tenant) => Ok(Some(TenantWrapper::new(tenant))),
            None => Ok(None),
        }
    }

    /// Update tenant information
    #[pyo3(signature = (tenant_id, name=None, description=None, resource_limits=None))]
    fn update_tenant(&self, py: Python, tenant_id: String, name: Option<String>, description: Option<String>, resource_limits: Option<&PyDict>) -> PyResult<PyObject> {
        let limits_data = if let Some(limits_dict) = resource_limits {
            Some(parse_resource_limits(limits_dict)?)
        } else {
            None
        };

        let mut manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.update_tenant(&tenant_id, name, description, limits_data) {
                Ok(updated) => {
                    Ok(updated.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to update tenant: {}", e))),
            }
        })
    }

    /// Delete a tenant
    fn delete_tenant(&self, py: Python, tenant_id: String) -> PyResult<PyObject> {
        let mut manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.delete_tenant(&tenant_id) {
                Ok(deleted) => {
                    Ok(deleted.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to delete tenant: {}", e))),
            }
        })
    }

    /// List all tenants
    fn list_tenants(&self) -> PyResult<Vec<String>> {
        Ok(self.manager.list_tenants())
    }

    /// Activate a tenant
    fn activate_tenant(&self, py: Python, tenant_id: String) -> PyResult<PyObject> {
        let mut manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.activate_tenant(&tenant_id) {
                Ok(activated) => {
                    Ok(activated.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to activate tenant: {}", e))),
            }
        })
    }

    /// Deactivate a tenant
    fn deactivate_tenant(&self, py: Python, tenant_id: String) -> PyResult<PyObject> {
        let mut manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.deactivate_tenant(&tenant_id) {
                Ok(deactivated) => {
                    Ok(deactivated.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to deactivate tenant: {}", e))),
            }
        })
    }
}

/// Python wrapper for Tenant
#[pyclass]
pub struct TenantWrapper {
    tenant: TenantData,
}

impl TenantWrapper {
    fn new(tenant: TenantData) -> Self {
        Self { tenant }
    }
}

#[pymethods]
impl TenantWrapper {
    /// Get tenant ID
    fn id(&self) -> String {
        self.tenant.id.clone()
    }

    /// Get tenant name
    fn name(&self) -> String {
        self.tenant.name.clone()
    }

    /// Get tenant description
    fn description(&self) -> Option<String> {
        self.tenant.description.clone()
    }

    /// Get resource limits
    fn resource_limits(&self) -> TenantResourceLimitsWrapper {
        TenantResourceLimitsWrapper::new(&self.tenant.resource_limits)
    }

    /// Check if tenant is active
    fn is_active(&self) -> bool {
        self.tenant.active
    }

    /// Get creation time
    fn created_at(&self) -> String {
        self.tenant.created_at.to_rfc3339()
    }

    /// Get modification time
    fn modified_at(&self) -> String {
        self.tenant.modified_at.to_rfc3339()
    }
}

/// Python wrapper for TenantResourceLimits
#[pyclass]
pub struct TenantResourceLimitsWrapper {
    limits: TenantResourceLimitsData,
}

impl TenantResourceLimitsWrapper {
    fn new(limits: &TenantResourceLimitsData) -> Self {
        Self { limits: limits.clone() }
    }
}

#[pymethods]
impl TenantResourceLimitsWrapper {
    /// Get max storage in MB
    fn max_storage_mb(&self) -> Option<u64> {
        self.limits.max_storage_mb
    }

    /// Get max keys
    fn max_keys(&self) -> Option<u64> {
        self.limits.max_keys
    }

    /// Get max API calls per hour
    fn max_api_calls_per_hour(&self) -> Option<u64> {
        self.limits.max_api_calls_per_hour
    }
}

/// Parse resource limits from Python dictionary
fn parse_resource_limits(py_dict: &PyDict) -> PyResult<TenantResourceLimitsData> {
    let max_storage_mb = py_dict.get_item("max_storage_mb")
        .and_then(|v| v.extract::<u64>().ok());
    
    let max_keys = py_dict.get_item("max_keys")
        .and_then(|v| v.extract::<u64>().ok());
    
    let max_api_calls_per_hour = py_dict.get_item("max_api_calls_per_hour")
        .and_then(|v| v.extract::<u64>().ok());

    Ok(TenantResourceLimitsData {
        max_storage_mb,
        max_keys,
        max_api_calls_per_hour,
    })
}
