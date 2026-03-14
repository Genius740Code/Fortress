//! Multi-tenant management for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;
use fortress_core::tenant::{TenantManager, Tenant, TenantId, CreateTenantRequest, UpdateTenantRequest, TenantStats, TenantResourceLimits};

/// Python wrapper for TenantManager
#[pyclass]
pub struct TenantManager {
    manager: fortress_core::tenant::TenantManager,
}

#[pymethods]
impl TenantManager {
    /// Create a new TenantManager
    #[new]
    fn new() -> Self {
        Self {
            manager: fortress_core::tenant::TenantManager::new(),
        }
    }

    /// Create a new tenant
    #[pyo3(signature = (request))]
    fn create_tenant(&self, py: Python, request: &CreateTenantRequestWrapper) -> PyResult<PyObject> {
        let manager = self.manager.clone();
        let request_data = request.request.clone();
        
        future_into_py(py, async move {
            match manager.create_tenant(request_data).await {
                Ok(tenant) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let tenant_wrapper = TenantWrapper::new(tenant);
                    Ok(tenant_wrapper.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create tenant: {}", e))),
            }
        })
    }

    /// Get a tenant by ID
    #[pyo3(signature = (tenant_id))]
    fn get_tenant(&self, py: Python, tenant_id: String) -> PyResult<PyObject> {
        let tenant_id_parsed = TenantId::from_str(&tenant_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid tenant ID: {}", e)))?;

        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.get_tenant(&tenant_id_parsed).await {
                Ok(tenant) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let tenant_wrapper = TenantWrapper::new(tenant);
                    Ok(tenant_wrapper.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to get tenant: {}", e))),
            }
        })
    }

    /// Update a tenant
    #[pyo3(signature = (tenant_id, request))]
    fn update_tenant(&self, py: Python, tenant_id: String, request: &UpdateTenantRequestWrapper) -> PyResult<PyObject> {
        let tenant_id_parsed = TenantId::from_str(&tenant_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid tenant ID: {}", e)))?;

        let manager = self.manager.clone();
        let request_data = request.request.clone();
        
        future_into_py(py, async move {
            match manager.update_tenant(&tenant_id_parsed, request_data).await {
                Ok(tenant) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let tenant_wrapper = TenantWrapper::new(tenant);
                    Ok(tenant_wrapper.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to update tenant: {}", e))),
            }
        })
    }

    /// Delete a tenant
    #[pyo3(signature = (tenant_id))]
    fn delete_tenant(&self, py: Python, tenant_id: String) -> PyResult<PyObject> {
        let tenant_id_parsed = TenantId::from_str(&tenant_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid tenant ID: {}", e)))?;

        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.delete_tenant(&tenant_id_parsed).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to delete tenant: {}", e))),
            }
        })
    }

    /// List all tenants
    fn list_tenants(&self, py: Python) -> PyResult<PyObject> {
        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.list_tenants().await {
                Ok(tenants) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let list = PyList::empty(py);
                    for tenant in tenants {
                        let tenant_wrapper = TenantWrapper::new(tenant);
                        list.append(tenant_wrapper)?;
                    }
                    Ok(list.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to list tenants: {}", e))),
            }
        })
    }

    /// Get tenant statistics
    #[pyo3(signature = (tenant_id))]
    fn get_tenant_stats(&self, py: Python, tenant_id: String) -> PyResult<PyObject> {
        let tenant_id_parsed = TenantId::from_str(&tenant_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid tenant ID: {}", e)))?;

        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.get_tenant_stats(&tenant_id_parsed).await {
                Ok(stats) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let stats_wrapper = TenantStatsWrapper::new(stats);
                    Ok(stats_wrapper.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to get tenant stats: {}", e))),
            }
        })
    }
}

/// Python wrapper for Tenant
#[pyclass]
pub struct TenantWrapper {
    tenant: Tenant,
}

impl TenantWrapper {
    fn new(tenant: Tenant) -> Self {
        Self { tenant }
    }
}

#[pymethods]
impl TenantWrapper {
    /// Get tenant ID
    fn id(&self) -> String {
        self.tenant.id().to_string()
    }

    /// Get tenant name
    fn name(&self) -> String {
        self.tenant.name().to_string()
    }

    /// Get tenant description
    fn description(&self) -> String {
        self.tenant.description().to_string()
    }

    /// Get tenant status
    fn status(&self) -> String {
        format!("{:?}", self.tenant.status())
    }

    /// Get creation timestamp
    fn created_at(&self) -> String {
        self.tenant.created_at().to_rfc3339()
    }

    /// Get last updated timestamp
    fn updated_at(&self) -> String {
        self.tenant.updated_at().to_rfc3339()
    }

    /// Get resource limits
    fn resource_limits(&self) -> PyResult<TenantResourceLimitsWrapper> {
        Ok(TenantResourceLimitsWrapper::new(self.tenant.resource_limits().clone()))
    }

    /// Get tenant as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("id".to_string(), self.tenant.id().to_string().into_py(py));
        dict.insert("name".to_string(), self.tenant.name().to_string().into_py(py));
        dict.insert("description".to_string(), self.tenant.description().to_string().into_py(py));
        dict.insert("status".to_string(), format!("{:?}", self.tenant.status()).into_py(py));
        dict.insert("created_at".to_string(), self.tenant.created_at().to_rfc3339().into_py(py));
        dict.insert("updated_at".to_string(), self.tenant.updated_at().to_rfc3339().into_py(py));
        
        let limits_wrapper = TenantResourceLimitsWrapper::new(self.tenant.resource_limits().clone());
        dict.insert("resource_limits".to_string(), limits_wrapper.to_dict()?.into_py(py));

        Ok(dict)
    }
}

/// Python wrapper for CreateTenantRequest
#[pyclass]
pub struct CreateTenantRequestWrapper {
    request: CreateTenantRequest,
}

#[pymethods]
impl CreateTenantRequestWrapper {
    /// Create a new tenant creation request
    #[new]
    fn new(name: String, description: String, resource_limits: Option<&TenantResourceLimitsWrapper>) -> PyResult<Self> {
        let limits = resource_limits.map(|l| l.limits.clone()).unwrap_or_default();
        let request = CreateTenantRequest::new(name, description, limits);
        Ok(Self { request })
    }
}

/// Python wrapper for UpdateTenantRequest
#[pyclass]
pub struct UpdateTenantRequestWrapper {
    request: UpdateTenantRequest,
}

#[pymethods]
impl UpdateTenantRequestWrapper {
    /// Create a new tenant update request
    #[new]
    fn new(name: Option<String>, description: Option<String>, resource_limits: Option<&TenantResourceLimitsWrapper>) -> Self {
        let limits = resource_limits.map(|l| l.limits.clone());
        let request = UpdateTenantRequest::new(name, description, limits);
        Self { request }
    }
}

/// Python wrapper for TenantResourceLimits
#[pyclass]
pub struct TenantResourceLimitsWrapper {
    limits: TenantResourceLimits,
}

impl TenantResourceLimitsWrapper {
    fn new(limits: TenantResourceLimits) -> Self {
        Self { limits }
    }
}

#[pymethods]
impl TenantResourceLimitsWrapper {
    /// Create new resource limits
    #[new]
    fn new_limits(
        max_keys: Option<usize>,
        max_storage_mb: Option<u64>,
        max_users: Option<usize>,
        max_api_calls_per_hour: Option<u64>,
    ) -> Self {
        let mut limits = TenantResourceLimits::default();
        
        if let Some(keys) = max_keys {
            limits.set_max_keys(keys);
        }
        if let Some(storage) = max_storage_mb {
            limits.set_max_storage_mb(storage);
        }
        if let Some(users) = max_users {
            limits.set_max_users(users);
        }
        if let Some(calls) = max_api_calls_per_hour {
            limits.set_max_api_calls_per_hour(calls);
        }

        Self { limits }
    }

    /// Get maximum keys
    fn max_keys(&self) -> usize {
        self.limits.max_keys()
    }

    /// Get maximum storage in MB
    fn max_storage_mb(&self) -> u64 {
        self.limits.max_storage_mb()
    }

    /// Get maximum users
    fn max_users(&self) -> usize {
        self.limits.max_users()
    }

    /// Get maximum API calls per hour
    fn max_api_calls_per_hour(&self) -> u64 {
        self.limits.max_api_calls_per_hour()
    }

    /// Get limits as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("max_keys".to_string(), self.limits.max_keys().into_py(py));
        dict.insert("max_storage_mb".to_string(), self.limits.max_storage_mb().into_py(py));
        dict.insert("max_users".to_string(), self.limits.max_users().into_py(py));
        dict.insert("max_api_calls_per_hour".to_string(), self.limits.max_api_calls_per_hour().into_py(py));

        Ok(dict)
    }
}

/// Python wrapper for TenantStats
#[pyclass]
pub struct TenantStatsWrapper {
    stats: TenantStats,
}

impl TenantStatsWrapper {
    fn new(stats: TenantStats) -> Self {
        Self { stats }
    }
}

#[pymethods]
impl TenantStatsWrapper {
    /// Get current key count
    fn current_keys(&self) -> usize {
        self.stats.current_keys()
    }

    /// Get current storage usage in MB
    fn current_storage_mb(&self) -> u64 {
        self.stats.current_storage_mb()
    }

    /// Get current user count
    fn current_users(&self) -> usize {
        self.stats.current_users()
    }

    /// Get current API calls per hour
    fn current_api_calls_per_hour(&self) -> u64 {
        self.stats.current_api_calls_per_hour()
    }

    /// Get resource utilization percentage
    fn resource_utilization(&self) -> f64 {
        self.stats.resource_utilization()
    }

    /// Get stats as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("current_keys".to_string(), self.stats.current_keys().into_py(py));
        dict.insert("current_storage_mb".to_string(), self.stats.current_storage_mb().into_py(py));
        dict.insert("current_users".to_string(), self.stats.current_users().into_py(py));
        dict.insert("current_api_calls_per_hour".to_string(), self.stats.current_api_calls_per_hour().into_py(py));
        dict.insert("resource_utilization".to_string(), self.stats.resource_utilization().into_py(py));

        Ok(dict)
    }
}

/// Tenant utilities
#[pyfunction]
fn create_tenant_request(name: String, description: String, resource_limits: Option<&TenantResourceLimitsWrapper>) -> PyResult<CreateTenantRequestWrapper> {
    CreateTenantRequestWrapper::new(name, description, resource_limits)
}

#[pyfunction]
fn create_update_tenant_request(name: Option<String>, description: Option<String>, resource_limits: Option<&TenantResourceLimitsWrapper>) -> UpdateTenantRequestWrapper {
    UpdateTenantRequestWrapper::new(name, description, resource_limits)
}

#[pyfunction]
fn create_resource_limits(
    max_keys: Option<usize>,
    max_storage_mb: Option<u64>,
    max_users: Option<usize>,
    max_api_calls_per_hour: Option<u64>,
) -> TenantResourceLimitsWrapper {
    TenantResourceLimitsWrapper::new_limits(max_keys, max_storage_mb, max_users, max_api_calls_per_hour)
}

#[pyfunction]
fn generate_tenant_id() -> String {
    TenantId::new().to_string()
}
