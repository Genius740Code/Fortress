//! Policy engine and RBAC for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;
use fortress_core::policy::{PolicyEngine, Role, Permission, Resource, PolicyEffect};

/// Python wrapper for PolicyEngine
#[pyclass]
pub struct PolicyEngine {
    engine: fortress_core::policy::PolicyEngine,
}

#[pymethods]
impl PolicyEngine {
    /// Create a new PolicyEngine
    #[new]
    fn new() -> Self {
        Self {
            engine: fortress_core::policy::PolicyEngine::new(),
        }
    }

    /// Add a role to the policy engine
    #[pyo3(signature = (role))]
    fn add_role(&self, py: Python, role: &RoleWrapper) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        let role_data = role.role.clone();
        
        future_into_py(py, async move {
            match engine.add_role(role_data).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to add role: {}", e))),
            }
        })
    }

    /// Remove a role from the policy engine
    #[pyo3(signature = (role_name))]
    fn remove_role(&self, py: Python, role_name: String) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.remove_role(&role_name).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to remove role: {}", e))),
            }
        })
    }

    /// Assign a role to a user
    #[pyo3(signature = (user_id, role_name))]
    fn assign_role(&self, py: Python, user_id: String, role_name: String) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.assign_role(&user_id, &role_name).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to assign role: {}", e))),
            }
        })
    }

    /// Revoke a role from a user
    #[pyo3(signature = (user_id, role_name))]
    fn revoke_role(&self, py: Python, user_id: String, role_name: String) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.revoke_role(&user_id, &role_name).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to revoke role: {}", e))),
            }
        })
    }

    /// Check if a user has permission for a resource
    #[pyo3(signature = (user_id, resource, action))]
    fn check_permission(&self, py: Python, user_id: String, resource: String, action: String) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.check_permission(&user_id, &resource, &action).await {
                Ok(allowed) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(allowed.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Permission check failed: {}", e))),
            }
        })
    }

    /// Get all roles for a user
    #[pyo3(signature = (user_id))]
    fn get_user_roles(&self, py: Python, user_id: String) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.get_user_roles(&user_id).await {
                Ok(roles) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let list = PyList::empty(py);
                    for role in roles {
                        let role_wrapper = RoleWrapper::new(role);
                        list.append(role_wrapper)?;
                    }
                    Ok(list.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to get user roles: {}", e))),
            }
        })
    }

    /// List all roles
    fn list_roles(&self, py: Python) -> PyResult<PyObject> {
        let engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.list_roles().await {
                Ok(roles) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let list = PyList::empty(py);
                    for role in roles {
                        let role_wrapper = RoleWrapper::new(role);
                        list.append(role_wrapper)?;
                    }
                    Ok(list.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to list roles: {}", e))),
            }
        })
    }
}

/// Python wrapper for Role
#[pyclass]
pub struct RoleWrapper {
    role: Role,
}

impl RoleWrapper {
    fn new(role: Role) -> Self {
        Self { role }
    }
}

#[pymethods]
impl RoleWrapper {
    /// Create a new role
    #[new]
    fn new_role(name: String, description: String, permissions: Vec<String>) -> PyResult<Self> {
        let role_permissions = permissions.into_iter()
            .map(|p| Permission::from_string(&p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid permission: {}", e)))?;

        let role = Role::new(name, description, role_permissions);
        Ok(Self { role })
    }

    /// Get role name
    fn name(&self) -> String {
        self.role.name().to_string()
    }

    /// Get role description
    fn description(&self) -> String {
        self.role.description().to_string()
    }

    /// Get role permissions
    fn permissions(&self) -> Vec<String> {
        self.role.permissions().iter().map(|p| p.to_string()).collect()
    }

    /// Check if role has specific permission
    #[pyo3(signature = (permission))]
    fn has_permission(&self, permission: String) -> PyResult<bool> {
        let perm = Permission::from_string(&permission)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid permission: {}", e)))?;
        Ok(self.role.has_permission(&perm))
    }

    /// Get role as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("name".to_string(), self.role.name().to_string().into_py(py));
        dict.insert("description".to_string(), self.role.description().to_string().into_py(py));
        
        let permissions_list = PyList::empty(py);
        for permission in self.role.permissions() {
            permissions_list.append(permission.to_string())?;
        }
        dict.insert("permissions".to_string(), permissions_list.into());

        Ok(dict)
    }
}

/// Python wrapper for Permission
#[pyclass]
pub struct PermissionWrapper {
    permission: Permission,
}

#[pymethods]
impl PermissionWrapper {
    /// Create a new permission
    #[staticmethod]
    fn new(resource: String, action: String, effect: String) -> PyResult<Self> {
        let effect_parsed = match effect.as_str() {
            "Allow" => PolicyEffect::Allow,
            "Deny" => PolicyEffect::Deny,
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid effect: {}", effect)
            )),
        };

        let permission = Permission::new(resource, action, effect_parsed);
        Ok(Self { permission })
    }

    /// Get resource
    fn resource(&self) -> String {
        self.permission.resource().to_string()
    }

    /// Get action
    fn action(&self) -> String {
        self.permission.action().to_string()
    }

    /// Get effect
    fn effect(&self) -> String {
        format!("{:?}", self.permission.effect())
    }

    /// Get permission as string
    fn to_string(&self) -> String {
        self.permission.to_string()
    }
}

/// Python wrapper for Resource
#[pyclass]
pub struct ResourceWrapper {
    resource: Resource,
}

#[pymethods]
impl ResourceWrapper {
    /// Create a new resource
    #[new]
    fn new(name: String, resource_type: String, path: Option<String>, attributes: Option<HashMap<String, String>>) -> Self {
        let resource = Resource::new(name, resource_type, path, attributes.unwrap_or_default());
        Self { resource }
    }

    /// Get resource name
    fn name(&self) -> String {
        self.resource.name().to_string()
    }

    /// Get resource type
    fn resource_type(&self) -> String {
        self.resource.resource_type().to_string()
    }

    /// Get resource path
    fn path(&self) -> Option<String> {
        self.resource.path().map(|p| p.to_string())
    }

    /// Get resource attributes
    fn attributes(&self) -> HashMap<String, String> {
        self.resource.attributes().clone()
    }

    /// Get resource as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("name".to_string(), self.resource.name().to_string().into_py(py));
        dict.insert("type".to_string(), self.resource.resource_type().to_string().into_py(py));
        dict.insert("path".to_string(), self.resource.path().map(|p| p.to_string()).into_py(py));
        
        let attributes_dict = PyDict::new(py);
        for (key, value) in self.resource.attributes() {
            attributes_dict.set_item(key, value)?;
        }
        dict.insert("attributes".to_string(), attributes_dict.into());

        Ok(dict)
    }
}

/// Policy utilities
#[pyfunction]
fn create_role(name: String, description: String, permissions: Vec<String>) -> PyResult<RoleWrapper> {
    RoleWrapper::new_role(name, description, permissions)
}

#[pyfunction]
fn create_permission(resource: String, action: String, effect: String) -> PyResult<PermissionWrapper> {
    PermissionWrapper::new(resource, action, effect)
}

#[pyfunction]
fn create_resource(name: String, resource_type: String, path: Option<String>, attributes: Option<HashMap<String, String>>) -> ResourceWrapper {
    ResourceWrapper::new(name, resource_type, path, attributes)
}

#[pyfunction]
fn list_permission_effects() -> Vec<String> {
    vec![
        "Allow".to_string(),
        "Deny".to_string(),
    ]
}

#[pyfunction]
fn list_resource_types() -> Vec<String> {
    vec![
        "key".to_string(),
        "data".to_string(),
        "config".to_string(),
        "audit".to_string(),
        "policy".to_string(),
        "tenant".to_string(),
        "cluster".to_string(),
        "backup".to_string(),
        "hsm".to_string(),
    ]
}

#[pyfunction]
fn list_actions() -> Vec<String> {
    vec![
        "read".to_string(),
        "write".to_string(),
        "delete".to_string(),
        "create".to_string(),
        "update".to_string(),
        "execute".to_string(),
        "admin".to_string(),
    ]
}
