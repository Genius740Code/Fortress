//! Storage backend operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;

/// Python wrapper for StorageBackend
#[pyclass]
pub struct StorageBackend {
    backend: BackendWrapper,
}

#[derive(Clone)]
enum BackendWrapper {
    Memory(MemoryStorage),
    File(FileStorage),
    Sqlite(SqliteStorage),
}

impl BackendWrapper {
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            BackendWrapper::Memory(backend) => backend.store(key, value).await.map_err(|e| Box::new(e) as _),
            BackendWrapper::File(backend) => backend.store(key, value).await.map_err(|e| Box::new(e) as _),
            BackendWrapper::Sqlite(backend) => backend.store(key, value).await.map_err(|e| Box::new(e) as _),
        }
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            BackendWrapper::Memory(backend) => backend.retrieve(key).await.map_err(|e| Box::new(e) as _),
            BackendWrapper::File(backend) => backend.retrieve(key).await.map_err(|e| Box::new(e) as _),
            BackendWrapper::Sqlite(backend) => backend.retrieve(key).await.map_err(|e| Box::new(e) as _),
        }
    }

    async fn delete(&self, key: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            BackendWrapper::Memory(backend) => backend.delete(key).await.map_err(|e| Box::new(e) as _),
            BackendWrapper::File(backend) => backend.delete(key).await.map_err(|e| Box::new(e) as _),
            BackendWrapper::Sqlite(backend) => backend.delete(key).await.map_err(|e| Box::new(e) as _),
        }
    }

    async fn list_keys(&self) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            BackendWrapper::Memory(backend) => backend.list_keys().await.map_err(|e| Box::new(e) as _),
            BackendWrapper::File(backend) => backend.list_keys().await.map_err(|e| Box::new(e) as _),
            BackendWrapper::Sqlite(backend) => backend.list_keys().await.map_err(|e| Box::new(e) as _),
        }
    }
}

#[pymethods]
impl StorageBackend {
    /// Create a new memory storage backend
    #[staticmethod]
    fn memory() -> Self {
        Self {
            backend: BackendWrapper::Memory(MemoryStorage::new()),
        }
    }

    /// Create a new file storage backend
    #[staticmethod]
    fn file(path: String) -> PyResult<Self> {
        let backend = FileStorage::new(&path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Failed to create file storage: {}", e)))?;
        Ok(Self {
            backend: BackendWrapper::File(backend),
        })
    }

    /// Create a new SQLite storage backend
    #[staticmethod]
    fn sqlite(path: String) -> PyResult<Self> {
        let backend = SqliteStorage::new(&path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Failed to create SQLite storage: {}", e)))?;
        Ok(Self {
            backend: BackendWrapper::Sqlite(backend),
        })
    }

    /// Store data
    #[pyo3(signature = (key, value))]
    fn store(&self, py: Python, key: String, value: &PyBytes) -> PyResult<PyObject> {
        let value_data = value.as_bytes().to_vec();
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.store(&key, &value_data).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(true.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Store failed: {}", e))),
            }
        })
    }

    /// Retrieve data
    fn retrieve(&self, py: Python, key: String) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.retrieve(&key).await {
                Ok(Some(data)) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(PyBytes::new(py, &data).into())
                }
                Ok(None) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Retrieve failed: {}", e))),
            }
        })
    }

    /// Delete data
    fn delete(&self, py: Python, key: String) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.delete(&key).await {
                Ok(deleted) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(deleted.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Delete failed: {}", e))),
            }
        })
    }

    /// List all keys
    fn list_keys(&self, py: Python) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.list_keys().await {
                Ok(keys) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(keys.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("List keys failed: {}", e))),
            }
        })
    }
}
