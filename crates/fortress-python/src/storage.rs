//! Storage backend operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;
use fortress_core::storage::{StorageBackend, StorageConfig, StorageError};

/// Python wrapper for StorageBackend
#[pyclass]
pub struct StorageBackend {
    backend: Box<dyn fortress_core::storage::StorageBackend + Send + Sync>,
}

#[pymethods]
impl StorageBackend {
    /// Create a new local filesystem storage backend
    #[staticmethod]
    fn local(base_path: String) -> PyResult<Self> {
        let config = StorageConfig::local_filesystem(base_path);
        let backend = fortress_core::storage::create_local_filesystem_backend(config)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create local storage: {}", e)))?;
        
        Ok(Self { backend })
    }

    /// Create a new S3 storage backend
    #[staticmethod]
    fn s3(bucket: String, region: String, access_key: String, secret_key: String) -> PyResult<Self> {
        let config = StorageConfig::s3(bucket, region, access_key, secret_key);
        let backend = fortress_core::storage::create_s3_backend(config)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create S3 storage: {}", e)))?;
        
        Ok(Self { backend })
    }

    /// Create a new Azure Blob storage backend
    #[staticmethod]
    fn azure_blob(account: String, container: String, access_key: String) -> PyResult<Self> {
        let config = StorageConfig::azure_blob(account, container, access_key);
        let backend = fortress_core::storage::create_azure_blob_backend(config)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create Azure storage: {}", e)))?;
        
        Ok(Self { backend })
    }

    /// Store data
    #[pyo3(signature = (key, value, metadata=None))]
    fn store(&self, py: Python, key: String, value: &PyBytes, metadata: Option<&PyDict>) -> PyResult<PyObject> {
        let value_data = value.as_bytes().to_vec();
        let metadata_map = if let Some(meta_dict) = metadata {
            Some(parse_metadata(meta_dict)?)
        } else {
            None
        };

        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.store(&key, value_data, metadata_map).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Storage failed: {}", e))),
            }
        })
    }

    /// Retrieve data
    #[pyo3(signature = (key))]
    fn retrieve(&self, py: Python, key: String) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.retrieve(&key).await {
                Ok((value, _metadata)) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(PyBytes::new(py, &value).into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Retrieval failed: {}", e))),
            }
        })
    }

    /// Delete data
    #[pyo3(signature = (key))]
    fn delete(&self, py: Python, key: String) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.delete(&key).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Deletion failed: {}", e))),
            }
        })
    }

    /// List keys
    #[pyo3(signature = (prefix=None))]
    fn list_keys(&self, py: Python, prefix: Option<String>) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.list_keys(prefix.as_deref()).await {
                Ok(keys) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let list = PyList::empty(py);
                    for key in keys {
                        list.append(PyString::new(py, &key))?;
                    }
                    Ok(list.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("List keys failed: {}", e))),
            }
        })
    }

    /// Check if key exists
    #[pyo3(signature = (key))]
    fn exists(&self, py: Python, key: String) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.exists(&key).await {
                Ok(exists) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(exists.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Exists check failed: {}", e))),
            }
        })
    }

    /// Get storage statistics
    fn stats(&self, py: Python) -> PyResult<PyObject> {
        let backend = self.backend.clone();
        
        future_into_py(py, async move {
            match backend.stats().await {
                Ok(stats) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let dict = PyDict::new(py);
                    dict.set_item("total_keys", stats.total_keys)?;
                    dict.set_item("total_size", stats.total_size)?;
                    dict.set_item("backend_type", stats.backend_type)?;
                    Ok(dict.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Stats failed: {}", e))),
            }
        })
    }
}

/// Helper function to parse metadata from Python dict
fn parse_metadata(dict: &PyDict) -> PyResult<HashMap<String, String>> {
    let mut metadata = HashMap::new();
    
    for (key, value) in dict.iter() {
        let key_str = key.extract::<String>()?;
        let value_str = value.extract::<String>()?;
        metadata.insert(key_str, value_str);
    }
    
    Ok(metadata)
}

/// Storage configuration utilities
#[pyfunction]
fn create_local_config(base_path: String) -> PyResult<StorageConfigWrapper> {
    let config = StorageConfig::local_filesystem(base_path);
    Ok(StorageConfigWrapper { config })
}

#[pyfunction]
fn create_s3_config(bucket: String, region: String, access_key: String, secret_key: String) -> PyResult<StorageConfigWrapper> {
    let config = StorageConfig::s3(bucket, region, access_key, secret_key);
    Ok(StorageConfigWrapper { config })
}

#[pyfunction]
fn create_azure_config(account: String, container: String, access_key: String) -> PyResult<StorageConfigWrapper> {
    let config = StorageConfig::azure_blob(account, container, access_key);
    Ok(StorageConfigWrapper { config })
}

/// Python wrapper for StorageConfig
#[pyclass]
pub struct StorageConfigWrapper {
    config: StorageConfig,
}

#[pymethods]
impl StorageConfigWrapper {
    /// Get backend type
    fn backend_type(&self) -> String {
        match self.config {
            StorageConfig::LocalFilesystem { .. } => "local".to_string(),
            StorageConfig::S3 { .. } => "s3".to_string(),
            StorageConfig::AzureBlob { .. } => "azure".to_string(),
        }
    }

    /// Get configuration as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, String>> {
        let mut dict = HashMap::new();
        match &self.config {
            StorageConfig::LocalFilesystem { base_path } => {
                dict.insert("backend_type".to_string(), "local".to_string());
                dict.insert("base_path".to_string(), base_path.clone());
            }
            StorageConfig::S3 { bucket, region, .. } => {
                dict.insert("backend_type".to_string(), "s3".to_string());
                dict.insert("bucket".to_string(), bucket.clone());
                dict.insert("region".to_string(), region.clone());
            }
            StorageConfig::AzureBlob { account, container, .. } => {
                dict.insert("backend_type".to_string(), "azure".to_string());
                dict.insert("account".to_string(), account.clone());
                dict.insert("container".to_string(), container.clone());
            }
        }
        Ok(dict)
    }
}
