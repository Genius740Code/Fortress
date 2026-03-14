//! Key management operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;
use fortress_core::key::{KeyId, KeyMetadata, RotationInterval, RotationMetrics};

/// Python wrapper for KeyManager
#[pyclass]
pub struct KeyManager {
    manager: fortress_core::key::KeyManager,
}

#[pymethods]
impl KeyManager {
    /// Create a new KeyManager
    #[new]
    fn new() -> Self {
        Self {
            manager: fortress_core::key::KeyManager::new(),
        }
    }

    /// Generate a new key
    #[pyo3(signature = (algorithm_name, metadata=None))]
    fn generate_key(&self, py: Python, algorithm_name: String, metadata: Option<&PyDict>) -> PyResult<PyObject> {
        let algorithm = match algorithm_name.as_str() {
            "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
            "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
            "aes256gcm" => Box::new(Aes256Gcm::new()),
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Unknown algorithm: {}", algorithm_name)
            )),
        };

        let key_metadata = if let Some(meta_dict) = metadata {
            Some(parse_key_metadata(meta_dict)?)
        } else {
            None
        };

        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.generate_key_with_metadata(&*algorithm, key_metadata).await {
                Ok(key_id) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(PyString::new(py, &key_id.to_string()).into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key generation failed: {}", e))),
            }
        })
    }

    /// Get a key by ID
    #[pyo3(signature = (key_id))]
    fn get_key(&self, py: Python, key_id: String) -> PyResult<PyObject> {
        let key_id_parsed = KeyId::from_str(&key_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key ID: {}", e)))?;

        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.get_key(&key_id_parsed).await {
                Ok(key) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(PyBytes::new(py, &key).into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key retrieval failed: {}", e))),
            }
        })
    }

    /// Delete a key
    #[pyo3(signature = (key_id))]
    fn delete_key(&self, py: Python, key_id: String) -> PyResult<PyObject> {
        let key_id_parsed = KeyId::from_str(&key_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key ID: {}", e)))?;

        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.delete_key(&key_id_parsed).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key deletion failed: {}", e))),
            }
        })
    }

    /// List all keys
    fn list_keys(&self, py: Python) -> PyResult<PyObject> {
        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.list_keys().await {
                Ok(keys) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let list = PyList::empty(py);
                    for key_id in keys {
                        list.append(PyString::new(py, &key_id.to_string()))?;
                    }
                    Ok(list.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key listing failed: {}", e))),
            }
        })
    }

    /// Rotate a key
    #[pyo3(signature = (key_id))]
    fn rotate_key(&self, py: Python, key_id: String) -> PyResult<PyObject> {
        let key_id_parsed = KeyId::from_str(&key_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key ID: {}", e)))?;

        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.rotate_key(&key_id_parsed).await {
                Ok(new_key_id) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(PyString::new(py, &new_key_id.to_string()).into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key rotation failed: {}", e))),
            }
        })
    }
}

/// Python wrapper for KeyMetadata
#[pyclass]
pub struct KeyMetadata {
    metadata: fortress_core::key::KeyMetadata,
}

#[pymethods]
impl KeyMetadata {
    /// Create new key metadata
    #[new]
    fn new(
        algorithm: String,
        created_at: String,
        expires_at: Option<String>,
        purpose: Option<String>,
        tags: Option<Vec<String>>,
    ) -> PyResult<Self> {
        let created_dt = chrono::DateTime::parse_from_rfc3339(&created_at)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid created_at format: {}", e)))?
            .with_timezone(&chrono::Utc);

        let expires_dt = if let Some(exp_str) = expires_at {
            Some(chrono::DateTime::parse_from_rfc3339(&exp_str)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid expires_at format: {}", e)))?
                .with_timezone(&chrono::Utc))
        } else {
            None
        };

        let metadata = fortress_core::key::KeyMetadata::new(
            algorithm,
            created_dt,
            expires_dt,
            purpose,
            tags.unwrap_or_default(),
        );

        Ok(Self { metadata })
    }

    /// Get algorithm name
    fn algorithm(&self) -> String {
        self.metadata.algorithm().to_string()
    }

    /// Get creation timestamp
    fn created_at(&self) -> String {
        self.metadata.created_at().to_rfc3339()
    }

    /// Get expiration timestamp
    fn expires_at(&self) -> Option<String> {
        self.metadata.expires_at().map(|dt| dt.to_rfc3339())
    }

    /// Get purpose
    fn purpose(&self) -> Option<String> {
        self.metadata.purpose().map(|p| p.to_string())
    }

    /// Get tags
    fn tags(&self) -> Vec<String> {
        self.metadata.tags().clone()
    }
}

/// Helper function to parse key metadata from Python dict
fn parse_key_metadata(dict: &PyDict) -> PyResult<KeyMetadata> {
    let algorithm = dict.get_item("algorithm")
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing 'algorithm' field"))?
        .extract::<String>()?;

    let created_at = dict.get_item("created_at")
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("Missing 'created_at' field"))?
        .extract::<String>()?;

    let expires_at = dict.get_item("expires_at")?.extract::<Option<String>>()?;
    let purpose = dict.get_item("purpose")?.extract::<Option<String>>()?;
    let tags = dict.get_item("tags")?.extract::<Option<Vec<String>>>()?;

    Ok(KeyMetadata::new(algorithm, created_at, expires_at, purpose, tags)?)
}
