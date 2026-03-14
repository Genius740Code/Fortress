//! Key management operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;
use fortress_core::key::{KeyId, RotationInterval, RotationMetrics};

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
                    Ok(key_id.to_string().into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key generation failed: {}", e))),
            }
        })
    }

    /// Get key metadata
    fn get_key_metadata(&self, key_id: String) -> PyResult<KeyMetadataWrapper> {
        let key_id = KeyId::from_string(&key_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key ID: {}", e)))?;
        
        match self.manager.get_metadata(&key_id) {
            Some(metadata) => Ok(KeyMetadataWrapper::new(metadata)),
            None => Err(PyErr::new::<pyo3::exceptions::PyKeyError, _>("Key not found")),
        }
    }

    /// List all keys
    fn list_keys(&self) -> PyResult<Vec<String>> {
        let keys = self.manager.list_keys();
        Ok(keys.into_iter().map(|id| id.to_string()).collect())
    }

    /// Rotate a key
    #[pyo3(signature = (key_id, force=false))]
    fn rotate_key(&self, py: Python, key_id: String, force: bool) -> PyResult<PyObject> {
        let key_id = KeyId::from_string(&key_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key ID: {}", e)))?;
        
        let manager = self.manager.clone();
        
        future_into_py(py, async move {
            match manager.rotate_key(&key_id, force).await {
                Ok(new_key_id) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(new_key_id.to_string().into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key rotation failed: {}", e))),
            }
        })
    }

    /// Delete a key
    fn delete_key(&self, key_id: String) -> PyResult<bool> {
        let key_id = KeyId::from_string(&key_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key ID: {}", e)))?;
        
        Ok(self.manager.delete_key(&key_id))
    }
}

/// Python wrapper for KeyMetadata
#[pyclass]
pub struct KeyMetadataWrapper {
    metadata: KeyMetadataData,
}

struct KeyMetadataData {
    id: String,
    algorithm: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_rotated: Option<chrono::DateTime<chrono::Utc>>,
    rotation_interval: RotationInterval,
    usage_count: u64,
}

impl KeyMetadataWrapper {
    fn new(metadata: fortress_core::key::KeyMetadata) -> Self {
        Self {
            metadata: KeyMetadataData {
                id: metadata.id().to_string(),
                algorithm: metadata.algorithm().to_string(),
                created_at: metadata.created_at(),
                last_rotated: metadata.last_rotated(),
                rotation_interval: metadata.rotation_interval().clone(),
                usage_count: metadata.usage_count(),
            },
        }
    }
}

#[pymethods]
impl KeyMetadataWrapper {
    /// Get key ID
    fn id(&self) -> String {
        self.metadata.id.clone()
    }

    /// Get algorithm name
    fn algorithm(&self) -> String {
        self.metadata.algorithm.clone()
    }

    /// Get creation time
    fn created_at(&self) -> String {
        self.metadata.created_at.to_rfc3339()
    }

    /// Get last rotation time
    fn last_rotated(&self) -> Option<String> {
        self.metadata.last_rotated.map(|dt| dt.to_rfc3339())
    }

    /// Get rotation interval in seconds
    fn rotation_interval_secs(&self) -> u64 {
        self.metadata.rotation_interval.as_secs()
    }

    /// Get usage count
    fn usage_count(&self) -> u64 {
        self.metadata.usage_count
    }

    /// Check if key needs rotation
    fn needs_rotation(&self) -> bool {
        if let Some(last_rotated) = self.metadata.last_rotated {
            let now = chrono::Utc::now();
            let elapsed = now.signed_duration_since(last_rotated);
            elapsed.num_seconds() as u64 >= self.metadata.rotation_interval.as_secs()
        } else {
            true
        }
    }
}

/// Parse key metadata from Python dictionary
fn parse_key_metadata(py_dict: &PyDict) -> PyResult<fortress_core::key::KeyMetadata> {
    let id = py_dict.get_item("id")
        .and_then(|v| v.extract::<String>().ok())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    let algorithm = py_dict.get_item("algorithm")
        .and_then(|v| v.extract::<String>().ok())
        .unwrap_or_else(|| "aegis256".to_string());
    
    let rotation_interval_secs = py_dict.get_item("rotation_interval_secs")
        .and_then(|v| v.extract::<u64>().ok())
        .unwrap_or(86400); // 24 hours default

    let key_id = KeyId::from_string(&id)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key ID: {}", e)))?;

    let rotation_interval = RotationInterval::from_secs(rotation_interval_secs);
    
    fortress_core::key::KeyMetadata::new(
        key_id,
        algorithm,
        chrono::Utc::now(),
        rotation_interval,
    )
}
