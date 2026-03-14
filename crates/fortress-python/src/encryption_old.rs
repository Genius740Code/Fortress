//! Encryption algorithms and operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3_asyncio::tokio::future_into_py;

use fortress_core::prelude::*;
use fortress_core::encryption::{EncryptionProfile, Aegis256, ChaCha20Poly1305, Aes256Gcm};

/// Python wrapper for encryption algorithms
#[pyclass]
pub struct EncryptionAlgorithm {
    algorithm: Box<dyn EncryptionAlgorithm + Send + Sync>,
}

#[pymethods]
impl EncryptionAlgorithm {
    /// Create a new AEGIS-256 encryption algorithm
    #[staticmethod]
    fn aegis256() -> Self {
        Self {
            algorithm: Box::new(Aegis256::new()),
        }
    }

    /// Create a new ChaCha20-Poly1305 encryption algorithm
    #[staticmethod]
    fn chacha20poly1305() -> Self {
        Self {
            algorithm: Box::new(ChaCha20Poly1305::new()),
        }
    }

    /// Create a new AES-256-GCM encryption algorithm
    #[staticmethod]
    fn aes256gcm() -> Self {
        Self {
            algorithm: Box::new(Aes256Gcm::new()),
        }
    }

    /// Encrypt data
    #[pyo3(signature = (plaintext, key))]
    fn encrypt(&self, py: Python, plaintext: &PyBytes, key: &PyBytes) -> PyResult<PyObject> {
        let plaintext_data = plaintext.as_bytes();
        let key_data = key.as_bytes();
        
        let algorithm = self.algorithm.clone();
        let plaintext_vec = plaintext_data.to_vec();
        let key_vec = key_data.to_vec();

        future_into_py(py, async move {
            match algorithm.encrypt(&plaintext_vec, &key_vec) {
                Ok(ciphertext) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(PyBytes::new(py, &ciphertext).into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Encryption failed: {}", e))),
            }
        })
    }

    /// Decrypt data
    #[pyo3(signature = (ciphertext, key))]
    fn decrypt(&self, py: Python, ciphertext: &PyBytes, key: &PyBytes) -> PyResult<PyObject> {
        let ciphertext_data = ciphertext.as_bytes();
        let key_data = key.as_bytes();
        
        let algorithm = self.algorithm.clone();
        let ciphertext_vec = ciphertext_data.to_vec();
        let key_vec = key_data.to_vec();

        future_into_py(py, async move {
            match algorithm.decrypt(&ciphertext_vec, &key_vec) {
                Ok(plaintext) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(PyBytes::new(py, &plaintext).into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Decryption failed: {}", e))),
            }
        })
    }

    /// Get algorithm name
    fn algorithm_name(&self) -> String {
        self.algorithm.name().to_string()
    }

    /// Get key size in bytes
    fn key_size(&self) -> usize {
        self.algorithm.key_size()
    }

    /// Get nonce size in bytes
    fn nonce_size(&self) -> usize {
        self.algorithm.nonce_size()
    }

    /// Get tag size in bytes
    fn tag_size(&self) -> usize {
        self.algorithm.tag_size()
    }
}

/// Python wrapper for encryption profiles
#[pyclass]
pub struct EncryptionProfile {
    profile: fortress_core::encryption::EncryptionProfile,
}

#[pymethods]
impl EncryptionProfile {
    /// Create a new encryption profile
    #[new]
    fn new(algorithm_name: String, key_rotation_interval_secs: u64) -> PyResult<Self> {
        let algorithm = match algorithm_name.as_str() {
            "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
            "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
            "aes256gcm" => Box::new(Aes256Gcm::new()),
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Unknown algorithm: {}", algorithm_name)
            )),
        };

        let profile = fortress_core::encryption::EncryptionProfile::new(
            algorithm,
            std::time::Duration::from_secs(key_rotation_interval_secs),
        );

        Ok(Self { profile })
    }

    /// Get profile name
    fn name(&self) -> String {
        self.profile.name().to_string()
    }

    /// Get algorithm name
    fn algorithm(&self) -> String {
        self.profile.algorithm().name().to_string()
    }

    /// Get key rotation interval
    fn key_rotation_interval(&self) -> u64 {
        self.profile.key_rotation_interval().as_secs()
    }

    /// Check if profile is secure
    fn is_secure(&self) -> bool {
        self.profile.is_secure()
    }
}

/// Utility functions for encryption operations
#[pyfunction]
fn generate_key(algorithm_name: String) -> PyResult<Vec<u8>> {
    let algorithm = match algorithm_name.as_str() {
        "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
        "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
        "aes256gcm" => Box::new(Aes256Gcm::new()),
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Unknown algorithm: {}", algorithm_name)
        )),
    };

    let key_manager = KeyManager::new();
    match key_manager.generate_key(&*algorithm) {
        Ok(key) => Ok(key.to_vec()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key generation failed: {}", e))),
    }
}

#[pyfunction]
fn generate_nonce(algorithm_name: String) -> PyResult<Vec<u8>> {
    let algorithm = match algorithm_name.as_str() {
        "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
        "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
        "aes256gcm" => Box::new(Aes256Gcm::new()),
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Unknown algorithm: {}", algorithm_name)
        )),
    };

    let nonce = vec![0u8; algorithm.nonce_size()];
    Ok(nonce)
}
