//! Configuration management for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;

use fortress_core::prelude::*;
use fortress_core::config::{Config, PerformanceProfile, SecurityLevel};

/// Python wrapper for Fortress configuration
#[pyclass]
pub struct FortressConfig {
    config: Config,
}

#[pymethods]
impl FortressConfig {
    /// Create a new FortressConfig from Rust Config
    pub(crate) fn new(config: Config) -> Self {
        Self { config }
    }

    /// Create default configuration
    #[staticmethod]
    fn default() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Create lightning profile configuration
    #[staticmethod]
    fn lightning() -> Self {
        Self {
            config: Config::lightning(),
        }
    }

    /// Create balanced profile configuration
    #[staticmethod]
    fn balanced() -> Self {
        Self {
            config: Config::balanced(),
        }
    }

    /// Create fortress profile configuration
    #[staticmethod]
    fn fortress() -> Self {
        Self {
            config: Config::fortress(),
        }
    }

    /// Create startup profile configuration
    #[staticmethod]
    fn startup() -> Self {
        Self {
            config: Config::startup(),
        }
    }

    /// Create enterprise profile configuration
    #[staticmethod]
    fn enterprise() -> Self {
        Self {
            config: Config::enterprise(),
        }
    }

    /// Load configuration from file
    #[staticmethod]
    fn from_file(path: String) -> PyResult<Self> {
        let config = Config::from_file(&path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to load config: {}", e)))?;
        Ok(Self { config })
    }

    /// Save configuration to file
    fn save_to_file(&self, path: String) -> PyResult<()> {
        self.config.save_to_file(&path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to save config: {}", e)))?;
        Ok(())
    }

    /// Get performance profile
    fn performance_profile(&self) -> String {
        format!("{:?}", self.config.performance_profile())
    }

    /// Get security level
    fn security_level(&self) -> String {
        format!("{:?}", self.config.security_level())
    }

    /// Get default encryption algorithm
    fn default_encryption_algorithm(&self) -> String {
        self.config.default_encryption_algorithm().to_string()
    }

    /// Get key rotation interval in seconds
    fn key_rotation_interval(&self) -> u64 {
        self.config.key_rotation_interval().as_secs()
    }

    /// Get maximum number of keys
    fn max_keys(&self) -> usize {
        self.config.max_keys()
    }

    /// Get audit log retention in days
    fn audit_log_retention_days(&self) -> u32 {
        self.config.audit_log_retention_days()
    }

    /// Get configuration as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("performance_profile".to_string(), format!("{:?}", self.config.performance_profile()).into_py(py));
        dict.insert("security_level".to_string(), format!("{:?}", self.config.security_level()).into_py(py));
        dict.insert("default_encryption_algorithm".to_string(), self.config.default_encryption_algorithm().to_string().into_py(py));
        dict.insert("key_rotation_interval".to_string(), self.config.key_rotation_interval().as_secs().into_py(py));
        dict.insert("max_keys".to_string(), self.config.max_keys().into_py(py));
        dict.insert("audit_log_retention_days".to_string(), self.config.audit_log_retention_days().into_py(py));

        Ok(dict)
    }

    /// Update configuration from dictionary
    fn update_from_dict(&mut self, dict: &PyDict) -> PyResult<()> {
        // This is a simplified implementation - in practice, you'd want more sophisticated
        // configuration merging logic
        if let Some(profile) = dict.get_item("performance_profile")? {
            let profile_str = profile.extract::<String>()?;
            self.config.set_performance_profile(match profile_str.as_str() {
                "Lightning" => PerformanceProfile::Lightning,
                "Balanced" => PerformanceProfile::Balanced,
                "Fortress" => PerformanceProfile::Fortress,
                _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid performance profile: {}", profile_str)
                )),
            });
        }

        if let Some(level) = dict.get_item("security_level")? {
            let level_str = level.extract::<String>()?;
            self.config.set_security_level(match level_str.as_str() {
                "Standard" => SecurityLevel::Standard,
                "High" => SecurityLevel::High,
                "Maximum" => SecurityLevel::Maximum,
                _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid security level: {}", level_str)
                )),
            });
        }

        Ok(())
    }

    /// Validate configuration
    fn validate(&self) -> PyResult<()> {
        self.config.validate()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Configuration validation failed: {}", e)))?;
        Ok(())
    }

    /// Clone configuration
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

/// Configuration utilities
#[pyfunction]
fn list_performance_profiles() -> Vec<String> {
    vec![
        "Lightning".to_string(),
        "Balanced".to_string(),
        "Fortress".to_string(),
    ]
}

#[pyfunction]
fn list_security_levels() -> Vec<String> {
    vec![
        "Standard".to_string(),
        "High".to_string(),
        "Maximum".to_string(),
    ]
}

#[pyfunction]
fn list_encryption_algorithms() -> Vec<String> {
    vec![
        "aegis256".to_string(),
        "chacha20poly1305".to_string(),
        "aes256gcm".to_string(),
        "xchacha20poly1305".to_string(),
        "blake3_encrypt".to_string(),
        "hmacsha512_encrypt".to_string(),
        "aes256ctr".to_string(),
        "argon2id_encrypt".to_string(),
        "composite_encrypt".to_string(),
    ]
}

#[pyfunction]
fn create_custom_config(
    performance_profile: String,
    security_level: String,
    default_encryption_algorithm: String,
    key_rotation_interval_secs: u64,
    max_keys: usize,
    audit_log_retention_days: u32,
) -> PyResult<FortressConfig> {
    let profile = match performance_profile.as_str() {
        "Lightning" => PerformanceProfile::Lightning,
        "Balanced" => PerformanceProfile::Balanced,
        "Fortress" => PerformanceProfile::Fortress,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid performance profile: {}", performance_profile)
        )),
    };

    let level = match security_level.as_str() {
        "Standard" => SecurityLevel::Standard,
        "High" => SecurityLevel::High,
        "Maximum" => SecurityLevel::Maximum,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid security level: {}", security_level)
        )),
    };

    let mut config = Config::default();
    config.set_performance_profile(profile);
    config.set_security_level(level);
    config.set_default_encryption_algorithm(&default_encryption_algorithm);
    config.set_key_rotation_interval(std::time::Duration::from_secs(key_rotation_interval_secs));
    config.set_max_keys(max_keys);
    config.set_audit_log_retention_days(audit_log_retention_days);

    Ok(FortressConfig::new(config))
}
