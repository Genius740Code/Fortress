//! Python bindings for Fortress secure database system
//!
//! This module provides a Python interface to the Fortress core library,
//! allowing Python developers to use Fortress's encryption and key management
//! capabilities directly from Python code.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;
use std::sync::Arc;

use fortress_core::prelude::*;
use fortress_core::{VERSION, build};

mod encryption;
mod key_management;
mod storage;
mod error;
mod config;
mod audit;
mod policy;
mod tenant;

use encryption::*;
use key_management::*;
use storage::*;
use error::*;
use config::*;
use audit::*;
use policy::*;
use tenant::*;

/// Fortress Python module
#[pymodule]
fn _fortress(_py: Python, m: &PyModule) -> PyResult<()> {
    // Version information
    m.add("__version__", VERSION)?;
    m.add("__build_timestamp__", build::TIMESTAMP)?;
    m.add("__git_sha__", build::GIT_SHA)?;
    m.add("__rust_version__", build::RUST_VERSION)?;
    m.add("__target__", build::TARGET)?;

    // Core classes
    m.add_class::<FortressConfig>()?;
    m.add_class::<EncryptionAlgorithm>()?;
    m.add_class::<KeyManager>()?;
    m.add_class::<StorageBackend>()?;
    m.add_class::<PolicyEngine>()?;
    m.add_class::<AuditLogger>()?;
    m.add_class::<TenantManager>()?;
    m.add_class::<FortressError>()?;

    // Utility functions
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    m.add_function(wrap_pyfunction!(get_build_info, m)?)?;
    m.add_function(wrap_pyfunction!(list_algorithms, m)?)?;
    m.add_function(wrap_pyfunction!(create_config, m)?)?;

    Ok(())
}

/// Get Fortress version information
#[pyfunction]
fn get_version() -> String {
    VERSION.to_string()
}

/// Get Fortress build information
#[pyfunction]
fn get_build_info() -> HashMap<String, String> {
    let mut info = HashMap::new();
    info.insert("timestamp".to_string(), build::TIMESTAMP.to_string());
    info.insert("git_sha".to_string(), build::GIT_SHA.to_string());
    info.insert("rust_version".to_string(), build::RUST_VERSION.to_string());
    info.insert("target".to_string(), build::TARGET.to_string());
    info
}

/// List available encryption algorithms
#[pyfunction]
fn list_algorithms() -> Vec<String> {
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

/// Create a new Fortress configuration
#[pyfunction]
fn create_config(profile: Option<String>) -> PyResult<FortressConfig> {
    let config = match profile.as_deref() {
        Some("lightning") => Config::lightning(),
        Some("balanced") => Config::balanced(),
        Some("fortress") => Config::fortress(),
        Some("startup") => Config::startup(),
        Some("enterprise") => Config::enterprise(),
        _ => Config::default(),
    };
    Ok(FortressConfig::new(config))
}
