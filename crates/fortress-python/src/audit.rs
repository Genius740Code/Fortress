//! Audit logging for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;
use fortress_core::audit::{AuditLogger, AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome};

/// Python wrapper for AuditLogger
#[pyclass]
pub struct AuditLogger {
    logger: fortress_core::audit::AuditLogger,
}

#[pymethods]
impl AuditLogger {
    /// Create a new AuditLogger with default configuration
    #[new]
    fn new() -> PyResult<Self> {
        let config = AuditConfig::default();
        let logger = fortress_core::audit::AuditLogger::new(config)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create audit logger: {}", e)))?;
        Ok(Self { logger })
    }

    /// Create a new AuditLogger with custom configuration
    #[staticmethod]
    fn with_config(config: &AuditConfigWrapper) -> PyResult<Self> {
        let logger = fortress_core::audit::AuditLogger::new(config.config.clone())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to create audit logger: {}", e)))?;
        Ok(Self { logger })
    }

    /// Log an audit event
    #[pyo3(signature = (event_type, user_id, resource, outcome, details=None, security_level=None))]
    fn log_event(&self, py: Python, event_type: String, user_id: String, resource: String, outcome: String, details: Option<&PyDict>, security_level: Option<String>) -> PyResult<PyObject> {
        let event_type_parsed = parse_audit_event_type(&event_type)?;
        let outcome_parsed = parse_event_outcome(&outcome)?;
        let security_level_parsed = security_level.map(|s| parse_security_level(&s)).transpose()?;
        
        let details_map = if let Some(details_dict) = details {
            Some(parse_audit_details(details_dict)?)
        } else {
            None
        };

        let logger = self.logger.clone();
        
        future_into_py(py, async move {
            let entry = AuditEntry::new(
                event_type_parsed,
                user_id,
                resource,
                outcome_parsed,
                details_map,
                security_level_parsed,
            );

            match logger.log(entry).await {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(py.None())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to log event: {}", e))),
            }
        })
    }

    /// Query audit events
    #[pyo3(signature = (start_time, end_time, event_types=None, user_ids=None, resources=None, outcomes=None, security_levels=None, limit=None))]
    fn query_events(&self, py: Python, start_time: String, end_time: String, event_types: Option<Vec<String>>, user_ids: Option<Vec<String>>, resources: Option<Vec<String>>, outcomes: Option<Vec<String>>, security_levels: Option<Vec<String>>, limit: Option<usize>) -> PyResult<PyObject> {
        let start_dt = chrono::DateTime::parse_from_rfc3339(&start_time)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid start_time format: {}", e)))?
            .with_timezone(&chrono::Utc);

        let end_dt = chrono::DateTime::parse_from_rfc3339(&end_time)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid end_time format: {}", e)))?
            .with_timezone(&chrono::Utc);

        let event_types_parsed = event_types.map(|types| {
            types.into_iter().map(parse_audit_event_type).collect::<PyResult<Vec<_>>>()
        }).transpose()?;

        let outcomes_parsed = outcomes.map(|types| {
            types.into_iter().map(parse_event_outcome).collect::<PyResult<Vec<_>>>()
        }).transpose()?;

        let security_levels_parsed = security_levels.map(|levels| {
            levels.into_iter().map(parse_security_level).collect::<PyResult<Vec<_>>>()
        }).transpose()?;

        let logger = self.logger.clone();
        
        future_into_py(py, async move {
            let query = fortress_core::audit::AuditQuery::new()
                .time_range(start_dt, end_dt)
                .event_types(event_types_parsed.unwrap_or_default())
                .user_ids(user_ids.unwrap_or_default())
                .resources(resources.unwrap_or_default())
                .outcomes(outcomes_parsed.unwrap_or_default())
                .security_levels(security_levels_parsed.unwrap_or_default())
                .limit(limit.unwrap_or(100));

            match logger.query(query).await {
                Ok(entries) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let list = PyList::empty(py);
                    for entry in entries {
                        let entry_wrapper = AuditEntryWrapper::new(entry);
                        list.append(entry_wrapper)?;
                    }
                    Ok(list.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Query failed: {}", e))),
            }
        })
    }

    /// Get audit statistics
    fn get_statistics(&self, py: Python) -> PyResult<PyObject> {
        let logger = self.logger.clone();
        
        future_into_py(py, async move {
            match logger.get_statistics().await {
                Ok(stats) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    let dict = PyDict::new(py);
                    dict.set_item("total_events", stats.total_events)?;
                    dict.set_item("successful_events", stats.successful_events)?;
                    dict.set_item("failed_events", stats.failed_events)?;
                    dict.set_item("security_events", stats.security_events)?;
                    dict.set_item("oldest_event", stats.oldest_event.map(|dt| dt.to_rfc3339()))?;
                    dict.set_item("newest_event", stats.newest_event.map(|dt| dt.to_rfc3339()))?;
                    Ok(dict.into())
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to get statistics: {}", e))),
            }
        })
    }
}

/// Python wrapper for AuditConfig
#[pyclass]
pub struct AuditConfigWrapper {
    config: AuditConfig,
}

#[pymethods]
impl AuditConfigWrapper {
    /// Create default audit configuration
    #[staticmethod]
    fn default() -> Self {
        Self {
            config: AuditConfig::default(),
        }
    }

    /// Create audit configuration with custom settings
    #[new]
    fn new(
        log_file_path: Option<String>,
        max_file_size_mb: Option<u64>,
        max_files: Option<usize>,
        enable_compression: Option<bool>,
        enable_encryption: Option<bool>,
        buffer_size: Option<usize>,
        flush_interval_secs: Option<u64>,
    ) -> Self {
        let mut config = AuditConfig::default();
        
        if let Some(path) = log_file_path {
            config.set_log_file_path(path);
        }
        if let Some(size) = max_file_size_mb {
            config.set_max_file_size(size * 1024 * 1024); // Convert MB to bytes
        }
        if let Some(files) = max_files {
            config.set_max_files(files);
        }
        if let Some(compression) = enable_compression {
            config.set_compression_enabled(compression);
        }
        if let Some(encryption) = enable_encryption {
            config.set_encryption_enabled(encryption);
        }
        if let Some(buffer) = buffer_size {
            config.set_buffer_size(buffer);
        }
        if let Some(interval) = flush_interval_secs {
            config.set_flush_interval(std::time::Duration::from_secs(interval));
        }

        Self { config }
    }

    /// Get configuration as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("log_file_path".to_string(), self.config.log_file_path().into_py(py));
        dict.insert("max_file_size".to_string(), self.config.max_file_size().into_py(py));
        dict.insert("max_files".to_string(), self.config.max_files().into_py(py));
        dict.insert("compression_enabled".to_string(), self.config.compression_enabled().into_py(py));
        dict.insert("encryption_enabled".to_string(), self.config.encryption_enabled().into_py(py));
        dict.insert("buffer_size".to_string(), self.config.buffer_size().into_py(py));
        dict.insert("flush_interval_secs".to_string(), self.config.flush_interval().as_secs().into_py(py));

        Ok(dict)
    }
}

/// Python wrapper for AuditEntry
#[pyclass]
pub struct AuditEntryWrapper {
    entry: AuditEntry,
}

impl AuditEntryWrapper {
    fn new(entry: AuditEntry) -> Self {
        Self { entry }
    }
}

#[pymethods]
impl AuditEntryWrapper {
    /// Get event type
    fn event_type(&self) -> String {
        format!("{:?}", self.entry.event_type())
    }

    /// Get user ID
    fn user_id(&self) -> String {
        self.entry.user_id().to_string()
    }

    /// Get resource
    fn resource(&self) -> String {
        self.entry.resource().to_string()
    }

    /// Get outcome
    fn outcome(&self) -> String {
        format!("{:?}", self.entry.outcome())
    }

    /// Get timestamp
    fn timestamp(&self) -> String {
        self.entry.timestamp().to_rfc3339()
    }

    /// Get security level
    fn security_level(&self) -> Option<String> {
        self.entry.security_level().map(|level| format!("{:?}", level))
    }

    /// Get details
    fn details(&self) -> PyResult<HashMap<String, String>> {
        Ok(self.entry.details().clone())
    }

    /// Get entry as dictionary
    fn to_dict(&self) -> PyResult<HashMap<String, PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let mut dict = HashMap::new();

        dict.insert("event_type".to_string(), format!("{:?}", self.entry.event_type()).into_py(py));
        dict.insert("user_id".to_string(), self.entry.user_id().to_string().into_py(py));
        dict.insert("resource".to_string(), self.entry.resource().to_string().into_py(py));
        dict.insert("outcome".to_string(), format!("{:?}", self.entry.outcome()).into_py(py));
        dict.insert("timestamp".to_string(), self.entry.timestamp().to_rfc3339().into_py(py));
        dict.insert("security_level".to_string(), self.entry.security_level().map(|level| format!("{:?}", level)).into_py(py));
        
        let details_dict = PyDict::new(py);
        for (key, value) in self.entry.details() {
            details_dict.set_item(key, value)?;
        }
        dict.insert("details".to_string(), details_dict.into());

        Ok(dict)
    }
}

// Helper functions for parsing enums
fn parse_audit_event_type(event_type: &str) -> PyResult<AuditEventType> {
    match event_type {
        "Authentication" => Ok(AuditEventType::Authentication),
        "Authorization" => Ok(AuditEventType::Authorization),
        "KeyGeneration" => Ok(AuditEventType::KeyGeneration),
        "KeyRotation" => Ok(AuditEventType::KeyRotation),
        "KeyDeletion" => Ok(AuditEventType::KeyDeletion),
        "Encryption" => Ok(AuditEventType::Encryption),
        "Decryption" => Ok(AuditEventType::Decryption),
        "DataAccess" => Ok(AuditEventType::DataAccess),
        "DataModification" => Ok(AuditEventType::DataModification),
        "ConfigurationChange" => Ok(AuditEventType::ConfigurationChange),
        "PolicyChange" => Ok(AuditEventType::PolicyChange),
        "SystemEvent" => Ok(AuditEventType::SystemEvent),
        "SecurityEvent" => Ok(AuditEventType::SecurityEvent),
        "Error" => Ok(AuditEventType::Error),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid audit event type: {}", event_type)
        )),
    }
}

fn parse_event_outcome(outcome: &str) -> PyResult<EventOutcome> {
    match outcome {
        "Success" => Ok(EventOutcome::Success),
        "Failure" => Ok(EventOutcome::Failure),
        "Error" => Ok(EventOutcome::Error),
        "Denied" => Ok(EventOutcome::Denied),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid event outcome: {}", outcome)
        )),
    }
}

fn parse_security_level(security_level: &str) -> PyResult<SecurityLevel> {
    match security_level {
        "Low" => Ok(SecurityLevel::Low),
        "Medium" => Ok(SecurityLevel::Medium),
        "High" => Ok(SecurityLevel::High),
        "Critical" => Ok(SecurityLevel::Critical),
        _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid security level: {}", security_level)
        )),
    }
}

fn parse_audit_details(dict: &PyDict) -> PyResult<HashMap<String, String>> {
    let mut details = HashMap::new();
    
    for (key, value) in dict.iter() {
        let key_str = key.extract::<String>()?;
        let value_str = value.extract::<String>()?;
        details.insert(key_str, value_str);
    }
    
    Ok(details)
}
