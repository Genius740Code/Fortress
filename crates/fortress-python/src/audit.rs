//! Audit logging operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;

/// Python wrapper for AuditLogger
#[pyclass]
pub struct AuditLogger {
    logger: LoggerWrapper,
}

#[derive(Clone)]
struct LoggerWrapper {
    events: Vec<AuditEvent>,
}

#[derive(Clone)]
struct AuditEvent {
    id: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    event_type: String,
    user_id: Option<String>,
    resource: Option<String>,
    action: Option<String>,
    outcome: String,
    details: HashMap<String, String>,
}

impl LoggerWrapper {
    fn new() -> Self {
        Self {
            events: Vec::new(),
        }
    }

    fn log_event(&mut self, event: AuditEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.events.push(event);
        Ok(())
    }

    fn get_events(&self, limit: Option<usize>) -> Vec<AuditEvent> {
        match limit {
            Some(limit) => self.events.iter().rev().take(limit).cloned().collect(),
            None => self.events.clone(),
        }
    }

    fn get_events_by_user(&self, user_id: &str, limit: Option<usize>) -> Vec<AuditEvent> {
        let filtered: Vec<AuditEvent> = self.events
            .iter()
            .filter(|event| event.user_id.as_ref().map_or(false, |uid| uid == user_id))
            .cloned()
            .collect();
        
        match limit {
            Some(limit) => filtered.into_iter().rev().take(limit).collect(),
            None => filtered,
        }
    }

    fn get_events_by_type(&self, event_type: &str, limit: Option<usize>) -> Vec<AuditEvent> {
        let filtered: Vec<AuditEvent> = self.events
            .iter()
            .filter(|event| event.event_type == event_type)
            .cloned()
            .collect();
        
        match limit {
            Some(limit) => filtered.into_iter().rev().take(limit).collect(),
            None => filtered,
        }
    }
}

#[pymethods]
impl AuditLogger {
    /// Create a new AuditLogger
    #[new]
    fn new() -> Self {
        Self {
            logger: LoggerWrapper::new(),
        }
    }

    /// Log an audit event
    #[pyo3(signature = (event_type, user_id=None, resource=None, action=None, outcome="success", details=None))]
    fn log_event(&self, py: Python, event_type: String, user_id: Option<String>, resource: Option<String>, action: Option<String>, outcome: String, details: Option<&PyDict>) -> PyResult<PyObject> {
        let mut details_map = HashMap::new();
        
        if let Some(details_dict) = details {
            for (key, value) in details_dict.iter() {
                if let (Ok(key_str), Ok(value_str)) = (key.extract::<String>(), value.extract::<String>()) {
                    details_map.insert(key_str, value_str);
                }
            }
        }

        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type,
            user_id,
            resource,
            action,
            outcome,
            details: details_map,
        };

        let mut logger = self.logger.clone();
        
        future_into_py(py, async move {
            match logger.log_event(event) {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(true.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to log event: {}", e))),
            }
        })
    }

    /// Get all audit events
    #[pyo3(signature = (limit=None))]
    fn get_events(&self, limit: Option<usize>) -> PyResult<Vec<AuditEventWrapper>> {
        let events = self.logger.get_events(limit);
        Ok(events.into_iter().map(AuditEventWrapper::new).collect())
    }

    /// Get events by user
    #[pyo3(signature = (user_id, limit=None))]
    fn get_events_by_user(&self, user_id: String, limit: Option<usize>) -> PyResult<Vec<AuditEventWrapper>> {
        let events = self.logger.get_events_by_user(&user_id, limit);
        Ok(events.into_iter().map(AuditEventWrapper::new).collect())
    }

    /// Get events by type
    #[pyo3(signature = (event_type, limit=None))]
    fn get_events_by_type(&self, event_type: String, limit: Option<usize>) -> PyResult<Vec<AuditEventWrapper>> {
        let events = self.logger.get_events_by_type(&event_type, limit);
        Ok(events.into_iter().map(AuditEventWrapper::new).collect())
    }
}

/// Python wrapper for AuditEvent
#[pyclass]
pub struct AuditEventWrapper {
    event: AuditEventData,
}

struct AuditEventData {
    id: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    event_type: String,
    user_id: Option<String>,
    resource: Option<String>,
    action: Option<String>,
    outcome: String,
    details: HashMap<String, String>,
}

impl AuditEventWrapper {
    fn new(event: AuditEvent) -> Self {
        Self {
            event: AuditEventData {
                id: event.id,
                timestamp: event.timestamp,
                event_type: event.event_type,
                user_id: event.user_id,
                resource: event.resource,
                action: event.action,
                outcome: event.outcome,
                details: event.details,
            },
        }
    }
}

#[pymethods]
impl AuditEventWrapper {
    /// Get event ID
    fn id(&self) -> String {
        self.event.id.clone()
    }

    /// Get timestamp
    fn timestamp(&self) -> String {
        self.event.timestamp.to_rfc3339()
    }

    /// Get event type
    fn event_type(&self) -> String {
        self.event.event_type.clone()
    }

    /// Get user ID
    fn user_id(&self) -> Option<String> {
        self.event.user_id.clone()
    }

    /// Get resource
    fn resource(&self) -> Option<String> {
        self.event.resource.clone()
    }

    /// Get action
    fn action(&self) -> Option<String> {
        self.event.action.clone()
    }

    /// Get outcome
    fn outcome(&self) -> String {
        self.event.outcome.clone()
    }

    /// Get details
    fn details(&self) -> PyResult<HashMap<String, String>> {
        Ok(self.event.details.clone())
    }
}
