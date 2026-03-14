//! Policy engine operations for Python bindings

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_asyncio::tokio::future_into_py;
use std::collections::HashMap;

use fortress_core::prelude::*;

/// Python wrapper for PolicyEngine
#[pyclass]
pub struct PolicyEngine {
    engine: EngineWrapper,
}

#[derive(Clone)]
struct EngineWrapper {
    policies: HashMap<String, PolicyData>,
}

#[derive(Clone)]
struct PolicyData {
    name: String,
    rules: Vec<RuleData>,
    enabled: bool,
}

#[derive(Clone)]
struct RuleData {
    name: String,
    conditions: Vec<String>,
    actions: Vec<String>,
}

impl EngineWrapper {
    fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    fn add_policy(&mut self, name: String, rules: Vec<RuleData>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let policy = PolicyData {
            name: name.clone(),
            rules,
            enabled: true,
        };
        self.policies.insert(name, policy);
        Ok(())
    }

    fn remove_policy(&mut self, name: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.policies.remove(name).is_some())
    }

    fn evaluate_policy(&self, policy_name: &str, context: &HashMap<String, String>) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(policy) = self.policies.get(policy_name) {
            if !policy.enabled {
                return Ok(false);
            }
            
            // Simple evaluation logic - can be enhanced
            for rule in &policy.rules {
                let mut rule_satisfied = true;
                for condition in &rule.conditions {
                    if !context.contains_key(condition) {
                        rule_satisfied = false;
                        break;
                    }
                }
                if rule_satisfied {
                    return Ok(true);
                }
            }
            Ok(false)
        } else {
            Err(format!("Policy '{}' not found", policy_name).into())
        }
    }

    fn list_policies(&self) -> Vec<String> {
        self.policies.keys().cloned().collect()
    }
}

#[pymethods]
impl PolicyEngine {
    /// Create a new PolicyEngine
    #[new]
    fn new() -> Self {
        Self {
            engine: EngineWrapper::new(),
        }
    }

    /// Add a policy
    #[pyo3(signature = (name, rules))]
    fn add_policy(&self, py: Python, name: String, rules: &PyList) -> PyResult<PyObject> {
        let mut rule_data = Vec::new();
        
        for rule_item in rules.iter() {
            let rule_dict = rule_item.downcast::<PyDict>()?;
            let rule_name = rule_dict.get_item("name")
                .and_then(|v| v.extract::<String>().ok())
                .unwrap_or_else(|| "unnamed".to_string());
            
            let conditions = rule_dict.get_item("conditions")
                .and_then(|v| v.extract::<Vec<String>>().ok())
                .unwrap_or_default();
            
            let actions = rule_dict.get_item("actions")
                .and_then(|v| v.extract::<Vec<String>>().ok())
                .unwrap_or_default();
            
            rule_data.push(RuleData {
                name: rule_name,
                conditions,
                actions,
            });
        }

        let mut engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.add_policy(name, rule_data) {
                Ok(_) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(true.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to add policy: {}", e))),
            }
        })
    }

    /// Remove a policy
    fn remove_policy(&self, py: Python, name: String) -> PyResult<PyObject> {
        let mut engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.remove_policy(&name) {
                Ok(removed) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(removed.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to remove policy: {}", e))),
            }
        })
    }

    /// Evaluate a policy
    fn evaluate_policy(&self, py: Python, policy_name: String, context: &PyDict) -> PyResult<PyObject> {
        let mut context_map = HashMap::new();
        
        for (key, value) in context.iter() {
            if let (Ok(key_str), Ok(value_str)) = (key.extract::<String>(), value.extract::<String>()) {
                context_map.insert(key_str, value_str);
            }
        }

        let engine = self.engine.clone();
        
        future_into_py(py, async move {
            match engine.evaluate_policy(&policy_name, &context_map) {
                Ok(result) => {
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    Ok(result.into_py(py))
                }
                Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Policy evaluation failed: {}", e))),
            }
        })
    }

    /// List all policies
    fn list_policies(&self) -> PyResult<Vec<String>> {
        Ok(self.engine.list_policies())
    }
}
