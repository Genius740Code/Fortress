//! Enhanced error reporting system with structured error handling
//!
//! Provides comprehensive error messages, troubleshooting steps,
//! and documentation integration for better user experience.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "error_type")]
pub enum FortressError {
    EncryptionError {
        reason: String,
        #[serde(skip)]
        source: Option<String>,
        #[serde(skip)]
        suggestion: Option<String>,
        error_code: String,
        help_text: String,
        related_docs: Vec<String>,
        troubleshooting_steps: Vec<String>,
    },

    DatabaseError {
        database: String,
        host: String,
        port: u16,
        #[serde(skip)]
        source: Option<String>,
        error_code: String,
        help_text: String,
        troubleshooting_steps: Vec<String>,
        common_causes: Vec<String>,
    },

    ConfigurationError {
        field: String,
        value: String,
        expected_format: String,
        suggestion: String,
        error_code: String,
        help_text: String,
        validation_rules: Vec<String>,
    },

    AuthenticationError {
        reason: String,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
        security_recommendations: Vec<String>,
    },

    KeyError {
        operation: String,
        key_id: Option<String>,
        error_code: String,
        help_text: String,
        #[serde(skip)]
        suggestion: Option<String>,
        recovery_steps: Vec<String>,
    },

    NetworkError {
        operation: String,
        endpoint: String,
        error_code: String,
        help_text: String,
        timeout_info: Option<String>,
        retry_strategy: Vec<String>,
    },

    FileSystemError {
        operation: String,
        path: String,
        error_code: String,
        help_text: String,
        permission_info: Option<String>,
        alternative_paths: Vec<String>,
    },

    ComplianceError {
        regulation: String,
        requirement: String,
        error_code: String,
        help_text: String,
        remediation_steps: Vec<String>,
        audit_trail: Vec<String>,
    },

    PerformanceError {
        metric: String,
        threshold: String,
        actual_value: String,
        error_code: String,
        help_text: String,
        optimization_suggestions: Vec<String>,
    },

    PluginError {
        plugin_name: String,
        operation: String,
        error_code: String,
        help_text: String,
        plugin_version: Option<String>,
        compatibility_info: Vec<String>,
    },

    CliError {
        command: String,
        reason: String,
        error_code: String,
        help_text: String,
        suggestion: Option<String>,
        example_usage: Option<String>,
    },
}

impl fmt::Display for FortressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FortressError::EncryptionError { reason, .. } => {
                write!(f, "Encryption failed: {}", reason)
            }
            FortressError::DatabaseError {
                database,
                host,
                port,
                ..
            } => write!(
                f,
                "Database connection failed: {}@{}:{}",
                database, host, port
            ),
            FortressError::ConfigurationError { field, .. } => {
                write!(f, "Configuration error: {}", field)
            }
            FortressError::AuthenticationError { reason, .. } => {
                write!(f, "Authentication failed: {}", reason)
            }
            FortressError::KeyError { operation, .. } => {
                write!(f, "Key management error: {}", operation)
            }
            FortressError::NetworkError { operation, .. } => {
                write!(f, "Network error: {}", operation)
            }
            FortressError::FileSystemError { operation, .. } => {
                write!(f, "File system error: {}", operation)
            }
            FortressError::ComplianceError { regulation, .. } => {
                write!(f, "Compliance violation: {}", regulation)
            }
            FortressError::PerformanceError { metric, .. } => {
                write!(f, "Performance degradation: {}", metric)
            }
            FortressError::PluginError { plugin_name, .. } => {
                write!(f, "Plugin error: {}", plugin_name)
            }
            FortressError::CliError { command, .. } => {
                write!(f, "CLI error in command '{}': {}", command, command)
            }
        }
    }
}

impl FortressError {
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        match &mut self {
            FortressError::EncryptionError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::AuthenticationError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::KeyError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            FortressError::CliError { suggestion: s, .. } => {
                *s = Some(suggestion.into());
            }
            _ => {}
        }
        self
    }

    pub fn error_code(&self) -> &str {
        match self {
            FortressError::EncryptionError { error_code, .. } => error_code,
            FortressError::DatabaseError { error_code, .. } => error_code,
            FortressError::ConfigurationError { error_code, .. } => error_code,
            FortressError::AuthenticationError { error_code, .. } => error_code,
            FortressError::KeyError { error_code, .. } => error_code,
            FortressError::NetworkError { error_code, .. } => error_code,
            FortressError::FileSystemError { error_code, .. } => error_code,
            FortressError::ComplianceError { error_code, .. } => error_code,
            FortressError::PerformanceError { error_code, .. } => error_code,
            FortressError::PluginError { error_code, .. } => error_code,
            FortressError::CliError { error_code, .. } => error_code,
        }
    }

    pub fn help_text(&self) -> &str {
        match self {
            FortressError::EncryptionError { help_text, .. } => help_text,
            FortressError::DatabaseError { help_text, .. } => help_text,
            FortressError::ConfigurationError { help_text, .. } => help_text,
            FortressError::AuthenticationError { help_text, .. } => help_text,
            FortressError::KeyError { help_text, .. } => help_text,
            FortressError::NetworkError { help_text, .. } => help_text,
            FortressError::FileSystemError { help_text, .. } => help_text,
            FortressError::ComplianceError { help_text, .. } => help_text,
            FortressError::PerformanceError { help_text, .. } => help_text,
            FortressError::PluginError { help_text, .. } => help_text,
            FortressError::CliError { help_text, .. } => help_text,
        }
    }

    pub fn troubleshooting_steps(&self) -> Vec<String> {
        match self {
            FortressError::EncryptionError {
                troubleshooting_steps,
                ..
            } => troubleshooting_steps.clone(),
            FortressError::DatabaseError {
                troubleshooting_steps,
                ..
            } => troubleshooting_steps.clone(),
            FortressError::ConfigurationError {
                validation_rules, ..
            } => validation_rules.clone(),
            FortressError::AuthenticationError {
                security_recommendations,
                ..
            } => security_recommendations.clone(),
            FortressError::KeyError { recovery_steps, .. } => recovery_steps.clone(),
            FortressError::NetworkError { retry_strategy, .. } => retry_strategy.clone(),
            FortressError::FileSystemError {
                alternative_paths, ..
            } => alternative_paths.clone(),
            FortressError::ComplianceError {
                remediation_steps, ..
            } => remediation_steps.clone(),
            FortressError::PerformanceError {
                optimization_suggestions,
                ..
            } => optimization_suggestions.clone(),
            FortressError::PluginError {
                compatibility_info, ..
            } => compatibility_info.clone(),
            FortressError::CliError {
                suggestion,
                example_usage,
                ..
            } => {
                let mut steps = vec![
                    "Check command syntax and parameters".to_string(),
                    "Run 'fortress help' for available commands".to_string(),
                    "Verify configuration files are correct".to_string(),
                ];
                if let Some(suggestion) = suggestion {
                    steps.push(format!("Suggestion: {}", suggestion));
                }
                if let Some(example) = example_usage {
                    steps.push(format!("Example: {}", example));
                }
                steps
            }
        }
    }

    pub fn severity(&self) -> ErrorSeverity {
        match self {
            FortressError::EncryptionError { .. } => ErrorSeverity::High,
            FortressError::DatabaseError { .. } => ErrorSeverity::High,
            FortressError::ConfigurationError { .. } => ErrorSeverity::Medium,
            FortressError::AuthenticationError { .. } => ErrorSeverity::High,
            FortressError::KeyError { .. } => ErrorSeverity::High,
            FortressError::NetworkError { .. } => ErrorSeverity::Medium,
            FortressError::FileSystemError { .. } => ErrorSeverity::Medium,
            FortressError::ComplianceError { .. } => ErrorSeverity::Critical,
            FortressError::PerformanceError { .. } => ErrorSeverity::Medium,
            FortressError::PluginError { .. } => ErrorSeverity::Low,
            FortressError::CliError { .. } => ErrorSeverity::Medium,
        }
    }
}

// Error constructors with helpful defaults
impl FortressError {
    pub fn encryption_failed(reason: impl Into<String>) -> Self {
        FortressError::EncryptionError {
            reason: reason.into(),
            source: None,
            suggestion: None,
            error_code: "ENC001".to_string(),
            help_text: "Encryption operation failed. Check your encryption keys and algorithm configuration.".to_string(),
            related_docs: vec![
                "https://docs.fortress.security/encryption/troubleshooting".to_string(),
                "https://docs.fortress.security/encryption/algorithms".to_string(),
            ],
            troubleshooting_steps: vec![
                "Verify encryption keys are valid and accessible".to_string(),
                "Check if the encryption algorithm is supported".to_string(),
                "Ensure sufficient memory for encryption operations".to_string(),
                "Review encryption configuration settings".to_string(),
            ],
        }
    }

    pub fn database_connection_failed(
        database: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        FortressError::DatabaseError {
            database: database.into(),
            host: host.into(),
            port,
            source: None,
            error_code: "DB001".to_string(),
            help_text:
                "Database connection failed. Check database server status and network connectivity."
                    .to_string(),
            troubleshooting_steps: vec![
                "Verify database server is running and accessible".to_string(),
                "Check network connectivity to database host".to_string(),
                "Validate database credentials and permissions".to_string(),
                "Ensure database port is open and not blocked by firewall".to_string(),
                "Check database connection pool settings".to_string(),
                "Verify database server load and capacity".to_string(),
            ],
            common_causes: vec![
                "Database server is down or unreachable".to_string(),
                "Network connectivity issues".to_string(),
                "Invalid credentials or insufficient permissions".to_string(),
                "Database server overload or resource constraints".to_string(),
                "Firewall blocking database port".to_string(),
            ],
        }
    }

    pub fn configuration_error(
        field: impl Into<String>,
        value: impl Into<String>,
        expected_format: impl Into<String>,
    ) -> Self {
        FortressError::ConfigurationError {
            field: field.into(),
            value: value.into(),
            expected_format: expected_format.into(),
            suggestion: "Please check the configuration documentation for valid values".to_string(),
            error_code: "CFG001".to_string(),
            help_text: "Configuration value is invalid. Please check the expected format and update your configuration.".to_string(),
            validation_rules: vec![
                "Ensure the value matches the expected format".to_string(),
                "Check for any required dependencies".to_string(),
                "Verify the value is within allowed ranges".to_string(),
                "Review configuration file syntax".to_string(),
            ],
        }
    }

    pub fn authentication_failed(reason: impl Into<String>) -> Self {
        FortressError::AuthenticationError {
            reason: reason.into(),
            error_code: "AUTH001".to_string(),
            help_text: "Authentication failed. Please check your credentials and try again."
                .to_string(),
            suggestion: None,
            security_recommendations: vec![
                "Use strong, unique passwords".to_string(),
                "Enable multi-factor authentication".to_string(),
                "Regularly rotate authentication tokens".to_string(),
                "Monitor for suspicious login attempts".to_string(),
            ],
        }
    }

    pub fn key_operation_failed(operation: impl Into<String>, key_id: Option<&str>) -> Self {
        FortressError::KeyError {
            operation: operation.into(),
            key_id: key_id.map(|k| k.into()),
            error_code: "KEY001".to_string(),
            help_text: "Key management operation failed. Check key permissions and availability."
                .to_string(),
            suggestion: None,
            recovery_steps: vec![
                "Verify key exists and is accessible".to_string(),
                "Check key permissions and ownership".to_string(),
                "Ensure key store is available and not corrupted".to_string(),
                "Review key operation logs for specific error details".to_string(),
                "Consider key rotation if key is compromised".to_string(),
            ],
        }
    }

    pub fn network_error(operation: impl Into<String>, endpoint: impl Into<String>) -> Self {
        FortressError::NetworkError {
            operation: operation.into(),
            endpoint: endpoint.into(),
            error_code: "NET001".to_string(),
            help_text:
                "Network operation failed. Check network connectivity and service availability."
                    .to_string(),
            timeout_info: Some("Default timeout is 30 seconds".to_string()),
            retry_strategy: vec![
                "Wait 5 seconds and retry".to_string(),
                "Check network connectivity".to_string(),
                "Verify service endpoint is accessible".to_string(),
                "Consider increasing timeout for large operations".to_string(),
                "Check firewall and proxy settings".to_string(),
            ],
        }
    }

    pub fn file_system_error(operation: impl Into<String>, path: impl Into<String>) -> Self {
        FortressError::FileSystemError {
            operation: operation.into(),
            path: path.into(),
            error_code: "FS001".to_string(),
            help_text: "File system operation failed. Check file permissions and disk space."
                .to_string(),
            permission_info: Some(
                "Ensure the process has read/write permissions to the target directory".to_string(),
            ),
            alternative_paths: vec![
                "Try using an alternative directory with proper permissions".to_string(),
                "Check if the file is locked by another process".to_string(),
                "Verify disk space is available".to_string(),
            ],
        }
    }

    pub fn compliance_violation(
        regulation: impl Into<String>,
        requirement: impl Into<String>,
    ) -> Self {
        FortressError::ComplianceError {
            regulation: regulation.into(),
            requirement: requirement.into(),
            error_code: "COMP001".to_string(),
            help_text: "Compliance violation detected. Please review and address the compliance requirements.".to_string(),
            remediation_steps: vec![
                "Review compliance requirements for the specific regulation".to_string(),
                "Update configurations to meet compliance standards".to_string(),
                "Document remediation actions taken".to_string(),
                "Schedule compliance audit verification".to_string(),
                "Implement ongoing compliance monitoring".to_string(),
            ],
            audit_trail: vec![
                "Compliance check performed".to_string(),
                "Violation identified and logged".to_string(),
                "Remediation initiated".to_string(),
            ],
        }
    }

    pub fn performance_degradation(
        metric: impl Into<String>,
        threshold: impl Into<String>,
        actual_value: impl Into<String>,
    ) -> Self {
        FortressError::PerformanceError {
            metric: metric.into(),
            threshold: threshold.into(),
            actual_value: actual_value.into(),
            error_code: "PERF001".to_string(),
            help_text: "Performance threshold exceeded. Consider optimization or resource scaling."
                .to_string(),
            optimization_suggestions: vec![
                "Review and optimize database queries".to_string(),
                "Consider adding indexes to improve query performance".to_string(),
                "Scale resources if needed".to_string(),
                "Implement caching for frequently accessed data".to_string(),
                "Monitor and optimize memory usage".to_string(),
            ],
        }
    }

    pub fn plugin_error(plugin_name: impl Into<String>, operation: impl Into<String>) -> Self {
        FortressError::PluginError {
            plugin_name: plugin_name.into(),
            operation: operation.into(),
            error_code: "PLUGIN001".to_string(),
            help_text: "Plugin operation failed. Check plugin configuration and compatibility."
                .to_string(),
            plugin_version: Some("Check plugin documentation for version requirements".to_string()),
            compatibility_info: vec![
                "Verify plugin is compatible with current Fortress version".to_string(),
                "Check plugin dependencies are installed".to_string(),
                "Review plugin configuration settings".to_string(),
                "Consider updating to latest plugin version".to_string(),
            ],
        }
    }

    pub fn io_error(message: impl Into<String>) -> Self {
        FortressError::FileSystemError {
            operation: "IO operation".to_string(),
            path: "unknown".to_string(),
            error_code: "IO001".to_string(),
            help_text: message.into(),
            permission_info: Some("Check file permissions and disk space".to_string()),
            alternative_paths: vec![
                "Try using a different file path".to_string(),
                "Check if the file exists and is accessible".to_string(),
            ],
        }
    }

    pub fn io_error_with_path(operation: impl Into<String>, path: impl Into<String>, message: impl Into<String>) -> Self {
        FortressError::FileSystemError {
            operation: operation.into(),
            path: path.into(),
            error_code: "IO001".to_string(),
            help_text: message.into(),
            permission_info: Some("Check file permissions and disk space".to_string()),
            alternative_paths: vec![
                "Try using a different file path".to_string(),
                "Check if the file exists and is accessible".to_string(),
            ],
        }
    }

    pub fn cli(command: impl Into<String>, reason: impl Into<String>) -> Self {
        let cmd_str = command.into();
        let reason_str = reason.into();
        FortressError::CliError {
            command: cmd_str.clone(),
            reason: reason_str.clone(),
            error_code: "CLI001".to_string(),
            help_text: format!("CLI command '{}' failed: {}", cmd_str, reason_str),
            suggestion: Some(format!(
                "Check 'fortress help {}' for correct usage",
                cmd_str
            )),
            example_usage: Some(format!("fortress {} <options>", cmd_str)),
        }
    }

    pub fn is_recoverable(&self) -> bool {
        match self.severity() {
            ErrorSeverity::Low | ErrorSeverity::Medium => true,
            ErrorSeverity::High | ErrorSeverity::Critical => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "Low"),
            ErrorSeverity::Medium => write!(f, "Medium"),
            ErrorSeverity::High => write!(f, "High"),
            ErrorSeverity::Critical => write!(f, "Critical"),
        }
    }
}

// Error documentation system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDocumentation {
    pub error_code: String,
    pub title: String,
    pub description: String,
    pub causes: Vec<String>,
    pub solutions: Vec<String>,
    pub prevention_tips: Vec<String>,
    pub related_errors: Vec<String>,
    pub examples: Vec<String>,
}

impl ErrorDocumentation {
    pub fn for_error_code(error_code: &str) -> Option<Self> {
        match error_code {
            "ENC001" => Some(ErrorDocumentation {
                error_code: "ENC001".to_string(),
                title: "Invalid Key Length".to_string(),
                description: "The provided encryption key does not meet the required length for the selected algorithm.".to_string(),
                causes: vec![
                    "Key generation failed or was interrupted".to_string(),
                    "Key was truncated during storage or transmission".to_string(),
                    "Wrong algorithm selected for the key length".to_string(),
                ],
                solutions: vec![
                    "Generate a new key with the correct length".to_string(),
                    "Verify the key length matches algorithm requirements".to_string(),
                    "Check key storage and transmission integrity".to_string(),
                ],
                prevention_tips: vec![
                    "Always validate key length before use".to_string(),
                    "Use secure key generation methods".to_string(),
                    "Implement key integrity checks".to_string(),
                ],
                related_errors: vec!["KEY001".to_string()],
                examples: vec![
                    "AES-256 requires 32-byte keys".to_string(),
                    "RSA-2048 requires 256-byte keys".to_string(),
                ],
            }),
            "DB001" => Some(ErrorDocumentation {
                error_code: "DB001".to_string(),
                title: "Database Connection Failed".to_string(),
                description: "Unable to establish connection to the database server.".to_string(),
                causes: vec![
                    "Database server is down or unreachable".to_string(),
                    "Network connectivity issues".to_string(),
                    "Invalid credentials or insufficient permissions".to_string(),
                ],
                solutions: vec![
                    "Verify database server status and connectivity".to_string(),
                    "Check network configuration and firewall rules".to_string(),
                    "Validate database credentials and permissions".to_string(),
                ],
                prevention_tips: vec![
                    "Implement connection health checks".to_string(),
                    "Use connection pooling for better reliability".to_string(),
                    "Monitor database server metrics".to_string(),
                ],
                related_errors: vec!["NET001".to_string()],
                examples: vec![
                    "Connection timeout after 30 seconds".to_string(),
                    "Authentication failed for user 'fortress_app'".to_string(),
                ],
            }),
            _ => None,
        }
    }
}

// Error analyzer for tracking and reporting
pub struct ErrorAnalyzer {
    errors: Vec<ErrorReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub error_code: String,
    pub message: String,
    pub context: HashMap<String, String>,
    pub severity: ErrorSeverity,
}

impl ErrorAnalyzer {
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    pub fn report_error(&mut self, error: &FortressError, context: HashMap<String, String>) {
        let report = ErrorReport {
            timestamp: chrono::Utc::now(),
            error_code: error.error_code().to_string(),
            message: error.to_string(),
            context,
            severity: error.severity(),
        };

        self.errors.push(report);

        // Keep only last 1000 errors
        if self.errors.len() > 1000 {
            self.errors.remove(0);
        }
    }

    pub fn get_error_summary(&self, hours: u64) -> ErrorSummary {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
        let recent_errors: Vec<_> = self
            .errors
            .iter()
            .filter(|e| e.timestamp > cutoff)
            .collect();

        let mut error_counts = HashMap::new();
        let mut severity_counts = HashMap::new();

        for error in &recent_errors {
            *error_counts.entry(error.error_code.clone()).or_insert(0) += 1;
            *severity_counts
                .entry(format!("{:?}", error.severity))
                .or_insert(0) += 1;
        }

        ErrorSummary {
            total_errors: recent_errors.len(),
            error_counts: error_counts.clone(),
            severity_counts,
            most_common: error_counts
                .iter()
                .max_by_key(|(_, &count)| count)
                .map(|(code, count)| (code.clone(), *count)),
            time_period_hours: hours,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSummary {
    pub total_errors: usize,
    pub error_counts: HashMap<String, usize>,
    pub severity_counts: HashMap<String, usize>,
    pub most_common: Option<(String, usize)>,
    pub time_period_hours: u64,
}

impl Default for ErrorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
