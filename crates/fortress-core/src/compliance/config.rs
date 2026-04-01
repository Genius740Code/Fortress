//! Compliance Configuration Module
//!
//! Provides configuration management for compliance frameworks with validation,
//! default settings, and environment-specific configurations.

use crate::error::{FortressError, Result};
use crate::compliance::framework::*;
use std::collections::HashMap;
use chrono::Duration;

/// Compliance configuration manager
pub struct ComplianceConfigManager {
    configs: HashMap<String, ComplianceConfig>,
    validators: HashMap<ComplianceFramework, Box<dyn ConfigValidator>>,
}

/// Configuration validator trait
pub trait ConfigValidator: Send + Sync {
    /// Validate a compliance configuration
    /// 
    /// # Arguments
    /// * `config` - The configuration to validate
    /// 
    /// # Returns
    /// Vector of compliance issues found during validation
    fn validate(&self, config: &ComplianceConfig) -> Result<Vec<ComplianceIssue>>;
    
    /// Get the default configuration for this validator
    /// 
    /// # Returns
    /// Default compliance configuration
    fn get_default_config(&self) -> ComplianceConfig;
    
    /// Merge two configurations with override logic
    /// 
    /// # Arguments
    /// * `base` - The base configuration
    /// * `override_config` - The configuration to override with
    /// 
    /// # Returns
    /// Merged configuration
    fn merge_configs(&self, base: &ComplianceConfig, override_config: &ComplianceConfig) -> Result<ComplianceConfig>;
}

impl ComplianceConfigManager {
    /// Create a new compliance configuration manager
    /// 
    /// # Returns
    /// Manager with default validators for GDPR, HIPAA, and PCI-DSS
    pub fn new() -> Self {
        let mut validators: HashMap<ComplianceFramework, Box<dyn ConfigValidator>> = HashMap::new();
        validators.insert(ComplianceFramework::GDPR, Box::new(GdprConfigValidator));
        validators.insert(ComplianceFramework::HIPAA, Box::new(HipaaConfigValidator));
        validators.insert(ComplianceFramework::PCIDSS, Box::new(PciDssConfigValidator));

        Self {
            configs: HashMap::new(),
            validators,
        }
    }

    /// Add a new configuration to the manager
    /// 
    /// # Arguments
    /// * `name` - Name identifier for the configuration
    /// * `config` - The compliance configuration to add
    /// 
    /// # Returns
    /// Ok if successful, Err if validation fails
    pub fn add_config(&mut self, name: String, config: ComplianceConfig) -> Result<()> {
        // Validate the configuration
        let issues = self.validate_config(&config)?;
        if !issues.is_empty() {
            log::warn!("Configuration validation found {} issues", issues.len());
            for issue in &issues {
                log::warn!("{}: {}", issue.severity, issue.description);
            }
        }

        self.configs.insert(name, config);
        Ok(())
    }

    /// Get a configuration by name
    /// 
    /// # Arguments
    /// * `name` - Name of the configuration to retrieve
    /// 
    /// # Returns
    /// Reference to the configuration if found, None otherwise
    pub fn get_config(&self, name: &str) -> Option<&ComplianceConfig> {
        self.configs.get(name)
    }

    /// Validate a compliance configuration against all enabled frameworks
    /// 
    /// # Arguments
    /// * `config` - The configuration to validate
    /// 
    /// # Returns
    /// Vector of compliance issues found during validation
    pub fn validate_config(&self, config: &ComplianceConfig) -> Result<Vec<ComplianceIssue>> {
        let mut all_issues = Vec::new();

        for framework in &config.enabled_frameworks {
            if let Some(validator) = self.validators.get(framework) {
                let issues = validator.validate(config);
                all_issues.extend(issues?);
            }
        }

        // General validation
        if config.enabled_frameworks.is_empty() {
            all_issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "At least one compliance framework must be enabled".to_string(),
                affected_section: "enabled_frameworks".to_string(),
                recommendation: "Enable at least one compliance framework".to_string(),
            });
        }

        Ok(all_issues)
    }

    /// Get the default configuration for a specific compliance framework
    /// 
    /// # Arguments
    /// * `framework` - The compliance framework to get defaults for
    /// 
    /// # Returns
    /// Default configuration if framework is supported, None otherwise
    pub fn get_default_config(&self, framework: ComplianceFramework) -> Option<ComplianceConfig> {
        self.validators.get(&framework).map(|v| v.get_default_config())
    }

    /// Merge two configurations using the appropriate validator
    /// 
    /// # Arguments
    /// * `base_name` - Name of the base configuration
    /// * `override_name` - Name of the configuration to override with
    /// 
    /// # Returns
    /// Merged configuration
    pub fn merge_configs(&self, base_name: &str, override_name: &str) -> Result<ComplianceConfig> {
        let base = self.configs.get(base_name)
            .ok_or_else(|| FortressError::compliance(format!("Base config '{}' not found", base_name)))?;
        let override_config = self.configs.get(override_name)
            .ok_or_else(|| FortressError::compliance(format!("Override config '{}' not found", override_name)))?;

        // Use the first framework's validator for merging
        let framework = base.enabled_frameworks.first()
            .ok_or_else(|| FortressError::compliance("No frameworks enabled in base config"))?;

        if let Some(validator) = self.validators.get(framework) {
            validator.merge_configs(base, override_config)
        } else {
            Err(FortressError::compliance("No validator available for framework"))
        }
    }
}

impl Default for ComplianceConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

/// GDPR configuration validator
pub struct GdprConfigValidator;

impl ConfigValidator for GdprConfigValidator {
    fn validate(&self, config: &ComplianceConfig) -> Result<Vec<ComplianceIssue>> {
        let mut issues = Vec::new();

        // GDPR requires breach notification within 72 hours
        if config.breach_notification.notification_deadline_hours > 72 {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "GDPR requires breach notification within 72 hours".to_string(),
                affected_section: "breach_notification".to_string(),
                recommendation: "Set notification deadline to 72 hours or less".to_string(),
            });
        }

        // GDPR requires comprehensive audit logging
        if !config.audit_logging.enabled {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "GDPR requires comprehensive audit logging".to_string(),
                affected_section: "audit_logging".to_string(),
                recommendation: "Enable audit logging for GDPR compliance".to_string(),
            });
        }

        // Validate retention periods
        if config.default_retention_period > Duration::days(365 * 7) {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Warning,
                description: "Default retention period exceeds 7 years".to_string(),
                affected_section: "default_retention_period".to_string(),
                recommendation: "Review retention periods against GDPR principles".to_string(),
            });
        }

        // GDPR requires encryption
        if !config.encryption.encryption_at_rest_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "GDPR requires encryption of personal data at rest".to_string(),
                affected_section: "encryption".to_string(),
                recommendation: "Enable encryption at rest".to_string(),
            });
        }

        if !config.encryption.encryption_in_transit_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "GDPR requires encryption of personal data in transit".to_string(),
                affected_section: "encryption".to_string(),
                recommendation: "Enable encryption in transit".to_string(),
            });
        }

        Ok(issues)
    }

    fn get_default_config(&self) -> ComplianceConfig {
        ComplianceConfig {
            enabled_frameworks: vec![ComplianceFramework::GDPR],
            default_retention_period: Duration::days(365 * 5), // 5 years
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 72,
                notification_recipients: vec!["dpo@company.com".to_string()],
                regulatory_bodies: vec!["ICO".to_string()],
                notification_template: "GDPR breach notification template".to_string(),
            },
            audit_logging: ComplianceAuditConfig {
                enabled: true,
                retention_period: Duration::days(365 * 7), // 7 years
                logged_events: vec![
                    "data_access".to_string(),
                    "data_modification".to_string(),
                    "consent_changes".to_string(),
                    "rights_requests".to_string(),
                    "data_breaches".to_string(),
                    "audit_trail_access".to_string(),
                ],
                storage_location: "gdpr_audit_storage".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec!["AES-256-GCM".to_string(), "ChaCha20-Poly1305".to_string()],
                minimum_key_strength: 256,
                encryption_at_rest_required: true,
                encryption_in_transit_required: true,
            },
            access_control: AccessControlConfig {
                rbac_enabled: true,
                mfa_required: false,
                session_timeout_minutes: 30,
                password_policy: PasswordPolicy {
                    min_length: 12,
                    require_special_chars: true,
                    require_numbers: true,
                    require_uppercase: true,
                    expiration_days: 90,
                },
            },
        }
    }

    fn merge_configs(&self, base: &ComplianceConfig, override_config: &ComplianceConfig) -> Result<ComplianceConfig> {
        let _base = base; // Suppress unused warning
        Ok(ComplianceConfig {
            enabled_frameworks: override_config.enabled_frameworks.clone(),
            default_retention_period: override_config.default_retention_period,
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: override_config.breach_notification.notification_deadline_hours,
                notification_recipients: override_config.breach_notification.notification_recipients.clone(),
                regulatory_bodies: override_config.breach_notification.regulatory_bodies.clone(),
                notification_template: override_config.breach_notification.notification_template.clone(),
            },
            audit_logging: ComplianceAuditConfig {
                enabled: override_config.audit_logging.enabled,
                retention_period: override_config.audit_logging.retention_period,
                logged_events: override_config.audit_logging.logged_events.clone(),
                storage_location: override_config.audit_logging.storage_location.clone(),
            },
            encryption: EncryptionConfig {
                required_algorithms: override_config.encryption.required_algorithms.clone(),
                minimum_key_strength: override_config.encryption.minimum_key_strength,
                encryption_at_rest_required: override_config.encryption.encryption_at_rest_required,
                encryption_in_transit_required: override_config.encryption.encryption_in_transit_required,
            },
            access_control: AccessControlConfig {
                rbac_enabled: override_config.access_control.rbac_enabled,
                mfa_required: override_config.access_control.mfa_required,
                session_timeout_minutes: override_config.access_control.session_timeout_minutes,
                password_policy: PasswordPolicy {
                    min_length: override_config.access_control.password_policy.min_length,
                    require_special_chars: override_config.access_control.password_policy.require_special_chars,
                    require_numbers: override_config.access_control.password_policy.require_numbers,
                    require_uppercase: override_config.access_control.password_policy.require_uppercase,
                    expiration_days: override_config.access_control.password_policy.expiration_days,
                },
            },
        })
    }
}

/// HIPAA configuration validator
pub struct HipaaConfigValidator;

impl ConfigValidator for HipaaConfigValidator {
    fn validate(&self, config: &ComplianceConfig) -> Result<Vec<ComplianceIssue>> {
        let mut issues = Vec::new();

        // HIPAA requires comprehensive audit logging
        if !config.audit_logging.enabled {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "HIPAA requires comprehensive audit logging for PHI access".to_string(),
                affected_section: "audit_logging".to_string(),
                recommendation: "Enable audit logging for HIPAA compliance".to_string(),
            });
        }

        // HIPAA requires encryption of PHI
        if !config.encryption.encryption_at_rest_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "HIPAA requires encryption of PHI at rest".to_string(),
                affected_section: "encryption".to_string(),
                recommendation: "Enable encryption at rest for PHI protection".to_string(),
            });
        }

        if !config.encryption.encryption_in_transit_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "HIPAA requires encryption of PHI in transit".to_string(),
                affected_section: "encryption".to_string(),
                recommendation: "Enable encryption in transit for PHI protection".to_string(),
            });
        }

        // HIPAA requires role-based access control
        if !config.access_control.rbac_enabled {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "HIPAA requires role-based access controls for PHI".to_string(),
                affected_section: "access_control".to_string(),
                recommendation: "Enable RBAC for proper PHI access control".to_string(),
            });
        }

        // HIPAA recommends MFA for remote access
        if !config.access_control.mfa_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Warning,
                description: "HIPAA recommends multi-factor authentication for remote access".to_string(),
                affected_section: "access_control".to_string(),
                recommendation: "Enable MFA for enhanced security".to_string(),
            });
        }

        Ok(issues)
    }

    fn get_default_config(&self) -> ComplianceConfig {
        ComplianceConfig {
            enabled_frameworks: vec![ComplianceFramework::HIPAA],
            default_retention_period: Duration::days(365 * 6), // 6 years
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 60, // HIPAA doesn't specify, but 60 hours is reasonable
                notification_recipients: vec!["security_officer@company.com".to_string()],
                regulatory_bodies: vec!["HHS".to_string()],
                notification_template: "HIPAA breach notification template".to_string(),
            },
            audit_logging: ComplianceAuditConfig {
                enabled: true,
                retention_period: Duration::days(365 * 6), // 6 years
                logged_events: vec![
                    "phi_access".to_string(),
                    "phi_modification".to_string(),
                    "user_authentication".to_string(),
                    "security_incidents".to_string(),
                    "system_changes".to_string(),
                ],
                storage_location: "hipaa_audit_storage".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec!["AES-256-GCM".to_string(), "RSA-2048".to_string()],
                minimum_key_strength: 256,
                encryption_at_rest_required: true,
                encryption_in_transit_required: true,
            },
            access_control: AccessControlConfig {
                rbac_enabled: true,
                mfa_required: true,
                session_timeout_minutes: 15,
                password_policy: PasswordPolicy {
                    min_length: 15,
                    require_special_chars: true,
                    require_numbers: true,
                    require_uppercase: true,
                    expiration_days: 60,
                },
            },
        }
    }

    fn merge_configs(&self, base: &ComplianceConfig, override_config: &ComplianceConfig) -> Result<ComplianceConfig> {
        GdprConfigValidator.merge_configs(base, override_config)
    }
}

/// PCI-DSS configuration validator
pub struct PciDssConfigValidator;

impl ConfigValidator for PciDssConfigValidator {
    fn validate(&self, config: &ComplianceConfig) -> Result<Vec<ComplianceIssue>> {
        let mut issues = Vec::new();

        // PCI-DSS requires encryption of cardholder data
        if !config.encryption.encryption_at_rest_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "PCI-DSS requires encryption of cardholder data at rest".to_string(),
                affected_section: "encryption".to_string(),
                recommendation: "Enable encryption at rest for cardholder data".to_string(),
            });
        }

        if !config.encryption.encryption_in_transit_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "PCI-DSS requires encryption of cardholder data in transit".to_string(),
                affected_section: "encryption".to_string(),
                recommendation: "Enable encryption in transit for cardholder data".to_string(),
            });
        }

        // PCI-DSS requires strong encryption
        if config.encryption.minimum_key_strength < 128 {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "PCI-DSS requires minimum key strength of 128 bits".to_string(),
                affected_section: "encryption".to_string(),
                recommendation: "Set minimum key strength to 128 bits or higher".to_string(),
            });
        }

        // PCI-DSS requires role-based access control
        if !config.access_control.rbac_enabled {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "PCI-DSS requires role-based access controls".to_string(),
                affected_section: "access_control".to_string(),
                recommendation: "Enable RBAC for proper access control".to_string(),
            });
        }

        // PCI-DSS recommends MFA
        if !config.access_control.mfa_required {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Warning,
                description: "PCI-DSS recommends multi-factor authentication".to_string(),
                affected_section: "access_control".to_string(),
                recommendation: "Enable MFA for enhanced security".to_string(),
            });
        }

        Ok(issues)
    }

    fn get_default_config(&self) -> ComplianceConfig {
        ComplianceConfig {
            enabled_frameworks: vec![ComplianceFramework::PCIDSS],
            default_retention_period: Duration::days(365 * 3), // 3 years
            breach_notification: BreachNotificationConfig {
                notification_deadline_hours: 72, // PCI-DSS requires prompt notification
                notification_recipients: vec!["compliance@company.com".to_string()],
                regulatory_bodies: vec!["PCI_SSC".to_string()],
                notification_template: "PCI-DSS breach notification template".to_string(),
            },
            audit_logging: ComplianceAuditConfig {
                enabled: true,
                retention_period: Duration::days(365 * 3), // 3 years
                logged_events: vec![
                    "cardholder_data_access".to_string(),
                    "authentication_events".to_string(),
                    "system_changes".to_string(),
                    "vulnerability_scans".to_string(),
                    "security_incidents".to_string(),
                ],
                storage_location: "pci_dss_audit_storage".to_string(),
            },
            encryption: EncryptionConfig {
                required_algorithms: vec!["AES-256-GCM".to_string(), "RSA-2048".to_string(), "Triple-DES".to_string()],
                minimum_key_strength: 128,
                encryption_at_rest_required: true,
                encryption_in_transit_required: true,
            },
            access_control: AccessControlConfig {
                rbac_enabled: true,
                mfa_required: true,
                session_timeout_minutes: 10,
                password_policy: PasswordPolicy {
                    min_length: 12,
                    require_special_chars: true,
                    require_numbers: true,
                    require_uppercase: true,
                    expiration_days: 90,
                },
            },
        }
    }

    fn merge_configs(&self, base: &ComplianceConfig, override_config: &ComplianceConfig) -> Result<ComplianceConfig> {
        GdprConfigValidator.merge_configs(base, override_config)
    }
}
