//! Compliance Framework for Fortress
//!
//! This module provides comprehensive compliance support for major regulatory frameworks
//! including GDPR, HIPAA, and PCI-DSS. It implements data protection, audit trails,
//! consent management, and reporting capabilities required for enterprise deployments.

pub mod audit;
pub mod config;
pub mod framework;
pub mod gdpr;
pub mod hipaa;
pub mod pci_dss;
pub mod reporting;
pub mod unified_manager;

// Use specific imports to avoid ambiguous re-exports
pub use audit::*;
pub use config::*;
pub use framework::{
    AccessControl, AccessControlConfig, ActionItem as FrameworkActionItem,
    BreachNotificationConfig, CardAccessEvent, CardholderData, ComplianceAuditConfig,
    ComplianceConfig, ComplianceDeadline, ComplianceEvent, ComplianceEventOutcome,
    ComplianceFinding, ComplianceFramework, ComplianceIssue, ComplianceManager, ComplianceMetrics,
    ComplianceReport, ComplianceStatus, ConsentRecord, DataSubject, EncryptionConfig,
    EventSeverity, FindingStatus, PasswordPolicy, PciRequirement, PhiType, ProtectedHealthInfo,
    RequestStatus, RightsRequest, RightsRequestType, RiskAssessment,
};
pub use gdpr::*;
pub use hipaa::*;
pub use pci_dss::{
    ActionItem, ActionItemStatus, AssessmentType, ComplianceAssessment, ComplianceImpact,
    ControlStatus, CorrectiveActionPlan, IssueStatus, KeyPurpose, NonComplianceIssue,
    OverallComplianceStatus, PciDssComplianceManager, PciDssComplianceStatus, PciDssMetrics,
    PciDssReport, PciEncryptionKey, RemediationPriority, RemediationStatus, RequirementOutcome,
    RequirementResult, RiskLevel, RotationSchedule, ScanConfiguration, ScanType, ScheduledScan,
    ScheduledScanStatus, SecurityControl, VulnerabilityAnalysis, VulnerabilityFinding,
    VulnerabilityScan, VulnerabilitySeverity,
};
pub use reporting::*;
