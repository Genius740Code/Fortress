//! Compliance Framework for Fortress
//!
//! This module provides comprehensive compliance support for major regulatory frameworks
//! including GDPR, HIPAA, and PCI-DSS. It implements data protection, audit trails,
//! consent management, and reporting capabilities required for enterprise deployments.

pub mod framework;
pub mod gdpr;
pub mod hipaa;
pub mod pci_dss;
pub mod reporting;
pub mod audit;
pub mod config;
pub mod unified_manager;

// Use specific imports to avoid ambiguous re-exports
pub use framework::{
    ComplianceFramework, ComplianceEvent, EventSeverity, ComplianceEventOutcome,
    ComplianceFinding, FindingStatus, ComplianceIssue, ComplianceStatus, ComplianceDeadline,
    ComplianceConfig, ComplianceMetrics, ComplianceReport, DataSubject, ConsentRecord, RightsRequest,
    ComplianceManager, RightsRequestType, RequestStatus, ProtectedHealthInfo, PhiType, AccessControl,
    CardholderData, CardAccessEvent, PciRequirement, BreachNotificationConfig,
    ComplianceAuditConfig, EncryptionConfig, AccessControlConfig, PasswordPolicy,
    RiskAssessment, ActionItem as FrameworkActionItem
};
pub use gdpr::*;
pub use hipaa::*;
pub use pci_dss::{
    RiskLevel, SecurityControl, ControlStatus, VulnerabilityScan, ScanType, VulnerabilityFinding,
    VulnerabilitySeverity, RemediationStatus, ComplianceAssessment, AssessmentType, OverallComplianceStatus,
    RequirementResult, RequirementOutcome, NonComplianceIssue, IssueStatus, CorrectiveActionPlan,
    ActionItem, ActionItemStatus, ScanConfiguration, ScheduledScan, ScheduledScanStatus,
    VulnerabilityAnalysis, RemediationPriority, ComplianceImpact, PciDssComplianceManager,
    PciEncryptionKey, KeyPurpose, RotationSchedule, PciDssComplianceStatus, PciDssMetrics, PciDssReport
};
pub use reporting::*;
pub use audit::*;
pub use config::*;
