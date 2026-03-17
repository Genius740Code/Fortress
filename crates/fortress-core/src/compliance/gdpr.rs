//! GDPR Compliance Implementation
//!
//! Implements General Data Protection Regulation compliance features including
//! data subject rights, consent management, data breach notification, and
//! privacy by design principles.

use crate::error::{FortressError, Result};
use crate::compliance::framework::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// GDPR-specific compliance manager
pub struct GdprComplianceManager {
    base_manager: Box<dyn ComplianceManager>,
    data_processor_registry: std::sync::Arc<tokio::sync::RwLock<HashMap<String, DataProcessor>>>,
    data_protection_impact_assessments: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Dpia>>>,
    breach_records: std::sync::Arc<tokio::sync::RwLock<Vec<DataBreach>>>,
}

/// Data processor registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProcessor {
    /// Unique identifier for the data processor
    pub id: String,
    /// Name of the data processor
    pub name: String,
    /// Contact information
    pub contact_info: String,
    /// Types of data processed
    pub data_types: Vec<String>,
    /// Processing purposes
    pub purposes: Vec<String>,
    /// Data subject categories
    pub data_subject_categories: Vec<String>,
    /// Data retention periods
    pub retention_periods: HashMap<String, Duration>,
    /// Security measures
    pub security_measures: Vec<String>,
    /// International data transfers
    pub international_transfers: Vec<InternationalTransfer>,
    /// Registration date
    pub registered_at: DateTime<Utc>,
    /// Last updated date
    pub updated_at: DateTime<Utc>,
}

/// International data transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternationalTransfer {
    /// Destination country
    pub destination_country: String,
    /// Transfer mechanism (SCCs, BCRs, Adequacy Decision)
    pub mechanism: String,
    /// Data categories transferred
    pub data_categories: Vec<String>,
    /// Frequency of transfer
    pub frequency: String,
}

/// Data Protection Impact Assessment (DPIA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dpia {
    /// Unique identifier for the DPIA
    pub id: String,
    /// Name of the processing activity
    pub activity_name: String,
    /// Description of the processing
    pub description: String,
    /// Data types involved
    pub data_types: Vec<String>,
    /// Data subjects affected
    pub data_subjects: Vec<String>,
    /// Nature and scope of processing
    pub scope: String,
    /// Purposes of processing
    pub purposes: Vec<String>,
    /// Likelihood and severity of risk
    pub risk_assessment: RiskAssessment,
    /// Measures to mitigate risks
    pub mitigation_measures: Vec<String>,
    /// Whether DPIA is required
    pub required: bool,
    /// DPIA status
    pub status: DpiaStatus,
    /// Review date
    pub review_date: Option<DateTime<Utc>>,
    /// Assessor information
    pub assessor: String,
    /// Approval information
    pub approval: Option<DpiaApproval>,
}

/// Risk assessment for DPIA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Likelihood of risk (1-5 scale)
    pub likelihood: u8,
    /// Severity of impact (1-5 scale)
    pub severity: u8,
    /// Overall risk score
    pub risk_score: u8,
    /// Risk categories
    pub risk_categories: Vec<String>,
    /// Specific risks identified
    pub risks: Vec<String>,
}

/// DPIA status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpiaStatus {
    /// DPIA not started
    NotStarted,
    /// DPIA in progress
    InProgress,
    /// DPIA completed
    Completed,
    /// DPIA approved
    Approved,
    /// DPIA rejected
    Rejected,
    /// DPIA requires review
    RequiresReview,
}

/// DPIA approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiaApproval {
    /// Approver name
    pub approver: String,
    /// Approval date
    pub approval_date: DateTime<Utc>,
    /// Approval comments
    pub comments: String,
    /// Conditions for approval
    pub conditions: Vec<String>,
}

/// Data breach record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBreach {
    /// Unique identifier for the breach
    pub id: Uuid,
    /// Date and time breach was discovered
    pub discovered_at: DateTime<Utc>,
    /// Date and time breach occurred (if known)
    pub occurred_at: Option<DateTime<Utc>>,
    /// Breach description
    pub description: String,
    /// Types of data affected
    pub data_types_affected: Vec<String>,
    /// Number of data subjects affected
    pub subjects_affected: u32,
    /// Categories of data subjects affected
    pub subject_categories: Vec<String>,
    /// Likely consequences
    pub likely_consequences: Vec<String>,
    /// Measures taken to address breach
    pub measures_taken: Vec<String>,
    /// Measures proposed to address breach
    pub measures_proposed: Vec<String>,
    /// Whether supervisory authority was notified
    pub authority_notified: bool,
    /// Date authority was notified
    pub authority_notification_date: Option<DateTime<Utc>>,
    /// Whether data subjects were notified
    pub subjects_notified: bool,
    /// Date subjects were notified
    pub subjects_notification_date: Option<DateTime<Utc>>,
    /// Data Protection Officer contact
    pub dpo_contact: String,
    /// Breach severity
    pub severity: BreachSeverity,
    /// Breach status
    pub status: BreachStatus,
}

/// Breach severity levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreachSeverity {
    /// Low impact breach
    Low,
    /// Medium impact breach
    Medium,
    /// High impact breach
    High,
    /// Critical impact breach
    Critical,
}

/// Breach status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreachStatus {
    /// Breach discovered
    Discovered,
    /// Investigation in progress
    Investigating,
    /// Containment measures in progress
    Containing,
    /// Breach contained
    Contained,
    /// Recovery in progress
    Recovering,
    /// Breach resolved
    Resolved,
    /// Breach closed
    Closed,
}

impl GdprComplianceManager {
    /// Create a new GDPR compliance manager
    pub fn new(base_manager: Box<dyn ComplianceManager>) -> Self {
        Self {
            base_manager,
            data_processor_registry: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            data_protection_impact_assessments: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            breach_records: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// Register a data processor
    pub async fn register_data_processor(&self, processor: &DataProcessor) -> Result<()> {
        log::info!("Registering data processor: {}", processor.name);
        
        let mut registry = self.data_processor_registry.write().await;
        registry.insert(processor.id.clone(), processor.clone());
        
        // Log the registration
        let event = ComplianceEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            framework: ComplianceFramework::GDPR,
            event_type: "data_processor_registered".to_string(),
            severity: EventSeverity::Info,
            description: format!("Data processor {} registered", processor.name),
            affected_resources: vec![processor.id.clone()],
            actor: "system".to_string(),
            outcome: EventOutcome::Success,
            metadata: HashMap::new(),
        };
        
        self.base_manager.log_event(&event).await?;
        Ok(())
    }

    /// Create and manage DPIA
    pub async fn create_dpia(&self, dpia: &Dpia) -> Result<()> {
        log::info!("Creating DPIA for activity: {}", dpia.activity_name);
        
        let mut dpias = self.data_protection_impact_assessments.write().await;
        dpias.insert(dpia.id.clone(), dpia.clone());
        
        // Log DPIA creation
        let event = ComplianceEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            framework: ComplianceFramework::GDPR,
            event_type: "dpia_created".to_string(),
            severity: EventSeverity::Info,
            description: format!("DPIA created for activity: {}", dpia.activity_name),
            affected_resources: vec![dpia.id.clone()],
            actor: dpia.assessor.clone(),
            outcome: EventOutcome::Success,
            metadata: HashMap::new(),
        };
        
        self.base_manager.log_event(&event).await?;
        Ok(())
    }

    /// Record and manage data breach
    pub async fn record_data_breach(&self, breach: &DataBreach) -> Result<()> {
        log::warn!("Recording data breach: {}", breach.id);
        
        let mut breaches = self.breach_records.write().await;
        breaches.push(breach.clone());
        
        // Check if notification is required (within 72 hours)
        let now = Utc::now();
        let hours_since_discovery = (now - breach.discovered_at).num_hours();
        
        if hours_since_discovery >= 72 && !breach.authority_notified {
            log::error!("Breach notification deadline exceeded for breach: {}", breach.id);
            
            // Create critical event for missed deadline
            let critical_event = ComplianceEvent {
                id: Uuid::new_v4(),
                timestamp: now,
                framework: ComplianceFramework::GDPR,
                event_type: "breach_notification_deadline_missed".to_string(),
                severity: EventSeverity::Critical,
                description: format!("72-hour breach notification deadline missed for breach: {}", breach.id),
                affected_resources: vec![breach.id.to_string()],
                actor: "system".to_string(),
                outcome: EventOutcome::Failure,
                metadata: HashMap::new(),
            };
            
            self.base_manager.log_event(&critical_event).await?;
        }
        
        // Log the breach recording
        let event = ComplianceEvent {
            id: Uuid::new_v4(),
            timestamp: now,
            framework: ComplianceFramework::GDPR,
            event_type: "data_breach_recorded".to_string(),
            severity: match breach.severity {
                BreachSeverity::Critical => EventSeverity::Critical,
                BreachSeverity::High => EventSeverity::Error,
                BreachSeverity::Medium => EventSeverity::Warning,
                BreachSeverity::Low => EventSeverity::Info,
            },
            description: format!("Data breach recorded: {}", breach.description),
            affected_resources: vec![breach.id.to_string()],
            actor: "system".to_string(),
            outcome: EventOutcome::Success,
            metadata: HashMap::new(),
        };
        
        self.base_manager.log_event(&event).await?;
        Ok(())
    }

    /// Check if DPIA is required for processing activity
    pub async fn is_dpia_required(&self, activity: &str, data_types: &[String]) -> Result<bool> {
        // DPIA is required for:
        // 1. Systematic and extensive evaluation of personal aspects
        // 2. Large-scale processing of special categories of data
        // 3. Large-scale systematic monitoring of public areas
        // 4. Processing that presents a high risk to data subjects' rights
        
        let special_categories = vec![
            "racial_or_ethnic_origin",
            "political_opinions",
            "religious_beliefs",
            "trade_union_membership",
            "genetic_data",
            "biometric_data",
            "health_data",
            "sex_life_or_sexual_orientation",
        ];
        
        let has_special_category = data_types.iter()
            .any(|dt| special_categories.contains(&dt.as_str()));
        
        let is_large_scale = activity.contains("large_scale") || 
                            activity.contains("systematic") ||
                            activity.contains("extensive");
        
        let is_high_risk = activity.contains("profiling") ||
                         activity.contains("automated_decision_making") ||
                         activity.contains("systematic_monitoring");
        
        Ok(has_special_category || is_large_scale || is_high_risk)
    }

    /// Generate GDPR-specific compliance report
    pub async fn generate_gdpr_report(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<GdprReport> {
        log::info!("Generating GDPR compliance report from {} to {}", start_date, end_date);
        
        let registry = self.data_processor_registry.read().await;
        let dpias = self.data_protection_impact_assessments.read().await;
        let breaches = self.breach_records.read().await;
        
        // Count breaches in the period
        let period_breaches: Vec<&DataBreach> = breaches.iter()
            .filter(|b| b.discovered_at >= start_date && b.discovered_at <= end_date)
            .collect();
        
        // Count DPIAs in the period
        let period_dpias: Vec<&Dpia> = dpias.values()
            .filter(|d| d.review_date.map_or(false, |date| date >= start_date && date <= end_date))
            .collect();
        
        let report = GdprReport {
            id: Uuid::new_v4(),
            generated_at: Utc::now(),
            period_start: start_date,
            period_end: end_date,
            total_data_processors: registry.len(),
            active_dpias: dpias.len(),
            completed_dpias: dpias.values().filter(|d| matches!(d.status, DpiaStatus::Completed | DpiaStatus::Approved)).count(),
            total_breaches: breaches.len(),
            breaches_in_period: period_breaches.len(),
            critical_breaches: period_breaches.iter().filter(|b| matches!(b.severity, BreachSeverity::Critical)).count(),
            compliance_score: self.calculate_gdpr_score(&registry, &dpias, &breaches).await?,
            recommendations: self.generate_gdpr_recommendations(&registry, &dpias, &breaches).await,
        };
        
        Ok(report)
    }

    async fn calculate_gdpr_score(
        &self,
        _registry: &HashMap<String, DataProcessor>,
        dpias: &HashMap<String, Dpia>,
        breaches: &Vec<DataBreach>,
    ) -> Result<u32> {
        let mut score = 100u32;
        
        // Deduct points for incomplete DPIAs
        let incomplete_dpias = dpias.values()
            .filter(|d| !matches!(d.status, DpiaStatus::Completed | DpiaStatus::Approved))
            .count();
        score = score.saturating_sub((incomplete_dpias * 5) as u32);
        
        // Deduct points for breaches
        let recent_breaches = breaches.iter()
            .filter(|b| Utc::now() - b.discovered_at < Duration::days(90))
            .count();
        score = score.saturating_sub((recent_breaches * 10) as u32);
        
        // Deduct points for critical breaches
        let critical_breaches = breaches.iter()
            .filter(|b| matches!(b.severity, BreachSeverity::Critical))
            .count();
        score = score.saturating_sub((critical_breaches * 20) as u32);
        
        Ok(score.max(0))
    }

    async fn generate_gdpr_recommendations(
        &self,
        _registry: &HashMap<String, DataProcessor>,
        dpias: &HashMap<String, Dpia>,
        breaches: &Vec<DataBreach>,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // DPIA recommendations
        let incomplete_dpias = dpias.values()
            .filter(|d| !matches!(d.status, DpiaStatus::Completed | DpiaStatus::Approved))
            .count();
        if incomplete_dpias > 0 {
            recommendations.push(format!("Complete {} incomplete DPIAs", incomplete_dpias));
        }
        
        // Breach recommendations
        let recent_breaches = breaches.iter()
            .filter(|b| Utc::now() - b.discovered_at < Duration::days(90))
            .count();
        if recent_breaches > 0 {
            recommendations.push("Review and enhance security measures to prevent future breaches".to_string());
        }
        
        // General recommendations
        if recommendations.is_empty() {
            recommendations.push("Continue monitoring compliance and maintaining records".to_string());
        }
        
        recommendations
    }
}

/// GDPR-specific compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdprReport {
    /// Unique identifier for the report
    pub id: Uuid,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Report period
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    /// Total number of registered data processors
    pub total_data_processors: usize,
    /// Total number of DPIAs
    pub active_dpias: usize,
    /// Number of completed DPIAs
    pub completed_dpias: usize,
    /// Total number of breaches
    pub total_breaches: usize,
    /// Number of breaches in the reporting period
    pub breaches_in_period: usize,
    /// Number of critical breaches
    pub critical_breaches: usize,
    /// Overall compliance score (0-100)
    pub compliance_score: u32,
    /// Recommendations for improvement
    pub recommendations: Vec<String>,
}

#[async_trait]
impl ComplianceManager for GdprComplianceManager {
    async fn initialize(&self, config: &ComplianceConfig) -> Result<()> {
        self.base_manager.initialize(config).await?;
        log::info!("GDPR compliance manager initialized");
        Ok(())
    }

    async fn register_data_subject(&self, subject: &DataSubject) -> Result<()> {
        self.base_manager.register_data_subject(subject).await
    }

    async fn record_consent(&self, subject_id: &str, consent: &ConsentRecord) -> Result<()> {
        self.base_manager.record_consent(subject_id, consent).await
    }

    async fn process_rights_request(&self, request: &RightsRequest) -> Result<()> {
        log::info!("Processing GDPR rights request: {:?}", request.request_type);
        
        // GDPR-specific processing logic
        match request.request_type {
            RightsRequestType::Access => {
                log::info!("Processing data access request");
                // Implement data access logic
            },
            RightsRequestType::Erasure => {
                log::info!("Processing right to be forgotten request");
                // Implement data deletion logic
            },
            RightsRequestType::Portability => {
                log::info!("Processing data portability request");
                // Implement data export logic
            },
            _ => {
                log::info!("Processing rights request: {:?}", request.request_type);
            }
        }
        
        self.base_manager.process_rights_request(request).await
    }

    async fn log_event(&self, event: &ComplianceEvent) -> Result<()> {
        self.base_manager.log_event(event).await
    }

    async fn check_access_compliance(
        &self,
        user_id: &str,
        data_id: &str,
        framework: ComplianceFramework,
    ) -> Result<bool> {
        if framework == ComplianceFramework::GDPR {
            // GDPR-specific checks: consent, purpose limitation, data minimization
            // In a real implementation, this would check:
            // - Valid consent for the processing
            // - Processing is within stated purposes
            // - Data collection is adequate and limited
            // - Data retention periods are respected
        }
        
        self.base_manager.check_access_compliance(user_id, data_id, framework).await
    }

    async fn generate_report(
        &self,
        framework: ComplianceFramework,
        report_type: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<ComplianceReport> {
        if framework == ComplianceFramework::GDPR {
            let gdpr_report = self.generate_gdpr_report(start_date, end_date).await?;
            
            return Ok(ComplianceReport {
                id: gdpr_report.id,
                framework,
                report_type: report_type.to_string(),
                generated_at: gdpr_report.generated_at,
                period_start: gdpr_report.period_start,
                period_end: gdpr_report.period_end,
                compliance_score: gdpr_report.compliance_score,
                findings: vec![],
                recommendations: gdpr_report.recommendations,
                evidence: HashMap::new(),
            });
        }
        
        self.base_manager.generate_report(framework, report_type, start_date, end_date).await
    }

    async fn validate_configuration(&self, config: &ComplianceConfig) -> Result<Vec<ComplianceIssue>> {
        let mut issues = self.base_manager.validate_configuration(config).await?;
        
        // GDPR-specific validations
        if !config.enabled_frameworks.contains(&ComplianceFramework::GDPR) {
            return Ok(issues);
        }
        
        // Validate breach notification deadline (GDPR requires 72 hours)
        if config.breach_notification.notification_deadline_hours > 72 {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Error,
                description: "GDPR requires breach notification within 72 hours".to_string(),
                affected_section: "breach_notification".to_string(),
                recommendation: "Set notification deadline to 72 hours or less".to_string(),
            });
        }
        
        // Validate data retention periods
        if config.default_retention_period > Duration::days(365 * 7) {
            issues.push(ComplianceIssue {
                severity: EventSeverity::Warning,
                description: "Default retention period exceeds 7 years".to_string(),
                affected_section: "default_retention_period".to_string(),
                recommendation: "Review retention periods against GDPR principles".to_string(),
            });
        }
        
        Ok(issues)
    }
}
