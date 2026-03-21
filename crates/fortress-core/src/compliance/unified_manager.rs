//! Unified Compliance Manager
//!
//! Provides a unified interface for managing multiple compliance frameworks
//! with centralized reporting and risk assessment.

use crate::compliance::framework::*;
use crate::compliance::gdpr::GdprComplianceManager;
use crate::compliance::hipaa::HipaaComplianceManager;
use crate::compliance::pci_dss::PciDssComplianceManager;
use crate::error::FortressError;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;
use tokio::sync::RwLock;

/// Unified compliance manager that handles multiple frameworks
pub struct UnifiedComplianceManager {
    gdpr_manager: Option<GdprComplianceManager>,
    hipaa_manager: Option<HipaaComplianceManager>,
    pci_dss_manager: Option<PciDssComplianceManager>,
    config: RwLock<Option<ComplianceConfig>>,
}

impl UnifiedComplianceManager {
    /// Create a new unified compliance manager
    pub fn new() -> Self {
        Self {
            gdpr_manager: None,
            hipaa_manager: None,
            pci_dss_manager: None,
            config: RwLock::new(None),
        }
    }

    /// Initialize with GDPR manager
    pub async fn with_gdpr(mut self, _config: &ComplianceConfig) -> Result<Self, FortressError> {
        // Create a default GDPR manager
        self.gdpr_manager = Some(GdprComplianceManager::new());
        Ok(self)
    }

    /// Initialize with HIPAA manager
    pub async fn with_hipaa(mut self, _config: &ComplianceConfig) -> Result<Self, FortressError> {
        // Create a default HIPAA manager with a mock base manager
        let base_manager = Box::new(crate::compliance::framework::DefaultComplianceManager::new());
        self.hipaa_manager = Some(HipaaComplianceManager::new(base_manager));
        Ok(self)
    }

    /// Initialize with PCI-DSS manager
    pub async fn with_pci_dss(mut self, _config: &ComplianceConfig) -> Result<Self, FortressError> {
        // Create a default PCI-DSS manager
        self.pci_dss_manager = Some(PciDssComplianceManager::new(Box::new(crate::compliance::framework::DefaultComplianceManager::new())));
        Ok(self)
    }

    /// Generate automated compliance report
    async fn generate_automated_report(
        &self,
        report_type: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<ComplianceReport, FortressError> {
        let mut all_findings = Vec::new();
        let mut all_recommendations = Vec::new();

        // Collect findings from all frameworks
        if let Some(gdpr_manager) = &self.gdpr_manager {
            let findings = gdpr_manager.collect_findings(start_date, end_date).await?;
            all_findings.extend(findings);
        }

        if let Some(hipaa_manager) = &self.hipaa_manager {
            let findings = hipaa_manager.collect_findings(start_date, end_date).await?;
            all_findings.extend(findings);
        }

        if let Some(pci_dss_manager) = &self.pci_dss_manager {
            let findings = pci_dss_manager.collect_findings(start_date, end_date).await?;
            all_findings.extend(findings);
        }

        // Generate recommendations based on findings
        let issues = self.assess_compliance_issues().await?;
        all_recommendations.extend(self.generate_recommendations(&issues).await?);

        Ok(ComplianceReport {
            id: Uuid::new_v4(),
            framework: ComplianceFramework::GDPR, // Default to GDPR for unified reports
            report_type: report_type.to_string(),
            generated_at: Utc::now(),
            period_start: start_date,
            period_end: end_date,
            compliance_score: self.calculate_overall_score(&all_findings).await? as u32,
            findings: all_findings,
            recommendations: all_recommendations,
            evidence: HashMap::new(),
        })
    }

    /// Calculate overall compliance score from findings
    async fn calculate_overall_score(&self, findings: &[ComplianceFinding]) -> Result<f64, FortressError> {
        if findings.is_empty() {
            return Ok(100.0);
        }

        let critical_count = findings.iter().filter(|f| matches!(f.severity, EventSeverity::Critical)).count();
        let error_count = findings.iter().filter(|f| matches!(f.severity, EventSeverity::Error)).count();
        let warning_count = findings.iter().filter(|f| matches!(f.severity, EventSeverity::Warning)).count();

        let base_score = 100.0;
        let critical_penalty = (critical_count as f64) * 20.0;
        let error_penalty = (error_count as f64) * 10.0;
        let warning_penalty = (warning_count as f64) * 5.0;

        Ok((base_score - critical_penalty - error_penalty - warning_penalty).max(0.0))
    }

    /// Assess risks based on findings
    async fn assess_risks(&self, findings: &[ComplianceFinding]) -> Result<RiskAssessment, FortressError> {
        let mut risk_by_category = HashMap::new();
        let mut high_risk_areas = Vec::new();
        let critical_count = findings.iter().filter(|f| matches!(f.severity, EventSeverity::Critical)).count();
        let high_count = findings.iter().filter(|f| matches!(f.severity, EventSeverity::Error)).count();
        
        // Determine overall risk
        let overall_risk = match (critical_count, high_count) {
            (0, 0) => "Low".to_string(),
            (0, 1..=3) => "Medium".to_string(),
            (0, 4..) => "High".to_string(),
            (1..=2, _) => "High".to_string(),
            _ => "Critical".to_string(),
        };
        
        // Risk by category
        risk_by_category.insert("Access Control".to_string(), 
            if findings.iter().any(|f| f.category.contains("access")) { "Medium" } else { "Low" }.to_string());
        risk_by_category.insert("Data Protection".to_string(), 
            if findings.iter().any(|f| f.category.contains("encryption")) { "Low" } else { "Medium" }.to_string());
        risk_by_category.insert("Audit Trail".to_string(), 
            if findings.iter().any(|f| f.category.contains("audit")) { "Low" } else { "Medium" }.to_string());
        
        // High risk areas
        if critical_count > 0 {
            high_risk_areas.push("Critical compliance issues".to_string());
        }
        if high_count > 3 {
            high_risk_areas.push("Multiple high-severity findings".to_string());
        }
        
        Ok(RiskAssessment {
            overall_risk,
            risk_by_category,
            high_risk_areas,
            risk_trends: Vec::new(), // Would be populated with historical data
        })
    }

    /// Generate action items from findings
    async fn generate_action_items(&self, findings: &[ComplianceFinding]) -> Vec<ActionItem> {
        findings.iter().map(|finding| {
            ActionItem {
                id: Uuid::new_v4(),
                title: format!("Address: {}", finding.category),
                description: finding.description.clone(),
                priority: finding.severity.to_string(),
                assigned_to: None,
                due_date: Utc::now() + chrono::Duration::days(30),
                status: "Open".to_string(),
                framework: "Compliance".to_string(),
            }
        }).collect()
    }

    /// Collect evidence for findings
    async fn collect_evidence(&self, framework_findings: &HashMap<String, Vec<ComplianceFinding>>) -> Result<Vec<EvidenceAttachment>, FortressError> {
        let mut evidence = Vec::new();
        
        for (framework, findings) in framework_findings {
            for finding in findings {
                evidence.push(EvidenceAttachment {
                    id: Uuid::new_v4(),
                    evidence_type: format!("{}_audit_log", framework.to_lowercase()),
                    description: format!("Audit log evidence for: {}", finding.category),
                    location: format!("/var/log/fortress/compliance/{}_audit.log", framework.to_lowercase()),
                    collected_at: Utc::now(),
                    verified: true,
                });
            }
        }
        
        Ok(evidence)
    }

    /// Generate executive summary
    async fn generate_executive_summary(&self, findings: &[ComplianceFinding], risk_assessment: &RiskAssessment) -> String {
        let total_findings = findings.len();
        let critical_findings = findings.iter().filter(|f| matches!(f.severity, EventSeverity::Critical)).count();
        let high_findings = findings.iter().filter(|f| matches!(f.severity, EventSeverity::Error)).count();
        
        format!(
            "Compliance assessment completed with {} total findings. \
             Risk level: {}. \
             {} critical and {} high-priority issues require immediate attention. \
             Overall compliance posture is {} based on current findings.",
            total_findings,
            risk_assessment.overall_risk,
            critical_findings,
            high_findings,
            if risk_assessment.overall_risk == "Low" { "strong" } else { "needs improvement" }
        )
    }
}

#[async_trait::async_trait]
impl ComplianceManager for UnifiedComplianceManager {
    async fn initialize(&self, config: &ComplianceConfig) -> Result<(), FortressError> {
        log::info!("Initializing unified compliance manager with frameworks: {:?}", config.enabled_frameworks);
        
        // Validate configuration
        let issues = self.validate_configuration(config).await?;
        if !issues.is_empty() {
            log::warn!("Configuration validation found {} issues", issues.len());
            for issue in &issues {
                log::warn!("{}: {}", issue.severity, issue.description);
            }
        }

        // Store configuration
        *self.config.write().await = Some(config.clone());
        log::info!("Unified compliance manager initialized successfully");
        Ok(())
    }

    async fn register_data_subject(&self, subject: &DataSubject) -> Result<(), FortressError> {
        if let Some(gdpr_manager) = &self.gdpr_manager {
            gdpr_manager.register_data_subject(subject).await?;
        }
        Ok(())
    }

    async fn record_consent(&self, subject_id: &str, consent: &ConsentRecord) -> Result<(), FortressError> {
        if let Some(gdpr_manager) = &self.gdpr_manager {
            gdpr_manager.record_consent(subject_id, consent).await?;
        }
        Ok(())
    }

    async fn process_rights_request(&self, request: &RightsRequest) -> Result<(), FortressError> {
        if let Some(gdpr_manager) = &self.gdpr_manager {
            gdpr_manager.process_rights_request(request).await?;
        }
        Ok(())
    }

    async fn log_event(&self, event: &ComplianceEvent) -> Result<(), FortressError> {
        match event.framework {
            ComplianceFramework::GDPR => {
                if let Some(gdpr_manager) = &self.gdpr_manager {
                    gdpr_manager.log_event(event).await?;
                }
            },
            ComplianceFramework::HIPAA => {
                if let Some(hipaa_manager) = &self.hipaa_manager {
                    hipaa_manager.log_event(event).await?;
                }
            },
            ComplianceFramework::PCIDSS => {
                if let Some(pci_dss_manager) = &self.pci_dss_manager {
                    pci_dss_manager.log_event(event).await?;
                }
            },
        }
        Ok(())
    }

    async fn check_access_compliance(
        &self,
        user_id: &str,
        data_id: &str,
        framework: ComplianceFramework,
    ) -> Result<bool, FortressError> {
        match framework {
            ComplianceFramework::GDPR => {
                if let Some(gdpr_manager) = &self.gdpr_manager {
                    gdpr_manager.check_access_compliance(user_id, data_id).await
                } else {
                    Ok(false)
                }
            },
            ComplianceFramework::HIPAA => {
                if let Some(hipaa_manager) = &self.hipaa_manager {
                    hipaa_manager.check_access_compliance(user_id, data_id, framework).await
                } else {
                    Ok(false)
                }
            },
            ComplianceFramework::PCIDSS => {
                if let Some(pci_dss_manager) = &self.pci_dss_manager {
                    pci_dss_manager.check_access_compliance(user_id, data_id, framework).await
                } else {
                    Ok(false)
                }
            },
        }
    }

    async fn generate_report(
        &self,
        framework: ComplianceFramework,
        report_type: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<ComplianceReport, FortressError> {
        let automated_report = self.generate_automated_report(report_type, start_date, end_date).await?;
        
        Ok(ComplianceReport {
            id: automated_report.id,
            framework,
            report_type: automated_report.report_type,
            generated_at: automated_report.generated_at,
            period_start: automated_report.period_start,
            period_end: automated_report.period_end,
            compliance_score: automated_report.compliance_score,
            findings: automated_report.findings,
            recommendations: automated_report.recommendations,
            evidence: automated_report.evidence,
        })
    }

    async fn validate_configuration(&self, config: &ComplianceConfig) -> Result<Vec<ComplianceIssue>, FortressError> {
        let mut all_issues = Vec::new();

        if let Some(gdpr_manager) = &self.gdpr_manager {
            all_issues.extend(gdpr_manager.validate_configuration(config).await?);
        }
        
        if let Some(hipaa_manager) = &self.hipaa_manager {
            all_issues.extend(hipaa_manager.validate_configuration(config).await?);
        }
        
        if let Some(pci_dss_manager) = &self.pci_dss_manager {
            all_issues.extend(pci_dss_manager.validate_configuration(config).await?);
        }
        
        Ok(all_issues)
    }

    async fn collect_findings(&self, start_date: DateTime<Utc>, end_date: DateTime<Utc>) -> Result<Vec<ComplianceFinding>, FortressError> {
        let mut all_findings = Vec::new();

        if let Some(gdpr_manager) = &self.gdpr_manager {
            let findings = gdpr_manager.collect_findings(start_date, end_date).await?;
            all_findings.extend(findings);
        }

        if let Some(hipaa_manager) = &self.hipaa_manager {
            let findings = hipaa_manager.collect_findings(start_date, end_date).await?;
            all_findings.extend(findings);
        }

        if let Some(pci_dss_manager) = &self.pci_dss_manager {
            let findings = pci_dss_manager.collect_findings(start_date, end_date).await?;
            all_findings.extend(findings);
        }

        Ok(all_findings)
    }

    async fn assess_compliance_issues(&self) -> Result<Vec<ComplianceIssue>, FortressError> {
        let mut all_issues = Vec::new();

        if let Some(gdpr_manager) = &self.gdpr_manager {
            all_issues.extend(gdpr_manager.assess_compliance_issues().await?);
        }

        if let Some(hipaa_manager) = &self.hipaa_manager {
            all_issues.extend(hipaa_manager.assess_compliance_issues().await?);
        }

        if let Some(pci_dss_manager) = &self.pci_dss_manager {
            all_issues.extend(pci_dss_manager.assess_compliance_issues().await?);
        }

        Ok(all_issues)
    }

    async fn get_upcoming_deadlines(&self) -> Result<Vec<ComplianceDeadline>, FortressError> {
        let mut all_deadlines = Vec::new();

        if let Some(gdpr_manager) = &self.gdpr_manager {
            let gdpr_deadlines = gdpr_manager.get_upcoming_deadlines().await?;
            for deadline in gdpr_deadlines {
                all_deadlines.push(ComplianceDeadline {
                    id: deadline.id,
                    deadline_type: deadline.deadline_type,
                    description: deadline.description,
                    due_date: deadline.due_date,
                    framework: ComplianceFramework::GDPR,
                });
            }
        }

        if let Some(hipaa_manager) = &self.hipaa_manager {
            let hipaa_deadlines = hipaa_manager.get_upcoming_deadlines().await?;
            for deadline in hipaa_deadlines {
                all_deadlines.push(ComplianceDeadline {
                    id: deadline.id,
                    deadline_type: deadline.deadline_type,
                    description: deadline.description,
                    due_date: deadline.due_date,
                    framework: ComplianceFramework::HIPAA,
                });
            }
        }

        if let Some(pci_dss_manager) = &self.pci_dss_manager {
            let pci_dss_deadlines = pci_dss_manager.get_upcoming_deadlines().await?;
            for deadline in pci_dss_deadlines {
                all_deadlines.push(ComplianceDeadline {
                    id: deadline.id,
                    deadline_type: deadline.deadline_type,
                    description: deadline.description,
                    due_date: deadline.due_date,
                    framework: ComplianceFramework::PCIDSS,
                });
            }
        }

        Ok(all_deadlines)
    }

    async fn calculate_compliance_score(&self, issues: &[ComplianceIssue]) -> Result<f64, FortressError> {
        let critical_count = issues.iter().filter(|i| matches!(i.severity, EventSeverity::Critical)).count();
        let warning_count = issues.iter().filter(|i| matches!(i.severity, EventSeverity::Warning)).count();
        let error_count = issues.iter().filter(|i| matches!(i.severity, EventSeverity::Error)).count();
        
        let base_score = 100.0;
        let critical_penalty = (critical_count as f64) * 20.0;
        let error_penalty = (error_count as f64) * 10.0;
        let warning_penalty = (warning_count as f64) * 5.0;
        
        Ok((base_score - critical_penalty - error_penalty - warning_penalty).max(0.0))
    }

    async fn generate_recommendations(&self, issues: &[ComplianceIssue]) -> Result<Vec<String>, FortressError> {
        let mut recommendations = Vec::new();
        
        for issue in issues {
            recommendations.push(issue.recommendation.clone());
        }
        
        if recommendations.is_empty() {
            recommendations.push("Continue monitoring compliance posture".to_string());
        }
        
        Ok(recommendations)
    }

    async fn get_compliance_status(&self) -> Result<ComplianceStatus, FortressError> {
        let issues = self.assess_compliance_issues().await?;
        let score = self.calculate_compliance_score(&issues).await?;
        
        let mut framework_status = HashMap::new();
        framework_status.insert("GDPR".to_string(), score);
        framework_status.insert("HIPAA".to_string(), score);
        framework_status.insert("PCI-DSS".to_string(), score);
        
        Ok(ComplianceStatus {
            compliance_percentage: score,
            active_issues: issues.len() as u32,
            last_assessment: Utc::now(),
            framework_status,
        })
    }

    async fn generate_daily_report(&self) -> Result<(), FortressError> {
        log::info!("Generating unified daily compliance report");
        let now = Utc::now();
        let start_date = now - chrono::Duration::days(1);
        let end_date = now;
        
        let findings = self.collect_findings(start_date, end_date).await?;
        log::info!("Daily unified report: {} findings found", findings.len());
        
        Ok(())
    }

    async fn process_expired_consent(&self) -> Result<(), FortressError> {
        if let Some(gdpr_manager) = &self.gdpr_manager {
            gdpr_manager.process_expired_consent().await?;
        }
        Ok(())
    }

    async fn get_open_rights_requests(&self) -> Result<Vec<RightsRequest>, FortressError> {
        if let Some(gdpr_manager) = &self.gdpr_manager {
            gdpr_manager.get_open_rights_requests().await
        } else {
            Ok(Vec::new())
        }
    }

    async fn collect_metrics(&self) -> Result<ComplianceMetrics, FortressError> {
        // For unified manager, aggregate metrics from all frameworks
        let mut total_events = 0u64;
        let mut events_by_severity = HashMap::new();
        events_by_severity.insert(EventSeverity::Info, 0);
        events_by_severity.insert(EventSeverity::Warning, 0);
        events_by_severity.insert(EventSeverity::Error, 0);
        events_by_severity.insert(EventSeverity::Critical, 0);
        
        // In a real implementation, would collect from all framework managers
        Ok(ComplianceMetrics {
            total_events,
            events_by_severity,
            avg_response_time: 24.0, // Placeholder
            compliance_score: 85.0, // Placeholder
        })
    }
}
