//! Audit log analysis tools for Fortress
//!
//! This module provides comprehensive analysis capabilities for audit logs,
//! including pattern detection, anomaly detection, and security insights.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Timelike};

use crate::audit::{AuditEntry, AuditEventType, SecurityLevel, EventOutcome, AuditQuery};
use crate::error::{FortressError, Result};

/// Analysis engine for audit logs
pub struct AuditAnalyzer {
    entries: Vec<AuditEntry>,
}

impl AuditAnalyzer {
    /// Create a new analyzer with the given audit entries
    pub fn new(entries: Vec<AuditEntry>) -> Self {
        Self { entries }
    }

    /// Detect security anomalies in the audit log
    pub fn detect_anomalies(&self) -> Result<Vec<SecurityAnomaly>> {
        let mut anomalies = Vec::new();

        // Detect brute force attempts
        anomalies.extend(self.detect_brute_force_attempts()?);

        // Detect privilege escalation attempts
        anomalies.extend(self.detect_privilege_escalation()?);

        // Detect unusual access patterns
        anomalies.extend(self.detect_unusual_access_patterns()?);

        // Detect mass data access
        anomalies.extend(self.detect_mass_data_access()?);

        // Detect configuration tampering
        anomalies.extend(self.detect_configuration_tampering()?);

        // Detect time-based anomalies
        anomalies.extend(self.detect_time_based_anomalies()?);

        Ok(anomalies)
    }

    /// Generate security insights from the audit log
    pub fn generate_insights(&self) -> Result<SecurityInsights> {
        let total_entries = self.entries.len();
        let mut entries_by_type = HashMap::new();
        let mut entries_by_level = HashMap::new();
        let mut entries_by_outcome = HashMap::new();
        let mut failed_auth_by_principal = HashMap::new();
        let mut top_resources = HashMap::new();
        let mut active_principals = HashSet::new();

        for entry in &self.entries {
            // Count by event type
            *entries_by_type.entry(entry.event_type.clone()).or_insert(0) += 1;

            // Count by security level
            *entries_by_level.entry(entry.security_level.clone()).or_insert(0) += 1;

            // Count by outcome
            *entries_by_outcome.entry(entry.outcome.clone()).or_insert(0) += 1;

            // Track failed authentications
            if entry.event_type == AuditEventType::Authentication && entry.outcome == EventOutcome::Failure {
                if let Some(principal) = &entry.principal {
                    *failed_auth_by_principal.entry(principal.clone()).or_insert(0) += 1;
                }
            }

            // Track resource access
            if let Some(resource) = &entry.resource {
                *top_resources.entry(resource.clone()).or_insert(0) += 1;
            }

            // Track active principals
            if let Some(principal) = &entry.principal {
                active_principals.insert(principal.clone());
            }
        }

        // Sort resources by access count
        let mut sorted_resources: Vec<_> = top_resources.into_iter().collect();
        sorted_resources.sort_by(|a, b| b.1.cmp(&a.1));
        let top_resources = sorted_resources.into_iter().take(10).collect();

        // Calculate time range
        let time_range = if !self.entries.is_empty() {
            let timestamps: Vec<u64> = self.entries.iter().map(|e| e.timestamp).collect();
            let min_time = *timestamps.iter().min().unwrap();
            let max_time = *timestamps.iter().max().unwrap();
            Some((min_time, max_time))
        } else {
            None
        };

        Ok(SecurityInsights {
            total_entries,
            entries_by_type,
            entries_by_level,
            entries_by_outcome,
            failed_auth_by_principal,
            top_resources,
            active_principals: active_principals.into_iter().collect(),
            time_range,
        })
    }

    /// Detect brute force authentication attempts
    fn detect_brute_force_attempts(&self) -> Result<Vec<SecurityAnomaly>> {
        let mut anomalies = Vec::new();
        let mut auth_attempts_by_principal: HashMap<String, Vec<u64>> = HashMap::new();

        // Group authentication attempts by principal and timestamp
        for entry in &self.entries {
            if entry.event_type == AuditEventType::Authentication {
                if let Some(principal) = &entry.principal {
                    auth_attempts_by_principal
                        .entry(principal.clone())
                        .or_insert_with(Vec::new)
                        .push(entry.timestamp);
                }
            }
        }

        // Check for patterns indicating brute force
        for (principal, timestamps) in auth_attempts_by_principal {
            if timestamps.len() >= 10 {
                // Check if attempts occurred in a short time window
                let mut sorted_timestamps = timestamps.clone();
                sorted_timestamps.sort();

                for window in sorted_timestamps.windows(10) {
                    let time_span = window[9] - window[0];
                    if time_span < 300_000 { // 5 minutes in milliseconds
                        anomalies.push(SecurityAnomaly {
                            anomaly_type: AnomalyType::BruteForceAttack,
                            severity: SecurityLevel::High,
                            description: format!(
                                "Potential brute force attack detected for principal: {} (10 failed attempts in {} seconds)",
                                principal,
                                time_span / 1000
                            ),
                            timestamp: window[0],
                            principal: Some(principal.clone()),
                            resource: None,
                            metadata: {
                                let mut meta = HashMap::new();
                                meta.insert("attempt_count".to_string(), "10".to_string());
                                meta.insert("time_window_ms".to_string(), time_span.to_string());
                                meta
                            },
                        });
                        break;
                    }
                }
            }
        }

        Ok(anomalies)
    }

    /// Detect privilege escalation attempts
    fn detect_privilege_escalation(&self) -> Result<Vec<SecurityAnomaly>> {
        let mut anomalies = Vec::new();
        let mut role_changes_by_principal: HashMap<String, Vec<(u64, String, String)>> = HashMap::new();

        // Track role changes
        for entry in &self.entries {
            if entry.event_type == AuditEventType::Authorization {
                if let Some(principal) = &entry.principal {
                    if let Some(action) = Some(entry.action.clone()) {
                        if action.contains("role") || action.contains("permission") {
                        role_changes_by_principal
                            .entry(principal.clone())
                            .or_insert_with(Vec::new)
                            .push((entry.timestamp, action.clone(), format!("{:?}", entry.outcome)));
                        }
                    }
                }
            }
        }

        // Detect suspicious role change patterns
        for (principal, changes) in role_changes_by_principal {
            if changes.len() > 5 {
                anomalies.push(SecurityAnomaly {
                    anomaly_type: AnomalyType::PrivilegeEscalation,
                    severity: SecurityLevel::Critical,
                    description: format!(
                        "Excessive role/permission changes detected for principal: {} ({} changes)",
                        principal,
                        changes.len()
                    ),
                    timestamp: changes[0].0,
                    principal: Some(principal),
                    resource: None,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("change_count".to_string(), changes.len().to_string());
                        meta
                    },
                });
            }
        }

        Ok(anomalies)
    }

    /// Detect unusual access patterns
    fn detect_unusual_access_patterns(&self) -> Result<Vec<SecurityAnomaly>> {
        let mut anomalies = Vec::new();
        let mut access_by_principal: HashMap<String, HashMap<String, u64>> = HashMap::new();

        // Track resource access by principal
        for entry in &self.entries {
            if entry.event_type == AuditEventType::DataAccess {
                if let (Some(principal), Some(resource)) = (&entry.principal, &entry.resource) {
                    let principal_access = access_by_principal
                        .entry(principal.clone())
                        .or_insert_with(HashMap::new);
                    *principal_access.entry(resource.clone()).or_insert(0) += 1;
                }
            }
        }

        // Detect principals accessing unusual numbers of resources
        for (principal, resources) in access_by_principal {
            let total_resources = resources.len();
            if total_resources > 1000 {
                anomalies.push(SecurityAnomaly {
                    anomaly_type: AnomalyType::UnusualAccessPattern,
                    severity: SecurityLevel::Medium,
                    description: format!(
                        "Principal {} accessed {} different resources (potential data scraping)",
                        principal,
                        total_resources
                    ),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    principal: Some(principal),
                    resource: None,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("resource_count".to_string(), total_resources.to_string());
                        meta
                    },
                });
            }
        }

        Ok(anomalies)
    }

    /// Detect mass data access
    fn detect_mass_data_access(&self) -> Result<Vec<SecurityAnomaly>> {
        let mut anomalies = Vec::new();
        let mut access_events_by_time: HashMap<u64, u64> = HashMap::new();

        // Count access events by time window (1-minute buckets)
        for entry in &self.entries {
            if entry.event_type == AuditEventType::DataAccess && entry.outcome == EventOutcome::Success {
                let time_bucket = (entry.timestamp / 60_000) * 60_000; // Round to nearest minute
                *access_events_by_time.entry(time_bucket).or_insert(0) += 1;
            }
        }

        // Detect time windows with excessive access
        for (time_bucket, count) in access_events_by_time {
            if count > 10000 {
                anomalies.push(SecurityAnomaly {
                    anomaly_type: AnomalyType::MassDataAccess,
                    severity: SecurityLevel::High,
                    description: format!(
                        "Mass data access detected: {} access events in 1-minute window",
                        count
                    ),
                    timestamp: time_bucket,
                    principal: None,
                    resource: None,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("access_count".to_string(), count.to_string());
                        meta
                    },
                });
            }
        }

        Ok(anomalies)
    }

    /// Detect configuration tampering
    fn detect_configuration_tampering(&self) -> Result<Vec<SecurityAnomaly>> {
        let mut anomalies = Vec::new();
        let mut config_changes_by_principal: HashMap<String, Vec<u64>> = HashMap::new();

        // Track configuration changes
        for entry in &self.entries {
            if entry.event_type == AuditEventType::ConfigurationChange {
                if let Some(principal) = &entry.principal {
                    config_changes_by_principal
                        .entry(principal.clone())
                        .or_insert_with(Vec::new)
                        .push(entry.timestamp);
                }
            }
        }

        // Detect excessive configuration changes
        for (principal, changes) in config_changes_by_principal {
            if changes.len() > 50 {
                anomalies.push(SecurityAnomaly {
                    anomaly_type: AnomalyType::ConfigurationTampering,
                    severity: SecurityLevel::Critical,
                    description: format!(
                        "Excessive configuration changes detected: {} changes by {}",
                        changes.len(),
                        principal
                    ),
                    timestamp: changes[0],
                    principal: Some(principal),
                    resource: None,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("change_count".to_string(), changes.len().to_string());
                        meta
                    },
                });
            }
        }

        Ok(anomalies)
    }

    /// Detect time-based anomalies
    fn detect_time_based_anomalies(&self) -> Result<Vec<SecurityAnomaly>> {
        let mut anomalies = Vec::new();
        
        // Group entries by hour of day
        let mut entries_by_hour: HashMap<u32, u64> = HashMap::new();
        
        for entry in &self.entries {
            let datetime = chrono::DateTime::from_timestamp(
                (entry.timestamp / 1000) as i64,
                ((entry.timestamp % 1000) * 1_000_000) as u32,
            ).unwrap();
            let hour = datetime.hour() as u32;
            *entries_by_hour.entry(hour).or_insert(0) += 1;
        }

        // Detect unusual activity during off-hours (e.g., 2 AM - 4 AM)
        let off_hours_total: u64 = (2..=4).map(|h| entries_by_hour.get(&h).unwrap_or(&0)).sum();
        let business_hours_total: u64 = (9..=17).map(|h| entries_by_hour.get(&h).unwrap_or(&0)).sum();
        
        if business_hours_total > 0 && off_hours_total as f64 / business_hours_total as f64 > 0.5 {
            anomalies.push(SecurityAnomaly {
                anomaly_type: AnomalyType::UnusualTimePattern,
                severity: SecurityLevel::Medium,
                description: format!(
                    "Unusual activity pattern detected: {} off-hours events vs {} business hours events",
                    off_hours_total,
                    business_hours_total
                ),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                principal: None,
                resource: None,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("off_hours_count".to_string(), off_hours_total.to_string());
                    meta.insert("business_hours_count".to_string(), business_hours_total.to_string());
                    meta
                },
            });
        }

        Ok(anomalies)
    }

    /// Search for specific patterns in the audit log
    pub fn search(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>> {
        let mut results = Vec::new();

        for entry in &self.entries {
            // Time range filter
            if let Some(start_time) = query.start_time {
                if entry.timestamp < start_time {
                    continue;
                }
            }
            if let Some(end_time) = query.end_time {
                if entry.timestamp > end_time {
                    continue;
                }
            }

            // Event type filter
            if let Some(event_types) = &query.event_types {
                if !event_types.contains(&entry.event_type) {
                    continue;
                }
            }

            // Security level filter
            if let Some(security_levels) = &query.security_levels {
                if !security_levels.contains(&entry.security_level) {
                    continue;
                }
            }

            // Principal filter
            if let Some(principal) = &query.principal {
                if entry.principal.as_ref().map_or(true, |p| !p.contains(principal)) {
                    continue;
                }
            }

            // Resource filter
            if let Some(resource) = &query.resource {
                if entry.resource.as_ref().map_or(true, |r| !r.contains(resource)) {
                    continue;
                }
            }

            // Action filter
            if let Some(action) = &query.action {
                if !entry.action.contains(action) {
                    continue;
                }
            }

            // Outcome filter
            if let Some(outcome) = &query.outcome {
                if &entry.outcome != outcome {
                    continue;
                }
            }

            results.push(entry.clone());
        }

        // Apply limit and offset
        if let Some(offset) = query.offset {
            let offset = offset as usize;
            if offset < results.len() {
                results.drain(0..offset);
            } else {
                results.clear();
            }
        }

        if let Some(limit) = query.limit {
            let limit = limit as usize;
            if results.len() > limit {
                results.truncate(limit);
            }
        }

        Ok(results)
    }
}

/// Security anomaly detected in audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnomaly {
    /// Type of anomaly
    pub anomaly_type: AnomalyType,
    /// Severity level
    pub severity: SecurityLevel,
    /// Description of the anomaly
    pub description: String,
    /// Timestamp when the anomaly was detected
    pub timestamp: u64,
    /// Principal involved (if applicable)
    pub principal: Option<String>,
    /// Resource involved (if applicable)
    pub resource: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of security anomalies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyType {
    /// Brute force authentication attack
    BruteForceAttack,
    /// Privilege escalation attempt
    PrivilegeEscalation,
    /// Unusual access pattern
    UnusualAccessPattern,
    /// Mass data access
    MassDataAccess,
    /// Configuration tampering
    ConfigurationTampering,
    /// Unusual time-based pattern
    UnusualTimePattern,
    /// Multiple failed operations
    MultipleFailures,
    /// Suspicious sequence of events
    SuspiciousSequence,
}

/// Security insights derived from audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInsights {
    /// Total number of audit entries
    pub total_entries: usize,
    /// Entries grouped by event type
    pub entries_by_type: HashMap<AuditEventType, usize>,
    /// Entries grouped by security level
    pub entries_by_level: HashMap<SecurityLevel, usize>,
    /// Entries grouped by outcome
    pub entries_by_outcome: HashMap<EventOutcome, usize>,
    /// Failed authentication attempts by principal
    pub failed_auth_by_principal: HashMap<String, usize>,
    /// Most accessed resources
    pub top_resources: Vec<(String, usize)>,
    /// Active principals
    pub active_principals: Vec<String>,
    /// Time range of the audit log
    pub time_range: Option<(u64, u64)>,
}

/// Report generator for audit analysis
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate a comprehensive security report
    pub fn generate_security_report(
        insights: &SecurityInsights,
        anomalies: &[SecurityAnomaly],
    ) -> Result<SecurityReport> {
        let risk_score = Self::calculate_risk_score(insights, anomalies);
        let recommendations = Self::generate_recommendations(insights, anomalies);

        Ok(SecurityReport {
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            insights: insights.clone(),
            anomalies: anomalies.to_vec(),
            risk_score,
            recommendations,
        })
    }

    /// Calculate overall risk score
    fn calculate_risk_score(insights: &SecurityInsights, anomalies: &[SecurityAnomaly]) -> f64 {
        let mut score = 0.0;

        // Base score from failed authentications
        let total_failed_auth: usize = insights.failed_auth_by_principal.values().sum();
        score += (total_failed_auth as f64) * 0.1;

        // Score from anomalies
        for anomaly in anomalies {
            match anomaly.severity {
                SecurityLevel::Low => score += 1.0,
                SecurityLevel::Medium => score += 5.0,
                SecurityLevel::High => score += 10.0,
                SecurityLevel::Critical => score += 25.0,
            }
        }

        // Normalize to 0-100 scale
        (score.min(100.0))
    }

    /// Generate security recommendations
    fn generate_recommendations(
        insights: &SecurityInsights,
        anomalies: &[SecurityAnomaly],
    ) -> Vec<SecurityRecommendation> {
        let mut recommendations = Vec::new();

        // Check for brute force attacks
        if anomalies.iter().any(|a| matches!(a.anomaly_type, AnomalyType::BruteForceAttack)) {
            recommendations.push(SecurityRecommendation {
                priority: SecurityLevel::High,
                category: "Authentication Security".to_string(),
                title: "Implement account lockout policy".to_string(),
                description: "Configure automatic account lockout after multiple failed authentication attempts to prevent brute force attacks.".to_string(),
            });
        }

        // Check for privilege escalation
        if anomalies.iter().any(|a| matches!(a.anomaly_type, AnomalyType::PrivilegeEscalation)) {
            recommendations.push(SecurityRecommendation {
                priority: SecurityLevel::Critical,
                category: "Access Control".to_string(),
                title: "Review role assignment procedures".to_string(),
                description: "Implement stricter controls and approval workflows for role and permission changes.".to_string(),
            });
        }

        // Check for unusual access patterns
        if anomalies.iter().any(|a| matches!(a.anomaly_type, AnomalyType::UnusualAccessPattern)) {
            recommendations.push(SecurityRecommendation {
                priority: SecurityLevel::Medium,
                category: "Data Access".to_string(),
                title: "Implement data access quotas".to_string(),
                description: "Set limits on the number of resources a principal can access within a time period to prevent data scraping.".to_string(),
            });
        }

        // Check for configuration tampering
        if anomalies.iter().any(|a| matches!(a.anomaly_type, AnomalyType::ConfigurationTampering)) {
            recommendations.push(SecurityRecommendation {
                priority: SecurityLevel::Critical,
                category: "Configuration Management".to_string(),
                title: "Implement configuration change approval".to_string(),
                description: "Require multi-person approval for configuration changes and maintain immutable configuration history.".to_string(),
            });
        }

        recommendations
    }
}

/// Comprehensive security report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// When the report was generated
    pub generated_at: u64,
    /// Security insights
    pub insights: SecurityInsights,
    /// Detected anomalies
    pub anomalies: Vec<SecurityAnomaly>,
    /// Overall risk score (0-100)
    pub risk_score: f64,
    /// Security recommendations
    pub recommendations: Vec<SecurityRecommendation>,
}

/// Security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    /// Priority level
    pub priority: SecurityLevel,
    /// Category of recommendation
    pub category: String,
    /// Title of recommendation
    pub title: String,
    /// Detailed description
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEntry, AuditEventType, SecurityLevel, EventOutcome};

    #[test]
    fn test_anomaly_detection() {
        let entries = vec![
            AuditEntry {
                id: "1".to_string(),
                timestamp: 1000,
                event_type: AuditEventType::Authentication,
                security_level: SecurityLevel::Medium,
                principal: Some("user1".to_string()),
                resource: None,
                action: "login".to_string(),
                outcome: EventOutcome::Failure,
                metadata: HashMap::new(),
                previous_hash: None,
                current_hash: "hash1".to_string(),
                signature: "sig1".to_string(),
            },
        ];

        let analyzer = AuditAnalyzer::new(entries);
        let anomalies = analyzer.detect_anomalies().unwrap();
        assert!(anomalies.is_empty()); // No anomalies with single entry
    }

    #[test]
    fn test_insights_generation() {
        let entries = vec![
            AuditEntry {
                id: "1".to_string(),
                timestamp: 1000,
                event_type: AuditEventType::Authentication,
                security_level: SecurityLevel::Medium,
                principal: Some("user1".to_string()),
                resource: None,
                action: "login".to_string(),
                outcome: EventOutcome::Success,
                metadata: HashMap::new(),
                previous_hash: None,
                current_hash: "hash1".to_string(),
                signature: "sig1".to_string(),
            },
        ];

        let analyzer = AuditAnalyzer::new(entries);
        let insights = analyzer.generate_insights().unwrap();
        assert_eq!(insights.total_entries, 1);
        assert_eq!(insights.active_principals.len(), 1);
    }
}
