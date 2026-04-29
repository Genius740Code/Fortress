//! Compatibility Manager Module
//!
//! This module provides backward compatibility management for Fortress
//! serialization protocols with version negotiation and migration support.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};
use super::SerializationFormat;

/// Compatibility manager for version handling
pub struct CompatibilityManager {
    /// Compatibility level
    compatibility_level: CompatibilityLevel,
    /// Version registry
    version_registry: Arc<RwLock<HashMap<String, VersionInfo>>>,
    /// Migration rules
    migration_rules: Arc<RwLock<HashMap<(String, String), MigrationRule>>>,
    /// Compatibility metrics
    metrics: Arc<RwLock<CompatibilityMetrics>>,
    /// Current version
    current_version: String,
}

/// Compatibility levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompatibilityLevel {
    /// Strict compatibility (exact version match)
    Strict,
    /// Minor version compatibility
    Minor,
    /// Major version compatibility
    Major,
    /// No compatibility checking
    None,
}

/// Version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Version string
    pub version: String,
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version
    pub patch: u32,
    /// Pre-release identifier
    pub pre_release: Option<String>,
    /// Build metadata
    pub build_metadata: Option<String>,
    /// Supported formats
    pub supported_formats: Vec<SerializationFormat>,
    /// Breaking changes
    pub breaking_changes: Vec<String>,
    /// Deprecated features
    pub deprecated_features: Vec<String>,
    /// New features
    pub new_features: Vec<String>,
    /// Release date
    pub release_date: chrono::DateTime<chrono::Utc>,
    /// End of life date
    pub end_of_life_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// Migration rule for version transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRule {
    /// Source version
    pub from_version: String,
    /// Target version
    pub to_version: String,
    /// Migration type
    pub migration_type: MigrationType,
    /// Migration steps
    pub steps: Vec<MigrationStep>,
    /// Automatic migration enabled
    pub automatic: bool,
    /// Required for compatibility
    pub required: bool,
}

/// Migration types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MigrationType {
    /// Forward migration (older to newer)
    Forward,
    /// Backward migration (newer to older)
    Backward,
    /// Bidirectional migration
    Bidirectional,
}

/// Migration step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStep {
    /// Step name
    pub name: String,
    /// Step description
    pub description: String,
    /// Transformation function (placeholder)
    pub transformation: String,
    /// Field mappings
    pub field_mappings: HashMap<String, String>,
    /// Data type conversions
    pub type_conversions: HashMap<String, String>,
}

/// Compatibility metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityMetrics {
    /// Total compatibility checks
    pub total_checks: u64,
    /// Successful checks
    pub successful_checks: u64,
    /// Failed checks
    pub failed_checks: u64,
    /// Migrations performed
    pub migrations_performed: u64,
    /// Automatic migrations
    pub automatic_migrations: u64,
    /// Manual migrations
    pub manual_migrations: u64,
    /// Version distribution
    pub version_distribution: HashMap<String, u64>,
    /// Format compatibility matrix
    pub format_compatibility: HashMap<String, HashMap<String, f64>>,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Compatibility check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityResult {
    /// Is compatible
    pub compatible: bool,
    /// Compatibility score (0.0 to 1.0)
    pub score: f64,
    /// Compatibility level achieved
    pub level: CompatibilityLevel,
    /// Issues found
    pub issues: Vec<CompatibilityIssue>,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// Migration required
    pub migration_required: bool,
    /// Migration path
    pub migration_path: Option<Vec<String>>,
}

/// Compatibility issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityIssue {
    /// Issue severity
    pub severity: IssueSeverity,
    /// Issue type
    pub issue_type: IssueType,
    /// Description
    pub description: String,
    /// Affected component
    pub component: Option<String>,
    /// Suggested fix
    pub suggested_fix: Option<String>,
}

/// Issue severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssueSeverity {
    /// Informational
    Info,
    /// Warning
    Warning,
    /// Error
    Error,
    /// Critical
    Critical,
}

/// Issue types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssueType {
    /// Version mismatch
    VersionMismatch,
    /// Format not supported
    FormatNotSupported,
    /// Breaking change
    BreakingChange,
    /// Deprecated feature
    DeprecatedFeature,
    /// Type mismatch
    TypeMismatch,
    /// Field missing
    FieldMissing,
    /// Field renamed
    FieldRenamed,
}

impl CompatibilityManager {
    /// Create a new compatibility manager
    pub fn new(compatibility_level: CompatibilityLevel) -> Result<Self> {
        let mut manager = Self {
            compatibility_level,
            version_registry: Arc::new(RwLock::new(HashMap::new())),
            migration_rules: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(CompatibilityMetrics::default())),
            current_version: "1.0.0".to_string(),
        };

        // Initialize version registry
        manager.initialize_version_registry();
        
        Ok(manager)
    }

    /// Initialize version registry with known versions
    fn initialize_version_registry(&mut self) {
        let mut registry = self.version_registry.try_write().unwrap();
        
        // Current version
        registry.insert("1.0.0".to_string(), VersionInfo {
            version: "1.0.0".to_string(),
            major: 1,
            minor: 0,
            patch: 0,
            pre_release: None,
            build_metadata: None,
            supported_formats: vec![
                SerializationFormat::Binary,
                SerializationFormat::Json,
                SerializationFormat::Protobuf,
                SerializationFormat::MessagePack,
                SerializationFormat::Cbor,
            ],
            breaking_changes: vec![],
            deprecated_features: vec![],
            new_features: vec![
                "Binary protocol".to_string(),
                "Protocol negotiation".to_string(),
                "Compression".to_string(),
            ],
            release_date: chrono::Utc::now(),
            end_of_life_date: None,
        });

        // Previous version
        registry.insert("0.9.0".to_string(), VersionInfo {
            version: "0.9.0".to_string(),
            major: 0,
            minor: 9,
            patch: 0,
            pre_release: None,
            build_metadata: None,
            supported_formats: vec![
                SerializationFormat::Json,
                SerializationFormat::MessagePack,
            ],
            breaking_changes: vec![
                "Removed legacy XML format".to_string(),
            ],
            deprecated_features: vec![
                "Legacy field names".to_string(),
            ],
            new_features: vec![
                "MessagePack support".to_string(),
            ],
            release_date: chrono::Utc::now() - chrono::Duration::days(30),
            end_of_life_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
        });

        // Development version
        registry.insert("2.0.0-alpha".to_string(), VersionInfo {
            version: "2.0.0-alpha".to_string(),
            major: 2,
            minor: 0,
            patch: 0,
            pre_release: Some("alpha".to_string()),
            build_metadata: None,
            supported_formats: vec![
                SerializationFormat::Binary,
                SerializationFormat::Json,
                SerializationFormat::Protobuf,
                SerializationFormat::MessagePack,
                SerializationFormat::Cbor,
            ],
            breaking_changes: vec![
                "New binary protocol format".to_string(),
                "Changed field ordering".to_string(),
            ],
            deprecated_features: vec![
                "Legacy compression".to_string(),
            ],
            new_features: vec![
                "Quantum-resistant encryption".to_string(),
                "ML-based optimization".to_string(),
            ],
            release_date: chrono::Utc::now() + chrono::Duration::days(30),
            end_of_life_date: None,
        });
    }

    /// Check compatibility with a version
    pub async fn is_compatible(&self, version: &str) -> Result<bool> {
        let result = self.check_compatibility(version).await?;
        Ok(result.compatible)
    }

    /// Check detailed compatibility
    pub async fn check_compatibility(&self, version: &str) -> Result<CompatibilityResult> {
        let _start = std::time::Instant::now();
        
        let registry = self.version_registry.read().await;
        let version_info = registry.get(version).ok_or_else(|| {
            FortressError::serialization("Unknown version", &format!("Version {} not found", version))
        })?;

        let current_info = registry.get(&self.current_version).unwrap();

        let mut compatible = true;
        let mut score = 1.0;
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();
        let mut migration_required = false;

        // Check compatibility level
        match self.compatibility_level {
            CompatibilityLevel::Strict => {
                if version != self.current_version {
                    compatible = false;
                    score = 0.0;
                    issues.push(CompatibilityIssue {
                        severity: IssueSeverity::Error,
                        issue_type: IssueType::VersionMismatch,
                        description: format!("Version {} does not match current version {}", version, self.current_version),
                        component: None,
                        suggested_fix: Some(format!("Upgrade to version {}", self.current_version)),
                    });
                    recommendations.push(format!("Upgrade to version {}", self.current_version));
                    migration_required = true;
                }
            }
            CompatibilityLevel::Minor => {
                if version_info.major != current_info.major {
                    compatible = false;
                    score = 0.3;
                    issues.push(CompatibilityIssue {
                        severity: IssueSeverity::Error,
                        issue_type: IssueType::BreakingChange,
                        description: format!("Major version mismatch: {} vs {}", version_info.major, current_info.major),
                        component: None,
                        suggested_fix: Some(format!("Upgrade to version {}.x", current_info.major)),
                    });
                    recommendations.push(format!("Upgrade to version {}.x", current_info.major));
                    migration_required = true;
                } else if version_info.minor != current_info.minor {
                    score = 0.8;
                    issues.push(CompatibilityIssue {
                        severity: IssueSeverity::Warning,
                        issue_type: IssueType::VersionMismatch,
                        description: format!("Minor version mismatch: {} vs {}", version_info.minor, current_info.minor),
                        component: None,
                        suggested_fix: Some("Consider upgrading to latest minor version".to_string()),
                    });
                    recommendations.push("Consider upgrading to latest minor version".to_string());
                }
            }
            CompatibilityLevel::Major => {
                if version_info.major > current_info.major {
                    compatible = false;
                    score = 0.2;
                    issues.push(CompatibilityIssue {
                        severity: IssueSeverity::Error,
                        issue_type: IssueType::BreakingChange,
                        description: format!("Version {} is newer than current version {}", version, self.current_version),
                        component: None,
                        suggested_fix: Some("Upgrade Fortress to newer version".to_string()),
                    });
                    recommendations.push("Upgrade Fortress to newer version".to_string());
                } else if version_info.major < current_info.major {
                    score = 0.7;
                    issues.push(CompatibilityIssue {
                        severity: IssueSeverity::Warning,
                        issue_type: IssueType::VersionMismatch,
                        description: format!("Version {} is older than current version {}", version, self.current_version),
                        component: None,
                        suggested_fix: Some("Consider upgrading for new features".to_string()),
                    });
                    recommendations.push("Consider upgrading for new features".to_string());
                }
            }
            CompatibilityLevel::None => {
                // Always compatible
                score = 1.0;
            }
        }

        // Check format compatibility
        let mut format_score = 1.0;
        for format in &version_info.supported_formats {
            if !current_info.supported_formats.contains(format) {
                format_score -= 0.1;
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Warning,
                    issue_type: IssueType::FormatNotSupported,
                    description: format!("Format {:?} not supported in current version", format),
                    component: Some(format!("{:?}", format)),
                    suggested_fix: Some("Use supported format".to_string()),
                });
            }
        }
        score *= format_score;

        // Check breaking changes
        for breaking_change in &version_info.breaking_changes {
            if version_info.version > self.current_version {
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Error,
                    issue_type: IssueType::BreakingChange,
                    description: format!("Breaking change: {}", breaking_change),
                    component: None,
                    suggested_fix: Some("Upgrade Fortress".to_string()),
                });
                score -= 0.2;
                migration_required = true;
            }
        }

        // Check deprecated features
        for deprecated_feature in &version_info.deprecated_features {
            issues.push(CompatibilityIssue {
                severity: IssueSeverity::Warning,
                issue_type: IssueType::DeprecatedFeature,
                description: format!("Deprecated feature: {}", deprecated_feature),
                component: Some(deprecated_feature.clone()),
                suggested_fix: Some("Update to use new feature".to_string()),
            });
            score -= 0.05;
        }

        // Determine migration path
        let migration_path = if migration_required {
            self.find_migration_path(version, &self.current_version).await
        } else {
            None
        };

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_checks += 1;
            if compatible {
                metrics.successful_checks += 1;
            } else {
                metrics.failed_checks += 1;
            }
            *metrics.version_distribution.entry(version.to_string()).or_insert(0) += 1;
            metrics.last_updated = chrono::Utc::now();
        }

        Ok(CompatibilityResult {
            compatible,
            score,
            level: self.compatibility_level.clone(),
            issues,
            recommendations,
            migration_required,
            migration_path,
        })
    }

    /// Find migration path between versions
    async fn find_migration_path(&self, from_version: &str, to_version: &str) -> Option<Vec<String>> {
        let migration_rules = self.migration_rules.read().await;
        
        // Simple pathfinding - in a real implementation, this would be more sophisticated
        let mut path = Vec::new();
        let mut current = from_version.to_string();
        
        while current != to_version {
            let mut found_next = false;
            
            // Look for direct migration rule
            for ((from, to), _rule) in migration_rules.iter() {
                if from == &current && self.can_migrate_to(to, to_version) {
                    path.push(to.clone());
                    current = to.clone();
                    found_next = true;
                    break;
                }
            }
            
            if !found_next {
                return None; // No path found
            }
        }
        
        Some(path)
    }

    /// Check if we can migrate to a target version
    fn can_migrate_to(&self, current: &str, target: &str) -> bool {
        // Simple version comparison
        if let (Ok(current_ver), Ok(target_ver)) = (self.parse_version(current), self.parse_version(target)) {
            current_ver <= target_ver
        } else {
            false
        }
    }

    /// Parse version string into comparable tuple
    fn parse_version(&self, version: &str) -> Result<(u32, u32, u32)> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() >= 3 {
            let major = parts[0].parse::<u32>()
                .map_err(|_| FortressError::serialization("Invalid version", "Cannot parse major version"))?;
            let minor = parts[1].parse::<u32>()
                .map_err(|_| FortressError::serialization("Invalid version", "Cannot parse minor version"))?;
            let patch = parts[2].split('-').next().unwrap_or(&parts[2]).parse::<u32>()
                .map_err(|_| FortressError::serialization("Invalid version", "Cannot parse patch version"))?;
            Ok((major, minor, patch))
        } else {
            Err(FortressError::serialization("Invalid version format", "Expected x.y.z format"))
        }
    }

    /// Register a new version
    pub async fn register_version(&self, version_info: VersionInfo) -> Result<()> {
        let mut registry = self.version_registry.write().await;
        registry.insert(version_info.version.clone(), version_info);
        Ok(())
    }

    /// Add migration rule
    pub async fn add_migration_rule(&self, rule: MigrationRule) -> Result<()> {
        let mut rules = self.migration_rules.write().await;
        rules.insert((rule.from_version.clone(), rule.to_version.clone()), rule);
        Ok(())
    }

    /// Get supported versions
    pub async fn get_supported_versions(&self) -> Result<Vec<String>> {
        let registry = self.version_registry.read().await;
        Ok(registry.keys().cloned().collect())
    }

    /// Get version information
    pub async fn get_version_info(&self, version: &str) -> Result<Option<VersionInfo>> {
        let registry = self.version_registry.read().await;
        Ok(registry.get(version).cloned())
    }

    /// Get compatibility metrics
    pub async fn get_metrics(&self) -> Result<CompatibilityMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Set compatibility level
    pub fn set_compatibility_level(&mut self, level: CompatibilityLevel) {
        self.compatibility_level = level;
    }

    /// Set current version
    pub fn set_current_version(&mut self, version: String) {
        self.current_version = version;
    }

    /// Generate compatibility report
    pub async fn generate_compatibility_report(&self) -> Result<CompatibilityReport> {
        let registry = self.version_registry.read().await;
        let metrics = self.metrics.read().await;
        
        let mut version_summaries = Vec::new();
        for (version, info) in registry.iter() {
            let compatibility_result = self.check_compatibility(version).await?;
            
            version_summaries.push(VersionSummary {
                version: version.clone(),
                compatible: compatibility_result.compatible,
                score: compatibility_result.score,
                issues_count: compatibility_result.issues.len(),
                supported_formats: info.supported_formats.clone(),
                release_date: info.release_date,
                end_of_life_date: info.end_of_life_date,
            });
        }

        Ok(CompatibilityReport {
            current_version: self.current_version.clone(),
            compatibility_level: self.compatibility_level.clone(),
            total_versions: registry.len(),
            compatible_versions: version_summaries.iter().filter(|v| v.compatible).count(),
            version_summaries,
            metrics: metrics.clone(),
            generated_at: chrono::Utc::now(),
        })
    }

    /// Cleanup old versions
    pub async fn cleanup_old_versions(&self, max_age_days: u64) -> Result<usize> {
        let mut registry = self.version_registry.write().await;
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(max_age_days as i64);
        
        let mut removed = 0;
        registry.retain(|version, info| {
            let keep = info.end_of_life_date.map(|eol| eol > cutoff_date).unwrap_or(true) 
                || version == &self.current_version;
            if !keep {
                removed += 1;
            }
            keep
        });

        Ok(removed)
    }
}

/// Version summary for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionSummary {
    /// Version string
    pub version: String,
    /// Is compatible
    pub compatible: bool,
    /// Compatibility score
    pub score: f64,
    /// Number of issues
    pub issues_count: usize,
    /// Supported formats
    pub supported_formats: Vec<SerializationFormat>,
    /// Release date
    pub release_date: chrono::DateTime<chrono::Utc>,
    /// End of life date
    pub end_of_life_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// Compatibility report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityReport {
    /// Current version
    pub current_version: String,
    /// Compatibility level
    pub compatibility_level: CompatibilityLevel,
    /// Total versions
    pub total_versions: usize,
    /// Compatible versions
    pub compatible_versions: usize,
    /// Version summaries
    pub version_summaries: Vec<VersionSummary>,
    /// Metrics
    pub metrics: CompatibilityMetrics,
    /// Report generation time
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

impl Default for CompatibilityMetrics {
    fn default() -> Self {
        Self {
            total_checks: 0,
            successful_checks: 0,
            failed_checks: 0,
            migrations_performed: 0,
            automatic_migrations: 0,
            manual_migrations: 0,
            version_distribution: HashMap::new(),
            format_compatibility: HashMap::new(),
            last_updated: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compatibility_manager() {
        let manager = CompatibilityManager::new(CompatibilityLevel::Minor).unwrap();
        
        // Test compatibility check
        let compatible = manager.is_compatible("1.0.0").await.unwrap();
        assert!(compatible);
        
        let compatible = manager.is_compatible("0.9.0").await.unwrap();
        assert!(compatible);
        
        let compatible = manager.is_compatible("2.0.0-alpha").await.unwrap();
        assert!(!compatible); // Major version mismatch
    }

    #[tokio::test]
    async fn test_detailed_compatibility() {
        let manager = CompatibilityManager::new(CompatibilityLevel::Minor).unwrap();
        
        let result = manager.check_compatibility("0.9.0").await.unwrap();
        assert!(result.compatible);
        assert!(result.score > 0.5);
        assert!(!result.issues.is_empty()); // Should have some warnings
    }

    #[tokio::test]
    async fn test_version_registration() {
        let manager = CompatibilityManager::new(CompatibilityLevel::None).unwrap();
        
        let new_version = VersionInfo {
            version: "1.1.0".to_string(),
            major: 1,
            minor: 1,
            patch: 0,
            pre_release: None,
            build_metadata: None,
            supported_formats: vec![SerializationFormat::Binary],
            breaking_changes: vec![],
            deprecated_features: vec![],
            new_features: vec!["New feature".to_string()],
            release_date: chrono::Utc::now(),
            end_of_life_date: None,
        };
        
        manager.register_version(new_version).await.unwrap();
        
        let compatible = manager.is_compatible("1.1.0").await.unwrap();
        assert!(compatible);
    }

    #[tokio::test]
    async fn test_compatibility_report() {
        let manager = CompatibilityManager::new(CompatibilityLevel::Minor).unwrap();
        
        let report = manager.generate_compatibility_report().await.unwrap();
        assert!(!report.version_summaries.is_empty());
        assert_eq!(report.current_version, "1.0.0");
    }
}
