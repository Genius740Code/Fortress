//! API versioning system with backward-compatible version management
//! 
//! Provides comprehensive version registry, deprecation management,
//! and migration helpers for API evolution.

use serde::{Serialize, Deserialize};
use async_graphql::{SimpleObject, Context, Result};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVersion {
    pub version: String,
    pub deprecated: bool,
    pub removal_date: Option<DateTime<Utc>>,
    pub supported_until: Option<DateTime<Utc>>,
    pub migration_guide: Option<String>,
    pub features: Vec<String>,
    pub breaking_changes: Vec<String>,
    pub compatibility_matrix: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub current: String,
    pub supported: Vec<ApiVersion>,
    pub deprecated: Vec<ApiVersion>,
    pub removed: Vec<ApiVersion>,
    pub migration_paths: Vec<MigrationPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPath {
    pub from_version: String,
    pub to_version: String,
    pub automated: bool,
    pub estimated_time_minutes: u32,
    pub complexity: MigrationComplexity,
    pub prerequisites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationComplexity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationWarning {
    pub message: String,
    pub removal_date: DateTime<Utc>,
    pub alternative: String,
    pub migration_guide: String,
    pub affected_endpoints: Vec<String>,
    pub breaking_changes: Vec<String>,
}

pub struct VersionRegistry {
    versions: HashMap<String, ApiVersion>,
    default_version: String,
    deprecation_manager: DeprecationManager,
}

impl VersionRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            versions: HashMap::new(),
            default_version: "v2".to_string(),
            deprecation_manager: DeprecationManager::new(),
        };
        
        // Register supported versions
        registry.register_version(ApiVersion {
            version: "v1".to_string(),
            deprecated: false,
            removal_date: None,
            supported_until: Some(DateTime::parse_from_rfc3339("2024-12-31T23:59:59Z").unwrap().with_timezone(&Utc)),
            migration_guide: Some("https://docs.fortress.security/migration/v1-to-v2".to_string()),
            features: vec![
                "basic_authentication".to_string(),
                "simple_encryption".to_string(),
                "basic_queries".to_string(),
                "file_operations".to_string(),
            ],
            breaking_changes: vec![],
            compatibility_matrix: HashMap::from([
                ("v1".to_string(), true),
                ("v2".to_string(), false),
            ]),
        });
        
        registry.register_version(ApiVersion {
            version: "v2".to_string(),
            deprecated: false,
            removal_date: None,
            supported_until: None,
            migration_guide: None,
            features: vec![
                "enhanced_authentication".to_string(),
                "field_level_encryption".to_string(),
                "advanced_queries".to_string(),
                "real_time_subscriptions".to_string(),
                "performance_monitoring".to_string(),
                "batch_operations".to_string(),
                "query_optimization".to_string(),
                "api_versioning".to_string(),
            ],
            breaking_changes: vec![
                "Authentication response format changed".to_string(),
                "Encryption key format updated".to_string(),
                "Query response structure enhanced".to_string(),
            ],
            compatibility_matrix: HashMap::from([
                ("v1".to_string(), true),
                ("v2".to_string(), true),
            ]),
        });
        
        registry.register_version(ApiVersion {
            version: "v3".to_string(),
            deprecated: false,
            removal_date: None,
            supported_until: None,
            migration_guide: Some("https://docs.fortress.security/migration/v2-to-v3".to_string()),
            features: vec![
                "all_v2_features".to_string(),
                "advanced_security".to_string(),
                "machine_learning_integration".to_string(),
                "quantum_resistant_cryptography".to_string(),
                "distributed_tracing".to_string(),
                "advanced_analytics".to_string(),
            ],
            breaking_changes: vec![
                "Security model updated with RBAC v2".to_string(),
                "Query syntax enhanced with new operators".to_string(),
                "Response format standardized across all endpoints".to_string(),
            ],
            compatibility_matrix: HashMap::from([
                ("v1".to_string(), false),
                ("v2".to_string(), true),
                ("v3".to_string(), true),
            ]),
        });
        
        // Register deprecated versions
        registry.register_version(ApiVersion {
            version: "v0".to_string(),
            deprecated: true,
            removal_date: Some(DateTime::parse_from_rfc3339("2023-06-30T23:59:59Z").unwrap().with_timezone(&Utc)),
            supported_until: Some(DateTime::parse_from_rfc3339("2023-12-31T23:59:59Z").unwrap().with_timezone(&Utc)),
            migration_guide: Some("https://docs.fortress.security/migration/v0-to-v1".to_string()),
            features: vec![
                "experimental_features".to_string(),
                "basic_operations".to_string(),
            ],
            breaking_changes: vec![
                "Complete API redesign".to_string(),
                "Authentication model changed".to_string(),
            ],
            compatibility_matrix: HashMap::from([
                ("v0".to_string(), true),
                ("v1".to_string(), false),
            ]),
        });
        
        registry
    }
    
    pub fn register_version(&mut self, version: ApiVersion) {
        self.versions.insert(version.version.clone(), version);
    }
    
    pub fn get_version(&self, version: &str) -> Option<&ApiVersion> {
        self.versions.get(version)
    }
    
    pub fn is_supported(&self, version: &str) -> bool {
        if let Some(api_version) = self.get_version(version) {
            !api_version.deprecated && api_version.removal_date.is_none()
        } else {
            false
        }
    }
    
    pub fn get_default_version(&self) -> &str {
        &self.default_version
    }
    
    pub fn list_supported_versions(&self) -> Vec<&ApiVersion> {
        self.versions.values()
            .filter(|v| !v.deprecated && v.removal_date.is_none())
            .collect()
    }
    
    pub fn list_deprecated_versions(&self) -> Vec<&ApiVersion> {
        self.versions.values()
            .filter(|v| v.deprecated)
            .collect()
    }
    
    pub fn list_removed_versions(&self) -> Vec<&ApiVersion> {
        self.versions.values()
            .filter(|v| v.removal_date.is_some() && v.removal_date <= Some(Utc::now()))
            .collect()
    }
    
    pub fn get_migration_path(&self, from: &str, to: &str) -> Option<MigrationPath> {
        // Check if direct migration is supported
        if let (Some(from_version), Some(to_version)) = (self.get_version(from), self.get_version(to)) {
            if let Some(&compatible) = from_version.compatibility_matrix.get(to) {
                if compatible {
                    return Some(MigrationPath {
                        from_version: from.to_string(),
                        to_version: to.to_string(),
                        automated: true,
                        estimated_time_minutes: self::estimate_migration_time(from, to),
                        complexity: self::calculate_migration_complexity(from, to),
                        prerequisites: self::get_migration_prerequisites(from, to),
                    });
                }
            }
        }
        
        // Check for multi-step migration
        self::find_multi_step_migration(from, to)
    }
    
    pub fn get_all_migration_paths(&self) -> Vec<MigrationPath> {
        let mut paths = Vec::new();
        let versions: Vec<String> = self.versions.keys().cloned().collect();
        
        for from in &versions {
            for to in &versions {
                if from != to {
                    if let Some(path) = self.get_migration_path(from, to) {
                        paths.push(path);
                    }
                }
            }
        }
        
        paths
    }
    
    fn estimate_migration_time(&self, from: &str, to: &str) -> u32 {
        let base_time = match (from, to) {
            ("v0", "v1") => 30,
            ("v1", "v2") => 60,
            ("v2", "v3") => 120,
            ("v1", "v3") => 180,
            _ => 90,
        };
        
        // Add complexity based on breaking changes
        if let Some(from_version) = self.get_version(from) {
            base_time + (from_version.breaking_changes.len() as u32 * 15)
        } else {
            base_time
        }
    }
    
    fn calculate_migration_complexity(&self, from: &str, to: &str) -> MigrationComplexity {
        let breaking_changes_count = self.get_version(from)
            .map(|v| v.breaking_changes.len())
            .unwrap_or(0);
        
        match breaking_changes_count {
            0 => MigrationComplexity::Low,
            1..=3 => MigrationComplexity::Medium,
            _ => MigrationComplexity::High,
        }
    }
    
    fn get_migration_prerequisites(&self, from: &str, to: &str) -> Vec<String> {
        let mut prerequisites = Vec::new();
        
        // Common prerequisites
        prerequisites.push("Create backup of current configuration".to_string());
        prerequisites.push("Review breaking changes documentation".to_string());
        
        // Version-specific prerequisites
        match (from, to) {
            ("v1", "v2") => {
                prerequisites.push("Update authentication tokens to new format".to_string());
                prerequisites.push("Migrate encryption keys to new format".to_string());
            },
            ("v2", "v3") => {
                prerequisites.push("Update RBAC permissions to v2 format".to_string());
                prerequisites.push("Review and update security policies".to_string());
            },
            ("v1", "v3") => {
                prerequisites.push("Complete v1 to v2 migration first".to_string());
                prerequisites.push("Then complete v2 to v3 migration".to_string());
            },
            _ => {}
        }
        
        prerequisites
    }
    
    fn find_multi_step_migration(&self, from: &str, to: &str) -> Option<MigrationPath> {
        // For simplicity, only support v1->v3 as multi-step
        if (from, to) == ("v1", "v3") {
            Some(MigrationPath {
                from_version: from.to_string(),
                to_version: to.to_string(),
                automated: false,
                estimated_time_minutes: 180,
                complexity: MigrationComplexity::High,
                prerequisites: vec![
                    "Complete v1 to v2 migration".to_string(),
                    "Complete v2 to v3 migration".to_string(),
                    "Verify all functionality after each step".to_string(),
                ],
            })
        } else {
            None
        }
    }
}

impl Default for VersionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Deprecation management
pub struct DeprecationManager {
    deprecations: HashMap<String, ApiDeprecation>,
}

#[derive(Debug, Clone)]
pub struct ApiDeprecation {
    pub deprecated_version: String,
    pub removal_date: DateTime<Utc>,
    pub alternative: String,
    pub migration_guide: String,
    pub warning_message: String,
    pub affected_endpoints: Vec<String>,
    pub breaking_changes: Vec<String>,
}

impl DeprecationManager {
    pub fn new() -> Self {
        let mut manager = Self {
            deprecations: HashMap::new(),
        };
        
        // Register deprecations
        manager.register_deprecation(ApiDeprecation {
            deprecated_version: "v1".to_string(),
            removal_date: DateTime::parse_from_rfc3339("2024-12-31T23:59:59Z").unwrap().with_timezone(&Utc),
            alternative: "v2".to_string(),
            migration_guide: "https://docs.fortress.security/migration/v1-to-v2".to_string(),
            warning_message: "API v1 is deprecated and will be removed on 2024-12-31. Please migrate to v2.".to_string(),
            affected_endpoints: vec![
                "/api/v1/auth/login".to_string(),
                "/api/v1/data/query".to_string(),
                "/api/v1/keys/generate".to_string(),
            ],
            breaking_changes: vec![
                "Authentication response format changed".to_string(),
                "Query response structure enhanced".to_string(),
            ],
        });
        
        manager.register_deprecation(ApiDeprecation {
            deprecated_version: "v0".to_string(),
            removal_date: DateTime::parse_from_rfc3339("2023-06-30T23:59:59Z").unwrap().with_timezone(&Utc),
            alternative: "v3".to_string(),
            migration_guide: "https://docs.fortress.security/migration/v0-to-v3".to_string(),
            warning_message: "API v0 is deprecated and was removed on 2023-06-30. Please migrate to v3.".to_string(),
            affected_endpoints: vec![
                "/api/v0/*".to_string(),
            ],
            breaking_changes: vec![
                "Complete API redesign".to_string(),
                "Authentication model changed".to_string(),
            ],
        });
        
        manager
    }
    
    pub fn register_deprecation(&mut self, deprecation: ApiDeprecation) {
        self.deprecations.insert(deprecation.deprecated_version.clone(), deprecation);
    }
    
    pub fn check_deprecation(&self, requested_version: &str) -> Option<DeprecationWarning> {
        if let Some(deprecation) = self.deprecations.get(requested_version) {
            Some(DeprecationWarning {
                message: deprecation.warning_message.clone(),
                removal_date: deprecation.removal_date,
                alternative: deprecation.alternative.clone(),
                migration_guide: deprecation.migration_guide.clone(),
                affected_endpoints: deprecation.affected_endpoints.clone(),
                breaking_changes: deprecation.breaking_changes.clone(),
            })
        } else {
            None
        }
    }
}

#[derive(SimpleObject)]
pub struct DeprecationWarning {
    pub message: String,
    pub removal_date: DateTime<Utc>,
    pub alternative: String,
    pub migration_guide: String,
    pub affected_endpoints: Vec<String>,
    pub breaking_changes: Vec<String>,
}

// Version-aware resolvers
pub struct VersionResolver;

#[Object]
impl VersionResolver {
    /// Get API version information
    async fn version_info(&self, ctx: &Context<'_>) -> Result<VersionInfo> {
        let version_registry = ctx.data::<Arc<VersionRegistry>>()
            .ok_or_else(|| async_graphql::Error::new("Version registry not available"))?;
        let deprecation_manager = ctx.data::<Arc<DeprecationManager>>()
            .ok_or_else(|| async_graphql::Error::new("Deprecation manager not available"))?;
        
        let supported = version_registry.list_supported_versions().cloned();
        let deprecated = version_registry.list_deprecated_versions().cloned();
        let removed = version_registry.list_removed_versions().cloned();
        let migration_paths = version_registry.get_all_migration_paths();
        
        Ok(VersionInfo {
            current: version_registry.get_default_version().to_string(),
            supported,
            deprecated,
            removed,
            migration_paths,
        })
    }
    
    /// Check if a specific version is supported
    async fn is_version_supported(
        &self, 
        ctx: &Context<'_>, 
        version: String
    ) -> Result<bool> {
        let version_registry = ctx.data::<Arc<VersionRegistry>>()
            .ok_or_else(|| async_graphql::Error::new("Version registry not available"))?;
        Ok(version_registry.is_supported(&version))
    }
    
    /// Get deprecation warnings for a version
    async fn deprecation_warnings(
        &self, 
        ctx: &Context<'_>, 
        version: String
    ) -> Result<Option<DeprecationWarning>> {
        let deprecation_manager = ctx.data::<Arc<DeprecationManager>>()
            .ok_or_else(|| async_graphql::Error::new("Deprecation manager not available"))?;
        Ok(deprecation_manager.check_deprecation(&version))
    }
    
    /// Get available migration paths
    async fn migration_paths(&self, ctx: &Context<'_>) -> Result<Vec<MigrationPath>> {
        let version_registry = ctx.data::<Arc<VersionRegistry>>()
            .ok_or_else(|| async_graphql::Error::new("Version registry not available"))?;
        Ok(version_registry.get_all_migration_paths())
    }
    
    /// Get migration path between specific versions
    async fn migration_path(
        &self, 
        ctx: &Context<'_>,
        from_version: String,
        to_version: String
    ) -> Result<Option<MigrationPath>> {
        let version_registry = ctx.data::<Arc<VersionRegistry>>()
            .ok_or_else(|| async_graphql::Error::new("Version registry not available"))?;
        Ok(version_registry.get_migration_path(&from_version, &to_version))
    }
}

// Migration helpers
pub struct MigrationResolver;

#[Object]
impl MigrationResolver {
    /// Generate migration script from v1 to v2
    async fn generate_migration_script(
        &self,
        ctx: &Context<'_>,
        from_version: String,
        to_version: String
    ) -> Result<MigrationScript> {
        let version_registry = ctx.data::<Arc<VersionRegistry>>()
            .ok_or_else(|| async_graphql::Error::new("Version registry not available"))?;
        
        // Validate versions
        if !version_registry.is_supported(&to_version) {
            return Err(async_graphql::Error::new(format!("Target version {} is not supported", to_version)));
        }
        
        let script = match (from_version.as_str(), to_version.as_str()) {
            ("v1", "v2") => MigrationScript {
                from_version: from_version.clone(),
                to_version: to_version.clone(),
                steps: vec![
                    MigrationStep {
                        description: "Update authentication system to enhanced format".to_string(),
                        code: r#"
# Old authentication
mutation Login($email: String!, $password: String!) {
  login(email: $email, password: $password) {
    token
    user {
      id
      name
    }
  }
}

# New authentication
mutation Login($email: String!, $password: String!) {
  login(email: $email, password: $password) {
    token
    refreshToken
    expiresAt
    user {
      id
      name
      permissions
    }
  }
}"#.to_string(),
                        breaking_change: true,
                    },
                    MigrationStep {
                        description: "Update query responses to enhanced format".to_string(),
                        code: r#"
# Old query format
query GetUser($id: ID!) {
  user(id: $id) {
    id
    name
    email
    createdAt
  }
}

# New query format
query GetUser($id: ID!) {
  user(id: $id) {
    id
    name
    email
    profile {
      bio
      avatarUrl
    }
    createdAt
    updatedAt
    lastLogin
    permissions
  }
}"#.to_string(),
                        breaking_change: true,
                    },
                    MigrationStep {
                        description: "Update encryption key format to new standard".to_string(),
                        code: r#"
# Old key format
{
  "algorithm": "aes256",
  "key": "base64_encoded_key",
  "iv": "base64_encoded_iv"
}

# New key format
{
  "algorithm": "aes256gcm",
  "key": "base64_encoded_key",
  "nonce": "base64_encoded_nonce",
  "version": "v2",
  "metadata": {
    "created_at": "2024-01-01T00:00:00Z",
    "rotation_policy": "90_days"
  }
}"#.to_string(),
                        breaking_change: true,
                    },
                ],
                estimated_time: std::time::Duration::from_secs(3600), // 1 hour
                complexity: MigrationComplexity::Medium,
            },
            ("v2", "v3") => MigrationScript {
                from_version: from_version.clone(),
                to_version: to_version.clone(),
                steps: vec![
                    MigrationStep {
                        description: "Update RBAC system to v2 format".to_string(),
                        code: r#"
# Old RBAC format
{
  "user_id": "user123",
  "roles": ["admin", "user"],
  "permissions": ["read", "write"]
}

# New RBAC format
{
  "user_id": "user123",
  "roles": [{
    "name": "admin",
    "permissions": ["system.*"],
    "scope": "global",
    "conditions": {
      "ip_whitelist": ["192.168.1.0/24"],
      "time_restrictions": {
        "start": "09:00",
        "end": "17:00"
      }
    }
  }],
  "permissions": ["custom.permission"],
  "version": "v2"
}"#.to_string(),
                        breaking_change: true,
                    },
                    MigrationStep {
                        description: "Update query syntax with new operators".to_string(),
                        code: r#"
# Old query syntax
query GetUsers {
  users {
    id
    name
    email
  }
}

# New query syntax with enhanced operators
query GetUsers {
  users(
    where: {
      created_at: { gt: "2024-01-01" }
      status: { eq: "active" }
    }
    orderBy: { created_at: DESC }
    limit: 100
  ) {
    id
    name
    email
    profile {
      department
      role
    }
    metadata {
      last_login
      activity_score
    }
  }
}"#.to_string(),
                        breaking_change: false,
                    },
                ],
                estimated_time: std::time::Duration::from_secs(7200), // 2 hours
                complexity: MigrationComplexity::High,
            },
            ("v1", "v3") => MigrationScript {
                from_version: from_version.clone(),
                to_version: to_version.clone(),
                steps: vec![
                    MigrationStep {
                        description: "Step 1: Migrate from v1 to v2".to_string(),
                        code: "Follow the v1 to v2 migration guide first".to_string(),
                        breaking_change: true,
                    },
                    MigrationStep {
                        description: "Step 2: Migrate from v2 to v3".to_string(),
                        code: "Then follow the v2 to v3 migration guide".to_string(),
                        breaking_change: true,
                    },
                ],
                estimated_time: std::time::Duration::from_secs(10800), // 3 hours
                complexity: MigrationComplexity::High,
            },
            _ => return Err(async_graphql::Error::new("Migration path not supported")),
        };
        
        Ok(script)
    }
    
    /// Validate migration readiness
    async fn validate_migration_readiness(
        &self,
        ctx: &Context<'_>,
        from_version: String,
        to_version: String
    ) -> Result<MigrationReadiness> {
        let version_registry = ctx.data::<Arc<VersionRegistry>>()
            .ok_or_else(|| async_graphql::Error::new("Version registry not available"))?;
        
        let migration_path = version_registry.get_migration_path(&from_version, &to_version)
            .ok_or_else(|| async_graphql::Error::new("Migration path not found"))?;
        
        let checks = vec![
            ReadinessCheck {
                name: "Source version compatibility".to_string(),
                status: version_registry.is_supported(&from_version),
                message: if version_registry.is_supported(&from_version) {
                    "Source version is supported".to_string()
                } else {
                    "Source version is not supported".to_string()
                },
            },
            ReadinessCheck {
                name: "Target version availability".to_string(),
                status: version_registry.is_supported(&to_version),
                message: if version_registry.is_supported(&to_version) {
                    "Target version is supported".to_string()
                } else {
                    "Target version is not supported".to_string()
                },
            },
            ReadinessCheck {
                name: "Migration path exists".to_string(),
                status: true,
                message: "Migration path is available".to_string(),
            },
            ReadinessCheck {
                name: "Automated migration support".to_string(),
                status: migration_path.automated,
                message: if migration_path.automated {
                    "Migration can be automated".to_string()
                } else {
                    "Manual migration required".to_string()
                },
            },
        ];
        
        let overall_ready = checks.iter().all(|check| check.status);
        
        Ok(MigrationReadiness {
            from_version,
            to_version,
            ready: overall_ready,
            checks,
            estimated_time_minutes: migration_path.estimated_time_minutes,
            complexity: migration_path.complexity,
            prerequisites: migration_path.prerequisites,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct MigrationScript {
    pub from_version: String,
    pub to_version: String,
    pub steps: Vec<MigrationStep>,
    pub estimated_time: std::time::Duration,
    pub complexity: MigrationComplexity,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct MigrationStep {
    pub description: String,
    pub code: String,
    pub breaking_change: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct MigrationReadiness {
    pub from_version: String,
    pub to_version: String,
    pub ready: bool,
    pub checks: Vec<ReadinessCheck>,
    pub estimated_time_minutes: u32,
    pub complexity: MigrationComplexity,
    pub prerequisites: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct ReadinessCheck {
    pub name: String,
    pub status: bool,
    pub message: String,
}
