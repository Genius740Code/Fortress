//! Token types and structures
//!
//! This module defines the core types used throughout the token management system.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Token type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TokenType {
    /// Service token (long-lived, for backend services)
    Service,
    /// User token (interactive user sessions)
    User,
    /// Batch token (for automated processes)
    Batch,
    /// Emergency token (for disaster recovery)
    Emergency,
    /// Recovery token (for system recovery)
    Recovery,
}

/// Token role for authorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TokenRole {
    /// Root administrator
    Root,
    /// Standard administrator
    Admin,
    /// Operator with limited privileges
    Operator,
    /// Auditor (read-only access)
    Auditor,
    /// Anonymous user
    Anonymous,
    /// Custom role
    Custom(String),
}

/// Core token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Unique token identifier
    pub id: String,
    /// Accessor identifier for logging
    pub accessor: String,
    /// Token type
    pub token_type: TokenType,
    /// Token role
    pub role: TokenRole,
    /// Associated policies
    pub policies: Vec<String>,
    /// Token time-to-live
    pub ttl: Duration,
    /// Whether token is renewable
    pub renewable: bool,
    /// Maximum number of renewals allowed
    pub max_renewals: Option<u32>,
    /// Current renewal count
    pub renewal_count: u32,
    /// Allowed path suffixes
    pub path_suffixes: Vec<String>,
    /// Token creation timestamp
    pub created_time: DateTime<Utc>,
    /// Last renewal timestamp
    pub last_renewal: Option<DateTime<Utc>>,
    /// Token expiration timestamp
    pub expires_time: DateTime<Utc>,
    /// Parent token ID (for child tokens)
    pub parent_token: Option<String>,
    /// Entity ID this token belongs to
    pub entity_id: String,
    /// Token metadata
    pub metadata: HashMap<String, String>,
    /// IP address restrictions
    pub ip_restrictions: Vec<String>,
    /// User agent restrictions
    pub user_agent_restrictions: Vec<String>,
}

impl Token {
    /// Create a new token
    pub fn new(
        token_type: TokenType,
        role: TokenRole,
        policies: Vec<String>,
        ttl: Duration,
        entity_id: String,
    ) -> Self {
        let now = Utc::now();
        let token_id = Uuid::new_v4().to_string();
        let accessor = format!("s.{}", Uuid::new_v4());

        Self {
            id: token_id.clone(),
            accessor,
            token_type,
            role,
            policies,
            ttl,
            renewable: true,
            max_renewals: Some(10),
            renewal_count: 0,
            path_suffixes: Vec::new(),
            created_time: now,
            last_renewal: None,
            expires_time: now + ttl,
            parent_token: None,
            entity_id,
            metadata: HashMap::new(),
            ip_restrictions: Vec::new(),
            user_agent_restrictions: Vec::new(),
        }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_time
    }

    /// Check if token is renewable
    pub fn is_renewable(&self) -> bool {
        if !self.renewable {
            return false;
        }

        if let Some(max_renewals) = self.max_renewals {
            self.renewal_count < max_renewals
        } else {
            true
        }
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        let now = Utc::now();
        if now > self.expires_time {
            Duration::zero()
        } else {
            self.expires_time - now
        }
    }

    /// Check if token has specific policy
    pub fn has_policy(&self, policy: &str) -> bool {
        self.policies.contains(&policy.to_string())
    }

    /// Check if token has specific role
    pub fn has_role(&self, role: &TokenRole) -> bool {
        &self.role == role
    }

    /// Add metadata to token
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Add IP restriction
    pub fn add_ip_restriction(&mut self, ip: String) {
        self.ip_restrictions.push(ip);
    }

    /// Check if IP is allowed
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.ip_restrictions.is_empty() {
            return true;
        }

        self.ip_restrictions.contains(&ip.to_string())
    }

    /// Add user agent restriction
    pub fn add_user_agent_restriction(&mut self, user_agent: String) {
        self.user_agent_restrictions.push(user_agent);
    }

    /// Check if user agent is allowed
    pub fn is_user_agent_allowed(&self, user_agent: &str) -> bool {
        if self.user_agent_restrictions.is_empty() {
            return true;
        }

        self.user_agent_restrictions
            .iter()
            .any(|ua| user_agent.contains(ua))
    }
}

/// Extended token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// The token itself
    pub token: Token,
    /// Token display name
    pub display_name: String,
    /// Token description
    pub description: Option<String>,
    /// Token usage statistics
    pub usage_stats: TokenUsageStats,
    /// Token creation context
    pub creation_context: TokenCreationContext,
}

/// Token usage statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsageStats {
    /// Number of times token was used
    pub usage_count: u64,
    /// Last usage timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Number of failed authentications
    pub failed_auth_count: u64,
    /// Last failed authentication timestamp
    pub last_failed_auth: Option<DateTime<Utc>>,
    /// Average requests per hour
    pub avg_requests_per_hour: f64,
    /// Peak usage hour
    pub peak_usage_hour: Option<u32>,
}

/// Token creation context
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenCreationContext {
    /// Who created this token
    pub created_by: String,
    /// Method used to create token
    pub creation_method: String,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Request ID that created this token
    pub request_id: Option<String>,
}

/// Request to create a new token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    /// Token type
    pub token_type: TokenType,
    /// Token role
    pub role: TokenRole,
    /// Associated policies
    pub policies: Vec<String>,
    /// Token time-to-live
    pub ttl: Duration,
    /// Whether token is renewable
    pub renewable: bool,
    /// Maximum number of renewals
    pub max_renewals: Option<u32>,
    /// Path suffixes
    pub path_suffixes: Option<Vec<String>>,
    /// Parent token ID
    pub parent_token: Option<String>,
    /// Entity ID
    pub entity_id: String,
    /// Token metadata
    pub metadata: Option<HashMap<String, String>>,
    /// IP restrictions
    pub ip_restrictions: Option<Vec<String>>,
    /// User agent restrictions
    pub user_agent_restrictions: Option<Vec<String>>,
    /// Display name
    pub display_name: Option<String>,
    /// Description
    pub description: Option<String>,
}

impl Default for CreateTokenRequest {
    fn default() -> Self {
        Self {
            token_type: TokenType::User,
            role: TokenRole::Anonymous,
            policies: Vec::new(),
            ttl: Duration::hours(1),
            renewable: true,
            max_renewals: Some(10),
            path_suffixes: None,
            parent_token: None,
            entity_id: String::new(),
            metadata: None,
            ip_restrictions: None,
            user_agent_restrictions: None,
            display_name: None,
            description: None,
        }
    }
}

/// Request to renew a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewTokenRequest {
    /// Token ID to renew
    pub token_id: String,
    /// TTL increment
    pub increment: Duration,
    /// Requester token ID
    pub requester_token: String,
}

/// Request to revoke a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeTokenRequest {
    /// Token ID to revoke
    pub token_id: String,
    /// Revocation reason
    pub reason: String,
    /// Requester token ID
    pub requester_token: String,
    /// Force revocation (ignore restrictions)
    pub force: bool,
}

/// Token validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidationResult {
    /// Whether validation passed
    pub valid: bool,
    /// Token information if valid
    pub token_info: Option<TokenInfo>,
    /// Validation errors
    pub errors: Vec<String>,
    /// Warnings
    pub warnings: Vec<String>,
    /// Validation timestamp
    pub validated_at: DateTime<Utc>,
}

/// Token lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLookupResult {
    /// Whether token was found
    pub found: bool,
    /// Token information if found
    pub token_info: Option<TokenInfo>,
    /// Lookup timestamp
    pub looked_up_at: DateTime<Utc>,
}

/// Token metadata for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// Token ID
    pub token_id: String,
    /// Token type
    pub token_type: TokenType,
    /// Entity ID
    pub entity_id: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Storage backend
    pub storage_backend: String,
    /// Additional metadata
    pub custom_metadata: HashMap<String, String>,
}

impl TokenMetadata {
    /// Create new token metadata
    pub fn new(
        token_id: String,
        token_type: TokenType,
        entity_id: String,
        storage_backend: String,
    ) -> Self {
        let now = Utc::now();

        Self {
            token_id,
            token_type,
            entity_id,
            created_at: now,
            updated_at: now,
            storage_backend,
            custom_metadata: HashMap::new(),
        }
    }

    /// Update the updated timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Add custom metadata
    pub fn add_custom_metadata(&mut self, key: String, value: String) {
        self.custom_metadata.insert(key, value);
        self.touch();
    }

    /// Get custom metadata
    pub fn get_custom_metadata(&self, key: &str) -> Option<&String> {
        self.custom_metadata.get(key)
    }
}

/// Token search criteria
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenSearchCriteria {
    /// Token type filter
    pub token_type: Option<TokenType>,
    /// Token role filter
    pub role: Option<TokenRole>,
    /// Entity ID filter
    pub entity_id: Option<String>,
    /// Policy filter (tokens must have this policy)
    pub has_policy: Option<String>,
    /// Created after timestamp
    pub created_after: Option<DateTime<Utc>>,
    /// Created before timestamp
    pub created_before: Option<DateTime<Utc>>,
    /// Expires after timestamp
    pub expires_after: Option<DateTime<Utc>>,
    /// Expires before timestamp
    pub expires_before: Option<DateTime<Utc>>,
    /// Only renewable tokens
    pub renewable_only: Option<bool>,
    /// Only expired tokens
    pub expired_only: Option<bool>,
    /// IP address filter
    pub ip_restriction: Option<String>,
    /// Metadata filter
    pub metadata_filter: Option<HashMap<String, String>>,
    /// Limit results
    pub limit: Option<u32>,
    /// Offset for pagination
    pub offset: Option<u32>,
}

/// Token search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSearchResults {
    /// Matching tokens
    pub tokens: Vec<TokenInfo>,
    /// Total number of matches
    pub total_count: u64,
    /// Search criteria used
    pub criteria: TokenSearchCriteria,
    /// Search timestamp
    pub searched_at: DateTime<Utc>,
}

impl TokenSearchResults {
    /// Create new search results
    pub fn new(tokens: Vec<TokenInfo>, criteria: TokenSearchCriteria, total_count: u64) -> Self {
        Self {
            tokens,
            total_count,
            criteria,
            searched_at: Utc::now(),
        }
    }

    /// Check if there are more results
    pub fn has_more(&self) -> bool {
        if let Some(limit) = self.criteria.limit {
            (self.tokens.len() as u64) < self.total_count && (self.tokens.len() as u32) < limit
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation() {
        let token = Token::new(
            TokenType::User,
            TokenRole::Admin,
            vec!["default".to_string()],
            Duration::hours(1),
            "user123".to_string(),
        );

        assert!(!token.is_expired());
        assert!(token.is_renewable());
        assert!(token.has_policy("default"));
        assert!(token.has_role(&TokenRole::Admin));
        assert_eq!(token.renewal_count, 0);
    }

    #[test]
    fn test_token_expiration() {
        let mut token = Token::new(
            TokenType::Service,
            TokenRole::Operator,
            vec![],
            Duration::seconds(1),
            "service1".to_string(),
        );

        assert!(!token.is_expired());

        // Manually set expiration to past
        token.expires_time = Utc::now() - Duration::seconds(1);
        assert!(token.is_expired());
    }

    #[test]
    fn test_token_renewal_limits() {
        let mut token = Token::new(
            TokenType::Batch,
            TokenRole::Operator,
            vec![],
            Duration::hours(24),
            "batch1".to_string(),
        );

        token.max_renewals = Some(2);

        assert!(token.is_renewable());

        token.renewal_count = 2;
        assert!(!token.is_renewable());
    }

    #[test]
    fn test_token_restrictions() {
        let mut token = Token::new(
            TokenType::User,
            TokenRole::Admin,
            vec![],
            Duration::hours(1),
            "user123".to_string(),
        );

        // No restrictions initially
        assert!(token.is_ip_allowed("192.168.1.1"));
        assert!(token.is_user_agent_allowed("Mozilla/5.0"));

        // Add restrictions
        token.add_ip_restriction("192.168.1.1".to_string());
        token.add_user_agent_restriction("Mozilla".to_string());

        assert!(token.is_ip_allowed("192.168.1.1"));
        assert!(!token.is_ip_allowed("10.0.0.1"));
        assert!(token.is_user_agent_allowed("Mozilla/5.0"));
        assert!(!token.is_user_agent_allowed("curl/7.68.0"));
    }

    #[test]
    fn test_token_metadata() {
        let mut token = Token::new(
            TokenType::Service,
            TokenRole::Admin,
            vec![],
            Duration::hours(24),
            "service1".to_string(),
        );

        token.add_metadata("department".to_string(), "engineering".to_string());
        token.add_metadata("environment".to_string(), "production".to_string());

        assert_eq!(
            token.get_metadata("department"),
            Some(&"engineering".to_string())
        );
        assert_eq!(
            token.get_metadata("environment"),
            Some(&"production".to_string())
        );
        assert_eq!(token.get_metadata("nonexistent"), None);
    }

    #[test]
    fn test_create_token_request_default() {
        let request = CreateTokenRequest::default();

        assert_eq!(request.token_type, TokenType::User);
        assert_eq!(request.role, TokenRole::Anonymous);
        assert_eq!(request.ttl, Duration::hours(1));
        assert!(request.renewable);
        assert_eq!(request.max_renewals, Some(10));
    }

    #[test]
    fn test_token_metadata_operations() {
        let mut metadata = TokenMetadata::new(
            "token123".to_string(),
            TokenType::User,
            "user123".to_string(),
            "memory".to_string(),
        );

        metadata.add_custom_metadata("key1".to_string(), "value1".to_string());
        metadata.add_custom_metadata("key2".to_string(), "value2".to_string());

        assert_eq!(
            metadata.get_custom_metadata("key1"),
            Some(&"value1".to_string())
        );
        assert_eq!(
            metadata.get_custom_metadata("key2"),
            Some(&"value2".to_string())
        );

        let initial_updated = metadata.updated_at;
        metadata.add_custom_metadata("key3".to_string(), "value3".to_string());
        assert!(metadata.updated_at > initial_updated);
    }

    #[test]
    fn test_token_search_criteria() {
        let criteria = TokenSearchCriteria {
            token_type: Some(TokenType::Service),
            role: Some(TokenRole::Admin),
            renewable_only: Some(true),
            limit: Some(100),
            ..Default::default()
        };

        assert_eq!(criteria.token_type, Some(TokenType::Service));
        assert_eq!(criteria.role, Some(TokenRole::Admin));
        assert_eq!(criteria.renewable_only, Some(true));
        assert_eq!(criteria.limit, Some(100));
    }

    #[test]
    fn test_token_search_results() {
        let tokens = vec![];
        let criteria = TokenSearchCriteria::default();
        let results = TokenSearchResults::new(tokens, criteria.clone(), 0);

        assert_eq!(results.tokens.len(), 0);
        assert_eq!(results.total_count, 0);
        assert!(!results.has_more());
    }
}
