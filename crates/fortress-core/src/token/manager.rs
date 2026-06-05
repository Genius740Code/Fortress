//! Token Manager implementation
//!
//! This module provides the main TokenManager that coordinates all token operations
//! including creation, validation, renewal, revocation, and lease management.

use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    lease::LeaseManager,
    revocation::{RevocationEntry, RevocationList, RevocationReason},
    types::{
        CreateTokenRequest, RenewTokenRequest, RevokeTokenRequest, Token, TokenCreationContext,
        TokenInfo, TokenLookupResult, TokenMetadata, TokenRole, TokenSearchCriteria,
        TokenSearchResults, TokenType, TokenUsageStats, TokenValidationResult,
    },
};
use crate::error::{FortressError, Result, TokenErrorCode};

/// Token manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenManagerConfig {
    /// Default token TTL
    pub default_ttl: Duration,
    /// Maximum allowed TTL
    pub max_ttl: Duration,
    /// Default number of renewals allowed
    pub default_max_renewals: u32,
    /// Maximum number of renewals allowed
    pub max_max_renewals: u32,
    /// Cleanup interval for expired tokens
    pub cleanup_interval: Duration,
    /// Whether to enable token usage tracking
    pub enable_usage_tracking: bool,
    /// Maximum number of tokens per entity
    pub max_tokens_per_entity: Option<u32>,
    /// Token storage backend
    pub storage_backend: String,
}

impl Default for TokenManagerConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::hours(1),
            max_ttl: Duration::days(30),
            default_max_renewals: 10,
            max_max_renewals: 100,
            cleanup_interval: Duration::minutes(5),
            enable_usage_tracking: true,
            max_tokens_per_entity: Some(1000),
            storage_backend: "memory".to_string(),
        }
    }
}

/// Main token manager
pub struct TokenManager {
    /// Token storage
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    /// Token metadata storage
    token_metadata: Arc<RwLock<HashMap<String, TokenMetadata>>>,
    /// Entity to tokens mapping
    entity_tokens: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Revocation list
    revocation_list: Arc<RevocationList>,
    /// Lease manager
    lease_manager: Arc<LeaseManager>,
    /// Configuration
    config: TokenManagerConfig,
    /// Cleanup task handle
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
    /// Indexed fields for efficient search
    type_index: Arc<RwLock<HashMap<TokenType, Vec<String>>>>,
    role_index: Arc<RwLock<HashMap<TokenRole, Vec<String>>>>,
    entity_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl TokenManager {
    /// Create a new token manager with default configuration
    pub fn new() -> Self {
        Self::with_config(TokenManagerConfig::default())
    }

    /// Create a new token manager with custom configuration
    pub fn with_config(config: TokenManagerConfig) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            token_metadata: Arc::new(RwLock::new(HashMap::new())),
            entity_tokens: Arc::new(RwLock::new(HashMap::new())),
            revocation_list: Arc::new(RevocationList::new()),
            lease_manager: Arc::new(LeaseManager::new(config.cleanup_interval)),
            config,
            cleanup_task: None,
            type_index: Arc::new(RwLock::new(HashMap::new())),
            role_index: Arc::new(RwLock::new(HashMap::new())),
            entity_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new token
    pub async fn create_token(&mut self, request: CreateTokenRequest) -> Result<TokenInfo> {
        // Validate request
        self.validate_create_request(&request)?;

        // Check entity token limit
        if let Some(max_tokens) = self.config.max_tokens_per_entity {
            let entity_tokens = self.entity_tokens.read().await;
            if let Some(tokens) = entity_tokens.get(&request.entity_id) {
                if tokens.len() as u32 >= max_tokens {
                    return Err(FortressError::token_with_id(
                        format!(
                            "Entity {} has reached maximum token limit",
                            request.entity_id
                        ),
                        None,
                        TokenErrorCode::CreationFailed,
                    ));
                }
            }
        }

        // Create token
        let mut token = Token::new(
            request.token_type.clone(),
            request.role.clone(),
            request.policies.clone(),
            request.ttl,
            request.entity_id.clone(),
        );

        // Apply request settings
        token.renewable = request.renewable;
        token.max_renewals = request
            .max_renewals
            .or(Some(self.config.default_max_renewals));
        token.path_suffixes = request.path_suffixes.unwrap_or_default();
        token.parent_token = request.parent_token;
        token.ip_restrictions = request.ip_restrictions.unwrap_or_default();
        token.user_agent_restrictions = request.user_agent_restrictions.unwrap_or_default();

        // Add metadata
        if let Some(metadata) = request.metadata {
            for (key, value) in metadata {
                token.add_metadata(key, value);
            }
        }

        // Create token info
        let token_info = TokenInfo {
            token: token.clone(),
            display_name: request
                .display_name
                .unwrap_or_else(|| format!("{} Token", request.token_type.display_name())),
            description: request.description,
            usage_stats: TokenUsageStats::default(),
            creation_context: TokenCreationContext {
                created_by: "system".to_string(), // Would be set from auth context
                creation_method: "api".to_string(),
                source_ip: None,
                user_agent: None,
                request_id: None,
            },
        };

        // Store token
        {
            let mut tokens = self.tokens.write().await;
            tokens.insert(token.id.clone(), token_info.clone());
        }

        // Store metadata
        let metadata = TokenMetadata::new(
            token.id.clone(),
            token.token_type.clone(),
            token.entity_id.clone(),
            self.config.storage_backend.clone(),
        );
        {
            let mut token_metadata = self.token_metadata.write().await;
            token_metadata.insert(token.id.clone(), metadata);
        }

        // Update entity mapping
        {
            let mut entity_tokens = self.entity_tokens.write().await;
            entity_tokens
                .entry(token.entity_id.clone())
                .or_insert_with(Vec::new)
                .push(token.id.clone());
        }

        // Start cleanup task if not already running
        if self.cleanup_task.is_none() {
            self.start_cleanup_task().await;
        }

        Ok(token_info)
    }

    /// Validate a token
    pub async fn validate_token(
        &self,
        token_id: &str,
        context: &TokenValidationContext,
    ) -> Result<TokenValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut token_info_option = None;
        let mut validation_successful = false; // Flag to track if validation passed initially

        // Check if token is revoked
        if self.revocation_list.is_revoked(token_id).await {
            errors.push("Token is revoked".to_string());
            return Ok(TokenValidationResult {
                valid: false,
                token_info: None,
                errors,
                warnings,
                validated_at: Utc::now(),
            });
        }

        {
            let tokens = self.tokens.read().await; // Acquire read lock
            if let Some(info) = tokens.get(token_id) {
                // Check expiration
                if info.token.is_expired() {
                    errors.push("Token has expired".to_string());
                }

                // Check IP restrictions
                if let Some(ip) = &context.ip_address {
                    if !info.token.is_ip_allowed(ip) {
                        errors.push("IP address not allowed".to_string());
                    }
                }

                // Check user agent restrictions
                if let Some(user_agent) = &context.user_agent {
                    if !info.token.is_user_agent_allowed(user_agent) {
                        errors.push("User agent not allowed".to_string());
                    }
                }

                // Check path suffix restrictions
                if !context.request_path.is_empty() {
                    let path_allowed = info.token.path_suffixes.is_empty()
                        || info
                            .token
                            .path_suffixes
                            .iter()
                            .any(|suffix| context.request_path.starts_with(suffix));

                    if !path_allowed {
                        errors.push("Path not allowed for this token".to_string());
                    }
                }

                // Warnings
                if info.token.remaining_ttl() < Duration::minutes(15) {
                    warnings.push("Token will expire soon".to_string());
                }

                if !info.token.is_renewable() {
                    warnings.push("Token is not renewable".to_string());
                }

                token_info_option = Some(info.clone());
                validation_successful = errors.is_empty();
            } else {
                errors.push("Token not found".to_string());
            }
        } // Read lock on `tokens` is released here

        // Now, outside the read lock, update usage statistics if tracking is enabled
        if self.config.enable_usage_tracking {
            if validation_successful {
                self.update_usage_stats(token_id, true, false).await;
            } else {
                self.update_usage_stats(token_id, false, true).await;
            }
        }

        Ok(TokenValidationResult {
            valid: validation_successful,
            token_info: token_info_option,
            errors,
            warnings,
            validated_at: Utc::now(),
        })
    }

    /// Renew a token
    pub async fn renew_token(&self, request: RenewTokenRequest) -> Result<TokenInfo> {
        let mut tokens = self.tokens.write().await;
        let token_info = tokens.get_mut(&request.token_id).ok_or_else(|| {
            FortressError::token_with_id(
                "Token not found",
                Some(request.token_id.clone()),
                TokenErrorCode::TokenNotFound,
            )
        })?;

        // Check if token is renewable
        if !token_info.token.is_renewable() {
            return Err(FortressError::token_with_id(
                "Token is not renewable",
                Some(request.token_id.clone()),
                TokenErrorCode::NotRenewable,
            ));
        }

        // Check if token is expired
        if token_info.token.is_expired() {
            return Err(FortressError::token_with_id(
                "Cannot renew expired token",
                Some(request.token_id.clone()),
                TokenErrorCode::TokenExpired,
            ));
        }

        // Renew the token
        token_info.token.expires_time = Utc::now() + request.increment;
        token_info.token.last_renewal = Some(Utc::now());
        token_info.token.renewal_count += 1;

        // Update metadata
        {
            let mut token_metadata = self.token_metadata.write().await;
            if let Some(metadata) = token_metadata.get_mut(&request.token_id) {
                metadata.touch();
            }
        }

        Ok(token_info.clone())
    }

    /// Revoke a token
    pub async fn revoke_token(&self, request: RevokeTokenRequest) -> Result<()> {
        // Check if token exists
        let token_info = {
            let tokens = self.tokens.read().await;
            tokens.get(&request.token_id).cloned()
        };

        if token_info.is_none() {
            return Err(FortressError::token_with_id(
                "Token not found",
                Some(request.token_id.clone()),
                TokenErrorCode::TokenNotFound,
            ));
        }

        // Create revocation entry
        let revocation_reason = match request.reason.as_str() {
            "compromised" => RevocationReason::Compromised,
            "expired" => RevocationReason::Expired,
            "user_request" => RevocationReason::UserRequest,
            "administrative" => RevocationReason::Administrative,
            "security_violation" => RevocationReason::SecurityViolation,
            "entity_disabled" => RevocationReason::EntityDisabled,
            "limit_exceeded" => RevocationReason::LimitExceeded,
            "maintenance" => RevocationReason::Maintenance,
            _ => RevocationReason::Custom(request.reason.clone()),
        };

        let revocation_entry = RevocationEntry::new(
            request.token_id.clone(),
            revocation_reason,
            request.requester_token.clone(),
        );

        // Add to revocation list
        self.revocation_list.revoke_token(revocation_entry).await?;

        // Remove from active tokens
        {
            let mut tokens = self.tokens.write().await;
            tokens.remove(&request.token_id);
        }

        // Remove metadata
        {
            let mut token_metadata = self.token_metadata.write().await;
            token_metadata.remove(&request.token_id);
        }

        // Update entity mapping
        if let Some(ref token_info) = token_info {
            let mut entity_tokens = self.entity_tokens.write().await;
            if let Some(tokens) = entity_tokens.get_mut(&token_info.token.entity_id) {
                tokens.retain(|token_id| token_id != &request.token_id);
                if tokens.is_empty() {
                    entity_tokens.remove(&token_info.token.entity_id);
                }
            }
        }

        Ok(())
    }

    /// Lookup a token
    pub async fn lookup_token(&self, token_id: &str) -> Result<TokenLookupResult> {
        let tokens = self.tokens.read().await;
        let token_info = tokens.get(token_id).cloned();

        Ok(TokenLookupResult {
            found: token_info.is_some(),
            token_info: token_info,
            looked_up_at: Utc::now(),
        })
    }

    /// List tokens for an entity
    pub async fn list_entity_tokens(&self, entity_id: &str) -> Result<Vec<TokenInfo>> {
        let entity_tokens = self.entity_tokens.read().await;
        let tokens = self.tokens.read().await;

        let mut result = Vec::new();
        if let Some(token_ids) = entity_tokens.get(entity_id) {
            for token_id in token_ids {
                if let Some(token_info) = tokens.get(token_id) {
                    result.push(token_info.clone());
                }
            }
        }

        Ok(result)
    }

    /// Search tokens
    pub async fn search_tokens(&self, criteria: TokenSearchCriteria) -> Result<TokenSearchResults> {
        let tokens = self.tokens.read().await;
        let _matching_tokens: Vec<TokenInfo> = Vec::new();

        // Use indexed search when possible
        let candidate_tokens = if let Some(ref token_type) = criteria.token_type {
            // Use type index
            let type_index = self.type_index.read().await;
            type_index.get(token_type).cloned().unwrap_or_default()
        } else if let Some(ref role) = criteria.role {
            // Use role index
            let role_index = self.role_index.read().await;
            role_index.get(role).cloned().unwrap_or_default()
        } else if let Some(ref entity_id) = criteria.entity_id {
            // Use entity index
            let entity_index = self.entity_index.read().await;
            entity_index.get(entity_id).cloned().unwrap_or_default()
        } else {
            // Fall back to all token IDs
            tokens.keys().cloned().collect()
        };

        // Use indexed lookup with filter
        let matching_tokens: Vec<_> = candidate_tokens
            .iter()
            .filter_map(|token_id| tokens.get(token_id))
            .filter(|token_info| self.token_matches_criteria(token_info, &criteria))
            .cloned()
            .collect();

        // Apply pagination
        let total_count = matching_tokens.len() as u64;
        let offset = criteria.offset.unwrap_or(0) as usize;
        let limit = criteria.limit.unwrap_or(100) as usize;

        let paginated_tokens = if offset < matching_tokens.len() {
            let end = std::cmp::min(offset + limit, matching_tokens.len());
            matching_tokens[offset..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(TokenSearchResults::new(
            paginated_tokens,
            criteria,
            total_count,
        ))
    }

    /// Get token statistics
    pub async fn get_statistics(&self) -> Result<TokenManagerStatistics> {
        let tokens = self.tokens.read().await;
        let entity_tokens = self.entity_tokens.read().await;
        let revocation_stats = self.revocation_list.get_statistics().await;
        let lease_stats = self.lease_manager.get_lease_statistics().await;

        let mut stats = TokenManagerStatistics {
            total_tokens: tokens.len() as u64,
            total_entities: entity_tokens.len() as u64,
            tokens_by_type: HashMap::new(),
            tokens_by_role: HashMap::new(),
            expired_tokens: 0,
            renewable_tokens: 0,
            tokens_expiring_soon: 0,
            revocation_stats,
            lease_stats: lease_stats?,
        };

        // Count tokens by type and role
        for token_info in tokens.values() {
            // Count by type
            *stats
                .tokens_by_type
                .entry(token_info.token.token_type.clone())
                .or_insert(0) += 1;

            // Count by role
            *stats
                .tokens_by_role
                .entry(token_info.token.role.clone())
                .or_insert(0) += 1;

            // Count expired tokens
            if token_info.token.is_expired() {
                stats.expired_tokens += 1;
            }

            // Count renewable tokens
            if token_info.token.is_renewable() {
                stats.renewable_tokens += 1;
            }

            // Count tokens expiring soon (within 1 hour)
            if token_info.token.remaining_ttl() < Duration::hours(1) {
                stats.tokens_expiring_soon += 1;
            }
        }

        Ok(stats)
    }

    /// Cleanup expired tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        let mut tokens = self.tokens.write().await;
        let mut token_metadata = self.token_metadata.write().await;
        let mut entity_tokens = self.entity_tokens.write().await;

        let mut expired_count = 0;
        let mut expired_token_ids = Vec::new();

        // Find expired tokens
        for (token_id, token_info) in tokens.iter() {
            if token_info.token.is_expired() {
                expired_token_ids.push(token_id.clone());
            }
        }

        // Remove expired tokens
        for token_id in expired_token_ids {
            if let Some(token_info) = tokens.remove(&token_id) {
                // Update entity mapping
                if let Some(tokens) = entity_tokens.get_mut(&token_info.token.entity_id) {
                    tokens.retain(|id| id != &token_id);
                    if tokens.is_empty() {
                        entity_tokens.remove(&token_info.token.entity_id);
                    }
                }

                // Remove metadata
                token_metadata.remove(&token_id);

                expired_count += 1;
            }
        }

        Ok(expired_count)
    }

    /// Validate create token request
    fn validate_create_request(&self, request: &CreateTokenRequest) -> Result<()> {
        // Check TTL limits
        if request.ttl > self.config.max_ttl {
            return Err(FortressError::token_with_id(
                format!(
                    "TTL exceeds maximum allowed duration of {:?}",
                    self.config.max_ttl
                ),
                None,
                TokenErrorCode::CreationFailed,
            ));
        }

        if request.ttl <= Duration::zero() {
            return Err(FortressError::token_with_id(
                "TTL must be greater than zero",
                None,
                TokenErrorCode::CreationFailed,
            ));
        }

        // Check renewal limits
        if let Some(max_renewals) = request.max_renewals {
            if max_renewals > self.config.max_max_renewals {
                return Err(FortressError::token_with_id(
                    format!(
                        "Maximum renewals exceeds allowed limit of {}",
                        self.config.max_max_renewals
                    ),
                    None,
                    TokenErrorCode::CreationFailed,
                ));
            }
        }

        // Validate entity ID
        if request.entity_id.is_empty() {
            return Err(FortressError::token_with_id(
                "Entity ID cannot be empty",
                None,
                TokenErrorCode::CreationFailed,
            ));
        }

        Ok(())
    }

    /// Check if token matches search criteria
    fn token_matches_criteria(
        &self,
        token_info: &TokenInfo,
        criteria: &TokenSearchCriteria,
    ) -> bool {
        // Token type filter
        if let Some(ref token_type) = criteria.token_type {
            if token_info.token.token_type != *token_type {
                return false;
            }
        }

        // Role filter
        if let Some(ref role) = criteria.role {
            if token_info.token.role != *role {
                return false;
            }
        }

        // Entity ID filter
        if let Some(ref entity_id) = criteria.entity_id {
            if token_info.token.entity_id != *entity_id {
                return false;
            }
        }

        // Policy filter
        if let Some(ref has_policy) = criteria.has_policy {
            if !token_info.token.has_policy(has_policy) {
                return false;
            }
        }

        // Created after filter
        if let Some(ref created_after) = criteria.created_after {
            if token_info.token.created_time < *created_after {
                return false;
            }
        }

        // Created before filter
        if let Some(ref created_before) = criteria.created_before {
            if token_info.token.created_time > *created_before {
                return false;
            }
        }

        // Expires after filter
        if let Some(ref expires_after) = criteria.expires_after {
            if token_info.token.expires_time < *expires_after {
                return false;
            }
        }

        // Expires before filter
        if let Some(ref expires_before) = criteria.expires_before {
            if token_info.token.expires_time > *expires_before {
                return false;
            }
        }

        // Renewable filter
        if let Some(renewable_only) = criteria.renewable_only {
            if token_info.token.renewable != renewable_only {
                return false;
            }
        }

        // Expired filter
        if let Some(expired_only) = criteria.expired_only {
            if token_info.token.is_expired() != expired_only {
                return false;
            }
        }

        // IP restriction filter
        if let Some(ref ip_restriction) = criteria.ip_restriction {
            if !token_info.token.ip_restrictions.contains(ip_restriction) {
                return false;
            }
        }

        // Metadata filter
        if let Some(ref metadata_filter) = criteria.metadata_filter {
            for (key, value) in metadata_filter {
                if token_info.token.get_metadata(key) != Some(value) {
                    return false;
                }
            }
        }

        true
    }

    /// Update token usage statistics
    async fn update_usage_stats(&self, token_id: &str, _success: bool, failed: bool) {
        let mut tokens = self.tokens.write().await;
        if let Some(token_info) = tokens.get_mut(token_id) {
            let now = Utc::now();

            token_info.usage_stats.usage_count += 1;
            token_info.usage_stats.last_used = Some(now);

            if failed {
                token_info.usage_stats.failed_auth_count += 1;
                token_info.usage_stats.last_failed_auth = Some(now);
            }

            // Update hourly statistics (simplified)
            let hour = now.hour() as u32;
            token_info.usage_stats.peak_usage_hour = Some(hour);
        }
    }

    /// Start the cleanup task
    async fn start_cleanup_task(&mut self) {
        let tokens = self.tokens.clone();
        let entity_tokens = self.entity_tokens.clone();
        let token_metadata = self.token_metadata.clone();
        let revocation_list = self.revocation_list.clone();
        let lease_manager = self.lease_manager.clone();
        let interval = self.config.cleanup_interval;

        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(std::time::Duration::from_secs(
                interval.num_seconds() as u64,
            ));

            loop {
                interval_timer.tick().await;

                // Clean up expired tokens
                {
                    let mut tokens_guard = tokens.write().await;
                    let mut metadata_guard = token_metadata.write().await;
                    let mut entity_tokens_guard = entity_tokens.write().await;
                    let _now = Utc::now();

                    let mut expired_token_ids = Vec::new();

                    for (token_id, token_info) in tokens_guard.iter() {
                        if token_info.token.is_expired() {
                            expired_token_ids.push(token_id.clone());
                        }
                    }

                    for token_id in expired_token_ids {
                        if let Some(token_info) = tokens_guard.remove(&token_id) {
                            // Update entity mapping
                            if let Some(tokens) =
                                entity_tokens_guard.get_mut(&token_info.token.entity_id)
                            {
                                tokens.retain(|id| id != &token_id);
                                if tokens.is_empty() {
                                    entity_tokens_guard.remove(&token_info.token.entity_id);
                                }
                            }

                            // Remove metadata
                            metadata_guard.remove(&token_id);
                        }
                    }
                }

                // Clean up expired leases
                let _ = lease_manager.cleanup_expired_leases().await;

                // Clean up old revocations (older than 90 days)
                let now = Utc::now();
                let cutoff = now - chrono::Duration::days(90);
                let _ = revocation_list.cleanup_old_revocations(cutoff).await;
            }
        });

        self.cleanup_task = Some(task);
    }

    /// Stop the cleanup task
    pub async fn stop_cleanup_task(&mut self) {
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
    }
}

impl Drop for TokenManager {
    fn drop(&mut self) {
        // The cleanup task will be automatically aborted when dropped
    }
}

/// Token validation context
#[derive(Debug, Clone)]
pub struct TokenValidationContext {
    /// IP address of the request
    pub ip_address: Option<String>,
    /// User agent of the request
    pub user_agent: Option<String>,
    /// Request path being accessed
    pub request_path: String,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
}

impl Default for TokenValidationContext {
    fn default() -> Self {
        Self {
            ip_address: None,
            user_agent: None,
            request_path: String::new(),
            timestamp: Utc::now(),
        }
    }
}

/// Token manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenManagerStatistics {
    /// Total number of active tokens
    pub total_tokens: u64,
    /// Total number of entities with tokens
    pub total_entities: u64,
    /// Tokens grouped by type
    pub tokens_by_type: HashMap<TokenType, u64>,
    /// Tokens grouped by role
    pub tokens_by_role: HashMap<TokenRole, u64>,
    /// Number of expired tokens
    pub expired_tokens: u64,
    /// Number of renewable tokens
    pub renewable_tokens: u64,
    /// Number of tokens expiring soon (within 1 hour)
    pub tokens_expiring_soon: u64,
    /// Revocation statistics
    pub revocation_stats: super::revocation::RevocationStatistics,
    /// Lease statistics
    pub lease_stats: super::lease::LeaseStatistics,
}

impl TokenType {
    /// Get display name for token type
    pub fn display_name(&self) -> &str {
        match self {
            TokenType::Service => "Service",
            TokenType::User => "User",
            TokenType::Batch => "Batch",
            TokenType::Emergency => "Emergency",
            TokenType::Recovery => "Recovery",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_token_manager_creation() {
        let token_manager = TokenManager::new();
        let stats = token_manager.get_statistics().await.unwrap();
        assert_eq!(stats.total_tokens, 0);
        assert_eq!(stats.total_entities, 0);
    }

    #[tokio::test]
    async fn test_create_token() {
        let mut token_manager = TokenManager::new();

        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec!["default".to_string()],
            ttl: Duration::hours(1),
            entity_id: "user123".to_string(),
            ..Default::default()
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        assert_eq!(token_info.token.token_type, TokenType::User);
        assert_eq!(token_info.token.role, TokenRole::Admin);
        assert!(token_info.token.has_policy("default"));
        assert!(!token_info.token.is_expired());
        assert!(token_info.token.is_renewable());
    }

    #[tokio::test]
    async fn test_token_validation() {
        let mut token_manager = TokenManager::new();

        // Create token
        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec![],
            ttl: Duration::hours(1),
            entity_id: "user123".to_string(),
            ..Default::default()
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Validate token
        let context = TokenValidationContext::default();
        let result = token_manager
            .validate_token(&token_info.token.id, &context)
            .await
            .unwrap();

        assert!(result.valid);
        assert!(result.token_info.is_some());
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_token_renewal() {
        let mut token_manager = TokenManager::new();

        let request = CreateTokenRequest {
            token_type: TokenType::Service,
            role: TokenRole::Operator,
            policies: vec![],
            ttl: Duration::minutes(30),
            entity_id: "service1".to_string(),
            ..Default::default()
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Renew token
        let renew_request = RenewTokenRequest {
            token_id: token_info.token.id.clone(),
            increment: Duration::minutes(30),
            requester_token: "admin_token".to_string(),
        };

        let renewed_info = token_manager.renew_token(renew_request).await.unwrap();
        assert_eq!(renewed_info.token.renewal_count, 1);
        assert!(renewed_info.token.last_renewal.is_some());
    }

    #[tokio::test]
    async fn test_token_revocation() {
        let mut token_manager = TokenManager::new();

        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec![],
            ttl: Duration::hours(1),
            entity_id: "user123".to_string(),
            ..Default::default()
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Revoke token
        let revoke_request = RevokeTokenRequest {
            token_id: token_info.token.id.clone(),
            reason: "user_request".to_string(),
            requester_token: "admin_token".to_string(),
            force: false,
        };

        token_manager.revoke_token(revoke_request).await.unwrap();

        // Token should no longer be valid
        let context = TokenValidationContext::default();
        let result = token_manager
            .validate_token(&token_info.token.id, &context)
            .await
            .unwrap();
        assert!(!result.valid);
        assert!(result.errors.contains(&"Token is revoked".to_string()));
    }

    #[tokio::test]
    async fn test_entity_token_listing() {
        let mut token_manager = TokenManager::new();

        // Create multiple tokens for same entity
        for _i in 0..3 {
            let request = CreateTokenRequest {
                token_type: TokenType::User,
                role: TokenRole::Operator,
                policies: vec![],
                ttl: Duration::hours(1),
                entity_id: "user123".to_string(),
                ..Default::default()
            };
            token_manager.create_token(request).await.unwrap();
        }

        // List entity tokens
        let entity_tokens = token_manager.list_entity_tokens("user123").await.unwrap();
        assert_eq!(entity_tokens.len(), 3);

        // All should belong to the same entity
        for token_info in &entity_tokens {
            assert_eq!(token_info.token.entity_id, "user123");
        }
    }

    #[tokio::test]
    async fn test_token_search() {
        let mut token_manager = TokenManager::new();

        // Create tokens with different types and roles
        let user_request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec![],
            ttl: Duration::hours(1),
            entity_id: "user123".to_string(),
            ..Default::default()
        };

        let service_request = CreateTokenRequest {
            token_type: TokenType::Service,
            role: TokenRole::Operator,
            policies: vec![],
            ttl: Duration::hours(24),
            entity_id: "service1".to_string(),
            ..Default::default()
        };

        token_manager.create_token(user_request).await.unwrap();
        token_manager.create_token(service_request).await.unwrap();

        // Search by type
        let criteria = TokenSearchCriteria {
            token_type: Some(TokenType::User),
            ..Default::default()
        };

        let results = token_manager.search_tokens(criteria).await.unwrap();
        assert_eq!(results.tokens.len(), 1);
        assert_eq!(results.tokens[0].token.token_type, TokenType::User);

        // Search by role
        let criteria = TokenSearchCriteria {
            role: Some(TokenRole::Admin),
            ..Default::default()
        };

        let results = token_manager.search_tokens(criteria).await.unwrap();
        assert_eq!(results.tokens.len(), 1);
        assert_eq!(results.tokens[0].token.role, TokenRole::Admin);
    }

    #[tokio::test]
    async fn test_token_statistics() {
        let mut token_manager = TokenManager::new();

        // Create tokens with different types
        let types = vec![TokenType::User, TokenType::Service, TokenType::Batch];
        for (i, token_type) in types.iter().enumerate() {
            let request = CreateTokenRequest {
                token_type: token_type.clone(),
                role: TokenRole::Operator,
                policies: vec![],
                ttl: Duration::hours(1),
                entity_id: format!("entity{}", i),
                ..Default::default()
            };
            token_manager.create_token(request).await.unwrap();
        }

        let stats = token_manager.get_statistics().await.unwrap();
        assert_eq!(stats.total_tokens, 3);
        assert_eq!(stats.total_entities, 3);
        assert_eq!(stats.tokens_by_type.get(&TokenType::User), Some(&1));
        assert_eq!(stats.tokens_by_type.get(&TokenType::Service), Some(&1));
        assert_eq!(stats.tokens_by_type.get(&TokenType::Batch), Some(&1));
    }

    #[tokio::test]
    async fn test_token_validation_context() {
        let mut token_manager = TokenManager::new();

        // Create token with IP restrictions
        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec![],
            ttl: Duration::hours(1),
            entity_id: "user123".to_string(),
            ip_restrictions: Some(vec!["192.168.1.1".to_string()]),
            ..Default::default()
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Test with allowed IP
        let context = TokenValidationContext {
            ip_address: Some("192.168.1.1".to_string()),
            ..Default::default()
        };

        let result = token_manager
            .validate_token(&token_info.token.id, &context)
            .await
            .unwrap();
        assert!(result.valid);

        // Test with disallowed IP
        let context = TokenValidationContext {
            ip_address: Some("10.0.0.1".to_string()),
            ..Default::default()
        };

        let result = token_manager
            .validate_token(&token_info.token.id, &context)
            .await
            .unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .contains(&"IP address not allowed".to_string()));
    }

    #[tokio::test]
    async fn test_cleanup_expired_tokens() {
        let mut token_manager = TokenManager::new();

        // Create token with very short TTL
        let request = CreateTokenRequest {
            token_type: TokenType::User,
            role: TokenRole::Admin,
            policies: vec![],
            ttl: Duration::seconds(1),
            entity_id: "user123".to_string(),
            ..Default::default()
        };

        let token_info = token_manager.create_token(request).await.unwrap();

        // Should have 1 token initially
        let stats = token_manager.get_statistics().await.unwrap();
        assert_eq!(stats.total_tokens, 1);

        // Wait for token to expire (in real test, you'd use time mocking)
        // For now, manually expire it
        {
            let mut tokens = token_manager.tokens.write().await;
            if let Some(token_info) = tokens.get_mut(&token_info.token.id) {
                token_info.token.expires_time = Utc::now() - Duration::seconds(1);
            }
        }

        // Run cleanup
        let cleaned_count = token_manager.cleanup_expired_tokens().await.unwrap();
        assert_eq!(cleaned_count, 1);

        // Should have 0 tokens now
        let stats = token_manager.get_statistics().await.unwrap();
        assert_eq!(stats.total_tokens, 0);
    }
}
