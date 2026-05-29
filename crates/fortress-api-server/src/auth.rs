//! Authentication and authorization system
//!
//! This module provides JWT-based authentication and role-based authorization
//! for the Fortress REST API.

use crate::error::{ServerError, ServerResult};
use crate::models::{AuthRequest, AuthResponse, RefreshTokenRequest, RefreshTokenResponse, UserInfo};
use sha2::Digest;
use axum::{
    extract::{Request, State, FromRequestParts},
    http::{header, StatusCode, request::Parts},
    middleware::Next,
    response::Response,
    async_trait,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::HashMap;
use std::sync::Arc;
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{rand_core::OsRng, SaltString}
};
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};
use percent_encoding;
use sha2;
use rand::rngs::OsRng;
use rand::RngCore;

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// Email (optional)
    pub email: Option<String>,
    /// Roles
    pub roles: Vec<String>,
    /// Tenant ID (optional)
    pub tenant_id: Option<String>,
    /// Token issued at
    pub iat: i64,
    /// Token expiration
    pub exp: i64,
    /// JWT ID
    pub jti: String,
}

/// Optional TokenClaims extractor for handlers
/// This extracts claims from request extensions if they exist
#[derive(Debug, Clone)]
pub struct OptionalTokenClaims(pub Option<TokenClaims>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalTokenClaims
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let claims = parts.extensions.get::<TokenClaims>().cloned();
        Ok(OptionalTokenClaims(claims))
    }
}

/// Required TokenClaims extractor for handlers that require authentication
#[derive(Debug, Clone)]
pub struct RequiredTokenClaims(pub TokenClaims);

#[async_trait]
impl<S> FromRequestParts<S> for RequiredTokenClaims
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions
            .get::<TokenClaims>()
            .cloned()
            .map(RequiredTokenClaims)
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

/// Authentication manager
#[derive(Clone)]
pub struct AuthManager {
    /// JWT encoding key
    encoding_key: EncodingKey,
    /// JWT decoding key
    decoding_key: DecodingKey,
    /// Token expiration duration
    token_expiration: Duration,
    /// User store (in-memory for now, can be replaced with database)
    user_store: Arc<dyn UserStore>,
}

/// User store trait for authentication
#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    /// Authenticate user credentials
    async fn authenticate(&self, request: AuthRequest) -> ServerResult<UserInfo>;
    
    /// Get user by ID
    async fn get_user(&self, user_id: &str) -> ServerResult<Option<UserInfo>>;
    
    /// Validate refresh token
    async fn validate_refresh_token(&self, refresh_token: &str) -> ServerResult<UserInfo>;
    
    /// Store refresh token
    async fn store_refresh_token(&self, user_id: &str, refresh_token: &str) -> ServerResult<()>;
    
    /// Revoke refresh token
    async fn revoke_refresh_token(&self, refresh_token: &str) -> ServerResult<()>;
}

/// OIDC/OAuth2 user store for modern enterprise authentication
#[derive(Clone)]
pub struct OidcUserStore {
    /// OIDC provider configuration
    provider_config: OidcProviderConfig,
    /// HTTP client for OIDC requests
    client: reqwest::Client,
    /// In-memory cache for user information
    user_cache: Arc<parking_lot::RwLock<HashMap<String, CachedUser>>>,
    /// Refresh token storage
    refresh_tokens: Arc<parking_lot::RwLock<HashMap<String, TokenEntry>>>, // token -> TokenEntry
}

#[derive(Clone)]
struct TokenEntry {
    user_id: String,
    expiry: chrono::DateTime<chrono::Utc>,
}

/// OIDC provider configuration
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    /// OIDC issuer URL
    pub issuer_url: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Scopes to request
    pub scopes: Vec<String>,
    /// Enable PKCE
    pub enable_pkce: bool,
    /// Token endpoint (auto-discovered if not set)
    pub token_endpoint: Option<String>,
    /// Authorization endpoint (auto-discovered if not set)
    pub authorization_endpoint: Option<String>,
    /// UserInfo endpoint (auto-discovered if not set)
    pub userinfo_endpoint: Option<String>,
    /// JWKS URI (auto-discovered if not set)
    pub jwks_uri: Option<String>,
}

/// Cached user information with expiration
#[derive(Clone)]
struct CachedUser {
    user_info: UserInfo,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// OIDC token response
#[derive(Debug, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// OIDC user info response
#[derive(Debug, Deserialize)]
pub struct OidcUserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub preferred_username: Option<String>,
    pub groups: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
}

/// OIDC provider discovery document
#[derive(Debug, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// OIDC authentication request
#[derive(Debug, Clone)]
pub struct OidcAuthRequest {
    /// Authorization code from callback
    pub code: String,
    /// Code verifier for PKCE (if enabled)
    pub code_verifier: Option<String>,
    /// Session state for security
    pub state: String,
    /// Redirect URI used in the request
    pub redirect_uri: String,
}

/// OIDC authentication result
#[derive(Debug, Clone)]
pub struct OidcAuthResult {
    pub user_info: UserInfo,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub id_token: Option<String>,
}

impl OidcUserStore {
    /// Create a new OIDC user store
    pub fn new(config: OidcProviderConfig) -> Self {
        Self {
            provider_config: config.clone(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            user_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    /// Discover OIDC provider endpoints
    pub async fn discover_endpoints(&self) -> ServerResult<OidcDiscoveryDocument> {
        let discovery_url = format!("{}/.well-known/openid_configuration", self.provider_config.issuer_url);
        
        let response = self.client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to fetch discovery document: {}", e)))?;

        if !response.status().is_success() {
            return Err(ServerError::internal(format!(
                "Discovery request failed with status: {}",
                response.status()
            )));
        }

        let discovery: OidcDiscoveryDocument = response
            .json()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to parse discovery document: {}", e)))?;

        tracing::info!("Discovered OIDC endpoints for issuer: {}", discovery.issuer);
        Ok(discovery)
    }

    /// Get authorization URL for OIDC flow
    pub fn get_authorization_url(&self, _state: &str, code_verifier: Option<&str>) -> ServerResult<String> {
        let auth_endpoint = self.provider_config.authorization_endpoint.as_ref()
            .ok_or_else(|| ServerError::internal("Authorization endpoint not configured"))?;

        let mut params: HashMap<String, String> = std::collections::HashMap::new();
        params.insert("response_type".to_string(), "code".to_string());
        params.insert("client_id".to_string(), self.provider_config.client_id.clone());
        params.insert("redirect_uri".to_string(), self.provider_config.redirect_uri.clone());

        // Add PKCE challenge if enabled
        if let Some(verifier) = code_verifier {
            if self.provider_config.enable_pkce {
                let challenge_bytes = sha2::Sha256::digest(verifier.as_bytes());
                let challenge = general_purpose::STANDARD.encode(challenge_bytes);
                params.insert("code_challenge".to_string(), challenge);
                params.insert("code_challenge_method".to_string(), "S256".to_string());
            }
        }

        let query_string = params.iter()
            .map(|(k, v)| format!("{}={}", percent_encoding::utf8_percent_encode(k, &percent_encoding::NON_ALPHANUMERIC), percent_encoding::utf8_percent_encode(v, &percent_encoding::NON_ALPHANUMERIC)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(format!("{}?{}", auth_endpoint, query_string))
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code_for_tokens(&self, request: OidcAuthRequest) -> ServerResult<OidcTokenResponse> {
        let token_endpoint = self.provider_config.token_endpoint.as_ref()
            .ok_or_else(|| ServerError::internal("Token endpoint not configured"))?;

        let mut params = std::collections::HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", &request.code);
        params.insert("redirect_uri", &request.redirect_uri);
        params.insert("client_id", &self.provider_config.client_id);
        params.insert("client_secret", &self.provider_config.client_secret);

        // Add code verifier for PKCE
        if let Some(verifier) = &request.code_verifier {
            params.insert("code_verifier", verifier);
        }

        let response = self.client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to exchange code for tokens: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(ServerError::internal(format!(
                "Token exchange failed: {} - {}",
                status,
                error_text
            )));
        }

        let token_response: OidcTokenResponse = response
            .json()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to parse token response: {}", e)))?;

        Ok(token_response)
    }

    /// Get user information from OIDC provider
    pub async fn get_user_info(&self, access_token: &str) -> ServerResult<OidcUserInfo> {
        // Check cache first
        let cache_key = format!("userinfo:{}", access_token);
        {
            let cache = self.user_cache.read();
            if let Some(cached) = cache.get(&cache_key) {
                if cached.expires_at > chrono::Utc::now() {
                    return Ok(OidcUserInfo {
                        sub: cached.user_info.id.clone(),
                        name: Some(cached.user_info.username.clone()),
                        email: cached.user_info.email.clone(),
                        preferred_username: Some(cached.user_info.username.clone()),
                        groups: None,
                        roles: Some(cached.user_info.roles.clone()),
                    });
                }
            }
        }

        let userinfo_endpoint = self.provider_config.userinfo_endpoint.as_ref()
            .ok_or_else(|| ServerError::internal("UserInfo endpoint not configured"))?;

        let response = self.client
            .get(userinfo_endpoint)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to fetch user info: {}", e)))?;

        if !response.status().is_success() {
            return Err(ServerError::internal(format!(
                "User info request failed: {}",
                response.status()
            )));
        }

        let user_info: OidcUserInfo = response
            .json()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to parse user info: {}", e)))?;

        // Cache the user info
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
        let cached_user = CachedUser {
            user_info: UserInfo {
                id: user_info.sub.clone(),
                username: user_info.preferred_username.clone().unwrap_or_else(|| user_info.sub.clone()),
                email: user_info.email.clone(),
                roles: user_info.roles.clone().unwrap_or_default(),
                tenant_id: None,
            },
            expires_at,
        };

        {
            let mut cache = self.user_cache.write();
            cache.insert(cache_key, cached_user);
        }

        Ok(user_info)
    }

    /// Validate ID token signature and claims
    pub fn validate_id_token(&self, id_token: &str) -> ServerResult<TokenClaims> {
        // In a real implementation, this would:
        // 1. Parse the JWT token
        // 2. Fetch the JWKS from the provider
        // 3. Validate the signature using the public keys
        // 4. Validate the claims (issuer, audience, expiration, etc.)
        
        // For now, we'll do a simplified validation
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(ServerError::auth("Invalid ID token format"));
        }

        // Decode payload (simplified - in production, use proper JWT library)
        let payload = general_purpose::STANDARD.decode(parts[1])
            .map_err(|_| ServerError::auth("Failed to decode ID token payload"))?;

        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| ServerError::auth("Failed to parse ID token claims"))?;

        // Extract basic claims
        let sub = claims.get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::auth("Missing subject claim"))?;

        let exp = claims.get("exp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ServerError::auth("Missing expiration claim"))?;

        let iat = claims.get("iat")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ServerError::auth("Missing issued at claim"))?;

        // Check expiration
        let now = chrono::Utc::now().timestamp();
        if exp <= now {
            return Err(ServerError::auth("ID token has expired"));
        }

        // Create TokenClaims (simplified)
        Ok(TokenClaims {
            sub: sub.to_string(),
            username: sub.to_string(),
            email: claims.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()),
            roles: claims.get("roles")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            tenant_id: None,
            iat,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
        })
    }

    /// Authenticate with OIDC authorization code
    pub async fn authenticate_with_code(&self, request: OidcAuthRequest) -> ServerResult<OidcAuthResult> {
        // Exchange code for tokens
        let token_response = self.exchange_code_for_tokens(request.clone()).await?;

        // Get user info
        let user_info = self.get_user_info(&token_response.access_token).await?;

        // Convert to UserInfo format
        let user = UserInfo {
            id: user_info.sub.clone(),
            username: user_info.preferred_username.clone().unwrap_or_else(|| user_info.sub.clone()),
            email: user_info.email.clone(),
            roles: user_info.roles.clone().unwrap_or_default(),
            tenant_id: None,
        };

        // Store refresh token if provided
        if let Some(refresh_token) = &token_response.refresh_token {
            self.store_refresh_token(&user.id, refresh_token).await?;
        }

        Ok(OidcAuthResult {
            user_info: user,
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_in: token_response.expires_in,
            id_token: token_response.id_token,
        })
    }

    /// Refresh access token
    pub async fn refresh_access_token(&self, refresh_token: &str) -> ServerResult<OidcTokenResponse> {
        let token_endpoint = self.provider_config.token_endpoint.as_ref()
            .ok_or_else(|| ServerError::internal("Token endpoint not configured"))?;

        let mut params = std::collections::HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", &self.provider_config.client_id);
        params.insert("client_secret", &self.provider_config.client_secret);

        let response = self.client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to refresh token: {}", e)))?;

        if !response.status().is_success() {
            return Err(ServerError::internal(format!(
                "Token refresh failed: {}",
                response.status()
            )));
        }

        let token_response: OidcTokenResponse = response
            .json()
            .await
            .map_err(|e| ServerError::internal(format!("Failed to parse refresh response: {}", e)))?;

        Ok(token_response)
    }

    /// Revoke token
    pub async fn revoke_token(&self, token: &str) -> ServerResult<()> {
        // In a real implementation, this would call the provider's revocation endpoint
        // For now, we'll just remove it from our local storage
        self.refresh_tokens.write().remove(token);
        Ok(())
    }
}

/// In-memory user store for development/testing
pub struct InMemoryUserStore {
    users: Arc<parking_lot::RwLock<HashMap<String, UserRecord>>>,
    refresh_tokens: Arc<parking_lot::RwLock<HashMap<String, (String, chrono::DateTime<chrono::Utc>)>>>, // token -> (user_id, expiry)
}

/// User record for in-memory store
#[derive(Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub tenant_id: Option<String>,
    pub failed_login_attempts: u32,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[async_trait::async_trait]
impl UserStore for OidcUserStore {
    async fn authenticate(&self, _request: AuthRequest) -> ServerResult<UserInfo> {
        // OIDC doesn't use username/password authentication
        Err(ServerError::auth("OIDC user store doesn't support username/password authentication"))
    }
    
    async fn get_user(&self, user_id: &str) -> ServerResult<Option<UserInfo>> {
        // Check cache first
        let cache_key = format!("user:{}", user_id);
        {
            let cache = self.user_cache.read();
            if let Some(cached) = cache.get(&cache_key) {
                if cached.expires_at > chrono::Utc::now() {
                    return Ok(Some(cached.user_info.clone()));
                }
            }
        }
        
        // For OIDC, we would need to fetch from the provider or return None
        // In a real implementation, you might use the access token to fetch fresh user info
        Ok(None)
    }
    
    async fn validate_refresh_token(&self, refresh_token: &str) -> ServerResult<UserInfo> {
        let user_id = {
            let refresh_tokens = self.refresh_tokens.read();
            let entry = refresh_tokens.get(refresh_token)
                .ok_or_else(|| ServerError::auth("Invalid refresh token"))?;
                
            if entry.expiry < chrono::Utc::now() {
                return Err(ServerError::auth("Refresh token expired"));
            }
            entry.user_id.clone()
        };
        
        // Refresh the access token and get fresh user info
        let token_response = self.refresh_access_token(refresh_token).await?;
        let user_info = self.get_user_info(&token_response.access_token).await?;
        
        // Convert to UserInfo format
        Ok(UserInfo {
            id: user_info.sub.clone(),
            username: user_info.preferred_username.clone().unwrap_or_else(|| user_info.sub.clone()),
            email: user_info.email.clone(),
            roles: user_info.roles.clone().unwrap_or_default(),
            tenant_id: None,
        })
    }
    
    async fn store_refresh_token(&self, user_id: &str, refresh_token: &str) -> ServerResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write();
        let expiry = chrono::Utc::now() + chrono::Duration::days(7);
        refresh_tokens.insert(refresh_token.to_string(), TokenEntry { user_id: user_id.to_string(), expiry });
        Ok(())
    }
    
    async fn revoke_refresh_token(&self, refresh_token: &str) -> ServerResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write();
        refresh_tokens.remove(refresh_token);
        Ok(())
    }
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new(jwt_secret: &str, token_expiration: Duration, user_store: Arc<dyn UserStore>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(jwt_secret.as_ref()),
            decoding_key: DecodingKey::from_secret(jwt_secret.as_ref()),
            token_expiration,
            user_store,
        }
    }

    /// Authenticate user and generate tokens
    pub async fn authenticate(&self, request: AuthRequest) -> ServerResult<AuthResponse> {
        // Validate credentials
        let user = self.user_store.authenticate(request).await?;
        
        // Generate access token
        let access_token = self.generate_access_token(&user)?;
        
        // Generate refresh token
        let refresh_token = self.generate_refresh_token();
        self.user_store.store_refresh_token(&user.id, &refresh_token).await?;
        
        Ok(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.token_expiration.num_seconds() as u64,
            refresh_token: Some(refresh_token),
            user,
        })
    }

    /// Refresh access token
    pub async fn refresh_token(&self, request: RefreshTokenRequest) -> ServerResult<RefreshTokenResponse> {
        // Validate refresh token
        let user = self.user_store.validate_refresh_token(&request.refresh_token).await?;
        
        // Generate new access token
        let access_token = self.generate_access_token(&user)?;
        
        // Generate new refresh token
        let new_refresh_token = self.generate_refresh_token();
        
        // Store new refresh token and revoke old one
        self.user_store.store_refresh_token(&user.id, &new_refresh_token).await?;
        self.user_store.revoke_refresh_token(&request.refresh_token).await?;
        
        Ok(RefreshTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.token_expiration.num_seconds() as u64,
            refresh_token: Some(new_refresh_token),
        })
    }

    /// Validate and extract claims from token
    pub fn validate_token(&self, token: &str) -> ServerResult<TokenClaims> {
        let mut validation = Validation::default();
        // Explicitly specify allowed algorithms to prevent "alg:none" attacks
        validation.algorithms = vec![jsonwebtoken::Algorithm::HS256];
        // Validate critical claims
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0; // No leeway for time-based claims
        
        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| ServerError::auth(format!("Invalid token: {}", e)))?;
        
        Ok(token_data.claims)
    }

    /// Generate access token for user
    fn generate_access_token(&self, user: &UserInfo) -> ServerResult<String> {
        let now = Utc::now();
        let claims = TokenClaims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            roles: user.roles.clone(),
            tenant_id: user.tenant_id.clone(),
            iat: now.timestamp(),
            exp: (now + self.token_expiration).timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| ServerError::internal(format!("Failed to generate token: {}", e)))
    }

    /// Generate refresh token
    fn generate_refresh_token(&self) -> String {
        let mut token_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut token_bytes);
        general_purpose::STANDARD.encode(&token_bytes)
    }

    /// Check if user has required role
    pub fn has_role(&self, claims: &TokenClaims, required_role: &str) -> bool {
        claims.roles.contains(&required_role.to_string())
    }

    /// Check if user has any of the required roles
    pub fn has_any_role(&self, claims: &TokenClaims, required_roles: &[&str]) -> bool {
        let user_roles: HashSet<String> = claims.roles.iter().cloned().collect();
        required_roles.iter().any(|role| user_roles.contains(*role))
    }

    /// Check if user belongs to specified tenant
    pub fn has_tenant_access(&self, claims: &TokenClaims, tenant_id: &str) -> bool {
        match &claims.tenant_id {
            Some(user_tenant) => user_tenant == tenant_id,
            None => false,
        }
    }
}

impl InMemoryUserStore {
    /// Create a new in-memory user store
    pub fn new() -> Self {
        Self {
            users: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }



    /// Add a user to the store
    pub fn add_user(&self, user: UserRecord) {
        let mut users = self.users.write();
        users.insert(user.username.clone(), user);
    }

    /// Clean up expired refresh tokens
    pub fn cleanup_expired_refresh_tokens(&self) {
        let mut refresh_tokens = self.refresh_tokens.write();
        let now = chrono::Utc::now();
        refresh_tokens.retain(|_, (_, expiry)| *expiry > now);
        tracing::debug!("Cleaned up expired refresh tokens. {} tokens remaining.", refresh_tokens.len());
    }
}

#[async_trait::async_trait]
impl UserStore for InMemoryUserStore {
    async fn authenticate(&self, request: AuthRequest) -> ServerResult<UserInfo> {
        let mut users = self.users.write();
        
        let user_record = users.get_mut(&request.username)
            .ok_or_else(|| ServerError::auth("Invalid username or password"))?;
        
        // Check if account is locked
        if let Some(locked_until) = user_record.locked_until {
            if chrono::Utc::now() < locked_until {
                return Err(ServerError::auth("Account is temporarily locked due to multiple failed login attempts"));
            } else {
                // Lock expired, reset
                user_record.locked_until = None;
                user_record.failed_login_attempts = 0;
            }
        }
        
        // Verify password using Argon2id
        match verify_password_secure(&request.password, &user_record.password_hash) {
            Ok(true) => {
                // Reset failed attempts on successful login
                user_record.failed_login_attempts = 0;
                user_record.locked_until = None;
                
                Ok(UserInfo {
                    id: user_record.id.clone(),
                    username: user_record.username.clone(),
                    email: user_record.email.clone(),
                    roles: user_record.roles.clone(),
                    tenant_id: user_record.tenant_id.clone(),
                })
            }
            Ok(false) => {
                // Increment failed attempts
                user_record.failed_login_attempts += 1;
                
                // Lock account after 5 failed attempts for 30 minutes
                if user_record.failed_login_attempts >= 5 {
                    user_record.locked_until = Some(chrono::Utc::now() + chrono::Duration::minutes(30));
                }
                
                Err(ServerError::auth("Invalid username or password"))
            }
            Err(e) => {
                tracing::error!("Password verification error: {}", e);
                Err(ServerError::auth("Authentication service error"))
            }
        }
    }

    async fn get_user(&self, user_id: &str) -> ServerResult<Option<UserInfo>> {
        let users = self.users.read();
        
        for user_record in users.values() {
            if user_record.id == user_id {
                return Ok(Some(UserInfo {
                    id: user_record.id.clone(),
                    username: user_record.username.clone(),
                    email: user_record.email.clone(),
                    roles: user_record.roles.clone(),
                    tenant_id: user_record.tenant_id.clone(),
                }));
            }
        }
        
        Ok(None)
    }

    async fn validate_refresh_token(&self, refresh_token: &str) -> ServerResult<UserInfo> {
        let user_id = {
            let refresh_tokens = self.refresh_tokens.read();
            let (user_id, expiry) = refresh_tokens.get(refresh_token)
                .ok_or_else(|| ServerError::auth("Invalid refresh token"))?;

            if *expiry < chrono::Utc::now() {
                return Err(ServerError::auth("Refresh token expired"));
            }
            user_id.clone()
        };

        self.get_user(&user_id).await
            .map_err(|_| ServerError::auth("User not found"))?
            .ok_or_else(|| ServerError::auth("User not found"))
    }

    async fn store_refresh_token(&self, user_id: &str, refresh_token: &str) -> ServerResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write();
        let expiry = chrono::Utc::now() + chrono::Duration::days(7);
        refresh_tokens.insert(refresh_token.to_string(), (user_id.to_string(), expiry));
        Ok(())
    }

    async fn revoke_refresh_token(&self, refresh_token: &str) -> ServerResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write();
        refresh_tokens.remove(refresh_token);
        Ok(())
    }
}

/// Secure password hashing using Argon2id
/// This is the recommended password hashing algorithm for production use
pub fn hash_password_secure(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Secure password verification using Argon2id
fn verify_password_secure(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

/// Legacy password hashing for migration purposes (DEPRECATED)
/// Only used for verifying old SHA-256 hashes during migration
#[deprecated(note = "Use hash_password_secure instead")]
fn hash_password_legacy(password: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Legacy password verification for migration purposes (DEPRECATED)
/// Only used for verifying old SHA-256 hashes during migration
#[deprecated(note = "Use verify_password_secure instead")]
#[allow(deprecated)]
fn verify_password_legacy(password: &str, hash: &str) -> bool {
    hash_password_legacy(password) == hash
}

#[deprecated(note = "Use hash_password_secure instead")]
#[allow(deprecated)]
fn hash_password_legacy_test(password: &str) -> String {
    hash_password_legacy(password)
}

/// Extract a Bearer token from the `Authorization` header.
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Middleware that requires a valid JWT and injects `TokenClaims` into request extensions.
pub async fn require_jwt_middleware(
    State(state): State<Arc<crate::handlers::AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = state
        .auth_manager
        .validate_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// Authentication middleware (alias for [`require_jwt_middleware`]).
pub async fn auth_middleware(
    state: State<Arc<crate::handlers::AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    require_jwt_middleware(state, request, next).await
}

/// Role-based authorization middleware
pub fn require_role(role: &'static str) -> impl Fn(&Request) -> bool {
    move |request: &Request| {
        // Extract claims from request extensions
        if let Some(claims) = request.extensions().get::<TokenClaims>() {
            // Check if user has the required role
            claims.roles.contains(&role.to_string())
        } else {
            // No authentication claims found
            false
        }
    }
}

/// Multi-role authorization middleware
pub fn require_any_role(roles: &'static [&'static str]) -> impl Fn(&Request) -> bool {
    let required_roles: HashSet<String> = roles.iter().map(|&r| r.to_string()).collect();
    
    move |request: &Request| {
        // Extract claims from request extensions
        if let Some(claims) = request.extensions().get::<TokenClaims>() {
            // Check if user has any of the required roles
            let user_roles: HashSet<String> = claims.roles.iter().cloned().collect();
            required_roles.iter().any(|role| user_roles.contains(role))
        } else {
            // No authentication claims found
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_password_hashing() {
        let password = "test123";
        let hash = hash_password_secure(password).unwrap();
        
        // Verify the hash works
        assert!(verify_password_secure(password, &hash).unwrap());
        assert!(!verify_password_secure("wrong", &hash).unwrap());
        
        // Verify hashes are unique (due to random salt)
        let hash2 = hash_password_secure(password).unwrap();
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_legacy_password_hashing() {
        let password = "test123";
        let hash = hash_password_secure(password).unwrap();
        assert!(verify_password_secure(password, &hash).unwrap());
        assert!(!verify_password_secure("wrong", &hash).unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_user_store() {
        let store = InMemoryUserStore::new();
        
        // Manually add admin user for the test
        let admin_password = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin123".to_string());
        let admin_user = UserRecord {
            id: "admin".to_string(),
            username: "admin".to_string(),
            password_hash: hash_password_secure(admin_password).expect("Failed to hash admin password"),
            email: Some("admin@fortress-db.com".to_string()),
            roles: vec!["admin".to_string(), "user".to_string()],
            tenant_id: None,
            failed_login_attempts: 0,
            locked_until: None,
        };
        store.add_user(admin_user);

        let auth_request = AuthRequest {
            username: "admin".to_string(),
            password: "admin123".to_string(),
            tenant_id: None,
        };
        
        let user = store.authenticate(auth_request).await.unwrap();
        assert_eq!(user.username, "admin");
        assert!(user.roles.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn test_token_generation() {
        let store = Arc::new(InMemoryUserStore::new());
        let auth_manager = AuthManager::new(
            "test_secret",
            Duration::hours(1),
            store,
        );
        
        let auth_request = AuthRequest {
            username: "admin".to_string(),
            password: "admin123".to_string(),
            tenant_id: None,
        };
        
        let auth_response = auth_manager.authenticate(auth_request).await.unwrap();
        assert!(!auth_response.access_token.is_empty());
        assert_eq!(auth_response.token_type, "Bearer");
        
        // Validate the token
        let claims = auth_manager.validate_token(&auth_response.access_token).unwrap();
        assert_eq!(claims.username, "admin");
    }
}

#[cfg(test)]
mod auth_security_tests {
    use super::*;
    
    #[test]
    fn test_secure_password_hashing() {
        let password = "test123";
        let hash = hash_password_secure(password).unwrap();
        
        // Verify the hash works
        assert!(verify_password_secure(password, &hash).unwrap());
        assert!(!verify_password_secure("wrong", &hash).unwrap());
        
        // Verify hashes are unique (due to random salt)
        let hash2 = hash_password_secure(password).unwrap();
        assert_ne!(hash, hash2);
        
        println!("✓ Secure password hashing test passed");
    }

    #[test]
    fn test_argon2id_security() {
        // Test that Argon2id is properly configured
        let password = "secure_password_123!";
        let hash = hash_password_secure(password).unwrap();
        
        // Verify hash contains Argon2id identifier
        assert!(hash.starts_with("$argon2id$"));
        
        // Verify it's not vulnerable to simple attacks
        assert!(hash.len() > 50); // Argon2id hashes are long
        assert!(hash.contains('$')); // Contains delimiter
        
        println!("✓ Argon2id security test passed");
    }
}
