//! Authentication and authorization system
//!
//! This module provides JWT-based authentication and role-based authorization
//! for the Fortress REST API.

use crate::error::{ServerError, ServerResult};
use crate::models::{AuthRequest, AuthResponse, RefreshTokenRequest, RefreshTokenResponse, UserInfo};
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

/// In-memory user store for development/testing
pub struct InMemoryUserStore {
    users: Arc<parking_lot::RwLock<HashMap<String, UserRecord>>>,
    refresh_tokens: Arc<parking_lot::RwLock<HashMap<String, String>>>, // token -> user_id
}

/// User record for in-memory store
#[derive(Clone)]
pub struct UserRecord {
    id: String,
    username: String,
    password_hash: String,
    email: Option<String>,
    roles: Vec<String>,
    tenant_id: Option<String>,
    failed_login_attempts: u32,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
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
        let validation = Validation::default();
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
        use rand::Rng;
        let mut token = String::with_capacity(64);
        let mut rng = rand::thread_rng();
        
        for _ in 0..64 {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            token.push(chars[rng.gen_range(0..chars.len())] as char);
        }
        
        token
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

    /// Create a new in-memory user store with default admin user
    /// WARNING: Only for development/testing - change default password in production!
    pub fn with_default_admin() -> Self {
        let mut store = Self::new();
        
        // Create default admin user with secure password hashing
        let admin_password = "admin123"; // Change this in production!
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
        
        {
            let mut users = store.users.write();
            users.insert("admin".to_string(), admin_user);
        }
        
        store
    }

    /// Add a user to the store
    pub fn add_user(&self, user: UserRecord) {
        let mut users = self.users.write();
        users.insert(user.username.clone(), user);
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
            refresh_tokens.get(refresh_token)
                .ok_or_else(|| ServerError::auth("Invalid refresh token"))?
                .clone()
        };
        
        self.get_user(&user_id).await
            .map_err(|_| ServerError::auth("User not found"))?
            .ok_or_else(|| ServerError::auth("User not found"))
    }

    async fn store_refresh_token(&self, user_id: &str, refresh_token: &str) -> ServerResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write();
        refresh_tokens.insert(refresh_token.to_string(), user_id.to_string());
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
fn hash_password_secure(password: &str) -> Result<String, argon2::password_hash::Error> {
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
fn verify_password_legacy(password: &str, hash: &str) -> bool {
    hash_password_legacy(password) == hash
}

#[deprecated(note = "Use hash_password_secure instead")]
fn hash_password_legacy_test(password: &str) -> String {
    hash_password_legacy(password)
}

/// Authentication middleware
pub async fn auth_middleware(
    State(auth_manager): State<Arc<AuthManager>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match auth_manager.validate_token(token) {
                Ok(claims) => {
                    // Add claims to request extensions
                    request.extensions_mut().insert(claims);
                    return Ok(next.run(request).await);
                }
                Err(_) => {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
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
        let hash = hash_password_legacy(password);
        assert!(verify_password_legacy(password, &hash));
        assert!(!verify_password_legacy("wrong", &hash));
    }

    #[tokio::test]
    async fn test_in_memory_user_store() {
        let store = InMemoryUserStore::with_default_admin();
        
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
        
        println!("✅ Secure password hashing test passed");
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
        
        println!("✅ Argon2id security test passed");
    }
}
