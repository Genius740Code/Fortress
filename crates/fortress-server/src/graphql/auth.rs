//! Enhanced authentication and authorization for GraphQL API
//!
//! Implements JWT-based authentication, role-based access control,
//! session management, and comprehensive security policies.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use async_graphql::{Result, Error, ErrorExtensions};
use jsonwebtoken::{encode, decode, Validation, Algorithm, Header, DecodingKey, EncodingKey};
use uuid::Uuid;
use regex::Regex;
use once_cell::sync::Lazy;
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{rand_core::OsRng, SaltString}
};

/// JWT token claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub exp: usize,        // Expiration time
    pub iat: usize,        // Issued at
    pub iss: String,        // Issuer
    pub aud: String,        // Audience
    pub jti: String,        // JWT ID
    pub roles: Vec<String>, // User roles
    pub permissions: Vec<String>, // Specific permissions
    pub tenant_id: Option<String>, // Multi-tenant support
    pub session_id: String, // Session identifier
    pub device_id: Option<String>, // Device fingerprint
    pub ip_address: String, // Client IP address
    pub user_agent: String,  // Client user agent
}

/// User information for GraphQL context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub tenant_id: Option<String>,
    pub session_id: String,
    pub last_login: Option<usize>,
    pub device_id: Option<String>,
    pub metadata: serde_json::Value,
}

/// Role definition with permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub is_system_role: bool,
    pub tenant_id: Option<String>,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub description: String,
    pub resource: String,
    pub action: String,
    pub is_system_permission: bool,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: usize,
    pub expires_at: usize,
    pub last_activity: usize,
    pub ip_address: String,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub is_active: bool,
    pub metadata: serde_json::Value,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiration: Duration,
    pub session_timeout: Duration,
    pub max_sessions_per_user: usize,
    pub password_policy: PasswordPolicy,
    pub enable_multi_factor_auth: bool,
    pub enable_device_tracking: bool,
    pub enable_ip_whitelist: bool,
    pub allowed_origins: Vec<String>,
    pub blocked_ips: Vec<String>,
}

/// Password policy for authentication
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum password length
    pub min_length: usize,
    /// Require uppercase letters
    pub require_uppercase: bool,
    /// Require lowercase letters
    pub require_lowercase: bool,
    /// Require numbers
    pub require_numbers: bool,
    /// Require special symbols
    pub require_symbols: bool,
    /// Forbidden password patterns
    pub forbidden_patterns: Vec<String>,
    /// Maximum password age in days
    pub max_age_days: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "your-secret-key".to_string(), // Should be from environment
            jwt_expiration: Duration::from_secs(3600), // 1 hour
            session_timeout: Duration::from_secs(1800), // 30 minutes
            max_sessions_per_user: 5,
            password_policy: PasswordPolicy {
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_symbols: true,
                forbidden_patterns: vec!["password".to_string(), "123456".to_string(), "qwerty".to_string()],
                max_age_days: 90,
            },
            enable_multi_factor_auth: false,
            enable_device_tracking: true,
            enable_ip_whitelist: false,
            allowed_origins: vec!["*".to_string()],
            blocked_ips: Vec::new(),
        }
    }
}

/// Authentication manager
pub struct AuthManager {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    users: Arc<RwLock<HashMap<String, AuthenticatedUser>>>,
    roles: Arc<RwLock<HashMap<String, Role>>>,
    permissions: Arc<RwLock<HashMap<String, Permission>>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    device_fingerprints: Arc<RwLock<HashMap<String, String>>>,
    ip_whitelist: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new(config: AuthConfig) -> Result<Self> {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Ok(Self {
            config,
            encoding_key,
            decoding_key,
            users: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            permissions: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            device_fingerprints: Arc::new(RwLock::new(HashMap::new())),
            ip_whitelist: Arc::new(RwLock::new(std::collections::HashSet::new())),
        })
    }

    /// Authenticate user with credentials
    pub async fn authenticate(&self, username: &str, password: &str, ip_address: &str, user_agent: &str) -> Result<AuthResult> {
        // Check IP whitelist if enabled
        if self.config.enable_ip_whitelist {
            let whitelist = self.ip_whitelist.read().await;
            if !whitelist.contains(ip_address) {
                return Ok(AuthResult::Failed {
                    reason: "IP address not whitelisted".to_string(),
                });
            }
        }

        // Check if user exists and password is correct (simplified for demo)
        let users = self.users.read().await;
        let user = users.get(username);

        if let Some(user) = user {
            if self.verify_password(password, user).unwrap_or(false) {
                // Create session
                let session_id = Uuid::new_v4().to_string();
                let device_fingerprint = self.generate_device_fingerprint(user_agent, ip_address);
                
                let session = Session {
                    id: session_id.clone(),
                    user_id: user.id.clone(),
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as usize,
                    expires_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as usize + self.config.session_timeout.as_secs() as usize,
                    last_activity: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as usize,
                    ip_address: ip_address.to_string(),
                    user_agent: user_agent.to_string(),
                    device_fingerprint: device_fingerprint.clone(),
                    is_active: true,
                    metadata: serde_json::json!({
                        "login_time": SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }),
                };

                // Store session
                let mut sessions = self.sessions.write().await;
                sessions.insert(session_id.clone(), session);

                // Store device fingerprint
                let mut fingerprints = self.device_fingerprints.write().await;
                fingerprints.insert(user.id.clone(), device_fingerprint);

                // Update user last login
                let mut users = self.users.write().await;
                if let Some(user) = users.get_mut(username) {
                    user.last_login = Some(SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as usize);
                }

                // Generate JWT token
                let token = self.generate_jwt_token(user, &session_id, ip_address, user_agent)?;

                return Ok(AuthResult::Success {
                    token,
                    user: user.clone(),
                    session_id,
                    expires_in: self.config.jwt_expiration.as_secs(),
                });
            }
        }

        Ok(AuthResult::Failed {
            reason: "Invalid credentials".to_string(),
        })
    }

    /// Verify JWT token and return user information
    pub async fn verify_token(&self, token: &str, ip_address: &str, user_agent: &str) -> Result<TokenVerificationResult> {
        // Decode and validate JWT
        let _now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::new(Algorithm::HS256))
            .map_err(|_| Error::new("Invalid token").extend_with(|_, e| e.set("code", "INVALID_TOKEN")))?;

        // Check expiration
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if token_data.claims.exp < current_time as usize {
            return Ok(TokenVerificationResult::Expired);
        }

        // Check if session is still valid
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&token_data.claims.session_id) {
            if !session.is_active || session.expires_at < current_time as usize {
                return Ok(TokenVerificationResult::SessionExpired);
            }

            // Check IP address and user agent (if device tracking is enabled)
            if self.config.enable_device_tracking {
                let fingerprints = self.device_fingerprints.read().await;
                let expected_fingerprint = fingerprints.get(&token_data.claims.sub);
                
                if let Some(expected) = expected_fingerprint {
                    let current_fingerprint = self.generate_device_fingerprint(user_agent, ip_address);
                    if current_fingerprint != *expected {
                        return Ok(TokenVerificationResult::DeviceMismatch);
                    }
                }
            }

            // Get user information
            let users = self.users.read().await;
            if let Some(user) = users.get(&token_data.claims.sub) {
                Ok(TokenVerificationResult::Valid {
                    user: user.clone(),
                    claims: token_data.claims,
                    session: session.clone(),
                })
            } else {
                Ok(TokenVerificationResult::UserNotFound)
            }
        } else {
            Ok(TokenVerificationResult::SessionExpired)
        }
    }

    /// Refresh JWT token
    pub async fn refresh_token(&self, token: &str, ip_address: &str, user_agent: &str) -> Result<TokenRefreshResult> {
        let verification = self.verify_token(token, ip_address, user_agent).await?;

        match verification {
            TokenVerificationResult::Valid { user, claims: _, session } => {
                // Check if session is still valid for refresh
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if session.expires_at.saturating_sub(now as usize) < 300 { // Only allow refresh if session has more than 5 minutes left
                    return Ok(TokenRefreshResult::SessionTooOld);
                }

                // Generate new token
                let new_token = self.generate_jwt_token(&user, &session.id, ip_address, user_agent)?;

                // Update session activity
                let mut sessions = self.sessions.write().await;
                if let Some(session) = sessions.get_mut(&session.id) {
                    session.last_activity = now as usize;
                }

                Ok(TokenRefreshResult::Success {
                    token: new_token,
                    expires_in: self.config.jwt_expiration.as_secs(),
                })
            }
            _ => Ok(TokenRefreshResult::Failed {
                reason: "Token verification failed".to_string(),
            }),
        }
    }

    /// Logout user (invalidate session)
    pub async fn logout(&self, token: &str) -> Result<()> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::new(Algorithm::HS256))
            .map_err(|_| Error::new("Invalid token").extend_with(|_, e| e.set("code", "INVALID_TOKEN")))?;

        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&token_data.claims.session_id) {
            session.is_active = false;
        }

        Ok(())
    }

    /// Invalidate all user sessions
    pub async fn invalidate_user_sessions(&self, user_id: &str) -> Result<()> {
        let sessions = self.sessions.read().await;
        let session_ids: Vec<String> = sessions
            .values()
            .filter(|s| s.user_id == user_id)
            .map(|s| s.id.clone())
            .collect();

        drop(sessions);

        let mut sessions = self.sessions.write().await;
        for session_id in session_ids {
            if let Some(session) = sessions.get_mut(&session_id) {
                session.is_active = false;
            }
        }

        Ok(())
    }

    /// Check if user has required role
    pub fn has_role(&self, user: &AuthenticatedUser, required_role: &str) -> bool {
        user.roles.contains(&required_role.to_string())
    }

    /// Check if user has any of the required roles
    pub fn has_any_role(&self, user: &AuthenticatedUser, required_roles: &[&str]) -> bool {
        required_roles.iter().any(|role| user.roles.contains(&role.to_string()))
    }

    /// Check if user has required permission
    pub fn has_permission(&self, user: &AuthenticatedUser, required_permission: &str) -> bool {
        user.permissions.contains(&required_permission.to_string())
    }

    /// Check if user can access resource
    pub async fn can_access_resource(&self, user: &AuthenticatedUser, resource: &str, action: &str) -> bool {
        // Check specific permission
        let permission = format!("{}:{}", resource, action);
        if self.has_permission(user, &permission) {
            return true;
        }

        // Check role-based permissions
        let roles = self.roles.read().await;
        for role_name in &user.roles {
            if let Some(role) = roles.get(role_name) {
                for permission in &role.permissions {
                    if permission.starts_with(&format!("{}:", resource)) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Generate JWT token
    fn generate_jwt_token(&self, user: &AuthenticatedUser, session_id: &str, ip_address: &str, user_agent: &str) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let claims = Claims {
            sub: user.id.clone(),
            exp: (now + self.config.jwt_expiration.as_secs()) as usize,
            iat: now as usize,
            iss: "fortress-api".to_string(),
            aud: "fortress-client".to_string(),
            jti: Uuid::new_v4().to_string(),
            roles: user.roles.clone(),
            permissions: user.permissions.clone(),
            tenant_id: user.tenant_id.clone(),
            session_id: session_id.to_string(),
            device_id: user.device_id.clone(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| Error::new(format!("Failed to generate token: {}", e))
                .extend_with(|_, e| e.set("code", "TOKEN_GENERATION_FAILED")))
    }

    /// Verify password using Argon2id
    fn verify_password(&self, password: &str, user: &AuthenticatedUser) -> Result<bool> {
        // Get stored password hash from user metadata
        let stored_hash = user.metadata.get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::new("Password hash not found")
                .extend_with(|_, e| e.set("code", "PASSWORD_HASH_MISSING")))?;
        
        // Verify using Argon2id
        match verify_password_secure(password, stored_hash) {
            Ok(is_valid) => Ok(is_valid),
            Err(e) => {
                tracing::error!("Password verification error: {}", e);
                Err(Error::new("Password verification failed")
                    .extend_with(|_, e| e.set("code", "PASSWORD_VERIFICATION_ERROR")))
            }
        }
    }

    /// Create a new user with secure password hashing
    pub async fn create_user(&self, username: &str, password: &str, email: &str, roles: Vec<String>) -> Result<AuthenticatedUser> {
        let user_id = Uuid::new_v4().to_string();
        let password_hash = hash_password_secure(password)
            .map_err(|e| Error::new(format!("Failed to hash password: {}", e))
                .extend_with(|_, e| e.set("code", "PASSWORD_HASHING_FAILED")))?;
        
        let user = AuthenticatedUser {
            id: user_id.clone(),
            username: username.to_string(),
            email: email.to_string(),
            roles,
            permissions: vec![],
            tenant_id: None,
            session_id: String::new(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({
                "password_hash": password_hash
            }),
        };
        
        self.upsert_user(user.clone()).await?;
        Ok(user)
    }

    /// Generate device fingerprint
    fn generate_device_fingerprint(&self, user_agent: &str, ip_address: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        user_agent.hash(&mut hasher);
        ip_address.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Add or update user
    pub async fn upsert_user(&self, user: AuthenticatedUser) -> Result<()> {
        let mut users = self.users.write().await;
        users.insert(user.id.clone(), user);
        Ok(())
    }

    /// Add or update role
    pub async fn upsert_role(&self, role: Role) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles.insert(role.id.clone(), role);
        Ok(())
    }

    /// Add or update permission
    pub async fn upsert_permission(&self, permission: Permission) -> Result<()> {
        let mut permissions = self.permissions.write().await;
        permissions.insert(permission.id.clone(), permission);
        Ok(())
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: &str) -> Option<AuthenticatedUser> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// Get role by ID
    pub async fn get_role(&self, role_id: &str) -> Option<Role> {
        let roles = self.roles.read().await;
        roles.get(role_id).cloned()
    }

    /// Get permission by ID
    pub async fn get_permission(&self, permission_id: &str) -> Option<Permission> {
        let permissions = self.permissions.read().await;
        permissions.get(permission_id).cloned()
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();
        
        sessions.retain(|_, session| session.expires_at > now as usize && session.is_active);

        Ok(initial_count - sessions.len())
    }

    /// Get session statistics
    pub async fn get_session_stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let active_sessions = sessions.values()
            .filter(|s| s.is_active && s.expires_at > now as usize)
            .count();

        let expired_sessions = sessions.values()
            .filter(|s| !s.is_active || s.expires_at <= now as usize)
            .count();

        SessionStats {
            total_sessions: sessions.len(),
            active_sessions,
            expired_sessions,
            max_sessions_per_user: self.config.max_sessions_per_user,
        }
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication succeeded with user information and token
    Success {
        /// Authenticated user information
        user: AuthenticatedUser,
        /// JWT access token
        token: String,
        /// Session identifier
        session_id: String,
        /// Token expiration time in seconds
        expires_in: u64,
    },
    /// Authentication failed with reason
    Failed {
        /// Reason for authentication failure
        reason: String,
    },
}

/// Token verification result
#[derive(Debug, Clone)]
pub enum TokenVerificationResult {
    /// Token is valid and contains valid user information
    Valid {
        /// Authenticated user information
        user: AuthenticatedUser,
        /// JWT claims extracted from token
        claims: Claims,
        /// Session information
        session: Session,
    },
    /// Token has expired
    Expired,
    /// Session associated with token has expired
    SessionExpired,
    /// Device fingerprint mismatch
    DeviceMismatch,
    /// User not found in system
    UserNotFound,
    /// Token is invalid or malformed
    Invalid,
}

/// Token refresh result
#[derive(Debug, Clone)]
pub enum TokenRefreshResult {
    /// Token refresh succeeded
    Success {
        /// New JWT access token
        token: String,
        /// New token expiration time in seconds
        expires_in: u64,
    },
    /// Token refresh failed
    Failed {
        /// Reason for refresh failure
        reason: String,
    },
    /// Session is too old to be refreshed
    SessionTooOld,
}

/// Session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    /// Total number of sessions
    pub total_sessions: usize,
    /// Currently active sessions
    pub active_sessions: usize,
    /// Expired sessions
    pub expired_sessions: usize,
    /// Maximum allowed sessions per user
    pub max_sessions_per_user: usize,
}

/// Secure password hashing using Argon2id
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

/// Security policy enforcement
pub struct SecurityPolicy {
    auth_manager: Arc<AuthManager>,
    policies: Arc<RwLock<Vec<SecurityPolicyRule>>>,
}

/// Security policy rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicyRule {
    /// Unique identifier for the policy rule
    pub id: String,
    /// Human-readable name for the policy
    pub name: String,
    /// Detailed description of what the policy does
    pub description: String,
    /// Conditions that must be met for this policy to apply
    pub conditions: Vec<PolicyCondition>,
    /// Actions to take when policy conditions are met
    pub actions: Vec<PolicyAction>,
    /// Priority of this rule (higher numbers have higher priority)
    pub priority: u32,
    /// Whether this policy rule is currently enabled
    pub enabled: bool,
}

/// Policy condition types for security rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// Condition based on user role
    UserRole {
        /// Role name to check against
        role: String,
        /// Comparison operator for the role check
        operator: ComparisonOperator,
    },
    /// Condition based on resource access
    Resource {
        /// Resource pattern or identifier
        resource: String,
        /// Comparison operator for resource matching
        operator: ComparisonOperator,
    },
    /// Time-based access restriction
    TimeRestriction {
        /// Start hour (24-hour format)
        start_hour: u32,
        /// End hour (24-hour format)
        end_hour: u32,
        /// Days of week when restriction applies (0=Sunday, 6=Saturday)
        days_of_week: Vec<u8>,
    },
    /// IP address whitelist
    IpWhitelist {
        /// List of allowed IP addresses
        ips: Vec<String>,
    },
    /// IP address blacklist
    IpBlacklist {
        /// List of blocked IP addresses
        ips: Vec<String>,
    },
}

/// Comparison operators for policy conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    /// Exact equality match
    Equals,
    /// Not equal match
    NotEquals,
    /// Contains substring
    Contains,
    /// Does not contain substring
    NotContains,
    /// Starts with pattern
    StartsWith,
    /// Ends with pattern
    EndsWith,
    /// Value is in a set of allowed values
    In,
    /// Value is not in a set of prohibited values
    NotIn,
}

/// Policy actions that can be taken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow the requested action
    Allow,
    /// Deny the requested action
    Deny,
    /// Require multi-factor authentication
    RequireMFA,
    /// Log an alert but allow the action
    LogAlert,
    /// Require approval before allowing the action
    RequireApproval,
}

impl SecurityPolicy {
    /// Create a new security policy instance
    pub fn new(auth_manager: Arc<AuthManager>) -> Self {
        Self {
            auth_manager,
            policies: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add security policy rule
    pub async fn add_policy(&self, policy: SecurityPolicyRule) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.push(policy);
        Ok(())
    }

    /// Evaluate security policies for a request
    pub async fn evaluate_request(&self, user: &AuthenticatedUser, resource: &str, action: &str, context: &SecurityContext) -> PolicyEvaluationResult {
        let policies = self.policies.read().await;
        
        let mut results = Vec::new();
        
        for policy in policies.iter().filter(|p| p.enabled) {
            if let Some(result) = self.evaluate_policy_rule(policy, user, resource, action, context) {
                results.push(result);
            }
        }

        // Sort by evaluation result type (Deny results first)
        results.sort_by(|a, b| {
            match (a, b) {
                (PolicyEvaluationResult::Deny { .. }, PolicyEvaluationResult::Allow) => std::cmp::Ordering::Less,
                (PolicyEvaluationResult::Allow, PolicyEvaluationResult::Deny { .. }) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            }
        });

        // Return the highest priority non-allow result
        for result in results {
            if !matches!(result, PolicyEvaluationResult::Allow) {
                return result;
            }
        }

        PolicyEvaluationResult::Allow
    }

    fn evaluate_policy_rule(&self, policy: &SecurityPolicyRule, user: &AuthenticatedUser, resource: &str, _action: &str, context: &SecurityContext) -> Option<PolicyEvaluationResult> {
        let mut conditions_met = Vec::new();
        let mut _action = "";

        for condition in &policy.conditions {
            let met = match condition {
                PolicyCondition::UserRole { role, operator } => {
                    self.evaluate_condition(&user.roles, role, operator)
                }
                PolicyCondition::Resource { resource: resource_pattern, operator } => {
                    self.evaluate_condition(&[resource.to_string()], resource_pattern, operator)
                }
                PolicyCondition::TimeRestriction { start_hour, end_hour, days_of_week } => {
                    self.evaluate_time_restriction(*start_hour, *end_hour, days_of_week, context.timestamp)
                }
                PolicyCondition::IpWhitelist { ips } => {
                    ips.contains(&context.ip_address)
                }
                PolicyCondition::IpBlacklist { ips } => {
                    ips.contains(&context.ip_address)
                }
            };
            
            conditions_met.push(met);
        }

        // All conditions must be met for the policy to apply
        let all_conditions_met = conditions_met.iter().all(|&met| met);

        if all_conditions_met {
            // Return the first action that applies
            for action in &policy.actions {
                let result = match action {
                    PolicyAction::Allow => PolicyEvaluationResult::Allow,
                    PolicyAction::Deny => PolicyEvaluationResult::Deny {
                        reason: format!("Denied by policy: {}", policy.name),
                        policy_id: policy.id.clone(),
                    },
                    PolicyAction::RequireMFA => PolicyEvaluationResult::RequireMFA {
                        reason: format!("Multi-factor authentication required by policy: {}", policy.name),
                        policy_id: policy.id.clone(),
                    },
                    PolicyAction::LogAlert => PolicyEvaluationResult::LogAlert {
                        reason: format!("Alert triggered by policy: {}", policy.name),
                        policy_id: policy.id.clone(),
                    },
                    PolicyAction::RequireApproval => PolicyEvaluationResult::RequireApproval {
                        reason: format!("Approval required by policy: {}", policy.name),
                        policy_id: policy.id.clone(),
                    },
                };
                return Some(result);
            }
        }

        None
    }

    fn evaluate_condition(&self, values: &[String], target: &str, operator: &ComparisonOperator) -> bool {
        match operator {
            ComparisonOperator::Equals => values.contains(&target.to_string()),
            ComparisonOperator::NotEquals => !values.contains(&target.to_string()),
            ComparisonOperator::Contains => values.iter().any(|v| v.contains(target)),
            ComparisonOperator::NotContains => !values.iter().any(|v| v.contains(target)),
            ComparisonOperator::StartsWith => values.iter().any(|v| v.starts_with(target)),
            ComparisonOperator::EndsWith => values.iter().any(|v| v.ends_with(target)),
            ComparisonOperator::In => values.iter().any(|v| v == target),
            ComparisonOperator::NotIn => !values.iter().any(|v| v == target),
        }
    }

    fn evaluate_time_restriction(&self, start_hour: u32, end_hour: u32, days_of_week: &[u8], timestamp: u64) -> bool {
        use chrono::{DateTime, Utc, Datelike, Timelike};
        
        let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0);
        let weekday = datetime.map(|dt| dt.weekday().num_days_from_monday() as u8).unwrap_or(0);
        let hour = datetime.map(|dt| dt.hour() as u32).unwrap_or(0);
        
        // Check if current day is allowed
        if !days_of_week.contains(&weekday) {
            return false;
        }

        
        // Check if current hour is within allowed range
        if start_hour <= end_hour {
            hour >= start_hour && hour <= end_hour
        } else {
            hour >= start_hour || hour <= end_hour
        }
    }
}

/// Policy evaluation result
#[derive(Debug, Clone)]
pub enum PolicyEvaluationResult {
    /// Access is allowed
    Allow,
    /// Access is denied
    Deny {
        /// Reason for denial
        reason: String,
        /// ID of the policy that caused the denial
        policy_id: String,
    },
    /// Multi-factor authentication is required
    RequireMFA {
        /// Reason MFA is required
        reason: String,
        /// ID of the policy requiring MFA
        policy_id: String,
    },
    /// Log an alert but allow access
    LogAlert {
        /// Reason for the alert
        reason: String,
        /// ID of the policy triggering the alert
        policy_id: String,
    },
    /// Approval is required before access
    RequireApproval {
        /// Reason approval is required
        reason: String,
        /// ID of the policy requiring approval
        policy_id: String,
    },
}

/// Security context for policy evaluation
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Timestamp when security context was created (Unix timestamp in seconds)
    pub timestamp: u64,
    /// IP address of client making the request
    pub ip_address: String,
    /// User agent string from the client's request headers
    pub user_agent: String,
    /// API endpoint or resource path being accessed
    pub request_path: String,
    /// HTTP method used for the request (GET, POST, PUT, DELETE, etc.)
    pub request_method: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test authentication functionality
    #[tokio::test]
    async fn test_authentication() {
        let config = AuthConfig::default();
        let auth_manager = AuthManager::new(config).unwrap();

        // Create a test user with secure password hashing
        let password_hash = hash_password_secure("password123").unwrap();
        let user = AuthenticatedUser {
            id: "test_user".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read:own".to_string()],
            tenant_id: None,
            session_id: "test_session".to_string(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({
                "password_hash": password_hash
            }),
        };

        auth_manager.upsert_user(user).await.unwrap();

        // Test authentication
        let result = auth_manager.authenticate("testuser", "password123", "127.0.0.1", "Mozilla/5.0").await;
        assert!(matches!(result, Ok(AuthResult::Success { .. })));
    }

    #[tokio::test]
    async fn test_token_verification() {
        let config = AuthConfig::default();
        let auth_manager = AuthManager::new(config).unwrap();

        // Create and authenticate a user with secure password hashing
        let password_hash = hash_password_secure("password123").unwrap();
        let user = AuthenticatedUser {
            id: "test_user".to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read:own".to_string()],
            tenant_id: None,
            session_id: "test_session".to_string(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({
                "password_hash": password_hash
            }),
        };

        auth_manager.upsert_user(user).await.unwrap();
        
        let auth_result = auth_manager.authenticate("testuser", "password123", "127.0.0.1", "Mozilla/5.0").await.unwrap();
        let token = if let AuthResult::Success { token, .. } = auth_result { token } else { panic!("Authentication failed") };

        // Test token verification
        let verification = auth_manager.verify_token(&token, "127.0.0.1", "Mozilla/5.0").await;
        assert!(matches!(verification, Ok(TokenVerificationResult::Valid { .. })));
    }

    #[tokio::test]
    async fn test_role_based_access_control() {
        let config = AuthConfig::default();
        let auth_manager = AuthManager::new(config).unwrap();

        let admin_user = AuthenticatedUser {
            id: "admin_user".to_string(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
            permissions: vec!["read:all".to_string(), "write:all".to_string()],
            tenant_id: None,
            session_id: "admin_session".to_string(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({}),
        };

        let regular_user = AuthenticatedUser {
            id: "regular_user".to_string(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read:own".to_string()],
            tenant_id: None,
            session_id: "user_session".to_string(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({}),
        };

        // Test role-based access
        assert!(auth_manager.has_role(&admin_user, "admin"));
        assert!(!auth_manager.has_role(&regular_user, "admin"));
        assert!(auth_manager.has_any_role(&regular_user, &["user", "guest"]));
        assert!(auth_manager.has_any_role(&admin_user, &["admin", "super_admin"]));

        // Test permission-based access
        assert!(auth_manager.has_permission(&admin_user, "read:all"));
        assert!(!auth_manager.has_permission(&regular_user, "read:all"));
        assert!(auth_manager.has_permission(&regular_user, "read:own"));
    }

    #[tokio::test]
    async fn test_security_policies() {
        let config = AuthConfig::default();
        let auth_manager = Arc::new(AuthManager::new(config).unwrap());
        let security_policy = SecurityPolicy::new(auth_manager);

        // Add a policy that requires admin role for sensitive operations
        let policy = SecurityPolicyRule {
            id: "admin_only".to_string(),
            name: "Admin Only Operations".to_string(),
            description: "Only admins can perform sensitive operations".to_string(),
            conditions: vec![
                PolicyCondition::UserRole {
                    role: "admin".to_string(),
                    operator: ComparisonOperator::Equals,
                },
            ],
            actions: vec![PolicyAction::Deny],
            priority: 100,
            enabled: true,
        };

        security_policy.add_policy(policy).await.unwrap();

        let admin_user = AuthenticatedUser {
            id: "admin_user".to_string(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec!["read:all".to_string()],
            tenant_id: None,
            session_id: "admin_session".to_string(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({}),
        };

        let regular_user = AuthenticatedUser {
            id: "regular_user".to_string(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            roles: vec!["user".to_string()],
            permissions: vec!["read:own".to_string()],
            tenant_id: None,
            session_id: "user_session".to_string(),
            last_login: None,
            device_id: None,
            metadata: serde_json::json!({}),
        };

        let context = SecurityContext {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ip_address: "127.0.0.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            request_path: "/admin/users".to_string(),
            request_method: "POST".to_string(),
        };

        // Admin should be allowed for admin operations
        let result = security_policy.evaluate_request(&admin_user, "/admin/users", "DELETE", &context).await;
        assert!(matches!(result, PolicyEvaluationResult::Allow));

        // Regular user should be denied for admin operations
        let result = security_policy.evaluate_request(&regular_user, "/admin/users", "DELETE", &context).await;
        assert!(matches!(result, PolicyEvaluationResult::Deny { .. }));
    }
}
