//! Authentication and Authorization System
//! 
//! This module provides comprehensive authentication and authorization capabilities
//! for the Fortress system, including user management, role-based access control,
//! and token-based authentication.

use crate::error::FortressError;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{PasswordHash, SaltString};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Unique identifier for a user
pub type UserId = String;

/// Unique identifier for a role
pub type RoleId = String;

/// Unique identifier for a permission
pub type PermissionId = String;

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user
    pub id: UserId,
    /// Username for login
    pub username: String,
    /// Email address
    pub email: String,
    /// User's full name
    pub full_name: String,
    /// Roles assigned to the user
    pub roles: Vec<RoleId>,
    /// Whether the user is active
    pub active: bool,
    /// When the user was created
    pub created_at: u64,
    /// Last login timestamp
    pub last_login: Option<u64>,
    /// Password hash (in production, this would be properly hashed)
    pub password_hash: String,
}

/// Role definition for RBAC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique identifier for the role
    pub id: RoleId,
    /// Role name
    pub name: String,
    /// Role description
    pub description: String,
    /// Permissions granted by this role
    pub permissions: Vec<PermissionId>,
    /// Whether the role is active
    pub active: bool,
    /// When the role was created
    pub created_at: u64,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash)]
pub struct AuthPermission {
    /// Unique identifier for the permission
    pub id: PermissionId,
    /// Permission name
    pub name: String,
    /// Permission description
    pub description: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action this permission grants
    pub action: String,
    /// Whether the permission is active
    pub active: bool,
    /// When the permission was created
    pub created_at: u64,
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Token value
    pub token: String,
    /// User ID this token belongs to
    pub user_id: UserId,
    /// When the token was issued
    pub issued_at: u64,
    /// When the token expires
    pub expires_at: u64,
    /// Token permissions (cached)
    pub permissions: Vec<PermissionId>,
}

/// JWT token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Expiration time
    pub exp: u64,
    /// Issued at
    pub iat: u64,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// OAuth scope
    pub scope: String,
}

/// Login request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Username or email
    pub username: String,
    /// Password
    pub password: String,
    /// Optional device fingerprint
    pub device_fingerprint: Option<String>,
    /// Optional IP address
    pub ip_address: Option<String>,
}

/// Login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    /// Authentication token
    pub token: String,
    /// Token expiration time
    pub expires_at: u64,
    /// User information
    pub user: User,
    /// Session ID
    pub session_id: String,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// User ID this session belongs to
    pub user_id: UserId,
    /// When the session was created
    pub created_at: u64,
    /// When the session expires
    pub expires_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// IP address of the session
    pub ip_address: Option<String>,
    /// User agent of the session
    pub user_agent: Option<String>,
    /// Whether the session is active
    pub active: bool,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Token expiration time in seconds
    pub token_expiration: u64,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Maximum number of sessions per user
    pub max_sessions_per_user: usize,
    /// Whether to enable device fingerprinting
    pub enable_device_fingerprinting: bool,
    /// Password policy
    pub password_policy: PasswordPolicy,
}

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length
    pub min_length: usize,
    /// Require uppercase letters
    pub require_uppercase: bool,
    /// Require lowercase letters
    pub require_lowercase: bool,
    /// Require numbers
    pub require_numbers: bool,
    /// Require special characters
    pub require_special_chars: bool,
    /// Maximum password age in seconds
    pub max_age_seconds: u64,
}

/// Session manager for handling user sessions
#[derive(Debug)]
pub struct SessionManager {
    /// Active sessions
    sessions: HashMap<String, Session>,
    /// User to sessions mapping
    user_sessions: HashMap<UserId, Vec<String>>,
    /// Configuration
    config: AuthConfig,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: AuthConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            user_sessions: HashMap::new(),
            config,
        }
    }

    /// Create a new session
    pub fn create_session(
        &mut self,
        user_id: UserId,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String, FortressError> {
        // Check session limit
        let user_session_count = self.user_sessions.get(&user_id).map(|s| s.len()).unwrap_or(0);
        if user_session_count >= self.config.max_sessions_per_user {
            return Err(FortressError::authentication("Maximum sessions per user exceeded", None));
        }

        let session_id = Uuid::new_v4().to_string();
        let now = current_timestamp();
        let expires_at = now + self.config.session_timeout;

        let session = Session {
            id: session_id.clone(),
            user_id: user_id.clone(),
            created_at: now,
            expires_at,
            last_activity: now,
            ip_address,
            user_agent,
            active: true,
        };

        self.sessions.insert(session_id.clone(), session.clone());
        self.user_sessions
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(session_id.clone());

        Ok(session_id)
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    /// Update session activity
    pub fn update_activity(&mut self, session_id: &str) -> Result<(), FortressError> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| FortressError::authentication("Session not found", None))?;

        // Check if session is expired
        if current_timestamp() > session.expires_at {
            session.active = false;
            return Err(FortressError::authentication("Session expired", None));
        }

        session.last_activity = current_timestamp();
        Ok(())
    }

    /// Invalidate a session
    pub fn invalidate_session(&mut self, session_id: &str) -> Result<(), FortressError> {
        let session = self.sessions.remove(session_id)
            .ok_or_else(|| FortressError::authentication("Session not found", None))?;

        // Remove from user sessions mapping
        if let Some(sessions) = self.user_sessions.get_mut(&session.user_id) {
            sessions.retain(|s| s != session_id);
            if sessions.is_empty() {
                self.user_sessions.remove(&session.user_id);
            }
        }

        Ok(())
    }

    /// Invalidate all sessions for a user
    pub fn invalidate_user_sessions(&mut self, user_id: &UserId) -> Result<usize, FortressError> {
        let session_ids = self.user_sessions.get(user_id).cloned().unwrap_or_default();
        let mut invalidated_count = 0;

        for session_id in session_ids {
            if self.sessions.remove(&session_id).is_some() {
                invalidated_count += 1;
            }
        }

        self.user_sessions.remove(user_id);
        Ok(invalidated_count)
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&mut self) -> usize {
        let now = current_timestamp();
        let mut expired_count = 0;

        let expired_sessions: Vec<String> = self.sessions
            .values()
            .filter(|s| s.expires_at < now)
            .map(|s| s.id.clone())
            .collect();

        for session_id in expired_sessions {
            if let Some(session) = self.sessions.remove(&session_id) {
                // Remove from user sessions mapping
                if let Some(sessions) = self.user_sessions.get_mut(&session.user_id) {
                    sessions.retain(|s| s != &session_id);
                    if sessions.is_empty() {
                        self.user_sessions.remove(&session.user_id);
                    }
                }
                expired_count += 1;
            }
        }

        expired_count
    }
}

/// Authentication and authorization manager
#[derive(Debug)]
pub struct AuthManager {
    /// User storage
    users: HashMap<UserId, User>,
    /// Role storage
    roles: HashMap<RoleId, Role>,
    /// Permission storage
    permissions: HashMap<PermissionId, AuthPermission>,
    /// Active tokens
    tokens: HashMap<String, AuthToken>,
    /// Session manager
    session_manager: SessionManager,
    /// Configuration
    config: AuthConfig,
}

impl AuthManager {
    /// Create a new auth manager
    pub fn new() -> Self {
        let config = AuthConfig {
            token_expiration: 3600, // 1 hour
            session_timeout: 86400, // 24 hours
            max_sessions_per_user: 5,
            enable_device_fingerprinting: true,
            password_policy: PasswordPolicy {
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special_chars: true,
                max_age_seconds: 7776000, // 90 days
            },
        };

        Self {
            users: HashMap::new(),
            roles: HashMap::new(),
            permissions: HashMap::new(),
            tokens: HashMap::new(),
            session_manager: SessionManager::new(config.clone()),
            config,
        }
    }

    /// Create a new user
    pub async fn create_user(
        &mut self,
        username: String,
        password: String,
    ) -> Result<UserId, FortressError> {
        // Validate username
        if username.len() < 3 {
            return Err(FortressError::validation("Username must be at least 3 characters", None, None));
        }

        // Check if username already exists
        if self.users.values().any(|u| u.username == username) {
            return Err(FortressError::validation("Username already exists", None, None));
        }

        // Validate password against policy
        self.validate_password(&password)?;

        // Hash password using Argon2
        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_e| FortressError::encryption("Password hashing failed", "argon2", crate::error::EncryptionErrorCode::EncryptionFailed))?;

        let password_hash = password_hash.to_string();

        let user_id = Uuid::new_v4().to_string();
        let user = User {
            id: user_id.clone(),
            username: username.clone(),
            email: format!("{}@example.com", username),
            full_name: username.clone(),
            roles: Vec::new(),
            active: true,
            created_at: current_timestamp(),
            last_login: None,
            password_hash,
        };

        self.users.insert(user_id.clone(), user);
        Ok(user_id)
    }

    /// Authenticate a user
    pub async fn authenticate(
        &mut self,
        request: LoginRequest,
    ) -> Result<LoginResponse, FortressError> {
        // Find user by username
        let user_id = self.users.values()
            .find(|u| u.username == request.username && u.active)
            .map(|u| u.id.clone())
            .ok_or_else(|| FortressError::authentication("Invalid credentials", None))?;

        // Get user for password verification and update
        let user = self.users.get(&user_id)
            .ok_or_else(|| FortressError::authentication("Invalid credentials", None))?;

        // Verify password using Argon2
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| FortressError::authentication("Invalid password hash format", None))?;
        
        let argon2 = Argon2::default();
        if argon2.verify_password(request.password.as_bytes(), &parsed_hash).is_err() {
            return Err(FortressError::authentication("Invalid credentials", None));
        }

        // Update last login
        let user_id_clone = user_id.clone();
        let _ = user;
        
        if let Some(user) = self.users.get_mut(&user_id_clone) {
            user.last_login = Some(current_timestamp());
        }

        // Create session
        let session_id = self.session_manager.create_session(
            user_id.clone(),
            request.ip_address,
            None, // User agent would be extracted from request headers
        )?;

        // Create token
        let user_for_token = self.users.get(&user_id)
            .ok_or_else(|| FortressError::authentication(
                "User not found after successful authentication",
                Some("race_condition_detected".to_string()),
            ))?;
        let token = self.create_token(user_for_token)?;

        // Store token
        self.tokens.insert(token.token.clone(), token.clone());

        // Get user for response
        let user_for_response = self.users.get(&user_id)
            .ok_or_else(|| FortressError::authentication(
                "User not found after token creation",
                Some("race_condition_detected".to_string()),
            ))?;

        Ok(LoginResponse {
            token: token.token,
            expires_at: token.expires_at,
            user: user_for_response.clone(),
            session_id,
        })
    }

    /// Create an authentication token
    fn create_token(&self, user: &User) -> Result<AuthToken, FortressError> {
        let token_value = Uuid::new_v4().to_string();
        let now = current_timestamp();
        let expires_at = now + self.config.token_expiration;

        // Get user permissions
        let permissions = self.get_user_permissions(&user.id);

        let token = AuthToken {
            token: token_value.clone(),
            user_id: user.id.clone(),
            issued_at: now,
            expires_at,
            permissions: permissions.into_iter().map(|p| p.id.clone()).collect(),
        };

        Ok(token)
    }

    /// Validate a token
    pub fn validate_token(&self, token: &str) -> Result<&User, FortressError> {
        let auth_token = self.tokens.get(token)
            .ok_or_else(|| FortressError::authentication("Invalid token", None))?;

        // Check if token is expired
        if current_timestamp() > auth_token.expires_at {
            return Err(FortressError::authentication("Token expired", None));
        }

        // Get user
        let user = self.users.get(&auth_token.user_id)
            .ok_or_else(|| FortressError::authentication("User not found", None))?;

        if !user.active {
            return Err(FortressError::authentication("User is not active", None));
        }

        Ok(user)
    }

    /// Check if a user has a specific permission
    pub fn user_has_permission(&self, user_id: &UserId, permission_id: &PermissionId) -> bool {
        self.get_user_permissions(user_id)
            .iter()
            .any(|p| p.id == *permission_id)
    }

    /// Get all permissions for a user
    pub fn get_user_permissions(&self, user_id: &UserId) -> Vec<&AuthPermission> {
        let user = match self.users.get(user_id) {
            Some(u) => u,
            None => return Vec::new(),
        };

        let mut permissions = HashSet::new();
        
        for role_id in &user.roles {
            if let Some(role) = self.roles.get(role_id) {
                for permission_id in &role.permissions {
                    if let Some(permission) = self.permissions.get(permission_id) {
                        permissions.insert(permission.id.clone());
                    }
                }
            }
        }

        permissions.into_iter()
            .filter_map(|id| self.permissions.get(&id))
            .collect()
    }

    /// Assign a role to a user
    pub fn assign_role(&mut self, user_id: &UserId, role_id: RoleId) -> Result<(), FortressError> {
        let user = self.users.get_mut(user_id)
            .ok_or_else(|| FortressError::validation("User not found", None, None))?;

        let _role = self.roles.get(&role_id)
            .ok_or_else(|| FortressError::validation("Role not found", None, None))?;

        if !user.roles.contains(&role_id) {
            user.roles.push(role_id);
        }

        Ok(())
    }

    /// Create a role
    pub fn create_role(
        &mut self,
        name: String,
        description: String,
        permissions: Vec<PermissionId>,
    ) -> Result<RoleId, FortressError> {
        let role_id = Uuid::new_v4().to_string();
        let role = Role {
            id: role_id.clone(),
            name,
            description,
            permissions,
            active: true,
            created_at: current_timestamp(),
        };

        self.roles.insert(role_id.clone(), role);
        Ok(role_id)
    }

    /// Create a permission
    pub fn create_permission(
        &mut self,
        name: String,
        description: String,
        resource: String,
        action: String,
    ) -> Result<PermissionId, FortressError> {
        let permission_id = Uuid::new_v4().to_string();
        let permission = AuthPermission {
            id: permission_id.clone(),
            name,
            description,
            resource,
            action,
            active: true,
            created_at: current_timestamp(),
        };

        self.permissions.insert(permission_id.clone(), permission);
        Ok(permission_id)
    }

    /// Check if a user exists
    pub fn user_exists(&self, user_id: &UserId) -> bool {
        self.users.contains_key(user_id)
    }

    /// Get a role by ID
    pub fn get_role(&self, role_id: &RoleId) -> Option<&Role> {
        self.roles.get(role_id)
    }

    /// Get a user by ID
    pub fn get_user(&self, user_id: &UserId) -> Option<&User> {
        self.users.get(user_id)
    }

    /// Validate password against policy
    fn validate_password(&self, password: &str) -> Result<(), FortressError> {
        let policy = &self.config.password_policy;

        if password.len() < policy.min_length {
            return Err(FortressError::validation("Password too short", None, None));
        }

        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(FortressError::validation("Password must contain uppercase letters", None, None));
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(FortressError::validation("Password must contain lowercase letters", None, None));
        }

        if policy.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(FortressError::validation("Password must contain numbers", None, None));
        }

        if policy.require_special_chars && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(FortressError::validation("Password must contain special characters", None, None));
        }

        Ok(())
    }

    /// Logout a user (invalidate token and session)
    pub fn logout(&mut self, token: &str) -> Result<(), FortressError> {
        let _auth_token = self.tokens.remove(token)
            .ok_or_else(|| FortressError::authentication("Invalid token", None))?;

        // Invalidate session (would need session_id from token in real implementation)
        // For now, we'll just remove the token
        
        Ok(())
    }

    /// Get session manager reference
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get mutable session manager reference
    pub fn session_manager_mut(&mut self) -> &mut SessionManager {
        &mut self.session_manager
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current timestamp in seconds since Unix epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_creation() {
        let mut auth = AuthManager::new();
        
        let user_id = auth.create_user("testuser".to_string(), "Password123!".to_string()).await.unwrap();
        
        let user = auth.get_user(&user_id).unwrap();
        assert_eq!(user.username, "testuser");
        assert!(user.active);
    }

    #[tokio::test]
    async fn test_authentication() {
        let mut auth = AuthManager::new();
        
        let user_id = auth.create_user("testuser".to_string(), "Password123!".to_string()).await.unwrap();
        
        let login_request = LoginRequest {
            username: "testuser".to_string(),
            password: "Password123!".to_string(),
            device_fingerprint: None,
            ip_address: Some("127.0.0.1".to_string()),
        };
        
        let response = auth.authenticate(login_request).await.unwrap();
        assert_eq!(response.user.id, user_id);
        assert!(!response.token.is_empty());
    }

    #[tokio::test]
    async fn test_role_assignment() {
        let mut auth = AuthManager::new();
        
        let user_id = auth.create_user("testuser".to_string(), "Password123!".to_string()).await.unwrap();
        
        let permission_id = auth.create_permission(
            "read_data".to_string(),
            "Read data permission".to_string(),
            "data".to_string(),
            "read".to_string(),
        ).unwrap();
        
        let role_id = auth.create_role(
            "data_reader".to_string(),
            "Can read data".to_string(),
            vec![permission_id.clone()],
        ).unwrap();
        
        auth.assign_role(&user_id, role_id.clone()).unwrap();
        
        let user = auth.get_user(&user_id).unwrap();
        assert!(user.roles.contains(&role_id));
        
        assert!(auth.user_has_permission(&user_id, &permission_id));
    }

    #[test]
    fn test_session_management() {
        let config = AuthConfig {
            token_expiration: 3600,
            session_timeout: 86400,
            max_sessions_per_user: 2,
            enable_device_fingerprinting: true,
            password_policy: PasswordPolicy {
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special_chars: true,
                max_age_seconds: 7776000,
            },
        };
        
        let mut session_manager = SessionManager::new(config);
        
        let user_id = "user1".to_string();
        
        let session_id1 = session_manager.create_session(
            user_id.clone(),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).unwrap();
        
        let session_id2 = session_manager.create_session(
            user_id.clone(),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        ).unwrap();
        
        // Should fail due to session limit
        let result = session_manager.create_session(
            user_id.clone(),
            Some("127.0.0.1".to_string()),
            Some("Test Agent".to_string()),
        );
        assert!(result.is_err());
        
        // Get session
        let session = session_manager.get_session(&session_id1).unwrap();
        assert_eq!(session.user_id, user_id);
        
        // Invalidate session
        session_manager.invalidate_session(&session_id1).unwrap();
        assert!(session_manager.get_session(&session_id1).is_none());
    }
}
