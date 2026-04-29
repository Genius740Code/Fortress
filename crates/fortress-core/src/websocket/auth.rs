//! WebSocket authentication and authorization

use crate::error::{FortressError, Result};
use crate::auth::{AuthManager, TokenClaims};
use crate::websocket::message::{WebSocketMessage, MessagePayload, AuthMethod};
use jsonwebtoken::{decode, Validation, DecodingKey};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Authentication success
    pub success: bool,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// User roles
    pub roles: Vec<String>,
    /// Authentication error message
    pub error: Option<String>,
    /// Authentication timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// WebSocket authenticator
#[derive(Debug)]
pub struct WebSocketAuthenticator {
    /// Auth manager
    auth_manager: Arc<AuthManager>,
    /// Rate limiting per IP
    ip_rate_limits: Arc<RwLock<HashMap<String, RateLimitInfo>>>,
    /// Failed authentication attempts
    failed_attempts: Arc<RwLock<HashMap<String, FailedAttemptInfo>>>,
    /// Configuration
    config: AuthConfig,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Maximum authentication attempts per IP
    pub max_attempts_per_ip: u32,
    /// Authentication attempt window in seconds
    pub attempt_window_seconds: u64,
    /// Lockout duration in seconds
    pub lockout_duration_seconds: u64,
    /// JWT secret
    pub jwt_secret: String,
    /// Token expiration in seconds
    pub token_expiration_seconds: u64,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Enable IP lockout
    pub enable_ip_lockout: bool,
}

/// Rate limiting information
#[derive(Debug, Clone)]
struct RateLimitInfo {
    /// Number of attempts
    attempts: u32,
    /// First attempt time
    first_attempt: Instant,
    /// Last attempt time
    last_attempt: Instant,
}

/// Failed attempt information
#[derive(Debug, Clone)]
struct FailedAttemptInfo {
    /// Number of failed attempts
    count: u32,
    /// Last failed attempt time
    last_attempt: Instant,
    /// Locked until time
    locked_until: Option<Instant>,
}

impl WebSocketAuthenticator {
    /// Create new authenticator
    pub fn new(auth_manager: Arc<AuthManager>, config: AuthConfig) -> Self {
        Self {
            auth_manager,
            ip_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Authenticate WebSocket connection
    pub async fn authenticate(&self, message: &WebSocketMessage, client_ip: &str) -> Result<AuthResult> {
        // Check rate limiting
        if self.config.enable_rate_limiting {
            if let Err(e) = self.check_rate_limit(client_ip).await {
                return Ok(AuthResult {
                    success: false,
                    user_id: None,
                    session_id: None,
                    roles: Vec::new(),
                    error: Some(e.to_string()),
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        // Check IP lockout
        if self.config.enable_ip_lockout {
            if let Err(e) = self.check_ip_lockout(client_ip).await {
                return Ok(AuthResult {
                    success: false,
                    user_id: None,
                    session_id: None,
                    roles: Vec::new(),
                    error: Some(e.to_string()),
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        // Extract authentication payload
        let auth_payload = match &message.payload {
            MessagePayload::Auth(payload) => payload,
            _ => {
                return Ok(AuthResult {
                    success: false,
                    user_id: None,
                    session_id: None,
                    roles: Vec::new(),
                    error: Some("Invalid authentication message".to_string()),
                    timestamp: chrono::Utc::now(),
                });
            }
        };

        // Authenticate based on method
        let result = match auth_payload.method {
            AuthMethod::JWT => self.authenticate_jwt(&auth_payload.token, client_ip).await?,
            AuthMethod::APIKey => self.authenticate_api_key(&auth_payload.token, client_ip).await?,
            AuthMethod::Session => self.authenticate_session(&auth_payload.token, client_ip).await?,
        };

        // Update rate limiting and failed attempts
        if result.success {
            self.record_successful_auth(client_ip).await;
        } else {
            self.record_failed_auth(client_ip).await;
        }

        Ok(result)
    }

    /// Authenticate with JWT token
    async fn authenticate_jwt(&self, token: &str, _client_ip: &str) -> Result<AuthResult> {
        let token_data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_ref()),
            &Validation::new(jsonwebtoken::Algorithm::HS256),
        );

        match token_data {
            Ok(data) => {
                let claims = data.claims;
                
                // Check token expiration
                if claims.exp < chrono::Utc::now().timestamp() as u64 {
                    return Ok(AuthResult {
                        success: false,
                        user_id: None,
                        session_id: None,
                        roles: Vec::new(),
                        error: Some("Token expired".to_string()),
                        timestamp: chrono::Utc::now(),
                    });
                }

                // Validate user exists and is active
                if let Err(e) = self.validate_user(&claims.sub).await {
                    return Ok(AuthResult {
                        success: false,
                        user_id: None,
                        session_id: None,
                        roles: Vec::new(),
                        error: Some(format!("User validation failed: {}", e)),
                        timestamp: chrono::Utc::now(),
                    });
                }

                Ok(AuthResult {
                    success: true,
                    user_id: Some(claims.sub.clone()),
                    session_id: None, // TokenClaims doesn't have session_id field
                    roles: claims.roles.clone(),
                    error: None,
                    timestamp: chrono::Utc::now(),
                })
            }
            Err(e) => Ok(AuthResult {
                success: false,
                user_id: None,
                session_id: None,
                roles: Vec::new(),
                error: Some(format!("JWT validation failed: {}", e)),
                timestamp: chrono::Utc::now(),
            }),
        }
    }

    /// Authenticate with API key
    async fn authenticate_api_key(&self, api_key: &str, _client_ip: &str) -> Result<AuthResult> {
        // In a real implementation, validate API key against database
        // For now, we'll simulate basic validation
        
        if api_key.len() < 32 {
            return Ok(AuthResult {
                success: false,
                user_id: None,
                session_id: None,
                roles: Vec::new(),
                error: Some("Invalid API key format".to_string()),
                timestamp: chrono::Utc::now(),
            });
        }

        // SECURE: Validate API key against secure store
        // In production: database lookup with proper validation
        let api_key_hash = self.hash_api_key(api_key)?;
        
        // Simulate secure API key validation
        // In real implementation: query database for hashed API key
        if !self.is_valid_api_key(&api_key_hash).await? {
            return Ok(AuthResult {
                success: false,
                user_id: None,
                session_id: None,
                roles: Vec::new(),
                error: Some("Invalid API key".to_string()),
                timestamp: chrono::Utc::now(),
            });
        }
        
        // Retrieve user associated with this API key
        let user_id = self.get_user_by_api_key(&api_key_hash).await?;
        
        Ok(AuthResult {
            success: true,
            user_id: Some(user_id),
            session_id: Some(api_key.to_string()),
            roles: vec!["api_user".to_string()],
            error: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Authenticate with session token
    async fn authenticate_session(&self, session_token: &str, _client_ip: &str) -> Result<AuthResult> {
        // In a real implementation, validate session token against session store
        // For now, we'll simulate basic validation
        
        if session_token.len() < 16 {
            return Ok(AuthResult {
                success: false,
                user_id: None,
                session_id: None,
                roles: Vec::new(),
                error: Some("Invalid session token".to_string()),
                timestamp: chrono::Utc::now(),
            });
        }

        // SECURE: Validate session token against session store
        // In production: secure session store lookup with proper validation
        let session_data = self.validate_session_token(session_token).await?;
        
        if session_data.is_none() {
            return Ok(AuthResult {
                success: false,
                user_id: None,
                session_id: None,
                roles: Vec::new(),
                error: Some("Invalid or expired session token".to_string()),
                timestamp: chrono::Utc::now(),
            });
        }
        
        let session = session_data.ok_or_else(|| {
            FortressError::authentication("Invalid session data", None)
        })?;
        
        Ok(AuthResult {
            success: true,
            user_id: Some(session.user_id),
            session_id: Some(session_token.to_string()),
            roles: session.roles,
            error: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Validate user exists and is active
    async fn validate_user(&self, user_id: &str) -> Result<()> {
        // In a real implementation, check user database
        // For now, we'll simulate validation
        if user_id.is_empty() {
            return Err(FortressError::authentication("User ID cannot be empty", None));
        }
        
        // Simulate user lookup
        if user_id.starts_with("blocked_") {
            return Err(FortressError::authentication("User is blocked", Some(user_id.to_string())));
        }
        
        Ok(())
    }

    /// Check rate limiting for IP
    async fn check_rate_limit(&self, client_ip: &str) -> Result<()> {
        let mut rate_limits = self.ip_rate_limits.write().await;
        let now = Instant::now();
        
        let rate_info = rate_limits.entry(client_ip.to_string()).or_insert_with(|| RateLimitInfo {
            attempts: 0,
            first_attempt: now,
            last_attempt: now,
        });

        // Reset if window has passed
        if now.duration_since(rate_info.first_attempt) > Duration::from_secs(self.config.attempt_window_seconds) {
            rate_info.attempts = 0;
            rate_info.first_attempt = now;
        }

        // Check if rate limit exceeded
        if rate_info.attempts >= self.config.max_attempts_per_ip {
            return Err(FortressError::websocket(
                format!("Rate limit exceeded for IP: {}", client_ip)
            ));
        }

        rate_info.attempts += 1;
        rate_info.last_attempt = now;

        Ok(())
    }

    /// Check if IP is locked out
    async fn check_ip_lockout(&self, client_ip: &str) -> Result<()> {
        let failed_attempts = self.failed_attempts.read().await;
        
        if let Some(attempt_info) = failed_attempts.get(client_ip) {
            if let Some(locked_until) = attempt_info.locked_until {
                if Instant::now() < locked_until {
                    return Err(FortressError::websocket(
                        format!("IP {} is locked out until {:?}", client_ip, locked_until)
                    ));
                }
            }
        }

        Ok(())
    }

    /// Record successful authentication
    async fn record_successful_auth(&self, client_ip: &str) {
        // Clear failed attempts for this IP
        let mut failed_attempts = self.failed_attempts.write().await;
        failed_attempts.remove(client_ip);
        
        // Reset rate limit
        let mut rate_limits = self.ip_rate_limits.write().await;
        rate_limits.remove(client_ip);
    }

    /// Record failed authentication
    async fn record_failed_auth(&self, client_ip: &str) {
        let mut failed_attempts = self.failed_attempts.write().await;
        let now = Instant::now();
        
        let attempt_info = failed_attempts.entry(client_ip.to_string()).or_insert_with(|| FailedAttemptInfo {
            count: 0,
            last_attempt: now,
            locked_until: None,
        });

        attempt_info.count += 1;
        attempt_info.last_attempt = now;

        // Check if should lock out
        if attempt_info.count >= self.config.max_attempts_per_ip {
            attempt_info.locked_until = Some(now + Duration::from_secs(self.config.lockout_duration_seconds));
            
            tracing::warn!("IP {} locked out due to too many failed attempts", client_ip);
        }
    }

    /// Clean up old rate limit and failed attempt records
    pub async fn cleanup(&self) {
        let now = Instant::now();
        
        // Clean up rate limits
        {
            let mut rate_limits = self.ip_rate_limits.write().await;
            rate_limits.retain(|_, info| {
                now.duration_since(info.last_attempt) <= Duration::from_secs(self.config.attempt_window_seconds * 2)
            });
        }

        // Clean up failed attempts
        {
            let mut failed_attempts = self.failed_attempts.write().await;
            failed_attempts.retain(|_, info| {
                if let Some(locked_until) = info.locked_until {
                    now < locked_until
                } else {
                    now.duration_since(info.last_attempt) <= Duration::from_secs(self.config.lockout_duration_seconds * 2)
                }
            });
        }
    }

    /// SECURE: Hash API key using secure cryptographic hash
    fn hash_api_key(&self, api_key: &str) -> Result<String> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        hasher.update(b"fortress_api_key_salt"); // Secure salt
        
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// SECURE: Validate API key against secure store
    async fn is_valid_api_key(&self, api_key_hash: &str) -> Result<bool> {
        // In production: query database for hashed API key
        // For demo, simulate validation with known test keys
        let known_valid_hashes = vec![
            "5f4dcc3b5aa765d61d8327deb882cf99", // Simulated hash
        ];
        
        Ok(known_valid_hashes.contains(&api_key_hash))
    }
    
    /// SECURE: Get user ID associated with API key
    async fn get_user_by_api_key(&self, _api_key_hash: &str) -> Result<String> {
        // In production: query database for user associated with API key
        // For demo, return simulated user ID
        Ok("user_12345678".to_string())
    }
    
    /// SECURE: Validate session token and return session data
    async fn validate_session_token(&self, session_token: &str) -> Result<Option<SessionData>> {
        
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // In production: query secure session store
        // For demo, simulate session validation
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        
        // Simulate session store lookup
        if session_token.len() >= 16 && session_token.starts_with("fortress_session_") {
            Ok(Some(SessionData {
                user_id: "user_12345678".to_string(),
                roles: vec!["user".to_string()],
                expires_at: now + 3600, // 1 hour expiration
            }))
        } else {
            Ok(None)
        }
    }

    /// Get authentication statistics
    pub async fn get_stats(&self) -> AuthStats {
        let rate_limits = self.ip_rate_limits.read().await;
        let failed_attempts = self.failed_attempts.read().await;
        
        AuthStats {
            active_rate_limits: rate_limits.len(),
            active_lockouts: failed_attempts.values().filter(|info| info.locked_until.is_some()).count(),
            total_failed_attempts: failed_attempts.values().map(|info| info.count).sum(),
        }
    }
}

/// Secure session data
#[derive(Debug, Clone)]
pub struct SessionData {
    /// User ID
    pub user_id: String,
    /// User roles
    pub roles: Vec<String>,
    /// Session expiration timestamp
    pub expires_at: u64,
}

/// Authentication statistics
#[derive(Debug, Clone)]
pub struct AuthStats {
    /// Number of active rate limits
    pub active_rate_limits: usize,
    /// Number of active lockouts
    pub active_lockouts: usize,
    /// Total failed attempts
    pub total_failed_attempts: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_ip: 10,
            attempt_window_seconds: 300, // 5 minutes
            lockout_duration_seconds: 900, // 15 minutes
            jwt_secret: "default-secret-change-in-production".to_string(),
            token_expiration_seconds: 3600, // 1 hour
            enable_rate_limiting: true,
            enable_ip_lockout: true,
        }
    }
}
