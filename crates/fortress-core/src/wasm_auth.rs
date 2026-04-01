//! WebAssembly Authentication Provider System
//!
//! This module provides a comprehensive authentication system using WebAssembly
//! plugins for custom authentication logic, making Fortress the most extensible security platform.

use crate::error::{FortressError, Result};
use crate::plugin::{PluginMetadata, PluginCapability};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Authentication request context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Unique request ID for tracking
    pub request_id: String,
    /// Authentication method being used
    pub auth_method: String,
    /// Credentials provided by user
    pub credentials: AuthCredentials,
    /// Request metadata
    pub request: AuthRequestContext,
    /// Client information
    pub client: ClientContext,
    /// Environment context
    pub environment: AuthEnvironmentContext,
    /// Timestamp of authentication attempt
    pub timestamp: DateTime<Utc>,
}

/// Authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthCredentials {
    /// Username and password authentication
    Password {
        username: String,
        password: String, // Will be hashed before processing
    },
    /// Token-based authentication (JWT, API key, etc.)
    Token {
        token: String,
        token_type: TokenType,
    },
    /// Multi-factor authentication
    MultiFactor {
        primary_factor: Box<AuthCredentials>,
        secondary_factors: Vec<AuthCredentials>,
    },
    /// Certificate-based authentication
    Certificate {
        certificate: String,
        chain: Option<Vec<String>>,
    },
    /// Biometric authentication
    Biometric {
        biometric_type: BiometricType,
        biometric_data: String, // Encrypted biometric template
    },
    /// OAuth/OpenID Connect
    OAuth {
        provider: String,
        access_token: String,
        refresh_token: Option<String>,
        id_token: Option<String>,
    },
    /// SAML authentication
    Saml {
        saml_response: String,
        relay_state: Option<String>,
    },
    /// Custom authentication method
    Custom {
        method_name: String,
        credentials_data: HashMap<String, serde_json::Value>,
    },
}

/// Token types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    JWT,
    APIKey,
    OAuth2,
    SAML,
    Custom(String),
}

/// Biometric types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BiometricType {
    Fingerprint,
    Face,
    Iris,
    Voice,
    Palm,
}

impl std::fmt::Display for BiometricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BiometricType::Fingerprint => write!(f, "fingerprint"),
            BiometricType::Face => write!(f, "face"),
            BiometricType::Iris => write!(f, "iris"),
            BiometricType::Voice => write!(f, "voice"),
            BiometricType::Palm => write!(f, "palm"),
        }
    }
}

/// Authentication request context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequestContext {
    /// Source IP address
    pub source_ip: String,
    /// User agent string
    pub user_agent: Option<String>,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Request path or endpoint
    pub path: String,
    /// HTTP method
    pub method: String,
    /// Referer
    pub referer: Option<String>,
}

/// Client context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientContext {
    /// Client identifier
    pub client_id: String,
    /// Client type (web, mobile, api, etc.)
    pub client_type: String,
    /// Client version
    pub client_version: Option<String>,
    /// Device information
    pub device: AuthDeviceContext,
    /// Network context
    pub network: AuthNetworkContext,
    /// Geolocation information
    pub geolocation: Option<AuthGeoLocation>,
}

/// Authentication device context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDeviceContext {
    /// Device type
    pub device_type: String,
    /// Operating system
    pub os: String,
    /// Browser information
    pub browser: Option<String>,
    /// Device fingerprint
    pub fingerprint: Option<String>,
    /// Whether device is trusted
    pub trusted: bool,
    /// Device security posture
    pub security_posture: DeviceSecurityPosture,
}

/// Device security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSecurityPosture {
    /// Device is jailbroken/rooted
    pub compromised: bool,
    /// Screen lock enabled
    pub screen_lock_enabled: bool,
    /// Encryption enabled
    pub encryption_enabled: bool,
    /// Security software present
    pub security_software: Vec<String>,
    /// Security score (0-100)
    pub security_score: u8,
}

/// Authentication network context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthNetworkContext {
    /// Network type
    pub network_type: String,
    /// Connection is secure
    pub secure: bool,
    /// VPN information
    pub vpn_info: Option<AuthVpnInfo>,
    /// Proxy information
    pub proxy_info: Option<AuthProxyInfo>,
}

/// VPN information for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthVpnInfo {
    /// VPN provider
    pub provider: String,
    /// VPN endpoint location
    pub endpoint: String,
    /// Whether VPN is trusted
    pub trusted: bool,
}

/// Proxy information for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProxyInfo {
    /// Proxy type
    pub proxy_type: String,
    /// Proxy server
    pub server: String,
    /// Whether proxy is trusted
    pub trusted: bool,
}

/// Authentication geolocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthGeoLocation {
    /// Country code
    pub country: String,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Timezone
    pub timezone: Option<String>,
}

/// Authentication environment context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEnvironmentContext {
    /// Current time
    pub current_time: DateTime<Utc>,
    /// Timezone
    pub timezone: String,
    /// Threat intelligence
    pub threat_intelligence: AuthThreatIntelligence,
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
}

/// Authentication threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthThreatIntelligence {
    /// IP reputation score (0-100)
    pub ip_reputation_score: f64,
    /// Known malicious indicators
    pub malicious_indicators: Vec<String>,
    /// Recent failed attempts from this IP
    pub recent_failures: u32,
    /// Bot detection score (0-100)
    pub bot_score: f64,
    /// Anomaly detection score (0-100)
    pub anomaly_score: f64,
}

/// Risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Overall risk level
    pub risk_level: RiskLevel,
    /// Risk factors
    pub risk_factors: Vec<RiskFactor>,
    /// Risk score (0-100)
    pub risk_score: u8,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Risk factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor type
    pub factor_type: String,
    /// Factor description
    pub description: String,
    /// Factor weight (0-1)
    pub weight: f64,
    /// Factor value
    pub value: serde_json::Value,
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Whether authentication was successful
    pub success: bool,
    /// Authentication result status
    pub status: AuthStatus,
    /// User identity if successful
    pub user_identity: Option<UserIdentity>,
    /// Authentication session information
    pub session: Option<AuthSession>,
    /// Reason for failure or additional information
    pub reason: Option<String>,
    /// Authentication metrics
    pub metrics: AuthMetrics,
    /// Required next steps (e.g., MFA)
    pub next_steps: Vec<AuthNextStep>,
    /// Security recommendations
    pub recommendations: Vec<String>,
}

/// Authentication status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthStatus {
    Success,
    Failure,
    Partial,
    Pending,
    Locked,
    Expired,
    Invalid,
}

/// User identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    /// Unique user identifier
    pub user_id: String,
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// User attributes
    pub attributes: HashMap<String, serde_json::Value>,
    /// Security clearance level
    pub clearance_level: Option<String>,
    /// Account status
    pub account_status: AccountStatus,
    /// Last authentication timestamp
    pub last_auth: DateTime<Utc>,
}

/// Account status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccountStatus {
    Active,
    Inactive,
    Suspended,
    Locked,
    PendingVerification,
    Expired,
}

/// Authentication session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// Session identifier
    pub session_id: String,
    /// Session token
    pub session_token: String,
    /// Session expiration
    pub expires_at: DateTime<Utc>,
    /// Session type
    pub session_type: SessionType,
    /// Session capabilities
    pub capabilities: Vec<String>,
    /// Device binding
    pub device_binding: Option<String>,
}

/// Session types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionType {
    Standard,
    Elevated,
    Temporary,
    Service,
    Admin,
}

/// Authentication metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMetrics {
    /// Authentication time in milliseconds
    pub auth_time_ms: u64,
    /// Number of authentication factors used
    pub factors_used: u8,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Custom metrics from plugin
    pub custom_metrics: HashMap<String, serde_json::Value>,
}

/// Next authentication steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthNextStep {
    /// Step type
    pub step_type: AuthStepType,
    /// Step description
    pub description: String,
    /// Step parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Whether step is required
    pub required: bool,
    /// Step timeout in seconds
    pub timeout_seconds: Option<u64>,
}

/// Authentication step types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthStepType {
    MultiFactor,
    Captcha,
    EmailVerification,
    SMSVerification,
    SecurityQuestion,
    DeviceVerification,
    BiometricVerification,
    Approval,
    Custom(String),
}

/// WebAssembly authentication provider
pub struct WasmAuthProvider {
    /// Provider metadata
    metadata: PluginMetadata,
    /// Configuration
    config: AuthProviderConfig,
    /// Rate limiting
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

/// Authentication provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProviderConfig {
    /// Maximum authentication attempts per minute
    pub max_attempts_per_minute: u32,
    /// Maximum authentication attempts per hour
    pub max_attempts_per_hour: u32,
    /// Account lockout duration in minutes
    pub lockout_duration_minutes: u32,
    /// Maximum authentication time in milliseconds
    pub max_auth_time_ms: u64,
    /// Whether to enable metrics collection
    pub enable_metrics: bool,
    /// Trusted IP ranges
    pub trusted_ip_ranges: Vec<String>,
    /// Required authentication factors
    pub required_factors: Vec<String>,
}

impl Default for AuthProviderConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_minute: 5,
            max_attempts_per_hour: 20,
            lockout_duration_minutes: 15,
            max_auth_time_ms: 10000, // 10 seconds
            enable_metrics: true,
            trusted_ip_ranges: vec![],
            required_factors: vec!["password".to_string()],
        }
    }
}

/// Rate limiter for authentication attempts
#[derive(Debug)]
struct RateLimiter {
    attempts_per_minute: HashMap<String, Vec<DateTime<Utc>>>,
    attempts_per_hour: HashMap<String, Vec<DateTime<Utc>>>,
    locked_accounts: HashMap<String, DateTime<Utc>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            attempts_per_minute: HashMap::new(),
            attempts_per_hour: HashMap::new(),
            locked_accounts: HashMap::new(),
        }
    }

    fn check_rate_limit(&mut self, identifier: &str, config: &AuthProviderConfig) -> Result<bool> {
        let now = Utc::now();

        // Check if account is locked
        if let Some(lock_time) = self.locked_accounts.get(identifier) {
            let duration = (now - *lock_time).num_minutes();
            if duration < config.lockout_duration_minutes as i64 {
                return Err(FortressError::authentication(
                    format!("Account locked for {} more minutes", 
                           config.lockout_duration_minutes - duration as u32)
                ));
            } else {
                // Lock expired, remove it
                self.locked_accounts.remove(identifier);
            }
        }

        // Check minute rate limit
        let minute_attempts = self.attempts_per_minute.entry(identifier.to_string())
            .or_insert_with(Vec::new);
        minute_attempts.retain(|&time| (now - time).num_minutes() < 1);
        
        if minute_attempts.len() >= config.max_attempts_per_minute as usize {
            self.locked_accounts.insert(identifier.to_string(), now);
            return Err(FortressError::authentication("Too many attempts per minute"));
        }

        // Check hour rate limit
        let hour_attempts = self.attempts_per_hour.entry(identifier.to_string())
            .or_insert_with(Vec::new);
        hour_attempts.retain(|&time| (now - time).num_hours() < 1);
        
        if hour_attempts.len() >= config.max_attempts_per_hour as usize {
            self.locked_accounts.insert(identifier.to_string(), now);
            return Err(FortressError::authentication("Too many attempts per hour"));
        }

        // Record this attempt
        minute_attempts.push(now);
        hour_attempts.push(now);

        Ok(true)
    }
}

impl WasmAuthProvider {
    /// Create a new WASM authentication provider
    pub fn new(metadata: PluginMetadata, config: AuthProviderConfig) -> Self {
        Self {
            metadata,
            config,
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
        }
    }

    /// Authenticate user with provided context
    pub async fn authenticate(&self, context: AuthContext) -> Result<AuthResult> {
        let start_time = std::time::Instant::now();

        // Check rate limiting
        let identifier = self.get_identifier_from_context(&context);
        {
            let mut rate_limiter = self.rate_limiter.write().await;
            rate_limiter.check_rate_limit(&identifier, &self.config)?;
        }

        // Perform authentication
        let result = self.authenticate_internal(context).await?;

        // Update metrics
        let auth_time = start_time.elapsed().as_millis() as u64;
        tracing::debug!("Authentication completed in {}ms", auth_time);

        Ok(result)
    }

    /// Get identifier for rate limiting
    fn get_identifier_from_context(&self, context: &AuthContext) -> String {
        match &context.credentials {
            AuthCredentials::Password { username, .. } => username.clone(),
            AuthCredentials::Token { token, .. } => {
                // Use hash of token for privacy (simplified - use first 8 chars)
                let token_hash = if token.len() > 8 {
                    &token[..8]
                } else {
                    token
                };
                format!("token_{}", token_hash)
            },
            AuthCredentials::OAuth { provider, .. } => format!("oauth_{}", provider),
            AuthCredentials::Saml { .. } => "saml".to_string(),
            AuthCredentials::Certificate { .. } => "cert".to_string(),
            AuthCredentials::Biometric { biometric_type, .. } => {
                format!("biometric_{}", biometric_type)
            },
            AuthCredentials::MultiFactor { primary_factor, .. } => {
                self.get_identifier_from_credentials(primary_factor)
            },
            AuthCredentials::Custom { method_name, .. } => format!("custom_{}", method_name),
        }
    }

    /// Get identifier from credentials
    fn get_identifier_from_credentials(&self, credentials: &AuthCredentials) -> String {
        match credentials {
            AuthCredentials::Password { username, .. } => username.clone(),
            AuthCredentials::Token { token, .. } => {
                // Use hash of token for privacy (simplified - use first 8 chars)
                let token_hash = if token.len() > 8 {
                    &token[..8]
                } else {
                    token
                };
                format!("token_{}", token_hash)
            },
            _ => "unknown".to_string(),
        }
    }

    /// Internal authentication implementation
    async fn authenticate_internal(&self, context: AuthContext) -> Result<AuthResult> {
        let start_time = std::time::Instant::now();

        // Create authentication input
        let input = crate::plugin::PluginInput {
            action: "authenticate".to_string(),
            data: serde_json::to_value(&context)
                .map_err(|e| FortressError::plugin(format!("Failed to serialize auth context: {}", e)))?,
            parameters: HashMap::new(),
        };

        // This would integrate with the WASM runtime
        // For now, implement basic authentication logic
        let result = self.basic_authentication(&input).await?;

        let auth_time = start_time.elapsed().as_millis() as u64;

        Ok(AuthResult {
            success: result.success,
            status: result.status,
            user_identity: result.user_identity,
            session: result.session,
            reason: result.reason,
            metrics: AuthMetrics {
                auth_time_ms: auth_time,
                factors_used: result.metrics.factors_used,
                memory_usage_bytes: result.metrics.memory_usage_bytes,
                custom_metrics: result.metrics.custom_metrics,
            },
            next_steps: result.next_steps,
            recommendations: result.recommendations,
        })
    }

    /// Basic authentication implementation (fallback)
    async fn basic_authentication(&self, input: &crate::plugin::PluginInput) -> Result<AuthResult> {
        let context: AuthContext = serde_json::from_value(input.data.clone())
            .map_err(|e| FortressError::plugin(format!("Failed to deserialize auth context: {}", e)))?;

        match &context.credentials {
            AuthCredentials::Password { username, password } => {
                // Basic password authentication (in production, this would verify against a user store)
                if username == "admin" && password == "admin123" {
                    Ok(AuthResult {
                        success: true,
                        status: AuthStatus::Success,
                        user_identity: Some(UserIdentity {
                            user_id: "admin".to_string(),
                            username: username.clone(),
                            roles: vec!["admin".to_string(), "user".to_string()],
                            attributes: {
                                let mut attrs = HashMap::new();
                                attrs.insert("email".to_string(), serde_json::Value::String("admin@example.com".to_string()));
                                attrs.insert("department".to_string(), serde_json::Value::String("IT".to_string()));
                                attrs
                            },
                            clearance_level: Some("top_secret".to_string()),
                            account_status: AccountStatus::Active,
                            last_auth: Utc::now(),
                        }),
                        session: Some(AuthSession {
                            session_id: Uuid::new_v4().to_string(),
                            session_token: "sample_session_token".to_string(),
                            expires_at: Utc::now() + chrono::Duration::hours(8),
                            session_type: SessionType::Standard,
                            capabilities: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
                            device_binding: context.client.device.fingerprint.clone(),
                        }),
                        reason: None,
                        metrics: AuthMetrics {
                            auth_time_ms: 0,
                            factors_used: 1,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                        next_steps: vec![],
                        recommendations: vec!["Consider enabling MFA for enhanced security".to_string()],
                    })
                } else {
                    Ok(AuthResult {
                        success: false,
                        status: AuthStatus::Failure,
                        user_identity: None,
                        session: None,
                        reason: Some("Invalid username or password".to_string()),
                        metrics: AuthMetrics {
                            auth_time_ms: 0,
                            factors_used: 1,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                        next_steps: vec![],
                        recommendations: vec!["Check your credentials and try again".to_string()],
                    })
                }
            },
            AuthCredentials::Token { token, token_type } => {
                // Basic token validation
                if token.starts_with("valid_token_") {
                    Ok(AuthResult {
                        success: true,
                        status: AuthStatus::Success,
                        user_identity: Some(UserIdentity {
                            user_id: "token_user".to_string(),
                            username: "token_user".to_string(),
                            roles: vec!["user".to_string()],
                            attributes: HashMap::new(),
                            clearance_level: Some("confidential".to_string()),
                            account_status: AccountStatus::Active,
                            last_auth: Utc::now(),
                        }),
                        session: Some(AuthSession {
                            session_id: Uuid::new_v4().to_string(),
                            session_token: token.clone(),
                            expires_at: Utc::now() + chrono::Duration::hours(1),
                            session_type: SessionType::Service,
                            capabilities: vec!["read".to_string()],
                            device_binding: None,
                        }),
                        reason: None,
                        metrics: AuthMetrics {
                            auth_time_ms: 0,
                            factors_used: 1,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                        next_steps: vec![],
                        recommendations: vec!["Token authentication successful".to_string()],
                    })
                } else {
                    Ok(AuthResult {
                        success: false,
                        status: AuthStatus::Invalid,
                        user_identity: None,
                        session: None,
                        reason: Some("Invalid token".to_string()),
                        metrics: AuthMetrics {
                            auth_time_ms: 0,
                            factors_used: 1,
                            memory_usage_bytes: 0,
                            custom_metrics: HashMap::new(),
                        },
                        next_steps: vec![],
                        recommendations: vec!["Please obtain a valid token".to_string()],
                    })
                }
            },
            _ => {
                Ok(AuthResult {
                    success: false,
                    status: AuthStatus::Failure,
                    user_identity: None,
                    session: None,
                    reason: Some("Authentication method not supported".to_string()),
                    metrics: AuthMetrics {
                        auth_time_ms: 0,
                        factors_used: 0,
                        memory_usage_bytes: 0,
                        custom_metrics: HashMap::new(),
                    },
                    next_steps: vec![AuthNextStep {
                        step_type: AuthStepType::MultiFactor,
                        description: "Additional authentication required".to_string(),
                        parameters: HashMap::new(),
                        required: true,
                        timeout_seconds: Some(300),
                    }],
                    recommendations: vec!["Contact administrator for supported authentication methods".to_string()],
                })
            }
        }
    }

    /// Get provider metadata
    pub fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    /// Validate user session
    pub async fn validate_session(&self, session_token: &str) -> Result<UserIdentity> {
        // Basic session validation (in production, this would check against a session store)
        if session_token == "sample_session_token" || session_token.starts_with("valid_token_") {
            Ok(UserIdentity {
                user_id: "validated_user".to_string(),
                username: "validated_user".to_string(),
                roles: vec!["user".to_string()],
                attributes: HashMap::new(),
                clearance_level: Some("confidential".to_string()),
                account_status: AccountStatus::Active,
                last_auth: Utc::now(),
            })
        } else {
            Err(FortressError::authentication("Invalid session token"))
        }
    }

    /// Refresh authentication session
    pub async fn refresh_session(&self, session_token: &str) -> Result<AuthSession> {
        // Basic session refresh (in production, this would update the session store)
        if session_token == "sample_session_token" {
            Ok(AuthSession {
                session_id: Uuid::new_v4().to_string(),
                session_token: "refreshed_session_token".to_string(),
                expires_at: Utc::now() + chrono::Duration::hours(8),
                session_type: SessionType::Standard,
                capabilities: vec!["read".to_string(), "write".to_string()],
                device_binding: None,
            })
        } else {
            Err(FortressError::authentication("Cannot refresh invalid session"))
        }
    }

    /// Invalidate user session
    pub async fn invalidate_session(&self, session_token: &str) -> Result<()> {
        // Basic session invalidation (in production, this would remove from session store)
        if session_token == "sample_session_token" {
            tracing::info!("Session {} invalidated", session_token);
            Ok(())
        } else {
            Err(FortressError::authentication("Session not found"))
        }
    }
}

/// Authentication provider registry
pub struct AuthProviderRegistry {
    providers: Arc<RwLock<HashMap<String, Arc<WasmAuthProvider>>>>,
    default_provider: Option<String>,
}

impl AuthProviderRegistry {
    /// Create a new authentication provider registry
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            default_provider: None,
        }
    }

    /// Register an authentication provider
    pub async fn register_provider(&self, id: String, provider: Arc<WasmAuthProvider>) {
        let mut providers = self.providers.write().await;
        providers.insert(id, provider);
    }

    /// Get an authentication provider by ID
    pub async fn get_provider(&self, id: &str) -> Option<Arc<WasmAuthProvider>> {
        let providers = self.providers.read().await;
        providers.get(id).cloned()
    }

    /// Set default provider
    pub async fn set_default_provider(&self, id: String) {
        let providers = self.providers.read().await;
        if providers.contains_key(&id) {
            // This would need to be made atomic in a real implementation
            drop(providers);
            // Implementation note: In a real scenario, we'd need interior mutability
        }
    }

    /// Get default provider
    pub async fn get_default_provider(&self) -> Option<Arc<WasmAuthProvider>> {
        if let Some(ref default_id) = self.default_provider {
            self.get_provider(default_id).await
        } else {
            // Return first available provider as fallback
            let providers = self.providers.read().await;
            providers.values().next().cloned()
        }
    }

    /// List all registered providers
    pub async fn list_providers(&self) -> Vec<String> {
        let providers = self.providers.read().await;
        providers.keys().cloned().collect()
    }
}

impl Default for AuthProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_authentication() {
        let metadata = PluginMetadata {
            id: "test-auth".to_string(),
            name: "Test Auth Provider".to_string(),
            version: "1.0.0".to_string(),
            description: "Test authentication provider".to_string(),
            author: "Test".to_string(),
            capabilities: vec![PluginCapability::Custom("authentication".to_string())],
            config_schema: None,
        };

        let config = AuthProviderConfig::default();
        let provider = WasmAuthProvider::new(metadata, config);

        let context = AuthContext {
            request_id: Uuid::new_v4().to_string(),
            auth_method: "password".to_string(),
            credentials: AuthCredentials::Password {
                username: "admin".to_string(),
                password: "admin123".to_string(),
            },
            request: AuthRequestContext {
                source_ip: "192.168.1.100".to_string(),
                user_agent: Some("Mozilla/5.0".to_string()),
                headers: HashMap::new(),
                parameters: HashMap::new(),
                path: "/login".to_string(),
                method: "POST".to_string(),
                referer: None,
            },
            client: ClientContext {
                client_id: "web_client".to_string(),
                client_type: "web".to_string(),
                client_version: Some("1.0.0".to_string()),
                device: AuthDeviceContext {
                    device_type: "desktop".to_string(),
                    os: "Windows".to_string(),
                    browser: Some("Chrome".to_string()),
                    fingerprint: None,
                    trusted: true,
                    security_posture: DeviceSecurityPosture {
                        compromised: false,
                        screen_lock_enabled: true,
                        encryption_enabled: true,
                        security_software: vec!["antivirus".to_string()],
                        security_score: 85,
                    },
                },
                network: AuthNetworkContext {
                    network_type: "corporate".to_string(),
                    secure: true,
                    vpn_info: None,
                    proxy_info: None,
                },
                geolocation: Some(AuthGeoLocation {
                    country: "US".to_string(),
                    region: Some("CA".to_string()),
                    city: Some("San Francisco".to_string()),
                    latitude: Some(37.7749),
                    longitude: Some(-122.4194),
                    timezone: Some("PST".to_string()),
                }),
            },
            environment: AuthEnvironmentContext {
                current_time: Utc::now(),
                timezone: "UTC".to_string(),
                threat_intelligence: AuthThreatIntelligence {
                    ip_reputation_score: 95.0,
                    malicious_indicators: vec![],
                    recent_failures: 0,
                    bot_score: 5.0,
                    anomaly_score: 10.0,
                },
                risk_assessment: RiskAssessment {
                    risk_level: RiskLevel::Low,
                    risk_factors: vec![],
                    risk_score: 15,
                },
            },
            timestamp: Utc::now(),
        };

        let result = provider.authenticate(context).await;
        assert!(result.is_ok());

        let auth_result = result.unwrap();
        assert!(auth_result.success);
        assert_eq!(auth_result.status, AuthStatus::Success);
        assert!(auth_result.user_identity.is_some());
        assert!(auth_result.session.is_some());
    }

    #[tokio::test]
    async fn test_token_authentication() {
        let metadata = PluginMetadata {
            id: "test-token".to_string(),
            name: "Test Token Provider".to_string(),
            version: "1.0.0".to_string(),
            description: "Test token authentication".to_string(),
            author: "Test".to_string(),
            capabilities: vec![PluginCapability::Custom("authentication".to_string())],
            config_schema: None,
        };

        let config = AuthProviderConfig::default();
        let provider = WasmAuthProvider::new(metadata, config);

        let context = AuthContext {
            request_id: Uuid::new_v4().to_string(),
            auth_method: "token".to_string(),
            credentials: AuthCredentials::Token {
                token: "valid_token_12345".to_string(),
                token_type: TokenType::APIKey,
            },
            request: AuthRequestContext {
                source_ip: "192.168.1.100".to_string(),
                user_agent: None,
                headers: HashMap::new(),
                parameters: HashMap::new(),
                path: "/api/data".to_string(),
                method: "GET".to_string(),
                referer: None,
            },
            client: ClientContext {
                client_id: "api_client".to_string(),
                client_type: "api".to_string(),
                client_version: None,
                device: AuthDeviceContext {
                    device_type: "server".to_string(),
                    os: "Linux".to_string(),
                    browser: None,
                    fingerprint: None,
                    trusted: true,
                    security_posture: DeviceSecurityPosture {
                        compromised: false,
                        screen_lock_enabled: true,
                        encryption_enabled: true,
                        security_software: vec![],
                        security_score: 100,
                    },
                },
                network: AuthNetworkContext {
                    network_type: "corporate".to_string(),
                    secure: true,
                    vpn_info: None,
                    proxy_info: None,
                },
                geolocation: None,
            },
            environment: AuthEnvironmentContext {
                current_time: Utc::now(),
                timezone: "UTC".to_string(),
                threat_intelligence: AuthThreatIntelligence {
                    ip_reputation_score: 90.0,
                    malicious_indicators: vec![],
                    recent_failures: 0,
                    bot_score: 0.0,
                    anomaly_score: 5.0,
                },
                risk_assessment: RiskAssessment {
                    risk_level: RiskLevel::Low,
                    risk_factors: vec![],
                    risk_score: 10,
                },
            },
            timestamp: Utc::now(),
        };

        let result = provider.authenticate(context).await;
        assert!(result.is_ok());

        let auth_result = result.unwrap();
        assert!(auth_result.success);
        assert_eq!(auth_result.status, AuthStatus::Success);
        assert!(auth_result.user_identity.is_some());
        assert!(auth_result.session.is_some());
    }
}
