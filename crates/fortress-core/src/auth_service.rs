//! Plugin-Based Authentication Service
//!
//! This module provides a unified authentication service that uses the hot-swappable
//! plugin system. It replaces the hardcoded authentication methods with a flexible
//! plugin-based architecture.

use crate::auth_plugin::*;
use crate::auth_plugin_manager::*;
use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// Unified authentication service using plugin system
pub struct PluginAuthService {
    /// Hot-swappable plugin manager
    plugin_manager: Arc<HotSwappableAuthPluginManager>,
    /// Service configuration
    config: AuthServiceConfig,
    /// Service statistics
    stats: Arc<RwLock<AuthServiceStats>>,
}

/// Authentication service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthServiceConfig {
    /// Plugin directory
    pub plugin_directory: String,
    /// Default authentication method
    pub default_method: AuthMethod,
    /// Enable hot-reloading
    pub enable_hot_reload: bool,
    /// Health check interval in seconds
    pub health_check_interval: u64,
    /// Maximum plugin instances
    pub max_plugins: usize,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Token expiration in seconds
    pub token_expiration: u64,
    /// Enable device fingerprinting
    pub enable_device_fingerprinting: bool,
    /// Security policies
    pub security_policies: SecurityPolicies,
}

/// Security policies for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicies {
    /// Maximum failed login attempts
    pub max_failed_attempts: u32,
    /// Account lockout duration in seconds
    pub lockout_duration: u64,
    /// Password complexity requirements
    pub password_policy: PasswordPolicy,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
    /// IP whitelist/blacklist
    pub ip_filtering: IpFilteringConfig,
}

/// Password policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
    pub max_age_days: u32,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub max_requests_per_minute: u32,
    pub max_requests_per_hour: u32,
    pub burst_size: u32,
}

/// IP filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilteringConfig {
    pub enabled: bool,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
}

/// Authentication service statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthServiceStats {
    /// Total authentication requests
    pub total_requests: u64,
    /// Successful authentications
    pub successful_auths: u64,
    /// Failed authentications
    pub failed_auths: u64,
    /// Successful authentications by method
    pub successful_by_method: HashMap<String, u64>,
    /// Failed authentications by method
    pub failed_by_method: HashMap<String, u64>,
    /// Average authentication time in milliseconds
    pub avg_auth_time_ms: f64,
    /// Active sessions
    pub active_sessions: u64,
    /// Plugin reloads
    pub plugin_reloads: u64,
    /// Security events
    pub security_events: u64,
}

/// Authentication context for service operations
#[derive(Debug, Clone)]
pub struct ServiceContext {
    /// Client IP address
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Request timestamp
    pub timestamp: u64,
    /// Request ID for tracing
    pub request_id: String,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Default for ServiceContext {
    fn default() -> Self {
        Self {
            ip_address: None,
            user_agent: None,
            device_fingerprint: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            request_id: uuid::Uuid::new_v4().to_string(),
            metadata: HashMap::new(),
        }
    }
}

impl Default for AuthServiceConfig {
    fn default() -> Self {
        Self {
            plugin_directory: "./plugins/auth".to_string(),
            default_method: AuthMethod::JWT,
            enable_hot_reload: true,
            health_check_interval: 60,
            max_plugins: 10,
            session_timeout: 86400, // 24 hours
            token_expiration: 3600, // 1 hour
            enable_device_fingerprinting: true,
            security_policies: SecurityPolicies {
                max_failed_attempts: 5,
                lockout_duration: 1800, // 30 minutes
                password_policy: PasswordPolicy {
                    min_length: 8,
                    require_uppercase: true,
                    require_lowercase: true,
                    require_numbers: true,
                    require_special_chars: true,
                    max_age_days: 90,
                },
                rate_limiting: RateLimitingConfig {
                    enabled: true,
                    max_requests_per_minute: 10,
                    max_requests_per_hour: 100,
                    burst_size: 20,
                },
                ip_filtering: IpFilteringConfig {
                    enabled: false,
                    whitelist: vec![],
                    blacklist: vec![],
                },
            },
        }
    }
}

impl PluginAuthService {
    /// Create a new plugin-based authentication service
    pub async fn new(config: AuthServiceConfig) -> Result<Self> {
        let plugin_config = AuthPluginManagerConfig {
            plugin_directory: config.plugin_directory.clone(),
            default_method: config.default_method.clone(),
            enable_hot_reload: config.enable_hot_reload,
            health_check_interval: config.health_check_interval,
            max_plugins: config.max_plugins,
        };

        let plugin_manager = Arc::new(
            HotSwappableAuthPluginManager::new(plugin_config).await
                .map_err(|e| FortressError::authentication(format!("Failed to create plugin manager: {}", e), None))?
        );

        Ok(Self {
            plugin_manager,
            config,
            stats: Arc::new(RwLock::new(AuthServiceStats::default())),
        })
    }

    /// Authenticate a request using the appropriate plugin
    pub async fn authenticate(&self, request: AuthRequest, context: ServiceContext) -> Result<AuthResult> {
        let start_time = std::time::Instant::now();

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
            
            let method_key = format!("{:?}", request.method);
            *stats.successful_by_method.entry(method_key.clone()).or_insert(0) += 0;
            *stats.failed_by_method.entry(method_key).or_insert(0) += 0;
        }

        info!("Processing authentication request for method: {:?}", request.method);

        // Apply security policies
        let request_method = request.method.clone();
        if let Err(e) = self.apply_security_policies(&request, &context).await {
            return Err(e);
        }

        // Route to appropriate plugin
        let result = self.plugin_manager.authenticate(request).await;

        // Update statistics based on result
        let elapsed = start_time.elapsed().as_millis() as f64;
        {
            let mut stats = self.stats.write().await;
            
            if result.is_ok() {
                stats.successful_auths += 1;
                if let Some(ref user_info) = result.as_ref().ok().unwrap().user_info {
                    stats.active_sessions += 1;
                }
                
                let method_key = format!("{:?}", request_method);
                *stats.successful_by_method.entry(method_key).or_insert(0) += 1;
            } else {
                stats.failed_auths += 1;
                stats.security_events += 1;
                
                let method_key = format!("{:?}", request_method);
                *stats.failed_by_method.entry(method_key).or_insert(0) += 1;
            }
            
            // Update average authentication time
            let total_requests = stats.total_requests;
            stats.avg_auth_time_ms = (stats.avg_auth_time_ms * (total_requests - 1) as f64 + elapsed) / total_requests as f64;
        }

        // Log authentication result
        match &result {
            Ok(auth_result) => {
                info!("Authentication successful for user: {:?}", 
                      auth_result.user_info.as_ref().map(|u| &u.username));
            }
            Err(e) => {
                warn!("Authentication failed: {}", e);
            }
        }

        result
    }

    /// Validate an existing token
    pub async fn validate_token(&self, token: &str, context: ServiceContext) -> Result<AuthUserInfo> {
        info!("Validating token for request: {}", context.request_id);

        // Try to get plugin for token validation
        // In a real implementation, we'd extract the method from the token
        // For now, we'll try JWT first, then OAuth
        let methods = vec![AuthMethod::JWT, AuthMethod::OAuth, AuthMethod::SAML];

        for method in methods {
            if let Ok(plugin) = self.plugin_manager.get_plugin_for_method(&method).await {
                let auth_request = AuthRequest {
                    method: method.clone(),
                    credentials: AuthCredentials {
                        username: None,
                        password: None,
                        token: Some(token.to_string()),
                        authorization_code: None,
                        state: None,
                        redirect_uri: None,
                        saml_assertion: None,
                        api_key: None,
                        additional_data: HashMap::new(),
                    },
                    context: AuthContext {
                        ip_address: context.ip_address.clone(),
                        user_agent: context.user_agent.clone(),
                        timestamp: context.timestamp,
                        device_fingerprint: context.device_fingerprint.clone(),
                        request_id: context.request_id.clone(),
                    },
                };

                match plugin.validate_token(token).await {
                    Ok(user_info) => {
                        info!("Token validation successful for method: {:?}", method);
                        return Ok(user_info);
                    }
                    Err(_) => {
                        debug!("Token validation failed for method: {:?}", method);
                        // Continue to next method
                    }
                }
            }
        }

        Err(FortressError::authentication("Token validation failed".to_string(), None))
    }

    /// Refresh an authentication token
    pub async fn refresh_token(&self, refresh_token: &str, context: ServiceContext) -> Result<AuthResult> {
        info!("Refreshing token for request: {}", context.request_id);

        // Try to refresh with available plugins
        let methods = vec![AuthMethod::JWT, AuthMethod::OAuth, AuthMethod::SAML];

        for method in methods {
            if let Ok(plugin) = self.plugin_manager.get_plugin_for_method(&method).await {
                match plugin.refresh_token(refresh_token).await {
                    Ok(result) => {
                        info!("Token refresh successful for method: {:?}", method);
                        return Ok(result);
                    }
                    Err(_) => {
                        debug!("Token refresh failed for method: {:?}", method);
                        // Continue to next method
                    }
                }
            }
        }

        Err(FortressError::authentication("Token refresh failed".to_string(), None))
    }

    /// Logout a user/token
    pub async fn logout(&self, token: &str, context: ServiceContext) -> Result<()> {
        info!("Logging out token for request: {}", context.request_id);

        // Try to logout with available plugins
        let methods = vec![AuthMethod::JWT, AuthMethod::OAuth, AuthMethod::SAML];

        for method in methods {
            if let Ok(plugin) = self.plugin_manager.get_plugin_for_method(&method).await {
                match plugin.logout(token).await {
                    Ok(()) => {
                        info!("Logout successful for method: {:?}", method);
                        
                        // Update statistics
                        {
                            let mut stats = self.stats.write().await;
                            if stats.active_sessions > 0 {
                                stats.active_sessions -= 1;
                            }
                        }
                        
                        return Ok(());
                    }
                    Err(_) => {
                        debug!("Logout failed for method: {:?}", method);
                        // Continue to next method
                    }
                }
            }
        }

        Err(FortressError::authentication("Logout failed".to_string(), None))
    }

    /// Get available authentication methods
    pub async fn get_available_methods(&self) -> Vec<AuthMethod> {
        let plugins = self.plugin_manager.list_loaded_plugins().await;
        let mut methods = Vec::new();

        for plugin_name in plugins {
            if let Some(metadata) = self.plugin_manager.get_plugin_metadata(&plugin_name).await {
                methods.extend(metadata.supported_methods);
            }
        }

        // Remove duplicates
        methods.sort();
        methods.dedup();
        methods
    }

    /// Get service statistics
    pub async fn get_stats(&self) -> AuthServiceStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Get plugin manager statistics
    pub async fn get_plugin_stats(&self) -> PluginManagerStats {
        self.plugin_manager.get_stats().await
    }

    /// Hot-swap a plugin
    pub async fn reload_plugin(&self, request: PluginReloadRequest) -> Result<()> {
        info!("Reloading plugin: {}", request.plugin_name);

        match self.plugin_manager.hot_swap_plugin(request.clone()).await {
            Ok(()) => {
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.plugin_reloads += 1;
                }
                
                info!("Plugin reload successful: {}", request.plugin_name);
                Ok(())
            }
            Err(e) => {
                error!("Plugin reload failed: {}", e);
                Err(e)
            }
        }
    }

    /// Deploy a new plugin
    pub async fn deploy_plugin(&self, deployment: PluginDeployment) -> Result<()> {
        info!("Deploying plugin: {} v{}", deployment.name, deployment.version);

        match self.plugin_manager.deploy_plugin(deployment.clone()).await {
            Ok(()) => {
                info!("Plugin deployment successful: {}", deployment.name);
                Ok(())
            }
            Err(e) => {
                error!("Plugin deployment failed: {}", e);
                Err(e)
            }
        }
    }

    /// Get plugin registry
    pub async fn get_plugin_registry(&self) -> Vec<PluginRegistryEntry> {
        self.plugin_manager.list_registered_plugins().await
    }

    /// Set default authentication method
    pub async fn set_default_method(&self, method: AuthMethod) -> Result<()> {
        self.plugin_manager.set_default_method(method).await
    }

    /// Get default authentication method
    pub async fn get_default_method(&self) -> AuthMethod {
        self.plugin_manager.get_default_method().await
    }

    /// Perform health check on all plugins
    pub async fn health_check(&self) -> HashMap<String, bool> {
        self.plugin_manager.health_check_all().await
    }

    /// Apply security policies to the request
    async fn apply_security_policies(&self, request: &AuthRequest, context: &ServiceContext) -> Result<()> {
        let policies = &self.config.security_policies;

        // IP filtering
        if policies.ip_filtering.enabled {
            if let Some(ref ip_address) = context.ip_address {
                if !policies.ip_filtering.whitelist.is_empty() {
                    if !policies.ip_filtering.whitelist.contains(ip_address) {
                        return Err(FortressError::authentication(
                            format!("IP address not whitelisted: {}", ip_address),
                            None
                        ));
                    }
                }

                if policies.ip_filtering.blacklist.contains(ip_address) {
                    return Err(FortressError::authentication(
                            format!("IP address blacklisted: {}", ip_address),
                            Some("IP address is blacklisted and cannot be used for authentication".to_string())
                        ));
                }
            }
        }

        // Rate limiting (simplified - in production, use proper rate limiting)
        if policies.rate_limiting.enabled {
            // This would typically involve checking request history per IP
            // For now, we'll just log it
            debug!("Rate limiting check for IP: {:?}", context.ip_address);
        }

        // Password policy validation (for basic auth)
        if let (Some(ref username), Some(ref password)) = (&request.credentials.username, &request.credentials.password) {
            self.validate_password_policy(username, password, &policies.password_policy)?;
        }

        Ok(())
    }

    /// Validate password against policy
    fn validate_password_policy(&self, username: &str, password: &str, policy: &PasswordPolicy) -> Result<()> {
        if password.len() < policy.min_length {
            return Err(FortressError::authentication(
                format!("Password too short, minimum {} characters", policy.min_length),
                Some(username.to_string())
            ));
        }

        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(FortressError::authentication(
                "Password must contain uppercase letters".to_string(),
                Some(username.to_string())
            ));
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(FortressError::authentication(
                "Password must contain lowercase letters".to_string(),
                Some(username.to_string())
            ));
        }

        if policy.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(FortressError::authentication(
                "Password must contain numbers".to_string(),
                Some(username.to_string())
            ));
        }

        if policy.require_special_chars && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(FortressError::authentication(
                "Password must contain special characters".to_string(),
                Some(username.to_string())
            ));
        }

        // Check for common weak passwords
        if self.is_weak_password(username, password) {
            return Err(FortressError::authentication(
                "Password is too weak or common".to_string(),
                Some(username.to_string())
            ));
        }

        Ok(())
    }

    /// Check if password is weak or common
    fn is_weak_password(&self, username: &str, password: &str) -> bool {
        let weak_passwords = vec![
            "password", "123456", "password123", "admin", "root",
            "qwerty", "letmein", "welcome", "changeme",
        ];

        // Check if password is in weak list
        if weak_passwords.contains(&password.to_lowercase().as_str()) {
            return true;
        }

        // Check if password contains username
        if password.to_lowercase().contains(&username.to_lowercase()) {
            return true;
        }

        // Check for simple patterns
        if password.chars().collect::<Vec<_>>().windows(3).any(|w| {
            w[0] == w[1] && w[1] == w[2]
        }) {
            return true;
        }

        false
    }

    /// Shutdown the authentication service
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down plugin-based authentication service");

        // Shutdown plugin manager
        self.plugin_manager.shutdown().await?;

        // Log final statistics
        let stats = self.stats.read().await;
        info!("Final statistics: {} total requests, {} successful, {} failed",
               stats.total_requests, stats.successful_auths, stats.failed_auths);

        Ok(())
    }

    /// Get plugin metadata
    pub async fn get_plugin_metadata(&self, plugin_name: &str) -> Result<Option<AuthPluginMetadata>> {
        Ok(self.plugin_manager.get_plugin_metadata(plugin_name).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_creation() {
        let config = AuthServiceConfig::default();
        let service = PluginAuthService::new(config).await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_password_validation() {
        let config = AuthServiceConfig::default();
        let service = PluginAuthService::new(config).await.unwrap();
        
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            max_age_days: 90,
        };

        // Test valid password
        assert!(service.validate_password_policy("user", "SecurePass123!", &policy).is_ok());
        
        // Test invalid password - too short
        assert!(service.validate_password_policy("user", "short", &policy).is_err());
        
        // Test invalid password - no uppercase
        assert!(service.validate_password_policy("user", "lowercase123!", &policy).is_err());
    }

    #[tokio::test]
    async fn test_weak_password_detection() {
        let config = AuthServiceConfig::default();
        let service = PluginAuthService::new(config).await.unwrap();
        
        // Test weak passwords
        assert!(service.is_weak_password("user", "password"));
        assert!(service.is_weak_password("user", "user"));
        assert!(service.is_weak_password("admin", "admin123"));
        
        // Test strong password
        assert!(!service.is_weak_password("user", "SecurePass123!"));
    }
}
