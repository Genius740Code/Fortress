//! Authentication Plugin Management API
//!
//! This module provides REST API endpoints for managing authentication plugins,
//! including deployment, configuration, monitoring, and hot-swapping.

use crate::auth_plugin_manager::{PluginDeployment, PluginReloadRequest, DeploymentStrategy, PluginRegistryEntry, PluginManagerStats};
use crate::auth_service::{PluginAuthService, ServiceContext, AuthServiceStats};
use crate::auth_plugin::{AuthMethod, AuthRequest, AuthPluginMetadata};
use crate::error::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;
use warp::Filter;
use serde::{Serialize, Deserialize};

/// API response wrapper
#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
    message: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }

    fn error(message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
            message: Some(message.to_string()),
        }
    }
}

/// Authentication API manager
pub struct AuthApiManager {
    /// Plugin-based authentication service
    auth_service: Arc<PluginAuthService>,
    /// API configuration
    config: AuthApiConfig,
    /// Plugin registry
    plugins: Arc<RwLock<HashMap<String, String>>>,
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthApiConfig {
    /// Enable API endpoints
    pub enabled: bool,
    /// API authentication required
    pub require_auth: bool,
    /// Allowed origins for CORS
    pub allowed_origins: Vec<String>,
    /// Rate limiting
    pub rate_limiting: ApiRateLimitConfig,
}

/// Token validation request
#[derive(Debug, Deserialize)]
struct TokenValidationRequest {
    token: String,
    request_id: Option<String>,
}

/// Token refresh request
#[derive(Debug, Deserialize)]
struct TokenRefreshRequest {
    refresh_token: String,
    request_id: Option<String>,
}

/// Logout request
#[derive(Debug, Deserialize)]
struct LogoutRequest {
    token: String,
    request_id: Option<String>,
}

/// Reload plugin request
#[derive(Debug, Deserialize)]
struct ReloadPluginRequest {
    plugin_name: String,
    force: bool,
}

/// API rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
}

impl Default for AuthApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_auth: true,
            allowed_origins: vec!["*".to_string()],
            rate_limiting: ApiRateLimitConfig {
                enabled: true,
                requests_per_minute: 60,
                requests_per_hour: 1000,
            },
        }
    }
}

impl AuthApiManager {
    /// Create a new authentication API manager
    pub fn new(auth_service: Arc<PluginAuthService>, config: AuthApiConfig) -> Self {
        Self {
            auth_service,
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get all registered plugins
    pub async fn list_plugins(&self) -> Result<Vec<PluginRegistryEntry>> {
        Ok(self.auth_service.get_plugin_registry().await)
    }

    /// Get loaded plugins
    pub async fn list_loaded_plugins(&self) -> Result<Vec<String>> {
        Ok(self.auth_service.get_available_methods().await
            .into_iter()
            .map(|m| format!("{:?}", m))
            .collect())
    }

    /// Get plugin metadata
    pub async fn get_plugin_metadata(&self, plugin_name: &str) -> Result<Option<AuthPluginMetadata>> {
        self.auth_service.get_plugin_metadata(plugin_name).await
    }

    /// Deploy a new plugin
    pub async fn deploy_plugin(&self, deployment: PluginDeployment) -> Result<()> {
        self.auth_service.deploy_plugin(deployment).await
    }

    /// Reload a plugin
    pub async fn reload_plugin(&self, plugin_name: &str, force: bool) -> Result<()> {
        let request = PluginReloadRequest {
            plugin_name: plugin_name.to_string(),
            force,
            reason: "API request".to_string(),
            strategy: DeploymentStrategy::Immediate,
        };

        self.auth_service.reload_plugin(request).await
    }

    /// Set default authentication method
    pub async fn set_default_method(&self, method: AuthMethod) -> Result<()> {
        self.auth_service.set_default_method(method).await
    }

    /// Get default authentication method
    pub async fn get_default_method(&self) -> Result<AuthMethod> {
        Ok(self.auth_service.get_default_method().await)
    }

    /// Get service statistics
    pub async fn get_service_stats(&self) -> Result<AuthServiceStats> {
        Ok(self.auth_service.get_stats().await)
    }

    /// Get plugin statistics
    pub async fn get_plugin_stats(&self) -> Result<PluginManagerStats> {
        Ok(self.auth_service.get_plugin_stats().await)
    }

    /// Perform health check
    pub async fn health_check(&self) -> Result<HashMap<String, bool>> {
        Ok(self.auth_service.health_check().await)
    }

    /// Get available authentication methods
    pub async fn get_available_methods(&self) -> Result<Vec<AuthMethod>> {
        Ok(self.auth_service.get_available_methods().await)
    }
}

/// Create API routes for authentication plugin management
pub fn create_auth_api_routes(
    api_manager: Arc<AuthApiManager>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let api_manager_clone = api_manager.clone();

    // List plugins endpoint
    let list_plugins = warp::path("plugins")
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|manager: Arc<AuthApiManager>| async move {
            match manager.list_plugins().await {
                Ok(plugins) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(plugins))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // List loaded plugins
    let list_loaded = warp::path("plugins")
        .and(warp::path("loaded"))
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|manager: Arc<AuthApiManager>| async move {
            match manager.list_loaded_plugins().await {
                Ok(plugins) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(plugins))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Get plugin metadata endpoint
    let get_plugin = warp::path!("plugins")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|plugin_name: String, manager: Arc<AuthApiManager>| async move {
            match manager.get_plugin_metadata(&plugin_name).await {
                Ok(metadata) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(metadata))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Deploy plugin endpoint
    let deploy_plugin = warp::path("plugins")
        .and(warp::path("deploy"))
        .and(warp::post())
        .and(warp::body::json::<PluginDeployment>())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|deployment: PluginDeployment, manager: Arc<AuthApiManager>| async move {
            match manager.deploy_plugin(deployment).await {
                Ok(()) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success("Plugin deployed successfully"))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Reload plugin endpoint
    let reload_plugin = warp::path("plugins")
        .and(warp::path("reload"))
        .and(warp::post())
        .and(warp::body::json::<ReloadPluginRequest>())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|request: ReloadPluginRequest, manager: Arc<AuthApiManager>| async move {
            match manager.reload_plugin(&request.plugin_name, request.force).await {
                Ok(()) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success("Plugin reloaded successfully"))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Set default method endpoint
    let set_default_method = warp::path("methods")
        .and(warp::path("default"))
        .and(warp::post())
        .and(warp::body::json::<AuthMethod>())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|method: AuthMethod, manager: Arc<AuthApiManager>| async move {
            match manager.set_default_method(method).await {
                Ok(()) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success("Default method updated"))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Get default method
    let get_default_method = warp::path("methods")
        .and(warp::path("default"))
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|manager: Arc<AuthApiManager>| async move {
            match manager.get_default_method().await {
                Ok(method) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(method))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Get service statistics
    let get_service_stats = warp::path("stats")
        .and(warp::path("service"))
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|manager: Arc<AuthApiManager>| async move {
            match manager.get_service_stats().await {
                Ok(stats) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(stats))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Get plugin statistics
    let get_plugin_stats = warp::path("stats")
        .and(warp::path("plugins"))
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|manager: Arc<AuthApiManager>| async move {
            match manager.get_plugin_stats().await {
                Ok(stats) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(stats))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Health check
    let health_check = warp::path("health")
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|manager: Arc<AuthApiManager>| async move {
            match manager.health_check().await {
                Ok(health) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(health))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Get available methods
    let get_available_methods = warp::path("methods")
        .and(warp::path("available"))
        .and(warp::get())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|manager: Arc<AuthApiManager>| async move {
            match manager.get_available_methods().await {
                Ok(methods) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(methods))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Authentication endpoint
    let authenticate = warp::path("auth")
        .and(warp::post())
        .and(warp::body::json::<AuthRequest>())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|request: AuthRequest, manager: Arc<AuthApiManager>| async move {
            let context = ServiceContext {
                ip_address: None,
                user_agent: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                device_fingerprint: None,
                request_id: Uuid::new_v4().to_string(),
                metadata: HashMap::new(),
            };

            match manager.auth_service.authenticate(request, context).await {
                Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(result))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Token validation endpoint
    let validate_token = warp::path("auth")
        .and(warp::path("validate"))
        .and(warp::post())
        .and(warp::body::json::<TokenValidationRequest>())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|request: TokenValidationRequest, manager: Arc<AuthApiManager>| async move {
            let context = ServiceContext {
                ip_address: None,
                user_agent: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                device_fingerprint: None,
                request_id: request.request_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
                metadata: HashMap::new(),
            };

            match manager.auth_service.validate_token(&request.token, context).await {
                Ok(user_info) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(user_info))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Token refresh endpoint
    let refresh_token = warp::path("auth")
        .and(warp::path("refresh"))
        .and(warp::post())
        .and(warp::body::json::<TokenRefreshRequest>())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|request: TokenRefreshRequest, manager: Arc<AuthApiManager>| async move {
            let context = ServiceContext {
                ip_address: None,
                user_agent: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                device_fingerprint: None,
                request_id: request.request_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
                metadata: HashMap::new(),
            };

            match manager.auth_service.refresh_token(&request.refresh_token, context).await {
                Ok(result) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success(result))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Logout endpoint
    let logout = warp::path("auth")
        .and(warp::path("logout"))
        .and(warp::post())
        .and(warp::body::json::<LogoutRequest>())
        .and(with_auth_api_manager(api_manager_clone.clone()))
        .and_then(|request: LogoutRequest, manager: Arc<AuthApiManager>| async move {
            let context = ServiceContext {
                ip_address: None,
                user_agent: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                device_fingerprint: None,
                request_id: request.request_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
                metadata: HashMap::new(),
            };

            match manager.auth_service.logout(&request.token, context).await {
                Ok(()) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::success("Logged out successfully"))),
                Err(e) => Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value>::error(&e.to_string()))),
            }
        });

    // Combine all routes
    list_plugins
        .or(list_loaded)
        .or(get_plugin)
        .or(deploy_plugin)
        .or(reload_plugin)
        .or(set_default_method)
        .or(get_default_method)
        .or(get_service_stats)
        .or(get_plugin_stats)
        .or(health_check)
        .or(get_available_methods)
        .or(authenticate)
        .or(validate_token)
        .or(refresh_token)
        .or(logout)
}

/// Warp filter to inject the API manager
fn with_auth_api_manager(
    api_manager: Arc<AuthApiManager>,
) -> impl Clone + warp::Filter<Extract = (Arc<AuthApiManager>,), Error = std::convert::Infallible> {
    warp::any().map(move || api_manager.clone())
}

/// Create CORS configuration for API
pub fn create_cors_config(_config: &AuthApiConfig) -> warp::cors::Builder {
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec![
            warp::http::Method::GET,
            warp::http::Method::POST,
            warp::http::Method::PUT,
            warp::http::Method::DELETE,
            warp::http::Method::OPTIONS,
        ])
        .allow_headers(vec![
            warp::http::header::AUTHORIZATION,
            warp::http::header::ACCEPT,
            warp::http::header::CONTENT_TYPE,
        ])
        .allow_credentials(true);
    
    cors
}

/// API documentation structure
#[derive(Debug, Serialize)]
struct ApiDocumentation {
    title: String,
    version: String,
    description: String,
    endpoints: Vec<EndpointDoc>,
}

#[derive(Debug, Serialize)]
struct EndpointDoc {
    path: String,
    method: String,
    description: String,
    parameters: Vec<ParameterDoc>,
}

#[derive(Debug, Serialize)]
struct ParameterDoc {
    name: String,
    type_: String,
    description: String,
    required: bool,
}

/// Get API documentation
pub fn get_api_documentation() -> ApiDocumentation {
    ApiDocumentation {
        title: "Fortress Authentication Plugin API".to_string(),
        version: "1.0.0".to_string(),
        description: "REST API for managing authentication plugins and performing authentication".to_string(),
        endpoints: vec![
            EndpointDoc {
                path: "/plugins".to_string(),
                method: "GET".to_string(),
                description: "List all registered plugins".to_string(),
                parameters: vec![],
            },
            EndpointDoc {
                path: "/plugins/loaded".to_string(),
                method: "GET".to_string(),
                description: "List currently loaded plugins".to_string(),
                parameters: vec![],
            },
            EndpointDoc {
                path: "/plugins/{name}".to_string(),
                method: "GET".to_string(),
                description: "Get plugin metadata".to_string(),
                parameters: vec![
                    ParameterDoc {
                        name: "name".to_string(),
                        type_: "string".to_string(),
                        description: "Plugin name".to_string(),
                        required: true,
                    },
                ],
            },
            EndpointDoc {
                path: "/plugins/deploy".to_string(),
                method: "POST".to_string(),
                description: "Deploy a new plugin".to_string(),
                parameters: vec![
                    ParameterDoc {
                        name: "deployment".to_string(),
                        type_: "object".to_string(),
                        description: "Plugin deployment configuration".to_string(),
                        required: true,
                    },
                ],
            },
            EndpointDoc {
                path: "/plugins/{name}/reload".to_string(),
                method: "POST".to_string(),
                description: "Reload a plugin".to_string(),
                parameters: vec![
                    ParameterDoc {
                        name: "name".to_string(),
                        type_: "string".to_string(),
                        description: "Plugin name".to_string(),
                        required: true,
                    },
                    ParameterDoc {
                        name: "force".to_string(),
                        type_: "boolean".to_string(),
                        description: "Force reload even if same version".to_string(),
                        required: false,
                    },
                ],
            },
            EndpointDoc {
                path: "/auth".to_string(),
                method: "POST".to_string(),
                description: "Authenticate using available methods".to_string(),
                parameters: vec![
                    ParameterDoc {
                        name: "request".to_string(),
                        type_: "object".to_string(),
                        description: "Authentication request".to_string(),
                        required: true,
                    },
                ],
            },
            EndpointDoc {
                path: "/auth/validate".to_string(),
                method: "POST".to_string(),
                description: "Validate authentication token".to_string(),
                parameters: vec![
                    ParameterDoc {
                        name: "token".to_string(),
                        type_: "string".to_string(),
                        description: "Token to validate".to_string(),
                        required: true,
                    },
                ],
            },
            EndpointDoc {
                path: "/auth/refresh".to_string(),
                method: "POST".to_string(),
                description: "Refresh authentication token".to_string(),
                parameters: vec![
                    ParameterDoc {
                        name: "refresh_token".to_string(),
                        type_: "string".to_string(),
                        description: "Refresh token".to_string(),
                        required: true,
                    },
                ],
            },
            EndpointDoc {
                path: "/auth/logout".to_string(),
                method: "POST".to_string(),
                description: "Logout user/session".to_string(),
                parameters: vec![
                    ParameterDoc {
                        name: "token".to_string(),
                        type_: "string".to_string(),
                        description: "Token to logout".to_string(),
                        required: true,
                    },
                ],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_manager_creation() {
        let auth_service = Arc::new(PluginAuthService::new(AuthServiceConfig::default()).await.unwrap());
        let config = AuthApiConfig::default();
        let api_manager = AuthApiManager::new(auth_service, config);
        
        // Test that the manager was created successfully
        let plugins = api_manager.list_plugins().await;
        assert!(plugins.is_ok());
    }

    #[tokio::test]
    async fn test_api_documentation() {
        let docs = get_api_documentation();
        assert_eq!(docs.title, "Fortress Authentication Plugin API");
        assert_eq!(docs.endpoints.len(), 10);
    }

    #[tokio::test]
    async fn test_cors_config() {
        let config = AuthApiConfig::default();
        let cors = create_cors_config(&config);
        
        // Verify CORS configuration
        assert_eq!(cors.allowed_origins.len(), 1);
        assert_eq!(cors.allowed_origins[0], "*");
    }
}
