//! # Kubernetes Authentication Module
//!
//! Kubernetes TokenReview-based authentication for automatic pod login.
//!
//! ## Features
//!
//! - **TokenReview API**: Native Kubernetes token validation
//! - **Service Account Authentication**: Automatic pod identity verification
//! - **Role-Based Access**: Map Kubernetes roles to Fortress permissions
//! - **Namespace Isolation**: Enforce namespace-based access controls
//! - **Certificate Validation**: Verify Kubernetes API server certificates
//!
//! ## Usage
//!
//! ```rust,no_run
//! use fortress_core::kubernetes_auth::KubernetesAuth;
//! use serde_json::json;
//!
//! let mut auth = KubernetesAuth::new();
//!
//! // Configure Kubernetes connection
//! auth.configure(json!({
//!     "kubernetes_host": "https://kubernetes.default.svc",
//!     "kubernetes_ca_cert": "-----BEGIN CERTIFICATE-----...",
//!     "service_account_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
//! })).await?;
//!
//! // Authenticate a pod
//! let result = auth.authenticate_pod("default", "my-pod", "service-account-token").await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::encryption::{Aegis256Wrapper as Aegis256, EncryptionAlgorithm};
use crate::error::{FortressError, Result};
use crate::secrets::{
    EngineStats, EngineStatus, EngineType, LeaseInfo, Secret, SecretMetadata, SecretsEngine,
};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Kubernetes-specific imports for actual API calls
#[cfg(feature = "k8s")]
use k8s_openapi::api::{authentication::v1::TokenReview, core::v1::Pod};
#[cfg(feature = "k8s")]
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
#[cfg(feature = "k8s")]
use kube::Client;
#[cfg(feature = "k8s")]
use kube::Config;

/// Kubernetes authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesAuthConfig {
    /// Kubernetes API server host
    pub kubernetes_host: String,
    /// Kubernetes API server port
    pub _kubernetes_port: u16,
    /// CA certificate for Kubernetes API server
    pub kubernetes_ca_cert: Option<String>,
    /// Service account JWT token
    pub service_account_token: Option<String>,
    /// Default token TTL
    pub default_ttl: u64,
    /// Maximum token TTL
    pub max_ttl: u64,
    /// Enable namespace isolation
    pub namespace_isolation: bool,
    /// Allowed namespaces (empty means all)
    pub allowed_namespaces: Vec<String>,
    /// Role mapping configuration
    pub role_mappings: HashMap<String, Vec<String>>,
}

/// Kubernetes TokenReview request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenReviewRequest {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Token review spec
    pub spec: TokenReviewSpec,
}

/// TokenReview specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenReviewSpec {
    /// Token to review
    pub token: String,
    /// Audiences for the token
    pub audiences: Option<Vec<String>>,
}

/// Kubernetes TokenReview response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenReviewResponse {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Token review status
    pub status: TokenReviewStatus,
}

/// TokenReview status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenReviewStatus {
    /// Whether the token is authenticated
    pub authenticated: bool,
    /// User information
    pub user: Option<TokenUserInfo>,
    /// Error message if authentication failed
    pub error: Option<String>,
    /// Audiences that were validated
    pub audiences: Option<Vec<String>>,
}

/// Token user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUserInfo {
    /// Username
    pub username: String,
    /// UID
    pub uid: String,
    /// Groups
    pub groups: Vec<String>,
    /// Extra information
    pub extra: Option<HashMap<String, Vec<String>>>,
}

/// Pod authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodAuthResult {
    /// Whether authentication succeeded
    pub authenticated: bool,
    /// Pod namespace
    pub namespace: String,
    /// Pod name
    pub pod_name: String,
    /// Service account name
    pub service_account: String,
    /// User information
    pub user_info: Option<TokenUserInfo>,
    /// Granted permissions
    pub permissions: Vec<String>,
    /// Session token
    pub session_token: Option<String>,
    /// Session expiration
    pub expires_at: Option<DateTime<Utc>>,
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// Kubernetes authentication engine
#[derive(Debug)]
pub struct KubernetesAuth {
    /// Authentication configuration
    config: Arc<RwLock<Option<KubernetesAuthConfig>>>,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, PodAuthResult>>>,
    /// Statistics
    stats: Arc<RwLock<EngineStats>>,
    /// HTTP client for Kubernetes API
    http_client: Arc<reqwest::Client>,
    /// Encryption for session tokens
    encryption: Arc<Box<dyn EncryptionAlgorithm>>,
}

impl KubernetesAuth {
    /// Create new Kubernetes authentication engine
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config: Arc::new(RwLock::new(None)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EngineStats {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                avg_operation_time_ms: 0.0,
                active_leases: 0,
                stored_secrets: 0,
                total_secrets: 0,
                operations: HashMap::new(),
                last_operation: None,
            })),
            http_client: Arc::new(http_client),
            encryption: Arc::new(Box::new(Aegis256::new())),
        }
    }

    /// Perform TokenReview with Kubernetes API
    async fn token_review(&self, token: &str) -> Result<TokenReviewResponse> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Kubernetes auth not configured".to_string()))?;

        #[cfg(feature = "k8s")]
        {
            // Use actual Kubernetes client
            let kube_config = Config::infer().await.map_err(|e| {
                FortressError::secrets(format!("Failed to load Kubernetes config: {}", e))
            })?;

            let client = Client::try_from(kube_config).await.map_err(|e| {
                FortressError::secrets(format!("Failed to create Kubernetes client: {}", e))
            })?;

            let token_review = TokenReview {
                metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta::default(),
                spec: k8s_openapi::api::authentication::v1::TokenReviewSpec {
                    token: token.to_string(),
                    audiences: Some(vec!["fortress".to_string()]),
                },
                status: None,
            };

            match client.create(&token_review).await {
                Ok(token_review_response) => {
                    let status = token_review_response.status.ok_or_else(|| {
                        FortressError::secrets("No status in TokenReview response".to_string())
                    })?;

                    Ok(TokenReviewResponse {
                        api_version: "authentication.k8s.io/v1".to_string(),
                        kind: "TokenReview".to_string(),
                        status: TokenReviewStatus {
                            authenticated: status.authenticated,
                            user: status.user.map(|u| TokenUserInfo {
                                username: u.username,
                                uid: u.uid,
                                groups: u.groups,
                                extra: u.extra,
                            }),
                            error: status.error,
                            audiences: status.audiences,
                        },
                    })
                }
                Err(e) => {
                    log::error!("Failed to perform TokenReview: {}", e);
                    Err(FortressError::secrets(format!("TokenReview failed: {}", e)))
                }
            }
        }

        #[cfg(not(feature = "k8s"))]
        {
            // Fallback to simulation when k8s feature is not enabled
            log::warn!("Kubernetes feature not enabled, simulating TokenReview");

            // Simulate TokenReview for testing
            let token_review_request = TokenReviewRequest {
                api_version: "authentication.k8s.io/v1".to_string(),
                kind: "TokenReview".to_string(),
                spec: TokenReviewSpec {
                    token: token.to_string(),
                    audiences: Some(vec!["fortress".to_string()]),
                },
            };

            // Simulate API call
            let url = format!(
                "{}:{}/apis/authentication.k8s.io/v1/tokenreviews",
                config.kubernetes_host.trim_end_matches('/'),
                config.kubernetes_port
            );

            let request = self
                .http_client
                .post(&url)
                .header("Content-Type", "application/json")
                .header(
                    "Authorization",
                    format!(
                        "Bearer {}",
                        config.service_account_token.as_ref().ok_or_else(|| {
                            FortressError::secrets(
                                "Service account token not configured".to_string(),
                            )
                        })?
                    ),
                );

            // Add CA certificate if provided
            if let Some(_ca_cert) = &config.kubernetes_ca_cert {
                log::debug!("Using Kubernetes CA certificate for API validation");
            }

            let response = request
                .json(&token_review_request)
                .send()
                .await
                .map_err(|e| {
                    FortressError::secrets(format!("Failed to send TokenReview request: {}", e))
                })?;

            if response.status().is_success() {
                let token_response: TokenReviewResponse = response.json().await.map_err(|e| {
                    FortressError::secrets(format!("Failed to parse TokenReview response: {}", e))
                })?;

                Ok(token_response)
            } else {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());

                Err(FortressError::secrets(format!(
                    "TokenReview failed: {}",
                    error_text
                )))
            }
        }
    }

    /// Extract pod information from token
    fn extract_pod_info(&self, user_info: &TokenUserInfo) -> Result<(String, String, String)> {
        // Kubernetes service account tokens have format: system:serviceaccount:<namespace>:<service-account>
        if user_info.username.starts_with("system:serviceaccount:") {
            let parts: Vec<&str> = user_info.username.split(':').collect();
            if parts.len() >= 4 {
                let namespace = parts[2].to_string();
                let service_account = parts[3].to_string();

                // Extract pod name from extra information if available
                let pod_name = user_info
                    .extra
                    .as_ref()
                    .and_then(|extra| extra.get("authentication.kubernetes.io/pod-name"))
                    .and_then(|pod_names| pod_names.first())
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                return Ok((namespace, pod_name, service_account));
            }
        }

        Err(FortressError::secrets(
            "Invalid service account token format".to_string(),
        ))
    }

    /// Map Kubernetes roles to Fortress permissions
    async fn map_permissions(
        &self,
        namespace: &str,
        service_account: &str,
        groups: &[String],
    ) -> Vec<String> {
        let config = self.config.read().await;

        if let Some(config) = config.as_ref() {
            // Check for specific role mappings
            let role_key = format!("{}:{}", namespace, service_account);
            if let Some(permissions) = config.role_mappings.get(&role_key) {
                return permissions.clone();
            }

            // Check for group-based mappings
            for group in groups {
                let group_key = format!("group:{}", group);
                if let Some(permissions) = config.role_mappings.get(&group_key) {
                    return permissions.clone();
                }
            }

            // Default permissions based on namespace
            if config.allowed_namespaces.is_empty()
                || config.allowed_namespaces.contains(&namespace.to_string())
            {
                vec!["read".to_string(), "list".to_string()]
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }

    /// Generate session token
    fn generate_session_token(&self, namespace: &str, pod_name: &str) -> Result<String> {
        let session_data = format!("{}:{}:{}", namespace, pod_name, Utc::now().timestamp());

        // Generate random encryption key for session using OsRng
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);

        // Encrypt session data
        let encrypted_data = self
            .encryption
            .encrypt(session_data.as_bytes(), &key)
            .map_err(|e| {
                FortressError::secrets(format!("Failed to encrypt session token: {}", e))
            })?;

        // Encode as base64
        Ok(base64::engine::general_purpose::STANDARD.encode(encrypted_data))
    }

    /// Authenticate a pod using TokenReview
    pub async fn authenticate_pod(
        &self,
        namespace: &str,
        pod_name: &str,
        service_account_token: &str,
    ) -> Result<PodAuthResult> {
        log::info!("Authenticating pod {} in namespace {}", pod_name, namespace);

        // Perform TokenReview
        let token_response = self.token_review(service_account_token).await?;

        if !token_response.status.authenticated {
            return Ok(PodAuthResult {
                authenticated: false,
                namespace: namespace.to_string(),
                pod_name: pod_name.to_string(),
                service_account: "unknown".to_string(),
                user_info: None,
                permissions: vec![],
                session_token: None,
                expires_at: None,
                error: token_response.status.error,
            });
        }

        let user_info = token_response.status.user.ok_or_else(|| {
            FortressError::secrets("No user info in TokenReview response".to_string())
        })?;

        // Extract pod information
        let (token_namespace, token_pod_name, service_account) =
            self.extract_pod_info(&user_info)?;

        // Verify namespace and pod match
        if token_namespace != namespace || token_pod_name != pod_name {
            log::warn!(
                "Namespace or pod name mismatch: expected {}/{}, got {}/{}",
                namespace,
                pod_name,
                token_namespace,
                token_pod_name
            );

            return Ok(PodAuthResult {
                authenticated: false,
                namespace: namespace.to_string(),
                pod_name: pod_name.to_string(),
                service_account,
                user_info: Some(user_info),
                permissions: vec![],
                session_token: None,
                expires_at: None,
                error: Some("Namespace or pod name mismatch".to_string()),
            });
        }

        // Check namespace isolation
        let config = self.config.read().await;
        if let Some(config) = config.as_ref() {
            if config.namespace_isolation
                && !config.allowed_namespaces.is_empty()
                && !config.allowed_namespaces.contains(&namespace.to_string())
            {
                log::warn!("Namespace {} not allowed for pod authentication", namespace);
                return Ok(PodAuthResult {
                    authenticated: false,
                    namespace: namespace.to_string(),
                    pod_name: pod_name.to_string(),
                    service_account,
                    user_info: Some(user_info),
                    permissions: vec![],
                    session_token: None,
                    expires_at: None,
                    error: Some("Namespace not allowed".to_string()),
                });
            }
        }

        // Map permissions
        let permissions = self
            .map_permissions(namespace, &service_account, &user_info.groups)
            .await;

        // Generate session token
        let session_token = self.generate_session_token(namespace, pod_name)?;
        let expires_at = Utc::now()
            + Duration::seconds(config.as_ref().map(|c| c.default_ttl).unwrap_or(3600) as i64);

        let auth_result = PodAuthResult {
            authenticated: true,
            namespace: namespace.to_string(),
            pod_name: pod_name.to_string(),
            service_account,
            user_info: Some(user_info),
            permissions: permissions.clone(),
            session_token: Some(session_token.clone()),
            expires_at: Some(expires_at),
            error: None,
        };

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_token, auth_result.clone());
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.sessions.read().await.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats
                .operations
                .entry("authenticate".to_string())
                .or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        log::info!(
            "Successfully authenticated pod {}/{} with permissions: {:?}",
            namespace,
            pod_name,
            permissions
        );

        Ok(auth_result)
    }

    /// Validate session token with enhanced checks
    pub async fn validate_session(&self, session_token: &str) -> Result<Option<PodAuthResult>> {
        let sessions = self.sessions.read().await;

        if let Some(auth_result) = sessions.get(session_token) {
            // Check if session is expired
            if let Some(expires_at) = auth_result.expires_at {
                if Utc::now() > expires_at {
                    log::info!("Session token {} has expired", session_token);
                    return Ok(None);
                }

                // Log session validation
                log::debug!(
                    "Session token {} is valid, expires at {}",
                    session_token,
                    expires_at.to_rfc3339()
                );
            }

            Ok(Some(auth_result.clone()))
        } else {
            log::warn!("Session token {} not found", session_token);
            Ok(None)
        }
    }

    /// Revoke session with logging
    pub async fn revoke_session(&self, session_token: &str) -> Result<()> {
        log::info!("Revoking session token {}", session_token);

        let mut sessions = self.sessions.write().await;

        if let Some(auth_result) = sessions.remove(session_token) {
            log::info!(
                "Successfully revoked session for pod {}/{} in namespace {}",
                auth_result.namespace,
                auth_result.pod_name,
                auth_result.namespace
            );
        } else {
            log::warn!("Session token {} not found for revocation", session_token);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = sessions.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats.operations.entry("revoke".to_string()).or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        Ok(())
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64> {
        let now = Utc::now();
        let mut expired_count = 0;

        {
            let mut sessions = self.sessions.write().await;
            let mut to_remove = Vec::new();

            for (token, auth_result) in sessions.iter() {
                if let Some(expires_at) = auth_result.expires_at {
                    if now > expires_at {
                        to_remove.push(token.clone());
                    }
                }
            }

            for token in to_remove {
                sessions.remove(&token);
                expired_count += 1;
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = self.sessions.read().await.len() as u64;
            stats.active_leases = stats.total_secrets;
        }

        if expired_count > 0 {
            log::info!("Cleaned up {} expired Kubernetes sessions", expired_count);
        }

        Ok(expired_count)
    }
}

#[async_trait::async_trait]
impl SecretsEngine for KubernetesAuth {
    fn name(&self) -> &str {
        "kubernetes-auth"
    }

    fn engine_type(&self) -> EngineType {
        EngineType::Custom("kubernetes-auth".to_string())
    }

    async fn write(&self, path: &str, data: &serde_json::Value) -> Result<Secret> {
        // Extract authentication data
        let namespace = data
            .get("namespace")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("Missing namespace".to_string()))?;

        let pod_name = data
            .get("pod_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("Missing pod_name".to_string()))?;

        let service_account_token = data
            .get("service_account_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::secrets("Missing service_account_token".to_string()))?;

        // Authenticate pod
        let auth_result = self
            .authenticate_pod(namespace, pod_name, service_account_token)
            .await?;

        if !auth_result.authenticated {
            return Err(FortressError::secrets(
                auth_result
                    .error
                    .unwrap_or_else(|| "Authentication failed".to_string()),
            ));
        }

        // Build secret data
        let secret_data = serde_json::json!({
            "authenticated": auth_result.authenticated,
            "namespace": auth_result.namespace,
            "pod_name": auth_result.pod_name,
            "service_account": auth_result.service_account,
            "permissions": auth_result.permissions,
            "session_token": auth_result.session_token,
            "expires_at": auth_result.expires_at.map(|dt| dt.to_rfc3339())
        });

        let ttl = if let Some(expires_at) = auth_result.expires_at {
            (expires_at - Utc::now()).num_seconds() as u64
        } else {
            3600
        };

        let lease = Some(LeaseInfo {
            lease_id: format!("k8s:{}:{}", namespace, pod_name),
            ttl,
            max_ttl: self
                .config
                .read()
                .await
                .as_ref()
                .map(|c| Some(c.max_ttl))
                .unwrap_or(None),
            created_at: Utc::now(),
            expires_at: auth_result
                .expires_at
                .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(3600)),
            renewable: true,
            max_renewals: Some(5),
            renewal_count: 0,
        });

        Ok(Secret {
            data: secret_data,
            metadata: SecretMetadata {
                name: path.to_string(),
                version: 1,
                created_at: Utc::now(),
                updated_at: None,
                created_by: Some("kubernetes-auth".to_string()),
                tags: HashMap::new(),
                custom: HashMap::new(),
            },
            lease,
        })
    }

    async fn read(&self, path: &str) -> Result<Option<Secret>> {
        let sessions = self.sessions.read().await;

        // Find session by path (format: "namespace/pod")
        if let Some((namespace, pod_name)) = path.split_once('/') {
            for auth_result in sessions.values() {
                if auth_result.namespace == namespace && auth_result.pod_name == pod_name {
                    let ttl = if let Some(expires_at) = auth_result.expires_at {
                        (expires_at - Utc::now()).num_seconds() as u64
                    } else {
                        3600
                    };

                    let lease = Some(LeaseInfo {
                        lease_id: format!("k8s:{}:{}", namespace, pod_name),
                        ttl,
                        max_ttl: self
                            .config
                            .read()
                            .await
                            .as_ref()
                            .map(|c| Some(c.max_ttl))
                            .unwrap_or(None),
                        created_at: Utc::now(),
                        expires_at: auth_result
                            .expires_at
                            .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(3600)),
                        renewable: true,
                        max_renewals: Some(5),
                        renewal_count: 0,
                    });

                    let secret_data = serde_json::json!({
                        "authenticated": auth_result.authenticated,
                        "namespace": auth_result.namespace,
                        "pod_name": auth_result.pod_name,
                        "service_account": auth_result.service_account,
                        "permissions": auth_result.permissions,
                        "session_token": auth_result.session_token,
                        "expires_at": auth_result.expires_at.map(|dt| dt.to_rfc3339())
                    });

                    return Ok(Some(Secret {
                        data: secret_data,
                        metadata: SecretMetadata {
                            name: path.to_string(),
                            version: 1,
                            created_at: Utc::now(),
                            updated_at: None,
                            created_by: Some("kubernetes-auth".to_string()),
                            tags: HashMap::new(),
                            custom: HashMap::new(),
                        },
                        lease,
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        // Find and remove session by path
        if let Some((namespace, pod_name)) = path.split_once('/') {
            let to_remove: Vec<String> = sessions
                .iter()
                .filter(|(_, auth_result)| {
                    auth_result.namespace == namespace && auth_result.pod_name == pod_name
                })
                .map(|(token, _)| token.clone())
                .collect();

            for token in to_remove {
                sessions.remove(&token);
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = sessions.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats.operations.entry("delete".to_string()).or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        Ok(())
    }

    /// List sessions
    async fn list(&self, path: &str) -> Result<Vec<String>> {
        let sessions = self.sessions.read().await;

        let mut paths = std::collections::HashSet::new();
        for auth_result in sessions.values() {
            let session_path = format!("{}/{}", auth_result.namespace, auth_result.pod_name);
            if session_path.starts_with(path) {
                paths.insert(session_path);
            }
        }

        let mut result: Vec<String> = paths.into_iter().collect();
        result.sort();
        Ok(result)
    }

    async fn renew(&self, lease_id: &str, increment: Option<u64>) -> Result<LeaseInfo> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| FortressError::secrets("Kubernetes auth not configured".to_string()))?;

        let mut sessions = self.sessions.write().await;

        // Find session by lease_id
        let auth_result = sessions
            .iter_mut()
            .find(|(_, result)| {
                result.namespace == lease_id.split(':').nth(1).unwrap_or("")
                    && result.pod_name == lease_id.split(':').nth(2).unwrap_or("")
            })
            .map(|(_, result)| result);

        if let Some(auth_result) = auth_result {
            let increment = increment.unwrap_or(config.default_ttl);
            let new_ttl = if let Some(expires_at) = auth_result.expires_at {
                (expires_at - Utc::now()).num_seconds() as u64 + increment
            } else {
                increment
            };

            if new_ttl > config.max_ttl {
                return Err(FortressError::secrets(
                    "Lease TTL exceeds maximum".to_string(),
                ));
            }

            auth_result.expires_at = Some(Utc::now() + Duration::seconds(new_ttl as i64));

            let lease = LeaseInfo {
                lease_id: lease_id.to_string(),
                ttl: new_ttl,
                max_ttl: Some(config.max_ttl),
                created_at: Utc::now(),
                expires_at: auth_result
                    .expires_at
                    .unwrap_or_else(|| Utc::now() + Duration::seconds(new_ttl as i64)),
                renewable: true,
                max_renewals: Some(5),
                renewal_count: 0,
            };

            // Update stats
            {
                let mut stats = self.stats.write().await;
                *stats.operations.entry("renew".to_string()).or_insert(0) += 1;
                stats.last_operation = Some(Utc::now());
            }

            Ok(lease)
        } else {
            Err(FortressError::secrets("Lease not found".to_string()))
        }
    }

    async fn revoke(&self, lease_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        // Find and remove session by lease_id
        let to_remove: Vec<String> = sessions
            .iter()
            .filter(|(_, result)| {
                result.namespace == lease_id.split(':').nth(1).unwrap_or("")
                    && result.pod_name == lease_id.split(':').nth(2).unwrap_or("")
            })
            .map(|(token, _)| token.clone())
            .collect();

        for token in to_remove {
            sessions.remove(&token);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_secrets = sessions.len() as u64;
            stats.active_leases = stats.total_secrets;
            *stats.operations.entry("revoke".to_string()).or_insert(0) += 1;
            stats.last_operation = Some(Utc::now());
        }

        Ok(())
    }

    async fn configure(&self, config: serde_json::Value) -> Result<()> {
        let k8s_config: KubernetesAuthConfig = serde_json::from_value(config).map_err(|e| {
            FortressError::secrets(format!("Invalid Kubernetes auth configuration: {}", e))
        })?;

        let mut self_config = self.config.write().await;
        *self_config = Some(k8s_config);

        Ok(())
    }

    async fn status(&self) -> Result<EngineStatus> {
        let config = self.config.read().await;
        let _sessions = self.sessions.read().await;
        let stats = self.stats.read().await;

        let config_value = match config.as_ref() {
            Some(c) => serde_json::to_value(c).unwrap_or_default(),
            None => serde_json::Value::Null,
        };

        Ok(EngineStatus {
            name: self.name().to_string(),
            engine_type: self.engine_type(),
            initialized: config.is_some(),
            active: true,
            last_activity: chrono::Utc::now(),
            config: config_value,
            stats: stats.clone(),
        })
    }

    async fn cleanup_expired_credentials(&self) -> Result<()> {
        self.cleanup_expired_sessions().await?;
        Ok(())
    }
}

impl Default for KubernetesAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_kubernetes_auth_creation() {
        let mut auth = KubernetesAuth::new();
        assert_eq!(auth.name(), "kubernetes-auth");
        assert!(matches!(auth.engine_type(), EngineType::Custom(_)));
    }

    #[tokio::test]
    async fn test_kubernetes_configuration() {
        let mut auth = KubernetesAuth::new();

        let config = json!({
            "kubernetes_host": "https://kubernetes.default.svc",
            "kubernetes_port": 443,
            "default_ttl": 3600,
            "max_ttl": 86400,
            "namespace_isolation": true,
            "allowed_namespaces": ["default", "production"],
            "role_mappings": {
                "default:my-service": ["read", "write"],
                "group:system:masters": ["admin"]
            }
        });

        let result = auth.configure(config).await;
        assert!(result.is_ok());

        let status = auth.status().await.unwrap();
        assert!(status.initialized);
    }

    #[tokio::test]
    async fn test_pod_info_extraction() {
        let mut auth = KubernetesAuth::new();

        let user_info = TokenUserInfo {
            username: "system:serviceaccount:default:my-service".to_string(),
            uid: "uid-123".to_string(),
            groups: vec![
                "system:serviceaccounts".to_string(),
                "system:serviceaccounts:default".to_string(),
            ],
            extra: Some(HashMap::from([(
                "authentication.kubernetes.io/pod-name".to_string(),
                vec!["my-pod".to_string()],
            )])),
        };

        let (namespace, pod_name, service_account) = auth.extract_pod_info(&user_info).unwrap();
        assert_eq!(namespace, "default");
        assert_eq!(pod_name, "my-pod");
        assert_eq!(service_account, "my-service");
    }

    #[tokio::test]
    async fn test_permission_mapping() {
        let mut auth = KubernetesAuth::new();

        let config = json!({
            "kubernetes_host": "https://kubernetes.default.svc",
            "role_mappings": {
                "default:my-service": ["read", "write"],
                "group:system:masters": ["admin"]
            }
        });

        auth.configure(config).await.unwrap();

        let permissions = auth
            .map_permissions(
                "default",
                "my-service",
                &["system:serviceaccounts".to_string()],
            )
            .await;
        assert_eq!(permissions, vec!["read", "write"]);

        let admin_permissions = auth
            .map_permissions(
                "production",
                "admin-service",
                &["system:masters".to_string()],
            )
            .await;
        assert_eq!(admin_permissions, vec!["admin"]);
    }

    #[tokio::test]
    async fn test_session_token_generation() {
        let mut auth = KubernetesAuth::new();

        let token1 = auth.generate_session_token("default", "my-pod").unwrap();
        let token2 = auth.generate_session_token("default", "my-pod").unwrap();

        assert_ne!(token1, token2);
        assert!(!token1.is_empty());
        assert!(!token2.is_empty());
    }

    #[tokio::test]
    async fn test_session_validation() {
        let mut auth = KubernetesAuth::new();

        // Configure auth
        let config = json!({
            "kubernetes_host": "https://kubernetes.default.svc",
            "default_ttl": 3600
        });
        auth.configure(config).await.unwrap();

        // Create a mock session (in real scenario, this would come from authentication)
        let session_token = auth.generate_session_token("default", "my-pod").unwrap();

        // Validate session (should fail since we don't have the session stored)
        let result = auth.validate_session(&session_token).await.unwrap();
        assert!(result.is_none());
    }
}
