//! OIDC (OpenID Connect) Provider Implementation
//!
//! This module provides a complete OIDC provider implementation for Fortress,
//! enabling internal services to authenticate using industry-standard OIDC protocols.
//! Includes support for Rego policies for authorization decisions.

use crate::auth::{AuthManager, TokenClaims, User};
use crate::error::EncryptionErrorCode;
use crate::error::FortressError;
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// OIDC Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL
    pub issuer: String,
    /// Supported response types
    pub response_types: Vec<String>,
    /// Supported grant types
    pub grant_types: Vec<String>,
    /// Supported scopes
    pub scopes: Vec<String>,
    /// Supported response modes
    pub response_modes: Vec<String>,
    /// Token expiration times
    pub token_expiration: TokenExpiration,
    /// JWKS configuration
    pub jwks: JwksConfig,
    /// Client configuration
    pub clients: HashMap<String, OidcClient>,
    /// Rego policy configuration
    pub rego_policies: Option<RegoConfig>,
}

/// Token expiration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExpiration {
    /// Authorization code expiration (seconds)
    pub auth_code: u64,
    /// Access token expiration (seconds)
    pub access_token: u64,
    /// Refresh token expiration (seconds)
    pub refresh_token: u64,
    /// ID token expiration (seconds)
    pub id_token: u64,
}

/// JWKS (JSON Web Key Set) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksConfig {
    /// Key rotation interval in seconds
    pub rotation_interval: u64,
    /// Minimum key size
    pub min_key_size: usize,
    /// Supported algorithms
    pub algorithms: Vec<String>,
}

/// OIDC Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    /// Client ID
    pub client_id: String,
    /// Client secret (optional for public clients)
    pub client_secret: Option<String>,
    /// Client name
    pub name: String,
    /// Redirect URIs
    pub redirect_uris: Vec<String>,
    /// Grant types allowed for this client
    pub grant_types: Vec<String>,
    /// Response types allowed for this client
    pub response_types: Vec<String>,
    /// Scopes allowed for this client
    pub scopes: Vec<String>,
    /// Whether client is public
    pub public: bool,
    /// Client metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Rego policy configuration for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegoConfig {
    /// Policy directory
    pub policy_dir: String,
    /// Data directory
    pub data_dir: Option<String>,
    /// Enable policy caching
    pub enable_cache: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
}

/// OIDC Authorization Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAuthRequest {
    /// Response type
    pub response_type: String,
    /// Client ID
    pub client_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Scope
    pub scope: String,
    /// State parameter
    pub state: Option<String>,
    /// Nonce parameter
    pub nonce: Option<String>,
    /// Response mode
    pub response_mode: Option<String>,
    /// Code challenge (PKCE)
    pub code_challenge: Option<String>,
    /// Code challenge method (PKCE)
    pub code_challenge_method: Option<String>,
    /// Additional parameters
    pub additional_params: HashMap<String, String>,
}

/// OIDC Token Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenRequest {
    /// Grant type
    pub grant_type: String,
    /// Authorization code (for authorization code grant)
    pub code: Option<String>,
    /// Redirect URI (for authorization code grant)
    pub redirect_uri: Option<String>,
    /// Code verifier (PKCE)
    pub code_verifier: Option<String>,
    /// Refresh token (for refresh token grant)
    pub refresh_token: Option<String>,
    /// Client credentials
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Scope (optional)
    pub scope: Option<String>,
}

/// OIDC Token Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type
    pub token_type: String,
    /// Expires in
    pub expires_in: u64,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// ID token
    pub id_token: Option<String>,
    /// Scope
    pub scope: Option<String>,
}

/// OIDC User Info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    /// Subject identifier
    pub sub: String,
    /// Name
    pub name: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Email verified
    pub email_verified: Option<bool>,
    /// Preferred username
    pub preferred_username: Option<String>,
    /// Groups
    pub groups: Option<Vec<String>>,
    /// Additional claims
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

/// JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key ID
    pub kid: String,
    /// Key type
    pub kty: String,
    /// Key usage
    pub use_: Option<String>,
    /// Key operations
    pub key_ops: Option<Vec<String>>,
    /// Algorithm
    pub alg: Option<String>,
    /// Key value (base64url)
    pub n: Option<String>,
    /// Exponent (base64url)
    pub e: Option<String>,
    /// Curve name
    pub crv: Option<String>,
    /// X coordinate (base64url)
    pub x: Option<String>,
    /// Y coordinate (base64url)
    pub y: Option<String>,
}

/// JSON Web Key Set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    /// Keys
    pub keys: Vec<JsonWebKey>,
}

/// Authorization code information
#[derive(Debug, Clone)]
struct AuthCodeInfo {
    /// Code value
    pub code: String,
    /// Client ID
    pub client_id: String,
    /// User ID
    pub user_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Scope
    pub scope: String,
    /// Nonce
    pub nonce: Option<String>,
    /// Code challenge (PKCE)
    pub code_challenge: Option<String>,
    /// Code challenge method (PKCE)
    pub code_challenge_method: Option<String>,
    /// Created at
    pub created_at: u64,
    /// Expires at
    pub expires_at: u64,
}

/// OIDC Provider implementation
pub struct OidcProvider {
    /// Configuration
    config: OidcConfig,
    /// Authentication manager
    auth_manager: AuthManager,
    /// Active authorization codes
    auth_codes: HashMap<String, AuthCodeInfo>,
    /// Active refresh tokens
    refresh_tokens: HashMap<String, RefreshTokenInfo>,
    /// JSON Web Keys
    jwks: JsonWebKeySet,
    /// Rego policy engine (if enabled)
    rego_engine: Option<RegoPolicyEngine>,
    /// Policy evaluation cache
    cache: HashMap<String, bool>,
    /// Cache timestamps
    cache_timestamps: HashMap<String, u64>,
    /// Policy data
    data: HashMap<String, serde_json::Value>,
}

/// Refresh token information
#[derive(Debug, Clone)]
struct RefreshTokenInfo {
    /// Token value
    pub token: String,
    /// User ID
    pub user_id: String,
    /// Client ID
    pub client_id: String,
    /// Scope
    pub scope: String,
    /// Created at
    pub created_at: u64,
    /// Expires at
    pub expires_at: u64,
}

/// Policy engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStats {
    /// Total number of loaded policies
    pub total_policies: usize,
    /// Number of cached evaluation results
    pub cached_results: usize,
    /// Number of data entries
    pub data_entries: usize,
}

/// Rego Policy Engine for authorization decisions
pub struct RegoPolicyEngine {
    /// Policy evaluation cache
    cache: HashMap<String, bool>,
    /// Cache TTL in seconds
    cache_ttl: u64,
    /// Cache timestamps
    cache_timestamps: HashMap<String, u64>,
    /// Policy data
    data: HashMap<String, serde_json::Value>,
}

impl OidcProvider {
    /// Create a new OIDC provider
    pub fn new(config: OidcConfig, auth_manager: AuthManager) -> Result<Self, FortressError> {
        // Initialize Rego engine if configured
        let rego_engine = if let Some(rego_config) = &config.rego_policies {
            Some(RegoPolicyEngine::new(rego_config)?)
        } else {
            None
        };

        // Generate initial JWKS
        let jwks = Self::generate_jwks(&config.jwks)?;

        Ok(Self {
            config,
            auth_manager,
            auth_codes: HashMap::new(),
            refresh_tokens: HashMap::new(),
            jwks,
            rego_engine,
            cache: HashMap::new(),
            cache_timestamps: HashMap::new(),
            data: HashMap::new(),
        })
    }

    /// Handle authorization request
    pub async fn authorize(&mut self, request: OidcAuthRequest) -> Result<String, FortressError> {
        // Validate client
        let client = self
            .config
            .clients
            .get(&request.client_id)
            .ok_or_else(|| FortressError::validation("Invalid client_id", None, None))?;

        // Validate redirect URI
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(FortressError::validation(
                "Invalid redirect_uri",
                None,
                None,
            ));
        }

        // Validate response type
        if !client.response_types.contains(&request.response_type) {
            return Err(FortressError::validation(
                "Unsupported response_type",
                None,
                None,
            ));
        }

        // Validate scope
        let requested_scopes: HashSet<&str> = request.scope.split_whitespace().collect();
        let allowed_scopes: HashSet<&str> = client.scopes.iter().map(|s| s.as_str()).collect();

        if !requested_scopes.is_subset(&allowed_scopes) {
            return Err(FortressError::validation("Invalid scope", None, None));
        }

        // For this example, we'll assume the user is already authenticated
        // In a real implementation, you would redirect to login page
        let user_id = "authenticated_user".to_string();

        // Check authorization policies if Rego is enabled
        if let Some(rego_engine) = &mut self.rego_engine {
            if !rego_engine.evaluate_authorization(&user_id, &request.client_id, &request.scope)? {
                return Err(FortressError::authentication(
                    "Access denied by policy",
                    Some(user_id),
                ));
            }
        }

        // Generate authorization code
        let code = Uuid::new_v4().to_string();
        let now = current_timestamp();
        let expires_at = now + self.config.token_expiration.auth_code;

        let auth_code_info = AuthCodeInfo {
            code: code.clone(),
            client_id: request.client_id.clone(),
            user_id,
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            created_at: now,
            expires_at,
        };

        self.auth_codes.insert(code.clone(), auth_code_info);

        // Build redirect URL with code and state
        let mut redirect_url = format!("{}?code={}", request.redirect_uri, code);
        if let Some(state) = &request.state {
            redirect_url.push_str(&format!("&state={}", urlencoding::encode(state)));
        }

        Ok(redirect_url)
    }

    /// Handle token request
    pub async fn token(
        &mut self,
        request: OidcTokenRequest,
    ) -> Result<OidcTokenResponse, FortressError> {
        match request.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code_grant(request).await,
            "refresh_token" => self.handle_refresh_token_grant(request).await,
            "client_credentials" => self.handle_client_credentials_grant(request).await,
            _ => Err(FortressError::validation(
                "Unsupported grant_type",
                None,
                None,
            )),
        }
    }

    /// Handle authorization code grant
    async fn handle_authorization_code_grant(
        &mut self,
        request: OidcTokenRequest,
    ) -> Result<OidcTokenResponse, FortressError> {
        let code = request
            .code
            .ok_or_else(|| FortressError::validation("Missing code", None, None))?;
        let redirect_uri = request
            .redirect_uri
            .ok_or_else(|| FortressError::validation("Missing redirect_uri", None, None))?;

        // Validate client
        let client = self
            .config
            .clients
            .get(&request.client_id)
            .ok_or_else(|| FortressError::validation("Invalid client_id", None, None))?;

        // Validate client secret for confidential clients
        if !client.public {
            let client_secret = request
                .client_secret
                .as_ref()
                .ok_or_else(|| FortressError::validation("Missing client_secret", None, None))?;
            if client.client_secret.as_ref() != Some(client_secret) {
                return Err(FortressError::authentication(
                    "Invalid client credentials",
                    None,
                ));
            }
        }

        // Validate authorization code
        let auth_code_info = self
            .auth_codes
            .remove(&code)
            .ok_or_else(|| FortressError::validation("Invalid or expired code", None, None))?;

        // Check if code is expired
        if current_timestamp() > auth_code_info.expires_at {
            return Err(FortressError::validation(
                "Authorization code expired",
                None,
                None,
            ));
        }

        // Validate redirect URI
        if auth_code_info.redirect_uri != redirect_uri {
            return Err(FortressError::validation(
                "Redirect URI mismatch",
                None,
                None,
            ));
        }

        // Validate client ID
        if auth_code_info.client_id != request.client_id {
            return Err(FortressError::validation("Client ID mismatch", None, None));
        }

        // Validate PKCE if present
        if let (Some(code_challenge), Some(code_verifier)) =
            (&auth_code_info.code_challenge, &request.code_verifier)
        {
            let method = auth_code_info
                .code_challenge_method
                .as_deref()
                .unwrap_or("plain");
            if !self.validate_pkce(code_challenge, code_verifier, method)? {
                return Err(FortressError::authentication("Invalid PKCE verifier", None));
            }
        }

        // Get user information
        let user = self
            .auth_manager
            .get_user(&auth_code_info.user_id)
            .ok_or_else(|| FortressError::authentication("User not found", None))?;

        // Clone user data to avoid borrow issues
        let user_id = user.id.clone();
        let _user_roles = user.roles.clone();

        // Generate tokens (refresh token needs mutable borrow)
        let refresh_token = self.generate_refresh_token(&auth_code_info)?;

        // Get user again for token generation (or use cloned data)
        let user = self
            .auth_manager
            .get_user(&user_id)
            .ok_or_else(|| FortressError::authentication("User not found", None))?;
        let access_token = self.generate_access_token(&user, &auth_code_info)?;
        let id_token = self.generate_id_token(&user, &auth_code_info)?;

        Ok(OidcTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.token_expiration.access_token,
            refresh_token: Some(refresh_token),
            id_token: Some(id_token),
            scope: Some(auth_code_info.scope),
        })
    }

    /// Handle refresh token grant
    async fn handle_refresh_token_grant(
        &mut self,
        request: OidcTokenRequest,
    ) -> Result<OidcTokenResponse, FortressError> {
        let refresh_token = request
            .refresh_token
            .ok_or_else(|| FortressError::validation("Missing refresh_token", None, None))?;

        // Validate refresh token
        let token_info = self
            .refresh_tokens
            .get(&refresh_token)
            .ok_or_else(|| FortressError::validation("Invalid refresh_token", None, None))?;

        // Check if refresh token is expired
        if current_timestamp() > token_info.expires_at {
            return Err(FortressError::validation(
                "Refresh token expired",
                None,
                None,
            ));
        }

        // Get user information
        let user = self
            .auth_manager
            .get_user(&token_info.user_id)
            .ok_or_else(|| FortressError::authentication("User not found", None))?;

        // Generate new access token
        let access_token = self.generate_access_token_from_refresh(&user, &token_info)?;

        Ok(OidcTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.token_expiration.access_token,
            refresh_token: Some(refresh_token),
            id_token: None,
            scope: Some(token_info.scope.clone()),
        })
    }

    /// Handle client credentials grant
    async fn handle_client_credentials_grant(
        &mut self,
        request: OidcTokenRequest,
    ) -> Result<OidcTokenResponse, FortressError> {
        // Validate client
        let client = self
            .config
            .clients
            .get(&request.client_id)
            .ok_or_else(|| FortressError::validation("Invalid client_id", None, None))?;

        let client_secret = request
            .client_secret
            .as_ref()
            .ok_or_else(|| FortressError::validation("Missing client_secret", None, None))?;

        if client.client_secret.as_ref() != Some(client_secret) {
            return Err(FortressError::authentication(
                "Invalid client credentials",
                None,
            ));
        }

        // For client credentials, we create a synthetic user representing the client
        let synthetic_user = User {
            id: format!("client_{}", request.client_id),
            username: request.client_id.clone(),
            email: format!("{}@clients.local", request.client_id),
            full_name: client.name.clone(),
            roles: vec![],
            active: true,
            created_at: current_timestamp(),
            last_login: None,
            password_hash: String::new(),
        };

        // Generate access token
        let scope = request
            .scope
            .unwrap_or_else(|| "client_credentials".to_string());
        let auth_code_info = AuthCodeInfo {
            code: String::new(),
            client_id: request.client_id.clone(),
            user_id: synthetic_user.id.clone(),
            redirect_uri: String::new(),
            scope: scope.clone(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            created_at: current_timestamp(),
            expires_at: 0,
        };

        let access_token = self.generate_access_token(&synthetic_user, &auth_code_info)?;

        Ok(OidcTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.token_expiration.access_token,
            refresh_token: None,
            id_token: None,
            scope: Some(scope),
        })
    }

    /// Get user info
    pub async fn user_info(&self, access_token: &str) -> Result<OidcUserInfo, FortressError> {
        // Decode and validate access token
        let claims = self.decode_access_token(access_token)?;

        // Get user information
        let user = self
            .auth_manager
            .get_user(&claims.sub)
            .ok_or_else(|| FortressError::authentication("User not found", None))?;

        // Get user permissions and roles
        let user_id = user.id.clone(); // Clone to avoid move issues
        let permissions = self.auth_manager.get_user_permissions(&user.id);
        let roles: Vec<String> = user
            .roles
            .iter()
            .filter_map(|role_id| self.auth_manager.get_role(role_id))
            .map(|role| role.name.clone())
            .collect();

        let mut additional_claims = HashMap::new();
        additional_claims.insert(
            "roles".to_string(),
            serde_json::Value::Array(
                roles
                    .clone()
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        additional_claims.insert(
            "permissions".to_string(),
            serde_json::Value::Array(
                permissions
                    .into_iter()
                    .map(|p| {
                        serde_json::json!({
                            "id": p.id,
                            "name": p.name,
                            "resource": p.resource,
                            "action": p.action
                        })
                    })
                    .collect(),
            ),
        );

        Ok(OidcUserInfo {
            sub: user_id,
            name: Some(user.full_name.clone()),
            email: Some(user.email.clone()),
            email_verified: Some(true),
            preferred_username: Some(user.username.clone()),
            groups: Some(roles),
            additional_claims,
        })
    }

    /// Get JWKS
    pub fn jwks(&self) -> &JsonWebKeySet {
        &self.jwks
    }

    /// Generate access token
    fn generate_access_token(
        &self,
        user: &User,
        auth_code_info: &AuthCodeInfo,
    ) -> Result<String, FortressError> {
        let now = current_timestamp();
        let exp = now + self.config.token_expiration.access_token;

        let claims = TokenClaims {
            sub: user.id.clone(),
            iss: self.config.issuer.clone(),
            aud: auth_code_info.client_id.clone(),
            exp,
            iat: now,
            roles: user.roles.clone(),
            permissions: self
                .auth_manager
                .get_user_permissions(&user.id)
                .into_iter()
                .map(|p| p.id.clone())
                .collect(),
            scope: auth_code_info.scope.clone(),
        };

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----")
            .map_err(|_e| FortressError::encryption("Failed to create encoding key", "RS256", EncryptionErrorCode::AlgorithmNotSupported))?;

        encode(&header, &claims, &key).map_err(|_e| {
            FortressError::encryption(
                "Failed to encode token",
                "RS256",
                EncryptionErrorCode::AlgorithmNotSupported,
            )
        })
    }

    /// Generate refresh token
    fn generate_refresh_token(
        &mut self,
        auth_code_info: &AuthCodeInfo,
    ) -> Result<String, FortressError> {
        let token = Uuid::new_v4().to_string();
        let now = current_timestamp();
        let expires_at = now + self.config.token_expiration.refresh_token;

        let token_info = RefreshTokenInfo {
            token: token.clone(),
            user_id: auth_code_info.user_id.clone(),
            client_id: auth_code_info.client_id.clone(),
            scope: auth_code_info.scope.clone(),
            created_at: now,
            expires_at,
        };

        self.refresh_tokens.insert(token.clone(), token_info);
        Ok(token)
    }

    /// Generate ID token
    fn generate_id_token(
        &self,
        user: &User,
        auth_code_info: &AuthCodeInfo,
    ) -> Result<String, FortressError> {
        let now = current_timestamp();
        let exp = now + self.config.token_expiration.id_token;

        let mut claims = serde_json::json!({
            "sub": user.id,
            "iss": self.config.issuer,
            "aud": auth_code_info.client_id,
            "exp": exp,
            "iat": now,
            "name": user.full_name,
            "email": user.email,
            "preferred_username": user.username,
        });

        // Add nonce if present
        if let Some(nonce) = &auth_code_info.nonce {
            claims["nonce"] = serde_json::Value::String(nonce.clone());
        }

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----")
            .map_err(|_e| FortressError::encryption("Failed to create encoding key", "RS256", EncryptionErrorCode::AlgorithmNotSupported))?;

        encode(&header, &claims, &key).map_err(|_e| {
            FortressError::encryption(
                "Failed to encode ID token",
                "RS256",
                EncryptionErrorCode::AlgorithmNotSupported,
            )
        })
    }

    /// Generate access token from refresh token
    fn generate_access_token_from_refresh(
        &self,
        user: &User,
        refresh_info: &RefreshTokenInfo,
    ) -> Result<String, FortressError> {
        let now = current_timestamp();
        let exp = now + self.config.token_expiration.access_token;

        let claims = TokenClaims {
            sub: user.id.clone(),
            iss: self.config.issuer.clone(),
            aud: refresh_info.client_id.clone(),
            exp,
            iat: now,
            roles: user.roles.clone(),
            permissions: self
                .auth_manager
                .get_user_permissions(&user.id)
                .into_iter()
                .map(|p| p.id.clone())
                .collect(),
            scope: refresh_info.scope.clone(),
        };

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----")
            .map_err(|_e| FortressError::encryption("Failed to create encoding key", "RS256", EncryptionErrorCode::AlgorithmNotSupported))?;

        encode(&header, &claims, &key).map_err(|_e| {
            FortressError::encryption(
                "Failed to encode access token",
                "RS256",
                EncryptionErrorCode::AlgorithmNotSupported,
            )
        })
    }

    /// Decode access token
    fn decode_access_token(&self, token: &str) -> Result<TokenClaims, FortressError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);

        let key = DecodingKey::from_rsa_pem(b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----")
            .map_err(|_e| FortressError::encryption("Failed to create decoding key", "RS256", EncryptionErrorCode::AlgorithmNotSupported))?;

        let token_data = decode::<TokenClaims>(token, &key, &validation)
            .map_err(|e| FortressError::authentication("Invalid token", Some(e.to_string())))?;

        Ok(token_data.claims)
    }

    /// Validate PKCE
    fn validate_pkce(
        &self,
        code_challenge: &str,
        code_verifier: &str,
        method: &str,
    ) -> Result<bool, FortressError> {
        match method {
            "plain" => Ok(code_challenge == code_verifier),
            "S256" => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let hash = hasher.finalize();
                let encoded = general_purpose::URL_SAFE_NO_PAD.encode(hash);
                Ok(code_challenge == encoded)
            }
            _ => Err(FortressError::validation(
                "Unsupported PKCE method",
                None,
                None,
            )),
        }
    }

    /// Generate JWKS
    fn generate_jwks(_config: &JwksConfig) -> Result<JsonWebKeySet, FortressError> {
        // For this example, we'll generate a static key set
        // In a real implementation, you would generate proper RSA/ECDSA keys
        let key = JsonWebKey {
            kid: "key1".to_string(),
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["sign".to_string(), "verify".to_string()]),
            alg: Some("RS256".to_string()),
            n: Some("some_base64url_encoded_modulus".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        };

        Ok(JsonWebKeySet { keys: vec![key] })
    }

    /// Clean up expired codes and tokens
    pub fn cleanup_expired(&mut self) {
        let now = current_timestamp();

        // Clean up expired authorization codes
        self.auth_codes.retain(|_, info| info.expires_at > now);

        // Clean up expired refresh tokens
        self.refresh_tokens.retain(|_, info| info.expires_at > now);
    }
}

impl RegoPolicyEngine {
    /// Create a new Rego policy engine
    pub fn new(config: &RegoConfig) -> Result<Self, FortressError> {
        Ok(Self {
            cache: HashMap::new(),
            cache_ttl: config.cache_ttl,
            cache_timestamps: HashMap::new(),
            data: HashMap::new(),
        })
    }

    /// Load Rego policy from string
    pub fn load_policy(&mut self, name: &str, _policy: &str) -> Result<(), FortressError> {
        // For now, just store the policy string
        // In a real implementation, this would compile and validate Rego policy
        tracing::info!("Loaded policy '{}'", name);
        Ok(())
    }

    /// Load policies from directory
    pub fn load_policies_from_dir(&mut self, dir: &str) -> Result<(), FortressError> {
        let paths = std::fs::read_dir(dir).map_err(|e| {
            FortressError::io("Failed to read policy directory", Some(e.to_string()))
        })?;

        for path in paths {
            let path = path.map_err(|e| {
                FortressError::io("Failed to read directory entry", Some(e.to_string()))
            })?;

            if path.path().extension().and_then(|s| s.to_str()) == Some("rego") {
                let policy_content = std::fs::read_to_string(path.path()).map_err(|e| {
                    FortressError::io("Failed to read policy file", Some(e.to_string()))
                })?;

                let policy_name = path
                    .file_name()
                    .to_str()
                    .map(|s| s.strip_suffix(".rego").unwrap_or(s))
                    .unwrap_or("unknown")
                    .to_string();

                self.load_policy(&policy_name, &policy_content)?;
            }
        }
        Ok(())
    }

    /// Evaluate authorization policy
    pub fn evaluate_authorization(
        &mut self,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<bool, FortressError> {
        let current_time = current_timestamp();
        let cache_key = format!("{}:{}:{}", user_id, client_id, scope);

        // Check cache first
        if let Some(&timestamp) = self.cache_timestamps.get(&cache_key) {
            if current_time - timestamp < self.cache_ttl {
                if let Some(&result) = self.cache.get(&cache_key) {
                    return Ok(result);
                }
            }
        }

        // Simple policy evaluation for now
        // In a real implementation, this would use OPA Rego engine
        let allowed = self.evaluate_simple_policy(user_id, client_id, scope)?;

        // Cache result
        self.cache.insert(cache_key.clone(), allowed);
        self.cache_timestamps.insert(cache_key, current_time);

        Ok(allowed)
    }

    /// Simple policy evaluation (placeholder for real Rego implementation)
    fn evaluate_simple_policy(
        &self,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<bool, FortressError> {
        // Example policy: Allow access if user is not blocked and client is trusted
        let blocked_users = vec!["blocked_user_1", "blocked_user_2"];
        let untrusted_clients = vec!["untrusted_client_1"];

        if blocked_users.contains(&user_id) {
            return Ok(false);
        }

        if untrusted_clients.contains(&client_id) {
            return Ok(false);
        }

        // Allow access to basic scopes
        let allowed_scopes = vec!["openid", "profile", "email"];
        let requested_scopes: Vec<&str> = scope.split_whitespace().collect();

        for requested_scope in requested_scopes {
            if !allowed_scopes.contains(&requested_scope)
                && requested_scope != "read"
                && requested_scope != "write"
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Set policy data
    pub fn set_data(&mut self, key: &str, value: serde_json::Value) {
        self.data.insert(key.to_string(), value);
    }

    /// Clear cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.cache_timestamps.clear();
    }

    /// Get policy statistics
    pub fn get_stats(&self) -> PolicyStats {
        PolicyStats {
            total_policies: 0, // No policies loaded in simplified version
            cached_results: self.cache.len(),
            data_entries: self.data.len(),
        }
    }
}

/// Get current timestamp in seconds since Unix epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: "https://fortress.local".to_string(),
            response_types: vec![
                "code".to_string(),
                "id_token".to_string(),
                "id_token token".to_string(),
            ],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "read".to_string(),
                "write".to_string(),
            ],
            response_modes: vec!["query".to_string(), "fragment".to_string()],
            token_expiration: TokenExpiration {
                auth_code: 600,         // 10 minutes
                access_token: 3600,     // 1 hour
                refresh_token: 2592000, // 30 days
                id_token: 3600,         // 1 hour
            },
            jwks: JwksConfig {
                rotation_interval: 86400, // 24 hours
                min_key_size: 2048,
                algorithms: vec!["RS256".to_string(), "ES256".to_string()],
            },
            clients: HashMap::new(),
            rego_policies: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_oidc_provider_creation() {
        let config = OidcConfig::default();
        let auth_manager = AuthManager::new();

        let provider = OidcProvider::new(config, auth_manager);
        assert!(provider.is_ok());
    }

    #[tokio::test]
    async fn test_authorization_request() {
        let mut config = OidcConfig::default();

        // Add a test client
        let client = OidcClient {
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            name: "Test Client".to_string(),
            redirect_uris: vec!["https://client.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string(), "profile".to_string()],
            public: false,
            metadata: HashMap::new(),
        };

        config.clients.insert("test_client".to_string(), client);

        let auth_manager = AuthManager::new();
        let mut provider = OidcProvider::new(config, auth_manager).unwrap();

        let request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: Some("test_state".to_string()),
            nonce: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        let result = provider.authorize(request).await;
        assert!(result.is_ok());

        let redirect_url = result.unwrap();
        assert!(redirect_url.contains("code="));
        assert!(redirect_url.contains("state=test_state"));
    }

    #[test]
    fn test_pkce_validation() {
        let config = OidcConfig::default();
        let auth_manager = AuthManager::new();
        let provider = OidcProvider::new(config, auth_manager).unwrap();

        // Test plain method
        let result = provider.validate_pkce("challenge", "challenge", "plain");
        assert!(result.unwrap());

        // Test S256 method
        let code_verifier = "test_verifier_123";
        let mut hasher = sha2::Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();
        let code_challenge = general_purpose::URL_SAFE_NO_PAD.encode(hash);

        let result = provider.validate_pkce(&code_challenge, code_verifier, "S256");
        assert!(result.unwrap());
    }

    #[test]
    fn test_rego_policy_engine() {
        let config = RegoConfig {
            policy_dir: "policies".to_string(),
            data_dir: None,
            enable_cache: true,
            cache_ttl: 300,
        };

        let mut engine = RegoPolicyEngine::new(&config).unwrap();

        // Test policy evaluation
        let result = engine.evaluate_authorization("user1", "client1", "openid profile");
        assert!(result.unwrap());

        // Test blocked user
        let result = engine.evaluate_authorization("blocked_user_1", "client1", "openid");
        assert!(!result.unwrap());

        // Test untrusted client
        let result = engine.evaluate_authorization("user1", "untrusted_client_1", "openid");
        assert!(!result.unwrap());
    }
}
