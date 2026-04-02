//! OAuth Authentication Plugin for Fortress
//! 
//! This is a WebAssembly plugin that provides OAuth 2.0 / OpenID Connect
//! authentication including authorization code flow, token exchange, and user info retrieval.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

// Plugin metadata
const PLUGIN_NAME: &str = "oauth_auth";
const PLUGIN_VERSION: &str = "1.0.0";
const PLUGIN_DESCRIPTION: &str = "OAuth 2.0 / OpenID Connect authentication plugin";
const PLUGIN_AUTHOR: &str = "Fortress Team";

// OAuth configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthConfig {
    client_id: String,
    client_secret: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    redirect_uri: String,
    scopes: Vec<String>,
    enable_pkce: bool,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            client_id: "default-client-id".to_string(),
            client_secret: "default-client-secret".to_string(),
            authorization_endpoint: "https://oauth.example.com/auth".to_string(),
            token_endpoint: "https://oauth.example.com/token".to_string(),
            userinfo_endpoint: "https://oauth.example.com/userinfo".to_string(),
            redirect_uri: "http://localhost:8080/callback".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            enable_pkce: true,
        }
    }
}

// OAuth token response
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

// OAuth user info response
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthUserInfo {
    sub: String,
    name: Option<String>,
    email: Option<String>,
    preferred_username: Option<String>,
    picture: Option<String>,
    groups: Option<Vec<String>>,
    roles: Option<Vec<String>>,
}

// Authentication request from host
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthRequest {
    method: String,
    credentials: AuthCredentials,
    context: AuthContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthCredentials {
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    authorization_code: Option<String>,
    state: Option<String>,
    redirect_uri: Option<String>,
    saml_assertion: Option<String>,
    api_key: Option<String>,
    additional_data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthContext {
    ip_address: Option<String>,
    user_agent: Option<String>,
    timestamp: u64,
    device_fingerprint: Option<String>,
    request_id: String,
}

// Authentication response to host
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthResult {
    success: bool,
    user_info: Option<AuthUserInfo>,
    token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
    error: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthUserInfo {
    id: String,
    username: String,
    email: Option<String>,
    display_name: Option<String>,
    roles: Vec<String>,
    permissions: Vec<String>,
    tenant_id: Option<String>,
    attributes: HashMap<String, serde_json::Value>,
}

// Global plugin state
static mut PLUGIN_CONFIG: Option<OAuthConfig> = None;
static mut PLUGIN_INITIALIZED: bool = false;
static mut TOKEN_CACHE: Option<Mutex<HashMap<String, CachedToken>>> = None;

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
    user_info: Option<OAuthUserInfo>,
}

// WASM host function declarations
extern "C" {
    fn auth_log(level: i32, ptr: *const u8, len: usize);
    fn auth_store_session(session_id_ptr: *const u8, session_id_len: usize, user_data_ptr: *const u8, user_data_len: usize) -> i32;
    fn auth_get_session(session_id_ptr: *const u8, session_id_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn auth_delete_session(session_id_ptr: *const u8, session_id_len: usize) -> i32;
    fn auth_cache_token(token_ptr: *const u8, token_len: usize, user_data_ptr: *const u8, user_data_len: usize) -> i32;
    fn auth_get_cached_token(token_ptr: *const u8, token_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn auth_make_http_request(url_ptr: *const u8, url_len: usize, method_ptr: *const u8, method_len: usize, body_ptr: *const u8, body_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn get_config(key_ptr: *const u8, key_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn get_timestamp() -> i64;
}

// Helper functions for WASM memory operations
fn write_string_to_wasm(s: &str, ptr: *mut u8, len: usize) -> usize {
    let bytes = s.as_bytes();
    let write_len = std::cmp::min(bytes.len(), len);
    
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, write_len);
    }
    
    write_len
}

fn read_string_from_wasm(ptr: *const u8, len: usize) -> String {
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf8_lossy(slice).to_string()
    }
}

// Logging helper
fn log_message(level: i32, message: &str) {
    unsafe {
        auth_log(level, message.as_ptr(), message.len());
    }
}

// HTTP request helper
fn make_http_request(url: &str, method: &str, body: Option<&str>) -> Result<String, String> {
    let mut response_buffer = [0u8; 4096];
    let body_ptr = body.map(|b| b.as_ptr()).unwrap_or(std::ptr::null());
    let body_len = body.map(|b| b.len()).unwrap_or(0);
    
    unsafe {
        let len = auth_make_http_request(
            url.as_ptr(),
            url.len(),
            method.as_ptr(),
            method.len(),
            body_ptr,
            body_len,
            response_buffer.as_mut_ptr(),
            response_buffer.len()
        );
        
        if len > 0 {
            Ok(read_string_from_wasm(response_buffer.as_ptr(), len as usize))
        } else {
            Err("HTTP request failed".to_string())
        }
    }
}

// PKCE (Proof Key for Code Exchange) helpers
fn generate_code_verifier() -> String {
    use sha2::{Sha256, Digest};
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_code_challenge(code_verifier: &str) -> String {
    use sha2::{Sha256, Digest};
    
    let hash = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

// Token management
fn cache_token(access_token: &str, refresh_token: Option<String>, user_info: Option<OAuthUserInfo>, expires_in: Option<u64>) {
    unsafe {
        if TOKEN_CACHE.is_none() {
            TOKEN_CACHE = Some(Mutex::new(HashMap::new()));
        }
        
        let now = get_timestamp() as u64;
        let expires_at = now + expires_in.unwrap_or(3600);
        
        let cached = CachedToken {
            access_token: access_token.to_string(),
            refresh_token,
            expires_at,
            user_info,
        };
        
        if let Some(ref cache) = TOKEN_CACHE {
            if let Ok(mut cache) = cache.lock() {
                cache.insert(access_token.to_string(), cached);
            }
        }
    }
}

fn get_cached_token(access_token: &str) -> Option<CachedToken> {
    unsafe {
        if let Some(ref cache) = TOKEN_CACHE {
            if let Ok(cache) = cache.lock() {
                cache.get(access_token).cloned()
            } else {
                None
            }
        } else {
            None
        }
    }
}

fn validate_cached_token(access_token: &str) -> Option<OAuthUserInfo> {
    if let Some(cached) = get_cached_token(access_token) {
        let now = unsafe { get_timestamp() } as u64;
        if cached.expires_at > now {
            return cached.user_info;
        }
    }
    None
}

// OAuth flow implementations
fn exchange_authorization_code_for_token(
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    config: &OAuthConfig,
) -> Result<OAuthTokenResponse, String> {
    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}",
        code,
        redirect_uri,
        config.client_id
    );
    
    if let Some(verifier) = code_verifier {
        body.push_str(&format!("&code_verifier={}", verifier));
    } else {
        body.push_str(&format!("&client_secret={}", config.client_secret));
    }
    
    match make_http_request(&config.token_endpoint, "POST", Some(&body)) {
        Ok(response) => {
            serde_json::from_str(&response)
                .map_err(|e| format!("Failed to parse token response: {}", e))
        }
        Err(e) => Err(format!("Token exchange failed: {}", e)),
    }
}

fn get_user_info_from_token(access_token: &str, config: &OAuthConfig) -> Result<OAuthUserInfo, String> {
    let url = format!("{}?access_token={}", config.userinfo_endpoint, access_token);
    
    match make_http_request(&url, "GET", None) {
        Ok(response) => {
            serde_json::from_str(&response)
                .map_err(|e| format!("Failed to parse user info: {}", e))
        }
        Err(e) => Err(format!("User info request failed: {}", e)),
    }
}

fn validate_id_token(id_token: &str) -> Result<OAuthUserInfo, String> {
    // Simplified ID token validation (in production, use proper JWT validation)
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid ID token format".to_string());
    }
    
    let payload = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|_| "Failed to decode ID token payload".to_string())?;
    
    let payload_str = String::from_utf8(payload)
        .map_err(|_| "Invalid UTF-8 in ID token".to_string())?;
    
    serde_json::from_str(&payload_str)
        .map_err(|e| format!("Failed to parse ID token claims: {}", e))
}

// Plugin entry points
#[no_mangle]
pub extern "C" fn initialize() -> i32 {
    log_message(2, "Initializing OAuth authentication plugin");
    
    // Load configuration
    let config_key = "oauth_config";
    let mut config_buffer = [0u8; 1024];
    unsafe {
        let len = get_config(
            config_key.as_ptr(),
            config_key.len(),
            config_buffer.as_mut_ptr(),
            config_buffer.len()
        );
        
        if len > 0 {
            let config_json = read_string_from_wasm(config_buffer.as_ptr(), len as usize);
            match serde_json::from_str::<OAuthConfig>(&config_json) {
                Ok(config) => {
                    unsafe { PLUGIN_CONFIG = Some(config); }
                    unsafe { PLUGIN_INITIALIZED = true; }
                    log_message(2, "OAuth plugin initialized successfully");
                    return 1;
                }
                Err(e) => {
                    log_message(0, &format!("Failed to parse config: {}", e));
                    return 0;
                }
            }
        } else {
            // Use default configuration
            unsafe { PLUGIN_CONFIG = Some(OAuthConfig::default()); }
            unsafe { PLUGIN_INITIALIZED = true; }
            log_message(2, "OAuth plugin initialized with default config");
            return 1;
        }
    }
}

#[no_mangle]
pub extern "C" fn oauth_authenticate(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !unsafe { PLUGIN_INITIALIZED } {
        return 0;
    }
    
    let request_json = read_string_from_wasm(request_ptr, request_len);
    let auth_request: AuthRequest = match serde_json::from_str(&request_json) {
        Ok(req) => req,
        Err(e) => {
            log_message(0, &format!("Failed to parse auth request: {}", e));
            return 0;
        }
    };
    
    log_message(2, &format!("Processing OAuth authentication request"));
    
    let config = unsafe { PLUGIN_CONFIG.as_ref().unwrap() };
    
    match auth_request.method.as_str() {
        "OAuth" => {
            // Handle OAuth authorization code flow
            if let (Some(code), Some(_state), Some(redirect_uri)) = (
                &auth_request.credentials.authorization_code,
                &auth_request.credentials.state,
                &auth_request.credentials.redirect_uri
            ) {
                // Exchange authorization code for tokens
                let code_verifier = if config.enable_pkce {
                    // In a real implementation, this would be retrieved from session
                    Some(generate_code_verifier())
                } else {
                    None
                };
                
                match exchange_authorization_code_for_token(code, redirect_uri, code_verifier.as_deref(), config) {
                    Ok(token_response) => {
                        // Get user info
                        let user_info = match get_user_info_from_token(&token_response.access_token, config) {
                            Ok(info) => Some(info),
                            Err(e) => {
                                log_message(1, &format!("Failed to get user info: {}", e));
                                None
                            }
                        };
                        
                        // Cache token
                        cache_token(
                            &token_response.access_token,
                            token_response.refresh_token.clone(),
                            user_info.clone(),
                            token_response.expires_in
                        );
                        
                        // Convert to AuthUserInfo
                        let auth_user_info = user_info.map(|info| AuthUserInfo {
                            id: info.sub.clone(),
                            username: info.preferred_username.clone().unwrap_or_else(|| info.sub.clone()),
                            email: info.email.clone(),
                            display_name: info.name.clone(),
                            roles: info.roles.unwrap_or_default(),
                            permissions: vec![], // OAuth doesn't typically provide permissions
                            tenant_id: None,
                            attributes: HashMap::new(),
                        });
                        
                        let expires_at = token_response.expires_in.map(|seconds| {
                            (unsafe { get_timestamp() } as u64) + seconds
                        });
                        
                        let result = AuthResult {
                            success: true,
                            user_info: auth_user_info,
                            token: Some(token_response.access_token),
                            refresh_token: token_response.refresh_token,
                            expires_at,
                            error: None,
                            metadata: {
                                let mut metadata = HashMap::new();
                                metadata.insert("token_type".to_string(), serde_json::Value::String(token_response.token_type));
                                metadata.insert("scope".to_string(), serde_json::Value::String(token_response.scope.unwrap_or_default()));
                                metadata
                            },
                        };
                        
                        let result_json = serde_json::to_string(&result).unwrap_or_default();
                        return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
                    }
                    Err(e) => {
                        let result = AuthResult {
                            success: false,
                            user_info: None,
                            token: None,
                            refresh_token: None,
                            expires_at: None,
                            error: Some(format!("Token exchange failed: {}", e)),
                            metadata: HashMap::new(),
                        };
                        
                        let result_json = serde_json::to_string(&result).unwrap_or_default();
                        return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
                    }
                }
            } else {
                let result = AuthResult {
                    success: false,
                    user_info: None,
                    token: None,
                    refresh_token: None,
                    expires_at: None,
                    error: Some("Authorization code, state, and redirect_uri are required".to_string()),
                    metadata: HashMap::new(),
                };
                
                let result_json = serde_json::to_string(&result).unwrap_or_default();
                return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
            }
        }
        _ => {
            let result = AuthResult {
                success: false,
                user_info: None,
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some(format!("Unsupported authentication method: {}", auth_request.method)),
                metadata: HashMap::new(),
            };
            
            let result_json = serde_json::to_string(&result).unwrap_or_default();
            return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
        }
    }
}

#[no_mangle]
pub extern "C" fn validate_token(
    token_ptr: *const u8,
    token_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !unsafe { PLUGIN_INITIALIZED } {
        return 0;
    }
    
    let token = read_string_from_wasm(token_ptr, token_len);
    
    // Check cache first
    if let Some(user_info) = validate_cached_token(&token) {
        let auth_user_info = AuthUserInfo {
            id: user_info.sub.clone(),
            username: user_info.preferred_username.clone().unwrap_or_else(|| user_info.sub.clone()),
            email: user_info.email.clone(),
            display_name: user_info.name.clone(),
            roles: user_info.roles.unwrap_or_default(),
            permissions: vec![],
            tenant_id: None,
            attributes: HashMap::new(),
        };
        
        let response = serde_json::json!({
            "valid": true,
            "user_info": auth_user_info
        });
        
        let response_json = serde_json::to_string(&response).unwrap_or_default();
        return write_string_to_wasm(&response_json, response_ptr, response_len) as i32;
    }
    
    let response = serde_json::json!({
        "valid": false,
        "error": "Token not found or expired"
    });
    
    let response_json = serde_json::to_string(&response).unwrap_or_default();
    return write_string_to_wasm(&response_json, response_ptr, response_len) as i32;
}

#[no_mangle]
pub extern "C" fn refresh_token(
    refresh_token_ptr: *const u8,
    refresh_token_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !unsafe { PLUGIN_INITIALIZED } {
        return 0;
    }
    
    let refresh_token = read_string_from_wasm(refresh_token_ptr, refresh_token_len);
    let config = unsafe { PLUGIN_CONFIG.as_ref().unwrap() };
    
    // Exchange refresh token for new access token
    let body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        refresh_token, config.client_id, config.client_secret
    );
    
    match make_http_request(&config.token_endpoint, "POST", Some(&body)) {
        Ok(response) => {
            match serde_json::from_str::<OAuthTokenResponse>(&response) {
                Ok(token_response) => {
                    // Get user info for new token
                    let user_info = match get_user_info_from_token(&token_response.access_token, config) {
                        Ok(info) => Some(info),
                        Err(e) => {
                            log_message(1, &format!("Failed to get user info: {}", e));
                            None
                        }
                    };
                    
                    // Cache new token
                    cache_token(
                        &token_response.access_token,
                        token_response.refresh_token.clone(),
                        user_info.clone(),
                        token_response.expires_in
                    );
                    
                    let auth_user_info = user_info.map(|info| AuthUserInfo {
                        id: info.sub.clone(),
                        username: info.preferred_username.clone().unwrap_or_else(|| info.sub.clone()),
                        email: info.email.clone(),
                        display_name: info.name.clone(),
                        roles: info.roles.unwrap_or_default(),
                        permissions: vec![],
                        tenant_id: None,
                        attributes: HashMap::new(),
                    });
                    
                    let expires_at = token_response.expires_in.map(|seconds| {
                        (unsafe { get_timestamp() } as u64) + seconds
                    });
                    
                    let result = AuthResult {
                        success: true,
                        user_info: auth_user_info,
                        token: Some(token_response.access_token),
                        refresh_token: token_response.refresh_token,
                        expires_at,
                        error: None,
                        metadata: HashMap::new(),
                    };
                    
                    let result_json = serde_json::to_string(&result).unwrap_or_default();
                    return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
                }
                Err(e) => {
                    let result = AuthResult {
                        success: false,
                        user_info: None,
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some(format!("Failed to parse refresh response: {}", e)),
                        metadata: HashMap::new(),
                    };
                    
                    let result_json = serde_json::to_string(&result).unwrap_or_default();
                    return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
                }
            }
        }
        Err(e) => {
            let result = AuthResult {
                success: false,
                user_info: None,
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some(format!("Refresh token request failed: {}", e)),
                metadata: HashMap::new(),
            };
            
            let result_json = serde_json::to_string(&result).unwrap_or_default();
            return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
        }
    }
}

#[no_mangle]
pub extern "C" fn logout(
    token_ptr: *const u8,
    token_len: usize
) -> i32 {
    if !unsafe { PLUGIN_INITIALIZED } {
        return 0;
    }
    
    let token = read_string_from_wasm(token_ptr, token_len);
    log_message(2, &format!("Logging out OAuth token: {}", token));
    
    // Remove from cache
    unsafe {
        if let Some(ref mut cache) = TOKEN_CACHE {
            if let Ok(mut cache) = cache.lock() {
                cache.remove(&token);
            }
        }
    }
    
    1 // Success
}

#[no_mangle]
pub extern "C" fn health_check() -> i32 {
    if unsafe { PLUGIN_INITIALIZED } {
        1 // Healthy
    } else {
        0 // Unhealthy
    }
}

#[no_mangle]
pub extern "C" fn oauth_cleanup() -> i32 {
    log_message(2, "Cleaning up OAuth authentication plugin");
    
    unsafe {
        PLUGIN_INITIALIZED = false;
        PLUGIN_CONFIG = None;
        TOKEN_CACHE = None;
    }
    
    1 // Success
}

// Plugin metadata exports
#[no_mangle]
pub extern "C" fn get_plugin_name() -> *const u8 {
    PLUGIN_NAME.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_plugin_name_len() -> usize {
    PLUGIN_NAME.len()
}

#[no_mangle]
pub extern "C" fn get_plugin_version() -> *const u8 {
    PLUGIN_VERSION.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_plugin_version_len() -> usize {
    PLUGIN_VERSION.len()
}

#[no_mangle]
pub extern "C" fn get_supported_methods() -> *const u8 {
    let methods = r#"["OAuth"]"#;
    methods.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_supported_methods_len() -> usize {
    let methods = r#"["OAuth"]"#;
    methods.len()
}

// Plugin metadata function
pub fn get_metadata() -> PluginMetadata {
    PluginMetadata {
        name: PLUGIN_NAME.to_string(),
        version: PLUGIN_VERSION.to_string(),
        description: PLUGIN_DESCRIPTION.to_string(),
        author: PLUGIN_AUTHOR.to_string(),
        supported_methods: vec!["OAuth".to_string()],
        required_config: vec!["oauth_config".to_string()],
        capabilities: PluginCapabilities {
            can_generate_tokens: true,
            can_validate_tokens: true,
            can_refresh_tokens: true,
            supports_mfa: true,
            supports_rbac: true,
        },
    }
}

// Define the types locally for the binary target
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub supported_methods: Vec<String>,
    pub required_config: Vec<String>,
    pub capabilities: PluginCapabilities,
}

#[derive(Debug, Clone)]
pub struct PluginCapabilities {
    pub can_generate_tokens: bool,
    pub can_validate_tokens: bool,
    pub can_refresh_tokens: bool,
    pub supports_mfa: bool,
    pub supports_rbac: bool,
}

// Main function for binary compilation
fn main() {
    println!("OAuth Authentication Plugin for Fortress");
    println!("This is a WebAssembly plugin and should be loaded by the Fortress runtime.");
}
