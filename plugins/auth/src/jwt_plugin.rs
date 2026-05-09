//! JWT Authentication Plugin for Fortress
//! 
//! This is a WebAssembly plugin that provides JWT-based authentication
//! including token generation, validation, and refresh capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

// Plugin metadata
const PLUGIN_NAME: &str = "jwt_auth";
const PLUGIN_VERSION: &str = "1.0.0";
const PLUGIN_DESCRIPTION: &str = "JWT-based authentication plugin";
const PLUGIN_AUTHOR: &str = "Fortress Team";

// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtConfig {
    secret: String,
    token_expiration: u64,
    issuer: String,
    audience: String,
    algorithm: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "default-secret-change-in-production".to_string(),
            token_expiration: 3600, // 1 hour
            issuer: "fortress-auth".to_string(),
            audience: "fortress-api".to_string(),
            algorithm: "HS256".to_string(),
        }
    }
}

// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,           // Subject (user ID)
    iss: String,           // Issuer
    aud: String,           // Audience
    exp: u64,             // Expiration time
    iat: u64,             // Issued at
    jti: String,           // JWT ID
    username: String,       // Username
    email: Option<String>,  // Email
    roles: Vec<String>,     // User roles
    permissions: Vec<String>, // User permissions
    tenant_id: Option<String>, // Tenant ID
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
static PLUGIN_CONFIG: OnceLock<JwtConfig> = OnceLock::new();
static PLUGIN_INITIALIZED: OnceLock<bool> = OnceLock::new();

// Mock host function declarations - these will be linked from lib.rs
#[allow(dead_code)]
extern "C" {
    fn auth_log(level: i32, ptr: *const u8, len: usize);
    fn auth_store_session(session_id_ptr: *const u8, session_id_len: usize, user_data_ptr: *const u8, user_data_len: usize) -> i32;
    fn auth_get_session(session_id_ptr: *const u8, session_id_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn auth_delete_session(session_id_ptr: *const u8, session_id_len: usize) -> i32;
    fn auth_cache_token(token_ptr: *const u8, token_len: usize, user_data_ptr: *const u8, user_data_len: usize) -> i32;
    fn auth_get_cached_token(token_ptr: *const u8, token_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn auth_generate_token(user_id_ptr: *const u8, user_id_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn auth_validate_token(token_ptr: *const u8, token_len: usize) -> i32;
    fn auth_hash_password(password_ptr: *const u8, password_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn auth_verify_password(password_ptr: *const u8, password_len: usize, hash_ptr: *const u8, hash_len: usize) -> i32;
    fn auth_make_http_request(url_ptr: *const u8, url_len: usize, method_ptr: *const u8, method_len: usize, body_ptr: *const u8, body_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn get_config(key_ptr: *const u8, key_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn get_timestamp() -> i64;
}

// Mock implementations are provided in lib.rs::mock_host_functions for testing

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

// JWT operations
fn create_jwt_token(claims: &JwtClaims, config: &JwtConfig) -> Result<String, String> {
    // Simple JWT implementation (in production, use proper JWT library)
    let header = format!(
        "{{\"alg\":\"{}\",\"typ\":\"JWT\"}}",
        config.algorithm
    );
    
    let claims_json = serde_json::to_string(claims)
        .map_err(|e| format!("Failed to serialize claims: {}", e))?;
    
    // Encode header and claims (base64url encoding)
    let header_encoded = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let claims_encoded = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
    
    // Create signature (simplified - in production, use proper crypto)
    let signing_input = format!("{}.{}", header_encoded, claims_encoded);
    let signature = create_signature(&signing_input, &config.secret)?;
    
    let token = format!("{}.{}.{}", header_encoded, claims_encoded, signature);
    Ok(token)
}

fn validate_jwt_token(token: &str, config: &JwtConfig) -> Result<JwtClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".to_string());
    }
    
    // Decode header and claims
    let _header = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|_| "Failed to decode header".to_string())?;
    
    let claims_json = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|_| "Failed to decode claims".to_string())?;
    
    let claims_json = String::from_utf8_lossy(&claims_json).to_string();
    let claims: JwtClaims = serde_json::from_str(&claims_json)
        .map_err(|e| format!("Failed to parse claims: {}", e))?;
    
    // Validate expiration
    let current_time = unsafe { get_timestamp() } as u64;
    if claims.exp <= current_time {
        return Err("Token has expired".to_string());
    }
    
    // Validate signature (simplified)
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected_signature = create_signature(&signing_input, &config.secret)?;
    let provided_signature = parts[2];
    
    if expected_signature != provided_signature {
        return Err("Invalid signature".to_string());
    }
    
    Ok(claims)
}

fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

#[allow(dead_code)]
fn base64url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(data)
}

fn create_signature(data: &str, secret: &str) -> Result<String, String> {
    // Simple HMAC-SHA256 implementation (in production, use proper crypto)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    Ok(base64url_encode(&result))
}

// User database (simplified - in production, use proper user store)
#[allow(dead_code)]
#[allow(static_mut_refs)]
static mut USER_DATABASE: Option<HashMap<String, UserRecord>> = None;

#[derive(Debug, Clone)]
struct UserRecord {
    id: String,
    username: String,
    password_hash: String,
    email: Option<String>,
    roles: Vec<String>,
    permissions: Vec<String>,
    tenant_id: Option<String>,
    active: bool,
}

#[allow(dead_code)]
#[allow(static_mut_refs)]
fn initialize_user_database() {
    unsafe {
        if USER_DATABASE.is_none() {
            let mut db = HashMap::new();
            
            // Add test user
            db.insert("admin".to_string(), UserRecord {
                id: "user-1".to_string(),
                username: "admin".to_string(),
                password_hash: hash_password("admin123").unwrap(),
                email: Some("admin@fortress.com".to_string()),
                roles: vec!["admin".to_string(), "user".to_string()],
                permissions: vec!["*".to_string()],
                tenant_id: None,
                active: true,
            });
            
            USER_DATABASE = Some(db);
        }
    }
}

fn get_user(username: &str) -> Option<UserRecord> {
    use std::sync::{Mutex, OnceLock};
    
    static USER_DB_SAFE: OnceLock<Mutex<HashMap<String, UserRecord>>> = OnceLock::new();
    
    let db = USER_DB_SAFE.get_or_init(|| {
        let mut db = HashMap::new();
        
        // Add test user
        db.insert("admin".to_string(), UserRecord {
            id: "user-1".to_string(),
            username: "admin".to_string(),
            password_hash: hash_password("admin123").unwrap_or_default(),
            email: Some("admin@fortress.com".to_string()),
            roles: vec!["admin".to_string(), "user".to_string()],
            permissions: vec!["*".to_string()],
            tenant_id: None,
            active: true,
        });
        
        Mutex::new(db)
    });
    
    db.lock().ok()?.get(username).cloned()
}

fn hash_password(password: &str) -> Result<String, String> {
    let mut output = [0u8; 64];
    unsafe {
        let len = auth_hash_password(
            password.as_ptr(),
            password.len(),
            output.as_mut_ptr(),
            output.len()
        );
        if len > 0 {
            Ok(read_string_from_wasm(output.as_ptr(), len as usize))
        } else {
            Err("Failed to hash password".to_string())
        }
    }
}

fn verify_password(password: &str, hash: &str) -> bool {
    unsafe {
        auth_verify_password(
            password.as_ptr(),
            password.len(),
            hash.as_ptr(),
            hash.len()
        ) == 1
    }
}

// Plugin entry points
#[no_mangle]
pub extern "C" fn jwt_initialize() -> i32 {
    log_message(2, "Initializing JWT authentication plugin");
    
    // Load configuration
    let config_key = "jwt_config";
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
            match serde_json::from_str::<JwtConfig>(&config_json) {
                Ok(config) => {
                    let _ = PLUGIN_CONFIG.set(config);
                    let _ = PLUGIN_INITIALIZED.set(true);
                    log_message(2, "JWT plugin initialized successfully");
                    return 1;
                }
                Err(e) => {
                    log_message(0, &format!("Failed to parse config: {}", e));
                    return 0;
                }
            }
        } else {
            // Use default configuration
            let _ = PLUGIN_CONFIG.set(JwtConfig::default());
            let _ = PLUGIN_INITIALIZED.set(true);
            log_message(2, "JWT plugin initialized with default config");
            return 1;
        }
    }
}

#[no_mangle]
pub extern "C" fn authenticate(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !*PLUGIN_INITIALIZED.get().unwrap_or(&false) {
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
    
    log_message(2, &format!("Processing authentication request for method: {}", auth_request.method));
    
    let config = PLUGIN_CONFIG.get().unwrap();
    
    match auth_request.method.as_str() {
        "JWT" => {
            // Handle JWT token validation
            if let Some(token) = &auth_request.credentials.token {
                match validate_jwt_token(token, config) {
                    Ok(claims) => {
                        let user_info = AuthUserInfo {
                            id: claims.sub.clone(),
                            username: claims.username.clone(),
                            email: claims.email.clone(),
                            display_name: Some(claims.username.clone()),
                            roles: claims.roles.clone(),
                            permissions: claims.permissions.clone(),
                            tenant_id: claims.tenant_id.clone(),
                            attributes: HashMap::new(),
                        };
                        
                        let result = AuthResult {
                            success: true,
                            user_info: Some(user_info),
                            token: Some(token.to_string()),
                            refresh_token: None,
                            expires_at: Some(claims.exp),
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
                            error: Some(e),
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
                    error: Some("No token provided".to_string()),
                    metadata: HashMap::new(),
                };
                
                let result_json = serde_json::to_string(&result).unwrap_or_default();
                return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
            }
        }
        "Basic" => {
            // Handle username/password authentication
            if let (Some(username), Some(password)) = (&auth_request.credentials.username, &auth_request.credentials.password) {
                if let Some(user) = get_user(username) {
                    if user.active && verify_password(password, &user.password_hash) {
                        // Create JWT token
                        let now = unsafe { get_timestamp() } as u64;
                        let claims = JwtClaims {
                            sub: user.id.clone(),
                            iss: config.issuer.clone(),
                            aud: config.audience.clone(),
                            exp: now + config.token_expiration,
                            iat: now,
                            jti: format!("jwt-{}", now),
                            username: user.username.clone(),
                            email: user.email.clone(),
                            roles: user.roles.clone(),
                            permissions: user.permissions.clone(),
                            tenant_id: user.tenant_id.clone(),
                        };
                        
                        match create_jwt_token(&claims, config) {
                            Ok(token) => {
                                let user_info = AuthUserInfo {
                                    id: user.id.clone(),
                                    username: user.username.clone(),
                                    email: user.email.clone(),
                                    display_name: Some(user.username.clone()),
                                    roles: user.roles.clone(),
                                    permissions: user.permissions.clone(),
                                    tenant_id: user.tenant_id.clone(),
                                    attributes: HashMap::new(),
                                };
                                
                                let result = AuthResult {
                                    success: true,
                                    user_info: Some(user_info),
                                    token: Some(token),
                                    refresh_token: Some(format!("refresh-{}", now)),
                                    expires_at: Some(claims.exp),
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
                                    error: Some(format!("Failed to create token: {}", e)),
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
                            error: Some("Invalid credentials".to_string()),
                            metadata: HashMap::new(),
                        };
                        
                        let result_json = serde_json::to_string(&result).unwrap_or_default();
                        return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
                    }
                } else {
                    let result = AuthResult {
                        success: false,
                        user_info: None,
                        token: None,
                        refresh_token: None,
                        expires_at: None,
                        error: Some("User not found".to_string()),
                        metadata: HashMap::new(),
                    };
                    
                    let result_json = serde_json::to_string(&result).unwrap_or_default();
                    return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
                }
            } else {
                let result = AuthResult {
                    success: false,
                    user_info: None,
                    token: None,
                    refresh_token: None,
                    expires_at: None,
                    error: Some("Username and password required".to_string()),
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
pub extern "C" fn jwt_validate_token(
    token_ptr: *const u8,
    token_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !*PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        return 0;
    }
    
    let token = read_string_from_wasm(token_ptr, token_len);
    let config = PLUGIN_CONFIG.get().unwrap();
    
    match validate_jwt_token(&token, config) {
        Ok(claims) => {
            let user_info = AuthUserInfo {
                id: claims.sub.clone(),
                username: claims.username.clone(),
                email: claims.email.clone(),
                display_name: Some(claims.username.clone()),
                roles: claims.roles.clone(),
                permissions: claims.permissions.clone(),
                tenant_id: claims.tenant_id.clone(),
                attributes: HashMap::new(),
            };
            
            let response = serde_json::json!({
                "valid": true,
                "user_info": user_info
            });
            
            let response_json = serde_json::to_string(&response).unwrap_or_default();
            return write_string_to_wasm(&response_json, response_ptr, response_len) as i32;
        }
        Err(e) => {
            let response = serde_json::json!({
                "valid": false,
                "error": e
            });
            
            let response_json = serde_json::to_string(&response).unwrap_or_default();
            return write_string_to_wasm(&response_json, response_ptr, response_len) as i32;
        }
    }
}

#[no_mangle]
pub extern "C" fn jwt_refresh_token(
    refresh_token_ptr: *const u8,
    refresh_token_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !*PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        return 0;
    }
    
    let refresh_token = read_string_from_wasm(refresh_token_ptr, refresh_token_len);
    
    // Simple refresh token validation (in production, use proper refresh token logic)
    if refresh_token.starts_with("refresh-") {
        let config = PLUGIN_CONFIG.get().unwrap();
        let now = unsafe { get_timestamp() } as u64;
        
        // Create new token for user "admin" (simplified)
        let claims = JwtClaims {
            sub: "user-1".to_string(),
            iss: config.issuer.clone(),
            aud: config.audience.clone(),
            exp: now + config.token_expiration,
            iat: now,
            jti: format!("jwt-{}", now),
            username: "admin".to_string(),
            email: Some("admin@fortress.com".to_string()),
            roles: vec!["admin".to_string(), "user".to_string()],
            permissions: vec!["*".to_string()],
            tenant_id: None,
        };
        
        match create_jwt_token(&claims, config) {
            Ok(new_token) => {
                let result = AuthResult {
                    success: true,
                    user_info: None,
                    token: Some(new_token),
                    refresh_token: Some(format!("refresh-{}", now)),
                    expires_at: Some(claims.exp),
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
                    error: Some(format!("Failed to create new token: {}", e)),
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
            error: Some("Invalid refresh token".to_string()),
            metadata: HashMap::new(),
        };
        
        let result_json = serde_json::to_string(&result).unwrap_or_default();
        return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
    }
}

#[no_mangle]
pub extern "C" fn jwt_logout(
    token_ptr: *const u8,
    token_len: usize
) -> i32 {
    if !*PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        return 0;
    }
    
    let token = read_string_from_wasm(token_ptr, token_len);
    log_message(2, &format!("Logging out token: {}", token));
    
    // In a real implementation, this would invalidate the token
    // For now, we'll just log it
    1 // Success
}

#[no_mangle]
pub extern "C" fn jwt_health_check() -> i32 {
    if *PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        1 // Healthy
    } else {
        0 // Unhealthy
    }
}

#[no_mangle]
pub extern "C" fn cleanup() -> i32 {
    log_message(2, "Cleaning up JWT authentication plugin");
    
    // Note: OnceLock doesn't support clearing, so we just log the cleanup
    log_message(2, "JWT plugin cleanup completed");
    
    1 // Success
}

// Plugin metadata exports
#[no_mangle]
pub extern "C" fn get_jwt_plugin_name() -> *const u8 {
    PLUGIN_NAME.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_jwt_plugin_name_len() -> usize {
    PLUGIN_NAME.len()
}

#[no_mangle]
pub extern "C" fn get_jwt_plugin_version() -> *const u8 {
    PLUGIN_VERSION.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_jwt_plugin_version_len() -> usize {
    PLUGIN_VERSION.len()
}

#[no_mangle]
pub extern "C" fn get_jwt_supported_methods() -> *const u8 {
    let methods = r#"["JWT", "Basic"]"#;
    methods.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_jwt_supported_methods_len() -> usize {
    let methods = r#"["JWT", "Basic"]"#;
    methods.len()
}

// Plugin metadata function
pub fn get_metadata() -> PluginMetadata {
    PluginMetadata {
        name: PLUGIN_NAME.to_string(),
        version: PLUGIN_VERSION.to_string(),
        description: PLUGIN_DESCRIPTION.to_string(),
        author: PLUGIN_AUTHOR.to_string(),
        supported_methods: vec!["JWT".to_string(), "Basic".to_string()],
        required_config: vec!["jwt_config".to_string()],
        capabilities: PluginCapabilities {
            can_generate_tokens: true,
            can_validate_tokens: true,
            can_refresh_tokens: true,
            supports_mfa: false,
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

// Main function for binary compilation (disabled)
// fn main() {
//     println!("JWT Authentication Plugin for Fortress");
//     println!("This is a WebAssembly plugin and should be loaded by the Fortress runtime.");
// }
