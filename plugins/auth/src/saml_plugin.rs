//! SAML Authentication Plugin for Fortress
//! 
//! This is a WebAssembly plugin that provides SAML 2.0 authentication
//! including assertion validation, attribute extraction, and user mapping.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// Plugin metadata
const PLUGIN_NAME: &str = "saml_auth";
const PLUGIN_VERSION: &str = "1.0.0";
const PLUGIN_DESCRIPTION: &str = "SAML 2.0 authentication plugin";
const PLUGIN_AUTHOR: &str = "Fortress Team";

// SAML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlConfig {
    entity_id: String,
    sso_url: String,
    slo_url: String,
    certificate: String,
    name_id_format: String,
    attribute_mapping: HashMap<String, String>,
    clock_skew_seconds: u64,
}

impl Default for SamlConfig {
    fn default() -> Self {
        let mut attribute_mapping = HashMap::new();
        attribute_mapping.insert("email".to_string(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_string());
        attribute_mapping.insert("name".to_string(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_string());
        attribute_mapping.insert("username".to_string(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier".to_string());
        
        Self {
            entity_id: "fortress-saml".to_string(),
            sso_url: "https://sso.example.com/saml".to_string(),
            slo_url: "https://sso.example.com/saml/slo".to_string(),
            certificate: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attribute_mapping,
            clock_skew_seconds: 300, // 5 minutes
        }
    }
}

// SAML assertion structure (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlAssertion {
    id: String,
    issue_instant: String,
    subject: SamlSubject,
    conditions: Option<SamlConditions>,
    attribute_statement: Option<SamlAttributeStatement>,
    signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlSubject {
    name_id: SamlNameId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlNameId {
    format: Option<String>,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlConditions {
    not_before: Option<String>,
    not_on_or_after: Option<String>,
    audience_restriction: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlAttributeStatement {
    attributes: Vec<SamlAttribute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlAttribute {
    name: String,
    name_format: Option<String>,
    values: Vec<String>,
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
static PLUGIN_CONFIG: OnceLock<SamlConfig> = OnceLock::new();
static PLUGIN_INITIALIZED: OnceLock<bool> = OnceLock::new();
static SESSION_CACHE: OnceLock<Mutex<HashMap<String, SamlSession>>> = OnceLock::new();

#[derive(Debug, Clone)]
struct SamlSession {
    user_info: AuthUserInfo,
    #[allow(dead_code)]
    created_at: u64,
    #[allow(dead_code)]
    expires_at: u64,
    #[allow(dead_code)]
    assertion: String,
}

// Mock host function declarations - these will be linked from lib.rs
#[allow(dead_code)]
extern "C" {
    fn auth_log(level: i32, ptr: *const u8, len: usize);
    fn auth_store_session(session_id_ptr: *const u8, session_id_len: usize, user_data_ptr: *const u8, user_data_len: usize) -> i32;
    fn auth_get_session(session_id_ptr: *const u8, session_id_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;
    fn auth_delete_session(session_id_ptr: *const u8, session_id_len: usize) -> i32;
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

// HTTP request helper
#[allow(dead_code)]
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

// SAML parsing and validation
fn parse_saml_assertion(assertion: &str) -> Result<SamlAssertion, String> {
    // Simplified SAML assertion parsing (in production, use proper XML parsing)
    // This is a very basic implementation for demonstration
    
    // Extract ID
    let id = extract_attribute_from_assertion(assertion, "ID")
        .unwrap_or_else(|| format!("assertion-{}", unsafe { get_timestamp() }));
    
    // Extract issue instant
    let issue_instant = extract_attribute_from_assertion(assertion, "IssueInstant")
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339().to_string());
    
    // Extract subject name ID
    let name_id_value = extract_name_id_from_assertion(assertion)
        .unwrap_or_else(|| "unknown@example.com".to_string());
    
    let subject = SamlSubject {
        name_id: SamlNameId {
            format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()),
            value: name_id_value,
        },
    };
    
    // Extract conditions
    let conditions = extract_conditions_from_assertion(assertion);
    
    // Extract attributes
    let attribute_statement = extract_attributes_from_assertion(assertion);
    
    Ok(SamlAssertion {
        id,
        issue_instant,
        subject,
        conditions,
        attribute_statement,
        signature: extract_signature_from_assertion(assertion),
    })
}

fn extract_attribute_from_assertion(assertion: &str, attribute_name: &str) -> Option<String> {
    // Very simplified XML attribute extraction
    // In production, use proper XML parsing library
    let pattern = format!(r#"{}="([^"]*)""#, attribute_name);
    
    // Simple regex-like extraction (simplified for WASM compatibility)
    if let Some(start) = assertion.find(&pattern) {
        let after_start = &assertion[start + pattern.len()..];
        if let Some(end) = after_start.find('"') {
            return Some(after_start[..end].to_string());
        }
    }
    None
}

fn extract_name_id_from_assertion(assertion: &str) -> Option<String> {
    // Extract NameID value
    if let Some(start) = assertion.find("<NameID>") {
        let name_id_start = start + 8; // Length of "<NameID>"
        if let Some(end) = assertion[start..].find("</NameID>") {
            return Some(assertion[name_id_start..name_id_start + end].to_string());
        }
    }
    None
}

fn extract_conditions_from_assertion(assertion: &str) -> Option<SamlConditions> {
    // Extract conditions
    let not_before = extract_attribute_from_assertion(assertion, "NotBefore");
    let not_on_or_after = extract_attribute_from_assertion(assertion, "NotOnOrAfter");
    
    if not_before.is_some() || not_on_or_after.is_some() {
        Some(SamlConditions {
            not_before,
            not_on_or_after,
            audience_restriction: None, // Simplified
        })
    } else {
        None
    }
}

fn extract_attributes_from_assertion(assertion: &str) -> Option<SamlAttributeStatement> {
    // Extract attributes from assertion
    let mut attributes = Vec::new();
    
    // Extract email
    if let Some(email) = extract_attribute_from_assertion(assertion, "EmailAddress") {
        attributes.push(SamlAttribute {
            name: "email".to_string(),
            name_format: None,
            values: vec![email],
        });
    }
    
    // Extract name
    if let Some(name) = extract_attribute_from_assertion(assertion, "DisplayName") {
        attributes.push(SamlAttribute {
            name: "name".to_string(),
            name_format: None,
            values: vec![name],
        });
    }
    
    // Extract roles
    if let Some(roles_str) = extract_attribute_from_assertion(assertion, "MemberOf") {
        let roles: Vec<String> = roles_str.split(',').map(|s| s.trim().to_string()).collect();
        attributes.push(SamlAttribute {
            name: "roles".to_string(),
            name_format: None,
            values: roles,
        });
    }
    
    if !attributes.is_empty() {
        Some(SamlAttributeStatement { attributes })
    } else {
        None
    }
}

fn extract_signature_from_assertion(assertion: &str) -> Option<String> {
    // Extract signature (simplified)
    if let Some(start) = assertion.find("<Signature>") {
        if let Some(end) = assertion[start..].find("</Signature>") {
            return Some(assertion[start..start + end + 11].to_string());
        }
    }
    None
}

fn validate_saml_assertion(assertion: &SamlAssertion, config: &SamlConfig) -> Result<(), String> {
    let now = unsafe { get_timestamp() } as u64;
    let clock_skew = config.clock_skew_seconds;
    
    // Validate time conditions
    if let Some(conditions) = &assertion.conditions {
        if let Some(not_before) = &conditions.not_before {
            let not_before_timestamp = parse_saml_timestamp(not_before)?;
            if now + clock_skew < not_before_timestamp {
                return Err("Assertion is not yet valid".to_string());
            }
        }
        
        if let Some(not_on_or_after) = &conditions.not_on_or_after {
            let not_on_or_after_timestamp = parse_saml_timestamp(not_on_or_after)?;
            if now - clock_skew > not_on_or_after_timestamp {
                return Err("Assertion has expired".to_string());
            }
        }
    }
    
    // Validate subject
    if assertion.subject.name_id.value.is_empty() {
        return Err("Assertion missing subject".to_string());
    }
    
    // In a real implementation, validate signature against certificate
    // For now, we'll just check if signature exists
    if assertion.signature.is_none() {
        return Err("Assertion missing signature".to_string());
    }
    
    Ok(())
}

fn parse_saml_timestamp(timestamp: &str) -> Result<u64, String> {
    // Simplified SAML timestamp parsing
    // SAML timestamps are in ISO 8601 format
    match chrono::DateTime::parse_from_rfc3339(timestamp) {
        Ok(dt) => Ok(dt.timestamp() as u64),
        Err(e) => Err(format!("Failed to parse timestamp: {}", e)),
    }
}

fn create_saml_session(user_info: AuthUserInfo, assertion: &str, expires_in: u64) -> SamlSession {
    let now = unsafe { get_timestamp() } as u64;
    
    SamlSession {
        user_info,
        created_at: now,
        expires_at: now + expires_in,
        assertion: assertion.to_string(),
    }
}

fn cache_saml_session(session_id: &str, session: SamlSession) {
    let cache = SESSION_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut cache) = cache.lock() {
        cache.insert(session_id.to_string(), session);
    }
}

fn get_cached_session(session_id: &str) -> Option<SamlSession> {
    if let Some(cache) = SESSION_CACHE.get() {
        if let Ok(cache) = cache.lock() {
            let now = unsafe { get_timestamp() } as u64;
            if let Some(session) = cache.get(session_id) {
                if session.expires_at > now {
                    return Some(session.clone());
                }
            }
        }
    }
    None
}

// Plugin entry points
#[no_mangle]
pub extern "C" fn saml_initialize() -> i32 {
    log_message(2, "Initializing SAML authentication plugin");
    
    // Load configuration
    let config_key = "saml_config";
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
            match serde_json::from_str::<SamlConfig>(&config_json) {
                Ok(config) => {
                    let _ = PLUGIN_CONFIG.set(config);
                    let _ = PLUGIN_INITIALIZED.set(true);
                    log_message(2, "SAML plugin initialized successfully");
                    return 1;
                }
                Err(e) => {
                    log_message(0, &format!("Failed to parse config: {}", e));
                    return 0;
                }
            }
        } else {
            // Use default configuration
            let _ = PLUGIN_CONFIG.set(SamlConfig::default());
            let _ = PLUGIN_INITIALIZED.set(true);
            log_message(2, "SAML plugin initialized with default config");
            return 1;
        }
    }
}

#[no_mangle]
pub extern "C" fn saml_authenticate(
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
    
    log_message(2, &format!("Processing SAML authentication request"));
    
    let config = PLUGIN_CONFIG.get().unwrap();
    
    match auth_request.method.as_str() {
        "SAML" => {
            // Handle SAML assertion authentication
            if let Some(assertion) = &auth_request.credentials.saml_assertion {
                // Parse SAML assertion
                match parse_saml_assertion(assertion) {
                    Ok(saml_assertion) => {
                        // Validate assertion
                        match validate_saml_assertion(&saml_assertion, config) {
                            Ok(()) => {
                                // Extract user information
                                let user_id = saml_assertion.subject.name_id.value.clone();
                                let mut user_info = AuthUserInfo {
                                    id: user_id.clone(),
                                    username: user_id.clone(),
                                    email: None,
                                    display_name: None,
                                    roles: vec![],
                                    permissions: vec![],
                                    tenant_id: None,
                                    attributes: HashMap::new(),
                                };
                                
                                // Extract attributes from assertion
                                if let Some(attr_statement) = &saml_assertion.attribute_statement {
                                    for attribute in &attr_statement.attributes {
                                        match attribute.name.as_str() {
                                            "email" => {
                                                if !attribute.values.is_empty() {
                                                    user_info.email = Some(attribute.values[0].clone());
                                                }
                                            }
                                            "name" => {
                                                if !attribute.values.is_empty() {
                                                    user_info.display_name = Some(attribute.values[0].clone());
                                                }
                                            }
                                            "roles" => {
                                                user_info.roles = attribute.values.clone();
                                            }
                                            _ => {
                                                // Store additional attributes
                                                user_info.attributes.insert(
                                                    attribute.name.clone(),
                                                    serde_json::Value::Array(
                                                        attribute.values.iter()
                                                            .map(|v| serde_json::Value::String(v.clone()))
                                                            .collect()
                                                    )
                                                );
                                            }
                                        }
                                    }
                                }
                                
                                // Create session
                                let session_id = format!("saml-session-{}", unsafe { get_timestamp() });
                                let session = create_saml_session(user_info.clone(), assertion, 3600); // 1 hour
                                cache_saml_session(&session_id, session.clone());
                    
                                let result = AuthResult {
                                    success: true,
                                    user_info: Some(user_info),
                                    token: Some(session_id.clone()),
                                    refresh_token: None,
                                    expires_at: Some(session.expires_at),
                                    error: None,
                                    metadata: {
                                        let mut metadata = HashMap::new();
                                        metadata.insert("session_id".to_string(), serde_json::Value::String(session_id.clone()));
                                        metadata.insert("assertion_id".to_string(), serde_json::Value::String(saml_assertion.id));
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
                                    error: Some(format!("SAML assertion validation failed: {}", e)),
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
                            error: Some(format!("Failed to parse SAML assertion: {}", e)),
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
                    error: Some("SAML assertion is required".to_string()),
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
pub extern "C" fn saml_validate_token(
    token_ptr: *const u8,
    token_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !*PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        return 0;
    }
    
    let token = read_string_from_wasm(token_ptr, token_len);
    
    // Check session cache
    if let Some(session) = get_cached_session(&token) {
        let response = serde_json::json!({
            "valid": true,
            "user_info": session.user_info
        });
        
        let response_json = serde_json::to_string(&response).unwrap_or_default();
        return write_string_to_wasm(&response_json, response_ptr, response_len) as i32;
    }
    
    let response = serde_json::json!({
        "valid": false,
        "error": "Session not found or expired"
    });
    
    let response_json = serde_json::to_string(&response).unwrap_or_default();
    return write_string_to_wasm(&response_json, response_ptr, response_len) as i32;
}

#[no_mangle]
pub extern "C" fn saml_refresh_token(
    _refresh_token_ptr: *const u8,
    _refresh_token_len: usize,
    response_ptr: *mut u8,
    response_len: usize
) -> i32 {
    if !*PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        return 0;
    }
    
    // SAML doesn't typically use refresh tokens
    // Users need to re-authenticate with a new SAML assertion
    let result = AuthResult {
        success: false,
        user_info: None,
        token: None,
        refresh_token: None,
        expires_at: None,
        error: Some("SAML does not support token refresh. Please re-authenticate with SAML assertion.".to_string()),
        metadata: HashMap::new(),
    };
    
    let result_json = serde_json::to_string(&result).unwrap_or_default();
    return write_string_to_wasm(&result_json, response_ptr, response_len) as i32;
}

#[no_mangle]
pub extern "C" fn saml_logout(
    token_ptr: *const u8,
    token_len: usize
) -> i32 {
    if !*PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        return 0;
    }
    
    let token = read_string_from_wasm(token_ptr, token_len);
    log_message(2, &format!("Logging out SAML session: {}", token));
    
    // Remove from session cache
    if let Some(cache) = SESSION_CACHE.get() {
        if let Ok(mut cache) = cache.lock() {
            cache.remove(&token);
        }
    }
    
    1 // Success
}

#[no_mangle]
pub extern "C" fn saml_health_check() -> i32 {
    if *PLUGIN_INITIALIZED.get().unwrap_or(&false) {
        1 // Healthy
    } else {
        0 // Unhealthy
    }
}

#[no_mangle]
pub extern "C" fn saml_cleanup() -> i32 {
    log_message(2, "Cleaning up SAML authentication plugin");
    
    // Note: OnceLock doesn't support clearing, so we just log the cleanup
    log_message(2, "SAML plugin cleanup completed");
    
    1 // Success
}

// Plugin metadata exports
#[no_mangle]
pub extern "C" fn get_saml_plugin_name() -> *const u8 {
    PLUGIN_NAME.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_saml_plugin_name_len() -> usize {
    PLUGIN_NAME.len()
}

#[no_mangle]
pub extern "C" fn get_saml_plugin_version() -> *const u8 {
    PLUGIN_VERSION.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_saml_plugin_version_len() -> usize {
    PLUGIN_VERSION.len()
}

#[no_mangle]
pub extern "C" fn get_saml_supported_methods() -> *const u8 {
    let methods = r#"["SAML"]"#;
    methods.as_ptr()
}

#[no_mangle]
pub extern "C" fn get_saml_supported_methods_len() -> usize {
    let methods = r#"["SAML"]"#;
    methods.len()
}

// Plugin metadata function
pub fn get_metadata() -> PluginMetadata {
    PluginMetadata {
        name: PLUGIN_NAME.to_string(),
        version: PLUGIN_VERSION.to_string(),
        description: PLUGIN_DESCRIPTION.to_string(),
        author: PLUGIN_AUTHOR.to_string(),
        supported_methods: vec!["SAML".to_string()],
        required_config: vec!["saml_config".to_string()],
        capabilities: PluginCapabilities {
            can_generate_tokens: false, // SAML doesn't generate tokens directly
            can_validate_tokens: true,
            can_refresh_tokens: false,  // SAML uses assertions, not refresh tokens
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

// Main function for binary compilation (disabled)
// fn main() {
//     println!("SAML Authentication Plugin for Fortress");
//     println!("This is a WebAssembly plugin and should be loaded by the Fortress runtime.");
// }
