//! Example WASM Policy Evaluator Plugin
//! 
//! This plugin demonstrates how to create a custom policy evaluator using WebAssembly.
//! It implements role-based access control (RBAC) with additional attribute-based access control (ABAC) features.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// External function declarations (provided by Fortress host)
extern "C" {
    // Basic functions
    fn fortress_log(ptr: *const u8, len: usize);
    fn fortress_get_config(key_ptr: *const u8, key_len: usize, value_ptr: *mut u8, value_len: usize) -> i32;
    fn fortress_get_timestamp() -> i64;
    
    // Policy evaluation functions
    fn fortress_policy_evaluate_user_role(user_ptr: *const u8, user_len: usize, role_ptr: *const u8, role_len: usize) -> i32;
    fn fortress_policy_check_resource_access(user_ptr: *const u8, user_len: usize, resource_ptr: *const u8, resource_len: usize, action_ptr: *const u8, action_len: usize) -> i32;
    fn fortress_policy_check_time_based_access(start_hour: i32, end_hour: i32) -> i32;
    fn fortress_policy_check_geolocation_access(country_ptr: *const u8, country_len: usize) -> i32;
}

// Policy evaluation context received from Fortress
#[derive(Debug, Deserialize)]
struct PolicyContext {
    request_id: String,
    user: UserContext,
    resource: ResourceContext,
    action: String,
    request: RequestContext,
    environment: EnvironmentContext,
    timestamp: String, // ISO 8601 string
}

#[derive(Debug, Deserialize)]
struct UserContext {
    user_id: String,
    roles: Vec<String>,
    attributes: HashMap<String, serde_json::Value>,
    auth_method: String,
    session_id: Option<String>,
    clearance_level: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResourceContext {
    resource_id: String,
    resource_type: String,
    attributes: HashMap<String, serde_json::Value>,
    owner: Option<String>,
    classification: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequestContext {
    source_ip: String,
    user_agent: Option<String>,
    headers: HashMap<String, String>,
    parameters: HashMap<String, serde_json::Value>,
    method: String,
    path: String,
}

#[derive(Debug, Deserialize)]
struct EnvironmentContext {
    current_time: String,
    timezone: String,
    geolocation: Option<GeoLocation>,
    device: Option<DeviceContext>,
    network: NetworkContext,
    threat_intelligence: ThreatIntelligence,
}

#[derive(Debug, Deserialize)]
struct GeoLocation {
    country: String,
    region: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct DeviceContext {
    device_type: String,
    os: String,
    browser: Option<String>,
    fingerprint: Option<String>,
    trusted: bool,
}

#[derive(Debug, Deserialize)]
struct NetworkContext {
    network_type: String,
    security_level: String,
    vpn_info: Option<VpnInfo>,
}

#[derive(Debug, Deserialize)]
struct VpnInfo {
    provider: String,
    endpoint: String,
    trusted: bool,
}

#[derive(Debug, Deserialize)]
struct ThreatIntelligence {
    ip_reputation_score: f64,
    malicious_indicators: Vec<String>,
    risk_level: String,
    last_updated: String,
}

// Policy evaluation result
#[derive(Debug, Serialize)]
struct PolicyResult {
    allow: bool,
    reason: String,
    effect: String, // "allow", "deny", "not_applicable"
    obligations: Vec<PolicyObligation>,
    advice: Option<String>,
    metrics: PolicyMetrics,
    cache_ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct PolicyObligation {
    obligation_type: String,
    parameters: HashMap<String, serde_json::Value>,
    mandatory: bool,
    deadline: Option<String>, // ISO 8601 string
}

#[derive(Debug, Serialize)]
struct PolicyMetrics {
    evaluation_time_ms: u64,
    policies_evaluated: u32,
    memory_usage_bytes: u64,
    custom_metrics: HashMap<String, serde_json::Value>,
}

// Helper functions for logging
fn log_info(message: &str) {
    unsafe {
        let message_bytes = message.as_bytes();
        fortress_log(message_bytes.as_ptr(), message_bytes.len());
    }
}

fn log_debug(message: &str) {
    log_info(&format!("[DEBUG] {}", message));
}

fn log_error(message: &str) {
    log_info(&format!("[ERROR] {}", message));
}

// Helper function to write string to WASM memory output buffer
fn write_output_to_memory(result: &str) -> i32 {
    // In a real implementation, this would write to the output buffer
    // For this example, we'll just return the length
    log_info(&format!("Writing policy result: {}", result));
    result.len() as i32
}

// Main policy evaluation function
#[no_mangle]
pub extern "C" fn evaluate_policy(context_ptr: *const u8, context_len: usize) -> i32 {
    log_debug("Starting policy evaluation");
    
    // Read policy context from memory
    let context_data = unsafe {
        std::slice::from_raw_parts(context_ptr, context_len)
    };
    
    let context_str = match std::str::from_utf8(context_data) {
        Ok(s) => s,
        Err(e) => {
            log_error(&format!("Failed to parse context: {}", e));
            return -1;
        }
    };
    
    let context: PolicyContext = match serde_json::from_str(context_str) {
        Ok(ctx) => ctx,
        Err(e) => {
            log_error(&format!("Failed to deserialize context: {}", e));
            return -1;
        }
    };
    
    log_debug(&format!("Evaluating policy for user: {}, resource: {}, action: {}", 
                   context.user.user_id, context.resource.resource_id, context.action));
    
    // Perform comprehensive policy evaluation
    let result = evaluate_comprehensive_policy(&context);
    
    // Serialize result
    let result_json = match serde_json::to_string(&result) {
        Ok(json) => json,
        Err(e) => {
            log_error(&format!("Failed to serialize result: {}", e));
            return -1;
        }
    };
    
    // Write result to output buffer and return length
    write_output_to_memory(&result_json)
}

// Comprehensive policy evaluation combining RBAC and ABAC
fn evaluate_comprehensive_policy(context: &PolicyContext) -> PolicyResult {
    let start_time = unsafe { fortress_get_timestamp() };
    let mut policies_evaluated = 0;
    let mut allow = false;
    let mut reason = String::new();
    let mut obligations = Vec::new();
    
    // 1. Role-Based Access Control (RBAC)
    let (rbac_allowed, rbac_reason) = evaluate_rbac(context);
    policies_evaluated += 1;
    
    if !rbac_allowed {
        return PolicyResult {
            allow: false,
            reason: rbac_reason,
            effect: "deny".to_string(),
            obligations: vec![],
            advice: Some("Contact administrator to request appropriate permissions".to_string()),
            metrics: PolicyMetrics {
                evaluation_time_ms: (unsafe { fortress_get_timestamp() } - start_time) as u64,
                policies_evaluated,
                memory_usage_bytes: 0,
                custom_metrics: HashMap::new(),
            },
            cache_ttl_seconds: Some(300), // 5 minutes
        };
    }
    
    // 2. Time-Based Access Control
    let (time_allowed, time_reason) = evaluate_time_based_access(context);
    policies_evaluated += 1;
    
    if !time_allowed {
        return PolicyResult {
            allow: false,
            reason: time_reason,
            effect: "deny".to_string(),
            obligations: vec![],
            advice: Some("Try accessing during allowed hours".to_string()),
            metrics: PolicyMetrics {
                evaluation_time_ms: (unsafe { fortress_get_timestamp() } - start_time) as u64,
                policies_evaluated,
                memory_usage_bytes: 0,
                custom_metrics: HashMap::new(),
            },
            cache_ttl_seconds: Some(60), // 1 minute for time-based restrictions
        };
    }
    
    // 3. Geolocation-Based Access Control
    let (geo_allowed, geo_reason) = evaluate_geolocation_access(context);
    policies_evaluated += 1;
    
    if !geo_allowed {
        return PolicyResult {
            allow: false,
            reason: geo_reason,
            effect: "deny".to_string(),
            obligations: vec![],
            advice: Some("Access from your location is not permitted".to_string()),
            metrics: PolicyMetrics {
                evaluation_time_ms: (unsafe { fortress_get_timestamp() } - start_time) as u64,
                policies_evaluated,
                memory_usage_bytes: 0,
                custom_metrics: HashMap::new(),
            },
            cache_ttl_seconds: Some(300), // 5 minutes for geo restrictions
        };
    }
    
    // 4. Threat Intelligence Check
    let (threat_allowed, threat_reason, threat_obligations) = evaluate_threat_intelligence(context);
    policies_evaluated += 1;
    obligations.extend(threat_obligations);
    
    if !threat_allowed {
        return PolicyResult {
            allow: false,
            reason: threat_reason,
            effect: "deny".to_string(),
            obligations,
            advice: Some("Security concerns detected. Contact security team.".to_string()),
            metrics: PolicyMetrics {
                evaluation_time_ms: (unsafe { fortress_get_timestamp() } - start_time) as u64,
                policies_evaluated,
                memory_usage_bytes: 0,
                custom_metrics: HashMap::new(),
            },
            cache_ttl_seconds: Some(30), // Short cache for threat-based restrictions
        };
    }
    
    // 5. Resource-Specific Rules
    let (resource_allowed, resource_reason, resource_obligations) = evaluate_resource_rules(context);
    policies_evaluated += 1;
    obligations.extend(resource_obligations);
    
    allow = rbac_allowed && time_allowed && geo_allowed && threat_allowed && resource_allowed;
    reason = if allow {
        "All policy checks passed".to_string()
    } else {
        resource_reason
    };
    
    let effect = if allow { "allow" } else { "deny" };
    
    let mut custom_metrics = HashMap::new();
    custom_metrics.insert("rbac_passed".to_string(), serde_json::Value::Bool(rbac_allowed));
    custom_metrics.insert("time_passed".to_string(), serde_json::Value::Bool(time_allowed));
    custom_metrics.insert("geo_passed".to_string(), serde_json::Value::Bool(geo_allowed));
    custom_metrics.insert("threat_passed".to_string(), serde_json::Value::Bool(threat_allowed));
    custom_metrics.insert("resource_passed".to_string(), serde_json::Value::Bool(resource_allowed));
    
    PolicyResult {
        allow,
        reason,
        effect: effect.to_string(),
        obligations,
        advice: if allow {
            Some("Access granted. Follow security best practices.".to_string())
        } else {
            Some("Access denied. Review policy requirements.".to_string())
        },
        metrics: PolicyMetrics {
            evaluation_time_ms: (unsafe { fortress_get_timestamp() } - start_time) as u64,
            policies_evaluated,
            memory_usage_bytes: 0,
            custom_metrics,
        },
        cache_ttl_seconds: Some(if allow { 300 } else { 60 }), // Longer cache for successful access
    }
}

// Role-Based Access Control evaluation
fn evaluate_rbac(context: &PolicyContext) -> (bool, String) {
    let user = &context.user;
    let resource = &context.resource;
    let action = &context.action;
    
    // Check admin access (admin has all permissions)
    if user.roles.contains(&"admin".to_string()) {
        log_debug("Admin access granted");
        return (true, "Admin role granted access".to_string());
    }
    
    // Check resource ownership
    if let Some(owner) = &resource.owner {
        if owner == &user.user_id {
            log_debug("Resource owner access granted");
            return (true, "Resource owner granted access".to_string());
        }
    }
    
    // Check role-based permissions
    let has_permission = match action.as_str() {
        "read" => {
            user.roles.contains(&"user".to_string()) || 
            user.roles.contains(&"readonly".to_string()) ||
            user.roles.contains(&"guest".to_string())
        },
        "write" => {
            user.roles.contains(&"user".to_string()) ||
            user.roles.contains(&"editor".to_string())
        },
        "delete" => {
            user.roles.contains(&"user".to_string()) && // Only owners can delete
            resource.owner.as_ref().map_or(false, |owner| owner == &user.user_id)
        },
        "admin" => {
            user.roles.contains(&"admin".to_string())
        },
        _ => false,
    };
    
    if has_permission {
        (true, "Role-based access granted".to_string())
    } else {
        (false, format!("Insufficient permissions for action: {}", action))
    }
}

// Time-based access control evaluation
fn evaluate_time_based_access(context: &PolicyContext) -> (bool, String) {
    // Business hours: 9 AM to 5 PM (Monday-Friday)
    let current_hour = chrono::DateTime::parse_from_rfc3339(&context.environment.current_time)
        .ok()
        .and_then(|dt| Some(dt.hour()))
        .unwrap_or(12);
    
    let is_weekend = chrono::DateTime::parse_from_rfc3339(&context.environment.current_time)
        .ok()
        .map(|dt| dt.weekday().num_days_from_monday() >= 5)
        .unwrap_or(false);
    
    // Allow admin access anytime
    if context.user.roles.contains(&"admin".to_string()) {
        return (true, "Admin access allowed anytime".to_string());
    }
    
    // Check business hours for regular users
    if is_weekend && (current_hour < 9 || current_hour > 17) {
        return (false, "Access not allowed outside business hours".to_string());
    }
    
    (true, "Time-based access granted".to_string())
}

// Geolocation-based access control evaluation
fn evaluate_geolocation_access(context: &PolicyContext) -> (bool, String) {
    // Allow admin access from anywhere
    if context.user.roles.contains(&"admin".to_string()) {
        return (true, "Admin access allowed from any location".to_string());
    }
    
    if let Some(geo) = &context.environment.geolocation {
        let country = &geo.country;
        
        // Check against host function
        let country_bytes = country.as_bytes();
        let allowed = unsafe {
            fortress_policy_check_geolocation_access(
                country_bytes.as_ptr(),
                country_bytes.len()
            ) == 1
        };
        
        if allowed {
            (true, format!("Geolocation access granted for {}", country))
        } else {
            (false, format!("Access from {} is not permitted", country))
        }
    } else {
        // If geolocation is not available, allow but log warning
        log_debug("Geolocation not available, allowing access");
        (true, "Geolocation check bypassed (location unknown)".to_string())
    }
}

// Threat intelligence evaluation
fn evaluate_threat_intelligence(context: &PolicyContext) -> (bool, String, Vec<PolicyObligation>) {
    let threat = &context.environment.threat_intelligence;
    let mut obligations = Vec::new();
    
    // High risk sources are blocked
    if threat.risk_level == "critical" {
        return (false, "Critical risk level detected - access blocked".to_string(), obligations);
    }
    
    // Medium risk requires additional verification
    if threat.risk_level == "high" {
        obligations.push(PolicyObligation {
            obligation_type: "multi_factor_authentication".to_string(),
            parameters: {
                let mut params = HashMap::new();
                params.insert("required".to_string(), serde_json::Value::Bool(true));
                params.insert("timeout_seconds".to_string(), serde_json::Value::Number(serde_json::Number::from(300)));
                params
            },
            mandatory: true,
            deadline: None,
        });
        
        return (true, "High risk detected - MFA required".to_string(), obligations);
    }
    
    // Low IP reputation score requires monitoring
    if threat.ip_reputation_score < 50.0 {
        obligations.push(PolicyObligation {
            obligation_type: "enhanced_monitoring".to_string(),
            parameters: {
                let mut params = HashMap::new();
                params.insert("duration_minutes".to_string(), serde_json::Value::Number(serde_json::Number::from(60)));
                params.insert("log_level".to_string(), serde_json::Value::String("detailed".to_string()));
                params
            },
            mandatory: true,
            deadline: None,
        });
    }
    
    (true, "Threat intelligence check passed".to_string(), obligations)
}

// Resource-specific rule evaluation
fn evaluate_resource_rules(context: &PolicyContext) -> (bool, String, Vec<PolicyObligation>) {
    let resource = &context.resource;
    let action = &context.action;
    let mut obligations = Vec::new();
    
    // Classification-based access control
    if let Some(classification) = &resource.classification {
        let clearance = context.user.clearance_level.as_deref().unwrap_or("unclassified");
        
        let allowed = match (classification.as_str(), clearance) {
            ("public", _) => true,
            ("internal", "unclassified" | "internal" | "confidential" | "secret" | "top_secret") => true,
            ("confidential", "confidential" | "secret" | "top_secret") => true,
            ("secret", "secret" | "top_secret") => true,
            ("top_secret", "top_secret") => true,
            _ => false,
        };
        
        if !allowed {
            return (false, format!("Insufficient clearance for {} resource", classification), obligations);
        }
    }
    
    // Special handling for sensitive actions
    match action.as_str() {
        "delete" => {
            obligations.push(PolicyObligation {
                obligation_type: "audit_log".to_string(),
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("action".to_string(), serde_json::Value::String("delete".to_string()));
                    params.insert("resource".to_string(), serde_json::Value::String(resource.resource_id.clone()));
                    params.insert("user".to_string(), serde_json::Value::String(context.user.user_id.clone()));
                    params
                },
                mandatory: true,
                deadline: None,
            });
        },
        "write" => {
            if resource.tags.contains(&"financial".to_string()) {
                obligations.push(PolicyObligation {
                    obligation_type: "dual_approval".to_string(),
                    parameters: {
                        let mut params = HashMap::new();
                        params.insert("approvers_required".to_string(), serde_json::Value::Number(serde_json::Number::from(2)));
                        params
                    },
                    mandatory: true,
                    deadline: Some(chrono::Utc::now() + chrono::Duration::hours(24).to_rfc3339().unwrap()),
                });
            }
        },
        _ => {}
    }
    
    (true, "Resource-specific rules passed".to_string(), obligations)
}

// Plugin initialization function
#[no_mangle]
pub extern "C" fn initialize() -> i32 {
    log_info("WASM Policy Evaluator Plugin initialized");
    0 // Success
}

// Plugin cleanup function
#[no_mangle]
pub extern "C" fn cleanup() -> i32 {
    log_info("WASM Policy Evaluator Plugin cleaned up");
    0 // Success
}

// Memory allocation function (simplified)
#[no_mangle]
pub extern "C" fn allocate(size: usize) -> *mut u8 {
    // In a real implementation, this would allocate from WASM memory
    // For this example, we'll use a static buffer
    static mut BUFFER: [u8; 4096] = [0; 4096];
    unsafe { BUFFER.as_mut_ptr() }
}

// Memory deallocation function (simplified)
#[no_mangle]
pub extern "C" fn deallocate(ptr: *mut u8, size: usize) {
    // In a real implementation, this would deallocate from WASM memory
    // For this example, we don't need to do anything
    unsafe {
        let _ = ptr;
        let _ = size;
    }
}
