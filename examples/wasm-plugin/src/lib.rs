use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

// Plugin metadata that would be registered with Fortress
#[no_mangle]
pub static PLUGIN_METADATA: &str = r#"{
  "name": "enhanced-audit",
  "version": "0.1.0", 
  "description": "Enhanced audit logging with real-time analytics",
  "author": "Fortress Team",
  "license": "Apache-2.0",
  "hooks": ["data_access", "data_modification", "authentication", "key_rotation"]
}"#;

// Enhanced audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAuditEvent {
    #[serde(rename = "eventId")]
    event_id: String,
    
    #[serde(rename = "eventType")]
    event_type: String,
    
    #[serde(rename = "timestamp")]
    timestamp: DateTime<Utc>,
    
    #[serde(rename = "userId")]
    user_id: Option<String>,
    
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    
    #[serde(rename = "resource")]
    resource: String,
    
    #[serde(rename = "action")]
    action: String,
    
    #[serde(rename = "result")]
    result: String,
    
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
    
    #[serde(rename = "metadata")]
    metadata: HashMap<String, serde_json::Value>,
    
    #[serde(rename = "riskScore")]
    risk_score: Option<f64>,
    
    #[serde(rename = "anomalyFlags")]
    anomaly_flags: Vec<String>,
}

// Plugin state for analytics
#[derive(Debug)]
pub struct PluginState {
    event_count: u64,
    failed_auth_count: u64,
    suspicious_patterns: HashMap<String, u64>,
    last_activity: DateTime<Utc>,
}

impl Default for PluginState {
    fn default() -> Self {
        Self {
            event_count: 0,
            failed_auth_count: 0,
            suspicious_patterns: HashMap::new(),
            last_activity: Utc::now(),
        }
    }
}

// Main plugin struct
pub struct EnhancedAuditPlugin {
    state: PluginState,
}

impl EnhancedAuditPlugin {
    pub fn new() -> Self {
        Self {
            state: PluginState::default(),
        }
    }
    
    fn calculate_risk_score(&self, event: &EnhancedAuditEvent) -> Option<f64> {
        let mut score: f64 = 0.0;
        
        // High-risk actions
        match event.action.as_str() {
            "DELETE" => score += 30.0,
            "DROP_TABLE" => score += 50.0,
            "KEY_ROTATE" => score += 20.0,
            _ => {}
        }
        
        // Suspicious patterns
        if let Some(ip) = &event.ip_address {
            if is_suspicious_ip(ip) {
                score += 40.0;
            }
        }
        
        // Failed authentication
        if event.event_type == "AUTH_FAILURE" {
            score += 25.0;
        }
        
        // Unusual timing
        let time_diff = event.timestamp.signed_duration_since(self.state.last_activity);
        if time_diff.num_hours() < 1 && self.state.event_count > 100 {
            score += 15.0;
        }
        
        Some(score.min(100.0))
    }
    
    fn detect_anomalies(&mut self, event: &EnhancedAuditEvent) -> Vec<String> {
        let mut anomalies = Vec::new();
        
        // Check for unusual access patterns
        if event.event_type == "DATA_ACCESS" {
            let key = format!("{}:{}", event.user_id.as_deref().unwrap_or("anonymous"), event.resource);
            let count = self.state.suspicious_patterns.entry(key.clone()).or_insert(0);
            *count += 1;
            
            if *count > 1000 {  // More than 1000 accesses to same resource
                anomalies.push("HIGH_FREQUENCY_ACCESS".to_string());
            }
        }
        
        // Check for privileged operations
        if event.action.contains("ADMIN") || event.action.contains("SYSTEM") {
            anomalies.push("PRIVILEGED_OPERATION".to_string());
        }
        
        // Check for bulk operations
        if let Some(metadata) = event.metadata.get("rowCount") {
            if let Some(count) = metadata.as_u64() {
                if count > 10000 {
                    anomalies.push("BULK_OPERATION".to_string());
                }
            }
        }
        
        anomalies
    }
    
    fn process_event(&mut self, event_type: &str, context: &HashMap<String, serde_json::Value>) -> Result<String, String> {
        let event = EnhancedAuditEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type: event_type.to_string(),
            timestamp: Utc::now(),
            user_id: context.get("user_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
            session_id: context.get("session_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
            resource: context.get("resource").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            action: context.get("action").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            result: context.get("result").and_then(|v| v.as_str()).unwrap_or("SUCCESS").to_string(),
            ip_address: context.get("ip_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
            user_agent: context.get("user_agent").and_then(|v| v.as_str()).map(|s| s.to_string()),
            metadata: context.clone(),
            risk_score: self.calculate_risk_score(&EnhancedAuditEvent {
                event_id: String::new(),
                event_type: event_type.to_string(),
                timestamp: Utc::now(),
                user_id: context.get("user_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                session_id: context.get("session_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                resource: context.get("resource").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                action: context.get("action").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                result: context.get("result").and_then(|v| v.as_str()).unwrap_or("SUCCESS").to_string(),
                ip_address: context.get("ip_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                user_agent: context.get("user_agent").and_then(|v| v.as_str()).map(|s| s.to_string()),
                metadata: context.clone(),
                risk_score: None,
                anomaly_flags: Vec::new(),
            }),
            anomaly_flags: self.detect_anomalies(&EnhancedAuditEvent {
                event_id: String::new(),
                event_type: event_type.to_string(),
                timestamp: Utc::now(),
                user_id: context.get("user_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                session_id: context.get("session_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                resource: context.get("resource").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                action: context.get("action").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                result: context.get("result").and_then(|v| v.as_str()).unwrap_or("SUCCESS").to_string(),
                ip_address: context.get("ip_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                user_agent: context.get("user_agent").and_then(|v| v.as_str()).map(|s| s.to_string()),
                metadata: context.clone(),
                risk_score: None,
                anomaly_flags: Vec::new(),
            }),
        };
        
        self.state.event_count += 1;
        self.state.last_activity = Utc::now();
        
        // Log enhanced event
        match serde_json::to_string(&event) {
            Ok(json) => {
                println!("AUDIT: {}", json);
                Ok(json)
            }
            Err(e) => Err(format!("Failed to serialize event: {}", e))
        }
    }
}

// Check if IP address is suspicious
fn is_suspicious_ip(ip: &str) -> bool {
    // Simple heuristic - in production, use a threat intelligence feed
    ip.starts_with("10.0.0.") ||  // Internal network
    ip.starts_with("192.168.") ||   // Internal network  
    ip.contains("tor") ||           // Tor exit node
    ip.parse::<std::net::IpAddr>().is_ok() && ip.parse::<std::net::IpAddr>().unwrap().is_loopback()
}

// Plugin entry point for demonstration
#[no_mangle]
pub extern "C" fn create_plugin() -> *mut EnhancedAuditPlugin {
    let plugin = Box::new(EnhancedAuditPlugin::new());
    Box::into_raw(plugin)
}

// Plugin cleanup
#[no_mangle]
pub extern "C" fn destroy_plugin(plugin: *mut EnhancedAuditPlugin) {
    if !plugin.is_null() {
        unsafe {
            let _ = Box::from_raw(plugin);
        }
    }
}

// Demonstration functions
#[no_mangle]
pub extern "C" fn process_data_access(_context_ptr: *const u8, _context_len: usize) -> *mut u8 {
    let mut plugin = EnhancedAuditPlugin::new();
    
    // In a real implementation, this would parse context from bytes
    let mut context = HashMap::new();
    context.insert("user_id".to_string(), serde_json::Value::String("demo_user".to_string()));
    context.insert("resource".to_string(), serde_json::Value::String("database.users".to_string()));
    context.insert("action".to_string(), serde_json::Value::String("READ".to_string()));
    context.insert("result".to_string(), serde_json::Value::String("SUCCESS".to_string()));
    
    match plugin.process_event("DATA_ACCESS", &context) {
        Ok(result) => {
            let result_bytes = result.into_bytes();
            let ptr = result_bytes.as_ptr();
            std::mem::forget(result_bytes);
            ptr as *mut u8
        }
        Err(_) => std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn process_authentication(_context_ptr: *const u8, _context_len: usize) -> *mut u8 {
    let mut plugin = EnhancedAuditPlugin::new();
    
    let mut context = HashMap::new();
    context.insert("user_id".to_string(), serde_json::Value::String("demo_user".to_string()));
    context.insert("action".to_string(), serde_json::Value::String("LOGIN_SUCCESS".to_string()));
    context.insert("result".to_string(), serde_json::Value::String("SUCCESS".to_string()));
    context.insert("ip_address".to_string(), serde_json::Value::String("192.168.1.100".to_string()));
    
    match plugin.process_event("AUTHENTICATION", &context) {
        Ok(result) => {
            let result_bytes = result.into_bytes();
            let ptr = result_bytes.as_ptr();
            std::mem::forget(result_bytes);
            ptr as *mut u8
        }
        Err(_) => std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn free_memory(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = EnhancedAuditPlugin::new();
        assert_eq!(plugin.state.event_count, 0);
    }

    #[test]
    fn test_risk_scoring() {
        let plugin = EnhancedAuditPlugin::new();
        let event = EnhancedAuditEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type: "DATA_ACCESS".to_string(),
            timestamp: Utc::now(),
            user_id: Some("test_user".to_string()),
            session_id: None,
            resource: "database.users".to_string(),
            action: "DELETE".to_string(),  // High risk action
            result: "SUCCESS".to_string(),
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: None,
            metadata: HashMap::new(),
            risk_score: None,
            anomaly_flags: Vec::new(),
        };

        let score = plugin.calculate_risk_score(&event);
        assert!(score.is_some());
        assert!(score.unwrap() > 20.0);  // Should be high due to DELETE action
    }

    #[test]
    fn test_suspicious_ip_detection() {
        assert!(is_suspicious_ip("10.0.0.1"));
        assert!(is_suspicious_ip("192.168.1.1"));
        assert!(!is_suspicious_ip("8.8.8.8"));
    }
}
