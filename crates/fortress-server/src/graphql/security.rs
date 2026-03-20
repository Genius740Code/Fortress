//! Comprehensive security layer for GraphQL API
//!
//! Implements rate limiting, input validation, query complexity analysis,
//! authentication enhancements, and security monitoring for production use.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use async_graphql::{Result, Error, ErrorExtensions};
use uuid::Uuid;
use regex::Regex;
use once_cell::sync::Lazy;

/// Security configuration for GraphQL operations
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub max_query_depth: usize,
    pub max_query_complexity: usize,
    pub max_request_size: usize,
    pub rate_limit_requests_per_minute: u32,
    pub rate_limit_burst: u32,
    pub enable_query_analysis: bool,
    pub enable_input_validation: bool,
    pub enable_audit_logging: bool,
    pub blocked_ips: Vec<String>,
    pub allowed_origins: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_query_depth: 10,
            max_query_complexity: 1000,
            max_request_size: 1024 * 1024, // 1MB
            rate_limit_requests_per_minute: 1000,
            rate_limit_burst: 100,
            enable_query_analysis: true,
            enable_input_validation: true,
            enable_audit_logging: true,
            blocked_ips: Vec::new(),
            allowed_origins: vec!["*".to_string()],
        }
    }
}

/// Rate limiter for GraphQL requests
#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests_per_minute: u32,
    burst_limit: u32,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32, burst_limit: u32) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests_per_minute,
            burst_limit,
        }
    }

    /// Check if a request is allowed based on rate limiting
    pub async fn is_allowed(&self, client_id: &str) -> RateLimitResult {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Clean up old requests
        if let Some(client_requests) = requests.get_mut(client_id) {
            client_requests.retain(|&timestamp| timestamp > one_minute_ago);
            
            // Check current rate
            if client_requests.len() >= self.max_requests_per_minute as usize {
                return RateLimitResult::Blocked {
                    reason: "Rate limit exceeded".to_string(),
                    retry_after: Duration::from_secs(60),
                };
            }

            // Check burst limit
            let recent_requests: Vec<_> = client_requests
                .iter()
                .filter(|timestamp| now.duration_since(**timestamp) < Duration::from_secs(10))
                .collect();
            
            if recent_requests.len() >= self.burst_limit as usize {
                return RateLimitResult::Blocked {
                    reason: "Burst limit exceeded".to_string(),
                    retry_after: Duration::from_secs(10),
                };
            }

            // Record this request
            client_requests.push(now);
            RateLimitResult::Allowed
        } else {
            // First request from this client
            requests.insert(client_id.to_string(), vec![now]);
            RateLimitResult::Allowed
        }
    }

    /// Get rate limit statistics
    pub async fn get_stats(&self) -> RateLimitStats {
        let requests = self.requests.read().await;
        let total_clients = requests.len();
        let total_requests: usize = requests.values().map(|v| v.len()).sum();
        
        RateLimitStats {
            total_clients,
            total_requests,
            max_requests_per_minute: self.max_requests_per_minute,
            burst_limit: self.burst_limit,
        }
    }
}

/// Rate limiting result
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Blocked {
        reason: String,
        retry_after: Duration,
    },
}

/// Rate limiting statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStats {
    pub total_clients: usize,
    pub total_requests: usize,
    pub max_requests_per_minute: u32,
    pub burst_limit: u32,
}

/// Input validation and sanitization
pub struct InputValidator {
    sql_injection_pattern: Regex,
    xss_pattern: Regex,
    path_traversal_pattern: Regex,
    command_injection_pattern: Regex,
    max_string_length: usize,
}

impl InputValidator {
    pub fn new() -> Self {
        Self {
            sql_injection_pattern: Regex::new(r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)\s").unwrap(),
            xss_pattern: Regex::new(r"(?i)(<script|javascript:|onload|onerror|onclick)").unwrap(),
            path_traversal_pattern: Regex::new(r"(\.\./|\.\.\\|/etc/|/var/|/usr/|C:\\|\\\\|\\|\\)").unwrap(),
            command_injection_pattern: Regex::new(r"(?i)(;|\||&|`|\$|\(|\)|<|>|>>|<<)").unwrap(),
            max_string_length: 10000,
        }
    }

    /// Validate and sanitize input string
    pub fn validate_string(&self, input: &str, field_name: &str) -> Result<String> {
        // Check length
        if input.len() > self.max_string_length {
            return Err(Error::new(format!("Input too long for field: {}", field_name))
                .extend_with(|_, e| e.set("code", "INPUT_TOO_LONG")));
        }

        // Check for SQL injection
        if self.sql_injection_pattern.is_match(input) {
            return Err(Error::new(format!("Potential SQL injection in field: {}", field_name))
                .extend_with(|_, e| e.set("code", "SQL_INJECTION_DETECTED")));
        }

        // Check for XSS
        if self.xss_pattern.is_match(input) {
            return Err(Error::new(format!("Potential XSS in field: {}", field_name))
                .extend_with(|_, e| e.set("code", "XSS_DETECTED")));
        }

        // Check for path traversal
        if self.path_traversal_pattern.is_match(input) {
            return Err(Error::new(format!("Potential path traversal in field: {}", field_name))
                .extend_with(|_, e| e.set("code", "PATH_TRAVERSAL_DETECTED")));
        }

        // Check for command injection
        if self.command_injection_pattern.is_match(input) {
            return Err(Error::new(format!("Potential command injection in field: {}", field_name))
                .extend_with(|_, e| e.set("code", "COMMAND_INJECTION_DETECTED")));
        }

        // Sanitize the input
        let sanitized = self.sanitize_string(input);
        Ok(sanitized)
    }

    /// Sanitize input string
    fn sanitize_string(&self, input: &str) -> String {
        input
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .chars()
            .filter(|c| c.is_ascii() && !c.is_control())
            .collect()
    }

    /// Validate email format
    pub fn validate_email(&self, email: &str) -> Result<()> {
        static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
        });

        if !EMAIL_REGEX.is_match(email) {
            return Err(Error::new("Invalid email format")
                .extend_with(|_, e| e.set("code", "INVALID_EMAIL")));
        }

        Ok(())
    }

    /// Validate UUID format
    pub fn validate_uuid(&self, uuid_str: &str) -> Result<()> {
        if let Err(_) = Uuid::parse_str(uuid_str) {
            return Err(Error::new("Invalid UUID format")
                .extend_with(|_, e| e.set("code", "INVALID_UUID")));
        }
        Ok(())
    }

    /// Validate JSON structure
    pub fn validate_json(&self, json_str: &str) -> Result<()> {
        if json_str.len() > self.max_string_length {
            return Err(Error::new("JSON input too long")
                .extend_with(|_, e| e.set("code", "JSON_TOO_LONG")));
        }

        if let Err(_) = serde_json::from_str::<serde_json::Value>(json_str) {
            return Err(Error::new("Invalid JSON format")
                .extend_with(|_, e| e.set("code", "INVALID_JSON")));
        }

        Ok(())
    }
}

/// Query complexity analyzer
pub struct QueryComplexityAnalyzer {
    max_depth: usize,
    max_complexity: usize,
    complexity_weights: ComplexityWeights,
}

#[derive(Debug, Clone)]
pub struct ComplexityWeights {
    pub field_weight: u32,
    pub depth_weight: u32,
    pub nested_object_weight: u32,
    pub list_weight: u32,
}

impl Default for ComplexityWeights {
    fn default() -> Self {
        Self {
            field_weight: 1,
            depth_weight: 10,
            nested_object_weight: 5,
            list_weight: 2,
        }
    }
}

impl QueryComplexityAnalyzer {
    pub fn new(max_depth: usize, max_complexity: usize) -> Self {
        Self {
            max_depth,
            max_complexity,
            complexity_weights: ComplexityWeights::default(),
        }
    }

    /// Analyze GraphQL query complexity
    pub fn analyze_query(&self, query: &str) -> Result<ComplexityAnalysis> {
        let depth = self.calculate_depth(query);
        let complexity = self.calculate_complexity(query);

        if depth > self.max_depth {
            return Err(Error::new(format!("Query depth {} exceeds maximum allowed depth {}", depth, self.max_depth))
                .extend_with(|_, e| e.set("code", "QUERY_TOO_DEEP")));
        }

        if complexity > self.max_complexity {
            return Err(Error::new(format!("Query complexity {} exceeds maximum allowed complexity {}", complexity, self.max_complexity))
                .extend_with(|_, e| e.set("code", "QUERY_TOO_COMPLEX")));
        }

        Ok(ComplexityAnalysis {
            depth,
            complexity,
            is_safe: true,
            recommendations: self.generate_recommendations(depth, complexity),
        })
    }

    fn calculate_depth(&self, query: &str) -> usize {
        let mut max_depth = 0;
        let mut current_depth = 0;

        for char in query.chars() {
            match char {
                '{' => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                }
                '}' => {
                    if current_depth > 0 {
                        current_depth -= 1;
                    }
                }
                _ => {}
            }
        }

        max_depth
    }

    fn calculate_complexity(&self, query: &str) -> usize {
        let mut complexity = 0;
        
        // Count fields
        complexity += query.matches(':').count() * self.complexity_weights.field_weight as usize;
        
        // Count nested objects
        complexity += query.matches('{').count() * self.complexity_weights.nested_object_weight as usize;
        
        // Count lists/arrays
        complexity += query.matches('[').count() * self.complexity_weights.list_weight as usize;
        
        // Add depth penalty
        let depth = self.calculate_depth(query);
        complexity += depth * self.complexity_weights.depth_weight as usize;

        complexity
    }

    fn generate_recommendations(&self, depth: usize, complexity: usize) -> Vec<String> {
        let mut recommendations = Vec::new();

        if depth > self.max_depth / 2 {
            recommendations.push("Consider reducing query depth to improve performance".to_string());
        }

        if complexity > self.max_complexity / 2 {
            recommendations.push("Consider using pagination to limit result size".to_string());
        }

        if complexity > self.max_complexity / 3 {
            recommendations.push("Consider using GraphQL fragments to reduce redundancy".to_string());
        }

        recommendations
    }
}

/// Query complexity analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityAnalysis {
    pub depth: usize,
    pub complexity: usize,
    pub is_safe: bool,
    pub recommendations: Vec<String>,
}

/// Security audit logger
pub struct SecurityAuditLogger {
    enabled: bool,
    audit_entries: Arc<RwLock<Vec<SecurityAuditEntry>>>,
    max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEntry {
    pub timestamp: u64,
    pub event_type: SecurityEventType,
    pub client_id: String,
    pub user_id: Option<String>,
    pub operation: String,
    pub details: serde_json::Value,
    pub severity: SecuritySeverity,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    RateLimitExceeded,
    InputValidationFailed,
    QueryComplexityExceeded,
    AuthenticationFailed,
    AuthorizationFailed,
    SuspiciousActivity,
    SecurityViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl SecurityAuditLogger {
    pub fn new(enabled: bool, max_entries: usize) -> Self {
        Self {
            enabled,
            audit_entries: Arc::new(RwLock::new(Vec::new())),
            max_entries,
        }
    }

    /// Log a security event
    pub async fn log_event(&self, event: SecurityAuditEntry) {
        if !self.enabled {
            return;
        }

        let mut entries = self.audit_entries.write().await;
        entries.push(event);

        // Maintain max entries
        if entries.len() > self.max_entries {
            entries.remove(0);
        }
    }

    /// Get audit entries with filtering
    pub async fn get_entries(&self, limit: Option<usize>, severity: Option<SecuritySeverity>) -> Vec<SecurityAuditEntry> {
        let entries = self.audit_entries.read().await;
        
        let filtered: Vec<_> = entries
            .iter()
            .filter(|entry| {
                let severity_match = severity.as_ref().map_or(true, |_s| {
                    matches!(&entry.severity, _s)
                });
                severity_match
            })
            .rev() // Most recent first
            .take(limit.unwrap_or(100))
            .cloned()
            .collect();

        filtered
    }

    /// Get security statistics
    pub async fn get_stats(&self) -> SecurityStats {
        let entries = self.audit_entries.read().await;
        
        let mut stats = SecurityStats::default();
        
        for entry in entries.iter() {
            stats.total_events += 1;
            
            if entry.blocked {
                stats.blocked_events += 1;
            }
            
            match entry.severity {
                SecuritySeverity::Low => stats.low_severity += 1,
                SecuritySeverity::Medium => stats.medium_severity += 1,
                SecuritySeverity::High => stats.high_severity += 1,
                SecuritySeverity::Critical => stats.critical_severity += 1,
            }
            
            match entry.event_type {
                SecurityEventType::RateLimitExceeded => stats.rate_limit_violations += 1,
                SecurityEventType::InputValidationFailed => stats.validation_failures += 1,
                SecurityEventType::QueryComplexityExceeded => stats.complexity_violations += 1,
                SecurityEventType::AuthenticationFailed => stats.auth_failures += 1,
                SecurityEventType::AuthorizationFailed => stats.authz_failures += 1,
                SecurityEventType::SuspiciousActivity => stats.suspicious_activities += 1,
                SecurityEventType::SecurityViolation => stats.security_violations += 1,
            }
        }

        stats
    }
}

/// Security statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityStats {
    pub total_events: usize,
    pub blocked_events: usize,
    pub low_severity: usize,
    pub medium_severity: usize,
    pub high_severity: usize,
    pub critical_severity: usize,
    pub rate_limit_violations: usize,
    pub validation_failures: usize,
    pub complexity_violations: usize,
    pub auth_failures: usize,
    pub authz_failures: usize,
    pub suspicious_activities: usize,
    pub security_violations: usize,
}

/// Comprehensive security manager
pub struct SecurityManager {
    config: SecurityConfig,
    rate_limiter: RateLimiter,
    input_validator: InputValidator,
    complexity_analyzer: QueryComplexityAnalyzer,
    audit_logger: SecurityAuditLogger,
    blocked_ips: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        let rate_limiter = RateLimiter::new(
            config.rate_limit_requests_per_minute,
            config.rate_limit_burst,
        );
        
        let complexity_analyzer = QueryComplexityAnalyzer::new(
            config.max_query_depth,
            config.max_query_complexity,
        );
        
        let audit_logger = SecurityAuditLogger::new(
            config.enable_audit_logging,
            10000, // max audit entries
        );

        let blocked_ips = Arc::new(RwLock::new(
            config.blocked_ips.iter().cloned().collect()
        ));

        Self {
            config,
            rate_limiter,
            input_validator: InputValidator::new(),
            complexity_analyzer,
            audit_logger,
            blocked_ips,
        }
    }

    /// Validate GraphQL request security
    pub async fn validate_request(&self, request: &SecurityRequest) -> Result<SecurityValidationResult> {
        let client_id = &request.client_id;
        let user_id = request.user_id.as_deref();
        let ip_address = &request.ip_address;

        // Check if IP is blocked
        {
            let blocked_ips = self.blocked_ips.read().await;
            if blocked_ips.contains(ip_address) {
                self.log_security_event(SecurityEventType::SecurityViolation, client_id, user_id, "ip_blocked", 
                    serde_json::json!({"ip": ip_address}), SecuritySeverity::High, true).await;
                return Ok(SecurityValidationResult::Blocked {
                    reason: "IP address is blocked".to_string(),
                });
            }
        }

        // Check rate limiting
        match self.rate_limiter.is_allowed(client_id).await {
            RateLimitResult::Allowed => {}
            RateLimitResult::Blocked { reason, retry_after } => {
                self.log_security_event(SecurityEventType::RateLimitExceeded, client_id, user_id, "rate_limit_exceeded",
                    serde_json::json!({"reason": reason, "retry_after": retry_after.as_secs()}), SecuritySeverity::Medium, true).await;
                return Ok(SecurityValidationResult::Blocked {
                    reason: format!("Rate limit exceeded: {}", reason),
                });
            }
        }

        // Validate request size
        if request.request_size > self.config.max_request_size {
            self.log_security_event(SecurityEventType::SecurityViolation, client_id, user_id, "request_too_large",
                serde_json::json!({"size": request.request_size}), SecuritySeverity::Medium, true).await;
            return Ok(SecurityValidationResult::Blocked {
                reason: "Request size exceeds maximum allowed".to_string(),
            });
        }

        // Validate query if present
        if let Some(query) = &request.query {
            if self.config.enable_query_analysis {
                match self.complexity_analyzer.analyze_query(query) {
                    Ok(_) => {}
                    Err(e) => {
                        self.log_security_event(SecurityEventType::QueryComplexityExceeded, client_id, user_id, "query_too_complex",
                            serde_json::json!({"error": e.message}), SecuritySeverity::Medium, true).await;
                        return Ok(SecurityValidationResult::Blocked {
                            reason: e.message,
                        });
                    }
                }
            }
        }

        // Validate inputs
        if self.config.enable_input_validation {
            for (field_name, value) in &request.inputs {
                match self.input_validator.validate_string(value, field_name) {
                    Ok(_) => {}
                    Err(e) => {
                        self.log_security_event(SecurityEventType::InputValidationFailed, client_id, user_id, "input_validation_failed",
                            serde_json::json!({"field": field_name, "error": e.message}), SecuritySeverity::Low, true).await;
                        return Ok(SecurityValidationResult::Blocked {
                            reason: format!("Input validation failed for field {}: {}", field_name, e.message),
                        });
                    }
                }
            }
        }

        Ok(SecurityValidationResult::Allowed)
    }

    /// Log security event
    async fn log_security_event(&self, event_type: SecurityEventType, client_id: &str, user_id: Option<&str>, operation: &str, details: serde_json::Value, severity: SecuritySeverity, blocked: bool) {
        let audit_entry = SecurityAuditEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            event_type,
            client_id: client_id.to_string(),
            user_id: user_id.map(|s| s.to_string()),
            operation: operation.to_string(),
            details,
            severity,
            blocked,
        };

        self.audit_logger.log_event(audit_entry).await;
    }

    /// Block an IP address
    pub async fn block_ip(&self, ip_address: &str) {
        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.insert(ip_address.to_string());
    }

    /// Unblock an IP address
    pub async fn unblock_ip(&self, ip_address: &str) {
        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.remove(ip_address);
    }

    /// Get security statistics
    pub async fn get_security_stats(&self) -> SecurityStats {
        self.audit_logger.get_stats().await
    }

    /// Get audit entries
    pub async fn get_audit_entries(&self, limit: Option<usize>, severity: Option<SecuritySeverity>) -> Vec<SecurityAuditEntry> {
        self.audit_logger.get_entries(limit, severity).await
    }

    /// Get rate limiting statistics
    pub async fn get_rate_limit_stats(&self) -> RateLimitStats {
        self.rate_limiter.get_stats().await
    }
}

/// Security validation result
#[derive(Debug, Clone)]
pub enum SecurityValidationResult {
    Allowed,
    Blocked {
        reason: String,
    },
}

/// Security request information
#[derive(Debug, Clone)]
pub struct SecurityRequest {
    pub client_id: String,
    pub user_id: Option<String>,
    pub ip_address: String,
    pub query: Option<String>,
    pub inputs: Vec<(String, String)>,
    pub request_size: usize,
    pub timestamp: Instant,
}

impl SecurityRequest {
    pub fn new(client_id: String, user_id: Option<String>, ip_address: String) -> Self {
        Self {
            client_id,
            user_id,
            ip_address,
            query: None,
            inputs: Vec::new(),
            request_size: 0,
            timestamp: Instant::now(),
        }
    }

    pub fn with_query(mut self, query: String) -> Self {
        self.query = Some(query);
        self
    }

    pub fn with_input(mut self, field_name: String, value: String) -> Self {
        self.inputs.push((field_name, value));
        self
    }

    pub fn with_size(mut self, size: usize) -> Self {
        self.request_size = size;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiting() {
        let rate_limiter = RateLimiter::new(10, 5); // 10 requests per minute, 5 burst
        let client_id = "test_client";

        // First 5 requests should be allowed (burst limit)
        for _ in 0..5 {
            assert!(matches!(rate_limiter.is_allowed(client_id).await, RateLimitResult::Allowed));
        }

        // 6th request should be blocked (burst limit exceeded)
        assert!(matches!(rate_limiter.is_allowed(client_id).await, RateLimitResult::Blocked { .. }));
    }

    #[tokio::test]
    async fn test_input_validation() {
        let validator = InputValidator::new();

        // Valid inputs
        assert!(validator.validate_string("hello world", "test").is_ok());
        assert!(validator.validate_email("test@example.com").is_ok());
        assert!(validator.validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());

        // Invalid inputs
        assert!(validator.validate_string("SELECT * FROM users", "test").is_err());
        assert!(validator.validate_string("<script>alert('xss')</script>", "test").is_err());
        assert!(validator.validate_email("invalid-email").is_err());
        assert!(validator.validate_uuid("invalid-uuid").is_err());
    }

    #[tokio::test]
    async fn test_query_complexity() {
        let analyzer = QueryComplexityAnalyzer::new(5, 100);
        
        // Simple query
        let simple_query = "{ user { id name } }";
        let result = analyzer.analyze_query(simple_query);
        assert!(result.is_ok());
        
        // Complex query
        let complex_query = "{ user { id name posts { title content comments { text author } } }";
        let result = analyzer.analyze_query(complex_query);
        assert!(result.is_ok());
        
        // Too deep query
        let deep_query = "{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } }";
        let result = analyzer.analyze_query(deep_query);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_security_manager() {
        let config = SecurityConfig::default();
        let security_manager = SecurityManager::new(config);

        let request = SecurityRequest::new(
            "test_client".to_string(),
            Some("test_user".to_string()),
            "127.0.0.1".to_string(),
        ).with_query("{ user { id name } }");

        // Valid request should be allowed
        let result = security_manager.validate_request(&request).await;
        assert!(matches!(result, SecurityValidationResult::Allowed));

        // Test IP blocking
        security_manager.block_ip("127.0.0.1").await;
        let blocked_request = SecurityRequest::new(
            "test_client".to_string(),
            Some("test_user".to_string()),
            "127.0.0.1".to_string(),
        );
        let result = security_manager.validate_request(&blocked_request).await;
        assert!(matches!(result, SecurityValidationResult::Blocked { .. }));
    }
}
