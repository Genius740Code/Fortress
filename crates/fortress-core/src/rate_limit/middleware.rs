//! Rate Limiting Middleware
//!
//! This module provides HTTP middleware for rate limiting requests
//! with configurable algorithms and storage backends.

use crate::error::{FortressError, Result};
use crate::rate_limit::{RateLimitAction, RateLimitContext, RateLimitManager, RateLimitResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// HTTP request for rate limiting
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub remote_addr: String,
    pub timestamp: DateTime<Utc>,
}

/// HTTP response for rate limiting
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
}

/// Rate limiting middleware configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitMiddlewareConfig {
    pub enabled: bool,
    pub default_rules: HashMap<String, String>,
    pub custom_headers: HashMap<String, String>,
    pub response_headers: bool,
    pub logging_enabled: bool,
    pub metrics_enabled: bool,
    pub cache_headers: bool,
    pub bypass_paths: Vec<String>,
    pub bypass_ips: Vec<String>,
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    manager: Arc<RateLimitManager>,
    config: RateLimitMiddlewareConfig,
}

impl RateLimitMiddleware {
    /// Create a new rate limiting middleware
    pub fn new(manager: RateLimitManager, config: RateLimitMiddlewareConfig) -> Self {
        Self {
            manager: Arc::new(manager),
            config,
        }
    }

    /// Process an HTTP request through rate limiting
    pub async fn process_request(
        &self,
        request: &HttpRequest,
    ) -> Result<RateLimitMiddlewareResult> {
        // Check if request should bypass rate limiting
        if self.should_bypass(request) {
            return Ok(RateLimitMiddlewareResult {
                allowed: true,
                response: None,
                rate_limit_results: Vec::new(),
                bypass_reason: Some("Bypass rule matched".to_string()),
            });
        }

        // Create rate limit context
        let context = self.create_context(request);

        // Check rate limits
        let rate_limit_results = self.manager.check_rate_limits(&context).await?;

        // Determine if request is allowed
        let allowed = rate_limit_results.iter().all(|result| result.allowed);

        // Create response if not allowed
        let response = if !allowed {
            Some(self.create_rate_limit_response(&rate_limit_results))
        } else {
            None
        };

        // Log rate limiting decision
        if self.config.logging_enabled {
            self.log_rate_limit_decision(request, &rate_limit_results, allowed)
                .await;
        }

        Ok(RateLimitMiddlewareResult {
            allowed,
            response,
            rate_limit_results,
            bypass_reason: None,
        })
    }

    /// Check if request should bypass rate limiting
    fn should_bypass(&self, request: &HttpRequest) -> bool {
        // Check bypass paths
        for bypass_path in &self.config.bypass_paths {
            if request.path.starts_with(bypass_path) {
                return true;
            }
        }

        // Check bypass IPs
        for bypass_ip in &self.config.bypass_ips {
            if request.remote_addr.starts_with(bypass_ip) {
                return true;
            }
        }

        false
    }

    /// Create rate limit context from HTTP request
    fn create_context(&self, request: &HttpRequest) -> RateLimitContext {
        // Extract user ID from headers or query params
        let user_id = request
            .headers
            .get("X-User-ID")
            .or_else(|| request.headers.get("User-ID"))
            .or_else(|| request.query_params.get("user_id"))
            .cloned();

        // Extract API key from headers or query params
        let api_key = request
            .headers
            .get("X-API-Key")
            .or_else(|| request.headers.get("API-Key"))
            .or_else(|| request.query_params.get("api_key"))
            .cloned();

        // Extract token from headers
        let token = request
            .headers
            .get("Authorization")
            .or_else(|| request.headers.get("X-Auth-Token"))
            .cloned();

        // Create metadata from headers and query params
        let mut metadata = HashMap::new();

        // Add query params to metadata
        for (key, value) in &request.query_params {
            metadata.insert(key.clone(), serde_json::Value::String(value.clone()));
        }

        // Add custom headers to metadata
        for (key, value) in &request.headers {
            if key.starts_with("X-") {
                metadata.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
        }

        RateLimitContext {
            request_id: generate_request_id(),
            ip_address: request.remote_addr.clone(),
            user_id,
            api_key,
            token,
            path: request.path.clone(),
            method: request.method.clone(),
            headers: request.headers.clone(),
            timestamp: request.timestamp,
            metadata,
        }
    }

    /// Create rate limit response
    fn create_rate_limit_response(&self, results: &[RateLimitResult]) -> HttpResponse {
        // Find the most restrictive result
        let most_restrictive = results
            .iter()
            .filter(|r| !r.allowed)
            .min_by(|a, b| a.priority.cmp(&b.priority))
            .unwrap_or_else(|| &results[0]);

        let mut headers = HashMap::new();

        // Add rate limit headers
        if self.config.response_headers {
            headers.insert(
                "X-RateLimit-Limit".to_string(),
                most_restrictive.limit.to_string(),
            );
            headers.insert(
                "X-RateLimit-Remaining".to_string(),
                most_restrictive.remaining.to_string(),
            );
            headers.insert(
                "X-RateLimit-Reset".to_string(),
                most_restrictive.reset_time.timestamp().to_string(),
            );

            if let Some(retry_after) = most_restrictive.retry_after {
                headers.insert(
                    "Retry-After".to_string(),
                    retry_after.num_seconds().to_string(),
                );
            }
        }

        // Add custom headers
        for (key, value) in &self.config.custom_headers {
            headers.insert(key.clone(), value.clone());
        }

        // Add cache headers
        if self.config.cache_headers {
            headers.insert("Cache-Control".to_string(), "no-cache".to_string());
            headers.insert("Pragma".to_string(), "no-cache".to_string());
        }

        let body = serde_json::json!({
            "error": "Rate limit exceeded",
            "message": most_restrictive.message.clone(),
            "limit": most_restrictive.limit,
            "remaining": most_restrictive.remaining,
            "reset_time": most_restrictive.reset_time,
            "retry_after": most_restrictive.retry_after,
        });

        HttpResponse {
            status_code: 429,
            headers,
            body: Some(body.to_string().into_bytes()),
            timestamp: Utc::now(),
        }
    }

    /// Log rate limiting decision
    async fn log_rate_limit_decision(
        &self,
        request: &HttpRequest,
        results: &[RateLimitResult],
        allowed: bool,
    ) {
        let log_level = if allowed { "INFO" } else { "WARN" };

        tracing::info!(
            target: "rate_limit",
            method = %request.method,
            path = %request.path,
            remote_addr = %request.remote_addr,
            allowed = allowed,
            results_count = results.len(),
            "{} - Rate limit decision: {}", log_level, if allowed { "ALLOWED" } else { "REJECTED" }
        );

        // Log individual rule results
        for result in results {
            tracing::info!(
                target: "rate_limit",
                rule_name = %result.rule_name,
                allowed = result.allowed,
                limit = result.limit,
                remaining = result.remaining,
                action = ?result.action,
                "Rule evaluation: {} - {} ({}/{})",
                result.rule_name,
                if result.allowed { "ALLOWED" } else { "REJECTED" },
                result.remaining,
                result.limit
            );
        }
    }

    /// Get rate limiting metrics
    pub async fn get_metrics(&self) -> crate::rate_limit::RateLimitMetrics {
        self.manager.get_metrics().await
    }

    /// Reset rate limit for a specific key
    pub async fn reset_rate_limit(&self, key: &str, rule_name: &str) -> Result<()> {
        self.manager.reset_rate_limit(key, rule_name).await
    }

    /// Get current usage for a key and rule
    pub async fn get_usage(&self, key: &str, rule_name: &str) -> Result<Option<u64>> {
        self.manager.get_usage(key, rule_name).await
    }
}

/// Rate limiting middleware result
#[derive(Debug, Clone)]
pub struct RateLimitMiddlewareResult {
    pub allowed: bool,
    pub response: Option<HttpResponse>,
    pub rate_limit_results: Vec<RateLimitResult>,
    pub bypass_reason: Option<String>,
}

/// Rate limiting middleware for web frameworks
pub struct WebRateLimitMiddleware {
    inner: RateLimitMiddleware,
}

impl WebRateLimitMiddleware {
    /// Create a new web rate limiting middleware
    pub fn new(manager: RateLimitManager, config: RateLimitMiddlewareConfig) -> Self {
        Self {
            inner: RateLimitMiddleware::new(manager, config),
        }
    }

    /// Process a web request (generic interface)
    pub async fn process_web_request<F, R>(
        &self,
        request: &R,
        context_extractor: F,
    ) -> Result<RateLimitMiddlewareResult>
    where
        F: Fn(&R) -> HttpRequest,
    {
        let http_request = context_extractor(request);
        self.inner.process_request(&http_request).await
    }

    /// Get the inner middleware
    pub fn inner(&self) -> &RateLimitMiddleware {
        &self.inner
    }
}

/// Generate a unique request ID
fn generate_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(
        "req-{}-{}",
        Utc::now().timestamp_nanos_opt().unwrap_or(0),
        id
    )
}

/// Rate limiting middleware for HTTP servers
pub struct HttpRateLimitMiddleware {
    inner: RateLimitMiddleware,
}

impl HttpRateLimitMiddleware {
    /// Create a new HTTP rate limiting middleware
    pub fn new(manager: RateLimitManager, config: RateLimitMiddlewareConfig) -> Self {
        Self {
            inner: RateLimitMiddleware::new(manager, config),
        }
    }

    /// Process an HTTP request and return response if rate limited
    pub async fn check_rate_limit(&self, request: &HttpRequest) -> Result<Option<HttpResponse>> {
        let result = self.inner.process_request(request).await?;
        Ok(result.response)
    }

    /// Get rate limiting headers for successful requests
    pub fn get_rate_limit_headers(&self, results: &[RateLimitResult]) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        if let Some(result) = results.first() {
            headers.insert("X-RateLimit-Limit".to_string(), result.limit.to_string());
            headers.insert(
                "X-RateLimit-Remaining".to_string(),
                result.remaining.to_string(),
            );
            headers.insert(
                "X-RateLimit-Reset".to_string(),
                result.reset_time.timestamp().to_string(),
            );
        }

        headers
    }

    /// Get the inner middleware
    pub fn inner(&self) -> &RateLimitMiddleware {
        &self.inner
    }
}

impl Default for RateLimitMiddlewareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_rules: HashMap::new(),
            custom_headers: HashMap::new(),
            response_headers: true,
            logging_enabled: true,
            metrics_enabled: true,
            cache_headers: true,
            bypass_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/status".to_string(),
            ],
            bypass_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_middleware_config_default() {
        let config = RateLimitMiddlewareConfig::default();
        assert!(config.enabled);
        assert!(config.response_headers);
        assert!(config.logging_enabled);
        assert!(config.metrics_enabled);
        assert!(config.cache_headers);
        assert_eq!(config.bypass_paths.len(), 3);
        assert_eq!(config.bypass_ips.len(), 2);
    }

    #[test]
    fn test_generate_request_id() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();

        assert_ne!(id1, id2);
        assert!(id1.starts_with("req-"));
        assert!(id2.starts_with("req-"));
    }

    #[test]
    fn test_http_request_creation() {
        let mut headers = HashMap::new();
        headers.insert("X-User-ID".to_string(), "user123".to_string());
        headers.insert("X-API-Key".to_string(), "key456".to_string());

        let mut query_params = HashMap::new();
        query_params.insert("param1".to_string(), "value1".to_string());

        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers,
            query_params,
            body: None,
            remote_addr: "192.168.1.1".to_string(),
            timestamp: Utc::now(),
        };

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/test");
        assert_eq!(request.remote_addr, "192.168.1.1");
        assert_eq!(
            request.headers.get("X-User-ID"),
            Some(&"user123".to_string())
        );
        assert_eq!(
            request.headers.get("X-API-Key"),
            Some(&"key456".to_string())
        );
    }

    #[test]
    fn test_should_bypass() {
        let config = RateLimitMiddlewareConfig::default();
        let middleware = RateLimitMiddleware::new(
            crate::rate_limit::RateLimitManager::new(crate::rate_limit::RateLimitConfig::default()),
            config,
        );

        // Test bypass path
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/health".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            remote_addr: "192.168.1.1".to_string(),
            timestamp: Utc::now(),
        };

        assert!(middleware.should_bypass(&request));

        // Test bypass IP
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            remote_addr: "127.0.0.1".to_string(),
            timestamp: Utc::now(),
        };

        assert!(middleware.should_bypass(&request));

        // Test non-bypass
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            remote_addr: "192.168.1.100".to_string(),
            timestamp: Utc::now(),
        };

        assert!(!middleware.should_bypass(&request));
    }

    #[test]
    fn test_create_context() {
        let config = RateLimitMiddlewareConfig::default();
        let middleware = RateLimitMiddleware::new(
            crate::rate_limit::RateLimitManager::new(crate::rate_limit::RateLimitConfig::default()),
            config,
        );

        let mut headers = HashMap::new();
        headers.insert("X-User-ID".to_string(), "user123".to_string());
        headers.insert("X-API-Key".to_string(), "key456".to_string());
        headers.insert("Authorization".to_string(), "Bearer token789".to_string());
        headers.insert("X-Custom".to_string(), "custom_value".to_string());

        let mut query_params = HashMap::new();
        query_params.insert("param1".to_string(), "value1".to_string());

        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/api/test".to_string(),
            headers,
            query_params,
            body: None,
            remote_addr: "192.168.1.1".to_string(),
            timestamp: Utc::now(),
        };

        let context = middleware.create_context(&request);

        assert_eq!(context.ip_address, "192.168.1.1");
        assert_eq!(context.user_id, Some("user123".to_string()));
        assert_eq!(context.api_key, Some("key456".to_string()));
        assert_eq!(context.token, Some("Bearer token789".to_string()));
        assert_eq!(context.path, "/api/test");
        assert_eq!(context.method, "POST");

        // Check metadata
        assert!(context.metadata.contains_key("param1"));
        assert_eq!(
            context.metadata.get("param1").unwrap(),
            &serde_json::Value::String("value1".to_string())
        );
        assert!(context.metadata.contains_key("X-Custom"));
        assert_eq!(
            context.metadata.get("X-Custom").unwrap(),
            &serde_json::Value::String("custom_value".to_string())
        );
    }

    #[test]
    fn test_web_rate_limit_middleware() {
        let manager =
            crate::rate_limit::RateLimitManager::new(crate::rate_limit::RateLimitConfig::default());
        let config = RateLimitMiddlewareConfig::default();
        let middleware = WebRateLimitMiddleware::new(manager, config);

        // Test that inner middleware is accessible
        assert_eq!(middleware.inner().name(), "rate_limit");
    }

    #[test]
    fn test_http_rate_limit_middleware() {
        let manager =
            crate::rate_limit::RateLimitManager::new(crate::rate_limit::RateLimitConfig::default());
        let config = RateLimitMiddlewareConfig::default();
        let middleware = HttpRateLimitMiddleware::new(manager, config);

        // Test that inner middleware is accessible
        assert_eq!(middleware.inner().name(), "rate_limit");
    }
}
