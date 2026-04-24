//! Rate Limiting Middleware
//! 
//! This module provides Axum middleware for rate limiting with
//! comprehensive request analysis and response handling.

use std::sync::Arc;
use std::time::Instant;
use axum::{
    extract::{Request, State},
    http::{StatusCode, HeaderMap, HeaderValue},
    response::{Response, IntoResponse},
    Json,
};
use tower::{Layer, Service};
use tower_http::classify::SharedClassifier;
use serde_json::{json, Value};
use chrono::{DateTime, Utc, Duration};
use crate::error::{FortressError, Result};
use super::{
    ProductionRateLimiter, ProductionRateLimitConfig, RateLimitRequest, RateLimitResponse,
    RateLimitAction, ThreatLevel, GeoLocation
};
use async_trait::async_trait;

/// Rate limiting middleware configuration
#[derive(Debug, Clone)]
pub struct RateLimitMiddlewareConfig {
    /// Rate limiter instance
    pub rate_limiter: Arc<dyn ProductionRateLimiter>,
    /// Whether to extract geographic information
    pub geo_extraction_enabled: bool,
    /// Whether to extract device fingerprint
    pub device_fingerprinting_enabled: bool,
    /// Custom headers to extract
    pub custom_headers: Vec<String>,
    /// Paths to exclude from rate limiting
    pub excluded_paths: Vec<String>,
    /// Methods to exclude from rate limiting
    pub excluded_methods: Vec<String>,
    /// Whether to add rate limit headers to responses
    pub add_rate_limit_headers: bool,
    /// Whether to log rate limit violations
    pub log_violations: bool,
}

/// Rate limiting middleware service
pub struct RateLimitMiddlewareService<S> {
    inner: S,
    config: RateLimitMiddlewareConfig,
}

/// Rate limiting middleware layer
pub type RateLimitMiddlewareLayer = Layer<RateLimitMiddlewareService<axum::routing::Route>, axum::routing::Route>;

/// Rate limit error response
#[derive(Debug)]
pub struct RateLimitError {
    /// Response from rate limiter
    pub response: RateLimitResponse,
    /// Request context
    pub request: RateLimitRequest,
}

impl RateLimitMiddlewareConfig {
    /// Create a new middleware configuration
    pub fn new(rate_limiter: Arc<dyn ProductionRateLimiter>) -> Self {
        Self {
            rate_limiter,
            geo_extraction_enabled: true,
            device_fingerprinting_enabled: true,
            custom_headers: Vec::new(),
            excluded_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/favicon.ico".to_string(),
            ],
            excluded_methods: vec!["OPTIONS".to_string()],
            add_rate_limit_headers: true,
            log_violations: true,
        }
    }
}

impl<S> RateLimitMiddlewareService<S> {
    /// Create a new rate limiting middleware service
    pub fn new(inner: S, config: RateLimitMiddlewareConfig) -> Self {
        Self { inner, config }
    }

    /// Extract IP address from request
    fn extract_ip_address(&self, headers: &HeaderMap) -> String {
        // Check for common IP headers
        let ip_headers = [
            "x-forwarded-for",
            "x-real-ip",
            "cf-connecting-ip",
            "x-client-ip",
        ];

        for header_name in &ip_headers {
            if let Some(header_value) = headers.get(header_name) {
                if let Ok(ip_str) = header_value.to_str() {
                    // X-Forwarded-For can contain multiple IPs, take the first one
                    let ip = ip_str.split(',').next().unwrap_or(ip_str).trim();
                    if !ip.is_empty() {
                        return ip.to_string();
                    }
                }
            }
        }

        // Fallback to remote address (would be available in real implementation)
        "127.0.0.1".to_string()
    }

    /// Extract user agent from request
    fn extract_user_agent(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Extract API key from request
    fn extract_api_key(&self, headers: &HeaderMap) -> Option<String> {
        // Check Authorization header for Bearer token
        if let Some(auth_header) = headers.get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = auth_str.trim_start_matches("Bearer ");
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }

        // Check for X-API-Key header
        if let Some(api_key_header) = headers.get("x-api-key") {
            if let Ok(api_key) = api_key_header.to_str() {
                return Some(api_key.to_string());
            }
        }

        None
    }

    /// Extract user ID from request (would come from JWT/auth middleware)
    fn extract_user_id(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get("x-user-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Extract geographic information
    fn extract_geo_location(&self, headers: &HeaderMap) -> Option<GeoLocation> {
        if !self.config.geo_extraction_enabled {
            return None;
        }

        // Check for Cloudflare country header
        if let Some(country_header) = headers.get("cf-ipcountry") {
            if let Ok(country) = country_header.to_str() {
                return Some(GeoLocation {
                    country: country.to_string(),
                    region: None,
                    city: None,
                    latitude: None,
                    longitude: None,
                    isp: None,
                    asn: None,
                });
            }
        }

        // Check for custom geo headers
        if let Some(geo_header) = headers.get("x-geo-location") {
            if let Ok(geo_str) = geo_header.to_str() {
                // Parse JSON geo location if available
                if let Ok(geo_json) = serde_json::from_str::<Value>(geo_str) {
                    return Some(GeoLocation {
                        country: geo_json.get("country")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        region: geo_json.get("region")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        city: geo_json.get("city")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        latitude: geo_json.get("latitude")
                            .and_then(|v| v.as_f64()),
                        longitude: geo_json.get("longitude")
                            .and_then(|v| v.as_f64()),
                        isp: geo_json.get("isp")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        asn: geo_json.get("asn")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as u32),
                    });
                }
            }
        }

        None
    }

    /// Extract device fingerprint
    fn extract_device_fingerprint(&self, headers: &HeaderMap) -> Option<String> {
        if !self.config.device_fingerprinting_enabled {
            return None;
        }

        // Simple fingerprinting based on headers
        let mut fingerprint_parts = Vec::new();

        // User agent
        if let Some(ua) = self.extract_user_agent(headers) {
            fingerprint_parts.push(format!("ua:{}", ua));
        }

        // Accept-Language
        if let Some(lang) = headers.get("accept-language").and_then(|h| h.to_str().ok()) {
            fingerprint_parts.push(format!("lang:{}", lang));
        }

        // Accept-Encoding
        if let Some(encoding) = headers.get("accept-encoding").and_then(|h| h.to_str().ok()) {
            fingerprint_parts.push(format!("enc:{}", encoding));
        }

        if !fingerprint_parts.is_empty() {
            let fingerprint = fingerprint_parts.join("|");
            // Create a simple hash (in real implementation, use proper hashing)
            let hash = format!("{:x}", fingerprint.len() * 31);
            Some(hash)
        } else {
            None
        }
    }

    /// Extract custom headers
    fn extract_custom_headers(&self, headers: &HeaderMap) -> std::collections::HashMap<String, String> {
        let mut custom_headers = std::collections::HashMap::new();

        for header_name in &self.config.custom_headers {
            if let Some(header_value) = headers.get(header_name) {
                if let Ok(value) = header_value.to_str() {
                    custom_headers.insert(header_name.clone(), value.to_string());
                }
            }
        }

        custom_headers
    }

    /// Check if request should be excluded from rate limiting
    fn should_exclude_request(&self, path: &str, method: &str) -> bool {
        self.config.excluded_paths.iter().any(|exclude_path| {
            path.starts_with(exclude_path) || path == exclude_path
        }) || self.config.excluded_methods.iter().any(|exclude_method| {
            method == exclude_method
        })
    }

    /// Create rate limit request from HTTP request
    async fn create_rate_limit_request(
        &self,
        request: &Request<axum::body::Body>,
        headers: &HeaderMap,
        path: &str,
        method: &str,
    ) -> RateLimitRequest {
        let ip = self.extract_ip_address(headers);
        let user_id = self.extract_user_id(headers);
        let api_key = self.extract_api_key(headers);
        let user_agent = self.extract_user_agent(headers);
        let geo_location = self.extract_geo_location(headers);
        let device_fingerprint = self.extract_device_fingerprint(headers);
        let custom_headers = self.extract_custom_headers(headers);

        RateLimitRequest {
            request_id: format!("{}-{}", Utc::now().timestamp_millis(), ip_address),
            ip_address,
            user_id,
            api_key,
            path: path.to_string(),
            method: method.to_string(),
            user_agent,
            headers: headers.iter()
                .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.to_string(), v.to_string())))
                .collect(),
            timestamp: Utc::now(),
            request_size: 0, // Would be extracted from request body in real implementation
            geo_location,
            device_fingerprint,
            metadata: {
                let mut metadata = std::collections::HashMap::new();
                for (key, value) in custom_headers {
                    metadata.insert(key, serde_json::Value::String(value));
                }
                metadata
            },
        }
    }

    /// Add rate limit headers to response
    fn add_rate_limit_headers(&self, response: Response, rate_limit_response: &RateLimitResponse) -> Response {
        if !self.config.add_rate_limit_headers {
            return response;
        }

        let mut response = response;
        let headers = response.headers_mut();

        // Add standard rate limit headers
        if let Ok(limit_value) = HeaderValue::from_str(&rate_limit_response.limit.to_string()) {
            headers.insert("X-RateLimit-Limit", limit_value);
        }

        if let Ok(remaining_value) = HeaderValue::from_str(&rate_limit_response.remaining.to_string()) {
            headers.insert("X-RateLimit-Remaining", remaining_value);
        }

        if let Ok(reset_value) = HeaderValue::from_str(&rate_limit_response.reset_time.timestamp().to_string()) {
            headers.insert("X-RateLimit-Reset", reset_value);
        }

        if let Some(retry_after) = rate_limit_response.retry_after {
            if let Ok(retry_value) = HeaderValue::from_str(&retry_after.num_seconds().to_string()) {
                headers.insert("Retry-After", retry_value);
            }
        }

        // Add custom headers for threat level and action
        if let Ok(threat_value) = HeaderValue::from_str(&format!("{:?}", rate_limit_response.threat_level)) {
            headers.insert("X-RateLimit-Threat-Level", threat_value);
        }

        if let Ok(action_value) = HeaderValue::from_str(&format!("{:?}", rate_limit_response.action)) {
            headers.insert("X-RateLimit-Action", action_value);
        }

        response
    }

    /// Create error response for rate limit violation
    fn create_rate_limit_error_response(&self, rate_limit_response: &RateLimitResponse) -> Response {
        let status_code = match rate_limit_response.action {
            RateLimitAction::Reject => StatusCode::TOO_MANY_REQUESTS,
            RateLimitAction::Throttle => StatusCode::TOO_MANY_REQUESTS,
            RateLimitAction::TemporaryBlock => StatusCode::SERVICE_UNAVAILABLE,
            RateLimitAction::Escalate => StatusCode::SERVICE_UNAVAILABLE,
            RateLimitAction::Monitor => StatusCode::OK,
        };

        let error_body = json!({
            "error": {
                "type": "rate_limit_exceeded",
                "message": rate_limit_response.reason,
                "code": "RATE_LIMIT_EXCEEDED",
                "details": {
                    "limit": rate_limit_response.limit,
                    "remaining": rate_limit_response.remaining,
                    "reset_time": rate_limit_response.reset_time,
                    "retry_after": rate_limit_response.retry_after,
                    "action": format!("{:?}", rate_limit_response.action),
                    "threat_level": format!("{:?}", rate_limit_response.threat_level),
                    "violation_count": rate_limit_response.violation_count,
                }
            }
        });

        let mut response = (status_code, Json(error_body)).into_response();
        self.add_rate_limit_headers(response, rate_limit_response)
    }

    /// Log rate limit violation
    fn log_violation(&self, request: &RateLimitRequest, response: &RateLimitResponse) {
        if !self.config.log_violations {
            return;
        }

        let log_level = match response.threat_level {
            ThreatLevel::None => "info",
            ThreatLevel::Low => "warn",
            ThreatLevel::Medium => "warn",
            ThreatLevel::High => "error",
            ThreatLevel::Critical => "error",
        };

        tracing::event!(
            target: "rate_limiter",
            log_level,
            request_id = %request.request_id,
            ip_address = %request.ip_address,
            user_id = ?request.user_id,
            path = %request.path,
            method = %request.method,
            threat_level = ?response.threat_level,
            action = ?response.action,
            reason = %response.reason,
            violation_count = response.violation_count,
        );
    }
}

impl<S> Service<Request<axum::body::Body>> for RateLimitMiddlewareService<S>
where
    S: Service<Request<axum::body::Body>> + Clone + Send + 'static,
    S::Response: IntoResponse,
{
    type Response = axum::response::Response;
    type Error = S::Error;

    fn call(&self, request: Request<axum::body::Body>) -> Result<Self::Response, Self::Error> {
        let start_time = Instant::now();
        
        // Extract request information
        let path = request.uri().path();
        let method = request.method().as_str();
        let headers = request.headers();

        // Check if request should be excluded
        if self.should_exclude_request(path, method) {
            return self.inner.call(request);
        }

        // Create rate limit request
        let rate_limit_request = self.create_rate_limit_request(&request, headers, path, method);

        // Check rate limit
        let rate_limit_response = self.config.rate_limiter.check_rate_limit(&rate_limit_request)
            .map_err(|e| FortressError::rate_limit(
                format!("Rate limit check failed: {}", e),
                None,
                None,
            ))?;

        match rate_limit_response {
            Ok(response) => {
                let processing_time = start_time.elapsed();

                if response.allowed {
                    // Request allowed, continue with inner service
                    let mut inner_response = self.inner.call(request)?;
                    
                    // Add rate limit headers to successful response
                    inner_response = self.add_rate_limit_headers(inner_response, &response);
                    
                    Ok(inner_response)
                } else {
                    // Request blocked, return rate limit error
                    self.log_violation(&rate_limit_request, &response);
                    
                    Err(axum::Error::new(RateLimitError {
                        response,
                        request: rate_limit_request,
                    }))
                }
            }
            Err(e) => {
                tracing::error!("Rate limiting error: {}", e);
                
                // On rate limiter error, allow request but log the error
                self.inner.call(request)
            }
        }
    }
}

impl<S> Clone for RateLimitMiddlewareService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
        }
    }
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> axum::response::Response {
        // This would be handled by the middleware service
        // This is a fallback implementation
        let error_body = json!({
            "error": {
                "type": "rate_limit_exceeded",
                "message": self.response.reason,
                "code": "RATE_LIMIT_EXCEEDED",
            }
        });

        (StatusCode::TOO_MANY_REQUESTS, Json(error_body)).into_response()
    }
}

/// Create rate limiting middleware layer
pub fn rate_limit_middleware(config: RateLimitMiddlewareConfig) -> RateLimitMiddlewareLayer {
    // Use tower's ServiceBuilder to create the middleware
    Layer::new(move |inner| RateLimitMiddlewareService::new(inner, config.clone()))
}

/// Convenience function to create rate limiting middleware with default config
pub fn rate_limit(rate_limiter: Arc<dyn ProductionRateLimiter>) -> RateLimitMiddlewareLayer {
    rate_limit_middleware(RateLimitMiddlewareConfig::new(rate_limiter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, HeaderMap, StatusCode},
        response::Response,
    };
    use tower::Service;

    #[test]
    fn test_ip_extraction() {
        let config = RateLimitMiddlewareConfig::new(
            Arc::new(crate::security::rate_limiter::token_bucket::ProductionTokenBucket::new(
                crate::security::rate_limiter::ProductionRateLimitConfig::default()
            ))
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.1".parse().unwrap());
        
        let ip = config.extract_ip_address(&headers);
        assert_eq!(ip, "192.168.1.1");
    }

    #[test]
    fn test_api_key_extraction() {
        let config = RateLimitMiddlewareConfig::new(
            Arc::new(crate::security::rate_limiter::token_bucket::ProductionTokenBucket::new(
                crate::security::rate_limiter::ProductionRateLimitConfig::default()
            ))
        );

        // Test Bearer token
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-api-key-123".parse().unwrap());
        
        let api_key = config.extract_api_key(&headers);
        assert_eq!(api_key, Some("test-api-key-123".to_string()));

        // Test X-API-Key header
        let mut headers2 = HeaderMap::new();
        headers2.insert("x-api-key", "test-api-key-456".parse().unwrap());
        
        let api_key2 = config.extract_api_key(&headers2);
        assert_eq!(api_key2, Some("test-api-key-456".to_string()));
    }

    #[test]
    fn test_exclusion_logic() {
        let config = RateLimitMiddlewareConfig::new(
            Arc::new(crate::security::rate_limiter::token_bucket::ProductionTokenBucket::new(
                crate::security::rate_limiter::ProductionRateLimitConfig::default()
            ))
        );

        // Test path exclusion
        assert!(config.should_exclude_request("/health", "GET"));
        assert!(config.should_exclude_request("/api/v1/users", "GET"));
        assert!(!config.should_exclude_request("/api/v1/data", "GET"));

        // Test method exclusion
        assert!(config.should_exclude_request("/api/v1/data", "OPTIONS"));
        assert!(!config.should_exclude_request("/api/v1/data", "POST"));
    }

    #[test]
    fn test_geo_location_extraction() {
        let config = RateLimitMiddlewareConfig::new(
            Arc::new(crate::security::rate_limiter::token_bucket::ProductionTokenBucket::new(
                crate::security::rate_limiter::ProductionRateLimitConfig::default()
            ))
        );

        // Test Cloudflare country header
        let mut headers = HeaderMap::new();
        headers.insert("cf-ipcountry", "US".parse().unwrap());
        
        let geo = config.extract_geo_location(&headers);
        assert!(geo.is_some());
        assert_eq!(geo.unwrap().country, "US");
    }

    #[test]
    fn test_device_fingerprinting() {
        let config = RateLimitMiddlewareConfig::new(
            Arc::new(crate::security::rate_limiter::token_bucket::ProductionTokenBucket::new(
                crate::security::rate_limiter::ProductionRateLimitConfig::default()
            ))
        );

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".parse().unwrap());
        headers.insert("accept-language", "en-US,en;q=0.9".parse().unwrap());
        
        let fingerprint = config.extract_device_fingerprint(&headers);
        assert!(fingerprint.is_some());
        assert!(!fingerprint.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_rate_limit_request_creation() {
        let config = RateLimitMiddlewareConfig::new(
            Arc::new(crate::security::rate_limiter::token_bucket::ProductionTokenBucket::new(
                crate::security::rate_limiter::ProductionRateLimitConfig::default()
            ))
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
        headers.insert("user-agent", "test-agent".parse().unwrap());

        let request = Request::builder()
            .uri("/api/test")
            .method("POST")
            .header("x-forwarded-for", "192.168.1.100")
            .header("user-agent", "test-agent")
            .body(Body::empty())
            .unwrap();

        let rate_limit_request = config.create_rate_limit_request(&request, &headers, "/api/test", "POST").await;

        assert_eq!(rate_limit_request.ip_address, "192.168.1.100");
        assert_eq!(rate_limit_request.path, "/api/test");
        assert_eq!(rate_limit_request.method, "POST");
        assert_eq!(rate_limit_request.user_agent, Some("test-agent".to_string()));
    }
}
