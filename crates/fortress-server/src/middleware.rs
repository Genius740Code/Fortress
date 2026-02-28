//! HTTP middleware for the Fortress server
//!
//! This module provides various middleware components for request processing,
//! including logging, rate limiting, CORS, and request validation.

use crate::auth::TokenClaims;
use crate::config::{NetworkConfig, RateLimitConfig};
use crate::error::{ServerError, ServerResult};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tower::Layer;
use tower_http::{
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{info, warn, error};

/// Rate limiter middleware
#[derive(Clone)]
pub struct RateLimiter {
    /// Rate limit configuration
    config: RateLimitConfig,
    /// In-memory rate limit storage (for development)
    /// In production, use Redis or similar distributed storage
    storage: Arc<RwLock<HashMap<String, RateLimitInfo>>>,
}

/// Rate limit information for a client
#[derive(Clone, Debug)]
struct RateLimitInfo {
    /// Requests per minute counter
    per_minute: u32,
    /// Requests per hour counter
    per_hour: u32,
    /// Last minute reset
    last_minute_reset: Instant,
    /// Last hour reset
    last_hour_reset: Instant,
    /// Burst tokens
    burst_tokens: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a request is allowed
    pub async fn check_rate_limit(&self, client_id: &str) -> ServerResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut storage = self.storage.write().await;
        let now = Instant::now();
        
        let info = storage.entry(client_id.to_string()).or_insert_with(|| RateLimitInfo {
            per_minute: 0,
            per_hour: 0,
            last_minute_reset: now,
            last_hour_reset: now,
            burst_tokens: self.config.burst_size,
        });

        // Reset counters if needed
        if now.duration_since(info.last_minute_reset) >= Duration::from_secs(60) {
            info.per_minute = 0;
            info.last_minute_reset = now;
            info.burst_tokens = self.config.burst_size;
        }

        if now.duration_since(info.last_hour_reset) >= Duration::from_secs(3600) {
            info.per_hour = 0;
            info.last_hour_reset = now;
        }

        // Check limits
        if info.per_minute >= self.config.requests_per_minute {
            return Err(ServerError::RateLimit);
        }

        if info.per_hour >= self.config.requests_per_hour {
            return Err(ServerError::RateLimit);
        }

        // Check burst limit
        if info.burst_tokens == 0 {
            return Err(ServerError::RateLimit);
        }

        // Increment counters
        info.per_minute += 1;
        info.per_hour += 1;
        info.burst_tokens = info.burst_tokens.saturating_sub(1);

        Ok(())
    }

    /// Get rate limit headers for a client
    pub async fn get_rate_limit_headers(&self, client_id: &str) -> Option<(HeaderValue, HeaderValue, HeaderValue)> {
        if !self.config.enabled {
            return None;
        }

        let storage = self.storage.read().await;
        if let Some(info) = storage.get(client_id) {
            let remaining = std::cmp::min(
                self.config.requests_per_minute - info.per_minute,
                info.burst_tokens,
            );
            
            let reset_time = info.last_minute_reset + Duration::from_secs(60);
            let reset_timestamp = reset_time.duration_since(Instant::now()).as_secs();

            Some((
                HeaderValue::from_str(&remaining.to_string()).ok()?,
                HeaderValue::from_str(&self.config.requests_per_minute.to_string()).ok()?,
                HeaderValue::from_str(&reset_timestamp.to_string()).ok()?,
            ))
        } else {
            None
        }
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(rate_limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract client ID (IP address or authenticated user)
    let client_id = extract_client_id(&request);
    
    // Check rate limit
    match rate_limiter.check_rate_limit(&client_id).await {
        Ok(()) => {
            let mut response = next.run(request).await;
            
            // Add rate limit headers
            if let Some((remaining, limit, reset)) = rate_limiter.get_rate_limit_headers(&client_id).await {
                response.headers_mut().insert("X-RateLimit-Remaining", remaining);
                response.headers_mut().insert("X-RateLimit-Limit", limit);
                response.headers_mut().insert("X-RateLimit-Reset", reset);
            }
            
            Ok(response)
        }
        Err(ServerError::RateLimit) => {
            warn!(
                client_id = %client_id,
                "Rate limit exceeded"
            );
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Request logging middleware
pub async fn request_logging_middleware(
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    // Extract user info if authenticated
    let user_id = request
        .extensions()
        .get::<TokenClaims>()
        .map(|claims| claims.sub.clone());

    let response = next.run(request).await;
    
    let duration = start.elapsed();
    let status = response.status();
    
    if status.is_server_error() {
        error!(
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = duration.as_millis(),
            user_agent = %user_agent,
            user_id = ?user_id,
            "Request completed with server error"
        );
    } else if status.is_client_error() {
        warn!(
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = duration.as_millis(),
            user_agent = %user_agent,
            user_id = ?user_id,
            "Request completed with client error"
        );
    } else {
        info!(
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = duration.as_millis(),
            user_agent = %user_agent,
            user_id = ?user_id,
            "Request completed successfully"
        );
    }

    response
}

/// Request size limiting middleware
pub async fn request_size_middleware(
    State(network_config): State<NetworkConfig>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check content length if available
    if let Some(content_length) = request.headers().get(header::CONTENT_LENGTH) {
        if let Ok(length) = content_length.to_str() {
            if let Ok(size) = length.parse::<usize>() {
                if size > network_config.max_body_size {
                    warn!(
                        request_size = size,
                        max_size = network_config.max_body_size,
                        "Request payload too large"
                    );
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }
    }

    Ok(next.run(request).await)
}

/// Tenant isolation middleware
pub async fn tenant_isolation_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract tenant from JWT claims or request headers
    let tenant_id = request
        .extensions()
        .get::<TokenClaims>()
        .and_then(|claims| claims.tenant_id.clone())
        .or_else(|| {
            request
                .headers()
                .get("X-Tenant-ID")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        });

    // Add tenant ID to request extensions for handlers to use
    if let Some(tenant_id) = tenant_id {
        let mut request = request;
        request.extensions_mut().insert(tenant_id);
        return Ok(next.run(request).await);
    }

    // If no tenant ID and multi-tenant is enabled, this is an error
    // For single-tenant mode, this is fine
    Ok(next.run(request).await)
}

/// Security headers middleware
pub async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    
    // Security headers
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    headers.insert("Strict-Transport-Security", HeaderValue::from_static("max-age=31536000; includeSubDomains"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert("Content-Security-Policy", HeaderValue::from_static("default-src 'self'"));
    
    response
}

/// Create CORS layer
pub fn create_cors_layer(config: &crate::config::CorsConfig) -> CorsLayer {
    let origins: Vec<_> = config.allowed_origins.iter().map(|s| s.as_str()).collect::<Vec<_>>();
    let methods: Vec<_> = config.allowed_methods.iter().map(|s| s.as_str()).collect::<Vec<_>>();
    let headers: Vec<_> = config.allowed_headers.iter().map(|s| s.as_str()).collect::<Vec<_>>();

    CorsLayer::new()
        .allow_origin(origins.into_iter().map(|s| s.parse().unwrap()).collect::<Vec<_>>())
        .allow_methods(methods.into_iter().map(|s| s.parse().unwrap()).collect::<Vec<_>>())
        .allow_headers(headers.into_iter().map(|s| s.parse().unwrap()).collect::<Vec<_>>())
        .allow_credentials(config.allow_credentials)
}

/// Create timeout layer
pub fn create_timeout_layer(timeout_seconds: u64) -> TimeoutLayer {
    TimeoutLayer::new(Duration::from_secs(timeout_seconds))
}

/// Create trace layer
pub fn create_trace_layer() -> TraceLayer {
    TraceLayer::new_for_http()
        .make_span_with(|request: &Request<_>| {
            tracing::info_span!(
                "http_request",
                method = %request.method(),
                uri = %request.uri(),
                version = ?request.version(),
            )
        })
        .on_request(|_request: &Request<_>, _span: &tracing::Span| {
            tracing::info!("started processing request");
        })
        .on_response(|_response: &Response<_>, latency: Duration, _span: &tracing::Span| {
            tracing::info!("finished processing request in {:?}", latency);
        })
}

/// Extract client ID from request
fn extract_client_id(request: &Request) -> String {
    // Try to get user ID from JWT claims first
    if let Some(claims) = request.extensions().get::<TokenClaims>() {
        return format!("user:{}", claims.sub);
    }

    // Fall back to IP address
    request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| format!("ip:{}", s.trim()))
        .or_else(|| {
            request
                .headers()
                .get("X-Real-IP")
                .and_then(|h| h.to_str().ok())
                .map(|s| format!("ip:{}", s))
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Middleware stack builder
pub struct MiddlewareStack {
    layers: Vec<Box<dyn Layer<Body> + Send + Sync>>,
}

impl MiddlewareStack {
    /// Create a new middleware stack
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
        }
    }

    /// Add a layer to the stack
    pub fn add_layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Body> + Send + Sync + 'static,
    {
        self.layers.push(Box::new(layer));
        self
    }

    /// Build the middleware stack
    pub fn build(self) -> Vec<Box<dyn Layer<Body> + Send + Sync>> {
        self.layers
    }
}

impl Default for MiddlewareStack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Empty;
    use axum::http::Method;

    #[test]
    fn test_client_id_extraction() {
        // Test with user claims
        let claims = TokenClaims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            email: None,
            roles: vec![],
            tenant_id: None,
            iat: 0,
            exp: 0,
            jti: "test".to_string(),
        };

        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Empty::new())
            .unwrap();

        request.extensions_mut().insert(claims);
        
        let client_id = extract_client_id(&request);
        assert_eq!(client_id, "user:user123");
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_minute: 2,
            requests_per_hour: 10,
            burst_size: 2,
        };

        let rate_limiter = RateLimiter::new(config);
        
        // First request should succeed
        rate_limiter.check_rate_limit("client1").await.unwrap();
        
        // Second request should succeed
        rate_limiter.check_rate_limit("client1").await.unwrap();
        
        // Third request should fail
        assert!(matches!(
            rate_limiter.check_rate_limit("client1").await,
            Err(ServerError::RateLimit)
        ));
    }

    #[test]
    fn test_cors_layer_creation() {
        let config = crate::config::CorsConfig::default();
        let cors_layer = create_cors_layer(&config);
        // Just test that it doesn't panic
        assert!(true);
    }
}
