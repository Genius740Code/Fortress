//! Advanced rate limiting and DDoS protection for Fortress
//!
//! This module provides production-ready rate limiting with multiple algorithms,
//! distributed storage support, and comprehensive DDoS protection mechanisms.

use crate::config::{NetworkConfig, RateLimitConfig, RateLimitAlgorithm};
use crate::error::{ServerError, ServerResult};
use crate::auth::TokenClaims;
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower_http::{
    cors::CorsLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tower_http::classify::{SharedClassifier, ServerErrorsAsFailures};
use tracing::{info, warn, error};

/// Advanced rate limiter with multiple algorithms and DDoS protection
#[derive(Clone)]
pub struct AdvancedRateLimiter {
    /// Rate limit configuration
    config: RateLimitConfig,
    /// Algorithm to use
    algorithm: RateLimitAlgorithm,
    /// In-memory storage for development/single-instance
    /// In production, use Redis or similar distributed storage
    token_bucket_storage: Arc<DashMap<String, TokenBucketState>>,
    sliding_window_storage: Arc<DashMap<String, SlidingWindowState>>,
    fixed_window_storage: Arc<DashMap<String, FixedWindowState>>,
    leaky_bucket_storage: Arc<DashMap<String, LeakyBucketState>>,
    /// DDoS detection and protection
    ddos_protection: Arc<DdosProtection>,
    /// Metrics
    metrics: Arc<RateLimitMetrics>,
}

/// Token bucket state
#[derive(Clone, Debug)]
struct TokenBucketState {
    /// Current number of tokens
    tokens: u32,
    /// Last refill timestamp
    last_refill: Instant,
    /// Burst capacity
    burst_capacity: u32,
}

/// Sliding window state
#[derive(Clone, Debug)]
struct SlidingWindowState {
    /// Request timestamps in the current window
    request_timestamps: Vec<Instant>,
    /// Window size
    window_size: Duration,
}

/// Fixed window state
#[derive(Clone, Debug)]
struct FixedWindowState {
    /// Request count in current window
    request_count: u32,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
}

/// Leaky bucket state
#[derive(Clone, Debug)]
struct LeakyBucketState {
    /// Current queue size
    queue_size: u32,
    /// Last leak timestamp
    last_leak: Instant,
    /// Maximum queue size
    max_queue_size: u32,
    /// Leak rate per second
    leak_rate: u32,
}

/// DDoS protection mechanisms
#[derive(Clone)]
struct DdosProtection {
    /// Suspicious IP tracking
    suspicious_ips: Arc<DashMap<String, SuspiciousIpInfo>>,
    /// Global request tracking
    global_requests: Arc<DashMap<Instant, u32>>,
    /// Configuration
    config: DdosConfig,
}

/// Suspicious IP information
#[derive(Clone, Debug)]
struct SuspiciousIpInfo {
    /// Request count in last minute
    requests_per_minute: u32,
    /// Failed requests count
    failed_requests: u32,
    /// Last activity timestamp
    last_activity: Instant,
    /// Reputation score (0-100)
    reputation_score: u8,
    /// Is currently blocked
    blocked: bool,
    /// Block expiry time
    block_expiry: Option<Instant>,
}

/// DDoS protection configuration
#[derive(Debug, Clone)]
struct DdosConfig {
    /// Enable DDoS protection
    enabled: bool,
    /// Global requests per second threshold
    global_rps_threshold: u32,
    /// IP requests per second threshold
    ip_rps_threshold: u32,
    /// Auto-block threshold
    auto_block_threshold: u32,
    /// Block duration
    block_duration: Duration,
    /// Reputation decay rate per hour
    reputation_decay_rate: u8,
}

/// Rate limiting metrics
#[derive(Clone, Debug)]
struct RateLimitMetrics {
    /// Total requests processed
    total_requests: Arc<std::sync::atomic::AtomicU64>,
    /// Requests allowed
    allowed_requests: Arc<std::sync::atomic::AtomicU64>,
    /// Requests blocked
    blocked_requests: Arc<std::sync::atomic::AtomicU64>,
    /// DDoS blocks
    ddos_blocks: Arc<std::sync::atomic::AtomicU64>,
}

/// Rate limiting metrics snapshot
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitMetricsSnapshot {
    /// Total requests processed
    pub total_requests: u64,
    /// Requests allowed
    pub allowed_requests: u64,
    /// Requests blocked
    pub blocked_requests: u64,
    /// DDoS blocks
    pub ddos_blocks: u64,
}

impl RateLimitMetrics {
    fn new() -> Self {
        Self {
            total_requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            allowed_requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocked_requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ddos_blocks: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl DdosProtection {
    fn new(config: DdosConfig) -> Self {
        Self {
            suspicious_ips: Arc::new(DashMap::new()),
            global_requests: Arc::new(DashMap::new()),
            config,
        }
    }

    async fn check_ddos_protection(&self, client_id: &str) -> ServerResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let now = Instant::now();
        let ip = self.extract_ip_from_client_id(client_id);

        // Check if IP is currently blocked
        if let Some(ip_info) = self.suspicious_ips.get(&ip) {
            if ip_info.blocked {
                if let Some(expiry) = ip_info.block_expiry {
                    if now < expiry {
                        warn!(
                            ip = %ip,
                            expiry = ?expiry,
                            "Blocked IP attempted request"
                        );
                        return Err(ServerError::DdosBlocked);
                    } else {
                        // Block expired, unblock
                        let mut info = ip_info.clone();
                        info.blocked = false;
                        info.block_expiry = None;
                        self.suspicious_ips.insert(ip.clone(), info);
                    }
                }
            }
        }

        // Check global request rate
        self.cleanup_global_requests(now);
        let current_rps = self.global_requests.iter().map(|entry| *entry.value()).sum::<u32>();
        
        if current_rps > self.config.global_rps_threshold {
            warn!(
                current_rps = current_rps,
                threshold = self.config.global_rps_threshold,
                "Global request rate threshold exceeded"
            );
            return Err(ServerError::DdosBlocked);
        }

        // Check IP-specific request rate
        let mut ip_info = self.suspicious_ips
            .entry(ip.clone())
            .or_insert_with(|| SuspiciousIpInfo {
                requests_per_minute: 0,
                failed_requests: 0,
                last_activity: now,
                reputation_score: 100, // Start with perfect reputation
                blocked: false,
                block_expiry: None,
            });

        // Update request tracking
        ip_info.requests_per_minute += 1;
        ip_info.last_activity = now;

        // Check IP request rate
        if ip_info.requests_per_minute > self.config.ip_rps_threshold * 60 {
            warn!(
                ip = %ip,
                requests_per_minute = ip_info.requests_per_minute,
                threshold = self.config.ip_rps_threshold * 60,
                "IP request rate threshold exceeded"
            );
            
            // Decrease reputation
            ip_info.reputation_score = ip_info.reputation_score.saturating_sub(20);
            
            // Auto-block if threshold exceeded
            if ip_info.requests_per_minute > self.config.auto_block_threshold {
                ip_info.blocked = true;
                ip_info.block_expiry = Some(now + self.config.block_duration);
                warn!(
                    ip = %ip,
                    duration = ?self.config.block_duration,
                    "IP auto-blocked due to excessive requests"
                );
                return Err(ServerError::DdosBlocked);
            }
        }

        // Apply reputation-based filtering
        if ip_info.reputation_score < 30 {
            // Low reputation: apply stricter rate limiting
            if ip_info.requests_per_minute > (self.config.ip_rps_threshold * 30) {
                warn!(
                    ip = %ip,
                    reputation = ip_info.reputation_score,
                    "Low reputation IP exceeded strict rate limit"
                );
                return Err(ServerError::RateLimit);
            }
        }

        // Decay reputation over time
        let hours_since_last_activity = now.duration_since(ip_info.last_activity).as_secs() / 3600;
        if hours_since_last_activity > 0 {
            ip_info.reputation_score = (ip_info.reputation_score + 
                (hours_since_last_activity as u8 * self.config.reputation_decay_rate)).min(100);
        }

        // Reset per-minute counter if needed
        if now.duration_since(ip_info.last_activity) >= Duration::from_secs(60) {
            ip_info.requests_per_minute = 0;
        }

        Ok(())
    }

    async fn record_failed_request(&self, client_id: &str) {
        let ip = self.extract_ip_from_client_id(client_id);
        
        if let Some(mut ip_info) = self.suspicious_ips.get_mut(&ip) {
            ip_info.failed_requests += 1;
            ip_info.reputation_score = ip_info.reputation_score.saturating_sub(5);
            
            // Block if too many failed requests
            if ip_info.failed_requests > 10 {
                ip_info.blocked = true;
                ip_info.block_expiry = Some(Instant::now() + self.config.block_duration);
                warn!(
                    ip = %ip,
                    failed_requests = ip_info.failed_requests,
                    "IP blocked due to excessive failed requests"
                );
            }
        }
    }

    async fn cleanup(&self) {
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(3600); // 1 hour

        // Cleanup old IP entries
        self.suspicious_ips.retain(|_, info| {
            now.duration_since(info.last_activity) < cleanup_threshold
        });

        // Cleanup global requests
        self.cleanup_global_requests(now);
    }

    fn cleanup_global_requests(&self, now: Instant) {
        let cutoff = now - Duration::from_secs(60); // Keep last minute
        self.global_requests.retain(|&timestamp, _| timestamp > cutoff);
    }

    fn extract_ip_from_client_id(&self, client_id: &str) -> String {
        if client_id.starts_with("ip:") {
            client_id[3..].to_string()
        } else if client_id.starts_with("user:") {
            // For user-based client IDs, we can't extract IP
            // In a real implementation, you might maintain a mapping
            "unknown_user".to_string()
        } else {
            client_id.to_string()
        }
    }
}

// Track global requests for DDoS detection
fn track_global_request(ddos_protection: &Arc<DdosProtection>) {
    let now = Instant::now();
    let mut counter = ddos_protection.global_requests.entry(now).or_insert(0);
    *counter += 1;
}

impl AdvancedRateLimiter {
    /// Create a new advanced rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        let ddos_config = DdosConfig {
            enabled: config.ddos_protection.enabled,
            global_rps_threshold: config.ddos_protection.global_rps_threshold
                .unwrap_or_else(|| config.requests_per_minute / 60),
            ip_rps_threshold: config.ddos_protection.ip_rps_threshold
                .unwrap_or_else(|| config.requests_per_minute / 600), // 10% of per-minute limit
            auto_block_threshold: config.ddos_protection.auto_block_threshold
                .unwrap_or_else(|| config.requests_per_minute * 2),
            block_duration: Duration::from_secs(config.ddos_protection.block_duration_seconds),
            reputation_decay_rate: config.ddos_protection.reputation_decay_rate,
        };

        Self {
            algorithm: config.algorithm.clone(),
            config,
            token_bucket_storage: Arc::new(DashMap::new()),
            sliding_window_storage: Arc::new(DashMap::new()),
            fixed_window_storage: Arc::new(DashMap::new()),
            leaky_bucket_storage: Arc::new(DashMap::new()),
            ddos_protection: Arc::new(DdosProtection::new(ddos_config)),
            metrics: Arc::new(RateLimitMetrics::new()),
        }
    }

    /// Create rate limiter with specific algorithm
    pub fn with_algorithm(config: RateLimitConfig, algorithm: RateLimitAlgorithm) -> Self {
        let mut limiter = Self::new(config);
        limiter.algorithm = algorithm;
        limiter
    }

    /// Check if a request is allowed
    pub async fn check_rate_limit(&self, client_id: &str) -> ServerResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Increment total requests
        self.metrics.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Track global request for DDoS detection
        track_global_request(&self.ddos_protection);

        // Check DDoS protection first
        if let Err(e) = self.ddos_protection.check_ddos_protection(client_id).await {
            self.metrics.ddos_blocks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(e);
        }

        // Check rate limit based on algorithm
        let result = match self.algorithm {
            RateLimitAlgorithm::TokenBucket => self.check_token_bucket(client_id).await,
            RateLimitAlgorithm::SlidingWindow => self.check_sliding_window(client_id).await,
            RateLimitAlgorithm::FixedWindow => self.check_fixed_window(client_id).await,
            RateLimitAlgorithm::LeakyBucket => self.check_leaky_bucket(client_id).await,
        };

        match result {
            Ok(()) => {
                self.metrics.allowed_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.metrics.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.ddos_protection.record_failed_request(client_id).await;
                Err(e)
            }
        }
    }

    /// Token bucket algorithm implementation
    async fn check_token_bucket(&self, client_id: &str) -> ServerResult<()> {
        let now = Instant::now();
        let mut state = self.token_bucket_storage
            .entry(client_id.to_string())
            .or_insert_with(|| TokenBucketState {
                tokens: self.config.burst_size,
                last_refill: now,
                burst_capacity: self.config.burst_size,
            });

        // Refill tokens based on time elapsed
        let time_elapsed = now.duration_since(state.last_refill);
        let tokens_to_add = (time_elapsed.as_secs() as u32 * self.config.requests_per_minute) / 60;
        
        if tokens_to_add > 0 {
            state.tokens = (state.tokens + tokens_to_add).min(state.burst_capacity);
            state.last_refill = now;
        }

        // Check if we have enough tokens
        if state.tokens == 0 {
            return Err(ServerError::RateLimit);
        }

        // Consume one token
        state.tokens -= 1;
        Ok(())
    }

    /// Sliding window algorithm implementation
    async fn check_sliding_window(&self, client_id: &str) -> ServerResult<()> {
        let now = Instant::now();
        let window_size = Duration::from_secs(60);
        let mut state = self.sliding_window_storage
            .entry(client_id.to_string())
            .or_insert_with(|| SlidingWindowState {
                request_timestamps: Vec::new(),
                window_size,
            });

        // Remove old timestamps outside the window
        state.request_timestamps.retain(|&timestamp| {
            now.duration_since(timestamp) < window_size
        });

        // Check if we're at the limit
        if state.request_timestamps.len() as u32 >= self.config.requests_per_minute {
            return Err(ServerError::RateLimit);
        }

        // Add current request timestamp
        state.request_timestamps.push(now);
        Ok(())
    }

    /// Fixed window algorithm implementation
    async fn check_fixed_window(&self, client_id: &str) -> ServerResult<()> {
        let now = Instant::now();
        let window_duration = Duration::from_secs(60);
        let mut state = self.fixed_window_storage
            .entry(client_id.to_string())
            .or_insert_with(|| FixedWindowState {
                request_count: 0,
                window_start: now,
                window_duration,
            });

        // Reset window if needed
        if now.duration_since(state.window_start) >= window_duration {
            state.request_count = 0;
            state.window_start = now;
        }

        // Check if we're at the limit
        if state.request_count >= self.config.requests_per_minute {
            return Err(ServerError::RateLimit);
        }

        // Increment request count
        state.request_count += 1;
        Ok(())
    }

    /// Leaky bucket algorithm implementation
    async fn check_leaky_bucket(&self, client_id: &str) -> ServerResult<()> {
        let now = Instant::now();
        let leak_rate = self.config.requests_per_minute / 60;
        let max_queue_size = self.config.burst_size;
        
        let mut state = self.leaky_bucket_storage
            .entry(client_id.to_string())
            .or_insert_with(|| LeakyBucketState {
                queue_size: 0,
                last_leak: now,
                max_queue_size,
                leak_rate,
            });

        // Leak tokens based on time elapsed
        let time_elapsed = now.duration_since(state.last_leak);
        let tokens_to_leak = (time_elapsed.as_secs() as u32 * leak_rate).min(state.queue_size);
        
        if tokens_to_leak > 0 {
            state.queue_size -= tokens_to_leak;
            state.last_leak = now;
        }

        // Check if queue is full
        if state.queue_size >= max_queue_size {
            return Err(ServerError::RateLimit);
        }

        // Add request to queue
        state.queue_size += 1;
        Ok(())
    }

    /// Get rate limit headers for a client
    pub async fn get_rate_limit_headers(&self, client_id: &str) -> Option<(HeaderValue, HeaderValue, HeaderValue)> {
        if !self.config.enabled {
            return None;
        }

        let remaining = match self.algorithm {
            RateLimitAlgorithm::TokenBucket => {
                if let Some(state) = self.token_bucket_storage.get(client_id) {
                    state.tokens
                } else {
                    self.config.burst_size
                }
            }
            RateLimitAlgorithm::SlidingWindow => {
                if let Some(state) = self.sliding_window_storage.get(client_id) {
                    let now = Instant::now();
                    let count = state.request_timestamps.iter()
                        .filter(|&&timestamp| now.duration_since(timestamp) < state.window_size)
                        .count() as u32;
                    self.config.requests_per_minute.saturating_sub(count)
                } else {
                    self.config.requests_per_minute
                }
            }
            RateLimitAlgorithm::FixedWindow => {
                if let Some(state) = self.fixed_window_storage.get(client_id) {
                    self.config.requests_per_minute.saturating_sub(state.request_count)
                } else {
                    self.config.requests_per_minute
                }
            }
            RateLimitAlgorithm::LeakyBucket => {
                if let Some(state) = self.leaky_bucket_storage.get(client_id) {
                    state.max_queue_size.saturating_sub(state.queue_size)
                } else {
                    self.config.burst_size
                }
            }
        };

        let reset_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + 60;

        Some((
            HeaderValue::from_str(&remaining.to_string()).ok()?,
            HeaderValue::from_str(&self.config.requests_per_minute.to_string()).ok()?,
            HeaderValue::from_str(&reset_timestamp.to_string()).ok()?,
        ))
    }

    /// Get rate limiting metrics
    pub fn get_metrics(&self) -> RateLimitMetricsSnapshot {
        RateLimitMetricsSnapshot {
            total_requests: self.metrics.total_requests.load(std::sync::atomic::Ordering::Relaxed),
            allowed_requests: self.metrics.allowed_requests.load(std::sync::atomic::Ordering::Relaxed),
            blocked_requests: self.metrics.blocked_requests.load(std::sync::atomic::Ordering::Relaxed),
            ddos_blocks: self.metrics.ddos_blocks.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Cleanup old entries
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let cleanup_threshold = Duration::from_secs(300); // 5 minutes

        // Cleanup token bucket storage
        self.token_bucket_storage.retain(|_, state| {
            now.duration_since(state.last_refill) < cleanup_threshold
        });

        // Cleanup sliding window storage
        self.sliding_window_storage.retain(|_, state| {
            !state.request_timestamps.is_empty() &&
            now.duration_since(*state.request_timestamps.last().unwrap()) < cleanup_threshold
        });

        // Cleanup fixed window storage
        self.fixed_window_storage.retain(|_, state| {
            now.duration_since(state.window_start) < cleanup_threshold
        });

        // Cleanup leaky bucket storage
        self.leaky_bucket_storage.retain(|_, state| {
            now.duration_since(state.last_leak) < cleanup_threshold
        });

        // Cleanup DDoS protection data
        self.ddos_protection.cleanup().await;
    }
}

/// Advanced rate limiting middleware
pub async fn advanced_rate_limit_middleware(
    State(rate_limiter): State<Arc<AdvancedRateLimiter>>,
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
        Err(ServerError::DdosBlocked) => {
            warn!(
                client_id = %client_id,
                "Request blocked by DDoS protection"
            );
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Legacy rate limiting middleware (for backward compatibility)
pub async fn rate_limit_middleware(
    State(rate_limiter): State<Arc<AdvancedRateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    advanced_rate_limit_middleware(State(rate_limiter), request, next).await
}

/// Request logging middleware
pub async fn request_logging_middleware(
    request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    
    // Extract headers and user info before moving request
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

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

/// Create CORS layer with optimized parsing
pub fn create_cors_layer(config: &crate::config::CorsConfig) -> CorsLayer {
    use tower_http::cors::CorsLayer;
    use http::{HeaderName, Method};
    
    // Parse and cache CORS configuration once per function call
    // This avoids repeated parsing on every request while staying thread-safe
    // For even better performance, consider caching at application startup
    let origins: Vec<_> = config.allowed_origins.iter()
        .filter_map(|s| s.as_str().parse().ok())
        .collect();
    
    let methods: Vec<Method> = config.allowed_methods.iter()
        .filter_map(|s| s.as_str().parse().ok())
        .collect();
    
    let headers: Vec<HeaderName> = config.allowed_headers.iter()
        .filter_map(|s| s.as_str().parse().ok())
        .collect();

    let mut cors_layer = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(methods)
        .allow_headers(headers);
    
    if config.allow_credentials {
        cors_layer = cors_layer.allow_credentials(true);
    }
    
    cors_layer
}

/// Create timeout layer
pub fn create_timeout_layer(timeout_seconds: u64) -> TimeoutLayer {
    TimeoutLayer::new(Duration::from_secs(timeout_seconds))
}

/// Create trace layer
pub fn create_trace_layer() -> TraceLayer<SharedClassifier<ServerErrorsAsFailures>> {
    TraceLayer::new_for_http()
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

/// Middleware stack builder - simplified for axum compatibility
pub struct MiddlewareStack;

impl MiddlewareStack {
    /// Create a new middleware stack
    pub fn new() -> Self {
        Self
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
    use axum::body::Body;
    use axum::http::Method;
    use crate::config::DdosProtectionConfig;

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
            algorithm: RateLimitAlgorithm::TokenBucket,
            ddos_protection: DdosProtectionConfig::default(),
        };

        let rate_limiter = AdvancedRateLimiter::new(config);
        
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
        let _cors_layer = create_cors_layer(&config);
        // Just test that it doesn't panic
        assert!(true);
    }
}
