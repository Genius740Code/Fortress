//! Security Module
//! 
//! This module provides comprehensive security features including
//! rate limiting, threat detection, and security monitoring.

pub mod rate_limiter;
pub mod headers;
pub mod monitoring;
pub mod audit;
pub mod side_channel;

pub use rate_limiter::{
    ProductionRateLimiter, ProductionRateLimitConfig, RateLimitRequest, RateLimitResponse,
    ProductionRateLimitMetrics, RateLimitSpec, ViolationAction, ThreatLevel, GeoLocation,
    ProductionTokenBucket, ProductionSlidingWindow, AdaptiveRateLimiter, DistributedRateLimiter,
    RateLimitMiddleware, RateLimitMiddlewareConfig, rate_limit, rate_limit_middleware
};

pub use headers::SecurityHeaders;
pub use monitoring::SecurityMonitor;
pub use audit::SecurityAuditor;
pub use side_channel::{
    SideChannelProtectionManager, SideChannelConfig, NoiseLevel, ProtectionLevel,
    AttackDetectionResult, AttackType, AttackSeverity, SecurityAuditResult
};
