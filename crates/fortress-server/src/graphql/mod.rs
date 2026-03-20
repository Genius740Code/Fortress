//! GraphQL API implementation for Fortress
//!
//! This module provides a complete GraphQL API for all Fortress operations including
//! database management, table operations, data CRUD, encryption management, and more.

pub mod schema;
pub mod enhanced_schema;
pub mod query;
pub mod mutation;
pub mod subscription;
pub mod types;
pub mod context;
pub mod cache;
pub mod optimized_queries;
pub mod optimized_mutations;
pub mod performance;
pub mod benchmark;
pub mod security;
pub mod auth;
pub mod encryption;
pub mod security_tests;
pub mod integration_test;

// Include tests when running tests
#[cfg(test)]
mod tests;

// Re-export GraphQL components
pub use schema::{FortressSchema, create_schema};
pub use enhanced_schema::{EnhancedGraphQLSchema, create_enhanced_schema, ResourceUsage};
pub use context::GraphQLContext;
pub use types::*;
pub use cache::{GraphQLCacheManager, CacheConfig};
pub use optimized_queries::OptimizedQuery;
pub use optimized_mutations::OptimizedMutation;
pub use performance::{PerformanceMonitor, QueryAnalyzer, ResourceMonitor, SerializableOperationMetrics};
pub use benchmark::{PerformanceBenchmark, BenchmarkConfig, BenchmarkResults};
pub use security::{SecurityManager, SecurityConfig, SecurityRequest, SecurityValidationResult, RateLimiter, InputValidator, QueryComplexityAnalyzer, SecurityAuditLogger, SecurityStats};
pub use auth::{AuthManager, AuthConfig, AuthenticatedUser, Claims, Role, Permission, Session, AuthResult, TokenVerificationResult, TokenRefreshResult, SessionStats, SecurityPolicy, PolicyEvaluationResult};
pub use encryption::{DataEncryptionManager, EncryptionConfig, FieldEncryptionConfig, EncryptedField, DecryptedField, EncryptedRecord, EncryptionStats, DataProtectionPolicyManager, DataProtectionPolicy, PolicyEvaluationResult as DataPolicyEvaluationResult, UserContext};
pub use security_tests::{SecurityTestSuite, SecurityTestResults, TestResult};
pub use integration_test::{IntegrationTestSuite, IntegrationTestResults};
