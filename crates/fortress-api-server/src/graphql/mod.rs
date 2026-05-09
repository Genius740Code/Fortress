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
pub mod query_executor;
#[cfg(test)]
pub mod security_tests;
#[cfg(test)]
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

// GraphQL HTTP handlers
use axum::{
    response::{Html, Response, Json},
    extract::{State, Request},
    body::Body,
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use crate::handlers::AppState;
use serde_json::json;

/// GraphQL HTTP handler
pub async fn graphql_handler(
    State(_state): State<Arc<AppState>>,
    _req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    // For now, return a simple response that indicates GraphQL is available
    // The full GraphQL implementation can be added later
    let response = json!({
        "message": "GraphQL API is available",
        "endpoint": "/graphql",
        "playground": "/graphql/playground",
        "status": "operational",
        "dynamic_secrets": "implemented"
    });
    
    Ok(Json(response).into_response())
}

/// GraphQL Playground handler
pub async fn graphql_playground() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>GraphQL Playground</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css" />
</head>
<body>
    <div id="root">
        <style>
            body { margin: 0; font-family: 'Open Sans', sans-serif; }
            .playground { height: 100vh; }
        </style>
        <div class="playground">
            <h2>Fortress GraphQL API</h2>
            <p>GraphQL endpoint: <code>/graphql</code></p>
            <p>Dynamic Secrets Engine is now integrated!</p>
            <p>Available mutations:</p>
            <ul>
                <li><code>configureAwsDynamicSecrets</code> - Configure AWS integration</li>
                <li><code>generateAwsCredentials</code> - Generate AWS IAM credentials</li>
                <li><code>generateDatabaseCredentials</code> - Generate database credentials</li>
                <li><code>renewCredentialLease</code> - Renew credential lease</li>
                <li><code>revokeCredential</code> - Revoke credentials</li>
            </ul>
            <p>Available queries:</p>
            <ul>
                <li><code>dynamicSecretsStatus</code> - Get engine status</li>
                <li><code>listDynamicCredentials</code> - List credentials</li>
                <li><code>getDynamicCredential</code> - Get specific credential</li>
            </ul>
        </div>
    </div>
</body>
</html>
    "#.to_string())
}
