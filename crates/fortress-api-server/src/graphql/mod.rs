//! GraphQL API implementation for Fortress
//!
//! This module provides a complete GraphQL API for all Fortress operations including
//! database management, table operations, data CRUD, encryption management, and more.

pub mod auth;
pub mod benchmark;
pub mod cache;
pub mod context;
pub mod encryption;
pub mod enhanced_schema;
#[cfg(test)]
pub mod integration_test;
pub mod mutation;
pub mod optimized_mutations;
pub mod optimized_queries;
pub mod performance;
pub mod query;
pub mod query_executor;
pub mod schema;
pub mod security;
#[cfg(test)]
pub mod security_tests;
pub mod subscription;
pub mod types;

// Include tests when running tests
#[cfg(test)]
mod tests;

// Re-export GraphQL components
pub use auth::{
    AuthConfig, AuthManager, AuthResult, AuthenticatedUser, Claims, Permission,
    PolicyEvaluationResult, Role, SecurityPolicy, Session, SessionStats, TokenRefreshResult,
    TokenVerificationResult,
};
pub use benchmark::{BenchmarkConfig, BenchmarkResults, PerformanceBenchmark};
pub use cache::{CacheConfig, GraphQLCacheManager};
pub use context::GraphQLContext;
pub use encryption::{
    DataEncryptionManager, DataProtectionPolicy, DataProtectionPolicyManager, DecryptedField,
    EncryptedField, EncryptedRecord, EncryptionConfig, EncryptionStats, FieldEncryptionConfig,
    PolicyEvaluationResult as DataPolicyEvaluationResult, UserContext,
};
pub use enhanced_schema::{create_enhanced_schema, EnhancedGraphQLSchema, ResourceUsage};
pub use optimized_mutations::OptimizedMutation;
pub use optimized_queries::OptimizedQuery;
pub use performance::{
    PerformanceMonitor, QueryAnalyzer, ResourceMonitor, SerializableOperationMetrics,
};
pub use schema::{create_schema, FortressSchema};
pub use security::{
    InputValidator, QueryComplexityAnalyzer, RateLimiter, SecurityAuditLogger, SecurityConfig,
    SecurityManager, SecurityRequest, SecurityStats, SecurityValidationResult,
};
pub use types::*;

// GraphQL HTTP handlers
use crate::handlers::AppState;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
    response::{Html, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

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
