//! GraphQL context implementation
//!
//! Provides the request context for GraphQL operations including authentication,
//! database connections, and other services.

use async_graphql::{Context, Result, Error, ErrorExtensions};
use std::sync::Arc;
use crate::handlers::AppState;

/// GraphQL context for each request
pub struct GraphQLContext {
    /// Application state
    pub app_state: Arc<AppState>,
    /// Authenticated user info (if any)
    pub user: Option<AuthenticatedUser>,
}

/// Authenticated user information
#[derive(async_graphql::SimpleObject, Clone, Debug)]
pub struct AuthenticatedUser {
    /// User ID
    pub id: String,
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// Tenant ID (if multi-tenant)
    pub tenant_id: Option<String>,
}

impl GraphQLContext {
    /// Create a new GraphQL context
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            app_state,
            user: None,
        }
    }

    /// Create a GraphQL context with authenticated user
    pub fn with_user(app_state: Arc<AppState>, user: AuthenticatedUser) -> Self {
        Self {
            app_state,
            user: Some(user),
        }
    }

    /// Get the authenticated user or return an error
    pub fn require_auth(&self) -> Result<&AuthenticatedUser> {
        self.user.as_ref().ok_or_else(|| {
            Error::new("Authentication required")
                .extend_with(|_, e| e.set("code", "AUTH_REQUIRED"))
        })
    }

    /// Check if the user has the required role
    pub fn require_role(&self, role: &str) -> Result<&AuthenticatedUser> {
        let user = self.require_auth()?;
        if user.roles.contains(&role.to_string()) {
            Ok(user)
        } else {
            Err(Error::new(format!("Required role: {}", role))
                .extend_with(|_, e| e.set("code", "INSUFFICIENT_PERMISSIONS")))
        }
    }

    /// Check if the user has any of the required roles
    pub fn require_any_role(&self, roles: &[&str]) -> Result<&AuthenticatedUser> {
        let user = self.require_auth()?;
        if roles.iter().any(|role| user.roles.contains(&role.to_string())) {
            Ok(user)
        } else {
            Err(Error::new(format!("Required one of roles: {:?}", roles))
                .extend_with(|_, e| e.set("code", "INSUFFICIENT_PERMISSIONS")))
        }
    }

    /// Get the tenant ID for the current user
    pub fn tenant_id(&self) -> Option<&str> {
        self.user.as_ref()?.tenant_id.as_deref()
    }
}

/// Get the GraphQL context from the request
pub fn from_context<'a>(ctx: &'a Context<'a>) -> Result<&'a GraphQLContext> {
    ctx.data::<GraphQLContext>()
        .map_err(|_| {
            Error::new("GraphQL context not found")
                .extend_with(|_, e| e.set("code", "INTERNAL_ERROR"))
        })
}
