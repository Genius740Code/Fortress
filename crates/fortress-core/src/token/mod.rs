//! Advanced Token Management System
//!
//! This module provides a comprehensive token management system with support for:
//! - Token lifecycle management (creation, renewal, revocation)
//! - Time-to-live (TTL) and expiration handling
//! - Lease management for dynamic secrets
//! - Token-based authentication and authorization
//! - Role-based access control integration

pub mod manager;
pub mod lease;
pub mod revocation;
pub mod types;

// Re-export main types for convenience
pub use manager::TokenManager;
pub use lease::{LeaseManager, LeaseInfo, LeaseStatus};
pub use revocation::{RevocationList, RevocationReason, RevocationEntry};
pub use types::{
    Token, TokenInfo, TokenMetadata, TokenType, TokenRole,
    CreateTokenRequest, RenewTokenRequest, RevokeTokenRequest,
    TokenValidationResult, TokenLookupResult,
};
