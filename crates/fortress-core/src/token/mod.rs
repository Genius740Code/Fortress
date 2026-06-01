//! Advanced Token Management System
//!
//! This module provides a comprehensive token management system with support for:
//! - Token lifecycle management (creation, renewal, revocation)
//! - Time-to-live (TTL) and expiration handling
//! - Lease management for dynamic secrets
//! - Token-based authentication and authorization
//! - Role-based access control integration

pub mod lease;
pub mod manager;
pub mod revocation;
pub mod types;

// Re-export main types for convenience
pub use lease::{LeaseInfo, LeaseManager, LeaseStatus};
pub use manager::TokenManager;
pub use revocation::{RevocationEntry, RevocationList, RevocationReason};
pub use types::{
    CreateTokenRequest, RenewTokenRequest, RevokeTokenRequest, Token, TokenCreationContext,
    TokenInfo, TokenLookupResult, TokenMetadata, TokenRole, TokenType, TokenUsageStats,
    TokenValidationResult,
};
