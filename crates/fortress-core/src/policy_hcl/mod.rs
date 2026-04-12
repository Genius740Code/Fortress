//! HCL Policy Engine
//!
//! This module provides a comprehensive HCL (HashiCorp Configuration Language) policy engine
//! for fine-grained access control. It supports policy parsing, evaluation, and enforcement
//! with built-in functions and role-based access control integration.

pub mod parser;
pub mod evaluator;
pub mod types;
pub mod builtin_functions;

// Re-export main types for convenience
pub use evaluator::HclPolicyEngine;
pub use types::{
    ParsedPolicy, PolicyContext, PolicyResult, PolicyConstraint,
    ConstraintOperator, ParameterType, PolicyEvaluationResult,
    RoleStore, InMemoryRoleStore, PolicyFunction,
};
