//! HCL Policy Engine
//!
//! This module provides a comprehensive HCL (HashiCorp Configuration Language) policy engine
//! for fine-grained access control. It supports policy parsing, evaluation, and enforcement
//! with built-in functions and role-based access control integration.

pub mod builtin_functions;
pub mod evaluator;
pub mod parser;
pub mod types;

// Re-export main types for convenience
pub use evaluator::HclPolicyEngine;
pub use types::{
    ConstraintOperator, InMemoryRoleStore, ParameterType, ParsedPolicy, PolicyConstraint,
    PolicyContext, PolicyEvaluationResult, PolicyFunction, PolicyResult, RoleStore,
};
