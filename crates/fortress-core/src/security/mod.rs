//! Security Module
//!
//! This module provides comprehensive security features including
//! rate limiting, threat detection, and security monitoring.

pub mod memory_safety;
pub mod zero_knowledge;

pub use memory_safety::{
    utils, ConstantTimeOps, GlobalSecureMemoryPool, SecureKey, SecureMemoryPool,
};
pub use zero_knowledge::{
    AccessControlCircuit, AccessControlProof, AnonymousAuth, AnonymousProof, ConsentRecord,
    Credential, GdprComplianceProof, GroupParameters, PersonalData, ProcessingPurpose,
    SchnorrProof, SchnorrProofData, SecurityLevel, UserId, ZeroKnowledgeProof,
};

#[cfg(test)]
mod memory_safety_tests;

#[cfg(test)]
mod zero_knowledge_tests;
