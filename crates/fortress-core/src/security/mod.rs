//! Security Module
//! 
//! This module provides comprehensive security features including
//! rate limiting, threat detection, and security monitoring.

pub mod memory_safety;
pub mod zero_knowledge;

pub use memory_safety::{
    ConstantTimeOps, SecureKey, SecureMemoryPool, GlobalSecureMemoryPool, utils
};
pub use zero_knowledge::{
    ZeroKnowledgeProof, SecurityLevel, SchnorrProof, SchnorrProofData,
    AccessControlProof, AccessControlCircuit, AnonymousAuth, GroupParameters,
    UserId, Credential, AnonymousProof, GdprComplianceProof, PersonalData,
    ProcessingPurpose, ConsentRecord
};

#[cfg(test)]
mod memory_safety_tests;

#[cfg(test)]
mod zero_knowledge_tests;
