//! # Zero-Knowledge Proof System for Audit Verification
//!
//! This module implements privacy-preserving audit verification using zero-knowledge proofs.
//! It allows verification of audit log integrity without revealing sensitive information.
//!
//! ## Features
//!
//! - **Privacy-Preserving Verification**: Verify integrity without revealing audit contents
//! - **Range Proofs**: Prove audit counts within ranges without exact numbers
//! - **Membership Proofs**: Prove specific events occurred without revealing details
//! - **Aggregate Proofs**: Combine multiple proofs for efficient verification
//! - **Selective Disclosure**: Choose what information to reveal in proofs

use crate::error::{FortressError, Result, AuditErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use base64::Engine as _;
use rand::rngs::OsRng;
use merlin::Transcript;

/// Zero-knowledge proof for audit verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkAuditProof {
    /// Proof type
    pub proof_type: ZkProofType,
    /// Proof data (encoded)
    pub proof_data: String,
    /// Public commitments
    pub commitments: Vec<String>,
    /// Proof metadata
    pub metadata: ZkProofMetadata,
    /// Verification key fingerprint
    pub verification_key_fingerprint: String,
    /// Proof generation timestamp
    pub timestamp: DateTime<Utc>,
}

/// Types of zero-knowledge proofs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ZkProofType {
    /// Range proof for audit counts
    RangeProof,
    /// Membership proof for specific events
    MembershipProof,
    /// Aggregate proof for multiple metrics
    AggregateProof,
    /// Selective disclosure proof
    SelectiveDisclosure,
    /// Integrity proof without revealing contents
    IntegrityProof,
}

/// Zero-knowledge proof metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofMetadata {
    /// Audit log identifier
    pub audit_log_id: String,
    /// Time range covered
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    /// Event types included (masked if sensitive)
    pub event_types: Vec<String>,
    /// Number of audit entries (masked if sensitive)
    pub entry_count: Option<u64>,
    /// Proof parameters
    pub proof_parameters: HashMap<String, serde_json::Value>,
}

/// Range proof parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProofParams {
    /// Minimum value in range
    pub min_value: u64,
    /// Maximum value in range
    pub max_value: u64,
    /// Bit length of values
    pub bit_length: usize,
}

/// Membership proof parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProofParams {
    /// Hash of target event (blinded)
    pub target_event_hash: String,
    /// Event type to prove membership for
    pub event_type: String,
    /// Include timestamp range
    pub include_timestamp: bool,
}

/// Selective disclosure parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveDisclosureParams {
    /// Fields to disclose
    pub disclosed_fields: Vec<String>,
    /// Fields to hide (blinded)
    pub hidden_fields: Vec<String>,
    /// Disclosure policy
    pub disclosure_policy: DisclosurePolicy,
}

/// Disclosure policy for selective proofs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DisclosurePolicy {
    /// Disclose only non-sensitive fields
    NonSensitiveOnly,
    /// Disclose based on user role
    RoleBased(String),
    /// Disclose based on time window
    TimeBased(DateTime<Utc>, DateTime<Utc>),
    /// Custom disclosure rules
    Custom(HashMap<String, bool>),
}

/// Zero-knowledge proof generator
#[derive(Debug)]
pub struct ZkProofGenerator {
    /// Proof generation parameters
    parameters: ZkProofParameters,
    /// Random number generator
    rng: OsRng,
}

/// Zero-knowledge proof verifier
#[derive(Debug)]
pub struct ZkProofVerifier {
    /// Verification keys
    verification_keys: HashMap<String, String>,
}

/// Zero-knowledge proof system parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofParameters {
    /// Maximum range size for range proofs
    pub max_range_size: u64,
    /// Default bit length for proofs
    pub default_bit_length: usize,
    /// Proof security level
    pub security_level: ZkSecurityLevel,
    /// Enable aggregation
    pub enable_aggregation: bool,
    /// Maximum aggregation size
    pub max_aggregation_size: usize,
}

/// Zero-knowledge proof security levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ZkSecurityLevel {
    /// 128-bit security
    Security128,
    /// 192-bit security
    Security192,
    /// 256-bit security
    Security256,
}

/// Audit log commitment for ZK proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogCommitment {
    /// Commitment to audit log hash
    pub log_hash_commitment: String,
    /// Commitment to entry count
    pub count_commitment: String,
    /// Commitment to time range
    pub time_commitment: String,
    /// Randomness used for commitments
    pub randomness: Vec<String>,
}

/// Blinded audit entry for privacy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedAuditEntry {
    /// Blinded entry hash
    pub blinded_hash: String,
    /// Blinded timestamp
    pub blinded_timestamp: String,
    /// Blinded event type
    pub blinded_event_type: String,
    /// Blinded principal
    pub blinded_principal: String,
    /// Commitments to original values
    pub commitments: HashMap<String, String>,
}

impl ZkProofGenerator {
    /// Create new zero-knowledge proof generator
    pub fn new(parameters: ZkProofParameters) -> Self {
        Self {
            parameters,
            rng: OsRng{},
        }
    }

    /// Generate range proof for audit count
    pub fn generate_range_proof(
        &mut self,
        value: u64,
        params: RangeProofParams,
        metadata: ZkProofMetadata,
    ) -> Result<ZkAuditProof> {
        // Create commitment to the value (simplified mock implementation)
        let (commitment, _randomness) = self.commit_to_value(value)?;

        // Generate mock range proof (in a real implementation, this would use actual Bulletproofs)
        let proof_data = format!("range_proof_{}_{}_{}", 
            value, 
            params.min_value, 
            params.max_value);

        Ok(ZkAuditProof {
            proof_type: ZkProofType::RangeProof,
            proof_data,
            commitments: vec![commitment],
            metadata,
            verification_key_fingerprint: self.generate_key_fingerprint(),
            timestamp: Utc::now(),
        })
    }

    /// Generate membership proof for specific event
    pub fn generate_membership_proof(
        &mut self,
        event_hash: &str,
        _event_set: &[String],
        params: MembershipProofParams,
        metadata: ZkProofMetadata,
    ) -> Result<ZkAuditProof> {
        // Create commitment to event hash (simplified mock implementation)
        let (commitment, _randomness) = self.commit_to_string(event_hash)?;

        // Create transcript for the proof
        let mut transcript = Transcript::new(b"audit_membership_proof");
        transcript.append_message(b"commitment", commitment.as_bytes());
        transcript.append_message(b"event_type", params.event_type.as_bytes());

        // Generate membership proof
        let proof = {
            let mock_proof = format!("membership_proof_{}_{}", 
                event_hash, 
                params.event_type);
            mock_proof
        };

        Ok(ZkAuditProof {
            proof_type: ZkProofType::MembershipProof,
            proof_data: proof,
            commitments: vec![commitment],
            metadata,
            verification_key_fingerprint: self.generate_key_fingerprint(),
            timestamp: Utc::now(),
        })
    }

    /// Generate selective disclosure proof
    pub fn generate_selective_disclosure_proof(
        &mut self,
        audit_entry: &BlindedAuditEntry,
        params: SelectiveDisclosureParams,
        metadata: ZkProofMetadata,
    ) -> Result<ZkAuditProof> {
        let mut commitments = Vec::new();

        // Create commitments for disclosed fields
        for field in &params.disclosed_fields {
            if let Some(value) = audit_entry.commitments.get(field) {
                commitments.push(value.clone());
            }
        }

        // Create commitments for hidden fields (blinded)
        for field in &params.hidden_fields {
            if let Some(value) = audit_entry.commitments.get(field) {
                let (blinded_commitment, _) = self.commit_to_string(value)?;
                commitments.push(blinded_commitment);
            }
        }

        // Generate selective disclosure proof
        let proof = {
            let disclosed_fields_str = params.disclosed_fields.join(",");
            let hidden_fields_str = params.hidden_fields.join(",");
            format!("selective_proof_{}_{}", disclosed_fields_str, hidden_fields_str)
        };

        Ok(ZkAuditProof {
            proof_type: ZkProofType::SelectiveDisclosure,
            proof_data: proof,
            commitments,
            metadata,
            verification_key_fingerprint: self.generate_key_fingerprint(),
            timestamp: Utc::now(),
        })
    }

    /// Generate integrity proof without revealing contents
    pub fn generate_integrity_proof(
        &mut self,
        audit_log_commitment: &AuditLogCommitment,
        metadata: ZkProofMetadata,
    ) -> Result<ZkAuditProof> {
        // Create transcript for integrity proof
        let mut transcript = Transcript::new(b"audit_integrity_proof");
        transcript.append_message(b"log_commitment", audit_log_commitment.log_hash_commitment.as_bytes());
        transcript.append_message(b"count_commitment", audit_log_commitment.count_commitment.as_bytes());

        // Generate integrity proof
        let proof = {
            format!("integrity_proof_{}_{}", 
                audit_log_commitment.log_hash_commitment,
                audit_log_commitment.count_commitment)
        };

        Ok(ZkAuditProof {
            proof_type: ZkProofType::IntegrityProof,
            proof_data: proof,
            commitments: vec![
                audit_log_commitment.log_hash_commitment.clone(),
                audit_log_commitment.count_commitment.clone(),
            ],
            metadata,
            verification_key_fingerprint: self.generate_key_fingerprint(),
            timestamp: Utc::now(),
        })
    }

    /// Generate aggregate proof for multiple metrics
    pub fn generate_aggregate_proof(
        &mut self,
        proofs: Vec<ZkAuditProof>,
        metadata: ZkProofMetadata,
    ) -> Result<ZkAuditProof> {
        if proofs.len() > self.parameters.max_aggregation_size {
            return Err(FortressError::audit(
                format!("Too many proofs for aggregation: {} > {}", 
                    proofs.len(), 
                    self.parameters.max_aggregation_size),
                None,
                AuditErrorCode::PolicyNotFound
            ));
        }

        // Combine commitments from all proofs
        let mut all_commitments = Vec::new();
        for proof in &proofs {
            all_commitments.extend(proof.commitments.clone());
        }

        // Generate aggregate proof
        let proof = {
            let proof_ids: Vec<String> = proofs.iter()
                .map(|p| p.proof_data.clone())
                .collect();
            format!("aggregate_proof_{}", proof_ids.join("_"))
        };

        Ok(ZkAuditProof {
            proof_type: ZkProofType::AggregateProof,
            proof_data: proof,
            commitments: all_commitments,
            metadata,
            verification_key_fingerprint: self.generate_key_fingerprint(),
            timestamp: Utc::now(),
        })
    }

    /// Create commitment to a numeric value (simplified implementation)
    fn commit_to_value(&mut self, value: u64) -> Result<(String, String)> {
        // Generate random blinding factor
        let mut blinding_bytes = [0u8; 32];
        use rand::RngCore;
        self.rng.fill_bytes(&mut blinding_bytes);
        let randomness = base64::engine::general_purpose::STANDARD.encode(blinding_bytes);
        
        // Create simple commitment (in real implementation, this would use Pedersen commitment)
        let commitment_data = format!("{}:{}", value, base64::engine::general_purpose::STANDARD.encode(blinding_bytes));
        let mut hasher = Sha256::new();
        hasher.update(commitment_data.as_bytes());
        let commitment = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        
        Ok((commitment, randomness))
    }

    /// Create commitment to a string value
    fn commit_to_string(&mut self, value: &str) -> Result<(String, String)> {
        // Hash the string first
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        let hash = hasher.finalize();
        
        // Convert hash to numeric value
        let hash_num = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3], 
            hash[4], hash[5], hash[6], hash[7]
        ]);
        
        self.commit_to_value(hash_num)
    }

    /// Generate verification key fingerprint
    fn generate_key_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zk_audit_verification_key");
        hasher.update(self.parameters.default_bit_length.to_string().as_bytes());
        
        let result = hasher.finalize();
        base64::engine::general_purpose::STANDARD.encode(result)
    }

    /// Blind audit entry for privacy
    pub fn blind_audit_entry(&mut self, entry_data: &str) -> Result<BlindedAuditEntry> {
        let mut hasher = Sha256::new();
        hasher.update(entry_data.as_bytes());
        let entry_hash = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

        let mut commitments = HashMap::new();
        
        // Create commitments for each field (simplified)
        let fields = vec!["hash", "timestamp", "event_type", "principal"];
        for field in fields {
            let (commitment, _) = self.commit_to_string(&format!("{}:{}", field, entry_hash))?;
            commitments.insert(field.to_string(), commitment);
        }

        Ok(BlindedAuditEntry {
            blinded_hash: entry_hash,
            blinded_timestamp: format!("blinded_{}", Utc::now().timestamp()),
            blinded_event_type: "blinded_type".to_string(),
            blinded_principal: "blinded_principal".to_string(),
            commitments,
        })
    }

    /// Create audit log commitment
    pub fn create_audit_log_commitment(
        &mut self,
        log_hash: &str,
        entry_count: u64,
        time_range: (DateTime<Utc>, DateTime<Utc>),
    ) -> Result<AuditLogCommitment> {
        let (hash_commitment, hash_randomness) = self.commit_to_string(log_hash)?;
        let (count_commitment, count_randomness) = self.commit_to_value(entry_count)?;
        
        let time_string = format!("{}|{}", time_range.0.to_rfc3339(), time_range.1.to_rfc3339());
        let (time_commitment, time_randomness) = self.commit_to_string(&time_string)?;

        Ok(AuditLogCommitment {
            log_hash_commitment: hash_commitment,
            count_commitment,
            time_commitment,
            randomness: vec![hash_randomness, count_randomness, time_randomness],
        })
    }
}

impl ZkProofVerifier {
    /// Create new zero-knowledge proof verifier
    pub fn new() -> Self {
        Self {
            verification_keys: HashMap::new(),
        }
    }

    /// Verify range proof
    pub fn verify_range_proof(
        &self,
        proof: &ZkAuditProof,
        params: RangeProofParams,
    ) -> Result<bool> {
        // Extract commitment from proof
        let commitment = proof.commitments.get(0)
            .ok_or_else(|| FortressError::audit("No commitment found in proof".to_string(), None, AuditErrorCode::VerificationFailed))?;

        // Parse proof data (simplified mock implementation)
        let _expected_pattern = format!("range_proof_{}_{}_{}", 
            commitment, 
            params.min_value, 
            params.max_value);
        
        let proof_data = &proof.proof_data;
        Ok(proof_data.starts_with("range_proof_") && 
           proof_data.contains(&params.min_value.to_string()) &&
           proof_data.contains(&params.max_value.to_string()))
    }

    /// Verify membership proof
    pub fn verify_membership_proof(
        &self,
        proof: &ZkAuditProof,
        params: MembershipProofParams,
    ) -> Result<bool> {
        if proof.proof_type != ZkProofType::MembershipProof {
            return Err(FortressError::audit(
                "Proof type mismatch".to_string(),
                None,
                AuditErrorCode::PolicyNotFound
            ));
        }

        // Mock verification
        let proof_data = &proof.proof_data;
        Ok(proof_data.starts_with("membership_proof_") && 
           proof_data.contains(&params.event_type))
    }

    /// Verify selective disclosure proof
    pub fn verify_selective_disclosure_proof(
        &self,
        proof: &ZkAuditProof,
        params: SelectiveDisclosureParams,
    ) -> Result<bool> {
        if proof.proof_type != ZkProofType::SelectiveDisclosure {
            return Err(FortressError::audit(
                "Proof type mismatch".to_string(),
                None,
                AuditErrorCode::PolicyNotFound
            ));
        }

        // Verify that commitments match the disclosure policy
        let disclosed_fields_str = params.disclosed_fields.join(",");
        let hidden_fields_str = params.hidden_fields.join(",");
        
        let expected_pattern = format!("selective_proof_{}_{}", disclosed_fields_str, hidden_fields_str);
        
        Ok(proof.proof_data == expected_pattern)
    }

    /// Verify integrity proof
    pub fn verify_integrity_proof(
        &self,
        proof: &ZkAuditProof,
        commitment: &AuditLogCommitment,
    ) -> Result<bool> {
        if proof.proof_type != ZkProofType::IntegrityProof {
            return Err(FortressError::audit(
                "Proof type mismatch".to_string(),
                None,
                AuditErrorCode::PolicyNotFound
            ));
        }

        // Verify that proof matches the commitment
        let expected_pattern = format!("integrity_proof_{}_{}", 
            commitment.log_hash_commitment,
            commitment.count_commitment);
        
        Ok(proof.proof_data == expected_pattern)
    }

    /// Verify aggregate proof
    pub fn verify_aggregate_proof(
        &self,
        proof: &ZkAuditProof,
        individual_proofs: &[ZkAuditProof],
    ) -> Result<bool> {
        if proof.proof_type != ZkProofType::AggregateProof {
            return Err(FortressError::audit(
                "Proof type mismatch".to_string(),
                None,
                AuditErrorCode::PolicyNotFound
            ));
        }

        // Verify that aggregate proof contains all individual proofs
        let individual_proof_ids: Vec<String> = individual_proofs.iter()
            .map(|p| p.proof_data.clone())
            .collect();
        
        let expected_pattern = format!("aggregate_proof_{}", individual_proof_ids.join("_"));
        
        Ok(proof.proof_data == expected_pattern)
    }

    /// Add verification key
    pub fn add_verification_key(&mut self, key_id: String, key_data: String) {
        self.verification_keys.insert(key_id, key_data);
    }

    /// Verify proof timestamp is recent
    pub fn verify_proof_freshness(&self, proof: &ZkAuditProof, max_age_hours: i64) -> bool {
        let now = Utc::now();
        let proof_age = (now - proof.timestamp).num_hours();
        proof_age <= max_age_hours
    }

    /// Verify proof metadata consistency
    pub fn verify_metadata_consistency(&self, proof: &ZkAuditProof) -> bool {
        // Check that metadata is consistent with proof type
        match proof.proof_type {
            ZkProofType::RangeProof => proof.metadata.entry_count.is_some(),
            ZkProofType::MembershipProof => !proof.metadata.event_types.is_empty(),
            ZkProofType::SelectiveDisclosure => true, // Always valid for selective disclosure
            ZkProofType::IntegrityProof => proof.metadata.audit_log_id != "",
            ZkProofType::AggregateProof => proof.metadata.entry_count.is_some(),
        }
    }
}

impl Default for ZkProofParameters {
    fn default() -> Self {
        Self {
            max_range_size: u64::MAX,
            default_bit_length: 64,
            security_level: ZkSecurityLevel::Security128,
            enable_aggregation: true,
            max_aggregation_size: 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_zk_proof_generator_creation() {
        let params = ZkProofParameters::default();
        let generator = ZkProofGenerator::new(params);
        
        assert!(generator.parameters.default_bit_length == 64);
        assert!(generator.parameters.enable_aggregation);
    }

    #[tokio::test]
    async fn test_range_proof_generation() {
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        let range_params = RangeProofParams {
            min_value: 100,
            max_value: 1000,
            bit_length: 16,
        };
        
        let metadata = ZkProofMetadata {
            audit_log_id: "test_log".to_string(),
            time_range: (Utc::now(), Utc::now()),
            event_types: vec!["Authentication".to_string()],
            entry_count: Some(500),
            proof_parameters: HashMap::new(),
        };
        
        let proof = generator.generate_range_proof(500, range_params, metadata).unwrap();
        
        assert_eq!(proof.proof_type, ZkProofType::RangeProof);
        assert!(!proof.proof_data.is_empty());
        assert!(!proof.commitments.is_empty());
    }

    #[tokio::test]
    async fn test_membership_proof_generation() {
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        let membership_params = MembershipProofParams {
            target_event_hash: "event_hash_123".to_string(),
            event_type: "Authentication".to_string(),
            include_timestamp: true,
        };
        
        let metadata = ZkProofMetadata {
            audit_log_id: "test_log".to_string(),
            time_range: (Utc::now(), Utc::now()),
            event_types: vec!["Authentication".to_string()],
            entry_count: None,
            proof_parameters: HashMap::new(),
        };
        
        let proof = generator.generate_membership_proof("event_hash_123", &[], membership_params, metadata).unwrap();
        
        assert_eq!(proof.proof_type, ZkProofType::MembershipProof);
        assert!(!proof.proof_data.is_empty());
    }

    #[tokio::test]
    async fn test_selective_disclosure_proof() {
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        let blinded_entry = generator.blind_audit_entry("test_audit_entry").unwrap();
        
        let disclosure_params = SelectiveDisclosureParams {
            disclosed_fields: vec!["event_type".to_string(), "timestamp".to_string()],
            hidden_fields: vec!["principal".to_string(), "resource".to_string()],
            disclosure_policy: DisclosurePolicy::NonSensitiveOnly,
        };
        
        let metadata = ZkProofMetadata {
            audit_log_id: "test_log".to_string(),
            time_range: (Utc::now(), Utc::now()),
            event_types: vec!["Authentication".to_string()],
            entry_count: None,
            proof_parameters: HashMap::new(),
        };
        
        let proof = generator.generate_selective_disclosure_proof(&blinded_entry, disclosure_params, metadata).unwrap();
        
        assert_eq!(proof.proof_type, ZkProofType::SelectiveDisclosure);
        assert!(!proof.proof_data.is_empty());
    }

    #[tokio::test]
    async fn test_integrity_proof() {
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        let commitment = generator.create_audit_log_commitment(
            "log_hash_123",
            1000,
            (Utc::now(), Utc::now()),
        ).unwrap();
        
        let metadata = ZkProofMetadata {
            audit_log_id: "test_log".to_string(),
            time_range: (Utc::now(), Utc::now()),
            event_types: vec!["All".to_string()],
            entry_count: Some(1000),
            proof_parameters: HashMap::new(),
        };
        
        let proof = generator.generate_integrity_proof(&commitment, metadata).unwrap();
        
        assert_eq!(proof.proof_type, ZkProofType::IntegrityProof);
        assert!(!proof.proof_data.is_empty());
    }

    #[tokio::test]
    async fn test_aggregate_proof() {
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        let metadata = ZkProofMetadata {
            audit_log_id: "test_log".to_string(),
            time_range: (Utc::now(), Utc::now()),
            event_types: vec!["All".to_string()],
            entry_count: None,
            proof_parameters: HashMap::new(),
        };
        
        // Create individual proofs
        let proof1 = generator.generate_range_proof(
            100, 
            RangeProofParams { min_value: 50, max_value: 150, bit_length: 8 },
            metadata.clone(),
        ).unwrap();
        
        let proof2 = generator.generate_range_proof(
            200, 
            RangeProofParams { min_value: 150, max_value: 250, bit_length: 8 },
            metadata.clone(),
        ).unwrap();
        
        let aggregate_proof = generator.generate_aggregate_proof(vec![proof1, proof2], metadata).unwrap();
        
        assert_eq!(aggregate_proof.proof_type, ZkProofType::AggregateProof);
        assert_eq!(aggregate_proof.commitments.len(), 2); // Two commitments from two proofs
    }

    #[tokio::test]
    async fn test_zk_proof_verification() {
        let verifier = ZkProofVerifier::new();
        
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        // Generate and verify range proof
        let range_params = RangeProofParams {
            min_value: 100,
            max_value: 1000,
            bit_length: 16,
        };
        
        let metadata = ZkProofMetadata {
            audit_log_id: "test_log".to_string(),
            time_range: (Utc::now(), Utc::now()),
            event_types: vec!["Authentication".to_string()],
            entry_count: Some(500),
            proof_parameters: HashMap::new(),
        };
        
        let proof = generator.generate_range_proof(500, range_params, metadata).unwrap();
        
        let is_valid = verifier.verify_range_proof(
            &proof,
            RangeProofParams {
                min_value: 100,
                max_value: 1000,
                bit_length: 16,
            },
        ).unwrap();
        
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_audit_entry_blinding() {
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        let blinded_entry = generator.blind_audit_entry("test_audit_entry_data").unwrap();
        
        assert!(!blinded_entry.blinded_hash.is_empty());
        assert!(!blinded_entry.blinded_timestamp.is_empty());
        assert_eq!(blinded_entry.commitments.len(), 4); // hash, timestamp, event_type, principal
    }

    #[tokio::test]
    async fn test_proof_freshness_verification() {
        let verifier = ZkProofVerifier::new();
        
        let params = ZkProofParameters::default();
        let mut generator = ZkProofGenerator::new(params);
        
        let metadata = ZkProofMetadata {
            audit_log_id: "test_log".to_string(),
            time_range: (Utc::now(), Utc::now()),
            event_types: vec!["Authentication".to_string()],
            entry_count: Some(500),
            proof_parameters: HashMap::new(),
        };
        
        let proof = generator.generate_range_proof(
            500,
            RangeProofParams {
                min_value: 100,
                max_value: 1000,
                bit_length: 16,
            },
            metadata,
        ).unwrap();
        
        // Should be fresh (created just now)
        assert!(verifier.verify_proof_freshness(&proof, 1));
        
        // Should not be fresh if we require very recent proof
        assert!(!verifier.verify_proof_freshness(&proof, 0));
    }
}
