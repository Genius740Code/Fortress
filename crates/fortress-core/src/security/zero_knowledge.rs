//! Zero-Knowledge Proof Module
//! 
//! This module provides zero-knowledge proof implementations for privacy-preserving
//! authentication, access control, and compliance verification.

use crate::error::FortressError;
use crate::security::memory_safety::{SecureKey, ConstantTimeOps};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Core trait for zero-knowledge proof systems
pub trait ZeroKnowledgeProof {
    /// Type representing the statement to be proven
    type Statement;
    
    /// Type representing the witness (secret information)
    type Witness;
    
    /// Type representing the generated proof
    type Proof;
    
    /// Generate a zero-knowledge proof
    /// 
    /// # Arguments
    /// * `statement` - Public statement to be proven
    /// * `witness` - Secret witness information
    /// 
    /// # Returns
    /// * `Result<Self::Proof, FortressError>` - Generated proof or error
    /// 
    /// # Security
    /// The proof reveals nothing about the witness beyond the validity of the statement.
    fn prove(statement: &Self::Statement, witness: &Self::Witness) -> Result<Self::Proof, FortressError>;
    
    /// Verify a zero-knowledge proof
    /// 
    /// # Arguments
    /// * `statement` - Public statement to verify against
    /// * `proof` - Proof to verify
    /// 
    /// # Returns
    /// * `Result<bool, FortressError>` - true if proof is valid, false otherwise
    fn verify(statement: &Self::Statement, proof: &Self::Proof) -> Result<bool, FortressError>;
    
    /// Get the security level of this proof system
    /// 
    /// # Returns
    /// * `SecurityLevel` - Security level information
    fn security_level() -> SecurityLevel;
}

/// Security levels for zero-knowledge proof systems
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128-bit security level
    Level128,
    /// 192-bit security level  
    Level192,
    /// 256-bit security level
    Level256,
}

impl SecurityLevel {
    /// Get the bit security level
    pub fn bits(&self) -> usize {
        match self {
            SecurityLevel::Level128 => 128,
            SecurityLevel::Level192 => 192,
            SecurityLevel::Level256 => 256,
        }
    }
    
    /// Get recommended curve for this security level
    pub fn recommended_curve(&self) -> &'static str {
        match self {
            SecurityLevel::Level128 => "BLS12-381",
            SecurityLevel::Level192 => "BLS12-381",
            SecurityLevel::Level256 => "BLS12-381",
        }
    }
}

/// Basic Schnorr signature-based zero-knowledge proof
#[derive(Debug, Clone)]
pub struct SchnorrProof;

impl ZeroKnowledgeProof for SchnorrProof {
    type Statement = Vec<u8>;
    type Witness = SecureKey;
    type Proof = SchnorrProofData;

    fn prove(statement: &Self::Statement, witness: &Self::Witness) -> Result<Self::Proof, FortressError> {
        use rand::RngCore;
        use sha2::{Sha256, Digest};
        
        let mut rng = rand::thread_rng();
        
        // Generate random nonce
        let mut nonce_bytes = vec![0u8; 32];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = SecureKey::new(nonce_bytes);
        
        // Compute commitment (simplified for demonstration)
        let mut hasher = Sha256::new();
        hasher.update(&nonce.as_bytes());
        hasher.update(statement);
        hasher.update(witness.as_bytes());
        let commitment = hasher.finalize();
        
        // Compute challenge (simplified)
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(&commitment);
        challenge_hasher.update(statement);
        let challenge = challenge_hasher.finalize();
        
        // Compute response (simplified)
        let mut response_hasher = Sha256::new();
        response_hasher.update(&challenge);
        response_hasher.update(witness.as_bytes());
        let response = response_hasher.finalize();
        
        Ok(SchnorrProofData {
            commitment: commitment.to_vec(),
            challenge: challenge.to_vec(),
            response: response.to_vec(),
            statement: statement.clone(),
        })
    }

    fn verify(statement: &Self::Statement, proof: &Self::Proof) -> Result<bool, FortressError> {
        use sha2::{Sha256, Digest};
        
        // Recompute expected commitment
        let mut hasher = Sha256::new();
        hasher.update(&proof.response);
        hasher.update(&proof.challenge);
        let expected_commitment = hasher.finalize();
        
        // Verify commitment matches
        let commitment_matches = ConstantTimeOps::compare_bytes_secure(
            &proof.commitment,
            &expected_commitment
        );
        
        // Verify statement matches
        let statement_matches = ConstantTimeOps::compare_bytes_secure(
            statement,
            &proof.statement
        );
        
        Ok(commitment_matches && statement_matches)
    }

    fn security_level() -> SecurityLevel {
        SecurityLevel::Level128
    }
}

/// Schnorr proof data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProofData {
    /// Commitment value
    pub commitment: Vec<u8>,
    /// Challenge value
    pub challenge: Vec<u8>,
    /// Response value
    pub response: Vec<u8>,
    /// Original statement
    pub statement: Vec<u8>,
}

/// Access control proof structure for ZK-SNARK implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlProof {
    /// Hashed user identifier
    pub user_id_hash: Vec<u8>,
    /// Hashed resource identifier
    pub resource_id_hash: Vec<u8>,
    /// Hashed permissions
    pub permissions_hash: Vec<u8>,
    /// Zero-knowledge proof
    pub proof: Vec<u8>,
    /// Proof timestamp
    pub timestamp: DateTime<Utc>,
    /// Proof unique identifier
    pub proof_id: Uuid,
}

impl AccessControlProof {
    /// Create a new access control proof
    /// 
    /// # Arguments
    /// * `user_key` - User's secret key
    /// * `resource_policy` - Resource access policy
    /// * `permissions` - User permissions
    /// 
    /// # Returns
    /// * `Result<Self, FortressError>` - Generated proof or error
    /// 
    /// # Security
    /// Creates a proof that user has required permissions without revealing
    /// the actual permissions or user identity.
    pub fn create_proof(
        user_key: &SecureKey,
        resource_policy: &[u8],
        permissions: &[u8],
    ) -> Result<Self, FortressError> {
        use sha2::{Sha256, Digest};
        
        // Build access circuit (simplified for demonstration)
        let circuit = AccessControlCircuit::build(resource_policy, permissions)?;
        
        // Create witness from user key
        let witness = circuit.create_witness(user_key)?;
        
        // Generate SNARK proof (simplified)
        let proof_data = generate_snark_proof(&circuit, &witness)?;
        
        // Hash sensitive information
        let mut hasher = Sha256::new();
        hasher.update(user_key.as_bytes());
        let user_id_hash = hasher.finalize().to_vec();
        
        let mut resource_hasher = Sha256::new();
        resource_hasher.update(resource_policy);
        let resource_id_hash = resource_hasher.finalize().to_vec();
        
        let mut permissions_hasher = Sha256::new();
        permissions_hasher.update(permissions);
        let permissions_hash = permissions_hasher.finalize().to_vec();
        
        Ok(Self {
            user_id_hash,
            resource_id_hash,
            permissions_hash,
            proof: proof_data,
            timestamp: Utc::now(),
            proof_id: Uuid::new_v4(),
        })
    }
    
    /// Verify the access control proof
    /// 
    /// # Arguments
    /// * `policy_requirements` - Required policy requirements
    /// 
    /// # Returns
    /// * `Result<bool, FortressError>` - true if proof is valid
    /// 
    /// # Security
    /// Verifies proof without learning sensitive information.
    pub fn verify_proof(&self, policy_requirements: &[u8]) -> Result<bool, FortressError> {
        // Build verification circuit
        let circuit = AccessControlCircuit::build(policy_requirements, &self.permissions_hash)?;
        
        // Prepare public inputs
        let public_inputs = self.prepare_public_inputs();
        
        // Verify SNARK proof
        verify_snark_proof(&circuit, &self.proof, &public_inputs)
    }
    
    /// Prepare public inputs for verification
    fn prepare_public_inputs(&self) -> Vec<Vec<u8>> {
        vec![
            self.user_id_hash.clone(),
            self.resource_id_hash.clone(),
            self.permissions_hash.clone(),
        ]
    }
    
    /// Check if proof has expired
    /// 
    /// # Arguments
    /// * `max_age_seconds` - Maximum age in seconds
    /// 
    /// # Returns
    /// * `bool` - true if proof is still valid
    pub fn is_valid(&self, max_age_seconds: i64) -> bool {
        let now = Utc::now();
        let age = now.signed_duration_since(self.timestamp);
        age.num_seconds() <= max_age_seconds
    }
}

/// Access control circuit for SNARK proofs
#[derive(Debug, Clone)]
pub struct AccessControlCircuit {
    /// Circuit constraints
    pub constraints: Vec<Vec<u8>>,
    /// Circuit public inputs
    pub public_inputs: Vec<Vec<u8>>,
    /// Circuit private inputs
    pub private_inputs: Vec<Vec<u8>>,
}

impl AccessControlCircuit {
    /// Build an access control circuit
    /// 
    /// # Arguments
    /// * `policy` - Access policy
    /// * `permissions` - User permissions
    /// 
    /// # Returns
    /// * `Result<Self, FortressError>` - Built circuit
    pub fn build(policy: &[u8], permissions: &[u8]) -> Result<Self, FortressError> {
        use sha2::{Sha256, Digest};
        
        // Simplified circuit building - in a real implementation,
        // this would build actual arithmetic circuits
        
        let mut hasher = Sha256::new();
        hasher.update(policy);
        hasher.update(permissions);
        let constraint = hasher.finalize();
        
        Ok(Self {
            constraints: vec![constraint.to_vec()],
            public_inputs: vec![policy.to_vec()],
            private_inputs: vec![permissions.to_vec()],
        })
    }
    
    /// Create witness for the circuit
    /// 
    /// # Arguments
    /// * `user_key` - User's secret key
    /// 
    /// # Returns
    /// * `Result<Vec<u8>, FortressError>` - Circuit witness
    pub fn create_witness(&self, user_key: &SecureKey) -> Result<Vec<u8>, FortressError> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&self.private_inputs[0]);
        hasher.update(user_key.as_bytes());
        Ok(hasher.finalize().to_vec())
    }
}

/// Anonymous authentication system
#[derive(Debug, Clone)]
pub struct AnonymousAuth {
    /// Group parameters for anonymous credentials
    pub group_params: GroupParameters,
    /// User credentials (in practice, this would be stored securely)
    pub user_credentials: HashMap<UserId, Credential>,
}

/// Group parameters for anonymous authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupParameters {
    /// Group generator
    pub generator: Vec<u8>,
    /// Group order
    pub order: Vec<u8>,
    /// Security level
    pub security_level: SecurityLevel,
}

/// User identifier (hashed)
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserId(Vec<u8>);

impl UserId {
    /// Create a new user ID from a string
    pub fn from_string(s: &str) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        Self(hasher.finalize().to_vec())
    }
    
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Anonymous credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Credential identifier
    pub id: Uuid,
    /// Public key component
    pub public_key: Vec<u8>,
    /// Secret key component
    pub secret_key: SecureKey,
    /// Issue timestamp
    pub issued_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
}

/// Anonymous proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousProof {
    /// Zero-knowledge proof data
    pub proof: Vec<u8>,
    /// Proof timestamp
    pub timestamp: DateTime<Utc>,
    /// Challenge hash
    pub challenge_hash: Vec<u8>,
    /// Proof unique identifier
    pub proof_id: Uuid,
}

impl AnonymousAuth {
    /// Create a new anonymous authentication system
    /// 
    /// # Arguments
    /// * `security_level` - Security level for the system
    /// 
    /// # Returns
    /// * `Self` - New anonymous auth system
    pub fn new(security_level: SecurityLevel) -> Self {
        use rand::RngCore;
        
        let mut rng = rand::thread_rng();
        let mut generator = vec![0u8; 32];
        let mut order = vec![0u8; 32];
        rng.fill_bytes(&mut generator);
        rng.fill_bytes(&mut order);
        
        Self {
            group_params: GroupParameters {
                generator,
                order,
                security_level,
            },
            user_credentials: HashMap::new(),
        }
    }
    
    /// Register a new user
    /// 
    /// # Arguments
    /// * `user_id` - User identifier
    /// * `valid_days` - Number of days until credential expires
    /// 
    /// # Returns
    /// * `Result<Credential, FortressError>` - Generated credential
    pub fn register_user(&mut self, user_id: UserId, valid_days: i64) -> Result<Credential, FortressError> {
        use rand::RngCore;
        
        let mut rng = rand::thread_rng();
        
        // Generate key pair
        let mut public_key = vec![0u8; 32];
        let mut secret_key_bytes = vec![0u8; 32];
        rng.fill_bytes(&mut public_key);
        rng.fill_bytes(&mut secret_key_bytes);
        
        let secret_key = SecureKey::new(secret_key_bytes);
        
        let now = Utc::now();
        let credential = Credential {
            id: Uuid::new_v4(),
            public_key,
            secret_key: secret_key.clone(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(valid_days),
        };
        
        self.user_credentials.insert(user_id, credential.clone());
        Ok(credential)
    }
    
    /// Authenticate anonymously
    /// 
    /// # Arguments
    /// * `user_id` - User identifier
    /// * `challenge` - Authentication challenge
    /// 
    /// # Returns
    /// * `Result<AnonymousProof, FortressError>` - Anonymous proof
    /// 
    /// # Security
    /// Creates zero-knowledge proof of knowledge of credential without revealing identity.
    pub fn authenticate_anonymously(&self, user_id: &UserId, challenge: &[u8]) -> Result<AnonymousProof, FortressError> {
        let credential = self.user_credentials.get(user_id)
            .ok_or(FortressError::authentication("User not found", None))?;
        
        // Create zero-knowledge proof of knowledge of credential
        let proof = self.create_credential_proof(credential, challenge)?;
        
        // Hash the challenge
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        let challenge_hash = hasher.finalize().to_vec();
        
        Ok(AnonymousProof {
            proof,
            timestamp: Utc::now(),
            challenge_hash,
            proof_id: Uuid::new_v4(),
        })
    }
    
    /// Verify anonymous authentication
    /// 
    /// # Arguments
    /// * `proof` - Anonymous proof to verify
    /// * `challenge` - Original challenge
    /// 
    /// # Returns
    /// * `Result<bool, FortressError>` - true if proof is valid
    /// 
    /// # Security
    /// Verifies proof without learning which user authenticated.
    pub fn verify_anonymous(&self, proof: &AnonymousProof, challenge: &[u8]) -> Result<bool, FortressError> {
        // Verify challenge hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        let expected_challenge_hash = hasher.finalize().to_vec();
        
        let challenge_valid = ConstantTimeOps::compare_bytes_secure(
            &proof.challenge_hash,
            &expected_challenge_hash
        );
        
        if !challenge_valid {
            return Ok(false);
        }
        
        // Verify credential proof
        self.verify_credential_proof(&proof.proof, challenge)
    }
    
    /// Create credential proof (simplified implementation)
    fn create_credential_proof(&self, credential: &Credential, challenge: &[u8]) -> Result<Vec<u8>, FortressError> {
        use sha2::{Sha256, Digest};
        
        // Simplified proof generation - in practice, this would use
        // actual zero-knowledge proof systems like Camenisch-Lysyanskaya
        let mut hasher = Sha256::new();
        hasher.update(&credential.public_key);
        hasher.update(credential.secret_key.as_bytes());
        hasher.update(challenge);
        hasher.update(&self.group_params.generator);
        Ok(hasher.finalize().to_vec())
    }
    
    /// Verify credential proof (simplified implementation)
    fn verify_credential_proof(&self, proof: &[u8], challenge: &[u8]) -> Result<bool, FortressError> {
        use sha2::{Sha256, Digest};
        
        // Simplified verification - in practice, this would verify
        // actual zero-knowledge proof
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(&self.group_params.generator);
        let expected_proof = hasher.finalize();
        
        Ok(ConstantTimeOps::compare_bytes_secure(proof, &expected_proof))
    }
}

/// GDPR compliance proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdprComplianceProof {
    /// Hashed data subject identifier
    pub data_subject_hash: Vec<u8>,
    /// Hashed processing purpose
    pub processing_purpose_hash: Vec<u8>,
    /// Consent proof
    pub consent_proof: Vec<u8>,
    /// Retention compliance proof
    pub retention_compliance_proof: Vec<u8>,
    /// Data subject rights proof
    pub data_subject_rights_proof: Vec<u8>,
    /// Proof timestamp
    pub timestamp: DateTime<Utc>,
    /// Valid until timestamp
    pub valid_until: DateTime<Utc>,
}

impl GdprComplianceProof {
    /// Create GDPR compliance proof
    /// 
    /// # Arguments
    /// * `data_subject` - Personal data subject information
    /// * `processing_purpose` - Purpose of data processing
    /// * `consent_record` - User consent record
    /// * `retention_period_days` - Data retention period in days
    /// 
    /// # Returns
    /// * `Result<Self, FortressError>` - Compliance proof
    /// 
    /// # Security
    /// Creates ZK proofs that demonstrate GDPR compliance without exposing
    /// the actual personal data or consent details.
    pub fn create_compliance_proof(
        data_subject: &PersonalData,
        processing_purpose: &ProcessingPurpose,
        consent_record: &ConsentRecord,
        retention_period_days: i64,
    ) -> Result<Self, FortressError> {
        use sha2::{Sha256, Digest};
        
        // Create consent proof
        let consent_proof = Self::prove_consent_obtained(consent_record)?;
        
        // Create retention compliance proof
        let retention_proof = Self::prove_retention_compliance(data_subject, retention_period_days)?;
        
        // Create data subject rights proof
        let rights_proof = Self::prove_data_subject_rights(data_subject, consent_record)?;
        
        // Hash sensitive information
        let mut subject_hasher = Sha256::new();
        subject_hasher.update(&data_subject.id);
        let data_subject_hash = subject_hasher.finalize().to_vec();
        
        let mut purpose_hasher = Sha256::new();
        purpose_hasher.update(&processing_purpose.id);
        let processing_purpose_hash = purpose_hasher.finalize().to_vec();
        
        let now = Utc::now();
        let valid_until = now + chrono::Duration::days(30); // Valid for 30 days
        
        Ok(Self {
            data_subject_hash,
            processing_purpose_hash,
            consent_proof,
            retention_compliance_proof: retention_proof,
            data_subject_rights_proof: rights_proof,
            timestamp: now,
            valid_until,
        })
    }
    
    /// Verify GDPR compliance proof
    /// 
    /// # Returns
    /// * `Result<bool, FortressError>` - true if proof is valid
    pub fn verify_compliance(&self) -> Result<bool, FortressError> {
        // Check if proof is still valid
        if Utc::now() > self.valid_until {
            return Ok(false);
        }
        
        // Verify individual components
        let consent_valid = self.verify_consent_proof()?;
        let retention_valid = self.verify_retention_proof()?;
        let rights_valid = self.verify_rights_proof()?;
        
        Ok(consent_valid && retention_valid && rights_valid)
    }
    
    /// Prove that consent was obtained
    fn prove_consent_obtained(consent_record: &ConsentRecord) -> Result<Vec<u8>, FortressError> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&consent_record.id);
        hasher.update(&consent_record.timestamp.to_rfc3339().as_bytes());
        hasher.update(if consent_record.granted { b"1" } else { b"0" });
        Ok(hasher.finalize().to_vec())
    }
    
    /// Prove retention compliance
    fn prove_retention_compliance(data_subject: &PersonalData, retention_days: i64) -> Result<Vec<u8>, FortressError> {
        use sha2::{Sha256, Digest};
        
        let retention_date = data_subject.created_at + chrono::Duration::days(retention_days);
        let now = Utc::now();
        
        let mut hasher = Sha256::new();
        hasher.update(&data_subject.id);
        hasher.update(retention_date.to_rfc3339().as_bytes());
        hasher.update(now.to_rfc3339().as_bytes());
        Ok(hasher.finalize().to_vec())
    }
    
    /// Prove data subject rights
    fn prove_data_subject_rights(data_subject: &PersonalData, consent: &ConsentRecord) -> Result<Vec<u8>, FortressError> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&data_subject.id);
        hasher.update(b"data_access"); // Right to access
        hasher.update(b"data_portability"); // Right to portability
        hasher.update(b"data_deletion"); // Right to deletion
        hasher.update(&consent.id);
        Ok(hasher.finalize().to_vec())
    }
    
    /// Verify consent proof
    fn verify_consent_proof(&self) -> Result<bool, FortressError> {
        // Simplified verification - would check against actual consent records
        Ok(!self.consent_proof.is_empty())
    }
    
    /// Verify retention proof
    fn verify_retention_proof(&self) -> Result<bool, FortressError> {
        // Simplified verification - would check retention policies
        Ok(!self.retention_compliance_proof.is_empty())
    }
    
    /// Verify rights proof
    fn verify_rights_proof(&self) -> Result<bool, FortressError> {
        // Simplified verification - would check rights implementation
        Ok(!self.data_subject_rights_proof.is_empty())
    }
}

/// Personal data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalData {
    /// Data subject identifier
    pub id: Vec<u8>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Data category
    pub category: String,
    /// Processing purposes
    pub processing_purposes: Vec<String>,
}

/// Processing purpose structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingPurpose {
    /// Purpose identifier
    pub id: Vec<u8>,
    /// Purpose description
    pub description: String,
    /// Legal basis
    pub legal_basis: String,
}

/// Consent record structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Consent identifier
    pub id: Vec<u8>,
    /// Consent timestamp
    pub timestamp: DateTime<Utc>,
    /// Whether consent was granted
    pub granted: bool,
    /// Consent scope
    pub scope: Vec<String>,
}

/// Simplified SNARK proof generation (placeholder implementation)
fn generate_snark_proof(circuit: &AccessControlCircuit, witness: &[u8]) -> Result<Vec<u8>, FortressError> {
    use sha2::{Sha256, Digest};
    
    // In a real implementation, this would use actual SNARK libraries
    // like bellman, arkworks, or libsnark
    let mut hasher = Sha256::new();
    hasher.update(&circuit.constraints[0]);
    hasher.update(witness);
    Ok(hasher.finalize().to_vec())
}

/// Simplified SNARK proof verification (placeholder implementation)
fn verify_snark_proof(
    circuit: &AccessControlCircuit,
    proof: &[u8],
    public_inputs: &[Vec<u8>],
) -> Result<bool, FortressError> {
    use sha2::{Sha256, Digest};
    
    // In a real implementation, this would verify actual SNARK proofs
    let mut hasher = Sha256::new();
    hasher.update(&circuit.constraints[0]);
    for input in public_inputs {
        hasher.update(input);
    }
    let expected_proof = hasher.finalize();
    
    Ok(ConstantTimeOps::compare_bytes_secure(proof, &expected_proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_proof() {
        let statement = b"test statement".to_vec();
        let witness = SecureKey::new(vec![1, 2, 3, 4, 5]);
        
        let proof = SchnorrProof::prove(&statement, &witness).unwrap();
        let verified = SchnorrProof::verify(&statement, &proof).unwrap();
        
        assert!(verified);
        
        // Test with wrong statement
        let wrong_statement = b"wrong statement".to_vec();
        let not_verified = SchnorrProof::verify(&wrong_statement, &proof).unwrap();
        assert!(!not_verified);
    }

    #[test]
    fn test_access_control_proof() {
        let user_key = SecureKey::generate_random(32).unwrap();
        let resource_policy = b"admin_access_required".to_vec();
        let permissions = b"read,write,admin".to_vec();
        
        let proof = AccessControlProof::create_proof(&user_key, &resource_policy, &permissions).unwrap();
        let verified = proof.verify_proof(&resource_policy).unwrap();
        
        assert!(verified);
        assert!(proof.is_valid(3600)); // Valid for 1 hour
        
        // Test with wrong policy
        let wrong_policy = b"read_only_required".to_vec();
        let not_verified = proof.verify_proof(&wrong_policy).unwrap();
        assert!(!not_verified);
    }

    #[test]
    fn test_anonymous_auth() {
        let mut auth = AnonymousAuth::new(SecurityLevel::Level128);
        
        let user_id = UserId::from_string("test_user");
        let _credential = auth.register_user(user_id.clone(), 30).unwrap();
        
        let challenge = b"authentication_challenge";
        let proof = auth.authenticate_anonymously(&user_id, challenge).unwrap();
        let verified = auth.verify_anonymous(&proof, challenge).unwrap();
        
        assert!(verified);
        
        // Test with wrong challenge
        let wrong_challenge = b"wrong_challenge";
        let not_verified = auth.verify_anonymous(&proof, wrong_challenge).unwrap();
        assert!(!not_verified);
    }

    #[test]
    fn test_gdpr_compliance_proof() {
        let data_subject = PersonalData {
            id: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            category: "personal".to_string(),
            processing_purposes: vec!["marketing".to_string()],
        };
        
        let processing_purpose = ProcessingPurpose {
            id: vec![5, 6, 7, 8],
            description: "Direct marketing".to_string(),
            legal_basis: "Consent".to_string(),
        };
        
        let consent_record = ConsentRecord {
            id: vec![9, 10, 11, 12],
            timestamp: Utc::now(),
            granted: true,
            scope: vec!["marketing".to_string()],
        };
        
        let proof = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_record,
            365, // 1 year retention
        ).unwrap();
        
        let verified = proof.verify_compliance().unwrap();
        assert!(verified);
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(SecurityLevel::Level128.bits(), 128);
        assert_eq!(SecurityLevel::Level192.bits(), 192);
        assert_eq!(SecurityLevel::Level256.bits(), 256);
        
        assert_eq!(SecurityLevel::Level128.recommended_curve(), "BLS12-381");
    }

    #[test]
    fn test_user_id() {
        let user_id1 = UserId::from_string("test_user");
        let user_id2 = UserId::from_string("test_user");
        let user_id3 = UserId::from_string("different_user");
        
        assert_eq!(user_id1, user_id2);
        assert_ne!(user_id1, user_id3);
    }
}
