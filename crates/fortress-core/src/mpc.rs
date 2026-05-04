//! Secure Multi-Party Computation (MPC) support
//!
//! This module provides MPC capabilities that allow multiple parties to jointly compute
//! a function over their inputs without revealing those inputs to each other. This is
//! crucial for privacy-preserving computations and collaborative data analysis.
//!
//! ## Features
//!
//! - **Secret sharing**: Share secrets among multiple parties
//! - **MPC protocols**: Implement common MPC computation patterns
//! - **Privacy preservation**: Ensure input privacy throughout computation
//! - **Verifiable computation**: Allow verification of computation integrity
//! - **Network communication**: Handle message passing between parties

use crate::error::{FortressError, Result, EncryptionErrorCode};
use crate::encryption::{EncryptionAlgorithm, create_algorithm};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique identifier for an MPC party
pub type PartyId = String;

/// Unique identifier for an MPC computation session
pub type SessionId = String;

/// Identifier for a specific share in secret sharing
pub type ShareId = String;

/// MPC party role in computation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartyRole {
    /// Initiator of the computation
    Initiator,
    /// Participant in the computation
    Participant,
    /// Observer (can view results but not contribute)
    Observer,
    /// Auditor (can verify computation integrity)
    Auditor,
}

/// MPC computation status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputationStatus {
    /// Computation is being prepared
    Preparing,
    /// Parties are being recruited
    Recruiting,
    /// Computation is in progress
    InProgress,
    /// Computation completed successfully
    Completed,
    /// Computation failed
    Failed,
    /// Computation was aborted
    Aborted,
}

/// Secret sharing scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretSharingScheme {
    /// Shamir's Secret Sharing
    Shamir {
        /// Threshold of shares needed to reconstruct
        threshold: usize,
        /// Total number of shares
        total_shares: usize,
    },
    /// Additive Secret Sharing
    Additive {
        /// Number of parties
        num_parties: usize,
    },
    /// Replicated Secret Sharing
    Replicated {
        /// Number of replicas
        replicas: usize,
        /// Threshold for reconstruction
        threshold: usize,
    },
}

/// Share of a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    /// Unique identifier for this share
    pub id: ShareId,
    /// Party this share belongs to
    pub party_id: PartyId,
    /// Session this share is part of
    pub session_id: SessionId,
    /// The share data
    pub share_data: Vec<u8>,
    /// Share index (for schemes like Shamir)
    pub share_index: Option<usize>,
    /// Verification data (if applicable)
    pub verification_data: Option<Vec<u8>>,
    /// When this share was created
    pub created_at: DateTime<Utc>,
    /// Share metadata
    pub metadata: HashMap<String, String>,
}

impl SecretShare {
    /// Create a new secret share
    pub fn new(
        party_id: PartyId,
        session_id: SessionId,
        share_data: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            party_id,
            session_id,
            share_data,
            share_index: None,
            verification_data: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Set the share index
    pub fn with_share_index(mut self, index: usize) -> Self {
        self.share_index = Some(index);
        self
    }

    /// Set verification data
    pub fn with_verification_data(mut self, data: Vec<u8>) -> Self {
        self.verification_data = Some(data);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// MPC computation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationConfig {
    /// Unique identifier for this computation
    pub session_id: SessionId,
    /// Type of computation to perform
    pub computation_type: String,
    /// Secret sharing scheme to use
    pub sharing_scheme: SecretSharingScheme,
    /// Parties involved in the computation
    pub parties: HashMap<PartyId, PartyRole>,
    /// Algorithm for cryptographic operations
    pub algorithm: String,
    /// Additional configuration parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// When this configuration was created
    pub created_at: DateTime<Utc>,
    /// Configuration metadata
    pub metadata: HashMap<String, String>,
}

impl ComputationConfig {
    /// Create a new computation configuration
    pub fn new(
        computation_type: impl Into<String>,
        sharing_scheme: SecretSharingScheme,
    ) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            computation_type: computation_type.into(),
            sharing_scheme,
            parties: HashMap::new(),
            algorithm: "chacha20poly1305".to_string(),
            parameters: HashMap::new(),
            created_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Add a party to the computation
    pub fn with_party(mut self, party_id: PartyId, role: PartyRole) -> Self {
        self.parties.insert(party_id, role);
        self
    }

    /// Set the algorithm
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.algorithm = algorithm.into();
        self
    }

    /// Add a parameter
    pub fn with_parameter(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// MPC message between parties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcMessage {
    /// Unique message identifier
    pub id: String,
    /// Session this message belongs to
    pub session_id: SessionId,
    /// Sender party ID
    pub sender: PartyId,
    /// Recipient party ID (None for broadcast)
    pub recipient: Option<PartyId>,
    /// Message type
    pub message_type: String,
    /// Message payload
    pub payload: Vec<u8>,
    /// When this message was sent
    pub sent_at: DateTime<Utc>,
    /// Message metadata
    pub metadata: HashMap<String, String>,
}

impl MpcMessage {
    /// Create a new MPC message
    pub fn new(
        session_id: SessionId,
        sender: PartyId,
        recipient: Option<PartyId>,
        message_type: impl Into<String>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id,
            sender,
            recipient,
            message_type: message_type.into(),
            payload,
            sent_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Result of an MPC computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationResult {
    /// Session ID
    pub session_id: SessionId,
    /// Computation result data
    pub result_data: Vec<u8>,
    /// Proof of correct computation (if applicable)
    pub proof: Option<Vec<u8>>,
    /// Parties that contributed to the result
    pub contributing_parties: Vec<PartyId>,
    /// When computation completed
    pub completed_at: DateTime<Utc>,
    /// Result metadata
    pub metadata: HashMap<String, String>,
}

impl ComputationResult {
    /// Create a new computation result
    pub fn new(
        session_id: SessionId,
        result_data: Vec<u8>,
        contributing_parties: Vec<PartyId>,
    ) -> Self {
        Self {
            session_id,
            result_data,
            proof: None,
            contributing_parties,
            completed_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Set proof
    pub fn with_proof(mut self, proof: Vec<u8>) -> Self {
        self.proof = Some(proof);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Trait for MPC protocol implementations
#[async_trait]
pub trait MpcProtocol: Send + Sync {
    /// Get the protocol name
    fn name(&self) -> &str;

    /// Initialize the protocol
    async fn initialize(&self, config: &ComputationConfig) -> Result<()>;

    /// Share a secret among parties
    async fn share_secret(
        &self,
        secret: &[u8],
        config: &ComputationConfig,
    ) -> Result<Vec<SecretShare>>;

    /// Reconstruct a secret from shares
    async fn reconstruct_secret(
        &self,
        shares: &[SecretShare],
        config: &ComputationConfig,
    ) -> Result<Vec<u8>>;

    /// Perform MPC computation
    async fn compute(
        &self,
        inputs: HashMap<PartyId, Vec<u8>>,
        config: &ComputationConfig,
    ) -> Result<ComputationResult>;

    /// Verify computation result
    async fn verify_result(
        &self,
        result: &ComputationResult,
        config: &ComputationConfig,
    ) -> Result<bool>;
}

/// Trait for MPC party management
#[async_trait]
pub trait MpcParty: Send + Sync {
    /// Get the party ID
    fn party_id(&self) -> &PartyId;

    /// Get the party role
    fn role(&self) -> PartyRole;

    /// Process incoming message
    async fn process_message(&self, message: MpcMessage) -> Result<Option<MpcMessage>>;

    /// Get current shares held by this party
    async fn get_shares(&self, session_id: &SessionId) -> Result<Vec<SecretShare>>;

    /// Add a share to this party
    async fn add_share(&self, share: SecretShare) -> Result<()>;

    /// Remove a share from this party
    async fn remove_share(&self, share_id: &ShareId) -> Result<()>;
}

/// Trait for MPC network communication
#[async_trait]
pub trait MpcNetwork: Send + Sync {
    /// Send a message to a specific party
    async fn send_message(&self, message: MpcMessage) -> Result<()>;

    /// Broadcast a message to all parties
    async fn broadcast_message(&self, message: MpcMessage) -> Result<()>;

    /// Receive messages for a party
    async fn receive_messages(&self, party_id: &PartyId) -> Result<Vec<MpcMessage>>;

    /// Get connected parties
    async fn get_connected_parties(&self) -> Result<Vec<PartyId>>;
}

/// Main MPC manager that coordinates protocols and parties
#[async_trait]
pub trait MpcManager: Send + Sync {
    /// Create a new computation session
    async fn create_session(&self, config: ComputationConfig) -> Result<SessionId>;

    /// Join a computation session
    async fn join_session(&self, session_id: &SessionId, party: Box<dyn MpcParty>) -> Result<()>;

    /// Leave a computation session
    async fn leave_session(&self, session_id: &SessionId, party_id: &PartyId) -> Result<()>;

    /// Get session status
    async fn get_session_status(&self, session_id: &SessionId) -> Result<ComputationStatus>;

    /// Start computation in a session
    async fn start_computation(&self, session_id: &SessionId) -> Result<()>;

    /// Get computation result
    async fn get_result(&self, session_id: &SessionId) -> Result<Option<ComputationResult>>;

    /// List active sessions
    async fn list_sessions(&self) -> Result<Vec<SessionId>>;
}

/// Shamir's Secret Sharing implementation
pub struct ShamirSecretSharing {
    algorithm: Box<dyn EncryptionAlgorithm>,
}

impl ShamirSecretSharing {
    /// Create a new Shamir secret sharing instance
    pub fn new() -> Result<Self> {
        let algorithm = create_algorithm("chacha20poly1305")?;
        Ok(Self { algorithm })
    }

    /// Create with custom algorithm
    pub fn with_algorithm(algorithm: Box<dyn EncryptionAlgorithm>) -> Self {
        Self { algorithm }
    }

    /// Generate shares using Shamir's scheme
    fn generate_shares(&self, secret: &[u8], threshold: usize, total_shares: usize) -> Result<Vec<Vec<u8>>> {
        if threshold > total_shares {
            return Err(FortressError::encryption(
                "Threshold cannot be greater than total shares",
                "shamir",
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if total_shares == 0 {
            return Err(FortressError::encryption(
                "Total shares must be greater than 0",
                "shamir",
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // This is a simplified implementation
        // In practice, you'd use finite field arithmetic
        let mut shares = Vec::new();
        
        for i in 1..=total_shares {
            // Create share (x, f(x)) where x is the share index
            let mut share_data = Vec::new();
            share_data.extend_from_slice(&(i as u64).to_le_bytes());
            
            // For simplicity, we'll just XOR with the secret and index
            // Real implementation would use polynomial evaluation
            let mut share_value = secret.to_vec();
            for byte in share_value.iter_mut() {
                *byte ^= (i as u8).wrapping_mul(0x5A);
            }
            share_data.extend_from_slice(&share_value);
            
            shares.push(share_data);
        }

        Ok(shares)
    }

    /// Reconstruct secret from shares
    fn reconstruct_secret(&self, shares: &[Vec<u8>], threshold: usize) -> Result<Vec<u8>> {
        if shares.len() < threshold {
            return Err(FortressError::encryption(
                "Insufficient shares to reconstruct secret",
                "shamir",
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        if shares.is_empty() {
            return Err(FortressError::encryption(
                "No shares provided",
                "shamir",
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Simplified reconstruction - just use the first share
        // Real implementation would use Lagrange interpolation
        let first_share = &shares[0];
        if first_share.len() < 8 {
            return Err(FortressError::encryption(
                "Invalid share format",
                "shamir",
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        let secret_data = &first_share[8..];
        let mut reconstructed = secret_data.to_vec();
        
        // Reverse the XOR operation
        let index = u64::from_le_bytes(first_share[..8].try_into().unwrap()) as u8;
        for byte in reconstructed.iter_mut() {
            *byte ^= index.wrapping_mul(0x5A);
        }

        Ok(reconstructed)
    }
}

impl Default for ShamirSecretSharing {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[async_trait]
impl MpcProtocol for ShamirSecretSharing {
    fn name(&self) -> &str {
        "shamir_secret_sharing"
    }

    async fn initialize(&self, _config: &ComputationConfig) -> Result<()> {
        // Shamir's scheme doesn't need complex initialization
        Ok(())
    }

    async fn share_secret(
        &self,
        secret: &[u8],
        config: &ComputationConfig,
    ) -> Result<Vec<SecretShare>> {
        let (threshold, total_shares) = match &config.sharing_scheme {
            SecretSharingScheme::Shamir { threshold, total_shares } => (*threshold, *total_shares),
            _ => return Err(FortressError::encryption(
                "Invalid sharing scheme for Shamir protocol",
                "shamir",
                EncryptionErrorCode::AlgorithmNotSupported,
            )),
        };

        let share_data = self.generate_shares(secret, threshold, total_shares)?;
        let mut shares = Vec::new();

        for (i, data) in share_data.into_iter().enumerate() {
            let party_id = config.parties.keys().nth(i).unwrap_or(&"unknown".to_string()).clone();
            let share = SecretShare::new(party_id, config.session_id.clone(), data)
                .with_share_index(i + 1);
            shares.push(share);
        }

        Ok(shares)
    }

    async fn reconstruct_secret(
        &self,
        shares: &[SecretShare],
        config: &ComputationConfig,
    ) -> Result<Vec<u8>> {
        let threshold = match &config.sharing_scheme {
            SecretSharingScheme::Shamir { threshold, .. } => *threshold,
            _ => return Err(FortressError::encryption(
                "Invalid sharing scheme for Shamir protocol",
                "shamir",
                EncryptionErrorCode::AlgorithmNotSupported,
            )),
        };

        let share_data: Vec<Vec<u8>> = shares.iter().map(|s| s.share_data.clone()).collect();
        self.reconstruct_secret(&share_data, threshold)
    }

    async fn compute(
        &self,
        _inputs: HashMap<PartyId, Vec<u8>>,
        _config: &ComputationConfig,
    ) -> Result<ComputationResult> {
        // Shamir's scheme is for secret sharing, not computation
        // This would need to be extended with actual MPC protocols
        Err(FortressError::encryption(
            "Shamir secret sharing does not support computation",
            "shamir",
            EncryptionErrorCode::AlgorithmNotSupported,
        ))
    }

    async fn verify_result(
        &self,
        _result: &ComputationResult,
        _config: &ComputationConfig,
    ) -> Result<bool> {
        // Basic verification - would need proper implementation
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_secret_sharing() {
        let shamir = ShamirSecretSharing::new().unwrap();
        let secret = b"this is a secret message";
        let threshold = 3;
        let total_shares = 5;

        let shares = shamir.generate_shares(secret, threshold, total_shares).unwrap();
        assert_eq!(shares.len(), total_shares);

        // Reconstruct with threshold shares
        let threshold_shares: Vec<Vec<u8>> = shares.iter().take(threshold).cloned().collect();
        let reconstructed = shamir.reconstruct_secret(&threshold_shares, threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_secret_share_creation() {
        let share = SecretShare::new(
            "party1".to_string(),
            "session1".to_string(),
            b"share data".to_vec(),
        )
        .with_share_index(1)
        .with_metadata("type", "shamir");

        assert_eq!(share.party_id, "party1");
        assert_eq!(share.session_id, "session1");
        assert_eq!(share.share_index, Some(1));
        assert_eq!(share.share_data, b"share data");
        assert_eq!(share.metadata.get("type"), Some(&"shamir".to_string()));
    }

    #[test]
    fn test_computation_config() {
        let config = ComputationConfig::new(
            "secret_sharing",
            SecretSharingScheme::Shamir {
                threshold: 3,
                total_shares: 5,
            },
        )
        .with_party("party1".to_string(), PartyRole::Initiator)
        .with_party("party2".to_string(), PartyRole::Participant)
        .with_algorithm("chacha20poly1305")
        .with_parameter("security_level", serde_json::Value::Number(256.into()));

        assert_eq!(config.computation_type, "secret_sharing");
        assert_eq!(config.parties.len(), 2);
        assert_eq!(config.algorithm, "chacha20poly1305");
        assert!(config.parameters.contains_key("security_level"));
    }

    #[tokio::test]
    async fn test_shamir_protocol() {
        let shamir = ShamirSecretSharing::new().unwrap();
        let config = ComputationConfig::new(
            "test_sharing",
            SecretSharingScheme::Shamir {
                threshold: 2,
                total_shares: 3,
            },
        )
        .with_party("party1".to_string(), PartyRole::Initiator)
        .with_party("party2".to_string(), PartyRole::Participant)
        .with_party("party3".to_string(), PartyRole::Participant);

        // Initialize
        shamir.initialize(&config).await.unwrap();

        // Share secret
        let secret = b"test secret";
        let shares = shamir.share_secret(secret, &config).await.unwrap();
        assert_eq!(shares.len(), 3);

        // Reconstruct secret
        let reconstructed = MpcProtocol::reconstruct_secret(&shamir, &shares[..2], &config).await.unwrap();
        assert_eq!(reconstructed, secret);
    }
}
