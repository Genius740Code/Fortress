//! MPC Manager implementation

//!

//! This module provides the default implementation of the MpcManager trait

//! with in-memory storage for sessions and coordination of MPC protocols.



use crate::error::{FortressError, Result, EncryptionErrorCode};

use crate::mpc_party::InMemoryMpcParty;
use crate::mpc::PartyRole;
use crate::mpc::{

    MpcProtocol, MpcParty, MpcNetwork, MpcManager, ComputationConfig, SessionId,

    PartyId, ComputationStatus, MpcMessage, ComputationResult, ShamirSecretSharing,

};


use crate::mpc_network::InMemoryMpcNetwork;



use async_trait::async_trait;

use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::RwLock;



/// Default implementation of MPC manager

pub struct DefaultMpcManager {

    /// Active computation sessions

    sessions: Arc<RwLock<HashMap<SessionId, SessionState>>>,

    /// Available protocols

    protocols: HashMap<String, Box<dyn MpcProtocol>>,

    /// Network for communication

    network: Arc<dyn MpcNetwork>,

    /// Default protocol to use

    default_protocol: String,

}



/// State of an MPC session

struct SessionState {

    /// Session configuration

    config: ComputationConfig,

    /// Current status

    status: ComputationStatus,

    /// Parties in the session

    parties: HashMap<PartyId, Arc<dyn MpcParty>>,

    /// Computation result (if completed)

    result: Option<ComputationResult>,

    /// Messages exchanged in this session

    messages: Vec<MpcMessage>,

    /// When the session was created

    created_at: chrono::DateTime<chrono::Utc>,

    /// When the session was last updated

    updated_at: chrono::DateTime<chrono::Utc>,

}



impl SessionState {

    fn new(config: ComputationConfig) -> Self {

        let now = chrono::Utc::now();

        Self {

            config,

            status: ComputationStatus::Preparing,

            parties: HashMap::new(),

            result: None,

            messages: Vec::new(),

            created_at: now,

            updated_at: now,

        }

    }



    fn update_status(&mut self, status: ComputationStatus) {

        self.status = status;

        self.updated_at = chrono::Utc::now();

    }



    fn add_party(&mut self, party_id: PartyId, party: Arc<dyn MpcParty>) {

        self.parties.insert(party_id, party);

        self.updated_at = chrono::Utc::now();

    }



    fn remove_party(&mut self, party_id: &PartyId) {

        self.parties.remove(party_id);

        self.updated_at = chrono::Utc::now();

    }



    fn add_message(&mut self, message: MpcMessage) {

        self.messages.push(message);

        self.updated_at = chrono::Utc::now();

    }



    fn set_result(&mut self, result: ComputationResult) {

        self.result = Some(result);

        self.status = ComputationStatus::Completed;

        self.updated_at = chrono::Utc::now();

    }

}



impl DefaultMpcManager {

    /// Create a new MPC manager

    pub fn new() -> Result<Self> {

        let network = Arc::new(InMemoryMpcNetwork::new());

        Self::with_network(network)

    }



    /// Create a new MPC manager with custom network

    pub fn with_network(network: Arc<dyn MpcNetwork>) -> Result<Self> {

        let mut protocols: HashMap<String, Box<dyn MpcProtocol>> = HashMap::new();

        

        // Add built-in protocols

        protocols.insert("shamir".to_string(), Box::new(ShamirSecretSharing::new()?));

        

        Ok(Self {

            sessions: Arc::new(RwLock::new(HashMap::new())),

            protocols,

            network,

            default_protocol: "shamir".to_string(),

        })

    }



    /// Create a new MPC manager with custom protocols

    pub fn with_protocols(

        network: Arc<dyn MpcNetwork>,

        protocols: HashMap<String, Box<dyn MpcProtocol>>,

    ) -> Self {

        Self {

            sessions: Arc::new(RwLock::new(HashMap::new())),

            protocols,

            network,

            default_protocol: "shamir".to_string(),

        }

    }



    /// Set the default protocol

    pub fn with_default_protocol(mut self, protocol: impl Into<String>) -> Self {

        self.default_protocol = protocol.into();

        self

    }



    /// Add a custom protocol

    pub fn add_protocol(&mut self, name: impl Into<String>, protocol: Box<dyn MpcProtocol>) {

        self.protocols.insert(name.into(), protocol);

    }



    /// Get protocol by name

    fn get_protocol(&self, name: &str) -> Result<&dyn MpcProtocol> {

        self.protocols.get(name).ok_or_else(|| {

            FortressError::encryption(

                format!("Protocol '{}' not found", name),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            )

        }).map(|p| p.as_ref())

    }



    /// Validate session configuration

    fn validate_config(&self, config: &ComputationConfig) -> Result<()> {

        if config.parties.is_empty() {

            return Err(FortressError::encryption(

                "At least one party is required".to_string(),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ));

        }



        // Check if we have the required protocol

        if !self.protocols.contains_key(&config.computation_type) {

            return Err(FortressError::encryption(

                format!("Protocol '{}' not available", config.computation_type),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ));

        }



        // Validate secret sharing scheme

        match &config.sharing_scheme {

            crate::mpc::SecretSharingScheme::Shamir { threshold, total_shares } => {

                if *threshold == 0 || *total_shares == 0 {

                    return Err(FortressError::encryption(

                        "Threshold and total shares must be greater than 0".to_string(),

                        "mpc_manager".to_string(),

                        EncryptionErrorCode::AlgorithmNotSupported,

                    ));

                }

                if *threshold > *total_shares {

                    return Err(FortressError::encryption(

                        "Threshold cannot be greater than total shares".to_string(),

                        "mpc_manager".to_string(),

                        EncryptionErrorCode::AlgorithmNotSupported,

                    ));

                }

            }

            crate::mpc::SecretSharingScheme::Additive { num_parties } => {

                if *num_parties == 0 {

                    return Err(FortressError::encryption(

                        "Number of parties must be greater than 0".to_string(),

                        "mpc_manager".to_string(),

                        EncryptionErrorCode::AlgorithmNotSupported,

                    ));

                }

            }

            crate::mpc::SecretSharingScheme::Replicated { replicas, threshold } => {

                if *replicas == 0 || *threshold == 0 {

                    return Err(FortressError::encryption(

                        "Replicas and threshold must be greater than 0".to_string(),

                        "mpc_manager".to_string(),

                        EncryptionErrorCode::AlgorithmNotSupported,

                    ));

                }

                if *threshold > *replicas {

                    return Err(FortressError::encryption(

                        "Threshold cannot be greater than replicas".to_string(),

                        "mpc_manager".to_string(),

                        EncryptionErrorCode::AlgorithmNotSupported,

                    ));

                }

            }

        }



        Ok(())

    }



    /// Check if session is ready to start computation

    async fn is_ready_to_start(&self, session_state: &SessionState) -> bool {

        // Check if we have enough parties

        let required_parties = match &session_state.config.sharing_scheme {

            crate::mpc::SecretSharingScheme::Shamir { total_shares, .. } => *total_shares,

            crate::mpc::SecretSharingScheme::Additive { num_parties } => *num_parties,

            crate::mpc::SecretSharingScheme::Replicated { replicas, .. } => *replicas,

        };



        session_state.parties.len() >= required_parties &&

        matches!(session_state.status, ComputationStatus::Recruiting)

    }

}



#[async_trait]

impl MpcManager for DefaultMpcManager {

    async fn create_session(&self, config: ComputationConfig) -> Result<SessionId> {

        // Validate configuration

        self.validate_config(&config)?;



        let session_id = config.session_id.clone();

        let session_state = SessionState::new(config);



        // Store session

        let mut sessions = self.sessions.write().await;

        sessions.insert(session_id.clone(), session_state);



        Ok(session_id)

    }



    async fn join_session(&self, session_id: &SessionId, party: Box<dyn MpcParty>) -> Result<()> {

        let mut sessions = self.sessions.write().await;

        let session_state = sessions.get_mut(session_id)

            .ok_or_else(|| FortressError::encryption(

                format!("Session '{}' not found", session_id),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ))?;



        // Check if session is in recruiting state

        if !matches!(session_state.status, ComputationStatus::Recruiting | ComputationStatus::Preparing) {

            return Err(FortressError::encryption(

                format!("Session '{}' is not accepting new parties", session_id),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ));

        }



        let party_id = party.party_id().clone();

        let party_arc = Arc::from(party);



        // Add party to session

        session_state.add_party(party_id.clone(), party_arc);



        // Update status to recruiting if this is the first party

        if session_state.parties.len() == 1 {

            session_state.update_status(ComputationStatus::Recruiting);

        }



        // Check if ready to start

        if self.is_ready_to_start(session_state).await {

            session_state.update_status(ComputationStatus::InProgress);

        }



        Ok(())

    }



    async fn leave_session(&self, session_id: &SessionId, party_id: &PartyId) -> Result<()> {

        let mut sessions = self.sessions.write().await;

        let session_state = sessions.get_mut(session_id)

            .ok_or_else(|| FortressError::encryption(

                format!("Session '{}' not found", session_id),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ))?;



        // Remove party from session

        session_state.remove_party(party_id);



        // Update status based on remaining parties

        if session_state.parties.is_empty() {

            session_state.update_status(ComputationStatus::Preparing);

        } else if matches!(session_state.status, ComputationStatus::InProgress) {

            session_state.update_status(ComputationStatus::Recruiting);

        }



        Ok(())

    }



    async fn get_session_status(&self, session_id: &SessionId) -> Result<ComputationStatus> {

        let sessions = self.sessions.read().await;

        let session_state = sessions.get(session_id)

            .ok_or_else(|| FortressError::encryption(

                format!("Session '{}' not found", session_id),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ))?;



        Ok(session_state.status.clone())

    }



    async fn start_computation(&self, session_id: &SessionId) -> Result<()> {

        let mut sessions = self.sessions.write().await;

        let session_state = sessions.get_mut(session_id)

            .ok_or_else(|| FortressError::encryption(

                format!("Session '{}' not found", session_id),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ))?;



        // Check if ready to start

        if !self.is_ready_to_start(session_state).await {

            return Err(FortressError::encryption(

                format!("Session '{}' is not ready to start computation", session_id),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ));

        }



        // Get protocol

        let protocol = self.get_protocol(&session_state.config.computation_type)?;



        // Initialize protocol

        protocol.initialize(&session_state.config).await?;



        // Update status

        session_state.update_status(ComputationStatus::InProgress);



        // For now, we'll just mark as completed

        // In a real implementation, you'd coordinate the actual computation

        session_state.update_status(ComputationStatus::Completed);



        Ok(())

    }



    async fn get_result(&self, session_id: &SessionId) -> Result<Option<ComputationResult>> {

        let sessions = self.sessions.read().await;

        let session_state = sessions.get(session_id)

            .ok_or_else(|| FortressError::encryption(

                format!("Session '{}' not found", session_id),

                "mpc_manager".to_string(),

                EncryptionErrorCode::AlgorithmNotSupported,

            ))?;



        Ok(session_state.result.clone())

    }



    async fn list_sessions(&self) -> Result<Vec<SessionId>> {

        let sessions = self.sessions.read().await;

        Ok(sessions.keys().cloned().collect())

    }

}



/// Builder for MPC manager

pub struct MpcManagerBuilder {

    network: Option<Arc<dyn MpcNetwork>>,

    protocols: Option<HashMap<String, Box<dyn MpcProtocol>>>,

    default_protocol: Option<String>,

}



impl MpcManagerBuilder {

    /// Create a new builder

    pub fn new() -> Self {

        Self {

            network: None,

            protocols: None,

            default_protocol: None,

        }

    }



    /// Set the network

    pub fn with_network(mut self, network: Arc<dyn MpcNetwork>) -> Self {

        self.network = Some(network);

        self

    }



    /// Set the protocols

    pub fn with_protocols(mut self, protocols: HashMap<String, Box<dyn MpcProtocol>>) -> Self {

        self.protocols = Some(protocols);

        self

    }



    /// Set the default protocol

    pub fn with_default_protocol(mut self, protocol: impl Into<String>) -> Self {

        self.default_protocol = Some(protocol.into());

        self

    }



    /// Build the MPC manager

    pub fn build(self) -> Result<DefaultMpcManager> {

        let network = self.network.unwrap_or_else(|| Arc::new(InMemoryMpcNetwork::new()));

        

        let protocols = self.protocols.unwrap_or_else(|| {

            let mut p = HashMap::new();

            p.insert("shamir".to_string(), Box::new(ShamirSecretSharing::new().unwrap()) as Box<dyn MpcProtocol>);

            p

        });



        let mut manager = DefaultMpcManager::with_protocols(network, protocols);



        if let Some(default_protocol) = self.default_protocol {

            manager = manager.with_default_protocol(default_protocol);

        }



        Ok(manager)

    }

}



impl Default for MpcManagerBuilder {

    fn default() -> Self {

        Self::new()

    }

}



#[cfg(test)]

mod tests {

    use super::*;

    use crate::mpc::{PartyRole, SecretSharingScheme};



    #[tokio::test]

    async fn test_mpc_manager_creation() {

        let manager = DefaultMpcManager::new().unwrap();

        assert_eq!(manager.default_protocol, "shamir");

        assert!(manager.protocols.contains_key("shamir"));

    }



    #[tokio::test]

    async fn test_session_creation() {

        let manager = DefaultMpcManager::new().unwrap();

        

        let config = ComputationConfig::new(

            "shamir",

            SecretSharingScheme::Shamir {

                threshold: 2,

                total_shares: 3,

            },

        )

        .with_party("party1".to_string(), PartyRole::Initiator)

        .with_party("party2".to_string(), PartyRole::Participant);



        let session_id = manager.create_session(config).await.unwrap();

        assert!(!session_id.is_empty());



        let status = manager.get_session_status(&session_id).await.unwrap();

        assert_eq!(status, ComputationStatus::Preparing);

    }



    #[tokio::test]

    async fn test_session_joining() {

        let manager = DefaultMpcManager::new().unwrap();

        

        let config = ComputationConfig::new(

            "shamir",

            SecretSharingScheme::Shamir {

                threshold: 2,

                total_shares: 2,

            },

        )

        .with_party("party1".to_string(), PartyRole::Initiator)

        .with_party("party2".to_string(), PartyRole::Participant);



        let session_id = manager.create_session(config).await.unwrap();



        // Create parties

        let party1 = Arc::new(InMemoryMpcParty::new("party1".to_string(), PartyRole::Initiator));

        let party2 = Arc::new(InMemoryMpcParty::new("party2".to_string(), PartyRole::Participant));



        // Join session

        manager.join_session(&session_id, Box::new(party1.as_ref().clone())).await.unwrap();

        

        let status = manager.get_session_status(&session_id).await.unwrap();

        assert_eq!(status, ComputationStatus::Recruiting);



        manager.join_session(&session_id, Box::new(party2.as_ref().clone())).await.unwrap();

        

        let status = manager.get_session_status(&session_id).await.unwrap();

        assert_eq!(status, ComputationStatus::InProgress);

    }



    #[tokio::test]

    async fn test_session_listing() {

        let manager = DefaultMpcManager::new().unwrap();

        

        let config1 = ComputationConfig::new(

            "shamir",

            SecretSharingScheme::Shamir {

                threshold: 2,

                total_shares: 3,

            },

        );

        

        let config2 = ComputationConfig::new(

            "shamir",

            SecretSharingScheme::Additive { num_parties: 2 },

        );



        let session1 = manager.create_session(config1).await.unwrap();

        let session2 = manager.create_session(config2).await.unwrap();



        let sessions = manager.list_sessions().await.unwrap();

        assert_eq!(sessions.len(), 2);

        assert!(sessions.contains(&session1));

        assert!(sessions.contains(&session2));

    }



    #[test]

    fn test_mpc_manager_builder() {

        let builder = MpcManagerBuilder::new()

            .with_default_protocol("shamir");

        

        let manager = builder.build().unwrap();

        assert_eq!(manager.default_protocol, "shamir");

    }

}

