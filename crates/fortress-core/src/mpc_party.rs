//! MPC Party implementation
//!
//! This module provides the default implementation of the MpcParty trait
//! with in-memory storage for shares and message processing.

use crate::error::{FortressError, Result, EncryptionErrorCode};
use crate::mpc::{MpcParty, PartyId, PartyRole, SessionId, ShareId, SecretShare, MpcMessage};

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// In-memory implementation of MPC party
pub struct InMemoryMpcParty {
    /// Party identifier
    party_id: PartyId,
    /// Party role
    role: PartyRole,
    /// Shares held by this party
    shares: Arc<RwLock<HashMap<SessionId, HashMap<ShareId, SecretShare>>>>,
    /// Message inbox
    inbox: Arc<RwLock<Vec<MpcMessage>>>,
    /// Message outbox
    outbox: Arc<RwLock<Vec<MpcMessage>>>,
    /// Party metadata
    metadata: Arc<RwLock<HashMap<String, String>>>,
}

impl InMemoryMpcParty {
    /// Create a new in-memory MPC party
    pub fn new(party_id: PartyId, role: PartyRole) -> Self {
        Self {
            party_id,
            role,
            shares: Arc::new(RwLock::new(HashMap::new())),
            inbox: Arc::new(RwLock::new(Vec::new())),
            outbox: Arc::new(RwLock::new(Vec::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with metadata
    pub async fn with_metadata(
        party_id: PartyId,
        role: PartyRole,
        metadata: HashMap<String, String>,
    ) -> Self {
        let party = Self::new(party_id, role);
        *party.metadata.write().await = metadata;
        party
    }

    /// Add metadata
    pub async fn add_metadata(&self, key: impl Into<String>, value: impl Into<String>) {
        let mut metadata = self.metadata.write().await;
        metadata.insert(key.into(), value.into());
    }

    /// Get metadata
    pub async fn get_metadata(&self) -> HashMap<String, String> {
        self.metadata.read().await.clone()
    }

    /// Get message count in inbox
    pub async fn inbox_count(&self) -> usize {
        self.inbox.read().await.len()
    }

    /// Get message count in outbox
    pub async fn outbox_count(&self) -> usize {
        self.outbox.read().await.len()
    }

    /// Clear outbox
    pub async fn clear_outbox(&self) -> Vec<MpcMessage> {
        let mut outbox = self.outbox.write().await;
        outbox.drain(..).collect()
    }

    /// Process all messages in inbox
    pub async fn process_all_messages(&self) -> Result<Vec<MpcMessage>> {
        let mut inbox = self.inbox.write().await;
        let messages = inbox.drain(..).collect::<Vec<_>>();
        drop(inbox);

        let mut responses = Vec::new();
        for message in messages {
            if let Some(response) = self.process_message(message).await? {
                responses.push(response);
            }
        }

        Ok(responses)
    }

    /// Validate share ownership
    fn validate_share_ownership(&self, share: &SecretShare) -> Result<()> {
        if share.party_id != self.party_id {
            return Err(FortressError::encryption(
                format!("Share belongs to party {}, not {}", share.party_id, self.party_id),
                "mpc_party".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }
        Ok(())
    }

    /// Generate share ID
    fn generate_share_id(&self) -> ShareId {
        Uuid::new_v4().to_string()
    }
}

#[async_trait]
impl MpcParty for InMemoryMpcParty {
    fn party_id(&self) -> &PartyId {
        &self.party_id
    }

    fn role(&self) -> PartyRole {
        self.role.clone()
    }

    async fn process_message(&self, message: MpcMessage) -> Result<Option<MpcMessage>> {
        // Check if message is for this party
        if let Some(recipient) = &message.recipient {
            if recipient != &self.party_id {
                return Ok(None);
            }
        }

        // Process different message types
        match message.message_type.as_str() {
            "share_request" => {
                // Handle share request
                let response = MpcMessage::new(
                    message.session_id.clone(),
                    self.party_id.clone(),
                    Some(message.sender.clone()),
                    "share_response".to_string(),
                    b"share_data_placeholder".to_vec(),
                );
                
                // Add to outbox
                let mut outbox = self.outbox.write().await;
                outbox.push(response.clone());
                
                Ok(Some(response))
            }
            
            "share_delivery" => {
                // Handle share delivery
                // In a real implementation, you'd parse the payload and store the share
                Ok(None)
            }
            
            "computation_request" => {
                // Handle computation request
                let response = MpcMessage::new(
                    message.session_id.clone(),
                    self.party_id.clone(),
                    Some(message.sender.clone()),
                    "computation_response".to_string(),
                    b"computation_result_placeholder".to_vec(),
                );
                
                let mut outbox = self.outbox.write().await;
                outbox.push(response.clone());
                
                Ok(Some(response))
            }
            
            "verification_request" => {
                // Handle verification request
                let response = MpcMessage::new(
                    message.session_id.clone(),
                    self.party_id.clone(),
                    Some(message.sender.clone()),
                    "verification_response".to_string(),
                    b"verified".to_vec(),
                );
                
                let mut outbox = self.outbox.write().await;
                outbox.push(response.clone());
                
                Ok(Some(response))
            }
            
            _ => {
                // Unknown message type
                Ok(None)
            }
        }
    }

    async fn get_shares(&self, session_id: &SessionId) -> Result<Vec<SecretShare>> {
        let shares = self.shares.read().await;
        match shares.get(session_id) {
            Some(session_shares) => Ok(session_shares.values().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }

    async fn add_share(&self, share: SecretShare) -> Result<()> {
        // Validate share ownership
        self.validate_share_ownership(&share)?;

        let mut shares = self.shares.write().await;
        let session_shares = shares.entry(share.session_id.clone()).or_insert_with(HashMap::new);
        session_shares.insert(share.id.clone(), share);
        
        Ok(())
    }

    async fn remove_share(&self, share_id: &ShareId) -> Result<()> {
        let mut shares = self.shares.write().await;
        
        // Find and remove the share
        for session_shares in shares.values_mut() {
            if session_shares.remove(share_id).is_some() {
                return Ok(());
            }
        }
        
        Err(FortressError::encryption(
            format!("Share '{}' not found", share_id),
            "mpc_party".to_string(),
            EncryptionErrorCode::AlgorithmNotSupported,
        ))
    }
}

impl Clone for InMemoryMpcParty {
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id.clone(),
            role: self.role.clone(),
            shares: Arc::new(RwLock::new(HashMap::new())),
            inbox: Arc::new(RwLock::new(Vec::new())),
            outbox: Arc::new(RwLock::new(Vec::new())),
            metadata: Arc::new(RwLock::new(self.metadata.blocking_read().clone())),
        }
    }
}

/// Builder for MPC party
pub struct MpcPartyBuilder {
    party_id: Option<PartyId>,
    role: Option<PartyRole>,
    metadata: HashMap<String, String>,
}

impl MpcPartyBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            party_id: None,
            role: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the party ID
    pub fn with_party_id(mut self, party_id: PartyId) -> Self {
        self.party_id = Some(party_id);
        self
    }

    /// Set the party role
    pub fn with_role(mut self, role: PartyRole) -> Self {
        self.role = Some(role);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the MPC party
    pub async fn build(self) -> Result<InMemoryMpcParty> {
        let party_id = self.party_id.ok_or_else(|| {
            FortressError::encryption(
                "Party ID is required".to_string(),
                "mpc_party".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            )
        })?;

        let role = self.role.unwrap_or(PartyRole::Participant);

        let party = InMemoryMpcParty::with_metadata(party_id, role, self.metadata).await;
        Ok(party)
    }
}

impl Default for MpcPartyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Message handler for processing MPC messages
pub struct MessageHandler {
    party: Arc<dyn MpcParty>,
}

impl MessageHandler {
    /// Create a new message handler
    pub fn new(party: Arc<dyn MpcParty>) -> Self {
        Self { party }
    }

    /// Handle incoming message
    pub async fn handle_message(&self, message: MpcMessage) -> Result<Option<MpcMessage>> {
        self.party.process_message(message).await
    }

    /// Get party reference
    pub fn party(&self) -> &Arc<dyn MpcParty> {
        &self.party
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::{SessionId, ShareId};

    #[tokio::test]
    async fn test_mpc_party_creation() {
        let party = InMemoryMpcParty::new("party1".to_string(), PartyRole::Initiator);
        
        assert_eq!(party.party_id(), "party1");
        assert_eq!(party.role(), PartyRole::Initiator);
        assert_eq!(party.inbox_count().await, 0);
        assert_eq!(party.outbox_count().await, 0);
    }

    #[tokio::test]
    async fn test_share_management() {
        let party = InMemoryMpcParty::new("party1".to_string(), PartyRole::Participant);
        let session_id = "session1".to_string();
        
        // Initially no shares
        let shares = party.get_shares(&session_id).await.unwrap();
        assert!(shares.is_empty());
        
        // Add a share
        let share = SecretShare::new(
            "party1".to_string(),
            session_id.clone(),
            b"share_data".to_vec(),
        );
        
        party.add_share(share.clone()).await.unwrap();
        
        // Check share exists
        let shares = party.get_shares(&session_id).await.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].id, share.id);
        
        // Remove share
        party.remove_share(&share.id).await.unwrap();
        
        // Check share removed
        let shares = party.get_shares(&session_id).await.unwrap();
        assert!(shares.is_empty());
    }

    #[tokio::test]
    async fn test_message_processing() {
        let party = InMemoryMpcParty::new("party1".to_string(), PartyRole::Participant);
        
        // Create a message for this party
        let message = MpcMessage::new(
            "session1".to_string(),
            "party2".to_string(),
            Some("party1".to_string()),
            "share_request".to_string(),
            b"request_data".to_vec(),
        );
        
        // Process message
        let response = party.process_message(message).await.unwrap();
        assert!(response.is_some());
        
        // Check outbox
        assert_eq!(party.outbox_count().await, 1);
        
        // Clear outbox
        let outbox_messages = party.clear_outbox().await;
        assert_eq!(outbox_messages.len(), 1);
        assert_eq!(party.outbox_count().await, 0);
    }

    #[tokio::test]
    async fn test_metadata_management() {
        let party = InMemoryMpcParty::new("party1".to_string(), PartyRole::Initiator);
        
        // Add metadata
        party.add_metadata("location", "us-east-1").await;
        party.add_metadata("version", "1.0").await;
        
        // Get metadata
        let metadata = party.get_metadata().await;
        assert_eq!(metadata.get("location"), Some(&"us-east-1".to_string()));
        assert_eq!(metadata.get("version"), Some(&"1.0".to_string()));
    }

    #[tokio::test]
    async fn test_mpc_party_builder() {
        let party = MpcPartyBuilder::new()
            .with_party_id("party1".to_string())
            .with_role(PartyRole::Initiator)
            .with_metadata("region", "us-west-2")
            .build()
            .await
            .unwrap();
        
        assert_eq!(party.party_id(), "party1");
        assert_eq!(party.role(), PartyRole::Initiator);
    }

    #[test]
    fn test_party_clone() {
        let party1 = InMemoryMpcParty::new("party1".to_string(), PartyRole::Participant);
        let party2 = party1.clone();
        
        assert_eq!(party1.party_id(), party2.party_id());
        assert_eq!(party1.role(), party2.role());
    }

    #[tokio::test]
    async fn test_message_handler() {
        let party = Arc::new(InMemoryMpcParty::new("party1".to_string(), PartyRole::Participant));
        let handler = MessageHandler::new(party.clone());
        
        let message = MpcMessage::new(
            "session1".to_string(),
            "party2".to_string(),
            Some("party1".to_string()),
            "share_request".to_string(),
            b"test".to_vec(),
        );
        
        let response = handler.handle_message(message).await.unwrap();
        assert!(response.is_some());
        assert_eq!(handler.party().party_id(), "party1");
    }
}
