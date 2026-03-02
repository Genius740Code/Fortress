//! MPC Network implementation
//!
//! This module provides the default implementation of the MpcNetwork trait
//! with in-memory message passing between parties.

use crate::error::{FortressError, Result, EncryptionErrorCode};
use crate::mpc::{MpcNetwork, PartyId, MpcMessage};

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory implementation of MPC network
pub struct InMemoryMpcNetwork {
    /// Message boxes for each party
    message_boxes: Arc<RwLock<HashMap<PartyId, Vec<MpcMessage>>>>,
    /// Connected parties
    connected_parties: Arc<RwLock<Vec<PartyId>>>,
    /// Network metadata
    metadata: Arc<RwLock<HashMap<String, String>>>,
}

impl InMemoryMpcNetwork {
    /// Create a new in-memory MPC network
    pub fn new() -> Self {
        Self {
            message_boxes: Arc::new(RwLock::new(HashMap::new())),
            connected_parties: Arc::new(RwLock::new(Vec::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with initial parties
    pub fn with_parties(parties: Vec<PartyId>) -> Self {
        let network = Self::new();
        
        // Initialize message boxes for each party
        let mut message_boxes = HashMap::new();
        for party in &parties {
            message_boxes.insert(party.clone(), Vec::new());
        }
        
        *network.message_boxes.blocking_write() = message_boxes;
        *network.connected_parties.blocking_write() = parties;
        
        network
    }

    /// Add a party to the network
    pub async fn add_party(&self, party_id: PartyId) -> Result<()> {
        let mut message_boxes = self.message_boxes.write().await;
        let mut connected_parties = self.connected_parties.write().await;
        
        // Check if party already exists
        if message_boxes.contains_key(&party_id) {
            return Err(FortressError::encryption(
                format!("Party '{}' already connected", party_id),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }
        
        // Add message box for the party
        message_boxes.insert(party_id.clone(), Vec::new());
        connected_parties.push(party_id);
        
        Ok(())
    }

    /// Remove a party from the network
    pub async fn remove_party(&self, party_id: &PartyId) -> Result<()> {
        let mut message_boxes = self.message_boxes.write().await;
        let mut connected_parties = self.connected_parties.write().await;
        
        // Remove message box
        message_boxes.remove(party_id);
        
        // Remove from connected parties
        connected_parties.retain(|p| p != party_id);
        
        Ok(())
    }

    /// Check if a party is connected
    pub async fn is_connected(&self, party_id: &PartyId) -> bool {
        let message_boxes = self.message_boxes.read().await;
        message_boxes.contains_key(party_id)
    }

    /// Get message count for a party
    pub async fn message_count(&self, party_id: &PartyId) -> usize {
        let message_boxes = self.message_boxes.read().await;
        message_boxes.get(party_id).map(|msgs| msgs.len()).unwrap_or(0)
    }

    /// Clear all messages for a party
    pub async fn clear_messages(&self, party_id: &PartyId) -> Result<Vec<MpcMessage>> {
        let mut message_boxes = self.message_boxes.write().await;
        match message_boxes.get_mut(party_id) {
            Some(messages) => {
                let cleared = messages.drain(..).collect();
                Ok(cleared)
            }
            None => Err(FortressError::encryption(
                format!("Party '{}' not found", party_id),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            )),
        }
    }

    /// Add network metadata
    pub async fn add_metadata(&self, key: impl Into<String>, value: impl Into<String>) {
        let mut metadata = self.metadata.write().await;
        metadata.insert(key.into(), value.into());
    }

    /// Get network metadata
    pub async fn get_metadata(&self) -> HashMap<String, String> {
        self.metadata.read().await.clone()
    }

    /// Get total message count across all parties
    pub async fn total_message_count(&self) -> usize {
        let message_boxes = self.message_boxes.read().await;
        message_boxes.values().map(|msgs| msgs.len()).sum()
    }

    /// Validate message before sending
    fn validate_message(&self, message: &MpcMessage) -> Result<()> {
        if message.id.is_empty() {
            return Err(FortressError::encryption(
                "Message ID cannot be empty".to_string(),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }

        if message.session_id.is_empty() {
            return Err(FortressError::encryption(
                "Session ID cannot be empty".to_string(),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }

        if message.sender.is_empty() {
            return Err(FortressError::encryption(
                "Sender cannot be empty".to_string(),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }

        if message.message_type.is_empty() {
            return Err(FortressError::encryption(
                "Message type cannot be empty".to_string(),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }

        Ok(())
    }

    /// Route message to appropriate recipients
    async fn route_message(&self, message: MpcMessage) -> Result<()> {
        match &message.recipient {
            Some(recipient) => {
                // Send to specific recipient
                let recipient = recipient.clone();
                self.send_to_party(&recipient, message).await
            }
            None => {
                // Broadcast to all parties except sender
                self.broadcast_to_all(message).await
            }
        }
    }

    /// Send message to specific party
    async fn send_to_party(&self, recipient: &PartyId, message: MpcMessage) -> Result<()> {
        let mut message_boxes = self.message_boxes.write().await;
        
        match message_boxes.get_mut(recipient) {
            Some(messages) => {
                messages.push(message);
                Ok(())
            }
            None => Err(FortressError::encryption(
                format!("Recipient party '{}' not found", recipient),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            )),
        }
    }

    /// Broadcast message to all parties except sender
    async fn broadcast_to_all(&self, message: MpcMessage) -> Result<()> {
        let mut message_boxes = self.message_boxes.write().await;
        let sender = &message.sender;
        
        let mut sent_count = 0;
        let mut errors = Vec::new();
        
        for (party_id, messages) in message_boxes.iter_mut() {
            if party_id != sender {
                messages.push(message.clone());
                sent_count += 1;
            }
        }
        
        if sent_count == 0 {
            errors.push("No recipients found (sender might be the only party)".to_string());
        }
        
        if !errors.is_empty() {
            return Err(FortressError::encryption(
                format!("Broadcast failed: {}", errors.join(", ")),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }
        
        Ok(())
    }
}

impl Default for InMemoryMpcNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MpcNetwork for InMemoryMpcNetwork {
    async fn send_message(&self, message: MpcMessage) -> Result<()> {
        // Validate message
        self.validate_message(&message)?;
        
        // Check if sender is connected
        if !self.is_connected(&message.sender).await {
            return Err(FortressError::encryption(
                format!("Sender party '{}' is not connected", message.sender),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }
        
        // Route message
        self.route_message(message).await
    }

    async fn broadcast_message(&self, message: MpcMessage) -> Result<()> {
        // Validate message
        self.validate_message(&message)?;
        
        // Check if sender is connected
        if !self.is_connected(&message.sender).await {
            return Err(FortressError::encryption(
                format!("Sender party '{}' is not connected", message.sender),
                "mpc_network".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }
        
        // Create broadcast message (no specific recipient)
        let broadcast_msg = MpcMessage {
            recipient: None,
            ..message
        };
        
        // Route to all parties
        self.broadcast_to_all(broadcast_msg).await
    }

    async fn receive_messages(&self, party_id: &PartyId) -> Result<Vec<MpcMessage>> {
        let messages = self.clear_messages(party_id).await?;
        Ok(messages)
    }

    async fn get_connected_parties(&self) -> Result<Vec<PartyId>> {
        let connected_parties = self.connected_parties.read().await;
        Ok(connected_parties.clone())
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    /// Number of connected parties
    pub connected_parties: usize,
    /// Total messages in network
    pub total_messages: usize,
    /// Messages per party
    pub messages_per_party: HashMap<PartyId, usize>,
    /// Network metadata
    pub metadata: HashMap<String, String>,
}

impl InMemoryMpcNetwork {
    /// Get network statistics
    pub async fn get_stats(&self) -> NetworkStats {
        let message_boxes = self.message_boxes.read().await;
        let connected_parties = self.connected_parties.read().await;
        let metadata = self.metadata.read().await;
        
        let mut messages_per_party = HashMap::new();
        let mut total_messages = 0;
        
        for (party_id, messages) in message_boxes.iter() {
            let count = messages.len();
            messages_per_party.insert(party_id.clone(), count);
            total_messages += count;
        }
        
        NetworkStats {
            connected_parties: connected_parties.len(),
            total_messages,
            messages_per_party,
            metadata: metadata.clone(),
        }
    }

    /// Reset network (clear all messages and parties)
    pub async fn reset(&self) -> Result<()> {
        let mut message_boxes = self.message_boxes.write().await;
        let mut connected_parties = self.connected_parties.write().await;
        
        message_boxes.clear();
        connected_parties.clear();
        
        Ok(())
    }

    /// Simulate network delay (for testing)
    pub async fn simulate_delay(&self, delay_ms: u64) {
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
    }

    /// Simulate network partition (disconnect parties)
    pub async fn simulate_partition(&self, party_ids: &[PartyId]) -> Result<()> {
        for party_id in party_ids {
            self.remove_party(party_id).await?;
        }
        Ok(())
    }

    /// Heal network partition (reconnect parties)
    pub async fn heal_partition(&self, party_ids: &[PartyId]) -> Result<()> {
        for party_id in party_ids {
            self.add_party(party_id.clone()).await?;
        }
        Ok(())
    }
}

/// Builder for MPC network
pub struct MpcNetworkBuilder {
    parties: Vec<PartyId>,
    metadata: HashMap<String, String>,
}

impl MpcNetworkBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            parties: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a party
    pub fn with_party(mut self, party_id: PartyId) -> Self {
        self.parties.push(party_id);
        self
    }

    /// Add multiple parties
    pub fn with_parties(mut self, parties: Vec<PartyId>) -> Self {
        self.parties.extend(parties);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the network
    pub fn build(self) -> InMemoryMpcNetwork {
        let network = InMemoryMpcNetwork::with_parties(self.parties);
        
        // Add metadata
        {
            let mut metadata = network.metadata.blocking_write();
            for (key, value) in self.metadata {
                metadata.insert(key, value);
            }
        }
        
        network
    }
}

impl Default for MpcNetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_creation() {
        let network = InMemoryMpcNetwork::new();
        
        let parties = network.get_connected_parties().await.unwrap();
        assert!(parties.is_empty());
        
        let stats = network.get_stats().await;
        assert_eq!(stats.connected_parties, 0);
        assert_eq!(stats.total_messages, 0);
    }

    #[tokio::test]
    async fn test_party_management() {
        let network = InMemoryMpcNetwork::new();
        
        // Add parties
        network.add_party("party1".to_string()).await.unwrap();
        network.add_party("party2".to_string()).await.unwrap();
        
        let parties = network.get_connected_parties().await.unwrap();
        assert_eq!(parties.len(), 2);
        assert!(parties.contains(&"party1".to_string()));
        assert!(parties.contains(&"party2".to_string()));
        
        // Check connection status
        assert!(network.is_connected(&"party1".to_string()).await);
        assert!(network.is_connected(&"party2".to_string()).await);
        assert!(!network.is_connected(&"party3".to_string()).await);
        
        // Remove party
        network.remove_party(&"party1".to_string()).await.unwrap();
        let parties = network.get_connected_parties().await.unwrap();
        assert_eq!(parties.len(), 1);
        assert!(!parties.contains(&"party1".to_string()));
    }

    #[tokio::test]
    async fn test_message_sending() {
        let network = InMemoryMpcNetwork::new();
        
        // Add parties
        network.add_party("party1".to_string()).await.unwrap();
        network.add_party("party2".to_string()).await.unwrap();
        
        // Send message from party1 to party2
        let message = MpcMessage::new(
            "session1".to_string(),
            "party1".to_string(),
            Some("party2".to_string()),
            "test".to_string(),
            b"hello".to_vec(),
        );
        
        network.send_message(message).await.unwrap();
        
        // Check message count
        assert_eq!(network.message_count(&"party1".to_string()).await, 0);
        assert_eq!(network.message_count(&"party2".to_string()).await, 1);
        
        // Receive message
        let messages = network.receive_messages(&"party2".to_string()).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].sender, "party1");
        assert_eq!(messages[0].recipient, Some("party2".to_string()));
        
        // Message should be cleared
        assert_eq!(network.message_count(&"party2".to_string()).await, 0);
    }

    #[tokio::test]
    async fn test_message_broadcast() {
        let network = InMemoryMpcNetwork::new();
        
        // Add parties
        network.add_party("party1".to_string()).await.unwrap();
        network.add_party("party2".to_string()).await.unwrap();
        network.add_party("party3".to_string()).await.unwrap();
        
        // Broadcast message from party1
        let message = MpcMessage::new(
            "session1".to_string(),
            "party1".to_string(),
            None, // No recipient = broadcast
            "broadcast".to_string(),
            b"hello everyone".to_vec(),
        );
        
        network.broadcast_message(message).await.unwrap();
        
        // Check message counts (sender should not receive their own broadcast)
        assert_eq!(network.message_count(&"party1".to_string()).await, 0);
        assert_eq!(network.message_count(&"party2".to_string()).await, 1);
        assert_eq!(network.message_count(&"party3".to_string()).await, 1);
    }

    #[tokio::test]
    async fn test_network_stats() {
        let network = InMemoryMpcNetwork::new();
        
        // Add parties
        network.add_party("party1".to_string()).await.unwrap();
        network.add_party("party2".to_string()).await.unwrap();
        
        // Send some messages
        let message1 = MpcMessage::new(
            "session1".to_string(),
            "party1".to_string(),
            Some("party2".to_string()),
            "test1".to_string(),
            b"message1".to_vec(),
        );
        
        let message2 = MpcMessage::new(
            "session1".to_string(),
            "party2".to_string(),
            Some("party1".to_string()),
            "test2".to_string(),
            b"message2".to_vec(),
        );
        
        network.send_message(message1).await.unwrap();
        network.send_message(message2).await.unwrap();
        
        // Get stats
        let stats = network.get_stats().await;
        assert_eq!(stats.connected_parties, 2);
        assert_eq!(stats.total_messages, 2);
        assert_eq!(stats.messages_per_party.get("party1"), Some(&1));
        assert_eq!(stats.messages_per_party.get("party2"), Some(&1));
    }

    #[tokio::test]
    async fn test_network_builder() {
        let network = MpcNetworkBuilder::new()
            .with_party("party1".to_string())
            .with_party("party2".to_string())
            .with_metadata("region", "us-east-1")
            .build();
        
        let parties = network.get_connected_parties().await.unwrap();
        assert_eq!(parties.len(), 2);
        
        let metadata = network.get_metadata().await;
        assert_eq!(metadata.get("region"), Some(&"us-east-1".to_string()));
    }

    #[tokio::test]
    async fn test_network_reset() {
        let network = InMemoryMpcNetwork::new();
        
        // Add parties and messages
        network.add_party("party1".to_string()).await.unwrap();
        network.add_party("party2".to_string()).await.unwrap();
        
        let message = MpcMessage::new(
            "session1".to_string(),
            "party1".to_string(),
            Some("party2".to_string()),
            "test".to_string(),
            b"hello".to_vec(),
        );
        
        network.send_message(message).await.unwrap();
        
        // Reset network
        network.reset().await.unwrap();
        
        // Check everything is cleared
        let parties = network.get_connected_parties().await.unwrap();
        assert!(parties.is_empty());
        
        let stats = network.get_stats().await;
        assert_eq!(stats.connected_parties, 0);
        assert_eq!(stats.total_messages, 0);
    }
}
