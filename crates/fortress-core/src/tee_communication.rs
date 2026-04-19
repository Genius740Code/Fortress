//! Secure Enclave Communication Protocols
//!
//! This module provides secure communication protocols for TEE enclaves,
//! including encrypted messaging, authentication, and key exchange mechanisms.

use crate::error::{FortressError, Result};
use crate::key::SecureKey;
use crate::tee::SecureChannel;
use rand::RngCore;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};

/// Secure message types for enclave communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureMessageType {
    /// Key exchange initiation
    KeyExchangeInit,
    /// Key exchange response
    KeyExchangeResponse,
    /// Encrypted data message
    EncryptedData,
    /// Authentication challenge
    AuthChallenge,
    /// Authentication response
    AuthResponse,
    /// Heartbeat/ping
    Heartbeat,
    /// Key rotation request
    KeyRotation,
    /// Session termination
    SessionTerminate,
}

/// Secure message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessageHeader {
    /// Message type
    pub message_type: SecureMessageType,
    /// Message ID
    pub message_id: String,
    /// Channel ID
    pub channel_id: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Sequence number
    pub sequence_number: u64,
    /// Message version
    pub version: u32,
}

/// Encrypted message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Encrypted data (base64 encoded)
    pub encrypted_data: String,
    /// Authentication tag
    pub auth_tag: String,
    /// Nonce
    pub nonce: String,
    /// Additional authenticated data
    pub aad: Option<String>,
}

/// Complete secure message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessage {
    /// Message header
    pub header: SecureMessageHeader,
    /// Encrypted payload
    pub payload: EncryptedPayload,
    /// Message signature
    pub signature: String,
}

/// Key exchange protocol data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeData {
    /// Public key (base64 encoded)
    pub public_key: String,
    /// Key exchange algorithm
    pub algorithm: String,
    /// Key parameters
    pub parameters: HashMap<String, String>,
    /// Nonce
    pub nonce: String,
}

/// Authentication data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthData {
    /// Authentication token
    pub token: String,
    /// Authentication method
    pub method: String,
    /// Challenge response
    pub challenge_response: Option<String>,
    /// Additional claims
    pub claims: HashMap<String, String>,
}

/// Secure communication protocol handler
pub struct SecureProtocolHandler {
    /// Active secure channels
    channels: Arc<RwLock<HashMap<String, ChannelState>>>,
    /// Protocol configuration
    config: ProtocolConfig,
}

/// Channel state for secure communication
#[derive(Debug, Clone)]
pub struct ChannelState {
    /// Channel information
    channel: SecureChannel,
    /// Current sequence number
    sequence_number: u64,
    /// Last activity timestamp
    last_activity: chrono::DateTime<chrono::Utc>,
    /// Channel encryption key
    encryption_key: SecureKey,
    /// Channel authentication key
    auth_key: SecureKey,
    /// Channel status
    is_active: bool,
}

/// Protocol configuration
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Message timeout in seconds
    pub message_timeout: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Maximum sequence number before rollover
    pub max_sequence_number: u64,
    /// Require message signing
    pub require_message_signing: bool,
    /// Enable message compression
    pub enable_compression: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            message_timeout: 300,        // 5 minutes
            max_message_size: 1024 * 1024, // 1MB
            heartbeat_interval: 60,       // 1 minute
            key_rotation_interval: 3600,  // 1 hour
            max_sequence_number: u64::MAX - 1,
            require_message_signing: true,
            enable_compression: true,
        }
    }
}

impl SecureProtocolHandler {
    /// Create a new secure protocol handler
    pub fn new(config: ProtocolConfig) -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Initialize a new secure channel
    pub async fn initialize_channel(&self, channel: SecureChannel) -> Result<()> {
        let channel_state = ChannelState {
            channel: channel.clone(),
            sequence_number: 0,
            last_activity: chrono::Utc::now(),
            encryption_key: channel.session_key.clone(),
            auth_key: SecureKey::generate(32).expect("Failed to generate secure key"), // Separate auth key
            is_active: true,
        };
        
        let mut channels = self.channels.write().await;
        channels.insert(channel.channel_id.clone(), channel_state);
        
        Ok(())
    }
    
    /// Create secure message
    pub async fn create_message(
        &self,
        channel_id: &str,
        message_type: SecureMessageType,
        data: &[u8],
    ) -> Result<SecureMessage> {
        let channels = self.channels.read().await;
        let channel_state = channels.get(channel_id)
            .ok_or_else(|| FortressError::tee(
                format!("Channel not found: {}", channel_id),
                "SecureProtocolHandler::create_message".to_string()
            ))?;
        
        if !channel_state.is_active {
            return Err(FortressError::tee(
                format!("Channel is not active: {}", channel_id),
                "SecureProtocolHandler::create_message".to_string()
            ));
        }
        
        // Create message header
        let header = SecureMessageHeader {
            message_type: message_type.clone(),
            message_id: Uuid::new_v4().to_string(),
            channel_id: channel_id.to_string(),
            timestamp: chrono::Utc::now(),
            sequence_number: channel_state.sequence_number + 1,
            version: 1,
        };
        
        // Encrypt payload
        let encrypted_payload = self.encrypt_payload(
            &channel_state.encryption_key,
            data,
            &header,
        ).await?;
        
        // Create message
        let message = SecureMessage {
            header,
            payload: encrypted_payload,
            signature: String::new(), // Will be added below
        };
        
        // Sign message
        let signed_message = self.sign_message(&channel_state.auth_key, &message).await?;
        
        Ok(signed_message)
    }
    
    /// Process incoming secure message
    pub async fn process_message(
        &self,
        message: SecureMessage,
    ) -> Result<(SecureMessageType, Vec<u8>)> {
        // Verify message signature
        let channels = self.channels.read().await;
        let channel_state = channels.get(&message.header.channel_id)
            .ok_or_else(|| FortressError::tee(
                format!("Channel not found: {}", message.header.channel_id),
                "SecureProtocolHandler::process_message".to_string()
            ))?;
        
        self.verify_message_signature(&channel_state.auth_key, &message).await?;
        
        // Verify message timestamp
        let now = chrono::Utc::now();
        let age = (now - message.header.timestamp).num_seconds();
        if age > self.config.message_timeout as i64 {
            return Err(FortressError::tee(
                format!("Message timestamp too old: {} seconds", age),
                "SecureProtocolHandler::process_message".to_string()
            ));
        }
        
        // Decrypt payload
        let decrypted_data = self.decrypt_payload(
            &channel_state.encryption_key,
            &message.payload,
            &message.header,
        ).await?;
        
        // Update channel activity
        drop(channels);
        let mut channels = self.channels.write().await;
        if let Some(channel_state) = channels.get_mut(&message.header.channel_id) {
            channel_state.last_activity = now;
            channel_state.sequence_number = message.header.sequence_number;
        }
        
        Ok((message.header.message_type, decrypted_data))
    }
    
    /// Encrypt payload
    async fn encrypt_payload(
        &self,
        key: &SecureKey,
        data: &[u8],
        header: &SecureMessageHeader,
    ) -> Result<EncryptedPayload> {
        // Apply compression if enabled
        let _processed_data = if self.config.enable_compression {
            self.compress_data(data).await?
        } else {
            data.to_vec()
        };
        
        // Create additional authenticated data from header
        let aad = serde_json::to_vec(header)
            .map_err(|e| FortressError::tee(
                format!("Failed to serialize header for AAD: {}", e),
                "SecureProtocolHandler::encrypt_payload".to_string()
            ))?;
        
        // Generate nonce
        let nonce_bytes = {
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            nonce
        };
        
        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| FortressError::tee(
                format!("Failed to create cipher: {}", e),
                "SecureProtocolHandler::encrypt_payload".to_string()
            ))?;
        
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, aad.as_ref())
            .map_err(|e| FortressError::tee(
                format!("Failed to encrypt payload: {}", e),
                "SecureProtocolHandler::encrypt_payload".to_string()
            ))?;
        
        // Split ciphertext and tag
        let tag_start = ciphertext.len() - 16; // GCM tag is 16 bytes
        let encrypted_data = ciphertext[..tag_start].to_vec();
        let auth_tag = ciphertext[tag_start..].to_vec();
        
        Ok(EncryptedPayload {
            encrypted_data: general_purpose::STANDARD.encode(&encrypted_data),
            auth_tag: general_purpose::STANDARD.encode(&auth_tag),
            nonce: general_purpose::STANDARD.encode(&nonce_bytes),
            aad: Some(general_purpose::STANDARD.encode(&aad)),
        })
    }
    
    /// Decrypt payload
    async fn decrypt_payload(
        &self,
        key: &SecureKey,
        payload: &EncryptedPayload,
        header: &SecureMessageHeader,
    ) -> Result<Vec<u8>> {
        // Decode base64 data
        let encrypted_data = base64::engine::general_purpose::STANDARD.decode(&payload.encrypted_data)
            .map_err(|e| FortressError::tee(
                format!("Failed to decode encrypted data: {}", e),
                "SecureProtocolHandler::decrypt_payload".to_string()
            ))?;
        
        let auth_tag = base64::engine::general_purpose::STANDARD.decode(&payload.auth_tag)
            .map_err(|e| FortressError::tee(
                format!("Failed to decode auth tag: {}", e),
                "SecureProtocolHandler::decrypt_payload".to_string()
            ))?;
        
        let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&payload.nonce)
            .map_err(|e| FortressError::tee(
                format!("Failed to decode nonce: {}", e),
                "SecureProtocolHandler::decrypt_payload".to_string()
            ))?;
        
        // Recombine ciphertext and tag
        let mut ciphertext = encrypted_data;
        ciphertext.extend_from_slice(&auth_tag);
        
        // Get AAD
        let aad_result = if let Some(ref aad_str) = payload.aad {
            general_purpose::STANDARD.decode(aad_str)
                .map_err(|e| FortressError::tee(
                    format!("Failed to decode AAD: {}", e),
                    "SecureProtocolHandler::decrypt_payload".to_string()
                ))
        } else {
            serde_json::to_vec(header)
                .map_err(|e| FortressError::tee(
                    format!("Failed to serialize header for AAD: {}", e),
                    "SecureProtocolHandler::decrypt_payload".to_string()
                ))
        };
        
        // Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| FortressError::tee(
                format!("Failed to create cipher: {}", e),
                "SecureProtocolHandler::decrypt_payload".to_string()
            ))?;
        
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad_vec = aad_result.unwrap_or(vec![]);
        let plaintext = cipher.decrypt(nonce, aad_vec.as_ref())
            .map_err(|e| FortressError::tee(
                format!("Failed to decrypt payload: {}", e),
                "SecureProtocolHandler::decrypt_payload".to_string()
            ))?;
        
        // Apply decompression if enabled
        if self.config.enable_compression {
            self.decompress_data(&plaintext).await
        } else {
            Ok(plaintext)
        }
    }
    
    /// Sign message
    async fn sign_message(&self, key: &SecureKey, message: &SecureMessage) -> Result<SecureMessage> {
        if !self.config.require_message_signing {
            return Ok(message.clone());
        }
        
        // Serialize message without signature
        let message_bytes = serde_json::to_vec(&SecureMessage {
            header: message.header.clone(),
            payload: message.payload.clone(),
            signature: String::new(),
        }).map_err(|e| FortressError::tee(
            format!("Failed to serialize message for signing: {}", e),
            "SecureProtocolHandler::sign_message".to_string()
        ))?;
        
        // Sign with HMAC-SHA256
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key.as_bytes())
            .map_err(|e| FortressError::tee(
                format!("Failed to create HMAC: {}", e),
                "SecureProtocolHandler::sign_message".to_string()
            ))?;
        
        mac.update(&message_bytes);
        let signature = mac.finalize().into_bytes();
        
        Ok(SecureMessage {
            header: message.header.clone(),
            payload: message.payload.clone(),
            signature: general_purpose::STANDARD.encode(&signature),
        })
    }
    
    /// Verify message signature
    async fn verify_message_signature(&self, key: &SecureKey, message: &SecureMessage) -> Result<()> {
        if !self.config.require_message_signing {
            return Ok(());
        }
        
        // Decode signature
        let signature = general_purpose::STANDARD.decode(&message.signature)
            .map_err(|e| FortressError::tee(
                format!("Failed to decode message signature: {}", e),
                "SecureProtocolHandler::verify_message_signature".to_string()
            ))?;
        
        // Serialize message without signature
        let message_bytes = serde_json::to_vec(&SecureMessage {
            header: message.header.clone(),
            payload: message.payload.clone(),
            signature: String::new(),
        }).map_err(|e| FortressError::tee(
            format!("Failed to serialize message for verification: {}", e),
            "SecureProtocolHandler::verify_message_signature".to_string()
        ))?;
        
        // Verify HMAC-SHA256
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key.as_bytes())
            .map_err(|e| FortressError::tee(
                format!("Failed to create HMAC: {}", e),
                "SecureProtocolHandler::verify_message_signature".to_string()
            ))?;
        
        mac.update(&message_bytes);
        mac.verify_slice(&signature)
            .map_err(|e| FortressError::tee(
                format!("Message signature verification failed: {}", e),
                "SecureProtocolHandler::verify_message_signature".to_string()
            ))?;
        
        Ok(())
    }
    
    /// Compress data
    async fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simple compression using flate2
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)
            .map_err(|e| FortressError::tee(
                format!("Failed to compress data: {}", e),
                "SecureProtocolHandler::compress_data".to_string()
            ))?;
        
        encoder.finish()
            .map_err(|e| FortressError::tee(
                format!("Failed to finish compression: {}", e),
                "SecureProtocolHandler::compress_data".to_string()
            ))
    }
    
    /// Decompress data
    async fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::GzDecoder;
        use std::io::Read;
        
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| FortressError::tee(
                format!("Failed to decompress data: {}", e),
                "SecureProtocolHandler::decompress_data".to_string()
            ))?;
        
        Ok(decompressed)
    }
    
    /// Send heartbeat message
    pub async fn send_heartbeat(&self, channel_id: &str) -> Result<SecureMessage> {
        self.create_message(
            channel_id,
            SecureMessageType::Heartbeat,
            b"heartbeat",
        ).await
    }
    
    /// Initiate key rotation
    pub async fn initiate_key_rotation(&self, channel_id: &str) -> Result<SecureMessage> {
        // Generate new session key
        let new_key = SecureKey::generate(32).expect("Failed to generate secure key");
        
        // Create key exchange data
        let key_exchange = KeyExchangeData {
            public_key: general_purpose::STANDARD.encode(new_key.as_bytes()),
            algorithm: "AES-256-GCM".to_string(),
            parameters: HashMap::new(),
            nonce: Uuid::new_v4().to_string(),
        };
        
        let exchange_bytes = serde_json::to_vec(&key_exchange)
            .map_err(|e| FortressError::tee(
                format!("Failed to serialize key exchange data: {}", e),
                "SecureProtocolHandler::initiate_key_rotation".to_string()
            ))?;
        
        self.create_message(
            channel_id,
            SecureMessageType::KeyRotation,
            &exchange_bytes,
        ).await
    }
    
    /// Terminate session
    pub async fn terminate_session(&self, channel_id: &str) -> Result<SecureMessage> {
        let message = self.create_message(
            channel_id,
            SecureMessageType::SessionTerminate,
            b"session_terminate",
        ).await?;
        
        // Mark channel as inactive
        let mut channels = self.channels.write().await;
        if let Some(channel_state) = channels.get_mut(channel_id) {
            channel_state.is_active = false;
        }
        
        Ok(message)
    }
    
    /// Get channel status
    pub async fn get_channel_status(&self, channel_id: &str) -> Option<ChannelState> {
        let channels = self.channels.read().await;
        channels.get(channel_id).cloned()
    }
    
    /// List active channels
    pub async fn list_active_channels(&self) -> Vec<String> {
        let channels = self.channels.read().await;
        channels.keys()
            .filter(|&id| {
                channels.get(id)
                    .map(|state| state.is_active)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }
    
    /// Cleanup inactive channels
    pub async fn cleanup_inactive_channels(&self, timeout_seconds: u64) -> Result<usize> {
        let now = chrono::Utc::now();
        let mut channels = self.channels.write().await;
        
        let initial_count = channels.len();
        channels.retain(|_, state| {
            let age = (now - state.last_activity).num_seconds();
            state.is_active && i64::from(age) < timeout_seconds as i64
        });
        
        Ok(initial_count - channels.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::SecureChannel;
    
    #[tokio::test]
    async fn test_protocol_handler_creation() {
        let config = ProtocolConfig::default();
        let handler = SecureProtocolHandler::new(config);
        
        let active_channels = handler.list_active_channels().await;
        assert!(active_channels.is_empty());
    }
    
    #[tokio::test]
    async fn test_channel_initialization() {
        let config = ProtocolConfig::default();
        let handler = SecureProtocolHandler::new(config);
        
        let channel = SecureChannel {
            channel_id: "test-channel".to_string(),
            enclave_id: "test-enclave".to_string(),
            session_key: SecureKey::generate(32).expect("Failed to generate secure key"),
            created_at: chrono::Utc::now(),
            is_active: true,
        };
        
        let result = handler.initialize_channel(channel).await;
        assert!(result.is_ok());
        
        let active_channels = handler.list_active_channels().await;
        assert_eq!(active_channels.len(), 1);
        assert!(active_channels.contains(&"test-channel".to_string()));
    }
    
    #[tokio::test]
    async fn test_message_creation() {
        let config = ProtocolConfig::default();
        let handler = SecureProtocolHandler::new(config);
        
        let channel = SecureChannel {
            channel_id: "test-channel".to_string(),
            enclave_id: "test-enclave".to_string(),
            session_key: SecureKey::generate(32).expect("Failed to generate secure key"),
            created_at: chrono::Utc::now(),
            is_active: true,
        };
        
        handler.initialize_channel(channel).await.unwrap();
        
        let message = handler.create_message(
            "test-channel",
            SecureMessageType::Heartbeat,
            b"test data",
        ).await;
        
        assert!(message.is_ok());
        let message = message.unwrap();
        
        assert_eq!(message.header.channel_id, "test-channel");
        assert!(matches!(message.header.message_type, SecureMessageType::Heartbeat));
        assert!(!message.signature.is_empty());
    }
    
    #[tokio::test]
    async fn test_message_processing() {
        let config = ProtocolConfig::default();
        let handler = SecureProtocolHandler::new(config);
        
        let channel = SecureChannel {
            channel_id: "test-channel".to_string(),
            enclave_id: "test-enclave".to_string(),
            session_key: SecureKey::generate(32).expect("Failed to generate secure key"),
            created_at: chrono::Utc::now(),
            is_active: true,
        };
        
        handler.initialize_channel(channel).await.unwrap();
        
        let message = handler.create_message(
            "test-channel",
            SecureMessageType::Heartbeat,
            b"test data",
        ).await.unwrap();
        
        let result = handler.process_message(message).await;
        assert!(result.is_ok());
        
        let (message_type, data) = result.unwrap();
        assert!(matches!(message_type, SecureMessageType::Heartbeat));
        assert_eq!(data, b"test data");
    }
    
    #[tokio::test]
    async fn test_compression() {
        let config = ProtocolConfig::default();
        let handler = SecureProtocolHandler::new(config);
        
        let test_data = b"This is test data that should be compressible. ".repeat(10);
        let compressed = handler.compress_data(&test_data).await.unwrap();
        let decompressed = handler.decompress_data(&compressed).await.unwrap();
        
        assert_eq!(test_data, decompressed.as_slice());
    }
}
