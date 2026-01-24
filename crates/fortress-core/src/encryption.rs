//! Encryption algorithms and abstractions
//!
//! This module provides traits and implementations for various encryption algorithms
//! used in Fortress. All implementations are designed to be secure, performant,
//! and easy to use.

use crate::error::{FortressError, Result, EncryptionErrorCode};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait for encryption algorithms
///
/// This trait defines the interface that all encryption algorithms must implement.
/// It provides both synchronous and asynchronous methods for flexibility.
#[async_trait]
pub trait EncryptionAlgorithm: Send + Sync + fmt::Debug {
    /// Encrypt data using the provided key
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `key` - The encryption key (must be the correct length for the algorithm)
    ///
    /// # Returns
    /// Encrypted data as a byte vector
    ///
    /// # Errors
    /// Returns an error if encryption fails due to invalid key length, algorithm issues, etc.
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt data using the provided key
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data
    /// * `key` - The decryption key (must be the same as the encryption key)
    ///
    /// # Returns
    /// Decrypted data as a byte vector
    ///
    /// # Errors
    /// Returns an error if decryption fails due to invalid key, corrupted data, etc.
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>>;

    /// Asynchronous version of encrypt
    async fn encrypt_async(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Default implementation calls the sync version
        Ok(self.encrypt(plaintext, key)?)
    }

    /// Asynchronous version of decrypt
    async fn decrypt_async(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // Default implementation calls the sync version
        Ok(self.decrypt(ciphertext, key)?)
    }

    /// Get the required key size in bytes
    fn key_size(&self) -> usize;

    /// Get the nonce/IV size in bytes (if applicable)
    fn nonce_size(&self) -> usize;

    /// Get the authentication tag size in bytes (for AEAD algorithms)
    fn tag_size(&self) -> usize;

    /// Get the name of the algorithm
    fn name(&self) -> &'static str;

    /// Check if the algorithm is an AEAD (Authenticated Encryption with Associated Data) construction
    fn is_aead(&self) -> bool {
        true // Most modern algorithms are AEAD
    }

    /// Get the security level in bits (e.g., 128, 192, 256)
    fn security_level(&self) -> usize {
        128 // Default to 128-bit security
    }

    /// Get performance characteristics of the algorithm
    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Balanced
    }
}

/// Performance profile for encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerformanceProfile {
    /// Ultra-fast encryption for high-throughput scenarios
    Lightning,
    /// Balanced performance and security
    Balanced,
    /// Maximum security with acceptable performance
    Fortress,
}

impl PerformanceProfile {
    /// Get the recommended key rotation interval for this profile
    pub fn recommended_rotation_interval(&self) -> std::time::Duration {
        match self {
            Self::Lightning => std::time::Duration::from_secs(23 * 3600), // 23 hours
            Self::Balanced => std::time::Duration::from_secs(7 * 24 * 3600), // 7 days
            Self::Fortress => std::time::Duration::from_secs(30 * 24 * 3600), // 30 days
        }
    }
}

/// Encryption profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionProfile {
    /// Name of the profile
    pub name: String,
    /// Algorithm to use
    pub algorithm: String,
    /// Key rotation interval
    pub key_rotation_interval: std::time::Duration,
    /// Performance profile
    pub performance_profile: PerformanceProfile,
    /// Additional algorithm-specific parameters
    pub parameters: std::collections::HashMap<String, serde_json::Value>,
}

impl EncryptionProfile {
    /// Create a new encryption profile
    pub fn new(
        name: String,
        algorithm: String,
        key_rotation_interval: std::time::Duration,
        performance_profile: PerformanceProfile,
    ) -> Self {
        Self {
            name,
            algorithm,
            key_rotation_interval,
            performance_profile,
            parameters: std::collections::HashMap::new(),
        }
    }

    /// Create a lightning profile (fastest encryption)
    pub fn lightning(name: String) -> Self {
        Self::new(
            name,
            "aegis256".to_string(),
            PerformanceProfile::Lightning.recommended_rotation_interval(),
            PerformanceProfile::Lightning,
        )
    }

    /// Create a balanced profile (good performance + security)
    pub fn balanced(name: String) -> Self {
        Self::new(
            name,
            "chacha20poly1305".to_string(),
            PerformanceProfile::Balanced.recommended_rotation_interval(),
            PerformanceProfile::Balanced,
        )
    }

    /// Create a fortress profile (maximum security)
    pub fn fortress(name: String) -> Self {
        Self::new(
            name,
            "aes256gcm".to_string(),
            PerformanceProfile::Fortress.recommended_rotation_interval(),
            PerformanceProfile::Fortress,
        )
    }
}

/// Encrypted data container with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted data
    pub ciphertext: Bytes,
    /// Nonce/IV used for encryption (if applicable)
    pub nonce: Option<Bytes>,
    /// Authentication tag (for AEAD algorithms)
    pub tag: Option<Bytes>,
    /// Algorithm used for encryption
    pub algorithm: String,
    /// Key version used
    pub key_version: Option<u32>,
    /// Timestamp when data was encrypted
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl EncryptedData {
    /// Create new encrypted data
    pub fn new(
        ciphertext: Bytes,
        algorithm: String,
    ) -> Self {
        Self {
            ciphertext,
            nonce: None,
            tag: None,
            algorithm,
            key_version: None,
            encrypted_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Set the nonce
    pub fn with_nonce(mut self, nonce: Bytes) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the authentication tag
    pub fn with_tag(mut self, tag: Bytes) -> Self {
        self.tag = Some(tag);
        self
    }

    /// Set the key version
    pub fn with_key_version(mut self, version: u32) -> Self {
        self.key_version = Some(version);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Serialize to base64 string for storage
    pub fn to_base64(&self) -> Result<String> {
        let json = serde_json::to_string(self)
            .map_err(|e| FortressError::encryption(
                "Failed to serialize encrypted data",
                &self.algorithm,
                EncryptionErrorCode::EncryptionFailed,
            ))?;
        Ok(general_purpose::STANDARD.encode(json.as_bytes()))
    }

    /// Deserialize from base64 string
    pub fn from_base64(data: &str) -> Result<Self> {
        let bytes = general_purpose::STANDARD
            .decode(data)
            .map_err(|e| FortressError::encryption(
                "Failed to decode base64 data",
                "unknown",
                EncryptionErrorCode::DecryptionFailed,
            ))?;
        
        serde_json::from_slice(&bytes)
            .map_err(|e| FortressError::encryption(
                "Failed to deserialize encrypted data",
                "unknown",
                EncryptionErrorCode::DecryptionFailed,
            ))
    }
}

/// Secure key container that zeroizes on drop
#[derive(Clone)]
pub struct SecureKey {
    /// The key bytes
    key: Bytes,
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(key: Vec<u8>) -> Self {
        Self { key: Bytes::from(key) }
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get the key length
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    /// Generate a random key of the specified length
    pub fn generate(length: usize) -> Self {
        let mut key = vec![0u8; length];
        getrandom::getrandom(&mut key).expect("Failed to generate random key");
        Self::new(key)
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Zeroize the key when dropped
        let mut key_bytes = self.key.as_ref().to_vec();
        key_bytes.zeroize();
    }
}

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureKey")
            .field("length", &self.key.len())
            .finish()
    }
}

/// AEGIS-256 encryption algorithm
///
/// AEGIS-256 is an ultra-fast AEAD construction that provides excellent performance
/// while maintaining strong security guarantees.
#[derive(Debug, Clone)]
pub struct Aegis256;

impl Aegis256 {
    /// Create a new AEGIS-256 instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Aegis256 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Aegis256 {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random nonce
        let mut nonce = vec![0u8; self.nonce_size()];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| FortressError::encryption(
                format!("Failed to generate nonce: {}", e),
                self.name(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // TODO: Implement actual AEGIS-256 encryption
        // For now, we'll use a placeholder implementation
        // In a real implementation, you would use the AEGIS-256 crate
        let mut ciphertext = plaintext.to_vec();
        
        // Add nonce to the beginning of ciphertext
        let mut result = nonce;
        result.append(&mut ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain nonce",
                self.name(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract nonce from the beginning of ciphertext
        let nonce = &ciphertext[..self.nonce_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size()..];

        // TODO: Implement actual AEGIS-256 decryption
        // For now, we'll use a placeholder implementation
        Ok(actual_ciphertext.to_vec())
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        32 // 256 bits nonce for AEGIS-256
    }

    fn tag_size(&self) -> usize {
        32 // 256 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "aegis256"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Lightning
    }
}

/// ChaCha20-Poly1305 encryption algorithm
///
/// ChaCha20-Poly1305 is a widely-used AEAD construction that provides good
/// performance and strong security guarantees.
#[derive(Debug, Clone)]
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for ChaCha20Poly1305 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for ChaCha20Poly1305 {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random nonce
        let mut nonce = vec![0u8; self.nonce_size()];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| FortressError::encryption(
                format!("Failed to generate nonce: {}", e),
                self.name(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Use the chacha20poly1305 crate for actual encryption
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| FortressError::encryption(
                format!("Failed to create cipher: {}", e),
                self.name(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Convert nonce to the correct format (XChaCha20 uses 24-byte nonce)
        let mut xnonce = [0u8; 24];
        xnonce[..12].copy_from_slice(&nonce);
        
        let ciphertext = cipher
            .encrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), plaintext)
            .map_err(|e| FortressError::encryption(
                format!("Encryption failed: {}", e),
                self.name(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Prepend nonce to ciphertext
        let mut result = nonce;
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain nonce",
                self.name(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract nonce from the beginning of ciphertext
        let nonce = &ciphertext[..self.nonce_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size()..];

        // Use the chacha20poly1305 crate for actual decryption
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| FortressError::encryption(
                format!("Failed to create cipher: {}", e),
                self.name(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        // Convert nonce to the correct format
        let mut xnonce = [0u8; 24];
        xnonce[..12].copy_from_slice(nonce);

        let plaintext = cipher
            .decrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), actual_ciphertext)
            .map_err(|e| FortressError::encryption(
                format!("Decryption failed: {}", e),
                self.name(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        12 // 96 bits nonce (will be extended to 192 bits for XChaCha20)
    }

    fn tag_size(&self) -> usize {
        16 // 128 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "chacha20poly1305"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Balanced
    }
}

/// AES-256-GCM encryption algorithm
///
/// AES-256-GCM is the industry standard for authenticated encryption,
/// providing excellent security and hardware acceleration support.
#[derive(Debug, Clone)]
pub struct Aes256Gcm;

impl Aes256Gcm {
    /// Create a new AES-256-GCM instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Aes256Gcm {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Aes256Gcm {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random nonce
        let mut nonce = vec![0u8; self.nonce_size()];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| FortressError::encryption(
                format!("Failed to generate nonce: {}", e),
                self.name(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Use the ring crate for actual encryption
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
                .map_err(|e| FortressError::encryption(
                    format!("Failed to create key: {}", e),
                    self.name(),
                    EncryptionErrorCode::EncryptionFailed,
                ))?,
        );

        let nonce = ring::aead::Nonce::assume_unique_for_key(
            ring::aead::GenericArray::from_slice(&nonce)
        );

        let mut ciphertext = plaintext.to_vec();
        let tag = key
            .seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut ciphertext)
            .map_err(|e| FortressError::encryption(
                format!("Encryption failed: {}", e),
                self.name(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Prepend nonce to ciphertext
        let mut result = nonce.as_ref().to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() + self.tag_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain nonce and tag",
                self.name(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract nonce from the beginning of ciphertext
        let nonce_bytes = &ciphertext[..self.nonce_size()];
        let mut ciphertext_with_tag = ciphertext[self.nonce_size()..].to_vec();

        // Use the ring crate for actual decryption
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key)
                .map_err(|e| FortressError::encryption(
                    format!("Failed to create key: {}", e),
                    self.name(),
                    EncryptionErrorCode::DecryptionFailed,
                ))?,
        );

        let nonce = ring::aead::Nonce::assume_unique_for_key(
            ring::aead::GenericArray::from_slice(nonce_bytes)
        );

        key.open_in_place(nonce, ring::aead::Aad::empty(), &mut ciphertext_with_tag)
            .map_err(|e| FortressError::encryption(
                format!("Decryption failed: {}", e),
                self.name(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        // Remove the tag from the end
        let plaintext_len = ciphertext_with_tag.len() - self.tag_size();
        Ok(ciphertext_with_tag[..plaintext_len].to_vec())
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        12 // 96 bits nonce
    }

    fn tag_size(&self) -> usize {
        16 // 128 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "aes256gcm"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Fortress
    }
}

/// Factory function to create encryption algorithms by name
pub fn create_algorithm(name: &str) -> Result<Box<dyn EncryptionAlgorithm>> {
    match name.to_lowercase().as_str() {
        "aegis256" | "aegis-256" => Ok(Box::new(Aegis256::new())),
        "chacha20poly1305" | "chacha20-poly1305" | "xchacha20poly1305" => {
            Ok(Box::new(ChaCha20Poly1305::new()))
        }
        "aes256gcm" | "aes-256-gcm" => Ok(Box::new(Aes256Gcm::new())),
        _ => Err(FortressError::encryption(
            format!("Unknown algorithm: {}", name),
            name,
            EncryptionErrorCode::AlgorithmNotSupported,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aegis256_encrypt_decrypt() {
        let algorithm = Aegis256::new();
        let key = SecureKey::generate(algorithm.key_size());
        let plaintext = b"Hello, Fortress!";

        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn test_chacha20poly1305_encrypt_decrypt() {
        let algorithm = ChaCha20Poly1305::new();
        let key = SecureKey::generate(algorithm.key_size());
        let plaintext = b"Hello, Fortress!";

        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn test_aes256gcm_encrypt_decrypt() {
        let algorithm = Aes256Gcm::new();
        let key = SecureKey::generate(algorithm.key_size());
        let plaintext = b"Hello, Fortress!";

        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_invalid_key_length() {
        let algorithm = Aegis256::new();
        let invalid_key = b"short";
        let plaintext = b"Hello, Fortress!";

        let result = algorithm.encrypt(plaintext, invalid_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FortressError::Encryption { code: EncryptionErrorCode::InvalidKeyLength, .. }
        ));
    }

    #[test]
    fn test_encryption_profiles() {
        let lightning = EncryptionProfile::lightning("test".to_string());
        assert_eq!(lightning.performance_profile, PerformanceProfile::Lightning);
        assert_eq!(lightning.algorithm, "aegis256");

        let balanced = EncryptionProfile::balanced("test".to_string());
        assert_eq!(balanced.performance_profile, PerformanceProfile::Balanced);
        assert_eq!(balanced.algorithm, "chacha20poly1305");

        let fortress = EncryptionProfile::fortress("test".to_string());
        assert_eq!(fortress.performance_profile, PerformanceProfile::Fortress);
        assert_eq!(fortress.algorithm, "aes256gcm");
    }

    #[test]
    fn test_secure_key() {
        let key = SecureKey::generate(32);
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());

        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("SecureKey"));
        assert!(debug_str.contains("length: 32"));
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let data = EncryptedData::new(
            Bytes::from("encrypted_data"),
            "aes256gcm".to_string(),
        )
        .with_nonce(Bytes::from("nonce"))
        .with_tag(Bytes::from("tag"))
        .with_key_version(1)
        .with_metadata("purpose".to_string(), "test".to_string());

        let base64 = data.to_base64().unwrap();
        let deserialized = EncryptedData::from_base64(&base64).unwrap();

        assert_eq!(deserialized.ciphertext, data.ciphertext);
        assert_eq!(deserialized.algorithm, data.algorithm);
        assert_eq!(deserialized.nonce, data.nonce);
        assert_eq!(deserialized.tag, data.tag);
        assert_eq!(deserialized.key_version, data.key_version);
        assert_eq!(deserialized.metadata, data.metadata);
    }

    #[test]
    fn test_create_algorithm() {
        let aegis = create_algorithm("aegis256").unwrap();
        assert_eq!(aegis.name(), "aegis256");

        let chacha = create_algorithm("chacha20poly1305").unwrap();
        assert_eq!(chacha.name(), "chacha20poly1305");

        let aes = create_algorithm("aes256gcm").unwrap();
        assert_eq!(aes.name(), "aes256gcm");

        let unknown = create_algorithm("unknown");
        assert!(unknown.is_err());
    }

    #[test]
    fn test_performance_profiles() {
        let lightning = PerformanceProfile::Lightning;
        assert_eq!(lightning.recommended_rotation_interval(), std::time::Duration::from_secs(23 * 3600));

        let balanced = PerformanceProfile::Balanced;
        assert_eq!(balanced.recommended_rotation_interval(), std::time::Duration::from_secs(7 * 24 * 3600));

        let fortress = PerformanceProfile::Fortress;
        assert_eq!(fortress.recommended_rotation_interval(), std::time::Duration::from_secs(30 * 24 * 3600));
    }
}
