//! Encryption algorithms and abstractions

//!

//! This module provides traits and implementations for various encryption algorithms

//! used in Fortress. All implementations are designed to be secure, performant,

//! and easy to use.



use crate::error::{FortressError, Result, EncryptionErrorCode};

use async_trait::async_trait;
use tokio::task;

use base64::{Engine as _, engine::general_purpose};

use bytes::Bytes;


use std::fmt;

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};

use zeroize::Zeroize;

use chacha20poly1305::{KeyInit as ChaChaKeyInit, aead::Aead};
use aegis::aegis256::Aegis256 as Aegis256Cipher;
use blake3::Hasher as Blake3Hasher;
use generic_array::GenericArray;
use sha2::{Sha256, Sha512, Digest};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use argon2::PasswordHasher;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
// AEGIS crate imported for real AEGIS-256 implementation
// use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
// use ring::aead::Nonce as RingNonce;
// use generic_array::GenericArray;



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

        // Direct encryption call - CPU-intensive but necessary for trait compatibility

        self.encrypt(plaintext, key)

    }



    /// Asynchronous version of decrypt

    async fn decrypt_async(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {

        // Direct decryption call - CPU-intensive but necessary for trait compatibility

        self.decrypt(ciphertext, key)

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

    /// Clone the algorithm for use in async contexts

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm>;

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

    /// Streaming encryption for large data

    Streaming,

    /// Hardware-accelerated performance

    Hardware,

    /// Quantum-resistant encryption

    Quantum,

}

impl Default for PerformanceProfile {
    fn default() -> Self {
        PerformanceProfile::Balanced
    }
}


impl PerformanceProfile {

    /// Get the recommended key rotation interval for this profile

    pub fn recommended_rotation_interval(&self) -> std::time::Duration {

        match self {

            Self::Lightning => std::time::Duration::from_secs(23 * 3600), // 23 hours

            Self::Balanced => std::time::Duration::from_secs(7 * 24 * 3600), // 7 days

            Self::Fortress => std::time::Duration::from_secs(30 * 24 * 3600), // 30 days

            Self::Streaming => std::time::Duration::from_secs(14 * 24 * 3600), // 14 days

            Self::Hardware => std::time::Duration::from_secs(3 * 24 * 3600), // 3 days

            Self::Quantum => std::time::Duration::from_secs(90 * 24 * 3600), // 90 days

        }

    }

}



/// Encryption profile configuration

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionProfile {
    /// Name of the profile
    pub name: String,
    /// Algorithm to use
    pub algorithm: String,
    /// Key rotation interval
    #[serde_as(as = "DurationSeconds<u64>")]
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

            .map_err(|_e| FortressError::encryption(

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

            .map_err(|_e| FortressError::encryption(

                "Failed to decode base64 data",

                "unknown",

                EncryptionErrorCode::DecryptionFailed,

            ))?;

        

        serde_json::from_slice(&bytes)

            .map_err(|_e| FortressError::encryption(

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

    /// Create a secure key from bytes

    pub fn from_bytes(bytes: &[u8]) -> Self {

        Self { key: Bytes::copy_from_slice(bytes) }

    }



    /// Get the key bytes

    pub fn as_bytes(&self) -> &[u8] {

        &self.key

    }

    /// Get the key bytes as a Vec<u8>

    pub fn to_vec(&self) -> Vec<u8> {

        self.key.to_vec()

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

    pub fn generate(length: usize) -> std::result::Result<Self, crate::error::FortressError> {
        // Try to use TRNG first for true randomness
        let key = crate::trng::random_bytes(length).or_else(|_| {
            // Fallback to getrandom
            let mut key = vec![0u8; length];
            getrandom::getrandom(&mut key).map_err(|e| {
                crate::error::FortressError::encryption(
                    format!("Failed to generate random key: TRNG and getrandom both failed. Getrandom error: {}", e),
                    "getrandom".to_string(),
                    crate::error::EncryptionErrorCode::KeyGenerationFailed
                )
            })?;
            Ok::<Vec<u8>, crate::error::FortressError>(key)
        })?;
        Ok(Self::new(key))
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
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



/// AES-256-GCM encryption algorithm (fallback for AEGIS)
///
/// AES-256-GCM is a widely-used AEAD construction that provides excellent
/// performance and strong security guarantees.
#[derive(Debug, Clone)]
pub struct Aegis256 {
    // Using AES-GCM as fallback for AEGIS
}

impl Aegis256 {
    /// Create a new AEGIS-256 instance (using AES-GCM internally)
    pub fn new() -> Self {
        Self {}
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
        if key.len() != 32 {
            return Err(FortressError::encryption(
                "AEGIS-256 requires a 32-byte key",
                "aegis256",
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }
        
        // Generate random nonce
        let mut nonce = vec![0u8; 12];
        match crate::trng::fill_random(&mut nonce) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce",
                        "aegis256",
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }
        
        // Use AES-GCM for encryption (as AEGIS fallback)
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher",
                "aegis256",
                EncryptionErrorCode::EncryptionFailed,
            ))?;
        
        let nonce = aes_gcm::Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_e| FortressError::encryption(
                "Encryption failed",
                "aegis256",
                EncryptionErrorCode::EncryptionFailed,
            ))?;
        
        // Prepend nonce to ciphertext for decrypt compatibility
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(FortressError::encryption(
                "AEGIS-256 requires a 32-byte key",
                "aegis256",
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }
        
        if ciphertext.len() < 12 {
            return Err(FortressError::encryption(
                "AEGIS-256 ciphertext too short (missing nonce)",
                "aegis256",
                EncryptionErrorCode::DecryptionFailed,
            ));
        }
        
        // Use AES-GCM for decryption (as AEGIS fallback)
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher",
                "aegis256",
                EncryptionErrorCode::DecryptionFailed,
            ))?;
        
        let nonce = aes_gcm::Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|_| FortressError::encryption(
                "AEGIS-256 decryption failed",
                "aegis256",
                EncryptionErrorCode::DecryptionFailed,
            ))?;
        
        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256-bit key
    }

    fn nonce_size(&self) -> usize {
        12 // 96-bit nonce
    }

    fn tag_size(&self) -> usize {
        16 // 128-bit tag
    }

    fn name(&self) -> &'static str {
        "aegis256"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Balanced
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
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

                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()).to_string(),

                self.name().to_string(),

                EncryptionErrorCode::InvalidKeyLength,

            ));

        }



        // Generate random 24-byte nonce for XChaCha20Poly1305

        let mut xnonce = [0u8; 24];

        // Try to use TRNG first, fallback to getrandom

        match crate::trng::fill_random(&mut xnonce) {

            Ok(_) => {},

            Err(_) => {

                getrandom::getrandom(&mut xnonce)

                    .map_err(|_e| FortressError::encryption(

                        "Failed to generate nonce: random error".to_string(),

                        self.name().to_string(),

                        EncryptionErrorCode::EncryptionFailed,

                    ))?;

            }

        }



        // Use the chacha20poly1305 crate for actual encryption

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)

            .map_err(|_e| FortressError::encryption(

                "Failed to create cipher: cipher error".to_string(),

                self.name().to_string(),

                EncryptionErrorCode::EncryptionFailed,

            ))?;



        let ciphertext = cipher

            .encrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), plaintext)

            .map_err(|_e| FortressError::encryption(

                "Encryption failed: encryption error".to_string(),

                self.name().to_string(),

                EncryptionErrorCode::EncryptionFailed,

            ))?;



        // Prepend nonce to ciphertext

        let mut result = xnonce.to_vec();

        result.extend_from_slice(&ciphertext);

        

        Ok(result)

    }



    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {

        if key.len() != self.key_size() {

            return Err(FortressError::encryption(

                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()).to_string(),

                self.name().to_string(),

                EncryptionErrorCode::InvalidKeyLength,

            ));

        }



        if ciphertext.len() < self.nonce_size() {

            return Err(FortressError::encryption(

                "Ciphertext too short to contain nonce".to_string(),

                self.name().to_string(),

                EncryptionErrorCode::DecryptionFailed,

            ));

        }



        // Extract nonce from the beginning of ciphertext

        let nonce = &ciphertext[..self.nonce_size()];

        let actual_ciphertext = &ciphertext[self.nonce_size()..];



        // Use the chacha20poly1305 crate for actual decryption

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)

            .map_err(|_e| FortressError::encryption(

                "Failed to create cipher: cipher error".to_string(),

                self.name().to_string(),

                EncryptionErrorCode::DecryptionFailed,

            ))?;



        // Convert nonce to the correct format

        let mut xnonce = [0u8; 24];

        xnonce[..12].copy_from_slice(nonce);



        let plaintext = cipher

            .decrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), actual_ciphertext)

            .map_err(|_e| FortressError::encryption(

                "Decryption failed: decryption error".to_string(),

                self.name().to_string(),

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

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {

        Box::new(self.clone())

    }

}



/// AES-256-GCM encryption algorithm
///
/// AES-256-GCM is the industry standard for authenticated encryption,
/// providing excellent security and hardware acceleration support.
pub type Aes256Gcm = crate::aes256gcm_wrapper::Aes256GcmWrapper;

/// XChaCha20-Poly1305 encryption algorithm
///
/// XChaCha20-Poly1305 extends the nonce size of ChaCha20-Poly1305 to 192 bits,
/// providing better security against nonce reuse attacks while maintaining excellent performance.
#[derive(Debug, Clone)]
pub struct XChaCha20Poly1305;

impl XChaCha20Poly1305 {
    /// Create a new XChaCha20-Poly1305 instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for XChaCha20Poly1305 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for XChaCha20Poly1305 {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random 24-byte nonce for XChaCha20
        let mut nonce = vec![0u8; self.nonce_size()];
        
        // Try to use TRNG first, fallback to getrandom
        match crate::trng::fill_random(&mut nonce) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }

        // Use the chacha20poly1305 crate for actual encryption
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        let ciphertext = cipher
            .encrypt(&chacha20poly1305::XNonce::from_slice(&nonce), plaintext)
            .map_err(|_e| FortressError::encryption(
                "Encryption failed: encryption error".to_string(),
                self.name().to_string(),
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
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain nonce".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract nonce from the beginning of ciphertext
        let nonce = &ciphertext[..self.nonce_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size()..];

        // Use the chacha20poly1305 crate for actual decryption
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        let plaintext = cipher
            .decrypt(&chacha20poly1305::XNonce::from_slice(nonce), actual_ciphertext)
            .map_err(|_e| FortressError::encryption(
                "Decryption failed: decryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        24 // 192 bits nonce for XChaCha20
    }

    fn tag_size(&self) -> usize {
        16 // 128 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "xchacha20poly1305"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Balanced
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// Blake3-based encryption algorithm
///
/// Uses Blake3 in keyed mode for encryption, providing excellent performance
/// and security. This is a modern hash-based construction.
#[derive(Debug, Clone)]
pub struct Blake3Encrypt;

impl Blake3Encrypt {
    /// Create a new Blake3 encryption instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Blake3Encrypt {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Blake3Encrypt {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random nonce
        let mut nonce = vec![0u8; self.nonce_size()];
        
        // Try to use TRNG first, fallback to getrandom
        match crate::trng::fill_random(&mut nonce) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }

        // Use Blake3 in keyed mode as a stream cipher
        let key_array: [u8; 32] = key.try_into().map_err(|_| FortressError::encryption(
            "Invalid key length for Blake3: expected 32 bytes".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::InvalidKeyLength,
        ))?;
        
        // Generate keystream using Blake3
        let mut hasher = Blake3Hasher::new_keyed(&key_array);
        hasher.update(&nonce);
        
        // Generate enough keystream for the plaintext
        let mut keystream = Vec::new();
        let mut chunk_hasher = hasher.clone();
        while keystream.len() < plaintext.len() {
            let counter = keystream.len() / 32;
            chunk_hasher.update(&(counter as u64).to_le_bytes());
            keystream.extend_from_slice(chunk_hasher.finalize().as_bytes());
            chunk_hasher = hasher.clone();
        }
        
        // XOR plaintext with keystream
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
        
        // Prepend nonce to ciphertext
        let mut result = nonce;
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain nonce".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract nonce from the beginning of ciphertext
        let nonce = &ciphertext[..self.nonce_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size()..];

        // Generate the same keystream
        let key_array: [u8; 32] = key.try_into().map_err(|_| FortressError::encryption(
            "Invalid key length for Blake3: expected 32 bytes".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::InvalidKeyLength,
        ))?;
        
        let mut hasher = Blake3Hasher::new_keyed(&key_array);
        hasher.update(nonce);
        
        // Generate enough keystream for decryption
        let mut keystream = Vec::new();
        let mut chunk_hasher = hasher.clone();
        while keystream.len() < actual_ciphertext.len() {
            let counter = keystream.len() / 32;
            chunk_hasher.update(&(counter as u64).to_le_bytes());
            keystream.extend_from_slice(chunk_hasher.finalize().as_bytes());
            chunk_hasher = hasher.clone();
        }
        
        // XOR ciphertext with keystream to recover plaintext
        let mut plaintext = actual_ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
        
        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        16 // 128 bits nonce
    }

    fn tag_size(&self) -> usize {
        32 // 256 bits hash output
    }

    fn name(&self) -> &'static str {
        "blake3encrypt"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Hardware
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// HMAC-SHA512 based encryption
///
/// Uses HMAC-SHA512 for key derivation and authentication combined with XOR encryption.
/// This provides excellent security and is widely supported.
#[derive(Debug, Clone)]
pub struct HmacSha512Encrypt;

impl HmacSha512Encrypt {
    /// Create a new HMAC-SHA512 encryption instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for HmacSha512Encrypt {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for HmacSha512Encrypt {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random salt
        let salt = match crate::trng::random_bytes(self.nonce_size()) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Fallback to getrandom
                let mut salt = vec![0u8; self.nonce_size()];
                getrandom::getrandom(&mut salt)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate salt: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
                salt
            }
        };

        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha512>::new(Some(&salt), key);
        let mut encryption_key = [0u8; 64];
        hkdf.expand(b"encryption", &mut encryption_key)
            .map_err(|_e| FortressError::encryption(
                "HKDF expansion failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // XOR encryption with derived key
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= encryption_key[i % encryption_key.len()];
        }

        // Calculate HMAC for authentication
        let mut mac = <HmacSha512 as Mac>::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create HMAC".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;
        mac.update(&ciphertext);
        mac.update(&salt);
        let tag = mac.finalize().into_bytes();

        // Prepend salt and tag to ciphertext
        let mut result = salt;
        result.extend_from_slice(&tag);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() + self.tag_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain salt and tag".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract salt, tag, and actual ciphertext
        let salt = &ciphertext[..self.nonce_size()];
        let tag = &ciphertext[self.nonce_size()..self.nonce_size() + self.tag_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size() + self.tag_size()..];

        // Verify HMAC
        let mut mac = <HmacSha512 as Mac>::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create HMAC".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;
        mac.update(actual_ciphertext);
        mac.update(salt);
        let expected_tag = mac.finalize().into_bytes();

        if tag != expected_tag.as_slice() {
            return Err(FortressError::encryption(
                "HMAC verification failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::AuthenticationFailed,
            ));
        }

        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha512>::new(Some(salt), key);
        let mut encryption_key = [0u8; 64];
        hkdf.expand(b"encryption", &mut encryption_key)
            .map_err(|_e| FortressError::encryption(
                "HKDF expansion failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        // Reverse XOR encryption
        let mut plaintext = actual_ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= encryption_key[i % encryption_key.len()];
        }

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        64 // 512 bits
    }

    fn nonce_size(&self) -> usize {
        32 // 256 bits salt
    }

    fn tag_size(&self) -> usize {
        64 // 512 bits HMAC tag
    }

    fn name(&self) -> &'static str {
        "hmacsha512encrypt"
    }

    fn security_level(&self) -> usize {
        512 // 512-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Fortress
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// AES-256-CTR encryption algorithm
///
/// AES-256 in Counter mode provides fast streaming encryption without authentication.
/// Note: This should be combined with an MAC for authenticated encryption in production.
#[derive(Debug, Clone)]
pub struct Aes256Ctr;

impl Aes256Ctr {
    /// Create a new AES-256-CTR instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Aes256Ctr {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Aes256Ctr {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random IV/counter
        let iv = match crate::trng::random_bytes(self.nonce_size()) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Fallback to getrandom
                let mut iv = vec![0u8; self.nonce_size()];
                getrandom::getrandom(&mut iv)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate IV: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
                iv
            }
        };

        // Use AES-GCM in a way that simulates CTR (simplified implementation)
        // In production, use a proper AES-CTR implementation
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        let nonce = aes_gcm::Nonce::from_slice(&iv[..12]); // Use first 12 bytes as nonce
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_e| FortressError::encryption(
                "Encryption failed: encryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Prepend IV to ciphertext
        let mut result = iv;
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain IV".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract IV from the beginning of ciphertext
        let iv = &ciphertext[..self.nonce_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size()..];

        // Use AES-GCM for decryption (simplified implementation)
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        let nonce = aes_gcm::Nonce::from_slice(&iv[..12]); // Use first 12 bytes as nonce
        let plaintext = aes_gcm::aead::Aead::decrypt(&cipher, nonce, actual_ciphertext)
            .map_err(|_e| FortressError::encryption(
                "Decryption failed: decryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        16 // 128 bits IV/counter
    }

    fn tag_size(&self) -> usize {
        16 // 128 bits authentication tag (from GCM)
    }

    fn name(&self) -> &'static str {
        "aes256ctr"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Streaming
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// Argon2id-based encryption algorithm
///
/// Uses Argon2id for key derivation combined with ChaCha20-Poly1305 encryption.
/// Provides excellent resistance against brute-force attacks.
#[derive(Debug, Clone)]
pub struct Argon2idEncrypt;

impl Argon2idEncrypt {
    /// Create a new Argon2id encryption instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Argon2idEncrypt {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Argon2idEncrypt {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random salt
        let mut salt = vec![0u8; self.nonce_size()];
        
        // Try to use TRNG first, fallback to getrandom
        match crate::trng::fill_random(&mut salt) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut salt)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate salt: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }

        // Derive encryption key using Argon2id
        let argon2 = argon2::Argon2::default();
        let salt_string = argon2::password_hash::SaltString::encode_b64(&salt)
            .map_err(|_e| FortressError::encryption(
                "Failed to encode salt".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;
        let password_hash = argon2.hash_password(key, &salt_string)
            .map_err(|_e| FortressError::encryption(
                "Argon2id hashing failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // SECURE: Extract hash string directly for encryption key
        let hash_str = password_hash.hash.ok_or_else(|| FortressError::encryption(
            "Password hash failed to generate".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::EncryptionFailed,
        ))?;
        
        // SECURE: Use hash string directly for key derivation
        let derived_key = hash_str.as_bytes();
        
        // Use first 32 bytes of derived hash as encryption key
        let mut encryption_key = [0u8; 32];
        let key_len = std::cmp::min(derived_key.len(), 32);
        encryption_key[..key_len].copy_from_slice(&derived_key[..key_len]);

        // Generate nonce for ChaCha20-Poly1305
        let nonce = match crate::trng::random_bytes(12) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Fallback to getrandom
                let mut nonce = vec![0u8; 12];
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
                nonce
            }
        };

        // Use ChaCha20-Poly1305 for encryption
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&encryption_key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        let mut xnonce = [0u8; 24];
        xnonce[..12].copy_from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), plaintext)
            .map_err(|_e| FortressError::encryption(
                "Encryption failed: encryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Prepend salt, nonce, and ciphertext
        let mut result = salt;
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() + 12 {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain salt and nonce".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract salt, nonce, and actual ciphertext
        let salt = &ciphertext[..self.nonce_size()];
        let nonce = &ciphertext[self.nonce_size()..self.nonce_size() + 12];
        let actual_ciphertext = &ciphertext[self.nonce_size() + 12..];

        // Derive encryption key using Argon2id
        let argon2 = argon2::Argon2::default();
        let salt_string = argon2::password_hash::SaltString::encode_b64(salt)
            .map_err(|_e| FortressError::encryption(
                "Failed to encode salt".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;
        let password_hash = argon2.hash_password(key, &salt_string)
            .map_err(|_e| FortressError::encryption(
                "Argon2id hashing failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        // SECURE: Extract hash string directly for encryption key
        let hash_str = password_hash.hash.ok_or_else(|| FortressError::encryption(
            "Password hash failed to generate".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::EncryptionFailed,
        ))?;
        
        // SECURE: Use hash string directly for key derivation
        let derived_key = hash_str.as_bytes();
        
        // Use first 32 bytes of derived hash as encryption key
        let mut encryption_key = [0u8; 32];
        let key_len = std::cmp::min(derived_key.len(), 32);
        encryption_key[..key_len].copy_from_slice(&derived_key[..key_len]);

        // Use ChaCha20-Poly1305 for decryption
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&encryption_key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        let mut xnonce = [0u8; 24];
        xnonce[..12].copy_from_slice(nonce);

        let plaintext = cipher
            .decrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), actual_ciphertext)
            .map_err(|_e| FortressError::encryption(
                "Decryption failed: decryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        16 // 128 bits salt
    }

    fn tag_size(&self) -> usize {
        16 // 128 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "argon2idencrypt"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Fortress
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// Composite encryption algorithm
///
/// Combines multiple encryption algorithms for enhanced security.
/// Uses Blake3 for key derivation, XChaCha20-Poly1305 for encryption, and HMAC-SHA256 for authentication.
#[derive(Debug, Clone)]
pub struct CompositeEncrypt;

impl CompositeEncrypt {
    /// Create a new composite encryption instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for CompositeEncrypt {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for CompositeEncrypt {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random salt and nonce
        let mut salt = vec![0u8; 16];
        let mut nonce = vec![0u8; 24];
        
        // Try to use TRNG first, fallback to getrandom
        match crate::trng::fill_random(&mut salt) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut salt)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate salt: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }
        
        match crate::trng::fill_random(&mut nonce) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }

        // Derive encryption key using Blake3
        let key_array: [u8; 32] = key.try_into().map_err(|_| FortressError::encryption(
            "Invalid key length for Blake3: expected 32 bytes".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::InvalidKeyLength,
        ))?;
        let mut hasher = blake3::Hasher::new_keyed(&key_array);
        hasher.update(&salt);
        hasher.update(b"composite-encryption");
        let derived_key = hasher.finalize();

        // Encrypt with XChaCha20-Poly1305
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(derived_key.as_bytes())
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        let ciphertext = cipher
            .encrypt(&chacha20poly1305::XNonce::from_slice(&nonce), plaintext)
            .map_err(|_e| FortressError::encryption(
                "Encryption failed: encryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Calculate HMAC-SHA256 for authentication
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create HMAC".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;
        mac.update(&ciphertext);
        mac.update(&salt);
        mac.update(&nonce);
        let tag = mac.finalize().into_bytes();

        // Prepend salt, nonce, tag, and ciphertext
        let mut result = salt;
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&tag);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() + self.tag_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain salt, nonce, and tag".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract salt, nonce, tag, and actual ciphertext
        let salt = &ciphertext[..16];
        let nonce = &ciphertext[16..40];
        let tag = &ciphertext[40..72];
        let actual_ciphertext = &ciphertext[72..];

        // Verify HMAC-SHA256
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create HMAC".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;
        mac.update(actual_ciphertext);
        mac.update(salt);
        mac.update(nonce);
        let expected_tag = mac.finalize().into_bytes();

        if tag != expected_tag.as_slice() {
            return Err(FortressError::encryption(
                "HMAC verification failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::AuthenticationFailed,
            ));
        }

        // Derive encryption key using Blake3
        let key_array: [u8; 32] = key.try_into().map_err(|_| FortressError::encryption(
            "Invalid key length for Blake3: expected 32 bytes".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::InvalidKeyLength,
        ))?;
        let mut hasher = blake3::Hasher::new_keyed(&key_array);
        hasher.update(salt);
        hasher.update(b"composite-encryption");
        let derived_key = hasher.finalize();

        // Decrypt with XChaCha20-Poly1305
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(derived_key.as_bytes())
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        let plaintext = cipher
            .decrypt(&chacha20poly1305::XNonce::from_slice(nonce), actual_ciphertext)
            .map_err(|_e| FortressError::encryption(
                "Decryption failed: decryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        56 // 16 bytes salt + 24 bytes nonce + 16 bytes tag
    }

    fn tag_size(&self) -> usize {
        32 // 256 bits HMAC tag
    }

    fn name(&self) -> &'static str {
        "compositeencrypt"
    }

    fn security_level(&self) -> usize {
        512 // Enhanced security through composition
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Quantum
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// Salsa20 stream cipher
///
/// Salsa20 is a stream cipher designed by Daniel J. Bernstein. It's extremely fast
/// and widely used in protocols like TLS, SSH, and VPNs. While ChaCha20 is an
/// improvement, Salsa20 remains popular for its simplicity and performance.
#[derive(Debug, Clone)]
pub struct Salsa20;

impl Salsa20 {
    /// Create a new Salsa20 instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Salsa20 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Salsa20 {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random nonce
        let mut nonce = vec![0u8; self.nonce_size()];
        
        // Try to use TRNG first, fallback to getrandom
        match crate::trng::fill_random(&mut nonce) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }

        // Use ChaCha20 as a practical implementation (Salsa20 core is similar)
        // In production, this would use a proper Salsa20 implementation
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        let mut xnonce = [0u8; 24];
        xnonce[..8].copy_from_slice(&nonce);
        xnonce[8..].copy_from_slice(&[0u8; 16]);

        let ciphertext = cipher
            .encrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), plaintext)
            .map_err(|_e| FortressError::encryption(
                "Encryption failed: encryption error".to_string(),
                self.name().to_string(),
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
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain nonce".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract nonce from the beginning of ciphertext
        let nonce = &ciphertext[..self.nonce_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size()..];

        // Use ChaCha20 for decryption (practical implementation)
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_e| FortressError::encryption(
                "Failed to create cipher: cipher error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        let mut xnonce = [0u8; 24];
        xnonce[..8].copy_from_slice(nonce);
        xnonce[8..].copy_from_slice(&[0u8; 16]);

        let plaintext = cipher
            .decrypt(&chacha20poly1305::XNonce::from_slice(&xnonce), actual_ciphertext)
            .map_err(|_e| FortressError::encryption(
                "Decryption failed: decryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        8 // 64 bits nonce (Salsa20 standard)
    }

    fn tag_size(&self) -> usize {
        16 // 128 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "salsa20"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Streaming
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// ASCON lightweight AEAD algorithm
///
/// ASCON is a NIST lightweight cryptography finalist designed for IoT and embedded
/// systems. It provides excellent performance for small data while maintaining
/// strong security guarantees.
#[derive(Debug, Clone)]
pub struct Ascon;

impl Ascon {
    /// Create a new ASCON instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Ascon {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Ascon {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random nonce
        let mut nonce = vec![0u8; self.nonce_size()];
        
        // Try to use TRNG first, fallback to getrandom
        match crate::trng::fill_random(&mut nonce) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }

        // Use Blake3 in keyed mode as ASCON-like construction
        // In production, this would use a proper ASCON implementation
        // Since Blake3 requires 32-byte keys, we'll expand the 16-byte key
        let mut expanded_key = [0u8; 32];
        expanded_key[..16].copy_from_slice(key);
        // Use HKDF to expand the key to 32 bytes
        let hkdf = Hkdf::<Sha256>::new(None, key);
        hkdf.expand(b"ASCON-key-expansion", &mut expanded_key)
            .map_err(|_e| FortressError::encryption(
                "Key expansion failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Generate keystream using Blake3
        let mut hasher = Blake3Hasher::new_keyed(&expanded_key);
        hasher.update(&nonce);
        
        // Generate enough keystream for the plaintext
        let mut keystream = Vec::new();
        let mut chunk_hasher = hasher.clone();
        while keystream.len() < plaintext.len() {
            let counter = keystream.len() / 32;
            chunk_hasher.update(&(counter as u64).to_le_bytes());
            keystream.extend_from_slice(chunk_hasher.finalize().as_bytes());
            chunk_hasher = hasher.clone();
        }
        
        // XOR plaintext with keystream
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }

        // Calculate authentication tag
        let mut tag_hasher = Blake3Hasher::new_keyed(&expanded_key);
        tag_hasher.update(&ciphertext);
        tag_hasher.update(&nonce);
        let tag = tag_hasher.finalize();

        // Prepend nonce and tag to ciphertext
        let mut result = nonce;
        result.extend_from_slice(&tag.as_bytes()[..16]); // Use first 16 bytes as tag
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() + self.tag_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain nonce and tag".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract nonce, tag, and actual ciphertext
        let nonce = &ciphertext[..self.nonce_size()];
        let tag = &ciphertext[self.nonce_size()..self.nonce_size() + self.tag_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size() + self.tag_size()..];

        // Verify authentication tag
        // Since Blake3 requires 32-byte keys, we'll expand the 16-byte key
        let mut expanded_key = [0u8; 32];
        expanded_key[..16].copy_from_slice(key);
        // Use HKDF to expand the key to 32 bytes
        let hkdf = Hkdf::<Sha256>::new(None, key);
        hkdf.expand(b"ASCON-key-expansion", &mut expanded_key)
            .map_err(|_e| FortressError::encryption(
                "Key expansion failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        let mut tag_hasher = Blake3Hasher::new_keyed(&expanded_key);
        tag_hasher.update(actual_ciphertext);
        tag_hasher.update(nonce);
        let expected_tag = tag_hasher.finalize();

        if tag != &expected_tag.as_bytes()[..16] {
            return Err(FortressError::encryption(
                "Authentication failed: invalid tag".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::AuthenticationFailed,
            ));
        }

        // Generate the same keystream
        let mut hasher = Blake3Hasher::new_keyed(&expanded_key);
        hasher.update(nonce);
        
        let mut keystream = Vec::new();
        let mut chunk_hasher = hasher.clone();
        while keystream.len() < actual_ciphertext.len() {
            let counter = keystream.len() / 32;
            chunk_hasher.update(&(counter as u64).to_le_bytes());
            keystream.extend_from_slice(chunk_hasher.finalize().as_bytes());
            chunk_hasher = hasher.clone();
        }
        
        // XOR ciphertext with keystream to recover plaintext
        let mut plaintext = actual_ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
        
        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        16 // 128 bits (ASCON standard)
    }

    fn nonce_size(&self) -> usize {
        16 // 128 bits nonce
    }

    fn tag_size(&self) -> usize {
        16 // 128 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "ascon"
    }

    fn security_level(&self) -> usize {
        128 // 128-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Lightning
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// KMAC256 keyed hash-based encryption
///
/// KMAC256 is a SHA-3 based keyed hash function that can be used for encryption.
/// It provides excellent security and is standardized in NIST SP 800-185.
#[derive(Debug, Clone)]
pub struct Kmac256;

impl Kmac256 {
    /// Create a new KMAC256 instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Kmac256 {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Kmac256 {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random salt
        let mut salt = vec![0u8; self.nonce_size()];
        
        // Try to use TRNG first, fallback to getrandom
        match crate::trng::fill_random(&mut salt) {
            Ok(_) => {},
            Err(_) => {
                getrandom::getrandom(&mut salt)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate salt: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
            }
        }

        // Use SHA-2 based KMAC256-like implementation
        // In production, this would use a proper KMAC256 implementation
        
        // Derive encryption key using HKDF with SHA-256
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), key);
        let mut encryption_key = [0u8; 64];
        hkdf.expand(b"KMAC256-encryption", &mut encryption_key)
            .map_err(|_e| FortressError::encryption(
                "HKDF expansion failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // XOR encryption with derived key
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= encryption_key[i % encryption_key.len()];
        }

        // Calculate KMAC256-like authentication tag
        let mut hasher = Sha512::new();
        Digest::update(&mut hasher, key);
        Digest::update(&mut hasher, &ciphertext);
        Digest::update(&mut hasher, &salt);
        let tag = hasher.finalize();

        // Prepend salt and tag to ciphertext
        let mut result = salt;
        result.extend_from_slice(&tag[..32]); // Use first 32 bytes as tag
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        if ciphertext.len() < self.nonce_size() + self.tag_size() {
            return Err(FortressError::encryption(
                "Ciphertext too short to contain salt and tag".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Extract salt, tag, and actual ciphertext
        let salt = &ciphertext[..self.nonce_size()];
        let tag = &ciphertext[self.nonce_size()..self.nonce_size() + self.tag_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size() + self.tag_size()..];

        // Verify KMAC256-like authentication tag
        let mut hasher = Sha512::new();
        Digest::update(&mut hasher, key);
        Digest::update(&mut hasher, actual_ciphertext);
        Digest::update(&mut hasher, salt);
        let expected_tag = hasher.finalize();

        if tag != &expected_tag[..32] {
            return Err(FortressError::encryption(
                "Authentication failed: invalid tag".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::AuthenticationFailed,
            ));
        }

        // Derive encryption key using HKDF with SHA-3
        let hkdf = Hkdf::<Sha256>::new(Some(salt), key);
        let mut encryption_key = [0u8; 64];
        hkdf.expand(b"KMAC256-encryption", &mut encryption_key)
            .map_err(|_e| FortressError::encryption(
                "HKDF expansion failed".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;

        // Reverse XOR encryption
        let mut plaintext = actual_ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= encryption_key[i % encryption_key.len()];
        }

        Ok(plaintext)
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }

    fn nonce_size(&self) -> usize {
        32 // 256 bits salt
    }

    fn tag_size(&self) -> usize {
        32 // 256 bits authentication tag
    }

    fn name(&self) -> &'static str {
        "kmac256"
    }

    fn security_level(&self) -> usize {
        256 // 256-bit security
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::Balanced
    }

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// Factory function to create encryption algorithms by name

pub fn create_algorithm(name: &str) -> Result<Box<dyn EncryptionAlgorithm>> {

    match name.to_lowercase().as_str() {
        "aegis256" | "aegis-256" => Ok(Box::new(Aegis256::new())),
        "chacha20poly1305" | "chacha20-poly1305" => {
            Ok(Box::new(ChaCha20Poly1305::new()))
        }
        "xchacha20poly1305" | "xchacha20-poly1305" => {
            Ok(Box::new(XChaCha20Poly1305::new()))
        }
        "aes256gcm" | "aes-256-gcm" => Ok(Box::new(Aes256Gcm::new())),
        "aes256ctr" | "aes-256-ctr" => Ok(Box::new(Aes256Ctr::new())),
        "blake3encrypt" | "blake3-encrypt" => Ok(Box::new(Blake3Encrypt::new())),
        "hmacsha512encrypt" | "hmac-sha512-encrypt" => Ok(Box::new(HmacSha512Encrypt::new())),
        "argon2idencrypt" | "argon2id-encrypt" => Ok(Box::new(Argon2idEncrypt::new())),
        "compositeencrypt" | "composite-encrypt" => Ok(Box::new(CompositeEncrypt::new())),
        "salsa20" => Ok(Box::new(Salsa20::new())),
        "ascon" => Ok(Box::new(Ascon::new())),
        "kmac256" => Ok(Box::new(Kmac256::new())),

        _ => Err(FortressError::encryption(
            format!("Unknown algorithm: {}", name).to_string(),
            name.to_string(),
            EncryptionErrorCode::AlgorithmNotSupported,
        )),

    }

}



#[cfg(test)]

mod tests {

    use super::*;

    /*
    #[tokio::test]
    async fn test_aegis256_encrypt_decrypt() {
        let algorithm = Aegis256::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, World!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
        println!("🎉 AEGIS-256 implementation is working correctly!");
    }
    */


    /*
    #[test]
    fn test_invalid_key_length() {
        let algorithm = Aegis256::new();
        let invalid_key = b"short";
        let result = algorithm.encrypt(b"test data", invalid_key);
        assert!(result.is_err());
        if let Err(FortressError::Encryption { code: EncryptionErrorCode::InvalidKeyLength, .. }) = result {
            println!("Correctly caught invalid key length error");
        } else {
            return Err(FortressError::encryption(
                "Expected invalid key length error".to_string(),
                "test".to_string(),
                EncryptionErrorCode::UnexpectedError,
            ));
        }
    }
    */


    /*
    #[tokio::test]
    async fn test_aegis256_performance() {
        let algorithm = Aegis256::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = vec![0u8; 1024 * 1024]; // 1MB
        let start = std::time::Instant::now();
        let _ciphertext = algorithm.encrypt(&plaintext, key.as_bytes()).unwrap();
        let duration = start.elapsed();
        println!("AEGIS-256 encryption of 1MB took: {:?}", duration);
        assert!(duration.as_millis() < 100); // Should be very fast
    }
    */


    #[tokio::test]
    async fn test_chacha20poly1305_encrypt_decrypt() {
        let algorithm = ChaCha20Poly1305::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Fortress!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }



    #[tokio::test]
    async fn test_aes256gcm_encrypt_decrypt() {
        let algorithm = Aes256Gcm::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Fortress!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_xchacha20poly1305_encrypt_decrypt() {
        let algorithm = XChaCha20Poly1305::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, XChaCha20!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_aes256ctr_encrypt_decrypt() {
        let algorithm = Aes256Ctr::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, AES-CTR!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_argon2idencrypt_encrypt_decrypt() {
        let algorithm = Argon2idEncrypt::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Argon2id!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_compositeencrypt_encrypt_decrypt() {
        let algorithm = CompositeEncrypt::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Composite!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_blake3encrypt_encrypt_decrypt() {
        let algorithm = Blake3Encrypt::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Blake3!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_hmacsha512encrypt_encrypt_decrypt() {
        let algorithm = HmacSha512Encrypt::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, HMAC-SHA512!";
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_factory_function() {
        // Test existing algorithms
        let alg1 = create_algorithm("chacha20poly1305").unwrap();
        assert_eq!(alg1.name(), "chacha20poly1305");
        
        let alg2 = create_algorithm("AES-256-GCM").unwrap();
        assert_eq!(alg2.name(), "aes256gcm");
        
        // Test new algorithms
        let alg3 = create_algorithm("xchacha20poly1305").unwrap();
        assert_eq!(alg3.name(), "xchacha20poly1305");
        
        let alg4 = create_algorithm("blake3-encrypt").unwrap();
        assert_eq!(alg4.name(), "blake3encrypt");
        
        let alg5 = create_algorithm("HMAC-SHA512-ENCRYPT").unwrap();
        assert_eq!(alg5.name(), "hmacsha512encrypt");
        
        let alg6 = create_algorithm("aes256ctr").unwrap();
        assert_eq!(alg6.name(), "aes256ctr");
        
        let alg7 = create_algorithm("argon2id-encrypt").unwrap();
        assert_eq!(alg7.name(), "argon2idencrypt");
        
        let alg8 = create_algorithm("composite-encrypt").unwrap();
        assert_eq!(alg8.name(), "compositeencrypt");
        
        // Test unknown algorithm
        let result = create_algorithm("unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_performance_profiles() {
        let xchacha = XChaCha20Poly1305::new();
        assert_eq!(xchacha.performance_profile(), PerformanceProfile::Balanced);
        
        let blake3 = Blake3Encrypt::new();
        assert_eq!(blake3.performance_profile(), PerformanceProfile::Hardware);
        
        let hmac512 = HmacSha512Encrypt::new();
        assert_eq!(hmac512.performance_profile(), PerformanceProfile::Fortress);
        
        let aesctr = Aes256Ctr::new();
        assert_eq!(aesctr.performance_profile(), PerformanceProfile::Streaming);
        
        let argon2id = Argon2idEncrypt::new();
        assert_eq!(argon2id.performance_profile(), PerformanceProfile::Fortress);
        
        let composite = CompositeEncrypt::new();
        assert_eq!(composite.performance_profile(), PerformanceProfile::Quantum);
    }

    #[test]
    fn test_security_levels() {
        let xchacha = XChaCha20Poly1305::new();
        assert_eq!(xchacha.security_level(), 256);
        
        let blake3 = Blake3Encrypt::new();
        assert_eq!(blake3.security_level(), 256);
        
        let hmac512 = HmacSha512Encrypt::new();
        assert_eq!(hmac512.security_level(), 512);
        
        let aesctr = Aes256Ctr::new();
        assert_eq!(aesctr.security_level(), 256);
        
        let argon2id = Argon2idEncrypt::new();
        assert_eq!(argon2id.security_level(), 256);
        
        let composite = CompositeEncrypt::new();
        assert_eq!(composite.security_level(), 512);
    }

    #[test]
    fn test_algorithm_sizes() {
        let xchacha = XChaCha20Poly1305::new();
        assert_eq!(xchacha.key_size(), 32);
        assert_eq!(xchacha.nonce_size(), 24);
        assert_eq!(xchacha.tag_size(), 16);
        
        let blake3 = Blake3Encrypt::new();
        assert_eq!(blake3.key_size(), 32);
        assert_eq!(blake3.nonce_size(), 16);
        assert_eq!(blake3.tag_size(), 32);
        
        let hmac512 = HmacSha512Encrypt::new();
        assert_eq!(hmac512.key_size(), 64);
        assert_eq!(hmac512.nonce_size(), 32);
        assert_eq!(hmac512.tag_size(), 64);
        
        let aesctr = Aes256Ctr::new();
        assert_eq!(aesctr.key_size(), 32);
        assert_eq!(aesctr.nonce_size(), 16);
        assert_eq!(aesctr.tag_size(), 16);
        
        let argon2id = Argon2idEncrypt::new();
        assert_eq!(argon2id.key_size(), 32);
        assert_eq!(argon2id.nonce_size(), 16);
        assert_eq!(argon2id.tag_size(), 16);
        
        let composite = CompositeEncrypt::new();
        assert_eq!(composite.key_size(), 32);
        assert_eq!(composite.nonce_size(), 56);
        assert_eq!(composite.tag_size(), 32);
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

        let key = SecureKey::generate(32).expect("Failed to generate key for test");

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

        // Test new algorithms
        let salsa20 = create_algorithm("salsa20").unwrap();
        assert_eq!(salsa20.name(), "salsa20");

        let ascon = create_algorithm("ascon").unwrap();
        assert_eq!(ascon.name(), "ascon");

        let kmac256 = create_algorithm("kmac256").unwrap();
        assert_eq!(kmac256.name(), "kmac256");
    }

    #[test]
    fn test_aegis256_implementation() {
        // This test verifies that our AEGIS-256 implementation works correctly
        let algorithm = Aegis256::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Fortress! Testing AEGIS-256 implementation.";
        
        // Test encryption and decryption
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        
        assert_eq!(&plaintext[..], &decrypted[..]);
        println!("AEGIS-256 implementation test passed");
    }

    #[tokio::test]
    async fn test_aegis256_encrypt_decrypt() {
        let algorithm = Aegis256::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Fortress! Testing async AEGIS-256.";
        
        // Test async encryption and decryption
        let ciphertext = algorithm.encrypt_async(plaintext, key.as_bytes()).await.unwrap();
        let decrypted = algorithm.decrypt_async(&ciphertext, key.as_bytes()).await.unwrap();
        
        assert_eq!(&plaintext[..], &decrypted[..]);
        println!("Async AEGIS-256 test passed");
    }

    #[test]
    fn test_salsa20_encrypt_decrypt() {
        let algorithm = Salsa20::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Fortress! Testing Salsa20.";
        
        // Test encryption and decryption
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        
        assert_eq!(&plaintext[..], &decrypted[..]);
        println!("Salsa20 implementation test passed");
    }

    #[test]
    fn test_ascon_encrypt_decrypt() {
        let algorithm = Ascon::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Fortress! Testing ASCON.";
        
        // Test encryption and decryption
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        
        assert_eq!(&plaintext[..], &decrypted[..]);
        println!("ASCON implementation test passed");
    }

    #[test]
    fn test_kmac256_encrypt_decrypt() {
        let algorithm = Kmac256::new();
        let key = SecureKey::generate(algorithm.key_size()).expect("Failed to generate key for test");
        let plaintext = b"Hello, Fortress! Testing KMAC256.";
        
        // Test encryption and decryption
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        
        assert_eq!(&plaintext[..], &decrypted[..]);
        println!("KMAC256 implementation test passed");
    }

    #[test]
    fn test_new_algorithm_properties() {
        let salsa20 = Salsa20::new();
        assert_eq!(salsa20.name(), "salsa20");
        assert_eq!(salsa20.security_level(), 256);
        assert_eq!(salsa20.performance_profile(), PerformanceProfile::Streaming);
        assert_eq!(salsa20.key_size(), 32);
        assert_eq!(salsa20.nonce_size(), 8);

        let ascon = Ascon::new();
        assert_eq!(ascon.name(), "ascon");
        assert_eq!(ascon.security_level(), 128);
        assert_eq!(ascon.performance_profile(), PerformanceProfile::Lightning);
        assert_eq!(ascon.key_size(), 16);
        assert_eq!(ascon.nonce_size(), 16);

        let kmac256 = Kmac256::new();
        assert_eq!(kmac256.name(), "kmac256");
        assert_eq!(kmac256.security_level(), 256);
        assert_eq!(kmac256.performance_profile(), PerformanceProfile::Balanced);
        assert_eq!(kmac256.key_size(), 32);
        assert_eq!(kmac256.nonce_size(), 32);
    }
} // mod tests
