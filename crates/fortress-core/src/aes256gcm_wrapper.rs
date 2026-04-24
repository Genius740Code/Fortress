//! AES-256-GCM wrapper implementing the EncryptionAlgorithm trait

use crate::error::{FortressError, Result, EncryptionErrorCode};
use crate::encryption::{EncryptionAlgorithm, PerformanceProfile};
use async_trait::async_trait;
use aes_gcm::{aead::{Aead, KeyInit as AeadKeyInit}};

/// AES-256-GCM wrapper implementing EncryptionAlgorithm trait
#[derive(Debug, Clone)]
pub struct Aes256GcmWrapper;

impl Aes256GcmWrapper {
    /// Create a new AES-256-GCM wrapper
    pub fn new() -> Self {
        Self
    }
}

impl Default for Aes256GcmWrapper {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EncryptionAlgorithm for Aes256GcmWrapper {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_size() {
            return Err(FortressError::encryption(
                format!("Invalid key length: expected {}, got {}", self.key_size(), key.len()),
                self.name().to_string(),
                EncryptionErrorCode::InvalidKeyLength,
            ));
        }

        // Generate random nonce
        let nonce = match crate::trng::random_bytes(self.nonce_size()) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Fallback to getrandom
                let mut nonce = vec![0u8; self.nonce_size()];
                getrandom::getrandom(&mut nonce)
                    .map_err(|_e| FortressError::encryption(
                        "Failed to generate nonce: random error".to_string(),
                        self.name().to_string(),
                        EncryptionErrorCode::EncryptionFailed,
                    ))?;
                nonce
            }
        };

        // Create cipher with the provided key
        let key_array: [u8; 32] = key.try_into().map_err(|_| FortressError::encryption(
            "Invalid key length for AES-256-GCM: expected 32 bytes".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::InvalidKeyLength,
        ))?;
        let cipher = aes_gcm::Aes256Gcm::new(&key_array.into());

        let nonce_bytes: [u8; 12] = nonce.try_into().map_err(|_e| FortressError::encryption(
            "Failed to generate nonce: invalid length".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::EncryptionFailed,
        ))?;

        let ciphertext = cipher
            .encrypt(&aes_gcm::Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_e| FortressError::encryption(
                "Encryption failed: encryption error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
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

        // Extract nonce from the beginning of ciphertext
        let nonce_bytes = &ciphertext[..self.nonce_size()];
        let actual_ciphertext = &ciphertext[self.nonce_size()..];

        // Create cipher with the provided key
        let key_array: [u8; 32] = key.try_into().map_err(|_| FortressError::encryption(
            "Invalid key length for AES-256-GCM: expected 32 bytes".to_string(),
            self.name().to_string(),
            EncryptionErrorCode::InvalidKeyLength,
        ))?;
        let cipher = aes_gcm::Aes256Gcm::new(&key_array.into());

        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|_e| FortressError::encryption(
                "Decryption failed: authentication error".to_string(),
                self.name().to_string(),
                EncryptionErrorCode::AuthenticationFailed,
            ))?;

        Ok(plaintext)
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

    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

/// Type alias for easier use of AES-256-GCM wrapper
pub type Aes256Gcm = Aes256GcmWrapper;
