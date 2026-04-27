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
}

/// Type alias for easier use of AES-256-GCM wrapper
pub type Aes256Gcm = Aes256GcmWrapper;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::EncryptionAlgorithm;
    
    /// Test basic encryption and decryption functionality
    #[tokio::test]
    async fn test_basic_encrypt_decrypt() {
        let aes = Aes256GcmWrapper::new();
        let plaintext = b"Hello, Fortress!";
        let key = [0u8; 32]; // Test key
        
        // Test encryption
        let ciphertext = aes.encrypt(plaintext, &key).expect("Encryption should succeed");
        assert!(ciphertext.len() > plaintext.len(), "Ciphertext should be longer than plaintext");
        assert_eq!(ciphertext.len(), plaintext.len() + 12 + 16, "Ciphertext should include nonce (12) + tag (16)");
        
        // Test decryption
        let decrypted = aes.decrypt(&ciphertext, &key).expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext, "Decrypted text should match original");
    }
    
    /// Test encryption with various input sizes
    #[tokio::test]
    async fn test_encrypt_various_sizes() {
        let aes = Aes256GcmWrapper::new();
        let key = [1u8; 32];
        
        // Test with different input sizes
        let test_sizes = vec![1, 16, 32, 64, 128, 256, 512, 1024, 4096];
        
        for size in test_sizes {
            let plaintext = vec![0u8; size];
            
            let ciphertext = aes.encrypt(&plaintext, &key)
                .unwrap_or_else(|_| panic!("Encryption failed for size {}", size));
            
            assert_eq!(ciphertext.len(), size + 12 + 16, 
                      "Ciphertext length incorrect for size {}", size);
            
            let decrypted = aes.decrypt(&ciphertext, &key)
                .unwrap_or_else(|_| panic!("Decryption failed for size {}", size));
            
            assert_eq!(decrypted, plaintext, 
                     "Decrypted data doesn't match for size {}", size);
        }
    }
    
    /// Test with empty input
    #[tokio::test]
    async fn test_empty_input() {
        let aes = Aes256GcmWrapper::new();
        let key = [2u8; 32];
        let plaintext = b"";
        
        let ciphertext = aes.encrypt(plaintext, &key).expect("Empty encryption should succeed");
        assert_eq!(ciphertext.len(), 28, "Empty ciphertext should be nonce + tag only");
        
        let decrypted = aes.decrypt(&ciphertext, &key).expect("Empty decryption should succeed");
        assert_eq!(decrypted, plaintext, "Empty decrypted should match original");
    }
    
    /// Test with invalid key sizes
    #[tokio::test]
    async fn test_invalid_key_sizes() {
        let aes = Aes256GcmWrapper::new();
        let plaintext = b"Test data";
        
        // Test with keys that are too short
        let short_keys = vec![vec![0u8; 16], vec![0u8; 24], vec![0u8; 31]];
        for key in short_keys {
            let result = aes.encrypt(plaintext, &key);
            assert!(result.is_err(), "Should reject short key of length {}", key.len());
        }
        
        // Test with keys that are too long
        let long_keys = vec![vec![0u8; 33], vec![0u8; 48], vec![0u8; 64]];
        for key in long_keys {
            let result = aes.encrypt(plaintext, &key);
            assert!(result.is_err(), "Should reject long key of length {}", key.len());
        }
    }
    
    /// Test with invalid ciphertext format
    #[tokio::test]
    async fn test_invalid_ciphertext() {
        let aes = Aes256GcmWrapper::new();
        let key = [3u8; 32];
        
        // Test with ciphertext that's too short
        let short_ciphertexts = vec![vec![], vec![0u8; 10], vec![0u8; 20]];
        for ciphertext in short_ciphertexts {
            let result = aes.decrypt(&ciphertext, &key);
            assert!(result.is_err(), "Should reject short ciphertext of length {}", ciphertext.len());
        }
        
        // Test with ciphertext that has correct length but invalid content
        let mut invalid_ciphertext = vec![0u8; 28]; // 12 nonce + 16 tag
        let result = aes.decrypt(&invalid_ciphertext, &key);
        assert!(result.is_err(), "Should reject invalid ciphertext");
    }
    
    /// Test with different keys
    #[tokio::test]
    async fn test_different_keys() {
        let aes = Aes256GcmWrapper::new();
        let plaintext = b"Test message for different keys";
        
        let keys = vec![
            [0u8; 32],
            [1u8; 32],
            [255u8; 32],
            {
                let mut key = [0u8; 32];
                for i in 0..32 {
                    key[i] = (i * 7) as u8;
                }
                key
            },
        ];
        
        for (i, key) in keys.iter().enumerate() {
            let ciphertext = aes.encrypt(plaintext, key)
                .unwrap_or_else(|_| panic!("Encryption failed for key {}", i));
            
            let decrypted = aes.decrypt(&ciphertext, key)
                .unwrap_or_else(|_| panic!("Decryption failed for key {}", i));
            
            assert_eq!(decrypted, plaintext, "Decryption failed for key {}", i);
        }
    }
    
    /// Test algorithm properties
    #[tokio::test]
    async fn test_algorithm_properties() {
        let aes = Aes256GcmWrapper::new();
        
        assert_eq!(aes.name(), "aes256gcm");
        assert_eq!(aes.key_size(), 32);
        assert_eq!(aes.nonce_size(), 12);
        assert_eq!(aes.tag_size(), 16);
        assert_eq!(aes.security_level(), 256);
    }
    
    /// Test that encryption produces different ciphertexts each time (due to random nonce)
    #[tokio::test]
    async fn test_random_nonce() {
        let aes = Aes256GcmWrapper::new();
        let plaintext = b"Same plaintext multiple times";
        let key = [4u8; 32];
        
        // Encrypt multiple times
        let mut ciphertexts = Vec::new();
        for _ in 0..10 {
            let ciphertext = aes.encrypt(plaintext, &key).expect("Encryption should succeed");
            ciphertexts.push(ciphertext);
        }
        
        // All ciphertexts should be different (due to random nonce)
        for i in 0..ciphertexts.len() {
            for j in i+1..ciphertexts.len() {
                assert_ne!(ciphertexts[i], ciphertexts[j], 
                         "Ciphertexts {} and {} should be different", i, j);
            }
        }
        
        // But all should decrypt to the same plaintext
        for ciphertext in &ciphertexts {
            let decrypted = aes.decrypt(ciphertext, &key).expect("Decryption should succeed");
            assert_eq!(decrypted, plaintext, "All ciphertexts should decrypt to original");
        }
    }
    
    /// Test large data encryption
    #[tokio::test]
    async fn test_large_data() {
        let aes = Aes256GcmWrapper::new();
        let key = [5u8; 32];
        
        // Test with 1MB of data
        let large_plaintext = vec![42u8; 1024 * 1024];
        
        let ciphertext = aes.encrypt(&large_plaintext, &key)
            .expect("Large data encryption should succeed");
        
        assert_eq!(ciphertext.len(), large_plaintext.len() + 12 + 16);
        
        let decrypted = aes.decrypt(&ciphertext, &key)
            .expect("Large data decryption should succeed");
        
        assert_eq!(decrypted, large_plaintext);
    }
    
    /// Test clone functionality
    #[tokio::test]
    async fn test_clone() {
        let aes1 = Aes256GcmWrapper::new();
        let aes2 = aes1.clone();
        
        let plaintext = b"Clone test";
        let key = [6u8; 32];
        
        let ciphertext1 = aes1.encrypt(plaintext, &key).expect("Encryption should succeed");
        let ciphertext2 = aes2.encrypt(plaintext, &key).expect("Encryption should succeed");
        
        // Should produce different ciphertexts due to random nonce
        assert_ne!(ciphertext1, ciphertext2, "Cloned instances should produce different ciphertexts");
        
        // But both should decrypt correctly
        let decrypted1 = aes1.decrypt(&ciphertext1, &key).expect("Decryption should succeed");
        let decrypted2 = aes2.decrypt(&ciphertext2, &key).expect("Decryption should succeed");
        
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
    
    /// Test default implementation
    #[tokio::test]
    async fn test_default() {
        let aes = Aes256GcmWrapper::default();
        let plaintext = b"Default test";
        let key = [7u8; 32];
        
        let ciphertext = aes.encrypt(plaintext, &key).expect("Default encryption should succeed");
        let decrypted = aes.decrypt(&ciphertext, &key).expect("Default decryption should succeed");
        
        assert_eq!(decrypted, plaintext);
    }
}
