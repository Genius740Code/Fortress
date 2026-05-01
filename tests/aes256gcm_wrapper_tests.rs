//! Comprehensive AES-256-GCM Encryption Tests
//! 
//! This test suite provides comprehensive coverage for the AES-256-GCM wrapper implementation,
//! ensuring security, performance, and reliability of the encryption algorithm.

use fortress_core::aes256gcm_wrapper::Aes256GcmWrapper;
use fortress_core::encryption::EncryptionAlgorithm;
use fortress_core::error::{FortressError, EncryptionErrorCode};
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Test encryption with various input sizes (small, medium, large)
    #[tokio::test]
    async fn test_encrypt_various_sizes() {
        let aes = Aes256GcmWrapper::new();
        let key = [1u8; 32];
        
        // Test with different input sizes
        let test_sizes = vec![
            1,      // Small
            16,     // Block size
            32,     // Medium
            64,     // Medium-large
            128,    // Large
            256,    // Very large
            512,    // Extra large
            1024,   // 1KB
            4096,   // 4KB
            8192,   // 8KB
            16384,  // 16KB
        ];
        
        for size in test_sizes {
            let plaintext = vec![size as u8; size];
            
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

    /// Test key generation and validation
    #[tokio::test]
    async fn test_key_generation_and_validation() {
        let aes = Aes256GcmWrapper::new();
        
        // Test valid key generation
        let valid_keys = vec![
            vec![0u8; 32],
            vec![255u8; 32],
            vec![1u8; 32],
            {
                let mut key = vec![0u8; 32];
                for i in 0..32 {
                    key[i] = (i * 8) as u8;
                }
                key
            },
        ];
        
        for (i, key) in valid_keys.iter().enumerate() {
            let plaintext = format!("Test message for key {}", i);
            let ciphertext = aes.encrypt(plaintext.as_bytes(), key)
                .unwrap_or_else(|_| panic!("Encryption failed for valid key {}", i));
            
            let decrypted = aes.decrypt(&ciphertext, key)
                .unwrap_or_else(|_| panic!("Decryption failed for valid key {}", i));
            
            assert_eq!(decrypted, plaintext.as_bytes(), "Valid key {} failed", i);
        }
        
        // Test invalid key sizes
        let invalid_keys = vec![
            vec![0u8; 16],  // Too short
            vec![0u8; 24],  // Too short
            vec![0u8; 31],  // Too short
            vec![0u8; 33],  // Too long
            vec![0u8; 48],  // Too long
            vec![0u8; 64],  // Too long
        ];
        
        for (i, key) in invalid_keys.iter().enumerate() {
            let plaintext = b"Test message";
            let result = aes.encrypt(plaintext, key);
            assert!(result.is_err(), "Should reject invalid key {} of length {}", i, key.len());
            
            if let Err(FortressError::Encryption { code: EncryptionErrorCode::InvalidKeyLength, .. }) = result {
                // Expected error type
            } else {
                panic!("Expected InvalidKeyLength error for key {}", i);
            }
        }
    }

    /// Test error handling for invalid inputs
    #[tokio::test]
    async fn test_error_handling_invalid_inputs() {
        let aes = Aes256GcmWrapper::new();
        let key = [2u8; 32];
        
        // Test empty ciphertext
        let result = aes.decrypt(&[], &key);
        assert!(result.is_err(), "Should reject empty ciphertext");
        
        // Test ciphertext too short
        let short_ciphertexts = vec![vec![0u8; 10], vec![0u8; 20], vec![0u8; 27]];
        for (i, ciphertext) in short_ciphertexts.iter().enumerate() {
            let result = aes.decrypt(ciphertext, &key);
            assert!(result.is_err(), "Should reject short ciphertext {} of length {}", i, ciphertext.len());
        }
        
        // Test invalid ciphertext (correct length but invalid content)
        let mut invalid_ciphertext = vec![0u8; 28]; // 12 nonce + 16 tag
        let result = aes.decrypt(&invalid_ciphertext, &key);
        assert!(result.is_err(), "Should reject invalid ciphertext");
        
        // Test with wrong key
        let plaintext = b"Test message";
        let correct_key = [3u8; 32];
        let wrong_key = [4u8; 32];
        
        let ciphertext = aes.encrypt(plaintext, &correct_key).expect("Encryption should succeed");
        let result = aes.decrypt(&ciphertext, &wrong_key);
        assert!(result.is_err(), "Should reject decryption with wrong key");
        
        if let Err(FortressError::Encryption { code: EncryptionErrorCode::AuthenticationFailed, .. }) = result {
            // Expected error type
        } else {
            panic!("Expected AuthenticationFailed error for wrong key");
        }
    }

    /// Test performance benchmarks for encryption operations
    #[tokio::test]
    async fn test_performance_benchmarks() {
        let aes = Aes256GcmWrapper::new();
        let key = [5u8; 32];
        
        // Test different data sizes for performance
        let test_cases = vec![
            ("Small (1KB)", 1024),
            ("Medium (64KB)", 64 * 1024),
            ("Large (1MB)", 1024 * 1024),
        ];
        
        for (name, size) in test_cases {
            let plaintext = vec![42u8; size];
            
            // Benchmark encryption
            let start = Instant::now();
            let ciphertext = aes.encrypt(&plaintext, &key)
                .expect("Encryption should succeed for benchmark");
            let encrypt_duration = start.elapsed();
            
            // Benchmark decryption
            let start = Instant::now();
            let decrypted = aes.decrypt(&ciphertext, &key)
                .expect("Decryption should succeed for benchmark");
            let decrypt_duration = start.elapsed();
            
            // Verify correctness
            assert_eq!(decrypted, plaintext, "Benchmark verification failed for {}", name);
            
            // Performance assertions (these are rough guidelines)
            assert!(encrypt_duration.as_millis() < 1000, 
                   "Encryption too slow for {}: {}ms", name, encrypt_duration.as_millis());
            assert!(decrypt_duration.as_millis() < 1000, 
                   "Decryption too slow for {}: {}ms", name, decrypt_duration.as_millis());
            
            println!("{} - Encrypt: {}ms, Decrypt: {}ms", 
                    name, encrypt_duration.as_millis(), decrypt_duration.as_millis());
        }
    }

    /// Test concurrent encryption operations
    #[tokio::test]
    async fn test_concurrent_operations() {
        let aes = Aes256GcmWrapper::new();
        let key = [6u8; 32];
        
        // Test concurrent encryption
        let mut handles = Vec::new();
        for i in 0..10 {
            let aes_clone = aes.clone();
            let key_clone = key;
            let handle = tokio::spawn(async move {
                let plaintext = format!("Concurrent test message {}", i);
                let ciphertext = aes_clone.encrypt(plaintext.as_bytes(), &key_clone)
                    .expect("Concurrent encryption should succeed");
                
                let decrypted = aes_clone.decrypt(&ciphertext, &key_clone)
                    .expect("Concurrent decryption should succeed");
                
                assert_eq!(decrypted, plaintext.as_bytes(), 
                         "Concurrent operation {} failed", i);
                
                (ciphertext, plaintext)
            });
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        for handle in handles {
            let (ciphertext, original) = handle.await.expect("Task should complete");
            
            // Verify each result can be decrypted again
            let decrypted = aes.decrypt(&ciphertext, &key).expect("Re-decryption should succeed");
            assert_eq!(decrypted, original.as_bytes(), "Re-decryption verification failed");
        }
    }

    /// Test memory safety and edge cases
    #[tokio::test]
    async fn test_memory_safety_edge_cases() {
        let aes = Aes256GcmWrapper::new();
        let key = [7u8; 32];
        
        // Test with empty input
        let plaintext = b"";
        let ciphertext = aes.encrypt(plaintext, &key).expect("Empty encryption should succeed");
        assert_eq!(ciphertext.len(), 28, "Empty ciphertext should be nonce + tag only");
        
        let decrypted = aes.decrypt(&ciphertext, &key).expect("Empty decryption should succeed");
        assert_eq!(decrypted, plaintext, "Empty decrypted should match original");
        
        // Test with single byte
        let plaintext = b"x";
        let ciphertext = aes.encrypt(plaintext, &key).expect("Single byte encryption should succeed");
        let decrypted = aes.decrypt(&ciphertext, &key).expect("Single byte decryption should succeed");
        assert_eq!(decrypted, plaintext, "Single byte decryption should match");
        
        // Test with large data (10MB)
        let large_plaintext = vec![123u8; 10 * 1024 * 1024];
        let ciphertext = aes.encrypt(&large_plaintext, &key)
            .expect("Large data encryption should succeed");
        let decrypted = aes.decrypt(&ciphertext, &key)
            .expect("Large data decryption should succeed");
        assert_eq!(decrypted, large_plaintext, "Large data decryption should match");
    }

    /// Test nonce randomness and uniqueness
    #[tokio::test]
    async fn test_nonce_randomness_uniqueness() {
        let aes = Aes256GcmWrapper::new();
        let plaintext = b"Same plaintext multiple times";
        let key = [8u8; 32];
        
        // Encrypt multiple times to test nonce randomness
        let mut ciphertexts = Vec::new();
        let mut nonces = Vec::new();
        
        for _ in 0..100 {
            let ciphertext = aes.encrypt(plaintext, &key).expect("Encryption should succeed");
            
            // Extract nonce (first 12 bytes)
            let nonce = ciphertext[..12].to_vec();
            nonces.push(nonce);
            ciphertexts.push(ciphertext);
        }
        
        // Check that all nonces are unique
        for i in 0..nonces.len() {
            for j in i+1..nonces.len() {
                assert_ne!(nonces[i], nonces[j], 
                         "Nonces {} and {} should be different", i, j);
            }
        }
        
        // Check that all ciphertexts are different
        for i in 0..ciphertexts.len() {
            for j in i+1..ciphertexts.len() {
                assert_ne!(ciphertexts[i], ciphertexts[j], 
                         "Ciphertexts {} and {} should be different", i, j);
            }
        }
        
        // But all should decrypt to the same plaintext
        for (i, ciphertext) in ciphertexts.iter().enumerate() {
            let decrypted = aes.decrypt(ciphertext, &key)
                .unwrap_or_else(|_| panic!("Decryption {} failed", i));
            assert_eq!(decrypted, plaintext, "Ciphertext {} should decrypt to original", i);
        }
    }

    /// Test algorithm properties and constants
    #[tokio::test]
    async fn test_algorithm_properties() {
        let aes = Aes256GcmWrapper::new();
        
        // Test basic properties
        assert_eq!(aes.name(), "aes256gcm");
        assert_eq!(aes.key_size(), 32);
        assert_eq!(aes.nonce_size(), 12);
        assert_eq!(aes.tag_size(), 16);
        assert_eq!(aes.security_level(), 256);
        
        // Test that properties are consistent
        assert_eq!(aes.key_size(), 32, "Key size should be 32 bytes (256 bits)");
        assert_eq!(aes.nonce_size(), 12, "Nonce size should be 12 bytes (96 bits)");
        assert_eq!(aes.tag_size(), 16, "Tag size should be 16 bytes (128 bits)");
        assert_eq!(aes.security_level(), 256, "Security level should be 256 bits");
    }

    /// Test clone and default functionality
    #[tokio::test]
    async fn test_clone_default_functionality() {
        // Test default
        let aes_default = Aes256GcmWrapper::default();
        let plaintext = b"Default test";
        let key = [9u8; 32];
        
        let ciphertext = aes_default.encrypt(plaintext, &key).expect("Default encryption should succeed");
        let decrypted = aes_default.decrypt(&ciphertext, &key).expect("Default decryption should succeed");
        assert_eq!(decrypted, plaintext, "Default implementation should work");
        
        // Test clone
        let aes1 = Aes256GcmWrapper::new();
        let aes2 = aes1.clone();
        
        let plaintext = b"Clone test";
        
        let ciphertext1 = aes1.encrypt(plaintext, &key).expect("Clone encryption 1 should succeed");
        let ciphertext2 = aes2.encrypt(plaintext, &key).expect("Clone encryption 2 should succeed");
        
        // Should produce different ciphertexts due to random nonce
        assert_ne!(ciphertext1, ciphertext2, "Cloned instances should produce different ciphertexts");
        
        // But both should decrypt correctly
        let decrypted1 = aes1.decrypt(&ciphertext1, &key).expect("Clone decryption 1 should succeed");
        let decrypted2 = aes2.decrypt(&ciphertext2, &key).expect("Clone decryption 2 should succeed");
        
        assert_eq!(decrypted1, plaintext, "Clone decryption 1 should match");
        assert_eq!(decrypted2, plaintext, "Clone decryption 2 should match");
    }

    /// Test data integrity and authentication
    #[tokio::test]
    async fn test_data_integrity_authentication() {
        let aes = Aes256GcmWrapper::new();
        let key = [10u8; 32];
        let plaintext = b"Important data that must not be tampered";
        
        // Encrypt the data
        let ciphertext = aes.encrypt(plaintext, &key).expect("Encryption should succeed");
        
        // Test that any modification to ciphertext is detected
        let mut modified_ciphertext = ciphertext.clone();
        
        // Modify each byte position and verify detection
        for i in 0..modified_ciphertext.len() {
            modified_ciphertext[i] ^= 0x01; // Flip one bit
            
            let result = aes.decrypt(&modified_ciphertext, &key);
            assert!(result.is_err(), "Should detect tampering at byte {}", i);
            
            if let Err(FortressError::Encryption { code: EncryptionErrorCode::AuthenticationFailed, .. }) = result {
                // Expected error type
            } else {
                panic!("Expected AuthenticationFailed error for tampered data at byte {}", i);
            }
            
            // Restore the byte
            modified_ciphertext[i] ^= 0x01;
        }
        
        // Verify original still works
        let decrypted = aes.decrypt(&ciphertext, &key).expect("Original should still decrypt");
        assert_eq!(decrypted, plaintext, "Original should decrypt correctly");
        
        // Test truncation detection
        for trunc_len in 1..ciphertext.len() {
            let truncated = &ciphertext[..ciphertext.len() - trunc_len];
            let result = aes.decrypt(truncated, &key);
            assert!(result.is_err(), "Should detect truncation of length {}", trunc_len);
        }
    }

    /// Test key sensitivity and avalanche effect
    #[tokio::test]
    async fn test_key_sensitivity_avalanche() {
        let aes = Aes256GcmWrapper::new();
        let plaintext = b"Avalanche test - small key changes should produce completely different ciphertexts";
        
        let mut base_key = [0u8; 32];
        
        // Test that flipping one bit in the key produces completely different ciphertext
        for byte_pos in 0..32 {
            for bit_pos in 0..8 {
                // Create key with one bit flipped
                let mut modified_key = base_key;
                modified_key[byte_pos] ^= 1 << bit_pos;
                
                let ciphertext1 = aes.encrypt(plaintext, &base_key).expect("Base encryption should succeed");
                let ciphertext2 = aes.encrypt(plaintext, &modified_key).expect("Modified encryption should succeed");
                
                // Ciphertexts should be completely different
                assert_ne!(ciphertext1, ciphertext2, 
                         "Keys differing at bit {} of byte {} should produce different ciphertexts", 
                         bit_pos, byte_pos);
                
                // Hamming distance should be large (avalanche effect)
                let min_len = ciphertext1.len().min(ciphertext2.len());
                let mut differing_bytes = 0;
                for i in 0..min_len {
                    if ciphertext1[i] != ciphertext2[i] {
                        differing_bytes += 1;
                    }
                }
                
                // At least 50% of bytes should be different (rough avalanche check)
                assert!(differing_bytes > min_len / 2, 
                         "Insufficient avalanche effect: only {}/{} bytes differ", 
                         differing_bytes, min_len);
            }
        }
    }

    /// Test stress with many operations
    #[tokio::test]
    async fn test_stress_many_operations() {
        let aes = Aes256GcmWrapper::new();
        let key = [11u8; 32];
        
        let num_operations = 1000;
        let mut successful_ops = 0;
        
        for i in 0..num_operations {
            let plaintext = format!("Stress test message number {}", i);
            
            match aes.encrypt(plaintext.as_bytes(), &key) {
                Ok(ciphertext) => {
                    match aes.decrypt(&ciphertext, &key) {
                        Ok(decrypted) => {
                            if decrypted == plaintext.as_bytes() {
                                successful_ops += 1;
                            }
                        }
                        Err(_) => {
                            panic!("Decryption failed for operation {}", i);
                        }
                    }
                }
                Err(_) => {
                    panic!("Encryption failed for operation {}", i);
                }
            }
        }
        
        assert_eq!(successful_ops, num_operations, 
                 "All {} operations should succeed, but only {} succeeded", 
                 num_operations, successful_ops);
    }
}
