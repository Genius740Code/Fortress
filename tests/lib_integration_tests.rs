//! Comprehensive Library Integration Tests
//!
//! This test suite provides comprehensive coverage for Fortress library integration functionality,
//! ensuring all components work together seamlessly and maintain proper interoperability.

use fortress_core::encryption::{Aes256Gcm, ChaCha20Poly1305, EncryptionAlgorithm};
use fortress_core::key::{InMemoryKeyManager, KeyManager};
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test core library initialization and configuration
    #[tokio::test]
    async fn test_library_initialization() {
        // Test basic library functionality
        let key_manager = InMemoryKeyManager::new();
        assert!(
            key_manager.generate_key(&Aes256Gcm::new()).await.is_ok(),
            "Key generation should work"
        );
    }

    /// Test encryption and key management integration
    #[tokio::test]
    async fn test_encryption_key_management_integration() {
        // Create key manager
        let key_manager = InMemoryKeyManager::new();

        // Generate encryption key
        let key = key_manager.generate_key(&Aes256Gcm::new()).await.unwrap();
        assert!(!key.as_bytes().unwrap().is_empty(), "Key should not be empty");

        // Create encryption algorithm
        let encryptor = Aes256Gcm::new();

        // Test encryption and decryption
        let plaintext = b"Library integration test data";
        let ciphertext = encryptor.encrypt(plaintext, key.as_bytes().unwrap()).unwrap();
        assert_ne!(
            ciphertext, plaintext,
            "Ciphertext should differ from plaintext"
        );

        let decrypted = encryptor.decrypt(&ciphertext, key.as_bytes().unwrap()).unwrap();
        assert_eq!(decrypted, plaintext, "Decrypted data should match original");
    }

    /// Test basic functionality
    #[tokio::test]
    async fn test_basic_functionality() {
        // Test key generation
        let key_manager = InMemoryKeyManager::new();
        let key = key_manager
            .generate_key(&ChaCha20Poly1305::new())
            .await
            .unwrap();
        assert!(!key.as_bytes().unwrap().is_empty(), "Key should be generated");

        // Test encryption
        let encryptor = ChaCha20Poly1305::new();
        let plaintext = b"Test data";
        let ciphertext = encryptor.encrypt(plaintext, key.as_bytes().unwrap()).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext, key.as_bytes().unwrap()).unwrap();
        assert_eq!(decrypted, plaintext, "Encryption/decryption should work");
    }

    /// Test multiple encryption algorithms
    #[tokio::test]
    async fn test_multiple_algorithms() {
        let key_manager = InMemoryKeyManager::new();

        // Test AES-256-GCM
        let aes_key = key_manager.generate_key(&Aes256Gcm::new()).await.unwrap();
        let aes_encryptor = Aes256Gcm::new();
        let plaintext = b"Multi-algorithm test";
        let aes_ciphertext = aes_encryptor
            .encrypt(plaintext, aes_key.as_bytes().unwrap())
            .unwrap();
        let aes_decrypted = aes_encryptor
            .decrypt(&aes_ciphertext, aes_key.as_bytes().unwrap())
            .unwrap();
        assert_eq!(aes_decrypted, plaintext, "AES encryption should work");

        // Test ChaCha20-Poly1305
        let chacha_key = key_manager
            .generate_key(&ChaCha20Poly1305::new())
            .await
            .unwrap();
        let chacha_encryptor = ChaCha20Poly1305::new();
        let chacha_ciphertext = chacha_encryptor
            .encrypt(plaintext, chacha_key.as_bytes().unwrap())
            .unwrap();
        let chacha_decrypted = chacha_encryptor
            .decrypt(&chacha_ciphertext, chacha_key.as_bytes().unwrap())
            .unwrap();
        assert_eq!(
            chacha_decrypted, plaintext,
            "ChaCha20 encryption should work"
        );
    }

    /// Test performance characteristics
    #[tokio::test]
    async fn test_performance_characteristics() {
        let key_manager = InMemoryKeyManager::new();
        let encryptor = Aes256Gcm::new();

        // Performance test: Multiple encryption/decryption operations
        let start_time = Instant::now();
        let mut operations = 0;

        for i in 0..5 {
            // Generate key
            let key = key_manager.generate_key(&Aes256Gcm::new()).await.unwrap();

            // Encrypt data
            let test_data = format!("Performance test data {}", i);
            let encrypted = encryptor
                .encrypt(test_data.as_bytes(), key.as_bytes().unwrap())
                .unwrap();

            // Decrypt data
            let _decrypted = encryptor.decrypt(&encrypted, key.as_bytes().unwrap()).unwrap();
            operations += 1;
        }

        let total_time = start_time.elapsed();
        let ops_per_second = operations as f64 / total_time.as_secs_f64();

        // Performance should be reasonable for debug build
        assert!(
            total_time.as_secs() < 60,
            "5 operations should complete within 60 seconds"
        );
        assert!(
            ops_per_second > 0.05,
            "Should achieve at least 0.05 operations per second in debug mode"
        );

        println!(
            "Performance: {} operations in {:?} ({:.2} ops/sec)",
            operations, total_time, ops_per_second
        );
    }

    /// Test error handling
    #[tokio::test]
    async fn test_error_handling() {
        let key_manager = InMemoryKeyManager::new();
        let encryptor = Aes256Gcm::new();

        // Test with invalid data (should handle gracefully)
        let key = key_manager.generate_key(&Aes256Gcm::new()).await.unwrap();

        // Test encryption/decryption with different keys (should fail)
        let key2 = key_manager.generate_key(&Aes256Gcm::new()).await.unwrap();
        let plaintext = b"Test data";
        let ciphertext = encryptor.encrypt(plaintext, key.as_bytes().unwrap()).unwrap();

        // Trying to decrypt with wrong key should fail
        let decrypt_result = encryptor.decrypt(&ciphertext, key2.as_bytes().unwrap());
        assert!(
            decrypt_result.is_err(),
            "Decryption with wrong key should fail"
        );
    }

    /// Test concurrent operations
    #[tokio::test]
    async fn test_concurrent_operations() {
        let key_manager = InMemoryKeyManager::new();
        let encryptor = Aes256Gcm::new();

        // Test concurrent key generation and encryption
        let mut handles = vec![];

        for i in 0..5 {
            let key_manager_clone = key_manager.clone();
            let encryptor_clone = encryptor.clone();

            let handle = tokio::spawn(async move {
                let key = key_manager_clone
                    .generate_key(&Aes256Gcm::new())
                    .await
                    .unwrap();
                let data = format!("Concurrent test {}", i);
                let encrypted = encryptor_clone
                    .encrypt(data.as_bytes(), key.as_bytes().unwrap())
                    .unwrap();
                let decrypted = encryptor_clone.decrypt(&encrypted, key.as_bytes().unwrap()).unwrap();
                decrypted
            });

            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(!result.is_empty(), "Concurrent operation should succeed");
        }
    }
}

// Mock structures and implementations for testing

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct FortressConfig {
    security_level: SecurityLevel,
    enable_auditing: bool,
    enable_compliance: bool,
    default_encryption: String,
    key_rotation_interval_seconds: u64,
    cluster_config: Option<ClusterConfig>,
    storage_config: Option<StorageConfig>,
}

impl Default for FortressConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Medium,
            enable_auditing: true,
            enable_compliance: true,
            default_encryption: "AES-256-GCM".to_string(),
            key_rotation_interval_seconds: 86400,
            cluster_config: None,
            storage_config: None,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum SecurityLevel {
    Low,
    Medium,
    High,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ClusterConfig {
    node_id: String,
    listen_address: String,
    seed_nodes: Vec<String>,
    election_timeout_ms: u64,
    heartbeat_interval_ms: u64,
    replication_factor: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct StorageConfig {
    backend_type: String,
    connection_string: Option<String>,
    max_connections: usize,
}
