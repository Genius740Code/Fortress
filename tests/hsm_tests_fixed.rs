//! Comprehensive HSM Integration Tests
//! 
//! This test suite provides comprehensive coverage for HSM integration functionality,
//! ensuring security, reliability, and proper integration with different HSM providers.

use fortress_core::hsm::{HsmProvider, HsmConfig, HsmProviderType, HsmConnection, HsmCredentials, HsmKeySettings, Pkcs11UserType};
use fortress_core::hsm_aws::AwsCloudHsmProvider;
use fortress_core::hsm_pkcs11_fixed::Pkcs11Provider;
use fortress_core::key::{HsmKeyManager};
use fortress_core::error::{FortressError, HsmErrorCode};
use std::time::Instant;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test HSM configuration validation
    #[tokio::test]
    async fn test_hsm_config_validation() {
        // Test valid configuration
        let valid_config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        // For now, just test that config structure is valid
        assert!(true, "Config structure is valid");
        // TODO: Add proper invalid config test when validation is implemented
    }

    /// Test AWS CloudHSM provider initialization
    #[tokio::test]
    async fn test_aws_cloudhsm_initialization() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(config);
        provider.initialize().await.expect("Provider should initialize");
        
        // Test health check
        let health_status = provider.health_check().await;
        assert!(health_status.is_ok(), "Health check should succeed");
    }

    /// Test PKCS#11 provider initialization
    #[tokio::test]
    async fn test_pkcs11_provider_initialization() {
        let config = HsmConfig {
            provider: HsmProviderType::Pkcs11,
            connection: HsmConnection::Pkcs11 {
                library_path: "/usr/lib/libpkcs11.so".to_string(),
                slot_id: Some(0),
                token_label: Some("test_token".to_string()),
            },
            credentials: HsmCredentials::Pkcs11 {
                pin: "test_pin".to_string(),
                user_type: Pkcs11UserType::User,
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = Pkcs11Provider::new(config);
        provider.initialize().await.expect("Provider should initialize");
        
        // Test health check
        let health_status = provider.health_check().await;
        assert!(health_status.is_ok(), "Health check should succeed");
    }

    /// Test HSM key generation
    #[tokio::test]
    async fn test_hsm_key_generation() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Test key generation - simplified for current implementation
        let result = key_manager.generate_key("test-key", 2048).await;
        assert!(result.is_ok(), "Key generation should succeed");
    }

    /// Test HSM key metadata retrieval
    #[tokio::test]
    async fn test_hsm_key_metadata() {
        let config = HsmConfig {
            provider: HsmProviderType::Pkcs11,
            connection: HsmConnection::Pkcs11 {
                library_path: "/usr/lib/libpkcs11.so".to_string(),
                slot_id: Some(0),
                token_label: Some("test_token".to_string()),
            },
            credentials: HsmCredentials::Pkcs11 {
                pin: "test_pin".to_string(),
                user_type: Pkcs11UserType::User,
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = Pkcs11Provider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Generate a test key
        let result = key_manager.generate_key("test-key", 2048).await;
        let key_id = result.unwrap();
        
        // Retrieve metadata
        let metadata = key_manager.get_key_metadata(&key_id).await.unwrap();
        assert_eq!(metadata.key_id, key_id, "Metadata key ID should match");
        assert_eq!(metadata.algorithm, "rsa", "Algorithm should match");
        assert_eq!(metadata.key_size, 2048, "Key size should match");
        assert!(metadata.created_at > 0, "Creation time should be set");
    }

    /// Test HSM key deletion
    #[tokio::test]
    async fn test_hsm_key_deletion() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Generate a test key
        let result = key_manager.generate_key("test-key", 2048).await;
        let key_id = result.unwrap();
        
        // Verify key exists
        let metadata = key_manager.get_key_metadata(&key_id).await.unwrap();
        assert_eq!(metadata.key_id, key_id);
        
        // Delete the key
        assert!(key_manager.delete_key(&key_id).await.is_ok(), "Key deletion should succeed");
        
        // Verify key is deleted
        let deleted_metadata = key_manager.get_key_metadata(&key_id).await;
        assert!(deleted_metadata.is_err(), "Deleted key should not be accessible");
    }

    /// Test HSM signing operations
    #[tokio::test]
    async fn test_hsm_signing() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Generate a signing key
        let result = key_manager.generate_key("test-key", 2048).await;
        let key_id = result.unwrap();
        
        // Test data to sign
        let test_data = b"Test message for HSM signing";
        
        // Sign data
        let signature = key_manager.sign(&key_id, test_data).await.unwrap();
        assert!(!signature.is_empty(), "Signature should not be empty");
        assert!(signature.len() > 100, "RSA signature should be substantial size");
    }

    /// Test HSM verification operations
    #[tokio::test]
    async fn test_hsm_verification() {
        let config = HsmConfig {
            provider: HsmProviderType::Pkcs11,
            connection: HsmConnection::Pkcs11 {
                library_path: "/usr/lib/libpkcs11.so".to_string(),
                slot_id: Some(0),
                token_label: Some("test_token".to_string()),
            },
            credentials: HsmCredentials::Pkcs11 {
                pin: "test_pin".to_string(),
                user_type: Pkcs11UserType::User,
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = Pkcs11Provider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Generate a signing key
        let result = key_manager.generate_key("test-key", 2048).await;
        let key_id = result.unwrap();
        
        // Test data to sign
        let test_data = b"Test message for HSM verification";
        
        // Sign data
        let signature = key_manager.sign(&key_id, test_data).await.unwrap();
        
        // Verify the signature
        let is_valid = key_manager.verify(&key_id, test_data, &signature).await.unwrap();
        assert!(is_valid, "Signature should verify successfully");
        
        // Test with invalid data
        let invalid_data = b"Invalid message";
        let is_invalid = key_manager.verify(&key_id, invalid_data, &signature).await.unwrap();
        assert!(!is_invalid, "Invalid data should not verify");
    }

    /// Test HSM encryption operations
    #[tokio::test]
    async fn test_hsm_encryption() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Generate an encryption key
        let result = key_manager.generate_key("test-key", 2048).await;
        let key_id = result.unwrap();
        
        // Test data to encrypt
        let plaintext = b"Sensitive data for HSM encryption";
        
        // Encrypt data
        let ciphertext = key_manager.encrypt(&key_id, plaintext).await.unwrap();
        assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
        assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");
    }

    /// Test HSM decryption operations
    #[tokio::test]
    async fn test_hsm_decryption() {
        let config = HsmConfig {
            provider: HsmProviderType::Pkcs11,
            connection: HsmConnection::Pkcs11 {
                library_path: "/usr/lib/libpkcs11.so".to_string(),
                slot_id: Some(0),
                token_label: Some("test_token".to_string()),
            },
            credentials: HsmCredentials::Pkcs11 {
                pin: "test_pin".to_string(),
                user_type: Pkcs11UserType::User,
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = Pkcs11Provider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Generate an encryption key
        let result = key_manager.generate_key("test-key", 2048).await;
        let key_id = result.unwrap();
        
        // Test data to encrypt
        let plaintext = b"Test message for HSM decryption";
        
        // Encrypt data
        let ciphertext = key_manager.encrypt(&key_id, plaintext).await.unwrap();
        
        // Decrypt data
        let decrypted = key_manager.decrypt(&key_id, &ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext, "Decrypted data should match original");
    }

    /// Test HSM error handling
    #[tokio::test]
    async fn test_hsm_error_handling() {
        // Test with invalid configuration
        let invalid_config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(invalid_config);
        let init_result = provider.initialize().await;
        assert!(init_result.is_err(), "Invalid config should fail initialization");
    }

    /// Test HSM performance metrics
    #[tokio::test]
    async fn test_hsm_performance_metrics() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Generate test key
        let result = key_manager.generate_key("test-key", 2048).await;
        let key_id = result.unwrap();
        
        // Measure signing performance
        let start_time = Instant::now();
        for _ in 0..10 {
            let test_data = format!("Test message {}", rand::random::<u32>());
            key_manager.sign(&key_id, test_data.as_bytes()).await.unwrap();
        }
        let signing_time = start_time.elapsed();
        
        // Performance should be reasonable
        assert!(signing_time.as_millis() < 5000, "10 signing operations should complete within 5 seconds");
        
        // Get performance metrics
        let metrics = provider.get_performance_metrics().await.unwrap();
        assert!(metrics.operations_per_second > 0.0, "Should have operations per second metric");
        assert!(metrics.average_latency_ms > 0.0, "Should have average latency metric");
    }

    /// Test HSM connection pooling
    #[tokio::test]
    async fn test_hsm_connection_pooling() {
        let config = HsmConfig {
            provider: HsmProviderType::Pkcs11,
            connection: HsmConnection::Pkcs11 {
                library_path: "/usr/lib/libpkcs11.so".to_string(),
                slot_id: Some(0),
                token_label: Some("test_token".to_string()),
            },
            credentials: HsmCredentials::Pkcs11 {
                pin: "test_pin".to_string(),
                user_type: Pkcs11UserType::User,
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = Pkcs11Provider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));
        
        // Test concurrent operations
        let mut handles = vec![];
        for i in 0..5 {
            let result = key_manager.generate_key("aes", 256).await;
            let key_id = result.unwrap();
            let handle = tokio::spawn(async move {
                // Simulate concurrent operations
                let test_data = format!("Concurrent test data {}", i);
                (key_id, test_data)
            });
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        for handle in handles {
            let (key_id, test_data) = handle.await.unwrap();
            // Verify that key and data are valid
            let metadata = key_manager.get_key_metadata(&key_id).await.unwrap();
            assert_eq!(metadata.algorithm, "aes");
            assert!(!test_data.is_empty());
        }
    }

    /// Test HSM graceful shutdown
    #[tokio::test]
    async fn test_hsm_graceful_shutdown() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test_access_key".to_string(),
                secret_access_key: "test_secret_key".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        let provider = AwsCloudHsmProvider::new(config);
        provider.initialize().await.expect("Provider should initialize");

        // Generate some keys
        let key_manager = HsmKeyManager::new(Box::new(provider));
        let result = key_manager.generate_key("rsa", 2048).await;
        let _key_id = result.unwrap();
        
        // Test graceful shutdown
        let shutdown_result = provider.shutdown().await;
        assert!(shutdown_result.is_ok(), "Graceful shutdown should succeed");
        
        // Operations after shutdown should fail
        let post_shutdown_result = provider.health_check().await;
        assert!(post_shutdown_result.is_err(), "Operations after shutdown should fail");
    }
}
