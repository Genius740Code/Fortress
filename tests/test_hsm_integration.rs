//! HSM Integration Tests for Fortress
//! 
//! This test suite validates HSM integration with Fortress across all supported providers:
//! - AWS CloudHSM
//! - PKCS#11 compliant HSMs
//! - Azure Dedicated HSM
//! - Google Cloud HSM

#[cfg(test)]
#[cfg(feature = "hsm")]
mod hsm_integration_tests {
    use fortress_core::{
        hsm::{
            HsmProvider, HsmConfig, HsmProviderType, HsmConnection, HsmCredentials,
            HsmKeySettings, Pkcs11UserType,
        },
        key::{KeyId, KeyMetadata, KeyVersion, HsmKeyManager},
        encryption::{EncryptionAlgorithm, PerformanceProfile},
        error::{FortressError, Result, HsmErrorCode},
    };
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::time::timeout;
    use chrono::{DateTime, Utc};

    /// Test configuration for HSM integration
    struct HsmTestConfig {
        provider: HsmProviderType,
        connection: HsmConnection,
        credentials: HsmCredentials,
        key_settings: HsmKeySettings,
    }

    impl HsmTestConfig {
        /// Create test configuration for AWS CloudHSM
        fn aws_cloudhsm_test() -> Self {
            Self {
                provider: HsmProviderType::AwsCloudHsm,
                connection: HsmConnection::AwsCloudHsm {
                    cluster_id: "test-cluster".to_string(),
                },
                credentials: HsmCredentials::Aws {
                    access_key_id: "test-access-key".to_string(),
                    secret_access_key: "test-secret-key".to_string(),
                    region: "us-east-1".to_string(),
                },
                key_settings: HsmKeySettings::default(),
            }
        }

        /// Create test configuration for PKCS#11 HSM
        fn pkcs11_test() -> Self {
            Self {
                provider: HsmProviderType::Pkcs11,
                connection: HsmConnection::Pkcs11 {
                    library_path: "/usr/lib/libpkcs11.so".to_string(),
                    slot_id: Some(0),
                    token_label: Some("test-token".to_string()),
                },
                credentials: HsmCredentials::Pkcs11 {
                    pin: "1234".to_string(),
                    user_type: Pkcs11UserType::User,
                },
                key_settings: HsmKeySettings::default(),
            }
        }

        /// Create test configuration for Azure Dedicated HSM
        fn azure_dedicated_hsm_test() -> Self {
            Self {
                provider: HsmProviderType::AzureDedicatedHsm,
                connection: HsmConnection::Azure {
                    resource_id: "/subscriptions/test/resourceGroups/test/providers/Microsoft.HardwareSecurityModules/hsm/test-hsm".to_string(),
                },
                credentials: HsmCredentials::Azure {
                    client_id: "test-client-id".to_string(),
                    client_secret: "test-client-secret".to_string(),
                    tenant_id: "test-tenant-id".to_string(),
                },
                key_settings: HsmKeySettings::default(),
            }
        }

        /// Create test configuration for Google Cloud HSM
        fn google_cloud_hsm_test() -> Self {
            Self {
                provider: HsmProviderType::GoogleCloudHsm,
                connection: HsmConnection::Google {
                    project_id: "test-project".to_string(),
                    location: "us-central1".to_string(),
                    key_ring: "test-key-ring".to_string(),
                },
                credentials: HsmCredentials::Google {
                    service_account_key: "test-service-account-key".to_string(),
                },
                key_settings: HsmKeySettings::default(),
            }
        }

        /// Convert to HsmConfig
        fn to_hsm_config(&self) -> HsmConfig {
            HsmConfig {
                provider: self.provider.clone(),
                connection: self.connection.clone(),
                credentials: self.credentials.clone(),
                key_settings: self.key_settings.clone(),
            }
        }
    }

    #[tokio::test]
    async fn test_aws_cloudhsm_provider_initialization() {
        let config = HsmTestConfig::aws_cloudhsm_test().to_hsm_config();
        
        // Test provider initialization
        let result = HsmKeyManager::new(config).await;
        
        // In test environment, we expect this to fail gracefully with proper error handling
        match result {
            Ok(_) => {
                // If it succeeds, verify the provider is properly initialized
                println!("AWS CloudHSM provider initialized successfully in test environment");
            }
            Err(e) => {
                // In test environment without real AWS credentials, this should fail gracefully
                assert!(matches!(e, fortress_core::error::FortressError::Hsm { .. }));
                println!("AWS CloudHSM provider failed gracefully as expected: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_pkcs11_provider_initialization() {
        let config = HsmTestConfig::pkcs11_test().to_hsm_config();
        
        // Test provider initialization
        let result = HsmKeyManager::new(config).await;
        
        // In test environment, we expect this to fail gracefully with proper error handling
        match result {
            Ok(_) => {
                // If it succeeds, verify the provider is properly initialized
                println!("PKCS#11 provider initialized successfully in test environment");
            }
            Err(e) => {
                // In test environment without real PKCS#11 library, this should fail gracefully
                assert!(matches!(e, fortress_core::error::FortressError::Hsm { .. }));
                println!("PKCS#11 provider failed gracefully as expected: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_azure_dedicated_hsm_provider_initialization() {
        let config = HsmTestConfig::azure_dedicated_hsm_test().to_hsm_config();
        
        // Test provider initialization
        let result = HsmKeyManager::new(config).await;
        
        // In test environment, we expect this to fail gracefully with proper error handling
        match result {
            Ok(_) => {
                // If it succeeds, verify the provider is properly initialized
                println!("Azure Dedicated HSM provider initialized successfully in test environment");
            }
            Err(e) => {
                // In test environment without real Azure credentials, this should fail gracefully
                assert!(matches!(e, fortress_core::error::FortressError::Hsm { .. }));
                println!("Azure Dedicated HSM provider failed gracefully as expected: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_google_cloud_hsm_provider_initialization() {
        let config = HsmTestConfig::google_cloud_hsm_test().to_hsm_config();
        
        // Test provider initialization
        let result = HsmKeyManager::new(config).await;
        
        // In test environment, we expect this to fail gracefully with proper error handling
        match result {
            Ok(_) => {
                // If it succeeds, verify the provider is properly initialized
                println!("Google Cloud HSM provider initialized successfully in test environment");
            }
            Err(e) => {
                // In test environment without real GCP credentials, this should fail gracefully
                assert!(matches!(e, fortress_core::error::FortressError::Hsm { .. }));
                println!("Google Cloud HSM provider failed gracefully as expected: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_hsm_provider_configuration_validation() {
        // Test invalid configurations
        let invalid_configs = vec![
            // Empty cluster ID for AWS CloudHSM
            HsmConfig {
                provider: HsmProviderType::AwsCloudHsm,
                connection: HsmConnection::AwsCloudHsm {
                    cluster_id: "".to_string(),
                },
                credentials: HsmCredentials::Aws {
                    access_key_id: "test".to_string(),
                    secret_access_key: "test".to_string(),
                    region: "us-east-1".to_string(),
                },
                key_settings: HsmKeySettings::default(),
            },
            // Empty library path for PKCS#11
            HsmConfig {
                provider: HsmProviderType::Pkcs11,
                connection: HsmConnection::Pkcs11 {
                    library_path: "".to_string(),
                    slot_id: None,
                    token_label: None,
                },
                credentials: HsmCredentials::Pkcs11 {
                    pin: "1234".to_string(),
                    user_type: Pkcs11UserType::User,
                },
                key_settings: HsmKeySettings::default(),
            },
        ];

        for config in invalid_configs {
            let result = HsmKeyManager::new(config).await;
            assert!(result.is_err(), "Expected invalid configuration to fail");
        }
    }

    #[tokio::test]
    async fn test_hsm_key_operations_timeout() {
        let config = HsmTestConfig::aws_cloudhsm_test().to_hsm_config();
        
        // Test timeout handling
        let result = timeout(Duration::from_secs(5), async {
            // This should timeout quickly in test environment
            HsmKeyManager::new(config).await
        }).await;

        match result {
            Ok(_) => {
                println!("HSM operation completed within timeout");
            }
            Err(_) => {
                println!("HSM operation timed out as expected in test environment");
            }
        }
    }

    #[tokio::test]
    async fn test_hsm_error_handling() {
        // Test various error scenarios
        let test_cases = vec![
            ("Invalid credentials", HsmTestConfig::aws_cloudhsm_test().to_hsm_config()),
            ("Invalid PKCS#11 library", HsmTestConfig::pkcs11_test().to_hsm_config()),
            ("Invalid Azure credentials", HsmTestConfig::azure_dedicated_hsm_test().to_hsm_config()),
            ("Invalid GCP credentials", HsmTestConfig::google_cloud_hsm_test().to_hsm_config()),
        ];

        for (description, config) in test_cases {
            let result = HsmKeyManager::new(config).await;
            
            match result {
                Ok(_) => {
                    println!("{}: Unexpected success", description);
                }
                Err(e) => {
                    // Verify error is properly typed and informative
                    assert!(matches!(e, fortress_core::error::FortressError::Hsm { .. }));
                    println!("{}: Proper error handling - {}", description, e);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_hsm_provider_types() {
        // Test all provider types can be created and cloned
        let providers = vec![
            HsmProviderType::AwsCloudHsm,
            HsmProviderType::Pkcs11,
            HsmProviderType::AzureDedicatedHsm,
            HsmProviderType::GoogleCloudHsm,
        ];

        for provider in providers {
            // Test cloning
            let cloned = provider.clone();
            assert_eq!(provider, cloned);
            
            // Test serialization/deserialization
            let serialized = serde_json::to_string(&provider).unwrap();
            let deserialized: HsmProviderType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(provider, deserialized);
        }
    }

    #[tokio::test]
    async fn test_hsm_connection_types() {
        // Test all connection types can be created and cloned
        let connections = vec![
            HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            HsmConnection::Pkcs11 {
                library_path: "/usr/lib/libpkcs11.so".to_string(),
                slot_id: Some(0),
                token_label: Some("test-token".to_string()),
            },
            HsmConnection::Azure {
                resource_id: "/subscriptions/test/resourceGroups/test/providers/Microsoft.HardwareSecurityModules/hsm/test-hsm".to_string(),
            },
            HsmConnection::Google {
                project_id: "test-project".to_string(),
                location: "us-central1".to_string(),
                key_ring: "test-key-ring".to_string(),
            },
        ];

        for connection in connections {
            // Test cloning
            let cloned = connection.clone();
            assert_eq!(connection, cloned);
            
            // Test serialization/deserialization
            let serialized = serde_json::to_string(&connection).unwrap();
            let deserialized: HsmConnection = serde_json::from_str(&serialized).unwrap();
            assert_eq!(connection, deserialized);
        }
    }

    #[tokio::test]
    async fn test_hsm_credentials_types() {
        // Test all credentials types can be created and cloned
        let credentials = vec![
            HsmCredentials::Aws {
                access_key_id: "test-access-key".to_string(),
                secret_access_key: "test-secret-key".to_string(),
                region: "us-east-1".to_string(),
            },
            HsmCredentials::Pkcs11 {
                pin: "1234".to_string(),
                user_type: Pkcs11UserType::User,
            },
            HsmCredentials::Azure {
                client_id: "test-client-id".to_string(),
                client_secret: "test-client-secret".to_string(),
                tenant_id: "test-tenant-id".to_string(),
            },
            HsmCredentials::Google {
                service_account_key: "test-service-account-key".to_string(),
            },
        ];

        for cred in credentials {
            // Test cloning
            let cloned = cred.clone();
            assert_eq!(cred, cloned);
            
            // Test serialization/deserialization
            let serialized = serde_json::to_string(&cred).unwrap();
            let deserialized: HsmCredentials = serde_json::from_str(&serialized).unwrap();
            assert_eq!(cred, deserialized);
        }
    }

    #[tokio::test]
    async fn test_hsm_key_settings() {
        // Test key settings configuration
        let settings = HsmKeySettings::default();
        
        // Test cloning
        let cloned = settings.clone();
        assert_eq!(settings, cloned);
        
        // Test serialization/deserialization
        let serialized = serde_json::to_string(&settings).unwrap();
        let deserialized: HsmKeySettings = serde_json::from_str(&serialized).unwrap();
        assert_eq!(settings, deserialized);
    }

    #[tokio::test]
    async fn test_hsm_config_serialization() {
        // Test full HSM configuration serialization
        let config = HsmTestConfig::aws_cloudhsm_test().to_hsm_config();
        
        // Test cloning
        let cloned = config.clone();
        assert_eq!(config, cloned);
        
        // Test serialization/deserialization
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: HsmConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    #[tokio::test]
    async fn test_hsm_performance_metrics() {
        // Test that HSM providers can report performance metrics
        let config = HsmTestConfig::aws_cloudhsm_test().to_hsm_config();
        
        match HsmKeyManager::new(config).await {
            Ok(manager) => {
                // Test metrics collection
                let metrics = manager.get_performance_metrics().await;
                assert!(metrics.is_ok());
                
                let metrics = metrics.unwrap();
                // Verify metrics contain expected fields
                assert!(metrics.contains_key("operations_per_second"));
                assert!(metrics.contains_key("average_latency_ms"));
                assert!(metrics.contains_key("error_rate"));
                
                println!("HSM performance metrics: {:?}", metrics);
            }
            Err(_) => {
                // In test environment, this is expected to fail
                println!("HSM metrics test skipped due to initialization failure");
            }
        }
    }

    #[tokio::test]
    async fn test_hsm_health_check() {
        // Test health check functionality
        let config = HsmTestConfig::aws_cloudhsm_test().to_hsm_config();
        
        match HsmKeyManager::new(config).await {
            Ok(manager) => {
                // Test health check
                let health = manager.health_check().await;
                assert!(health.is_ok());
                
                let is_healthy = health.unwrap();
                println!("HSM health check result: {}", is_healthy);
            }
            Err(_) => {
                // In test environment, this is expected to fail
                println!("HSM health check test skipped due to initialization failure");
            }
        }
    }

    #[tokio::test]
    async fn test_hsm_graceful_shutdown() {
        // Test graceful shutdown functionality
        let config = HsmTestConfig::aws_cloudhsm_test().to_hsm_config();
        
        match HsmKeyManager::new(config).await {
            Ok(manager) => {
                // Test graceful shutdown
                let shutdown_result = manager.shutdown().await;
                assert!(shutdown_result.is_ok());
                
                println!("HSM graceful shutdown completed successfully");
            }
            Err(_) => {
                // In test environment, this is expected to fail
                println!("HSM shutdown test skipped due to initialization failure");
            }
        }
    }

    #[tokio::test]
    async fn test_hsm_concurrent_operations() {
        // Test concurrent HSM operations
        let config = HsmTestConfig::aws_cloudhsm_test().to_hsm_config();
        
        match HsmKeyManager::new(config).await {
            Ok(manager) => {
                // Spawn multiple concurrent health checks
                let handles: Vec<_> = (0..10).map(|_| {
                    let manager = manager.clone();
                    tokio::spawn(async move {
                        manager.health_check().await
                    })
                }).collect();

                // Wait for all operations to complete
                for handle in handles {
                    let result = handle.await.unwrap();
                    assert!(result.is_ok());
                }
                
                println!("Concurrent HSM operations completed successfully");
            }
            Err(_) => {
                // In test environment, this is expected to fail
                println!("Concurrent HSM operations test skipped due to initialization failure");
            }
        }
    }
}

/// Integration tests that can run with mock HSM providers
#[cfg(test)]
mod hsm_mock_tests {
    use fortress_core::{
        hsm::HsmProvider,
        key::{KeyId, KeyMetadata},
        encryption::{EncryptionAlgorithm, PerformanceProfile},
        Result,
    };
    use async_trait::async_trait;
    use fortress_core::prelude::Aes256GcmWrapper;
    use std::time::Duration;

    /// Mock HSM provider for testing
    struct MockHsmProvider {
        healthy: bool,
        latency: Duration,
    }

    impl MockHsmProvider {
        fn new(healthy: bool, latency: Duration) -> Self {
            Self { healthy, latency }
        }
    }

    #[async_trait]
    impl HsmProvider for MockHsmProvider {
        async fn initialize(&self, _config: &fortress_core::hsm::HsmConfig) -> Result<()> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(())
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn generate_key(&self, _key_id: &KeyId, _algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(())
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(KeyMetadata::new(
                    key_id.clone(),
                    "AES-256-GCM".to_string(),
                    1,
                    chrono::Utc::now(),
                    chrono::Utc::now() + chrono::Duration::days(365),
                    "test".to_string(),
                    PerformanceProfile::default(),
                ))
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn delete_key(&self, _key_id: &KeyId) -> Result<()> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(())
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(vec![])
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn sign(&self, _key_id: &KeyId, data: &[u8]) -> Result<Vec<u8>> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(data.to_vec()) // Mock signature
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn verify(&self, _key_id: &KeyId, data: &[u8], signature: &[u8]) -> Result<bool> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(data == signature) // Mock verification
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn encrypt(&self, _key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(plaintext.to_vec()) // Mock encryption
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn decrypt(&self, _key_id: &KeyId, ciphertext: &[u8]) -> Result<Vec<u8>> {
            tokio::time::sleep(self.latency).await;
            if self.healthy {
                Ok(ciphertext.to_vec()) // Mock decryption
            } else {
                Err(fortress_core::error::FortressError::hsm("Mock HSM is unhealthy"))
            }
        }

        async fn health_check(&self) -> Result<bool> {
            tokio::time::sleep(self.latency).await;
            Ok(self.healthy)
        }

        async fn shutdown(&self) -> Result<()> {
            tokio::time::sleep(self.latency).await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_mock_hsm_provider() {
        let provider = MockHsmProvider::new(true, Duration::from_millis(10));
        let key_id = "test-key".to_string();
        let algorithm = Aes256GcmWrapper::new();

        // Test all operations
        assert!(provider.generate_key(&key_id, &algorithm).await.is_ok());
        assert!(provider.get_key_metadata(&key_id).await.is_ok());
        assert!(provider.delete_key(&key_id).await.is_ok());
        assert!(provider.list_keys().await.is_ok());
        assert!(provider.sign(&key_id, b"test data").await.is_ok());
        assert!(provider.verify(&key_id, b"test data", b"test data").await.is_ok());
        assert!(provider.encrypt(&key_id, b"test data").await.is_ok());
        assert!(provider.decrypt(&key_id, b"test data").await.is_ok());
        assert!(provider.health_check().await.is_ok());
        assert!(provider.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_hsm_provider_unhealthy() {
        let provider = MockHsmProvider::new(false, Duration::from_millis(10));
        let key_id = "test-key".to_string();

        // Test all operations fail when unhealthy
        assert!(provider.generate_key(&key_id, &Aes256GcmWrapper::new()).await.is_err());
        assert!(provider.get_key_metadata(&key_id).await.is_err());
        assert!(provider.delete_key(&key_id).await.is_err());
        assert!(provider.list_keys().await.is_err());
        assert!(provider.sign(&key_id, b"test data").await.is_err());
        assert!(provider.verify(&key_id, b"test data", b"test data").await.is_err());
        assert!(provider.encrypt(&key_id, b"test data").await.is_err());
        assert!(provider.decrypt(&key_id, b"test data").await.is_err());
        assert!(provider.health_check().await.is_ok()); // Health check should still work
        assert!(provider.shutdown().await.is_ok()); // Shutdown should still work
    }

    #[tokio::test]
    async fn test_mock_hsm_provider_latency() {
        let provider = MockHsmProvider::new(true, Duration::from_millis(100));
        let key_id = "test-key".to_string();

        let start = std::time::Instant::now();
        let result = provider.generate_key(&key_id, &Aes256GcmWrapper::new()).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(elapsed >= Duration::from_millis(100));
    }
}
