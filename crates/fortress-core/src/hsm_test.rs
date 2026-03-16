//! HSM integration tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aegis256;
    use crate::hsm::{HsmConfig, HsmConnection, HsmCredentials, HsmKeySettings, HsmProviderType, Pkcs11UserType};

    #[tokio::test]
    async fn test_hsm_config_creation() {
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test-key".to_string(),
                secret_access_key: "test-secret".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        assert!(matches!(config.provider, HsmProviderType::AwsCloudHsm));
    }

    #[tokio::test]
    async fn test_pkcs11_config_creation() {
        let config = HsmConfig {
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
        };

        assert!(matches!(config.provider, HsmProviderType::Pkcs11));
    }

    #[tokio::test]
    async fn test_hsm_key_settings_default() {
        let settings = HsmKeySettings::default();
        
        assert!(!settings.extractable);
        assert!(settings.sensitive);
        assert_eq!(settings.default_key_size, 256);
        assert!(settings.key_template.contains_key("token"));
        assert!(settings.key_template.contains_key("private"));
    }

    #[tokio::test]
    async fn test_aws_cloudhsm_provider_initialization() {
        let provider = crate::hsm::AwsCloudHsmProvider::new().await.unwrap();
        
        let config = HsmConfig {
            provider: HsmProviderType::AwsCloudHsm,
            connection: HsmConnection::AwsCloudHsm {
                cluster_id: "test-cluster".to_string(),
            },
            credentials: HsmCredentials::Aws {
                access_key_id: "test-key".to_string(),
                secret_access_key: "test-secret".to_string(),
                region: "us-east-1".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        // This should succeed (though it will log warnings about test credentials)
        let result = provider.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pkcs11_provider_initialization() {
        let provider = crate::hsm::Pkcs11Provider::new().await.unwrap();
        
        let config = HsmConfig {
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
        };

        // This should succeed (though it will log warnings about test library)
        let result = provider.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hsm_provider_health_check() {
        let aws_provider = crate::hsm::AwsCloudHsmProvider::new().await.unwrap();
        let pkcs11_provider = crate::hsm::Pkcs11Provider::new().await.unwrap();

        // Both providers should return healthy (placeholder implementation)
        assert!(aws_provider.health_check().await.unwrap());
        assert!(pkcs11_provider.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn test_hsm_key_operations() {
        let provider = crate::hsm::AwsCloudHsmProvider::new().await.unwrap();
        let algorithm = Aegis256::new();
        let key_id = "test-key-123".to_string();

        // Test key generation (should succeed with placeholder)
        let result = provider.generate_key(&key_id, &algorithm).await;
        assert!(result.is_ok());

        // Test metadata retrieval (should succeed with placeholder)
        let metadata = provider.get_key_metadata(&key_id).await.unwrap();
        assert_eq!(metadata.key_id, key_id);

        // Test key listing (should return empty list for now)
        let keys = provider.list_keys().await.unwrap();
        assert!(keys.is_empty());

        // Test key deletion (should succeed with placeholder)
        let result = provider.delete_key(&key_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_azure_hsm_config_creation() {
        let config = HsmConfig {
            provider: HsmProviderType::AzureDedicatedHsm,
            connection: HsmConnection::Azure {
                resource_id: "/subscriptions/test-subscription/resourceGroups/test-rg/providers/Microsoft.HardwareSecurityModules/hsm/test-hsm".to_string(),
            },
            credentials: HsmCredentials::Azure {
                client_id: "test-client-id".to_string(),
                client_secret: "test-client-secret".to_string(),
                tenant_id: "test-tenant-id".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        assert!(matches!(config.provider, HsmProviderType::AzureDedicatedHsm));
    }

    #[tokio::test]
    async fn test_google_cloud_hsm_config_creation() {
        let config = HsmConfig {
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
        };

        assert!(matches!(config.provider, HsmProviderType::GoogleCloudHsm));
    }

    #[tokio::test]
    async fn test_azure_hsm_provider_initialization() {
        let provider = crate::hsm::AzureDedicatedHsmProvider::new().await.unwrap();
        
        let config = HsmConfig {
            provider: HsmProviderType::AzureDedicatedHsm,
            connection: HsmConnection::Azure {
                resource_id: "/subscriptions/test-subscription/resourceGroups/test-rg/providers/Microsoft.HardwareSecurityModules/hsm/test-hsm".to_string(),
            },
            credentials: HsmCredentials::Azure {
                client_id: "test-client-id".to_string(),
                client_secret: "test-client-secret".to_string(),
                tenant_id: "test-tenant-id".to_string(),
            },
            key_settings: HsmKeySettings::default(),
        };

        // This should succeed (though it will log warnings about test credentials)
        let result = provider.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_google_cloud_hsm_provider_initialization() {
        let provider = crate::hsm::GoogleCloudHsmProvider::new().await.unwrap();
        
        let config = HsmConfig {
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
        };

        // This should succeed (though it will log warnings about test credentials)
        let result = provider.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_all_hsm_providers_health_check() {
        let aws_provider = crate::hsm::AwsCloudHsmProvider::new().await.unwrap();
        let pkcs11_provider = crate::hsm::Pkcs11Provider::new().await.unwrap();
        let azure_provider = crate::hsm::AzureDedicatedHsmProvider::new().await.unwrap();
        let google_provider = crate::hsm::GoogleCloudHsmProvider::new().await.unwrap();

        // All providers should return healthy (placeholder implementation)
        assert!(aws_provider.health_check().await.unwrap());
        assert!(pkcs11_provider.health_check().await.unwrap());
        assert!(azure_provider.health_check().await.unwrap());
        assert!(google_provider.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn test_azure_hsm_key_operations() {
        let provider = crate::hsm::AzureDedicatedHsmProvider::new().await.unwrap();
        let algorithm = Aegis256::new();
        let key_id = "test-azure-key-456".to_string();

        // Test key generation
        let result = provider.generate_key(&key_id, &algorithm).await;
        assert!(result.is_ok());

        // Test metadata retrieval
        let metadata = provider.get_key_metadata(&key_id).await.unwrap();
        assert_eq!(metadata.key_id, key_id);

        // Test key listing
        let keys = provider.list_keys().await.unwrap();
        assert!(!keys.is_empty()); // Azure should return sample keys

        // Test key deletion
        let result = provider.delete_key(&key_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_google_cloud_hsm_key_operations() {
        let provider = crate::hsm::GoogleCloudHsmProvider::new().await.unwrap();
        let algorithm = Aegis256::new();
        let key_id = "test-google-key-789".to_string();

        // Test key generation
        let result = provider.generate_key(&key_id, &algorithm).await;
        assert!(result.is_ok());

        // Test metadata retrieval
        let metadata = provider.get_key_metadata(&key_id).await.unwrap();
        assert_eq!(metadata.key_id, key_id);

        // Test key listing
        let keys = provider.list_keys().await.unwrap();
        assert!(!keys.is_empty()); // Google should return sample keys

        // Test key deletion
        let result = provider.delete_key(&key_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hsm_sign_verify_operations() {
        let providers = vec![
            crate::hsm::AwsCloudHsmProvider::new().await.unwrap(),
            crate::hsm::Pkcs11Provider::new().await.unwrap(),
            crate::hsm::AzureDedicatedHsmProvider::new().await.unwrap(),
            crate::hsm::GoogleCloudHsmProvider::new().await.unwrap(),
        ];

        for provider in providers {
            let key_id = "test-sign-key".to_string();
            let data = b"test data to sign";

            // Initialize provider with minimal config for testing
            let config = match provider.as_ref() {
                p if p.downcast_ref::<crate::hsm::AwsCloudHsmProvider>().is_some() => HsmConfig {
                    provider: HsmProviderType::AwsCloudHsm,
                    connection: HsmConnection::AwsCloudHsm {
                        cluster_id: "test-cluster".to_string(),
                    },
                    credentials: HsmCredentials::Aws {
                        access_key_id: "test-key".to_string(),
                        secret_access_key: "test-secret".to_string(),
                        region: "us-east-1".to_string(),
                    },
                    key_settings: HsmKeySettings::default(),
                },
                p if p.downcast_ref::<crate::hsm::Pkcs11Provider>().is_some() => HsmConfig {
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
                },
                p if p.downcast_ref::<crate::hsm::AzureDedicatedHsmProvider>().is_some() => HsmConfig {
                    provider: HsmProviderType::AzureDedicatedHsm,
                    connection: HsmConnection::Azure {
                        resource_id: "test-resource".to_string(),
                    },
                    credentials: HsmCredentials::Azure {
                        client_id: "test-client".to_string(),
                        client_secret: "test-secret".to_string(),
                        tenant_id: "test-tenant".to_string(),
                    },
                    key_settings: HsmKeySettings::default(),
                },
                p if p.downcast_ref::<crate::hsm::GoogleCloudHsmProvider>().is_some() => HsmConfig {
                    provider: HsmProviderType::GoogleCloudHsm,
                    connection: HsmConnection::Google {
                        project_id: "test-project".to_string(),
                        location: "us-central1".to_string(),
                        key_ring: "test-keyring".to_string(),
                    },
                    credentials: HsmCredentials::Google {
                        service_account_key: "test-key".to_string(),
                    },
                    key_settings: HsmKeySettings::default(),
                },
                _ => unreachable!(),
            };

            let _ = provider.initialize(&config).await;

            // Test signing and verification
            let signature = provider.sign(&key_id, data).await.unwrap();
            let is_valid = provider.verify(&key_id, data, &signature).await.unwrap();
            assert!(is_valid);
        }
    }

    #[tokio::test]
    async fn test_hsm_encrypt_decrypt_operations() {
        let providers = vec![
            crate::hsm::AwsCloudHsmProvider::new().await.unwrap(),
            crate::hsm::Pkcs11Provider::new().await.unwrap(),
            crate::hsm::AzureDedicatedHsmProvider::new().await.unwrap(),
            crate::hsm::GoogleCloudHsmProvider::new().await.unwrap(),
        ];

        for provider in providers {
            let key_id = "test-encrypt-key".to_string();
            let plaintext = b"test data to encrypt";

            // Initialize provider with minimal config for testing
            let config = HsmConfig {
                provider: HsmProviderType::AwsCloudHsm, // Simplified for test
                connection: HsmConnection::AwsCloudHsm {
                    cluster_id: "test-cluster".to_string(),
                },
                credentials: HsmCredentials::Aws {
                    access_key_id: "test-key".to_string(),
                    secret_access_key: "test-secret".to_string(),
                    region: "us-east-1".to_string(),
                },
                key_settings: HsmKeySettings::default(),
            };

            let _ = provider.initialize(&config).await;

            // Test encryption and decryption
            let ciphertext = provider.encrypt(&key_id, plaintext).await.unwrap();
            let decrypted = provider.decrypt(&key_id, &ciphertext).await.unwrap();
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }
}
