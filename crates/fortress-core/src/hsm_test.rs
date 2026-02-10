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
}
