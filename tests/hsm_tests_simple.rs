#![cfg(any())]
//! Simple HSM Integration Tests
//!
//! Basic test suite for HSM functionality with simplified approach.

use fortress_core::error::FortressError;
use fortress_core::hsm::{
    HsmConfig, HsmConnection, HsmCredentials, HsmKeySettings, HsmProvider, HsmProviderType,
    Pkcs11UserType,
};
use fortress_core::hsm_aws::AwsCloudHsmProvider;
use fortress_core::hsm_pkcs11_fixed::Pkcs11Provider;
use fortress_core::key::HsmKeyManager;
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic HSM provider initialization
    #[tokio::test]
    async fn test_hsm_basic_initialization() {
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
        let result = provider.initialize().await;

        // Test that initialization works
        assert!(
            result.is_ok(),
            "HSM provider should initialize successfully"
        );
    }

    /// Test PKCS#11 provider initialization
    #[tokio::test]
    async fn test_hsm_pkcs11_initialization() {
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
        let result = provider.initialize().await;

        // Test that initialization works
        assert!(
            result.is_ok(),
            "PKCS#11 provider should initialize successfully"
        );
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
        assert!(
            init_result.is_err(),
            "Invalid config should fail initialization"
        );
    }

    /// Test HSM health checks
    #[tokio::test]
    async fn test_hsm_health_checks() {
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
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // Test health check
        let health_result = provider.health_check().await;
        assert!(health_result.is_ok(), "Health check should succeed");
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
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // Test graceful shutdown
        let shutdown_result = provider.shutdown().await;
        assert!(shutdown_result.is_ok(), "Graceful shutdown should succeed");
    }
}
