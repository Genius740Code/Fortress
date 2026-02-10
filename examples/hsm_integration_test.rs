//! Simple HSM integration test to verify basic functionality

use fortress_core::hsm::{HsmConfig, HsmConnection, HsmCredentials, HsmKeySettings, HsmProviderType, Pkcs11UserType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing HSM integration...");
    
    // Test AWS CloudHSM configuration
    let aws_config = HsmConfig {
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
    
    println!("✓ AWS CloudHSM configuration created successfully");
    
    // Test PKCS#11 configuration
    let pkcs11_config = HsmConfig {
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
    
    println!("✓ PKCS#11 configuration created successfully");
    
    // Test key settings
    let settings = HsmKeySettings::default();
    assert!(!settings.extractable);
    assert!(settings.sensitive);
    assert_eq!(settings.default_key_size, 256);
    
    println!("✓ HSM key settings work correctly");
    
    println!("All HSM integration tests passed! ✅");
    
    Ok(())
}
