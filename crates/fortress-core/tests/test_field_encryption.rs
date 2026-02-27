//! Integration tests for per-field encryption
//!
//! This test module provides comprehensive testing of the field-level encryption
//! system including different algorithms, strategies, and edge cases.

use fortress_core::{
    field_encryption::*,
    field_encryption_manager::*,
    key::{InMemoryKeyManager, KeyManager},
    encryption::{EncryptionAlgorithm, PerformanceProfile},
};
use std::collections::HashMap;

#[tokio::test]
async fn test_basic_field_encryption() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    let field = FieldIdentifier::name("email");
    let plaintext = b"test@example.com";

    // Test encryption
    let encrypted = field_manager.encrypt_field(&field, plaintext).await.unwrap();
    assert!(!encrypted.ciphertext.is_empty());
    assert_ne!(encrypted.ciphertext, plaintext);
    assert_eq!(encrypted.metadata.field, field);

    // Test decryption
    let decrypted = field_manager
        .decrypt_field(&encrypted.ciphertext, &encrypted.metadata)
        .await
        .unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.field, field);
}

#[tokio::test]
async fn test_nested_field_encryption() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    let field = FieldIdentifier::path(vec!["user", "profile", "email"]);
    let plaintext = b"nested@example.com";

    let encrypted = field_manager.encrypt_field(&field, plaintext).await.unwrap();
    let decrypted = field_manager
        .decrypt_field(&encrypted.ciphertext, &encrypted.metadata)
        .await
        .unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.field, field);
}

#[tokio::test]
async fn test_indexed_field_encryption() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    let field = FieldIdentifier::indexed(vec!["users", "0", "email"], 1);
    let plaintext = b"indexed@example.com";

    let encrypted = field_manager.encrypt_field(&field, plaintext).await.unwrap();
    let decrypted = field_manager
        .decrypt_field(&encrypted.ciphertext, &encrypted.metadata)
        .await
        .unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.field, field);
}

#[tokio::test]
async fn test_field_configuration_management() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    let field = FieldIdentifier::name("ssn");

    // Initially no configuration
    let config = field_manager.get_field_config(&field).await.unwrap();
    assert!(config.is_none());

    // Create and set configuration
    let new_config = FieldEncryptionConfig::new(
        field.clone(),
        FieldEncryptionStrategy::Algorithm("aes256gcm".to_string()),
    )
    .with_performance_profile(PerformanceProfile::Fortress)
    .with_compliance_tag("HIPAA")
    .with_compliance_tag("PCI-DSS")
    .with_metadata("department".to_string(), "hr".to_string());

    field_manager.set_field_config(new_config.clone()).await.unwrap();

    // Retrieve configuration
    let retrieved = field_manager.get_field_config(&field).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();

    assert_eq!(retrieved.field, field);
    assert_eq!(retrieved.algorithm_name(), Some("aes256gcm"));
    assert_eq!(retrieved.performance_profile, PerformanceProfile::Fortress);
    assert_eq!(retrieved.compliance_tags.len(), 2);
    assert!(retrieved.compliance_tags.contains(&"HIPAA".to_string()));
    assert!(retrieved.compliance_tags.contains(&"PCI-DSS".to_string()));
    assert_eq!(retrieved.metadata.get("department"), Some(&"hr".to_string()));

    // List all configurations
    let configs = field_manager.list_field_configs().await.unwrap();
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].field, field);

    // Remove configuration
    field_manager.remove_field_config(&field).await.unwrap();
    let config = field_manager.get_field_config(&field).await.unwrap();
    assert!(config.is_none());
}

#[tokio::test]
async fn test_different_encryption_strategies() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    let plaintext = b"sensitive_data";

    // Test default strategy
    let field1 = FieldIdentifier::name("field1");
    let config1 = FieldEncryptionConfig::new(field1.clone(), FieldEncryptionStrategy::Default);
    field_manager.set_field_config(config1).await.unwrap();

    let encrypted1 = field_manager.encrypt_field(&field1, plaintext).await.unwrap();
    assert!(encrypted1.ciphertext != plaintext);

    // Test specific algorithm strategy
    let field2 = FieldIdentifier::name("field2");
    let config2 = FieldEncryptionConfig::new(
        field2.clone(),
        FieldEncryptionStrategy::Algorithm("aes256gcm".to_string()),
    );
    field_manager.set_field_config(config2).await.unwrap();

    let encrypted2 = field_manager.encrypt_field(&field2, plaintext).await.unwrap();
    assert!(encrypted2.ciphertext != plaintext);
    assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext); // Different algorithms

    // Test no encryption strategy
    let field3 = FieldIdentifier::name("field3");
    let config3 = FieldEncryptionConfig::new(field3.clone(), FieldEncryptionStrategy::None);
    field_manager.set_field_config(config3).await.unwrap();

    let result = field_manager.encrypt_field(&field3, plaintext).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_batch_encryption() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    // Prepare test data
    let mut fields = HashMap::new();
    fields.insert(FieldIdentifier::name("email"), b"user@example.com".to_vec());
    fields.insert(FieldIdentifier::name("phone"), b"+1234567890".to_vec());
    fields.insert(FieldIdentifier::name("ssn"), b"123-45-6789".to_vec());

    // Encrypt batch
    let encrypted_fields = field_manager.encrypt_fields_batch(&fields).await.unwrap();
    assert_eq!(encrypted_fields.len(), 3);

    // Verify all fields are encrypted
    for (field, encrypted) in &encrypted_fields {
        let original = fields.get(field).unwrap();
        assert_ne!(encrypted.ciphertext, *original);
        assert_eq!(encrypted.metadata.field, *field);
    }

    // Prepare for decryption
    let mut decrypt_inputs = HashMap::new();
    for (field, encrypted) in &encrypted_fields {
        decrypt_inputs.insert(
            field.clone(),
            (encrypted.ciphertext.clone(), encrypted.metadata.clone()),
        );
    }

    // Decrypt batch
    let decrypted_fields = field_manager.decrypt_fields_batch(&decrypt_inputs).await.unwrap();
    assert_eq!(decrypted_fields.len(), 3);

    // Verify decryption results
    for (field, decrypted) in decrypted_fields {
        let original = fields.get(&field).unwrap();
        assert_eq!(decrypted.plaintext, *original);
        assert_eq!(decrypted.field, field);
    }
}

#[tokio::test]
async fn test_field_encryption_builder() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    
    // Test builder with default settings
    let manager1 = FieldEncryptionManagerBuilder::new()
        .with_key_manager(key_manager.clone())
        .build()
        .unwrap();

    let field = FieldIdentifier::name("test");
    let plaintext = b"test_data";
    let encrypted = manager1.encrypt_field(&field, plaintext).await.unwrap();
    let decrypted = manager1
        .decrypt_field(&encrypted.ciphertext, &encrypted.metadata)
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext, plaintext);

    // Test builder with custom algorithm
    let manager2 = FieldEncryptionManagerBuilder::new()
        .with_key_manager(key_manager.clone())
        .with_default_algorithm("aes256gcm")
        .build()
        .unwrap();

    let encrypted2 = manager2.encrypt_field(&field, plaintext).await.unwrap();
    let decrypted2 = manager2
        .decrypt_field(&encrypted2.ciphertext, &encrypted2.metadata)
        .await
        .unwrap();
    assert_eq!(decrypted2.plaintext, plaintext);
    assert_ne!(encrypted.ciphertext, encrypted2.ciphertext); // Different algorithms

    // Test builder without key manager should fail
    let result = FieldEncryptionManagerBuilder::new().build();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_algorithm_selector() {
    let selector = DefaultAlgorithmSelector;

    // Test strategy-based selection
    let field = FieldIdentifier::name("test");
    
    let algorithm = selector
        .select_algorithm(
            &field,
            &FieldEncryptionStrategy::Default,
            PerformanceProfile::Lightning,
            &[],
        )
        .unwrap();
    assert_eq!(algorithm, "aegis256");

    let algorithm = selector
        .select_algorithm(
            &field,
            &FieldEncryptionStrategy::Default,
            PerformanceProfile::Balanced,
            &[],
        )
        .unwrap();
    assert_eq!(algorithm, "chacha20poly1305");

    let algorithm = selector
        .select_algorithm(
            &field,
            &FieldEncryptionStrategy::Default,
            PerformanceProfile::Fortress,
            &[],
        )
        .unwrap();
    assert_eq!(algorithm, "aes256gcm");

    // Test specific algorithm
    let algorithm = selector
        .select_algorithm(
            &field,
            &FieldEncryptionStrategy::Algorithm("custom_algo".to_string()),
            PerformanceProfile::Balanced,
            &[],
        )
        .unwrap();
    assert_eq!(algorithm, "custom_algo");

    // Test data type recommendations
    let algorithm = selector
        .recommend_algorithm_for_type("email", FieldSensitivity::Restricted)
        .unwrap();
    assert_eq!(algorithm, "aes256gcm");

    let algorithm = selector
        .recommend_algorithm_for_type("blob", FieldSensitivity::Internal)
        .unwrap();
    assert_eq!(algorithm, "aegis256");

    let algorithm = selector
        .recommend_algorithm_for_type("text", FieldSensitivity::Public)
        .unwrap_err(); // Should error for public data
}

#[tokio::test]
async fn test_field_identifier_serialization() {
    // Test that field identifiers can be serialized/deserialized
    let field1 = FieldIdentifier::name("email");
    let field2 = FieldIdentifier::path(vec!["user", "profile", "email"]);
    let field3 = FieldIdentifier::indexed(vec!["users", "0", "email"], 1);

    // Test string representation
    assert_eq!(field1.as_string(), "email");
    assert_eq!(field2.as_string(), "user.profile.email");
    assert_eq!(field3.as_string(), "users.0.email.1");

    // Test that they can be used as HashMap keys
    let mut map = HashMap::new();
    map.insert(field1.clone(), "value1");
    map.insert(field2.clone(), "value2");
    map.insert(field3.clone(), "value3");

    assert_eq!(map.get(&field1), Some(&"value1"));
    assert_eq!(map.get(&field2), Some(&"value2"));
    assert_eq!(map.get(&field3), Some(&"value3"));
}

#[tokio::test]
async fn test_encryption_metadata() {
    let config_id = "test_config".to_string();
    let field = FieldIdentifier::name("test");
    let algorithm = "aes256gcm".to_string();
    let key_id = "test_key".to_string();
    let key_version = 1;

    let metadata = FieldEncryptionMetadata::new(
        config_id.clone(),
        field.clone(),
        algorithm.clone(),
        key_id.clone(),
        key_version,
    )
    .with_nonce(vec![1, 2, 3, 4])
    .with_tag(vec![5, 6, 7, 8])
    .with_metadata("custom".to_string(), "value".to_string());

    assert_eq!(metadata.config_id, config_id);
    assert_eq!(metadata.field, field);
    assert_eq!(metadata.algorithm, algorithm);
    assert_eq!(metadata.key_id, key_id);
    assert_eq!(metadata.key_version, key_version);
    assert_eq!(metadata.nonce, Some(vec![1, 2, 3, 4]));
    assert_eq!(metadata.tag, Some(vec![5, 6, 7, 8]));
    assert_eq!(metadata.metadata.get("custom"), Some(&"value".to_string()));
}

#[tokio::test]
async fn test_compliance_tag_handling() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    // Create fields with different compliance requirements
    let phi_field = FieldIdentifier::name("medical_record");
    let pci_field = FieldIdentifier::name("credit_card");
    let standard_field = FieldIdentifier::name("username");

    // Configure PHI field (HIPAA compliance)
    let phi_config = FieldEncryptionConfig::new(
        phi_field.clone(),
        FieldEncryptionStrategy::Algorithm("aes256gcm".to_string()),
    )
    .with_performance_profile(PerformanceProfile::Fortress)
    .with_compliance_tag("HIPAA")
    .with_compliance_tag("PHI");

    field_manager.set_field_config(phi_config).await.unwrap();

    // Configure PCI field (PCI-DSS compliance)
    let pci_config = FieldEncryptionConfig::new(
        pci_field.clone(),
        FieldEncryptionStrategy::Algorithm("aes256gcm".to_string()),
    )
    .with_performance_profile(PerformanceProfile::Fortress)
    .with_compliance_tag("PCI-DSS")
    .with_compliance_tag("PAN");

    field_manager.set_field_config(pci_config).await.unwrap();

    // Configure standard field
    let standard_config = FieldEncryptionConfig::new(
        standard_field.clone(),
        FieldEncryptionStrategy::Default,
    );

    field_manager.set_field_config(standard_config).await.unwrap();

    // Test encryption with different compliance requirements
    let phi_data = b"patient_medical_history";
    let pci_data = b"4111111111111111";
    let standard_data = b"john_doe";

    let phi_encrypted = field_manager.encrypt_field(&phi_field, phi_data).await.unwrap();
    let pci_encrypted = field_manager.encrypt_field(&pci_field, pci_data).await.unwrap();
    let standard_encrypted = field_manager.encrypt_field(&standard_field, standard_data).await.unwrap();

    // All should be encrypted
    assert_ne!(phi_encrypted.ciphertext, phi_data);
    assert_ne!(pci_encrypted.ciphertext, pci_data);
    assert_ne!(standard_encrypted.ciphertext, standard_data);

    // Verify decryption
    let phi_decrypted = field_manager
        .decrypt_field(&phi_encrypted.ciphertext, &phi_encrypted.metadata)
        .await
        .unwrap();
    let pci_decrypted = field_manager
        .decrypt_field(&pci_encrypted.ciphertext, &pci_encrypted.metadata)
        .await
        .unwrap();
    let standard_decrypted = field_manager
        .decrypt_field(&standard_encrypted.ciphertext, &standard_encrypted.metadata)
        .await
        .unwrap();

    assert_eq!(phi_decrypted.plaintext, phi_data);
    assert_eq!(pci_decrypted.plaintext, pci_data);
    assert_eq!(standard_decrypted.plaintext, standard_data);
}

#[tokio::test]
async fn test_error_handling() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    // Test decryption with invalid metadata
    let invalid_metadata = FieldEncryptionMetadata::new(
        "invalid".to_string(),
        FieldIdentifier::name("invalid"),
        "invalid_algorithm".to_string(),
        "invalid_key".to_string(),
        1,
    );

    let result = field_manager
        .decrypt_field(b"invalid_ciphertext", &invalid_metadata)
        .await;
    assert!(result.is_err());

    // Test decryption with corrupted ciphertext
    let field = FieldIdentifier::name("test");
    let plaintext = b"test_data";
    
    let encrypted = field_manager.encrypt_field(&field, plaintext).await.unwrap();
    let mut corrupted = encrypted.ciphertext;
    corrupted[0] ^= 0xFF; // Corrupt first byte

    let result = field_manager
        .decrypt_field(&corrupted, &encrypted.metadata)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_performance_profiles() {
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    let plaintext = b"performance_test_data";

    // Test Lightning profile
    let lightning_field = FieldIdentifier::name("lightning_field");
    let lightning_config = FieldEncryptionConfig::new(
        lightning_field.clone(),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Lightning);

    field_manager.set_field_config(lightning_config).await.unwrap();

    // Test Balanced profile
    let balanced_field = FieldIdentifier::name("balanced_field");
    let balanced_config = FieldEncryptionConfig::new(
        balanced_field.clone(),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Balanced);

    field_manager.set_field_config(balanced_config).await.unwrap();

    // Test Fortress profile
    let fortress_field = FieldIdentifier::name("fortress_field");
    let fortress_config = FieldEncryptionConfig::new(
        fortress_field.clone(),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Fortress);

    field_manager.set_field_config(fortress_config).await.unwrap();

    // Encrypt with different profiles
    let lightning_encrypted = field_manager.encrypt_field(&lightning_field, plaintext).await.unwrap();
    let balanced_encrypted = field_manager.encrypt_field(&balanced_field, plaintext).await.unwrap();
    let fortress_encrypted = field_manager.encrypt_field(&fortress_field, plaintext).await.unwrap();

    // All should produce different ciphertexts (different algorithms)
    assert_ne!(lightning_encrypted.ciphertext, balanced_encrypted.ciphertext);
    assert_ne!(balanced_encrypted.ciphertext, fortress_encrypted.ciphertext);
    assert_ne!(lightning_encrypted.ciphertext, fortress_encrypted.ciphertext);

    // All should decrypt correctly
    let lightning_decrypted = field_manager
        .decrypt_field(&lightning_encrypted.ciphertext, &lightning_encrypted.metadata)
        .await
        .unwrap();
    let balanced_decrypted = field_manager
        .decrypt_field(&balanced_encrypted.ciphertext, &balanced_encrypted.metadata)
        .await
        .unwrap();
    let fortress_decrypted = field_manager
        .decrypt_field(&fortress_encrypted.ciphertext, &fortress_encrypted.metadata)
        .await
        .unwrap();

    assert_eq!(lightning_decrypted.plaintext, plaintext);
    assert_eq!(balanced_decrypted.plaintext, plaintext);
    assert_eq!(fortress_decrypted.plaintext, plaintext);
}
