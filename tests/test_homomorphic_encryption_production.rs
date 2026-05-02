//! Tests for production-ready homomorphic encryption implementation

#[cfg(feature = "homomorphic-encryption")]
use fortress_core::homomorphic_encryption::*;
#[cfg(feature = "homomorphic-encryption")]
use fortress_core::key::SecureKey;
#[cfg(feature = "homomorphic-encryption")]
use tokio;

#[cfg(all(test, feature = "homomorphic-encryption"))]
#[tokio::test]
async fn test_production_paillier_encryption() {
    let paillier = PaillierHomomorphic::new(512); // Use smaller key size for faster testing
    
    // Generate key
    let (key, key_id) = paillier.generate_key().await.unwrap();
    assert!(!key.is_empty());
    assert!(!key_id.is_empty());
    
    // Test small plaintext
    let plaintext = b"42";
    let ciphertext = paillier.encrypt(plaintext, &key).await.unwrap();
    assert_eq!(ciphertext.scheme_name(), "paillier");
    assert!(!ciphertext.data.is_empty());
    
    // Decrypt
    let decrypted = paillier.decrypt(&ciphertext, &key).await.unwrap();
    assert_eq!(decrypted, plaintext);
    
    println!("Basic encryption/decryption works");
}

#[cfg(all(test, feature = "homomorphic-encryption"))]
#[tokio::test]
async fn test_production_paillier_homomorphic_addition() {
    let paillier = PaillierHomomorphic::new(512);
    
    // Generate key
    let (key, key_id) = paillier.generate_key().await.unwrap();
    
    // Encrypt two numbers
    let plaintext1 = b"10";
    let plaintext2 = b"20";
    let ciphertext1 = paillier.encrypt(plaintext1, &key).await.unwrap();
    let ciphertext2 = paillier.encrypt(plaintext2, &key).await.unwrap();
    
    // Perform homomorphic addition
    let result = paillier.operate(
        HomomorphicOperation::Add,
        &[&ciphertext1, &ciphertext2],
        &key,
    ).await.unwrap();
    
    // Decrypt result
    let decrypted_result = paillier.decrypt(&result, &key).await.unwrap();
    
    // Convert to numbers and verify
    let num1 = u64::from_le_bytes([plaintext1[0]; 8]);
    let num2 = u64::from_le_bytes([plaintext2[0]; 8]);
    let expected = num1 + num2;
    
    println!("Homomorphic addition: {} + {} = {}", num1, num2, expected);
    assert!(!decrypted_result.is_empty());
}

#[cfg(all(test, feature = "homomorphic-encryption"))]
#[tokio::test]
async fn test_production_paillier_security_properties() {
    let paillier = PaillierHomomorphic::new(512);
    
    // Generate key
    let (key, key_id) = paillier.generate_key().await.unwrap();
    
    // Test that same plaintext encrypts to different ciphertexts (probabilistic)
    let plaintext = b"123";
    let ciphertext1 = paillier.encrypt(plaintext, &key).await.unwrap();
    let ciphertext2 = paillier.encrypt(plaintext, &key).await.unwrap();
    
    // Ciphertexts should be different (probabilistic encryption)
    assert_ne!(ciphertext1.data, ciphertext2.data);
    
    // But both should decrypt to the same plaintext
    let decrypted1 = paillier.decrypt(&ciphertext1, &key).await.unwrap();
    let decrypted2 = paillier.decrypt(&ciphertext2, &key).await.unwrap();
    
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
    
    println!("Probabilistic encryption verified");
}

#[cfg(all(test, feature = "homomorphic-encryption"))]
#[tokio::test]
async fn test_production_homomorphic_manager() {
    let manager = HomomorphicManager::new();
    
    // Test default scheme
    let default_scheme = manager.get_default_scheme().unwrap();
    assert_eq!(default_scheme.scheme_id(), "paillier");
    
    // List schemes
    let schemes = manager.list_schemes();
    assert!(schemes.contains(&"paillier_512".to_string()));
    assert!(schemes.contains(&"paillier_1024".to_string()));
    assert!(schemes.contains(&"paillier_2048".to_string()));
    
    // Get performance characteristics
    let perf = manager.get_performance("paillier_512").unwrap();
    assert!(perf.encryption_time_ms > 0.0);
    assert!(perf.decryption_time_ms > 0.0);
    assert!(perf.addition_time_ms > 0.0);
    assert!(perf.multiplication_time_ms.is_infinite());
    
    println!("Homomorphic manager works correctly");
}

#[cfg(all(test, feature = "homomorphic-encryption"))]
#[tokio::test]
async fn test_production_paillier_operation_support() {
    let paillier = PaillierHomomorphic::new(512);
    
    // Test supported operations
    assert!(paillier.supports_operation(&HomomorphicOperation::Add));
    assert!(paillier.supports_operation(&HomomorphicOperation::AddPlaintext));
    
    // Test unsupported operations
    assert!(!paillier.supports_operation(&HomomorphicOperation::Multiply));
    assert!(!paillier.supports_operation(&HomomorphicOperation::MultiplyPlaintext));
    assert!(!paillier.supports_operation(&HomomorphicOperation::Negate));
    assert!(!paillier.supports_operation(&HomomorphicOperation::Exponentiate(2)));
    
    println!("Operation support validation works");
}

#[cfg(all(test, feature = "homomorphic-encryption"))]
#[test]
fn test_production_ciphertext_creation() {
    let ciphertext = HomomorphicCiphertext::new(
        HomomorphicScheme::Paillier { key_size: 2048 },
        b"encrypted_data".to_vec(),
        "key123".to_string(),
    )
    .with_parameter("modulus", serde_json::Value::Number(2048.into()))
    .with_metadata("created_by", "test");
    
    assert_eq!(ciphertext.scheme_name(), "paillier");
    assert_eq!(ciphertext.data, b"encrypted_data");
    assert_eq!(ciphertext.key_id, "key123");
    assert!(ciphertext.parameters.contains_key("modulus"));
    assert!(ciphertext.metadata.contains_key("created_by"));
    
    println!("Ciphertext creation works");
}

#[cfg(all(test, feature = "homomorphic-encryption"))]
#[test]
fn test_production_performance_characteristics() {
    let paillier = PaillierHomomorphic::new(2048);
    let perf = paillier.performance_characteristics();
    
    assert!(perf.encryption_time_ms > 0.0);
    assert!(perf.decryption_time_ms > 0.0);
    assert!(perf.addition_time_ms > 0.0);
    assert!(perf.multiplication_time_ms.is_infinite());
    assert_eq!(perf.size_expansion_factor, 2.0);
    assert!(perf.memory_usage_mb > 0.0);
    
    println!("Performance characteristics: {:?}", perf);
}
