//! Field Encryption Demo
//!
//! This example demonstrates the per-field encryption capabilities of Fortress,
//! showing how different fields can be encrypted with different algorithms
//! based on their sensitivity and performance requirements.

use fortress_core::{
    field_encryption::*,
    field_encryption_manager::*,
    key::InMemoryKeyManager,
    encryption::PerformanceProfile,
};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Fortress Field Encryption Demo");
    println!("================================");

    // Initialize key manager and field encryption manager
    let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());
    let field_manager = DefaultFieldEncryptionManager::new(key_manager);

    // Example user data with different sensitivity levels
    let mut user_data = HashMap::new();
    user_data.insert(FieldIdentifier::name("username"), b"john_doe".to_vec());
    user_data.insert(FieldIdentifier::name("email"), b"john@example.com".to_vec());
    user_data.insert(FieldIdentifier::name("phone"), b"+1234567890".to_vec());
    user_data.insert(FieldIdentifier::name("ssn"), b"123-45-6789".to_vec());
    user_data.insert(FieldIdentifier::path(vec!["profile", "bio"]), b"Software engineer".to_vec());

    // Configure field encryption based on sensitivity
    println!("\n📋 Configuring field encryption...");

    // Username - no encryption (public)
    let username_config = FieldEncryptionConfig::new(
        FieldIdentifier::name("username"),
        FieldEncryptionStrategy::None,
    );
    field_manager.set_field_config(username_config).await?;

    // Email - standard encryption
    let email_config = FieldEncryptionConfig::new(
        FieldIdentifier::name("email"),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Balanced)
    .with_compliance_tag("GDPR");
    field_manager.set_field_config(email_config).await?;

    // Phone - high-performance encryption
    let phone_config = FieldEncryptionConfig::new(
        FieldIdentifier::name("phone"),
        FieldEncryptionStrategy::Algorithm("chacha20poly1305".to_string()),
    )
    .with_performance_profile(PerformanceProfile::Lightning);
    field_manager.set_field_config(phone_config).await?;

    // SSN - maximum security encryption
    let ssn_config = FieldEncryptionConfig::new(
        FieldIdentifier::name("ssn"),
        FieldEncryptionStrategy::Algorithm("aes256gcm".to_string()),
    )
    .with_performance_profile(PerformanceProfile::Fortress)
    .with_compliance_tag("HIPAA")
    .with_compliance_tag("PCI-DSS");
    field_manager.set_field_config(ssn_config).await?;

    // Profile bio - balanced encryption
    let bio_config = FieldEncryptionConfig::new(
        FieldIdentifier::path(vec!["profile", "bio"]),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Balanced);
    field_manager.set_field_config(bio_config).await?;

    println!("✅ Field encryption configured successfully!");

    // Encrypt all fields
    println!("\n🔒 Encrypting user data...");
    let encrypted_data = field_manager.encrypt_fields_batch(&user_data).await?;

    println!("📊 Encryption Results:");
    for (field, encrypted) in &encrypted_data {
        let original_size = user_data.get(field).unwrap().len();
        let encrypted_size = encrypted.ciphertext.len();
        let algorithm = &encrypted.metadata.algorithm;
        
        println!("  • {}: {} → {} bytes (algorithm: {})", 
            field.as_string(), 
            original_size, 
            encrypted_size,
            algorithm
        );
    }

    // Decrypt all fields
    println!("\n🔓 Decrypting user data...");
    let mut decrypt_inputs = HashMap::new();
    for (field, encrypted) in &encrypted_data {
        decrypt_inputs.insert(
            field.clone(),
            (encrypted.ciphertext.clone(), encrypted.metadata.clone()),
        );
    }

    let decrypted_data = field_manager.decrypt_fields_batch(&decrypt_inputs).await?;

    println!("✅ Decryption completed successfully!");

    // Verify data integrity
    println!("\n🔍 Verifying data integrity...");
    let mut all_match = true;
    for (field, decrypted) in &decrypted_data {
        let original = user_data.get(field).unwrap();
        let matches = decrypted.plaintext == *original;
        
        println!("  • {}: {}", 
            field.as_string(), 
            if matches { "✅ Match" } else { "❌ Mismatch" }
        );
        
        if !matches {
            all_match = false;
        }
    }

    if all_match {
        println!("\n🎉 All fields encrypted and decrypted successfully!");
    } else {
        println!("\n❌ Some fields failed verification!");
    }

    // Demonstrate different encryption strategies
    println!("\n📚 Encryption Strategy Examples:");
    
    // Test different performance profiles
    let test_data = b"sensitive_test_data";
    
    let lightning_field = FieldIdentifier::name("test_lightning");
    let lightning_config = FieldEncryptionConfig::new(
        lightning_field.clone(),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Lightning);
    field_manager.set_field_config(lightning_config).await?;

    let balanced_field = FieldIdentifier::name("test_balanced");
    let balanced_config = FieldEncryptionConfig::new(
        balanced_field.clone(),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Balanced);
    field_manager.set_field_config(balanced_config).await?;

    let fortress_field = FieldIdentifier::name("test_fortress");
    let fortress_config = FieldEncryptionConfig::new(
        fortress_field.clone(),
        FieldEncryptionStrategy::Default,
    )
    .with_performance_profile(PerformanceProfile::Fortress);
    field_manager.set_field_config(fortress_config).await?;

    // Encrypt with different profiles
    let lightning_enc = field_manager.encrypt_field(&lightning_field, test_data).await?;
    let balanced_enc = field_manager.encrypt_field(&balanced_field, test_data).await?;
    let fortress_enc = field_manager.encrypt_field(&fortress_field, test_data).await?;

    println!("  • Lightning: {} bytes (algorithm: {})", 
        lightning_enc.ciphertext.len(), 
        lightning_enc.metadata.algorithm
    );
    println!("  • Balanced: {} bytes (algorithm: {})", 
        balanced_enc.ciphertext.len(), 
        balanced_enc.metadata.algorithm
    );
    println!("  • Fortress: {} bytes (algorithm: {})", 
        fortress_enc.ciphertext.len(), 
        fortress_enc.metadata.algorithm
    );

    // Show field configuration management
    println!("\n⚙️  Field Configuration Management:");
    let configs = field_manager.list_field_configs().await?;
    println!("  Total field configurations: {}", configs.len());
    
    for config in &configs {
        let compliance = if config.compliance_tags.is_empty() {
            "None".to_string()
        } else {
            config.compliance_tags.join(", ")
        };
        
        println!("  • {}: {} (Compliance: {})", 
            config.field.as_string(),
            config.algorithm_name().unwrap_or("None"),
            compliance
        );
    }

    println!("\n🏁 Demo completed successfully!");
    Ok(())
}
