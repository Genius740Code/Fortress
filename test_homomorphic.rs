use fortress_core::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Testing Production Homomorphic Encryption");
    
    // Test HomomorphicManager with production schemes
    let manager = HomomorphicManager::new();
    
    // List available schemes
    println!("Available schemes:");
    for scheme_id in manager.list_schemes() {
        println!("  - {}", scheme_id);
    }
    
    // Test CKKS scheme
    println!("\nTesting CKKS Scheme");
    let ckks_scheme = manager.get_scheme("ckks_2048").unwrap();
    
    // Generate keys
    let (key, key_id) = ckks_scheme.generate_key().await?;
    println!("Generated key: {}", key_id);
    
    // Test encryption/decryption
    let plaintext = 42.5f64.to_le_bytes().to_vec();
    let ciphertext = ckks_scheme.encrypt(&plaintext, &key).await?;
    println!("Encrypted successfully");
    
    let decrypted = ckks_scheme.decrypt(&ciphertext, &key).await?;
    let decrypted_value = f64::from_le_bytes([
        decrypted[0], decrypted[1], decrypted[2], decrypted[3],
        decrypted[4], decrypted[5], decrypted[6], decrypted[7],
    ]);
    
    println!("Original: {}, Decrypted: {}", 42.5, decrypted_value);
    
    // Test homomorphic operations
    let plaintext2 = 17.3f64.to_le_bytes().to_vec();
    let ciphertext2 = ckks_scheme.encrypt(&plaintext2, &key).await?;
    
    let sum_ciphertext = ckks_scheme.operate(
        HomomorphicOperation::Add,
        &[&ciphertext, &ciphertext2],
        &key,
    ).await?;
    
    let sum_decrypted = ckks_scheme.decrypt(&sum_ciphertext, &key).await?;
    let sum_value = f64::from_le_bytes([
        sum_decrypted[0], sum_decrypted[1], sum_decrypted[2], sum_decrypted[3],
        sum_decrypted[4], sum_decrypted[5], sum_decrypted[6], sum_decrypted[7],
    ]);
    
    println!("42.5 + 17.3 = {} (homomorphic addition)", sum_value);
    
    // Test performance characteristics
    let perf = ckks_scheme.performance_characteristics();
    println!("Performance characteristics:");
    println!("  Encryption time: {} ms", perf.encryption_time_ms);
    println!("  Decryption time: {} ms", perf.decryption_time_ms);
    println!("  Addition time: {} ms", perf.addition_time_ms);
    
    println!("\n✓ Production Homomorphic Encryption Test Complete!");
    Ok(())
}
