//! Quick test to verify homomorphic encryption is working

use std::time::Instant;
use fortress_core::homomorphic_encryption::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Quick Homomorphic Encryption Test");
    
    let start = Instant::now();
    
    // Test with 256-bit key for speed
    let paillier = PaillierHomomorphic::new(256);
    println!("✅ Created Paillier instance");
    
    // Generate key
    let (private_key, _key_id) = paillier.generate_key().await?;
    let keygen_time = start.elapsed();
    println!("✅ Key generation: {:?}", keygen_time);
    
    // Test encryption
    let plaintext = b"hello";
    let ciphertext = paillier.encrypt(plaintext, &private_key).await?;
    let encrypt_time = start.elapsed();
    println!("✅ Encryption: {:?}", encrypt_time);
    
    // Test decryption
    let decrypted = paillier.decrypt(&ciphertext, &private_key).await?;
    let decrypt_time = start.elapsed();
    println!("✅ Decryption: {:?}", decrypt_time);
    
    // Verify correctness
    assert_eq!(decrypted, plaintext);
    println!("✅ Correctness: PASSED");
    
    // Test probabilistic encryption
    let ciphertext2 = paillier.encrypt(plaintext, &private_key).await?;
    assert_ne!(ciphertext.data, ciphertext2.data);
    println!("✅ Probabilistic encryption: PASSED");
    
    let total_time = start.elapsed();
    println!("🎉 ALL TESTS PASSED in {:?}", total_time);
    
    Ok(())
}
