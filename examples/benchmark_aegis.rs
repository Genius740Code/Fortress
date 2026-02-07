//! Example usage of Fortress AEGIS-256 benchmarking
//! 
//! This example demonstrates how to use the benchmarking suite to test
//! the performance of the AEGIS-256 encryption algorithm.

use fortress_core::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Fortress AEGIS-256 Performance Benchmark");
    println!("==========================================");
    
    // Create benchmark instance
    let benchmark = AegisBenchmark::new();
    
    // Run comprehensive benchmark suite
    let results = benchmark.run_suite();
    
    // Run concurrent benchmark to test thread safety
    benchmark.run_concurrent_benchmark(4, 1_048_576, 5);
    
    // Demonstrate basic encryption usage
    println!("\n🔐 Basic Usage Example");
    println!("======================");
    
    let algorithm = Aegis256::new();
    let key = vec![42u8; 32]; // Test key
    let plaintext = b"Fortress: Turnkey's simplicity meets Vault's security with custom encryption!";
    
    println!("📝 Algorithm: {}", algorithm.name());
    println!("🔑 Key size: {} bytes", algorithm.key_size());
    println!("🎲 Nonce size: {} bytes", algorithm.nonce_size());
    println!("🏷️  Tag size: {} bytes", algorithm.tag_size());
    println!("🛡️  Security level: {} bits", algorithm.security_level());
    println!("⚡ Performance profile: {:?}", algorithm.performance_profile());
    
    // Encrypt
    let start = std::time::Instant::now();
    let ciphertext = algorithm.encrypt(plaintext, &key)?;
    let encrypt_time = start.elapsed();
    
    println!("✅ Encryption successful");
    println!("📊 Plaintext size: {} bytes", plaintext.len());
    println!("📊 Ciphertext size: {} bytes", ciphertext.len());
    println!("⏱️  Encryption time: {:?}", encrypt_time);
    
    // Decrypt
    let start = std::time::Instant::now();
    let decrypted = algorithm.decrypt(&ciphertext, &key)?;
    let decrypt_time = start.elapsed();
    
    println!("✅ Decryption successful");
    println!("⏱️  Decryption time: {:?}", decrypt_time);
    
    // Verify
    assert_eq!(plaintext, &decrypted[..], "Decrypted data should match original");
    println!("✅ Verification passed - data integrity confirmed");
    
    // Performance summary
    let encrypt_throughput = (plaintext.len() as f64) / (1024.0 * 1024.0) / encrypt_time.as_secs_f64();
    let decrypt_throughput = (decrypted.len() as f64) / (1024.0 * 1024.0) / decrypt_time.as_secs_f64();
    
    println!("📈 Performance Summary:");
    println!("  ⚡ Encryption throughput: {:.2} MB/s", encrypt_throughput);
    println!("  🔓 Decryption throughput: {:.2} MB/s", decrypt_throughput);
    println!("  🚀 Combined throughput: {:.2} MB/s", encrypt_throughput + decrypt_throughput);
    
    println!("\n🎉 Benchmark completed successfully!");
    println!("📚 Fortress is ready for production use with ultra-fast AEGIS-256 encryption!");
    
    Ok(())
}
