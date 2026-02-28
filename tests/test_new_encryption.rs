//! Test file for new encryption algorithms

use fortress_core::encryption::{create_algorithm, SecureKey};

#[tokio::test]
async fn test_new_algorithms() {
    // Test XChaCha20-Poly1305
    let alg = create_algorithm("xchacha20poly1305").unwrap();
    let key = SecureKey::generate(alg.key_size());
    let plaintext = b"Hello, XChaCha20!";
    let ciphertext = alg.encrypt(plaintext, key.as_bytes()).unwrap();
    let decrypted = alg.decrypt(&ciphertext, key.as_bytes()).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
    println!("✅ XChaCha20-Poly1305 test passed");

    // Test Blake3Encrypt
    let alg = create_algorithm("blake3encrypt").unwrap();
    let key = SecureKey::generate(alg.key_size());
    let plaintext = b"Hello, Blake3!";
    let ciphertext = alg.encrypt(plaintext, key.as_bytes()).unwrap();
    let decrypted = alg.decrypt(&ciphertext, key.as_bytes()).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
    println!("✅ Blake3Encrypt test passed");

    // Test HMAC-SHA512 Encrypt
    let alg = create_algorithm("hmacsha512encrypt").unwrap();
    let key = SecureKey::generate(alg.key_size());
    let plaintext = b"Hello, HMAC-SHA512!";
    let ciphertext = alg.encrypt(plaintext, key.as_bytes()).unwrap();
    let decrypted = alg.decrypt(&ciphertext, key.as_bytes()).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
    println!("✅ HMAC-SHA512 Encrypt test passed");
}

fn main() {
    println!("Testing new encryption algorithms...");
    
    // Test factory function
    let algorithms = vec![
        "xchacha20poly1305",
        "blake3encrypt", 
        "hmacsha512encrypt",
        "chacha20poly1305",
        "aes256gcm"
    ];
    
    for alg_name in algorithms {
        match create_algorithm(alg_name) {
            Ok(alg) => {
                println!("✅ Successfully created algorithm: {}", alg.name());
                println!("   Key size: {} bytes", alg.key_size());
                println!("   Nonce size: {} bytes", alg.nonce_size());
                println!("   Tag size: {} bytes", alg.tag_size());
                println!("   Security level: {} bits", alg.security_level());
                println!("   Performance profile: {:?}", alg.performance_profile());
                println!();
            }
            Err(e) => {
                println!("❌ Failed to create algorithm {}: {:?}", alg_name, e);
            }
        }
    }
}
