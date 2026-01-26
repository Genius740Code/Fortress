use aegis::{Aegis256, Key, Nonce};
use getrandom::getrandom;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing AEGIS-256 implementation...");
    
    // Generate a random key
    let mut key_bytes = [0u8; 32];
    getrandom(&mut key_bytes)?;
    let key = Key::from_slice(&key_bytes);
    
    // Generate a random nonce
    let mut nonce_bytes = [0u8; 32];
    getrandom(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Create cipher
    let cipher = Aegis256::new(key);
    
    // Test data
    let plaintext = b"Hello, Fortress! Testing AEGIS-256 encryption.";
    
    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext);
    println!("✓ Encryption successful");
    println!("  Plaintext: {:?}", std::str::from_utf8(plaintext));
    println!("  Ciphertext length: {} bytes", ciphertext.len());
    
    // Decrypt
    let decrypted = cipher.decrypt(nonce, &ciphertext)?;
    println!("✓ Decryption successful");
    println!("  Decrypted: {:?}", std::str::from_utf8(&decrypted));
    
    // Verify
    assert_eq!(plaintext, &decrypted[..]);
    println!("✓ Verification passed - plaintext matches decrypted data");
    
    println!("\n🎉 AEGIS-256 implementation is working correctly!");
    Ok(())
}
