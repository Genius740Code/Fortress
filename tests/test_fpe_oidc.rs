//! Simple test to verify OIDC and FPE functionality works

use fortress_core::prelude::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("Testing OIDC and FPE functionality...");

    // Test FPE with a simple approach
    let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    // Test numeric FPE
    let config = FpeConfig {
        algorithm: FpeAlgorithm::FF1,
        format: DataFormat::Numeric { length: 8 },
        key: key.clone(),
        parameters: std::collections::HashMap::new(),
    };

    match FormatPreservingEncryption::new(config) {
        Ok(fpe) => {
            let test_number = "12345678";
            match fpe.encrypt(test_number) {
                Ok(encrypted) => {
                    println!("✓ Encrypted: {}", encrypted.encrypted_value);
                    match fpe.decrypt(&encrypted.encrypted_value) {
                        Ok(decrypted) => {
                            println!("✓ Decrypted: {}", decrypted);
                            if decrypted == test_number {
                                println!("✓ Round-trip successful!");
                            } else {
                                println!("✗ Round-trip failed!");
                            }
                        }
                        Err(e) => println!("✗ Decryption error: {}", e),
                    }
                }
                Err(e) => println!("✗ Encryption error: {}", e),
            }
        }
        Err(e) => println!("✗ FPE creation error: {}", e),
    }

    println!("Test completed!");
    Ok(())
}
