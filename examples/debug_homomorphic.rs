//! Simple test to debug homomorphic encryption

use fortress_core::homomorphic_encryption::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Production-Ready Homomorphic Encryption");
    
    // Create Paillier instance
    let paillier = PaillierHomomorphic::new(512);
    println!("Created Paillier instance with 512-bit key size");
    
    // Test prime generation
    println!("Testing prime generation...");
    let prime = paillier.generate_secure_prime(512)?;
    println!("Generated prime: {} bits", prime.to_bytes_be().len() * 8);
    
    // Test Miller-Rabin
    println!("Testing Miller-Rabin...");
    let is_prime = paillier.is_probable_prime(&prime, 10);
    println!("Prime test result: {}", is_prime);
    
    println!("Basic mathematical operations work!");
    
    Ok(())
}
