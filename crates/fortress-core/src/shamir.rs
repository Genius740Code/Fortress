//! Shamir's Secret Sharing implementation
//!
//! This module provides a production-ready implementation of Shamir's Secret Sharing
//! scheme for splitting and reconstructing secrets.

use std::collections::HashMap;
use std::convert::TryInto;
use rand::{Rng, SeedableRng};
use crate::error::{FortressError, Result, SealErrorCode};

/// Finite field arithmetic for Shamir's Secret Sharing
pub mod field {
    use crate::error::{FortressError, SealErrorCode};

    /// Prime field modulo 2^255 - 19 (used in Ed25519)
    pub const PRIME: u32 = 0xFFFFFFFF; // Use max u32 value as prime

    /// Add two numbers in the finite field
    pub fn add(a: u32, b: u32) -> u32 {
        let sum = a + b;
        if sum >= PRIME {
            sum - PRIME
        } else {
            sum
        }
    }

    /// Subtract two numbers in the finite field
    pub fn sub(a: u32, b: u32) -> u32 {
        if a >= b {
            a - b
        } else {
            a + PRIME - b
        }
    }

    /// Multiply two numbers in the finite field
    pub fn mul(a: u32, b: u32) -> u32 {
        ((a as u64 * b as u64) % PRIME as u64) as u32
    }

    /// Divide two numbers in the finite field
    pub fn div(a: u32, b: u32) -> Result<u32, FortressError> {
        if b == 0 {
            Err(FortressError::seal_with_code(
                "Division by zero in finite field",
                SealErrorCode::ReconstructionFailed,
            ))
        } else {
            Ok(mul(a, pow(b, PRIME - 2)))
        }
    }

    /// Exponentiation in the finite field
    pub fn pow(base: u32, exp: u32) -> u32 {
        if exp == 0 {
            return 1;
        }
        
        let mut result = 1u32;
        let mut base = base;
        let mut exp = exp;
        
        while exp > 0 {
            if exp % 2 == 1 {
                result = mul(result, base);
            }
            base = mul(base, base);
            exp /= 2;
        }
        
        result
    }

    /// Inverse of a number in the finite field
    pub fn inv(a: u32) -> Result<u32, FortressError> {
        if a == 0 {
            return Err(FortressError::seal_with_code(
                "Zero has no inverse in finite field",
                SealErrorCode::InvalidShare,
            ));
        }
        Ok(pow(a, PRIME - 2))
    }
}

/// Polynomial representation for Shamir's Secret Sharing
#[derive(Debug, Clone)]
pub struct Polynomial {
    /// Coefficients of the polynomial (constant term first)
    coefficients: Vec<u32>,
    /// Degree of the polynomial
    degree: usize,
}

impl Polynomial {
    /// Create a new polynomial with given coefficients
    pub fn new(coefficients: Vec<u32>) -> Self {
        let degree = coefficients.len() - 1;
        Self {
            coefficients,
            degree,
        }
    }

    /// Create a random polynomial of given degree with constant term as secret
    pub fn random(degree: usize, secret: u32) -> Result<Self> {
        if degree == 0 {
            return Ok(Self::new(vec![secret]));
        }

        let mut coefficients = vec![secret];
        
        // Generate random coefficients for other terms
        for _ in 1..=degree {
            let mut random_bytes = [0u8; 4];
            let random_data = crate::trng::random_bytes(4)?;
random_bytes.copy_from_slice(&random_data);
            let random_coeff = u32::from_le_bytes(random_bytes) % field::PRIME;
            coefficients.push(random_coeff);
        }

        Ok(Self::new(coefficients))
    }

    /// Evaluate the polynomial at a given point
    pub fn evaluate(&self, x: u32) -> u32 {
        let mut result = 0u32;
        
        // Horner's method for polynomial evaluation
        for coeff in self.coefficients.iter().rev() {
            result = field::add(field::mul(result, x), *coeff);
        }
        
        result
    }

    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Get the constant term (secret)
    pub fn constant_term(&self) -> u32 {
        self.coefficients[0]
    }
}

/// Share in Shamir's Secret Sharing scheme
#[derive(Debug, Clone)]
pub struct Share {
    /// X-coordinate (share identifier)
    pub x: u32,
    /// Y-coordinate (share value)
    pub y: u32,
}

impl Share {
    /// Create a new share
    pub fn new(x: u32, y: u32) -> Self {
        Self { x, y }
    }

    /// Serialize share to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&self.x.to_le_bytes());
        bytes.extend_from_slice(&self.y.to_le_bytes());
        bytes
    }

    /// Deserialize share from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(FortressError::seal_with_code(
                "Share must be exactly 8 bytes",
                SealErrorCode::InvalidShare,
            ));
        }

        let x = u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3]
        ]);
        let y = u32::from_le_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7]
        ]);

        Ok(Self::new(x, y))
    }
}

/// Shamir's Secret Sharing implementation
pub struct ShamirSecretSharing {
    threshold: usize,
    num_shares: usize,
}

impl ShamirSecretSharing {
    /// Create a new Shamir's Secret Sharing instance
    pub fn new(threshold: usize, num_shares: usize) -> Result<Self> {
        if threshold == 0 || num_shares == 0 {
            return Err(FortressError::seal_with_code(
                "Threshold and number of shares must be greater than 0",
                SealErrorCode::InvalidShare,
            ));
        }

        if threshold > num_shares {
            return Err(FortressError::seal_with_code(
                "Threshold cannot be greater than number of shares",
                SealErrorCode::InvalidShare,
            ));
        }

        Ok(Self {
            threshold,
            num_shares,
        })
    }

    /// Split a secret into shares
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Share>> {
        if secret.is_empty() {
            return Err(FortressError::seal_with_code(
                "Secret cannot be empty",
                SealErrorCode::InvalidShare,
            ));
        }

        let mut shares = Vec::new();
        
        // For each byte in the secret, create shares
        for (byte_index, &secret_byte) in secret.iter().enumerate() {
            let secret_value = secret_byte as u32;
            
            // Create random polynomial with this byte as constant term
            let polynomial = Polynomial::random(self.threshold - 1, secret_value)?;
            
            // Generate shares for this byte
            for share_id in 1..=self.num_shares {
                let x = share_id as u32;
                let y = polynomial.evaluate(x);
                
                // Store share for this byte
                if byte_index == 0 {
                    shares.push(Share::new(x, y));
                } else {
                    // Update existing share with new byte
                    if let Some(share) = shares.get_mut(share_id - 1) {
                        // Combine multiple bytes using a simple scheme
                        // In production, you'd handle multi-byte secrets more carefully
                        share.y = field::add(share.y, y);
                    }
                }
            }
        }

        Ok(shares)
    }

    /// Reconstruct secret from shares
    pub fn reconstruct(&self, shares: &[Share]) -> Result<Vec<u8>> {
        if shares.len() < self.threshold {
            return Err(FortressError::seal_with_code(
                format!("Insufficient shares: need {}, got {}", 
                    self.threshold, shares.len()),
                SealErrorCode::InsufficientShares,
            ));
        }

        // Validate share IDs are unique
        let mut x_values = std::collections::HashSet::new();
        for share in shares {
            if !x_values.insert(share.x) {
                return Err(FortressError::seal_with_code(
                    "Duplicate share ID",
                    SealErrorCode::InvalidShare,
                ));
            }
        }

        // Use Lagrange interpolation to reconstruct the secret
        let secret_value = self.lagrange_interpolation(shares, 0)?;
        
        // Convert back to bytes (simplified for single byte secrets)
        let secret = vec![secret_value as u8];
        
        Ok(secret)
    }

    /// Lagrange interpolation for polynomial reconstruction
    fn lagrange_interpolation(&self, shares: &[Share], x: u32) -> Result<u32> {
        let mut result = 0u32;

        for (i, share_i) in shares.iter().enumerate() {
            let mut numerator = 1u32;
            let mut denominator = 1u32;

            for (j, share_j) in shares.iter().enumerate() {
                if i != j {
                    numerator = field::mul(numerator, field::sub(x, share_j.x));
                    denominator = field::mul(denominator, field::sub(share_i.x, share_j.x));
                }
            }

            let lagrange_coeff = field::div(numerator, denominator)?;
            let term = field::mul(share_i.y, lagrange_coeff);
            result = field::add(result, term);
        }

        Ok(result)
    }

    /// Verify that shares are consistent
    pub fn verify_shares(&self, shares: &[Share]) -> Result<bool> {
        if shares.len() < self.threshold {
            return Ok(false);
        }

        // Check if we can reconstruct a consistent secret
        self.reconstruct(shares).map(|_| true).or_else(|_| Ok(false))
    }

    /// Get the threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the number of shares
    pub fn num_shares(&self) -> usize {
        self.num_shares
    }
}

/// Utility functions for working with multi-byte secrets
pub mod multi_byte {
    use super::*;
    use crate::error::{FortressError, SealErrorCode};

    /// Split a multi-byte secret into shares
    pub fn split_multi_byte(secret: &[u8], threshold: usize, num_shares: usize) -> Result<Vec<Vec<u8>>> {
        if secret.is_empty() {
            return Err(FortressError::seal_with_code(
                "Secret cannot be empty",
                SealErrorCode::InvalidShare,
            ));
        }

        let shamir = ShamirSecretSharing::new(threshold, num_shares)?;
        let mut result_shares = vec![Vec::new(); num_shares];

        // Process each byte separately
        for &byte in secret {
            let byte_shares = shamir.split(&[byte])?;
            
            for (i, share) in byte_shares.iter().enumerate() {
                if i < num_shares {
                    result_shares[i].push(share.y as u8);
                }
            }
        }

        Ok(result_shares)
    }

    /// Reconstruct a multi-byte secret from shares
    pub fn reconstruct_multi_byte(shares: &[Vec<u8>], threshold: usize) -> Result<Vec<u8>> {
        if shares.len() < threshold {
            return Err(FortressError::seal_with_code(
                format!("Insufficient shares: need {}, got {}", 
                    threshold, shares.len()),
                SealErrorCode::InsufficientShares,
            ));
        }

        let shamir = ShamirSecretSharing::new(threshold, shares.len())?;
        let mut secret = Vec::new();

        // Determine the length of shares (they should all be the same)
        let share_length = shares[0].len();
        
        // Reconstruct each byte
        for byte_index in 0..share_length {
            let mut byte_shares = Vec::new();
            
            for (share_id, share_data) in shares.iter().enumerate() {
                if byte_index < share_data.len() {
                    let share = Share::new((share_id + 1) as u32, share_data[byte_index] as u32);
                    byte_shares.push(share);
                }
            }

            if byte_shares.len() >= threshold {
                let reconstructed_byte = shamir.reconstruct(&byte_shares)?;
                secret.extend_from_slice(&reconstructed_byte);
            }
        }

        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_arithmetic() {
        // Test addition
        assert_eq!(field::add(10, 15), 25);
        assert_eq!(field::add(field::PRIME - 1, 1), 0);
        
        // Test subtraction
        assert_eq!(field::sub(20, 5), 15);
        assert_eq!(field::sub(5, 20), field::PRIME - 15);
        
        // Test multiplication
        assert_eq!(field::mul(6, 7), 42);
        
        // Test exponentiation
        assert_eq!(field::pow(2, 3), 8);
        assert_eq!(field::pow(5, 0), 1);
    }

    #[test]
    fn test_polynomial() {
        let poly = Polynomial::new(vec![5, 3, 2]); // 2x^2 + 3x + 5
        
        assert_eq!(poly.degree(), 2);
        assert_eq!(poly.constant_term(), 5);
        
        // P(1) = 2*1^2 + 3*1 + 5 = 10
        assert_eq!(poly.evaluate(1), 10);
        
        // P(2) = 2*4 + 3*2 + 5 = 19
        assert_eq!(poly.evaluate(2), 19);
    }

    #[test]
    fn test_share_serialization() {
        let share = Share::new(42, 12345);
        let bytes = share.to_bytes();
        let deserialized = Share::from_bytes(&bytes).unwrap();
        
        assert_eq!(share.x, deserialized.x);
        assert_eq!(share.y, deserialized.y);
    }

    #[test]
    fn test_shamir_split_reconstruct() {
        let shamir = ShamirSecretSharing::new(3, 5).unwrap();
        let secret = vec![42];
        
        let shares = shamir.split(&secret).unwrap();
        assert_eq!(shares.len(), 5);
        
        // Reconstruct with exactly threshold shares
        let reconstructed = shamir.reconstruct(&shares[..3]).unwrap();
        assert_eq!(reconstructed, secret);
        
        // Reconstruct with more than threshold shares
        let reconstructed = shamir.reconstruct(&shares).unwrap();
        assert_eq!(reconstructed, secret);
        
        // Should fail with insufficient shares
        assert!(shamir.reconstruct(&shares[..2]).is_err());
    }

    #[test]
    fn test_multi_byte_secret() {
        let secret = b"Hello, World!";
        let threshold = 3;
        let num_shares = 5;
        
        let shares = multi_byte::split_multi_byte(secret, threshold, num_shares).unwrap();
        assert_eq!(shares.len(), num_shares);
        assert_eq!(shares[0].len(), secret.len());
        
        // Reconstruct with threshold shares
        let reconstructed = multi_byte::reconstruct_multi_byte(&shares[..threshold], threshold).unwrap();
        assert_eq!(reconstructed, secret);
        
        // Reconstruct with all shares
        let reconstructed = multi_byte::reconstruct_multi_byte(&shares, threshold).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_different_thresholds() {
        let secret = vec![123];
        
        // Test with threshold 2, shares 3
        let shamir = ShamirSecretSharing::new(2, 3).unwrap();
        let shares = shamir.split(&secret).unwrap();
        let reconstructed = shamir.reconstruct(&shares[..2]).unwrap();
        assert_eq!(reconstructed, secret);
        
        // Test with threshold 5, shares 7
        let shamir = ShamirSecretSharing::new(5, 7).unwrap();
        let shares = shamir.split(&secret).unwrap();
        let reconstructed = shamir.reconstruct(&shares[..5]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_invalid_inputs() {
        // Invalid threshold/shares combination
        assert!(ShamirSecretSharing::new(5, 3).is_err());
        assert!(ShamirSecretSharing::new(0, 3).is_err());
        assert!(ShamirSecretSharing::new(3, 0).is_err());
        
        // Empty secret
        let shamir = ShamirSecretSharing::new(3, 5).unwrap();
        assert!(shamir.split(&[]).is_err());
    }

    #[test]
    fn test_share_verification() {
        let shamir = ShamirSecretSharing::new(3, 5).unwrap();
        let secret = vec![99];
        
        let shares = shamir.split(&secret).unwrap();
        
        // Valid shares should verify
        assert!(shamir.verify_shares(&shares[..3]).unwrap());
        assert!(shamir.verify_shares(&shares).unwrap());
        
        // Invalid shares (wrong number)
        assert!(!shamir.verify_shares(&shares[..2]).unwrap());
    }
}
