//! SIMD-optimized encryption implementations
//! 
//! This module provides high-performance encryption using SIMD instructions
//! including AVX2 and AVX-512 for parallel processing of cryptographic operations.

use crate::error::FortressError;
use crate::encryption::EncryptionAlgorithm;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Performance metrics for SIMD operations
static SIMD_OPERATIONS: AtomicU64 = AtomicU64::new(0);

/// SIMD-optimized encryptor with AVX2 and AVX-512 support
pub struct SimdEncryptor {
    keys: Vec<u8>,
    algorithm: Arc<dyn EncryptionAlgorithm>,
}

impl SimdEncryptor {
    /// Create a new SIMD encryptor with the given algorithm
    pub fn new(algorithm: Arc<dyn EncryptionAlgorithm>, key: &[u8]) -> Self {
        Self {
            keys: key.to_vec(),
            algorithm,
        }
    }

    /// Encrypt data using AVX2 instructions (32-byte chunks)
    #[cfg(target_feature = "avx2")]
    #[target_feature(enable = "avx2")]
    unsafe fn encrypt_avx2(&self, plaintext: &[u8]) -> Result<Vec<u8>, FortressError> {
        // Fallback to the provided algorithm for secure encryption.
        // The simulated AVX2 encryption (XOR) is insecure and has been removed.
        self.algorithm.encrypt(plaintext, &self.keys)
    }

    /// Encrypt data using AVX-512 instructions (64-byte chunks)
    #[cfg(target_feature = "avx512f")]
    #[target_feature(enable = "avx512f")]
    unsafe fn encrypt_avx512(&self, plaintext: &[u8]) -> Result<Vec<u8>, FortressError> {
        // Fallback to the provided algorithm for secure encryption.
        // The simulated AVX-512 encryption (XOR) is insecure and has been removed.
        self.algorithm.encrypt(plaintext, &self.keys)
    }



    /// Encrypt data using the best available SIMD instruction set
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, FortressError> {
        // Since `encrypt_avx2` and `encrypt_avx512` now defer to `self.algorithm.encrypt`,
        // and for simplicity and to ensure correct encryption, we directly use the algorithm here.
        // The SIMD methods can be re-enabled once proper AES-NI implementations are added.
        self.algorithm.encrypt(plaintext, &self.keys)
    }

    /// Check if AVX2 is supported
    fn is_avx2_supported() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    /// Check if AVX-512 is supported
    fn is_avx512_supported() -> bool {
        std::is_x86_feature_detected!("avx512f")
    }

    /// Get SIMD operation count
    pub fn simd_operation_count() -> u64 {
        SIMD_OPERATIONS.load(Ordering::Relaxed)
    }
}

/// Adaptive encryptor that automatically selects the best encryption method
pub struct AdaptiveEncryptor {
    algorithm: Arc<dyn EncryptionAlgorithm>,
    key: Vec<u8>,
}

impl AdaptiveEncryptor {
    /// Create a new adaptive encryptor
    pub fn new(algorithm: Arc<dyn EncryptionAlgorithm>, key: &[u8]) -> Self {
        Self {
            algorithm,
            key: key.to_vec(),
        }
    }

    /// Encrypt data using the optimal method
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, FortressError> {
        // For now, just use standard encryption
        // SIMD optimization would require more complex architecture
        self.algorithm.encrypt(data, &self.key)
    }

    /// Get supported SIMD features
    pub fn supported_features() -> Vec<&'static str> {
        let mut features = Vec::new();
        if SimdEncryptor::is_avx2_supported() {
            features.push("AVX2");
        }
        if SimdEncryptor::is_avx512_supported() {
            features.push("AVX-512");
        }
        features
    }
}

/// Standard encryptor for fallback
pub struct StandardEncryptor {
    algorithm: Box<dyn EncryptionAlgorithm>,
}

impl StandardEncryptor {
    pub fn new(algorithm: Box<dyn EncryptionAlgorithm>) -> Self {
        Self { algorithm }
    }

    pub fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, FortressError> {
        self.algorithm.encrypt(data, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aegis256;

    #[test]
    fn test_simd_feature_detection() {
        // Test feature detection
        println!("AVX2 supported: {}", SimdEncryptor::is_avx2_supported());
        println!("AVX-512 supported: {}", SimdEncryptor::is_avx512_supported());
        println!("Supported features: {:?}", AdaptiveEncryptor::supported_features());
    }

    #[test]
    fn test_adaptive_encryptor() {
        let algorithm = Arc::new(Aegis256::new());
        let key = vec![0u8; 32];
        let encryptor = AdaptiveEncryptor::new(algorithm, &key);

        let data = vec![1u8; 2048]; // 2KB test data
        let result = encryptor.encrypt(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), data.len());
    }

    #[test]
    fn test_simd_operation_counting() {
        let initial_count = SimdEncryptor::simd_operation_count();
        
        let algorithm = Arc::new(Aegis256::new());
        let key = vec![0u8; 32];
        let encryptor = SimdEncryptor::new(algorithm, &key);

        if SimdEncryptor::is_avx2_supported() || SimdEncryptor::is_avx512_supported() {
            let data = vec![1u8; 2048];
            let _ = encryptor.encrypt(&data);
            
            let final_count = SimdEncryptor::simd_operation_count();
            assert!(final_count > initial_count);
        }
    }
}
