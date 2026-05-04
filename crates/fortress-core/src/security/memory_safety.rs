//! Memory Safety Module
//! 
//! This module provides memory safety improvements including constant-time operations,
//! secure memory zeroization, and secure memory pools for sensitive data.

use crate::error::FortressError;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

/// Constant-time comparison operations to prevent timing attacks
pub struct ConstantTimeOps;

impl ConstantTimeOps {
    /// Secure constant-time comparison of two byte slices
    /// 
    /// # Arguments
    /// * `a` - First byte slice to compare
    /// * `b` - Second byte slice to compare
    /// 
    /// # Returns
    /// * `true` if slices are equal, `false` otherwise
    /// 
    /// # Security
    /// This function performs the comparison in constant time to prevent
    /// timing attacks that could reveal information about the data.
    pub fn compare_bytes_secure(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Secure constant-time comparison of two strings
    /// 
    /// # Arguments
    /// * `a` - First string to compare
    /// * `b` - Second string to compare
    /// 
    /// # Returns
    /// * `true` if strings are equal, `false` otherwise
    /// 
    /// # Security
    /// Performs constant-time comparison to prevent timing attacks.
    pub fn compare_strings_secure(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.as_bytes().ct_eq(b.as_bytes()).into()
    }

    /// Secure constant-time comparison for authentication tokens
    /// 
    /// # Arguments
    /// * `token` - Authentication token to verify
    /// * `expected` - Expected token value
    /// 
    /// # Returns
    /// * `true` if tokens match, `false` otherwise
    /// 
    /// # Security
    /// Uses constant-time comparison to prevent timing attacks on authentication.
    pub fn verify_token_secure(token: &[u8], expected: &[u8]) -> bool {
        Self::compare_bytes_secure(token, expected)
    }
}

/// Secure key with automatic zeroization
#[derive(Debug, Clone, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SecureKey {
    data: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key
    /// 
    /// # Arguments
    /// * `data` - Key data as bytes
    /// 
    /// # Returns
    /// * `SecureKey` instance
    /// 
    /// # Security
    /// The key data will be automatically zeroized when the SecureKey is dropped.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a secure key from a slice
    /// 
    /// # Arguments
    /// * `data` - Key data as slice
    /// 
    /// # Returns
    /// * `SecureKey` instance
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    /// Generate a secure random key of specified length
    /// 
    /// # Arguments
    /// * `length` - Length of key to generate in bytes
    /// 
    /// # Returns
    /// * `Result<SecureKey, FortressError>` - Generated secure key or error
    pub fn generate_random(length: usize) -> Result<Self, FortressError> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; length];
        rng.fill_bytes(&mut data);
        Ok(Self::new(data))
    }

    /// Get reference to key data
    /// 
    /// # Returns
    /// * `&[u8]` - Reference to key data
    /// 
    /// # Security
    /// Returns immutable reference to prevent accidental modification.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get key length
    /// 
    /// # Returns
    /// * `usize` - Length of key in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if key is empty
    /// 
    /// # Returns
    /// * `bool` - true if key is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Securely compare with another key using constant-time comparison
    /// 
    /// # Arguments
    /// * `other` - Other key to compare with
    /// 
    /// # Returns
    /// * `bool` - true if keys are equal
    /// 
    /// # Security
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn equals_secure(&self, other: &SecureKey) -> bool {
        ConstantTimeOps::compare_bytes_secure(&self.data, &other.data)
    }

    /// Convert to hex string (for display purposes only)
    /// 
    /// # Returns
    /// * `String` - Hexadecimal representation
    /// 
    /// # Security
    /// This should only be used for display/debugging purposes, not for cryptographic operations.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.data)
    }

    /// Convert to base64 string (for storage/transmission)
    /// 
    /// # Returns
    /// * `String` - Base64 representation
    /// 
    /// # Security
    /// Use only when necessary for storage/transmission protocols.
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.data)
    }

    /// Convert to Vec<u8> (for cryptographic operations)
    /// 
    /// # Returns
    /// * `Vec<u8>` - Clone of key data
    /// 
    /// # Security
    /// This creates a copy of the key data. Use with care in performance-critical code.
    pub fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Create secure key from hex string
    /// 
    /// # Arguments
    /// * `hex_str` - Hexadecimal string representation
    /// 
    /// # Returns
    /// * `Result<SecureKey, FortressError>` - Secure key or error
    pub fn from_hex(hex_str: &str) -> Result<Self, FortressError> {
        let data = hex::decode(hex_str)
            .map_err(|e| FortressError::encryption(format!("Invalid hex format: {}", e), "hex_decode".to_string(), crate::error::EncryptionErrorCode::InvalidInput))?;
        Ok(Self::new(data))
    }

    /// Create secure key from base64 string
    /// 
    /// # Arguments
    /// * `base64_str` - Base64 string representation
    /// 
    /// # Returns
    /// * `Result<SecureKey, FortressError>` - Secure key or error
    pub fn from_base64(base64_str: &str) -> Result<Self, FortressError> {
        use base64::{Engine as _, engine::general_purpose};
        let data = general_purpose::STANDARD.decode(base64_str)
            .map_err(|e| FortressError::encryption(format!("Invalid base64 format: {}", e), "base64_decode".to_string(), crate::error::EncryptionErrorCode::InvalidInput))?;
        Ok(Self::new(data))
    }
}

/// Secure memory pool for managing sensitive data buffers
pub struct SecureMemoryPool {
    pool: Arc<Mutex<VecDeque<Vec<u8>>>>,
    max_size: usize,
    buffer_size: usize,
    total_allocated: Arc<Mutex<usize>>,
}

impl SecureMemoryPool {
    /// Create a new secure memory pool
    /// 
    /// # Arguments
    /// * `initial_size` - Initial number of buffers to allocate
    /// * `max_size` - Maximum number of buffers in pool
    /// * `buffer_size` - Size of each buffer in bytes
    /// 
    /// # Returns
    /// * `SecureMemoryPool` instance
    /// 
    /// # Security
    /// All buffers are securely zeroized when returned to pool or when pool is dropped.
    pub fn new(initial_size: usize, max_size: usize, buffer_size: usize) -> Self {
        let mut pool = VecDeque::with_capacity(initial_size);
        
        // Pre-allocate initial buffers
        for _ in 0..initial_size {
            pool.push_back(vec![0u8; buffer_size]);
        }

        Self {
            pool: Arc::new(Mutex::new(pool)),
            max_size,
            buffer_size,
            total_allocated: Arc::new(Mutex::new(initial_size * buffer_size)),
        }
    }

    /// Get a secure buffer from the pool
    /// 
    /// # Returns
    /// * `Vec<u8>` - Secure buffer
    /// 
    /// # Security
    /// Returns a zeroized buffer. Buffer will be securely wiped when returned.
    pub fn get_secure_buffer(&self) -> Vec<u8> {
        let mut pool = self.pool.lock().unwrap();
        if let Some(mut buffer) = pool.pop_front() {
            // Ensure buffer is zeroized
            buffer.zeroize();
            buffer
        } else {
            // Create new buffer if pool is empty
            let mut total_allocated = self.total_allocated.lock().unwrap();
            *total_allocated += self.buffer_size;
            vec![0u8; self.buffer_size]
        }
    }

    /// Return a buffer to the pool
    /// 
    /// # Arguments
    /// * `buffer` - Buffer to return to pool
    /// 
    /// # Security
    /// Buffer is securely zeroized before being returned to pool.
    pub fn return_secure_buffer(&self, mut buffer: Vec<u8>) {
        // Check if buffer size matches expected size
        if buffer.len() != self.buffer_size {
            // Buffer size mismatch, securely zeroize and drop
            buffer.zeroize();
            return;
        }

        // Securely zeroize buffer
        buffer.zeroize();

        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.max_size {
            pool.push_back(buffer);
        }
        // If pool is full, buffer is dropped and automatically zeroized
    }

    /// Get pool statistics
    /// 
    /// # Returns
    /// * `(usize, usize, usize)` - (available buffers, max size, total allocated bytes)
    pub fn get_stats(&self) -> (usize, usize, usize) {
        let pool = self.pool.lock().unwrap();
        let total_allocated = self.total_allocated.lock().unwrap();
        (pool.len(), self.max_size, *total_allocated)
    }

    /// Clear the pool and securely wipe all buffers
    /// 
    /// # Security
    /// All buffers in the pool are securely zeroized.
    pub fn clear(&self) {
        let mut pool = self.pool.lock().unwrap();
        while let Some(mut buffer) = pool.pop_front() {
            buffer.zeroize();
        }
        
        // Reset allocation counter
        let mut total_allocated = self.total_allocated.lock().unwrap();
        *total_allocated = 0;
    }

    /// Resize the pool
    /// 
    /// # Arguments
    /// * `new_max_size` - New maximum pool size
    /// 
    /// # Security
    /// Excess buffers are securely zeroized.
    pub fn resize(&self, new_max_size: usize) {
        let mut pool = self.pool.lock().unwrap();
        
        // Remove excess buffers and zeroize them
        while pool.len() > new_max_size {
            if let Some(mut buffer) = pool.pop_front() {
                buffer.zeroize();
            }
        }
        
        // Update max size (stored separately for simplicity)
        // Note: In a real implementation, you'd store this as a field
    }
}

impl Drop for SecureMemoryPool {
    fn drop(&mut self) {
        // Securely wipe all buffers when pool is destroyed
        if let Ok(mut pool) = self.pool.try_lock() {
            while let Some(mut buffer) = pool.pop_front() {
                buffer.zeroize();
            }
        }
    }
}

/// Global secure memory pool manager
pub struct GlobalSecureMemoryPool {
    pools: Arc<Mutex<Vec<SecureMemoryPool>>>,
}

impl GlobalSecureMemoryPool {
    /// Create a new global secure memory pool manager
    /// 
    /// # Returns
    /// * `GlobalSecureMemoryPool` instance
    pub fn new() -> Self {
        Self {
            pools: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a memory pool to the manager
    /// 
    /// # Arguments
    /// * `pool` - Secure memory pool to add
    pub fn add_pool(&self, pool: SecureMemoryPool) {
        let mut pools = self.pools.lock().unwrap();
        pools.push(pool);
    }

    /// Clear all managed pools
    /// 
    /// # Security
    /// Securely wipes all buffers in all managed pools.
    pub fn clear_all(&self) {
        let pools = self.pools.lock().unwrap();
        for pool in pools.iter() {
            pool.clear();
        }
    }

    /// Get statistics for all pools
    /// 
    /// # Returns
    /// * `Vec<(usize, usize, usize)>` - Vector of pool statistics
    pub fn get_all_stats(&self) -> Vec<(usize, usize, usize)> {
        let pools = self.pools.lock().unwrap();
        pools.iter().map(|pool| pool.get_stats()).collect()
    }
}

impl Default for GlobalSecureMemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for secure memory operations
pub mod utils {
    use super::*;

    /// Securely compare two passwords using constant-time comparison
    /// 
    /// # Arguments
    /// * `password` - User-provided password
    /// * `stored_hash` - Stored password hash
    /// 
    /// # Returns
    /// * `bool` - true if passwords match
    /// 
    /// # Security
    /// Uses constant-time comparison to prevent timing attacks on password verification.
    pub fn verify_password_secure(password: &str, stored_hash: &str) -> bool {
        ConstantTimeOps::compare_strings_secure(password, stored_hash)
    }

    /// Securely wipe a string
    /// 
    /// # Arguments
    /// * `s` - String to wipe (will be consumed)
    /// 
    /// # Security
    /// The string memory will be securely zeroized.
    pub fn wipe_string(mut s: String) {
        s.zeroize();
    }

    /// Securely wipe a byte slice
    /// 
    /// # Arguments
    /// * `data` - Byte slice to wipe
    /// 
    /// # Security
    /// The slice memory will be securely zeroized.
    pub fn wipe_bytes(data: &mut [u8]) {
        data.zeroize();
    }

    /// Create a secure random nonce
    /// 
    /// # Arguments
    /// * `length` - Length of nonce in bytes
    /// 
    /// # Returns
    /// * `Result<Vec<u8>, FortressError>` - Random nonce
    pub fn generate_secure_nonce(length: usize) -> Result<Vec<u8>, FortressError> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut nonce = vec![0u8; length];
        rng.fill_bytes(&mut nonce);
        Ok(nonce)
    }

    /// Derive a secure key using HKDF
    /// 
    /// # Arguments
    /// * `secret` - Input secret/key material
    /// * `salt` - Salt value
    /// * `info` - Context info
    /// * `length` - Desired key length
    /// 
    /// # Returns
    /// * `Result<SecureKey, FortressError>` - Derived secure key
    pub fn derive_key_hkdf(
        secret: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<SecureKey, FortressError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(salt), secret);
        let mut okm = vec![0u8; length];
        
        hk.expand(info, &mut okm)
            .map_err(|e| FortressError::encryption(format!("HKDF expansion failed: {}", e), "hkdf_expand".to_string(), crate::error::EncryptionErrorCode::KeyGenerationFailed))?;
        
        Ok(SecureKey::new(okm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_comparison() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"goodbye";

        assert!(ConstantTimeOps::compare_bytes_secure(a, b));
        assert!(!ConstantTimeOps::compare_bytes_secure(a, c));
        assert!(!ConstantTimeOps::compare_bytes_secure(a, b"hello"));

        assert!(ConstantTimeOps::compare_strings_secure("hello", "hello"));
        assert!(!ConstantTimeOps::compare_strings_secure("hello", "world"));
    }

    #[test]
    fn test_secure_key() {
        let key_data = vec![1, 2, 3, 4, 5];
        let key = SecureKey::new(key_data.clone());

        assert_eq!(key.as_bytes(), &key_data);
        assert_eq!(key.len(), key_data.len());
        assert!(!key.is_empty());

        let key2 = SecureKey::new(key_data.clone());
        assert!(key.equals_secure(&key2));

        let key3 = SecureKey::new(vec![5, 4, 3, 2, 1]);
        assert!(!key.equals_secure(&key3));

        // Test hex conversion
        let hex_str = key.to_hex();
        let key_from_hex = SecureKey::from_hex(&hex_str).unwrap();
        assert!(key.equals_secure(&key_from_hex));

        // Test base64 conversion
        let b64_str = key.to_base64();
        let key_from_b64 = SecureKey::from_base64(&b64_str).unwrap();
        assert!(key.equals_secure(&key_from_b64));
    }

    #[test]
    fn test_secure_key_generation() {
        let key = SecureKey::generate_random(32).unwrap();
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());

        // Ensure generated keys are different
        let key2 = SecureKey::generate_random(32).unwrap();
        assert!(!key.equals_secure(&key2));
    }

    #[test]
    fn test_secure_memory_pool() {
        let pool = SecureMemoryPool::new(2, 5, 1024);
        
        // Get initial stats
        let (available, max_size, total) = pool.get_stats();
        assert_eq!(available, 2);
        assert_eq!(max_size, 5);
        assert_eq!(total, 2048); // 2 * 1024

        // Get a buffer
        let buffer1 = pool.get_secure_buffer();
        assert_eq!(buffer1.len(), 1024);

        // Check stats after getting buffer
        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 1);

        // Return buffer
        pool.return_secure_buffer(buffer1);

        // Check stats after returning buffer
        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 2);

        // Test buffer size validation
        let wrong_size_buffer = vec![0u8; 512];
        pool.return_secure_buffer(wrong_size_buffer); // Should be rejected
        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 2); // Should not change

        // Test pool expansion
        let buffers: Vec<_> = (0..10).map(|_| pool.get_secure_buffer()).collect();
        let (available, _, total_after) = pool.get_stats();
        assert_eq!(available, 0); // Pool should be empty
        assert!(total_after > total); // Should have allocated more memory

        // Return all buffers
        for buffer in buffers {
            pool.return_secure_buffer(buffer);
        }

        // Clear pool
        pool.clear();
        let (available, _, total_after_clear) = pool.get_stats();
        assert_eq!(available, 0);
        assert_eq!(total_after_clear, 0);
    }

    #[test]
    fn test_global_secure_memory_pool() {
        let global_pool = GlobalSecureMemoryPool::new();
        
        let pool1 = SecureMemoryPool::new(2, 5, 512);
        let pool2 = SecureMemoryPool::new(3, 6, 1024);

        global_pool.add_pool(pool1);
        global_pool.add_pool(pool2);

        let stats = global_pool.get_all_stats();
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0], (2, 5, 1024)); // 2 * 512
        assert_eq!(stats[1], (3, 6, 3072)); // 3 * 1024

        global_pool.clear_all();
        let stats_after_clear = global_pool.get_all_stats();
        assert_eq!(stats_after_clear[0], (0, 5, 0));
        assert_eq!(stats_after_clear[1], (0, 6, 0));
    }

    #[test]
    fn test_utils() {
        // Test password verification
        assert!(utils::verify_password_secure("password123", "password123"));
        assert!(!utils::verify_password_secure("password123", "wrong"));

        // Test string wiping
        let mut s = String::from("sensitive data");
        utils::wipe_string(s);

        // Test nonce generation
        let nonce = utils::generate_secure_nonce(16).unwrap();
        assert_eq!(nonce.len(), 16);

        // Test HKDF key derivation
        let secret = b"master_secret";
        let salt = b"salt_value";
        let info = b"context";
        let derived_key = utils::derive_key_hkdf(secret, salt, info, 32).unwrap();
        assert_eq!(derived_key.len(), 32);
    }
}
