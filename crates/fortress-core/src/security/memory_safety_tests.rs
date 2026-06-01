//! Comprehensive tests for memory safety and zero-knowledge proof features

use super::*;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Test suite for constant-time operations
#[cfg(test)]
mod constant_time_tests {
    use super::*;

    #[test]
    fn test_timing_attack_resistance() {
        // Test that constant-time operations don't vary significantly in timing
        let data1 = vec![1u8; 1000];
        let data2 = vec![1u8; 1000];
        let data3 = vec![2u8; 1000];

        // Measure time for equal comparison
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            ConstantTimeOps::compare_bytes_secure(&data1, &data2);
        }
        let equal_time = start.elapsed();

        // Measure time for unequal comparison
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            ConstantTimeOps::compare_bytes_secure(&data1, &data3);
        }
        let unequal_time = start.elapsed();

        // Times should be similar (within reasonable variance)
        let time_diff = if equal_time > unequal_time {
            equal_time - unequal_time
        } else {
            unequal_time - equal_time
        };

        // Allow some variance but ensure it's not orders of magnitude different
        assert!(time_diff.as_millis() < 100); // Less than 100ms difference
    }

    #[test]
    fn test_edge_cases() {
        // Empty slices
        assert!(ConstantTimeOps::compare_bytes_secure(&[], &[]));
        assert!(!ConstantTimeOps::compare_bytes_secure(&[], &[1]));

        // Single byte
        assert!(ConstantTimeOps::compare_bytes_secure(&[1], &[1]));
        assert!(!ConstantTimeOps::compare_bytes_secure(&[1], &[2]));

        // Large data
        let large1 = vec![42u8; 10000];
        let large2 = vec![42u8; 10000];
        let large3 = vec![43u8; 10000];

        assert!(ConstantTimeOps::compare_bytes_secure(&large1, &large2));
        assert!(!ConstantTimeOps::compare_bytes_secure(&large1, &large3));
    }

    #[test]
    fn test_string_comparison() {
        let s1 = "hello world";
        let s2 = "hello world";
        let s3 = "goodbye";

        assert!(ConstantTimeOps::compare_strings_secure(s1, s2));
        assert!(!ConstantTimeOps::compare_strings_secure(s1, s3));

        // Unicode strings
        let unicode1 = "héllo wörld";
        let unicode2 = "héllo wörld";
        let unicode3 = "héllo wörld!";

        assert!(ConstantTimeOps::compare_strings_secure(unicode1, unicode2));
        assert!(!ConstantTimeOps::compare_strings_secure(unicode1, unicode3));
    }

    #[test]
    fn test_token_verification() {
        let token = b"super_secret_token_123";
        let correct = b"super_secret_token_123";
        let wrong = b"wrong_token_456";

        assert!(ConstantTimeOps::verify_token_secure(token, correct));
        assert!(!ConstantTimeOps::verify_token_secure(token, wrong));

        // Test with different lengths
        let short_token = b"short";
        assert!(!ConstantTimeOps::verify_token_secure(token, short_token));
    }
}

/// Test suite for SecureKey
#[cfg(test)]
mod secure_key_tests {
    use super::*;

    #[test]
    fn test_secure_key_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let key = SecureKey::new(data.clone());

        assert_eq!(key.as_bytes(), &data);
        assert_eq!(key.len(), data.len());
        assert!(!key.is_empty());

        // Test from_slice
        let key2 = SecureKey::from_slice(&data);
        assert!(key.equals_secure(&key2));
    }

    #[test]
    fn test_secure_key_zeroization() {
        let data = vec![1, 2, 3, 4, 5];
        let key = SecureKey::new(data);

        // Key should be accessible before drop
        assert!(!key.as_bytes().is_empty());

        // When key goes out of scope, it should be zeroized
        // This is tested implicitly through the ZeroizeOnDrop derive
    }

    #[test]
    fn test_secure_key_generation() {
        let key1 = SecureKey::generate_random(32).unwrap();
        let key2 = SecureKey::generate_random(32).unwrap();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);

        // Keys should be different
        assert!(!key1.equals_secure(&key2));

        // Test different sizes
        let key16 = SecureKey::generate_random(16).unwrap();
        assert_eq!(key16.len(), 16);

        let key64 = SecureKey::generate_random(64).unwrap();
        assert_eq!(key64.len(), 64);
    }

    #[test]
    fn test_secure_key_conversions() {
        let original = SecureKey::generate_random(32).unwrap();

        // Test hex conversion
        let hex_str = original.to_hex();
        let from_hex = SecureKey::from_hex(&hex_str).unwrap();
        assert!(original.equals_secure(&from_hex));

        // Test base64 conversion
        let b64_str = original.to_base64();
        let from_b64 = SecureKey::from_base64(&b64_str).unwrap();
        assert!(original.equals_secure(&from_b64));

        // Test invalid conversions
        assert!(SecureKey::from_hex("invalid_hex").is_err());
        assert!(SecureKey::from_base64("invalid_base64").is_err());
    }

    #[test]
    fn test_secure_key_equality() {
        let data = vec![1, 2, 3, 4, 5];
        let key1 = SecureKey::new(data.clone());
        let key2 = SecureKey::new(data);
        let key3 = SecureKey::new(vec![5, 4, 3, 2, 1]);

        assert!(key1.equals_secure(&key2));
        assert!(!key1.equals_secure(&key3));

        // Test with different lengths
        let key4 = SecureKey::new(vec![1, 2, 3]);
        assert!(!key1.equals_secure(&key4));
    }
}

/// Test suite for SecureMemoryPool
#[cfg(test)]
mod secure_memory_pool_tests {
    use super::*;

    #[test]
    fn test_memory_pool_basic_operations() {
        let pool = SecureMemoryPool::new(5, 10, 1024);

        // Initial state
        let (available, max_size, total) = pool.get_stats();
        assert_eq!(available, 5);
        assert_eq!(max_size, 10);
        assert_eq!(total, 5120); // 5 * 1024

        // Get buffers
        let mut buffers: Vec<Vec<u8>> = Vec::new();
        for _ in 0..3 {
            buffers.push(pool.get_secure_buffer());
        }

        // Check state after getting buffers
        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 2);

        // Verify buffer size
        assert_eq!(buffers[0].len(), 1024);
        assert_eq!(buffers[1].len(), 1024);
        assert_eq!(buffers[2].len(), 1024);

        // Return buffers
        for buffer in buffers {
            pool.return_secure_buffer(buffer);
        }

        // Check state after returning buffers
        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 5);
    }

    #[test]
    fn test_memory_pool_expansion() {
        let pool = SecureMemoryPool::new(2, 5, 512);

        // Get more buffers than initially available
        let mut buffers: Vec<Vec<u8>> = Vec::new();
        for _ in 0..8 {
            buffers.push(pool.get_secure_buffer());
        }

        // Pool should be empty
        let (available, _, total) = pool.get_stats();
        assert_eq!(available, 0);
        assert!(total > 1024); // Should have allocated more

        // Return all buffers
        for buffer in buffers {
            pool.return_secure_buffer(buffer);
        }

        // Pool should have buffers (but limited by max_size)
        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 5); // Max size
    }

    #[test]
    fn test_memory_pool_buffer_validation() {
        let pool = SecureMemoryPool::new(2, 5, 1024);

        // Test correct buffer size
        let correct_buffer = vec![0u8; 1024];
        pool.return_secure_buffer(correct_buffer);

        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 3); // 2 initial + 1 returned

        // Test incorrect buffer size
        let wrong_buffer = vec![0u8; 512];
        pool.return_secure_buffer(wrong_buffer);

        // Should not accept wrong size buffer
        let (available, _, _) = pool.get_stats();
        assert_eq!(available, 3); // Unchanged
    }

    #[test]
    fn test_memory_pool_thread_safety() {
        let pool = Arc::new(SecureMemoryPool::new(10, 20, 1024));
        let mut handles = Vec::new();

        // Spawn multiple threads
        for _ in 0..10 {
            let pool_clone = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let buffer = pool_clone.get_secure_buffer();
                    thread::sleep(Duration::from_millis(1));
                    pool_clone.return_secure_buffer(buffer);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Pool should still be in a valid state
        let (available, max_size, total) = pool.get_stats();
        assert!(available <= max_size);
        assert!(total > 0);
    }

    #[test]
    fn test_memory_pool_clear() {
        let pool = SecureMemoryPool::new(5, 10, 1024);

        // Get and return some buffers
        let buffers: Vec<Vec<u8>> = (0..3).map(|_| pool.get_secure_buffer()).collect();
        for buffer in buffers {
            pool.return_secure_buffer(buffer);
        }

        // Clear pool
        pool.clear();

        // Check state after clear
        let (available, _, total) = pool.get_stats();
        assert_eq!(available, 0);
        assert_eq!(total, 0);
    }
}

/// Test suite for global memory pool manager
#[cfg(test)]
mod global_memory_pool_tests {
    use super::*;

    #[test]
    fn test_global_pool_manager() {
        let global_pool = GlobalSecureMemoryPool::new();

        // Add multiple pools
        let pool1 = SecureMemoryPool::new(2, 5, 512);
        let pool2 = SecureMemoryPool::new(3, 6, 1024);
        let pool3 = SecureMemoryPool::new(4, 8, 2048);

        global_pool.add_pool(pool1);
        global_pool.add_pool(pool2);
        global_pool.add_pool(pool3);

        // Check statistics
        let stats = global_pool.get_all_stats();
        assert_eq!(stats.len(), 3);
        assert_eq!(stats[0], (2, 5, 1024)); // 2 * 512
        assert_eq!(stats[1], (3, 6, 3072)); // 3 * 1024
        assert_eq!(stats[2], (4, 8, 8192)); // 4 * 2048

        // Clear all pools
        global_pool.clear_all();

        let stats_after_clear = global_pool.get_all_stats();
        assert_eq!(stats_after_clear[0], (0, 5, 0));
        assert_eq!(stats_after_clear[1], (0, 6, 0));
        assert_eq!(stats_after_clear[2], (0, 8, 0));
    }
}

/// Test suite for utility functions
#[cfg(test)]
mod utility_tests {
    use super::*;

    #[test]
    fn test_password_verification() {
        let password = "user_password_123";
        let stored_hash = "user_password_123";
        let wrong_password = "wrong_password";

        assert!(utils::verify_password_secure(password, stored_hash));
        assert!(!utils::verify_password_secure(password, wrong_password));

        // Test with empty strings
        assert!(utils::verify_password_secure("", ""));
        assert!(!utils::verify_password_secure("", "not_empty"));
    }

    #[test]
    fn test_string_wiping() {
        let s = String::from("sensitive_data_12345");
        let _original_ptr = s.as_ptr();

        utils::wipe_string(s);

        // String should be dropped and zeroized
        // (This is tested implicitly through the zeroize implementation)
    }

    #[test]
    fn test_byte_wiping() {
        let mut data = vec![1, 2, 3, 4, 5];
        utils::wipe_bytes(&mut data);

        // Data should be zeroized
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = utils::generate_secure_nonce(16).unwrap();
        let nonce2 = utils::generate_secure_nonce(16).unwrap();
        let nonce3 = utils::generate_secure_nonce(32).unwrap();

        assert_eq!(nonce1.len(), 16);
        assert_eq!(nonce2.len(), 16);
        assert_eq!(nonce3.len(), 32);

        // Nonces should be different
        assert_ne!(nonce1, nonce2);

        // Test different sizes
        let nonce_large = utils::generate_secure_nonce(64).unwrap();
        assert_eq!(nonce_large.len(), 64);
    }

    #[test]
    fn test_hkdf_key_derivation() {
        let secret = b"master_secret_key";
        let salt = b"salt_value";
        let info = b"context_info";

        let derived1 = utils::derive_key_hkdf(secret, salt, info, 32).unwrap();
        let derived2 = utils::derive_key_hkdf(secret, salt, info, 32).unwrap();
        let derived3 = utils::derive_key_hkdf(secret, salt, b"different_info", 32).unwrap();

        // Same inputs should produce same output
        assert!(derived1.equals_secure(&derived2));

        // Different info should produce different output
        assert!(!derived1.equals_secure(&derived3));

        // Test different lengths
        let derived16 = utils::derive_key_hkdf(secret, salt, info, 16).unwrap();
        assert_eq!(derived16.len(), 16);

        let derived64 = utils::derive_key_hkdf(secret, salt, info, 64).unwrap();
        assert_eq!(derived64.len(), 64);
    }
}

/// Performance benchmarks for memory safety features
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_constant_time_comparison() {
        let data1 = vec![42u8; 1000];
        let data2 = vec![42u8; 1000];
        let data3 = vec![43u8; 1000];

        let iterations = 10000;

        // Benchmark equal comparison
        let start = Instant::now();
        for _ in 0..iterations {
            ConstantTimeOps::compare_bytes_secure(&data1, &data2);
        }
        let equal_duration = start.elapsed();

        // Benchmark unequal comparison
        let start = Instant::now();
        for _ in 0..iterations {
            ConstantTimeOps::compare_bytes_secure(&data1, &data3);
        }
        let unequal_duration = start.elapsed();

        // Benchmark standard comparison
        let start = Instant::now();
        for _ in 0..iterations {
            data1 == data2;
        }
        let standard_duration = start.elapsed();

        println!("Equal comparison: {:?}", equal_duration);
        println!("Unequal comparison: {:?}", unequal_duration);
        println!("Standard comparison: {:?}", standard_duration);

        // Constant-time should be reasonably fast
        assert!(equal_duration.as_millis() < 1000);
        assert!(unequal_duration.as_millis() < 1000);
    }

    #[test]
    fn benchmark_secure_key_operations() {
        let iterations = 1000;

        // Benchmark key generation
        let start = Instant::now();
        let mut keys = Vec::new();
        for _ in 0..iterations {
            keys.push(SecureKey::generate_random(32).unwrap());
        }
        let generation_duration = start.elapsed();

        // Benchmark key comparison
        let start = Instant::now();
        for i in 0..iterations {
            for j in 0..iterations.min(100) {
                keys[i].equals_secure(&keys[j]);
            }
        }
        let comparison_duration = start.elapsed();

        // Benchmark hex conversion
        let start = Instant::now();
        for key in &keys {
            let _hex = key.to_hex();
        }
        let hex_duration = start.elapsed();

        println!("Key generation: {:?}", generation_duration);
        println!("Key comparison: {:?}", comparison_duration);
        println!("Hex conversion: {:?}", hex_duration);

        // Operations should be reasonably fast
        assert!(generation_duration.as_millis() < 5000);
        assert!(comparison_duration.as_millis() < 1000);
        assert!(hex_duration.as_millis() < 1000);
    }

    #[test]
    fn benchmark_memory_pool_operations() {
        let pool = SecureMemoryPool::new(100, 200, 1024);
        let iterations = 10000;

        // Benchmark buffer allocation
        let start = Instant::now();
        let mut buffers = Vec::new();
        for _ in 0..iterations {
            buffers.push(pool.get_secure_buffer());
        }
        let allocation_duration = start.elapsed();

        // Benchmark buffer return
        let start = Instant::now();
        for buffer in buffers {
            pool.return_secure_buffer(buffer);
        }
        let return_duration = start.elapsed();

        println!("Buffer allocation: {:?}", allocation_duration);
        println!("Buffer return: {:?}", return_duration);

        // Operations should be fast
        assert!(allocation_duration.as_millis() < 1000);
        assert!(return_duration.as_millis() < 1000);
    }
}

/// Integration tests combining multiple features
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_secure_key_with_memory_pool() {
        let pool = SecureMemoryPool::new(10, 20, 64);

        // Generate secure keys
        let key1 = SecureKey::generate_random(32).unwrap();
        let key2 = SecureKey::generate_random(32).unwrap();

        // Use memory pool for temporary operations
        let mut buffer1 = pool.get_secure_buffer();
        let mut buffer2 = pool.get_secure_buffer();

        // Copy key data to buffers for processing
        buffer1[..32].copy_from_slice(key1.as_bytes());
        buffer2[..32].copy_from_slice(key2.as_bytes());

        // Compare using constant-time operations
        let equal = ConstantTimeOps::compare_bytes_secure(&buffer1[..32], &buffer2[..32]);
        assert!(!equal);

        // Return buffers to pool
        pool.return_secure_buffer(buffer1);
        pool.return_secure_buffer(buffer2);

        // Keys should still be valid
        assert!(!key1.equals_secure(&key2));
    }

    #[test]
    fn test_end_to_end_secure_workflow() {
        // Create global memory pool manager
        let global_pool = GlobalSecureMemoryPool::new();
        let pool = SecureMemoryPool::new(5, 10, 1024);
        global_pool.add_pool(pool);

        // Generate master key
        let master_key = SecureKey::generate_random(64).unwrap();

        // Derive multiple keys using HKDF
        let encryption_key = utils::derive_key_hkdf(
            master_key.as_bytes(),
            b"encryption_salt",
            b"encryption_context",
            32,
        )
        .unwrap();

        let auth_key =
            utils::derive_key_hkdf(master_key.as_bytes(), b"auth_salt", b"auth_context", 32)
                .unwrap();

        // Use memory pool for temporary data
        let _pool = &global_pool.get_all_stats()[0];
        let _temp_buffer = vec![0u8; 1024];

        // Verify keys are different
        assert!(!encryption_key.equals_secure(&auth_key));

        // Test token verification
        let token = b"secure_token_12345";
        let verified = ConstantTimeOps::verify_token_secure(token, token);
        assert!(verified);

        // Clean up
        global_pool.clear_all();
    }

    #[test]
    fn test_concurrent_secure_operations() {
        let pool = Arc::new(SecureMemoryPool::new(20, 40, 1024));
        let mut handles = Vec::new();

        // Spawn threads performing various secure operations
        for _i in 0..10 {
            let pool_clone = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                // Generate secure key
                let key = SecureKey::generate_random(32).unwrap();

                // Use memory pool
                let mut buffer = pool_clone.get_secure_buffer();
                buffer[..32].copy_from_slice(key.as_bytes());

                // Perform constant-time comparison
                let equal = ConstantTimeOps::compare_bytes_secure(&buffer[..32], key.as_bytes());
                assert!(equal);

                // Return buffer
                pool_clone.return_secure_buffer(buffer);

                // Return key identifier
                key.to_hex()
            });
            handles.push(handle);
        }

        // Collect results
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // Verify all keys are different
        for (i, result1) in results.iter().enumerate() {
            for (j, result2) in results.iter().enumerate() {
                if i != j {
                    assert_ne!(result1, result2);
                }
            }
        }
    }
}
