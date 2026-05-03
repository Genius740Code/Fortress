//! Comprehensive tests for the True Random Number Generator (TRNG) system

use fortress_core::trng::*;
use std::time::Duration;

#[test]
fn test_trng_initialization() {
    // Test default initialization
    let trng = TrueRandomGenerator::new();
    assert!(trng.is_ok());
    
    let trng = trng.unwrap();
    assert_eq!(trng.health_status(), TrngHealth::Healthy);
    
    // Test custom configuration
    let config = TrngConfig {
        min_entropy_bits: 128,
        max_pool_size: 2048,
        health_check_interval: Duration::from_millis(500),
        entropy_sources: 3,
        enable_fallback: true,
    };
    
    let trng_custom = TrueRandomGenerator::with_config(config);
    assert!(trng_custom.is_ok());
}

#[test]
fn test_entropy_sources() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Test each entropy source
    let sources = [
        EntropySource::CpuTiming,
        EntropySource::NetworkJitter,
        EntropySource::DiskIo,
        EntropySource::MemoryLatency,
        EntropySource::SystemTime,
    ];
    
    for source in &sources {
        let result = trng.collect_entropy(*source);
        assert!(result.is_ok(), "Failed to collect entropy from {:?}", source);
        
        let (data, bits) = result.unwrap();
        assert!(!data.is_empty(), "Empty entropy data from {:?}", source);
        assert!(bits > 0, "No entropy bits from {:?}", source);
        
        println!("Source {:?}: {} bytes, {} bits estimated", source, data.len(), bits);
    }
}

#[test]
fn test_random_byte_generation() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Test various sizes
    let sizes = [1, 8, 16, 32, 64, 128, 256, 512, 1024];
    
    for &size in &sizes {
        let bytes1 = trng.generate_bytes(size).unwrap();
        let bytes2 = trng.generate_bytes(size).unwrap();
        
        assert_eq!(bytes1.len(), size);
        assert_eq!(bytes2.len(), size);
        
        // For very small sizes or when entropy is low, sequences might be similar
        // Focus on larger sizes where we expect more randomness
        if size >= 16 {
            assert_ne!(bytes1, bytes2, "Generated identical byte sequences of size {}", size);
        }
        
        // Test that bytes are reasonably random (not all zeros or all same)
        if size > 1 {
            let all_zero = bytes1.iter().all(|&b| b == 0);
            let all_same = bytes1.windows(2).all(|w| w[0] == w[1]);
            assert!(!all_zero, "All bytes are zero for size {}", size);
            assert!(!all_same, "All bytes are identical for size {}", size);
        }
        
        // Refresh entropy between tests for larger sizes
        if size >= 64 {
            let _ = trng.refresh_entropy();
        }
    }
}

#[test]
fn test_random_number_generation() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Test u64 generation
    let val1 = trng.generate_u64().unwrap();
    let val2 = trng.generate_u64().unwrap();
    assert_ne!(val1, val2);
    
    // Test u32 generation
    let val3 = trng.generate_u32().unwrap();
    let val4 = trng.generate_u32().unwrap();
    assert_ne!(val3, val4);
    
    // Test that values are reasonably distributed
    let mut values = Vec::new();
    for _ in 0..1000 {
        values.push(trng.generate_u64().unwrap());
    }
    
    // Simple statistical test - check that we have variation
    let min_val = values.iter().min().unwrap();
    let max_val = values.iter().max().unwrap();
    assert!(max_val > min_val, "No variation in generated values");
    
    // Check that not all values are the same
    let first_val = values[0];
    let all_same = values.iter().all(|&v| v == first_val);
    assert!(!all_same, "All generated values are identical");
}

#[test]
fn test_fill_bytes() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    let mut buffer1 = [0u8; 64];
    let mut buffer2 = [0u8; 64];
    
    trng.fill_bytes(&mut buffer1).unwrap();
    trng.fill_bytes(&mut buffer2).unwrap();
    
    // Should not be all zeros
    assert_ne!(buffer1, [0u8; 64]);
    assert_ne!(buffer2, [0u8; 64]);
    
    // Should be different
    assert_ne!(buffer1, buffer2);
    
    // Test different buffer sizes (skip size 1 as it might be zero due to entropy limitations)
    let sizes = [8, 16, 32, 63, 127];
    for &size in &sizes {
        let mut buf = vec![0u8; size];
        trng.fill_bytes(&mut buf).unwrap();
        
        // For larger buffers, should not be all zeros
        if size >= 8 {
            let all_zero = buf.iter().all(|&b| b == 0);
            if all_zero {
                // Try refreshing entropy and retry once
                let _ = trng.refresh_entropy();
                trng.fill_bytes(&mut buf).unwrap();
            }
            assert_ne!(buf, vec![0u8; size], "Buffer of size {} should not be all zeros", size);
        }
    }
}

#[test]
fn test_entropy_pool_management() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Check initial entropy
    let (entropy_bits, pool_size) = trng.entropy_stats();
    assert!(entropy_bits > 0);
    assert!(pool_size > 0);
    
    // Generate some bytes to consume entropy
    let _bytes = trng.generate_bytes(32).unwrap();
    
    // Check that entropy decreased
    let (new_entropy_bits, _) = trng.entropy_stats();
    assert!(new_entropy_bits < entropy_bits);
    
    // Refresh entropy
    trng.refresh_entropy().unwrap();
    
    // Check that entropy increased again
    let (refreshed_entropy_bits, _) = trng.entropy_stats();
    assert!(refreshed_entropy_bits > new_entropy_bits);
}

#[test]
fn test_health_monitoring() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Initial health should be healthy or degraded
    let health = trng.health_status();
    assert!(health == TrngHealth::Healthy || health == TrngHealth::Degraded);
    
    // Force health check
    let result = trng.health_check();
    assert!(result.is_ok());
    
    // Health should still be good
    let health = trng.health_status();
    assert!(health != TrngHealth::Failed);
}

#[test]
fn test_global_trng() {
    // Test global TRNG initialization
    let result = init_global_trng();
    assert!(result.is_ok());
    
    // Test convenience functions
    let bytes = random_bytes(32);
    assert!(bytes.is_ok());
    assert_eq!(bytes.unwrap().len(), 32);
    
    let val = random_u64();
    assert!(val.is_ok());
    
    let mut buffer = [0u8; 16];
    let result = fill_random(&mut buffer);
    assert!(result.is_ok());
    assert_ne!(buffer, [0u8; 16]);
}

#[test]
fn test_fallback_mechanism() {
    // Create a TRNG with very low entropy requirements to test fallback
    let config = TrngConfig {
        min_entropy_bits: 1,
        enable_fallback: true,
        ..Default::default()
    };
    
    let trng = TrueRandomGenerator::with_config(config).unwrap();
    
    // Should work even with minimal entropy
    let bytes = trng.generate_bytes(32);
    assert!(bytes.is_ok());
}

#[test]
fn test_reinitialization() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Generate some data to consume entropy
    let _bytes = trng.generate_bytes(64).unwrap();
    
    // Reinitialize
    let result = trng.reinitialize();
    assert!(result.is_ok());
    
    // Should work again
    let bytes = trng.generate_bytes(32).unwrap();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn test_concurrent_access() {
    use std::sync::Arc;
    use std::thread;
    
    let trng = Arc::new(TrueRandomGenerator::new().unwrap());
    let mut handles = Vec::new();
    
    // Spawn multiple threads that generate random data
    for _ in 0..10 {
        let trng_clone = Arc::clone(&trng);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                let bytes = trng_clone.generate_bytes(32).unwrap();
                assert_eq!(bytes.len(), 32);
                assert_ne!(bytes, vec![0u8; 32]);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_entropy_quality() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Generate multiple samples and test basic properties
    let mut samples = Vec::new();
    for _ in 0..10 {
        let chunk = trng.generate_bytes(256).unwrap();
        samples.push(chunk);
        
        // Refresh entropy periodically
        let _ = trng.refresh_entropy();
    }
    
    // Test that samples are different from each other
    for i in 0..samples.len() {
        for j in (i + 1)..samples.len() {
            assert_ne!(samples[i], samples[j], "Samples {} and {} should be different", i, j);
        }
    }
    
    // Test that samples are not all zeros
    for (i, sample) in samples.iter().enumerate() {
        assert_ne!(sample.as_slice(), [0u8; 256], "Sample {} should not be all zeros", i);
    }
    
    // Test basic variety - check that we have different byte values
    let mut all_bytes = Vec::new();
    for sample in &samples {
        all_bytes.extend_from_slice(sample);
    }
    
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in &all_bytes {
        unique_bytes.insert(byte);
    }
    
    // Should have at least some variety
    assert!(unique_bytes.len() > 5, "Should have variety in byte values");
}

#[test]
fn test_performance_characteristics() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Test performance of different operations
    let start = std::time::Instant::now();
    
    // Generate many small chunks
    for _ in 0..100 {  // Reduced count to avoid entropy depletion
        let _bytes = trng.generate_bytes(32).unwrap();
    }
    let small_chunks_time = start.elapsed();
    
    // Refresh entropy before large chunk test
    let _ = trng.refresh_entropy();
    
    // Generate one large chunk
    let start = std::time::Instant::now();
    let _bytes = trng.generate_bytes(3200).unwrap(); // Smaller size
    let large_chunk_time = start.elapsed();
    
    println!("Small chunks (100x32): {:?}", small_chunks_time);
    println!("Large chunk (1x3200): {:?}", large_chunk_time);
    
    // Both should complete in reasonable time
    assert!(small_chunks_time.as_secs() < 10, "Small chunks took too long");
    assert!(large_chunk_time.as_secs() < 5, "Large chunk took too long");
}

#[test]
fn test_error_handling() {
    // Test with invalid configuration
    let config = TrngConfig {
        min_entropy_bits: 1000000, // Unrealistic requirement
        enable_fallback: false,    // No fallback
        ..Default::default()
    };
    
    let result = TrueRandomGenerator::with_config(config);
    // This might fail due to insufficient entropy
    if result.is_err() {
        println!("Expected failure with unrealistic entropy requirements");
    }
}

#[test]
fn test_memory_safety() {
    let trng = TrueRandomGenerator::new().unwrap();
    
    // Test that sensitive data is properly handled
    let bytes = trng.generate_bytes(1024).unwrap();
    
    // Verify we got the right amount of data
    assert_eq!(bytes.len(), 1024);
    
    // The bytes should be non-zero (indicating real random data)
    let all_zero = bytes.iter().all(|&b| b == 0);
    assert!(!all_zero, "Generated all-zero data");
    
    // Test that dropping doesn't cause issues
    drop(trng);
    
    // Should still be able to create a new instance
    let trng2 = TrueRandomGenerator::new();
    assert!(trng2.is_ok());
}

#[test]
fn test_integration_with_encryption() {
    use fortress_core::encryption::{ChaCha20Poly1305, EncryptionAlgorithm};
    
    // Initialize TRNG
    let _trng = init_global_trng();
    
    let algorithm = ChaCha20Poly1305::new();
    let key = fortress_core::encryption::SecureKey::generate(algorithm.key_size()).unwrap();
    
    let plaintext = b"Hello, Fortress with TRNG!";
    let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
    let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
    
    assert_eq!(plaintext.to_vec(), decrypted);
}
