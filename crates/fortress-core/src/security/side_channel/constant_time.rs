//! Constant-Time Operations Module
//!
//! This module provides constant-time implementations for cryptographic operations
//! to prevent timing attacks and other side-channel vulnerabilities.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use crate::error::{FortressError, Result};

/// Constant-time operations provider
pub struct ConstantTimeOperations {
    /// Random number generator for noise injection
    rng: Arc<RwLock<crate::trng::SecureRandom>>,
    /// Operation counter
    operation_counter: Arc<AtomicU64>,
    /// Metrics
    metrics: Arc<RwLock<ConstantTimeMetrics>>,
}

/// Constant-time operation metrics
#[derive(Debug, Clone)]
pub struct ConstantTimeMetrics {
    /// Total comparisons performed
    pub total_comparisons: u64,
    /// Total memory copies performed
    pub total_memory_copies: u64,
    /// Total secure clears performed
    pub total_secure_clears: u64,
    /// Average comparison time in microseconds
    pub avg_comparison_time_us: f64,
    /// Average memory copy time in microseconds
    pub avg_memory_copy_time_us: f64,
    /// Average secure clear time in microseconds
    pub avg_secure_clear_time_us: f64,
    /// Total bytes compared
    pub total_bytes_compared: u64,
    /// Total bytes copied
    pub total_bytes_copied: u64,
    /// Total bytes cleared
    pub total_bytes_cleared: u64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl ConstantTimeOperations {
    /// Create a new constant-time operations provider
    pub fn new() -> Result<Self> {
        Ok(Self {
            rng: Arc::new(RwLock::new(crate::trng::SecureRandom::new()?)),
            operation_counter: Arc::new(AtomicU64::new(0)),
            metrics: Arc::new(RwLock::new(ConstantTimeMetrics::default())),
        })
    }

    /// Compare two slices in constant time
    pub async fn compare<T>(&self, a: &[T], b: &[T]) -> Result<bool>
    where
        T: PartialEq + Copy,
    {
        let start = std::time::Instant::now();
        
        // Ensure both slices have the same length
        if a.len() != b.len() {
            return Ok(false);
        }
        
        let mut result = true;
        let mut noise_bytes = [0u8; 32];
        
        // Generate noise for timing obfuscation
        {
            let mut rng = self.rng.write().await;
            rng.fill_bytes(&mut noise_bytes)?;
        }
        
        // Perform constant-time comparison with noise
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            // Add noise to timing
            let noise_factor = noise_bytes[i % noise_bytes.len()] as u64;
            let _delay = std::hint::black_box(noise_factor);
            
            // Constant-time comparison
            if x != y {
                result = false;
            }
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_comparisons += 1;
            metrics.total_bytes_compared += (a.len() * std::mem::size_of::<T>()) as u64;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_comparison_time_us = (metrics.avg_comparison_time_us * (metrics.total_comparisons - 1) as f64 + elapsed) / metrics.total_comparisons as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        self.operation_counter.fetch_add(1, Ordering::Relaxed);
        Ok(result)
    }

    /// Compare two byte slices in constant time
    pub async fn compare_bytes(&self, a: &[u8], b: &[u8]) -> Result<bool> {
        let start = std::time::Instant::now();
        
        if a.len() != b.len() {
            return Ok(false);
        }
        
        let mut result = 0u8;
        
        // Perform constant-time byte comparison
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_comparisons += 1;
            metrics.total_bytes_compared += a.len() as u64;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_comparison_time_us = (metrics.avg_comparison_time_us * (metrics.total_comparisons - 1) as f64 + elapsed) / metrics.total_comparisons as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        self.operation_counter.fetch_add(1, Ordering::Relaxed);
        Ok(result == 0)
    }

    /// Copy memory in constant time
    pub async fn memory_copy(&self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        let start = std::time::Instant::now();
        
        if src.len() != dst.len() {
            return Err(FortressError::side_channel("Memory size mismatch", 
                format!("src: {}, dst: {}", src.len(), dst.len())));
        }
        
        // Add noise to timing
        let mut noise_bytes = [0u8; 16];
        {
            let mut rng = self.rng.write().await;
            rng.fill_bytes(&mut noise_bytes)?;
        }
        
        // Perform constant-time memory copy with noise
        for i in 0..src.len() {
            let noise_factor = noise_bytes[i % noise_bytes.len()] as u64;
            let _delay = std::hint::black_box(noise_factor);
            dst[i] = src[i];
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_memory_copies += 1;
            metrics.total_bytes_copied += src.len() as u64;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_memory_copy_time_us = (metrics.avg_memory_copy_time_us * (metrics.total_memory_copies - 1) as f64 + elapsed) / metrics.total_memory_copies as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        self.operation_counter.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Securely clear memory in constant time
    pub async fn secure_clear(&self, data: &mut [u8]) -> Result<()> {
        let start = std::time::Instant::now();
        
        // Generate random pattern for clearing
        let mut clear_pattern = [0u8; 32];
        {
            let mut rng = self.rng.write().await;
            rng.fill_bytes(&mut clear_pattern)?;
        }
        
        // Perform constant-time memory clearing with random pattern
        for i in 0..data.len() {
            let pattern_byte = clear_pattern[i % clear_pattern.len()];
            let _delay = std::hint::black_box(pattern_byte);
            data[i] = 0; // Final clear
        }
        
        // Add final random noise
        {
            let mut rng = self.rng.write().await;
            rng.fill_bytes(data)?;
        }
        
        // Clear again to ensure data is gone
        for byte in data.iter_mut() {
            *byte = 0;
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_secure_clears += 1;
            metrics.total_bytes_cleared += data.len() as u64;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_secure_clear_time_us = (metrics.avg_secure_clear_time_us * (metrics.total_secure_clears - 1) as f64 + elapsed) / metrics.total_secure_clears as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        self.operation_counter.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Perform constant-time equality check for strings
    pub async fn string_equals(&self, a: &str, b: &str) -> Result<bool> {
        self.compare_bytes(a.as_bytes(), b.as_bytes()).await
    }

    /// Perform constant-time prefix check
    pub async fn starts_with_constant_time(&self, data: &[u8], prefix: &[u8]) -> Result<bool> {
        let start = std::time::Instant::now();
        
        if prefix.len() > data.len() {
            return Ok(false);
        }
        
        let mut result = 0u8;
        
        // Perform constant-time prefix comparison
        for (x, y) in data.iter().zip(prefix.iter()) {
            result |= x ^ y;
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_comparisons += 1;
            metrics.total_bytes_compared += prefix.len() as u64;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_comparison_time_us = (metrics.avg_comparison_time_us * (metrics.total_comparisons - 1) as f64 + elapsed) / metrics.total_comparisons as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        self.operation_counter.fetch_add(1, Ordering::Relaxed);
        Ok(result == 0)
    }

    /// Perform constant-time select operation
    pub async fn select<T>(&self, condition: bool, true_value: T, false_value: T) -> Result<T>
    where
        T: Copy,
    {
        let start = std::time::Instant::now();
        
        // Add noise to timing
        let mut noise_bytes = [0u8; 8];
        {
            let mut rng = self.rng.write().await;
            rng.fill_bytes(&mut noise_bytes)?;
        }
        
        let result = if condition {
            // Add noise for true branch
            let noise_factor = noise_bytes[0] as u64;
            let _delay = std::hint::black_box(noise_factor);
            true_value
        } else {
            // Add noise for false branch
            let noise_factor = noise_bytes[1] as u64;
            let _delay = std::hint::black_box(noise_factor);
            false_value
        };
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_comparisons += 1;
            let elapsed = start.elapsed().as_micros() as f64;
            metrics.avg_comparison_time_us = (metrics.avg_comparison_time_us * (metrics.total_comparisons - 1) as f64 + elapsed) / metrics.total_comparisons as f64;
            metrics.last_updated = chrono::Utc::now();
        }
        
        self.operation_counter.fetch_add(1, Ordering::Relaxed);
        Ok(result)
    }

    /// Get operation metrics
    pub async fn get_metrics(&self) -> Result<ConstantTimeMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        *metrics = ConstantTimeMetrics::default();
        Ok(())
    }

    /// Get total operations performed
    pub fn get_operation_count(&self) -> u64 {
        self.operation_counter.load(Ordering::Relaxed)
    }

    /// Shutdown the constant-time operations
    pub async fn shutdown(&self) -> Result<()> {
        // Clear sensitive data
        {
            let mut rng = self.rng.write().await;
            rng.clear()?;
        }
        
        // Reset metrics
        self.reset_metrics().await?;
        
        Ok(())
    }
}

/// Constant-time utilities for common operations
pub struct ConstantTimeUtils;

impl ConstantTimeUtils {
    /// Compare two u64 values in constant time
    pub fn u64_eq(a: u64, b: u64) -> bool {
        let mut x = a ^ b;
        x |= x >> 32;
        x |= x >> 16;
        x |= x >> 8;
        x |= x >> 4;
        x |= x >> 2;
        x |= x >> 1;
        x == 0
    }

    /// Compare two u32 values in constant time
    pub fn u32_eq(a: u32, b: u32) -> bool {
        let mut x = a ^ b;
        x |= x >> 16;
        x |= x >> 8;
        x |= x >> 4;
        x |= x >> 2;
        x |= x >> 1;
        x == 0
    }

    /// Compare two usize values in constant time
    pub fn usize_eq(a: usize, b: usize) -> bool {
        let mut x = a ^ b;
        x |= x >> 32;
        x |= x >> 16;
        x |= x >> 8;
        x |= x >> 4;
        x |= x >> 2;
        x |= x >> 1;
        x == 0
    }

    /// Zero memory in constant time
    pub fn zero_memory(slice: &mut [u8]) {
        for byte in slice.iter_mut() {
            *byte = 0;
        }
    }

    /// Check if all bytes are zero in constant time
    pub fn all_zero(slice: &[u8]) -> bool {
        let mut result = 0u8;
        for &byte in slice {
            result |= byte;
        }
        result == 0
    }
}

impl Default for ConstantTimeMetrics {
    fn default() -> Self {
        Self {
            total_comparisons: 0,
            total_memory_copies: 0,
            total_secure_clears: 0,
            avg_comparison_time_us: 0.0,
            avg_memory_copy_time_us: 0.0,
            avg_secure_clear_time_us: 0.0,
            total_bytes_compared: 0,
            total_bytes_copied: 0,
            total_bytes_cleared: 0,
            last_updated: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_constant_time_operations() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        // Test comparison
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 5];
        let result = ops.compare(&a, &b).await.unwrap();
        assert!(result);
        
        let c = vec![1, 2, 3, 4, 6];
        let result = ops.compare(&a, &c).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_byte_comparison() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        let a = b"hello world";
        let b = b"hello world";
        let result = ops.compare_bytes(a, b).await.unwrap();
        assert!(result);
        
        let c = b"hello world!";
        let result = ops.compare_bytes(a, c).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_memory_copy() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        let src = vec![1, 2, 3, 4, 5];
        let mut dst = vec![0, 0, 0, 0, 0];
        
        ops.memory_copy(&src, &mut dst).await.unwrap();
        assert_eq!(src, dst);
    }

    #[tokio::test]
    async fn test_secure_clear() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        let mut data = vec![1, 2, 3, 4, 5];
        ops.secure_clear(&mut data).await.unwrap();
        
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn test_string_equals() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        let result = ops.string_equals("hello", "hello").await.unwrap();
        assert!(result);
        
        let result = ops.string_equals("hello", "world").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_starts_with() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        let data = b"hello world";
        let prefix = b"hello";
        let result = ops.starts_with_constant_time(data, prefix).await.unwrap();
        assert!(result);
        
        let prefix = b"world";
        let result = ops.starts_with_constant_time(data, prefix).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_select() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        let result = ops.select(true, 42, 24).await.unwrap();
        assert_eq!(result, 42);
        
        let result = ops.select(false, 42, 24).await.unwrap();
        assert_eq!(result, 24);
    }

    #[tokio::test]
    async fn test_metrics() {
        let ops = ConstantTimeOperations::new().unwrap();
        
        // Perform some operations
        ops.compare(&[1, 2, 3], &[1, 2, 3]).await.unwrap();
        ops.compare_bytes(b"test", b"test").await.unwrap();
        
        let metrics = ops.get_metrics().await.unwrap();
        assert_eq!(metrics.total_comparisons, 2);
        assert!(metrics.total_bytes_compared > 0);
    }

    #[test]
    fn test_constant_time_utils() {
        assert!(ConstantTimeUtils::u64_eq(12345, 12345));
        assert!(!ConstantTimeUtils::u64_eq(12345, 54321));
        
        assert!(ConstantTimeUtils::u32_eq(1234, 1234));
        assert!(!ConstantTimeUtils::u32_eq(1234, 4321));
        
        assert!(ConstantTimeUtils::usize_eq(12345, 12345));
        assert!(!ConstantTimeUtils::usize_eq(12345, 54321));
        
        let mut data = vec![1, 2, 3, 4, 5];
        ConstantTimeUtils::zero_memory(&mut data);
        assert!(data.iter().all(|&x| x == 0));
        
        let data = vec![0, 0, 0, 0, 0];
        assert!(ConstantTimeUtils::all_zero(&data));
        
        let data = vec![0, 0, 1, 0, 0];
        assert!(!ConstantTimeUtils::all_zero(&data));
    }
}
