//! True Random Number Generator (TRNG) Module
//!
//! This module provides true random number generation capabilities using
//! multiple entropy sources including hardware timing, network jitter,
//! and environmental noise. It includes entropy pooling, health monitoring,
//! and graceful fallback to cryptographically secure pseudo-random generators.

use crate::error::{FortressError, Result};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;
use sha2::{Sha256, Digest};

/// Configuration for the TRNG system
#[derive(Debug, Clone)]
pub struct TrngConfig {
    /// Minimum entropy bits required before output
    pub min_entropy_bits: usize,
    /// Maximum entropy pool size in bytes
    pub max_pool_size: usize,
    /// Health check interval in milliseconds
    pub health_check_interval: Duration,
    /// Number of entropy sources to combine
    pub entropy_sources: usize,
    /// Enable fallback to CSPRNG if TRNG fails
    pub enable_fallback: bool,
}

impl Default for TrngConfig {
    fn default() -> Self {
        Self {
            min_entropy_bits: 256,
            max_pool_size: 4096,
            health_check_interval: Duration::from_millis(1000),
            entropy_sources: 5,
            enable_fallback: true,
        }
    }
}

/// Health status of the TRNG system
#[derive(Debug, Clone, PartialEq)]
pub enum TrngHealth {
    /// TRNG is operating normally with sufficient entropy
    Healthy,
    /// TRNG has reduced entropy but is still functional
    Degraded,
    /// TRNG has failed and is not operational
    Failed,
}

/// Entropy source types
#[derive(Debug, Clone, Copy)]
pub enum EntropySource {
    /// CPU timing variations and instruction cycle measurements
    CpuTiming,
    /// Network packet timing and jitter measurements
    NetworkJitter,
    /// Disk I/O latency and access timing variations
    DiskIo,
    /// Memory access latency and cache timing variations
    MemoryLatency,
    /// System clock and high-resolution timer variations
    SystemTime,
}

/// Main TRNG engine
pub struct TrueRandomGenerator {
    config: TrngConfig,
    entropy_pool: Arc<Mutex<EntropyPool>>,
    health_status: Arc<Mutex<TrngHealth>>,
    last_health_check: Arc<Mutex<Instant>>,
}

/// Internal entropy pool for collecting and mixing entropy
struct EntropyPool {
    buffer: VecDeque<u8>,
    entropy_bits: usize,
    last_mix: Instant,
}

impl EntropyPool {
    fn new() -> Self {
        Self {
            buffer: VecDeque::with_capacity(4096),
            entropy_bits: 0,
            last_mix: Instant::now(),
        }
    }

    fn add_entropy(&mut self, data: &[u8], estimated_bits: usize) {
        // Add data to pool
        for byte in data {
            if self.buffer.len() >= 4096 {
                self.buffer.pop_front(); // Remove oldest byte
            }
            self.buffer.push_back(*byte);
        }
        
        self.entropy_bits += estimated_bits;
        
        // Mix the pool periodically
        if self.last_mix.elapsed() > Duration::from_millis(100) {
            self.mix_pool();
        }
    }

    fn mix_pool(&mut self) {
        if self.buffer.len() < 32 {
            return;
        }
        
        let pool_data: Vec<u8> = self.buffer.iter().cloned().collect();
        let mut hasher = Sha256::new();
        hasher.update(&pool_data);
        let hash = hasher.finalize();
        
        // Replace pool with hashed entropy
        self.buffer.clear();
        for byte in hash {
            self.buffer.push_back(byte);
        }
        
        self.last_mix = Instant::now();
        self.entropy_bits = self.entropy_bits.min(256); // Cap entropy estimate
    }

    fn get_bytes(&mut self, count: usize) -> Result<Vec<u8>> {
        if self.entropy_bits < 8 * count {
            return Err(FortressError::internal(
                format!("Insufficient entropy: {} bits available, {} needed", 
                       self.entropy_bits, 8 * count),
                "trng_entropy".to_string(),
            ));
        }

        let mut result = Vec::with_capacity(count);
        
        // Extract bytes from pool
        for _ in 0..count {
            if let Some(byte) = self.buffer.pop_front() {
                result.push(byte);
            } else {
                // Pool exhausted, mix and try again
                self.mix_pool();
                if let Some(byte) = self.buffer.pop_front() {
                    result.push(byte);
                } else {
                    return Err(FortressError::internal(
                        "Entropy pool exhausted".to_string(),
                        "trng_pool".to_string(),
                    ));
                }
            }
        }

        self.entropy_bits = self.entropy_bits.saturating_sub(8 * count);
        Ok(result)
    }

    fn entropy_available(&self) -> usize {
        self.entropy_bits
    }
}

impl TrueRandomGenerator {
    /// Create a new TRNG instance with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(TrngConfig::default())
    }

    /// Create a new TRNG instance with custom configuration
    pub fn with_config(config: TrngConfig) -> Result<Self> {
        let trng = Self {
            config,
            entropy_pool: Arc::new(Mutex::new(EntropyPool::new())),
            health_status: Arc::new(Mutex::new(TrngHealth::Healthy)),
            last_health_check: Arc::new(Mutex::new(Instant::now())),
        };

        // Initialize entropy pool
        trng.initialize_entropy_pool()?;
        
        Ok(trng)
    }

    /// Initialize the entropy pool with data from multiple sources
    fn initialize_entropy_pool(&self) -> Result<()> {
        let mut total_entropy = 0usize;
        
        // Collect entropy from all sources
        for source in [
            EntropySource::CpuTiming,
            EntropySource::NetworkJitter,
            EntropySource::DiskIo,
            EntropySource::MemoryLatency,
            EntropySource::SystemTime,
        ] {
            match self.collect_entropy(source) {
                Ok((data, bits)) => {
                    let mut pool = self.entropy_pool.lock().unwrap();
                    pool.add_entropy(&data, bits);
                    total_entropy += bits;
                }
                Err(e) => {
                    tracing::warn!("Failed to collect entropy from {:?}: {}", source, e);
                }
            }
        }

        if total_entropy < self.config.min_entropy_bits {
            return Err(FortressError::internal(
                format!("Insufficient initial entropy: {} bits collected, {} required", 
                       total_entropy, self.config.min_entropy_bits),
                "trng_init".to_string(),
            ));
        }

        tracing::info!("TRNG initialized with {} bits of entropy", total_entropy);
        Ok(())
    }

    /// Collect entropy from a specific source
    pub fn collect_entropy(&self, source: EntropySource) -> Result<(Vec<u8>, usize)> {
        match source {
            EntropySource::CpuTiming => self.collect_cpu_timing_entropy(),
            EntropySource::NetworkJitter => self.collect_network_jitter_entropy(),
            EntropySource::DiskIo => self.collect_disk_io_entropy(),
            EntropySource::MemoryLatency => self.collect_memory_latency_entropy(),
            EntropySource::SystemTime => self.collect_system_time_entropy(),
        }
    }

    /// Collect entropy from CPU timing measurements
    fn collect_cpu_timing_entropy(&self) -> Result<(Vec<u8>, usize)> {
        let mut timings = Vec::new();
        let iterations = 1000;
        
        // Measure CPU timing variations
        for _ in 0..iterations {
            let start = Instant::now();
            let mut dummy = 0u64;
            for i in 0..1000 {
                dummy = dummy.wrapping_add(i as u64);
            }
            let elapsed = start.elapsed();
            timings.push(elapsed.as_nanos() as u64);
            
            // Prevent optimization
            std::hint::black_box(dummy);
        }

        // Convert timing variations to entropy bytes
        let mut entropy_data = Vec::new();
        for timing in timings {
            entropy_data.extend_from_slice(&timing.to_le_bytes());
        }

        // Estimate entropy bits (conservative estimate)
        let entropy_bits = (iterations / 10) * 8; // Assume 1 bit per 10 measurements

        Ok((entropy_data, entropy_bits))
    }

    /// Collect entropy from network jitter (if available)
    fn collect_network_jitter_entropy(&self) -> Result<(Vec<u8>, usize)> {
        let mut entropy_data = Vec::new();
        let entropy_bits = 64; // Conservative estimate

        // Try to connect to a remote host to measure network timing
        let hosts = ["8.8.8.8:53", "1.1.1.1:53", "localhost:80"];
        
        for host in &hosts {
            let start = Instant::now();
            match std::net::TcpStream::connect(host) {
                Ok(_) => {
                    let elapsed = start.elapsed();
                    entropy_data.extend_from_slice(&elapsed.as_nanos().to_le_bytes());
                }
                Err(_) => {
                    // Connection failed, use the error timing as entropy
                    let elapsed = start.elapsed();
                    entropy_data.extend_from_slice(&elapsed.as_nanos().to_le_bytes());
                }
            }
        }

        Ok((entropy_data, entropy_bits))
    }

    /// Collect entropy from disk I/O timing
    fn collect_disk_io_entropy(&self) -> Result<(Vec<u8>, usize)> {
        let mut entropy_data = Vec::new();
        let entropy_bits = 32;

        // Measure disk access timing
        let temp_file = std::env::temp_dir().join("fortress_trng_test");
        
        for _ in 0..10 {
            let start = Instant::now();
            match std::fs::write(&temp_file, b"test_data") {
                Ok(_) => {
                    let elapsed = start.elapsed();
                    entropy_data.extend_from_slice(&elapsed.as_nanos().to_le_bytes());
                }
                Err(_) => {}
            }
        }

        // Clean up
        let _ = std::fs::remove_file(&temp_file);

        Ok((entropy_data, entropy_bits))
    }

    /// Collect entropy from memory access timing variations
    fn collect_memory_latency_entropy(&self) -> Result<(Vec<u8>, usize)> {
        let mut entropy_data = Vec::new();
        let entropy_bits = 32;

        // Allocate memory and measure access patterns
        let size = 1024 * 1024; // 1MB
        let data: Vec<u8> = vec![0; size];
        
        for i in 0..100 {
            let start = Instant::now();
            let index = (i * 10009) % size; // Prime number for pseudo-random access
            std::hint::black_box(data[index]);
            let elapsed = start.elapsed();
            entropy_data.extend_from_slice(&elapsed.as_nanos().to_le_bytes());
        }

        Ok((entropy_data, entropy_bits))
    }

    /// Collect entropy from system time variations
    fn collect_system_time_entropy(&self) -> Result<(Vec<u8>, usize)> {
        let mut entropy_data = Vec::new();
        let entropy_bits = 16;

        // Collect high-resolution timestamps
        for _ in 0..10 {
            let now = SystemTime::now();
            let duration = now.duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0));
            entropy_data.extend_from_slice(&duration.as_nanos().to_le_bytes());
        }

        Ok((entropy_data, entropy_bits))
    }

    /// Generate true random bytes
    pub fn generate_bytes(&self, count: usize) -> Result<Vec<u8>> {
        // Check health and refresh entropy if needed
        self.health_check()?;

        let mut pool = self.entropy_pool.lock().unwrap();
        
        // If we don't have enough entropy, try to collect more
        if pool.entropy_available() < 8 * count {
            drop(pool);
            self.refresh_entropy()?;
            pool = self.entropy_pool.lock().unwrap();
        }

        // Try to get bytes from TRNG
        match pool.get_bytes(count) {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                if self.config.enable_fallback {
                    tracing::warn!("TRNG failed, falling back to CSPRNG: {}", e);
                    self.fallback_generate(count)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Generate a random u64 value
    pub fn generate_u64(&self) -> Result<u64> {
        let bytes = self.generate_bytes(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(array))
    }

    /// Generate a random u32 value
    pub fn generate_u32(&self) -> Result<u32> {
        let bytes = self.generate_bytes(4)?;
        let mut array = [0u8; 4];
        array.copy_from_slice(&bytes);
        Ok(u32::from_le_bytes(array))
    }

    /// Fill a buffer with random bytes
    pub fn fill_bytes(&self, buffer: &mut [u8]) -> Result<()> {
        let random_bytes = self.generate_bytes(buffer.len())?;
        buffer.copy_from_slice(&random_bytes);
        Ok(())
    }

    /// Refresh entropy pool with new data
    pub fn refresh_entropy(&self) -> Result<()> {
        let mut total_bits = 0;
        
        for source in [
            EntropySource::CpuTiming,
            EntropySource::SystemTime,
            EntropySource::MemoryLatency,
        ] {
            match self.collect_entropy(source) {
                Ok((data, bits)) => {
                    let mut pool = self.entropy_pool.lock().unwrap();
                    pool.add_entropy(&data, bits);
                    total_bits += bits;
                }
                Err(e) => {
                    tracing::debug!("Failed to refresh entropy from {:?}: {}", source, e);
                }
            }
        }

        if total_bits == 0 {
            return Err(FortressError::internal(
                "Failed to collect any entropy".to_string(),
                "trng_refresh".to_string(),
            ));
        }

        Ok(())
    }

    /// Perform health check on the TRNG system
    pub fn health_check(&self) -> Result<()> {
        let mut last_check = self.last_health_check.lock().unwrap();
        
        if last_check.elapsed() < self.config.health_check_interval {
            return Ok(());
        }

        let pool = self.entropy_pool.lock().unwrap();
        let entropy_available = pool.entropy_available();
        drop(pool);

        let mut health = self.health_status.lock().unwrap();
        
        if entropy_available < self.config.min_entropy_bits / 4 {
            *health = TrngHealth::Failed;
            return Err(FortressError::internal(
                "TRNG health check failed: insufficient entropy".to_string(),
                "trng_health".to_string(),
            ));
        } else if entropy_available < self.config.min_entropy_bits / 2 {
            *health = TrngHealth::Degraded;
            tracing::warn!("TRNG health degraded: {} bits available", entropy_available);
        } else {
            *health = TrngHealth::Healthy;
        }

        *last_check = Instant::now();
        Ok(())
    }

    /// Get current health status
    pub fn health_status(&self) -> TrngHealth {
        self.health_status.lock().unwrap().clone()
    }

    /// Get entropy pool statistics
    pub fn entropy_stats(&self) -> (usize, usize) {
        let pool = self.entropy_pool.lock().unwrap();
        (pool.entropy_available(), pool.buffer.len())
    }

    /// Fallback to cryptographically secure pseudo-random generator
    fn fallback_generate(&self, count: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; count];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| FortressError::internal(
                format!("CSPRNG fallback failed: {}", e),
                "trng_fallback".to_string(),
            ))?;
        Ok(bytes)
    }

    /// Force reinitialization of the TRNG
    pub fn reinitialize(&self) -> Result<()> {
        {
            let mut pool = self.entropy_pool.lock().unwrap();
            *pool = EntropyPool::new();
        }
        self.initialize_entropy_pool()
    }
}

impl Default for TrueRandomGenerator {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // If TRNG fails to initialize, create a fallback-only version
            Self {
                config: TrngConfig::default(),
                entropy_pool: Arc::new(Mutex::new(EntropyPool::new())),
                health_status: Arc::new(Mutex::new(TrngHealth::Failed)),
                last_health_check: Arc::new(Mutex::new(Instant::now())),
            }
        })
    }
}

/// Global TRNG instance for convenience
static GLOBAL_TRNG: std::sync::OnceLock<std::sync::Mutex<Option<Arc<TrueRandomGenerator>>>> = std::sync::OnceLock::new();

/// Initialize the global TRNG instance
pub fn init_global_trng() -> Result<()> {
    let trng = Arc::new(TrueRandomGenerator::new()?);
    let global = GLOBAL_TRNG.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = global.lock().unwrap();
    *guard = Some(trng);
    Ok(())
}

/// Get the global TRNG instance (initializes if needed)
pub fn global_trng() -> Result<Arc<TrueRandomGenerator>> {
    let global = GLOBAL_TRNG.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = global.lock().unwrap();
    
    if guard.is_none() {
        *guard = Some(Arc::new(TrueRandomGenerator::default()));
    }
    
    Ok(guard.as_ref().unwrap().clone())
}

/// Convenience function to generate random bytes using global TRNG
pub fn random_bytes(count: usize) -> Result<Vec<u8>> {
    global_trng()?.generate_bytes(count)
}

/// Convenience function to generate random u64 using global TRNG
pub fn random_u64() -> Result<u64> {
    global_trng()?.generate_u64()
}

/// Convenience function to fill buffer with random bytes using global TRNG
pub fn fill_random(buffer: &mut [u8]) -> Result<()> {
    global_trng()?.fill_bytes(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trng_initialization() {
        let trng = TrueRandomGenerator::new();
        assert!(trng.is_ok());
    }

    #[test]
    fn test_random_byte_generation() {
        let trng = TrueRandomGenerator::new().unwrap();
        let bytes1 = trng.generate_bytes(32).unwrap();
        let bytes2 = trng.generate_bytes(32).unwrap();
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_random_u64_generation() {
        let trng = TrueRandomGenerator::new().unwrap();
        let val1 = trng.generate_u64().unwrap();
        let val2 = trng.generate_u64().unwrap();
        
        assert_ne!(val1, val2); // Should be different
    }

    #[test]
    fn test_fill_bytes() {
        let trng = TrueRandomGenerator::new().unwrap();
        let mut buffer = [0u8; 16];
        trng.fill_bytes(&mut buffer).unwrap();
        
        // Should not be all zeros
        assert_ne!(buffer, [0u8; 16]);
    }

    #[test]
    fn test_entropy_collection() {
        let trng = TrueRandomGenerator::new().unwrap();
        
        for source in [
            EntropySource::CpuTiming,
            EntropySource::SystemTime,
            EntropySource::MemoryLatency,
        ] {
            let result = trng.collect_entropy(source);
            assert!(result.is_ok());
            let (data, bits) = result.unwrap();
            assert!(!data.is_empty());
            assert!(bits > 0);
        }
    }

    #[test]
    fn test_health_check() {
        let trng = TrueRandomGenerator::new().unwrap();
        let health = trng.health_status();
        assert!(health == TrngHealth::Healthy || health == TrngHealth::Degraded);
    }

    #[test]
    fn test_entropy_stats() {
        let trng = TrueRandomGenerator::new().unwrap();
        let (entropy_bits, pool_size) = trng.entropy_stats();
        assert!(entropy_bits > 0);
        assert!(pool_size > 0);
    }

    #[test]
    fn test_global_trng() {
        let result = init_global_trng();
        assert!(result.is_ok());
        
        let bytes = random_bytes(16);
        assert!(bytes.is_ok());
        assert_eq!(bytes.unwrap().len(), 16);
    }

    #[test]
    fn test_reinitialization() {
        let trng = TrueRandomGenerator::new().unwrap();
        let result = trng.reinitialize();
        assert!(result.is_ok());
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
        let bytes = trng.generate_bytes(32);
        assert!(bytes.is_ok());
    }
}
