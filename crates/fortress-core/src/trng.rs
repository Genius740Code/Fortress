//! True Random Number Generator (TRNG) Module
//!
//! This module provides true random number generation capabilities using
//! multiple entropy sources including hardware timing, network jitter,
//! and environmental noise. It includes entropy pooling, health monitoring,
//! and graceful fallback to cryptographically secure pseudo-random generators.

use crate::error::{FortressError, Result};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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

/// Circular buffer for efficient entropy management
struct CircularBuffer {
    buffer: [u8; 4096],
    head: usize,
    size: usize,
}

impl CircularBuffer {
    fn new() -> Self {
        Self {
            buffer: [0u8; 4096],
            head: 0,
            size: 0,
        }
    }

    fn add_entropy(&mut self, data: &[u8]) {
        for &byte in data {
            self.buffer[self.head] = byte;
            self.head = (self.head + 1) % 4096;
            if self.size < 4096 {
                self.size += 1;
            }
        }
    }

    fn len(&self) -> usize {
        self.size
    }

    fn as_vec(&self) -> Vec<u8> {
        if self.size == 0 {
            return Vec::new();
        }

        let mut result = Vec::with_capacity(self.size);
        let start_pos = if self.size < 4096 { 0 } else { self.head };
        
        for i in 0..self.size {
            let pos = (start_pos + i) % 4096;
            result.push(self.buffer[pos]);
        }
        
        result
    }

    fn pop_front(&mut self) -> Option<u8> {
        if self.size == 0 {
            return None;
        }

        let tail_pos = (self.head + 4096 - self.size) % 4096;
        let byte = self.buffer[tail_pos];
        self.size -= 1;

        Some(byte)
    }
}

/// Internal entropy pool for collecting and mixing entropy
struct EntropyPool {
    buffer: CircularBuffer,
    entropy_bits: usize,
    last_mix: Instant,
}

impl EntropyPool {
    fn new() -> Self {
        Self {
            buffer: CircularBuffer::new(),
            entropy_bits: 0,
            last_mix: Instant::now(),
        }
    }

    fn add_entropy(&mut self, data: &[u8], estimated_bits: usize) {
        // Add data to pool using efficient circular buffer
        self.buffer.add_entropy(data);
        
        self.entropy_bits += estimated_bits;
        
        // Mix the pool periodically
        if self.last_mix.elapsed() > Duration::from_millis(100) {
            if let Err(e) = self.mix_pool() {
                tracing::warn!("Failed to mix entropy pool: {}", e);
            }
        }
    }

    fn mix_pool(&mut self) -> Result<()> {
        if self.buffer.len() < 32 {
            return Ok(());
        }
        
        let pool_data = self.buffer.as_vec();
        let original_len = self.buffer.len();
        let mut hasher = Sha256::new();
        
        // Multiple hash rounds for better mixing
        for round in 0..3 {
            hasher.update(&pool_data);
            
            // Add round-specific entropy
            let round_data = [
                (round as u8).wrapping_mul(0x9b),
                (original_len % 256) as u8,
                self.entropy_bits as u8,
                (self.last_mix.elapsed().as_nanos() as u64 % 256) as u8,
            ];
            hasher.update(&round_data);
        }
        
        let hash = hasher.finalize();
        
        // Replace pool with hashed entropy with enhanced mixing
        let mut new_buffer = CircularBuffer::new();
        for (i, &byte) in hash.iter().enumerate() {
            // Enhanced mixing with multiple entropy sources
            let mixed_byte = byte
                .wrapping_add(i as u8)
                .wrapping_add((original_len % 256) as u8)
                .wrapping_add(self.entropy_bits as u8)
                .wrapping_add((hash.len() % 256) as u8)
                .wrapping_mul((i + 1) as u8)
                ^ (i.wrapping_mul(0x9e3779b9) % 256) as u8;
            new_buffer.add_entropy(&[mixed_byte]);
        }
        
        // Add additional entropy from system state
        let time_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| FortressError::internal(
                "System time went backwards",
                "trng_system_time",
            ))?;
        
        let system_entropy = [
            (time_now.as_nanos() as u64 % 256) as u8,
            (std::process::id() as u64 % 256) as u8,
            (self.buffer.len() % 256) as u8,
        ];
        
        for &byte in &system_entropy {
            new_buffer.add_entropy(&[byte.wrapping_add(self.entropy_bits as u8)]);
        }
        
        // Replace the old buffer with the new mixed buffer
        self.buffer = new_buffer;
        self.last_mix = Instant::now();
        self.entropy_bits = self.entropy_bits.min(256); // Cap entropy estimate
        Ok(())
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
                if let Err(e) = self.mix_pool() {
                    return Err(FortressError::internal(
                        format!("Failed to mix entropy pool: {}", e),
                        "trng_pool_mix".to_string(),
                    ));
                }
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
                    let mut pool = self.entropy_pool.lock().map_err(|_| {
                        FortressError::internal(
                            "Failed to acquire entropy pool lock",
                            "trng_lock",
                        )
                    })?;
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
        
        // Measure CPU timing variations with more entropy sources
        for i in 0..iterations {
            let start = Instant::now();
            let mut dummy = 0u64;
            
            // Variable loop iterations based on i to add more variation
            let loop_size = 1000 + (i % 500);
            for j in 0u32..loop_size as u32 {
                dummy = dummy.wrapping_add(j as u64);
                dummy = dummy.wrapping_mul((i + 1) as u64);
                dummy = dummy ^ (j.wrapping_mul(i) as u64);
            }
            
            let elapsed = start.elapsed();
            timings.push(elapsed.as_nanos() as u64);
            
            // Add memory access timing variation
            let mem_start = Instant::now();
            let data: Vec<u8> = vec![i as u8; 1024];
            std::hint::black_box(data.len());
            let mem_elapsed = mem_start.elapsed();
            timings.push(mem_elapsed.as_nanos() as u64);
            
            // Prevent optimization
            std::hint::black_box(dummy);
        }

        // Convert timing variations to entropy bytes
        let mut entropy_data = Vec::new();
        for timing in timings {
            entropy_data.extend_from_slice(&timing.to_le_bytes());
        }

        // Estimate entropy bits (more conservative with better sources)
        let entropy_bits: usize = ((iterations as usize) / 5) * 8; // Assume 1 bit per 5 measurements

        Ok((entropy_data, entropy_bits))
    }

    /// Collect entropy from network jitter (if available)
    fn collect_network_jitter_entropy(&self) -> Result<(Vec<u8>, usize)> {
        let mut entropy_data = Vec::new();
        let entropy_bits: usize = 64; // Conservative estimate

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
        let entropy_bits: usize = 32;

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
        let entropy_bits: usize = 64; // Increased entropy estimate

        // Allocate memory and measure access patterns with more variation
        let size = 2048 * 1024; // 2MB for more variation
        let data: Vec<u8> = vec![0; size];
        
        for i in 0..200 {
            // Use multiple access patterns
            let patterns = [
                (i * 10009) % size, // Prime number for pseudo-random access
                (i * 10007) % size, // Different prime
                (i * i) % size,     // Quadratic pattern
                (i.wrapping_mul(0x9e3779b9) as usize) % size, // Golden ratio hash
            ];
            
            for &index in &patterns {
                let start = Instant::now();
                std::hint::black_box(data[index]);
                let elapsed = start.elapsed();
                entropy_data.extend_from_slice(&elapsed.as_nanos().to_le_bytes());
                
                // Add some computation between accesses
                let mut dummy = index as u64;
                dummy = dummy.wrapping_mul(i as u64).wrapping_add(index as u64);
                std::hint::black_box(dummy);
            }
            
            // Add cache flush timing variation
            let flush_start = Instant::now();
            let flush_size = 1024 * (i % 16 + 1);
            for j in 0..flush_size {
                std::hint::black_box(data[j * 64 % size]);
            }
            let flush_elapsed = flush_start.elapsed();
            entropy_data.extend_from_slice(&flush_elapsed.as_nanos().to_le_bytes());
        }

        Ok((entropy_data, entropy_bits))
    }

    /// Collect entropy from system time variations
    fn collect_system_time_entropy(&self) -> Result<(Vec<u8>, usize)> {
        let mut entropy_data = Vec::new();
        let entropy_bits: usize = 32; // Increased entropy estimate

        // Collect high-resolution timestamps with more variation
        for i in 0..20 {
            let now = SystemTime::now();
            let duration = now.duration_since(UNIX_EPOCH)
                .map_err(|_| FortressError::internal(
                    "System time went backwards during entropy collection",
                    "trng_entropy_time",
                ))?;
            
            // Add different time components
            entropy_data.extend_from_slice(&duration.as_nanos().to_le_bytes());
            entropy_data.extend_from_slice(&duration.as_secs().to_le_bytes());
            entropy_data.extend_from_slice(&duration.subsec_nanos().to_le_bytes());
            
            // Add some computation time variation
            let compute_start = Instant::now();
            let mut dummy = i as u64;
            for j in 0..(i % 100 + 1) {
                dummy = dummy.wrapping_add(j as u64).wrapping_mul(i as u64);
            }
            let compute_elapsed = compute_start.elapsed();
            entropy_data.extend_from_slice(&compute_elapsed.as_nanos().to_le_bytes());
            std::hint::black_box(dummy);
            
            // Small delay to add timing variation
            std::thread::sleep(std::time::Duration::from_nanos(i % 1000));
        }

        Ok((entropy_data, entropy_bits))
    }

    /// Generate true random bytes
    pub fn generate_bytes(&self, count: usize) -> Result<Vec<u8>> {
        // First try to use entropy pool
        match self.generate_from_entropy_pool(count) {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                tracing::warn!("Entropy pool generation failed: {}, using CSPRNG fallback", e);
                if self.config.enable_fallback {
                    self.fallback_generate(count)
                } else {
                    Err(FortressError::internal(
                        "TRNG failed and fallback is disabled",
                        "trng_no_fallback",
                    ))
                }
            }
        }
    }

    /// Generate random bytes from entropy pool
    fn generate_from_entropy_pool(&self, count: usize) -> Result<Vec<u8>> {
        // Perform health check first
        self.health_check()?;
        
        let mut pool = self.entropy_pool.lock().map_err(|_| {
            FortressError::internal(
                "Failed to acquire entropy pool lock",
                "trng_pool_lock",
            )
        })?;
        
        // If insufficient entropy, refresh or use CSPRNG fallback
        if pool.entropy_available() < 8 * count {
            drop(pool);
            // CSPRNG-only instances (min_entropy_bits == 0) use getrandom directly
            if self.config.min_entropy_bits == 0 {
                return self.fallback_generate(count);
            }
            self.refresh_entropy_pool()?;
            pool = self.entropy_pool.lock().map_err(|_| {
                FortressError::internal(
                    "Failed to acquire entropy pool lock after refresh",
                    "trng_pool_lock_refresh",
                )
            })?;
        }
        
        pool.get_bytes(count)
    }

    /// Refresh entropy pool with new data
    fn refresh_entropy_pool(&self) -> Result<()> {
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
                    let mut pool = self.entropy_pool.lock().map_err(|_| {
                        FortressError::internal(
                            "Failed to acquire entropy pool lock for refresh",
                            "trng_refresh_lock",
                        )
                    })?;
                    pool.add_entropy(&data, bits);
                    total_entropy += bits;
                }
                Err(e) => {
                    tracing::warn!("Failed to collect entropy from {:?} during refresh: {}", source, e);
                }
            }
        }
        
        if total_entropy == 0 {
            return Err(FortressError::internal(
                "Failed to collect any entropy during refresh",
                "trng_refresh_failed",
            ));
        }
        
        tracing::debug!("Refreshed entropy pool with {} bits", total_entropy);
        Ok(())
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

    /// Refresh entropy pool with new data (public interface)
    pub fn refresh_entropy(&self) -> Result<()> {
        self.refresh_entropy_pool()
    }

    /// Perform health check on the TRNG system
    pub fn health_check(&self) -> Result<()> {
        let mut last_check = self.last_health_check.lock().map_err(|_| {
            FortressError::internal(
                "Failed to acquire health check lock",
                "trng_health_lock",
            )
        })?;
        
        if last_check.elapsed() < self.config.health_check_interval {
            return Ok(());
        }

        let pool = self.entropy_pool.lock().map_err(|_| {
            FortressError::internal(
                "Failed to acquire entropy pool lock for health check",
                "trng_health_pool_lock",
            )
        })?;
        let entropy_available = pool.entropy_available();
        drop(pool);

        let mut health = self.health_status.lock().map_err(|_| {
            FortressError::internal(
                "Failed to acquire health status lock",
                "trng_health_status_lock",
            )
        })?;
        
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
        match self.health_status.lock() {
            Ok(health) => health.clone(),
            Err(_) => {
                tracing::error!("Failed to acquire health status lock, returning default");
                TrngHealth::Failed
            }
        }
    }

    /// Get entropy pool statistics
    pub fn entropy_stats(&self) -> (usize, usize) {
        match self.entropy_pool.lock() {
            Ok(pool) => (pool.entropy_available(), pool.buffer.len()),
            Err(_) => {
                tracing::error!("Failed to acquire entropy pool lock for stats, returning defaults");
                (0, 0) // Return defaults if lock fails
            }
        }
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

    /// Force reinitialization of TRNG
    pub fn reinitialize(&self) -> Result<()> {
        {
            let mut pool = self.entropy_pool.lock().map_err(|_| {
                FortressError::internal(
                    "Failed to acquire entropy pool lock for reinitialization",
                    "trng_reinit_lock",
                )
            })?;
            *pool = EntropyPool::new();
        }
        self.initialize_entropy_pool()
    }
}

impl Default for TrueRandomGenerator {
    fn default() -> Self {
        // For Default implementation, create a CSPRNG-only TRNG
        // This ensures we never have a failed TRNG instance
        let config = TrngConfig {
            min_entropy_bits: 0, // Don't require entropy pool
            enable_fallback: true, // Always enable fallback
            ..TrngConfig::default()
        };
        
        Self {
            config,
            entropy_pool: Arc::new(Mutex::new(EntropyPool::new())),
            health_status: Arc::new(Mutex::new(TrngHealth::Healthy)),
            last_health_check: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

/// Global TRNG instance for convenience
static GLOBAL_TRNG: std::sync::OnceLock<std::sync::Mutex<Option<Arc<TrueRandomGenerator>>>> = std::sync::OnceLock::new();

/// Initialize the global TRNG instance
pub fn init_global_trng() -> Result<()> {
    let trng = match TrueRandomGenerator::new() {
        Ok(trng) => Arc::new(trng),
        Err(e) => {
            tracing::warn!("Failed to initialize full TRNG: {}, using CSPRNG fallback", e);
            Arc::new(TrueRandomGenerator::default())
        }
    };
    
    let global = GLOBAL_TRNG.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = global.lock().map_err(|_| FortressError::key_management(
        "Failed to acquire lock on global TRNG during initialization", 
        None, 
        crate::error::KeyErrorCode::ProviderError
    ))?;
    *guard = Some(trng);
    Ok(())
}

/// Get the global TRNG instance (initializes if needed)
pub fn global_trng() -> Result<Arc<TrueRandomGenerator>> {
    let global = GLOBAL_TRNG.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = global.lock().map_err(|_| FortressError::key_management(
        "Failed to acquire lock on global TRNG", 
        None, 
        crate::error::KeyErrorCode::ProviderError
    ))?;
    
    if guard.is_none() {
        *guard = Some(Arc::new(TrueRandomGenerator::default()));
    }
    
    // Since we initialize if None above, this should always be Some
    match guard.as_ref() {
        Some(trng) => Ok(trng.clone()),
        None => Err(FortressError::key_management(
            "Failed to initialize global TRNG", 
            None, 
            crate::error::KeyErrorCode::ProviderError
        ))
    }
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
