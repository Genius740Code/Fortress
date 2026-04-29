//! Compression Engine Module
//!
//! This module provides high-performance compression for Fortress
//! serialization with multiple algorithms and adaptive selection.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};

/// Compression engine for data compression
pub struct CompressionEngine {
    /// Compression threshold in bytes
    compression_threshold: usize,
    /// Default compression algorithm
    default_algorithm: CompressionAlgorithm,
    /// Algorithm configurations
    algorithm_configs: Arc<RwLock<std::collections::HashMap<CompressionAlgorithm, AlgorithmConfig>>>,
    /// Compression metrics
    metrics: Arc<RwLock<CompressionMetrics>>,
    /// Adaptive compression enabled
    adaptive_enabled: bool,
    /// Compression cache
    compression_cache: Arc<RwLock<std::collections::HashMap<u64, Vec<u8>>>>,
}

/// Compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// LZ4 (fast)
    Lz4,
    /// Zstandard (balanced)
    Zstd,
    /// Gzip (standard)
    Gzip,
    /// Brotli (web optimized)
    Brotli,
    /// Adaptive (automatic selection)
    Adaptive,
}

/// Algorithm configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmConfig {
    /// Compression level (1-9)
    pub level: u8,
    /// Enable dictionary
    pub dictionary_enabled: bool,
    /// Window size
    pub window_size: Option<u32>,
    /// Maximum compression ratio
    pub max_compression_ratio: f64,
    /// Minimum size for compression
    pub min_size: usize,
    /// Performance score
    pub performance_score: u8,
    /// Compression ratio score
    pub compression_score: u8,
}

/// Compression metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionMetrics {
    /// Total compressions
    pub total_compressions: u64,
    /// Total decompressions
    pub total_decompressions: u64,
    /// Total bytes before compression
    pub total_input_bytes: u64,
    /// Total bytes after compression
    pub total_output_bytes: u64,
    /// Compression ratio
    pub compression_ratio: f64,
    /// Average compression time in microseconds
    pub avg_compression_time_us: f64,
    /// Average decompression time in microseconds
    pub avg_decompression_time_us: f64,
    /// Algorithm usage statistics
    pub algorithm_usage: std::collections::HashMap<CompressionAlgorithm, u64>,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Adaptive selections
    pub adaptive_selections: u64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Compression result
#[derive(Debug, Clone)]
pub struct CompressionResult {
    /// Compressed data
    pub data: Vec<u8>,
    /// Algorithm used
    pub algorithm: CompressionAlgorithm,
    /// Original size
    pub original_size: usize,
    /// Compressed size
    pub compressed_size: usize,
    /// Compression ratio
    pub compression_ratio: f64,
    /// Compression time
    pub compression_time: std::time::Duration,
}

impl CompressionEngine {
    /// Create a new compression engine
    pub fn new(compression_threshold: usize) -> Result<Self> {
        let mut engine = Self {
            compression_threshold,
            default_algorithm: CompressionAlgorithm::Zstd,
            algorithm_configs: Arc::new(RwLock::new(std::collections::HashMap::new())),
            metrics: Arc::new(RwLock::new(CompressionMetrics::default())),
            adaptive_enabled: true,
            compression_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
        };

        // Initialize algorithm configurations
        engine.initialize_algorithm_configs();
        
        Ok(engine)
    }

    /// Initialize algorithm configurations
    fn initialize_algorithm_configs(&mut self) {
        let mut configs = self.algorithm_configs.try_write().unwrap();
        
        // LZ4 configuration
        configs.insert(CompressionAlgorithm::Lz4, AlgorithmConfig {
            level: 1,
            dictionary_enabled: false,
            window_size: None,
            max_compression_ratio: 0.7,
            min_size: 64,
            performance_score: 95,
            compression_score: 70,
        });

        // Zstandard configuration
        configs.insert(CompressionAlgorithm::Zstd, AlgorithmConfig {
            level: 3,
            dictionary_enabled: true,
            window_size: Some(32768),
            max_compression_ratio: 0.8,
            min_size: 128,
            performance_score: 85,
            compression_score: 85,
        });

        // Gzip configuration
        configs.insert(CompressionAlgorithm::Gzip, AlgorithmConfig {
            level: 6,
            dictionary_enabled: false,
            window_size: Some(32768),
            max_compression_ratio: 0.75,
            min_size: 256,
            performance_score: 70,
            compression_score: 80,
        });

        // Brotli configuration
        configs.insert(CompressionAlgorithm::Brotli, AlgorithmConfig {
            level: 4,
            dictionary_enabled: true,
            window_size: Some(22),
            max_compression_ratio: 0.85,
            min_size: 512,
            performance_score: 60,
            compression_score: 90,
        });

        // None configuration
        configs.insert(CompressionAlgorithm::None, AlgorithmConfig {
            level: 0,
            dictionary_enabled: false,
            window_size: None,
            max_compression_ratio: 1.0,
            min_size: 0,
            performance_score: 100,
            compression_score: 0,
        });
    }

    /// Compress data using the best algorithm
    pub async fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        
        // Check if compression is needed
        if data.len() < self.compression_threshold {
            return Ok(data.to_vec());
        }

        // Check cache first
        let data_hash = self.calculate_hash(data);
        {
            let cache = self.compression_cache.read().await;
            if let Some(cached) = cache.get(&data_hash) {
                let mut metrics = self.metrics.write().await;
                metrics.cache_hits += 1;
                return Ok(cached.clone());
            }
        }

        // Select algorithm
        let algorithm = if self.adaptive_enabled {
            self.select_best_algorithm(data).await?
        } else {
            self.default_algorithm.clone()
        };

        // Compress data
        let compressed = self.compress_with_algorithm(data, &algorithm).await?;
        
        // Check if compression is beneficial
        let compression_ratio = compressed.len() as f64 / data.len() as f64;
        let config = self.algorithm_configs.read().await;
        let algorithm_config = &config[&algorithm];
        
        let final_data = if compression_ratio >= algorithm_config.max_compression_ratio {
            // Compression not beneficial, use original
            data.to_vec()
        } else {
            compressed
        };

        // Cache the result
        {
            let mut cache = self.compression_cache.write().await;
            if cache.len() < 10000 { // Limit cache size
                cache.insert(data_hash, final_data.clone());
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_compressions += 1;
            metrics.total_input_bytes += data.len() as u64;
            metrics.total_output_bytes += final_data.len() as u64;
            metrics.compression_ratio = metrics.total_output_bytes as f64 / metrics.total_input_bytes as f64;
            metrics.avg_compression_time_us = (metrics.avg_compression_time_us * (metrics.total_compressions - 1) as f64 
                + start.elapsed().as_micros() as f64) / metrics.total_compressions as f64;
            
            *metrics.algorithm_usage.entry(algorithm).or_insert(0) += 1;
            metrics.cache_misses += 1;
            metrics.last_updated = chrono::Utc::now();
        }

        Ok(final_data)
    }

    /// Decompress data
    pub async fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        
        // Check if data is compressed
        if !self.is_compressed(data)? {
            return Ok(data.to_vec());
        }

        // Detect compression algorithm
        let algorithm = self.detect_algorithm(data)?;
        
        // Decompress data
        let decompressed = self.decompress_with_algorithm(data, &algorithm).await?;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_decompressions += 1;
            metrics.avg_decompression_time_us = (metrics.avg_decompression_time_us * (metrics.total_decompressions - 1) as f64 
                + start.elapsed().as_micros() as f64) / metrics.total_decompressions as f64;
            metrics.last_updated = chrono::Utc::now();
        }

        Ok(decompressed)
    }

    /// Check if data is compressed
    pub fn is_compressed(&self, data: &[u8]) -> Result<bool> {
        // Simple heuristic: check for compression magic bytes
        if data.len() < 4 {
            return Ok(false);
        }

        let magic = &data[0..4];
        Ok(magic == b"FZL4" || magic == b"FZSD" || magic == b"FZGZ" || magic == b"FZBR")
    }

    /// Detect compression algorithm from data
    fn detect_algorithm(&self, data: &[u8]) -> Result<CompressionAlgorithm> {
        if data.len() < 4 {
            return Ok(CompressionAlgorithm::None);
        }

        let magic = &data[0..4];
        match magic {
            b"FZL4" => Ok(CompressionAlgorithm::Lz4),
            b"FZSD" => Ok(CompressionAlgorithm::Zstd),
            b"FZGZ" => Ok(CompressionAlgorithm::Gzip),
            b"FZBR" => Ok(CompressionAlgorithm::Brotli),
            _ => Ok(CompressionAlgorithm::None),
        }
    }

    /// Select best algorithm for data
    async fn select_best_algorithm(&self, data: &[u8]) -> Result<CompressionAlgorithm> {
        let configs = self.algorithm_configs.read().await;
        
        // Score each algorithm based on data characteristics
        let mut scored_algorithms: Vec<(CompressionAlgorithm, u32)> = configs.iter()
            .filter(|(_alg, config)| data.len() >= config.min_size)
            .map(|(alg, config)| {
                let mut score = 0u32;
                
                // Performance score
                score += config.performance_score as u32 * 2;
                
                // Compression score
                score += config.compression_score as u32;
                
                // Data size considerations
                if data.len() < 1024 {
                    // Small data - prefer fast algorithms
                    if *alg == CompressionAlgorithm::Lz4 {
                        score += 50;
                    }
                } else if data.len() > 1024 * 1024 {
                    // Large data - prefer high compression
                    if config.compression_score >= 85 {
                        score += 30;
                    }
                }
                
                // Data entropy estimation (simplified)
                let entropy = self.estimate_entropy(data);
                if entropy > 0.8 {
                    // High entropy - prefer high compression
                    if config.compression_score >= 80 {
                        score += 20;
                    }
                } else {
                    // Low entropy - prefer fast algorithms
                    if config.performance_score >= 90 {
                        score += 20;
                    }
                }
                
                (alg.clone(), score)
            })
            .collect();

        // Sort by score (descending)
        scored_algorithms.sort_by(|a, b| b.1.cmp(&a.1));

        // Return the highest scoring algorithm
        scored_algorithms.into_iter()
            .next()
            .map(|(alg, _score)| alg)
            .ok_or_else(|| FortressError::compression("No suitable algorithm found", "Data too small"))
    }

    /// Estimate data entropy (simplified)
    fn estimate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u64; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &frequency {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy / 8.0 // Normalize to 0-1 range
    }

    /// Compress with specific algorithm
    async fn compress_with_algorithm(&self, data: &[u8], algorithm: &CompressionAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            CompressionAlgorithm::None => Ok(data.to_vec()),
            CompressionAlgorithm::Lz4 => self.compress_lz4(data).await,
            CompressionAlgorithm::Zstd => self.compress_zstd(data).await,
            CompressionAlgorithm::Gzip => self.compress_gzip(data).await,
            CompressionAlgorithm::Brotli => self.compress_brotli(data).await,
            CompressionAlgorithm::Adaptive => {
                let best = self.select_best_algorithm(data).await?;
                Box::pin(self.compress_with_algorithm_internal(data, &best)).await
            }
        }
    }

    /// Internal compression method to avoid recursion
    async fn compress_with_algorithm_internal(&self, data: &[u8], algorithm: &CompressionAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            CompressionAlgorithm::None => Ok(data.to_vec()),
            CompressionAlgorithm::Lz4 => self.compress_lz4(data).await,
            CompressionAlgorithm::Zstd => self.compress_zstd(data).await,
            CompressionAlgorithm::Gzip => self.compress_gzip(data).await,
            CompressionAlgorithm::Brotli => self.compress_brotli(data).await,
            CompressionAlgorithm::Adaptive => {
                let best = self.select_best_algorithm(data).await?;
                Box::pin(self.compress_with_algorithm_internal(data, &best)).await
            }
        }
    }

    /// Decompress with specific algorithm
    async fn decompress_with_algorithm(&self, data: &[u8], algorithm: &CompressionAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            CompressionAlgorithm::None => Ok(data.to_vec()),
            CompressionAlgorithm::Lz4 => self.decompress_lz4(data).await,
            CompressionAlgorithm::Zstd => self.decompress_zstd(data).await,
            CompressionAlgorithm::Gzip => self.decompress_gzip(data).await,
            CompressionAlgorithm::Brotli => self.decompress_brotli(data).await,
            CompressionAlgorithm::Adaptive => {
                let best = self.detect_algorithm(data)?;
                Box::pin(self.decompress_with_algorithm_internal(data, &best)).await
            }
        }
    }

    async fn decompress_with_algorithm_internal(&self, data: &[u8], algorithm: &CompressionAlgorithm) -> Result<Vec<u8>> {
        match algorithm {
            CompressionAlgorithm::None => Ok(data.to_vec()),
            CompressionAlgorithm::Lz4 => self.decompress_lz4(data).await,
            CompressionAlgorithm::Zstd => self.decompress_zstd(data).await,
            CompressionAlgorithm::Gzip => self.decompress_gzip(data).await,
            CompressionAlgorithm::Brotli => self.decompress_brotli(data).await,
            CompressionAlgorithm::Adaptive => {
                let best = self.detect_algorithm(data)?;
                Box::pin(self.decompress_with_algorithm_internal(data, &best)).await
            }
        }
    }

    /// LZ4 compression (placeholder implementation)
    async fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        compressed.extend_from_slice(b"FZL4"); // Magic bytes
        
        // Placeholder: simple run-length encoding as LZ4 substitute
        let mut i = 0;
        while i < data.len() {
            let current_byte = data[i];
            let mut run_length = 1;
            
            while i + run_length < data.len() && data[i + run_length] == current_byte && run_length < 255 {
                run_length += 1;
            }
            
            compressed.push(run_length as u8);
            compressed.push(current_byte);
            i += run_length;
        }
        
        Ok(compressed)
    }

    /// LZ4 decompression
    async fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 4 || &data[0..4] != b"FZL4" {
            return Err(FortressError::compression("Invalid LZ4 data", "Magic bytes mismatch"));
        }
        
        let mut decompressed = Vec::new();
        let mut i = 4;
        
        while i < data.len() {
            if i + 1 >= data.len() {
                break;
            }
            
            let run_length = data[i] as usize;
            let byte_value = data[i + 1];
            
            for _ in 0..run_length {
                decompressed.push(byte_value);
            }
            
            i += 2;
        }
        
        Ok(decompressed)
    }

    /// Zstandard compression (placeholder implementation)
    async fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        compressed.extend_from_slice(b"FZSD"); // Magic bytes
        compressed.extend_from_slice(&(data.len() as u32).to_le_bytes());
        
        // Placeholder: simple compression
        let mut compressed_data = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if i + 4 <= data.len() {
                // Copy 4 bytes
                compressed_data.extend_from_slice(&data[i..i+4]);
                i += 4;
            } else {
                // Copy remaining bytes
                compressed_data.extend_from_slice(&data[i..]);
                break;
            }
        }
        
        compressed.extend_from_slice(&compressed_data);
        Ok(compressed)
    }

    /// Zstandard decompression
    async fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 8 || &data[0..4] != b"FZSD" {
            return Err(FortressError::compression("Invalid Zstd data", "Magic bytes mismatch"));
        }
        
        let original_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let compressed_data = &data[8..];
        
        // Placeholder: simple decompression
        let mut decompressed = Vec::new();
        for &byte in compressed_data {
            decompressed.push(byte);
        }
        
        // Pad or truncate to original size
        decompressed.resize(original_size, 0);
        
        Ok(decompressed)
    }

    /// Gzip compression (placeholder implementation)
    async fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        compressed.extend_from_slice(b"FZGZ"); // Magic bytes
        
        // Placeholder: simple compression
        compressed.extend_from_slice(data);
        Ok(compressed)
    }

    /// Gzip decompression
    async fn decompress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 4 || &data[0..4] != b"FZGZ" {
            return Err(FortressError::compression("Invalid Gzip data", "Magic bytes mismatch"));
        }
        
        Ok(data[4..].to_vec())
    }

    /// Brotli compression (placeholder implementation)
    async fn compress_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        compressed.extend_from_slice(b"FZBR"); // Magic bytes
        
        // Placeholder: simple compression
        compressed.extend_from_slice(data);
        Ok(compressed)
    }

    /// Brotli decompression
    async fn decompress_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 4 || &data[0..4] != b"FZBR" {
            return Err(FortressError::compression("Invalid Brotli data", "Magic bytes mismatch"));
        }
        
        Ok(data[4..].to_vec())
    }

    /// Calculate simple hash for caching
    fn calculate_hash(&self, data: &[u8]) -> u64 {
        let mut hash = 0u64;
        for (i, &byte) in data.iter().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64).wrapping_add(i as u64);
        }
        hash
    }

    /// Get compression ratio
    pub async fn get_compression_ratio(&self) -> Result<f64> {
        let metrics = self.metrics.read().await;
        Ok(metrics.compression_ratio)
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Result<CompressionMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Clear compression cache
    pub async fn clear_cache(&self) -> Result<()> {
        self.compression_cache.write().await.clear();
        Ok(())
    }

    /// Set adaptive compression
    pub fn set_adaptive(&mut self, enabled: bool) {
        self.adaptive_enabled = enabled;
    }

    /// Set default algorithm
    pub fn set_default_algorithm(&mut self, algorithm: CompressionAlgorithm) {
        self.default_algorithm = algorithm;
    }

    /// Benchmark compression algorithms
    pub async fn benchmark_algorithms(&self, test_data: &[u8], iterations: usize) -> Result<std::collections::HashMap<CompressionAlgorithm, BenchmarkResult>> {
        let mut results = std::collections::HashMap::new();
        
        for algorithm in [CompressionAlgorithm::Lz4, CompressionAlgorithm::Zstd, CompressionAlgorithm::Gzip, CompressionAlgorithm::Brotli] {
            let start = std::time::Instant::now();
            let mut total_compressed_size = 0usize;
            
            for _ in 0..iterations {
                let compressed = self.compress_with_algorithm(test_data, &algorithm).await?;
                total_compressed_size += compressed.len();
            }
            
            let duration = start.elapsed();
            let throughput = iterations as f64 / duration.as_secs_f64();
            let avg_compressed_size = total_compressed_size / iterations;
            let compression_ratio = avg_compressed_size as f64 / test_data.len() as f64;
            
            results.insert(algorithm.clone(), BenchmarkResult {
                algorithm,
                iterations,
                total_time: duration,
                avg_time_per_op: duration / iterations as u32,
                throughput_ops_per_sec: throughput,
                avg_size_bytes: avg_compressed_size,
                compression_ratio,
            });
        }
        
        Ok(results)
    }

    /// Shutdown the compression engine
    pub async fn shutdown(&self) -> Result<()> {
        self.clear_cache().await?;
        Ok(())
    }
}

/// Compression benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Algorithm tested
    pub algorithm: CompressionAlgorithm,
    /// Number of iterations
    pub iterations: usize,
    /// Total time taken
    pub total_time: std::time::Duration,
    /// Average time per operation
    pub avg_time_per_op: std::time::Duration,
    /// Throughput in operations per second
    pub throughput_ops_per_sec: f64,
    /// Average compressed size
    pub avg_size_bytes: usize,
    /// Compression ratio
    pub compression_ratio: f64,
}

impl Default for CompressionMetrics {
    fn default() -> Self {
        Self {
            total_compressions: 0,
            total_decompressions: 0,
            total_input_bytes: 0,
            total_output_bytes: 0,
            compression_ratio: 1.0,
            avg_compression_time_us: 0.0,
            avg_decompression_time_us: 0.0,
            algorithm_usage: std::collections::HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
            adaptive_selections: 0,
            last_updated: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compression_engine() {
        let engine = CompressionEngine::new(100).unwrap();
        
        let test_data = vec![1u8; 1000]; // 1KB of data
        
        // Test compression
        let compressed = engine.compress(&test_data).await.unwrap();
        assert!(!compressed.is_empty());
        
        // Test decompression
        let decompressed = engine.decompress(&compressed).await.unwrap();
        assert_eq!(decompressed, test_data);
    }

    #[tokio::test]
    async fn test_compression_detection() {
        let engine = CompressionEngine::new(100).unwrap();
        
        let test_data = vec![1, 2, 3, 4, 5];
        let compressed = engine.compress(&test_data).await.unwrap();
        
        // Should detect compression
        assert!(engine.is_compressed(&compressed).unwrap());
        
        // Should detect algorithm
        let algorithm = engine.detect_algorithm(&compressed).unwrap();
        assert!(algorithm != CompressionAlgorithm::None);
    }

    #[tokio::test]
    async fn test_adaptive_compression() {
        let mut engine = CompressionEngine::new(100).unwrap();
        engine.set_adaptive(true);
        
        let test_data = vec![1u8; 1000];
        let compressed = engine.compress(&test_data).await.unwrap();
        
        // Should compress
        assert!(engine.is_compressed(&compressed).unwrap());
    }

    #[tokio::test]
    async fn test_compression_metrics() {
        let engine = CompressionEngine::new(100).unwrap();
        
        let test_data = vec![1u8; 1000];
        engine.compress(&test_data).await.unwrap();
        engine.decompress(&test_data).await.unwrap();
        
        let metrics = engine.get_metrics().await.unwrap();
        assert_eq!(metrics.total_compressions, 1);
        assert_eq!(metrics.total_decompressions, 0); // Original data not compressed
    }
}
