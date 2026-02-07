//! Performance benchmarks for AEGIS-256 encryption
//! 
//! This module provides comprehensive performance testing for the AEGIS-256 algorithm
//! to validate its speed claims and provide optimization insights.

use crate::encryption::{Aegis256, EncryptionAlgorithm};
use std::time::Instant;
use std::sync::Arc;

/// Performance benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    /// Data size in bytes
    pub data_size: usize,
    /// Encryption time in nanoseconds
    pub encrypt_time_ns: u128,
    /// Decryption time in nanoseconds
    pub decrypt_time_ns: u128,
    /// Encryption throughput in MB/s
    pub encrypt_throughput_mbps: f64,
    /// Decryption throughput in MB/s
    pub decrypt_throughput_mbps: f64,
    /// Memory usage peak in bytes (if available)
    pub memory_usage_bytes: Option<usize>,
}

impl BenchmarkResults {
    /// Create new benchmark results
    pub fn new(data_size: usize, encrypt_time: std::time::Duration, decrypt_time: std::time::Duration) -> Self {
        let encrypt_throughput = if encrypt_time.as_secs_f64() > 0.0 {
            (data_size as f64) / (1024.0 * 1024.0) / encrypt_time.as_secs_f64()
        } else {
            0.0
        };
        
        let decrypt_throughput = if decrypt_time.as_secs_f64() > 0.0 {
            (data_size as f64) / (1024.0 * 1024.0) / decrypt_time.as_secs_f64()
        } else {
            0.0
        };

        Self {
            data_size,
            encrypt_time_ns: encrypt_time.as_nanos(),
            decrypt_time_ns: decrypt_time.as_nanos(),
            encrypt_throughput_mbps: encrypt_throughput,
            decrypt_throughput_mbps: decrypt_throughput,
            memory_usage_bytes: None,
        }
    }

    /// Format throughput as human readable string
    pub fn format_throughput(throughput_mbps: f64) -> String {
        if throughput_mbps >= 1000.0 {
            format!("{:.2} GB/s", throughput_mbps / 1024.0)
        } else {
            format!("{:.2} MB/s", throughput_mbps)
        }
    }

    /// Print detailed results
    pub fn print_detailed(&self, algorithm_name: &str) {
        println!("🔬 {} Performance Results:", algorithm_name);
        println!("  📊 Data size: {} bytes", self.data_size);
        println!("  ⚡ Encryption: {} ({})", 
            BenchmarkResults::format_throughput(self.encrypt_throughput_mbps),
            format_duration(self.encrypt_time_ns)
        );
        println!("  🔓 Decryption: {} ({})", 
            BenchmarkResults::format_throughput(self.decrypt_throughput_mbps),
            format_duration(self.decrypt_time_ns)
        );
        println!("  📈 Combined throughput: {}", 
            BenchmarkResults::format_throughput(self.encrypt_throughput_mbps + self.decrypt_throughput_mbps)
        );
    }
}

/// Format duration from nanoseconds to human readable
fn format_duration(nanos: u128) -> String {
    if nanos < 1_000 {
        format!("{} ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{:.2} μs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.3} s", nanos as f64 / 1_000_000_000.0)
    }
}

/// Comprehensive benchmark suite for AEGIS-256
pub struct AegisBenchmark {
    algorithm: Arc<Aegis256>,
}

impl AegisBenchmark {
    /// Create new benchmark instance
    pub fn new() -> Self {
        Self {
            algorithm: Arc::new(Aegis256::new()),
        }
    }

    /// Run comprehensive benchmark suite
    pub fn run_suite(&self) -> Vec<BenchmarkResults> {
        println!("🚀 Starting AEGIS-256 Performance Benchmark Suite");
        println!("==================================================");
        
        let mut results = Vec::new();
        
        // Test different data sizes
        let test_sizes = vec![
            (64, "64 bytes"),
            (1024, "1 KB"),
            (10_240, "10 KB"),
            (102_400, "100 KB"),
            (1_048_576, "1 MB"),
            (10_485_760, "10 MB"),
            (104_857_600, "100 MB"),
        ];

        for (size, description) in test_sizes {
            println!("\n📏 Testing {} ({})", description, size);
            
            // Generate test data
            let data = vec![0u8; size];
            let key = vec![42u8; 32]; // Test key
            
            // Warm up
            let _ = self.algorithm.encrypt(&data, &key);
            
            // Benchmark encryption
            let encrypt_start = Instant::now();
            let ciphertext = self.algorithm.encrypt(&data, &key)
                .expect("Encryption should succeed");
            let encrypt_time = encrypt_start.elapsed();
            
            // Benchmark decryption
            let decrypt_start = Instant::now();
            let _plaintext = self.algorithm.decrypt(&ciphertext, &key)
                .expect("Decryption should succeed");
            let decrypt_time = decrypt_start.elapsed();
            
            let result = BenchmarkResults::new(size, encrypt_time, decrypt_time);
            result.print_detailed("AEGIS-256");
            results.push(result);
        }

        // Summary statistics
        self.print_summary(&results);
        
        results
    }

    /// Print summary statistics
    fn print_summary(&self, results: &[BenchmarkResults]) {
        println!("\n📊 Performance Summary");
        println!("=====================");
        
        if let (Some(min), Some(max)) = (
            results.iter().min_by_key(|r| r.data_size),
            results.iter().max_by_key(|r| r.data_size)
        ) {
            println!("🔹 Small data ({}): {}", 
                min.data_size, 
                BenchmarkResults::format_throughput(min.encrypt_throughput_mbps)
            );
            println!("🔸 Large data ({}): {}", 
                max.data_size, 
                BenchmarkResults::format_throughput(max.encrypt_throughput_mbps)
            );
        }

        // Calculate average throughput
        let avg_encrypt: f64 = results.iter().map(|r| r.encrypt_throughput_mbps).sum::<f64>() / results.len() as f64;
        let avg_decrypt: f64 = results.iter().map(|r| r.decrypt_throughput_mbps).sum::<f64>() / results.len() as f64;
        
        println!("📈 Average encryption: {}", 
            BenchmarkResults::format_throughput(avg_encrypt)
        );
        println!("📉 Average decryption: {}", 
            BenchmarkResults::format_throughput(avg_decrypt)
        );
        println!("⚡ Combined average: {}", 
            BenchmarkResults::format_throughput(avg_encrypt + avg_decrypt)
        );

        // Performance validation
        if avg_encrypt >= 10_000.0 {
            println!("✅ Excellent performance - exceeds 10 GB/s");
        } else if avg_encrypt >= 1_000.0 {
            println!("✅ Good performance - exceeds 1 GB/s");
        } else if avg_encrypt >= 100.0 {
            println!("⚠️  Moderate performance - below 1 GB/s");
        } else {
            println!("❌ Poor performance - below 100 MB/s");
        }
    }

    /// Run concurrent benchmark to test thread safety
    pub fn run_concurrent_benchmark(&self, threads: usize, data_size: usize, iterations: usize) {
        println!("\n🔄 Concurrent Benchmark ({} threads, {} bytes, {} iterations)", 
            threads, data_size, iterations);
        
        use std::sync::mpsc;
        use std::thread;
        
        let (tx, rx) = mpsc::channel();
        let algorithm = Arc::clone(&self.algorithm);
        
        let start = Instant::now();
        
        for _ in 0..threads {
            let tx = tx.clone();
            let alg = Arc::clone(&algorithm);
            let data = vec![0u8; data_size];
            let key = vec![42u8; 32];
            
            thread::spawn(move || {
                for _ in 0..iterations {
                    let encrypt_start = Instant::now();
                    let ciphertext = alg.encrypt(&data, &key).unwrap();
                    let encrypt_time = encrypt_start.elapsed();
                    
                    let decrypt_start = Instant::now();
                    let _plaintext = alg.decrypt(&ciphertext, &key).unwrap();
                    let decrypt_time = decrypt_start.elapsed();
                    
                    tx.send((encrypt_time, decrypt_time)).unwrap();
                }
            });
        }
        
        drop(tx);
        
        let mut total_encrypt_time = std::time::Duration::ZERO;
        let mut total_decrypt_time = std::time::Duration::ZERO;
        let mut operations = 0;
        
        for (encrypt_time, decrypt_time) in rx {
            total_encrypt_time += encrypt_time;
            total_decrypt_time += decrypt_time;
            operations += 1;
        }
        
        let total_time = start.elapsed();
        
        println!("📊 Concurrent Results:");
        println!("  🔢 Total operations: {}", operations);
        println!("  ⏱️  Total time: {:?}", total_time);
        println!("  🚀 Operations/sec: {:.2}", operations as f64 / total_time.as_secs_f64());
        println!("  ⚡ Avg encryption: {}", format_duration(total_encrypt_time.as_nanos() / operations as u128));
        println!("  🔓 Avg decryption: {}", format_duration(total_decrypt_time.as_nanos() / operations as u128));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_creation() {
        let benchmark = AegisBenchmark::new();
        let results = benchmark.run_suite();
        assert!(!results.is_empty(), "Should generate benchmark results");
    }

    #[test]
    fn test_concurrent_benchmark() {
        let benchmark = AegisBenchmark::new();
        benchmark.run_concurrent_benchmark(4, 1024, 10);
    }
}
