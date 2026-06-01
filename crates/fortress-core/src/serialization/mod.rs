//! Serialization Module
//!
//! This module provides high-performance binary serialization for internal
//! Fortress communication with protocol negotiation and compression.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

// pub mod binary_protocol; // Temporarily disabled due to lifetime issues
pub mod compatibility;
pub mod compression;
pub mod protocol_negotiation;

// pub use binary_protocol::BinaryProtocol; // Temporarily disabled
pub use compatibility::CompatibilityManager;
pub use compression::CompressionEngine;
pub use protocol_negotiation::ProtocolNegotiator;

/// Serialization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializationConfig {
    /// Default serialization format
    pub default_format: SerializationFormat,
    /// Compression enabled
    pub compression_enabled: bool,
    /// Compression threshold in bytes
    pub compression_threshold: usize,
    /// Protocol negotiation enabled
    pub protocol_negotiation_enabled: bool,
    /// Backward compatibility enabled
    pub backward_compatibility_enabled: bool,
    /// Version compatibility level
    pub compatibility_level: CompatibilityLevel,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Serialization timeout in milliseconds
    pub serialization_timeout_ms: u64,
}

/// Serialization format types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum SerializationFormat {
    /// JSON format (human-readable)
    Json,
    /// Binary format (high-performance)
    Binary,
    /// Protocol Buffers
    Protobuf,
    /// MessagePack
    MessagePack,
    /// CBOR (Concise Binary Object Representation)
    Cbor,
}

// Re-export CompatibilityLevel from compatibility module
pub use compatibility::CompatibilityLevel;

/// Serialization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializationMetrics {
    /// Total serializations
    pub total_serializations: u64,
    /// Total deserializations
    pub total_deserializations: u64,
    /// Average serialization time in microseconds
    pub avg_serialization_time_us: f64,
    /// Average deserialization time in microseconds
    pub avg_deserialization_time_us: f64,
    /// Total bytes serialized
    pub total_bytes_serialized: u64,
    /// Total bytes deserialized
    pub total_bytes_deserialized: u64,
    /// Compression ratio (0.0 to 1.0)
    pub compression_ratio: f64,
    /// Protocol format usage statistics
    pub format_usage: std::collections::HashMap<SerializationFormat, u64>,
    /// Error count
    pub error_count: u64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Main serialization manager
pub struct SerializationManager {
    config: SerializationConfig,
    protocol_negotiator: Option<Arc<ProtocolNegotiator>>,
    compression_engine: Option<Arc<CompressionEngine>>,
    compatibility_manager: Option<Arc<CompatibilityManager>>,
    metrics: Arc<RwLock<SerializationMetrics>>,
}

impl SerializationManager {
    /// Create a new serialization manager
    pub fn new(config: SerializationConfig) -> Result<Self> {
        let mut manager = Self {
            protocol_negotiator: None,
            compression_engine: None,
            compatibility_manager: None,
            metrics: Arc::new(RwLock::new(SerializationMetrics::default())),
            config,
        };

        // Initialize components based on configuration
        if manager.config.protocol_negotiation_enabled {
            manager.protocol_negotiator = Some(Arc::new(ProtocolNegotiator::new()?));
        }

        if manager.config.compression_enabled {
            manager.compression_engine = Some(Arc::new(CompressionEngine::new(
                manager.config.compression_threshold,
            )?));
        }

        if manager.config.backward_compatibility_enabled {
            manager.compatibility_manager = Some(Arc::new(CompatibilityManager::new(
                manager.config.compatibility_level.clone(),
            )?));
        }

        Ok(manager)
    }

    /// Serialize data using the configured format
    pub async fn serialize<T>(
        &self,
        data: &T,
        format: Option<SerializationFormat>,
    ) -> Result<Vec<u8>>
    where
        T: Serialize + Send + Sync,
    {
        let start = std::time::Instant::now();
        let format = format.unwrap_or_else(|| self.config.default_format.clone());

        // Serialize based on format
        let mut serialized = match format {
            SerializationFormat::Json => serde_json::to_vec(data).map_err(|e| {
                FortressError::serialization("JSON serialization failed", &e.to_string())
            }),
            SerializationFormat::Binary => {
                // Binary protocol temporarily disabled
                return Err(FortressError::serialization(
                    "Binary protocol temporarily disabled",
                    "binary_protocol module disabled",
                ));
            }
            SerializationFormat::Protobuf => {
                // Placeholder for protobuf implementation
                serde_json::to_vec(data).map_err(|e| {
                    FortressError::serialization("Protobuf serialization failed", &e.to_string())
                })
            }
            SerializationFormat::MessagePack => {
                // Placeholder for MessagePack implementation
                serde_json::to_vec(data).map_err(|e| {
                    FortressError::serialization("MessagePack serialization failed", &e.to_string())
                })
            }
            SerializationFormat::Cbor => {
                // Placeholder for CBOR implementation
                serde_json::to_vec(data).map_err(|e| {
                    FortressError::serialization("CBOR serialization failed", &e.to_string())
                })
            }
        }?;

        // Apply compression if enabled and threshold is met
        if let Some(compression_engine) = &self.compression_engine {
            if serialized.len() > self.config.compression_threshold {
                serialized = compression_engine.compress(&serialized).await?;
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_serializations += 1;
            metrics.total_bytes_serialized += serialized.len() as u64;
            metrics.avg_serialization_time_us = (metrics.avg_serialization_time_us
                * (metrics.total_serializations - 1) as f64
                + start.elapsed().as_micros() as f64)
                / metrics.total_serializations as f64;

            *metrics.format_usage.entry(format).or_insert(0) += 1;
            metrics.last_updated = chrono::Utc::now();
        }

        // Check message size limit
        if serialized.len() > self.config.max_message_size {
            return Err(FortressError::serialization(
                "Message size exceeds limit",
                &format!(
                    "Size: {} bytes, Limit: {} bytes",
                    serialized.len(),
                    self.config.max_message_size
                ),
            ));
        }

        Ok(serialized)
    }

    /// Deserialize data using the specified format
    pub async fn deserialize<T>(&self, data: &[u8], format: SerializationFormat) -> Result<T>
    where
        T: for<'de> Deserialize<'de> + Send + Sync,
    {
        let start = std::time::Instant::now();

        // Apply decompression if needed
        let mut data = data.to_vec();
        if let Some(compression_engine) = &self.compression_engine {
            if compression_engine.is_compressed(&data)? {
                data = compression_engine.decompress(&data).await?;
            }
        }

        // Deserialize based on format
        let result = match format {
            SerializationFormat::Json => serde_json::from_slice(&data).map_err(|e| {
                FortressError::serialization("JSON deserialization failed", &e.to_string())
            }),
            SerializationFormat::Binary => {
                // Binary protocol temporarily disabled
                return Err(FortressError::serialization(
                    "Binary protocol temporarily disabled",
                    "binary_protocol module disabled",
                ));
            }
            SerializationFormat::Protobuf => {
                // Placeholder for protobuf implementation
                serde_json::from_slice(&data).map_err(|e| {
                    FortressError::serialization("Protobuf deserialization failed", &e.to_string())
                })
            }
            SerializationFormat::MessagePack => {
                // Placeholder for MessagePack implementation
                serde_json::from_slice(&data).map_err(|e| {
                    FortressError::serialization(
                        "MessagePack deserialization failed",
                        &e.to_string(),
                    )
                })
            }
            SerializationFormat::Cbor => {
                // Placeholder for CBOR implementation
                serde_json::from_slice(&data).map_err(|e| {
                    FortressError::serialization("CBOR deserialization failed", &e.to_string())
                })
            }
        }?;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_deserializations += 1;
            metrics.total_bytes_deserialized += data.len() as u64;
            metrics.avg_deserialization_time_us = (metrics.avg_deserialization_time_us
                * (metrics.total_deserializations - 1) as f64
                + start.elapsed().as_micros() as f64)
                / metrics.total_deserializations as f64;
            metrics.last_updated = chrono::Utc::now();
        }

        Ok(result)
    }

    /// Negotiate protocol with a peer
    pub async fn negotiate_protocol(
        &self,
        peer_capabilities: &[SerializationFormat],
    ) -> Result<SerializationFormat> {
        if let Some(negotiator) = &self.protocol_negotiator {
            negotiator.negotiate(peer_capabilities)
        } else {
            Ok(self.config.default_format.clone())
        }
    }

    /// Check compatibility with a version
    pub async fn check_compatibility(&self, version: &str) -> Result<bool> {
        if let Some(compatibility_manager) = &self.compatibility_manager {
            compatibility_manager.is_compatible(version).await
        } else {
            Ok(true)
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Result<SerializationMetrics> {
        let metrics = self.metrics.read().await;

        // Calculate compression ratio
        let mut updated_metrics = metrics.clone();
        if metrics.total_bytes_serialized > 0 {
            updated_metrics.compression_ratio =
                if let Some(compression_engine) = &self.compression_engine {
                    compression_engine.get_compression_ratio().await?
                } else {
                    1.0
                };
        }

        Ok(updated_metrics)
    }

    /// Get supported formats
    pub fn get_supported_formats(&self) -> Vec<SerializationFormat> {
        vec![
            SerializationFormat::Json,
            SerializationFormat::Binary,
            SerializationFormat::Protobuf,
            SerializationFormat::MessagePack,
            SerializationFormat::Cbor,
        ]
    }

    /// Benchmark serialization performance
    pub async fn benchmark_serialization<T>(
        &self,
        data: &T,
        iterations: usize,
    ) -> Result<BenchmarkResult>
    where
        T: Serialize + Clone + Send + Sync,
    {
        let mut results = std::collections::HashMap::new();

        for format in self.get_supported_formats() {
            let start = std::time::Instant::now();
            let mut total_size = 0usize;

            for _ in 0..iterations {
                let serialized = self.serialize(data, Some(format.clone())).await?;
                total_size += serialized.len();
            }

            let duration = start.elapsed();
            let avg_time = duration / iterations as u32;
            let throughput = iterations as f64 / duration.as_secs_f64();

            results.insert(
                format,
                BenchmarkMetrics {
                    avg_time_per_op: avg_time,
                    throughput_ops_per_sec: throughput,
                    avg_size_bytes: total_size / iterations,
                    total_time: duration,
                },
            );
        }

        Ok(BenchmarkResult {
            iterations,
            results,
        })
    }

    /// Shutdown the serialization manager
    pub async fn shutdown(&self) -> Result<()> {
        // Cleanup components
        if let Some(compression_engine) = &self.compression_engine {
            compression_engine.shutdown().await?;
        }

        Ok(())
    }
}

/// Benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Number of iterations
    pub iterations: usize,
    /// Results per format
    pub results: std::collections::HashMap<SerializationFormat, BenchmarkMetrics>,
}

/// Benchmark metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    /// Average time per operation
    pub avg_time_per_op: std::time::Duration,
    /// Throughput in operations per second
    pub throughput_ops_per_sec: f64,
    /// Average size in bytes
    pub avg_size_bytes: usize,
    /// Total time taken
    pub total_time: std::time::Duration,
}

impl Default for SerializationConfig {
    fn default() -> Self {
        Self {
            default_format: SerializationFormat::Binary,
            compression_enabled: true,
            compression_threshold: 1024, // 1KB
            protocol_negotiation_enabled: true,
            backward_compatibility_enabled: true,
            compatibility_level: CompatibilityLevel::Minor,
            max_message_size: 100 * 1024 * 1024, // 100MB
            serialization_timeout_ms: 5000,      // 5 seconds
        }
    }
}

impl Default for SerializationMetrics {
    fn default() -> Self {
        Self {
            total_serializations: 0,
            total_deserializations: 0,
            avg_serialization_time_us: 0.0,
            avg_deserialization_time_us: 0.0,
            total_bytes_serialized: 0,
            total_bytes_deserialized: 0,
            compression_ratio: 1.0,
            format_usage: std::collections::HashMap::new(),
            error_count: 0,
            last_updated: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug)]
    struct TestData {
        id: u64,
        name: String,
        data: Vec<u8>,
    }

    #[tokio::test]
    async fn test_serialization_manager() {
        let config = SerializationConfig::default();
        let manager = SerializationManager::new(config).unwrap();

        let test_data = TestData {
            id: 123,
            name: "test".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };

        // Test serialization
        let serialized = manager.serialize(&test_data, None).await.unwrap();
        assert!(!serialized.is_empty());

        // Test deserialization
        let deserialized: TestData = manager
            .deserialize(&serialized, SerializationFormat::Binary)
            .await
            .unwrap();
        assert_eq!(deserialized.id, test_data.id);
        assert_eq!(deserialized.name, test_data.name);
        assert_eq!(deserialized.data, test_data.data);
    }

    #[tokio::test]
    async fn test_protocol_negotiation() {
        let config = SerializationConfig::default();
        let manager = SerializationManager::new(config).unwrap();

        let peer_formats = vec![SerializationFormat::Binary, SerializationFormat::Json];

        let negotiated = manager.negotiate_protocol(&peer_formats).await.unwrap();
        assert!(peer_formats.contains(&negotiated));
    }

    #[tokio::test]
    async fn test_compatibility_check() {
        let config = SerializationConfig::default();
        let manager = SerializationManager::new(config).unwrap();

        let compatible = manager.check_compatibility("1.0.0").await.unwrap();
        assert!(compatible);
    }
}
