//! Protocol Negotiation Module
//!
//! This module provides protocol negotiation capabilities for Fortress
//! to automatically select the best serialization format for communication.

use super::SerializationFormat;
use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Protocol negotiator for automatic format selection
pub struct ProtocolNegotiator {
    /// Supported formats with capabilities
    supported_formats: HashMap<SerializationFormat, FormatCapabilities>,
    /// Format preferences (higher = more preferred)
    format_preferences: HashMap<SerializationFormat, u8>,
    /// Negotiation metrics
    metrics: Arc<RwLock<NegotiationMetrics>>,
    /// Cache for negotiated formats
    negotiation_cache: Arc<RwLock<HashMap<String, SerializationFormat>>>,
}

/// Format capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatCapabilities {
    /// Format name
    pub name: String,
    /// Performance score (0-100)
    pub performance_score: u8,
    /// Compatibility score (0-100)
    pub compatibility_score: u8,
    /// Compression support
    pub compression_support: bool,
    /// Schema evolution support
    pub schema_evolution: bool,
    /// Human readable
    pub human_readable: bool,
    /// Binary format
    pub binary: bool,
    /// Maximum message size
    pub max_message_size: usize,
    /// Supported data types
    pub supported_types: Vec<String>,
}

/// Negotiation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationMetrics {
    /// Total negotiations
    pub total_negotiations: u64,
    /// Successful negotiations
    pub successful_negotiations: u64,
    /// Failed negotiations
    pub failed_negotiations: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Average negotiation time in microseconds
    pub avg_negotiation_time_us: f64,
    /// Format selection statistics
    pub format_selections: HashMap<SerializationFormat, u64>,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Negotiation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationRequest {
    /// Client supported formats
    pub client_formats: Vec<SerializationFormat>,
    /// Client capabilities
    pub client_capabilities: HashMap<SerializationFormat, FormatCapabilities>,
    /// Negotiation preferences
    pub preferences: NegotiationPreferences,
}

/// Negotiation preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationPreferences {
    /// Prefer performance
    pub prefer_performance: bool,
    /// Prefer compatibility
    pub prefer_compatibility: bool,
    /// Prefer human readable
    pub prefer_human_readable: bool,
    /// Prefer binary
    pub prefer_binary: bool,
    /// Minimum compatibility score
    pub min_compatibility_score: u8,
}

/// Negotiation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationResponse {
    /// Selected format
    pub selected_format: SerializationFormat,
    /// Negotiation reason
    pub reason: String,
    /// Server capabilities for selected format
    pub server_capabilities: FormatCapabilities,
}

impl ProtocolNegotiator {
    /// Create a new protocol negotiator
    pub fn new() -> Result<Self> {
        let mut negotiator = Self {
            supported_formats: HashMap::new(),
            format_preferences: HashMap::new(),
            metrics: Arc::new(RwLock::new(NegotiationMetrics::default())),
            negotiation_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // Initialize supported formats
        negotiator.initialize_supported_formats();

        Ok(negotiator)
    }

    /// Initialize supported formats with their capabilities
    fn initialize_supported_formats(&mut self) {
        // Binary format
        self.supported_formats.insert(
            SerializationFormat::Binary,
            FormatCapabilities {
                name: "Fortress Binary".to_string(),
                performance_score: 95,
                compatibility_score: 80,
                compression_support: true,
                schema_evolution: true,
                human_readable: false,
                binary: true,
                max_message_size: 100 * 1024 * 1024, // 100MB
                supported_types: vec![
                    "bool".to_string(),
                    "i8".to_string(),
                    "i16".to_string(),
                    "i32".to_string(),
                    "i64".to_string(),
                    "u8".to_string(),
                    "u16".to_string(),
                    "u32".to_string(),
                    "u64".to_string(),
                    "f32".to_string(),
                    "f64".to_string(),
                    "string".to_string(),
                    "bytes".to_string(),
                    "vec".to_string(),
                    "map".to_string(),
                    "option".to_string(),
                    "struct".to_string(),
                    "enum".to_string(),
                ],
            },
        );

        // JSON format
        self.supported_formats.insert(
            SerializationFormat::Json,
            FormatCapabilities {
                name: "JSON".to_string(),
                performance_score: 60,
                compatibility_score: 95,
                compression_support: true,
                schema_evolution: true,
                human_readable: true,
                binary: false,
                max_message_size: 50 * 1024 * 1024, // 50MB
                supported_types: vec![
                    "bool".to_string(),
                    "number".to_string(),
                    "string".to_string(),
                    "array".to_string(),
                    "object".to_string(),
                    "null".to_string(),
                ],
            },
        );

        // Protocol Buffers
        self.supported_formats.insert(
            SerializationFormat::Protobuf,
            FormatCapabilities {
                name: "Protocol Buffers".to_string(),
                performance_score: 90,
                compatibility_score: 85,
                compression_support: true,
                schema_evolution: true,
                human_readable: false,
                binary: true,
                max_message_size: 200 * 1024 * 1024, // 200MB
                supported_types: vec![
                    "bool".to_string(),
                    "int32".to_string(),
                    "int64".to_string(),
                    "uint32".to_string(),
                    "uint64".to_string(),
                    "float".to_string(),
                    "double".to_string(),
                    "string".to_string(),
                    "bytes".to_string(),
                    "enum".to_string(),
                    "message".to_string(),
                    "repeated".to_string(),
                    "map".to_string(),
                    "oneof".to_string(),
                ],
            },
        );

        // MessagePack
        self.supported_formats.insert(
            SerializationFormat::MessagePack,
            FormatCapabilities {
                name: "MessagePack".to_string(),
                performance_score: 85,
                compatibility_score: 90,
                compression_support: true,
                schema_evolution: true,
                human_readable: false,
                binary: true,
                max_message_size: 150 * 1024 * 1024, // 150MB
                supported_types: vec![
                    "bool".to_string(),
                    "int".to_string(),
                    "uint".to_string(),
                    "float".to_string(),
                    "str".to_string(),
                    "bin".to_string(),
                    "array".to_string(),
                    "map".to_string(),
                    "ext".to_string(),
                    "nil".to_string(),
                ],
            },
        );

        // CBOR
        self.supported_formats.insert(
            SerializationFormat::Cbor,
            FormatCapabilities {
                name: "CBOR".to_string(),
                performance_score: 80,
                compatibility_score: 88,
                compression_support: true,
                schema_evolution: true,
                human_readable: false,
                binary: true,
                max_message_size: 120 * 1024 * 1024, // 120MB
                supported_types: vec![
                    "bool".to_string(),
                    "int".to_string(),
                    "uint".to_string(),
                    "float".to_string(),
                    "string".to_string(),
                    "bytes".to_string(),
                    "array".to_string(),
                    "map".to_string(),
                    "tag".to_string(),
                    "simple".to_string(),
                ],
            },
        );

        // Set format preferences (higher = more preferred)
        self.format_preferences
            .insert(SerializationFormat::Binary, 100);
        self.format_preferences
            .insert(SerializationFormat::Protobuf, 90);
        self.format_preferences
            .insert(SerializationFormat::MessagePack, 85);
        self.format_preferences
            .insert(SerializationFormat::Cbor, 80);
        self.format_preferences
            .insert(SerializationFormat::Json, 70);
    }

    /// Negotiate protocol with peer capabilities
    pub fn negotiate(&self, peer_formats: &[SerializationFormat]) -> Result<SerializationFormat> {
        let start = std::time::Instant::now();

        // Find common formats
        let common_formats: Vec<&SerializationFormat> = peer_formats
            .iter()
            .filter(|format| self.supported_formats.contains_key(format))
            .collect();

        if common_formats.is_empty() {
            return Err(FortressError::serialization(
                "No common format found",
                &format!("Peer formats: {:?}", peer_formats),
            ));
        }

        // Select best format based on preferences and capabilities
        let selected_format = self.select_best_format(&common_formats)?;

        // Update metrics
        {
            let mut metrics = self.metrics.try_write().unwrap();
            metrics.total_negotiations += 1;
            metrics.successful_negotiations += 1;
            metrics.avg_negotiation_time_us = (metrics.avg_negotiation_time_us
                * (metrics.total_negotiations - 1) as f64
                + start.elapsed().as_micros() as f64)
                / metrics.total_negotiations as f64;

            *metrics
                .format_selections
                .entry(selected_format.clone())
                .or_insert(0) += 1;
            metrics.last_updated = chrono::Utc::now();
        }

        Ok(selected_format)
    }

    /// Negotiate protocol with full request/response
    pub async fn negotiate_full(&self, request: NegotiationRequest) -> Result<NegotiationResponse> {
        let start = std::time::Instant::now();

        // Check cache first
        let cache_key = self.generate_cache_key(&request);
        {
            let cache = self.negotiation_cache.read().await;
            if let Some(&cached_format) = cache.get(&cache_key) {
                let mut metrics = self.metrics.write().await;
                metrics.cache_hits += 1;

                let cached_format_clone = cached_format.clone();
                return Ok(NegotiationResponse {
                    selected_format: cached_format,
                    reason: "Cached negotiation result".to_string(),
                    server_capabilities: self.supported_formats[&cached_format_clone].clone(),
                });
            }
        }

        // Perform negotiation
        let selected_format = self.negotiate(&request.client_formats)?;

        let reason = self.generate_negotiation_reason(&request, &selected_format);
        let server_capabilities = self.supported_formats[&selected_format].clone();

        // Cache the result
        {
            let mut cache = self.negotiation_cache.write().await;
            cache.insert(cache_key, selected_format.clone());
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.cache_misses += 1;
            metrics.total_negotiations += 1;
            metrics.successful_negotiations += 1;
            metrics.avg_negotiation_time_us = (metrics.avg_negotiation_time_us
                * (metrics.total_negotiations - 1) as f64
                + start.elapsed().as_micros() as f64)
                / metrics.total_negotiations as f64;
            metrics.last_updated = chrono::Utc::now();
        }

        Ok(NegotiationResponse {
            selected_format,
            reason,
            server_capabilities,
        })
    }

    /// Select best format from common formats
    fn select_best_format(
        &self,
        common_formats: &[&SerializationFormat],
    ) -> Result<SerializationFormat> {
        // Score each format based on multiple criteria
        let mut scored_formats: Vec<(SerializationFormat, u32)> = common_formats
            .iter()
            .map(|&&format| {
                let capabilities = &self.supported_formats[&format];
                let preference = self.format_preferences[&format] as u32;

                // Calculate composite score
                let performance_score = capabilities.performance_score as u32 * 2;
                let compatibility_score = capabilities.compatibility_score as u32;
                let preference_score = preference * 3;

                let total_score = performance_score + compatibility_score + preference_score;

                (format, total_score)
            })
            .collect();

        // Sort by score (descending)
        scored_formats.sort_by(|a, b| b.1.cmp(&a.1));

        // Return the highest scoring format
        scored_formats
            .into_iter()
            .next()
            .map(|(format, _score)| format)
            .ok_or_else(|| FortressError::serialization("No format selected", "Scoring failed"))
    }

    /// Generate cache key for negotiation request
    fn generate_cache_key(&self, request: &NegotiationRequest) -> String {
        let mut formats = request.client_formats.clone();
        formats.sort();

        format!(
            "{}-{:?}-{:?}",
            formats
                .iter()
                .map(|f| format!("{:?}", f))
                .collect::<Vec<_>>()
                .join(","),
            request.preferences.prefer_performance,
            request.preferences.prefer_compatibility
        )
    }

    /// Generate negotiation reason
    fn generate_negotiation_reason(
        &self,
        request: &NegotiationRequest,
        selected_format: &SerializationFormat,
    ) -> String {
        let capabilities = &self.supported_formats[selected_format];

        let mut reasons = Vec::new();

        if request.preferences.prefer_performance && capabilities.performance_score >= 90 {
            reasons.push("High performance");
        }

        if request.preferences.prefer_compatibility && capabilities.compatibility_score >= 90 {
            reasons.push("High compatibility");
        }

        if request.preferences.prefer_binary && capabilities.binary {
            reasons.push("Binary format");
        }

        if request.preferences.prefer_human_readable && capabilities.human_readable {
            reasons.push("Human readable");
        }

        if reasons.is_empty() {
            format!("Selected based on overall score: {}", capabilities.name)
        } else {
            format!("Selected {}: {}", capabilities.name, reasons.join(", "))
        }
    }

    /// Get supported formats
    pub fn get_supported_formats(&self) -> Vec<SerializationFormat> {
        self.supported_formats.keys().cloned().collect()
    }

    /// Get format capabilities
    pub fn get_format_capabilities(
        &self,
        format: &SerializationFormat,
    ) -> Option<&FormatCapabilities> {
        self.supported_formats.get(format)
    }

    /// Update format preferences
    pub fn update_preferences(&mut self, preferences: HashMap<SerializationFormat, u8>) {
        self.format_preferences = preferences;
    }

    /// Get negotiation metrics
    pub async fn get_metrics(&self) -> Result<NegotiationMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Clear negotiation cache
    pub async fn clear_cache(&self) -> Result<()> {
        self.negotiation_cache.write().await.clear();
        Ok(())
    }

    /// Get format compatibility matrix
    pub fn get_compatibility_matrix(
        &self,
    ) -> HashMap<SerializationFormat, HashMap<SerializationFormat, f64>> {
        let mut matrix = HashMap::new();

        for format1 in self.supported_formats.keys() {
            let mut compat_row = HashMap::new();

            for format2 in self.supported_formats.keys() {
                let compatibility = self.calculate_compatibility(format1, format2);
                compat_row.insert(format2.clone(), compatibility);
            }

            matrix.insert(format1.clone(), compat_row);
        }

        matrix
    }

    /// Calculate compatibility between two formats
    fn calculate_compatibility(
        &self,
        format1: &SerializationFormat,
        format2: &SerializationFormat,
    ) -> f64 {
        if format1 == format2 {
            return 1.0;
        }

        let caps1 = &self.supported_formats[format1];
        let caps2 = &self.supported_formats[format2];

        // Calculate type compatibility
        let mut common_types = 0;
        let total_types = caps1.supported_types.len();

        for type1 in &caps1.supported_types {
            if caps2.supported_types.contains(type1) {
                common_types += 1;
            }
        }

        let type_compatibility = if total_types > 0 {
            common_types as f64 / total_types as f64
        } else {
            0.0
        };

        // Calculate feature compatibility
        let mut feature_score = 0.0;
        let mut total_features = 0.0;

        if caps1.compression_support == caps2.compression_support {
            feature_score += 1.0;
        }
        total_features += 1.0;

        if caps1.schema_evolution == caps2.schema_evolution {
            feature_score += 1.0;
        }
        total_features += 1.0;

        if caps1.human_readable == caps2.human_readable {
            feature_score += 1.0;
        }
        total_features += 1.0;

        if caps1.binary == caps2.binary {
            feature_score += 1.0;
        }
        total_features += 1.0;

        let feature_compatibility = if total_features > 0.0 {
            feature_score / total_features
        } else {
            0.0
        };

        // Weighted average
        (type_compatibility * 0.7) + (feature_compatibility * 0.3)
    }

    /// Benchmark format performance
    pub async fn benchmark_formats(
        &self,
        test_data: &[u8],
        iterations: usize,
    ) -> Result<HashMap<SerializationFormat, BenchmarkResult>> {
        let mut results = HashMap::new();

        for format in self.get_supported_formats() {
            let start = std::time::Instant::now();

            // Simulate serialization/deserialization
            for _ in 0..iterations {
                // In a real implementation, this would actually serialize/deserialize
                tokio::task::yield_now().await;
            }

            let duration = start.elapsed();
            let throughput = iterations as f64 / duration.as_secs_f64();

            results.insert(
                format.clone(),
                BenchmarkResult {
                    format: format.clone(),
                    iterations,
                    total_time: duration,
                    avg_time_per_op: duration / iterations as u32,
                    throughput_ops_per_sec: throughput,
                    avg_size_bytes: test_data.len(),
                },
            );
        }

        Ok(results)
    }
}

/// Benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Format tested
    pub format: SerializationFormat,
    /// Number of iterations
    pub iterations: usize,
    /// Total time taken
    pub total_time: std::time::Duration,
    /// Average time per operation
    pub avg_time_per_op: std::time::Duration,
    /// Throughput in operations per second
    pub throughput_ops_per_sec: f64,
    /// Average size in bytes
    pub avg_size_bytes: usize,
}

impl Default for NegotiationMetrics {
    fn default() -> Self {
        Self {
            total_negotiations: 0,
            successful_negotiations: 0,
            failed_negotiations: 0,
            cache_hits: 0,
            cache_misses: 0,
            avg_negotiation_time_us: 0.0,
            format_selections: HashMap::new(),
            last_updated: chrono::Utc::now(),
        }
    }
}

impl Default for NegotiationPreferences {
    fn default() -> Self {
        Self {
            prefer_performance: true,
            prefer_compatibility: true,
            prefer_human_readable: false,
            prefer_binary: true,
            min_compatibility_score: 70,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_protocol_negotiation() {
        let negotiator = ProtocolNegotiator::new().unwrap();

        let peer_formats = vec![SerializationFormat::Binary, SerializationFormat::Json];

        let selected = negotiator.negotiate(&peer_formats).unwrap();
        assert!(peer_formats.contains(&selected));

        // Binary should be preferred over JSON
        assert_eq!(selected, SerializationFormat::Binary);
    }

    #[tokio::test]
    async fn test_full_negotiation() {
        let negotiator = ProtocolNegotiator::new().unwrap();

        let request = NegotiationRequest {
            client_formats: vec![SerializationFormat::Binary, SerializationFormat::Json],
            client_capabilities: HashMap::new(),
            preferences: NegotiationPreferences::default(),
        };

        let response = negotiator.negotiate_full(request).await.unwrap();
        assert_eq!(response.selected_format, SerializationFormat::Binary);
        assert!(!response.reason.is_empty());
    }

    #[test]
    fn test_compatibility_matrix() {
        let negotiator = ProtocolNegotiator::new().unwrap();

        let matrix = negotiator.get_compatibility_matrix();
        assert!(!matrix.is_empty());

        // Same format should have 1.0 compatibility
        let binary_compat = matrix[&SerializationFormat::Binary][&SerializationFormat::Binary];
        assert_eq!(binary_compat, 1.0);
    }

    #[tokio::test]
    async fn test_metrics() {
        let negotiator = ProtocolNegotiator::new().unwrap();

        // Perform some negotiations
        negotiator
            .negotiate(&[SerializationFormat::Binary])
            .unwrap();
        negotiator.negotiate(&[SerializationFormat::Json]).unwrap();

        let metrics = negotiator.get_metrics().await.unwrap();
        assert_eq!(metrics.total_negotiations, 2);
        assert_eq!(metrics.successful_negotiations, 2);
    }
}
