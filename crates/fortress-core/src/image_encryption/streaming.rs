//! Streaming image encryption for large images in Fortress
//!
//! This module provides streaming encryption capabilities for large images including:
//! - Chunked encryption for memory efficiency
//! - Progressive encryption/decryption
//! - Parallel processing of chunks
//! - Resumable encryption operations
//! - Memory-efficient streaming for very large files

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptionAlgorithm, SecureKey, EncryptedData};
use crate::image_encryption::{
    ImageFormat, EncryptionOptions, EncryptionMode, ImageEncryptionError, 
    encryptor::ImageEncryptorFactory, EncryptedImage, ImageFormatInfo, 
    ColorSpace, CompressionInfo, EncryptionStats
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use bytes::Bytes;

/// Chunk configuration for streaming encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkConfig {
    /// Chunk size in bytes
    pub chunk_size: usize,
    /// Number of parallel workers
    pub parallel_workers: usize,
    /// Buffer size for streaming
    pub buffer_size: usize,
    /// Whether to compress chunks before encryption
    pub compress_chunks: bool,
    /// Compression level (if compression is enabled)
    pub compression_level: Option<u8>,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1MB chunks
            parallel_workers: num_cpus::get(),
            buffer_size: 8 * 1024 * 1024, // 8MB buffer
            compress_chunks: false,
            compression_level: Some(6),
        }
    }
}

/// Streaming encryption state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingState {
    /// Unique session identifier
    pub session_id: String,
    /// Total file size
    pub total_size: usize,
    /// Processed bytes count
    pub processed_bytes: usize,
    /// Current chunk index
    pub current_chunk: usize,
    /// Total number of chunks
    pub total_chunks: usize,
    /// Encryption status
    pub status: StreamingStatus,
    /// Start timestamp
    pub started_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Error information (if any)
    pub error: Option<String>,
}

/// Streaming status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamingStatus {
    /// Not started
    NotStarted,
    /// In progress
    InProgress,
    /// Paused
    Paused,
    /// Completed successfully
    Completed,
    /// Failed with error
    Failed,
    /// Cancelled by user
    Cancelled,
}

/// Encrypted chunk information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    /// Chunk index
    pub index: usize,
    /// Encrypted data
    pub data: Bytes,
    /// Original size before encryption
    pub original_size: usize,
    /// Checksum for integrity verification
    pub checksum: String,
    /// Compression information (if applicable)
    pub compression_info: Option<CompressionInfo>,
    /// Chunk metadata
    pub metadata: HashMap<String, String>,
}

/// Streaming encryption result
#[derive(Debug, Clone)]
pub struct StreamingResult {
    /// Session identifier
    pub session_id: String,
    /// Encrypted chunks
    pub chunks: Vec<EncryptedChunk>,
    /// Final state
    pub final_state: StreamingState,
    /// Total encryption time
    pub total_time_ms: u64,
    /// Average throughput (bytes/second)
    pub throughput_bps: f64,
    /// Additional statistics
    pub statistics: StreamingStatistics,
}

/// Streaming statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingStatistics {
    /// Total bytes processed
    pub total_bytes: usize,
    /// Total chunks processed
    pub total_chunks: usize,
    /// Average chunk size
    pub avg_chunk_size: f64,
    /// Min chunk size
    pub min_chunk_size: usize,
    /// Max chunk size
    pub max_chunk_size: usize,
    /// Total compression ratio (if applicable)
    pub total_compression_ratio: Option<f64>,
    /// Peak memory usage (bytes)
    pub peak_memory_usage: usize,
    /// CPU usage percentage (average)
    pub avg_cpu_usage: f64,
}

/// Streaming image encryptor
pub struct StreamingImageEncryptor {
    encryption_algorithm: Box<dyn EncryptionAlgorithm>,
    chunk_config: ChunkConfig,
    active_sessions: Arc<RwLock<HashMap<String, StreamingState>>>,
}

/// Compress chunk data
pub async fn compress_chunk(data: &[u8]) -> Result<Vec<u8>> {
    // This is a placeholder implementation
    // In practice, we would use compression libraries like lz4, zstd, etc.
    Ok(data.to_vec())
}

/// Decompress chunk data
pub async fn decompress_chunk(data: &[u8], _compression_info: &CompressionInfo) -> Result<Vec<u8>> {
    // Placeholder implementation
    Ok(data.to_vec())
}

/// Calculate checksum for data integrity
fn calculate_checksum(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

impl StreamingImageEncryptor {
    /// Create a new streaming image encryptor
    pub fn new(encryption_algorithm: Box<dyn EncryptionAlgorithm>, chunk_config: ChunkConfig) -> Self {
        Self {
            encryption_algorithm,
            chunk_config,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start streaming encryption session
    pub async fn start_encryption_session(
        &self,
        image_data: &[u8],
        options: EncryptionOptions,
    ) -> Result<String> {
        let session_id = self.generate_session_id();
        let total_size = image_data.len();
        let total_chunks = self.calculate_chunk_count(total_size);

        let state = StreamingState {
            session_id: session_id.clone(),
            total_size,
            processed_bytes: 0,
            current_chunk: 0,
            total_chunks,
            status: StreamingStatus::NotStarted,
            started_at: Utc::now(),
            updated_at: Utc::now(),
            error: None,
        };

        // Store session state
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(session_id.clone(), state);
        }

        tracing::info!(
            "Started streaming encryption session: {}, size: {}, chunks: {}",
            session_id, total_size, total_chunks
        );

        Ok(session_id)
    }

    /// Encrypt image data in streaming fashion
    pub async fn encrypt_streaming(
        &self,
        session_id: &str,
        image_data: &[u8],
        options: EncryptionOptions,
        key: &SecureKey,
    ) -> Result<StreamingResult> {
        let start_time = std::time::Instant::now();

        // Validate session
        self.validate_session(session_id).await?;

        // Update session status to in progress
        self.update_session_status(session_id, StreamingStatus::InProgress).await?;

        // Detect image format
        let format = crate::image_encryption::ImageFormatDetector::detect(image_data)?;
        if format == crate::image_encryption::ImageFormat::Unknown {
            return Err(ImageEncryptionError::UnsupportedFormat("Unknown image format".to_string()).into());
        }

        // Process image based on encryption mode
        let processed_data = match options.encryption_mode {
            EncryptionMode::Full => image_data.to_vec(),
            EncryptionMode::DataOnly => self.extract_image_data_only(image_data, format)?,
            EncryptionMode::Regional => image_data.to_vec(), // Simplified for now
            EncryptionMode::FormatAware => image_data.to_vec(), // Simplified for now
        };

        // Split into chunks
        let chunks = self.split_into_chunks(&processed_data).await?;

        // Encrypt chunks in parallel
        let encrypted_chunks = self.encrypt_chunks_parallel(chunks, key).await?;

        // Update final state
        let final_state = self.update_session_completion(session_id, processed_data.len()).await?;

        // Calculate statistics
        let total_time = start_time.elapsed();
        let throughput_bps = processed_data.len() as f64 / total_time.as_secs_f64();
        let statistics = self.calculate_statistics(&encrypted_chunks, &processed_data).await?;

        let result = StreamingResult {
            session_id: session_id.to_string(),
            chunks: encrypted_chunks,
            final_state,
            total_time_ms: total_time.as_millis() as u64,
            throughput_bps,
            statistics,
        };

        tracing::info!(
            "Completed streaming encryption: {}, time: {}ms, throughput: {:.2} MB/s",
            session_id,
            result.total_time_ms,
            result.throughput_bps / (1024.0 * 1024.0)
        );

        Ok(result)
    }

    /// Decrypt streaming image data
    pub async fn decrypt_streaming(
        &self,
        encrypted_chunks: &[EncryptedChunk],
        key: &SecureKey,
    ) -> Result<Vec<u8>> {
        if encrypted_chunks.is_empty() {
            return Err(ImageEncryptionError::CorruptedData("No chunks to decrypt".to_string()).into());
        }

        // Sort chunks by index
        let mut sorted_chunks = encrypted_chunks.to_vec();
        sorted_chunks.sort_by_key(|chunk| chunk.index);

        // Decrypt chunks in parallel
        let decrypted_chunks = self.decrypt_chunks_parallel(sorted_chunks, key).await?;

        // Combine decrypted data
        let mut result = Vec::with_capacity(decrypted_chunks.iter().map(|chunk| chunk.len()).sum());
        for chunk in decrypted_chunks {
            result.extend_from_slice(&chunk);
        }

        Ok(result)
    }

    /// Get session status
    pub async fn get_session_status(&self, session_id: &str) -> Result<Option<StreamingState>> {
        let sessions = self.active_sessions.read().await;
        Ok(sessions.get(session_id).cloned())
    }

    /// Cancel streaming session
    pub async fn cancel_session(&self, session_id: &str) -> Result<()> {
        self.update_session_status(session_id, StreamingStatus::Cancelled).await?;
        
        // Remove session from active sessions
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.remove(session_id);
        }

        tracing::info!("Cancelled streaming encryption session: {}", session_id);
        Ok(())
    }

    /// Pause streaming session
    pub async fn pause_session(&self, session_id: &str) -> Result<()> {
        self.update_session_status(session_id, StreamingStatus::Paused).await?;
        tracing::info!("Paused streaming encryption session: {}", session_id);
        Ok(())
    }

    /// Resume streaming session
    pub async fn resume_session(&self, session_id: &str) -> Result<()> {
        self.update_session_status(session_id, StreamingStatus::InProgress).await?;
        tracing::info!("Resumed streaming encryption session: {}", session_id);
        Ok(())
    }

    // Private helper methods

    /// Generate unique session ID
    fn generate_session_id(&self) -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string()
    }

    /// Calculate number of chunks for given data size
    fn calculate_chunk_count(&self, data_size: usize) -> usize {
        if data_size == 0 {
            return 0;
        }
        (data_size + self.chunk_config.chunk_size - 1) / self.chunk_config.chunk_size
    }

    /// Validate session exists
    async fn validate_session(&self, session_id: &str) -> Result<()> {
        let sessions = self.active_sessions.read().await;
        if !sessions.contains_key(session_id) {
            return Err(FortressError::encryption(
                format!("Session not found: {}", session_id),
                "streaming_encryptor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ));
        }
        Ok(())
    }

    /// Update session status
    async fn update_session_status(&self, session_id: &str, status: StreamingStatus) -> Result<()> {
        let mut sessions = self.active_sessions.write().await;
        if let Some(state) = sessions.get_mut(session_id) {
            state.status = status;
            state.updated_at = Utc::now();
        }
        Ok(())
    }

    /// Update session completion
    async fn update_session_completion(&self, session_id: &str, processed_bytes: usize) -> Result<StreamingState> {
        let mut sessions = self.active_sessions.write().await;
        if let Some(state) = sessions.get_mut(session_id) {
            state.status = StreamingStatus::Completed;
            state.processed_bytes = processed_bytes;
            state.current_chunk = state.total_chunks;
            state.updated_at = Utc::now();
            Ok(state.clone())
        } else {
            return Err(FortressError::encryption(
                format!("Session not found: {}", session_id),
                "streaming_encryptor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ))
        }
    }

    /// Extract image data only for data-only encryption
    fn extract_image_data_only(&self, data: &[u8], format: ImageFormat) -> Result<Vec<u8>> {
        let header_size = format.header_size();
        
        if data.len() <= header_size {
            return Err(ImageEncryptionError::CorruptedData("Image too small for data-only encryption".to_string()).into());
        }

        // Return only the image data portion
        Ok(data[header_size..].to_vec())
    }

    /// Split data into chunks
    async fn split_into_chunks(&self, data: &[u8]) -> Result<Vec<Bytes>> {
        let chunk_size = self.chunk_config.chunk_size;
        let total_chunks = self.calculate_chunk_count(data.len());
        let mut chunks = Vec::with_capacity(total_chunks);

        for i in 0..total_chunks {
            let start = i * chunk_size;
            let end = std::cmp::min(start + chunk_size, data.len());
            let chunk_data = Bytes::copy_from_slice(&data[start..end]);
            chunks.push(chunk_data);
        }

        Ok(chunks)
    }

    /// Encrypt chunks in parallel
    async fn encrypt_chunks_parallel(&self, chunks: Vec<Bytes>, key: &SecureKey) -> Result<Vec<EncryptedChunk>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.chunk_config.parallel_workers));
        let key = Arc::new(key.clone());
        let chunk_config = self.chunk_config.clone();
        
        let mut tasks = Vec::with_capacity(chunks.len());

        for (index, chunk) in chunks.into_iter().enumerate() {
            let semaphore = Arc::clone(&semaphore);
            let key = Arc::clone(&key);
            let chunk_config = chunk_config.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.map_err(|_| {
                    FortressError::encryption(
                        "Failed to acquire semaphore permit".to_string(),
                        "streaming_encryptor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    )
                })?;

                // Compress chunk if enabled
                let processed_chunk = if chunk_config.compress_chunks {
                    compress_chunk(&chunk).await?
                } else {
                    chunk.to_vec()
                };

                // Store the original length for compression info
                let processed_chunk_len = processed_chunk.len();

                // Encrypt chunk using the algorithm name
                let encrypted_image = {
                    let encryptor = ImageEncryptorFactory::create_encryptor("chacha20poly1305")?;
                    encryptor.encrypt(processed_chunk, EncryptionOptions::default(), &key).await?
                };
                let encrypted_data = encrypted_image.encrypted_data.ciphertext;

                // Calculate checksum
                let checksum = calculate_checksum(&encrypted_data);

                // Create compression info
                let compression_info = if chunk_config.compress_chunks {
                    Some(CompressionInfo {
                        compression_type: "lz4".to_string(),
                        level: None,
                        is_lossy: false,
                        ratio: Some(processed_chunk_len as f64 / chunk.len() as f64),
                    })
                } else {
                    None
                };

                let mut metadata = HashMap::new();
                metadata.insert("chunk_index".to_string(), index.to_string());
                metadata.insert("original_size".to_string(), chunk.len().to_string());
                metadata.insert("encrypted_size".to_string(), encrypted_data.len().to_string());

                Ok(EncryptedChunk {
                    index,
                    data: Bytes::from(encrypted_data),
                    original_size: chunk.len(),
                    checksum,
                    compression_info,
                    metadata,
                })
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        let results = futures::future::join_all(tasks).await;
        let mut encrypted_chunks = Vec::with_capacity(results.len());

        for result in results {
            match result {
                Ok(Ok(chunk)) => encrypted_chunks.push(chunk),
                Ok(Err(e)) => return Err(e),
                Err(e) => {
                    return Err(FortressError::encryption(
                        format!("Task join error: {}", e),
                        "streaming_encryptor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ))
                }
            }
        }

        Ok(encrypted_chunks)
    }

    /// Decrypt chunks in parallel
    async fn decrypt_chunks_parallel(&self, chunks: Vec<EncryptedChunk>, key: &SecureKey) -> Result<Vec<Vec<u8>>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.chunk_config.parallel_workers));
        let key = Arc::new(key.clone());

        let mut tasks = Vec::with_capacity(chunks.len());

        for chunk in chunks {
            let semaphore = Arc::clone(&semaphore);
            let key = Arc::clone(&key);

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.map_err(|_| {
                    FortressError::encryption(
                        "Failed to acquire semaphore permit".to_string(),
                        "streaming_encryptor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    )
                })?;

                // Decrypt chunk using the algorithm name
                let decrypted_data: Vec<u8> = {
                    let encryptor = ImageEncryptorFactory::create_encryptor("chacha20poly1305")?;
                    // We need to create an EncryptedImage from the chunk data
                    let encrypted_image = EncryptedImage {
                        encrypted_data: EncryptedData::new(
                            chunk.data.clone(),
                            "chacha20poly1305".to_string(),
                        ),
                        encryption_options: EncryptionOptions::default(),
                        format_info: ImageFormatInfo {
                            format: ImageFormat::Unknown,
                            mime_type: "application/octet-stream".to_string(),
                            extension: "bin".to_string(),
                            supports_lossless: false,
                            supports_multiple_pages: false,
                            format_metadata: HashMap::new(),
                        },
                        original_size: chunk.original_size,
                        metadata: None,
                        thumbnail: None,
                        encrypted_at: Utc::now(),
                        dimensions: None,
                        additional_info: HashMap::new(),
                    };
                    encryptor.decrypt(&encrypted_image, &key).await?
                };

                // Verify checksum
                let calculated_checksum = calculate_checksum(&chunk.data);
                if calculated_checksum != chunk.checksum {
                    return Err(FortressError::encryption(
                        "Chunk checksum verification failed".to_string(),
                        "streaming_decryptor".to_string(),
                        crate::error::EncryptionErrorCode::DecryptionFailed,
                    ));
                }

                // Decompress if needed
                let final_data = if let Some(_compression_info) = &chunk.compression_info {
                    decompress_chunk(&decrypted_data, &CompressionInfo {
                        compression_type: "lz4".to_string(),
                        level: None,
                        is_lossy: false,
                        ratio: Some(0.0),
                    }).await?
                } else {
                    decrypted_data.to_vec()
                };

                Ok(final_data)
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        let results = futures::future::join_all(tasks).await;
        let mut decrypted_chunks = Vec::with_capacity(results.len());

        for result in results {
            match result {
                Ok(Ok(chunk)) => decrypted_chunks.push(chunk),
                Ok(Err(e)) => return Err(e),
                Err(e) => {
                    return Err(FortressError::encryption(
                        format!("Task join error: {}", e),
                        "streaming_encryptor".to_string(),
                        crate::error::EncryptionErrorCode::DecryptionFailed,
                    ))
                }
            }
        }

        Ok(decrypted_chunks)
    }

    /// Calculate streaming statistics
    async fn calculate_statistics(&self, chunks: &[EncryptedChunk], original_data: &[u8]) -> Result<StreamingStatistics> {
        let total_chunks = chunks.len();
        let total_bytes = original_data.len();
        
        let chunk_sizes: Vec<usize> = chunks.iter().map(|chunk| chunk.original_size).collect();
        let avg_chunk_size = if !chunk_sizes.is_empty() {
            chunk_sizes.iter().sum::<usize>() as f64 / chunk_sizes.len() as f64
        } else {
            0.0
        };
        
        let min_chunk_size = chunk_sizes.iter().min().copied().unwrap_or(0);
        let max_chunk_size = chunk_sizes.iter().max().copied().unwrap_or(0);

        // Calculate total compression ratio
        let total_compression_ratio = if chunks.iter().any(|chunk| chunk.compression_info.is_some()) {
            // Since we don't have original_size and compressed_size fields in the new CompressionInfo,
            // we'll use the ratio field directly if available
            let ratios: Vec<f64> = chunks.iter()
                .filter_map(|chunk| chunk.compression_info.as_ref())
                .filter_map(|info| info.ratio)
                .collect();
            
            if !ratios.is_empty() {
                Some(ratios.iter().sum::<f64>() / ratios.len() as f64)
            } else {
                None
            }
        } else {
            None
        };

        Ok(StreamingStatistics {
            total_bytes,
            total_chunks,
            avg_chunk_size,
            min_chunk_size,
            max_chunk_size,
            total_compression_ratio,
            peak_memory_usage: 0, // Would need memory tracking
            avg_cpu_usage: 0.0,   // Would need CPU monitoring
        })
    }

    /// Get active sessions count
    pub async fn get_active_sessions_count(&self) -> usize {
        let sessions = self.active_sessions.read().await;
        sessions.len()
    }

    /// Clean up completed sessions
    pub async fn cleanup_completed_sessions(&self) -> Result<usize> {
        let mut sessions = self.active_sessions.write().await;
        let initial_count = sessions.len();
        
        sessions.retain(|_, state| {
            matches!(state.status, StreamingStatus::NotStarted | StreamingStatus::InProgress | StreamingStatus::Paused)
        });
        
        let cleaned_count = initial_count - sessions.len();
        tracing::info!("Cleaned up {} completed streaming sessions", cleaned_count);
        
        Ok(cleaned_count)
    }
}

/// Streaming image decryptor
pub struct StreamingImageDecryptor {
    encryption_algorithm: Box<dyn EncryptionAlgorithm>,
}

impl StreamingImageDecryptor {
    /// Create a new streaming image decryptor
    pub fn new(encryption_algorithm: Box<dyn EncryptionAlgorithm>) -> Self {
        Self {
            encryption_algorithm,
        }
    }

    /// Decrypt streaming image with progress callback
    pub async fn decrypt_with_progress<F>(
        &self,
        encrypted_chunks: &[EncryptedChunk],
        key: &SecureKey,
        progress_callback: F,
    ) -> Result<Vec<u8>>
    where
        F: Fn(usize, usize) + Send + Sync,
    {
        let total_chunks = encrypted_chunks.len();
        let mut decrypted_data = Vec::new();

        for (index, chunk) in encrypted_chunks.iter().enumerate() {
            // Decrypt chunk
            let decrypted_chunk = self.encryption_algorithm.decrypt(&chunk.data, key.as_bytes())?;

            // Verify checksum
            let calculated_checksum = calculate_checksum(&chunk.data);
            if calculated_checksum != chunk.checksum {
                return Err(FortressError::encryption(
                    "Chunk checksum verification failed".to_string(),
                    "streaming_decryptor".to_string(),
                    crate::error::EncryptionErrorCode::DecryptionFailed,
                ));
            }

            // Decompress if needed
            let final_chunk = if let Some(compression_info) = &chunk.compression_info {
                decompress_chunk(&decrypted_chunk, compression_info).await?
            } else {
                decrypted_chunk
            };

            decrypted_data.extend_from_slice(&final_chunk);

            // Report progress
            progress_callback(index + 1, total_chunks);
        }

        Ok(decrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::ChaCha20Poly1305;

    #[test]
    fn test_chunk_config_default() {
        let config = ChunkConfig::default();
        assert_eq!(config.chunk_size, 1024 * 1024);
        assert_eq!(config.parallel_workers, num_cpus::get());
        assert_eq!(config.buffer_size, 8 * 1024 * 1024);
        assert!(!config.compress_chunks);
        assert_eq!(config.compression_level, Some(6));
    }

    #[test]
    fn test_streaming_status() {
        assert_eq!(StreamingStatus::NotStarted as u8, 0);
        assert_eq!(StreamingStatus::InProgress as u8, 1);
        assert_eq!(StreamingStatus::Paused as u8, 2);
        assert_eq!(StreamingStatus::Completed as u8, 3);
        assert_eq!(StreamingStatus::Failed as u8, 4);
        assert_eq!(StreamingStatus::Cancelled as u8, 5);
    }

    #[tokio::test]
    async fn test_streaming_encryptor_creation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let config = ChunkConfig::default();
        let encryptor = StreamingImageEncryptor::new(algorithm, config);
        
        assert_eq!(encryptor.get_active_sessions_count().await, 0);
    }

    #[tokio::test]
    async fn test_encryption_session_lifecycle() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let config = ChunkConfig::default();
        let encryptor = StreamingImageEncryptor::new(algorithm, config);
        
        let image_data = vec![0u8; 1024 * 1024]; // 1MB test data
        let options = crate::image_encryption::EncryptionOptions::default();
        
        // Start session
        let session_id = encryptor.start_encryption_session(&image_data, options.clone()).await.unwrap();
        assert_eq!(encryptor.get_active_sessions_count().await, 1);
        
        // Check session status
        let status = encryptor.get_session_status(&session_id).await.unwrap();
        assert!(status.is_some());
        assert_eq!(status.unwrap().status, StreamingStatus::NotStarted);
        
        // Pause session
        encryptor.pause_session(&session_id).await.unwrap();
        let status = encryptor.get_session_status(&session_id).await.unwrap();
        assert_eq!(status.unwrap().status, StreamingStatus::Paused);
        
        // Resume session
        encryptor.resume_session(&session_id).await.unwrap();
        let status = encryptor.get_session_status(&session_id).await.unwrap();
        assert_eq!(status.unwrap().status, StreamingStatus::InProgress);
        
        // Cancel session
        encryptor.cancel_session(&session_id).await.unwrap();
        assert_eq!(encryptor.get_active_sessions_count().await, 0);
    }

    #[tokio::test]
    async fn test_chunk_calculation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let config = ChunkConfig {
            chunk_size: 1024,
            ..Default::default()
        };
        let encryptor = StreamingImageEncryptor::new(algorithm, config);
        
        // Test various sizes
        assert_eq!(encryptor.calculate_chunk_count(0), 0);
        assert_eq!(encryptor.calculate_chunk_count(512), 1);
        assert_eq!(encryptor.calculate_chunk_count(1024), 1);
        assert_eq!(encryptor.calculate_chunk_count(1025), 2);
        assert_eq!(encryptor.calculate_chunk_count(2048), 2);
        assert_eq!(encryptor.calculate_chunk_count(2049), 3);
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let config = ChunkConfig::default();
        let encryptor = StreamingImageEncryptor::new(algorithm, config);
        
        let image_data = vec![0u8; 1024];
        let options = crate::image_encryption::EncryptionOptions::default();
        
        // Start multiple sessions
        let session1 = encryptor.start_encryption_session(&image_data, options.clone()).await.unwrap();
        let session2 = encryptor.start_encryption_session(&image_data, options.clone()).await.unwrap();
        
        assert_eq!(encryptor.get_active_sessions_count().await, 2);
        
        // Cancel one session
        encryptor.cancel_session(&session1).await.unwrap();
        assert_eq!(encryptor.get_active_sessions_count().await, 1);
        
        // Cleanup completed sessions
        let cleaned = encryptor.cleanup_completed_sessions().await.unwrap();
        assert_eq!(cleaned, 1);
        assert_eq!(encryptor.get_active_sessions_count().await, 0);
    }

    #[test]
    fn test_encrypted_chunk() {
        let chunk = EncryptedChunk {
            index: 0,
            data: Bytes::from("test_data"),
            original_size: 9,
            checksum: "test_checksum".to_string(),
            compression_info: None,
            metadata: HashMap::new(),
        };
        
        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.original_size, 9);
        assert_eq!(chunk.checksum, "test_checksum");
    }

    #[test]
    fn test_compression_info() {
        let info = CompressionInfo {
            compression_type: "lz4".to_string(),
            level: Some(6),
            is_lossy: false,
            ratio: Some(0.5),
        };
        
        assert_eq!(info.compression_type, "lz4");
        assert_eq!(info.level, Some(6));
        assert_eq!(info.is_lossy, false);
        assert_eq!(info.ratio, Some(0.5));
    }
}
