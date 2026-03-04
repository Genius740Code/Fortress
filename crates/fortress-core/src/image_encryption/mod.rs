//! Image encryption module for Fortress
//!
//! This module provides comprehensive image encryption capabilities including:
//! - Full and partial image encryption
//! - Format-aware encryption preserving image structure
//! - Metadata encryption for EXIF, IPTC, XMP data
//! - Secure thumbnail generation
//! - Streaming encryption for large images
//! - Multi-format support (JPEG, PNG, TIFF, BMP, WebP, HEIC, DICOM, RAW)

pub mod encryptor;
pub mod formats;
pub mod metadata;
pub mod streaming;
pub mod thumbnails;
pub mod api;

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptedData, SecureKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Re-export main components
pub use encryptor::ImageEncryptor;
pub use formats::{ImageFormat, ImageFormatDetector};
pub use metadata::{ImageMetadata, EncryptedMetadata};
pub use streaming::{StreamingImageEncryptor, ChunkConfig};
pub use thumbnails::{ThumbnailGenerator, ThumbnailSize, EncryptedThumbnail};
pub use api::{
    ImageEncryptionService, ImageStore, KeyManager,
    EncryptImageRequest, EncryptImageResponse, DecryptImageRequest, DecryptImageResponse,
    GenerateThumbnailsRequest, GenerateThumbnailsResponse, StartStreamingRequest, StartStreamingResponse,
    GetStreamingStatusRequest, GetStreamingStatusResponse, SearchImagesRequest, SearchImagesResponse,
    GetImageMetadataRequest, GetImageMetadataResponse, DeleteImageRequest, DeleteImageResponse,
};

/// Image encryption options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionOptions {
    /// Encryption algorithm to use
    pub algorithm: String,
    /// Whether to encrypt the entire image or just the data portion
    pub encryption_mode: EncryptionMode,
    /// Whether to encrypt metadata
    pub encrypt_metadata: bool,
    /// Chunk size for streaming (bytes)
    pub chunk_size: Option<usize>,
    /// Quality settings for lossy formats during re-encoding
    pub quality: Option<u8>,
    /// Additional custom options
    pub custom_options: HashMap<String, serde_json::Value>,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        Self {
            algorithm: "chacha20poly1305".to_string(),
            encryption_mode: EncryptionMode::Full,
            encrypt_metadata: true,
            chunk_size: Some(1024 * 1024), // 1MB chunks
            quality: None,
            custom_options: HashMap::new(),
        }
    }
}

/// Encryption modes for images
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMode {
    /// Encrypt the entire image file
    Full,
    /// Encrypt only the image data, preserve headers
    DataOnly,
    /// Encrypt specific regions of the image
    Regional,
    /// Encrypt while preserving format compatibility
    FormatAware,
}

/// Encrypted image container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedImage {
    /// Encrypted image data
    pub encrypted_data: EncryptedData,
    /// Image format information
    pub format_info: ImageFormatInfo,
    /// Encrypted metadata (if any)
    pub metadata: Option<EncryptedMetadata>,
    /// Thumbnail data (if generated)
    pub thumbnail: Option<EncryptedThumbnail>,
    /// Encryption options used
    pub encryption_options: EncryptionOptions,
    /// When the image was encrypted
    pub encrypted_at: DateTime<Utc>,
    /// Image dimensions (if available)
    pub dimensions: Option<(u32, u32)>,
    /// File size before encryption
    pub original_size: usize,
    /// Additional metadata
    pub additional_info: HashMap<String, String>,
}

/// Image format information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageFormatInfo {
    /// Image format
    pub format: ImageFormat,
    /// MIME type
    pub mime_type: String,
    /// File extension
    pub extension: String,
    /// Whether the format supports lossless compression
    pub supports_lossless: bool,
    /// Whether the format supports multiple pages/layers
    pub supports_multiple_pages: bool,
    /// Format-specific metadata
    pub format_metadata: HashMap<String, String>,
}

/// Image processing result
#[derive(Debug, Clone)]
pub struct ImageProcessingResult {
    /// Success status
    pub success: bool,
    /// Processed image data
    pub data: Vec<u8>,
    /// Processing metadata
    pub metadata: HashMap<String, String>,
    /// Warnings or errors encountered
    pub messages: Vec<String>,
}

/// Image encryption statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionStats {
    /// Original file size
    pub original_size: usize,
    /// Encrypted size
    pub encrypted_size: usize,
    /// Compression ratio (if any)
    pub compression_ratio: Option<f64>,
    /// Encryption time in milliseconds
    pub encryption_time_ms: u64,
    /// Algorithm used
    pub algorithm: String,
    /// Number of chunks processed (for streaming)
    pub chunk_count: Option<usize>,
}

impl Default for EncryptionStats {
    fn default() -> Self {
        Self {
            original_size: 0,
            encrypted_size: 0,
            compression_ratio: None,
            encryption_time_ms: 0,
            algorithm: "chacha20poly1305".to_string(),
            chunk_count: None,
        }
    }
}

/// Data classification for images
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClassification {
    /// Public data
    Public,
    /// Internal company data
    Internal,
    /// Confidential data
    Confidential,
    /// Secret/Highly sensitive data
    Secret,
    /// Top secret classification
    TopSecret,
}

impl DataClassification {
    /// Get the security level (1-5, higher is more sensitive)
    pub fn security_level(&self) -> u8 {
        match self {
            Self::Public => 1,
            Self::Internal => 2,
            Self::Confidential => 3,
            Self::Secret => 4,
            Self::TopSecret => 5,
        }
    }
}

/// Access permissions for images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPermissions {
    /// Data classification
    pub classification: DataClassification,
    /// Who can view the image
    pub viewers: Vec<String>,
    /// Who can edit the image
    pub editors: Vec<String>,
    /// Who can share the image
    pub sharers: Vec<String>,
    /// Expiration time for access (if any)
    pub expires_at: Option<DateTime<Utc>>,
    /// Geographic restrictions (if any)
    pub geo_restrictions: Vec<String>,
    /// IP address restrictions (if any)
    pub ip_restrictions: Vec<String>,
}

impl Default for AccessPermissions {
    fn default() -> Self {
        Self {
            classification: DataClassification::Internal,
            viewers: vec!["owner".to_string()],
            editors: vec!["owner".to_string()],
            sharers: vec!["owner".to_string()],
            expires_at: None,
            geo_restrictions: Vec::new(),
            ip_restrictions: Vec::new(),
        }
    }
}

/// Image search criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchCriteria {
    /// Text search in metadata
    pub text_query: Option<String>,
    /// Image format filter
    pub format_filter: Option<ImageFormat>,
    /// Size range filter
    pub size_range: Option<(usize, usize)>,
    /// Date range filter
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Classification filter
    pub classification_filter: Option<DataClassification>,
    /// Tags filter
    pub tags: Vec<String>,
    /// Custom field filters
    pub custom_filters: HashMap<String, String>,
}

/// Image filter for listing operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageFilter {
    /// Pagination offset
    pub offset: Option<usize>,
    /// Limit results
    pub limit: Option<usize>,
    /// Sort by field
    pub sort_by: Option<String>,
    /// Sort order
    pub sort_order: Option<SortOrder>,
    /// Additional filter criteria
    pub criteria: SearchCriteria,
}

/// Sort order for listing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    Ascending,
    Descending,
}

/// Image search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSearchResult {
    /// Image identifier
    pub id: String,
    /// Basic image info
    pub info: ImageInfo,
    /// Relevance score (if applicable)
    pub relevance_score: Option<f64>,
    /// Match highlights
    pub highlights: Vec<String>,
}

/// Basic image information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image ID
    pub id: String,
    /// Format information
    pub format: ImageFormatInfo,
    /// Dimensions
    pub dimensions: Option<(u32, u32)>,
    /// File size
    pub size: usize,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub modified_at: DateTime<Utc>,
    /// Data classification
    pub classification: DataClassification,
    /// Tags
    pub tags: Vec<String>,
    /// Owner
    pub owner: String,
}

/// Color space information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColorSpace {
    RGB,
    CMYK,
    Grayscale,
    LAB,
    XYZ,
    YCbCr,
}

/// Compression information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionInfo {
    /// Compression type
    pub compression_type: String,
    /// Compression level (if applicable)
    pub level: Option<u8>,
    /// Whether compression is lossy
    pub is_lossy: bool,
    /// Compression ratio
    pub ratio: Option<f64>,
}

/// Error types specific to image encryption
#[derive(Debug, Clone, thiserror::Error)]
pub enum ImageEncryptionError {
    #[error("Unsupported image format: {0}")]
    UnsupportedFormat(String),
    
    #[error("Corrupted image data: {0}")]
    CorruptedData(String),
    
    #[error("Invalid image dimensions: {0}x{1}")]
    InvalidDimensions(u32, u32),
    
    #[error("Metadata extraction failed: {0}")]
    MetadataError(String),
    
    #[error("Thumbnail generation failed: {0}")]
    ThumbnailError(String),
    
    #[error("Streaming error: {0}")]
    StreamingError(String),
    
    #[error("Format conversion failed: {0}")]
    ConversionError(String),
    
    #[error("Processing error: {0}")]
    ProcessingError(String),
}

impl From<ImageEncryptionError> for FortressError {
    fn from(err: ImageEncryptionError) -> Self {
        FortressError::encryption(
            err.to_string(),
            "image_encryption".to_string(),
            crate::error::EncryptionErrorCode::EncryptionFailed,
        )
    }
}

/// Utility functions
pub mod utils {
    use super::*;
    
    /// Detect image format from bytes
    pub fn detect_image_format(data: &[u8]) -> Result<ImageFormat> {
        ImageFormatDetector::detect(data)
    }
    
    /// Validate image data integrity
    pub fn validate_image_data(data: &[u8], format: ImageFormat) -> Result<bool> {
        format.validate_data(data)
    }
    
    /// Calculate optimal chunk size based on image size
    pub fn calculate_chunk_size(image_size: usize) -> usize {
        // Use 1MB chunks for small images, up to 10MB for large ones
        let base_chunk = 1024 * 1024; // 1MB
        let max_chunk = 10 * 1024 * 1024; // 10MB
        
        if image_size <= base_chunk {
            base_chunk
        } else {
            std::cmp::min(base_chunk * (image_size / base_chunk), max_chunk)
        }
    }
    
    /// Generate image fingerprint for deduplication
    pub fn generate_fingerprint(data: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(data);
        format!("{:x}", hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption_options_default() {
        let options = EncryptionOptions::default();
        assert_eq!(options.algorithm, "chacha20poly1305");
        assert_eq!(options.encryption_mode, EncryptionMode::Full);
        assert!(options.encrypt_metadata);
        assert_eq!(options.chunk_size, Some(1024 * 1024));
    }
    
    #[test]
    fn test_data_classification_security_level() {
        assert_eq!(DataClassification::Public.security_level(), 1);
        assert_eq!(DataClassification::Internal.security_level(), 2);
        assert_eq!(DataClassification::Confidential.security_level(), 3);
        assert_eq!(DataClassification::Secret.security_level(), 4);
        assert_eq!(DataClassification::TopSecret.security_level(), 5);
    }
    
    #[test]
    fn test_access_permissions_default() {
        let perms = AccessPermissions::default();
        assert_eq!(perms.classification, DataClassification::Internal);
        assert_eq!(perms.viewers, vec!["owner"]);
        assert_eq!(perms.editors, vec!["owner"]);
        assert_eq!(perms.sharers, vec!["owner"]);
    }
}
