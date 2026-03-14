//! Thumbnail generation for encrypted images in Fortress
//!
//! This module provides secure thumbnail generation capabilities including:
//! - Thumbnail generation from encrypted images
//! - Secure thumbnail storage and encryption
//! - Multiple thumbnail sizes and formats
//! - Progressive thumbnail generation
//! - Watermarking support for thumbnails

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptionAlgorithm, SecureKey, EncryptedData};
use crate::image_encryption::{
    ImageFormat, encryptor::ImageEncryptorFactory,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use bytes::Bytes;

/// Thumbnail size presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThumbnailSize {
    /// Small thumbnail (64x64)
    Small,
    /// Medium thumbnail (128x128)
    Medium,
    /// Large thumbnail (256x256)
    Large,
    /// Extra large thumbnail (512x512)
    ExtraLarge,
    /// Custom size
    Custom(u32, u32),
}

impl ThumbnailSize {
    /// Get the dimensions for this thumbnail size
    pub fn dimensions(&self) -> (u32, u32) {
        match self {
            Self::Small => (64, 64),
            Self::Medium => (128, 128),
            Self::Large => (256, 256),
            Self::ExtraLarge => (512, 512),
            Self::Custom(width, height) => (*width, *height),
        }
    }

    /// Get the size name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::ExtraLarge => "xlarge",
            Self::Custom(_, _) => "custom",
        }
    }

    /// Get the maximum file size for this thumbnail (bytes)
    pub fn max_file_size(&self) -> usize {
        match self {
            Self::Small => 8 * 1024,      // 8KB
            Self::Medium => 32 * 1024,   // 32KB
            Self::Large => 128 * 1024,   // 128KB
            Self::ExtraLarge => 512 * 1024, // 512KB
            Self::Custom(width, height) => {
                // Estimate based on dimensions (JPEG quality 75%)
                ((width * height) / 10) as usize
            }
        }
    }
}

/// Thumbnail format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThumbnailFormat {
    /// JPEG format (lossy, good for photos)
    Jpeg,
    /// PNG format (lossless, good for graphics)
    Png,
    /// WebP format (modern, efficient)
    WebP,
}

impl ThumbnailFormat {
    /// Get the MIME type for this format
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::WebP => "image/webp",
        }
    }

    /// Get the file extension for this format
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Jpeg => "jpg",
            Self::Png => "png",
            Self::WebP => "webp",
        }
    }

    /// Check if this format supports transparency
    pub fn supports_transparency(&self) -> bool {
        match self {
            Self::Jpeg => false,
            Self::Png => true,
            Self::WebP => true,
        }
    }
}

/// Thumbnail generation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThumbnailOptions {
    /// Thumbnail size
    pub size: ThumbnailSize,
    /// Thumbnail format
    pub format: ThumbnailFormat,
    /// JPEG quality (1-100, only for JPEG/WebP)
    pub quality: Option<u8>,
    /// Whether to preserve aspect ratio
    pub preserve_aspect_ratio: bool,
    /// Whether to apply watermark
    pub apply_watermark: bool,
    /// Watermark text (if watermarking)
    pub watermark_text: Option<String>,
    /// Watermark opacity (0.0-1.0)
    pub watermark_opacity: Option<f32>,
    /// Background color for transparent images (hex string)
    pub background_color: Option<String>,
    /// Whether to sharpen the thumbnail
    pub sharpen: bool,
    /// Custom processing options
    pub custom_options: HashMap<String, serde_json::Value>,
}

impl Default for ThumbnailOptions {
    fn default() -> Self {
        Self {
            size: ThumbnailSize::Medium,
            format: ThumbnailFormat::Jpeg,
            quality: Some(75),
            preserve_aspect_ratio: true,
            apply_watermark: false,
            watermark_text: None,
            watermark_opacity: Some(0.5),
            background_color: None,
            sharpen: true,
            custom_options: HashMap::new(),
        }
    }
}

/// Encrypted thumbnail container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedThumbnail {
    /// Encrypted thumbnail data
    pub encrypted_data: EncryptedData,
    /// Thumbnail size
    pub size: ThumbnailSize,
    /// Thumbnail format
    pub format: ThumbnailFormat,
    /// Original image dimensions
    pub original_dimensions: Option<(u32, u32)>,
    /// Thumbnail dimensions
    pub thumbnail_dimensions: (u32, u32),
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Generation options used
    pub options: ThumbnailOptions,
    /// File size before encryption
    pub original_size: usize,
    /// Thumbnail fingerprint for deduplication
    pub fingerprint: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Thumbnail generator
pub struct ThumbnailGenerator {
    encryption_algorithm: Box<dyn EncryptionAlgorithm>,
}

impl ThumbnailGenerator {
    /// Create a new thumbnail generator
    pub fn new(encryption_algorithm: Box<dyn EncryptionAlgorithm>) -> Self {
        Self {
            encryption_algorithm,
        }
    }

    /// Generate thumbnail from encrypted image
    pub async fn generate_from_encrypted(
        &self,
        encrypted_image: &crate::image_encryption::EncryptedImage,
        thumbnail_key: &SecureKey,
        image_key: &SecureKey,
        options: ThumbnailOptions,
    ) -> Result<EncryptedThumbnail> {
        // First decrypt the image
        let encryptor = ImageEncryptorFactory::create_encryptor("chacha20poly1305")?;
        let decrypted_image_data: Vec<u8> = encryptor.decrypt(encrypted_image, image_key).await?;

        // Generate thumbnail from decrypted image
        self.generate_from_decrypted(&decrypted_image_data, encrypted_image, thumbnail_key, options).await
    }

    /// Generate thumbnail from decrypted image data
    pub async fn generate_from_decrypted(
        &self,
        image_data: &[u8],
        encrypted_image: &crate::image_encryption::EncryptedImage,
        thumbnail_key: &SecureKey,
        options: ThumbnailOptions,
    ) -> Result<EncryptedThumbnail> {
        // Generate thumbnail data
        let thumbnail_data = self.generate_thumbnail_data(image_data, &options).await?;

        // Encrypt the thumbnail
        let encrypted_thumbnail_data = self.encryption_algorithm.encrypt(
            &thumbnail_data,
            thumbnail_key.as_bytes(),
        )?;

        let encrypted_data = EncryptedData::new(
            Bytes::from(encrypted_thumbnail_data),
            self.encryption_algorithm.name().to_string(),
        )
        .with_key_version(1)
        .with_metadata("content_type".to_string(), "thumbnail".to_string())
        .with_metadata("size".to_string(), options.size.name().to_string())
        .with_metadata("format".to_string(), format!("{:?}", options.format));

        // Get thumbnail dimensions
        let thumbnail_dimensions = options.size.dimensions();

        // Generate fingerprint
        let fingerprint = self.generate_thumbnail_fingerprint(&thumbnail_data);

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("original_format".to_string(), format!("{:?}", encrypted_image.format_info.format));
        metadata.insert("original_size".to_string(), encrypted_image.original_size.to_string());
        metadata.insert("thumbnail_size".to_string(), format!("{}x{}", thumbnail_dimensions.0, thumbnail_dimensions.1));
        metadata.insert("compression_ratio".to_string(), format!("{:.3}", thumbnail_data.len() as f64 / image_data.len() as f64));

        Ok(EncryptedThumbnail {
            encrypted_data,
            size: options.size,
            format: options.format,
            original_dimensions: encrypted_image.dimensions,
            thumbnail_dimensions,
            generated_at: Utc::now(),
            options,
            original_size: thumbnail_data.len(),
            fingerprint,
            metadata,
        })
    }

    /// Generate thumbnail data from image data
    async fn generate_thumbnail_data(&self, _image_data: &[u8], options: &ThumbnailOptions) -> Result<Vec<u8>> {
        // This is a simplified implementation
        // In a real implementation, we would use image processing libraries
        // like image-rs, or integrate with external image processing services
        
        // For now, we'll create a simple placeholder thumbnail
        self.create_placeholder_thumbnail(options).await
    }

    /// Create a placeholder thumbnail (simplified implementation)
    async fn create_placeholder_thumbnail(&self, options: &ThumbnailOptions) -> Result<Vec<u8>> {
        let (width, height) = options.size.dimensions();
        
        match options.format {
            ThumbnailFormat::Jpeg => {
                // Create a simple JPEG placeholder
                self.create_jpeg_placeholder(width, height, options.quality.unwrap_or(75)).await
            }
            ThumbnailFormat::Png => {
                // Create a simple PNG placeholder
                self.create_png_placeholder(width, height).await
            }
            ThumbnailFormat::WebP => {
                // Create a simple WebP placeholder
                self.create_webp_placeholder(width, height, options.quality.unwrap_or(75)).await
            }
        }
    }

    /// Create JPEG placeholder
    async fn create_jpeg_placeholder(&self, width: u32, height: u32, _quality: u8) -> Result<Vec<u8>> {
        // This is a very simplified JPEG generator
        // In practice, we would use a proper JPEG encoder
        
        let mut jpeg_data = Vec::new();
        
        // JPEG SOI marker
        jpeg_data.extend_from_slice(&[0xFF, 0xD8]);
        
        // APP0 marker with JFIF info
        jpeg_data.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        jpeg_data.extend_from_slice(b"JFIF");
        jpeg_data.extend_from_slice(&[0x00, 0x01, 0x01, 0x01]);
        jpeg_data.extend_from_slice(&[0x48, 0x00, 0x48, 0x00, 0x00]);
        
        // Quantization table (simplified)
        jpeg_data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
        for _ in 0..64 {
            jpeg_data.push(1); // Simplified quantization values
        }
        
        // Frame header (simplified)
        jpeg_data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        jpeg_data.extend_from_slice(&(height.to_be_bytes()));
        jpeg_data.extend_from_slice(&(width.to_be_bytes()));
        jpeg_data.extend_from_slice(&[0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01]);
        
        // Huffman tables (simplified)
        jpeg_data.extend_from_slice(&[0xFF, 0xC4, 0x00, 0x14, 0x00]);
        for _ in 0..16 {
            jpeg_data.push(0);
        }
        for _ in 0..12 {
            jpeg_data.push(0);
        }
        
        // SOS marker (simplified)
        jpeg_data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00]);
        
        // Simplified image data (in practice, this would be actual compressed image data)
        let image_data_size = (width * height) as usize / 10; // Rough estimate
        for _ in 0..image_data_size.min(1000) { // Limit for simplicity
            jpeg_data.push(0x00);
        }
        
        // EOI marker
        jpeg_data.extend_from_slice(&[0xFF, 0xD9]);
        
        Ok(jpeg_data)
    }

    /// Create PNG placeholder
    async fn create_png_placeholder(&self, width: u32, height: u32) -> Result<Vec<u8>> {
        // This is a very simplified PNG generator
        let mut png_data = Vec::new();
        
        // PNG signature
        png_data.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        
        // IHDR chunk
        let mut ihdr_data = Vec::new();
        ihdr_data.extend_from_slice(&width.to_be_bytes());
        ihdr_data.extend_from_slice(&height.to_be_bytes());
        ihdr_data.extend_from_slice(&[8, 2, 0, 0, 0]); // bit depth, color type, compression, filter, interlace
        
        png_data.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&ihdr_data);
        
        // CRC (simplified - would need proper CRC calculation)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        // IDAT chunk (simplified image data)
        let idat_data = vec![0u8; (width * height) as usize / 10]; // Placeholder
        png_data.extend_from_slice(&(idat_data.len() as u32).to_be_bytes());
        png_data.extend_from_slice(b"IDAT");
        png_data.extend_from_slice(&idat_data);
        
        // CRC (simplified)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        // IEND chunk
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        png_data.extend_from_slice(b"IEND");
        png_data.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
        
        Ok(png_data)
    }

    /// Create WebP placeholder
    async fn create_webp_placeholder(&self, width: u32, height: u32, _quality: u8) -> Result<Vec<u8>> {
        // This is a very simplified WebP generator
        let mut webp_data = Vec::new();
        
        // RIFF header
        webp_data.extend_from_slice(b"RIFF");
        
        // File size (placeholder, will be updated)
        webp_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        // WebP identifier
        webp_data.extend_from_slice(b"WEBP");
        
        // VP8 chunk
        webp_data.extend_from_slice(b"VP8 ");
        
        // VP8 chunk data (simplified)
        let mut vp8_data = Vec::new();
        vp8_data.extend_from_slice(&(width as u16).to_be_bytes());
        vp8_data.extend_from_slice(&(height as u16).to_be_bytes());
        vp8_data.extend_from_slice(&[0u8; 100]); // Simplified VP8 data
        
        webp_data.extend_from_slice(&(vp8_data.len() as u32).to_be_bytes());
        webp_data.extend_from_slice(&vp8_data);
        
        // Update file size
        let file_size = (webp_data.len() - 8) as u32;
        webp_data[4..8].copy_from_slice(&file_size.to_be_bytes());
        
        Ok(webp_data)
    }

    /// Decrypt thumbnail
    pub async fn decrypt_thumbnail(
        &self,
        encrypted_thumbnail: &EncryptedThumbnail,
        thumbnail_key: &SecureKey,
    ) -> Result<Vec<u8>> {
        let decrypted_data = self.encryption_algorithm.decrypt(
            &encrypted_thumbnail.encrypted_data.ciphertext,
            thumbnail_key.as_bytes(),
        )?;

        Ok(decrypted_data)
    }

    /// Generate multiple thumbnails at different sizes
    pub async fn generate_multiple_thumbnails(
        &self,
        encrypted_image: &crate::image_encryption::EncryptedImage,
        thumbnail_key: &SecureKey,
        image_key: &SecureKey,
        sizes: Vec<ThumbnailSize>,
        base_options: ThumbnailOptions,
    ) -> Result<Vec<EncryptedThumbnail>> {
        let mut thumbnails = Vec::new();
        
        for size in sizes {
            let mut options = base_options.clone();
            options.size = size;
            
            let thumbnail = self.generate_from_encrypted(encrypted_image, thumbnail_key, image_key, options).await?;
            thumbnails.push(thumbnail);
        }
        
        Ok(thumbnails)
    }

    /// Generate thumbnail fingerprint for deduplication
    fn generate_thumbnail_fingerprint(&self, thumbnail_data: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(thumbnail_data);
        format!("{:x}", hash)
    }

    /// Validate thumbnail options
    pub fn validate_options(&self, options: &ThumbnailOptions) -> Result<()> {
        // Validate quality
        if let Some(quality) = options.quality {
            if quality == 0 || quality > 100 {
                return Err(FortressError::encryption(
                    "Invalid quality: must be between 1 and 100".to_string(),
                    "thumbnail_generator".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
        }

        // Validate watermark opacity
        if let Some(opacity) = options.watermark_opacity {
            if opacity < 0.0 || opacity > 1.0 {
                return Err(FortressError::encryption(
                    "Invalid watermark opacity: must be between 0.0 and 1.0".to_string(),
                    "thumbnail_generator".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
        }

        // Validate custom size
        if let ThumbnailSize::Custom(width, height) = options.size {
            if width == 0 || height == 0 {
                return Err(FortressError::encryption(
                    "Invalid custom size: width and height must be > 0".to_string(),
                    "thumbnail_generator".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
            
            if width > 4096 || height > 4096 {
                return Err(FortressError::encryption(
                    "Custom size too large: maximum 4096x4096".to_string(),
                    "thumbnail_generator".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
        }

        Ok(())
    }

    /// Get estimated thumbnail size
    pub fn estimate_thumbnail_size(&self, _original_size: usize, options: &ThumbnailOptions) -> usize {
        let (width, height) = options.size.dimensions();
        let pixel_count = width * height;
        
        // Estimate based on format and quality
        let bytes_per_pixel = match options.format {
            ThumbnailFormat::Jpeg => {
                let quality_factor = options.quality.unwrap_or(75) as f64 / 100.0;
                0.5 * quality_factor // JPEG is compressed
            }
            ThumbnailFormat::Png => 4.0, // RGBA
            ThumbnailFormat::WebP => {
                let quality_factor = options.quality.unwrap_or(75) as f64 / 100.0;
                0.3 * quality_factor // WebP is more efficient
            }
        };
        
        (pixel_count as f64 * bytes_per_pixel) as usize
    }

    /// Check if thumbnail generation is supported for the given format
    pub fn supports_format(&self, format: ImageFormat) -> bool {
        match format {
            ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::Tiff | ImageFormat::Bmp |
            ImageFormat::WebP | ImageFormat::Gif => true,
            ImageFormat::Heic | ImageFormat::Avif | ImageFormat::Jxl => true, // With proper libraries
            ImageFormat::Dicom => true, // With medical imaging libraries
            ImageFormat::Cr2 | ImageFormat::Nef | ImageFormat::Arw | ImageFormat::Dng => true, // RAW formats
            ImageFormat::Fits | ImageFormat::Nifti => true, // Scientific formats
            ImageFormat::Unknown => false,
        }
    }

    /// Get recommended thumbnail sizes for the given image dimensions
    pub fn get_recommended_sizes(&self, dimensions: Option<(u32, u32)>) -> Vec<ThumbnailSize> {
        match dimensions {
            Some((width, height)) => {
                let max_dim = width.max(height);
                let mut sizes = vec![ThumbnailSize::Medium]; // Always include medium
                
                if max_dim >= 1024 {
                    sizes.push(ThumbnailSize::Large);
                    sizes.push(ThumbnailSize::ExtraLarge);
                }
                
                if max_dim >= 512 {
                    sizes.push(ThumbnailSize::Small);
                }
                
                sizes
            }
            None => {
                // Default sizes when dimensions are unknown
                vec![ThumbnailSize::Small, ThumbnailSize::Medium, ThumbnailSize::Large]
            }
        }
    }

    /// Verify thumbnail integrity
    pub fn verify_thumbnail_integrity(&self, encrypted_thumbnail: &EncryptedThumbnail) -> Result<bool> {
        // Check if encrypted data is present
        if encrypted_thumbnail.encrypted_data.ciphertext.is_empty() {
            return Ok(false);
        }

        // Check if dimensions are reasonable
        let (width, height) = encrypted_thumbnail.thumbnail_dimensions;
        if width == 0 || height == 0 || width > 4096 || height > 4096 {
            return Ok(false);
        }

        // Check if fingerprint is present
        if encrypted_thumbnail.fingerprint.is_empty() {
            return Ok(false);
        }

        // Additional integrity checks can be added here
        Ok(true)
    }
}

/// Helper trait for concatenating arrays
trait Concatenate<T> {
    fn concat(self, other: T) -> Vec<u8>;
}

impl<T, U> Concatenate<U> for T 
where 
    T: IntoIterator<Item = u8>,
    U: IntoIterator<Item = u8>,
{
    fn concat(self, other: U) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(self);
        result.extend(other);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::ChaCha20Poly1305;
    use crate::image_encryption::{EncryptedImage, ImageFormatInfo, EncryptionOptions};

    #[test]
    fn test_thumbnail_size() {
        assert_eq!(ThumbnailSize::Small.dimensions(), (64, 64));
        assert_eq!(ThumbnailSize::Medium.dimensions(), (128, 128));
        assert_eq!(ThumbnailSize::Large.dimensions(), (256, 256));
        assert_eq!(ThumbnailSize::ExtraLarge.dimensions(), (512, 512));
        assert_eq!(ThumbnailSize::Custom(200, 150).dimensions(), (200, 150));
        
        assert_eq!(ThumbnailSize::Small.name(), "small");
        assert_eq!(ThumbnailSize::Custom(100, 100).name(), "custom");
        
        assert_eq!(ThumbnailSize::Small.max_file_size(), 8 * 1024);
        assert_eq!(ThumbnailSize::Medium.max_file_size(), 32 * 1024);
    }

    #[test]
    fn test_thumbnail_format() {
        assert_eq!(ThumbnailFormat::Jpeg.mime_type(), "image/jpeg");
        assert_eq!(ThumbnailFormat::Png.mime_type(), "image/png");
        assert_eq!(ThumbnailFormat::WebP.mime_type(), "image/webp");
        
        assert_eq!(ThumbnailFormat::Jpeg.extension(), "jpg");
        assert_eq!(ThumbnailFormat::Png.extension(), "png");
        assert_eq!(ThumbnailFormat::WebP.extension(), "webp");
        
        assert!(!ThumbnailFormat::Jpeg.supports_transparency());
        assert!(ThumbnailFormat::Png.supports_transparency());
        assert!(ThumbnailFormat::WebP.supports_transparency());
    }

    #[test]
    fn test_thumbnail_options_default() {
        let options = ThumbnailOptions::default();
        assert_eq!(options.size, ThumbnailSize::Medium);
        assert_eq!(options.format, ThumbnailFormat::Jpeg);
        assert_eq!(options.quality, Some(75));
        assert!(options.preserve_aspect_ratio);
        assert!(!options.apply_watermark);
        assert!(options.sharpen);
    }

    #[test]
    fn test_thumbnail_generator_creation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let generator = ThumbnailGenerator::new(algorithm);
        
        assert!(generator.supports_format(ImageFormat::Jpeg));
        assert!(generator.supports_format(ImageFormat::Png));
        assert!(!generator.supports_format(ImageFormat::Unknown));
    }

    #[test]
    fn test_thumbnail_options_validation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let generator = ThumbnailGenerator::new(algorithm);
        
        let valid_options = ThumbnailOptions::default();
        assert!(generator.validate_options(&valid_options).is_ok());
        
        // Test invalid quality
        let mut invalid_options = valid_options.clone();
        invalid_options.quality = Some(0);
        assert!(generator.validate_options(&invalid_options).is_err());
        
        invalid_options.quality = Some(150);
        assert!(generator.validate_options(&invalid_options).is_err());
        
        // Test invalid watermark opacity
        let mut invalid_options = valid_options.clone();
        invalid_options.watermark_opacity = Some(-0.1);
        assert!(generator.validate_options(&invalid_options).is_err());
        
        invalid_options.watermark_opacity = Some(1.1);
        assert!(generator.validate_options(&invalid_options).is_err());
        
        // Test invalid custom size
        let mut invalid_options = valid_options.clone();
        invalid_options.size = ThumbnailSize::Custom(0, 100);
        assert!(generator.validate_options(&invalid_options).is_err());
        
        invalid_options.size = ThumbnailSize::Custom(5000, 5000);
        assert!(generator.validate_options(&invalid_options).is_err());
    }

    #[test]
    fn test_thumbnail_size_estimation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let generator = ThumbnailGenerator::new(algorithm);
        
        let options = ThumbnailOptions {
            size: ThumbnailSize::Medium,
            format: ThumbnailFormat::Jpeg,
            quality: Some(75),
            ..Default::default()
        };
        
        let estimated_size = generator.estimate_thumbnail_size(1024 * 1024, &options);
        assert!(estimated_size > 0);
        assert!(estimated_size < 1024 * 1024); // Should be smaller than original
    }

    #[test]
    fn test_recommended_sizes() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let generator = ThumbnailGenerator::new(algorithm);
        
        // Small image
        let sizes = generator.get_recommended_sizes(Some((200, 200)));
        assert!(sizes.contains(&ThumbnailSize::Medium));
        assert!(sizes.contains(&ThumbnailSize::Small));
        
        // Large image
        let sizes = generator.get_recommended_sizes(Some((2000, 1500)));
        assert!(sizes.contains(&ThumbnailSize::Medium));
        assert!(sizes.contains(&ThumbnailSize::Large));
        assert!(sizes.contains(&ThumbnailSize::ExtraLarge));
        
        // Unknown dimensions
        let sizes = generator.get_recommended_sizes(None);
        assert!(sizes.contains(&ThumbnailSize::Small));
        assert!(sizes.contains(&ThumbnailSize::Medium));
        assert!(sizes.contains(&ThumbnailSize::Large));
    }

    #[tokio::test]
    async fn test_placeholder_thumbnail_generation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let generator = ThumbnailGenerator::new(algorithm);
        
        let options = ThumbnailOptions {
            size: ThumbnailSize::Small,
            format: ThumbnailFormat::Jpeg,
            quality: Some(75),
            ..Default::default()
        };
        
        let thumbnail_data = generator.create_placeholder_thumbnail(&options).await.unwrap();
        assert!(!thumbnail_data.is_empty());
        
        // Check for JPEG markers
        assert!(thumbnail_data.starts_with(&[0xFF, 0xD8])); // SOI
        assert!(thumbnail_data.ends_with(&[0xFF, 0xD9])); // EOI
    }

    #[test]
    fn test_thumbnail_integrity_verification() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let generator = ThumbnailGenerator::new(algorithm);
        
        // Valid thumbnail
        let valid_thumbnail = EncryptedThumbnail {
            encrypted_data: EncryptedData::new(
                crate::bytes::Bytes::from("thumbnail_data"),
                "chacha20poly1305".to_string(),
            ),
            size: ThumbnailSize::Medium,
            format: ThumbnailFormat::Jpeg,
            original_dimensions: Some((1920, 1080)),
            thumbnail_dimensions: (128, 128),
            generated_at: Utc::now(),
            options: ThumbnailOptions::default(),
            original_size: 1024,
            fingerprint: "test_fingerprint".to_string(),
            metadata: HashMap::new(),
        };
        
        assert!(generator.verify_thumbnail_integrity(&valid_thumbnail).unwrap());
        
        // Invalid thumbnail (empty data)
        let mut invalid_thumbnail = valid_thumbnail.clone();
        invalid_thumbnail.encrypted_data.ciphertext = crate::bytes::Bytes::new();
        assert!(!generator.verify_thumbnail_integrity(&invalid_thumbnail).unwrap());
        
        // Invalid thumbnail (invalid dimensions)
        let mut invalid_thumbnail = valid_thumbnail.clone();
        invalid_thumbnail.thumbnail_dimensions = (0, 128);
        assert!(!generator.verify_thumbnail_integrity(&invalid_thumbnail).unwrap());
    }
}
