//! Core image encryption logic for Fortress
//!
//! This module provides the main image encryption functionality including:
//! - Full and partial image encryption
//! - Format-aware encryption
//! - Regional encryption for specific areas
//! - Integration with existing Fortress encryption algorithms
//! - Performance optimization for various image sizes

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptionAlgorithm, SecureKey, EncryptedData};
use crate::image_encryption::{
    ImageFormat, EncryptionOptions, EncryptionMode, ImageEncryptionError,
    EncryptedImage, ImageFormatInfo, ImageMetadata, EncryptionStats,
    formats::{FormatProcessorFactory},
    metadata::{MetadataProcessor, DefaultMetadataExtractor, MetadataExtractor}, ImageFormatDetector,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Instant;
use chrono::Utc;

/// Main image encryptor
pub struct ImageEncryptor {
    encryption_algorithm: Box<dyn EncryptionAlgorithm>,
    metadata_processor: MetadataProcessor,
    format_detector: ImageFormatDetector,
}

impl ImageEncryptor {
    /// Create a new image encryptor with the specified algorithm
    pub fn new(encryption_algorithm: Box<dyn EncryptionAlgorithm>) -> Self {
        // Create metadata processor with a new instance of the same algorithm type
        let algorithm_name = encryption_algorithm.name();
        let metadata_algorithm = ImageEncryptorFactory::create_encryptor(algorithm_name).ok();
        let metadata_processor = metadata_algorithm.map(|alg| {
            // Extract the encryption algorithm from the encryptor
            let algorithm = alg.encryption_algorithm.clone();
            MetadataProcessor::new(algorithm)
        });
        
        Self {
            encryption_algorithm: encryption_algorithm.clone(),
            metadata_processor: metadata_processor.unwrap_or_else(|| {
                // Fallback to a default processor if we can't create a matching one
                MetadataProcessor::new(encryption_algorithm.clone())
            }),
            format_detector: ImageFormatDetector,
        }
    }

    /// Get a reference to the encryption algorithm
    pub fn encryption_algorithm(&self) -> &Box<dyn EncryptionAlgorithm> {
        &self.encryption_algorithm
    }

    /// Encrypt image data with the given options
    pub async fn encrypt(
        &self,
        image_data: Vec<u8>,
        options: EncryptionOptions,
        key: &SecureKey,
    ) -> Result<EncryptedImage> {
        let start_time = Instant::now();
        
        // Validate input
        if image_data.is_empty() {
            return Err(ImageEncryptionError::CorruptedData("Empty image data".to_string()).into());
        }

        // Detect image format
        let format = ImageFormatDetector::detect(&image_data)?;
        if format == ImageFormat::Unknown {
            return Err(ImageEncryptionError::UnsupportedFormat("Unknown image format".to_string()).into());
        }

        // Validate image data
        if !format.validate_data(&image_data)? {
            return Err(ImageEncryptionError::CorruptedData("Invalid image data for detected format".to_string()).into());
        }

        // Extract metadata if requested
        let metadata = if options.encrypt_metadata {
            let extractor = DefaultMetadataExtractor;
            Some(extractor.extract_metadata(&image_data, format)?)
        } else {
            None
        };

        // Process image based on encryption mode
        let processed_data = self.process_image_for_encryption(&image_data, format, &options)?;
        
        // Encrypt the processed data
        let encrypted_data_bytes = self.encryption_algorithm.encrypt(
            &processed_data,
            key.as_bytes(),
        )?;

        let encrypted_data = EncryptedData::new(
            Bytes::from(encrypted_data_bytes),
            self.encryption_algorithm.name().to_string(),
        )
        .with_key_version(1)
        .with_metadata("content_type".to_string(), "image_data".to_string())
        .with_metadata("format".to_string(), format!("{:?}", format))
        .with_metadata("encryption_mode".to_string(), format!("{:?}", options.encryption_mode));

        // Encrypt metadata if requested
        let encrypted_metadata = if let Some(metadata) = metadata {
            Some(self.metadata_processor.encrypt_metadata(&metadata, key)?)
        } else {
            None
        };

        // Get image dimensions
        let processor = FormatProcessorFactory::create_processor(format);
        let dimensions = processor.get_dimensions(&image_data)?;

        // Create format info
        let format_info = ImageFormatInfo {
            format,
            mime_type: format.mime_type().to_string(),
            extension: format.extensions().first().unwrap_or(&"").to_string(),
            supports_lossless: format.supports_lossless(),
            supports_multiple_pages: format.supports_multiple_pages(),
            format_metadata: format.format_metadata(),
        };

        // Calculate encryption stats
        let encryption_time = start_time.elapsed();
        let stats = EncryptionStats {
            original_size: image_data.len(),
            encrypted_size: encrypted_data.ciphertext.len(),
            compression_ratio: if processed_data.len() < image_data.len() {
                Some(processed_data.len() as f64 / image_data.len() as f64)
            } else {
                None
            },
            encryption_time_ms: encryption_time.as_millis() as u64,
            algorithm: self.encryption_algorithm.name().to_string(),
            chunk_count: None, // Not applicable for non-streaming encryption
        };

        // Create additional info
        let mut additional_info = HashMap::new();
        additional_info.insert("encryption_time_ms".to_string(), stats.encryption_time_ms.to_string());
        additional_info.insert("original_size".to_string(), stats.original_size.to_string());
        additional_info.insert("encrypted_size".to_string(), stats.encrypted_size.to_string());
        if let Some(ratio) = stats.compression_ratio {
            additional_info.insert("compression_ratio".to_string(), format!("{:.3}", ratio));
        }

        Ok(EncryptedImage {
            encrypted_data,
            format_info,
            metadata: encrypted_metadata,
            thumbnail: None, // Thumbnails are generated separately
            encryption_options: options,
            encrypted_at: Utc::now(),
            dimensions,
            original_size: image_data.len(),
            additional_info,
        })
    }

    /// Decrypt image data
    pub async fn decrypt(
        &self,
        encrypted_image: &EncryptedImage,
        key: &SecureKey,
    ) -> Result<Vec<u8>> {
        let start_time = Instant::now();

        // Decrypt the image data
        let decrypted_bytes = self.encryption_algorithm.decrypt(
            &encrypted_image.encrypted_data.ciphertext,
            key.as_bytes(),
        )?;

        // Process the decrypted data based on encryption mode
        let processed_data = self.process_image_after_decryption(
            &decrypted_bytes,
            encrypted_image.format_info.format,
            &encrypted_image.encryption_options,
        )?;

        // Validate the decrypted data
        if !encrypted_image.format_info.format.validate_data(&processed_data)? {
            return Err(ImageEncryptionError::CorruptedData("Decrypted data validation failed".to_string()).into());
        }

        // Log decryption time
        let decryption_time = start_time.elapsed();
        tracing::debug!(
            "Image decrypted in {}ms, size: {} bytes",
            decryption_time.as_millis(),
            processed_data.len()
        );

        Ok(processed_data)
    }

    /// Decrypt metadata only
    pub async fn decrypt_metadata(
        &self,
        encrypted_image: &EncryptedImage,
        key: &SecureKey,
    ) -> Result<Option<ImageMetadata>> {
        if let Some(encrypted_metadata) = &encrypted_image.metadata {
            let metadata = self.metadata_processor.decrypt_metadata(encrypted_metadata, key)?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    /// Process image data before encryption
    fn process_image_for_encryption(
        &self,
        data: &[u8],
        format: ImageFormat,
        options: &EncryptionOptions,
    ) -> Result<Vec<u8>> {
        let processor = FormatProcessorFactory::create_processor(format);
        
        match options.encryption_mode {
            EncryptionMode::Full => {
                // Encrypt the entire file as-is
                processor.process_for_encryption(data)
            }
            EncryptionMode::DataOnly => {
                // Extract only the image data portion, preserve headers
                self.extract_image_data_only(data, format, processor)
            }
            EncryptionMode::Regional => {
                // For regional encryption, we'd need region definitions
                // For now, fall back to full encryption
                processor.process_for_encryption(data)
            }
            EncryptionMode::FormatAware => {
                // Format-aware encryption preserves format structure
                self.format_aware_processing(data, format, processor, options)
            }
        }
    }

    /// Process image data after decryption
    fn process_image_after_decryption(
        &self,
        data: &[u8],
        format: ImageFormat,
        options: &EncryptionOptions,
    ) -> Result<Vec<u8>> {
        let processor = FormatProcessorFactory::create_processor(format);
        
        match options.encryption_mode {
            EncryptionMode::Full => {
                // Return data as-is for full encryption
                processor.process_after_decryption(data)
            }
            EncryptionMode::DataOnly => {
                // Reconstruct the full image file from data-only encryption
                self.reconstruct_image_from_data_only(data, format, processor)
            }
            EncryptionMode::Regional => {
                // Regional processing would need region reconstruction
                processor.process_after_decryption(data)
            }
            EncryptionMode::FormatAware => {
                // Reverse format-aware processing
                self.reverse_format_aware_processing(data, format, processor, options)
            }
        }
    }

    /// Extract only the image data portion for data-only encryption
    fn extract_image_data_only(
        &self,
        data: &[u8],
        format: ImageFormat,
        processor: Box<dyn crate::image_encryption::formats::FormatProcessor>,
    ) -> Result<Vec<u8>> {
        // For data-only encryption, we need to extract just the image data
        // and preserve the headers separately
        let header_size = format.header_size();
        
        if data.len() <= header_size {
            return Err(ImageEncryptionError::CorruptedData("Image too small for data-only encryption".to_string()).into());
        }

        let header = &data[..header_size];
        let image_data = &data[header_size..];

        // Process the image data
        let processed_data = processor.process_for_encryption(image_data)?;

        // Combine header with processed data
        let mut result = Vec::with_capacity(header.len() + processed_data.len());
        result.extend_from_slice(header);
        result.extend_from_slice(&processed_data);

        Ok(result)
    }

    /// Reconstruct full image from data-only encryption
    fn reconstruct_image_from_data_only(
        &self,
        data: &[u8],
        format: ImageFormat,
        processor: Box<dyn crate::image_encryption::formats::FormatProcessor>,
    ) -> Result<Vec<u8>> {
        let header_size = format.header_size();
        
        if data.len() <= header_size {
            return Err(ImageEncryptionError::CorruptedData("Encrypted data too small for reconstruction".to_string()).into());
        }

        let header = &data[..header_size];
        let encrypted_image_data = &data[header_size..];

        // Process the image data
        let processed_data = processor.process_after_decryption(encrypted_image_data)?;

        // Combine header with processed data
        let mut result = Vec::with_capacity(header.len() + processed_data.len());
        result.extend_from_slice(header);
        result.extend_from_slice(&processed_data);

        Ok(result)
    }

    /// Format-aware processing for encryption
    fn format_aware_processing(
        &self,
        data: &[u8],
        format: ImageFormat,
        processor: Box<dyn crate::image_encryption::formats::FormatProcessor>,
        options: &EncryptionOptions,
    ) -> Result<Vec<u8>> {
        match format {
            ImageFormat::Jpeg => self.jpeg_format_aware_processing(data, options),
            ImageFormat::Png => self.png_format_aware_processing(data, options),
            ImageFormat::Tiff => self.tiff_format_aware_processing(data, options),
            _ => {
                // For unsupported formats, fall back to standard processing
                processor.process_for_encryption(data)
            }
        }
    }

    /// Reverse format-aware processing for decryption
    fn reverse_format_aware_processing(
        &self,
        data: &[u8],
        format: ImageFormat,
        processor: Box<dyn crate::image_encryption::formats::FormatProcessor>,
        options: &EncryptionOptions,
    ) -> Result<Vec<u8>> {
        match format {
            ImageFormat::Jpeg => self.reverse_jpeg_format_aware_processing(data, options),
            ImageFormat::Png => self.reverse_png_format_aware_processing(data, options),
            ImageFormat::Tiff => self.reverse_tiff_format_aware_processing(data, options),
            _ => {
                // For unsupported formats, fall back to standard processing
                processor.process_after_decryption(data)
            }
        }
    }

    /// JPEG format-aware encryption
    fn jpeg_format_aware_processing(&self, data: &[u8], _options: &EncryptionOptions) -> Result<Vec<u8>> {
        // For JPEG, we can preserve the file structure markers
        // and only encrypt the actual image data segments
        
        // Parse JPEG markers
        let mut result = Vec::new();
        let mut pos = 0;
        
        while pos < data.len() {
            if pos + 1 >= data.len() {
                break;
            }
            
            // JPEG markers start with 0xFF
            if data[pos] != 0xFF {
                return Err(ImageEncryptionError::CorruptedData("Invalid JPEG marker".to_string()).into());
            }
            
            let marker = data[pos + 1];
            result.push(data[pos]);
            result.push(data[pos + 1]);
            pos += 2;
            
            // Handle different marker types
            match marker {
                // SOI, EOI markers have no data
                0xD8 | 0xD9 => continue,
                
                // Skip markers that should remain unencrypted
                0xE0..=0xEF | 0xFE | 0xD0..=0xD7 => {
                    // These markers have length fields
                    if pos + 2 > data.len() {
                        break;
                    }
                    let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    if pos + length > data.len() {
                        return Err(ImageEncryptionError::CorruptedData("Invalid JPEG segment length".to_string()).into());
                    }
                    
                    // Copy the segment as-is
                    result.extend_from_slice(&data[pos..pos + length]);
                    pos += length;
                }
                
                // Encrypt image data segments (SOS, etc.)
                0xDA => {
                    // Start of Scan - this contains the actual image data
                    // We need to find the end of the scan data
                    let scan_start = pos;
                    let mut scan_end = data.len();
                    
                    // Find the next marker (0xFF followed by non-0x00)
                    for i in pos..data.len() - 1 {
                        if data[i] == 0xFF && data[i + 1] != 0x00 {
                            scan_end = i;
                            break;
                        }
                    }
                    
                    // Copy segment header
                    if scan_start + 2 > data.len() {
                        break;
                    }
                    let length = u16::from_be_bytes([data[scan_start], data[scan_start + 1]]) as usize;
                    if scan_start + length > data.len() {
                        break;
                    }
                    
                    result.extend_from_slice(&data[scan_start..scan_start + length]);
                    
                    // For now, skip encryption of scan data and just copy it
                    // In a full implementation, we would encrypt this portion
                    let scan_data = &data[scan_start + length..scan_end];
                    result.extend_from_slice(scan_data);
                    
                    pos = scan_end;
                }
                
                _ => {
                    // Default handling for other markers
                    if pos + 2 > data.len() {
                        break;
                    }
                    let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    if pos + length > data.len() {
                        return Err(ImageEncryptionError::CorruptedData("Invalid JPEG segment length".to_string()).into());
                    }
                    
                    result.extend_from_slice(&data[pos..pos + length]);
                    pos += length;
                }
            }
        }
        
        Ok(result)
    }

    /// Reverse JPEG format-aware decryption
    fn reverse_jpeg_format_aware_processing(&self, data: &[u8], _options: &EncryptionOptions) -> Result<Vec<u8>> {
        // This is the reverse of jpeg_format_aware_processing
        // For now, return as-is since the actual implementation would be complex
        Ok(data.to_vec())
    }

    /// PNG format-aware encryption
    fn png_format_aware_processing(&self, data: &[u8], _options: &EncryptionOptions) -> Result<Vec<u8>> {
        // For PNG, we can preserve the PNG structure and encrypt only the image data chunks
        // This is a simplified implementation
        Ok(data.to_vec())
    }

    /// Reverse PNG format-aware decryption
    fn reverse_png_format_aware_processing(&self, data: &[u8], _options: &EncryptionOptions) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    /// TIFF format-aware encryption
    fn tiff_format_aware_processing(&self, data: &[u8], _options: &EncryptionOptions) -> Result<Vec<u8>> {
        // For TIFF, we can preserve the header and encrypt only the image data
        // This is a simplified implementation
        Ok(data.to_vec())
    }

    /// Reverse TIFF format-aware decryption
    fn reverse_tiff_format_aware_processing(&self, data: &[u8], _options: &EncryptionOptions) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    /// Validate encryption options
    pub fn validate_options(&self, options: &EncryptionOptions) -> Result<()> {
        // Check if algorithm is supported
        if options.algorithm != self.encryption_algorithm.name() {
            return Err(FortressError::encryption(
                format!("Algorithm mismatch: expected {}, got {}", 
                    self.encryption_algorithm.name(), options.algorithm),
                "image_encryptor".to_string(),
                crate::error::EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }

        // Validate chunk size
        if let Some(chunk_size) = options.chunk_size {
            if chunk_size == 0 || chunk_size > 100 * 1024 * 1024 { // Max 100MB
                return Err(FortressError::encryption(
                    "Invalid chunk size: must be > 0 and <= 100MB".to_string(),
                    "image_encryptor".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
        }

        // Validate quality setting
        if let Some(quality) = options.quality {
            if quality > 100 {
                return Err(FortressError::encryption(
                    "Invalid quality: must be <= 100".to_string(),
                    "image_encryptor".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
        }

        Ok(())
    }

    /// Get supported formats
    pub fn supported_formats(&self) -> Vec<ImageFormat> {
        vec![
            ImageFormat::Jpeg,
            ImageFormat::Png,
            ImageFormat::Tiff,
            ImageFormat::Bmp,
            ImageFormat::WebP,
            ImageFormat::Gif,
            ImageFormat::Heic,
            ImageFormat::Avif,
            ImageFormat::Jxl,
            ImageFormat::Dicom,
        ]
    }

    /// Get encryption statistics for an encrypted image
    pub fn get_encryption_stats(&self, encrypted_image: &EncryptedImage) -> EncryptionStats {
        EncryptionStats {
            original_size: encrypted_image.original_size,
            encrypted_size: encrypted_image.encrypted_data.ciphertext.len(),
            compression_ratio: None, // Would need original processed data size
            encryption_time_ms: encrypted_image.additional_info
                .get("encryption_time_ms")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            algorithm: encrypted_image.encrypted_data.algorithm.clone(),
            chunk_count: None,
        }
    }

    /// Verify encrypted image integrity
    pub fn verify_integrity(&self, encrypted_image: &EncryptedImage) -> Result<bool> {
        // Verify encrypted data structure
        if encrypted_image.encrypted_data.ciphertext.is_empty() {
            return Ok(false);
        }

        // Verify format info
        if encrypted_image.format_info.format == ImageFormat::Unknown {
            return Ok(false);
        }

        // Verify metadata if present
        if let Some(metadata) = &encrypted_image.metadata {
            if metadata.checksum.is_empty() {
                return Ok(false);
            }
        }

        // Additional integrity checks can be added here
        Ok(true)
    }
}

// Extension trait to allow cloning Box<dyn EncryptionAlgorithm>
trait EncryptionAlgorithmClone {
    fn box_clone(&self) -> Box<dyn EncryptionAlgorithm>;
}

impl<T: EncryptionAlgorithm + Clone + 'static> EncryptionAlgorithmClone for T {
    fn box_clone(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn EncryptionAlgorithm> {
    fn clone(&self) -> Box<dyn EncryptionAlgorithm> {
        // This is a simplified implementation
        // In practice, we'd need a proper cloning mechanism
        panic!("Cannot clone Box<dyn EncryptionAlgorithm> directly")
    }
}

/// Image encryption factory
pub struct ImageEncryptorFactory;

impl ImageEncryptorFactory {
    /// Create an image encryptor with the specified algorithm
    pub fn create_encryptor(algorithm_name: &str) -> Result<ImageEncryptor> {
        let algorithm: Box<dyn EncryptionAlgorithm> = match algorithm_name {
            "chacha20poly1305" => Box::new(crate::encryption::ChaCha20Poly1305::new()),
            "aegis256" => Box::new(crate::encryption::Aegis256::new()),
            "xchacha20poly1305" => Box::new(crate::encryption::XChaCha20Poly1305::new()),
            "aes256gcm" => Box::new(crate::encryption::Aes256Gcm::new()),
            "blake3" => Box::new(crate::encryption::Blake3Encrypt::new()),
            _ => return Err(FortressError::encryption(
                format!("Unsupported encryption algorithm: {}", algorithm_name),
                "image_encryptor_factory".to_string(),
                crate::error::EncryptionErrorCode::AlgorithmNotSupported,
            )),
        };

        Ok(ImageEncryptor::new(algorithm))
    }

    /// Create an image encryptor with default algorithm
    pub fn create_default() -> Result<ImageEncryptor> {
        Self::create_encryptor("chacha20poly1305")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::ChaCha20Poly1305;

    #[test]
    fn test_image_encryptor_creation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let encryptor = ImageEncryptor::new(algorithm);
        
        let supported_formats = encryptor.supported_formats();
        assert!(supported_formats.contains(&ImageFormat::Jpeg));
        assert!(supported_formats.contains(&ImageFormat::Png));
    }

    #[test]
    fn test_encryption_options_validation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let encryptor = ImageEncryptor::new(algorithm);
        
        let valid_options = EncryptionOptions {
            algorithm: "chacha20poly1305".to_string(),
            encryption_mode: EncryptionMode::Full,
            encrypt_metadata: true,
            chunk_size: Some(1024 * 1024),
            quality: Some(85),
            custom_options: HashMap::new(),
        };
        
        assert!(encryptor.validate_options(&valid_options).is_ok());
        
        // Test invalid algorithm
        let mut invalid_options = valid_options.clone();
        invalid_options.algorithm = "invalid_algorithm".to_string();
        assert!(encryptor.validate_options(&invalid_options).is_err());
        
        // Test invalid chunk size
        let mut invalid_options = valid_options.clone();
        invalid_options.chunk_size = Some(0);
        assert!(encryptor.validate_options(&invalid_options).is_err());
        
        // Test invalid quality
        let mut invalid_options = valid_options.clone();
        invalid_options.quality = Some(150);
        assert!(encryptor.validate_options(&invalid_options).is_err());
    }

    #[tokio::test]
    async fn test_simple_image_encryption() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let encryptor = ImageEncryptor::new(algorithm);
        let key = SecureKey::generate(32);
        
        // Create a simple JPEG header for testing
        let jpeg_data = vec![
            0xFF, 0xD8, // JPEG SOI
            0xFF, 0xE0, 0x00, 0x10, // APP0 marker
            b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
            0xFF, 0xD9, // JPEG EOI
        ];
        
        let options = EncryptionOptions::default();
        
        let result = encryptor.encrypt(jpeg_data.clone(), options, &key).await;
        assert!(result.is_ok());
        
        let encrypted = result.unwrap();
        assert_eq!(encrypted.format_info.format, ImageFormat::Jpeg);
        assert_eq!(encrypted.original_size, jpeg_data.len());
        assert!(!encrypted.encrypted_data.ciphertext.is_empty());
    }

    #[test]
    fn test_image_encryptor_factory() {
        let encryptor = ImageEncryptorFactory::create_default().unwrap();
        assert!(encryptor.supported_formats().contains(&ImageFormat::Jpeg));
        
        let encryptor = ImageEncryptorFactory::create_encryptor("chacha20poly1305").unwrap();
        assert!(encryptor.supported_formats().contains(&ImageFormat::Png));
        
        let result = ImageEncryptorFactory::create_encryptor("invalid_algorithm");
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_stats() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let encryptor = ImageEncryptor::new(algorithm);
        
        let encrypted_image = EncryptedImage {
            encrypted_data: EncryptedData::new(
                crate::bytes::Bytes::from("encrypted_data"),
                "chacha20poly1305".to_string(),
            ),
            format_info: ImageFormatInfo {
                format: ImageFormat::Jpeg,
                mime_type: "image/jpeg".to_string(),
                extension: "jpg".to_string(),
                supports_lossless: false,
                supports_multiple_pages: false,
                format_metadata: HashMap::new(),
            },
            metadata: None,
            thumbnail: None,
            encryption_options: EncryptionOptions::default(),
            encrypted_at: Utc::now(),
            dimensions: Some((1920, 1080)),
            original_size: 1024,
            additional_info: {
                let mut info = HashMap::new();
                info.insert("encryption_time_ms".to_string(), "100".to_string());
                info
            },
        };
        
        let stats = encryptor.get_encryption_stats(&encrypted_image);
        assert_eq!(stats.original_size, 1024);
        assert_eq!(stats.encryption_time_ms, 100);
        assert_eq!(stats.algorithm, "chacha20poly1305");
    }

    #[test]
    fn test_integrity_verification() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let encryptor = ImageEncryptor::new(algorithm);
        
        // Valid encrypted image
        let valid_image = EncryptedImage {
            encrypted_data: EncryptedData::new(
                crate::bytes::Bytes::from("encrypted_data"),
                "chacha20poly1305".to_string(),
            ),
            format_info: ImageFormatInfo {
                format: ImageFormat::Jpeg,
                mime_type: "image/jpeg".to_string(),
                extension: "jpg".to_string(),
                supports_lossless: false,
                supports_multiple_pages: false,
                format_metadata: HashMap::new(),
            },
            metadata: None,
            thumbnail: None,
            encryption_options: EncryptionOptions::default(),
            encrypted_at: Utc::now(),
            dimensions: None,
            original_size: 1024,
            additional_info: HashMap::new(),
        };
        
        assert!(encryptor.verify_integrity(&valid_image).unwrap());
        
        // Invalid encrypted image (empty data)
        let mut invalid_image = valid_image.clone();
        invalid_image.encrypted_data.ciphertext = crate::bytes::Bytes::new();
        assert!(!encryptor.verify_integrity(&invalid_image).unwrap());
    }
}
