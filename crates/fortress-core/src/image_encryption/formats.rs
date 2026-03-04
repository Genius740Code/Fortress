//! Image format support and detection for Fortress image encryption
//!
//! This module provides comprehensive support for various image formats including:
//! - Common formats: JPEG, PNG, TIFF, BMP, WebP, GIF
//! - Advanced formats: HEIC, AVIF, JXL
//! - Medical imaging: DICOM
//! - RAW formats: CR2, NEF, ARW, DNG, etc.
//! - Scientific formats: FITS, NIfTI

use crate::error::{FortressError, Result};
use crate::image_encryption::{ImageEncryptionError, ColorSpace, CompressionInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported image formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImageFormat {
    /// JPEG/JFIF format
    Jpeg,
    /// PNG format
    Png,
    /// TIFF format
    Tiff,
    /// Bitmap format
    Bmp,
    /// WebP format
    WebP,
    /// HEIC/HEIF format
    Heic,
    /// AVIF format
    Avif,
    /// JPEG XL format
    Jxl,
    /// GIF format
    Gif,
    /// DICOM medical imaging format
    Dicom,
    /// Canon RAW format
    Cr2,
    /// Nikon RAW format
    Nef,
    /// Sony RAW format
    Arw,
    /// Adobe DNG format
    Dng,
    /// FITS astronomical format
    Fits,
    /// NIfTI medical format
    Nifti,
    /// Unknown format
    Unknown,
}

impl ImageFormat {
    /// Get the MIME type for this format
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Tiff => "image/tiff",
            Self::Bmp => "image/bmp",
            Self::WebP => "image/webp",
            Self::Heic => "image/heic",
            Self::Avif => "image/avif",
            Self::Jxl => "image/jxl",
            Self::Gif => "image/gif",
            Self::Dicom => "application/dicom",
            Self::Cr2 => "image/x-canon-cr2",
            Self::Nef => "image/x-nikon-nef",
            Self::Arw => "image/x-sony-arw",
            Self::Dng => "image/x-adobe-dng",
            Self::Fits => "image/fits",
            Self::Nifti => "application/x-nifti",
            Self::Unknown => "application/octet-stream",
        }
    }

    /// Get the common file extensions for this format
    pub fn extensions(&self) -> Vec<&'static str> {
        match self {
            Self::Jpeg => vec!["jpg", "jpeg", "jfif"],
            Self::Png => vec!["png"],
            Self::Tiff => vec!["tif", "tiff"],
            Self::Bmp => vec!["bmp"],
            Self::WebP => vec!["webp"],
            Self::Heic => vec!["heic", "heif"],
            Self::Avif => vec!["avif"],
            Self::Jxl => vec!["jxl"],
            Self::Gif => vec!["gif"],
            Self::Dicom => vec!["dcm", "dicom"],
            Self::Cr2 => vec!["cr2", "cr3"],
            Self::Nef => vec!["nef"],
            Self::Arw => vec!["arw"],
            Self::Dng => vec!["dng"],
            Self::Fits => vec!["fits", "fit"],
            Self::Nifti => vec!["nii", "nii.gz"],
            Self::Unknown => vec![],
        }
    }

    /// Check if the format supports lossless compression
    pub fn supports_lossless(&self) -> bool {
        match self {
            Self::Png | Self::Tiff | Self::Bmp | Self::WebP | Self::Avif | Self::Jxl | 
            Self::Gif | Self::Fits | Self::Nifti => true,
            Self::Jpeg | Self::Heic => false,
            Self::Dicom | Self::Cr2 | Self::Nef | Self::Arw | Self::Dng | Self::Unknown => false,
        }
    }

    /// Check if the format supports multiple pages/layers
    pub fn supports_multiple_pages(&self) -> bool {
        match self {
            Self::Tiff | Self::Gif | Self::Dicom | Self::Fits => true,
            _ => false,
        }
    }

    /// Get the default color space for this format
    pub fn default_color_space(&self) -> ColorSpace {
        match self {
            Self::Jpeg | Self::WebP | Self::Heic | Self::Avif => ColorSpace::YCbCr,
            Self::Png | Self::Tiff | Self::Bmp | Self::Gif => ColorSpace::RGB,
            Self::Jxl => ColorSpace::RGB, // Can support multiple, default to RGB
            Self::Dicom | Self::Fits | Self::Nifti => ColorSpace::Grayscale, // Often grayscale
            Self::Cr2 | Self::Nef | Self::Arw | Self::Dng => ColorSpace::RGB, // RAW sensors
            Self::Unknown => ColorSpace::RGB,
        }
    }

    /// Get format-specific metadata
    pub fn format_metadata(&self) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        
        match self {
            Self::Jpeg => {
                metadata.insert("supports_exif".to_string(), "true".to_string());
                metadata.insert("supports_iptc".to_string(), "true".to_string());
                metadata.insert("supports_xmp".to_string(), "true".to_string());
            }
            Self::Png => {
                metadata.insert("supports_transparency".to_string(), "true".to_string());
                metadata.insert("supports_metadata".to_string(), "true".to_string());
            }
            Self::Tiff => {
                metadata.insert("supports_multiple_pages".to_string(), "true".to_string());
                metadata.insert("supports_metadata".to_string(), "true".to_string());
            }
            Self::WebP => {
                metadata.insert("supports_animation".to_string(), "true".to_string());
                metadata.insert("supports_transparency".to_string(), "true".to_string());
            }
            Self::Heic => {
                metadata.insert("supports_heif".to_string(), "true".to_string());
                metadata.insert("supports_multiple_images".to_string(), "true".to_string());
            }
            Self::Dicom => {
                metadata.insert("medical_format".to_string(), "true".to_string());
                metadata.insert("supports_metadata".to_string(), "true".to_string());
            }
            _ => {}
        }
        
        metadata
    }

    /// Validate image data for this format
    pub fn validate_data(&self, data: &[u8]) -> Result<bool> {
        if data.is_empty() {
            return Ok(false);
        }

        // Basic validation based on format signatures
        let is_valid = match self {
            Self::Jpeg => data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8,
            Self::Png => data.len() >= 8 && 
                       data[0] == 0x89 && data[1] == 0x50 && 
                       data[2] == 0x4E && data[3] == 0x47 &&
                       data[4] == 0x0D && data[5] == 0x0A &&
                       data[6] == 0x1A && data[7] == 0x0A,
            Self::Tiff => {
                if data.len() < 4 {
                    false
                } else {
                    // Little-endian or big-endian TIFF
                    (data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00) ||
                    (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A)
                }
            }
            Self::Bmp => data.len() >= 2 && data[0] == 0x42 && data[1] == 0x4D,
            Self::WebP => data.len() >= 4 && 
                        data[0] == 0x52 && data[1] == 0x49 && 
                        data[2] == 0x46 && data[3] == 0x46, // "RIFF"
            Self::Gif => data.len() >= 6 &&
                       ((data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x38 && data[4] == 0x37 && data[5] == 0x61) || // "GIF87a"
                        (data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x38 && data[4] == 0x39 && data[5] == 0x61)), // "GIF89a"
            Self::Dicom => data.len() >= 132 && 
                          &data[128..132] == b"DICM",
            // For more complex formats, we'd need more sophisticated validation
            Self::Heic | Self::Avif | Self::Jxl | Self::Cr2 | Self::Nef | Self::Arw | 
            Self::Dng | Self::Fits | Self::Nifti => {
                // Basic check - these formats require more complex validation
                // For now, just check if we have enough data
                data.len() > 100
            }
            Self::Unknown => false,
        };

        Ok(is_valid)
    }

    /// Get the header size for this format
    pub fn header_size(&self) -> usize {
        match self {
            Self::Jpeg => 2, // FF D8
            Self::Png => 8,  // PNG signature
            Self::Tiff => 8,  // TIFF header
            Self::Bmp => 54, // BMP header
            Self::WebP => 12, // RIFF + WebP
            Self::Gif => 6,   // GIF header
            Self::Dicom => 132, // DICOM header
            _ => 0, // Variable or unknown
        }
    }

    /// Check if this format can be processed for thumbnails
    pub fn supports_thumbnails(&self) -> bool {
        match self {
            Self::Jpeg | Self::Png | Self::Tiff | Self::Bmp | Self::WebP | 
            Self::Heic | Self::Avif | Self::Jxl | Self::Gif => true,
            Self::Dicom | Self::Cr2 | Self::Nef | Self::Arw | Self::Dng | 
            Self::Fits | Self::Nifti => true, // With special handling
            Self::Unknown => false,
        }
    }
}

/// Image format detector
pub struct ImageFormatDetector;

impl ImageFormatDetector {
    /// Detect image format from file data
    pub fn detect(data: &[u8]) -> Result<ImageFormat> {
        if data.len() < 4 {
            return Ok(ImageFormat::Unknown);
        }

        // Check format signatures in order of specificity
        if Self::is_png(data) {
            Ok(ImageFormat::Png)
        } else if Self::is_jpeg(data) {
            Ok(ImageFormat::Jpeg)
        } else if Self::is_tiff(data) {
            Ok(ImageFormat::Tiff)
        } else if Self::is_bmp(data) {
            Ok(ImageFormat::Bmp)
        } else if Self::is_webp(data) {
            Ok(ImageFormat::WebP)
        } else if Self::is_gif(data) {
            Ok(ImageFormat::Gif)
        } else if Self::is_heic(data) {
            Ok(ImageFormat::Heic)
        } else if Self::is_avif(data) {
            Ok(ImageFormat::Avif)
        } else if Self::is_jxl(data) {
            Ok(ImageFormat::Jxl)
        } else if Self::is_dicom(data) {
            Ok(ImageFormat::Dicom)
        } else if Self::is_cr2(data) {
            Ok(ImageFormat::Cr2)
        } else if Self::is_nef(data) {
            Ok(ImageFormat::Nef)
        } else if Self::is_arw(data) {
            Ok(ImageFormat::Arw)
        } else if Self::is_dng(data) {
            Ok(ImageFormat::Dng)
        } else if Self::is_fits(data) {
            Ok(ImageFormat::Fits)
        } else if Self::is_nifti(data) {
            Ok(ImageFormat::Nifti)
        } else {
            Ok(ImageFormat::Unknown)
        }
    }

    /// Detect format from file extension
    pub fn detect_from_extension(extension: &str) -> ImageFormat {
        let ext = extension.to_lowercase();
        
        match ext.as_str() {
            "jpg" | "jpeg" | "jfif" => ImageFormat::Jpeg,
            "png" => ImageFormat::Png,
            "tif" | "tiff" => ImageFormat::Tiff,
            "bmp" => ImageFormat::Bmp,
            "webp" => ImageFormat::WebP,
            "heic" | "heif" => ImageFormat::Heic,
            "avif" => ImageFormat::Avif,
            "jxl" => ImageFormat::Jxl,
            "gif" => ImageFormat::Gif,
            "dcm" | "dicom" => ImageFormat::Dicom,
            "cr2" | "cr3" => ImageFormat::Cr2,
            "nef" => ImageFormat::Nef,
            "arw" => ImageFormat::Arw,
            "dng" => ImageFormat::Dng,
            "fits" | "fit" => ImageFormat::Fits,
            "nii" | "nii.gz" => ImageFormat::Nifti,
            _ => ImageFormat::Unknown,
        }
    }

    // Format detection helpers
    fn is_png(data: &[u8]) -> bool {
        data.len() >= 8 &&
        data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 &&
        data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A
    }

    fn is_jpeg(data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8
    }

    fn is_tiff(data: &[u8]) -> bool {
        data.len() >= 4 &&
        ((data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00) ||
         (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A))
    }

    fn is_bmp(data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == 0x42 && data[1] == 0x4D // "BM"
    }

    fn is_webp(data: &[u8]) -> bool {
        data.len() >= 12 &&
        data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 && // "RIFF"
        data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50  // "WEBP"
    }

    fn is_gif(data: &[u8]) -> bool {
        data.len() >= 6 &&
        ((data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x38 && data[4] == 0x37 && data[5] == 0x61) || // "GIF87a"
         (data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x38 && data[4] == 0x39 && data[5] == 0x61))   // "GIF89a"
    }

    fn is_heic(data: &[u8]) -> bool {
        data.len() >= 12 &&
        data[4] == 0x66 && data[5] == 0x74 && data[6] == 0x79 && data[7] == 0x70 && // "ftyp"
        data[8] == 0x68 && data[9] == 0x65 && data[10] == 0x69 && data[11] == 0x63  // "heic"
    }

    fn is_avif(data: &[u8]) -> bool {
        data.len() >= 12 &&
        data[4] == 0x66 && data[5] == 0x74 && data[6] == 0x79 && data[7] == 0x70 && // "ftyp"
        data[8] == 0x61 && data[9] == 0x76 && data[10] == 0x69 && data[11] == 0x66  // "avif"
    }

    fn is_jxl(data: &[u8]) -> bool {
        data.len() >= 2 &&
        ((data[0] == 0xFF && data[1] == 0x0A) || // JPEG XL signature
         (data.len() >= 12 && &data[4..12] == b"JXL "))
    }

    fn is_dicom(data: &[u8]) -> bool {
        data.len() >= 132 && &data[128..132] == b"DICM"
    }

    fn is_cr2(data: &[u8]) -> bool {
        data.len() >= 8 &&
        ((data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00) || // Little-endian TIFF
         (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A)) && // Big-endian TIFF
        data.len() > 16 && data[8] == 0x43 && data[9] == 0x52 && data[10] == 0x32 // "CR2"
    }

    fn is_nef(data: &[u8]) -> bool {
        // NEF is TIFF-based with Nikon-specific markers
        data.len() >= 8 &&
        ((data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00) ||
         (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A))
    }

    fn is_arw(data: &[u8]) -> bool {
        // ARW is TIFF-based with Sony-specific markers
        data.len() >= 8 &&
        ((data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00) ||
         (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A))
    }

    fn is_dng(data: &[u8]) -> bool {
        // DNG is TIFF-based with Adobe-specific markers
        data.len() >= 8 &&
        ((data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00) ||
         (data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A))
    }

    fn is_fits(data: &[u8]) -> bool {
        data.len() >= 6 &&
        data[0] == b'S' && data[1] == b'I' && data[2] == b'M' && 
        data[3] == b'P' && data[4] == b'L' && data[5] == b'E'
    }

    fn is_nifti(data: &[u8]) -> bool {
        data.len() >= 348 &&
        ((data[344] == 0x6E && data[345] == 0x69 && data[346] == 0x31 && data[347] == 0x00) || // "ni1\0"
         (data[344] == 0x6E && data[345] == 0x69 && data[346] == 0x32 && data[347] == 0x00))   // "ni2\0"
    }
}

/// Format-specific processor trait
pub trait FormatProcessor: Send + Sync {
    /// Process image data for encryption
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Process image data after decryption
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Extract format-specific metadata
    fn extract_metadata(&self, data: &[u8]) -> Result<HashMap<String, String>>;
    
    /// Get compression information
    fn get_compression_info(&self, data: &[u8]) -> Result<Option<CompressionInfo>>;
    
    /// Get image dimensions
    fn get_dimensions(&self, data: &[u8]) -> Result<Option<(u32, u32)>>;
}

/// Default processor for unknown formats
pub struct DefaultFormatProcessor;

impl FormatProcessor for DefaultFormatProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, _data: &[u8]) -> Result<HashMap<String, String>> {
        Ok(HashMap::new())
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(None)
    }
    
    fn get_dimensions(&self, _data: &[u8]) -> Result<Option<(u32, u32)>> {
        Ok(None)
    }
}

/// Format processor factory
pub struct FormatProcessorFactory;

impl FormatProcessorFactory {
    /// Create a processor for the given format
    pub fn create_processor(format: ImageFormat) -> Box<dyn FormatProcessor> {
        match format {
            ImageFormat::Jpeg => Box::new(JpegProcessor),
            ImageFormat::Png => Box::new(PngProcessor),
            ImageFormat::Tiff => Box::new(TiffProcessor),
            ImageFormat::Bmp => Box::new(BmpProcessor),
            ImageFormat::WebP => Box::new(WebPProcessor),
            ImageFormat::Gif => Box::new(GifProcessor),
            _ => Box::new(DefaultFormatProcessor),
        }
    }
}

// Placeholder processors for common formats
pub struct JpegProcessor;
pub struct PngProcessor;
pub struct TiffProcessor;
pub struct BmpProcessor;
pub struct WebPProcessor;
pub struct GifProcessor;

impl FormatProcessor for JpegProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        // For JPEG, we could extract and preserve headers, EXIF data, etc.
        // For now, return as-is
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, _data: &[u8]) -> Result<HashMap<String, String>> {
        // TODO: Implement JPEG metadata extraction (EXIF, IPTC, XMP)
        Ok(HashMap::new())
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(Some(CompressionInfo {
            compression_type: "JPEG".to_string(),
            level: None,
            is_lossy: true,
            ratio: None,
        }))
    }
    
    fn get_dimensions(&self, _data: &[u8]) -> Result<Option<(u32, u32)>> {
        // TODO: Implement JPEG dimension extraction
        Ok(None)
    }
}

impl FormatProcessor for PngProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, _data: &[u8]) -> Result<HashMap<String, String>> {
        // TODO: Implement PNG metadata extraction
        Ok(HashMap::new())
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(Some(CompressionInfo {
            compression_type: "DEFLATE".to_string(),
            level: None,
            is_lossy: false,
            ratio: None,
        }))
    }
    
    fn get_dimensions(&self, _data: &[u8]) -> Result<Option<(u32, u32)>> {
        // TODO: Implement PNG dimension extraction
        Ok(None)
    }
}

impl FormatProcessor for TiffProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, _data: &[u8]) -> Result<HashMap<String, String>> {
        Ok(HashMap::new())
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(None) // TIFF can use various compression methods
    }
    
    fn get_dimensions(&self, _data: &[u8]) -> Result<Option<(u32, u32)>> {
        Ok(None)
    }
}

impl FormatProcessor for BmpProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, _data: &[u8]) -> Result<HashMap<String, String>> {
        Ok(HashMap::new())
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(Some(CompressionInfo {
            compression_type: "None".to_string(),
            level: None,
            is_lossy: false,
            ratio: None,
        }))
    }
    
    fn get_dimensions(&self, _data: &[u8]) -> Result<Option<(u32, u32)>> {
        Ok(None)
    }
}

impl FormatProcessor for WebPProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, _data: &[u8]) -> Result<HashMap<String, String>> {
        Ok(HashMap::new())
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(Some(CompressionInfo {
            compression_type: "VP8".to_string(),
            level: None,
            is_lossy: true,
            ratio: None,
        }))
    }
    
    fn get_dimensions(&self, _data: &[u8]) -> Result<Option<(u32, u32)>> {
        Ok(None)
    }
}

impl FormatProcessor for GifProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, _data: &[u8]) -> Result<HashMap<String, String>> {
        Ok(HashMap::new())
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(Some(CompressionInfo {
            compression_type: "LZW".to_string(),
            level: None,
            is_lossy: false,
            ratio: None,
        }))
    }
    
    fn get_dimensions(&self, _data: &[u8]) -> Result<Option<(u32, u32)>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        // JPEG signature
        let jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(ImageFormatDetector::detect(&jpeg_data).unwrap(), ImageFormat::Jpeg);

        // PNG signature
        let png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(ImageFormatDetector::detect(&png_data).unwrap(), ImageFormat::Png);

        // BMP signature
        let bmp_data = vec![0x42, 0x4D];
        assert_eq!(ImageFormatDetector::detect(&bmp_data).unwrap(), ImageFormat::Bmp);
    }

    #[test]
    fn test_extension_detection() {
        assert_eq!(ImageFormatDetector::detect_from_extension("jpg"), ImageFormat::Jpeg);
        assert_eq!(ImageFormatDetector::detect_from_extension("png"), ImageFormat::Png);
        assert_eq!(ImageFormatDetector::detect_from_extension("tiff"), ImageFormat::Tiff);
        assert_eq!(ImageFormatDetector::detect_from_extension("unknown"), ImageFormat::Unknown);
    }

    #[test]
    fn test_format_properties() {
        assert!(ImageFormat::Png.supports_lossless());
        assert!(!ImageFormat::Jpeg.supports_lossless());
        assert!(ImageFormat::Tiff.supports_multiple_pages());
        assert!(!ImageFormat::Jpeg.supports_multiple_pages());
    }

    #[test]
    fn test_mime_types() {
        assert_eq!(ImageFormat::Jpeg.mime_type(), "image/jpeg");
        assert_eq!(ImageFormat::Png.mime_type(), "image/png");
        assert_eq!(ImageFormat::Tiff.mime_type(), "image/tiff");
    }

    #[test]
    fn test_extensions() {
        let jpeg_exts = ImageFormat::Jpeg.extensions();
        assert!(jpeg_exts.contains(&"jpg"));
        assert!(jpeg_exts.contains(&"jpeg"));
        assert!(jpeg_exts.contains(&"jfif"));
    }
}
