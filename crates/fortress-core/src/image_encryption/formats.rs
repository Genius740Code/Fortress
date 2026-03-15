//! Image format support and detection for Fortress image encryption
//!
//! This module provides comprehensive support for various image formats including:
//! - Common formats: JPEG, PNG, TIFF, BMP, WebP, GIF
//! - Advanced formats: HEIC, AVIF, JXL
//! - Medical imaging: DICOM
//! - RAW formats: CR2, NEF, ARW, DNG, etc.
//! - Scientific formats: FITS, NIfTI

use crate::error::{FortressError, Result};
use crate::image_encryption::{ColorSpace, CompressionInfo};
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
/// JPEG image processor
pub struct JpegProcessor;
/// PNG image processor
pub struct PngProcessor;
/// TIFF image processor
pub struct TiffProcessor;
/// BMP image processor
pub struct BmpProcessor;
/// WebP image processor
pub struct WebPProcessor;
/// GIF image processor
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
    
    fn extract_metadata(&self, data: &[u8]) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        
        if data.len() < 4 {
            return Ok(metadata);
        }
        
        // Check for JPEG signature
        if data[0] != 0xFF || data[1] != 0xD8 {
            return Ok(metadata);
        }
        
        let mut pos = 2;
        
        while pos + 4 <= data.len() {
            // Look for marker
            if data[pos] != 0xFF {
                break;
            }
            
            let marker = data[pos + 1];
            pos += 2;
            
            // Skip SOF, EOI, and RST markers
            if marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0xD9 {
                continue;
            }
            
            // Read segment length
            if pos + 2 > data.len() {
                break;
            }
            
            let segment_length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            if pos + segment_length > data.len() {
                break;
            }
            
            let segment_data = &data[pos + 2..pos + segment_length];
            
            // Extract metadata from different segments
            match marker {
                0xE0 => {
                    metadata.insert("app0_jfif".to_string(), "JFIF".to_string());
                }
                0xE1 => {
                    // EXIF data
                    if segment_length > 6 && &segment_data[0..4] == b"Exif" {
                        metadata.insert("exif_present".to_string(), "true".to_string());
                        
                        // Parse basic EXIF info
                        self.parse_exif_data(segment_data, &mut metadata);
                    }
                    
                    // XMP data (can also be in APP1)
                    if segment_length > 30 {
                        let segment_str = String::from_utf8_lossy(segment_data);
                        if segment_str.contains("http://ns.adobe.com/xap/1.0/") {
                            metadata.insert("xmp_present".to_string(), "true".to_string());
                            self.parse_xmp_data(segment_data, &mut metadata);
                        }
                    }
                }
                0xED => {
                    // IPTC data
                    if segment_length > 14 && &segment_data[0..8] == b"Photoshop" {
                        metadata.insert("iptc_present".to_string(), "true".to_string());
                        self.parse_iptc_data(segment_data, &mut metadata);
                    }
                }
                0xE2 => {
                    // XMP data (in APP2)
                    if segment_length > 30 {
                        let segment_str = String::from_utf8_lossy(segment_data);
                        if segment_str.contains("http://ns.adobe.com/xap/1.0/") {
                            metadata.insert("xmp_present".to_string(), "true".to_string());
                            self.parse_xmp_data(segment_data, &mut metadata);
                        }
                    }
                }
                _ => {}
            };
            
            pos += segment_length;
        }
        
        Ok(metadata)
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(Some(CompressionInfo {
            compression_type: "JPEG".to_string(),
            level: None,
            is_lossy: true,
            ratio: None,
        }))
    }
    
    fn get_dimensions(&self, data: &[u8]) -> Result<Option<(u32, u32)>> {
        if data.len() < 4 {
            return Ok(None);
        }
        
        // Check for JPEG signature
        if data[0] != 0xFF || data[1] != 0xD8 {
            return Ok(None);
        }
        
        let mut pos = 2;
        
        while pos + 4 <= data.len() {
            // Look for marker
            if data[pos] != 0xFF {
                break;
            }
            
            let marker = data[pos + 1];
            pos += 2;
            
            // Look for SOF (Start of Frame) markers which contain dimensions
            match marker {
                0xC0 | 0xC1 | 0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD | 0xCE | 0xCF => {
                    // SOF markers
                    if pos + 2 > data.len() {
                        break;
                    }
                    
                    let segment_length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    if pos + segment_length > data.len() || segment_length < 8 {
                        break;
                    }
                    
                    // Extract dimensions from SOF segment
                    // Format: [length][precision][height][width]...
                    let height = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as u32;
                    let width = u16::from_be_bytes([data[pos + 5], data[pos + 6]]) as u32;
                    
                    return Ok(Some((width, height)));
                }
                _ => {
                    // Skip other markers
                    if pos + 2 > data.len() {
                        break;
                    }
                    let segment_length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    if pos + segment_length > data.len() {
                        break;
                    }
                    pos += segment_length;
                }
            }
        }
        
        Ok(None)
    }
}

impl JpegProcessor {
    /// Parse basic EXIF data from segment
    fn parse_exif_data(&self, data: &[u8], metadata: &mut HashMap<String, String>) {
        if data.len() < 8 {
            return;
        }
        
        // Skip "Exif\0\0" header
        let exif_data = &data[6..];
        
        // Look for TIFF header
        if exif_data.len() < 8 {
            return;
        }
        
        // Check byte order (II for Intel, MM for Motorola)
        let byte_order = if &exif_data[0..2] == b"II" {
            "LittleEndian"
        } else if &exif_data[0..2] == b"MM" {
            "BigEndian"
        } else {
            return;
        };
        
        metadata.insert("exif_byte_order".to_string(), byte_order.to_string());
        
        // Extract some basic EXIF tags (simplified implementation)
        // In a full implementation, we would parse the IFD structure
        metadata.insert("exif_format".to_string(), "TIFF".to_string());
    }
    
    /// Parse basic IPTC data from segment
    fn parse_iptc_data(&self, data: &[u8], metadata: &mut HashMap<String, String>) {
        if data.len() < 14 {
            return;
        }
        
        // Look for 8BIM resource blocks
        let mut pos = 0;
        while pos + 8 < data.len() {
            if &data[pos..pos + 4] == b"8BIM" {
                pos += 4;
                
                if pos + 2 > data.len() {
                    break;
                }
                
                // Resource type and name
                let resource_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                
                // Skip name (p-string)
                if pos >= data.len() {
                    break;
                }
                let name_len = data[pos] as usize;
                pos += 1 + name_len;
                if pos % 2 == 1 {
                    pos += 1; // Align to even byte
                }
                
                // Resource size
                if pos + 4 > data.len() {
                    break;
                }
                let resource_size = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
                pos += 4;
                
                if pos + resource_size > data.len() {
                    break;
                }
                
                // Check for IPTC data (resource type 1028)
                if resource_type == 1028 {
                    metadata.insert("iptc_resource_size".to_string(), resource_size.to_string());
                    // In a full implementation, we would parse the IPTC tags
                    break;
                }
                
                pos += resource_size;
            } else {
                pos += 1;
            }
        }
    }
    
    /// Parse basic XMP data from segment
    fn parse_xmp_data(&self, data: &[u8], metadata: &mut HashMap<String, String>) {
        let xmp_str = String::from_utf8_lossy(data);
        
        // Extract some basic XMP information
        if xmp_str.contains("x:xmpmeta") {
            metadata.insert("xmp_format".to_string(), "XMP".to_string());
        }
        
        // Look for common XMP namespaces
        if xmp_str.contains("dc:") {
            metadata.insert("xmp_dc_namespace".to_string(), "present".to_string());
        }
        if xmp_str.contains("xmp:") {
            metadata.insert("xmp_xmp_namespace".to_string(), "present".to_string());
        }
        if xmp_str.contains("photoshop:") {
            metadata.insert("xmp_photoshop_namespace".to_string(), "present".to_string());
        }
    }
}

impl FormatProcessor for PngProcessor {
    fn process_for_encryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn process_after_decryption(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    fn extract_metadata(&self, data: &[u8]) -> Result<HashMap<String, String>> {
        let mut metadata = HashMap::new();
        
        if data.len() < 8 {
            return Ok(metadata);
        }
        
        // Check for PNG signature
        if &data[0..8] != b"\x89PNG\r\n\x1a\n" {
            return Ok(metadata);
        }
        
        let mut pos = 8;
        
        while pos + 8 <= data.len() {
            // Read chunk length
            let chunk_length = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            
            if pos + 4 > data.len() {
                break;
            }
            
            // Read chunk type
            let chunk_type = &data[pos..pos + 4];
            pos += 4;
            
            if pos + chunk_length > data.len() {
                break;
            }
            
            let chunk_data = &data[pos..pos + chunk_length];
            pos += chunk_length;
            
            // Skip CRC (4 bytes)
            pos += 4;
            
            // Process different chunk types
            match chunk_type {
                b"IHDR" => {
                    if chunk_length >= 13 {
                        let width = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]]);
                        let height = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
                        let bit_depth = chunk_data[8];
                        let color_type = chunk_data[9];
                        let compression = chunk_data[10];
                        let filter = chunk_data[11];
                        let interlace = chunk_data[12];
                        
                        metadata.insert("png_width".to_string(), width.to_string());
                        metadata.insert("png_height".to_string(), height.to_string());
                        metadata.insert("png_bit_depth".to_string(), bit_depth.to_string());
                        metadata.insert("png_color_type".to_string(), color_type.to_string());
                        metadata.insert("png_compression".to_string(), compression.to_string());
                        metadata.insert("png_filter".to_string(), filter.to_string());
                        metadata.insert("png_interlace".to_string(), interlace.to_string());
                    }
                }
                b"tEXt" => {
                    // Text metadata chunks
                    if let Some(null_pos) = chunk_data.iter().position(|&b| b == 0) {
                        if null_pos > 0 {
                            let keyword = String::from_utf8_lossy(&chunk_data[..null_pos]);
                            let text = String::from_utf8_lossy(&chunk_data[null_pos + 1..]);
                            metadata.insert(format!("png_text_{}", keyword), text.to_string());
                        }
                    }
                }
                b"iTXt" => {
                    // International text metadata chunks
                    metadata.insert("png_itxt_present".to_string(), "true".to_string());
                }
                b"zTXt" => {
                    // Compressed text metadata chunks
                    if let Some(null_pos) = chunk_data.iter().position(|&b| b == 0) {
                        if null_pos > 0 {
                            let keyword = String::from_utf8_lossy(&chunk_data[..null_pos]);
                            metadata.insert(format!("png_ztxt_{}", keyword), "compressed".to_string());
                        }
                    }
                }
                b"tIME" => {
                    // Time chunk
                    if chunk_length >= 7 {
                        let year = u16::from_be_bytes([chunk_data[0], chunk_data[1]]);
                        let month = chunk_data[2];
                        let day = chunk_data[3];
                        let hour = chunk_data[4];
                        let minute = chunk_data[5];
                        let second = chunk_data[6];
                        
                        metadata.insert("png_time".to_string(), 
                            format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hour, minute, second));
                    }
                }
                b"pHYs" => {
                    // Physical pixel dimensions
                    if chunk_length >= 9 {
                        let pixels_per_unit_x = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]]);
                        let pixels_per_unit_y = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
                        let unit = chunk_data[8];
                        
                        metadata.insert("png_pixels_per_unit_x".to_string(), pixels_per_unit_x.to_string());
                        metadata.insert("png_pixels_per_unit_y".to_string(), pixels_per_unit_y.to_string());
                        metadata.insert("png_unit".to_string(), if unit == 1 { "meter".to_string() } else { "unknown".to_string() });
                    }
                }
                b"sRGB" => {
                    // sRGB rendering intent
                    if chunk_length >= 1 {
                        let rendering_intent = chunk_data[0];
                        metadata.insert("png_srgb".to_string(), "true".to_string());
                        metadata.insert("png_rendering_intent".to_string(), rendering_intent.to_string());
                    }
                }
                b"gAMA" => {
                    // Gamma chunk
                    if chunk_length >= 4 {
                        let gamma = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]]);
                        let gamma_value = gamma as f64 / 100000.0;
                        metadata.insert("png_gamma".to_string(), format!("{:.5}", gamma_value));
                    }
                }
                b"cHRM" => {
                    // Chromaticity chunk
                    metadata.insert("png_chromaticity".to_string(), "present".to_string());
                }
                _ => {}
            }
            
            // Break on IEND chunk
            if chunk_type == b"IEND" {
                break;
            }
        }
        
        Ok(metadata)
    }
    
    fn get_compression_info(&self, _data: &[u8]) -> Result<Option<CompressionInfo>> {
        Ok(Some(CompressionInfo {
            compression_type: "DEFLATE".to_string(),
            level: None,
            is_lossy: false,
            ratio: None,
        }))
    }
    
    fn get_dimensions(&self, data: &[u8]) -> Result<Option<(u32, u32)>> {
        if data.len() < 8 {
            return Ok(None);
        }
        
        // Check for PNG signature
        if &data[0..8] != b"\x89PNG\r\n\x1a\n" {
            return Ok(None);
        }
        
        // The first chunk should be IHDR
        if data.len() < 25 {
            return Ok(None);
        }
        
        // Check if first chunk is IHDR
        if &data[12..16] != b"IHDR" {
            return Ok(None);
        }
        
        // Extract dimensions from IHDR chunk
        // Format: [4 bytes length][4 bytes type][4 bytes width][4 bytes height]...
        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        
        Ok(Some((width, height)))
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
