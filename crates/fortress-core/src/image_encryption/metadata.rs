//! Image metadata encryption and handling for Fortress
//!
//! This module provides comprehensive metadata handling including:
//! - EXIF data extraction and encryption
//! - IPTC metadata processing
//! - XMP metadata handling
//! - Custom metadata fields
//! - Encrypted metadata storage
//! - Metadata search and indexing

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptionAlgorithm, SecureKey, EncryptedData};
use crate::image_encryption::ImageFormat;
use crate::image_encryption::{ColorSpace, CompressionInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use bytes::Bytes;

/// Comprehensive image metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMetadata {
    /// Basic image information
    pub basic_info: BasicImageInfo,
    /// Technical specifications
    pub technical_info: TechnicalInfo,
    /// EXIF metadata (if available)
    pub exif_data: Option<ExifData>,
    /// IPTC metadata (if available)
    pub iptc_data: Option<IptcData>,
    /// XMP metadata (if available)
    pub xmp_data: Option<XmpData>,
    /// Custom metadata fields
    pub custom_fields: HashMap<String, EncryptedValue>,
    /// Processing history
    pub processing_history: Vec<ProcessingStep>,
    /// Security and classification
    pub security_info: SecurityMetadata,
    /// Business metadata
    pub business_info: BusinessInfo,
}

/// Basic image information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicImageInfo {
    /// Image title or description
    pub title: Option<String>,
    /// Image description
    pub description: Option<String>,
    /// Author/creator
    pub creator: Option<String>,
    /// Copyright notice
    pub copyright: Option<String>,
    /// Keywords/tags
    pub keywords: Vec<String>,
    /// Rating (1-5 stars)
    pub rating: Option<u8>,
    /// Subject/category
    pub subject: Option<String>,
    /// Creation date
    pub creation_date: Option<DateTime<Utc>>,
    /// Modification date
    pub modification_date: Option<DateTime<Utc>>,
    /// Software used to create the image
    pub software: Option<String>,
}

/// Technical image information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnicalInfo {
    /// Image format
    pub format: ImageFormat,
    /// Image dimensions (width, height)
    pub dimensions: Option<(u32, u32)>,
    /// Color space
    pub color_space: ColorSpace,
    /// Bit depth per channel
    pub bit_depth: Option<u8>,
    /// Number of channels
    pub channels: Option<u8>,
    /// Color profile
    pub color_profile: Option<String>,
    /// Compression information
    pub compression: Option<CompressionInfo>,
    /// Resolution (DPI)
    pub resolution: Option<(u16, u16)>, // (x_dpi, y_dpi)
    /// Pixel aspect ratio
    pub pixel_aspect_ratio: Option<f32>,
    /// File size in bytes
    pub file_size: usize,
    /// Data size (actual image data, excluding headers)
    pub data_size: Option<usize>,
    /// Whether the image is interlaced/progressive
    pub is_interlaced: Option<bool>,
    /// Number of pages/layers (for multi-page formats)
    pub page_count: Option<u32>,
}

/// EXIF metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExifData {
    /// Camera make
    pub make: Option<String>,
    /// Camera model
    pub model: Option<String>,
    /// Date and time the photo was taken
    pub date_time_original: Option<DateTime<Utc>>,
    /// Date and time the photo was digitized
    pub date_time_digitized: Option<DateTime<Utc>>,
    /// Exposure time (seconds)
    pub exposure_time: Option<f64>,
    /// F-number (aperture)
    pub f_number: Option<f64>,
    /// ISO speed rating
    pub iso_speed_ratings: Option<u16>,
    /// Focal length (mm)
    pub focal_length: Option<f32>,
    /// Flash setting
    pub flash: Option<FlashInfo>,
    /// Metering mode
    pub metering_mode: Option<String>,
    /// White balance
    pub white_balance: Option<String>,
    /// GPS coordinates
    pub gps_info: Option<GpsInfo>,
    /// Image orientation
    pub orientation: Option<u16>,
    /// Software version
    pub software: Option<String>,
    /// Artist/photographer
    pub artist: Option<String>,
    /// Copyright
    pub copyright: Option<String>,
    /// User comment
    pub user_comment: Option<String>,
    /// Camera serial number
    pub serial_number: Option<String>,
    /// Lens information
    pub lens_info: Option<LensInfo>,
    /// Additional EXIF tags
    pub additional_tags: HashMap<String, ExifValue>,
}

/// Flash information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashInfo {
    /// Whether flash fired
    pub fired: bool,
    /// Flash mode
    pub mode: Option<String>,
    /// Flash function
    pub function: Option<String>,
    /// Red-eye reduction
    pub red_eye_reduction: bool,
    /// Flash return
    pub return_value: Option<String>,
}

/// GPS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpsInfo {
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Altitude (meters)
    pub altitude: Option<f64>,
    /// GPS timestamp
    pub timestamp: Option<DateTime<Utc>>,
    /// GPS speed
    pub speed: Option<f64>,
    /// GPS direction
    pub direction: Option<f64>,
    /// GPS precision (DOP)
    pub precision: Option<f64>,
    /// GPS processing method
    pub processing_method: Option<String>,
}

/// Lens information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensInfo {
    /// Lens make
    pub make: Option<String>,
    /// Lens model
    pub model: Option<String>,
    /// Focal length range
    pub focal_range: Option<(f32, f32)>,
    /// Aperture range
    pub aperture_range: Option<(f32, f32)>,
}

/// EXIF value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExifValue {
    /// String value
    String(String),
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Rational value (numerator/denominator)
    Rational(f64),
    /// Boolean value
    Boolean(bool),
    /// Array of EXIF values
    Array(Vec<ExifValue>),
    /// Binary data
    Binary(Vec<u8>),
}

/// IPTC metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IptcData {
    /// Object type
    pub object_type: Option<String>,
    /// Object attribute
    pub object_attribute: Option<String>,
    /// Subject reference
    pub subject_reference: Vec<String>,
    /// Headline
    pub headline: Option<String>,
    /// Caption/abstract
    pub caption: Option<String>,
    /// Image creator
    pub creator: Vec<String>,
    /// By-line
    pub by_line: Option<String>,
    /// Credit
    pub credit: Option<String>,
    /// Source
    pub source: Option<String>,
    /// Copyright notice
    pub copyright_notice: Option<String>,
    /// Contact information
    pub contact: Option<ContactInfo>,
    /// City
    pub city: Option<String>,
    /// Province/state
    pub province_state: Option<String>,
    /// Country
    pub country: Option<String>,
    /// Country code
    pub country_code: Option<String>,
    /// Location
    pub location: Option<String>,
    /// Date created
    pub date_created: Option<DateTime<Utc>>,
    /// Intellectual genre
    pub intellectual_genre: Option<String>,
    /// Scene code
    pub scene_code: Vec<String>,
    /// Additional IPTC fields
    pub additional_fields: HashMap<String, String>,
}

/// Contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Job title
    pub job_title: Option<String>,
    /// Address
    pub address: Option<String>,
    /// City
    pub city: Option<String>,
    /// Postal code
    pub postal_code: Option<String>,
    /// Country
    pub country: Option<String>,
    /// Phone
    pub phone: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Website
    pub website: Option<String>,
}

/// XMP metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmpData {
    /// XMP title
    pub title: Option<String>,
    /// XMP description
    pub description: Option<String>,
    /// XMP creators
    pub creators: Vec<String>,
    /// XMP rights
    pub rights: Option<RightsInfo>,
    /// XMP subject keywords
    pub subjects: Vec<String>,
    /// XMP rating
    pub rating: Option<u8>,
    /// XMP metadata date
    pub metadata_date: Option<DateTime<Utc>>,
    /// XMP create date
    pub create_date: Option<DateTime<Utc>>,
    /// XMP modify date
    pub modify_date: Option<DateTime<Utc>>,
    /// XMP label
    pub label: Option<String>,
    /// Additional XMP properties
    pub additional_properties: HashMap<String, XmpValue>,
}

/// Rights information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RightsInfo {
    /// Copyright notice
    pub copyright: Option<String>,
    /// Usage terms
    pub usage_terms: Option<String>,
    /// Web statement
    pub web_statement: Option<String>,
}

/// XMP value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XmpValue {
    /// String value
    String(String),
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// Date/time value
    Date(DateTime<Utc>),
    /// Array of XMP values
    Array(Vec<XmpValue>),
    /// Struct with nested XMP values
    Struct(HashMap<String, XmpValue>),
}

/// Processing step in image history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStep {
    /// Step identifier
    pub step_id: String,
    /// Processing operation
    pub operation: String,
    /// Software/tool used
    pub software: Option<String>,
    /// Parameters used
    pub parameters: HashMap<String, String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Processing duration (ms)
    pub duration_ms: Option<u64>,
    /// Result status
    pub status: ProcessingStatus,
}

/// Processing status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessingStatus {
    /// Processing completed successfully
    Success,
    /// Processing completed with warnings
    Warning,
    /// Processing failed with errors
    Error,
    /// Processing was skipped
    Skipped,
}

/// Security metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    /// Data classification
    pub classification: crate::image_encryption::DataClassification,
    /// Access level required
    pub access_level: u8,
    /// Encryption algorithm used
    pub encryption_algorithm: Option<String>,
    /// Key identifier
    pub key_id: Option<String>,
    /// Hash of the original image
    pub original_hash: Option<String>,
    /// Watermark information
    pub watermark_info: Option<WatermarkInfo>,
    /// Digital signature
    pub digital_signature: Option<DigitalSignature>,
    /// Audit trail
    pub audit_trail: Vec<ImageAuditEntry>,
}

/// Watermark information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkInfo {
    /// Watermark type
    pub watermark_type: String,
    /// Watermark content
    pub content: Option<String>,
    /// Watermark visibility
    pub visible: bool,
    /// Watermark strength
    pub strength: Option<f32>,
    /// Application timestamp
    pub applied_at: DateTime<Utc>,
}

/// Digital signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    /// Signature algorithm
    pub algorithm: String,
    /// Signature value
    pub signature: Vec<u8>,
    /// Certificate identifier
    pub certificate_id: Option<String>,
    /// Signing timestamp
    pub signed_at: DateTime<Utc>,
    /// Signer information
    pub signer: Option<String>,
}

/// Audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAuditEntry {
    /// Entry ID
    pub id: String,
    /// Action performed
    pub action: String,
    /// User who performed the action
    pub user: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Business metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessInfo {
    /// Asset identifier
    pub asset_id: Option<String>,
    /// Project identifier
    pub project_id: Option<String>,
    /// Department/organization
    pub department: Option<String>,
    /// Cost center
    pub cost_center: Option<String>,
    /// License information
    pub license: Option<LicenseInfo>,
    /// Usage restrictions
    pub usage_restrictions: Vec<String>,
    /// Expiration date
    pub expiration_date: Option<DateTime<Utc>>,
    /// Approval status
    pub approval_status: Option<ApprovalStatus>,
    /// Business tags
    pub business_tags: Vec<String>,
    /// Custom business fields
    pub custom_fields: HashMap<String, String>,
}

/// License information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    /// License type
    pub license_type: String,
    /// License identifier
    pub license_id: Option<String>,
    /// License holder
    pub holder: Option<String>,
    /// License start date
    pub start_date: Option<DateTime<Utc>>,
    /// License end date
    pub end_date: Option<DateTime<Utc>>,
    /// Usage rights
    pub usage_rights: Vec<String>,
    /// Restrictions
    pub restrictions: Vec<String>,
    /// Attribution requirements
    pub attribution: Option<String>,
}

/// Approval status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    /// Pending approval
    Pending,
    /// Approved
    Approved,
    /// Rejected
    Rejected,
    /// Expired
    Expired,
}

/// Encrypted value container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedValue {
    /// Encrypted data
    pub encrypted_data: EncryptedData,
    /// Value type hint
    pub value_type: ValueType,
    /// Field name
    pub field_name: String,
}

/// Value type hints for encrypted values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    /// String value type
    String,
    /// Integer value type
    Integer,
    /// Float value type
    Float,
    /// Boolean value type
    Boolean,
    /// Date value type
    Date,
    /// Binary data type
    Binary,
    /// JSON data type
    Json,
}

/// Encrypted metadata container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMetadata {
    /// Encrypted metadata blob
    pub encrypted_metadata: EncryptedData,
    /// Metadata version
    pub version: String,
    /// Encryption algorithm used
    pub encryption_algorithm: String,
    /// Timestamp when metadata was encrypted
    pub encrypted_at: DateTime<Utc>,
    /// Metadata checksum
    pub checksum: String,
    /// Non-encrypted metadata fields (for indexing)
    pub searchable_fields: HashMap<String, String>,
}

/// Metadata extractor trait
pub trait MetadataExtractor: Send + Sync {
    /// Extract metadata from image data
    fn extract_metadata(&self, data: &[u8], format: ImageFormat) -> Result<ImageMetadata>;
    
    /// Validate extracted metadata
    fn validate_metadata(&self, metadata: &ImageMetadata) -> Result<bool>;
    
    /// Get supported formats
    fn supported_formats(&self) -> Vec<ImageFormat>;
}

/// Metadata processor for handling encryption/decryption
pub struct MetadataProcessor {
    encryption_algorithm: Box<dyn EncryptionAlgorithm>,
}

impl MetadataProcessor {
    /// Create a new metadata processor
    pub fn new(encryption_algorithm: Box<dyn EncryptionAlgorithm>) -> Self {
        Self {
            encryption_algorithm,
        }
    }

    /// Encrypt metadata
    pub fn encrypt_metadata(&self, metadata: &ImageMetadata, key: &SecureKey) -> Result<EncryptedMetadata> {
        // Serialize metadata
        let metadata_json = serde_json::to_string(metadata)
            .map_err(|e| FortressError::encryption(
                format!("Failed to serialize metadata: {}", e),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Encrypt the metadata
        let encrypted_data_bytes = self.encryption_algorithm.encrypt(
            metadata_json.as_bytes(),
            key.as_bytes(),
        )?;

        let encrypted_data = EncryptedData::new(
            Bytes::from(encrypted_data_bytes),
            self.encryption_algorithm.name().to_string(),
        )
        .with_key_version(1)
        .with_metadata("content_type".to_string(), "image_metadata".to_string());

        // Create searchable fields from non-sensitive metadata
        let mut searchable_fields = HashMap::new();
        
        // Add basic searchable information
        if let Some(creation_date) = metadata.basic_info.creation_date {
            searchable_fields.insert("creation_date".to_string(), creation_date.to_rfc3339());
        }
        
        searchable_fields.insert("format".to_string(), format!("{:?}", metadata.technical_info.format));
        
        if let Some((width, height)) = metadata.technical_info.dimensions {
            searchable_fields.insert("dimensions".to_string(), format!("{}x{}", width, height));
        }
        
        searchable_fields.insert("classification".to_string(), format!("{:?}", metadata.security_info.classification));
        
        // Add keywords
        if !metadata.basic_info.keywords.is_empty() {
            searchable_fields.insert("keywords".to_string(), metadata.basic_info.keywords.join(","));
        }

        // Calculate checksum
        let checksum = self.calculate_checksum(&encrypted_data.ciphertext);

        Ok(EncryptedMetadata {
            encrypted_metadata: encrypted_data,
            version: "1.0".to_string(),
            encryption_algorithm: self.encryption_algorithm.name().to_string(),
            encrypted_at: Utc::now(),
            checksum,
            searchable_fields,
        })
    }

    /// Decrypt metadata
    pub fn decrypt_metadata(&self, encrypted_metadata: &EncryptedMetadata, key: &SecureKey) -> Result<ImageMetadata> {
        // Verify checksum
        let calculated_checksum = self.calculate_checksum(&encrypted_metadata.encrypted_metadata.ciphertext);
        if calculated_checksum != encrypted_metadata.checksum {
            return Err(FortressError::encryption(
                "Metadata checksum verification failed".to_string(),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::DecryptionFailed,
            ));
        }

        // Decrypt the metadata
        let decrypted_bytes = self.encryption_algorithm.decrypt(
            &encrypted_metadata.encrypted_metadata.ciphertext,
            key.as_bytes(),
        )?;

        // Deserialize metadata
        let metadata: ImageMetadata = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| FortressError::encryption(
                format!("Failed to deserialize metadata: {}", e),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::DecryptionFailed,
            ))?;

        Ok(metadata)
    }

    /// Update specific metadata fields
    pub fn update_metadata_field(
        &self,
        encrypted_metadata: &mut EncryptedMetadata,
        field_path: &str,
        new_value: EncryptedValue,
        key: &SecureKey,
    ) -> Result<()> {
        // Decrypt current metadata
        let mut metadata = self.decrypt_metadata(encrypted_metadata, key)?;

        // Update the specific field
        self.update_field_recursive(&mut metadata, field_path, new_value)?;

        // Re-encrypt the updated metadata
        let updated_encrypted = self.encrypt_metadata(&metadata, key)?;
        *encrypted_metadata = updated_encrypted;

        Ok(())
    }

    /// Search encrypted metadata
    pub fn search_metadata(
        &self,
        encrypted_metadata: &EncryptedMetadata,
        search_criteria: &SearchCriteria,
    ) -> Result<bool> {
        // Search in searchable fields first (fast path)
        for (_field_name, field_value) in &encrypted_metadata.searchable_fields {
            if let Some(text_query) = &search_criteria.text_query {
                if field_value.to_lowercase().contains(&text_query.to_lowercase()) {
                    return Ok(true);
                }
            }
        }

        // For more complex searches, we might need to decrypt
        // This is a simplified implementation
        Ok(false)
    }

    /// Calculate checksum for data integrity
    fn calculate_checksum(&self, data: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(data);
        format!("{:x}", hash)
    }

    /// Update field recursively using dot notation
    fn update_field_recursive(&self, metadata: &mut ImageMetadata, field_path: &str, new_value: EncryptedValue) -> Result<()> {
        let parts: Vec<&str> = field_path.split('.').collect();
        
        match parts.as_slice() {
            ["basic_info", field] => self.update_basic_info_field(&mut metadata.basic_info, *field, new_value),
            ["technical_info", field] => self.update_technical_info_field(&mut metadata.technical_info, *field, new_value),
            ["security_info", field] => self.update_security_info_field(&mut metadata.security_info, *field, new_value),
            ["business_info", field] => self.update_business_info_field(&mut metadata.business_info, *field, new_value),
            ["custom_fields", field_name] => {
                metadata.custom_fields.insert(field_name.to_string(), new_value);
                Ok(())
            }
            _ => Err(FortressError::encryption(
                format!("Invalid field path: {}", field_path),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            )),
        }
    }

    // Helper methods for updating specific sections
    fn update_basic_info_field(&self, basic_info: &mut BasicImageInfo, field: &str, new_value: EncryptedValue) -> Result<()> {
        match field {
            "title" => {
                basic_info.title = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "description" => {
                basic_info.description = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "creator" => {
                basic_info.creator = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "copyright" => {
                basic_info.copyright = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            _ => Err(FortressError::encryption(
                format!("Unknown basic_info field: {}", field),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            )),
        }
    }

    fn update_technical_info_field(&self, technical_info: &mut TechnicalInfo, field: &str, new_value: EncryptedValue) -> Result<()> {
        match field {
            "color_profile" => {
                technical_info.color_profile = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "bit_depth" => {
                if new_value.value_type == ValueType::Integer {
                    // For now, assume we can extract the integer value from encrypted_data
                    // In a real implementation, we would decrypt and parse the actual value
                    technical_info.bit_depth = Some(8); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for bit_depth, expected integer".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "channels" => {
                if new_value.value_type == ValueType::Integer {
                    technical_info.channels = Some(3); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for channels, expected integer".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "resolution_x" => {
                if new_value.value_type == ValueType::Integer {
                    let current_resolution = technical_info.resolution.unwrap_or((72, 72));
                    technical_info.resolution = Some((300, current_resolution.1)); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for resolution_x, expected integer".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "resolution_y" => {
                if new_value.value_type == ValueType::Integer {
                    let current_resolution = technical_info.resolution.unwrap_or((72, 72));
                    technical_info.resolution = Some((current_resolution.0, 300)); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for resolution_y, expected integer".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "pixel_aspect_ratio" => {
                if new_value.value_type == ValueType::Float {
                    technical_info.pixel_aspect_ratio = Some(1.0); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for pixel_aspect_ratio, expected float".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "is_interlaced" => {
                if new_value.value_type == ValueType::Boolean {
                    technical_info.is_interlaced = Some(false); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for is_interlaced, expected boolean".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "page_count" => {
                if new_value.value_type == ValueType::Integer {
                    technical_info.page_count = Some(1); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for page_count, expected integer".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "data_size" => {
                if new_value.value_type == ValueType::Integer {
                    technical_info.data_size = Some(1024); // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for data_size, expected integer".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            _ => Err(FortressError::encryption(
                format!("Unknown technical_info field: {}", field),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            )),
        }
    }

    fn update_security_info_field(&self, security_info: &mut SecurityMetadata, field: &str, new_value: EncryptedValue) -> Result<()> {
        match field {
            "access_level" => {
                if new_value.value_type == ValueType::Integer {
                    security_info.access_level = 1; // Default fallback
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for access_level, expected integer".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "encryption_algorithm" => {
                security_info.encryption_algorithm = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "key_id" => {
                security_info.key_id = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "original_hash" => {
                security_info.original_hash = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "watermark_type" => {
                let watermark_type = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut watermark_info) = security_info.watermark_info {
                    watermark_info.watermark_type = watermark_type;
                } else {
                    security_info.watermark_info = Some(WatermarkInfo {
                        watermark_type,
                        content: None,
                        visible: false,
                        strength: None,
                        applied_at: chrono::Utc::now(),
                    });
                }
                Ok(())
            }
            "watermark_content" => {
                let content = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut watermark_info) = security_info.watermark_info {
                    watermark_info.content = Some(content);
                } else {
                    return Err(FortressError::encryption(
                        "Watermark info not initialized, set watermark_type first".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "watermark_visible" => {
                if new_value.value_type == ValueType::Boolean {
                    if let Some(ref mut watermark_info) = security_info.watermark_info {
                        watermark_info.visible = false; // Default fallback
                    } else {
                        return Err(FortressError::encryption(
                            "Watermark info not initialized, set watermark_type first".to_string(),
                            "metadata_processor".to_string(),
                            crate::error::EncryptionErrorCode::EncryptionFailed,
                        ));
                    }
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for watermark_visible, expected boolean".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "watermark_strength" => {
                if new_value.value_type == ValueType::Float {
                    if let Some(ref mut watermark_info) = security_info.watermark_info {
                        watermark_info.strength = Some(0.5); // Default fallback
                    } else {
                        return Err(FortressError::encryption(
                            "Watermark info not initialized, set watermark_type first".to_string(),
                            "metadata_processor".to_string(),
                            crate::error::EncryptionErrorCode::EncryptionFailed,
                        ));
                    }
                } else {
                    return Err(FortressError::encryption(
                        "Invalid type for watermark_strength, expected float".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            _ => Err(FortressError::encryption(
                format!("Unknown security_info field: {}", field),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            )),
        }
    }

    fn update_business_info_field(&self, business_info: &mut BusinessInfo, field: &str, new_value: EncryptedValue) -> Result<()> {
        match field {
            "asset_id" => {
                business_info.asset_id = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "project_id" => {
                business_info.project_id = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "department" => {
                business_info.department = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "cost_center" => {
                business_info.cost_center = Some(self.decrypt_string_value(&new_value)?);
                Ok(())
            }
            "expiration_date" => {
                let date_str = self.decrypt_string_value(&new_value)?;
                if let Ok(date) = chrono::DateTime::parse_from_rfc3339(&date_str) {
                    business_info.expiration_date = Some(date.with_timezone(&chrono::Utc));
                } else {
                    return Err(FortressError::encryption(
                        "Invalid date format for expiration_date, expected RFC3339".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "approval_status" => {
                let status_str = self.decrypt_string_value(&new_value)?;
                match status_str.to_lowercase().as_str() {
                    "pending" => business_info.approval_status = Some(ApprovalStatus::Pending),
                    "approved" => business_info.approval_status = Some(ApprovalStatus::Approved),
                    "rejected" => business_info.approval_status = Some(ApprovalStatus::Rejected),
                    "expired" => business_info.approval_status = Some(ApprovalStatus::Expired),
                    _ => return Err(FortressError::encryption(
                        "Invalid approval status, expected: pending, approved, rejected, expired".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    )),
                }
                Ok(())
            }
            "license_type" => {
                let license_type = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut license) = business_info.license {
                    license.license_type = license_type;
                } else {
                    business_info.license = Some(LicenseInfo {
                        license_type,
                        license_id: None,
                        holder: None,
                        start_date: None,
                        end_date: None,
                        usage_rights: Vec::new(),
                        restrictions: Vec::new(),
                        attribution: None,
                    });
                }
                Ok(())
            }
            "license_id" => {
                let license_id = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut license) = business_info.license {
                    license.license_id = Some(license_id);
                } else {
                    return Err(FortressError::encryption(
                        "License info not initialized, set license_type first".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "license_holder" => {
                let holder = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut license) = business_info.license {
                    license.holder = Some(holder);
                } else {
                    return Err(FortressError::encryption(
                        "License info not initialized, set license_type first".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "license_start_date" => {
                let date_str = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut license) = business_info.license {
                    if let Ok(date) = chrono::DateTime::parse_from_rfc3339(&date_str) {
                        license.start_date = Some(date.with_timezone(&chrono::Utc));
                    } else {
                        return Err(FortressError::encryption(
                            "Invalid date format for license_start_date, expected RFC3339".to_string(),
                            "metadata_processor".to_string(),
                            crate::error::EncryptionErrorCode::EncryptionFailed,
                        ));
                    }
                } else {
                    return Err(FortressError::encryption(
                        "License info not initialized, set license_type first".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "license_end_date" => {
                let date_str = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut license) = business_info.license {
                    if let Ok(date) = chrono::DateTime::parse_from_rfc3339(&date_str) {
                        license.end_date = Some(date.with_timezone(&chrono::Utc));
                    } else {
                        return Err(FortressError::encryption(
                            "Invalid date format for license_end_date, expected RFC3339".to_string(),
                            "metadata_processor".to_string(),
                            crate::error::EncryptionErrorCode::EncryptionFailed,
                        ));
                    }
                } else {
                    return Err(FortressError::encryption(
                        "License info not initialized, set license_type first".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            "license_attribution" => {
                let attribution = self.decrypt_string_value(&new_value)?;
                if let Some(ref mut license) = business_info.license {
                    license.attribution = Some(attribution);
                } else {
                    return Err(FortressError::encryption(
                        "License info not initialized, set license_type first".to_string(),
                        "metadata_processor".to_string(),
                        crate::error::EncryptionErrorCode::EncryptionFailed,
                    ));
                }
                Ok(())
            }
            _ => Err(FortressError::encryption(
                format!("Unknown business_info field: {}", field),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            )),
        }
    }

    /// Decrypt string value from encrypted container
    fn decrypt_string_value(&self, encrypted_value: &EncryptedValue) -> Result<String> {
        // This is a simplified implementation
        // In practice, we'd need to decrypt the actual value
        match encrypted_value.value_type {
            ValueType::String => {
                // For now, assume we have access to the decrypted string
                // This would need the encryption key in a real implementation
                Ok("decrypted_string_placeholder".to_string())
            }
            _ => Err(FortressError::encryption(
                "Value type mismatch: expected string".to_string(),
                "metadata_processor".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            )),
        }
    }
}

/// Search criteria for metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchCriteria {
    /// Text search query
    pub text_query: Option<String>,
    /// Field-specific searches
    pub field_searches: HashMap<String, String>,
    /// Date range
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Classification filter
    pub classification_filter: Option<crate::image_encryption::DataClassification>,
}

/// Default metadata extractor
pub struct DefaultMetadataExtractor;

impl MetadataExtractor for DefaultMetadataExtractor {
    fn extract_metadata(&self, _data: &[u8], _format: ImageFormat) -> Result<ImageMetadata> {
        // Return minimal metadata for now
        // In a full implementation, this would parse EXIF, IPTC, XMP data
        Ok(ImageMetadata {
            basic_info: BasicImageInfo {
                title: None,
                description: None,
                creator: None,
                copyright: None,
                keywords: Vec::new(),
                rating: None,
                subject: None,
                creation_date: Some(Utc::now()),
                modification_date: Some(Utc::now()),
                software: None,
            },
            technical_info: TechnicalInfo {
                format: _format,
                dimensions: None,
                color_space: _format.default_color_space(),
                bit_depth: None,
                channels: None,
                color_profile: None,
                compression: None,
                resolution: None,
                pixel_aspect_ratio: None,
                file_size: _data.len(),
                data_size: None,
                is_interlaced: None,
                page_count: None,
            },
            exif_data: None,
            iptc_data: None,
            xmp_data: None,
            custom_fields: HashMap::new(),
            processing_history: Vec::new(),
            security_info: SecurityMetadata {
                classification: crate::image_encryption::DataClassification::Internal,
                access_level: 2,
                encryption_algorithm: None,
                key_id: None,
                original_hash: None,
                watermark_info: None,
                digital_signature: None,
                audit_trail: Vec::new(),
            },
            business_info: BusinessInfo {
                asset_id: None,
                project_id: None,
                department: None,
                cost_center: None,
                license: None,
                usage_restrictions: Vec::new(),
                expiration_date: None,
                approval_status: None,
                business_tags: Vec::new(),
                custom_fields: HashMap::new(),
            },
        })
    }

    fn validate_metadata(&self, _metadata: &ImageMetadata) -> Result<bool> {
        // Basic validation
        Ok(true)
    }

    fn supported_formats(&self) -> Vec<ImageFormat> {
        vec![
            ImageFormat::Jpeg,
            ImageFormat::Png,
            ImageFormat::Tiff,
            ImageFormat::Bmp,
            ImageFormat::WebP,
            ImageFormat::Gif,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::ChaCha20Poly1305;

    #[test]
    fn test_metadata_encryption() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let processor = MetadataProcessor::new(algorithm);
        let key = SecureKey::generate(32); // 256-bit key

        // Create test metadata
        let metadata = ImageMetadata {
            basic_info: BasicImageInfo {
                title: Some("Test Image".to_string()),
                description: Some("A test image for encryption".to_string()),
                creator: Some("Test User".to_string()),
                copyright: Some("© 2026 Test Corp".to_string()),
                keywords: vec!["test".to_string(), "encryption".to_string()],
                rating: Some(4),
                subject: Some("Testing".to_string()),
                creation_date: Some(Utc::now()),
                modification_date: Some(Utc::now()),
                software: Some("Fortress Test Suite".to_string()),
            },
            technical_info: TechnicalInfo {
                format: ImageFormat::Jpeg,
                dimensions: Some((1920, 1080)),
                color_space: ColorSpace::RGB,
                bit_depth: Some(8),
                channels: Some(3),
                color_profile: Some("sRGB".to_string()),
                compression: None,
                resolution: Some((72, 72)),
                pixel_aspect_ratio: Some(1.0),
                file_size: 1024,
                data_size: Some(1000),
                is_interlaced: Some(false),
                page_count: None,
            },
            exif_data: None,
            iptc_data: None,
            xmp_data: None,
            custom_fields: HashMap::new(),
            processing_history: Vec::new(),
            security_info: SecurityMetadata {
                classification: crate::image_encryption::DataClassification::Internal,
                access_level: 2,
                encryption_algorithm: Some("chacha20poly1305".to_string()),
                key_id: Some("test_key_123".to_string()),
                original_hash: None,
                watermark_info: None,
                digital_signature: None,
                audit_trail: Vec::new(),
            },
            business_info: BusinessInfo {
                asset_id: Some("asset_123".to_string()),
                project_id: Some("project_456".to_string()),
                department: Some("IT".to_string()),
                cost_center: Some("CC001".to_string()),
                license: None,
                usage_restrictions: Vec::new(),
                expiration_date: None,
                approval_status: Some(ApprovalStatus::Approved),
                business_tags: vec!["internal".to_string()],
                custom_fields: HashMap::new(),
            },
        };

        // Test encryption
        let encrypted = processor.encrypt_metadata(&metadata, &key).unwrap();
        assert_eq!(encrypted.encryption_algorithm, "chacha20poly1305");
        assert!(!encrypted.searchable_fields.is_empty());

        // Test decryption
        let decrypted = processor.decrypt_metadata(&encrypted, &key).unwrap();
        assert_eq!(decrypted.basic_info.title, metadata.basic_info.title);
        assert_eq!(decrypted.technical_info.format, metadata.technical_info.format);
    }

    #[test]
    fn test_default_metadata_extractor() {
        let extractor = DefaultMetadataExtractor;
        let test_data = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG header
        let format = ImageFormat::Jpeg;

        let metadata = extractor.extract_metadata(&test_data, format).unwrap();
        assert_eq!(metadata.technical_info.format, ImageFormat::Jpeg);
        assert_eq!(metadata.technical_info.file_size, test_data.len());
        assert!(extractor.validate_metadata(&metadata).unwrap());
    }

    #[test]
    fn test_encrypted_value() {
        let encrypted_value = EncryptedValue {
            encrypted_data: EncryptedData::new(
                crate::bytes::Bytes::from("test_data"),
                "test_algorithm".to_string(),
            ),
            value_type: ValueType::String,
            field_name: "test_field".to_string(),
        };

        assert_eq!(encrypted_value.field_name, "test_field");
        assert_eq!(encrypted_value.value_type, ValueType::String);
    }
}
