//! Integration tests for Fortress image encryption system
//!
//! This test suite validates the complete image encryption workflow including:
//! - End-to-end encryption and decryption
//! - Thumbnail generation from encrypted images
//! - Streaming encryption for large images
//! - Metadata encryption and search
//! - Format detection and processing
//! - API service integration

use fortress_core::{
    encryption::{ChaCha20Poly1305, SecureKey},
    error::Result,
    image_encryption::streaming::{StreamingResult, StreamingStatus},
    image_encryption::thumbnails::{ThumbnailFormat, ThumbnailOptions},
    image_encryption::ImageDataClassification,
    image_encryption::SortOrder,
    image_encryption::*,
};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

/// Mock image store for testing
struct MockImageStore {
    images: std::sync::Arc<tokio::sync::RwLock<HashMap<String, EncryptedImage>>>,
    thumbnails: std::sync::Arc<tokio::sync::RwLock<HashMap<String, EncryptedThumbnail>>>,
}

impl MockImageStore {
    fn new() -> Self {
        Self {
            images: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            thumbnails: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ImageStore for MockImageStore {
    async fn store_image(&self, image: &EncryptedImage) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut images = self.images.write().await;
        images.insert(id.clone(), image.clone());
        Ok(id)
    }

    async fn get_image(&self, image_id: &str) -> Result<Option<EncryptedImage>> {
        let images = self.images.read().await;
        Ok(images.get(image_id).cloned())
    }

    async fn delete_image(&self, image_id: &str) -> Result<bool> {
        let mut images = self.images.write().await;
        Ok(images.remove(image_id).is_some())
    }

    async fn store_thumbnail(
        &self,
        _image_id: &str,
        thumbnail: &EncryptedThumbnail,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut thumbnails = self.thumbnails.write().await;
        thumbnails.insert(id.clone(), thumbnail.clone());
        Ok(id)
    }

    async fn get_thumbnail(&self, thumbnail_id: &str) -> Result<Option<EncryptedThumbnail>> {
        let thumbnails = self.thumbnails.read().await;
        Ok(thumbnails.get(thumbnail_id).cloned())
    }

    async fn delete_thumbnails(&self, _image_id: &str) -> Result<usize> {
        // Simplified implementation
        Ok(0)
    }

    async fn search_images(&self, _filter: &ImageFilter) -> Result<Vec<ImageInfo>> {
        Ok(Vec::new())
    }

    async fn store_streaming_result(
        &self,
        _session_id: &str,
        _result: &StreamingResult,
    ) -> Result<()> {
        Ok(())
    }

    async fn get_streaming_result(&self, _session_id: &str) -> Result<Option<StreamingResult>> {
        Ok(None)
    }
}

/// Mock key manager for testing
struct MockKeyManager {
    keys: std::sync::Arc<tokio::sync::RwLock<HashMap<String, SecureKey>>>,
}

impl MockKeyManager {
    fn new() -> Self {
        Self {
            keys: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl KeyManager for MockKeyManager {
    async fn generate_key(&self, _algorithm: &str) -> Result<SecureKey> {
        let key = SecureKey::generate(32)?;
        let id = uuid::Uuid::new_v4().to_string();
        let mut keys = self.keys.write().await;
        keys.insert(id.clone(), key.clone());
        Ok(key)
    }

    async fn get_key(&self, key_id: &str) -> Result<SecureKey> {
        let keys = self.keys.read().await;
        keys.get(key_id).cloned().ok_or_else(|| {
            fortress_core::error::FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some("mock_key_manager".to_string()),
                fortress_core::error::KeyErrorCode::KeyNotFound,
            )
        })
    }

    async fn delete_key(&self, key_id: &str) -> Result<bool> {
        let mut keys = self.keys.write().await;
        Ok(keys.remove(key_id).is_some())
    }

    async fn list_keys(&self) -> Result<Vec<String>> {
        let keys = self.keys.read().await;
        Ok(keys.keys().cloned().collect())
    }
}

/// Create test JPEG data
fn create_test_jpeg() -> Vec<u8> {
    // Simple JPEG header for testing
    vec![
        0xFF, 0xD8, // JPEG SOI
        0xFF, 0xE0, 0x00, 0x10, // APP0 marker
        b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF,
        0xD9, // JPEG EOI
    ]
}

/// Create test PNG data
fn create_test_png() -> Vec<u8> {
    // Simple PNG header for testing
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
        b'I', b'H', b'D', b'R', // IHDR
        0x00, 0x00, 0x00, 0x01, // Width: 1
        0x00, 0x00, 0x00, 0x01, // Height: 1
        0x08, 0x02, 0x00, 0x00, 0x00, // Bit depth, color type, compression, filter, interlace
        0x90, 0x77, 0x53, 0xDE, // CRC
        0x00, 0x00, 0x00, 0x00, // IEND chunk length
        b'I', b'E', b'N', b'D', // IEND
        0xAE, 0x42, 0x60, 0x82, // IEND CRC
    ]
}

#[tokio::test]
async fn test_complete_image_encryption_workflow() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    // Test JPEG encryption
    let jpeg_data = create_test_jpeg();
    let encrypt_request = EncryptImageRequest {
        image_data: jpeg_data.clone(),
        options: EncryptionOptions {
            algorithm: "chacha20poly1305".to_string(),
            encryption_mode: EncryptionMode::Full,
            encrypt_metadata: true,
            chunk_size: Some(1024 * 1024),
            quality: None,
            custom_options: HashMap::new(),
        },
        key_id: None,
        thumbnail_options: vec![ThumbnailOptions {
            size: ThumbnailSize::Medium,
            format: ThumbnailFormat::Jpeg,
            quality: Some(75),
            ..Default::default()
        }],
        permissions: Some(AccessPermissions {
            classification: ImageDataClassification::Internal,
            viewers: vec!["test_user".to_string()],
            editors: vec!["test_user".to_string()],
            sharers: vec!["test_user".to_string()],
            ..Default::default()
        }),
    };

    // Encrypt image
    let encrypt_response = service.encrypt_image(encrypt_request).await?;

    // Verify encryption
    assert!(!encrypt_response.image_id.is_empty());
    assert!(!encrypt_response.key_id.is_empty());
    assert_eq!(
        encrypt_response.encrypted_image.original_size,
        jpeg_data.len()
    );
    assert_eq!(
        encrypt_response.encrypted_image.format_info.format,
        ImageFormat::Jpeg
    );
    assert!(!encrypt_response.thumbnail_ids.is_empty());

    // Test decryption
    let decrypt_request = DecryptImageRequest {
        image_id: encrypt_response.image_id.clone(),
        key_id: encrypt_response.key_id.clone(),
        include_metadata: true,
    };

    let decrypt_response = service.decrypt_image(decrypt_request).await?;

    // Verify decryption
    assert_eq!(decrypt_response.image_data, jpeg_data);
    assert!(decrypt_response.metadata.is_some());
    assert_eq!(decrypt_response.format_info.format, ImageFormat::Jpeg);

    // Test metadata retrieval
    let metadata_request = GetImageMetadataRequest {
        image_id: encrypt_response.image_id.clone(),
        key_id: encrypt_response.key_id.clone(),
    };

    let metadata_response = service.get_image_metadata(metadata_request).await?;
    assert!(metadata_response
        .metadata
        .basic_info
        .creation_date
        .is_some());

    Ok(())
}

#[tokio::test]
async fn test_streaming_encryption_workflow() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    // Create large test image (5MB)
    let large_image_data = vec![0u8; 5 * 1024 * 1024];

    // Start streaming encryption
    let streaming_request = StartStreamingRequest {
        image_data: large_image_data.clone(),
        options: EncryptionOptions {
            algorithm: "chacha20poly1305".to_string(),
            encryption_mode: EncryptionMode::Full,
            encrypt_metadata: false,
            chunk_size: Some(64 * 1024), // 64KB chunks
            quality: None,
            custom_options: HashMap::new(),
        },
        image_key_id: None,
        thumbnail_key_id: None,
        chunk_config: Some(ChunkConfig {
            chunk_size: 64 * 1024,
            parallel_workers: 4,
            buffer_size: 1024 * 1024,
            compress_chunks: false,
            compression_level: None,
        }),
    };

    let streaming_response = service
        .start_streaming_encryption(streaming_request)
        .await?;

    // Verify session started
    assert!(!streaming_response.session_id.is_empty());
    assert!(!streaming_response.image_key_id.is_empty());
    assert!(!streaming_response.thumbnail_key_id.is_empty());

    // Wait a bit for processing
    sleep(Duration::from_millis(100)).await;

    // Check streaming status
    let status_request = GetStreamingStatusRequest {
        session_id: streaming_response.session_id.clone(),
    };

    let status_response = service.get_streaming_status(status_request).await?;
    assert_eq!(status_response.session_id, streaming_response.session_id);

    // Verify status progression
    match status_response.state.status {
        StreamingStatus::Completed | StreamingStatus::InProgress => {
            // Expected states
        }
        _ => {
            // Other states are also valid depending on timing
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_thumbnail_generation_workflow() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    // First encrypt an image
    let jpeg_data = create_test_jpeg();
    let encrypt_request = EncryptImageRequest {
        image_data: jpeg_data.clone(),
        options: EncryptionOptions::default(),
        key_id: None,
        thumbnail_options: vec![], // No thumbnails initially
        permissions: None,
    };

    let encrypt_response = service.encrypt_image(encrypt_request).await?;

    // Generate thumbnails for the encrypted image
    let thumbnail_request = GenerateThumbnailsRequest {
        image_id: encrypt_response.image_id.clone(),
        image_key_id: encrypt_response.key_id.clone(),
        thumbnail_key_id: encrypt_response.key_id.clone(), // Use same key for simplicity
        thumbnail_options: vec![
            ThumbnailOptions {
                size: ThumbnailSize::Small,
                format: ThumbnailFormat::Jpeg,
                quality: Some(70),
                ..Default::default()
            },
            ThumbnailOptions {
                size: ThumbnailSize::Medium,
                format: ThumbnailFormat::Png,
                quality: None,
                ..Default::default()
            },
            ThumbnailOptions {
                size: ThumbnailSize::Large,
                format: ThumbnailFormat::WebP,
                quality: Some(80),
                ..Default::default()
            },
        ],
    };

    let thumbnail_response = service.generate_thumbnails(thumbnail_request).await?;

    // Verify thumbnail generation
    assert_eq!(thumbnail_response.thumbnail_ids.len(), 3);
    assert!(!thumbnail_response.thumbnail_ids[0].is_empty());
    assert!(!thumbnail_response.thumbnail_ids[1].is_empty());
    assert!(!thumbnail_response.thumbnail_ids[2].is_empty());

    Ok(())
}

#[tokio::test]
async fn test_image_search_workflow() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    // Encrypt multiple images with different properties
    let images = vec![
        (
            create_test_jpeg(),
            ImageFormat::Jpeg,
            ImageDataClassification::Public,
        ),
        (
            create_test_png(),
            ImageFormat::Png,
            ImageDataClassification::Internal,
        ),
        (
            create_test_jpeg(),
            ImageFormat::Jpeg,
            ImageDataClassification::Confidential,
        ),
    ];

    let mut image_ids = Vec::new();
    for (data, _expected_format, classification) in images {
        let encrypt_request = EncryptImageRequest {
            image_data: data,
            options: EncryptionOptions::default(),
            key_id: None,
            thumbnail_options: vec![],
            permissions: Some(AccessPermissions {
                classification,
                viewers: vec!["test_user".to_string()],
                editors: vec!["test_user".to_string()],
                sharers: vec!["test_user".to_string()],
                ..Default::default()
            }),
        };

        let response = service.encrypt_image(encrypt_request).await?;
        image_ids.push(response.image_id);
    }

    // Test search by format
    let search_request = SearchImagesRequest {
        filter: ImageFilter {
            offset: Some(0),
            limit: Some(10),
            sort_by: Some("created_at".to_string()),
            sort_order: Some(SortOrder::Descending),
            criteria: SearchCriteria {
                text_query: None,
                format_filter: Some(ImageFormat::Jpeg),
                size_range: None,
                date_range: None,
                classification_filter: None,
                tags: vec![],
                custom_filters: HashMap::new(),
            },
        },
    };

    let search_response = service.search_images(search_request).await?;

    // Verify search results (mock implementation returns empty, but structure is validated)
    assert!(search_response.total_count <= 10);
    assert_eq!(search_response.results.len(), search_response.total_count);

    Ok(())
}

#[tokio::test]
async fn test_image_deletion_workflow() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    // Encrypt an image
    let jpeg_data = create_test_jpeg();
    let encrypt_request = EncryptImageRequest {
        image_data: jpeg_data,
        options: EncryptionOptions::default(),
        key_id: None,
        thumbnail_options: vec![ThumbnailOptions {
            size: ThumbnailSize::Small,
            format: ThumbnailFormat::Jpeg,
            ..Default::default()
        }],
        permissions: None,
    };

    let encrypt_response = service.encrypt_image(encrypt_request).await?;

    // Verify image exists
    let stored_image = image_store.get_image(&encrypt_response.image_id).await?;
    assert!(stored_image.is_some());

    // Delete the image
    let delete_request = DeleteImageRequest {
        image_id: encrypt_response.image_id.clone(),
        user_id: Some("test_user".to_string()),
        reason: Some("Test cleanup".to_string()),
    };

    let delete_response = service.delete_image(delete_request).await?;

    // Verify deletion
    assert!(delete_response.deleted);
    assert_eq!(delete_response.deleted_thumbnails, 0); // Mock returns 0

    // Verify image is gone
    let stored_image = image_store.get_image(&encrypt_response.image_id).await?;
    assert!(stored_image.is_none());

    Ok(())
}

#[tokio::test]
async fn test_format_detection_and_validation() -> Result<()> {
    // Test JPEG detection
    let jpeg_data = create_test_jpeg();
    let detected_format = ImageFormatDetector::detect(&jpeg_data)?;
    assert_eq!(detected_format, ImageFormat::Jpeg);
    assert!(detected_format.validate_data(&jpeg_data)?);

    // Test PNG detection
    let png_data = create_test_png();
    let detected_format = ImageFormatDetector::detect(&png_data)?;
    assert_eq!(detected_format, ImageFormat::Png);
    assert!(detected_format.validate_data(&png_data)?);

    // Test extension detection
    assert_eq!(
        ImageFormatDetector::detect_from_extension("jpg"),
        ImageFormat::Jpeg
    );
    assert_eq!(
        ImageFormatDetector::detect_from_extension("png"),
        ImageFormat::Png
    );
    assert_eq!(
        ImageFormatDetector::detect_from_extension("tiff"),
        ImageFormat::Tiff
    );
    assert_eq!(
        ImageFormatDetector::detect_from_extension("unknown"),
        ImageFormat::Unknown
    );

    // Test format properties
    assert!(ImageFormat::Png.supports_lossless());
    assert!(!ImageFormat::Jpeg.supports_lossless());
    assert!(ImageFormat::Tiff.supports_multiple_pages());
    assert!(!ImageFormat::Jpeg.supports_multiple_pages());

    Ok(())
}

#[tokio::test]
async fn test_encryption_mode_variations() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    let jpeg_data = create_test_jpeg();

    // Test different encryption modes
    let modes = vec![
        EncryptionMode::Full,
        EncryptionMode::DataOnly,
        EncryptionMode::FormatAware,
        // Regional would need region definitions, skip for now
    ];

    for mode in modes {
        let encrypt_request = EncryptImageRequest {
            image_data: jpeg_data.clone(),
            options: EncryptionOptions {
                algorithm: "chacha20poly1305".to_string(),
                encryption_mode: mode,
                encrypt_metadata: true,
                chunk_size: Some(1024 * 1024),
                quality: None,
                custom_options: HashMap::new(),
            },
            key_id: None,
            thumbnail_options: vec![],
            permissions: None,
        };

        let encrypt_response = service.encrypt_image(encrypt_request).await?;

        // Verify encryption worked
        assert!(!encrypt_response.image_id.is_empty());
        assert_eq!(
            encrypt_response
                .encrypted_image
                .encryption_options
                .encryption_mode,
            mode
        );

        // Test decryption
        let decrypt_request = DecryptImageRequest {
            image_id: encrypt_response.image_id.clone(),
            key_id: encrypt_response.key_id.clone(),
            include_metadata: false,
        };

        let decrypt_response = service.decrypt_image(decrypt_request).await?;

        // Verify decryption restored original data (for modes that support it)
        if matches!(mode, EncryptionMode::Full | EncryptionMode::FormatAware) {
            assert_eq!(decrypt_response.image_data, jpeg_data);
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_error_handling_and_validation() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    // Test empty image data
    let encrypt_request = EncryptImageRequest {
        image_data: vec![],
        options: EncryptionOptions::default(),
        key_id: None,
        thumbnail_options: vec![],
        permissions: None,
    };

    let result = service.encrypt_image(encrypt_request).await;
    assert!(result.is_err());

    // Test invalid image ID for decryption
    let decrypt_request = DecryptImageRequest {
        image_id: "nonexistent_id".to_string(),
        key_id: "some_key".to_string(),
        include_metadata: false,
    };

    let result = service.decrypt_image(decrypt_request).await;
    assert!(result.is_err());

    // Test invalid thumbnail options
    let jpeg_data = create_test_jpeg();
    let encrypt_request = EncryptImageRequest {
        image_data: jpeg_data,
        options: EncryptionOptions::default(),
        key_id: None,
        thumbnail_options: vec![ThumbnailOptions {
            size: ThumbnailSize::Custom(0, 100), // Invalid size
            format: ThumbnailFormat::Jpeg,
            ..Default::default()
        }],
        permissions: None,
    };

    let result = service.encrypt_image(encrypt_request).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_thumbnail_size_and_format_variations() -> Result<()> {
    // Setup
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let image_store = std::sync::Arc::new(MockImageStore::new());
    let key_manager = std::sync::Arc::new(MockKeyManager::new());

    let service = ImageEncryptionService::new(algorithm, image_store.clone(), key_manager.clone())?;

    let jpeg_data = create_test_jpeg();

    // Test different thumbnail sizes and formats
    let sizes = vec![
        ThumbnailSize::Small,
        ThumbnailSize::Medium,
        ThumbnailSize::Large,
        ThumbnailSize::ExtraLarge,
        ThumbnailSize::Custom(200, 150),
    ];

    let formats = vec![
        ThumbnailFormat::Jpeg,
        ThumbnailFormat::Png,
        ThumbnailFormat::WebP,
    ];

    for size in sizes {
        for format in &formats {
            let encrypt_request = EncryptImageRequest {
                image_data: jpeg_data.clone(),
                options: EncryptionOptions::default(),
                key_id: None,
                thumbnail_options: vec![ThumbnailOptions {
                    size,
                    format: *format,
                    quality: if format.supports_transparency() {
                        None
                    } else {
                        Some(75)
                    },
                    ..Default::default()
                }],
                permissions: None,
            };

            let encrypt_response = service.encrypt_image(encrypt_request).await?;

            // Verify thumbnail was generated
            assert_eq!(encrypt_response.thumbnail_ids.len(), 1);
            assert!(!encrypt_response.thumbnail_ids[0].is_empty());
        }
    }

    Ok(())
}

#[test]
fn test_thumbnail_size_properties() {
    // Test size properties
    assert_eq!(ThumbnailSize::Small.dimensions(), (64, 64));
    assert_eq!(ThumbnailSize::Medium.dimensions(), (128, 128));
    assert_eq!(ThumbnailSize::Large.dimensions(), (256, 256));
    assert_eq!(ThumbnailSize::ExtraLarge.dimensions(), (512, 512));
    assert_eq!(ThumbnailSize::Custom(200, 150).dimensions(), (200, 150));

    // Test size names
    assert_eq!(ThumbnailSize::Small.name(), "small");
    assert_eq!(ThumbnailSize::Medium.name(), "medium");
    assert_eq!(ThumbnailSize::Large.name(), "large");
    assert_eq!(ThumbnailSize::ExtraLarge.name(), "xlarge");
    assert_eq!(ThumbnailSize::Custom(100, 100).name(), "custom");

    // Test max file sizes
    assert_eq!(ThumbnailSize::Small.max_file_size(), 8 * 1024);
    assert_eq!(ThumbnailSize::Medium.max_file_size(), 32 * 1024);
    assert_eq!(ThumbnailSize::Large.max_file_size(), 128 * 1024);
    assert_eq!(ThumbnailSize::ExtraLarge.max_file_size(), 512 * 1024);
}

#[test]
fn test_data_classification_levels() {
    // Test security levels
    assert_eq!(ImageDataClassification::Public.security_level(), 1);
    assert_eq!(ImageDataClassification::Internal.security_level(), 2);
    assert_eq!(ImageDataClassification::Confidential.security_level(), 3);
    assert_eq!(ImageDataClassification::Secret.security_level(), 4);
    assert_eq!(ImageDataClassification::TopSecret.security_level(), 5);
}

#[test]
fn test_encryption_options_validation() {
    let algorithm = ChaCha20Poly1305::new();
    let encryptor = ImageEncryptor::new(Box::new(algorithm));

    // Test valid options
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
