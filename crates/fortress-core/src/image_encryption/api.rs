//! API endpoints and service layer for Fortress image encryption
//!
//! This module provides high-level API endpoints and service functions for:
//! - Image encryption and decryption operations
//! - Thumbnail generation and management
//! - Streaming encryption for large images
//! - Metadata search and retrieval
//! - Image management and organization

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptionAlgorithm, SecureKey};
use crate::image_encryption::{
    ImageEncryptor, encryptor::ImageEncryptorFactory, EncryptedImage, EncryptionOptions,
    ThumbnailGenerator, thumbnails::ThumbnailOptions, EncryptedThumbnail,
    StreamingImageEncryptor, ChunkConfig, streaming::{StreamingState, StreamingResult, StreamingImageDecryptor}, AccessPermissions, ImageFilter, ImageSearchResult, ImageInfo,
    ImageMetadata, ImageFormatInfo,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};

/// Image encryption service
pub struct ImageEncryptionService {
    encryptor: Arc<ImageEncryptor>,
    thumbnail_generator: Arc<ThumbnailGenerator>,
    streaming_encryptor: Arc<StreamingImageEncryptor>,
    streaming_decryptor: Arc<StreamingImageDecryptor>,
    image_store: Arc<dyn ImageStore>,
    key_manager: Arc<dyn KeyManager>,
}

impl ImageEncryptionService {
    /// Create a new image encryption service
    pub fn new(
        encryption_algorithm: Box<dyn EncryptionAlgorithm>,
        image_store: Arc<dyn ImageStore>,
        key_manager: Arc<dyn KeyManager>,
    ) -> Result<Self> {
        // We need to create multiple instances, so we'll use the factory pattern
        let algorithm_name = encryption_algorithm.name();
        let encryptor = Arc::new(ImageEncryptor::new(encryption_algorithm));
        
        // Create additional instances using the factory
        let thumbnail_generator = Arc::new(ThumbnailGenerator::new(
            ImageEncryptorFactory::create_encryptor(algorithm_name)?.encryption_algorithm().clone()
        ));
        let streaming_encryptor = Arc::new(StreamingImageEncryptor::new(
            ImageEncryptorFactory::create_encryptor(algorithm_name)?.encryption_algorithm().clone(),
            ChunkConfig::default(),
        ));
        let streaming_decryptor = Arc::new(StreamingImageDecryptor::new(
            ImageEncryptorFactory::create_encryptor(algorithm_name)?.encryption_algorithm().clone()
        ));

        Ok(Self {
            encryptor,
            thumbnail_generator,
            streaming_encryptor,
            streaming_decryptor,
            image_store,
            key_manager,
        })
    }

    /// Encrypt an image
    pub async fn encrypt_image(
        &self,
        request: EncryptImageRequest,
    ) -> Result<EncryptImageResponse> {
        // Validate request
        self.validate_encrypt_request(&request)?;

        // Generate or retrieve encryption key
        let key = if let Some(key_id) = &request.key_id {
            self.key_manager.get_key(key_id).await?
        } else {
            self.key_manager.generate_key(&request.options.algorithm).await?
        };

        // Encrypt the image
        let encrypted_image = self.encryptor
            .encrypt(request.image_data, request.options.clone(), &key)
            .await?;

        // Generate thumbnails if requested
        let thumbnails = if !request.thumbnail_options.is_empty() {
            self.generate_thumbnails_for_image(&encrypted_image, &key, &request.thumbnail_options).await?
        } else {
            Vec::new()
        };

        // Store encrypted image
        let image_id = self.image_store.store_image(&encrypted_image).await?;

        // Store thumbnails
        let thumbnail_ids = self.store_thumbnails(&image_id, thumbnails).await?;

        // Create response
        let response = EncryptImageResponse {
            image_id,
            key_id: "generated_key".to_string(),
            encrypted_image: encrypted_image.clone(),
            thumbnail_ids,
            encryption_stats: self.encryptor.get_encryption_stats(&encrypted_image),
            processed_at: Utc::now(),
        };

        Ok(response)
    }

    /// Decrypt an image
    pub async fn decrypt_image(
        &self,
        request: DecryptImageRequest,
    ) -> Result<DecryptImageResponse> {
        // Validate request
        self.validate_decrypt_request(&request)?;

        // Retrieve encrypted image
        let encrypted_image = self.image_store.get_image(&request.image_id).await?
            .ok_or_else(|| FortressError::encryption(
                format!("Image not found: {}", request.image_id),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Retrieve decryption key
        let key = self.key_manager.get_key(&request.key_id).await?;

        // Decrypt the image
        let decrypted_data = self.encryptor.decrypt(&encrypted_image, &key).await?;

        // Decrypt metadata if requested
        let metadata = if request.include_metadata {
            self.encryptor.decrypt_metadata(&encrypted_image, &key).await?
        } else {
            None
        };

        Ok(DecryptImageResponse {
            image_data: decrypted_data,
            metadata,
            format_info: encrypted_image.format_info,
            decrypted_at: Utc::now(),
        })
    }

    /// Generate thumbnails for an encrypted image
    pub async fn generate_thumbnails(
        &self,
        request: GenerateThumbnailsRequest,
    ) -> Result<GenerateThumbnailsResponse> {
        // Retrieve encrypted image
        let encrypted_image = self.image_store.get_image(&request.image_id).await?
            .ok_or_else(|| FortressError::encryption(
                format!("Image not found: {}", request.image_id),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Retrieve keys
        let _image_key = self.key_manager.get_key(&request.image_key_id).await?;
        let thumbnail_key = self.key_manager.get_key(&request.thumbnail_key_id).await?;

        // Generate thumbnails
        let thumbnails = self.generate_thumbnails_for_image(
            &encrypted_image,
            &thumbnail_key,
            &request.thumbnail_options,
        ).await?;

        // Store thumbnails
        let thumbnail_ids = self.store_thumbnails(&request.image_id, thumbnails).await?;

        Ok(GenerateThumbnailsResponse {
            thumbnail_ids,
            generated_at: Utc::now(),
        })
    }

    /// Start streaming encryption
    pub async fn start_streaming_encryption(
        &self,
        request: StartStreamingRequest,
    ) -> Result<StartStreamingResponse> {
        // Validate request
        self.validate_streaming_request(&request)?;

        // Start streaming session
        let session_id = self.streaming_encryptor
            .start_encryption_session(&request.image_data, request.options.clone())
            .await?;

        // Generate or retrieve keys
        let image_key = if let Some(key_id) = &request.image_key_id {
            self.key_manager.get_key(key_id).await?
        } else {
            self.key_manager.generate_key(&request.options.algorithm).await?
        };

        let thumbnail_key = if let Some(key_id) = &request.thumbnail_key_id {
            self.key_manager.get_key(key_id).await?
        } else {
            self.key_manager.generate_key(&request.options.algorithm).await?
        };

        // Start encryption in background
        let encryptor = Arc::clone(&self.streaming_encryptor);
        let image_store = Arc::clone(&self.image_store);
        let session_id_clone = session_id.clone();
        let image_key_clone = image_key.clone();
        let _thumbnail_key_clone = thumbnail_key.clone();
        let options_clone = request.options.clone();

        tokio::spawn(async move {
            let result = encryptor.encrypt_streaming(
                &session_id_clone,
                &request.image_data,
                options_clone,
                &image_key_clone,
            ).await;

            match result {
                Ok(streaming_result) => {
                    // Store streaming result
                    if let Err(e) = image_store.store_streaming_result(&session_id_clone, &streaming_result).await {
                        tracing::error!("Failed to store streaming result: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Streaming encryption failed: {}", e);
                }
            }
        });

        Ok(StartStreamingResponse {
            session_id,
            image_key_id: "generated_key".to_string(),
            thumbnail_key_id: "generated_key".to_string(),
            started_at: Utc::now(),
        })
    }

    /// Get streaming status
    pub async fn get_streaming_status(
        &self,
        request: GetStreamingStatusRequest,
    ) -> Result<GetStreamingStatusResponse> {
        let status = self.streaming_encryptor.get_session_status(&request.session_id).await?;
        
        match status {
            Some(state) => Ok(GetStreamingStatusResponse {
                session_id: request.session_id,
                state,
                queried_at: Utc::now(),
            }),
            None => Err(FortressError::encryption(
                format!("Streaming session not found: {}", request.session_id),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            )),
        }
    }

    /// Search encrypted images
    pub async fn search_images(
        &self,
        request: SearchImagesRequest,
    ) -> Result<SearchImagesResponse> {
        // Validate search criteria
        self.validate_search_request(&request)?;

        // Search images
        let results = self.image_store.search_images(&request.filter).await?;

        // Convert to search results
        let search_results: Vec<_> = results.into_iter()
            .map(|image_info| ImageSearchResult {
                id: image_info.id.clone(),
                info: image_info.clone(),
                relevance_score: None, // Would need search engine for relevance
                highlights: Vec::new(),
            })
            .collect();

        Ok(SearchImagesResponse {
            results: search_results.clone(),
            total_count: search_results.len(),
            searched_at: Utc::now(),
        })
    }

    /// Get image metadata
    pub async fn get_image_metadata(
        &self,
        request: GetImageMetadataRequest,
    ) -> Result<GetImageMetadataResponse> {
        // Retrieve encrypted image
        let encrypted_image = self.image_store.get_image(&request.image_id).await?
            .ok_or_else(|| FortressError::encryption(
                format!("Image not found: {}", request.image_id),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ))?;

        // Retrieve key
        let key = self.key_manager.get_key(&request.key_id).await?;

        // Decrypt metadata
        let metadata = self.encryptor.decrypt_metadata(&encrypted_image, &key).await?
            .ok_or_else(|| FortressError::encryption(
                "No metadata available for this image".to_string(),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ))?;

        Ok(GetImageMetadataResponse {
            metadata,
            retrieved_at: Utc::now(),
        })
    }

    /// Delete an encrypted image
    pub async fn delete_image(
        &self,
        request: DeleteImageRequest,
    ) -> Result<DeleteImageResponse> {
        // Validate permissions
        self.validate_delete_permissions(&request)?;

        // Delete image
        let deleted = self.image_store.delete_image(&request.image_id).await?;

        if !deleted {
            return Err(FortressError::encryption(
                format!("Image not found: {}", request.image_id),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ));
        }

        // Delete associated thumbnails
        let deleted_thumbnails = self.image_store.delete_thumbnails(&request.image_id).await?;

        Ok(DeleteImageResponse {
            deleted: true,
            deleted_thumbnails,
            deleted_at: Utc::now(),
        })
    }

    // Private helper methods

    fn validate_encrypt_request(&self, request: &EncryptImageRequest) -> Result<()> {
        if request.image_data.is_empty() {
            return Err(FortressError::encryption(
                "Image data cannot be empty".to_string(),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ));
        }

        // Validate encryption options
        self.encryptor.validate_options(&request.options)?;

        // Validate thumbnail options
        for options in &request.thumbnail_options {
            self.thumbnail_generator.validate_options(options)?;
        }

        Ok(())
    }

    fn validate_decrypt_request(&self, request: &DecryptImageRequest) -> Result<()> {
        if request.image_id.is_empty() {
            return Err(FortressError::encryption(
                "Image ID cannot be empty".to_string(),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ));
        }

        if request.key_id.is_empty() {
            return Err(FortressError::encryption(
                "Key ID cannot be empty".to_string(),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ));
        }

        Ok(())
    }

    fn validate_streaming_request(&self, request: &StartStreamingRequest) -> Result<()> {
        if request.image_data.is_empty() {
            return Err(FortressError::encryption(
                "Image data cannot be empty".to_string(),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ));
        }

        self.encryptor.validate_options(&request.options)?;
        Ok(())
    }

    fn validate_search_request(&self, request: &SearchImagesRequest) -> Result<()> {
        // Validate filter criteria
        if let Some(offset) = request.filter.offset {
            if offset > 10000 {
                return Err(FortressError::encryption(
                    "Offset too large (max 10000)".to_string(),
                    "image_service".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
        }

        if let Some(limit) = request.filter.limit {
            if limit == 0 || limit > 1000 {
                return Err(FortressError::encryption(
                    "Limit must be between 1 and 1000".to_string(),
                    "image_service".to_string(),
                    crate::error::EncryptionErrorCode::EncryptionFailed,
                ));
            }
        }

        Ok(())
    }

    fn validate_delete_permissions(&self, request: &DeleteImageRequest) -> Result<()> {
        // In a real implementation, this would check user permissions
        // For now, just validate the request structure
        if request.image_id.is_empty() {
            return Err(FortressError::encryption(
                "Image ID cannot be empty".to_string(),
                "image_service".to_string(),
                crate::error::EncryptionErrorCode::EncryptionFailed,
            ));
        }

        Ok(())
    }

    async fn generate_thumbnails_for_image(
        &self,
        encrypted_image: &EncryptedImage,
        thumbnail_key: &SecureKey,
        thumbnail_options: &[ThumbnailOptions],
    ) -> Result<Vec<EncryptedThumbnail>> {
        let mut thumbnails = Vec::new();

        // Get image key for decryption
        let image_key = self.key_manager.generate_key(&encrypted_image.encryption_options.algorithm).await?;

        for options in thumbnail_options {
            let thumbnail = self.thumbnail_generator
                .generate_from_encrypted(encrypted_image, thumbnail_key, &image_key, options.clone())
                .await?;
            thumbnails.push(thumbnail);
        }

        Ok(thumbnails)
    }

    async fn store_thumbnails(
        &self,
        image_id: &str,
        thumbnails: Vec<EncryptedThumbnail>,
    ) -> Result<Vec<String>> {
        let mut thumbnail_ids = Vec::new();

        for thumbnail in thumbnails {
            let thumbnail_id = self.image_store.store_thumbnail(image_id, &thumbnail).await?;
            thumbnail_ids.push(thumbnail_id);
        }

        Ok(thumbnail_ids)
    }
}

// Trait definitions for dependencies

/// Image storage backend trait
#[async_trait::async_trait]
pub trait ImageStore: Send + Sync {
    /// Store an encrypted image
    async fn store_image(&self, image: &EncryptedImage) -> Result<String>;
    
    /// Retrieve an encrypted image
    async fn get_image(&self, image_id: &str) -> Result<Option<EncryptedImage>>;
    
    /// Delete an encrypted image
    async fn delete_image(&self, image_id: &str) -> Result<bool>;
    
    /// Store a thumbnail
    async fn store_thumbnail(&self, image_id: &str, thumbnail: &EncryptedThumbnail) -> Result<String>;
    
    /// Retrieve a thumbnail
    async fn get_thumbnail(&self, thumbnail_id: &str) -> Result<Option<EncryptedThumbnail>>;
    
    /// Delete thumbnails for an image
    async fn delete_thumbnails(&self, image_id: &str) -> Result<usize>;
    
    /// Search images
    async fn search_images(&self, filter: &ImageFilter) -> Result<Vec<ImageInfo>>;
    
    /// Store streaming result
    async fn store_streaming_result(&self, session_id: &str, result: &StreamingResult) -> Result<()>;
    
    /// Get streaming result
    async fn get_streaming_result(&self, session_id: &str) -> Result<Option<StreamingResult>>;
}

/// Key management trait
#[async_trait::async_trait]
pub trait KeyManager: Send + Sync {
    /// Generate a new key
    async fn generate_key(&self, algorithm: &str) -> Result<SecureKey>;
    
    /// Get an existing key
    async fn get_key(&self, key_id: &str) -> Result<SecureKey>;
    
    /// Delete a key
    async fn delete_key(&self, key_id: &str) -> Result<bool>;
    
    /// List keys
    async fn list_keys(&self) -> Result<Vec<String>>;
}

// Request/Response types

/// Request to encrypt an image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptImageRequest {
    /// Image data to encrypt
    pub image_data: Vec<u8>,
    /// Encryption options
    pub options: EncryptionOptions,
    /// Optional key ID to use
    pub key_id: Option<String>,
    /// Thumbnail generation options
    pub thumbnail_options: Vec<ThumbnailOptions>,
    /// Access permissions
    pub permissions: Option<AccessPermissions>,
}

/// Response from image encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptImageResponse {
    /// ID of the encrypted image
    pub image_id: String,
    /// ID of the encryption key
    pub key_id: String,
    /// Encrypted image data
    pub encrypted_image: EncryptedImage,
    /// IDs of generated thumbnails
    pub thumbnail_ids: Vec<String>,
    /// Encryption statistics
    pub encryption_stats: crate::image_encryption::EncryptionStats,
    /// When the image was processed
    pub processed_at: DateTime<Utc>,
}

/// Request to decrypt an image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptImageRequest {
    /// ID of the image to decrypt
    pub image_id: String,
    /// ID of the decryption key
    pub key_id: String,
    /// Whether to include metadata
    pub include_metadata: bool,
}

/// Response from image decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptImageResponse {
    /// Decrypted image data
    pub image_data: Vec<u8>,
    /// Decrypted metadata (if requested)
    pub metadata: Option<ImageMetadata>,
    /// Format information
    pub format_info: ImageFormatInfo,
    /// When the image was decrypted
    pub decrypted_at: DateTime<Utc>,
}

/// Request to generate thumbnails
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateThumbnailsRequest {
    /// ID of the source image
    pub image_id: String,
    /// ID of the image decryption key
    pub image_key_id: String,
    /// ID of the thumbnail encryption key
    pub thumbnail_key_id: String,
    /// Thumbnail generation options
    pub thumbnail_options: Vec<ThumbnailOptions>,
}

/// Response from thumbnail generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateThumbnailsResponse {
    /// IDs of generated thumbnails
    pub thumbnail_ids: Vec<String>,
    /// When thumbnails were generated
    pub generated_at: DateTime<Utc>,
}

/// Request to start streaming encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartStreamingRequest {
    /// Image data to encrypt
    pub image_data: Vec<u8>,
    /// Encryption options
    pub options: EncryptionOptions,
    /// Optional image key ID
    pub image_key_id: Option<String>,
    /// Optional thumbnail key ID
    pub thumbnail_key_id: Option<String>,
    /// Chunk configuration
    pub chunk_config: Option<ChunkConfig>,
}

/// Response from starting streaming encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartStreamingResponse {
    /// Streaming session ID
    pub session_id: String,
    /// ID of the image encryption key
    pub image_key_id: String,
    /// ID of the thumbnail encryption key
    pub thumbnail_key_id: String,
    /// When streaming started
    pub started_at: DateTime<Utc>,
}

/// Request to get streaming status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStreamingStatusRequest {
    /// Streaming session ID
    pub session_id: String,
}

/// Response with streaming status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStreamingStatusResponse {
    /// Streaming session ID
    pub session_id: String,
    /// Current streaming state
    pub state: StreamingState,
    /// When status was queried
    pub queried_at: DateTime<Utc>,
}

/// Request to search images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchImagesRequest {
    /// Search filter criteria
    pub filter: ImageFilter,
}

/// Response from image search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchImagesResponse {
    /// Search results
    pub results: Vec<ImageSearchResult>,
    /// Total number of results
    pub total_count: usize,
    /// When search was performed
    pub searched_at: DateTime<Utc>,
}

/// Request to get image metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetImageMetadataRequest {
    /// ID of the image
    pub image_id: String,
    /// ID of the decryption key
    pub key_id: String,
}

/// Response with image metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetImageMetadataResponse {
    /// Image metadata
    pub metadata: ImageMetadata,
    /// When metadata was retrieved
    pub retrieved_at: DateTime<Utc>,
}

/// Request to delete an image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteImageRequest {
    /// ID of the image to delete
    pub image_id: String,
    /// User requesting deletion (for permissions)
    pub user_id: Option<String>,
    /// Reason for deletion
    pub reason: Option<String>,
}

/// Response from image deletion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteImageResponse {
    /// Whether the image was deleted
    pub deleted: bool,
    /// Number of thumbnails deleted
    pub deleted_thumbnails: usize,
    /// When image was deleted
    pub deleted_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::ChaCha20Poly1305;

    // Mock implementations for testing
    struct MockImageStore;
    struct MockKeyManager;

    #[async_trait::async_trait]
    impl ImageStore for MockImageStore {
        async fn store_image(&self, _image: &EncryptedImage) -> Result<String> {
            Ok(Uuid::new_v4().to_string())
        }

        async fn get_image(&self, _image_id: &str) -> Result<Option<EncryptedImage>> {
            Ok(None)
        }

        async fn delete_image(&self, _image_id: &str) -> Result<bool> {
            Ok(true)
        }

        async fn store_thumbnail(&self, _image_id: &str, _thumbnail: &EncryptedThumbnail) -> Result<String> {
            Ok(Uuid::new_v4().to_string())
        }

        async fn get_thumbnail(&self, _thumbnail_id: &str) -> Result<Option<EncryptedThumbnail>> {
            Ok(None)
        }

        async fn delete_thumbnails(&self, _image_id: &str) -> Result<usize> {
            Ok(0)
        }

        async fn search_images(&self, _filter: &ImageFilter) -> Result<Vec<ImageInfo>> {
            Ok(Vec::new())
        }

        async fn store_streaming_result(&self, _session_id: &str, _result: &StreamingResult) -> Result<()> {
            Ok(())
        }

        async fn get_streaming_result(&self, _session_id: &str) -> Result<Option<StreamingResult>> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl KeyManager for MockKeyManager {
        async fn generate_key(&self, _algorithm: &str) -> Result<SecureKey> {
            Ok(SecureKey::generate(32))
        }

        async fn get_key(&self, _key_id: &str) -> Result<SecureKey> {
            Ok(SecureKey::generate(32))
        }

        async fn delete_key(&self, _key_id: &str) -> Result<bool> {
            Ok(true)
        }

        async fn list_keys(&self) -> Result<Vec<String>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_service_creation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let image_store = Arc::new(MockImageStore);
        let key_manager = Arc::new(MockKeyManager);

        let service = ImageEncryptionService::new(algorithm, image_store, key_manager);
        assert!(service.is_ok());
    }

    #[test]
    fn test_request_validation() {
        let algorithm = Box::new(ChaCha20Poly1305::new());
        let image_store = Arc::new(MockImageStore);
        let key_manager = Arc::new(MockKeyManager);

        let service = ImageEncryptionService::new(algorithm, image_store, key_manager).unwrap();

        // Test empty image data
        let request = EncryptImageRequest {
            image_data: vec![],
            options: EncryptionOptions::default(),
            key_id: None,
            thumbnail_options: vec![],
            permissions: None,
        };

        assert!(service.validate_encrypt_request(&request).is_err());

        // Test valid request
        let request = EncryptImageRequest {
            image_data: vec![1, 2, 3, 4],
            options: EncryptionOptions::default(),
            key_id: None,
            thumbnail_options: vec![],
            permissions: None,
        };

        assert!(service.validate_encrypt_request(&request).is_ok());
    }
}
