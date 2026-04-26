//! Image Encryption Demo for Fortress
//!
//! This example demonstrates how to use Fortress's image encryption capabilities
//! including basic encryption, thumbnail generation, and streaming encryption.

use fortress_core::{
    encryption::ChaCha20Poly1305,
    image_encryption::{
        ImageEncryptorFactory, EncryptionOptions, EncryptionMode, ThumbnailGenerator,
        ThumbnailSize, ThumbnailFormat, ThumbnailOptions, StreamingImageEncryptor,
        ChunkConfig, ImageFormatDetector, ImageEncryptionService,
    },
    key::KeyManager,
    storage::InMemoryStorage,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Fortress Image Encryption Demo");
    println!("================================");

    // Create a simple test image (JPEG header with some data)
    let test_image_data = create_test_jpeg_image();

    // Demo 1: Basic Image Encryption
    println!("\nDemo 1: Basic Image Encryption");
    demo_basic_encryption(&test_image_data).await?;

    // Demo 2: Thumbnail Generation
    println!("\nDemo 2: Thumbnail Generation");
    demo_thumbnail_generation(&test_image_data).await?;

    // Demo 3: Streaming Encryption
    println!("\nDemo 3: Streaming Encryption");
    demo_streaming_encryption(&test_image_data).await?;

    // Demo 4: Format Detection
    println!("\nDemo 4: Format Detection");
    demo_format_detection(&test_image_data)?;

    // Demo 5: Metadata Handling
    println!("\nDemo 5: Metadata Handling");
    demo_metadata_handling(&test_image_data).await?;

    println!("\nAll demos completed successfully!");
    Ok(())
}

/// Create a simple test JPEG image
fn create_test_jpeg_image() -> Vec<u8> {
    let mut jpeg_data = Vec::new();
    
    // JPEG SOI marker
    jpeg_data.extend_from_slice(&[0xFF, 0xD8]);
    
    // APP0 marker with JFIF info
    jpeg_data.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
    jpeg_data.extend_from_slice(b"JFIF");
    jpeg_data.extend_from_slice(&[0x00, 0x01, 0x01, 0x01]);
    jpeg_data.extend_from_slice(&[0x48, 0x00, 0x48, 0x00, 0x00]);
    
    // Simple image data (placeholder)
    for i in 0..1000 {
        jpeg_data.push((i % 256) as u8);
    }
    
    // JPEG EOI marker
    jpeg_data.extend_from_slice(&[0xFF, 0xD9]);
    
    jpeg_data
}

/// Demo basic image encryption
async fn demo_basic_encryption(image_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating image encryptor...");
    
    // Create encryptor with ChaCha20Poly1305
    let encryptor = ImageEncryptorFactory::create_encryptor("chacha20poly1305")?;
    
    // Generate encryption key
    let key = fortress_core::encryption::SecureKey::generate(32);
    
    // Configure encryption options
    let options = EncryptionOptions {
        algorithm: "chacha20poly1305".to_string(),
        encryption_mode: EncryptionMode::Full,
        encrypt_metadata: true,
        chunk_size: Some(1024 * 1024), // 1MB chunks
        quality: None,
        custom_options: std::collections::HashMap::new(),
    };
    
    println!("Encrypting image ({} bytes)...", image_data.len());
    let start_time = std::time::Instant::now();
    
    // Encrypt the image
    let encrypted_image = encryptor.encrypt(image_data.to_vec(), options, &key).await?;
    
    let encryption_time = start_time.elapsed();
    println!("✓ Encryption completed in {:?}", encryption_time);
    println!("   Original size: {} bytes", encrypted_image.original_size);
    println!("   Encrypted size: {} bytes", encrypted_image.encrypted_data.ciphertext.len());
    println!("   Format: {:?}", encrypted_image.format_info.format);
    
    // Decrypt the image
    println!("Decrypting image...");
    let start_time = std::time::Instant::now();
    
    let decrypted_data = encryptor.decrypt(&encrypted_image, &key).await?;
    
    let decryption_time = start_time.elapsed();
    println!("✓ Decryption completed in {:?}", decryption_time);
    println!("   Decrypted size: {} bytes", decrypted_data.len());
    
    // Verify integrity
    let integrity_check = image_data == decrypted_data.as_slice();
    println!("   Integrity check: {}", if integrity_check { "✓ PASSED" } else { "❌ FAILED" });
    
    Ok(())
}

/// Demo thumbnail generation
async fn demo_thumbnail_generation(image_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating thumbnail generator...");
    
    // Create thumbnail generator
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let thumbnail_generator = ThumbnailGenerator::new(algorithm);
    
    // Generate keys
    let image_key = fortress_core::encryption::SecureKey::generate(32);
    let thumbnail_key = fortress_core::encryption::SecureKey::generate(32);
    
    // First encrypt the image
    let encryptor = ImageEncryptorFactory::create_default()?;
    let options = EncryptionOptions::default();
    let encrypted_image = encryptor.encrypt(image_data.to_vec(), options, &image_key).await?;
    
    // Configure thumbnail options
    let thumbnail_options = vec![
        ThumbnailOptions {
            size: ThumbnailSize::Small,
            format: ThumbnailFormat::Jpeg,
            quality: Some(75),
            preserve_aspect_ratio: true,
            apply_watermark: false,
            watermark_text: None,
            watermark_opacity: None,
            background_color: None,
            sharpen: true,
            custom_options: std::collections::HashMap::new(),
        },
        ThumbnailOptions {
            size: ThumbnailSize::Medium,
            format: ThumbnailFormat::Png,
            quality: None,
            preserve_aspect_ratio: true,
            apply_watermark: true,
            watermark_text: Some("Fortress Demo".to_string()),
            watermark_opacity: Some(0.3),
            background_color: Some("#FFFFFF".to_string()),
            sharpen: true,
            custom_options: std::collections::HashMap::new(),
        },
    ];
    
    println!("Generating {} thumbnails...", thumbnail_options.len());
    
    for (i, options) in thumbnail_options.iter().enumerate() {
        let start_time = std::time::Instant::now();
        
        let thumbnail = thumbnail_generator
            .generate_from_encrypted(&encrypted_image, &thumbnail_key, &image_key, options.clone())
            .await?;
        
        let generation_time = start_time.elapsed();
        
        println!("   Thumbnail {}: {:?} ({:?})", i + 1, options.size, generation_time);
        println!("     Format: {:?}", thumbnail.format);
        println!("     Dimensions: {}x{}", thumbnail.thumbnail_dimensions.0, thumbnail.thumbnail_dimensions.1);
        println!("     Size: {} bytes", thumbnail.original_size);
        println!("     Fingerprint: {}", thumbnail.fingerprint);
    }
    
    Ok(())
}

/// Demo streaming encryption
async fn demo_streaming_encryption(image_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating streaming encryptor...");
    
    // Create streaming encryptor
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let chunk_config = ChunkConfig {
        chunk_size: 1024, // Small chunks for demo
        parallel_workers: 2,
        buffer_size: 8192,
        compress_chunks: false,
        compression_level: None,
    };
    
    let streaming_encryptor = StreamingImageEncryptor::new(algorithm, chunk_config);
    
    // Generate key
    let key = fortress_core::encryption::SecureKey::generate(32);
    
    // Configure options
    let options = EncryptionOptions {
        algorithm: "chacha20poly1305".to_string(),
        encryption_mode: EncryptionMode::Full,
        encrypt_metadata: true,
        chunk_size: Some(1024),
        quality: None,
        custom_options: std::collections::HashMap::new(),
    };
    
    println!("Starting streaming encryption session...");
    
    // Start streaming session
    let session_id = streaming_encryptor.start_encryption_session(image_data, options.clone()).await?;
    println!("   Session ID: {}", session_id);
    
    // Get session status
    let status = streaming_encryptor.get_session_status(&session_id).await?;
    if let Some(state) = status {
        println!("   Status: {:?}", state.status);
        println!("   Total chunks: {}", state.total_chunks);
        println!("   Total size: {} bytes", state.total_size);
    }
    
    // Perform streaming encryption
    println!("Performing streaming encryption...");
    let start_time = std::time::Instant::now();
    
    let result = streaming_encryptor.encrypt_streaming(&session_id, image_data, options, &key).await?;
    
    let encryption_time = start_time.elapsed();
    println!("✓ Streaming encryption completed in {:?}", encryption_time);
    println!("   Total chunks: {}", result.chunks.len());
    println!("   Throughput: {:.2} MB/s", result.throughput_bps / (1024.0 * 1024.0));
    println!("   Statistics:");
    println!("     Total bytes: {}", result.statistics.total_bytes);
    println!("     Avg chunk size: {:.2} bytes", result.statistics.avg_chunk_size);
    println!("     Min chunk size: {} bytes", result.statistics.min_chunk_size);
    println!("     Max chunk size: {} bytes", result.statistics.max_chunk_size);
    
    // Decrypt streaming data
    println!("Decrypting streaming data...");
    let start_time = std::time::Instant::now();
    
    let streaming_decryptor = fortress_core::image_encryption::StreamingImageDecryptor::new(
        Box::new(ChaCha20Poly1305::new())
    );
    
    let decrypted_data = streaming_decryptor.decrypt_streaming(&result.chunks, &key).await?;
    
    let decryption_time = start_time.elapsed();
    println!("✓ Streaming decryption completed in {:?}", decryption_time);
    println!("   Decrypted size: {} bytes", decrypted_data.len());
    
    // Verify integrity
    let integrity_check = image_data == decrypted_data.as_slice();
    println!("   Integrity check: {}", if integrity_check { "✓ PASSED" } else { "❌ FAILED" });
    
    // Clean up session
    streaming_encryptor.cancel_session(&session_id).await?;
    println!("   Session cancelled and cleaned up");
    
    Ok(())
}

/// Demo format detection
fn demo_format_detection(image_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Detecting image format...");
    
    // Detect format from data
    let detected_format = ImageFormatDetector::detect(image_data)?;
    println!("   Detected format: {:?}", detected_format);
    println!("   MIME type: {}", detected_format.mime_type());
    println!("   Extensions: {:?}", detected_format.extensions());
    println!("   Supports lossless: {}", detected_format.supports_lossless());
    println!("   Supports multiple pages: {}", detected_format.supports_multiple_pages());
    println!("   Default color space: {:?}", detected_format.default_color_space());
    
    // Test format validation
    let is_valid = detected_format.validate_data(image_data)?;
    println!("   Data validation: {}", if is_valid { "✓ VALID" } else { "❌ INVALID" });
    
    // Test extension detection
    let extensions = vec!["jpg", "jpeg", "png", "tiff", "bmp", "webp"];
    println!("   Testing extension detection:");
    for ext in extensions {
        let format = ImageFormatDetector::detect_from_extension(ext);
        println!("     .{} -> {:?}", ext, format);
    }
    
    Ok(())
}

/// Demo metadata handling
async fn demo_metadata_handling(image_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing metadata handling...");
    
    // Create metadata processor
    let algorithm = Box::new(ChaCha20Poly1305::new());
    let metadata_processor = fortress_core::image_encryption::MetadataProcessor::new(algorithm);
    
    // Generate key
    let key = fortress_core::encryption::SecureKey::generate(32);
    
    // Extract metadata from image
    let format = ImageFormatDetector::detect(image_data)?;
    let extractor = fortress_core::image_encryption::DefaultMetadataExtractor;
    let metadata = extractor.extract_metadata(image_data, format)?;
    
    println!("   Extracted metadata:");
    println!("     Title: {:?}", metadata.basic_info.title);
    println!("     Description: {:?}", metadata.basic_info.description);
    println!("     Creator: {:?}", metadata.basic_info.creator);
    println!("     Keywords: {:?}", metadata.basic_info.keywords);
    println!("     Format: {:?}", metadata.technical_info.format);
    println!("     Color space: {:?}", metadata.technical_info.color_space);
    println!("     File size: {} bytes", metadata.technical_info.file_size);
    println!("     Classification: {:?}", metadata.security_info.classification);
    
    // Encrypt metadata
    println!("   Encrypting metadata...");
    let start_time = std::time::Instant::now();
    
    let encrypted_metadata = metadata_processor.encrypt_metadata(&metadata, &key)?;
    
    let encryption_time = start_time.elapsed();
    println!("   ✓ Metadata encrypted in {:?}", encryption_time);
    println!("     Algorithm: {}", encrypted_metadata.encryption_algorithm);
    println!("     Version: {}", encrypted_metadata.version);
    println!("     Checksum: {}", encrypted_metadata.checksum);
    println!("     Searchable fields: {}", encrypted_metadata.searchable_fields.len());
    
    // Decrypt metadata
    println!("   Decrypting metadata...");
    let start_time = std::time::Instant::now();
    
    let decrypted_metadata = metadata_processor.decrypt_metadata(&encrypted_metadata, &key)?;
    
    let decryption_time = start_time.elapsed();
    println!("   ✓ Metadata decrypted in {:?}", decryption_time);
    
    // Verify metadata integrity
    let integrity_check = metadata.basic_info.title == decrypted_metadata.basic_info.title &&
                         metadata.technical_info.format == decrypted_metadata.technical_info.format;
    println!("   Metadata integrity: {}", if integrity_check { "✓ PASSED" } else { "❌ FAILED" });
    
    // Test searchable fields
    println!("   Searchable fields:");
    for (field, value) in &encrypted_metadata.searchable_fields {
        println!("     {}: {}", field, value);
    }
    
    Ok(())
}
