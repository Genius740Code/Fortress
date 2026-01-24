//! Integration tests for fortress-core

use fortress_core::{
    encryption::{Aegis256, ChaCha20Poly1305, Aes256Gcm, EncryptionAlgorithm},
    key::{InMemoryKeyManager, KeyManager, KeyMetadata},
    storage::{InMemoryStorage, FileSystemStorage, StorageBackend},
    query::{InMemoryQueryEngine, QueryEngine, TableSchema, ColumnInfo, ColumnType, Row, QueryParameter},
    config::{Config, DatabaseConfig, EncryptionConfig},
    error::FortressError,
};

use tempfile::TempDir;
use uuid::Uuid;

#[tokio::test]
async fn test_end_to_end_encryption_workflow() {
    // Create key manager
    let key_manager = InMemoryKeyManager::new();
    let algorithm = Aegis256::new();
    
    // Generate and store key
    let key = key_manager.generate_key(&algorithm).await.unwrap();
    let key_id = Uuid::new_v4().to_string();
    let metadata = KeyMetadata::builder()
        .key_id(key_id.clone())
        .algorithm(algorithm.name().to_string())
        .version(1)
        .expires_at(chrono::Utc::now() + chrono::Duration::days(90))
        .purpose("test".to_string())
        .performance_profile(fortress_core::encryption::PerformanceProfile::Lightning)
        .build()
        .unwrap();
    
    key_manager.store_key(&key_id, &key, &metadata).await.unwrap();
    
    // Test encryption and decryption
    let plaintext = b"Hello, Fortress! This is a test message for end-to-end encryption.";
    let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
    let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
    
    assert_eq!(plaintext, decrypted);
    
    // Verify key retrieval
    let (retrieved_key, retrieved_metadata) = key_manager.retrieve_key(&key_id).await.unwrap();
    assert_eq!(key.as_bytes(), retrieved_key.as_bytes());
    assert_eq!(metadata.key_id, retrieved_metadata.key_id);
}

#[tokio::test]
async fn test_multi_algorithm_encryption() {
    let algorithms: Vec<Box<dyn EncryptionAlgorithm>> = vec![
        Box::new(Aegis256::new()),
        Box::new(ChaCha20Poly1305::new()),
        Box::new(Aes256Gcm::new()),
    ];
    
    let plaintext = b"Multi-algorithm test message";
    
    for algorithm in algorithms {
        let key = fortress_core::encryption::SecureKey::generate(algorithm.key_size());
        
        // Test encryption
        let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext.to_vec());
        
        // Test decryption
        let decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
        assert_eq!(plaintext, decrypted);
        
        // Test async methods
        let ciphertext_async = algorithm.encrypt_async(plaintext, key.as_bytes()).await.unwrap();
        let decrypted_async = algorithm.decrypt_async(&ciphertext_async, key.as_bytes()).await.unwrap();
        assert_eq!(plaintext, decrypted_async);
    }
}

#[tokio::test]
async fn test_storage_backends() {
    let test_data = b"Test data for storage backends";
    let test_key = "test_key";
    
    // Test in-memory storage
    let memory_storage = InMemoryStorage::new();
    memory_storage.put(test_key, test_data).await.unwrap();
    let retrieved = memory_storage.get(test_key).await.unwrap();
    assert_eq!(retrieved, Some(test_data.to_vec()));
    assert!(memory_storage.exists(test_key).await.unwrap());
    
    // Test file system storage
    let temp_dir = TempDir::new().unwrap();
    let fs_storage = FileSystemStorage::new(temp_dir.path()).unwrap();
    fs_storage.put(test_key, test_data).await.unwrap();
    let retrieved = fs_storage.get(test_key).await.unwrap();
    assert_eq!(retrieved, Some(test_data.to_vec()));
    assert!(fs_storage.exists(test_key).await.unwrap());
    
    // Test health checks
    let memory_health = memory_storage.health_check().await.unwrap();
    assert!(memory_health.healthy);
    
    let fs_health = fs_storage.health_check().await.unwrap();
    assert!(fs_health.healthy);
    
    // Test metadata
    let memory_metadata = memory_storage.metadata();
    assert_eq!(memory_metadata.backend_type, "in_memory");
    
    let fs_metadata = fs_storage.metadata();
    assert_eq!(fs_metadata.backend_type, "filesystem");
}

#[tokio::test]
async fn test_query_engine_integration() {
    let engine = InMemoryQueryEngine::new();
    
    // Create table schema
    let schema = TableSchema::new("users".to_string())
        .add_column(ColumnInfo {
            name: "id".to_string(),
            column_type: ColumnType::Uuid,
            nullable: false,
            encrypted: false,
            size: None,
        })
        .add_column(ColumnInfo {
            name: "name".to_string(),
            column_type: ColumnType::Text,
            nullable: false,
            encrypted: false,
            size: None,
        })
        .add_column(ColumnInfo {
            name: "email".to_string(),
            column_type: ColumnType::Text,
            nullable: false,
            encrypted: true,
            size: None,
        })
        .add_column(ColumnInfo {
            name: "created_at".to_string(),
            column_type: ColumnType::Timestamp,
            nullable: false,
            encrypted: false,
            size: None,
        })
        .with_primary_key(vec!["id".to_string()]);
    
    engine.create_table(schema).await.unwrap();
    
    // Insert test data
    let user_id = Uuid::new_v4();
    let row = Row::new(vec![
        QueryParameter::Uuid(user_id),
        QueryParameter::String("Alice Johnson".to_string()),
        QueryParameter::String("alice@example.com".to_string()),
        QueryParameter::Timestamp(chrono::Utc::now()),
    ]);
    engine.insert("users", row).await.unwrap();
    
    // Query data
    let result = engine.execute("SELECT * FROM users", &[]).await.unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.columns.len(), 4);
    assert_eq!(result.total_rows, Some(1));
    
    // Test row access with type conversion
    let row = &result.rows[0];
    let id: Uuid = row.get_as(0).unwrap();
    let name: String = row.get_as(1).unwrap();
    let email: String = row.get_as(2).unwrap();
    
    assert_eq!(id, user_id);
    assert_eq!(name, "Alice Johnson");
    assert_eq!(email, "alice@example.com");
    
    // Test table metadata
    let table_schema = engine.get_table_schema("users").await.unwrap();
    assert_eq!(table_schema.name, "users");
    assert_eq!(table_schema.columns.len(), 4);
    assert_eq!(table_schema.primary_key, vec!["id"]);
    
    let tables = engine.list_tables().await.unwrap();
    assert_eq!(tables, vec!["users"]);
}

#[tokio::test]
async fn test_key_rotation_workflow() {
    let key_manager = InMemoryKeyManager::new();
    let algorithm = ChaCha20Poly1305::new();
    
    // Create initial key
    let key_id = Uuid::new_v4().to_string();
    let key = key_manager.generate_key(&algorithm).await.unwrap();
    let metadata = KeyMetadata::builder()
        .key_id(key_id.clone())
        .algorithm(algorithm.name().to_string())
        .version(1)
        .expires_at(chrono::Utc::now() - chrono::Duration::hours(1)) // Expired
        .purpose("rotation_test".to_string())
        .performance_profile(fortress_core::encryption::PerformanceProfile::Balanced)
        .build()
        .unwrap();
    
    key_manager.store_key(&key_id, &key, &metadata).await.unwrap();
    
    // Check if rotation is needed
    let needs_rotation = key_manager.needs_rotation(&key_id).await.unwrap();
    assert!(needs_rotation);
    
    // Rotate key
    let (new_key, new_metadata) = key_manager.rotate_key(&key_id, &algorithm).await.unwrap();
    assert_ne!(key.as_bytes(), new_key.as_bytes());
    assert_eq!(new_metadata.key_id, key_id);
    
    // Verify new key is stored
    let (retrieved_key, retrieved_metadata) = key_manager.retrieve_key(&key_id).await.unwrap();
    assert_eq!(new_key.as_bytes(), retrieved_key.as_bytes());
    assert_eq!(new_metadata.version, retrieved_metadata.version);
}

#[tokio::test]
async fn test_configuration_validation() {
    // Test valid configuration
    let valid_config = Config::builder()
        .database(DatabaseConfig {
            path: "/tmp/test.db".to_string(),
            ..Default::default()
        })
        .encryption(EncryptionConfig {
            default_algorithm: "aegis256".to_string(),
            ..Default::default()
        })
        .build()
        .unwrap();
    
    assert!(valid_config.validate().is_ok());
    
    // Test invalid configuration
    let result = Config::builder()
        .database(DatabaseConfig {
            path: "".to_string(), // Invalid: empty path
            ..Default::default()
        })
        .build();
    
    assert!(result.is_err());
    
    let result = Config::builder()
        .database(DatabaseConfig::default())
        .encryption(EncryptionConfig {
            default_algorithm: "invalid_algorithm".to_string(), // Invalid algorithm
            ..Default::default()
        })
        .build();
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_encrypted_data_serialization() {
    let algorithm = Aegis256::new();
    let key = fortress_core::encryption::SecureKey::generate(algorithm.key_size());
    let plaintext = b"Test data for serialization";
    
    // Encrypt data
    let ciphertext = algorithm.encrypt(plaintext, key.as_bytes()).unwrap();
    
    // Create encrypted data container
    let encrypted_data = fortress_core::encryption::EncryptedData::new(
        ciphertext.into(),
        algorithm.name().to_string(),
    )
    .with_nonce(fortress_core::encryption::SecureKey::generate(algorithm.nonce_size()).as_bytes().to_vec().into())
    .with_key_version(1)
    .with_metadata("purpose".to_string(), "test".to_string());
    
    // Test serialization
    let base64 = encrypted_data.to_base64().unwrap();
    let deserialized = fortress_core::encryption::EncryptedData::from_base64(&base64).unwrap();
    
    assert_eq!(encrypted_data.ciphertext, deserialized.ciphertext);
    assert_eq!(encrypted_data.algorithm, deserialized.algorithm);
    assert_eq!(encrypted_data.key_version, deserialized.key_version);
    assert_eq!(encrypted_data.metadata, deserialized.metadata);
}

#[tokio::test]
async fn test_error_handling() {
    // Test encryption errors
    let algorithm = Aegis256::new();
    let invalid_key = b"short"; // Too short for AEGIS-256
    let plaintext = b"Test data";
    
    let result = algorithm.encrypt(plaintext, invalid_key);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FortressError::Encryption { code: fortress_core::error::EncryptionErrorCode::InvalidKeyLength, .. }
    ));
    
    // Test storage errors
    let storage = InMemoryStorage::new();
    let result = storage.get("nonexistent_key").await.unwrap();
    assert_eq!(result, None);
    
    let result = storage.delete("nonexistent_key").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FortressError::Storage { code: fortress_core::error::StorageErrorCode::NotFound, .. }
    ));
    
    // Test query errors
    let engine = InMemoryQueryEngine::new();
    let result = engine.execute("INVALID SQL", &[]).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FortressError::QueryExecution { code: fortress_core::error::QueryErrorCode::InvalidSyntax, .. }
    ));
}

#[tokio::test]
async fn test_concurrent_operations() {
    let storage = Arc::new(InMemoryStorage::new());
    let key_manager = Arc::new(InMemoryKeyManager::new());
    
    // Test concurrent storage operations
    let mut handles = vec![];
    for i in 0..10 {
        let storage_clone = storage.clone();
        let handle = tokio::spawn(async move {
            let key = format!("concurrent_key_{}", i);
            let value = format!("concurrent_value_{}", i);
            storage_clone.put(&key, value.as_bytes()).await.unwrap();
            
            let retrieved = storage_clone.get(&key).await.unwrap();
            assert_eq!(retrieved, Some(value.into_bytes()));
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Test concurrent key operations
    let mut handles = vec![];
    let algorithm = Aegis256::new();
    for i in 0..5 {
        let key_manager_clone = key_manager.clone();
        let algorithm_clone = algorithm.clone();
        let handle = tokio::spawn(async move {
            let key = key_manager_clone.generate_key(&algorithm_clone).await.unwrap();
            let key_id = format!("concurrent_key_{}", i);
            let metadata = KeyMetadata::builder()
                .key_id(key_id.clone())
                .algorithm(algorithm_clone.name().to_string())
                .version(1)
                .expires_at(chrono::Utc::now() + chrono::Duration::days(90))
                .purpose("concurrent_test".to_string())
                .performance_profile(fortress_core::encryption::PerformanceProfile::Lightning)
                .build()
                .unwrap();
            
            key_manager_clone.store_key(&key_id, &key, &metadata).await.unwrap();
            
            let (retrieved_key, _) = key_manager_clone.retrieve_key(&key_id).await.unwrap();
            assert_eq!(key.as_bytes(), retrieved_key.as_bytes());
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_performance_characteristics() {
    let algorithm = Aegis256::new();
    let key = fortress_core::encryption::SecureKey::generate(algorithm.key_size());
    
    // Test encryption performance
    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    let start = std::time::Instant::now();
    
    for _ in 0..100 {
        let ciphertext = algorithm.encrypt(&large_data, key.as_bytes()).unwrap();
        let _decrypted = algorithm.decrypt(&ciphertext, key.as_bytes()).unwrap();
    }
    
    let duration = start.elapsed();
    println!("100 iterations of 1MB encryption/decryption took: {:?}", duration);
    
    // Should complete reasonably fast (adjust threshold as needed)
    assert!(duration.as_secs() < 10); // Less than 10 seconds for 100MB of data
}

#[test]
fn test_utility_functions() {
    use fortress_core::utils::*;
    
    // Test ID generation
    let id1 = generate_id();
    let id2 = generate_id();
    assert_ne!(id1, id2);
    assert_eq!(id1.len(), 36);
    
    // Test checksum
    let data = b"test data";
    let checksum = sha256_checksum(data);
    assert_eq!(checksum.len(), 64);
    assert!(verify_sha256_checksum(data, &checksum));
    
    // Test encoding
    let encoded = hex_encode(data);
    let decoded = hex_decode(&encoded).unwrap();
    assert_eq!(decoded, data);
    
    let encoded = base64_encode(data);
    let decoded = base64_decode(&encoded).unwrap();
    assert_eq!(decoded, data);
    
    // Test validation
    assert!(validate_table_name("users").is_ok());
    assert!(validate_column_name("id").is_ok());
    assert!(validate_table_name("").is_err());
    assert!(validate_column_name("invalid-name").is_err());
    
    // Test formatting
    assert_eq!(format_bytes(1024), "1.00 KB");
    assert_eq!(format_bytes(1536), "1.50 KB");
}
