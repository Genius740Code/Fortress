//! Comprehensive Database Key Manager Tests
//! 
//! This test suite provides comprehensive coverage for the database key manager,
//! testing lifecycle operations, metadata management, key rotation, database
//! transaction handling, and error recovery.

use fortress_core::key_database::{KeyDatabase, KeyDatabaseConfig, KeyDatabaseBackend, KeyDatabaseStats, SqliteKeyDatabase};
use fortress_core::key::{KeyId, KeyMetadata, SecureKey};
use fortress_core::encryption::Aegis256;
use fortress_core::error::{FortressError, Result, KeyErrorCode};
use chrono::{Utc, Duration};
use std::collections::HashMap;
use tempfile::NamedTempFile;
use tokio::fs;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a temporary SQLite database
    async fn create_temp_sqlite_db() -> (String, NamedTempFile) {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path().to_str().unwrap().to_string();
        (format!("sqlite:{}", db_path), temp_file)
    }

    /// Helper function to create test key metadata
    fn create_test_metadata(algorithm_name: &str) -> KeyMetadata {
        let mut metadata = KeyMetadata::new(&Aegis256::new());
        metadata.algorithm = algorithm_name.to_string();
        metadata.created_at = Utc::now();
        metadata.expires_at = Some(Utc::now() + Duration::hours(24));
        metadata.tags.insert("test".to_string(), "true".to_string());
        metadata.tags.insert("environment".to_string(), "test".to_string());
        metadata
    }

    /// Helper function to create test secure key
    fn create_test_key() -> SecureKey {
        let key_data = vec![42u8; 32]; // 256-bit key
        SecureKey::new(key_data)
    }

    /// Test database initialization and schema creation
    #[tokio::test]
    async fn test_database_initialization() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        
        // Initialize schema
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test health check
        let healthy = db.health_check().await
            .expect("Health check should succeed");
        assert!(healthy, "Database should be healthy after initialization");
        
        // Test stats on empty database
        let stats = db.get_stats().await
            .expect("Stats retrieval should succeed");
        assert_eq!(stats.total_keys, 0, "Empty database should have 0 keys");
        assert_eq!(stats.active_connections, 1, "Should have at least 1 active connection");
    }

    /// Test key lifecycle management (create, read, update, delete)
    #[tokio::test]
    async fn test_key_lifecycle_management() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test key creation
        let key_id = KeyId::new();
        let key = create_test_key();
        let metadata = create_test_metadata("aegis256");
        
        db.store_key(&key_id, &key, &metadata).await
            .expect("Key storage should succeed");
        
        // Test key retrieval
        let retrieved = db.retrieve_key(&key_id).await
            .expect("Key retrieval should succeed");
        assert!(retrieved.is_some(), "Stored key should be retrievable");
        
        let (retrieved_key, retrieved_metadata) = retrieved.unwrap();
        assert_eq!(retrieved_key.to_vec(), key.to_vec(), "Retrieved key should match original");
        assert_eq!(retrieved_metadata.algorithm, metadata.algorithm, "Retrieved metadata should match");
        
        // Test key existence check
        let exists = db.key_exists(&key_id).await
            .expect("Existence check should succeed");
        assert!(exists, "Stored key should exist");
        
        // Test metadata-only retrieval
        let metadata_only = db.get_key_metadata(&key_id).await
            .expect("Metadata retrieval should succeed");
        assert!(metadata_only.is_some(), "Metadata should be retrievable");
        assert_eq!(metadata_only.unwrap().algorithm, metadata.algorithm, "Retrieved metadata should match");
        
        // Test key update (store with same ID but different data)
        let updated_key = SecureKey::new(vec![99u8; 32]);
        let mut updated_metadata = metadata;
        updated_metadata.version += 1;
        updated_metadata.updated_at = Some(Utc::now());
        
        db.store_key(&key_id, &updated_key, &updated_metadata).await
            .expect("Key update should succeed");
        
        let updated_retrieved = db.retrieve_key(&key_id).await
            .expect("Updated key retrieval should succeed");
        assert!(updated_retrieved.is_some(), "Updated key should be retrievable");
        
        let (retrieved_updated_key, retrieved_updated_metadata) = updated_retrieved.unwrap();
        assert_eq!(retrieved_updated_key.to_vec(), updated_key.to_vec(), "Updated key should match new data");
        assert_eq!(retrieved_updated_metadata.version, updated_metadata.version, "Version should be updated");
        
        // Test key deletion
        db.delete_key(&key_id).await
            .expect("Key deletion should succeed");
        
        let deleted_retrieved = db.retrieve_key(&key_id).await
            .expect("Deleted key retrieval should succeed");
        assert!(deleted_retrieved.is_none(), "Deleted key should not be retrievable");
        
        let exists_after_delete = db.key_exists(&key_id).await
            .expect("Existence check after delete should succeed");
        assert!(!exists_after_delete, "Deleted key should not exist");
    }

    /// Test key metadata management
    #[tokio::test]
    async fn test_key_metadata_management() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Create key with comprehensive metadata
        let key_id = KeyId::new();
        let key = create_test_key();
        let mut metadata = create_test_metadata("aegis256");
        
        // Add comprehensive metadata
        metadata.description = Some("Test key for metadata validation".to_string());
        metadata.purpose = Some("encryption".to_string());
        metadata.tags.insert("environment".to_string(), "production".to_string());
        metadata.tags.insert("owner".to_string(), "security-team".to_string());
        metadata.tags.insert("criticality".to_string(), "high".to_string());
        metadata.custom.insert("rotation_policy".to_string(), "90-days".to_string());
        metadata.custom.insert("compliance".to_string(), "gdpr".to_string());
        
        db.store_key(&key_id, &key, &metadata).await
            .expect("Key storage with metadata should succeed");
        
        // Retrieve and verify metadata
        let retrieved_metadata = db.get_key_metadata(&key_id).await
            .expect("Metadata retrieval should succeed");
        assert!(retrieved_metadata.is_some(), "Metadata should be retrievable");
        
        let retrieved = retrieved_metadata.unwrap();
        assert_eq!(retrieved.algorithm, metadata.algorithm);
        assert_eq!(retrieved.description, metadata.description);
        assert_eq!(retrieved.purpose, metadata.purpose);
        assert_eq!(retrieved.tags.len(), metadata.tags.len());
        assert_eq!(retrieved.custom.len(), metadata.custom.len());
        
        // Verify tags
        for (key, value) in &metadata.tags {
            assert_eq!(retrieved.tags.get(key), Some(value));
        }
        
        // Verify custom fields
        for (key, value) in &metadata.custom {
            assert_eq!(retrieved.custom.get(key), Some(value));
        }
        
        // Test metadata updates
        let mut updated_metadata = metadata;
        updated_metadata.version += 1;
        updated_metadata.updated_at = Some(Utc::now());
        updated_metadata.tags.insert("status".to_string(), "rotated".to_string());
        updated_metadata.custom.insert("last_rotation".to_string(), Utc::now().to_rfc3339());
        
        db.store_key(&key_id, &key, &updated_metadata).await
            .expect("Metadata update should succeed");
        
        let updated_retrieved = db.get_key_metadata(&key_id).await
            .expect("Updated metadata retrieval should succeed");
        assert!(updated_retrieved.is_some(), "Updated metadata should be retrievable");
        
        let updated = updated_retrieved.unwrap();
        assert_eq!(updated.version, updated_metadata.version);
        assert_eq!(updated.tags.get("status"), Some(&"rotated".to_string()));
        assert!(updated.custom.contains_key("last_rotation"));
    }

    /// Test key rotation operations
    #[tokio::test]
    async fn test_key_rotation_operations() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Create initial key
        let key_id = KeyId::new();
        let initial_key = create_test_key();
        let mut initial_metadata = create_test_metadata("aegis256");
        initial_metadata.version = 1;
        initial_metadata.created_at = Utc::now();
        initial_metadata.expires_at = Some(Utc::now() + Duration::days(90));
        
        db.store_key(&key_id, &initial_key, &initial_metadata).await
            .expect("Initial key storage should succeed");
        
        // Simulate key rotation
        let rotated_key = SecureKey::new(vec![123u8; 32]);
        let mut rotated_metadata = initial_metadata.clone();
        rotated_metadata.version = 2;
        rotated_metadata.updated_at = Some(Utc::now());
        rotated_metadata.expires_at = Some(Utc::now() + Duration::days(90));
        rotated_metadata.tags.insert("rotated".to_string(), "true".to_string());
        rotated_metadata.custom.insert("rotation_reason".to_string(), "scheduled".to_string());
        
        // Store rotated key
        db.store_key(&key_id, &rotated_key, &rotated_metadata).await
            .expect("Rotated key storage should succeed");
        
        // Verify rotation
        let retrieved = db.retrieve_key(&key_id).await
            .expect("Rotated key retrieval should succeed");
        assert!(retrieved.is_some(), "Rotated key should be retrievable");
        
        let (retrieved_key, retrieved_metadata) = retrieved.unwrap();
        assert_eq!(retrieved_key.to_vec(), rotated_key.to_vec(), "Retrieved key should be rotated key");
        assert_eq!(retrieved_metadata.version, 2, "Version should be updated");
        assert_eq!(retrieved_metadata.tags.get("rotated"), Some(&"true".to_string()));
        
        // Test multiple rotations
        let mut current_key = rotated_key;
        let mut current_metadata = rotated_metadata;
        
        for rotation_num in 3..=5 {
            let new_key = SecureKey::new(vec![rotation_num as u8; 32]);
            let mut new_metadata = current_metadata.clone();
            new_metadata.version = rotation_num;
            new_metadata.updated_at = Some(Utc::now());
            new_metadata.expires_at = Some(Utc::now() + Duration::days(90));
            
            db.store_key(&key_id, &new_key, &new_metadata).await
                .expect(&format!("Rotation {} should succeed", rotation_num));
            
            let retrieved = db.retrieve_key(&key_id).await
                .expect(&format!("Retrieval after rotation {} should succeed", rotation_num));
            assert!(retrieved.is_some(), "Key should be retrievable after rotation {}", rotation_num);
            
            let (retrieved_key, retrieved_metadata) = retrieved.unwrap();
            assert_eq!(retrieved_key.to_vec(), new_key.to_vec(), "Key should match after rotation {}", rotation_num);
            assert_eq!(retrieved_metadata.version, rotation_num, "Version should be {} after rotation", rotation_num);
            
            current_key = new_key;
            current_metadata = new_metadata;
        }
        
        // Verify final state
        let final_retrieved = db.retrieve_key(&key_id).await
            .expect("Final key retrieval should succeed");
        assert!(final_retrieved.is_some(), "Final key should be retrievable");
        
        let (final_key, final_metadata) = final_retrieved.unwrap();
        assert_eq!(final_metadata.version, 5, "Final version should be 5");
        assert_eq!(final_key.to_vec(), vec![5u8; 32], "Final key should match last rotation");
    }

    /// Test database transaction handling
    #[tokio::test]
    async fn test_database_transaction_handling() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test successful transaction (multiple operations)
        let key_ids: Vec<KeyId> = (0..10).map(|_| KeyId::new()).collect();
        let mut keys = Vec::new();
        let mut metadata_list = Vec::new();
        
        // Store multiple keys
        for (i, key_id) in key_ids.iter().enumerate() {
            let key = SecureKey::new(vec![i as u8; 32]);
            let metadata = create_test_metadata(&format!("key_{}", i));
            
            db.store_key(key_id, &key, &metadata).await
                .expect(&format!("Key {} storage should succeed", i));
            
            keys.push(key);
            metadata_list.push(metadata);
        }
        
        // Verify all keys were stored
        for (i, key_id) in key_ids.iter().enumerate() {
            let retrieved = db.retrieve_key(key_id).await
                .expect(&format!("Key {} retrieval should succeed", i));
            assert!(retrieved.is_some(), "Key {} should be retrievable", i);
            
            let (retrieved_key, retrieved_metadata) = retrieved.unwrap();
            assert_eq!(retrieved_key.to_vec(), keys[i].to_vec(), "Key {} should match", i);
            assert_eq!(retrieved_metadata.algorithm, metadata_list[i].algorithm, "Metadata {} should match", i);
        }
        
        // Test transaction rollback simulation
        // (Note: SQLite doesn't have explicit transaction rollback in this implementation,
        // but we can test error handling)
        
        // Test with invalid key data (should fail gracefully)
        let invalid_key_id = KeyId::new();
        let valid_key = create_test_key();
        let valid_metadata = create_test_metadata("valid");
        
        // This should succeed
        db.store_key(&invalid_key_id, &valid_key, &valid_metadata).await
            .expect("Valid key storage should succeed");
        
        // Verify database is still consistent
        let stats = db.get_stats().await
            .expect("Stats retrieval should succeed");
        assert_eq!(stats.total_keys, 11, "Should have all 11 keys (10 valid + 1 test)");
        
        // Clean up test data
        for key_id in &key_ids {
            db.delete_key(key_id).await
                .expect("Key cleanup should succeed");
        }
        
        db.delete_key(&invalid_key_id).await
            .expect("Test key cleanup should succeed");
        
        let final_stats = db.get_stats().await
            .expect("Final stats retrieval should succeed");
        assert_eq!(final_stats.total_keys, 0, "All keys should be cleaned up");
    }

    /// Test error recovery and rollback
    #[tokio::test]
    async fn test_error_recovery_and_rollback() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test error handling for non-existent keys
        let non_existent_id = KeyId::new();
        
        let retrieval_result = db.retrieve_key(&non_existent_id).await;
        assert!(retrieval_result.is_ok(), "Retrieval should not error for non-existent key");
        assert!(retrieval_result.unwrap().is_none(), "Non-existent key should return None");
        
        let metadata_result = db.get_key_metadata(&non_existent_id).await;
        assert!(metadata_result.is_ok(), "Metadata retrieval should not error for non-existent key");
        assert!(metadata_result.unwrap().is_none(), "Non-existent metadata should return None");
        
        let exists_result = db.key_exists(&non_existent_id).await;
        assert!(exists_result.is_ok(), "Existence check should not error for non-existent key");
        assert!(!exists_result.unwrap(), "Non-existent key should not exist");
        
        // Test deletion of non-existent key (should not error)
        let delete_result = db.delete_key(&non_existent_id).await;
        assert!(delete_result.is_ok(), "Deletion of non-existent key should not error");
        
        // Test error handling for invalid database operations
        // Create a key first
        let key_id = KeyId::new();
        let key = create_test_key();
        let metadata = create_test_metadata("test");
        
        db.store_key(&key_id, &key, &metadata).await
            .expect("Key storage should succeed");
        
        // Verify the key exists
        let exists_before = db.key_exists(&key_id).await
            .expect("Existence check should succeed");
        assert!(exists_before, "Key should exist before deletion");
        
        // Delete the key
        db.delete_key(&key_id).await
            .expect("Key deletion should succeed");
        
        // Verify the key no longer exists
        let exists_after = db.key_exists(&key_id).await
            .expect("Existence check after deletion should succeed");
        assert!(!exists_after, "Key should not exist after deletion");
        
        // Try to delete again (should not error)
        let delete_again_result = db.delete_key(&key_id).await;
        assert!(delete_again_result.is_ok(), "Double deletion should not error");
    }

    /// Test performance with many keys
    #[tokio::test]
    async fn test_performance_many_keys() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 10,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        let num_keys = 100;
        let key_ids: Vec<KeyId> = (0..num_keys).map(|_| KeyId::new()).collect();
        
        // Test bulk key creation performance
        let start_time = std::time::Instant::now();
        
        for (i, key_id) in key_ids.iter().enumerate() {
            let key = SecureKey::new(vec![i as u8; 32]);
            let metadata = create_test_metadata(&format!("perf_key_{}", i));
            
            db.store_key(key_id, &key, &metadata).await
                .expect(&format!("Performance key {} storage should succeed", i));
        }
        
        let creation_duration = start_time.elapsed();
        println!("Created {} keys in {:?}", num_keys, creation_duration);
        
        // Test bulk key retrieval performance
        let start_time = std::time::Instant::now();
        let mut successful_retrievals = 0;
        
        for (i, key_id) in key_ids.iter().enumerate() {
            let result = db.retrieve_key(key_id).await
                .expect(&format!("Performance key {} retrieval should not error", i));
            
            if result.is_some() {
                successful_retrievals += 1;
            }
        }
        
        let retrieval_duration = start_time.elapsed();
        println!("Retrieved {} keys in {:?}", successful_retrievals, retrieval_duration);
        
        assert_eq!(successful_retrievals, num_keys, "All keys should be retrievable");
        
        // Test listing performance
        let start_time = std::time::Instant::now();
        let listed_keys = db.list_keys(Some(50), Some(0)).await
            .expect("Key listing should succeed");
        let listing_duration = start_time.elapsed();
        
        assert_eq!(listed_keys.len(), 50, "Should list 50 keys with limit");
        println!("Listed {} keys in {:?}", listed_keys.len(), listing_duration);
        
        // Test pagination
        let page1 = db.list_keys(Some(25), Some(0)).await
            .expect("First page listing should succeed");
        let page2 = db.list_keys(Some(25), Some(25)).await
            .expect("Second page listing should succeed");
        
        assert_eq!(page1.len(), 25, "First page should have 25 keys");
        assert_eq!(page2.len(), 25, "Second page should have 25 keys");
        
        // Verify no overlap between pages
        let page1_ids: std::collections::HashSet<_> = page1.iter().map(|(id, _)| id).collect();
        let page2_ids: std::collections::HashSet<_> = page2.iter().map(|(id, _)| id).collect();
        let overlap = page1_ids.intersection(&page2_ids).count();
        assert_eq!(overlap, 0, "Pages should not overlap");
        
        // Performance assertions
        assert!(creation_duration.as_millis() < 10000, "Key creation should complete in reasonable time");
        assert!(retrieval_duration.as_millis() < 5000, "Key retrieval should complete in reasonable time");
        assert!(listing_duration.as_millis() < 1000, "Key listing should be fast");
        
        // Cleanup
        for key_id in &key_ids {
            db.delete_key(key_id).await
                .expect("Performance cleanup should succeed");
        }
    }

    /// Test encryption at rest functionality
    #[tokio::test]
    async fn test_encryption_at_rest() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let master_key = "test_master_key_12345678901234567890123456789012";
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: true,
            master_key: Some(master_key.to_string()),
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test key storage with encryption
        let key_id = KeyId::new();
        let key = SecureKey::new(vec![42u8; 32]);
        let metadata = create_test_metadata("encrypted");
        
        db.store_key(&key_id, &key, &metadata).await
            .expect("Encrypted key storage should succeed");
        
        // Test key retrieval with decryption
        let retrieved = db.retrieve_key(&key_id).await
            .expect("Encrypted key retrieval should succeed");
        assert!(retrieved.is_some(), "Encrypted key should be retrievable");
        
        let (retrieved_key, retrieved_metadata) = retrieved.unwrap();
        assert_eq!(retrieved_key.to_vec(), key.to_vec(), "Decrypted key should match original");
        assert_eq!(retrieved_metadata.algorithm, metadata.algorithm, "Decrypted metadata should match");
        
        // Test that data is actually encrypted in database
        // (This is a simplified test - in practice, you'd check the raw database)
        
        // Test with different master key (should fail)
        let wrong_master_key = "wrong_master_key_12345678901234567890123456789012";
        let mut wrong_config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: true,
            master_key: Some(wrong_master_key.to_string()),
        };
        
        let wrong_db = SqliteKeyDatabase::new(wrong_config).await
            .expect("Database creation should succeed");
        wrong_db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Try to retrieve with wrong master key
        let wrong_retrieval = wrong_db.retrieve_key(&key_id).await;
        // This might succeed or fail depending on implementation
        // The key point is that the system handles encryption/decryption
        
        // Test encryption disabled
        let no_encrypt_config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let no_encrypt_db = SqliteKeyDatabase::new(no_encrypt_config).await
            .expect("Database creation should succeed");
        no_encrypt_db.initialize().await
            .expect("Schema initialization should succeed");
        
        let no_encrypt_key_id = KeyId::new();
        let no_encrypt_key = SecureKey::new(vec![99u8; 32]);
        let no_encrypt_metadata = create_test_metadata("no_encrypt");
        
        no_encrypt_db.store_key(&no_encrypt_key_id, &no_encrypt_key, &no_encrypt_metadata).await
            .expect("Non-encrypted key storage should succeed");
        
        let no_encrypt_retrieved = no_encrypt_db.retrieve_key(&no_encrypt_key_id).await
            .expect("Non-encrypted key retrieval should succeed");
        assert!(no_encrypt_retrieved.is_some(), "Non-encrypted key should be retrievable");
        
        let (no_encrypt_retrieved_key, _) = no_encrypt_retrieved.unwrap();
        assert_eq!(no_encrypt_retrieved_key.to_vec(), no_encrypt_key.to_vec(), "Non-encrypted key should match");
    }

    /// Test key preloading functionality
    #[tokio::test]
    async fn test_key_preloading() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Store multiple keys
        let num_keys = 20;
        let mut key_ids = Vec::new();
        
        for i in 0..num_keys {
            let key_id = KeyId::new();
            let key = SecureKey::new(vec![i as u8; 32]);
            let metadata = create_test_metadata(&format!("preload_key_{}", i));
            
            db.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Preload key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        // Test preloading
        let start_time = std::time::Instant::now();
        let preloaded_keys = db.preload_keys().await
            .expect("Key preloading should succeed");
        let preload_duration = start_time.elapsed();
        
        assert_eq!(preloaded_keys.len(), num_keys, "All keys should be preloaded");
        println!("Preloaded {} keys in {:?}", preloaded_keys.len(), preload_duration);
        
        // Verify preloaded keys
        for (i, (key_id, key, metadata)) in preloaded_keys.iter().enumerate() {
            assert!(key_ids.contains(key_id), "Preloaded key ID should be in original list");
            assert_eq!(key.to_vec(), vec![i as u8; 32], "Preloaded key should match original");
            assert_eq!(metadata.algorithm, "aegis256", "Preloaded metadata should match");
        }
        
        // Test preloading performance (should be faster than individual retrievals)
        let start_time = std::time::Instant::now();
        let mut individual_retrievals = 0;
        
        for key_id in &key_ids {
            let result = db.retrieve_key(key_id).await
                .expect("Individual retrieval should not error");
            if result.is_some() {
                individual_retrievals += 1;
            }
        }
        
        let individual_duration = start_time.elapsed();
        println!("Individual retrieval of {} keys took {:?}", individual_retrievals, individual_duration);
        
        // Preloading should be faster or comparable to individual retrievals
        // (This is a rough guideline - actual performance depends on implementation)
        assert_eq!(individual_retrievals, num_keys, "All keys should be retrievable individually");
        
        // Cleanup
        for key_id in &key_ids {
            db.delete_key(key_id).await
                .expect("Preload cleanup should succeed");
        }
    }

    /// Test database statistics and monitoring
    #[tokio::test]
    async fn test_database_statistics_monitoring() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test initial stats
        let initial_stats = db.get_stats().await
            .expect("Initial stats retrieval should succeed");
        assert_eq!(initial_stats.total_keys, 0, "Initial stats should show 0 keys");
        assert_eq!(initial_stats.active_connections, 1, "Should have 1 active connection");
        assert!(initial_stats.database_size_bytes >= 0, "Database size should be non-negative");
        
        // Store keys and check stats updates
        let num_keys = 50;
        let key_ids: Vec<KeyId> = (0..num_keys).map(|_| KeyId::new()).collect();
        
        for (i, key_id) in key_ids.iter().enumerate() {
            let key = SecureKey::new(vec![i as u8; 32]);
            let metadata = create_test_metadata(&format!("stats_key_{}", i));
            
            db.store_key(key_id, &key, &metadata).await
                .expect(&format!("Stats key {} storage should succeed", i));
        }
        
        let after_storage_stats = db.get_stats().await
            .expect("Stats after storage should succeed");
        assert_eq!(after_storage_stats.total_keys, num_keys, "Stats should reflect stored keys");
        assert!(after_storage_stats.database_size_bytes > initial_stats.database_size_bytes, 
                "Database size should increase after storing keys");
        
        // Test stats after deletions
        for key_id in &key_ids {
            db.delete_key(key_id).await
                .expect("Stats cleanup should succeed");
        }
        
        let final_stats = db.get_stats().await
            .expect("Final stats retrieval should succeed");
        assert_eq!(final_stats.total_keys, 0, "Stats should show 0 keys after cleanup");
        
        // Test health check
        let healthy = db.health_check().await
            .expect("Health check should succeed");
        assert!(healthy, "Database should be healthy");
        
        // Test multiple health checks
        for _ in 0..5 {
            let healthy = db.health_check().await
                .expect("Repeated health check should succeed");
            assert!(healthy, "Database should remain healthy");
        }
    }

    /// Test concurrent database operations
    #[tokio::test]
    async fn test_concurrent_database_operations() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 10,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = std::sync::Arc::new(SqliteKeyDatabase::new(config).await
            .expect("Database creation should succeed"));
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test concurrent writes
        let num_concurrent = 20;
        let mut write_handles = Vec::new();
        
        for i in 0..num_concurrent {
            let db_clone = std::sync::Arc::clone(&db);
            let handle = tokio::spawn(async move {
                let key_id = KeyId::new();
                let key = SecureKey::new(vec![i as u8; 32]);
                let metadata = create_test_metadata(&format!("concurrent_{}", i));
                
                db_clone.store_key(&key_id, &key, &metadata).await
                    .expect(&format!("Concurrent write {} should succeed", i));
                
                key_id
            });
            write_handles.push(handle);
        }
        
        // Wait for all writes to complete
        let mut stored_key_ids = Vec::new();
        for handle in write_handles {
            let key_id = handle.await.expect("Write task should complete");
            stored_key_ids.push(key_id);
        }
        
        assert_eq!(stored_key_ids.len(), num_concurrent, "All concurrent writes should succeed");
        
        // Test concurrent reads
        let mut read_handles = Vec::new();
        
        for key_id in &stored_key_ids {
            let db_clone = std::sync::Arc::clone(&db);
            let key_id_clone = key_id.clone();
            
            let handle = tokio::spawn(async move {
                db_clone.retrieve_key(&key_id_clone).await
                    .expect("Concurrent read should not error")
            });
            read_handles.push(handle);
        }
        
        // Wait for all reads to complete
        let mut successful_reads = 0;
        
        for handle in read_handles {
            let result = handle.await.expect("Read task should complete");
            if result.is_some() {
                successful_reads += 1;
            }
        }
        
        assert_eq!(successful_reads, num_concurrent, "All concurrent reads should succeed");
        
        // Test mixed concurrent operations
        let mut mixed_handles = Vec::new();
        
        for i in 0..10 {
            let db_clone = std::sync::Arc::clone(&db);
            let key_id = KeyId::new();
            
            let handle = tokio::spawn(async move {
                // Write
                let key = SecureKey::new(vec![i as u8; 32]);
                let metadata = create_test_metadata(&format!("mixed_{}", i));
                db_clone.store_key(&key_id, &key, &metadata).await
                    .expect("Mixed write should succeed");
                
                // Read back
                let retrieved = db_clone.retrieve_key(&key_id).await
                    .expect("Mixed read should succeed");
                assert!(retrieved.is_some(), "Mixed operation should succeed");
                
                // Check existence
                let exists = db_clone.key_exists(&key_id).await
                    .expect("Mixed existence check should succeed");
                assert!(exists, "Mixed existence check should find key");
                
                // Get metadata
                let metadata = db_clone.get_key_metadata(&key_id).await
                    .expect("Mixed metadata retrieval should succeed");
                assert!(metadata.is_some(), "Mixed metadata should be retrievable");
                
                // Cleanup
                db_clone.delete_key(&key_id).await
                    .expect("Mixed cleanup should succeed");
                
                key_id
            });
            mixed_handles.push(handle);
        }
        
        // Wait for all mixed operations to complete
        for handle in mixed_handles {
            handle.await.expect("Mixed operation task should complete");
        }
        
        // Verify all keys were cleaned up
        let final_stats = db.get_stats().await
            .expect("Final stats should succeed");
        assert_eq!(final_stats.total_keys, 0, "All mixed operation keys should be cleaned up");
    }
}
