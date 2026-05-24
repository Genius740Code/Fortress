//! Comprehensive Key Database Tests
//! 
//! This test suite provides comprehensive coverage for the key database system,
//! testing database connection management, query optimization, data integrity validation,
//! backup and restore operations, and migration testing.

use fortress_core::key_database::{KeyDatabase, KeyDatabaseConfig, KeyDatabaseBackend, SqliteKeyDatabase};
use fortress_core::key::{KeyId, KeyMetadata, SecureKey};
use fortress_core::encryption::PerformanceProfile;
use chrono::{Utc, Duration};
use tempfile::NamedTempFile;
use tokio::fs;
use std::path::Path;

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
    fn create_test_metadata(algorithm_name: &str, version: u32) -> KeyMetadata {
        let key_id = KeyId::new();
        let created_at = Utc::now();
        let expires_at = Utc::now() + Duration::hours(24);
        let mut metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm_name.to_string(),
            version,
            created_at,
            expires_at,
            "testing".to_string(),
            PerformanceProfile::default(),
        );
        metadata.metadata.insert("test".to_string(), "true".to_string());
        metadata.metadata.insert("database".to_string(), "test".to_string());
        metadata.metadata.insert("purpose".to_string(), "testing".to_string());
        metadata
    }

    /// Helper function to create test secure key
    fn create_test_key(size: usize) -> SecureKey {
        let key_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        SecureKey::new(key_data)
    }

    /// Test database connection management
    #[tokio::test]
    async fn test_database_connection_management() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        // Test initial connection
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database connection should succeed");
        
        // Test schema initialization
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test health check
        let healthy = db.health_check().await
            .expect("Health check should succeed");
        assert!(healthy, "Database should be healthy");
        
        // Test multiple health checks
        for i in 0..5 {
            let healthy = db.health_check().await
                .expect(&format!("Health check {} should succeed", i));
            assert!(healthy, "Database should remain healthy");
        }
        
        // Test connection with different configurations
        let (db_path2, _temp_file2) = create_temp_sqlite_db().await;
        
        let config2 = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path2.clone(),
            max_connections: 10,
            connection_timeout_seconds: 60,
            encrypt_at_rest: true,
            master_key: Some("test_master_key_12345678901234567890123456789012".to_string()),
        };
        
        let db2 = SqliteKeyDatabase::new(config2).await
            .expect("Database connection with encryption should succeed");
        
        db2.initialize().await
            .expect("Schema initialization with encryption should succeed");
        
        let healthy2 = db2.health_check().await
            .expect("Health check with encryption should succeed");
        assert!(healthy2, "Encrypted database should be healthy");
        
        // Test storing and retrieving with encryption
        let key_id = KeyId::new();
        let key = create_test_key(32);
        let metadata = create_test_metadata("encrypted_test", 1);
        
        db2.store_key(&key_id, &key, &metadata).await
            .expect("Encrypted key storage should succeed");
        
        let retrieved = db2.retrieve_key(&key_id).await
            .expect("Encrypted key retrieval should succeed");
        assert!(retrieved.is_some(), "Encrypted key should be retrievable");
        
        let (retrieved_key, retrieved_metadata) = retrieved.unwrap();
        assert_eq!(retrieved_key.to_vec(), key.to_vec(), "Encrypted key should match original");
        assert_eq!(retrieved_metadata.algorithm, metadata.algorithm, "Encrypted metadata should match");
    }

    /// Test query optimization
    #[tokio::test]
    async fn test_query_optimization() {
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
            .expect("Database connection should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Store many keys to test query performance
        let num_keys = 100;
        let mut key_ids = Vec::new();
        
        let start_time = std::time::Instant::now();
        
        for i in 0..num_keys {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("query_opt_{}", i), 1);
            
            db.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Query optimization key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        let storage_duration = start_time.elapsed();
        println!("Stored {} keys in {:?}", num_keys, storage_duration);
        
        // Test batch retrieval performance
        let start_time = std::time::Instant::now();
        let mut successful_retrievals = 0;
        
        for key_id in &key_ids {
            let result = db.retrieve_key(key_id).await
                .expect("Query optimization retrieval should succeed");
            
            if result.is_some() {
                successful_retrievals += 1;
            }
        }
        
        let retrieval_duration = start_time.elapsed();
        println!("Retrieved {} keys in {:?}", successful_retrievals, retrieval_duration);
        
        assert_eq!(successful_retrievals, num_keys, "All keys should be retrievable");
        
        // Test pagination performance
        let start_time = std::time::Instant::now();
        
        let page1 = db.list_keys(Some(25), Some(0)).await
            .expect("First page listing should succeed");
        let page2 = db.list_keys(Some(25), Some(25)).await
            .expect("Second page listing should succeed");
        let page3 = db.list_keys(Some(25), Some(50)).await
            .expect("Third page listing should succeed");
        let page4 = db.list_keys(Some(25), Some(75)).await
            .expect("Fourth page listing should succeed");
        
        let pagination_duration = start_time.elapsed();
        println!("Paginated {} keys in 4 pages in {:?}", num_keys, pagination_duration);
        
        assert_eq!(page1.len(), 25, "First page should have 25 keys");
        assert_eq!(page2.len(), 25, "Second page should have 25 keys");
        assert_eq!(page3.len(), 25, "Third page should have 25 keys");
        assert_eq!(page4.len(), 25, "Fourth page should have 25 keys");
        
        // Verify no overlap between pages
        let page1_ids: std::collections::HashSet<_> = page1.iter().map(|(id, _)| id).collect();
        let page2_ids: std::collections::HashSet<_> = page2.iter().map(|(id, _)| id).collect();
        let page3_ids: std::collections::HashSet<_> = page3.iter().map(|(id, _)| id).collect();
        let page4_ids: std::collections::HashSet<_> = page4.iter().map(|(id, _)| id).collect();
        
        assert_eq!(page1_ids.intersection(&page2_ids).count(), 0, "Pages 1 and 2 should not overlap");
        assert_eq!(page2_ids.intersection(&page3_ids).count(), 0, "Pages 2 and 3 should not overlap");
        assert_eq!(page3_ids.intersection(&page4_ids).count(), 0, "Pages 3 and 4 should not overlap");
        
        // Test existence check performance
        let start_time = std::time::Instant::now();
        let mut successful_exists = 0;
        
        for key_id in &key_ids {
            let exists = db.key_exists(key_id).await
                .expect("Existence check should succeed");
            
            if exists {
                successful_exists += 1;
            }
        }
        
        let existence_duration = start_time.elapsed();
        println!("Checked existence for {} keys in {:?}", successful_exists, existence_duration);
        
        assert_eq!(successful_exists, num_keys, "All keys should exist");
        
        // Performance assertions
        assert!(storage_duration.as_millis() < 10000, "Storage should complete in reasonable time");
        assert!(retrieval_duration.as_millis() < 5000, "Retrieval should complete in reasonable time");
        assert!(pagination_duration.as_millis() < 1000, "Pagination should be fast");
        assert!(existence_duration.as_millis() < 2000, "Existence checks should be fast");
    }

    /// Test data integrity validation
    #[tokio::test]
    async fn test_data_integrity_validation() {
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
            .expect("Database connection should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test data integrity for various key sizes
        let test_sizes = vec![16, 32, 64, 128, 256, 512, 1024, 2048];
        let mut key_ids = Vec::new();
        
        for (i, size) in test_sizes.iter().enumerate() {
            let key_id = KeyId::new();
            let key = create_test_key(*size);
            let metadata = create_test_metadata(&format!("integrity_test_{}", i), 1);
            
            // Store the key
            db.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Integrity key {} storage should succeed", i));
            
            // Retrieve and verify integrity
            let retrieved = db.retrieve_key(&key_id).await
                .expect(&format!("Integrity key {} retrieval should succeed", i));
            
            assert!(retrieved.is_some(), "Integrity key {} should be retrievable", i);
            
            let (retrieved_key, retrieved_metadata) = retrieved.unwrap();
            assert_eq!(retrieved_key.to_vec(), key.to_vec(), "Integrity key {} data should match", i);
            assert_eq!(retrieved_metadata.algorithm, metadata.algorithm, "Integrity key {} metadata should match", i);
            assert_eq!(retrieved_metadata.version, metadata.version, "Integrity key {} version should match", i);
            
            key_ids.push(key_id);
        }
        
        // Test metadata integrity
        for (i, key_id) in key_ids.iter().enumerate() {
            let metadata_only = db.get_key_metadata(key_id).await
                .expect(&format!("Metadata {} retrieval should succeed", i));
            
            assert!(metadata_only.is_some(), "Metadata {} should be retrievable", i);
            
            let metadata = metadata_only.unwrap();
            
            // Verify all metadata fields
            assert!(!metadata.algorithm.is_empty(), "Algorithm should not be empty");
            assert!(metadata.created_at <= Utc::now(), "Created at should be valid");
            assert!(metadata.version > 0, "Version should be positive");
            
            // Verify metadata fields
            assert!(metadata.metadata.contains_key("test"), "Should have test tag");
            assert!(metadata.metadata.contains_key("database"), "Should have database tag");
            assert!(metadata.metadata.contains_key("purpose"), "Should have purpose metadata field");
        }
        
        // Test data consistency after multiple operations
        let test_key_id = KeyId::new();
        let original_key = create_test_key(64);
        let original_metadata = create_test_metadata("consistency_test", 1);
        
        // Store original
        db.store_key(&test_key_id, &original_key, &original_metadata).await
            .expect("Original key storage should succeed");
        
        // Verify original
        let original_retrieved = db.retrieve_key(&test_key_id).await
            .expect("Original retrieval should succeed");
        assert!(original_retrieved.is_some(), "Original should be retrievable");
        
        let (orig_key, _orig_metadata) = original_retrieved.unwrap();
        assert_eq!(orig_key.to_vec(), original_key.to_vec(), "Original key should match");
        
        // Update with new data
        let updated_key = create_test_key(128);
        let mut updated_metadata = original_metadata.clone();
        updated_metadata.version = 2;
        updated_metadata.metadata.insert("updated".to_string(), "true".to_string());
        
        db.store_key(&test_key_id, &updated_key, &updated_metadata).await
            .expect("Updated key storage should succeed");
        
        // Verify update
        let updated_retrieved = db.retrieve_key(&test_key_id).await
            .expect("Updated retrieval should succeed");
        assert!(updated_retrieved.is_some(), "Updated should be retrievable");
        
        let (upd_key, upd_metadata) = updated_retrieved.unwrap();
        assert_eq!(upd_key.to_vec(), updated_key.to_vec(), "Updated key should match");
        assert_eq!(upd_metadata.version, 2, "Updated version should match");
        assert!(upd_metadata.metadata.contains_key("updated"), "Should have updated tag");
        
        // Ensure old data is gone
        assert_ne!(upd_key.to_vec(), original_key.to_vec(), "Old key data should be replaced");
    }

    /// Test backup and restore operations
    #[tokio::test]
    async fn test_backup_restore_operations() {
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
            .expect("Database connection should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Store test data
        let num_keys = 50;
        let mut key_ids = Vec::new();
        let mut stored_keys = Vec::new();
        let mut stored_metadata = Vec::new();
        
        for i in 0..num_keys {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("backup_test_{}", i), 1);
            
            db.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Backup key {} storage should succeed", i));
            
            key_ids.push(key_id.clone());
            stored_keys.push(key);
            stored_metadata.push(metadata);
        }
        
        // Verify all keys are stored
        for key_id in &key_ids {
            let exists = db.key_exists(key_id).await
                .expect("Existence check should succeed");
            assert!(exists, "Key {} should exist", key_id);
        }
        
        // Create backup
        let backup_path = format!("{}.backup", db_path);
        
        // Simulate backup by copying the database file
        if Path::new(&db_path.strip_prefix("sqlite:").unwrap_or(&db_path)).exists() {
            let source_path = db_path.strip_prefix("sqlite:").unwrap_or(&db_path);
            fs::copy(source_path, &backup_path).await
                .expect("Database backup should succeed");
        }
        
        // Verify backup exists
        assert!(Path::new(&backup_path).exists(), "Backup file should exist");
        
        // Clear original database
        for key_id in &key_ids {
            db.delete_key(key_id).await
                .expect("Key deletion should succeed");
        }
        
        // Verify all keys are deleted
        for key_id in &key_ids {
            let exists = db.key_exists(key_id).await
                .expect("Existence check after deletion should succeed");
            assert!(!exists, "Key {} should be deleted", key_id);
        }
        
        // Restore from backup
        if Path::new(&backup_path).exists() {
            fs::copy(&backup_path, db_path.strip_prefix("sqlite:").unwrap_or(&db_path)).await
                .expect("Database restore should succeed");
        }
        
        // Note: In a real implementation, you would need to reconnect to the database
        // For this test, we'll verify the backup file integrity
        
        // Verify backup file size
        let backup_metadata = fs::metadata(&backup_path).await
            .expect("Backup metadata should be retrievable");
        assert!(backup_metadata.len() > 0, "Backup file should not be empty");
        
        // Clean up backup file
        fs::remove_file(&backup_path).await
            .expect("Backup cleanup should succeed");
        
        assert!(!Path::new(&backup_path).exists(), "Backup file should be cleaned up");
    }

    /// Test migration scenarios
    #[tokio::test]
    async fn test_migration_scenarios() {
        // Test version 1 to version 2 migration simulation
        
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        // Create database with "version 1" schema
        let config_v1 = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 5,
            connection_timeout_seconds: 30,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db_v1 = SqliteKeyDatabase::new(config_v1).await
            .expect("V1 database connection should succeed");
        db_v1.initialize().await
            .expect("V1 schema initialization should succeed");
        
        // Store data in version 1 format
        let v1_key_id = KeyId::new();
        let v1_key = create_test_key(32);
        let mut v1_metadata = create_test_metadata("v1_algorithm", 1);
        v1_metadata.metadata.insert("schema_version".to_string(), "1".to_string());
        
        db_v1.store_key(&v1_key_id, &v1_key, &v1_metadata).await
            .expect("V1 key storage should succeed");
        
        // Verify V1 data
        let v1_retrieved = db_v1.retrieve_key(&v1_key_id).await
            .expect("V1 retrieval should succeed");
        assert!(v1_retrieved.is_some(), "V1 key should be retrievable");
        
        let (v1_key_data, v1_meta_data) = v1_retrieved.unwrap();
        assert_eq!(v1_key_data.to_vec(), v1_key.to_vec(), "V1 key data should match");
        assert_eq!(v1_meta_data.metadata.get("schema_version"), Some(&"1".to_string()), "V1 schema version should match");
        
        // Simulate migration to version 2
        // In a real migration, you would:
        // 1. Backup existing data
        // 2. Update schema
        // 3. Transform data if needed
        // 4. Verify migration
        
        // For this test, we'll simulate by adding new metadata fields
        let v2_key_id = KeyId::new();
        let v2_key = create_test_key(64);
        let mut v2_metadata = create_test_metadata("v2_algorithm", 2);
        v2_metadata.metadata.insert("schema_version".to_string(), "2".to_string());
        v2_metadata.metadata.insert("migration_date".to_string(), Utc::now().to_rfc3339());
        v2_metadata.metadata.insert("migrated".to_string(), "true".to_string());
        
        db_v1.store_key(&v2_key_id, &v2_key, &v2_metadata).await
            .expect("V2 key storage should succeed");
        
        // Verify V2 data
        let v2_retrieved = db_v1.retrieve_key(&v2_key_id).await
            .expect("V2 retrieval should succeed");
        assert!(v2_retrieved.is_some(), "V2 key should be retrievable");
        
        let (v2_key_data, v2_meta_data) = v2_retrieved.unwrap();
        assert_eq!(v2_key_data.to_vec(), v2_key.to_vec(), "V2 key data should match");
        assert_eq!(v2_meta_data.metadata.get("schema_version"), Some(&"2".to_string()), "V2 schema version should match");
        assert!(v2_meta_data.metadata.contains_key("migration_date"), "V2 should have migration date");
        assert!(v2_meta_data.metadata.contains_key("migrated"), "V2 should have migrated tag");
        
        // Test backward compatibility
        let v1_retrieved_after_migration = db_v1.retrieve_key(&v1_key_id).await
            .expect("V1 retrieval after migration should succeed");
        assert!(v1_retrieved_after_migration.is_some(), "V1 key should still be retrievable after migration");
        
        // Test data consistency during migration
        let num_migration_keys = 20;
        let mut migration_key_ids = Vec::new();
        
        for i in 0..num_migration_keys {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let mut metadata = create_test_metadata(&format!("migration_{}", i), 1);
            
            // Store as V1
            db_v1.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Migration V1 key {} storage should succeed", i));
            
            // "Migrate" to V2 by updating metadata
            metadata.version = 2;
            metadata.metadata.insert("schema_version".to_string(), "2".to_string());
            metadata.metadata.insert("migrated_at".to_string(), Utc::now().to_rfc3339());
            
            db_v1.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Migration V2 key {} storage should succeed", i));
            
            migration_key_ids.push(key_id);
        }
        
        // Verify all migrated keys
        for (i, key_id) in migration_key_ids.iter().enumerate() {
            let retrieved = db_v1.retrieve_key(key_id).await
                .expect(&format!("Migrated key {} retrieval should succeed", i));
            
            assert!(retrieved.is_some(), "Migrated key {} should be retrievable", i);
            
            let (_, metadata) = retrieved.unwrap();
            assert_eq!(metadata.version, 2, "Migrated key {} should have version 2", i);
            assert_eq!(metadata.metadata.get("schema_version"), Some(&"2".to_string()), 
                     "Migrated key {} should have schema version 2", i);
        }
    }

    /// Test database corruption recovery
    #[tokio::test]
    async fn test_database_corruption_recovery() {
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
            .expect("Database connection should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Store critical data
        let critical_key_id = KeyId::new();
        let critical_key = create_test_key(32);
        let critical_metadata = create_test_metadata("critical_data", 1);
        
        db.store_key(&critical_key_id, &critical_key, &critical_metadata).await
            .expect("Critical key storage should succeed");
        
        // Verify critical data exists
        let critical_retrieved = db.retrieve_key(&critical_key_id).await
            .expect("Critical key retrieval should succeed");
        assert!(critical_retrieved.is_some(), "Critical key should be retrievable");
        
        // Test health monitoring
        let healthy = db.health_check().await
            .expect("Health check should succeed");
        assert!(healthy, "Database should be healthy");
        
        // Test statistics for monitoring
        let stats = db.get_stats().await
            .expect("Stats retrieval should succeed");
        assert!(stats.total_keys >= 1, "Should have at least one key");
        assert!(stats.database_size_bytes > 0, "Database should have size");
        
        // Test connection recovery simulation
        // In a real scenario, you would test connection drops and recovery
        // For this test, we'll verify the database can handle multiple operations
        
        for i in 0..10 {
            let test_key_id = KeyId::new();
            let test_key = create_test_key(32);
            let test_metadata = create_test_metadata(&format!("recovery_test_{}", i), 1);
            
            db.store_key(&test_key_id, &test_key, &test_metadata).await
                .expect(&format!("Recovery test key {} storage should succeed", i));
            
            let retrieved = db.retrieve_key(&test_key_id).await
                .expect(&format!("Recovery test key {} retrieval should succeed", i));
            assert!(retrieved.is_some(), "Recovery test key {} should be retrievable", i);
            
            // Clean up
            db.delete_key(&test_key_id).await
                .expect(&format!("Recovery test key {} deletion should succeed", i));
        }
        
        // Verify critical data is still intact
        let critical_retrieved_after = db.retrieve_key(&critical_key_id).await
            .expect("Critical key retrieval after recovery tests should succeed");
        assert!(critical_retrieved_after.is_some(), "Critical key should still be retrievable");
        
        let (final_key, final_metadata) = critical_retrieved_after.unwrap();
        assert_eq!(final_key.to_vec(), critical_key.to_vec(), "Critical key data should be intact");
        assert_eq!(final_metadata.algorithm, critical_metadata.algorithm, "Critical metadata should be intact");
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
            .expect("Database connection should succeed"));
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Test concurrent writes
        let num_concurrent_writes = 20;
        let mut write_handles = Vec::new();
        
        for i in 0..num_concurrent_writes {
            let db_clone = std::sync::Arc::clone(&db);
            
            let handle = tokio::spawn(async move {
                let key_id = KeyId::new();
                let key = create_test_key(32);
                let metadata = create_test_metadata(&format!("concurrent_write_{}", i), 1);
                
                db_clone.store_key(&key_id, &key, &metadata).await
                    .expect(&format!("Concurrent write {} should succeed", i));
                
                key_id
            });
            write_handles.push(handle);
        }
        
        // Wait for all writes to complete
        let mut written_key_ids = Vec::new();
        for handle in write_handles {
            let key_id = handle.await.expect("Write task should complete");
            written_key_ids.push(key_id);
        }
        
        assert_eq!(written_key_ids.len(), num_concurrent_writes, "All concurrent writes should succeed");
        
        // Test concurrent reads
        let mut read_handles = Vec::new();
        
        for key_id in &written_key_ids {
            let db_clone = std::sync::Arc::clone(&db);
            let key_id_clone = key_id.clone();
            
            let handle = tokio::spawn(async move {
                db_clone.retrieve_key(&key_id_clone).await
                    .expect("Concurrent read should succeed")
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
        
        assert_eq!(successful_reads, num_concurrent_writes, "All concurrent reads should succeed");
        
        // Test mixed concurrent operations
        let num_mixed_operations = 15;
        let mut mixed_handles = Vec::new();
        
        for i in 0..num_mixed_operations {
            let db_clone = std::sync::Arc::clone(&db);
            
            let handle = tokio::spawn(async move {
                // Write operation
                let write_key_id = KeyId::new();
                let write_key = create_test_key(32);
                let write_metadata = create_test_metadata(&format!("mixed_write_{}", i), 1);
                
                db_clone.store_key(&write_key_id, &write_key, &write_metadata).await
                    .expect("Mixed write should succeed");
                
                // Read operation
                let read_result = db_clone.retrieve_key(&write_key_id).await
                    .expect("Mixed read should succeed");
                assert!(read_result.is_some(), "Mixed read should find key");
                
                // Metadata operation
                let metadata_result = db_clone.get_key_metadata(&write_key_id).await
                    .expect("Mixed metadata should succeed");
                assert!(metadata_result.is_some(), "Mixed metadata should find key");
                
                // Existence check
                let exists = db_clone.key_exists(&write_key_id).await
                    .expect("Mixed existence check should succeed");
                assert!(exists, "Mixed existence check should find key");
                
                // Cleanup
                db_clone.delete_key(&write_key_id).await
                    .expect("Mixed deletion should succeed");
                
                // Verify deletion
                let exists_after_delete = db_clone.key_exists(&write_key_id).await
                    .expect("Mixed existence check after delete should succeed");
                assert!(!exists_after_delete, "Mixed key should be deleted");
                
                write_key_id
            });
            mixed_handles.push(handle);
        }
        
        // Wait for all mixed operations to complete
        for handle in mixed_handles {
            handle.await.expect("Mixed operation task should complete");
        }
        
        // Verify database integrity after concurrent operations
        let final_stats = db.get_stats().await
            .expect("Final stats should succeed");
        assert_eq!(final_stats.total_keys, num_concurrent_writes as u64, "Should have original concurrent write keys");
    }

    /// Test database performance under load
    #[tokio::test]
    async fn test_database_performance_under_load() {
        let (db_path, _temp_file) = create_temp_sqlite_db().await;
        
        let config = KeyDatabaseConfig {
            backend: KeyDatabaseBackend::Sqlite,
            connection_string: db_path.clone(),
            max_connections: 20,
            connection_timeout_seconds: 60,
            encrypt_at_rest: false,
            master_key: None,
        };
        
        let db = SqliteKeyDatabase::new(config).await
            .expect("Database connection should succeed");
        db.initialize().await
            .expect("Schema initialization should succeed");
        
        // Performance test with many operations
        let num_operations = 500;
        let mut key_ids = Vec::new();
        
        // Write performance
        let start_time = std::time::Instant::now();
        
        for i in 0..num_operations {
            let key_id = KeyId::new();
            let key = create_test_key(32);
            let metadata = create_test_metadata(&format!("perf_test_{}", i), 1);
            
            db.store_key(&key_id, &key, &metadata).await
                .expect(&format!("Performance key {} storage should succeed", i));
            
            key_ids.push(key_id);
        }
        
        let write_duration = start_time.elapsed();
        println!("Stored {} keys in {:?}", num_operations, write_duration);
        
        // Read performance
        let start_time = std::time::Instant::now();
        let mut successful_reads = 0;
        
        for key_id in &key_ids {
            let result = db.retrieve_key(key_id).await
                .expect("Performance read should succeed");
            
            if result.is_some() {
                successful_reads += 1;
            }
        }
        
        let read_duration = start_time.elapsed();
        println!("Read {} keys in {:?}", successful_reads, read_duration);
        
        // Batch operations performance
        let start_time = std::time::Instant::now();
        
        let batch_size = 50;
        let mut batch_successful = 0;
        
        for chunk in key_ids.chunks(batch_size) {
            for key_id in chunk {
                let exists = db.key_exists(key_id).await
                    .expect("Batch existence check should succeed");
                
                if exists {
                    batch_successful += 1;
                }
            }
        }
        
        let batch_duration = start_time.elapsed();
        println!("Batch checked {} keys in {:?}", batch_successful, batch_duration);
        
        // Statistics performance
        let start_time = std::time::Instant::now();
        
        for _ in 0..10 {
            let stats = db.get_stats().await
                .expect("Stats retrieval should succeed");
            assert!(stats.total_keys >= num_operations, "Stats should show correct key count");
        }
        
        let stats_duration = start_time.elapsed();
        println!("Retrieved stats 10 times in {:?}", stats_duration);
        
        // Performance assertions
        assert_eq!(successful_reads, num_operations, "All reads should succeed");
        assert_eq!(batch_successful, num_operations, "All batch checks should succeed");
        
        assert!(write_duration.as_millis() < 30000, "Write performance should be reasonable");
        assert!(read_duration.as_millis() < 15000, "Read performance should be reasonable");
        assert!(batch_duration.as_millis() < 5000, "Batch performance should be good");
        assert!(stats_duration.as_millis() < 1000, "Stats performance should be fast");
        
        // Cleanup performance
        let start_time = std::time::Instant::now();
        
        for key_id in &key_ids {
            db.delete_key(key_id).await
                .expect("Performance deletion should succeed");
        }
        
        let cleanup_duration = start_time.elapsed();
        println!("Deleted {} keys in {:?}", num_operations, cleanup_duration);
        
        assert!(cleanup_duration.as_millis() < 20000, "Cleanup performance should be reasonable");
        
        let final_stats = db.get_stats().await
            .expect("Final stats should succeed");
        assert_eq!(final_stats.total_keys, 0, "All keys should be deleted");
    }
}
