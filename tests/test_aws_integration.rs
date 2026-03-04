//! AWS Integration Tests for Fortress
//! 
//! This test suite validates AWS S3, CloudHSM, and RDS integration with Fortress.
//! Tests are designed to run against actual AWS services using test credentials.

#[cfg(test)]
mod aws_integration_tests {
    use fortress_core::{
        storage::{S3Storage, StorageBackend, InMemoryStorage},
        error::{FortressError, Result},
        config::Config,
        encryption::{EncryptionAlgorithm, EncryptionProfile},
    };
    use tokio::time::{timeout, Duration};
    use std::env;
    use serde_json::json;

    /// Test configuration for AWS integration
    struct AwsTestConfig {
        bucket_name: String,
        region: String,
        test_prefix: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    }

    impl AwsTestConfig {
        /// Load configuration from environment variables
        fn from_env() -> Option<Self> {
            Some(Self {
                bucket_name: env::var("FORTRESS_TEST_S3_BUCKET").ok()?,
                region: env::var("FORTRESS_TEST_AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
                test_prefix: format!("fortress-test-{}", uuid::Uuid::new_v4()),
                access_key_id: env::var("FORTRESS_TEST_AWS_ACCESS_KEY_ID").ok()?,
                secret_access_key: env::var("FORTRESS_TEST_AWS_SECRET_ACCESS_KEY").ok()?,
                session_token: env::var("FORTRESS_TEST_AWS_SESSION_TOKEN").ok(),
            })
        }

        /// Set environment variables for AWS SDK
        fn set_env_vars(&self) {
            env::set_var("AWS_ACCESS_KEY_ID", &self.access_key_id);
            env::set_var("AWS_SECRET_ACCESS_KEY", &self.secret_access_key);
            if let Some(ref token) = self.session_token {
                env::set_var("AWS_SESSION_TOKEN", token);
            }
            env::set_var("AWS_DEFAULT_REGION", &self.region);
        }

        /// Clean up environment variables
        fn cleanup_env_vars(&self) {
            env::remove_var("AWS_ACCESS_KEY_ID");
            env::remove_var("AWS_SECRET_ACCESS_KEY");
            env::remove_var("AWS_SESSION_TOKEN");
            env::remove_var("AWS_DEFAULT_REGION");
        }
    }

    /// Test data for integration tests
    struct TestData {
        key: String,
        value: Vec<u8>,
        large_value: Vec<u8>,
    }

    impl TestData {
        fn new() -> Self {
            Self {
                key: format!("test-key-{}", uuid::Uuid::new_v4()),
                value: b"Hello, Fortress AWS Integration!".to_vec(),
                large_value: vec![0u8; 10 * 1024 * 1024], // 10MB test data
            }
        }
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_basic_operations() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 integration test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        // Create S3 storage backend
        let storage = match S3Storage::new(
            config.bucket_name.clone(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await {
            Ok(storage) => storage,
            Err(e) => {
                config.cleanup_env_vars();
                panic!("Failed to create S3 storage: {}", e);
            }
        };

        let test_data = TestData::new();

        // Test put operation
        storage.put(&test_data.key, &test_data.value).await
            .expect("Failed to put data to S3");

        // Test get operation
        let retrieved = storage.get(&test_data.key).await
            .expect("Failed to get data from S3");
        assert_eq!(retrieved, Some(test_data.value));

        // Test exists operation
        let exists = storage.exists(&test_data.key).await
            .expect("Failed to check existence in S3");
        assert!(exists);

        // Test delete operation
        storage.delete(&test_data.key).await
            .expect("Failed to delete data from S3");

        // Verify deletion
        let exists_after_delete = storage.exists(&test_data.key).await
            .expect("Failed to check existence after delete");
        assert!(!exists_after_delete);

        config.cleanup_env_vars();
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_large_file_operations() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 large file test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        let storage = S3Storage::new(
            config.bucket_name.clone(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await.expect("Failed to create S3 storage");

        let test_data = TestData::new();
        let large_key = format!("large-{}", test_data.key);

        // Test large file upload
        let start = std::time::Instant::now();
        storage.put(&large_key, &test_data.large_value).await
            .expect("Failed to upload large file to S3");
        let upload_time = start.elapsed();

        // Test large file download
        let start = std::time::Instant::now();
        let retrieved = storage.get(&large_key).await
            .expect("Failed to download large file from S3");
        let download_time = start.elapsed();

        assert_eq!(retrieved, Some(test_data.large_value));

        println!("Large file (10MB) upload time: {:?}", upload_time);
        println!("Large file (10MB) download time: {:?}", download_time);

        // Performance assertions (adjust based on your requirements)
        assert!(upload_time.as_secs() < 30, "Upload took too long: {:?}", upload_time);
        assert!(download_time.as_secs() < 30, "Download took too long: {:?}", download_time);

        // Cleanup
        storage.delete(&large_key).await.expect("Failed to delete large file");

        config.cleanup_env_vars();
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_health_check() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 health check test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        let storage = S3Storage::new(
            config.bucket_name.clone(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await.expect("Failed to create S3 storage");

        // Test health check
        let health_status = storage.health_check().await
            .expect("S3 health check failed");

        assert!(health_status.healthy, "S3 should be healthy");
        assert!(health_status.response_time_ms < 5000, "Health check response time too high: {}ms", 
                health_status.response_time_ms);

        println!("S3 health check passed in {}ms", health_status.response_time_ms);

        config.cleanup_env_vars();
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_list_operations() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 list operations test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        let storage = S3Storage::new(
            config.bucket_name.clone(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await.expect("Failed to create S3 storage");

        // Create test data with different prefixes
        let prefix1 = "folder1/";
        let prefix2 = "folder2/";

        let keys = vec![
            format!("{}file1.txt", prefix1),
            format!("{}file2.txt", prefix1),
            format!("{}file3.txt", prefix2),
            format!("{}file4.txt", prefix2),
        ];

        // Upload test files
        for key in &keys {
            storage.put(key, format!("content of {}", key).as_bytes()).await
                .expect("Failed to upload test file");
        }

        // Test listing with prefix1
        let listed_keys = storage.list_prefix(prefix1).await
            .expect("Failed to list keys with prefix1");
        assert_eq!(listed_keys.len(), 2);
        assert!(listed_keys.iter().any(|k| k.contains("file1.txt")));
        assert!(listed_keys.iter().any(|k| k.contains("file2.txt")));

        // Test listing with prefix2
        let listed_keys = storage.list_prefix(prefix2).await
            .expect("Failed to list keys with prefix2");
        assert_eq!(listed_keys.len(), 2);
        assert!(listed_keys.iter().any(|k| k.contains("file3.txt")));
        assert!(listed_keys.iter().any(|k| k.contains("file4.txt")));

        // Cleanup test files
        for key in &keys {
            storage.delete(key).await.expect("Failed to delete test file");
        }

        config.cleanup_env_vars();
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_concurrent_operations() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 concurrent operations test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        let storage = std::sync::Arc::new(
            S3Storage::new(
                config.bucket_name.clone(),
                config.region.clone(),
                Some(config.test_prefix.clone()),
            ).await.expect("Failed to create S3 storage")
        );

        let num_operations = 10;
        let mut handles = Vec::new();

        // Spawn concurrent write operations
        for i in 0..num_operations {
            let storage_clone = storage.clone();
            let key = format!("concurrent-{}", i);
            let value = format!("concurrent-value-{}", i).into_bytes();

            let handle = tokio::spawn(async move {
                storage_clone.put(&key, &value).await
                    .expect("Failed to put data in concurrent operation");
            });
            handles.push(handle);
        }

        // Wait for all writes to complete
        for handle in handles {
            handle.await.expect("Failed to join write operation");
        }

        // Verify all data was written correctly
        for i in 0..num_operations {
            let key = format!("concurrent-{}", i);
            let expected_value = format!("concurrent-value-{}", i).into_bytes();
            
            let retrieved = storage.get(&key).await
                .expect("Failed to get data in concurrent test");
            assert_eq!(retrieved, Some(expected_value));
        }

        // Cleanup
        for i in 0..num_operations {
            let key = format!("concurrent-{}", i);
            storage.delete(&key).await.expect("Failed to delete data in cleanup");
        }

        config.cleanup_env_vars();
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_error_handling() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 error handling test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        // Test with invalid bucket name
        let invalid_storage_result = S3Storage::new(
            "non-existent-bucket-12345".to_string(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await;

        assert!(invalid_storage_result.is_err(), "Should fail with invalid bucket name");

        // Test with valid storage but invalid operations
        let storage = S3Storage::new(
            config.bucket_name.clone(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await.expect("Failed to create valid S3 storage");

        // Test getting non-existent key
        let non_existent = storage.get("non-existent-key").await
            .expect("Failed to check non-existent key");
        assert_eq!(non_existent, None);

        // Test deleting non-existent key (should not error)
        storage.delete("non-existent-key").await
            .expect("Delete of non-existent key should not error");

        config.cleanup_env_vars();
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_metadata() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 metadata test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        let storage = S3Storage::new(
            config.bucket_name.clone(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await.expect("Failed to create S3 storage");

        let metadata = storage.metadata();

        assert_eq!(metadata.backend_type, "s3");
        assert!(!metadata.version.is_empty());
        assert!(!metadata.supports_transactions); // S3 doesn't support transactions
        assert!(metadata.supports_encryption_at_rest); // S3 supports server-side encryption
        assert!(metadata.max_object_size.is_some());
        assert!(metadata.max_object_size.unwrap() > 0);

        println!("S3 Backend Metadata:");
        println!("  Type: {}", metadata.backend_type);
        println!("  Version: {}", metadata.version);
        println!("  Max Object Size: {} bytes", metadata.max_object_size.unwrap());
        println!("  Supports Encryption at Rest: {}", metadata.supports_encryption_at_rest);

        config.cleanup_env_vars();
    }

    /// Integration test that combines S3 storage with Fortress encryption
    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_with_fortress_encryption() {
        let config = match AwsTestConfig::from_env() {
            Some(cfg) => cfg,
            None => {
                println!("Skipping S3 with Fortress encryption test - missing environment variables");
                return;
            }
        };

        config.set_env_vars();

        // Create S3 storage backend
        let storage = S3Storage::new(
            config.bucket_name.clone(),
            config.region.clone(),
            Some(config.test_prefix.clone()),
        ).await.expect("Failed to create S3 storage");

        // Create Fortress encryption profile
        let encryption_profile = EncryptionProfile::new(
            EncryptionAlgorithm::Aegis256,
            "test-password-123".to_string(),
        ).expect("Failed to create encryption profile");

        // Test data
        let original_data = json!({
            "user_id": 12345,
            "username": "test_user",
            "email": "test@example.com",
            "sensitive_data": "this should be encrypted"
        });

        let serialized_data = serde_json::to_vec(&original_data)
            .expect("Failed to serialize test data");

        let test_key = format!("encrypted-{}", uuid::Uuid::new_v4());

        // Encrypt and store data
        let encrypted_data = encryption_profile.encrypt(&serialized_data)
            .expect("Failed to encrypt data");
        
        storage.put(&test_key, &encrypted_data).await
            .expect("Failed to store encrypted data");

        // Retrieve and decrypt data
        let retrieved_encrypted = storage.get(&test_key).await
            .expect("Failed to retrieve encrypted data");
        
        let decrypted_data = encryption_profile.decrypt(
            &retrieved_encrypted.expect("No data found")
        ).expect("Failed to decrypt data");

        let retrieved_json: serde_json::Value = serde_json::from_slice(&decrypted_data)
            .expect("Failed to deserialize decrypted data");

        assert_eq!(original_data, retrieved_json);

        // Cleanup
        storage.delete(&test_key).await.expect("Failed to cleanup test data");

        config.cleanup_env_vars();
    }
}
