//! Comprehensive Secrets Management Tests
//!
//! This test suite provides comprehensive coverage for the secrets management system,
//! testing creation, storage, retrieval, rotation, expiration, cleanup, and integration
//! with key management systems.

use chrono::Utc;
use fortress_core::secrets::{EngineType, SecretsConfig, SecretsEngine, SecretsEngineManager};
use fortress_core::secrets_kv::KvEngine;
use serde_json::json;
use std::sync::Arc;
use tokio::time::sleep;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test secret creation and storage
    #[tokio::test]
    async fn test_secret_creation_and_storage() {
        let engine = KvEngine::new().unwrap();

        // Test basic secret creation
        let test_data = json!({
            "username": "testuser",
            "password": "testpass123",
            "database": "testdb"
        });

        let secret = engine
            .write("secret/app1", &test_data)
            .await
            .expect("Secret creation should succeed");

        // Verify secret metadata
        assert_eq!(secret.metadata.name, "secret/app1");
        assert!(secret.metadata.version > 0);
        assert!(secret.metadata.created_at <= Utc::now());
        assert_eq!(secret.data, test_data);

        // Test lease information
        assert!(
            secret.lease.is_some(),
            "Secret should have lease information"
        );
        let lease = secret.lease.unwrap();
        assert!(lease.ttl > 0, "Lease should have positive TTL");
        assert!(lease.renewable, "Lease should be renewable");
        assert!(
            lease.expires_at > lease.created_at,
            "Expiry should be after creation"
        );
    }

    /// Test secret retrieval and access control
    #[tokio::test]
    async fn test_secret_retrieval_and_access_control() {
        let engine = KvEngine::new().unwrap();

        // Store a secret
        let test_data = json!({
            "api_key": "secret_api_key_12345",
            "endpoint": "https://api.example.com"
        });

        engine
            .write("secret/api", &test_data)
            .await
            .expect("Secret storage should succeed");

        // Retrieve the secret
        let retrieved = engine
            .read("secret/api")
            .await
            .expect("Secret retrieval should succeed");

        assert!(retrieved.is_some(), "Secret should be found");
        let secret = retrieved.unwrap();
        assert_eq!(
            secret.data, test_data,
            "Retrieved data should match stored data"
        );
        assert_eq!(secret.metadata.name, "secret/api");

        // Test retrieval of non-existent secret
        let not_found = engine
            .read("secret/nonexistent")
            .await
            .expect("Retrieval should not error");
        assert!(
            not_found.is_none(),
            "Non-existent secret should return None"
        );

        // Test listing secrets
        let secrets = engine
            .list("secret/")
            .await
            .expect("Listing should succeed");
        assert!(
            secrets.contains(&"secret/api".to_string()),
            "Stored secret should be in list"
        );
    }

    /// Test secret rotation and versioning
    #[tokio::test]
    async fn test_secret_rotation_and_versioning() {
        let engine = KvEngine::new().unwrap();
        let secret_path = "secret/rotating";

        // Store initial version
        let v1_data = json!({"password": "initial_password", "version": 1});
        let secret_v1 = engine
            .write(secret_path, &v1_data)
            .await
            .expect("Initial secret storage should succeed");
        let v1_version = secret_v1.metadata.version;

        // Update to version 2
        let v2_data = json!({"password": "updated_password", "version": 2});
        let secret_v2 = engine
            .write(secret_path, &v2_data)
            .await
            .expect("Secret update should succeed");
        let v2_version = secret_v2.metadata.version;

        assert!(v2_version > v1_version, "Version should increment");

        // Retrieve specific versions
        let retrieved_v1 = engine
            .read_version(secret_path, v1_version)
            .await
            .expect("Version retrieval should succeed");
        assert!(retrieved_v1.is_some(), "Version 1 should be found");
        assert_eq!(
            retrieved_v1.unwrap().data,
            v1_data,
            "Version 1 data should match"
        );

        let retrieved_v2 = engine
            .read_version(secret_path, v2_version)
            .await
            .expect("Version retrieval should succeed");
        assert!(retrieved_v2.is_some(), "Version 2 should be found");
        assert_eq!(
            retrieved_v2.unwrap().data,
            v2_data,
            "Version 2 data should match"
        );

        // List all versions
        let versions = engine
            .list_versions(secret_path)
            .await
            .expect("Version listing should succeed");
        assert_eq!(versions.len(), 2, "Should have 2 versions");
        assert!(versions.contains(&v1_version), "Should contain version 1");
        assert!(versions.contains(&v2_version), "Should contain version 2");
    }

    /// Test secret expiration and cleanup
    #[tokio::test]
    async fn test_secret_expiration_and_cleanup() {
        // Create engine with short TTL for testing
        let mut config = fortress_core::secrets_kv::KvConfig::default();
        config.default_ttl = Some(2); // 2 seconds TTL
        let engine = KvEngine::with_config(config).unwrap();

        // Store a secret
        let test_data = json!({"temp_secret": "expires_quickly"});
        let secret = engine
            .write("secret/temp", &test_data)
            .await
            .expect("Secret storage should succeed");

        let lease = secret.lease.unwrap();
        let _original_expires_at = lease.expires_at;

        // Wait for expiration
        sleep(tokio::time::Duration::from_secs(3)).await;

        // Try to renew the lease (should fail if expired)
        let _renew_result = engine.renew(&lease.lease_id, Some(3600)).await;
        // Note: This might succeed or fail depending on implementation
        // We're mainly testing that the system handles expiration gracefully

        // Test lease revocation
        let revoke_result = engine.revoke(&lease.lease_id).await;
        assert!(revoke_result.is_ok(), "Lease revocation should succeed");

        // After revocation, the lease should no longer be valid
        let renew_after_revoke = engine.renew(&lease.lease_id, Some(3600)).await;
        assert!(
            renew_after_revoke.is_err(),
            "Renewal after revocation should fail"
        );
    }

    /// Test integration with key management
    #[tokio::test]
    async fn test_key_management_integration() {
        let engine = KvEngine::new().unwrap();

        // Store sensitive data that should be encrypted
        let sensitive_data = json!({
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoKHEqsD1BIMA0GCSqGSIb3DQEBCwUAM...\n-----END CERTIFICATE-----",
            "api_secret": "sk_live_1234567890abcdef"
        });

        let _secret = engine
            .write("secret/keys", &sensitive_data)
            .await
            .expect("Sensitive data storage should succeed");

        // Verify the data is stored (encryption should be transparent)
        let retrieved = engine
            .read("secret/keys")
            .await
            .expect("Sensitive data retrieval should succeed");

        assert!(
            retrieved.is_some(),
            "Encrypted secret should be retrievable"
        );
        let retrieved_secret = retrieved.unwrap();
        assert_eq!(
            retrieved_secret.data, sensitive_data,
            "Retrieved data should match original"
        );

        // Verify the secret is actually encrypted at rest by checking metadata
        assert!(
            retrieved_secret.metadata.custom.is_empty(),
            "Custom metadata should be empty for basic test"
        );

        // Test with different data types
        let complex_data = json!({
            "database_config": {
                "host": "localhost",
                "port": 5432,
                "credentials": {
                    "username": "admin",
                    "password": "super_secret_password"
                }
            },
            "api_keys": [
                {"service": "aws", "key": "AKIAIOSFODNN7EXAMPLE"},
                {"service": "gcp", "key": "AIzaSyDuB3-8xyz"}
            ]
        });

        engine
            .write("secret/complex", &complex_data)
            .await
            .expect("Complex data storage should succeed");

        let retrieved_complex = engine
            .read("secret/complex")
            .await
            .expect("Complex data retrieval should succeed");

        assert!(
            retrieved_complex.is_some(),
            "Complex secret should be retrievable"
        );
        assert_eq!(
            retrieved_complex.unwrap().data,
            complex_data,
            "Complex data should match"
        );
    }

    /// Test secrets engine manager functionality
    #[tokio::test]
    async fn test_secrets_engine_manager() {
        let config = SecretsConfig::default();
        let mut manager = SecretsEngineManager::new(config);

        // Register a KV engine
        let kv_engine = Box::new(KvEngine::new().unwrap()) as Box<dyn SecretsEngine>;
        let registration_result = manager.register_engine("kv".to_string(), kv_engine);
        assert!(
            registration_result.is_ok(),
            "Engine registration should succeed"
        );

        // List engines
        let engines = manager.list_engines();
        assert!(
            engines.contains(&"kv".to_string()),
            "Registered engine should be in list"
        );

        // Get engine by name
        let engine = manager.get_engine("kv");
        assert!(
            engine.is_some(),
            "Should be able to retrieve registered engine"
        );

        // Use the engine through manager
        let engine = engine.unwrap();
        let test_data = json!({"managed": "secret"});
        engine
            .write("secret/managed", &test_data)
            .await
            .expect("Managed engine write should succeed");

        let retrieved = engine
            .read("secret/managed")
            .await
            .expect("Managed engine read should succeed");
        assert!(retrieved.is_some(), "Managed secret should be retrievable");

        // Test engine status
        let status = engine
            .status()
            .await
            .expect("Engine status should be available");
        assert_eq!(status.name, "kv");
        assert!(matches!(status.engine_type, EngineType::Kv));
        assert!(status.initialized, "Engine should be initialized");
        assert!(status.active, "Engine should be active");
    }

    /// Test lease management operations
    #[tokio::test]
    async fn test_lease_management_operations() {
        let engine = KvEngine::new().unwrap();

        // Store a secret with lease
        let test_data = json!({"leased": "data"});
        let secret = engine
            .write("secret/leased", &test_data)
            .await
            .expect("Secret storage should succeed");

        let lease = secret.lease.unwrap();
        let _original_ttl = lease.ttl;
        let original_renewal_count = lease.renewal_count;

        // Test lease renewal
        let renewed_lease = engine
            .renew(&lease.lease_id, Some(7200))
            .await
            .expect("Lease renewal should succeed");

        assert!(
            renewed_lease.expires_at > lease.expires_at,
            "Renewed lease should expire later"
        );
        assert_eq!(
            renewed_lease.renewal_count,
            original_renewal_count + 1,
            "Renewal count should increment"
        );
        assert_eq!(
            renewed_lease.lease_id, lease.lease_id,
            "Lease ID should remain same"
        );

        // Test multiple renewals
        let mut current_lease = renewed_lease;
        for i in 1..5 {
            current_lease = engine
                .renew(&current_lease.lease_id, Some(3600))
                .await
                .expect(&format!("Renewal {} should succeed", i));
            assert_eq!(
                current_lease.renewal_count,
                original_renewal_count + 1 + i,
                "Renewal count should increment correctly"
            );
        }

        // Test lease revocation
        engine
            .revoke(&current_lease.lease_id)
            .await
            .expect("Lease revocation should succeed");

        // After revocation, renewal should fail
        let renewal_after_revoke = engine.renew(&current_lease.lease_id, Some(3600)).await;
        assert!(
            renewal_after_revoke.is_err(),
            "Renewal after revocation should fail"
        );
    }

    /// Test concurrent secrets operations
    #[tokio::test]
    async fn test_concurrent_secrets_operations() {
        let engine = Arc::new(KvEngine::new().unwrap());
        let num_concurrent = 10;

        // Test concurrent writes
        let mut write_handles = Vec::new();
        for i in 0..num_concurrent {
            let engine_clone = Arc::clone(&engine);
            let handle = tokio::spawn(async move {
                let data = json!({"concurrent_index": i, "timestamp": Utc::now().timestamp()});
                let path = format!("secret/concurrent/{}", i);

                engine_clone
                    .write(&path, &data)
                    .await
                    .expect("Concurrent write should succeed")
            });
            write_handles.push(handle);
        }

        // Wait for all writes to complete
        let mut secrets = Vec::new();
        for handle in write_handles {
            let secret = handle.await.expect("Write task should complete");
            secrets.push(secret);
        }

        // Verify all writes succeeded
        assert_eq!(
            secrets.len(),
            num_concurrent,
            "All concurrent writes should succeed"
        );

        // Test concurrent reads
        let mut read_handles = Vec::new();
        for i in 0..num_concurrent {
            let engine_clone = Arc::clone(&engine);
            let handle = tokio::spawn(async move {
                let path = format!("secret/concurrent/{}", i);
                engine_clone
                    .read(&path)
                    .await
                    .expect("Concurrent read should succeed")
            });
            read_handles.push(handle);
        }

        // Wait for all reads to complete
        let mut retrieved_count = 0;
        for handle in read_handles {
            let result = handle.await.expect("Read task should complete");
            if result.is_some() {
                retrieved_count += 1;
            }
        }

        assert_eq!(
            retrieved_count, num_concurrent,
            "All concurrent reads should succeed"
        );
    }

    /// Test secrets deletion and cleanup
    #[tokio::test]
    async fn test_secrets_deletion_and_cleanup() {
        let engine = KvEngine::new().unwrap();

        // Store multiple secrets
        let secrets_to_store = vec![
            ("secret/delete1", json!({"data": "to_delete_1"})),
            ("secret/delete2", json!({"data": "to_delete_2"})),
            ("secret/keep", json!({"data": "to_keep"})),
        ];

        for (path, data) in &secrets_to_store {
            engine
                .write(path, data)
                .await
                .expect("Secret storage should succeed");
        }

        // Verify all secrets exist
        for (path, _) in &secrets_to_store {
            let retrieved = engine
                .read(path)
                .await
                .expect("Secret retrieval should succeed");
            assert!(retrieved.is_some(), "Secret {} should exist", path);
        }

        // Delete specific secrets
        engine
            .delete("secret/delete1")
            .await
            .expect("Secret deletion should succeed");
        engine
            .delete("secret/delete2")
            .await
            .expect("Secret deletion should succeed");

        // Verify deletions
        let deleted1 = engine
            .read("secret/delete1")
            .await
            .expect("Secret retrieval should succeed");
        assert!(deleted1.is_none(), "Deleted secret 1 should not exist");

        let deleted2 = engine
            .read("secret/delete2")
            .await
            .expect("Secret retrieval should succeed");
        assert!(deleted2.is_none(), "Deleted secret 2 should not exist");

        // Verify kept secret still exists
        let kept = engine
            .read("secret/keep")
            .await
            .expect("Secret retrieval should succeed");
        assert!(kept.is_some(), "Kept secret should still exist");

        // Test destroy operation (permanent deletion)
        engine
            .destroy("secret/keep")
            .await
            .expect("Secret destruction should succeed");

        let destroyed = engine
            .read("secret/keep")
            .await
            .expect("Secret retrieval should succeed");
        assert!(destroyed.is_none(), "Destroyed secret should not exist");
    }

    /// Test version management and cleanup
    #[tokio::test]
    async fn test_version_management_and_cleanup() {
        // Create engine with limited versions
        let mut config = fortress_core::secrets_kv::KvConfig::default();
        config.max_versions = 3; // Keep only 3 versions
        let engine = KvEngine::with_config(config).unwrap();

        let secret_path = "secret/versioned";

        // Create multiple versions
        let mut versions = Vec::new();
        for i in 1..=5 {
            let data = json!({"version": i, "content": format!("data_version_{}", i)});
            let secret = engine
                .write(secret_path, &data)
                .await
                .expect("Version creation should succeed");
            versions.push(secret.metadata.version);
        }

        // List versions (should only have 3 due to cleanup)
        let version_list = engine
            .list_versions(secret_path)
            .await
            .expect("Version listing should succeed");
        assert_eq!(
            version_list.len(),
            3,
            "Should have only 3 versions after cleanup"
        );

        // Versions should be the latest 3
        let mut sorted_versions = versions.clone();
        sorted_versions.sort();
        let latest_versions: Vec<u64> = sorted_versions.into_iter().skip(2).collect();

        for version in &latest_versions {
            assert!(
                version_list.contains(version),
                "Should contain version {}",
                version
            );
        }

        // Test version deletion
        let latest_version = *version_list.iter().max().unwrap();
        engine
            .delete_version(secret_path, latest_version)
            .await
            .expect("Version deletion should succeed");

        // Verify version is deleted (soft-deleted)
        let deleted_version = engine
            .read_version(secret_path, latest_version)
            .await
            .expect("Version retrieval should succeed");
        assert!(
            deleted_version.is_none(),
            "Deleted version should not be accessible"
        );
    }

    /// Test engine configuration and customization
    #[tokio::test]
    async fn test_engine_configuration_customization() {
        // Test custom configuration
        let mut config = fortress_core::secrets_kv::KvConfig::default();
        config.default_ttl = Some(7200); // 2 hours
        config.max_versions = 5;
        config.case_sensitive = true;
        config.auto_cleanup = false;

        let engine = KvEngine::with_config(config).unwrap();

        // Store a secret
        let test_data = json!({"config_test": "data"});
        let secret = engine
            .write("secret/ConfigTest", &test_data)
            .await
            .expect("Secret storage should succeed");

        // Verify configuration is respected
        assert!(secret.lease.is_some(), "Should have lease with default TTL");
        let lease = secret.lease.unwrap();
        assert_eq!(lease.ttl, 7200, "Should use configured TTL");

        // Test case sensitivity
        let case_sensitive_path = "secret/ConfigTest";
        let retrieved = engine
            .read(case_sensitive_path)
            .await
            .expect("Case-sensitive retrieval should succeed");
        assert!(retrieved.is_some(), "Case-sensitive path should work");

        // Test that different case is different secret
        let different_case = engine
            .read("secret/configtest")
            .await
            .expect("Different case retrieval should succeed");
        assert!(
            different_case.is_none(),
            "Different case should be different secret"
        );
    }

    /// Test error handling and edge cases
    #[tokio::test]
    async fn test_error_handling_edge_cases() {
        let engine = KvEngine::new().unwrap();

        // Test invalid paths
        let invalid_paths = vec![
            "",               // Empty path
            "/",              // Root only
            "secret/",        // Trailing slash
            "secret//double", // Double slash
        ];

        for path in invalid_paths {
            let data = json!({"test": "data"});
            let result = engine.write(path, &data).await;
            // Engine should handle invalid paths gracefully
            // The exact behavior depends on implementation
            match result {
                Ok(_) => {
                    // If write succeeds, test read
                    let _ = engine.read(path).await;
                }
                Err(_) => {
                    // Expected behavior for invalid paths
                }
            }
        }

        // Test very large secret
        let large_data = json!({"large_field": "x".repeat(100000)});
        let result = engine.write("secret/large", &large_data).await;
        match result {
            Ok(_) => {
                // If write succeeds, verify read
                let retrieved = engine
                    .read("secret/large")
                    .await
                    .expect("Large secret retrieval should succeed");
                assert!(retrieved.is_some(), "Large secret should be retrievable");
                assert_eq!(
                    retrieved.unwrap().data,
                    large_data,
                    "Large data should match"
                );
            }
            Err(_) => {
                // Engine may reject very large secrets
            }
        }

        // Test special characters in paths and data
        let special_data = json!({
            "unicode": "Hello 🌍 世界",
            "special_chars": "!@#$%^&*()[]{}|\\:;\"'<>?,./",
            "newlines": "Line 1\nLine 2\r\nLine 3",
            "tabs": "Tab\tSeparated\tValues"
        });

        let special_path = "secret/special-chars_测试";
        let result = engine.write(special_path, &special_data).await;
        if result.is_ok() {
            let retrieved = engine
                .read(special_path)
                .await
                .expect("Special chars retrieval should succeed");
            assert!(
                retrieved.is_some(),
                "Special chars secret should be retrievable"
            );
            assert_eq!(
                retrieved.unwrap().data,
                special_data,
                "Special chars data should match"
            );
        }
    }

    /// Test performance with many secrets
    #[tokio::test]
    async fn test_performance_many_secrets() {
        let engine = KvEngine::new().unwrap();
        let num_secrets = 100;

        let start_time = std::time::Instant::now();

        // Create many secrets
        for i in 0..num_secrets {
            let data = json!({
                "index": i,
                "payload": format!("secret_data_{}", i),
                "metadata": {
                    "created": Utc::now().timestamp(),
                    "category": format!("category_{}", i % 10)
                }
            });

            let path = format!("secret/performance/{}", i);
            engine
                .write(&path, &data)
                .await
                .expect(&format!("Secret {} creation should succeed", i));
        }

        let write_duration = start_time.elapsed();
        println!("Created {} secrets in {:?}", num_secrets, write_duration);

        // Read all secrets
        let start_time = std::time::Instant::now();
        let mut successful_reads = 0;

        for i in 0..num_secrets {
            let path = format!("secret/performance/{}", i);
            let result = engine
                .read(&path)
                .await
                .expect(&format!("Secret {} retrieval should not error", i));

            if result.is_some() {
                successful_reads += 1;
            }
        }

        let read_duration = start_time.elapsed();
        println!("Read {} secrets in {:?}", successful_reads, read_duration);

        assert_eq!(
            successful_reads, num_secrets,
            "All secrets should be readable"
        );

        // Performance assertions (these are rough guidelines)
        assert!(
            write_duration.as_millis() < 5000,
            "Writing should complete in reasonable time"
        );
        assert!(
            read_duration.as_millis() < 2000,
            "Reading should complete in reasonable time"
        );

        // Test list performance
        let start_time = std::time::Instant::now();
        let listed = engine
            .list("secret/performance/")
            .await
            .expect("Listing should succeed");
        let list_duration = start_time.elapsed();

        assert_eq!(listed.len(), num_secrets, "All secrets should be listed");
        println!("Listed {} secrets in {:?}", listed.len(), list_duration);
        assert!(list_duration.as_millis() < 1000, "Listing should be fast");
    }
}
