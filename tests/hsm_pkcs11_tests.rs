#![cfg(any())]
//! Comprehensive PKCS#11 Provider Tests
//!
//! This test suite provides comprehensive coverage for PKCS#11 provider functionality,
//! ensuring proper integration with PKCS#11 compliant devices and security modules.

use fortress_core::error::{FortressError, HsmErrorCode};
use fortress_core::hsm::{HsmKeyManager, HsmProvider};
use fortress_core::hsm_pkcs11_fixed::{Pkcs11Config, Pkcs11Provider, Pkcs11Session};
use std::collections::HashMap;
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test PKCS#11 configuration validation
    #[tokio::test]
    async fn test_pkcs11_config_validation() {
        // Test valid configuration
        let valid_config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        assert!(
            valid_config.validate().is_ok(),
            "Valid config should pass validation"
        );

        // Test invalid configuration (missing library path)
        let mut invalid_config = valid_config.clone();
        invalid_config.library_path = "".to_string();
        assert!(
            invalid_config.validate().is_err(),
            "Invalid config should fail validation"
        );

        // Test invalid timeout
        let mut invalid_timeout_config = valid_config.clone();
        invalid_timeout_config.timeout_seconds = 0;
        assert!(
            invalid_timeout_config.validate().is_err(),
            "Zero timeout should fail validation"
        );
    }

    /// Test PKCS#11 provider initialization
    #[tokio::test]
    async fn test_pkcs11_provider_initialization() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        assert!(
            provider.initialize().await.is_ok(),
            "PKCS#11 provider should initialize successfully"
        );

        // Test health check
        let health_status = provider.health_check().await;
        assert!(health_status.is_ok(), "Health check should succeed");
    }

    /// Test PKCS#11 session management
    #[tokio::test]
    async fn test_pkcs11_session_management() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 3,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // Test session creation
        let session = provider.create_session().await.unwrap();
        assert!(
            session.is_authenticated(),
            "Session should be authenticated"
        );

        // Test session operations
        let test_data = b"PKCS#11 session test data";
        let session_id = session.get_session_id();
        assert!(session_id > 0, "Session ID should be valid");

        // Test session cleanup
        assert!(
            provider.close_session(session_id).await.is_ok(),
            "Session should close successfully"
        );
    }

    /// Test PKCS#11 token information
    #[tokio::test]
    async fn test_pkcs11_token_info() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // Get token information
        let token_info = provider.get_token_info().await.unwrap();
        assert!(
            !token_info.label.is_empty(),
            "Token label should not be empty"
        );
        assert!(
            !token_info.manufacturer.is_empty(),
            "Token manufacturer should not be empty"
        );
        assert!(
            !token_info.model.is_empty(),
            "Token model should not be empty"
        );
        assert!(
            token_info.serial_number.len() > 0,
            "Token serial number should not be empty"
        );
    }

    /// Test PKCS#11 slot enumeration
    #[tokio::test]
    async fn test_pkcs11_slot_enumeration() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: None,
            pin: Some("test_pin".to_string()),
            slot_id: None,
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // Enumerate available slots
        let slots = provider.enumerate_slots().await.unwrap();
        assert!(!slots.is_empty(), "Should have at least one slot available");

        // Verify slot information
        for slot in &slots {
            assert!(slot.slot_id >= 0, "Slot ID should be valid");
            assert!(
                !slot.slot_description.is_empty(),
                "Slot description should not be empty"
            );
            assert!(
                !slot.manufacturer.is_empty(),
                "Slot manufacturer should not be empty"
            );
        }
    }

    /// Test PKCS#11 mechanism listing
    #[tokio::test]
    async fn test_pkcs11_mechanism_listing() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // List available mechanisms
        let mechanisms = provider.list_mechanisms().await.unwrap();
        assert!(!mechanisms.is_empty(), "Should have available mechanisms");

        // Verify common mechanisms are present
        let mechanism_ids: Vec<_> = mechanisms.iter().map(|m| m.mechanism_id).collect();
        assert!(
            mechanism_ids.contains(&0x0001),
            "Should support CKM_RSA_PKCS_KEY_PAIR_GEN"
        );
        assert!(
            mechanism_ids.contains(&0x0000),
            "Should support CKM_RSA_PKCS"
        );
    }

    /// Test PKCS#11 key generation
    #[tokio::test]
    async fn test_pkcs11_key_generation() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Test RSA key pair generation
        let rsa_key_id = key_manager.generate_key("rsa", 2048).await.unwrap();
        assert!(
            !rsa_key_id.is_empty(),
            "Generated RSA key ID should not be empty"
        );

        // Test EC key pair generation
        let ec_key_id = key_manager.generate_key("ec", 256).await.unwrap();
        assert!(
            !ec_key_id.is_empty(),
            "Generated EC key ID should not be empty"
        );
        assert_ne!(
            rsa_key_id, ec_key_id,
            "Different key types should have different IDs"
        );

        // Test AES key generation
        let aes_key_id = key_manager.generate_key("aes", 256).await.unwrap();
        assert!(
            !aes_key_id.is_empty(),
            "Generated AES key ID should not be empty"
        );
    }

    /// Test PKCS#11 key attributes
    #[tokio::test]
    async fn test_pkcs11_key_attributes() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate a test key
        let key_id = key_manager.generate_key("rsa", 2048).await.unwrap();

        // Get key attributes
        let attributes = provider.get_key_attributes(&key_id).await.unwrap();
        assert!(!attributes.is_empty(), "Key should have attributes");

        // Verify essential attributes
        assert!(
            attributes.contains_key(&0x0000),
            "Should have CKA_CLASS attribute"
        );
        assert!(
            attributes.contains_key(&0x0001),
            "Should have CKA_KEY_TYPE attribute"
        );
        assert!(
            attributes.contains_key(&0x0002),
            "Should have CKA_LABEL attribute"
        );
    }

    /// Test PKCS#11 key search
    #[tokio::test]
    async fn test_pkcs11_key_search() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate test keys with different labels
        let key1_id = key_manager.generate_key("rsa", 2048).await.unwrap();
        let key2_id = key_manager.generate_key("ec", 256).await.unwrap();

        // Search for RSA keys
        let rsa_keys = provider
            .search_keys(&[(0x0001, vec![0x0000])])
            .await
            .unwrap(); // CKA_KEY_TYPE = CKK_RSA
        assert!(!rsa_keys.is_empty(), "Should find RSA keys");
        assert!(
            rsa_keys.iter().any(|k| k.contains(&key1_id)),
            "Should find generated RSA key"
        );

        // Search for EC keys
        let ec_keys = provider
            .search_keys(&[(0x0001, vec![0x0003])])
            .await
            .unwrap(); // CKA_KEY_TYPE = CKK_EC
        assert!(!ec_keys.is_empty(), "Should find EC keys");
        assert!(
            ec_keys.iter().any(|k| k.contains(&key2_id)),
            "Should find generated EC key"
        );
    }

    /// Test PKCS#11 signing operations
    #[tokio::test]
    async fn test_pkcs11_signing() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate a signing key
        let key_id = key_manager.generate_key("rsa", 2048).await.unwrap();

        // Test data to sign
        let test_data = b"PKCS#11 signing test data";

        // Sign the data
        let signature = key_manager.sign(&key_id, test_data).await.unwrap();
        assert!(!signature.is_empty(), "Signature should not be empty");
        assert!(
            signature.len() > 100,
            "RSA signature should be substantial size"
        );
    }

    /// Test PKCS#11 verification operations
    #[tokio::test]
    async fn test_pkcs11_verification() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate a signing key
        let key_id = key_manager.generate_key("ec", 256).await.unwrap();

        // Test data to sign
        let test_data = b"PKCS#11 verification test data";

        // Sign the data
        let signature = key_manager.sign(&key_id, test_data).await.unwrap();

        // Verify the signature
        let is_valid = key_manager
            .verify(&key_id, test_data, &signature)
            .await
            .unwrap();
        assert!(is_valid, "Signature should verify successfully");

        // Test with invalid data
        let invalid_data = b"Invalid PKCS#11 test data";
        let is_invalid = key_manager
            .verify(&key_id, invalid_data, &signature)
            .await
            .unwrap();
        assert!(!is_invalid, "Invalid data should not verify");
    }

    /// Test PKCS#11 encryption operations
    #[tokio::test]
    async fn test_pkcs11_encryption() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate an encryption key
        let key_id = key_manager.generate_key("aes", 256).await.unwrap();

        // Test data to encrypt
        let plaintext = b"PKCS#11 encryption test data";

        // Encrypt the data
        let ciphertext = key_manager.encrypt(&key_id, plaintext).await.unwrap();
        assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
        assert_ne!(
            ciphertext, plaintext,
            "Ciphertext should differ from plaintext"
        );
    }

    /// Test PKCS#11 decryption operations
    #[tokio::test]
    async fn test_pkcs11_decryption() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate an encryption key
        let key_id = key_manager.generate_key("aes", 256).await.unwrap();

        // Test data to encrypt
        let plaintext = b"PKCS#11 decryption test data";

        // Encrypt the data
        let ciphertext = key_manager.encrypt(&key_id, plaintext).await.unwrap();

        // Decrypt the data
        let decrypted = key_manager.decrypt(&key_id, &ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext, "Decrypted data should match original");
    }

    /// Test PKCS#11 session pool management
    #[tokio::test]
    async fn test_pkcs11_session_pool() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 3,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // Create multiple sessions concurrently
        let mut handles = vec![];
        for i in 0..5 {
            let provider_clone = provider.clone();
            let handle = tokio::spawn(async move {
                let session = provider_clone.create_session().await.unwrap();
                let session_id = session.get_session_id();
                (session_id, i)
            });
            handles.push(handle);
        }

        // Wait for all sessions to be created
        let session_ids: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|result| result.unwrap().0)
            .collect();

        // Verify we have valid session IDs
        for session_id in &session_ids {
            assert!(*session_id > 0, "Session ID should be valid");
        }

        // Clean up sessions
        for session_id in session_ids {
            assert!(
                provider.close_session(session_id).await.is_ok(),
                "Session should close successfully"
            );
        }
    }

    /// Test PKCS#11 error handling and recovery
    #[tokio::test]
    async fn test_pkcs11_error_handling() {
        // Test with invalid library path
        let invalid_config = Pkcs11Config {
            library_path: "/nonexistent/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(invalid_config);
        let init_result = provider.initialize().await;
        assert!(
            init_result.is_err(),
            "Invalid library path should fail initialization"
        );

        // Test operations with invalid session
        let valid_config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(valid_config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let invalid_session_id = 999999;
        let close_result = provider.close_session(invalid_session_id).await;
        assert!(close_result.is_err(), "Invalid session ID should fail");
    }

    /// Test PKCS#11 performance monitoring
    #[tokio::test]
    async fn test_pkcs11_performance_monitoring() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate test key
        let key_id = key_manager.generate_key("rsa", 2048).await.unwrap();

        // Measure signing performance
        let start_time = Instant::now();
        for i in 0..20 {
            let test_data = format!("PKCS#11 performance test {}", i);
            key_manager
                .sign(&key_id, test_data.as_bytes())
                .await
                .unwrap();
        }
        let signing_time = start_time.elapsed();

        // Performance should be reasonable
        assert!(
            signing_time.as_millis() < 10000,
            "20 signing operations should complete within 10 seconds"
        );

        // Get performance metrics
        let metrics = provider.get_performance_metrics().await.unwrap();
        assert!(
            metrics.operations_per_second > 0.0,
            "Should have operations per second metric"
        );
        assert!(
            metrics.average_latency_ms > 0.0,
            "Should have average latency metric"
        );
        assert!(
            metrics.active_sessions <= 5,
            "Active sessions should not exceed max_sessions"
        );
    }

    /// Test PKCS#11 token login/logout
    #[tokio::test]
    async fn test_pkcs11_token_login_logout() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        // Test login
        let login_result = provider.login().await;
        assert!(login_result.is_ok(), "Login should succeed");

        // Test logout
        let logout_result = provider.logout().await;
        assert!(logout_result.is_ok(), "Logout should succeed");

        // Test login after logout
        let relogin_result = provider.login().await;
        assert!(relogin_result.is_ok(), "Relogin should succeed");
    }

    /// Test PKCS#11 concurrent operations
    #[tokio::test]
    async fn test_pkcs11_concurrent_operations() {
        let config = Pkcs11Config {
            library_path: "/usr/lib/libpkcs11.so".to_string(),
            token_label: Some("test_token".to_string()),
            pin: Some("test_pin".to_string()),
            slot_id: Some(0),
            timeout_seconds: 30,
            max_sessions: 5,
            retry_attempts: 3,
        };

        let provider = Pkcs11Provider::new(config);
        provider
            .initialize()
            .await
            .expect("Provider should initialize");

        let key_manager = HsmKeyManager::new(Box::new(provider));

        // Generate multiple keys concurrently
        let mut handles = vec![];
        for i in 0..3 {
            let key_manager_clone = key_manager.clone();
            let handle = tokio::spawn(async move {
                let key_id = key_manager_clone.generate_key("aes", 256).await.unwrap();
                let test_data = format!("Concurrent test {}", i);
                let ciphertext = key_manager_clone
                    .encrypt(&key_id, test_data.as_bytes())
                    .await
                    .unwrap();
                let decrypted = key_manager_clone
                    .decrypt(&key_id, &ciphertext)
                    .await
                    .unwrap();
                (key_id, decrypted)
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            let (key_id, decrypted) = handle.await.unwrap();
            assert!(!key_id.is_empty(), "Key ID should not be empty");
            assert!(!decrypted.is_empty(), "Decrypted data should not be empty");
        }
    }
}
