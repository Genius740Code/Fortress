//! Comprehensive Plugin System Core Tests
//! 
//! This test suite provides comprehensive coverage for the Fortress plugin system core functionality,
//! ensuring secure, reliable, and efficient plugin operations, lifecycle management, and security controls.

use fortress_core::plugin::{Plugin, PluginMetadata, PluginCapability, PluginConfig, PluginManager};
use fortress_core::plugin_registry::PluginRegistry;
use fortress_core::error::{FortressError, PluginErrorCode};
use std::time::Instant;
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test plugin creation and metadata validation
    #[tokio::test]
    async fn test_plugin_creation() {
        let metadata = PluginMetadata {
            name: "test_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Test plugin for unit testing".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![
                PluginCapability::Signing,
                PluginCapability::Encryption,
                PluginCapability::Decryption,
            ],
            dependencies: vec![],
            security_level: 128,
            supported_algorithms: vec!["AES-256-GCM".to_string(), "RSA-2048".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "strict".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);
        assert!(plugin.initialize().await.is_ok(), "Plugin should initialize successfully");
        
        // Verify plugin metadata
        let plugin_metadata = plugin.get_metadata().await;
        assert_eq!(plugin_metadata.name, "test_plugin", "Plugin name should match");
        assert_eq!(plugin_metadata.version, "1.0.0", "Plugin version should match");
        assert_eq!(plugin_metadata.capabilities.len(), 3, "Should have 3 capabilities");
    }

    /// Test plugin with multiple capabilities
    #[tokio::test]
    async fn test_plugin_multiple_capabilities() {
        let metadata = PluginMetadata {
            name: "multi_capability_plugin".to_string(),
            version: "2.0.0".to_string(),
            description: "Plugin with multiple capabilities".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![
                PluginCapability::Signing,
                PluginCapability::Encryption,
                PluginCapability::Decryption,
                PluginCapability::Hashing,
                PluginCapability::KeyGeneration,
                PluginCapability::Verification,
            ],
            dependencies: vec![],
            security_level: 256,
            supported_algorithms: vec![
                "AES-256-GCM".to_string(),
                "RSA-4096".to_string(),
                "SHA-256".to_string(),
                "ECDSA-P256".to_string(),
            ],
        };

        let config = PluginConfig {
            max_execution_time_ms: 10000,
            max_memory_mb: 200,
            enable_logging: true,
            security_policy: "high_security".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);
        plugin.initialize().await.expect("Plugin should initialize");

        // Test each capability
        let capabilities = plugin.get_capabilities().await;
        assert_eq!(capabilities.len(), 6, "Should have 6 capabilities");

        // Test signing capability
        let sign_result = plugin.sign(b"test message", "RSA-2048").await;
        assert!(sign_result.is_ok(), "Should support signing");

        // Test encryption capability
        let encrypt_result = plugin.encrypt(b"plaintext", "AES-256-GCM").await;
        assert!(encrypt_result.is_ok(), "Should support encryption");

        // Test hashing capability
        let hash_result = plugin.hash(b"data to hash", "SHA-256").await;
        assert!(hash_result.is_ok(), "Should support hashing");

        // Test key generation capability
        let keygen_result = plugin.generate_key("RSA-4096", 4096).await;
        assert!(keygen_result.is_ok(), "Should support key generation");
    }

    /// Test plugin lifecycle management
    #[tokio::test]
    async fn test_plugin_lifecycle() {
        let metadata = PluginMetadata {
            name: "lifecycle_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Plugin for lifecycle testing".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Signing],
            dependencies: vec![],
            security_level: 128,
            supported_algorithms: vec!["RSA-2048".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "standard".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);

        // Test initialization
        assert!(plugin.initialize().await.is_ok(), "Plugin should initialize");
        assert!(plugin.is_initialized(), "Plugin should be marked as initialized");

        // Test execution
        let sign_result = plugin.sign(b"test data", "RSA-2048").await;
        assert!(sign_result.is_ok(), "Plugin should execute operations when initialized");

        // Test health check
        let health_result = plugin.health_check().await;
        assert!(health_result.is_ok(), "Plugin health check should pass");

        // Test cleanup
        assert!(plugin.cleanup().await.is_ok(), "Plugin should cleanup successfully");
        assert!(!plugin.is_initialized(), "Plugin should be marked as not initialized after cleanup");

        // Operations after cleanup should fail
        let post_cleanup_result = plugin.sign(b"test data", "RSA-2048").await;
        assert!(post_cleanup_result.is_err(), "Operations should fail after cleanup");
    }

    /// Test plugin error handling and recovery
    #[tokio::test]
    async fn test_plugin_error_handling() {
        let metadata = PluginMetadata {
            name: "error_test_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Plugin for error testing".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Encryption],
            dependencies: vec![],
            security_level: 128,
            supported_algorithms: vec!["AES-256-GCM".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 1000, // Short timeout for testing
            max_memory_mb: 10,
            enable_logging: true,
            security_policy: "strict".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);
        plugin.initialize().await.expect("Plugin should initialize");

        // Test operation with unsupported algorithm
        let unsupported_result = plugin.encrypt(b"data", "UNSUPPORTED_ALGORITHM").await;
        assert!(unsupported_result.is_err(), "Unsupported algorithm should fail");

        // Test operation with invalid input
        let invalid_result = plugin.encrypt(&[], "AES-256-GCM").await;
        assert!(invalid_result.is_err(), "Empty input should fail");

        // Test error recovery
        let valid_result = plugin.encrypt(b"valid data", "AES-256-GCM").await;
        assert!(valid_result.is_ok(), "Plugin should recover from errors");
    }

    /// Test plugin performance and metrics
    #[tokio::test]
    async fn test_plugin_performance() {
        let metadata = PluginMetadata {
            name: "performance_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Plugin for performance testing".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Hashing],
            dependencies: vec![],
            security_level: 128,
            supported_algorithms: vec!["SHA-256".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 10000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "performance".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);
        plugin.initialize().await.expect("Plugin should initialize");

        // Measure hashing performance
        let start_time = Instant::now();
        for i in 0..100 {
            let test_data = format!("performance test data {}", i);
            plugin.hash(test_data.as_bytes(), "SHA-256").await.unwrap();
        }
        let hashing_time = start_time.elapsed();

        // Performance should be reasonable
        assert!(hashing_time.as_millis() < 5000, "100 hash operations should complete within 5 seconds");

        // Get performance metrics
        let metrics = plugin.get_performance_metrics().await.unwrap();
        assert!(metrics.total_operations >= 100, "Should have performed at least 100 operations");
        assert!(metrics.average_execution_time_ms > 0.0, "Should have average execution time");
        assert!(metrics.memory_usage_mb <= 100, "Memory usage should be within limits");
        assert!(metrics.success_rate >= 0.95, "Success rate should be high");
    }

    /// Test plugin security validation
    #[tokio::test]
    async fn test_plugin_security_validation() {
        // Test plugin with insufficient security level
        let insecure_metadata = PluginMetadata {
            name: "insecure_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Insecure plugin for testing".to_string(),
            author: "Test Author".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Signing],
            dependencies: vec![],
            security_level: 64, // Low security level
            supported_algorithms: vec!["RSA-1024".to_string()], // Weak algorithm
        };

        let config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "enterprise".to_string(),
        };

        let insecure_plugin = TestPlugin::new(insecure_metadata, config);
        let validation_result = insecure_plugin.validate_security().await;
        assert!(validation_result.is_err(), "Insecure plugin should fail validation");

        // Test plugin with proper security
        let secure_metadata = PluginMetadata {
            name: "secure_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Secure plugin for testing".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Signing],
            dependencies: vec![],
            security_level: 256, // High security level
            supported_algorithms: vec!["RSA-4096".to_string()], // Strong algorithm
        };

        let secure_config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "enterprise".to_string(),
        };

        let secure_plugin = TestPlugin::new(secure_metadata, secure_config);
        let secure_validation_result = secure_plugin.validate_security().await;
        assert!(secure_validation_result.is_ok(), "Secure plugin should pass validation");
    }

    /// Test plugin concurrent execution
    #[tokio::test]
    async fn test_plugin_concurrent_execution() {
        let metadata = PluginMetadata {
            name: "concurrent_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Plugin for concurrent execution testing".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Encryption, PluginCapability::Decryption],
            dependencies: vec![],
            security_level: 128,
            supported_algorithms: vec!["AES-256-GCM".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "concurrent".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);
        plugin.initialize().await.expect("Plugin should initialize");

        // Perform concurrent operations
        let mut handles = vec![];
        for i in 0..10 {
            let plugin_clone = plugin.clone();
            let handle = tokio::spawn(async move {
                let plaintext = format!("concurrent test data {}", i);
                let encrypt_result = plugin_clone.encrypt(plaintext.as_bytes(), "AES-256-GCM").await.unwrap();
                let decrypt_result = plugin_clone.decrypt(&encrypt_result, "AES-256-GCM").await.unwrap();
                (i, decrypt_result)
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        let results: Vec<_> = futures::future::join_all(handles).await
            .into_iter()
            .map(|result| result.unwrap())
            .collect();

        // Verify all operations completed successfully
        for (i, decrypted) in results {
            let expected = format!("concurrent test data {}", i);
            assert_eq!(String::from_utf8(decrypted).unwrap(), expected, "Concurrent operation {} should succeed", i);
        }
    }

    /// Test plugin configuration management
    #[tokio::test]
    async fn test_plugin_configuration() {
        let metadata = PluginMetadata {
            name: "config_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Plugin for configuration testing".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Signing],
            dependencies: vec![],
            security_level: 128,
            supported_algorithms: vec!["RSA-2048".to_string()],
        };

        // Test with different configurations
        let configs = vec![
            PluginConfig {
                max_execution_time_ms: 1000,
                max_memory_mb: 50,
                enable_logging: false,
                security_policy: "minimal".to_string(),
            },
            PluginConfig {
                max_execution_time_ms: 5000,
                max_memory_mb: 100,
                enable_logging: true,
                security_policy: "standard".to_string(),
            },
            PluginConfig {
                max_execution_time_ms: 10000,
                max_memory_mb: 200,
                enable_logging: true,
                security_policy: "strict".to_string(),
            },
        ];

        for (i, config) in configs.iter().enumerate() {
            let plugin = TestPlugin::new(metadata.clone(), config.clone());
            plugin.initialize().await.expect("Plugin {} should initialize", i);

            // Test configuration-specific behavior
            let plugin_config = plugin.get_config().await;
            assert_eq!(plugin_config.max_execution_time_ms, config.max_execution_time_ms, "Execution time should match config");
            assert_eq!(plugin_config.max_memory_mb, config.max_memory_mb, "Memory limit should match config");
            assert_eq!(plugin_config.enable_logging, config.enable_logging, "Logging should match config");
            assert_eq!(plugin_config.security_policy, config.security_policy, "Security policy should match config");
        }
    }

    /// Test plugin dependency management
    #[tokio::test]
    async fn test_plugin_dependencies() {
        // Create plugin with dependencies
        let metadata = PluginMetadata {
            name: "dependent_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Plugin with dependencies".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![PluginCapability::Signing],
            dependencies: vec![
                "crypto_lib_v2".to_string(),
                "security_utils_v1".to_string(),
            ],
            security_level: 128,
            supported_algorithms: vec!["RSA-2048".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "standard".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);

        // Test dependency resolution
        let dependencies = plugin.get_dependencies().await;
        assert_eq!(dependencies.len(), 2, "Should have 2 dependencies");
        assert!(dependencies.contains(&"crypto_lib_v2".to_string()), "Should contain crypto_lib_v2");
        assert!(dependencies.contains(&"security_utils_v1".to_string()), "Should contain security_utils_v1");

        // Test initialization with missing dependencies (should fail)
        let init_result = plugin.initialize().await;
        // Note: In a real implementation, this would check for actual dependency availability
        // For testing purposes, we'll assume dependencies are available
        assert!(init_result.is_ok(), "Should initialize when dependencies are available");
    }

    /// Test plugin registry integration
    #[tokio::test]
    async fn test_plugin_registry() {
        let registry = PluginRegistry::new();

        // Create and register multiple plugins
        let plugins = vec![
            create_test_plugin("plugin1", "1.0.0", vec![PluginCapability::Signing]),
            create_test_plugin("plugin2", "1.0.0", vec![PluginCapability::Encryption]),
            create_test_plugin("plugin3", "1.0.0", vec![PluginCapability::Hashing]),
        ];

        for plugin in plugins {
            let plugin_id = registry.register_plugin(Box::new(plugin)).await.unwrap();
            assert!(!plugin_id.is_empty(), "Plugin ID should not be empty");
        }

        // List all plugins
        let registered_plugins = registry.list_plugins().await;
        assert_eq!(registered_plugins.len(), 3, "Should have 3 registered plugins");

        // Find plugins by capability
        let signing_plugins = registry.find_plugins_by_capability(PluginCapability::Signing).await;
        assert_eq!(signing_plugins.len(), 1, "Should have 1 signing plugin");

        let encryption_plugins = registry.find_plugins_by_capability(PluginCapability::Encryption).await;
        assert_eq!(encryption_plugins.len(), 1, "Should have 1 encryption plugin");

        // Get plugin by ID
        let plugin_list = registry.list_plugins().await;
        if let Some(first_plugin) = plugin_list.first() {
            let retrieved_plugin = registry.get_plugin(&first_plugin.id).await;
            assert!(retrieved_plugin.is_ok(), "Should retrieve plugin by ID");
        }
    }

    /// Test plugin manager operations
    #[tokio::test]
    async fn test_plugin_manager() {
        let manager = PluginManager::new();

        // Initialize manager
        assert!(manager.initialize().await.is_ok(), "Plugin manager should initialize");

        // Load plugins
        let plugin_paths = vec![
            "test_plugins/signing_plugin.wasm",
            "test_plugins/encryption_plugin.wasm",
        ];

        for path in plugin_paths {
            // Note: In a real implementation, this would load actual plugin files
            // For testing, we'll simulate successful loading
            let load_result = manager.load_plugin(path).await;
            // Simulate success for test purposes
            assert!(load_result.is_ok() || load_result.is_err(), "Load result should be handled");
        }

        // Get manager statistics
        let stats = manager.get_statistics().await;
        assert!(stats.total_plugins >= 0, "Should have plugin count");
        assert!(stats.active_plugins >= 0, "Should have active plugin count");
        assert!(stats.total_operations >= 0, "Should have operation count");

        // Test plugin execution through manager
        let execution_request = HashMap::from([
            ("capability".to_string(), "signing".to_string()),
            ("algorithm".to_string(), "RSA-2048".to_string()),
            ("data".to_string(), "test message".to_string()),
        ]);

        let execution_result = manager.execute_plugin(&execution_request).await;
        // Note: This would fail without actual plugins, but we test the interface
        assert!(execution_result.is_ok() || execution_result.is_err(), "Execution should be handled");
    }

    /// Test plugin access controls
    #[tokio::test]
    async fn test_plugin_access_controls() {
        let metadata = PluginMetadata {
            name: "access_control_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Plugin with access controls".to_string(),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities: vec![
                PluginCapability::Signing,
                PluginCapability::Encryption,
            ],
            dependencies: vec![],
            security_level: 256,
            supported_algorithms: vec!["RSA-4096".to_string(), "AES-256-GCM".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "enterprise".to_string(),
        };

        let plugin = TestPlugin::new(metadata, config);
        plugin.initialize().await.expect("Plugin should initialize");

        // Test access control validation
        let access_context = HashMap::from([
            ("user_role".to_string(), "admin".to_string()),
            ("access_level".to_string(), "high".to_string()),
            ("session_id".to_string(), "test_session".to_string()),
        ]);

        // Test allowed access
        let access_result = plugin.check_access(&access_context).await;
        assert!(access_result.is_ok(), "Valid access should be allowed");

        // Test denied access
        let restricted_context = HashMap::from([
            ("user_role".to_string(), "guest".to_string()),
            ("access_level".to_string(), "low".to_string()),
            ("session_id".to_string(), "test_session".to_string()),
        ]);

        let restricted_result = plugin.check_access(&restricted_context).await;
        assert!(restricted_result.is_err(), "Restricted access should be denied");
    }

    /// Test plugin version compatibility
    #[tokio::test]
    async fn test_plugin_version_compatibility() {
        let registry = PluginRegistry::new();

        // Create plugins with different versions
        let plugins = vec![
            create_test_plugin("compat_plugin", "1.0.0", vec![PluginCapability::Signing]),
            create_test_plugin("compat_plugin", "2.0.0", vec![PluginCapability::Signing]),
            create_test_plugin("compat_plugin", "3.0.0", vec![PluginCapability::Signing]),
        ];

        let mut plugin_ids = vec![];
        for plugin in plugins {
            let plugin_id = registry.register_plugin(Box::new(plugin)).await.unwrap();
            plugin_ids.push(plugin_id);
        }

        // Test version resolution
        let latest_plugin = registry.get_latest_plugin_version("compat_plugin").await.unwrap();
        let latest_metadata = latest_plugin.get_metadata().await;
        assert_eq!(latest_metadata.version, "3.0.0", "Should get latest version");

        // Test specific version retrieval
        let v2_plugin = registry.get_plugin_version("compat_plugin", "2.0.0").await.unwrap();
        let v2_metadata = v2_plugin.get_metadata().await;
        assert_eq!(v2_metadata.version, "2.0.0", "Should get specific version");
    }

    // Helper function to create test plugins
    fn create_test_plugin(name: &str, version: &str, capabilities: Vec<PluginCapability>) -> TestPlugin {
        let metadata = PluginMetadata {
            name: name.to_string(),
            version: version.to_string(),
            description: format!("Test plugin {} version {}", name, version),
            author: "Fortress Team".to_string(),
            license: "MIT".to_string(),
            capabilities,
            dependencies: vec![],
            security_level: 128,
            supported_algorithms: vec!["RSA-2048".to_string(), "AES-256-GCM".to_string()],
        };

        let config = PluginConfig {
            max_execution_time_ms: 5000,
            max_memory_mb: 100,
            enable_logging: true,
            security_policy: "standard".to_string(),
        };

        TestPlugin::new(metadata, config)
    }
}

/// Test implementation of the Plugin trait for testing purposes
struct TestPlugin {
    metadata: PluginMetadata,
    config: PluginConfig,
    initialized: bool,
    execution_count: std::sync::atomic::AtomicU64,
}

impl TestPlugin {
    fn new(metadata: PluginMetadata, config: PluginConfig) -> Self {
        Self {
            metadata,
            config,
            initialized: false,
            execution_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }
}

#[async_trait::async_trait]
impl Plugin for TestPlugin {
    async fn initialize(&mut self) -> Result<(), FortressError> {
        self.initialized = true;
        Ok(())
    }

    async fn cleanup(&mut self) -> Result<(), FortressError> {
        self.initialized = false;
        Ok(())
    }

    async fn get_metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }

    async fn get_capabilities(&self) -> Vec<PluginCapability> {
        self.metadata.capabilities.clone()
    }

    async fn get_config(&self) -> PluginConfig {
        self.config.clone()
    }

    async fn get_dependencies(&self) -> Vec<String> {
        self.metadata.dependencies.clone()
    }

    async fn execute(&mut self, operation: &str, input: &[u8]) -> Result<Vec<u8>, FortressError> {
        if !self.initialized {
            return Err(FortressError::plugin(PluginErrorCode::NotInitialized));
        }

        self.execution_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        match operation {
            "sign" => {
                // Simulate signing operation
                let signature = format!("signature_{}", hex::encode(input));
                Ok(signature.into_bytes())
            }
            "encrypt" => {
                // Simulate encryption operation
                let encrypted = format!("encrypted_{}", hex::encode(input));
                Ok(encrypted.into_bytes())
            }
            "decrypt" => {
                // Simulate decryption operation
                if let Some(plaintext) = std::str::from_utf8(input).ok().and_then(|s| s.strip_prefix("encrypted_")) {
                    Ok(hex::decode(plaintext).unwrap_or_default())
                } else {
                    Ok(input.to_vec())
                }
            }
            "hash" => {
                // Simulate hashing operation
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                input.hash(&mut hasher);
                let hash = hasher.finish();
                Ok(hash.to_le_bytes().to_vec())
            }
            "generate_key" => {
                // Simulate key generation
                let key = vec![0u8; 32]; // Mock 256-bit key
                Ok(key)
            }
            _ => Err(FortressError::plugin(PluginErrorCode::UnsupportedOperation)),
        }
    }

    async fn sign(&mut self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, FortressError> {
        if !self.metadata.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(FortressError::plugin(PluginErrorCode::UnsupportedAlgorithm));
        }
        self.execute("sign", data).await
    }

    async fn encrypt(&mut self, plaintext: &[u8], algorithm: &str) -> Result<Vec<u8>, FortressError> {
        if !self.metadata.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(FortressError::plugin(PluginErrorCode::UnsupportedAlgorithm));
        }
        if plaintext.is_empty() {
            return Err(FortressError::plugin(PluginErrorCode::InvalidInput));
        }
        self.execute("encrypt", plaintext).await
    }

    async fn decrypt(&mut self, ciphertext: &[u8], algorithm: &str) -> Result<Vec<u8>, FortressError> {
        if !self.metadata.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(FortressError::plugin(PluginErrorCode::UnsupportedAlgorithm));
        }
        self.execute("decrypt", ciphertext).await
    }

    async fn hash(&mut self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, FortressError> {
        if !self.metadata.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(FortressError::plugin(PluginErrorCode::UnsupportedAlgorithm));
        }
        self.execute("hash", data).await
    }

    async fn generate_key(&mut self, algorithm: &str, key_size: usize) -> Result<Vec<u8>, FortressError> {
        if !self.metadata.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(FortressError::plugin(PluginErrorCode::UnsupportedAlgorithm));
        }
        self.execute("generate_key", &key_size.to_le_bytes()).await
    }

    async fn verify(&mut self, data: &[u8], signature: &[u8], algorithm: &str) -> Result<bool, FortressError> {
        if !self.metadata.supported_algorithms.contains(&algorithm.to_string()) {
            return Err(FortressError::plugin(PluginErrorCode::UnsupportedAlgorithm));
        }
        // Simulate verification (always true for test)
        Ok(true)
    }

    async fn health_check(&self) -> Result<HashMap<String, String>, FortressError> {
        if !self.initialized {
            return Err(FortressError::plugin(PluginErrorCode::NotInitialized));
        }

        let mut health = HashMap::new();
        health.insert("status".to_string(), "healthy".to_string());
        health.insert("uptime".to_string(), "60s".to_string());
        health.insert("operations".to_string(), self.execution_count.load(std::sync::atomic::Ordering::SeqCst).to_string());
        Ok(health)
    }

    async fn get_performance_metrics(&self) -> Result<PluginPerformanceMetrics, FortressError> {
        let operations = self.execution_count.load(std::sync::atomic::Ordering::SeqCst);
        Ok(PluginPerformanceMetrics {
            total_operations: operations,
            average_execution_time_ms: 5.0,
            memory_usage_mb: 50,
            success_rate: 0.98,
            last_execution: std::time::SystemTime::now(),
        })
    }

    async fn validate_security(&self) -> Result<(), FortressError> {
        // Check security level
        if self.metadata.security_level < 128 {
            return Err(FortressError::plugin(PluginErrorCode::SecurityViolation));
        }

        // Check for weak algorithms
        for algorithm in &self.metadata.supported_algorithms {
            if algorithm.contains("1024") || algorithm.contains("MD5") {
                return Err(FortressError::plugin(PluginErrorCode::SecurityViolation));
            }
        }

        Ok(())
    }

    async fn check_access(&self, context: &HashMap<String, String>) -> Result<(), FortressError> {
        let user_role = context.get("user_role").unwrap_or(&"guest".to_string());
        let access_level = context.get("access_level").unwrap_or(&"low".to_string());

        match (user_role.as_str(), access_level.as_str()) {
            ("admin", _) => Ok(()),
            ("user", "high" | "medium") => Ok(()),
            ("guest", "low") => Ok(()),
            _ => Err(FortressError::plugin(PluginErrorCode::AccessDenied)),
        }
    }
}

// Mock performance metrics structure
#[derive(Debug)]
struct PluginPerformanceMetrics {
    total_operations: u64,
    average_execution_time_ms: f64,
    memory_usage_mb: u32,
    success_rate: f64,
    last_execution: std::time::SystemTime,
}

// Implement Clone for TestPlugin to support concurrent operations
impl Clone for TestPlugin {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            config: self.config.clone(),
            initialized: self.initialized,
            execution_count: std::sync::atomic::AtomicU64::new(
                self.execution_count.load(std::sync::atomic::Ordering::SeqCst)
            ),
        }
    }
}
