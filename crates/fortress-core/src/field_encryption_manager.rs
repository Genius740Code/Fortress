//! In-memory implementation of field encryption manager
//!
//! This module provides the default implementation of the FieldEncryptionManager trait
//! with in-memory storage for configurations and metadata.

use crate::encryption::{create_algorithm, EncryptionAlgorithm};
use crate::error::{EncryptionErrorCode, FortressError, Result};
use crate::field_encryption::{
    DecryptedField, DefaultAlgorithmSelector, EncryptedField, FieldAlgorithmSelector,
    FieldEncryptionConfig, FieldEncryptionManager, FieldEncryptionMetadata,
    FieldEncryptionStrategy, FieldIdentifier,
};
use crate::key::{KeyManager, SecureKey};

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Default implementation of field encryption manager
pub struct DefaultFieldEncryptionManager {
    /// Key manager for encryption keys
    key_manager: Arc<dyn KeyManager>,
    /// Algorithm selector for choosing algorithms
    algorithm_selector: Arc<dyn FieldAlgorithmSelector>,
    /// Field configurations
    configs: Arc<RwLock<HashMap<String, FieldEncryptionConfig>>>,
    /// Default encryption profile
    default_algorithm: String,
}

impl DefaultFieldEncryptionManager {
    /// Create a new field encryption manager
    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {
        Self::with_algorithm_selector(key_manager, Arc::new(DefaultAlgorithmSelector))
    }

    /// Create a new field encryption manager with custom algorithm selector
    pub fn with_algorithm_selector(
        key_manager: Arc<dyn KeyManager>,
        algorithm_selector: Arc<dyn FieldAlgorithmSelector>,
    ) -> Self {
        Self {
            key_manager,
            algorithm_selector,
            configs: Arc::new(RwLock::new(HashMap::new())),
            default_algorithm: "kyber768".to_string(),
        }
    }

    /// Set the default algorithm
    pub fn with_default_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.default_algorithm = algorithm.into();
        self
    }

    /// Get or create a key for a field configuration
    async fn get_or_create_key(
        &self,
        config: &FieldEncryptionConfig,
    ) -> Result<(SecureKey, String)> {
        match &config.key_id {
            Some(key_id) => {
                // Use existing key
                let (key, _) = self.key_manager.retrieve_key(key_id).await?;
                Ok((key, key_id.clone()))
            }
            None => {
                // Generate a new key for this field
                let algorithm_name = config.algorithm_name().unwrap_or(&self.default_algorithm);
                let algorithm = create_algorithm(algorithm_name)?;

                let key = self.key_manager.generate_key(algorithm.as_ref()).await?;
                let key_id = Uuid::new_v4().to_string();

                // Store the key with metadata
                let metadata = crate::key::KeyMetadata::new(
                    key_id.clone(),
                    algorithm_name.to_string(),
                    1,
                    chrono::Utc::now(),
                    chrono::Utc::now() + chrono::Duration::days(90),
                    format!("field:{}", config.field.as_string()),
                    config.performance_profile,
                );

                self.key_manager.store_key(&key_id, &key, &metadata).await?;
                Ok((key, key_id))
            }
        }
    }

    /// Get algorithm instance for a configuration
    async fn get_algorithm(
        &self,
        config: &FieldEncryptionConfig,
    ) -> Result<Box<dyn EncryptionAlgorithm>> {
        let _algorithm_name = config.algorithm_name().unwrap_or(&self.default_algorithm);

        // Use the algorithm selector to choose the best algorithm for this field
        let selected_algorithm = self.algorithm_selector.select_algorithm(
            &config.field,
            &config.strategy,
            config.performance_profile,
            &config.compliance_tags,
        )?;

        create_algorithm(&selected_algorithm)
    }

    /// Generate nonce for algorithms that need it
    fn generate_nonce(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<Vec<u8>> {
        let nonce_size = algorithm.nonce_size();
        if nonce_size == 0 {
            return Ok(Vec::new());
        }

        match crate::trng::random_bytes(nonce_size) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                // Fallback to getrandom
                let mut nonce = vec![0u8; nonce_size];
                getrandom::getrandom(&mut nonce).map_err(|e| {
                    FortressError::encryption(
                        format!("Failed to generate nonce: {}", e),
                        "nonce_generation".to_string(),
                        EncryptionErrorCode::AlgorithmNotSupported,
                    )
                })?;
                Ok(nonce)
            }
        }
    }
}

#[async_trait]
impl FieldEncryptionManager for DefaultFieldEncryptionManager {
    async fn encrypt_field(
        &self,
        field: &FieldIdentifier,
        plaintext: &[u8],
    ) -> Result<EncryptedField> {
        // Get configuration for this field
        let config = {
            let configs = self.configs.read().await;
            configs.get(&field.as_string()).cloned()
        };

        let config = match config {
            Some(config) => config,
            None => {
                // Create default configuration
                let default_config =
                    FieldEncryptionConfig::new(field.clone(), FieldEncryptionStrategy::Default);
                default_config
            }
        };

        // Check if field should be encrypted
        if !config.should_encrypt() {
            return Err(FortressError::encryption(
                "Field is configured for no encryption",
                "none",
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }

        // Get or create key
        let (key, key_id) = self.get_or_create_key(&config).await?;

        // Get algorithm
        let algorithm = self.get_algorithm(&config).await?;

        // Generate nonce if needed
        let nonce = self.generate_nonce(algorithm.as_ref())?;

        // Encrypt the data
        let ciphertext = if nonce.is_empty() {
            algorithm.encrypt(plaintext, key.as_bytes().expect("Key material must be local for field encryption"))?
        } else {
            // For algorithms with nonce, we need to handle it properly
            // This is a simplified implementation - in practice, you'd need
            // to handle the nonce according to each algorithm's requirements
            algorithm.encrypt(plaintext, key.as_bytes().expect("Key material must be local for field encryption"))?
        };

        // Create metadata with actual key version
        let key_version = self
            .key_manager
            .get_active_key_version(&key_id)
            .await
            .unwrap_or(1);
        let mut metadata = FieldEncryptionMetadata::new(
            config.id.clone(),
            field.clone(),
            algorithm.name().to_string(),
            key_id,
            key_version,
        )
        .with_nonce(nonce.clone());

        // Add authentication tag if algorithm is AEAD
        if algorithm.is_aead() && algorithm.tag_size() > 0 {
            // For AEAD algorithms, the tag is typically included in the ciphertext
            // This is a simplified approach - in practice, you'd extract it properly
            let tag_size = algorithm.tag_size();
            if ciphertext.len() >= tag_size {
                let tag = ciphertext[ciphertext.len() - tag_size..].to_vec();
                metadata = metadata.with_tag(tag);
            }
        }

        Ok(EncryptedField {
            ciphertext,
            metadata,
        })
    }

    async fn decrypt_field(
        &self,
        ciphertext: &[u8],
        metadata: &FieldEncryptionMetadata,
    ) -> Result<DecryptedField> {
        // Retrieve the key
        let (key, _) = self.key_manager.retrieve_key(&metadata.key_id).await?;

        // Get algorithm
        let algorithm = create_algorithm(&metadata.algorithm)?;

        // Decrypt the data
        let plaintext = algorithm.decrypt(ciphertext, key.as_bytes().expect("Key material must be local for field decryption"))?;

        Ok(DecryptedField {
            plaintext,
            field: metadata.field.clone(),
            metadata: metadata.clone(),
        })
    }

    async fn get_field_config(
        &self,
        field: &FieldIdentifier,
    ) -> Result<Option<FieldEncryptionConfig>> {
        let configs = self.configs.read().await;
        Ok(configs.get(&field.as_string()).cloned())
    }

    async fn set_field_config(&self, config: FieldEncryptionConfig) -> Result<()> {
        let mut configs = self.configs.write().await;
        configs.insert(config.field.as_string(), config);
        Ok(())
    }

    async fn remove_field_config(&self, field: &FieldIdentifier) -> Result<()> {
        let mut configs = self.configs.write().await;
        configs.remove(&field.as_string());
        Ok(())
    }

    async fn list_field_configs(&self) -> Result<Vec<FieldEncryptionConfig>> {
        let configs = self.configs.read().await;
        Ok(configs.values().cloned().collect())
    }
}

/// Builder for field encryption manager
pub struct FieldEncryptionManagerBuilder {
    key_manager: Option<Arc<dyn KeyManager>>,
    algorithm_selector: Option<Arc<dyn FieldAlgorithmSelector>>,
    default_algorithm: Option<String>,
}

impl FieldEncryptionManagerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            key_manager: None,
            algorithm_selector: None,
            default_algorithm: None,
        }
    }

    /// Set the key manager
    pub fn with_key_manager(mut self, key_manager: Arc<dyn KeyManager>) -> Self {
        self.key_manager = Some(key_manager);
        self
    }

    /// Set the algorithm selector
    pub fn with_algorithm_selector(mut self, selector: Arc<dyn FieldAlgorithmSelector>) -> Self {
        self.algorithm_selector = Some(selector);
        self
    }

    /// Set the default algorithm
    pub fn with_default_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.default_algorithm = Some(algorithm.into());
        self
    }

    /// Build the field encryption manager
    pub fn build(self) -> Result<DefaultFieldEncryptionManager> {
        let key_manager = self.key_manager.ok_or_else(|| {
            FortressError::encryption(
                "Key manager is required",
                "none",
                EncryptionErrorCode::AlgorithmNotSupported,
            )
        })?;

        let algorithm_selector = self
            .algorithm_selector
            .unwrap_or_else(|| Arc::new(DefaultAlgorithmSelector));

        let mut manager =
            DefaultFieldEncryptionManager::with_algorithm_selector(key_manager, algorithm_selector);

        if let Some(default_algorithm) = self.default_algorithm {
            manager = manager.with_default_algorithm(default_algorithm);
        }

        Ok(manager)
    }
}

impl Default for FieldEncryptionManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::InMemoryKeyManager;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_field_encryption_roundtrip() {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let field_manager = DefaultFieldEncryptionManager::new(key_manager);

        let field = FieldIdentifier::name("email");
        let plaintext = b"user@example.com";

        // Encrypt the field
        let encrypted = field_manager
            .encrypt_field(&field, plaintext)
            .await
            .unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.metadata.field, field);

        // Decrypt the field
        let decrypted = field_manager
            .decrypt_field(&encrypted.ciphertext, &encrypted.metadata)
            .await
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.field, field);
    }

    #[tokio::test]
    async fn test_field_configuration() {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let field_manager = DefaultFieldEncryptionManager::new(key_manager);

        let field = FieldIdentifier::name("ssn");

        // Initially no configuration
        let config = field_manager.get_field_config(&field).await.unwrap();
        assert!(config.is_none());

        // Set a configuration
        let new_config = FieldEncryptionConfig::new(
            field.clone(),
            FieldEncryptionStrategy::Algorithm("aes256gcm".to_string()),
        )
        .with_compliance_tag("HIPAA");

        field_manager
            .set_field_config(new_config.clone())
            .await
            .unwrap();

        // Retrieve the configuration
        let retrieved = field_manager.get_field_config(&field).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.field, field);
        assert_eq!(retrieved.algorithm_name(), Some("aes256gcm"));
        assert!(retrieved.compliance_tags.contains(&"HIPAA".to_string()));
    }

    #[tokio::test]
    async fn test_batch_encryption() {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let field_manager = DefaultFieldEncryptionManager::new(key_manager);

        let mut fields = HashMap::new();
        fields.insert(FieldIdentifier::name("email"), b"user@example.com".to_vec());
        fields.insert(FieldIdentifier::name("phone"), b"+1234567890".to_vec());

        // Encrypt batch
        let encrypted_fields = field_manager.encrypt_fields_batch(&fields).await.unwrap();
        assert_eq!(encrypted_fields.len(), 2);

        // Decrypt batch
        let mut decrypt_inputs = HashMap::new();
        for (field, encrypted) in &encrypted_fields {
            decrypt_inputs.insert(
                field.clone(),
                (encrypted.ciphertext.clone(), encrypted.metadata.clone()),
            );
        }

        let decrypted_fields = field_manager
            .decrypt_fields_batch(&decrypt_inputs)
            .await
            .unwrap();
        assert_eq!(decrypted_fields.len(), 2);

        // Verify results
        for (field, decrypted) in decrypted_fields {
            let original = fields.get(&field).unwrap();
            assert_eq!(decrypted.plaintext, *original);
        }
    }
}
