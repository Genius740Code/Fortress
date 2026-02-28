//! Per-field encryption with custom algorithm selection
//!
//! This module provides field-level encryption capabilities that allow different
//! fields within a data structure to be encrypted using different algorithms
//! based on their sensitivity, performance requirements, and compliance needs.
//!
//! ## Features
//!
//! - **Field-specific algorithm selection**: Choose different encryption algorithms per field
//! - **Metadata management**: Track encryption metadata for each field
//! - **Performance optimization**: Use fast algorithms for high-throughput fields
//! - **Compliance support**: Meet regulatory requirements with appropriate algorithms
//! - **Key isolation**: Separate keys per field or field groups

use crate::error::{FortressError, Result, EncryptionErrorCode};
use crate::encryption::{EncryptionProfile, PerformanceProfile};
use crate::key::{KeyId};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique identifier for a field encryption configuration
pub type FieldConfigId = String;

/// Identifier for a specific field within a data structure
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldIdentifier {
    /// Simple field name (e.g., "email", "ssn")
    Name(String),
    /// Nested field path (e.g., "user.profile.email")
    Path(Vec<String>),
    /// Indexed field (e.g., array elements)
    Indexed { 
        /// Field path
        path: Vec<String>, 
        /// Array index
        index: usize 
    },
}

impl FieldIdentifier {
    /// Create a simple field identifier
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    /// Create a nested field identifier
    pub fn path(path: Vec<impl Into<String>>) -> Self {
        Self::Path(path.into_iter().map(|p| p.into()).collect())
    }

    /// Create an indexed field identifier
    pub fn indexed(path: Vec<impl Into<String>>, index: usize) -> Self {
        Self::Indexed {
            path: path.into_iter().map(|p| p.into()).collect(),
            index,
        }
    }

    /// Get the string representation of the field identifier
    pub fn as_string(&self) -> String {
        match self {
            Self::Name(name) => name.clone(),
            Self::Path(path) => path.join("."),
            Self::Indexed { path, index } => format!("{}.{}", path.join("."), index),
        }
    }
}

/// Encryption strategy for a field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldEncryptionStrategy {
    /// No encryption (plaintext)
    None,
    /// Use default encryption
    Default,
    /// Use specific algorithm
    Algorithm(String),
    /// Use specific encryption profile
    Profile(String),
    /// Use field-specific key
    DedicatedKey,
    /// Use key derived from field value and master key
    DerivedKey,
}

impl Default for FieldEncryptionStrategy {
    fn default() -> Self {
        Self::Default
    }
}

/// Configuration for field-level encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEncryptionConfig {
    /// Unique identifier for this configuration
    pub id: FieldConfigId,
    /// Field identifier
    pub field: FieldIdentifier,
    /// Encryption strategy
    pub strategy: FieldEncryptionStrategy,
    /// Key ID to use (if applicable)
    pub key_id: Option<KeyId>,
    /// Encryption profile to use (if applicable)
    pub profile: Option<EncryptionProfile>,
    /// Performance requirements
    pub performance_profile: PerformanceProfile,
    /// Compliance requirements
    pub compliance_tags: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// When this configuration was created
    pub created_at: DateTime<Utc>,
    /// When this configuration was last updated
    pub updated_at: DateTime<Utc>,
}

impl FieldEncryptionConfig {
    /// Create a new field encryption configuration
    pub fn new(
        field: FieldIdentifier,
        strategy: FieldEncryptionStrategy,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            field,
            strategy,
            key_id: None,
            profile: None,
            performance_profile: PerformanceProfile::Balanced,
            compliance_tags: Vec::new(),
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the key ID for this field
    pub fn with_key_id(mut self, key_id: KeyId) -> Self {
        self.key_id = Some(key_id);
        self.updated_at = Utc::now();
        self
    }

    /// Set the encryption profile for this field
    pub fn with_profile(mut self, profile: EncryptionProfile) -> Self {
        self.profile = Some(profile);
        self.updated_at = Utc::now();
        self
    }

    /// Set the performance profile
    pub fn with_performance_profile(mut self, profile: PerformanceProfile) -> Self {
        self.performance_profile = profile;
        self.updated_at = Utc::now();
        self
    }

    /// Add compliance tags
    pub fn with_compliance_tag(mut self, tag: impl Into<String>) -> Self {
        self.compliance_tags.push(tag.into());
        self.updated_at = Utc::now();
        self
    }

    /// Add custom metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self.updated_at = Utc::now();
        self
    }

    /// Check if this field should be encrypted
    pub fn should_encrypt(&self) -> bool {
        !matches!(self.strategy, FieldEncryptionStrategy::None)
    }

    /// Get the effective algorithm name
    pub fn algorithm_name(&self) -> Option<&str> {
        match &self.strategy {
            FieldEncryptionStrategy::Algorithm(name) => Some(name),
            FieldEncryptionStrategy::Profile(profile_name) => Some(profile_name),
            _ => self.profile.as_ref().map(|p| p.algorithm.as_str()),
        }
    }
}

/// Metadata for encrypted field data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEncryptionMetadata {
    /// Field configuration ID
    pub config_id: FieldConfigId,
    /// Field identifier
    pub field: FieldIdentifier,
    /// Algorithm used for encryption
    pub algorithm: String,
    /// Key ID used
    pub key_id: KeyId,
    /// Key version
    pub key_version: u32,
    /// When the field was encrypted
    pub encrypted_at: DateTime<Utc>,
    /// Nonce/IV used (if applicable)
    pub nonce: Option<Vec<u8>>,
    /// Authentication tag (if applicable)
    pub tag: Option<Vec<u8>>,
    /// Additional encryption metadata
    pub metadata: HashMap<String, String>,
}

impl FieldEncryptionMetadata {
    /// Create new field encryption metadata
    pub fn new(
        config_id: FieldConfigId,
        field: FieldIdentifier,
        algorithm: String,
        key_id: KeyId,
        key_version: u32,
    ) -> Self {
        Self {
            config_id,
            field,
            algorithm,
            key_id,
            key_version,
            encrypted_at: Utc::now(),
            nonce: None,
            tag: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the nonce
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the authentication tag
    pub fn with_tag(mut self, tag: Vec<u8>) -> Self {
        self.tag = Some(tag);
        self
    }

    /// Add custom metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Result of field encryption operation
#[derive(Debug, Clone)]
pub struct EncryptedField {
    /// The encrypted data
    pub ciphertext: Vec<u8>,
    /// Encryption metadata
    pub metadata: FieldEncryptionMetadata,
}

/// Result of field decryption operation
#[derive(Debug)]
pub struct DecryptedField {
    /// The decrypted data
    pub plaintext: Vec<u8>,
    /// Field identifier
    pub field: FieldIdentifier,
    /// Encryption metadata
    pub metadata: FieldEncryptionMetadata,
}

/// Trait for field encryption managers
#[async_trait]
pub trait FieldEncryptionManager: Send + Sync {
    /// Encrypt a field value
    async fn encrypt_field(
        &self,
        field: &FieldIdentifier,
        plaintext: &[u8],
    ) -> Result<EncryptedField>;

    /// Decrypt a field value
    async fn decrypt_field(
        &self,
        ciphertext: &[u8],
        metadata: &FieldEncryptionMetadata,
    ) -> Result<DecryptedField>;

    /// Get configuration for a field
    async fn get_field_config(&self, field: &FieldIdentifier) -> Result<Option<FieldEncryptionConfig>>;

    /// Set configuration for a field
    async fn set_field_config(&self, config: FieldEncryptionConfig) -> Result<()>;

    /// Remove configuration for a field
    async fn remove_field_config(&self, field: &FieldIdentifier) -> Result<()>;

    /// List all field configurations
    async fn list_field_configs(&self) -> Result<Vec<FieldEncryptionConfig>>;

    /// Encrypt multiple fields in a batch
    async fn encrypt_fields_batch(
        &self,
        fields: &HashMap<FieldIdentifier, Vec<u8>>,
    ) -> Result<HashMap<FieldIdentifier, EncryptedField>> {
        let mut results = HashMap::new();
        for (field, plaintext) in fields {
            let encrypted = self.encrypt_field(field, plaintext).await?;
            results.insert(field.clone(), encrypted);
        }
        Ok(results)
    }

    /// Decrypt multiple fields in a batch
    async fn decrypt_fields_batch(
        &self,
        fields: &HashMap<FieldIdentifier, (Vec<u8>, FieldEncryptionMetadata)>,
    ) -> Result<HashMap<FieldIdentifier, DecryptedField>> {
        let mut results = HashMap::new();
        for (field, (ciphertext, metadata)) in fields {
            let decrypted = self.decrypt_field(ciphertext, metadata).await?;
            results.insert(field.clone(), decrypted);
        }
        Ok(results)
    }
}

/// Algorithm selector for field encryption
pub trait FieldAlgorithmSelector: Send + Sync {
    /// Select algorithm for a field based on its characteristics
    fn select_algorithm(
        &self,
        field: &FieldIdentifier,
        strategy: &FieldEncryptionStrategy,
        performance_profile: PerformanceProfile,
        compliance_tags: &[String],
    ) -> Result<String>;

    /// Get recommended algorithm for data type
    fn recommend_algorithm_for_type(&self, data_type: &str, sensitivity: FieldSensitivity) -> Result<String>;
}

/// Sensitivity level for field data
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FieldSensitivity {
    /// Public data (no encryption needed)
    Public,
    /// Internal data (basic encryption)
    Internal,
    /// Confidential data (standard encryption)
    Confidential,
    /// Highly sensitive data (maximum security)
    Restricted,
    /// Critical data (highest security, special handling)
    Critical,
}

impl Default for FieldSensitivity {
    fn default() -> Self {
        Self::Internal
    }
}

/// Default algorithm selector implementation
pub struct DefaultAlgorithmSelector;

impl FieldAlgorithmSelector for DefaultAlgorithmSelector {
    fn select_algorithm(
        &self,
        _field: &FieldIdentifier,
        strategy: &FieldEncryptionStrategy,
        performance_profile: PerformanceProfile,
        _compliance_tags: &[String],
    ) -> Result<String> {
        match strategy {
            FieldEncryptionStrategy::None => Err(FortressError::encryption(
                "No encryption selected",
                "none",
                EncryptionErrorCode::AlgorithmNotSupported,
            )),
            FieldEncryptionStrategy::Default => Ok(match performance_profile {
                PerformanceProfile::Lightning => "aegis256",
                PerformanceProfile::Balanced => "xchacha20poly1305",
                PerformanceProfile::Fortress => "argon2idencrypt",
                PerformanceProfile::Streaming => "aes256ctr",
                PerformanceProfile::Hardware => "blake3encrypt",
                PerformanceProfile::Quantum => "compositeencrypt",
            }.to_string()),
            FieldEncryptionStrategy::Algorithm(name) => Ok(name.clone()),
            FieldEncryptionStrategy::Profile(profile_name) => Ok(profile_name.clone()),
            FieldEncryptionStrategy::DedicatedKey | FieldEncryptionStrategy::DerivedKey => {
                // For key-specific strategies, use balanced algorithm by default
                Ok("xchacha20poly1305".to_string())
            }
        }
    }

    fn recommend_algorithm_for_type(&self, data_type: &str, sensitivity: FieldSensitivity) -> Result<String> {
        match (data_type, sensitivity) {
            // High-performance for large data
            ("blob", FieldSensitivity::Internal) => Ok("aes256ctr".to_string()),
            ("blob", FieldSensitivity::Confidential) => Ok("blake3encrypt".to_string()),
            ("blob", FieldSensitivity::Restricted | FieldSensitivity::Critical) => Ok("compositeencrypt".to_string()),
            
            // Standard for text fields
            ("text" | "string", FieldSensitivity::Public) => Err(FortressError::encryption(
                "Public data should not be encrypted",
                "none",
                EncryptionErrorCode::AlgorithmNotSupported,
            )),
            ("text" | "string", FieldSensitivity::Internal) => Ok("xchacha20poly1305".to_string()),
            ("text" | "string", FieldSensitivity::Confidential) => Ok("argon2idencrypt".to_string()),
            ("text" | "string", FieldSensitivity::Restricted | FieldSensitivity::Critical) => Ok("compositeencrypt".to_string()),
            
            // High security for identifiers
            ("email" | "phone" | "ssn" | "credit_card", _) => Ok("compositeencrypt".to_string()),
            
            // Balanced for numeric data
            ("number" | "decimal" | "integer", FieldSensitivity::Internal) => Ok("xchacha20poly1305".to_string()),
            ("number" | "decimal" | "integer", _) => Ok("argon2idencrypt".to_string()),
            
            // Default to balanced
            _ => Ok("xchacha20poly1305".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_identifier() {
        let field1 = FieldIdentifier::name("email");
        assert_eq!(field1.as_string(), "email");

        let field2 = FieldIdentifier::path(vec!["user", "profile", "email"]);
        assert_eq!(field2.as_string(), "user.profile.email");

        let field3 = FieldIdentifier::indexed(vec!["users", "0", "email"], 1);
        assert_eq!(field3.as_string(), "users.0.email.1");
    }

    #[test]
    fn test_field_encryption_config() {
        let config = FieldEncryptionConfig::new(
            FieldIdentifier::name("ssn"),
            FieldEncryptionStrategy::Algorithm("aes256gcm".to_string()),
        )
        .with_performance_profile(PerformanceProfile::Fortress)
        .with_compliance_tag("HIPAA");

        assert!(config.should_encrypt());
        assert_eq!(config.algorithm_name(), Some("aes256gcm"));
        assert_eq!(config.performance_profile, PerformanceProfile::Fortress);
        assert!(config.compliance_tags.contains(&"HIPAA".to_string()));
    }

    #[test]
    fn test_default_algorithm_selector() {
        let selector = DefaultAlgorithmSelector;

        // Test strategy-based selection
        let field = FieldIdentifier::name("test");
        let algorithm = selector.select_algorithm(
            &field,
            &FieldEncryptionStrategy::Default,
            PerformanceProfile::Lightning,
            &[],
        ).unwrap();
        assert_eq!(algorithm, "aegis256");

        // Test data type recommendations
        let algorithm = selector.recommend_algorithm_for_type("email", FieldSensitivity::Restricted).unwrap();
        assert_eq!(algorithm, "hmacsha512encrypt");

        let algorithm = selector.recommend_algorithm_for_type("blob", FieldSensitivity::Internal).unwrap();
        assert_eq!(algorithm, "blake3encrypt");

        let algorithm = selector.recommend_algorithm_for_type("text", FieldSensitivity::Confidential).unwrap();
        assert_eq!(algorithm, "xchacha20poly1305");
    }
}
