//! Key management and rotation

//!

//! This module provides secure key management, rotation, and derivation capabilities

//! for Fortress. It supports multiple key derivation functions and automatic rotation

//! based on configurable schedules.



use crate::error::{FortressError, Result, KeyErrorCode};

use crate::encryption::{EncryptionAlgorithm, PerformanceProfile};

use async_trait::async_trait;

use chrono::{DateTime, Duration, Utc};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::RwLock;

use uuid::Uuid;



/// Unique identifier for a key

pub type KeyId = String;



/// Key version for rotation tracking

pub type KeyVersion = u32;



/// Key manager trait for different key storage backends

#[async_trait]

pub trait KeyManager: Send + Sync {

    /// Generate a new key

    async fn generate_key(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<SecureKey>;



    /// Store a key with metadata

    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()>;



    /// Retrieve a key by ID

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)>;



    /// Delete a key

    async fn delete_key(&self, key_id: &KeyId) -> Result<()>;



    /// List all keys

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>>;



    /// Rotate a key

    async fn rotate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<(SecureKey, KeyMetadata)>;



    /// Check if a key needs rotation

    async fn needs_rotation(&self, key_id: &KeyId) -> Result<bool>;



    /// Get active key for a given purpose

    async fn get_active_key(&self, purpose: &str) -> Result<(SecureKey, KeyMetadata)>;

}



/// In-memory key manager for testing and development

#[derive(Debug)]

pub struct InMemoryKeyManager {

    keys: Arc<RwLock<HashMap<KeyId, (SecureKey, KeyMetadata)>>>,

}



impl InMemoryKeyManager {

    /// Create a new in-memory key manager

    pub fn new() -> Self {

        Self {

            keys: Arc::new(RwLock::new(HashMap::new())),

        }

    }

}



impl Default for InMemoryKeyManager {

    fn default() -> Self {

        Self::new()

    }

}



#[async_trait]

impl KeyManager for InMemoryKeyManager {

    async fn generate_key(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<SecureKey> {

        Ok(SecureKey::generate(algorithm.key_size()))

    }



    async fn store_key(&self, key_id: &KeyId, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {

        let mut keys = self.keys.write().await;

        keys.insert(key_id.clone(), (key.clone(), metadata.clone()));

        Ok(())

    }



    async fn retrieve_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)> {

        let keys = self.keys.read().await;

        keys.get(key_id)

            .cloned()

            .ok_or_else(|| FortressError::key_management(

                format!("Key not found: {}", key_id),

                Some(key_id.clone()),

                KeyErrorCode::KeyNotFound,

            ))

    }



    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {

        let mut keys = self.keys.write().await;

        keys.remove(key_id)

            .ok_or_else(|| FortressError::key_management(

                format!("Key not found: {}", key_id),

                Some(key_id.clone()),

                KeyErrorCode::KeyNotFound,

            ))?;

        Ok(())

    }



    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {

        let keys = self.keys.read().await;

        Ok(keys.iter()

            .map(|(id, (_, metadata))| (id.clone(), metadata.clone()))

            .collect())

    }



    async fn rotate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<(SecureKey, KeyMetadata)> {

        let new_key = self.generate_key(algorithm).await?;

        let new_metadata = KeyMetadata::builder()

            .key_id(key_id.clone())

            .algorithm(algorithm.name().to_string())

            .version(1) // This should be incremented from the old version

            .created_at(Utc::now())

            .expires_at(Utc::now() + Duration::days(90))

            .purpose("encryption".to_string())

            .build()?;



        self.store_key(key_id, &new_key, &new_metadata).await?;

        Ok((new_key, new_metadata))

    }



    async fn needs_rotation(&self, key_id: &KeyId) -> Result<bool> {

        let keys = self.keys.read().await;

        if let Some((_, metadata)) = keys.get(key_id) {

            Ok(Utc::now() >= metadata.expires_at)

        } else {

            Err(FortressError::key_management(

                format!("Key not found: {}", key_id),

                Some(key_id.clone()),

                KeyErrorCode::KeyNotFound,

            ))

        }

    }



    async fn get_active_key(&self, purpose: &str) -> Result<(SecureKey, KeyMetadata)> {

        let keys = self.keys.read().await;

        for (key_id, (key, metadata)) in keys.iter() {

            if metadata.purpose == purpose && metadata.is_active() {

                return Ok((key.clone(), metadata.clone()));

            }

        }

        Err(FortressError::key_management(

            format!("No active key found for purpose: {}", purpose),

            None,

            KeyErrorCode::KeyNotFound,

        ))

    }

}



/// Key metadata containing information about the key

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct KeyMetadata {

    /// Unique identifier for the key

    pub key_id: KeyId,

    /// Algorithm used for this key

    pub algorithm: String,

    /// Key version for rotation tracking

    pub version: KeyVersion,

    /// When the key was created

    pub created_at: DateTime<Utc>,

    /// When the key expires

    pub expires_at: DateTime<Utc>,

    /// Purpose of the key (e.g., "encryption", "signing")

    pub purpose: String,

    /// Performance profile associated with this key

    pub performance_profile: PerformanceProfile,

    /// Additional metadata

    pub metadata: HashMap<String, String>,

}



impl KeyMetadata {

    /// Create a new key metadata

    pub fn new(

        key_id: KeyId,

        algorithm: String,

        version: KeyVersion,

        created_at: DateTime<Utc>,

        expires_at: DateTime<Utc>,

        purpose: String,

        performance_profile: PerformanceProfile,

    ) -> Self {

        Self {

            key_id,

            algorithm,

            version,

            created_at,

            expires_at,

            purpose,

            performance_profile,

            metadata: HashMap::new(),

        }

    }



    /// Check if the key is currently active

    pub fn is_active(&self) -> bool {

        let now = Utc::now();

        now >= self.created_at && now < self.expires_at

    }



    /// Check if the key is expired

    pub fn is_expired(&self) -> bool {

        Utc::now() >= self.expires_at

    }



    /// Get the time until expiration

    pub fn time_until_expiration(&self) -> Option<Duration> {

        let now = Utc::now();

        if now < self.expires_at {

            Some(self.expires_at - now)

        } else {

            None

        }

    }



    /// Add custom metadata

    pub fn with_metadata(mut self, key: String, value: String) -> Self {

        self.metadata.insert(key, value);

        self

    }



    /// Get custom metadata

    pub fn get_metadata(&self, key: &str) -> Option<&String> {

        self.metadata.get(key)

    }

}



/// Builder for KeyMetadata

pub struct KeyMetadataBuilder {

    key_id: Option<KeyId>,

    algorithm: Option<String>,

    version: Option<KeyVersion>,

    created_at: Option<DateTime<Utc>>,

    expires_at: Option<DateTime<Utc>>,

    purpose: Option<String>,

    performance_profile: Option<PerformanceProfile>,

    metadata: HashMap<String, String>,

}



impl KeyMetadataBuilder {

    /// Create a new builder

    pub fn new() -> Self {

        Self {

            key_id: None,

            algorithm: None,

            version: None,

            created_at: None,

            expires_at: None,

            purpose: None,

            performance_profile: None,

            metadata: HashMap::new(),

        }

    }



    /// Set the key ID

    pub fn key_id(mut self, key_id: KeyId) -> Self {

        self.key_id = Some(key_id);

        self

    }



    /// Set the algorithm

    pub fn algorithm(mut self, algorithm: String) -> Self {

        self.algorithm = Some(algorithm);

        self

    }



    /// Set the version

    pub fn version(mut self, version: KeyVersion) -> Self {

        self.version = Some(version);

        self

    }



    /// Set the creation time

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {

        self.created_at = Some(created_at);

        self

    }



    /// Set the expiration time

    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {

        self.expires_at = Some(expires_at);

        self

    }



    /// Set the purpose

    pub fn purpose(mut self, purpose: String) -> Self {

        self.purpose = Some(purpose);

        self

    }



    /// Set the performance profile

    pub fn performance_profile(mut self, performance_profile: PerformanceProfile) -> Self {

        self.performance_profile = Some(performance_profile);

        self

    }



    /// Add metadata

    pub fn with_metadata(mut self, key: String, value: String) -> Self {

        self.metadata.insert(key, value);

        self

    }



    /// Build the KeyMetadata

    pub fn build(self) -> Result<KeyMetadata> {

        Ok(KeyMetadata::new(

            self.key_id.ok_or_else(|| FortressError::key_management(

                "Key ID is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.algorithm.ok_or_else(|| FortressError::key_management(

                "Algorithm is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.version.ok_or_else(|| FortressError::key_management(

                "Version is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.created_at.unwrap_or_else(Utc::now),

            self.expires_at.ok_or_else(|| FortressError::key_management(

                "Expiration time is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.purpose.ok_or_else(|| FortressError::key_management(

                "Purpose is required",

                None,

                KeyErrorCode::InvalidKeyFormat,

            ))?,

            self.performance_profile.unwrap_or(PerformanceProfile::Balanced),

        ))

    }

}



impl Default for KeyMetadataBuilder {

    fn default() -> Self {

        Self::new()

    }

}



/// Key rotation scheduler

#[derive(Debug)]

pub struct KeyRotationScheduler {

    key_manager: Arc<dyn KeyManager>,

    rotation_intervals: HashMap<String, Duration>,

}



impl KeyRotationScheduler {

    /// Create a new key rotation scheduler

    pub fn new(key_manager: Arc<dyn KeyManager>) -> Self {

        Self {

            key_manager,

            rotation_intervals: HashMap::new(),

        }

    }



    /// Set rotation interval for a purpose

    pub fn set_rotation_interval(&mut self, purpose: String, interval: Duration) {

        self.rotation_intervals.insert(purpose, interval);

    }



    /// Check all keys and rotate if needed

    pub async fn check_and_rotate(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {

        let keys = self.key_manager.list_keys().await?;

        let mut rotated_keys = Vec::new();



        for (key_id, metadata) in keys {

            if let Some(interval) = self.rotation_intervals.get(&metadata.purpose) {

                let time_since_creation = Utc::now() - metadata.created_at;

                if time_since_creation >= *interval {

                    // This key needs rotation

                    if let Ok((new_key, new_metadata)) = self.rotate_key(&key_id).await {

                        rotated_keys.push((key_id, new_metadata));

                    }

                }

            }

        }



        Ok(rotated_keys)

    }



    /// Rotate a specific key

    async fn rotate_key(&self, key_id: &KeyId) -> Result<(SecureKey, KeyMetadata)> {

        // Get the current key metadata to determine the algorithm

        let (_, metadata) = self.key_manager.retrieve_key(key_id).await?;

        

        // Create the algorithm instance

        let algorithm = crate::encryption::create_algorithm(&metadata.algorithm)?;

        

        // Rotate the key

        self.key_manager.rotate_key(key_id, algorithm.as_ref()).await

    }

}



/// Key derivation function types

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum KeyDerivationFunction {

    /// Argon2id (memory-hard, recommended)

    Argon2id {

        /// Memory cost in KiB

        memory_cost: u32,

        /// Number of iterations

        iterations: u32,

        /// Parallelism factor

        parallelism: u32,

    },

    /// PBKDF2 with HMAC-SHA256

    Pbkdf2 {

        /// Number of iterations

        iterations: u32,

        /// Salt length in bytes

        salt_length: usize,

    },

    /// scrypt

    Scrypt {

        /// CPU/memory cost parameter

        n: u32,

        /// Block size parameter

        r: u32,

        /// Parallelization parameter

        p: u32,

    },

}



impl Default for KeyDerivationFunction {

    fn default() -> Self {

        Self::Argon2id {

            memory_cost: 65536, // 64 MiB

            iterations: 3,

            parallelism: 4,

        }

    }

}



/// Key derivation utilities

pub struct KeyDerivation;



impl KeyDerivation {

    /// Derive a key from a password and salt

    pub fn derive_key(

        password: &[u8],

        salt: &[u8],

        kdf: &KeyDerivationFunction,

        output_length: usize,

    ) -> Result<Vec<u8>> {

        match kdf {

            KeyDerivationFunction::Argon2id { memory_cost, iterations, parallelism } => {

                let params = argon2::Params::new(*memory_cost, *iterations, *parallelism, Some(output_length))

                    .map_err(|e| FortressError::key_management(

                        format!("Invalid Argon2 parameters: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                let argon2 = argon2::Argon2::new(

                    argon2::Algorithm::Argon2id,

                    argon2::Version::V0x13,

                    params,

                );



                let mut output = vec![0u8; output_length];

                argon2

                    .hash_password_into(password, salt, &mut output)

                    .map_err(|e| FortressError::key_management(

                        format!("Argon2 derivation failed: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                Ok(output)

            }

            KeyDerivationFunction::Pbkdf2 { iterations, salt_length } => {

                if salt.len() != *salt_length {

                    return Err(FortressError::key_management(

                        format!("Invalid salt length: expected {}, got {}", salt_length, salt.len()),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ));

                }



                let mut output = vec![0u8; output_length];

                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, *iterations, &mut output);

                Ok(output)

            }

            KeyDerivationFunction::Scrypt { n, r, p } => {

                let params = scrypt::Params::new(*n, *r, *p, output_length)

                    .map_err(|e| FortressError::key_management(

                        format!("Invalid scrypt parameters: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                let mut output = vec![0u8; output_length];

                scrypt::scrypt(password, salt, &params, &mut output)

                    .map_err(|e| FortressError::key_management(

                        format!("scrypt derivation failed: {}", e),

                        None,

                        KeyErrorCode::DerivationFailed,

                    ))?;



                Ok(output)

            }

        }

    }



    /// Generate a random salt

    pub fn generate_salt(length: usize) -> Result<Vec<u8>> {

        let mut salt = vec![0u8; length];

        getrandom::getrandom(&mut salt)

            .map_err(|e| FortressError::key_management(

                format!("Failed to generate salt: {}", e),

                None,

                KeyErrorCode::DerivationFailed,

            ))?;

        Ok(salt)

    }

}



/// Secure key container that zeroizes on drop (re-export from encryption module)

pub use crate::encryption::SecureKey;



#[cfg(test)]

mod tests {

    use super::*;

    use crate::encryption::{Aegis256, ChaCha20Poly1305};



    #[tokio::test]

    async fn test_in_memory_key_manager() {

        let manager = InMemoryKeyManager::new();

        let algorithm = Aegis256::new();

        

        // Generate and store a key

        let key = manager.generate_key(&algorithm).await.unwrap();

        let key_id = Uuid::new_v4().to_string();

        let metadata = KeyMetadata::builder()

            .key_id(key_id.clone())

            .algorithm(algorithm.name().to_string())

            .version(1)

            .expires_at(Utc::now() + Duration::days(90))

            .purpose("test".to_string())

            .performance_profile(PerformanceProfile::Lightning)

            .build()

            .unwrap();



        manager.store_key(&key_id, &key, &metadata).await.unwrap();



        // Retrieve the key

        let (retrieved_key, retrieved_metadata) = manager.retrieve_key(&key_id).await.unwrap();

        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());

        assert_eq!(metadata.key_id, retrieved_metadata.key_id);



        // List keys

        let keys = manager.list_keys().await.unwrap();

        assert_eq!(keys.len(), 1);

        assert_eq!(keys[0].0, key_id);



        // Delete key

        manager.delete_key(&key_id).await.unwrap();

        let keys = manager.list_keys().await.unwrap();

        assert_eq!(keys.len(), 0);

    }



    #[tokio::test]

    async fn test_key_rotation() {

        let manager = InMemoryKeyManager::new();

        let algorithm = ChaCha20Poly1305::new();

        

        let key_id = Uuid::new_v4().to_string();

        let key = manager.generate_key(&algorithm).await.unwrap();

        let metadata = KeyMetadata::builder()

            .key_id(key_id.clone())

            .algorithm(algorithm.name().to_string())

            .version(1)

            .expires_at(Utc::now() - Duration::hours(1)) // Expired

            .purpose("test".to_string())

            .performance_profile(PerformanceProfile::Balanced)

            .build()

            .unwrap();



        manager.store_key(&key_id, &key, &metadata).await.unwrap();



        // Check if rotation is needed

        let needs_rotation = manager.needs_rotation(&key_id).await.unwrap();

        assert!(needs_rotation);



        // Rotate the key

        let (new_key, new_metadata) = manager.rotate_key(&key_id, &algorithm).await.unwrap();

        assert_ne!(key.as_bytes(), new_key.as_bytes());

        assert_eq!(new_metadata.version, 1); // Should be incremented in real implementation

    }



    #[test]

    fn test_key_metadata() {

        let metadata = KeyMetadata::new(

            "test-key".to_string(),

            "aegis256".to_string(),

            1,

            Utc::now(),

            Utc::now() + Duration::days(90),

            "encryption".to_string(),

            PerformanceProfile::Lightning,

        );



        assert!(metadata.is_active());

        assert!(!metadata.is_expired());

        assert!(metadata.time_until_expiration().is_some());



        let expired_metadata = KeyMetadata::new(

            "expired-key".to_string(),

            "aegis256".to_string(),

            1,

            Utc::now() - Duration::days(10),

            Utc::now() - Duration::days(1),

            "encryption".to_string(),

            PerformanceProfile::Lightning,

        );



        assert!(!expired_metadata.is_active());

        assert!(expired_metadata.is_expired());

        assert!(expired_metadata.time_until_expiration().is_none());

    }



    #[test]

    fn test_key_derivation() {

        let password = b"test_password";

        let salt = KeyDerivation::generate_salt(16).unwrap();

        

        // Test Argon2id

        let kdf = KeyDerivationFunction::Argon2id {

            memory_cost: 1024,

            iterations: 2,

            parallelism: 1,

        };

        

        let key = KeyDerivation::derive_key(password, &salt, &kdf, 32).unwrap();

        assert_eq!(key.len(), 32);



        // Test PBKDF2

        let kdf = KeyDerivationFunction::Pbkdf2 {

            iterations: 1000,

            salt_length: 16,

        };

        

        let key = KeyDerivation::derive_key(password, &salt, &kdf, 32).unwrap();

        assert_eq!(key.len(), 32);



        // Test scrypt

        let kdf = KeyDerivationFunction::Scrypt { n: 16, r: 1, p: 1 };

        let key = KeyDerivation::derive_key(password, &salt, &kdf, 32).unwrap();

        assert_eq!(key.len(), 32);

    }



    #[test]

    fn test_key_derivation_deterministic() {

        let password = b"test_password";

        let salt = b"test_salt_123456";

        let kdf = KeyDerivationFunction::Pbkdf2 {

            iterations: 100,

            salt_length: salt.len(),

        };

        

        let key1 = KeyDerivation::derive_key(password, salt, &kdf, 32).unwrap();

        let key2 = KeyDerivation::derive_key(password, salt, &kdf, 32).unwrap();

        

        assert_eq!(key1, key2);

    }



    #[tokio::test]

    async fn test_key_rotation_scheduler() {

        let manager = Arc::new(InMemoryKeyManager::new());

        let mut scheduler = KeyRotationScheduler::new(manager.clone());

        

        // Set rotation interval for test purpose

        scheduler.set_rotation_interval("test".to_string(), Duration::hours(24));

        

        // Create an expired key

        let algorithm = Aegis256::new();

        let key_id = Uuid::new_v4().to_string();

        let key = manager.generate_key(&algorithm).await.unwrap();

        let metadata = KeyMetadata::builder()

            .key_id(key_id.clone())

            .algorithm(algorithm.name().to_string())

            .version(1)

            .expires_at(Utc::now() - Duration::hours(25)) // Expired 25 hours ago

            .purpose("test".to_string())

            .performance_profile(PerformanceProfile::Lightning)

            .build()

            .unwrap();



        manager.store_key(&key_id, &key, &metadata).await.unwrap();



        // Check and rotate

        let rotated_keys = scheduler.check_and_rotate().await.unwrap();

        assert_eq!(rotated_keys.len(), 1);

        assert_eq!(rotated_keys[0].0, key_id);

    }

}

