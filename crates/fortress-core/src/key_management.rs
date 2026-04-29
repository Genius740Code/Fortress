//! Unified Key Management Interface
//!
//! This module provides a unified interface to all key management functionality
//! in Fortress, making it easier for CLI tools and other components to interact
//! with the key system without needing to know about specific implementations.

use crate::error::Result;
use crate::key::{KeyManager, KeyId, KeyMetadata};
use crate::database_key_manager::{DatabaseKeyManager, DatabaseKeyManagerConfig};
use async_trait::async_trait;
use std::sync::Arc;

/// Unified key manager that provides a simple interface to all key operations
pub struct UnifiedKeyManager {
    /// The underlying database key manager
    inner: Arc<DatabaseKeyManager>,
}

impl UnifiedKeyManager {
    /// Create a new unified key manager with default configuration
    pub async fn new() -> Result<Self> {
        let config = DatabaseKeyManagerConfig::default();
        let manager = DatabaseKeyManager::new(config).await?;
        Ok(Self {
            inner: Arc::new(manager),
        })
    }

    /// Create a new unified key manager with custom configuration
    pub async fn with_config(config: DatabaseKeyManagerConfig) -> Result<Self> {
        let manager = DatabaseKeyManager::new(config).await?;
        Ok(Self {
            inner: Arc::new(manager),
        })
    }

    /// Get all key IDs as strings for CLI completion
    pub async fn list_key_ids(&self) -> Result<Vec<String>> {
        let keys = self.inner.list_keys().await?;
        Ok(keys.into_iter().map(|(id, _)| id.to_string()).collect())
    }

    /// Get all key IDs with their metadata for richer completions
    pub async fn list_keys_with_metadata(&self) -> Result<Vec<(String, KeyMetadata)>> {
        let keys = self.inner.list_keys().await?;
        Ok(keys.into_iter()
            .map(|(id, metadata)| (id.to_string(), metadata))
            .collect())
    }

    /// Filter keys by algorithm type
    pub async fn list_keys_by_algorithm(&self, algorithm: &str) -> Result<Vec<String>> {
        let keys = self.inner.list_keys().await?;
        Ok(keys.into_iter()
            .filter(|(_, metadata)| metadata.algorithm.to_lowercase().contains(&algorithm.to_lowercase()))
            .map(|(id, _)| id.to_string())
            .collect())
    }

    /// Get keys that are currently active (not expired)
    pub async fn list_active_keys(&self) -> Result<Vec<String>> {
        let keys = self.inner.list_keys().await?;
        let now = chrono::Utc::now();
        Ok(keys.into_iter()
            .filter(|(_, metadata)| {
                metadata.expires_at > now
            })
            .map(|(id, _)| id.to_string())
            .collect())
    }
}

#[async_trait]
impl KeyManager for UnifiedKeyManager {
    async fn generate_key(&self, algorithm: &dyn crate::encryption::EncryptionAlgorithm) -> Result<crate::key::SecureKey> {
        self.inner.generate_key(algorithm).await
    }

    async fn store_key(&self, key_id: &KeyId, key: &crate::key::SecureKey, metadata: &KeyMetadata) -> Result<()> {
        self.inner.store_key(key_id, key, metadata).await
    }

    async fn retrieve_key(&self, key_id: &KeyId) -> Result<(crate::key::SecureKey, KeyMetadata)> {
        self.inner.retrieve_key(key_id).await
    }

    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        self.inner.delete_key(key_id).await
    }

    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        self.inner.list_keys().await
    }

    async fn rotate_key(&self, key_id: &KeyId, algorithm: &dyn crate::encryption::EncryptionAlgorithm) -> Result<()> {
        self.inner.rotate_key(key_id, algorithm).await
    }

    async fn rotate_key_with_zero_downtime(&self, key_id: &KeyId, algorithm: &dyn crate::encryption::EncryptionAlgorithm) -> Result<()> {
        self.inner.rotate_key_with_zero_downtime(key_id, algorithm).await
    }

    async fn key_exists(&self, key_id: &KeyId) -> Result<bool> {
        self.inner.key_exists(key_id).await
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata> {
        self.inner.get_key_metadata(key_id).await
    }

    async fn get_active_key_version(&self, key_id: &KeyId) -> Result<u32> {
        self.inner.get_active_key_version(key_id).await
    }

    async fn initiate_key_transition(&self, key_id: &KeyId, algorithm: &dyn crate::encryption::EncryptionAlgorithm) -> Result<u32> {
        self.inner.initiate_key_transition(key_id, algorithm).await
    }

    async fn complete_key_transition(&self, key_id: &KeyId, new_version: u32) -> Result<()> {
        self.inner.complete_key_transition(key_id, new_version).await
    }

    async fn validate_dual_keys(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<bool> {
        self.inner.validate_dual_keys(key_id, old_version, new_version).await
    }

    async fn rollback_key_transition(&self, key_id: &KeyId, old_version: u32, new_version: u32) -> Result<()> {
        self.inner.rollback_key_transition(key_id, old_version, new_version).await
    }

    async fn needs_rotation(&self, key_id: &KeyId) -> Result<bool> {
        self.inner.needs_rotation(key_id).await
    }

    async fn get_active_key(&self, purpose: &str) -> Result<(crate::key::SecureKey, KeyMetadata)> {
        self.inner.get_active_key(purpose).await
    }

    async fn validate_new_key(&self, new_versioned_id: &KeyId) -> Result<()> {
        self.inner.validate_new_key(new_versioned_id).await
    }

    async fn validate_post_switch(&self, key_id: &KeyId, expected_version: u32) -> Result<()> {
        self.inner.validate_post_switch(key_id, expected_version).await
    }

    async fn perform_key_transition_initiation(&self, key_id: &KeyId, algorithm: &dyn crate::encryption::EncryptionAlgorithm) -> Result<u32> {
        self.inner.perform_key_transition_initiation(key_id, algorithm).await
    }
}

/// Convenience function to create a key manager for CLI usage
pub async fn create_cli_key_manager() -> Result<UnifiedKeyManager> {
    UnifiedKeyManager::new().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aegis256;

    #[tokio::test]
    async fn test_list_key_ids() {
        let manager = UnifiedKeyManager::new().await.unwrap();
        
        // Generate a test key
        let algorithm = Aegis256::new();
        let key = manager.generate_key(&algorithm).await.unwrap();
        let key_id = KeyId::new();
        let metadata = KeyMetadata::new(&algorithm);
        
        // Store the key
        manager.store_key(&key_id, &key, &metadata).await.unwrap();
        
        // List key IDs
        let key_ids = manager.list_key_ids().await.unwrap();
        assert!(!key_ids.is_empty());
        assert!(key_ids.contains(&key_id.to_string()));
        
        // Clean up
        manager.delete_key(&key_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_list_keys_by_algorithm() {
        let manager = UnifiedKeyManager::new().await.unwrap();
        
        // Generate test keys with different algorithms
        let algorithm1 = Aegis256::new();
        let key1 = manager.generate_key(&algorithm1).await.unwrap();
        let key_id1 = KeyId::new();
        let metadata1 = KeyMetadata::new(&algorithm1);
        
        manager.store_key(&key_id1, &key1, &metadata1).await.unwrap();
        
        // List keys by algorithm
        let aegis_keys = manager.list_keys_by_algorithm("aegis").await.unwrap();
        assert!(!aegis_keys.is_empty());
        assert!(aegis_keys.contains(&key_id1.to_string()));
        
        // Clean up
        manager.delete_key(&key_id1).await.unwrap();
    }
}
