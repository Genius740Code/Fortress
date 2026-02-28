//! Smart key rotation system tests

use crate::key::{
    KeyManager, KeyMetadata, SecureKey, SmartKeyRotationScheduler, 
    RotationInterval, RotationMetrics, InMemoryKeyManager
};
use crate::encryption::{create_algorithm, EncryptionAlgorithm};
use crate::error::Result;

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock key manager for testing
    struct MockKeyManager {
        keys: Arc<RwLock<HashMap<String, (SecureKey, KeyMetadata)>>>,
    }

    impl MockKeyManager {
        fn new() -> Self {
            Self {
                keys: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        async fn add_test_key(&self, purpose: &str, created_hours_ago: i64) -> String {
            let key_id = Uuid::new_v4().to_string();
            let algorithm = create_algorithm("AES256-GCM").unwrap();
            let key = SecureKey::generate(algorithm.key_size());
            
            let created_at = Utc::now() - Duration::hours(created_hours_ago);
            let expires_at = created_at + Duration::days(90);
            
            let metadata = KeyMetadata::new(
                key_id.clone(),
                "AES256-GCM".to_string(),
                1,
                created_at,
                expires_at,
                purpose.to_string(),
                Default::default(),
            );

            let mut keys = self.keys.write().await;
            keys.insert(key_id.clone(), (key, metadata));
            key_id
        }
    }

    #[async_trait::async_trait]
    impl KeyManager for MockKeyManager {
        async fn generate_key(&self, algorithm: &dyn EncryptionAlgorithm) -> Result<SecureKey> {
            Ok(SecureKey::generate(algorithm.key_size()))
        }

        async fn store_key(&self, key_id: &str, key: &SecureKey, metadata: &KeyMetadata) -> Result<()> {
            let mut keys = self.keys.write().await;
            keys.insert(key_id.to_string(), (key.clone(), metadata.clone()));
            Ok(())
        }

        async fn retrieve_key(&self, key_id: &str) -> Result<(SecureKey, KeyMetadata)> {
            let keys = self.keys.read().await;
            keys.get(key_id)
                .cloned()
                .ok_or_else(|| crate::error::FortressError::key_management(
                    format!("Key not found: {}", key_id),
                    Some(key_id.to_string()),
                    crate::error::KeyErrorCode::KeyNotFound,
                ))
        }

        async fn delete_key(&self, key_id: &str) -> Result<()> {
            let mut keys = self.keys.write().await;
            keys.remove(key_id).ok_or_else(|| crate::error::FortressError::key_management(
                format!("Key not found: {}", key_id),
                Some(key_id.to_string()),
                crate::error::KeyErrorCode::KeyNotFound,
            ))?;
            Ok(())
        }

        async fn list_keys(&self) -> Result<Vec<(String, KeyMetadata)>> {
            let keys = self.keys.read().await;
            Ok(keys.iter()
                .map(|(id, (_, metadata))| (id.clone(), metadata.clone()))
                .collect())
        }

        async fn rotate_key(&self, key_id: &str, algorithm: &dyn EncryptionAlgorithm) -> Result<(SecureKey, KeyMetadata)> {
            let new_key = self.generate_key(algorithm).await?;
            let (_, old_metadata) = self.retrieve_key(key_id).await?;
            
            let new_metadata = KeyMetadata::new(
                key_id.to_string(),
                algorithm.name().to_string(),
                old_metadata.version + 1,
                Utc::now(),
                Utc::now() + Duration::days(90),
                old_metadata.purpose.clone(),
                old_metadata.performance_profile,
            );

            self.store_key(key_id, &new_key, &new_metadata).await?;
            Ok((new_key, new_metadata))
        }

        async fn needs_rotation(&self, key_id: &str) -> Result<bool> {
            let (_, metadata) = self.retrieve_key(key_id).await?;
            Ok(Utc::now() >= metadata.expires_at)
        }

        async fn get_active_key(&self, purpose: &str) -> Result<(SecureKey, KeyMetadata)> {
            let keys = self.keys.read().await;
            for (_key_id, (key, metadata)) in keys.iter() {
                if metadata.purpose == purpose && metadata.is_active() {
                    return Ok((key.clone(), metadata.clone()));
                }
            }
            Err(crate::error::FortressError::key_management(
                format!("No active key found for purpose: {}", purpose),
                None,
                crate::error::KeyErrorCode::KeyNotFound,
            ))
        }
    }

    #[tokio::test]
    async fn test_rotation_interval_durations() {
        assert_eq!(RotationInterval::Hour23.duration(), Duration::hours(23));
        assert_eq!(RotationInterval::Days7.duration(), Duration::days(7));
        assert_eq!(RotationInterval::Days30.duration(), Duration::days(30));
        assert_eq!(RotationInterval::Days90.duration(), Duration::days(90));
        
        let custom = RotationInterval::Custom(Duration::hours(48));
        assert_eq!(custom.duration(), Duration::hours(48));
    }

    #[tokio::test]
    async fn test_scheduler_initialization() {
        let key_manager = Arc::new(MockKeyManager::new());
        let scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        // Test default configuration
        let metrics = scheduler.get_metrics().await;
        assert_eq!(metrics.total_rotations, 0);
        assert_eq!(metrics.successful_rotations, 0);
        assert_eq!(metrics.failed_rotations, 0);
    }

    #[tokio::test]
    async fn test_security_level_intervals() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager);
        
        scheduler.set_security_level_intervals();
        
        assert_eq!(
            scheduler.get_rotation_interval("high_security"),
            Some(&RotationInterval::Hour23)
        );
        assert_eq!(
            scheduler.get_rotation_interval("sensitive"),
            Some(&RotationInterval::Days7)
        );
        assert_eq!(
            scheduler.get_rotation_interval("standard"),
            Some(&RotationInterval::Days30)
        );
        assert_eq!(
            scheduler.get_rotation_interval("low_sensitivity"),
            Some(&RotationInterval::Days90)
        );
    }

    #[tokio::test]
    async fn test_23_hour_rotation() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        // Set 23-hour rotation for high security keys
        scheduler.set_rotation_interval("high_security".to_string(), RotationInterval::Hour23);
        
        // Add a key created 24 hours ago (should need rotation)
        let key_id = key_manager.add_test_key("high_security", 24).await;
        
        // Check and rotate
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 1);
        assert_eq!(rotated_keys[0].0, key_id);
        
        // Verify metrics
        let metrics = scheduler.get_metrics().await;
        assert_eq!(metrics.total_rotations, 1);
        assert_eq!(metrics.successful_rotations, 1);
    }

    #[tokio::test]
    async fn test_7_day_rotation() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        scheduler.set_rotation_interval("sensitive".to_string(), RotationInterval::Days7);
        
        // Add a key created 8 days ago (should need rotation)
        let key_id = key_manager.add_test_key("sensitive", 24 * 8).await;
        
        // Add a key created 6 days ago (should not need rotation)
        key_manager.add_test_key("sensitive", 24 * 6).await;
        
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 1);
        assert_eq!(rotated_keys[0].0, key_id);
    }

    #[tokio::test]
    async fn test_30_day_rotation() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        scheduler.set_rotation_interval("standard".to_string(), RotationInterval::Days30);
        
        // Add a key created 31 days ago (should need rotation)
        let key_id = key_manager.add_test_key("standard", 24 * 31).await;
        
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 1);
        assert_eq!(rotated_keys[0].0, key_id);
    }

    #[tokio::test]
    async fn test_90_day_rotation() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        scheduler.set_rotation_interval("low_sensitivity".to_string(), RotationInterval::Days90);
        
        // Add a key created 91 days ago (should need rotation)
        let key_id = key_manager.add_test_key("low_sensitivity", 24 * 91).await;
        
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 1);
        assert_eq!(rotated_keys[0].0, key_id);
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let key_manager = Arc::new(MockKeyManager::new());
        let scheduler = SmartKeyRotationScheduler::with_config(
            key_manager.clone(),
            2, // batch size
            5, // max concurrent rotations
        );
        
        let mut scheduler_mut = SmartKeyRotationScheduler::with_config(
            key_manager.clone(),
            2,
            5,
        );
        scheduler_mut.set_rotation_interval("high_security".to_string(), RotationInterval::Hour23);
        
        // Add multiple keys that need rotation
        let mut key_ids = Vec::new();
        for i in 0..5 {
            let key_id = key_manager.add_test_key("high_security", 24).await;
            key_ids.push(key_id);
        }
        
        let rotated_keys = scheduler_mut.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 5);
        
        // Verify all keys were rotated
        let metrics = scheduler_mut.get_metrics().await;
        assert_eq!(metrics.total_rotations, 5);
        assert_eq!(metrics.successful_rotations, 5);
    }

    #[tokio::test]
    async fn test_soon_rotation_prediction() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        scheduler.set_rotation_interval("high_security".to_string(), RotationInterval::Hour23);
        
        // Add a key that will need rotation in 2 hours
        key_manager.add_test_key("high_security", 21).await;
        
        // Add a key that will need rotation in 25 hours (outside prediction window)
        key_manager.add_test_key("high_security", 1).await;
        
        let soon_keys = scheduler.get_keys_needing_soon_rotation(24).await.unwrap();
        assert_eq!(soon_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_force_rotation() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        scheduler.set_rotation_interval("standard".to_string(), RotationInterval::Days30);
        
        // Add a fresh key (should not need rotation normally)
        let key_id = key_manager.add_test_key("standard", 1).await;
        
        // Force rotate it
        let (new_key, new_metadata) = scheduler.force_rotate_key(&key_id).await.unwrap();
        
        // Verify the key was updated
        assert_eq!(new_metadata.version, 2); // Should be incremented
        
        let metrics = scheduler.get_metrics().await;
        assert_eq!(metrics.total_rotations, 1);
    }

    #[tokio::test]
    async fn test_cache_performance() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        scheduler.set_rotation_interval("high_security".to_string(), RotationInterval::Hour23);
        
        // Add a key that needs rotation
        key_manager.add_test_key("high_security", 24).await;
        
        // First check should find and rotate the key
        let rotated_keys1 = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys1.len(), 1);
        
        // Second check should not rotate again due to cache
        let rotated_keys2 = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys2.len(), 0);
        
        // Clear cache and check again
        scheduler.clear_cache().await;
        let rotated_keys3 = scheduler.check_and_rotate().await.unwrap();
        // Should still be 0 because the key was just rotated
        assert_eq!(rotated_keys3.len(), 0);
    }

    #[tokio::test]
    async fn test_custom_intervals() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        // Set custom 48-hour interval
        let custom_interval = RotationInterval::Custom(Duration::hours(48));
        scheduler.set_rotation_interval("custom".to_string(), custom_interval);
        
        // Add a key created 49 hours ago (should need rotation)
        let key_id = key_manager.add_test_key("custom", 49).await;
        
        // Add a key created 47 hours ago (should not need rotation)
        key_manager.add_test_key("custom", 47).await;
        
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 1);
        assert_eq!(rotated_keys[0].0, key_id);
    }

    #[tokio::test]
    async fn test_metrics_tracking() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        scheduler.set_rotation_interval("high_security".to_string(), RotationInterval::Hour23);
        
        // Add and rotate multiple keys
        for _ in 0..3 {
            key_manager.add_test_key("high_security", 24).await;
        }
        
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 3);
        
        let metrics = scheduler.get_metrics().await;
        assert_eq!(metrics.total_rotations, 3);
        assert_eq!(metrics.successful_rotations, 3);
        assert_eq!(metrics.failed_rotations, 0);
        assert!(metrics.last_rotation_time.is_some());
        assert!(metrics.average_rotation_time_ms > 0);
    }

    #[tokio::test]
    async fn test_mixed_security_levels() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::new(key_manager.clone());
        
        // Set up all security levels
        scheduler.set_security_level_intervals();
        
        // Add keys for each security level with different ages
        let high_sec_key = key_manager.add_test_key("high_security", 24); // 23h interval - should rotate
        let sensitive_key = key_manager.add_test_key("sensitive", 24 * 8); // 7d interval - should rotate
        let standard_key = key_manager.add_test_key("standard", 24 * 31); // 30d interval - should rotate
        let low_sec_key = key_manager.add_test_key("low_sensitivity", 24 * 91); // 90d interval - should rotate
        
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        assert_eq!(rotated_keys.len(), 4);
        
        // Verify all keys were rotated
        let rotated_ids: Vec<_> = rotated_keys.iter().map(|(id, _)| id).collect();
        assert!(rotated_ids.contains(&high_sec_key));
        assert!(rotated_ids.contains(&sensitive_key));
        assert!(rotated_ids.contains(&standard_key));
        assert!(rotated_ids.contains(&low_sec_key));
    }

    #[tokio::test]
    async fn test_performance_with_large_keyset() {
        let key_manager = Arc::new(MockKeyManager::new());
        let mut scheduler = SmartKeyRotationScheduler::with_config(
            key_manager.clone(),
            50,  // batch size
            20,  // max concurrent rotations
        );
        
        scheduler.set_rotation_interval("standard".to_string(), RotationInterval::Days30);
        
        // Add 100 keys that need rotation
        for _ in 0..100 {
            key_manager.add_test_key("standard", 24 * 31).await;
        }
        
        let start = std::time::Instant::now();
        let rotated_keys = scheduler.check_and_rotate().await.unwrap();
        let duration = start.elapsed();
        
        assert_eq!(rotated_keys.len(), 100);
        assert!(duration.as_millis() < 5000); // Should complete within 5 seconds
        
        let metrics = scheduler.get_metrics().await;
        assert_eq!(metrics.total_rotations, 100);
        assert_eq!(metrics.successful_rotations, 100);
    }
}
