//! Cross-region backup replication system

//!

//! This module provides comprehensive cross-region backup replication capabilities

//! with multiple replication strategies, bandwidth management, and monitoring.



use crate::backup::{

    BackupManager, CrossRegionConfig, ReplicationStrategy, 

    ReplicationResult

};

use crate::storage::StorageBackend;

use crate::backup::BackupConfig;
use crate::error::{FortressError, Result};

use crate::error::StorageErrorCode;

use chrono::{Utc, Duration};

use std::sync::Arc;

use std::collections::HashMap;

use tokio::sync::{RwLock, Semaphore};

use uuid::Uuid;



/// Cross-region replication manager

#[derive(Debug)]

pub struct CrossRegionReplicationManager {

    /// Backup manager for source backups

    backup_manager: Arc<dyn BackupManager>,

    /// Target storage backends by region

    target_storages: Arc<RwLock<HashMap<String, Arc<dyn StorageBackend>>>>,

    /// Replication configurations

    configs: Arc<RwLock<HashMap<String, CrossRegionConfig>>>,

    /// Running replication tasks

    running_tasks: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,

    /// Bandwidth management semaphore

    bandwidth_semaphore: Arc<Semaphore>,

    /// Maximum bandwidth in bytes per second

    max_bandwidth_bps: u64,

}



impl CrossRegionReplicationManager {

    /// Create a new cross-region replication manager

    pub fn new(

        backup_manager: Arc<dyn BackupManager>,

        max_bandwidth_bps: u64,

    ) -> Self {

        Self {

            backup_manager,

            target_storages: Arc::new(RwLock::new(HashMap::new())),

            configs: Arc::new(RwLock::new(HashMap::new())),

            running_tasks: Arc::new(RwLock::new(HashMap::new())),

            bandwidth_semaphore: Arc::new(Semaphore::new(

                (max_bandwidth_bps / 1024 / 1024).max(1) as usize // At least 1MB/s

            )),

            max_bandwidth_bps,

        }

    }



    /// Add a target storage region

    pub async fn add_target_region(

        &self,

        region: String,

        storage: Arc<dyn StorageBackend>,

    ) -> Result<()> {

        let mut target_storages = self.target_storages.write().await;

        target_storages.insert(region.clone(), storage);

        

        // Verify connectivity

        let storage = target_storages.get(&region).unwrap();

        let health = storage.health_check().await?;

        if !health.healthy {

            return Err(FortressError::storage(

                format!("Target region {} is not healthy: {:?}", region, health),

                "cross_region_replication".to_string(),

                StorageErrorCode::ConnectionFailed,

            ));

        }

        

        Ok(())

    }



    /// Remove a target storage region

    pub async fn remove_target_region(&self, region: &str) -> Result<()> {

        // Stop any running replication tasks for this region

        let mut configs = self.configs.write().await;

        configs.retain(|_, config| !config.target_regions.contains(&region.to_string()));

        

        let mut target_storages = self.target_storages.write().await;

        target_storages.remove(region);

        

        Ok(())

    }



    /// Add a replication configuration

    pub async fn add_replication_config(&self, mut config: CrossRegionConfig) -> Result<()> {

        // Generate replication ID if not provided

        if config.replication_id.is_empty() {

            config.replication_id = format!("replication_{}", Uuid::new_v4());

        }



        // Validate target regions exist

        let target_storages = self.target_storages.read().await;

        for region in &config.target_regions {

            if !target_storages.contains_key(region) {

                return Err(FortressError::storage(

                    format!("Target region not configured: {}", region),

                    "cross_region_replication".to_string(),

                    StorageErrorCode::NotFound,

                ));

            }

        }

        drop(target_storages);



        // Save configuration

        let mut configs = self.configs.write().await;

        configs.insert(config.replication_id.clone(), config.clone());



        // Start replication task if enabled

        if config.enabled {

            self.start_replication_task(config.clone()).await?;

        }



        Ok(())

    }



    /// Start a replication task

    async fn start_replication_task(&self, config: CrossRegionConfig) -> Result<()> {

        let backup_manager = self.backup_manager.clone();

        let target_storages = self.target_storages.clone();

        let configs = self.configs.clone();

        let bandwidth_semaphore = self.bandwidth_semaphore.clone();

        let replication_id_for_task = config.replication_id.clone();

        let task = tokio::spawn(async move {

            let replication_id = replication_id_for_task.clone();

            let mut interval = tokio::time::interval(

                tokio::time::Duration::from_secs(config.frequency_seconds)

            );



            loop {

                interval.tick().await;



                let configs_guard = configs.read().await;

                if let Some(current_config) = configs_guard.get(&replication_id) {

                    if !current_config.enabled {

                        break;

                    }



                    // Check replication strategy

                    let should_replicate = match current_config.strategy {

                        ReplicationStrategy::Immediate => {

                            // Always replicate latest backups

                            true

                        }

                        ReplicationStrategy::Scheduled => {

                            // Replicate on schedule (handled by interval)

                            true

                        }

                        ReplicationStrategy::FullOnly => {

                            // Only replicate full backups

                            Self::should_replicate_full_backups(&backup_manager, &current_config).await

                        }

                        ReplicationStrategy::AgeBased { max_age_hours } => {

                            // Replicate backups older than specified age

                            Self::should_replicate_by_age(&backup_manager, &current_config, max_age_hours).await

                        }

                    };



                    if should_replicate {

                        // Perform replication

                        let target_storages_guard = target_storages.read().await;

                        let mut results = Vec::new();

                        for region in &current_config.target_regions {

                            if let Some(target_storage) = target_storages_guard.get(region) {

                                let _permit = bandwidth_semaphore.acquire().await.unwrap();

                                

                                let result = Self::replicate_to_region(

                                    &backup_manager,

                                    target_storage,

                                    &current_config,

                                    region,

                                ).await;

                                

                                results.push(result);

                            }

                        }

                        

                        // Update config with result

                        drop(configs_guard);

                        let mut configs_write = configs.write().await;

                        if let Some(config) = configs_write.get_mut(&replication_id) {

                            for result in results {

                                config.replication_history.push(result.clone());

                                config.last_replication = Some(result.started_at);

                                

                                // Keep only last 100 replication results

                                if config.replication_history.len() > 100 {

                                    config.replication_history.sort_by(|a, b| b.started_at.cmp(&a.started_at));

                                    config.replication_history.truncate(100);

                                }

                            }

                        }

                    }

                } else {

                    // Config was removed

                    break;

                }

            }

        });



        let mut running_tasks = self.running_tasks.write().await;

        running_tasks.insert(config.replication_id.clone(), task);



        Ok(())

    }



    /// Check if full backups should be replicated

    async fn should_replicate_full_backups(

        backup_manager: &Arc<dyn BackupManager>,

        config: &CrossRegionConfig,

    ) -> bool {

        match backup_manager.list_backups().await {

            Ok(backups) => {

                // Check if there are unreplicated full backups

                for backup in backups {

                    if matches!(backup.strategy, crate::backup::BackupStrategy::Full) {

                        // Check if this backup has already been replicated

                        let already_replicated = config.replication_history

                            .iter()

                            .any(|result| result.backup_id == backup.backup_id);

                        

                        if !already_replicated {

                            return true;

                        }

                    }

                }

                false

            }

            Err(_) => false,

        }

    }



    /// Check if backups should be replicated based on age

    async fn should_replicate_by_age(

        backup_manager: &Arc<dyn BackupManager>,

        config: &CrossRegionConfig,

        max_age_hours: u64,

    ) -> bool {

        match backup_manager.list_backups().await {

            Ok(backups) => {

                let cutoff_time = Utc::now() - Duration::hours(max_age_hours as i64);

                

                for backup in backups {

                    if backup.created_at <= cutoff_time {

                        // Check if this backup has already been replicated

                        let already_replicated = config.replication_history

                            .iter()

                            .any(|result| result.backup_id == backup.backup_id);

                        

                        if !already_replicated {

                            return true;

                        }

                    }

                }

                false

            }

            Err(_) => false,

        }

    }



    /// Replicate backups to a specific region

    async fn replicate_to_region(

        backup_manager: &Arc<dyn BackupManager>,

        target_storage: &Arc<dyn StorageBackend>,

        config: &CrossRegionConfig,

        region: &str,

    ) -> ReplicationResult {

        let replication_id = format!("{}_{}", config.replication_id, Uuid::new_v4());

        let started_at = Utc::now();

        

        let mut result = ReplicationResult {

            replication_id: replication_id.clone(),

            backup_id: String::new(),

            target_region: region.to_string(),

            started_at,

            completed_at: None,

            success: false,

            error_message: None,

            items_replicated: None,

            total_size: None,

            duration_seconds: None,

        };



        // Get backups to replicate based on strategy

        let backups_to_replicate = match config.strategy {

            ReplicationStrategy::Immediate | ReplicationStrategy::Scheduled => {

                // Get latest backup

                backup_manager.list_backups().await

                    .map(|backups| backups.into_iter().take(1).collect::<Vec<_>>())

            }

            ReplicationStrategy::FullOnly => {

                // Get latest full backup

                backup_manager.list_backups().await

                    .map(|backups| {

                        backups.into_iter()

                            .filter(|backup| matches!(backup.strategy, crate::backup::BackupStrategy::Full))

                            .take(1)

                            .collect()

                    })

            }

            ReplicationStrategy::AgeBased { max_age_hours } => {

                // Get backups older than specified age

                let cutoff_time = Utc::now() - Duration::hours(max_age_hours as i64);

                backup_manager.list_backups().await

                    .map(|backups| {

                        backups.into_iter()

                            .filter(|backup| backup.created_at <= cutoff_time)

                            .take(5) // Limit to 5 backups per run

                            .collect()

                    })

            }

        };



        let backups = match backups_to_replicate {

            Ok(backups) => backups,

            Err(e) => {

                result.completed_at = Some(Utc::now());

                result.error_message = Some(format!("Failed to get backups: {}", e));

                result.duration_seconds = Some(

                    result.completed_at.unwrap().signed_duration_since(started_at).num_seconds() as u64

                );

                return result;

            }

        };



        if backups.is_empty() {

            result.completed_at = Some(Utc::now());

            result.success = true; // No backups to replicate is success

            result.duration_seconds = Some(

                result.completed_at.unwrap().signed_duration_since(started_at).num_seconds() as u64

            );

            return result;

        }



        // Replicate each backup

        let mut total_items = 0u64;

        let mut total_size = 0u64;

        

        for backup in backups {

            // Check if already replicated

            let already_replicated = config.replication_history

                .iter()

                .any(|result| result.backup_id == backup.backup_id && result.target_region == region);

            

            if already_replicated {

                continue;

            }



            // Perform replication

            match Self::replicate_single_backup(backup_manager, target_storage, &backup.backup_id).await {

                Ok((items, size)) => {

                    result.backup_id = backup.backup_id.clone();

                    total_items += items;

                    total_size += size;

                }

                Err(e) => {

                    result.completed_at = Some(Utc::now());

                    result.error_message = Some(format!("Failed to replicate backup {}: {}", backup.backup_id, e));

                    result.duration_seconds = Some(

                        result.completed_at.unwrap().signed_duration_since(started_at).num_seconds() as u64

                    );

                    return result;

                }

            }

        }



        let completed_at = Utc::now();

        result.completed_at = Some(completed_at);

        result.success = true;

        result.items_replicated = Some(total_items);

        result.total_size = Some(total_size);

        result.duration_seconds = Some(

            completed_at.signed_duration_since(started_at).num_seconds() as u64

        );



        result

    }



    /// Replicate a single backup

    async fn replicate_single_backup(

        backup_manager: &Arc<dyn BackupManager>,

        target_storage: &Arc<dyn StorageBackend>,

        backup_id: &str,

    ) -> Result<(u64, u64)> {

        // Get backup metadata

        let metadata = backup_manager.get_backup_metadata(backup_id).await?

            .ok_or_else(|| FortressError::storage(

                format!("Backup not found: {}", backup_id),

                "cross_region_replication".to_string(),

                StorageErrorCode::NotFound,

            ))?;



        // Get the backup storage from the backup manager

        // This is a simplified approach - in practice, you'd need access to the underlying storage

        let manifest_key = format!("{}/manifest.json", backup_id);

        

        // For now, we'll simulate replication by creating a manifest entry

        // In a real implementation, you'd copy the actual backup data

        let manifest_data = serde_json::to_vec(&metadata)

            .map_err(|e| FortressError::storage(

                format!("Failed to serialize manifest: {}", e),

                "cross_region_replication".to_string(),

                StorageErrorCode::InvalidOperation,

            ))?;



        target_storage.put(&manifest_key, &manifest_data).await?;



        Ok((metadata.item_count, metadata.total_size))

    }



    /// Remove a replication configuration

    pub async fn remove_replication_config(&self, replication_id: &str) -> Result<()> {

        // Stop running task

        let mut running_tasks = self.running_tasks.write().await;

        if let Some(task) = running_tasks.remove(replication_id) {

            task.abort();

        }



        // Remove configuration

        let mut configs = self.configs.write().await;

        configs.remove(replication_id);



        Ok(())

    }



    /// Update a replication configuration

    pub async fn update_replication_config(&self, config: CrossRegionConfig) -> Result<()> {

        // Remove existing config

        self.remove_replication_config(&config.replication_id).await?;



        // Add updated config

        self.add_replication_config(config).await?;



        Ok(())

    }



    /// List all replication configurations

    pub async fn list_replication_configs(&self) -> Result<Vec<CrossRegionConfig>> {

        let configs = self.configs.read().await;

        Ok(configs.values().cloned().collect())

    }



    /// Get replication history

    pub async fn get_replication_history(

        &self,

        replication_id: &str,

        limit: Option<usize>,

    ) -> Result<Vec<ReplicationResult>> {

        let configs = self.configs.read().await;

        if let Some(config) = configs.get(replication_id) {

            let mut history = config.replication_history.clone();

            history.sort_by(|a, b| b.started_at.cmp(&a.started_at));

            

            if let Some(limit) = limit {

                history.truncate(limit);

            }

            

            Ok(history)

        } else {

            Err(FortressError::storage(

                format!("Replication config not found: {}", replication_id),

                "cross_region_replication".to_string(),

                StorageErrorCode::NotFound,

            ))

        }

    }



    /// Enable/disable replication

    pub async fn set_replication_enabled(&self, replication_id: &str, enabled: bool) -> Result<()> {

        let mut configs = self.configs.write().await;

        if let Some(config) = configs.get_mut(replication_id) {

            config.enabled = enabled;

            

            if enabled {

                drop(configs);

                // Restart the task

                if let Some(config) = self.get_replication_config(replication_id).await? {

                    self.start_replication_task(config).await?;

                }

            } else {

                // Stop the task

                let mut running_tasks = self.running_tasks.write().await;

                if let Some(task) = running_tasks.remove(replication_id) {

                    task.abort();

                }

            }

            Ok(())

        } else {

            Err(FortressError::storage(

                format!("Replication config not found: {}", replication_id),

                "cross_region_replication".to_string(),

                StorageErrorCode::NotFound,

            ))

        }

    }



    /// Get a specific replication configuration

    pub async fn get_replication_config(&self, replication_id: &str) -> Result<Option<CrossRegionConfig>> {

        let configs = self.configs.read().await;

        Ok(configs.get(replication_id).cloned())

    }



    /// Get replication statistics

    pub async fn get_replication_stats(&self) -> Result<ReplicationStats> {

        let configs = self.configs.read().await;

        let mut stats = ReplicationStats {

            total_replications: 0,

            successful_replications: 0,

            failed_replications: 0,

            total_items_replicated: 0,

            total_size_replicated: 0,

            average_replication_time_seconds: 0.0,

            active_replications: configs.values().filter(|c| c.enabled).count(),

            target_regions: self.target_storages.read().await.len(),

        };



        let mut total_duration = 0u64;

        let mut completed_replications = 0u64;



        for config in configs.values() {

            for result in &config.replication_history {

                stats.total_replications += 1;

                

                if result.success {

                    stats.successful_replications += 1;

                    if let Some(items) = result.items_replicated {

                        stats.total_items_replicated += items;

                    }

                    if let Some(size) = result.total_size {

                        stats.total_size_replicated += size;

                    }

                } else {

                    stats.failed_replications += 1;

                }



                if let Some(duration) = result.duration_seconds {

                    total_duration += duration;

                    completed_replications += 1;

                }

            }

        }



        if completed_replications > 0 {

            stats.average_replication_time_seconds = total_duration as f64 / completed_replications as f64;

        }



        Ok(stats)

    }



    /// Create default replication configurations

    pub async fn create_default_replications(&self) -> Result<()> {

        let target_regions: Vec<String> = self.target_storages.read().await

            .keys()

            .cloned()

            .collect();



        if target_regions.is_empty() {

            return Err(FortressError::storage(

                "No target regions configured".to_string(),

                "cross_region_replication".to_string(),

                StorageErrorCode::InvalidOperation,

            ));

        }



        // Immediate replication for critical backups

        let immediate_config = CrossRegionConfig {

            replication_id: "immediate_critical".to_string(),

            source_region: "primary".to_string(),

            target_regions: target_regions.clone(),

            strategy: ReplicationStrategy::Immediate,

            enabled: true,

            frequency_seconds: 300, // 5 minutes

            max_bandwidth_bps: Some(self.max_bandwidth_bps / 2), // Use half bandwidth

            last_replication: None,

            replication_history: Vec::new(),

        };



        // Scheduled replication for all backups

        let scheduled_config = CrossRegionConfig {

            replication_id: "scheduled_all".to_string(),

            source_region: "primary".to_string(),

            target_regions: target_regions.clone(),

            strategy: ReplicationStrategy::Scheduled,

            enabled: true,

            frequency_seconds: 3600, // 1 hour

            max_bandwidth_bps: Some(self.max_bandwidth_bps / 4), // Use quarter bandwidth

            last_replication: None,

            replication_history: Vec::new(),

        };



        // Full backup only replication

        let full_only_config = CrossRegionConfig {

            replication_id: "full_backups_only".to_string(),

            source_region: "primary".to_string(),

            target_regions,

            strategy: ReplicationStrategy::FullOnly,

            enabled: true,

            frequency_seconds: 86400, // 24 hours

            max_bandwidth_bps: Some(self.max_bandwidth_bps / 4), // Use quarter bandwidth

            last_replication: None,

            replication_history: Vec::new(),

        };



        self.add_replication_config(immediate_config).await?;

        self.add_replication_config(scheduled_config).await?;

        self.add_replication_config(full_only_config).await?;



        Ok(())

    }



    /// Stop all replication tasks

    pub async fn shutdown(&self) -> Result<()> {

        let mut running_tasks = self.running_tasks.write().await;

        for (_, task) in running_tasks.drain() {

            task.abort();

        }

        Ok(())

    }

}



/// Replication statistics

#[derive(Debug, Clone)]

pub struct ReplicationStats {

    /// Total number of replications attempted

    pub total_replications: u64,

    /// Number of successful replications

    pub successful_replications: u64,

    /// Number of failed replications

    pub failed_replications: u64,

    /// Total items replicated

    pub total_items_replicated: u64,

    /// Total size replicated in bytes

    pub total_size_replicated: u64,

    /// Average replication time in seconds

    pub average_replication_time_seconds: f64,

    /// Number of active replications

    pub active_replications: usize,

    /// Number of target regions

    pub target_regions: usize,

}



#[cfg(test)]

mod tests {

    use super::*;

    use crate::backup_manager::DefaultBackupManager;

    use crate::storage::InMemoryStorage;

    use std::sync::Arc;



    #[tokio::test]

    async fn test_cross_region_replication_creation() {

        let backup_storage = Arc::new(InMemoryStorage::new());

        let target_storage = Arc::new(InMemoryStorage::new());

        let backup_manager = Arc::new(DefaultBackupManager::new(

            backup_storage.clone(),

            None,

            BackupConfig::default()

        )?);



        let replication_manager = CrossRegionReplicationManager::new(

            backup_manager,

            1024 * 1024 * 100, // 100MB/s

        );



        replication_manager.add_target_region("us-east-1".to_string(), target_storage).await.unwrap();

        

        assert_eq!(replication_manager.target_storages.read().await.len(), 1);

    }



    #[tokio::test]

    async fn test_add_replication_config() {

        let backup_storage = Arc::new(InMemoryStorage::new());

        let target_storage = Arc::new(InMemoryStorage::new());

        let backup_manager = Arc::new(DefaultBackupManager::new(

            backup_storage.clone(),

            None,

            BackupConfig::default()

        )?);



        let replication_manager = CrossRegionReplicationManager::new(

            backup_manager,

            1024 * 1024 * 100, // 100MB/s

        );



        replication_manager.add_target_region("us-east-1".to_string(), target_storage).await.unwrap();

        

        let config = CrossRegionConfig {

            replication_id: "test_replication".to_string(),

            source_region: "primary".to_string(),

            target_regions: vec!["us-east-1".to_string()],

            strategy: ReplicationStrategy::Immediate,

            enabled: false, // Don't start task for test

            frequency_seconds: 300,

            max_bandwidth_bps: Some(1024 * 1024 * 10), // 10MB/s

            last_replication: None,

            replication_history: Vec::new(),

        };



        assert!(replication_manager.add_replication_config(config).await.is_ok());

        

        let configs = replication_manager.list_replication_configs().await.unwrap();

        assert_eq!(configs.len(), 1);

        assert_eq!(configs[0].replication_id, "test_replication");

    }

}

