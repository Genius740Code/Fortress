//! Automated backup scheduling system
//!
//! This module provides comprehensive backup scheduling capabilities with cron-based
//! scheduling, retry logic, and automated retention management.

use crate::backup::{
    BackupManager, BackupConfig, BackupStrategy, BackupSchedule, 
    ScheduledRunResult
};
use crate::storage::StorageBackend;
use crate::error::{FortressError, Result};
use crate::error::StorageErrorCode;
use chrono::Utc;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;
use cron::Schedule as CronSchedule;

/// Backup scheduler manager
#[derive(Debug)]
pub struct BackupScheduler {
    /// Backup manager for creating backups
    backup_manager: Arc<dyn BackupManager>,
    /// Source storage for backups
    source_storage: Arc<dyn StorageBackend>,
    /// Active schedules
    schedules: Arc<RwLock<HashMap<String, BackupSchedule>>>,
    /// Running tasks
    running_tasks: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl BackupScheduler {
    /// Create a new backup scheduler
    pub fn new(
        backup_manager: Arc<dyn BackupManager>,
        source_storage: Arc<dyn StorageBackend>,
    ) -> Self {
        Self {
            backup_manager,
            source_storage,
            schedules: Arc::new(RwLock::new(HashMap::new())),
            running_tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a new backup schedule
    pub async fn add_schedule(&self, mut schedule: BackupSchedule) -> Result<()> {
        // Generate schedule ID if not provided
        if schedule.schedule_id.is_empty() {
            schedule.schedule_id = format!("schedule_{}", Uuid::new_v4());
        }

        // Validate cron expression
        let cron_schedule = CronSchedule::try_from(schedule.cron_expression.as_str())
            .map_err(|e| FortressError::configuration(
                format!("Invalid cron expression: {}", e),
                Some("cron_expression".to_string()),
                crate::error::ConfigurationErrorCode::InvalidValue,
            ))?;

        // Calculate next run time
        let _now = Utc::now();
        let next_run = cron_schedule.upcoming(Utc).take(1).next().ok_or_else(|| {
            FortressError::configuration(
                "Could not calculate next run time".to_string(),
                Some("cron_expression".to_string()),
                crate::error::ConfigurationErrorCode::InvalidValue,
            )
        })?;
        schedule.next_run = Some(next_run);

        // Save schedule
        let mut schedules = self.schedules.write().await;
        schedules.insert(schedule.schedule_id.clone(), schedule.clone());

        // Start scheduler task if enabled
        if schedule.enabled {
            self.start_schedule_task(schedule.clone()).await?;
        }

        Ok(())
    }

    /// Start a scheduler task for a schedule
    async fn start_schedule_task(&self, schedule: BackupSchedule) -> Result<()> {
        let backup_manager = self.backup_manager.clone();
        let source_storage = self.source_storage.clone();
        let schedules = self.schedules.clone();
        let schedule_id_for_task = schedule.schedule_id.clone();
        let task = tokio::spawn(async move {
            let schedule_id = schedule_id_for_task.clone();
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(60) // Check every minute
            );

            loop {
                interval.tick().await;

                let schedules_guard = schedules.read().await;
                if let Some(current_schedule) = schedules_guard.get(&schedule_id) {
                    if !current_schedule.enabled {
                        break;
                    }

                    if let Some(next_run) = current_schedule.next_run {
                        if Utc::now() >= next_run {
                            // Time to run backup
                            let run_result = Self::execute_scheduled_backup(
                                &backup_manager,
                                &source_storage,
                                current_schedule,
                            ).await;

                            // Update schedule with run result
                            drop(schedules_guard);
                            let mut schedules_write = schedules.write().await;
                            if let Some(schedule) = schedules_write.get_mut(&schedule_id) {
                                schedule.last_run = Some(run_result.started_at);
                                schedule.run_history.push(run_result.clone());

                                // Keep only last 50 run results
                                if schedule.run_history.len() > 50 {
                                    schedule.run_history.sort_by(|a, b| b.started_at.cmp(&a.started_at));
                                    schedule.run_history.truncate(50);
                                }

                                // Calculate next run time
                                if let Ok(cron_schedule) = CronSchedule::try_from(schedule.cron_expression.as_str()) {
                                    if let Some(next) = cron_schedule.upcoming(Utc).take(1).next() {
                                        schedule.next_run = Some(next);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Schedule was removed
                    break;
                }
            }
        });

        let mut running_tasks = self.running_tasks.write().await;
        running_tasks.insert(schedule.schedule_id.clone(), task);

        Ok(())
    }

    /// Execute a scheduled backup
    async fn execute_scheduled_backup(
        backup_manager: &Arc<dyn BackupManager>,
        source_storage: &Arc<dyn StorageBackend>,
        schedule: &BackupSchedule,
    ) -> ScheduledRunResult {
        let run_id = format!("run_{}", Uuid::new_v4());
        let started_at = Utc::now();

        // Create backup config based on schedule
        let config = BackupConfig {
            default_strategy: schedule.strategy.clone(),
            ..BackupConfig::default()
        };

        let mut run_result = ScheduledRunResult {
            run_id: run_id.clone(),
            started_at,
            completed_at: None,
            success: false,
            backup_id: None,
            error_message: None,
            items_backed_up: None,
            total_size: None,
            duration_seconds: None,
        };

        // Execute backup with retry logic
        let mut _last_error = None;
        for attempt in 0..=schedule.max_retries {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    schedule.retry_delay_seconds as u64
                )).await;
            }

            match backup_manager.create_backup(&**source_storage, &config).await {
                Ok(backup_metadata) => {
                    run_result.success = true;
                    run_result.backup_id = Some(backup_metadata.backup_id.clone());
                    run_result.items_backed_up = Some(backup_metadata.item_count);
                    run_result.total_size = Some(backup_metadata.total_size);
                    return run_result;
                }
                Err(e) => {
                    let error_msg = format!("Attempt {} failed: {}", attempt + 1, e);
                    _last_error = Some(error_msg.clone());
                    if attempt == schedule.max_retries {
                        run_result.error_message = Some(error_msg);
                    }
                }
            }
        }

        let completed_at = Utc::now();
        run_result.completed_at = Some(completed_at);
        run_result.duration_seconds = Some(
            completed_at.signed_duration_since(started_at).num_seconds() as u64
        );

        run_result
    }

    /// Remove a schedule
    pub async fn remove_schedule(&self, schedule_id: &str) -> Result<()> {
        // Stop running task
        let mut running_tasks = self.running_tasks.write().await;
        if let Some(task) = running_tasks.remove(schedule_id) {
            task.abort();
        }

        // Remove schedule
        let mut schedules = self.schedules.write().await;
        schedules.remove(schedule_id);

        Ok(())
    }

    /// Update a schedule
    pub async fn update_schedule(&self, schedule: BackupSchedule) -> Result<()> {
        // Remove existing schedule
        self.remove_schedule(&schedule.schedule_id).await?;

        // Add updated schedule
        self.add_schedule(schedule).await?;

        Ok(())
    }

    /// List all schedules
    pub async fn list_schedules(&self) -> Result<Vec<BackupSchedule>> {
        let schedules = self.schedules.read().await;
        Ok(schedules.values().cloned().collect())
    }

    /// Get a specific schedule
    pub async fn get_schedule(&self, schedule_id: &str) -> Result<Option<BackupSchedule>> {
        let schedules = self.schedules.read().await;
        Ok(schedules.get(schedule_id).cloned())
    }

    /// Enable/disable a schedule
    pub async fn set_schedule_enabled(&self, schedule_id: &str, enabled: bool) -> Result<()> {
        let mut schedules = self.schedules.write().await;
        if let Some(schedule) = schedules.get_mut(schedule_id) {
            schedule.enabled = enabled;
            
            if enabled {
                drop(schedules);
                // Restart the task
                if let Some(schedule) = self.get_schedule(schedule_id).await? {
                    self.start_schedule_task(schedule).await?;
                }
            } else {
                // Stop the task
                let mut running_tasks = self.running_tasks.write().await;
                if let Some(task) = running_tasks.remove(schedule_id) {
                    task.abort();
                }
            }
            Ok(())
        } else {
            Err(FortressError::storage(
                format!("Schedule not found: {}", schedule_id),
                "backup_scheduler".to_string(),
                StorageErrorCode::NotFound,
            ))
        }
    }

    /// Get schedule run history
    pub async fn get_run_history(&self, schedule_id: &str, limit: Option<usize>) -> Result<Vec<ScheduledRunResult>> {
        let schedules = self.schedules.read().await;
        if let Some(schedule) = schedules.get(schedule_id) {
            let mut history = schedule.run_history.clone();
            history.sort_by(|a, b| b.started_at.cmp(&a.started_at));
            
            if let Some(limit) = limit {
                history.truncate(limit);
            }
            
            Ok(history)
        } else {
            Err(FortressError::storage(
                format!("Schedule not found: {}", schedule_id),
                "backup_scheduler".to_string(),
                StorageErrorCode::NotFound,
            ))
        }
    }

    /// Create default schedules
    pub async fn create_default_schedules(&self) -> Result<()> {
        // Daily full backup at 2 AM
        let daily_full = BackupSchedule {
            schedule_id: "daily_full".to_string(),
            name: "Daily Full Backup".to_string(),
            strategy: BackupStrategy::Full,
            cron_expression: "0 2 * * *".to_string(), // 2 AM every day
            enabled: true,
            timezone: "UTC".to_string(),
            max_retries: 3,
            retry_delay_seconds: 300, // 5 minutes
            last_run: None,
            next_run: None,
            run_history: Vec::new(),
        };

        // Hourly incremental backup
        let hourly_incremental = BackupSchedule {
            schedule_id: "hourly_incremental".to_string(),
            name: "Hourly Incremental Backup".to_string(),
            strategy: BackupStrategy::Incremental { 
                base_backup_id: "daily_full".to_string() 
            },
            cron_expression: "0 * * * *".to_string(), // Every hour
            enabled: true,
            timezone: "UTC".to_string(),
            max_retries: 2,
            retry_delay_seconds: 180, // 3 minutes
            last_run: None,
            next_run: None,
            run_history: Vec::new(),
        };

        // Weekly maintenance and cleanup
        let weekly_maintenance = BackupSchedule {
            schedule_id: "weekly_maintenance".to_string(),
            name: "Weekly Maintenance and Cleanup".to_string(),
            strategy: BackupStrategy::Full, // Will trigger cleanup
            cron_expression: "0 3 * * 0".to_string(), // 3 AM on Sunday
            enabled: true,
            timezone: "UTC".to_string(),
            max_retries: 1,
            retry_delay_seconds: 600, // 10 minutes
            last_run: None,
            next_run: None,
            run_history: Vec::new(),
        };

        // Add all schedules
        self.add_schedule(daily_full).await?;
        self.add_schedule(hourly_incremental).await?;
        self.add_schedule(weekly_maintenance).await?;

        Ok(())
    }

    /// Stop all scheduler tasks
    pub async fn shutdown(&self) -> Result<()> {
        let mut running_tasks = self.running_tasks.write().await;
        for (_, task) in running_tasks.drain() {
            task.abort();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_manager::DefaultBackupManager;
    use crate::storage::InMemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_backup_scheduler_creation() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let scheduler = BackupScheduler::new(backup_manager, source_storage);
        
        assert!(!scheduler.schedules.try_read().is_some_and_then(|guard| Some(!guard.is_empty())).unwrap_or(false));
    }

    #[tokio::test]
    async fn test_add_schedule() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let scheduler = BackupScheduler::new(backup_manager, source_storage);
        
        let schedule = BackupSchedule {
            schedule_id: "test_schedule".to_string(),
            name: "Test Schedule".to_string(),
            strategy: BackupStrategy::Full,
            cron_expression: "0 2 * * *".to_string(),
            enabled: false, // Don't start task for test
            timezone: "UTC".to_string(),
            max_retries: 1,
            retry_delay_seconds: 60,
            last_run: None,
            next_run: None,
            run_history: Vec::new(),
        };

        assert!(scheduler.add_schedule(schedule).await.is_ok());
        
        let schedules = scheduler.list_schedules().await.unwrap();
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules[0].schedule_id, "test_schedule");
    }

    #[tokio::test]
    async fn test_remove_schedule() {
        let source_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(DefaultBackupManager::new(
            backup_storage.clone(),
            None,
            BackupConfig::default(),
        ).unwrap());

        let scheduler = BackupScheduler::new(backup_manager, source_storage);
        
        let schedule = BackupSchedule {
            schedule_id: "test_schedule".to_string(),
            name: "Test Schedule".to_string(),
            strategy: BackupStrategy::Full,
            cron_expression: "0 2 * * *".to_string(),
            enabled: false,
            timezone: "UTC".to_string(),
            max_retries: 1,
            retry_delay_seconds: 60,
            last_run: None,
            next_run: None,
            run_history: Vec::new(),
        };

        scheduler.add_schedule(schedule).await.unwrap();
        assert!(scheduler.remove_schedule("test_schedule").await.is_ok());
        
        let schedules = scheduler.list_schedules().await.unwrap();
        assert_eq!(schedules.len(), 0);
    }
}
