//! Disaster recovery manager implementation
//!
//! This module provides the implementation of the DisasterRecoveryManager trait
//! with comprehensive recovery planning, execution, and testing capabilities.

use crate::backup::utils;
use crate::backup::{
    BackupConfig, BackupManager, DisasterRecoveryManager, DisasterRecoveryPlan, RecoveryPriority,
    RecoveryStep, RestoreOperationStatus, RestoreStatus, RetentionPolicy, StepTestResult,
    TestResult, VerificationLevel,
};
use crate::error::StorageErrorCode;
use crate::error::{FortressError, Result};
use crate::storage::StorageBackend;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Default disaster recovery manager implementation
#[derive(Debug)]
pub struct DefaultDisasterRecoveryManager {
    /// Storage for recovery plans
    plan_storage: Arc<dyn StorageBackend>,
    /// Backup manager for recovery operations
    backup_manager: Arc<dyn BackupManager>,
    /// Recovery plan cache
    plans: Arc<RwLock<HashMap<String, DisasterRecoveryPlan>>>,
    /// Test history cache
    test_history: Arc<RwLock<HashMap<String, Vec<TestResult>>>>,
}

impl DefaultDisasterRecoveryManager {
    /// Create a new disaster recovery manager
    pub fn new(
        plan_storage: Arc<dyn StorageBackend>,
        backup_manager: Arc<dyn BackupManager>,
    ) -> Self {
        Self {
            plan_storage,
            backup_manager,
            plans: Arc::new(RwLock::new(HashMap::new())),
            test_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a unique plan ID
    fn generate_plan_id(&self) -> String {
        format!("plan_{}", Uuid::new_v4())
    }

    /// Generate a unique test ID
    fn generate_test_id(&self) -> String {
        format!("test_{}", Uuid::new_v4())
    }

    /// Save recovery plan to storage
    async fn save_plan(&self, plan: &DisasterRecoveryPlan) -> Result<()> {
        let plan_key = format!("plans/{}.json", plan.plan_id);
        let plan_data = serde_json::to_vec(plan).map_err(|e| {
            FortressError::storage(
                format!("Failed to serialize recovery plan: {}", e),
                "disaster_recovery".to_string(),
                StorageErrorCode::InvalidOperation,
            )
        })?;

        self.plan_storage.put(&plan_key, &plan_data).await?;

        // Update cache
        let mut plans = self.plans.write().await;
        plans.insert(plan.plan_id.clone(), plan.clone());

        Ok(())
    }

    /// Load recovery plan from storage
    async fn load_plan(&self, plan_id: &str) -> Result<Option<DisasterRecoveryPlan>> {
        // Check cache first
        {
            let plans = self.plans.read().await;
            if let Some(plan) = plans.get(plan_id) {
                return Ok(Some(plan.clone()));
            }
        }

        // Load from storage
        let plan_key = format!("plans/{}.json", plan_id);
        let plan_data = match self.plan_storage.get(&plan_key).await? {
            Some(data) => data,
            None => return Ok(None),
        };

        let plan: DisasterRecoveryPlan = serde_json::from_slice(&plan_data).map_err(|e| {
            FortressError::storage(
                format!("Failed to deserialize recovery plan: {}", e),
                "disaster_recovery".to_string(),
                StorageErrorCode::CorruptedData,
            )
        })?;

        // Update cache
        let mut plans = self.plans.write().await;
        plans.insert(plan_id.to_string(), plan.clone());

        Ok(Some(plan))
    }

    /// Save test result to storage
    async fn save_test_result(&self, result: &TestResult) -> Result<()> {
        let test_key = format!("tests/{}.json", result.test_id);
        let test_data = serde_json::to_vec(result).map_err(|e| {
            FortressError::storage(
                format!("Failed to serialize test result: {}", e),
                "disaster_recovery".to_string(),
                StorageErrorCode::InvalidOperation,
            )
        })?;

        self.plan_storage.put(&test_key, &test_data).await?;

        // Update history cache
        let mut history = self.test_history.write().await;
        let plan_tests = history
            .entry(result.plan_id.clone())
            .or_insert_with(Vec::new);
        plan_tests.push(result.clone());

        // Keep only last 10 test results per plan
        if plan_tests.len() > 10 {
            plan_tests.sort_by(|a, b| b.tested_at.cmp(&a.tested_at));
            plan_tests.truncate(10);
        }

        Ok(())
    }

    /// Execute a single recovery step
    async fn execute_recovery_step(
        &self,
        step: &RecoveryStep,
        backup_id: &str,
        target_storage: &dyn StorageBackend,
    ) -> Result<StepTestResult> {
        let start_time = std::time::Instant::now();
        let mut issues = Vec::new();
        let mut passed = true;

        // Execute the step based on its command
        if let Some(command) = &step.command {
            match self
                .execute_recovery_command(command, backup_id, target_storage)
                .await
            {
                Ok(()) => {
                    // Verify step if criteria specified
                    if let Some(criteria) = &step.verification_criteria {
                        match self.verify_step_criteria(criteria, target_storage).await {
                            Ok(()) => {
                                // Step passed verification
                            }
                            Err(e) => {
                                passed = false;
                                issues.push(format!("Verification failed: {}", e));
                            }
                        }
                    }
                }
                Err(e) => {
                    passed = false;
                    issues.push(format!("Command execution failed: {}", e));
                }
            }
        } else {
            // For steps without commands, just verify criteria if specified
            if let Some(criteria) = &step.verification_criteria {
                match self.verify_step_criteria(criteria, target_storage).await {
                    Ok(()) => {
                        // Step passed verification
                    }
                    Err(e) => {
                        passed = false;
                        issues.push(format!("Verification failed: {}", e));
                    }
                }
            }
        }

        let duration = start_time.elapsed().as_secs();

        Ok(StepTestResult {
            step_number: step.step_number,
            passed,
            duration_seconds: duration,
            issues,
        })
    }

    /// Execute a recovery command
    async fn execute_recovery_command(
        &self,
        command: &str,
        _backup_id: &str,
        target_storage: &dyn StorageBackend,
    ) -> Result<()> {
        // Parse and execute different types of commands
        if command.starts_with("restore:") {
            // Format: restore:backup_id
            let parts: Vec<&str> = command.split(':').collect();
            if parts.len() != 2 {
                return Err(FortressError::configuration(
                    "Invalid restore command format".to_string(),
                    Some("command".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ));
            }

            let backup_to_restore = parts[1];
            let config = BackupConfig::default(); // Use default config for recovery

            let restore_status = self
                .backup_manager
                .restore_backup(backup_to_restore, target_storage, &config)
                .await?;

            match restore_status.status {
                RestoreOperationStatus::Completed => Ok(()),
                _ => Err(FortressError::storage(
                    format!("Restore operation failed: {:?}", restore_status.status),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::InvalidOperation,
                )),
            }
        } else if command.starts_with("verify:") {
            // Format: verify:backup_id:level
            let parts: Vec<&str> = command.split(':').collect();
            if parts.len() != 3 {
                return Err(FortressError::configuration(
                    "Invalid verify command format".to_string(),
                    Some("command".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ));
            }

            let backup_to_verify = parts[1];
            let level_str = parts[2];

            let level = match level_str {
                "basic" => VerificationLevel::Basic,
                "full" => VerificationLevel::Full,
                "comprehensive" => VerificationLevel::Comprehensive,
                _ => {
                    return Err(FortressError::configuration(
                        "Invalid verification level".to_string(),
                        Some("command".to_string()),
                        crate::error::ConfigurationErrorCode::InvalidValue,
                    ))
                }
            };

            let is_valid = self
                .backup_manager
                .verify_backup(backup_to_verify, level)
                .await?;

            if is_valid {
                Ok(())
            } else {
                Err(FortressError::storage(
                    "Backup verification failed".to_string(),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::CorruptedData,
                ))
            }
        } else if command.starts_with("cleanup:") {
            // Format: cleanup:max_age_days
            let parts: Vec<&str> = command.split(':').collect();
            if parts.len() != 2 {
                return Err(FortressError::configuration(
                    "Invalid cleanup command format".to_string(),
                    Some("command".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ));
            }

            let _max_age_days = parts[1].parse::<u32>().map_err(|_| {
                FortressError::configuration(
                    "Invalid max age days".to_string(),
                    Some("command".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                )
            })?;

            let policy = RetentionPolicy {
                max_full_backups: 10,
                max_incremental_backups: 50,
                max_age_days: 30,
                auto_cleanup: true,
            };

            self.backup_manager.cleanup_old_backups(&policy).await?;
            Ok(())
        } else {
            Err(FortressError::configuration(
                format!("Unknown recovery command: {}", command),
                Some("command".to_string()),
                crate::error::ConfigurationErrorCode::InvalidValue,
            ))
        }
    }

    /// Verify step criteria
    async fn verify_step_criteria(
        &self,
        criteria: &str,
        target_storage: &dyn StorageBackend,
    ) -> Result<()> {
        if criteria.starts_with("storage_health:") {
            // Format: storage_health
            let health = target_storage.health_check().await?;
            if !health.healthy {
                return Err(FortressError::storage(
                    "Target storage is not healthy".to_string(),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::ConnectionFailed,
                ));
            }
        } else if criteria.starts_with("key_exists:") {
            // Format: key_exists:key_name
            let parts: Vec<&str> = criteria.split(':').collect();
            if parts.len() != 2 {
                return Err(FortressError::configuration(
                    "Invalid key_exists criteria format".to_string(),
                    Some("criteria".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ));
            }

            let key_name = parts[1];
            let exists = target_storage.exists(key_name).await?;
            if !exists {
                return Err(FortressError::storage(
                    format!("Required key does not exist: {}", key_name),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::NotFound,
                ));
            }
        } else if criteria.starts_with("backup_count:") {
            // Format: backup_count:min_count
            let parts: Vec<&str> = criteria.split(':').collect();
            if parts.len() != 2 {
                return Err(FortressError::configuration(
                    "Invalid backup_count criteria format".to_string(),
                    Some("criteria".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ));
            }

            let min_count = parts[1].parse::<u64>().map_err(|_| {
                FortressError::configuration(
                    "Invalid backup count".to_string(),
                    Some("criteria".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                )
            })?;

            let backups = self.backup_manager.list_backups().await?;
            if (backups.len() as u64) < min_count {
                return Err(FortressError::storage(
                    format!(
                        "Insufficient backup count: {} < {}",
                        backups.len(),
                        min_count
                    ),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::InvalidOperation,
                ));
            }
        } else {
            return Err(FortressError::configuration(
                format!("Unknown verification criteria: {}", criteria),
                Some("criteria".to_string()),
                crate::error::ConfigurationErrorCode::InvalidValue,
            ));
        }

        Ok(())
    }

    /// Create default recovery plans
    pub async fn create_default_plans(&self) -> Result<()> {
        // Plan 1: Complete System Recovery
        let complete_recovery_plan = DisasterRecoveryPlan {
            plan_id: self.generate_plan_id(),
            name: "Complete System Recovery".to_string(),
            description: "Full system recovery from the latest backup".to_string(),
            recovery_steps: vec![
                RecoveryStep {
                    step_number: 1,
                    description: "Verify target storage health".to_string(),
                    command: None,
                    expected_duration_minutes: 5,
                    critical: true,
                    verification_criteria: Some("storage_health".to_string()),
                },
                RecoveryStep {
                    step_number: 2,
                    description: "Verify backup integrity".to_string(),
                    command: Some("verify:latest:comprehensive".to_string()),
                    expected_duration_minutes: 30,
                    critical: true,
                    verification_criteria: None,
                },
                RecoveryStep {
                    step_number: 3,
                    description: "Restore from latest backup".to_string(),
                    command: Some("restore:latest".to_string()),
                    expected_duration_minutes: 60,
                    critical: true,
                    verification_criteria: Some("key_exists:system_config".to_string()),
                },
                RecoveryStep {
                    step_number: 4,
                    description: "Verify system functionality".to_string(),
                    command: None,
                    expected_duration_minutes: 15,
                    critical: true,
                    verification_criteria: Some("storage_health".to_string()),
                },
            ],
            required_resources: vec![
                "Target storage backend".to_string(),
                "Valid backup".to_string(),
                "Sufficient storage space".to_string(),
            ],
            estimated_recovery_time_minutes: 110,
            priority: RecoveryPriority::Critical,
            last_tested: None,
        };

        // Plan 2: Partial Data Recovery
        let partial_recovery_plan = DisasterRecoveryPlan {
            plan_id: self.generate_plan_id(),
            name: "Partial Data Recovery".to_string(),
            description: "Recovery of specific data subsets".to_string(),
            recovery_steps: vec![
                RecoveryStep {
                    step_number: 1,
                    description: "Verify target storage health".to_string(),
                    command: None,
                    expected_duration_minutes: 5,
                    critical: true,
                    verification_criteria: Some("storage_health".to_string()),
                },
                RecoveryStep {
                    step_number: 2,
                    description: "Verify specific backup integrity".to_string(),
                    command: Some("verify:specified:full".to_string()),
                    expected_duration_minutes: 15,
                    critical: true,
                    verification_criteria: None,
                },
                RecoveryStep {
                    step_number: 3,
                    description: "Restore specific data".to_string(),
                    command: Some("restore:specified".to_string()),
                    expected_duration_minutes: 30,
                    critical: true,
                    verification_criteria: Some("key_exists:restored_data".to_string()),
                },
            ],
            required_resources: vec![
                "Target storage backend".to_string(),
                "Specific backup".to_string(),
                "Data selection criteria".to_string(),
            ],
            estimated_recovery_time_minutes: 50,
            priority: RecoveryPriority::High,
            last_tested: None,
        };

        // Plan 3: Backup Cleanup and Maintenance
        let maintenance_plan = DisasterRecoveryPlan {
            plan_id: self.generate_plan_id(),
            name: "Backup Cleanup and Maintenance".to_string(),
            description: "Routine cleanup of old backups and maintenance tasks".to_string(),
            recovery_steps: vec![
                RecoveryStep {
                    step_number: 1,
                    description: "Verify backup storage health".to_string(),
                    command: None,
                    expected_duration_minutes: 5,
                    critical: false,
                    verification_criteria: Some("backup_count:1".to_string()),
                },
                RecoveryStep {
                    step_number: 2,
                    description: "Clean up old backups".to_string(),
                    command: Some("cleanup:90".to_string()),
                    expected_duration_minutes: 20,
                    critical: false,
                    verification_criteria: None,
                },
                RecoveryStep {
                    step_number: 3,
                    description: "Verify backup system functionality".to_string(),
                    command: None,
                    expected_duration_minutes: 10,
                    critical: false,
                    verification_criteria: Some("backup_count:1".to_string()),
                },
            ],
            required_resources: vec![
                "Backup storage backend".to_string(),
                "Sufficient permissions".to_string(),
            ],
            estimated_recovery_time_minutes: 35,
            priority: RecoveryPriority::Low,
            last_tested: None,
        };

        // Save all plans
        self.save_plan(&complete_recovery_plan).await?;
        self.save_plan(&partial_recovery_plan).await?;
        self.save_plan(&maintenance_plan).await?;

        Ok(())
    }
}

#[async_trait]
impl DisasterRecoveryManager for DefaultDisasterRecoveryManager {
    fn create_recovery_plan<'a>(
        &'a self,
        plan: DisasterRecoveryPlan,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // Validate plan
            if plan.recovery_steps.is_empty() {
                return Err(FortressError::configuration(
                    "Recovery plan must have at least one step".to_string(),
                    Some("recovery_steps".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ));
            }

            if plan.name.is_empty() {
                return Err(FortressError::configuration(
                    "Recovery plan must have a name".to_string(),
                    Some("name".to_string()),
                    crate::error::ConfigurationErrorCode::InvalidValue,
                ));
            }

            // Save plan
            self.save_plan(&plan).await
        })
    }

    fn get_recovery_plan<'a>(
        &'a self,
        plan_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<DisasterRecoveryPlan>>> + Send + 'a>,
    > {
        Box::pin(async move { self.load_plan(plan_id).await })
    }

    fn list_recovery_plans<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<DisasterRecoveryPlan>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let plan_keys = self.plan_storage.list_prefix("plans/").await?;
            let mut plans = Vec::new();

            for key in plan_keys {
                if key.ends_with(".json") {
                    let plan_id = key
                        .strip_prefix("plans/")
                        .and_then(|s| s.strip_suffix(".json"))
                        .unwrap_or("unknown");

                    if let Ok(Some(plan)) = self.load_plan(plan_id).await {
                        plans.push(plan);
                    }
                }
            }

            // Sort by priority and name
            plans.sort_by(|a, b| match (&a.priority, &b.priority) {
                (RecoveryPriority::Critical, RecoveryPriority::Critical) => a.name.cmp(&b.name),
                (RecoveryPriority::Critical, _) => std::cmp::Ordering::Less,
                (RecoveryPriority::High, RecoveryPriority::Critical) => std::cmp::Ordering::Greater,
                (RecoveryPriority::High, RecoveryPriority::High) => a.name.cmp(&b.name),
                (RecoveryPriority::High, _) => std::cmp::Ordering::Less,
                (RecoveryPriority::Medium, RecoveryPriority::Critical | RecoveryPriority::High) => {
                    std::cmp::Ordering::Greater
                }
                (RecoveryPriority::Medium, RecoveryPriority::Medium) => a.name.cmp(&b.name),
                (RecoveryPriority::Medium, _) => std::cmp::Ordering::Less,
                (RecoveryPriority::Low, _) => std::cmp::Ordering::Greater,
            });

            Ok(plans)
        })
    }

    fn execute_recovery_plan<'a>(
        &'a self,
        plan_id: &'a str,
        backup_id: &'a str,
        target_storage: &'a dyn StorageBackend,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<RestoreStatus>> + Send + 'a>>
    {
        Box::pin(async move {
            let plan = self.load_plan(plan_id).await?.ok_or_else(|| {
                FortressError::storage(
                    format!("Recovery plan not found: {}", plan_id),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::NotFound,
                )
            })?;

            let restore_id = utils::generate_restore_id();
            let start_time = Utc::now();
            let mut items_restored = 0u64;
            let total_items = plan.recovery_steps.len() as u64;
            let mut errors = Vec::new();

            // Execute each step
            for step in &plan.recovery_steps {
                match self
                    .execute_recovery_step(step, backup_id, target_storage)
                    .await
                {
                    Ok(step_result) => {
                        if step_result.passed {
                            items_restored += 1;
                        } else {
                            let error_msg = format!(
                                "Step {} failed: {:?}",
                                step.step_number, step_result.issues
                            );
                            errors.push(error_msg.clone());

                            if step.critical {
                                // Stop execution on critical step failure
                                return Ok(RestoreStatus {
                                    restore_id,
                                    backup_id: backup_id.to_string(),
                                    status: RestoreOperationStatus::Failed,
                                    progress_percentage: (items_restored as f32
                                        / total_items as f32)
                                        * 100.0,
                                    items_restored,
                                    total_items,
                                    started_at: start_time,
                                    estimated_completion: None,
                                    errors,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        let error_msg =
                            format!("Step {} execution failed: {}", step.step_number, e);
                        errors.push(error_msg.clone());

                        if step.critical {
                            return Ok(RestoreStatus {
                                restore_id,
                                backup_id: backup_id.to_string(),
                                status: RestoreOperationStatus::Failed,
                                progress_percentage: (items_restored as f32 / total_items as f32)
                                    * 100.0,
                                items_restored,
                                total_items,
                                started_at: start_time,
                                estimated_completion: None,
                                errors,
                            });
                        }
                    }
                }
            }

            let status = if errors.is_empty() {
                RestoreOperationStatus::Completed
            } else {
                RestoreOperationStatus::Completed // Some non-critical steps failed but overall completed
            };

            Ok(RestoreStatus {
                restore_id,
                backup_id: backup_id.to_string(),
                status,
                progress_percentage: 100.0,
                items_restored,
                total_items,
                started_at: start_time,
                estimated_completion: Some(Utc::now()),
                errors,
            })
        })
    }

    fn test_recovery_plan<'a>(
        &'a self,
        plan_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TestResult>> + Send + 'a>> {
        Box::pin(async move {
            let plan = self.load_plan(plan_id).await?.ok_or_else(|| {
                FortressError::storage(
                    format!("Recovery plan not found: {}", plan_id),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::NotFound,
                )
            })?;

            let test_id = self.generate_test_id();
            let start_time = std::time::Instant::now();
            let mut step_results = Vec::new();
            let mut all_passed = true;
            let mut issues = Vec::new();
            let mut recommendations = Vec::new();

            // Create a temporary storage for testing
            let test_storage = Arc::new(crate::storage::InMemoryStorage::new());

            // Test each step
            for step in &plan.recovery_steps {
                match self
                    .execute_recovery_step(step, "test_backup", &*test_storage)
                    .await
                {
                    Ok(step_result) => {
                        if !step_result.passed {
                            all_passed = false;
                            issues.extend(step_result.issues.clone());

                            if step.critical {
                                recommendations.push(format!(
                                    "Critical step {} failed: {:?}",
                                    step.step_number, step_result.issues
                                ));
                            }
                        }
                        step_results.push(step_result);
                    }
                    Err(e) => {
                        all_passed = false;
                        let error_msg = format!("Step {} test failed: {}", step.step_number, e);
                        issues.push(error_msg.clone());

                        if step.critical {
                            recommendations
                                .push(format!("Critical step {} failed: {}", step.step_number, e));
                        }

                        step_results.push(StepTestResult {
                            step_number: step.step_number,
                            passed: false,
                            duration_seconds: 0,
                            issues: vec![error_msg],
                        });
                    }
                }
            }

            // Add general recommendations
            if all_passed {
                recommendations.push("All tests passed successfully".to_string());
            } else {
                recommendations.push("Review failed steps and update the plan".to_string());
                recommendations
                    .push("Consider increasing time estimates for failed steps".to_string());
            }

            let duration = start_time.elapsed().as_secs();
            let test_result = TestResult {
                test_id,
                plan_id: plan_id.to_string(),
                tested_at: Utc::now(),
                passed: all_passed,
                duration_seconds: duration,
                step_results,
                issues,
                recommendations,
            };

            // Save test result
            self.save_test_result(&test_result).await?;

            // Update plan's last tested timestamp
            let mut updated_plan = plan.clone();
            updated_plan.last_tested = Some(test_result.tested_at);
            self.save_plan(&updated_plan).await?;

            Ok(test_result)
        })
    }

    fn update_recovery_plan<'a>(
        &'a self,
        plan: DisasterRecoveryPlan,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // Verify plan exists
            let _existing = self.load_plan(&plan.plan_id).await?.ok_or_else(|| {
                FortressError::storage(
                    format!("Recovery plan not found: {}", plan.plan_id),
                    "disaster_recovery".to_string(),
                    StorageErrorCode::NotFound,
                )
            })?;

            self.save_plan(&plan).await
        })
    }

    fn delete_recovery_plan<'a>(
        &'a self,
        plan_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // Delete from storage
            let plan_key = format!("plans/{}.json", plan_id);
            self.plan_storage.delete(&plan_key).await?;

            // Remove from cache
            let mut plans = self.plans.write().await;
            plans.remove(plan_id);

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_manager::DefaultBackupManager;
    use crate::storage::InMemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_disaster_recovery_manager_creation() {
        let plan_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(
            DefaultBackupManager::new(backup_storage.clone(), None, BackupConfig::default())
                .unwrap(),
        );

        let dr_manager = DefaultDisasterRecoveryManager::new(plan_storage.clone(), backup_manager);

        assert!(!dr_manager.plans.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_create_recovery_plan() {
        let plan_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(
            DefaultBackupManager::new(backup_storage.clone(), None, BackupConfig::default())
                .unwrap(),
        );

        let dr_manager = DefaultDisasterRecoveryManager::new(plan_storage.clone(), backup_manager);

        let plan = DisasterRecoveryPlan {
            plan_id: "test_plan".to_string(),
            name: "Test Plan".to_string(),
            description: "Test recovery plan".to_string(),
            recovery_steps: vec![RecoveryStep {
                step_number: 1,
                description: "Test step".to_string(),
                command: None,
                expected_duration_minutes: 5,
                critical: true,
                verification_criteria: Some("storage_health".to_string()),
            }],
            required_resources: vec!["Test resource".to_string()],
            estimated_recovery_time_minutes: 5,
            priority: RecoveryPriority::High,
            last_tested: None,
        };

        assert!(dr_manager.create_recovery_plan(plan).await.is_ok());
    }

    #[tokio::test]
    async fn test_list_recovery_plans() {
        let plan_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(
            DefaultBackupManager::new(backup_storage.clone(), None, BackupConfig::default())
                .unwrap(),
        );

        let dr_manager = DefaultDisasterRecoveryManager::new(plan_storage.clone(), backup_manager);

        // Create default plans
        dr_manager.create_default_plans().await.unwrap();

        let plans = dr_manager.list_recovery_plans().await.unwrap();
        assert_eq!(plans.len(), 3);

        // Verify plans are sorted by priority
        assert!(matches!(plans[0].priority, RecoveryPriority::Critical));
        assert!(matches!(plans[1].priority, RecoveryPriority::High));
        assert!(matches!(plans[2].priority, RecoveryPriority::Low));
    }

    #[tokio::test]
    async fn test_recovery_plan_validation() {
        let plan_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(
            DefaultBackupManager::new(backup_storage.clone(), None, BackupConfig::default())
                .unwrap(),
        );

        let dr_manager = DefaultDisasterRecoveryManager::new(plan_storage.clone(), backup_manager);

        // Test invalid plan (no steps)
        let invalid_plan = DisasterRecoveryPlan {
            plan_id: "invalid_plan".to_string(),
            name: "Invalid Plan".to_string(),
            description: "Invalid recovery plan".to_string(),
            recovery_steps: vec![],
            required_resources: vec![],
            estimated_recovery_time_minutes: 0,
            priority: RecoveryPriority::Low,
            last_tested: None,
        };

        assert!(dr_manager.create_recovery_plan(invalid_plan).await.is_err());

        // Test invalid plan (no name)
        let invalid_plan2 = DisasterRecoveryPlan {
            plan_id: "invalid_plan2".to_string(),
            name: "".to_string(),
            description: "Invalid recovery plan".to_string(),
            recovery_steps: vec![],
            required_resources: vec![],
            estimated_recovery_time_minutes: 0,
            priority: RecoveryPriority::Low,
            last_tested: None,
        };

        assert!(dr_manager
            .create_recovery_plan(invalid_plan2)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_recovery_plan_commands() {
        let plan_storage = Arc::new(InMemoryStorage::new());
        let backup_storage = Arc::new(InMemoryStorage::new());
        let backup_manager = Arc::new(
            DefaultBackupManager::new(backup_storage.clone(), None, BackupConfig::default())
                .unwrap(),
        );

        let dr_manager = DefaultDisasterRecoveryManager::new(plan_storage.clone(), backup_manager);

        let test_storage = Arc::new(InMemoryStorage::new());

        // Test storage health verification
        let result = dr_manager
            .verify_step_criteria("storage_health", &*test_storage)
            .await;
        assert!(result.is_ok());

        // Test key exists verification
        test_storage.put("test_key", b"test_data").await.unwrap();
        let result = dr_manager
            .verify_step_criteria("key_exists:test_key", &*test_storage)
            .await;
        assert!(result.is_ok());

        let result = dr_manager
            .verify_step_criteria("key_exists:nonexistent", &*test_storage)
            .await;
        assert!(result.is_err());

        // Test backup count verification
        let result = dr_manager
            .verify_step_criteria("backup_count:0", &*test_storage)
            .await;
        assert!(result.is_err()); // Should fail since we have backups
    }
}
