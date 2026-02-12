//! Audit log rotation and retention policies for Fortress
//!
//! This module provides automated log rotation, retention management,
//! and cleanup capabilities for audit logs.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Datelike};

use crate::error::{FortressError, Result};
use crate::audit::{AuditConfig, AuditEntry, AuditLogger};

/// Log rotation strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RotationStrategy {
    /// Rotate logs daily
    Daily,
    /// Rotate logs weekly
    Weekly,
    /// Rotate logs monthly
    Monthly,
    /// Rotate logs when file size exceeds limit
    SizeBased,
    /// Rotate logs after specified time interval
    Interval { seconds: u64 },
}

/// Retention policy for audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// How long to keep logs (in days)
    pub retention_days: u32,
    /// Maximum number of rotated files to keep
    pub max_files: u32,
    /// Compress old logs
    pub compress_old_logs: bool,
    /// Delete logs older than retention period
    pub auto_delete: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retention_days: 90,
            max_files: 10,
            compress_old_logs: true,
            auto_delete: true,
        }
    }
}

/// Log rotation manager
pub struct LogRotationManager {
    config: AuditConfig,
    retention_policy: RetentionPolicy,
    rotation_strategy: RotationStrategy,
    log_directory: PathBuf,
    current_log_file: PathBuf,
    last_rotation_time: Option<SystemTime>,
}

impl LogRotationManager {
    /// Create a new log rotation manager
    pub fn new(
        config: AuditConfig,
        retention_policy: RetentionPolicy,
        rotation_strategy: RotationStrategy,
    ) -> Result<Self> {
        let log_directory = config.log_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("logs"))
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        let current_log_file = config.log_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| log_directory.join("audit.log"));

        // Ensure log directory exists
        fs::create_dir_all(&log_directory)
            .map_err(|e| FortressError::io(
                format!("Failed to create log directory: {}", e),
                Some(log_directory.to_string_lossy().to_string()),
            ))?;

        Ok(Self {
            config,
            retention_policy,
            rotation_strategy,
            log_directory,
            current_log_file,
            last_rotation_time: None,
        })
    }

    /// Check if rotation is needed and perform it if necessary
    pub fn check_and_rotate(&mut self) -> Result<bool> {
        if !self.config.enable_rotation {
            return Ok(false);
        }

        let needs_rotation = self.needs_rotation()?;
        
        if needs_rotation {
            self.rotate_logs()?;
            self.cleanup_old_logs()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if log rotation is needed
    fn needs_rotation(&self) -> Result<bool> {
        match &self.rotation_strategy {
            RotationStrategy::Daily => {
                if let Some(last_rotation) = self.last_rotation_time {
                    let now = SystemTime::now();
                    let duration = now.duration_since(last_rotation)
                        .map_err(|e| FortressError::internal(
                            format!("Time error checking rotation: {}", e),
                            "TIME_ERROR".to_string(),
                        ))?;
                    Ok(duration >= Duration::from_secs(24 * 60 * 60))
                } else {
                    Ok(true) // First time, need to check existing file
                }
            }
            RotationStrategy::Weekly => {
                if let Some(last_rotation) = self.last_rotation_time {
                    let now = SystemTime::now();
                    let duration = now.duration_since(last_rotation)
                        .map_err(|e| FortressError::internal(
                            format!("Time error checking rotation: {}", e),
                            "TIME_ERROR".to_string(),
                        ))?;
                    Ok(duration >= Duration::from_secs(7 * 24 * 60 * 60))
                } else {
                    Ok(true)
                }
            }
            RotationStrategy::Monthly => {
                if let Some(last_rotation) = self.last_rotation_time {
                    let now = SystemTime::now();
                    let duration = now.duration_since(last_rotation)
                        .map_err(|e| FortressError::internal(
                            format!("Time error checking rotation: {}", e),
                            "TIME_ERROR".to_string(),
                        ))?;
                    Ok(duration >= Duration::from_secs(30 * 24 * 60 * 60))
                } else {
                    Ok(true)
                }
            }
            RotationStrategy::SizeBased => {
                if let Ok(metadata) = fs::metadata(&self.current_log_file) {
                    Ok(metadata.len() >= self.config.max_file_size)
                } else {
                    Ok(false)
                }
            }
            RotationStrategy::Interval { seconds } => {
                if let Some(last_rotation) = self.last_rotation_time {
                    let now = SystemTime::now();
                    let duration = now.duration_since(last_rotation)
                        .map_err(|e| FortressError::internal(
                            format!("Time error checking rotation: {}", e),
                            "TIME_ERROR".to_string(),
                        ))?;
                    Ok(duration >= Duration::from_secs(*seconds))
                } else {
                    Ok(true)
                }
            }
        }
    }

    /// Perform log rotation
    fn rotate_logs(&mut self) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| FortressError::internal(
                format!("Failed to get current time: {}", e),
                "TIME_ERROR".to_string(),
            ))?
            .as_secs();

        let rotated_filename = format!(
            "audit_{}.log",
            DateTime::from_timestamp(timestamp as i64, 0)
                .unwrap_or_default()
                .format("%Y%m%d_%H%M%S")
        );

        let rotated_path = self.log_directory.join(&rotated_filename);

        // Move current log to rotated file
        if self.current_log_file.exists() {
            fs::rename(&self.current_log_file, &rotated_path)
                .map_err(|e| FortressError::io(
                    format!("Failed to rotate log file: {}", e),
                    Some(self.current_log_file.to_string_lossy().to_string()),
                ))?;

            // Compress if enabled
            if self.retention_policy.compress_old_logs {
                self.compress_log_file(&rotated_path)?;
            }
        }

        // Update last rotation time
        self.last_rotation_time = Some(SystemTime::now());

        Ok(())
    }

    /// Compress a log file using gzip
    fn compress_log_file(&self, log_path: &Path) -> Result<()> {
        let compressed_path = log_path.with_extension("log.gz");
        
        // Read the original file
        let content = fs::read(log_path)
            .map_err(|e| FortressError::io(
                format!("Failed to read log file for compression: {}", e),
                Some(log_path.to_string_lossy().to_string()),
            ))?;

        // Compress using flate2
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut encoder = encoder;
        
        encoder.write_all(&content)
            .map_err(|e| FortressError::io(
                format!("Failed to compress log file: {}", e),
                Some(log_path.to_string_lossy().to_string()),
            ))?;

        let compressed_data = encoder.finish()
            .map_err(|e| FortressError::io(
                format!("Failed to finish compression: {}", e),
                Some(log_path.to_string_lossy().to_string()),
            ))?;

        // Write compressed file
        fs::write(&compressed_path, compressed_data)
            .map_err(|e| FortressError::io(
                format!("Failed to write compressed log file: {}", e),
                Some(compressed_path.to_string_lossy().to_string()),
            ))?;

        // Remove original file
        fs::remove_file(log_path)
            .map_err(|e| FortressError::io(
                format!("Failed to remove original log file after compression: {}", e),
                Some(log_path.to_string_lossy().to_string()),
            ))?;

        Ok(())
    }

    /// Clean up old log files based on retention policy
    fn cleanup_old_logs(&self) -> Result<()> {
        let entries = self.list_log_files()?;
        let cutoff_time = SystemTime::now() - Duration::from_secs(
            self.retention_policy.retention_days as u64 * 24 * 60 * 60
        );

        let mut files_to_delete = Vec::new();
        let mut file_count = 0;

        for entry in entries {
            file_count += 1;

            // Check if file is older than retention period
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified_time) = metadata.modified() {
                    if modified_time < cutoff_time {
                        files_to_delete.push(entry.path());
                        continue;
                    }
                }
            }

            // Check if we have too many files
            if file_count > self.retention_policy.max_files {
                files_to_delete.push(entry.path());
            }
        }

        // Delete old files if auto-delete is enabled
        if self.retention_policy.auto_delete {
            for file_path in files_to_delete {
                if let Err(e) = fs::remove_file(&file_path) {
                    eprintln!("Failed to delete old log file {}: {}", 
                             file_path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// List all log files in the directory
    fn list_log_files(&self) -> Result<Vec<fs::DirEntry>> {
        let mut entries = Vec::new();

        if self.log_directory.exists() {
            for entry in fs::read_dir(&self.log_directory)
                .map_err(|e| FortressError::io(
                    format!("Failed to read log directory: {}", e),
                    Some(self.log_directory.to_string_lossy().to_string()),
                ))? {
                let entry = entry
                    .map_err(|e| FortressError::io(
                        format!("Failed to read directory entry: {}", e),
                        None,
                    ))?;

                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                // Include audit log files (current and rotated)
                if file_name_str.starts_with("audit_") && 
                   (file_name_str.ends_with(".log") || file_name_str.ends_with(".log.gz")) {
                    entries.push(entry);
                }
            }
        }

        // Sort by modification time (newest first)
        entries.sort_by(|a, b| {
            let time_a = a.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(UNIX_EPOCH);
            let time_b = b.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(UNIX_EPOCH);
            time_b.cmp(&time_a)
        });

        Ok(entries)
    }

    /// Get statistics about log files
    pub fn get_log_statistics(&self) -> Result<LogStatistics> {
        let entries = self.list_log_files()?;
        let mut total_size = 0u64;
        let mut file_count = 0;
        let mut compressed_count = 0;
        let mut oldest_file: Option<SystemTime> = None;
        let mut newest_file: Option<SystemTime> = None;

        for entry in entries {
            file_count += 1;

            let metadata = entry.metadata()
                .map_err(|e| FortressError::io(
                    format!("Failed to get file metadata: {}", e),
                    Some(entry.path().to_string_lossy().to_string()),
                ))?;

            total_size += metadata.len();

            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.ends_with(".gz") {
                compressed_count += 1;
            }

            if let Ok(modified_time) = metadata.modified() {
                oldest_file = oldest_file.map_or(Some(modified_time), |oldest| {
                    Some(oldest.min(modified_time))
                });
                newest_file = newest_file.map_or(Some(modified_time), |newest| {
                    Some(newest.max(modified_time))
                });
            }
        }

        Ok(LogStatistics {
            total_files: file_count,
            total_size_bytes: total_size,
            compressed_files: compressed_count,
            oldest_file,
            newest_file,
            retention_policy: self.retention_policy.clone(),
            rotation_strategy: self.rotation_strategy.clone(),
        })
    }

    /// Force an immediate rotation
    pub fn force_rotation(&mut self) -> Result<()> {
        self.rotate_logs()?;
        self.cleanup_old_logs()?;
        Ok(())
    }
}

/// Statistics about audit log files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStatistics {
    /// Total number of log files
    pub total_files: u32,
    /// Total size of all log files in bytes
    pub total_size_bytes: u64,
    /// Number of compressed log files
    pub compressed_files: u32,
    /// Oldest log file modification time
    pub oldest_file: Option<SystemTime>,
    /// Newest log file modification time
    pub newest_file: Option<SystemTime>,
    /// Current retention policy
    pub retention_policy: RetentionPolicy,
    /// Current rotation strategy
    pub rotation_strategy: RotationStrategy,
}

/// Background task for automatic log rotation
pub struct RotationTask {
    manager: LogRotationManager,
    check_interval: Duration,
}

impl RotationTask {
    /// Create a new rotation task
    pub fn new(
        manager: LogRotationManager,
        check_interval: Duration,
    ) -> Self {
        Self {
            manager,
            check_interval,
        }
    }

    /// Run the rotation task (blocking)
    pub fn run(&mut self) -> Result<()> {
        loop {
            std::thread::sleep(self.check_interval);
            
            if let Err(e) = self.manager.check_and_rotate() {
                eprintln!("Log rotation error: {}", e);
            }
        }
    }

    /// Run the rotation task with a timeout
    pub fn run_with_timeout(&mut self, timeout: Duration) -> Result<()> {
        let start = SystemTime::now();
        
        while start.elapsed().unwrap_or(Duration::MAX) < timeout {
            std::thread::sleep(self.check_interval.min(Duration::from_secs(60)));
            
            if let Err(e) = self.manager.check_and_rotate() {
                eprintln!("Log rotation error: {}", e);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_retention_policy_default() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.retention_days, 90);
        assert_eq!(policy.max_files, 10);
        assert!(policy.compress_old_logs);
        assert!(policy.auto_delete);
    }

    #[test]
    fn test_log_rotation_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_audit.log");
        
        let config = AuditConfig {
            enabled: true,
            log_path: Some(log_path.to_string_lossy().to_string()),
            enable_rotation: true,
            ..Default::default()
        };

        let retention_policy = RetentionPolicy::default();
        let rotation_strategy = RotationStrategy::Daily;

        let manager = LogRotationManager::new(
            config,
            retention_policy,
            rotation_strategy,
        ).unwrap();

        assert!(manager.log_directory.exists());
    }

    #[test]
    fn test_size_based_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test_audit.log");
        
        // Create a small log file
        fs::write(&log_path, "test log content").unwrap();

        let config = AuditConfig {
            enabled: true,
            log_path: Some(log_path.to_string_lossy().to_string()),
            enable_rotation: true,
            max_file_size: 10, // Very small to trigger rotation
            ..Default::default()
        };

        let retention_policy = RetentionPolicy::default();
        let rotation_strategy = RotationStrategy::SizeBased;

        let mut manager = LogRotationManager::new(
            config,
            retention_policy,
            rotation_strategy,
        ).unwrap();

        // Should need rotation
        assert!(manager.needs_rotation().unwrap());
    }

    #[test]
    fn test_log_statistics() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create some test log files
        fs::write(temp_dir.path().join("audit_20231201_120000.log"), "log1").unwrap();
        fs::write(temp_dir.path().join("audit_20231202_120000.log.gz"), "log2").unwrap();
        fs::write(temp_dir.path().join("other_file.txt"), "other").unwrap();

        let config = AuditConfig {
            enabled: true,
            log_path: Some(temp_dir.path().join("audit.log").to_string_lossy().to_string()),
            enable_rotation: true,
            ..Default::default()
        };

        let retention_policy = RetentionPolicy::default();
        let rotation_strategy = RotationStrategy::Daily;

        let manager = LogRotationManager::new(
            config,
            retention_policy,
            rotation_strategy,
        ).unwrap();

        let stats = manager.get_log_statistics().unwrap();
        assert_eq!(stats.total_files, 2); // Only audit log files
        assert_eq!(stats.compressed_files, 1); // One .gz file
    }

    #[test]
    fn test_rotation_strategies() {
        let daily = RotationStrategy::Daily;
        let weekly = RotationStrategy::Weekly;
        let monthly = RotationStrategy::Monthly;
        let size_based = RotationStrategy::SizeBased;
        let interval = RotationStrategy::Interval { seconds: 3600 };

        assert_eq!(daily, RotationStrategy::Daily);
        assert_eq!(weekly, RotationStrategy::Weekly);
        assert_eq!(monthly, RotationStrategy::Monthly);
        assert_eq!(size_based, RotationStrategy::SizeBased);
        assert_eq!(interval, RotationStrategy::Interval { seconds: 3600 });
    }
}
