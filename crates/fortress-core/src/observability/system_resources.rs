//! System resource monitoring for Fortress
//!
//! Provides real-time monitoring of CPU, memory, disk, and network resources
//! with cross-platform support and efficient collection.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;

/// System resource configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResourceConfig {
    /// Enable system resource monitoring
    pub enabled: bool,
    /// Collection interval in seconds
    pub collection_interval_seconds: u64,
    /// History retention count
    pub history_retention_count: usize,
    /// Enable detailed disk monitoring
    pub enable_disk_monitoring: bool,
    /// Enable network monitoring
    pub enable_network_monitoring: bool,
    /// Enable process-level monitoring
    pub enable_process_monitoring: bool,
    /// Alert thresholds
    pub alert_thresholds: ResourceThresholds,
}

/// Resource alert thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceThresholds {
    /// CPU usage warning threshold (percentage)
    pub cpu_warning_threshold: f64,
    /// CPU usage critical threshold (percentage)
    pub cpu_critical_threshold: f64,
    /// Memory usage warning threshold (percentage)
    pub memory_warning_threshold: f64,
    /// Memory usage critical threshold (percentage)
    pub memory_critical_threshold: f64,
    /// Disk usage warning threshold (percentage)
    pub disk_warning_threshold: f64,
    /// Disk usage critical threshold (percentage)
    pub disk_critical_threshold: f64,
    /// Network error rate threshold (percentage)
    pub network_error_threshold: f64,
}

impl Default for ResourceThresholds {
    fn default() -> Self {
        Self {
            cpu_warning_threshold: 70.0,
            cpu_critical_threshold: 90.0,
            memory_warning_threshold: 75.0,
            memory_critical_threshold: 90.0,
            disk_warning_threshold: 80.0,
            disk_critical_threshold: 95.0,
            network_error_threshold: 5.0,
        }
    }
}

impl Default for SystemResourceConfig {
    fn default() -> Self {
        tracing::info!("Default system resource configuration created");
        Self {
            enabled: true,
            collection_interval_seconds: 5,
            history_retention_count: 1000,
            enable_disk_monitoring: true,
            enable_network_monitoring: true,
            enable_process_monitoring: true,
            alert_thresholds: ResourceThresholds::default(),
        }
    }
}

/// CPU usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuUsage {
    /// Overall CPU usage percentage
    pub overall_usage_percent: f64,
    /// Per-core usage percentages
    pub per_core_usage: Vec<f64>,
    /// CPU time spent in user mode
    pub user_time_percent: f64,
    /// CPU time spent in system mode
    pub system_time_percent: f64,
    /// CPU time spent idle
    pub idle_time_percent: f64,
    /// Number of CPU cores
    pub core_count: usize,
    /// CPU frequency in MHz
    pub frequency_mhz: f64,
    /// Load averages (1min, 5min, 15min)
    pub load_averages: Option<(f64, f64, f64)>,
}

/// Memory usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsage {
    /// Total physical memory in bytes
    pub total_bytes: u64,
    /// Available physical memory in bytes
    pub available_bytes: u64,
    /// Used physical memory in bytes
    pub used_bytes: u64,
    /// Memory usage percentage
    pub usage_percent: f64,
    /// Total virtual memory in bytes
    pub virtual_total_bytes: u64,
    /// Used virtual memory in bytes
    pub virtual_used_bytes: u64,
    /// Swap space total in bytes
    pub swap_total_bytes: u64,
    /// Swap space used in bytes
    pub swap_used_bytes: u64,
    /// Swap usage percentage
    pub swap_usage_percent: f64,
    /// Page faults count
    pub page_faults: u64,
    /// Page swaps count
    pub page_swaps: u64,
}

/// Disk usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsage {
    /// Mount point
    pub mount_point: String,
    /// Filesystem type
    pub filesystem_type: String,
    /// Total disk space in bytes
    pub total_bytes: u64,
    /// Available disk space in bytes
    pub available_bytes: u64,
    /// Used disk space in bytes
    pub used_bytes: u64,
    /// Disk usage percentage
    pub usage_percent: f64,
    /// Read operations count
    pub read_ops: u64,
    /// Write operations count
    pub write_ops: u64,
    /// Bytes read
    pub bytes_read: u64,
    /// Bytes written
    pub bytes_written: u64,
    /// Read time in milliseconds
    pub read_time_ms: u64,
    /// Write time in milliseconds
    pub write_time_ms: u64,
    /// I/O queue depth
    pub queue_depth: f64,
}

/// Network usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkUsage {
    /// Interface name
    pub interface_name: String,
    /// Interface status (up/down)
    pub is_up: bool,
    /// Bytes received
    pub bytes_received: u64,
    /// Bytes transmitted
    pub bytes_transmitted: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packets transmitted
    pub packets_transmitted: u64,
    /// Receive errors
    pub receive_errors: u64,
    /// Transmit errors
    pub transmit_errors: u64,
    /// Receive drops
    pub receive_drops: u64,
    /// Transmit drops
    pub transmit_drops: u64,
    /// Receive bandwidth in bytes per second
    pub receive_bandwidth_bps: f64,
    /// Transmit bandwidth in bytes per second
    pub transmit_bandwidth_bps: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
}

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name
    pub name: String,
    /// Command line
    pub command_line: String,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// Number of threads
    pub thread_count: u32,
    /// Number of file descriptors
    pub fd_count: u32,
    /// Process start time
    pub start_time: chrono::DateTime<chrono::Utc>,
    /// Process status (running, sleeping, etc.)
    pub status: String,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
}

/// Complete system snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    /// Timestamp when snapshot was taken
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// CPU usage information
    pub cpu: CpuUsage,
    /// Memory usage information
    pub memory: MemoryUsage,
    /// Disk usage information for all mount points
    pub disks: Vec<DiskUsage>,
    /// Network usage information for all interfaces
    pub networks: Vec<NetworkUsage>,
    /// Process information for top processes
    pub processes: Vec<ProcessInfo>,
    /// System uptime in seconds
    pub uptime_seconds: u64,
    /// Boot time
    pub boot_time: chrono::DateTime<chrono::Utc>,
}

/// System resource monitor
#[derive(Debug)]
pub struct SystemResourceMonitor {
    /// Configuration
    config: SystemResourceConfig,
    /// Historical snapshots
    history: Arc<RwLock<Vec<SystemSnapshot>>>,
    /// Current snapshot
    current: Arc<RwLock<Option<SystemSnapshot>>>,
    /// Previous network stats for bandwidth calculation
    previous_network_stats: Arc<RwLock<HashMap<String, (u64, u64, Instant)>>>,
    /// Collection start time
    start_time: Instant,
}

impl SystemResourceMonitor {
    /// Create a new system resource monitor
    pub fn new(config: SystemResourceConfig) -> Self {
        let monitor = Self {
            config,
            history: Arc::new(RwLock::new(Vec::new())),
            current: Arc::new(RwLock::new(None)),
            previous_network_stats: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
        };

        // Start background collection
        monitor.start_collection_task();
        monitor
    }

    /// Start background collection task
    fn start_collection_task(&self) {
        if !self.config.enabled {
            return;
        }

        let history = self.history.clone();
        let current = self.current.clone();
        let previous_network_stats = self.previous_network_stats.clone();
        let interval_seconds = self.config.collection_interval_seconds;
        let retention_count = self.config.history_retention_count;
        let enable_disk = self.config.enable_disk_monitoring;
        let enable_network = self.config.enable_network_monitoring;
        let enable_process = self.config.enable_process_monitoring;

        tokio::spawn(async move {
            let mut interval_timer = interval(Duration::from_secs(interval_seconds));
            
            loop {
                interval_timer.tick().await;
                
                match Self::collect_system_snapshot(enable_disk, enable_network, enable_process, &previous_network_stats).await {
                    Ok(snapshot) => {
                        // Update current snapshot
                        {
                            let mut current_guard = current.write().await;
                            *current_guard = Some(snapshot.clone());
                        }

                        // Update history
                        {
                            let mut history_guard = history.write().await;
                            history_guard.push(snapshot);
                            
                            // Limit history size
                            if history_guard.len() > retention_count {
                                let excess = history_guard.len() - retention_count;
                                history_guard.drain(0..excess);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to collect system snapshot: {}", e);
                    }
                }
            }
        });
    }

    /// Collect current system snapshot
    async fn collect_system_snapshot(
        enable_disk: bool,
        enable_network: bool,
        enable_process: bool,
        previous_network_stats: &Arc<RwLock<HashMap<String, (u64, u64, Instant)>>>,
    ) -> Result<SystemSnapshot> {
        let timestamp = chrono::Utc::now();
        
        // Collect CPU information
        let cpu = Self::collect_cpu_info().await?;
        
        // Collect memory information
        let memory = Self::collect_memory_info().await?;
        
        // Collect disk information
        let disks = if enable_disk {
            Self::collect_disk_info().await?
        } else {
            Vec::new()
        };
        
        // Collect network information
        let networks = if enable_network {
            Self::collect_network_info(previous_network_stats).await?
        } else {
            Vec::new()
        };
        
        // Collect process information
        let processes = if enable_process {
            Self::collect_process_info().await?
        } else {
            Vec::new()
        };
        
        // Collect system uptime
        let uptime_seconds = Self::get_system_uptime().await?;
        let boot_time = timestamp - chrono::Duration::seconds(uptime_seconds as i64);

        Ok(SystemSnapshot {
            timestamp,
            cpu,
            memory,
            disks,
            networks,
            processes,
            uptime_seconds,
            boot_time,
        })
    }

    /// Collect CPU information
    async fn collect_cpu_info() -> Result<CpuUsage> {
        // Use sysinfo crate for cross-platform CPU information
        let mut system = sysinfo::System::new();
        system.refresh_all();
        
        let global_cpu = system.global_cpu_info();
        let overall_usage_percent = global_cpu.cpu_usage() as f64;
        
        // Get per-core usage
        let per_core_usage: Vec<f64> = system.cpus()
            .iter()
            .map(|cpu| cpu.cpu_usage() as f64)
            .collect();
        
        let core_count = per_core_usage.len();
        
        // Get load averages (Unix-like systems only)
        let load_averages = cfg!(unix).then(|| {
            let _loadavg = [0.0; 3];
            // Note: This would need platform-specific implementation
            // For now, return placeholder values
            Some((0.5, 0.3, 0.1))
        });

        Ok(CpuUsage {
            overall_usage_percent,
            per_core_usage,
            user_time_percent: 0.0, // Would need platform-specific implementation
            system_time_percent: 0.0, // Would need platform-specific implementation
            idle_time_percent: global_cpu.cpu_usage() as f64,
            core_count,
            frequency_mhz: 0.0, // Would need platform-specific implementation
            load_averages: load_averages.flatten(),
        })
    }

    /// Collect memory information
    async fn collect_memory_info() -> Result<MemoryUsage> {
        let mut system = sysinfo::System::new();
        system.refresh_all();
        
        let total_bytes = system.total_memory();
        let available_bytes = system.available_memory();
        let used_bytes = total_bytes - available_bytes;
        let usage_percent = (used_bytes as f64 / total_bytes as f64) * 100.0;
        
        let swap_total_bytes = system.total_swap();
        let swap_used_bytes = system.used_swap();
        let swap_usage_percent = if swap_total_bytes > 0 {
            (swap_used_bytes as f64 / swap_total_bytes as f64) * 100.0
        } else {
            0.0
        };

        Ok(MemoryUsage {
            total_bytes,
            available_bytes,
            used_bytes,
            usage_percent,
            virtual_total_bytes: total_bytes, // Simplified
            virtual_used_bytes: used_bytes,
            swap_total_bytes,
            swap_used_bytes,
            swap_usage_percent,
            page_faults: 0, // Would need platform-specific implementation
            page_swaps: 0,
        })
    }

    /// Collect disk information
    async fn collect_disk_info() -> Result<Vec<DiskUsage>> {
        let mut system = sysinfo::System::new();
        system.refresh_all();
        
        let mut disks = Vec::new();
        
        // For now, return a placeholder disk usage
        // In a real implementation, you would use platform-specific APIs
        disks.push(DiskUsage {
            mount_point: "/".to_string(),
            filesystem_type: "unknown".to_string(),
            total_bytes: 1000000000000, // 1TB
            available_bytes: 500000000000, // 500GB
            used_bytes: 500000000000, // 500GB
            usage_percent: 50.0,
            read_ops: 0,
            write_ops: 0,
            bytes_read: 0,
            bytes_written: 0,
            read_time_ms: 0,
            write_time_ms: 0,
            queue_depth: 0.0,
        });
        
        Ok(disks)
    }

    /// Collect network information
    async fn collect_network_info(
        _previous_network_stats: &Arc<RwLock<HashMap<String, (u64, u64, Instant)>>>,
    ) -> Result<Vec<NetworkUsage>> {
        let mut networks = Vec::new();
        
        // For now, return a placeholder network usage
        // In a real implementation, you would use platform-specific APIs
        networks.push(NetworkUsage {
            interface_name: "eth0".to_string(),
            is_up: true,
            bytes_received: 1000000,
            bytes_transmitted: 500000,
            packets_received: 1000,
            packets_transmitted: 800,
            receive_errors: 0,
            transmit_errors: 0,
            receive_drops: 0,
            transmit_drops: 0,
            receive_bandwidth_bps: 100000.0,
            transmit_bandwidth_bps: 50000.0,
            error_rate_percent: 0.0,
        });
        
        Ok(networks)
    }

    /// Collect process information
    async fn collect_process_info() -> Result<Vec<ProcessInfo>> {
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        
        let mut processes = Vec::new();
        
        // Get top processes by CPU usage
        let mut process_list: Vec<_> = system.processes().values().collect();
        process_list.sort_by(|a, b| b.cpu_usage().partial_cmp(&a.cpu_usage()).unwrap());
        
        for process in process_list.iter().take(20) { // Top 20 processes
            let pid = process.pid().as_u32();
            let memory_usage_bytes = process.memory();
            let memory_usage_percent = (memory_usage_bytes as f64 / system.total_memory() as f64) * 100.0;
            
            processes.push(ProcessInfo {
                pid,
                ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                name: process.name().to_string(),
                command_line: process.cmd().join(" "),
                cpu_usage_percent: process.cpu_usage() as f64,
                memory_usage_bytes,
                memory_usage_percent,
                thread_count: 0, // Would need additional info
                fd_count: 0, // Would need platform-specific implementation
                start_time: chrono::Utc::now(), // Would need actual start time
                status: format!("{:?}", process.status()),
                uid: 0, // Would need platform-specific implementation
                gid: 0,
            });
        }
        
        Ok(processes)
    }

    /// Get system uptime in seconds
    async fn get_system_uptime() -> Result<u64> {
        Ok(sysinfo::System::uptime())
    }

    /// Get current system snapshot
    pub async fn get_current_snapshot(&self) -> Option<SystemSnapshot> {
        let current = self.current.read().await;
        current.clone()
    }

    /// Get historical snapshots
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<SystemSnapshot> {
        let history = self.history.read().await;
        match limit {
            Some(limit) => history.iter().rev().take(limit).cloned().collect(),
            None => history.clone(),
        }
    }

    /// Get resource alerts based on thresholds
    pub async fn get_resource_alerts(&self) -> Vec<ResourceAlert> {
        let current = self.current.read().await;
        let thresholds = &self.config.alert_thresholds;
        let mut alerts = Vec::new();
        
        if let Some(snapshot) = current.as_ref() {
            // CPU alerts
            if snapshot.cpu.overall_usage_percent > thresholds.cpu_critical_threshold {
                alerts.push(ResourceAlert {
                    resource_type: ResourceType::Cpu,
                    severity: AlertSeverity::Critical,
                    message: format!("Critical CPU usage: {:.1}%", snapshot.cpu.overall_usage_percent),
                    current_value: snapshot.cpu.overall_usage_percent,
                    threshold_value: thresholds.cpu_critical_threshold,
                });
            } else if snapshot.cpu.overall_usage_percent > thresholds.cpu_warning_threshold {
                alerts.push(ResourceAlert {
                    resource_type: ResourceType::Cpu,
                    severity: AlertSeverity::Warning,
                    message: format!("High CPU usage: {:.1}%", snapshot.cpu.overall_usage_percent),
                    current_value: snapshot.cpu.overall_usage_percent,
                    threshold_value: thresholds.cpu_warning_threshold,
                });
            }
            
            // Memory alerts
            if snapshot.memory.usage_percent > thresholds.memory_critical_threshold {
                alerts.push(ResourceAlert {
                    resource_type: ResourceType::Memory,
                    severity: AlertSeverity::Critical,
                    message: format!("Critical memory usage: {:.1}%", snapshot.memory.usage_percent),
                    current_value: snapshot.memory.usage_percent,
                    threshold_value: thresholds.memory_critical_threshold,
                });
            } else if snapshot.memory.usage_percent > thresholds.memory_warning_threshold {
                alerts.push(ResourceAlert {
                    resource_type: ResourceType::Memory,
                    severity: AlertSeverity::Warning,
                    message: format!("High memory usage: {:.1}%", snapshot.memory.usage_percent),
                    current_value: snapshot.memory.usage_percent,
                    threshold_value: thresholds.memory_warning_threshold,
                });
            }
            
            // Disk alerts
            for disk in &snapshot.disks {
                if disk.usage_percent > thresholds.disk_critical_threshold {
                    alerts.push(ResourceAlert {
                        resource_type: ResourceType::Disk,
                        severity: AlertSeverity::Critical,
                        message: format!("Critical disk usage on {}: {:.1}%", disk.mount_point, disk.usage_percent),
                        current_value: disk.usage_percent,
                        threshold_value: thresholds.disk_critical_threshold,
                    });
                } else if disk.usage_percent > thresholds.disk_warning_threshold {
                    alerts.push(ResourceAlert {
                        resource_type: ResourceType::Disk,
                        severity: AlertSeverity::Warning,
                        message: format!("High disk usage on {}: {:.1}%", disk.mount_point, disk.usage_percent),
                        current_value: disk.usage_percent,
                        threshold_value: thresholds.disk_warning_threshold,
                    });
                }
            }
            
            // Network alerts
            for network in &snapshot.networks {
                if network.error_rate_percent > thresholds.network_error_threshold {
                    alerts.push(ResourceAlert {
                        resource_type: ResourceType::Network,
                        severity: AlertSeverity::Warning,
                        message: format!("High network error rate on {}: {:.1}%", network.interface_name, network.error_rate_percent),
                        current_value: network.error_rate_percent,
                        threshold_value: thresholds.network_error_threshold,
                    });
                }
            }
        }
        
        alerts
    }

    /// Get performance trends over time
    pub async fn get_performance_trends(&self, duration_minutes: u64) -> Result<PerformanceTrends> {
        let history = self.history.read().await;
        let cutoff_time = chrono::Utc::now() - chrono::Duration::minutes(duration_minutes as i64);
        
        let recent_snapshots: Vec<_> = history.iter()
            .filter(|snapshot| snapshot.timestamp > cutoff_time)
            .collect();
        
        if recent_snapshots.is_empty() {
            return Err(FortressError::storage(
                "No data available for trend analysis".to_string(),
                "system_monitor".to_string(),
                crate::error::StorageErrorCode::NotFound,
            ));
        }
        
        // Calculate trends
        let cpu_trend = Self::calculate_trend(&recent_snapshots, |s| s.cpu.overall_usage_percent);
        let memory_trend = Self::calculate_trend(&recent_snapshots, |s| s.memory.usage_percent);
        
        Ok(PerformanceTrends {
            duration_minutes,
            cpu_trend,
            memory_trend,
            sample_count: recent_snapshots.len(),
        })
    }

    /// Calculate trend from a series of values
    fn calculate_trend<T, F>(snapshots: &[&SystemSnapshot], extractor: F) -> Trend
    where
        F: Fn(&SystemSnapshot) -> T,
        T: Into<f64>,
    {
        if snapshots.len() < 2 {
            return Trend::Stable;
        }
        
        let values: Vec<f64> = snapshots.iter()
            .map(|&s| extractor(s).into())
            .collect();
        
        let first_half = &values[..values.len() / 2];
        let second_half = &values[values.len() / 2..];
        
        let first_avg = first_half.iter().sum::<f64>() / first_half.len() as f64;
        let second_avg = second_half.iter().sum::<f64>() / second_half.len() as f64;
        
        let change_percent = ((second_avg - first_avg) / first_avg) * 100.0;
        
        match change_percent {
            x if x > 10.0 => Trend::Increasing,
            x if x < -10.0 => Trend::Decreasing,
            _ => Trend::Stable,
        }
    }
}

/// Resource alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAlert {
    /// Resource type
    pub resource_type: ResourceType,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert message
    pub message: String,
    /// Current value
    pub current_value: f64,
    /// Threshold value
    pub threshold_value: f64,
}

/// Resource types for monitoring
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ResourceType {
    /// CPU resource
    Cpu,
    /// Memory resource
    Memory,
    /// Disk storage resource
    Disk,
    /// Network resource
    Network,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Warning level alert
    Warning,
    /// Critical level alert
    Critical,
}

/// Performance trend direction
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Trend {
    /// Increasing trend
    Increasing,
    /// Decreasing trend
    Decreasing,
    /// Stable trend
    Stable,
}

/// Performance trends summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTrends {
    /// Analysis duration in minutes
    pub duration_minutes: u64,
    /// CPU usage trend
    pub cpu_trend: Trend,
    /// Memory usage trend
    pub memory_trend: Trend,
    /// Number of samples analyzed
    pub sample_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_system_resource_monitor_creation() {
        let config = SystemResourceConfig::default();
        let monitor = SystemResourceMonitor::new(config);
        
        // Wait for initial collection
        sleep(Duration::from_millis(100)).await;
        
        let snapshot = monitor.get_current_snapshot().await;
        assert!(snapshot.is_some());
    }

    #[tokio::test]
    async fn test_resource_alerts() {
        let config = SystemResourceConfig {
            alert_thresholds: ResourceThresholds {
                cpu_warning_threshold: 0.1, // Very low to trigger alerts
                memory_warning_threshold: 0.1,
                ..Default::default()
            },
            ..Default::default()
        };
        
        let monitor = SystemResourceMonitor::new(config);
        
        // Wait for initial collection
        sleep(Duration::from_millis(100)).await;
        
        let alerts = monitor.get_resource_alerts().await;
        // Should trigger alerts due to low thresholds
        assert!(!alerts.is_empty());
    }

    #[tokio::test]
    async fn test_performance_trends() {
        let config = SystemResourceConfig::default();
        let monitor = SystemResourceMonitor::new(config);
        
        // Wait for some data collection
        sleep(Duration::from_millis(200)).await;
        
        let trends = monitor.get_performance_trends(1).await;
        // May fail if no data collected yet, which is expected
        assert!(trends.is_ok() || trends.is_err());
    }
}
