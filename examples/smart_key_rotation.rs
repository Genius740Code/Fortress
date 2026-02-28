//! Smart Key Rotation System Configuration and Monitoring Example

use fortress_core::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration as TokioDuration};
use chrono::{DateTime, Utc, Duration as ChronoDuration};

/// Configuration for the smart key rotation system
#[derive(Debug, Clone)]
pub struct SmartRotationConfig {
    /// Batch size for processing rotations
    pub batch_size: usize,
    /// Maximum concurrent rotations
    pub max_concurrent_rotations: usize,
    /// Rotation check interval in seconds
    pub check_interval_seconds: u64,
    /// Enable automatic rotation
    pub auto_rotation_enabled: bool,
    /// Alert threshold for soon-to-expire keys (hours)
    pub alert_threshold_hours: u64,
    /// Performance monitoring enabled
    pub performance_monitoring: bool,
}

impl Default for SmartRotationConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            max_concurrent_rotations: 10,
            check_interval_seconds: 3600, // 1 hour
            auto_rotation_enabled: true,
            alert_threshold_hours: 24,
            performance_monitoring: true,
        }
    }
}

/// Monitoring and metrics collector for key rotation
pub struct RotationMonitor {
    scheduler: Arc<SmartKeyRotationScheduler>,
    config: SmartRotationConfig,
    alert_handlers: Vec<Box<dyn RotationAlertHandler>>,
}

/// Trait for handling rotation alerts
pub trait RotationAlertHandler: Send + Sync {
    async fn handle_alert(&self, alert: RotationAlert) -> Result<()>;
}

/// Types of rotation alerts
#[derive(Debug, Clone)]
pub enum RotationAlert {
    /// Keys will need rotation soon
    UpcomingRotations { keys: Vec<(KeyId, DateTime<Utc>)>, hours_until: u64 },
    /// Rotation performance degraded
    PerformanceIssue { metric: String, value: f64, threshold: f64 },
    /// Rotation failure rate too high
    HighFailureRate { failure_rate: f64, threshold: f64 },
    /// No keys configured for rotation
    NoRotationConfigured,
}

/// Console alert handler for demonstration
pub struct ConsoleAlertHandler;

impl RotationAlertHandler for ConsoleAlertHandler {
    async fn handle_alert(&self, alert: RotationAlert) -> Result<()> {
        match alert {
            RotationAlert::UpcomingRotations { keys, hours_until } => {
                println!("🔑 ALERT: {} keys need rotation within {} hours", keys.len(), hours_until);
                for (key_id, when) in keys {
                    println!("  - Key {} at {}", key_id, when.format("%Y-%m-%d %H:%M:%S UTC"));
                }
            }
            RotationAlert::PerformanceIssue { metric, value, threshold } => {
                println!("⚠️  PERFORMANCE ALERT: {} = {} (threshold: {})", metric, value, threshold);
            }
            RotationAlert::HighFailureRate { failure_rate, threshold } => {
                println!("🚨 HIGH FAILURE RATE: {:.2}% (threshold: {:.2}%)", failure_rate * 100.0, threshold * 100.0);
            }
            RotationAlert::NoRotationConfigured => {
                println!("⚠️  CONFIGURATION ALERT: No keys configured for automatic rotation");
            }
        }
        Ok(())
    }
}

impl RotationMonitor {
    /// Create a new rotation monitor
    pub fn new(scheduler: Arc<SmartKeyRotationScheduler>, config: SmartRotationConfig) -> Self {
        Self {
            scheduler,
            config,
            alert_handlers: Vec::new(),
        }
    }

    /// Add an alert handler
    pub fn add_alert_handler(&mut self, handler: Box<dyn RotationAlertHandler>) {
        self.alert_handlers.push(handler);
    }

    /// Start the monitoring loop
    pub async fn start_monitoring(&self) -> Result<()> {
        if !self.config.auto_rotation_enabled {
            println!("Auto-rotation disabled, monitoring only");
        }

        let mut interval = interval(TokioDuration::from_secs(self.config.check_interval_seconds));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.perform_monitoring_cycle().await {
                eprintln!("Monitoring cycle failed: {}", e);
            }
        }
    }

    /// Perform a single monitoring cycle
    async fn perform_monitoring_cycle(&self) -> Result<()> {
        // Check for upcoming rotations
        self.check_upcoming_rotations().await?;
        
        // Check performance metrics
        if self.config.performance_monitoring {
            self.check_performance_metrics().await?;
        }
        
        // Perform auto-rotation if enabled
        if self.config.auto_rotation_enabled {
            self.perform_auto_rotation().await?;
        }
        
        Ok(())
    }

    /// Check for keys that will need rotation soon
    async fn check_upcoming_rotations(&self) -> Result<()> {
        let upcoming_keys = self.scheduler
            .get_keys_needing_soon_rotation(self.config.alert_threshold_hours as i64)
            .await?;
        
        if !upcoming_keys.is_empty() {
            let alert = RotationAlert::UpcomingRotations {
                keys: upcoming_keys.into_iter()
                    .map(|(id, metadata)| (id, metadata.created_at + metadata.expires_at.timestamp() as i64))
                    .collect(),
                hours_until: self.config.alert_threshold_hours,
            };
            
            self.send_alert(alert).await?;
        }
        
        Ok(())
    }

    /// Check performance metrics and alert on issues
    async fn check_performance_metrics(&self) -> Result<()> {
        let metrics = self.scheduler.get_metrics().await;
        
        // Check average rotation time (alert if > 5 seconds)
        if metrics.average_rotation_time_ms > 5000 {
            let alert = RotationAlert::PerformanceIssue {
                metric: "average_rotation_time_ms".to_string(),
                value: metrics.average_rotation_time_ms as f64,
                threshold: 5000.0,
            };
            self.send_alert(alert).await?;
        }
        
        // Check failure rate (alert if > 10%)
        if metrics.total_rotations > 0 {
            let failure_rate = metrics.failed_rotations as f64 / metrics.total_rotations as f64;
            if failure_rate > 0.1 {
                let alert = RotationAlert::HighFailureRate {
                    failure_rate,
                    threshold: 0.1,
                };
                self.send_alert(alert).await?;
            }
        }
        
        Ok(())
    }

    /// Perform automatic rotation
    async fn perform_auto_rotation(&self) -> Result<()> {
        let start_time = std::time::Instant::now();
        let rotated_keys = self.scheduler.check_and_rotate().await?;
        let duration = start_time.elapsed();
        
        if !rotated_keys.is_empty() {
            println!("✅ Auto-rotated {} keys in {:?}", rotated_keys.len(), duration);
            
            // Log rotation details
            for (key_id, metadata) in rotated_keys {
                println!("  - Rotated key {} (purpose: {}, version: {})", 
                    key_id, metadata.purpose, metadata.version);
            }
        }
        
        Ok(())
    }

    /// Send alert to all handlers
    async fn send_alert(&self, alert: RotationAlert) -> Result<()> {
        for handler in &self.alert_handlers {
            if let Err(e) = handler.handle_alert(alert.clone()).await {
                eprintln!("Failed to send alert: {}", e);
            }
        }
        Ok(())
    }

    /// Get comprehensive status report
    pub async fn get_status_report(&self) -> Result<RotationStatusReport> {
        let metrics = self.scheduler.get_metrics().await;
        let upcoming_keys = self.scheduler
            .get_keys_needing_soon_rotation(self.config.alert_threshold_hours as i64)
            .await?;
        
        Ok(RotationStatusReport {
            timestamp: Utc::now(),
            metrics,
            upcoming_rotations: upcoming_keys.len(),
            config: self.config.clone(),
            alert_handlers_count: self.alert_handlers.len(),
        })
    }
}

/// Comprehensive status report
#[derive(Debug, Clone)]
pub struct RotationStatusReport {
    pub timestamp: DateTime<Utc>,
    pub metrics: RotationMetrics,
    pub upcoming_rotations: usize,
    pub config: SmartRotationConfig,
    pub alert_handlers_count: usize,
}

/// Example usage of the smart key rotation system
pub async fn example_usage() -> Result<()> {
    println!("🚀 Smart Key Rotation System Example");
    println!("=====================================");
    
    // Create key manager
    let key_manager = Arc::new(InMemoryKeyManager::new());
    
    // Create smart rotation scheduler
    let mut scheduler = SmartKeyRotationScheduler::with_config(
        key_manager.clone(),
        50,  // batch size
        20,  // max concurrent rotations
    );
    
    // Configure rotation intervals for different security levels
    scheduler.set_security_level_intervals();
    
    // Add custom interval for special case
    scheduler.set_rotation_interval(
        "critical_infrastructure".to_string(),
        RotationInterval::Custom(ChronoDuration::hours(12))
    );
    
    println!("✅ Configured rotation intervals:");
    println!("  - High Security: 23 hours");
    println!("  - Sensitive: 7 days");
    println!("  - Standard: 30 days");
    println!("  - Low Sensitivity: 90 days");
    println!("  - Critical Infrastructure: 12 hours (custom)");
    
    // Create monitor with configuration
    let config = SmartRotationConfig {
        batch_size: 50,
        max_concurrent_rotations: 20,
        check_interval_seconds: 300, // 5 minutes for demo
        auto_rotation_enabled: true,
        alert_threshold_hours: 48,
        performance_monitoring: true,
    };
    
    let monitor = RotationMonitor::new(
        Arc::new(scheduler),
        config.clone()
    );
    
    // Add alert handlers
    let mut monitor_with_handlers = monitor;
    monitor_with_handlers.add_alert_handler(Box::new(ConsoleAlertHandler));
    
    println!("✅ Monitoring configured:");
    println!("  - Check interval: {} seconds", config.check_interval_seconds);
    println!("  - Auto-rotation: {}", config.auto_rotation_enabled);
    println!("  - Alert threshold: {} hours", config.alert_threshold_hours);
    
    // Generate some test keys
    println!("\n🔑 Generating test keys...");
    let algorithm = create_algorithm("AES256-GCM")?;
    
    // Create keys with different purposes and ages
    let test_keys = vec![
        ("high_security_key_1", "high_security", 25), // 25 hours old - needs rotation
        ("sensitive_key_1", "sensitive", 24 * 8),     // 8 days old - needs rotation
        ("standard_key_1", "standard", 24 * 31),      // 31 days old - needs rotation
        ("low_security_key_1", "low_sensitivity", 24 * 5), // 5 days old - doesn't need rotation
        ("critical_key_1", "critical_infrastructure", 13), // 13 hours old - needs rotation
    ];
    
    for (key_name, purpose, hours_old) in test_keys {
        let key = key_manager.generate_key(algorithm.as_ref()).await?;
        let created_at = Utc::now() - ChronoDuration::hours(hours_old);
        let expires_at = created_at + ChronoDuration::days(90);
        
        let metadata = KeyMetadata::new(
            key_name.to_string(),
            "AES256-GCM".to_string(),
            1,
            created_at,
            expires_at,
            purpose.to_string(),
            PerformanceProfile::Balanced,
        );
        
        key_manager.store_key(key_name, &key, &metadata).await?;
        println!("  - Created {} ({}) - {} hours old", key_name, purpose, hours_old);
    }
    
    // Perform initial rotation check
    println!("\n🔄 Performing initial rotation check...");
    let rotated_keys = monitor_with_handlers.scheduler.check_and_rotate().await?;
    println!("✅ Rotated {} keys", rotated_keys.len());
    
    // Get status report
    println!("\n📊 Status Report:");
    let report = monitor_with_handlers.get_status_report().await?;
    println!("  - Total rotations: {}", report.metrics.total_rotations);
    println!("  - Successful rotations: {}", report.metrics.successful_rotations);
    println!("  - Failed rotations: {}", report.metrics.failed_rotations);
    println!("  - Average rotation time: {} ms", report.metrics.average_rotation_time_ms);
    println!("  - Upcoming rotations: {}", report.upcoming_rotations);
    
    // Demonstrate force rotation
    println!("\n🔧 Demonstrating force rotation...");
    let (new_key, new_metadata) = monitor_with_handlers.scheduler.force_rotate_key("low_security_key_1").await?;
    println!("✅ Force rotated key to version {}", new_metadata.version);
    
    // Show metrics after force rotation
    let final_metrics = monitor_with_handlers.scheduler.get_metrics().await?;
    println!("📈 Final metrics:");
    println!("  - Total rotations: {}", final_metrics.total_rotations);
    println!("  - Last rotation: {:?}", final_metrics.last_rotation_time);
    
    println!("\n🎉 Smart key rotation system demo completed!");
    println!("📝 In production, the monitoring loop would run continuously");
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    example_usage().await
}
