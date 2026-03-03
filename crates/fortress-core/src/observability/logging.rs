//! Structured logging system for Fortress
//!
//! Provides comprehensive structured logging with multiple output formats,
//! log levels, filtering, and integration with observability stack.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[cfg(feature = "tracing-subscriber")]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Structured logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Enable structured logging
    pub enabled: bool,
    /// Default log level
    pub level: LogLevel,
    /// Output format
    pub format: LogFormat,
    /// Output configuration
    pub output: LogOutputConfig,
    /// Filtering configuration
    pub filtering: LogFilteringConfig,
    /// Sampling configuration
    pub sampling: LogSamplingConfig,
    /// Context enrichment
    pub context: LogContextConfig,
}

/// Log levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Trace level
    Trace,
    /// Debug level
    Debug,
    /// Info level
    Info,
    /// Warn level
    Warn,
    /// Error level
    Error,
}

/// Log output formats
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogFormat {
    /// Plain text format
    Plain,
    /// JSON format
    Json,
    /// Compact JSON format
    CompactJson,
    /// Pretty format for development
    Pretty,
    /// Structured format with fields
    Structured,
}

/// Log output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogOutputConfig {
    /// Output targets
    pub targets: Vec<LogOutputTarget>,
    /// Buffer configuration
    pub buffer: LogBufferConfig,
    /// Rotation configuration
    pub rotation: LogRotationConfig,
}

/// Log output targets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogOutputTarget {
    /// Target ID
    pub id: String,
    /// Target type
    pub target_type: LogOutputType,
    /// Target configuration
    pub config: HashMap<String, String>,
    /// Enabled status
    pub enabled: bool,
    /// Log levels for this target
    pub levels: Vec<LogLevel>,
}

/// Log output types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogOutputType {
    /// Console output
    Console,
    /// File output
    File,
    /// Syslog output
    Syslog,
    /// Network output
    Network,
    /// Elasticsearch output
    Elasticsearch,
    /// Loki output
    Loki,
}

/// Log buffer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogBufferConfig {
    /// Enable buffering
    pub enabled: bool,
    /// Buffer size in bytes
    pub size_bytes: usize,
    /// Flush interval in seconds
    pub flush_interval_seconds: u64,
    /// Maximum number of buffered logs
    pub max_logs: usize,
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Enable rotation
    pub enabled: bool,
    /// Maximum file size in bytes
    pub max_file_size_bytes: u64,
    /// Maximum number of files to keep
    pub max_files: usize,
    /// Rotation schedule
    pub schedule: RotationSchedule,
}

/// Rotation schedule
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RotationSchedule {
    /// Rotate daily
    Daily,
    /// Rotate hourly
    Hourly,
    /// Rotate when file size limit reached
    Size,
    /// Rotate both size and time
    Both,
}

/// Log filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilteringConfig {
    /// Enable filtering
    pub enabled: bool,
    /// Module filters
    pub module_filters: HashMap<String, LogLevel>,
    /// Target filters
    pub target_filters: HashMap<String, Vec<String>>,
    /// Field filters
    pub field_filters: Vec<String>,
    /// Exclude patterns
    pub exclude_patterns: Vec<String>,
}

/// Log sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSamplingConfig {
    /// Enable sampling
    pub enabled: bool,
    /// Sampling strategy
    pub strategy: SamplingStrategy,
    /// Sampling rate (0.0 to 1.0)
    pub rate: f64,
    /// Maximum samples per second
    pub max_samples_per_second: u32,
}

/// Sampling strategies
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SamplingStrategy {
    /// Random sampling
    Random,
    /// Rate-based sampling
    Rate,
    /// Priority-based sampling
    Priority,
}

/// Log context configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogContextConfig {
    /// Enable context enrichment
    pub enabled: bool,
    /// Global context fields
    pub global_fields: HashMap<String, String>,
    /// Automatic fields to include
    pub auto_fields: Vec<AutoField>,
    /// Custom context providers
    pub custom_providers: Vec<String>,
}

/// Automatic fields to include
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AutoField {
    /// Timestamp
    Timestamp,
    /// Process ID
    ProcessId,
    /// Thread ID
    ThreadId,
    /// Hostname
    Hostname,
    /// Service name
    ServiceName,
    /// Service version
    ServiceVersion,
    /// Trace ID (if available)
    TraceId,
    /// Span ID (if available)
    SpanId,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: LogLevel::Info,
            format: LogFormat::Json,
            output: LogOutputConfig::default(),
            filtering: LogFilteringConfig::default(),
            sampling: LogSamplingConfig::default(),
            context: LogContextConfig::default(),
        }
    }
}

impl Default for LogOutputConfig {
    fn default() -> Self {
        Self {
            targets: vec![LogOutputTarget {
                id: "console".to_string(),
                target_type: LogOutputType::Console,
                config: HashMap::new(),
                enabled: true,
                levels: vec![LogLevel::Trace, LogLevel::Debug, LogLevel::Info, LogLevel::Warn, LogLevel::Error],
            }],
            buffer: LogBufferConfig::default(),
            rotation: LogRotationConfig::default(),
        }
    }
}

impl Default for LogBufferConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size_bytes: 1024 * 1024, // 1MB
            flush_interval_seconds: 5,
            max_logs: 10000,
        }
    }
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_file_size_bytes: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            schedule: RotationSchedule::Size,
        }
    }
}

impl Default for LogFilteringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            module_filters: HashMap::new(),
            target_filters: HashMap::new(),
            field_filters: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }
}

impl Default for LogSamplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: SamplingStrategy::Random,
            rate: 1.0,
            max_samples_per_second: 1000,
        }
    }
}

impl Default for LogContextConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_fields: HashMap::new(),
            auto_fields: vec![
                AutoField::Timestamp,
                AutoField::ProcessId,
                AutoField::ThreadId,
                AutoField::Hostname,
                AutoField::ServiceName,
                AutoField::ServiceVersion,
            ],
            custom_providers: Vec::new(),
        }
    }
}

/// Structured logger
#[derive(Debug)]
pub struct StructuredLogger {
    /// Configuration
    config: LogConfig,
    /// Global context
    global_context: Arc<RwLock<HashMap<String, String>>>,
    /// Statistics
    stats: Arc<RwLock<LogStats>>,
    /// Start time
    start_time: Instant,
}

/// Logging statistics
#[derive(Debug, Default)]
struct LogStats {
    total_logs: u64,
    logs_by_level: HashMap<LogLevel, u64>,
    logs_by_target: HashMap<String, u64>,
    dropped_logs: u64,
    last_log_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl StructuredLogger {
    /// Create a new structured logger
    pub fn new(config: LogConfig) -> Self {
        Self {
            config,
            global_context: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(LogStats::default())),
            start_time: Instant::now(),
        }
    }

    /// Initialize the logging system
    #[cfg(feature = "tracing-subscriber")]
    pub fn init(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Create environment filter
        let env_filter = self.create_env_filter()?;

        // Create layers based on configuration
        let layers = self.create_layers()?;

        // Initialize subscriber
        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(layers);

        subscriber.init();

        tracing::info!("Structured logging initialized");
        Ok(())
    }

    /// Initialize the logging system (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-subscriber"))]
    pub fn init(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        tracing::info!("Structured logging initialized (basic mode)");
        Ok(())
    }

    /// Create environment filter
    #[cfg(feature = "tracing-subscriber")]
    fn create_env_filter(&self) -> Result<EnvFilter> {
        let mut filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(self.level_to_string(self.config.level)));

        // Add module-specific filters
        for (module, level) in &self.config.filtering.module_filters {
            filter = filter.add_directive(format!("{}={}", module, self.level_to_string(*level)).parse()?);
        }

        Ok(filter)
    }

    /// Create subscriber layers
    #[cfg(feature = "tracing-subscriber")]
    fn create_layers(&self) -> Result<Vec<Box<dyn Layer< tracing_subscriber::Registry> + Send + Sync>>> {
        let mut layers = Vec::new();

        for target in &self.config.output.targets {
            if !target.enabled {
                continue;
            }

            let layer = match target.target_type {
                LogOutputType::Console => self.create_console_layer(target)?,
                LogOutputType::File => self.create_file_layer(target)?,
                LogOutputType::Network => self.create_network_layer(target)?,
                LogOutputType::Elasticsearch => self.create_elasticsearch_layer(target)?,
                LogOutputType::Loki => self.create_loki_layer(target)?,
                LogOutputType::Syslog => self.create_syslog_layer(target)?,
            };

            layers.push(layer);
        }

        Ok(layers)
    }

    /// Create console layer
    #[cfg(feature = "tracing-subscriber")]
    fn create_console_layer(&self, target: &LogOutputTarget) -> Result<Box<dyn Layer< tracing_subscriber::Registry> + Send + Sync>> {
        let layer = match self.config.format {
            LogFormat::Plain => {
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stdout)
                    .with_ansi(true)
                    .boxed()
            }
            LogFormat::Json => {
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::io::stdout)
                    .boxed()
            }
            LogFormat::CompactJson => {
                tracing_subscriber::fmt::layer()
                    .compact()
                    .json()
                    .with_writer(std::io::stdout)
                    .boxed()
            }
            LogFormat::Pretty => {
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_writer(std::io::stdout)
                    .boxed()
            }
            LogFormat::Structured => {
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_process_id(true)
                    .with_writer(std::io::stdout)
                    .boxed()
            }
        };

        Ok(layer)
    }

    /// Create console layer (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-subscriber"))]
    fn create_console_layer(&self, _target: &LogOutputTarget) -> Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }

    /// Create file layer
    #[cfg(feature = "tracing-subscriber")]
    fn create_file_layer(&self, target: &LogOutputTarget) -> Result<Box<dyn Layer< tracing_subscriber::Registry> + Send + Sync>> {
        let file_path = target.config.get("path").ok_or_else(|| {
            FortressError::validation("File path not specified for file output".to_string())
        })?;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;

        let layer = match self.config.format {
            LogFormat::Json => {
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(file)
                    .boxed()
            }
            LogFormat::CompactJson => {
                tracing_subscriber::fmt::layer()
                    .compact()
                    .json()
                    .with_writer(file)
                    .boxed()
            }
            _ => {
                tracing_subscriber::fmt::layer()
                    .with_writer(file)
                    .boxed()
            }
        };

        Ok(layer)
    }

    /// Create file layer (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-subscriber"))]
    fn create_file_layer(&self, _target: &LogOutputTarget) -> Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }

    /// Create network layer
    #[cfg(feature = "tracing-subscriber")]
    fn create_network_layer(&self, target: &LogOutputTarget) -> Result<Box<dyn Layer< tracing_subscriber::Registry> + Send + Sync>> {
        // For now, return a no-op layer
        // In a full implementation, this would set up network logging
        tracing::warn!("Network logging not yet implemented");
        Ok(Box::new(tracing_subscriber::fmt::layer().with_writer(std::io::sink)))
    }

    /// Create network layer (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-subscriber"))]
    fn create_network_layer(&self, _target: &LogOutputTarget) -> Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }

    /// Create Elasticsearch layer
    #[cfg(feature = "tracing-subscriber")]
    fn create_elasticsearch_layer(&self, target: &LogOutputTarget) -> Result<Box<dyn Layer< tracing_subscriber::Registry> + Send + Sync>> {
        // For now, return a no-op layer
        // In a full implementation, this would set up Elasticsearch logging
        tracing::warn!("Elasticsearch logging not yet implemented");
        Ok(Box::new(tracing_subscriber::fmt::layer().with_writer(std::io::sink)))
    }

    /// Create Elasticsearch layer (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-subscriber"))]
    fn create_elasticsearch_layer(&self, _target: &LogOutputTarget) -> Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }

    /// Create Loki layer
    #[cfg(feature = "tracing-subscriber")]
    fn create_loki_layer(&self, target: &LogOutputTarget) -> Result<Box<dyn Layer< tracing_subscriber::Registry> + Send + Sync>> {
        // For now, return a no-op layer
        // In a full implementation, this would set up Loki logging
        tracing::warn!("Loki logging not yet implemented");
        Ok(Box::new(tracing_subscriber::fmt::layer().with_writer(std::io::sink)))
    }

    /// Create Loki layer (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-subscriber"))]
    fn create_loki_layer(&self, _target: &LogOutputTarget) -> Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }

    /// Create syslog layer (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-subscriber"))]
    fn create_syslog_layer(&self, _target: &LogOutputTarget) -> Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(()))
    }

    /// Add global context field
    pub async fn add_global_context(&self, key: &str, value: &str) -> Result<()> {
        let mut context = self.global_context.write().await;
        context.insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// Remove global context field
    pub async fn remove_global_context(&self, key: &str) -> Result<()> {
        let mut context = self.global_context.write().await;
        context.remove(key);
        Ok(())
    }

    /// Get global context
    pub async fn get_global_context(&self) -> HashMap<String, String> {
        let context = self.global_context.read().await;
        context.clone()
    }

    /// Get logging statistics
    pub async fn get_stats(&self) -> LogStats {
        let stats = self.stats.read().await;
        LogStats {
            total_logs: stats.total_logs,
            logs_by_level: stats.logs_by_level.clone(),
            logs_by_target: stats.logs_by_target.clone(),
            dropped_logs: stats.dropped_logs,
            last_log_time: stats.last_log_time,
        }
    }

    /// Start the structured logger
    pub async fn start(&self) -> Result<()> {
        if self.config.enabled {
            // Initialize global context
            self.initialize_global_context().await;
            
            tracing::info!("Structured logger started");
        }
        Ok(())
    }

    /// Shutdown the structured logger
    pub async fn shutdown(&self) -> Result<()> {
        if self.config.enabled {
            tracing::info!("Structured logger shutdown");
        }
        Ok(())
    }

    /// Initialize global context
    async fn initialize_global_context(&self) {
        let mut context = self.global_context.write().await;
        
        // Add automatic fields
        for auto_field in &self.config.context.auto_fields {
            match auto_field {
                AutoField::Timestamp => {
                    // Timestamp is handled by tracing
                }
                AutoField::ProcessId => {
                    context.insert("process_id".to_string(), std::process::id().to_string());
                }
                AutoField::ThreadId => {
                    // Thread ID is handled by tracing
                }
                AutoField::Hostname => {
                    #[cfg(feature = "gethostname")]
                    {
                        if let Ok(hostname) = std::env::var("HOSTNAME") {
                            context.insert("hostname".to_string(), hostname);
                        } else if let Ok(hostname) = gethostname::gethostname() {
                            if let Some(hostname_str) = hostname.to_str() {
                                context.insert("hostname".to_string(), hostname_str.to_string());
                            }
                        }
                    }
                    #[cfg(not(feature = "gethostname"))]
                    {
                        if let Ok(hostname) = std::env::var("HOSTNAME") {
                            context.insert("hostname".to_string(), hostname);
                        }
                    }
                }
                AutoField::ServiceName => {
                    context.insert("service_name".to_string(), "fortress".to_string());
                }
                AutoField::ServiceVersion => {
                    context.insert("service_version".to_string(), "0.1.0".to_string());
                }
                AutoField::TraceId => {
                    // Trace ID is handled by tracing
                }
                AutoField::SpanId => {
                    // Span ID is handled by tracing
                }
            }
        }

        // Add global fields from config
        for (key, value) in &self.config.context.global_fields {
            context.insert(key.clone(), value.clone());
        }
    }

    /// Convert log level to string
    fn level_to_string(&self, level: LogLevel) -> &'static str {
        match level {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Convert string to log level
    fn string_to_level(&self, level: &str) -> LogLevel {
        match level {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        }
    }
}

/// Macro for structured logging with context
#[macro_export]
macro_rules! log_structured {
    (level: $level:expr, message: $message:expr $(, $($key:ident = $value:expr),*)?) => {
        {
            let mut event = tracing::event!(target: "fortress", $level, %$message);
            $(
                $(event = event.field(stringify!($key), &$value);)*
            )?
            event;
        }
    };
}

/// Macro for logging with error context
#[macro_export]
macro_rules! log_error {
    ($error:expr, $($key:ident = $value:expr),*) => {
        tracing::error!(
            error = %$error,
            $($key = &$value),*
        );
    };
}

/// Macro for logging performance metrics
#[macro_export]
macro_rules! log_performance {
    ($operation:expr, $duration:expr, $($key:ident = $value:expr),*) => {
        tracing::info!(
            operation = $operation,
            duration_ms = $duration.as_millis(),
            $($key = &$value),*
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert!(config.enabled);
        assert_eq!(config.level, LogLevel::Info);
        assert_eq!(config.format, LogFormat::Json);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
        assert!(LogLevel::Debug > LogLevel::Trace);
    }

    #[tokio::test]
    async fn test_structured_logger_creation() {
        let config = LogConfig::default();
        let logger = StructuredLogger::new(config);
        
        // Test adding global context
        logger.add_global_context("test_key", "test_value").await.unwrap();
        
        let context = logger.get_global_context().await;
        assert_eq!(context.get("test_key"), Some(&"test_value".to_string()));
    }

    #[tokio::test]
    async fn test_logging_stats() {
        let config = LogConfig::default();
        let logger = StructuredLogger::new(config);
        
        let stats = logger.get_stats().await;
        assert_eq!(stats.total_logs, 0);
        assert_eq!(stats.dropped_logs, 0);
    }

    #[test]
    fn test_level_conversion() {
        let logger = StructuredLogger::new(LogConfig::default());
        
        assert_eq!(logger.level_to_string(LogLevel::Info), "info");
        assert_eq!(logger.string_to_level("error"), LogLevel::Error);
        assert_eq!(logger.string_to_level("invalid"), LogLevel::Info);
    }
}
