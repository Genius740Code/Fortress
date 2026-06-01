//! Hot-reloading functionality for Fortress authentication plugins

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use uuid::Uuid;

use crate::*;

/// Hot-reload configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadConfig {
    /// Enable hot-reloading
    pub enabled: bool,
    /// Directory to watch for plugin changes
    pub watch_directory: PathBuf,
    /// Polling interval in milliseconds
    pub poll_interval_ms: u64,
    /// Maximum number of concurrent reload operations
    pub max_concurrent_reloads: usize,
    /// Enable automatic reload on file changes
    pub auto_reload: bool,
    /// Backup directory for plugin versions
    pub backup_directory: Option<PathBuf>,
    /// Maximum number of backup versions to keep
    pub max_backups: usize,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_directory: PathBuf::from("./plugins"),
            poll_interval_ms: 1000,
            max_concurrent_reloads: 3,
            auto_reload: true,
            backup_directory: Some(PathBuf::from("./backups")),
            max_backups: 5,
        }
    }
}

/// Plugin reload status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReloadStatus {
    /// Plugin is up to date
    UpToDate,
    /// Plugin is being reloaded
    Reloading,
    /// Plugin reload completed successfully
    Reloaded { version: String, timestamp: u64 },
    /// Plugin reload failed
    Failed { error: String, timestamp: u64 },
}

/// Plugin file metadata
#[derive(Debug, Clone)]
struct PluginFile {
    path: PathBuf,
    last_modified: SystemTime,
    checksum: String,
    version: String,
}

/// Hot-reload manager
pub struct HotReloadManager {
    config: HotReloadConfig,
    plugin_registry: Arc<RwLock<PluginRegistry>>,
    plugin_files: Arc<RwLock<HashMap<String, PluginFile>>>,
    reload_semaphore: Arc<Semaphore>,
    reload_status: Arc<RwLock<HashMap<String, ReloadStatus>>>,
    is_running: Arc<RwLock<bool>>,
}

impl HotReloadManager {
    /// Create a new hot-reload manager
    pub fn new(config: HotReloadConfig, plugin_registry: Arc<RwLock<PluginRegistry>>) -> Self {
        Self {
            reload_semaphore: Arc::new(Semaphore::new(config.max_concurrent_reloads)),
            plugin_files: Arc::new(RwLock::new(HashMap::new())),
            reload_status: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
            config,
            plugin_registry,
        }
    }

    /// Start the hot-reload service
    pub async fn start(&self) -> Result<(), PluginError> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(PluginError::AlreadyRunning);
        }
        *is_running = true;
        drop(is_running);

        // Initialize plugin file tracking
        self.initialize_plugin_tracking().await?;

        // Start the monitoring loop
        let manager = self.clone();
        tokio::spawn(async move {
            manager.monitor_loop().await;
        });

        Ok(())
    }

    /// Stop the hot-reload service
    pub async fn stop(&self) -> Result<(), PluginError> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        Ok(())
    }

    /// Get reload status for all plugins
    pub async fn get_reload_status(&self) -> HashMap<String, ReloadStatus> {
        self.reload_status.read().await.clone()
    }

    /// Get reload status for a specific plugin
    pub async fn get_plugin_reload_status(&self, plugin_name: &str) -> Option<ReloadStatus> {
        self.reload_status.read().await.get(plugin_name).cloned()
    }

    /// Manually trigger a reload for a specific plugin
    pub async fn reload_plugin(&self, plugin_name: &str) -> Result<(), PluginError> {
        if !self.config.enabled {
            return Err(PluginError::HotReloadDisabled);
        }

        let permit = self
            .reload_semaphore
            .acquire()
            .await
            .map_err(|_| PluginError::ReloadInProgress)?;

        let result = self.perform_reload(plugin_name).await;
        drop(permit);

        result
    }

    /// Initialize plugin file tracking
    async fn initialize_plugin_tracking(&self) -> Result<(), PluginError> {
        let mut plugin_files = self.plugin_files.write().await;

        // Scan the watch directory for WASM files
        let mut entries = fs::read_dir(&self.config.watch_directory)
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                if let Ok(metadata) = fs::metadata(&path).await {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(checksum) = self.calculate_checksum(&path).await {
                            let plugin_name = path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("unknown")
                                .to_string();

                            plugin_files.insert(
                                plugin_name.clone(),
                                PluginFile {
                                    path: path.clone(),
                                    last_modified: modified,
                                    checksum,
                                    version: self.generate_version(),
                                },
                            );

                            // Set initial status
                            let mut reload_status = self.reload_status.write().await;
                            reload_status.insert(plugin_name, ReloadStatus::UpToDate);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Main monitoring loop
    async fn monitor_loop(&self) {
        let interval = Duration::from_millis(self.config.poll_interval_ms);

        loop {
            // Check if we should continue running
            {
                let is_running = self.is_running.read().await;
                if !*is_running {
                    break;
                }
            }

            // Check for file changes
            if let Err(e) = self.check_for_changes().await {
                eprintln!("Hot-reload error: {:?}", e);
            }

            sleep(interval).await;
        }
    }

    /// Check for plugin file changes
    async fn check_for_changes(&self) -> Result<(), PluginError> {
        let plugin_files = self.plugin_files.read().await;
        let mut entries = fs::read_dir(&self.config.watch_directory)
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                if let Ok(metadata) = fs::metadata(&path).await {
                    if let Ok(modified) = metadata.modified() {
                        let plugin_name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        if let Some(plugin_file) = plugin_files.get(&plugin_name) {
                            // Check if file has changed
                            if modified != plugin_file.last_modified {
                                if let Ok(new_checksum) = self.calculate_checksum(&path).await {
                                    if new_checksum != plugin_file.checksum {
                                        // File has changed, trigger reload
                                        if self.config.auto_reload {
                                            let manager = self.clone();
                                            let plugin_name_clone = plugin_name.clone();
                                            tokio::spawn(async move {
                                                if let Err(e) =
                                                    manager.reload_plugin(&plugin_name_clone).await
                                                {
                                                    eprintln!(
                                                        "Auto-reload failed for {}: {:?}",
                                                        plugin_name_clone, e
                                                    );
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Perform the actual plugin reload
    async fn perform_reload(&self, plugin_name: &str) -> Result<(), PluginError> {
        // Update status to reloading
        {
            let mut reload_status = self.reload_status.write().await;
            reload_status.insert(plugin_name.to_string(), ReloadStatus::Reloading);
        }

        // Get current plugin file info
        let plugin_file = {
            let plugin_files = self.plugin_files.read().await;
            plugin_files.get(plugin_name).cloned()
        };

        if let Some(plugin_file) = plugin_file {
            // Create backup if configured
            if let Some(backup_dir) = &self.config.backup_directory {
                self.create_backup(&plugin_file, backup_dir).await?;
            }

            // Load the new plugin
            let result = self.load_plugin_from_file(&plugin_file.path).await;

            match result {
                Ok(_) => {
                    // Update plugin file info
                    {
                        let mut plugin_files = self.plugin_files.write().await;
                        if let Some(file) = plugin_files.get_mut(plugin_name) {
                            file.last_modified = SystemTime::now();
                            file.checksum = self.calculate_checksum(&plugin_file.path).await?;
                            file.version = self.generate_version();
                        }
                    }

                    // Update status to success
                    {
                        let mut reload_status = self.reload_status.write().await;
                        reload_status.insert(
                            plugin_name.to_string(),
                            ReloadStatus::Reloaded {
                                version: plugin_file.version.clone(),
                                timestamp: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            },
                        );
                    }

                    Ok(())
                }
                Err(e) => {
                    // Update status to failed
                    {
                        let mut reload_status = self.reload_status.write().await;
                        reload_status.insert(
                            plugin_name.to_string(),
                            ReloadStatus::Failed {
                                error: e.to_string(),
                                timestamp: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            },
                        );
                    }
                    Err(e)
                }
            }
        } else {
            Err(PluginError::PluginNotFound(plugin_name.to_string()))
        }
    }

    /// Load plugin from file
    async fn load_plugin_from_file(&self, path: &Path) -> Result<(), PluginError> {
        let wasm_bytes = fs::read(path)
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        // Load the WASM module
        let plugin_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| PluginError::InvalidPluginName)?;

        // Unload existing plugin if it exists
        {
            let mut registry = self.plugin_registry.write().await;
            registry.unload_plugin(plugin_name).await?;
        }

        // Load new plugin
        {
            let mut registry = self.plugin_registry.write().await;
            registry
                .load_plugin_from_bytes(plugin_name, &wasm_bytes)
                .await?;
        }

        Ok(())
    }

    /// Calculate file checksum
    async fn calculate_checksum(&self, path: &Path) -> Result<String, PluginError> {
        use sha2::{Digest, Sha256};

        let contents = fs::read(path)
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&contents);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Generate a version string
    fn generate_version(&self) -> String {
        format!(
            "v{}.{}.{}",
            Uuid::new_v4().simple().to_string()[..8].to_string(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            rand::random::<u32>()
        )
    }

    /// Create backup of plugin file
    async fn create_backup(
        &self,
        plugin_file: &PluginFile,
        backup_dir: &Path,
    ) -> Result<(), PluginError> {
        // Create backup directory if it doesn't exist
        fs::create_dir_all(backup_dir)
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        // Generate backup filename with timestamp
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let plugin_name = plugin_file
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let backup_filename = format!("{}_{}.wasm.bak", plugin_name, timestamp);
        let backup_path = backup_dir.join(backup_filename);

        // Copy file to backup location
        fs::copy(&plugin_file.path, &backup_path)
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        // Clean up old backups
        self.cleanup_old_backups(backup_dir, plugin_name).await?;

        Ok(())
    }

    /// Clean up old backup files
    async fn cleanup_old_backups(
        &self,
        backup_dir: &Path,
        plugin_name: &str,
    ) -> Result<(), PluginError> {
        let mut entries = fs::read_dir(backup_dir)
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?;

        let mut backup_files = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| PluginError::IoError(e.to_string()))?
        {
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
                if filename.starts_with(plugin_name) && filename.ends_with(".wasm.bak") {
                    if let Ok(metadata) = fs::metadata(&path).await {
                        if let Ok(modified) = metadata.modified() {
                            backup_files.push((path, modified));
                        }
                    }
                }
            }
        }

        // Sort by modification time (oldest first)
        backup_files.sort_by_key(|(_, modified)| *modified);

        // Remove excess backups
        if backup_files.len() > self.config.max_backups {
            for (path, _) in backup_files
                .iter()
                .take(backup_files.len() - self.config.max_backups)
            {
                fs::remove_file(path)
                    .await
                    .map_err(|e| PluginError::IoError(e.to_string()))?;
            }
        }

        Ok(())
    }
}

impl Clone for HotReloadManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            plugin_registry: Arc::clone(&self.plugin_registry),
            plugin_files: Arc::clone(&self.plugin_files),
            reload_semaphore: Arc::clone(&self.reload_semaphore),
            reload_status: Arc::clone(&self.reload_status),
            is_running: Arc::clone(&self.is_running),
        }
    }
}

/// Plugin hot-reload errors
#[derive(Debug, Clone)]
pub enum PluginError {
    HotReloadDisabled,
    AlreadyRunning,
    PluginNotFound(String),
    InvalidPluginName,
    IoError(String),
    ReloadInProgress,
    LoadError(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginError::HotReloadDisabled => write!(f, "Hot-reload is disabled"),
            PluginError::AlreadyRunning => write!(f, "Hot-reload service is already running"),
            PluginError::PluginNotFound(name) => write!(f, "Plugin not found: {}", name),
            PluginError::InvalidPluginName => write!(f, "Invalid plugin name"),
            PluginError::IoError(msg) => write!(f, "IO error: {}", msg),
            PluginError::ReloadInProgress => write!(f, "Reload operation in progress"),
            PluginError::LoadError(msg) => write!(f, "Plugin loading error: {}", msg),
        }
    }
}

impl std::error::Error for PluginError {}

impl From<crate::PluginError> for PluginError {
    fn from(err: crate::PluginError) -> Self {
        match err {
            crate::PluginError::LoadError(msg) => PluginError::LoadError(msg),
            crate::PluginError::IoError(msg) => PluginError::IoError(msg),
            _ => PluginError::LoadError(err.to_string()),
        }
    }
}
