//! Plugin Marketplace and Distribution System
//! 
//! This module provides functionality for downloading, installing, and managing
//! plugins from remote repositories and marketplaces.

use crate::error::{FortressError, Result};
use crate::plugin::PluginCapability;
use sha2::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::RwLock;

/// Plugin package metadata from repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPackage {
    /// Unique package identifier
    pub id: String,
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package description
    pub description: String,
    /// Package author/maintainer
    pub author: String,
    /// Plugin capabilities
    pub capabilities: Vec<PluginCapability>,
    /// Download URL for the plugin package
    pub download_url: String,
    /// Checksum for verification
    pub checksum: String,
    /// Minimum Fortress version required
    pub min_fortress_version: String,
    /// Plugin dependencies
    pub dependencies: Vec<String>,
    /// Configuration schema
    pub config_schema: Option<serde_json::Value>,
    /// Security signature
    pub signature: Option<String>,
    /// Installation size in bytes
    pub size_bytes: u64,
    /// Download count
    pub download_count: u64,
    /// Rating (0-5)
    pub rating: f32,
    /// Tags for search
    pub tags: Vec<String>,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Plugin repository client
#[derive(Debug, Clone)]
pub struct PluginRepository {
    /// Repository base URL
    base_url: String,
    /// HTTP client
    client: reqwest::Client,
    /// Cache for package metadata
    package_cache: Arc<RwLock<HashMap<String, PluginPackage>>>,
}

impl PluginRepository {
    /// Create a new repository client
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
            package_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Search for plugins in the repository
    pub async fn search(&self, query: &str, limit: Option<usize>) -> Result<Vec<PluginPackage>> {
        let url = format!("{}/api/plugins/search", self.base_url);
        
        let mut params: HashMap<String, String> = HashMap::new();
        params.insert("q".to_string(), query.to_string());
        if let Some(limit) = limit {
            params.insert("limit".to_string(), limit.to_string());
        }

        let response = self.client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to search plugins: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::plugin(format!(
                "Search failed with status: {}",
                response.status()
            )));
        }

        let packages: Vec<PluginPackage> = response
            .json()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to parse search results: {}", e)))?;

        // Cache the results
        {
            let mut cache = self.package_cache.write().await;
            for package in &packages {
                cache.insert(package.id.clone(), package.clone());
            }
        }

        Ok(packages)
    }

    /// Get plugin package details
    pub async fn get_package(&self, package_id: &str) -> Result<PluginPackage> {
        // Check cache first
        {
            let cache = self.package_cache.read().await;
            if let Some(package) = cache.get(package_id) {
                return Ok(package.clone());
            }
        }

        let url = format!("{}/api/plugins/{}", self.base_url, package_id);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to get package: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::plugin(format!(
                "Package not found: {}",
                response.status()
            )));
        }

        let package: PluginPackage = response
            .json()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to parse package: {}", e)))?;

        // Cache the result
        {
            let mut cache = self.package_cache.write().await;
            cache.insert(package_id.to_string(), package.clone());
        }

        Ok(package)
    }

    /// Download plugin package
    pub async fn download_package(&self, package: &PluginPackage, download_dir: &PathBuf) -> Result<PathBuf> {
        let package_filename = format!("{}-{}.fplugin", package.id, package.version);
        let package_path = download_dir.join(&package_filename);

        // Download the package
        let response = self.client
            .get(&package.download_url)
            .send()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to download package: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::plugin(format!(
                "Download failed with status: {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to read package bytes: {}", e)))?;

        // Verify checksum
        let checksum = format!("{:x}", sha2::Sha256::digest(&bytes));
        if checksum != package.checksum {
            return Err(FortressError::plugin("Checksum verification failed".to_string()));
        }

        // Write to file
        fs::write(&package_path, bytes)
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to write package file: {}", e)))?;

        Ok(package_path)
    }

    /// List popular plugins
    pub async fn list_popular(&self, limit: Option<usize>) -> Result<Vec<PluginPackage>> {
        let url = format!("{}/api/plugins/popular", self.base_url);
        
        let mut params: HashMap<String, String> = HashMap::new();
        if let Some(limit) = limit {
            params.insert("limit".to_string(), limit.to_string());
        }

        let response = self.client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to list popular plugins: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::plugin(format!(
                "Failed to get popular plugins: {}",
                response.status()
            )));
        }

        let packages: Vec<PluginPackage> = response
            .json()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to parse popular plugins: {}", e)))?;

        Ok(packages)
    }

    /// List plugins by category
    pub async fn list_by_category(&self, category: &str, limit: Option<usize>) -> Result<Vec<PluginPackage>> {
        let url = format!("{}/api/plugins/category/{}", self.base_url, category);
        
        let mut params: HashMap<String, String> = HashMap::new();
        if let Some(limit) = limit {
            params.insert("limit".to_string(), limit.to_string());
        }

        let response = self.client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to list plugins by category: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::plugin(format!(
                "Failed to get plugins by category: {}",
                response.status()
            )));
        }

        let packages: Vec<PluginPackage> = response
            .json()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to parse category plugins: {}", e)))?;

        Ok(packages)
    }
}

/// Plugin installer for managing plugin installation
#[derive(Debug)]
pub struct PluginInstaller {
    /// Fortress plugins directory
    plugins_dir: PathBuf,
    /// Download directory for temporary files
    download_dir: PathBuf,
    /// Repository client
    repository: PluginRepository,
}

impl PluginInstaller {
    /// Create a new plugin installer
    pub fn new(plugins_dir: PathBuf, repository: PluginRepository) -> Result<Self> {
        let download_dir = plugins_dir.join("downloads");
        
        Ok(Self {
            plugins_dir,
            download_dir,
            repository,
        })
    }

    /// Install a plugin from the repository
    pub async fn install(&self, package_id: &str, config: Option<HashMap<String, serde_json::Value>>) -> Result<()> {
        // Get package information
        let package = self.repository.get_package(package_id).await?;

        // Verify compatibility
        self.verify_compatibility(&package)?;

        // Create directories if they don't exist
        fs::create_dir_all(&self.plugins_dir).await
            .map_err(|e| FortressError::plugin(format!("Failed to create plugins directory: {}", e)))?;
        fs::create_dir_all(&self.download_dir).await
            .map_err(|e| FortressError::plugin(format!("Failed to create download directory: {}", e)))?;

        // Download the package
        let package_path = self.repository.download_package(&package, &self.download_dir).await?;

        // Extract and install the plugin
        self.extract_and_install(&package_path, &package, config).await?;

        // Clean up download
        fs::remove_file(&package_path).await
            .map_err(|e| FortressError::plugin(format!("Failed to cleanup download: {}", e)))?;

        println!("Plugin '{}' v{} installed successfully!", package.name, package.version);
        Ok(())
    }

    /// Uninstall a plugin
    pub async fn uninstall(&self, plugin_id: &str) -> Result<()> {
        let plugin_dir = self.plugins_dir.join(plugin_id);
        
        if !plugin_dir.exists() {
            return Err(FortressError::plugin(format!("Plugin '{}' is not installed", plugin_id)));
        }

        // Remove plugin directory
        fs::remove_dir_all(&plugin_dir).await
            .map_err(|e| FortressError::plugin(format!("Failed to uninstall plugin: {}", e)))?;

        println!("Plugin '{}' uninstalled successfully!", plugin_id);
        Ok(())
    }

    /// List installed plugins
    pub async fn list_installed(&self) -> Result<Vec<InstalledPlugin>> {
        let mut installed_plugins = Vec::new();

        if !self.plugins_dir.exists() {
            return Ok(installed_plugins);
        }

        let mut entries = fs::read_dir(&self.plugins_dir).await
            .map_err(|e| FortressError::plugin(format!("Failed to read plugins directory: {}", e)))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| FortressError::plugin(format!("Failed to read directory entry: {}", e)))? {
            
            let path = entry.path();
            if path.is_dir() {
                if let Ok(plugin) = self.load_installed_plugin(&path).await {
                    installed_plugins.push(plugin);
                }
            }
        }

        Ok(installed_plugins)
    }

    /// Update an installed plugin
    pub async fn update(&self, plugin_id: &str) -> Result<()> {
        // Get current installation info
        let current = self.get_installed_plugin(plugin_id).await?;
        
        // Get latest package info
        let latest = self.repository.get_package(plugin_id).await?;

        // Check if update is needed
        if current.metadata.version == latest.version {
            println!("Plugin '{}' is already up to date!", plugin_id);
            return Ok(());
        }

        println!("Updating plugin '{}' from v{} to v{}...", plugin_id, current.metadata.version, latest.version);

        // Uninstall current version
        self.uninstall(plugin_id).await?;

        // Install latest version (preserve config)
        self.install(plugin_id, current.config).await?;

        println!("Plugin '{}' updated successfully!", plugin_id);
        Ok(())
    }

    /// Verify plugin compatibility
    fn verify_compatibility(&self, package: &PluginPackage) -> Result<()> {
        // Check Fortress version compatibility using semantic versioning
        let current_version = env!("CARGO_PKG_VERSION");
        
        // Parse versions for proper comparison
        let current_parsed = self.parse_version(current_version)?;
        let required_parsed = self.parse_version(&package.min_fortress_version)?;
        
        // Compare major.minor.patch versions
        if current_parsed < required_parsed {
            return Err(FortressError::plugin(format!(
                "Plugin requires Fortress version {} or higher, current version is {}",
                package.min_fortress_version,
                current_version
            )));
        }

        Ok(())
    }

    /// Parse version string into comparable tuple (major, minor, patch)
    fn parse_version(&self, version: &str) -> Result<(u32, u32, u32)> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(FortressError::plugin(format!(
                "Invalid version format: {}. Expected major.minor.patch",
                version
            )));
        }
        
        let major = parts[0].parse()
            .map_err(|_| FortressError::plugin(format!("Invalid major version: {}", parts[0])))?;
        let minor = parts[1].parse()
            .map_err(|_| FortressError::plugin(format!("Invalid minor version: {}", parts[1])))?;
        let patch = parts[2].parse()
            .map_err(|_| FortressError::plugin(format!("Invalid patch version: {}", parts[2])))?;
        
        Ok((major, minor, patch))
    }

    /// Extract and install plugin package
    async fn extract_and_install(
        &self,
        package_path: &PathBuf,
        package: &PluginPackage,
        config: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<()> {
        let plugin_dir = self.plugins_dir.join(&package.id);

        // Remove existing installation
        if plugin_dir.exists() {
            fs::remove_dir_all(&plugin_dir).await
                .map_err(|e| FortressError::plugin(format!("Failed to remove existing plugin: {}", e)))?;
        }

        // Create plugin directory
        fs::create_dir_all(&plugin_dir).await
            .map_err(|e| FortressError::plugin(format!("Failed to create plugin directory: {}", e)))?;

        // Read and extract package using tar/gzip
        let package_data = fs::read(package_path).await
            .map_err(|e| FortressError::plugin(format!("Failed to read package: {}", e)))?;

        // Extract tar.gz package
        use flate2::read::GzDecoder;
        use tar::Archive;
        
        let cursor = std::io::Cursor::new(package_data);
        let decoder = GzDecoder::new(cursor);
        let mut archive = Archive::new(decoder);
        
        archive.unpack(&plugin_dir)
            .map_err(|e| FortressError::plugin(format!("Failed to extract package: {}", e)))?;

        // Write package metadata
        let metadata_path = plugin_dir.join("metadata.json");
        let metadata_json = serde_json::to_string_pretty(package)
            .map_err(|e| FortressError::plugin(format!("Failed to serialize metadata: {}", e)))?;
        fs::write(&metadata_path, metadata_json).await
            .map_err(|e| FortressError::plugin(format!("Failed to write metadata: {}", e)))?;

        // Write configuration if provided
        if let Some(config) = config {
            let config_path = plugin_dir.join("config.json");
            let config_json = serde_json::to_string_pretty(&config)
                .map_err(|e| FortressError::plugin(format!("Failed to serialize config: {}", e)))?;
            fs::write(&config_path, config_json).await
                .map_err(|e| FortressError::plugin(format!("Failed to write config: {}", e)))?;
        }

        Ok(())
    }

    /// Load installed plugin information
    async fn load_installed_plugin(&self, plugin_dir: &PathBuf) -> Result<InstalledPlugin> {
        let metadata_path = plugin_dir.join("metadata.json");
        let config_path = plugin_dir.join("config.json");

        let metadata: PluginPackage = {
            let metadata_data = fs::read_to_string(&metadata_path).await
                .map_err(|e| FortressError::plugin(format!("Failed to read metadata: {}", e)))?;
            serde_json::from_str(&metadata_data)
                .map_err(|e| FortressError::plugin(format!("Failed to parse metadata: {}", e)))?
        };

        let config = if config_path.exists() {
            let config_data = fs::read_to_string(&config_path).await
                .map_err(|e| FortressError::plugin(format!("Failed to read config: {}", e)))?;
            Some(serde_json::from_str(&config_data)
                .map_err(|e| FortressError::plugin(format!("Failed to parse config: {}", e)))?)
        } else {
            None
        };

        Ok(InstalledPlugin {
            metadata,
            config,
            installed_at: fs::metadata(plugin_dir)
                .await
                .map_err(|e| FortressError::plugin(format!("Failed to get plugin metadata: {}", e)))?
                .modified()
                .map_err(|e| FortressError::plugin(format!("Failed to get modification time: {}", e)))?
                .into(),
        })
    }

    /// Get specific installed plugin
    async fn get_installed_plugin(&self, plugin_id: &str) -> Result<InstalledPlugin> {
        let plugin_dir = self.plugins_dir.join(plugin_id);
        self.load_installed_plugin(&plugin_dir).await
    }
}

/// Information about an installed plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugin {
    /// Plugin package metadata
    pub metadata: PluginPackage,
    /// Plugin configuration
    pub config: Option<HashMap<String, serde_json::Value>>,
    /// Installation timestamp
    pub installed_at: chrono::DateTime<chrono::Utc>,
}

/// Plugin marketplace manager
#[derive(Debug)]
pub struct PluginMarketplace {
    /// Repository client
    repository: PluginRepository,
    /// Plugin installer
    installer: PluginInstaller,
}

impl PluginMarketplace {
    /// Create a new marketplace manager
    pub fn new(plugins_dir: PathBuf, repository_url: Option<String>) -> Result<Self> {
        let repository_url = repository_url.unwrap_or_else(|| "https://plugins.fortress-db.com".to_string());
        let repository = PluginRepository::new(repository_url);
        let installer = PluginInstaller::new(plugins_dir, repository.clone())?;

        Ok(Self {
            repository,
            installer,
        })
    }

    /// Search for plugins
    pub async fn search(&self, query: &str, limit: Option<usize>) -> Result<Vec<PluginPackage>> {
        self.repository.search(query, limit).await
    }

    /// Install a plugin
    pub async fn install(&self, package_id: &str, config: Option<HashMap<String, serde_json::Value>>) -> Result<()> {
        self.installer.install(package_id, config).await
    }

    /// Uninstall a plugin
    pub async fn uninstall(&self, plugin_id: &str) -> Result<()> {
        self.installer.uninstall(plugin_id).await
    }

    /// List installed plugins
    pub async fn list_installed(&self) -> Result<Vec<InstalledPlugin>> {
        self.installer.list_installed().await
    }

    /// Update a plugin
    pub async fn update(&self, plugin_id: &str) -> Result<()> {
        self.installer.update(plugin_id).await
    }

    /// List popular plugins
    pub async fn list_popular(&self, limit: Option<usize>) -> Result<Vec<PluginPackage>> {
        self.repository.list_popular(limit).await
    }

    /// List plugins by category
    pub async fn list_by_category(&self, category: &str, limit: Option<usize>) -> Result<Vec<PluginPackage>> {
        self.repository.list_by_category(category, limit).await
    }

    /// Get plugin package details (direct repository access)
    pub async fn get_package(&self, package_id: &str) -> Result<PluginPackage> {
        self.repository.get_package(package_id).await
    }
}

use std::sync::Arc;
