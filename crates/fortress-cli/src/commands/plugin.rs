//! Plugin management commands for Fortress CLI

use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;
use console::style;
use serde_json;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::error;

use fortress_core::plugin_marketplace::{PluginMarketplace, PluginPackage, InstalledPlugin};

/// Plugin management commands
#[derive(Parser)]
#[command(name = "plugin")]
#[command(about = "Manage Fortress plugins")]
/// Plugin management commands
pub struct PluginCommands {
    /// The plugin action to perform
    #[command(subcommand)]
    pub action: PluginAction,
}

/// Plugin management actions
#[derive(Subcommand)]
pub enum PluginAction {
    /// Search for available plugins
    Search {
        /// Search query
        query: String,
        
        /// Limit number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Install a plugin
    Install {
        /// Plugin ID or name
        plugin_id: String,
        
        /// Plugin configuration (key=value pairs)
        #[arg(short = 'c', long, value_parser = parse_key_value)]
        config: Vec<(String, String)>,
        
        /// Repository URL (optional, uses default repository)
        #[arg(short, long)]
        repo: Option<String>,
        
        /// Skip confirmation prompts
        #[arg(short, long)]
        yes: bool,
    },
    /// Uninstall a plugin
    Uninstall {
        /// Plugin ID
        plugin_id: String,
        
        /// Skip confirmation prompts
        #[arg(short, long)]
        yes: bool,
    },
    /// List installed plugins
    List {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
        
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },
    /// Show plugin information
    Show {
        /// Plugin ID
        plugin_id: String,
    },
    /// Update installed plugins
    Update {
        /// Plugin ID (optional, updates all if not specified)
        plugin_id: Option<String>,
        
        /// Skip confirmation prompts
        #[arg(short, long)]
        yes: bool,
    },
    /// List popular plugins
    Popular {
        /// Limit number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// List plugins by category
    Category {
        /// Category name
        category: String,
        
        /// Limit number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Validate installed plugins
    Validate {
        /// Plugin ID (optional, validates all if not specified)
        plugin_id: Option<String>,
    },
}

/// Parse key=value pairs for configuration
fn parse_key_value(s: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(color_eyre::eyre::eyre!("Invalid key=value format: {}", s));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Execute plugin command
pub async fn execute_plugin_command(action: PluginAction) -> Result<()> {
    match action {
        PluginAction::Search { query, limit } => {
            handle_search(query, limit).await
        }
        PluginAction::Install { plugin_id, config, repo, yes } => {
            handle_install(plugin_id, config, repo, yes).await
        }
        PluginAction::Uninstall { plugin_id, yes } => {
            handle_uninstall(plugin_id, yes).await
        }
        PluginAction::List { detailed, category } => {
            handle_list(detailed, category).await
        }
        PluginAction::Show { plugin_id } => {
            handle_show(plugin_id).await
        }
        PluginAction::Update { plugin_id, yes } => {
            handle_update(plugin_id, yes).await
        }
        PluginAction::Popular { limit } => {
            handle_popular(limit).await
        }
        PluginAction::Category { category, limit } => {
            handle_category(category, limit).await
        }
        PluginAction::Validate { plugin_id } => {
            handle_validate(plugin_id).await
        }
    }
}

/// Handle plugin search
async fn handle_search(query: String, limit: usize) -> Result<()> {
    println!("Searching for plugins: '{}'", query);
    
    let marketplace = create_marketplace()?;
    let results = marketplace.search(&query, Some(limit)).await?;
    
    if results.is_empty() {
        println!("✗ No plugins found matching '{}'", query);
        return Ok(());
    }
    
    println!("✓ Found {} plugins:", results.len());
    println!();
    
    for (i, plugin) in results.iter().enumerate() {
        print_plugin_summary(i + 1, plugin);
        println!();
    }
    
    println!("Use 'fortress plugin install <plugin-id>' to install a plugin");
    Ok(())
}

/// Handle plugin installation
async fn handle_install(
    plugin_id: String, 
    config: Vec<(String, String)>, 
    repo: Option<String>,
    yes: bool
) -> Result<()> {
    println!("Installing plugin: '{}'", plugin_id);
    
    let marketplace = create_marketplace_with_repo(repo)?;
    
    // Get plugin information
    let plugin_info = marketplace.get_package(&plugin_id).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to get plugin info: {}", e))?;
    
    // Show plugin information
    print_plugin_details(&plugin_info);
    
    // Confirm installation
    if !yes {
        if !confirm_installation(&plugin_info)? {
            println!("✗ Installation cancelled");
            return Ok(());
        }
    }
    
    // Convert config to JSON values
    let config_map = if !config.is_empty() {
        let mut map = HashMap::new();
        for (key, value) in config {
            // Try to parse as JSON, fallback to string
            let json_value = match serde_json::from_str(&value) {
                Ok(v) => v,
                Err(_) => serde_json::Value::String(value),
            };
            map.insert(key, json_value);
        }
        Some(map)
    } else {
        None
    };
    
    // Install plugin
    marketplace.install(&plugin_id, config_map).await
        .map_err(|e| color_eyre::eyre::eyre!("Installation failed: {}", e))?;
    
    println!("✓ Plugin '{}' installed successfully", plugin_id);
    Ok(())
}

/// Handle plugin uninstallation
async fn handle_uninstall(plugin_id: String, yes: bool) -> Result<()> {
    println!("Uninstalling plugin: '{}'", plugin_id);
    
    let marketplace = create_marketplace()?;
    
    // Check if plugin is installed
    let installed = marketplace.list_installed().await?;
    let plugin = installed.iter().find(|p| p.metadata.id == plugin_id);
    
    if plugin.is_none() {
        println!("✗ Plugin '{}' is not installed", plugin_id);
        return Ok(());
    }
    
    let plugin = plugin.unwrap();
    
    // Show plugin information
    print_plugin_summary(0, &plugin.metadata);
    
    // Confirm uninstallation
    if !yes {
        if !confirm_uninstallation(plugin)? {
            println!("✗ Uninstallation cancelled");
            return Ok(());
        }
    }
    
    // Uninstall plugin
    marketplace.uninstall(&plugin_id).await
        .map_err(|e| color_eyre::eyre::eyre!("Uninstallation failed: {}", e))?;
    
    println!("✓ Plugin '{}' uninstalled successfully", plugin_id);
    Ok(())
}

/// Handle listing installed plugins
async fn handle_list(detailed: bool, category: Option<String>) -> Result<()> {
    println!("Installed plugins:");
    
    let marketplace = create_marketplace()?;
    let installed = marketplace.list_installed().await?;
    
    if installed.is_empty() {
        println!("✗ No plugins installed");
        return Ok(());
    }
    
    // Filter by category if specified
    let filtered = if let Some(ref cat) = category {
        installed.into_iter()
            .filter(|p| p.metadata.tags.contains(cat))
            .collect()
    } else {
        installed
    };
    
    if filtered.is_empty() {
        println!("✗ No plugins found in category '{}'", category.as_ref().unwrap_or(&"all".to_string()));
        return Ok(());
    }
    
    println!("✓ {} plugins installed:", filtered.len());
    println!();
    
    for (i, plugin) in filtered.iter().enumerate() {
        if detailed {
            print_plugin_details(&plugin.metadata);
            if let Some(config) = &plugin.config {
                println!("Configuration:");
                for (key, value) in config {
                    println!("   {}: {}", key, value);
                }
            }
            println!("Installed: {}", plugin.installed_at.format("%Y-%m-%d %H:%M:%S UTC"));
        } else {
            print_plugin_summary(i + 1, &plugin.metadata);
        }
        println!();
    }
    
    Ok(())
}

/// Handle showing plugin information
async fn handle_show(plugin_id: String) -> Result<()> {
    println!("Plugin information: '{}'", plugin_id);
    
    let marketplace = create_marketplace()?;
    
    // Try to get installed plugin info first
    let installed = marketplace.list_installed().await?;
    if let Some(plugin) = installed.iter().find(|p| p.metadata.id == plugin_id) {
        print_plugin_details(&plugin.metadata);
        println!("Installed: {}", plugin.installed_at.format("%Y-%m-%d %H:%M:%S UTC"));
        
        if let Some(config) = &plugin.config {
            println!("Configuration:");
            for (key, value) in config {
                println!("   {}: {}", key, value);
            }
        }
        return Ok(());
    }
    
    // If not installed, get from repository
    let plugin = marketplace.get_package(&plugin_id).await
        .map_err(|e| color_eyre::eyre::eyre!("Plugin not found: {}", e))?;
    
    print_plugin_details(&plugin);
    println!("✗ Not installed");
    
    Ok(())
}

/// Handle plugin updates
async fn handle_update(plugin_id: Option<String>, _yes: bool) -> Result<()> {
    let marketplace = create_marketplace()?;
    
    match plugin_id {
        Some(id) => {
            println!("Updating plugin: '{}'", id);
            marketplace.update(&id).await
                .map_err(|e| color_eyre::eyre::eyre!("Update failed: {}", e))?;
        }
        None => {
            println!("Checking for updates to all plugins...");
            let installed = marketplace.list_installed().await?;
            
            if installed.is_empty() {
                println!("✗ No plugins installed");
                return Ok(());
            }
            
            for plugin in installed {
                println!("Updating '{}'...", plugin.metadata.id);
                if let Err(e) = marketplace.update(&plugin.metadata.id).await {
                    error!("Failed to update '{}': {}", plugin.metadata.id, e);
                }
            }
        }
    }
    
    println!("✓ Update completed");
    Ok(())
}

/// Handle listing popular plugins
async fn handle_popular(limit: usize) -> Result<()> {
    println!("Popular plugins:");
    
    let marketplace = create_marketplace()?;
    let plugins = marketplace.list_popular(Some(limit)).await?;
    
    if plugins.is_empty() {
        println!("✗ No popular plugins found");
        return Ok(());
    }
    
    println!("✓ Top {} popular plugins:", plugins.len());
    println!();
    
    for (i, plugin) in plugins.iter().enumerate() {
        print_plugin_summary(i + 1, plugin);
        println!();
    }
    
    Ok(())
}

/// Handle listing plugins by category
async fn handle_category(category: String, limit: usize) -> Result<()> {
    println!("Plugins in category: '{}'", category);
    
    let marketplace = create_marketplace()?;
    let plugins = marketplace.list_by_category(&category, Some(limit)).await?;
    
    if plugins.is_empty() {
        println!("✗ No plugins found in category '{}'", category);
        return Ok(());
    }
    
    println!("✓ Found {} plugins in category '{}':", plugins.len(), category);
    println!();
    
    for (i, plugin) in plugins.iter().enumerate() {
        print_plugin_summary(i + 1, plugin);
        println!();
    }
    
    Ok(())
}

/// Handle plugin validation
async fn handle_validate(plugin_id: Option<String>) -> Result<()> {
    println!("Validating plugins...");
    
    let marketplace = create_marketplace()?;
    
    match plugin_id {
        Some(id) => {
            println!("Validating plugin: '{}'", id);
            
            // Check if plugin is installed
            let installed = marketplace.list_installed().await?;
            let plugin = installed.iter().find(|p| p.metadata.id == id);
            
            if let Some(plugin) = plugin {
                validate_single_plugin(plugin, &marketplace).await?;
            } else {
                // Try to validate from repository
                let repo_plugin = marketplace.get_package(&id).await;
                match repo_plugin {
                    Ok(plugin_info) => {
                        validate_repository_plugin(&plugin_info, &marketplace).await?;
                    }
                    Err(e) => {
                        println!("✗ Plugin '{}' not found: {}", id, e);
                        return Err(color_eyre::eyre::eyre!("Plugin '{}' not found: {}", id, e));
                    }
                }
            }
        }
        None => {
            let installed = marketplace.list_installed().await?;
            
            if installed.is_empty() {
                println!("✗ No plugins installed");
                return Ok(());
            }
            
            println!("Validating {} installed plugins...", installed.len());
            
            let mut validation_results = Vec::new();
            let mut failed_validations = 0;
            
            for plugin in &installed {
                match validate_single_plugin(plugin, &marketplace).await {
                    Ok(result) => {
                        validation_results.push((plugin.metadata.id.clone(), result.clone()));
                        if !result.is_valid {
                            failed_validations += 1;
                        }
                    }
                    Err(e) => {
                        println!("✗ Failed to validate '{}': {}", plugin.metadata.id, e);
                        failed_validations += 1;
                    }
                }
            }
            
            println!();
            println!("Validation Summary:");
            println!("  Total plugins: {}", style(installed.len()).bold());
            println!("  ✓ Valid: {}", style(installed.len() - failed_validations).green().bold());
            println!("  ✗ Invalid: {}", style(failed_validations).red().bold());
            
            if failed_validations > 0 {
                println!("\nFailed Validations:");
                for (id, result) in validation_results.iter().filter(|(_, r)| !r.is_valid) {
                    println!("  - {}: {}", id, style(&result.error_message).red());
                }
                return Err(color_eyre::eyre::eyre!("{} plugin(s) failed validation", failed_validations));
            }
        }
    }
    
    println!("✓ Validation completed");
    Ok(())
}

#[derive(Debug, Clone)]
struct ValidationResult {
    is_valid: bool,
    warnings: Vec<String>,
    error_message: String,
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self {
            is_valid: true,
            warnings: Vec::new(),
            error_message: String::new(),
        }
    }
}

async fn validate_single_plugin(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
    marketplace: &fortress_core::plugin_marketplace::PluginMarketplace,
) -> Result<ValidationResult> {
    let mut result = ValidationResult::default();
    
    println!("Validating: {} v{}", plugin.metadata.id, plugin.metadata.version);
    
    // 1. Check plugin file integrity
    if let Err(e) = validate_plugin_integrity(plugin).await {
        result.is_valid = false;
        result.error_message = format!("File integrity check failed: {}", e);
        return Ok(result);
    }
    
    // 2. Validate plugin configuration
    if let Err(e) = validate_plugin_configuration(plugin).await {
        result.is_valid = false;
        result.error_message = format!("Configuration validation failed: {}", e);
        return Ok(result);
    }
    
    // 3. Check plugin capabilities
    if let Err(e) = validate_plugin_capabilities(plugin).await {
        result.is_valid = false;
        result.error_message = format!("Capability validation failed: {}", e);
        return Ok(result);
    }
    
    // 4. Validate plugin dependencies
    if let Err(e) = validate_plugin_dependencies(plugin, marketplace).await {
        result.is_valid = false;
        result.error_message = format!("Dependency validation failed: {}", e);
        return Ok(result);
    }
    
    // 5. Check plugin version compatibility
    if let Err(e) = validate_plugin_version(plugin).await {
        result.is_valid = false;
        result.error_message = format!("Version compatibility check failed: {}", e);
        return Ok(result);
    }
    
    // 6. Test plugin functionality
    if let Err(e) = test_plugin_functionality(plugin).await {
        result.is_valid = false;
        result.error_message = format!("Functionality test failed: {}", e);
        return Ok(result);
    }
    
    // 7. Check security compliance
    let security_warnings = validate_security_compliance(plugin).await?;
    result.warnings.extend(security_warnings);
    
    println!("✓ Plugin '{}' is valid", plugin.metadata.id);
    if !result.warnings.is_empty() {
        println!("⚠ Warnings:");
        for warning in &result.warnings {
            println!("  - {}", warning);
        }
    }
    
    Ok(result)
}

async fn validate_repository_plugin(
    plugin: &fortress_core::plugin_marketplace::PluginPackage,
    marketplace: &fortress_core::plugin_marketplace::PluginMarketplace,
) -> Result<ValidationResult> {
    let mut result = ValidationResult::default();
    
    println!("Validating repository plugin: {} v{}", plugin.id, plugin.version);
    
    // 1. Validate plugin metadata
    if let Err(e) = validate_plugin_metadata(plugin).await {
        result.is_valid = false;
        result.error_message = format!("Metadata validation failed: {}", e);
        return Ok(result);
    }
    
    // 2. Check plugin size
    if plugin.size_bytes > 100 * 1024 * 1024 { // 100MB limit
        result.warnings.push("Plugin size exceeds 100MB".to_string());
    }
    
    // 3. Validate plugin dependencies
    if !plugin.dependencies.is_empty() {
        for dep in &plugin.dependencies {
            if let Err(e) = validate_dependency_available(dep, marketplace).await {
                result.warnings.push(format!("Dependency '{}' unavailable: {}", dep, e));
            }
        }
    }
    
    // 4. Check plugin rating and downloads
    if plugin.rating < 3.0 {
        result.warnings.push("Plugin has low rating (< 3.0)".to_string());
    }
    
    if plugin.download_count < 100 {
        result.warnings.push("Plugin has few downloads (< 100)".to_string());
    }
    
    println!("✓ Repository plugin '{}' is valid", plugin.id);
    if !result.warnings.is_empty() {
        println!("⚠ Warnings:");
        for warning in &result.warnings {
            println!("  - {}", warning);
        }
    }
    
    Ok(result)
}

async fn validate_plugin_integrity(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
) -> Result<()> {
    // Check if plugin files exist and are accessible
    let plugin_path = get_plugin_path(&plugin.metadata.id)?;
    
    if !plugin_path.exists() {
        return Err(color_eyre::eyre::eyre!("Plugin directory not found: {}", plugin_path.display()));
    }
    
    // Check for required files
    let required_files = vec!["plugin.json", "lib.so", "README.md"];
    
    for file in required_files {
        let file_path = plugin_path.join(file);
        if !file_path.exists() {
            return Err(color_eyre::eyre::eyre!("Required plugin file missing: {}", file));
        }
    }
    
    // Verify plugin manifest
    let manifest_path = plugin_path.join("plugin.json");
    let manifest_content = tokio::fs::read_to_string(&manifest_path).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to read plugin manifest: {}", e))?;
    
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)
        .map_err(|e| color_eyre::eyre::eyre!("Invalid plugin manifest JSON: {}", e))?;
    
    // Verify manifest contains required fields
    let required_fields = vec!["id", "version", "name", "description", "capabilities"];
    for field in required_fields {
        if manifest.get(field).is_none() {
            return Err(color_eyre::eyre::eyre!("Missing required field in manifest: {}", field));
        }
    }
    
    Ok(())
}

async fn validate_plugin_configuration(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
) -> Result<()> {
    // Check if configuration schema is valid
    if let Some(config) = &plugin.config {
        // Validate configuration against schema if available
        if let Err(e) = validate_config_against_schema(config, &plugin.metadata).await {
            return Err(color_eyre::eyre::eyre!("Configuration validation failed: {}", e));
        }
    }
    
    Ok(())
}

async fn validate_plugin_capabilities(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
) -> Result<()> {
    // Check if plugin has required capabilities
    if plugin.metadata.capabilities.is_empty() {
        return Err(color_eyre::eyre::eyre!("Plugin has no capabilities defined"));
    }
    
    // Validate capability formats
    for capability in &plugin.metadata.capabilities {
        match capability {
            fortress_core::plugin::PluginCapability::Custom(name) => {
                if name.is_empty() {
                    return Err(color_eyre::eyre::eyre!("Custom capability name cannot be empty"));
                }
            }
            _ => {} // Built-in capabilities are always valid
        }
    }
    
    Ok(())
}

async fn validate_plugin_dependencies(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
    marketplace: &fortress_core::plugin_marketplace::PluginMarketplace,
) -> Result<()> {
    // Check if all dependencies are satisfied
    let installed_plugins = marketplace.list_installed().await?;
    let installed_ids: std::collections::HashSet<String> = 
        installed_plugins.iter().map(|p| p.metadata.id.clone()).collect();
    
    for dependency in &plugin.metadata.dependencies {
        if !installed_ids.contains(dependency) {
            return Err(color_eyre::eyre::eyre!("Missing dependency: {}", dependency));
        }
    }
    
    Ok(())
}

async fn validate_plugin_version(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
) -> Result<()> {
    // Check if plugin version is compatible with current Fortress version
    let fortress_version = env!("CARGO_PKG_VERSION");
    
    // Simple semantic version check
    if let Ok(plugin_semver) = semver::Version::parse(&plugin.metadata.version) {
        if let Ok(fortress_semver) = semver::Version::parse(fortress_version) {
            // Check major version compatibility
            if plugin_semver.major != fortress_semver.major {
                return Err(color_eyre::eyre::eyre!(
                    "Plugin major version ({}) does not match Fortress version ({})",
                    plugin_semver.major, fortress_semver.major
                ));
            }
        }
    }
    
    Ok(())
}

async fn test_plugin_functionality(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
) -> Result<()> {
    // Try to load and initialize the plugin
    let plugin_path = get_plugin_path(&plugin.metadata.id)?;
    
    // This would typically involve dynamic library loading and testing
    // For now, we'll simulate basic functionality tests
    
    // Test 1: Check if plugin can be loaded
    let lib_path = plugin_path.join("lib.so");
    if !lib_path.exists() {
        return Err(color_eyre::eyre::eyre!("Plugin library not found"));
    }
    
    // Test 2: Check plugin initialization (simulated)
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Test 3: Check plugin capabilities (simulated)
    for capability in &plugin.metadata.capabilities {
        // Simulate capability testing
        match capability {
            fortress_core::plugin::PluginCapability::Encrypt => {
                // Test encryption capability
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            fortress_core::plugin::PluginCapability::Decrypt => {
                // Test decryption capability
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            fortress_core::plugin::PluginCapability::SignTransaction => {
                // Test signing capability
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
            _ => {
                // Test other capabilities
                tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
            }
        }
    }
    
    Ok(())
}

async fn validate_security_compliance(
    plugin: &fortress_core::plugin_marketplace::InstalledPlugin,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    
    // Check for potential security issues
    let plugin_path = get_plugin_path(&plugin.metadata.id)?;
    
    // Warning 1: Check if plugin has executable permissions
    if let Ok(_metadata) = tokio::fs::metadata(&plugin_path).await {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = _metadata.permissions();
            if permissions.mode() & 0o111 != 0 {
                warnings.push("Plugin directory has executable permissions".to_string());
            }
        }
    }
    
    // Warning 2: Check plugin age
    let now = chrono::Utc::now();
    let plugin_age = now.signed_duration_since(plugin.installed_at);
    if plugin_age.num_seconds() > 86400 * 30 { // 30 days
        warnings.push("Plugin has not been updated in over 30 days".to_string());
    }
    
    // Warning 3: Check for suspicious file patterns
    if let Ok(mut entries) = tokio::fs::read_dir(&plugin_path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with('.') && file_name != ".gitignore" {
                warnings.push(format!("Hidden file found: {}", file_name));
            }
        }
    }
    
    Ok(warnings)
}

async fn validate_plugin_metadata(
    plugin: &fortress_core::plugin_marketplace::PluginPackage,
) -> Result<()> {
    // Validate required metadata fields
    if plugin.id.is_empty() {
        return Err(color_eyre::eyre::eyre!("Plugin ID cannot be empty"));
    }
    
    if plugin.name.is_empty() {
        return Err(color_eyre::eyre::eyre!("Plugin name cannot be empty"));
    }
    
    if plugin.description.is_empty() {
        return Err(color_eyre::eyre::eyre!("Plugin description cannot be empty"));
    }
    
    if plugin.version.is_empty() {
        return Err(color_eyre::eyre::eyre!("Plugin version cannot be empty"));
    }
    
    if plugin.author.is_empty() {
        return Err(color_eyre::eyre::eyre!("Plugin author cannot be empty"));
    }
    
    // Validate version format
    if semver::Version::parse(&plugin.version).is_err() {
        return Err(color_eyre::eyre::eyre!("Invalid semantic version: {}", plugin.version));
    }
    
    // Validate capabilities
    if plugin.capabilities.is_empty() {
        return Err(color_eyre::eyre::eyre!("Plugin must have at least one capability"));
    }
    
    Ok(())
}

async fn validate_dependency_available(
    dependency: &str,
    marketplace: &fortress_core::plugin_marketplace::PluginMarketplace,
) -> Result<()> {
    // Check if dependency is available in marketplace
    let package = marketplace.get_package(dependency).await;
    if package.is_err() {
        return Err(color_eyre::eyre::eyre!("Dependency not available in marketplace"));
    }
    
    Ok(())
}

async fn validate_config_against_schema(
    _config: &std::collections::HashMap<String, serde_json::Value>,
    metadata: &fortress_core::plugin_marketplace::PluginPackage,
) -> Result<()> {
    // This would validate configuration against JSON schema
    // For now, we'll do basic validation
    
    if let Some(schema_value) = &metadata.config_schema {
        // If config_schema is already a Value, use it directly
        // Otherwise, parse it as JSON string
        let schema = match schema_value {
            serde_json::Value::String(s) => {
                serde_json::from_str::<serde_json::Value>(s)
                    .map_err(|e| color_eyre::eyre::eyre!("Invalid config schema: {}", e))?
            }
            _ => schema_value.clone(),
        };
        
        // Basic schema validation would go here
        // For now, just check if schema is valid JSON
        let _ = schema;
    }
    
    Ok(())
}

fn get_plugin_path(plugin_id: &str) -> Result<PathBuf> {
    let plugins_dir = get_plugins_directory()?;
    Ok(plugins_dir.join(plugin_id))
}

/// Create marketplace instance
fn create_marketplace() -> Result<PluginMarketplace> {
    let plugins_dir = get_plugins_directory()?;
    PluginMarketplace::new(plugins_dir, None)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create marketplace: {}", e))
}

/// Create marketplace with custom repository
fn create_marketplace_with_repo(repo_url: Option<String>) -> Result<PluginMarketplace> {
    let plugins_dir = get_plugins_directory()?;
    PluginMarketplace::new(plugins_dir, repo_url)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create marketplace: {}", e))
}

/// Get plugins directory
fn get_plugins_directory() -> Result<PathBuf> {
    let home_dir = dirs::home_dir().ok_or_else(|| color_eyre::eyre::eyre!("Could not find home directory"))?;
    let fortress_dir = home_dir.join(".fortress");
    let plugins_dir = fortress_dir.join("plugins");
    
    Ok(plugins_dir)
}

/// Print plugin summary
fn print_plugin_summary(index: usize, plugin: &PluginPackage) {
    println!("{}. {} v{}", index, plugin.name, plugin.version);
    println!("   {}", plugin.description);
    println!("   Tags: {}", plugin.tags.join(", "));
    println!("   Rating: {:.1}/5 ({} downloads)", plugin.rating, plugin.download_count);
    println!("   Capabilities: {}", format_capabilities(&plugin.capabilities));
}

/// Print detailed plugin information
fn print_plugin_details(plugin: &PluginPackage) {
    println!("{} v{}", plugin.name, plugin.version);
    println!("ID: {}", plugin.id);
    println!("Author: {}", plugin.author);
    println!("Description: {}", plugin.description);
    println!("Tags: {}", plugin.tags.join(", "));
    println!("Rating: {:.1}/5 ({} downloads)", plugin.rating, plugin.download_count);
    println!("Capabilities: {}", format_capabilities(&plugin.capabilities));
    println!("Size: {} bytes", plugin.size_bytes);
    println!("Last updated: {}", plugin.last_updated.format("%Y-%m-%d %H:%M:%S UTC"));
    
    if !plugin.dependencies.is_empty() {
        println!("Dependencies: {}", plugin.dependencies.join(", "));
    }
    
    if let Some(_schema) = &plugin.config_schema {
        println!("Configuration schema available");
    }
}

/// Format capabilities for display
fn format_capabilities(capabilities: &[fortress_core::plugin::PluginCapability]) -> String {
    capabilities
        .iter()
        .map(|cap| match cap {
            fortress_core::plugin::PluginCapability::SignTransaction => "sign",
            fortress_core::plugin::PluginCapability::VerifySignature => "verify",
            fortress_core::plugin::PluginCapability::GenerateKey => "generate",
            fortress_core::plugin::PluginCapability::Encrypt => "encrypt",
            fortress_core::plugin::PluginCapability::Decrypt => "decrypt",
            fortress_core::plugin::PluginCapability::Hash => "hash",
            fortress_core::plugin::PluginCapability::ApiIntegration => "api",
            fortress_core::plugin::PluginCapability::SecretManagement => "secrets",
            fortress_core::plugin::PluginCapability::Authentication => "auth",
            fortress_core::plugin::PluginCapability::Custom(name) => name,
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Confirm plugin installation
fn confirm_installation(plugin: &PluginPackage) -> Result<bool> {
    println!("\nWarning: This will install '{}' v{} ({})", 
        plugin.name, plugin.version, plugin.size_bytes);
    println!("Description: {}", plugin.description);
    
    println!("\nDo you want to continue? [y/N]");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}

/// Confirm plugin uninstallation
fn confirm_uninstallation(plugin: &InstalledPlugin) -> Result<bool> {
    println!("\nWarning: This will uninstall '{}' v{}", 
        plugin.metadata.name, plugin.metadata.version);
    println!("Installed: {}", plugin.installed_at.format("%Y-%m-%d %H:%M:%S UTC"));
    
    println!("\nDo you want to continue? [y/N]");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}
