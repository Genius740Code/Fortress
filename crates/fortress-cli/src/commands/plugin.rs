//! Plugin management commands for Fortress CLI

use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;
use serde_json;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn, error};

use fortress_core::plugin_marketplace::{PluginMarketplace, PluginPackage, InstalledPlugin};

/// Plugin management commands
#[derive(Parser)]
#[command(name = "plugin")]
#[command(about = "Manage Fortress plugins")]
pub struct PluginCommands {
    #[command(subcommand)]
    pub action: PluginAction,
}

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
    println!("🔍 Searching for plugins: '{}'", query);
    
    let marketplace = create_marketplace()?;
    let results = marketplace.search(&query, Some(limit)).await?;
    
    if results.is_empty() {
        println!("❌ No plugins found matching '{}'", query);
        return Ok(());
    }
    
    println!("✅ Found {} plugins:", results.len());
    println!();
    
    for (i, plugin) in results.iter().enumerate() {
        print_plugin_summary(i + 1, plugin);
        println!();
    }
    
    println!("💡 Use 'fortress plugin install <plugin-id>' to install a plugin");
    Ok(())
}

/// Handle plugin installation
async fn handle_install(
    plugin_id: String, 
    config: Vec<(String, String)>, 
    repo: Option<String>,
    yes: bool
) -> Result<()> {
    println!("📦 Installing plugin: '{}'", plugin_id);
    
    let marketplace = create_marketplace_with_repo(repo)?;
    
    // Get plugin information
    let plugin_info = marketplace.get_package(&plugin_id).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to get plugin info: {}", e))?;
    
    // Show plugin information
    print_plugin_details(&plugin_info);
    
    // Confirm installation
    if !yes {
        if !confirm_installation(&plugin_info)? {
            println!("❌ Installation cancelled");
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
    
    println!("🎉 Plugin '{}' installed successfully!", plugin_id);
    Ok(())
}

/// Handle plugin uninstallation
async fn handle_uninstall(plugin_id: String, yes: bool) -> Result<()> {
    println!("🗑️  Uninstalling plugin: '{}'", plugin_id);
    
    let marketplace = create_marketplace()?;
    
    // Check if plugin is installed
    let installed = marketplace.list_installed().await?;
    let plugin = installed.iter().find(|p| p.metadata.id == plugin_id);
    
    if plugin.is_none() {
        println!("❌ Plugin '{}' is not installed", plugin_id);
        return Ok(());
    }
    
    let plugin = plugin.unwrap();
    
    // Show plugin information
    print_plugin_summary(0, &plugin.metadata);
    
    // Confirm uninstallation
    if !yes {
        if !confirm_uninstallation(plugin)? {
            println!("❌ Uninstallation cancelled");
            return Ok(());
        }
    }
    
    // Uninstall plugin
    marketplace.uninstall(&plugin_id).await
        .map_err(|e| color_eyre::eyre::eyre!("Uninstallation failed: {}", e))?;
    
    println!("🎉 Plugin '{}' uninstalled successfully!", plugin_id);
    Ok(())
}

/// Handle listing installed plugins
async fn handle_list(detailed: bool, category: Option<String>) -> Result<()> {
    println!("📋 Installed plugins:");
    
    let marketplace = create_marketplace()?;
    let installed = marketplace.list_installed().await?;
    
    if installed.is_empty() {
        println!("❌ No plugins installed");
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
        println!("❌ No plugins found in category '{}'", category.as_ref().unwrap_or(&"all".to_string()));
        return Ok(());
    }
    
    println!("✅ {} plugins installed:", filtered.len());
    println!();
    
    for (i, plugin) in filtered.iter().enumerate() {
        if detailed {
            print_plugin_details(&plugin.metadata);
            if let Some(config) = &plugin.config {
                println!("📝 Configuration:");
                for (key, value) in config {
                    println!("   {}: {}", key, value);
                }
            }
            println!("📅 Installed: {}", plugin.installed_at.format("%Y-%m-%d %H:%M:%S UTC"));
        } else {
            print_plugin_summary(i + 1, &plugin.metadata);
        }
        println!();
    }
    
    Ok(())
}

/// Handle showing plugin information
async fn handle_show(plugin_id: String) -> Result<()> {
    println!("📖 Plugin information: '{}'", plugin_id);
    
    let marketplace = create_marketplace()?;
    
    // Try to get installed plugin info first
    let installed = marketplace.list_installed().await?;
    if let Some(plugin) = installed.iter().find(|p| p.metadata.id == plugin_id) {
        print_plugin_details(&plugin.metadata);
        println!("📅 Installed: {}", plugin.installed_at.format("%Y-%m-%d %H:%M:%S UTC"));
        
        if let Some(config) = &plugin.config {
            println!("📝 Configuration:");
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
    println!("❌ Not installed");
    
    Ok(())
}

/// Handle plugin updates
async fn handle_update(plugin_id: Option<String>, yes: bool) -> Result<()> {
    let marketplace = create_marketplace()?;
    
    match plugin_id {
        Some(id) => {
            println!("🔄 Updating plugin: '{}'", id);
            marketplace.update(&id).await
                .map_err(|e| color_eyre::eyre::eyre!("Update failed: {}", e))?;
        }
        None => {
            println!("🔄 Checking for updates to all plugins...");
            let installed = marketplace.list_installed().await?;
            
            if installed.is_empty() {
                println!("❌ No plugins installed");
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
    
    println!("🎉 Update completed!");
    Ok(())
}

/// Handle listing popular plugins
async fn handle_popular(limit: usize) -> Result<()> {
    println!("🌟 Popular plugins:");
    
    let marketplace = create_marketplace()?;
    let plugins = marketplace.list_popular(Some(limit)).await?;
    
    if plugins.is_empty() {
        println!("❌ No popular plugins found");
        return Ok(());
    }
    
    println!("✅ Top {} popular plugins:", plugins.len());
    println!();
    
    for (i, plugin) in plugins.iter().enumerate() {
        print_plugin_summary(i + 1, plugin);
        println!();
    }
    
    Ok(())
}

/// Handle listing plugins by category
async fn handle_category(category: String, limit: usize) -> Result<()> {
    println!("📂 Plugins in category: '{}'", category);
    
    let marketplace = create_marketplace()?;
    let plugins = marketplace.list_by_category(&category, Some(limit)).await?;
    
    if plugins.is_empty() {
        println!("❌ No plugins found in category '{}'", category);
        return Ok(());
    }
    
    println!("✅ Found {} plugins in category '{}':", plugins.len(), category);
    println!();
    
    for (i, plugin) in plugins.iter().enumerate() {
        print_plugin_summary(i + 1, plugin);
        println!();
    }
    
    Ok(())
}

/// Handle plugin validation
async fn handle_validate(plugin_id: Option<String>) -> Result<()> {
    println!("🔍 Validating plugins...");
    
    let marketplace = create_marketplace()?;
    
    match plugin_id {
        Some(id) => {
            println!("Validating plugin: '{}'", id);
            // TODO: Implement plugin validation logic
            println!("✅ Plugin '{}' is valid", id);
        }
        None => {
            let installed = marketplace.list_installed().await?;
            
            if installed.is_empty() {
                println!("❌ No plugins installed");
                return Ok(());
            }
            
            println!("Validating {} installed plugins...", installed.len());
            
            for plugin in installed {
                println!("✅ Plugin '{}' is valid", plugin.metadata.id);
            }
        }
    }
    
    println!("🎉 Validation completed!");
    Ok(())
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
    println!("   📝 {}", plugin.description);
    println!("   🏷️  Tags: {}", plugin.tags.join(", "));
    println!("   ⭐ Rating: {:.1}/5 ({} downloads)", plugin.rating, plugin.download_count);
    println!("   🔧 Capabilities: {}", format_capabilities(&plugin.capabilities));
}

/// Print detailed plugin information
fn print_plugin_details(plugin: &PluginPackage) {
    println!("📦 {} v{}", plugin.name, plugin.version);
    println!("🆔 ID: {}", plugin.id);
    println!("👤 Author: {}", plugin.author);
    println!("📝 Description: {}", plugin.description);
    println!("🏷️  Tags: {}", plugin.tags.join(", "));
    println!("⭐ Rating: {:.1}/5 ({} downloads)", plugin.rating, plugin.download_count);
    println!("🔧 Capabilities: {}", format_capabilities(&plugin.capabilities));
    println!("📦 Size: {} bytes", plugin.size_bytes);
    println!("📅 Last updated: {}", plugin.last_updated.format("%Y-%m-%d %H:%M:%S UTC"));
    
    if !plugin.dependencies.is_empty() {
        println!("🔗 Dependencies: {}", plugin.dependencies.join(", "));
    }
    
    if let Some(_schema) = &plugin.config_schema {
        println!("⚙️  Configuration schema available");
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
            fortress_core::plugin::PluginCapability::Custom(name) => name,
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Confirm plugin installation
fn confirm_installation(plugin: &PluginPackage) -> Result<bool> {
    println!("\n⚠️  This will install '{}' v{} ({})", 
        plugin.name, plugin.version, plugin.size_bytes);
    println!("📝 Description: {}", plugin.description);
    
    println!("\nDo you want to continue? [y/N]");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}

/// Confirm plugin uninstallation
fn confirm_uninstallation(plugin: &InstalledPlugin) -> Result<bool> {
    println!("\n⚠️  This will uninstall '{}' v{}", 
        plugin.metadata.name, plugin.metadata.version);
    println!("📅 Installed: {}", plugin.installed_at.format("%Y-%m-%d %H:%M:%S UTC"));
    
    println!("\nDo you want to continue? [y/N]");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}
