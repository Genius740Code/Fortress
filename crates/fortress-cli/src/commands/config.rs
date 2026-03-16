use color_eyre::eyre::Result;
use console::style;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tracing::{info, warn, error};
use crate::ConfigAction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSettings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
    pub max_connections: usize,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub encryption_algorithm: String,
    pub key_rotation_interval: u64,
    pub audit_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: Option<String>,
    pub max_file_size: u64,
}

impl Default for ConfigSettings {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: num_cpus::get(),
            },
            database: DatabaseConfig {
                path: "./fortress".to_string(),
                max_connections: 100,
                connection_timeout: 30,
            },
            security: SecurityConfig {
                encryption_algorithm: "aegis256".to_string(),
                key_rotation_interval: 86400 * 7, // 7 days
                audit_enabled: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: None,
                max_file_size: 10 * 1024 * 1024, // 10MB
            },
            custom: HashMap::new(),
        }
    }
}

pub async fn handle_config_action(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            handle_config_show().await
        }
        ConfigAction::Set { key, value } => {
            handle_config_set(key, value).await
        }
        ConfigAction::Reset => {
            handle_config_reset().await
        }
        ConfigAction::Validate => {
            handle_config_validate().await
        }
    }
}

async fn handle_config_show() -> Result<()> {
    println!("{}", style("⚙️ Current configuration").bold().cyan());
    println!();
    
    let config_path = get_config_path()?;
    
    if !config_path.exists() {
        println!("{} No configuration file found. Using defaults.", style("⚠️").yellow());
        println!();
        print_default_config();
        return Ok(());
    }
    
    let config_content = fs::read_to_string(&config_path).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to read config file: {}", e))?;
    
    let config: ConfigSettings = toml::from_str(&config_content)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse config file: {}", e))?;
    
    print_config(&config);
    println!("📁 Configuration file: {}", style(config_path.display()).bold());
    
    Ok(())
}

async fn handle_config_set(key: String, value: String) -> Result<()> {
    println!("{}", style("⚙️ Setting configuration").bold().cyan());
    println!("{} = {}", style(key.clone()).bold(), style(value.clone()).bold());
    
    let config_path = get_config_path()?;
    let mut config = load_or_create_config(&config_path).await?;
    
    // Parse and set the configuration value
    set_config_value(&mut config, &key, &value)?;
    
    // Save the updated configuration
    save_config(&config_path, &config).await?;
    
    println!("✅ Configuration updated successfully!");
    info!("Configuration updated: {} = {}", key, value);
    
    Ok(())
}

async fn handle_config_reset() -> Result<()> {
    println!("{}", style("⚙️ Resetting configuration").bold().cyan());
    
    let config_path = get_config_path()?;
    
    if !config_path.exists() {
        println!("{} No configuration file exists. Nothing to reset.", style("ℹ️").blue());
        return Ok(());
    }
    
    // Create backup before reset
    let backup_path = config_path.with_extension("toml.bak");
    fs::copy(&config_path, &backup_path).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create backup: {}", e))?;
    
    println!("📋 Configuration backed up to: {}", style(backup_path.display()).bold());
    
    // Reset to defaults
    let default_config = ConfigSettings::default();
    save_config(&config_path, &default_config).await?;
    
    println!("✅ Configuration reset to defaults successfully!");
    info!("Configuration reset to defaults");
    
    Ok(())
}

async fn handle_config_validate() -> Result<()> {
    println!("{}", style("⚙️ Validating configuration").bold().cyan());
    
    let config_path = get_config_path()?;
    
    if !config_path.exists() {
        println!("{} No configuration file found. Using defaults.", style("⚠️").yellow());
        let default_config = ConfigSettings::default();
        validate_config(&default_config)?;
        return Ok(());
    }
    
    let config_content = fs::read_to_string(&config_path).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to read config file: {}", e))?;
    
    let config: ConfigSettings = toml::from_str(&config_content)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse config file: {}", e))?;
    
    validate_config(&config)?;
    
    println!("✅ Configuration is valid!");
    println!("📁 Configuration file: {}", style(config_path.display()).bold());
    
    Ok(())
}

pub fn get_config_path() -> Result<PathBuf> {
    let home_dir = dirs::home_dir().ok_or_else(|| color_eyre::eyre::eyre!("Could not find home directory"))?;
    let fortress_dir = home_dir.join(".fortress");
    Ok(fortress_dir.join("config").join("fortress.toml"))
}

pub async fn load_or_create_config(config_path: &PathBuf) -> Result<ConfigSettings> {
    if config_path.exists() {
        let config_content = fs::read_to_string(config_path).await
            .map_err(|e| color_eyre::eyre::eyre!("Failed to read config file: {}", e))?;
        
        toml::from_str(&config_content)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to parse config file: {}", e))
    } else {
        // Create parent directories if they don't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).await
                .map_err(|e| color_eyre::eyre::eyre!("Failed to create config directory: {}", e))?;
        }
        
        Ok(ConfigSettings::default())
    }
}

async fn save_config(config_path: &PathBuf, config: &ConfigSettings) -> Result<()> {
    let config_content = toml::to_string_pretty(config)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to serialize config: {}", e))?;
    
    fs::write(config_path, config_content).await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to write config file: {}", e))?;
    
    Ok(())
}

fn set_config_value(config: &mut ConfigSettings, key: &str, value: &str) -> Result<()> {
    let parts: Vec<&str> = key.split('.').collect();
    
    match parts.as_slice() {
        ["server", "host"] => {
            config.server.host = value.to_string();
        }
        ["server", "port"] => {
            config.server.port = value.parse()
                .map_err(|_| color_eyre::eyre::eyre!("Invalid port number: {}", value))?;
        }
        ["server", "workers"] => {
            config.server.workers = value.parse()
                .map_err(|_| color_eyre::eyre::eyre!("Invalid worker count: {}", value))?;
        }
        ["database", "path"] => {
            config.database.path = value.to_string();
        }
        ["database", "max_connections"] => {
            config.database.max_connections = value.parse()
                .map_err(|_| color_eyre::eyre::eyre!("Invalid max connections: {}", value))?;
        }
        ["database", "connection_timeout"] => {
            config.database.connection_timeout = value.parse()
                .map_err(|_| color_eyre::eyre::eyre!("Invalid connection timeout: {}", value))?;
        }
        ["security", "encryption_algorithm"] => {
            config.security.encryption_algorithm = value.to_string();
        }
        ["security", "key_rotation_interval"] => {
            config.security.key_rotation_interval = value.parse()
                .map_err(|_| color_eyre::eyre::eyre!("Invalid key rotation interval: {}", value))?;
        }
        ["security", "audit_enabled"] => {
            config.security.audit_enabled = value.parse()
                .map_err(|_| color_eyre::eyre::eyre!("Invalid audit enabled value: {}", value))?;
        }
        ["logging", "level"] => {
            config.logging.level = value.to_string();
        }
        ["logging", "file_path"] => {
            config.logging.file_path = if value.is_empty() { None } else { Some(value.to_string()) };
        }
        ["logging", "max_file_size"] => {
            config.logging.max_file_size = value.parse()
                .map_err(|_| color_eyre::eyre::eyre!("Invalid max file size: {}", value))?;
        }
        _ => {
            // Handle custom configuration values
            let json_value = parse_value_to_json(value)?;
            config.custom.insert(key.to_string(), json_value);
        }
    }
    
    Ok(())
}

fn parse_value_to_json(value: &str) -> Result<serde_json::Value> {
    // Try to parse as JSON first
    if let Ok(json_val) = serde_json::from_str(value) {
        return Ok(json_val);
    }
    
    // Try to parse as boolean
    if let Ok(bool_val) = value.parse::<bool>() {
        return Ok(serde_json::Value::Bool(bool_val));
    }
    
    // Try to parse as number
    if let Ok(int_val) = value.parse::<i64>() {
        return Ok(serde_json::Value::Number(serde_json::Number::from(int_val)));
    }
    
    if let Ok(float_val) = value.parse::<f64>() {
        return Ok(serde_json::Value::Number(serde_json::Number::from_f64(float_val)
            .ok_or_else(|| color_eyre::eyre::eyre!("Invalid float value: {}", value))?));
    }
    
    // Default to string
    Ok(serde_json::Value::String(value.to_string()))
}

fn validate_config(config: &ConfigSettings) -> Result<()> {
    let mut errors = Vec::new();
    
    // Validate server configuration
    if config.server.host.is_empty() {
        errors.push("Server host cannot be empty");
    }
    
    if config.server.port == 0 || config.server.port > 65535 {
        errors.push("Server port must be between 1 and 65535");
    }
    
    if config.server.workers == 0 || config.server.workers > 1024 {
        errors.push("Worker count must be between 1 and 1024");
    }
    
    // Validate database configuration
    if config.database.path.is_empty() {
        errors.push("Database path cannot be empty");
    }
    
    if config.database.max_connections == 0 || config.database.max_connections > 10000 {
        errors.push("Max connections must be between 1 and 10000");
    }
    
    if config.database.connection_timeout == 0 || config.database.connection_timeout > 3600 {
        errors.push("Connection timeout must be between 1 and 3600 seconds");
    }
    
    // Validate security configuration
    if !["aegis256", "aes256gcm", "chacha20poly1305"].contains(&config.security.encryption_algorithm.as_str()) {
        errors.push("Encryption algorithm must be one of: aegis256, aes256gcm, chacha20poly1305");
    }
    
    if config.security.key_rotation_interval < 3600 {
        errors.push("Key rotation interval must be at least 1 hour");
    }
    
    // Validate logging configuration
    if !["trace", "debug", "info", "warn", "error"].contains(&config.logging.level.as_str()) {
        errors.push("Logging level must be one of: trace, debug, info, warn, error");
    }
    
    if config.logging.max_file_size < 1024 * 1024 {
        errors.push("Max file size must be at least 1MB");
    }
    
    if !errors.is_empty() {
        println!("{} Configuration validation failed:", style("❌").red());
        for error in errors {
            println!("  - {}", style(error).red());
        }
        return Err(color_eyre::eyre::eyre!("Configuration validation failed"));
    }
    
    Ok(())
}

fn print_config(config: &ConfigSettings) {
    println!("{} Server Configuration:", style("🖥️").blue());
    println!("  Host: {}", style(&config.server.host).bold());
    println!("  Port: {}", style(config.server.port).bold());
    println!("  Workers: {}", style(config.server.workers).bold());
    println!();
    
    println!("{} Database Configuration:", style("💾").blue());
    println!("  Path: {}", style(&config.database.path).bold());
    println!("  Max Connections: {}", style(config.database.max_connections).bold());
    println!("  Connection Timeout: {}s", style(config.database.connection_timeout).bold());
    println!();
    
    println!("{} Security Configuration:", style("🔐").blue());
    println!("  Encryption Algorithm: {}", style(&config.security.encryption_algorithm).bold());
    println!("  Key Rotation Interval: {}h", style(config.security.key_rotation_interval / 3600).bold());
    println!("  Audit Enabled: {}", style(config.security.audit_enabled).bold());
    println!();
    
    println!("{} Logging Configuration:", style("📝").blue());
    println!("  Level: {}", style(&config.logging.level).bold());
    if let Some(ref file_path) = config.logging.file_path {
        println!("  File Path: {}", style(file_path).bold());
    } else {
        println!("  File Path: {}", style("stdout").dim());
    }
    println!("  Max File Size: {}MB", style(config.logging.max_file_size / 1024 / 1024).bold());
    println!();
    
    if !config.custom.is_empty() {
        println!("{} Custom Configuration:", style("⚙️").blue());
        for (key, value) in &config.custom {
            println!("  {}: {}", style(key).bold(), value);
        }
        println!();
    }
}

fn print_default_config() {
    let default_config = ConfigSettings::default();
    print_config(&default_config);
}
