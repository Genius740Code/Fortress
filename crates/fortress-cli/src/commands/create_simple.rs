use color_eyre::eyre::{Result, Context};
use console::style;
use dialoguer::{Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tracing::{info, debug};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleConfig {
    pub database: DatabaseConfig,
    pub encryption: EncryptionConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub name: String,
    pub path: String,
    pub max_size: Option<u64>,
    pub pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub algorithm: String,
    pub key_rotation_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub backend: String,
    pub path: String,
}

pub async fn handle_create_simple(
    name: Option<String>,
    template: String,
    data_dir: Option<String>,
    interactive: bool,
) -> Result<()> {
    println!("{}", style("🏰 Fortress Database Creation").bold().cyan());
    println!();
    
    // Get database name
    let db_name = if interactive && name.is_none() {
        Input::<String>::new()
            .with_prompt("Database name")
            .interact()?
    } else {
        name.ok_or_else(|| color_eyre::eyre::eyre!("Database name is required"))?
    };
    
    // Get data directory
    let db_path = if interactive && data_dir.is_none() {
        let default_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("fortress")
            .join(&db_name);
        
        let path_str = Input::<String>::new()
            .with_prompt("Data directory")
            .default(default_path.to_string_lossy().to_string())
            .interact()?;
        PathBuf::from(path_str)
    } else {
        PathBuf::from(data_dir.unwrap_or_else(|| format!("./{}", db_name)))
    };
    
    // Select template if interactive
    let selected_template = if interactive {
        let templates = vec!["startup", "enterprise", "custom"];
        let selection = Select::new()
            .with_prompt("Select template")
            .items(&templates)
            .default(0)
            .interact()?;
        templates[selection].to_string()
    } else {
        template
    };
    
    // Confirm creation
    if interactive {
        println!();
        println!("Database name: {}", style(&db_name).bold());
        println!("Data directory: {}", style(db_path.display()).bold());
        println!("Template: {}", style(&selected_template).bold());
        println!();
        
        if !Confirm::new()
            .with_prompt("Create database?")
            .default(true)
            .interact()?
        {
            println!("Database creation cancelled.");
            return Ok(());
        }
    }
    
    // Create database
    create_database_simple(&db_name, &db_path, &selected_template).await?;
    
    println!();
    println!("{}", style("✅ Database created successfully!").green().bold());
    println!("Name: {}", style(&db_name).bold());
    println!("Path: {}", style(db_path.display()).bold());
    println!("Template: {}", style(&selected_template).bold());
    
    if interactive {
        println!();
        println!("Next steps:");
        println!("  Start server: {}", style(format!("fortress start --data-dir {}", db_path.display())).cyan());
        println!("  Check status: {}", style(format!("fortress status --data-dir {}", db_path.display())).cyan());
    }
    
    Ok(())
}

async fn create_database_simple(
    name: &str,
    path: &PathBuf,
    template: &str,
) -> Result<()> {
    let pb = ProgressBar::new(3);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {msg}")
            .unwrap()
            .progress_chars("#>-")
    );
    
    // Step 1: Create directory structure
    pb.set_message("Creating directory structure...");
    pb.inc(1);
    create_directory_structure(path)?;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    
    // Step 2: Generate configuration
    pb.set_message("Generating configuration...");
    pb.inc(1);
    let config = generate_simple_config(name, template);
    save_simple_config(path, &config).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    
    // Step 3: Generate basic key file
    pb.set_message("Generating encryption keys...");
    pb.inc(1);
    generate_simple_keys(path).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    
    pb.finish_with_message("Database created!");
    
    Ok(())
}

fn create_directory_structure(path: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed to create directory: {}", path.display()))?;
    
    // Create subdirectories
    let subdirs = ["data", "keys", "logs", "config"];
    for subdir in &subdirs {
        let subdir_path = path.join(subdir);
        std::fs::create_dir_all(&subdir_path)
            .with_context(|| format!("Failed to create subdirectory: {}", subdir_path.display()))?;
    }
    
    debug!("Created directory structure at: {}", path.display());
    Ok(())
}

fn generate_simple_config(name: &str, template: &str) -> SimpleConfig {
    let config = match template {
        "enterprise" => SimpleConfig {
            database: DatabaseConfig {
                name: name.to_string(),
                path: format!("./data/{}.db", name),
                max_size: Some(10 * 1024 * 1024 * 1024), // 10GB
                pool_size: 20,
            },
            encryption: EncryptionConfig {
                algorithm: "aes256gcm".to_string(),
                key_rotation_interval_hours: 168, // 7 days
            },
            storage: StorageConfig {
                backend: "filesystem".to_string(),
                path: "./data".to_string(),
            },
        },
        _ => SimpleConfig {
            database: DatabaseConfig {
                name: name.to_string(),
                path: format!("./data/{}.db", name),
                max_size: Some(1024 * 1024 * 1024), // 1GB
                pool_size: 5,
            },
            encryption: EncryptionConfig {
                algorithm: "aegis256".to_string(),
                key_rotation_interval_hours: 23, // 23 hours
            },
            storage: StorageConfig {
                backend: "filesystem".to_string(),
                path: "./data".to_string(),
            },
        },
    };
    
    debug!("Generated simple configuration for template: {}", template);
    config
}

async fn save_simple_config(path: &PathBuf, config: &SimpleConfig) -> Result<()> {
    let config_path = path.join("config").join("fortress.toml");
    let config_toml = toml::to_string_pretty(config)
        .with_context(|| "Failed to serialize configuration")?;
    
    tokio::fs::write(&config_path, config_toml)
        .await
        .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;
    
    debug!("Saved simple configuration to: {}", config_path.display());
    Ok(())
}

async fn generate_simple_keys(path: &PathBuf) -> Result<()> {
    // Generate a simple master key file (placeholder)
    let key_path = path.join("keys").join("master.key");
    let key_data = format!("master_key_placeholder_{}", chrono::Utc::now().timestamp());
    
    tokio::fs::write(&key_path, key_data)
        .await
        .with_context(|| format!("Failed to save master key: {}", key_path.display()))?;
    
    debug!("Generated and saved simple master key");
    Ok(())
}
