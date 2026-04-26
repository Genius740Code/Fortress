use color_eyre::eyre::{Result, Context};
use console::style;
use dialoguer::{Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tracing::debug;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Simple configuration structure for Fortress database
///
/// Contains the basic configuration needed to set up a Fortress database
/// with database, encryption, and storage settings.
pub struct SimpleConfig {
    /// Database configuration settings
    pub database: DatabaseConfig,
    /// Encryption configuration settings
    pub encryption: EncryptionConfig,
    /// Storage configuration settings
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Database configuration settings
///
/// Defines the database connection parameters including name, path,
/// size limits, and connection pool settings.
pub struct DatabaseConfig {
    /// Database name identifier
    pub name: String,
    /// File system path for the database
    pub path: String,
    /// Maximum database size in bytes (None for unlimited)
    pub max_size: Option<u64>,
    /// Number of connections in the database pool
    pub pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Encryption configuration settings
///
/// Defines the encryption algorithm and key rotation policy
/// for database encryption.
pub struct EncryptionConfig {
    /// Encryption algorithm name (e.g., "aegis256", "aes256gcm")
    pub algorithm: String,
    /// Key rotation interval in hours
    pub key_rotation_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Storage configuration settings
///
/// Defines the storage backend and path for data storage.
pub struct StorageConfig {
    /// Storage backend type (e.g., "filesystem", "s3")
    pub backend: String,
    /// Base path for storage
    pub path: String,
}

/// Handle the create simple command
///
/// Creates a new Fortress database with simple configuration using
/// either interactive mode or provided parameters.
///
/// # Arguments
/// * `name` - Optional database name
/// * `template` - Configuration template to use
/// * `data_dir` - Optional data directory path
/// * `interactive` - Whether to run in interactive mode
/// * `_dry_run` - Whether to perform a dry run (unused)
///
/// # Returns
/// Result indicating success or failure
pub async fn handle_create_simple(
    name: Option<String>,
    template: String,
    data_dir: Option<String>,
    interactive: bool,
    _dry_run: bool,
) -> Result<()> {
    println!("{}", style("Fortress Database Creation").bold().cyan());
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
    
    // Advanced configuration in interactive mode
    let (encryption_config, database_config) = if interactive {
        let encryption_config = configure_encryption_interactive(&selected_template)?;
        let database_config = configure_database_interactive(&selected_template)?;
        (encryption_config, database_config)
    } else {
        let config = generate_simple_config(&db_name, &selected_template);
        (config.encryption, config.database)
    };
    
    // Confirm creation
    if interactive {
        println!();
        println!("{}", style("Configuration Summary").bold().cyan());
        println!("Database name: {}", style(&db_name).bold());
        println!("Data directory: {}", style(db_path.display()).bold());
        println!("Template: {}", style(&selected_template).bold());
        println!("Encryption algorithm: {}", style(&encryption_config.algorithm).bold());
        println!("Key rotation: {} hours", style(&encryption_config.key_rotation_interval_hours).bold());
        println!("Database pool size: {}", style(&database_config.pool_size).bold());
        if let Some(max_size) = database_config.max_size {
            println!("Max database size: {} GB", style(max_size / (1024 * 1024 * 1024)).bold());
        }
        println!();
        
        if !Confirm::new()
            .with_prompt("Create database with these settings?")
            .default(true)
            .interact()?
        {
            println!("Database creation cancelled.");
            return Ok(());
        }
    }
    
    // Create database
    let mut final_database_config = database_config;
    final_database_config.name = db_name.clone();
    final_database_config.path = format!("./data/{}.db", db_name);
    
    create_database_simple(&db_name, &db_path, &selected_template, encryption_config, final_database_config).await?;
    
    println!();
    println!("{}", style("✓ Database created successfully").green().bold());
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
    _name: &str,
    path: &PathBuf,
    _template: &str,
    encryption_config: EncryptionConfig,
    database_config: DatabaseConfig,
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
    let config = SimpleConfig {
        database: database_config,
        encryption: encryption_config,
        storage: StorageConfig {
            backend: "filesystem".to_string(),
            path: "./data".to_string(),
        },
    };
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
    use fortress_core::key::{SecureKey, KeyId};
    
    // Generate a real cryptographic key
    let key = SecureKey::generate(32).expect("Failed to generate secure key"); // 256-bit key
    let key_id = KeyId::new();
    
    // Create keys directory
    let keys_dir = path.join("keys");
    tokio::fs::create_dir_all(&keys_dir).await
        .with_context(|| format!("Failed to create keys directory: {}", keys_dir.display()))?;
    
    // Save the key securely
    let key_path = keys_dir.join("master.key");
    let key_data = key.as_bytes();
    
    tokio::fs::write(&key_path, key_data)
        .await
        .with_context(|| format!("Failed to save master key: {}", key_path.display()))?;
    
    // Save key metadata
    let metadata_path = keys_dir.join("master.meta");
    let metadata = serde_json::json!({
        "key_id": key_id.to_string(),
        "algorithm": "aegis256",
        "created_at": chrono::Utc::now().to_rfc3339(),
        "key_size": 32
    });
    
    tokio::fs::write(&metadata_path, metadata.to_string())
        .await
        .with_context(|| format!("Failed to save key metadata: {}", metadata_path.display()))?;
    
    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(&key_path).await?.permissions();
        perms.set_mode(0o600); // Read/write for owner only
        tokio::fs::set_permissions(&key_path, perms).await
            .with_context(|| format!("Failed to set key permissions: {}", key_path.display()))?;
    }
    
    debug!("Generated and saved secure master key with ID: {}", key_id);
    Ok(())
}

fn configure_encryption_interactive(template: &str) -> Result<EncryptionConfig> {
    println!();
    println!("{}", style("Encryption Configuration").bold().cyan());
    
    // Encryption algorithm selection
    let algorithms = vec!["aegis256", "aes256gcm", "chacha20poly1305"];
    let default_index = match template {
        "enterprise" => 1, // aes256gcm
        _ => 0, // aegis256
    };
    
    let algorithm_selection = Select::new()
        .with_prompt("Select encryption algorithm")
        .items(&algorithms)
        .default(default_index)
        .interact()?;
    
    let algorithm = algorithms[algorithm_selection].to_string();
    
    // Key rotation interval
    let rotation_intervals = vec![
        ("23 hours", 23),
        ("7 days", 168),
        ("30 days", 720),
        ("90 days", 2160),
    ];
    
    let default_rotation = match template {
        "enterprise" => 168, // 7 days
        _ => 23, // 23 hours
    };
    
    let rotation_items: Vec<String> = rotation_intervals.iter().map(|(name, _)| name.to_string()).collect();
    let default_rotation_index = rotation_intervals.iter().position(|(_, hours)| *hours == default_rotation).unwrap_or(0);
    
    let rotation_selection = Select::new()
        .with_prompt("Select key rotation interval")
        .items(&rotation_items)
        .default(default_rotation_index)
        .interact()?;
    
    let key_rotation_interval_hours = rotation_intervals[rotation_selection].1;
    
    Ok(EncryptionConfig {
        algorithm,
        key_rotation_interval_hours,
    })
}

fn configure_database_interactive(template: &str) -> Result<DatabaseConfig> {
    println!();
    println!("{}", style("🗄️ Database Configuration").bold().cyan());
    
    // Pool size configuration
    let pool_sizes = vec![
        ("Small (5 connections)", 5),
        ("Medium (10 connections)", 10),
        ("Large (20 connections)", 20),
        ("Enterprise (50 connections)", 50),
    ];
    
    let default_pool = match template {
        "enterprise" => 20,
        _ => 5,
    };
    
    let pool_items: Vec<String> = pool_sizes.iter().map(|(name, _)| name.to_string()).collect();
    let default_pool_index = pool_sizes.iter().position(|(_, size)| *size == default_pool).unwrap_or(0);
    
    let pool_selection = Select::new()
        .with_prompt("Select database connection pool size")
        .items(&pool_items)
        .default(default_pool_index)
        .interact()?;
    
    let pool_size = pool_sizes[pool_selection].1;
    
    // Max database size
    let size_options = vec![
        ("1 GB", Some(1024 * 1024 * 1024)),
        ("5 GB", Some(5 * 1024 * 1024 * 1024)),
        ("10 GB", Some(10 * 1024 * 1024 * 1024)),
        ("50 GB", Some(50 * 1024 * 1024 * 1024)),
        ("Unlimited", None),
    ];
    
    let default_size = match template {
        "enterprise" => Some(10 * 1024 * 1024 * 1024),
        _ => Some(1024 * 1024 * 1024),
    };
    
    let size_items: Vec<String> = size_options.iter().map(|(name, _)| name.to_string()).collect();
    let default_size_index = size_options.iter().position(|(_, size)| *size == default_size).unwrap_or(0);
    
    let size_selection = Select::new()
        .with_prompt("Select maximum database size")
        .items(&size_items)
        .default(default_size_index)
        .interact()?;
    
    let max_size = size_options[size_selection].1;
    
    Ok(DatabaseConfig {
        name: String::new(), // Will be set by caller
        path: String::new(), // Will be set by caller
        max_size,
        pool_size,
    })
}
