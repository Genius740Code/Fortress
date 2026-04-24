use color_eyre::eyre::{Result, Context};
use console::style;
use dialoguer::{Confirm, Input, Select};
use fortress_core::{Config, StorageBackend};
use fortress_core::config::{DatabaseConfig, EncryptionConfig, StorageConfig, ApiConfig, MonitoringConfig};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tracing::{info, debug};
use crate::config_manager::ConfigManager;
use crate::utils::path_utils;

pub async fn handle_create(
    name: Option<String>,
    template: String,
    data_dir: Option<String>,
    interactive: bool,
    dry_run: bool,
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
    
    // Handle list-templates
    if selected_template == "list-templates" {
        list_available_templates();
        return Ok(());
    }
    
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
    
    // Handle dry-run mode
    if dry_run {
        println!();
        println!("{}", style("🔍 DRY RUN MODE - Template Preview").bold().yellow());
        println!();
        
        let config = generate_config(&db_name, &selected_template)?;
        display_template_preview(&selected_template, &config);
        
        println!();
        println!("{}", style("ℹ️  Use --dry-run to preview templates without creating").cyan());
        return Ok(());
    }
    
    // Create database
    create_database(&db_name, &db_path, &selected_template).await?;
    
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

async fn create_database(
    name: &str,
    path: &PathBuf,
    template: &str,
) -> Result<()> {
    let pb = ProgressBar::new(4);
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
    let config = generate_config(name, template)?;
    save_config(path, &config).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    
    // Step 3: Initialize storage
    pb.set_message("Initializing storage...");
    pb.inc(1);
    initialize_storage(path, &config).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    
    // Step 4: Generate encryption keys
    pb.set_message("Generating encryption keys...");
    pb.inc(1);
    generate_keys(path).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    
    pb.finish_with_message("Database created!");
    
    Ok(())
}

fn create_directory_structure(path: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed to create directory: {}", path.display()))?;
    
    // Create subdirectories
    let subdirs = ["data", "keys", "logs", "config", "backups"];
    for subdir in &subdirs {
        let subdir_path = path.join(subdir);
        std::fs::create_dir_all(&subdir_path)
            .with_context(|| format!("Failed to create subdirectory: {}", subdir_path.display()))?;
    }
    
    debug!("Created directory structure at: {}", path.display());
    Ok(())
}

fn generate_config(name: &str, template: &str) -> Result<Config> {
    let mut config = match template {
        "startup" => create_startup_template(name),
        "enterprise" => create_enterprise_template(name),
        "custom" => Config::default(),
        _ => create_startup_template(name),
    };
    
    config.database.path = format!("./data/{}.db", name);
    
    debug!("Generated configuration for template: {}", template);
    Ok(config)
}

async fn save_config(path: &PathBuf, config: &Config) -> Result<()> {
    let config_path = path.join("config").join("fortress.toml");
    let config_toml = toml::to_string_pretty(config)
        .with_context(|| "Failed to serialize configuration")?;
    
    tokio::fs::write(&config_path, config_toml)
        .await
        .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;
    
    debug!("Saved configuration to: {}", config_path.display());
    Ok(())
}

async fn initialize_storage(path: &PathBuf, config: &Config) -> Result<()> {
    use fortress_core::storage::FileSystemStorage;
    
    // Initialize the storage backend
    let storage = FileSystemStorage::new(path.join("data"))
        .with_context(|| "Failed to initialize storage backend")?;
    
    debug!("Initialized storage backend");
    Ok(())
}

async fn generate_keys(path: &PathBuf) -> Result<()> {
    use fortress_core::key::SecureKey;
    
    // Generate master key (32 bytes for AES-256)
    let master_key = SecureKey::generate(32)
        .with_context(|| "Failed to generate master key")?;
    
    // Save master key
    let key_path = path.join("keys").join("master.key");
    let key_data = master_key.as_bytes();
    
    tokio::fs::write(&key_path, key_data)
        .await
        .with_context(|| format!("Failed to save master key: {}", key_path.display()))?;
    
    debug!("Generated and saved master key");
    Ok(())
}

fn create_startup_template(name: &str) -> Config {
    Config {
        database: DatabaseConfig {
            path: format!("./data/{}.db", name),
            max_size: Some(1024 * 1024 * 1024), // 1GB
            cache_size: Some(32 * 1024 * 1024),  // 32MB
            enable_wal: true,
            pool_size: 5,
        },
        encryption: EncryptionConfig {
            default_algorithm: "aegis256".to_string(),
            key_rotation_interval: std::time::Duration::from_secs(23 * 3600), // 23 hours
            master_key_rotation_interval: std::time::Duration::from_secs(90 * 24 * 3600), // 90 days
            profiles: std::collections::HashMap::new(),
            key_derivation: fortress_core::config::KeyDerivationConfig::default(),
        },
        storage: StorageConfig {
            backend: "filesystem".to_string(),
            base_path: Some("./data".to_string()),
            s3: None,
            azure_blob: None,
            gcs: None,
            compression: true,
            checksum: "sha256".to_string(),
        },
        api: Some(ApiConfig {
            rest_port: 8080,
            grpc_port: 50051,
            enable_cors: true,
            enable_wasm: false,
            rate_limit: None,
            authentication: None,
        }),
        monitoring: Some(MonitoringConfig {
            enable_metrics: false,
            metrics_port: 9090,
            enable_tracing: false,
            jaeger_endpoint: None,
            log_level: "info".to_string(),
        }),
    }
}

fn create_enterprise_template(name: &str) -> Config {
    Config {
        database: DatabaseConfig {
            path: format!("./data/{}.db", name),
            max_size: Some(10 * 1024 * 1024 * 1024), // 10GB
            cache_size: Some(256 * 1024 * 1024),      // 256MB
            enable_wal: true,
            pool_size: 20,
        },
        encryption: EncryptionConfig {
            default_algorithm: "aes256gcm".to_string(),
            key_rotation_interval: std::time::Duration::from_secs(7 * 24 * 3600), // 7 days
            master_key_rotation_interval: std::time::Duration::from_secs(30 * 24 * 3600), // 30 days
            profiles: std::collections::HashMap::new(),
            key_derivation: fortress_core::config::KeyDerivationConfig {
                kdf: "argon2id".to_string(),
                memory_cost: Some(256 * 1024), // 256 MiB
                iterations: Some(5),
                parallelism: Some(8),
                salt_length: Some(64),
            },
        },
        storage: StorageConfig {
            backend: "filesystem".to_string(),
            base_path: Some("./data".to_string()),
            s3: None,
            azure_blob: None,
            gcs: None,
            compression: true,
            checksum: "sha512".to_string(),
        },
        api: Some(ApiConfig {
            rest_port: 8080,
            grpc_port: 50051,
            enable_cors: true,
            enable_wasm: true,
            rate_limit: Some(fortress_core::config::RateLimitConfig {
                requests_per_minute: 1000,
                burst_size: 100,
            }),
            authentication: Some(fortress_core::config::AuthenticationConfig {
                auth_type: "jwt".to_string(),
                jwt_secret: None,
                api_key_header: Some("X-Fortress-API-Key".to_string()),
                ldap: None,
            }),
        }),
        monitoring: Some(MonitoringConfig {
            enable_metrics: true,
}

fn display_template_preview(template_name: &str, config: &Config) {
    println!("{}", style("Template Preview: {}").bold().cyan(), template_name);
    println!("{}", "=".repeat(50));
    
    match template_name {
        "startup" => {
            println!("{}", style("Startup Template").bold().yellow());
            println!("Perfect for development and small applications");
            println!();
            println!("Database Configuration:");
            println!("  Max Size: {}", style("1GB").bold());
            println!("  Cache Size: {}", style("32MB").bold());
            println!("  Pool Size: {}", style("5").bold());
            println!();
            println!("Encryption:");
            println!("  Algorithm: {}", style("AEGIS-256").bold().green());
            println!("  Key Rotation: {}", style("23 hours").bold());
            println!("  Master Key Rotation: {}", style("90 days").bold());
            println!();
            println!("Features:");
            println!("  ✓ Development optimized");
            println!("  ✓ Fast startup");
            println!("  ✓ Minimal resource usage");
        }
        "enterprise" => {
            println!("{}", style("Enterprise Template").bold().yellow());
            println!("Production-ready with enhanced security and monitoring");
            println!();
            println!("Database Configuration:");
            println!("  Max Size: {}", style("10GB").bold());
            println!("  Cache Size: {}", style("256MB").bold());
            println!("  Pool Size: {}", style("20").bold());
            println!();
            println!("Encryption:");
            println!("  Algorithm: {}", style("AES-256-GCM").bold().green());
            println!("  Key Rotation: {}", style("7 days").bold());
            println!("  Master Key Rotation: {}", style("30 days").bold());
            println!("  Key Derivation: {}", style("Argon2id").bold());
            println!();
            println!("Features:");
            println!("  ✓ Production ready");
            println!("  ✓ Enhanced security");
            println!("  ✓ Monitoring enabled");
            println!("  ✓ WebAssembly support");
            println!("  ✓ Rate limiting");
            println!("  ✓ JWT authentication");
        }
        "custom" => {
            println!("{}", style("Custom Template").bold().yellow());
            println!("Flexible configuration for specific requirements");
            println!();
            println!("Database Configuration:");
            println!("  Max Size: {}", style(config.database.max_size.unwrap_or(1024*1024*1024) / (1024*1024)).bold());
            println!("  Cache Size: {}", style(config.encryption.key_derivation.memory_cost.unwrap_or(64*1024) / 1024).bold());
            println!("  Pool Size: {}", style(config.database.pool_size).bold());
            println!();
            println!("Encryption:");
            println!("  Algorithm: {}", style(config.encryption.default_algorithm).bold().green());
            println!("  Key Rotation: {}", style(config.encryption.key_rotation_interval.as_secs() / 3600).bold());
            println!("  Master Key Rotation: {}", style(config.encryption.master_key_rotation_interval.as_secs() / (24*3600)).bold());
            println!();
            println!("Features:");
            println!("  ✓ Customizable");
            println!("  ✓ Flexible configuration");
        }
        _ => {
            println!("✗ Unknown template: {}", style(template_name).red());
            return;
        }
    }
    
    println!();
    println!("📁 Target Location: {}", style(config.database.path).bold());
    println!("📂 Data Directory: {}", style(config.storage.base_path.as_ref().unwrap_or(&"./data".to_string())).bold());
}

fn list_available_templates() {
    println!("{}", style("Available Templates").bold().cyan());
    println!("{}", "=".repeat(50));
    
    let templates = vec![
        ("startup", "Development and small applications", "🚀"),
        ("enterprise", "Production-ready with enhanced security", "🏢"),
        ("custom", "Flexible configuration for specific needs", "🎨"),
    ];
    
    for (name, description, icon) in templates {
        println!("{} {} {}", style(icon).bold(), style(name).bold().yellow(), style(description).dim());
    }
    
    println!();
    println!("{}", style("Usage:").bold());
    println!("  fortress create --template <name> <database_name>");
    println!("  fortress create --template <name> --dry-run <database_name>");
    println!();
    println!("{}", style("Examples:").bold());
    println!("  fortress create --template startup myapp");
    println!("  fortress create --template enterprise --dry-run production_db");
    println!("  fortress create --template custom --interactive");
}
