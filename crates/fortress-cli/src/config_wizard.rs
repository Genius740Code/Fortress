use dialoguer::{Select, Confirm, Input, Password};
use console::Term;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Serialize, Deserialize};
use crate::enhanced_error::FortressError;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FortressConfig {
    pub database: DatabaseConfig,
    pub encryption: EncryptionConfig,
    pub networking: NetworkingConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub backend: String,
    pub host: String,
    pub port: u16,
    pub estimated_downtime_secs: u64,
    pub credentials: DatabaseCredentials,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub key_rotation_days: u32,
    pub field_level_encryption: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkingConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub max_connections: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityConfig {
    pub auth_method: String,
    pub session_timeout_minutes: u32,
    pub rate_limiting: bool,
    pub audit_logging: bool,
}

pub struct ConfigurationWizard;

impl ConfigurationWizard {
    pub async fn run_interactive_setup() -> Result<FortressConfig, FortressError> {
        let term = Term::stdout();
        
        term.clear_screen()
            .map_err(|e| FortressError::configuration_error("clear_screen", &format!("{}", e), "terminal operation"))?;
        println!("🛡️  Fortress Configuration Wizard");
        println!("================================");
        println!("This wizard will help you configure Fortress for your environment.\n");
        
        // Welcome message
        if !Confirm::new()
            .with_prompt("Would you like to continue with the interactive setup?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("interactive_setup", &format!("{}", e), "user interaction"))? 
        {
            return Err(FortressError::configuration_error("setup_cancelled", "user_cancelled", "user confirmation"));
        }
        
        let config = FortressConfig {
            database: Self::configure_database().await?,
            encryption: Self::configure_encryption().await?,
            networking: Self::configure_networking().await?,
            security: Self::configure_security().await?,
        };
        
        // Configuration summary
        Self::display_configuration_summary(&config)?;
        
        // Save configuration
        if Confirm::new()
            .with_prompt("Save this configuration?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("save_confirmation", &format!("{}", e), "user confirmation"))? 
        {
            Self::save_configuration(&config).await?;
            println!("✅ Configuration saved successfully!");
        }
        
        Ok(config)
    }
    
    async fn configure_database() -> Result<DatabaseConfig, FortressError> {
        println!("\n📊 Database Configuration");
        println!("--------------------------");
        
        let db_choices = vec!["SQLite (Recommended for development)", 
                              "PostgreSQL (Recommended for production)", 
                              "MySQL", 
                              "MongoDB"];
        let db_selection = Select::new()
            .with_prompt("Select database backend:")
            .items(&db_choices)
            .interact()
            .map_err(|e| FortressError::configuration_error("database_selection", &format!("{}", e), "valid database choice"))?;
        
        let backend = match db_selection {
            0 => "sqlite",
            1 => "postgresql", 
            2 => "mysql",
            3 => "mongodb",
            _ => return Err(FortressError::configuration_error("database_selection", "invalid_choice", "valid database choice")),
        }.to_string();
        
        let (host, port, database_name) = match backend.as_str() {
            "sqlite" => {
                let path = Input::<String>::new()
                    .with_prompt("SQLite database file path")
                    .default("./fortress.db".to_string())
                    .interact()
                    .map_err(|e| FortressError::configuration_error("database_backend", &format!("{}", e), "valid database backend"))?;
                (path, 0, String::new())
            },
            _ => {
                let host = Input::<String>::new()
                    .with_prompt("Database host")
                    .default("localhost".to_string())
                    .interact()
                    .map_err(|e| FortressError::configuration_error("database_host", &format!("{}", e), "valid hostname"))?;
                
                let port = Input::<u16>::new()
                    .with_prompt("Database port")
                    .default(match backend.as_str() {
                        "postgresql" => 5432,
                        "mysql" => 3306,
                        "mongodb" => 27017,
                        _ => 5432,
                    })
                    .interact()
                    .map_err(|e| FortressError::configuration_error("database_port", &format!("{}", e), "number 1-65535"))?;
                
                let database_name = Input::<String>::new()
                    .with_prompt("Database name")
                    .default("fortress".to_string())
                    .interact()
                    .map_err(|e| FortressError::configuration_error("database_name", &format!("{}", e), "valid database name"))?;
                
                (host, port, database_name)
            }
        };
        
        let credentials = if backend != "sqlite" {
            let username = Input::<String>::new()
                .with_prompt("Database username")
                .interact()
                .map_err(|e| FortressError::configuration_error("database_username", &format!("{}", e), "valid username"))?;
            
            let password = Password::new()
                .with_prompt("Database password")
                .allow_empty_password(true)
                .interact()
                .map_err(|e| FortressError::configuration_error("database_password", &format!("{}", e), "valid password"))?;
            
            DatabaseCredentials { username, password }
        } else {
            DatabaseCredentials { username: String::new(), password: String::new() }
        };
        
        Ok(DatabaseConfig {
            backend,
            host,
            port,
            estimated_downtime_secs: 0,
            credentials,
        })
    }
    
    async fn configure_encryption() -> Result<EncryptionConfig, FortressError> {
        println!("\n🔐 Encryption Configuration");
        println!("---------------------------");
        
        let enable_encryption = Confirm::new()
            .with_prompt("Enable field-level encryption?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("encryption_enabled", &format!("{}", e), "boolean value"))?;
        
        let (algorithm, key_rotation_days, field_level_encryption) = if enable_encryption {
            let algo_choices = vec!["AEGIS-256 (Recommended - Highest performance)",
                                   "ChaCha20-Poly1305",
                                   "AES-256-GCM"];
            let algo_selection = Select::new()
                .with_prompt("Select encryption algorithm:")
                .items(&algo_choices)
                .interact()
                .map_err(|e| FortressError::configuration_error("encryption_algorithm", &format!("{}", e), "valid algorithm choice"))?;
            
            let algorithm = match algo_selection {
                0 => "aegis256",
                1 => "chacha20poly1305",
                2 => "aes256gcm",
                _ => "aegis256",
            }.to_string();
            
            let key_rotation_days = Input::<u32>::new()
                .with_prompt("Key rotation interval (days)")
                .default(90)
                .interact()
                .map_err(|e| FortressError::configuration_error("key_rotation_interval", &format!("{}", e), "number in days"))?;
            
            let field_level_encryption = Confirm::new()
                .with_prompt("Enable per-field encryption algorithms?")
                .default(true)
                .interact()
                .map_err(|e| FortressError::configuration_error("field_level_encryption", &format!("{}", e), "boolean value"))?;
            
            (algorithm, key_rotation_days, field_level_encryption)
        } else {
            ("none".to_string(), 0, false)
        };
        
        Ok(EncryptionConfig {
            enabled: enable_encryption,
            algorithm,
            key_rotation_days,
            field_level_encryption,
        })
    }
    
    async fn configure_networking() -> Result<NetworkingConfig, FortressError> {
        println!("\n🌐 Networking Configuration");
        println!("---------------------------");
        
        let bind_address = Input::<String>::new()
            .with_prompt("Bind address")
            .default("0.0.0.0".to_string())
            .interact()
            .map_err(|e| FortressError::configuration_error("bind_address", &format!("{}", e), "valid IP address"))?;
        
        let port = Input::<u16>::new()
            .with_prompt("Port")
            .default(8080)
            .interact()
            .map_err(|e| FortressError::configuration_error("port", &format!("{}", e), "number 1-65535"))?;
        
        let tls_enabled = Confirm::new()
            .with_prompt("Enable TLS/SSL?")
            .default(false)
            .interact()
            .map_err(|e| FortressError::configuration_error("tls_enabled", &format!("{}", e), "boolean value"))?;
        
        let max_connections = Input::<usize>::new()
            .with_prompt("Maximum concurrent connections")
            .default(1000)
            .interact()
            .map_err(|e| FortressError::configuration_error("max_connections", &format!("{}", e), "number > 0"))?;
        
        Ok(NetworkingConfig {
            bind_address,
            port,
            tls_enabled,
            max_connections,
        })
    }
    
    async fn configure_security() -> Result<SecurityConfig, FortressError> {
        println!("\n🛡️  Security Configuration");
        println!("---------------------------");
        
        let auth_choices = vec!["JWT Tokens (Recommended)", "API Keys", "OAuth2", "LDAP"];
        let auth_selection = Select::new()
            .with_prompt("Select authentication method:")
            .items(&auth_choices)
            .interact()
            .map_err(|e| FortressError::configuration_error("auth_method", &format!("{}", e), "valid auth method"))?;
        
        let auth_method = match auth_selection {
            0 => "jwt",
            1 => "api_key",
            2 => "oauth2",
            3 => "ldap",
            _ => "jwt",
        }.to_string();
        
        let session_timeout_minutes = Input::<u32>::new()
            .with_prompt("Session timeout (minutes)")
            .default(60)
            .interact()
            .map_err(|e| FortressError::configuration_error("session_timeout", &format!("{}", e), "number in seconds"))?;
        
        let rate_limiting = Confirm::new()
            .with_prompt("Enable rate limiting?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("rate_limiting", &format!("{}", e), "boolean value"))?;
        
        let audit_logging = Confirm::new()
            .with_prompt("Enable comprehensive audit logging?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("audit_logging", &format!("{}", e), "boolean value"))?;
        
        Ok(SecurityConfig {
            auth_method,
            session_timeout_minutes,
            rate_limiting,
            audit_logging,
        })
    }
    
    fn display_configuration_summary(config: &FortressConfig) -> Result<(), FortressError> {
        println!("\n📋 Configuration Summary");
        println!("========================");
        
        if config.database.backend == "sqlite" {
            println!("Database: {} @ {}", config.database.backend, config.database.host);
        } else {
            println!("Database: {} @ {}:{}/{}", 
                    config.database.backend,
                    config.database.host,
                    config.database.port,
                    "default"); // database_name field doesn't exist
        }
        
        if config.encryption.enabled {
            println!("Encryption: {} (rotation: {} days)", 
                    config.encryption.algorithm, 
                    config.encryption.key_rotation_days);
        } else {
            println!("Encryption: Disabled");
        }
        
        println!("Networking: {}:{}", config.networking.bind_address, config.networking.port);
        if config.networking.tls_enabled {
            println!("TLS: Enabled");
        }
        
        println!("Authentication: {}", config.security.auth_method);
        println!("Session timeout: {} minutes", config.security.session_timeout_minutes);
        println!("Rate limiting: {}", if config.security.rate_limiting { "Enabled" } else { "Disabled" });
        println!("Audit logging: {}", if config.security.audit_logging { "Enabled" } else { "Disabled" });
        
        Ok(())
    }
    
    async fn save_configuration(config: &FortressConfig) -> Result<(), FortressError> {
        let config_path = dirs::config_dir()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
            .join("fortress")
            .join("config.toml");
        
        // Create directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| FortressError::io_error(format!("Failed to create config directory: {}", e)))?;
        }
        
        let config_toml = toml::to_string_pretty(config)
            .map_err(|e| FortressError::configuration_error("serialization", &format!("{}", e), "valid TOML format"))?;
        
        std::fs::write(&config_path, config_toml)
            .map_err(|e| FortressError::configuration_error("file_write", &format!("{}", e), "writable file path"))?;
        
        println!("Configuration saved to: {}", config_path.display());
        Ok(())
    }
    
    pub async fn load_configuration() -> Result<Option<FortressConfig>, FortressError> {
        let config_path = dirs::config_dir()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
            .join("fortress")
            .join("config.toml");
        
        if !config_path.exists() {
            return Ok(None);
        }
        
        let config_content = std::fs::read_to_string(&config_path)
            .map_err(|e| FortressError::configuration_error("file_read", &format!("{}", e), "readable file path"))?;
        
        let config = toml::from_str(&config_content)
            .map_err(|e| FortressError::configuration_error("file_parse", &format!("{}", e), "valid TOML format"))?;
        
        Ok(Some(config))
    }
    
    pub async fn validate_configuration(config: &FortressConfig) -> Result<Vec<String>, FortressError> {
        let mut warnings = Vec::new();
        
        // Validate database configuration
        if config.database.backend != "sqlite" && config.database.host.is_empty() {
            warnings.push("Database host is required for non-SQLite backends".to_string());
        }
        
        if config.database.port == 0 && config.database.backend != "sqlite" {
            warnings.push("Database port is required for non-SQLite backends".to_string());
        }
        
        // Validate encryption configuration
        if config.encryption.enabled && config.encryption.algorithm == "none" {
            warnings.push("Encryption is enabled but no algorithm is specified".to_string());
        }
        
        if config.encryption.key_rotation_days == 0 && config.encryption.enabled {
            warnings.push("Key rotation interval should be greater than 0 days".to_string());
        }
        
        // Validate networking configuration
        if config.networking.port == 0 {
            warnings.push("Network port cannot be 0".to_string());
        }
        
        if config.networking.max_connections == 0 {
            warnings.push("Maximum connections should be greater than 0".to_string());
        }
        
        // Validate security configuration
        if config.security.session_timeout_minutes == 0 {
            warnings.push("Session timeout should be greater than 0 minutes".to_string());
        }
        
        Ok(warnings)
    }
}
