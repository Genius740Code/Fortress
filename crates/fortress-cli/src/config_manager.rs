use color_eyre::eyre::Result;
use std::path::PathBuf;
use fortress_core::config::Config;

pub struct ConfigManager {
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }
    
    pub async fn load(&self) -> Result<Config> {
        if !self.config_path.exists() {
            return Err(color_eyre::Report::msg(format!("Configuration file not found: {}", self.config_path.display())));
        }
        
        let config_content = tokio::fs::read_to_string(&self.config_path)
            .await
            .map_err(|e| color_eyre::Report::msg(format!("Failed to read config file: {}", e)))?;
        
        let config: Config = toml::from_str(&config_content)
            .map_err(|e| color_eyre::Report::msg(format!("Failed to parse configuration: {}", e)))?;
        
        Ok(config)
    }
    
    pub async fn save(&self, config: &Config) -> Result<()> {
        let config_toml = toml::to_string_pretty(config)
            .map_err(|e| color_eyre::Report::msg(format!("Failed to serialize configuration: {}", e)))?;
        
        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| color_eyre::Report::msg(format!("Failed to create config directory: {}", e)))?;
        }
        
        tokio::fs::write(&self.config_path, config_toml)
            .await
            .map_err(|e| color_eyre::Report::msg(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    pub fn path(&self) -> &PathBuf {
        &self.config_path
    }
}
