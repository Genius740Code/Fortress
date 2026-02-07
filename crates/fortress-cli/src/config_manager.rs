use color_eyre::eyre::{Result, Context};
use std::path::PathBuf;
use fortress_core::Config;

pub struct ConfigManager {
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }
    
    pub async fn load(&self) -> Result<Config> {
        if !self.config_path.exists() {
            return Err(color_eyre::eyre::eyre!(
                "Configuration file not found: {}",
                self.config_path.display()
            ));
        }
        
        let config_content = tokio::fs::read_to_string(&self.config_path)
            .await
            .with_context(|| format!("Failed to read config file: {}", self.config_path.display()))?;
        
        let config: Config = toml::from_str(&config_content)
            .with_context(|| "Failed to parse configuration")?;
        
        Ok(config)
    }
    
    pub async fn save(&self, config: &Config) -> Result<()> {
        let config_toml = toml::to_string_pretty(config)
            .with_context(|| "Failed to serialize configuration")?;
        
        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }
        
        tokio::fs::write(&self.config_path, config_toml)
            .await
            .with_context(|| format!("Failed to write config file: {}", self.config_path.display()))?;
        
        Ok(())
    }
    
    pub fn path(&self) -> &PathBuf {
        &self.config_path
    }
}
