//! Engine registry for managing secret engine instances

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::error::{FortressError, Result, SecretsErrorCode};
use super::base::*;
use super::types::*;

/// Registry for managing secret engine factories
pub struct EngineRegistry {
    factories: Arc<RwLock<HashMap<String, Box<dyn EngineFactory>>>>,
    instances: Arc<RwLock<HashMap<String, Arc<dyn SecretsEngine>>>>,
}

/// Factory trait for creating engine instances
pub trait EngineFactory: Send + Sync {
    /// Create a new engine instance
    fn create_engine(&self, config: &EngineConfig) -> Result<Box<dyn SecretsEngine>>;
    
    /// Get engine name
    fn engine_name(&self) -> &str;
    
    /// Get engine version
    fn engine_version(&self) -> &str;
    
    /// Get default configuration
    fn default_config(&self) -> EngineConfig;
}

impl EngineRegistry {
    /// Create a new engine registry
    pub fn new() -> Self {
        Self {
            factories: Arc::new(RwLock::new(HashMap::new())),
            instances: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register an engine factory
    pub async fn register_factory(&self, factory: Box<dyn EngineFactory>) -> Result<()> {
        let name = factory.engine_name().to_string();
        let mut factories = self.factories.write().await;
        
        if factories.contains_key(&name) {
            return Err(FortressError::engine(format!("Engine '{}' already registered", name), SecretsErrorCode::InvalidConfiguration));
        }
        
        factories.insert(name, factory);
        Ok(())
    }
    
    /// Create an engine instance
    pub async fn create_engine(&self, config: &EngineConfig) -> Result<Arc<dyn SecretsEngine>> {
        let factories = self.factories.read().await;
        let factory = factories.get(&config.name)
            .ok_or_else(|| FortressError::engine(format!("Engine '{}' not found", config.name), SecretsErrorCode::EngineNotFound))?;
        
        let engine = factory.create_engine(config)?;
        Ok(Arc::from(engine))
    }
    
    /// Get an engine instance
    pub async fn get_engine(&self, name: &str) -> Result<Arc<dyn SecretsEngine>> {
        let instances = self.instances.read().await;
        instances.get(name)
            .cloned()
            .ok_or_else(|| FortressError::engine(format!("Engine instance '{}' not found", name), SecretsErrorCode::EngineNotFound))
    }
    
    /// Create and store an engine instance
    pub async fn create_and_store_engine(&self, config: &EngineConfig) -> Result<Arc<dyn SecretsEngine>> {
        let engine = self.create_engine(config).await?;
        
        let mut instances = self.instances.write().await;
        instances.insert(config.name.clone(), engine.clone());
        
        Ok(engine)
    }
    
    /// Create, initialize, and store an engine instance
    pub async fn create_and_initialize_engine(&self, config: &EngineConfig, init_config: &serde_json::Value) -> Result<Arc<dyn SecretsEngine>> {
        let mut engine = self.create_engine(config).await?;
        
        // We need to initialize the engine, but we have an Arc.
        // For now, we'll create a new engine and initialize it before wrapping in Arc.
        let factories = self.factories.read().await;
        let factory = factories.get(&config.name)
            .ok_or_else(|| FortressError::engine(format!("Engine '{}' not found", config.name), SecretsErrorCode::EngineNotFound))?;
        
        let mut raw_engine = factory.create_engine(config)?;
        raw_engine.initialize(init_config).await?;
        let initialized_engine: Arc<dyn SecretsEngine> = Arc::from(raw_engine);
        
        let mut instances = self.instances.write().await;
        instances.insert(config.name.clone(), initialized_engine.clone());
        
        Ok(initialized_engine)
    }
    
    /// List registered engine types
    pub async fn list_engines(&self) -> Vec<String> {
        let factories = self.factories.read().await;
        factories.keys().cloned().collect()
    }
    
    /// List active engine instances
    pub async fn list_instances(&self) -> Vec<String> {
        let instances = self.instances.read().await;
        instances.keys().cloned().collect()
    }
    
    /// Remove an engine instance
    pub async fn remove_engine(&self, name: &str) -> Result<()> {
        let mut instances = self.instances.write().await;
        
        if let Some(engine) = instances.remove(name) {
            // Shutdown the engine
            // Note: This is a simplified approach - in practice, you'd need
            // to handle the Arc reference count properly
            drop(engine);
        }
        
        Ok(())
    }
    
    /// Shutdown all engines
    pub async fn shutdown_all(&self) -> Result<()> {
        let mut instances = self.instances.write().await;
        
        for (name, engine) in instances.drain() {
            // Note: This is simplified - proper shutdown would require
            // handling Arc reference counts and ensuring no active operations
            tracing::info!("Shutting down engine: {}", name);
        }
        
        Ok(())
    }
}

impl Default for EngineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to register an engine factory
#[macro_export]
macro_rules! register_engine {
    ($registry:expr, $engine_type:ty, $config:expr) => {
        $registry.register_factory(Box::new($crate::engines::registry::EngineFactoryImpl::<$engine_type>::new())).await
    };
}

/// Generic engine factory implementation
pub struct EngineFactoryImpl<T: SecretsEngine + Default + 'static> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: SecretsEngine + Default + 'static> EngineFactoryImpl<T> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: SecretsEngine + Default + 'static> EngineFactory for EngineFactoryImpl<T> {
    fn create_engine(&self, config: &EngineConfig) -> Result<Box<dyn SecretsEngine>> {
        let mut engine = T::default();
        // Initialize would need to be called separately
        Ok(Box::new(engine))
    }
    
    fn engine_name(&self) -> &str {
        std::any::type_name::<T>().split("::").last().unwrap_or("unknown")
    }
    
    fn engine_version(&self) -> &str {
        "1.0.0"
    }
    
    fn default_config(&self) -> EngineConfig {
        EngineConfig {
            name: self.engine_name().to_string(),
            version: self.engine_version().to_string(),
            enabled: true,
            mount_path: format!("{}/", self.engine_name().to_lowercase()),
            description: None,
            config: serde_json::Value::Null,
        }
    }
}
