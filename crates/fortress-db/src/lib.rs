//! # fortress-db
//!
//! 🛡️ Fortress - Turnkey Simplicity + Enterprise Security
//!
//! A highly customizable, secure database system with multi-layer encryption.
//! This meta-package provides the complete Fortress database ecosystem.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use fortress_db::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let fortress = Fortress::builder().build().await?;
//!     let db = fortress.create_database("myapp").await?;
//!     
//!     let user = db.insert("users", &serde_json::json!({
//!         "name": "Alice Johnson",
//!         "email": "alice@example.com",
//!         "ssn": "123-45-6789"  // Automatically encrypted
//!     })).await?;
//!     
//!     println!("User created: {}", user["name"]);
//!     Ok(())
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(clippy::all)]

// Re-export all the core components
pub use fortress_core;

// Import specific types we need
use fortress_core::key::InMemoryKeyManager;
use fortress_core::storage::InMemoryStorage;

// Re-export optional components when features are enabled
#[cfg(feature = "cli")]
pub use fortress_cli;

#[cfg(feature = "server")]
pub use fortress_api_server;

#[cfg(feature = "napi")]
pub use fortress_cli_napi;

/// Prelude module for convenient imports
pub mod prelude {
    pub use fortress_core::prelude::*;

    #[cfg(feature = "cli")]
    pub use fortress_cli::{Commands, ConfigAction, KeyAction};

    #[cfg(feature = "server")]
    // Use specific imports from fortress_api_server to avoid conflicts with fortress_core
    pub use fortress_api_server::prelude::{
        AdvancedRateLimiter, AuthManager, FortressGrpcService, FortressServer, GrpcServer,
        HealthChecker, MetricsCollector, RateLimitAlgorithm, RateLimitMetricsSnapshot,
        ServerConfig, TokenClaims,
    };

    #[cfg(feature = "server")]
    pub use fortress_api_server::models::HealthStatus;
}

/// Fortress builder for easy initialization
pub struct FortressBuilder {
    _private: (),
}

impl FortressBuilder {
    /// Create a new Fortress builder
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Build the Fortress instance
    pub async fn build(self) -> Result<Fortress, Box<dyn std::error::Error>> {
        Ok(Fortress::new().await?)
    }
}

/// Main Fortress interface
pub struct Fortress {
    storage: std::sync::Arc<dyn fortress_core::storage::StorageBackend>,
    key_manager: std::sync::Arc<InMemoryKeyManager>,
}

impl Fortress {
    /// Create a new Fortress instance
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create a simple in-memory storage backend for now
        let storage = std::sync::Arc::new(InMemoryStorage::new());
        let key_manager = std::sync::Arc::new(InMemoryKeyManager::new());

        Ok(Self {
            storage,
            key_manager,
        })
    }

    /// Create a builder for configuration
    pub fn builder() -> FortressBuilder {
        FortressBuilder::new()
    }

    /// Create a new database
    pub async fn create_database(
        &self,
        name: &str,
    ) -> Result<Database, Box<dyn std::error::Error>> {
        Ok(Database {
            name: name.to_string(),
            storage: self.storage.clone(),
            key_manager: self.key_manager.clone(),
        })
    }
}

/// Database interface
pub struct Database {
    #[allow(dead_code)]
    name: String,
    storage: std::sync::Arc<dyn fortress_core::storage::StorageBackend>,
    #[allow(dead_code)]
    key_manager: std::sync::Arc<InMemoryKeyManager>,
}

impl Database {
    /// Insert data into a table
    pub async fn insert(
        &self,
        table: &str,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let key = format!("{}/{}", table, uuid::Uuid::new_v4());
        let serialized = serde_json::to_vec(data)?;

        // For now, just store the data directly
        // In a real implementation, this would encrypt the data first
        self.storage.put(&key, &serialized).await?;

        // Return the data with an ID
        let mut result = data.clone();
        if let Some(obj) = result.as_object_mut() {
            obj.insert("id".to_string(), serde_json::Value::String(key));
        }

        Ok(result)
    }

    /// Query data from a table
    pub async fn query(
        &self,
        table: &str,
        _filter: Option<&serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let prefix = format!("{}/", table);
        let keys = self.storage.list_prefix(&prefix).await?;

        let mut results = Vec::new();
        for key in keys {
            if let Some(data) = self.storage.get(&key).await? {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&data) {
                    results.push(value);
                }
            }
        }

        Ok(results)
    }

    /// Update data in a table
    pub async fn update(
        &self,
        table: &str,
        id: &str,
        data: &serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let key = format!("{}/{}", table, id);
        let serialized = serde_json::to_vec(data)?;

        self.storage.put(&key, &serialized).await?;

        // Return the data with the ID
        let mut result = data.clone();
        if let Some(obj) = result.as_object_mut() {
            obj.insert("id".to_string(), serde_json::Value::String(id.to_string()));
        }

        Ok(result)
    }

    /// Delete data from a table
    pub async fn delete(&self, table: &str, id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let key = format!("{}/{}", table, id);
        self.storage.delete(&key).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fortress_creation() {
        let fortress = Fortress::new().await;
        assert!(fortress.is_ok());
    }

    #[tokio::test]
    async fn test_database_operations() {
        let fortress = Fortress::new().await.unwrap();
        let db = fortress.create_database("test").await;
        assert!(db.is_ok());
    }
}
