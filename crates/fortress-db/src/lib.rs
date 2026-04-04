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

// Re-export optional components when features are enabled
#[cfg(feature = "cli")]
pub use fortress_cli;

#[cfg(feature = "server")]  
pub use fortress_server;

#[cfg(feature = "napi")]
pub use fortress_cli_napi;

/// Prelude module for convenient imports
pub mod prelude {
    pub use fortress_core::prelude::*;
    
    #[cfg(feature = "cli")]
    pub use fortress_cli::prelude::*;
    
    #[cfg(feature = "server")]
    pub use fortress_server::prelude::*;
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
    core: fortress_core::Fortress,
}

impl Fortress {
    /// Create a new Fortress instance
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let core = fortress_core::Fortress::builder().build().await?;
        Ok(Self { core })
    }
    
    /// Create a builder for configuration
    pub fn builder() -> FortressBuilder {
        FortressBuilder::new()
    }
    
    /// Create a new database
    pub async fn create_database(&self, name: &str) -> Result<Database, Box<dyn std::error::Error>> {
        let db = self.core.create_database(name).await?;
        Ok(Database { inner: db })
    }
}

/// Database interface
pub struct Database {
    inner: fortress_core::Database,
}

impl Database {
    /// Insert data into a table
    pub async fn insert(&self, table: &str, data: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let result = self.inner.insert(table, data).await?;
        Ok(result)
    }
    
    /// Query data from a table
    pub async fn query(&self, table: &str, filter: Option<&serde_json::Value>) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let results = self.inner.query(table, filter).await?;
        Ok(results)
    }
    
    /// Update data in a table
    pub async fn update(&self, table: &str, id: &str, data: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let result = self.inner.update(table, id, data).await?;
        Ok(result)
    }
    
    /// Delete data from a table
    pub async fn delete(&self, table: &str, id: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let deleted = self.inner.delete(table, id).await?;
        Ok(deleted)
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
