//! # Fortress
//!
//! A highly customizable, secure database system with multi-layer encryption.
//!
//! ## Features
//!
//! - Multi-layer encryption (field, row, table, database level)
//! - Multiple encryption algorithms (AEGIS-256, ChaCha20-Poly1305, AES-256-GCM)
//! - Time-based key rotation
//! - Multiple storage backends (local, AWS S3, Azure, GCP)
//! - Zero-knowledge architecture
//! - High performance with hardware acceleration
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use fortress::{Fortress, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::builder()
//!         .database_path("./mydb")
//!         .default_algorithm("aegis256")
//!         .build()?;
//!
//!     let db = Fortress::connect(config).await?;
//!
//!     // Create table
//!     db.create_table("users", &schema).await?;
//!
//!     // Insert encrypted data
//!     db.insert("users", &user_data).await?;
//!
//!     // Query automatically decrypted data
//!     let results = db.query("SELECT * FROM users").await?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![allow(clippy::module_name_repetitions)]

pub use fortress_core::{
    error::{FortressError, Result},
    Fortress, Config,
    encryption::{EncryptionAlgorithm, EncryptionProfile},
    storage::StorageBackend,
    query::{QueryEngine, QueryResult},
};

/// Re-export commonly used types
pub mod prelude {
    pub use fortress_core::{
        error::{FortressError, Result},
        Fortress, Config,
        encryption::{EncryptionAlgorithm, EncryptionProfile},
        storage::StorageBackend,
        query::{QueryEngine, QueryResult},
    };
}

#[cfg(feature = "cli")]
pub use fortress_cli as cli;

#[cfg(feature = "server")]
pub use fortress_server as server;

#[cfg(feature = "wasm")]
pub use fortress_wasm as wasm;

/// Fortress version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fortress build information
pub mod build {
    /// Build timestamp
    pub const TIMESTAMP: &str = env!("VERGEN_BUILD_TIMESTAMP", "unknown");
    
    /// Git commit SHA
    pub const GIT_SHA: &str = env!("VERGEN_GIT_SHA", "unknown");
    
    /// Rust version
    pub const RUST_VERSION: &str = env!("VERGEN_RUSTC_SEMVER", "unknown");
    
    /// Target triple
    pub const TARGET: &str = env!("VERGEN_CARGO_TARGET_TRIPLE", "unknown");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_build_info() {
        assert!(!build::TIMESTAMP.is_empty());
        assert!(!build::GIT_SHA.is_empty());
        assert!(!build::RUST_VERSION.is_empty());
        assert!(!build::TARGET.is_empty());
    }
}
