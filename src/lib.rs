//! # Fortress
//!
//! A highly customizable, secure database system with multi-layer encryption.
//!
//! This is the main Fortress meta-package. The actual functionality is provided
//! by the individual crates:
//! - `fortress-core` - Core library
//! - `fortress-cli` - Command-line interface
//! - `fortress-server` - Server components
//!
//! ## Quick Start
//!
//! Add the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! fortress-core = "0.1.0"
//! ```
//!
//! Then use the core library directly:
//!
//! ```rust,no_run
//! use fortress_core::{Fortress, Config};
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

/// Fortress version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fortress build information
pub mod build {
    /// Build timestamp
    pub const TIMESTAMP: &str = "unknown";

    /// Git commit SHA
    pub const GIT_SHA: &str = "unknown";

    /// Rust version
    pub const RUST_VERSION: &str = "unknown";

    /// Target triple
    pub const TARGET: &str = "unknown";
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
