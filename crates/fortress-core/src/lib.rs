//! # Fortress Core
//!
//! Core library for Fortress secure database system.
//!
//! This library provides the fundamental building blocks for encrypted data storage:
//!
//! - **Encryption Abstractions**: Traits and implementations for various encryption algorithms
//! - **Key Management**: Secure key generation, rotation, and storage
//! - **Error Handling**: Comprehensive error types for security operations
//! - **Utilities**: Helper functions for cryptographic operations
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use fortress_core::{
//!     encryption::{Aegis256, EncryptionAlgorithm},
//!     key::KeyManager,
//! };
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let algorithm = Aegis256::new();
//! let key_manager = KeyManager::new();
//! let key = key_manager.generate_key(&algorithm)?;
//!
//! let plaintext = b"Hello, Fortress!";
//! let ciphertext = algorithm.encrypt(plaintext, &key)?;
//! let decrypted = algorithm.decrypt(&ciphertext, &key)?;
//!
//! assert_eq!(plaintext, decrypted);
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![allow(clippy::module_name_repetitions)]

/// Core error types
pub mod error;

/// Encryption algorithms and abstractions
pub mod encryption;

/// Key management and rotation
pub mod key;

/// Storage backend abstractions
pub mod storage;

/// Query engine and execution
pub mod query;

/// Configuration management
pub mod config;

/// Utility functions and helpers
pub mod utils;

/// Performance benchmarking suite
pub mod benchmark;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::error::{FortressError, Result};
    pub use crate::encryption::{
        EncryptionAlgorithm, EncryptionProfile, Aegis256, ChaCha20Poly1305, Aes256Gcm,
    };
    pub use crate::key::{KeyManager, KeyId, KeyMetadata};
    pub use crate::storage::StorageBackend;
    pub use crate::config::Config;
    pub use crate::benchmark::{AegisBenchmark, BenchmarkResults};
}

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
