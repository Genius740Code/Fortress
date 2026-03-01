//! Performance profiles for Fortress
//!
//! This module provides performance profiles that allow users to optimize Fortress
//! for different use cases - from maximum speed (Lightning) to maximum security (Fortress).
//! Users can also create custom profiles with granular control over various parameters.

use crate::error::{FortressError, Result, ConfigurationErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Performance profile types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PerformanceProfile {
    /// Lightning mode - Maximum speed, minimal security overhead
    Lightning,
    /// Balanced mode - Equal emphasis on performance and security
    Balanced,
    /// Fortress mode - Maximum security, accepting performance trade-offs
    Fortress,
    /// Custom profile with user-defined settings
    Custom,
}

impl fmt::Display for PerformanceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PerformanceProfile::Lightning => write!(f, "Lightning"),
            PerformanceProfile::Balanced => write!(f, "Balanced"),
            PerformanceProfile::Fortress => write!(f, "Fortress"),
            PerformanceProfile::Custom => write!(f, "Custom"),
        }
    }
}

/// Resource allocation limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage in MB
    pub max_memory_mb: u64,
    /// Maximum CPU usage percentage (0-100)
    pub max_cpu_percent: u8,
    /// Maximum concurrent operations
    pub max_concurrent_ops: u32,
    /// Thread pool size
    pub thread_pool_size: u32,
    /// Cache size in MB
    pub cache_size_mb: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 1024,      // 1GB default
            max_cpu_percent: 80,      // 80% CPU usage
            max_concurrent_ops: 100,  // 100 concurrent operations
            thread_pool_size: 4,      // 4 threads
            cache_size_mb: 256,       // 256MB cache
        }
    }
}

/// Encryption performance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionSettings {
    /// Preferred encryption algorithm
    pub algorithm: String,
    /// Key derivation function
    pub kdf: String,
    /// KDF memory cost (for Argon2)
    pub kdf_memory_cost: u32,
    /// KDF iterations
    pub kdf_iterations: u32,
    /// KDF parallelism
    pub kdf_parallelism: u32,
    /// Enable hardware acceleration
    pub hardware_acceleration: bool,
    /// Enable SIMD optimizations
    pub simd_optimizations: bool,
    /// Batch encryption size
    pub batch_size: u32,
}

impl Default for EncryptionSettings {
    fn default() -> Self {
        Self {
            algorithm: "aegis256".to_string(),
            kdf: "argon2id".to_string(),
            kdf_memory_cost: 65536,     // 64 MiB
            kdf_iterations: 3,
            kdf_parallelism: 4,
            hardware_acceleration: true,
            simd_optimizations: true,
            batch_size: 1024,
        }
    }
}

/// Storage performance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Compression algorithm
    pub compression: String,
    /// Compression level (1-9)
    pub compression_level: u8,
    /// Enable write-ahead logging
    pub enable_wal: bool,
    /// Sync mode
    pub sync_mode: SyncMode,
    /// Page size in bytes
    pub page_size: u32,
    /// Cache size in pages
    pub cache_pages: u32,
    /// Enable async writes
    pub async_writes: bool,
    /// Batch write size
    pub batch_write_size: u32,
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self {
            compression: "lz4".to_string(),
            compression_level: 4,
            enable_wal: true,
            sync_mode: SyncMode::Normal,
            page_size: 4096,
            cache_pages: 1024,
            async_writes: true,
            batch_write_size: 100,
        }
    }
}

/// Database sync modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncMode {
    /// No synchronization - fastest but least safe
    Off,
    /// Normal synchronization - balanced
    Normal,
    /// Full synchronization - safest but slowest
    Full,
    /// Extra synchronization - maximum durability
    Extra,
}

/// Network performance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Connection pool size
    pub connection_pool_size: u32,
    /// Enable connection keep-alive
    pub keep_alive: bool,
    /// Enable compression
    pub compression: bool,
    /// Buffer size in bytes
    pub buffer_size: u32,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            connection_timeout_secs: 30,
            request_timeout_secs: 60,
            max_connections: 100,
            connection_pool_size: 10,
            keep_alive: true,
            compression: true,
            buffer_size: 8192,
        }
    }
}

/// Complete performance profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceProfileConfig {
    /// Profile name
    pub name: String,
    /// Profile type
    pub profile_type: PerformanceProfile,
    /// Resource limits
    pub resources: ResourceLimits,
    /// Encryption settings
    pub encryption: EncryptionSettings,
    /// Storage settings
    pub storage: StorageSettings,
    /// Network settings
    pub network: NetworkSettings,
    /// Profile description
    pub description: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl PerformanceProfileConfig {
    /// Create a new custom profile
    pub fn new(name: String) -> Self {
        Self {
            name,
            profile_type: PerformanceProfile::Custom,
            resources: ResourceLimits::default(),
            encryption: EncryptionSettings::default(),
            storage: StorageSettings::default(),
            network: NetworkSettings::default(),
            description: None,
            tags: Vec::new(),
        }
    }

    /// Create a Lightning profile
    pub fn lightning(name: String) -> Self {
        Self {
            name,
            profile_type: PerformanceProfile::Lightning,
            resources: ResourceLimits {
                max_memory_mb: 512,
                max_cpu_percent: 60,
                max_concurrent_ops: 50,
                thread_pool_size: 2,
                cache_size_mb: 128,
            },
            encryption: EncryptionSettings {
                algorithm: "chacha20poly1305".to_string(),
                kdf: "argon2id".to_string(),
                kdf_memory_cost: 16384,  // 16 MiB - lower for speed
                kdf_iterations: 1,       // Lower iterations for speed
                kdf_parallelism: 2,
                hardware_acceleration: true,
                simd_optimizations: true,
                batch_size: 2048,        // Larger batches for throughput
            },
            storage: StorageSettings {
                compression: "none".to_string(),
                compression_level: 1,
                enable_wal: false,       // Disable WAL for speed
                sync_mode: SyncMode::Off,
                page_size: 8192,         // Larger pages
                cache_pages: 512,
                async_writes: true,
                batch_write_size: 200,   // Larger batches
            },
            network: NetworkSettings {
                connection_timeout_secs: 10,
                request_timeout_secs: 30,
                max_connections: 50,
                connection_pool_size: 5,
                keep_alive: true,
                compression: false,       // Disable compression for speed
                buffer_size: 16384,      // Larger buffers
            },
            description: Some("Maximum speed profile optimized for high-throughput scenarios".to_string()),
            tags: vec!["speed".to_string(), "high-throughput".to_string()],
        }
    }

    /// Create a Balanced profile
    pub fn balanced(name: String) -> Self {
        Self {
            name,
            profile_type: PerformanceProfile::Balanced,
            resources: ResourceLimits {
                max_memory_mb: 1024,
                max_cpu_percent: 75,
                max_concurrent_ops: 100,
                thread_pool_size: 4,
                cache_size_mb: 256,
            },
            encryption: EncryptionSettings {
                algorithm: "aegis256".to_string(),
                kdf: "argon2id".to_string(),
                kdf_memory_cost: 65536,  // 64 MiB
                kdf_iterations: 3,
                kdf_parallelism: 4,
                hardware_acceleration: true,
                simd_optimizations: true,
                batch_size: 1024,
            },
            storage: StorageSettings {
                compression: "lz4".to_string(),
                compression_level: 4,
                enable_wal: true,
                sync_mode: SyncMode::Normal,
                page_size: 4096,
                cache_pages: 1024,
                async_writes: true,
                batch_write_size: 100,
            },
            network: NetworkSettings {
                connection_timeout_secs: 30,
                request_timeout_secs: 60,
                max_connections: 100,
                connection_pool_size: 10,
                keep_alive: true,
                compression: true,
                buffer_size: 8192,
            },
            description: Some("Balanced profile providing good performance and security".to_string()),
            tags: vec!["balanced".to_string(), "general-purpose".to_string()],
        }
    }

    /// Create a Fortress profile
    pub fn fortress(name: String) -> Self {
        Self {
            name,
            profile_type: PerformanceProfile::Fortress,
            resources: ResourceLimits {
                max_memory_mb: 2048,
                max_cpu_percent: 90,
                max_concurrent_ops: 200,
                thread_pool_size: 8,
                cache_size_mb: 512,
            },
            encryption: EncryptionSettings {
                algorithm: "aes256gcm".to_string(),
                kdf: "argon2id".to_string(),
                kdf_memory_cost: 262144, // 256 MiB - higher for security
                kdf_iterations: 5,      // Higher iterations for security
                kdf_parallelism: 8,
                hardware_acceleration: true,
                simd_optimizations: true,
                batch_size: 512,         // Smaller batches for security
            },
            storage: StorageSettings {
                compression: "flate2".to_string(),
                compression_level: 9,    // Maximum compression
                enable_wal: true,
                sync_mode: SyncMode::Full,
                page_size: 2048,         // Smaller pages for security
                cache_pages: 2048,
                async_writes: false,     // Synchronous writes for security
                batch_write_size: 50,    // Smaller batches
            },
            network: NetworkSettings {
                connection_timeout_secs: 60,
                request_timeout_secs: 120,
                max_connections: 200,
                connection_pool_size: 20,
                keep_alive: true,
                compression: true,
                buffer_size: 4096,      // Smaller buffers for security
            },
            description: Some("Maximum security profile with comprehensive protection".to_string()),
            tags: vec!["security".to_string(), "high-protection".to_string()],
        }
    }

    /// Validate the profile configuration
    pub fn validate(&self) -> Result<()> {
        // Validate resource limits
        if self.resources.max_memory_mb == 0 {
            return Err(FortressError::configuration(
                "Max memory cannot be zero".to_string(),
                Some("resources.max_memory_mb".to_string()),
                ConfigurationErrorCode::InvalidValue,
            ));
        }

        if self.resources.max_cpu_percent > 100 {
            return Err(FortressError::configuration(
                "Max CPU percentage cannot exceed 100".to_string(),
                Some("resources.max_cpu_percent".to_string()),
                ConfigurationErrorCode::InvalidValue,
            ));
        }

        // Validate encryption settings
        if self.encryption.kdf_memory_cost == 0 {
            return Err(FortressError::configuration(
                "KDF memory cost cannot be zero".to_string(),
                Some("encryption.kdf_memory_cost".to_string()),
                ConfigurationErrorCode::InvalidValue,
            ));
        }

        if self.encryption.kdf_iterations == 0 {
            return Err(FortressError::configuration(
                "KDF iterations cannot be zero".to_string(),
                Some("encryption.kdf_iterations".to_string()),
                ConfigurationErrorCode::InvalidValue,
            ));
        }

        // Validate storage settings
        if self.storage.compression_level > 9 {
            return Err(FortressError::configuration(
                "Compression level cannot exceed 9".to_string(),
                Some("storage.compression_level".to_string()),
                ConfigurationErrorCode::InvalidValue,
            ));
        }

        Ok(())
    }

    /// Get profile summary
    pub fn summary(&self) -> String {
        format!(
            "Profile: {} ({})\n\
             Memory: {}MB, CPU: {}%, Threads: {}\n\
             Algorithm: {}, KDF: {} ({}MB, {} iterations)\n\
             Storage: {} compression, WAL: {}, Sync: {:?}\n\
             Network: {} connections, Compression: {}",
            self.name,
            self.profile_type,
            self.resources.max_memory_mb,
            self.resources.max_cpu_percent,
            self.resources.thread_pool_size,
            self.encryption.algorithm,
            self.encryption.kdf,
            self.encryption.kdf_memory_cost / 1024,
            self.encryption.kdf_iterations,
            self.storage.compression,
            self.storage.enable_wal,
            self.storage.sync_mode,
            self.network.max_connections,
            self.network.compression
        )
    }
}

/// Performance profile manager
#[derive(Debug, Clone)]
pub struct ProfileManager {
    profiles: HashMap<String, PerformanceProfileConfig>,
    default_profile: String,
}

impl ProfileManager {
    /// Create a new profile manager with default profiles
    pub fn new() -> Self {
        let mut manager = Self {
            profiles: HashMap::new(),
            default_profile: "balanced".to_string(),
        };

        // Add default profiles
        let _ = manager.add_profile(PerformanceProfileConfig::lightning("lightning".to_string()));
        let _ = manager.add_profile(PerformanceProfileConfig::balanced("balanced".to_string()));
        let _ = manager.add_profile(PerformanceProfileConfig::fortress("fortress".to_string()));

        manager
    }

    /// Add a profile to the manager
    pub fn add_profile(&mut self, profile: PerformanceProfileConfig) -> Result<()> {
        profile.validate()?;
        self.profiles.insert(profile.name.clone(), profile);
        Ok(())
    }

    /// Get a profile by name
    pub fn get_profile(&self, name: &str) -> Option<&PerformanceProfileConfig> {
        self.profiles.get(name)
    }

    /// List all available profiles
    pub fn list_profiles(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }

    /// Set the default profile
    pub fn set_default_profile(&mut self, name: &str) -> Result<()> {
        if !self.profiles.contains_key(name) {
            return Err(FortressError::configuration(
                format!("Profile '{}' not found", name),
                None,
                ConfigurationErrorCode::InvalidValue,
            ));
        }
        self.default_profile = name.to_string();
        Ok(())
    }

    /// Get the default profile
    pub fn get_default_profile(&self) -> Option<&PerformanceProfileConfig> {
        self.profiles.get(&self.default_profile)
    }

    /// Remove a profile
    pub fn remove_profile(&mut self, name: &str) -> Result<()> {
        if name == self.default_profile {
            return Err(FortressError::configuration(
                "Cannot remove the default profile".to_string(),
                None,
                ConfigurationErrorCode::InvalidValue,
            ));
        }
        
        if !self.profiles.contains_key(name) {
            return Err(FortressError::configuration(
                format!("Profile '{}' not found", name),
                None,
                ConfigurationErrorCode::InvalidValue,
            ));
        }

        self.profiles.remove(name);
        Ok(())
    }

    /// Find profiles by tags
    pub fn find_profiles_by_tag(&self, tag: &str) -> Vec<&PerformanceProfileConfig> {
        self.profiles
            .values()
            .filter(|profile| profile.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Auto-optimize profile based on system capabilities
    pub fn auto_optimize(&mut self, system_info: &SystemInfo) -> Result<String> {
        let profile_name = if system_info.total_memory_gb >= 16 && system_info.cpu_cores >= 8 {
            // High-end system - use Fortress
            "fortress"
        } else if system_info.total_memory_gb >= 8 && system_info.cpu_cores >= 4 {
            // Mid-range system - use Balanced
            "balanced"
        } else {
            // Low-end system - use Lightning
            "lightning"
        };

        self.set_default_profile(profile_name)?;
        Ok(profile_name.to_string())
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

/// System information for auto-optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Total memory in GB
    pub total_memory_gb: u64,
    /// Available memory in GB
    pub available_memory_gb: u64,
    /// CPU cores
    pub cpu_cores: u32,
    /// CPU architecture
    pub cpu_arch: String,
    /// Available disk space in GB
    pub available_disk_gb: u64,
    /// Network bandwidth in Mbps
    pub network_bandwidth_mbps: Option<u64>,
}

impl SystemInfo {
    /// Detect system information (simplified implementation)
    pub fn detect() -> Self {
        // This is a simplified implementation
        // In a real scenario, you'd use system APIs to get actual values
        Self {
            total_memory_gb: 8,      // Default to 8GB
            available_memory_gb: 4,   // Default to 4GB available
            cpu_cores: 4,             // Default to 4 cores
            cpu_arch: "x86_64".to_string(),
            available_disk_gb: 100,   // Default to 100GB
            network_bandwidth_mbps: Some(1000), // Default to 1Gbps
        }
    }

    /// Get system capabilities
    pub fn capabilities(&self) -> SystemCapabilities {
        SystemCapabilities {
            supports_hardware_acceleration: self.cpu_arch.contains("x86_64") || self.cpu_arch.contains("aarch64"),
            supports_simd: self.cpu_arch.contains("x86_64") || self.cpu_arch.contains("aarch64"),
            high_memory: self.total_memory_gb >= 16,
            multi_core: self.cpu_cores >= 4,
            fast_storage: self.available_disk_gb >= 50,
            fast_network: self.network_bandwidth_mbps.unwrap_or(0) >= 1000,
        }
    }
}

/// System capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCapabilities {
    /// Supports hardware acceleration
    pub supports_hardware_acceleration: bool,
    /// Supports SIMD optimizations
    pub supports_simd: bool,
    /// Has high memory
    pub high_memory: bool,
    /// Has multiple cores
    pub multi_core: bool,
    /// Has fast storage
    pub fast_storage: bool,
    /// Has fast network
    pub fast_network: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lightning_profile() {
        let profile = PerformanceProfileConfig::lightning("test".to_string());
        assert_eq!(profile.profile_type, PerformanceProfile::Lightning);
        assert_eq!(profile.encryption.algorithm, "chacha20poly1305");
        assert_eq!(profile.storage.compression, "none");
        assert!(!profile.storage.enable_wal);
        assert_eq!(profile.storage.sync_mode, SyncMode::Off);
    }

    #[test]
    fn test_balanced_profile() {
        let profile = PerformanceProfileConfig::balanced("test".to_string());
        assert_eq!(profile.profile_type, PerformanceProfile::Balanced);
        assert_eq!(profile.encryption.algorithm, "aegis256");
        assert_eq!(profile.storage.compression, "lz4");
        assert!(profile.storage.enable_wal);
        assert_eq!(profile.storage.sync_mode, SyncMode::Normal);
    }

    #[test]
    fn test_fortress_profile() {
        let profile = PerformanceProfileConfig::fortress("test".to_string());
        assert_eq!(profile.profile_type, PerformanceProfile::Fortress);
        assert_eq!(profile.encryption.algorithm, "aes256gcm");
        assert_eq!(profile.storage.compression, "flate2");
        assert!(profile.storage.enable_wal);
        assert_eq!(profile.storage.sync_mode, SyncMode::Full);
    }

    #[test]
    fn test_profile_validation() {
        let mut profile = PerformanceProfileConfig::new("test".to_string());
        
        // Valid profile should pass
        assert!(profile.validate().is_ok());

        // Invalid CPU percentage should fail
        profile.resources.max_cpu_percent = 150;
        assert!(profile.validate().is_err());

        // Reset and test invalid memory
        profile.resources.max_cpu_percent = 80;
        profile.resources.max_memory_mb = 0;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn test_profile_manager() {
        let mut manager = ProfileManager::new();
        
        // Should have default profiles
        assert!(manager.get_profile("lightning").is_some());
        assert!(manager.get_profile("balanced").is_some());
        assert!(manager.get_profile("fortress").is_some());

        // Default should be balanced
        assert_eq!(manager.get_default_profile().unwrap().profile_type, PerformanceProfile::Balanced);

        // Can set new default
        manager.set_default_profile("lightning").unwrap();
        assert_eq!(manager.get_default_profile().unwrap().profile_type, PerformanceProfile::Lightning);

        // Can add custom profile
        let custom = PerformanceProfileConfig::new("custom".to_string());
        manager.add_profile(custom).unwrap();
        assert!(manager.get_profile("custom").is_some());

        // Can remove non-default profile
        manager.remove_profile("custom").unwrap();
        assert!(manager.get_profile("custom").is_none());

        // Cannot remove default profile
        assert!(manager.remove_profile("lightning").is_err());
    }

    #[test]
    fn test_auto_optimization() {
        let mut manager = ProfileManager::new();
        
        // High-end system
        let high_end = SystemInfo {
            total_memory_gb: 32,
            available_memory_gb: 16,
            cpu_cores: 16,
            cpu_arch: "x86_64".to_string(),
            available_disk_gb: 500,
            network_bandwidth_mbps: Some(10000),
        };
        
        let profile = manager.auto_optimize(&high_end).unwrap();
        assert_eq!(profile, "fortress");

        // Low-end system
        let low_end = SystemInfo {
            total_memory_gb: 4,
            available_memory_gb: 2,
            cpu_cores: 2,
            cpu_arch: "x86_64".to_string(),
            available_disk_gb: 50,
            network_bandwidth_mbps: Some(100),
        };
        
        let profile = manager.auto_optimize(&low_end).unwrap();
        assert_eq!(profile, "lightning");
    }

    #[test]
    fn test_profile_summary() {
        let profile = PerformanceProfileConfig::balanced("test".to_string());
        let summary = profile.summary();
        assert!(summary.contains("test"));
        assert!(summary.contains("Balanced"));
        assert!(summary.contains("aegis256"));
    }
}
