//! Algorithm Registry for Fortress
//!
//! This module provides a centralized registry for encryption algorithms,
//! making it extremely easy to add new algorithms and manage them efficiently.

use crate::error::Result;
use crate::encryption::{EncryptionAlgorithm, create_algorithm};
use std::collections::HashMap;
use std::sync::Arc;

/// Algorithm metadata for registry
#[derive(Debug, Clone)]
pub struct AlgorithmMetadata {
    /// Algorithm name
    pub name: String,
    /// Display name
    pub display_name: String,
    /// Description
    pub description: String,
    /// Security level in bits
    pub security_level: usize,
    /// Key size in bytes
    pub key_size: usize,
    /// Nonce/IV size in bytes
    pub nonce_size: usize,
    /// Tag size in bytes
    pub tag_size: usize,
    /// Whether it's an AEAD algorithm
    pub is_aead: bool,
    /// Year introduced/standardized
    pub year: u32,
    /// Algorithm family
    pub family: String,
    /// Recommended use cases
    pub use_cases: Vec<String>,
    /// Performance characteristics
    pub performance_notes: String,
}

/// Algorithm registry for easy management and discovery
pub struct AlgorithmRegistry {
    algorithms: HashMap<String, Arc<dyn EncryptionAlgorithm>>,
    metadata: HashMap<String, AlgorithmMetadata>,
}

impl AlgorithmRegistry {
    /// Create a new algorithm registry with all available algorithms
    pub fn new() -> Result<Self> {
        let mut registry = Self {
            algorithms: HashMap::new(),
            metadata: HashMap::new(),
        };

        // Register all available algorithms
        registry.register_all_algorithms()?;
        
        Ok(registry)
    }

    /// Register all available algorithms
    fn register_all_algorithms(&mut self) -> Result<()> {
        let algorithm_configs = vec![
            // Existing algorithms
            ("chacha20poly1305", "ChaCha20-Poly1305", 
             "Balanced performance and security", 256, 32, 12, 16, true, 2015,
             "ChaCha20", vec!["general-purpose".to_string(), "mobile".to_string(), "balanced".to_string()], 
             "Excellent performance on all platforms"),
            
            ("xchacha20poly1305", "XChaCha20-Poly1305", 
             "Extended nonce size for better security", 256, 32, 24, 16, true, 2018,
             "ChaCha20", vec!["high-security".to_string(), "nonce-critical".to_string(), "balanced".to_string()], 
             "192-bit nonce prevents reuse attacks"),
            
            ("aes256gcm", "AES-256-GCM", 
             "Industry standard with hardware acceleration", 256, 32, 12, 16, true, 2001,
             "AES", vec!["enterprise".to_string(), "hardware-accelerated".to_string(), "compliance".to_string()], 
             "Hardware acceleration available on most CPUs"),
            
            // Previously added algorithms
            ("blake3encrypt", "Blake3 Encrypt", 
             "Modern hash-based encryption with SIMD", 256, 32, 16, 32, true, 2020,
             "Blake3", vec!["high-performance".to_string(), "streaming".to_string(), "hardware-optimized".to_string()], 
             "SIMD optimized, excellent parallel performance"),
            
            ("hmacsha512encrypt", "HMAC-SHA512 Encrypt", 
             "High security with 512-bit protection", 512, 64, 32, 64, true, 2008,
             "SHA-2", vec!["maximum-security".to_string(), "long-term".to_string(), "compliance".to_string()], 
             "512-bit security level for future-proofing"),
            
            // Newly added algorithms
            ("aes256ctr", "AES-256-CTR", 
             "Fast streaming encryption mode", 256, 32, 16, 0, false, 2000,
             "AES", vec!["streaming".to_string(), "high-throughput".to_string(), "large-files".to_string()], 
             "Counter mode, ideal for streaming large data"),
            
            ("argon2idencrypt", "Argon2id Encrypt", 
             "Memory-hard key derivation with encryption", 256, 32, 16, 16, true, 2019,
             "Argon2", vec!["password-based".to_string(), "brute-force-resistant".to_string(), "key-derivation".to_string()], 
             "Memory-hard algorithm resistant to GPU attacks"),
            
            ("compositeencrypt", "Composite Encrypt", 
             "Multiple algorithms for maximum security", 512, 32, 56, 32, true, 2024,
             "Composite", vec!["maximum-security".to_string(), "quantum-resistant".to_string(), "defense-in-depth".to_string()], 
             "Combines Blake3, XChaCha20, and HMAC-SHA256"),
        ];

        for (name, display_name, description, security_level, key_size, nonce_size, 
             tag_size, is_aead, year, family, use_cases, performance_notes) in algorithm_configs {
            let algorithm = create_algorithm(name)?;
            let metadata = AlgorithmMetadata {
                name: name.to_string(),
                display_name: display_name.to_string(),
                description: description.to_string(),
                security_level,
                key_size,
                nonce_size,
                tag_size,
                is_aead,
                year,
                family: family.to_string(),
                use_cases,
                performance_notes: performance_notes.to_string(),
            };
            
            self.algorithms.insert(name.to_string(), Arc::from(algorithm));
            self.metadata.insert(name.to_string(), metadata);
        }

        Ok(())
    }

    /// Get an algorithm by name
    pub fn get_algorithm(&self, name: &str) -> Option<Arc<dyn EncryptionAlgorithm>> {
        self.algorithms.get(name).cloned()
    }

    /// Get algorithm metadata
    pub fn get_metadata(&self, name: &str) -> Option<&AlgorithmMetadata> {
        self.metadata.get(name)
    }

    /// List all available algorithms
    pub fn list_algorithms(&self) -> Vec<&str> {
        self.algorithms.keys().map(|s| s.as_str()).collect()
    }

    /// List algorithms by family
    pub fn list_by_family(&self, family: &str) -> Vec<&str> {
        self.algorithms.keys()
            .filter(|name| {
                self.metadata.get(*name)
                    .map(|meta| meta.family == family)
                    .unwrap_or(false)
            })
            .map(|s| s.as_str())
            .collect()
    }

    /// Find algorithms by security level
    pub fn find_by_security_level(&self, min_security: usize) -> Vec<&str> {
        self.algorithms.keys()
            .filter(|name| {
                self.metadata.get(*name)
                    .map(|meta| meta.security_level >= min_security)
                    .unwrap_or(false)
            })
            .map(|s| s.as_str())
            .collect()
    }

    /// Find algorithms by use case
    pub fn find_by_use_case(&self, use_case: &str) -> Vec<&str> {
        self.algorithms.keys()
            .filter(|name| {
                self.metadata.get(*name)
                    .map(|meta| meta.use_cases.contains(&use_case.to_string()))
                    .unwrap_or(false)
            })
            .map(|s| s.as_str())
            .collect()
    }

    /// Get recommended algorithm for specific requirements
    pub fn recommend(&self, requirements: &AlgorithmRequirements) -> Option<&str> {
        let candidates: Vec<&str> = self.algorithms.keys()
            .filter(|name| {
                if let Some(meta) = self.metadata.get(*name) {
                    meta.security_level >= requirements.min_security_level
                        && meta.is_aead == requirements.require_aead.unwrap_or(true)
                        && meta.key_size <= requirements.max_key_size.unwrap_or(usize::MAX)
                        && (requirements.use_cases.is_empty() || 
                            requirements.use_cases.iter().any(|uc| meta.use_cases.contains(uc)))
                } else {
                    false
                }
            })
            .map(|s| s.as_str())
            .collect();

        // Select the best candidate based on security level and performance
        candidates.into_iter()
            .max_by_key(|name| {
                let meta = self.metadata.get(*name).unwrap();
                (meta.security_level, meta.year) // Prefer newer, more secure algorithms
            })
    }

    /// Get algorithm statistics
    pub fn statistics(&self) -> AlgorithmStatistics {
        let total_algorithms = self.algorithms.len();
        let families: std::collections::HashSet<_> = self.metadata.values()
            .map(|meta| meta.family.clone())
            .collect();
        let total_families = families.len();
        
        let aead_count = self.metadata.values()
            .filter(|meta| meta.is_aead)
            .count();
        
        let avg_security = self.metadata.values()
            .map(|meta| meta.security_level)
            .sum::<usize>() as f64 / total_algorithms as f64;

        AlgorithmStatistics {
            total_algorithms,
            total_families,
            aead_count,
            average_security_level: avg_security,
            newest_year: self.metadata.values().map(|meta| meta.year).max().unwrap_or(0),
            oldest_year: self.metadata.values().map(|meta| meta.year).min().unwrap_or(0),
        }
    }
}

/// Requirements for algorithm recommendation
#[derive(Debug, Default)]
pub struct AlgorithmRequirements {
    /// Minimum security level in bits
    pub min_security_level: usize,
    /// Maximum key size in bytes
    pub max_key_size: Option<usize>,
    /// Whether AEAD is required
    pub require_aead: Option<bool>,
    /// Required use cases
    pub use_cases: Vec<String>,
}

/// Algorithm statistics
#[derive(Debug)]
pub struct AlgorithmStatistics {
    /// Total number of algorithms registered
    pub total_algorithms: usize,
    /// Total number of algorithm families
    pub total_families: usize,
    /// Number of AEAD algorithms
    pub aead_count: usize,
    /// Average security level (1-10 scale)
    pub average_security_level: f64,
    /// Newest algorithm year
    pub newest_year: u32,
    /// Oldest algorithm year
    pub oldest_year: u32,
}

impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_registry() {
        let registry = AlgorithmRegistry::new().unwrap();
        
        // Test listing algorithms
        let algorithms = registry.list_algorithms();
        assert!(!algorithms.is_empty());
        assert!(algorithms.contains(&"chacha20poly1305"));
        assert!(algorithms.contains(&"aes256ctr"));
        assert!(algorithms.contains(&"compositeencrypt"));
        
        // Test getting algorithm
        let algorithm = registry.get_algorithm("xchacha20poly1305").unwrap();
        assert_eq!(algorithm.name(), "xchacha20poly1305");
        
        // Test metadata
        let metadata = registry.get_metadata("blake3encrypt").unwrap();
        assert_eq!(metadata.display_name, "Blake3 Encrypt");
        assert_eq!(metadata.security_level, 256);
        assert!(metadata.use_cases.contains(&"high-performance".to_string()));
    }

    #[test]
    fn test_algorithm_families() {
        let registry = AlgorithmRegistry::new().unwrap();
        
        let aes_algorithms = registry.list_by_family("AES");
        assert!(!aes_algorithms.is_empty());
        assert!(aes_algorithms.contains(&"aes256gcm"));
        assert!(aes_algorithms.contains(&"aes256ctr"));
        
        let chacha_algorithms = registry.list_by_family("ChaCha20");
        assert!(!chacha_algorithms.is_empty());
        assert!(chacha_algorithms.contains(&"chacha20poly1305"));
        assert!(chacha_algorithms.contains(&"xchacha20poly1305"));
    }

    #[test]
    fn test_algorithm_recommendation() {
        let registry = AlgorithmRegistry::new().unwrap();
        
        let requirements = AlgorithmRequirements {
            min_security_level: 256,
            require_aead: Some(true),
            use_cases: vec!["maximum-security".to_string()],
            ..Default::default()
        };
        
        let recommended = registry.recommend(&requirements);
        assert!(recommended.is_some());
        
        // Should recommend a high-security algorithm
        let rec_name = recommended.unwrap();
        let metadata = registry.get_metadata(rec_name).unwrap();
        assert!(metadata.security_level >= 256);
        assert!(metadata.is_aead);
    }

    #[test]
    fn test_algorithm_statistics() {
        let registry = AlgorithmRegistry::new().unwrap();
        let stats = registry.statistics();
        
        assert!(stats.total_algorithms >= 8); // At least our algorithms
        assert!(stats.total_families >= 3); // AES, ChaCha20, etc.
        assert!(stats.aead_count > 0);
        assert!(stats.average_security_level > 0.0);
        assert!(stats.newest_year >= 2024); // Our composite algorithm
        assert!(stats.oldest_year <= 2000); // AES is from 2000/2001
    }
}
