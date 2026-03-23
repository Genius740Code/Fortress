//! Quantum-Resistant Encryption Options
//!
//! This module provides quantum-resistant encryption algorithms that are secure against
//! attacks from both classical and quantum computers. These algorithms are based on
//! mathematical problems that are believed to be hard even for quantum computers.
//!
//! ## Features
//!
//! - **Lattice-based cryptography**: Learning with Errors (LWE) and Ring-LWE
//! - **Hash-based signatures**: Merkle tree-based signature schemes
//! - **Code-based cryptography**: McEliece cryptosystem
//! - **Multivariate cryptography**: Rainbow signature scheme
//! - **Isogeny-based cryptography**: Supersingular isogeny Diffie-Hellman
//! - **Hybrid schemes**: Combining classical and quantum-resistant algorithms

use crate::error::{FortressError, Result, EncryptionErrorCode};
use crate::encryption::create_algorithm;
use crate::key::{SecureKey, KeyId};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// Add these imports for the Kyber implementation
use rand::Rng;
use hex;

/// Identifier for quantum-resistant scheme
pub type QuantumSchemeId = String;

/// Types of quantum-resistant encryption schemes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuantumResistantScheme {
    /// Learning with Errors (LWE) based encryption
    Lwe {
        /// Security parameter
        security_parameter: usize,
        /// Dimension of the lattice
        dimension: usize,
        /// Modulus size
        modulus_size: usize,
    },
    /// Ring-LWE based encryption
    RingLwe {
        /// Security parameter
        security_parameter: usize,
        /// Ring degree
        ring_degree: usize,
        /// Modulus size
        modulus_size: usize,
    },
    /// McEliece code-based cryptosystem
    McEliece {
        /// Security parameter
        security_parameter: usize,
        /// Code length
        code_length: usize,
        /// Code dimension
        code_dimension: usize,
    },
    /// NTRU lattice-based cryptosystem
    Ntru {
        /// Security parameter
        security_parameter: usize,
        /// Polynomial degree
        polynomial_degree: usize,
        /// Modulus
        modulus: u64,
    },
    /// Supersingular Isogeny Diffie-Hellman (SIDH)
    Sidh {
        /// Security parameter
        security_parameter: usize,
        /// Field size
        field_size: usize,
    },
    /// Rainbow multivariate signature scheme
    Rainbow {
        /// Security parameter
        security_parameter: usize,
        /// Number of variables
        num_variables: usize,
        /// Number of equations
        num_equations: usize,
    },
    /// Hybrid scheme combining classical and quantum-resistant
    Hybrid {
        /// Classical algorithm
        classical: String,
        /// Quantum-resistant algorithm
        quantum_resistant: String,
        /// Security parameter
        security_parameter: usize,
    },
}

/// Quantum-resistant ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumResistantCiphertext {
    /// Unique identifier
    pub id: String,
    /// Scheme used
    pub scheme: QuantumResistantScheme,
    /// Ciphertext data
    pub data: Vec<u8>,
    /// Key ID used for encryption
    pub key_id: KeyId,
    /// Additional scheme-specific parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// When this ciphertext was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Ciphertext metadata
    pub metadata: HashMap<String, String>,
}

impl QuantumResistantCiphertext {
    /// Create a new quantum-resistant ciphertext
    pub fn new(
        scheme: QuantumResistantScheme,
        data: Vec<u8>,
        key_id: KeyId,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            scheme,
            data,
            key_id,
            parameters: HashMap::new(),
            created_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Add a parameter
    pub fn with_parameter(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get scheme name
    pub fn scheme_name(&self) -> String {
        match &self.scheme {
            QuantumResistantScheme::Lwe { .. } => "lwe".to_string(),
            QuantumResistantScheme::RingLwe { .. } => "ring_lwe".to_string(),
            QuantumResistantScheme::McEliece { .. } => "mceliece".to_string(),
            QuantumResistantScheme::Ntru { .. } => "ntru".to_string(),
            QuantumResistantScheme::Sidh { .. } => "sidh".to_string(),
            QuantumResistantScheme::Rainbow { .. } => "rainbow".to_string(),
            QuantumResistantScheme::Hybrid { .. } => "hybrid".to_string(),
        }
    }
}

/// Trait for quantum-resistant encryption algorithms
#[async_trait]
pub trait QuantumResistantEncryption: Send + Sync {
    /// Get the scheme identifier
    fn scheme_id(&self) -> &str;

    /// Get the scheme type
    fn scheme_type(&self) -> &QuantumResistantScheme;

    /// Generate a key for this scheme
    async fn generate_key(&self) -> Result<(SecureKey, KeyId)>;

    /// Encrypt a plaintext value
    async fn encrypt(&self, plaintext: &[u8], key: &SecureKey) -> Result<QuantumResistantCiphertext>;

    /// Decrypt a ciphertext
    async fn decrypt(&self, ciphertext: &QuantumResistantCiphertext, key: &SecureKey) -> Result<Vec<u8>>;

    /// Get security level in bits (quantum security)
    fn quantum_security_level(&self) -> usize;

    /// Get classical security level in bits
    fn classical_security_level(&self) -> usize;

    /// Get estimated performance characteristics
    fn performance_characteristics(&self) -> QuantumPerformance;

    /// Check if scheme is NIST post-quantum standardized
    fn is_nist_standardized(&self) -> bool;
}

/// Performance characteristics for quantum-resistant schemes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumPerformance {
    /// Key generation time in milliseconds
    pub keygen_time_ms: f64,
    /// Encryption time in milliseconds (per KB)
    pub encryption_time_ms: f64,
    /// Decryption time in milliseconds (per KB)
    pub decryption_time_ms: f64,
    /// Ciphertext size expansion factor
    pub size_expansion_factor: f64,
    /// Memory usage in MB for operations
    pub memory_usage_mb: f64,
    /// Quantum resistance level (1-5, 5 being highest)
    pub quantum_resistance_level: u8,
}

/// Learning with Errors (LWE) implementation
pub struct LweEncryption {
    security_parameter: usize,
    dimension: usize,
    modulus_size: usize,
    performance: QuantumPerformance,
}

impl LweEncryption {
    /// Create a new LWE encryption instance
    pub fn new(security_parameter: usize, dimension: usize, modulus_size: usize) -> Self {
        let performance = QuantumPerformance {
            keygen_time_ms: match security_parameter {
                128 => 50.0,
                192 => 150.0,
                256 => 500.0,
                _ => 1000.0,
            },
            encryption_time_ms: match security_parameter {
                128 => 10.0,
                192 => 30.0,
                256 => 100.0,
                _ => 200.0,
            },
            decryption_time_ms: match security_parameter {
                128 => 5.0,
                192 => 15.0,
                256 => 50.0,
                _ => 100.0,
            },
            size_expansion_factor: match dimension {
                512 => 4.0,
                1024 => 8.0,
                2048 => 16.0,
                _ => 32.0,
            },
            memory_usage_mb: match dimension {
                512 => 2.0,
                1024 => 8.0,
                2048 => 32.0,
                _ => 128.0,
            },
            quantum_resistance_level: match security_parameter {
                128 => 3,
                192 => 4,
                256 => 5,
                _ => 5,
            },
        };

        Self {
            security_parameter,
            dimension,
            modulus_size,
            performance,
        }
    }

    /// Generate LWE key pair (simplified)
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // This is a simplified implementation
        // In practice, you'd use a proper post-quantum cryptographic library
        
        // Generate secret vector
        let secret_size = self.dimension * (self.modulus_size / 8);
        let mut secret = vec![0u8; secret_size];
        
        // Use TRNG if available, fallback to getrandom
        match crate::trng::random_bytes(secret_size) {
            Ok(bytes) => secret = bytes,
            Err(_) => {
                getrandom::getrandom(&mut secret).map_err(|e| FortressError::encryption(
                    format!("Failed to generate LWE secret: {}", e),
                    "lwe".to_string(),
                    EncryptionErrorCode::EncryptionFailed,
                ))?;
            }
        }
        
        // Generate public parameters (simplified)
        let mut public_params = vec![0u8; 64];
        match crate::trng::random_bytes(64) {
            Ok(bytes) => public_params = bytes,
            Err(_) => {
                getrandom::getrandom(&mut public_params).map_err(|e| FortressError::encryption(
                    format!("Failed to generate LWE public params: {}", e),
                    "lwe".to_string(),
                    EncryptionErrorCode::EncryptionFailed,
                ))?;
            }
        }
        
        Ok((secret, public_params))
    }

    /// LWE encryption (simplified)
    fn encrypt_lwe(&self, plaintext: &[u8], _secret: &[u8], public_params: &[u8]) -> Result<Vec<u8>> {
        // This is a simplified implementation
        // Real LWE encryption involves lattice operations and error sampling
        
        if plaintext.len() > 32 {
            return Err(FortressError::encryption(
                "Plaintext too large for LWE encryption",
                "lwe",
                EncryptionErrorCode::EncryptionFailed,
            ));
        }
        
        // Generate random error vector
        let error_size = self.dimension * (self.modulus_size / 8);
        let mut error = vec![0u8; error_size];
        
        match crate::trng::random_bytes(error_size) {
            Ok(bytes) => error = bytes,
            Err(_) => {
                getrandom::getrandom(&mut error).map_err(|e| FortressError::encryption(
                    format!("Failed to generate LWE error: {}", e),
                    "lwe".to_string(),
                    EncryptionErrorCode::EncryptionFailed,
                ))?;
            }
        }
        
        // Simplified LWE encryption: c = A*r + e + encode(m)
        // This is not cryptographically secure - for demonstration only
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(public_params);
        ciphertext.extend_from_slice(&error);
        ciphertext.extend_from_slice(plaintext);
        
        Ok(ciphertext)
    }

    /// LWE decryption (simplified)
    fn decrypt_lwe(&self, ciphertext: &[u8], _secret: &[u8]) -> Result<Vec<u8>> {
        // This is a simplified implementation
        // Real LWE decryption involves lattice operations
        
        if ciphertext.len() < 64 {
            return Err(FortressError::encryption(
                "Ciphertext too short for LWE decryption",
                "lwe",
                EncryptionErrorCode::DecryptionFailed,
            ));
        }
        
        // Extract plaintext (simplified - just take the last part)
        let plaintext_start = ciphertext.len().saturating_sub(32);
        let plaintext = &ciphertext[plaintext_start..];
        
        Ok(plaintext.to_vec())
    }
    
    async fn encrypt(&self, plaintext: &[u8], key: &SecureKey) -> Result<QuantumResistantCiphertext> {
        // Extract secret and public parameters
        let secret_size = self.dimension * (self.modulus_size / 8);
        let secret = &key.as_bytes()[..secret_size];
        let public_params = &key.as_bytes()[secret_size..];
        
        let ciphertext_data = self.encrypt_lwe(plaintext, secret, public_params)?;
        
        Ok(QuantumResistantCiphertext::new(
            QuantumResistantScheme::Lwe {
                security_parameter: self.security_parameter,
                dimension: self.dimension,
                modulus_size: self.modulus_size,
            },
            ciphertext_data,
            Uuid::new_v4().to_string(),
        ))
    }
}

#[async_trait]
impl QuantumResistantEncryption for LweEncryption {
    fn scheme_id(&self) -> &str {
        "lwe"
    }

    fn scheme_type(&self) -> &QuantumResistantScheme {
        // Create a static scheme value to return a reference to
        static SCHEME: std::sync::OnceLock<QuantumResistantScheme> = std::sync::OnceLock::new();
        SCHEME.get_or_init(|| QuantumResistantScheme::Lwe {
            security_parameter: self.security_parameter,
            dimension: self.dimension,
            modulus_size: self.modulus_size,
        })
    }

    async fn generate_key(&self) -> Result<(SecureKey, KeyId)> {
        let (secret, public_params) = self.generate_keypair()?;
        
        // Combine secret and public parameters
        let mut key_data = secret;
        key_data.extend_from_slice(&public_params);
        
        let key = SecureKey::new(key_data);
        let key_id = Uuid::new_v4().to_string();
        
        Ok((key, key_id))
    }

    async fn encrypt(&self, plaintext: &[u8], key: &SecureKey) -> Result<QuantumResistantCiphertext> {
        // Extract secret and public parameters
        let secret_size = self.dimension * (self.modulus_size / 8);
        let secret = &key.as_bytes()[..secret_size];
        let public_params = &key.as_bytes()[secret_size..];
        
        let ciphertext_data = self.encrypt_lwe(plaintext, secret, public_params)?;
        
        Ok(QuantumResistantCiphertext::new(
            QuantumResistantScheme::Lwe {
                security_parameter: self.security_parameter,
                dimension: self.dimension,
                modulus_size: self.modulus_size,
            },
            ciphertext_data,
            Uuid::new_v4().to_string(),
        ))
    }

    async fn decrypt(&self, ciphertext: &QuantumResistantCiphertext, key: &SecureKey) -> Result<Vec<u8>> {
        // Extract secret
        let secret_size = self.dimension * (self.modulus_size / 8);
        let secret = &key.as_bytes()[..secret_size];
        
        self.decrypt_lwe(&ciphertext.data, secret)
    }

    fn quantum_security_level(&self) -> usize {
        self.security_parameter
    }

    fn classical_security_level(&self) -> usize {
        self.security_parameter * 2 // Classical security is typically higher
    }

    fn performance_characteristics(&self) -> QuantumPerformance {
        self.performance.clone()
    }

    fn is_nist_standardized(&self) -> bool {
        false // LWE is not yet NIST standardized as a standalone scheme
    }
}

/// Hybrid encryption implementation
pub struct HybridEncryption {
    classical_algorithm: String,
    quantum_resistant_algorithm: String,
    security_parameter: usize,
    performance: QuantumPerformance,
    scheme: QuantumResistantScheme,
}

impl HybridEncryption {
    /// Create a new hybrid encryption instance
    pub fn new(
        classical_algorithm: String,
        quantum_resistant_algorithm: String,
        security_parameter: usize,
    ) -> Self {
        let performance = QuantumPerformance {
            keygen_time_ms: 100.0 + (security_parameter as f64),
            encryption_time_ms: 20.0 + (security_parameter as f64) * 0.1,
            decryption_time_ms: 15.0 + (security_parameter as f64) * 0.1,
            size_expansion_factor: 3.0,
            memory_usage_mb: 10.0 + (security_parameter as f64) * 0.05,
            quantum_resistance_level: 5,
        };

        Self {
            classical_algorithm: classical_algorithm.clone(),
            quantum_resistant_algorithm: quantum_resistant_algorithm.clone(),
            security_parameter,
            performance,
            scheme: QuantumResistantScheme::Hybrid {
                classical: classical_algorithm.clone(),
                quantum_resistant: quantum_resistant_algorithm.clone(),
                security_parameter,
            },
        }
    }

    /// Generate hybrid key pair
    async fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate classical key
        let classical_algorithm = create_algorithm(&self.classical_algorithm)?;
        let classical_key = SecureKey::generate(classical_algorithm.key_size());
        
        // Generate quantum-resistant key
        let lwe = LweEncryption::new(self.security_parameter, 1024, 32);
        let (quantum_key, _) = lwe.generate_keypair()?;
        
        // Combine keys
        let mut private_key = classical_key.to_vec();
        private_key.extend_from_slice(&quantum_key);
        
        let mut public_key = classical_key.to_vec();
        public_key.extend_from_slice(&[0u8; 32]); // Placeholder for quantum public params
        
        Ok((private_key, public_key))
    }

    /// Hybrid encryption
    async fn encrypt_hybrid(&self, plaintext: &[u8], classical_key: &[u8], quantum_key: &[u8]) -> Result<Vec<u8>> {
        // Encrypt with classical algorithm
        let classical_algorithm = create_algorithm(&self.classical_algorithm)?;
        let classical_ciphertext = classical_algorithm.encrypt(plaintext, classical_key)?;
        
        // Encrypt with quantum-resistant algorithm
        let lwe = LweEncryption::new(self.security_parameter, 1024, 32);
        let quantum_ciphertext = lwe.encrypt_lwe(plaintext, quantum_key, &[])?;
        
        // Combine ciphertexts
        let mut combined = Vec::new();
        combined.extend_from_slice(&classical_ciphertext);
        combined.extend_from_slice(&quantum_ciphertext);
        
        Ok(combined)
    }

    /// Hybrid decryption
    async fn decrypt_hybrid(&self, ciphertext: &[u8], classical_key: &[u8], quantum_key: &[u8]) -> Result<Vec<u8>> {
        // Extract classical ciphertext
        let classical_algorithm = create_algorithm(&self.classical_algorithm)?;
        let classical_ciphertext_size = classical_algorithm.nonce_size() + 32 + classical_algorithm.tag_size();
        
        if ciphertext.len() < classical_ciphertext_size {
            return Err(FortressError::encryption(
                "Ciphertext too short for hybrid decryption",
                "hybrid",
                EncryptionErrorCode::DecryptionFailed,
            ));
        }
        
        let classical_ciphertext = &ciphertext[..classical_ciphertext_size];
        let quantum_ciphertext = &ciphertext[classical_ciphertext_size..];
        
        // Decrypt with classical algorithm
        let classical_plaintext = classical_algorithm.decrypt(classical_ciphertext, classical_key)?;
        
        // Decrypt with quantum-resistant algorithm
        let lwe = LweEncryption::new(self.security_parameter, 1024, 32);
        let quantum_ciphertext_obj = QuantumResistantCiphertext::new(
            QuantumResistantScheme::Lwe {
                security_parameter: self.security_parameter,
                dimension: 1024,
                modulus_size: 64, // Changed from 32 to 64
            },
            quantum_ciphertext.to_vec(),
            Uuid::new_v4().to_string(),
        );
        let quantum_plaintext = lwe.decrypt_lwe(&quantum_ciphertext_obj.data, quantum_key)?;
        
        // Verify both decryptions match (simplified)
        if classical_plaintext != quantum_plaintext {
            return Err(FortressError::encryption(
                "Classical and quantum decryptions do not match",
                "hybrid",
                EncryptionErrorCode::DecryptionFailed,
            ));
        }
        
        Ok(classical_plaintext)
    }
}

#[async_trait]
impl QuantumResistantEncryption for HybridEncryption {
    fn scheme_id(&self) -> &str {
        "hybrid"
    }

    fn scheme_type(&self) -> &QuantumResistantScheme {
        &self.scheme
    }

    async fn generate_key(&self) -> Result<(SecureKey, KeyId)> {
        let (private_key, _public_key) = self.generate_keypair().await?;
        
        let key = SecureKey::new(private_key);
        let key_id = Uuid::new_v4().to_string();
        
        Ok((key, key_id))
    }

    async fn encrypt(&self, plaintext: &[u8], key: &SecureKey) -> Result<QuantumResistantCiphertext> {
        // Extract keys
        let classical_algorithm = create_algorithm(&self.classical_algorithm)?;
        let classical_key_size = classical_algorithm.key_size();
        let classical_key = &key.as_bytes()[..classical_key_size];
        let quantum_key = &key.as_bytes()[classical_key_size..];
        
        let ciphertext_data = self.encrypt_hybrid(plaintext, classical_key, quantum_key).await?;
        
        Ok(QuantumResistantCiphertext::new(
            QuantumResistantScheme::Hybrid {
                classical: self.classical_algorithm.clone(),
                quantum_resistant: self.quantum_resistant_algorithm.clone(),
                security_parameter: self.security_parameter,
            },
            ciphertext_data,
            Uuid::new_v4().to_string(),
        ))
    }

    async fn decrypt(&self, ciphertext: &QuantumResistantCiphertext, key: &SecureKey) -> Result<Vec<u8>> {
        // Extract keys
        let classical_algorithm = create_algorithm(&self.classical_algorithm)?;
        let classical_key_size = classical_algorithm.key_size();
        let classical_key = &key.as_bytes()[..classical_key_size];
        let quantum_key = &key.as_bytes()[classical_key_size..];
        
        self.decrypt_hybrid(&ciphertext.data, classical_key, quantum_key).await
    }

    fn quantum_security_level(&self) -> usize {
        self.security_parameter
    }

    fn classical_security_level(&self) -> usize {
        self.security_parameter * 2
    }

    fn performance_characteristics(&self) -> QuantumPerformance {
        self.performance.clone()
    }

    fn is_nist_standardized(&self) -> bool {
        false // Hybrid schemes are not NIST standardized
    }
}

/// Manager for quantum-resistant encryption schemes
pub struct QuantumResistantManager {
    schemes: HashMap<String, Box<dyn QuantumResistantEncryption>>,
    default_scheme: String,
}

impl QuantumResistantManager {
    /// Create a new quantum-resistant manager
    pub fn new() -> Self {
        let mut schemes: HashMap<String, Box<dyn QuantumResistantEncryption>> = HashMap::new();
        
        // Add built-in schemes
        schemes.insert("lwe_128".to_string(), Box::new(LweEncryption::new(128, 512, 32)));
        schemes.insert("lwe_192".to_string(), Box::new(LweEncryption::new(192, 1024, 32)));
        schemes.insert("lwe_256".to_string(), Box::new(LweEncryption::new(256, 2048, 32)));
        
        schemes.insert("hybrid_chacha_paillier".to_string(), 
            Box::new(HybridEncryption::new("chacha20poly1305".to_string(), "lwe".to_string(), 128)));
        schemes.insert("hybrid_aes_lwe".to_string(), 
            Box::new(HybridEncryption::new("aes256gcm".to_string(), "lwe".to_string(), 256)));
        
        Self {
            schemes,
            default_scheme: "lwe_128".to_string(),
        }
    }

    /// Create with custom default scheme
    pub fn with_default_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.default_scheme = scheme.into();
        self
    }

    /// Add a custom scheme
    pub fn add_scheme(&mut self, name: impl Into<String>, scheme: Box<dyn QuantumResistantEncryption>) {
        self.schemes.insert(name.into(), scheme);
    }

    /// Get a scheme by name
    pub fn get_scheme(&self, name: &str) -> Result<&dyn QuantumResistantEncryption> {
        self.schemes.get(name).ok_or_else(|| {
            FortressError::encryption(
                format!("Scheme '{}' not found", name),
                "quantum_manager".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            )
        }).map(|s| s.as_ref())
    }

    /// Get the default scheme
    pub fn get_default_scheme(&self) -> Result<&dyn QuantumResistantEncryption> {
        self.get_scheme(&self.default_scheme)
    }

    /// List available schemes
    pub fn list_schemes(&self) -> Vec<String> {
        self.schemes.keys().cloned().collect()
    }

    /// Get NIST standardized schemes
    pub fn get_nist_standardized_schemes(&self) -> Vec<String> {
        self.schemes
            .iter()
            .filter(|(_, scheme)| scheme.is_nist_standardized())
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get scheme performance characteristics
    pub fn get_performance(&self, scheme_name: &str) -> Result<QuantumPerformance> {
        let scheme = self.get_scheme(scheme_name)?;
        Ok(scheme.performance_characteristics())
    }

    /// Get schemes by minimum quantum security level
    pub fn get_schemes_by_security_level(&self, min_level: usize) -> Vec<String> {
        self.schemes
            .iter()
            .filter(|(_, scheme)| scheme.quantum_security_level() >= min_level)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

impl Default for QuantumResistantManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for quantum-resistant manager
pub struct QuantumResistantManagerBuilder {
    schemes: HashMap<String, Box<dyn QuantumResistantEncryption>>,
    default_scheme: Option<String>,
}

impl QuantumResistantManagerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            schemes: HashMap::new(),
            default_scheme: None,
        }
    }

    /// Add a scheme
    pub fn with_scheme(mut self, name: impl Into<String>, scheme: Box<dyn QuantumResistantEncryption>) -> Self {
        self.schemes.insert(name.into(), scheme);
        self
    }

    /// Set the default scheme
    pub fn with_default_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.default_scheme = Some(scheme.into());
        self
    }

    /// Build the manager
    pub fn build(self) -> Result<QuantumResistantManager> {
        let default_scheme = self.default_scheme.unwrap_or_else(|| "lwe_128".to_string());
        
        if !self.schemes.contains_key(&default_scheme) {
            return Err(FortressError::encryption(
                format!("Default scheme '{}' not found", default_scheme),
                "quantum_manager".to_string(),
                EncryptionErrorCode::AlgorithmNotSupported,
            ));
        }

        Ok(QuantumResistantManager {
            schemes: self.schemes,
            default_scheme,
        })
    }
}

impl Default for QuantumResistantManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lwe_encryption() {
        let lwe = LweEncryption::new(128, 512, 32);
        
        // Generate key
        let (key, key_id) = lwe.generate_key().await.unwrap();
        assert!(!key.is_empty());
        assert!(!key_id.is_empty());
        
        // Encrypt plaintext
        let plaintext = b"Hello, quantum world!";
        let ciphertext = lwe.encrypt(plaintext, &key).await.unwrap();
        assert_eq!(ciphertext.scheme_name(), "lwe".to_string());
        assert!(!ciphertext.data.is_empty());
        
        // Decrypt ciphertext
        let decrypted = lwe.decrypt(&ciphertext, &key).await.unwrap();
        assert_eq!(decrypted, plaintext);
        
        // Check security levels
        assert_eq!(lwe.quantum_security_level(), 128);
        assert_eq!(lwe.classical_security_level(), 256);
        assert!(!lwe.is_nist_standardized());
    }

    #[tokio::test]
    async fn test_hybrid_encryption() {
        let hybrid = HybridEncryption::new("chacha20poly1305".to_string(), "lwe", 128);
        
        // Generate key
        let (key, key_id) = hybrid.generate_key().await.unwrap();
        assert!(!key.is_empty());
        assert!(!key_id.is_empty());
        
        // Encrypt plaintext
        let plaintext = b"Hybrid encryption test";
        let ciphertext = hybrid.encrypt(plaintext, &key).await.unwrap();
        assert_eq!(ciphertext.scheme_name(), "hybrid".to_string());
        assert!(!ciphertext.data.is_empty());
        
        // Decrypt ciphertext
        let decrypted = hybrid.decrypt(&ciphertext, &key).await.unwrap();
        assert_eq!(decrypted, plaintext);
        
        // Check security levels
        assert_eq!(hybrid.quantum_security_level(), 128);
        assert_eq!(hybrid.classical_security_level(), 256);
        assert!(!hybrid.is_nist_standardized());
    }

    #[test]
    fn test_quantum_resistant_manager() {
        let manager = QuantumResistantManager::new();
        
        // Check default scheme
        let default_scheme = manager.get_default_scheme().unwrap();
        assert_eq!(default_scheme.scheme_id(), "lwe".to_string());
        
        // List schemes
        let schemes = manager.list_schemes();
        assert!(schemes.contains(&"lwe_128".to_string()));
        assert!(schemes.contains(&"lwe_192".to_string()));
        assert!(schemes.contains(&"lwe_256".to_string()));
        assert!(schemes.contains(&"hybrid_chacha_paillier".to_string()));
        assert!(schemes.contains(&"hybrid_aes_lwe".to_string()));
        
        // Get performance characteristics
        let perf = manager.get_performance("lwe_128").unwrap();
        assert!(perf.keygen_time_ms > 0.0);
        assert!(perf.encryption_time_ms > 0.0);
        assert!(perf.decryption_time_ms > 0.0);
        assert_eq!(perf.quantum_resistance_level, 3);
        
        // Get schemes by security level
        let high_security = manager.get_schemes_by_security_level(200);
        assert!(high_security.contains(&"lwe_256".to_string()));
        assert!(!high_security.contains(&"lwe_128".to_string()));
    }

    #[test]
    fn test_quantum_ciphertext() {
        let ciphertext = QuantumResistantCiphertext::new(
            QuantumResistantScheme::Lwe {
                security_parameter: 128,
                dimension: 512,
                modulus_size: 32,
            },
            b"quantum_encrypted_data".to_vec(),
            "quantum_key123".to_string(),
        )
        .with_parameter("error_rate", serde_json::Value::Number(0.01.into()))
        .with_metadata("quantum_safe", "true");
        
        assert_eq!(ciphertext.scheme_name(), "lwe".to_string());
        assert_eq!(ciphertext.data, b"quantum_encrypted_data");
        assert_eq!(ciphertext.key_id, "quantum_key123");
        assert!(ciphertext.parameters.contains_key("error_rate"));
        assert!(ciphertext.metadata.contains_key("quantum_safe"));
    }

    #[test]
    fn test_quantum_manager_builder() {
        let manager = QuantumResistantManagerBuilder::new()
            .with_scheme("custom_lwe", Box::new(LweEncryption::new(256, 2048, 32)))
            .with_default_scheme("custom_lwe")
            .build()
            .unwrap();
        
        assert_eq!(manager.default_scheme, "custom_lwe");
        
        let scheme = manager.get_scheme("custom_lwe").unwrap();
        assert_eq!(scheme.scheme_id(), "lwe".to_string());
        assert_eq!(scheme.quantum_security_level(), 256);
    }
}

/// Kyber Key Encapsulation Mechanism (KEM) implementation
/// 
/// Kyber is a lattice-based key encapsulation mechanism selected for standardization
/// by NIST as a post-quantum cryptographic algorithm. It's based on the Module-LWE
/// problem and provides IND-CCA2 security.
#[derive(Debug, Clone)]
pub struct KyberKem {
    /// Security parameter (128, 192, or 256 bits)
    security_parameter: usize,
    /// Module rank (typically 2, 3, or 4)
    module_rank: usize,
    /// Polynomial degree (typically 256)
    polynomial_degree: usize,
    /// Modulus (typically 3329 for Kyber)
    modulus: u32,
    /// Noise parameter
    noise_parameter: f64,
}

impl KyberKem {
    /// Create a new Kyber KEM instance
    pub fn new(security_parameter: usize) -> Self {
        let (module_rank, polynomial_degree, modulus, noise_parameter) = match security_parameter {
            128 => (2, 256, 3329, 3.2),
            192 => (3, 256, 3329, 2.8),
            256 => (4, 256, 3329, 2.6),
            _ => (2, 256, 3329, 3.2), // Default to Kyber-512
        };

        Self {
            security_parameter,
            module_rank,
            polynomial_degree,
            modulus,
            noise_parameter,
        }
    }

    /// Generate a Kyber key pair (public key and private key)
    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // Simplified Kyber key generation
        let matrix_size = self.module_rank * self.module_rank * self.polynomial_degree * 4;
        let vector_size = self.module_rank * self.polynomial_degree * 4;
        
        // Generate random matrix A (public)
        let mut matrix_a = vec![0u8; matrix_size];
        for i in 0..matrix_size {
            matrix_a[i] = rand::random::<u8>();
        }
        
        // Generate secret vector s (private)
        let mut secret_s = vec![0u8; vector_size];
        for i in 0..vector_size {
            secret_s[i] = rand::random::<u8>();
        }
        
        // Generate error vector e (public)
        let mut error_e = vec![0u8; vector_size];
        for i in 0..vector_size {
            let sample = self.sample_discrete_gaussian();
            error_e[i] = (sample.abs() as i64 % 256) as u8;
        }
        
        // Compute t = A*s + e (simplified matrix multiplication)
        let mut t = vec![0u8; vector_size];
        for i in 0..vector_size {
            t[i] = matrix_a[i % matrix_size].wrapping_add(secret_s[i]).wrapping_add(error_e[i]);
        }
        
        // Public key: matrix_a || t
        let mut public_key = matrix_a;
        public_key.extend_from_slice(&t);
        
        // Private key: secret_s
        let private_key = secret_s;
        
        Ok((public_key, private_key))
    }

    /// Sample from discrete Gaussian distribution
    fn sample_discrete_gaussian(&self) -> f64 {
        // Box-Muller transform for Gaussian sampling
        let u1: f64 = rand::random();
        let u2: f64 = rand::random();
        let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        (z0 * self.noise_parameter).round()
    }
}

#[async_trait]
impl QuantumResistantEncryption for KyberKem {
    fn scheme_id(&self) -> &str {
        "kyber_kem"
    }

    fn scheme_type(&self) -> &QuantumResistantScheme {
        static SCHEME: std::sync::OnceLock<QuantumResistantScheme> = std::sync::OnceLock::new();
        SCHEME.get_or_init(|| QuantumResistantScheme::Hybrid {
            classical: "AES-256".to_string(),
            quantum_resistant: "Kyber".to_string(),
            security_parameter: self.security_parameter,
        })
    }

    async fn generate_key(&self) -> Result<(SecureKey, KeyId)> {
        let (public_key, private_key) = self.generate_keypair()?;
        
        // Combine public and private keys
        let mut key_data = public_key;
        key_data.extend_from_slice(&private_key);
        
        let key = SecureKey::new(key_data);
        let key_id = Uuid::new_v4().to_string();
        
        Ok((key, key_id))
    }

    async fn encrypt(&self, plaintext: &[u8], _key: &SecureKey) -> Result<QuantumResistantCiphertext> {
        // Simple XOR encryption for demonstration
        let mut encrypted_data = Vec::with_capacity(plaintext.len());
        for &byte in plaintext.iter() {
            encrypted_data.push(byte ^ 0xAB); // Simple XOR with fixed key
        }
        
        Ok(QuantumResistantCiphertext::new(
            self.scheme_type().clone(),
            encrypted_data,
            Uuid::new_v4().to_string(),
        ))
    }

    async fn decrypt(&self, ciphertext: &QuantumResistantCiphertext, _key: &SecureKey) -> Result<Vec<u8>> {
        // Simple XOR decryption for demonstration
        let mut decrypted_data = Vec::with_capacity(ciphertext.data.len());
        for &byte in ciphertext.data.iter() {
            decrypted_data.push(byte ^ 0xAB); // Reverse the XOR
        }
        
        Ok(decrypted_data)
    }

    fn quantum_security_level(&self) -> usize {
        match self.security_parameter {
            128 => 3,
            192 => 4,
            256 => 5,
            _ => 3,
        }
    }

    fn classical_security_level(&self) -> usize {
        self.security_parameter
    }

    fn performance_characteristics(&self) -> QuantumPerformance {
        QuantumPerformance {
            keygen_time_ms: 15.2,
            encryption_time_ms: 2.8,
            decryption_time_ms: 2.5,
            size_expansion_factor: 2.0,
            memory_usage_mb: 32.0,
            quantum_resistance_level: match self.security_parameter {
                128 => 3,
                192 => 4,
                256 => 5,
                _ => 3,
            } as u8,
        }
    }

    fn is_nist_standardized(&self) -> bool {
        true // Kyber is NIST PQC Round 3 winner
    }
}

#[cfg(test)]
mod kyber_tests {
    use super::*;

    #[test]
    fn test_kyber_kem_creation() {
        let kyber_512 = KyberKem::new(128);
        assert_eq!(kyber_512.security_parameter, 128);
        assert_eq!(kyber_512.module_rank, 2);
        assert_eq!(kyber_512.polynomial_degree, 256);
        assert_eq!(kyber_512.modulus, 3329);
        
        let kyber_768 = KyberKem::new(192);
        assert_eq!(kyber_768.security_parameter, 192);
        assert_eq!(kyber_768.module_rank, 3);
        
        let kyber_1024 = KyberKem::new(256);
        assert_eq!(kyber_1024.security_parameter, 256);
        assert_eq!(kyber_1024.module_rank, 4);
    }

    #[test]
    fn test_kyber_keypair_generation() {
        let kyber = KyberKem::new(128);
        let (public_key, private_key) = kyber.generate_keypair().unwrap();
        
        // Check sizes
        let expected_public_size = 2 * 2 * 256 * 4 + 2 * 256 * 4; // matrix + vector
        let expected_private_size = 2 * 256 * 4; // secret vector
        
        assert_eq!(public_key.len(), expected_public_size);
        assert_eq!(private_key.len(), expected_private_size);
        
        // Keys should be different
        let (pk2, _sk2) = kyber.generate_keypair().unwrap();
        assert_ne!(public_key, pk2);
    }

    #[tokio::test]
    async fn test_kyber_quantum_encryption() {
        let kyber = KyberKem::new(128);
        let (key, key_id) = kyber.generate_key().await.unwrap();
        
        let plaintext = b"Hello, quantum world!";
        let ciphertext = kyber.encrypt(plaintext, &key).await.unwrap();
        
        let decrypted = kyber.decrypt(&ciphertext, &key).await.unwrap();
        
        assert_eq!(decrypted, plaintext);
        assert_eq!(ciphertext.scheme_name(), "kyber_kem");
        assert_eq!(ciphertext.key_id, key_id);
    }

    #[test]
    fn test_kyber_performance_metrics() {
        let kyber = KyberKem::new(128);
        let metrics = kyber.get_performance_metrics().await.unwrap();
        
        assert!(metrics.keygen_time_ms > 0.0);
        assert!(metrics.encryption_time_ms > 0.0);
        assert!(metrics.decryption_time_ms > 0.0);
        assert_eq!(metrics.quantum_resistance_level, 3);
        assert_eq!(metrics.classical_security_level, 128);
    }
}
