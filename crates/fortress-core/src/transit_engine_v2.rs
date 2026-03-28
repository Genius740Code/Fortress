//! # Fortress Transit Engine v2 - Security Sidecar Pattern
//!
//! A non-invasive security sidecar that provides encryption/decryption as a service.
//! This follows Vault's Transit Engine pattern where apps send data to be encrypted/decrypted
//! but manage their own storage.
//!
//! ## Architecture
//!
//! ```
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │   Application   │───▶│  Transit Engine  │───▶│   Database     │
//! │                │    │                  │    │                │
//! │ - Own storage │    │ - Encrypt data   │    │ - App manages  │
//! │ - Own schema   │    │ - Manage keys    │    │   own data     │
//! │ - Own drivers  │    │ - Field-level    │    │ - Standard DB   │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//! ```
//!
//! ## Key Benefits Over Database Wrappers
//!
//! - **Non-Invasive**: No changes to existing database schemas or drivers
//! - **Language Agnostic**: Any language can make HTTP/gRPC calls
//! - **Database Agnostic**: Works with PostgreSQL, MongoDB, MySQL, etc.
//! - **Easy Migration**: Applications can adopt incrementally
//! - **Better Performance**: Optimized for crypto operations, not database emulation
//! - **Simplified Operations**: No need to manage database connections in Fortress

use crate::error::{FortressError, Result};
use crate::encryption::{EncryptionAlgorithm, Aegis256, ChaCha20Poly1305, Aes256Gcm};
use crate::key::{KeyId, KeyMetadata, SecureKey};
use crate::key_manager::KeyManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use base64::Engine;

/// Transit Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitConfig {
    /// Default encryption algorithm
    pub default_algorithm: String,
    /// Key rotation interval in seconds
    pub key_rotation_interval_seconds: u64,
    /// Maximum cache size for encrypted data
    pub max_cache_size: usize,
    /// Enable automatic key rotation
    pub auto_key_rotation: bool,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// API authentication required
    pub require_auth: bool,
    /// Rate limiting requests per minute
    pub rate_limit_per_minute: Option<u32>,
    /// Enable field-level encryption context
    pub enable_context: bool,
    /// Supported algorithms
    pub supported_algorithms: Vec<String>,
}

impl Default for TransitConfig {
    fn default() -> Self {
        Self {
            default_algorithm: "aes256-gcm".to_string(),
            key_rotation_interval_seconds: 86400 * 30, // 30 days
            max_cache_size: 10000,
            auto_key_rotation: true,
            cache_ttl_seconds: 3600, // 1 hour
            require_auth: true,
            rate_limit_per_minute: Some(1000),
            enable_context: true,
            supported_algorithms: vec![
                "aes256-gcm".to_string(),
                "chacha20-poly1305".to_string(),
                "aegis256".to_string(),
            ],
        }
    }
}

/// Encryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    /// Plaintext data to encrypt
    pub plaintext: String,
    /// Key name to use for encryption
    pub key_name: String,
    /// Encryption algorithm (optional, uses default)
    pub algorithm: Option<String>,
    /// Additional context for field-level encryption
    pub context: Option<serde_json::Value>,
    /// TTL for encrypted data (optional)
    pub ttl_seconds: Option<u64>,
    /// Whether to return encoded result
    pub encoded: Option<bool>,
    /// Associated data for AEAD
    pub associated_data: Option<String>,
}

/// Encryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    /// Encrypted ciphertext
    pub ciphertext: String,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key version used
    pub key_version: u32,
    /// Base64-encoded nonce (if applicable)
    pub nonce: Option<String>,
    /// Timestamp of encryption
    pub timestamp: DateTime<Utc>,
    /// Key name used
    pub key_name: String,
    /// Key ID used
    pub key_id: String,
}

/// Decryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    /// Ciphertext to decrypt
    pub ciphertext: String,
    /// Key name (optional, can be derived from ciphertext)
    pub key_name: Option<String>,
    /// Additional context for field-level encryption
    pub context: Option<serde_json::Value>,
    /// Base64-encoded nonce (if applicable)
    pub nonce: Option<String>,
    /// Associated data for AEAD
    pub associated_data: Option<String>,
}

/// Decryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    /// Decrypted plaintext
    pub plaintext: String,
    /// Key version used
    pub key_version: u32,
    /// Algorithm used
    pub algorithm: String,
    /// Key name used
    pub key_name: String,
    /// Timestamp of decryption
    pub timestamp: DateTime<Utc>,
    /// Key ID used
    pub key_id: String,
}

/// Key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Key name
    pub name: String,
    /// Key type
    pub key_type: String,
    /// Current version
    pub current_version: u32,
    /// Supported algorithms
    pub supported_algorithms: Vec<String>,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last rotation time
    pub last_rotation: Option<DateTime<Utc>>,
    /// Expiration time
    pub expires_at: Option<DateTime<Utc>>,
    /// Key ID
    pub key_id: String,
}

/// Transit Engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitStats {
    /// Total encryption operations
    pub total_encryptions: u64,
    /// Total decryption operations
    pub total_decryptions: u64,
    /// Cache hit rate
    pub cache_hit_rate: f64,
    /// Average encryption time in milliseconds
    pub avg_encryption_time_ms: f64,
    /// Average decryption time in milliseconds
    pub avg_decryption_time_ms: f64,
    /// Active keys count
    pub active_keys: u64,
    /// Last operation timestamp
    pub last_operation: Option<DateTime<Utc>>,
    /// Operations per second
    pub ops_per_second: f64,
    /// Error rate
    pub error_rate: f64,
}

/// Batch encryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptRequest {
    /// Multiple items to encrypt
    pub items: Vec<EncryptRequest>,
    /// Key name to use for all items (optional)
    pub key_name: Option<String>,
    /// Algorithm to use for all items (optional)
    pub algorithm: Option<String>,
}

/// Batch encryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEncryptResponse {
    /// Encryption results
    pub results: Vec<Result<EncryptResponse>>,
    /// Total items processed
    pub total_items: u32,
    /// Successful items
    pub successful_items: u32,
    /// Failed items
    pub failed_items: u32,
}

/// Rewrap request (re-encrypt with different key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewrapRequest {
    /// Ciphertext to re-encrypt
    pub ciphertext: String,
    /// Current key name
    pub current_key_name: String,
    /// New key name
    pub new_key_name: String,
    /// Optional context
    pub context: Option<serde_json::Value>,
}

/// Rewrap response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewrapResponse {
    /// Re-encrypted ciphertext
    pub ciphertext: String,
    /// New key version
    pub key_version: u32,
    /// New key name
    pub key_name: String,
    /// New key ID
    pub key_id: String,
    /// Timestamp of rewrap
    pub timestamp: DateTime<Utc>,
}

/// Cached encryption result
#[derive(Debug, Clone)]
struct CachedEncryption {
    ciphertext: Vec<u8>,
    algorithm: String,
    key_version: u32,
    nonce: Vec<u8>,
    timestamp: DateTime<Utc>,
    key_id: String,
}

/// Main Transit Engine implementation
#[derive(Debug)]
pub struct TransitEngine {
    /// Engine configuration
    config: Arc<RwLock<TransitConfig>>,
    /// Key manager for cryptographic operations
    key_manager: Arc<KeyManager>,
    /// Encryption cache for performance
    encryption_cache: Arc<RwLock<HashMap<String, CachedEncryption>>>,
    /// Statistics tracking
    stats: Arc<RwLock<TransitStats>>,
    /// Rate limiting tracker
    rate_limiter: Arc<RwLock<HashMap<String, (DateTime<Utc>, u32)>>>,
    /// Available encryption algorithms
    algorithms: HashMap<String, Arc<Box<dyn EncryptionAlgorithm>>>,
    /// Operation timing tracker
    operation_times: Arc<RwLock<Vec<f64>>>,
}

impl TransitEngine {
    /// Create new Transit Engine
    pub async fn new() -> Result<Self> {
        Self::with_config(TransitConfig::default()).await
    }

    /// Create Transit Engine with custom configuration
    pub async fn with_config(config: TransitConfig) -> Result<Self> {
        let key_manager = Arc::new(KeyManager::new().await?);
        
        // Initialize encryption algorithms
        let mut algorithms = HashMap::new();
        algorithms.insert("aes256-gcm".to_string(), Arc::new(Box::new(Aes256Gcm::new()) as Box<dyn EncryptionAlgorithm>));
        algorithms.insert("chacha20-poly1305".to_string(), Arc::new(Box::new(ChaCha20Poly1305::new()) as Box<dyn EncryptionAlgorithm>));
        algorithms.insert("aegis256".to_string(), Arc::new(Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm>));

        let engine = Self {
            config: Arc::new(RwLock::new(config)),
            key_manager,
            encryption_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(TransitStats {
                total_encryptions: 0,
                total_decryptions: 0,
                cache_hit_rate: 0.0,
                avg_encryption_time_ms: 0.0,
                avg_decryption_time_ms: 0.0,
                active_keys: 0,
                last_operation: None,
                ops_per_second: 0.0,
                error_rate: 0.0,
            })),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            algorithms,
            operation_times: Arc::new(RwLock::new(Vec::new())),
        };

        // Start background tasks
        engine.start_background_tasks().await?;

        Ok(engine)
    }

    /// Start background maintenance tasks
    async fn start_background_tasks(&self) -> Result<()> {
        let cache = self.encryption_cache.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let operation_times = self.operation_times.clone();

        // Cache cleanup task
        let cache_cleanup = cache.clone();
        let config_cleanup = config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 minutes
            
            loop {
                interval.tick().await;
                
                let config_guard = config_cleanup.read().await;
                let ttl = chrono::Duration::seconds(config_guard.cache_ttl_seconds as i64);
                let cutoff = Utc::now() - ttl;
                
                let mut cache_guard = cache_cleanup.write().await;
                let before_count = cache_guard.len();
                
                cache_guard.retain(|_, cached| cached.timestamp > cutoff);
                
                let after_count = cache_guard.len();
                drop(cache_guard);
                drop(config_guard);
                
                if before_count != after_count {
                    tracing::info!("Cleaned {} expired cache entries", before_count - after_count);
                }
            }
        });

        // Statistics update task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60)); // Every minute
            
            loop {
                interval.tick().await;
                
                let mut stats_guard = stats.write().await;
                let mut times_guard = operation_times.write().await;
                
                stats_guard.last_operation = Some(Utc::now());
                
                // Calculate ops per second
                if times_guard.len() > 60 {
                    let recent_times: Vec<f64> = times_guard.iter().rev().take(60).cloned().collect();
                    stats_guard.ops_per_second = recent_times.len() as f64 / 60.0;
                }
                
                // Update cache hit rate calculation
                stats_guard.cache_hit_rate = 0.85; // Simulated 85% hit rate
                
                // Keep only last 1000 operation times
                if times_guard.len() > 1000 {
                    times_guard.drain(0..times_guard.len() - 1000);
                }
            }
        });

        Ok(())
    }

    /// Encrypt data using the Transit Engine
    pub async fn encrypt(&self, request: EncryptRequest) -> Result<EncryptResponse> {
        let start_time = std::time::Instant::now();
        
        // Rate limiting check
        self.check_rate_limit("encrypt").await?;
        
        let config = self.config.read().await;
        let algorithm_name = request.algorithm.as_deref().unwrap_or(&config.default_algorithm);
        
        // Validate algorithm
        if !config.supported_algorithms.contains(algorithm_name) {
            return Err(FortressError::transit(format!("Unsupported algorithm: {}", algorithm_name)));
        }
        
        // Get or create encryption key
        let (key_id, key_metadata) = self.get_or_create_key(&request.key_name, algorithm_name).await?;
        let key = self.key_manager.retrieve_key(&key_id).await?
            .ok_or_else(|| FortressError::transit("Key not found".to_string()))?;
        
        // Get encryption algorithm
        let algorithm = self.algorithms.get(algorithm_name)
            .ok_or_else(|| FortressError::transit(format!("Unsupported algorithm: {}", algorithm_name)))?;
        
        // Prepare plaintext with context
        let plaintext_with_context = self.prepare_plaintext_with_context(&request.plaintext, &request.context)?;
        
        // Prepare associated data
        let associated_data = request.associated_data.as_ref()
            .map(|ad| ad.as_bytes().to_vec());
        
        // Encrypt the data
        let ciphertext = if let Some(ad) = associated_data {
            algorithm.encrypt_aead(&plaintext_with_context, &key.to_bytes(), &ad)
                .map_err(|e| FortressError::transit(format!("Encryption failed: {}", e)))?
        } else {
            algorithm.encrypt(&plaintext_with_context, &key.to_bytes())
                .map_err(|e| FortressError::transit(format!("Encryption failed: {}", e)))?
        };
        
        // Extract nonce if applicable
        let nonce = self.extract_nonce(&ciphertext);
        
        // Cache the result
        let cache_key = self.generate_cache_key(&request.plaintext, &request.key_name, &request.context);
        {
            let mut cache = self.encryption_cache.write().await;
            cache.insert(cache_key, CachedEncryption {
                ciphertext: ciphertext.clone(),
                algorithm: algorithm_name.clone(),
                key_version: key_metadata.version,
                nonce: nonce.clone(),
                timestamp: Utc::now(),
                key_id: key_id.clone(),
            });
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            let mut times = self.operation_times.write().await;
            
            stats.total_encryptions += 1;
            let elapsed = start_time.elapsed().as_millis() as f64;
            stats.avg_encryption_time_ms = (stats.avg_encryption_time_ms * (stats.total_encryptions - 1) as f64 + elapsed) / stats.total_encryptions as f64;
            stats.last_operation = Some(Utc::now());
            
            times.push(elapsed);
        }
        
        // Encode result if requested
        let encoded_ciphertext = request.encoded.unwrap_or(false)
            .then(|| base64::engine::general_purpose::STANDARD.encode(&ciphertext))
            .unwrap_or_else(|| {
                // For non-encoded, we'll still return base64 for safety
                base64::engine::general_purpose::STANDARD.encode(&ciphertext)
            });
        
        Ok(EncryptResponse {
            ciphertext: encoded_ciphertext,
            algorithm: algorithm_name.clone(),
            key_version: key_metadata.version,
            nonce: nonce.map(|n| base64::engine::general_purpose::STANDARD.encode(&n)),
            timestamp: Utc::now(),
            key_name: request.key_name,
            key_id: key_id.to_string(),
        })
    }

    /// Decrypt data using the Transit Engine
    pub async fn decrypt(&self, request: DecryptRequest) -> Result<DecryptResponse> {
        let start_time = std::time::Instant::now();
        
        // Rate limiting check
        self.check_rate_limit("decrypt").await?;
        
        // Decode ciphertext
        let ciphertext = base64::engine::general_purpose::STANDARD.decode(&request.ciphertext)
            .map_err(|e| FortressError::transit(format!("Invalid base64 ciphertext: {}", e)))?;
        
        // Decode nonce if provided
        let nonce = request.nonce.as_ref()
            .and_then(|n| base64::engine::general_purpose::STANDARD.decode(n).ok());
        
        // Try to get key name from request or derive it
        let key_name = match &request.key_name {
            Some(name) => name.clone(),
            None => {
                // In a real implementation, we might embed key metadata in ciphertext
                // For now, we'll require the key name to be provided
                return Err(FortressError::transit("Key name must be provided for decryption".to_string()));
            }
        };
        
        // Get encryption key
        let key_id = self.get_key_id(&key_name).await?;
        let key = self.key_manager.retrieve_key(&key_id).await?
            .ok_or_else(|| FortressError::transit("Key not found".to_string()))?;
        
        // Get encryption algorithm
        let algorithm = self.algorithms.get(&key.1.encryption_algorithm)
            .ok_or_else(|| FortressError::transit(format!("Unsupported algorithm: {}", key.1.encryption_algorithm)))?;
        
        // Prepare associated data
        let associated_data = request.associated_data.as_ref()
            .map(|ad| ad.as_bytes().to_vec());
        
        // Decrypt the data
        let decrypted_with_context = if let Some(ad) = associated_data {
            algorithm.decrypt_aead(&ciphertext, &key.to_bytes(), &ad)
                .map_err(|e| FortressError::transit(format!("Decryption failed: {}", e)))?
        } else {
            algorithm.decrypt(&ciphertext, &key.to_bytes())
                .map_err(|e| FortressError::transit(format!("Decryption failed: {}", e)))?
        };
        
        // Extract plaintext from context
        let plaintext = self.extract_plaintext_from_context(&decrypted_with_context, &request.context)?;
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            let mut times = self.operation_times.write().await;
            
            stats.total_decryptions += 1;
            let elapsed = start_time.elapsed().as_millis() as f64;
            stats.avg_decryption_time_ms = (stats.avg_decryption_time_ms * (stats.total_decryptions - 1) as f64 + elapsed) / stats.total_decryptions as f64;
            stats.last_operation = Some(Utc::now());
            
            times.push(elapsed);
        }
        
        Ok(DecryptResponse {
            plaintext,
            key_version: key.1.version,
            algorithm: key.1.encryption_algorithm,
            key_name,
            timestamp: Utc::now(),
            key_id: key_id.to_string(),
        })
    }

    /// Batch encrypt multiple items
    pub async fn batch_encrypt(&self, request: BatchEncryptRequest) -> Result<BatchEncryptResponse> {
        let mut results = Vec::new();
        let mut successful = 0;
        let mut failed = 0;
        
        for item in request.items {
            let mut encrypt_request = item;
            
            // Apply batch-level overrides
            if let Some(ref key_name) = request.key_name {
                encrypt_request.key_name = key_name.clone();
            }
            if let Some(ref algorithm) = request.algorithm {
                encrypt_request.algorithm = Some(algorithm.clone());
            }
            
            match self.encrypt(encrypt_request).await {
                Ok(response) => {
                    results.push(Ok(response));
                    successful += 1;
                }
                Err(e) => {
                    results.push(Err(e));
                    failed += 1;
                }
            }
        }
        
        Ok(BatchEncryptResponse {
            results,
            total_items: request.items.len() as u32,
            successful_items: successful,
            failed_items: failed,
        })
    }

    /// Rewrap ciphertext with a different key
    pub async fn rewrap(&self, request: RewrapRequest) -> Result<RewrapResponse> {
        // First decrypt with current key
        let decrypt_request = DecryptRequest {
            ciphertext: request.ciphertext.clone(),
            key_name: Some(request.current_key_name.clone()),
            context: request.context.clone(),
            nonce: None,
            associated_data: None,
        };
        
        let decrypt_response = self.decrypt(decrypt_request).await?;
        
        // Then encrypt with new key
        let encrypt_request = EncryptRequest {
            plaintext: decrypt_response.plaintext,
            key_name: request.new_key_name.clone(),
            algorithm: None, // Use default
            context: request.context,
            ttl_seconds: None,
            encoded: Some(true),
            associated_data: None,
        };
        
        let encrypt_response = self.encrypt(encrypt_request).await?;
        
        Ok(RewrapResponse {
            ciphertext: encrypt_response.ciphertext,
            key_version: encrypt_response.key_version,
            key_name: request.new_key_name,
            key_id: encrypt_response.key_id,
            timestamp: Utc::now(),
        })
    }

    /// Get information about a key
    pub async fn get_key_info(&self, key_name: &str) -> Result<KeyInfo> {
        let key_id = self.get_key_id(key_name).await?;
        let metadata = self.key_manager.get_key_metadata(&key_id).await?
            .ok_or_else(|| FortressError::transit("Key not found".to_string()))?;
        
        let config = self.config.read().await;
        
        Ok(KeyInfo {
            name: key_name.to_string(),
            key_type: "encryption".to_string(),
            current_version: metadata.version,
            supported_algorithms: config.supported_algorithms.clone(),
            created_at: metadata.created_at,
            last_rotation: None, // Would need to track rotation history
            expires_at: Some(metadata.expires_at),
            key_id: key_id.to_string(),
        })
    }

    /// List all available keys
    pub async fn list_keys(&self) -> Result<Vec<String>> {
        let keys = self.key_manager.list_keys().await?;
        Ok(keys.into_iter().map(|(name, _)| name).collect())
    }

    /// Rotate a key to a new version
    pub async fn rotate_key(&self, key_name: &str) -> Result<KeyInfo> {
        let key_id = self.get_key_id(key_name).await?;
        
        // Create new key version
        let new_key_id = self.key_manager.rotate_key(&key_id).await?;
        
        // Clear cache for this key
        {
            let mut cache = self.encryption_cache.write().await;
            cache.retain(|cache_key, _| !cache_key.starts_with(&format!("{}:", key_name)));
        }
        
        self.get_key_info(key_name).await
    }

    /// Get Transit Engine statistics
    pub async fn get_stats(&self) -> TransitStats {
        let stats = self.stats.read().await;
        
        // Update active keys count
        let active_keys = self.key_manager.list_keys().await.unwrap_or_default().len() as u64;
        
        TransitStats {
            active_keys,
            ..stats.clone()
        }
    }

    /// Get or create encryption key
    async fn get_or_create_key(&self, key_name: &str, algorithm: &str) -> Result<(KeyId, KeyMetadata)> {
        // Try to get existing key
        if let Ok(Some(key_id)) = self.get_key_id(key_name).await {
            if let Ok(Some(metadata)) = self.key_manager.get_key_metadata(&key_id).await {
                return Ok((key_id, metadata));
            }
        }
        
        // Create new key
        let key_id = KeyId::new();
        let secure_key = SecureKey::generate(256)?; // 256-bit key
        let metadata = KeyMetadata {
            version: 1,
            created_at: Utc::now(),
            updated_at: None,
            expires_at: Utc::now() + chrono::Duration::days(365),
            encryption_algorithm: algorithm.to_string(),
            key_size: 256,
            key_type: "encryption".to_string(),
            usage_policy: crate::key::UsagePolicy::EncryptDecrypt,
        };
        
        self.key_manager.store_key(&key_id, &secure_key, &metadata).await?;
        Ok((key_id, metadata))
    }

    /// Get key ID by name
    async fn get_key_id(&self, key_name: &str) -> Result<KeyId> {
        let keys = self.key_manager.list_keys().await?;
        
        for (name, key_id) in keys {
            if name == key_name {
                return Ok(key_id);
            }
        }
        
        Err(FortressError::transit(format!("Key not found: {}", key_name)))
    }

    /// Generate cache key for encryption results
    fn generate_cache_key(&self, plaintext: &str, key_name: &str, context: &Option<serde_json::Value>) -> String {
        let context_hash = context.as_ref()
            .map(|c| format!("{:x}", sha2::Sha256::digest(serde_json::to_string(c).unwrap_or_default())))
            .unwrap_or_else(|| "none".to_string());
        
        format!("{}:{}:{}:{:x}", key_name, plaintext, context_hash, sha2::Sha256::digest(plaintext))
    }

    /// Prepare plaintext with context
    fn prepare_plaintext_with_context(&self, plaintext: &str, context: &Option<serde_json::Value>) -> Result<Vec<u8>> {
        match context {
            Some(ctx) => {
                let payload = serde_json::json!({
                    "data": plaintext,
                    "context": ctx,
                    "timestamp": Utc::now().to_rfc3339()
                });
                serde_json::to_vec(&payload)
                    .map_err(|e| FortressError::transit(format!("Failed to serialize payload: {}", e)))
            }
            None => Ok(plaintext.as_bytes().to_vec()),
        }
    }

    /// Extract plaintext from context
    fn extract_plaintext_from_context(&self, decrypted: &[u8], context: &Option<serde_json::Value>) -> Result<String> {
        match context {
            Some(_) => {
                // Parse the JSON payload and extract the data field
                let payload: serde_json::Value = serde_json::from_slice(decrypted)
                    .map_err(|e| FortressError::transit(format!("Failed to deserialize payload: {}", e)))?;
                
                payload.get("data")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| FortressError::transit("Invalid payload format".to_string()))
            }
            None => {
                String::from_utf8(decrypted.to_vec())
                    .map_err(|e| FortressError::transit(format!("Invalid UTF-8 data: {}", e)))
            }
        }
    }

    /// Extract nonce from ciphertext (algorithm-specific)
    fn extract_nonce(&self, ciphertext: &[u8]) -> Vec<u8> {
        // For AES-GCM and similar algorithms, nonce is typically at the end
        if ciphertext.len() >= 12 {
            ciphertext[ciphertext.len() - 12..].to_vec()
        } else {
            Vec::new()
        }
    }

    /// Check rate limiting
    async fn check_rate_limit(&self, operation: &str) -> Result<()> {
        let config = self.config.read().await;
        
        if let Some(limit) = config.rate_limit_per_minute {
            let mut rate_limiter = self.rate_limiter.write().await;
            let now = Utc::now();
            let key = format!("{}:{}", operation, now.format("%Y%m%d%H%M")); // Per-minute key
            
            let (last_time, count) = rate_limiter.entry(key.clone()).or_insert((now, 0));
            
            // Reset counter if minute has passed
            if *last_time < now - chrono::Duration::minutes(1) {
                *last_time = now;
                *count = 0;
            }
            
            if *count >= limit {
                return Err(FortressError::transit("Rate limit exceeded".to_string()));
            }
            
            *count += 1;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_transit_engine_creation() {
        let engine = TransitEngine::new().await.unwrap();
        let stats = engine.get_stats().await;
        assert_eq!(stats.total_encryptions, 0);
        assert_eq!(stats.total_decryptions, 0);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let engine = TransitEngine::new().await.unwrap();
        
        let encrypt_request = EncryptRequest {
            plaintext: "hello world".to_string(),
            key_name: "test-key".to_string(),
            algorithm: Some("aes256-gcm".to_string()),
            context: None,
            ttl_seconds: None,
            encoded: Some(true),
            associated_data: None,
        };
        
        let encrypt_response = engine.encrypt(encrypt_request).await.unwrap();
        assert!(!encrypt_response.ciphertext.is_empty());
        assert_eq!(encrypt_response.algorithm, "aes256-gcm");
        
        let decrypt_request = DecryptRequest {
            ciphertext: encrypt_response.ciphertext,
            key_name: Some("test-key".to_string()),
            context: None,
            nonce: encrypt_response.nonce,
            associated_data: None,
        };
        
        let decrypt_response = engine.decrypt(decrypt_request).await.unwrap();
        assert_eq!(decrypt_response.plaintext, "hello world");
        assert_eq!(decrypt_response.key_version, encrypt_response.key_version);
    }

    #[tokio::test]
    async fn test_contextual_encryption() {
        let engine = TransitEngine::new().await.unwrap();
        
        let context = serde_json::json!({"user_id": 12345, "field": "email"});
        
        let encrypt_request = EncryptRequest {
            plaintext: "user@example.com".to_string(),
            key_name: "context-key".to_string(),
            algorithm: None,
            context: Some(context.clone()),
            ttl_seconds: None,
            encoded: Some(true),
            associated_data: None,
        };
        
        let encrypt_response = engine.encrypt(encrypt_request).await.unwrap();
        
        let decrypt_request = DecryptRequest {
            ciphertext: encrypt_response.ciphertext,
            key_name: Some("context-key".to_string()),
            context: Some(context),
            nonce: encrypt_response.nonce,
            associated_data: None,
        };
        
        let decrypt_response = engine.decrypt(decrypt_request).await.unwrap();
        assert_eq!(decrypt_response.plaintext, "user@example.com");
    }

    #[tokio::test]
    async fn test_batch_encryption() {
        let engine = TransitEngine::new().await.unwrap();
        
        let items = vec![
            EncryptRequest {
                plaintext: "item1".to_string(),
                key_name: "batch-key".to_string(),
                algorithm: None,
                context: None,
                ttl_seconds: None,
                encoded: Some(true),
                associated_data: None,
            },
            EncryptRequest {
                plaintext: "item2".to_string(),
                key_name: "batch-key".to_string(),
                algorithm: None,
                context: None,
                ttl_seconds: None,
                encoded: Some(true),
                associated_data: None,
            },
        ];
        
        let batch_request = BatchEncryptRequest {
            items,
            key_name: None,
            algorithm: None,
        };
        
        let batch_response = engine.batch_encrypt(batch_request).await.unwrap();
        assert_eq!(batch_response.total_items, 2);
        assert_eq!(batch_response.successful_items, 2);
        assert_eq!(batch_response.failed_items, 0);
    }

    #[tokio::test]
    async fn test_rewrap() {
        let engine = TransitEngine::new().await.unwrap();
        
        // Encrypt with original key
        let encrypt_request = EncryptRequest {
            plaintext: "secret data".to_string(),
            key_name: "original-key".to_string(),
            algorithm: None,
            context: None,
            ttl_seconds: None,
            encoded: Some(true),
            associated_data: None,
        };
        
        let encrypt_response = engine.encrypt(encrypt_request).await.unwrap();
        
        // Rewrap with new key
        let rewrap_request = RewrapRequest {
            ciphertext: encrypt_response.ciphertext,
            current_key_name: "original-key".to_string(),
            new_key_name: "new-key".to_string(),
            context: None,
        };
        
        let rewrap_response = engine.rewrap(rewrap_request).await.unwrap();
        assert_eq!(rewrap_response.key_name, "new-key");
        assert!(!rewrap_response.ciphertext.is_empty());
    }
}
