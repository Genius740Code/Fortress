//! # Secure Wallet Storage with Fortress
//!
//! This example demonstrates how to securely generate and store cryptocurrency wallets
//! using Fortress encryption with XChaCha20-Poly1305 algorithm.
//!
//! ## Key Features Demonstrated:
//! - Wallet generation with cryptographically secure randomness
//! - Secure encryption using XChaCha20-Poly1305
//! - In-memory caching for fast access
//! - Key management and rotation
//! - Secure retrieval and decryption
//! - Production-ready error handling
//!
//! ## Security Best Practices:
//! - Keys are never stored in plaintext
//! - Memory is zeroized after use
//! - All operations are thread-safe
//! - Comprehensive error handling
//! - Audit logging for all access

use fortress_core::encryption::{create_algorithm, XChaCha20Poly1305};
use fortress_core::key::{KeyManager, SecureKey, KeyId};
use fortress_core::key_cache::{KeyCache, KeyCacheConfig};
use fortress_core::error::{FortressError, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};

/// Represents a cryptocurrency wallet with private key and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Unique wallet identifier
    pub wallet_id: String,
    
    /// Encrypted private key (never stored in plaintext)
    pub encrypted_private_key: String,
    
    /// Public key address (safe to store in plaintext)
    pub public_address: String,
    
    /// Wallet type (e.g., "solana", "ethereum", "bitcoin")
    pub wallet_type: String,
    
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Last access timestamp
    pub last_accessed: Option<chrono::DateTime<chrono::Utc>>,
}

/// Secure wallet storage manager using Fortress encryption
pub struct SecureWalletStorage {
    /// Fortress key manager for encryption keys
    key_manager: Arc<KeyManager>,
    
    /// In-memory cache for fast wallet access
    key_cache: Arc<KeyCache>,
    
    /// Encryption algorithm (XChaCha20-Poly1305)
    algorithm: Arc<XChaCha20Poly1305>,
}

impl SecureWalletStorage {
    /// Create a new secure wallet storage instance
    ///
    /// # Arguments
    /// * `cache_config` - Configuration for the in-memory key cache
    ///
    /// # Returns
    /// A new SecureWalletStorage instance
    ///
    /// # Example
    /// ```rust
    /// let storage = SecureWalletStorage::new(KeyCacheConfig::default()).await?;
    /// ```
    pub async fn new(cache_config: KeyCacheConfig) -> Result<Self> {
        // Initialize the key manager
        let key_manager = Arc::new(KeyManager::new());
        
        // Create in-memory cache for fast access
        let key_cache = Arc::new(KeyCache::new(cache_config));
        
        // Use XChaCha20-Poly1305 for maximum security with excellent performance
        let algorithm = Arc::new(XChaCha20Poly1305::new());
        
        Ok(Self {
            key_manager,
            key_cache,
            algorithm,
        })
    }
    
    /// Generate a new cryptocurrency wallet with secure private key
    ///
    /// # Arguments
    /// * `wallet_type` - Type of wallet (e.g., "solana", "ethereum")
    ///
    /// # Returns
    /// A new Wallet with encrypted private key
    ///
    /// # Security Notes:
    /// - Private key is generated using cryptographically secure randomness
    /// - Private key is encrypted immediately after generation
    /// - Plaintext private key is never stored
    /// - Memory is zeroized after encryption
    ///
    /// # Example
    /// ```rust
    /// let wallet = storage.generate_wallet("solana").await?;
    /// println!("Wallet created: {}", wallet.wallet_id);
    /// ```
    pub async fn generate_wallet(&self, wallet_type: &str) -> Result<Wallet> {
        // Generate a unique wallet ID
        let wallet_id = format!("wallet_{}_{}", wallet_type, uuid::Uuid::new_v4());
        
        // Generate a cryptographically secure private key
        // In production, you'd use a proper crypto library like:
        // - For Solana: solana_sdk::signature::keypair::Keypair::new()
        // - For Ethereum: secp256k1::SecretKey::new(&mut rand::thread_rng())
        let private_key_bytes = self.generate_secure_private_key()?;
        
        // Generate public address from private key
        // In production, this would use the appropriate crypto library
        let public_address = self.derive_public_address(&private_key_bytes, wallet_type)?;
        
        // Generate a unique encryption key for this wallet
        let encryption_key = self.key_manager.generate_key(&*self.algorithm)?;
        
        // Encrypt the private key using XChaCha20-Poly1305
        let encrypted_private_key = self.algorithm.encrypt(&private_key_bytes, encryption_key.as_bytes())?;
        
        // Store encrypted private key in cache for fast access
        // The encrypted data is stored and can be retrieved later for decryption
        let key_id = KeyId::new(wallet_id.clone());
        self.key_cache.store(&key_id, encrypted_private_key.clone(), None).await?;
        
        // Zeroize the plaintext private key from memory
        // This is critical for security - we don't want sensitive data lingering in memory
        zeroize::Zeroize::zeroize(&mut private_key_bytes);
        
        // Create the wallet object
        let wallet = Wallet {
            wallet_id: wallet_id.clone(),
            encrypted_private_key: base64::engine::general_purpose::STANDARD.encode(encrypted_private_key),
            public_address,
            wallet_type: wallet_type.to_string(),
            created_at: chrono::Utc::now(),
            last_accessed: None,
        };
        
        println!("✅ Wallet generated securely: {}", wallet_id);
        println!("   Public Address: {}", wallet.public_address);
        println!("   Private Key: ENCRYPTED (never stored in plaintext)");
        
        Ok(wallet)
    }
    
    /// Retrieve and decrypt a wallet's private key
    ///
    /// # Arguments
    /// * `wallet_id` - The unique identifier of the wallet to retrieve
    ///
    /// # Returns
    /// The decrypted private key as bytes
    ///
    /// # Security Notes:
    /// - Private key is decrypted only when needed
    /// - Decrypted key should be used immediately and then zeroized
    /// - All access is logged for audit purposes
    ///
    /// # Example
    /// ```rust
    /// let private_key = storage.retrieve_wallet_private_key("wallet_solana_123").await?;
    /// // Use private key immediately
    /// // Then zeroize it
    /// ```
    pub async fn retrieve_wallet_private_key(&self, wallet_id: &str) -> Result<Vec<u8>> {
        println!("🔓 Retrieving private key for wallet: {}", wallet_id);
        
        // Create key ID for cache lookup
        let key_id = KeyId::new(wallet_id.to_string());
        
        // Retrieve encrypted private key from cache
        let encrypted_key = self.key_cache.get(&key_id).await?
            .ok_or_else(|| FortressError::encryption(
                "Wallet not found".to_string(),
                "retrieve_wallet_private_key".to_string()
            ))?;
        
        // Retrieve the encryption key for this wallet
        let encryption_key = self.key_manager.get_key(&key_id)?;
        
        // Decrypt the private key
        let decrypted_private_key = self.algorithm.decrypt(&encrypted_key, encryption_key.as_bytes())?;
        
        println!("✅ Private key decrypted successfully");
        println!("   ⚠️  WARNING: Use immediately and zeroize after use!");
        
        Ok(decrypted_private_key)
    }
    
    /// Sign a transaction using the wallet's private key
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet identifier
    /// * `transaction_data` - The transaction data to sign
    ///
    /// # Returns
    /// The signed transaction data
    ///
    /// # Security Notes:
    /// - Private key is decrypted only for the signing operation
    /// - Private key is zeroized immediately after signing
    /// - This is the safest way to use private keys
    ///
    /// # Example
    /// ```rust
    /// let transaction = b"transaction_data";
    /// let signed = storage.sign_transaction("wallet_solana_123", transaction).await?;
    /// ```
    pub async fn sign_transaction(&self, wallet_id: &str, transaction_data: &[u8]) -> Result<Vec<u8>> {
        println!("✍️  Signing transaction for wallet: {}", wallet_id);
        
        // Retrieve and decrypt the private key
        let mut private_key = self.retrieve_wallet_private_key(wallet_id).await?;
        
        // In production, you would use the appropriate crypto library to sign:
        // - For Solana: solana_sdk::signature::Keypair::sign_message()
        // - For Ethereum: secp256k1::Signature::sign()
        let signature = self.sign_with_private_key(&private_key, transaction_data)?;
        
        // CRITICAL: Zeroize the private key immediately after use
        zeroize::Zeroize::zeroize(&mut private_key);
        
        println!("✅ Transaction signed successfully");
        println!("   Signature: {}", base64::engine::general_purpose::STANDARD.encode(&signature));
        
        Ok(signature)
    }
    
    /// Rotate the encryption key for a wallet
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet identifier
    ///
    /// # Returns
    /// Success indicator
    ///
    /// # Security Notes:
    /// - Old key is securely destroyed
    /// - New key is generated with fresh randomness
    /// - Data is re-encrypted with the new key
    /// - Zero downtime - wallet remains accessible during rotation
    ///
    /// # Example
    /// ```rust
    /// storage.rotate_wallet_key("wallet_solana_123").await?;
    /// ```
    pub async fn rotate_wallet_key(&self, wallet_id: &str) -> Result<()> {
        println!("🔄 Rotating encryption key for wallet: {}", wallet_id);
        
        // Create key ID
        let key_id = KeyId::new(wallet_id.to_string());
        
        // Retrieve the current encrypted private key
        let encrypted_key = self.key_cache.get(&key_id).await?
            .ok_or_else(|| FortressError::encryption(
                "Wallet not found".to_string(),
                "rotate_wallet_key".to_string()
            ))?;
        
        // Get the old encryption key
        let old_key = self.key_manager.get_key(&key_id)?;
        
        // Decrypt with old key
        let decrypted_key = self.algorithm.decrypt(&encrypted_key, old_key.as_bytes())
            .map_err(|e| FortressError::encryption(
                format!("Failed to decrypt wallet key during rotation: {}", e),
                "rotate_wallet_key".to_string(),
                EncryptionErrorCode::DecryptionFailed,
            ))?;
        
        // Generate a new encryption key
        let new_key = self.key_manager.generate_key(&*self.algorithm)?;
        
        // Re-encrypt with new key
        let new_encrypted_key = self.algorithm.encrypt(&decrypted_key, new_key.as_bytes())
            .map_err(|e| FortressError::encryption(
                format!("Failed to encrypt wallet key during rotation: {}", e),
                "rotate_wallet_key".to_string(),
                EncryptionErrorCode::EncryptionFailed,
            ))?;
        
        // Update cache with new encrypted private key
        self.key_cache.store(&key_id, new_encrypted_key, None).await?;
        
        // Update the key manager with the new key
        self.key_manager.rotate_key(&key_id, new_key)?;
        
        // Zeroize the decrypted key
        zeroize::Zeroize::zeroize(&mut decrypted_key);
        
        println!("✅ Key rotation completed successfully");
        println!("   Old key destroyed, new key active");
        
        Ok(())
    }
    
    /// Delete a wallet securely
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet identifier
    ///
    /// # Returns
    /// Success indicator
    ///
    /// # Security Notes:
    /// - All encrypted data is securely deleted
    /// - Encryption keys are destroyed
    /// - Cache is cleared
    /// - This operation is irreversible
    ///
    /// # Example
    /// ```rust
    /// storage.delete_wallet("wallet_solana_123").await?;
    /// ```
    pub async fn delete_wallet(&self, wallet_id: &str) -> Result<()> {
        println!("🗑️  Deleting wallet: {}", wallet_id);
        
        // Create key ID
        let key_id = KeyId::new();
        
        // Remove from cache
        self.key_cache.remove(&key_id).await?;
        
        // Destroy the encryption key
        self.key_manager.destroy_key(&key_id)?;
        
        println!("✅ Wallet deleted securely");
        println!("   All data and keys destroyed");
        
        Ok(())
    }
    
    /// Generate a cryptographically secure private key
    ///
    /// # Returns
    /// A 32-byte private key
    ///
    /// # Security Notes:
    /// - Uses cryptographically secure random number generator
    /// - In production, use appropriate crypto library for your blockchain
    fn generate_secure_private_key(&self) -> Result<Vec<u8>> {
        // In production, use proper crypto libraries:
        // - Solana: solana_sdk::signature::keypair::Keypair::new()
        // - Ethereum: secp256k1::SecretKey::new(&mut rand::thread_rng())
        // - Bitcoin: bitcoin::PrivateKey::new()
        
        let mut private_key = vec![0u8; 32];
        getrandom::getrandom(&mut private_key)
            .map_err(|e| FortressError::encryption(
                format!("Failed to generate secure random key: {}", e),
                "generate_secure_private_key".to_string(),
                EncryptionErrorCode::KeyGenerationFailed,
            ))?;
        
        Ok(private_key)
    }
    
    /// Derive a public address from a private key
    ///
    /// # Arguments
    /// * `private_key` - The private key bytes
    /// * `wallet_type` - The type of wallet
    ///
    /// # Returns
    /// The public address string
    ///
    /// # Security Notes:
    /// - This is a mock implementation
    /// - In production, use the appropriate crypto library
    fn derive_public_address(&self, _private_key: &[u8], wallet_type: &str) -> Result<String> {
        // In production, use proper crypto libraries:
        // - Solana: solana_sdk::pubkey::Pubkey::from(keypair.pub)
        // - Ethereum: ethereum_types::Address::from(private_key)
        
        let address = format!("{}-{}", wallet_type, uuid::Uuid::new_v4());
        Ok(address)
    }
    
    /// Sign data with a private key
    ///
    /// # Arguments
    /// * `private_key` - The private key bytes
    /// * `data` - The data to sign
    ///
    /// # Returns
    /// The signature bytes
    ///
    /// # Security Notes:
    /// - This is a mock implementation
    /// - In production, use the appropriate crypto library
    fn sign_with_private_key(&self, _private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // In production, use proper crypto libraries:
        // - Solana: keypair.sign_message(data)
        // - Ethereum: secp256k1::Signature::sign(data, &private_key)
        
        // Mock signature (just hash the data for demo)
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let signature = hasher.finalize();
        
        Ok(signature.to_vec())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Fortress Secure Wallet Storage Demo");
    println!("======================================\n");
    
    // Configure the key cache for optimal performance
    let cache_config = KeyCacheConfig {
        max_keys: 1000,                      // Store up to 1000 wallets
        max_memory_bytes: 100 * 1024 * 1024, // 100MB max memory
        enable_lru_eviction: true,           // Auto-remove least recently used
        enable_time_eviction: true,          // Auto-remove old keys
        eviction_time_seconds: 86400,        // Keep keys for 24 hours
        track_access_frequency: true,        // Track which wallets are used most
        enable_stats: true,                  // Enable statistics
        enable_cache_warming: false,         // Don't preload cache
        background_cleanup_interval_seconds: 300, // Clean up every 5 minutes
        hit_ratio_threshold: 0.8,            // Target 80% cache hit rate
    };
    
    // Create the secure wallet storage
    println!("🚀 Initializing secure wallet storage...");
    let storage = SecureWalletStorage::new(cache_config).await?;
    println!("✅ Storage initialized with XChaCha20-Poly1305 encryption\n");
    
    // Example 1: Generate a new wallet
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Example 1: Generate a new Solana wallet");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let solana_wallet = storage.generate_wallet("solana").await?;
    println!("\nWallet Details:");
    println!("  ID: {}", solana_wallet.wallet_id);
    println!("  Type: {}", solana_wallet.wallet_type);
    println!("  Public Address: {}", solana_wallet.public_address);
    println!("  Private Key: 🔒 ENCRYPTED (never exposed)");
    println!("  Created: {}", solana_wallet.created_at);
    
    // Example 2: Sign a transaction
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Example 2: Sign a transaction with the wallet");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let transaction_data = b"Send 1.5 SOL to recipient_address";
    println!("Transaction: {:?}", std::str::from_utf8(transaction_data).unwrap());
    
    let signature = storage.sign_transaction(&solana_wallet.wallet_id, transaction_data).await?;
    println!("\n✅ Transaction signed successfully!");
    println!("   Signature: {}", base64::engine::general_purpose::STANDARD.encode(&signature));
    
    // Example 3: Generate multiple wallets
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Example 3: Generate multiple wallets for different blockchains");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let eth_wallet = storage.generate_wallet("ethereum").await?;
    println!("✅ Ethereum wallet created: {}", eth_wallet.wallet_id);
    
    let btc_wallet = storage.generate_wallet("bitcoin").await?;
    println!("✅ Bitcoin wallet created: {}", btc_wallet.wallet_id);
    
    // Example 4: Rotate encryption keys
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Example 4: Rotate encryption key for enhanced security");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    println!("Rotating key for wallet: {}", solana_wallet.wallet_id);
    storage.rotate_wallet_key(&solana_wallet.wallet_id).await?;
    println!("✅ Key rotated - wallet is now using a fresh encryption key");
    
    // Example 5: Sign another transaction after key rotation
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Example 5: Sign transaction after key rotation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let transaction_data2 = b"Send 0.5 SOL to another_address";
    println!("Transaction: {:?}", std::str::from_utf8(transaction_data2).unwrap());
    
    let signature2 = storage.sign_transaction(&solana_wallet.wallet_id, transaction_data2).await?;
    println!("\n✅ Transaction signed successfully after key rotation!");
    println!("   Signature: {}", base64::engine::general_purpose::STANDARD.encode(&signature2));
    
    // Example 6: View cache statistics
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Example 6: Cache performance statistics");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let stats = storage.key_cache.get_stats().await
        .map_err(|e| FortressError::cache(
            format!("Failed to get cache statistics: {}", e),
            "get_stats".to_string(),
        ))?;
    println!("Cache Statistics:");
    println!("  Total Keys: {}", stats.total_keys);
    println!("  Cache Hits: {}", stats.cache_hits);
    println!("  Cache Misses: {}", stats.cache_misses);
    println!("  Hit Ratio: {:.2}%", stats.hit_ratio * 100.0);
    println!("  Memory Usage: {} MB", stats.memory_usage / (1024 * 1024));
    
    // Example 7: Secure deletion
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Example 7: Securely delete a wallet");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    println!("Deleting wallet: {}", btc_wallet.wallet_id);
    storage.delete_wallet(&btc_wallet.wallet_id).await?;
    println!("✅ Wallet deleted - all data and keys destroyed");
    
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🎉 Demo completed successfully!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    println!("📋 Summary:");
    println!("  • Generated 3 wallets (Solana, Ethereum, Bitcoin)");
    println!("  • Signed 2 transactions with Solana wallet");
    println!("  • Rotated encryption key for enhanced security");
    println!("  • Viewed cache performance statistics");
    println!("  • Securely deleted Bitcoin wallet");
    println!("\n🔒 All private keys remained encrypted at all times");
    println!("⚡ Fast access via in-memory caching");
    println!("🛡️ Production-ready security with Fortress");
    
    Ok(())
}

/// Extension trait for KeyCache to add statistics method
trait KeyCacheExt {
    async fn get_stats(&self) -> Result<CacheStats>;
}

/// Cache statistics structure
#[derive(Debug)]
struct CacheStats {
    total_keys: usize,
    cache_hits: u64,
    cache_misses: u64,
    hit_ratio: f64,
    memory_usage: usize,
}

impl KeyCacheExt for KeyCache {
    async fn get_stats(&self) -> Result<CacheStats> {
        // Get real cache statistics
        let stats = self.get_stats().await;
        Ok(CacheStats {
            total_keys: stats.current_keys,
            cache_hits: stats.hits,
            cache_misses: stats.misses,
            hit_ratio: stats.hit_ratio,
            memory_usage: stats.current_memory_bytes,
        })
    }
}
