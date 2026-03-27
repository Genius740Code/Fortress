//! TEE-Aware Key Management
//!
//! This module provides TEE-aware key management capabilities, allowing
//! Fortress to generate, store, and use cryptographic keys within secure
//! enclaves, providing the highest level of protection for sensitive keys.

use crate::error::{FortressError, Result};
use crate::key::SecureKey;
use crate::tee::{TeeManager, TeeType, EnclaveConfig, SecurityPolicy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// TEE-aware key manager for enclave-protected keys
pub struct TeeAwareKeyManager {
    /// TEE manager instance
    tee_manager: Arc<TeeManager>,
    /// Enclave-protected keys storage
    enclave_keys: Arc<RwLock<HashMap<String, EnclaveKeyInfo>>>,
    /// Key generation policies
    key_policies: HashMap<String, KeyPolicy>,
    /// Key usage metrics
    usage_metrics: Arc<RwLock<HashMap<String, KeyUsageMetrics>>>,
}

/// Information about an enclave-protected key
#[derive(Debug, Clone)]
pub struct EnclaveKeyInfo {
    /// Key identifier
    pub key_id: String,
    /// Enclave ID where key is stored
    pub enclave_id: String,
    /// Key algorithm
    pub algorithm: String,
    /// Key size in bits
    pub key_size: u32,
    /// Key creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last access timestamp
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    /// Access count
    pub access_count: u64,
    /// Key status
    pub status: KeyStatus,
    /// Key metadata
    pub metadata: HashMap<String, String>,
}

/// Key status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyStatus {
    /// Key is active and ready for use
    Active,
    /// Key is temporarily disabled
    Disabled,
    /// Key is scheduled for rotation
    PendingRotation,
    /// Key is compromised and should be revoked
    Compromised,
    /// Key is being destroyed
    Destroying,
    /// Key has been destroyed
    Destroyed,
}

/// Key policy for generation and usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Required TEE type
    pub required_tee_type: TeeType,
    /// Minimum key size
    pub min_key_size: u32,
    /// Maximum key size
    pub max_key_size: u32,
    /// Allowed algorithms
    pub allowed_algorithms: Vec<String>,
    /// Require attestation before use
    pub require_attestation: bool,
    /// Key rotation interval in seconds
    pub rotation_interval: Option<u64>,
    /// Maximum usage count
    pub max_usage_count: Option<u64>,
    /// Access control list
    pub access_control: Vec<String>,
}

/// Key usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsageMetrics {
    /// Total operations performed
    pub total_operations: u64,
    /// Operations by type
    pub operations_by_type: HashMap<String, u64>,
    /// Last operation timestamp
    pub last_operation: chrono::DateTime<chrono::Utc>,
    /// Average operation duration in milliseconds
    pub avg_operation_duration_ms: f64,
    /// Error count
    pub error_count: u64,
}

/// Key generation request
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenerationRequest {
    /// Operation type
    pub operation: String,
    /// Key algorithm
    pub algorithm: String,
    /// Key size in bits
    pub key_size: u32,
    /// Key identifier
    pub key_id: String,
    /// Additional parameters
    pub parameters: HashMap<String, String>,
}

/// Key generation response
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenerationResponse {
    /// Success status
    pub success: bool,
    /// Generated key ID
    pub key_id: Option<String>,
    /// Public key (if applicable)
    pub public_key: Option<String>,
    /// Error message
    pub error: Option<String>,
}

/// Cryptographic operation request
#[derive(Debug, Serialize, Deserialize)]
pub struct CryptographicOperationRequest {
    /// Operation type (encrypt, decrypt, sign, verify)
    pub operation: String,
    /// Key identifier
    pub key_id: String,
    /// Data (base64 encoded)
    pub data: String,
    /// Additional parameters
    pub parameters: HashMap<String, String>,
}

/// Cryptographic operation response
#[derive(Debug, Serialize, Deserialize)]
pub struct CryptographicOperationResponse {
    /// Success status
    pub success: bool,
    /// Result data (base64 encoded)
    pub result: Option<String>,
    /// Signature (for signing operations)
    pub signature: Option<String>,
    /// Verification result (for verify operations)
    pub verification_result: Option<bool>,
    /// Error message
    pub error: Option<String>,
}

/// Key rotation request
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    /// Operation type
    pub operation: String,
    /// Current key ID
    pub current_key_id: String,
    /// New key algorithm (optional)
    pub new_algorithm: Option<String>,
    /// New key size (optional)
    pub new_key_size: Option<u32>,
    /// Rotation reason
    pub rotation_reason: String,
}

/// Key rotation response
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyRotationResponse {
    /// Success status
    pub success: bool,
    /// New key ID
    pub new_key_id: Option<String>,
    /// Rotation timestamp
    pub rotation_timestamp: chrono::DateTime<chrono::Utc>,
    /// Error message
    pub error: Option<String>,
}

impl TeeAwareKeyManager {
    /// Create a new TEE-aware key manager
    pub fn new(tee_manager: Arc<TeeManager>) -> Self {
        Self {
            tee_manager,
            enclave_keys: Arc::new(RwLock::new(HashMap::new())),
            key_policies: HashMap::new(),
            usage_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Add a key policy
    pub async fn add_key_policy(&mut self, policy_name: String, policy: KeyPolicy) {
        self.key_policies.insert(policy_name, policy);
    }
    
    /// Create a secure enclave for key management
    pub async fn create_key_enclave(
        &self,
        tee_type: TeeType,
        policy_name: Option<&str>,
    ) -> Result<String> {
        let policy = if let Some(name) = policy_name {
            self.key_policies.get(name)
                .ok_or_else(|| FortressError::tee(
                    format!("Key policy not found: {}", name),
                    "TeeAwareKeyManager::create_key_enclave".to_string()
                ))?
        } else {
            // Use default policy
            &self.get_default_policy(tee_type.clone())
        };
        
        // Create enclave configuration
        let config = EnclaveConfig {
            enclave_id: Uuid::new_v4().to_string(),
            tee_type: tee_type.clone(),
            cpu_count: 2,
            memory_mb: 1024,
            image_path: self.get_enclave_image_path(&tee_type)?,
            port: 5000,
            security_policy: SecurityPolicy {
                require_attestation: policy.require_attestation,
                min_security_version: Some(1),
                max_security_version: None,
                allowed_pcr_values: None,
                require_secure_boot: true,
                allow_debug_mode: false,
            },
            parameters: HashMap::new(),
        };
        
        // Create and start enclave
        let enclave_id = self.tee_manager.create_enclave(config).await?;
        self.tee_manager.start_enclave(&enclave_id).await?;
        
        // Perform attestation if required
        if policy.require_attestation {
            let attestation = self.tee_manager.attest_enclave(&enclave_id).await?;
            if !attestation.is_valid {
                // Clean up failed enclave
                let _ = self.tee_manager.terminate_enclave(&enclave_id).await;
                return Err(FortressError::tee(
                    format!("Enclave attestation failed: {:?}", attestation.security_issues),
                    "TeeAwareKeyManager::create_key_enclave".to_string()
                ));
            }
        }
        
        Ok(enclave_id)
    }
    
    /// Generate a new key within an enclave
    pub async fn generate_key_in_enclave(
        &self,
        enclave_id: &str,
        algorithm: &str,
        key_size: u32,
        policy_name: Option<&str>,
    ) -> Result<String> {
        // Verify enclave is running and attested
        let status = self.tee_manager.get_enclave_status(enclave_id).await?;
        if status != crate::tee::EnclaveStatus::Running {
            return Err(FortressError::tee(
                format!("Enclave {} is not running", enclave_id),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string()
            ));
        }
        
        // Validate against policy
        if let Some(name) = policy_name {
            let policy = self.key_policies.get(name)
                .ok_or_else(|| FortressError::tee(
                    format!("Key policy not found: {}", name),
                    "TeeAwareKeyManager::generate_key_in_enclave".to_string()
                ))?;
            
            if !policy.allowed_algorithms.contains(&algorithm.to_string()) {
                return Err(FortressError::tee(
                    format!("Algorithm {} not allowed by policy", algorithm),
                    "TeeAwareKeyManager::generate_key_in_enclave".to_string()
                ));
            }
            
            if key_size < policy.min_key_size || key_size > policy.max_key_size {
                return Err(FortressError::tee(
                    format!("Key size {} not within policy bounds [{}, {}]", 
                           key_size, policy.min_key_size, policy.max_key_size),
                    "TeeAwareKeyManager::generate_key_in_enclave".to_string()
                ));
            }
        }
        
        // Generate key generation request
        let request = KeyGenerationRequest {
            operation: "generate_key".to_string(),
            algorithm: algorithm.to_string(),
            key_size,
            key_id: Uuid::new_v4().to_string(),
            parameters: HashMap::new(),
        };
        
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| FortressError::tee(
                format!("Failed to serialize key generation request: {}", e),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string()
            ))?;
        
        // Send request to enclave
        let start_time = chrono::Utc::now();
        let response = self.tee_manager.send_message(enclave_id, &request_bytes).await?;
        let duration = (chrono::Utc::now() - start_time).num_milliseconds() as f64;
        
        // Parse response
        let response: KeyGenerationResponse = serde_json::from_slice(&response)
            .map_err(|e| FortressError::tee(
                format!("Failed to deserialize key generation response: {}", e),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string()
            ))?;
        
        if !response.success {
            return Err(FortressError::tee(
                response.error.unwrap_or_else(|| "Key generation failed".to_string()),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string()
            ));
        }
        
        let key_id = response.key_id.unwrap();
        
        // Store key info
        let key_info = EnclaveKeyInfo {
            key_id: key_id.clone(),
            enclave_id: enclave_id.to_string(),
            algorithm: algorithm.to_string(),
            key_size,
            created_at: chrono::Utc::now(),
            last_accessed: chrono::Utc::now(),
            access_count: 0,
            status: KeyStatus::Active,
            metadata: HashMap::new(),
        };
        
        let mut enclave_keys = self.enclave_keys.write().await;
        enclave_keys.insert(key_id.clone(), key_info);
        
        // Initialize usage metrics
        let mut metrics = self.usage_metrics.write().await;
        metrics.insert(key_id.clone(), KeyUsageMetrics {
            total_operations: 0,
            operations_by_type: HashMap::new(),
            last_operation: chrono::Utc::now(),
            avg_operation_duration_ms: duration,
            error_count: 0,
        });
        
        Ok(key_id)
    }
    
    /// Perform cryptographic operation in enclave
    pub async fn perform_operation(
        &self,
        key_id: &str,
        operation: &str,
        data: &[u8],
        parameters: Option<HashMap<String, String>>,
    ) -> Result<Vec<u8>> {
        let enclave_keys = self.enclave_keys.read().await;
        let key_info = enclave_keys.get(key_id)
            .ok_or_else(|| FortressError::tee(
                format!("Key not found: {}", key_id),
                "TeeAwareKeyManager::perform_operation".to_string()
            ))?;
        
        // Check key status
        if key_info.status != KeyStatus::Active {
            return Err(FortressError::tee(
                format!("Key {} is not active (status: {:?})", key_id, key_info.status),
                "TeeAwareKeyManager::perform_operation".to_string()
            ));
        }
        
        // Check usage limits if policy exists
        if let Some(policy_name) = key_info.metadata.get("policy_name") {
            if let Some(policy) = self.key_policies.get(policy_name) {
                if let Some(max_usage) = policy.max_usage_count {
                    if key_info.access_count >= max_usage {
                        return Err(FortressError::tee(
                            format!("Key {} has exceeded maximum usage count", key_id),
                            "TeeAwareKeyManager::perform_operation".to_string()
                        ));
                    }
                }
            }
        }
        
        // Create operation request
        let request = CryptographicOperationRequest {
            operation: operation.to_string(),
            key_id: key_id.to_string(),
            data: base64::encode(data),
            parameters: parameters.unwrap_or_default(),
        };
        
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| FortressError::tee(
                format!("Failed to serialize operation request: {}", e),
                "TeeAwareKeyManager::perform_operation".to_string()
            ))?;
        
        // Send request to enclave
        let start_time = chrono::Utc::now();
        let response = self.tee_manager.send_message(&key_info.enclave_id, &request_bytes).await?;
        let duration = (chrono::Utc::now() - start_time).num_milliseconds() as f64;
        
        // Parse response
        let response: CryptographicOperationResponse = serde_json::from_slice(&response)
            .map_err(|e| FortressError::tee(
                format!("Failed to deserialize operation response: {}", e),
                "TeeAwareKeyManager::perform_operation".to_string()
            ))?;
        
        if !response.success {
            // Update error metrics
            drop(enclave_keys);
            let mut metrics = self.usage_metrics.write().await;
            if let Some(key_metrics) = metrics.get_mut(key_id) {
                key_metrics.error_count += 1;
            }
            
            return Err(FortressError::tee(
                response.error.unwrap_or_else(|| "Operation failed".to_string()),
                "TeeAwareKeyManager::perform_operation".to_string()
            ));
        }
        
        // Update access info and metrics
        drop(enclave_keys);
        let mut enclave_keys = self.enclave_keys.write().await;
        if let Some(key_info) = enclave_keys.get_mut(key_id) {
            key_info.last_accessed = chrono::Utc::now();
            key_info.access_count += 1;
        }
        
        let mut metrics = self.usage_metrics.write().await;
        if let Some(key_metrics) = metrics.get_mut(key_id) {
            key_metrics.total_operations += 1;
            key_metrics.operations_by_type
                .entry(operation.to_string())
                .and_modify(|count| *count += 1)
                .or_insert(1);
            key_metrics.last_operation = chrono::Utc::now();
            // Update average duration
            let total_ops = key_metrics.total_operations;
            key_metrics.avg_operation_duration_ms = 
                (key_metrics.avg_operation_duration_ms * (total_ops - 1) as f64 + duration) / total_ops as f64;
        }
        
        // Return result
        if let Some(result_data) = response.result {
            base64::decode(&result_data).map_err(|e| FortressError::tee(
                format!("Failed to decode operation result: {}", e),
                "TeeAwareKeyManager::perform_operation".to_string()
            ))
        } else if let Some(signature) = response.signature {
            base64::decode(&signature).map_err(|e| FortressError::tee(
                format!("Failed to decode signature: {}", e),
                "TeeAwareKeyManager::perform_operation".to_string()
            ))
        } else {
            Ok(vec![]) // For operations like verify that return boolean result
        }
    }
    
    /// Rotate a key within the same or different enclave
    pub async fn rotate_key(
        &self,
        key_id: &str,
        new_algorithm: Option<String>,
        new_key_size: Option<u32>,
        rotation_reason: &str,
    ) -> Result<String> {
        let enclave_keys = self.enclave_keys.read().await;
        let key_info = enclave_keys.get(key_id)
            .ok_or_else(|| FortressError::tee(
                format!("Key not found: {}", key_id),
                "TeeAwareKeyManager::rotate_key".to_string()
            ))?;
        
        // Create rotation request
        let request = KeyRotationRequest {
            operation: "rotate_key".to_string(),
            current_key_id: key_id.to_string(),
            new_algorithm,
            new_key_size,
            rotation_reason: rotation_reason.to_string(),
        };
        
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| FortressError::tee(
                format!("Failed to serialize rotation request: {}", e),
                "TeeAwareKeyManager::rotate_key".to_string()
            ))?;
        
        // Send request to enclave
        let response = self.tee_manager.send_message(&key_info.enclave_id, &request_bytes).await?;
        
        // Parse response
        let response: KeyRotationResponse = serde_json::from_slice(&response)
            .map_err(|e| FortressError::tee(
                format!("Failed to deserialize rotation response: {}", e),
                "TeeAwareKeyManager::rotate_key".to_string()
            ))?;
        
        if !response.success {
            return Err(FortressError::tee(
                response.error.unwrap_or_else(|| "Key rotation failed".to_string()),
                "TeeAwareKeyManager::rotate_key".to_string()
            ));
        }
        
        let new_key_id = response.new_key_id.unwrap();
        
        // Update key status
        drop(enclave_keys);
        let mut enclave_keys = self.enclave_keys.write().await;
        if let Some(key_info) = enclave_keys.get_mut(key_id) {
            key_info.status = KeyStatus::PendingRotation;
        }
        
        Ok(new_key_id)
    }
    
    /// Destroy a key
    pub async fn destroy_key(&self, key_id: &str) -> Result<()> {
        let mut enclave_keys = self.enclave_keys.write().await;
        let key_info = enclave_keys.get_mut(key_id)
            .ok_or_else(|| FortressError::tee(
                format!("Key not found: {}", key_id),
                "TeeAwareKeyManager::destroy_key".to_string()
            ))?;
        
        // Mark key as destroying
        key_info.status = KeyStatus::Destroying;
        
        // Create destroy request
        let request = serde_json::json!({
            "operation": "destroy_key",
            "key_id": key_id
        });
        
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| FortressError::tee(
                format!("Failed to serialize destroy request: {}", e),
                "TeeAwareKeyManager::destroy_key".to_string()
            ))?;
        
        // Send request to enclave
        let response = self.tee_manager.send_message(&key_info.enclave_id, &request_bytes).await?;
        
        // Parse response
        let response: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| FortressError::tee(
                format!("Failed to deserialize destroy response: {}", e),
                "TeeAwareKeyManager::destroy_key".to_string()
            ))?;
        
        if response.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            // Mark key as destroyed
            key_info.status = KeyStatus::Destroyed;
            
            // Remove from active storage
            enclave_keys.remove(key_id);
            
            // Remove usage metrics
            let mut metrics = self.usage_metrics.write().await;
            metrics.remove(key_id);
            
            Ok(())
        } else {
            let error = response.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Key destruction failed");
            
            Err(FortressError::tee(
                error.to_string(),
                "TeeAwareKeyManager::destroy_key".to_string()
            ))
        }
    }
    
    /// List all enclave-protected keys
    pub async fn list_keys(&self) -> Vec<EnclaveKeyInfo> {
        let enclave_keys = self.enclave_keys.read().await;
        enclave_keys.values().cloned().collect()
    }
    
    /// Get key usage metrics
    pub async fn get_key_metrics(&self, key_id: &str) -> Option<KeyUsageMetrics> {
        let metrics = self.usage_metrics.read().await;
        metrics.get(key_id).cloned()
    }
    
    /// Get default policy for TEE type
    fn get_default_policy(&self, tee_type: TeeType) -> KeyPolicy {
        match tee_type {
            TeeType::AwsNitro => KeyPolicy {
                required_tee_type: TeeType::AwsNitro,
                min_key_size: 128,
                max_key_size: 4096,
                allowed_algorithms: vec![
                    "aes-256-gcm".to_string(),
                    "rsa-2048".to_string(),
                    "rsa-4096".to_string(),
                    "ecdsa-p256".to_string(),
                    "ecdsa-p384".to_string(),
                ],
                require_attestation: true,
                rotation_interval: Some(86400 * 30), // 30 days
                max_usage_count: None,
                access_control: vec![],
            },
            TeeType::IntelSgx => KeyPolicy {
                required_tee_type: TeeType::IntelSgx,
                min_key_size: 128,
                max_key_size: 4096,
                allowed_algorithms: vec![
                    "aes-256-gcm".to_string(),
                    "rsa-2048".to_string(),
                    "rsa-3072".to_string(),
                    "rsa-4096".to_string(),
                    "ecdsa-p256".to_string(),
                    "ecdsa-p384".to_string(),
                ],
                require_attestation: true,
                rotation_interval: Some(86400 * 30), // 30 days
                max_usage_count: None,
                access_control: vec![],
            },
            _ => KeyPolicy {
                required_tee_type: tee_type,
                min_key_size: 128,
                max_key_size: 256,
                allowed_algorithms: vec!["aes-256-gcm".to_string()],
                require_attestation: true,
                rotation_interval: Some(86400 * 30),
                max_usage_count: None,
                access_control: vec![],
            },
        }
    }
    
    /// Get enclave image path for TEE type
    fn get_enclave_image_path(&self, tee_type: &TeeType) -> Result<String> {
        match tee_type {
            TeeType::AwsNitro => Ok("/opt/fortress/enclaves/nitro-key-manager.eif".to_string()),
            TeeType::IntelSgx => Ok("/opt/fortress/enclaves/sgx-key-manager.so".to_string()),
            _ => Err(FortressError::tee(
                format!("Unsupported TEE type: {:?}", tee_type),
                "TeeAwareKeyManager::get_enclave_image_path".to_string(),
            )),
        }
    }
    
    /// Check if key needs rotation
    pub async fn needs_rotation(&self, key_id: &str) -> Result<bool> {
        let enclave_keys = self.enclave_keys.read().await;
        let key_info = enclave_keys.get(key_id)
            .ok_or_else(|| FortressError::tee(
                format!("Key not found: {}", key_id),
                "TeeAwareKeyManager::needs_rotation".to_string()
            ))?;
        
        // Check if key has policy with rotation interval
        if let Some(policy_name) = key_info.metadata.get("policy_name") {
            if let Some(policy) = self.key_policies.get(policy_name) {
                if let Some(rotation_interval) = policy.rotation_interval {
                    let age = (chrono::Utc::now() - key_info.created_at).num_seconds();
                    return Ok(age >= rotation_interval as i64);
                }
            }
        }
        
        Ok(false)
    }
    
    /// Get keys that need rotation
    pub async fn get_keys_needing_rotation(&self) -> Vec<String> {
        let enclave_keys = self.enclave_keys.read().await;
        let mut keys_needing_rotation = Vec::new();
        
        for (key_id, key_info) in enclave_keys.iter() {
            if key_info.status == KeyStatus::Active {
                if let Ok(needs_rotation) = self.needs_rotation(key_id).await {
                    if needs_rotation {
                        keys_needing_rotation.push(key_id.clone());
                    }
                }
            }
        }
        
        keys_needing_rotation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::{TeeManager, SecurityPolicy};
    
    #[tokio::test]
    async fn test_tee_aware_key_manager_creation() {
        let policy = SecurityPolicy::default();
        let tee_manager = Arc::new(TeeManager::new(policy));
        let key_manager = TeeAwareKeyManager::new(tee_manager);
        
        // Should be able to create manager
        let keys = key_manager.list_keys().await;
        assert!(keys.is_empty());
    }
    
    #[tokio::test]
    async fn test_key_policy() {
        let policy = KeyPolicy {
            required_tee_type: TeeType::AwsNitro,
            min_key_size: 2048,
            max_key_size: 4096,
            allowed_algorithms: vec!["rsa-2048".to_string(), "rsa-4096".to_string()],
            require_attestation: true,
            rotation_interval: Some(86400),
            max_usage_count: Some(1000),
            access_control: vec!["admin".to_string()],
        };
        
        assert_eq!(policy.min_key_size, 2048);
        assert!(policy.allowed_algorithms.contains(&"rsa-2048".to_string()));
        assert!(policy.require_attestation);
    }
    
    #[tokio::test]
    async fn test_key_status_transitions() {
        let mut status = KeyStatus::Active;
        assert_eq!(status, KeyStatus::Active);
        
        status = KeyStatus::PendingRotation;
        assert_eq!(status, KeyStatus::PendingRotation);
        
        status = KeyStatus::Destroyed;
        assert_eq!(status, KeyStatus::Destroyed);
    }
    
    #[tokio::test]
    async fn test_usage_metrics() {
        let mut metrics = KeyUsageMetrics {
            total_operations: 0,
            operations_by_type: HashMap::new(),
            last_operation: chrono::Utc::now(),
            avg_operation_duration_ms: 0.0,
            error_count: 0,
        };
        
        assert_eq!(metrics.total_operations, 0);
        assert_eq!(metrics.error_count, 0);
        
        // Simulate operation
        metrics.total_operations += 1;
        metrics.operations_by_type.insert("encrypt".to_string(), 1);
        metrics.avg_operation_duration_ms = 50.0;
        
        assert_eq!(metrics.total_operations, 1);
        assert_eq!(metrics.operations_by_type.get("encrypt"), Some(&1));
    }
    
    #[tokio::test]
    async fn test_default_policies() {
        let policy = SecurityPolicy::default();
        let tee_manager = Arc::new(TeeManager::new(policy));
        let key_manager = TeeAwareKeyManager::new(tee_manager);
        
        let nitro_policy = key_manager.get_default_policy(TeeType::AwsNitro);
        assert_eq!(nitro_policy.required_tee_type, TeeType::AwsNitro);
        assert!(nitro_policy.allowed_algorithms.contains(&"aes-256-gcm".to_string()));
        
        let sgx_policy = key_manager.get_default_policy(TeeType::IntelSgx);
        assert_eq!(sgx_policy.required_tee_type, TeeType::IntelSgx);
        assert!(sgx_policy.allowed_algorithms.contains(&"rsa-2048".to_string()));
    }
}
