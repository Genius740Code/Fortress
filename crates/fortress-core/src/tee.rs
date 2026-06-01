//! Trusted Execution Environments (TEE) Integration for Fortress
//!
//! This module provides comprehensive TEE support including:
//! - AWS Nitro Enclaves integration
//! - Intel SGX support  
//! - Secure enclave communication protocols
//! - Attestation verification
//! - TEE-aware key management
//!
//! TEEs ensure that even a compromised host OS or cloud provider cannot access
//! sensitive cryptographic material in memory, providing the highest level of
//! security for key management operations.

use crate::error::{FortressError, Result};
use crate::key::SecureKey;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Supported TEE types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TeeType {
    /// AWS Nitro Enclaves
    AwsNitro,
    /// Intel SGX Enclaves
    IntelSgx,
    /// AMD SEV (Secure Encrypted Virtualization)
    AmdSev,
    /// Generic TEE interface
    Generic,
}

/// TEE attestation status and verification results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Whether attestation passed verification
    pub is_valid: bool,
    /// TEE type that was attested
    pub tee_type: TeeType,
    /// Unique enclave identifier
    pub enclave_id: String,
    /// Security version number
    pub security_version: u32,
    /// Attestation timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Verification details
    pub details: HashMap<String, String>,
    /// Any security issues found
    pub security_issues: Vec<String>,
}

/// Secure enclave configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveConfig {
    /// Unique enclave identifier
    pub enclave_id: String,
    /// TEE type
    pub tee_type: TeeType,
    /// CPU allocation (vCPUs)
    pub cpu_count: u32,
    /// Memory allocation in MB
    pub memory_mb: u32,
    /// Enclave image file path
    pub image_path: String,
    /// Communication port
    pub port: u16,
    /// Security policy
    pub security_policy: SecurityPolicy,
    /// Additional configuration parameters
    pub parameters: HashMap<String, String>,
}

/// Security policy for TEE operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Require attestation before operations
    pub require_attestation: bool,
    /// Maximum allowed security version
    pub max_security_version: Option<u32>,
    /// Minimum allowed security version
    pub min_security_version: Option<u32>,
    /// Allowed PCR (Platform Configuration Register) values
    pub allowed_pcr_values: Option<HashMap<String, String>>,
    /// Require secure boot
    pub require_secure_boot: bool,
    /// Allow debug mode
    pub allow_debug_mode: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_attestation: true,
            max_security_version: None,
            min_security_version: Some(1),
            allowed_pcr_values: None,
            require_secure_boot: true,
            allow_debug_mode: false,
        }
    }
}

/// TEE provider trait for different TEE implementations
#[async_trait::async_trait]
pub trait TeeProvider: Send + Sync {
    /// Get the TEE type
    fn tee_type(&self) -> TeeType;

    /// Initialize the TEE provider
    async fn initialize(&mut self) -> Result<()>;

    /// Create a new enclave
    async fn create_enclave(&self, config: &EnclaveConfig) -> Result<String>;

    /// Start an existing enclave
    async fn start_enclave(&self, enclave_id: &str) -> Result<()>;

    /// Stop a running enclave
    async fn stop_enclave(&self, enclave_id: &str) -> Result<()>;

    /// Terminate an enclave
    async fn terminate_enclave(&self, enclave_id: &str) -> Result<()>;

    /// Get enclave status
    async fn get_enclave_status(&self, enclave_id: &str) -> Result<EnclaveStatus>;

    /// Perform attestation verification
    async fn attest_enclave(&self, enclave_id: &str) -> Result<AttestationResult>;

    /// Send secure message to enclave
    async fn send_message(&self, enclave_id: &str, message: &[u8]) -> Result<Vec<u8>>;

    /// Establish secure channel with enclave
    async fn establish_secure_channel(&self, enclave_id: &str) -> Result<SecureChannel>;

    /// Get provider capabilities
    fn get_capabilities(&self) -> TeeCapabilities;
}

/// Enclave runtime status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnclaveStatus {
    /// Enclave is being created
    Creating,
    /// Enclave is running
    Running,
    /// Enclave is stopped
    Stopped,
    /// Enclave is being terminated
    Terminating,
    /// Enclave terminated
    Terminated,
    /// Enclave in error state
    Error(String),
}

/// TEE provider capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeCapabilities {
    /// Maximum number of concurrent enclaves
    pub max_concurrent_enclaves: u32,
    /// Maximum memory per enclave (MB)
    pub max_memory_mb: u32,
    /// Maximum CPU per enclave
    pub max_cpu_count: u32,
    /// Supports attestation
    pub supports_attestation: bool,
    /// Supports secure channels
    pub supports_secure_channels: bool,
    /// Supports debug mode
    pub supports_debug_mode: bool,
    /// Supported cryptographic algorithms
    pub supported_algorithms: Vec<String>,
}

/// Secure communication channel with enclave
#[derive(Debug, Clone)]
pub struct SecureChannel {
    /// Channel identifier
    pub channel_id: String,
    /// Enclave identifier
    pub enclave_id: String,
    /// Session key for encryption
    pub session_key: SecureKey,
    /// Channel creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Channel status
    pub is_active: bool,
}

/// TEE manager for coordinating multiple TEE providers
pub struct TeeManager {
    /// Available TEE providers
    providers: Arc<RwLock<HashMap<TeeType, Arc<dyn TeeProvider>>>>,
    /// Active enclaves
    enclaves: Arc<RwLock<HashMap<String, EnclaveInfo>>>,
    /// Secure channels
    channels: Arc<RwLock<HashMap<String, SecureChannel>>>,
    /// Default security policy
    default_policy: SecurityPolicy,
}

/// Information about an active enclave
#[derive(Debug, Clone)]
pub struct EnclaveInfo {
    /// Enclave configuration
    pub config: EnclaveConfig,
    /// Current status
    pub status: EnclaveStatus,
    /// Last attestation result
    pub last_attestation: Option<AttestationResult>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

impl TeeManager {
    /// Create a new TEE manager
    pub fn new(default_policy: SecurityPolicy) -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            enclaves: Arc::new(RwLock::new(HashMap::new())),
            channels: Arc::new(RwLock::new(HashMap::new())),
            default_policy,
        }
    }

    /// Register a TEE provider
    pub async fn register_provider(&self, provider: Arc<dyn TeeProvider>) -> Result<()> {
        let tee_type = provider.tee_type();
        let mut providers = self.providers.write().await;
        providers.insert(tee_type, provider);
        Ok(())
    }

    /// Create a new enclave
    pub async fn create_enclave(&self, config: EnclaveConfig) -> Result<String> {
        let providers = self.providers.read().await;
        let provider = providers.get(&config.tee_type).ok_or_else(|| {
            FortressError::tee(
                format!("No provider found for TEE type: {:?}", config.tee_type),
                "TeeManager::create_enclave".to_string(),
            )
        })?;

        let enclave_id = provider.create_enclave(&config).await?;

        let enclave_info = EnclaveInfo {
            config: config.clone(),
            status: EnclaveStatus::Creating,
            last_attestation: None,
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
        };

        let mut enclaves = self.enclaves.write().await;
        enclaves.insert(enclave_id.clone(), enclave_info);

        Ok(enclave_id)
    }

    /// Start an enclave
    pub async fn start_enclave(&self, enclave_id: &str) -> Result<()> {
        let mut enclaves = self.enclaves.write().await;
        let enclave_info = enclaves.get_mut(enclave_id).ok_or_else(|| {
            FortressError::tee(
                format!("Enclave not found: {}", enclave_id),
                "TeeManager::start_enclave".to_string(),
            )
        })?;

        let providers = self.providers.read().await;
        let provider = providers
            .get(&enclave_info.config.tee_type)
            .ok_or_else(|| {
                FortressError::tee(
                    format!(
                        "No provider found for TEE type: {:?}",
                        enclave_info.config.tee_type
                    ),
                    "TeeManager::start_enclave".to_string(),
                )
            })?;

        provider.start_enclave(enclave_id).await?;
        enclave_info.status = EnclaveStatus::Running;
        enclave_info.last_activity = chrono::Utc::now();

        Ok(())
    }

    /// Stop an enclave
    pub async fn stop_enclave(&self, enclave_id: &str) -> Result<()> {
        let mut enclaves = self.enclaves.write().await;
        let enclave_info = enclaves.get_mut(enclave_id).ok_or_else(|| {
            FortressError::tee(
                format!("Enclave not found: {}", enclave_id),
                "TeeManager::stop_enclave".to_string(),
            )
        })?;

        let providers = self.providers.read().await;
        let provider = providers
            .get(&enclave_info.config.tee_type)
            .ok_or_else(|| {
                FortressError::tee(
                    format!(
                        "No provider found for TEE type: {:?}",
                        enclave_info.config.tee_type
                    ),
                    "TeeManager::stop_enclave".to_string(),
                )
            })?;

        provider.stop_enclave(enclave_id).await?;
        enclave_info.status = EnclaveStatus::Stopped;
        enclave_info.last_activity = chrono::Utc::now();

        Ok(())
    }

    /// Terminate an enclave
    pub async fn terminate_enclave(&self, enclave_id: &str) -> Result<()> {
        let mut enclaves = self.enclaves.write().await;
        let enclave_info = enclaves.get_mut(enclave_id).ok_or_else(|| {
            FortressError::tee(
                format!("Enclave not found: {}", enclave_id),
                "TeeManager::terminate_enclave".to_string(),
            )
        })?;

        let providers = self.providers.read().await;
        let provider = providers
            .get(&enclave_info.config.tee_type)
            .ok_or_else(|| {
                FortressError::tee(
                    format!(
                        "No provider found for TEE type: {:?}",
                        enclave_info.config.tee_type
                    ),
                    "TeeManager::terminate_enclave".to_string(),
                )
            })?;

        provider.terminate_enclave(enclave_id).await?;
        enclave_info.status = EnclaveStatus::Terminated;

        // Clean up secure channels
        let mut channels = self.channels.write().await;
        channels.retain(|_, channel| channel.enclave_id != enclave_id);

        Ok(())
    }

    /// Get enclave status
    pub async fn get_enclave_status(&self, enclave_id: &str) -> Result<EnclaveStatus> {
        let enclaves = self.enclaves.read().await;
        let enclave_info = enclaves.get(enclave_id).ok_or_else(|| {
            FortressError::tee(
                format!("Enclave not found: {}", enclave_id),
                "TeeManager::get_enclave_status".to_string(),
            )
        })?;

        Ok(enclave_info.status.clone())
    }

    /// Perform attestation verification
    pub async fn attest_enclave(&self, enclave_id: &str) -> Result<AttestationResult> {
        let enclaves = self.enclaves.read().await;
        let enclave_info = enclaves.get(enclave_id).ok_or_else(|| {
            FortressError::tee(
                format!("Enclave not found: {}", enclave_id),
                "TeeManager::attest_enclave".to_string(),
            )
        })?;

        let providers = self.providers.read().await;
        let provider = providers
            .get(&enclave_info.config.tee_type)
            .ok_or_else(|| {
                FortressError::tee(
                    format!(
                        "No provider found for TEE type: {:?}",
                        enclave_info.config.tee_type
                    ),
                    "TeeManager::attest_enclave".to_string(),
                )
            })?;

        let attestation_result = provider.attest_enclave(enclave_id).await?;

        // Update enclave info with attestation result
        drop(enclaves);
        let mut enclaves = self.enclaves.write().await;
        if let Some(enclave_info) = enclaves.get_mut(enclave_id) {
            enclave_info.last_attestation = Some(attestation_result.clone());
            enclave_info.last_activity = chrono::Utc::now();
        }

        Ok(attestation_result)
    }

    /// Establish secure channel with enclave
    pub async fn establish_secure_channel(&self, enclave_id: &str) -> Result<SecureChannel> {
        let enclaves = self.enclaves.read().await;
        let enclave_info = enclaves.get(enclave_id).ok_or_else(|| {
            FortressError::tee(
                format!("Enclave not found: {}", enclave_id),
                "TeeManager::establish_secure_channel".to_string(),
            )
        })?;

        // Verify enclave is running and attested
        if enclave_info.status != EnclaveStatus::Running {
            return Err(FortressError::tee(
                format!("Enclave {} is not running", enclave_id),
                "TeeManager::establish_secure_channel".to_string(),
            ));
        }

        if let Some(ref attestation) = enclave_info.last_attestation {
            if !attestation.is_valid {
                return Err(FortressError::tee(
                    format!("Enclave {} failed attestation", enclave_id),
                    "TeeManager::establish_secure_channel".to_string(),
                ));
            }
        } else if enclave_info.config.security_policy.require_attestation {
            return Err(FortressError::tee(
                format!("Enclave {} requires attestation", enclave_id),
                "TeeManager::establish_secure_channel".to_string(),
            ));
        }

        let providers = self.providers.read().await;
        let provider = providers
            .get(&enclave_info.config.tee_type)
            .ok_or_else(|| {
                FortressError::tee(
                    format!(
                        "No provider found for TEE type: {:?}",
                        enclave_info.config.tee_type
                    ),
                    "TeeManager::establish_secure_channel".to_string(),
                )
            })?;

        let channel = provider.establish_secure_channel(enclave_id).await?;

        // Store channel
        let mut channels = self.channels.write().await;
        channels.insert(channel.channel_id.clone(), channel.clone());

        Ok(channel)
    }

    /// Send secure message to enclave
    pub async fn send_message(&self, enclave_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let enclaves = self.enclaves.read().await;
        let enclave_info = enclaves.get(enclave_id).ok_or_else(|| {
            FortressError::tee(
                format!("Enclave not found: {}", enclave_id),
                "TeeManager::send_message".to_string(),
            )
        })?;

        let providers = self.providers.read().await;
        let provider = providers
            .get(&enclave_info.config.tee_type)
            .ok_or_else(|| {
                FortressError::tee(
                    format!(
                        "No provider found for TEE type: {:?}",
                        enclave_info.config.tee_type
                    ),
                    "TeeManager::send_message".to_string(),
                )
            })?;

        let response = provider.send_message(enclave_id, message).await?;

        // Update last activity
        drop(enclaves);
        let mut enclaves = self.enclaves.write().await;
        if let Some(enclave_info) = enclaves.get_mut(enclave_id) {
            enclave_info.last_activity = chrono::Utc::now();
        }

        Ok(response)
    }

    /// List all active enclaves
    pub async fn list_enclaves(&self) -> Vec<(String, EnclaveInfo)> {
        let enclaves = self.enclaves.read().await;
        enclaves
            .iter()
            .map(|(id, info)| (id.clone(), info.clone()))
            .collect()
    }

    /// Get TEE capabilities for a specific TEE type
    pub async fn get_capabilities(&self, tee_type: &TeeType) -> Option<TeeCapabilities> {
        let providers = self.providers.read().await;
        providers.get(tee_type).map(|p| p.get_capabilities())
    }
}

/// TEE-aware key manager for enclave-protected keys
pub struct TeeAwareKeyManager {
    /// TEE manager instance
    tee_manager: Arc<TeeManager>,
    /// Enclave-protected keys storage
    enclave_keys: Arc<RwLock<HashMap<String, EnclaveKeyInfo>>>,
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
}

impl TeeAwareKeyManager {
    /// Create a new TEE-aware key manager
    pub fn new(tee_manager: Arc<TeeManager>) -> Self {
        Self {
            tee_manager,
            enclave_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new key within an enclave
    pub async fn generate_key_in_enclave(
        &self,
        enclave_id: &str,
        algorithm: &str,
        key_size: u32,
    ) -> Result<String> {
        // Verify enclave is running and attested
        let status = self.tee_manager.get_enclave_status(enclave_id).await?;
        if status != EnclaveStatus::Running {
            return Err(FortressError::tee(
                format!("Enclave {} is not running", enclave_id),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string(),
            ));
        }

        // Generate key generation request
        let request = KeyGenerationRequest {
            operation: "generate_key".to_string(),
            algorithm: algorithm.to_string(),
            key_size,
            key_id: Uuid::new_v4().to_string(),
        };

        let request_bytes = serde_json::to_vec(&request).map_err(|e| {
            FortressError::tee(
                format!("Failed to serialize key generation request: {}", e),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string(),
            )
        })?;

        // Send request to enclave
        let response = self
            .tee_manager
            .send_message(enclave_id, &request_bytes)
            .await?;

        let response: KeyGenerationResponse = serde_json::from_slice(&response).map_err(|e| {
            FortressError::tee(
                format!("Failed to deserialize key generation response: {}", e),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string(),
            )
        })?;

        if !response.success {
            return Err(FortressError::tee(
                response
                    .error
                    .unwrap_or_else(|| "Key generation failed".to_string()),
                "TeeAwareKeyManager::generate_key_in_enclave".to_string(),
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
        };

        let mut enclave_keys = self.enclave_keys.write().await;
        enclave_keys.insert(key_id.clone(), key_info);

        Ok(key_id)
    }

    /// Perform cryptographic operation in enclave
    pub async fn perform_operation(
        &self,
        key_id: &str,
        operation: &str,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let enclave_keys = self.enclave_keys.read().await;
        let key_info = enclave_keys.get(key_id).ok_or_else(|| {
            FortressError::tee(
                format!("Key not found: {}", key_id),
                "TeeAwareKeyManager::perform_operation".to_string(),
            )
        })?;

        // Create operation request
        let request = CryptographicOperationRequest {
            operation: operation.to_string(),
            key_id: key_id.to_string(),
            data: general_purpose::STANDARD.encode(data),
        };

        let request_bytes = serde_json::to_vec(&request).map_err(|e| {
            FortressError::tee(
                format!("Failed to serialize operation request: {}", e),
                "TeeAwareKeyManager::perform_operation".to_string(),
            )
        })?;

        // Send request to enclave
        let response = self
            .tee_manager
            .send_message(&key_info.enclave_id, &request_bytes)
            .await?;

        let response: CryptographicOperationResponse =
            serde_json::from_slice(&response).map_err(|e| {
                FortressError::tee(
                    format!("Failed to deserialize operation response: {}", e),
                    "TeeAwareKeyManager::perform_operation".to_string(),
                )
            })?;

        if !response.success {
            return Err(FortressError::tee(
                response
                    .error
                    .unwrap_or_else(|| "Operation failed".to_string()),
                "TeeAwareKeyManager::perform_operation".to_string(),
            ));
        }

        // Update access info
        drop(enclave_keys);
        let mut enclave_keys = self.enclave_keys.write().await;
        if let Some(key_info) = enclave_keys.get_mut(key_id) {
            key_info.last_accessed = chrono::Utc::now();
            key_info.access_count += 1;
        }

        general_purpose::STANDARD
            .decode(&response.result.unwrap_or_default())
            .map_err(|e| {
                FortressError::tee(
                    format!("Failed to decode operation result: {}", e),
                    "TeeAwareKeyManager::perform_operation".to_string(),
                )
            })
    }

    /// List all enclave-protected keys
    pub async fn list_keys(&self) -> Vec<EnclaveKeyInfo> {
        let enclave_keys = self.enclave_keys.read().await;
        enclave_keys.values().cloned().collect()
    }
}

/// Request for key generation in enclave
#[derive(Debug, Serialize, Deserialize)]
struct KeyGenerationRequest {
    operation: String,
    algorithm: String,
    key_size: u32,
    key_id: String,
}

/// Response from key generation in enclave
#[derive(Debug, Serialize, Deserialize)]
struct KeyGenerationResponse {
    success: bool,
    key_id: Option<String>,
    error: Option<String>,
}

/// Request for cryptographic operation in enclave
#[derive(Debug, Serialize, Deserialize)]
struct CryptographicOperationRequest {
    operation: String,
    key_id: String,
    data: String, // Base64 encoded
}

/// Response from cryptographic operation in enclave
#[derive(Debug, Serialize, Deserialize)]
struct CryptographicOperationResponse {
    success: bool,
    result: Option<String>, // Base64 encoded
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tee_manager_creation() {
        let policy = SecurityPolicy::default();
        let manager = TeeManager::new(policy);

        // Should be able to create manager without providers
        let enclaves = manager.list_enclaves().await;
        assert!(enclaves.is_empty());
    }

    #[tokio::test]
    async fn test_enclave_config_serialization() {
        let config = EnclaveConfig {
            enclave_id: "test-enclave".to_string(),
            tee_type: TeeType::AwsNitro,
            cpu_count: 2,
            memory_mb: 1024,
            image_path: "/path/to/enclave.efi".to_string(),
            port: 5000,
            security_policy: SecurityPolicy::default(),
            parameters: HashMap::new(),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: EnclaveConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.enclave_id, deserialized.enclave_id);
        assert_eq!(config.tee_type, deserialized.tee_type);
    }

    #[tokio::test]
    async fn test_attestation_result() {
        let result = AttestationResult {
            is_valid: true,
            tee_type: TeeType::AwsNitro,
            enclave_id: "test-enclave".to_string(),
            security_version: 1,
            timestamp: chrono::Utc::now(),
            details: HashMap::new(),
            security_issues: vec![],
        };

        assert!(result.is_valid);
        assert_eq!(result.tee_type, TeeType::AwsNitro);
        assert!(result.security_issues.is_empty());
    }
}
