//! Hardware Security Module (HSM) support
//!
//! This module provides HSM integration for Fortress, allowing keys to be stored
//! and managed in hardware security modules for enhanced security.

use crate::error::{FortressError, Result, KeyErrorCode};
use crate::key::{KeyId, KeyMetadata};
use crate::encryption::EncryptionAlgorithm;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use pkcs11::{Ctx, CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, 
             CK_SESSION_FLAGS, CK_USER_TYPE, CK_ATTRIBUTE_TYPE};

/// HSM provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// HSM provider type
    pub provider: HsmProviderType,
    /// Connection details specific to the provider
    pub connection: HsmConnection,
    /// Authentication credentials
    pub credentials: HsmCredentials,
    /// Key storage settings
    pub key_settings: HsmKeySettings,
}

/// HSM provider types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmProviderType {
    /// AWS CloudHSM
    AwsCloudHsm,
    /// Generic PKCS#11 compliant HSM
    Pkcs11,
    /// Azure Dedicated HSM
    AzureDedicatedHsm,
    /// Google Cloud HSM
    GoogleCloudHsm,
}

/// HSM connection details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmConnection {
    /// AWS CloudHSM cluster configuration
    AwsCloudHsm { 
        /// Cluster identifier
        cluster_id: String 
    },
    /// PKCS#11 library configuration
    Pkcs11 { 
        /// Path to PKCS#11 library
        library_path: String,
        /// Slot identifier
        slot_id: Option<u64>,
        /// Token label
        token_label: Option<String>,
    },
    /// Azure Dedicated HSM configuration
    Azure { 
        /// Resource identifier
        resource_id: String 
    },
    /// Google Cloud HSM configuration
    Google { 
        /// Project identifier
        project_id: String,
        /// Location
        location: String,
        /// Key ring name
        key_ring: String,
    },
}

/// HSM authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmCredentials {
    /// AWS CloudHSM credentials
    Aws { 
        /// AWS access key ID
        access_key_id: String,
        /// AWS secret access key
        secret_access_key: String,
        /// AWS region
        region: String,
    },
    /// PKCS#11 PIN and optional user type
    Pkcs11 { 
        /// PIN for token access
        pin: String,
        /// User type for authentication
        user_type: Pkcs11UserType,
    },
    /// Azure authentication
    Azure { 
        /// Azure client ID
        client_id: String,
        /// Azure client secret
        client_secret: String,
        /// Azure tenant ID
        tenant_id: String,
    },
    /// Google Cloud authentication
    Google { 
        /// Service account key
        service_account_key: String,
    },
}

/// PKCS#11 user types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Pkcs11UserType {
    /// Security Officer (SO)
    SecurityOfficer,
    /// Regular User
    User,
}

/// HSM key storage settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeySettings {
    /// Key template attributes
    pub key_template: HashMap<String, String>,
    /// Whether keys should be extractable
    pub extractable: bool,
    /// Key sensitivity settings
    pub sensitive: bool,
    /// Default key size for generation
    pub default_key_size: usize,
}

impl Default for HsmKeySettings {
    fn default() -> Self {
        let mut key_template = HashMap::new();
        key_template.insert("token".to_string(), "true".to_string());
        key_template.insert("private".to_string(), "true".to_string());
        
        Self {
            key_template,
            extractable: false,
            sensitive: true,
            default_key_size: 256,
        }
    }
}

/// HSM provider trait for different HSM implementations
#[async_trait]
pub trait HsmProvider: Send + Sync {
    /// Initialize connection to HSM
    async fn initialize(&self, config: &HsmConfig) -> Result<()>;
    
    /// Generate a new key in HSM
    async fn generate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()>;
    
    /// Retrieve key metadata from HSM
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata>;
    
    /// Delete a key from HSM
    async fn delete_key(&self, key_id: &KeyId) -> Result<()>;
    
    /// List all keys in HSM
    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>>;
    
    /// Perform cryptographic operation using HSM key
    async fn sign(&self, key_id: &KeyId, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Verify signature using HSM key
    async fn verify(&self, key_id: &KeyId, data: &[u8], signature: &[u8]) -> Result<bool>;
    
    /// Encrypt data using HSM key
    async fn encrypt(&self, key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data using HSM key
    async fn decrypt(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<Vec<u8>>;
    
    /// Check if HSM is healthy and accessible
    async fn health_check(&self) -> Result<bool>;
    
    /// Close connection to HSM
    async fn shutdown(&self) -> Result<()>;
}

/// HSM-backed key manager that integrates with the existing KeyManager trait
pub struct HsmKeyManager {
    /// HSM configuration
    #[allow(dead_code)]
    config: HsmConfig,
    provider: Arc<dyn HsmProvider>,
    /// Cache for key metadata to reduce HSM calls
    /// Cache for key metadata to reduce HSM calls
    #[allow(dead_code)]
    metadata_cache: Arc<RwLock<HashMap<KeyId, KeyMetadata>>>,
}

impl HsmKeyManager {
    /// Create a new HSM-backed key manager
    pub async fn new(config: HsmConfig) -> Result<Self> {
        let provider: Arc<dyn HsmProvider> = match config.provider {
            HsmProviderType::AwsCloudHsm => {
                Arc::new(AwsCloudHsmProvider::new().await?)
            }
            HsmProviderType::Pkcs11 => {
                Arc::new(Pkcs11Provider::new().await?)
            }
            HsmProviderType::AzureDedicatedHsm => {
                return Err(FortressError::key_management(
                    "Azure HSM provider not yet implemented".to_string(),
                    None,
                    crate::error::KeyErrorCode::ProviderError,
                ));
            }
            HsmProviderType::GoogleCloudHsm => {
                return Err(FortressError::key_management(
                    "Google Cloud HSM provider not yet implemented".to_string(),
                    None,
                    crate::error::KeyErrorCode::ProviderError,
                ));
            }
        };
        
        provider.initialize(&config).await?;
        
        Ok(Self {
            config,
            provider,
            metadata_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Get reference to the underlying HSM provider
    pub fn provider(&self) -> &dyn HsmProvider {
        self.provider.as_ref()
    }
}

/// AWS CloudHSM provider implementation
pub struct AwsCloudHsmProvider;
/// PKCS#11 provider implementation
pub struct Pkcs11Provider {
    /// PKCS#11 context
    ctx: Arc<RwLock<Option<Ctx>>>,
    /// Session handle
    session: Arc<RwLock<Option<CK_OBJECT_HANDLE>>>,
    /// Slot ID
    slot_id: Arc<RwLock<Option<u64>>>,
    /// Library path
    library_path: Arc<RwLock<Option<String>>>,
    /// Token label
    token_label: Arc<RwLock<Option<String>>>,
    /// Is initialized
    initialized: Arc<RwLock<bool>>,
}

impl AwsCloudHsmProvider {
    /// Create a new AWS CloudHSM provider
    pub async fn new() -> Result<Self> {
        // TODO: Initialize AWS CloudHSM client
        Ok(Self)
    }
}

#[async_trait]
impl HsmProvider for AwsCloudHsmProvider {
    async fn initialize(&self, config: &HsmConfig) -> Result<()> {
        match &config.connection {
            HsmConnection::AwsCloudHsm { cluster_id } => {
                // Initialize AWS CloudHSM client with cluster ID
                log::info!("Initializing AWS CloudHSM for cluster: {}", cluster_id);
                
                // TODO: Set up AWS client configuration
                match &config.credentials {
                    HsmCredentials::Aws { access_key_id: _, secret_access_key: _, region } => {
                        // TODO: Configure AWS credentials
                        log::info!("Configuring AWS CloudHSM credentials for region: {}", region);
                    }
                    _ => {
                        return Err(FortressError::key_management(
                            "Invalid credentials for AWS CloudHSM".to_string(),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }
                }
                
                Ok(())
            }
            _ => Err(FortressError::key_management(
                "Invalid connection configuration for AWS CloudHSM".to_string(),
                None,
                KeyErrorCode::ProviderError,
            )),
        }
    }
    
    async fn generate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
        log::info!("Generating key {} in AWS CloudHSM with algorithm: {}", key_id, algorithm.name());
        
        // TODO: Implement AWS CloudHSM key generation
        // This would use the AWS CloudHSM API to create a new key
        
        Ok(())
    }
    
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata> {
        log::info!("Retrieving metadata for key {} from AWS CloudHSM", key_id);
        
        // TODO: Implement AWS CloudHSM key metadata retrieval
        // This would query AWS CloudHSM for key attributes
        
        let metadata = KeyMetadata::new(
            key_id.clone(),
            "AES-256-GCM".to_string(),
            1,
            chrono::Utc::now(),
            chrono::Utc::now() + chrono::Duration::days(90),
            "encryption".to_string(),
            crate::encryption::PerformanceProfile::Balanced,
        );
        
        Ok(metadata)
    }
    
    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        log::info!("Deleting key {} from AWS CloudHSM", key_id);
        
        // TODO: Implement AWS CloudHSM key deletion
        // This would use the AWS CloudHSM API to delete the key
        
        Ok(())
    }
    
    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        log::info!("Listing keys from AWS CloudHSM");
        
        // TODO: Implement AWS CloudHSM key listing
        // This would query AWS CloudHSM for all keys
        
        Ok(vec![]) // Return empty list for now
    }
    
    async fn sign(&self, key_id: &KeyId, _data: &[u8]) -> Result<Vec<u8>> {
        log::info!("Signing data with key {} using AWS CloudHSM", key_id);
        
        // TODO: Implement AWS CloudHSM signing
        // This would use the AWS CloudHSM API to sign data
        
        Ok(vec![]) // Return empty signature for now
    }
    
    async fn verify(&self, key_id: &KeyId, _data: &[u8], _signature: &[u8]) -> Result<bool> {
        log::info!("Verifying signature with key {} using AWS CloudHSM", key_id);
        
        // TODO: Implement AWS CloudHSM verification
        // This would use the AWS CloudHSM API to verify the signature
        
        Ok(false) // Return false for now
    }
    
    async fn encrypt(&self, key_id: &KeyId, _plaintext: &[u8]) -> Result<Vec<u8>> {
        log::info!("Encrypting data with key {} using AWS CloudHSM", key_id);
        
        // TODO: Implement AWS CloudHSM encryption
        // This would use the AWS CloudHSM API to encrypt data
        
        Ok(vec![]) // Return empty ciphertext for now
    }
    
    async fn decrypt(&self, key_id: &KeyId, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        log::info!("Decrypting data with key {} using AWS CloudHSM", key_id);
        
        // TODO: Implement AWS CloudHSM decryption
        // This would use the AWS CloudHSM API to decrypt data
        
        Ok(vec![]) // Return empty plaintext for now
    }
    
    async fn health_check(&self) -> Result<bool> {
        log::info!("Performing AWS CloudHSM health check");
        
        // TODO: Implement AWS CloudHSM health check
        // This would check if the CloudHSM cluster is accessible
        
        Ok(true) // Return healthy for now
    }
    
    async fn shutdown(&self) -> Result<()> {
        log::info!("Shutting down AWS CloudHSM provider");
        
        // TODO: Implement AWS CloudHSM cleanup
        // This would clean up any resources
        
        Ok(())
    }
}

impl Pkcs11Provider {
    /// Create a new PKCS#11 provider
    pub async fn new() -> Result<Self> {
        log::info!("Initializing PKCS#11 provider");
        
        // Initialize PKCS#11 context - defer library loading until initialize()
        Ok(Self {
            ctx: Arc::new(RwLock::new(None)),
            session: Arc::new(RwLock::new(None)),
            slot_id: Arc::new(RwLock::new(None)),
            library_path: Arc::new(RwLock::new(None)),
            token_label: Arc::new(RwLock::new(None)),
            initialized: Arc::new(RwLock::new(false)),
        })
    }

    /// Get the current session handle
    async fn get_session(&self) -> Result<CK_OBJECT_HANDLE> {
        let session_guard = self.session.read().await;
        match *session_guard {
            Some(session) => Ok(session),
            None => Err(FortressError::key_management(
                "No active PKCS#11 session".to_string(),
                None,
                KeyErrorCode::ProviderError,
            )),
        }
    }

    /// Get the current PKCS#11 context
    async fn get_context(&self) -> Result<Ctx> {
        let ctx_guard = self.ctx.read().await;
        match ctx_guard.as_ref() {
            Some(_) => {
                // For now, create a new context since Ctx doesn't implement Clone
                // In a real implementation, we'd store the context differently
                let library_path_guard = self.library_path.read().await;
                if let Some(path) = library_path_guard.as_ref() {
                    match Ctx::new(path) {
                        Ok(ctx) => Ok(ctx),
                        Err(e) => Err(FortressError::key_management(
                            format!("Failed to create PKCS#11 context: {}", e),
                            None,
                            KeyErrorCode::ProviderError,
                        ))
                    }
                } else {
                    Err(FortressError::key_management(
                        "PKCS#11 library path not set".to_string(),
                        None,
                        KeyErrorCode::ProviderError,
                    ))
                }
            }
            None => Err(FortressError::key_management(
                "PKCS#11 context not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            )),
        }
    }

    /// Find slot by token label
    async fn find_slot_by_label(&self, ctx: &mut Ctx, label: &str) -> Result<u64> {
        let slots = match ctx.get_slot_list(true) {
            Ok(slots) => slots,
            Err(e) => {
                return Err(FortressError::key_management(
                    format!("Failed to get slot list: {}", e),
                    None,
                    KeyErrorCode::ProviderError,
                ));
            }
        };

        for slot in slots {
            let token_info = match ctx.get_token_info(slot) {
                Ok(info) => info,
                Err(_) => continue, // Skip slots we can't read
            };

            // Convert the blank-padded string to regular string
            let token_label_bytes = &token_info.label;
            let token_label_str = std::str::from_utf8(token_label_bytes)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();

            if token_label_str == label {
                log::info!("Found token '{}' in slot {}", label, slot);
                return Ok(slot as u64);
            }
        }

        Err(FortressError::key_management(
            format!("Token with label '{}' not found", label),
            None,
            KeyErrorCode::ProviderError,
        ))
    }

    /// Convert algorithm to PKCS#11 mechanism
    fn algorithm_to_mechanism(algorithm: &dyn EncryptionAlgorithm) -> CK_MECHANISM {
        match algorithm.name().to_lowercase().as_str() {
            "aes-256-gcm" => CK_MECHANISM {
                mechanism: CK_MECHANISM_TYPE::CKM_AES_GCM,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            "aes-256-cbc" => CK_MECHANISM {
                mechanism: CK_MECHANISM_TYPE::CKM_AES_CBC,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            "chacha20poly1305" => CK_MECHANISM {
                mechanism: CK_MECHANISM_TYPE::CKM_CHACHA20_POLY1305,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            _ => CK_MECHANISM {
                mechanism: CK_MECHANISM_TYPE::CKM_AES_GCM, // Default fallback
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
        }
    }

    /// Generate key template based on algorithm
    fn generate_key_template(algorithm: &dyn EncryptionAlgorithm, key_id: &KeyId) -> Vec<CK_ATTRIBUTE> {
        let mut template = vec![
            CK_ATTRIBUTE {
                type_: CK_ATTRIBUTE_TYPE::CKA_CLASS,
                pValue: Box::into_raw(Box::new(CK_OBJECT_CLASS::CKO_SECRET_KEY as u64)) as *mut std::ffi::c_void,
                ulValueLen: std::mem::size_of::<u64>() as u64,
            },
            CK_ATTRIBUTE {
                type_: CK_ATTRIBUTE_TYPE::CKA_TOKEN,
                pValue: Box::into_raw(Box::new(1u8)) as *mut std::ffi::c_void,
                ulValueLen: 1,
            },
            CK_ATTRIBUTE {
                type_: CK_ATTRIBUTE_TYPE::CKA_PRIVATE,
                pValue: Box::into_raw(Box::new(1u8)) as *mut std::ffi::c_void,
                ulValueLen: 1,
            },
            CK_ATTRIBUTE {
                type_: CK_ATTRIBUTE_TYPE::CKA_SENSITIVE,
                pValue: Box::into_raw(Box::new(1u8)) as *mut std::ffi::c_void,
                ulValueLen: 1,
            },
            CK_ATTRIBUTE {
                type_: CK_ATTRIBUTE_TYPE::CKA_EXTRACTABLE,
                pValue: Box::into_raw(Box::new(0u8)) as *mut std::ffi::c_void,
                ulValueLen: 1,
            },
        ];

        // Add key ID and label
        let key_id_bytes = key_id.as_bytes();
        template.push(CK_ATTRIBUTE {
            type_: CK_ATTRIBUTE_TYPE::CKA_ID,
            pValue: Box::into_raw(key_id_bytes.to_vec().into_boxed_slice()) as *mut std::ffi::c_void,
            ulValueLen: key_id_bytes.len() as u64,
        });
        template.push(CK_ATTRIBUTE {
            type_: CK_ATTRIBUTE_TYPE::CKA_LABEL,
            pValue: Box::into_raw(key_id_bytes.to_vec().into_boxed_slice()) as *mut std::ffi::c_void,
            ulValueLen: key_id_bytes.len() as u64,
        });

        // Add key type and value length based on algorithm
        match algorithm.name().to_lowercase().as_str() {
            "aes-256-gcm" | "aes-256-cbc" => {
                template.push(CK_ATTRIBUTE {
                    type_: CK_ATTRIBUTE_TYPE::CKA_KEY_TYPE,
                    pValue: Box::into_raw(Box::new(CK_MECHANISM_TYPE::CKK_AES as u64)) as *mut std::ffi::c_void,
                    ulValueLen: std::mem::size_of::<u64>() as u64,
                });
                template.push(CK_ATTRIBUTE {
                    type_: CK_ATTRIBUTE_TYPE::CKA_VALUE_LEN,
                    pValue: Box::into_raw(Box::new(32u64)) as *mut std::ffi::c_void,
                    ulValueLen: std::mem::size_of::<u64>() as u64,
                });
            }
            "chacha20poly1305" => {
                template.push(CK_ATTRIBUTE {
                    type_: CK_ATTRIBUTE_TYPE::CKA_KEY_TYPE,
                    pValue: Box::into_raw(Box::new(CK_MECHANISM_TYPE::CKK_AES as u64)) as *mut std::ffi::c_void, // Fallback
                    ulValueLen: std::mem::size_of::<u64>() as u64,
                });
                template.push(CK_ATTRIBUTE {
                    type_: CK_ATTRIBUTE_TYPE::CKA_VALUE_LEN,
                    pValue: Box::into_raw(Box::new(32u64)) as *mut std::ffi::c_void,
                    ulValueLen: std::mem::size_of::<u64>() as u64,
                });
            }
            _ => {
                template.push(CK_ATTRIBUTE {
                    type_: CK_ATTRIBUTE_TYPE::CKA_KEY_TYPE,
                    pValue: Box::into_raw(Box::new(CK_MECHANISM_TYPE::CKK_AES as u64)) as *mut std::ffi::c_void,
                    ulValueLen: std::mem::size_of::<u64>() as u64,
                });
                template.push(CK_ATTRIBUTE {
                    type_: CK_ATTRIBUTE_TYPE::CKA_VALUE_LEN,
                    pValue: Box::into_raw(Box::new(32u64)) as *mut std::ffi::c_void,
                    ulValueLen: std::mem::size_of::<u64>() as u64,
                });
            }
        }

        template
    }
}

#[async_trait]
impl HsmProvider for Pkcs11Provider {
    async fn initialize(&self, config: &HsmConfig) -> Result<()> {
        match &config.connection {
            HsmConnection::Pkcs11 { library_path, slot_id, token_label } => {
                log::info!("Initializing PKCS#11 with library: {}", library_path);
                
                // Load PKCS#11 library and initialize
                let mut ctx_guard = self.ctx.write().await;
                let ctx = match ctx_guard.as_mut() {
                    Some(ctx) => ctx,
                    None => {
                        return Err(FortressError::key_management(
                            "PKCS#11 context not initialized".to_string(),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }
                };

                // Load the PKCS#11 library
                match ctx.load(library_path.as_str()) {
                    Ok(_) => {
                        log::info!("PKCS#11 library loaded successfully: {}", library_path);
                    }
                    Err(e) => {
                        log::error!("Failed to load PKCS#11 library {}: {}", library_path, e);
                        return Err(FortressError::key_management(
                            format!("Failed to load PKCS#11 library: {}", e),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }
                }

                // Initialize the PKCS#11 library
                match ctx.initialize(None) {
                    Ok(_) => {
                        log::info!("PKCS#11 library initialized successfully");
                    }
                    Err(e) => {
                        log::error!("Failed to initialize PKCS#11 library: {}", e);
                        return Err(FortressError::key_management(
                            format!("Failed to initialize PKCS#11 library: {}", e),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }
                }

                // Determine the slot to use
                let target_slot = if let Some(slot) = slot_id {
                    log::info!("Using specified PKCS#11 slot: {}", slot);
                    *slot
                } else if let Some(label) = token_label {
                    log::info!("Searching for token with label: {}", label);
                    match self.find_slot_by_label(ctx, label).await {
                        Ok(found_slot) => found_slot,
                        Err(e) => {
                            log::error!("Failed to find token with label '{}': {}", label, e);
                            return Err(e);
                        }
                    }
                } else {
                    // Use the first available slot
                    let slots = match ctx.get_slot_list(true) {
                        Ok(slots) => slots,
                        Err(e) => {
                            log::error!("Failed to get slot list: {}", e);
                            return Err(FortressError::key_management(
                                format!("Failed to get slot list: {}", e),
                                None,
                                KeyErrorCode::ProviderError,
                            ));
                        }
                    };

                    if slots.is_empty() {
                        return Err(FortressError::key_management(
                            "No PKCS#11 slots available".to_string(),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }

                    log::info!("Using first available slot: {}", slots[0]);
                    slots[0] as u64
                };

                // Open a session with the slot
                let session = match ctx.open_session(target_slot, pkcs11::SessionFlags::RW | pkcs11::SessionFlags::SerialSession, None, None) {
                    Ok(session) => {
                        log::info!("PKCS#11 session opened successfully with slot {}", target_slot);
                        session
                    }
                    Err(e) => {
                        log::error!("Failed to open PKCS#11 session with slot {}: {}", target_slot, e);
                        return Err(FortressError::key_management(
                            format!("Failed to open PKCS#11 session: {}", e),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }
                };

                // Store session and configuration
                {
                    let mut session_guard = self.session.write().await;
                    *session_guard = Some(session);
                }
                {
                    let mut slot_id_guard = self.slot_id.write().await;
                    *slot_id_guard = Some(target_slot);
                }
                {
                    let mut library_path_guard = self.library_path.write().await;
                    *library_path_guard = Some(library_path.clone());
                }
                {
                    let mut token_label_guard = self.token_label.write().await;
                    *token_label_guard = token_label.clone();
                }

                // Perform login if credentials are provided
                match &config.credentials {
                    HsmCredentials::Pkcs11 { pin, user_type } => {
                        log::info!("Configuring PKCS#11 authentication for user type: {:?}", user_type);
                        
                        // Convert user type to PKCS#11 user type
                        let pkcs11_user_type = match user_type {
                            Pkcs11UserType::SecurityOfficer => pkcs11::UserType::SO,
                            Pkcs11UserType::User => pkcs11::UserType::User,
                        };

                        // Login to PKCS#11 token with PIN
                        match ctx.login(session, pkcs11_user_type, Some(pin)) {
                            Ok(_) => {
                                log::info!("PKCS#11 login successful for user type: {:?}", user_type);
                            }
                            Err(e) => {
                                log::error!("PKCS#11 login failed: {}", e);
                                return Err(FortressError::key_management(
                                    format!("PKCS#11 login failed: {}", e),
                                    None,
                                    KeyErrorCode::AuthenticationError,
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(FortressError::key_management(
                            "Invalid credentials for PKCS#11".to_string(),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }
                }

                // Mark as initialized
                {
                    let mut initialized_guard = self.initialized.write().await;
                    *initialized_guard = true;
                }

                log::info!("PKCS#11 provider initialization completed successfully");
                Ok(())
            }
            _ => Err(FortressError::key_management(
                "Invalid connection configuration for PKCS#11".to_string(),
                None,
                KeyErrorCode::ProviderError,
            )),
        }
    }
    
    async fn generate_key(&self, key_id: &KeyId, algorithm: &dyn EncryptionAlgorithm) -> Result<()> {
        log::info!("Generating key {} in PKCS#11 HSM with algorithm: {}", key_id, algorithm.name());
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Generate key template based on algorithm
        let template = Self::generate_key_template(algorithm, key_id);

        // Generate the key using PKCS#11 C_GenerateKey
        let mechanism = Self::algorithm_to_mechanism(algorithm);
        
        match ctx.generate_key(session, mechanism, &template) {
            Ok(_) => {
                log::info!("Key {} generated successfully in PKCS#11 HSM", key_id);
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to generate key {} in PKCS#11 HSM: {}", key_id, e);
                Err(FortressError::key_management(
                    format!("Failed to generate key in PKCS#11 HSM: {}", e),
                    None,
                    KeyErrorCode::KeyGenerationError,
                ))
            }
        }
    }
    
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata> {
        log::info!("Retrieving metadata for key {} from PKCS#11 HSM", key_id);
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Find the key by ID
        let key_object = self.find_key_by_id(&ctx, session, key_id).await?;
        
        // Get key attributes using C_GetAttributeValue
        let attributes = vec![
            pkcs11::AttributeType::KeyType,
            pkcs11::AttributeType::ValueLen,
            pkcs11::AttributeType::Modifiable,
            pkcs11::AttributeType::Label,
        ];

        let attribute_values = match ctx.get_attribute_value(session, key_object, &attributes) {
            Ok(values) => values,
            Err(e) => {
                log::error!("Failed to get attributes for key {}: {}", key_id, e);
                return Err(FortressError::key_management(
                    format!("Failed to get key attributes: {}", e),
                    None,
                    KeyErrorCode::ProviderError,
                ));
            }
        };

        // Parse attributes to build metadata
        let algorithm_name = self.extract_algorithm_name(&attribute_values)?;
        let key_size = self.extract_key_size(&attribute_values)?;
        let created_at = chrono::Utc::now(); // PKCS#11 doesn't always provide creation time
        let expires_at = created_at + chrono::Duration::days(90); // Default 90 days

        let metadata = KeyMetadata::new(
            key_id.clone(),
            algorithm_name,
            key_size,
            created_at,
            expires_at,
            "encryption".to_string(),
            crate::encryption::PerformanceProfile::Balanced,
        );
        
        log::info!("Retrieved metadata for key {} from PKCS#11 HSM", key_id);
        Ok(metadata)
    }

    /// Find a key object by its ID
    async fn find_key_by_id(&self, ctx: &Ctx, session: u32, key_id: &KeyId) -> Result<ObjectHandle> {
        // Search for objects with the matching ID
        let template = vec![
            (pkcs11::AttributeType::Class, vec![0x03]), // CKO_SECRET_KEY
            (pkcs11::AttributeType::Id, key_id.as_bytes().to_vec()),
        ];

        match ctx.find_objects_init(session, &template) {
            Ok(_) => {
                let objects = match ctx.find_objects(session, 1) {
                    Ok(objects) => objects,
                    Err(e) => {
                        ctx.find_objects_final(session).ok(); // Clean up
                        return Err(FortressError::key_management(
                            format!("Failed to find key objects: {}", e),
                            None,
                            KeyErrorCode::ProviderError,
                        ));
                    }
                };

                ctx.find_objects_final(session).ok(); // Clean up

                if let Some(object) = objects.first() {
                    Ok(*object)
                } else {
                    Err(FortressError::key_management(
                        format!("Key {} not found in PKCS#11 HSM", key_id),
                        None,
                        KeyErrorCode::KeyNotFound,
                    ))
                }
            }
            Err(e) => {
                Err(FortressError::key_management(
                    format!("Failed to initialize key search: {}", e),
                    None,
                    KeyErrorCode::ProviderError,
                ))
            }
        }
    }

    /// Extract algorithm name from PKCS#11 attributes
    fn extract_algorithm_name(&self, attribute_values: &[pkcs11::Attribute]) -> Result<String> {
        for attr in attribute_values {
            if attr.attribute_type == pkcs11::AttributeType::KeyType {
                return match attr.value.get(0) {
                    Some(&0x1f) => Ok("AES-256-GCM".to_string()), // CKK_AES
                    Some(&0x25) => Ok("ChaCha20-Poly1305".to_string()), // CKK_CHACHA20
                    _ => Ok("AES-256-GCM".to_string()), // Default fallback
                };
            }
        }
        Ok("AES-256-GCM".to_string()) // Default fallback
    }

    /// Extract key size from PKCS#11 attributes
    fn extract_key_size(&self, attribute_values: &[pkcs11::Attribute]) -> Result<usize> {
        for attr in attribute_values {
            if attr.attribute_type == pkcs11::AttributeType::ValueLen {
                if let Some(&size) = attr.value.first() {
                    return Ok(size as usize);
                }
            }
        }
        Ok(256) // Default fallback (256 bits)
    }
    
    async fn delete_key(&self, key_id: &KeyId) -> Result<()> {
        log::info!("Deleting key {} from PKCS#11 HSM", key_id);
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Find the key by ID
        let key_object = self.find_key_by_id(&ctx, session, key_id).await?;
        
        // Destroy the key object using C_DestroyObject
        match ctx.destroy_object(session, key_object) {
            Ok(_) => {
                log::info!("Key {} deleted successfully from PKCS#11 HSM", key_id);
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to delete key {} from PKCS#11 HSM: {}", key_id, e);
                Err(FortressError::key_management(
                    format!("Failed to delete key from PKCS#11 HSM: {}", e),
                    None,
                    KeyErrorCode::KeyDeletionError,
                ))
            }
        }
    }
    
    async fn list_keys(&self) -> Result<Vec<(KeyId, KeyMetadata)>> {
        log::info!("Listing keys from PKCS#11 HSM");
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Search for all secret keys
        let template = vec![
            (pkcs11::AttributeType::Class, vec![0x03]), // CKO_SECRET_KEY
        ];

        match ctx.find_objects_init(session, &template) {
            Ok(_) => {
                let mut all_keys = Vec::new();
                let mut found_objects = true;

                while found_objects {
                    match ctx.find_objects(session, 10) {
                        Ok(objects) => {
                            if objects.is_empty() {
                                found_objects = false;
                                break;
                            }

                            for object in objects {
                                // Get the key ID
                                let id_attributes = vec![pkcs11::AttributeType::Id];
                                match ctx.get_attribute_value(session, object, &id_attributes) {
                                    Ok(id_values) => {
                                        if !id_values.is_empty() {
                                            let id_attr = &id_values[0];
                                            let key_id = String::from_utf8_lossy(&id_attr.value).to_string();
                                            
                                            // Get metadata for this key
                                            match self.get_key_metadata(&key_id).await {
                                                Ok(metadata) => {
                                                    all_keys.push((key_id, metadata));
                                                }
                                                Err(e) => {
                                                    log::warn!("Failed to get metadata for key {}: {}", key_id, e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("Failed to get ID for object: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            ctx.find_objects_final(session).ok(); // Clean up
                            return Err(FortressError::key_management(
                                format!("Failed to find key objects: {}", e),
                                None,
                                KeyErrorCode::ProviderError,
                            ));
                        }
                    }
                }

                ctx.find_objects_final(session).ok(); // Clean up
                
                log::info!("Found {} keys in PKCS#11 HSM", all_keys.len());
                Ok(all_keys)
            }
            Err(e) => {
                Err(FortressError::key_management(
                    format!("Failed to initialize key search: {}", e),
                    None,
                    KeyErrorCode::ProviderError,
                ))
            }
        }
    }
    
    async fn sign(&self, key_id: &KeyId, data: &[u8]) -> Result<Vec<u8>> {
        log::info!("Signing data with key {} using PKCS#11 HSM", key_id);
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Find the key by ID
        let key_object = self.find_key_by_id(&ctx, session, key_id).await?;
        
        // Initialize signing using C_SignInit
        let mechanism = Mechanism::Sha256Hmac; // Use HMAC-SHA256 for signing
        
        match ctx.sign_init(session, mechanism, key_object) {
            Ok(_) => {
                // Perform signing using C_Sign
                match ctx.sign(session, data) {
                    Ok(signature) => {
                        log::info!("Data signed successfully with key {} using PKCS#11 HSM", key_id);
                        Ok(signature)
                    }
                    Err(e) => {
                        log::error!("Failed to sign data with key {} using PKCS#11 HSM: {}", key_id, e);
                        Err(FortressError::key_management(
                            format!("Failed to sign data with PKCS#11 HSM: {}", e),
                            None,
                            KeyErrorCode::SigningError,
                        ))
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to initialize signing with key {} using PKCS#11 HSM: {}", key_id, e);
                Err(FortressError::key_management(
                    format!("Failed to initialize signing with PKCS#11 HSM: {}", e),
                    None,
                    KeyErrorCode::SigningError,
                ))
            }
        }
    }
    
    async fn verify(&self, key_id: &KeyId, data: &[u8], signature: &[u8]) -> Result<bool> {
        log::info!("Verifying signature with key {} using PKCS#11 HSM", key_id);
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Find the key by ID
        let key_object = self.find_key_by_id(&ctx, session, key_id).await?;
        
        // Initialize verification using C_VerifyInit
        let mechanism = Mechanism::Sha256Hmac; // Use HMAC-SHA256 for verification
        
        match ctx.verify_init(session, mechanism, key_object) {
            Ok(_) => {
                // Perform verification using C_Verify
                match ctx.verify(session, data, signature) {
                    Ok(_) => {
                        log::info!("Signature verified successfully with key {} using PKCS#11 HSM", key_id);
                        Ok(true)
                    }
                    Err(e) => {
                        log::error!("Failed to verify signature with key {} using PKCS#11 HSM: {}", key_id, e);
                        // Verification failure is not necessarily an error - could be invalid signature
                        Ok(false)
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to initialize verification with key {} using PKCS#11 HSM: {}", key_id, e);
                Err(FortressError::key_management(
                    format!("Failed to initialize verification with PKCS#11 HSM: {}", e),
                    None,
                    KeyErrorCode::VerificationError,
                ))
            }
        }
    }
    
    async fn encrypt(&self, key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>> {
        log::info!("Encrypting data with key {} using PKCS#11 HSM", key_id);
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Find the key by ID
        let key_object = self.find_key_by_id(&ctx, session, key_id).await?;
        
        // Initialize encryption using C_EncryptInit
        let mechanism = Mechanism::AesGcm; // Use AES-GCM for encryption
        
        match ctx.encrypt_init(session, mechanism, key_object) {
            Ok(_) => {
                // Perform encryption using C_Encrypt
                match ctx.encrypt(session, plaintext) {
                    Ok(ciphertext) => {
                        log::info!("Data encrypted successfully with key {} using PKCS#11 HSM", key_id);
                        Ok(ciphertext)
                    }
                    Err(e) => {
                        log::error!("Failed to encrypt data with key {} using PKCS#11 HSM: {}", key_id, e);
                        Err(FortressError::key_management(
                            format!("Failed to encrypt data with PKCS#11 HSM: {}", e),
                            None,
                            KeyErrorCode::EncryptionError,
                        ))
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to initialize encryption with key {} using PKCS#11 HSM: {}", key_id, e);
                Err(FortressError::key_management(
                    format!("Failed to initialize encryption with PKCS#11 HSM: {}", e),
                    None,
                    KeyErrorCode::EncryptionError,
                ))
            }
        }
    }
    
    async fn decrypt(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<Vec<u8>> {
        log::info!("Decrypting data with key {} using PKCS#11 HSM", key_id);
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            return Err(FortressError::key_management(
                "PKCS#11 provider not initialized".to_string(),
                None,
                KeyErrorCode::ProviderError,
            ));
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Find the key by ID
        let key_object = self.find_key_by_id(&ctx, session, key_id).await?;
        
        // Initialize decryption using C_DecryptInit
        let mechanism = Mechanism::AesGcm; // Use AES-GCM for decryption
        
        match ctx.decrypt_init(session, mechanism, key_object) {
            Ok(_) => {
                // Perform decryption using C_Decrypt
                match ctx.decrypt(session, ciphertext) {
                    Ok(plaintext) => {
                        log::info!("Data decrypted successfully with key {} using PKCS#11 HSM", key_id);
                        Ok(plaintext)
                    }
                    Err(e) => {
                        log::error!("Failed to decrypt data with key {} using PKCS#11 HSM: {}", key_id, e);
                        Err(FortressError::key_management(
                            format!("Failed to decrypt data with PKCS#11 HSM: {}", e),
                            None,
                            KeyErrorCode::DecryptionError,
                        ))
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to initialize decryption with key {} using PKCS#11 HSM: {}", key_id, e);
                Err(FortressError::key_management(
                    format!("Failed to initialize decryption with PKCS#11 HSM: {}", e),
                    None,
                    KeyErrorCode::DecryptionError,
                ))
            }
        }
    }
    
    async fn health_check(&self) -> Result<bool> {
        log::info!("Performing PKCS#11 HSM health check");
        
        // Check if initialized
        let initialized_guard = self.initialized.read().await;
        if !*initialized_guard {
            log::warn!("PKCS#11 provider not initialized");
            return Ok(false);
        }
        drop(initialized_guard);

        let session = self.get_session().await?;
        let ctx = self.get_context().await?;

        // Perform a simple operation to check if the HSM is accessible
        match ctx.get_session_info(session) {
            Ok(session_info) => {
                // Copy the state to avoid packed field reference
                let state = session_info.state;
                log::info!("PKCS#11 HSM health check passed - session state: {:?}", state);
                Ok(true)
            }
            Err(e) => {
                log::error!("PKCS#11 HSM health check failed: {}", e);
                Ok(false)
            }
        }
    }
    
    async fn shutdown(&self) -> Result<()> {
        log::info!("Shutting down PKCS#11 provider");
        
        let mut ctx = self.get_context().await?;
        let session_guard = self.session.read().await;
        
        if let Some(session) = *session_guard {
            // Logout from the session
            ctx.logout(session).ok();
            
            // Close the session
            ctx.close_session(session).ok();
        }
        drop(session_guard);

        // Finalize the PKCS#11 library
        ctx.finalize().ok();

        // Mark as not initialized
        {
            let mut initialized_guard = self.initialized.write().await;
            *initialized_guard = false;
        }

        log::info!("PKCS#11 provider shutdown completed");
        Ok(())
    }
}
