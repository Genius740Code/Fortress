//! Data encryption and field-level security for GraphQL API
//!
//! Implements end-to-end encryption, field-level access control,
//  secure key management, and data protection policies.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use async_graphql::{Result, Error, ErrorExtensions};
use uuid::Uuid;
use fortress_core::encryption::{EncryptionAlgorithm, SecureKey};
use fortress_core::key::KeyManager;

/// Field-level encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEncryptionConfig {
    pub field_name: String,
    pub resource_type: String,
    pub encryption_enabled: bool,
    pub encryption_algorithm: String,
    pub key_rotation_enabled: bool,
    pub key_rotation_interval_days: u32,
    pub access_roles: Vec<String>,
    pub access_permissions: Vec<String>,
    pub masking_enabled: bool,
    pub masking_type: MaskingType,
}

/// Data masking types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaskingType {
    None,
    Partial { visible_chars: usize, mask_char: char },
    Full,
    Email,
    Phone,
    CreditCard,
    Custom { pattern: String },
}

/// Encryption key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKeyMetadata {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_rotated: u64,
    pub rotation_count: u32,
    pub status: KeyStatus,
    pub access_policies: Vec<KeyAccessPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Rotating,
    Deprecated,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAccessPolicy {
    pub role: String,
    pub permission: String,
    pub conditions: Vec<AccessCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessCondition {
    TimeRestriction { start_hour: u32, end_hour: u32 },
    IpWhitelist { ips: Vec<String> },
    DeviceWhitelist { devices: Vec<String> },
}

/// Data encryption manager
pub struct DataEncryptionManager {
    key_manager: Arc<dyn KeyManager>,
    field_configs: Arc<RwLock<HashMap<String, FieldEncryptionConfig>>>,
    key_metadata: Arc<RwLock<HashMap<String, EncryptionKeyMetadata>>>,
    encryption_cache: Arc<RwLock<HashMap<String, EncryptedData>>>,
    config: EncryptionConfig,
}

#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub default_algorithm: String,
    pub key_rotation_interval: Duration,
    pub cache_size: usize,
    pub audit_encryption: bool,
    pub enable_field_level_encryption: bool,
    pub enable_data_masking: bool,
    pub secure_key_storage: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            default_algorithm: "AEGIS256".to_string(),
            key_rotation_interval: Duration::from_secs(86400 * 30), // 30 days
            cache_size: 10000,
            audit_encryption: true,
            enable_field_level_encryption: true,
            enable_data_masking: true,
            secure_key_storage: true,
        }
    }
}

impl DataEncryptionManager {
    pub fn new(key_manager: Arc<dyn KeyManager>, config: EncryptionConfig) -> Self {
        Self {
            key_manager,
            field_configs: Arc::new(RwLock::new(HashMap::new())),
            key_metadata: Arc::new(RwLock::new(HashMap::new())),
            encryption_cache: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Encrypt field data
    pub async fn encrypt_field(&self, field_name: &str, resource_type: &str, data: &str, user_context: &UserContext) -> Result<EncryptedField> {
        let config_key = format!("{}:{}", resource_type, field_name);
        
        // Check if field encryption is enabled
        let field_configs = self.field_configs.read().await;
        let config = field_configs.get(&config_key);
        
        if let Some(field_config) = config {
            if !field_config.encryption_enabled {
                return Ok(EncryptedField {
                    field_name: field_name.to_string(),
                    data: data.to_string(),
                    is_encrypted: false,
                    is_masked: false,
                    key_id: None,
                    algorithm: None,
                });
            }

            // Check user access
            if !self.check_field_access(field_config, user_context) {
                return self.apply_masking(field_config, data);
            }

            // Get or create encryption key
            let key_id = self.get_or_create_key(field_config).await?;
            
            // Encrypt the data
            let algorithm = self.get_algorithm(&field_config.encryption_algorithm)?;
            let (key, _) = self.key_manager.retrieve_key(&key_id).await
                .map_err(|e| {
                    let error = Error::new(format!("Failed to get encryption key: {}", e))
                        .extend_with(|_, ext| ext.set("code", "KEY_RETRIEVAL_FAILED"));
                    error
                })?;

            let encrypted_data = algorithm.encrypt(data.as_bytes(), key.as_bytes())
                .map_err(|e| Error::new(format!("Encryption failed: {}", e))
                    .extend_with(|_, e| e.set("code", "ENCRYPTION_FAILED")))?;

            // Cache the encrypted data
            let cache_key = format!("{}:{}:{}", resource_type, field_name, self.hash_data(data));
            let mut cache = self.encryption_cache.write().await;
            cache.insert(cache_key, EncryptedData {
                encrypted_data: encrypted_data.clone(),
                key_id: key_id.clone(),
                algorithm: field_config.encryption_algorithm.clone(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });

            Ok(EncryptedField {
                field_name: field_name.to_string(),
                data: hex::encode(&encrypted_data),
                is_encrypted: true,
                is_masked: false,
                key_id: Some(key_id),
                algorithm: Some(field_config.encryption_algorithm.clone()),
            })
        } else {
            // No specific config, return unencrypted
            Ok(EncryptedField {
                field_name: field_name.to_string(),
                data: data.to_string(),
                is_encrypted: false,
                is_masked: false,
                key_id: None,
                algorithm: None,
            })
        }
    }

    /// Decrypt field data
    pub async fn decrypt_field(&self, field_name: &str, resource_type: &str, encrypted_data: &str, user_context: &UserContext) -> Result<DecryptedField> {
        let config_key = format!("{}:{}", resource_type, field_name);
        
        // Check field configuration
        let field_configs = self.field_configs.read().await;
        let config = field_configs.get(&config_key);
        
        if let Some(field_config) = config {
            if !field_config.encryption_enabled {
                return Ok(DecryptedField {
                    field_name: field_name.to_string(),
                    data: encrypted_data.to_string(),
                    is_encrypted: false,
                    is_masked: false,
                });
            }

            // Check user access
            if !self.check_field_access(field_config, user_context) {
                return self.apply_masking_to_decrypted(field_config, encrypted_data);
            }

            // Decode encrypted data
            let encrypted_bytes = hex::decode(encrypted_data)
                .map_err(|e| Error::new(format!("Invalid encrypted data format: {}", e))
                    .extend_with(|_, e| e.set("code", "INVALID_ENCRYPTED_DATA")))?;

            // Get encryption key
            let key_id = self.get_active_key(field_config).await
                .ok_or_else(|| Error::new("No active key available")
                    .extend_with(|_, e| e.set("code", "NO_ACTIVE_KEY")))?;
            let (key, _) = self.key_manager.retrieve_key(&key_id).await
                .map_err(|e| Error::new(format!("Failed to get decryption key: {}", e))
                    .extend_with(|_, e| e.set("code", "KEY_RETRIEVAL_FAILED")))?;

            // Decrypt the data
            let algorithm = self.get_algorithm(&field_config.encryption_algorithm)?;
            let decrypted_data = algorithm.decrypt(&encrypted_bytes, key.as_bytes())
                .map_err(|e| Error::new(format!("Decryption failed: {}", e))
                    .extend_with(|_, e| e.set("code", "DECRYPTION_FAILED")))?;

            let decrypted_string = String::from_utf8(decrypted_data)
                .map_err(|e| Error::new(format!("Invalid UTF-8 in decrypted data: {}", e))
                    .extend_with(|_, e| e.set("code", "INVALID_DECRYPTED_DATA")))?;

            Ok(DecryptedField {
                field_name: field_name.to_string(),
                data: decrypted_string,
                is_encrypted: true,
                is_masked: false,
            })
        } else {
            // No specific config, return as-is
            Ok(DecryptedField {
                field_name: field_name.to_string(),
                data: encrypted_data.to_string(),
                is_encrypted: false,
                is_masked: false,
            })
        }
    }

    /// Encrypt entire record
    pub async fn encrypt_record(&self, resource_type: &str, record: &serde_json::Value, user_context: &UserContext) -> Result<EncryptedRecord> {
        let mut encrypted_fields = Vec::new();
        let mut field_access = Vec::new();

        if let Some(obj) = record.as_object() {
            for (field_name, field_value) in obj {
                if let Some(string_value) = field_value.as_str() {
                    let encrypted_field = self.encrypt_field(field_name, resource_type, string_value, user_context).await?;
                    encrypted_fields.push(encrypted_field.clone());
                    
                    // Track access level
                    field_access.push(FieldAccess {
                        field_name: field_name.to_string(),
                        access_level: if encrypted_field.is_encrypted {
                            AccessLevel::Encrypted
                        } else if encrypted_field.is_masked {
                            AccessLevel::Masked
                        } else {
                            AccessLevel::Plain
                        },
                    });
                } else {
                    // Handle non-string fields
                    encrypted_fields.push(EncryptedField {
                        field_name: field_name.to_string(),
                        data: field_value.to_string(),
                        is_encrypted: false,
                        is_masked: false,
                        key_id: None,
                        algorithm: None,
                    });
                    
                    field_access.push(FieldAccess {
                        field_name: field_name.to_string(),
                        access_level: AccessLevel::Plain,
                    });
                }
            }
        }

        Ok(EncryptedRecord {
            resource_type: resource_type.to_string(),
            fields: encrypted_fields,
            access_levels: field_access,
            encryption_metadata: self.generate_encryption_metadata(resource_type).await,
        })
    }

    /// Decrypt entire record
    pub async fn decrypt_record(&self, resource_type: &str, encrypted_record: &EncryptedRecord, user_context: &UserContext) -> Result<serde_json::Value> {
        let mut decrypted_obj = serde_json::Map::new();

        for field in &encrypted_record.fields {
            if field.is_encrypted {
                let decrypted = self.decrypt_field(&field.field_name, resource_type, &field.data, user_context).await?;
                decrypted_obj.insert(field.field_name.clone(), serde_json::Value::String(decrypted.data));
            } else {
                decrypted_obj.insert(field.field_name.clone(), serde_json::Value::String(field.data.clone()));
            }
        }

        Ok(serde_json::Value::Object(decrypted_obj))
    }

    /// Add field encryption configuration
    pub async fn add_field_config(&self, config: FieldEncryptionConfig) -> Result<()> {
        let config_key = format!("{}:{}", config.resource_type, config.field_name);
        
        let mut configs = self.field_configs.write().await;
        configs.insert(config_key, config);
        
        Ok(())
    }

    /// Rotate encryption key
    pub async fn rotate_key(&self, field_name: &str, resource_type: &str) -> Result<String> {
        let config_key = format!("{}:{}", resource_type, field_name);
        
        let field_configs = self.field_configs.read().await;
        let config = field_configs.get(&config_key)
            .ok_or_else(|| Error::new("Field configuration not found")
                .extend_with(|_, e| e.set("code", "FIELD_CONFIG_NOT_FOUND")))?;

        if !config.key_rotation_enabled {
            return Err(Error::new("Key rotation not enabled for this field")
                .extend_with(|_, e| e.set("code", "KEY_ROTATION_DISABLED")));
        }

        // Generate new key
        let algorithm = self.get_algorithm(&config.encryption_algorithm)?;
        let new_key = self.key_manager.generate_key(algorithm.as_ref()).await
            .map_err(|e| Error::new(format!("Failed to generate new key: {}", e))
                .extend_with(|_, e| e.set("code", "KEY_GENERATION_FAILED")))?;

        // Update key metadata
        let key_id = hex::encode(new_key.as_bytes());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = EncryptionKeyMetadata {
            key_id: key_id.clone(),
            algorithm: config.encryption_algorithm.clone(),
            created_at: now,
            expires_at: Some(now + self.config.key_rotation_interval.as_secs()),
            last_rotated: now,
            rotation_count: 1,
            status: KeyStatus::Active,
            access_policies: vec![],
        };

        let mut key_metadata = self.key_metadata.write().await;
        key_metadata.insert(key_id.clone(), metadata);

        // Invalidate cache for this field
        let mut cache = self.encryption_cache.write().await;
        cache.retain(|key, _| !key.starts_with(&format!("{}:{}", resource_type, field_name)));

        Ok(key_id)
    }

    /// Get encryption statistics
    pub async fn get_encryption_stats(&self) -> EncryptionStats {
        let field_configs = self.field_configs.read().await;
        let key_metadata = self.key_metadata.read().await;
        let cache = self.encryption_cache.read().await;

        let total_fields = field_configs.len();
        let encrypted_fields = field_configs.values()
            .filter(|config| config.encryption_enabled)
            .count();
        
        let total_keys = key_metadata.len();
        let active_keys = key_metadata.values()
            .filter(|metadata| matches!(metadata.status, KeyStatus::Active))
            .count();

        EncryptionStats {
            total_fields,
            encrypted_fields,
            total_keys,
            active_keys,
            cache_size: cache.len(),
            default_algorithm: self.config.default_algorithm.clone(),
        }
    }

    /// Check user access to field
    fn check_field_access(&self, config: &FieldEncryptionConfig, user_context: &UserContext) -> bool {
        // Check role-based access
        for role in &config.access_roles {
            if user_context.roles.contains(role) {
                return true;
            }
        }

        // Check permission-based access
        for permission in &config.access_permissions {
            if user_context.permissions.contains(permission) {
                return true;
            }
        }

        false
    }

    /// Apply data masking
    fn apply_masking(&self, config: &FieldEncryptionConfig, data: &str) -> Result<EncryptedField> {
        if !config.masking_enabled {
            return Ok(EncryptedField {
                field_name: config.field_name.clone(),
                data: data.to_string(),
                is_encrypted: false,
                is_masked: false,
                key_id: None,
                algorithm: None,
            });
        }

        let masked_data = self.mask_data(data, &config.masking_type);

        Ok(EncryptedField {
            field_name: config.field_name.clone(),
            data: masked_data,
            is_encrypted: false,
            is_masked: true,
            key_id: None,
            algorithm: None,
        })
    }

    /// Apply masking to decrypted data
    fn apply_masking_to_decrypted(&self, config: &FieldEncryptionConfig, data: &str) -> Result<DecryptedField> {
        if !config.masking_enabled {
            return Ok(DecryptedField {
                field_name: config.field_name.clone(),
                data: data.to_string(),
                is_encrypted: false,
                is_masked: false,
            });
        }

        let masked_data = self.mask_data(data, &config.masking_type);

        Ok(DecryptedField {
            field_name: config.field_name.clone(),
            data: masked_data,
            is_encrypted: false,
            is_masked: true,
        })
    }

    /// Mask data based on masking type
    fn mask_data(&self, data: &str, masking_type: &MaskingType) -> String {
        match masking_type {
            MaskingType::None => data.to_string(),
            MaskingType::Partial { visible_chars, mask_char: _ } => {
                if data.len() <= *visible_chars {
                    data.to_string()
                } else {
                    let visible = &data[..*visible_chars];
                    let masked = "*".repeat(data.len() - *visible_chars);
                    format!("{}{}", visible, masked)
                }
            }
            MaskingType::Full => "*".repeat(data.len()),
            MaskingType::Email => {
                if let Some(at_pos) = data.find('@') {
                    let username = &data[..at_pos];
                    let domain = &data[at_pos..];
                    let masked_username = if username.len() > 2 {
                        format!("{}***", &username[..2])
                    } else {
                        "***".repeat(username.len())
                    };
                    format!("{}{}", masked_username, domain)
                } else {
                    "***@***".to_string()
                }
            }
            MaskingType::Phone => {
                if data.len() >= 4 {
                    let last_four = &data[data.len()-4..];
                    format!("***-***-***-{}", last_four)
                } else {
                    "***".repeat(data.len())
                }
            }
            MaskingType::CreditCard => {
                if data.len() >= 4 {
                    let last_four = &data[data.len()-4..];
                    format!("****-****-****-{}", last_four)
                } else {
                    "*".repeat(data.len())
                }
            }
            MaskingType::Custom { pattern } => {
                // Simple pattern replacement (can be enhanced)
                pattern.replace("*", &"*".repeat(data.len()))
            }
        }
    }

    /// Get or create encryption key
    async fn get_or_create_key(&self, config: &FieldEncryptionConfig) -> Result<String> {
        // Check for existing active key
        if let Some(key_id) = self.get_active_key(config).await {
            return Ok(key_id);
        }

        // Create new key
        let algorithm = self.get_algorithm(&config.encryption_algorithm)?;
        let key = self.key_manager.generate_key(algorithm.as_ref()).await
            .map_err(|e| Error::new(format!("Failed to generate encryption key: {}", e))
                .extend_with(|_, e| e.set("code", "KEY_GENERATION_FAILED")))?;

        let key_id = hex::encode(key.as_bytes());
        
        // Store key metadata
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = EncryptionKeyMetadata {
            key_id: key_id.clone(),
            algorithm: config.encryption_algorithm.clone(),
            created_at: now,
            expires_at: Some(now + self.config.key_rotation_interval.as_secs()),
            last_rotated: now,
            rotation_count: 0,
            status: KeyStatus::Active,
            access_policies: vec![],
        };

        let mut key_metadata = self.key_metadata.write().await;
        key_metadata.insert(key_id.clone(), metadata);

        Ok(key_id)
    }

    /// Get active key for field
    async fn get_active_key(&self, config: &FieldEncryptionConfig) -> Option<String> {
        let key_metadata = self.key_metadata.read().await;
        
        // Find the most recent active key for this algorithm
        key_metadata.values()
            .filter(|metadata| {
                metadata.algorithm == config.encryption_algorithm
                    && matches!(metadata.status, KeyStatus::Active)
            })
            .max_by_key(|metadata| metadata.last_rotated)
            .map(|metadata| metadata.key_id.clone())
    }

    /// Get encryption algorithm
    fn get_algorithm(&self, algorithm_name: &str) -> Result<Box<dyn EncryptionAlgorithm>> {
        match algorithm_name {
            "AEGIS256" => Ok(Box::new(fortress_core::encryption::Aegis256::new())),
            "AES256GCM" => Ok(Box::new(fortress_core::encryption::Aes256Ctr::new())),
            "CHACHA20POLY1305" => Ok(Box::new(fortress_core::encryption::ChaCha20Poly1305::new())),
            _ => Err(Error::new(format!("Unsupported encryption algorithm: {}", algorithm_name))
                .extend_with(|_, e| e.set("code", "UNSUPPORTED_ALGORITHM"))),
        }
    }

    /// Generate encryption metadata
    async fn generate_encryption_metadata(&self, resource_type: &str) -> EncryptionMetadata {
        let field_configs = self.field_configs.read().await;
        let encrypted_fields: Vec<String> = field_configs
            .keys()
            .filter(|key| key.starts_with(&format!("{}:", resource_type)))
            .map(|key| key.split(':').nth(1).unwrap_or("").to_string())
            .collect();

        EncryptionMetadata {
            resource_type: resource_type.to_string(),
            encrypted_fields,
            encryption_enabled: true,
            last_key_rotation: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Hash data for cache key
    fn hash_data(&self, data: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

/// Encrypted field data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedField {
    pub field_name: String,
    pub data: String,
    pub is_encrypted: bool,
    pub is_masked: bool,
    pub key_id: Option<String>,
    pub algorithm: Option<String>,
}

/// Decrypted field data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedField {
    pub field_name: String,
    pub data: String,
    pub is_encrypted: bool,
    pub is_masked: bool,
}

/// Encrypted record data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub resource_type: String,
    pub fields: Vec<EncryptedField>,
    pub access_levels: Vec<FieldAccess>,
    pub encryption_metadata: EncryptionMetadata,
}

/// Field access level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccess {
    pub field_name: String,
    pub access_level: AccessLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessLevel {
    Plain,
    Masked,
    Encrypted,
}

/// Encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub resource_type: String,
    pub encrypted_fields: Vec<String>,
    pub encryption_enabled: bool,
    pub last_key_rotation: u64,
}

/// Cached encrypted data
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub encrypted_data: Vec<u8>,
    pub key_id: String,
    pub algorithm: String,
    pub created_at: u64,
}

/// User context for access control
#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub tenant_id: Option<String>,
    pub ip_address: String,
    pub device_id: Option<String>,
}

/// Encryption statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionStats {
    pub total_fields: usize,
    pub encrypted_fields: usize,
    pub total_keys: usize,
    pub active_keys: usize,
    pub cache_size: usize,
    pub default_algorithm: String,
}

/// Data protection policy manager
pub struct DataProtectionPolicyManager {
    encryption_manager: Arc<DataEncryptionManager>,
    policies: Arc<RwLock<Vec<DataProtectionPolicy>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProtectionPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub resource_type: String,
    pub data_classification: DataClassification,
    pub retention_period_days: u32,
    pub encryption_required: bool,
    pub masking_required: bool,
    pub access_controls: Vec<AccessControl>,
    pub audit_requirements: Vec<AuditRequirement>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControl {
    pub role: String,
    pub permissions: Vec<String>,
    pub conditions: Vec<AccessCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRequirement {
    pub event_type: String,
    pub log_level: String,
    pub retention_days: u32,
}

impl DataProtectionPolicyManager {
    pub fn new(encryption_manager: Arc<DataEncryptionManager>) -> Self {
        Self {
            encryption_manager,
            policies: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add data protection policy
    pub async fn add_policy(&self, policy: DataProtectionPolicy) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.push(policy);
        Ok(())
    }

    /// Evaluate data protection policies
    pub async fn evaluate_policies(&self, resource_type: &str, user_context: &UserContext) -> PolicyEvaluationResult {
        let policies = self.policies.read().await;
        
        let mut applicable_policies = Vec::new();
        
        for policy in policies.iter().filter(|p| p.enabled && p.resource_type == resource_type) {
            if self.check_policy_access(policy, user_context) {
                applicable_policies.push(policy.clone());
            }
        }

        PolicyEvaluationResult {
            applicable_policies: applicable_policies.clone(),
            encryption_required: applicable_policies.iter().any(|p| p.encryption_required),
            masking_required: applicable_policies.iter().any(|p| p.masking_required),
            max_retention_days: applicable_policies.iter()
                .map(|p| p.retention_period_days)
                .max()
                .unwrap_or(0),
        }
    }

    fn check_policy_access(&self, policy: &DataProtectionPolicy, user_context: &UserContext) -> bool {
        for access_control in &policy.access_controls {
            if user_context.roles.contains(&access_control.role) {
                // Check if user has required permissions
                let has_permissions = access_control.permissions.iter()
                    .all(|perm| user_context.permissions.contains(perm));
                
                if has_permissions {
                    // Check conditions (simplified)
                    return true;
                }
            }
        }
        false
    }
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub applicable_policies: Vec<DataProtectionPolicy>,
    pub encryption_required: bool,
    pub masking_required: bool,
    pub max_retention_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fortress_core::key::InMemoryKeyManager;

    #[tokio::test]
    async fn test_field_encryption() {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let config = EncryptionConfig::default();
        let encryption_manager = DataEncryptionManager::new(key_manager, config);

        // Add field configuration
        let field_config = FieldEncryptionConfig {
            field_name: "email".to_string(),
            resource_type: "user".to_string(),
            encryption_enabled: true,
            encryption_algorithm: "AEGIS256".to_string(),
            key_rotation_enabled: false,
            key_rotation_interval_days: 30,
            access_roles: vec!["admin".to_string()],
            access_permissions: vec![],
            masking_enabled: false,
            masking_type: MaskingType::None,
        };

        encryption_manager.add_field_config(field_config).await.unwrap();

        let user_context = UserContext {
            user_id: "test_user".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec![],
            tenant_id: None,
            ip_address: "127.0.0.1".to_string(),
            device_id: None,
        };

        // Test encryption
        let encrypted = encryption_manager.encrypt_field("email", "user", "test@example.com", &user_context).await.unwrap();
        assert!(encrypted.is_encrypted);
        assert!(encrypted.key_id.is_some());

        // Test decryption
        let decrypted = encryption_manager.decrypt_field("email", "user", &encrypted.data, &user_context).await.unwrap();
        assert_eq!(decrypted.data, "test@example.com");
        assert!(decrypted.is_encrypted);
    }

    #[tokio::test]
    async fn test_data_masking() {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let config = EncryptionConfig::default();
        let encryption_manager = DataEncryptionManager::new(key_manager, config);

        // Test different masking types
        let test_cases = vec![
            ("john.doe@example.com", MaskingType::Email, "jo***@example.com"),
            ("1234567890", MaskingType::Phone, "***-***-***-7890"),
            ("4111111111111111", MaskingType::CreditCard, "****-****-****-1111"),
            ("sensitive_data", MaskingType::Partial { visible_chars: 4, mask_char: '*' }, "sens************"),
            ("visible", MaskingType::Full, "*******"),
        ];

        for (input, masking_type, expected) in test_cases {
            let masked = encryption_manager.mask_data(input, masking_type);
            assert_eq!(masked, expected);
        }
    }

    #[tokio::test]
    async fn test_record_encryption() {
        let key_manager = Arc::new(InMemoryKeyManager::new());
        let config = EncryptionConfig::default();
        let encryption_manager = DataEncryptionManager::new(key_manager, config);

        // Add field configurations
        let email_config = FieldEncryptionConfig {
            field_name: "email".to_string(),
            resource_type: "user".to_string(),
            encryption_enabled: true,
            encryption_algorithm: "AEGIS256".to_string(),
            key_rotation_enabled: false,
            key_rotation_interval_days: 30,
            access_roles: vec!["admin".to_string()],
            access_permissions: vec![],
            masking_enabled: false,
            masking_type: MaskingType::None,
        };

        encryption_manager.add_field_config(email_config).await.unwrap();

        let user_context = UserContext {
            user_id: "test_user".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec![],
            tenant_id: None,
            ip_address: "127.0.0.1".to_string(),
            device_id: None,
        };

        let record = serde_json::json!({
            "id": "123",
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30
        });

        // Test record encryption
        let encrypted_record = encryption_manager.encrypt_record("user", &record, &user_context).await.unwrap();
        assert_eq!(encrypted_record.fields.len(), 4);
        
        // Check that email field is encrypted
        let email_field = encrypted_record.fields.iter().find(|f| f.field_name == "email").unwrap();
        assert!(email_field.is_encrypted);

        // Test record decryption
        let decrypted_record = encryption_manager.decrypt_record("user", &encrypted_record, &user_context).await.unwrap();
        assert_eq!(decrypted_record, record);
    }
}
