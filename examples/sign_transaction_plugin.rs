//! Example Sign Transaction Plugin
//! 
//! This example demonstrates how to create a Fortress plugin for signing transactions
//! using private keys. The plugin can be used to integrate with blockchain networks,
//! financial systems, or any service that requires digital signatures.

use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::Utc;
use sha2::Digest;

/// Configuration schema for the sign transaction plugin
const PLUGIN_CONFIG_SCHEMA: &str = r#"
{
    "type": "object",
    "properties": {
        "private_key": {
            "type": "string",
            "description": "Private key for signing (hex encoded)"
        },
        "key_type": {
            "type": "string",
            "enum": ["secp256k1", "ed25519", "rsa"],
            "description": "Type of private key"
        },
        "network": {
            "type": "string",
            "description": "Network identifier (e.g., 'ethereum', 'bitcoin')"
        },
        "api_endpoint": {
            "type": "string",
            "description": "Optional API endpoint for external validation"
        }
    },
    "required": ["private_key", "key_type"]
}
"#;

/// Sign transaction plugin implementation
#[derive(Debug)]
struct SignTransactionPlugin {
    metadata: PluginMetadata,
    context: Option<PluginContext>,
    private_key: Option<Vec<u8>>,
    key_type: KeyType,
    network: Option<String>,
    api_endpoint: Option<String>,
}

/// Supported key types
#[derive(Debug, Clone, Serialize, Deserialize)]
enum KeyType {
    Secp256k1,
    Ed25519,
    Rsa,
}

/// Transaction signing request
#[derive(Debug, Serialize, Deserialize)]
struct SignRequest {
    /// Transaction data to sign
    transaction_data: String,
    /// Optional metadata
    metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Transaction signing response
#[derive(Debug, Serialize, Deserialize)]
struct SignResponse {
    /// Signature
    signature: String,
    /// Public key (for verification)
    public_key: String,
    /// Signing timestamp
    timestamp: chrono::DateTime<chrono::Utc>,
    /// Transaction hash
    transaction_hash: String,
}

/// Signature verification request
#[derive(Debug, Serialize, Deserialize)]
struct VerifyRequest {
    /// Original message
    message: String,
    /// Signature to verify
    signature: String,
    /// Public key for verification
    public_key: String,
}

/// Signature verification response
#[derive(Debug, Serialize, Deserialize)]
struct VerifyResponse {
    /// Whether signature is valid
    valid: bool,
    /// Verification timestamp
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl SignTransactionPlugin {
    fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                id: "sign-transaction".to_string(),
                name: "Sign Transaction Plugin".to_string(),
                version: "1.0.0".to_string(),
                description: "Plugin for signing transactions using private keys".to_string(),
                author: "Fortress Team".to_string(),
                capabilities: vec![
                    PluginCapability::SignTransaction,
                    PluginCapability::VerifySignature,
                    PluginCapability::GenerateKey,
                    PluginCapability::ApiIntegration,
                ],
                config_schema: Some(serde_json::from_str(PLUGIN_CONFIG_SCHEMA).unwrap()),
            },
            context: None,
            private_key: None,
            key_type: KeyType::Secp256k1,
            network: None,
            api_endpoint: None,
        }
    }

    /// Parse private key from hex string
    fn parse_private_key(&mut self, key_hex: &str) -> Result<()> {
        let key_bytes = hex::decode(key_hex.trim_start_matches("0x"))
            .map_err(|e| FortressError::plugin(format!("Invalid hex private key: {}", e)))?;
        
        // Validate key length based on key type
        let expected_length = match self.key_type {
            KeyType::Secp256k1 => 32,
            KeyType::Ed25519 => 32,
            KeyType::Rsa => {
                // RSA keys are variable length, just check minimum
                if key_bytes.len() < 128 {
                    return Err(FortressError::plugin("RSA key too short (minimum 1024 bits)"));
                }
                key_bytes.len()
            }
        };

        if matches!(self.key_type, KeyType::Secp256k1 | KeyType::Ed25519) && key_bytes.len() != expected_length {
            return Err(FortressError::plugin(format!(
                "Invalid key length for {:?}: expected {} bytes, got {}",
                self.key_type, expected_length, key_bytes.len()
            )));
        }

        self.private_key = Some(key_bytes);
        Ok(())
    }

    /// Generate a mock signature (in production, use proper cryptographic libraries)
    fn generate_signature(&self, message: &str) -> Result<String> {
        match &self.private_key {
            Some(key) => {
                // This is a mock implementation - in production, use proper crypto
                let combined = format!("{}+{}", hex::encode(key), message);
                let mut hasher = sha2::Sha256::new();
                hasher.update(combined.as_bytes());
                let hash = hasher.finalize();
                Ok(format!("0x{}", hex::encode(hash)))
            }
            None => Err(FortressError::plugin("Private key not configured")),
        }
    }

    /// Get public key (mock implementation)
    fn get_public_key(&self) -> Result<String> {
        match &self.private_key {
            Some(key) => {
                // Mock public key derivation - in production, use proper crypto
                let mut hasher = sha2::Sha256::new();
                hasher.update(key);
                let hash = hasher.finalize();
                Ok(format!("0x{}", hex::encode(&hash[..32])))
            }
            None => Err(FortressError::plugin("Private key not configured")),
        }
    }

    /// Call external API if configured
    async fn call_external_api(&self, endpoint: &str, data: serde_json::Value) -> Result<serde_json::Value> {
        let client = reqwest::Client::new();
        let response = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&data)
            .send()
            .await
            .map_err(|e| FortressError::plugin(format!("API call failed: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to parse API response: {}", e)))?;

        Ok(result)
    }
}

#[async_trait]
impl Plugin for SignTransactionPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, context: PluginContext) -> Result<()> {
        // Extract configuration
        if let Some(private_key) = context.config.get("private_key") {
            let key_str = private_key.as_str()
                .ok_or_else(|| FortressError::plugin("Private key must be a string"))?;
            
            // Parse key type
            let key_type = if let Some(key_type) = context.config.get("key_type") {
                match key_type.as_str() {
                    Some("secp256k1") => KeyType::Secp256k1,
                    Some("ed25519") => KeyType::Ed25519,
                    Some("rsa") => KeyType::Rsa,
                    _ => return Err(FortressError::plugin("Invalid key type")),
                }
            } else {
                KeyType::Secp256k1 // default
            };

            // Note: In a real implementation, we'd need to store this state
            // For this example, we'll just validate the key format
            let key_bytes = hex::decode(key_str.trim_start_matches("0x"))
                .map_err(|e| FortressError::plugin(format!("Invalid hex private key: {}", e)))?;
            
            // Validate key length
            let expected_length = match key_type {
                KeyType::Secp256k1 => 32,
                KeyType::Ed25519 => 32,
                KeyType::Rsa => {
                    if key_bytes.len() < 128 {
                        return Err(FortressError::plugin("RSA key too short (minimum 1024 bits)"));
                    }
                    key_bytes.len()
                }
            };

            if matches!(key_type, KeyType::Secp256k1 | KeyType::Ed25519) && key_bytes.len() != expected_length {
                return Err(FortressError::plugin(format!(
                    "Invalid key length for {:?}: expected {} bytes, got {}",
                    key_type, expected_length, key_bytes.len()
                )));
            }
        }

        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        let start_time = std::time::Instant::now();

        let result = match input.action.as_str() {
            "sign" => {
                let sign_req: SignRequest = serde_json::from_value(input.data)
                    .map_err(|e| FortressError::plugin(format!("Invalid sign request: {}", e)))?;

                // For this example, we'll use a mock signature
                // In a real implementation, you'd retrieve the private key securely
                let mut hasher = sha2::Sha256::new();
                hasher.update(sign_req.transaction_data.as_bytes());
                let hash = hasher.finalize();
                let mock_signature = format!("0x{}", hex::encode(hash));
                let mock_public_key = "0x1234567890abcdef1234567890abcdef12345678".to_string();
                
                let mut tx_hasher = sha2::Sha256::new();
                tx_hasher.update(sign_req.transaction_data.as_bytes());
                let transaction_hash = tx_hasher.finalize();

                let response = SignResponse {
                    signature: mock_signature,
                    public_key: mock_public_key,
                    timestamp: Utc::now(),
                    transaction_hash: format!("0x{}", hex::encode(transaction_hash)),
                };

                serde_json::to_value(response)
                    .map_err(|e| FortressError::plugin(format!("Failed to serialize response: {}", e)))
            }
            "verify" => {
                let verify_req: VerifyRequest = serde_json::from_value(input.data)
                    .map_err(|e| FortressError::plugin(format!("Invalid verify request: {}", e)))?;

                // Mock verification - in production, use proper cryptographic verification
                let expected_signature = format!("0x{}", hex::encode(sha2::Sha256::digest(verify_req.message.as_bytes())));
                let valid = expected_signature == verify_req.signature;

                let response = VerifyResponse {
                    valid,
                    timestamp: Utc::now(),
                };

                serde_json::to_value(response)
                    .map_err(|e| FortressError::plugin(format!("Failed to serialize response: {}", e)))
            }
            "get_public_key" => {
                let mut response = serde_json::Map::new();
                response.insert("public_key".to_string(), serde_json::Value::String("0x1234567890abcdef1234567890abcdef12345678".to_string()));
                response.insert("key_type".to_string(), serde_json::Value::String("secp256k1".to_string()));
                response.insert("network".to_string(), serde_json::Value::String("ethereum".to_string()));

                Ok(serde_json::Value::Object(response))
            }
            _ => Err(FortressError::plugin(format!("Unknown action: {}", input.action))),
        };

        let execution_time = start_time.elapsed().as_millis() as u64;
        let mut custom_metrics = HashMap::new();
        custom_metrics.insert("action".to_string(), serde_json::Value::String(input.action));

        match result {
            Ok(data) => Ok(PluginResult {
                success: true,
                data: Some(data),
                error: None,
                metrics: PluginMetrics {
                    execution_time_ms: execution_time,
                    memory_usage_bytes: 0, // Could be implemented with memory profiling
                    custom_metrics,
                },
            }),
            Err(e) => Ok(PluginResult {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metrics: PluginMetrics {
                    execution_time_ms: execution_time,
                    memory_usage_bytes: 0,
                    custom_metrics,
                },
            }),
        }
    }

    async fn cleanup(&self) -> Result<()> {
        // Clear sensitive data
        // Note: In a real implementation, we would zero out the private key memory
        Ok(())
    }

    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        // Check required fields
        if !config.contains_key("private_key") {
            return Err(FortressError::plugin("Missing required field: private_key"));
        }

        if !config.contains_key("key_type") {
            return Err(FortressError::plugin("Missing required field: key_type"));
        }

        // Validate key type
        if let Some(key_type) = config.get("key_type") {
            match key_type.as_str() {
                Some("secp256k1") | Some("ed25519") | Some("rsa") => (),
                _ => return Err(FortressError::plugin("Invalid key type")),
            }
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        // In a real implementation, you'd check if the plugin is properly configured
        // For this example, we'll always return healthy
        Ok(PluginHealth {
            healthy: true,
            message: "Plugin is healthy and ready to sign transactions".to_string(),
            last_check: Utc::now(),
        })
    }
}

/// Example usage of the sign transaction plugin
#[tokio::main]
async fn main() -> Result<()> {
    // Create plugin manager
    let plugin_manager = PluginManager::new();

    // Create the sign transaction plugin
    let plugin = SignTransactionPlugin::new();
    let plugin = Arc::new(plugin);

    // Configure the plugin
    let mut config = HashMap::new();
    config.insert("private_key".to_string(), serde_json::Value::String(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()
    ));
    config.insert("key_type".to_string(), serde_json::Value::String("secp256k1".to_string()));
    config.insert("network".to_string(), serde_json::Value::String("ethereum".to_string()));

    // Load the plugin
    plugin_manager.load_plugin(plugin, config).await?;

    // Test signing a transaction
    let sign_input = PluginInput {
        action: "sign".to_string(),
        data: serde_json::json!({
            "transaction_data": "transfer 100 ETH to 0x742d35Cc6634C0532925a3b8D4C9db96c4b4Db45",
            "metadata": {
                "gas_limit": "21000",
                "gas_price": "20 gwei"
            }
        }),
        parameters: HashMap::new(),
    };

    let result = plugin_manager.execute_plugin("sign-transaction", sign_input).await?;
    
    println!("Sign Result: {}", serde_json::to_string_pretty(&result)?);

    // Test getting public key
    let pubkey_input = PluginInput {
        action: "get_public_key".to_string(),
        data: serde_json::Value::Null,
        parameters: HashMap::new(),
    };

    let pubkey_result = plugin_manager.execute_plugin("sign-transaction", pubkey_input).await?;
    println!("Public Key Result: {}", serde_json::to_string_pretty(&pubkey_result)?);

    // Test health check
    let health_status = plugin_manager.get_all_health_status().await;
    for (plugin_id, health) in health_status {
        println!("Plugin {} health: {} - {}", plugin_id, health.healthy, health.message);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_metadata() {
        let plugin = SignTransactionPlugin::new();
        let metadata = plugin.metadata();
        
        assert_eq!(metadata.id, "sign-transaction");
        assert_eq!(metadata.name, "Sign Transaction Plugin");
        assert!(metadata.capabilities.contains(&PluginCapability::SignTransaction));
        assert!(metadata.capabilities.contains(&PluginCapability::VerifySignature));
    }

    #[test]
    fn test_config_validation() {
        let plugin = SignTransactionPlugin::new();
        
        // Valid config
        let mut valid_config = HashMap::new();
        valid_config.insert("private_key".to_string(), serde_json::Value::String("0x1234".to_string()));
        valid_config.insert("key_type".to_string(), serde_json::Value::String("secp256k1".to_string()));
        assert!(plugin.validate_config(&valid_config).is_ok());
        
        // Missing private key
        let mut invalid_config = HashMap::new();
        invalid_config.insert("key_type".to_string(), serde_json::Value::String("secp256k1".to_string()));
        assert!(plugin.validate_config(&invalid_config).is_err());
        
        // Invalid key type
        let mut invalid_config = HashMap::new();
        invalid_config.insert("private_key".to_string(), serde_json::Value::String("0x1234".to_string()));
        invalid_config.insert("key_type".to_string(), serde_json::Value::String("invalid".to_string()));
        assert!(plugin.validate_config(&invalid_config).is_err());
    }
}
