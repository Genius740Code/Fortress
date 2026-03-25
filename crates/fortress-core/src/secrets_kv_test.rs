//! Simple test for KV secrets engine encryption and persistence

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets_kv::{KvEngine, KvConfig};
    use crate::secrets::{SecretsEngine, EngineType};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_kv_encryption_basic() {
        println!("Testing KV secrets engine with encryption...");
        
        // Create engine with encryption enabled
        let config = KvConfig {
            max_versions: 10,
            default_ttl: Some(3600),
            case_sensitive: false,
            encryption_at_rest: true,
            storage_backend: Some("memory".to_string()),
            master_key: None,
        };
        
        let engine = KvEngine::with_config(config);
        
        // Write a secret
        let mut secret_data = HashMap::new();
        secret_data.insert("username".to_string(), serde_json::Value::String("admin".to_string()));
        secret_data.insert("password".to_string(), serde_json::Value::String("super-secret".to_string()));
        
        let result = engine.write("secret/app", secret_data.clone(), None).await;
        assert!(result.is_ok(), "Failed to write secret: {:?}", result.err());
        println!("✅ Secret written successfully with encryption");
        
        // Read the secret back
        let retrieved_secret = engine.read("secret/app").await;
        assert!(retrieved_secret.is_ok(), "Failed to read secret: {:?}", retrieved_secret.err());
        println!("✅ Secret retrieved successfully");
        
        // Verify the data matches
        if let Ok(Some(secret)) = retrieved_secret {
            let data = secret.data.as_object().unwrap();
            assert_eq!(data.get("username").unwrap().as_str().unwrap(), "admin");
            assert_eq!(data.get("password").unwrap().as_str().unwrap(), "super-secret");
            println!("✅ Secret data verified");
        } else {
            panic!("Expected to find secret but got None");
        }
        
        // Check engine status
        let status = engine.status().await;
        assert!(status.is_ok(), "Failed to get status: {:?}", status.err());
        
        if let Ok(status) = status {
            assert_eq!(status.engine_type, EngineType::Kv);
            assert_eq!(status.total_secrets, 1);
            println!("✅ Engine status verified");
        }
        
        println!("🎉 All encryption tests passed!");
    }

    #[tokio::test]
    async fn test_kv_no_encryption() {
        println!("Testing KV secrets engine without encryption...");
        
        // Create engine without encryption
        let config = KvConfig {
            max_versions: 5,
            default_ttl: None,
            case_sensitive: true,
            encryption_at_rest: false,
            storage_backend: Some("memory".to_string()),
            master_key: None,
        };
        
        let engine = KvEngine::with_config(config);
        
        // Write a secret
        let mut secret_data = HashMap::new();
        secret_data.insert("public".to_string(), serde_json::Value::String("data".to_string()));
        
        let result = engine.write("public/data", secret_data, None).await;
        assert!(result.is_ok(), "Failed to write secret: {:?}", result.err());
        
        // Read the secret back
        let retrieved_secret = engine.read("public/data").await;
        assert!(retrieved_secret.is_ok(), "Failed to read secret: {:?}", retrieved_secret.err());
        assert!(retrieved_secret.unwrap().is_some(), "Expected to find secret but got None");
        
        println!("✅ Non-encrypted mode works correctly");
        println!("🎉 All non-encryption tests passed!");
    }
}
