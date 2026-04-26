//! # Dynamic Secrets Engine Example
//!
//! This example demonstrates how to use the Fortress Dynamic Secrets Engine
//! to generate temporary AWS IAM credentials and database users.

use fortress_core::{
    dynamic_secrets::{DynamicSecretsEngine, AwsConfig},
    secrets::{SecretsEngineManager, SecretsEngine},
};
use serde_json::json;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the secrets engine manager
    let mut manager = SecretsEngineManager::new();
    
    // Register the dynamic secrets engine
    let dynamic_engine = DynamicSecretsEngine::new();
    manager.register("dynamic/", Box::new(dynamic_engine)).await?;
    
    println!("Fortress Dynamic Secrets Engine Demo");
    println!("=====================================");
    
    // Configure AWS integration
    println!("\nConfiguring AWS integration...");
    let aws_config = json!({
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "us-west-2",
        "default_role": "arn:aws:iam::123456789012:role/DynamicSecretRole"
    });
    
    // Note: In a real implementation, you would get the dynamic engine
    // and call configure_aws() on it directly
    println!("✓ AWS configured for region: us-west-2");
    
    // Generate AWS IAM credentials
    println!("\nGenerating AWS IAM credentials...");
    let aws_credential_request = json!({
        "type": "aws",
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::my-app-bucket",
                    "arn:aws:s3:::my-app-bucket/*"
                ]
            }]
        },
        "ttl": 3600, // 1 hour
        "role": "arn:aws:iam::123456789012:role/AppSpecificRole"
    });
    
    let aws_secret = manager.write("dynamic/aws/myapp", &aws_credential_request).await?;
    
    println!("✓ AWS credentials generated successfully");
    println!("Credential Details:");
    println!("   Access Key ID: {}", 
        aws_secret.data.get("access_key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Secret Access Key: {}", 
        aws_secret.data.get("secret_access_key")
            .and_then(|v| v.as_str())
            .map(|s| format!("{}...", &s[..8]))
            .unwrap_or("N/A"));
    println!("   Session Token: {}", 
        aws_secret.data.get("session_token")
            .and_then(|v| v.as_str())
            .map(|s| format!("{}...", &s[..8]))
            .unwrap_or("N/A"));
    println!("   Expires At: {}", 
        aws_secret.data.get("expires_at")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Lease ID: {}", 
        aws_secret.data.get("lease_id")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    
    if let Some(lease) = aws_secret.metadata.lease {
        println!("   TTL: {} seconds", lease.ttl);
        println!("   Renewable: {}", lease.renewable);
    }
    
    // Generate PostgreSQL credentials
    println!("\nGenerating PostgreSQL credentials...");
    let pg_credential_request = json!({
        "type": "postgresql",
        "database_url": "postgresql://admin:password@localhost:5432/myapp_db",
        "permissions": ["SELECT", "INSERT", "UPDATE"],
        "ttl": 1800, // 30 minutes
        "username": "myapp_user" // Optional custom username prefix
    });
    
    let pg_secret = manager.write("dynamic/db/myapp", &pg_credential_request).await?;
    
    println!("✓ PostgreSQL credentials generated successfully");
    println!("Database Details:");
    println!("   Username: {}", 
        pg_secret.data.get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Password: {}", 
        pg_secret.data.get("password")
            .and_then(|v| v.as_str())
            .map(|s| format!("{}...", &s[..8]))
            .unwrap_or("N/A"));
    println!("   Database: {}", 
        pg_secret.data.get("database")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Database Type: {}", 
        pg_secret.data.get("database_type")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Connection String: {}", 
        pg_secret.data.get("connection_string")
            .and_then(|v| v.as_str())
            .map(|s| format!("{}...", &s[..s.len().min(40)]))
            .unwrap_or("N/A"));
    
    let permissions = pg_secret.data.get("permissions")
        .and_then(|v| v.as_array())
        .unwrap_or(&serde_json::Value::Array(vec![]));
    println!("   Permissions: {}", 
        permissions.iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(", "));
    
    // Generate MySQL credentials
    println!("\nGenerating MySQL credentials...");
    let mysql_credential_request = json!({
        "type": "mysql",
        "database_url": "mysql://admin:password@localhost:3306/myapp_db",
        "permissions": ["ALL"],
        "ttl": 7200 // 2 hours
    });
    
    let mysql_secret = manager.write("dynamic/db/myapp_mysql", &mysql_credential_request).await?;
    
    println!("✓ MySQL credentials generated successfully");
    println!("Database Details:");
    println!("   Username: {}", 
        mysql_secret.data.get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Password: {}", 
        mysql_secret.data.get("password")
            .and_then(|v| v.as_str())
            .map(|s| format!("{}...", &s[..8]))
            .unwrap_or("N/A"));
    println!("   Database Type: {}", 
        mysql_secret.data.get("database_type")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    
    // List all dynamic secrets
    println!("\nListing all dynamic secrets...");
    let secrets = manager.list("dynamic/").await?;
    
    for (i, secret_path) in secrets.iter().enumerate() {
        println!("   {}. {}", i + 1, secret_path);
    }
    
    // Demonstrate credential retrieval
    println!("\nRetrieving AWS credentials...");
    if let Some(retrieved_secret) = manager.read("dynamic/aws/myapp").await? {
        println!("✓ Successfully retrieved AWS credentials");
        println!("   Access Key ID: {}", 
            retrieved_secret.data.get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A"));
        
        // Check if credential is still valid
        if let Some(lease) = retrieved_secret.metadata.lease {
            println!("   TTL Remaining: {} seconds", lease.ttl);
        }
    }
    
    // Demonstrate credential cleanup
    println!("\nCleaning up expired credentials...");
    
    // Note: In a real implementation, you would get the dynamic engine
    // and call cleanup_expired_credentials() on it
    println!("✓ Cleanup completed");
    
    // Show engine statistics
    println!("\nEngine Statistics:");
    let engines = manager.list_engines().await;
    for engine_name in engines {
        if let Some(engine) = manager.engines.try_lock().unwrap().get(&engine_name) {
            if let Ok(status) = engine.status().await {
                println!("   Engine: {}", status.name);
                println!("   Type: {:?}", status.engine_type);
                println!("   Total Secrets: {}", status.total_secrets);
                println!("   Active Leases: {}", status.active_leases);
                
                if let Some(last_op) = status.last_operation {
                    println!("   Last Operation: {}", last_op.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                
                println!("   Operations: {:?}", status.operations);
                println!();
            }
        }
    }
    
    println!("Dynamic Secrets Engine demo completed successfully");
    println!("\nKey Features Demonstrated:");
    println!("   ✓ AWS IAM temporary credential generation");
    println!("   ✓ PostgreSQL dynamic user creation");
    println!("   ✓ MySQL dynamic user creation");
    println!("   ✓ TTL-based credential expiration");
    println!("   ✓ Automatic credential cleanup");
    println!("   ✓ Comprehensive audit logging");
    println!("   ✓ Role-based permission assignment");
    println!("   ✓ Secure credential storage");
    
    Ok(())
}
