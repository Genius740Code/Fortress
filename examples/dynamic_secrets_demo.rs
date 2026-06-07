//! # Dynamic Secrets Engine Example
//!
//! This example demonstrates how to use the Fortress Dynamic Secrets Engine
//! to generate temporary AWS IAM credentials and database users.

use fortress_core::{
    dynamic_secrets::DynamicSecretsEngine,
    secrets::{SecretsEngineManager, SecretsConfig, SecretsEngine},
};
use serde_json::json;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the secrets engine manager
    let mut manager = SecretsEngineManager::new(SecretsConfig::default());
    
    // Register the dynamic secrets engine
    let dynamic_engine_instance = DynamicSecretsEngine::new();
    manager.register_engine("dynamic/".to_string(), Box::new(dynamic_engine_instance))?;

    let dynamic_engine: &dyn SecretsEngine = manager.get_engine("dynamic/").ok_or("Dynamic engine not found")?;

    println!("Fortress Dynamic Secrets Engine Demo");
    println!("=====================================");
    
    // Configure AWS integration through the manager's engine
    println!("\nConfiguring AWS integration...");
    let aws_config_json = json!({
        "aws": {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2",
            "default_role": "arn:aws:iam::123456789012:role/DynamicSecretRole"
        }
    });

    dynamic_engine.configure(aws_config_json).await?;
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
    
    let aws_secret = dynamic_engine.write("dynamic/aws/myapp", &aws_credential_request).await?;
    
    println!("✓ AWS credentials generated successfully");
    println!("Credential Details:");
    println!("   Access Key ID: {}", 
        aws_secret.data.get("access_key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    let secret_access_key = aws_secret.data.get("secret_access_key")
        .and_then(|v| v.as_str());
    println!("   Secret Access Key: {}", secret_access_key.map_or("N/A".to_string(), |s| format!("{}...", &s[..8])));
    let session_token = aws_secret.data.get("session_token")
        .and_then(|v| v.as_str());
    println!("   Session Token: {}", session_token.map_or("N/A".to_string(), |s| format!("{}...", &s[..8])));
    println!("   Expires At: {}", 
        aws_secret.data.get("expires_at")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Lease ID: {}", 
        aws_secret.data.get("lease_id")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    
    if let Some(lease) = aws_secret.lease {
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
        "username": "myapp_user", // Optional custom username prefix
        "database_type": "postgresql",
        "connection_string": "postgresql://admin:password@localhost:5432/myapp_db"
    });
    
    let pg_secret = dynamic_engine.write("dynamic/db/myapp", &pg_credential_request).await?;
    
    println!("✓ PostgreSQL credentials generated successfully");
    println!("Database Details:");
    println!("   Username: {}", 
        pg_secret.data.get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    let pg_password = pg_secret.data.get("password")
        .and_then(|v| v.as_str());
    println!("   Password: {}", pg_password.map_or("N/A".to_string(), |s| format!("{}...", &s[..8])));
    println!("   Database: {}", 
        pg_secret.data.get("database")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    println!("   Database Type: {}", 
        pg_secret.data.get("database_type")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    let pg_connection_string = pg_secret.data.get("connection_string")
        .and_then(|v| v.as_str());
    println!("   Connection String: {}", pg_connection_string.map_or("N/A".to_string(), |s| format!("{}...", &s[..s.len().min(40)])));
    
    let permissions = pg_secret.data.get("permissions")
        .and_then(|v| v.as_array())
        .map_or(&[] as &[serde_json::Value], |v| v);
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
    
    let mysql_secret = dynamic_engine.write("dynamic/db/myapp_mysql", &mysql_credential_request).await?;
    
    println!("✓ MySQL credentials generated successfully");
    println!("Database Details:");
    println!("   Username: {}", 
        mysql_secret.data.get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    let mysql_password = mysql_secret.data.get("password")
        .and_then(|v| v.as_str());
    println!("   Password: {}", mysql_password.map_or("N/A".to_string(), |s| format!("{}...", &s[..8])));
    println!("   Database Type: {}", 
        mysql_secret.data.get("database_type")
            .and_then(|v| v.as_str())
            .unwrap_or("N/A"));
    
    // List all dynamic secrets
    println!("\nListing all dynamic secrets...");
    let secrets = dynamic_engine.list("dynamic/").await?;
    
    for (i, secret_path) in secrets.iter().enumerate() {
        println!("   {}. {}", i + 1, secret_path);
    }
    
    // Demonstrate credential retrieval
    println!("\nRetrieving AWS credentials...");
    if let Some(retrieved_secret) = dynamic_engine.read("dynamic/aws/myapp").await? {
        println!("✓ Successfully retrieved AWS credentials");
        println!("   Access Key ID: {}", 
            retrieved_secret.data.get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A"));
        
        // Check if credential is still valid
        if let Some(lease) = retrieved_secret.lease {
            println!("   TTL Remaining: {} seconds", lease.ttl);
        }
    }
    
    // Demonstrate credential cleanup
    println!("\nCleaning up expired credentials...");
    dynamic_engine.cleanup_expired_credentials().await?;
    println!("✓ Cleanup completed");
    
    // Show engine statistics
    println!("\nEngine Statistics:");
    let engines = manager.list_engines();
    for engine_name in engines {
        if let Some(engine) = manager.get_engine(&engine_name) {
            if let Ok(status) = engine.status().await {
                println!("   Engine: {}", status.name);
                println!("   Type: {:?}", status.engine_type);
                println!("   Total Secrets: {}", status.stats.total_secrets);
                println!("   Active Leases: {}", status.stats.active_leases);
                
                if let Some(last_op) = status.stats.last_operation {
                    println!("   Last Operation: {}", last_op.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                
                println!("   Operations: {:?}", status.stats.operations);
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
