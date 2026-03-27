//! # Dynamic Secrets Engine Tests
//!
//! Comprehensive test suite for dynamic secrets generation and management.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{SecretsEngine, Secret, SecretMetadata, LeaseInfo};
    use serde_json::json;
    use tokio::time::{sleep, Duration};
    use chrono::Utc;

    #[tokio::test]
    async fn test_dynamic_secrets_engine_creation() {
        let engine = DynamicSecretsEngine::new();
        
        // Test basic properties
        assert_eq!(engine.name(), "dynamic");
        assert_eq!(engine.engine_type(), crate::secrets::EngineType::Dynamic);
        
        // Test initial status
        let status = engine.status().await.unwrap();
        assert_eq!(status.engine_name, "dynamic");
        assert_eq!(status.total_secrets, 0);
        assert_eq!(status.active_leases, 0);
    }

    #[tokio::test]
    async fn test_aws_configuration() {
        let engine = DynamicSecretsEngine::new();
        
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2",
            "default_role": "arn:aws:iam::123456789012:role/DynamicSecretRole"
        });
        
        // Configure AWS
        assert!(engine.configure_aws(aws_config).await.is_ok());
        
        // Verify configuration was stored
        let status = engine.status().await.unwrap();
        let config_value = status.config.get("aws");
        assert!(config_value.is_some());
    }

    #[tokio::test]
    async fn test_aws_credential_generation() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS first
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        // Generate AWS credentials
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::mybucket/*"
                }]
            },
            "ttl": 3600
        });
        
        let secret = engine.write("aws/myapp", &credential_request).await.unwrap();
        
        // Verify secret structure
        assert!(secret.data.get("access_key_id").is_some());
        assert!(secret.data.get("secret_access_key").is_some());
        assert!(secret.data.get("session_token").is_some());
        assert!(secret.data.get("expires_at").is_some());
        assert!(secret.data.get("policy").is_some());
        assert!(secret.data.get("lease_id").is_some());
        
        // Verify lease information
        assert!(secret.metadata.lease.is_some());
        let lease = secret.metadata.lease.unwrap();
        assert_eq!(lease.ttl, 3600);
        assert!(lease.renewable);
        assert!(lease.lease_id.starts_with("aws:myapp:"));
    }

    #[tokio::test]
    async fn test_postgresql_credential_generation() {
        let engine = DynamicSecretsEngine::new();
        
        // Generate PostgreSQL credentials
        let db_request = json!({
            "type": "postgresql",
            "database_url": "postgresql://admin:password@localhost:5432/testdb",
            "permissions": ["SELECT", "INSERT"],
            "ttl": 1800
        });
        
        let secret = engine.write("db/myapp", &db_request).await.unwrap();
        
        // Verify secret structure
        assert!(secret.data.get("username").is_some());
        assert!(secret.data.get("password").is_some());
        assert!(secret.data.get("database_type").is_some());
        assert_eq!(secret.data.get("database_type").unwrap().as_str().unwrap(), "postgresql");
        assert!(secret.data.get("database").is_some());
        assert!(secret.data.get("connection_string").is_some());
        assert!(secret.data.get("permissions").is_some());
        assert!(secret.data.get("expires_at").is_some());
        assert!(secret.data.get("lease_id").is_some());
        
        // Verify permissions
        let permissions = secret.data.get("permissions").unwrap().as_array().unwrap();
        assert_eq!(permissions.len(), 2);
        assert!(permissions.iter().any(|p| p.as_str().unwrap() == "SELECT"));
        assert!(permissions.iter().any(|p| p.as_str().unwrap() == "INSERT"));
        
        // Verify lease information
        assert!(secret.metadata.lease.is_some());
        let lease = secret.metadata.lease.unwrap();
        assert_eq!(lease.ttl, 1800);
        assert!(lease.renewable);
        assert!(lease.lease_id.starts_with("db:myapp:"));
    }

    #[tokio::test]
    async fn test_mysql_credential_generation() {
        let engine = DynamicSecretsEngine::new();
        
        // Generate MySQL credentials
        let db_request = json!({
            "type": "mysql",
            "database_url": "mysql://admin:password@localhost:3306/testdb",
            "permissions": ["ALL"],
            "ttl": 3600
        });
        
        let secret = engine.write("db/myapp", &db_request).await.unwrap();
        
        // Verify secret structure
        assert_eq!(secret.data.get("database_type").unwrap().as_str().unwrap(), "mysql");
        
        let permissions = secret.data.get("permissions").unwrap().as_array().unwrap();
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].as_str().unwrap(), "ALL");
    }

    #[tokio::test]
    async fn test_sqlserver_credential_generation() {
        let engine = DynamicSecretsEngine::new();
        
        // Generate SQL Server credentials
        let db_request = json!({
            "type": "sqlserver",
            "database_url": "sqlserver://admin:password@localhost:1433/testdb",
            "permissions": ["SELECT", "INSERT", "UPDATE"],
            "ttl": 7200
        });
        
        let secret = engine.write("db/myapp", &db_request).await.unwrap();
        
        // Verify secret structure
        assert_eq!(secret.data.get("database_type").unwrap().as_str().unwrap(), "sqlserver");
        
        let permissions = secret.data.get("permissions").unwrap().as_array().unwrap();
        assert_eq!(permissions.len(), 3);
    }

    #[tokio::test]
    async fn test_unsupported_database_type() {
        let engine = DynamicSecretsEngine::new();
        
        // Try unsupported database type
        let db_request = json!({
            "type": "unsupported",
            "database_url": "unsupported://admin:password@localhost/testdb",
            "permissions": ["SELECT"],
            "ttl": 3600
        });
        
        let result = engine.write("db/myapp", &db_request).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Unsupported database type"));
    }

    #[tokio::test]
    async fn test_ttl_validation() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS first
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        // Try TTL that exceeds maximum
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "ttl": 100000 // Exceeds max_ttl of 86400
        });
        
        let result = engine.write("aws/myapp", &credential_request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TTL exceeds maximum"));
    }

    #[tokio::test]
    async fn test_credential_retrieval() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        // Generate AWS credentials
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "ttl": 3600
        });
        
        let write_secret = engine.write("aws/myapp", &credential_request).await.unwrap();
        let lease_id = write_secret.metadata.lease.unwrap().lease_id.clone();
        
        // Retrieve the credential
        let read_secret = engine.read(&lease_id).await.unwrap();
        assert!(read_secret.is_some());
        
        let retrieved = read_secret.unwrap();
        assert_eq!(retrieved.data.get("access_key_id"), write_secret.data.get("access_key_id"));
        assert_eq!(retrieved.data.get("secret_access_key"), write_secret.data.get("secret_access_key"));
        assert_eq!(retrieved.data.get("lease_id"), write_secret.data.get("lease_id"));
    }

    #[tokio::test]
    async fn test_credential_listing() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        // Generate multiple credentials
        for i in 1..=3 {
            let credential_request = json!({
                "type": "aws",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "*"
                    }]
                },
                "ttl": 3600
            });
            
            engine.write(&format!("aws/myapp{}", i), &credential_request).await.unwrap();
        }
        
        // List credentials
        let credentials = engine.list("aws/myapp").await.unwrap();
        assert_eq!(credentials.len(), 3);
        
        // Verify all credentials are listed
        for cred in &credentials {
            assert!(cred.starts_with("aws/"));
        }
    }

    #[tokio::test]
    async fn test_credential_revocation() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        // Generate credential
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "ttl": 3600
        });
        
        let secret = engine.write("aws/myapp", &credential_request).await.unwrap();
        let lease_id = secret.metadata.lease.unwrap().lease_id.clone();
        
        // Verify credential exists
        let read_secret = engine.read(&lease_id).await.unwrap();
        assert!(read_secret.is_some());
        
        // Revoke credential
        assert!(engine.delete(&lease_id).await.is_ok());
        
        // Verify credential is gone
        let read_secret_after = engine.read(&lease_id).await.unwrap();
        assert!(read_secret_after.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired_credentials() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        // Generate credential with very short TTL
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "ttl": 1 // 1 second
        });
        
        engine.write("aws/myapp", &credential_request).await.unwrap();
        
        // Wait for expiration
        sleep(Duration::from_secs(2)).await;
        
        // Cleanup expired credentials
        let cleaned_count = engine.cleanup_expired_credentials().await.unwrap();
        assert_eq!(cleaned_count, 1);
        
        // Verify credential is gone
        let credentials = engine.list("aws/myapp").await.unwrap();
        assert_eq!(credentials.len(), 0);
    }

    #[tokio::test]
    async fn test_database_username_generation() {
        let engine = DynamicSecretsEngine::new();
        
        // Generate multiple usernames for the same prefix
        let username1 = engine.generate_database_username("test_user");
        let username2 = engine.generate_database_username("test_user");
        
        // Usernames should be different (due to timestamp/randomness)
        assert_ne!(username1, username2);
        
        // Both should start with the prefix
        assert!(username1.starts_with("test_user"));
        assert!(username2.starts_with("test_user"));
        
        // Should contain timestamp and random suffix
        assert!(username1.len() > "test_user".len());
        assert!(username2.len() > "test_user".len());
    }

    #[tokio::test]
    async fn test_password_generation() {
        let engine = DynamicSecretsEngine::new();
        
        // Generate passwords
        let password1 = engine.generate_secure_password(16);
        let password2 = engine.generate_secure_password(16);
        
        // Passwords should be different
        assert_ne!(password1, password2);
        
        // Should have correct length
        assert_eq!(password1.len(), 16);
        assert_eq!(password2.len(), 16);
        
        // Should contain only valid characters
        let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
        for ch in password1.chars() {
            assert!(valid_chars.contains(ch));
        }
        for ch in password2.chars() {
            assert!(valid_chars.contains(ch));
        }
    }

    #[tokio::test]
    async fn test_connection_string_building() {
        let engine = DynamicSecretsEngine::new();
        
        // Test PostgreSQL connection string
        let pg_conn = engine.build_connection_string(
            "postgresql",
            "testuser",
            "testpass",
            "postgresql://admin:password@localhost:5432/testdb"
        ).unwrap();
        assert_eq!(pg_conn, "postgresql://testuser:testpass@localhost:5432/testdb");
        
        // Test MySQL connection string
        let mysql_conn = engine.build_connection_string(
            "mysql",
            "testuser",
            "testpass",
            "mysql://admin:password@localhost:3306/testdb"
        ).unwrap();
        assert_eq!(mysql_conn, "mysql://testuser:testpass@localhost:3306/testdb");
        
        // Test SQL Server connection string
        let sqlserver_conn = engine.build_connection_string(
            "sqlserver",
            "testuser",
            "testpass",
            "sqlserver://admin:password@localhost:1433/testdb"
        ).unwrap();
        assert_eq!(sqlserver_conn, "sqlserver://testuser:testpass@localhost:1433/testdb");
        
        // Test unsupported database type
        let invalid_conn = engine.build_connection_string(
            "unsupported",
            "testuser",
            "testpass",
            "unsupported://admin:password@localhost/testdb"
        );
        assert!(invalid_conn.is_err());
    }

    #[tokio::test]
    async fn test_aws_not_configured_error() {
        let engine = DynamicSecretsEngine::new();
        
        // Try to generate AWS credentials without configuring AWS
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "ttl": 3600
        });
        
        let result = engine.write("aws/myapp", &credential_request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("AWS not configured"));
    }

    #[tokio::test]
    async fn test_missing_required_parameters() {
        let engine = DynamicSecretsEngine::new();
        
        // Test missing database URL
        let db_request_no_url = json!({
            "type": "postgresql",
            "permissions": ["SELECT"],
            "ttl": 3600
        });
        
        let result = engine.write("db/myapp", &db_request_no_url).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Database URL is required"));
        
        // Test missing database type
        let db_request_no_type = json!({
            "database_url": "postgresql://admin:password@localhost:5432/testdb",
            "permissions": ["SELECT"],
            "ttl": 3600
        });
        
        let result = engine.write("db/myapp", &db_request_no_type).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Database type is required"));
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        let initial_stats = engine.stats().await.unwrap();
        assert_eq!(initial_stats.total_secrets, 0);
        assert_eq!(initial_stats.active_leases, 0);
        
        // Generate AWS credential
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "ttl": 3600
        });
        
        engine.write("aws/myapp", &credential_request).await.unwrap();
        
        let updated_stats = engine.stats().await.unwrap();
        assert_eq!(updated_stats.total_secrets, 1);
        assert_eq!(updated_stats.active_leases, 1);
        assert!(updated_stats.operations.contains_key("aws_generate"));
        assert_eq!(updated_stats.operations["aws_generate"], 1);
        assert!(updated_stats.last_operation.is_some());
    }

    #[tokio::test]
    async fn test_default_values() {
        let engine = DynamicSecretsEngine::new();
        
        // Test default configuration
        let status = engine.status().await.unwrap();
        let config = status.config;
        
        assert_eq!(config.get("default_ttl").unwrap().as_u64().unwrap(), 3600);
        assert_eq!(config.get("max_ttl").unwrap().as_u64().unwrap(), 86400);
        assert_eq!(config.get("cleanup_interval").unwrap().as_u64().unwrap(), 300);
        assert_eq!(config.get("auto_cleanup").unwrap().as_bool().unwrap(), true);
    }

    #[tokio::test]
    async fn test_role_assumption() {
        let engine = DynamicSecretsEngine::new();
        
        // Configure AWS with default role
        let aws_config = json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-west-2",
            "default_role": "arn:aws:iam::123456789012:role/DefaultRole"
        });
        engine.configure_aws(aws_config).await.unwrap();
        
        // Generate credentials without specifying role (should use default)
        let credential_request = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "ttl": 3600
        });
        
        let secret = engine.write("aws/myapp", &credential_request).await.unwrap();
        
        // Should have the default role
        assert_eq!(
            secret.data.get("role").unwrap().as_str().unwrap(),
            "arn:aws:iam::123456789012:role/DefaultRole"
        );
        
        // Generate credentials with specific role (should override default)
        let credential_request_with_role = json!({
            "type": "aws",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*"
                }]
            },
            "role": "arn:aws:iam::123456789012:role/SpecificRole",
            "ttl": 3600
        });
        
        let secret_with_role = engine.write("aws/myapp2", &credential_request_with_role).await.unwrap();
        
        // Should have the specific role
        assert_eq!(
            secret_with_role.data.get("role").unwrap().as_str().unwrap(),
            "arn:aws:iam::123456789012:role/SpecificRole"
        );
    }
}
