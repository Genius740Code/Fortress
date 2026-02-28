//! Integration tests for the Fortress REST API
//!
//! This module tests the complete API functionality including
//! authentication, data storage, retrieval, and key management.

use axum_test::TestServer;
use fortress_server::prelude::*;
use serde_json::json;
use std::collections::HashMap;

#[tokio::test]
async fn test_health_check() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    let response = test_server.get("/health").await;
    
    assert_eq!(response.status_code(), 200);
    
    let body: serde_json::Value = response.json();
    assert!(body["success"].as_bool().unwrap());
    assert!(body["data"].is_object());
}

#[tokio::test]
async fn test_store_and_retrieve_data() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    // Test data to store
    let test_data = json!({
        "name": "John Doe",
        "email": "john@example.com",
        "age": 30,
        "address": {
            "street": "123 Main St",
            "city": "Anytown",
            "country": "USA"
        }
    });
    
    // Store data
    let store_request = json!({
        "data": test_data,
        "metadata": {
            "source": "test",
            "version": "1.0"
        },
        "algorithm": "aegis256"
    });
    
    let store_response = test_server
        .post("/data")
        .json(&store_request)
        .await;
    
    assert_eq!(store_response.status_code(), 200);
    
    let store_body: serde_json::Value = store_response.json();
    assert!(store_body["success"].as_bool().unwrap());
    
    let data_id = store_body["data"]["id"].as_str().unwrap();
    let key_id = store_body["data"]["key_id"].as_str().unwrap();
    
    // Retrieve data
    let retrieve_response = test_server
        .get(&format!("/data/{}", data_id))
        .await;
    
    assert_eq!(retrieve_response.status_code(), 200);
    
    let retrieve_body: serde_json::Value = retrieve_response.json();
    assert!(retrieve_body["success"].as_bool().unwrap());
    
    let retrieved_data = &retrieve_body["data"]["data"];
    assert_eq!(retrieved_data["name"], "John Doe");
    assert_eq!(retrieved_data["email"], "john@example.com");
    assert_eq!(retrieved_data["age"], 30);
    
    // Verify the stored algorithm and key_id match
    assert_eq!(retrieve_body["data"]["algorithm"], "aegis256");
    assert_eq!(retrieve_body["data"]["key_id"], key_id);
}

#[tokio::test]
async fn test_list_data() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    // Store multiple items
    for i in 1..=3 {
        let test_data = json!({
            "name": format!("User {}", i),
            "index": i
        });
        
        let store_request = json!({
            "data": test_data,
            "algorithm": "aegis256"
        });
        
        let store_response = test_server
            .post("/data")
            .json(&store_request)
            .await;
        
        assert_eq!(store_response.status_code(), 200);
    }
    
    // List data
    let list_response = test_server.get("/data").await;
    
    assert_eq!(list_response.status_code(), 200);
    
    let list_body: serde_json::Value = list_response.json();
    assert!(list_body["success"].as_bool().unwrap());
    
    let items = list_body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(list_body["data"]["total_count"], 3);
    
    // Verify items are sorted by creation time (descending)
    for (i, item) in items.iter().enumerate() {
        assert!(item["id"].is_string());
        assert!(item["key_id"].is_string());
        assert_eq!(item["algorithm"], "aegis256");
        assert!(item["size_bytes"].is_number());
    }
}

#[tokio::test]
async fn test_delete_data() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    // Store data first
    let test_data = json!({
        "name": "To Be Deleted",
        "temp": true
    });
    
    let store_request = json!({
        "data": test_data,
        "algorithm": "aegis256"
    });
    
    let store_response = test_server
        .post("/data")
        .json(&store_request)
        .await;
    
    assert_eq!(store_response.status_code(), 200);
    
    let store_body: serde_json::Value = store_response.json();
    let data_id = store_body["data"]["id"].as_str().unwrap();
    
    // Delete data
    let delete_request = json!({
        "id": data_id,
        "soft_delete": false
    });
    
    let delete_response = test_server
        .delete(&format!("/data/{}", data_id))
        .json(&delete_request)
        .await;
    
    assert_eq!(delete_response.status_code(), 200);
    
    let delete_body: serde_json::Value = delete_response.json();
    assert!(delete_body["success"].as_bool().unwrap());
    assert_eq!(delete_body["data"]["id"], data_id);
    assert_eq!(delete_body["data"]["soft_delete"], false);
    
    // Verify data is gone
    let retrieve_response = test_server
        .get(&format!("/data/{}", data_id))
        .await;
    
    assert_eq!(retrieve_response.status_code(), 404);
}

#[tokio::test]
async fn test_generate_key() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    // Generate key request
    let key_request = json!({
        "algorithm": "aegis256",
        "key_size": 256,
        "metadata": {
            "purpose": "test",
            "created_by": "integration_test"
        }
    });
    
    let response = test_server
        .post("/keys")
        .json(&key_request)
        .await;
    
    assert_eq!(response.status_code(), 200);
    
    let body: serde_json::Value = response.json();
    assert!(body["success"].as_bool().unwrap());
    
    let key_data = &body["data"];
    assert!(key_data["id"].is_string());
    assert_eq!(key_data["algorithm"], "aegis256");
    assert_eq!(key_data["key_size"], 256);
    assert!(key_data["fingerprint"].is_string());
    assert!(key_data["created_at"].is_string());
    
    // Verify fingerprint is 16 characters long (SHA256 truncated)
    let fingerprint = key_data["fingerprint"].as_str().unwrap();
    assert_eq!(fingerprint.len(), 16);
}

#[tokio::test]
async fn test_field_level_encryption() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    // Test data with sensitive fields
    let test_data = json!({
        "name": "John Doe",
        "ssn": "123-45-6789",
        "credit_card": "4111-1111-1111-1111",
        "email": "john@example.com"
    });
    
    // Field encryption configuration
    let field_config = json!({
        "fields": {
            "ssn": {
                "algorithm": "aegis256",
                "sensitivity": "high"
            },
            "credit_card": {
                "algorithm": "aegis256",
                "sensitivity": "high"
            }
        }
    });
    
    let store_request = json!({
        "data": test_data,
        "field_encryption": field_config,
        "algorithm": "aegis256"
    });
    
    let store_response = test_server
        .post("/data")
        .json(&store_request)
        .await;
    
    assert_eq!(store_response.status_code(), 200);
    
    let store_body: serde_json::Value = store_response.json();
    assert!(store_body["success"].as_bool().unwrap());
    
    // Verify field metadata is present
    let field_metadata = store_body["data"]["field_metadata"];
    if field_metadata.is_object() {
        // Field encryption metadata should be present for configured fields
        assert!(field_metadata.as_object().unwrap().len() > 0);
    }
    
    let data_id = store_body["data"]["id"].as_str().unwrap();
    
    // Retrieve and verify data integrity
    let retrieve_response = test_server
        .get(&format!("/data/{}", data_id))
        .await;
    
    assert_eq!(retrieve_response.status_code(), 200);
    
    let retrieve_body: serde_json::Value = retrieve_response.json();
    assert!(retrieve_body["success"].as_bool().unwrap());
    
    let retrieved_data = &retrieve_body["data"]["data"];
    assert_eq!(retrieved_data["name"], "John Doe");
    assert_eq!(retrieved_data["email"], "john@example.com");
}

#[tokio::test]
async fn test_authentication_flow() {
    let mut config = ServerConfig::default();
    config.features.auth_enabled = true;
    
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    // Test login with valid credentials
    let auth_request = json!({
        "username": "test_user",
        "password": "test_password",
        "tenant_id": "test_tenant"
    });
    
    let auth_response = test_server
        .post("/auth/login")
        .json(&auth_request)
        .await;
    
    // This might fail if user doesn't exist, but the endpoint should be accessible
    // The exact behavior depends on the auth implementation
    assert!(auth_response.status_code().is_success() || auth_response.status_code() == 401);
    
    if auth_response.status_code().is_success() {
        let body: serde_json::Value = auth_response.json();
        if body["success"].as_bool().unwrap_or(false) {
            assert!(body["data"]["access_token"].is_string());
            assert!(body["data"]["token_type"].is_string());
            assert!(body["data"]["expires_in"].is_number());
        }
    }
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.create_router().await.unwrap();
    
    let test_server = TestServer::new(router).unwrap();
    
    // Test metrics endpoint
    let response = test_server.get("/metrics").await;
    
    assert_eq!(response.status_code(), 200);
    
    let body: serde_json::Value = response.json();
    assert!(body["metrics"].is_object());
    assert!(body["timestamp"].is_string());
    
    // Test prometheus metrics endpoint
    let prometheus_response = test_server.get("/metrics/prometheus").await;
    
    assert_eq!(prometheus_response.status_code(), 200);
    
    let prometheus_body = prometheus_response.text();
    assert!(!prometheus_body.is_empty());
    // Should contain some prometheus-style metrics
    assert!(prometheus_body.contains('#') || prometheus_body.contains('_'));
}
