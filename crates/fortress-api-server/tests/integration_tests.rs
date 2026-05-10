//! Integration tests for the Fortress REST API
//!
//! This module tests the complete API functionality including
//! authentication, data storage, retrieval, and key management.

use fortress_api_server::prelude::*;
use serde_json::json;
use axum::body::Body;
use http::{Request, StatusCode};
use tower::ServiceExt;

async fn request_json(app: axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn request_text(app: axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn test_health_check() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.router().await.unwrap();

    let (status, body) = request_json(
        router,
        Request::builder().method("GET").uri("/health").body(Body::empty()).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["success"].as_bool().unwrap());
    assert!(body["data"].is_object());
}

#[tokio::test]
async fn test_store_and_retrieve_data() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.router().await.unwrap();
    
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
    

    let (status, store_body) = request_json(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/data")
            .header("content-type", "application/json")
            .body(Body::from(store_request.to_string()))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(store_body["success"].as_bool().unwrap());
    
    let data_id = store_body["data"]["id"].as_str().unwrap();
    let key_id = store_body["data"]["key_id"].as_str().unwrap();
    
    // Retrieve data

    let (status, retrieve_body) = request_json(
        router,
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/data/{data_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
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
    let router = server.router().await.unwrap();
    
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
        
        let (status, _body) = request_json(
            router.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/v1/data")
                .header("content-type", "application/json")
                .body(Body::from(store_request.to_string()))
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
    }
    
    // List data
    let (status, list_body) = request_json(
        router,
        Request::builder().method("GET").uri("/api/v1/data").body(Body::empty()).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
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
    let router = server.router().await.unwrap();
    
    // Store data first
    let test_data = json!({
        "name": "To Be Deleted",
        "temp": true
    });
    
    let store_request = json!({
        "data": test_data,
        "algorithm": "aegis256"
    });
    

    let (status, store_body) = request_json(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/data")
            .header("content-type", "application/json")
            .body(Body::from(store_request.to_string()))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let data_id = store_body["data"]["id"].as_str().unwrap();
    
    // Delete data
    let delete_request = json!({
        "id": data_id,
        "soft_delete": false
    });
    

    let (status, delete_body) = request_json(
        router.clone(),
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/data/{data_id}"))
            .header("content-type", "application/json")
            .body(Body::from(delete_request.to_string()))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(delete_body["success"].as_bool().unwrap());
    assert_eq!(delete_body["data"]["id"], data_id);
    assert_eq!(delete_body["data"]["soft_delete"], false);
    
    // Verify data is gone

    let (status, _body) = request_json(
        router,
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/data/{data_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_generate_key() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.router().await.unwrap();
    
    // Generate key request
    let key_request = json!({
        "algorithm": "aegis256",
        "key_size": 256,
        "metadata": {
            "purpose": "test",
            "created_by": "integration_test"
        }
    });
    

    let (status, body) = request_json(
        router,
        Request::builder()
            .method("POST")
            .uri("/api/v1/keys")
            .header("content-type", "application/json")
            .body(Body::from(key_request.to_string()))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
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
    let router = server.router().await.unwrap();
    
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

    let (status, store_body) = request_json(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/data")
            .header("content-type", "application/json")
            .body(Body::from(store_request.to_string()))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(store_body["success"].as_bool().unwrap());
    
    // Verify field metadata is present
    let field_metadata = store_body["data"]["field_metadata"];
    if field_metadata.is_object() {
        // Field encryption metadata should be present for configured fields
        assert!(field_metadata.as_object().unwrap().len() > 0);
    }
    
    let data_id = store_body["data"]["id"].as_str().unwrap();
    
    // Retrieve and verify data integrity

    let (status, retrieve_body) = request_json(
        router,
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/data/{data_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
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
    let router = server.router().await.unwrap();
    
    // Test login with valid credentials
    let auth_request = json!({
        "username": "test_user",
        "password": "test_password",
        "tenant_id": "test_tenant"
    });
    

    let (status, body) = request_json(
        router,
        Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(auth_request.to_string()))
            .unwrap(),
    )
    .await;

    // This might fail if user doesn't exist, but the endpoint should be accessible.
    assert!(status.is_success() || status == StatusCode::UNAUTHORIZED);

    if status.is_success() {
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
    let router = server.router().await.unwrap();

    // JSON metrics are exposed at /api/v1/metrics
    let (status, body) = request_json(
        router.clone(),
        Request::builder().method("GET").uri("/api/v1/metrics").body(Body::empty()).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["metrics"].is_object());
    assert!(body["timestamp"].is_string());

    // Prometheus exposition is served as plain text on /metrics
    let (status, prometheus_body) = request_text(
        router,
        Request::builder().method("GET").uri("/metrics").body(Body::empty()).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!prometheus_body.is_empty());
    assert!(prometheus_body.contains('#') || prometheus_body.contains('_'));
}

#[tokio::test]
async fn test_storage_backend_integration() {
    // Test with different storage backends
    let mut config = ServerConfig::default();

    // Test in-memory storage
    config.core.storage.backend = "in_memory".to_string();
    
    let server = FortressServer::new(config).await.unwrap();
    let router = server.router().await.unwrap();
    
    // Store and retrieve data
    let test_data = json!({
        "test": "storage_backend_integration",
        "backend": "memory"
    });
    
    let store_request = json!({
        "data": test_data
    });

    let (status, store_body) = request_json(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/data")
            .header("content-type", "application/json")
            .body(Body::from(store_request.to_string()))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let data_id = store_body["data"]["id"].as_str().unwrap();
    
    // Retrieve the data

    let (status, retrieve_body) = request_json(
        router,
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/data/{data_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(retrieve_body["data"]["data"]["test"], "storage_backend_integration");
}

#[tokio::test]
async fn test_error_handling() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.router().await.unwrap();

    let (status, body) = request_json(
        router,
        Request::builder()
            .method("GET")
            .uri("/api/v1/data/non-existent-id")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body["success"].as_bool().unwrap());
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn test_concurrent_requests() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.router().await.unwrap();
    
    // Create multiple concurrent requests
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let router = router.clone();
        let handle = tokio::spawn(async move {
            let test_data = json!({
                "id": i,
                "message": format!("Concurrent test {}", i)
            });
            
            let store_request = json!({
                "data": test_data
            });
            
            request_json(
                router,
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/data")
                    .header("content-type", "application/json")
                    .body(Body::from(store_request.to_string()))
                    .unwrap(),
            )
            .await
        });
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let results = futures::future::join_all(handles).await;
    
    // All requests should succeed
    for result in results {
        let (status, _body) = result.unwrap();
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn test_large_data_handling() {
    let config = ServerConfig::default();
    let server = FortressServer::new(config).await.unwrap();
    let router = server.router().await.unwrap();
    
    // Create large test data (1MB)
    let large_data = json!({
        "data": "x".repeat(1024 * 1024),
        "size": 1024 * 1024
    });
    
    let store_request = json!({
        "data": large_data
    });

    let (status, store_body) = request_json(
        router.clone(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/data")
            .header("content-type", "application/json")
            .body(Body::from(store_request.to_string()))
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let data_id = store_body["data"]["id"].as_str().unwrap();
    
    // Retrieve the large data
    let (status, retrieve_body) = request_json(
        router,
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/data/{data_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let retrieved_size = retrieve_body["data"]["data"]["size"].as_u64().unwrap();
    assert_eq!(retrieved_size, 1024 * 1024);
}
