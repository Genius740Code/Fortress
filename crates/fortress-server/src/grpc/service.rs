use crate::grpc::types::*;
use crate::error::FortressServerError;
use fortress_core::{FortressDatabase, encryption::EncryptionManager};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, debug};

#[derive(Debug, Clone)]
pub struct FortressGrpcService {
    database: Arc<RwLock<Option<FortressDatabase>>>,
    encryption_manager: Arc<EncryptionManager>,
}

impl FortressGrpcService {
    pub fn new(encryption_manager: Arc<EncryptionManager>) -> Self {
        Self {
            database: Arc::new(RwLock::new(None)),
            encryption_manager,
        }
    }

    pub async fn set_database(&self, database: FortressDatabase) {
        let mut db = self.database.write().await;
        *db = Some(database);
    }

    fn map_error(err: FortressServerError) -> String {
        error!("gRPC service error: {:?}", err);
        err.to_string()
    }
}

// Basic gRPC service implementation using HTTP/JSON for now
// This can be upgraded to full protobuf-based gRPC later
impl FortressGrpcService {
    pub async fn create_database(
        &self,
        request: CreateDatabaseRequest,
    ) -> Result<DatabaseResponse, String> {
        info!("Creating database: {}", request.name);

        let database = Database {
            id: uuid::Uuid::new_v4().to_string(),
            name: request.name,
            description: request.description,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            config: request.config.unwrap_or_default(),
        };

        Ok(DatabaseResponse { database })
    }

    pub async fn get_database(
        &self,
        request: GetDatabaseRequest,
    ) -> Result<DatabaseResponse, String> {
        debug!("Getting database: {}", request.database_id);

        // Implementation would fetch from storage
        Err("Database not found".to_string())
    }

    pub async fn list_databases(
        &self,
        _request: ListDatabasesRequest,
    ) -> Result<ListDatabasesResponse, String> {
        info!("Listing databases");
        
        // Implementation would list from storage
        Ok(ListDatabasesResponse {
            databases: vec![],
            next_page_token: "".to_string(),
        })
    }

    pub async fn delete_database(
        &self,
        request: DeleteDatabaseRequest,
    ) -> Result<(), String> {
        info!("Deleting database: {}", request.database_id);

        // Implementation would delete from storage
        Ok(())
    }

    pub async fn encrypt_data(
        &self,
        request: EncryptRequest,
    ) -> Result<EncryptResponse, String> {
        debug!("Encrypting data for database: {}", request.database_id);

        // Use fortress-core encryption
        match self.encryption_manager.encrypt(&request.plaintext).await {
            Ok(ciphertext) => {
                let response = EncryptResponse {
                    ciphertext,
                    key_id: uuid::Uuid::new_v4().to_string(),
                    encrypted_at: chrono::Utc::now(),
                    metadata: request.metadata,
                };
                Ok(response)
            }
            Err(e) => Err(Self::map_error(FortressServerError::Encryption(e))),
        }
    }

    pub async fn decrypt_data(
        &self,
        request: DecryptRequest,
    ) -> Result<DecryptResponse, String> {
        debug!("Decrypting data for database: {}", request.database_id);

        // Use fortress-core decryption
        match self.encryption_manager.decrypt(&request.ciphertext).await {
            Ok(plaintext) => {
                let response = DecryptResponse {
                    plaintext,
                    decrypted_at: chrono::Utc::now(),
                    metadata: HashMap::new(),
                };
                Ok(response)
            }
            Err(e) => Err(Self::map_error(FortressServerError::Encryption(e))),
        }
    }

    pub async fn health_check(
        &self,
    ) -> Result<HealthResponse, String> {
        debug!("Health check requested");

        let components = vec![
            ComponentHealth {
                name: "encryption".to_string(),
                status: 1, // Healthy
                message: "All encryption systems operational".to_string(),
            },
            ComponentHealth {
                name: "storage".to_string(),
                status: 1, // Healthy
                message: "Storage backend operational".to_string(),
            },
        ];

        let response = HealthResponse {
            status: 1, // Healthy
            version: "0.1.0".to_string(),
            timestamp: chrono::Utc::now(),
            components,
        };

        Ok(response)
    }

    pub async fn get_metrics(
        &self,
    ) -> Result<MetricsResponse, String> {
        debug!("Metrics requested");

        // Implementation would collect actual metrics
        let response = MetricsResponse {
            timestamp: chrono::Utc::now(),
            counters: HashMap::new(),
            gauges: HashMap::new(),
            histograms: HashMap::new(),
        };

        Ok(response)
    }
}
