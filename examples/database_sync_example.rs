//! Database synchronization example using MongoDB and PostgreSQL
//!
//! This example demonstrates how to use the Fortress push/pull operations
//! to synchronize data between MongoDB and PostgreSQL databases.

use fortress_core::prelude::*;
use std::collections::HashMap;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🔐 Fortress Database Synchronization Example");
    println!("==========================================");
    
    // Create push/pull manager
    let config = PushPullConfig {
        max_batch_size: 100,
        max_concurrent_ops: 5,
        timeout_seconds: 60,
        enable_compression: true,
        conflict_resolution: ConflictResolution::Timestamp,
        enable_incremental: true,
        verify_checksums: true,
        enable_progress: true,
    };
    
    let manager = PushPullManager::new(config);
    
    // Configure MongoDB source
    let mongo_config = MongoConfig {
        connection_string: "mongodb://localhost:27017".to_string(),
        database_name: "fortress_source".to_string(),
        keys_collection: "fortress_keys".to_string(),
        data_collection: "fortress_data".to_string(),
        max_pool_size: 10,
        tls_enabled: false,
        auth_database: None,
        replica_set: None,
        read_preference: MongoReadPreference::Primary,
        write_concern: MongoWriteConcern::Acknowledged,
    };
    
    // Configure PostgreSQL target
    let postgres_config = PostgresConfig {
        connection_string: "postgresql://localhost:5432/fortress_target".to_string(),
        database_name: "fortress_target".to_string(),
        schema: "public".to_string(),
        keys_table: "fortress_keys".to_string(),
        data_table: "fortress_data".to_string(),
        max_connections: 20,
        connection_timeout_seconds: 30,
        ssl_enabled: false,
        log_statements: false,
        enable_pooling: true,
        partitioning: Some(PostgresPartitioning::ByDate { 
            column: "created_at".to_string(), 
            interval: "1 day".to_string() 
        }),
        replication: PostgresReplicationConfig {
            streaming_enabled: false,
            slot_name: None,
            publication_name: None,
            sync_mode: PostgresSyncMode::Asynchronous,
        },
    };
    
    // Initialize databases
    println!("📊 Initializing databases...");
    
    let mongo_db = MongoKeyDatabase::new(mongo_config.clone()).await?;
    mongo_db.initialize().await?;
    println!("✅ MongoDB initialized");
    
    let postgres_db = PostgresKeyDatabase::new(postgres_config.clone()).await?;
    postgres_db.initialize().await?;
    println!("✅ PostgreSQL initialized");
    
    // Add sample data to MongoDB
    println!("📝 Adding sample data to MongoDB...");
    add_sample_data_to_mongo(&mongo_db).await?;
    
    // Perform MongoDB to PostgreSQL push
    println!("🚀 Pushing data from MongoDB to PostgreSQL...");
    let push_result = push_mongo_to_postgres(&manager, &mongo_config, &postgres_config).await?;
    
    print_operation_result(&push_result);
    
    // Perform PostgreSQL to MongoDB pull
    println!("🔄 Pulling data from PostgreSQL to MongoDB...");
    let pull_result = pull_postgres_to_mongo(&manager, &postgres_config, &mongo_config).await?;
    
    print_operation_result(&pull_result);
    
    // Demonstrate advanced MongoDB operations
    println!("🔍 Demonstrating advanced MongoDB operations...");
    demonstrate_mongo_features(&mongo_db).await?;
    
    // Demonstrate advanced PostgreSQL operations
    println!("🔍 Demonstrating advanced PostgreSQL operations...");
    demonstrate_postgres_features(&postgres_db).await?;
    
    // Demonstrate bidirectional sync
    println!("🔄 Demonstrating bidirectional synchronization...");
    demonstrate_bidirectional_sync(&manager, &mongo_config, &postgres_config).await?;
    
    println!("✅ Database synchronization example completed successfully!");
    
    Ok(())
}

/// Add sample data to MongoDB
async fn add_sample_data_to_mongo(mongo_db: &MongoKeyDatabase) -> Result<()> {
    let mut sample_data = Vec::new();
    
    // Add various types of data
    for i in 1..=50 {
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), if i % 2 == 0 { "document" } else { "binary" }.to_string());
        metadata.insert("category".to_string(), format!("category_{}", i % 5));
        metadata.insert("priority".to_string(), if i % 3 == 0 { "high" } else { "normal" }.to_string());
        
        let data = if i % 2 == 0 {
            format!("Document content for item {}", i).into_bytes()
        } else {
            (0..100).map(|j| (i * j) as u8).collect::<Vec<u8>>()
        };
        
        sample_data.push((format!("item_{}", i), data, metadata));
    }
    
    let count = mongo_db.push_bulk(sample_data).await?;
    println!("📈 Added {} sample items to MongoDB", count);
    
    Ok(())
}

/// Push data from MongoDB to PostgreSQL
async fn push_mongo_to_postgres(
    manager: &PushPullManager,
    mongo_config: &MongoConfig,
    postgres_config: &PostgresConfig,
) -> Result<PushPullResult> {
    let push_request = PushRequest {
        operation_id: format!("mongo_to_postgres_{}", uuid::Uuid::new_v4()),
        source: StorageSource::Mongo { config: mongo_config.clone() },
        target: StorageTarget::Postgres { config: postgres_config.clone() },
        filter: PushFilter::All,
        config: PushPullConfig::default(),
        started_at: chrono::Utc::now(),
    };
    
    let result = manager.push(push_request).await?;
    Ok(result)
}

/// Pull data from PostgreSQL to MongoDB
async fn pull_postgres_to_mongo(
    manager: &PushPullManager,
    postgres_config: &PostgresConfig,
    mongo_config: &MongoConfig,
) -> Result<PushPullResult> {
    let pull_request = PullRequest {
        operation_id: format!("postgres_to_mongo_{}", uuid::Uuid::new_v4()),
        source: StorageSource::Postgres { config: postgres_config.clone() },
        target: StorageTarget::Mongo { config: mongo_config.clone() },
        filter: PullFilter::DateRange { 
            start: chrono::Utc::now() - chrono::Duration::hours(1),
            end: chrono::Utc::now(),
        },
        config: PushPullConfig::default(),
        started_at: chrono::Utc::now(),
    };
    
    let result = manager.pull(pull_request).await?;
    Ok(result)
}

/// Print operation result
fn print_operation_result(result: &PushPullResult) {
    println!("📊 Operation Result:");
    println!("  Type: {:?}", result.operation_type);
    println!("  Success: {}", result.success);
    println!("  Items Processed: {}", result.items_processed);
    println!("  Items Succeeded: {}", result.items_succeeded);
    println!("  Items Failed: {}", result.items_failed);
    println!("  Bytes Transferred: {}", result.bytes_transferred);
    
    if let Some(duration) = result.duration_seconds {
        println!("  Duration: {} seconds", duration);
    }
    
    if let Some(ref error) = result.error_message {
        println!("  Error: {}", error);
    }
    
    if !result.progress_updates.is_empty() {
        println!("  Progress Updates: {}", result.progress_updates.len());
    }
    
    println!();
}

/// Demonstrate advanced MongoDB features
async fn demonstrate_mongo_features(mongo_db: &MongoKeyDatabase) -> Result<()> {
    // Test aggregation pipeline
    println!("  📊 Testing MongoDB aggregation...");
    let pipeline = MongoPipeline {
        operation: "count_by_type".to_string(),
        stages: vec![],
    };
    
    let aggregation_results = mongo_db.aggregate(pipeline).await?;
    println!("    Aggregation results: {:?}", aggregation_results);
    
    // Test text search
    println!("  🔍 Testing MongoDB text search...");
    let search_results = mongo_db.text_search("document", Some(5)).await?;
    println!("    Search results: {} items found", search_results.len());
    
    // Test filtered pull
    println!("  🎯 Testing filtered pull...");
    let filtered_results = mongo_db.pull_filtered(MongoPullFilter::Prefix("item_1".to_string())).await?;
    println!("    Filtered results: {} items", filtered_results.len());
    
    Ok(())
}

/// Demonstrate advanced PostgreSQL features
async fn demonstrate_postgres_features(postgres_db: &PostgresKeyDatabase) -> Result<()> {
    // Test cursor-based query
    println!("  📊 Testing PostgreSQL cursor query...");
    let query = PostgresQuery {
        key_filter: Some("item_".to_string()),
        date_start: None,
        date_end: None,
        min_size: None,
        max_size: None,
        content_type: None,
        offset: Some(0),
        limit: Some(10),
    };
    
    let cursor = postgres_db.pull_cursor(query).await?;
    println!("    Cursor results: {} items", cursor.results.len());
    
    // Test full-text search
    println!("  🔍 Testing PostgreSQL full-text search...");
    let search_results = postgres_db.full_text_search("content", Some(5)).await?;
    println!("    Search results: {} items found", search_results.len());
    
    // Test JSONB query
    println!("  🎯 Testing PostgreSQL JSONB query...");
    let jsonb_query = PostgresJsonbQuery::Equals {
        path: "priority",
        value: serde_json::Value::String("high".to_string()),
    };
    
    let jsonb_results = postgres_db.jsonb_query(jsonb_query).await?;
    println!("    JSONB query results: {} items", jsonb_results.len());
    
    // Test bulk operations
    println!("  📦 Testing PostgreSQL bulk operations...");
    let bulk_entries = vec![
        PostgresBulkEntry {
            key: "bulk_test_1".to_string(),
            data: b"Bulk test data 1".to_vec(),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("bulk".to_string(), "true".to_string());
                meta
            },
            content_type: "text/plain".to_string(),
            encoding: "utf-8".to_string(),
            compression: "none".to_string(),
            partition_key: Some("test_partition".to_string()),
        },
        PostgresBulkEntry {
            key: "bulk_test_2".to_string(),
            data: b"Bulk test data 2".to_vec(),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("bulk".to_string(), "true".to_string());
                meta
            },
            content_type: "text/plain".to_string(),
            encoding: "utf-8".to_string(),
            compression: "none".to_string(),
            partition_key: Some("test_partition".to_string()),
        },
    ];
    
    let bulk_count = postgres_db.push_bulk_copy(bulk_entries).await?;
    println!("    Bulk operations: {} items processed", bulk_count);
    
    Ok(())
}

/// Demonstrate bidirectional synchronization
async fn demonstrate_bidirectional_sync(
    manager: &PushPullManager,
    mongo_config: &MongoConfig,
    postgres_config: &PostgresConfig,
) -> Result<()> {
    // Add new data to MongoDB
    let mongo_db = MongoKeyDatabase::new(mongo_config.clone()).await?;
    let new_data = vec![
        ("sync_test_1".to_string(), b"Sync test data 1".to_vec(), HashMap::new()),
        ("sync_test_2".to_string(), b"Sync test data 2".to_vec(), HashMap::new()),
    ];
    
    mongo_db.push_bulk(new_data).await?;
    println!("  📝 Added new test data to MongoDB");
    
    // Push to PostgreSQL
    let push_result = push_mongo_to_postgres(manager, mongo_config, postgres_config).await?;
    println!("  📤 Push result: {} items processed", push_result.items_processed);
    
    // Add new data to PostgreSQL
    let postgres_db = PostgresKeyDatabase::new(postgres_config.clone()).await?;
    let postgres_bulk = vec![
        PostgresBulkEntry {
            key: "sync_test_3".to_string(),
            data: b"Sync test data 3".to_vec(),
            metadata: HashMap::new(),
            content_type: "text/plain".to_string(),
            encoding: "utf-8".to_string(),
            compression: "none".to_string(),
            partition_key: None,
        },
    ];
    
    postgres_db.push_bulk_copy(postgres_bulk).await?;
    println!("  📝 Added new test data to PostgreSQL");
    
    // Pull from PostgreSQL to MongoDB
    let pull_result = pull_postgres_to_mongo(manager, postgres_config, mongo_config).await?;
    println!("  📥 Pull result: {} items processed", pull_result.items_processed);
    
    // Verify data exists in both databases
    let final_mongo_data = mongo_db.pull_filtered(MongoPullFilter::Prefix("sync_test".to_string())).await?;
    let final_postgres_query = PostgresQuery {
        key_filter: Some("sync_test".to_string()),
        date_start: None,
        date_end: None,
        min_size: None,
        max_size: None,
        content_type: None,
        offset: None,
        limit: None,
    };
    let final_postgres_data = postgres_db.pull_cursor(final_postgres_query).await?;
    
    println!("  ✅ Final verification:");
    println!("    MongoDB items: {}", final_mongo_data.len());
    println!("    PostgreSQL items: {}", final_postgres_data.results.len());
    
    Ok(())
}
