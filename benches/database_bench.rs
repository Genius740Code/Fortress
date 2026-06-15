use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fortress_core::key_database::{
    create_key_database, KeyDatabase, KeyDatabaseBackend, KeyDatabaseConfig,
};
use fortress_core::key::{KeyMetadata, SecureKey, KeyPurpose};
use fortress_core::encryption::{Aes256Gcm, EncryptionAlgorithm, PerformanceProfile};
use tokio::runtime::Runtime;
use uuid::Uuid;
use chrono::{Utc, Duration};
use std::sync::Arc;

async fn setup_db() -> Arc<dyn KeyDatabase> {
    let key_db_config = KeyDatabaseConfig {
        backend: KeyDatabaseBackend::Sqlite,
        connection_string: "sqlite::memory:".to_string(), // In-memory SQLite
        max_connections: 1, // Only one connection for benchmarking purposes
        connection_timeout_seconds: 5,
        encrypt_at_rest: false, // Disable encryption at rest for benchmarking
        master_key: None,
    };
    let db = create_key_database(key_db_config)
        .await
        .expect("Failed to set up database for benchmark");
    // db.initialize().await.expect("Failed to initialize database schema"); // Initialize is called inside create_key_database
    Arc::from(db)
}

fn create_test_key_data(id: &str, version: u32) -> (SecureKey, KeyMetadata) {
    let aes_gcm = Aes256Gcm::new();
    let key = SecureKey::generate(aes_gcm.key_size()).expect("Failed to generate test key");
    let metadata = KeyMetadata::new(
        id.to_string(),
        aes_gcm.name().to_string(),
        version,
        Utc::now(),
        Utc::now() + Duration::days(30),
        format!("{:?}", KeyPurpose::DataEncryption),
        PerformanceProfile::Balanced,
    );
    (key, metadata)
}

fn bench_db_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Benchmark Key Creation (Store)
    c.bench_function("db_store_key", |b| {
        let db = rt.block_on(setup_db());
        b.to_async(&rt).iter(|| async {
            let key_id = Uuid::new_v4().to_string();
            let (key, metadata) = create_test_key_data(&key_id, 1);
            black_box(db.store_key(&key_id, &key, &metadata).await.unwrap());
        });
    });

    // Prepare for Read, Update, Delete benchmarks by creating a key
    let db_for_crud = rt.block_on(setup_db());
    let existing_key_id = rt.block_on(async {
        let key_id = Uuid::new_v4().to_string();
        let (key, metadata) = create_test_key_data(&key_id, 1);
        db_for_crud.store_key(&key_id, &key, &metadata).await.unwrap();
        key_id
    });

    // Benchmark Key Read (Retrieve)
    c.bench_function("db_retrieve_key", |b| {
        let db = db_for_crud.clone();
        b.to_async(&rt).iter(|| async {
            black_box(db.retrieve_key(&existing_key_id).await.unwrap());
        });
    });

    // Benchmark Key Update (Store with existing ID)
    c.bench_function("db_update_key", |b| {
        let db = db_for_crud.clone();
        b.to_async(&rt).iter(|| async {
            let (new_key, new_metadata) = create_test_key_data(&existing_key_id, 2);
            black_box(db.store_key(&existing_key_id, &new_key, &new_metadata).await.unwrap());
        });
    });

    // Benchmark Key Deletion
    c.bench_function("db_delete_key", |b| {
        let db_cloned_for_setup = db_for_crud.clone(); // Clone once for the outer setup
        b.to_async(&rt).iter_custom(move |iters| { // Move db_cloned_for_setup into this closure
            let db_for_async_move = db_cloned_for_setup.clone(); // Clone again for the async move block
            async move { 
                let mut total_duration = std::time::Duration::new(0, 0);
                for _i in 0..iters {
                    let db_for_iteration = db_for_async_move.clone(); // Clone for each iteration within the loop
                    let key_id = Uuid::new_v4().to_string();
                    let (key, metadata) = create_test_key_data(&key_id, 1);
                    db_for_iteration.store_key(&key_id, &key, &metadata).await.unwrap();

                    let start = std::time::Instant::now();
                    black_box(db_for_iteration.delete_key(&key_id).await.unwrap());
                    total_duration += start.elapsed();
                }
                total_duration
            }
        });
    });

    // Benchmark Key Listing
    c.bench_function("db_list_keys", |b| {
        let db = db_for_crud.clone();
        // Populate with some keys for listing
        rt.block_on(async {
            for i in 0..100 {
                let key_id = format!("list_key_{}", i);
                let (key, metadata) = create_test_key_data(&key_id, 1);
                db.store_key(&key_id, &key, &metadata).await.unwrap();
            }
        });
        b.to_async(&rt).iter(|| async {
            black_box(db.list_keys(None, None).await.unwrap());
        });
    });
}

criterion_group!(benches, bench_db_operations);
criterion_main!(benches);