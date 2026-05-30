use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fortress_core::encryption::{Aegis256Wrapper, ChaCha20Poly1305, Aes256Gcm, EncryptionAlgorithm};
use fortress_core::key::{KeyManager, KeyMetadata};
use fortress_core::storage::StorageBackend;
use fortress_core::cache::CacheManager;
use std::time::Duration;

fn bench_encryption_algorithms(c: &mut Criterion) {
    let data_sizes = vec![1024, 4096, 16384]; // 1KB, 4KB, 16KB
    
    let mut group = c.benchmark_group("encryption");
    
    for size in data_sizes {
        let data = vec![0u8; size];
        
        // AEGIS-256
        group.bench_with_input(BenchmarkId::new("aegis256_encrypt", size), &size, |b, _| {
            let key = KeyManager::new().generate_key(&Aegis256Wrapper::new()).unwrap();
            b.iter(|| {
                let cipher = Aegis256Wrapper::new();
                cipher.encrypt(black_box(&data), black_box(&key))
            })
        });
        
        // ChaCha20Poly1305
        group.bench_with_input(BenchmarkId::new("chacha20poly1305_encrypt", size), &size, |b, _| {
            let key = KeyManager::new().generate_key(&ChaCha20Poly1305::new()).unwrap();
            b.iter(|| {
                let cipher = ChaCha20Poly1305::new();
                cipher.encrypt(black_box(&data), black_box(&key))
            })
        });
        
        // AES-256-GCM
        group.bench_with_input(BenchmarkId::new("aes256gcm_encrypt", size), &size, |b, _| {
            let key = KeyManager::new().generate_key(&Aes256Gcm::new()).unwrap();
            b.iter(|| {
                let cipher = Aes256Gcm::new();
                cipher.encrypt(black_box(&data), black_box(&key))
            })
        });
    }
    
    group.finish();
}

fn bench_decryption_algorithms(c: &mut Criterion) {
    let data = vec![0u8; 4096]; // 4KB
    
    let mut group = c.benchmark_group("decryption");
    
    // AEGIS-256
    group.bench_function("aegis256_decrypt", |b| {
        let key = KeyManager::new().generate_key(&Aegis256Wrapper::new()).unwrap();
        let cipher = Aegis256Wrapper::new();
        let encrypted = cipher.encrypt(&data, &key).unwrap();
        b.iter(|| {
            let cipher = Aegis256Wrapper::new();
            cipher.decrypt(black_box(&encrypted), black_box(&key))
        })
    });
    
    // ChaCha20Poly1305
    group.bench_function("chacha20poly1305_decrypt", |b| {
        let key = KeyManager::new().generate_key(&ChaCha20Poly1305::new()).unwrap();
        let cipher = ChaCha20Poly1305::new();
        let encrypted = cipher.encrypt(&data, &key).unwrap();
        b.iter(|| {
            let cipher = ChaCha20Poly1305::new();
            cipher.decrypt(black_box(&encrypted), black_box(&key))
        })
    });
    
    // AES-256-GCM
    group.bench_function("aes256gcm_decrypt", |b| {
        let key = KeyManager::new().generate_key(&Aes256Gcm::new()).unwrap();
        let cipher = Aes256Gcm::new();
        let encrypted = cipher.encrypt(&data, &key).unwrap();
        b.iter(|| {
            let cipher = Aes256Gcm::new();
            cipher.decrypt(black_box(&encrypted), black_box(&key))
        })
    });
    
    group.finish();
}

fn bench_key_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_operations");
    
    // Key generation
    group.bench_function("key_generation_aegis256", |b| {
        let key_manager = KeyManager::new();
        let algorithm = Aegis256Wrapper::new();
        b.iter(|| {
            key_manager.generate_key(black_box(&algorithm))
        })
    });
    
    group.bench_function("key_generation_chacha20poly1305", |b| {
        let key_manager = KeyManager::new();
        let algorithm = ChaCha20Poly1305::new();
        b.iter(|| {
            key_manager.generate_key(black_box(&algorithm))
        })
    });
    
    group.bench_function("key_generation_aes256gcm", |b| {
        let key_manager = KeyManager::new();
        let algorithm = Aes256Gcm::new();
        b.iter(|| {
            key_manager.generate_key(black_box(&algorithm))
        })
    });
    
    group.finish();
}

fn bench_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_operations");
    
    // Cache put
    group.bench_function("cache_put", |b| {
        let cache = CacheManager::new(1000);
        let key = "test_key";
        let value = vec![0u8; 1024];
        b.iter(|| {
            cache.put(black_box(key), black_box(value.clone()))
        })
    });
    
    // Cache get
    group.bench_function("cache_get", |b| {
        let cache = CacheManager::new(1000);
        let key = "test_key";
        let value = vec![0u8; 1024];
        cache.put(key, value).unwrap();
        b.iter(|| {
            cache.get(black_box(key))
        })
    });
    
    // Cache hit and miss
    group.bench_function("cache_miss", |b| {
        let cache = CacheManager::new(1000);
        b.iter(|| {
            cache.get(black_box("non_existent_key"))
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_encryption_algorithms,
    bench_decryption_algorithms,
    bench_key_operations,
    bench_cache_operations
);
criterion_main!(benches);
