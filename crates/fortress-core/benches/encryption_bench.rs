//! Encryption benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fortress_core::encryption::{Aegis256, ChaCha20Poly1305, Aes256Gcm, EncryptionAlgorithm};
use fortress_core::encryption::SecureKey;

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_decrypt");
    
    // Test different data sizes
    for size in [64, 1024, 8192, 65536, 1048576].iter() {
        // AEGIS-256
        group.bench_with_input(
            BenchmarkId::new("aegis256_encrypt", size),
            size,
            |b, &size| {
                let algorithm = Aegis256::new();
                let key = SecureKey::generate(algorithm.key_size());
                let data = vec![0u8; size];
                
                b.iter(|| {
                    black_box(algorithm.encrypt(black_box(&data), black_box(key.as_bytes())).unwrap())
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("aegis256_decrypt", size),
            size,
            |b, &size| {
                let algorithm = Aegis256::new();
                let key = SecureKey::generate(algorithm.key_size());
                let data = vec![0u8; size];
                let ciphertext = algorithm.encrypt(&data, key.as_bytes()).unwrap();
                
                b.iter(|| {
                    black_box(algorithm.decrypt(black_box(&ciphertext), black_box(key.as_bytes())).unwrap())
                });
            },
        );
        
        // ChaCha20-Poly1305
        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_encrypt", size),
            size,
            |b, &size| {
                let algorithm = ChaCha20Poly1305::new();
                let key = SecureKey::generate(algorithm.key_size());
                let data = vec![0u8; size];
                
                b.iter(|| {
                    black_box(algorithm.encrypt(black_box(&data), black_box(key.as_bytes())).unwrap())
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_decrypt", size),
            size,
            |b, &size| {
                let algorithm = ChaCha20Poly1305::new();
                let key = SecureKey::generate(algorithm.key_size());
                let data = vec![0u8; size];
                let ciphertext = algorithm.encrypt(&data, key.as_bytes()).unwrap();
                
                b.iter(|| {
                    black_box(algorithm.decrypt(black_box(&ciphertext), black_box(key.as_bytes())).unwrap())
                });
            },
        );
        
        // AES-256-GCM
        group.bench_with_input(
            BenchmarkId::new("aes256gcm_encrypt", size),
            size,
            |b, &size| {
                let algorithm = Aes256Gcm::new();
                let key = SecureKey::generate(algorithm.key_size());
                let data = vec![0u8; size];
                
                b.iter(|| {
                    black_box(algorithm.encrypt(black_box(&data), black_box(key.as_bytes())).unwrap())
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("aes256gcm_decrypt", size),
            size,
            |b, &size| {
                let algorithm = Aes256Gcm::new();
                let key = SecureKey::generate(algorithm.key_size());
                let data = vec![0u8; size];
                let ciphertext = algorithm.encrypt(&data, key.as_bytes()).unwrap();
                
                b.iter(|| {
                    black_box(algorithm.decrypt(black_box(&ciphertext), black_box(key.as_bytes())).unwrap())
                });
            },
        );
    }
    
    group.finish();
}

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");
    
    group.bench_function("secure_key_generate_32", |b| {
        b.iter(|| {
            black_box(SecureKey::generate(32))
        });
    });
    
    group.bench_function("secure_key_generate_64", |b| {
        b.iter(|| {
            black_box(SecureKey::generate(64))
        });
    });
    
    group.finish();
}

fn bench_encrypted_data_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypted_data_serialization");
    
    let algorithm = Aegis256::new();
    let key = SecureKey::generate(algorithm.key_size());
    let data = vec![0u8; 8192];
    let ciphertext = algorithm.encrypt(&data, key.as_bytes()).unwrap();
    
    let encrypted_data = fortress_core::encryption::EncryptedData::new(
        ciphertext.into(),
        algorithm.name().to_string(),
    );
    
    group.bench_function("to_base64", |b| {
        b.iter(|| {
            black_box(encrypted_data.to_base64().unwrap())
        });
    });
    
    let base64 = encrypted_data.to_base64().unwrap();
    group.bench_function("from_base64", |b| {
        b.iter(|| {
            black_box(fortress_core::encryption::EncryptedData::from_base64(black_box(&base64)).unwrap())
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_decrypt,
    bench_key_generation,
    bench_encrypted_data_serialization
);
criterion_main!(benches);
