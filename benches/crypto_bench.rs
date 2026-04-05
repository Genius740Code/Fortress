use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fortress_core::encryption::{Aegis256, EncryptionAlgorithm};
use fortress_core::key::{KeyManager, KeyMetadata};

fn bench_aegis256(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    let key = KeyManager::new().generate_key(&Aegis256::new()).unwrap();
    
    c.bench_function("aegis256_encrypt_1kb", |b| {
        b.iter(|| {
            let cipher = Aegis256::new();
            cipher.encrypt(black_box(&data), black_box(&key))
        })
    });
}

fn bench_aegis256_decrypt(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    let key = KeyManager::new().generate_key(&Aegis256::new()).unwrap();
    let cipher = Aegis256::new();
    let encrypted = cipher.encrypt(&data, &key).unwrap();
    
    c.bench_function("aegis256_decrypt_1kb", |b| {
        b.iter(|| {
            let cipher = Aegis256::new();
            cipher.decrypt(black_box(&encrypted), black_box(&key))
        })
    });
}

fn bench_key_generation(c: &mut Criterion) {
    let key_manager = KeyManager::new();
    let algorithm = Aegis256::new();
    
    c.bench_function("key_generation_aegis256", |b| {
        b.iter(|| {
            key_manager.generate_key(black_box(&algorithm))
        })
    });
}

criterion_group!(benches, bench_aegis256, bench_aegis256_decrypt, bench_key_generation);
criterion_main!(benches);
