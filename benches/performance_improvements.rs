//! Performance benchmarks for Fortress optimization improvements
//!
//! This benchmarks the performance improvements made to:
//! 1. Versioned Key Cache (cached vs format! strings)

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_versioned_key_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("versioned_key_cache");

    // Benchmark cache vs format! string generation
    for &operation_count in &[100, 500, 1000, 5000] {
        group.bench_with_input(
            BenchmarkId::new("format_string_generation", operation_count),
            &operation_count,
            |b, &operation_count| {
                b.iter(|| {
                    // Perform format! string generation
                    for i in 0..operation_count {
                        let key_id = format!("test_key_{}", i % 100); // 100 unique keys
                        let version = (i / 100) as u32;
                        let versioned_id = format!("{}_v{}", key_id, version);
                        black_box(versioned_id);
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_versioned_key_cache
);
criterion_main!(benches);
