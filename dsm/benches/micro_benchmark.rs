use blake3;
use criterion::{criterion_group, criterion_main, Criterion};

// Minimal benchmark that measures just the Blake3 hash function
fn hash_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Baseline Cryptography");

    group.bench_function("blake3_1kb", |b| {
        let data = vec![0u8; 1024]; // 1KB of data
        b.iter(|| {
            let hash = blake3::hash(&data);
            hash
        });
    });

    group.finish();
}

criterion_group!(hash_benchmarks, hash_benchmark);
criterion_main!(hash_benchmarks);
