use blake3::hash;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

mod bench;

pub fn hash_benchmark(c: &mut Criterion) {
    // Allocate data outside of benchmarking loop to avoid heap allocation influence
    let data_1kb = [0u8; 1024];
    let empty_data: [u8; 0] = [];

    // Perform cache warming to stabilize CPU conditions
    for _ in 0..1000 {
        hash(&data_1kb);
        hash(&empty_data);
    }

    let mut group = c.benchmark_group("Blake3 Hashing");
    group.sample_size(150);

    // Use references to avoid pointer operations during measurement
    let data_1kb_ref = &data_1kb;
    let empty_data_ref = &empty_data;

    group.bench_function("hash_1kb", |b| {
        b.iter_with_large_drop(|| hash(black_box(data_1kb_ref)))
    });

    group.bench_function("hash_empty", |b| {
        b.iter_with_large_drop(|| hash(black_box(empty_data_ref)))
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = hash_benchmark
);
criterion_main!(benches);
