use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};
// use std::time::Duration;

mod bench;

/// Benchmark state serialization and deserialization performance across formats.
///
/// This benchmark systematically quantifies the performance characteristics of various
/// serialization strategies for the DSM's state objects. Serialization efficiency
/// has outsized impact on network bandwidth utilization and storage requirements,
/// particularly in distributed deployment scenarios with frequent state synchronization.
fn serialization_benchmark(c: &mut Criterion) {
    dsm::initialize();

    // Create optimized benchmark group
    let mut group = c.benchmark_group("Serialization Performance");

    // Generate a variety of state objects with different characteristics
    let simple_state = create_genesis_state();
    let complex_state = generate_evolved_state(50); // More complex state with longer history
    let large_state = generate_state_with_large_data(); // State with large data payload

    // Benchmark Bincode serialization (canonical format)
    group.bench_function("bincode_serialize_simple", |b| {
        // Use reference to avoid cloning during benchmark
        let state_ref = &simple_state;
        b.iter(|| black_box(bincode::serialize(black_box(state_ref))))
    });

    group.bench_function("bincode_serialize_complex", |b| {
        let state_ref = &complex_state;
        b.iter(|| black_box(bincode::serialize(black_box(state_ref))))
    });

    group.bench_function("bincode_serialize_large", |b| {
        let state_ref = &large_state;
        b.iter(|| black_box(bincode::serialize(black_box(state_ref))))
    });

    // Benchmark Bincode deserialization
    group.bench_function("bincode_deserialize_simple", |b| {
        // Pre-serialize to avoid measuring serialization time
        let serialized = bincode::serialize(&simple_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(bincode::deserialize::<State>(black_box(serialized_ref))))
    });

    group.bench_function("bincode_deserialize_complex", |b| {
        let serialized = bincode::serialize(&complex_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(bincode::deserialize::<State>(black_box(serialized_ref))))
    });

    group.bench_function("bincode_deserialize_large", |b| {
        let serialized = bincode::serialize(&large_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(bincode::deserialize::<State>(black_box(serialized_ref))))
    });

    // Benchmark Postcard serialization (compact no-std format)
    group.bench_function("postcard_serialize_simple", |b| {
        let state_ref = &simple_state;
        b.iter(|| black_box(postcard::to_allocvec(black_box(state_ref))))
    });

    group.bench_function("postcard_serialize_complex", |b| {
        let state_ref = &complex_state;
        b.iter(|| black_box(postcard::to_allocvec(black_box(state_ref))))
    });

    group.bench_function("postcard_serialize_large", |b| {
        let state_ref = &large_state;
        b.iter(|| black_box(postcard::to_allocvec(black_box(state_ref))))
    });

    // Benchmark Postcard deserialization
    group.bench_function("postcard_deserialize_simple", |b| {
        let serialized = postcard::to_allocvec(&simple_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(postcard::from_bytes::<State>(black_box(serialized_ref))))
    });

    group.bench_function("postcard_deserialize_complex", |b| {
        let serialized = postcard::to_allocvec(&complex_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(postcard::from_bytes::<State>(black_box(serialized_ref))))
    });

    group.bench_function("postcard_deserialize_large", |b| {
        let serialized = postcard::to_allocvec(&large_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(postcard::from_bytes::<State>(black_box(serialized_ref))))
    });

    // Benchmark JSON serialization (human-readable format)
    group.bench_function("json_serialize_simple", |b| {
        let state_ref = &simple_state;
        b.iter(|| black_box(serde_json::to_string(black_box(state_ref))))
    });

    group.bench_function("json_serialize_complex", |b| {
        let state_ref = &complex_state;
        b.iter(|| black_box(serde_json::to_string(black_box(state_ref))))
    });

    group.bench_function("json_deserialize_simple", |b| {
        let serialized = serde_json::to_string(&simple_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(serde_json::from_str::<State>(black_box(serialized_ref))))
    });

    group.bench_function("json_deserialize_complex", |b| {
        let serialized = serde_json::to_string(&complex_state).unwrap();
        let serialized_ref = &serialized;
        b.iter(|| black_box(serde_json::from_str::<State>(black_box(serialized_ref))))
    });

    // Benchmark format size comparison
    group.bench_function("format_size_comparison", |b| {
        b.iter(|| {
            let bincode_size = bincode::serialize(&complex_state).unwrap().len();
            let postcard_size = postcard::to_allocvec(&complex_state).unwrap().len();
            let json_size = serde_json::to_string(&complex_state).unwrap().len();
            black_box((bincode_size, postcard_size, json_size))
        })
    });

    group.finish();
}

/// Benchmark serialization compression ratio across different state complexity levels
fn compression_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Serialization Compression");

    // Generate states of different evolution depths
    let states = (0..5)
        .map(|i| generate_evolved_state(i * 10))
        .collect::<Vec<_>>();

    for (i, state) in states.iter().enumerate() {
        let complexity = i * 10;

        group.bench_with_input(
            BenchmarkId::new("compression_ratio", complexity),
            &complexity,
            |b, _| {
                b.iter(|| {
                    // Calculate uncompressed size
                    let bincode_raw = bincode::serialize(state).unwrap();
                    let raw_size = bincode_raw.len();

                    // Create compression buffer with sufficient capacity
                    let compressed = Vec::with_capacity(raw_size);

                    // Perform compression
                    let mut encoder =
                        flate2::write::ZlibEncoder::new(compressed, flate2::Compression::default());

                    // Write and flush
                    std::io::copy(&mut bincode_raw.as_slice(), &mut encoder).unwrap();
                    let compressed = encoder.finish().unwrap();

                    // Calculate compression ratio
                    let compression_ratio = raw_size as f64 / compressed.len() as f64;
                    black_box(compression_ratio)
                })
            },
        );
    }

    group.finish();
}

/// Creates a genesis state for serialization benchmarking
fn create_genesis_state() -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info);
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;
    genesis
}

/// Generate an evolved state with a specific number of transitions
fn generate_evolved_state(transitions: u64) -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;

    let mut current_state = genesis;

    for i in 0..transitions {
        let operation = Operation::Generic {
            operation_type: format!("op_{}", i),
            data: vec![i as u8; 4],
            message: format!("Operation {}", i),
        };

        let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
            &current_state.entropy,
            &bincode::serialize(&operation).unwrap(),
            current_state.state_number + 1,
        )
        .as_bytes()
        .to_vec();

        let indices = State::calculate_sparse_indices(i + 1).unwrap();
        let sparse_index = SparseIndex::new(indices);

        let state_params = StateParams::new(i + 1, next_entropy, operation, device_info.clone())
            .with_encapsulated_entropy(Vec::new())
            .with_prev_state_hash(current_state.hash().unwrap())
            .with_sparse_index(sparse_index);

        let mut next_state = State::new(state_params);
        let computed_hash = next_state.compute_hash().unwrap();
        next_state.hash = computed_hash;

        current_state = next_state;
    }

    current_state
}

/// Generate a state with large embedded data for benchmarking large payload serialization
fn generate_state_with_large_data() -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());

    // Create a large data payload to stress serialization
    let large_data = vec![0xAA; 1024 * 10]; // 10KB payload

    let operation = Operation::Generic {
        operation_type: "large_data_op".to_string(),
        data: large_data,
        message: "Large data operation".to_string(),
    };

    let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
        &genesis.entropy,
        &bincode::serialize(&operation).unwrap(),
        genesis.state_number + 1,
    )
    .as_bytes()
    .to_vec();

    let indices = State::calculate_sparse_indices(1).unwrap();
    let sparse_index = SparseIndex::new(indices);

    let mut large_state = State::new(
        StateParams::new(1, next_entropy, operation, device_info)
            .with_encapsulated_entropy(Vec::new())
            .with_prev_state_hash(genesis.hash().unwrap())
            .with_sparse_index(sparse_index),
    );
    let computed_hash = large_state.compute_hash().unwrap();
    large_state.hash = computed_hash;
    large_state
}

criterion_group!(benches, serialization_benchmark, compression_benchmark);
criterion_main!(benches);
