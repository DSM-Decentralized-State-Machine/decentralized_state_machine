use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dsm::core::state_machine::StateMachine;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

mod bench;

/// Benchmark storage I/O performance for DSM state persistence.
///
/// This benchmark suite evaluates disk I/O performance for various DSM
/// storage operations, including state serialization, chain storage,
/// and recovery from disk. Results inform storage strategy optimizations
/// and hardware requirements for different deployment scenarios.
fn storage_io_benchmark(c: &mut Criterion) {
    // Initialize DSM runtime environment
    dsm::initialize();

    let mut group = c.benchmark_group("Storage I/O");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(10));

    // State sizes to benchmark
    let state_counts = [10, 100, 1000];

    // Create temporary directory for benchmark storage
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().to_owned();

    // Benchmark state serialization performance
    for &count in &state_counts {
        // Generate test chain
        let chain = generate_test_chain(count);

        group.bench_with_input(
            BenchmarkId::new("state_serialization", count),
            &count,
            |b, _| b.iter(|| black_box(serialize_chain_to_memory(&chain))),
        );
    }

    // Benchmark state deserialization performance
    for &count in &state_counts {
        // Generate and serialize test chain
        let chain = generate_test_chain(count);
        let serialized = serialize_chain_to_memory(&chain);

        group.bench_with_input(
            BenchmarkId::new("state_deserialization", count),
            &count,
            |b, _| b.iter(|| black_box(deserialize_chain_from_memory(&serialized))),
        );
    }

    // Benchmark disk write performance
    for &count in &state_counts {
        // Generate test chain
        let chain = generate_test_chain(count);
        let path = get_benchmark_path(&base_path, &format!("write_{}", count));

        group.bench_with_input(BenchmarkId::new("chain_write", count), &count, |b, _| {
            b.iter(|| black_box(write_chain_to_disk(&chain, &path)))
        });
    }

    // Benchmark disk read performance
    for &count in &state_counts {
        // Generate and write test chain
        let chain = generate_test_chain(count);
        let path = get_benchmark_path(&base_path, &format!("read_{}", count));
        write_chain_to_disk(&chain, &path).unwrap();

        group.bench_with_input(BenchmarkId::new("chain_read", count), &count, |b, _| {
            b.iter(|| black_box(read_chain_from_disk(&path)))
        });
    }

    // Benchmark random access performance
    for &count in &state_counts {
        let chain = generate_test_chain(count);
        let path = get_benchmark_path(&base_path, &format!("random_{}", count));
        write_chain_to_disk(&chain, &path).unwrap();

        group.bench_with_input(
            BenchmarkId::new("random_state_access", count),
            &count,
            |b, _| {
                b.iter_batched(
                    || {
                        // Generate random indices to access
                        let mut indices = Vec::new();
                        for _ in 0..10 {
                            indices.push(rand::random::<usize>() % count as usize);
                        }
                        (path.clone(), indices)
                    },
                    |(path, indices)| black_box(random_access_states(&path, &indices)),
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    // Benchmark database storage performance (RocksDB)
    for &count in &state_counts {
        let chain = generate_test_chain(count);
        let path = get_benchmark_path(&base_path, &format!("db_{}", count));

        group.bench_with_input(
            BenchmarkId::new("database_storage", count),
            &count,
            |b, _| b.iter(|| black_box(store_chain_in_database(&chain, &path))),
        );
    }

    // Benchmark database retrieval performance
    for &count in &state_counts {
        let chain = generate_test_chain(count);
        let path = get_benchmark_path(&base_path, &format!("db_read_{}", count));
        store_chain_in_database(&chain, &path).unwrap();

        group.bench_with_input(
            BenchmarkId::new("database_retrieval", count),
            &count,
            |b, _| b.iter(|| black_box(retrieve_chain_from_database(&path))),
        );
    }

    // Benchmark incremental sync performance
    for &count in &state_counts {
        let full_chain = generate_test_chain(count);
        let partial_chain = full_chain[0..(count / 2)].to_vec();
        let path = get_benchmark_path(&base_path, &format!("sync_{}", count));
        write_chain_to_disk(&partial_chain, &path).unwrap();

        group.bench_with_input(
            BenchmarkId::new("incremental_sync", count),
            &count,
            |b, _| b.iter(|| black_box(incremental_chain_sync(&partial_chain, &full_chain, &path))),
        );
    }

    group.finish();
}

/// Generate a test chain of specified length for benchmarking
fn generate_test_chain(length: usize) -> Vec<State> {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;

    let mut states = Vec::with_capacity(length + 1);
    states.push(genesis.clone());

    let mut current_state = genesis;

    for i in 0..length {
        let operation = Operation::Generic {
            operation_type: format!("op_{}", i),
            data: vec![(i % 255) as u8; 32],
            message: String::new(), // Fixed size for predictability
        };

        let mut state_machine = StateMachine::new();
        state_machine.set_state(current_state.clone());
        let new_state = state_machine.execute_transition(operation).unwrap();
        current_state = new_state;

        states.push(current_state.clone());
    }

    states
}

/// Serialize a chain to memory
fn serialize_chain_to_memory(chain: &[State]) -> Vec<u8> {
    bincode::serialize(chain).unwrap()
}

/// Deserialize a chain from memory
fn deserialize_chain_from_memory(data: &[u8]) -> Vec<State> {
    bincode::deserialize(data).unwrap()
}

/// Write a chain to disk
fn write_chain_to_disk(chain: &[State], path: &PathBuf) -> std::io::Result<()> {
    // Create directory if it doesn't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let serialized = serialize_chain_to_memory(chain);
    std::fs::write(path, serialized)
}

/// Read a chain from disk
fn read_chain_from_disk(path: &PathBuf) -> std::io::Result<Vec<State>> {
    let data = std::fs::read(path)?;
    Ok(deserialize_chain_from_memory(&data))
}

/// Access random states from disk storage
fn random_access_states(path: &PathBuf, indices: &[usize]) -> std::io::Result<Vec<State>> {
    let chain = read_chain_from_disk(path)?;
    let mut states = Vec::with_capacity(indices.len());
    for &idx in indices {
        if idx < chain.len() {
            states.push(chain[idx].clone());
        }
    }
    Ok(states)
}

/// Store a chain in a database (RocksDB)
fn store_chain_in_database(chain: &[State], path: &PathBuf) -> Result<(), String> {
    use rocksdb::{Options, DB};

    // Open database
    let mut opts = Options::default();
    opts.create_if_missing(true);

    let db = DB::open(&opts, path).map_err(|e: rocksdb::Error| e.to_string())?;

    // Store each state with state number as key
    for state in chain {
        let key = format!("state_{}", state.state_number);
        let value = bincode::serialize(state).map_err(|e| e.to_string())?;
        db.put(key.as_bytes(), value).map_err(|e| e.to_string())?;
    }

    // Store metadata
    db.put(b"chain_length", chain.len().to_string().as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Retrieve a chain from a database
fn retrieve_chain_from_database(path: &PathBuf) -> Result<Vec<State>, String> {
    use rocksdb::{Options, DB};

    // Open database
    let opts = Options::default();
    // Explicit type annotation for RocksDB errors
    let db: rocksdb::DB = DB::open(&opts, path).map_err(|e| e.to_string())?;

    // Get chain length
    let length_bytes = db
        .get(b"chain_length")
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Chain length not found".to_string())?;

    let length: usize = std::str::from_utf8(&length_bytes)
        .map_err(|e| e.to_string())?
        .parse::<usize>()
        .map_err(|e| e.to_string())?;

    // Retrieve states in order
    let mut chain = Vec::with_capacity(length);

    for i in 0..length {
        let key = format!("state_{}", i);
        let state_bytes = db
            .get(key.as_bytes())
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("State {} not found", i))?;

        let state: State = bincode::deserialize(&state_bytes).map_err(|e| e.to_string())?;

        chain.push(state);
    }

    Ok(chain)
}

/// Perform incremental sync of a chain
fn incremental_chain_sync(
    partial: &[State],
    full: &[State],
    path: &PathBuf,
) -> std::io::Result<()> {
    // Determine new states to append
    let last_idx = partial.len() - 1;
    let new_states = &full[last_idx + 1..];

    // In a real implementation, this would append to an existing file
    // For benchmark purposes, we'll rewrite the whole file
    let mut updated_chain = partial.to_vec();
    updated_chain.extend_from_slice(new_states);

    write_chain_to_disk(&updated_chain, path)
}

/// Get a unique path for a benchmark
fn get_benchmark_path(base: &Path, name: &str) -> PathBuf {
    base.join(format!("benchmark_{}", name))
}

criterion_group! {
    name = storage_benches;
    config = bench::configure_criterion("storage_io")();
    targets = storage_io_benchmark
}
criterion_main!(storage_benches);
