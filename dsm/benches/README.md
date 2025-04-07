# DSM Benchmarking Suite

This directory contains comprehensive benchmarks for the Decentralized State Machine (DSM) system, providing performance metrics across various components and operational scenarios.

## Overview

The benchmarks are organized by functional area and use the Criterion.rs framework for statistical rigor and reproducible measurements. Each benchmark is designed to evaluate specific aspects of the DSM system under controlled conditions.

## Benchmark Categories

### Core State Machine
- **state_transitions**: Measures core state transition performance
- **state_transition_benchmark**: Detailed analysis of state transition operations including creation, application, and verification
- **concurrent_verification**: Tests parallel verification scaling and throughput

### Cryptography
- **cryptography**: Basic crypto primitive benchmarks
- **crypto_benchmark**: Extended cryptographic operation metrics
- **quantum_crypto_benchmark**: Performance characteristics of post-quantum cryptography including Kyber KEM and SPHINCS+

### Networking
- **network_operations**: General network operation performance
- **network_transport_benchmark**: Detailed transport protocol benchmarks for TCP, UDP, and other protocols

### Recovery and Resilience
- **recovery_mechanisms_benchmark**: Performance metrics for various recovery scenarios including corrupted state recovery, entropy recovery, and chain reconciliation
- **recovery_performance**: Basic recovery operation benchmarks

### Resource Utilization
- **memory_profile_benchmark**: Memory usage patterns during sustained operation, including growth, caching effectiveness, and parallel processing impact
- **storage_io_benchmark**: Disk I/O performance for state persistence, including serialization, database operations, and incremental syncing

### Token System
- **token_operations**: Performance of token-related operations

### Misc
- **serialization_metrics**: Data structure serialization performance
- **timing_analysis**: Fine-grained timing analysis for critical path operations
- **pokemon_simulation**: Simulated load testing with game-like state transitions

## Running Benchmarks

To run all benchmarks:
```bash
cargo bench
```

To run a specific benchmark:
```bash
cargo bench --bench <benchmark_name>
```

For example:
```bash
cargo bench --bench quantum_crypto_benchmark
```

To run a specific benchmark function within a benchmark:
```bash
cargo bench --bench <benchmark_name> -- <function_pattern>
```

For example:
```bash
cargo bench --bench network_transport_benchmark -- throughput
```

## Benchmark Configuration

The `bench.rs` file provides common configuration for all benchmarks, including:
- Consistent sampling parameters
- Outlier filtering
- CPU frequency stabilization
- Warm-up periods

## Visualization

Benchmark results can be visualized using Criterion's built-in HTML report generation:
```bash
cargo bench
open target/criterion/report/index.html
```

## Interpreting Results

When analyzing benchmark results, pay special attention to:
1. **Throughput metrics**: Operations per second for core functions
2. **Latency distributions**: Especially tail latencies (95th, 99th percentiles)
3. **Resource scaling**: How performance changes with input size or parallelism
4. **Memory consumption**: Growth patterns during sustained operation

## Adding New Benchmarks

When adding new benchmarks:
1. Create a new file in the `benches` directory
2. Use the `bench::configure_criterion()` function for consistent configuration
3. Register the benchmark using `criterion_group!` and `criterion_main!`
4. Add an entry to `Cargo.toml` in the `[[bench]]` section
5. Document the benchmark in this README
