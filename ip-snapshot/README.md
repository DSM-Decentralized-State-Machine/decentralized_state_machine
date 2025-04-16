# IP-Snapshot: Cryptographically Verifiable IP Address Collection System

A cryptographically secure infrastructure for collecting and validating global IP address distributions with post-quantum secure verification primitives. Built for the Decentralized State Machine (DSM) ecosystem.

## Architecture

This system implements a secure, transparent IP collection mechanism with strong cryptographic guarantees:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Collection     │────▶│  Verification   │────▶│  Commitment     │
│  Endpoints      │     │  Pipeline       │     │  Generation     │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Geolocation    │     │  Fraud          │     │  Token          │
│  Resolution     │     │  Detection      │     │  Distribution   │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │                 │
                                               │  DSM Protocol   │
                                               │  Integration    │
                                               │                 │
                                               └─────────────────┘
```

## Core Components

1. **Collection System**: Transparent HTTP endpoint-based IP collection with comprehensive proxy resolution.
2. **Cryptographic Verification**: BLAKE3 and SHA3-256 based integrity verification with deterministic canonicalization.
3. **Fraud Detection**: Advanced proxy/VPN detection using network fingerprinting techniques.
4. **Geolocation Engine**: MaxMind GeoIP integration with cached lookups for high performance.
5. **Snapshot Export**: Multiple formats with cryptographic proofs (JSON, CSV, BLAKE3).
6. **Token Distribution**: Deterministic allocation system derived from cryptographic commitments.

## Security Features

- Post-quantum secure cryptographic primitives (BLAKE3, SHA3-256)
- Merkle tree commitments for efficient verification
- Deterministic canonicalization for reproducible hashing
- Double-hashing for cryptographic defense-in-depth
- Full audit trail with tamper-evident logs
- Rate limiting and abuse prevention
- Cross-validation of geographic data

## DSM Integration

This component is designed for integration with the DSM protocol, providing:

1. Cryptographic commitments suitable for on-chain anchoring
2. Deterministic token distribution from snapshot data
3. Verifiable random functions for fair allocation
4. Tamper-resistant state transitions

## Usage

### Collection Server

```bash
cargo run -- collect --listen 0.0.0.0:3000 --geoip ./GeoLite2-City.mmdb
```

### Create Snapshot

```bash
cargo run -- admin/snapshot
```

### Export Data

```bash
cargo run -- export --format json --output snapshot.json
```

### Verify Integrity

```bash
cargo run -- verify --snapshot snapshot.json
```

## Build Requirements

- Rust 1.70+
- MaxMind GeoIP2 database
- 64-bit architecture

## Performance Characteristics

- Collection throughput: ~10,000 IPs/sec
- Verification speed: ~50,000 IPs/sec
- Memory footprint: ~250MB for 1 million IPs
- Storage requirements: ~500MB for 1 million IPs with full metadata
