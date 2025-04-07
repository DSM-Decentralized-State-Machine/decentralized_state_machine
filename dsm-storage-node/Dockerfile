# DSM Storage Node Dockerfile
# Optimized for distributed policy storage with quantum resistance

# -----------------------------------------------------------------------------
# Stage 1: Build environment with dependency caching
# -----------------------------------------------------------------------------
FROM rust:1.76-slim-bullseye AS builder-base

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a new empty project for caching dependencies
WORKDIR /usr/src/dsm
RUN cargo new --bin dsm-storage-node
WORKDIR /usr/src/dsm/dsm-storage-node

# Copy the manifests
COPY dsm-storage-node/Cargo.toml .
COPY Cargo.toml /usr/src/dsm/
COPY cargo.toml /usr/src/dsm/
COPY Cargo.lock /usr/src/dsm/

# Build dependencies
RUN mkdir -p src && \
    echo "fn main() {println!(\"dependency placeholder\");}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# -----------------------------------------------------------------------------
# Stage 2: Build the application
# -----------------------------------------------------------------------------
FROM builder-base AS builder

# Copy the source code
COPY dsm-storage-node/src /usr/src/dsm/dsm-storage-node/src
COPY dsm-storage-node/bin /usr/src/dsm/dsm-storage-node/bin

# Copy required workspace dependencies
COPY dsm/src/types /usr/src/dsm/dsm/src/types
COPY dsm/src/crypto /usr/src/dsm/dsm/src/crypto
COPY dsm/src/policy /usr/src/dsm/dsm/src/policy

# Build the application
RUN RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C link-arg=-s -C lto=thin -C codegen-units=1" \
    cargo build --release --bin storage-node --bin storage-cli

# -----------------------------------------------------------------------------
# Stage 3: Create minimal runtime image
# -----------------------------------------------------------------------------
FROM debian:bullseye-slim AS runtime

# Add non-root user
RUN groupadd -r dsm && useradd -r -g dsm dsm

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    librocksdb6.11 \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binaries
COPY --from=builder /usr/src/dsm/target/release/storage-node /usr/local/bin/
COPY --from=builder /usr/src/dsm/target/release/storage-cli /usr/local/bin/

# Create necessary directories
RUN mkdir -p /var/lib/dsm-storage/data /var/lib/dsm-storage/config \
    && chown -R dsm:dsm /var/lib/dsm-storage

# Default config
COPY dsm-storage-node/config/default_config.json /var/lib/dsm-storage/config/
RUN chown dsm:dsm /var/lib/dsm-storage/config/default_config.json

# Set working directory
WORKDIR /var/lib/dsm-storage

# Set environment variables
ENV DSM_STORAGE_CONFIG_PATH=/var/lib/dsm-storage/config/default_config.json
ENV DSM_STORAGE_DATA_DIR=/var/lib/dsm-storage/data
ENV RUST_BACKTRACE=1

# Apply security hardening
RUN chmod 550 /usr/local/bin/storage-node /usr/local/bin/storage-cli && \
    chmod 770 /var/lib/dsm-storage/data /var/lib/dsm-storage/config

# Switch to non-root user
USER dsm

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/storage-cli", "status", "--json"] || exit 1

# Expose port for P2P communication
EXPOSE 8765

# Default command
ENTRYPOINT ["/usr/local/bin/storage-node"]
CMD ["--config", "/var/lib/dsm-storage/config/default_config.json"]

# Labels
LABEL org.opencontainers.image.title="DSM Storage Node"
LABEL org.opencontainers.image.description="Decentralized storage node for DSM policy and state storage"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="DSM Development Team"
