# DSM Ethereum Bridge Dockerfile
# Implements secure communication between DSM and Ethereum blockchain networks

# -----------------------------------------------------------------------------
# Stage 1: Build environment with dependency caching
# -----------------------------------------------------------------------------
FROM rust:1.76-slim-bullseye AS builder-base

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Create a new empty project for caching dependencies
WORKDIR /usr/src/dsm
RUN cargo new --bin dsm-ethereum-bridge
WORKDIR /usr/src/dsm/dsm-ethereum-bridge

# Copy the manifests
COPY dsm-ethereum-bridge/Cargo.toml .
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
COPY dsm-ethereum-bridge/src /usr/src/dsm/dsm-ethereum-bridge/src
COPY dsm-ethereum-bridge/bin /usr/src/dsm/dsm-ethereum-bridge/bin

# Copy required workspace dependencies
COPY dsm/src/types /usr/src/dsm/dsm/src/types
COPY dsm/src/crypto /usr/src/dsm/dsm/src/crypto

# Build the application
RUN RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C link-arg=-s -C lto=thin -C codegen-units=1" \
    cargo build --release --bin ethereum-bridge --bin bridge-cli

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
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binaries
COPY --from=builder /usr/src/dsm/target/release/ethereum-bridge /usr/local/bin/
COPY --from=builder /usr/src/dsm/target/release/bridge-cli /usr/local/bin/

# Create necessary directories
RUN mkdir -p /var/lib/dsm-bridge/data /var/lib/dsm-bridge/config \
    && chown -R dsm:dsm /var/lib/dsm-bridge

# Default config
COPY dsm-ethereum-bridge/config/default_config.json /var/lib/dsm-bridge/config/
RUN chown dsm:dsm /var/lib/dsm-bridge/config/default_config.json

# Copy smart contracts
COPY dsm-ethereum-bridge/contracts /var/lib/dsm-bridge/contracts
RUN chown -R dsm:dsm /var/lib/dsm-bridge/contracts

# Set working directory
WORKDIR /var/lib/dsm-bridge

# Set environment variables
ENV DSM_BRIDGE_CONFIG_PATH=/var/lib/dsm-bridge/config/default_config.json
ENV DSM_BRIDGE_DATA_DIR=/var/lib/dsm-bridge/data
ENV RUST_BACKTRACE=1

# Apply security hardening
RUN chmod 550 /usr/local/bin/ethereum-bridge /usr/local/bin/bridge-cli && \
    chmod 770 /var/lib/dsm-bridge/data /var/lib/dsm-bridge/config

# Switch to non-root user
USER dsm

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/bridge-cli", "status", "--json"] || exit 1

# Expose bridge API port
EXPOSE 8768

# Default command
ENTRYPOINT ["/usr/local/bin/ethereum-bridge"]
CMD ["--config", "/var/lib/dsm-bridge/config/default_config.json"]

# Labels
LABEL org.opencontainers.image.title="DSM Ethereum Bridge"
LABEL org.opencontainers.image.description="Bridge for interoperability between DSM and Ethereum networks"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="DSM Development Team"
