FROM gitpod/workspace-full

# Install additional tools
RUN cargo install cargo-audit cargo-deny cargo-criterion cargo-llvm-cov

# Install RocksDB dependencies
RUN sudo apt-get update && \
    sudo apt-get install -y \
    libclang-dev \
    libssl-dev \
    librocksdb-dev \
    pkg-config \
    && sudo rm -rf /var/lib/apt/lists/*

# Set up environment variables
ENV RUST_BACKTRACE=1
ENV CARGO_TERM_COLOR=always
