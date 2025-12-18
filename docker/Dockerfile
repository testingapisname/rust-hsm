# Multi-stage build: compile Rust, then create slim runtime with SoftHSM2

FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Copy workspace configuration
COPY Cargo.toml ./

# Copy Cargo files for both crates (for layer caching)
COPY crates/rust-hsm-core/Cargo.toml crates/rust-hsm-core/Cargo.toml
COPY crates/rust-hsm-cli/Cargo.toml crates/rust-hsm-cli/Cargo.toml

# Create dummy files with proper module structure to build dependencies
RUN mkdir -p crates/rust-hsm-core/src/keys && \
    echo "pub mod audit; pub mod benchmark; pub mod errors; pub mod info; pub mod keys; pub mod mechanisms; pub mod objects; pub mod random; pub mod slots; pub mod token; pub mod troubleshoot;" > crates/rust-hsm-core/src/lib.rs && \
    for f in audit benchmark errors info mechanisms objects random slots token troubleshoot; do echo "pub fn dummy() {}" > crates/rust-hsm-core/src/$f.rs; done && \
    echo "pub mod asymmetric; pub mod csr; pub mod export; pub mod hash; pub mod hmac; pub mod keypair; pub mod symmetric; pub mod utils; pub mod wrap;" > crates/rust-hsm-core/src/keys/mod.rs && \
    for f in asymmetric csr export hash hmac keypair symmetric utils wrap; do echo "pub fn dummy() {}" > crates/rust-hsm-core/src/keys/$f.rs; done && \
    mkdir -p crates/rust-hsm-cli/src && \
    echo "fn main() {}" > crates/rust-hsm-cli/src/main.rs && \
    cargo build --release && \
    rm -rf target/release/deps/rust_hsm_cli* target/release/deps/rust_hsm_core*

# Copy real source and build actual binaries
COPY crates/rust-hsm-core/src crates/rust-hsm-core/src
COPY crates/rust-hsm-cli/src crates/rust-hsm-cli/src
# Force rebuild by touching source files
RUN find crates/rust-hsm-core/src -name "*.rs" -exec touch {} + && \
    find crates/rust-hsm-cli/src -name "*.rs" -exec touch {} +
RUN cargo build --release --bin rust-hsm-cli

# Run tests
RUN cd crates/rust-hsm-cli && cargo test --release

# Kryoptic build stage (requires nightly for edition 2024 and OpenSSL >= 3.2)
# Using Ubuntu 24.04 which has OpenSSL 3.0.13, so we install from PPA or build static
FROM rust:1.83-bookworm AS kryoptic-builder

WORKDIR /kryoptic-build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        pkg-config \
        libsqlite3-dev \
        libclang-dev \
        clang \
        wget \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

# Install Rust nightly
RUN rustup install nightly && rustup default nightly

# Build OpenSSL 3.3 from source for Kryoptic
RUN wget https://www.openssl.org/source/openssl-3.3.2.tar.gz && \
    tar -xzf openssl-3.3.2.tar.gz && \
    cd openssl-3.3.2 && \
    ./config --prefix=/usr/local/openssl-3.3 --openssldir=/usr/local/openssl-3.3 && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf openssl-3.3.2 openssl-3.3.2.tar.gz

# Clone and build Kryoptic with custom OpenSSL
ENV PKG_CONFIG_PATH=/usr/local/openssl-3.3/lib64/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/openssl-3.3/lib64
RUN git clone https://github.com/latchset/kryoptic.git . && \
    CONFDIR=/etc cargo +nightly build --release --features standard

# Runtime stage: Debian with SoftHSM2 and Kryoptic
FROM debian:bookworm-slim

# Install SoftHSM2, Kryoptic runtime dependencies, and utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        softhsm2 \
        opensc \
        ca-certificates \
        jq \
        libssl3 \
        libsqlite3-0 && \
    rm -rf /var/lib/apt/lists/*

# Copy Rust binary from builder (built from workspace root)
COPY --from=builder /build/target/release/rust-hsm-cli /usr/local/bin/rust-hsm-cli

# Copy OpenSSL 3.3 libraries from kryoptic-builder (required by Kryoptic)
COPY --from=kryoptic-builder /usr/local/openssl-3.3/lib64/*.so* /usr/local/openssl-3.3/lib64/

# Copy Kryoptic PKCS#11 library from kryoptic-builder
COPY --from=kryoptic-builder /kryoptic-build/target/release/libkryoptic_pkcs11.so /usr/lib/kryoptic/libkryoptic_pkcs11.so

# Set library path to include OpenSSL 3.3 for Kryoptic
ENV LD_LIBRARY_PATH=/usr/local/openssl-3.3/lib64:$LD_LIBRARY_PATH

# Copy SoftHSM configuration and entrypoint
COPY docker/softhsm2.conf /etc/softhsm2.conf
COPY docker/entrypoint.sh /entrypoint.sh
COPY test.sh /app/test.sh
COPY cleanup-test-tokens.sh /app/cleanup-test-tokens.sh
COPY config.example.toml /app/.rust-hsm.toml
RUN chmod +x /entrypoint.sh /app/test.sh /app/cleanup-test-tokens.sh

# Set environment variables
ENV SOFTHSM2_CONF=/etc/softhsm2.conf
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

# Create token storage directories for both HSMs
RUN mkdir -p /tokens /kryoptic-tokens && chmod 755 /tokens /kryoptic-tokens

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
