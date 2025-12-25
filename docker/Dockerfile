# Multi-stage build: compile Rust, then create slim runtime with SoftHSM2

FROM rust:bookworm AS builder

WORKDIR /build

# Install clippy for linting
RUN rustup component add clippy

# Copy workspace configuration
COPY Cargo.toml ./

# Copy Cargo files for all crates (for layer caching)
COPY crates/rust-hsm-core/Cargo.toml crates/rust-hsm-core/Cargo.toml
COPY crates/rust-hsm-cli/Cargo.toml crates/rust-hsm-cli/Cargo.toml
COPY crates/observe-core/Cargo.toml crates/observe-core/Cargo.toml
COPY crates/observe-cryptoki/Cargo.toml crates/observe-cryptoki/Cargo.toml

# Create dummy files with proper module structure to build dependencies
RUN mkdir -p crates/rust-hsm-core/src/keys && \
    echo "pub mod audit; pub mod benchmark; pub mod errors; pub mod info; pub mod keys; pub mod mechanisms; pub mod objects; pub mod random; pub mod slots; pub mod token; pub mod troubleshoot;" > crates/rust-hsm-core/src/lib.rs && \
    for f in audit benchmark errors info mechanisms objects random slots token troubleshoot; do echo "pub fn dummy() {}" > crates/rust-hsm-core/src/$f.rs; done && \
    echo "pub mod asymmetric; pub mod csr; pub mod export; pub mod hash; pub mod hmac; pub mod keypair; pub mod symmetric; pub mod utils; pub mod wrap;" > crates/rust-hsm-core/src/keys/mod.rs && \
    for f in asymmetric csr export hash hmac keypair symmetric utils wrap; do echo "pub fn dummy() {}" > crates/rust-hsm-core/src/keys/$f.rs; done && \
    mkdir -p crates/rust-hsm-cli/src && \
    echo "fn main() {}" > crates/rust-hsm-cli/src/main.rs && \
    mkdir -p crates/observe-core/src && \
    echo "pub mod event; pub mod redaction; pub mod sink;" > crates/observe-core/src/lib.rs && \
    for f in event redaction sink; do echo "pub fn dummy() {}" > crates/observe-core/src/$f.rs; done && \
    mkdir -p crates/observe-cryptoki/src && \
    echo "pub mod config; pub mod pkcs11; pub mod session;" > crates/observe-cryptoki/src/lib.rs && \
    for f in config pkcs11 session; do echo "pub fn dummy() {}" > crates/observe-cryptoki/src/$f.rs; done && \
    cargo build --release && \
    rm -rf target/release/deps/rust_hsm_cli* target/release/deps/rust_hsm_core* target/release/deps/observe_core* target/release/deps/observe_cryptoki*

# Copy real source and build actual binaries
COPY crates/rust-hsm-core/src crates/rust-hsm-core/src
COPY crates/rust-hsm-cli/src crates/rust-hsm-cli/src
COPY crates/rust-hsm-cli/examples crates/rust-hsm-cli/examples
COPY crates/observe-core/src crates/observe-core/src
COPY crates/observe-cryptoki/src crates/observe-cryptoki/src
# Force rebuild by touching source files
RUN find crates/rust-hsm-core/src -name "*.rs" -exec touch {} + && \
    find crates/rust-hsm-cli/src -name "*.rs" -exec touch {} + && \
    find crates/observe-core/src -name "*.rs" -exec touch {} + && \
    find crates/observe-cryptoki/src -name "*.rs" -exec touch {} +
# Test observe-core first, then build CLI and examples
RUN cargo test --release -p observe-core && \
    cargo build --release --bin rust-hsm-cli && \
    cargo build --release -p rust-hsm-cli --example test_observe && \
    cargo build --release -p rust-hsm-cli --example test_wrapper

# Run clippy lints
RUN cargo clippy --all-features --workspace -- -D warnings

# Run tests
RUN cd crates/rust-hsm-cli && cargo test --release

# Kryoptic build stage (DISABLED - uncomment to enable Kryoptic support)
# This stage takes ~2-5 minutes due to OpenSSL compilation
# To enable: uncomment this section and the COPY commands below
#
# FROM rust:1.83-bookworm AS kryoptic-builder
# WORKDIR /kryoptic-build
# RUN apt-get update && \
#     apt-get install -y --no-install-recommends \
#         git pkg-config libsqlite3-dev libclang-dev clang wget build-essential && \
#     rm -rf /var/lib/apt/lists/*
# RUN rustup install nightly && rustup default nightly
# RUN wget https://www.openssl.org/source/openssl-3.3.2.tar.gz && \
#     tar -xzf openssl-3.3.2.tar.gz && \
#     cd openssl-3.3.2 && \
#     ./config --prefix=/usr/local/openssl-3.3 --openssldir=/usr/local/openssl-3.3 && \
#     make -j$(nproc) && \
#     make install && \
#     cd .. && rm -rf openssl-3.3.2 openssl-3.3.2.tar.gz
# ENV PKG_CONFIG_PATH=/usr/local/openssl-3.3/lib64/pkgconfig
# ENV LD_LIBRARY_PATH=/usr/local/openssl-3.3/lib64
# RUN git clone https://github.com/latchset/kryoptic.git . && \
#     CONFDIR=/etc cargo +nightly build --release --features standard

# Runtime stage: Debian with SoftHSM2 (and optionally Kryoptic)
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
COPY --from=builder /build/target/release/examples/test_observe /usr/local/bin/test-observe
COPY --from=builder /build/target/release/examples/test_wrapper /usr/local/bin/test-wrapper

# Kryoptic libraries (DISABLED - uncomment if Kryoptic build stage is enabled)
# COPY --from=kryoptic-builder /usr/local/openssl-3.3/lib64/*.so* /usr/local/openssl-3.3/lib64/
# COPY --from=kryoptic-builder /kryoptic-build/target/release/libkryoptic_pkcs11.so /usr/lib/kryoptic/libkryoptic_pkcs11.so
# ENV LD_LIBRARY_PATH=/usr/local/openssl-3.3/lib64:$LD_LIBRARY_PATH

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

# Create token storage directory
RUN mkdir -p /tokens && chmod 755 /tokens

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
