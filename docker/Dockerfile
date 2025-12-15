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

# Runtime stage: Debian with SoftHSM2
FROM debian:bookworm-slim

# Install SoftHSM2 and runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        softhsm2 \
        opensc \
        ca-certificates \
        jq && \
    rm -rf /var/lib/apt/lists/*

# Copy Rust binary from builder (built from workspace root)
COPY --from=builder /build/target/release/rust-hsm-cli /usr/local/bin/rust-hsm-cli

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
