# Multi-stage build: compile Rust, then create slim runtime with SoftHSM2

FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Copy workspace configuration first
COPY Cargo.toml ./

# Copy Cargo files for both crates (for layer caching)
COPY crates/rust-hsm-core/Cargo.toml crates/rust-hsm-core/Cargo.toml
COPY crates/rust-hsm-cli/Cargo.toml crates/rust-hsm-cli/Cargo.toml

# Create dummy files to build dependencies
RUN mkdir -p crates/rust-hsm-core/src && \
    echo "pub mod audit; pub mod benchmark; pub mod errors; pub mod info; pub mod keys; pub mod mechanisms; pub mod objects; pub mod random; pub mod slots; pub mod token; pub mod troubleshoot;" > crates/rust-hsm-core/src/lib.rs && \
    mkdir -p crates/rust-hsm-core/src/{keys,pkcs11} && \
    touch crates/rust-hsm-core/src/{audit.rs,benchmark.rs,errors.rs,info.rs,mechanisms.rs,objects.rs,random.rs,slots.rs,token.rs,troubleshoot.rs} && \
    touch crates/rust-hsm-core/src/keys/{mod.rs,asymmetric.rs,csr.rs,export.rs,hash.rs,hmac.rs,keypair.rs,symmetric.rs,utils.rs,wrap.rs} && \
    mkdir -p crates/rust-hsm-cli/src && \
    echo "fn main() {}" > crates/rust-hsm-cli/src/main.rs && \
    cargo build --release && \
    rm -rf target/release/deps/rust_hsm_cli* target/release/deps/rust_hsm_core*

# Copy source and build actual binaries
COPY crates/rust-hsm-core/src crates/rust-hsm-core/src
COPY crates/rust-hsm-cli/src crates/rust-hsm-cli/src
RUN cd crates/rust-hsm-cli && cargo build --release

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

# Copy Rust binary from builder
COPY --from=builder /build/crates/rust-hsm-cli/target/release/rust-hsm-cli /usr/local/bin/rust-hsm-cli

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
