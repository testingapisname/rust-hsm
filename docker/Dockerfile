# Multi-stage build: compile Rust, then create slim runtime with SoftHSM2

FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Copy Cargo files and build dependencies first (for layer caching)
COPY crates/rust-hsm-cli/Cargo.toml crates/rust-hsm-cli/Cargo.toml
RUN mkdir -p crates/rust-hsm-cli/src && \
    echo "fn main() {}" > crates/rust-hsm-cli/src/main.rs && \
    cd crates/rust-hsm-cli && \
    cargo build --release && \
    rm -rf target/release/deps/rust_hsm_cli*

# Copy source and build actual binary
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
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy Rust binary from builder
COPY --from=builder /build/crates/rust-hsm-cli/target/release/rust-hsm-cli /usr/local/bin/rust-hsm-cli

# Copy SoftHSM configuration and entrypoint
COPY docker/softhsm2.conf /etc/softhsm2.conf
COPY docker/entrypoint.sh /entrypoint.sh
COPY test.sh /app/test.sh
COPY config.example.toml /app/.rust-hsm.toml
RUN chmod +x /entrypoint.sh /app/test.sh

# Set environment variables
ENV SOFTHSM2_CONF=/etc/softhsm2.conf
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

# Create token storage directory
RUN mkdir -p /tokens && chmod 755 /tokens

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
