# Multi-stage build: compile Rust with cargo-chef, then create slim runtime with SoftHSM2

FROM rust:1.83-bookworm AS chef
RUN cargo install cargo-chef --version 0.1.68
WORKDIR /build

# Analyze dependencies
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies (cached layer)
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
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
