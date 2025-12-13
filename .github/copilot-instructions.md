# Copilot Instructions for rust-hsm

## Project Overview

This is a Rust PKCS#11 tool for interfacing with SoftHSM2 in a single Docker container. The container includes both SoftHSM2 and the Rust CLI, with the CLI loading the PKCS#11 module directly via `cryptoki`.

## Architecture

- **Single container**: Contains both SoftHSM2 and Rust CLI
- **Direct PKCS#11 access**: Rust CLI loads `libsofthsm2.so` locally using `cryptoki` crate
- **Token storage**: Persistent via Docker volume mounted at `/tokens`

## Tech Stack

- **Rust crate**: `cryptoki` for PKCS#11 bindings (not native bindings)
- **CLI framework**: `clap` with subcommands
- **Logging**: `tracing` + `tracing-subscriber`
- **Build**: Multi-stage Dockerfile (builder + slim runtime)

## File Structure (Target)

```
docker/
  Dockerfile             # Single container with SoftHSM2 + Rust CLI
  softhsm2.conf          # SoftHSM configuration
  entrypoint.sh          # Container startup script
compose.yaml             # Optional: for easy container management
crates/rust-hsm-cli/     # Rust CLI crate
  src/pkcs11/            # PKCS#11 wrapper modules (session, objects, keys, errors)
```

## Key Environment Variables

- `PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so` (path to PKCS#11 module)
- `SOFTHSM2_CONF=/etc/softhsm2.conf` (SoftHSM configuration file)
- `TOKEN_LABEL`, `USER_PIN`, `SO_PIN` (never hardcode PINs in code)

## Development Workflow

1. **Build and run**: `docker compose up -d` or `docker run -v tokens:/tokens rust-hsm`
2. **Run CLI commands**: `docker compose exec app rust-hsm-cli <command>` or exec into container
3. **Wipe token state**: `docker volume rm rust-hsm_tokens`

## Commands (CLI Interface)

```bash
rust-hsm-cli info                         # Module/token info
rust-hsm-cli list-slots                   # Enumerate slots and tokens
rust-hsm-cli init-token --label "..." --so-pin "..." --user-pin "..."
rust-hsm-cli list-objects --label "..." --user-pin "..."
rust-hsm-cli gen-keypair --label "..." --key-label "..." --type rsa --bits 2048
rust-hsm-cli sign --key-label "..." --in data.bin --out sig.bin
rust-hsm-cli verify --pubkey pub.pem --in data.bin --sig sig.bin
```

## Implementation Guidelines

### PKCS#11 Session Lifecycle
Always follow: init → open session → login → operation → logout → close

### Security Rules
- Never hardcode PINs in code (read from env/args)
- Never log PIN values
- Always print PKCS#11 return codes on error
- Consider `--pin-stdin` for safer automation

### Incremental Development
Implement in this order:
1. **Read-only commands first**: `info`, `list-slots`, `list-objects`
2. **Then mutation commands**: `init-token`, `gen-keypair`, `sign`, `verify`

### Error Handling
- Wrap `cryptoki` errors with context
- Use `src/pkcs11/errors.rs` for custom error types
- Print clear error messages with PKCS#11 return codes

## Testing Strategy

Run integration tests in container:
```bash
docker compose up -d
docker compose exec app rust-hsm-cli list-slots
# Test full workflow: init → keygen → sign → verify
```

Token storage persists via volume—test repeatability by wiping and recreating:
```bash
docker volume rm rust-hsm_tokens
```
