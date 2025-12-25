# Copilot Instructions for rust-hsm (PKCS#11 CLI + Observability)

## Purpose
You are working in **rust-hsm**, a Rust PKCS#11 CLI that supports both **SoftHSM2** and **Kryoptic** for learning, repeatable workflows, and troubleshooting. The project is **NOT for production security**.

**New direction (Dec 2025+)**: add **PKCS#11 observability** in a safe way:
- **Option C (in-process Rust wrapper)**: tracing around `cryptoki` usage inside the CLI.
- **Option A (drop-in proxy PKCS#11 module)**: a `cdylib` `.so` that forwards to a real vendor module and emits structured logs.
Both should share a single redaction-first logging core.

---

## Non-Negotiables (Security + Safety)
- **Never log PINs.**
- **Never log raw buffers** passed into crypto operations (data-to-sign, plaintext, ciphertext, derived secrets).
- **Never log sensitive attributes** (e.g., `CKA_VALUE`, private key components, secrets).
- **Default behavior must be safe** and suitable for open-source.
- Any "unsafe / verbose" mode must be explicitly opt-in and clearly documented.

Redaction rule of thumb:
- OK to log: attribute **names**, small enums (class/key type/mechanism), booleans, sizes/lengths, and hashed identifiers.
- NOT OK: raw attribute values, raw byte buffers, private key material, symmetric key material.

If unsure, **redact**.

## Current Architecture (Existing)
**Single-container design**: Both HSM providers and Rust CLI run in one container. The CLI loads the PKCS#11 module directly via `cryptoki` (no external pkcs11-tool calls).

**Supported HSM Providers**:
- **SoftHSM2** (default): `/usr/lib/softhsm/libsofthsm2.so` - token storage at `/tokens`
- **Kryoptic**: `/usr/lib/kryoptic/libkryoptic_pkcs11.so` - SQLite storage at `/kryoptic-tokens`

**Switching providers**: Use config file (`pkcs11_module` setting) or `PKCS11_MODULE` env var. See [SWITCHING_HSM_PROVIDERS.md](../docs/SWITCHING_HSM_PROVIDERS.md).

---

## Tech Stack
- **PKCS#11 bindings**: `cryptoki` v0.10
- **CLI**: `clap` v4.5 derive macros + subcommands
- **Logging**: `tracing` + `tracing-subscriber` (env-filter)
- **Container**: Multi-stage Dockerfile (Rust builder → Debian slim runtime)

---

## Codebase Structure (Existing)
```
crates/rust-hsm-cli/src/
  main.rs
  cli.rs
  config.rs
  pkcs11/
    mod.rs
    errors.rs
    info.rs
    slots.rs
    token.rs
    objects.rs
    audit.rs
    troubleshoot.rs
    keys/
      mod.rs
      utils.rs
      keypair.rs
      asymmetric.rs
      symmetric.rs
      export.rs
      wrap.rs
      csr.rs
      inspect.rs
      hash.rs
      hmac.rs
      benchmark.rs
```

---

## Observability: Implementation Strategy (NEW)

### Goal
Provide **structured, correlation-friendly traces** of PKCS#11 behavior to answer:
- What PKCS#11 call happened?
- What mechanism / object class / key type was involved?
- What failed (return code + context) and how long did it take?
- What state transitions occurred (init/login/find/sign/close)?

### Deliverables
We want both:
1. **Option C**: tracing wrappers in Rust around `cryptoki` (used by CLI and tests).
2. **Option A**: a **proxy PKCS#11 module** (`cdylib`) that forwards calls to a real module and logs events.

### Project Layout (Recommended)
Prefer a workspace layout so code is shared and not duplicated:
```
crates/
  observe-core/        # shared schema + redaction + sinks + hints (NO PKCS#11 FFI)
  observe-cryptoki/    # Option C: wrapper helpers around cryptoki (used by rust-hsm-cli)
  observe-proxy/       # Option A: cdylib PKCS#11 proxy module (C ABI via Rust FFI)
  rust-hsm-cli/        # existing CLI depends on observe-cryptoki/observe-core
```

If the repo is not yet a workspace, keep changes minimal and introduce crates gradually.

---

## observe-core Requirements (Shared Logging Core)
Implement a small, stable core API used by both Option A and Option C.

### Event Schema (JSONL-friendly)
Events must be serializable to JSON lines with stable keys:
- `ts` (RFC3339 or unix ms)
- `pid`, `tid`
- `module` (target module path or name; proxy should record both proxy+target)
- `func` (PKCS#11 function name, e.g., `C_SignInit`)
- `rv` numeric + `rv_name` string
- `dur_ms`
- `slot_id` (if known)
- `session` handle (if known)
- `mech` (if known)
- `template_summary` (if present)
- `op_id` correlation ID (optional but recommended)
- `hint` short human-friendly diagnosis (optional)

### Template Summary Rules
Summarize templates by listing attribute names and safe values:
- OK: `CKA_CLASS`, `CKA_KEY_TYPE`, booleans like `CKA_SIGN`, `CKA_DECRYPT`, lengths like `CKA_MODULUS_BITS`
- For `CKA_LABEL` / `CKA_ID`: log `len` + `sha256` (or `blake3`) hash, not plaintext.
- Never include raw bytes.

### Error Hints
Add small, context-aware hints:
- `CKR_MECHANISM_INVALID` / `CKR_MECHANISM_PARAM_INVALID`
- `CKR_KEY_TYPE_INCONSISTENT`
- `CKR_USER_NOT_LOGGED_IN`
- `CKR_ATTRIBUTE_SENSITIVE` / `CKR_ATTRIBUTE_TYPE_INVALID`
Keep hints concise and non-speculative.

### Sinks
- JSON Lines file sink
- stderr sink
(OTel/OTLP can be future work.)

---

## Option C (observe-cryptoki): How to Integrate
- Wrap common actions (init, open session, login, find objects, sign, encrypt/decrypt).
- Emit an event per "call boundary" with duration and rv.
- Correlate init/update/final sequences using an `op_id` attached to:
  - `FindObjectsInit/FindObjects/FindObjectsFinal`
  - `SignInit/Sign/SignFinal`
  - `EncryptInit/Encrypt/EncryptFinal`
  - `DecryptInit/Decrypt/DecryptFinal`

Keep wrappers ergonomic; avoid forcing major refactors in CLI.

---

## Option A (observe-proxy): Proxy Module Rules
- Build a `cdylib` that exports PKCS#11 entrypoints (at minimum `C_GetFunctionList`).
- It should `dlopen()` the target PKCS#11 module specified by env var:
  - `PKCS11_OBSERVE_TARGET=/path/to/vendor.so`
- Obtain the real `CK_FUNCTION_LIST`, then return a wrapped list where wrappers:
  - Start timer
  - Summarize safe parameters (mechanism enums, template attribute names, lengths)
  - Call the real function
  - Log rv + duration + context

### Context Tracking (Minimal)
Maintain small maps:
- `session_handle -> slot_id`
- `session_handle -> active op_id` (per operation family)
Keep it thread-safe (Mutex/RwLock) but simple.

### Proxy Must Not Change Behavior
- Forward return values exactly.
- Do not alter buffers.
- Do not "fix" errors.
- Do not reorder calls.
- Avoid panics; if internal logging fails, continue forwarding.

---

## PKCS#11 Patterns (Critical)
Always follow proper lifecycle:
- `C_Initialize` → operations → `C_Finalize`
- open session → optional login → operations → logout → close session
Skipping finalize can cause resource leaks.

**Logging convention (existing)**:
- `debug!("→ Calling C_X")` before calling underlying PKCS#11 operation.
Keep this pattern; observability layers should complement, not replace.

---

## CLI Conventions
- Use `clap` derive macros; keep subcommands in `cli.rs`, dispatch in `main.rs`.
- Keep operations in `pkcs11/*` modules.
- Add tests to `test.sh` when introducing core ops.

---

## Development Workflow

### Configuration File
Create `/app/.rust-hsm.toml` or `.rust-hsm.toml` to avoid repeating `--label`:
```toml
default_token_label = "DEV_TOKEN"
pkcs11_module = "/usr/lib/softhsm/libsofthsm2.so"  # or libkryoptic_pkcs11.so
```
- CLI args override config values
- Config module: [src/config.rs](../crates/rust-hsm-cli/src/config.rs)
- Switch HSM providers by changing `pkcs11_module` path
- Environment variable `PKCS11_MODULE` overrides config file

### Build & Run
```bash
docker compose up -d --build
docker exec rust-hsm-app rust-hsm-cli info
docker exec rust-hsm-app /app/test.sh          # SoftHSM2 tests
docker exec rust-hsm-app /app/testKryoptic.sh  # Kryoptic tests
```

Reset state:
```bash
docker compose down
docker volume rm rust-hsm_tokens rust-hsm_kryoptic-tokens
docker compose up -d --build
```

---

## Testing Requirements (Observability)
Add at least:
1) HSM provider "smoke" tests (both SoftHSM2 and Kryoptic):
- init token
- generate keypair
- sign
- verify
- ensure logs contain expected function names and rv=OK
2) Redaction test:
- ensure no PIN appears
- ensure no raw data buffers appear
- ensure `CKA_LABEL` is hashed not plaintext
3) Provider compatibility:
- Test with both SoftHSM2 and Kryoptic
- Use [testKryoptic.sh](../testKryoptic.sh) for Kryoptic validation
- Check for provider-specific behavior differences

---

## Performance Requirements
- Observability must add minimal overhead.
- Logging should be buffered or async where practical.
- Avoid expensive formatting on hot paths unless log level requires it.

---

## How to Respond as Copilot (Coding Style Guidance)
- Prefer small, reviewable commits.
- Avoid large refactors unless necessary.
- Make changes compile on stable Rust.
- Use explicit control flow (avoid ternary-style expressions).
- Handle errors with context (`anyhow`, custom error types) and avoid panics in proxy path.
- Add concise docs in `docs/` for new modules, including usage examples.

---

## "Done" Criteria for Observability MVP
- observe-core exists with JSONL sink + redaction.
- CLI can emit structured trace logs via observe-cryptoki (Option C).
- Proxy module builds as `cdylib` and can forward to SoftHSM module (Option A).
- Tests confirm behavior + redaction.
- Documentation explains how to run proxy:
  - setting `PKCS11_OBSERVE_TARGET`
  - using the proxy as the PKCS#11 module path in apps/tools


**Recent upgrade: v0.6 → v0.10 (Dec 2025)**
- `GcmParams::new()` now returns `Result<GcmParams, Error>` - use `?` operator
- IV parameter changed from `&[u8]` to `&mut [u8]` - use `let mut iv` and `&mut iv`
- `Ulong` still uses `u64` (not `u32`) - cast with `as u64`
- All 24 tests pass after migration

When upgrading to future versions:
1. Check [cryptoki changelog](https://github.com/parallaxsecond/rust-cryptoki/releases) for breaking changes
2. Update `mechanism_name()` helper with new mechanisms in [utils.rs](../crates/rust-hsm-cli/src/pkcs11/keys/utils.rs)
3. Test all existing operations with full Docker rebuild: `docker compose build --no-cache`
4. Run integration tests:
   - SoftHSM2: `docker exec rust-hsm-app /app/test.sh`
   - Kryoptic: `docker exec rust-hsm-app /app/testKryoptic.sh`
5. Update this file with newly supported mechanisms and API changes

---

## PKCS#11 Session Lifecycle (Critical)

Every function follows this pattern (see [symmetric.rs](../crates/rust-hsm-cli/src/pkcs11/keys/symmetric.rs)):
```rust
let pkcs11 = Pkcs11::new(module_path)?;
debug!("→ Calling C_Initialize");
pkcs11.initialize(CInitializeArgs::OsThreads)?;

let slot = find_token_slot(&pkcs11, label)?;
debug!("→ Calling C_OpenSession");
let session = pkcs11.open_rw_session(slot)?; // or open_ro_session for read-only

debug!("→ Calling C_Login");
session.login(UserType::User, Some(&pin))?;

// ... perform operations ...

debug!("→ Calling C_Logout");
session.logout()?;
debug!("→ Calling C_Finalize");
pkcs11.finalize();
```

**Why this matters**: PKCS#11 is stateful. Skipping finalize causes resource leaks. Logging C_ function names helps debug HSM issues.

---

## HSM Provider Differences

### SoftHSM2
- **Mature, widely tested**: Industry standard for PKCS#11 testing
- **Token storage**: File-based at `/tokens`
- **Mechanism support**: Comprehensive (RSA, ECDSA, AES-GCM, AES-CMAC, HMAC, etc.)
- **Best for**: General PKCS#11 operations, production-like testing

### Kryoptic
- **Rust-native**: Written in Rust, integrates well with Rust tooling
- **Token storage**: SQLite database at `/kryoptic-tokens`
- **Configuration**: Requires `KRYOPTIC_CONF` env var pointing to [kryoptic.conf](../kryoptic.conf)
- **Mechanism support**: Growing (may have differences from SoftHSM2)
- **Best for**: Rust ecosystem integration, modern cryptography
- **Note**: Some operations may behave differently - always test both providers

### Switching Providers
**Method 1 (Config file)**:
```toml
pkcs11_module = "/usr/lib/kryoptic/libkryoptic_pkcs11.so"
```

**Method 2 (Environment variable)**:
```bash
export PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so
export KRYOPTIC_CONF=/kryoptic-tokens/kryoptic.conf  # Required for Kryoptic
rust-hsm-cli info
```

**Full documentation**: [SWITCHING_HSM_PROVIDERS.md](../docs/SWITCHING_HSM_PROVIDERS.md)

---

## Key Operations Reference

### Asymmetric Key Signing Differences

**RSA**: Mechanism does hashing internally
```rust
let mechanism = Mechanism::Sha256RsaPkcs; // CKM_SHA256_RSA_PKCS
let signature = session.sign(&mechanism, key_handle, &data)?; // Pass raw data
```

**ECDSA**: Must hash data manually before signing
```rust
let mechanism = Mechanism::Ecdsa; // CKM_ECDSA
use sha2::{Sha256, Digest};
let hash = Sha256::digest(&data);
let signature = session.sign(&mechanism, key_handle, &hash)?; // Pass hash, not raw data
```

See [asymmetric.rs](../crates/rust-hsm-cli/src/pkcs11/keys/asymmetric.rs) for the detection logic.

### AES-GCM Format Convention

Encrypted files have this structure (implemented in [symmetric.rs](../crates/rust-hsm-cli/src/pkcs11/keys/symmetric.rs)):
```
[12-byte IV][16-byte auth tag][ciphertext]
```

**IV**: Random 96 bits, generated per encryption, prepended to output.  
**Auth Tag**: 128 bits, appended by PKCS#11, stored with ciphertext.

### Finding Keys by Label

Use the pattern from [utils.rs](../crates/rust-hsm-cli/src/pkcs11/keys/utils.rs):
```rust
let template = vec![
    Attribute::Class(ObjectClass::PrivateKey), // or PublicKey, SecretKey
    Attribute::Label(key_label.as_bytes().to_vec()),
];
let key_handle = session.find_objects(&template)?.first().copied()
    .ok_or_else(|| anyhow::anyhow!("Key '{}' not found", key_label))?;
```

---

## Adding New Commands

1. Add variant to `Commands` enum in [cli.rs](../crates/rust-hsm-cli/src/cli.rs)
2. Implement function in appropriate `pkcs11/*.rs` module
3. Add export to [pkcs11/keys/mod.rs](../crates/rust-hsm-cli/src/pkcs11/keys/mod.rs) if needed
4. Add match arm in [main.rs](../crates/rust-hsm-cli/src/main.rs) to dispatch to your function
5. Add test case to [test.sh](../test.sh) for SoftHSM2
6. Add test case to [testKryoptic.sh](../testKryoptic.sh) for Kryoptic
7. Update command documentation in [docs/commands/](../docs/commands/)

---

## Troubleshooting & Debugging

### Available Troubleshooting Commands
- **explain-error**: Decode PKCS#11 error codes (35+ codes with context)
- **find-key**: Fuzzy key search with Levenshtein distance
- **diff-keys**: Side-by-side key comparison (17 attributes)
- **audit**: Security auditing with severity levels

See [docs/commands/troubleshooting.md](../docs/commands/troubleshooting.md) for details.

### Debug Mode
```bash
RUST_LOG=debug docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label DEV_TOKEN --user-pin 123456 --key-label test --key-type rsa
```

### Common Issues

**"Token not found"**: Token might be in different slot. Run `list-slots` to see all tokens.
**"CKR_PIN_INCORRECT"**: Check PIN with `list-objects` first. SoftHSM locks after 3 failures.
**"Key not found"**: Use `list-objects` to see all objects on token - keys might have different label.
**Kryoptic issues**: Ensure `KRYOPTIC_CONF` env var is set to [kryoptic.conf](../kryoptic.conf) path.
**Provider differences**: Some mechanisms may work differently between SoftHSM2 and Kryoptic - test both.

---

## Security Rules

- **Never log PINs**: Use `debug!("User PIN: ***hidden***")` if mentioning PINs
- **Never hardcode PINs**: Always read from args/stdin (see `--pin-stdin` support in [main.rs](../crates/rust-hsm-cli/src/main.rs))
- **Mark keys as sensitive**: `Attribute::Sensitive(true)` for private/secret keys
- **Non-extractable by default**: Symmetric keys use `Attribute::Extractable(false)` unless `--extractable` flag
- **Redaction first**: When in doubt about logging, redact

---

## Cryptoki Version Upgrade Notes
