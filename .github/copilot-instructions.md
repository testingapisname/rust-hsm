# Copilot Instructions for rust-hsm

## Project Overview

A Rust PKCS#11 CLI tool for interfacing with **SoftHSM2** in a single Docker container. Provides repeatable HSM-style workflows for token management, asymmetric/symmetric key operations, signing, encryption, key wrapping, CSR generation, key fingerprints, and detailed inspection. Includes HMAC, CMAC, hashing, random generation, benchmarking, and security auditing. This is a learning tool - not for production security.

## Architecture & Key Insight

**Single-container design**: Both SoftHSM2 and Rust CLI run in the same container. The CLI loads `libsofthsm2.so` directly via the `cryptoki` crate (NOT calling external `pkcs11-tool` commands).

```
┌───────────────────────────────┐
│     rust-hsm-app container    │
│  ┌─────────────────────────┐  │
│  │  rust-hsm-cli binary    │  │
│  │  (loads libsofthsm2.so) │  │
│  └──────────┬──────────────┘  │
│             │ cryptoki FFI    │
│  ┌──────────▼──────────────┐  │
│  │  SoftHSM2 (PKCS#11)     │  │
│  │  /usr/lib/softhsm/      │  │
│  └──────────┬──────────────┘  │
│             │                 │
│  ┌──────────▼──────────────┐  │
│  │  Token Storage          │  │
│  │  /tokens (volume)       │  │
│  └─────────────────────────┘  │
└───────────────────────────────┘
```

**Token persistence**: Docker volume at `/tokens` survives container restarts. Wipe with `docker volume rm rust-hsm_tokens`.

## Tech Stack

- **PKCS#11 bindings**: `cryptoki` v0.10 (type-safe Rust wrapper, not raw FFI)
- **CLI**: `clap` v4.5 with derive macros and subcommands
- **Logging**: `tracing` + `tracing-subscriber` with env-filter (use `RUST_LOG=debug`)
- **Crypto libraries**: `sha2`, `simple_asn1`, `num-bigint` for data format conversions
- **Container**: Multi-stage Dockerfile (Rust 1.83 builder → Debian Bookworm Slim runtime)

## Critical Code Structure

```
crates/rust-hsm-cli/src/
  main.rs                   # CLI entry, subcommand dispatch, PIN input handling (328 lines)
  cli.rs                    # Command definitions with clap derive macros (531 lines)
  config.rs                 # Configuration file loading (.rust-hsm.toml)
  pkcs11/
    mod.rs                  # Module exports (thin layer)
    errors.rs               # Custom Pkcs11Error type wrapping cryptoki::error::Error
    info.rs                 # Module/slot/mechanism information with --detailed flags (179 lines)
    slots.rs                # Slot enumeration
    token.rs                # Token init, PIN setup
    objects.rs              # Object listing with --detailed flag (p11ls-style) (245 lines)
    audit.rs                # Security audit with severity levels and issue detection
    keys/
      mod.rs                # Re-exports all key operations
      utils.rs              # Shared helpers: find_token_slot, mechanism_name, get_key_type
      keypair.rs            # RSA/ECDSA key generation
      asymmetric.rs         # Sign/verify/encrypt/decrypt (RSA & ECDSA)
      symmetric.rs          # AES key gen, AES-GCM encrypt/decrypt
      export.rs             # PEM export for public keys
      wrap.rs               # AES Key Wrap (RFC 3394)
      csr.rs                # X.509 CSR generation
      inspect.rs            # Key attribute inspection with SHA-256 fingerprints (401 lines)
      hash.rs               # SHA-256/384/512/224/1 hashing (no login required)
      hmac.rs               # HMAC-SHA1/224/256/384/512 operations
      benchmark.rs          # Performance benchmarking suite
```

## Development Workflow

### Configuration File (New!)
Create `/ app/.rust-hsm.toml` or `.rust-hsm.toml` to avoid repeating `--label`:
```toml
default_token_label = "DEV_TOKEN"
pkcs11_module = "/usr/lib/softhsm/libsofthsm2.so"
```
- CLI args override config values
- Config module: [src/config.rs](../crates/rust-hsm-cli/src/config.rs)
- Loaded in [main.rs](../crates/rust-hsm-cli/src/main.rs#L336-L341)
- Example: [config.example.toml](../config.example.toml)

### Build & Run
```bash
docker compose up -d --build          # Rebuild after code changes
docker exec rust-hsm-app rust-hsm-cli info
```

### Testing
```bash
docker exec rust-hsm-app /app/test.sh  # Run full integration test suite (40 tests)
```

### Reset Token State
```bash
docker compose down
docker volume rm rust-hsm_tokens
docker compose up -d
```

## PKCS#11 Patterns (Critical for AI Agents)

### Session Lifecycle (Always Follow)

Every function follows this pattern (see [symmetric.rs](../crates/rust-hsm-cli/src/pkcs11/keys/symmetric.rs#L23-L70)):
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

**Why this matters**: PKCS#11 is stateful. Skipping finalize causes resource leaks. Logging C_ function names helps debug SoftHSM issues.

### Logging Convention (MANDATORY)

Use three-level logging with `tracing`:
- `info!()` - Major milestones: "Signing data with key 'X' on token 'Y'"
- `debug!()` - PKCS#11 calls: `debug!("→ Calling C_GenerateKey")`
- `trace!()` - Raw data: `trace!("Hash value: {:02x?}", &hash)`

**Pattern**: Always log the PKCS#11 C_ function name before calling it. Use [mechanism_name()](../crates/rust-hsm-cli/src/pkcs11/keys/utils.rs#L10-L21) to log mechanism types (e.g., "CKM_SHA256_RSA_PKCS").

### Key Type Differences (Asymmetric Signing)

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

See [asymmetric.rs](../crates/rust-hsm-cli/src/pkcs11/keys/asymmetric.rs#L57-L70) for the detection logic.

### AES-GCM Format Convention

Encrypted files have this structure (implemented in [symmetric.rs](../crates/rust-hsm-cli/src/pkcs11/keys/symmetric.rs)):
```
[12-byte IV][16-byte auth tag][ciphertext]
```

**IV**: Random 96 bits, generated per encryption, prepended to output.  
**Auth Tag**: 128 bits, appended by PKCS#11, stored with ciphertext.

### Security Rules

- **Never log PINs**: Use `debug!("User PIN: ***hidden***")` if mentioning PINs
- **Never hardcode PINs**: Always read from args/stdin (see `--pin-stdin` support in [main.rs](../crates/rust-hsm-cli/src/main.rs#L8-L14))
- **Mark keys as sensitive**: `Attribute::Sensitive(true)` for private/secret keys
- **Non-extractable by default**: Symmetric keys use `Attribute::Extractable(false)` unless `--extractable` flag

## Common Tasks for AI Agents

### Adding a New Command

1. Add variant to `Commands` enum in [main.rs](../crates/rust-hsm-cli/src/main.rs#L23)
2. Implement function in appropriate `pkcs11/keys/*.rs` module
3. Add export to [pkcs11/keys/mod.rs](../crates/rust-hsm-cli/src/pkcs11/keys/mod.rs)
4. Add match arm in `main()` to dispatch to your function
5. Add test case to [test.sh](../test.sh) if it's a core operation

### Important Refactoring: CLI Structure

**Major refactor (Dec 2025)**: Split `main.rs` (863 lines) into focused modules:
- **cli.rs (531 lines)**: All `Commands` enum definitions with clap derive macros
- **main.rs (328 lines)**: Command dispatch, PIN handling, error handling
- **Benefits**: Cleaner separation, easier to add commands, better IDE navigation

When adding new commands:
1. Define command struct in `cli.rs` with clap attributes
2. Add variant to `Commands` enum
3. Handle in `main.rs` match statement
4. Implement business logic in appropriate `pkcs11/*.rs` module

### Key Fingerprints (NEW!)

**SHA-256 fingerprints** for public key verification (like SSH fingerprints):
- Displayed automatically in `inspect-key` output
- Format: colon-separated hex (e.g., `ec:bb:93:16:a4:7c:...`)
- RSA: Hash of modulus + public exponent
- ECDSA: Hash of EC params + EC point
- Included in JSON output for automation
- Implementation: [inspect.rs calculate_fingerprint()](../crates/rust-hsm-cli/src/pkcs11/keys/inspect.rs)

### Troubleshooting Commands (NEW - Dec 2025!)

**Purpose**: HSM diagnostic and debugging tools for troubleshooting application errors.

**Implementation**: [troubleshoot.rs](../crates/rust-hsm-cli/src/pkcs11/troubleshoot.rs) - 655 lines

1. **explain-error**: PKCS#11 error code decoder
   - Pattern matching on error code strings (name, hex, decimal)
   - 35+ error codes with descriptions, causes, and solutions
   - Context-aware troubleshooting for operations (sign, verify, encrypt, decrypt, login, wrap)
   - Returns `Result<()>` with formatted output to stdout

2. **find-key**: Fuzzy key search with Levenshtein distance
   - Searches for exact matches first
   - If not found and `--show-similar`, calculates edit distance for all keys
   - Shows keys with distance ≤3 as "similar"
   - Displays key type, capabilities, and security flags
   - Requires session login (uses existing session pattern)

3. **diff-keys**: Side-by-side key comparison
   - Retrieves attributes for both keys in parallel
   - Compares 17 attributes: Class, KeyType, Token, Private, Modifiable, etc.
   - Displays comparison table with ✓ (match) or ✗ (difference) indicators
   - Lists all differences with severity assessment and explanations
   - No login required for public keys, login required for private keys

**Command Pattern**: These follow the same session management pattern but don't require login for read-only operations like explain-error. See [troubleshoot.rs](../crates/rust-hsm-cli/src/pkcs11/troubleshoot.rs) for reference implementations.

### Detailed Listing Flags (NEW!)

**--detailed flag pattern** for enhanced output:

1. **list-mechanisms --detailed**: Shows capability flags (like p11slotinfo)
   ```
   CKM_RSA_PKCS                               enc dec sig vfy wra unw
   CKM_AES_GCM                                enc dec
   ```
   Flags: enc, dec, sig, vfy, hsh, gkp, wra, unw, der, srec, vrec, gen

2. **list-objects --detailed**: Shows p11ls-style attributes
   ```
   prvk/rsa   my-key                               tok,prv,r/w,loc,sen,ase,nxt,XTR,sig,dec,unw,rsa(2048)
   pubk/ec    ec-key                               tok,pub,r/w,loc,vfy,enc,wra
   ```
   Attributes: tok, prv/pub, r/w/r/o, loc/imp, sig, vfy, enc, dec, wra, unw, der, sen, ase, nxt, XTR

**Implementation notes**:
- Use `MechanismInfo` from cryptoki for mechanism capabilities
- Format helpers in [info.rs format_mechanism_flags()](../crates/rust-hsm-cli/src/pkcs11/info.rs)
- Object details in [objects.rs get_detailed_object_info()](../crates/rust-hsm-cli/src/pkcs11/objects.rs)

### Finding Keys by Label

Use the pattern from [utils.rs](../crates/rust-hsm-cli/src/pkcs11/keys/utils.rs#L38-L49):
```rust
let template = vec![
    Attribute::Class(ObjectClass::PrivateKey), // or PublicKey, SecretKey
    Attribute::Label(key_label.as_bytes().to_vec()),
];
let key_handle = session.find_objects(&template)?.first().copied()
    .ok_or_else(|| anyhow::anyhow!("Key '{}' not found", key_label))?;
```

### Determining Mechanism Types

Check [utils.rs mechanism_name()](../crates/rust-hsm-cli/src/pkcs11/keys/utils.rs#L10-L21) for supported mechanisms. When adding new mechanisms:
1. Use the `cryptoki::mechanism::Mechanism` enum variant (NOT raw CKM_ constants)
2. Add logging case to `mechanism_name()` helper
3. Document which PKCS#11 operation it's used for (sign, encrypt, wrap, etc.)

**Note**: `cryptoki` v0.6 lacks some mechanisms like AES-CMAC. See [docs/IMPLEMENTING_AES_CMAC.md](../docs/IMPLEMENTING_AES_CMAC.md) for workarounds.

## Testing & Debugging

### Run Full Test Suite
```bash
docker exec rust-hsm-app /app/test.sh  # 43 tests: RSA, ECDSA, AES, wrap/unwrap, CSR, hash, HMAC, CMAC, fingerprints, troubleshooting
```

### Debug Mode
```bash
RUST_LOG=debug docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label DEV_TOKEN --user-pin 123456 --key-label test --key-type rsa
```

### Common Issues

**"Token not found"**: Token might be in different slot. Run `list-slots` to see all tokens.  
**"CKR_PIN_INCORRECT"**: Check PIN with `list-objects` first. SoftHSM locks after 3 failures.  
**"Key not found"**: Use `list-objects` to see all objects on token - keys might have different label.  
**Slot allocation**: SoftHSM picks the next available slot. If slot 0 is occupied, it uses slot 1, 2, etc.

### Reset Everything
```bash
docker compose down
docker volume rm rust-hsm_tokens
docker compose up -d --build
```

## Known Limitations & Future Work

### Current Limitations

**1. `cryptoki` v0.10 Mechanism Coverage**
- **✅ Implemented**: AES-CMAC (`CKM_AES_CMAC`, `CKM_AES_CMAC_GENERAL`) - full support including truncated MACs
- **✅ Implemented**: HMAC operations (SHA-1/224/256/384/512) - sign and verify
- **✅ Implemented**: Hashing (SHA-1/224/256/384/512) - no login required
- **✅ Implemented**: Random number generation (`C_GenerateRandom`) - no login required
- **Missing**: Raw RSA operations (OAEP padding, PSS signatures)
- **Missing**: Key derivation functions (PBKDF2, HKDF)
- **Note**: Upgraded from v0.6 - `GcmParams::new()` now returns `Result` and requires mutable IV reference

**2. Asymmetric Crypto Constraints**
- **RSA encryption size limit**: 245 bytes for 2048-bit keys, 501 bytes for 4096-bit keys (PKCS#1 v1.5 overhead)
- **No RSA-OAEP**: Only PKCS#1 v1.5 padding supported (`CKM_RSA_PKCS`)
- **Limited curves**: Only P-256 and P-384 ECDSA curves (no P-521, Ed25519, X25519)
- **No ECDH**: Key agreement not implemented

**3. Key Management**
- **✅ Key inspection**: Detailed CKA_* attribute display with `inspect-key` command
- **✅ Key fingerprints**: SHA-256 fingerprints for public keys (RSA & ECDSA)
- **✅ JSON output**: Machine-readable format for automation
- **✅ Security auditing**: Detect weak keys, improper configurations, security issues
- **No bulk operations**: Must delete keys one at a time
- **No key backup/restore**: Except via wrap/unwrap (requires extractable keys)

**4. Token Management**
- **Single token operations**: Commands operate on one token at a time
- **No SO PIN management**: Can't change SO PIN after initialization
- **Manual slot selection**: SoftHSM auto-assigns slots; can't force specific slot numbers

**5. Security Limitations (SoftHSM)**
- **Software-backed**: No hardware security module protection
- **Keys on disk**: Token storage at `/tokens` is just encrypted files
- **Not for production**: Educational/testing tool only

### Planned Future Work

**High Priority**
1. **✅ COMPLETED: MAC Operations**
   - HMAC (SHA-1/224/256/384/512): `hmac-sign`, `hmac-verify`
   - AES-CMAC: `cmac-sign`, `cmac-verify` with optional truncation
   - See [IMPLEMENTING_AES_CMAC.md](../docs/IMPLEMENTING_AES_CMAC.md) for implementation details

2. **✅ COMPLETED: Key Attribute Inspection**
   - `inspect-key` command with detailed CKA_* attributes
   - SHA-256 fingerprints for public keys
   - JSON output support with `--json` flag
   - Distinguishes between RSA and ECDSA keys automatically

3. **✅ COMPLETED: Detailed Object/Mechanism Listing**
   - `list-objects --detailed` shows p11ls-style output (type, flags, capabilities, sizes)
   - `list-mechanisms --detailed` shows p11slotinfo-style capabilities (enc/dec/sig/vfy/etc)
   - Supports `--slot` parameter for specific slot queries

4. **✅ COMPLETED: Security Auditing**
   - `audit` command detects weak keys, configuration issues, security problems
   - Severity levels: CRITICAL, HIGH, MEDIUM, LOW
   - Grouped by category for easy remediation

5. **Find Orphaned Keys**
   ```bash
   rust-hsm-cli delete-all-keys --label TOKEN --user-pin PIN --pattern "temp-*"
   rust-hsm-cli list-keys --label TOKEN --user-pin PIN --format json
   ```

   - Detect private keys without public keys (and vice versa)
   - Commands: `find-orphaned-keys`
   - Useful for cleanup and troubleshooting

6. **Compare Keys**
   - Side-by-side comparison of key attributes
   - Useful for troubleshooting key mismatches
   - Commands: `compare-keys --key-label KEY1 --key-label KEY2`

7. **RSA-OAEP Support**
   - Larger payload encryption (up to key_size - 66 bytes for SHA-256)
   - Stronger security than PKCS#1 v1.5
   - Requires `cryptoki` enum extension or raw mechanism

8. **Additional Curves**
   - P-521 for ECDSA
   - Curve25519 (Ed25519 signatures, X25519 ECDH)
   - Check `cryptoki` version support

**Medium Priority**
9. **Key Derivation Functions**
   - PBKDF2 for password-based key derivation
   - HKDF for key stretching
   - Useful for deriving encryption keys from passwords

10. **Batch Operations**
   ```bash
   rust-hsm-cli delete-all-keys --label TOKEN --user-pin PIN --pattern "temp-*"
   rust-hsm-cli list-keys --label TOKEN --user-pin PIN --format json
   ```

11. **Session Management**
   - Persistent sessions (avoid login for multiple operations)
   - Read-only session optimization (currently opens RW for everything)

12. **PIN Management**
   - Change user PIN command
   - Change SO PIN command
   - PIN complexity validation

13. **Certificate Management**
   - Import X.509 certificates to token
   - Link certificates to keypairs
   - Certificate chain validation

**Low Priority**
14. **Multi-token Operations**
    - Copy keys between tokens
    - Compare token contents
    - Synchronize key sets

15. **✅ COMPLETED: Performance Benchmarking**
    - `benchmark` command with full suite or specific key testing
    - Measures ops/sec and latency (P50/P95/P99)
    - Tests: RSA/ECDSA signing, encryption, hashing, MACs, random generation
    - Auto-detects key types and capabilities

16. **✅ COMPLETED: Troubleshooting Commands (Dec 2025)**
    - `explain-error` - Decode 35+ PKCS#11 error codes with context-aware troubleshooting
      - Supports name, hex, and decimal formats (CKR_PIN_INCORRECT, 0x000000A0, 160)
      - Context flags: sign, verify, encrypt, decrypt, login, wrap
      - Implementation: [troubleshoot.rs](../crates/rust-hsm-cli/src/pkcs11/troubleshoot.rs)
    - `find-key` - Fuzzy key search with Levenshtein distance matching
      - Shows exact matches and similar keys (edit distance ≤3)
      - Displays key type, capabilities, and security flags
      - Helps locate keys with typos or naming variations
    - `diff-keys` - Side-by-side key comparison
      - Compares 17 key attributes (class, type, capabilities, security flags)
      - Shows differences with severity indicators (CRITICAL/HIGH/MEDIUM/LOW)
      - Useful for troubleshooting "identical" keys with different behavior
    - Documentation: [docs/commands/troubleshooting.md](../docs/commands/troubleshooting.md)
    - Tests: 43 total (40 existing + 3 new troubleshooting tests)

### Contributing Notes

When implementing new features:
- **Start with mechanism support**: Check if `cryptoki` supports the mechanism first
- **Update `mechanism_name()`**: Add new mechanisms to [utils.rs](../crates/rust-hsm-cli/src/pkcs11/keys/utils.rs#L10-L21)
- **Follow logging pattern**: Always log C_ function names before PKCS#11 calls
- **Add to test suite**: Update [test.sh](../test.sh) with test cases
- **Document in README**: Add usage examples to main README
- **Reference standards**: Link to RFCs/NIST specs in code comments

### Cryptoki Version Migration

**Recent upgrade: v0.6 → v0.10 (Dec 2025)**
- `GcmParams::new()` now returns `Result<GcmParams, Error>` - use `?` operator
- IV parameter changed from `&[u8]` to `&mut [u8]` - use `let mut iv` and `&mut iv`
- `Ulong` still uses `u64` (not `u32`) - cast with `as u64`
- All 24 tests pass after migration

When upgrading to future versions:
1. Check [cryptoki changelog](https://github.com/parallaxsecond/rust-cryptoki/releases) for breaking changes
2. Update `mechanism_name()` helper with new mechanisms in [utils.rs](../crates/rust-hsm-cli/src/pkcs11/keys/utils.rs)
3. Test all existing operations with full Docker rebuild: `docker compose build --no-cache`
4. Run integration tests: `docker exec rust-hsm-app /app/test.sh`
5. Update this file with newly supported mechanisms and API changes
