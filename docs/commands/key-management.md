# Key Management Commands

## wrap-key

Wrap (encrypt) a key for secure export or backup using AES Key Wrap (RFC 3394).

### Syntax
```bash
rust-hsm-cli wrap-key --key-label <KEY_TO_WRAP> --wrapping-key-label <KEK> \
  --output <FILE> --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Key to wrap (must be extractable) (required)
- `--wrapping-key-label <KEK_LABEL>` - Key Encryption Key to use (required)
- `--output <FILE>` - Output wrapped key file (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
# 1. Generate Key Encryption Key (KEK)
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 --key-label kek --bits 256

# 2. Generate extractable key to wrap
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 --key-label backup-key --bits 256 --extractable

# 3. Wrap the key
docker exec rust-hsm-app rust-hsm-cli wrap-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label backup-key \
  --wrapping-key-label kek \
  --output /app/backup-key.wrapped
```

### Example Output
```
2025-12-13T21:45:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:45:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::wrap: Wrapping key 'backup-key' with KEK 'kek'
2025-12-13T21:45:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::wrap: Key wrapped successfully using AES Key Wrap (RFC 3394)
2025-12-13T21:45:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::wrap: Wrapped key written to /app/backup-key.wrapped (40 bytes)
```

### Wrapped Key Format

**AES Key Wrap (RFC 3394):**
- Mechanism: `CKM_AES_KEY_WRAP`
- Output size: Input key size + 8 bytes
- For AES-256 (32 bytes): Wrapped output = 40 bytes
- For AES-128 (16 bytes): Wrapped output = 24 bytes

**Security:**
- Provides confidentiality and integrity
- Detects tampering during unwrap
- Industry standard for key transport

---

## unwrap-key

Unwrap (decrypt) a previously wrapped key for restoration or import.

### Syntax
```bash
rust-hsm-cli unwrap-key --key-label <NEW_KEY_NAME> --wrapping-key-label <KEK> \
  --input <WRAPPED_FILE> --key-type <TYPE> --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Label for the unwrapped key (required)
- `--wrapping-key-label <KEK_LABEL>` - Key Encryption Key to use (required)
- `--input <FILE>` - Input wrapped key file (required)
- `--key-type <TYPE>` - Type of wrapped key: `aes` (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
# Unwrap previously wrapped key
docker exec rust-hsm-app rust-hsm-cli unwrap-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label restored-key \
  --wrapping-key-label kek \
  --input /app/backup-key.wrapped \
  --key-type aes
```

### Example Output
```
2025-12-13T21:50:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:50:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::wrap: Unwrapping key from /app/backup-key.wrapped with KEK 'kek'
2025-12-13T21:50:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::wrap: Key unwrapped successfully as 'restored-key'
2025-12-13T21:50:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::wrap: Unwrapped key is ready for use
```

### Verification
```bash
# List objects to see restored key
docker exec rust-hsm-app rust-hsm-cli list-objects \
  --label DEV_TOKEN --user-pin 123456 --detailed | grep restored-key

# Test the restored key
docker exec rust-hsm-app bash -c "echo 'test data' > /app/test.txt"
docker exec rust-hsm-app rust-hsm-cli encrypt-symmetric \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label restored-key \
  --input /app/test.txt --output /app/test.enc
```

---

## delete-key

Delete a keypair or symmetric key from the token.

### Syntax
```bash
rust-hsm-cli delete-key --key-label <KEY> --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Key to delete (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli delete-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label old-key
```

### Example Output
```
2025-12-13T21:55:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:55:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Deleting key 'old-key'
2025-12-13T21:55:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Found 2 objects with label 'old-key'
2025-12-13T21:55:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Deleted 2 objects
Key 'old-key' deleted successfully
```

### Delete Asymmetric Keypair
```bash
# Generate RSA keypair
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label DEV_TOKEN --user-pin 123456 --key-label temp-key --key-type rsa

# Delete both public and private keys
docker exec rust-hsm-app rust-hsm-cli delete-key \
  --label DEV_TOKEN --user-pin 123456 --key-label temp-key
```

**Output:**
```
2025-12-13T21:56:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Found 2 objects with label 'temp-key'
2025-12-13T21:56:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Deleted 2 objects
Key 'temp-key' deleted successfully
```

### Delete Symmetric Key
```bash
# Generate AES key
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 --key-label temp-aes --bits 256

# Delete it
docker exec rust-hsm-app rust-hsm-cli delete-key \
  --label DEV_TOKEN --user-pin 123456 --key-label temp-aes
```

**Output:**
```
2025-12-13T21:57:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Found 1 object with label 'temp-aes'
2025-12-13T21:57:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Deleted 1 object
Key 'temp-aes' deleted successfully
```

---

## Notes

### Key Wrapping Use Cases

1. **Backup and Recovery**
   - Wrap keys before backup
   - Store wrapped keys securely offline
   - Restore when needed

2. **Key Migration**
   - Export keys from one HSM
   - Import to another HSM
   - Maintain key continuity

3. **Key Distribution**
   - Securely transmit keys between systems
   - Share keys with partners
   - Multi-datacenter deployments

4. **Disaster Recovery**
   - Maintain encrypted key backups
   - Quick restoration after failures
   - Business continuity

### Extractable vs Non-Extractable Keys

**Extractable keys** (`--extractable` flag):
- Can be wrapped and exported
- Less secure (can leave HSM)
- Use for: backup, migration, distribution
- Example: Session keys, temporary keys

**Non-extractable keys** (default):
- Cannot leave the HSM
- Higher security
- Use for: Long-term signing keys, root keys
- Example: CA private keys, master encryption keys

### Key Wrap Workflow

**Export from Token A:**
```bash
# On Token A
rust-hsm-cli gen-symmetric-key --key-label shared-kek --bits 256
rust-hsm-cli gen-symmetric-key --key-label data-key --extractable
rust-hsm-cli wrap-key --key-label data-key --wrapping-key-label shared-kek \
  --output data-key.wrapped
```

**Import to Token B:**
```bash
# Generate matching KEK on Token B (same key material)
rust-hsm-cli gen-symmetric-key --key-label shared-kek --bits 256

# Unwrap the key
rust-hsm-cli unwrap-key --key-label data-key --wrapping-key-label shared-kek \
  --input data-key.wrapped --key-type aes
```

**Note**: In production, KEK distribution requires secure key exchange protocols.

### Delete Considerations

**⚠️ Warning**: Deletion is permanent and cannot be undone!

**Before deleting:**
1. Backup with wrap-key (if extractable)
2. Verify no active usage
3. Update applications referencing the key
4. Document the deletion

**Best practices:**
- Test deletion in development first
- Use key rotation instead of immediate deletion
- Maintain key lifecycle documentation
- Audit key deletions
