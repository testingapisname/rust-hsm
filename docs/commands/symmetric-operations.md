# Symmetric Operations Commands

## encrypt-symmetric

Encrypt data using AES-GCM symmetric encryption.

### Syntax
```bash
rust-hsm-cli encrypt-symmetric --key-label <KEY> --input <FILE> --output <ENC_FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - AES key to use (required)
- `--input <FILE>` - Input plaintext file (required)
- `--output <FILE>` - Output encrypted file (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
# Generate AES key first
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 --key-label aes-key --bits 256

# Create test data
docker exec rust-hsm-app bash -c "echo 'Large sensitive data that would not fit in RSA encryption' > /app/large-data.txt"

# Encrypt with AES-GCM
docker exec rust-hsm-app rust-hsm-cli encrypt-symmetric \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label aes-key \
  --input /app/large-data.txt --output /app/large-data.enc
```

### Example Output
```
2025-12-13T21:30:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:30:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Encrypting data with AES key 'aes-key'
2025-12-13T21:30:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Data encrypted successfully with AES-GCM
2025-12-13T21:30:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Encrypted data written to /app/large-data.enc (88 bytes)
```

### Encryption Details

**Mechanism:** `CKM_AES_GCM` (Galois/Counter Mode)

**File Format:**
```
[12-byte IV][16-byte auth tag][ciphertext]
```

- **IV (Initialization Vector)**: 96 bits, randomly generated per encryption
- **Authentication Tag**: 128 bits, provides integrity verification
- **Ciphertext**: Same length as plaintext

**Total overhead**: 28 bytes (12 + 16)

### Advantages Over RSA

1. **No size limits**: Can encrypt files of any size
2. **Faster**: Much faster than RSA for large data
3. **Authenticated**: Built-in integrity verification
4. **Streaming**: Can process large files efficiently

---

## decrypt-symmetric

Decrypt AES-GCM encrypted data.

### Syntax
```bash
rust-hsm-cli decrypt-symmetric --key-label <KEY> --input <ENC_FILE> --output <FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - AES key to use (required)
- `--input <FILE>` - Input encrypted file (required)
- `--output <FILE>` - Output plaintext file (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli decrypt-symmetric \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label aes-key \
  --input /app/large-data.enc --output /app/large-data-decrypted.txt

# Verify decryption
docker exec rust-hsm-app cat /app/large-data-decrypted.txt
```

### Example Output
```
2025-12-13T21:35:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:35:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Decrypting data with AES key 'aes-key'
2025-12-13T21:35:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Data decrypted successfully with AES-GCM
2025-12-13T21:35:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Decrypted data written to /app/large-data-decrypted.txt (60 bytes)

Large sensitive data that would not fit in RSA encryption
```

### Error Handling

**Tampered ciphertext:**
```bash
# Modify encrypted file
docker exec rust-hsm-app bash -c "echo 'corrupted' >> /app/large-data.enc"

# Try to decrypt
docker exec rust-hsm-app rust-hsm-cli decrypt-symmetric \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label aes-key \
  --input /app/large-data.enc --output /app/failed.txt
```

```
2025-12-13T21:36:00.123456Z ERROR rust_hsm_cli::pkcs11::keys::symmetric: Decryption failed - authentication tag mismatch
Error: Data integrity verification failed
```

**Wrong key:**
```bash
# Generate different key
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 --key-label wrong-key --bits 256

# Try to decrypt with wrong key
docker exec rust-hsm-app rust-hsm-cli decrypt-symmetric \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label wrong-key \
  --input /app/large-data.enc --output /app/failed.txt
```

```
2025-12-13T21:37:00.123456Z ERROR rust_hsm_cli::pkcs11::keys::symmetric: Decryption failed
Error: Failed to decrypt data with key 'wrong-key'
```

---

## Notes

### When to Use Symmetric vs Asymmetric Encryption

**Use Symmetric (AES-GCM) for:**
- Large files (> 245 bytes)
- High-performance requirements
- Bulk data encryption
- Database encryption
- File encryption
- Disk encryption

**Use Asymmetric (RSA) for:**
- Small secrets (passwords, keys)
- Digital envelopes (encrypt AES key with RSA, data with AES)
- Key exchange
- Maximum interoperability

### Hybrid Encryption Pattern

For large data with public-key cryptography:

1. **Generate ephemeral AES key**
   ```bash
   rust-hsm-cli gen-symmetric-key --key-label session-key --extractable
   ```

2. **Encrypt data with AES**
   ```bash
   rust-hsm-cli encrypt-symmetric --key-label session-key --input large-file.dat
   ```

3. **Wrap AES key with RSA public key** (or use wrap-key with another AES KEK)
   ```bash
   rust-hsm-cli wrap-key --key-label session-key --wrapping-key-label rsa-key
   ```

4. **Transmit**: Send encrypted data + wrapped key

5. **Recipient decrypts**: Unwrap AES key with RSA private key, decrypt data

### AES Key Sizes

- **AES-128**: Fast, sufficient for most use cases, widely supported
- **AES-192**: Middle ground, rarely used
- **AES-256**: Maximum security, slightly slower, recommended for sensitive data

All AES key sizes provide strong security. AES-256 is recommended for:
- Long-term encrypted data
- High-security environments
- Compliance requirements (e.g., government)

### GCM Mode Benefits

**Advantages over CBC:**
- Built-in authentication (detects tampering)
- Parallelizable (faster on multi-core)
- No padding oracle attacks
- NIST recommended

**Security:**
- Each IV must be unique per encryption
- Never reuse IV with same key
- Our implementation generates random IV per encryption
