# Hashing & MAC Commands

## hash

Compute cryptographic hash of data (SHA family). No authentication required.

### Syntax
```bash
rust-hsm-cli hash --input <FILE> [--output <FILE>] [--algorithm <ALG>]
```

### Flags
- `--input <FILE>` - Input file to hash (required)
- `--output <FILE>` - Output file for hash (optional, prints to stdout if omitted)
- `--algorithm <ALG>` - Hash algorithm: `sha256`, `sha384`, `sha512`, `sha224`, `sha1` (default: `sha256`)

### Example (SHA-256, default)
```bash
docker exec rust-hsm-app bash -c "echo 'Hello World' > /app/data.txt"

docker exec rust-hsm-app rust-hsm-cli hash --input /app/data.txt
```

### Example Output
```
d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26
```

### Example (Save to File)
```bash
docker exec rust-hsm-app rust-hsm-cli hash \
  --input /app/data.txt --output /app/data.sha256
```

### Example Output
```
2025-12-13T22:00:00.123456Z  INFO rust_hsm_cli::pkcs11::keys::hash: Hashing data with SHA-256
2025-12-13T22:00:00.134567Z  INFO rust_hsm_cli::pkcs11::keys::hash: Hash computed successfully (32 bytes)
```

### Example (Different Algorithms)
```bash
# SHA-384
docker exec rust-hsm-app rust-hsm-cli hash \
  --algorithm sha384 --input /app/data.txt

# SHA-512
docker exec rust-hsm-app rust-hsm-cli hash \
  --algorithm sha512 --input /app/data.txt

# SHA-224
docker exec rust-hsm-app rust-hsm-cli hash \
  --algorithm sha224 --input /app/data.txt

# SHA-1 (not recommended for security, use for compatibility only)
docker exec rust-hsm-app rust-hsm-cli hash \
  --algorithm sha1 --input /app/data.txt
```

### Hash Sizes

- **SHA-256**: 32 bytes (256 bits) - Recommended default
- **SHA-384**: 48 bytes (384 bits) - High security
- **SHA-512**: 64 bytes (512 bits) - Maximum security
- **SHA-224**: 28 bytes (224 bits) - Truncated SHA-256
- **SHA-1**: 20 bytes (160 bits) - ⚠️ Deprecated, avoid for security

---

## hmac-sign

Generate HMAC (Hash-based Message Authentication Code) using a secret key.

### Syntax
```bash
rust-hsm-cli hmac-sign --key-label <KEY> --input <FILE> --output <MAC_FILE> \
  --user-pin <PIN> [--label <TOKEN>] [--algorithm <ALG>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - HMAC key to use (required)
- `--input <FILE>` - Input data file (required)
- `--output <FILE>` - Output HMAC file (required)
- `--algorithm <ALG>` - Hash algorithm: `sha1`, `sha224`, `sha256`, `sha384`, `sha512` (default: `sha256`)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
# Generate HMAC key
docker exec rust-hsm-app rust-hsm-cli gen-hmac-key \
  --label DEV_TOKEN --user-pin 123456 --key-label hmac-key --bits 256

# Create test data
docker exec rust-hsm-app bash -c "echo 'Message to authenticate' > /app/message.txt"

# Generate HMAC-SHA256
docker exec rust-hsm-app rust-hsm-cli hmac-sign \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label hmac-key \
  --algorithm sha256 \
  --input /app/message.txt --output /app/message.hmac
```

### Example Output
```
2025-12-13T22:05:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T22:05:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Generating HMAC-SHA256 with key 'hmac-key'
2025-12-13T22:05:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::hmac: HMAC generated successfully (32 bytes)
2025-12-13T22:05:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: HMAC written to /app/message.hmac
```

### Example (Different Algorithms)
```bash
# HMAC-SHA512 (64 bytes output)
docker exec rust-hsm-app rust-hsm-cli hmac-sign \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label hmac-key --algorithm sha512 \
  --input /app/message.txt --output /app/message.hmac512

# HMAC-SHA384 (48 bytes output)
docker exec rust-hsm-app rust-hsm-cli hmac-sign \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label hmac-key --algorithm sha384 \
  --input /app/message.txt --output /app/message.hmac384
```

---

## hmac-verify

Verify an HMAC against the original data.

### Syntax
```bash
rust-hsm-cli hmac-verify --key-label <KEY> --input <FILE> --hmac <MAC_FILE> \
  --user-pin <PIN> [--label <TOKEN>] [--algorithm <ALG>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - HMAC key to use (required)
- `--input <FILE>` - Original data file (required)
- `--hmac <FILE>` - HMAC file to verify (required)
- `--algorithm <ALG>` - Hash algorithm (must match signing): `sha1`, `sha224`, `sha256`, `sha384`, `sha512` (default: `sha256`)
- `--pin-stdin` - Read PIN from stdin

### Example (Valid HMAC)
```bash
docker exec rust-hsm-app rust-hsm-cli hmac-verify \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label hmac-key \
  --algorithm sha256 \
  --input /app/message.txt --hmac /app/message.hmac
```

### Example Output (Valid)
```
2025-12-13T22:10:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T22:10:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Verifying HMAC-SHA256 with key 'hmac-key'
2025-12-13T22:10:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::hmac: HMAC verification SUCCEEDED
HMAC is valid!
```

### Example (Invalid HMAC - Modified Data)
```bash
# Modify the message
docker exec rust-hsm-app bash -c "echo 'Modified message' > /app/message.txt"

# Try to verify
docker exec rust-hsm-app rust-hsm-cli hmac-verify \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label hmac-key \
  --input /app/message.txt --hmac /app/message.hmac
```

### Example Output (Invalid)
```
2025-12-13T22:11:00.123456Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Verifying HMAC-SHA256 with key 'hmac-key'
2025-12-13T22:11:00.234567Z ERROR rust_hsm_cli::pkcs11::keys::hmac: HMAC verification FAILED
Error: HMAC verification failed - data may have been tampered with
```

---

## cmac-sign

Generate CMAC (Cipher-based MAC) using AES.

### Syntax
```bash
rust-hsm-cli cmac-sign --key-label <KEY> --input <FILE> --output <MAC_FILE> \
  --user-pin <PIN> [--label <TOKEN>] [--mac-len <BYTES>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - CMAC (AES) key to use (required)
- `--input <FILE>` - Input data file (required)
- `--output <FILE>` - Output CMAC file (required)
- `--mac-len <BYTES>` - Truncate MAC to N bytes (optional, default: 16, min: 8, max: 16)
- `--pin-stdin` - Read PIN from stdin

### Example (Full 16-byte CMAC)
```bash
# Generate CMAC key
docker exec rust-hsm-app rust-hsm-cli gen-cmac-key \
  --label DEV_TOKEN --user-pin 123456 --key-label cmac-key --bits 256

# Create test data
docker exec rust-hsm-app bash -c "echo 'API request data' > /app/request.txt"

# Generate CMAC
docker exec rust-hsm-app rust-hsm-cli cmac-sign \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label cmac-key \
  --input /app/request.txt --output /app/request.cmac
```

### Example Output
```
2025-12-13T22:15:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T22:15:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Generating AES-CMAC with key 'cmac-key'
2025-12-13T22:15:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::hmac: CMAC generated successfully (16 bytes)
2025-12-13T22:15:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: CMAC written to /app/request.cmac
```

### Example (Truncated 8-byte CMAC)
```bash
docker exec rust-hsm-app rust-hsm-cli cmac-sign \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label cmac-key \
  --input /app/request.txt --output /app/request-short.cmac \
  --mac-len 8
```

### Example Output
```
2025-12-13T22:16:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Generating AES-CMAC (8 bytes) with key 'cmac-key'
2025-12-13T22:16:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::hmac: CMAC generated successfully (8 bytes)
```

---

## cmac-verify

Verify a CMAC against the original data.

### Syntax
```bash
rust-hsm-cli cmac-verify --key-label <KEY> --input <FILE> --cmac <MAC_FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - CMAC (AES) key to use (required)
- `--input <FILE>` - Original data file (required)
- `--cmac <FILE>` - CMAC file to verify (required)
- `--pin-stdin` - Read PIN from stdin

### Example (Valid CMAC)
```bash
docker exec rust-hsm-app rust-hsm-cli cmac-verify \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label cmac-key \
  --input /app/request.txt --cmac /app/request.cmac
```

### Example Output (Valid)
```
2025-12-13T22:20:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T22:20:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Verifying AES-CMAC with key 'cmac-key'
2025-12-13T22:20:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::hmac: CMAC verification SUCCEEDED
CMAC is valid!
```

### Example (Invalid CMAC)
```bash
# Tamper with data
docker exec rust-hsm-app bash -c "echo 'Tampered API request' > /app/request.txt"

# Try to verify
docker exec rust-hsm-app rust-hsm-cli cmac-verify \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label cmac-key \
  --input /app/request.txt --cmac /app/request.cmac
```

### Example Output (Invalid)
```
2025-12-13T22:21:00.234567Z ERROR rust_hsm_cli::pkcs11::keys::hmac: CMAC verification FAILED
Error: CMAC verification failed - data integrity check failed
```

---

## Notes

### Hash vs HMAC vs CMAC

**Hash (SHA-256):**
- No key required
- Public verification
- Detects accidental corruption
- Cannot detect intentional tampering
- Fast

**HMAC (Hash-based MAC):**
- Requires secret key
- Authenticated integrity
- Detects tampering
- Variable output size (32-64 bytes)
- Based on hash functions

**CMAC (Cipher-based MAC):**
- Requires secret key (AES)
- Authenticated integrity
- Detects tampering
- Fixed 16-byte output (can truncate to 8+ bytes)
- Based on block cipher

### When to Use Each

**Use Hash for:**
- Checksums
- File integrity
- Content addressing
- No authentication needed

**Use HMAC for:**
- API authentication
- Message authentication
- JWT tokens
- Webhook signatures
- Longer MACs preferred

**Use CMAC for:**
- Short message authentication
- Block cipher-based systems
- Standards requiring CMAC
- When 16 bytes or less is sufficient

### HMAC Algorithms

- **SHA-256**: Default, 32 bytes, widely supported
- **SHA-384**: 48 bytes, higher security
- **SHA-512**: 64 bytes, maximum security
- **SHA-224**: 28 bytes, truncated SHA-256
- **SHA-1**: 20 bytes, legacy only (avoid)

### CMAC Truncation

**Full CMAC (16 bytes):**
- Maximum security
- Recommended for most use cases

**Truncated CMAC (8-12 bytes):**
- Bandwidth-constrained systems
- Still secure for most applications
- Minimum: 8 bytes for security

**Do not truncate below 8 bytes** - reduces security significantly.

### API Authentication Example

**Workflow with HMAC:**
```bash
# 1. Generate shared HMAC key
rust-hsm-cli gen-hmac-key --key-label api-key

# 2. Create API request
echo '{"action":"transfer","amount":1000}' > request.json

# 3. Generate HMAC
rust-hsm-cli hmac-sign --key-label api-key --input request.json --output request.sig

# 4. Send request.json + request.sig to server

# 5. Server verifies HMAC
rust-hsm-cli hmac-verify --key-label api-key --input request.json --hmac request.sig
```

### Security Considerations

1. **Key size**: Use at least 256 bits for HMAC/CMAC keys
2. **Algorithm choice**: SHA-256 or SHA-512 for HMAC, AES-256 for CMAC
3. **Key rotation**: Rotate MAC keys periodically
4. **Timing attacks**: HMAC/CMAC verification is constant-time in PKCS#11
5. **Key secrecy**: Never expose HMAC/CMAC keys
