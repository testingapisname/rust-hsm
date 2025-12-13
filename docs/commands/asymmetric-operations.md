# Asymmetric Operations Commands

## sign

Sign data using a private key (RSA or ECDSA).

### Syntax
```bash
rust-hsm-cli sign --key-label <KEY> --input <FILE> --output <SIG_FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Private key to use for signing (required)
- `--input <FILE>` - Input data file to sign (required)
- `--output <FILE>` - Output signature file (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
# Create test data
docker exec rust-hsm-app bash -c "echo 'Hello World' > /app/data.txt"

# Sign with RSA key
docker exec rust-hsm-app rust-hsm-cli sign \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key \
  --input /app/data.txt --output /app/data.sig
```

### Example Output
```
2025-12-13T21:00:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:00:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Signing data with key 'signing-key'
2025-12-13T21:00:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Signature created successfully (256 bytes)
2025-12-13T21:00:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Signature written to /app/data.sig
```

### Mechanisms Used

**RSA keys:**
- Mechanism: `CKM_SHA256_RSA_PKCS` (SHA-256 with RSA PKCS#1 v1.5)
- Signature size: 256 bytes (2048-bit key) or 512 bytes (4096-bit key)

**ECDSA keys:**
- Mechanism: `CKM_ECDSA`
- Data is hashed with SHA-256 before signing
- Signature size: ~70 bytes (P-256) or ~102 bytes (P-384)

---

## verify

Verify a signature using a public key.

### Syntax
```bash
rust-hsm-cli verify --key-label <KEY> --input <FILE> --signature <SIG_FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Public key to use for verification (required)
- `--input <FILE>` - Original data file (required)
- `--signature <FILE>` - Signature file to verify (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli verify \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key \
  --input /app/data.txt --signature /app/data.sig
```

### Example Output (Valid)
```
2025-12-13T21:05:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:05:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Verifying signature with key 'signing-key'
2025-12-13T21:05:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Signature verification SUCCEEDED
Signature is valid!
```

### Example Output (Invalid)
```bash
# Tamper with data
docker exec rust-hsm-app bash -c "echo 'Modified data' > /app/data.txt"

# Try to verify
docker exec rust-hsm-app rust-hsm-cli verify \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key \
  --input /app/data.txt --signature /app/data.sig
```

```
2025-12-13T21:06:00.123456Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Verifying signature with key 'signing-key'
2025-12-13T21:06:00.234567Z ERROR rust_hsm_cli::pkcs11::keys::asymmetric: Signature verification FAILED
Error: Signature verification failed
```

---

## encrypt

Encrypt data using an RSA public key (PKCS#1 v1.5 padding).

### Syntax
```bash
rust-hsm-cli encrypt --key-label <KEY> --input <FILE> --output <ENC_FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - RSA public key to use (required)
- `--input <FILE>` - Input plaintext file (required)
- `--output <FILE>` - Output encrypted file (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
docker exec rust-hsm-app bash -c "echo 'Secret message' > /app/secret.txt"

docker exec rust-hsm-app rust-hsm-cli encrypt \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key \
  --input /app/secret.txt --output /app/secret.enc
```

### Example Output
```
2025-12-13T21:10:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:10:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Encrypting data with public key 'signing-key'
2025-12-13T21:10:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Data encrypted successfully (256 bytes)
```

### Size Limitations

**PKCS#1 v1.5 padding overhead:**
- **2048-bit key**: Max plaintext = 245 bytes
- **4096-bit key**: Max plaintext = 501 bytes

For larger data, use `encrypt-symmetric` with AES-GCM.

---

## decrypt

Decrypt RSA-encrypted data using a private key.

### Syntax
```bash
rust-hsm-cli decrypt --key-label <KEY> --input <ENC_FILE> --output <FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - RSA private key to use (required)
- `--input <FILE>` - Input encrypted file (required)
- `--output <FILE>` - Output plaintext file (required)
- `--pin-stdin` - Read PIN from stdin

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli decrypt \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key \
  --input /app/secret.enc --output /app/secret-decrypted.txt

# Verify decryption
docker exec rust-hsm-app cat /app/secret-decrypted.txt
```

### Example Output
```
2025-12-13T21:15:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:15:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Decrypting data with private key 'signing-key'
2025-12-13T21:15:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::asymmetric: Data decrypted successfully (14 bytes)

Secret message
```

---

## export-pubkey

Export a public key in PEM format for sharing or external verification.

### Syntax
```bash
rust-hsm-cli export-pubkey --key-label <KEY> --output <PEM_FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Key to export (required)
- `--output <FILE>` - Output PEM file (required)
- `--pin-stdin` - Read PIN from stdin

### Example (RSA)
```bash
docker exec rust-hsm-app rust-hsm-cli export-pubkey \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key \
  --output /app/signing-key.pub.pem

# View the exported key
docker exec rust-hsm-app cat /app/signing-key.pub.pem
```

### Example Output (RSA)
```
2025-12-13T21:20:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T21:20:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::export: Exporting public key 'signing-key'
2025-12-13T21:20:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::export: Public key exported to /app/signing-key.pub.pem

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2jQ7Hx5vF4Gp8Yh3KqVr
...
-----END PUBLIC KEY-----
```

### Example (ECDSA)
```bash
docker exec rust-hsm-app rust-hsm-cli export-pubkey \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label ec-key \
  --output /app/ec-key.pub.pem
```

### Example Output (ECDSA)
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5iMqJvS8g9TxPz7yXKhXh3vF2nQY
...
-----END PUBLIC KEY-----
```

### Uses for Exported Keys

- **External verification**: Verify signatures without HSM access
- **Key distribution**: Share public keys securely
- **Integration**: Use with other tools (OpenSSL, web servers)
- **Certificate requests**: Generate CSRs externally

### Verify Exported Key
```bash
# View key details with OpenSSL
docker exec rust-hsm-app openssl rsa -pubin -in /app/signing-key.pub.pem -text -noout

# For ECDSA keys
docker exec rust-hsm-app openssl ec -pubin -in /app/ec-key.pub.pem -text -noout
```

---

## Notes

### Signing Workflow

1. **Generate keypair**: `gen-keypair --key-label my-key`
2. **Sign data**: `sign --key-label my-key --input data.txt --output data.sig`
3. **Verify locally**: `verify --key-label my-key --input data.txt --signature data.sig`
4. **Export public key**: `export-pubkey --key-label my-key --output pubkey.pem`
5. **Distribute**: Share `data.txt`, `data.sig`, and `pubkey.pem`
6. **External verification**: Use OpenSSL or other tools

### RSA vs ECDSA

**RSA Advantages:**
- Widely supported
- Simple mechanism (built-in hashing)
- Can encrypt/decrypt

**ECDSA Advantages:**
- Smaller signatures (~70 bytes vs 256 bytes)
- Faster signing operations
- Equivalent security with smaller keys

**Choose RSA when:**
- Need encryption/decryption
- Maximum compatibility required
- Working with legacy systems

**Choose ECDSA when:**
- Optimizing for performance
- Minimizing signature size
- Modern systems only
