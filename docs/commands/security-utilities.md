# Security & Utility Commands

## audit

Perform security audit of token, detecting weak keys and configuration issues.

### Syntax
```bash
rust-hsm-cli audit --user-pin <PIN> [--label <TOKEN>] [--json]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--pin-stdin` - Read PIN from stdin
- `--json` - Output in JSON format

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli audit \
  --label DEV_TOKEN --user-pin 123456
```

### Example Output
```
=== Security Audit Results ===

CRITICAL Issues (1):
  - RSA-1024 key 'weak-rsa-key' is below minimum secure size (2048 bits recommended)

HIGH Issues (2):
  - Key 'extractable-private-key' is marked extractable (CKA_EXTRACTABLE=true)
  - Private key 'not-sensitive' does not have CKA_SENSITIVE=true

MEDIUM Issues (1):
  - Public key 'imported-key' was imported (CKA_LOCAL=false) - verify source

LOW Issues (0):

Total: 4 issues found

Recommendations:
  - Replace weak RSA keys with 2048-bit or higher
  - Mark private keys as sensitive and non-extractable
  - Regenerate imported keys on the HSM when possible
  - Review extractable keys - only backup/migration keys should be extractable
```

### Example (JSON Output)
```bash
docker exec rust-hsm-app rust-hsm-cli audit \
  --label DEV_TOKEN --user-pin 123456 --json
```

### Example JSON Output
```json
{
  "summary": {
    "total_keys": 8,
    "total_issues": 4,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "issues": [
    {
      "severity": "CRITICAL",
      "category": "weak_key",
      "key_label": "weak-rsa-key",
      "description": "RSA-1024 key is below minimum secure size",
      "recommendation": "Use RSA-2048 or higher"
    },
    {
      "severity": "HIGH",
      "category": "extractable_private_key",
      "key_label": "extractable-private-key",
      "description": "Private key is marked extractable",
      "recommendation": "Mark as non-extractable unless needed for backup"
    }
  ]
}
```

### Audit Checks

**CRITICAL Severity:**
- RSA keys < 2048 bits
- ECDSA keys on weak curves
- Cryptographically broken algorithms

**HIGH Severity:**
- Private keys marked extractable
- Private keys not marked sensitive
- Missing security attributes

**MEDIUM Severity:**
- Imported keys (CKA_LOCAL=false)
- Modifiable private keys
- Weak key usage patterns

**LOW Severity:**
- Informational findings
- Best practice recommendations

---

## benchmark

Performance benchmarking for cryptographic operations.

### Syntax
```bash
rust-hsm-cli benchmark --user-pin <PIN> [--label <TOKEN>] [--key-label <KEY>] [--iterations <N>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--pin-stdin` - Read PIN from stdin
- `--key-label <KEY_LABEL>` - Benchmark specific key (optional, defaults to full suite)
- `--iterations <N>` - Number of iterations per test (default: 100)

### Example (Full Suite)
```bash
docker exec rust-hsm-app bash -c "echo '123456' | rust-hsm-cli benchmark \
  --label DEV_TOKEN --iterations 100 --pin-stdin"
```

### Example Output (Full Suite)
```
=== PKCS#11 Performance Benchmark ===
Token: DEV_TOKEN
Iterations: 100 per operation
Data size: 1024 bytes (where applicable)

Running benchmark suite...

Operation                         Ops/sec   Avg (ms)   P50 (ms)   P95 (ms)   P99 (ms)
─────────────────────────────────────────────────────────────────────────────────────
RSA-2048 Sign                      1304.2       0.77       0.74       0.94       1.19
RSA-2048 Verify                    5234.8       0.19       0.18       0.23       0.31
RSA-4096 Sign                       235.5       4.25       4.27       4.79       5.09
RSA-2048 Encrypt                   4892.1       0.20       0.19       0.25       0.33

ECDSA-P-256 Sign                  12433.0       0.08       0.06       0.14       0.99
ECDSA-P-256 Verify                 6547.9       0.15       0.14       0.19       0.27
ECDSA-P-384 Sign                   1297.2       0.77       0.72       0.96       1.15
ECDSA-P-384 Verify                 1089.3       0.92       0.87       1.12       1.45

AES-256-GCM Encrypt (1KB)         28240.4       0.04       0.02       0.05       0.29
AES-256-GCM Decrypt (1KB)         29154.3       0.03       0.02       0.04       0.25

SHA-256 Hash (1KB)               384457.2       0.00       0.00       0.00       0.06
SHA-384 Hash (1KB)               298745.1       0.00       0.00       0.01       0.07
SHA-512 Hash (1KB)               301234.5       0.00       0.00       0.01       0.07

HMAC-SHA256                       45678.3       0.02       0.02       0.03       0.11
AES-CMAC                          52341.2       0.02       0.01       0.02       0.09

Random 32 bytes                  189234.7       0.01       0.00       0.01       0.05

Benchmark completed successfully
```

### Example (Specific Key)
```bash
# Benchmark a specific application key
docker exec rust-hsm-app bash -c "echo '123456' | rust-hsm-cli benchmark \
  --label DEV_TOKEN --key-label my-app-key --iterations 100 --pin-stdin"
```

### Example Output (Specific Key - RSA)
```
=== PKCS#11 Performance Benchmark ===
Token: DEV_TOKEN
Key: my-app-key (RSA-2048)
Iterations: 100 per operation

Operation                         Ops/sec   Avg (ms)   P50 (ms)   P95 (ms)   P99 (ms)
─────────────────────────────────────────────────────────────────────────────────────
RSA-2048 Sign                      1298.5       0.77       0.75       0.93       1.21
RSA-2048 Verify                    5187.2       0.19       0.18       0.24       0.32
RSA-2048 Encrypt                   4831.6       0.21       0.20       0.26       0.34

Benchmark for key 'my-app-key' completed
```

### Interpretation

**Operations per second (Ops/sec):**
- Higher is better
- Shows throughput

**Latency (milliseconds):**
- Lower is better
- P50 (median): Typical performance
- P95: 95% of operations complete within this time
- P99: 99% of operations complete within this time

---

## gen-csr

Generate X.509 Certificate Signing Request from a keypair.

### Syntax
```bash
rust-hsm-cli gen-csr --key-label <KEY> --subject <DN> --output <CSR_FILE> \
  --user-pin <PIN> [--label <TOKEN>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Keypair to use (required)
- `--subject <DN>` - Subject Distinguished Name (required)
- `--output <FILE>` - Output CSR file (required)
- `--pin-stdin` - Read PIN from stdin

### Subject DN Format
```
"CN=<CommonName>,O=<Organization>,C=<Country>"
```

Additional fields: `OU` (Organizational Unit), `L` (Locality), `ST` (State)

### Example (RSA)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-csr \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key \
  --subject "CN=test.example.com,O=TestOrg,C=US" \
  --output /app/test.csr
```

### Example Output
```
2025-12-13T22:40:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T22:40:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::csr: Generating CSR for key 'signing-key'
2025-12-13T22:40:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::csr: CSR generated successfully
2025-12-13T22:40:00.245678Z  INFO rust_hsm_cli::pkcs11::keys::csr: CSR written to /app/test.csr
```

### Verify CSR
```bash
# View CSR details with OpenSSL
docker exec rust-hsm-app openssl req -in /app/test.csr -noout -text
```

### Example CSR Details
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C = US, O = TestOrg, CN = test.example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:da:34:3b:1f:1e:6f:17:81:a9:f1:88:77:2a:a5
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        8f:2a:b3:c4:d5:e6:f7:08:19:2a:3b:4c:5d:6e:7f:80
        ...

Signature ok
```

### Example (ECDSA)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-csr \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label ec-key \
  --subject "CN=api.example.com,O=MyCompany,OU=Engineering,C=US" \
  --output /app/api.csr
```

### Submit to CA
```bash
# Copy CSR out of container
docker cp rust-hsm-app:/app/test.csr ./test.csr

# Submit to Certificate Authority (CA)
# CA will return signed certificate

# Import certificate back to HSM (future feature)
```

---

## gen-random

Generate cryptographically secure random bytes from HSM's RNG.

### Syntax
```bash
rust-hsm-cli gen-random --bytes <N> [--output <FILE>] [--hex]
```

### Flags
- `--bytes <N>` - Number of random bytes to generate (required)
- `--output <FILE>` - Output file (optional, prints to stdout in hex if omitted)
- `--hex` - Output as hexadecimal text file instead of binary

### Example (Stdout, hex)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-random --bytes 32
```

### Example Output
```
a7f3c29d8e5b1a4f6c8d2e9f0b3a5c7d9e1f8a2b4c6d8e0f1a3b5c7d9e1f2a4b
```

### Example (Binary File)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-random --bytes 64 --output /app/random.bin
```

### Example Output
```
2025-12-13T22:50:00.123456Z  INFO rust_hsm_cli::pkcs11::keys::hash: Generating 64 random bytes
2025-12-13T22:50:00.134567Z  INFO rust_hsm_cli::pkcs11::keys::hash: Random data generated successfully
2025-12-13T22:50:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hash: Random data written to /app/random.bin
```

### Example (Hex File)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-random --bytes 32 --output /app/random.hex --hex

docker exec rust-hsm-app cat /app/random.hex
```

### Example Output
```
3f8a2b9c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a
```

### Use Cases

**Generate AES Key Material:**
```bash
# Generate 256 bits (32 bytes) of randomness
rust-hsm-cli gen-random --bytes 32 --output key-material.bin
```

**Generate IV for AES:**
```bash
# Generate 96-bit (12 bytes) IV for AES-GCM
rust-hsm-cli gen-random --bytes 12 --output iv.bin
```

**Generate Nonce:**
```bash
# Generate nonce for authentication protocols
rust-hsm-cli gen-random --bytes 16 --hex
```

**Generate Salt:**
```bash
# Generate salt for password hashing
rust-hsm-cli gen-random --bytes 16 --output salt.bin
```

**Generate Token:**
```bash
# Generate API token
rust-hsm-cli gen-random --bytes 32 --hex > api-token.txt
```

---

## Notes

### Security Audit Best Practices

**Run audits:**
- After initial setup
- After key generation
- Before production deployment
- Periodically (monthly/quarterly)
- After configuration changes

**Address findings by severity:**
1. CRITICAL: Fix immediately
2. HIGH: Fix within 1 week
3. MEDIUM: Fix within 1 month
4. LOW: Fix when convenient

### Benchmark Considerations

**Factors affecting performance:**
- Hardware: CPU speed, cores
- SoftHSM vs Hardware HSM
- Key sizes
- Data sizes
- Concurrent operations

**SoftHSM is slower than real HSMs** - these benchmarks show software performance only.

**Interpreting results:**
- RSA-4096 is ~5x slower than RSA-2048
- ECDSA-P256 is ~10x faster than RSA-2048 for signing
- Hashing is extremely fast (no private key operations)
- Symmetric operations (AES) are much faster than asymmetric

### CSR Workflow

1. **Generate keypair on HSM**
   ```bash
   rust-hsm-cli gen-keypair --key-label server-key
   ```

2. **Generate CSR**
   ```bash
   rust-hsm-cli gen-csr --key-label server-key --subject "CN=server.example.com" --output server.csr
   ```

3. **Submit to CA**
   - Public CA (Let's Encrypt, DigiCert)
   - Internal CA (OpenSSL, Microsoft CA)

4. **Receive certificate**
   - CA returns signed certificate (server.crt)

5. **Use certificate** (future feature: import to HSM)

### Random Number Generation

**Quality:**
- Uses HSM's hardware RNG (if available) or PRNG
- Cryptographically secure
- Suitable for keys, IVs, nonces, salts, tokens

**Do not use system `/dev/urandom` equivalents** - always use HSM RNG for cryptographic randomness.

**Entropy:**
- HSM RNG provides high-quality entropy
- No need to worry about entropy exhaustion
- Safe for concurrent requests
