# Key Generation Commands

## gen-keypair

Generate RSA or ECDSA asymmetric keypair on the token.

### Syntax
```bash
rust-hsm-cli gen-keypair --key-label <LABEL> --user-pin <PIN> \
  [--label <TOKEN>] [--key-type <TYPE>] [--bits <SIZE>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Label for the new keypair (required)
- `--pin-stdin` - Read PIN from stdin
- `--key-type <TYPE>` - Key type: `rsa`, `p256`, `p384` (default: `rsa`)
- `--bits <SIZE>` - RSA key size in bits: `2048`, `4096` (default: `2048`, ignored for ECDSA)

### Example (RSA 2048-bit)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label signing-key --key-type rsa --bits 2048
```

### Example Output
```
2025-12-13T20:30:15.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T20:30:15.145678Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Generating RSA-2048 keypair with label 'signing-key'
2025-12-13T20:30:15.567890Z  INFO rust_hsm_cli::pkcs11::keys::keypair: RSA-2048 keypair 'signing-key' generated successfully
```

### Example (ECDSA P-256)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label ec-key --key-type p256
```

### Example Output
```
2025-12-13T20:31:30.123456Z  INFO rust_hsm_cli::pkcs11::keys::keypair: Generating ECDSA P-256 keypair with label 'ec-key'
2025-12-13T20:31:30.234567Z  INFO rust_hsm_cli::pkcs11::keys::keypair: ECDSA P-256 keypair 'ec-key' generated successfully
```

### Example (ECDSA P-384)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label ec-384-key --key-type p384
```

### Supported Key Types
- `rsa` - RSA keypair (2048 or 4096 bits)
- `p256` - ECDSA with NIST P-256 curve (secp256r1)
- `p384` - ECDSA with NIST P-384 curve (secp384r1)

---

## gen-symmetric-key

Generate symmetric AES key for encryption/decryption.

### Syntax
```bash
rust-hsm-cli gen-symmetric-key --key-label <LABEL> --user-pin <PIN> \
  [--label <TOKEN>] [--bits <SIZE>] [--extractable]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Label for the new key (required)
- `--pin-stdin` - Read PIN from stdin
- `--bits <SIZE>` - Key size: `128`, `192`, `256` (default: `256`)
- `--extractable` - Allow key to be wrapped/exported (default: non-extractable)

### Example (AES-256)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label aes-key --bits 256
```

### Example Output
```
2025-12-13T20:35:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T20:35:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Generating AES-256 key with label 'aes-key'
2025-12-13T20:35:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: AES-256 key 'aes-key' generated successfully
```

### Example (Extractable Key for Wrapping)
```bash
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label backup-key --bits 256 --extractable
```

### Example Output
```
2025-12-13T20:36:00.123456Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: Generating AES-256 key with label 'backup-key' (extractable)
2025-12-13T20:36:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::symmetric: AES-256 key 'backup-key' generated successfully
```

---

## gen-hmac-key

Generate generic secret key for HMAC operations.

### Syntax
```bash
rust-hsm-cli gen-hmac-key --key-label <LABEL> --user-pin <PIN> \
  [--label <TOKEN>] [--bits <SIZE>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Label for the new key (required)
- `--pin-stdin` - Read PIN from stdin
- `--bits <SIZE>` - Key size in bits: `128`, `192`, `256`, `384`, `512` (default: `256`)

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli gen-hmac-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label hmac-key --bits 256
```

### Example Output
```
2025-12-13T20:40:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T20:40:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Generating 256-bit HMAC key with label 'hmac-key'
2025-12-13T20:40:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::hmac: HMAC key 'hmac-key' generated successfully
```

---

## gen-cmac-key

Generate AES key for CMAC (Cipher-based MAC) operations.

### Syntax
```bash
rust-hsm-cli gen-cmac-key --key-label <LABEL> --user-pin <PIN> \
  [--label <TOKEN>] [--bits <SIZE>]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Label for the new key (required)
- `--pin-stdin` - Read PIN from stdin
- `--bits <SIZE>` - AES key size: `128`, `192`, `256` (default: `256`)

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli gen-cmac-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label cmac-key --bits 256
```

### Example Output
```
2025-12-13T20:45:00.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T20:45:00.145678Z  INFO rust_hsm_cli::pkcs11::keys::hmac: Generating AES-256 CMAC key with label 'cmac-key'
2025-12-13T20:45:00.234567Z  INFO rust_hsm_cli::pkcs11::keys::hmac: CMAC key 'cmac-key' generated successfully
```

---

## Notes

### Key Attributes

**Non-extractable keys (default for symmetric/private keys):**
- `CKA_SENSITIVE: true`
- `CKA_EXTRACTABLE: false`
- `CKA_ALWAYS_SENSITIVE: true`
- `CKA_NEVER_EXTRACTABLE: true`

**Extractable keys (with --extractable flag):**
- `CKA_EXTRACTABLE: true`
- Can be wrapped for backup/migration
- Required for `wrap-key` operation

### Key Usage Flags

**RSA keypairs:**
- Public key: `CKA_ENCRYPT`, `CKA_VERIFY`, `CKA_WRAP`
- Private key: `CKA_SIGN`, `CKA_DECRYPT`, `CKA_UNWRAP`

**ECDSA keypairs:**
- Public key: `CKA_VERIFY`, `CKA_ENCRYPT`
- Private key: `CKA_SIGN`, `CKA_DECRYPT`

**AES keys:**
- `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP`, `CKA_UNWRAP`

**HMAC/CMAC keys:**
- `CKA_SIGN`, `CKA_VERIFY`

### RSA Key Sizes

- **2048-bit**: Balances security and performance, widely compatible
- **4096-bit**: Higher security, slower operations, larger signatures

### ECDSA Curves

- **P-256**: 256-bit curve, equivalent to ~3072-bit RSA, faster than RSA
- **P-384**: 384-bit curve, equivalent to ~7680-bit RSA, highest security
