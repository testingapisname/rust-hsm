# Implementing CKM_AES_CMAC_GENERAL

## Overview

`CKM_AES_CMAC_GENERAL` is a PKCS#11 mechanism for generating Message Authentication Codes (MACs) using AES in CMAC mode per NIST SP 800-38B. The "GENERAL" variant allows specifying the MAC output length (1-16 bytes for AES block size).

## Current Limitation

The `cryptoki` Rust crate (v0.6) does not include `Mechanism::AesCmac` or `Mechanism::AesCmacGeneral` variants. To implement this, you have several options:

## Option 1: Upgrade cryptoki (Recommended)

Check if newer versions of `cryptoki` support AES-CMAC:

```toml
[dependencies]
cryptoki = "0.7"  # Or latest version
```

Then use:
```rust
let mechanism = Mechanism::AesCmacGeneral(mac_len);
let mac = session.sign(&mechanism, key_handle, &data)?;
```

## Option 2: Use Raw PKCS#11 Mechanism Type

If `cryptoki` doesn't have the enum variant, use the raw mechanism code:

```rust
use cryptoki::mechanism::{Mechanism, MechanismType};

// CKM_AES_CMAC_GENERAL = 0x0000108A
const CKM_AES_CMAC_GENERAL: u64 = 0x0000108A;

// Create raw mechanism with parameter
let mechanism_type = MechanismType::from(CKM_AES_CMAC_GENERAL);
// Note: You'll need to construct the parameter bytes manually
// For AES_CMAC_GENERAL, the parameter is the MAC length as CK_ULONG
```

## Option 3: Use HMAC-SHA256 Instead (Current Workaround)

HMAC is widely supported and provides similar security properties:

```rust
// Generate a generic secret key (256 bits)
let mechanism = Mechanism::GenericSecretKeyGen;
let key_template = vec![
    Attribute::Token(true),
    Attribute::Label(b"hmac-key".to_vec()),
    Attribute::Sign(true),
    Attribute::Verify(true),
    Attribute::ValueLen(32.into()), // 32 bytes = 256 bits
];
let key = session.generate_key(&mechanism, &key_template)?;

// Generate MAC
let mechanism = Mechanism::Sha256Hmac;
let mac = session.sign(&mechanism, key, &data)?;

// Verify MAC
session.verify(&mechanism, key, &data, &mac)?;
```

### Key Differences:

| Feature | AES-CMAC | HMAC-SHA256 |
|---------|----------|-------------|
| Algorithm | Block cipher (AES) | Hash function (SHA-256) |
| Key Type | AES key | Generic secret key |
| Output Size | 16 bytes (AES block) | 32 bytes (SHA-256 digest) |
| Truncation | CKM_AES_CMAC_GENERAL | Manual truncation |
| Standard | NIST SP 800-38B | FIPS 198-1 |
| Use Case | Block cipher based systems | Hash-based systems |

## Complete Implementation Example

See [mac.rs.example](./mac.rs.example) for a complete implementation using HMAC-SHA256 as a fallback.

### CLI Commands

```bash
# Generate MAC key (256-bit generic secret)
rust-hsm-cli gen-symmetric-key \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label mac-key --bits 256

# Generate MAC (32 bytes for HMAC-SHA256, or truncate to desired length)
rust-hsm-cli generate-mac \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label mac-key \
  --input /app/data.txt \
  --output /app/data.mac \
  --mac-len 32

# Verify MAC  
rust-hsm-cli verify-mac \
  --label DEV_TOKEN --user-pin 123456 \
  --key-label mac-key \
  --input /app/data.txt \
  --mac /app/data.mac \
  --mac-len 32
```

## Testing

```bash
# Generate test data
echo "Test message for MAC" > /app/test.txt

# Generate MAC
rust-hsm-cli generate-mac \
  --label TEST --user-pin 123456 \
  --key-label mac-key \
  --input /app/test.txt \
  --output /app/test.mac \
  --mac-len 16

# Verify it works
rust-hsm-cli verify-mac \
  --label TEST --user-pin 123456 \
  --key-label mac-key \
  --input /app/test.txt \
  --mac /app/test.mac \
  --mac-len 16

# Test with tampered data (should fail)
echo "Tampered message" > /app/tampered.txt
rust-hsm-cli verify-mac \
  --label TEST --user-pin 123456 \
  --key-label mac-key \
  --input /app/tampered.txt \
  --mac /app/test.mac \
  --mac-len 16
# Expected: "MAC verification failed"
```

## Production Considerations

1. **Key Generation**: For CMAC, use `CKM_AES_KEY_GEN`. For HMAC, use `CKM_GENERIC_SECRET_KEY_GEN`.

2. **Key Attributes**: Ensure keys have `CKA_SIGN=true` and `CKA_VERIFY=true`.

3. **MAC Length**: 
   - AES-CMAC: 4-16 bytes (truncate from 16-byte block)
   - HMAC-SHA256: 1-32 bytes (truncate from 32-byte digest)
   - Never use less than 8 bytes in production

4. **Performance**: AES-CMAC is generally faster than HMAC for short messages.

5. **Compatibility**: HMAC is more widely supported across HSM vendors.

## References

- [NIST SP 800-38B](https://csrc.nist.gov/publications/detail/sp/800-38b/final) - AES-CMAC Specification
- [RFC 4493](https://tools.ietf.org/html/rfc4493) - The AES-CMAC Algorithm
- [FIPS 198-1](https://csrc.nist.gov/publications/detail/fips/198/1/final) - The Keyed-Hash Message Authentication Code (HMAC)
- [PKCS#11 v2.40](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html) - Mechanism List

## Why This Matters

MACs provide data integrity and authentication using symmetric keys:
- **Digital Signatures**: Asymmetric (RSA/ECDSA) - public verification
- **MACs**: Symmetric (AES-CMAC/HMAC) - shared secret verification

Use MACs when:
- Both parties share a secret key
- You need faster operations than digital signatures
- You don't need non-repudiation
- Examples: API authentication, session tokens, internal message validation
