# Comprehensive HSM Troubleshooting Guide

A complete guide to diagnosing and resolving common HSM issues using rust-hsm troubleshooting commands.

---

## Table of Contents

- [Common Troubleshooting Scenarios](#common-troubleshooting-scenarios)
- [Systematic Troubleshooting Workflow](#systematic-troubleshooting-workflow)
- [Error Categories](#error-categories)
- [Real-World Use Cases](#real-world-use-cases)
- [Troubleshooting Command Reference](#troubleshooting-command-reference)
- [Advanced Diagnostic Techniques](#advanced-diagnostic-techniques)

---

## Common Troubleshooting Scenarios

### 1. Token & Slot Issues

#### Scenario: "Token not found"
**Symptoms**: Commands fail with `CKR_TOKEN_NOT_PRESENT` or `CKR_SLOT_ID_INVALID`

**Diagnosis**:
```bash
# Step 1: List all available slots
docker exec rust-hsm-app rust-hsm-cli list-slots

# Step 2: Get HSM module info
docker exec rust-hsm-app rust-hsm-cli info

# Step 3: Explain the error
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_TOKEN_NOT_PRESENT
```

**Common Causes**:
- Token label typo
- Token not initialized
- HSM module not loaded
- Wrong slot number

**Solutions**:
```bash
# Verify token exists
docker exec rust-hsm-app rust-hsm-cli list-slots | grep "Label"

# Initialize token if missing
docker exec rust-hsm-app rust-hsm-cli init-token \
  --label CORRECT_TOKEN --so-pin 12345678
```

---

#### Scenario: "Too many sessions"
**Symptoms**: `CKR_SESSION_COUNT` error

**Diagnosis**:
```bash
# Check current session count
docker exec rust-hsm-app rust-hsm-cli list-slots --detailed

# Explain the error
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_SESSION_COUNT
```

**Solution**:
```bash
# Restart application to close stale sessions
# Or increase max sessions in HSM configuration
# For SoftHSM2: Edit softhsm2.conf
```

---

### 2. PIN & Authentication Issues

#### Scenario: "PIN incorrect"
**Symptoms**: `CKR_PIN_INCORRECT` on login

**Diagnosis**:
```bash
# Get detailed error explanation
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_PIN_INCORRECT --context login

# Check token status
docker exec rust-hsm-app rust-hsm-cli list-slots --detailed
```

**Common Mistakes**:
- Using user PIN instead of SO PIN (or vice versa)
- PIN format incorrect (length, characters)
- PIN already set but forgotten

**Solutions**:
```bash
# For SO PIN issues: Reinitialize token (WARNING: destroys all data)
docker exec rust-hsm-app rust-hsm-cli init-token --label TOKEN --so-pin NEW_PIN

# For user PIN: Reset with SO PIN
docker exec rust-hsm-app rust-hsm-cli init-pin --label TOKEN --so-pin SO_PIN --user-pin NEW_USER_PIN
```

---

#### Scenario: "PIN locked after multiple failures"
**Symptoms**: `CKR_PIN_LOCKED`

**Diagnosis**:
```bash
# Explain the error
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_PIN_LOCKED

# Check token info for attempt counters
docker exec rust-hsm-app rust-hsm-cli list-slots --detailed
```

**Solution**:
```bash
# Reset user PIN with SO PIN
docker exec rust-hsm-app rust-hsm-cli init-pin \
  --label TOKEN --so-pin SO_PIN --user-pin NEW_PIN

# If SO PIN is also locked: Token must be reinitialized (data loss!)
```

---

### 3. Key Management Issues

#### Scenario: "Key not found or handle invalid"
**Symptoms**: `CKR_KEY_HANDLE_INVALID` or `CKR_OBJECT_HANDLE_INVALID`

**Diagnosis**:
```bash
# Step 1: Search for the key
docker exec rust-hsm-app rust-hsm-cli find-key \
  --label TOKEN --user-pin PIN \
  --key-label suspected-name --show-similar

# Step 2: List all objects
docker exec rust-hsm-app rust-hsm-cli list-objects \
  --label TOKEN --user-pin PIN --detailed

# Step 3: Explain the error
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_KEY_HANDLE_INVALID --context sign
```

**Common Causes**:
- Key label typo
- Key was deleted
- Session expired
- Wrong key type (public vs private)

**Solutions**:
```bash
# Find similar keys with fuzzy matching
docker exec rust-hsm-app rust-hsm-cli find-key \
  --label TOKEN --user-pin PIN \
  --key-label "prod-signing" --show-similar

# If key doesn't exist, generate it
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label TOKEN --user-pin PIN \
  --key-label correct-name --key-type rsa --bits 2048
```

---

#### Scenario: "Key exists but operation fails"
**Symptoms**: Operation succeeds with one key but fails with another

**Diagnosis**:
```bash
# Compare two keys to see differences
docker exec rust-hsm-app rust-hsm-cli diff-keys \
  --label TOKEN --user-pin PIN \
  --key1-label working-key \
  --key2-label failing-key

# Inspect failing key attributes
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label TOKEN --user-pin PIN \
  --key-label failing-key
```

**Common Issues Found**:
- Missing CKA_SIGN/CKA_VERIFY/CKA_ENCRYPT/CKA_DECRYPT flags
- CKA_EXTRACTABLE=false prevents wrapping
- CKA_SENSITIVE=true affects key export
- Wrong key type for operation (RSA vs ECDSA)

**Solutions**:
```bash
# If attributes can't be fixed, regenerate key with correct flags
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label TOKEN --user-pin PIN \
  --key-label new-correct-key \
  --key-type rsa --bits 2048

# For symmetric keys that need wrapping
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label TOKEN --user-pin PIN \
  --key-label extractable-key \
  --bits 256 --extractable
```

---

### 4. Cryptographic Operation Issues

#### Scenario: "Signature verification fails"
**Symptoms**: `CKR_SIGNATURE_INVALID` or verify returns false

**Diagnosis**:
```bash
# Step 1: Explain the error
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_SIGNATURE_INVALID --context verify

# Step 2: Check public key attributes
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label TOKEN --user-pin PIN \
  --key-label pubkey

# Step 3: Verify key fingerprint matches
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label TOKEN --user-pin PIN \
  --key-label pubkey | grep "Fingerprint"
```

**Common Causes**:
- Wrong public key used
- Data modified after signing
- Incorrect hash algorithm
- Wrong signature format

**Solutions**:
```bash
# Test with known good data
echo "test data" > /app/test.txt
docker exec rust-hsm-app rust-hsm-cli sign \
  --label TOKEN --user-pin PIN \
  --key-label privkey \
  --input /app/test.txt --output /app/test.sig

docker exec rust-hsm-app rust-hsm-cli verify \
  --label TOKEN --user-pin PIN \
  --key-label pubkey \
  --input /app/test.txt --signature /app/test.sig
```

---

#### Scenario: "Encryption/Decryption fails"
**Symptoms**: `CKR_DATA_LEN_RANGE`, `CKR_DATA_INVALID`, or `CKR_ENCRYPTED_DATA_INVALID`

**Diagnosis**:
```bash
# Check error meaning
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_DATA_LEN_RANGE --context encrypt

# Inspect key to verify it's correct type
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label TOKEN --user-pin PIN \
  --key-label encrypt-key
```

**Common Causes**:
- Data too large for RSA key (max 245 bytes for RSA-2048 with PKCS#1 padding)
- Wrong padding mode
- Corrupted encrypted data
- Using wrong key (encrypt with private, decrypt with public)

**Solutions**:
```bash
# For large data: Use AES-GCM instead of RSA
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label TOKEN --user-pin PIN \
  --key-label aes-key --bits 256

docker exec rust-hsm-app rust-hsm-cli encrypt-symmetric \
  --label TOKEN --user-pin PIN \
  --key-label aes-key \
  --input /app/large-file.txt --output /app/encrypted.bin

# For RSA: Split data or use hybrid encryption
```

---

#### Scenario: "Key wrapping fails"
**Symptoms**: `CKR_KEY_UNEXTRACTABLE` or `CKR_WRAPPING_KEY_HANDLE_INVALID`

**Diagnosis**:
```bash
# Explain wrapping error
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_KEY_UNEXTRACTABLE --context wrap

# Check target key attributes
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label TOKEN --user-pin PIN \
  --key-label target-key | grep "EXTRACTABLE"

# Check wrapping key attributes  
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label TOKEN --user-pin PIN \
  --key-label wrap-key | grep "WRAP"
```

**Requirements for Wrapping**:
- Target key: `CKA_EXTRACTABLE=true`
- Wrapping key: `CKA_WRAP=true`
- Both keys accessible in session

**Solutions**:
```bash
# Generate extractable target key
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label TOKEN --user-pin PIN \
  --key-label target --bits 256 --extractable

# Generate wrapping key (KEK)
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label TOKEN --user-pin PIN \
  --key-label kek --bits 256

# Now wrap it
docker exec rust-hsm-app rust-hsm-cli wrap-key \
  --label TOKEN --user-pin PIN \
  --key-label target \
  --wrapping-key-label kek \
  --output /app/wrapped.bin
```

---

### 5. Mechanism & Algorithm Issues

#### Scenario: "Mechanism not supported"
**Symptoms**: `CKR_MECHANISM_INVALID` or `CKR_MECHANISM_PARAM_INVALID`

**Diagnosis**:
```bash
# List all supported mechanisms
docker exec rust-hsm-app rust-hsm-cli list-mechanisms --detailed

# Check specific mechanism
docker exec rust-hsm-app rust-hsm-cli list-mechanisms --detailed | grep -i "AES_GCM"

# Explain the error
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_MECHANISM_INVALID --context encrypt
```

**Common Issues**:
- Algorithm not supported by HSM
- Wrong parameters for mechanism
- Mechanism doesn't support operation (e.g., CKM_SHA256 can't sign)

**Solutions**:
```bash
# Use alternative mechanism
# Instead of AES-CTR, use AES-GCM
# Instead of RSA-OAEP, use RSA-PKCS

# Check mechanism capabilities
docker exec rust-hsm-app rust-hsm-cli list-mechanisms --detailed | \
  grep -A 10 "CKM_RSA_PKCS"
```

---

### 6. Performance & Resource Issues

#### Scenario: "Operations timing out"
**Symptoms**: Long delays or timeouts

**Diagnosis**:
```bash
# Run benchmarks to measure performance
docker exec rust-hsm-app rust-hsm-cli benchmark \
  --label TOKEN --user-pin PIN \
  --iterations 100

# Check if HSM is overloaded
docker exec rust-hsm-app rust-hsm-cli list-slots --detailed
```

**Common Causes**:
- Too many concurrent operations
- Large key sizes (RSA-4096 vs RSA-2048)
- Network latency (remote HSM)
- HSM hardware limitations

**Solutions**:
```bash
# Use smaller key sizes if acceptable
# RSA-2048 instead of RSA-4096
# P-256 instead of P-384

# Reduce concurrent operations
# Implement connection pooling
# Cache session handles
```

---

### 7. Data Format Issues

#### Scenario: "Invalid data format"
**Symptoms**: `CKR_DATA_INVALID`, parsing errors

**Diagnosis**:
```bash
# Check file size and format
ls -lh /app/problem-file.bin

# Verify file is not corrupted
file /app/problem-file.bin

# Check if data matches expected format
hexdump -C /app/problem-file.bin | head -20
```

**Common Issues**:
- Wrong encoding (PEM vs DER)
- Missing IV for symmetric encryption
- Corrupted file
- Endianness issues

**Solutions**:
```bash
# Export public key in correct format
docker exec rust-hsm-app rust-hsm-cli export-pubkey \
  --label TOKEN --user-pin PIN \
  --key-label mykey --output /app/key.pem

# Verify PEM format
docker exec rust-hsm-app cat /app/key.pem
# Should start with -----BEGIN PUBLIC KEY-----
```

---

## Systematic Troubleshooting Workflow

Use this workflow for any HSM issue:

### Phase 1: Identify the Error

```bash
# 1. Run the failing command and capture error
docker exec rust-hsm-app rust-hsm-cli <command> 2>&1 | tee error.log

# 2. Extract error code
grep "CKR_" error.log

# 3. Explain the error
docker exec rust-hsm-app rust-hsm-cli explain-error <ERROR_CODE> --context <operation>
```

### Phase 2: Verify Environment

```bash
# 1. Check HSM connectivity
docker exec rust-hsm-app rust-hsm-cli info

# 2. Verify token is accessible
docker exec rust-hsm-app rust-hsm-cli list-slots

# 3. Check authentication
docker exec rust-hsm-app rust-hsm-cli list-objects --label TOKEN --user-pin PIN
```

### Phase 3: Inspect Objects

```bash
# 1. Search for the key
docker exec rust-hsm-app rust-hsm-cli find-key \
  --label TOKEN --user-pin PIN \
  --key-label <name> --show-similar

# 2. Inspect key attributes
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label TOKEN --user-pin PIN \
  --key-label <name>

# 3. Compare with working key if available
docker exec rust-hsm-app rust-hsm-cli diff-keys \
  --label TOKEN --user-pin PIN \
  --key1-label working --key2-label failing
```

### Phase 4: Test Incrementally

```bash
# 1. Test with minimal data
echo "test" > /app/minimal.txt

# 2. Test operation step-by-step
# For sign/verify:
docker exec rust-hsm-app rust-hsm-cli sign \
  --label TOKEN --user-pin PIN --key-label key \
  --input /app/minimal.txt --output /app/minimal.sig

docker exec rust-hsm-app rust-hsm-cli verify \
  --label TOKEN --user-pin PIN --key-label key \
  --input /app/minimal.txt --signature /app/minimal.sig

# 3. Gradually increase complexity
```

### Phase 5: Document & Fix

```bash
# 1. Document the root cause
echo "Issue: <description>" >> troubleshooting.log
echo "Cause: <root cause>" >> troubleshooting.log
echo "Solution: <fix>" >> troubleshooting.log

# 2. Implement fix
# <run commands to fix>

# 3. Verify fix works
# <retest original operation>

# 4. Update documentation/runbooks
```

---

## Error Categories

### Authentication Errors
- `CKR_PIN_INCORRECT` - Wrong PIN
- `CKR_PIN_LOCKED` - Too many failed attempts
- `CKR_PIN_EXPIRED` - PIN needs rotation
- `CKR_USER_NOT_LOGGED_IN` - Must login first
- `CKR_USER_ALREADY_LOGGED_IN` - Already authenticated

### Object Errors
- `CKR_KEY_HANDLE_INVALID` - Key doesn't exist or session expired
- `CKR_OBJECT_HANDLE_INVALID` - Object not found
- `CKR_KEY_UNEXTRACTABLE` - Can't wrap/export key
- `CKR_KEY_FUNCTION_NOT_PERMITTED` - Missing attribute flags

### Operation Errors
- `CKR_OPERATION_NOT_INITIALIZED` - Must call init function first
- `CKR_OPERATION_ACTIVE` - Previous operation not finalized
- `CKR_MECHANISM_INVALID` - Algorithm not supported
- `CKR_FUNCTION_FAILED` - General operation failure

### Data Errors
- `CKR_DATA_INVALID` - Malformed input data
- `CKR_DATA_LEN_RANGE` - Data size incorrect
- `CKR_SIGNATURE_INVALID` - Verification failed
- `CKR_ENCRYPTED_DATA_INVALID` - Can't decrypt

### Resource Errors
- `CKR_HOST_MEMORY` - Out of memory
- `CKR_DEVICE_MEMORY` - HSM out of storage
- `CKR_SESSION_COUNT` - Too many open sessions
- `CKR_DEVICE_ERROR` - Hardware failure

---

## Real-World Use Cases

### Use Case 1: Key Rotation Troubleshooting

**Scenario**: Rotating production signing keys

```bash
# 1. Verify old key exists and works
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label PROD --user-pin *** --key-label old-signing-key

# 2. Generate new key with same attributes
# Use diff-keys to ensure attributes match
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --label PROD --user-pin *** \
  --key-label new-signing-key --key-type rsa --bits 2048

# 3. Compare keys to ensure compatibility
docker exec rust-hsm-app rust-hsm-cli diff-keys \
  --label PROD --user-pin *** \
  --key1-label old-signing-key \
  --key2-label new-signing-key

# 4. Test new key before cutover
docker exec rust-hsm-app rust-hsm-cli sign \
  --label PROD --user-pin *** --key-label new-signing-key \
  --input /app/test.txt --output /app/test.sig

# 5. Export old key for backup (if extractable)
docker exec rust-hsm-app rust-hsm-cli wrap-key \
  --label PROD --user-pin *** --key-label old-signing-key \
  --wrapping-key-label backup-kek --output /backup/old-key.wrapped

# 6. Verify backup
docker exec rust-hsm-app ls -lh /backup/old-key.wrapped
```

### Use Case 2: Debugging Production Signature Failures

**Scenario**: Signatures suddenly failing verification in production

```bash
# 1. Capture exact error
# <error from logs: CKR_SIGNATURE_INVALID>

# 2. Explain error with context
docker exec rust-hsm-app rust-hsm-cli explain-error \
  CKR_SIGNATURE_INVALID --context verify

# 3. Verify key hasn't changed
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label PROD --user-pin *** --key-label signing-key | \
  grep "Fingerprint"
# Compare with documented fingerprint

# 4. Test with known good data
docker exec rust-hsm-app rust-hsm-cli verify \
  --label PROD --user-pin *** --key-label signing-key \
  --input /app/known-good.txt --signature /app/known-good.sig

# 5. If known-good works, issue is with new data/signatures
# If known-good fails, key or HSM configuration changed
```

### Use Case 3: Migrating Keys Between HSMs

**Scenario**: Moving keys from dev to prod HSM

```bash
# Source HSM (dev):
# 1. Verify key is extractable
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label DEV --user-pin *** --key-label app-key | \
  grep "EXTRACTABLE"

# 2. Wrap key for migration
docker exec rust-hsm-app rust-hsm-cli wrap-key \
  --label DEV --user-pin *** --key-label app-key \
  --wrapping-key-label migration-kek --output /migration/app-key.wrapped

# 3. Export public key for verification
docker exec rust-hsm-app rust-hsm-cli export-pubkey \
  --label DEV --user-pin *** --key-label app-key \
  --output /migration/app-key.pub

# Target HSM (prod):
# 4. Unwrap key
docker exec rust-hsm-prod rust-hsm-cli unwrap-key \
  --label PROD --user-pin *** --key-label app-key \
  --wrapping-key-label migration-kek \
  --input /migration/app-key.wrapped --key-type aes

# 5. Verify key attributes match
docker exec rust-hsm-prod rust-hsm-cli inspect-key \
  --label PROD --user-pin *** --key-label app-key

# 6. Test functionality
docker exec rust-hsm-prod rust-hsm-cli encrypt-symmetric \
  --label PROD --user-pin *** --key-label app-key \
  --input /test.txt --output /test.enc
```

---

## Troubleshooting Command Reference

### Quick Command Index

```bash
# Error diagnosis
explain-error <code> [--context <op>]

# Key discovery
find-key --key-label <name> [--show-similar]
list-objects [--detailed]

# Key inspection
inspect-key --key-label <name>
diff-keys --key1-label <k1> --key2-label <k2>

# Environment verification
info
list-slots [--detailed]
list-mechanisms [--detailed]

# Testing
benchmark [--iterations N]
hash --algorithm sha256 --input <file>
random --bytes 32
```

### Command Decision Tree

```
Problem?
├─ Don't know error code?
│  └─ Check logs for "CKR_*"
├─ Have error code?
│  └─ explain-error <code> --context <operation>
├─ Can't find key?
│  ├─ find-key --key-label <name> --show-similar
│  └─ list-objects --detailed
├─ Key exists but fails?
│  ├─ inspect-key --key-label <name>
│  └─ diff-keys --key1-label good --key2-label bad
├─ Don't know what's supported?
│  ├─ list-mechanisms --detailed
│  └─ info
└─ Need performance baseline?
   └─ benchmark --iterations 100
```

---

## Advanced Diagnostic Techniques

### 1. Logging and Tracing

Enable detailed logging:
```bash
# Set RUST_LOG environment variable
export RUST_LOG=rust_hsm_cli=debug,cryptoki=trace

docker exec -e RUST_LOG=debug rust-hsm-app rust-hsm-cli <command>
```

### 2. Debugging with OpenSSL

Verify exported keys:
```bash
# Export key
docker exec rust-hsm-app rust-hsm-cli export-pubkey \
  --label TOKEN --user-pin PIN \
  --key-label mykey --output /app/key.pem

# Verify with OpenSSL
docker exec rust-hsm-app openssl rsa -pubin -in /app/key.pem -text -noout

# Check key modulus matches
docker exec rust-hsm-app openssl rsa -pubin -in /app/key.pem -modulus -noout
```

### 3. Binary Data Inspection

```bash
# Check file format
file /app/encrypted.bin

# View hex dump
hexdump -C /app/encrypted.bin | head

# Check file size
stat -f%z /app/encrypted.bin  # macOS
stat -c%s /app/encrypted.bin  # Linux
```

### 4. Performance Profiling

```bash
# Benchmark specific operations
docker exec rust-hsm-app rust-hsm-cli benchmark \
  --label TOKEN --user-pin PIN \
  --iterations 1000 --warmup 100 \
  --format json --output results.json

# Analyze results
docker exec rust-hsm-app cat results.json | jq '.results[] | {name, ops_per_sec, avg_latency_ms}'
```

### 5. Automated Health Checks

Create a health check script:
```bash
#!/bin/bash
# hsm-health-check.sh

echo "=== HSM Health Check ==="

# 1. Check connectivity
docker exec rust-hsm-app rust-hsm-cli info || exit 1

# 2. Verify token
docker exec rust-hsm-app rust-hsm-cli list-slots | grep "MY_TOKEN" || exit 1

# 3. Test authentication
docker exec rust-hsm-app rust-hsm-cli list-objects \
  --label MY_TOKEN --user-pin $PIN > /dev/null || exit 1

# 4. Test basic operation
echo "test" | docker exec -i rust-hsm-app rust-hsm-cli hash \
  --algorithm sha256 > /dev/null || exit 1

echo "✓ All checks passed"
```

---

## Conclusion

This guide covers the majority of HSM troubleshooting scenarios. Remember:

1. **Start with error codes** - Use `explain-error` for context
2. **Verify environment** - Check slots, tokens, mechanisms
3. **Inspect objects** - Use `find-key`, `inspect-key`, `diff-keys`
4. **Test incrementally** - Start simple, increase complexity
5. **Document findings** - Build institutional knowledge

For issues not covered here, check:
- HSM vendor documentation
- PKCS#11 specification
- Application logs with RUST_LOG=debug
- GitHub issues: https://github.com/testingapisname/rust-hsm/issues

---

*Last updated: December 15, 2025*
