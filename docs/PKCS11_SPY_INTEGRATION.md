# PKCS#11 Spy Integration Guide

Comprehensive guide to using OpenSC's pkcs11-spy with rust-hsm for transparent PKCS#11 operation logging and analysis.

---

## Table of Contents

1. [Overview](#overview)
2. [Configuration](#configuration)
3. [Log Format Examples](#log-format-examples)
4. [Analysis Commands](#analysis-commands)
5. [Use Cases](#use-cases)
6. [Comparison: pkcs11-spy vs observe-core](#comparison-pkcs11-spy-vs-observe-core)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The rust-hsm project implements a **dual observability strategy** using both OpenSC's `pkcs11-spy` and custom `observe-core` logging:

- **pkcs11-spy**: External proxy that logs all PKCS#11 calls in plaintext
- **observe-core**: Built-in structured JSON logging with security redaction

This approach provides immediate compatibility with existing applications while offering rich analysis capabilities.

### Architecture

```
Application → pkcs11-spy.so → Real HSM Module (SoftHSM2/Kryoptic)
                    ↓
              Plaintext logs → rust-hsm-cli analyze
```

```
rust-hsm-cli → observe-cryptoki → cryptoki → Real HSM Module
                        ↓
               Structured JSON → rust-hsm-cli analyze
```

---

## Configuration

### Basic Setup

The Docker environment includes OpenSC with pkcs11-spy pre-installed:

```bash
# Check pkcs11-spy availability
docker exec rust-hsm-app ls -la /usr/lib/x86_64-linux-gnu/pkcs11-spy.so
```

### Environment Variables

Configure pkcs11-spy logging with these environment variables:

```bash
# Target HSM module (what pkcs11-spy forwards to)
export PKCS11SPY=/usr/lib/softhsm/libsofthsm2.so

# Log output file
export PKCS11SPY_OUTPUT=/app/spy-operations.log

# Use pkcs11-spy as the PKCS#11 module
export PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so
```

### Quick Start Examples

#### SoftHSM2 with pkcs11-spy
```bash
docker exec rust-hsm-app bash -c '
export PKCS11SPY=/usr/lib/softhsm/libsofthsm2.so
export PKCS11SPY_OUTPUT=/app/softhsm-spy.log
export PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so

# Initialize token - all calls logged
rust-hsm-cli init-token --label SPY_TEST --so-pin 1234
rust-hsm-cli init-pin --label SPY_TEST --so-pin 1234 --user-pin 123456

# Generate keypair - calls logged
rust-hsm-cli gen-keypair --label SPY_TEST --user-pin 123456 --key-label spy-key --key-type rsa

# Analyze the spy logs
rust-hsm-cli analyze --log-file /app/softhsm-spy.log --format text
'
```

#### Kryoptic with pkcs11-spy
```bash
docker exec rust-hsm-app bash -c '
export PKCS11SPY=/usr/lib/kryoptic/libkryoptic_pkcs11.so
export KRYOPTIC_CONF=/kryoptic-tokens/kryoptic.conf
export PKCS11SPY_OUTPUT=/app/kryoptic-spy.log
export PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so

rust-hsm-cli info
'
```

---

## Log Format Examples

### pkcs11-spy Output (Plaintext)

When using pkcs11-spy, logs are written in OpenSC's plaintext format:

```
0: C_Initialize
Returned:  0 CKR_OK

1: C_GetInfo
Info: Manufacturer = SoftHSM                           
Info: Library = Implementation of PKCS11               
Info: Version = 2.6                                    
Returned:  0 CKR_OK

2: C_GetSlotList(FALSE, 0x0, &7)
Returned:  0 CKR_OK

3: C_GetSlotList(FALSE, 0x7ffe8c4b5a60, &7)
Slot: 1262138880
Slot: 1027594016  
Slot: 793049152
Returned:  0 CKR_OK

4: C_GetSlotInfo(1262138880, 0x7ffe8c4b5e00)
Slot Info: Description = SoftHSM slot ID 0x4b3a2a00               
Slot Info: Manufacturer = SoftHSM project                           
Slot Info: Flags = 7 (TOKEN_PRESENT | REMOVABLE_DEVICE | HW_SLOT)
Returned:  0 CKR_OK

5: C_InitToken(1262138880, 1234, 4, SPY_TEST                        )
Returned:  0 CKR_OK

6: C_OpenSession(1262138880, 6, 0x0, 0x0, &6)
Session: 6
Returned:  0 CKR_OK

7: C_Login(6, 0, 1234, 4)
Returned:  0 CKR_OK

8: C_GenerateKeyPair(6, {CKM_RSA_PKCS_KEY_PAIR_GEN, 0x0, 0}, 
    {Attributes: CKA_TOKEN = TRUE; CKA_PRIVATE = FALSE; CKA_ENCRYPT = TRUE; CKA_VERIFY = TRUE; CKA_MODULUS_BITS = 2048; CKA_PUBLIC_EXPONENT = 65537}, 
    {Attributes: CKA_TOKEN = TRUE; CKA_PRIVATE = TRUE; CKA_SIGN = TRUE; CKA_DECRYPT = TRUE}, 
    &4, &3)
Public Key: 4
Private Key: 3
Returned:  0 CKR_OK

9: C_Logout(6)
Returned:  0 CKR_OK

10: C_CloseSession(6)
Returned:  0 CKR_OK

11: C_Finalize(0x0)
Returned:  0 CKR_OK
```

### observe-core Output (Structured JSON)

When using observe-core with structured logging:

```json
{"ts":"2026-01-06T10:30:45.123Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_Initialize","rv":0,"rv_name":"CKR_OK","dur_ms":1.2,"op_id":"init_001"}

{"ts":"2026-01-06T10:30:45.125Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_GetInfo","rv":0,"rv_name":"CKR_OK","dur_ms":0.3,"library_description":"Implementation of PKCS11","library_version":"2.6","op_id":"init_001"}

{"ts":"2026-01-06T10:30:45.128Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_GetSlotList","rv":0,"rv_name":"CKR_OK","dur_ms":0.1,"slots_found":3,"op_id":"init_001"}

{"ts":"2026-01-06T10:30:45.130Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_InitToken","rv":0,"rv_name":"CKR_OK","dur_ms":245.7,"slot_id":1262138880,"token_label_hash":"sha256:a1b2c3d4...","op_id":"token_init_001"}

{"ts":"2026-01-06T10:30:45.385Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_OpenSession","rv":0,"rv_name":"CKR_OK","dur_ms":0.8,"slot_id":1262138880,"session":6,"op_id":"session_001"}

{"ts":"2026-01-06T10:30:45.387Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_Login","rv":0,"rv_name":"CKR_OK","dur_ms":12.4,"session":6,"user_type":"User","op_id":"session_001"}

{"ts":"2026-01-06T10:30:45.756Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_GenerateKeyPair","rv":0,"rv_name":"CKR_OK","dur_ms":368.9,"session":6,"mech":"CKM_RSA_PKCS_KEY_PAIR_GEN","template_summary":{"public":{"CKA_CLASS":"CKO_PUBLIC_KEY","CKA_KEY_TYPE":"CKK_RSA","CKA_MODULUS_BITS":2048,"CKA_PUBLIC_EXPONENT_len":3},"private":{"CKA_CLASS":"CKO_PRIVATE_KEY","CKA_KEY_TYPE":"CKK_RSA","CKA_SIGN":true,"CKA_DECRYPT":true}},"public_key_handle":4,"private_key_handle":3,"op_id":"keygen_001","hint":"RSA-2048 keypair generated successfully"}

{"ts":"2026-01-06T10:30:45.758Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_Logout","rv":0,"rv_name":"CKR_OK","dur_ms":1.1,"session":6,"op_id":"session_001"}

{"ts":"2026-01-06T10:30:45.760Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_CloseSession","rv":0,"rv_name":"CKR_OK","dur_ms":0.4,"session":6,"op_id":"session_001"}

{"ts":"2026-01-06T10:30:45.761Z","pid":1234,"tid":5678,"module":"rust-hsm-cli","func":"C_Finalize","rv":0,"rv_name":"CKR_OK","dur_ms":0.2,"op_id":"init_001"}
```

---

## Analysis Commands

### Analyzing pkcs11-spy Logs

```bash
# Basic analysis (auto-detects pkcs11-spy format)
rust-hsm-cli analyze --log-file /app/spy-operations.log --format text

# JSON output for further processing
rust-hsm-cli analyze --log-file /app/spy-operations.log --format json

# Raw events as JSON Lines (converted from plaintext)
rust-hsm-cli analyze --log-file /app/spy-operations.log --format events
```

### Analyzing observe-core Logs

```bash
# Analysis of structured JSON logs
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json --format text

# Pretty-print all events
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json --format pretty-events
```

### Sample Analysis Output

```
=== PKCS#11 Operation Analysis ===

📊 Summary Statistics:
Total Operations: 11
Successful: 11 (100%)
Failed: 0 (0%)
Total Duration: 630.1ms

⏱️ Performance Breakdown:
Slowest Operations:
  1. C_GenerateKeyPair: 368.9ms (58.5% of total)
  2. C_InitToken: 245.7ms (39.0% of total)  
  3. C_Login: 12.4ms (2.0% of total)

🔄 Operation Frequency:
  - C_GenerateKeyPair: 1 (9.1%)
  - C_InitToken: 1 (9.1%)
  - C_Initialize: 1 (9.1%)
  - Other: 8 operations

🔍 Session Lifecycle:
  Sessions opened: 1
  Sessions closed: 1
  Max concurrent: 1
  Login/logout pairs: 1

⚠️ Potential Issues:
  - No performance concerns detected
  - All sessions properly closed
  - All operations completed successfully
```

---

## Use Cases

### 1. Debugging Third-Party Applications

Monitor any PKCS#11 application without code changes:

```bash
# Monitor pkcs11-tool operations
export PKCS11SPY=/usr/lib/softhsm/libsofthsm2.so
export PKCS11SPY_OUTPUT=/app/pkcs11-tool.log
export PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so

pkcs11-tool --list-slots
rust-hsm-cli analyze --log-file /app/pkcs11-tool.log --format text
```

### 2. Performance Analysis

Compare operation timing across HSM providers:

```bash
# SoftHSM2 performance
export PKCS11SPY=/usr/lib/softhsm/libsofthsm2.so
export PKCS11SPY_OUTPUT=/app/softhsm-perf.log
rust-hsm-cli benchmark --label TEST --user-pin 123456 --iterations 10

# Kryoptic performance  
export PKCS11SPY=/usr/lib/kryoptic/libkryoptic_pkcs11.so
export PKCS11SPY_OUTPUT=/app/kryoptic-perf.log
rust-hsm-cli benchmark --label TEST --user-pin 123456 --iterations 10

# Compare results
rust-hsm-cli analyze --log-file /app/softhsm-perf.log --format json > softhsm-analysis.json
rust-hsm-cli analyze --log-file /app/kryoptic-perf.log --format json > kryoptic-analysis.json
```

### 3. Security Auditing

Log all PKCS#11 operations for compliance:

```bash
# Enable comprehensive logging
export PKCS11SPY_OUTPUT=/app/audit-$(date +%Y%m%d).log

# Run production operations
rust-hsm-cli sign --label PROD_TOKEN --user-pin $PIN --key-label signing-key --input document.pdf --output signature.bin

# Generate audit report
rust-hsm-cli analyze --log-file /app/audit-$(date +%Y%m%d).log --format json | jq '.summary'
```

### 4. Application Migration

Verify PKCS#11 call compatibility when migrating between HSMs:

```bash
# Test application with different providers
for provider in softhsm2 kryoptic; do
    echo "Testing with $provider..."
    # Configure provider-specific settings
    export PKCS11SPY_OUTPUT="/app/${provider}-migration.log"
    
    # Run test suite
    ./test-application.sh
    
    # Analyze for compatibility issues
    rust-hsm-cli analyze --log-file "/app/${provider}-migration.log" --format text
done
```

---

## Comparison: pkcs11-spy vs observe-core

| Feature | pkcs11-spy | observe-core |
|---------|------------|--------------|
| **Integration** | Zero code changes | Requires code integration |
| **Compatibility** | Any PKCS#11 application | rust-hsm-cli only |
| **Output Format** | Plaintext | Structured JSON |
| **Performance Impact** | ~5-10% overhead | ~2-5% overhead |
| **Security** | Logs raw data | Built-in redaction |
| **Analysis** | Basic parsing | Rich analytics |
| **Correlation** | Manual | Automatic op_id tracking |
| **Real-time** | File-based | Configurable sinks |

### When to Use Each

**Use pkcs11-spy for:**
- Debugging existing applications
- Quick troubleshooting
- External application auditing
- Provider compatibility testing

**Use observe-core for:**
- Production monitoring
- Performance optimization
- Security-conscious environments
- Custom application development

---

## Best Practices

### 1. Log Rotation

```bash
# Rotate logs to prevent disk space issues
export PKCS11SPY_OUTPUT="/app/logs/spy-$(date +%Y%m%d-%H%M%S).log"
```

### 2. Security Considerations

```bash
# Secure log files (PINs may appear in some error cases)
chmod 600 /app/*.log

# Use observe-core for production (built-in redaction)
export RUST_HSM_OBSERVE_ENABLED=true
export RUST_HSM_OBSERVE_LOG_FILE="/app/secure-operations.json"
```

### 3. Performance Monitoring

```bash
# Monitor log file size during operations
du -h /app/spy-operations.log

# Use structured logging for performance analysis
rust-hsm-cli analyze --log-file operations.json --format json | jq '.performance'
```

### 4. Integration Testing

```bash
# Test both logging methods produce consistent results
export PKCS11SPY_OUTPUT=/app/spy.log
export RUST_HSM_OBSERVE_LOG_FILE=/app/observe.json
export RUST_HSM_OBSERVE_ENABLED=true

rust-hsm-cli gen-keypair --label TEST --user-pin 123456 --key-label test-key --key-type rsa

# Compare operation counts
echo "pkcs11-spy operations:"
rust-hsm-cli analyze --log-file /app/spy.log --format json | jq '.summary.total_operations'

echo "observe-core operations:"  
rust-hsm-cli analyze --log-file /app/observe.json --format json | jq '.summary.total_operations'
```

---

## Troubleshooting

### Common Issues

#### 1. pkcs11-spy Not Logging

```bash
# Verify environment variables
echo "PKCS11SPY: $PKCS11SPY"
echo "PKCS11SPY_OUTPUT: $PKCS11SPY_OUTPUT"
echo "PKCS11_MODULE: $PKCS11_MODULE"

# Check module exists
ls -la $PKCS11_MODULE

# Test with simple operation
rust-hsm-cli info > /dev/null && echo "Logged to: $PKCS11SPY_OUTPUT"
```

#### 2. Log File Permission Issues

```bash
# Ensure directory is writable
touch $PKCS11SPY_OUTPUT && echo "Can write to log file"

# Check file permissions
ls -la $PKCS11SPY_OUTPUT
```

#### 3. Large Log Files

```bash
# Monitor log size during operations
tail -f $PKCS11SPY_OUTPUT | while read line; do echo "$(date): $line"; done

# Compress old logs
gzip /app/logs/spy-*.log
```

#### 4. Analysis Parser Errors

```bash
# Validate log format
head -20 $PKCS11SPY_OUTPUT

# Check for truncated logs
tail -5 $PKCS11SPY_OUTPUT | grep -q "C_Finalize" || echo "Log may be incomplete"

# Test with minimal log
echo "0: C_Initialize
Returned:  0 CKR_OK" > /tmp/test.log
rust-hsm-cli analyze --log-file /tmp/test.log --format text
```

---

## Advanced Usage

### Custom Log Analysis

```bash
# Extract only signing operations from pkcs11-spy logs
grep -A 3 "C_Sign" /app/spy.log

# Count operations by type
rust-hsm-cli analyze --log-file /app/spy.log --format json | jq '.operations | group_by(.func) | map({func: .[0].func, count: length})'

# Performance regression detection
rust-hsm-cli analyze --log-file baseline.log --format json > baseline.json
rust-hsm-cli analyze --log-file current.log --format json > current.json
diff <(jq '.performance' baseline.json) <(jq '.performance' current.json)
```

### Integration with CI/CD

```yaml
# GitHub Actions workflow step
- name: PKCS#11 Operation Audit
  run: |
    export PKCS11SPY=/usr/lib/softhsm/libsofthsm2.so
    export PKCS11SPY_OUTPUT=/tmp/ci-audit.log
    export PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so
    
    # Run test suite
    ./integration-tests.sh
    
    # Analyze for security issues
    rust-hsm-cli analyze --log-file /tmp/ci-audit.log --format json > audit-results.json
    
    # Check for failures
    jq -e '.summary.failed_operations == 0' audit-results.json
```

This dual observability approach provides comprehensive PKCS#11 monitoring capabilities for both development and production environments.