# Switching Between HSM Providers

This project supports both **SoftHSM2** and **Kryoptic** as PKCS#11 providers. You can switch between them by changing the configuration file.

## Available HSM Providers

### 1. SoftHSM2 (Default)
- **Path**: `/usr/lib/softhsm/libsofthsm2.so`
- **Type**: Software HSM implementation
- **Storage**: `/tokens` directory
- **Configuration**: `/etc/softhsm2.conf`
- **Best for**: General PKCS#11 operations, widely tested

### 2. Kryoptic
- **Path**: `/usr/lib/kryoptic/libkryoptic_pkcs11.so`
- **Type**: Rust-based PKCS#11 software token
- **Storage**: SQLite database in `/kryoptic-tokens`
- **Best for**: Rust ecosystem integration, FIPS builds, modern cryptography

## How to Switch

### Method 1: Configuration File (Recommended)

Edit your config file (`/app/.rust-hsm.toml` or `.rust-hsm.toml`):

**For SoftHSM2:**
```toml
default_token_label = "test-token"
pkcs11_module = "/usr/lib/softhsm/libsofthsm2.so"
```

**For Kryoptic:**
```toml
default_token_label = "test-token"
pkcs11_module = "/usr/lib/kryoptic/libkryoptic_pkcs11.so"
```

Then run any command:
```bash
rust-hsm-cli info
rust-hsm-cli list-slots
```

### Method 2: Environment Variable

Override the config file using the `PKCS11_MODULE` environment variable:

**For SoftHSM2:**
```bash
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
rust-hsm-cli info
```

**For Kryoptic:**
```bash
export PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so
rust-hsm-cli info
```

### Method 3: Docker Compose Environment

Update `compose.yaml` to set the default provider:

```yaml
services:
  app:
    environment:
      # For SoftHSM2 (default)
      - PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
      
      # Or for Kryoptic (uncomment to switch)
      # - PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so
```

Then restart the container:
```bash
docker compose down
docker compose up -d
```

## Testing Both Providers

### 1. Test SoftHSM2
```bash
# Inside container
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so

rust-hsm-cli info
rust-hsm-cli init-token --label SOFTHSM_TEST --so-pin 1234
rust-hsm-cli init-pin --label SOFTHSM_TEST --so-pin 1234 --user-pin 123456
rust-hsm-cli gen-keypair --label SOFTHSM_TEST --user-pin 123456 --key-label test-key --key-type rsa
rust-hsm-cli list-objects --label SOFTHSM_TEST --user-pin 123456
```

### 2. Test Kryoptic
```bash
# Inside container
export PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so

rust-hsm-cli info
rust-hsm-cli init-token --label KRYOPTIC_TEST --so-pin 1234
rust-hsm-cli init-pin --label KRYOPTIC_TEST --so-pin 1234 --user-pin 123456
rust-hsm-cli gen-keypair --label KRYOPTIC_TEST --user-pin 123456 --key-label test-key --key-type rsa
rust-hsm-cli list-objects --label KRYOPTIC_TEST --user-pin 123456
```

## Complete Example Workflow

```bash
# 1. Build the container (includes both HSM providers)
docker compose build

# 2. Start the container
docker compose up -d

# 3. Enter the container
docker exec -it rust-hsm-app bash

# 4. Test SoftHSM2
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
rust-hsm-cli info
# Output: SoftHSM cryptoki library

# 5. Switch to Kryoptic
export PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so
rust-hsm-cli info
# Output: Kryoptic library information

# 6. Create a token with Kryoptic
rust-hsm-cli init-token --label MY_KRYOPTIC_TOKEN --so-pin 1234
rust-hsm-cli init-pin --label MY_KRYOPTIC_TOKEN --so-pin 1234 --user-pin 123456

# 7. Generate keys
rust-hsm-cli gen-keypair --label MY_KRYOPTIC_TOKEN --user-pin 123456 \
  --key-label my-rsa-key --key-type rsa --bits 2048

# 8. List objects
rust-hsm-cli list-objects --label MY_KRYOPTIC_TOKEN --user-pin 123456 --detailed

# 9. Test operations
echo "test data" > /app/test.txt
rust-hsm-cli sign --label MY_KRYOPTIC_TOKEN --user-pin 123456 \
  --key-label my-rsa-key --input /app/test.txt --output /app/test.sig
rust-hsm-cli verify --label MY_KRYOPTIC_TOKEN --user-pin 123456 \
  --key-label my-rsa-key --input /app/test.txt --signature /app/test.sig
```

## Provider Comparison

| Feature | SoftHSM2 | Kryoptic |
|---------|----------|----------|
| **Language** | C/C++ | Rust |
| **Storage** | File-based | SQLite database |
| **FIPS Mode** | Limited | Full support with `--features fips` |
| **Maturity** | Very stable, widely used | Newer, actively developed |
| **Performance** | Excellent | Good |
| **Memory Safety** | No | Yes (Rust) |
| **Token Location** | `/tokens` | `/kryoptic-tokens` |
| **Config File** | `/etc/softhsm2.conf` | Built-in |

## Troubleshooting

### Module Not Found
If you get "Failed to load PKCS#11 module":
1. Check the file exists:
   ```bash
   ls -la /usr/lib/softhsm/libsofthsm2.so
   ls -la /usr/lib/kryoptic/libkryoptic_pkcs11.so
   ```
2. Verify permissions: Both should be readable

### Token Storage Issues

**SoftHSM2:**
- Tokens stored in: `/tokens`
- Clear tokens: `rm -rf /tokens/*`
- Config: Check `/etc/softhsm2.conf`

**Kryoptic:**
- Database stored in: `/kryoptic-tokens`
- Clear tokens: `rm -rf /kryoptic-tokens/*.db`

### Feature Differences

Some PKCS#11 mechanisms may behave differently between providers. Use these commands to check:

```bash
# Compare mechanisms
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
rust-hsm-cli list-mechanisms --detailed > softhsm-mechanisms.txt

export PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so
rust-hsm-cli list-mechanisms --detailed > kryoptic-mechanisms.txt

diff softhsm-mechanisms.txt kryoptic-mechanisms.txt
```

## Integration with CI/CD

You can test against both providers in your CI pipeline:

```bash
#!/bin/bash
# test-both-hsms.sh

for HSM in softhsm kryoptic; do
    echo "Testing with $HSM..."
    
    if [ "$HSM" = "softhsm" ]; then
        export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
    else
        export PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so
    fi
    
    # Run your test suite
    ./test.sh
    
    if [ $? -ne 0 ]; then
        echo "❌ Tests failed with $HSM"
        exit 1
    fi
    echo "✅ Tests passed with $HSM"
done
```

## Best Practices

1. **Development**: Use SoftHSM2 (most compatible, well-documented)
2. **Testing**: Test with both providers to ensure compatibility
3. **Production**: Choose based on your security requirements:
   - SoftHSM2: Mature, widely deployed
   - Kryoptic: Memory-safe, FIPS-ready
4. **Configuration Management**: Use config files to switch providers, not hardcoded paths
5. **Token Isolation**: Keep tokens for each provider in separate directories

## Further Reading

- [SoftHSM2 Documentation](https://github.com/opendnssec/SoftHSMv2)
- [Kryoptic GitHub](https://github.com/latchset/kryoptic)
- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/)
- [rust-hsm Configuration Guide](../config.example.toml)
