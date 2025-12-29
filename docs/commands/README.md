# Command Reference

Complete reference for all `rust-hsm-cli` commands with flags, options, and example outputs.

## Architecture

See [CLI Architecture](../CLI_ARCHITECTURE.md) for details on the modular command structure introduced in December 2025.

## Command Categories

### Token Management
- [init-token](token-management.md#init-token) - Initialize a new token
- [init-pin](token-management.md#init-pin) - Set user PIN

### Information & Discovery
- [info](information.md#info) - Display PKCS#11 module information
- [list-slots](information.md#list-slots) - List all slots and tokens
- [list-mechanisms](information.md#list-mechanisms) - List supported mechanisms
- [list-objects](information.md#list-objects) - List objects on a token
- [inspect-key](information.md#inspect-key) - Display detailed key attributes

### Key Generation
- [gen-keypair](key-generation.md#gen-keypair) - Generate RSA or ECDSA keypair
- [gen-symmetric-key](key-generation.md#gen-symmetric-key) - Generate AES key
- [gen-hmac-key](key-generation.md#gen-hmac-key) - Generate HMAC key
- [gen-cmac-key](key-generation.md#gen-cmac-key) - Generate CMAC key

### Asymmetric Operations
- [sign](asymmetric-operations.md#sign) - Sign data with private key
- [verify](asymmetric-operations.md#verify) - Verify signature with public key
- [encrypt](asymmetric-operations.md#encrypt) - Encrypt with RSA public key
- [decrypt](asymmetric-operations.md#decrypt) - Decrypt with RSA private key
- [export-pubkey](asymmetric-operations.md#export-pubkey) - Export public key in PEM format

### Symmetric Operations
- [encrypt-symmetric](symmetric-operations.md#encrypt-symmetric) - Encrypt with AES-GCM
- [decrypt-symmetric](symmetric-operations.md#decrypt-symmetric) - Decrypt with AES-GCM

### Key Management
- [wrap-key](key-management.md#wrap-key) - Wrap key for secure export
- [unwrap-key](key-management.md#unwrap-key) - Unwrap encrypted key
- [delete-key](key-management.md#delete-key) - Delete key from token

### Hashing & MACs
- [hash](hashing-macs.md#hash) - Hash data (SHA-256/384/512)
- [hmac-sign](hashing-macs.md#hmac-sign) - Generate HMAC
- [hmac-verify](hashing-macs.md#hmac-verify) - Verify HMAC
- [cmac-sign](hashing-macs.md#cmac-sign) - Generate CMAC
- [cmac-verify](hashing-macs.md#cmac-verify) - Verify CMAC

### Security & Utilities
- [audit](security-utilities.md#audit) - Security audit of token
- [benchmark](security-utilities.md#benchmark) - Performance benchmarking
- [gen-csr](security-utilities.md#gen-csr) - Generate Certificate Signing Request
- [gen-random](security-utilities.md#gen-random) - Generate random bytes

### Observability & Analysis
- [analyze](observability.md#analyze) - Analyze PKCS#11 operation logs and display statistics
- [gen-random](security-utilities.md#gen-random) - Generate random bytes

### Troubleshooting & Diagnostics
- [explain-error](troubleshooting.md#explain-error) - Decode PKCS#11 error codes with context-aware troubleshooting
- [find-key](troubleshooting.md#find-key) - Search for keys with fuzzy matching
- [diff-keys](troubleshooting.md#diff-keys) - Compare two keys side-by-side

## Common Flags

### Authentication
- `--label <TOKEN_LABEL>` - Token label (or use config file default)
- `--user-pin <PIN>` - User PIN for authentication
- `--so-pin <PIN>` - Security Officer PIN (for token initialization)
- `--pin-stdin` - Read user PIN from stdin (secure, no shell history)
- `--so-pin-stdin` - Read SO PIN from stdin
- `--user-pin-stdin` - Read user PIN from stdin (alias for --pin-stdin)

### Configuration
- `--config <PATH>` - Custom configuration file path

### Output Options
- `--json` - Output in JSON format (available for some commands)
- `--output <FILE>` - Write output to file
- `--hex` - Output in hexadecimal format (for random generation)

### Slot Selection
- `--slot <SLOT_ID>` - Target specific slot by ID

## Using Configuration File

To avoid repeating `--label` on every command, create `.rust-hsm.toml`:

```toml
default_token_label = "DEV_TOKEN"
pkcs11_module = "/usr/lib/softhsm/libsofthsm2.so"
```

Then commands become shorter:
```bash
# Without config: must specify --label
rust-hsm-cli gen-keypair --label DEV_TOKEN --user-pin 123456 --key-label my-key

# With config: --label uses default
rust-hsm-cli gen-keypair --user-pin 123456 --key-label my-key
```

## Security Best Practices

### Using --pin-stdin

Avoid PINs in shell history or process listings:

```bash
# Single PIN from stdin
echo "my-secure-pin" | rust-hsm-cli gen-keypair --pin-stdin --key-label my-key

# Multiple PINs (one per line)
printf "so-pin\nuser-pin" | rust-hsm-cli init-pin --so-pin-stdin --user-pin-stdin
```

### Environment Variables

Set defaults in environment:
```bash
export TOKEN_LABEL="PROD_TOKEN"
export USER_PIN="$(cat /secure/pin.txt)"
```
