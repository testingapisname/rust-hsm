# Token Management Commands

## init-token

Initialize a new token on an available slot.

### Syntax
```bash
rust-hsm-cli init-token --label <TOKEN_LABEL> --so-pin <SO_PIN>
```

### Flags
- `--label <TOKEN_LABEL>` - Label for the new token (required)
- `--so-pin <SO_PIN>` - Security Officer PIN (required, unless using --so-pin-stdin)
- `--so-pin-stdin` - Read SO PIN from stdin for security

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli init-token --label DEV_TOKEN --so-pin 1234
```

### Example Output
```
2025-12-13T20:15:30.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T20:15:30.145678Z  INFO rust_hsm_cli::pkcs11::token: Token 'DEV_TOKEN' initialized successfully
2025-12-13T20:15:30.145890Z  INFO rust_hsm_cli::pkcs11::token: Slot: 404614813
```

### Secure Alternative
```bash
echo "my-secure-so-pin" | docker exec -i rust-hsm-app \
  rust-hsm-cli init-token --label DEV_TOKEN --so-pin-stdin
```

---

## init-pin

Set or change the user PIN on an initialized token.

### Syntax
```bash
rust-hsm-cli init-pin --label <TOKEN_LABEL> --so-pin <SO_PIN> --user-pin <USER_PIN>
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--so-pin <SO_PIN>` - Security Officer PIN (required, unless using --so-pin-stdin)
- `--user-pin <USER_PIN>` - New user PIN to set (required, unless using --user-pin-stdin)
- `--so-pin-stdin` - Read SO PIN from stdin
- `--user-pin-stdin` - Read user PIN from stdin

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli init-pin \
  --label DEV_TOKEN --so-pin 1234 --user-pin 123456
```

### Example Output
```
2025-12-13T20:16:45.123456Z  INFO rust_hsm_cli: Using PKCS#11 module: /usr/lib/softhsm/libsofthsm2.so
2025-12-13T20:16:45.145678Z  INFO rust_hsm_cli::pkcs11::token: User PIN initialized successfully
```

### Secure Alternative (Both PINs from stdin)
```bash
printf "my-so-pin\nmy-user-pin" | docker exec -i rust-hsm-app \
  rust-hsm-cli init-pin --label DEV_TOKEN --so-pin-stdin --user-pin-stdin
```

---

## Notes

### Token Initialization Workflow

1. **Initialize token** with SO PIN
   ```bash
   rust-hsm-cli init-token --label MY_TOKEN --so-pin 1234
   ```

2. **Set user PIN** using SO PIN
   ```bash
   rust-hsm-cli init-pin --label MY_TOKEN --so-pin 1234 --user-pin 123456
   ```

3. **Use token** with user PIN for all operations
   ```bash
   rust-hsm-cli gen-keypair --label MY_TOKEN --user-pin 123456 --key-label app-key
   ```

### Security Considerations

- **SO PIN** is used only for administrative operations (token init, user PIN management)
- **User PIN** is used for all cryptographic operations
- SoftHSM locks tokens after 3 failed PIN attempts
- Use `--pin-stdin` options to avoid PINs in shell history
- Never commit PINs to version control
