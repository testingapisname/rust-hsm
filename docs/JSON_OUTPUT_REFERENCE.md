# JSON Output Reference

**rust-hsm** provides machine-parseable JSON output for automation, CI/CD integration, and fleet management.

## Quick Reference

| Command | JSON Flag | Output Structure |
|---------|-----------|------------------|
| `list-slots` | `--json` | Slot and token information |
| `list-objects` | `--json [--detailed]` | Object inventory with attributes |
| `list-mechanisms` | `--json [--detailed]` | Mechanism capabilities |
| `inspect-key` | `--json` | Key attributes and fingerprints |

---

## Command Reference

### list-slots --json

Returns information about all HSM slots and their tokens.

**Output Schema**:
```json
{
  "initialized_slot_count": <number>,
  "total_slot_count": <number>,
  "initialized_slots": [
    {
      "slot_id": <number>,
      "description": "<string>",
      "manufacturer": "<string>",
      "token": {
        "label": "<string>",
        "manufacturer": "<string>",
        "model": "<string>",
        "serial_number": "<string>"
      }
    }
  ],
  "all_slots": [ /* same structure as initialized_slots */ ]
}
```

**Example**:
```bash
rust-hsm-cli list-slots --json | jq '.initialized_slots[].token.label'
# Output: "PROD_TOKEN"
```

---

### list-objects --json [--detailed]

Lists all objects (keys, certificates) on a token.

**Output Schema**:
```json
{
  "token_label": "<string>",
  "object_count": <number>,
  "objects": [
    {
      "handle": "<string>",
      "label": "<string>",
      "class": "<string>",
      "id": "<hex_string>",
      "key_type": "<string>",          // optional
      "key_size_bits": <number>,        // optional
      "flags": {                        // optional (--detailed only)
        "token": <boolean>,
        "private": <boolean>,
        "modifiable": <boolean>,
        "local": <boolean>,
        "sign": <boolean>,              // optional
        "verify": <boolean>,            // optional
        "encrypt": <boolean>,           // optional
        "decrypt": <boolean>,           // optional
        "wrap": <boolean>,              // optional
        "unwrap": <boolean>,            // optional
        "derive": <boolean>,            // optional
        "sensitive": <boolean>,         // optional
        "always_sensitive": <boolean>,  // optional
        "never_extractable": <boolean>, // optional
        "extractable": <boolean>        // optional
      }
    }
  ]
}
```

**Examples**:
```bash
# List all key labels
rust-hsm-cli list-objects --label TOKEN --user-pin PIN --json \
  | jq -r '.objects[].label'

# Find all RSA keys
rust-hsm-cli list-objects --label TOKEN --user-pin PIN --json --detailed \
  | jq '.objects[] | select(.key_type | contains("val: 0")) | .label'

# Find non-extractable keys (compliance check)
rust-hsm-cli list-objects --label TOKEN --user-pin PIN --json --detailed \
  | jq '.objects[] | select(.flags.extractable == false) | {label, key_type}'

# Count objects
rust-hsm-cli list-objects --label TOKEN --user-pin PIN --json \
  | jq '.object_count'
```

---

### list-mechanisms --json [--detailed]

Lists all PKCS#11 mechanisms supported by the HSM.

**Output Schema**:
```json
{
  "slot_id": <number>,
  "mechanism_count": <number>,
  "mechanisms": [
    {
      "value": <number>,
      "name": "<string>",
      "category": "<string>",
      "capabilities": {              // optional (--detailed only)
        "encrypt": <boolean>,
        "decrypt": <boolean>,
        "digest": <boolean>,
        "sign": <boolean>,
        "sign_recover": <boolean>,
        "verify": <boolean>,
        "verify_recover": <boolean>,
        "generate": <boolean>,
        "generate_key_pair": <boolean>,
        "wrap": <boolean>,
        "unwrap": <boolean>,
        "derive": <boolean>
      }
    }
  ]
}
```

**Examples**:
```bash
# List all RSA mechanisms
rust-hsm-cli list-mechanisms --json \
  | jq '.mechanisms[] | select(.category == "RSA") | .name'

# Find mechanisms that support signing
rust-hsm-cli list-mechanisms --json --detailed \
  | jq '.mechanisms[] | select(.capabilities.sign == true) | .name'

# Count AES mechanisms
rust-hsm-cli list-mechanisms --json \
  | jq '[.mechanisms[] | select(.category == "AES")] | length'
```

---

### inspect-key --json

Inspects detailed attributes of a specific key.

**Output Schema**:
```json
{
  "key_label": "<string>",
  "object_count": <number>,
  "objects": [
    {
      "handle": "<string>",
      "fingerprint": "<string>",      // optional (public keys only)
      "attributes": {
        "CKA_TOKEN": <boolean>,
        "CKA_CLASS": "<string>",
        "CKA_ID": "<string>",
        "CKA_LABEL": "<string>",
        "CKA_KEY_TYPE": "<string>",
        "CKA_MODULUS": {               // RSA keys
          "bits": <number>,
          "bytes": <number>
        },
        "CKA_PUBLIC_EXPONENT": <number>,
        "CKA_PRIVATE": <boolean>,
        "CKA_MODIFIABLE": <boolean>,
        "CKA_LOCAL": <boolean>,
        "CKA_SIGN": <boolean>,         // optional
        "CKA_VERIFY": <boolean>,       // optional
        "CKA_ENCRYPT": <boolean>,      // optional
        "CKA_DECRYPT": <boolean>,      // optional
        "CKA_WRAP": <boolean>,         // optional
        "CKA_UNWRAP": <boolean>,       // optional
        "CKA_DERIVE": <boolean>,       // optional
        "CKA_SENSITIVE": <boolean>,    // optional
        "CKA_EXTRACTABLE": <boolean>,  // optional
        "CKA_ALWAYS_SENSITIVE": <boolean>,     // optional
        "CKA_NEVER_EXTRACTABLE": <boolean>     // optional
      }
    }
  ]
}
```

**Examples**:
```bash
# Get key fingerprint (for verification)
rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label KEY --json \
  | jq -r '.objects[0].fingerprint'
# Output: 7b:ca:ae:4e:4c:be:24:5e:...

# Check if key is extractable
rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label KEY --json \
  | jq '.objects[] | select(.attributes.CKA_EXTRACTABLE == false) | "Non-extractable"'

# Get key size
rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label KEY --json \
  | jq '.objects[0].attributes.CKA_MODULUS.bits'
```

---

## Common Patterns

### CI/CD Validation

```bash
#!/bin/bash
# Verify key exists and has correct fingerprint

EXPECTED_FP="7b:ca:ae:4e:4c:be:24:5e:ae:4c:9a:a1:78:ba:12:0a:a8:24:57:d6"

ACTUAL_FP=$(rust-hsm-cli inspect-key \
  --label PROD_TOKEN --user-pin $PIN --key-label prod-key --json \
  | jq -r '.objects[0].fingerprint')

if [ "$ACTUAL_FP" != "$EXPECTED_FP" ]; then
  echo "ERROR: Key fingerprint mismatch!"
  echo "Expected: $EXPECTED_FP"
  echo "Got: $ACTUAL_FP"
  exit 1
fi

echo "✓ Key fingerprint verified"
```

### Fleet Auditing

```bash
#!/bin/bash
# Audit all keys across multiple tokens

TOKENS=("TOKEN1" "TOKEN2" "TOKEN3")

for token in "${TOKENS[@]}"; do
  echo "=== $token ==="
  
  rust-hsm-cli list-objects --label $token --user-pin $PIN --json \
    | jq -r '.objects[] | "\(.label) [\(.class)]"'
  
  echo ""
done
```

### PowerShell Integration

```powershell
# Get all keys with their attributes
$output = docker exec rust-hsm-app rust-hsm-cli list-objects `
  --label DEV_TOKEN --user-pin 123456 --json --detailed | ConvertFrom-Json

# Filter and format
$output.objects | Where-Object { $_.key_type -ne $null } | ForEach-Object {
    [PSCustomObject]@{
        Label = $_.label
        Type = $_.key_type
        Size = $_.key_size_bits
        Extractable = $_.flags.extractable
    }
} | Format-Table -AutoSize
```

### Python Integration

```python
import subprocess
import json

def get_key_fingerprint(token, pin, key_label):
    """Get key fingerprint using JSON output"""
    cmd = [
        "docker", "exec", "rust-hsm-app",
        "rust-hsm-cli", "inspect-key",
        "--label", token,
        "--user-pin", pin,
        "--key-label", key_label,
        "--json"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    data = json.loads(result.stdout)
    
    return data['objects'][0]['fingerprint']

# Usage
fp = get_key_fingerprint("PROD_TOKEN", "123456", "signing-key")
print(f"Fingerprint: {fp}")
```

### Monitoring & Alerting

```bash
#!/bin/bash
# Monitor token capacity and alert if threshold exceeded

THRESHOLD=100

OBJECT_COUNT=$(rust-hsm-cli list-objects \
  --label PROD_TOKEN --user-pin $PIN --json \
  | jq '.object_count')

if [ $OBJECT_COUNT -gt $THRESHOLD ]; then
  # Send alert to monitoring system
  curl -X POST https://monitoring.example.com/alert \
    -d "token=PROD_TOKEN&objects=$OBJECT_COUNT&threshold=$THRESHOLD"
  
  echo "⚠️  WARNING: Token has $OBJECT_COUNT objects (threshold: $THRESHOLD)"
  exit 1
fi

echo "✓ Token capacity OK ($OBJECT_COUNT objects)"
```

### Compliance Reporting

```bash
#!/bin/bash
# Generate compliance report for audit

echo "=== HSM Compliance Report ==="
echo "Date: $(date)"
echo ""

# Non-extractable keys
echo "Non-Extractable Keys:"
rust-hsm-cli list-objects --label PROD_TOKEN --user-pin $PIN --json --detailed \
  | jq -r '.objects[] | select(.flags.extractable == false) | "  - \(.label) [\(.key_type)]"'

echo ""

# Key sizes
echo "Key Sizes:"
rust-hsm-cli list-objects --label PROD_TOKEN --user-pin $PIN --json --detailed \
  | jq -r '.objects[] | select(.key_size_bits != null) | "  - \(.label): \(.key_size_bits) bits"'

echo ""

# Total objects
TOTAL=$(rust-hsm-cli list-objects --label PROD_TOKEN --user-pin $PIN --json | jq '.object_count')
echo "Total Objects: $TOTAL"
```

---

## Error Handling

When using JSON output in scripts, handle errors appropriately:

```bash
#!/bin/bash
set -e  # Exit on error

OUTPUT=$(rust-hsm-cli list-objects \
  --label TOKEN --user-pin PIN --json 2>&1)

if echo "$OUTPUT" | jq . >/dev/null 2>&1; then
  # Valid JSON output
  echo "$OUTPUT" | jq '.objects[].label'
else
  # Error occurred
  echo "ERROR: $OUTPUT"
  exit 1
fi
```

---

## Tips

1. **Suppress logs**: JSON output includes log lines. Filter them with `jq`:
   ```bash
   rust-hsm-cli list-slots --json 2>/dev/null | jq '.'
   ```

2. **Pretty print**: Use `jq` for readable output:
   ```bash
   rust-hsm-cli list-objects --json | jq '.'
   ```

3. **Extract specific fields**: Use jq selectors:
   ```bash
   rust-hsm-cli inspect-key --json | jq -r '.objects[0].fingerprint'
   ```

4. **Combine with other tools**: JSON output works with any JSON processor:
   - **jq**: Command-line JSON processor
   - **PowerShell**: `ConvertFrom-Json`
   - **Python**: `json.loads()`
   - **Node.js**: `JSON.parse()`

---

## See Also

- [README.md](../README.md) - Main documentation
- [commands/](../docs/commands/) - Individual command reference
- [CKR_ERROR_REFERENCE.md](CKR_ERROR_REFERENCE.md) - Error code reference
