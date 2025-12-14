# Troubleshooting Commands

Diagnostic commands for debugging HSM issues, finding keys, and understanding errors.

## explain-error

Decode PKCS#11 error codes and get context-aware troubleshooting steps.

### Syntax

```bash
rust-hsm-cli explain-error <ERROR_CODE> [--context <OPERATION>]
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `ERROR_CODE` | Yes | Error code in multiple formats: `CKR_PIN_INCORRECT`, `0x000000A0`, or `160` |
| `--context` | No | Operation context for targeted advice: `sign`, `verify`, `encrypt`, `decrypt`, `login`, `wrap` |

### Examples

#### Explain error by name
```bash
$ rust-hsm-cli explain-error CKR_PIN_INCORRECT

=== PKCS#11 Error Explanation ===

Error Code: CKR_PIN_INCORRECT (0x000000A0)

Meaning: PIN is incorrect

Common Causes:
  1. Wrong PIN provided
  2. Check user PIN vs SO PIN
  3. PIN may be locked after multiple failures

General Troubleshooting:
  → Check token status: rust-hsm-cli list-slots
  → Verify connectivity: rust-hsm-cli info
  → Review application logs for additional context
  → Use --context flag for operation-specific guidance

Example:
  rust-hsm-cli explain-error CKR_PIN_INCORRECT --context sign
```

#### Explain error with operation context
```bash
$ rust-hsm-cli explain-error CKR_KEY_HANDLE_INVALID --context sign

=== PKCS#11 Error Explanation ===

Error Code: CKR_KEY_HANDLE_INVALID (0x00000060)

Meaning: The specified key handle is not valid

Common Causes:
  1. Key was deleted
  2. Session closed invalidating handle
  3. Wrong key type (public vs private)
  4. Key not accessible in current session

Context: sign operation

Troubleshooting Steps for Signing:
  → Verify key exists: rust-hsm-cli list-objects --detailed
  → Check key attributes: rust-hsm-cli inspect-key --key-label <name>
  → Ensure CKA_SIGN=true on private key
  → Test operation: rust-hsm-cli sign --key-label <name> --input test.txt
  → Check mechanism support: rust-hsm-cli list-mechanisms --detailed
```

#### Explain error by hex code
```bash
$ rust-hsm-cli explain-error 0x000000A0

=== PKCS#11 Error Explanation ===

Error Code: CKR_PIN_INCORRECT (0x000000A0)
...
```

#### Explain error by decimal code
```bash
$ rust-hsm-cli explain-error 160

=== PKCS#11 Error Explanation ===

Error Code: CKR_PIN_INCORRECT (0x000000A0)
...
```

### Supported Error Codes

The command supports 35+ common PKCS#11 error codes including:

| Error Code | Hex Value | Description |
|------------|-----------|-------------|
| CKR_OK | 0x00000000 | Success |
| CKR_CANCEL | 0x00000001 | Operation canceled |
| CKR_HOST_MEMORY | 0x00000002 | Host memory allocation failed |
| CKR_SLOT_ID_INVALID | 0x00000003 | Invalid slot ID |
| CKR_GENERAL_ERROR | 0x00000005 | General error |
| CKR_FUNCTION_FAILED | 0x00000006 | Function failed |
| CKR_ARGUMENTS_BAD | 0x00000007 | Bad arguments |
| CKR_ATTRIBUTE_READ_ONLY | 0x00000010 | Attribute is read-only |
| CKR_ATTRIBUTE_TYPE_INVALID | 0x00000012 | Invalid attribute type |
| CKR_ATTRIBUTE_VALUE_INVALID | 0x00000013 | Invalid attribute value |
| CKR_DATA_INVALID | 0x00000020 | Invalid data |
| CKR_DATA_LEN_RANGE | 0x00000021 | Data length out of range |
| CKR_DEVICE_ERROR | 0x00000030 | Device error |
| CKR_DEVICE_MEMORY | 0x00000031 | Device memory error |
| CKR_DEVICE_REMOVED | 0x00000032 | Device removed |
| CKR_KEY_HANDLE_INVALID | 0x00000060 | Invalid key handle |
| CKR_KEY_SIZE_RANGE | 0x00000062 | Key size out of range |
| CKR_KEY_TYPE_INCONSISTENT | 0x00000063 | Inconsistent key type |
| CKR_KEY_FUNCTION_NOT_PERMITTED | 0x00000068 | Key function not permitted |
| CKR_KEY_UNEXTRACTABLE | 0x0000006A | Key is not extractable |
| CKR_MECHANISM_INVALID | 0x00000070 | Invalid mechanism |
| CKR_OPERATION_ACTIVE | 0x00000090 | Operation already active |
| CKR_OPERATION_NOT_INITIALIZED | 0x00000091 | Operation not initialized |
| CKR_PIN_INCORRECT | 0x000000A0 | Incorrect PIN |
| CKR_PIN_INVALID | 0x000000A1 | Invalid PIN |
| CKR_PIN_LEN_RANGE | 0x000000A2 | PIN length out of range |
| CKR_PIN_EXPIRED | 0x000000A3 | PIN expired |
| CKR_PIN_LOCKED | 0x000000A4 | PIN locked |
| CKR_SESSION_CLOSED | 0x000000B0 | Session closed |
| CKR_SESSION_COUNT | 0x000000B1 | Too many sessions |
| CKR_SESSION_HANDLE_INVALID | 0x000000B3 | Invalid session handle |
| CKR_SESSION_READ_ONLY | 0x000000B5 | Session is read-only |
| CKR_SIGNATURE_INVALID | 0x000000C0 | Invalid signature |
| CKR_TOKEN_NOT_PRESENT | 0x000000E0 | Token not present |
| CKR_USER_ALREADY_LOGGED_IN | 0x00000100 | User already logged in |
| CKR_USER_NOT_LOGGED_IN | 0x00000101 | User not logged in |
| CKR_WRAPPED_KEY_INVALID | 0x00000110 | Invalid wrapped key |
| CKR_WRAPPED_KEY_LEN_RANGE | 0x00000112 | Wrapped key length out of range |
| CKR_BUFFER_TOO_SMALL | 0x00000150 | Buffer too small |

### Context-Aware Troubleshooting

When using `--context`, the command provides operation-specific guidance:

**For `--context sign`:**
- Verify key exists and has CKA_SIGN attribute
- Check if private key is accessible
- Validate mechanism support
- Test with sample data

**For `--context verify`:**
- Check public key availability
- Ensure CKA_VERIFY attribute is set
- Validate signature format and length
- Check data integrity

**For `--context encrypt`:**
- Verify public key for RSA or session key for AES
- Check CKA_ENCRYPT attribute
- Validate data size against key size
- Check mechanism parameters

**For `--context decrypt`:**
- Ensure private key is accessible
- Check CKA_DECRYPT attribute
- Validate encrypted data length
- Check for proper padding

**For `--context login`:**
- Verify token is initialized
- Check PIN format and length
- Review PIN policy settings
- Check for locked PINs

**For `--context wrap`:**
- Verify wrapping key has CKA_WRAP attribute
- Check target key has CKA_EXTRACTABLE attribute
- Validate mechanism support for key types
- Check key size compatibility

---

## find-key

Search for keys with fuzzy matching to help locate keys when exact label is unknown.

### Syntax

```bash
rust-hsm-cli find-key --label <TOKEN> --user-pin <PIN> --key-label <PATTERN> [--show-similar]
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--label` | Yes* | Token label (*uses config default if available) |
| `--user-pin` | Yes* | User PIN (*or use `--pin-stdin`) |
| `--key-label` | Yes | Key label pattern to search for |
| `--show-similar` | No | Show similar keys if exact match not found (edit distance ≤3) |
| `--pin-stdin` | No | Read PIN from stdin instead of command line |

### Examples

#### Find key by exact label
```bash
$ rust-hsm-cli find-key --label DEV_TOKEN --user-pin 123456 --key-label my-rsa-key

=== Key Search: 'my-rsa-key' ===

✓ Exact match found!

Match 1:
  Type: Private Key (KeyType { val: 0 })
  Capabilities: sign, decrypt
  Flags: local, sensitive, non-extractable

Match 2:
  Type: Public Key (KeyType { val: 0 })
  Capabilities: verify, encrypt
  Flags: local
```

#### Find key with fuzzy matching
```bash
$ rust-hsm-cli find-key --label DEV_TOKEN --user-pin 123456 \
    --key-label my-rza-key --show-similar

=== Key Search: 'my-rza-key' ===

✗ Exact match not found

Searching for similar keys...

Similar keys found:

1. 'my-rsa-key' (edit distance: 1)
   Type: Private Key (KeyType { val: 0 })
   Capabilities: sign, decrypt

2. 'my-rsa-key' (edit distance: 1)
   Type: Public Key (KeyType { val: 0 })
   Capabilities: verify, encrypt

3. 'my-dsa-key' (edit distance: 2)
   Type: Private Key (KeyType { val: 1 })
   Capabilities: sign

Suggestion: Check for typos or different separators (-, _, space)
```

#### Key not found
```bash
$ rust-hsm-cli find-key --label DEV_TOKEN --user-pin 123456 \
    --key-label nonexistent-key

=== Key Search: 'nonexistent-key' ===

✗ Exact match not found

No similar keys found (try --show-similar to search with fuzzy matching)
```

### Fuzzy Matching Algorithm

The command uses **Levenshtein distance** (edit distance) to find similar keys:

- **Edit distance ≤3**: Keys are considered similar
- **Operations counted**: insertions, deletions, substitutions
- **Case-sensitive**: 'MyKey' ≠ 'mykey'

**Examples of matches:**
- `my-key` ↔ `mykey` (distance: 1, deletion of `-`)
- `test-rsa` ↔ `test-ecdsa` (distance: 3, insertion of `ecd`)
- `key_2024` ↔ `key-2024` (distance: 1, substitution of `_` → `-`)

### Use Cases

1. **Typo correction**: Find keys when label has minor typos
2. **Separator confusion**: Locate keys with different separators (`-`, `_`, space)
3. **Naming variations**: Find keys with slightly different naming conventions
4. **Migration**: Locate keys after label format changes
5. **Exploration**: Discover available keys when exact names are unknown

---

## diff-keys

Compare two keys side-by-side to identify attribute differences and potential configuration issues.

### Syntax

```bash
rust-hsm-cli diff-keys --label <TOKEN> --user-pin <PIN> \
    --key1-label <KEY1> --key2-label <KEY2>
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--label` | Yes* | Token label (*uses config default if available) |
| `--user-pin` | Yes* | User PIN (*or use `--pin-stdin`) |
| `--key1-label` | Yes | First key label to compare |
| `--key2-label` | Yes | Second key label to compare |
| `--pin-stdin` | No | Read PIN from stdin instead of command line |

### Examples

#### Compare two RSA keys
```bash
$ rust-hsm-cli diff-keys --label DEV_TOKEN --user-pin 123456 \
    --key1-label my-rsa-key --key2-label backup-rsa-key

=== Key Comparison ===

Key 1: my-rsa-key
Key 2: backup-rsa-key

Attribute                      Key 1                Key 2                Status
────────────────────────────────────────────────────────────────────────────────
Class                          ObjectClass { val: 3 } ObjectClass { val: 3 } ✓
KeyType                        KeyType { val: 0 }   KeyType { val: 0 }   ✓
Token                          true                 true                 ✓
Private                        true                 true                 ✓
Modifiable                     true                 false                ✗
Local                          true                 true                 ✓
Sign                           true                 true                 ✓
Verify                         N/A                  N/A                  ✓
Encrypt                        N/A                  N/A                  ✓
Decrypt                        true                 true                 ✓
Wrap                           N/A                  N/A                  ✓
Unwrap                         true                 true                 ✓
Derive                         false                false                ✓
Sensitive                      true                 true                 ✓
AlwaysSensitive                true                 true                 ✓
NeverExtractable               true                 false                ✗
Extractable                    false                true                 ✗

✗ Found 3 difference(s):

⚠ Modifiable: true vs false
  → Security difference: Key 2 cannot be modified
  → Impact: Key 2 attributes are immutable

⚠ NeverExtractable: true vs false
  → Security difference: Key 2 was extractable at some point
  → Impact: Key 2 may have been exported

⚠ Extractable: false vs true
  → Security difference: Key 2 can be wrapped/exported
  → Impact: Key 2 can be extracted from HSM
```

#### Compare RSA vs ECDSA keys
```bash
$ rust-hsm-cli diff-keys --label DEV_TOKEN --user-pin 123456 \
    --key1-label my-rsa-key --key2-label my-ecdsa-key

=== Key Comparison ===

Key 1: my-rsa-key
Key 2: my-ecdsa-key

Attribute                      Key 1                Key 2                Status
────────────────────────────────────────────────────────────────────────────────
Class                          ObjectClass { val: 3 } ObjectClass { val: 3 } ✓
KeyType                        KeyType { val: 0 }   KeyType { val: 3 }   ✗
Token                          true                 true                 ✓
Private                        true                 true                 ✓
Modifiable                     true                 true                 ✓
Local                          true                 true                 ✓
Sign                           true                 true                 ✓
Verify                         N/A                  N/A                  ✓
...

✗ Found 1 difference(s):

ℹ KeyType: KeyType { val: 0 } vs KeyType { val: 3 }
  → Minor difference in key properties
  → KeyType 0 = RSA, KeyType 3 = ECDSA
```

### Compared Attributes

The command compares these key attributes:

| Attribute | Description | Severity when different |
|-----------|-------------|------------------------|
| **Class** | Object class (private/public/secret) | CRITICAL |
| **KeyType** | Algorithm type (RSA/ECDSA/AES) | HIGH |
| **Token** | Stored on token vs session | HIGH |
| **Private** | Requires login to access | HIGH |
| **Modifiable** | Can attributes be changed | MEDIUM |
| **Local** | Generated on HSM vs imported | MEDIUM |
| **Sign** | Can sign data | HIGH |
| **Verify** | Can verify signatures | HIGH |
| **Encrypt** | Can encrypt data | HIGH |
| **Decrypt** | Can decrypt data | HIGH |
| **Wrap** | Can wrap other keys | MEDIUM |
| **Unwrap** | Can unwrap keys | MEDIUM |
| **Derive** | Can derive other keys | MEDIUM |
| **Sensitive** | Cannot be read in plaintext | CRITICAL |
| **AlwaysSensitive** | Was always sensitive | HIGH |
| **NeverExtractable** | Never been extractable | HIGH |
| **Extractable** | Can be wrapped/exported | CRITICAL |

### Use Cases

1. **Configuration verification**: Ensure keys have matching security policies
2. **Migration validation**: Verify imported keys match source attributes
3. **Backup verification**: Confirm backup keys have identical capabilities
4. **Security audit**: Identify keys with different security attributes
5. **Troubleshooting**: Find why two "identical" keys behave differently
6. **Compliance**: Verify keys meet security requirements

### Severity Indicators

| Symbol | Severity | Meaning |
|--------|----------|---------|
| ✓ | Match | Attributes are identical |
| ℹ | INFO/LOW | Minor informational difference |
| ⚠ | MEDIUM/HIGH | Configuration or capability difference |
| ⛔ | CRITICAL | Security-critical difference |

---

## Common Troubleshooting Workflows

### Workflow 1: Application returns unknown error code

1. Get error code from application logs
2. Decode with `explain-error`:
   ```bash
   rust-hsm-cli explain-error 0x000000C0
   ```
3. Follow context-specific guidance
4. Verify with targeted commands

### Workflow 2: Cannot find key by name

1. Search with fuzzy matching:
   ```bash
   rust-hsm-cli find-key --key-label approx-name --show-similar
   ```
2. Identify correct label from similar matches
3. Update application configuration

### Workflow 3: Key works in development but not production

1. Compare keys between environments:
   ```bash
   # On dev
   rust-hsm-cli inspect-key --key-label my-key --json > dev-key.json
   
   # On prod
   rust-hsm-cli inspect-key --key-label my-key --json > prod-key.json
   
   # Compare directly
   rust-hsm-cli diff-keys --key1-label dev-key --key2-label prod-key
   ```
2. Identify attribute differences
3. Regenerate or reconfigure as needed

### Workflow 4: Signature verification fails unexpectedly

1. Check error code:
   ```bash
   rust-hsm-cli explain-error CKR_SIGNATURE_INVALID --context verify
   ```
2. Inspect key attributes:
   ```bash
   rust-hsm-cli inspect-key --key-label my-key
   ```
3. Verify key has CKA_VERIFY capability
4. Test with known-good signature

### Workflow 5: Key extraction/wrapping fails

1. Decode wrap error:
   ```bash
   rust-hsm-cli explain-error CKR_KEY_UNEXTRACTABLE --context wrap
   ```
2. Check both keys:
   ```bash
   rust-hsm-cli diff-keys --key1-label kek --key2-label target-key
   ```
3. Verify:
   - KEK has CKA_WRAP=true
   - Target has CKA_EXTRACTABLE=true
   - Target has CKA_NEVER_EXTRACTABLE=false

---

## Tips & Best Practices

### Error Code Lookup
- Use `explain-error` first before deep investigation
- Always provide `--context` when known
- Keep error codes from logs for future reference
- Document recurring errors with their solutions

### Key Search
- Start with exact match, then use `--show-similar`
- Note edit distance - lower is more similar
- Watch for separator differences (`-` vs `_` vs space)
- Consider case sensitivity in key labels

### Key Comparison
- Compare production keys against known-good templates
- Document expected attribute profiles
- Use diff before and after migrations
- Include in security audit procedures

### Secure PIN Handling
- Use `--pin-stdin` for automation
- Never log PINs in scripts
- Rotate PINs regularly
- Use separate PINs for dev/staging/prod
