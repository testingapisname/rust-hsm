# Troubleshooting Example: Key Wrapping Failure

A real-world walkthrough demonstrating how to diagnose and fix a common HSM issue using rust-hsm troubleshooting commands.

## Scenario Overview

**Problem:** You're trying to wrap (export) a key for backup, but the operation fails with a cryptic error message about CKA_EXTRACTABLE.

**Goal:** Understand why it's failing and fix it using the diagnostic commands.

---

## Step-by-Step Troubleshooting

### Initial Setup

First, let's create the scenario that causes the problem:

```bash
# Initialize token and PIN
docker exec rust-hsm-app rust-hsm-cli init-token --label DEMO_TOKEN --so-pin 1234
docker exec rust-hsm-app rust-hsm-cli init-pin --label DEMO_TOKEN --so-pin 1234 --user-pin 123456

# Generate a regular (non-extractable) AES key
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEMO_TOKEN --user-pin 123456 \
  --key-label secret-key --bits 256

# Generate a Key Encryption Key (KEK) for wrapping
docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEMO_TOKEN --user-pin 123456 \
  --key-label wrapping-key --bits 256
```

### The Problem: Wrap Operation Fails ❌

```bash
$ docker exec rust-hsm-app rust-hsm-cli wrap-key \
  --label DEMO_TOKEN --user-pin 123456 \
  --key-label secret-key \
  --wrapping-key-label wrapping-key \
  --output /app/wrapped.bin

Error: Function::WrapKey: PKCS11 error: The specified private or secret key can't 
be wrapped because its CKA_EXTRACTABLE attribute is set to CK_FALSE.
```

**What just happened?** 🤔
- The wrap operation failed
- Something about "CKA_EXTRACTABLE" being false
- But what does that mean? How do we fix it?

---

## Troubleshooting Process

### Step 1: Decode the Error 🔍

Use `explain-error` to understand what's happening:

```bash
$ docker exec rust-hsm-app rust-hsm-cli explain-error CKR_KEY_UNEXTRACTABLE --context wrap
```

**Output:**
```
=== PKCS#11 Error Explanation ===

Error Code: CKR_KEY_UNEXTRACTABLE (0x00000117)

Meaning: Key cannot be extracted (wrapped)

Common Causes:
  1. CKA_EXTRACTABLE=false
  2. Key marked non-extractable
  3. Cannot wrap sensitive keys
  4. Regenerate with --extractable if needed

Context: wrap operation

Troubleshooting Steps for Key Wrapping:
  → Ensure target key has CKA_EXTRACTABLE=true
  → Verify wrapping key has CKA_WRAP=true
  → Check mechanism support for key wrapping
  → Regenerate target key with --extractable if needed
```

**Key Insight:** The error tells us the key needs `CKA_EXTRACTABLE=true`, and we should check this attribute or regenerate the key with `--extractable`.

---

### Step 2: Inspect the Problematic Key 🔎

Let's verify the key's attributes:

```bash
$ docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label DEMO_TOKEN --user-pin 123456 \
  --key-label secret-key
```

**Output:**
```
Key: 'secret-key' (1 object(s) found)
================================================================================
  CKA_CLASS:              ObjectClass { val: 4 }
  CKA_KEY_TYPE:           KeyType { val: 31 }
  CKA_LABEL:              secret-key
  CKA_TOKEN:              true
  CKA_PRIVATE:            true
  CKA_MODIFIABLE:         true
  CKA_SENSITIVE:          true
  CKA_EXTRACTABLE:        false          ← ⚠️ PROBLEM!
  CKA_SIGN:               true
  CKA_VERIFY:             true
  CKA_ENCRYPT:            true
  CKA_DECRYPT:            true
  CKA_WRAP:               true
  CKA_UNWRAP:             true
  CKA_DERIVE:             false
  CKA_LOCAL:              true
  CKA_ALWAYS_SENSITIVE:   true
  CKA_NEVER_EXTRACTABLE:  true          ← ⚠️ PERMANENT!
  CKA_VALUE_LEN:          32 bytes
```

**Diagnosis:**
- ❌ `CKA_EXTRACTABLE: false` - The key cannot be wrapped
- ❌ `CKA_NEVER_EXTRACTABLE: true` - This is permanent, cannot be changed

**Conclusion:** This key was generated without the `--extractable` flag, so it **cannot** be wrapped. We need to create a new key.

---

### Step 3: Create an Extractable Key ✅

Generate a new key with the `--extractable` flag:

```bash
$ docker exec rust-hsm-app rust-hsm-cli gen-symmetric-key \
  --label DEMO_TOKEN --user-pin 123456 \
  --key-label backup-key --bits 256 \
  --extractable

AES-256 key 'backup-key' generated successfully
  Key handle: ObjectHandle { handle: 2 }
```

**Important:** The `--extractable` flag is **critical** for keys you plan to wrap/export.

---

### Step 4: Compare the Keys ⚖️

Use `diff-keys` to see exactly what's different:

```bash
$ docker exec rust-hsm-app rust-hsm-cli diff-keys \
  --label DEMO_TOKEN --user-pin 123456 \
  --key1-label secret-key \
  --key2-label backup-key
```

**Output:**
```
=== Key Comparison ===

Key 1: secret-key
Key 2: backup-key

Attribute                      Key 1                Key 2                Status
────────────────────────────────────────────────────────────────────────────────
Class                          ObjectClass { val: 4 } ObjectClass { val: 4 } ✓
KeyType                        KeyType { val: 31 }  KeyType { val: 31 }  ✓
Token                          true                 true                 ✓
Private                        true                 true                 ✓
Modifiable                     true                 true                 ✓
Local                          true                 true                 ✓
Sign                           true                 true                 ✓
Verify                         true                 true                 ✓
Encrypt                        true                 true                 ✓
Decrypt                        true                 true                 ✓
Wrap                           true                 true                 ✓
Unwrap                         true                 true                 ✓
Derive                         false                false                ✓
Sensitive                      true                 true                 ✓
AlwaysSensitive                true                 true                 ✓
NeverExtractable               true                 false                ✗
Extractable                    false                true                 ✗

✗ Found 2 difference(s):

ℹ NeverExtractable: true vs false
  → Minor difference in key properties

ℹ Extractable: false vs true
  → Minor difference in key properties
```

**Visual Proof:** The side-by-side comparison clearly shows:
- `secret-key`: `NeverExtractable=true`, `Extractable=false` ❌
- `backup-key`: `NeverExtractable=false`, `Extractable=true` ✅

---

### Step 5: Verify the Fix 🎉

Now try wrapping the extractable key:

```bash
$ docker exec rust-hsm-app rust-hsm-cli wrap-key \
  --label DEMO_TOKEN --user-pin 123456 \
  --key-label backup-key \
  --wrapping-key-label wrapping-key \
  --output /app/wrapped.bin

Key 'backup-key' wrapped successfully
  Wrapping key: wrapping-key
  Output: /app/wrapped.bin (40 bytes)
```

**Success!** ✅ The key was wrapped successfully.

---

## Bonus: Fuzzy Key Search 🔦

What if you forgot the exact key name? Use `find-key` with `--show-similar`:

```bash
$ docker exec rust-hsm-app rust-hsm-cli find-key \
  --label DEMO_TOKEN --user-pin 123456 \
  --key-label secrit-key \
  --show-similar
```

**Output:**
```
=== Key Search: 'secrit-key' ===

✗ Exact match not found

Searching for similar keys...

Similar keys found:

1. 'secret-key' (edit distance: 1)
   Type: Secret Key (KeyType { val: 31 })
   Capabilities: sign, verify, encrypt, decrypt

Suggestion: Check for typos or different separators (-, _, space)
```

**Result:** Despite the typo ("secrit" instead of "secret"), fuzzy matching found the correct key!

---

## Summary: Problem → Solution

| Step | Command | Purpose |
|------|---------|---------|
| 1 | `explain-error CKR_KEY_UNEXTRACTABLE --context wrap` | Understand the error and get troubleshooting steps |
| 2 | `inspect-key --key-label secret-key` | Verify the key's CKA_EXTRACTABLE attribute |
| 3 | `gen-symmetric-key --extractable` | Create a new extractable key (the fix) |
| 4 | `diff-keys --key1-label secret-key --key2-label backup-key` | Compare keys to see the difference |
| 5 | `wrap-key --key-label backup-key` | Verify the fix works |

---

## Key Takeaways

### 🎯 **The Problem**
Keys generated **without** `--extractable` flag have:
- `CKA_EXTRACTABLE = false`
- `CKA_NEVER_EXTRACTABLE = true`

These keys **cannot** be wrapped/exported (by design - security feature).

### ✅ **The Solution**
When generating keys that need to be backed up or migrated:
```bash
# ❌ BAD: Cannot be wrapped
rust-hsm-cli gen-symmetric-key --key-label my-key --bits 256

# ✅ GOOD: Can be wrapped
rust-hsm-cli gen-symmetric-key --key-label my-key --bits 256 --extractable
```

### ⚠️ **Security Note**
Non-extractable keys are **more secure** because they cannot leave the HSM. Only use `--extractable` when:
- You need to backup keys
- You need to migrate keys between HSMs
- You need to export keys for external use

For production keys that should stay in the HSM forever, **do not** use `--extractable`.

---

## Other Common Scenarios

This troubleshooting workflow can be adapted for:

1. **CKR_PIN_INCORRECT** - Wrong PIN issues
   ```bash
   rust-hsm-cli explain-error CKR_PIN_INCORRECT --context login
   ```

2. **CKR_KEY_HANDLE_INVALID** - Missing or deleted keys
   ```bash
   rust-hsm-cli find-key --key-label my-key --show-similar
   ```

3. **CKR_SIGNATURE_INVALID** - Signature verification failures
   ```bash
   rust-hsm-cli explain-error CKR_SIGNATURE_INVALID --context verify
   rust-hsm-cli inspect-key --key-label my-key  # Check CKA_VERIFY
   ```

4. **Configuration Drift** - Keys behaving differently in dev vs prod
   ```bash
   rust-hsm-cli diff-keys --key1-label dev-key --key2-label prod-key
   ```

---

## See Also

- [Troubleshooting Commands Reference](commands/troubleshooting.md) - Complete documentation
- [README.md](../README.md) - Main project documentation
- [Command Reference](commands/README.md) - All available commands

---

**Happy Troubleshooting!** 🚀
