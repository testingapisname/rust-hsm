# Information & Discovery Commands

## info

Display PKCS#11 module information including library version and manufacturer.

### Syntax
```bash
rust-hsm-cli info
```

### Flags
None - this command requires no authentication.

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli info
```

### Example Output
```
=== PKCS#11 Module Information ===
Library: /usr/lib/softhsm/libsofthsm2.so
Cryptoki Version: 2.40
Manufacturer: SoftHSM
Library Description: Implementation of PKCS11
Library Version: 2.6
```

---

## list-slots

List all available slots and their token information.

### Syntax
```bash
rust-hsm-cli list-slots
```

### Flags
None - this command requires no authentication.

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli list-slots
```

### Example Output
```
=== Available Slots ===

Slot 0:
  ID: 66658740
  Token Label: TEST
  Token Present: Yes
  Manufacturer ID: SoftHSM project
  Hardware Version: 2.6
  Firmware Version: 2.6

Slot 1:
  ID: 116402022
  Token Label: TEST2
  Token Present: Yes
  Manufacturer ID: SoftHSM project
  Hardware Version: 2.6
  Firmware Version: 2.6

Slot 2:
  ID: 404614813
  Token Label: test-token
  Token Present: Yes
  Manufacturer ID: SoftHSM project
  Hardware Version: 2.6
  Firmware Version: 2.6

Slot 3:
  ID: 3
  Token Present: No
```

---

## list-mechanisms

List all PKCS#11 mechanisms supported by the HSM.

### Syntax
```bash
rust-hsm-cli list-mechanisms [--detailed] [--slot <SLOT_ID>]
```

### Flags
- `--detailed` - Show mechanism capabilities (like p11slotinfo)
- `--slot <SLOT_ID>` - Query specific slot instead of default token

### Example (Simple)
```bash
docker exec rust-hsm-app rust-hsm-cli list-mechanisms
```

### Example Output (Simple)
```
=== Mechanisms for Slot 404614813 ===

AES (7 mechanisms):
  CKM_AES_KEY_GEN
  CKM_AES_ECB
  CKM_AES_CBC
  CKM_AES_CBC_PAD
  CKM_AES_GCM
  CKM_AES_CMAC
  CKM_AES_CMAC_GENERAL

RSA (9 mechanisms):
  CKM_RSA_PKCS_KEY_PAIR_GEN
  CKM_RSA_PKCS
  CKM_RSA_X_509
  CKM_SHA1_RSA_PKCS
  CKM_SHA256_RSA_PKCS
  CKM_SHA384_RSA_PKCS
  CKM_SHA512_RSA_PKCS
  CKM_RSA_PKCS_OAEP
  CKM_SHA1_RSA_PKCS_PSS
```

### Example (Detailed)
```bash
docker exec rust-hsm-app rust-hsm-cli list-mechanisms --detailed
```

### Example Output (Detailed)
```
=== Mechanisms for Slot 404614813 ===
Capability flags: enc=encrypt, dec=decrypt, sig=sign, vfy=verify, hsh=digest,
                  srec=sign_recover, vrec=verify_recover, gen=generate,
                  gkp=generate_key_pair, wra=wrap, unw=unwrap, der=derive

AES (7 mechanisms):
  CKM_AES_KEY_GEN                            gen
  CKM_AES_ECB                                enc dec wra unw
  CKM_AES_CBC                                enc dec wra unw
  CKM_AES_CBC_PAD                            enc dec wra unw
  CKM_AES_GCM                                enc dec
  CKM_AES_CMAC                               sig vfy
  CKM_AES_CMAC_GENERAL                       sig vfy

RSA (9 mechanisms):
  CKM_RSA_PKCS_KEY_PAIR_GEN                  gkp
  CKM_RSA_PKCS                               enc dec sig vfy wra unw
  CKM_SHA256_RSA_PKCS                        sig vfy
  CKM_SHA384_RSA_PKCS                        sig vfy
  CKM_SHA512_RSA_PKCS                        sig vfy
```

### Example (Specific Slot)
```bash
docker exec rust-hsm-app rust-hsm-cli list-mechanisms --slot 404614813 --detailed
```

---

## list-objects

List all objects stored on a token.

### Syntax
```bash
rust-hsm-cli list-objects --user-pin <PIN> [--label <TOKEN>] [--detailed]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--pin-stdin` - Read PIN from stdin
- `--detailed` - Show detailed attributes (p11ls-style output)

### Example (Simple)
```bash
docker exec rust-hsm-app rust-hsm-cli list-objects \
  --label test-token --user-pin userpin
```

### Example Output (Simple)
```
=== Objects on token 'test-token' ===

Object 1:
  Label: test-fp-p256
  Class: ObjectClass { val: 2 }
  ID: 01

Object 2:
  Label: test-rsa-1
  Class: ObjectClass { val: 2 }
  ID: 02

Object 3:
  Label: multi-issue-key
  Class: ObjectClass { val: 3 }
  ID: 03
```

### Example (Detailed)
```bash
docker exec rust-hsm-app rust-hsm-cli list-objects \
  --label test-token --user-pin userpin --detailed
```

### Example Output (Detailed)
```
=== Objects on token 'test-token' ===
pubk/ec    test-fp-p256                             tok,pub,r/w,loc,vfy,enc,wra
pubk/rsa   test-rsa-1                               tok,pub,r/w,loc,vfy,enc,wra,rsa(2048)
prvk/rsa   multi-issue-key                          tok,prv,r/w,loc,sig,dec,unw
pubk/rsa   test-fp-rsa                              tok,pub,r/w,loc,vfy,enc,wra,rsa(2048)
prvk/rsa   test-rsa-1                               tok,prv,r/w,loc,sen,ase,nxt,XTR,sig,dec,unw
prvk/rsa   test-fp-rsa                              tok,prv,r/w,loc,sen,ase,nxt,XTR,sig,dec,unw
pubk/rsa   multi-issue-key                          tok,pub,r/w,loc,vfy,enc,wra,rsa(2048)
prvk/ec    test-fp-p256                             tok,prv,r/w,loc,sen,ase,nxt,XTR,sig,dec,unw
```

### Attribute Flags Explained

**Object Types:**
- `pubk` - Public key
- `prvk` - Private key
- `seck` - Secret (symmetric) key
- `cert` - Certificate
- `data` - Data object

**Key Types:**
- `rsa` - RSA key with size, e.g., `rsa(2048)`
- `ec` - Elliptic Curve key
- `aes` - AES key with size, e.g., `aes(256)`

**Attributes:**
- `tok` - Token object (persistent)
- `prv` - Private (requires authentication)
- `pub` - Public (no authentication needed)
- `r/w` - Read/Write (modifiable)
- `r/o` - Read-only (not modifiable)
- `loc` - Local (generated on device)
- `imp` - Imported (created externally)

**Capabilities:**
- `sig` - Can sign
- `vfy` - Can verify
- `enc` - Can encrypt
- `dec` - Can decrypt
- `wra` - Can wrap keys
- `unw` - Can unwrap keys
- `der` - Can derive keys

**Security Attributes:**
- `sen` - Sensitive (cannot read value)
- `ase` - Always sensitive (never extractable)
- `nxt` - Never extractable
- `XTR` - Not extractable

---

## inspect-key

Display detailed attributes for a specific key including CKA_* values and fingerprint.

### Syntax
```bash
rust-hsm-cli inspect-key --key-label <KEY> --user-pin <PIN> [--label <TOKEN>] [--json]
```

### Flags
- `--label <TOKEN_LABEL>` - Token label (required, or use config default)
- `--user-pin <PIN>` - User PIN (required, unless using --pin-stdin)
- `--key-label <KEY_LABEL>` - Key to inspect (required)
- `--pin-stdin` - Read PIN from stdin
- `--json` - Output in JSON format

### Example
```bash
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label test-token --user-pin userpin --key-label test-rsa-1
```

### Example Output
```
=== Key Inspection: test-rsa-1 ===

FINGERPRINT (SHA-256): ec:bb:93:16:a4:7c:8d:2e:f1:45:b8:c3:7f:9a:d2:e6:11:5c:9b:f3:4a:d8:e2:76:cc:f4:3b:8a:12:65:7e:a9

Key Attributes:
  CKA_CLASS: CKO_PUBLIC_KEY
  CKA_KEY_TYPE: CKK_RSA
  CKA_TOKEN: true
  CKA_PRIVATE: false
  CKA_MODIFIABLE: true
  CKA_LABEL: test-rsa-1
  CKA_ID: 0x02
  CKA_LOCAL: true
  CKA_ENCRYPT: true
  CKA_VERIFY: true
  CKA_WRAP: true
  CKA_MODULUS_BITS: 2048
  CKA_PUBLIC_EXPONENT: 0x010001 (65537)
```

### Example (Private Key)
```bash
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label test-token --user-pin userpin --key-label test-rsa-1
```

### Example Output (Private Key)
```
=== Key Inspection: test-rsa-1 ===

Key Attributes:
  CKA_CLASS: CKO_PRIVATE_KEY
  CKA_KEY_TYPE: CKK_RSA
  CKA_TOKEN: true
  CKA_PRIVATE: true
  CKA_MODIFIABLE: true
  CKA_LABEL: test-rsa-1
  CKA_ID: 0x02
  CKA_LOCAL: true
  CKA_SENSITIVE: true
  CKA_EXTRACTABLE: false
  CKA_ALWAYS_SENSITIVE: true
  CKA_NEVER_EXTRACTABLE: true
  CKA_SIGN: true
  CKA_DECRYPT: true
  CKA_UNWRAP: true
  CKA_MODULUS_BITS: 2048
```

### Example (JSON Output)
```bash
docker exec rust-hsm-app rust-hsm-cli inspect-key \
  --label test-token --user-pin userpin --key-label test-rsa-1 --json
```

### Example JSON Output
```json
{
  "label": "test-rsa-1",
  "class": "CKO_PUBLIC_KEY",
  "key_type": "CKK_RSA",
  "fingerprint": "ec:bb:93:16:a4:7c:8d:2e:f1:45:b8:c3:7f:9a:d2:e6:11:5c:9b:f3:4a:d8:e2:76:cc:f4:3b:8a:12:65:7e:a9",
  "attributes": {
    "CKA_TOKEN": true,
    "CKA_PRIVATE": false,
    "CKA_MODIFIABLE": true,
    "CKA_LOCAL": true,
    "CKA_ENCRYPT": true,
    "CKA_VERIFY": true,
    "CKA_WRAP": true,
    "CKA_MODULUS_BITS": 2048,
    "CKA_PUBLIC_EXPONENT": "0x010001"
  }
}
```

---

## Notes

### Fingerprints

SHA-256 fingerprints are displayed for **public keys only** and are calculated from:
- **RSA**: Hash of modulus + public exponent
- **ECDSA**: Hash of EC parameters + EC point

Fingerprints are useful for:
- Verifying public key integrity
- Comparing keys across systems
- Identifying keys uniquely
- Detecting key tampering

Format: Colon-separated hex (64 hex digits with colons), similar to SSH fingerprints.
