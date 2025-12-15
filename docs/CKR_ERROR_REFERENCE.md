# PKCS#11 CKR Error Code Reference

Complete reference guide for all PKCS#11 CKR (Cryptoki Return) error codes with troubleshooting guidance.

---

## Quick Reference

Use the `explain-error` command for interactive troubleshooting:

```bash
# By error name
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_PIN_INCORRECT

# By hex code
docker exec rust-hsm-app rust-hsm-cli explain-error 0xA0

# By decimal code
docker exec rust-hsm-app rust-hsm-cli explain-error 160

# With operation context for specific guidance
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_KEY_HANDLE_INVALID --context sign
```

---

## Error Categories

- [Success Codes](#success-codes)
- [General Errors (0x01-0x09)](#general-errors)
- [Attribute Errors (0x10-0x1F)](#attribute-errors)
- [Data Errors (0x20-0x2F)](#data-errors)
- [Device Errors (0x30-0x4F)](#device-errors)
- [Function Errors (0x50-0x6F)](#function-errors)
- [Key Errors (0x60-0x7F)](#key-errors)
- [Mechanism Errors (0x70-0x8F)](#mechanism-errors)
- [Object Errors (0x80-0x9F)](#object-errors)
- [PIN Errors (0xA0-0xAF)](#pin-errors)
- [Session Errors (0xB0-0xCF)](#session-errors)
- [Signature/Encryption Errors (0xC0-0xDF)](#signatureencryption-errors)
- [Token Errors (0xE0-0xFF)](#token-errors)
- [User Errors (0x100-0x11F)](#user-errors)
- [Wrapping Errors (0x110-0x11F)](#wrapping-errors)
- [Buffer & Misc Errors (0x150+)](#buffer--misc-errors)

---

## Success Codes

### CKR_OK (0x00000000, 0)
**Meaning**: Success - operation completed without error

**No troubleshooting needed** - this is the success code.

---

## General Errors

### CKR_CANCEL (0x00000001, 1)
**Meaning**: Operation was cancelled

**Common Causes**:
- User cancelled the operation
- Application requested cancellation
- Timeout triggered cancellation

**Solutions**:
- Retry the operation if cancellation was unintended
- Check application timeout settings
- Verify no user interruption occurred

---

### CKR_HOST_MEMORY (0x00000002, 2)
**Meaning**: Insufficient host memory

**Common Causes**:
- System out of memory
- Memory allocation failed
- Too many concurrent operations
- Memory leak in application

**Solutions**:
```bash
# Check system memory
free -h

# Restart HSM application to free memory
docker compose restart

# Close other applications
# Monitor for memory leaks in your application
```

---

### CKR_SLOT_ID_INVALID (0x00000003, 3)
**Meaning**: Invalid slot ID specified

**Common Causes**:
- Slot number doesn't exist
- Using slot number instead of finding by token label
- HSM not connected or initialized
- Wrong slot index

**Solutions**:
```bash
# List all available slots
docker exec rust-hsm-app rust-hsm-cli list-slots

# Use token label instead of slot number
# Always verify slot exists before operations
```

---

### CKR_GENERAL_ERROR (0x00000005, 5)
**Meaning**: General unspecified error

**Common Causes**:
- Hardware failure
- HSM internal error
- Unexpected condition
- Vendor-specific issue

**Solutions**:
```bash
# Check HSM logs
docker logs rust-hsm-app

# Verify HSM connectivity
docker exec rust-hsm-app rust-hsm-cli info

# Check HSM documentation for vendor-specific errors
# Restart HSM if persistent
docker compose restart
```

---

### CKR_FUNCTION_FAILED (0x00000006, 6)
**Meaning**: Function failed for unspecified reason

**Common Causes**:
- Operation failed on HSM
- Mechanism not supported properly
- Key attributes don't match operation
- Internal HSM state issue

**Solutions**:
```bash
# Check mechanism support
docker exec rust-hsm-app rust-hsm-cli list-mechanisms

# Verify key attributes
docker exec rust-hsm-app rust-hsm-cli inspect-key --key-label <name>

# Test with known-good configuration
# Check HSM logs for details
```

---

### CKR_ARGUMENTS_BAD (0x00000007, 7)
**Meaning**: Invalid arguments provided to function

**Common Causes**:
- NULL pointer passed
- Invalid parameter value
- Incorrect argument combination
- Buffer size mismatch

**Solutions**:
- Verify all required parameters are provided
- Check parameter types match expected values
- Review API documentation for correct usage
- Validate buffer sizes

---

### CKR_NO_EVENT (0x00000008, 8)
**Meaning**: No event available (polling functions)

**Common Causes**:
- No events in queue
- Timeout expired waiting for event
- Non-blocking call with no pending events

**Solutions**:
- Normal condition for polling - retry if needed
- Increase timeout if using timed waits
- Check event callback registration

---

### CKR_NEED_TO_CREATE_THREADS (0x00000009, 9)
**Meaning**: Library cannot create OS threads

**Common Causes**:
- Application must create threads
- OS thread limit reached
- Thread creation failed

**Solutions**:
- Initialize PKCS#11 with application-created threads
- Check system thread limits
- Use `CInitializeArgs` with threading model

---

## Attribute Errors

### CKR_ATTRIBUTE_READ_ONLY (0x00000010, 16)
**Meaning**: Attribute is read-only and cannot be modified

**Common Causes**:
- Attempting to modify immutable attribute
- CKA_PRIVATE, CKA_MODIFIABLE set to false
- Token-enforced attribute restrictions

**Solutions**:
- Cannot modify read-only attributes
- Create new object with desired attributes
- Check attribute documentation for mutability

---

### CKR_ATTRIBUTE_SENSITIVE (0x00000011, 17)
**Meaning**: Attribute is sensitive and cannot be read

**Common Causes**:
- Attempting to read CKA_PRIVATE_EXPONENT
- Sensitive key material requested
- CKA_SENSITIVE=true prevents extraction

**Solutions**:
- Sensitive attributes cannot be read (by design)
- Use key wrapping to export if allowed
- This is a security feature, not an error

---

### CKR_ATTRIBUTE_TYPE_INVALID (0x00000012, 18)
**Meaning**: Invalid or unsupported attribute type

**Common Causes**:
- Attribute not supported for this object class
- Vendor-specific attribute not recognized
- Wrong attribute for key type

**Solutions**:
```bash
# Check supported attributes
docker exec rust-hsm-app rust-hsm-cli inspect-key --key-label <name>

# Review PKCS#11 specification for object class
# Use standard attributes only
```

---

### CKR_ATTRIBUTE_VALUE_INVALID (0x00000013, 19)
**Meaning**: Invalid attribute value

**Common Causes**:
- Value out of range
- Conflicting attribute values (e.g., CKA_ENCRYPT=true on private key)
- Type mismatch
- Invalid boolean/numeric value

**Solutions**:
- Verify value is appropriate for attribute
- Check for conflicting attributes
- Consult PKCS#11 spec for valid values
- Use standard key generation templates

---

## Data Errors

### CKR_DATA_INVALID (0x00000020, 32)
**Meaning**: Data is invalid or corrupted

**Common Causes**:
- Input data malformed
- Data doesn't match expected format
- Encryption/padding error
- Base64 decode failure

**Solutions**:
```bash
# Verify input file is not corrupted
hexdump -C input.bin | head

# Check file size
ls -lh input.bin

# Regenerate data if possible
# Verify encoding format (base64, PEM, DER)
```

---

### CKR_DATA_LEN_RANGE (0x00000021, 33)
**Meaning**: Data length is out of valid range

**Common Causes**:
- Data too short for operation
- Data too long for key size
- Doesn't match block size requirements
- RSA plaintext exceeds (key_size - padding_overhead)

**Solutions**:
```bash
# Check data size constraints for operation
# For RSA-2048 PKCS#1: max 245 bytes plaintext
# For AES-GCM: multiples of block size

# Verify data length
wc -c input.bin

# Use appropriate key size for data
# Chunk large data for RSA
```

---

### CKR_ENCRYPTED_DATA_INVALID (0x00000040, 64)
**Meaning**: Encrypted data is invalid

**Common Causes**:
- Wrong decryption key
- Data corrupted during transmission
- Wrong mechanism used
- IV/parameter mismatch

**Solutions**:
- Verify correct key is being used
- Check data integrity
- Ensure same mechanism for encrypt/decrypt
- Verify IV matches encryption

---

### CKR_ENCRYPTED_DATA_LEN_RANGE (0x00000041, 65)
**Meaning**: Encrypted data length invalid

**Common Causes**:
- Encrypted data truncated
- Wrong block size
- Padding error

**Solutions**:
- Verify complete encrypted data
- Check for data corruption
- Validate block alignment

---

## Device Errors

### CKR_DEVICE_ERROR (0x00000030, 48)
**Meaning**: Device error - hardware problem

**Common Causes**:
- HSM hardware failure
- Connection lost
- Device reset required
- Physical connectivity issue

**Solutions**:
```bash
# Check HSM connectivity
docker exec rust-hsm-app rust-hsm-cli info

# Restart HSM
docker compose restart

# Check physical connections (for hardware HSMs)
# Review HSM error logs
docker logs rust-hsm-app
```

---

### CKR_DEVICE_MEMORY (0x00000031, 49)
**Meaning**: Device is out of memory

**Common Causes**:
- HSM storage full
- Too many objects on token
- Memory leak in HSM firmware
- Session memory exhausted

**Solutions**:
```bash
# List and delete unused keys
docker exec rust-hsm-app rust-hsm-cli list-objects --detailed
docker exec rust-hsm-app rust-hsm-cli delete-key --key-label unused

# Clean up test tokens
docker exec -e AUTO_CONFIRM=yes rust-hsm-app /app/cleanup-test-tokens.sh

# For persistent issues: reinitialize token (data loss!)
# Check HSM documentation for memory limits
```

---

### CKR_DEVICE_REMOVED (0x00000032, 50)
**Meaning**: Device has been removed

**Common Causes**:
- USB HSM unplugged
- Network HSM disconnected
- Container stopped

**Solutions**:
```bash
# Verify HSM is connected
docker ps | grep rust-hsm

# Restart container
docker compose up -d

# Check USB connection (hardware HSM)
# Verify network connectivity (network HSM)
```

---

## Function Errors

### CKR_FUNCTION_NOT_PARALLEL (0x00000051, 81)
**Meaning**: Function cannot be called in parallel

**Common Causes**:
- Concurrent calls to non-thread-safe function
- Multiple operations on same session

**Solutions**:
- Serialize operations
- Use separate sessions for parallel operations
- Implement proper locking

---

### CKR_FUNCTION_NOT_SUPPORTED (0x00000054, 84)
**Meaning**: Function is not supported by this token

**Common Causes**:
- Mechanism not available
- Feature not implemented by vendor
- Operation not supported on this token type

**Solutions**:
```bash
# Check supported mechanisms
docker exec rust-hsm-app rust-hsm-cli list-mechanisms

# Verify token capabilities
docker exec rust-hsm-app rust-hsm-cli info

# Use alternative mechanism if available
# Check HSM documentation for feature support
```

---

## Key Errors

### CKR_KEY_HANDLE_INVALID (0x00000060, 96)
**Meaning**: The specified key handle is not valid

**Common Causes**:
- Key was deleted
- Session closed invalidating handle
- Wrong key type (public vs private)
- Key not accessible in current session
- Handle from different session used

**Solutions**:
```bash
# Search for the key
docker exec rust-hsm-app rust-hsm-cli find-key --label TOKEN --user-pin PIN --key-label key-name --show-similar

# List all objects
docker exec rust-hsm-app rust-hsm-cli list-objects --label TOKEN --user-pin PIN --detailed

# Verify key exists before use
# Re-login if session expired
```

---

### CKR_KEY_SIZE_RANGE (0x00000062, 98)
**Meaning**: Key size is outside valid range

**Common Causes**:
- Key too small (insecure, e.g., RSA-512)
- Key too large (not supported, e.g., RSA-16384)
- Non-standard key size

**Solutions**:
```bash
# Use standard key sizes:
# RSA: 2048, 3072, 4096
# AES: 128, 192, 256
# ECDSA: P-256, P-384, P-521

# Generate with standard size
docker exec rust-hsm-app rust-hsm-cli gen-keypair \
  --key-type rsa --key-size 2048
```

---

### CKR_KEY_TYPE_INCONSISTENT (0x00000063, 99)
**Meaning**: Key type inconsistent with operation

**Common Causes**:
- Using symmetric key for asymmetric operation
- Using public key for signing
- Mechanism requires different key type
- Wrong key class for operation

**Solutions**:
```bash
# Verify key type
docker exec rust-hsm-app rust-hsm-cli inspect-key --key-label <name>

# Use correct key type for operation:
# - RSA/ECDSA for sign/verify
# - AES for symmetric encryption
# - Use private key for signing, public key for verifying
```

---

### CKR_KEY_NOT_NEEDED (0x00000064, 100)
**Meaning**: Key not needed for this operation

**Common Causes**:
- Key provided for operation that doesn't use keys
- Hash operation given encryption key
- Digest mechanism with key parameter

**Solutions**:
- Remove key parameter from operation
- Use appropriate mechanism for key-based operations

---

### CKR_KEY_CHANGED (0x00000065, 101)
**Meaning**: Key has changed since operation began

**Common Causes**:
- Key modified during multi-part operation
- Key deleted and recreated with same label
- Concurrent modification

**Solutions**:
- Complete operations before modifying keys
- Use immutable keys for critical operations
- Retry operation with current key

---

### CKR_KEY_NEEDED (0x00000066, 102)
**Meaning**: Key is required but not provided

**Common Causes**:
- Encryption without key
- Signing without key handle
- Missing key parameter

**Solutions**:
- Provide key for operation
- Verify key exists and is accessible
- Check operation requires key

---

### CKR_KEY_INDIGESTIBLE (0x00000067, 103)
**Meaning**: Key cannot be digested

**Common Causes**:
- Attempting to hash a key
- Key type doesn't support digest
- Sensitive key cannot be hashed

**Solutions**:
- Don't attempt to hash keys directly
- Use key fingerprinting for identification
- Export public key if hashing is needed

---

### CKR_KEY_FUNCTION_NOT_PERMITTED (0x00000068, 104)
**Meaning**: Key cannot be used for this operation

**Common Causes**:
- CKA_SIGN=false for signing operation
- CKA_DECRYPT=false for decryption
- CKA_WRAP=false for wrapping
- Key usage restrictions

**Solutions**:
```bash
# Check key attributes
docker exec rust-hsm-app rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label <name>

# Look for:
# CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT
# CKA_WRAP, CKA_UNWRAP

# Regenerate key with correct usage attributes
# Cannot modify existing key attributes
```

---

### CKR_KEY_NOT_WRAPPABLE (0x00000069, 105)
**Meaning**: Key cannot be wrapped

**Common Causes**:
- CKA_EXTRACTABLE=false
- CKA_WRAP_WITH_TRUSTED=true but wrapping key not trusted
- Key policy prevents wrapping

**Solutions**:
```bash
# Check if key is extractable
docker exec rust-hsm-app rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label <name> | grep EXTRACTABLE

# Regenerate with --extractable if needed
# Some keys intentionally non-extractable for security
```

---

### CKR_KEY_UNEXTRACTABLE (0x00000117, 279)
**Meaning**: Key cannot be extracted (wrapped)

**Common Causes**:
- CKA_EXTRACTABLE=false
- Key marked non-extractable for security
- Cannot wrap sensitive keys
- Token policy prevents extraction

**Solutions**:
```bash
# Verify extractable attribute
docker exec rust-hsm-app rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label <name>

# If intentional: this is a security feature
# If unintentional: regenerate with --extractable
docker exec rust-hsm-app rust-hsm-cli gen-symmetric --label TOKEN --user-pin PIN --key-label new-key --key-size 256 --extractable
```

---

## Mechanism Errors

### CKR_MECHANISM_INVALID (0x00000070, 112)
**Meaning**: Invalid mechanism specified

**Common Causes**:
- Mechanism not supported by token
- Wrong mechanism for key type
- Mechanism code incorrect
- Vendor-specific mechanism unavailable

**Solutions**:
```bash
# Check supported mechanisms
docker exec rust-hsm-app rust-hsm-cli list-mechanisms --detailed

# Verify mechanism for key type:
# - CKM_RSA_PKCS for RSA keys
# - CKM_ECDSA for ECDSA keys  
# - CKM_AES_GCM for AES keys

# Use standard mechanism codes
```

---

### CKR_MECHANISM_PARAM_INVALID (0x00000071, 113)
**Meaning**: Invalid mechanism parameters

**Common Causes**:
- Wrong IV length for AES-GCM (should be 12 bytes)
- Invalid GCM tag length
- NULL parameter when required
- Parameter structure incorrect

**Solutions**:
```bash
# For AES-GCM: use 12-byte IV
# For RSA-OAEP: specify hash algorithm
# For ECDSA: no parameters needed

# Verify parameter structure matches specification
# Use library defaults when unsure
```

---

## Object Errors

### CKR_OBJECT_HANDLE_INVALID (0x00000082, 130)
**Meaning**: Invalid object handle

**Common Causes**:
- Object was deleted
- Handle from different session
- Session closed
- Handle never valid

**Solutions**:
```bash
# List current objects
docker exec rust-hsm-app rust-hsm-cli list-objects --label TOKEN --user-pin PIN --detailed

# Re-find object if needed
# Verify session is still open
# Don't cache handles across sessions
```

---

### CKR_OPERATION_ACTIVE (0x00000090, 144)
**Meaning**: Operation is already active

**Common Causes**:
- Starting new operation without finishing previous
- Multi-part operation in progress
- Concurrent operations on same session

**Solutions**:
- Finish or cancel current operation first
- Use separate sessions for parallel operations
- Call C_xxxFinal to complete multi-part operation

---

### CKR_OPERATION_NOT_INITIALIZED (0x00000091, 145)
**Meaning**: Operation has not been initialized

**Common Causes**:
- Calling C_xxxUpdate without C_xxxInit
- Calling C_xxxFinal without starting operation
- Session lost operation state

**Solutions**:
- Call C_xxxInit before C_xxxUpdate/Final
- Verify session is valid
- Restart operation from beginning

---

## PIN Errors

### CKR_PIN_INCORRECT (0x000000A0, 160)
**Meaning**: PIN is incorrect

**Common Causes**:
- Wrong PIN provided
- Using user PIN when SO PIN required (or vice versa)
- PIN typo or wrong value
- PIN format incorrect

**Solutions**:
```bash
# Verify you're using correct PIN type
# For init-token: need SO PIN
# For login operations: need user PIN

# Check token status
docker exec rust-hsm-app rust-hsm-cli list-slots

# Reset user PIN with SO PIN
docker exec rust-hsm-app rust-hsm-cli init-pin \
  --label TOKEN --so-pin SO_PIN --user-pin NEW_PIN

# For SO PIN: must reinitialize token (data loss!)
```

---

### CKR_PIN_INVALID (0x000000A1, 161)
**Meaning**: PIN format is invalid

**Common Causes**:
- PIN too short (minimum length not met)
- PIN too long (exceeds maximum)
- Invalid characters in PIN
- PIN doesn't meet complexity requirements

**Solutions**:
```bash
# Check PIN requirements:
# Minimum length: typically 4-8 characters
# Maximum length: typically 64 characters
# Allowed characters: depends on token

# Use alphanumeric PIN
# Avoid special characters unless required
```

---

### CKR_PIN_LEN_RANGE (0x000000A2, 162)
**Meaning**: PIN length is outside valid range

**Common Causes**:
- PIN too short
- PIN too long
- Length requirements not met

**Solutions**:
```bash
# For SoftHSM2:
# Minimum: 4 characters
# Maximum: 255 characters

# Use reasonable PIN length (8-20 characters)
# Check token-specific requirements
```

---

### CKR_PIN_EXPIRED (0x000000A3, 163)
**Meaning**: PIN has expired and must be changed

**Common Causes**:
- PIN age limit reached
- Token policy requires PIN rotation
- Administrative expiration

**Solutions**:
```bash
# Change PIN
docker exec rust-hsm-app rust-hsm-cli change-pin \
  --label TOKEN --old-pin OLD --new-pin NEW

# Or reset with SO PIN
docker exec rust-hsm-app rust-hsm-cli init-pin \
  --label TOKEN --so-pin SO_PIN --user-pin NEW_PIN
```

---

### CKR_PIN_LOCKED (0x000000A4, 164)
**Meaning**: PIN is locked due to too many failed attempts

**Common Causes**:
- Exceeded failed PIN attempts (typically 3-10)
- Brute force protection triggered
- Administrative lock

**Solutions**:
```bash
# Check token status
docker exec rust-hsm-app rust-hsm-cli list-slots

# Unlock with SO PIN
docker exec rust-hsm-app rust-hsm-cli init-pin \
  --label TOKEN --so-pin SO_PIN --user-pin NEW_PIN

# Wait for auto-unlock period (if configured)
# Contact HSM administrator for unlock
```

---

## Session Errors

### CKR_SESSION_CLOSED (0x000000B0, 176)
**Meaning**: Session is closed

**Common Causes**:
- Session explicitly closed
- Timeout occurred
- Token removed
- Application terminated session

**Solutions**:
- Open new session
- Re-login if needed
- Check session timeout settings
- Implement session keep-alive

---

### CKR_SESSION_COUNT (0x000000B1, 177)
**Meaning**: Too many sessions open

**Common Causes**:
- Exceeded token session limit
- Sessions not being closed properly
- Session leak in application

**Solutions**:
```bash
# Close unused sessions
# Restart application to cleanup
docker compose restart

# Implement proper session lifecycle
# Use try-finally blocks to ensure cleanup
# Check token session limits
```

---

### CKR_SESSION_HANDLE_INVALID (0x000000B3, 179)
**Meaning**: Invalid session handle

**Common Causes**:
- Session doesn't exist
- Using closed session
- Session expired
- Handle from different process

**Solutions**:
- Verify session is open before use
- Re-create session if expired
- Don't share session handles across processes

---

### CKR_SESSION_PARALLEL_NOT_SUPPORTED (0x000000B4, 180)
**Meaning**: Parallel sessions not supported

**Common Causes**:
- Token doesn't support concurrent sessions
- Feature not implemented

**Solutions**:
- Use serial operations
- Queue operations
- Check token capabilities

---

### CKR_SESSION_READ_ONLY (0x000000B5, 181)
**Meaning**: Session is read-only, cannot modify objects

**Common Causes**:
- Opened RO session for write operation
- Attempting to create/modify objects in RO session
- Token in RO state

**Solutions**:
```bash
# Open RW session for write operations
# Close RO session first
# Use appropriate session flags

# Operations requiring RW session:
# - Creating keys
# - Deleting objects
# - Modifying attributes
```

---

### CKR_SESSION_EXISTS (0x000000B6, 182)
**Meaning**: Session already exists for this token

**Common Causes**:
- Attempting to create duplicate session
- Session limit per token reached
- Token already has exclusive session

**Solutions**:
- Reuse existing session
- Close previous session first
- Check session management logic

---

### CKR_SESSION_READ_WRITE_SO_EXISTS (0x000000B7, 183)
**Meaning**: SO session already exists, cannot open

**Common Causes**:
- Read-write SO session already open
- Token allows only one SO session
- Attempting concurrent SO access

**Solutions**:
- Close existing SO session
- Wait for SO session to close
- Use separate token for concurrent access

---

## Signature/Encryption Errors

### CKR_SIGNATURE_INVALID (0x000000C0, 192)
**Meaning**: Signature verification failed

**Common Causes**:
- Data was modified after signing
- Wrong key used for verification
- Signature corrupted or truncated
- Data and signature don't match
- Wrong mechanism used

**Solutions**:
```bash
# Verify data hasn't been modified
# Check signature file integrity
# Ensure correct public key
# Use same mechanism for sign and verify

# Test with known-good signature
# Regenerate signature if necessary
```

---

### CKR_SIGNATURE_LEN_RANGE (0x000000C1, 193)
**Meaning**: Signature length is invalid

**Common Causes**:
- Signature truncated
- Wrong signature buffer size
- Mechanism produces different length

**Solutions**:
- Verify signature is complete
- Check expected signature length for mechanism
- RSA-2048: 256 bytes
- ECDSA P-256: 64 bytes
- ECDSA P-384: 96 bytes

---

## Token Errors

### CKR_TOKEN_NOT_PRESENT (0x000000E0, 224)
**Meaning**: Token is not present in slot

**Common Causes**:
- HSM disconnected
- Token not initialized
- Wrong slot number
- Container stopped
- USB device unplugged

**Solutions**:
```bash
# Verify token exists
docker exec rust-hsm-app rust-hsm-cli list-slots

# Check container is running
docker ps | grep rust-hsm

# Initialize token if needed
docker exec rust-hsm-app rust-hsm-cli init-token \
  --label TOKEN --so-pin 12345678

# Restart container
docker compose restart
```

---

### CKR_TOKEN_NOT_RECOGNIZED (0x000000E1, 225)
**Meaning**: Token is not recognized

**Common Causes**:
- Token format incompatible
- Wrong PKCS#11 module
- Token corrupted
- Unsupported token type

**Solutions**:
```bash
# Verify correct PKCS#11 module
# For SoftHSM2: /usr/lib/softhsm/libsofthsm2.so

# Check token format
# Reinitialize if corrupted (data loss!)
docker exec rust-hsm-app rust-hsm-cli init-token \
  --label TOKEN --so-pin 12345678
```

---

### CKR_TOKEN_WRITE_PROTECTED (0x000000E2, 226)
**Meaning**: Token is write-protected

**Common Causes**:
- Physical write-protect switch enabled
- Token in read-only mode
- Administrative protection

**Solutions**:
- Check physical write-protect switch
- Verify token permissions
- Contact administrator for write access
- Use different token for write operations

---

## User Errors

### CKR_USER_ALREADY_LOGGED_IN (0x00000100, 256)
**Meaning**: User is already logged in

**Common Causes**:
- Attempted second login without logout
- Session already authenticated
- Application state management issue

**Solutions**:
- Logout first, then login again
- Check session state before login
- Reuse existing authenticated session
- Implement proper session tracking

---

### CKR_USER_NOT_LOGGED_IN (0x00000101, 257)
**Meaning**: User must log in first

**Common Causes**:
- No C_Login called
- Session expired
- PIN not provided
- Private key access requires login
- Logout occurred

**Solutions**:
```bash
# Login before private key operations
docker exec rust-hsm-app rust-hsm-cli sign \
  --label TOKEN --user-pin PIN \
  --key-label key --input data.txt

# Operations requiring login:
# - Private key operations
# - Creating objects
# - Deleting objects
```

---

### CKR_USER_PIN_NOT_INITIALIZED (0x00000102, 258)
**Meaning**: User PIN has not been set

**Common Causes**:
- Token initialized but user PIN not set
- Only SO PIN exists
- Fresh token initialization

**Solutions**:
```bash
# Initialize user PIN with SO PIN
docker exec rust-hsm-app rust-hsm-cli init-pin \
  --label TOKEN --so-pin SO_PIN --user-pin USER_PIN

# Check token status
docker exec rust-hsm-app rust-hsm-cli list-slots
```

---

### CKR_USER_TYPE_INVALID (0x00000103, 259)
**Meaning**: Invalid user type

**Common Causes**:
- Wrong user type for operation
- Using CKU_USER when CKU_SO required
- Using CKU_SO when CKU_USER required
- Invalid user type constant

**Solutions**:
- Use CKU_USER for normal operations
- Use CKU_SO for PIN initialization
- Verify login user type matches operation

---

### CKR_USER_ANOTHER_ALREADY_LOGGED_IN (0x00000104, 260)
**Meaning**: Another user is already logged in

**Common Causes**:
- SO logged in, attempting user login
- User logged in, attempting SO login
- Session has different user type

**Solutions**:
- Logout current user first
- Use separate session for different user type
- Complete SO operations before user operations

---

### CKR_USER_TOO_MANY_TYPES (0x00000105, 261)
**Meaning**: Too many user types logged in

**Common Causes**:
- Multiple user types in same session
- Session state conflict

**Solutions**:
- Use separate sessions for different user types
- Logout before switching user type

---

## Wrapping Errors

### CKR_WRAPPED_KEY_INVALID (0x00000110, 272)
**Meaning**: Wrapped key is invalid or corrupted

**Common Causes**:
- Wrong unwrapping key
- Wrapped data corrupted
- Key wrap format mismatch
- Wrong mechanism for unwrapping

**Solutions**:
```bash
# Verify wrapping key is correct
# Check wrapped data integrity
# Ensure same mechanism for wrap/unwrap
# Regenerate wrapped key if corrupted

# Test with known-good wrapped key
hexdump -C wrapped-key.bin
```

---

### CKR_WRAPPED_KEY_LEN_RANGE (0x00000112, 274)
**Meaning**: Wrapped key length invalid

**Common Causes**:
- Wrapped key truncated
- Wrong key size
- Wrap format incorrect

**Solutions**:
- Verify complete wrapped key data
- Check expected wrapped length
- AES-wrapped key: multiple of 8 bytes + 8

---

### CKR_WRAPPING_KEY_HANDLE_INVALID (0x00000113, 275)
**Meaning**: Wrapping key handle is invalid

**Common Causes**:
- Wrapping key deleted
- Wrong key type for wrapping
- Session expired

**Solutions**:
```bash
# Verify wrapping key exists
docker exec rust-hsm-app rust-hsm-cli list-objects --label TOKEN --user-pin PIN

# Check key has CKA_WRAP=true
docker exec rust-hsm-app rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label wrap-key

# Regenerate wrapping key if needed
```

---

### CKR_WRAPPING_KEY_SIZE_RANGE (0x00000114, 276)
**Meaning**: Wrapping key size invalid

**Common Causes**:
- Wrapping key too small
- Key size doesn't match mechanism requirements

**Solutions**:
- Use AES-256 for wrapping (32 bytes)
- Verify key size matches mechanism
- Regenerate with correct size

---

### CKR_WRAPPING_KEY_TYPE_INCONSISTENT (0x00000115, 277)
**Meaning**: Wrapping key type wrong for mechanism

**Common Causes**:
- Using RSA key with AES wrap mechanism
- Wrong key type for wrap operation

**Solutions**:
- Use AES key for CKM_AES_KEY_WRAP
- Use RSA key for RSA-based wrapping
- Match key type to mechanism

---

## Buffer & Misc Errors

### CKR_BUFFER_TOO_SMALL (0x00000150, 336)
**Meaning**: Output buffer is too small

**Common Causes**:
- Provided buffer too small for result
- Need to query size first
- Signature/ciphertext larger than buffer

**Solutions**:
```bash
# Query required size first (pass NULL buffer)
# Allocate buffer with queried size
# Then call operation again with proper buffer

# Common sizes:
# RSA-2048 signature: 256 bytes
# ECDSA P-256 signature: 64 bytes
# AES-GCM ciphertext: plaintext + 16 bytes tag
```

---

### CKR_INFORMATION_SENSITIVE (0x00000180, 384)
**Meaning**: Information is sensitive and cannot be revealed

**Common Causes**:
- Attempting to read sensitive attribute
- Private key material requested
- Security policy prevents disclosure

**Solutions**:
- This is intentional security feature
- Use alternative methods (fingerprints, public keys)
- Cannot extract sensitive material by design

---

### CKR_RANDOM_NO_RNG (0x00000121, 289)
**Meaning**: No random number generator available

**Common Causes**:
- RNG not initialized
- Hardware RNG failed
- Entropy pool empty

**Solutions**:
```bash
# Check RNG availability
docker exec rust-hsm-app rust-hsm-cli random --length 32

# Restart HSM to reinitialize RNG
docker compose restart

# Check system entropy
cat /proc/sys/kernel/random/entropy_avail
```

---

### CKR_RANDOM_SEED_NOT_SUPPORTED (0x00000120, 288)
**Meaning**: Random seeding not supported

**Common Causes**:
- Token doesn't allow seeding
- Feature not implemented

**Solutions**:
- Don't attempt to seed RNG
- Use token's built-in RNG
- This is normal for many HSMs

---

### CKR_SAVED_STATE_INVALID (0x00000160, 352)
**Meaning**: Saved state is invalid

**Common Causes**:
- State data corrupted
- Wrong session for state
- State format incompatible

**Solutions**:
- Discard saved state
- Restart operation from beginning
- Don't rely on saved states across sessions

---

## Vendor-Specific Errors

### CKR_VENDOR_DEFINED (0x80000000+)
**Meaning**: Vendor-specific error code

**Common Causes**:
- Implementation-specific error
- Hardware-specific condition
- Custom error code

**Solutions**:
```bash
# Check vendor documentation
# Look for error code in HSM manual
# Contact vendor support

# Get error explanation
docker exec rust-hsm-app rust-hsm-cli explain-error <code>
```

---

## Context-Specific Troubleshooting

The `explain-error` command provides operation-specific guidance when you specify a `--context`:

### Signing Operations

```bash
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_KEY_HANDLE_INVALID --context sign
```

**Troubleshooting Steps:**
- → Verify key exists: `rust-hsm-cli list-objects --label TOKEN --user-pin PIN --detailed`
- → Check key attributes: `rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label <name>`
- → Ensure CKA_SIGN=true on private key
- → Test operation: `rust-hsm-cli sign --label TOKEN --user-pin PIN --key-label <name> --input test.txt`
- → Check mechanism support: `rust-hsm-cli list-mechanisms --detailed`

---

### Verification Operations

```bash
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_SIGNATURE_INVALID --context verify
```

**Troubleshooting Steps:**
- → Verify public key exists and has CKA_VERIFY=true
- → Ensure data hasn't been modified since signing
- → Check signature file is correct and complete
- → Verify same mechanism used for sign and verify

---

### Encryption Operations

```bash
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_DATA_LEN_RANGE --context encrypt
```

**Troubleshooting Steps:**
- → Check key has CKA_ENCRYPT=true
- → Verify data size within key limits (RSA: max 245 bytes for 2048-bit)
- → Check mechanism is appropriate for key type
- → For symmetric: ensure proper IV/parameters provided

---

### Decryption Operations

```bash
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_ENCRYPTED_DATA_INVALID --context decrypt
```

**Troubleshooting Steps:**
- → Check private key has CKA_DECRYPT=true
- → Verify encrypted data is not corrupted
- → Ensure correct key is being used
- → Check mechanism matches encryption mechanism

---

### Login Operations

```bash
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_PIN_INCORRECT --context login
```

**Troubleshooting Steps:**
- → Verify correct PIN (user vs SO PIN)
- → Check if PIN is locked: `rust-hsm-cli list-slots`
- → Ensure token is initialized: `rust-hsm-cli list-slots`
- → If locked, unlock with SO PIN or wait for timeout

---

### Key Wrapping Operations

```bash
docker exec rust-hsm-app rust-hsm-cli explain-error CKR_KEY_UNEXTRACTABLE --context wrap
```

**Troubleshooting Steps:**
- → Ensure target key has CKA_EXTRACTABLE=true
- → Verify wrapping key has CKA_WRAP=true
- → Check mechanism support for key wrapping
- → Regenerate target key with --extractable if needed

---

## Quick Troubleshooting Commands

```bash
# General HSM health check
docker exec rust-hsm-app rust-hsm-cli info
docker exec rust-hsm-app rust-hsm-cli list-slots

# Explain any error with context
docker exec rust-hsm-app rust-hsm-cli explain-error <code> --context <operation>

# Find missing keys
docker exec rust-hsm-app rust-hsm-cli find-key --label TOKEN --user-pin PIN --key-label <name> --show-similar

# Check key capabilities
docker exec rust-hsm-app rust-hsm-cli inspect-key --label TOKEN --user-pin PIN --key-label <name>

# Compare two keys
docker exec rust-hsm-app rust-hsm-cli diff-keys --label TOKEN --user-pin PIN --key1-label k1 --key2-label k2

# List all mechanisms
docker exec rust-hsm-app rust-hsm-cli list-mechanisms --detailed

# Clean up test tokens
docker exec -e AUTO_CONFIRM=yes rust-hsm-app /app/cleanup-test-tokens.sh

# Complete reset (deletes all data)
docker compose down
docker volume rm rust-hsm_tokens
docker compose up -d
```

---

## Additional Resources

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [SoftHSM2 Documentation](https://www.opendnssec.org/softhsm/)
- [Comprehensive Troubleshooting Guide](TROUBLESHOOTING_COMPREHENSIVE.md)
- [Command Reference](commands/README.md)

---

**Last Updated**: December 2025
**Status**: Complete reference with 80+ error codes
