#!/bin/bash
set -e

echo "=== Running rust-hsm integration tests ==="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Use unique token name to avoid conflicts
TEST_TOKEN="TEST_TOKEN_$(date +%s)"
SO_PIN="test-so-1234"
USER_PIN="test-user-123456"
TEST_KEY="test-key"

echo "Test token: $TEST_TOKEN"

# Cleanup function
cleanup() {
    set +e  # Disable exit on error for cleanup
    echo ""
    echo "Cleaning up test artifacts..."
    
    # Remove test files
    rm -f /app/test-*.txt /app/test-*.sig /app/test-*.enc /app/test-*.bin /app/test-*.pem /app/test.csr /app/test-wrapped.bin /app/test-*.mac /app/test-*.sha256 /app/test-*.sha512 2>/dev/null
    
    # Delete test token using rust-hsm-cli (works with any HSM, not just SoftHSM)
    if $CLI delete-token --label "$TEST_TOKEN" --so-pin "$SO_PIN" 2>&1 | grep -q "deleted"; then
        echo "✓ Removed test token: $TEST_TOKEN"
    fi
}

trap cleanup EXIT

# Run in container
if [ -n "$DOCKER_CONTAINER" ]; then
    EXEC_PREFIX="docker exec $DOCKER_CONTAINER"
else
    EXEC_PREFIX=""
fi

CLI="$EXEC_PREFIX rust-hsm-cli"

echo -e "\n${GREEN}[1/11] Testing info command${NC}"
$CLI info 2>/dev/null | grep -q "SoftHSM" && echo "✓ Info command works" || exit 1

echo -e "\n${GREEN}[2/11] Testing list-slots command${NC}"
$CLI list-slots 2>/dev/null | grep -q "Slot" && echo "✓ List-slots command works" || exit 1

echo -e "\n${GREEN}[3/11] Testing list-mechanisms command${NC}"
$CLI list-mechanisms | grep -q "Total mechanisms supported: 40" && echo "✓ List-mechanisms command works" || exit 1
$CLI list-mechanisms | grep -q "CKM_AES_GCM" && echo "✓ Mechanism names decoded correctly" || exit 1

echo -e "\n${GREEN}[4/11] Initializing test token${NC}"
# Note: SoftHSM will pick an available slot. If slot 0 is taken, it uses the next available.
$CLI init-token --label "$TEST_TOKEN" --so-pin "$SO_PIN" && echo "✓ Token initialized" || {
    echo -e "${RED}Failed to initialize token. This may happen if all slots are occupied.${NC}"
    echo "Try running: docker volume rm rust-hsm_tokens && docker compose up -d"
    exit 1
}

echo -e "\n${GREEN}[5/11] Setting user PIN${NC}"
$CLI init-pin --label "$TEST_TOKEN" --so-pin "$SO_PIN" --user-pin "$USER_PIN" && echo "✓ User PIN set" || exit 1

echo -e "\n${GREEN}[6/11] Listing objects (should be empty)${NC}"
$CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" | grep -q "Objects on token" && echo "✓ List objects works" || exit 1

echo -e "\n${GREEN}[7/11] Generating RSA-2048 keypair${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --key-type rsa --bits 2048 && echo "✓ Keypair generated" || exit 1

echo -e "\n${GREEN}[8/11] Verifying key exists${NC}"
$CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" | grep -q "$TEST_KEY" && echo "✓ Key visible in objects" || exit 1

echo -e "\n${GREEN}[9/11] Creating test data and signing${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'Test data for signing' > /app/test-data.txt"
else
    echo 'Test data for signing' > /app/test-data.txt
fi
$CLI sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --input /app/test-data.txt --output /app/test-data.sig && echo "✓ Data signed" || exit 1

echo -e "\n${GREEN}[10/11] Verifying signature${NC}"
$CLI verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --input /app/test-data.txt --signature /app/test-data.sig && echo "✓ Signature verified" || exit 1

echo -e "\n${GREEN}[11/11] Testing tampered data (should fail)${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'TAMPERED DATA' > /app/test-tampered.txt"
else
    echo 'TAMPERED DATA' > /app/test-tampered.txt
fi
if $CLI verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --input /app/test-tampered.txt --signature /app/test-data.sig 2>&1 | grep -q "failed"; then
    echo "✓ Correctly rejected tampered data"
else
    echo -e "${RED}✗ Should have rejected tampered data${NC}"
    exit 1
fi

echo -e "\n${GREEN}[12/14] Generating P-256 ECDSA keypair${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --key-type p256 && echo "✓ P-256 keypair generated" || exit 1

echo -e "\n${GREEN}[13/14] Testing P-256 ECDSA sign/verify${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'ECDSA test data' > /app/test-ec.txt"
else
    echo 'ECDSA test data' > /app/test-ec.txt
fi
$CLI sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --input /app/test-ec.txt --output /app/test-ec-p256.sig && echo "✓ P-256 data signed" || exit 1
$CLI verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --input /app/test-ec.txt --signature /app/test-ec-p256.sig && echo "✓ P-256 signature verified" || exit 1

echo -e "\n${GREEN}[14/16] Testing P-384 ECDSA sign/verify${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --key-type p384 && echo "✓ P-384 keypair generated" || exit 1
$CLI sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --input /app/test-ec.txt --output /app/test-ec-p384.sig && echo "✓ P-384 data signed" || exit 1
$CLI verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --input /app/test-ec.txt --signature /app/test-ec-p384.sig && echo "✓ P-384 signature verified" || exit 1

echo -e "\n${GREEN}[15/16] Testing RSA public key export${NC}"
$CLI export-pubkey --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --output /app/test-rsa-export.pem && echo "✓ RSA public key exported" || exit 1
openssl rsa -pubin -in /app/test-rsa-export.pem -text -noout > /dev/null 2>&1 && echo "✓ RSA PEM format valid" || exit 1

echo -e "\n${GREEN}[16/19] Testing ECDSA public key export${NC}"
$CLI export-pubkey --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --output /app/test-p256-export.pem && echo "✓ P-256 public key exported" || exit 1
openssl ec -pubin -in /app/test-p256-export.pem -text -noout > /dev/null 2>&1 && echo "✓ P-256 PEM format valid" || exit 1
$CLI export-pubkey --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --output /app/test-p384-export.pem && echo "✓ P-384 public key exported" || exit 1
openssl ec -pubin -in /app/test-p384-export.pem -text -noout > /dev/null 2>&1 && echo "✓ P-384 PEM format valid" || exit 1

echo -e "\n${GREEN}[17/19] Testing RSA encryption/decryption${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'Secret test message' > /app/test-encrypt.txt"
else
    echo 'Secret test message' > /app/test-encrypt.txt
fi
$CLI encrypt --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --input /app/test-encrypt.txt --output /app/test-encrypt.bin && echo "✓ Data encrypted" || exit 1
$CLI decrypt --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --input /app/test-encrypt.bin --output /app/test-decrypt.txt && echo "✓ Data decrypted" || exit 1
if [ -n "$DOCKER_CONTAINER" ]; then
    DECRYPTED=$(docker exec $DOCKER_CONTAINER cat /app/test-decrypt.txt)
else
    DECRYPTED=$(cat /app/test-decrypt.txt)
fi
if [ "$DECRYPTED" = "Secret test message" ]; then
    echo "✓ Decrypted content matches original"
else
    echo -e "${RED}✗ Decrypted content doesn't match${NC}"
    exit 1
fi

echo -e "\n${GREEN}[18/19] Testing key deletion${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "delete-me" --key-type rsa --bits 2048 && echo "✓ Temporary key created" || exit 1
$CLI delete-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "delete-me" && echo "✓ Key deleted successfully" || exit 1
if $CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" 2>&1 | grep -q "delete-me"; then
    echo -e "${RED}✗ Key still exists after deletion${NC}"
    exit 1
else
    echo "✓ Key no longer exists"
fi

echo -e "\n${GREEN}[19/22] Testing delete of non-existent key (should fail)${NC}"
if $CLI delete-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "nonexistent" 2>&1 | grep -q "not found"; then
    echo "✓ Correctly reported non-existent key"
else
    echo -e "${RED}✗ Should have failed to delete non-existent key${NC}"
    exit 1
fi

echo -e "\n${GREEN}[20/22] Testing AES symmetric key generation${NC}"
$CLI gen-symmetric-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "aes-test" --bits 256 && echo "✓ AES-256 key generated" || exit 1
if $CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" 2>&1 | grep -q "aes-test"; then
    echo "✓ AES key visible in objects"
else
    echo -e "${RED}✗ AES key not found in objects${NC}"
    exit 1
fi

echo -e "\n${GREEN}[21/22] Testing AES-GCM encryption/decryption${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'AES test message with more data than RSA can handle!' > /app/test-aes.txt"
else
    echo 'AES test message with more data than RSA can handle!' > /app/test-aes.txt
fi
$CLI encrypt-symmetric --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "aes-test" --input /app/test-aes.txt --output /app/test-aes.enc && echo "✓ AES data encrypted" || exit 1
$CLI decrypt-symmetric --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "aes-test" --input /app/test-aes.enc --output /app/test-aes-dec.txt && echo "✓ AES data decrypted" || exit 1
if [ -n "$DOCKER_CONTAINER" ]; then
    DECRYPTED_AES=$(docker exec $DOCKER_CONTAINER cat /app/test-aes-dec.txt)
else
    DECRYPTED_AES=$(cat /app/test-aes-dec.txt)
fi
if [ "$DECRYPTED_AES" = "AES test message with more data than RSA can handle!" ]; then
    echo "✓ AES decrypted content matches original"
else
    echo -e "${RED}✗ AES decrypted content doesn't match${NC}"
    exit 1
fi

echo -e "\n${GREEN}[22/24] Testing AES key sizes${NC}"
$CLI gen-symmetric-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "aes-128" --bits 128 && echo "✓ AES-128 key generated" || exit 1
$CLI gen-symmetric-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "aes-192" --bits 192 && echo "✓ AES-192 key generated" || exit 1

echo -e "\n${GREEN}[24/25] Testing key wrapping (AES Key Wrap)${NC}"
# Generate wrapping key (KEK)
$CLI gen-symmetric-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "kek" --bits 256 && echo "✓ KEK generated" || exit 1
# Generate extractable key to wrap
$CLI gen-symmetric-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "wrap-me" --bits 256 --extractable && echo "✓ Extractable key generated" || exit 1
# Wrap the key
$CLI wrap-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "wrap-me" --wrapping-key-label "kek" --output /app/test-wrapped.bin && echo "✓ Key wrapped" || exit 1
# Verify wrapped key file exists and has content
if [ -f /app/test-wrapped.bin ] && [ -s /app/test-wrapped.bin ]; then
    echo "✓ Wrapped key file created ($(wc -c < /app/test-wrapped.bin) bytes)"
else
    echo -e "${RED}✗ Wrapped key file not created${NC}"
    exit 1
fi

echo -e "\n${GREEN}[24/25] Testing key unwrapping${NC}"
# Unwrap the key with a new label
$CLI unwrap-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "unwrapped-key" --wrapping-key-label "kek" --input /app/test-wrapped.bin --key-type aes && echo "✓ Key unwrapped" || exit 1
# Verify unwrapped key exists in HSM
if $CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" 2>&1 | grep -q "unwrapped-key"; then
    echo "✓ Unwrapped key visible in HSM"
else
    echo -e "${RED}✗ Unwrapped key not found in HSM${NC}"
    exit 1
fi

echo -e "\n${GREEN}[25/25] Testing CSR generation${NC}"
# Generate CSR from existing RSA keypair
$CLI gen-csr --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --subject "CN=test.example.com,O=TestOrg,C=US" --output /app/test.csr && echo "✓ CSR generated" || exit 1
# Verify CSR file exists and is valid
if [ -f /app/test.csr ] && openssl req -in /app/test.csr -noout -text > /dev/null 2>&1; then
    echo "✓ CSR file valid ($(wc -c < /app/test.csr) bytes)"
else
    echo -e "${RED}✗ CSR file invalid or not created${NC}"
    exit 1
fi

echo -e "\n${GREEN}[26/27] Testing SHA-256 hash${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'Test data for hashing' > /app/test-hash-data.txt"
else
    echo 'Test data for hashing' > /app/test-hash-data.txt
fi
$CLI hash --algorithm sha256 --input /app/test-hash-data.txt --output /app/test-hash.sha256 && echo "✓ SHA-256 hash generated" || exit 1
# Verify hash file exists and has correct size (32 bytes for SHA-256)
if [ -f /app/test-hash.sha256 ] && [ $(wc -c < /app/test-hash.sha256) -eq 32 ]; then
    echo "✓ SHA-256 hash size correct (32 bytes)"
else
    echo -e "${RED}✗ SHA-256 hash size incorrect${NC}"
    exit 1
fi
# Verify hash matches system sha256sum
SYSTEM_HASH=$(sha256sum /app/test-hash-data.txt | awk '{print $1}')
HSM_HASH=$(od -An -tx1 /app/test-hash.sha256 | tr -d ' \n')
if [ "$SYSTEM_HASH" = "$HSM_HASH" ]; then
    echo "✓ SHA-256 hash matches system sha256sum"
else
    echo -e "${RED}✗ SHA-256 hash doesn't match system sha256sum${NC}"
    exit 1
fi

echo -e "\n${GREEN}[27/27] Testing SHA-512 hash${NC}"
$CLI hash --algorithm sha512 --input /app/test-hash-data.txt --output /app/test-hash.sha512 && echo "✓ SHA-512 hash generated" || exit 1
# Verify hash file exists and has correct size (64 bytes for SHA-512)
if [ -f /app/test-hash.sha512 ] && [ $(wc -c < /app/test-hash.sha512) -eq 64 ]; then
    echo "✓ SHA-512 hash size correct (64 bytes)"
else
    echo -e "${RED}✗ SHA-512 hash size incorrect${NC}"
    exit 1
fi
# Verify hash matches system sha512sum
SYSTEM_HASH=$(sha512sum /app/test-hash-data.txt | awk '{print $1}')
HSM_HASH=$(od -An -tx1 /app/test-hash.sha512 | tr -d ' \n')
if [ "$SYSTEM_HASH" = "$HSM_HASH" ]; then
    echo "✓ SHA-512 hash matches system sha512sum"
else
    echo -e "${RED}✗ SHA-512 hash doesn't match system sha512sum${NC}"
    exit 1
fi

echo -e "\n${GREEN}[28/30] Testing HMAC-SHA256 key generation and signing${NC}"
echo "test data for HMAC" > /app/test-hmac-data.txt
$CLI gen-hmac-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-hmac-key --bits 256 && echo "✓ HMAC-256 key generated" || exit 1
$CLI hmac-sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-hmac-key --algorithm sha256 --input /app/test-hmac-data.txt --output /app/test-hmac.mac && echo "✓ HMAC computed" || exit 1
# Verify HMAC file exists and has correct size (32 bytes for SHA-256 HMAC)
if [ -f /app/test-hmac.mac ] && [ $(wc -c < /app/test-hmac.mac) -eq 32 ]; then
    echo "✓ HMAC size correct (32 bytes)"
else
    echo -e "${RED}✗ HMAC size incorrect${NC}"
    exit 1
fi

echo -e "\n${GREEN}[29/30] Testing HMAC verification (valid)${NC}"
$CLI hmac-verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-hmac-key --algorithm sha256 --input /app/test-hmac-data.txt --hmac /app/test-hmac.mac && echo "✓ HMAC verification successful" || exit 1

echo -e "\n${GREEN}[30/33] Testing HMAC verification failure (tampered data)${NC}"
echo "TAMPERED data" > /app/test-hmac-data.txt
if $CLI hmac-verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-hmac-key --algorithm sha256 --input /app/test-hmac-data.txt --hmac /app/test-hmac.mac 2>/dev/null; then
    echo -e "${RED}✗ HMAC verification should have failed for tampered data${NC}"
    exit 1
else
    echo "✓ HMAC verification correctly rejected tampered data"
fi

echo -e "\n${GREEN}[31/33] Testing AES-CMAC key generation and signing${NC}"
echo "test data for CMAC" > /app/test-cmac-data.txt
$CLI gen-cmac-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-cmac-key --bits 256 && echo "✓ CMAC-256 key generated" || exit 1
$CLI cmac-sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-cmac-key --input /app/test-cmac-data.txt --output /app/test-cmac.mac && echo "✓ CMAC computed" || exit 1
# Verify CMAC file exists and has correct size (16 bytes for AES CMAC)
if [ -f /app/test-cmac.mac ] && [ $(wc -c < /app/test-cmac.mac) -eq 16 ]; then
    echo "✓ CMAC size correct (16 bytes)"
else
    echo -e "${RED}✗ CMAC size incorrect${NC}"
    exit 1
fi

echo -e "\n${GREEN}[32/33] Testing CMAC verification (valid)${NC}"
$CLI cmac-verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-cmac-key --input /app/test-cmac-data.txt --cmac /app/test-cmac.mac && echo "✓ CMAC verification successful" || exit 1

echo -e "\n${GREEN}[33/34] Testing CMAC verification failure (tampered data)${NC}"
echo "TAMPERED data" > /app/test-cmac-data.txt
if $CLI cmac-verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-cmac-key --input /app/test-cmac-data.txt --cmac /app/test-cmac.mac 2>/dev/null; then
    echo -e "${RED}✗ CMAC verification should have failed for tampered data${NC}"
    exit 1
else
    echo "✓ CMAC verification correctly rejected tampered data"
fi

echo -e "\n${GREEN}[34/36] Testing key attribute inspection${NC}"
$CLI inspect-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-key 2>/dev/null | grep -q "CKA_CLASS" && echo "✓ Inspect-key displays attributes" || exit 1
$CLI inspect-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label test-cmac-key 2>/dev/null | grep -q "CKA_VALUE_LEN" && echo "✓ AES key attributes displayed" || exit 1

echo -e "\n${GREEN}[35/36] Testing random number generation (hex output)${NC}"
RANDOM_HEX=$($CLI gen-random --bytes 32 2>/dev/null | tail -1)
if [ ${#RANDOM_HEX} -eq 64 ]; then
    echo "✓ Generated 32 random bytes (64 hex chars)"
else
    echo -e "${RED}✗ Random hex output incorrect length: ${#RANDOM_HEX}${NC}"
    exit 1
fi

echo -e "\n${GREEN}[36/36] Testing random number generation (file output)${NC}"
$CLI gen-random --bytes 16 --output /app/test-random.bin && echo "✓ Random bytes written to file" || exit 1
if [ -f /app/test-random.bin ] && [ $(wc -c < /app/test-random.bin) -eq 16 ]; then
    echo "✓ Random file size correct (16 bytes)"
else
    echo -e "${RED}✗ Random file size incorrect${NC}"
    exit 1
fi
$CLI gen-random --bytes 16 --output /app/test-random.hex --hex && echo "✓ Random hex file created" || exit 1
if [ -f /app/test-random.hex ] && [ $(wc -c < /app/test-random.hex) -eq 32 ]; then
    echo "✓ Random hex file size correct (32 chars)"
else
    echo -e "${RED}✗ Random hex file size incorrect${NC}"
    exit 1
fi

echo -e "\n${GREEN}=== All tests passed! ===${NC}"

