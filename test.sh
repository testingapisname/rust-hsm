#!/bin/bash
set -e

echo "=== Running rust-hsm integration tests ==="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Use timestamp for unique token name
TEST_TOKEN="TEST_TOKEN_$(date +%s)"
SO_PIN="test-so-1234"
USER_PIN="test-user-123456"
TEST_KEY="test-key"

echo "Test token: $TEST_TOKEN"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    rm -f /app/test-*.txt /app/test-*.sig
    # Try to remove test token files (best effort)
    rm -f /tokens/${TEST_TOKEN}.* 2>/dev/null || true
}

trap cleanup EXIT

# Run in container
if [ -n "$DOCKER_CONTAINER" ]; then
    EXEC_PREFIX="docker exec $DOCKER_CONTAINER"
else
    EXEC_PREFIX=""
fi

CLI="$EXEC_PREFIX rust-hsm-cli"

echo -e "\n${GREEN}[1/10] Testing info command${NC}"
$CLI info | grep -q "SoftHSM" && echo "✓ Info command works" || exit 1

echo -e "\n${GREEN}[2/10] Testing list-slots command${NC}"
$CLI list-slots | grep -q "Slot" && echo "✓ List-slots command works" || exit 1

echo -e "\n${GREEN}[3/10] Initializing test token${NC}"
# Note: SoftHSM will pick an available slot. If slot 0 is taken, it uses the next available.
$CLI init-token --label "$TEST_TOKEN" --so-pin "$SO_PIN" && echo "✓ Token initialized" || {
    echo -e "${RED}Failed to initialize token. This may happen if all slots are occupied.${NC}"
    echo "Try running: docker volume rm rust-hsm_tokens && docker compose up -d"
    exit 1
}

echo -e "\n${GREEN}[4/10] Setting user PIN${NC}"
$CLI init-pin --label "$TEST_TOKEN" --so-pin "$SO_PIN" --user-pin "$USER_PIN" && echo "✓ User PIN set" || exit 1

echo -e "\n${GREEN}[5/10] Listing objects (should be empty)${NC}"
$CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" | grep -q "Objects on token" && echo "✓ List objects works" || exit 1

echo -e "\n${GREEN}[6/10] Generating RSA-2048 keypair${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --key-type rsa --bits 2048 && echo "✓ Keypair generated" || exit 1

echo -e "\n${GREEN}[7/10] Verifying key exists${NC}"
$CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" | grep -q "$TEST_KEY" && echo "✓ Key visible in objects" || exit 1

echo -e "\n${GREEN}[8/10] Creating test data and signing${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'Test data for signing' > /app/test-data.txt"
else
    echo 'Test data for signing' > /app/test-data.txt
fi
$CLI sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --input /app/test-data.txt --output /app/test-data.sig && echo "✓ Data signed" || exit 1

echo -e "\n${GREEN}[9/10] Verifying signature${NC}"
$CLI verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --input /app/test-data.txt --signature /app/test-data.sig && echo "✓ Signature verified" || exit 1

echo -e "\n${GREEN}[10/10] Testing tampered data (should fail)${NC}"
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

echo -e "\n${GREEN}[11/13] Generating P-256 ECDSA keypair${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --key-type p256 && echo "✓ P-256 keypair generated" || exit 1

echo -e "\n${GREEN}[12/13] Testing P-256 ECDSA sign/verify${NC}"
if [ -n "$DOCKER_CONTAINER" ]; then
    docker exec $DOCKER_CONTAINER bash -c "echo 'ECDSA test data' > /app/test-ec.txt"
else
    echo 'ECDSA test data' > /app/test-ec.txt
fi
$CLI sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --input /app/test-ec.txt --output /app/test-ec-p256.sig && echo "✓ P-256 data signed" || exit 1
$CLI verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --input /app/test-ec.txt --signature /app/test-ec-p256.sig && echo "✓ P-256 signature verified" || exit 1

echo -e "\n${GREEN}[13/15] Testing P-384 ECDSA sign/verify${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --key-type p384 && echo "✓ P-384 keypair generated" || exit 1
$CLI sign --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --input /app/test-ec.txt --output /app/test-ec-p384.sig && echo "✓ P-384 data signed" || exit 1
$CLI verify --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --input /app/test-ec.txt --signature /app/test-ec-p384.sig && echo "✓ P-384 signature verified" || exit 1

echo -e "\n${GREEN}[14/15] Testing RSA public key export${NC}"
$CLI export-pubkey --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "$TEST_KEY" --output /app/test-rsa-export.pem && echo "✓ RSA public key exported" || exit 1
openssl rsa -pubin -in /app/test-rsa-export.pem -text -noout > /dev/null 2>&1 && echo "✓ RSA PEM format valid" || exit 1

echo -e "\n${GREEN}[15/18] Testing ECDSA public key export${NC}"
$CLI export-pubkey --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p256" --output /app/test-p256-export.pem && echo "✓ P-256 public key exported" || exit 1
openssl ec -pubin -in /app/test-p256-export.pem -text -noout > /dev/null 2>&1 && echo "✓ P-256 PEM format valid" || exit 1
$CLI export-pubkey --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "test-p384" --output /app/test-p384-export.pem && echo "✓ P-384 public key exported" || exit 1
openssl ec -pubin -in /app/test-p384-export.pem -text -noout > /dev/null 2>&1 && echo "✓ P-384 PEM format valid" || exit 1

echo -e "\n${GREEN}[16/18] Testing RSA encryption/decryption${NC}"
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

echo -e "\n${GREEN}[17/18] Testing key deletion${NC}"
$CLI gen-keypair --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "delete-me" --key-type rsa --bits 2048 && echo "✓ Temporary key created" || exit 1
$CLI delete-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "delete-me" && echo "✓ Key deleted successfully" || exit 1
if $CLI list-objects --label "$TEST_TOKEN" --user-pin "$USER_PIN" 2>&1 | grep -q "delete-me"; then
    echo -e "${RED}✗ Key still exists after deletion${NC}"
    exit 1
else
    echo "✓ Key no longer exists"
fi

echo -e "\n${GREEN}[18/18] Testing delete of non-existent key (should fail)${NC}"
if $CLI delete-key --label "$TEST_TOKEN" --user-pin "$USER_PIN" --key-label "nonexistent" 2>&1 | grep -q "not found"; then
    echo "✓ Correctly reported non-existent key"
else
    echo -e "${RED}✗ Should have failed to delete non-existent key${NC}"
    exit 1
fi

echo -e "\n${GREEN}=== All tests passed! ===${NC}"
