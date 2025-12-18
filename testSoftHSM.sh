#!/bin/bash
set -e

echo "=== Running rust-hsm integration tests with SoftHSM2 ==="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Use fixed token name (cleanup script will remove it after tests)
TEST_TOKEN="TEST_TOKEN"
SO_PIN="test-so-1234"
USER_PIN="test-user-123456"
TEST_KEY="test-key"

echo "Test token: $TEST_TOKEN"
echo "HSM Provider: SoftHSM2"

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

echo -e "\n${GREEN}=== All SoftHSM2 tests passed! ===${NC}"
