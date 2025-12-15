#!/bin/bash
set -e

echo "=== rust-hsm Demo ==="
echo ""

# Cleanup
echo "0. Cleaning up old test tokens..."
docker exec -e AUTO_CONFIRM=yes rust-hsm-app /app/cleanup-test-tokens.sh

# Initialize
echo ""
echo "1. Initializing token..."
docker exec rust-hsm-app rust-hsm-cli init-token --label DEMO --so-pin 12345678
docker exec rust-hsm-app rust-hsm-cli init-pin --label DEMO --so-pin 12345678 --user-pin demo

# Generate keys
echo ""
echo "2. Generating RSA keypair..."
docker exec rust-hsm-app rust-hsm-cli gen-keypair --label DEMO --user-pin demo --key-label demo-key --key-type rsa

# Create demo file inside container
echo ""
echo "3. Creating demo document..."
docker exec rust-hsm-app bash -c "echo 'Important document' > /app/demo.txt"

# Sign
echo ""
echo "4. Signing document..."
docker exec rust-hsm-app rust-hsm-cli sign --label DEMO --user-pin demo --key-label demo-key --input /app/demo.txt --output /app/demo.sig

# Verify
echo ""
echo "5. Verifying signature..."
docker exec rust-hsm-app rust-hsm-cli verify --label DEMO --user-pin demo --key-label demo-key --input /app/demo.txt --signature /app/demo.sig

# Show objects
echo ""
echo "6. Listing HSM objects..."
docker exec rust-hsm-app rust-hsm-cli list-objects --label DEMO --user-pin demo --detailed

echo ""
echo "=== Demo Complete ==="
echo ""
echo "Next steps to try:"
echo "  - Encrypt data: docker exec rust-hsm-app rust-hsm-cli gen-symmetric --label DEMO --user-pin demo --key-label aes-key --key-size 256"
echo "  - Explain errors: docker exec rust-hsm-app rust-hsm-cli explain-error CKR_PIN_INCORRECT"
echo "  - Find keys: docker exec rust-hsm-app rust-hsm-cli find-key --label DEMO --user-pin demo --key-label demo"
echo "  - Inspect key: docker exec rust-hsm-app rust-hsm-cli inspect-key --label DEMO --user-pin demo --key-label demo-key"
echo ""
