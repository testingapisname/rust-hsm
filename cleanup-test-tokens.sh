#!/bin/bash
# cleanup-test-tokens.sh
# Deletes all SoftHSM tokens with "test" or "TEST" in their label

set -e

echo "=== SoftHSM Test Token Cleanup ==="
echo ""

# Check if rust-hsm-cli is available
if ! command -v rust-hsm-cli &> /dev/null; then
    echo "Error: rust-hsm-cli not found. Run this inside the Docker container:"
    echo "  docker exec rust-hsm-app bash /app/cleanup-test-tokens.sh"
    exit 1
fi

# Default SO PIN (can be overridden with environment variable)
SO_PIN="${SO_PIN:-test-so-1234}"

echo "Scanning for test tokens..."
echo ""

# Get list of all slots with tokens
SLOTS_OUTPUT=$(rust-hsm-cli list-slots 2>/dev/null)

# Extract slot, label, and serial for tokens containing "test" (case-insensitive)
# Use only the "Initialized Slots" section to avoid duplicates
TEST_TOKENS=$(echo "$SLOTS_OUTPUT" | awk '
    /^=== Initialized Slots ===/ { in_init=1; next }
    /^=== All Slots ===/ { in_init=0 }
    in_init && /^Slot [0-9]/ { slot=$2 }
    in_init && /Token Label:/ { label=$NF }
    in_init && /Token Serial:/ { 
        serial=$NF
        if (tolower(label) ~ /test/) {
            print slot ":" label ":" serial
        }
    }
' | sort -u -t: -k3 || true)

if [ -z "$TEST_TOKENS" ]; then
    echo "✓ No test tokens found"
    exit 0
fi

# Count tokens
TOKEN_COUNT=$(echo "$TEST_TOKENS" | wc -l)
echo "Found $TOKEN_COUNT test token(s) to delete:"
echo ""

# Show what will be deleted
echo "$TEST_TOKENS" | while IFS=':' read -r slot label serial; do
    echo "  • $label (Slot $slot, Serial $serial)"
done

echo ""

# Check if running interactively
if [ -t 0 ]; then
    read -p "Delete these tokens? (y/N): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
else
    # Non-interactive mode - require explicit confirmation via env variable
    if [ "$AUTO_CONFIRM" != "yes" ]; then
        echo "Non-interactive mode. Set AUTO_CONFIRM=yes to proceed automatically."
        exit 1
    fi
    echo "AUTO_CONFIRM=yes, proceeding with deletion..."
fi

echo ""
echo "Deleting tokens..."

# Delete each token by serial number (avoid subshell to preserve counters)
DELETED=0
FAILED=0

while IFS=':' read -r slot label serial; do
    if [ -n "$serial" ]; then
        echo -n "Deleting '$label'... "
        if softhsm2-util --delete-token --serial "$serial" >/dev/null 2>&1; then
            echo "✓"
            DELETED=$((DELETED + 1))
        else
            echo "✗ Failed"
            FAILED=$((FAILED + 1))
        fi
    fi
done <<< "$TEST_TOKENS"

echo ""
echo "=== Cleanup Complete ==="
echo "Deleted: $DELETED"
[ $FAILED -gt 0 ] && echo "Failed: $FAILED"
echo ""
echo "Remaining slots:"
rust-hsm-cli list-slots 2>/dev/null | grep -E "Slot [0-9]|Token Label:" || echo "  (no tokens)"