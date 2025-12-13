#!/bin/bash
set -e

# Ensure token directory exists
mkdir -p /tokens
chmod 755 /tokens

# Print SoftHSM info
echo "SoftHSM2 version:"
softhsm2-util --version

echo "Token directory: /tokens"
echo "PKCS#11 module: ${PKCS11_MODULE}"

# Execute command
exec "$@"
