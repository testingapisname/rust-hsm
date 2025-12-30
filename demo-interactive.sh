#!/bin/bash
# Demo script for the new Interactive TUI mode

set -e

echo "🔐 rust-hsm Interactive TUI Demo"
echo "================================="
echo ""

echo "The Interactive TUI provides a menu-driven interface for HSM operations!"
echo ""

echo "📋 Features:"
echo "  • 📊 Information & Status - View HSM info, slots, mechanisms"
echo "  • 🔧 Token Management - Initialize and configure tokens"
echo "  • 🔑 Key Operations - Generate, inspect, export, delete keys"
echo "  • 🔐 Cryptographic Operations - Sign, verify, encrypt, decrypt"
echo "  • ⚡ Symmetric Operations - AES, key wrapping, HMAC"
echo "  • 🔍 Troubleshooting - Error explanations, key search, comparisons"
echo ""

echo "🎮 Navigation:"
echo "  • ↑/↓ arrows - Navigate menus"
echo "  • Enter - Select item"
echo "  • Esc - Go back / Quit"
echo "  • h - Help"
echo "  • q - Quit"
echo ""

echo "🚀 Launch the Interactive TUI:"
echo "  docker exec -it rust-hsm-app rust-hsm-cli interactive"
echo ""
echo "  With specific token:"
echo "  docker exec -it rust-hsm-app rust-hsm-cli interactive --label MY_TOKEN"
echo ""

echo "💡 Benefits:"
echo "  • Discover commands without reading docs"
echo "  • Guided workflows for beginners"
echo "  • Perfect for demos and exploration"
echo "  • Visual feedback and help text"
echo "  • No need to remember command syntax"
echo ""

echo "🎯 Perfect for:"
echo "  • Learning HSM operations"
echo "  • Quick operational tasks"
echo "  • Demonstrating capabilities"
echo "  • Guided troubleshooting"
echo ""

echo "Ready to explore your HSM interactively! 🎉"