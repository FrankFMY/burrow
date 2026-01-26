#!/bin/bash
# Burrow VPN - One-line installer
# curl -fsSL https://raw.githubusercontent.com/FrankFMY/burrow/main/scripts/install.sh | bash

set -e

REPO="FrankFMY/burrow"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux)  PLATFORM="linux-$ARCH" ;;
    darwin) PLATFORM="darwin-$ARCH" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

echo "🕳️  Installing Burrow for $PLATFORM..."

# Get latest release
LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "Could not determine latest release"
    exit 1
fi

echo "   Version: $LATEST"

# Download
URL="https://github.com/$REPO/releases/download/$LATEST/burrow-$PLATFORM.tar.gz"
TMP_DIR=$(mktemp -d)

echo "   Downloading..."
curl -fsSL "$URL" -o "$TMP_DIR/burrow.tar.gz"

echo "   Extracting..."
tar -xzf "$TMP_DIR/burrow.tar.gz" -C "$TMP_DIR"

echo "   Installing to $INSTALL_DIR..."
sudo mv "$TMP_DIR/burrow" "$INSTALL_DIR/"
sudo mv "$TMP_DIR/burrow-server" "$INSTALL_DIR/"
sudo mv "$TMP_DIR/burrow-agent" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/burrow" "$INSTALL_DIR/burrow-server" "$INSTALL_DIR/burrow-agent"

# Cleanup
rm -rf "$TMP_DIR"

echo ""
echo "✅ Burrow installed successfully!"
echo ""
echo "   Quick start:"
echo "   burrow --help"
echo ""
