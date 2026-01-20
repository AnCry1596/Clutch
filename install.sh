#!/bin/bash
# Clutch Installation Script for Rootless Jailbreaks (Dopamine, palera1n, etc.)

set -e

CLUTCH_BIN="Clutch"
ENTITLEMENTS="Clutch.entitlements"

# Detect jailbreak type
if [ -d "/var/jb" ]; then
    echo "[*] Detected rootless jailbreak"
    INSTALL_PATH="/var/jb/usr/bin"
    JB_ROOT="/var/jb"
else
    echo "[*] Detected rootful jailbreak"
    INSTALL_PATH="/usr/bin"
    JB_ROOT=""
fi

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "[!] This script must be run as root (use sudo)"
    exit 1
fi

# Check if Clutch binary exists
if [ ! -f "$CLUTCH_BIN" ]; then
    echo "[!] Clutch binary not found in current directory"
    echo "[!] Please run this script from the directory containing Clutch"
    exit 1
fi

# Create install directory if needed
mkdir -p "$INSTALL_PATH"

# Copy binary
echo "[*] Installing Clutch to $INSTALL_PATH..."
cp "$CLUTCH_BIN" "$INSTALL_PATH/Clutch"
chmod 755 "$INSTALL_PATH/Clutch"

# Sign with ldid if available and entitlements exist
if command -v ldid &> /dev/null; then
    if [ -f "$ENTITLEMENTS" ]; then
        echo "[*] Signing with ldid..."
        ldid -S"$ENTITLEMENTS" "$INSTALL_PATH/Clutch"
    else
        echo "[!] Warning: Clutch.entitlements not found, skipping signing"
        echo "[!] You may need to sign manually: ldid -S<entitlements> $INSTALL_PATH/Clutch"
    fi
else
    echo "[!] Warning: ldid not found"
    echo "[!] Install ldid and sign manually: ldid -S<entitlements> $INSTALL_PATH/Clutch"
fi

# For unc0ver, inject the binary
if [ -f "${JB_ROOT}/usr/bin/inject" ]; then
    echo "[*] Running inject for unc0ver compatibility..."
    "${JB_ROOT}/usr/bin/inject" "$INSTALL_PATH/Clutch" || true
fi

echo "[+] Installation complete!"
echo "[+] Run 'Clutch' or '$INSTALL_PATH/Clutch' to use"
