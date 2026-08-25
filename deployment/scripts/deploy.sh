#!/bin/bash

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
INSTALL_DIR="/opt/kernelshield"

echo "======================================"
echo " KernelShield Deployment"
echo "======================================"

# Root privileges required
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Deployment requires root privileges."
    echo "Run: sudo ./deployment/scripts/deploy.sh"
    exit 1
fi

# Check whether runtime environment exists
echo "[1/4] Checking runtime environment..."

for dir in /etc/kernelshield /var/log/kernelshield /var/lib/kernelshield /opt/kernelshield; do
    if [ ! -d "$dir" ]; then
        echo "[ERROR] Missing runtime directory: $dir"
        echo "Run prepare-runtime.sh first."
        exit 1
    fi
done

echo "[OK] Runtime environment available."

# Check for build output
echo "[2/4] Checking build artifacts..."

if [ ! -d "$BUILD_DIR" ]; then
    echo "[WAITING] Build directory does not exist:"
    echo "          $BUILD_DIR"
    echo
    echo "Core KernelShield components have not been built yet."
    exit 2
fi

# Find executable files
mapfile -t BINARIES < <(find "$BUILD_DIR" -maxdepth 1 -type f -executable)

if [ "${#BINARIES[@]}" -eq 0 ]; then
    echo "[WAITING] No executable KernelShield binaries found in:"
    echo "          $BUILD_DIR"
    exit 2
fi

echo "[3/4] Installing KernelShield binaries..."

for binary in "${BINARIES[@]}"; do
    echo "Installing $(basename "$binary")"
    install -m 755 "$binary" "$INSTALL_DIR/"
done

echo "[4/5] Installing response engine..."

mkdir -p "$INSTALL_DIR/response"

cp -r "$PROJECT_ROOT/response/"* "$INSTALL_DIR/response/"

chmod +x "$INSTALL_DIR/response/kernelshield_bridge.py"

echo "[OK] Response engine installed."

echo "[5/5] Verifying deployment..."

ls -lh "$INSTALL_DIR"

echo
echo "======================================"
echo " KernelShield deployment completed"
echo "======================================"
