#!/usr/bin/env bash
# Build and install my_sniffer on Linux, then grant it CAP_NET_RAW so it
# can capture packets without needing sudo on every run.
#
# Usage: scripts/install.sh [prefix]
#   prefix  install destination (default: /usr/local)

set -euo pipefail

PREFIX="${1:-/usr/local}"

echo "==> Detecting Conan profile"
conan profile detect --force >/dev/null 2>&1 || true

echo "==> Installing dependencies (Conan)"
conan install . --output-folder=build --build=missing

echo "==> Configuring (CMake)"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="$PWD/build/conan_toolchain.cmake"

echo "==> Building"
cmake --build build

echo "==> Installing to ${PREFIX} (requires sudo)"
sudo cmake --install build --prefix "${PREFIX}"

BINARY="${PREFIX}/bin/my_sniffer"

if command -v setcap >/dev/null 2>&1; then
    echo "==> Granting CAP_NET_RAW to ${BINARY}"
    sudo setcap cap_net_raw+ep "${BINARY}"
    echo "==> Done. Run without sudo: ${BINARY} <interface>"
else
    echo "==> 'setcap' not found (package 'libcap2-bin' on Debian/Ubuntu)."
    echo "==> Done. Run with sudo instead: sudo ${BINARY} <interface>"
fi
