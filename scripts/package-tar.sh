#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# fingerprint-fpc — Generic Portable Tarball (.tar.gz) Packaging Script
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PKG_NAME="fingerprint-fpc"
PKG_VERSION="${PKG_VERSION:-$(grep -m 1 '^version = ' Cargo.toml | cut -d '"' -f 2)}"

RAW_ARCH="${1:-${TARGET_ARCH:-$(uname -m)}}"
case "${RAW_ARCH}" in
    x86_64|amd64)
        NORM_ARCH="x86_64"
        ;;
    aarch64|arm64|armv8*)
        NORM_ARCH="aarch64"
        ;;
    *)
        NORM_ARCH="${RAW_ARCH}"
        ;;
esac

OUTPUT_DIR="${PROJECT_ROOT}/dist"
TAR_NAME="${PKG_NAME}-${PKG_VERSION}-linux-${NORM_ARCH}"
BUNDLE_DIR="${PROJECT_ROOT}/target/tarball/${TAR_NAME}"
OUTPUT_TAR="${OUTPUT_DIR}/${TAR_NAME}.tar.gz"

mkdir -p "${OUTPUT_DIR}"
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}/bin"
mkdir -p "${BUNDLE_DIR}/dbus"
mkdir -p "${BUNDLE_DIR}/polkit"
mkdir -p "${BUNDLE_DIR}/scripts"

if [ ! -f "target/release/fingerprint-fpc" ]; then
    echo "==> Building release binary (cargo build --release)..."
    cargo build --release
fi

echo "==> Assembling portable distribution bundle..."
install -m 0755 "target/release/fingerprint-fpc" "${BUNDLE_DIR}/bin/fingerprint-fpc"
install -m 0644 "fingerprint-fpc.service" "${BUNDLE_DIR}/fingerprint-fpc.service"
install -m 0644 "dbus/net.reactivated.Fprint.service" "${BUNDLE_DIR}/dbus/net.reactivated.Fprint.service"
install -m 0644 "polkit/net.reactivated.fprint.policy" "${BUNDLE_DIR}/polkit/net.reactivated.fprint.policy"
install -m 0755 "scripts/install.sh" "${BUNDLE_DIR}/install.sh"
install -m 0755 "scripts/uninstall.sh" "${BUNDLE_DIR}/uninstall.sh"
install -m 0644 "README.md" "${BUNDLE_DIR}/README.md"
install -m 0644 "CHANGELOG.md" "${BUNDLE_DIR}/CHANGELOG.md"
install -m 0644 "CHANGELOG.zh-CN.md" "${BUNDLE_DIR}/CHANGELOG.zh-CN.md" 2>/dev/null || true

# Package tarball
echo "==> Creating tarball: ${OUTPUT_TAR}..."
tar -czf "${OUTPUT_TAR}" -C "${PROJECT_ROOT}/target/tarball" "${TAR_NAME}"
echo "==> [OK] Successfully built: ${OUTPUT_TAR}"
