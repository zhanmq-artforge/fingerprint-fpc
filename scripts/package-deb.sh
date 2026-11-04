#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# fingerprint-fpc — Debian (.deb) Packaging Script
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PKG_NAME="fingerprint-fpc"
PKG_VERSION="${PKG_VERSION:-$(grep -m 1 '^version = ' Cargo.toml | cut -d '"' -f 2)}"

RAW_ARCH="${1:-${PKG_ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}}"
case "${RAW_ARCH}" in
    x86_64|amd64)
        PKG_ARCH="amd64"
        ;;
    aarch64|arm64|armv8*)
        PKG_ARCH="arm64"
        ;;
    *)
        PKG_ARCH="${RAW_ARCH}"
        ;;
esac

OUTPUT_DIR="${PROJECT_ROOT}/dist"
DEB_DIR="target/debian/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"
OUTPUT_DEB="${OUTPUT_DIR}/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"
mkdir -p "${OUTPUT_DIR}"

echo "==> Building release binary (cargo build --release)..."
cargo build --release

echo "==> Preparing Debian package directory in ${DEB_DIR}..."
rm -rf "${DEB_DIR}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/etc/systemd/system"
mkdir -p "${DEB_DIR}/usr/share/dbus-1/system-services"
mkdir -p "${DEB_DIR}/usr/share/dbus-1/system.d"
mkdir -p "${DEB_DIR}/usr/share/polkit-1/actions"

# Copy binary & assets
install -m 0755 "target/release/fingerprint-fpc" "${DEB_DIR}/usr/bin/fingerprint-fpc"
install -m 0644 "fingerprint-fpc.service" "${DEB_DIR}/etc/systemd/system/fingerprint-fpc.service"
install -m 0644 "dbus/net.reactivated.Fprint.service" "${DEB_DIR}/usr/share/dbus-1/system-services/net.reactivated.Fprint.service"
install -m 0644 "dbus/net.reactivated.Fprint.conf" "${DEB_DIR}/usr/share/dbus-1/system.d/net.reactivated.Fprint.conf"
install -m 0644 "polkit/net.reactivated.fprint.policy" "${DEB_DIR}/usr/share/polkit-1/actions/net.reactivated.fprint.policy"

# Process control files
sed -e "s/Architecture: any/Architecture: ${PKG_ARCH}/" \
    -e "s/Version: .*/Version: ${PKG_VERSION}/" \
    "packaging/debian/control" > "${DEB_DIR}/DEBIAN/control"

install -m 0755 "packaging/debian/postinst" "${DEB_DIR}/DEBIAN/postinst"
install -m 0755 "packaging/debian/prerm" "${DEB_DIR}/DEBIAN/prerm"
install -m 0755 "packaging/debian/postrm" "${DEB_DIR}/DEBIAN/postrm"

echo "==> Assembling .deb package into ${OUTPUT_DEB}..."
dpkg-deb --build --root-owner-group "${DEB_DIR}" "${OUTPUT_DEB}"
echo "==> [OK] Successfully built: ${OUTPUT_DEB}"
