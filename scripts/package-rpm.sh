#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# fingerprint-fpc — RedHat / Fedora / openSUSE (.rpm) Packaging Script
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PKG_NAME="fingerprint-fpc"
PKG_VERSION="${PKG_VERSION:-$(grep -m 1 '^version = ' Cargo.toml | cut -d '"' -f 2)}"

RAW_ARCH="${1:-${PKG_ARCH:-$(uname -m)}}"
case "${RAW_ARCH}" in
    x86_64|amd64)
        RPM_ARCH="x86_64"
        ;;
    aarch64|arm64|armv8*)
        RPM_ARCH="aarch64"
        ;;
    *)
        RPM_ARCH="${RAW_ARCH}"
        ;;
esac

OUTPUT_DIR="${PROJECT_ROOT}/dist"
RPMBUILD_ROOT="${PROJECT_ROOT}/target/rpmbuild"
mkdir -p "${OUTPUT_DIR}"

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "==> ⚠️ 'rpmbuild' is not installed. To build RPMs, install rpm-build (rpm) package."
    exit 1
fi

if [ ! -f "target/release/fingerprint-fpc" ]; then
    echo "==> Building release binary (cargo build --release)..."
    cargo build --release
fi

echo "==> Preparing rpmbuild environment in ${RPMBUILD_ROOT}..."
rm -rf "${RPMBUILD_ROOT}"
mkdir -p "${RPMBUILD_ROOT}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Prepare Source0 tarball
TAR_NAME="${PKG_NAME}-${PKG_VERSION}"
SRC_DIR="${RPMBUILD_ROOT}/BUILD/${TAR_NAME}"
mkdir -p "${SRC_DIR}"
cp -r Cargo.toml Cargo.lock src fingerprint-fpc.service dbus polkit README.md CHANGELOG.md "${SRC_DIR}/"
mkdir -p "${SRC_DIR}/target/release"
cp "target/release/fingerprint-fpc" "${SRC_DIR}/target/release/"
touch "${SRC_DIR}/LICENSE"
tar -czf "${RPMBUILD_ROOT}/SOURCES/${TAR_NAME}.tar.gz" -C "${RPMBUILD_ROOT}/BUILD" "${TAR_NAME}"

# Copy SPEC and build
cp "packaging/rpm/fingerprint-fpc.spec" "${RPMBUILD_ROOT}/SPECS/"

echo "==> Executing rpmbuild..."
rpmbuild --define "_topdir ${RPMBUILD_ROOT}" \
         --define "_rpmdir ${OUTPUT_DIR}" \
         --target "${RPM_ARCH}" \
         -bb "${RPMBUILD_ROOT}/SPECS/fingerprint-fpc.spec"

echo "==> [OK] Successfully built RPM in ${OUTPUT_DIR}"
