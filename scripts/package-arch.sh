#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# fingerprint-fpc — Arch Linux (.pkg.tar.zst) Packaging Script
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

OUTPUT_DIR="${PROJECT_ROOT}/dist"
ARCH_BUILD_DIR="${PROJECT_ROOT}/target/archlinux"
mkdir -p "${OUTPUT_DIR}"

if ! command -v makepkg >/dev/null 2>&1; then
    echo "==> ⚠️ 'makepkg' not found. Arch Linux packaging requires pacman/makepkg."
    echo "==> PKGBUILD is ready at packaging/arch/PKGBUILD for Arch Linux users."
    exit 0
fi

echo "==> Preparing Arch Linux package in ${ARCH_BUILD_DIR}..."
rm -rf "${ARCH_BUILD_DIR}"
mkdir -p "${ARCH_BUILD_DIR}"
cp "packaging/arch/PKGBUILD" "${ARCH_BUILD_DIR}/"
cp "packaging/arch/fingerprint-fpc.install" "${ARCH_BUILD_DIR}/"

# Build source tarball
PKG_VERSION="$(grep -m 1 '^version = ' Cargo.toml | cut -d '"' -f 2)"
TAR_NAME="fingerprint-fpc-${PKG_VERSION}.tar.gz"
git archive --format=tar.gz --prefix="fingerprint-fpc-${PKG_VERSION}/" HEAD > "${ARCH_BUILD_DIR}/${TAR_NAME}" 2>/dev/null || \
tar --exclude="target" --exclude=".git" --transform="s,^,fingerprint-fpc-${PKG_VERSION}/," -czf "${ARCH_BUILD_DIR}/${TAR_NAME}" .

cd "${ARCH_BUILD_DIR}"
makepkg -f --nodeps

cp ./*.pkg.tar.* "${OUTPUT_DIR}/"
echo "==> [OK] Successfully built Arch Linux package in ${OUTPUT_DIR}"
