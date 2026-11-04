#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# fingerprint-fpc — Master Packaging Script (All Platforms & Formats)
# Formats: Debian (.deb), Portable Tarball (.tar.gz), RedHat (.rpm), Arch Linux
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

RAW_ARCH="${1:-${PKG_ARCH:-$(uname -m)}}"
case "${RAW_ARCH}" in
    x86_64|amd64)
        DEB_ARCH="amd64"
        RPM_ARCH="x86_64"
        TAR_ARCH="x86_64"
        ;;
    aarch64|arm64|armv8*)
        DEB_ARCH="arm64"
        RPM_ARCH="aarch64"
        TAR_ARCH="aarch64"
        ;;
    *)
        DEB_ARCH="${RAW_ARCH}"
        RPM_ARCH="${RAW_ARCH}"
        TAR_ARCH="${RAW_ARCH}"
        ;;
esac

echo "======================================================================"
echo "==> Starting Master Packaging for fingerprint-fpc (${RAW_ARCH})"
echo "    Debian Arch:   ${DEB_ARCH}"
echo "    RPM Arch:      ${RPM_ARCH}"
echo "    Tarball Arch:  ${TAR_ARCH}"
echo "======================================================================"

# Step 0: Build release binary
echo "==> Compiling release binary..."
cargo build --release

# Step 1: Debian (.deb)
echo ""
echo "==> [1/4] Building Debian (.deb) package..."
"${PROJECT_ROOT}/scripts/package-deb.sh" "${DEB_ARCH}"

# Step 2: Portable Tarball (.tar.gz)
echo ""
echo "==> [2/4] Building Portable Tarball (.tar.gz)..."
"${PROJECT_ROOT}/scripts/package-tar.sh" "${TAR_ARCH}"

# Step 3: RedHat / Fedora (.rpm)
echo ""
echo "==> [3/4] Building RPM (.rpm) package..."
if command -v rpmbuild >/dev/null 2>&1; then
    "${PROJECT_ROOT}/scripts/package-rpm.sh" "${RPM_ARCH}" || echo "⚠️ RPM build failed or skipped"
else
    echo "⚠️ Skipping RPM build ('rpmbuild' not installed on host)."
fi

# Step 4: Arch Linux
echo ""
echo "==> [4/4] Building Arch Linux package..."
if command -v makepkg >/dev/null 2>&1; then
    "${PROJECT_ROOT}/scripts/package-arch.sh" "${RAW_ARCH}" || echo "⚠️ Arch build failed or skipped"
else
    echo "⚠️ Skipping Arch build ('makepkg' not installed on host)."
fi

echo ""
echo "======================================================================"
echo "==> Packaging Complete! Generated distribution artifacts in dist/:"
ls -lh "${PROJECT_ROOT}/dist"
echo "======================================================================"
