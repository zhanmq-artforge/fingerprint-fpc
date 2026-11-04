#!/usr/bin/env bash
# ==============================================================================
# fingerprint-fpc One-Click Production Installer
# High-reliability FPC 10a5:9201 / 10a5:a900 fingerprint daemon for Linux
# ==============================================================================

set -euo pipefail

# ANSI color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# 1. Ensure root permissions
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo ./scripts/install.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_SRC="${PROJECT_ROOT}/target/release/fingerprint-fpc"
BIN_DEST="/usr/bin/fingerprint-fpc"
SERVICE_DEST="/etc/systemd/system/fingerprint-fpc.service"
DBUS_ACT_DEST="/usr/share/dbus-1/system-services/net.reactivated.Fprint.service"
DBUS_CONF_DEST="/usr/share/dbus-1/system.d/net.reactivated.Fprint.conf"
POLKIT_DEST="/usr/share/polkit-1/actions/net.reactivated.fprint.policy"
STORAGE_DIR="/var/lib/fprint"

log_info "=== Starting fingerprint-fpc automated deployment ==="

# 2. Build or verify binary
if [[ ! -f "${BIN_SRC}" ]]; then
    log_info "Release binary target/release/fingerprint-fpc not found. Building with Cargo..."
    if ! command -v cargo >/dev/null 2>&1; then
        log_error "Cargo/Rust toolchain not found. Please install Rust (https://rustup.rs) or build first."
        exit 1
    fi
    # If run as sudo, run cargo build as the real invoking user if available
    INVOKING_USER="${SUDO_USER:-$(whoami)}"
    log_info "Building release binary as user '${INVOKING_USER}'..."
    sudo -u "${INVOKING_USER}" cargo build --release --manifest-path "${PROJECT_ROOT}/Cargo.toml"
fi

# 3. Install binary
log_info "Installing binary to ${BIN_DEST}..."
mkdir -p "$(dirname "${BIN_DEST}")"
install -m 0755 "${BIN_SRC}" "${BIN_DEST}"
# Clean up legacy /usr/local/bin location if present
rm -f "/usr/local/bin/fingerprint-fpc"
log_ok "Binary installed."

# 4. Prepare secure storage directory with strict 0700 permissions
log_info "Initializing secure storage directory at ${STORAGE_DIR}..."
mkdir -p "${STORAGE_DIR}"
chmod 0700 "${STORAGE_DIR}"
chown root:root "${STORAGE_DIR}"
log_ok "Storage directory ready."

# 5. Mask conflicting native fprintd service
log_info "Checking native fprintd service to prevent D-Bus bus conflicts..."
if systemctl list-unit-files | grep -q "^fprintd.service"; then
    log_info "Stopping and masking stock fprintd.service..."
    systemctl stop fprintd 2>/dev/null || true
    systemctl mask fprintd 2>/dev/null || true
    log_ok "Stock fprintd masked."
fi

# 6. Install systemd service
log_info "Installing systemd service to ${SERVICE_DEST}..."
install -m 0644 "${PROJECT_ROOT}/fingerprint-fpc.service" "${SERVICE_DEST}"

# 7. Install D-Bus On-Demand Activation definition & System Bus Policy
log_info "Installing D-Bus bus activation service to ${DBUS_ACT_DEST}..."
mkdir -p "$(dirname "${DBUS_ACT_DEST}")"
install -m 0644 "${PROJECT_ROOT}/dbus/net.reactivated.Fprint.service" "${DBUS_ACT_DEST}"

log_info "Installing D-Bus system bus security policy to ${DBUS_CONF_DEST}..."
mkdir -p "$(dirname "${DBUS_CONF_DEST}")"
install -m 0644 "${PROJECT_ROOT}/dbus/net.reactivated.Fprint.conf" "${DBUS_CONF_DEST}"

# 8. Install PolicyKit authority rules
log_info "Installing PolicyKit authorization policy to ${POLKIT_DEST}..."
mkdir -p "$(dirname "${POLKIT_DEST}")"
install -m 0644 "${PROJECT_ROOT}/polkit/net.reactivated.fprint.policy" "${POLKIT_DEST}"

# 9. Reload and activate services
log_info "Reloading systemd daemon and enabling fingerprint-fpc..."
systemctl daemon-reload
systemctl enable --now fingerprint-fpc.service
log_ok "fingerprint-fpc service active and running."

# 10. Configure PAM if on Debian/Ubuntu
if command -v pam-auth-update >/dev/null 2>&1; then
    log_info "Debian/Ubuntu PAM detected. Ensuring fingerprint authentication is enabled..."
    pam-auth-update --enable fingerprint || log_warn "Please run 'sudo pam-auth-update' manually if fingerprint auth is not enabled."
fi

# 11. Health self-check
log_info "Running post-installation diagnostic self-check..."
sleep 1
if systemctl is-active --quiet fingerprint-fpc.service; then
    log_ok "Service status: ACTIVE (running)"
else
    log_warn "Service is not active yet (will be started on-demand by D-Bus activation)."
fi

echo -e "\n${GREEN}==============================================================================${NC}"
echo -e "${GREEN} fingerprint-fpc successfully installed and enabled!${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo -e "You can now test your sensor using standard tools:"
echo -e "  1. List device:    ${BLUE}fprintd-list \$USER${NC}"
echo -e "  2. Enroll finger:  ${BLUE}fprintd-enroll -f right-index-finger \$USER${NC}"
echo -e "  3. Verify finger:  ${BLUE}fprintd-verify \$USER${NC}"
echo -e "  4. Test sudo:      ${BLUE}sudo ls${NC}"
echo -e ""
echo -e "To uninstall anytime, run: ${YELLOW}sudo ./scripts/uninstall.sh${NC}"
