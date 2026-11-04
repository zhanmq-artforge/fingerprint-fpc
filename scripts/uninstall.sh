#!/usr/bin/env bash
# ==============================================================================
# fingerprint-fpc One-Click Clean Uninstaller & Rollback Tool
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo ./scripts/uninstall.sh)"
    exit 1
fi

PURGE_DATA=false
if [[ "${1:-}" == "--purge" ]]; then
    PURGE_DATA=true
fi

log_info "=== Starting fingerprint-fpc uninstallation and rollback ==="

# 1. Stop and disable fingerprint-fpc service
if systemctl is-active --quiet fingerprint-fpc.service 2>/dev/null; then
    log_info "Stopping fingerprint-fpc service..."
    systemctl stop fingerprint-fpc.service || true
fi

if systemctl is-enabled --quiet fingerprint-fpc.service 2>/dev/null; then
    log_info "Disabling fingerprint-fpc service..."
    systemctl disable fingerprint-fpc.service || true
fi

# 2. Remove systemd service file
if [[ -f "/etc/systemd/system/fingerprint-fpc.service" ]]; then
    log_info "Removing systemd service unit..."
    rm -f "/etc/systemd/system/fingerprint-fpc.service"
fi

# 3. Remove D-Bus activation, D-Bus security policy, and Polkit files
if [[ -f "/usr/share/dbus-1/system-services/net.reactivated.Fprint.service" ]]; then
    log_info "Removing D-Bus activation entry..."
    rm -f "/usr/share/dbus-1/system-services/net.reactivated.Fprint.service"
fi

if [[ -f "/usr/share/dbus-1/system.d/net.reactivated.Fprint.conf" ]]; then
    log_info "Removing D-Bus system bus security policy..."
    rm -f "/usr/share/dbus-1/system.d/net.reactivated.Fprint.conf"
fi

if [[ -f "/usr/share/polkit-1/actions/net.reactivated.fprint.policy" ]]; then
    log_info "Removing PolicyKit authority rules..."
    rm -f "/usr/share/polkit-1/actions/net.reactivated.fprint.policy"
fi

# 4. Remove installed binary
if [[ -f "/usr/bin/fingerprint-fpc" ]]; then
    log_info "Removing binary from /usr/bin/fingerprint-fpc..."
    rm -f "/usr/bin/fingerprint-fpc"
fi
if [[ -f "/usr/local/bin/fingerprint-fpc" ]]; then
    log_info "Removing legacy binary from /usr/local/bin/fingerprint-fpc..."
    rm -f "/usr/local/bin/fingerprint-fpc"
fi

# 5. Restore stock fprintd if present
log_info "Unmasking stock fprintd.service..."
systemctl unmask fprintd 2>/dev/null || true

# 6. Clean biometric database if requested
if [[ "${PURGE_DATA}" == true ]]; then
    log_warn "Purging all enrolled biometric data from /var/lib/fprint..."
    rm -f /var/lib/fprint/fpc*.bin* 2>/dev/null || true
    log_ok "Biometric templates purged."
else
    log_info "Enrolled template database preserved in /var/lib/fprint. (Run with --purge to remove)."
fi

# 7. Reload systemd
systemctl daemon-reload
log_ok "systemd daemon reloaded."

echo -e "\n${GREEN}==============================================================================${NC}"
echo -e "${GREEN} fingerprint-fpc successfully uninstalled!${NC}"
echo -e "${GREEN}==============================================================================${NC}"
echo -e "Stock fprintd unmasked and system state restored."
echo -e "If you wish to update PAM authentication: ${BLUE}sudo pam-auth-update${NC}"
