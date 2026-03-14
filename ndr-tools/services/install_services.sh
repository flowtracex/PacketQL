#!/bin/bash
# Install PCAPQL systemd service files.
#
# Usage:
#   sudo bash install_services.sh           # Install all services
#   sudo bash install_services.sh --enable  # Install + enable (start on boot)
#   sudo bash install_services.sh --start   # Install + enable + start now
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICES=(ndr-enrich ndr-api ndr-frontend)
SYSTEMD_DIR="/etc/systemd/system"

echo "══════════════════════════════════════════════════"
echo "  PCAPQL Service Installer"
echo "══════════════════════════════════════════════════"

# Copy service files
for svc in "${SERVICES[@]}"; do
    src="${SCRIPT_DIR}/${svc}.service"
    dst="${SYSTEMD_DIR}/${svc}.service"

    if [ ! -f "$src" ]; then
        echo "  ⚠️  Missing: ${src}"
        continue
    fi

    cp "$src" "$dst"
    echo "  ✅ Installed: ${svc}.service"
done

# Reload systemd
systemctl daemon-reload
echo ""
echo "  systemd reloaded"

# Optional: enable services
if [[ "$1" == "--enable" || "$1" == "--start" ]]; then
    echo ""
    for svc in "${SERVICES[@]}"; do
        systemctl enable "$svc" 2>/dev/null && echo "  ✅ Enabled: ${svc}" || true
    done
fi

# Optional: start services
if [[ "$1" == "--start" ]]; then
    echo ""
    # Start in dependency order
    for svc in ndr-enrich ndr-api ndr-frontend; do
        systemctl start "$svc" 2>/dev/null && echo "  ✅ Started: ${svc}" || echo "  ❌ Failed: ${svc}"
        sleep 1
    done
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "  Usage:"
echo "    systemctl start ndr-enrich"
echo "    systemctl stop ndr-api"
echo "    systemctl status ndr-frontend"
echo "    journalctl -u ndr-enrich -f"
echo ""
echo "  All services:"
echo "    systemctl start ndr-{enrich,api,frontend}"
echo "    systemctl stop ndr-{enrich,api,frontend}"
echo "    systemctl status ndr-{enrich,api,frontend}"
echo "══════════════════════════════════════════════════"
