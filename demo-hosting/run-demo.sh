#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "${ROOT_DIR}/demo-data-seed/sources" ]; then
  echo "[demo] No demo seed found. Preparing from /opt/packetql-data-validation-prod..." >&2
  "${ROOT_DIR}/prepare-demo-data.sh"
fi

"${ROOT_DIR}/reset-demo-data.sh"

cd "${ROOT_DIR}"
docker compose down >/dev/null 2>&1 || true
docker compose up -d

echo "[demo] Hosted demo started"
echo "[demo] Open http://localhost:${DEMO_PORT:-8088}"
