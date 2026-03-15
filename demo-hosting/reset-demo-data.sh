#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEED_DIR="${ROOT_DIR}/demo-data-seed"
RUNTIME_DIR="${ROOT_DIR}/runtime-data"

if [ ! -d "${SEED_DIR}/sources" ]; then
  echo "[demo] Missing demo seed. Run ./prepare-demo-data.sh first." >&2
  exit 1
fi

rm -rf "${RUNTIME_DIR}"
mkdir -p "${RUNTIME_DIR}"
cp -a "${SEED_DIR}/." "${RUNTIME_DIR}/"

rm -rf "${RUNTIME_DIR}/kafka-logs"
mkdir -p "${RUNTIME_DIR}/kafka-logs"

rm -rf "${RUNTIME_DIR}/work"
mkdir -p "${RUNTIME_DIR}/work/pcap_ingest"

echo "[demo] Runtime data reset from clean seed"
du -sh "${RUNTIME_DIR}"
