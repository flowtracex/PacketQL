#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DATA_DIR="${1:-/opt/packetql-data-validation-prod}"
SEED_DIR="${ROOT_DIR}/demo-data-seed"

if [ ! -d "${SOURCE_DATA_DIR}/sources" ]; then
  echo "[demo] Source data directory not found or missing sources/: ${SOURCE_DATA_DIR}" >&2
  exit 1
fi

rm -rf "${SEED_DIR}"
mkdir -p "${SEED_DIR}"

cp -a "${SOURCE_DATA_DIR}/sources" "${SEED_DIR}/sources"

if [ -d "${SOURCE_DATA_DIR}/parquet" ]; then
  cp -a "${SOURCE_DATA_DIR}/parquet" "${SEED_DIR}/parquet"
fi

mkdir -p "${SEED_DIR}/work" "${SEED_DIR}/kafka-logs"

echo "[demo] Demo seed prepared at ${SEED_DIR}"
du -sh "${SEED_DIR}"
