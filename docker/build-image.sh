#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ZEEK_DIR="${ZEEK_DIR:-/opt/zeek}"
ZEEK_TAR="${ROOT_DIR}/docker/zeek-runtime.tar.gz"
KAFKA_VERSION="${KAFKA_VERSION:-3.7.1}"
KAFKA_SCALA="${KAFKA_SCALA:-2.13}"
KAFKA_TGZ="kafka_${KAFKA_SCALA}-${KAFKA_VERSION}.tgz"
KAFKA_TAR="${ROOT_DIR}/docker/${KAFKA_TGZ}"
IMAGE_TAG="${IMAGE_TAG:-packetql:single}"

if [ -d "${ZEEK_DIR}" ]; then
  echo "[build] Packing minimal Zeek runtime from ${ZEEK_DIR} -> ${ZEEK_TAR}"
  bash "${ROOT_DIR}/docker/package-zeek-runtime.sh" "${ZEEK_DIR}" "${ZEEK_TAR}"
else
  echo "[build] WARNING: ${ZEEK_DIR} not found. Creating empty zeek bundle placeholder."
  tmpd="$(mktemp -d)"
  mkdir -p "${tmpd}/opt/zeek/bin"
  tar -czf "${ZEEK_TAR}" -C "${tmpd}" opt
  rm -rf "${tmpd}"
fi

if [ ! -s "${KAFKA_TAR}" ]; then
  echo "[build] Downloading Kafka ${KAFKA_SCALA}-${KAFKA_VERSION} -> ${KAFKA_TAR}"
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors \
    --connect-timeout 10 --max-time 180 \
    -o "${KAFKA_TAR}" \
    "https://archive.apache.org/dist/kafka/${KAFKA_VERSION}/${KAFKA_TGZ}" \
    || curl -fL --retry 5 --retry-delay 2 --retry-all-errors \
    --connect-timeout 10 --max-time 180 \
    -o "${KAFKA_TAR}" \
    "https://dlcdn.apache.org/kafka/${KAFKA_VERSION}/${KAFKA_TGZ}"
else
  echo "[build] Using cached Kafka archive ${KAFKA_TAR}"
fi

echo "[build] Building Docker image ${IMAGE_TAG}"
docker build -f "${ROOT_DIR}/docker/Dockerfile.single" -t "${IMAGE_TAG}" "${ROOT_DIR}"

echo "[build] Done: ${IMAGE_TAG}"
