#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/packetql"
DATA_DIR="${NDR_DATA_DIR:-/data}"
PARQUET_DIR="${PARQUET_DATA_DIR:-${DATA_DIR}/parquet}"
APP_MODE="${APP_MODE:-demo}"
KAFKA_BOOTSTRAP_SERVERS="${KAFKA_BOOTSTRAP_SERVERS:-127.0.0.1:9092}"
DJANGO_DEBUG="${DJANGO_DEBUG:-0}"
DJANGO_ALLOWED_HOSTS="${DJANGO_ALLOWED_HOSTS:-127.0.0.1,localhost}"
CORS_ALLOW_ALL_ORIGINS="${CORS_ALLOW_ALL_ORIGINS:-0}"
CORS_ALLOWED_ORIGINS="${CORS_ALLOWED_ORIGINS:-http://localhost:3000,http://127.0.0.1:3000}"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-2}"
GUNICORN_THREADS="${GUNICORN_THREADS:-4}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-120}"

mkdir -p "${DATA_DIR}" "${PARQUET_DIR}" "${DATA_DIR}/kafka-logs" /tmp/packetql

if [ ! -x /opt/zeek/bin/zeek ]; then
  echo "[packetql] WARNING: /opt/zeek/bin/zeek not found."
  echo "[packetql] Provide docker/zeek-runtime.tar.gz at build time or mount /opt/zeek into container."
fi

# Configure Kafka KRaft
KAFKA_CFG=/tmp/packetql/kraft.properties
cp /opt/kafka/config/kraft/server.properties "${KAFKA_CFG}"
sed -i 's#^log.dirs=.*#log.dirs=/data/kafka-logs#' "${KAFKA_CFG}"
sed -i 's#^listeners=.*#listeners=PLAINTEXT://127.0.0.1:9092,CONTROLLER://127.0.0.1:9093#' "${KAFKA_CFG}"
sed -i 's#^advertised.listeners=.*#advertised.listeners=PLAINTEXT://127.0.0.1:9092#' "${KAFKA_CFG}"
sed -i 's#^controller.quorum.voters=.*#controller.quorum.voters=1@127.0.0.1:9093#' "${KAFKA_CFG}"
sed -i 's#^node.id=.*#node.id=1#' "${KAFKA_CFG}"

if [ ! -f /data/kafka-logs/meta.properties ]; then
  KRAFT_ID="$(/opt/kafka/bin/kafka-storage.sh random-uuid)"
  /opt/kafka/bin/kafka-storage.sh format -t "${KRAFT_ID}" -c "${KAFKA_CFG}"
fi

echo "[packetql] Starting Kafka (KRaft)..."
/opt/kafka/bin/kafka-server-start.sh "${KAFKA_CFG}" > /tmp/packetql/kafka.log 2>&1 &
PID_KAFKA=$!

# Wait for Kafka
for i in $(seq 1 60); do
  if nc -z 127.0.0.1 9092; then
    break
  fi
  sleep 1
done
if ! nc -z 127.0.0.1 9092; then
  echo "[packetql] Kafka failed to start"
  exit 1
fi

echo "[packetql] Ensuring Kafka topics exist..."
/opt/kafka/bin/kafka-topics.sh --bootstrap-server 127.0.0.1:9092 --create --if-not-exists --topic zeek-raw --partitions 1 --replication-factor 1 > /tmp/packetql/kafka-topic-create.log 2>&1 || true
/opt/kafka/bin/kafka-topics.sh --bootstrap-server 127.0.0.1:9092 --create --if-not-exists --topic zeek-normalized --partitions 1 --replication-factor 1 >> /tmp/packetql/kafka-topic-create.log 2>&1 || true

# Patch enrich config to container paths
ENRICH_CFG_SRC="${ROOT}/ndr-enrich/config/config.json"
ENRICH_CFG="/tmp/packetql/enrich.config.json"
cp "${ENRICH_CFG_SRC}" "${ENRICH_CFG}"
sed -i "s#/opt/tools/pcapql#${ROOT}#g" "${ENRICH_CFG}"
sed -i "s#\"localhost:9092\"#\"127.0.0.1:9092\"#g" "${ENRICH_CFG}"
sed -i "s#\"base_path\": \"[^\"]*\"#\"base_path\": \"${PARQUET_DIR}\"#" "${ENRICH_CFG}"

# The current enrich binary falls back to files relative to the config dir.
cp "${ROOT}/ndr-config/schemas/zeek/normalization.json" /tmp/packetql/normalization.json
cp "${ROOT}/ndr-config/datasets/enrich/asset_classification.csv" /tmp/packetql/asset_classification.csv

if [ -x "${ROOT}/ndr-enrich/zeek-parquet-pipeline" ]; then
  echo "[packetql] Starting enrich pipeline..."
  "${ROOT}/ndr-enrich/zeek-parquet-pipeline" --config "${ENRICH_CFG}" > /tmp/packetql/enrich.log 2>&1 &
  PID_ENRICH=$!
else
  echo "[packetql] WARNING: ndr-enrich/zeek-parquet-pipeline not found or not executable"
  PID_ENRICH=""
fi

# Backend
echo "[packetql] Starting Django API..."
cd "${ROOT}/ndr-api/flowtracex_api"
export APP_MODE
export NDR_DATA_DIR="${DATA_DIR}"
export PARQUET_DATA_DIR="${PARQUET_DIR}"
export KAFKA_BOOTSTRAP_SERVERS
export DJANGO_DEBUG
export DJANGO_ALLOWED_HOSTS
export CORS_ALLOW_ALL_ORIGINS
export CORS_ALLOWED_ORIGINS
python3 manage.py migrate --noinput > /tmp/packetql/migrate.log 2>&1 || true
if [ "${APP_MODE}" = "demo" ]; then
  python3 "${ROOT}/ndr-config/demo/bootstrap_demo.py" --sqlite --db-path "${ROOT}/ndr-config/demo/demo.sqlite" > /tmp/packetql/demo-seed.log 2>&1 || true
fi
gunicorn \
  --bind 0.0.0.0:8010 \
  --workers "${GUNICORN_WORKERS}" \
  --threads "${GUNICORN_THREADS}" \
  --timeout "${GUNICORN_TIMEOUT}" \
  --access-logfile - \
  --error-logfile - \
  flowtracex_api.wsgi:application > /tmp/packetql/api.log 2>&1 &
PID_API=$!

# Frontend (nginx serving static build with API proxy)
echo "[packetql] Starting frontend..."
nginx -g 'daemon off;' > /tmp/packetql/frontend.log 2>&1 &
PID_FE=$!

cleanup() {
  echo "[packetql] Shutting down..."
  kill ${PID_FE:-} ${PID_API:-} ${PID_ENRICH:-} ${PID_KAFKA:-} 2>/dev/null || true
  wait ${PID_FE:-} ${PID_API:-} ${PID_ENRICH:-} ${PID_KAFKA:-} 2>/dev/null || true
}
trap cleanup INT TERM

echo "[packetql] Ready. Open http://localhost:3000"

# Keep container alive and fail fast if critical service dies.
while true; do
  if ! kill -0 ${PID_KAFKA} 2>/dev/null; then
    echo "[packetql] Kafka exited"
    exit 1
  fi
  if [ -n "${PID_ENRICH:-}" ] && ! kill -0 ${PID_ENRICH} 2>/dev/null; then
    echo "[packetql] Enrich pipeline exited"
    exit 1
  fi
  if ! kill -0 ${PID_API} 2>/dev/null; then
    echo "[packetql] API exited"
    exit 1
  fi
  if ! kill -0 ${PID_FE} 2>/dev/null; then
    echo "[packetql] Frontend exited"
    exit 1
  fi
  sleep 2
done
