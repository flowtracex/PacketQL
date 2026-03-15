#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8093}"
API_URL="${API_URL:-http://127.0.0.1:18013}"
CONTAINER_NAME="${CONTAINER_NAME:-packetql-validation}"
SMALL_PCAP="${SMALL_PCAP:-${ROOT_DIR}/dhcp.pcap}"
LARGE_PCAP="${LARGE_PCAP:-${ROOT_DIR}/data/sources/4sics-geeklounge-151020_20260315055953/raw/4SICS-GeekLounge-151020.pcap}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

python3 - <<PY
import json, sys, urllib.request
base = "${BASE_URL}"
api = "${API_URL}"
ui_code = urllib.request.urlopen(base).status
health = json.load(urllib.request.urlopen(api + "/api/v1/system/health"))
if ui_code != 200 or health.get("status") != "healthy":
    raise SystemExit(f"initial health failed: ui={ui_code} api={health}")
print("initial health ok")
PY

upload_file() {
  local file_path="$1"
  local out_json="$2"
  curl -fsS -F "file=@${file_path}" "${BASE_URL}/api/v1/logs/upload-pcap" > "${out_json}"
}

wait_for_idle() {
  python3 - <<PY
import json, time, urllib.request
api = "${API_URL}/api/v1/logs/ingest-status"
for _ in range(180):
    data = json.load(urllib.request.urlopen(api))
    if not data.get("active"):
        print(json.dumps(data))
        raise SystemExit(0)
    time.sleep(2)
raise SystemExit("timed out waiting for ingest to finish")
PY
}

assert_recent_counts() {
  local source_name="$1"
  local min_total="$2"
  python3 - <<PY
import json, urllib.request
data = json.load(urllib.request.urlopen("${API_URL}/api/v1/logs/data-sources"))
sources = data.get("sources", [])
target = next((s for s in sources if s.get("name") == "${source_name}"), None)
if not target:
    raise SystemExit("source not found: ${source_name}")
tables = target.get("ingest_tables") or {}
total = sum(int(v or 0) for v in tables.values())
if str(target.get("ingest_status")).lower() != "ready":
    raise SystemExit(f"source not ready: {target}")
if total < ${min_total}:
    raise SystemExit(f"row count too low for ${source_name}: total={total} tables={tables}")
print(json.dumps({"source": target.get("source_id"), "tables": tables, "total": total}))
PY
}

echo "[validate] Uploading small PCAP: ${SMALL_PCAP}"
upload_file "${SMALL_PCAP}" "${tmpdir}/small.json"
wait_for_idle >/dev/null
assert_recent_counts "dhcp.pcap" 5

if [ -f "${LARGE_PCAP}" ]; then
  echo "[validate] Uploading large PCAP: ${LARGE_PCAP}"
  upload_file "${LARGE_PCAP}" "${tmpdir}/large.json"
  wait_for_idle >/dev/null
  assert_recent_counts "4SICS-GeekLounge-151020.pcap" 15000
fi

if docker exec "${CONTAINER_NAME}" sh -lc "grep -Eq 'Unknown Topic Or Partition|output channel full|dropping message|route channel full|producer write error' /tmp/packetql/enrich.log"; then
  echo "[validate] Kafka/pipeline errors found in enrich log" >&2
  exit 1
fi

echo "[validate] Production validation passed"
