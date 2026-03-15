#!/usr/bin/env bash
set -e
curl -fsS http://127.0.0.1:3000/ >/dev/null
curl -fsS http://127.0.0.1:8010/api/v1/system/health >/dev/null
nc -z 127.0.0.1 9092
pgrep -f '/opt/packetql/ndr-enrich/zeek-parquet-pipeline' >/dev/null
pgrep -f 'gunicorn.*flowtracex_api.wsgi:application' >/dev/null
