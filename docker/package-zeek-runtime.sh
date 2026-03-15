#!/usr/bin/env bash
set -euo pipefail

ZEEK_DIR="${1:-/opt/zeek}"
OUTPUT_TAR="${2:-$(pwd)/docker/zeek-runtime.tar.gz}"

if [ ! -d "${ZEEK_DIR}" ]; then
  echo "[zeek-package] Missing Zeek directory: ${ZEEK_DIR}" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

mkdir -p "${tmpdir}/opt/zeek"

for path in bin etc lib share; do
  if [ -e "${ZEEK_DIR}/${path}" ]; then
    cp -a "${ZEEK_DIR}/${path}" "${tmpdir}/opt/zeek/${path}"
  fi
done

rm -rf \
  "${tmpdir}/opt/zeek/logs" \
  "${tmpdir}/opt/zeek/spool" \
  "${tmpdir}/opt/zeek/var" \
  "${tmpdir}/opt/zeek/include" \
  "${tmpdir}/opt/zeek/share/btest" \
  "${tmpdir}/opt/zeek/share/man" \
  "${tmpdir}/opt/zeek/share/zeek/cmake" \
  "${tmpdir}/opt/zeek/share/zeek/python" \
  "${tmpdir}/opt/zeek/share/zeek/zeekygen" \
  "${tmpdir}/opt/zeek/share/zeekctl" \
  "${tmpdir}/opt/zeek/lib/cmake"

find "${tmpdir}/opt/zeek/lib" -type f \( -name '*.a' -o -name '*.la' \) -delete

plugin_root="${tmpdir}/opt/zeek/lib/zeek/plugins/packages/zeek-kafka"
if [ -d "${plugin_root}" ]; then
  if [ -L "${plugin_root}/scripts" ]; then
    scripts_src="$(readlink -f "${ZEEK_DIR}/lib/zeek/plugins/packages/zeek-kafka/scripts")"
    rm -f "${plugin_root}/scripts"
    if [ -d "${scripts_src}" ]; then
      mkdir -p "${plugin_root}/scripts"
      cp -a "${scripts_src}/." "${plugin_root}/scripts/"
    fi
  fi

  rm -rf "${plugin_root}/CMakeFiles" "${plugin_root}/dist"
  find "${plugin_root}" -type f \
    \( -name 'CMakeCache.txt' \
    -o -name 'cmake_install.cmake' \
    -o -name 'Makefile' \
    -o -name 'compile_commands.json' \
    -o -name 'config.status' \
    -o -name '*.cc' \
    -o -name '*.h' \) -delete
fi

mkdir -p "$(dirname "${OUTPUT_TAR}")"
tar -czf "${OUTPUT_TAR}" -C "${tmpdir}" opt

echo "[zeek-package] Wrote ${OUTPUT_TAR}"
du -h "${OUTPUT_TAR}"
