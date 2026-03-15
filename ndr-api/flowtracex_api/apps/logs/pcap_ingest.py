from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import duckdb


@dataclass
class IngestResult:
    success: bool
    message: str
    tables: Dict[str, int]
    logs_found: List[str]
    work_dir: str


def _find_zeek_binary() -> str:
    candidates = ["/opt/zeek/bin/zeek", "zeek"]
    for c in candidates:
        if c == "zeek":
            found = shutil.which("zeek")
            if found:
                return found
            continue
        if Path(c).exists():
            return c
    raise RuntimeError("Zeek binary not found. Expected /opt/zeek/bin/zeek or zeek in PATH.")


def _zeek_to_parquet_mapping() -> Dict[str, Tuple[str, str]]:
    return {
        "conn.log": (
            "conn",
            """
            SELECT
              TRY_CAST(ts AS DOUBLE) AS ts,
              CAST(uid AS VARCHAR) AS uid,
              CAST("id.orig_h" AS VARCHAR) AS src_ip,
              TRY_CAST("id.orig_p" AS BIGINT) AS src_port,
              CAST("id.resp_h" AS VARCHAR) AS dst_ip,
              TRY_CAST("id.resp_p" AS BIGINT) AS dst_port,
              CAST(proto AS VARCHAR) AS protocol,
              CAST(service AS VARCHAR) AS service,
              CAST(conn_state AS VARCHAR) AS conn_state,
              TRY_CAST(orig_bytes AS BIGINT) AS orig_bytes,
              TRY_CAST(resp_bytes AS BIGINT) AS resp_bytes,
              TRY_CAST(missed_bytes AS BIGINT) AS missed_bytes,
              TRY_CAST(duration AS DOUBLE) AS duration,
              TRY_CAST(ts AS DOUBLE) AS ingest_time
            FROM read_json_auto('{log_path}', ignore_errors=true)
            """,
        ),
        "dns.log": (
            "dns",
            """
            SELECT
              TRY_CAST(ts AS DOUBLE) AS ts,
              CAST(uid AS VARCHAR) AS uid,
              CAST("id.orig_h" AS VARCHAR) AS src_ip,
              TRY_CAST("id.orig_p" AS BIGINT) AS src_port,
              CAST("id.resp_h" AS VARCHAR) AS dst_ip,
              TRY_CAST("id.resp_p" AS BIGINT) AS dst_port,
              CAST(proto AS VARCHAR) AS protocol,
              CAST(query AS VARCHAR) AS query,
              CAST(qtype_name AS VARCHAR) AS qtype_name,
              CAST(rcode_name AS VARCHAR) AS rcode_name,
              TRY_CAST(ts AS DOUBLE) AS ingest_time
            FROM read_json_auto('{log_path}', ignore_errors=true)
            """,
        ),
        "http.log": (
            "http",
            """
            SELECT
              TRY_CAST(ts AS DOUBLE) AS ts,
              CAST(uid AS VARCHAR) AS uid,
              CAST("id.orig_h" AS VARCHAR) AS src_ip,
              TRY_CAST("id.orig_p" AS BIGINT) AS src_port,
              CAST("id.resp_h" AS VARCHAR) AS dst_ip,
              TRY_CAST("id.resp_p" AS BIGINT) AS dst_port,
              CAST(method AS VARCHAR) AS method,
              CAST(host AS VARCHAR) AS host,
              CAST(uri AS VARCHAR) AS uri,
              TRY_CAST(status_code AS BIGINT) AS status_code,
              TRY_CAST(ts AS DOUBLE) AS ingest_time
            FROM read_json_auto('{log_path}', ignore_errors=true)
            """,
        ),
        "ssl.log": (
            "ssl",
            """
            SELECT
              TRY_CAST(ts AS DOUBLE) AS ts,
              CAST(uid AS VARCHAR) AS uid,
              CAST("id.orig_h" AS VARCHAR) AS src_ip,
              TRY_CAST("id.orig_p" AS BIGINT) AS src_port,
              CAST("id.resp_h" AS VARCHAR) AS dst_ip,
              TRY_CAST("id.resp_p" AS BIGINT) AS dst_port,
              CAST(version AS VARCHAR) AS version,
              CAST(server_name AS VARCHAR) AS server_name,
              TRY_CAST(ts AS DOUBLE) AS ingest_time
            FROM read_json_auto('{log_path}', ignore_errors=true)
            """,
        ),
    }


def _snapshot_parquet_files(parquet_base: Path) -> set[str]:
    if not parquet_base.exists():
        return set()
    return {p.as_posix() for p in parquet_base.rglob("*.parquet")}


def _count_parquet_rows(file_path: Path) -> int:
    con = duckdb.connect()
    try:
        p = file_path.as_posix().replace("'", "''")
        row = con.execute(f"SELECT COUNT(*) FROM read_parquet('{p}')").fetchone()
        return int(row[0] or 0) if row else 0
    except Exception:
        return 0
    finally:
        con.close()


def _move_staged_parquet_files(shared_base: Path, source_base: Path) -> Dict[str, int]:
    moved_counts: Dict[str, int] = {}
    for src in sorted(shared_base.rglob("*.parquet")):
        try:
            rel = src.relative_to(shared_base)
        except Exception:
            continue
        table = rel.parts[0] if len(rel.parts) > 0 else "unknown"
        dst = source_base / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            row_count = _count_parquet_rows(src)
            src.replace(dst)
            moved_counts[table] = moved_counts.get(table, 0) + row_count
        except Exception:
            continue
    return moved_counts


def _split_endpoint(value: str) -> Tuple[str, int | None]:
    value = value.strip().strip(",")
    m = re.match(r"^(.*)\.(\d+)$", value)
    if m:
        return m.group(1), int(m.group(2))
    return value, None


def _fallback_tcpdump_to_conn_parquet(pcap_path: Path, parquet_base: Path, run_id: str) -> int:
    def _write_rows(rows: list[dict]) -> int:
        if not rows:
            return 0
        now = datetime.now(tz=timezone.utc)
        out_dir = parquet_base / "conn" / f"year={now.year}" / f"month={now.month:02d}" / f"day={now.day:02d}" / f"hour={now.hour:02d}"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{pcap_path.stem}_{run_id}_fallback.parquet"

        with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False) as tmp:
            tmp_path = tmp.name
            for r in rows:
                tmp.write(json.dumps(r) + "\n")

        con = duckdb.connect()
        try:
            out_file_escaped = out_file.as_posix().replace("'", "''")
            tmp_escaped = tmp_path.replace("'", "''")
            con.execute(
                f"COPY (SELECT * FROM read_json_auto('{tmp_escaped}', ignore_errors=true)) "
                f"TO '{out_file_escaped}' (FORMAT PARQUET)"
            )
        finally:
            con.close()
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass
        return len(rows)

    def _scapy_rows() -> list[dict]:
        try:
            from scapy.all import IP, IPv6, TCP, UDP, PcapReader
        except Exception:
            return []

        rows: list[dict] = []
        try:
            with PcapReader(str(pcap_path)) as reader:
                for pkt in reader:
                    if IP not in pkt and IPv6 not in pkt:
                        continue
                    ts = float(getattr(pkt, "time", 0.0) or 0.0)
                    if IP in pkt:
                        src_ip = str(pkt[IP].src)
                        dst_ip = str(pkt[IP].dst)
                        proto = int(pkt[IP].proto)
                    else:
                        src_ip = str(pkt[IPv6].src)
                        dst_ip = str(pkt[IPv6].dst)
                        proto = int(pkt[IPv6].nh)

                    src_port = None
                    dst_port = None
                    transport = "ip"
                    if TCP in pkt:
                        src_port = int(pkt[TCP].sport)
                        dst_port = int(pkt[TCP].dport)
                        transport = "tcp"
                    elif UDP in pkt:
                        src_port = int(pkt[UDP].sport)
                        dst_port = int(pkt[UDP].dport)
                        transport = "udp"
                    elif proto == 1:
                        transport = "icmp"
                    elif proto == 58:
                        transport = "icmpv6"

                    service = "dhcp" if src_port in (67, 68) or dst_port in (67, 68) else None
                    rows.append(
                        {
                            "ts": ts,
                            "uid": f"pcap-{run_id}-{len(rows)+1}",
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": transport,
                            "service": service,
                            "conn_state": None,
                            "orig_bytes": None,
                            "resp_bytes": None,
                            "missed_bytes": None,
                            "duration": None,
                            "ingest_time": ts,
                        }
                    )
        except Exception:
            return []
        return rows

    cmd = ["tcpdump", "-nn", "-tt", "-r", str(pcap_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    rows = []
    if proc.returncode == 0:
        for raw in (proc.stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue

            m = re.match(r"^(?P<ts>\d+(?:\.\d+)?)\s+(?P<l3>IP6?|ARP)\s+(?P<rest>.+)$", line)
            if not m:
                continue
            ts = float(m.group("ts"))
            l3 = m.group("l3")
            rest = m.group("rest")

            ep = re.match(r"^(?P<src>\S+)\s*>\s*(?P<dst>[^:]+):\s*(?P<msg>.*)$", rest)
            if not ep:
                continue

            src_raw = ep.group("src")
            dst_raw = ep.group("dst")
            msg = ep.group("msg")
            src_ip, src_port = _split_endpoint(src_raw)
            dst_ip, dst_port = _split_endpoint(dst_raw)

            proto = "udp" if (".67" in src_raw or ".67" in dst_raw or ".68" in src_raw or ".68" in dst_raw) else l3.lower()
            service = "dhcp" if "dhcp" in msg.lower() or src_port in (67, 68) or dst_port in (67, 68) else None

            rows.append(
                {
                    "ts": ts,
                    "uid": f"pcap-{run_id}-{len(rows)+1}",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "service": service,
                    "conn_state": None,
                    "orig_bytes": None,
                    "resp_bytes": None,
                    "missed_bytes": None,
                    "duration": None,
                    "ingest_time": ts,
                }
            )

    if not rows:
        rows = _scapy_rows()

    return _write_rows(rows)


def _normalize_mixed_pcapng_to_ethernet_pcap(input_path: Path, output_path: Path) -> tuple[bool, str]:
    """
    Normalize pcapng files with mixed linktypes/snaplen into Ethernet-only PCAP.
    This helps Zeek/libpcap parse captures that otherwise fail on interface mismatch.
    """
    try:
        from scapy.utils import PcapWriter, RawPcapNgReader
    except Exception as e:
        return False, f"Scapy unavailable for normalization: {e}"

    kept = 0
    dropped = 0
    try:
        writer = PcapWriter(str(output_path), linktype=1, append=False, sync=True)
        try:
            for raw, meta in RawPcapNgReader(str(input_path)):
                if getattr(meta, "linktype", None) != 1:
                    dropped += 1
                    continue
                writer.write(raw)
                kept += 1
        finally:
            writer.close()
    except Exception as e:
        return False, f"Normalization failed: {e}"

    if kept == 0:
        return False, "Normalization produced zero Ethernet packets."
    return True, f"Normalized mixed-linktype capture (kept={kept}, dropped={dropped})."


def ingest_pcap_to_parquet(
    pcap_path: Path,
    data_dir: Path,
    source_parquet_base: Path | None = None,
    timeout_sec: int = 180,
) -> IngestResult:
    zeek_bin = _find_zeek_binary()
    run_id = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
    work_dir = data_dir / "work" / "pcap_ingest" / run_id
    work_dir.mkdir(parents=True, exist_ok=True)
    shared_parquet_base = data_dir / "parquet"
    shared_parquet_base.mkdir(parents=True, exist_ok=True)

    parse_path = pcap_path
    normalize_note = ""

    def _zeek_cmd(target_pcap: Path) -> list[str]:
        return [
            zeek_bin,
            "-C",
            "-r",
            str(target_pcap),
            "-e",
            f"redef Log::default_logdir = \"{work_dir}\";",
            "-e",
            "redef LogAscii::use_json = T;",
            "local",
        ]

    try:
        subprocess.run(_zeek_cmd(parse_path), check=True, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        normalize_trigger = (
            "snapshot length" in stderr.lower()
            or "different from the snapshot length of the first interface" in stderr.lower()
        )
        if normalize_trigger:
            normalized_path = work_dir / f"{pcap_path.stem}_normalized.pcap"
            ok, note = _normalize_mixed_pcapng_to_ethernet_pcap(pcap_path, normalized_path)
            if ok:
                normalize_note = note
                parse_path = normalized_path
                try:
                    subprocess.run(_zeek_cmd(parse_path), check=True, capture_output=True, text=True, timeout=timeout_sec)
                except subprocess.CalledProcessError as e2:
                    stderr2 = (e2.stderr or "").strip()
                    fallback_rows = _fallback_tcpdump_to_conn_parquet(pcap_path, source_parquet_base or (data_dir / "parquet"), run_id)
                    if fallback_rows > 0:
                        return IngestResult(
                            True,
                            "Zeek failed after normalization; tcpdump fallback ingested conn rows.",
                            {"conn": fallback_rows},
                            ["tcpdump_fallback"],
                            str(work_dir),
                        )
                    msg = stderr2[:300] if stderr2 else "Zeek failed to parse PCAP after normalization."
                    return IngestResult(False, msg, {}, [], str(work_dir))
            else:
                fallback_rows = _fallback_tcpdump_to_conn_parquet(pcap_path, source_parquet_base or (data_dir / "parquet"), run_id)
                if fallback_rows > 0:
                    return IngestResult(
                        True,
                        f"Zeek parse failed; normalization failed ({note}); tcpdump fallback ingested conn rows.",
                        {"conn": fallback_rows},
                        ["tcpdump_fallback"],
                        str(work_dir),
                    )
                msg = stderr[:300] if stderr else "Zeek failed to parse PCAP."
                return IngestResult(False, msg, {}, [], str(work_dir))
        else:
            fallback_rows = _fallback_tcpdump_to_conn_parquet(pcap_path, source_parquet_base or (data_dir / "parquet"), run_id)
            if fallback_rows > 0:
                return IngestResult(
                    True,
                    "Zeek parse failed; tcpdump fallback ingested conn rows.",
                    {"conn": fallback_rows},
                    ["tcpdump_fallback"],
                    str(work_dir),
                )
            msg = stderr[:300] if stderr else "Zeek failed to parse PCAP."
            return IngestResult(False, msg, {}, [], str(work_dir))
    except subprocess.TimeoutExpired:
        return IngestResult(False, f"PCAP parsing timed out after {timeout_sec}s", {}, [], str(work_dir))

    mapping = _zeek_to_parquet_mapping()
    found_logs = [p.name for p in work_dir.glob("*.log") if p.name in mapping]
    if source_parquet_base is None:
        source_parquet_base = shared_parquet_base
    source_parquet_base.mkdir(parents=True, exist_ok=True)

    # Primary path: Native Zeek Kafka writer (already enabled) -> ndr-enrich -> parquet.
    # We do not re-publish in Python; we only observe parquet row deltas.
    kafka_topic = "zeek-raw"
    # In Kafka-first mode, data arrives in chunks. Do NOT mark completion on first chunk:
    # keep moving new parquet files until we observe a quiet period with no new files.
    deadline = time.time() + max(25, int(timeout_sec))
    quiet_after_sec = 30
    seen_progress = False
    last_progress_at = time.time()
    moved_totals: Dict[str, int] = {}

    while time.time() < deadline:
        moved = _move_staged_parquet_files(shared_parquet_base, source_parquet_base)
        if moved:
            seen_progress = True
            last_progress_at = time.time()
            for table, count in moved.items():
                moved_totals[table] = moved_totals.get(table, 0) + int(count or 0)

        if seen_progress and (time.time() - last_progress_at) >= quiet_after_sec:
            final_move = _move_staged_parquet_files(shared_parquet_base, source_parquet_base)
            for table, count in final_move.items():
                moved_totals[table] = moved_totals.get(table, 0) + int(count or 0)
            return IngestResult(
                True,
                (
                    f"Kafka-first ingest succeeded via native Zeek writer on topic '{kafka_topic}'. "
                    f"{normalize_note}"
                ).strip(),
                moved_totals,
                found_logs,
                str(work_dir),
            )

        time.sleep(1)

    final_move = _move_staged_parquet_files(shared_parquet_base, source_parquet_base)
    for table, count in final_move.items():
        moved_totals[table] = moved_totals.get(table, 0) + int(count or 0)
    if moved_totals:
        return IngestResult(
            True,
            (
                f"Kafka-first ingest succeeded via native Zeek writer on topic '{kafka_topic}'. "
                f"{normalize_note}"
            ).strip(),
            moved_totals,
            found_logs,
            str(work_dir),
        )

    if not found_logs:
        fallback_rows = _fallback_tcpdump_to_conn_parquet(pcap_path, source_parquet_base, run_id)
        if fallback_rows > 0:
            return IngestResult(
                True,
                "Fallback parser used (tcpdump/scapy) and conn rows were ingested.",
                {"conn": fallback_rows},
                ["tcpdump_fallback"],
                str(work_dir),
            )
        return IngestResult(False, "No supported Zeek logs were generated from this PCAP.", {}, [], str(work_dir))

    now = datetime.now(tz=timezone.utc)
    year, month, day, hour = now.year, now.month, now.day, now.hour
    parquet_base = data_dir / "parquet"
    parquet_base.mkdir(parents=True, exist_ok=True)

    tables_written: Dict[str, int] = {}
    con = duckdb.connect()
    try:
        for log_name in found_logs:
            table_name, sql_template = mapping[log_name]
            log_path = (work_dir / log_name).as_posix().replace("'", "''")
            sql = sql_template.format(log_path=log_path)

            out_dir = source_parquet_base / table_name / f"year={year}" / f"month={month:02d}" / f"day={day:02d}" / f"hour={hour:02d}"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{pcap_path.stem}_{run_id}.parquet"
            out_file_escaped = out_file.as_posix().replace("'", "''")

            count_row = con.execute(f"SELECT COUNT(*) FROM ({sql}) t").fetchone()
            row_count = int(count_row[0] or 0) if count_row else 0
            if row_count == 0:
                continue
            con.execute(f"COPY ({sql}) TO '{out_file_escaped}' (FORMAT PARQUET)")
            tables_written[table_name] = tables_written.get(table_name, 0) + row_count
    finally:
        con.close()

    if not tables_written:
        return IngestResult(False, "PCAP processed, but no rows were extracted into supported tables.", {}, found_logs, str(work_dir))

    return IngestResult(True, "PCAP parsed and parquet tables updated.", tables_written, found_logs, str(work_dir))
