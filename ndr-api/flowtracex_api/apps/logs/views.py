from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import StreamingHttpResponse, HttpResponse
from django.conf import settings
from services.log_service import LogService
from clients.state_store_client import StateStoreClient
from clients.duckdb_client import DuckDBClient
import threading
import json
from pathlib import Path
from datetime import datetime
import re
from .pcap_ingest import ingest_pcap_to_parquet
from .data_sources import (
    create_data_source,
    get_current_source,
    list_data_sources,
    reset_shared_ingest_runtime,
    resolve_source,
    reset_all_data_sources,
    set_current_source,
    update_data_source_ingest,
)


def _safe_age_seconds(iso_value: str) -> int | None:
    try:
        dt = datetime.fromisoformat(str(iso_value).replace("Z", "+00:00"))
        return max(0, int((datetime.now(dt.tzinfo) - dt).total_seconds()))
    except Exception:
        return None


def _mark_stale_processing_failed(data_dir: Path, stale_sec: int = 1800) -> None:
    for src in list_data_sources(data_dir):
        if str(src.ingest_status).lower() != "processing":
            continue
        age = _safe_age_seconds(src.updated_at or src.created_at)
        if age is not None and age > stale_sec:
            update_data_source_ingest(
                data_dir=data_dir,
                source_id=src.source_id,
                ingest_status="failed",
                ingest_message="Processing timed out (stale job). Please re-upload.",
                ingest_tables=src.ingest_tables or {},
            )


def _auto_finalize_stale_processing(data_dir: Path, finalize_after_sec: int = 30) -> None:
    for src in list_data_sources(data_dir):
        if str(src.ingest_status).lower() != "processing":
            continue
        age = _safe_age_seconds(src.updated_at or src.created_at)
        if age is None or age < finalize_after_sec:
            continue
        counts = _collect_table_counts(Path(src.parquet_dir))
        total = sum(counts.values())
        if total <= 0:
            continue
        update_data_source_ingest(
            data_dir=data_dir,
            source_id=src.source_id,
            ingest_status="ready",
            ingest_message="Processing completed.",
            ingest_tables=counts,
        )


def _collect_table_counts(parquet_base: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    try:
        tables = DuckDBClient.get_available_tables(parquet_base=parquet_base)
        for table in tables:
            q_table = '"' + str(table).replace('"', '""') + '"'
            rows = DuckDBClient.execute_dict_rows(f"SELECT COUNT(*) AS c FROM {q_table}", parquet_base=parquet_base)
            counts[table] = int((rows[0] or {}).get("c", 0) if rows else 0)
    except Exception:
        return counts
    return counts

class LogSearchView(APIView):

    def get(self, request):
        service = LogService()
        filters = request.query_params.dict()

        # Parse structured query builder conditions from JSON param
        conditions_raw = request.query_params.get('conditions', '')
        if conditions_raw:
            try:
                filters['conditions'] = json.loads(conditions_raw)
            except (json.JSONDecodeError, TypeError):
                filters['conditions'] = []
        else:
            filters['conditions'] = []

        page  = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))

        data = service.search_logs(filters, page, limit)
        return Response(data)

class LogAnalyticsView(APIView):

    def get(self, request):
        service = LogService()
        window = request.query_params.get('window', '24h')
        source_id = request.query_params.get('source_id')
        data = service.get_analytics(window=window, source_id=source_id)
        return Response(data)

class LogLiveStreamView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        service = LogService()
        return StreamingHttpResponse(service.stream_logs(), content_type='text/event-stream')


class LogPcapUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def _ingest_in_background(data_dir: Path, source_id: str, target: Path, parquet_dir: str):
        stop_heartbeat = threading.Event()
        stage = {"message": "Parsing PCAP and extracting events..."}
        parquet_base = Path(parquet_dir)

        def _heartbeat():
            while not stop_heartbeat.is_set():
                partial_counts = _collect_table_counts(parquet_base)
                partial_rows = sum(partial_counts.values())
                msg = stage["message"]
                if partial_rows > 0:
                    msg = f"{stage['message']} Rows written: {partial_rows}"
                update_data_source_ingest(
                    data_dir=data_dir,
                    source_id=source_id,
                    ingest_status="processing",
                    ingest_message=msg,
                    ingest_tables=partial_counts,
                )
                stop_heartbeat.wait(2)

        hb = threading.Thread(target=_heartbeat, daemon=True)
        hb.start()
        try:
            ingest = ingest_pcap_to_parquet(
                target,
                data_dir=data_dir,
                source_parquet_base=parquet_base,
            )
            stage["message"] = "Finalizing parsed data..."
            status_name = "ready" if ingest.success else "failed"
            stop_heartbeat.set()
            update_data_source_ingest(
                data_dir=data_dir,
                source_id=source_id,
                ingest_status=status_name,
                ingest_message=ingest.message,
                ingest_tables=ingest.tables,
            )
            if ingest.success:
                for key in StateStoreClient.scan_keys("ndr:logs:analytics:*"):
                    StateStoreClient.delete(key)
        except Exception as e:
            update_data_source_ingest(
                data_dir=data_dir,
                source_id=source_id,
                ingest_status="failed",
                ingest_message=f"Background ingest error: {e}",
                ingest_tables={},
            )
        finally:
            stop_heartbeat.set()

    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        name = (file_obj.name or "").strip()
        lower = name.lower()
        if not (lower.endswith('.pcap') or lower.endswith('.pcapng')):
            return Response({"error": "Only .pcap or .pcapng files are supported"}, status=status.HTTP_400_BAD_REQUEST)

        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        _mark_stale_processing_failed(data_dir)
        _auto_finalize_stale_processing(data_dir)
        for src in list_data_sources(data_dir):
            if str(src.ingest_status).lower() == "processing":
                return Response(
                    {
                        "error": "Another PCAP is currently processing. Wait until it finishes before uploading a new file.",
                        "active_source": src.to_dict(),
                    },
                    status=status.HTTP_409_CONFLICT,
                )

        reset_shared_ingest_runtime(data_dir)
        ds = create_data_source(data_dir, upload_name=name, upload_size=file_obj.size)
        target = Path(ds.root_dir) / "raw" / name

        with target.open('wb+') as dest:
            for chunk in file_obj.chunks():
                dest.write(chunk)

        # Return immediately and parse asynchronously to avoid UI "stuck at 100%" for large PCAPs.
        t = threading.Thread(
            target=self._ingest_in_background,
            args=(data_dir, ds.source_id, target, ds.parquet_dir),
            daemon=True,
        )
        t.start()

        return Response({
            "status": "uploaded",
            "filename": target.name,
            "size": target.stat().st_size,
            "path": str(target),
            "source": ds.to_dict(),
            "ingest": {
                "success": True,
                "status": "processing",
                "message": "Upload completed. Parsing started in background.",
                "tables": {},
            },
        }, status=status.HTTP_201_CREATED)


class LogPcapListView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        sources = [s.to_dict() for s in list_data_sources(data_dir)]
        return Response({"files": sources})


class DataSourceListView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        sources = [s.to_dict() for s in list_data_sources(data_dir)]
        return Response({"sources": sources})


class CurrentDataSourceView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        ds = get_current_source(data_dir)
        if not ds:
            return Response({"current": None})
        return Response({"current": ds.to_dict()})

    def post(self, request):
        source_id = (request.data.get("source_id") or "").strip()
        if not source_id:
            return Response({"error": "source_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        ok = set_current_source(data_dir, source_id)
        if not ok:
            return Response({"error": "unknown source_id"}, status=status.HTTP_404_NOT_FOUND)
        ds = resolve_source(data_dir, source_id)
        return Response({"current": ds.to_dict() if ds else None})


class DataSourceSummaryView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        source_id = request.query_params.get('source_id')
        ds = resolve_source(data_dir, source_id)
        if not ds:
            return Response({"error": "No data source selected"}, status=status.HTTP_404_NOT_FOUND)

        parquet_base = Path(ds.parquet_dir)
        tables = DuckDBClient.get_available_tables(parquet_base=parquet_base)
        table_counts = {}
        total_events = 0
        for table in tables:
            q_table = '"' + str(table).replace('"', '""') + '"'
            rows = DuckDBClient.execute_dict_rows(f"SELECT COUNT(*) AS c FROM {q_table}", parquet_base=parquet_base)
            count = int((rows[0] or {}).get("c", 0) if rows else 0)
            table_counts[table] = count
            total_events += count

        protocol_distribution = []
        if "conn" in tables:
            protocol_distribution = DuckDBClient.execute_dict_rows(
                """
                SELECT
                  LOWER(COALESCE(CAST(protocol AS VARCHAR), 'unknown')) AS protocol,
                  COUNT(*) AS count
                FROM conn
                GROUP BY 1
                ORDER BY count DESC
                LIMIT 8
                """,
                parquet_base=parquet_base,
            )

        return Response({
            "source": ds.to_dict(),
            "summary": {
                "total_events": total_events,
                "table_counts": table_counts,
                "protocol_distribution": protocol_distribution,
            },
            "ingest": {
                "status": ds.ingest_status,
                "message": ds.ingest_message,
                "tables": ds.ingest_tables or {},
                "updated_at": ds.updated_at,
            },
        })


class TableSchemaView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        source_id = request.query_params.get('source_id')
        ds = resolve_source(data_dir, source_id)
        if not ds:
            return Response({"error": "No data source selected"}, status=status.HTTP_404_NOT_FOUND)

        parquet_base = Path(ds.parquet_dir)
        con = DuckDBClient.get_connection(parquet_base=parquet_base)
        if con is None:
            return Response({"error": "DuckDB connection unavailable"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            tables = DuckDBClient.get_available_tables(parquet_base=parquet_base)
            schema_tables = []
            for table in tables:
                q_table = '"' + str(table).replace('"', '""') + '"'
                try:
                    rows = con.execute(f"DESCRIBE SELECT * FROM {q_table} LIMIT 0").fetchall()
                    fields = [{"name": r[0], "type": r[1]} for r in rows]
                except Exception:
                    fields = []
                schema_tables.append({
                    "table": table,
                    "field_count": len(fields),
                    "fields": fields,
                })
            return Response({"source": ds.to_dict(), "tables": schema_tables})
        finally:
            con.close()


class ResetDataView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        confirm = bool(request.data.get("confirm"))
        if not confirm:
            return Response({"error": "confirm=true is required"}, status=status.HTTP_400_BAD_REQUEST)

        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        result = reset_all_data_sources(data_dir)

        for key in StateStoreClient.scan_keys("ndr:logs:analytics:*"):
            StateStoreClient.delete(key)

        return Response({
            "status": "ok",
            "message": "All uploaded PCAP data and derived data were deleted.",
            **result,
        })


class IngestStatusView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        _mark_stale_processing_failed(data_dir)
        _auto_finalize_stale_processing(data_dir)
        sources = list_data_sources(data_dir)
        active = next((s for s in sources if str(s.ingest_status).lower() == "processing"), None)
        recent = None
        for src in sources:
            st = str(src.ingest_status).lower()
            if st in {"ready", "failed"}:
                age = _safe_age_seconds(src.updated_at or src.created_at)
                if age is None or age <= 900:
                    recent = src
                    break
        if not active:
            return Response({
                "has_active": False,
                "active": None,
                "recent": recent.to_dict() if recent else None,
            })

        updated_at = active.updated_at or active.created_at
        age_sec = _safe_age_seconds(updated_at)

        return Response({
            "has_active": True,
            "active": {
                "source": active.to_dict(),
                "ingest": {
                    "status": active.ingest_status,
                    "message": active.ingest_message,
                    "tables": active.ingest_tables or {},
                    "updated_at": updated_at,
                    "age_seconds": age_sec,
                },
            },
            "recent": recent.to_dict() if recent else None,
        })


def _extract_dropped_packets(message: str) -> int:
    text = str(message or "")
    m = re.search(r"dropped\s*=\s*(\d+)", text, flags=re.IGNORECASE)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return 0
    if "drop" in text.lower():
        # If drop is mentioned but no count is available, mark as unknown(1) for visibility.
        return 1
    return 0


def _log_level(line: str) -> str:
    low = line.lower()
    if "critical" in low:
        return "critical"
    if "error" in low or "failed" in low or "exception" in low:
        return "error"
    if "warn" in low or "timeout" in low:
        return "warning"
    if "drop" in low:
        return "drop"
    return "info"


def _collect_log_entries(paths: list[Path], max_lines_per_file: int = 80) -> list[dict]:
    keywords = ("error", "failed", "exception", "warn", "timeout", "drop", "stale")
    files_payload: list[dict] = []
    for p in paths:
        if not p.exists() or not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        filtered = [ln for ln in lines if any(k in ln.lower() for k in keywords)]
        if not filtered:
            continue
        sample = filtered[-max_lines_per_file:]
        files_payload.append({
            "file": str(p),
            "entries": [{"line": ln[-400:], "level": _log_level(ln)} for ln in sample],
        })
    return files_payload


class PipelineHealthView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        data_dir = Path(getattr(settings, 'DATA_DIR', Path('.')))
        source_id = request.query_params.get('source_id')
        current = resolve_source(data_dir, source_id)
        sources = list_data_sources(data_dir)

        if source_id:
            sources = [s for s in sources if s.source_id == source_id]

        processing_rows = []
        dropped_rows = []
        total_dropped = 0
        for src in sources:
            age = _safe_age_seconds(src.updated_at or src.created_at)
            tables = src.ingest_tables or {}
            dropped = _extract_dropped_packets(src.ingest_message or "")
            total_rows = sum(int(v or 0) for v in tables.values())
            row = {
                "source_id": src.source_id,
                "name": src.name,
                "status": src.ingest_status,
                "message": src.ingest_message,
                "updated_at": src.updated_at or src.created_at,
                "age_seconds": age,
                "tables": tables,
                "total_rows": total_rows,
                "dropped_packets": dropped,
            }
            processing_rows.append(row)
            if dropped > 0:
                dropped_rows.append(row)
                total_dropped += dropped

        processing_rows.sort(key=lambda r: str(r.get("updated_at", "")), reverse=True)
        active = next((r for r in processing_rows if str(r.get("status", "")).lower() == "processing"), None)

        project_dir = Path(getattr(settings, "PROJECT_DIR", Path(".")))
        log_candidates = [
            project_dir / "capture_loss.log",
            project_dir / "packet_filter.log",
            project_dir / "analyzer.log",
            project_dir / "reporter.log",
            project_dir / "logs" / "ndr-enrich.log",
            project_dir / "logs" / "ndr-api.log",
        ]
        log_files = _collect_log_entries(log_candidates)

        source_failures = [
            {
                "source_id": r["source_id"],
                "name": r["name"],
                "status": r["status"],
                "message": r["message"],
                "updated_at": r["updated_at"],
            }
            for r in processing_rows
            if str(r.get("status", "")).lower() == "failed" or "error" in str(r.get("message", "")).lower()
        ]

        return Response({
            "current_source": current.to_dict() if current else None,
            "processing_status": {
                "active": active,
                "sources": processing_rows[:30],
            },
            "dropped_events": {
                "total_dropped_packets": total_dropped,
                "sources": dropped_rows[:30],
            },
            "error_logs": {
                "files": log_files[:8],
                "source_failures": source_failures[:30],
            },
        })


def _build_schema_tables(project_dir: Path) -> list[dict]:
    catalog_path = project_dir / "ndr-frontend" / "gui" / "constants" / "zeek_field_catalog.json"
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    logs = payload.get("zeek_logs", [])
    tables = []
    for src in logs:
        name = str(src.get("name", "")).strip().lower()
        if not name:
            continue
        fields_map: dict[str, str] = {}
        for f in (src.get("raw_fields", []) or []):
            col = str(f.get("parquet", "")).strip()
            typ = str(f.get("type", "string")).strip().lower()
            if col and col not in fields_map:
                fields_map[col] = typ
        for f in (src.get("normalized_enriched", []) or []):
            col = str(f.get("parquet", "")).strip()
            typ = str(f.get("type", "string")).strip().lower()
            if col and col not in fields_map:
                fields_map[col] = typ
        fields = [{"name": col, "type": fields_map[col]} for col in sorted(fields_map.keys())]
        tables.append({"table": name, "fields": fields})
    tables.sort(key=lambda t: t["table"])
    return tables


def _to_sql_type(raw: str) -> str:
    t = str(raw or "").lower()
    if "bool" in t:
        return "BOOLEAN"
    if "int64" in t or "bigint" in t:
        return "BIGINT"
    if "int" in t:
        return "INTEGER"
    if "float" in t or "double" in t:
        return "DOUBLE"
    return "VARCHAR"


def _build_schema_sql(tables: list[dict]) -> str:
    lines = [
        "-- PCAPQL Schema Guide (Zeek Tables)",
        "-- Use these table/field definitions when asking AI to generate DuckDB SQL.",
        "",
    ]
    for t in tables:
        lines.append(f"CREATE TABLE {t['table']} (")
        cols = t.get("fields", [])
        for idx, f in enumerate(cols):
            comma = "," if idx < len(cols) - 1 else ""
            lines.append(f"  {f['name']} {_to_sql_type(f['type'])}{comma}")
        lines.append(");")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _build_schema_markdown(tables: list[dict]) -> str:
    lines = [
        "# PCAPQL AI SQL Assistant Guide",
        "",
        "## How to Use with ChatGPT/AI",
        "",
        "1. Download the schema SQL/PDF from PCAPQL.",
        "2. Upload the file into ChatGPT (or your AI assistant).",
        "3. Ask for a query with clear SOC intent (IOC hunt, beaconing, DNS anomalies, etc.).",
        "4. Copy generated SQL into PCAPQL SQL Query page and run.",
        "5. Verify results and refine query.",
        "",
        "## Safety Notes",
        "",
        "- Remove sensitive tenant/client identifiers before sharing externally.",
        "- Validate generated SQL before execution.",
        "- Prefer `LIMIT` for first run, then expand scope.",
        "",
        "## Prompt Template",
        "",
        "```",
        "You are a SOC SQL assistant for DuckDB.",
        "Use only the uploaded schema.",
        "Task: <describe detection objective>",
        "Return: SQL + short explanation + any assumptions.",
        "```",
        "",
        "## Table Summary",
        "",
    ]
    for t in tables:
        lines.append(f"### `{t['table']}`")
        for f in t.get("fields", []):
            lines.append(f"- `{f['name']}` ({_to_sql_type(f['type'])})")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_text_pdf(lines: list[str]) -> bytes:
    # Minimal multi-page PDF writer (Courier font, text-only).
    width, height = 612, 792
    top_margin = 760
    line_height = 13
    left = 40
    lines_per_page = 52
    pages_data = []
    for i in range(0, len(lines), lines_per_page):
        pages_data.append(lines[i:i + lines_per_page])
    if not pages_data:
        pages_data = [["PCAPQL Schema Guide"]]

    objects: list[str] = []

    def add_obj(content: str) -> int:
        objects.append(content)
        return len(objects)

    font_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    pages_id = add_obj("<< /Type /Pages /Kids [__KIDS__] /Count __COUNT__ >>")
    page_ids: list[int] = []

    for page_lines in pages_data:
        text_cmd = [f"BT /F1 10 Tf {left} {top_margin} Td"]
        for idx, ln in enumerate(page_lines):
            if idx == 0:
                text_cmd.append(f"({_pdf_escape(ln[:150])}) Tj")
            else:
                text_cmd.append(f"T* ({_pdf_escape(ln[:150])}) Tj")
        text_cmd.append("ET")
        stream = "\n".join(text_cmd)
        content_id = add_obj(f"<< /Length {len(stream.encode('utf-8'))} >>\nstream\n{stream}\nendstream")
        page_id = add_obj(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {width} {height}] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        )
        page_ids.append(page_id)

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[pages_id - 1] = objects[pages_id - 1].replace("__KIDS__", kids).replace("__COUNT__", str(len(page_ids)))
    catalog_id = add_obj(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{i} 0 obj\n".encode("utf-8"))
        out.extend(obj.encode("utf-8"))
        out.extend(b"\nendobj\n")
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("utf-8"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("utf-8"))
    out.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("utf-8")
    )
    return bytes(out)


class SchemaGuideView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        fmt = str(request.query_params.get("format", "sql")).lower()
        project_dir = Path(getattr(settings, "PROJECT_DIR", Path(".")))
        tables = _build_schema_tables(project_dir)

        if fmt == "sql":
            content = _build_schema_sql(tables)
            resp = HttpResponse(content, content_type="text/plain; charset=utf-8")
            resp["Content-Disposition"] = 'attachment; filename="pcapql_schema.sql"'
            return resp

        if fmt in {"md", "markdown"}:
            content = _build_schema_markdown(tables)
            resp = HttpResponse(content, content_type="text/markdown; charset=utf-8")
            resp["Content-Disposition"] = 'attachment; filename="pcapql_ai_sql_guide.md"'
            return resp

        if fmt == "pdf":
            md = _build_schema_markdown(tables)
            sql = _build_schema_sql(tables)
            lines = (md + "\n\n---\n\n" + sql).splitlines()
            pdf_bytes = _build_text_pdf(lines)
            resp = HttpResponse(pdf_bytes, content_type="application/pdf")
            resp["Content-Disposition"] = 'attachment; filename="pcapql_ai_sql_guide.pdf"'
            return resp

        return Response({"error": "Unsupported format. Use sql, md, or pdf."}, status=status.HTTP_400_BAD_REQUEST)
