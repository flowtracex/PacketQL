from ..base.log_repo import LogRepository
from clients.duckdb_client import DuckDBClient
from clients.state_store_client import StateStoreClient
from apps.logs.data_sources import resolve_source
from django.conf import settings
from pathlib import Path
try:
    from clients.kafka_consumer import KafkaLogConsumer
except ImportError:
    KafkaLogConsumer = None
import json
import logging
import math
import datetime
import hashlib
import re
import threading
import time

logger = logging.getLogger(__name__)

# Map UI window labels to lookback hours
WINDOW_HOURS = {
    "1h":        1,
    "6h":        6,
    "24h":      24,
    "7d":       24 * 7,
    "30d":      24 * 30,
    "all":      None,
    "Last 24h": 24,
    "Last 7d":  24 * 7,
    "Last 30d": 24 * 30,
    "Last 1h":  1,
    "Last 6h":  6,
}


INGEST_TIME_TS_EXPR = (
    "CASE "
    "WHEN TRY_CAST(ingest_time AS TIMESTAMP) IS NOT NULL "
    "THEN TRY_CAST(ingest_time AS TIMESTAMP) "
    "WHEN TRY_CAST(ingest_time AS BIGINT) IS NOT NULL "
    "AND TRY_CAST(ingest_time AS BIGINT) > 1000000000000 "
    "THEN to_timestamp(CAST(TRY_CAST(ingest_time AS BIGINT) AS DOUBLE) / 1000.0) "
    "WHEN TRY_CAST(ingest_time AS BIGINT) IS NOT NULL "
    "THEN to_timestamp(CAST(TRY_CAST(ingest_time AS BIGINT) AS DOUBLE)) "
    "ELSE NULL END"
)

_CACHE_LOCK = threading.Lock()
_SEARCH_CACHE = {}  # key -> {"ts": float, "value": dict}
_SEARCH_CACHE_TTL_SEC = 8
_SEARCH_CACHE_MAX = 128


def _is_safe_field_name(name: str) -> bool:
    # Conservative identifier policy for query-builder fields.
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""))


def _time_filter(window: str) -> str:
    """Convert a window label to a DuckDB WHERE fragment on ingest_time."""
    hours = WINDOW_HOURS.get(window)
    if not hours:
        return "1=1"
    cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=hours)
    return f"{INGEST_TIME_TS_EXPR} >= TIMESTAMP '{cutoff.strftime('%Y-%m-%d %H:%M:%S')}'"


def _ingest_time_clause(con, table: str, window: str) -> str:
    """
    Build a table-specific ingest_time filter.
    For numeric ingest_time columns this avoids expensive per-row timestamp casts.
    """
    hours = WINDOW_HOURS.get(window)
    if not hours:
        return "1=1"
    cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=hours)
    cutoff_s = int(cutoff.timestamp())
    cutoff_ms = int(cutoff.timestamp() * 1000)
    try:
        rows = con.execute(f"DESCRIBE {table}").fetchall()
        ingest_type = ""
        for r in rows:
            if str(r[0]).strip().lower() == "ingest_time":
                ingest_type = str(r[1]).strip().upper()
                break
        if ingest_type in {"BIGINT", "INTEGER", "INT", "SMALLINT", "HUGEINT", "UBIGINT", "DOUBLE", "FLOAT", "DECIMAL"}:
            return (
                "(CASE "
                "WHEN ingest_time > 1000000000000 THEN ingest_time >= " + str(cutoff_ms) + " "
                "ELSE ingest_time >= " + str(cutoff_s) + " "
                "END)"
            )
    except Exception:
        pass
    return f"{INGEST_TIME_TS_EXPR} >= TIMESTAMP '{cutoff.strftime('%Y-%m-%d %H:%M:%S')}'"


def _clean_row(row: dict) -> dict:
    """Sanitise a DuckDB result row — fix NaN/Inf floats and datetime objects."""
    for k, v in list(row.items()):
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            row[k] = None
        elif isinstance(v, (datetime.date, datetime.datetime)):
            row[k] = v.isoformat()
    return row


class ProductionLogRepository(LogRepository):
    """
    Production log repository.
    Queries Parquet files via DuckDB views.
    """

    @staticmethod
    def _empty_analytics(window: str) -> dict:
        return {
            "total_events": 0,
            "source_stats": {},
            "active_sources": 0,
            "protocol_distribution": [],
            "top_generators": [],
            "top_dst_ips": [],
            "top_dns_queries": [],
            "top_http_hosts": [],
            "top_response_codes": [],
            "hourly_trend": [{"hour": h, "count": 0} for h in range(24)],
            "alert_trend": [{"hour": h, "alerts": 0} for h in range(24)],
            "daily_trend": [],
            "source_trend": [],
            "event_distribution": [],
            "ingestion_rate_eps": 0.0,
            "window": window,
            "computed_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        }

    def _normalize_analytics_payload(self, payload: dict, window: str) -> dict:
        base = self._empty_analytics(window)
        if not isinstance(payload, dict):
            return base
        base.update(payload)
        return base

    def _source_parquet_base(self, source_id: str | None) -> Path | None:
        data_dir = Path(getattr(settings, "DATA_DIR", Path(".")))
        ds = resolve_source(data_dir, source_id)
        if not ds:
            return None
        return Path(ds.parquet_dir)

    def _compute_analytics_from_duckdb(self, window: str, source_id: str | None = None) -> dict:
        con = None
        try:
            parquet_base = self._source_parquet_base(source_id)
            available = set(DuckDBClient.get_available_tables(parquet_base=parquet_base) or [])
            if not available:
                return self._empty_analytics(window)

            con = DuckDBClient.get_connection(parquet_base=parquet_base)
            if con is None:
                return self._empty_analytics(window)

            payload = self._empty_analytics(window)
            source_order = [
                "conn", "dns", "http", "ssl", "ssh", "smtp", "dhcp", "ftp",
                "rdp", "smb_files", "kerberos", "ntlm", "dce_rpc", "snmp",
                "sip", "tunnel", "radius", "smb_mapping",
            ]

            total_events = 0
            source_stats = {}
            for src in source_order:
                if src not in available:
                    source_stats[src] = 0
                    continue
                where = _ingest_time_clause(con, src, window)
                try:
                    row = con.execute(f"SELECT COUNT(*) FROM {src} WHERE {where}").fetchone()
                    cnt = int(row[0]) if row and row[0] else 0
                except Exception:
                    cnt = 0
                source_stats[src] = cnt
                total_events += cnt

            payload["source_stats"] = source_stats
            payload["total_events"] = total_events
            payload["active_sources"] = sum(1 for v in source_stats.values() if v > 0)
            payload["event_distribution"] = [
                {"source": k, "count": v}
                for k, v in sorted(source_stats.items(), key=lambda kv: kv[1], reverse=True)
                if v > 0
            ]

            if "conn" in available:
                conn_where = _ingest_time_clause(con, "conn", window)
                try:
                    rows = con.execute(
                        f"SELECT COALESCE(protocol, 'unknown') AS proto, COUNT(*) AS cnt "
                        f"FROM conn WHERE {conn_where} "
                        f"GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                    ).fetchall()
                    payload["protocol_distribution"] = [
                        {"protocol": str(r[0]).lower(), "count": int(r[1] or 0)} for r in rows
                    ]
                except Exception:
                    payload["protocol_distribution"] = []

                try:
                    rows = con.execute(
                        f"SELECT src_ip, COUNT(*) AS cnt FROM conn "
                        f"WHERE {conn_where} AND src_ip IS NOT NULL "
                        f"GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                    ).fetchall()
                    payload["top_generators"] = [
                        {"ip": str(r[0]), "count": int(r[1] or 0)} for r in rows
                    ]
                except Exception:
                    payload["top_generators"] = []

                try:
                    rows = con.execute(
                        f"SELECT dst_ip, COUNT(*) AS cnt FROM conn "
                        f"WHERE {conn_where} AND dst_ip IS NOT NULL "
                        f"GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                    ).fetchall()
                    payload["top_dst_ips"] = [
                        {"ip": str(r[0]), "count": int(r[1] or 0)} for r in rows
                    ]
                except Exception:
                    payload["top_dst_ips"] = []

            if "dns" in available:
                dns_where = _ingest_time_clause(con, "dns", window)
                try:
                    rows = con.execute(
                        f"SELECT query, COUNT(*) AS cnt FROM dns "
                        f"WHERE {dns_where} AND query IS NOT NULL AND query <> '' AND query <> '-' "
                        f"GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                    ).fetchall()
                    payload["top_dns_queries"] = [
                        {"domain": str(r[0]), "count": int(r[1] or 0)} for r in rows
                    ]
                except Exception:
                    payload["top_dns_queries"] = []

            if "http" in available:
                http_where = _ingest_time_clause(con, "http", window)
                try:
                    rows = con.execute(
                        f"SELECT host, COUNT(*) AS cnt FROM http "
                        f"WHERE {http_where} AND host IS NOT NULL AND host <> '' AND host <> '-' "
                        f"GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                    ).fetchall()
                    payload["top_http_hosts"] = [
                        {"host": str(r[0]), "count": int(r[1] or 0)} for r in rows
                    ]
                except Exception:
                    payload["top_http_hosts"] = []

                try:
                    rows = con.execute(
                        f"SELECT CAST(status_code AS VARCHAR) AS code, COUNT(*) AS cnt FROM http "
                        f"WHERE {http_where} AND status_code IS NOT NULL "
                        f"GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                    ).fetchall()
                    payload["top_response_codes"] = [
                        {"code": str(r[0]), "count": int(r[1] or 0)} for r in rows
                    ]
                except Exception:
                    payload["top_response_codes"] = []

            # Hourly/source trend always over the latest 24h for chart readability.
            hourly_buckets = {h: 0 for h in range(24)}
            source_trend_buckets = {src: {h: 0 for h in range(24)} for src in ["conn", "dns", "http"]}
            for src in ["conn", "dns", "http"]:
                if src not in available:
                    continue
                h_where = _ingest_time_clause(con, src, "24h")
                try:
                    rows = con.execute(
                        f"SELECT HOUR({INGEST_TIME_TS_EXPR}) AS h, COUNT(*) AS cnt "
                        f"FROM {src} WHERE {h_where} GROUP BY 1"
                    ).fetchall()
                    for hr, cnt in rows:
                        h = int(hr or 0)
                        c = int(cnt or 0)
                        if 0 <= h <= 23:
                            hourly_buckets[h] += c
                            source_trend_buckets[src][h] += c
                except Exception:
                    continue

            payload["hourly_trend"] = [{"hour": h, "count": hourly_buckets[h]} for h in range(24)]
            payload["source_trend"] = [
                {
                    "hour": h,
                    "conn": source_trend_buckets["conn"][h],
                    "dns": source_trend_buckets["dns"][h],
                    "http": source_trend_buckets["http"][h],
                }
                for h in range(24)
            ]

            # Basic SOC-oriented "alert trend" proxy across conn/dns/http.
            alert_buckets = {h: 0 for h in range(24)}
            if "conn" in available:
                try:
                    rows = con.execute(
                        f"SELECT HOUR({INGEST_TIME_TS_EXPR}) AS h, COUNT(*) AS cnt "
                        f"FROM conn WHERE {_ingest_time_clause(con, 'conn', '24h')} "
                        f"AND conn_state IN ('REJ','S0','RSTO','RSTR') "
                        f"GROUP BY 1"
                    ).fetchall()
                    for hr, cnt in rows:
                        h = int(hr or 0)
                        if 0 <= h <= 23:
                            alert_buckets[h] += int(cnt or 0)
                except Exception:
                    pass

            if "dns" in available:
                try:
                    rows = con.execute(
                        f"SELECT HOUR({INGEST_TIME_TS_EXPR}) AS h, COUNT(*) AS cnt "
                        f"FROM dns WHERE {_ingest_time_clause(con, 'dns', '24h')} "
                        f"AND UPPER(COALESCE(rcode_name, '')) = 'NXDOMAIN' "
                        f"GROUP BY 1"
                    ).fetchall()
                    for hr, cnt in rows:
                        h = int(hr or 0)
                        if 0 <= h <= 23:
                            alert_buckets[h] += int(cnt or 0)
                except Exception:
                    pass

            if "http" in available:
                try:
                    rows = con.execute(
                        f"SELECT HOUR({INGEST_TIME_TS_EXPR}) AS h, COUNT(*) AS cnt "
                        f"FROM http WHERE {_ingest_time_clause(con, 'http', '24h')} "
                        f"AND TRY_CAST(status_code AS INTEGER) >= 400 "
                        f"GROUP BY 1"
                    ).fetchall()
                    for hr, cnt in rows:
                        h = int(hr or 0)
                        if 0 <= h <= 23:
                            alert_buckets[h] += int(cnt or 0)
                except Exception:
                    pass

            payload["alert_trend"] = [{"hour": h, "alerts": alert_buckets[h]} for h in range(24)]

            # Daily trend (up to 30 days)
            daily_hours = WINDOW_HOURS.get(window)
            if daily_hours is None:
                daily_hours = 24 * 30
            daily_hours = min(daily_hours, 24 * 30)
            day_where_window = "all" if window == "all" else ("30d" if daily_hours >= 24 * 30 else window)
            day_counts = {}
            for src in ["conn", "dns", "http"]:
                if src not in available:
                    continue
                d_where = _ingest_time_clause(con, src, day_where_window)
                try:
                    rows = con.execute(
                        f"SELECT DATE_TRUNC('day', {INGEST_TIME_TS_EXPR}) AS d, COUNT(*) AS cnt "
                        f"FROM {src} WHERE {d_where} GROUP BY 1 ORDER BY 1"
                    ).fetchall()
                    for day, cnt in rows:
                        if day is None:
                            continue
                        key = str(day)[:10]
                        day_counts[key] = day_counts.get(key, 0) + int(cnt or 0)
                except Exception:
                    continue
            payload["daily_trend"] = [{"day": d, "count": c} for d, c in sorted(day_counts.items())]

            hours = WINDOW_HOURS.get(window)
            if hours and total_events > 0:
                payload["ingestion_rate_eps"] = round(total_events / float(hours * 3600), 4)

            payload["computed_at"] = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            return payload
        except Exception as e:
            logger.error(f"DuckDB analytics fallback failed for window={window}: {e}")
            return self._empty_analytics(window)
        finally:
            if con:
                try:
                    con.close()
                except Exception:
                    pass

    def search_logs(self, filters, page=1, limit=10):
        con = None
        try:
            source_id = (filters.get('source_id', '') or '').strip()
            source  = (filters.get('source',  '') or '').strip().lower()
            search  = (filters.get('search',  '') or '').strip()
            # Default to bounded lookback; unbounded scans are too expensive at scale.
            window  = (filters.get('window',  '') or '24h').strip()
            # Structured field=value conditions from query builder
            # Format: list of {"field": "src_ip", "operator": "==", "value": "10.0.5.1"}
            conditions = filters.get('conditions', []) or []

            parquet_base = self._source_parquet_base(source_id)
            available_tables = DuckDBClient.get_available_tables(parquet_base=parquet_base) or []

            if source and source in available_tables:
                tables = [source]
            else:
                # All logs by default, with stable source ordering.
                preferred = [
                    "conn", "dns", "http", "ssl", "ssh", "smtp", "dhcp", "ftp",
                    "rdp", "smb_files", "kerberos", "ntlm", "dce_rpc", "snmp",
                    "sip", "tunnel", "radius", "smb_mapping",
                ]
                tables = [t for t in preferred if t in available_tables]
                tables += [t for t in available_tables if t not in tables]

            # ── Structured query builder conditions ────────────────────
            OP_MAP = {
                "==":       "=",
                "!=":       "!=",
                ">":        ">",
                "<":        "<",
                ">=":       ">=",
                "<=":       "<=",
                "contains": "ILIKE",
                "starts":   "ILIKE",
                "ends":     "ILIKE",
            }
            # Short-lived cache to avoid repeated scans from UI polling/filter toggles.
            cache_key = hashlib.sha1(
                json.dumps(
                    {
                        "source": source,
                        "search": search,
                        "window": window,
                        "conditions": conditions,
                        "page": page,
                        "limit": limit,
                        "source_id": source_id,
                    },
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            now = time.time()
            with _CACHE_LOCK:
                entry = _SEARCH_CACHE.get(cache_key)
                if entry and (now - entry["ts"]) <= _SEARCH_CACHE_TTL_SEC:
                    return entry["value"]

            con = DuckDBClient.get_connection(parquet_base=parquet_base)
            if con is None:
                return {"logs": [], "total": 0, "page": 1, "page_count": 0}

            # ── Count + Paginate ───────────────────────────────────────
            total = 0
            all_logs = []
            offset = (page - 1) * limit
            per_table = limit + offset
            needs_exact_count = bool(search or conditions)

            for t in tables:
                time_clause = _ingest_time_clause(con, t, window)
                dynamic_where = []

                try:
                    cols = con.execute(f"DESCRIBE {t}").fetchall()
                    table_columns = {str(r[0]).strip().lower() for r in cols}
                except Exception:
                    table_columns = set()

                if search:
                    se = search.replace("'", "''")
                    searchable_candidates = [
                        "src_ip", "dst_ip", "source_ip", "destination_ip",
                        "query", "host", "uri", "method", "status_code",
                        "protocol", "service", "conn_state", "id.orig_h", "id.resp_h",
                    ]
                    searchable = [c for c in searchable_candidates if c.lower() in table_columns and _is_safe_field_name(c)]
                    if searchable:
                        ors = [f"CAST({c} AS VARCHAR) ILIKE '%{se}%'" for c in searchable]
                        dynamic_where.append("(" + " OR ".join(ors) + ")")

                for cond in conditions:
                    field = cond.get("field", "").strip()
                    op = cond.get("operator", "==")
                    val = cond.get("value", "").strip().replace("'", "''")
                    if not field or not val or not _is_safe_field_name(field):
                        continue
                    if field.lower() not in table_columns:
                        continue
                    sql_op = OP_MAP.get(op, "=")
                    if op == "contains":
                        val = f"%{val}%"
                    elif op == "starts":
                        val = f"{val}%"
                    elif op == "ends":
                        val = f"%{val}"
                    dynamic_where.append(f"CAST({field} AS VARCHAR) {sql_op} '{val}'")

                static_where = " AND ".join(dynamic_where) if dynamic_where else "1=1"
                where = f"{time_clause} AND ({static_where})"
                if needs_exact_count:
                    try:
                        cr = con.execute(f"SELECT COUNT(*) FROM {t} WHERE {where}").fetchone()
                        total += int(cr[0]) if cr and cr[0] else 0
                    except Exception as e:
                        logger.error(f"search_logs count error for {t}: {e}")

                try:
                    result = con.execute(
                        f"SELECT * FROM {t} WHERE {where} ORDER BY ingest_time DESC LIMIT {per_table}"
                    )
                    cols = [d[0] for d in result.description]
                    rows = [dict(zip(cols, r)) for r in result.fetchall()]
                    for row in rows:
                        row['_source'] = t
                        _clean_row(row)
                    all_logs.extend(rows)
                except Exception as e:
                    logger.error(f"search_logs data error for {t}: {e}")

            all_logs.sort(key=lambda r: r.get('ingest_time', ''), reverse=True)
            logs = all_logs[offset:offset + limit]
            has_more = len(all_logs) > (offset + len(logs))
            if not needs_exact_count:
                # Broad, unfiltered log views should stay responsive: avoid full COUNT(*) scans.
                total = (offset + len(logs)) + (1 if has_more else 0)
                page_count = page + (1 if has_more else 0)
            else:
                page_count = max(1, (total + limit - 1) // limit) if total > 0 else 1

            result_payload = {
                "logs":       logs,
                "total":      total,
                "page":       page,
                "page_count": page_count,
            }
            with _CACHE_LOCK:
                if len(_SEARCH_CACHE) >= _SEARCH_CACHE_MAX:
                    _SEARCH_CACHE.clear()
                _SEARCH_CACHE[cache_key] = {"ts": now, "value": result_payload}
            return result_payload
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return {"logs": [], "total": 0, "page": 1, "page_count": 0}
        finally:
            if con:
                try:
                    con.close()
                except Exception:
                    pass

    def get_analytics(self, window="24h", source_id=None):
        """
        Returns log analytics for the given time window.
        Reads from ndr:logs:analytics:{window} (pre-computed by ndr-baseline).
        On cache miss, returns stale sibling window cache (24h/all) or fast empty payload.
        """
        try:
            data_dir = Path(getattr(settings, "DATA_DIR", Path(".")))
            if not source_id:
                ds = resolve_source(data_dir, None)
                source_id = ds.source_id if ds else None
            ds = resolve_source(data_dir, source_id)
            processing_live = bool(ds and str(ds.ingest_status).lower() == "processing")

            # During chunked ingest, serve LIVE analytics from DuckDB (no local state cache),
            # so dashboards update incrementally instead of showing stale zeros.
            if processing_live:
                payload = self._compute_analytics_from_duckdb(window, source_id=source_id)
                payload["cache_miss"] = True
                payload["stale_fallback"] = False
                payload["live_processing"] = True
                return self._normalize_analytics_payload(payload, window)
            # ── Primary: read pre-computed state key ───────────────────
            key = f"ndr:logs:analytics:{source_id or 'current'}:{window}"
            cached = StateStoreClient.get(key)
            if cached:
                return self._normalize_analytics_payload(json.loads(cached), window)

            # ── Primary fallback: compute requested window from DuckDB and cache briefly ──
            logger.warning(f"Cache miss for {key} — computing on-demand from DuckDB")
            payload = self._compute_analytics_from_duckdb(window, source_id=source_id)
            # For cache_miss visibility, keep the flag even when compute succeeds.
            payload["cache_miss"] = True
            payload["stale_fallback"] = False
            try:
                StateStoreClient.set(key, json.dumps(payload), ex=120)
            except Exception:
                pass
            payload = self._normalize_analytics_payload(payload, window)
            if payload.get("total_events", 0) > 0:
                return payload

            # ── Secondary stale fallback: use sibling window cache if available ─────────
            fallback_windows = ["24h", "all"] if window not in ("24h", "all") else ["all"]
            for fw in fallback_windows:
                fk = f"ndr:logs:analytics:{source_id or 'current'}:{fw}"
                fcached = StateStoreClient.get(fk)
                if fcached:
                    stale_payload = json.loads(fcached)
                    stale_payload["window_requested"] = window
                    stale_payload["window_served"] = fw
                    stale_payload["cache_miss"] = True
                    stale_payload["stale_fallback"] = True
                    return self._normalize_analytics_payload(stale_payload, window)

            return self._normalize_analytics_payload(payload, window)

        except Exception as e:
            logger.error(f"Error getting analytics: {e}")
            payload = self._empty_analytics(window)
            payload["cache_miss"] = True
            payload["stale_fallback"] = False
            return payload

    def get_log_sources(self):
        tables = DuckDBClient.get_available_tables()
        sources = []
        for table in tables:
            try:
                result = DuckDBClient.execute_query(f"SELECT COUNT(*) FROM {table}")
                count = result[0][0] if result else 0
                sources.append({"name": table, "events": count, "status": "active" if count > 0 else "no_data"})
            except Exception:
                sources.append({"name": table, "events": 0, "status": "error"})
        return sources

    def stream_logs(self):
        try:
            return KafkaLogConsumer.stream_logs()
        except Exception:
            return iter([])
