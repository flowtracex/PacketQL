import json
from ..base.network_repo import NetworkRepository
from datetime import datetime, timezone, timedelta

try:
    from clients.state_store_client import StateStoreClient
except Exception:
    StateStoreClient = None

try:
    from clients.duckdb_client import DuckDBClient
except Exception:
    DuckDBClient = None


class ProductionNetworkRepository(NetworkRepository):
    """Production network repo — reads fleet analytics from local state."""

    @staticmethod
    def _empty_analytics():
        return {
            "kpis": {
                "total_flows": 0,
                "total_bytes": 0,
                "total_bytes_fmt": "0 B",
                "unique_pairs": 0,
                "external_pairs": 0,
                "encryption_pct": 0.0,
                "unusual_count": 0,
            },
            "top_talkers_outbound": [],
            "top_talkers_lateral": [],
            "protocol_stats": [],
            "protocol_trends": [],
            "segment_matrix": [],
            "services": [],
            "unusual": [],
        }

    @staticmethod
    def _fmt_bytes(num):
        num = float(num or 0)
        if num >= 1e12:
            return f"{num / 1e12:.1f} TB"
        if num >= 1e9:
            return f"{num / 1e9:.1f} GB"
        if num >= 1e6:
            return f"{num / 1e6:.1f} MB"
        if num >= 1e3:
            return f"{num / 1e3:.1f} KB"
        return f"{int(num)} B"

    def _get_analytics_from_state_store(self):
        """Read fleet-wide analytics from local state (written by ndr-baseline)."""
        try:
            if StateStoreClient is None:
                return None
            r = StateStoreClient.get_instance()
            data = r.hgetall("ndr:network:analytics")
            if data:
                out = {}
                for k, v in data.items():
                    try:
                        out[k] = json.loads(v)
                    except Exception:
                        out[k] = v
                return out
        except Exception:
            pass
        return None

    def _ingest_time_clause(self, con, table: str, window: str) -> str:
        hours = self.WINDOW_HOURS.get(window, 24)
        if hours is None:
            return "1=1"
        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
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
                    f"WHEN ingest_time > 1000000000000 THEN ingest_time >= {cutoff_ms} "
                    f"ELSE ingest_time >= {cutoff_s} "
                    "END)"
                )
        except Exception:
            pass
        return f"{self.INGEST_TIME_TS_EXPR} >= TIMESTAMP '{cutoff.strftime('%Y-%m-%d %H:%M:%S')}'"

    def _compute_analytics_from_duckdb(self, window="24h"):
        """Fallback analytics when baseline local state cache is missing."""
        analytics = self._empty_analytics()
        if DuckDBClient is None:
            return analytics
        try:
            available = set(DuckDBClient.get_available_tables() or [])
        except Exception:
            available = set()
        if "conn" not in available:
            return analytics

        con = DuckDBClient.get_connection()
        if con is None:
            return analytics
        try:
            conn_where = self._ingest_time_clause(con, "conn", window)
        finally:
            con.close()

        # KPIs
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT
                  COUNT(*) as total_flows,
                  COALESCE(SUM(COALESCE(CAST(orig_bytes AS BIGINT), 0) + COALESCE(CAST(resp_bytes AS BIGINT), 0)), 0) as total_bytes,
                  COUNT(DISTINCT COALESCE(src_ip, '') || '->' || COALESCE(dst_ip, '')) as unique_pairs,
                  COALESCE(SUM(
                    CASE
                      WHEN NOT (
                        dst_ip LIKE '10.%'
                        OR dst_ip LIKE '192.168.%'
                        OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '172.17.%' OR dst_ip LIKE '172.18.%' OR dst_ip LIKE '172.19.%'
                        OR dst_ip LIKE '172.2%.%' OR dst_ip LIKE '172.30.%' OR dst_ip LIKE '172.31.%'
                        OR dst_ip = '127.0.0.1'
                      ) THEN 1 ELSE 0
                    END
                  ), 0) as external_pairs,
                  COALESCE(SUM(CASE WHEN LOWER(COALESCE(protocol, '')) IN ('ssl', 'tls') THEN 1 ELSE 0 END), 0) as encrypted_flows
                FROM conn
                WHERE """ + conn_where + """
                """
            )
            if rows:
                total_flows = int(rows[0][0] or 0)
                total_bytes = int(rows[0][1] or 0)
                encrypted = int(rows[0][4] or 0)
                analytics["kpis"] = {
                    "total_flows": total_flows,
                    "total_bytes": total_bytes,
                    "total_bytes_fmt": self._fmt_bytes(total_bytes),
                    "unique_pairs": int(rows[0][2] or 0),
                    "external_pairs": int(rows[0][3] or 0),
                    "encryption_pct": round((encrypted * 100.0 / total_flows), 1) if total_flows > 0 else 0.0,
                    "unusual_count": 0,
                }
        except Exception:
            pass

        # Top outbound talkers
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT
                  src_ip,
                  COALESCE(SUM(COALESCE(CAST(orig_bytes AS BIGINT), 0) + COALESCE(CAST(resp_bytes AS BIGINT), 0)), 0) as total_bytes,
                  COUNT(*) as connections,
                  COUNT(DISTINCT dst_ip) as unique_destinations
                FROM conn
                WHERE """ + conn_where + """ AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY total_bytes DESC
                LIMIT 10
                """
            )
            analytics["top_talkers_outbound"] = [
                {
                    "ip": str(r[0]),
                    "bytes": int(r[1] or 0),
                    "connections": int(r[2] or 0),
                    "unique_destinations": int(r[3] or 0),
                }
                for r in (rows or [])
            ]
        except Exception:
            pass

        # Top lateral talkers
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT
                  src_ip,
                  COUNT(*) as connections,
                  COUNT(DISTINCT dst_ip) as unique_internal_dst
                FROM conn
                WHERE """ + conn_where + """ AND src_ip LIKE '10.%' AND dst_ip LIKE '10.%'
                GROUP BY src_ip
                ORDER BY connections DESC
                LIMIT 10
                """
            )
            analytics["top_talkers_lateral"] = [
                {
                    "ip": str(r[0]),
                    "connections": int(r[1] or 0),
                    "unique_internal_dst": int(r[2] or 0),
                }
                for r in (rows or [])
            ]
        except Exception:
            pass

        # Protocol distribution
        colors = {"tcp": "#3b82f6", "udp": "#10b981", "icmp": "#f59e0b"}
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT
                  LOWER(COALESCE(protocol, 'unknown')) as proto,
                  COUNT(*) as cnt,
                  COALESCE(SUM(COALESCE(CAST(orig_bytes AS BIGINT), 0) + COALESCE(CAST(resp_bytes AS BIGINT), 0)), 0) as total_bytes
                FROM conn
                WHERE """ + conn_where + """
                GROUP BY proto
                ORDER BY cnt DESC
                LIMIT 10
                """
            )
            analytics["protocol_stats"] = [
                {
                    "name": str(r[0]),
                    "value": int(r[1] or 0),
                    "bytes": int(r[2] or 0),
                    "color": colors.get(str(r[0]), "#6366f1"),
                }
                for r in (rows or [])
            ]
        except Exception:
            pass

        # Minimal trends
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT HOUR(""" + self.INGEST_TIME_TS_EXPR + """) as h, LOWER(COALESCE(protocol, 'unknown')) as proto, COUNT(*) as cnt
                FROM conn
                WHERE """ + conn_where + """
                GROUP BY h, proto
                ORDER BY h ASC, cnt DESC
                LIMIT 300
                """
            )
            analytics["protocol_trends"] = [
                {"hour": int(r[0] or 0), "protocol": str(r[1]), "count": int(r[2] or 0)}
                for r in (rows or [])
            ]
        except Exception:
            pass

        # Services (best effort)
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT
                  CAST(resp_p AS INTEGER) as port,
                  LOWER(COALESCE(protocol, 'tcp')) as protocol,
                  COUNT(*) as connections,
                  COUNT(DISTINCT src_ip) as assets,
                  COALESCE(SUM(COALESCE(CAST(orig_bytes AS BIGINT), 0) + COALESCE(CAST(resp_bytes AS BIGINT), 0)), 0) as total_bytes
                FROM conn
                WHERE """ + conn_where + """ AND resp_p IS NOT NULL
                GROUP BY port, protocol
                ORDER BY connections DESC
                LIMIT 20
                """
            )
            analytics["services"] = [
                {
                    "port": int(r[0] or 0),
                    "protocol": str(r[1]).upper(),
                    "service": str(r[0] or "unknown"),
                    "assets": int(r[3] or 0),
                    "connections": int(r[2] or 0),
                    "bytes": int(r[4] or 0),
                    "risk": "low",
                }
                for r in (rows or [])
            ]
        except Exception:
            analytics["services"] = []

        # Unusual external talkers
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT
                  dst_ip,
                  COUNT(*) as cnt,
                  COALESCE(SUM(COALESCE(CAST(orig_bytes AS BIGINT), 0) + COALESCE(CAST(resp_bytes AS BIGINT), 0)), 0) as total_bytes
                FROM conn
                WHERE """ + conn_where + """ AND dst_ip IS NOT NULL
                  AND NOT (
                    dst_ip LIKE '10.%'
                    OR dst_ip LIKE '192.168.%'
                    OR dst_ip LIKE '172.16.%' OR dst_ip LIKE '172.17.%' OR dst_ip LIKE '172.18.%' OR dst_ip LIKE '172.19.%'
                    OR dst_ip LIKE '172.2%.%' OR dst_ip LIKE '172.30.%' OR dst_ip LIKE '172.31.%'
                    OR dst_ip = '127.0.0.1'
                  )
                GROUP BY dst_ip
                ORDER BY total_bytes DESC
                LIMIT 10
                """
            )
            analytics["unusual"] = [
                {
                    "description": f"High-volume external: {r[0]}",
                    "ip": str(r[0]),
                    "connections": int(r[1] or 0),
                    "bytes": int(r[2] or 0),
                    "risk": "medium",
                }
                for r in (rows or [])
            ]
            analytics["kpis"]["unusual_count"] = len(analytics["unusual"])
        except Exception:
            pass

        return analytics

    def get_topology(self):
        return {"nodes": [], "edges": []}

    def get_services(self):
        analytics = self._get_analytics_from_state_store()
        if analytics and "services" in analytics:
            return analytics["services"]
        return []

    def search_flows(self, filters, page=1, limit=10):
        return {"flows": [], "total": 0}

    def get_analytics(self, window="24h"):
        # Use pre-computed cache for 24h default view.
        if window in ("24h", "", None):
            analytics = self._get_analytics_from_state_store()
            if analytics:
                return analytics
        # For non-default windows (or cache miss), compute on-demand.
        return self._compute_analytics_from_duckdb(window=window or "24h")

    def get_pcap(self, pcap_id):
        return f"/data/pcap/{pcap_id}.pcap"
    WINDOW_HOURS = {
        "1h": 1,
        "6h": 6,
        "24h": 24,
        "7d": 24 * 7,
        "30d": 24 * 30,
        "all": None,
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
