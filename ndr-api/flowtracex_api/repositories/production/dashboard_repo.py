from ..base.dashboard_repo import DashboardRepository
from clients.redis_client import RedisClient
from clients.duckdb_client import DuckDBClient
import json
import logging

logger = logging.getLogger(__name__)


class ProductionDashboardRepository(DashboardRepository):
    """
    Production dashboard repo — reads pre-computed data from Redis.
    All data is populated by ndr-baseline dashboard-analytics job every 10 min.
    Falls back to DuckDB on-demand computation on cache miss.
    """

    @staticmethod
    def _asset_profiles():
        """
        Return merged asset profile hashes from both key families:
        - ndr:assets:profile:* (current enrich path)
        - ndr:asset:* (legacy path)
        Non-hash keys are skipped safely.
        """
        profiles = []
        client = RedisClient.client

        def _add_from_pattern(pattern, skip_tokens):
            for key in RedisClient.scan_keys(pattern):
                if any(tok in key for tok in skip_tokens):
                    continue
                try:
                    if client.type(key) != "hash":
                        continue
                    data = RedisClient.hgetall(key) or {}
                    if data:
                        profiles.append(data)
                except Exception:
                    continue

        _add_from_pattern("ndr:assets:profile:*", [":ips"])
        _add_from_pattern("ndr:asset:*", [":summary:", ":top:", ":counters:", ":ip_index:", ":mac_index:", ":role:"])
        return profiles

    def get_overview_metrics(self):
        cached = RedisClient.get("dashboard:overview")
        if cached:
            return json.loads(cached)

        # Fallback — compute best-effort metrics from DuckDB + Redis.
        logger.warning("Cache miss for dashboard:overview — computing fallback metrics")
        critical = 0
        high = 0
        try:
            rows = DuckDBClient.execute_query(
                """
                SELECT LOWER(COALESCE(severity, 'unknown')) as sev, COUNT(*) as cnt
                FROM correlation_alerts
                GROUP BY sev
                """
            )
            for sev, cnt in (rows or []):
                if sev == "critical":
                    critical = int(cnt or 0)
                elif sev == "high":
                    high = int(cnt or 0)
        except Exception:
            pass

        profiles = self._asset_profiles()
        asset_count = len(profiles)
        zeek_fingerprinted = 0
        for d in profiles:
            if d.get("ja3") or d.get("ja3s") or d.get("server_name") or d.get("user_agent"):
                zeek_fingerprinted += 1

        # If asset inventory isn't cached yet, infer minimal count from conn table.
        if asset_count == 0:
            try:
                rows = DuckDBClient.execute_query(
                    """
                    SELECT COUNT(DISTINCT ip) FROM (
                      SELECT src_ip as ip FROM conn WHERE src_ip IS NOT NULL
                      UNION
                      SELECT dst_ip as ip FROM conn WHERE dst_ip IS NOT NULL
                    ) t
                    """
                )
                asset_count = int(rows[0][0] or 0) if rows else 0
            except Exception:
                pass
        flow_only = max(asset_count - zeek_fingerprinted, 0)

        try:
            available = set(DuckDBClient.get_available_tables() or [])
        except Exception:
            available = set()
        expected = ["conn", "dns", "http", "ssl", "ssh"]
        active = sum(1 for t in expected if t in available)
        health_pct = round((active / max(len(expected), 1)) * 100)
        health_status = "Healthy" if health_pct >= 60 else "Degraded" if health_pct >= 30 else "Critical"

        return {
            "critical_alerts": {"count": critical, "change": "0", "period": "24h"},
            "high_alerts": {"count": high, "change": "0", "period": "24h"},
            "assets_monitored": {
                "count": asset_count, "change": "0", "period": "24h",
                "zeek_fingerprinted": zeek_fingerprinted, "flow_only": flow_only,
            },
            "network_health": {"percentage": health_pct, "status": health_status},
        }

    def get_traffic_metrics(self, range_str):
        # Try specific range first, fall back to 24h
        for key in [f"dashboard:traffic:{range_str}", "dashboard:traffic:24h"]:
            cached = RedisClient.get(key)
            if cached:
                return json.loads(cached)

        # Fallback — compute from DuckDB on-demand
        logger.warning("Cache miss for dashboard:traffic — computing from DuckDB")
        try:
            rows = DuckDBClient.execute_query(
                "SELECT HOUR(ingest_time) as h, "
                "SUM(COALESCE(CAST(orig_bytes AS BIGINT),0) + COALESCE(CAST(resp_bytes AS BIGINT),0)) as total_bytes "
                "FROM conn GROUP BY h ORDER BY h"
            )
            hour_map = {int(r[0]): int(r[1] or 0) for r in rows} if rows else {}
            return {
                "dataPoints": [
                    {"timestamp": f"{h:02d}:00", "trafficMBps": round(hour_map.get(h, 0) / 1e6, 2), "flows": 0, "alerts": 0}
                    for h in range(24)
                ]
            }
        except Exception as e:
            logger.error(f"DuckDB traffic fallback error: {e}")
            return {"dataPoints": []}

    def get_protocol_distribution(self):
        cached = RedisClient.get("dashboard:protocols")
        if cached:
            return json.loads(cached)

        # Fallback — compute from DuckDB
        logger.warning("Cache miss for dashboard:protocols — computing from DuckDB")
        colors = {"tcp": "#3b82f6", "udp": "#10b981", "icmp": "#f59e0b"}
        try:
            rows = DuckDBClient.execute_query(
                "SELECT COALESCE(protocol, 'unknown') as proto, COUNT(*) as cnt "
                "FROM conn GROUP BY proto ORDER BY cnt DESC LIMIT 10"
            )
            total = sum(r[1] for r in rows) if rows else 1
            protocols = [
                {"name": str(r[0]).lower(), "count": int(r[1]), "percentage": round(r[1] / total * 100, 1),
                 "color": colors.get(str(r[0]).lower(), "#6366f1")}
                for r in rows
            ] if rows else []
            return {"protocols": protocols}
        except Exception as e:
            logger.error(f"DuckDB protocol fallback error: {e}")
            return {"protocols": []}

    def get_deep_inspection_coverage(self):
        cached = RedisClient.get("dashboard:deep_inspection")
        if cached:
            return json.loads(cached)

        logger.warning("Cache miss for dashboard:deep_inspection — computing fallback coverage")
        try:
            available = set(DuckDBClient.get_available_tables() or [])
        except Exception:
            available = set()
        zeek_types = ["dns", "http", "ssl", "ssh", "dhcp", "ftp", "smtp", "kerberos", "ntlm", "rdp"]
        zeek_active = sum(1 for t in zeek_types if t in available)
        zeek_coverage = round((zeek_active / max(len(zeek_types), 1)) * 100)
        flow_coverage = 100 if "conn" in available else 0

        profiles = self._asset_profiles()
        total_assets = len(profiles)
        zeek_fingerprinted = 0
        for d in profiles:
            if d.get("ja3") or d.get("ja3s") or d.get("server_name") or d.get("user_agent"):
                zeek_fingerprinted += 1
        flow_only = max(total_assets - zeek_fingerprinted, 0)

        return {
            "zeek_coverage": zeek_coverage,
            "flow_coverage": flow_coverage,
            "hybrid_coverage": round((zeek_coverage + flow_coverage) / 2),
            "packet_drop": 0,
            "total_assets": total_assets,
            "zeek_fingerprinted": zeek_fingerprinted,
            "flow_only": flow_only,
        }
