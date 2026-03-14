import json
import os
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from ..base.detection_repo import DetectionRepository

logger = logging.getLogger(__name__)

# ── Redis connection for metadata enrichment ──
try:
    import redis
    _REDIS = redis.Redis(
        host=os.environ.get('REDIS_HOST', 'localhost'),
        port=int(os.environ.get('REDIS_PORT', '6379')),
        decode_responses=True,
        socket_connect_timeout=2,
    )
    _REDIS.ping()
except Exception:
    _REDIS = None


def _get_signal_meta(signal_id: str) -> dict:
    """Read signal metadata from Redis."""
    if not _REDIS:
        return {}
    try:
        raw = _REDIS.get(f'ndr:signal:{signal_id}:meta')
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _get_usecase_meta(uc_id: str) -> dict:
    """Read use case metadata from Redis."""
    if not _REDIS:
        return {}
    try:
        raw = _REDIS.get(f'ndr:usecase:{uc_id}:meta')
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _get_asset_info(asset_id: str) -> dict:
    """Read asset info (IP, hostname, OS, etc.) from Redis."""
    if not _REDIS:
        return {}
    try:
        # Current enrich/profiler path stores assets under ndr:assets:profile:<asset_id>.
        # Keep legacy fallback for older data.
        data = _REDIS.hgetall(f'ndr:assets:profile:{asset_id}')
        if not data:
            data = _REDIS.hgetall(f'ndr:asset:{asset_id}')
        if not data:
            return {}

        # Normalize OS field for frontend consumers.
        if "os" not in data and data.get("os_hint"):
            data["os"] = data.get("os_hint", "")
        return data
    except Exception:
        return {}

# Same DB the correlation engine writes to
_DB_PATH = str(Path(__file__).resolve().parent.parent.parent / "db.sqlite3")

_REQUIRED_TABLES = {"correlation_alerts", "correlation_processed_signals", "correlation_raw_signals"}


def _get_conn():
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=3000")
    return conn


def _tables_exist(conn):
    """Check if correlation tables exist in the database."""
    try:
        existing = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        return _REQUIRED_TABLES.issubset(existing)
    except Exception:
        return False


def _rows_to_dicts(rows):
    return [dict(r) for r in rows]


def _parse_json_fields(item, fields=("evidence", "contributing_signals", "metrics", "filters_applied")):
    """Safely parse JSON string fields into dicts/lists."""
    for f in fields:
        if f in item and isinstance(item[f], str):
            try:
                item[f] = json.loads(item[f])
            except (json.JSONDecodeError, TypeError):
                pass
    return item


def _parse_timestamp(ts: str):
    """Best-effort timestamp parser for mixed SQLite/ISO formats."""
    if not ts:
        return None
    s = str(ts).strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def _sqlite_time_modifier(window: str) -> str:
    """Convert UI window tokens to sqlite datetime modifiers."""
    w = (window or "24h").strip().lower()
    mapping = {
        "1h": "-1 hours",
        "24h": "-24 hours",
        "7d": "-7 days",
        "30d": "-30 days",
    }
    return mapping.get(w, "-24 hours")


def _time_range_where(filters: dict, ts_col: str = "timestamp"):
    """Build sqlite-compatible time range predicate + params."""
    if filters and filters.get("time_range"):
        return (
            f" AND datetime(replace(substr({ts_col}, 1, 19), 'T', ' ')) >= datetime('now', ?)",
            [_sqlite_time_modifier(filters.get("time_range"))],
        )
    return ("", [])


class ProductionDetectionRepository(DetectionRepository):
    @staticmethod
    def _build_alert_signals(item: dict) -> list:
        """
        Normalize alert signals for GUI timeline/modal.
        For standalone alerts with empty contributing_signals, synthesize one signal row.
        """
        evidence = item.get('evidence') or {}
        if not isinstance(evidence, dict):
            evidence = {}
        sig_meta = item.get('signal_meta') or {}
        if not isinstance(sig_meta, dict):
            sig_meta = {}

        raw_sigs = item.get('contributing_signals')
        if isinstance(raw_sigs, list) and raw_sigs:
            normalized = []
            for i, sig in enumerate(raw_sigs):
                if isinstance(sig, str):
                    sig = {'signal_id': sig}
                if not isinstance(sig, dict):
                    continue
                sid = sig.get('signal_id') or item.get('signal_id') or ""
                normalized.append({
                    **sig,
                    'signal_id': sid,
                    'stage': sig.get('stage', i + 1),
                    'timestamp': sig.get('timestamp', item.get('timestamp', '')),
                    'title': sig.get('title') or sig_meta.get('title') or sid,
                    'description': sig.get('description') or sig_meta.get('description') or item.get('description', ''),
                    'severity': sig.get('severity') or sig_meta.get('severity') or item.get('severity', 'medium'),
                    'detection_method': sig.get('detection_method') or sig_meta.get('detection_method', ''),
                    'log_source': sig.get('log_source') or sig_meta.get('log_source', ''),
                    'category': sig.get('category') or sig_meta.get('category') or item.get('category', ''),
                    'what_it_monitors': sig.get('what_it_monitors') or sig_meta.get('what_it_monitors', []),
                    'when_suspicious': sig.get('when_suspicious') or sig_meta.get('when_suspicious', []),
                    'why_it_matters': sig.get('why_it_matters') or sig_meta.get('why_it_matters', ''),
                    'mitre': sig.get('mitre') or sig_meta.get('mitre', {}),
                    'points': sig.get('points') or sig_meta.get('points', 0),
                    'evidence': sig.get('evidence') or {**evidence, 'ftx_ids': item.get('ftx_ids', '')},
                })
            if normalized:
                return normalized

        sid = item.get('signal_id')
        if sid:
            return [{
                'signal_id': sid,
                'stage': 1,
                'timestamp': item.get('timestamp', ''),
                'title': sig_meta.get('title', sid),
                'description': sig_meta.get('description') or item.get('description', ''),
                'severity': sig_meta.get('severity') or item.get('severity', 'medium'),
                'detection_method': sig_meta.get('detection_method', ''),
                'log_source': sig_meta.get('log_source', ''),
                'category': sig_meta.get('category') or item.get('category', ''),
                'what_it_monitors': sig_meta.get('what_it_monitors', []),
                'when_suspicious': sig_meta.get('when_suspicious', []),
                'why_it_matters': sig_meta.get('why_it_matters', ''),
                'mitre': sig_meta.get('mitre', {}),
                'points': sig_meta.get('points', 0),
                'evidence': {**evidence, 'ftx_ids': item.get('ftx_ids', '')},
            }]

        return []

    # ── Incidents (UC completions) ───────────────────────────────

    def list_incidents(self, filters, page=1, limit=10):
        conn = _get_conn()
        try:
            if not _tables_exist(conn):
                return {"items": [], "total": 0, "page": page, "page_count": 0, "summary": {}}
            where = "WHERE alert_type = 'use_case'"
            params = []

            if filters.get("severity"):
                placeholders = ",".join("?" * len(filters["severity"]))
                where += f" AND severity IN ({placeholders})"
                params.extend(filters["severity"])
            if filters.get("status"):
                placeholders = ",".join("?" * len(filters["status"]))
                where += f" AND status IN ({placeholders})"
                params.extend(filters["status"])
            if filters.get("search"):
                where += " AND (name LIKE ? OR asset_id LIKE ?)"
                s = f"%{filters['search']}%"
                params.extend([s, s])
            if filters.get("category"):
                where += " AND LOWER(COALESCE(category, '')) = ?"
                params.append(str(filters["category"]).strip().lower())
            time_where, time_params = _time_range_where(filters, "timestamp")
            where += time_where
            params.extend(time_params)

            total = conn.execute(
                f"SELECT COUNT(*) FROM correlation_alerts {where}", params
            ).fetchone()[0]

            offset = (page - 1) * limit
            rows = conn.execute(
                f"SELECT * FROM correlation_alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()

            items = [_parse_json_fields(dict(r)) for r in rows]

            # Enrich each incident with asset_info from Redis
            for item in items:
                aid = item.get('asset_id', '')
                if aid:
                    asset = _get_asset_info(aid)
                    if asset:
                        item['asset_info'] = {
                            'ip': asset.get('ip', ''),
                            'hostname': asset.get('hostname', ''),
                            'asset_type': asset.get('asset_type', ''),
                            'os': asset.get('os', ''),
                        }

            # Summary counts
            summary = {}
            for sev in ("critical", "high", "medium", "low"):
                summary[sev] = conn.execute(
                    "SELECT COUNT(*) FROM correlation_alerts WHERE alert_type='use_case' AND severity=?",
                    (sev,)
                ).fetchone()[0]

            return {
                "items": items,
                "total": total,
                "page": page,
                "page_count": max(1, (total + limit - 1) // limit),
                "summary": summary,
            }
        except Exception as e:
            logger.error(f"Error listing incidents: {e}")
            return {"items": [], "total": 0, "page": page, "page_count": 0, "summary": {}}
        finally:
            conn.close()

    def get_incident_detail(self, incident_id):
        conn = _get_conn()
        try:
            if not _tables_exist(conn):
                return None
            row = conn.execute(
                "SELECT * FROM correlation_alerts WHERE id = ? AND alert_type = 'use_case'",
                (incident_id,)
            ).fetchone()
            if not row:
                return None
            item = _parse_json_fields(dict(row))
            return self._enrich_incident(item, conn)
        finally:
            conn.close()

    @staticmethod
    def _enrich_incident(item: dict, conn=None) -> dict:
        """Enrich incident with Redis signal + use case metadata."""
        evidence = item.get('evidence') or {}
        asset_id = item.get('asset_id', '')

        # ── Normalize contributing_signals ──
        # DB stores them as ["SIG-001", "SIG-045", ...] (string list)
        # but the frontend expects [{signal_id, stage, title, ...}, ...]
        raw_sigs = item.get('contributing_signals')
        if isinstance(raw_sigs, list):
            # If items are strings, convert to dicts
            normalized = []
            kill_chain = evidence.get('kill_chain', []) if isinstance(evidence, dict) else []
            for idx, sig in enumerate(raw_sigs):
                if isinstance(sig, str):
                    normalized.append({
                        'signal_id': sig,
                        'stage': idx + 1,
                        'timestamp': item.get('timestamp', ''),
                    })
                elif isinstance(sig, dict):
                    normalized.append(sig)
            raw_sigs = normalized

        # ── Enrich contributing_signals with signal meta ──
        if isinstance(raw_sigs, list):
            enriched = []
            all_ftx = []
            for sig in raw_sigs:
                if not isinstance(sig, dict):
                    continue
                sid = sig.get('signal_id', '')
                meta = _get_signal_meta(sid)
                stage_key = str(sig.get('stage', ''))
                # Merge evidence data for this stage
                stage_evidence = {}
                if isinstance(evidence, dict):
                    stage_evidence = evidence.get(stage_key, {})
                    if isinstance(stage_evidence, dict):
                        stage_evidence = stage_evidence.get('data', {})

                # Look up raw signal IDs from DB for ftx_ids
                sig_ftx_ids = []
                if conn and sid and asset_id:
                    try:
                        raw_rows = conn.execute(
                            "SELECT id FROM correlation_raw_signals "
                            "WHERE signal_id = ? AND asset_id = ? "
                            "ORDER BY timestamp DESC LIMIT 5",
                            (sid, asset_id)
                        ).fetchall()
                        sig_ftx_ids = [str(r[0]) for r in raw_rows]
                    except Exception:
                        pass

                ftx_str = ','.join(sig_ftx_ids)
                all_ftx.extend(sig_ftx_ids)

                enriched.append({
                    **sig,
                    'title': meta.get('title', sid),
                    'description': meta.get('description', ''),
                    'category': meta.get('category', ''),
                    'severity': meta.get('severity', sig.get('severity', 'medium')),
                    'detection_method': meta.get('detection_method', ''),
                    'log_source': meta.get('log_source', ''),
                    'points': meta.get('points', 0),
                    'what_it_monitors': meta.get('what_it_monitors', []),
                    'when_suspicious': meta.get('when_suspicious', []),
                    'why_it_matters': meta.get('why_it_matters', ''),
                    'mitre': meta.get('mitre', {}),
                    'evidence': {
                        'z_score': stage_evidence.get('z_score') if isinstance(stage_evidence, dict) else None,
                        'baseline_source': stage_evidence.get('baseline_source', '') if isinstance(stage_evidence, dict) else '',
                        'features': stage_evidence.get('features', {}) if isinstance(stage_evidence, dict) else {},
                        'ftx_ids': ftx_str,
                    },
                })
            item['contributing_signals'] = enriched
            if all_ftx:
                item['ftx_ids'] = ','.join(all_ftx)

        # ── Add use_case_meta from Redis ──
        uc_id = item.get('use_case_id', '')
        if uc_id:
            uc_meta = _get_usecase_meta(uc_id)
            if uc_meta:
                item['use_case_meta'] = {
                    'title': uc_meta.get('title', ''),
                    'stages': uc_meta.get('stages', []),
                    'attack_story': uc_meta.get('attack_story', ''),
                    'mitre': uc_meta.get('mitre', {}),
                    'recommended_response': uc_meta.get('recommended_response', ''),
                    'time_window': uc_meta.get('time_window', ''),
                    'eval_mode': uc_meta.get('eval_mode', ''),
                }

        # ── Add asset info from Redis ──
        if asset_id:
            asset = _get_asset_info(asset_id)
            if asset:
                item['asset_info'] = {
                    'ip': asset.get('ip', ''),
                    'hostname': asset.get('hostname', ''),
                    'asset_type': asset.get('asset_type', ''),
                    'os': asset.get('os', ''),
                    'department': asset.get('department', ''),
                    'first_seen': asset.get('first_seen', ''),
                }

        return item

    # ── Alerts (standalone signals) ──────────────────────────────

    def list_alerts(self, filters, page=1, limit=10):
        conn = _get_conn()
        try:
            if not _tables_exist(conn):
                return {"alerts": [], "total": 0, "page": page, "page_count": 0, "summary": {}}
            where = "WHERE alert_type = 'signal'"
            params = []

            if filters.get("severity"):
                placeholders = ",".join("?" * len(filters["severity"]))
                where += f" AND severity IN ({placeholders})"
                params.extend(filters["severity"])
            if filters.get("status"):
                placeholders = ",".join("?" * len(filters["status"]))
                where += f" AND status IN ({placeholders})"
                params.extend(filters["status"])
            if filters.get("search"):
                where += " AND (name LIKE ? OR asset_id LIKE ?)"
                s = f"%{filters['search']}%"
                params.extend([s, s])
            if filters.get("mitre_tactic"):
                where += " AND LOWER(COALESCE(mitre_tactic, '')) LIKE ?"
                params.append(f"%{str(filters['mitre_tactic']).strip().lower()}%")
            if filters.get("category"):
                where += " AND LOWER(COALESCE(category, '')) = ?"
                params.append(str(filters["category"]).strip().lower())
            time_where, time_params = _time_range_where(filters, "timestamp")
            where += time_where
            params.extend(time_params)

            total = conn.execute(
                f"SELECT COUNT(*) FROM correlation_alerts {where}", params
            ).fetchone()[0]

            offset = (page - 1) * limit
            rows = conn.execute(
                f"SELECT * FROM correlation_alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()

            items = [_parse_json_fields(dict(r)) for r in rows]

            # Enrich each alert with asset_info and signal meta from Redis
            for item in items:
                aid = item.get('asset_id', '')
                if aid:
                    asset = _get_asset_info(aid)
                    if asset:
                        item['asset_info'] = {
                            'ip': asset.get('ip', ''),
                            'hostname': asset.get('hostname', ''),
                            'asset_type': asset.get('asset_type', ''),
                            'os': asset.get('os', ''),
                        }
                sid = item.get('signal_id', '')
                if sid:
                    meta = _get_signal_meta(sid)
                    if meta:
                        item['signal_meta'] = meta

            summary = {}
            for sev in ("critical", "high", "medium", "low"):
                summary[sev] = conn.execute(
                    "SELECT COUNT(*) FROM correlation_alerts WHERE alert_type = 'signal' AND severity=?",
                    (sev,)
                ).fetchone()[0]

            return {
                "alerts": items,
                "total": total,
                "page": page,
                "page_count": max(1, (total + limit - 1) // limit),
                "summary": summary,
            }
        except Exception as e:
            logger.error(f"Error listing alerts: {e}")
            return {"alerts": [], "total": 0, "page": page, "page_count": 0, "summary": {}}
        finally:
            conn.close()

    def get_alert_detail(self, alert_id):
        conn = _get_conn()
        try:
            if not _tables_exist(conn):
                return None
            row = conn.execute(
                "SELECT * FROM correlation_alerts WHERE id = ?",
                (alert_id,)
            ).fetchone()
            if not row:
                return None
            item = _parse_json_fields(dict(row))
            # Enrich with asset_info
            aid = item.get('asset_id', '')
            if aid:
                asset = _get_asset_info(aid)
                if asset:
                    item['asset_info'] = {
                        'ip': asset.get('ip', ''),
                        'hostname': asset.get('hostname', ''),
                        'asset_type': asset.get('asset_type', ''),
                        'os': asset.get('os', ''),
                    }
            # Enrich with signal meta
            sid = item.get('signal_id', '')
            if sid:
                meta = _get_signal_meta(sid)
                if meta:
                    item['signal_meta'] = meta
            item['contributing_signals'] = self._build_alert_signals(item)
            return item
        finally:
            conn.close()

    def update_alert(self, alert_id, data):
        conn = _get_conn()
        try:
            allowed = {"status", "verdict"}
            updates = {k: v for k, v in data.items() if k in allowed}
            if not updates:
                return self.get_alert_detail(alert_id)
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            conn.execute(
                f"UPDATE correlation_alerts SET {set_clause} WHERE id = ?",
                list(updates.values()) + [alert_id]
            )
            conn.commit()
            return self.get_alert_detail(alert_id)
        finally:
            conn.close()

    def get_alert_signals(self, alert_id):
        conn = _get_conn()
        try:
            alert = conn.execute(
                "SELECT signal_id, name, description, severity, category, timestamp, "
                "evidence, contributing_signals, ftx_ids "
                "FROM correlation_alerts WHERE id = ?",
                (alert_id,)
            ).fetchone()
            if not alert:
                return []
            item = _parse_json_fields(dict(alert))
            sid = item.get('signal_id', '')
            if sid:
                meta = _get_signal_meta(sid)
                if meta:
                    item['signal_meta'] = meta
            return self._build_alert_signals(item)
        finally:
            conn.close()

    def get_alert_evidence(self, alert_id):
        conn = _get_conn()
        try:
            alert = conn.execute(
                "SELECT evidence, ftx_ids FROM correlation_alerts WHERE id = ?",
                (alert_id,)
            ).fetchone()
            if not alert:
                return {}
            result = {}
            try:
                result["evidence"] = json.loads(alert["evidence"] or "{}")
            except (json.JSONDecodeError, TypeError):
                result["evidence"] = {}
            result["ftx_ids"] = alert["ftx_ids"] or ""
            return result
        finally:
            conn.close()

    def get_affected_systems(self, alert_id):
        conn = _get_conn()
        try:
            alert = conn.execute(
                "SELECT asset_id, asset_type, evidence FROM correlation_alerts WHERE id = ?",
                (alert_id,)
            ).fetchone()
            if not alert:
                return {}
            return {
                "asset_id": alert["asset_id"],
                "asset_type": alert["asset_type"],
            }
        finally:
            conn.close()

    def get_alert_network_activity(self, alert_id):
        conn = _get_conn()
        try:
            alert = conn.execute(
                "SELECT signal_id, asset_id, timestamp, ftx_ids FROM correlation_alerts WHERE id = ?",
                (alert_id,)
            ).fetchone()
            if not alert:
                return []

            signal_id = alert["signal_id"] or ""
            asset_id = alert["asset_id"] or ""
            alert_ts = _parse_timestamp(alert["timestamp"])
            ftx_ids = [f.strip() for f in (alert["ftx_ids"] or "").split(",") if f.strip()]

            rows = []
            seen_ids = set()

            # Preferred: exact contributing raw records by ftx_ids.
            for ftx in ftx_ids[:200]:
                for r in conn.execute(
                    "SELECT id, src_ip, dst_ip, timestamp, evidence FROM correlation_raw_signals WHERE ftx_ids LIKE ?",
                    (f"%{ftx}%",)
                ).fetchall():
                    rid = r["id"]
                    if rid in seen_ids:
                        continue
                    seen_ids.add(rid)
                    rows.append(dict(r))

            # Fallback: signal+asset window if ftx matching found nothing.
            if not rows and signal_id and asset_id:
                for r in conn.execute(
                    "SELECT id, src_ip, dst_ip, timestamp, evidence FROM correlation_raw_signals "
                    "WHERE signal_id = ? AND asset_id = ? ORDER BY timestamp DESC LIMIT 1000",
                    (signal_id, asset_id)
                ).fetchall():
                    rid = r["id"]
                    if rid in seen_ids:
                        continue
                    seen_ids.add(rid)
                    rows.append(dict(r))

            if not rows:
                return []

            # Bucket by minute for chart-friendly payload.
            buckets = defaultdict(lambda: {
                "events": 0, "bytes_in": 0, "bytes_out": 0,
                "src_ips": set(), "dst_ips": set()
            })
            for row in rows:
                ts = _parse_timestamp(row.get("timestamp"))
                if not ts:
                    continue
                # Keep to a +/- 15m region around alert time when available.
                if alert_ts and abs((ts - alert_ts).total_seconds()) > 900:
                    continue
                key = ts.strftime("%Y-%m-%dT%H:%M:00Z")
                b = buckets[key]
                b["events"] += 1
                if row.get("src_ip"):
                    b["src_ips"].add(row["src_ip"])
                if row.get("dst_ip"):
                    b["dst_ips"].add(row["dst_ip"])

                evidence = row.get("evidence")
                try:
                    evidence = json.loads(evidence) if isinstance(evidence, str) else (evidence or {})
                except Exception:
                    evidence = {}
                features = evidence.get("features", {}) if isinstance(evidence, dict) else {}
                b["bytes_in"] += int(
                    features.get("bytes_in") or features.get("resp_bytes") or 0
                )
                b["bytes_out"] += int(
                    features.get("bytes_out") or features.get("orig_bytes") or 0
                )

            out = []
            for ts in sorted(buckets.keys()):
                b = buckets[ts]
                out.append({
                    "timestamp": ts,
                    "events": b["events"],
                    "bytes_in": b["bytes_in"],
                    "bytes_out": b["bytes_out"],
                    "unique_src_ips": len(b["src_ips"]),
                    "unique_dst_ips": len(b["dst_ips"]),
                })
            return out
        finally:
            conn.close()

    # ── Anomalies (low-weight processed signals) ─────────────────

    def list_anomalies(self, filters, page=1, limit=10):
        conn = _get_conn()
        try:
            if not _tables_exist(conn):
                return {"items": [], "total": 0, "page": page, "page_count": 0}
            where = "WHERE visibility_mode = 'anomaly'"
            params = []

            if filters.get("severity"):
                placeholders = ",".join("?" * len(filters["severity"]))
                where += f" AND severity IN ({placeholders})"
                params.extend(filters["severity"])
            if filters.get("search"):
                where += " AND (signal_name LIKE ? OR asset_id LIKE ?)"
                s = f"%{filters['search']}%"
                params.extend([s, s])

            total = conn.execute(
                f"SELECT COUNT(*) FROM correlation_processed_signals {where}", params
            ).fetchone()[0]

            offset = (page - 1) * limit
            rows = conn.execute(
                f"SELECT * FROM correlation_processed_signals {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()

            items = [_parse_json_fields(dict(r)) for r in rows]

            return {
                "items": items,
                "total": total,
                "page": page,
                "page_count": max(1, (total + limit - 1) // limit),
            }
        finally:
            conn.close()

    def get_anomaly_detail(self, anomaly_id):
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT p.*, r.evidence, r.metrics, r.src_ip, r.dst_ip, r.category, r.detection_method "
                "FROM correlation_processed_signals p "
                "LEFT JOIN correlation_raw_signals r ON p.raw_signal_id = r.id "
                "WHERE p.id = ?",
                (anomaly_id,)
            ).fetchone()
            if not row:
                return None
            return _parse_json_fields(dict(row))
        finally:
            conn.close()

    # ── Forensic drill-down ──────────────────────────────────────

    def get_contributing_logs(self, ftx_ids_csv):
        """
        Given a comma-separated string of ftx_ids, look up the raw signals
        that contain those ftx_ids. In production, this would query Parquet
        via DuckDB. For now, return matching raw signals from SQLite.
        """
        if not ftx_ids_csv:
            return []
        conn = _get_conn()
        try:
            ftx_list = [f.strip() for f in ftx_ids_csv.split(",") if f.strip()]
            if not ftx_list:
                return []
            # Search raw signals where ftx_ids contains any of the requested IDs
            results = []
            for ftx_id in ftx_list[:100]:  # Cap at 100 to prevent abuse
                rows = conn.execute(
                    "SELECT * FROM correlation_raw_signals WHERE ftx_ids LIKE ?",
                    (f"%{ftx_id}%",)
                ).fetchall()
                results.extend(_rows_to_dicts(rows))
            # Deduplicate by id
            seen = set()
            unique = []
            for r in results:
                if r["id"] not in seen:
                    seen.add(r["id"])
                    unique.append(_parse_json_fields(r))
            return unique
        finally:
            conn.close()

    # ── Overview stats ───────────────────────────────────────────

    def get_overview_stats(self, time_range='24h'):
        conn = _get_conn()
        try:
            if not _tables_exist(conn):
                return {"incidents": 0, "alerts": 0, "anomalies": 0, "raw_signals": 0, "severity": {}}
            where = "WHERE datetime(replace(substr(timestamp, 1, 19), 'T', ' ')) >= datetime('now', ?)"
            params = [_sqlite_time_modifier(time_range)]
            incidents = conn.execute(
                f"SELECT COUNT(*) FROM correlation_alerts {where} AND alert_type='use_case'",
                params
            ).fetchone()[0]
            alerts = conn.execute(
                f"SELECT COUNT(*) FROM correlation_alerts {where} AND alert_type='signal'",
                params
            ).fetchone()[0]
            anomalies = conn.execute(
                "SELECT COUNT(*) FROM correlation_processed_signals WHERE visibility_mode='anomaly'"
            ).fetchone()[0]
            raw_total = conn.execute(
                "SELECT COUNT(*) FROM correlation_raw_signals"
            ).fetchone()[0]

            severity_breakdown = {}
            for sev in ("critical", "high", "medium", "low"):
                severity_breakdown[sev] = conn.execute(
                    f"SELECT COUNT(*) FROM correlation_alerts {where} AND severity = ?",
                    params + [sev]
                ).fetchone()[0]

            return {
                "incidents": incidents,
                "alerts": alerts,
                "anomalies": anomalies,
                "raw_signals": raw_total,
                "severity": severity_breakdown,
            }
        finally:
            conn.close()

    def get_detection_stats(self, time_range='24h'):
        """
        Enriched detection stats for the Overview analytics tab.
        All data from correlation_alerts / correlation_processed_signals SQLite tables.
        """
        conn = _get_conn()
        try:
            if not _tables_exist(conn):
                return {
                    "total_detections": 0, "incidents": 0, "alerts": 0,
                    "severity": {}, "timeline": [], "by_category": [],
                    "by_mitre": [], "top_assets": [], "protocol_threats": [],
                }

            # ── Counts ────────────────────────────────────────────
            where = "WHERE datetime(replace(substr(timestamp, 1, 19), 'T', ' ')) >= datetime('now', ?)"
            params = [_sqlite_time_modifier(time_range)]
            total = conn.execute(
                f"SELECT COUNT(*) FROM correlation_alerts {where}",
                params
            ).fetchone()[0]
            incidents = conn.execute(
                f"SELECT COUNT(*) FROM correlation_alerts {where} AND alert_type='use_case'",
                params
            ).fetchone()[0]
            alerts_count = conn.execute(
                f"SELECT COUNT(*) FROM correlation_alerts {where} AND alert_type='signal'",
                params
            ).fetchone()[0]

            # ── Severity breakdown ────────────────────────────────
            severity = {}
            for sev in ("critical", "high", "medium", "low"):
                severity[sev] = conn.execute(
                    f"SELECT COUNT(*) FROM correlation_alerts {where} AND severity = ?",
                    params + [sev]
                ).fetchone()[0]

            # ── Hourly timeline (24h buckets) ─────────────────────
            timeline = []
            try:
                rows = conn.execute(
                    "SELECT strftime('%H', datetime(replace(substr(timestamp, 1, 19), 'T', ' '))) as hour, COUNT(*) as cnt "
                    f"FROM correlation_alerts {where} GROUP BY hour ORDER BY hour",
                    params
                ).fetchall()
                hour_map = {r[0]: r[1] for r in rows}
                for h in range(24):
                    hk = f"{h:02d}"
                    timeline.append({"time": f"{hk}:00", "v": hour_map.get(hk, 0)})
            except Exception:
                timeline = [{"time": f"{h:02d}:00", "v": 0} for h in range(24)]

            # ── By category ───────────────────────────────────────
            by_category = []
            try:
                rows = conn.execute(
                    "SELECT COALESCE(category, 'Unknown') as cat, COUNT(*) as cnt "
                    f"FROM correlation_alerts {where} GROUP BY cat ORDER BY cnt DESC LIMIT 8",
                    params
                ).fetchall()
                cat_total = sum(r[1] for r in rows) or 1
                for r in rows:
                    by_category.append({
                        "label": r[0], "count": r[1],
                        "pct": round(r[1] / cat_total * 100),
                    })
            except Exception:
                pass

            # ── By MITRE tactic ───────────────────────────────────
            by_mitre = []
            try:
                rows = conn.execute(
                    "SELECT COALESCE(mitre_tactic, 'Unknown') as tactic, COUNT(*) as cnt "
                    f"FROM correlation_alerts {where} AND mitre_tactic IS NOT NULL AND mitre_tactic != '' "
                    "GROUP BY tactic ORDER BY cnt DESC LIMIT 6",
                    params
                ).fetchall()
                for r in rows:
                    by_mitre.append({"tactic": r[0], "count": r[1]})
            except Exception:
                pass

            # ── Top targeted assets ───────────────────────────────
            top_assets = []
            try:
                rows = conn.execute(
                    "SELECT asset_id, COUNT(*) as cnt, "
                    "MAX(name) as latest_alert, "
                    "MAX(CAST(risk_score AS REAL)) as max_score "
                    f"FROM correlation_alerts {where} AND asset_id IS NOT NULL AND asset_id != '' "
                    "GROUP BY asset_id ORDER BY cnt DESC LIMIT 5",
                    params
                ).fetchall()
                for r in rows:
                    # Try to get hostname from asset info
                    asset_id = r[0]
                    hostname = ""
                    try:
                        if _REDIS:
                            hostname = (
                                _REDIS.hget(f"ndr:assets:profile:{asset_id}", "hostname")
                                or _REDIS.hget(f"ndr:asset:{asset_id}", "hostname")
                                or ""
                            )
                    except Exception:
                        pass
                    top_assets.append({
                        "host": asset_id,
                        "tag": f"({hostname})" if hostname else "",
                        "alert": r[2] or "Unknown",
                        "volume": f"{r[1]} Hits",
                        "score": f"{int(r[3] or 0)}/100",
                        "count": r[1],
                    })
            except Exception:
                pass

            # ── Protocol-based threats ────────────────────────────
            protocol_threats = []
            try:
                rows = conn.execute(
                    "SELECT COALESCE(category, 'Unknown') as proto_cat, COUNT(*) as cnt "
                    f"FROM correlation_alerts {where} "
                    "GROUP BY proto_cat ORDER BY cnt DESC LIMIT 4",
                    params
                ).fetchall()
                proto_total = sum(r[1] for r in rows) or 1
                for r in rows:
                    protocol_threats.append({
                        "label": r[0],
                        "pct": round(r[1] / proto_total * 100),
                    })
            except Exception:
                pass

            return {
                "total_detections": total,
                "incidents": incidents,
                "alerts": alerts_count,
                "severity": severity,
                "timeline": timeline,
                "by_category": by_category,
                "by_mitre": by_mitre,
                "top_assets": top_assets,
                "protocol_threats": protocol_threats,
            }
        finally:
            conn.close()
