from ..base.asset_repo import AssetRepository
from clients.state_store_client import StateStoreClient
import json
import logging
import math
import time
import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
_DB_PATH = str(Path(__file__).resolve().parent.parent.parent / "db.sqlite3")


# Per-process micro-cache to reduce repeated heavy scans/computation.
_CACHE_LOCK = threading.Lock()
_CACHE = {
    "profiles": {"value": None, "ts": 0.0},
    "list": {},
    "analytics": {"value": None, "ts": 0.0},
}
_PROFILES_TTL_SEC = 8
_LIST_TTL_SEC = 5
_ANALYTICS_TTL_SEC = 20


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_int(v, default=0):
    try:
        return int(float(v or 0))
    except (ValueError, TypeError):
        return default


def _safe_float(v, default=0.0):
    try:
        return float(v or 0)
    except (ValueError, TypeError):
        return default


def _fmt_bytes(b):
    b = _safe_int(b)
    if b >= 1_000_000_000:
        return f"{b / 1_000_000_000:.1f} GB"
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    if b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b} B"


def _epoch_ms_to_iso(ms_str):
    """Convert epoch milliseconds string to ISO datetime string. Returns unchanged if already ISO."""
    if not ms_str:
        return ""
    s = str(ms_str).strip()
    # Already an ISO string (contains '-' or 'T') — return as-is
    if '-' in s or 'T' in s:
        return s
    try:
        ms = int(s)
        if ms > 1_000_000_000_000:  # milliseconds
            ms = ms / 1000
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ms, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return s


def _parse_time(ts):
    """Parse ISO or epoch (sec/ms) into timezone-aware datetime."""
    if ts is None:
        return None
    s = str(ts).strip()
    if not s:
        return None
    # Epoch-like
    if s.isdigit():
        try:
            v = int(s)
            if v > 1_000_000_000_000:
                v = v / 1000
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (ValueError, OSError):
            return None
    # ISO-like
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except ValueError:
        return None


def _time_ago_label(ts):
    d = _parse_time(ts)
    if not d:
        return "unknown"
    now = datetime.now(timezone.utc)
    diff = max(0, int((now - d).total_seconds()))
    if diff < 60:
        return f"{diff}s ago"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return f"{diff // 86400}d ago"


def _safe_ip(ip):
    return str(ip or "").strip()


def _safe_hgetall_if_hash(key):
    """
    Read state hash only when key type is actually 'hash'.
    Prevents WRONGTYPE noise from keys like ndr:assets:profile:*:ips (set).
    """
    try:
        if StateStoreClient.client.type(key) != "hash":
            return {}
        return StateStoreClient.hgetall(key) or {}
    except Exception:
        return {}


def _cache_get(name, key=None, ttl=5):
    now = time.time()
    with _CACHE_LOCK:
        if key is None:
            entry = _CACHE.get(name, {})
            if not entry:
                return None
            if (now - float(entry.get("ts", 0))) <= ttl:
                return entry.get("value")
            return None
        bucket = _CACHE.get(name, {})
        entry = bucket.get(key) if isinstance(bucket, dict) else None
        if not entry:
            return None
        if (now - float(entry.get("ts", 0))) <= ttl:
            return entry.get("value")
        return None


def _cache_set(name, value, key=None):
    now = time.time()
    with _CACHE_LOCK:
        if key is None:
            _CACHE[name] = {"value": value, "ts": now}
            return
        bucket = _CACHE.get(name)
        if not isinstance(bucket, dict):
            bucket = {}
            _CACHE[name] = bucket
        bucket[key] = {"value": value, "ts": now}


def _compute_maturity(profile, summary, counters):
    """
    Compute maturity score (0-100) from how many key fields are known.
    Returns dict: {score, fields_known, fields_total, checklist}
    """
    checks = [
        {
            "field": "ip",
            "label": "IP Address",
            "known": bool(profile.get("ip")),
            "value": profile.get("ip", ""),
            "source": "ndr-enrich",
            "needs": "Any network traffic",
        },
        {
            "field": "hostname",
            "label": "Hostname",
            "known": bool(profile.get("hostname")),
            "value": profile.get("hostname", ""),
            "source": "DHCP / Kerberos / NTLM",
            "needs": "DHCP lease or AD auth event",
        },
        {
            "field": "mac",
            "label": "MAC Address",
            "known": bool(profile.get("mac")),
            "value": profile.get("mac", ""),
            "source": "DHCP log",
            "needs": "DHCP event visible to Zeek",
        },
        {
            "field": "vendor",
            "label": "Vendor (OUI)",
            "known": bool(profile.get("vendor")),
            "value": profile.get("vendor", ""),
            "source": "OUI dataset",
            "needs": "MAC address + OUI dataset loaded",
        },
        {
            "field": "os_hint",
            "label": "OS Fingerprint",
            "known": bool(profile.get("os_hint")),
            "value": profile.get("os_hint", ""),
            "source": "HTTP User-Agent",
            "needs": "HTTP traffic from this asset",
        },
        {
            "field": "role",
            "label": "Role Classification",
            "known": profile.get("asset_type", "unknown") != "unknown",
            "value": profile.get("asset_type", ""),
            "source": "Traffic pattern analysis",
            "needs": "Minimum 50 connections observed",
        },
        {
            "field": "app_fingerprint",
            "label": "App / Browser",
            "known": bool(profile.get("app_fingerprint")),
            "value": profile.get("app_fingerprint", ""),
            "source": "JA3 fingerprint",
            "needs": "SSL/TLS traffic + JA3 dataset loaded",
        },
        {
            "field": "dns_behavior",
            "label": "DNS Behavior",
            "known": _safe_int(counters.get("dns_queries")) > 0,
            "value": f"{_safe_int(counters.get('dns_queries')):,} queries observed",
            "source": "DNS log",
            "needs": "DNS traffic from this asset",
        },
        {
            "field": "user_identity",
            "label": "User Identity",
            "known": bool(profile.get("hostname")) and profile.get("asset_type") == "workstation",
            "value": profile.get("hostname", ""),
            "source": "Kerberos / NTLM",
            "needs": "AD authentication events",
        },
        {
            "field": "baseline_trained",
            "label": "Baseline Trained",
            "known": summary.get("baseline_status") in ("normal", "anomalous"),
            "value": summary.get("baseline_status", ""),
            "source": "ndr-baseline",
            "needs": "7+ days of traffic data",
        },
    ]

    known_count = sum(1 for c in checks if c["known"])
    total = len(checks)
    score = round(known_count / total * 100)

    return {
        "score": score,
        "fields_known": known_count,
        "fields_total": total,
        "checklist": checks,
    }


def _compute_behavior(counters, summary):
    """Derive network behavior patterns from counters and summary."""
    _EMPTY_24H = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"
    hourly_raw = summary.get("hourly_activity") or _EMPTY_24H
    try:
        hourly = json.loads(hourly_raw)
    except (json.JSONDecodeError, TypeError):
        hourly = [0] * 24
    if not isinstance(hourly, list):
        hourly = [0] * 24

    max_val = max(hourly) if hourly else 0
    if max_val == 0:
        active_hours = 0
        peak_hour = 0
    else:
        active_hours = sum(1 for v in hourly if v >= max_val * 0.3)
        peak_hour = hourly.index(max_val)

    is_server = active_hours >= 20
    is_workstation = (not is_server) and 8 <= peak_hour <= 20 and active_hours >= 6

    conn_in = _safe_int(counters.get("conn_in"))
    conn_out = _safe_int(counters.get("conn_out"))
    bytes_out = _safe_int(counters.get("bytes_out"))
    bytes_in = _safe_int(counters.get("bytes_in"))

    flags = []

    # High outbound ratio (potential exfil hint)
    if conn_out > 0 and conn_in > 0:
        out_ratio = conn_out / (conn_in + conn_out)
        if out_ratio > 0.85 and bytes_out > 10_000_000:
            flags.append({
                "flag": "High Outbound Ratio",
                "detail": f"{round(out_ratio * 100)}% of connections are outbound with >{_fmt_bytes(bytes_out)} sent",
                "severity": "warning",
            })

    # High DNS queries
    dns = _safe_int(counters.get("dns_queries"))
    if dns > 5000:
        flags.append({
            "flag": "High DNS Volume",
            "detail": f"{dns:,} DNS queries observed — check for DGA or tunneling",
            "severity": "warning",
        })

    # Off-hours server pattern
    if not is_server and peak_hour not in range(7, 21) and max_val > 50:
        flags.append({
            "flag": "Off-Hours Activity",
            "detail": f"Peak activity at {peak_hour}:00 — unusual for a workstation",
            "severity": "warning",
        })

    return {
        "active_hours_per_day": active_hours,
        "peak_hour": peak_hour,
        "baseline_status": summary.get("baseline_status", "training"),
        "is_server_pattern": is_server,
        "is_workstation_pattern": is_workstation,
        "flags": flags,
    }


def _get_enrich_profile_by_ip(ip):
    """
    Resolve an asset profile by IP address.

    Priority order:
    1. DHCP chain: ndr:assets:ip_to_mac:{ip} → ndr:assets:mac_to_asset:{mac} → ndr:assets:profile:{id}
    2. Direct enrich key by IP: ndr:assets:profile:{ip}
    3. Scan all ndr:assets:profile:* for matching ip field
    4. Fallback: scan ndr:asset:* (preflight seed keys) for matching ip field
    """
    # 1. DHCP chain (fast path — ndr-enrich identity resolver)
    mac = StateStoreClient.get(f"ndr:assets:ip_to_mac:{ip}")
    if mac:
        asset_id = StateStoreClient.get(f"ndr:assets:mac_to_asset:{mac}")
        if asset_id:
            profile = StateStoreClient.hgetall(f"ndr:assets:profile:{asset_id}")
            if profile:
                profile["_asset_id"] = asset_id
                return profile

    # 2. Direct enrich key by IP
    profile = StateStoreClient.hgetall(f"ndr:assets:profile:{ip}")
    if profile:
        profile["_asset_id"] = ip
        return profile

    # 3. Scan enrich profile keys for matching ip field
    for key in StateStoreClient.scan_keys("ndr:assets:profile:*"):
        d = _safe_hgetall_if_hash(key)
        if d and d.get("ip") == ip:
            asset_id = key.replace("ndr:assets:profile:", "")
            d["_asset_id"] = asset_id
            return d

    # 4. Fallback: preflight seed keys (ndr:asset:AST-PF-XX) — scan for matching ip field
    for key in StateStoreClient.scan_keys("ndr:asset:*"):
        # Skip non-profile keys
        if any(x in key for x in [":summary:", ":top:", ":counters:", ":ip_index:", ":mac_index:", ":role:"]):
            continue
        d = _safe_hgetall_if_hash(key)
        if d and d.get("ip") == ip:
            asset_id = key.replace("ndr:asset:", "")
            d["_asset_id"] = asset_id
            return d

    return None


def _get_counters(asset_id, ip=None):
    """
    Read counters from both key families:
      - ndr:assets:counters:{asset_id} (new enrich path)
      - ndr:asset:counters:{ip|asset_id} (legacy/baseline path)
    """
    candidates = []
    if asset_id:
        candidates.extend([
            f"ndr:assets:counters:{asset_id}",
            f"ndr:asset:counters:{asset_id}",
        ])
    if ip:
        candidates.extend([
            f"ndr:assets:counters:{ip}",
            f"ndr:asset:counters:{ip}",
        ])
    for key in candidates:
        data = StateStoreClient.hgetall(key) or {}
        if data:
            return data
    return {}


def _get_summary(ip):
    return StateStoreClient.hgetall(f"ndr:asset:summary:{ip}") or {}


def _get_top(ip):
    return StateStoreClient.hgetall(f"ndr:asset:top:{ip}") or {}


def _get_risk_score(asset_id):
    risk_str = StateStoreClient.get(f"ndr:entity_risk:{asset_id}") or "0"
    try:
        return int(float(risk_str))
    except (ValueError, TypeError):
        return 0


def _sqlite_conn():
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=3000")
    return conn


def _has_alerts_table(conn):
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='correlation_alerts' LIMIT 1"
        ).fetchone()
        return bool(row)
    except Exception:
        return False


def _alert_counts_for_ips(ips):
    """
    Return {ip: count} where count includes rows matching src_ip OR asset_id OR dst_ip.
    """
    clean_ips = [_safe_ip(i) for i in ips if _safe_ip(i)]
    if not clean_ips:
        return {}
    counts = {ip: 0 for ip in clean_ips}
    try:
        conn = _sqlite_conn()
        if not _has_alerts_table(conn):
            conn.close()
            return counts
        for ip in clean_ips:
            row = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM correlation_alerts
                WHERE src_ip = ? OR asset_id = ? OR dst_ip = ?
                """,
                (ip, ip, ip),
            ).fetchone()
            counts[ip] = int(row["c"] if row and "c" in row.keys() else 0)
        conn.close()
    except Exception as e:
        logger.warning(f"Could not read alert counts: {e}")
    return counts


def _detections_for_ip(ip, limit=10):
    out = []
    sip = _safe_ip(ip)
    if not sip:
        return out
    try:
        conn = _sqlite_conn()
        if not _has_alerts_table(conn):
            conn.close()
            return out
        rows = conn.execute(
            """
            SELECT id, name, severity, timestamp
            FROM correlation_alerts
            WHERE src_ip = ? OR asset_id = ? OR dst_ip = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (sip, sip, sip, int(limit)),
        ).fetchall()
        conn.close()
        for r in rows:
            out.append({
                "id": int(r["id"]),
                "name": r["name"] or "Detection",
                "severity": (r["severity"] or "medium").lower(),
                "time_ago": _time_ago_label(r["timestamp"]),
            })
    except Exception as e:
        logger.warning(f"Could not read detections for {sip}: {e}")
    return out


def _collect_profiles():
    """
    Build an IP-indexed profile map from:
      1) ndr:assets:profile:* (primary)
      2) ndr:asset:* (legacy/preflight profile keys)
    """
    by_ip = {}

    # Primary profile keys
    for key in StateStoreClient.scan_keys("ndr:assets:profile:*"):
        profile = _safe_hgetall_if_hash(key)
        ip = _safe_ip(profile.get("ip"))
        if not ip:
            continue
        asset_id = key.replace("ndr:assets:profile:", "")
        profile["_asset_id"] = asset_id
        by_ip[ip] = profile

    # Legacy/preflight profile keys
    for key in StateStoreClient.scan_keys("ndr:asset:*"):
        if any(x in key for x in [":summary:", ":top:", ":counters:", ":ip_index:", ":mac_index:", ":role:"]):
            continue
        profile = _safe_hgetall_if_hash(key)
        ip = _safe_ip(profile.get("ip"))
        if not ip:
            continue
        asset_id = key.replace("ndr:asset:", "")
        if ip not in by_ip:
            profile["_asset_id"] = asset_id
            by_ip[ip] = profile

    return by_ip


def _collect_profiles_cached():
    cached = _cache_get("profiles", ttl=_PROFILES_TTL_SEC)
    if cached is not None:
        return cached
    by_ip = _collect_profiles()
    _cache_set("profiles", by_ip)
    return by_ip


def _bulk_risk_scores(asset_ids, batch_size=2000):
    """
    Bulk-read risk values using MGET to avoid one GET per asset.
    Returns {asset_id: risk_int}.
    """
    if not asset_ids:
        return {}
    keys = [f"ndr:entity_risk:{aid}" for aid in asset_ids]
    out = {}
    client = StateStoreClient.client
    for i in range(0, len(keys), batch_size):
        chunk = keys[i:i + batch_size]
        values = client.mget(chunk) or []
        for k, v in zip(chunk, values):
            aid = k.replace("ndr:entity_risk:", "")
            try:
                out[aid] = int(float(v or 0))
            except (ValueError, TypeError):
                out[aid] = 0
    return out


def _build_asset_card(profile, summary, counters, asset_id):
    """Build the list-view asset card from merged data."""
    ip = profile.get("ip", asset_id if "." in str(asset_id) else "")
    risk_score = _get_risk_score(asset_id)

    total_events = _safe_int(profile.get("total_events") or summary.get("total_events"))
    first_seen_raw = profile.get("first_seen", "")
    last_seen_raw = profile.get("last_seen", "")

    # Epoch ms → ISO conversion if needed
    first_seen = _epoch_ms_to_iso(first_seen_raw) if first_seen_raw and first_seen_raw.isdigit() else first_seen_raw
    last_seen = _epoch_ms_to_iso(last_seen_raw) if last_seen_raw and last_seen_raw.isdigit() else last_seen_raw

    # Compute EPS
    events_per_sec = 0.0
    if total_events > 0 and first_seen_raw and last_seen_raw:
        try:
            fs = int(first_seen_raw) / 1000 if int(first_seen_raw) > 1e11 else int(first_seen_raw)
            ls = int(last_seen_raw) / 1000 if int(last_seen_raw) > 1e11 else int(last_seen_raw)
            duration = ls - fs
            if duration > 0:
                events_per_sec = round(total_events / duration, 2)
        except (ValueError, TypeError):
            pass

    # Maturity score — always compute from field checklist (consistent with detail view)
    mc = _compute_maturity(profile, summary, counters)
    maturity_score = mc["score"]

    # Protocol breakdown for mini bars
    proto_raw = summary.get("protocol_breakdown", "{}")
    try:
        protocol_breakdown = json.loads(proto_raw)
    except (json.JSONDecodeError, TypeError):
        protocol_breakdown = {}

    return {
        "id": asset_id,
        "ip": ip,
        "hostname": profile.get("hostname", ""),
        "mac": profile.get("mac", ""),
        "asset_type": profile.get("asset_type", "unknown"),
        "type": profile.get("asset_type", "unknown"),
        "os": profile.get("os_hint", ""),
        "os_hint": profile.get("os_hint", ""),
        "vendor": profile.get("vendor", ""),
        "app_fingerprint": profile.get("app_fingerprint", ""),
        "segment": profile.get("segment", ""),
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 50 else "medium" if risk_score >= 30 else "low",
        "profile_pct": maturity_score,
        "maturity_score": maturity_score,
        "total_connections": _safe_int(counters.get("conn_out", 0)) + _safe_int(counters.get("conn_in", 0)),
        "protocols_seen": sum(1 for v in protocol_breakdown.values() if v > 0),
        "events_per_sec": events_per_sec,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "status": "active",
        "log_types": "[]",
        "alert_count": 0,
    }


def _build_light_asset_card(profile, asset_id):
    """Fast list/analytics card without per-IP summary/counter reads."""
    ip = profile.get("ip", asset_id if "." in str(asset_id) else "")
    maturity = _safe_int(profile.get("maturity_score") or profile.get("profile_pct"), -1)
    if maturity < 0:
        maturity = _compute_maturity(profile, {}, {})["score"]
    first_seen_raw = profile.get("first_seen", "")
    last_seen_raw = profile.get("last_seen", "")
    first_seen = _epoch_ms_to_iso(first_seen_raw) if first_seen_raw and str(first_seen_raw).isdigit() else first_seen_raw
    last_seen = _epoch_ms_to_iso(last_seen_raw) if last_seen_raw and str(last_seen_raw).isdigit() else last_seen_raw
    atype = profile.get("asset_type") or profile.get("type") or "unknown"

    return {
        "id": asset_id,
        "ip": ip,
        "hostname": profile.get("hostname", ""),
        "mac": profile.get("mac", ""),
        "asset_type": atype,
        "type": atype,
        "os": profile.get("os_hint", ""),
        "os_hint": profile.get("os_hint", ""),
        "vendor": profile.get("vendor", ""),
        "app_fingerprint": profile.get("app_fingerprint", ""),
        "segment": profile.get("segment", ""),
        "risk_score": _safe_int(profile.get("risk_score", 0)),
        "risk_level": "critical" if _safe_int(profile.get("risk_score", 0)) >= 70 else "high" if _safe_int(profile.get("risk_score", 0)) >= 50 else "medium" if _safe_int(profile.get("risk_score", 0)) >= 30 else "low",
        "profile_pct": maturity,
        "maturity_score": maturity,
        "total_connections": 0,
        "protocols_seen": 0,
        "events_per_sec": 0.0,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "status": "active",
        "log_types": "[]",
        "top_protocols": [],
        "alert_count": 0,
    }


# ── Repository ─────────────────────────────────────────────────────────────────

class ProductionAssetRepository(AssetRepository):
    """
    Reads assets from ndr-enrich's state keys (ndr:assets:profile:*) and
    merges with ndr-baseline summary/top keys for full enrichment.

    Key sources:
      ndr:assets:profile:{asset_id}   — identity: ip, hostname, mac, vendor, os_hint, type
      ndr:assets:counters:{asset_id}  — live counters: conn_in/out, bytes, dns, http, ssl, ssh
      ndr:asset:summary:{ip}          — batch stats: total_events, protocol_breakdown, hourly_activity, maturity_score
      ndr:asset:top:{ip}              — top-N: dns_domains, dst_ips, services, rare_ports
      ndr:entity_risk:{asset_id}      — risk score from correlation engine
    """

    def list_assets(self, filters, page=1, limit=10):
        try:
            list_cache_key = json.dumps(
                {
                    "page": page,
                    "limit": limit,
                    "search": (filters or {}).get("search"),
                    "type": (filters or {}).get("type"),
                    "segment": (filters or {}).get("segment"),
                    "risk_level": (filters or {}).get("risk_level"),
                    "tab": (filters or {}).get("tab", "active"),
                },
                sort_keys=True,
            )
            cached = _cache_get("list", key=list_cache_key, ttl=_LIST_TTL_SEC)
            if cached is not None:
                return cached

            # ── 1. Collect all profiles (including summary/top synthetic) ──
            by_ip = _collect_profiles_cached()
            if not by_ip:
                empty = {"assets": [], "total": 0, "page": page, "page_count": 0}
                _cache_set("list", empty, key=list_cache_key)
                return empty

            assets = []
            for ip, profile in by_ip.items():
                asset_id = profile.get("_asset_id", ip)
                card = _build_light_asset_card(profile, asset_id)
                assets.append(card)

            # ── 2. Filter ─────────────────────────────────────────────
            if filters:
                search = (filters.get("search") or "").lower()
                if search:
                    assets = [a for a in assets if
                               search in (a.get("ip") or "").lower() or
                               search in (a.get("hostname") or "").lower() or
                               search in (a.get("asset_type") or "").lower() or
                               search in (a.get("vendor") or "").lower()]
                asset_type = filters.get("type") or ""
                if asset_type:
                    assets = [a for a in assets if a.get("asset_type") == asset_type]

            # Sort: highest maturity first for 'active' tab, most recent first for 'discovered'
            tab = (filters or {}).get("tab", "active")
            if tab == "discovered":
                assets.sort(key=lambda a: a.get("first_seen") or "", reverse=True)
            elif tab == "threat":
                assets.sort(key=lambda a: a.get("risk_score") or 0, reverse=True)
            else:
                assets.sort(key=lambda a: a.get("maturity_score") or 0, reverse=True)

            total = len(assets)
            page_count = max(1, math.ceil(total / limit))
            start = (page - 1) * limit
            page_items = assets[start:start + limit]

            # Hydrate visible rows with summary/counters-backed metrics.
            for a in page_items:
                ip = _safe_ip(a.get("ip"))
                if not ip:
                    continue
                profile = by_ip.get(ip, {})
                asset_id = profile.get("_asset_id", ip)
                summary = _get_summary(ip)
                counters = _get_counters(asset_id, ip=ip)
                full = _build_asset_card(profile, summary, counters, asset_id)
                # Keep list-level alert count from SQL (set below)
                full["alert_count"] = a.get("alert_count", 0)
                a.update(full)

            # Fill alert counts only for visible page (keeps list performant).
            counts = _alert_counts_for_ips([a.get("ip") for a in page_items])
            for a in page_items:
                a["alert_count"] = counts.get(a.get("ip", ""), 0)

            result = {
                "assets": page_items,
                "total": total,
                "page": page,
                "page_count": page_count,
            }
            _cache_set("list", result, key=list_cache_key)
            return result

        except Exception as e:
            logger.error(f"Error listing assets: {e}", exc_info=True)
            return {"assets": [], "total": 0, "page": page, "page_count": 0}

    def get_asset_detail(self, ip, time_window="24h"):
        try:
            ip = _safe_ip(ip)
            if not ip:
                return None

            # ── 1. Get enrich profile ──────────────────────────────────
            profile = _get_enrich_profile_by_ip(ip)

            # Fallback to preflight seed key if enrich hasn't run yet
            if not profile:
                profile = StateStoreClient.hgetall(f"ndr:asset:{ip}") or {}

            # Fallback to synthetic profile when only baseline summary/top exists
            if not profile:
                has_summary = bool(_get_summary(ip))
                has_top = bool(_get_top(ip))
                if has_summary or has_top:
                    profile = {
                        "ip": ip,
                        "hostname": "",
                        "mac": "",
                        "vendor": "",
                        "os_hint": "",
                        "asset_type": "unknown",
                        "type": "unknown",
                        "first_seen": "",
                        "last_seen": "",
                        "_asset_id": ip,
                    }

            if not profile:
                return None

            asset_id = profile.get("_asset_id") or profile.get("asset_id") or ip

            # ── 2. Merge all data sources ──────────────────────────────
            counters = _get_counters(asset_id, ip=ip)
            summary = _get_summary(ip)
            top = _get_top(ip)
            risk_score = _get_risk_score(asset_id)

            # ── 3. Timestamps ──────────────────────────────────────────
            first_seen_raw = profile.get("first_seen", "")
            last_seen_raw = profile.get("last_seen", "")
            first_seen = _epoch_ms_to_iso(first_seen_raw) if first_seen_raw and str(first_seen_raw).isdigit() else first_seen_raw
            last_seen = _epoch_ms_to_iso(last_seen_raw) if last_seen_raw and str(last_seen_raw).isdigit() else last_seen_raw

            # ── 4. Maturity & checklist ────────────────────────────────
            maturity = _compute_maturity(profile, summary, counters)

            # ── 5. Connection summary ──────────────────────────────────
            conn_in = _safe_int(counters.get("conn_in"))
            conn_out = _safe_int(counters.get("conn_out"))
            total_conn = conn_in + conn_out
            bytes_out = _safe_int(counters.get("bytes_out"))
            bytes_in = _safe_int(counters.get("bytes_in"))
            unique_dst = _safe_int(
                counters.get("unique_dst_count") or summary.get("unique_dst_count")
            )

            inbound_ratio = round(conn_in / total_conn * 100) if total_conn > 0 else 0
            outbound_ratio = 100 - inbound_ratio

            # avg session duration from summary
            conn_out_count = _safe_int(summary.get("conn_out") or counters.get("conn_out"))
            avg_session = "—"

            total_events = _safe_int(
                counters.get("total_events") or summary.get("total_events") or profile.get("total_events")
            )
            connection_summary = {
                "total_events": total_events,
                "avg_session_duration": avg_session,
                "unique_dst_ips": unique_dst,
                "unique_domains": len(json.loads(top.get("top_dns_domains", "[]"))),
                "inbound_ratio": inbound_ratio,
                "outbound_ratio": outbound_ratio,
                "bytes_in": _fmt_bytes(bytes_in),
                "bytes_out": _fmt_bytes(bytes_out),
            }

            # ── 6. Protocol breakdown ──────────────────────────────────
            proto_raw = summary.get("protocol_breakdown", "{}")
            try:
                proto_dict = json.loads(proto_raw)
            except (json.JSONDecodeError, TypeError):
                # Derive from counters if summary not yet available
                dns = _safe_int(counters.get("dns_queries"))
                http = _safe_int(counters.get("http_requests"))
                ssl = _safe_int(counters.get("ssl_connections"))
                ssh = _safe_int(counters.get("ssh_sessions"))
                tot = dns + http + ssl + ssh or 1
                proto_dict = {
                    "dns": round(dns / tot * 100, 1),
                    "http": round(http / tot * 100, 1),
                    "ssl": round(ssl / tot * 100, 1),
                    "ssh": round(ssh / tot * 100, 1),
                }

            protocol_breakdown = [
                {"name": k.upper(), "pct": round(v)}
                for k, v in sorted(proto_dict.items(), key=lambda x: -x[1])
                if v > 0
            ]

            # ── 7. Top domains & top dest IPs ─────────────────────────
            try:
                top_domains = json.loads(top.get("top_dns_domains", "[]"))
            except (json.JSONDecodeError, TypeError):
                top_domains = []

            try:
                top_dst_raw = json.loads(top.get("top_dst_ips", "[]"))
                top_dst_ips = [
                    {"ip": d.get("ip", ""), "label": f"{d.get('count', 0):,} conns"}
                    for d in top_dst_raw
                ]
            except (json.JSONDecodeError, TypeError):
                top_dst_ips = []

            # ── 8. Hourly histogram ────────────────────────────────────
            try:
                hourly_histogram = json.loads(summary.get("hourly_activity") or "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]")
            except (json.JSONDecodeError, TypeError):
                hourly_histogram = [0] * 24


            # ── 9. Network behavior ────────────────────────────────────
            network_behavior = _compute_behavior(counters, summary)

            # ── 10. EPS ───────────────────────────────────────────────
            events_per_sec = 0.0
            if total_events > 0 and first_seen_raw and last_seen_raw:
                fs_dt = _parse_time(first_seen_raw)
                ls_dt = _parse_time(last_seen_raw)
                if fs_dt and ls_dt:
                    duration = (ls_dt - fs_dt).total_seconds()
                    if duration > 0:
                        events_per_sec = round(total_events / duration, 2)

            detections = _detections_for_ip(ip, limit=10)
            alert_count = _alert_counts_for_ips([ip]).get(ip, len(detections))

            return {
                # Identity
                "id": asset_id,
                "ip": ip,
                "hostname": profile.get("hostname", ""),
                "mac": profile.get("mac", ""),
                "asset_type": profile.get("asset_type", "unknown"),
                "vendor": profile.get("vendor", ""),
                "os_hint": profile.get("os_hint", ""),
                "app_fingerprint": profile.get("app_fingerprint", ""),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "status": "active",
                "risk_score": risk_score,
                "events_per_sec": events_per_sec,

                # Maturity panel
                "maturity": maturity,

                # Connection summary panel
                "connection_summary": connection_summary,

                # Protocol breakdown panel
                "protocol_breakdown": protocol_breakdown,
                "top_protocols": protocol_breakdown,

                # Counters (raw, for any client-side calculations)
                "counters": {
                    "total_events": total_events,
                    "conn_in": conn_in,
                    "conn_out": conn_out,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "dns_queries": _safe_int(counters.get("dns_queries")),
                    "http_requests": _safe_int(counters.get("http_requests")),
                    "ssl_connections": _safe_int(counters.get("ssl_connections")),
                    "ssh_sessions": _safe_int(counters.get("ssh_sessions")),
                },

                # Top domains & dest IPs panel
                "top_domains": top_domains,
                "top_dst_ips": top_dst_ips,

                # Hourly sparkline
                "hourly_histogram": hourly_histogram,

                # Network behavior panel
                "network_behavior": network_behavior,

                # Detections (alert_count + detections list)
                "alert_count": alert_count,
                "detections": detections,
            }

        except Exception as e:
            logger.error(f"Error getting asset detail for {ip}: {e}", exc_info=True)
            return None

    def get_asset_analytics(self):
        """
        Fleet-wide analytics for the Asset Analytics page.
        Reads from ndr:network:analytics (ndr-baseline network-summary job)
        and aggregates per-asset maturity / role / coverage from profile+summary keys.
        """
        try:
            cached = _cache_get("analytics", ttl=_ANALYTICS_TTL_SEC)
            if cached is not None:
                return cached

            result = {
                "riskDistribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
                "categories": [],
                "discoveryTimeline": [],
                "segmentRisk": [],
                # Extended analytics fields
                "fleet_kpis": {},
                "top_talkers_outbound": [],
                "top_talkers_lateral": [],
                "protocol_stats": [],
                "unusual": [],
                "segment_matrix": [],
                "maturity_distribution": {"mature": 0, "learning": 0, "sparse": 0},
                "profiling_coverage": {},
                "top_by_eps": [],
                "needs_attention": [],
            }

            # ── 1. Fleet-level analytics from network-summary ──────────
            net = StateStoreClient.hgetall("ndr:network:analytics") or {}
            if net:
                for field in ["kpis", "top_talkers_outbound", "top_talkers_lateral",
                               "protocol_stats", "unusual", "segment_matrix"]:
                    raw = net.get(field)
                    if raw:
                        try:
                            parsed = json.loads(raw)
                            if field == "kpis":
                                result["fleet_kpis"] = parsed
                            else:
                                result[field] = parsed
                        except (json.JSONDecodeError, TypeError):
                            pass

            # ── 2. Per-asset aggregation ───────────────────────────────
            by_ip = _collect_profiles_cached()
            enrich_items = list(by_ip.items())
            risk_map = _bulk_risk_scores([profile.get("_asset_id", ip) for ip, profile in enrich_items])

            type_counts = {}
            maturity_buckets = {"mature": 0, "learning": 0, "sparse": 0}
            total_maturity = 0
            hostname_known = vendor_known = os_known = role_known = 0
            eps_list = []
            maturity_list = []

            for ip, profile in enrich_items:
                asset_id = profile.get("_asset_id", ip)
                # Keep analytics path lightweight; avoid per-IP summary/counters lookups.
                summary = {}
                counters = {}

                # Role
                atype = profile.get("asset_type", "unknown")
                type_counts[atype] = type_counts.get(atype, 0) + 1

                # Risk
                risk = risk_map.get(str(asset_id), 0)
                if risk >= 70:
                    result["riskDistribution"]["critical"] += 1
                elif risk >= 50:
                    result["riskDistribution"]["high"] += 1
                elif risk >= 30:
                    result["riskDistribution"]["medium"] += 1
                else:
                    result["riskDistribution"]["low"] += 1

                # Maturity
                mc = _compute_maturity(profile, summary, counters)
                maturity_score = mc["score"]

                total_maturity += maturity_score
                if maturity_score >= 70:
                    maturity_buckets["mature"] += 1
                elif maturity_score >= 40:
                    maturity_buckets["learning"] += 1
                else:
                    maturity_buckets["sparse"] += 1

                # Coverage
                if profile.get("hostname"):
                    hostname_known += 1
                if profile.get("vendor"):
                    vendor_known += 1
                if profile.get("os_hint"):
                    os_known += 1
                if atype != "unknown":
                    role_known += 1

                # EPS
                eps = 0.0

                eps_list.append({"ip": ip, "hostname": profile.get("hostname", ""), "asset_type": atype, "events_per_sec": eps, "maturity_score": maturity_score})
                maturity_list.append({"ip": ip, "hostname": profile.get("hostname", ""), "vendor": profile.get("vendor", ""), "asset_type": atype, "maturity_score": maturity_score})

            total_assets = len(eps_list)

            result["maturity_distribution"] = maturity_buckets
            result["avg_maturity"] = round(total_maturity / total_assets) if total_assets else 0
            result["categories"] = [
                {"name": k, "count": v}
                for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
            ]
            result["profiling_coverage"] = {
                "hostname_pct": round(hostname_known / total_assets * 100) if total_assets else 0,
                "vendor_pct": round(vendor_known / total_assets * 100) if total_assets else 0,
                "os_pct": round(os_known / total_assets * 100) if total_assets else 0,
                "role_pct": round(role_known / total_assets * 100) if total_assets else 0,
            }
            result["top_by_eps"] = sorted(eps_list, key=lambda a: -a["events_per_sec"])[:10]
            result["needs_attention"] = sorted(maturity_list, key=lambda a: a["maturity_score"])[:10]
            result["total_assets"] = total_assets

            _cache_set("analytics", result)
            return result

        except Exception as e:
            logger.error(f"Error getting asset analytics: {e}", exc_info=True)
            return {
                "riskDistribution": {}, "categories": [],
                "discoveryTimeline": [], "segmentRisk": [],
            }

    def get_config_log(self, ip):
        return []
