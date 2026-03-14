#!/usr/bin/env python3
"""
Seed Redis with sample production data for RaceflowX NDR.
Run: python seed_production_data.py
"""

import redis
import json
import time
import uuid

REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0

def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

def seed_hunts(r):
    """Seed sample hunt definitions."""
    hunts = [
        {
            "id": "HNT-001",
            "name": "C2 Beaconing Detection",
            "hypothesis": "Detect periodic outbound HTTPS traffic patterns matching known C2 profiles.",
            "type": "visual",
            "log_source": "conn",
            "conditions": [{"field": "dst_port", "operator": "==", "value": "443"}],
            "time_range": "Last 24h",
            "status": "completed",
            "created_at": "2026-02-10T14:30:00Z",
            "last_run_at": "2026-02-11T09:15:00Z",
            "duration": 2.4,
            "data_processed": 847,
            "matches_found": 7,
            "confidence": "HIGH",
            "author": "Analyst_J_Miller"
        },
        {
            "id": "HNT-002",
            "name": "Large Data Transfers",
            "hypothesis": "Identify potential exfiltration via high-volume outbound sessions.",
            "type": "sql",
            "log_source": "conn",
            "sql_query": "SELECT src_ip, SUM(orig_bytes) as total_bytes FROM conn WHERE orig_bytes > 0 GROUP BY src_ip HAVING SUM(orig_bytes) > 1000000 ORDER BY total_bytes DESC LIMIT 50",
            "conditions": [{"field": "orig_bytes", "operator": ">", "value": "1000000"}],
            "time_range": "Last 7d",
            "status": "completed",
            "created_at": "2026-02-08T09:12:00Z",
            "last_run_at": "2026-02-10T14:45:00Z",
            "duration": 8.7,
            "data_processed": 2100,
            "matches_found": 3,
            "confidence": "MEDIUM",
            "author": "Analyst_K_Smith"
        },
        {
            "id": "HNT-003",
            "name": "DNS Tunneling Detection",
            "hypothesis": "Detect DNS tunneling by identifying unusually long DNS queries with high entropy.",
            "type": "sql",
            "log_source": "dns",
            "sql_query": "SELECT src_ip, query, LENGTH(query) as query_len FROM dns WHERE LENGTH(query) > 50 ORDER BY query_len DESC LIMIT 50",
            "conditions": [{"field": "query", "operator": "LENGTH >", "value": "50"}],
            "time_range": "Last 24h",
            "status": "completed",
            "created_at": "2026-02-11T11:20:00Z",
            "last_run_at": "2026-02-11T11:22:00Z",
            "duration": 1.2,
            "data_processed": 500,
            "matches_found": 12,
            "confidence": "HIGH",
            "author": "Analyst_L_Chen"
        },
        {
            "id": "HNT-004",
            "name": "Unusual Port Activity",
            "hypothesis": "Find connections to non-standard ports that may indicate backdoor or C2 channels.",
            "type": "visual",
            "log_source": "conn",
            "conditions": [{"field": "dst_port", "operator": ">", "value": "10000"}],
            "time_range": "Last 24h",
            "status": "completed",
            "created_at": "2026-02-09T16:00:00Z",
            "last_run_at": "2026-02-11T08:00:00Z",
            "duration": 3.1,
            "data_processed": 1200,
            "matches_found": 5,
            "confidence": "LOW",
            "author": "Analyst_J_Miller"
        },
        {
            "id": "HNT-005",
            "name": "SSL Certificate Anomalies",
            "hypothesis": "Detect self-signed or expired SSL certificates in outbound traffic.",
            "type": "visual",
            "log_source": "ssl",
            "conditions": [{"field": "validation_status", "operator": "!=", "value": "ok"}],
            "time_range": "Last 7d",
            "status": "completed",
            "created_at": "2026-02-07T10:00:00Z",
            "last_run_at": "2026-02-10T10:00:00Z",
            "duration": 5.5,
            "data_processed": 1800,
            "matches_found": 2,
            "confidence": "MEDIUM",
            "author": "Analyst_K_Smith"
        }
    ]
    
    for hunt in hunts:
        key = f"ndr:hunt:{hunt['id']}"
        r.set(key, json.dumps(hunt))
    
    print(f"  Seeded {len(hunts)} hunts")

def seed_hunt_runs(r):
    """Seed sample hunt run results."""
    runs = [
        {
            "run_id": "RUN-001-1",
            "hunt_id": "HNT-001",
            "status": "completed",
            "started_at": "2026-02-11T09:15:00Z",
            "completed_at": "2026-02-11T09:17:24Z",
            "duration": 2.4,
            "matches_found": 7,
            "query": "SELECT src_ip, dst_ip, dst_port, COUNT(*) as cnt FROM conn WHERE dst_port = 443 GROUP BY src_ip, dst_ip, dst_port HAVING cnt > 10 ORDER BY cnt DESC",
            "results": [
                {"src_ip": "10.128.0.4", "dst_ip": "169.254.169.254", "dst_port": 443, "cnt": 42},
                {"src_ip": "10.128.0.4", "dst_ip": "142.250.80.106", "dst_port": 443, "cnt": 28},
                {"src_ip": "10.128.0.4", "dst_ip": "35.186.238.101", "dst_port": 443, "cnt": 15}
            ]
        },
        {
            "run_id": "RUN-002-1",
            "hunt_id": "HNT-002",
            "status": "completed",
            "started_at": "2026-02-10T14:45:00Z",
            "completed_at": "2026-02-10T14:53:42Z",
            "duration": 8.7,
            "matches_found": 3,
            "query": "SELECT src_ip, SUM(orig_bytes) as total_bytes FROM conn WHERE orig_bytes > 0 GROUP BY src_ip HAVING SUM(orig_bytes) > 1000000 ORDER BY total_bytes DESC LIMIT 50",
            "results": [
                {"src_ip": "10.128.0.4", "total_bytes": 4520000},
                {"src_ip": "10.128.0.5", "total_bytes": 2310000},
                {"src_ip": "10.128.0.12", "total_bytes": 1150000}
            ]
        }
    ]

    for run in runs:
        key = f"ndr:hunt:runs:{run['hunt_id']}:{run['run_id']}"
        r.set(key, json.dumps(run))

    print(f"  Seeded {len(runs)} hunt runs")

def seed_alerts(r):
    """Seed sample detection alerts."""
    alerts = [
        {
            "id": "ALT-001",
            "name": "Suspicious DNS Query Pattern",
            "severity": "high",
            "status": "open",
            "source": "dns",
            "src_ip": "10.128.0.4",
            "dst_ip": "169.254.169.254",
            "timestamp": "2026-02-11T09:28:00Z",
            "description": "Burst of 50+ DNS queries in 5 minutes from single host"
        },
        {
            "id": "ALT-002",
            "name": "Large Outbound Transfer",
            "severity": "medium",
            "status": "investigating",
            "source": "conn",
            "src_ip": "10.128.0.4",
            "dst_ip": "35.186.238.101",
            "timestamp": "2026-02-11T10:15:00Z",
            "description": "4.5MB outbound transfer to external IP"
        },
        {
            "id": "ALT-003",
            "name": "Connection to High Port",
            "severity": "low",
            "status": "open",
            "source": "conn",
            "src_ip": "10.128.0.4",
            "dst_ip": "142.250.80.106",
            "timestamp": "2026-02-11T08:45:00Z",
            "description": "Outbound connection to port 8443"
        }
    ]

    for alert in alerts:
        key = f"ndr:detection:alert:{alert['id']}"
        r.set(key, json.dumps(alert))

    print(f"  Seeded {len(alerts)} alerts")

def seed_dashboard_stats(r):
    """Seed dashboard statistics cache."""
    stats = {
        "total_events": 22000,
        "events_per_second": 450,
        "active_alerts": 3,
        "total_hunts": 5,
        "log_sources": {
            "conn": {"events": 15000, "status": "active"},
            "dns": {"events": 7000, "status": "active"},
            "http": {"events": 0, "status": "no_data"},
            "ssl": {"events": 0, "status": "no_data"},
            "ssh": {"events": 0, "status": "no_data"}
        },
        "top_talkers": [
            {"ip": "10.128.0.4", "connections": 15000, "bytes": 4520000}
        ],
        "updated_at": "2026-02-11T09:30:00Z"
    }
    r.set("ndr:stats:dashboard", json.dumps(stats))
    print("  Seeded dashboard stats")

def seed_log_source_config(r):
    """Seed available log sources config."""
    sources = [
        "conn", "dns", "http", "ssl", "ssh", "ftp", "smtp", "dhcp",
        "rdp", "smb_files", "smb_mapping", "dce_rpc", "kerberos",
        "ntlm", "sip", "snmp", "radius", "tunnel"
    ]
    for s in sources:
        r.sadd("ndr:config:log_sources", s)
    print(f"  Seeded {len(sources)} log source configs")

def main():
    r = get_redis()
    print("Seeding production data to Redis...")
    print()
    
    seed_hunts(r)
    seed_hunt_runs(r)
    seed_alerts(r)
    seed_dashboard_stats(r)
    seed_log_source_config(r)
    
    print()
    print(f"Total Redis keys: {r.dbsize()}")
    print("Production data seeding complete!")

if __name__ == '__main__':
    main()
