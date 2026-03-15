#!/usr/bin/env python3
"""
Demo Mode Bootstrap — creates SQLite demo seed data
for evaluation/demo environments.

Demo Mode provides a fully populated UI experience without requiring
live network traffic. When NDR_MODE=demo:
  - API reads from SQLite
  - Preloaded assets, alerts, signals, risk scores, network flows

Usage:
    python bootstrap_demo.py              # Full bootstrap
    python bootstrap_demo.py --sqlite     # SQLite only
    python bootstrap_demo.py --reset      # Drop and recreate everything
"""

import argparse
import json
import logging
import os
import random
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("demo_bootstrap")

NDR_ROOT = Path(__file__).resolve().parent.parent  # /opt/ndr
DEMO_DIR = Path(__file__).resolve().parent
DEMO_DB_PATH = DEMO_DIR / "demo.sqlite"

# ─── Asset Pool (50 assets) ──────────────────────────────────────

DEMO_ASSETS = [
    # Workstations (15)
    {"asset_id": "AST-001", "ip": "10.0.1.10", "hostname": "ws-analyst-01",   "asset_type": "workstation", "os": "Windows 11",  "department": "SOC"},
    {"asset_id": "AST-002", "ip": "10.0.1.11", "hostname": "ws-analyst-02",   "asset_type": "workstation", "os": "macOS 14",    "department": "SOC"},
    {"asset_id": "AST-003", "ip": "10.0.1.12", "hostname": "ws-analyst-03",   "asset_type": "workstation", "os": "Windows 11",  "department": "SOC"},
    {"asset_id": "AST-004", "ip": "10.0.1.13", "hostname": "ws-analyst-04",   "asset_type": "workstation", "os": "Ubuntu 22",   "department": "SOC"},
    {"asset_id": "AST-005", "ip": "10.0.1.14", "hostname": "ws-analyst-05",   "asset_type": "workstation", "os": "macOS 14",    "department": "SOC"},
    {"asset_id": "AST-006", "ip": "10.0.1.20", "hostname": "ws-dev-01",       "asset_type": "workstation", "os": "Ubuntu 22",   "department": "Engineering"},
    {"asset_id": "AST-007", "ip": "10.0.1.21", "hostname": "ws-dev-02",       "asset_type": "workstation", "os": "macOS 14",    "department": "Engineering"},
    {"asset_id": "AST-008", "ip": "10.0.1.22", "hostname": "ws-dev-03",       "asset_type": "workstation", "os": "Ubuntu 22",   "department": "Engineering"},
    {"asset_id": "AST-009", "ip": "10.0.1.23", "hostname": "ws-dev-04",       "asset_type": "workstation", "os": "Windows 11",  "department": "Engineering"},
    {"asset_id": "AST-010", "ip": "10.0.1.24", "hostname": "ws-dev-05",       "asset_type": "workstation", "os": "macOS 14",    "department": "Engineering"},
    {"asset_id": "AST-011", "ip": "10.0.1.30", "hostname": "ws-exec-01",      "asset_type": "workstation", "os": "macOS 14",    "department": "Executive"},
    {"asset_id": "AST-012", "ip": "10.0.1.31", "hostname": "ws-exec-02",      "asset_type": "workstation", "os": "Windows 11",  "department": "Executive"},
    {"asset_id": "AST-013", "ip": "10.0.1.40", "hostname": "ws-finance-01",   "asset_type": "workstation", "os": "Windows 11",  "department": "Finance"},
    {"asset_id": "AST-014", "ip": "10.0.1.41", "hostname": "ws-finance-02",   "asset_type": "workstation", "os": "Windows 11",  "department": "Finance"},
    {"asset_id": "AST-015", "ip": "10.0.1.50", "hostname": "ws-hr-01",        "asset_type": "workstation", "os": "Windows 11",  "department": "HR"},

    # Servers (12)
    {"asset_id": "AST-016", "ip": "10.0.2.10", "hostname": "srv-web-01",      "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-017", "ip": "10.0.2.11", "hostname": "srv-web-02",      "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-018", "ip": "10.0.2.12", "hostname": "srv-web-03",      "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-019", "ip": "10.0.2.20", "hostname": "srv-db-master",   "asset_type": "server", "os": "CentOS 8",         "department": "IT"},
    {"asset_id": "AST-020", "ip": "10.0.2.21", "hostname": "srv-db-replica",  "asset_type": "server", "os": "CentOS 8",         "department": "IT"},
    {"asset_id": "AST-021", "ip": "10.0.2.22", "hostname": "srv-db-analytics","asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-022", "ip": "10.0.2.30", "hostname": "srv-app-01",      "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-023", "ip": "10.0.2.31", "hostname": "srv-app-02",      "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-024", "ip": "10.0.2.32", "hostname": "srv-app-03",      "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-025", "ip": "10.0.2.40", "hostname": "srv-mail-01",     "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},
    {"asset_id": "AST-026", "ip": "10.0.2.50", "hostname": "srv-file-01",     "asset_type": "server", "os": "Windows Server 2022", "department": "IT"},
    {"asset_id": "AST-027", "ip": "10.0.2.51", "hostname": "srv-backup-01",   "asset_type": "server", "os": "Ubuntu 22",        "department": "IT"},

    # Domain Controllers (3)
    {"asset_id": "AST-028", "ip": "10.0.2.60", "hostname": "dc-primary",      "asset_type": "domain_controller", "os": "Windows Server 2022", "department": "IT"},
    {"asset_id": "AST-029", "ip": "10.0.2.61", "hostname": "dc-backup",       "asset_type": "domain_controller", "os": "Windows Server 2022", "department": "IT"},
    {"asset_id": "AST-030", "ip": "10.0.2.62", "hostname": "dc-readonly",     "asset_type": "domain_controller", "os": "Windows Server 2022", "department": "IT"},

    # Network Devices (5)
    {"asset_id": "AST-031", "ip": "10.0.3.1",  "hostname": "fw-perimeter",    "asset_type": "network_device", "os": "pfSense",     "department": "Network"},
    {"asset_id": "AST-032", "ip": "10.0.3.2",  "hostname": "sw-core-01",      "asset_type": "network_device", "os": "Cisco IOS",   "department": "Network"},
    {"asset_id": "AST-033", "ip": "10.0.3.3",  "hostname": "sw-core-02",      "asset_type": "network_device", "os": "Cisco IOS",   "department": "Network"},
    {"asset_id": "AST-034", "ip": "10.0.3.4",  "hostname": "ap-floor-01",     "asset_type": "network_device", "os": "UniFi",       "department": "Network"},
    {"asset_id": "AST-035", "ip": "10.0.3.5",  "hostname": "vpn-gateway",     "asset_type": "network_device", "os": "OpenVPN",     "department": "Network"},

    # IoT (8)
    {"asset_id": "AST-036", "ip": "10.0.4.10", "hostname": "cam-lobby-01",    "asset_type": "iot", "os": "Embedded",     "department": "Facilities"},
    {"asset_id": "AST-037", "ip": "10.0.4.11", "hostname": "cam-parking-01",  "asset_type": "iot", "os": "Embedded",     "department": "Facilities"},
    {"asset_id": "AST-038", "ip": "10.0.4.12", "hostname": "cam-server-room", "asset_type": "iot", "os": "Embedded",     "department": "Facilities"},
    {"asset_id": "AST-039", "ip": "10.0.4.20", "hostname": "thermostat-01",   "asset_type": "iot", "os": "RTOS",         "department": "Facilities"},
    {"asset_id": "AST-040", "ip": "10.0.4.21", "hostname": "thermostat-02",   "asset_type": "iot", "os": "RTOS",         "department": "Facilities"},
    {"asset_id": "AST-041", "ip": "10.0.4.30", "hostname": "printer-01",      "asset_type": "iot", "os": "Embedded",     "department": "IT"},
    {"asset_id": "AST-042", "ip": "10.0.4.31", "hostname": "printer-02",      "asset_type": "iot", "os": "Embedded",     "department": "IT"},
    {"asset_id": "AST-043", "ip": "10.0.4.40", "hostname": "badge-reader-01", "asset_type": "iot", "os": "Embedded",     "department": "Facilities"},

    # Docker/Containers (5)
    {"asset_id": "AST-044", "ip": "172.17.0.10", "hostname": "container-nginx",  "asset_type": "docker", "os": "Alpine",  "department": "Engineering"},
    {"asset_id": "AST-045", "ip": "172.17.0.11", "hostname": "container-cache",  "asset_type": "docker", "os": "Alpine",  "department": "Engineering"},
    {"asset_id": "AST-046", "ip": "172.17.0.12", "hostname": "container-api",    "asset_type": "docker", "os": "Debian",  "department": "Engineering"},
    {"asset_id": "AST-047", "ip": "172.17.0.13", "hostname": "container-worker", "asset_type": "docker", "os": "Alpine",  "department": "Engineering"},
    {"asset_id": "AST-048", "ip": "172.17.0.14", "hostname": "container-monitor","asset_type": "docker", "os": "Alpine",  "department": "Engineering"},

    # Virtual Machines (2)
    {"asset_id": "AST-049", "ip": "10.0.5.10", "hostname": "vm-sandbox-01",   "asset_type": "virtual_machine", "os": "Ubuntu 22",   "department": "SOC"},
    {"asset_id": "AST-050", "ip": "10.0.5.11", "hostname": "vm-honeypot-01",  "asset_type": "virtual_machine", "os": "Windows 10",  "department": "SOC"},
]

# ─── Alerts (30 alerts across severities) ────────────────────────

DEMO_ALERTS = [
    # Critical (5)
    {"alert_id": "INC-001", "alert_type": "use_case",      "name": "Ransomware Pre-Encryption Recon",        "use_case_id": "UC-01", "asset_id": "AST-019", "severity": "critical", "confidence": 0.94, "category": "ransomware",        "risk_score": 92, "status": "new",           "signals_count": 4},
    {"alert_id": "INC-002", "alert_type": "risk_incident",  "name": "Entity Risk Threshold Crossed",          "use_case_id": "",      "asset_id": "AST-019", "severity": "critical", "confidence": 0.97, "category": "multi_stage",       "risk_score": 95, "status": "new",           "signals_count": 6},
    {"alert_id": "INC-003", "alert_type": "use_case",      "name": "C2 Beaconing with Data Exfiltration",    "use_case_id": "UC-25", "asset_id": "AST-008", "severity": "critical", "confidence": 0.88, "category": "c2",                "risk_score": 85, "status": "triaged",       "signals_count": 3},
    {"alert_id": "INC-004", "alert_type": "use_case",      "name": "Full Kill Chain Detected",               "use_case_id": "UC-30", "asset_id": "AST-006", "severity": "critical", "confidence": 0.91, "category": "advanced_threat",   "risk_score": 90, "status": "new",           "signals_count": 5},
    {"alert_id": "INC-005", "alert_type": "use_case",      "name": "Large Volume Data Exfiltration",         "use_case_id": "UC-07", "asset_id": "AST-013", "severity": "critical", "confidence": 0.86, "category": "exfiltration",      "risk_score": 82, "status": "new",           "signals_count": 3},

    # High (10)
    {"alert_id": "INC-006", "alert_type": "use_case",      "name": "Brute Force Compromise",                 "use_case_id": "UC-19", "asset_id": "AST-016", "severity": "high", "confidence": 0.85, "category": "credential_abuse",   "risk_score": 72, "status": "triaged",       "signals_count": 2},
    {"alert_id": "INC-007", "alert_type": "use_case",      "name": "Lateral Movement Chain",                 "use_case_id": "UC-13", "asset_id": "AST-006", "severity": "high", "confidence": 0.79, "category": "lateral_movement",   "risk_score": 68, "status": "new",           "signals_count": 3},
    {"alert_id": "INC-008", "alert_type": "signal",        "name": "DNS Tunneling Detected",                 "signal_id": "SIG-032", "asset_id": "AST-008", "severity": "high", "confidence": 0.72, "category": "exfiltration",       "risk_score": 55, "status": "new",           "signals_count": 1},
    {"alert_id": "INC-009", "alert_type": "use_case",      "name": "Gradual Data Exfiltration",              "use_case_id": "UC-08", "asset_id": "AST-011", "severity": "high", "confidence": 0.68, "category": "exfiltration",       "risk_score": 60, "status": "new",           "signals_count": 2},
    {"alert_id": "INC-010", "alert_type": "signal",        "name": "SMB File Access Spike",                  "signal_id": "SIG-011", "asset_id": "AST-019", "severity": "high", "confidence": 0.75, "category": "ransomware",         "risk_score": 58, "status": "triaged",       "signals_count": 1},
    {"alert_id": "INC-011", "alert_type": "use_case",      "name": "Off-Hours Exfiltration",                 "use_case_id": "UC-10", "asset_id": "AST-013", "severity": "high", "confidence": 0.71, "category": "insider_threat",     "risk_score": 62, "status": "new",           "signals_count": 2},
    {"alert_id": "INC-012", "alert_type": "signal",        "name": "Periodic Beacon Timing",                 "signal_id": "SIG-051", "asset_id": "AST-044", "severity": "high", "confidence": 0.77, "category": "c2",                 "risk_score": 65, "status": "new",           "signals_count": 1},
    {"alert_id": "INC-013", "alert_type": "use_case",      "name": "TLS-Based Exfiltration",                 "use_case_id": "UC-09", "asset_id": "AST-007", "severity": "high", "confidence": 0.74, "category": "exfiltration",       "risk_score": 58, "status": "new",           "signals_count": 2},
    {"alert_id": "INC-014", "alert_type": "signal",        "name": "Auth to Many Hosts",                     "signal_id": "SIG-045", "asset_id": "AST-006", "severity": "high", "confidence": 0.80, "category": "lateral_movement",   "risk_score": 55, "status": "triaged",       "signals_count": 1},
    {"alert_id": "INC-015", "alert_type": "use_case",      "name": "Credential Stuffing Attack",             "use_case_id": "UC-18", "asset_id": "AST-028", "severity": "high", "confidence": 0.82, "category": "credential_abuse",   "risk_score": 70, "status": "new",           "signals_count": 2},

    # Medium (10)
    {"alert_id": "INC-016", "alert_type": "signal",        "name": "Port Protocol Sweep",                   "signal_id": "SIG-004", "asset_id": "AST-006", "severity": "medium", "confidence": 0.65, "category": "reconnaissance",   "risk_score": 35, "status": "resolved",      "signals_count": 1},
    {"alert_id": "INC-017", "alert_type": "signal",        "name": "DNS Query Burst",                       "signal_id": "SIG-030", "asset_id": "AST-008", "severity": "medium", "confidence": 0.58, "category": "exfiltration",     "risk_score": 30, "status": "new",           "signals_count": 1},
    {"alert_id": "INC-018", "alert_type": "signal",        "name": "Off-Hours Privileged Login",             "signal_id": "SIG-035", "asset_id": "AST-028", "severity": "medium", "confidence": 0.62, "category": "insider_threat",   "risk_score": 32, "status": "resolved",      "signals_count": 1},
    {"alert_id": "INC-019", "alert_type": "signal",        "name": "Self-Signed Certificate Detected",      "signal_id": "SIG-101", "asset_id": "AST-044", "severity": "medium", "confidence": 0.70, "category": "tls_anomaly",      "risk_score": 28, "status": "false_positive", "signals_count": 1},
    {"alert_id": "INC-020", "alert_type": "signal",        "name": "First Seen Device",                     "signal_id": "SIG-059", "asset_id": "AST-043", "severity": "medium", "confidence": 0.55, "category": "visibility",       "risk_score": 20, "status": "resolved",      "signals_count": 1},
    {"alert_id": "INC-021", "alert_type": "signal",        "name": "Policy Violation Event",                "signal_id": "SIG-042", "asset_id": "AST-015", "severity": "medium", "confidence": 0.60, "category": "insider_threat",   "risk_score": 25, "status": "new",           "signals_count": 1},
    {"alert_id": "INC-022", "alert_type": "signal",        "name": "Data Staging Behavior",                 "signal_id": "SIG-022", "asset_id": "AST-013", "severity": "medium", "confidence": 0.58, "category": "exfiltration",     "risk_score": 30, "status": "new",           "signals_count": 1},
    {"alert_id": "INC-023", "alert_type": "signal",        "name": "Expired Certificate Detected",          "signal_id": "SIG-102", "asset_id": "AST-016", "severity": "medium", "confidence": 0.68, "category": "tls_anomaly",      "risk_score": 22, "status": "resolved",      "signals_count": 1},
    {"alert_id": "INC-024", "alert_type": "signal",        "name": "Service Fingerprinting",                "signal_id": "SIG-044", "asset_id": "AST-049", "severity": "medium", "confidence": 0.55, "category": "reconnaissance",   "risk_score": 18, "status": "false_positive", "signals_count": 1},
    {"alert_id": "INC-025", "alert_type": "signal",        "name": "Off-Hours Activity",                    "signal_id": "SIG-026", "asset_id": "AST-011", "severity": "medium", "confidence": 0.52, "category": "insider_threat",   "risk_score": 28, "status": "new",           "signals_count": 1},

    # Low (5)
    {"alert_id": "INC-026", "alert_type": "signal",        "name": "Zeek Traceroute Detection",             "signal_id": "SIG-173", "asset_id": "AST-049", "severity": "low", "confidence": 0.40, "category": "reconnaissance",     "risk_score": 10, "status": "resolved",      "signals_count": 1},
    {"alert_id": "INC-027", "alert_type": "signal",        "name": "Zeek Software Version Change",          "signal_id": "SIG-174", "asset_id": "AST-032", "severity": "low", "confidence": 0.35, "category": "visibility",         "risk_score": 8,  "status": "resolved",      "signals_count": 1},
    {"alert_id": "INC-028", "alert_type": "signal",        "name": "First Seen External Service",           "signal_id": "SIG-060", "asset_id": "AST-007", "severity": "low", "confidence": 0.42, "category": "visibility",         "risk_score": 12, "status": "resolved",      "signals_count": 1},
    {"alert_id": "INC-029", "alert_type": "signal",        "name": "FTP Anonymous Login",                   "signal_id": "SIG-191", "asset_id": "AST-050", "severity": "low", "confidence": 0.50, "category": "credential_abuse",   "risk_score": 15, "status": "false_positive", "signals_count": 1},
    {"alert_id": "INC-030", "alert_type": "signal",        "name": "Weak Cipher Suite Used",                "signal_id": "SIG-103", "asset_id": "AST-041", "severity": "low", "confidence": 0.45, "category": "tls_anomaly",        "risk_score": 10, "status": "resolved",      "signals_count": 1},
]

# ─── Processed Signals (200 detection events) ───────────────────

SIGNAL_POOL = [
    ("SIG-004", "medium", "reconnaissance", 15),
    ("SIG-005", "high", "lateral_movement", 25),
    ("SIG-006", "critical", "reconnaissance", 35),
    ("SIG-001", "high", "credential_abuse", 30),
    ("SIG-045", "critical", "lateral_movement", 35),
    ("SIG-043", "high", "reconnaissance", 25),
    ("SIG-050", "critical", "credential_abuse", 40),
    ("SIG-059", "high", "visibility", 15),
    ("SIG-101", "high", "tls_anomaly", 20),
    ("SIG-181", "high", "credential_abuse", 30),
    ("SIG-020", "critical", "exfiltration", 35),
    ("SIG-021", "critical", "exfiltration", 35),
    ("SIG-024", "critical", "exfiltration", 35),
    ("SIG-030", "medium", "exfiltration", 20),
    ("SIG-031", "critical", "exfiltration", 35),
    ("SIG-032", "critical", "exfiltration", 40),
    ("SIG-026", "high", "insider_threat", 20),
    ("SIG-042", "critical", "insider_threat", 30),
    ("SIG-008", "critical", "lateral_movement", 35),
    ("SIG-011", "high", "ransomware", 30),
    ("SIG-012", "critical", "ransomware", 40),
    ("SIG-007", "critical", "ransomware", 40),
    ("SIG-046", "critical", "lateral_movement", 35),
    ("SIG-035", "high", "insider_threat", 25),
    ("SIG-051", "high", "c2", 30),
    ("SIG-027", "high", "exfiltration", 25),
    ("SIG-054", "critical", "c2", 35),
    ("SIG-111", "critical", "web_attack", 40),
    ("SIG-061", "critical", "threat_intel", 40),
    ("SIG-131", "critical", "credential_abuse", 35),
]


# ─── Network Flows (for topology view) ──────────────────────────

def generate_network_flows() -> list:
    """Generate 500+ network flow records for topology view."""
    flows = []
    # Internal asset IPs
    internal_ips = [a["ip"] for a in DEMO_ASSETS]
    external_ips = [
        "203.0.113.10", "203.0.113.25", "198.51.100.1", "198.51.100.22",
        "185.199.108.153", "151.101.1.140", "93.184.216.34", "13.107.42.14",
        "104.16.132.229", "172.217.14.206", "31.13.65.36", "52.85.132.97",
    ]
    protocols = [("TCP", 443), ("TCP", 80), ("TCP", 22), ("TCP", 445),
                 ("UDP", 53), ("TCP", 3389), ("TCP", 8080), ("TCP", 25)]

    now = datetime.now(timezone.utc)

    for i in range(550):
        src = random.choice(internal_ips)
        if random.random() < 0.6:  # internal
            dst = random.choice([ip for ip in internal_ips if ip != src])
            direction = "internal"
        else:  # outbound
            dst = random.choice(external_ips)
            direction = "outbound"

        proto, port = random.choice(protocols)
        ts = (now - timedelta(hours=random.randint(0, 72))).isoformat()

        flows.append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "protocol": proto,
            "direction": direction,
            "bytes_sent": random.randint(100, 5000000),
            "bytes_recv": random.randint(100, 5000000),
            "packets": random.randint(5, 10000),
            "duration": round(random.uniform(0.1, 3600.0), 2),
            "timestamp": ts,
        })

    return flows


# ─── SQLite Bootstrap ────────────────────────────────────────────

def bootstrap_sqlite(db_path: Path, reset: bool = False):
    """Create and populate SQLite demo database."""
    logger.info(f"Bootstrapping SQLite at: {db_path}")
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if reset and db_path.exists():
        db_path.unlink()
        logger.info("  Deleted existing database")

    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()

    # ── Tables ──
    c.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT UNIQUE NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            asset_type TEXT,
            os TEXT,
            department TEXT,
            risk_score REAL DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE NOT NULL,
            alert_type TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            signal_id TEXT,
            use_case_id TEXT,
            asset_id TEXT NOT NULL,
            asset_type TEXT,
            severity TEXT NOT NULL DEFAULT 'medium',
            confidence REAL DEFAULT 0.5,
            category TEXT,
            risk_score REAL DEFAULT 0,
            status TEXT DEFAULT 'new',
            verdict TEXT DEFAULT 'pending',
            mitre_tactic TEXT,
            signals_count INTEGER DEFAULT 1,
            ftx_ids TEXT,
            timestamp TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS processed_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signal_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            severity TEXT,
            scored_points INTEGER DEFAULT 0,
            category TEXT,
            timestamp TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS entity_risk_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id TEXT NOT NULL,
            entity_type TEXT DEFAULT 'asset',
            signal_id TEXT NOT NULL,
            points INTEGER DEFAULT 0,
            running_total INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS network_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            protocol TEXT,
            direction TEXT,
            bytes_sent INTEGER DEFAULT 0,
            bytes_recv INTEGER DEFAULT 0,
            packets INTEGER DEFAULT 0,
            duration REAL DEFAULT 0,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()

    now = datetime.now(timezone.utc)

    # ── Insert assets (50) ──
    for asset in DEMO_ASSETS:
        risk = random.randint(5, 85)
        first_seen = (now - timedelta(days=random.randint(14, 90))).isoformat()
        last_seen = (now - timedelta(minutes=random.randint(5, 120))).isoformat()
        try:
            c.execute(
                """INSERT OR REPLACE INTO assets
                   (asset_id, ip, hostname, asset_type, os, department, risk_score, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (asset["asset_id"], asset["ip"], asset["hostname"],
                 asset["asset_type"], asset["os"], asset["department"],
                 risk, first_seen, last_seen)
            )
        except sqlite3.IntegrityError:
            pass

    # ── Insert alerts (30) ──
    for alert in DEMO_ALERTS:
        ts = (now - timedelta(hours=random.randint(1, 72))).isoformat()
        asset = next((a for a in DEMO_ASSETS if a["asset_id"] == alert["asset_id"]), {})
        try:
            c.execute(
                """INSERT OR REPLACE INTO alerts
                   (alert_id, alert_type, name, signal_id, use_case_id, asset_id, asset_type,
                    severity, confidence, category, risk_score, status, signals_count, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert["alert_id"], alert["alert_type"], alert["name"],
                 alert.get("signal_id", ""), alert.get("use_case_id", ""),
                 alert["asset_id"], asset.get("asset_type", "unknown"),
                 alert["severity"], alert["confidence"], alert["category"],
                 alert["risk_score"], alert["status"], alert["signals_count"], ts)
            )
        except sqlite3.IntegrityError:
            pass

    # ── Insert signals (200 detection events) ──
    asset_ids = [a["asset_id"] for a in DEMO_ASSETS]
    for i in range(200):
        sig_id, severity, category, points = random.choice(SIGNAL_POOL)
        asset_id = random.choice(asset_ids)
        ts = (now - timedelta(hours=random.randint(0, 72))).isoformat()
        c.execute(
            """INSERT INTO processed_signals
               (signal_id, asset_id, severity, scored_points, category, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (sig_id, asset_id, severity, points, category, ts)
        )

    # ── Insert entity risk ledger ──
    running_totals = {}
    for i in range(150):
        asset_id = random.choice(asset_ids)
        sig_id, _, _, points = random.choice(SIGNAL_POOL)
        running_totals[asset_id] = running_totals.get(asset_id, 0) + points
        ts = (now - timedelta(hours=random.randint(0, 72))).isoformat()
        c.execute(
            """INSERT INTO entity_risk_ledger
               (entity_id, entity_type, signal_id, points, running_total, timestamp)
               VALUES (?, 'asset', ?, ?, ?, ?)""",
            (asset_id, sig_id, points, running_totals[asset_id], ts)
        )

    # ── Insert network flows (550) ──
    flows = generate_network_flows()
    for flow in flows:
        c.execute(
            """INSERT INTO network_flows
               (src_ip, dst_ip, dst_port, protocol, direction,
                bytes_sent, bytes_recv, packets, duration, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (flow["src_ip"], flow["dst_ip"], flow["dst_port"], flow["protocol"],
             flow["direction"], flow["bytes_sent"], flow["bytes_recv"],
             flow["packets"], flow["duration"], flow["timestamp"])
        )

    conn.commit()

    # Verify counts
    counts = {}
    for table in ["assets", "alerts", "processed_signals", "entity_risk_ledger", "network_flows"]:
        c.execute(f"SELECT COUNT(*) FROM {table}")
        counts[table] = c.fetchone()[0]

    conn.close()

    for table, count in counts.items():
        logger.info(f"  {table}: {count}")

    logger.info(f"  SQLite bootstrap complete: {db_path}")
    return counts


# ─── Main ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Bootstrap Demo Mode")
    parser.add_argument("--sqlite", action="store_true", help="Bootstrap SQLite only")
    parser.add_argument("--reset", action="store_true", help="Drop and recreate everything")
    parser.add_argument("--db-path", type=str, default=str(DEMO_DB_PATH), help="SQLite database path")

    args = parser.parse_args()
    do_both = not args.sqlite

    if do_both or args.sqlite:
        bootstrap_sqlite(Path(args.db_path), reset=args.reset)

    logger.info("\n✅ Demo Mode bootstrap complete!")
    logger.info(f"   Set NDR_MODE=demo to enable")
    logger.info(f"   50 assets | 30 alerts | 200 signals | 550 flows")


if __name__ == "__main__":
    main()
