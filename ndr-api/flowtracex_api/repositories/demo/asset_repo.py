import math
import random
from datetime import datetime, timedelta
from ..base.asset_repo import AssetRepository
from apps.assets.models import Asset
from apps.assets.serializers import AssetSerializer
from django.core.paginator import Paginator


# ── Rich mock profiling data keyed by IP ────────────────────────────────────

PROFILES = {
    "10.0.5.42": {
        "vendor": "Dell Inc.", "os_hint": "Windows 11 23H2", "asset_type": "workstation",
        "app_fingerprint": "Chrome 120", "role_confidence": "high",
        "maturity_score": 82,
        "counters": {"dns_queries": 1420, "http_requests": 680, "ssl_connections": 910, "ssh_sessions": 0, "total_events": 3010},
        "top_protocols": [
            {"name": "DNS", "pct": 47}, {"name": "SSL", "pct": 30}, {"name": "HTTP", "pct": 23}
        ],
        "top_domains": [
            {"domain": "google.com", "count": 210}, {"domain": "office365.com", "count": 185},
            {"domain": "github.com", "count": 98}, {"domain": "slack.com", "count": 72},
            {"domain": "amazonaws.com", "count": 45}
        ],
        "top_dst_ips": [
            {"ip": "142.250.80.46", "count": 180, "label": "Google"}, {"ip": "52.96.165.130", "count": 160, "label": "Microsoft 365"},
            {"ip": "185.199.108.153", "count": 95, "label": "GitHub"}
        ],
        "hourly_histogram": [0,0,0,0,0,1,3,12,45,62,58,55,48,60,52,45,38,22,8,3,1,0,0,0],
        "events_per_sec": 3.2, "first_seen": "2026-02-16T13:04:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log", "when": "2h ago"},
            "hostname": {"known": True, "source": "kerberos.log", "when": "1h 45m ago"},
            "mac": {"known": False, "source": None, "needs": "DHCP traffic"},
            "vendor": {"known": True, "source": "OUI lookup", "when": "1h 45m ago"},
            "os_hint": {"known": True, "source": "http.log User-Agent", "when": "1h ago"},
            "app_fingerprint": {"known": True, "source": "ssl.log JA3", "when": "45m ago"},
            "role": {"known": True, "source": "traffic pattern", "when": "30m ago"},
            "dns_behavior": {"known": True, "source": "dns.log", "when": "ongoing"},
            "user_identity": {"known": False, "source": None, "needs": "NTLM/Kerberos with username"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "DHCP options"}
        },
        "alert_count": 2
    },
    "10.0.3.15": {
        "vendor": "VMware Inc.", "os_hint": "Windows Server 2022", "asset_type": "server",
        "app_fingerprint": None, "role_confidence": "high",
        "maturity_score": 91,
        "counters": {"dns_queries": 2860, "http_requests": 120, "ssl_connections": 340, "ssh_sessions": 45, "smb_sessions": 4200, "ldap_binds": 1580, "total_events": 9145},
        "top_protocols": [
            {"name": "SMB", "pct": 46}, {"name": "DNS", "pct": 31}, {"name": "LDAP", "pct": 17}
        ],
        "top_domains": [
            {"domain": "corp.local", "count": 1800}, {"domain": "windowsupdate.com", "count": 420},
            {"domain": "digicert.com", "count": 85}
        ],
        "top_dst_ips": [
            {"ip": "10.0.3.16", "count": 2400, "label": "DC-02 (replication)"}, {"ip": "10.0.1.10", "count": 890, "label": "DB-PROD-SQL"}
        ],
        "hourly_histogram": [22,18,15,12,14,20,35,55,78,82,80,75,72,80,76,70,65,55,42,38,35,30,28,25],
        "events_per_sec": 12.4, "first_seen": "2026-02-10T08:00:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "kerberos.log"},
            "mac": {"known": True, "source": "dhcp.log"},
            "vendor": {"known": True, "source": "OUI lookup"},
            "os_hint": {"known": True, "source": "kerberos.log"},
            "app_fingerprint": {"known": False, "source": None, "needs": "No browser traffic"},
            "role": {"known": True, "source": "SMB/LDAP pattern → domain_controller"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": True, "source": "kerberos.log → SYSTEM$"},
            "dhcp_fingerprint": {"known": True, "source": "dhcp.log"}
        },
        "alert_count": 1
    },
    "10.0.1.10": {
        "vendor": "Supermicro", "os_hint": "Linux (Ubuntu 22.04)", "asset_type": "database",
        "app_fingerprint": None, "role_confidence": "high",
        "maturity_score": 75,
        "counters": {"dns_queries": 120, "http_requests": 0, "ssl_connections": 890, "ssh_sessions": 12, "total_events": 1022},
        "top_protocols": [
            {"name": "SSL", "pct": 87}, {"name": "DNS", "pct": 12}, {"name": "SSH", "pct": 1}
        ],
        "top_domains": [
            {"domain": "ntp.ubuntu.com", "count": 40}, {"domain": "security.ubuntu.com", "count": 25}
        ],
        "top_dst_ips": [
            {"ip": "10.0.3.15", "count": 650, "label": "SRV-DC-01"}, {"ip": "10.0.5.42", "count": 220, "label": "WS-ENG-042"}
        ],
        "hourly_histogram": [5,5,4,4,5,6,8,15,32,38,35,30,28,35,32,28,22,15,10,8,7,6,5,5],
        "events_per_sec": 1.8, "first_seen": "2026-02-12T10:30:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "dns.log PTR"},
            "mac": {"known": True, "source": "dhcp.log"},
            "vendor": {"known": True, "source": "OUI lookup"},
            "os_hint": {"known": True, "source": "ssh.log banner"},
            "app_fingerprint": {"known": False, "source": None, "needs": "No browser/JA3"},
            "role": {"known": True, "source": "port 5432 → database"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": False, "source": None, "needs": "No auth traffic"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "Static IP"}
        },
        "alert_count": 0
    },
    "10.0.2.88": {
        "vendor": "Lenovo", "os_hint": "Windows 11", "asset_type": "workstation",
        "app_fingerprint": "Firefox 122", "role_confidence": "medium",
        "maturity_score": 68,
        "counters": {"dns_queries": 920, "http_requests": 410, "ssl_connections": 1200, "ssh_sessions": 0, "total_events": 2530},
        "top_protocols": [
            {"name": "SSL", "pct": 47}, {"name": "DNS", "pct": 36}, {"name": "HTTP", "pct": 16}
        ],
        "top_domains": [
            {"domain": "finance-app.corp.local", "count": 380}, {"domain": "bloomberg.com", "count": 210},
            {"domain": "reuters.com", "count": 95}, {"domain": "outlook.office365.com", "count": 180}
        ],
        "top_dst_ips": [
            {"ip": "10.0.1.50", "count": 320, "label": "DB-ANALYTICS"}, {"ip": "185.28.20.1", "count": 180, "label": "Bloomberg"}
        ],
        "hourly_histogram": [0,0,0,0,0,0,2,8,35,52,48,42,10,45,50,42,35,18,5,1,0,0,0,0],
        "events_per_sec": 2.1, "first_seen": "2026-02-14T09:15:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "kerberos.log"},
            "mac": {"known": False, "source": None, "needs": "DHCP"},
            "vendor": {"known": True, "source": "OUI lookup"},
            "os_hint": {"known": True, "source": "User-Agent"},
            "app_fingerprint": {"known": True, "source": "ssl.log JA3"},
            "role": {"known": True, "source": "traffic pattern"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": False, "source": None, "needs": "NTLM/Kerberos"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "DHCP"}
        },
        "alert_count": 1
    },
    "10.0.4.5": {
        "vendor": "Fortinet", "os_hint": "FortiOS 7.4", "asset_type": "network_device",
        "app_fingerprint": None, "role_confidence": "high",
        "maturity_score": 45,
        "counters": {"dns_queries": 0, "http_requests": 0, "ssl_connections": 12, "ssh_sessions": 3, "syslog": 8200, "total_events": 8215},
        "top_protocols": [
            {"name": "Syslog", "pct": 99}, {"name": "SSH", "pct": 1}
        ],
        "top_domains": [],
        "top_dst_ips": [
            {"ip": "10.0.3.15", "count": 4100, "label": "SRV-DC-01 (syslog)"}
        ],
        "hourly_histogram": [30,30,28,25,28,30,35,40,45,48,50,48,45,48,50,45,42,38,35,32,30,30,30,30],
        "events_per_sec": 8.5, "first_seen": "2026-02-08T00:00:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "dns.log PTR"},
            "mac": {"known": True, "source": "arp.log"},
            "vendor": {"known": True, "source": "OUI → Fortinet"},
            "os_hint": {"known": True, "source": "ssh.log banner"},
            "app_fingerprint": {"known": False, "source": None, "needs": "No browser traffic"},
            "role": {"known": True, "source": "vendor → network_device"},
            "dns_behavior": {"known": False, "source": None, "needs": "No DNS queries"},
            "user_identity": {"known": False, "source": None, "needs": "No auth"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "Static IP"}
        },
        "alert_count": 0
    },
    "10.0.6.201": {
        "vendor": "Unknown", "os_hint": "Ubuntu 22.04 LTS", "asset_type": "server",
        "app_fingerprint": None, "role_confidence": "medium",
        "maturity_score": 58,
        "counters": {"dns_queries": 340, "http_requests": 4200, "ssl_connections": 3800, "ssh_sessions": 28, "total_events": 8368},
        "top_protocols": [
            {"name": "HTTP", "pct": 50}, {"name": "SSL", "pct": 45}, {"name": "DNS", "pct": 4}
        ],
        "top_domains": [
            {"domain": "letsencrypt.org", "count": 12}, {"domain": "security.ubuntu.com", "count": 8}
        ],
        "top_dst_ips": [],
        "hourly_histogram": [15,12,10,8,10,12,18,35,65,72,68,60,55,68,70,62,55,40,30,25,20,18,16,15],
        "events_per_sec": 5.6, "first_seen": "2026-02-11T14:20:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "dns.log PTR"},
            "mac": {"known": False, "source": None, "needs": "DHCP / ARP"},
            "vendor": {"known": False, "source": None, "needs": "OUI lookup (MAC missing)"},
            "os_hint": {"known": True, "source": "ssh.log banner"},
            "app_fingerprint": {"known": False, "source": None, "needs": "No outbound browser"},
            "role": {"known": True, "source": "port 80/443 → web_server"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": False, "source": None, "needs": "No auth"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "Static IP likely"}
        },
        "alert_count": 1
    },
    "10.0.3.22": {
        "vendor": "HPE", "os_hint": "Windows Server 2019", "asset_type": "server",
        "app_fingerprint": None, "role_confidence": "high",
        "maturity_score": 88,
        "counters": {"dns_queries": 1800, "http_requests": 320, "ssl_connections": 2100, "ssh_sessions": 0, "smtp": 4500, "total_events": 8720},
        "top_protocols": [
            {"name": "SMTP", "pct": 52}, {"name": "SSL", "pct": 24}, {"name": "DNS", "pct": 21}
        ],
        "top_domains": [
            {"domain": "corp.local", "count": 900}, {"domain": "protection.outlook.com", "count": 380},
            {"domain": "spamhaus.org", "count": 120}
        ],
        "top_dst_ips": [
            {"ip": "10.0.3.15", "count": 1200, "label": "SRV-DC-01"}, {"ip": "52.96.165.130", "count": 380, "label": "Microsoft 365"}
        ],
        "hourly_histogram": [20,18,15,12,14,18,25,42,65,72,68,62,58,65,68,60,52,40,32,28,25,22,20,20],
        "events_per_sec": 7.2, "first_seen": "2026-02-09T06:00:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "kerberos.log"},
            "mac": {"known": True, "source": "dhcp.log"},
            "vendor": {"known": True, "source": "OUI lookup"},
            "os_hint": {"known": True, "source": "kerberos.log"},
            "app_fingerprint": {"known": False, "source": None, "needs": "No browser traffic"},
            "role": {"known": True, "source": "port 25/587 → mail_server"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": True, "source": "kerberos.log → EXCHANGE$"},
            "dhcp_fingerprint": {"known": True, "source": "dhcp.log"}
        },
        "alert_count": 3
    },
    "10.0.7.100": {
        "vendor": "Hikvision", "os_hint": "Linux (Embedded)", "asset_type": "iot",
        "app_fingerprint": None, "role_confidence": "high",
        "maturity_score": 32,
        "counters": {"dns_queries": 45, "http_requests": 12, "ssl_connections": 8, "ssh_sessions": 0, "total_events": 65},
        "top_protocols": [
            {"name": "DNS", "pct": 69}, {"name": "HTTP", "pct": 18}, {"name": "SSL", "pct": 12}
        ],
        "top_domains": [
            {"domain": "hikvision-cloud.com", "count": 30}
        ],
        "top_dst_ips": [
            {"ip": "47.91.170.22", "count": 25, "label": "Hikvision Cloud"}
        ],
        "hourly_histogram": [2,2,2,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3,3,2,2,2,2,2],
        "events_per_sec": 0.1, "first_seen": "2026-02-15T12:00:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": False, "source": None, "needs": "No hostname traffic"},
            "mac": {"known": True, "source": "dhcp.log"},
            "vendor": {"known": True, "source": "OUI → Hikvision"},
            "os_hint": {"known": False, "source": None, "needs": "No identifiable traffic"},
            "app_fingerprint": {"known": False, "source": None, "needs": "No JA3 match"},
            "role": {"known": True, "source": "vendor → iot"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": False, "source": None, "needs": "No auth"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "DHCP options"}
        },
        "alert_count": 0
    },
    "10.0.1.50": {
        "vendor": "Dell Inc.", "os_hint": "CentOS 8", "asset_type": "database",
        "app_fingerprint": None, "role_confidence": "medium",
        "maturity_score": 52,
        "counters": {"dns_queries": 80, "http_requests": 15, "ssl_connections": 420, "ssh_sessions": 8, "total_events": 523},
        "top_protocols": [
            {"name": "SSL", "pct": 80}, {"name": "DNS", "pct": 15}, {"name": "SSH", "pct": 2}
        ],
        "top_domains": [
            {"domain": "clickhouse.com", "count": 10}
        ],
        "top_dst_ips": [
            {"ip": "10.0.2.88", "count": 280, "label": "WS-FIN-088"}
        ],
        "hourly_histogram": [2,2,1,1,1,2,5,12,28,32,30,25,22,28,30,25,18,12,8,5,3,2,2,2],
        "events_per_sec": 0.8, "first_seen": "2026-02-13T16:00:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "dns.log PTR"},
            "mac": {"known": False, "source": None, "needs": "DHCP"},
            "vendor": {"known": True, "source": "OUI lookup"},
            "os_hint": {"known": True, "source": "ssh.log banner"},
            "app_fingerprint": {"known": False, "source": None, "needs": "No browser"},
            "role": {"known": True, "source": "port 8123 → database"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": False, "source": None, "needs": "No auth"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "Static IP"}
        },
        "alert_count": 0
    },
    "10.0.5.101": {
        "vendor": "Apple Inc.", "os_hint": "macOS 14.2 Sonoma", "asset_type": "workstation",
        "app_fingerprint": "Safari 17.2", "role_confidence": "high",
        "maturity_score": 78,
        "counters": {"dns_queries": 1100, "http_requests": 320, "ssl_connections": 1800, "ssh_sessions": 45, "total_events": 3265},
        "top_protocols": [
            {"name": "SSL", "pct": 55}, {"name": "DNS", "pct": 34}, {"name": "HTTP", "pct": 10}
        ],
        "top_domains": [
            {"domain": "github.com", "count": 420}, {"domain": "stackoverflow.com", "count": 180},
            {"domain": "npmjs.com", "count": 150}, {"domain": "apple.com", "count": 80}
        ],
        "top_dst_ips": [
            {"ip": "185.199.108.153", "count": 380, "label": "GitHub"}, {"ip": "151.101.1.69", "count": 160, "label": "StackOverflow"}
        ],
        "hourly_histogram": [0,0,0,0,0,0,1,5,25,42,48,45,15,42,48,45,38,22,8,2,0,0,0,0],
        "events_per_sec": 2.8, "first_seen": "2026-02-15T08:30:00Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": True, "source": "mdns.log"},
            "mac": {"known": True, "source": "dhcp.log"},
            "vendor": {"known": True, "source": "OUI → Apple"},
            "os_hint": {"known": True, "source": "User-Agent"},
            "app_fingerprint": {"known": True, "source": "ssl.log JA3"},
            "role": {"known": True, "source": "traffic pattern"},
            "dns_behavior": {"known": True, "source": "dns.log"},
            "user_identity": {"known": False, "source": None, "needs": "No NTLM (macOS)"},
            "dhcp_fingerprint": {"known": True, "source": "dhcp.log"}
        },
        "alert_count": 0
    }
}


def _get_profile(ip):
    """Get profile data for an IP, with fallback for unknown IPs."""
    if ip in PROFILES:
        return PROFILES[ip]
    # Unknown asset — sparse profile
    return {
        "vendor": None, "os_hint": None, "asset_type": "unknown",
        "app_fingerprint": None, "role_confidence": "low",
        "maturity_score": 12,
        "counters": {"dns_queries": 5, "total_events": 5},
        "top_protocols": [{"name": "DNS", "pct": 100}],
        "top_domains": [], "top_dst_ips": [],
        "hourly_histogram": [0]*24,
        "events_per_sec": 0.0, "first_seen": datetime.utcnow().isoformat() + "Z",
        "known_fields": {
            "ip": {"known": True, "source": "conn.log"},
            "hostname": {"known": False, "source": None, "needs": "DNS/DHCP/Kerberos"},
            "mac": {"known": False, "source": None, "needs": "DHCP"},
            "vendor": {"known": False, "source": None, "needs": "OUI lookup (MAC missing)"},
            "os_hint": {"known": False, "source": None, "needs": "User-Agent/SSH banner"},
            "app_fingerprint": {"known": False, "source": None, "needs": "JA3"},
            "role": {"known": False, "source": None, "needs": "More traffic"},
            "dns_behavior": {"known": False, "source": None, "needs": "DNS queries"},
            "user_identity": {"known": False, "source": None, "needs": "Auth traffic"},
            "dhcp_fingerprint": {"known": False, "source": None, "needs": "DHCP"}
        },
        "alert_count": 0
    }


def _enrich_asset(asset_data):
    """Add profiling fields to a serialized asset."""
    ip = asset_data.get("ip", "")
    p = _get_profile(ip)
    asset_data["vendor"] = p.get("vendor")
    asset_data["os_hint"] = p.get("os_hint") or asset_data.get("os", "")
    asset_data["asset_type"] = p.get("asset_type", asset_data.get("type", "unknown"))
    asset_data["maturity_score"] = p.get("maturity_score", 0)
    asset_data["top_protocols"] = p.get("top_protocols", [])
    asset_data["events_per_sec"] = p.get("events_per_sec", 0)
    asset_data["first_seen"] = p.get("first_seen")
    asset_data["alert_count"] = p.get("alert_count", 0)
    asset_data["role_confidence"] = p.get("role_confidence", "low")
    return asset_data


class DemoAssetRepository(AssetRepository):

    def list_assets(self, filters, page=1, limit=10):
        queryset = Asset.objects.all().order_by('-last_seen')

        if filters.get('search'):
            from django.db.models import Q
            s = filters['search']
            queryset = queryset.filter(Q(hostname__icontains=s) | Q(ip__icontains=s))
        if filters.get('type'):
            queryset = queryset.filter(type=filters['type'])
        if filters.get('segment'):
            queryset = queryset.filter(segment__icontains=filters['segment'])
        if filters.get('risk_level'):
            queryset = queryset.filter(risk_level=filters['risk_level'])
        if filters.get('tab') == 'threat':
            queryset = queryset.filter(is_threat=True)

        paginator = Paginator(queryset, limit)
        page_obj = paginator.get_page(page)

        assets = []
        for asset in page_obj.object_list:
            data = AssetSerializer(asset).data
            assets.append(_enrich_asset(data))

        return {
            "assets": assets,
            "total": paginator.count,
            "page": page_obj.number,
            "page_count": paginator.num_pages
        }

    def get_asset_detail(self, ip, time_window='24h'):
        try:
            asset = Asset.objects.get(ip=ip)
        except Asset.DoesNotExist:
            return None

        data = AssetSerializer(asset).data
        p = _get_profile(ip)

        # Identity
        data["vendor"] = p.get("vendor")
        data["os_hint"] = p.get("os_hint") or data.get("os", "")
        data["asset_type"] = p.get("asset_type", "unknown")
        data["app_fingerprint"] = p.get("app_fingerprint")
        data["role_confidence"] = p.get("role_confidence", "low")
        data["first_seen"] = p.get("first_seen")
        data["events_per_sec"] = p.get("events_per_sec", 0)

        # Build value map for checklist
        value_map = {
            "ip": ip,
            "hostname": data.get("hostname") or None,
            "mac": data.get("mac_address") or None,
            "vendor": p.get("vendor"),
            "os_hint": p.get("os_hint"),
            "app_fingerprint": p.get("app_fingerprint"),
            "role": p.get("asset_type", "unknown").replace("_", " ").title(),
            "dns_behavior": f"{p.get('counters', {}).get('dns_queries', 0)} queries" if p.get("known_fields", {}).get("dns_behavior", {}).get("known") else None,
            "user_identity": None,
            "dhcp_fingerprint": None,
        }

        # Maturity
        kf = p.get("known_fields", {})
        fields_known = sum(1 for v in kf.values() if v.get("known"))
        fields_total = len(kf)
        data["maturity"] = {
            "score": p.get("maturity_score", 0),
            "fields_known": fields_known,
            "fields_total": fields_total,
            "checklist": [
                {
                    "field": k,
                    "known": v.get("known", False),
                    "value": value_map.get(k),
                    "source": v.get("source"),
                    "when": v.get("when"),
                    "needs": v.get("needs")
                }
                for k, v in kf.items()
            ]
        }

        # Counters + protocol breakdown
        counters = p.get("counters", {})
        data["counters"] = counters
        data["protocol_breakdown"] = p.get("top_protocols", [])

        # Top-N
        data["top_domains"] = p.get("top_domains", [])
        data["top_dst_ips"] = p.get("top_dst_ips", [])

        # Hourly histogram
        data["hourly_histogram"] = p.get("hourly_histogram", [0]*24)

        # Connection summary (SOC card)
        total = counters.get("total_events", 0)
        data["connection_summary"] = {
            "total_events": total,
            "unique_dst_ips": len(p.get("top_dst_ips", [])),
            "unique_domains": len(p.get("top_domains", [])),
            "inbound_ratio": 65 if p.get("asset_type") == "server" else 30,
            "outbound_ratio": 35 if p.get("asset_type") == "server" else 70,
            "bytes_in": f"{random.uniform(0.5, 8.0):.1f} GB",
            "bytes_out": f"{random.uniform(0.1, 3.0):.1f} GB",
            "avg_session_duration": f"{random.randint(2, 120)}s",
        }

        # Network behavior (SOC card)
        histogram = p.get("hourly_histogram", [0]*24)
        max_h = max(histogram) if histogram else 0
        active_hours = sum(1 for v in histogram if v > max_h * 0.3) if max_h > 0 else 0
        peak_hour = histogram.index(max_h) if max_h > 0 else 0

        behavior_flags = []
        if active_hours >= 20:
            behavior_flags.append({"flag": "24/7 Activity", "severity": "info", "detail": "Always-on service pattern"})
        if counters.get("ssh_sessions", 0) > 20:
            behavior_flags.append({"flag": "Frequent SSH", "severity": "info", "detail": f"{counters['ssh_sessions']} sessions observed"})
        if p.get("asset_type") == "iot":
            behavior_flags.append({"flag": "IoT Device", "severity": "warning", "detail": "Limited visibility — no auth protocols"})
        if p.get("maturity_score", 0) < 40:
            behavior_flags.append({"flag": "Sparse Profile", "severity": "warning", "detail": "Less than 40% of identity fields known"})

        data["network_behavior"] = {
            "active_hours_per_day": active_hours,
            "peak_hour": peak_hour,
            "is_server_pattern": active_hours >= 18,
            "is_workstation_pattern": 6 <= active_hours <= 12,
            "baseline_status": "normal",
            "flags": behavior_flags,
        }

        # Alerts
        data["alert_count"] = p.get("alert_count", 0)

        # Mock detections
        detections = []
        if p.get("alert_count", 0) > 0:
            mock_detections = [
                {"id": "det-1", "name": "High-Entropy DNS Queries", "severity": "medium", "time_ago": "2 days ago"},
                {"id": "det-2", "name": "SMB Lateral Movement Attempt", "severity": "high", "time_ago": "5 days ago"},
                {"id": "det-3", "name": "Unusual Outbound TLS Volume", "severity": "medium", "time_ago": "1 day ago"},
                {"id": "det-4", "name": "Port Scan Detected (>50 ports)", "severity": "high", "time_ago": "3 days ago"},
            ]
            detections = mock_detections[:p["alert_count"]]
        data["detections"] = detections

        return data

    def get_asset_analytics(self):
        total = Asset.objects.count()
        return {
            "riskDistribution": {"high": 5, "medium": 15, "low": max(0, total - 20)},
            "categories": [
                {"name": "Servers", "count": 3},
                {"name": "Workstations", "count": 3},
                {"name": "Databases", "count": 2},
                {"name": "Network", "count": 1},
                {"name": "IoT", "count": 1}
            ],
            "discoveryTimeline": [],
            "segmentRisk": []
        }

    def get_config_log(self, ip):
        return [
            {"timestamp": "2026-02-16T12:00:00Z", "event": "Service Discovered", "service": "HTTP", "change": "Port 80 first seen"}
        ]
