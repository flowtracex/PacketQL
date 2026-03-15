import json
from ..base.network_repo import NetworkRepository
from clients.state_store_client import StateStoreClient


class DemoNetworkRepository(NetworkRepository):
    """Network repository that reads from local analytics state.

    Falls back to minimal stub data if no cached analytics exist.
    Works identically in demo and production — data comes from
    ndr-baseline's network-summary job.
    """

    def _get_analytics_from_store(self):
        """Try to read fleet-wide analytics from local store."""
        try:
            data = StateStoreClient.hgetall("ndr:network:analytics")
            if data:
                return {k: json.loads(v) for k, v in data.items()}
        except Exception:
            pass
        return None

    def get_topology(self):
        return [
            {"id": "n1", "name": "Firewall", "type": "firewall", "risk": 0, "ip": "10.0.0.1", "connections": ["n2", "n3"]},
            {"id": "n2", "name": "Switch-Core", "type": "switch", "risk": 0, "ip": "10.0.0.2", "connections": ["n4", "n5"]},
            {"id": "n3", "name": "Server-01", "type": "server", "risk": 80, "ip": "10.0.1.5", "connections": []},
        ]

    def get_services(self):
        analytics = self._get_analytics_from_store()
        if analytics and "services" in analytics:
            return analytics["services"]
        return [
            {"id": "s1", "port": 80, "protocol": "TCP", "service": "http", "assets": 5, "bandwidth": "100Mbps", "risk": "Low"},
            {"id": "s2", "port": 443, "protocol": "TCP", "service": "https", "assets": 5, "bandwidth": "500Mbps", "risk": "Low"},
        ]

    def search_flows(self, filters, page=1, limit=10):
        return {
            "flows": [
                {"timestamp": "2023-11-01T12:00:00Z", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "port": 53, "protocol": "UDP", "bytes": 120},
                {"timestamp": "2023-11-01T12:00:01Z", "src_ip": "10.0.0.5", "dst_ip": "1.1.1.1", "port": 53, "protocol": "UDP", "bytes": 120},
            ],
            "total": 2
        }

    def get_analytics(self):
        """Return fleet-wide network analytics from local store."""
        analytics = self._get_analytics_from_store()
        if analytics:
            return analytics
        # Fallback if the local cache is empty
        return {
            "kpis": {"total_flows": 0, "total_bytes": 0, "total_bytes_fmt": "0 B", "unique_pairs": 0, "external_pairs": 0, "encryption_pct": 0, "unusual_count": 0},
            "top_talkers_outbound": [],
            "top_talkers_lateral": [],
            "protocol_stats": [],
            "protocol_trends": [],
            "segment_matrix": [],
            "services": [],
            "unusual": [],
        }

    def get_pcap(self, pcap_id):
        return None
