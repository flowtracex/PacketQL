from ..base.dashboard_repo import DashboardRepository
from datetime import datetime, timedelta
import random

class DemoDashboardRepository(DashboardRepository):
    def get_overview_metrics(self):
        return {
            "critical_alerts": {"count": 12, "change": "+2", "period": "24h"},
            "high_alerts": {"count": 45, "change": "-5", "period": "24h"},
            "assets_monitored": {"count": 1250, "change": "+10", "period": "24h"},
            "network_health": {"percentage": 94, "status": "Good"}
        }

    def get_traffic_metrics(self, range_str):
        # Generate fake timeseries
        points = []
        now = datetime.now()
        hours = 24 if range_str == '24h' else 1
        intervals = 60 if range_str == '1h' else 24
        
        for i in range(intervals):
            t = now - timedelta(minutes=i) if range_str == '1h' else now - timedelta(hours=i)
            points.append({
                "timestamp": t.isoformat(),
                "trafficMBps": round(random.uniform(50, 500), 2),
                "alerts": random.randint(0, 5)
            })
        points.reverse()
        return {"dataPoints": points}

    def get_protocol_distribution(self):
        return {
            "protocols": [
                {"name": "HTTP/HTTPS", "percentage": 45, "volume": "500GB", "anomaly": False, "source": "Internal"},
                {"name": "DNS", "percentage": 15, "volume": "150GB", "anomaly": False, "source": "Internal"},
                {"name": "SSH", "percentage": 5, "volume": "50GB", "anomaly": True, "source": "External"},
                {"name": "Other", "percentage": 35, "volume": "350GB", "anomaly": False, "source": "Mixed"},
            ]
        }

    def get_deep_inspection_coverage(self):
        return {
            "zeek_coverage": 85,
            "flow_coverage": 100,
            "hybrid_coverage": 85
        }
