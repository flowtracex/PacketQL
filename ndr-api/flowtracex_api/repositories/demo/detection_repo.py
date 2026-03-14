from ..base.detection_repo import DetectionRepository
from apps.detections.models import Alert, AlertSignal
from apps.detections.serializers import AlertSerializer, AlertSignalSerializer
from django.core.paginator import Paginator

class DemoDetectionRepository(DetectionRepository):
    def list_alerts(self, filters, page=1, limit=10):
        queryset = Alert.objects.all().order_by('-timestamp')
        
        # Apply filters
        if filters.get('severity'):
            queryset = queryset.filter(severity__in=filters['severity'])
        if filters.get('status'):
            queryset = queryset.filter(status__in=filters['status'])
        if filters.get('search'):
            from django.db.models import Q
            s = filters['search']
            queryset = queryset.filter(
                Q(name__icontains=s) | Q(source_ip__icontains=s) | Q(destination_ip__icontains=s)
            )
        if filters.get('mitre_tactic'):
            queryset = queryset.filter(mitre_tactic__icontains=filters['mitre_tactic'])

        paginator = Paginator(queryset, limit)
        page_obj = paginator.get_page(page)
        
        return {
            "alerts": AlertSerializer(page_obj.object_list, many=True).data,
            "total": paginator.count,
            "page": page_obj.number,
            "page_count": paginator.num_pages,
            "summary": {
                "critical": Alert.objects.filter(severity='critical').count(),
                "high": Alert.objects.filter(severity='high').count(),
                "investigating": Alert.objects.filter(status='investigating').count(),
                "resolved": Alert.objects.filter(status='resolved').count()
            }
        }

    def get_alert_detail(self, alert_id):
        try:
            alert = Alert.objects.get(pk=alert_id)
            return AlertSerializer(alert).data
        except Alert.DoesNotExist:
            return None

    def update_alert(self, alert_id, data):
        try:
            alert = Alert.objects.get(pk=alert_id)
            for key, value in data.items():
                setattr(alert, key, value)
            alert.save()
            return AlertSerializer(alert).data
        except Alert.DoesNotExist:
            return None

    def get_alert_signals(self, alert_id):
        signals = AlertSignal.objects.filter(alert_id=alert_id)
        return AlertSignalSerializer(signals, many=True).data

    def get_alert_evidence(self, alert_id):
        # Demo: return some fake evidence log entries
        return [
            {"id": "ev1", "timestamp": "2023-10-27T10:00:00Z", "type": "dns", "content": "Query: malicious.com", "source": "Zeek"},
            {"id": "ev2", "timestamp": "2023-10-27T10:00:01Z", "type": "http", "content": "GET /payload.exe", "source": "Suricata"},
        ]

    def get_affected_systems(self, alert_id):
        return {
            "source": {"hostname": "finance-pc-01", "ip": "10.0.1.5", "vlan": "10", "classification": "Workstation"},
            "internalSystems": [{"count": 2, "vlan": "20", "type": "Server"}],
            "externalDestinations": {"count": 1, "ips": ["192.0.2.1"]}
        }

    def get_alert_network_activity(self, alert_id):
        return [{"timestamp": "2023-10-27T10:00:00Z", "trafficMBps": 12.5, "alerts": 1}]

    def get_detection_stats(self, time_range):
        return {
            "timeline": [],
            "heatmap": [],
            "targeted_assets": []
        }

    # ── Incidents (UC completions) ───────────────────────────────

    def list_incidents(self, filters, page=1, limit=10):
        return {
            "items": [
                {
                    "id": 1, "alert_id": "UC-RECON-001-abc12345-1700000000",
                    "alert_type": "use_case", "name": "Reconnaissance → Lateral Movement",
                    "use_case_id": "UC-RECON-001", "asset_id": "10.0.1.5",
                    "severity": "critical", "status": "new", "ftx_ids": "demo-uuid-1,demo-uuid-2",
                    "timestamp": "2026-02-23T12:00:00Z",
                    "description": "Multi-stage attack: port scan followed by lateral movement detected.",
                    "contributing_signals": [
                        {"stage": 1, "signal_id": "SIG-004", "timestamp": "2026-02-23T11:55:00Z"},
                        {"stage": 2, "signal_id": "SIG-005", "timestamp": "2026-02-23T11:58:00Z"}
                    ]
                }
            ],
            "total": 1, "page": 1, "page_count": 1,
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}
        }

    def get_incident_detail(self, incident_id):
        items = self.list_incidents({}).get("items", [])
        return items[0] if items else None

    # ── Anomalies ────────────────────────────────────────────────

    def list_anomalies(self, filters, page=1, limit=10):
        return {
            "items": [
                {
                    "id": 1, "signal_id": "SIG-026", "signal_name": "Off-Hours Activity",
                    "asset_id": "10.0.1.12", "visibility_mode": "anomaly",
                    "severity": "low", "scored_points": 10, "ftx_ids": "demo-uuid-3",
                    "timestamp": "2026-02-23T03:15:00Z"
                }
            ],
            "total": 1, "page": 1, "page_count": 1
        }

    def get_anomaly_detail(self, anomaly_id):
        items = self.list_anomalies({}).get("items", [])
        return items[0] if items else None

    # ── Forensic drill-down ──────────────────────────────────────

    def get_contributing_logs(self, ftx_ids_csv):
        return [
            {"ftx_id": "demo-uuid-1", "log_type": "conn", "src_ip": "10.0.1.5", "dst_ip": "10.0.2.10",
             "timestamp": "2026-02-23T11:55:00Z"},
            {"ftx_id": "demo-uuid-2", "log_type": "conn", "src_ip": "10.0.1.5", "dst_ip": "10.0.2.11",
             "timestamp": "2026-02-23T11:58:00Z"}
        ]

    # ── Overview stats ───────────────────────────────────────────

    def get_overview_stats(self, time_range='24h'):
        return {
            "incidents": 3,
            "alerts": 12,
            "anomalies": 47,
            "raw_signals": 215,
            "severity": {"critical": 1, "high": 4, "medium": 7, "low": 3}
        }
