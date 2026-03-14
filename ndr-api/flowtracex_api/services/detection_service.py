from django.conf import settings
from repositories.demo.detection_repo import DemoDetectionRepository
from repositories.production.detection_repo import ProductionDetectionRepository


class DetectionService:
    def __init__(self):
        if settings.APP_MODE == 'demo':
            self.repo = DemoDetectionRepository()
        else:
            self.repo = ProductionDetectionRepository()

    # ── Alerts (standalone signals) ──────────────────────────────
    def list_alerts(self, filters, page=1, limit=10):
        return self.repo.list_alerts(filters, page, limit)

    def get_alert_detail(self, alert_id):
        return self.repo.get_alert_detail(alert_id)

    def update_alert(self, alert_id, data):
        return self.repo.update_alert(alert_id, data)

    def get_alert_signals(self, alert_id):
        return self.repo.get_alert_signals(alert_id)

    def get_alert_evidence(self, alert_id):
        return self.repo.get_alert_evidence(alert_id)

    def get_affected_systems(self, alert_id):
        return self.repo.get_affected_systems(alert_id)

    def get_alert_network_activity(self, alert_id):
        return self.repo.get_alert_network_activity(alert_id)

    # ── Incidents (UC completions) ───────────────────────────────
    def list_incidents(self, filters, page=1, limit=10):
        return self.repo.list_incidents(filters, page, limit)

    def get_incident_detail(self, incident_id):
        return self.repo.get_incident_detail(incident_id)

    # ── Anomalies ────────────────────────────────────────────────
    def list_anomalies(self, filters, page=1, limit=10):
        return self.repo.list_anomalies(filters, page, limit)

    def get_anomaly_detail(self, anomaly_id):
        return self.repo.get_anomaly_detail(anomaly_id)

    # ── Forensic drill-down ──────────────────────────────────────
    def get_contributing_logs(self, ftx_ids_csv):
        return self.repo.get_contributing_logs(ftx_ids_csv)

    # ── Overview & Stats ─────────────────────────────────────────
    def get_overview_stats(self, time_range='24h'):
        return self.repo.get_overview_stats(time_range)

    def get_detection_stats(self, time_range):
        return self.repo.get_detection_stats(time_range)
