from abc import ABC, abstractmethod


class DetectionRepository(ABC):
    # ── Alerts (standalone signals: alert_type='signal') ─────────
    @abstractmethod
    def list_alerts(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_alert_detail(self, alert_id):
        pass

    @abstractmethod
    def update_alert(self, alert_id, data):
        pass

    @abstractmethod
    def get_alert_signals(self, alert_id):
        pass

    @abstractmethod
    def get_alert_evidence(self, alert_id):
        pass

    @abstractmethod
    def get_affected_systems(self, alert_id):
        pass

    @abstractmethod
    def get_alert_network_activity(self, alert_id):
        pass

    # ── Incidents (UC completions: alert_type='use_case') ────────
    @abstractmethod
    def list_incidents(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_incident_detail(self, incident_id):
        pass

    # ── Anomalies (visibility_mode='anomaly') ────────────────────
    @abstractmethod
    def list_anomalies(self, filters, page=1, limit=10):
        pass

    @abstractmethod
    def get_anomaly_detail(self, anomaly_id):
        pass

    # ── Forensic drill-down (ftx_ids → logs) ─────────────────────
    @abstractmethod
    def get_contributing_logs(self, ftx_ids_csv):
        pass

    # ── Overview stats ───────────────────────────────────────────
    @abstractmethod
    def get_overview_stats(self, time_range='24h'):
        pass

    @abstractmethod
    def get_detection_stats(self, time_range):
        pass
