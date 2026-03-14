from django.urls import path
from .views import (
    # Incidents
    IncidentListView,
    IncidentDetailView,
    # Alerts
    AlertListView,
    AlertDetailView,
    AlertActionView,
    AlertEscalateView,
    AlertSignalsView,
    AlertEvidenceView,
    AlertSystemsView,
    AlertNetworkActivityView,
    # Anomalies
    AnomalyListView,
    AnomalyDetailView,
    # Forensic + Overview
    ContributingLogsView,
    DetectionOverviewView,
    DetectionStatsView,
)

urlpatterns = [
    # ── Incidents ────────────────────────────────────────────────
    path('detections/incidents', IncidentListView.as_view(), name='incident_list'),
    path('detections/incidents/<int:pk>', IncidentDetailView.as_view(), name='incident_detail'),

    # ── Alerts ───────────────────────────────────────────────────
    path('detections/alerts', AlertListView.as_view(), name='alert_list'),
    path('detections/alerts/<int:pk>', AlertDetailView.as_view(), name='alert_detail'),
    path('detections/alerts/<int:pk>/acknowledge', AlertActionView.as_view(action='acknowledge'), name='alert_acknowledge'),
    path('detections/alerts/<int:pk>/escalate', AlertEscalateView.as_view(), name='alert_escalate'),
    path('detections/alerts/<int:pk>/resolve', AlertActionView.as_view(action='resolve'), name='alert_resolve'),
    path('detections/alerts/<int:pk>/false-positive', AlertActionView.as_view(action='false_positive'), name='alert_false_positive'),
    path('detections/alerts/<int:pk>/signals', AlertSignalsView.as_view(), name='alert_signals'),
    path('detections/alerts/<int:pk>/evidence', AlertEvidenceView.as_view(), name='alert_evidence'),
    path('detections/alerts/<int:pk>/systems', AlertSystemsView.as_view(), name='alert_systems'),
    path('detections/alerts/<int:pk>/network-activity', AlertNetworkActivityView.as_view(), name='alert_network_activity'),

    # ── Anomalies ────────────────────────────────────────────────
    path('detections/anomalies', AnomalyListView.as_view(), name='anomaly_list'),
    path('detections/anomalies/<int:pk>', AnomalyDetailView.as_view(), name='anomaly_detail'),

    # ── Forensic drill-down ──────────────────────────────────────
    path('detections/logs', ContributingLogsView.as_view(), name='contributing_logs'),

    # ── Overview & Stats ─────────────────────────────────────────
    path('detections/overview', DetectionOverviewView.as_view(), name='detection_overview'),
    path('detections/stats', DetectionStatsView.as_view(), name='detection_stats'),
]
