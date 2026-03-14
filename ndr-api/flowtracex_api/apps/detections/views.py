from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from services.detection_service import DetectionService
from .serializers import AlertSerializer
from apps.authentication.models import User


# ═══════════════════════════════════════════════════════════════
# INCIDENTS (UC completions — alert_type='use_case')
# ═══════════════════════════════════════════════════════════════

class IncidentListView(APIView):

    def get(self, request):
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        filters = {
            'severity': request.query_params.getlist('severity[]'),
            'status': request.query_params.getlist('status[]'),
            'search': request.query_params.get('search'),
            'category': request.query_params.get('category'),
            'time_range': request.query_params.get('time_range', '24h'),
        }
        service = DetectionService()
        data = service.list_incidents(filters, page, limit)
        return Response(data)


class IncidentDetailView(APIView):

    def get(self, request, pk):
        service = DetectionService()
        data = service.get_incident_detail(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)


# ═══════════════════════════════════════════════════════════════
# ALERTS (standalone signals — alert_type='signal')
# ═══════════════════════════════════════════════════════════════

class AlertListView(APIView):

    def get(self, request):
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        filters = {
            'severity': request.query_params.getlist('severity[]'),
            'status': request.query_params.getlist('status[]'),
            'search': request.query_params.get('search'),
            'mitre_tactic': request.query_params.get('mitre_tactic'),
            'category': request.query_params.get('category'),
            'time_range': request.query_params.get('time_range', '24h'),
        }
        service = DetectionService()
        data = service.list_alerts(filters, page, limit)
        return Response(data)


class AlertDetailView(APIView):

    def get(self, request, pk):
        service = DetectionService()
        data = service.get_alert_detail(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, pk):
        service = DetectionService()
        data = service.update_alert(pk, request.data)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)


class AlertActionView(APIView):
    action = None  # 'acknowledge', 'resolve', 'false_positive'

    def post(self, request, pk):
        service = DetectionService()
        update_data = {}

        if self.action == 'acknowledge':
            update_data = {'status': 'investigating'}
        elif self.action == 'resolve':
            update_data = {'status': 'resolved'}
        elif self.action == 'false_positive':
            update_data = {'status': 'false_positive', 'verdict': 'false_positive'}

        update_data.update(request.data)

        data = service.update_alert(pk, update_data)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)


class AlertSignalsView(APIView):

    def get(self, request, pk):
        service = DetectionService()
        data = service.get_alert_signals(pk)
        return Response(data)


class AlertEvidenceView(APIView):

    def get(self, request, pk):
        service = DetectionService()
        data = service.get_alert_evidence(pk)
        return Response(data)


class AlertSystemsView(APIView):

    def get(self, request, pk):
        service = DetectionService()
        data = service.get_affected_systems(pk)
        return Response(data)


class AlertNetworkActivityView(APIView):

    def get(self, request, pk):
        service = DetectionService()
        data = service.get_alert_network_activity(pk)
        return Response(data)


class AlertEscalateView(APIView):

    def post(self, request, pk):
        return Response({
            "id": 123,
            "title": f"Investigation for Alert {pk}",
            "status": "active"
        }, status=status.HTTP_201_CREATED)


# ═══════════════════════════════════════════════════════════════
# ANOMALIES (low-weight processed signals)
# ═══════════════════════════════════════════════════════════════

class AnomalyListView(APIView):

    def get(self, request):
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        filters = {
            'severity': request.query_params.getlist('severity[]'),
            'search': request.query_params.get('search'),
        }
        service = DetectionService()
        data = service.list_anomalies(filters, page, limit)
        return Response(data)


class AnomalyDetailView(APIView):

    def get(self, request, pk):
        service = DetectionService()
        data = service.get_anomaly_detail(pk)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)


# ═══════════════════════════════════════════════════════════════
# FORENSIC DRILL-DOWN (ftx_ids → contributing logs)
# ═══════════════════════════════════════════════════════════════

class ContributingLogsView(APIView):

    def get(self, request):
        ftx_ids = request.query_params.get('ftx_ids', '')
        if not ftx_ids:
            return Response({"error": "ftx_ids parameter required"}, status=status.HTTP_400_BAD_REQUEST)
        service = DetectionService()
        data = service.get_contributing_logs(ftx_ids)
        return Response(data)


# ═══════════════════════════════════════════════════════════════
# OVERVIEW STATS
# ═══════════════════════════════════════════════════════════════

class DetectionOverviewView(APIView):

    def get(self, request):
        time_range = request.query_params.get('time_range', '24h')
        service = DetectionService()
        data = service.get_overview_stats(time_range)
        return Response(data)


class DetectionStatsView(APIView):

    def get(self, request):
        time_range = request.query_params.get('time_range', '24h')
        service = DetectionService()
        data = service.get_detection_stats(time_range)
        return Response(data)
