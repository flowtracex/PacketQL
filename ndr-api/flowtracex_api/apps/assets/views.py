from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from services.asset_service import AssetService
import logging

logger = logging.getLogger(__name__)

class AssetListView(APIView):

    def get(self, request):
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        filters = {
            'search': request.query_params.get('search'),
            'type': request.query_params.get('type'),
            'segment': request.query_params.get('segment'),
            'risk_level': request.query_params.get('risk_level'),
            'tab': request.query_params.get('tab', 'active')
        }
        
        service = AssetService()
        data = service.list_assets(filters, page, limit)
        return Response(data)

class AssetDetailView(APIView):

    def get(self, request, ip):
        time_window = request.query_params.get('time_window', '24h')
        service = AssetService()
        data = service.get_asset_detail(ip, time_window)
        if data:
            return Response(data)
        return Response(status=status.HTTP_404_NOT_FOUND)

class AssetAnalyticsView(APIView):

    def get(self, request):
        service = AssetService()
        data = service.get_asset_analytics()
        return Response(data)

class AssetActionView(APIView):
    action = None

    def post(self, request, ip):
        # Mock implementation for Isolate/Review
        # Audit log creation should happen here
        logger.info(f"Asset action {self.action} triggered for {ip} by {request.user}")
        if self.action == 'isolate':
            return Response({"status": "isolation_requested"})
        elif self.action == 'review':
            return Response({"status": "review_triggered"})
        return Response(status=status.HTTP_400_BAD_REQUEST)

class AssetConfigLogView(APIView):

    def get(self, request, ip):
        service = AssetService()
        data = service.get_config_log(ip)
        return Response(data)
