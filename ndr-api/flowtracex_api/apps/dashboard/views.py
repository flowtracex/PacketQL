from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from services.dashboard_service import DashboardService

class DashboardOverviewView(APIView):

    def get(self, request):
        service = DashboardService()
        data = service.get_overview()
        return Response(data)

class DashboardTrafficView(APIView):

    def get(self, request):
        range_str = request.query_params.get('range', '1h')
        service = DashboardService()
        data = service.get_traffic(range_str)
        return Response(data)

class DashboardProtocolView(APIView):

    def get(self, request):
        service = DashboardService()
        data = service.get_protocols()
        return Response(data)

class DashboardCoverageView(APIView):

    def get(self, request):
        service = DashboardService()
        data = service.get_coverage()
        return Response(data)
