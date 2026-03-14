from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import FileResponse, HttpResponse
from services.network_service import NetworkService
import os

class NetworkTopologyView(APIView):

    def get(self, request):
        service = NetworkService()
        data = service.get_topology()
        return Response(data)

class NetworkServicesView(APIView):

    def get(self, request):
        service = NetworkService()
        data = service.get_services()
        return Response(data)

class NetworkFlowsView(APIView):

    def get(self, request):
        page = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))
        filters = request.query_params.dict()
        
        service = NetworkService()
        data = service.search_flows(filters, page, limit)
        return Response(data)

class NetworkAnalyticsView(APIView):

    def get(self, request):
        window = request.query_params.get('window', '24h')
        service = NetworkService()
        data = service.get_analytics(window=window)
        return Response(data)

class NetworkPCAPView(APIView):

    def get(self, request, pk):
        service = NetworkService()
        file_path = service.get_pcap(pk)
        
        if file_path and os.path.exists(file_path):
            return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=f"{pk}.pcap")
        elif file_path is None:
             # Demo mock or empty
             return HttpResponse("PCAP content", content_type='application/octet-stream')
             
        return Response(status=status.HTTP_404_NOT_FOUND)
