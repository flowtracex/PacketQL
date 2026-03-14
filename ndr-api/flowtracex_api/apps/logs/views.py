from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import StreamingHttpResponse
from services.log_service import LogService
import json

class LogSearchView(APIView):

    def get(self, request):
        service = LogService()
        filters = request.query_params.dict()

        # Parse structured query builder conditions from JSON param
        conditions_raw = request.query_params.get('conditions', '')
        if conditions_raw:
            try:
                filters['conditions'] = json.loads(conditions_raw)
            except (json.JSONDecodeError, TypeError):
                filters['conditions'] = []
        else:
            filters['conditions'] = []

        page  = int(request.query_params.get('page', 1))
        limit = int(request.query_params.get('limit', 10))

        data = service.search_logs(filters, page, limit)
        return Response(data)

class LogAnalyticsView(APIView):

    def get(self, request):
        service = LogService()
        window = request.query_params.get('window', '24h')
        data = service.get_analytics(window=window)
        return Response(data)

class LogLiveStreamView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request):
        service = LogService()
        return StreamingHttpResponse(service.stream_logs(), content_type='text/event-stream')

